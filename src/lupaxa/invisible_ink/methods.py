"""Five Unicode concealment methods sharing one contract."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from lupaxa.invisible_ink.errors import ArgumentError, CapacityError, IntegrityError, UnsupportedError
from lupaxa.invisible_ink.textutil import graphemes, insert_at_boundaries, insertion_points, order_indexes, spread_chunks

ZW_ZERO = "\u200b"
ZW_ONE = "\u200c"
TAG_TERM = "\U000e007f"
# Alphabet version homoglyph-1. Latin is bit 0 and the confusable is bit 1.
HOMOGLYPH_V1: tuple[tuple[str, str], ...] = (
    ("a", "\u0430"),
    ("e", "\u0435"),
    ("o", "\u043e"),
    ("p", "\u0440"),
    ("c", "\u0441"),
    ("A", "\u0410"),
    ("E", "\u0415"),
    ("O", "\u041e"),
    ("P", "\u0420"),
    ("C", "\u0421"),
    ("x", "\u0445"),
    ("y", "\u0443"),
    ("X", "\u0425"),
)


@dataclass
class Alphabet:
    """A reversible homoglyph mapping."""

    pairs: tuple[tuple[str, str], ...] = HOMOGLYPH_V1
    version: str = "homoglyph-1"
    zero_to_one: dict[str, str] = field(init=False)
    one_to_zero: dict[str, str] = field(init=False)

    def __post_init__(self) -> None:
        """Build the lookup tables and reject ambiguous pairs."""
        self.zero_to_one = {}
        self.one_to_zero = {}
        seen: set[str] = set()
        for left, right in self.pairs:
            if len(left) != 1 or len(right) != 1 or left == right:
                raise ArgumentError("Each homoglyph pair must be two distinct characters.")
            if left in seen or right in seen:
                raise ArgumentError("A character cannot appear in more than one homoglyph pair.")
            seen.add(left)
            seen.add(right)
            self.zero_to_one[left] = right
            self.one_to_zero[right] = left

    def bit(self, char: str) -> int | None:
        """Return 0, 1, or None when the character is outside the alphabet."""
        if char in self.zero_to_one:
            return 0
        if char in self.one_to_zero:
            return 1
        return None

    def apply(self, char: str, bit: int) -> str:
        """Return the alphabet character for a bit, preserving unrelated characters."""
        if bit == 0:
            return self.one_to_zero.get(char, char)
        return self.zero_to_one.get(char, char)


def validate_mapping(pairs: list[tuple[str, str]]) -> Alphabet:
    """Validate a custom homoglyph mapping."""
    return Alphabet(tuple(pairs), version="custom")


def byte_to_selector(value: int) -> str:
    """Map a byte onto U+FE00–U+FE0F and then U+E0100–U+E01EF."""
    if value < 16:
        return chr(0xFE00 + value)
    return chr(0xE0100 + (value - 16))


def selector_to_byte(code: int) -> int | None:
    """Inverse of :func:`byte_to_selector`."""
    if 0xFE00 <= code <= 0xFE0F:
        return code - 0xFE00
    if 0xE0100 <= code <= 0xE01EF:
        return 16 + (code - 0xE0100)
    return None


def is_tag(code: int) -> bool:
    """Return whether a scalar is an encoded tag character."""
    return 0xE0020 <= code <= 0xE007E


@dataclass
class Capacity:
    """Capacity reported for one method and cover."""

    eligible: int
    raw_symbols: int
    raw_bytes: int
    framing_overhead: int
    encryption_overhead: int
    max_payload: int
    restrictions: list[str]


class Method:
    """Shared method metadata."""

    identifier = ""
    inserts = False
    description = ""
    limitations = ""

    def supports(self, placement: str) -> bool:
        """Return whether the placement can be applied to this method."""
        return placement in {"start", "end", "between-words", "distributed", "random"}

    def encode(self, cover: str, data: bytes, placement: str, seed: int) -> str:
        """Insert or replace symbols. Subclasses implement the method."""
        raise UnsupportedError(f"{self.identifier} is not implemented.")


class ZeroWidth(Method):
    """Hide bits in U+200B and U+200C."""

    identifier = "zero-width"
    inserts = True
    description = "Maps each bit to a zero-width space or zero-width non-joiner."
    limitations = "Zero-width characters can change shaping and are often removed by editors."

    def encode(self, cover: str, data: bytes, placement: str, seed: int) -> str:
        """Insert the bit alphabet into the cover."""
        symbols = "".join(ZW_ONE if bit else ZW_ZERO for byte in data for bit in _bits(byte))
        return _insert(cover, symbols, placement, seed, after_base=False)

    def extract(self, text: str) -> bytes:
        """Read zero-width bits in document order."""
        bits = [1 if char == ZW_ONE else 0 for char in text if char in {ZW_ZERO, ZW_ONE}]
        if len(bits) % 8:
            raise IntegrityError("Zero-width stream ends in a partial byte.")
        out = bytearray()
        for start in range(0, len(bits), 8):
            value = 0
            for bit in bits[start : start + 8]:
                value = (value << 1) | bit
            out.append(value)
        return bytes(out)

    def symbols(self, text: str) -> list[int]:
        """Return code-point indexes of the alphabet."""
        return [index for index, char in enumerate(text) if char in {ZW_ZERO, ZW_ONE}]


class Variation(Method):
    """Hide one byte per variation selector."""

    identifier = "variation"
    inserts = True
    description = "Maps each byte to one variation selector in U+FE00–U+FE0F or U+E0100–U+E01EF."
    limitations = "Selectors can change glyph presentation or be stripped. Rendering is not identical across fonts."

    def encode(self, cover: str, data: bytes, placement: str, seed: int) -> str:
        """Attach selectors after existing graphemes."""
        if not graphemes(cover):
            raise CapacityError("Variation selectors need at least one base character.")
        symbols = "".join(byte_to_selector(byte) for byte in data)
        return _insert(cover, symbols, placement, seed, after_base=True)

    def extract(self, text: str) -> bytes:
        """Read selector bytes in document order."""
        out = bytearray()
        for char in text:
            value = selector_to_byte(ord(char))
            if value is not None:
                out.append(value)
        return bytes(out)

    def symbols(self, text: str) -> list[int]:
        """Return code-point indexes of variation selectors."""
        return [index for index, char in enumerate(text) if selector_to_byte(ord(char)) is not None]


class Spacing(Method):
    """Replace ordinary spaces with a no-break space for bit 1."""

    identifier = "spacing"
    inserts = False
    description = "Uses U+0020 as bit 0 and U+00A0 as bit 1 at existing spaces."
    limitations = "Line wrapping and Unicode normalisation can destroy the distinction."

    def eligible(self, text: str) -> list[int]:
        """Return indexes of ordinary and no-break spaces."""
        return [index for index, char in enumerate(text) if char in {" ", "\u00a0"}]

    def encode(self, cover: str, data: bytes, placement: str, seed: int) -> str:
        """Write bits into eligible spaces."""
        bits = [bit for byte in data for bit in _bits(byte)]
        indexes = self._ordered(cover, placement, seed)
        if len(bits) > len(indexes):
            raise CapacityError("Cover text does not have enough eligible spaces.")
        chars = list(cover)
        for index, bit in zip(indexes, bits, strict=False):
            chars[index] = "\u00a0" if bit else " "
        return "".join(chars)

    def extract_bits(self, text: str, placement: str, seed: int) -> list[int]:
        """Read bits from eligible spaces in canonical order."""
        return [1 if text[index] == "\u00a0" else 0 for index in self._ordered(text, placement, seed)]

    def _ordered(self, text: str, placement: str, seed: int) -> list[int]:
        indexes = self.eligible(text)
        if placement == "between-words":
            return indexes
        return order_indexes(indexes, placement, seed)


class Homoglyph(Method):
    """Substitute approved confusable characters."""

    identifier = "homoglyph"
    inserts = False
    description = "Swaps a versioned set of Latin characters with visually similar letters."
    limitations = "Substitutions can trip mixed-script checks and do not look identical in every font."

    def __init__(self, alphabet: Alphabet | None = None) -> None:
        self.alphabet = alphabet or Alphabet()

    def eligible(self, text: str) -> list[int]:
        """Return indexes that belong to either side of a pair."""
        return [index for index, char in enumerate(text) if self.alphabet.bit(char) is not None]

    def encode(self, cover: str, data: bytes, placement: str, seed: int) -> str:
        """Write bits into eligible characters."""
        bits = [bit for byte in data for bit in _bits(byte)]
        indexes = self._ordered(cover, placement, seed)
        if len(bits) > len(indexes):
            raise CapacityError("Cover text does not have enough homoglyph positions.")
        chars = list(cover)
        for index, bit in zip(indexes, bits, strict=False):
            chars[index] = self.alphabet.apply(chars[index], bit)
        return "".join(chars)

    def extract_bits(self, text: str, placement: str, seed: int) -> list[int]:
        """Read bits from eligible characters in canonical order."""
        bits: list[int] = []
        for index in self._ordered(text, placement, seed):
            bit = self.alphabet.bit(text[index])
            if bit is None:
                raise IntegrityError("Homoglyph position left the approved alphabet.")
            bits.append(bit)
        return bits

    def _ordered(self, text: str, placement: str, seed: int) -> list[int]:
        indexes = self.eligible(text)
        if placement == "between-words":
            chars = list(text)
            bounded = []
            for index in indexes:
                left = chars[index - 1] if index else " "
                right = chars[index + 1] if index + 1 < len(chars) else " "
                if left.isspace() or right.isspace():
                    bounded.append(index)
            if not bounded:
                raise UnsupportedError("Homoglyph between-words placement needs characters beside whitespace.")
            return bounded
        return order_indexes(indexes, placement, seed)


class Tag(Method):
    """Hide a base64 payload in Unicode tag characters."""

    identifier = "tag"
    inserts = True
    description = "Maps an ASCII-safe base64 form of the payload onto U+E0020–U+E007E and ends with U+E007F."
    limitations = "Tag characters may be stripped or treated as special syntax."

    def encode(self, cover: str, data: bytes, placement: str, seed: int) -> str:
        """Insert a terminated tag sequence."""
        ascii_form = base64.b64encode(data).decode("ascii")
        symbols = "".join(chr(0xE0000 + ord(char)) for char in ascii_form) + TAG_TERM
        return _insert(cover, symbols, placement, seed, after_base=False)

    def extract_sequences(self, text: str) -> list[bytes]:
        """Decode every terminated tag sequence."""
        found: list[bytes] = []
        current: list[str] = []
        open_run = False
        for char in text:
            code = ord(char)
            if is_tag(code):
                current.append(chr(code - 0xE0000))
                open_run = True
            elif char == TAG_TERM:
                if not open_run:
                    raise IntegrityError("Unicode tag terminator has no payload.")
                try:
                    found.append(base64.b64decode("".join(current), validate=True))
                except ValueError as exc:
                    raise IntegrityError("Unicode tag payload is not valid base64.") from exc
                current = []
                open_run = False
        if open_run:
            raise IntegrityError("Unicode tag sequence is missing its terminator.")
        return found

    def symbols(self, text: str) -> list[int]:
        """Return code-point indexes of tag characters, including the terminator."""
        return [index for index, char in enumerate(text) if is_tag(ord(char)) or char == TAG_TERM]


def _bits(byte: int) -> list[int]:
    return [(byte >> shift) & 1 for shift in range(7, -1, -1)]


def _insert(cover: str, symbols: str, placement: str, seed: int, *, after_base: bool) -> str:
    clusters = graphemes(cover)
    if placement == "between-words":
        points = [index for index, cluster in enumerate(clusters) if cluster.isspace()]
        if after_base:
            points = [index for index in points if index > 0]
        if not points:
            raise UnsupportedError("Between-words placement needs whitespace in the cover text.")
    else:
        points = insertion_points(len(clusters), placement, seed, after_base=after_base)
    if placement in {"start", "end", "random"} and points:
        # Random selects one boundary. Symbols stay in document order, so decoding does not need the seed.
        return insert_at_boundaries(cover, [(points[0], symbols)])
    return insert_at_boundaries(cover, spread_chunks(symbols, points))


METHODS: dict[str, type[Method]] = {
    "zero-width": ZeroWidth,
    "variation": Variation,
    "spacing": Spacing,
    "homoglyph": Homoglyph,
    "tag": Tag,
}


def get_method(name: str, alphabet: Alphabet | None = None) -> Method:
    """Construct a method by its identifier."""
    if name not in METHODS:
        raise UnsupportedError(f"Unknown method {name!r}.")
    if name == "homoglyph":
        return Homoglyph(alphabet)
    return METHODS[name]()
