"""Concealment, recovery, inspection, cleaning, and survival tests."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Any

from lupaxa.invisible_ink.config import Settings
from lupaxa.invisible_ink.crypto import open_sealed, seal
from lupaxa.invisible_ink.errors import (
    ArgumentError,
    CapacityError,
    IntegrityError,
    NotFoundError,
    UnsupportedError,
    VerificationError,
)
from lupaxa.invisible_ink.frame import HEADER_LEN, Frame, build_frame, parse_frames
from lupaxa.invisible_ink.methods import (
    TAG_TERM,
    ZW_ONE,
    ZW_ZERO,
    Alphabet,
    Capacity,
    Homoglyph,
    Spacing,
    Tag,
    Variation,
    ZeroWidth,
    get_method,
    is_tag,
    selector_to_byte,
)
from lupaxa.invisible_ink.textutil import bits_to_bytes, byte_offset, graphemes, utf8_len

INSERTION = {"zero-width", "variation", "tag"}


@dataclass
class Recovered:
    """One recovered payload."""

    payload: bytes
    method: str
    encrypted: bool
    authenticated: bool
    binary: bool
    candidate: bool
    warnings: list[str] = field(default_factory=list)


def _check_sizes(cover: str, payload: bytes, settings: Settings) -> None:
    if utf8_len(cover) > settings.max_cover_bytes:
        raise CapacityError("Cover text exceeds the configured size limit.")
    if len(payload) > settings.max_message_bytes:
        raise CapacityError("Message exceeds the configured size limit.")


def overhead(framed: bool, encrypt: bool) -> tuple[int, int]:
    """Return framing and encryption overhead in bytes."""
    return (HEADER_LEN if framed else 0, 16 if encrypt and framed else 0)


def measure(
    cover: str,
    method_name: str,
    settings: Settings,
    *,
    placement: str,
    seed: int,
    encrypt: bool,
    alphabet: Alphabet | None = None,
) -> Capacity:
    """Calculate embedding capacity for a cover and method."""
    method = get_method(method_name, alphabet)
    if not method.supports(placement):
        raise UnsupportedError(f"{method_name} does not support placement {placement!r}.")
    frame_overhead, crypto_overhead = overhead(True, encrypt)
    restrictions = [method.limitations]
    if method.inserts:
        if method_name == "variation" and not graphemes(cover):
            eligible = 0
            raw_bytes = 0
            restrictions.append("Variation selectors require a base character.")
        else:
            eligible = settings.max_message_bytes
            raw_bytes = settings.max_message_bytes
            restrictions.append("Insertion capacity is the configured message limit, not the cover length.")
    else:
        if not isinstance(method, Spacing | Homoglyph):
            raise UnsupportedError(f"{method_name} has no eligible-position capacity model.")
        eligible = len(method._ordered(cover, placement, seed))
        raw_bytes = eligible // 8
    max_payload = max(0, raw_bytes - frame_overhead - crypto_overhead)
    return Capacity(
        eligible=eligible,
        raw_symbols=eligible,
        raw_bytes=raw_bytes,
        framing_overhead=frame_overhead,
        encryption_overhead=crypto_overhead,
        max_payload=max_payload,
        restrictions=restrictions,
    )


def hide(
    cover: str,
    payload: bytes,
    settings: Settings,
    *,
    method_name: str,
    framed: bool,
    placement: str,
    seed: int,
    password: str | None,
    binary: bool,
    alphabet: Alphabet | None = None,
) -> tuple[str, list[str]]:
    """Conceal a payload and return the encoded text plus warnings."""
    _check_sizes(cover, payload, settings)
    warnings = _warnings(method_name)
    if placement == "random" and seed == 0:
        raise UnsupportedError("Random placement requires a non-zero --seed.")
    body_payload = payload
    sealed = None
    if password is not None:
        if not framed:
            raise UnsupportedError("Encryption requires the framed format.")
        sealed = seal(payload, password, settings)
        body_payload = sealed.body
    if framed:
        encoded = build_frame(
            method=method_name,
            placement=placement,
            seed=seed,
            payload=payload,
            binary=binary,
            sealed=sealed,
        )
    else:
        encoded = body_payload
    if len(encoded) > settings.max_message_bytes:
        raise CapacityError("Encoded message exceeds the configured size limit.")
    method = get_method(method_name, alphabet)
    text = method.encode(cover, encoded, placement, seed)
    return text, warnings


def _warnings(method_name: str) -> list[str]:
    method = get_method(method_name)
    notes = [
        "Concealment is not encryption. Invisible characters can be detected by inspecting code points.",
        method.limitations,
    ]
    if method_name == "homoglyph":
        notes.append("Homoglyph substitutions can trigger mixed-script security checks.")
    return notes


def reveal(
    text: str,
    settings: Settings,
    *,
    method_name: str | None,
    format_name: str,
    placement: str,
    seed: int,
    length: int | None,
    password: str | None,
    find_all: bool,
    alphabet: Alphabet | None = None,
) -> list[Recovered]:
    """Recover confirmed framed messages, or a raw payload when requested."""
    if utf8_len(text) > settings.max_cover_bytes:
        raise CapacityError("Cover text exceeds the configured size limit.")
    names = [method_name] if method_name else ["zero-width", "variation", "spacing", "homoglyph", "tag"]
    placements = [placement]
    if format_name != "raw" and method_name is None:
        placements = ["end", "start", "distributed", "between-words"]
        if seed:
            placements.append("random")
    found: list[Recovered] = []
    for name in names:
        if format_name == "raw":
            if method_name is None:
                raise ArgumentError("Raw decoding requires --method.")
            payload = _decode_raw(text, name, placement, seed, length, alphabet)
            found.append(Recovered(payload, name, encrypted=False, authenticated=False, binary=True, candidate=False))
            break
        for chosen in placements:
            found.extend(_decode_framed(text, name, chosen, seed, password, settings, alphabet))
            if found and not find_all:
                break
        if found and not find_all:
            break
    confirmed = [item for item in found if not item.candidate]
    if not confirmed:
        if _has_candidate(text):
            raise NotFoundError("Suspicious Unicode was found, but no framed message passed integrity checks.")
        raise NotFoundError("No recognised message was found.")
    if len(confirmed) > 1 and not find_all:
        raise ArgumentError("Several framed messages were found. Pass --all to extract each one.")
    return confirmed if find_all or len(confirmed) == 1 else confirmed[:1]


def _decode_raw(
    text: str,
    name: str,
    placement: str,
    seed: int,
    length: int | None,
    alphabet: Alphabet | None,
) -> bytes:
    method = get_method(name, alphabet)
    if isinstance(method, Tag):
        sequences = method.extract_sequences(text)
        if not sequences:
            raise NotFoundError("No terminated Unicode tag sequence was found.")
        payload = sequences[0]
    elif isinstance(method, ZeroWidth | Variation):
        payload = method.extract(text)
    elif isinstance(method, Spacing | Homoglyph):
        if length is None:
            raise ArgumentError("Raw replacement decoding requires --length.")
        bits = method.extract_bits(text, placement, seed)
        payload = bits_to_bytes(bits[: length * 8])
        return payload
    else:
        raise UnsupportedError(f"Unknown method {name!r}.")
    if length is not None:
        if len(payload) < length:
            raise IntegrityError("Raw payload is shorter than --length.")
        payload = payload[:length]
    elif isinstance(method, ZeroWidth | Variation) and length is None:
        raise ArgumentError("Raw decoding of this method requires --length.")
    return payload


def _decode_framed(
    text: str,
    name: str,
    placement: str,
    seed: int,
    password: str | None,
    settings: Settings,
    alphabet: Alphabet | None,
) -> list[Recovered]:
    method = get_method(name, alphabet)
    try:
        if isinstance(method, Tag):
            blobs = method.extract_sequences(text)
        elif isinstance(method, ZeroWidth | Variation):
            blobs = [method.extract(text)]
        elif isinstance(method, Spacing | Homoglyph):
            bits = method.extract_bits(text, placement, seed)
            usable = len(bits) - (len(bits) % 8)
            if usable < HEADER_LEN * 8:
                return []
            blobs = [bits_to_bytes(bits[:usable])]
        else:
            return []
    except (IntegrityError, UnsupportedError):
        return []
    recovered: list[Recovered] = []
    for blob in blobs:
        try:
            frames = parse_frames(blob, settings)
        except (IntegrityError, CapacityError):
            continue
        for frame, _end in frames:
            if frame.method != name:
                continue
            item = _open_frame(frame, password, settings)
            item.warnings.extend(_warnings(name))
            recovered.append(item)
            if len(recovered) >= settings.max_candidates:
                return recovered
    return recovered


def _open_frame(frame: Frame, password: str | None, settings: Settings) -> Recovered:
    if not frame.encrypted:
        return Recovered(frame.payload, frame.method, False, True, frame.binary, False)
    if password is None:
        raise ArgumentError("This framed message is encrypted. Provide a password.")
    payload = open_sealed(
        frame.body,
        password,
        salt=frame.salt,
        nonce=frame.nonce,
        time_cost=frame.time_cost,
        memory_kib=frame.memory_kib,
        parallelism=frame.parallelism,
        settings=settings,
    )
    if len(payload) != frame.declared_length:
        raise IntegrityError("Decrypted length does not match the framed payload length.")
    return Recovered(payload, frame.method, True, True, frame.binary, False)


def _has_candidate(text: str) -> bool:
    return any(
        char in {ZW_ZERO, ZW_ONE, TAG_TERM} or is_tag(ord(char)) or selector_to_byte(ord(char)) is not None
        for char in text
    )


def inspect_text(text: str, settings: Settings, *, show_all: bool) -> dict[str, Any]:
    """Describe Unicode concealment indicators without decrypting."""
    chars = list(text)
    locations: list[dict[str, Any]] = []
    invisible = unusual_space = selectors = tags = confusable = 0
    alphabet = Alphabet()
    for index, char in enumerate(chars):
        kind = _classify(char, alphabet, show_all)
        if kind is None:
            continue
        if kind == "zero-width":
            invisible += 1
        elif kind == "whitespace":
            unusual_space += 1
        elif kind == "variation":
            selectors += 1
        elif kind == "tag":
            tags += 1
        elif kind == "confusable":
            confusable += 1
        locations.append(
            {
                "code_point_index": index,
                "byte_offset": byte_offset(text, index),
                "code_point": f"U+{ord(char):04X}",
                "kind": kind,
            }
        )
    scripts = {_script(char) for char in chars if _script(char)}
    warnings: list[str] = []
    if len(scripts) > 1:
        warnings.append("Text uses more than one Unicode script.")
    candidates = _candidate_report(text, settings)
    return {
        "characters": len(chars),
        "utf8_bytes": utf8_len(text),
        "invisible": invisible,
        "unusual_whitespace": unusual_space,
        "variation_selectors": selectors,
        "tag_characters": tags,
        "confusable_candidates": confusable,
        "locations": locations,
        "framed_candidates": candidates,
        "warnings": warnings,
    }


def _script(char: str) -> str:
    if "LATIN" in unicodedata.name(char, ""):
        return "Latin"
    if "CYRILLIC" in unicodedata.name(char, ""):
        return "Cyrillic"
    return ""


def _classify(char: str, alphabet: Alphabet, show_all: bool) -> str | None:
    if char in {ZW_ZERO, ZW_ONE}:
        return "zero-width"
    if char == "\u00a0":
        return "whitespace"
    if selector_to_byte(ord(char)) is not None:
        return "variation"
    if is_tag(ord(char)) or char == TAG_TERM:
        return "tag"
    if alphabet.bit(char) == 1:
        return "confusable"
    if show_all and unicodedata.category(char) in {"Cf", "Cc", "Zs"} and char not in {" ", "\n", "\t"}:
        return "other"
    return None


def _candidate_report(text: str, settings: Settings) -> list[dict[str, Any]]:
    report: list[dict[str, object]] = []
    for name in ("zero-width", "variation", "spacing", "homoglyph", "tag"):
        try:
            items = _decode_framed(text, name, "end", 0, None, settings, None)
        except ArgumentError as exc:
            report.append({"method": name, "status": "encrypted", "detail": str(exc)})
            continue
        except (IntegrityError, UnsupportedError):
            continue
        for item in items:
            report.append(
                {
                    "method": item.method,
                    "status": "confirmed" if item.authenticated else "candidate",
                    "encrypted": item.encrypted,
                    "bytes": len(item.payload),
                }
            )
    if not report and _has_candidate(text):
        report.append({"method": None, "status": "candidate", "detail": "Matching symbols without a valid frame."})
    return report


def clean_text(
    text: str,
    settings: Settings,
    *,
    mode: str,
    method_name: str | None,
    alphabet: Alphabet | None = None,
) -> tuple[str, list[str]]:
    """Remove recognised concealment. Aggressive mode can change legitimate text."""
    warnings: list[str] = []
    if mode == "aggressive":
        warnings.append("Aggressive cleaning can alter legitimate Unicode text and cannot restore every original.")
        return _clean_aggressive(text, alphabet or Alphabet()), warnings
    if mode != "conservative":
        raise ArgumentError("Cleaning mode must be conservative or aggressive.")
    cleaned, notes = _clean_conservative(text, settings, method_name, alphabet)
    warnings.extend(notes)
    return cleaned, warnings


def _clean_conservative(
    text: str,
    settings: Settings,
    method_name: str | None,
    alphabet: Alphabet | None,
) -> tuple[str, list[str]]:
    notes = [
        "Characters that cannot be distinguished from legitimate Unicode were left unchanged.",
        "Original whitespace cannot be reconstructed when a no-break space was already present.",
    ]
    names = [method_name] if method_name else ["zero-width", "variation", "tag", "homoglyph", "spacing"]
    current = text
    for name in names:
        try:
            items = _decode_framed(current, name, "end", 0, None, settings, alphabet)
        except ArgumentError:
            notes.append(f"{name} contains an encrypted frame. It was identified and left in place.")
            continue
        if not items:
            if name == "homoglyph":
                alphabet_used = alphabet or Alphabet()
                if any(alphabet_used.bit(char) == 1 for char in current):
                    notes.append("Confusable characters were left unchanged because they do not form a valid frame.")
            if name == "spacing" and "\u00a0" in current:
                notes.append("No-break spaces were left unchanged because they do not form a valid frame.")
            continue
        current = _strip_method(current, name, alphabet)
    return current, notes


def _strip_method(text: str, name: str, alphabet: Alphabet | None) -> str:
    if name == "zero-width":
        return "".join(char for char in text if char not in {ZW_ZERO, ZW_ONE})
    if name == "variation":
        return "".join(char for char in text if selector_to_byte(ord(char)) is None)
    if name == "tag":
        return "".join(char for char in text if not is_tag(ord(char)) and char != TAG_TERM)
    if name == "homoglyph":
        mapping = alphabet or Alphabet()
        return "".join(mapping.one_to_zero.get(char, char) for char in text)
    if name == "spacing":
        return text.replace("\u00a0", " ")
    return text


def _clean_aggressive(text: str, alphabet: Alphabet) -> str:
    kept: list[str] = []
    for char in text:
        if char in {ZW_ZERO, ZW_ONE, "\u200d", "\ufeff"} or selector_to_byte(ord(char)) is not None:
            continue
        if is_tag(ord(char)) or char == TAG_TERM:
            continue
        if char == "\u00a0":
            kept.append(" ")
            continue
        kept.append(alphabet.one_to_zero.get(char, char))
    return "".join(kept)


def survival(text: str, settings: Settings, *, password: str | None, original: bytes | None) -> list[dict[str, Any]]:
    """Apply transformations to a copy and report whether a message still decodes."""
    transforms: list[tuple[str, str]] = [
        ("copy", text),
        ("nfc", unicodedata.normalize("NFC", text)),
        ("nfd", unicodedata.normalize("NFD", text)),
        ("nfkc", unicodedata.normalize("NFKC", text)),
        ("nfkd", unicodedata.normalize("NFKD", text)),
        ("trim", text.strip()),
        ("collapse-whitespace", " ".join(text.split())),
        ("crlf", text.replace("\r\n", "\n").replace("\n", "\r\n")),
        ("strip-format", "".join(char for char in text if unicodedata.category(char) != "Cf")),
        ("casefold", text.casefold()),
        ("utf8-roundtrip", text.encode("utf-8").decode("utf-8")),
    ]
    rows: list[dict[str, Any]] = []
    for name, changed in transforms:
        recoverable = False
        matches = False
        error = ""
        try:
            found = reveal(
                changed,
                settings,
                method_name=None,
                format_name="auto",
                placement="end",
                seed=0,
                length=None,
                password=password,
                find_all=False,
            )
            recoverable = True
            matches = original is None or found[0].payload == original
        except (NotFoundError, IntegrityError, ArgumentError, VerificationError) as exc:
            error = exc.__class__.__name__
        rows.append(
            {
                "transformation": name,
                "changed": changed != text,
                "recoverable": recoverable,
                "matches_original": matches,
                "error": error,
            }
        )
    return rows


def decode_output(recovered: Recovered) -> str | bytes:
    """Return text or exact bytes. Invalid UTF-8 is never replaced."""
    if recovered.binary:
        return recovered.payload
    try:
        return recovered.payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityError("Payload is not valid UTF-8. Pass --binary to write the bytes.") from exc
