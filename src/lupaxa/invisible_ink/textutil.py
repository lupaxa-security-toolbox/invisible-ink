"""Unicode helpers and bit packing."""

from __future__ import annotations

import hashlib
import hmac
import math
from typing import cast

import regex

from lupaxa.invisible_ink.errors import IntegrityError, UnsupportedError

PLACEMENTS = ("start", "end", "between-words", "distributed", "random")


def graphemes(text: str) -> list[str]:
    """Split text into extended grapheme clusters."""
    return cast(list[str], regex.findall(r"\X", text))


def utf8_len(text: str) -> int:
    """Return the UTF-8 size of text."""
    return len(text.encode("utf-8"))


def code_point_index(text: str, offset: int) -> int:
    """Return the code-point index of a code-point offset."""
    return offset


def byte_offset(text: str, code_index: int) -> int:
    """Return the UTF-8 byte offset of a code-point index."""
    return len("".join(list(text)[:code_index]).encode("utf-8"))


def bytes_to_bits(data: bytes) -> list[int]:
    """Expand bytes to a most-significant-bit-first bit list."""
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """Pack a bit list into bytes. A trailing partial byte is rejected."""
    if len(bits) % 8:
        raise IntegrityError("Encoded bit stream ends in a partial byte.")
    out = bytearray()
    for start in range(0, len(bits), 8):
        value = 0
        for bit in bits[start : start + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def take_bytes(bits: list[int], size: int) -> tuple[bytes, list[int]]:
    """Take a prefix of bits as bytes and return the remainder."""
    need = size * 8
    if len(bits) < need:
        raise IntegrityError("Encoded stream is shorter than the framed message.")
    return bits_to_bytes(bits[:need]), bits[need:]


def order_indexes(indexes: list[int], placement: str, seed: int) -> list[int]:
    """Return the canonical order of eligible positions."""
    if placement not in PLACEMENTS:
        raise UnsupportedError(f"Unknown placement {placement!r}.")
    if placement in {"start", "between-words"}:
        return list(indexes)
    if placement == "end":
        return list(reversed(indexes))
    if placement == "distributed":
        count = len(indexes)
        if count == 0:
            return []
        stride = 1
        for candidate in range(max(1, count // 2), count + 1):
            if math.gcd(candidate, count) == 1:
                stride = candidate
                break
        return [indexes[(position * stride) % count] for position in range(count)]
    if seed == 0:
        raise UnsupportedError("Random placement requires a non-zero --seed.")
    material = seed.to_bytes(8, "big")
    return sorted(indexes, key=lambda index: hmac.new(material, index.to_bytes(4, "big"), hashlib.sha256).digest())


def insertion_points(cluster_count: int, placement: str, seed: int, *, after_base: bool) -> list[int]:
    """Return grapheme-boundary indexes where symbols may be inserted.

    A boundary of ``n`` means after the first ``n`` graphemes. Variation
    selectors use only boundaries after a base grapheme.
    """
    start = 1 if after_base else 0
    points = list(range(start, cluster_count + 1))
    if not points:
        return []
    if placement == "start":
        return points
    if placement == "end":
        return list(reversed(points))
    if placement == "distributed":
        return order_indexes(points, "distributed", 0)
    if placement == "between-words":
        return points
    return order_indexes(points, "random", seed)


def spread_chunks(symbols: str, points: list[int]) -> list[tuple[int, str]]:
    """Split a symbol string into contiguous slices in document order."""
    ordered = sorted(set(points))
    if not ordered:
        raise UnsupportedError("The cover has no valid insertion position.")
    count = len(ordered)
    pieces: list[tuple[int, str]] = []
    start = 0
    for index, boundary in enumerate(ordered):
        take = len(symbols) // count + (1 if index < len(symbols) % count else 0)
        piece = symbols[start : start + take]
        start += take
        if piece:
            pieces.append((boundary, piece))
    return pieces


def insert_at_boundaries(text: str, pieces: list[tuple[int, str]]) -> str:
    """Insert symbol pieces at grapheme boundaries without splitting clusters."""
    clusters = graphemes(text)
    buckets: dict[int, list[str]] = {index: [] for index in range(len(clusters) + 1)}
    for boundary, piece in pieces:
        if boundary < 0 or boundary > len(clusters):
            raise UnsupportedError("Insertion boundary is outside the cover text.")
        buckets[boundary].append(piece)
    out: list[str] = []
    for index, cluster in enumerate(clusters):
        out.extend(buckets[index])
        out.append(cluster)
    out.extend(buckets[len(clusters)])
    return "".join(out)
