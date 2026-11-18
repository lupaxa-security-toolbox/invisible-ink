"""Versioned framed-message envelope.

The layout is big-endian and fixed at 96 bytes plus the body:

=======  ======  ============================================
Offset   Size    Field
=======  ======  ============================================
0        4       Magic ``INKI``
4        1       Format version (1)
5        1       Method identifier
6        1       Flags
7        1       Placement identifier
8        8       Seed used by random placement (0 otherwise)
16       4       Original payload length
20       4       Body length
24       4       Argon2 time cost (0 when unencrypted)
28       4       Argon2 memory in KiB
32       1       Argon2 parallelism
33       1       Encryption algorithm (1 = AES-256-GCM)
34       1       KDF identifier (1 = Argon2id)
35       1       Reserved, must be 0
36       16      Salt
52       12      Nonce
64       32      SHA-256 of the plaintext, or zeros when encrypted
96       body    Plaintext, or ciphertext including the GCM tag
=======  ======  ============================================

Flag bit 0 means encrypted. Flag bit 1 means the payload is binary.
Unencrypted integrity is SHA-256. It does not identify the sender.
Encrypted integrity is AES-GCM. A checksum of zeros is not a signature.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from lupaxa.invisible_ink.config import Settings
from lupaxa.invisible_ink.crypto import ALG_AES_GCM, KDF_ARGON2ID, TAG_LEN, Sealed
from lupaxa.invisible_ink.errors import IntegrityError, LimitError

MAGIC = b"INKI"
VERSION = 1
FLAG_ENCRYPTED = 0x01
FLAG_BINARY = 0x02
HEADER = struct.Struct(">4sBBBBQIIIIBBBB16s12s32s")
HEADER_LEN = HEADER.size

METHOD_IDS = {
    "zero-width": 1,
    "variation": 2,
    "spacing": 3,
    "homoglyph": 4,
    "tag": 5,
}
METHOD_NAMES = {value: key for key, value in METHOD_IDS.items()}
PLACEMENT_IDS = {"start": 0, "end": 1, "between-words": 2, "distributed": 3, "random": 4}
PLACEMENT_NAMES = {value: key for key, value in PLACEMENT_IDS.items()}


@dataclass
class Frame:
    """A parsed framed message."""

    method: str
    placement: str
    seed: int
    payload: bytes
    binary: bool
    encrypted: bool
    authenticated: bool
    declared_length: int = 0
    time_cost: int = 0
    memory_kib: int = 0
    parallelism: int = 0
    salt: bytes = b""
    nonce: bytes = b""
    body: bytes = b""


def build_frame(
    *,
    method: str,
    placement: str,
    seed: int,
    payload: bytes,
    binary: bool,
    sealed: Sealed | None,
) -> bytes:
    """Pack a framed message."""
    if method not in METHOD_IDS:
        raise IntegrityError(f"Unknown method {method!r}.")
    if placement not in PLACEMENT_IDS:
        raise IntegrityError(f"Unknown placement {placement!r}.")
    flags = FLAG_BINARY if binary else 0
    if sealed is None:
        body = payload
        checksum = hashlib.sha256(payload).digest()
        time_cost = memory_kib = parallelism = alg = kdf = 0
        salt = bytes(16)
        nonce = bytes(12)
    else:
        body = sealed.body
        checksum = bytes(32)
        flags |= FLAG_ENCRYPTED
        time_cost = sealed.time_cost
        memory_kib = sealed.memory_kib
        parallelism = sealed.parallelism
        alg = ALG_AES_GCM
        kdf = KDF_ARGON2ID
        salt = sealed.salt
        nonce = sealed.nonce
    if len(payload) > 0xFFFFFFFF or len(body) > 0xFFFFFFFF:
        raise LimitError("Payload exceeds the framed length field.")
    header = HEADER.pack(
        MAGIC,
        VERSION,
        METHOD_IDS[method],
        flags,
        PLACEMENT_IDS[placement],
        seed & 0xFFFFFFFFFFFFFFFF,
        len(payload),
        len(body),
        time_cost,
        memory_kib,
        parallelism,
        alg,
        kdf,
        0,
        salt,
        nonce,
        checksum,
    )
    return header + body


def parse_frames(data: bytes, settings: Settings) -> list[tuple[Frame, int]]:
    """Parse one or more frames. The integer is the exclusive end offset."""
    frames: list[tuple[Frame, int]] = []
    offset = 0
    while offset + HEADER_LEN <= len(data) and len(frames) < settings.max_candidates:
        if data[offset : offset + 4] != MAGIC:
            break
        try:
            fields = HEADER.unpack(data[offset : offset + HEADER_LEN])
        except struct.error as exc:
            raise IntegrityError("Framed header is truncated.") from exc
        (
            _magic,
            version,
            method_id,
            flags,
            placement_id,
            seed,
            payload_len,
            body_len,
            time_cost,
            memory_kib,
            parallelism,
            alg,
            kdf,
            _reserved,
            salt,
            nonce,
            checksum,
        ) = fields
        if version != VERSION:
            raise IntegrityError(f"Unsupported framed version {version}.")
        if method_id not in METHOD_NAMES or placement_id not in PLACEMENT_NAMES:
            raise IntegrityError("Framed method or placement is not supported.")
        if payload_len > settings.max_decoded_bytes or body_len > settings.max_decoded_bytes:
            raise LimitError("Framed length exceeds the configured limit.")
        end = offset + HEADER_LEN + body_len
        if end > len(data):
            raise IntegrityError("Framed body is truncated.")
        body = data[offset + HEADER_LEN : end]
        encrypted = bool(flags & FLAG_ENCRYPTED)
        if encrypted:
            if alg != ALG_AES_GCM or kdf != KDF_ARGON2ID:
                raise IntegrityError("Unsupported encryption metadata.")
            if body_len != payload_len + TAG_LEN:
                raise IntegrityError("Encrypted body length does not match the payload.")
            payload = b""
            authenticated = False
        else:
            if body_len != payload_len:
                raise IntegrityError("Plain body length does not match the payload.")
            digest = hashlib.sha256(body).digest()
            if digest != checksum:
                raise IntegrityError("Framed checksum does not match the payload.")
            payload = body
            authenticated = True
        frame = Frame(
            method=METHOD_NAMES[method_id],
            placement=PLACEMENT_NAMES[placement_id],
            seed=int(seed),
            payload=payload,
            binary=bool(flags & FLAG_BINARY),
            encrypted=encrypted,
            authenticated=authenticated,
            declared_length=int(payload_len),
            time_cost=int(time_cost),
            memory_kib=int(memory_kib),
            parallelism=int(parallelism),
            salt=bytes(salt),
            nonce=bytes(nonce),
            body=body,
        )
        frames.append((frame, end))
        offset = end
    return frames
