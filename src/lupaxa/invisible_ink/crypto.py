"""Password-based authenticated encryption."""

from __future__ import annotations

import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lupaxa.invisible_ink.config import Settings
from lupaxa.invisible_ink.errors import AuthenticationError, LimitError

ALG_AES_GCM = 1
KDF_ARGON2ID = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16


@dataclass
class Sealed:
    """Ciphertext with the parameters required to open it."""

    body: bytes
    salt: bytes
    nonce: bytes
    time_cost: int
    memory_kib: int
    parallelism: int


def _key(password: str, salt: bytes, time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    raw = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )
    return bytes(raw)


def seal(plaintext: bytes, password: str, settings: Settings) -> Sealed:
    """Encrypt plaintext with AES-256-GCM using an Argon2id key."""
    settings.check_kdf(settings.kdf_time_cost, settings.kdf_memory_kib, settings.kdf_parallelism)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _key(password, salt, settings.kdf_time_cost, settings.kdf_memory_kib, settings.kdf_parallelism)
    body = AESGCM(key).encrypt(nonce, plaintext, None)
    return Sealed(
        body=body,
        salt=salt,
        nonce=nonce,
        time_cost=settings.kdf_time_cost,
        memory_kib=settings.kdf_memory_kib,
        parallelism=settings.kdf_parallelism,
    )


def open_sealed(
    body: bytes,
    password: str,
    *,
    salt: bytes,
    nonce: bytes,
    time_cost: int,
    memory_kib: int,
    parallelism: int,
    settings: Settings,
) -> bytes:
    """Decrypt a sealed body or raise an authentication error."""
    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise AuthenticationError("Encryption salt or nonce has an invalid length.")
    if len(body) < TAG_LEN:
        raise AuthenticationError("Encrypted payload is truncated.")
    try:
        settings.check_kdf(time_cost, memory_kib, parallelism)
    except LimitError:
        raise
    key = _key(password, salt, time_cost, memory_kib, parallelism)
    try:
        return AESGCM(key).decrypt(nonce, body, None)
    except InvalidTag as exc:
        raise AuthenticationError("Password is incorrect or the ciphertext was modified.") from exc
