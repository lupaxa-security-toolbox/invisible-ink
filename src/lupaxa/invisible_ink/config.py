"""TOML configuration and precedence."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_config_dir

from lupaxa.invisible_ink.errors import ArgumentError, LimitError

APP_NAME = "invisible-ink"
APP_AUTHOR = "Lupaxa"


@dataclass
class Settings:
    """Resolved runtime limits and defaults."""

    method: str = "zero-width"
    format: str = "framed"
    placement: str = "end"
    max_message_bytes: int = 1_048_576
    max_cover_bytes: int = 8_388_608
    max_decoded_bytes: int = 1_048_576
    kdf_time_cost: int = 2
    kdf_memory_kib: int = 19_456
    kdf_parallelism: int = 1
    kdf_time_limit: int = 5
    kdf_memory_limit_kib: int = 262_144
    kdf_parallelism_limit: int = 4
    max_candidates: int = 32
    clean_mode: str = "conservative"
    colour: bool = True
    config_path: Path | None = None

    def check_kdf(self, time_cost: int, memory_kib: int, parallelism: int) -> None:
        """Reject KDF parameters outside the configured resource limits."""
        if time_cost < 1 or time_cost > self.kdf_time_limit:
            raise LimitError("Argon2 time cost is outside the configured limit.")
        if memory_kib < 8 or memory_kib > self.kdf_memory_limit_kib:
            raise LimitError("Argon2 memory cost is outside the configured limit.")
        if parallelism < 1 or parallelism > self.kdf_parallelism_limit:
            raise LimitError("Argon2 parallelism is outside the configured limit.")


def config_directory() -> Path:
    """Return the platform configuration directory."""
    return Path(user_config_dir(APP_NAME, APP_AUTHOR))


def _as_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArgumentError(f"Configuration {name} must be an integer.")
    return value


def _as_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ArgumentError(f"Configuration {name} must be a string.")
    return value


def _as_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ArgumentError(f"Configuration {name} must be a boolean.")
    return value


def load_settings(explicit: Path | None = None) -> Settings:
    """Load defaults, then the user file, then ``INVISIBLE_INK_*`` variables."""
    settings = Settings()
    path = explicit or (config_directory() / "config.toml")
    if path.is_file():
        settings.config_path = path
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise ArgumentError(f"Could not read configuration {path}.") from exc
        if not isinstance(raw, dict):
            raise ArgumentError("Configuration root must be a table.")
        _apply_table(settings, raw)
    _apply_env(settings)
    return settings


def _apply_table(settings: Settings, raw: dict[str, object]) -> None:
    mapping = {
        "method": ("method", _as_str),
        "format": ("format", _as_str),
        "placement": ("placement", _as_str),
        "max_message_bytes": ("max_message_bytes", _as_int),
        "max_cover_bytes": ("max_cover_bytes", _as_int),
        "max_decoded_bytes": ("max_decoded_bytes", _as_int),
        "kdf_time_cost": ("kdf_time_cost", _as_int),
        "kdf_memory_kib": ("kdf_memory_kib", _as_int),
        "kdf_parallelism": ("kdf_parallelism", _as_int),
        "kdf_time_limit": ("kdf_time_limit", _as_int),
        "kdf_memory_limit_kib": ("kdf_memory_limit_kib", _as_int),
        "kdf_parallelism_limit": ("kdf_parallelism_limit", _as_int),
        "max_candidates": ("max_candidates", _as_int),
        "clean_mode": ("clean_mode", _as_str),
        "colour": ("colour", _as_bool),
    }
    for key, (attr, cast) in mapping.items():
        if key in raw:
            setattr(settings, attr, cast(raw[key], key))


def _apply_env(settings: Settings) -> None:
    env_map = {
        "INVISIBLE_INK_METHOD": ("method", str),
        "INVISIBLE_INK_FORMAT": ("format", str),
        "INVISIBLE_INK_PLACEMENT": ("placement", str),
        "INVISIBLE_INK_MAX_MESSAGE_BYTES": ("max_message_bytes", int),
        "INVISIBLE_INK_MAX_COVER_BYTES": ("max_cover_bytes", int),
        "INVISIBLE_INK_MAX_DECODED_BYTES": ("max_decoded_bytes", int),
        "INVISIBLE_INK_KDF_TIME_COST": ("kdf_time_cost", int),
        "INVISIBLE_INK_KDF_MEMORY_KIB": ("kdf_memory_kib", int),
        "INVISIBLE_INK_KDF_PARALLELISM": ("kdf_parallelism", int),
        "INVISIBLE_INK_CLEAN_MODE": ("clean_mode", str),
    }
    for name, (attr, cast) in env_map.items():
        raw = os.environ.get(name)
        if raw is None or raw == "":
            continue
        try:
            value = cast(raw)
        except ValueError as exc:
            raise ArgumentError(f"Environment variable {name} is invalid.") from exc
        setattr(settings, attr, value)


def fast_settings() -> Settings:
    """Return inexpensive KDF settings for tests."""
    settings = Settings()
    settings.kdf_time_cost = 1
    settings.kdf_memory_kib = 8
    settings.kdf_parallelism = 1
    return settings
