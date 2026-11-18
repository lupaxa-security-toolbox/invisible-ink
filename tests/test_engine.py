"""Encoding, encryption, inspection, and CLI behaviour."""

import json
import struct
from pathlib import Path

import pytest

from lupaxa.invisible_ink.cli import main
from lupaxa.invisible_ink.config import Settings, fast_settings
from lupaxa.invisible_ink.crypto import open_sealed, seal
from lupaxa.invisible_ink.engine import clean_text, hide, inspect_text, measure, reveal
from lupaxa.invisible_ink.errors import (
    ArgumentError,
    AuthenticationError,
    CapacityError,
    IntegrityError,
    LimitError,
    NotFoundError,
)
from lupaxa.invisible_ink.frame import HEADER, parse_frames
from lupaxa.invisible_ink.methods import validate_mapping

MESSAGES = [
    "",
    "a",
    "Meet at nine",
    "café 東京",
    "emoji 😀",
    "👨‍👩‍👧‍👦",
]


@pytest.mark.parametrize("method", ["zero-width", "variation", "tag"])
@pytest.mark.parametrize("message", MESSAGES)
def test_insertion_round_trip(method: str, message: str) -> None:
    settings = fast_settings()
    cover = "See you tomorrow! مرحبا"
    text, warnings = hide(
        cover,
        message.encode(),
        settings,
        method_name=method,
        framed=True,
        placement="end",
        seed=0,
        password=None,
        binary=False,
    )
    assert warnings
    found = reveal(
        text,
        settings,
        method_name=method,
        format_name="framed",
        placement="end",
        seed=0,
        length=None,
        password=None,
        find_all=False,
    )
    assert found[0].payload == message.encode()
    assert found[0].authenticated


def test_binary_and_raw_zero_width() -> None:
    settings = fast_settings()
    payload = bytes(range(32))
    text, _warnings = hide(
        "cover",
        payload,
        settings,
        method_name="zero-width",
        framed=False,
        placement="start",
        seed=0,
        password=None,
        binary=True,
    )
    found = reveal(
        text,
        settings,
        method_name="zero-width",
        format_name="raw",
        placement="start",
        seed=0,
        length=len(payload),
        password=None,
        find_all=False,
    )
    assert found[0].payload == payload


def test_spacing_and_homoglyph_need_capacity() -> None:
    settings = fast_settings()
    with pytest.raises(CapacityError):
        hide(
            "short cover",
            b"hi",
            settings,
            method_name="spacing",
            framed=True,
            placement="end",
            seed=0,
            password=None,
            binary=False,
        )
    cover = "a" * 900
    text, _warnings = hide(
        cover,
        b"hi",
        settings,
        method_name="homoglyph",
        framed=True,
        placement="end",
        seed=0,
        password=None,
        binary=False,
    )
    found = reveal(
        text,
        settings,
        method_name="homoglyph",
        format_name="framed",
        placement="end",
        seed=0,
        length=None,
        password=None,
        find_all=False,
    )
    assert found[0].payload == b"hi"
    info = measure(cover, "homoglyph", settings, placement="end", seed=0, encrypt=False)
    assert info.max_payload > 0
    assert info.framing_overhead == 96


def test_spacing_round_trip() -> None:
    settings = fast_settings()
    cover = " " * 900
    text, _warnings = hide(
        cover,
        b"gap",
        settings,
        method_name="spacing",
        framed=True,
        placement="start",
        seed=0,
        password=None,
        binary=False,
    )
    found = reveal(
        text,
        settings,
        method_name="spacing",
        format_name="framed",
        placement="start",
        seed=0,
        length=None,
        password=None,
        find_all=False,
    )
    assert found[0].payload == b"gap"


def test_encryption_round_trip_and_failure() -> None:
    settings = fast_settings()
    text, _warnings = hide(
        "hello",
        b"secret",
        settings,
        method_name="zero-width",
        framed=True,
        placement="end",
        seed=0,
        password="correct horse",
        binary=False,
    )
    found = reveal(
        text,
        settings,
        method_name="zero-width",
        format_name="framed",
        placement="end",
        seed=0,
        length=None,
        password="correct horse",
        find_all=False,
    )
    assert found[0].payload == b"secret"
    with pytest.raises(AuthenticationError) as exc:
        reveal(
            text,
            settings,
            method_name="zero-width",
            format_name="framed",
            placement="end",
            seed=0,
            length=None,
            password="wrong",
            find_all=False,
        )
    assert "correct horse" not in str(exc.value)
    sealed = seal(b"", "pw", settings)
    sealed.body = sealed.body[:-1] + bytes([sealed.body[-1] ^ 1])
    with pytest.raises(AuthenticationError):
        open_sealed(
            sealed.body,
            "pw",
            salt=sealed.salt,
            nonce=sealed.nonce,
            time_cost=sealed.time_cost,
            memory_kib=sealed.memory_kib,
            parallelism=sealed.parallelism,
            settings=settings,
        )


def test_invalid_kdf_and_mapping() -> None:
    settings = Settings()
    with pytest.raises(LimitError):
        settings.check_kdf(100, 8, 1)
    with pytest.raises(ArgumentError):
        validate_mapping([("a", "a")])
    with pytest.raises(ArgumentError):
        validate_mapping([("a", "b"), ("b", "c")])


def test_inspect_and_clean() -> None:
    settings = fast_settings()
    text, _warnings = hide(
        "visible",
        b"hidden",
        settings,
        method_name="zero-width",
        framed=True,
        placement="end",
        seed=0,
        password=None,
        binary=False,
    )
    report = inspect_text(text, settings, show_all=False)
    assert report["invisible"] > 0
    assert "hidden" not in json.dumps(report)
    cleaned, notes = clean_text(text, settings, mode="conservative", method_name="zero-width")
    assert cleaned == "visible"
    assert notes
    aggressive, warnings = clean_text("ok\u200b", settings, mode="aggressive", method_name=None)
    assert aggressive == "ok"
    assert warnings


def test_candidate_is_not_confirmed() -> None:
    settings = fast_settings()
    with pytest.raises(NotFoundError):
        reveal(
            "plain\u200b\u200c",
            settings,
            method_name="zero-width",
            format_name="framed",
            placement="end",
            seed=0,
            length=None,
            password=None,
            find_all=False,
        )


def test_huge_declared_length_is_rejected() -> None:
    header = bytearray(96)
    header[0:4] = b"INKI"
    header[4] = 1
    header[5] = 1
    struct.pack_into(">I", header, 20, 50_000_000)
    with pytest.raises(LimitError):
        parse_frames(bytes(header), Settings())


def test_truncated_frame() -> None:
    header = bytearray(96)
    header[0:4] = b"INKI"
    header[4] = 1
    header[5] = 1
    struct.pack_into(">I", header, 16, 4)
    struct.pack_into(">I", header, 20, 4)
    with pytest.raises(IntegrityError):
        parse_frames(bytes(header), Settings())


def test_cli_streams_and_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--version"])
    assert code == 0
    assert capsys.readouterr().out.strip().count(".") >= 2
    code = main(["--json", "hide", "Meet at nine", "--cover", "See you tomorrow!", "--method", "zero-width"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["success"] is True
    output = tmp_path / "out.txt"
    output.write_text("keep", encoding="utf-8")
    code = main(["hide", "x", "--cover", "y", "--output", str(output)])
    assert code == 8
    missing = main(["reveal", str(tmp_path / "missing.txt")])
    assert missing == 8
    code = main(["hide"])
    assert code == 2
    encoded = tmp_path / "encoded.txt"
    assert main(["hide", "hi", "--cover", "hello", "--output", str(encoded)]) == 0
    assert main(["reveal", str(encoded), "--output", str(tmp_path / "back.txt")]) == 0
    assert (tmp_path / "back.txt").read_text(encoding="utf-8") == "hi"
    assert main(["--json", "methods"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed["data"]["methods"]) == 5


def test_header_size() -> None:
    assert HEADER.size == 96
