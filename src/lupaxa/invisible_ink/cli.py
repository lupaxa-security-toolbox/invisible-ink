"""Command-line interface."""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

import typer
from click import ClickException

from lupaxa.invisible_ink import __version__
from lupaxa.invisible_ink.config import Settings, load_settings
from lupaxa.invisible_ink.engine import clean_text, decode_output, inspect_text, measure, survival
from lupaxa.invisible_ink.engine import hide as conceal
from lupaxa.invisible_ink.engine import reveal as recover
from lupaxa.invisible_ink.errors import ArgumentError, FilesystemError, InkError, IntegrityError, LimitError
from lupaxa.invisible_ink.methods import METHODS, Alphabet, validate_mapping
from lupaxa.invisible_ink.result import Result
from lupaxa.invisible_ink.textutil import PLACEMENTS

app = typer.Typer(add_completion=False, no_args_is_help=True)


class State:
    """Options shared by every command."""

    def __init__(self) -> None:
        self.settings = Settings()
        self.json = False
        self.quiet = False
        self.force = False
        self.non_interactive = False
        self.debug = False
        self.verbose = False


def _state(ctx: typer.Context) -> State:
    if not isinstance(ctx.obj, State):
        ctx.obj = State()
    return ctx.obj


def _emit(ctx: typer.Context, result: Result) -> None:
    if _state(ctx).json:
        sys.stdout.write(result.to_json() + "\n")
    elif not _state(ctx).quiet:
        for warning in result.warnings:
            typer.echo(f"warning: {warning}", err=True)


def _fail(ctx: typer.Context, command: str, exc: InkError) -> int:
    result = Result(command, success=False)
    result.add_error(exc.code, str(exc), exit_code=exc.exit_code)
    if _state(ctx).json:
        sys.stdout.write(result.to_json() + "\n")
    else:
        typer.echo(str(exc), err=True)
    return exc.exit_code


def _read_bytes(path: Path, limit: int) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise FilesystemError(f"Could not read {path}.") from exc
    if len(data) > limit:
        raise LimitError(f"{path} exceeds the configured size limit.")
    return data


def _read_text(path: Path, limit: int) -> str:
    data = _read_bytes(path, limit)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityError(f"{path} is not valid UTF-8.") from exc


def _password(ctx: typer.Context, path: Path | None, *, confirm: bool) -> str:
    if path is not None:
        text = _read_text(path, 4096)
        return text[:-1] if text.endswith("\n") else text
    if _state(ctx).non_interactive:
        raise ArgumentError("A password is required. Pass --password-file in non-interactive mode.")
    first = getpass.getpass("Password: ")
    if confirm:
        second = getpass.getpass("Confirm password: ")
        if first != second:
            raise ArgumentError("Passwords do not match.")
    if first == "":
        raise ArgumentError("Password must not be empty.")
    return first


def _write(path: Path | None, data: str | bytes, force: bool) -> None:
    if path is None:
        if isinstance(data, bytes):
            sys.stdout.buffer.write(data)
        else:
            sys.stdout.write(data)
        return
    if path.exists() and not force:
        raise FilesystemError(f"{path} already exists. Pass --force to replace it.")
    temporary = path.with_name(f".{path.name}.invisible-ink-tmp")
    try:
        if isinstance(data, bytes):
            temporary.write_bytes(data)
        else:
            temporary.write_bytes(data.encode("utf-8"))
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise FilesystemError(f"Could not write {path}.") from exc


def _mapping(path: Path | None) -> Alphabet | None:
    if path is None:
        return None
    import tomllib

    raw = tomllib.loads(_read_text(path, 1_048_576))
    pairs = raw.get("pairs")
    if not isinstance(pairs, list):
        raise ArgumentError("Homoglyph mapping needs a pairs array.")
    converted: list[tuple[str, str]] = []
    for item in pairs:
        if not isinstance(item, list) or len(item) != 2 or not all(isinstance(part, str) for part in item):
            raise ArgumentError("Each homoglyph pair must be two strings.")
        converted.append((item[0], item[1]))
    return validate_mapping(converted)


@app.callback()
def main_callback(
    ctx: typer.Context,
    config: Path | None = typer.Option(None, "--config", help="Load an explicit TOML configuration."),
    json_output: bool = typer.Option(False, "--json", is_flag=True, help="Emit a JSON result envelope."),
    quiet: bool = typer.Option(False, "--quiet", is_flag=True),
    verbose: bool = typer.Option(False, "--verbose", is_flag=True),
    debug: bool = typer.Option(False, "--debug", is_flag=True),
    no_colour: bool = typer.Option(False, "--no-colour", is_flag=True),
    non_interactive: bool = typer.Option(False, "--non-interactive", is_flag=True),
    force: bool = typer.Option(False, "--force", is_flag=True),
    version: bool = typer.Option(
        False,
        "--version",
        is_flag=True,
        is_eager=True,
        callback=lambda value: _version(value),
    ),
) -> None:
    """Conceal and recover messages in ordinary Unicode text."""
    if version:
        return
    state = State()
    state.verbose = verbose
    state.settings = load_settings(config)
    state.json = json_output
    state.quiet = quiet
    state.force = force
    state.non_interactive = non_interactive
    state.debug = debug
    if no_colour or not state.settings.colour:
        os.environ["NO_COLOR"] = "1"
    ctx.obj = state


def _version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.command()
def hide(  # noqa: PLR0913
    ctx: typer.Context,
    message: str | None = typer.Argument(None),
    message_file: Path | None = typer.Option(None, "--message-file"),
    message_stdin: bool = typer.Option(False, "--message-stdin", is_flag=True),
    binary: bool = typer.Option(False, "--binary", is_flag=True),
    cover: str | None = typer.Option(None, "--cover"),
    cover_file: Path | None = typer.Option(None, "--cover-file"),
    cover_stdin: bool = typer.Option(False, "--cover-stdin", is_flag=True),
    method: str | None = typer.Option(None, "--method"),
    format_name: str | None = typer.Option(None, "--format"),
    placement: str | None = typer.Option(None, "--placement"),
    seed: int = typer.Option(0, "--seed"),
    encrypt: bool = typer.Option(False, "--encrypt", is_flag=True),
    password_file: Path | None = typer.Option(None, "--password-file"),
    output: Path | None = typer.Option(None, "--output"),
    verify: bool = typer.Option(False, "--verify", is_flag=True),
    mapping: Path | None = typer.Option(None, "--mapping"),
) -> None:
    """Hide a message in cover text."""
    state = _state(ctx)
    payload = _message_bytes(state, message, message_file, message_stdin, binary)
    cover_text = _cover_text(state, cover, cover_file, cover_stdin)
    chosen_method = method or state.settings.method
    chosen_format = format_name or state.settings.format
    chosen_placement = placement or state.settings.placement
    if chosen_format not in {"framed", "raw"} or chosen_placement not in PLACEMENTS:
        raise ArgumentError("Format must be framed or raw, and placement must be a supported strategy.")
    password = _password(ctx, password_file, confirm=True) if encrypt else None
    text, warnings = conceal(
        cover_text,
        payload,
        state.settings,
        method_name=chosen_method,
        framed=chosen_format == "framed",
        placement=chosen_placement,
        seed=seed,
        password=password,
        binary=binary,
        alphabet=_mapping(mapping),
    )
    if verify:
        found = recover(
            text,
            state.settings,
            method_name=chosen_method,
            format_name=chosen_format,
            placement=chosen_placement,
            seed=seed,
            length=len(payload) if chosen_format == "raw" else None,
            password=password,
            find_all=False,
            alphabet=_mapping(mapping),
        )
        if found[0].payload != payload:
            raise IntegrityError("Round-trip verification failed.")
    result = Result("hide", data={"method": chosen_method, "format": chosen_format, "characters": len(text)})
    result.warnings.extend(warnings)
    if output is None and not state.json:
        _write(None, text, state.force)
        _emit(ctx, result)
        return
    if output is not None:
        _write(output, text, state.force)
        result.data["output"] = str(output)
    else:
        result.data["text"] = text
    _emit(ctx, result)


@app.command()
def reveal(  # noqa: PLR0913
    ctx: typer.Context,
    source: Path | None = typer.Argument(None),
    method: str | None = typer.Option(None, "--method"),
    format_name: str = typer.Option("auto", "--format"),
    password_file: Path | None = typer.Option(None, "--password-file"),
    seed: int = typer.Option(0, "--seed"),
    length: int | None = typer.Option(None, "--length"),
    output: Path | None = typer.Option(None, "--output"),
    binary: bool = typer.Option(False, "--binary", is_flag=True),
    find_all: bool = typer.Option(False, "--all", is_flag=True),
    placement: str | None = typer.Option(None, "--placement"),
    mapping: Path | None = typer.Option(None, "--mapping"),
) -> None:
    """Recover a concealed message."""
    state = _state(ctx)
    text = _source_text(state, source)
    needs_password = password_file is not None
    password = _password(ctx, password_file, confirm=False) if needs_password else None
    try:
        found = recover(
            text,
            state.settings,
            method_name=method,
            format_name=format_name if format_name != "auto" else "framed",
            placement=placement or state.settings.placement,
            seed=seed,
            length=length,
            password=password,
            find_all=find_all,
            alphabet=_mapping(mapping),
        )
    except ArgumentError as exc:
        if "encrypted" not in str(exc).lower() or state.non_interactive:
            raise
        password = _password(ctx, None, confirm=False)
        found = recover(
            text,
            state.settings,
            method_name=method,
            format_name=format_name if format_name != "auto" else "framed",
            placement=placement or state.settings.placement,
            seed=seed,
            length=length,
            password=password,
            find_all=find_all,
            alphabet=_mapping(mapping),
        )
    payloads: list[dict[str, object]] = []
    for item in found:
        item.binary = item.binary or binary
        rendered = decode_output(item)
        payloads.append({"method": item.method, "encrypted": item.encrypted, "bytes": len(item.payload)})
        if output is None and not state.json and not find_all:
            _write(None, rendered, state.force)
        elif output is not None and not find_all:
            _write(output, rendered, state.force)
    result = Result("reveal", data={"messages": payloads})
    if state.json and not find_all and output is None:
        rendered = decode_output(found[0])
        if isinstance(rendered, bytes):
            result.data["payload_hex"] = rendered.hex()
        else:
            result.data["text"] = rendered
    _emit(ctx, result)


@app.command()
def inspect(
    ctx: typer.Context,
    source: Path | None = typer.Argument(None),
    show_hidden: bool = typer.Option(False, "--show-hidden", is_flag=True),
    show_codepoints: bool = typer.Option(False, "--show-codepoints", is_flag=True),
    show_offsets: bool = typer.Option(False, "--show-offsets", is_flag=True),
    show_context: bool = typer.Option(False, "--show-context", is_flag=True),
    all_unicode: bool = typer.Option(False, "--all-unicode", is_flag=True),
) -> None:
    """Report invisible and suspicious Unicode without revealing payloads."""
    state = _state(ctx)
    text = _source_text(state, source)
    report = inspect_text(text, state.settings, show_all=all_unicode)
    if not (show_hidden or show_codepoints or show_offsets or show_context):
        report["locations"] = report["locations"][:20]
    result = Result("inspect", data=report)
    warning_list = report["warnings"]
    if isinstance(warning_list, list):
        result.warnings.extend(str(item) for item in warning_list)
    if not state.json:
        typer.echo(
            f"characters {report['characters']} utf8 {report['utf8_bytes']} "
            f"invisible {report['invisible']} selectors {report['variation_selectors']} tags {report['tag_characters']}"
        )
    _emit(ctx, result)


@app.command()
def clean(
    ctx: typer.Context,
    source: Path | None = typer.Argument(None),
    mode: str | None = typer.Option(None, "--mode"),
    method: str | None = typer.Option(None, "--method"),
    output: Path | None = typer.Option(None, "--output"),
    dry_run: bool = typer.Option(False, "--dry-run", is_flag=True),
    report: bool = typer.Option(False, "--report", is_flag=True),
    mapping: Path | None = typer.Option(None, "--mapping"),
) -> None:
    """Remove recognised concealment characters."""
    state = _state(ctx)
    text = _source_text(state, source)
    cleaned, warnings = clean_text(
        text,
        state.settings,
        mode=mode or state.settings.clean_mode,
        method_name=method,
        alphabet=_mapping(mapping),
    )
    result = Result("clean", data={"changed": cleaned != text, "characters": len(cleaned)}, warnings=warnings)
    if dry_run or report:
        result.data["removed"] = len(text) - len(cleaned)
    if not dry_run:
        if output is None and not state.json:
            _write(None, cleaned, state.force)
        elif output is not None:
            _write(output, cleaned, state.force)
        elif state.json:
            result.data["text"] = cleaned
    _emit(ctx, result)


@app.command()
def capacity(
    ctx: typer.Context,
    cover: str | None = typer.Option(None, "--cover"),
    cover_file: Path | None = typer.Option(None, "--cover-file"),
    cover_stdin: bool = typer.Option(False, "--cover-stdin", is_flag=True),
    method: str | None = typer.Option(None, "--method"),
    placement: str | None = typer.Option(None, "--placement"),
    seed: int = typer.Option(0, "--seed"),
    encrypt: bool = typer.Option(False, "--encrypt", is_flag=True),
    mapping: Path | None = typer.Option(None, "--mapping"),
) -> None:
    """Report how much payload a cover can hold."""
    state = _state(ctx)
    cover_text = _cover_text(state, cover, cover_file, cover_stdin)
    info = measure(
        cover_text,
        method or state.settings.method,
        state.settings,
        placement=placement or state.settings.placement,
        seed=seed,
        encrypt=encrypt,
        alphabet=_mapping(mapping),
    )
    result = Result(
        "capacity",
        data={
            "eligible": info.eligible,
            "raw_symbols": info.raw_symbols,
            "raw_bytes": info.raw_bytes,
            "framing_overhead": info.framing_overhead,
            "encryption_overhead": info.encryption_overhead,
            "max_payload": info.max_payload,
            "restrictions": info.restrictions,
        },
    )
    if not state.json:
        typer.echo(f"max payload {info.max_payload} bytes ({info.eligible} eligible positions)")
    _emit(ctx, result)


@app.command()
def verify(
    ctx: typer.Context,
    source: Path | None = typer.Argument(None),
    message: str | None = typer.Argument(None),
    message_file: Path | None = typer.Option(None, "--message-file"),
    password_file: Path | None = typer.Option(None, "--password-file"),
    method: str | None = typer.Option(None, "--method"),
    binary: bool = typer.Option(False, "--binary", is_flag=True),
) -> None:
    """Check that a concealed message recovers and optionally matches an original."""
    state = _state(ctx)
    text = _source_text(state, source)
    password = _password(ctx, password_file, confirm=False) if password_file else None
    found = recover(
        text,
        state.settings,
        method_name=method,
        format_name="framed",
        placement=state.settings.placement,
        seed=0,
        length=None,
        password=password,
        find_all=False,
    )
    expected = _optional_message(state, message, message_file, binary)
    matches = expected is None or found[0].payload == expected
    result = Result(
        "verify",
        success=matches,
        data={"recoverable": True, "matches": matches, "method": found[0].method},
    )
    if not matches:
        result.add_error("verification_failed", "Recovered payload does not match the original message.", exit_code=9)
        _emit(ctx, result)
        raise typer.Exit(9)
    _emit(ctx, result)


@app.command("test")
def survive_cmd(
    ctx: typer.Context,
    source: Path | None = typer.Argument(None),
    message_file: Path | None = typer.Option(None, "--message-file"),
    password_file: Path | None = typer.Option(None, "--password-file"),
    run_all: bool = typer.Option(False, "--all", is_flag=True),
) -> None:
    """Test whether a message survives common text transformations."""
    del run_all
    state = _state(ctx)
    text = _source_text(state, source)
    original = _read_bytes(message_file, state.settings.max_message_bytes) if message_file else None
    password = _password(ctx, password_file, confirm=False) if password_file else None
    rows = survival(text, state.settings, password=password, original=original)
    result = Result("test", data={"results": rows})
    if not state.json:
        for row in rows:
            typer.echo(f"{row['transformation']}: recoverable={row['recoverable']} changed={row['changed']}")
    _emit(ctx, result)


@app.command()
def methods(
    ctx: typer.Context,
    details: bool = typer.Option(False, "--details", is_flag=True),
) -> None:
    """List encoding methods."""
    state = _state(ctx)
    rows = []
    for _name, kind in METHODS.items():
        item = kind()
        rows.append(
            {
                "identifier": item.identifier,
                "description": item.description,
                "placements": list(PLACEMENTS),
                "framed": True,
                "raw": True,
                "capacity": "configured-limit" if item.inserts else "eligible-positions",
                "limitations": item.limitations,
            }
        )
        if not state.json:
            line = item.identifier if not details else f"{item.identifier}: {item.description}"
            typer.echo(line)
    _emit(ctx, Result("methods", data={"methods": rows}))


def _message_bytes(
    state: State,
    message: str | None,
    message_file: Path | None,
    message_stdin: bool,
    binary: bool,
) -> bytes:
    sources = [message is not None, message_file is not None, message_stdin]
    if sum(sources) != 1:
        raise ArgumentError("Provide exactly one of a message, --message-file, or --message-stdin.")
    if message_stdin:
        data = sys.stdin.buffer.read() if binary else sys.stdin.read().encode("utf-8")
    elif message_file is not None:
        data = _read_bytes(message_file, state.settings.max_message_bytes)
        if not binary:
            data.decode("utf-8")
    elif message is not None:
        data = message.encode("utf-8")
    else:
        raise ArgumentError("Provide exactly one message source.")
    if len(data) > state.settings.max_message_bytes:
        raise LimitError("Message exceeds the configured size limit.")
    return data


def _optional_message(state: State, message: str | None, message_file: Path | None, binary: bool) -> bytes | None:
    if message is None and message_file is None:
        return None
    return _message_bytes(state, message, message_file, False, binary)


def _cover_text(state: State, cover: str | None, cover_file: Path | None, cover_stdin: bool) -> str:
    sources = [cover is not None, cover_file is not None, cover_stdin]
    if sum(sources) != 1:
        raise ArgumentError("Provide exactly one of --cover, --cover-file, or --cover-stdin.")
    if cover_stdin:
        return _decode_stdin(state.settings.max_cover_bytes)
    if cover_file is not None:
        return _read_text(cover_file, state.settings.max_cover_bytes)
    if cover is None:
        raise ArgumentError("Provide exactly one cover source.")
    if len(cover.encode("utf-8")) > state.settings.max_cover_bytes:
        raise LimitError("Cover text exceeds the configured size limit.")
    return cover


def _source_text(state: State, source: Path | None) -> str:
    if source is None:
        return _decode_stdin(state.settings.max_cover_bytes)
    return _read_text(source, state.settings.max_cover_bytes)


def _decode_stdin(limit: int) -> str:
    data = sys.stdin.buffer.read()
    if len(data) > limit:
        raise LimitError("Standard input exceeds the configured size limit.")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityError("Standard input is not valid UTF-8.") from exc


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and translate failures into exit codes."""
    try:
        app(args=argv, standalone_mode=False)
    except ClickException as exc:
        exc.show()
        return int(exc.exit_code or 2)
    except InkError as exc:
        if "--json" in (argv or sys.argv):
            result = Result("invisible-ink", success=False)
            result.add_error(exc.code, str(exc), exit_code=exc.exit_code)
            sys.stdout.write(result.to_json() + "\n")
        else:
            typer.echo(str(exc), err=True)
        return exc.exit_code
    except typer.Exit as exc:
        return int(exc.exit_code or 0)
    except Exception:
        debug = "--debug" in (argv or sys.argv)
        if debug:
            raise
        typer.echo("Unexpected failure.", err=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
