<p align="center">
  <a href="https://github.com/lupaxa-security-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/security-toolbox/readme-logo.png" alt="Security Toolbox" />
  </a>
</p>

<h1 align="center">Invisible Ink</h1>

Invisible Ink conceals and recovers messages in ordinary Unicode text. It runs offline and does not use the network.

Concealment is not encryption. Hidden characters can be found by looking at code points, and many editors remove them. Use `--encrypt` when the payload must stay secret.

## Install

Python 3.11 or newer:

```bash
pip install lupaxa-invisible-ink
```

The command is `invisible-ink`.

## Quick Start

```bash
invisible-ink hide "Meet at nine" --cover "See you tomorrow!" --method zero-width
invisible-ink reveal encoded.txt
invisible-ink capacity --method homoglyph --cover-file notes.txt
```

## What it Does

- Hides UTF-8 text or explicit binary payloads with five Unicode methods.
- Recovers framed messages and checks their integrity.
- Encrypts payloads with AES-256-GCM and Argon2id when asked.
- Reports capacity, suspicious characters, and survival under text transforms.
- Cleans recognised concealment in conservative or aggressive mode.
- Writes JSON envelopes and stable exit codes for scripts.

## Commands

Global options come before the subcommand.

| Option              | Effect                                 |
| ------------------- | -------------------------------------- |
| `--config PATH`     | Load a TOML file                       |
| `--json`            | Print a JSON envelope on stdout        |
| `--quiet`           | Hide warnings                          |
| `--verbose`         | More diagnostic detail                 |
| `--debug`           | Show a traceback for unexpected errors |
| `--no-colour`       | Plain text                             |
| `--non-interactive` | Do not prompt                          |
| `--force`           | Replace an existing output file        |
| `--version`         | Print the version                      |
| `--help`            | Show help                              |

Defaults are `--method zero-width`, `--format framed`, and `--placement end`. A password is prompted, or read from `--password-file`. It is not a command argument.

| Command    | Purpose                         | Main options                                                                                          |
| ---------- | ------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `hide`     | Conceal a message in cover text | One message and one cover: a string, a file, or stdin. `--binary`, `--encrypt`, `--verify`, `--seed`  |
| `reveal`   | Recover a concealed message     | A file or stdin. `--format auto` or `raw`. Raw needs `--method` and, except for `tag`, `--length`     |
| `inspect`  | Report unusual Unicode          | Counts and locations. Does not decrypt. `--show-codepoints`, `--show-offsets`, `--all-unicode`        |
| `clean`    | Remove recognised concealment   | `--mode conservative` or `aggressive`. `--dry-run`, `--output`                                        |
| `capacity` | Report how much payload fits    | Eligible positions, overhead, and the maximum payload. `--encrypt` includes the tag                   |
| `verify`   | Check that a message recovers   | Optional original message or `--message-file`. A mismatch exits 9                                     |
| `test`     | Try transforms on a copy        | Normalisation, trim, collapsed space, newlines, case, and UTF-8. The source file stays unchanged      |
| `methods`  | List the five methods           | `--details`                                                                                           |

`reveal --all` returns every confirmed frame. `reveal --binary` writes bytes exactly and does not replace invalid UTF-8. Conservative cleaning removes symbols only after a frame validates, and it leaves ambiguous characters in place.
Aggressive cleaning can change legitimate text. Neither mode restores every original.

## Encoding Methods

### Zero-Width

Identifier `zero-width`. U+200B is bit 0 and U+200C is bit 1, most-significant bit first. Symbols are inserted on grapheme boundaries. These characters can affect shaping and are often removed.

```bash
invisible-ink hide "Meet at nine" --cover "See you tomorrow!" --method zero-width
invisible-ink reveal encoded.txt --method zero-width
```

### Variation

Identifier `variation`. Bytes 0–15 map to U+FE00–U+FE0F. Bytes 16–255 map to U+E0100–U+E01EF. Selectors attach after an existing grapheme, so an empty cover has no capacity. Rendering can change, and some stacks drop selectors.

```bash
invisible-ink hide "note" --cover "Hello" --method variation
invisible-ink reveal encoded.txt --method variation
```

### Spacing

Identifier `spacing`. Existing U+0020 is bit 0 and U+00A0 is bit 1. The encoder never inserts a new visible space. A framed message needs 768 eligible spaces before any payload. Wrapping and normalisation can destroy the bits.

```bash
invisible-ink hide "gap" --cover-file spaced.txt --method spacing
invisible-ink reveal encoded.txt --method spacing --placement end
```

### Homoglyph

Identifier `homoglyph`. Alphabet `homoglyph-1` maps `a e o p c x y` and `A E O P C X` to the Cyrillic letters а е о р с х у and А Е О Р С Х. Bit 0 keeps the Latin character. Bit 1 uses the pair. Each custom `--mapping` pair is two distinct
characters, and no character may repeat.

```toml
pairs = [["a", "а"], ["e", "е"]]
```

The cover needs enough eligible letters for the frame. Mixed-script checks may flag the result. Fonts do not render every pair identically.

```bash
invisible-ink hide "hi" --cover-file letters.txt --method homoglyph
invisible-ink reveal encoded.txt --method homoglyph --placement end
```

### Tag

Identifier `tag`. The payload is base64. Each ASCII character becomes U+E0000 plus that character's code point, and U+E007F terminates the sequence. Raw mode can use the terminator instead of `--length`. Tags may be stripped.

```bash
invisible-ink hide "note" --cover "Hello" --method tag
invisible-ink reveal encoded.txt --method tag
```

## Placement

`start`, `end`, `between-words`, `distributed`, and `random` are accepted when the method has the required positions. Replacement methods read bits in document order, reversed order, a coprime stride, whitespace-adjacent letters, or
HMAC-SHA256 order for `--seed`. Random replacement decoding needs the same `--seed`. Insertion methods keep symbol order, so the seed only chooses a boundary.

`between-words` needs whitespace. Variation selectors are never placed before the first grapheme.

## Framed Format

`framed` is the default. The header is 96 bytes, big-endian.

| Offset | Size | Field                                       |
| ------ | ---- | ------------------------------------------- |
| 0      | 4    | Magic `INKI`                                |
| 4      | 1    | Version `1`                                 |
| 5      | 1    | Method id                                   |
| 6      | 1    | Flags                                       |
| 7      | 1    | Placement id                                |
| 8      | 8    | Seed                                        |
| 16     | 4    | Payload length                              |
| 20     | 4    | Body length                                 |
| 24     | 4    | Argon2 time                                 |
| 28     | 4    | Argon2 memory KiB                           |
| 32     | 1    | Argon2 parallelism                          |
| 33     | 1    | Cipher id, 1 = AES-256-GCM                  |
| 34     | 1    | KDF id, 1 = Argon2id                        |
| 35     | 1    | Reserved 0                                  |
| 36     | 16   | Salt                                        |
| 52     | 12   | Nonce                                       |
| 64     | 32   | SHA-256 of plaintext, or zeros if encrypted |
| 96     | body | Plaintext or ciphertext with GCM tag        |

Method ids are 1 `zero-width`, 2 `variation`, 3 `spacing`, 4 `homoglyph`, 5 `tag`. Flag bit 0 means encrypted. Flag bit 1 means binary. Declared lengths above the configured limit are rejected before the body is used. SHA-256 detects
corruption. It does not identify a sender.

## Raw Mode

`--format raw` stores the payload without the header. Decoding requires `--method`. `zero-width`, `variation`, `spacing`, and `homoglyph` also require `--length` in bytes. A partial trailing byte is an error. `tag` uses the U+E007F
terminator. Raw mode is for experiments. It is not a claim of undetectability.

## Encryption

`--encrypt` seals the payload with AES-256-GCM. The key is Argon2id. Salt and nonce are random. Untrusted KDF parameters are checked against the configured time, memory, and parallelism limits before derivation. A wrong password or a
modified tag fails closed and does not write plaintext. Encryption hides content, not the fact that unusual Unicode is present.

## JSON

`--json` prints one object and nothing else on standard output:

```json
{
  "schema_version": 1,
  "command": "inspect",
  "success": true,
  "data": {},
  "warnings": [],
  "errors": []
}
```

Errors use `code`, `message`, and `exit_code`. Encoded text is a file, or the `data.text` field, never a second stream mixed into the JSON.

## Exit Codes

| Code | Meaning                                  |
| ---- | ---------------------------------------- |
| 0    | Success                                  |
| 1    | General failure                          |
| 2    | Invalid arguments or configuration       |
| 3    | Unsupported method, format, or placement |
| 4    | Insufficient capacity                    |
| 5    | No recognised message                    |
| 6    | Corrupted or invalid encoded message     |
| 7    | Authentication or decryption failure     |
| 8    | File or permission error                 |
| 9    | Verification failure                     |
| 10   | Resource limit exceeded                  |

Expected errors do not print a traceback unless `--debug` is set.

## Configuration

A file is optional. The user file is the platform config directory for `invisible-ink` / `Lupaxa` / `config.toml`. `--config` selects another file. Environment variables override the file and use the `INVISIBLE_INK_` prefix, for example
`INVISIBLE_INK_METHOD`. Explicit CLI options override both.

```toml
method = "zero-width"
format = "framed"
placement = "end"
max_message_bytes = 1048576
max_cover_bytes = 8388608
max_decoded_bytes = 1048576
kdf_time_cost = 2
kdf_memory_kib = 19456
kdf_parallelism = 1
clean_mode = "conservative"
colour = true
```

## Troubleshooting

- `spacing` or `homoglyph` reports insufficient capacity when the cover lacks enough spaces or mapped letters for the 96-byte header.
- `variation` needs at least one base character.
- Reveal a replacement message with the same `--placement` used to hide it. Random replacement also needs the same `--seed`.
- A run of zero-width marks without a valid frame is a candidate, not a recovered message.
- If reveal says the text is not UTF-8, the file is not a text cover. Payloads that are not UTF-8 need `--binary`.

## Security

Do not describe any method as undetectable. Inspect code points. Prefer `--encrypt` when confidentiality matters. The tool does not log passwords, derived keys, or decrypted payloads. Cleaning cannot promise that arbitrary Unicode returns
to a previous original.

<a href="https://github.com/the-lupaxa-project">
  <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
