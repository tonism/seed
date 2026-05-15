#!/usr/bin/env python3
"""Convert the source prompt.txt to a JSON-escaped binary blob.

Seed embeds the result via NASM `incbin` and streams the bytes as-is over
TLS to the OpenAI Responses API body's `instructions` field. Doing the
escape at build time keeps the runtime streamer tiny — Seed's resident
budget can't afford an escape routine on the 16 KiB target.

RFC 8259 string rules applied:
  - `"`  -> `\\"`
  - `\\`  -> `\\\\`
  - `\\n` (0x0A) -> `\\n`
  - `\\r` (0x0D) -> `\\r`
  - `\\t` (0x09) -> `\\t`
  - `\\b` (0x08) -> `\\b`
  - `\\f` (0x0C) -> `\\f`
  - other 0x00..0x1F -> `\\u00XX`
  - 0x20..0x7F printable ASCII -> literal byte
  - 0x80..0xFF passed through (assumed UTF-8; server tolerates)

Trailing newline in prompt.txt is preserved — JSON-encoding it to `\\n`
is fine; the model just sees a final newline.
"""

from __future__ import annotations

import sys
from pathlib import Path


SHORT_ESCAPES = {
    0x22: b"\\\"",
    0x5C: b"\\\\",
    0x08: b"\\b",
    0x09: b"\\t",
    0x0A: b"\\n",
    0x0C: b"\\f",
    0x0D: b"\\r",
}


def escape_byte(b: int) -> bytes:
    if b in SHORT_ESCAPES:
        return SHORT_ESCAPES[b]
    if b < 0x20:
        return f"\\u{b:04x}".encode("ascii")
    return bytes([b])


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: build-dpi-prompt.py <source.txt> <escaped.bin>", file=sys.stderr)
        return 2
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    data = src.read_bytes()
    out = b"".join(escape_byte(b) for b in data)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(out)
    print(
        f"build-dpi-prompt: {src} ({len(data)} B) -> {dst} ({len(out)} B, "
        f"+{len(out) - len(data)} from JSON escaping)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
