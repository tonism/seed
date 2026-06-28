#!/usr/bin/env python3
"""Create and inspect ENV.DAT — Seed's persisted environment snapshot.

ENV.DAT is the env save/load file (notes/env-save-load-design.md). It carries TWO things, for two
different audiences:
  - the conversation window + arena ("region") -> restored into chat_context_start, for the MODEL
    (rides into the request so the agent remembers);
  - a literal screen snapshot (the video text buffer, char+attr cells) -> painted back to video
    memory verbatim, for the USER (so they land on the EXACT screen they left -- dim tool lines,
    prompts, wrapping and all -- not a semantic reconstruction of the window).
Seed writes it on `$s` and restores it after boot. This tool builds and inspects one OFFLINE, so the
boot-side RESTORE path can be validated against a known-good file before the on-target SAVE path
exists. It is the format's reference implementation; layout.inc mirrors these constants in asm and
the two must agree.

Format 2 (little-endian) -- the payload is TRIMMED to skip dead space so a save fits a floppy and
restores fast:
  - the region drops its TRAILING ZEROS (store region_stored of the full region_len);
  - the screen is PER-ROW trailing-blank trimmed: [screen_rows row-length bytes][packed used cells],
    a blank cell being a space (0x20). region_len / screen_cols / screen_rows stay the FULL extents
    (the restore uses them to clear the window/screen before painting the stored prefix).

  off   sz  field
  0x00  4   magic "SEDV"            (distinct from the handoff "SEED")
  0x04  1   format_version          (compatibility axis; seed gates min<=v<=current; 2 = trimmed)
  0x05  1   flags                   (reserved, 0)
  0x06  2   build_number            (provenance, informational)
  0x08  2   ram_top                 (save-time RAM top; a hint for the restore warning)
  0x0a  2   chat_context_len_var    (the OLD window/arena split boundary)
  0x0c  2   chat_context_used       (valid conversation bytes in the window)
  0x0e  2   note_len                (compacted-memory prefix length within the window)
  0x10  2   region_len              (FULL window+arena extent -> chat_context_start)
  0x12  2   region_stored           (region bytes in the file; trailing zeros trimmed, <= region_len)
  0x14  1   screen_cols             (FULL snapshot width; 0 = no snapshot)
  0x15  1   screen_rows             (FULL snapshot height)
  0x16  2   screen_stored           (encoded screen bytes: screen_rows + 2*sum(row_len))
  0x18  2   payload_checksum        (16-bit sum of the payload: region_stored + screen_stored bytes)
  0x1a  2   header_checksum         (16-bit sum of header bytes 0x00..0x1a)
  0x1c  ..  payload: [region_stored region bytes][screen_stored encoded-screen bytes]

The region block (full region_len, conceptually):
  [0 .. used)            conversation window     [0..note_len) note, [note_len..used) dialogue
  [used .. len_var)      unused window slack
  [len_var .. region_len) the arena (agent $w-built bytes; 0 if empty)
...but only region_stored bytes (up to the last non-zero) are stored; the rest is restored as zero.
The screen is row-major char+attr cells; per row, trailing spaces are dropped and the count kept.

Usage:
  env-dat.py create --out FILE --conversation "You: hi\\nAssistant: Hello!" \\
      [--note-len 0] [--window-cap N] [--arena SIZE] [--region-len N] \\
      [--screen "line1\\nline2"] [--screen-cols 80] [--screen-rows 25] \\
      [--ram-top 0x8000] [--build 12] [--format-version 2]
  env-dat.py inspect FILE
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGIC = b"SEDV"
FORMAT_VERSION = 2          # current; layout.inc env_format_current mirrors this
HEADER_LEN = 0x1c           # bytes before the payload (magic..header_checksum)
_HEADER_FMT = "<4sBBHHHHHHHBBHH"  # ...through payload_checksum (0x1a bytes); header_checksum (H) follows
DEFAULT_ATTR = 0x07         # synthesized-snapshot cell attribute (real saves capture the live attrs)
BLANK_CHAR = 0x20           # a cell whose char is a space is "blank" (trimmable / fill on restore)


def checksum16(data: bytes) -> int:
    """16-bit additive byte sum — corruption detection, not crypto (the file is the agent's own
    non-secret state). Cheap on the 8088: zero a word, add each zero-extended byte."""
    return sum(data) & 0xFFFF


def trim_region(region: bytes) -> bytes:
    """Trailing-zero trim: the stored region prefix is everything up to the last non-zero byte."""
    i = len(region)
    while i > 0 and region[i - 1] == 0:
        i -= 1
    return region[:i]


def encode_screen(cells: bytes, cols: int, rows: int) -> bytes:
    """Per-row trailing-blank trim. cells = rows*cols char+attr pairs (row-major). The encoding is
    [rows row-length bytes][for each row, row_len char+attr pairs]; row_len is the column after the
    last non-blank char (0 for a blank row)."""
    row_lens = []
    for r in range(rows):
        rl = 0
        for c in range(cols):
            if cells[(r * cols + c) * 2] != BLANK_CHAR:
                rl = c + 1
        row_lens.append(rl)
    enc = bytearray(row_lens)
    for r in range(rows):
        for c in range(row_lens[r]):
            base = (r * cols + c) * 2
            enc.append(cells[base])
            enc.append(cells[base + 1])
    return bytes(enc)


def decode_screen(enc: bytes, cols: int, rows: int, clear_attr: int = DEFAULT_ATTR) -> bytes:
    """Inverse of encode_screen: clear to space+clear_attr, then paint each row's stored cells."""
    cells = bytearray()
    for _ in range(rows * cols):
        cells += bytes((BLANK_CHAR, clear_attr))
    row_lens = enc[:rows]
    p = rows
    for r in range(rows):
        for c in range(row_lens[r]):
            base = (r * cols + c) * 2
            cells[base] = enc[p]
            cells[base + 1] = enc[p + 1]
            p += 2
    return bytes(cells)


def build(*, format_version: int, flags: int, build_number: int, ram_top: int,
          window_cap: int, used: int, note_len: int, region_len: int, region: bytes,
          screen_cols: int, screen_rows: int, screen_cells: bytes) -> bytes:
    if len(region) != region_len:
        raise ValueError(f"region is {len(region)} bytes, expected region_len({region_len})")
    if len(screen_cells) != screen_cols * screen_rows * 2:
        raise ValueError(f"screen is {len(screen_cells)} bytes, expected {screen_cols*screen_rows*2}")
    if not (note_len <= used <= window_cap <= region_len):
        raise ValueError(f"field order violated: note_len({note_len}) <= used({used}) <= "
                         f"window_cap({window_cap}) <= region_len({region_len})")
    region_stored = trim_region(region)
    screen_enc = encode_screen(screen_cells, screen_cols, screen_rows) if screen_cols else b""
    payload = region_stored + screen_enc
    head = struct.pack(_HEADER_FMT, MAGIC, format_version, flags, build_number, ram_top,
                       window_cap, used, note_len, region_len, len(region_stored),
                       screen_cols, screen_rows, len(screen_enc), checksum16(payload))
    assert len(head) == 0x1a, f"header pre-checksum is {len(head)} bytes, expected 0x1a"
    head += struct.pack("<H", checksum16(head))
    return head + payload


def parse(blob: bytes) -> dict:
    if len(blob) < HEADER_LEN:
        raise ValueError(f"file is {len(blob)} bytes, shorter than the {HEADER_LEN}-byte header")
    (magic, ver, flags, build_number, ram_top, window_cap, used, note_len, region_len,
     region_stored, screen_cols, screen_rows, screen_stored, payload_ck) = \
        struct.unpack(_HEADER_FMT, blob[:0x1a])
    stored_hck = struct.unpack("<H", blob[0x1a:0x1c])[0]
    header_ok = checksum16(blob[:0x1a]) == stored_hck
    payload = blob[HEADER_LEN:HEADER_LEN + region_stored + screen_stored]
    payload_present = len(payload) == region_stored + screen_stored
    payload_ok = payload_present and checksum16(payload) == payload_ck
    region = b""
    screen_cells = b""
    if payload_present:
        region = payload[:region_stored] + b"\x00" * (region_len - region_stored)
        if screen_cols:
            screen_cells = decode_screen(payload[region_stored:], screen_cols, screen_rows)
    return {
        "magic": magic, "magic_ok": magic == MAGIC,
        "format_version": ver, "flags": flags, "build_number": build_number,
        "ram_top": ram_top, "window_cap": window_cap, "used": used,
        "note_len": note_len, "region_len": region_len, "region_stored": region_stored,
        "screen_cols": screen_cols, "screen_rows": screen_rows, "screen_stored": screen_stored,
        "header_checksum_ok": header_ok,
        "payload_present": payload_present, "payload_checksum_ok": payload_ok,
        "window": region, "screen_cells": screen_cells,
    }


def _auto_int(s: str) -> int:
    return int(s, 0)


def _synthesize_screen(text: str, cols: int, rows: int, attr: int) -> bytes:
    """Build a cols*rows char+attr cell buffer from text lines, like a CGA/MDA text page. Real saves
    capture the live video buffer (true per-cell attributes); this uniform-attr synthesis is for
    testing the restore PAINT path."""
    cells = bytearray()
    lines = text.split("\n")
    for r in range(rows):
        line = lines[r] if r < len(lines) else ""
        for c in range(cols):
            ch = line[c] if c < len(line) else " "
            cells.append(ord(ch) & 0xFF)
            cells.append(attr)
    return bytes(cells)


def cmd_create(args: argparse.Namespace) -> int:
    window = args.conversation.encode("latin-1", "replace").replace(b"\\n", b"\n")
    if args.window_file:
        window = Path(args.window_file).read_bytes()
    used = len(window)
    window_cap = args.window_cap if args.window_cap is not None else used
    arena = b"\x00" * args.arena
    region_len = args.region_len if args.region_len is not None else window_cap + len(arena)
    if window_cap + len(arena) > region_len:
        print(f"error: arena overflows region_len", file=sys.stderr)
        return 2
    region = bytearray(region_len)
    region[:used] = window
    region[window_cap:window_cap + len(arena)] = arena

    screen_cells = b""
    screen_cols = screen_rows = 0
    if args.screen is not None:
        screen_cols, screen_rows = args.screen_cols, args.screen_rows
        text = args.screen.replace("\\n", "\n")
        screen_cells = _synthesize_screen(text, screen_cols, screen_rows, DEFAULT_ATTR)

    try:
        blob = build(format_version=args.format_version, flags=0, build_number=args.build,
                     ram_top=args.ram_top, window_cap=window_cap, used=used, note_len=args.note_len,
                     region_len=region_len, region=bytes(region),
                     screen_cols=screen_cols, screen_rows=screen_rows, screen_cells=screen_cells)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    Path(args.out).write_bytes(blob)
    info = parse(blob)
    print(f"wrote {args.out}: {len(blob)} bytes (header 0x{HEADER_LEN:x} + region "
          f"{info['region_stored']}/{region_len} + screen {info['screen_stored']}/{screen_cols*screen_rows*2})")
    print(f"  used={used} note_len={args.note_len} window_cap={window_cap} region_len={region_len} "
          f"screen={screen_cols}x{screen_rows} ram_top=0x{args.ram_top:04x} build={args.build} v{args.format_version}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    blob = Path(args.file).read_bytes()
    try:
        f = parse(blob)
    except ValueError as exc:
        print(f"UNREADABLE: {exc}", file=sys.stderr)
        return 1
    ok = lambda b: "ok" if b else "BAD"
    print(f"file: {args.file} ({len(blob)} bytes)")
    print(f"  magic            {f['magic']!r}  [{ok(f['magic_ok'])}]")
    print(f"  format_version   {f['format_version']}")
    print(f"  build_number     {f['build_number']}")
    print(f"  ram_top          0x{f['ram_top']:04x}")
    print(f"  window_cap       {f['window_cap']}   (chat_context_len_var)")
    print(f"  used             {f['used']}   (chat_context_used)")
    print(f"  note_len         {f['note_len']}")
    print(f"  region           {f['region_stored']}/{f['region_len']} stored (trailing zeros trimmed)")
    print(f"  screen           {f['screen_cols']}x{f['screen_rows']}  ({f['screen_stored']} bytes encoded)")
    print(f"  header_checksum  [{ok(f['header_checksum_ok'])}]")
    print(f"  payload          {'present' if f['payload_present'] else 'TRUNCATED'}  "
          f"checksum [{ok(f['payload_checksum_ok'])}]")
    valid = f["magic_ok"] and f["header_checksum_ok"] and f["payload_present"] and f["payload_checksum_ok"]
    if f["payload_present"]:
        win = f["window"][:f["used"]]
        note, dialogue = win[:f["note_len"]], win[f["note_len"]:]
        if note:
            print(f"  --- note ({f['note_len']} B) ---\n{note.decode('latin-1')}")
        print(f"  --- dialogue ({len(dialogue)} B) ---\n{dialogue.decode('latin-1')}")
    print(f"VALID: {valid}")
    return 0 if valid else 1


def main() -> int:
    p = argparse.ArgumentParser(description="Create and inspect Seed ENV.DAT snapshots.")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="build an ENV.DAT")
    c.add_argument("--out", required=True)
    c.add_argument("--conversation", default="", help=r"window text; \n becomes a newline")
    c.add_argument("--window-file", help="raw window bytes (overrides --conversation)")
    c.add_argument("--note-len", type=int, default=0)
    c.add_argument("--window-cap", type=int, default=None, help="split boundary; default = used")
    c.add_argument("--arena", type=int, default=0, help="arena size in bytes (zero-filled)")
    c.add_argument("--region-len", type=int, default=None, help="default = window_cap + arena")
    c.add_argument("--screen", default=None, help=r"screen snapshot text; \n separates rows")
    c.add_argument("--screen-cols", type=int, default=80)
    c.add_argument("--screen-rows", type=int, default=25)
    c.add_argument("--ram-top", type=_auto_int, default=0x8000)
    c.add_argument("--build", type=int, default=12)
    c.add_argument("--format-version", type=int, default=FORMAT_VERSION)
    c.set_defaults(func=cmd_create)

    i = sub.add_parser("inspect", help="parse + validate an ENV.DAT")
    i.add_argument("file")
    i.set_defaults(func=cmd_inspect)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
