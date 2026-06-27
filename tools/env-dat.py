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

Format (little-endian):

  off   sz  field
  0x00  4   magic "SEDV"            (distinct from the handoff "SEED")
  0x04  1   format_version          (compatibility axis; seed gates min<=v<=current)
  0x05  1   flags                   (reserved, 0)
  0x06  2   build_number            (provenance, informational)
  0x08  2   ram_top                 (save-time RAM top; a hint for the restore warning)
  0x0a  2   chat_context_len_var    (the OLD window/arena split boundary)
  0x0c  2   chat_context_used       (valid conversation bytes in the window)
  0x0e  2   note_len                (compacted-memory prefix length within the window)
  0x10  2   region_len              (window+arena bytes -> chat_context_start)
  0x12  1   screen_cols             (snapshot width; 0 = no snapshot)
  0x13  1   screen_rows             (snapshot height)
  0x14  2   payload_checksum        (16-bit sum of the whole payload)
  0x16  2   header_checksum         (16-bit sum of header bytes 0x00..0x16)
  0x18  ..  payload: [region_len window bytes][screen_cols*screen_rows*2 snapshot cells]

The window section's internal shape (offsets within the region block):
  [0 .. used)            conversation window     [0..note_len) note, [note_len..used) dialogue
  [used .. len_var)      unused window slack
  [len_var .. region_len) the arena (agent $w-built bytes; 0 if empty)
The screen section is row-major char+attr cells exactly as in CGA/MDA text memory.

Usage:
  env-dat.py create --out FILE --conversation "You: hi\\nAssistant: Hello!" \\
      [--note-len 0] [--window-cap N] [--arena SIZE] [--region-len N] \\
      [--screen "line1\\nline2"] [--screen-cols 80] [--screen-rows 25] \\
      [--ram-top 0x8000] [--build 12] [--format-version 1]
  env-dat.py inspect FILE
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGIC = b"SEDV"
FORMAT_VERSION = 1          # current; layout.inc env_format_current mirrors this
HEADER_LEN = 0x18           # bytes before the payload (magic..header_checksum)
_HEADER_FMT = "<4sBBHHHHHHBBH"  # ...through payload_checksum (0x16 bytes); header_checksum (H) follows
DEFAULT_ATTR = 0x07         # synthesized-snapshot cell attribute (real saves capture the live attrs)


def checksum16(data: bytes) -> int:
    """16-bit additive byte sum — corruption detection, not crypto (the file is the agent's own
    non-secret state). Cheap on the 8088: zero a word, add each zero-extended byte."""
    return sum(data) & 0xFFFF


def build(*, format_version: int, flags: int, build_number: int, ram_top: int,
          window_cap: int, used: int, note_len: int, region_len: int,
          screen_cols: int, screen_rows: int, payload: bytes) -> bytes:
    screen_len = screen_cols * screen_rows * 2
    if len(payload) != region_len + screen_len:
        raise ValueError(f"payload is {len(payload)} bytes, expected region_len({region_len}) + "
                         f"screen({screen_len})")
    if not (note_len <= used <= window_cap <= region_len):
        raise ValueError(f"field order violated: note_len({note_len}) <= used({used}) <= "
                         f"window_cap({window_cap}) <= region_len({region_len})")
    head = struct.pack(_HEADER_FMT, MAGIC, format_version, flags, build_number, ram_top,
                       window_cap, used, note_len, region_len, screen_cols, screen_rows,
                       checksum16(payload))
    assert len(head) == 0x16, f"header pre-checksum is {len(head)} bytes, expected 0x16"
    head += struct.pack("<H", checksum16(head))
    return head + payload


def parse(blob: bytes) -> dict:
    if len(blob) < HEADER_LEN:
        raise ValueError(f"file is {len(blob)} bytes, shorter than the {HEADER_LEN}-byte header")
    (magic, ver, flags, build_number, ram_top, window_cap, used, note_len, region_len,
     screen_cols, screen_rows, payload_ck) = struct.unpack(_HEADER_FMT, blob[:0x16])
    stored_hck = struct.unpack("<H", blob[0x16:0x18])[0]
    header_ok = checksum16(blob[:0x16]) == stored_hck
    screen_len = screen_cols * screen_rows * 2
    payload = blob[HEADER_LEN:HEADER_LEN + region_len + screen_len]
    payload_present = len(payload) == region_len + screen_len
    payload_ok = payload_present and checksum16(payload) == payload_ck
    return {
        "magic": magic, "magic_ok": magic == MAGIC,
        "format_version": ver, "flags": flags, "build_number": build_number,
        "ram_top": ram_top, "window_cap": window_cap, "used": used,
        "note_len": note_len, "region_len": region_len,
        "screen_cols": screen_cols, "screen_rows": screen_rows, "screen_len": screen_len,
        "header_checksum_ok": header_ok,
        "payload_present": payload_present, "payload_checksum_ok": payload_ok,
        "window": payload[:region_len] if payload_present else b"",
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
    region = bytearray(region_len)
    region[:used] = window
    if window_cap + len(arena) > region_len:
        print(f"error: arena overflows region_len", file=sys.stderr)
        return 2
    region[window_cap:window_cap + len(arena)] = arena

    screen = b""
    screen_cols = screen_rows = 0
    if args.screen is not None:
        screen_cols, screen_rows = args.screen_cols, args.screen_rows
        text = args.screen.replace("\\n", "\n")
        screen = _synthesize_screen(text, screen_cols, screen_rows, DEFAULT_ATTR)

    try:
        blob = build(format_version=args.format_version, flags=0, build_number=args.build,
                     ram_top=args.ram_top, window_cap=window_cap, used=used, note_len=args.note_len,
                     region_len=region_len, screen_cols=screen_cols, screen_rows=screen_rows,
                     payload=bytes(region) + screen)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    Path(args.out).write_bytes(blob)
    print(f"wrote {args.out}: {len(blob)} bytes (header 0x{HEADER_LEN:x} + window {region_len} "
          f"+ screen {len(screen)})")
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
    print(f"  region_len       {f['region_len']}")
    print(f"  screen           {f['screen_cols']}x{f['screen_rows']}  ({f['screen_len']} bytes)")
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
