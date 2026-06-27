#!/usr/bin/env python3
"""Create and inspect ENV.DAT — Seed's persisted environment snapshot.

ENV.DAT is the env save/load file (notes/env-save-load-design.md): one contiguous
snapshot of the user/agent region [chat_context_start, ceiling) — the conversation
window + arena — plus a small header. Seed writes it on `$s` and restores it after the
splash. This tool builds and inspects one OFFLINE, so the boot-side RESTORE path (build
step 3) can be validated against a known-good file BEFORE the on-target SAVE path
(step 4) exists. It is the format's reference implementation; layout.inc mirrors these
constants in asm (step 3) and the two must agree.

Format (all little-endian; "the payload" = the verbatim region block):

  off   sz  field
  0x00  4   magic "SEDV"            (distinct from the handoff "SEED")
  0x04  1   format_version          (compatibility axis; seed gates min<=v<=current)
  0x05  1   flags                   (reserved, 0)
  0x06  2   build_number            (provenance, informational)
  0x08  2   ram_top                 (save-time RAM top; a hint for the restore warning)
  0x0a  2   chat_context_len_var    (the OLD window/arena split boundary)
  0x0c  2   chat_context_used       (valid conversation bytes in the window)
  0x0e  2   note_len                (compacted-memory prefix length within the window)
  0x10  2   region_len              (payload size = ceiling - chat_context_start)
  0x12  2   header_checksum         (16-bit sum of bytes 0x00..0x12)
  0x14  ..  payload                 (region_len bytes, verbatim)
  tail  2   payload_checksum        (16-bit sum of the payload bytes)

The payload's internal shape (offsets within the region block):
  [0 .. chat_context_used)        conversation window content
      [0 .. note_len)               compacted note (rides the request "instructions")
      [note_len .. used)            live dialogue
  [chat_context_used .. len_var)  unused window slack
  [chat_context_len_var .. region_len)  the arena (agent $w-built bytes; 0 if empty)

Usage:
  env-dat.py create --out FILE --conversation "User: hi\\nYou: Hello!" \\
      [--note-len 0] [--window-cap N] [--arena SIZE|--arena-file F] \\
      [--region-len N] [--ram-top 0x8000] [--build 12] [--format-version 1]
  env-dat.py inspect FILE
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGIC = b"SEDV"
FORMAT_VERSION = 1          # current; layout.inc env_format_current mirrors this
HEADER_LEN = 0x14           # bytes before the payload (magic..header_checksum)
_HEADER_FMT = "<4sBBHHHHHH"  # magic, ver, flags, build, ram_top, len_var, used, note, region
# the header_checksum (0x12) and payload_checksum (tail) are appended separately


def checksum16(data: bytes) -> int:
    """16-bit additive byte sum — corruption detection, not crypto (the file is the
    agent's own non-secret state; see the design doc's Trust section). Cheap to recompute
    on the 8088: zero a word, add each zero-extended byte. Matches sum(data) & 0xFFFF."""
    return sum(data) & 0xFFFF


def build(*, format_version: int, flags: int, build_number: int, ram_top: int,
          window_cap: int, used: int, note_len: int, region_len: int,
          payload: bytes) -> bytes:
    if len(payload) != region_len:
        raise ValueError(f"payload is {len(payload)} bytes, region_len says {region_len}")
    if not (note_len <= used <= window_cap <= region_len):
        raise ValueError(
            f"field order violated: note_len({note_len}) <= used({used}) <= "
            f"window_cap({window_cap}) <= region_len({region_len})")
    head = struct.pack(_HEADER_FMT, MAGIC, format_version, flags, build_number,
                       ram_top, window_cap, used, note_len, region_len)
    assert len(head) == 0x12, f"header pre-checksum is {len(head)} bytes, expected 0x12"
    head += struct.pack("<H", checksum16(head))
    return head + payload + struct.pack("<H", checksum16(payload))


def parse(blob: bytes) -> dict:
    """Parse + validate an ENV.DAT. Returns a dict of fields plus checksum verdicts;
    raises ValueError only on a structurally unreadable file (too short)."""
    if len(blob) < HEADER_LEN:
        raise ValueError(f"file is {len(blob)} bytes, shorter than the {HEADER_LEN}-byte header")
    (magic, ver, flags, build_number, ram_top,
     window_cap, used, note_len, region_len) = struct.unpack(_HEADER_FMT, blob[:0x12])
    stored_hck = struct.unpack("<H", blob[0x12:0x14])[0]
    header_ok = checksum16(blob[:0x12]) == stored_hck
    payload = blob[HEADER_LEN:HEADER_LEN + region_len]
    payload_present = len(payload) == region_len
    pck_off = HEADER_LEN + region_len
    payload_ok = False
    if payload_present and len(blob) >= pck_off + 2:
        stored_pck = struct.unpack("<H", blob[pck_off:pck_off + 2])[0]
        payload_ok = checksum16(payload) == stored_pck
    return {
        "magic": magic, "magic_ok": magic == MAGIC,
        "format_version": ver, "flags": flags, "build_number": build_number,
        "ram_top": ram_top, "window_cap": window_cap, "used": used,
        "note_len": note_len, "region_len": region_len,
        "header_checksum_ok": header_ok,
        "payload_present": payload_present, "payload_checksum_ok": payload_ok,
        "payload": payload,
    }


def _auto_int(s: str) -> int:
    return int(s, 0)  # accepts 0x.. and decimal


def cmd_create(args: argparse.Namespace) -> int:
    window = args.conversation.encode("latin-1", "replace").replace(b"\\n", b"\n")
    if args.window_file:
        window = Path(args.window_file).read_bytes()
    used = len(window)
    window_cap = args.window_cap if args.window_cap is not None else used
    arena = b""
    if args.arena_file:
        arena = Path(args.arena_file).read_bytes()
    elif args.arena:
        arena = b"\x00" * args.arena
    region_len = args.region_len if args.region_len is not None else window_cap + len(arena)

    payload = bytearray(region_len)
    payload[:used] = window
    arena_base = window_cap
    if arena_base + len(arena) > region_len:
        print(f"error: arena ({len(arena)} B at {arena_base}) overflows region_len "
              f"({region_len})", file=sys.stderr)
        return 2
    payload[arena_base:arena_base + len(arena)] = arena

    try:
        blob = build(format_version=args.format_version, flags=0,
                     build_number=args.build, ram_top=args.ram_top,
                     window_cap=window_cap, used=used, note_len=args.note_len,
                     region_len=region_len, payload=bytes(payload))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    Path(args.out).write_bytes(blob)
    print(f"wrote {args.out}: {len(blob)} bytes "
          f"(header 0x{HEADER_LEN:x} + payload {region_len} + checksum 2)")
    print(f"  used={used} note_len={args.note_len} window_cap={window_cap} "
          f"region_len={region_len} ram_top=0x{args.ram_top:04x} build={args.build} v{args.format_version}")
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
    print(f"  flags            0x{f['flags']:02x}")
    print(f"  build_number     {f['build_number']}")
    print(f"  ram_top          0x{f['ram_top']:04x}")
    print(f"  window_cap       {f['window_cap']}   (chat_context_len_var)")
    print(f"  used             {f['used']}   (chat_context_used)")
    print(f"  note_len         {f['note_len']}")
    print(f"  region_len       {f['region_len']}")
    print(f"  header_checksum  [{ok(f['header_checksum_ok'])}]")
    print(f"  payload          {'present' if f['payload_present'] else 'TRUNCATED'}  "
          f"checksum [{ok(f['payload_checksum_ok'])}]")
    valid = f["magic_ok"] and f["header_checksum_ok"] and f["payload_present"] and f["payload_checksum_ok"]
    if f["payload_present"]:
        win = f["payload"][:f["used"]]
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
    c.add_argument("--arena-file", help="raw arena bytes (overrides --arena)")
    c.add_argument("--region-len", type=int, default=None,
                   help="total payload bytes; default = window_cap + arena")
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
