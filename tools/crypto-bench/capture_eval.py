#!/usr/bin/env python3
"""Oracle-gate the leaf-capture routine (core/x509_capture.inc) under unicorn.

The recertify flow must extract the leaf DER from the streamed, fragmented TLS Certificate message.
This builds the real Certificate message (leaf+WR1+root in the wire framing), feeds it to
capture_leaf_chunk in fragments of several sizes (stressing the fragment boundaries that span the
framing and the leaf), and checks the captured arena bytes == leaf.der exactly. The byte-stream
alignment (skip the 15-byte framing, copy cert0 bounded by its length, across fragments) is the
correctness-critical part of the port; this proves it before any hardware run.

Run: python3 tools/crypto-bench/capture_eval.py   (exit 0 == capture is byte-exact on every split)
"""
from __future__ import annotations
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import bench_harness as bh
from bench_harness import build, Run

CERTS = os.path.join(os.path.dirname(__file__), "..", "x509", "certs")
LEAF = open(os.path.join(CERTS, "leaf.der"), "rb").read()
WR1 = open(os.path.join(CERTS, "wr1.der"), "rb").read()
ROOT = open(os.path.join(CERTS, "root_r1.pem"), "rb").read()   # any 3rd cert; only the leaf matters


def u24(n: int) -> bytes:
    return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def cert_message(leaf: bytes, *rest: bytes) -> bytes:
    """A TLS Certificate handshake record: record hdr | hs hdr | cert_list_len | [len|cert]..."""
    certs = b"".join(u24(len(c)) + c for c in (leaf, *rest))
    body = u24(len(certs)) + certs                      # certificate_list length + the entries
    handshake = bytes([0x0B]) + u24(len(body)) + body   # handshake type 0x0b + 3-byte len + body
    record = bytes([0x16, 0x03, 0x03]) + struct.pack(">H", len(handshake)) + handshake
    return record


CERT_CAP = 8192
DATA = (
    "\nalign 2\n"
    f"cert_buf:  times {CERT_CAP} db 0\n"
    "frag_lens: times 600 dw 0\n"       # 0-terminated table of fragment lengths
)

# caller: force the 286 flag, reset, then walk the fragment-length table calling capture_leaf_chunk.
CALLER = """
    or word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    call capture_leaf_reset
    mov bx, frag_lens
    xor di, di
.floop:
    mov cx, [bx]
    or cx, cx
    jz .fdone
    mov si, cert_buf
    add si, di
    call capture_leaf_chunk
    add di, cx
    add bx, 2
    jmp .floop
.fdone:
"""

EXPORTS = ["cert_buf", "frag_lens", "capture_leaf_len", "capture_done", "leaf_capture_buf"]


def build_capture():
    MAGIC = 0x5A5ACA9E
    tbl = f"\n__cap_exports:\n    dd 0x{MAGIC:08X}\n" + "".join(f"    dd {n}\n" for n in EXPORTS)
    body = '%include "core/x509_capture.inc"\n' + tbl + DATA
    img, exp = build(body, CALLER)
    pos = img.find(struct.pack("<I", MAGIC))
    vals = struct.unpack_from("<%dI" % len(EXPORTS), img, pos + 4)
    exp.update(dict(zip(EXPORTS, vals)))
    return img, exp


def run_capture(img, exp, msg: bytes, frags: list[int]):
    assert sum(frags) == len(msg), (sum(frags), len(msg))
    assert len(frags) < 600

    def setup(uc, e):
        uc.mem_write(e["cert_buf"], msg)
        uc.mem_write(e["frag_lens"], struct.pack(f"<{len(frags)+1}H", *frags, 0))

    r = Run(img, exp)
    uc = r.run(setup=setup)
    leaf_len = struct.unpack("<H", bytes(uc.mem_read(exp["capture_leaf_len"], 2)))[0]
    done = struct.unpack("<H", bytes(uc.mem_read(exp["capture_done"], 2)))[0]
    captured = bytes(uc.mem_read(exp["leaf_capture_buf"], leaf_len)) if leaf_len else b""
    return leaf_len, done, captured


def split(total: int, size: int) -> list[int]:
    out = []
    while total > 0:
        out.append(min(size, total))
        total -= out[-1]
    return out


def main() -> int:
    print("assembling core/x509_capture.inc ...", file=sys.stderr)
    img, exp = build_capture()
    msg = cert_message(LEAF, WR1, ROOT)
    print(f"Certificate message {len(msg)} B; leaf {len(LEAF)} B at record offset 15", file=sys.stderr)

    fails = 0
    # (name, fragment-length pattern, expect_capture). Realistic splits (first segment large, as a
    # real server always sends) must capture byte-exact; a first fragment < 15 B can't hold the
    # framing, so it FAILS CLOSED (leaf_len=0 -> recertify refuses) -- never silently mis-captures.
    rest = len(msg) - 15 - len(LEAF)
    patterns = [
        ("single fragment",                          [len(msg)],                              True),
        ("592-byte MSS frags",                        split(len(msg), 592),                    True),
        ("100-byte frags",                            split(len(msg), 100),                    True),
        ("20-byte first, then 10-byte frags",         [20] + split(len(msg) - 20, 10),         True),
        ("frag boundary exactly at the leaf end",     [15 + len(LEAF), rest],                  True),
        ("frag boundary 1 byte into the leaf",        [16] + split(len(msg) - 16, 592),        True),
        ("tiny first fragment (8 B) fails closed",    [8] + split(len(msg) - 8, 592),          False),
        ("14-byte first fragment fails closed",       [14] + split(len(msg) - 14, 592),        False),
    ]
    for name, frags, expect in patterns:
        leaf_len, done, captured = run_capture(img, exp, msg, frags)
        if expect:
            ok = (leaf_len == len(LEAF) and done == len(LEAF) and captured == LEAF)
            detail = "" if ok else f"  !! leaf_len={leaf_len} done={done} match={captured == LEAF}"
        else:
            ok = (leaf_len == 0)                      # fail closed: nothing captured
            detail = "" if ok else f"  !! expected abort but leaf_len={leaf_len}"
        fails += 0 if ok else 1
        verb = "captures" if expect else "fails closed"
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<42} ({len(frags)} frags -> {verb}){detail}")

    print(f"\nOVERALL: {'ALL GREEN — capture is byte-exact across fragmentations' if not fails else 'FAILURES'}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
