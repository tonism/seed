#!/usr/bin/env python3
"""Oracle-gate the full off-race X.509 chain-verify (core/x509_chain_verify.inc) under unicorn.

This is the WHOLE trust core in asm: x509_parse_leaf -> SHA-256(TBS) -> rsa_pkcs1_verify against the
BAKED WR1 anchor (core/rsa_anchor_wr1.inc). The real api.openai.com leaf must ACCEPT (it chains to
WR1); any signature/TBS tamper or a cert signed by a different CA must REJECT. WR1 is compiled in,
so no anchor deploy is needed -- this exercises the real pinned key.

Run: python3 tools/crypto-bench/chain_eval.py   (exit 0 == chain-verify accepts real, rejects forged)
"""
from __future__ import annotations
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "x509"))
sys.path.insert(0, os.path.dirname(__file__))

import bench_harness as bh
from bench_harness import build, Run
import der_build as B

CERTS = os.path.join(os.path.dirname(__file__), "..", "x509", "certs")
LEAF = open(os.path.join(CERTS, "leaf.der"), "rb").read()

EXPORTS = ["certbuf", "certlen", "accept", "x509_mod_ptr"]

WORDS = 128
DATA = (
    "\nalign 2\n"
    + "".join(f"{n}: times {WORDS} dw 0\n" for n in
             ("rsa_n", "rsa_r2", "rsa_one", "rsa_sig", "rsa_result", "rsa_sm", "rsa_x"))
    + "rsa_n0inv: dw 0\n"
    + f"rsa_t: times {WORDS * 2 + 4} dw 0\n"
    + "certbuf: times 4096 db 0\n"
    + "certlen: dw 0\n"
    + "accept:  db 0\n"
)

CALLER = """
    mov si, certbuf
    mov cx, [certlen]
    call x509_chain_verify
    sbb al, al
    inc al
    mov [accept], al
"""

INCLUDES = (
    '%include "core/x509_verify.inc"\n'
    '%include "core/sha256.inc"\n'
    '%include "core/rsa_verify.inc"\n'
    '%include "core/rsa_pkcs1.inc"\n'
    '%include "core/rsa_anchor_wr1.inc"\n'
    '%include "core/x509_chain_verify.inc"\n'
)


def build_chain():
    MAGIC = 0x5A5AC409
    tbl = f"\n__chain_exports:\n    dd 0x{MAGIC:08X}\n" + "".join(f"    dd {n}\n" for n in EXPORTS)
    img, exp = build(INCLUDES + tbl + DATA, CALLER)
    pos = img.find(struct.pack("<I", MAGIC))
    vals = struct.unpack_from("<%dI" % len(EXPORTS), img, pos + 4)
    exp.update(dict(zip(EXPORTS, vals)))
    return img, exp


def run_chain(img, exp, der: bytes) -> bool:
    def setup(uc, e):
        uc.mem_write(e["certbuf"], der)
        uc.mem_write(e["certlen"], struct.pack("<H", len(der)))
    r = Run(img, exp)
    uc = r.run(setup=setup)
    res = uc.mem_read(exp["accept"], 1)[0] == 1
    run_chain.instrs = r.instr_count
    return res


def flip(buf, off, bit=0):
    b = bytearray(buf); b[off] ^= (1 << bit); return bytes(b)


def main() -> int:
    print("assembling the full chain-verify (parser+sha256+rsa_verify+rsa_pkcs1+WR1) ...", file=sys.stderr)
    img, exp = build_chain()
    ca_n, _, ca_d = B.gen_rsa(2048, seed=0x5EED)
    synth = B.mint_cert(ca_n=ca_n, ca_d=ca_d)            # valid structure, but signed by a non-WR1 CA

    cases = [
        ("real api.openai.com leaf",        LEAF,                 True),
        ("real leaf, signature bit flipped", flip(LEAF, 1086),     False),
        ("real leaf, TBS serial byte flipped", flip(LEAF, 20),     False),
        ("synthetic leaf (signed by non-WR1 CA)", synth,           False),
        ("truncated leaf",                  LEAF[:-200],           False),
    ]
    fails = 0
    for label, der, want in cases:
        got = run_chain(img, exp, der)
        ok = (got == want)
        fails += 0 if ok else 1
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:<40} want={'ACCEPT' if want else 'REJECT'} "
              f"got={'ACCEPT' if got else 'REJECT'} ({run_chain.instrs} instrs)")
    print(f"\nOVERALL: {'ALL GREEN — chain-verify accepts the real leaf, rejects every forgery' if not fails else 'FAILURES'}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
