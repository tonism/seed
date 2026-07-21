#!/usr/bin/env python3
"""Oracle-gate the 286 adopt math (core/rsa_adopt.inc) under unicorn.

After a rotated leaf chain-verifies vs WR1, rsa_adopt derives the leaf's Montgomery constants
(rsa_n, rsa_n0inv, rsa_r2) from its big-endian modulus and installs them as the fast-path pin. The
strongest correctness test: run rsa_adopt THEN rsa_verify and confirm the modexp reproduces
pow(sig, 65537, n) -- i.e. the derived params actually drive a correct RSA verify. Also cross-check
n0inv and r2 against Python directly. Tested on the real leaf + several synthetic moduli.

Run: python3 tools/crypto-bench/adopt_eval.py   (exit 0 == adopt is correct on every modulus)
"""
from __future__ import annotations
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "x509"))
sys.path.insert(0, os.path.dirname(__file__))

import bench_harness as bh
from bench_harness import build, Run
import x509_verify as X
import der_build as B

WORDS = 128
R = 1 << (WORDS * 16)

EXPORTS = ["rsa_n", "rsa_r2", "rsa_one", "rsa_n0inv", "rsa_sig", "rsa_result", "adopt_modbuf"]

DATA = (
    "\nalign 2\n"
    + "rsa_key_ready: db 0\nalign 2\n"
    + "".join(f"{n}: times {WORDS} dw 0\n" for n in
             ("rsa_n", "rsa_r2", "rsa_one", "rsa_sig", "rsa_result", "rsa_sm", "rsa_x"))
    + "rsa_n0inv: dw 0\n"
    + f"rsa_t: times {WORDS * 2 + 4} dw 0\n"
    + "adopt_modbuf: times 256 db 0\n"
)

CALLER = """
    mov si, adopt_modbuf
    call rsa_adopt
    call rsa_verify
"""


def to_words(v):
    return [(v >> (16 * i)) & 0xFFFF for i in range(WORDS)]


def from_words(ws):
    return sum((w & 0xFFFF) << (16 * i) for i, w in enumerate(ws))


def build_adopt():
    MAGIC = 0x5A5AAD09
    tbl = f"\n__adopt_exports:\n    dd 0x{MAGIC:08X}\n" + "".join(f"    dd {n}\n" for n in EXPORTS)
    body = '%include "core/rsa_verify.inc"\n%include "core/rsa_adopt.inc"\n' + tbl + DATA
    img, exp = build(body, CALLER)
    pos = img.find(struct.pack("<I", MAGIC))
    vals = struct.unpack_from("<%dI" % len(EXPORTS), img, pos + 4)
    exp.update(dict(zip(EXPORTS, vals)))
    return img, exp


def check(img, exp, n: int, label: str) -> bool:
    sig = pow(3, 0x5EED, n) % n                                  # any s < n exercises the same path
    expect_n0 = (-pow(n, -1, 1 << 16)) % (1 << 16)
    expect_r2 = pow(R, 2, n)
    expect_res = pow(sig, 65537, n)

    def setup(uc, e):
        uc.mem_write(e["adopt_modbuf"], n.to_bytes(256, "big"))   # big-endian modulus, as in the cert
        uc.mem_write(e["rsa_sig"], struct.pack(f"<{WORDS}H", *to_words(sig)))
        uc.mem_write(e["rsa_one"], struct.pack(f"<{WORDS}H", *to_words(1)))

    r = Run(img, exp)
    uc = r.run(setup=setup)
    got_n = from_words(struct.unpack(f"<{WORDS}H", bytes(uc.mem_read(exp["rsa_n"], WORDS * 2))))
    got_n0 = struct.unpack("<H", bytes(uc.mem_read(exp["rsa_n0inv"], 2)))[0]
    got_r2 = from_words(struct.unpack(f"<{WORDS}H", bytes(uc.mem_read(exp["rsa_r2"], WORDS * 2))))
    got_res = from_words(struct.unpack(f"<{WORDS}H", bytes(uc.mem_read(exp["rsa_result"], WORDS * 2))))
    ok_n = got_n == n
    ok_n0 = got_n0 == expect_n0
    ok_r2 = got_r2 == expect_r2
    ok_res = got_res == expect_res                                # the end-to-end gate
    ok = ok_n and ok_n0 and ok_r2 and ok_res
    print(f"  [{'PASS' if ok else 'FAIL'}] {label:<28} n={'ok' if ok_n else 'BAD'} "
          f"n0inv={'ok' if ok_n0 else 'BAD'} r2={'ok' if ok_r2 else 'BAD'} "
          f"verify={'ok' if ok_res else 'BAD'} ({r.instr_count} instrs)")
    return ok


def main() -> int:
    print("assembling core/rsa_adopt.inc + rsa_verify.inc ...", file=sys.stderr)
    img, exp = build_adopt()
    leaf_n = X.parse_certificate(open(os.path.join(os.path.dirname(__file__), "..", "x509",
                                                   "certs", "leaf.der"), "rb").read()).spki_modulus
    cases = [
        (leaf_n, "real api.openai.com leaf"),
        (B.gen_rsa(2048, seed=0x5EED)[0], "synthetic CA (seed 5EED)"),
        (B.gen_rsa(2048, seed=0x1EAF)[0], "synthetic leaf (seed 1EAF)"),
        (B.gen_rsa(2048, seed=0xBEEF)[0], "synthetic (seed BEEF)"),
    ]
    ok = all(check(img, exp, n, label) for n, label in cases)
    print(f"\nOVERALL: {'ALL GREEN — adopt derives working Montgomery params' if ok else 'FAILURES'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
