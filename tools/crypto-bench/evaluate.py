#!/usr/bin/env python3
"""Evaluate a SHA-256 variant: correctness (unicorn vs OpenSSL) + 8088 cycles.

A "variant" is a drop-in replacement for core/sha256.inc: it must define
sha256_init / sha256_update / sha256_finish / sha256_process_block /
hmac_prepare_current_key_context / hmac_sha256_prepared / sha256_save_context /
sha256_restore_context (the symbols the PRF driver calls), operating on the same
data.inc state addresses. It may rewrite internals freely (8086 only).

Gate (all host-side, instant, parallel-safe):
  * ok_sha   : SHA-256("abc") and a multi-block message match hashlib.
  * ok_prf   : the full TLS-PRF (master secret + key block) through this SHA
               matches the check-tls-prf OpenSSL vectors -- exercises
               init/update/finish/save/restore/hmac end to end.
  * cycles   : process_block and full-PRF 8088 cycle estimates (calibrated ~99%
               vs 86Box), and speedup vs the frozen baseline (the original
               core/sha256.inc, measured on the same model).

CLI: python3 evaluate.py path/to/variant_sha256.inc  [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import bench_harness as bh

CPU_HZ = 4772728.0

WANT_MASTER = bytes.fromhex(
    "518bc65fd30dabe86349152f98435c94d907b50c92a931c5"
    "a2f9e3a4d90f3439f2726c763fb1a40aec90b8bc60173f7c")
WANT_KEYBLK = bytes.fromhex(
    "9052d2e0e4485b2e323effcbc8a47e0839454ba1588ffbc35dccffd8fe8f67f3"
    "6aee3d733b5a6abc5818a826fab3fea582291c5ae2097fcbbcb6038cd5d6a970"
    "f236e9b87b13063de4518cc80660e7a4003c02ee214c1c93")

BASELINE_INC = '%include "core/sha256.inc"\n'


def _sha_correct(sha_inc: str) -> tuple[bool, str]:
    """SHA-256('abc') and a 3-block message via the variant, vs hashlib."""
    DIG = 0x4000
    for msg in (b"abc", b"The quick brown fox jumps over the lazy dog" * 3):
        caller = f"""
    call sha256_init
    mov si, __m
    mov cx, __ml
    call sha256_update
    mov di, {DIG}
    call sha256_finish
"""
        body = f"__m: db {','.join(str(b) for b in msg)}\n__ml equ $ - __m\n" + sha_inc
        try:
            img, exp = bh.build(body, caller)
            uc = bh.Run(img, exp).run()
        except Exception as e:  # nasm error / cpu violation / emu fault
            return False, f"sha build/run: {e}"
        got = bytes(uc.mem_read(DIG, 32))
        if got != hashlib.sha256(msg).digest():
            return False, f"sha256({msg[:8]!r}..) mismatch"
    return True, ""


def _prf_correct(sha_inc: str) -> tuple[bool, str]:
    """Full master+keyblock PRF via the variant SHA, vs OpenSSL vectors."""
    body = sha_inc + '%include "prf_driver.inc"\n'
    caller = "    call tls_prepare_master_secret\n    call tls_prepare_key_block\n"

    def setup(uc, exp):
        uc.mem_write(exp["tls_premaster_secret"], bytes(range(0x20)))
        uc.mem_write(exp["tls_random"], bytes(range(0x20, 0x40)))
        uc.mem_write(exp["tls_server_random"], bytes(range(0x40, 0x60)))
    try:
        img, exp = bh.build(body, caller)
        uc = bh.Run(img, exp).run(setup=setup)
    except Exception as e:
        return False, f"prf build/run: {e}"
    master = bytes(uc.mem_read(exp["tls_master_secret"], 48))
    keyblk = bytes(uc.mem_read(exp["tls_key_block"], 88))
    if master != WANT_MASTER:
        return False, "master secret mismatch"
    if keyblk != WANT_KEYBLK:
        return False, "key block mismatch"
    return True, ""


def _block_cycles(sha_inc: str) -> tuple[int, int]:
    """(cycles, instrs) for ONE process_block, isolated by the 2-minus-1 method."""
    def measure(n):
        caller = """
    call sha256_init
    mov di, sha256_block
    xor al, al
    mov cx, 64
.f: mov [di],al
    inc di
    inc al
    loop .f
""" + "    call sha256_process_block\n" * n
        img, exp = bh.build(sha_inc, caller)
        r = bh.Run(img, exp)
        r.run(cycles=True)
        return r.cycles, r.instr_count
    c1, i1 = measure(1)
    c2, i2 = measure(2)
    return c2 - c1, i2 - i1


def _prf_cycles(sha_inc: str) -> tuple[int, int]:
    body = sha_inc + '%include "prf_driver.inc"\n'
    caller = "    call tls_prepare_master_secret\n    call tls_prepare_key_block\n"

    def setup(uc, exp):
        uc.mem_write(exp["tls_premaster_secret"], bytes(range(0x20)))
        uc.mem_write(exp["tls_random"], bytes(range(0x20, 0x40)))
        uc.mem_write(exp["tls_server_random"], bytes(range(0x40, 0x60)))
    img, exp = bh.build(body, caller)
    r = bh.Run(img, exp)
    r.run(setup=setup, cycles=True)
    return r.cycles, r.instr_count


_baseline_cache = None


def baseline() -> dict:
    global _baseline_cache
    if _baseline_cache is None:
        bc, bi = _block_cycles(BASELINE_INC)
        pc, pi = _prf_cycles(BASELINE_INC)
        _baseline_cache = {"block_cycles": bc, "block_instrs": bi,
                           "prf_cycles": pc, "prf_instrs": pi}
    return _baseline_cache


def evaluate(variant_path: str | None) -> dict:
    if variant_path is None:
        sha_inc = BASELINE_INC
    else:
        sha_inc = Path(variant_path).read_text() + "\n"
    base = baseline()
    ok_sha, e1 = _sha_correct(sha_inc)
    ok_prf, e2 = _prf_correct(sha_inc)
    res = {"variant": variant_path or "BASELINE",
           "ok_sha": ok_sha, "ok_prf": ok_prf, "error": (e1 or e2) or None}
    if ok_sha and ok_prf:
        bc, bi = _block_cycles(sha_inc)
        pc, pi = _prf_cycles(sha_inc)
        res.update({
            "block_cycles": bc, "block_instrs": bi,
            "prf_cycles": pc, "prf_instrs": pi,
            "block_ms": round(bc / CPU_HZ * 1000, 2),
            "prf_ms": round(pc / CPU_HZ * 1000, 2),
            "block_speedup": round(base["block_cycles"] / bc, 4),
            "prf_speedup": round(base["prf_cycles"] / pc, 4),
            "block_cycles_baseline": base["block_cycles"],
            "prf_cycles_baseline": base["prf_cycles"],
        })
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("variant", nargs="?", help="variant sha256.inc (omit = baseline)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    res = evaluate(args.variant)
    if args.json:
        print(json.dumps(res))
    else:
        print(json.dumps(res, indent=2))
    sys.exit(0 if (res["ok_sha"] and res["ok_prf"]) else 1)


if __name__ == "__main__":
    main()
