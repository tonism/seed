#!/usr/bin/env python3
"""Evaluate an RSA-2048 verify variant: correctness (vs pow(s,65537,N)) + size.

Gate: rsa_verify computes rsa_sig^65537 mod rsa_n into rsa_result; it must equal
the oracle EXPECTED. Reports the unicorn instruction count for one full verify
(a rough cost proxy -- 86Box ibmat@6 via rsa_bench.asm is the authoritative time).

CLI: python3 rsa_eval.py [rsa_verify.inc] [--json]
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

import rsa_bench_harness as H


def evaluate(inc: str) -> dict:
    res = {"variant": inc}
    try:
        img, exp = H.build_rsa("    call rsa_verify\n", inc=inc)
    except Exception as e:
        return {**res, "ok": False, "error": f"assemble: {e}"}
    r = H.Run(img, exp)
    try:
        r.run(setup=H.deploy_inputs)
    except Exception as e:
        return {**res, "ok": False, "error": f"run: {e}", "instrs": r.instr_count}
    got = H.read_bignum(r.uc, exp["rsa_result"])
    ok = got == H.EXPECTED
    res.update({
        "ok": ok,
        "instrs": r.instr_count,
        "bytes": len(Path(H.BENCH_DIR / inc).read_bytes()) if (H.BENCH_DIR / inc).exists() else None,
        "error": None if ok else f"result mismatch (got {got:#x}...)"[:60],
    })
    return res


# convenience: BENCH dir for byte counts
H.BENCH_DIR = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("variant", nargs="?", default="rsa_verify.inc")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = evaluate(a.variant)
    print(json.dumps(res, indent=None if a.json else 2))
    sys.exit(0 if res.get("ok") else 1)


if __name__ == "__main__":
    main()
