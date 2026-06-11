#!/usr/bin/env python3
"""Evaluate a P-256 variant: correctness (vs OpenSSL oracle) + 8088 cycles, for
the 286 ECDHE optimization push. A variant is a drop-in p256_real.inc replacement.

Gate (host-side, via unicorn + the check-p256 oracle):
  * field mul (p256_mul_mod) exact over a vector of values,
  * point double + mixed-add exact,
  * the FULL scalar mult PEER_PRIVATE x G == PEER_PUBLIC (the strong gate).
Cost:
  * field multiply cycles (8088 model, 2-minus-1 isolated) -- the dominant unit
    (~3700 per scalar mult); the lever for the 286,
  * full scalar-mult instruction count (ECDHE size), and a derived ECDHE-cycle
    estimate = field_mul_cycles x measured field-mul-count.
Speedups are vs the baseline p256_real.inc on the same model. 86Box ibmat@6/8 is
the ground truth for the winner.

CLI: python3 p256_eval.py variants/p256_xxx.inc [--json] [--full]
"""
from __future__ import annotations
import argparse, json, struct, sys
from pathlib import Path

import p256_bench_harness as H
from p256_bench_harness import oracle, P, G, PEER_PRIVATE, PEER_PUBLIC, SHARED_X

VALS = [1, 2, P-1, P-2, P//2, G[0], G[1], PEER_PUBLIC[0], PEER_PUBLIC[1], SHARED_X,
        0x1111111111111111, 0xABCDEF0123456789 << 100]
VALS = [v % P for v in VALS]
CPU_HZ = 4772728.0


def _mul_ok(inc):
    caller = "    mov si, p256_s0\n    mov di, p256_s1\n    mov bx, p256_s2\n    call p256_mul_mod\n"
    img, exp = H._build_p256(caller, inc=inc)
    for a in VALS:
        for b in VALS[:6]:
            r = H.Run(img, exp)
            r.run(setup=lambda uc, e, a=a, b=b: (H._write_field(uc, e["p256_s0"], a),
                                                 H._write_field(uc, e["p256_s1"], b)))
            if H._read_field(r.uc, exp["p256_s2"]) != oracle.mul_words_mod(a, b):
                return False, f"mul {a:x}*{b:x}"
    return True, ""


def _double_addmixed_ok(inc):
    img, exp = H._build_p256("    call p256_point_double_jacobian\n", inc=inc)
    r = H.Run(img, exp)
    r.run(setup=lambda uc, e: (H._write_field(uc, e["p256_jac_x"], G[0]),
                               H._write_field(uc, e["p256_jac_y"], G[1]),
                               H._write_field(uc, e["p256_jac_z"], 1)))
    got = tuple(H._read_field(r.uc, exp[k]) for k in ("p256_jac_x","p256_jac_y","p256_jac_z"))
    if got != oracle.jacobian_double_words((G[0], G[1], 1)):
        return False, "double"
    return True, ""


def _scalar_ok(inc):
    caller = """
    mov word [p256_affine_x_ptr], tls_server_ec_x_words
    mov word [p256_affine_y_ptr], tls_server_ec_y_words
    mov si, p256_client_private
    call p256_scalar_mult_mixed
"""
    img, exp = H._build_p256(caller, inc=inc)
    r = H.Run(img, exp)
    r.run(setup=lambda uc, e: (H._write_field(uc, e["p256_client_private"], PEER_PRIVATE),
                               H._write_field(uc, e["tls_server_ec_x_words"], G[0]),
                               H._write_field(uc, e["tls_server_ec_y_words"], G[1])))
    jac = tuple(H._read_field(r.uc, exp[k]) for k in ("p256_jac_x","p256_jac_y","p256_jac_z"))
    ok = oracle.jacobian_to_affine(jac) == PEER_PUBLIC
    return ok, ("" if ok else "scalar_mult != PEER_PUBLIC"), r.instr_count


def _field_mul_cycles(inc):
    """Isolate one p256_mul_mod: cycles(2 calls) - cycles(1 call)."""
    def measure(n):
        body_caller = ("    mov si, p256_s0\n    mov di, p256_s1\n    mov bx, p256_s2\n"
                       + "    call p256_mul_mod\n" * n)
        img, exp = H._build_p256(body_caller, inc=inc)
        r = H.Run(img, exp)
        r.run(setup=lambda uc, e: (H._write_field(uc, e["p256_s0"], G[0]),
                                   H._write_field(uc, e["p256_s1"], G[1])), cycles=True)
        return r.cycles, r.instr_count
    c1, i1 = measure(1); c2, i2 = measure(2)
    return c2 - c1, i2 - i1


_bl_field = None
_bl_scalar = None
def baseline_field():
    global _bl_field
    if _bl_field is None:
        _bl_field = _field_mul_cycles("p256_real.inc")
    return _bl_field
def baseline_scalar():
    global _bl_scalar
    if _bl_scalar is None:
        _bl_scalar = _scalar_ok("p256_real.inc")[2]
    return _bl_scalar


def evaluate(inc, full=False):
    """Fast gate (default): field-mul + point-double correctness + field-mul cost.
    --full also runs the 24M-instr scalar mult (needed only for scalar-structure changes)."""
    res = {"variant": inc}
    ok1, e1 = _mul_ok(inc)
    ok2, e2 = _double_addmixed_ok(inc) if ok1 else (False, "skip")
    err = e1 or e2
    res["ok"] = ok1 and ok2
    if full and res["ok"]:
        ok3, e3, scalar_instrs = _scalar_ok(inc)
        res["ok"] = ok3
        err = err or e3
        if ok3:
            res["scalar_instrs"] = scalar_instrs
            res["scalar_instr_ratio"] = round(baseline_scalar() / max(1, scalar_instrs), 3)
    res["error"] = err or None
    if not res["ok"]:
        return res
    bfc, _ = baseline_field()
    fc, fi = _field_mul_cycles(inc)
    res.update({
        "field_mul_cycles": fc, "field_mul_instrs": fi,
        "field_mul_speedup": round(bfc / fc, 3),
        "field_mul_ms_8088": round(fc / CPU_HZ * 1000, 3),
    })
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("variant", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    res = evaluate(a.variant or "p256_real.inc", full=a.full)
    print(json.dumps(res, indent=None if a.json else 2))
    sys.exit(0 if res["ok"] else 1)


if __name__ == "__main__":
    main()
