#!/usr/bin/env python3
"""Incremental correctness verification of the dormant real P-256 asm vs oracle.

Each stage sets known field elements / points in emulated RAM, calls one asm
entry, reads the result back, and compares against tools/check-p256.py. Run all
stages; the first failure tells you exactly which primitive is wrong.
"""
from __future__ import annotations

import struct

import p256_bench_harness as H
from p256_bench_harness import oracle, P, G, PEER_PRIVATE, PEER_PUBLIC, CLIENT_PUBLIC, SHARED_X, WORD_COUNT


def _rng_vals(n=6):
    seed = 0x123456789ABCDEF
    out = []
    for _ in range(n):
        seed = (seed * 6364136223846793005 + 1442695040888963407) & ((1 << 256) - 1)
        out.append(seed % P)
    return out


TEST_VALS = [0, 1, 2, P - 1, P - 2, P // 2, G[0], G[1],
             PEER_PUBLIC[0], PEER_PUBLIC[1], SHARED_X] + _rng_vals()


# ---------------------------------------------------------------------------
def verify_mul():
    """p256_mul_mod: SI*DI -> BX  (note: entry takes left=SI, right=DI, out=BX)."""
    caller = """
    mov si, p256_s0
    mov di, p256_s1
    mov bx, p256_s2
    call p256_mul_mod
"""
    img, exp = H._build_p256(caller)
    fails = 0
    for a in TEST_VALS:
        for b in TEST_VALS[:8]:
            r = H.Run(img, exp)

            def setup(uc, e, a=a, b=b):
                H._write_field(uc, e["p256_s0"], a)
                H._write_field(uc, e["p256_s1"], b)
            uc = r.run(setup=setup)
            got = H._read_field(uc, exp["p256_s2"])
            want = oracle.mul_words_mod(a, b)
            if got != want:
                fails += 1
                if fails <= 3:
                    print(f"  MUL FAIL a={a:x} b={b:x}\n    got  {got:x}\n    want {want:x}")
    print(f"[p256_mul_mod] {'OK' if fails == 0 else f'{fails} FAILS'} "
          f"({len(TEST_VALS) * 8} cases)")
    return fails == 0


def verify_add_sub():
    for name, asm, oraclefn in (
        ("p256_add_mod", "call p256_add_mod", oracle.add_words_mod),
        ("p256_sub_mod", "call p256_sub_mod", oracle.sub_words_mod),
    ):
        caller = f"""
    mov si, p256_s0
    mov di, p256_s1
    mov bx, p256_s2
    {asm}
"""
        img, exp = H._build_p256(caller)
        fails = 0
        for a in TEST_VALS:
            for b in TEST_VALS[:8]:
                r = H.Run(img, exp)

                def setup(uc, e, a=a, b=b):
                    H._write_field(uc, e["p256_s0"], a)
                    H._write_field(uc, e["p256_s1"], b)
                uc = r.run(setup=setup)
                got = H._read_field(uc, exp["p256_s2"])
                want = oraclefn(a, b)
                if got != want:
                    fails += 1
                    if fails <= 3:
                        print(f"  {name} FAIL a={a:x} b={b:x} got {got:x} want {want:x}")
        print(f"[{name}] {'OK' if fails == 0 else f'{fails} FAILS'}")


def verify_inv():
    """p256_inv_mod: input SI, output DI (Fermat/binary-egcd inverse mod p)."""
    caller = """
    mov si, p256_s0
    mov di, p256_s1
    call p256_inv_mod
"""
    img, exp = H._build_p256(caller)
    fails = 0
    vals = [v for v in TEST_VALS if v != 0][:10]
    for a in vals:
        r = H.Run(img, exp)

        def setup(uc, e, a=a):
            H._write_field(uc, e["p256_s0"], a)
        uc = r.run(setup=setup)
        got = H._read_field(uc, exp["p256_s1"])
        want = oracle.inv_mod(a)
        if got != want:
            fails += 1
            if fails <= 3:
                print(f"  INV FAIL a={a:x}\n    got  {got:x}\n    want {want:x}")
    print(f"[p256_inv_mod] {'OK' if fails == 0 else f'{fails} FAILS'} ({len(vals)} cases)")
    return fails == 0


def verify_double():
    """p256_point_double_jacobian: in-place on p256_jac_{x,y,z}."""
    caller = "    call p256_point_double_jacobian\n"
    img, exp = H._build_p256(caller)
    # double the generator (z=1) and a non-trivial jacobian point
    cases = [
        (G[0], G[1], 1),
        oracle.jacobian_double_words((G[0], G[1], 1)),  # 2G in jacobian
    ]
    fails = 0
    for (x, y, z) in cases:
        r = H.Run(img, exp)

        def setup(uc, e, x=x, y=y, z=z):
            H._write_field(uc, e["p256_jac_x"], x)
            H._write_field(uc, e["p256_jac_y"], y)
            H._write_field(uc, e["p256_jac_z"], z)
        uc = r.run(setup=setup)
        gx = H._read_field(uc, exp["p256_jac_x"])
        gy = H._read_field(uc, exp["p256_jac_y"])
        gz = H._read_field(uc, exp["p256_jac_z"])
        wx, wy, wz = oracle.jacobian_double_words((x, y, z))
        if (gx, gy, gz) != (wx, wy, wz):
            fails += 1
            print(f"  DOUBLE FAIL in=({x:x},{y:x},{z:x})")
            print(f"    got  ({gx:x},{gy:x},{gz:x})")
            print(f"    want ({wx:x},{wy:x},{wz:x})")
    print(f"[p256_point_double_jacobian] {'OK' if fails == 0 else f'{fails} FAILS'}")
    return fails == 0


def verify_add_mixed():
    """p256_point_add_mixed: p256_jac += affine(p256_affine_*_ptr)."""
    caller = """
    mov word [p256_affine_x_ptr], tls_server_ec_x_words
    mov word [p256_affine_y_ptr], tls_server_ec_y_words
    call p256_point_add_mixed
"""
    img, exp = H._build_p256(caller)
    two_g = oracle.jacobian_double_words((G[0], G[1], 1))
    cases = [
        ((G[0], G[1], 1), G),       # G + G  (same point -> doubles)
        (two_g, G),                 # 2G + G = 3G
    ]
    fails = 0
    for (jac, aff) in cases:
        r = H.Run(img, exp)

        def setup(uc, e, jac=jac, aff=aff):
            H._write_field(uc, e["p256_jac_x"], jac[0])
            H._write_field(uc, e["p256_jac_y"], jac[1])
            H._write_field(uc, e["p256_jac_z"], jac[2])
            H._write_field(uc, e["tls_server_ec_x_words"], aff[0])
            H._write_field(uc, e["tls_server_ec_y_words"], aff[1])
        uc = r.run(setup=setup)
        gx = H._read_field(uc, exp["p256_jac_x"])
        gy = H._read_field(uc, exp["p256_jac_y"])
        gz = H._read_field(uc, exp["p256_jac_z"])
        wx, wy, wz = oracle.jacobian_add_mixed_words(jac, aff)
        if (gx, gy, gz) != (wx, wy, wz):
            fails += 1
            print(f"  ADD_MIXED FAIL jac=({jac[0]:x},{jac[1]:x},{jac[2]:x})")
            print(f"    got  ({gx:x},{gy:x},{gz:x})")
            print(f"    want ({wx:x},{wy:x},{wz:x})")
    print(f"[p256_point_add_mixed] {'OK' if fails == 0 else f'{fails} FAILS'}")
    return fails == 0


def verify_scalar_mult():
    """Full p256_scalar_mult_mixed: PEER_PRIVATE x G -> jacobian -> affine == PEER_PUBLIC."""
    caller = """
    mov word [p256_affine_x_ptr], tls_server_ec_x_words
    mov word [p256_affine_y_ptr], tls_server_ec_y_words
    mov si, p256_client_private
    call p256_scalar_mult_mixed
"""
    img, exp = H._build_p256(caller)
    r = H.Run(img, exp)

    def setup(uc, e):
        # scalar = PEER_PRIVATE at p256_client_private (16 LE words)
        H._write_field(uc, e["p256_client_private"], PEER_PRIVATE)
        H._write_field(uc, e["tls_server_ec_x_words"], G[0])
        H._write_field(uc, e["tls_server_ec_y_words"], G[1])
    uc = r.run(setup=setup)
    jx = H._read_field(uc, exp["p256_jac_x"])
    jy = H._read_field(uc, exp["p256_jac_y"])
    jz = H._read_field(uc, exp["p256_jac_z"])
    affine = oracle.jacobian_to_affine((jx, jy, jz))
    ok = affine == PEER_PUBLIC
    print(f"[p256_scalar_mult_mixed PEER_PRIVATE x G] {'OK == PEER_PUBLIC' if ok else 'FAIL'} "
          f"({r.instr_count} instrs)")
    if not ok:
        print(f"  got affine  {affine}")
        print(f"  want        {PEER_PUBLIC}")
    return ok


def verify_full_premaster():
    """End-to-end: p256_compute_server_shared_jacobian + inv -> shared X == SHARED_X.

    Mirrors the .generic_scalar branch of p256_compute_server_premaster_secret
    but with a settable client scalar (the shipped one hardcodes scalar=1)."""
    caller = """
    mov word [p256_affine_x_ptr], tls_server_ec_x_words
    mov word [p256_affine_y_ptr], tls_server_ec_y_words
    mov si, p256_client_private
    call p256_scalar_mult_mixed
    mov si, p256_jac_z
    mov di, p256_s0
    call p256_inv_mod
    mov si, p256_s0
    mov di, p256_s0
    mov bx, p256_s1
    call p256_mul_mod
    mov si, p256_jac_x
    mov di, p256_s1
    mov bx, tls_shared_x_words
    call p256_mul_mod
"""
    img, exp = H._build_p256(caller)
    r = H.Run(img, exp)

    def setup(uc, e):
        H._write_field(uc, e["p256_client_private"], 1)  # client scalar = 1
        H._write_field(uc, e["tls_server_ec_x_words"], PEER_PUBLIC[0])
        H._write_field(uc, e["tls_server_ec_y_words"], PEER_PUBLIC[1])
    uc = r.run(setup=setup)
    # client_private=1 -> shared point = PEER_PUBLIC, X coord = SHARED_X
    shared_x = H._read_field(uc, exp["tls_shared_x_words"])
    ok = shared_x == SHARED_X
    print(f"[shared-X via inv_mod, scalar=1 x PEER_PUBLIC] "
          f"{'OK == SHARED_X' if ok else 'FAIL'}")
    if not ok:
        print(f"  got  {shared_x:x}\n  want {SHARED_X:x}")
    return ok


if __name__ == "__main__":
    print("=== incremental P-256 asm verification vs oracle ===")
    verify_mul()
    verify_add_sub()
    verify_inv()
    verify_double()
    verify_add_mixed()
    verify_scalar_mult()
    verify_full_premaster()
