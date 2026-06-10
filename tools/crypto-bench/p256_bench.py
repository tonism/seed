#!/usr/bin/env python3
"""Cost + size benchmark for one real P-256 ECDHE scalar multiply on a 4.77 MHz 8088.

Run AFTER p256_verify.py confirms correctness. Measures, via the calibrated
cycles8088.py model (~99% vs real 86Box):

  * one full p256_scalar_mult_mixed (PEER_PRIVATE x G) -- cycles, ms, instrs
  * component primitives isolated by the 2-minus-1 method (subtract the
    one-call image from the two-call image to cancel caller/setup overhead):
    field multiply, point double, point add, inv_mod
  * code size in bytes of the real P-256 routines

Numbers are MODEL estimates; run86box.py is the 4.77 MHz ground truth (serial).
"""
from __future__ import annotations

import struct

import p256_bench_harness as H
from p256_bench_harness import oracle, P, G, PEER_PRIVATE, PEER_PUBLIC, SHARED_X, CPU_HZ


def _measure(caller, setup, count=60_000_000):
    img, exp = H._build_p256(caller)
    r = H.Run(img, exp)
    r.run(setup=setup, cycles=True, count=count)
    return r.cycles, r.instr_count


def _ms(cycles):
    return cycles / CPU_HZ * 1000.0


# ---------------------------------------------------------------------------
def measure_scalar_mult():
    caller = """
    mov word [p256_affine_x_ptr], tls_server_ec_x_words
    mov word [p256_affine_y_ptr], tls_server_ec_y_words
    mov si, p256_client_private
    call p256_scalar_mult_mixed
"""

    def setup(uc, e):
        H._write_field(uc, e["p256_client_private"], PEER_PRIVATE)
        H._write_field(uc, e["tls_server_ec_x_words"], G[0])
        H._write_field(uc, e["tls_server_ec_y_words"], G[1])
    return _measure(caller, setup)


def measure_full_ecdhe():
    """Scalar mult + final inversion + 2 muls = a complete ECDHE shared-secret."""
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

    def setup(uc, e):
        H._write_field(uc, e["p256_client_private"], PEER_PRIVATE)
        H._write_field(uc, e["tls_server_ec_x_words"], G[0])
        H._write_field(uc, e["tls_server_ec_y_words"], G[1])
    return _measure(caller, setup)


def measure_primitive(body_call, setup, n1=1, n2=2):
    """2-minus-1 isolation: (cost of n2 calls) - (cost of n1 calls), per extra call."""
    def caller_n(n):
        return body_call * n
    c1, i1 = _measure(caller_n(n1), setup)
    c2, i2 = _measure(caller_n(n2), setup)
    div = n2 - n1
    return (c2 - c1) // div, (i2 - i1) // div


def measure_field_mul():
    call = """
    mov si, p256_s0
    mov di, p256_s1
    mov bx, p256_s2
    call p256_mul_mod
"""

    def setup(uc, e):
        H._write_field(uc, e["p256_s0"], PEER_PUBLIC[0])
        H._write_field(uc, e["p256_s1"], PEER_PUBLIC[1])
    return measure_primitive(call, setup)


def measure_field_add():
    call = """
    mov si, p256_s0
    mov di, p256_s1
    mov bx, p256_s2
    call p256_add_mod
"""

    def setup(uc, e):
        H._write_field(uc, e["p256_s0"], PEER_PUBLIC[0])
        H._write_field(uc, e["p256_s1"], PEER_PUBLIC[1])
    return measure_primitive(call, setup)


def measure_point_double():
    call = "    call p256_point_double_jacobian\n"

    def setup(uc, e):
        # a stable non-degenerate point so repeated doubling stays well-defined
        H._write_field(uc, e["p256_jac_x"], G[0])
        H._write_field(uc, e["p256_jac_y"], G[1])
        H._write_field(uc, e["p256_jac_z"], 1)
    # doubling N times changes the point but cost-per-double is essentially
    # constant (constant-time field ops); 2-minus-1 still isolates one double.
    return measure_primitive(call, setup)


def measure_point_add():
    call = """
    mov word [p256_affine_x_ptr], tls_server_ec_x_words
    mov word [p256_affine_y_ptr], tls_server_ec_y_words
    call p256_point_add_mixed
"""

    def setup(uc, e):
        two_g = oracle.jacobian_double_words((G[0], G[1], 1))
        H._write_field(uc, e["p256_jac_x"], two_g[0])
        H._write_field(uc, e["p256_jac_y"], two_g[1])
        H._write_field(uc, e["p256_jac_z"], two_g[2])
        H._write_field(uc, e["tls_server_ec_x_words"], G[0])
        H._write_field(uc, e["tls_server_ec_y_words"], G[1])
    return measure_primitive(call, setup)


def measure_inv():
    # inv_mod consumes its input buffer (p256_s0) as internal scratch, so the
    # 2-minus-1 method would feed the 2nd call garbage. Measure ONE isolated
    # call and subtract the (4-cycle) empty baseline instead.
    call = """
    mov si, p256_s0
    mov di, p256_s1
    call p256_inv_mod
"""

    def setup(uc, e):
        H._write_field(uc, e["p256_s0"], PEER_PUBLIC[0])
    c1, i1 = _measure(call, setup)
    c0, i0 = _measure("    nop\n", setup)
    return c1 - c0, i1 - i0


# ---------------------------------------------------------------------------
def measure_code_size():
    """Bytes of the real P-256 routines (field math + point ops + scalar mult).

    Assemble p256_real.inc as a standalone -f bin module with our data block and
    read the labelled span. We bracket from the first routine (p256_from_be32)
    to the end-of-code marker placed right before the data segment.
    """
    # Use nasm map-free: emit a code-start and code-end label and diff exports.
    P256_MAGIC = 0xBEEFF00D
    body = (
        "__p256_code_start:\n"
        '%include "p256_real.inc"\n'
        "__p256_code_end:\n"
        f"\n__p256_exports:\n    dd 0x{P256_MAGIC:08X}\n"
        + "    dd __p256_code_start\n    dd __p256_code_end\n"
        + H.P256_DATA
    )
    img, exports = H.build(body, "    nop\n")
    marker = struct.pack("<I", P256_MAGIC)
    pos = img.find(marker)
    start, end = struct.unpack_from("<2I", img, pos + 4)
    return end - start


if __name__ == "__main__":
    print("=== P-256 real ECDHE cost on 4.77 MHz 8088 (cycles8088 model) ===\n")

    size = measure_code_size()
    print(f"CODE SIZE (real P-256 field+point+scalar):  {size} bytes\n")

    print("--- component primitives (one call, 2-minus-1 isolated) ---")
    mc, mi = measure_field_mul()
    print(f"field multiply  p256_mul_mod :  {mc:>10,} cyc  {_ms(mc):8.3f} ms  {mi:>6} instrs")
    ac, ai = measure_field_add()
    print(f"field add       p256_add_mod :  {ac:>10,} cyc  {_ms(ac):8.3f} ms  {ai:>6} instrs")
    dc, di_ = measure_point_double()
    print(f"point double                 :  {dc:>10,} cyc  {_ms(dc):8.3f} ms  {di_:>6} instrs")
    pc, pi = measure_point_add()
    print(f"point add (mixed)            :  {pc:>10,} cyc  {_ms(pc):8.3f} ms  {pi:>6} instrs")
    ic, ii = measure_inv()
    print(f"inv_mod (final, Fermat-egcd) :  {ic:>10,} cyc  {_ms(ic):8.3f} ms  {ii:>6} instrs")

    print("\n--- full operations ---")
    sc, si_ = measure_scalar_mult()
    print(f"ONE scalar mult (PEER_PRIVATE x G):")
    print(f"    {sc:,} cycles   {_ms(sc):.1f} ms   {_ms(sc)/1000:.3f} s   {si_:,} instrs")
    ec, ei = measure_full_ecdhe()
    print(f"FULL ECDHE (scalar mult + inv + 2 mul -> shared X):")
    print(f"    {ec:,} cycles   {_ms(ec):.1f} ms   {_ms(ec)/1000:.3f} s   {ei:,} instrs")

    print(f"\n(4.77 MHz = {CPU_HZ:.0f} Hz; model calibrated ~99% vs 86Box)")
