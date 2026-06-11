#!/usr/bin/env python3
"""Feasibility benchmark for Seed's dormant *real* P-256 ECDHE on a 4.77 MHz 8088.

The real constant-time P-256 field math + Jacobian point ops + scalar multiply
live under `%if 0` in targets/ibm_pc_5150/boot/core/p256.inc and have never been
assembled. This harness:

  1. assembles that dormant code (extracted to p256_real.inc) under `cpu 8086`,
     supplying ALL the ~39 buffer/var/constant symbols it references (their
     layout was never committed),
  2. verifies it INCREMENTALLY against the Python oracle in tools/check-p256.py
     (field mul/add/sub/inv, point double/add, then the full scalar multiply
     PEER_PRIVATE x G == PEER_PUBLIC),
  3. measures 8088 cycles (cycles8088.py, ~99% vs real 86Box) and code size for
     one real ECDHE scalar multiplication and its component primitives.

Reuses bench_harness.build()/Run for the assemble+unicorn machinery.
"""
from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

import bench_harness as bh
from bench_harness import build, Run

# ---------------------------------------------------------------------------
# the oracle (faithful python mirror of the asm word-level algorithm)
# ---------------------------------------------------------------------------
_spec = importlib.util.spec_from_file_location(
    "checkp256", Path(__file__).resolve().parents[1] / "check-p256.py"
)
oracle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oracle)

P = oracle.P
G = oracle.G
PEER_PRIVATE = oracle.PEER_PRIVATE
PEER_PUBLIC = oracle.PEER_PUBLIC
CLIENT_PUBLIC = oracle.CLIENT_PUBLIC
SHARED_X = oracle.SHARED_X
WORD_COUNT = 16

CPU_HZ = 4772728.0

# ---------------------------------------------------------------------------
# P-256 data segment definitions (never committed -- we lay them out here).
#
# Field element = 16 LE 16-bit words (32 B). p256_product is double-width
# (32 words / 64 B). p256_reduce_acc holds 16 *32-bit* accumulators
# (16 * 4 B = 64 B, the asm strides by 4 and writes [di]/[di+2]).
# p256_reduce_coeffs is a 16x16 table the asm reads BYTE-wise via lodsb,
# where -1 is encoded 0xff (handled as a subtract), 1/2/3 as add/shl/shl+add.
#
# Emitted as a nasm body block. Buffers are zero-filled; constants get real
# values. Generous and gap-free is fine -- correctness vs the oracle is the
# gate and this is a cost benchmark, not the shipped tight layout.
# ---------------------------------------------------------------------------

def _prime_words_db() -> str:
    words = oracle.to_words_le(P)
    return "p256_prime: dw " + ",".join(str(w) for w in words) + "\n"


def _reduce_coeffs_db() -> str:
    """16 rows x 16 signed bytes; -1 -> 0xff (the asm subtracts on 0xff)."""
    rows = oracle.reduce_coeff_rows()
    out = []
    for row in rows:
        bytes_ = [(v & 0xFF) for v in row]   # -1 -> 0xff
        out.append("    db " + ",".join(str(b) for b in bytes_))
    return "p256_reduce_coeffs:\n" + "\n".join(out) + "\n"


def _three_words_db() -> str:
    words = oracle.to_words_le(3 % P)
    return "p256_three: dw " + ",".join(str(w) for w in words) + "\n"


# field-element scratch buffers (32 B each)
_FIELD_BUFS = (
    ["p256_jac_x", "p256_jac_y", "p256_jac_z"]
    + [f"p256_s{i}" for i in range(9)]
    + ["p256_client_private"]
    + ["tls_server_ec_x_words", "tls_server_ec_y_words", "tls_shared_x_words"]
)
# tls_premaster_secret is already an EQU in data.inc (-> high_crypto_work, a
# fixed 32 B RAM scratch); p256_to_be32 writes its 32-byte BE output there.

# the data block appended after the code in the assembled image
P256_DATA = (
    "\n; ---- P-256 benchmark data segment (layout defined by the harness) ----\n"
    "align 2\n"
    + _prime_words_db()
    + _three_words_db()
    # scratch + I/O field elements, 32 B (16 words) each, zeroed
    + "".join(f"{name}: times {WORD_COUNT} dw 0\n" for name in _FIELD_BUFS)
    # double-width product (32 words / 64 B); over-allocate a couple words of slack
    + "p256_product: times 36 dw 0\n"
    # 16 x 32-bit reduce accumulators (the asm strides by 4)
    + "p256_reduce_acc: times 18 dd 0\n"
    # 16x16 reduce coefficient table, byte-encoded
    + _reduce_coeffs_db()
    # multiply column accumulators + indices
    + "p256_mul_acc0: dw 0\n"
    + "p256_mul_acc1: dw 0\n"
    + "p256_mul_acc2: dw 0\n"
    + "p256_mul_left_word: dw 0\n"
    + "p256_reduce_carry: dw 0\n"
    + "p256_i: db 0\n"
    + "p256_j: db 0\n"
    + "p256_carry: db 0\n"
    # pointers / scratch vars
    + "p256_left_ptr: dw 0\n"
    + "p256_right_ptr: dw 0\n"
    + "p256_result_ptr: dw 0\n"
    + "p256_inv_output_ptr: dw 0\n"
    + "p256_affine_x_ptr: dw 0\n"
    + "p256_affine_y_ptr: dw 0\n"
    # scalar-loop state
    + "p256_scalar_ptr: dw 0\n"
    + "p256_scalar_word_ptr: dw 0\n"
    + "p256_scalar_word_value: dw 0\n"
    + "p256_scalar_mask: dw 0\n"
    + "p256_scalar_word_count: db 0\n"
)

# extra exports so Python can read result buffers out of RAM by address
P256_EXPORTS = _FIELD_BUFS + ["p256_product", "p256_prime"]


def _build_p256(caller: str, extra_body: str = "", inc: str = "p256_real.inc") -> tuple[bytes, dict]:
    """Assemble the dormant real P-256 code + data + a caller.

    We extend bench_harness.build by appending an export sub-table (located by a
    second magic marker) so the resolved addresses of our P-256 buffers come
    back without parsing nasm symbols.
    """
    P256_MAGIC = 0xBEEFF00D
    export_tbl = (
        f"\n__p256_exports:\n    dd 0x{P256_MAGIC:08X}\n"
        + "".join(f"    dd {name}\n" for name in P256_EXPORTS)
    )
    body = (
        extra_body
        + f'%include "{inc}"\n'
        + export_tbl
        + P256_DATA
    )
    img, exports = build(body, caller)
    marker = struct.pack("<I", P256_MAGIC)
    pos = img.find(marker)
    if pos < 0:
        raise RuntimeError("p256 export marker not found")
    vals = struct.unpack_from("<%dI" % len(P256_EXPORTS), img, pos + 4)
    exports.update(dict(zip(P256_EXPORTS, vals)))
    return img, exports


def _read_field(uc, addr) -> int:
    """Read a 16-word LE field element from emulated RAM as an int."""
    raw = bytes(uc.mem_read(addr, WORD_COUNT * 2))
    words = struct.unpack(f"<{WORD_COUNT}H", raw)
    return oracle.from_words_le(list(words))


def _write_field(uc, addr, value) -> None:
    words = oracle.to_words_le(value % P if value else value)
    uc.mem_write(addr, struct.pack(f"<{WORD_COUNT}H", *words))


if __name__ == "__main__":
    # smoke test: does it assemble at all?
    img, exp = _build_p256("    nop\n")
    print(f"assembled OK: image {len(img)} bytes")
    print("p256_mul_mod at", hex(exp.get("__run", 0)))
