#!/usr/bin/env python3
"""RSA-2048 signature-verify (s^65537 mod N) feasibility/timing bench for the 286.

Shipped Seed TLS does NO cert auth (see project_tls_no_ecdh_honest). This testbench
asks the one remaining projected question for the "286 secure tier": how long is ONE
RSA-2048 verify on the lowest 286? Verify with e=65537 = 16 squarings + 1 multiply of
2048-bit numbers (128 x 16-bit words) with Montgomery reduction (19 montmuls total).

Oracle is trivial: rsa_result must equal pow(s, 65537, N). Mirrors the P-256 harness
(magic-marker export sub-table; buffers defined here, not in any shipped layout). The
real 286 time comes from 86Box (run via rsa_bench.asm); this host harness is the
correctness gate the asm iterates against.
"""
from __future__ import annotations

import random
import struct
from pathlib import Path

import bench_harness as bh
from bench_harness import build, Run

WORDS = 128          # 2048-bit operands, 16-bit little-endian limbs
NBITS = WORDS * 16   # 2048
E = 65537            # the standard RSA public exponent (2^16 + 1)
R = 1 << NBITS       # Montgomery radix


# ---------------------------------------------------------------------------
# a fixed, real RSA-2048 modulus (deterministic -- only the modexp cost matters,
# but use a genuine product-of-two-1024-bit-primes so the benchmark is honest)
# ---------------------------------------------------------------------------
def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rng = random.Random(0xC0FFEE ^ n)
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _det_prime(bits: int, seed: int) -> int:
    rng = random.Random(seed)
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


_p = _det_prime(1024, 0xA11CE)
_q = _det_prime(1024, 0xB0B)
N = _p * _q
assert N.bit_length() == 2048, N.bit_length()

# a signature-sized input (any s < N exercises the identical modexp cost)
SIG = (pow(3, 0x5EED, N) * 0x9E3779B97F4A7C15) % N

# Montgomery setup constants the asm consumes
N0INV = (-pow(N, -1, 1 << 16)) % (1 << 16)   # -N^-1 mod 2^16
R2 = pow(R, 2, N)                            # R^2 mod N  (R = 2^2048)
EXPECTED = pow(SIG, E, N)                    # the oracle answer


# ---------------------------------------------------------------------------
# bignum <-> emulated RAM (128 LE 16-bit words)
# ---------------------------------------------------------------------------
def to_words(value: int) -> list[int]:
    return [(value >> (16 * i)) & 0xFFFF for i in range(WORDS)]


def from_words(words: list[int]) -> int:
    return sum((w & 0xFFFF) << (16 * i) for i, w in enumerate(words))


def write_bignum(uc, addr: int, value: int) -> None:
    uc.mem_write(addr, struct.pack(f"<{WORDS}H", *to_words(value)))


def read_bignum(uc, addr: int) -> int:
    raw = bytes(uc.mem_read(addr, WORDS * 2))
    return from_words(list(struct.unpack(f"<{WORDS}H", raw)))


# ---------------------------------------------------------------------------
# RSA data segment (laid out here; not part of any shipped layout). All 128-word
# (256 B) buffers unless noted. Inputs: rsa_n, rsa_sig, rsa_r2, rsa_n0inv.
# Output: rsa_result. The rest is scratch the asm may use freely.
# ---------------------------------------------------------------------------
def _bignum(name: str, value: int | None = None) -> str:
    if value is None:
        return f"{name}: times {WORDS} dw 0\n"
    return f"{name}: dw " + ",".join(str(w) for w in to_words(value)) + "\n"


RSA_DATA = (
    "\n; ---- RSA-2048 benchmark data segment (defined by the harness) ----\n"
    "align 2\n"
    + _bignum("rsa_n")           # modulus N            (input)
    + _bignum("rsa_sig")         # signature s          (input)
    + _bignum("rsa_r2")          # R^2 mod N            (input, Montgomery)
    + _bignum("rsa_one", 1)      # the constant 1       (for the final montmul-out)
    + _bignum("rsa_result")      # s^65537 mod N        (OUTPUT)
    + "rsa_n0inv: dw 0\n"        # -N^-1 mod 2^16       (input)
    # scratch the asm may use:
    + _bignum("rsa_x")           # working accumulator
    + _bignum("rsa_sm")          # s in Montgomery form
    + _bignum("rsa_tmp")         # spare
    + f"rsa_t: times {WORDS * 2 + 4} dw 0\n"   # montmul CIOS accumulator (2n+4 words)
)

RSA_EXPORTS = [
    "rsa_n", "rsa_sig", "rsa_r2", "rsa_one", "rsa_result", "rsa_n0inv",
    "rsa_x", "rsa_sm", "rsa_tmp", "rsa_t",
]


def build_rsa(caller: str, inc: str = "rsa_verify.inc") -> tuple[bytes, dict]:
    """Assemble the RSA verify code + data + a caller; resolve buffer addresses
    via a magic-marker export sub-table (same trick as the P-256 harness)."""
    RSA_MAGIC = 0x5A5AF00D
    export_tbl = (
        f"\n__rsa_exports:\n    dd 0x{RSA_MAGIC:08X}\n"
        + "".join(f"    dd {name}\n" for name in RSA_EXPORTS)
    )
    body = f'%include "{inc}"\n' + export_tbl + RSA_DATA
    img, exports = build(body, caller)
    marker = struct.pack("<I", RSA_MAGIC)
    pos = img.find(marker)
    if pos < 0:
        raise RuntimeError("rsa export marker not found")
    vals = struct.unpack_from("<%dI" % len(RSA_EXPORTS), img, pos + 4)
    exports.update(dict(zip(RSA_EXPORTS, vals)))
    return img, exports


def deploy_inputs(uc, exp) -> None:
    write_bignum(uc, exp["rsa_n"], N)
    write_bignum(uc, exp["rsa_sig"], SIG)
    write_bignum(uc, exp["rsa_r2"], R2)
    write_bignum(uc, exp["rsa_one"], 1)
    uc.mem_write(exp["rsa_n0inv"], struct.pack("<H", N0INV))


if __name__ == "__main__":
    # smoke: parameters sane + a trivial stub assembles
    print(f"N      = {N:#x}")
    print(f"bits   = {N.bit_length()}")
    print(f"n0inv  = {N0INV:#06x}")
    print(f"expect = {EXPECTED:#x}"[:80] + " ...")
    img, exp = build_rsa("    nop\n", inc="rsa_stub.inc")
    print(f"stub image {len(img)} bytes; rsa_result at {exp['rsa_result']:#06x}")
