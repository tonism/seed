#!/usr/bin/env python3
"""Host-side crypto micro-benchmark harness for Seed's 8088 crypto.

Two cheap tiers, no 86Box needed:
  * CORRECTNESS (instant, parallel): assemble a variant with nasm, run its entry
    in unicorn (16-bit real mode), read the result out of emulated RAM, compare
    against an OpenSSL/hashlib reference vector.
  * SPEED estimate (instant): a static 8088 cycle-cost model over the executed
    instruction stream (see cycles8088.py). 86Box BIOS-tick timing stays the
    authoritative 4.77 MHz ground truth (run86box.py) and calibrates the model.

The crypto under test references FIXED data addresses from the real
layout.inc/data.inc (e.g. sha256_k=0x0500, sha256_state, sha256_block). The
harness assembles [layout.inc + data.inc EQU map] + [the variant body] + [a
caller], deploys the SHA/TLS constants into RAM exactly as tls_client_hello.inc
does at boot, sets inputs, runs, and reads results.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS,
    UC_X86_REG_SP, UC_X86_REG_IP, UC_X86_REG_FLAGS,
)

ROOT = Path(__file__).resolve().parents[2]
BOOT_INC = ROOT / "targets" / "ibm_pc_5150" / "boot"          # -I root: "core/..." resolves
CORE = BOOT_INC / "core"
BENCH = Path(__file__).resolve().parent

MEM_SIZE = 0x20000          # 128 KiB flat; CS=DS=ES=SS=0
CODE_ORG = 0x1000           # match the real SEED.SYS load address
STACK_TOP = 0xF000          # below the 64 KiB seg-0 wrap, well above crypto data/code


# ---------------------------------------------------------------------------
# SHA-256 / TLS constant deployment (mirrors phases/tls_client_hello.inc)
# ---------------------------------------------------------------------------
def _sha256_k() -> bytes:
    """64 round constants, little-endian 32-bit, as stored at sha256_k."""
    k = []
    primes = []
    n = 2
    while len(primes) < 64:
        if all(n % d for d in range(2, int(n**0.5) + 1)):
            primes.append(n)
        n += 1
    for p in primes:
        frac = (p ** (1.0 / 3.0)) % 1
        k.append(int(frac * (1 << 32)))
    return b"".join(struct.pack("<I", v) for v in k)


def _sha256_h0() -> bytes:
    """8 initial hash words, little-endian 32-bit, as stored at sha256_initial_state."""
    h = []
    primes = [2, 3, 5, 7, 11, 13, 17, 19]
    for p in primes:
        frac = (p ** 0.5) % 1
        h.append(int(frac * (1 << 32)))
    return b"".join(struct.pack("<I", v) for v in h)


def low_static_constants() -> bytes:
    """The exact low_static_constants block deployed at boot (data.inc:181-196)."""
    blk = b"master secret"          # 13
    blk += b"client finished"       # 15
    blk += b"server finished"       # 15
    blk += b"key expansion"         # 13
    blk += b"expand 32-byte k"      # 16  (ChaCha sigma)
    blk += b"\xfb" + b"\xff" * 15 + b"\x03"   # 17  poly1305 prime
    blk += _sha256_h0()             # 32
    assert len(blk) == 121, len(blk)
    return blk


SHA256_K = _sha256_k()
assert SHA256_K[:4] == struct.pack("<I", 0x428A2F98)


# ---------------------------------------------------------------------------
# assembling
# ---------------------------------------------------------------------------
def assemble(src: str) -> bytes:
    """nasm -f bin a source string; -I the boot dir so core/*.inc resolves."""
    with tempfile.TemporaryDirectory() as td:
        s = Path(td) / "v.asm"
        o = Path(td) / "v.bin"
        s.write_text(src)
        r = subprocess.run(
            ["nasm", "-f", "bin", f"-I{BOOT_INC}/", f"-I{BENCH}/", "-o", str(o), str(s)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"nasm failed:\n{r.stderr}\n--- source ---\n{src}")
        return o.read_bytes()


# An export table at org so Python learns the resolved EQU addresses without
# parsing nasm symbol tables. Order matters; keep in sync with EXPORTS.
EXPORTS = [
    "sha256_k", "sha256_initial_state", "low_static_constants_start",
    "low_static_constants_len", "sha256_block", "sha256_state", "sha256_w",
    "tls_premaster_secret", "tls_random", "tls_server_random",
    "tls_master_secret", "tls_key_block", "tls_prf_seed",
]

EXPORT_MAGIC = 0xC0DECAFE
# data.inc emits a few bytes (dw 0) before our table, and label offsets shift
# with code size, so locate the export table by a magic marker rather than math.
_ALL_EXPORTS = EXPORTS + ["__run", "__done"]

PRELUDE = f"""
bits 16
cpu 8086
org {CODE_ORG}
%include "core/layout.inc"
%include "core/data.inc"
__exports:
    dd 0x{EXPORT_MAGIC:08X}
""" + "".join(f"    dd {name}\n" for name in _ALL_EXPORTS) + """
    jmp __run
"""


def build(body: str, caller: str) -> tuple[bytes, dict]:
    """Assemble prelude+caller+body; return (image, resolved-export-addresses)."""
    src = PRELUDE + "__run:\n" + caller + "\n__done:\n    hlt\n" + body
    img = assemble(src)
    marker = struct.pack("<I", EXPORT_MAGIC)
    pos = img.find(marker)
    if pos < 0:
        raise RuntimeError("export marker not found in assembled image")
    vals = struct.unpack_from("<%dI" % len(_ALL_EXPORTS), img, pos + 4)
    exports = dict(zip(_ALL_EXPORTS, vals))
    return img, exports


# ---------------------------------------------------------------------------
# running in unicorn
# ---------------------------------------------------------------------------
class Run:
    def __init__(self, img: bytes, exports: dict):
        self.img = img
        self.exports = exports
        self.entry = exports["__run"]
        self.done = exports["__done"]
        self.instr_count = 0

    def run(self, setup=None, count=50_000_000, cycles=False):
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, MEM_SIZE)
        uc.mem_write(CODE_ORG, self.img)
        # deploy SHA/TLS constants exactly like the boot phase
        uc.mem_write(self.exports["sha256_k"], SHA256_K)
        uc.mem_write(self.exports["low_static_constants_start"], low_static_constants())
        for reg in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            uc.reg_write(reg, 0)
        uc.reg_write(UC_X86_REG_SP, STACK_TOP)
        uc.reg_write(UC_X86_REG_FLAGS, 0x0002)
        if setup:
            setup(uc, self.exports)

        self.instr_count = 0
        self.cyc = None
        if cycles:
            from cycles8088 import Cycle8088
            self.cyc = Cycle8088()

            def _h(uc, addr, size, _):
                self.instr_count += 1
                self.cyc.hook(uc, addr, size, _)
            uc.hook_add(UC_HOOK_CODE, _h)
        else:
            def _count(uc, addr, size, _):
                self.instr_count += 1
            uc.hook_add(UC_HOOK_CODE, _count)

        uc.emu_start(self.entry, self.done, count=count)
        if self.cyc:
            self.cyc.finish()
            self.cycles = self.cyc.cycles
        self.uc = uc
        return uc


def reference_sha256_block_state(block: bytes, state_in: list[int]) -> list[int]:
    """One SHA-256 compression on a 64-byte block given 8-word input state."""
    k = struct.unpack("<64I", SHA256_K)
    w = list(struct.unpack(">16I", block))
    def rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
    for i in range(16, 64):
        s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = state_in
    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state_in, [a, b, c, d, e, f, g, h])]


# ---------------------------------------------------------------------------
# self-test against the REAL sha256.inc (proves the whole approach)
# ---------------------------------------------------------------------------
def selftest_sha256():
    body = '%include "core/sha256.inc"\n'
    DIG = 0x4000
    caller = f"""
    call sha256_init
    mov si, __msg
    mov cx, __msglen
    call sha256_update
    mov di, {DIG}
    call sha256_finish
"""
    # message + length live after __done in the body region; declare them in body
    body = (
        f"__msg: db 'abc'\n__msglen equ $ - __msg\n" + body
    )
    img, exports = build(body, caller)
    r = Run(img, exports)
    uc = r.run()
    digest = uc.mem_read(DIG, 32)
    want = hashlib.sha256(b"abc").digest()
    ok = bytes(digest) == want
    print(f"[sha256 full init/update/finish 'abc'] {'OK' if ok else 'MISMATCH'} "
          f"({r.instr_count} instrs)")
    print("  got ", bytes(digest).hex())
    print("  want", want.hex())
    if not ok:
        raise SystemExit("baseline sha256 mismatch -- harness or layout assumption wrong")

    # also exercise a longer message that spans 2 blocks + padding
    msg = b"The quick brown fox jumps over the lazy dog" * 3
    body2 = '%include "core/sha256.inc"\n'
    body2 = f"__msg: db {','.join(str(b) for b in msg)}\n__msglen equ $ - __msg\n" + body2
    img2, exp2 = build(body2, caller)
    r2 = Run(img2, exp2)
    uc2 = r2.run()
    d2 = bytes(uc2.mem_read(DIG, 32))
    ok2 = d2 == hashlib.sha256(msg).digest()
    print(f"[sha256 multi-block {len(msg)}B] {'OK' if ok2 else 'MISMATCH'} ({r2.instr_count} instrs)")
    if not ok2:
        raise SystemExit("baseline sha256 multiblock mismatch")
    return r.instr_count


def selftest_prf():
    """Master secret + key block via the real PRF driver, vs check-tls-prf vectors."""
    body = '%include "core/sha256.inc"\n%include "prf_driver.inc"\n'
    caller = """
    call tls_prepare_master_secret
    call tls_prepare_key_block
"""
    img, exports = build(body, caller)

    def setup(uc, exp):
        uc.mem_write(exp["tls_premaster_secret"], bytes(range(0x20)))
        uc.mem_write(exp["tls_random"], bytes(range(0x20, 0x40)))
        uc.mem_write(exp["tls_server_random"], bytes(range(0x40, 0x60)))

    r = Run(img, exports)
    uc = r.run(setup=setup)
    master = bytes(uc.mem_read(exports["tls_master_secret"], 48))
    keyblk = bytes(uc.mem_read(exports["tls_key_block"], 88))

    want_master = bytes.fromhex(
        "518bc65fd30dabe86349152f98435c94d907b50c92a931c5"
        "a2f9e3a4d90f3439f2726c763fb1a40aec90b8bc60173f7c")
    want_keyblk = bytes.fromhex(
        "9052d2e0e4485b2e323effcbc8a47e0839454ba1588ffbc35dccffd8fe8f67f3"
        "6aee3d733b5a6abc5818a826fab3fea582291c5ae2097fcbbcb6038cd5d6a970"
        "f236e9b87b13063de4518cc80660e7a4003c02ee214c1c93")
    ok = master == want_master and keyblk == want_keyblk
    print(f"[tls prf master+keyblock] {'OK' if ok else 'MISMATCH'} ({r.instr_count} instrs)")
    print("  master got ", master.hex())
    print("  master want", want_master.hex())
    if not ok:
        print("  keyblk got ", keyblk.hex())
        print("  keyblk want", want_keyblk.hex())
        raise SystemExit("baseline PRF mismatch")
    return r.instr_count


if __name__ == "__main__":
    selftest_sha256()
    selftest_prf()
