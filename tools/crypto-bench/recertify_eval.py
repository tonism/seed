#!/usr/bin/env python3
"""Drive the REAL 286 secure module's recertify entry points under unicorn.

The rotation-sim fails on hardware but chain_eval (which tests x509_chain_verify.inc, the combined
offline routine) passes -- because the MODULE uses different entry points (p256_ep_capture_chunk /
recertify_prep / chain_verify_sig) wired via the entry table, with their own register conventions.
This loads the built p256_module.bin at its run address and calls those entries exactly as net_phase
does: capture the leaf from a fragmented Certificate -> recertify_prep (parse) -> SHA-256(TBS) in
Python -> chain_verify_sig (vs the baked WR1). Full visibility into the on-device path.

Run: python3 tools/crypto-bench/recertify_eval.py
"""
from __future__ import annotations
import hashlib
import os
import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_16
from unicorn.x86_const import (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS,
                               UC_X86_REG_SP, UC_X86_REG_FLAGS, UC_X86_REG_SI, UC_X86_REG_DI,
                               UC_X86_REG_CX)

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "x509"))
import capture_eval as CE   # cert_message() + the real chain

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
MODULE_BIN = os.path.join(ROOT, "build", "ibm_pc_5150", "p256_module.bin")

MODULE_LOAD = 0x4400          # p256_module_load = loop_cache_start (runtime_stack_top 0x8000 - 0x600 - 27*512)
HANDOFF = 0x0600
HANDOFF_FLAGS = 8
FLAG_286 = 0x0010
# entry-table offsets (layout.inc)
EP = {"parse_leaf": 12, "chain_verify_sig": 14, "adopt_leaf": 16,
      "capture_reset": 30, "capture_chunk": 32, "recertify_prep": 34}
# result block (module +18..+28)
RES = {"tbs_ptr": 18, "tbs_len": 20, "sig_ptr": 22, "mod_ptr": 24, "nb_ptr": 26, "na_ptr": 28}

MEM = 0x20000
STACK = 0xF000
HLT_AT = 0x100                 # a HLT byte the entries "return" to


class Mod:
    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, MEM)
        self.uc.mem_write(MODULE_LOAD, open(MODULE_BIN, "rb").read())
        self.uc.mem_write(HLT_AT, b"\xf4")                         # HLT return target
        for r in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            self.uc.reg_write(r, 0)
        self.uc.reg_write(UC_X86_REG_FLAGS, 0x0002)
        # set the 286 capability flag (the capture + chain entries gate on it)
        cur = struct.unpack("<H", bytes(self.uc.mem_read(HANDOFF + HANDOFF_FLAGS, 2)))[0]
        self.uc.mem_write(HANDOFF + HANDOFF_FLAGS, struct.pack("<H", cur | FLAG_286))

    def ep(self, name):
        return struct.unpack("<H", bytes(self.uc.mem_read(MODULE_LOAD + EP[name], 2)))[0]

    def res(self, name):
        return struct.unpack("<H", bytes(self.uc.mem_read(MODULE_LOAD + RES[name], 2)))[0]

    def call(self, entry_addr, si=0, di=0, cx=0):
        """Call a module routine; return CF (carry flag) after it RETs to our HLT."""
        self.uc.reg_write(UC_X86_REG_SP, STACK)
        self.uc.mem_write(STACK, struct.pack("<H", HLT_AT))        # return address
        self.uc.reg_write(UC_X86_REG_SI, si)
        self.uc.reg_write(UC_X86_REG_DI, di)
        self.uc.reg_write(UC_X86_REG_CX, cx)
        from unicorn.x86_const import UC_X86_REG_IP
        try:
            self.uc.emu_start(entry_addr, HLT_AT, count=50_000_000)
        except Exception as e:
            ip = self.uc.reg_read(UC_X86_REG_IP)
            print(f"    !! fault at IP={ip:#06x} (entry was {entry_addr:#06x}): {e}")
            raise
        return bool(self.uc.reg_read(UC_X86_REG_FLAGS) & 0x1)


def main() -> int:
    if not os.path.exists(MODULE_BIN):
        print("build p256_module.bin first (make)"); return 1
    leaf = CE.LEAF
    msg = CE.cert_message(leaf, CE.WR1, CE.ROOT)
    m = Mod()
    # Place the cert + capture buffer BELOW the module (0x4400+) with no overlap (the exact addresses
    # are arbitrary for the test; the device uses the arena, passed via capture_leaf_reset's DI).
    cert_at = 0x1000                                             # 4585 B -> 0x1000..0x2199
    cap_buf = 0x2800                                             # leaf 1342 B -> 0x2800..0x2d3e (clear of cert + module)
    m.uc.mem_write(cert_at, msg)
    print(f"module @ {MODULE_LOAD:#x}; cert {len(msg)} B; leaf {len(leaf)} B")

    # 1. capture: reset(di=cap_buf) then feed 592-byte fragments
    m.call(m.ep("capture_reset"), di=cap_buf)
    pos = 0
    while pos < len(msg):
        n = min(592, len(msg) - pos)
        m.call(m.ep("capture_chunk"), si=cert_at + pos, cx=n)
        pos += n
    captured = bytes(m.uc.mem_read(cap_buf, len(leaf)))
    cap_ok = captured == leaf
    print(f"  [{'PASS' if cap_ok else 'FAIL'}] module capture == leaf.der")

    # 2. recertify_prep: parse the captured leaf -> result block
    cf = m.call(m.ep("recertify_prep"))
    prep_ok = not cf
    print(f"  [{'PASS' if prep_ok else 'FAIL'}] recertify_prep CF=0 (leaf parsed)")
    if prep_ok:
        tbs_ptr, tbs_len, sig_ptr = m.res("tbs_ptr"), m.res("tbs_len"), m.res("sig_ptr")
        tbs = bytes(m.uc.mem_read(tbs_ptr, tbs_len))
        h = hashlib.sha256(tbs).digest()
        # check the TBS the module pointed at hashes to what WR1 signed
        tbs_ok = hashlib.sha256(tbs).hexdigest() == hashlib.sha256(leaf[4:4 + 1062]).hexdigest()
        print(f"  [{'PASS' if tbs_ok else 'FAIL'}] result TBS span correct (sha {h.hex()[:8]})")
        # 3. chain_verify_sig: leaf sig (result sig_ptr) chains to the baked WR1, over the TBS hash
        hash_buf = 0x3600                                        # high_crypto_work (as net_phase uses)
        m.uc.mem_write(hash_buf, h)
        cf = m.call(m.ep("chain_verify_sig"), si=sig_ptr, di=hash_buf)
        chain_ok = not cf
        print(f"  [{'PASS' if chain_ok else 'FAIL'}] chain_verify_sig CF=0 (leaf chains to WR1)")
        ok = cap_ok and prep_ok and tbs_ok and chain_ok
    else:
        ok = False
    print(f"\nOVERALL: {'ALL GREEN — the module recertify path works' if ok else 'FAILURE LOCALIZED above'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
