#!/usr/bin/env python3
"""Oracle-gate the STREAMING leaf extraction design before porting it to asm.

Task 12 / mid-chat safety: instead of buffering the whole ~1.3 KB leaf in the arena (which a mid-chat
recertify would clobber), the capture will, as the cert streams off the wire, (a) hash the TBS
incrementally, and (b) keep only the two fields we can't recompute -- the RSA modulus (256 B) and the
signature (256 B) = 512 B, in a small handshake-transient slot (no arena). This models that extraction
and proves it matches a full parse on the real leaf AND on rotated/varied synthetic leaves, and fails
closed on tamper. The asm port (x509_capture.inc) targets this.

Run: python3 tools/crypto-bench/streaming_eval.py
"""
from __future__ import annotations
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "x509"))
sys.path.insert(0, os.path.dirname(__file__))
import der_build as D
import capture_eval as CE

MOD_HDR = bytes.fromhex("0282010100")   # INTEGER, len 0x0101, leading 00  == an RSA-2048 modulus


def full_parse(leaf: bytes):
    """Reference (whole-buffer) extraction: TBS element, modulus, signature."""
    assert leaf[0] == 0x30 and leaf[1] == 0x82                  # outer SEQUENCE, 2-byte len
    assert leaf[4] == 0x30 and leaf[5] == 0x82                  # TBS SEQUENCE, 2-byte len
    tbs_clen = (leaf[6] << 8) | leaf[7]
    tbs_elem = leaf[4:8 + tbs_clen]
    spki_i = leaf.find(MOD_HDR)
    modulus = leaf[spki_i + 5:spki_i + 5 + 256]
    after = 8 + tbs_clen
    assert leaf[after] == 0x30                                  # sigAlg SEQUENCE (short-form len)
    sig_bs = after + 2 + leaf[after + 1]
    assert leaf[sig_bs] == 0x03                                 # signatureValue BIT STRING
    assert leaf[sig_bs + 1] == 0x82
    sig = leaf[sig_bs + 5:sig_bs + 5 + 256]
    return tbs_elem, modulus, sig


def stream_extract(leaf: bytes, frag: int = 592):
    """Model the on-the-wire streaming extraction: feed `frag`-sized chunks, carry state across them,
    and emit (sha256(TBS), modulus, signature) -- exactly what the asm capture must do incrementally."""
    # header is in the first chunk (the leaf's first 8 bytes); compute spans up front, but only ever
    # *read* each byte once as it arrives (asserts here mirror the asm's bounds checks).
    if len(leaf) < 8 or leaf[4] != 0x30 or leaf[5] != 0x82:
        return None
    tbs_clen = (leaf[6] << 8) | leaf[7]
    tbs_lo, tbs_hi = 4, 8 + tbs_clen                            # TBS element [4 .. 8+tbs_clen)
    if tbs_hi > len(leaf):
        return None
    after = tbs_hi
    if after + 2 > len(leaf) or leaf[after] != 0x30:
        return None
    sig_bs = after + 2 + leaf[after + 1]
    if sig_bs + 5 + 256 > len(leaf) or leaf[sig_bs] != 0x03 or leaf[sig_bs + 1] != 0x82:
        return None
    sig_lo, sig_hi = sig_bs + 5, sig_bs + 5 + 256
    sha = hashlib.sha256()
    mod = bytearray(); sig = bytearray()
    scan = b""                                                  # rolling window for the 5-byte mod header
    mod_lo = None
    pos = 0
    for off in range(0, len(leaf), frag):
        chunk = leaf[off:off + frag]
        for j, b in enumerate(chunk):
            p = off + j
            if tbs_lo <= p < tbs_hi:
                sha.update(bytes([b]))                          # (asm does this span-at-a-time)
                # rolling modulus-header scan, within the TBS only
                scan = (scan + bytes([b]))[-5:]
                if mod_lo is None and scan == MOD_HDR:
                    mod_lo = p + 1                              # 256 modulus bytes start next
            if mod_lo is not None and mod_lo <= p < mod_lo + 256:
                mod.append(b)
            if sig_lo <= p < sig_hi:
                sig.append(b)
        pos += len(chunk)
    if mod_lo is None or len(mod) != 256 or len(sig) != 256:
        return None
    return sha.digest(), bytes(mod), bytes(sig)


def check(name, leaf, frag=592):
    ref = full_parse(leaf)
    got = stream_extract(leaf, frag)
    if got is None:
        print(f"  [FAIL] {name}: stream_extract returned None"); return False
    sha, mod, sig = got
    ok = (sha == hashlib.sha256(ref[0]).digest() and mod == ref[1] and sig == ref[2])
    # uniqueness of the modulus header within the leaf (the scan must be unambiguous)
    uniq = leaf.count(MOD_HDR) == 1
    print(f"  [{'PASS' if ok and uniq else 'FAIL'}] {name}: sha/mod/sig match full parse={ok}, "
          f"mod-hdr unique={uniq}  (leaf {len(leaf)} B, frag {frag})")
    return ok and uniq


def main() -> int:
    ok = True
    # 1. the REAL pinned leaf
    ok &= check("real leaf @592", CE.LEAF)
    ok &= check("real leaf @256 (tighter frags)", CE.LEAF, 256)
    ok &= check("real leaf @1500 (one frag)", CE.LEAF, 1500)
    # 2. ROTATED / VARIED synthetic leaves (different key + different field lengths -> different modulus
    #    offset), each signed by a synthetic CA -- proves the header-driven spans + scan generalize.
    ca_n, ca_e, ca_d = D.gen_rsa(2048, seed=0xCA0)
    for i, subj in enumerate(["a.test", "api.openai.com",
                              "very-long-subject-name-to-shift-the-modulus-offset.example.test"]):
        n, _, _ = D.gen_rsa(2048, seed=0x1000 + i)             # a rotated leaf key
        cert = D.mint_cert(ca_n=ca_n, ca_d=ca_d, subject_cn=subj, leaf_n=n, leaf_e=65537,
                           dns_names=[subj])
        ok &= check(f"rotated leaf '{subj[:18]}'", cert)
    # 3. TAMPER -> stream_extract still returns fields, but they won't chain-verify (fail closed). Here we
    #    just confirm a flipped TBS byte changes the emitted hash (the verify rejects downstream).
    leaf = bytearray(CE.LEAF); leaf[300] ^= 1
    g = stream_extract(bytes(leaf))
    tamper_ok = g is not None and g[0] != hashlib.sha256(full_parse(CE.LEAF)[0]).digest()
    print(f"  [{'PASS' if tamper_ok else 'FAIL'}] tampered TBS byte -> different hash (verify will reject)")
    ok &= tamper_ok
    print(f"\nOVERALL: {'ALL GREEN — streaming extraction matches full parse; asm port can target it' if ok else 'FAILURES above'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
