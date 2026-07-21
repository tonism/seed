#!/usr/bin/env python3
"""The X.509 verifier TAMPER MATRIX — the false-security gate for auto-recertify.

A wrong parser accepts forged certs (the worst failure), so before ANY 286 wiring the oracle
(x509_verify.py) must: ACCEPT the one real leaf, and REJECT every tampered / forged / policy-
violating variant — each by the INTENDED gate (we assert the reject *reason*, so a "right answer
for the wrong reason" still fails the test).

Three layers:
  1. TLV strict-DER unit tests — feed crafted bytes to the reader; every BER/DER malformation must
     raise (indefinite length, non-minimal length, leading-zero length, OOB length, etc).
  2. Real-leaf tampers (anchor = the real WR1) — bit/byte flips break the signature; structural
     edits break the parse. The signature is over the exact TBS, so ANY content mutation is caught.
  3. Synthetic valid-sig policy violations (anchor = a synthetic CA we control) — certs carrying a
     VALID signature but wrong host / expired / duplicate-SAN / unusable-key, to prove the SAN,
     validity, single-SAN and adopt-key gates fire INDEPENDENTLY of the signature.

Run: python3 tools/x509/tamper_matrix.py   (exit 0 == all vectors behaved as required)
"""
from __future__ import annotations
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
import x509_verify as X
import der_build as B

CERTS = os.path.join(os.path.dirname(__file__), "certs")
LEAF = open(os.path.join(CERTS, "leaf.der"), "rb").read()
WR1_N, WR1_E = X.anchor_modulus_from_cert(open(os.path.join(CERTS, "wr1.der"), "rb").read())
REAL_CERT = X.parse_certificate(LEAF)

NOW = datetime(2026, 7, 21, 12, 0, 0, tzinfo=timezone.utc)            # within the real leaf's validity
PAST = datetime(2026, 11, 1, tzinfo=timezone.utc)                     # after the real leaf's notAfter
EARLY = datetime(2026, 1, 1, tzinfo=timezone.utc)                     # before the real leaf's notBefore

# synthetic CA + leaf keys (deterministic; generated once)
print("generating synthetic test keys (deterministic)...", file=sys.stderr)
CA_N, CA_E, CA_D = B.gen_rsa(2048, seed=0x5EED)
LEAF2048_N, _, _ = B.gen_rsa(2048, seed=0x1EAF)
LEAF1024_N, _, _ = B.gen_rsa(1024, seed=0x10AF)


# ---------------------------------------------------------------------------
# layer 1: TLV strict-DER unit tests
# ---------------------------------------------------------------------------
def _expect_dererror(fn, label: str) -> bool:
    try:
        fn()
    except X.DERError:
        return True
    except Exception as e:                                            # wrong exception type == fail
        print(f"  [FAIL] {label}: raised {type(e).__name__}, expected DERError")
        return False
    print(f"  [FAIL] {label}: no error raised (would be accepted)")
    return False


def tlv_unit_tests() -> bool:
    print("== layer 1: TLV strict-DER unit tests ==")
    ok = True
    cases = [
        ("indefinite length (0x80)",            bytes([0x30, 0x80, 0x00, 0x00])),
        ("reserved length octet 0xFF",          bytes([0x30, 0xFF])),
        ("non-minimal long form (0x81 0x7F)",   bytes([0x04, 0x81, 0x7F]) + b"\x00" * 0x7F),
        ("leading-zero length (0x82 0x00 0x80)", bytes([0x04, 0x82, 0x00, 0x80]) + b"\x00" * 0x80),
        ("length exceeds buffer",               bytes([0x04, 0x05, 0x01, 0x02])),
        ("high-tag-number form (0x1F)",         bytes([0x1F, 0x01, 0x00])),
    ]
    for label, raw in cases:
        ok &= _expect_dererror(lambda raw=raw: X.DER(raw).read_tlv(), label)
    # trailing bytes after a complete element
    def trailing():
        r = X.DER(bytes([0x05, 0x00, 0x05, 0x00]))                    # two NULLs
        r.read_tlv()
        r.expect_exhausted("unit")
    ok &= _expect_dererror(trailing, "trailing bytes after element")
    # INTEGER strictness (via _parse_uint over a crafted INTEGER)
    def uint(raw, lbl):
        r = X.DER(raw)
        _, cs, cl, _ = r.read_tlv(X.TAG_INTEGER)
        X._parse_uint(raw, cs, cl)
    ok &= _expect_dererror(lambda: uint(bytes([0x02, 0x01, 0x80]), "neg"), "negative INTEGER")
    ok &= _expect_dererror(lambda: uint(bytes([0x02, 0x02, 0x00, 0x01]), "nonmin"), "non-minimal INTEGER")
    ok &= _expect_dererror(lambda: uint(bytes([0x02, 0x00]), "empty"), "empty INTEGER")
    print(f"  layer 1: {'PASS' if ok else 'FAIL'}")
    return ok


# ---------------------------------------------------------------------------
# helpers for real-leaf surgery
# ---------------------------------------------------------------------------
def flip_bit(buf: bytes, off: int, bit: int = 0) -> bytes:
    b = bytearray(buf)
    b[off] ^= (1 << bit)
    return bytes(b)


def find_offset(buf: bytes, needle: bytes, start: int = 0) -> int:
    i = buf.find(needle, start)
    assert i >= 0, f"needle {needle!r} not found"
    return i


def ber_outer_nonminimal(der: bytes) -> bytes:
    # the real cert outer header is exactly 30 82 LL LL; re-encode the length non-minimally as
    # 30 83 00 LL LL (a spurious leading-zero length octet). Strict DER must reject.
    assert der[0] == 0x30 and der[1] == 0x82, "unexpected outer header"
    return bytes([0x30, 0x83, 0x00]) + der[2:4] + der[4:]


def ber_outer_indefinite(der: bytes) -> bytes:
    assert der[0] == 0x30 and der[1] == 0x82, "unexpected outer header"
    return bytes([0x30, 0x80]) + der[4:] + b"\x00\x00"                # BER indefinite + EOC


# ---------------------------------------------------------------------------
# vector definitions: (name, leaf_der, anchor_n, anchor_e, host, now, expect_accept, reason_substr)
# ---------------------------------------------------------------------------
def build_vectors():
    V = []

    def add(name, leaf, n, e, expect, reason="", host="api.openai.com", now=NOW):
        V.append((name, leaf, n, e, host, now, expect, reason))

    # --- controls (ACCEPT) ---
    add("C1 real leaf -> WR1 (within validity)", LEAF, WR1_N, WR1_E, True)
    synth_base = B.mint_cert(ca_n=CA_N, ca_d=CA_D, leaf_n=LEAF2048_N)
    add("C2 synthetic baseline -> synthetic CA", synth_base, CA_N, CA_E, True)

    # --- real-leaf tampers vs WR1 (REJECT) ---
    sig_off = find_offset(LEAF, REAL_CERT.signature)
    add("R1 signature bit flipped", flip_bit(LEAF, sig_off, 0), WR1_N, WR1_E, False,
        "signature does not verify")
    add("R2 signature last byte changed", flip_bit(LEAF, sig_off + len(REAL_CERT.signature) - 1, 3), WR1_N, WR1_E, False,
        "signature does not verify")
    san_off = find_offset(LEAF, b"api.openai.com", 600)                # the SAN dNSName (inside TBS)
    add("R3 TBS SAN host byte flipped", flip_bit(LEAF, san_off, 0), WR1_N, WR1_E, False,
        "signature does not verify")
    nb_off = find_offset(LEAF, REAL_CERT.validity.not_before.raw)       # notBefore (inside TBS)
    add("R4 TBS validity digit flipped", flip_bit(LEAF, nb_off, 0), WR1_N, WR1_E, False,
        "signature does not verify")
    add("R5 truncated (last byte dropped)", LEAF[:-1], WR1_N, WR1_E, False, "")
    add("R6 truncated (last 300 bytes dropped)", LEAF[:-300], WR1_N, WR1_E, False, "")
    add("R7 over-long (1 trailing byte)", LEAF + b"\x00", WR1_N, WR1_E, False, "trailing")
    add("R8 over-long (64 trailing bytes)", LEAF + b"\xaa" * 64, WR1_N, WR1_E, False, "trailing")
    add("R9 BER outer length non-minimal", ber_outer_nonminimal(LEAF), WR1_N, WR1_E, False,
        "non-minimal")
    add("R10 BER outer length indefinite", ber_outer_indefinite(LEAF), WR1_N, WR1_E, False,
        "indefinite")
    add("R11 real leaf -> WRONG anchor (synth CA)", LEAF, CA_N, CA_E, False,
        "signature does not verify")
    # outer sigAlg OID last byte changed (sha256->other): inner(TBS) != outer -> caught pre-verify
    outer_sigalg_off = find_offset(LEAF, REAL_CERT.outer_sigalg, len(REAL_CERT.tbs_span))
    outer_oid_tail = outer_sigalg_off + REAL_CERT.outer_sigalg.find(X.OID_SHA256_RSA) + len(X.OID_SHA256_RSA) - 1
    assert LEAF[outer_oid_tail] == 0x0B, f"expected outer sigAlg OID tail 0x0B, got {LEAF[outer_oid_tail]:#x}"
    add("R12 outer sigAlg substituted (inner!=outer)", flip_bit(LEAF, outer_oid_tail, 2), WR1_N, WR1_E, False,
        "mismatch")
    add("R13 real leaf, clock past notAfter", LEAF, WR1_N, WR1_E, False, "expired", now=PAST)
    add("R14 real leaf, clock before notBefore", LEAF, WR1_N, WR1_E, False, "not yet valid", now=EARLY)

    # --- synthetic valid-sig policy violations vs synthetic CA (REJECT) ---
    mk = lambda **kw: B.mint_cert(ca_n=CA_N, ca_d=CA_D, leaf_n=kw.pop("leaf_n", LEAF2048_N), **kw)
    add("S1 valid sig, SAN=evil.example.com", mk(dns_names=["evil.example.com"]), CA_N, CA_E, False,
        "does not cover")
    add("S2 valid sig, SAN suffix attack", mk(dns_names=["api.openai.com.evil.com"]), CA_N, CA_E, False,
        "does not cover")
    add("S3 valid sig, SAN prefix attack", mk(dns_names=["notapi.openai.com"]), CA_N, CA_E, False,
        "does not cover")
    add("S4 valid sig, wildcard only (no exact)", mk(dns_names=["*.api.openai.com"]), CA_N, CA_E, False,
        "does not cover")
    add("S5 valid sig, expired", mk(not_before="200101000000Z", not_after="210101000000Z"),
        CA_N, CA_E, False, "expired")
    add("S6 valid sig, not yet valid", mk(not_before="300101000000Z", not_after="310101000000Z"),
        CA_N, CA_E, False, "not yet valid")
    dup = B.mint_cert(ca_n=CA_N, ca_d=CA_D, leaf_n=LEAF2048_N,
                      extra_extensions=[B.san_ext(["api.openai.com"])])   # a SECOND SAN extension
    add("S7 valid sig, duplicate SAN extension", dup, CA_N, CA_E, False, "exactly 1 SubjectAltName")
    add("S8 valid sig, leaf exponent=3 (unusable)", mk(leaf_e=3), CA_N, CA_E, False, "exponent")
    add("S9 valid sig, leaf RSA-1024 (unusable)", mk(leaf_n=LEAF1024_N), CA_N, CA_E, False, "RSA-2048")
    synth_flip = bytearray(synth_base)
    synth_flip[-1] ^= 0x01                                            # flip a signature bit
    add("S10 synthetic cert, signature bit flipped", bytes(synth_flip), CA_N, CA_E, False,
        "signature does not verify")
    add("S11 synthetic cert -> WRONG anchor (WR1)", synth_base, WR1_N, WR1_E, False,
        "signature does not verify")
    return V


# ---------------------------------------------------------------------------
def run() -> int:
    all_ok = tlv_unit_tests()
    print("\n== layers 2-3: cert accept/reject matrix ==")
    vectors = build_vectors()
    width = max(len(v[0]) for v in vectors)
    fails = 0
    for name, leaf, n, e, host, now, expect_accept, reason in vectors:
        res = X.verify_leaf(leaf, n, e, host=host, now=now)
        verdict_ok = (res.accepted == expect_accept)
        reason_ok = (not reason) or (reason.lower() in res.reason.lower())
        ok = verdict_ok and reason_ok
        fails += 0 if ok else 1
        tag = "PASS" if ok else "FAIL"
        want = "ACCEPT" if expect_accept else "REJECT"
        got = "ACCEPT" if res.accepted else "REJECT"
        line = f"  [{tag}] {name:<{width}}  want={want} got={got}"
        if not res.accepted:
            line += f"  ({res.reason})"
        print(line)
        if not verdict_ok:
            print(f"         !! verdict mismatch")
        elif not reason_ok:
            print(f"         !! reason mismatch: expected to contain {reason!r}")
    print()
    total = len(vectors)
    print(f"layer 1 (TLV strict-DER): {'PASS' if all_ok else 'FAIL'}")
    print(f"layers 2-3 (cert matrix): {total - fails}/{total} vectors correct")
    overall = all_ok and fails == 0
    print(f"\nOVERALL: {'ALL GREEN — accept-real, reject-all-tampered' if overall else 'FAILURES PRESENT'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(run())
