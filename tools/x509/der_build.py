#!/usr/bin/env python3
"""Minimal DER X.509 cert ASSEMBLER + a synthetic RSA signer — for the tamper matrix ONLY.

Why this exists: to prove the SAN and validity gates fire *independently of the signature*, the
tamper matrix needs certificates that carry a VALID signature but violate policy (wrong host,
expired, duplicate extension). We can't forge WR1's signature, so we mint such certs under a
SYNTHETIC RSA CA whose private key we control. This module builds the TBSCertificate, signs it
RSA-PKCS#1-v1.5-SHA256 (raw pow with the synthetic d), and wraps the Certificate — the exact
inverse of x509_verify.parse_certificate, so it doubles as a structural spec.

The synthetic key is generated DETERMINISTICALLY (fixed seed) so the test vectors are stable and
committable. This is test-only RNG — NOT a secure keygen, and it never touches the device.
"""
from __future__ import annotations
import hashlib
import random

# ---- DER primitives ----------------------------------------------------------------------------
def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])                                   # short form
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes([0x80 | len(out)]) + bytes(out)            # minimal long form

def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_len(len(content)) + content

def enc_int(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body                            # keep it unsigned
    return tlv(0x02, body)

def enc_uint_bytes(raw: bytes) -> bytes:
    """INTEGER from raw big-endian bytes (used for the serial), kept unsigned + minimal."""
    raw = raw.lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return tlv(0x02, raw)

# OID TLVs (full, ready to embed)
OID_SHA256_RSA = bytes.fromhex("06092A864886F70D01010B")
OID_RSA_ENC    = bytes.fromhex("06092A864886F70D010101")
OID_SAN        = bytes.fromhex("0603551D11")
OID_CN         = bytes.fromhex("0603550403")                # 2.5.29.4? no -> commonName 2.5.4.3
OID_KEYUSAGE   = bytes.fromhex("0603551D0F")                # 2.5.29.15

SIGALG_SHA256RSA = tlv(0x30, OID_SHA256_RSA + tlv(0x05, b""))   # SEQ{ OID, NULL }

def enc_name_cn(cn: str) -> bytes:
    atv = tlv(0x30, OID_CN + tlv(0x0C, cn.encode()))         # SEQ{ OID commonName, UTF8String }
    rdn = tlv(0x31, atv)                                     # SET
    return tlv(0x30, rdn)                                    # SEQUENCE OF RDN

def enc_validity(not_before: str, not_after: str) -> bytes:
    # UTCTime "YYMMDDHHMMSSZ"
    return tlv(0x30, tlv(0x17, not_before.encode()) + tlv(0x17, not_after.encode()))

def enc_spki(n: int, e: int) -> bytes:
    rsapub = tlv(0x30, enc_int(n) + enc_int(e))             # RSAPublicKey SEQ{ n, e }
    bitstr = tlv(0x03, b"\x00" + rsapub)                    # BIT STRING, 0 unused bits
    algid  = tlv(0x30, OID_RSA_ENC + tlv(0x05, b""))        # SEQ{ rsaEncryption, NULL }
    return tlv(0x30, algid + bitstr)

def enc_ext(oid_tlv: bytes, value: bytes, critical: bool = False) -> bytes:
    body = oid_tlv
    if critical:
        body += tlv(0x01, b"\xff")                          # BOOLEAN TRUE
    body += tlv(0x04, value)                                # OCTET STRING extnValue
    return tlv(0x30, body)

def enc_san_value(dns_names: list[str]) -> bytes:
    gns = b"".join(tlv(0x82, d.encode()) for d in dns_names)   # [2] IMPLICIT dNSName
    return tlv(0x30, gns)                                       # GeneralNames SEQUENCE OF

def san_ext(dns_names: list[str]) -> bytes:
    return enc_ext(OID_SAN, enc_san_value(dns_names))


# ---- synthetic RSA keygen (deterministic, test-only) -------------------------------------------
def _is_probable_prime(n: int, rng: random.Random, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

def _gen_prime(bits: int, rng: random.Random) -> int:
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand, rng):
            return cand

def gen_rsa(bits: int = 2048, seed: int = 0x5EED, e: int = 65537) -> tuple[int, int, int]:
    """Deterministic (n, e, d). Test-only — predictable RNG, not secure."""
    rng = random.Random(seed)
    half = bits // 2
    while True:
        p = _gen_prime(half, rng)
        q = _gen_prime(half, rng)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)
        return n, e, d


# ---- sign a TBS with the synthetic key (RSA-PKCS#1-v1.5-SHA256) ---------------------------------
SHA256_DIGESTINFO = bytes.fromhex("3031300D060960864801650304020105000420")

def rsa_sign_pkcs1_sha256(tbs: bytes, d: int, n: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    h = hashlib.sha256(tbs).digest()
    pad_len = k - 3 - len(SHA256_DIGESTINFO) - len(h)
    em = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + SHA256_DIGESTINFO + h
    s = pow(int.from_bytes(em, "big"), d, n)
    return s.to_bytes(k, "big")


# ---- assemble a full Certificate ---------------------------------------------------------------
def build_tbs(*, serial: bytes, issuer_cn: str, subject_cn: str, not_before: str, not_after: str,
              leaf_n: int, leaf_e: int, extensions: list[bytes]) -> bytes:
    version = tlv(0xA0, enc_int(2))                          # [0] EXPLICIT version v3
    body = (version + enc_uint_bytes(serial) + SIGALG_SHA256RSA + enc_name_cn(issuer_cn)
            + enc_validity(not_before, not_after) + enc_name_cn(subject_cn)
            + enc_spki(leaf_n, leaf_e) + tlv(0xA3, tlv(0x30, b"".join(extensions))))
    return tlv(0x30, body)

def build_cert(tbs: bytes, signature: bytes) -> bytes:
    return tlv(0x30, tbs + SIGALG_SHA256RSA + tlv(0x03, b"\x00" + signature))

def mint_cert(*, ca_n: int, ca_d: int, serial: bytes = b"\x01", issuer_cn: str = "Synthetic Test CA",
              subject_cn: str = "api.openai.com", not_before: str = "200101000000Z",
              not_after: str = "300101000000Z", leaf_n: int | None = None, leaf_e: int = 65537,
              dns_names: list[str] | None = None, extra_extensions: list[bytes] | None = None) -> bytes:
    """Mint a Certificate signed by the synthetic CA. leaf_* default to a separate RSA-2048 leaf
    key (so the adopted-key checks see a real RSA-2048/65537 key). Returns DER bytes."""
    if leaf_n is None:
        leaf_n, _, _ = gen_rsa(2048, seed=0x1EAF)            # a distinct leaf key
    if dns_names is None:
        dns_names = ["api.openai.com", "*.api.openai.com"]
    exts = [san_ext(dns_names)]
    if extra_extensions:
        exts += extra_extensions
    tbs = build_tbs(serial=serial, issuer_cn=issuer_cn, subject_cn=subject_cn,
                    not_before=not_before, not_after=not_after, leaf_n=leaf_n, leaf_e=leaf_e,
                    extensions=exts)
    sig = rsa_sign_pkcs1_sha256(tbs, ca_d, ca_n)
    return build_cert(tbs, sig)


if __name__ == "__main__":
    # smoke: mint a baseline cert and round-trip it through the verifier
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    import x509_verify as X
    n, e, d = gen_rsa(2048, seed=0x5EED)
    cert = mint_cert(ca_n=n, ca_d=d)
    res = X.verify_leaf(cert, n, e, host="api.openai.com",
                        now=__import__("datetime").datetime(2026, 6, 14, tzinfo=__import__("datetime").timezone.utc))
    print(f"synthetic CA RSA-{n.bit_length()} e={e}")
    print(f"baseline synthetic leaf -> {'ACCEPT' if res.accepted else 'REJECT'}: {res.reason}")
    sys.exit(0 if res.accepted else 1)
