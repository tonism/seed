#!/usr/bin/env python3
"""Strict-DER X.509 leaf verifier — the OFFLINE ORACLE for the 286 auto-recertify path.

This is the trust-critical reference: the 286 module's X.509 parser must mirror THIS byte for
byte. The whole point of auto-recertify is to adopt a freshly-presented leaf ONLY after proving
it chains to an anchor we already trust (GTS WR1, the RSA-2048 issuing CA), so a wrong parse =
accepting a forged cert = false security (the worst failure). Hence: strict DER, positional walk,
fail closed, no lax structural acceptance.

What "verify a leaf against the pinned WR1" means, concretely (RFC 5280 + RFC 8017):
  1. Parse the leaf Certificate by POSITION (not by searching) — exact tags, minimal-length DER,
     strict bounds, no trailing bytes. Extract: the tbsCertificate raw span (the signed bytes),
     the inner+outer signatureAlgorithm (both must be sha256WithRSAEncryption and must match),
     validity, subjectPublicKeyInfo (the leaf RSA key to ADOPT), the SAN dNSNames, the signature.
  2. RSA-PKCS#1-v1.5 verify the signature against the PINNED WR1 public key: m = sig^e mod n_WR1,
     then RECONSTRUCT the full EMSA-PKCS1-v1.5 block (00 01 FF..FF 00 DigestInfo SHA256(tbs)) and
     compare all 256 bytes (no lax DigestInfo re-parse — blocks Bleichenbacher/BERserk padding
     forgeries). This is exactly how p256_module.asm verifies the ServerKeyExchange sig already.
  3. Check the SAN contains the exact host (api.openai.com) and the cert is within validity.
Only if ALL pass is the leaf trusted and its SPKI key adopted as the new fast-path pin.

This mirrors the on-device logic; it is NOT meant to be a general X.509 library. stdlib only.
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# DER constants (byte-exact OID TLVs; the device byte-compares these too)
# ---------------------------------------------------------------------------
OID_SHA256_RSA = bytes.fromhex("06092A864886F70D01010B")   # 1.2.840.113549.1.1.11 sha256WithRSAEncryption
OID_RSA_ENC    = bytes.fromhex("06092A864886F70D010101")   # 1.2.840.113549.1.1.1  rsaEncryption
OID_SAN        = bytes.fromhex("0603551D11")               # 2.5.29.17  subjectAltName
# The 19-byte DER DigestInfo prefix for SHA-256 (RFC 8017), identical to rsa_sha256_digestinfo.
SHA256_DIGESTINFO = bytes.fromhex("3031300D060960864801650304020105000420")

TAG_BOOLEAN     = 0x01
TAG_INTEGER     = 0x02
TAG_BITSTRING   = 0x03
TAG_OCTETSTRING = 0x04
TAG_NULL        = 0x05
TAG_OID         = 0x06
TAG_UTF8STRING  = 0x0C
TAG_SEQUENCE    = 0x30
TAG_SET         = 0x31
TAG_UTCTIME     = 0x17
TAG_GENTIME     = 0x18
TAG_CTX0        = 0xA0   # [0] EXPLICIT version
TAG_CTX3        = 0xA3   # [3] EXPLICIT extensions
TAG_DNSNAME     = 0x82   # [2] IMPLICIT IA5String dNSName (primitive) inside GeneralNames


class DERError(Exception):
    """Any strict-DER violation. The verifier turns every one of these into a CLOSED fail."""


# ---------------------------------------------------------------------------
# Strict DER reader. A cursor over a byte buffer with an explicit [pos,end) bound.
# Enforces: minimal-length encoding, no indefinite form, in-bounds lengths, and
# (where the caller asks) exact consumption of a container's content.
# ---------------------------------------------------------------------------
class DER:
    def __init__(self, buf: bytes, pos: int = 0, end: int | None = None):
        self.buf = buf
        self.pos = pos
        self.end = len(buf) if end is None else end
        if self.end > len(buf) or self.pos > self.end:
            raise DERError("reader bounds outside buffer")

    def at_end(self) -> bool:
        return self.pos >= self.end

    def _read_byte(self) -> int:
        if self.pos >= self.end:
            raise DERError("unexpected end of data")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def read_tlv(self, expect_tag: int | None = None) -> tuple[int, int, int, int]:
        """Read one TLV. Returns (tag, content_start, content_len, tlv_start).
        Advances the cursor PAST the value. Strict DER length rules enforced."""
        tlv_start = self.pos
        tag = self._read_byte()
        if (tag & 0x1F) == 0x1F:
            raise DERError("high-tag-number form not allowed")        # not used by X.509 here
        first = self._read_byte()
        if first < 0x80:
            length = first                                            # short form
        elif first == 0x80:
            raise DERError("indefinite length not allowed in DER")
        elif first == 0xFF:
            raise DERError("reserved length octet 0xFF")
        else:
            n = first & 0x7F
            if n > 4:
                raise DERError("length too large")                    # device handles <=2 bytes
            length = 0
            for i in range(n):
                length = (length << 8) | self._read_byte()
            # DER minimal-length: must not be representable in fewer octets, and first octet != 0.
            if length < 0x80:
                raise DERError("non-minimal long-form length (should be short form)")
            if (length >> (8 * (n - 1))) == 0:
                raise DERError("non-minimal long-form length (leading zero octet)")
        content_start = self.pos
        if content_start + length > self.end:
            raise DERError("length exceeds container bound")
        self.pos = content_start + length                            # skip the value
        if expect_tag is not None and tag != expect_tag:
            raise DERError(f"expected tag {expect_tag:#04x}, got {tag:#04x}")
        return tag, content_start, length, tlv_start

    def child(self, content_start: int, content_len: int) -> "DER":
        return DER(self.buf, content_start, content_start + content_len)

    def expect_exhausted(self, what: str):
        if self.pos != self.end:
            raise DERError(f"trailing bytes in {what}")


# ---------------------------------------------------------------------------
# Parsed certificate
# ---------------------------------------------------------------------------
@dataclass
class Validity:
    not_before: datetime
    not_after: datetime


@dataclass
class ParsedCert:
    tbs_span: bytes                      # the exact bytes SHA-256'd and signed
    serial: int
    inner_sigalg: bytes                  # TBS.signature AlgorithmIdentifier (full SEQUENCE bytes)
    outer_sigalg: bytes                  # Certificate.signatureAlgorithm (full SEQUENCE bytes)
    validity: Validity
    spki_modulus: int                    # leaf RSA modulus (to adopt as the new pin)
    spki_exponent: int                   # leaf RSA exponent (must be 65537 for the device)
    spki_bits: int
    dns_names: list[str]                 # SAN dNSNames (collected across all SAN extensions)
    san_count: int                       # number of SubjectAltName extensions (policy: must be 1)
    signature: bytes                     # 256-byte RSA signature value
    issuer_der: bytes = field(repr=False, default=b"")
    subject_der: bytes = field(repr=False, default=b"")


def _parse_time(buf: bytes, tag: int) -> datetime:
    s = buf.decode("ascii")
    if tag == TAG_UTCTIME:
        if len(s) != 13 or s[-1] != "Z":
            raise DERError("UTCTime must be YYMMDDHHMMSSZ")           # strict: seconds + Z required
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy                   # RFC 5280 §4.1.2.5.1
        rest = s[2:]
    elif tag == TAG_GENTIME:
        if len(s) != 15 or s[-1] != "Z":
            raise DERError("GeneralizedTime must be YYYYMMDDHHMMSSZ")
        year = int(s[0:4])
        rest = s[4:]
    else:
        raise DERError(f"unexpected time tag {tag:#04x}")
    mo, da, ho, mi, se = (int(rest[0:2]), int(rest[2:4]), int(rest[4:6]),
                          int(rest[6:8]), int(rest[8:10]))
    if not (1 <= mo <= 12 and 1 <= da <= 31 and ho <= 23 and mi <= 59 and se <= 60):
        raise DERError("time field out of range")
    return datetime(year, mo, da, ho, mi, se, tzinfo=timezone.utc)


def _parse_spki(buf: bytes, cs: int, cl: int) -> tuple[int, int, int]:
    """SubjectPublicKeyInfo -> (modulus, exponent, bits). Requires rsaEncryption."""
    spki = DER(buf, cs, cs + cl)
    _, acs, acl, _ = spki.read_tlv(TAG_SEQUENCE)                     # AlgorithmIdentifier
    alg_rdr = DER(buf, acs, acs + acl)
    otag, ocs, ocl, ostart = alg_rdr.read_tlv(TAG_OID)
    if buf[ostart:ocs + ocl] != OID_RSA_ENC:
        raise DERError("SPKI algorithm is not rsaEncryption")
    # parameters: must be NULL for rsaEncryption
    ptag, pcs, pcl, _ = alg_rdr.read_tlv()
    if ptag != TAG_NULL or pcl != 0:
        raise DERError("rsaEncryption parameters must be NULL")
    alg_rdr.expect_exhausted("SPKI AlgorithmIdentifier")
    btag, bcs, bcl, _ = spki.read_tlv(TAG_BITSTRING)                 # subjectPublicKey BIT STRING
    spki.expect_exhausted("SubjectPublicKeyInfo")
    if bcl < 1 or buf[bcs] != 0x00:
        raise DERError("SPKI BIT STRING must have 0 unused bits")
    rsapub = DER(buf, bcs + 1, bcs + bcl)                           # RSAPublicKey SEQUENCE
    _, rcs, rcl, _ = rsapub.read_tlv(TAG_SEQUENCE)
    rsapub.expect_exhausted("SPKI RSAPublicKey wrapper")
    inner = DER(buf, rcs, rcs + rcl)
    _, mcs, mcl, _ = inner.read_tlv(TAG_INTEGER)                     # modulus
    modulus = _parse_uint(buf, mcs, mcl)
    _, ecs, ecl, _ = inner.read_tlv(TAG_INTEGER)                     # exponent
    exponent = _parse_uint(buf, ecs, ecl)
    inner.expect_exhausted("RSAPublicKey")
    return modulus, exponent, modulus.bit_length()


def _parse_uint(buf: bytes, cs: int, cl: int) -> int:
    """A DER INTEGER that must be non-negative and minimally encoded."""
    if cl == 0:
        raise DERError("empty INTEGER")
    if buf[cs] & 0x80:
        raise DERError("negative INTEGER where unsigned expected")
    if cl > 1 and buf[cs] == 0x00 and not (buf[cs + 1] & 0x80):
        raise DERError("non-minimal INTEGER (illegal leading zero)")
    return int.from_bytes(buf[cs:cs + cl], "big")


def _collect_dns_names(buf: bytes, cs: int, cl: int) -> list[str]:
    """GeneralNames ::= SEQUENCE OF GeneralName; collect dNSName ([2] IMPLICIT IA5String)."""
    outer = DER(buf, cs, cs + cl)
    _, gcs, gcl, _ = outer.read_tlv(TAG_SEQUENCE)
    outer.expect_exhausted("SAN extnValue wrapper")
    names: list[str] = []
    gn = DER(buf, gcs, gcs + gcl)
    while not gn.at_end():
        tag, ncs, ncl, _ = gn.read_tlv()
        if tag == TAG_DNSNAME:
            names.append(buf[ncs:ncs + ncl].decode("ascii"))
    return names


def parse_certificate(der: bytes) -> ParsedCert:
    """Strict positional parse of an X.509 Certificate (RFC 5280). Raises DERError on any
    deviation. Returns the fields the verifier needs."""
    top = DER(der)
    _, cs, cl, _ = top.read_tlv(TAG_SEQUENCE)                        # Certificate
    top.expect_exhausted("Certificate (trailing bytes after the cert)")
    cert = DER(der, cs, cs + cl)

    # --- tbsCertificate: capture the EXACT signed span (tag..end of value) ---
    _, tcs, tcl, tstart = cert.read_tlv(TAG_SEQUENCE)
    tbs_span = der[tstart:tcs + tcl]
    tbs = DER(der, tcs, tcs + tcl)

    # version [0] EXPLICIT — present (v3) for all leaves carrying a SAN
    tag, vcs, vcl, _ = tbs.read_tlv()
    if tag != TAG_CTX0:
        raise DERError("missing explicit version (need v3 for extensions/SAN)")
    vrdr = DER(der, vcs, vcs + vcl)
    _, ivcs, ivcl, _ = vrdr.read_tlv(TAG_INTEGER)
    version = _parse_uint(der, ivcs, ivcl)
    vrdr.expect_exhausted("version")
    if version != 2:                                                 # 2 == v3
        raise DERError(f"unsupported X.509 version {version + 1}")

    _, scs, scl, _ = tbs.read_tlv(TAG_INTEGER)                       # serialNumber
    serial = int.from_bytes(der[scs:scs + scl], "big")

    _, sacs, sacl, sastart = tbs.read_tlv(TAG_SEQUENCE)              # signature AlgorithmIdentifier
    inner_sigalg = der[sastart:sacs + sacl]

    _, ics, icl, istart = tbs.read_tlv(TAG_SEQUENCE)                 # issuer Name
    issuer_der = der[istart:ics + icl]

    _, vlcs, vlcl, _ = tbs.read_tlv(TAG_SEQUENCE)                    # validity
    vrd = DER(der, vlcs, vlcs + vlcl)
    nbt, nbcs, nbcl, _ = vrd.read_tlv()
    not_before = _parse_time(der[nbcs:nbcs + nbcl], nbt)
    nat, nacs, nacl, _ = vrd.read_tlv()
    not_after = _parse_time(der[nacs:nacs + nacl], nat)
    vrd.expect_exhausted("validity")

    _, sjcs, sjcl, sjstart = tbs.read_tlv(TAG_SEQUENCE)              # subject Name
    subject_der = der[sjstart:sjcs + sjcl]

    _, pcs, pcl, _ = tbs.read_tlv(TAG_SEQUENCE)                      # subjectPublicKeyInfo
    modulus, exponent, bits = _parse_spki(der, pcs, pcl)

    # optional issuerUniqueID [1] / subjectUniqueID [2], then extensions [3] EXPLICIT
    dns_names: list[str] = []
    san_count = 0
    ext_ctx = None
    while not tbs.at_end():
        tag, xcs, xcl, _ = tbs.read_tlv()
        if tag == 0xA1 or tag == 0xA2:
            continue                                                 # uniqueIDs: skip
        if tag == TAG_CTX3:
            ext_ctx = (xcs, xcl)
            break
        raise DERError(f"unexpected TBS trailing field tag {tag:#04x}")
    tbs.expect_exhausted("tbsCertificate")

    # extensions [3] EXPLICIT { SEQUENCE OF Extension } — present on leaves (carrying the SAN) and
    # on CA certs (no SAN). Parse structurally; "SAN must cover the host" is a VERIFY policy gate
    # (host_matches([]) rejects a missing/empty SAN), so the same parser handles leaf and anchor.
    if ext_ctx is not None:
        erdr = DER(der, ext_ctx[0], ext_ctx[0] + ext_ctx[1])
        _, escs, escl, _ = erdr.read_tlv(TAG_SEQUENCE)
        erdr.expect_exhausted("extensions [3] wrapper")
        exts = DER(der, escs, escs + escl)
        while not exts.at_end():
            _, xcs, xcl, _ = exts.read_tlv(TAG_SEQUENCE)             # Extension
            ex = DER(der, xcs, xcs + xcl)
            otag, ocs, ocl, ostart = ex.read_tlv(TAG_OID)
            oid = der[ostart:ocs + ocl]
            # optional critical BOOLEAN, then extnValue OCTET STRING. We do NOT reject unknown
            # critical extensions: under the WR1-pin + exact-host model a GTS-issued api.openai.com
            # cert carrying an unrecognized critical extension is not a reachable threat (the
            # attacker would already control api.openai.com), and the allowlist it would need costs
            # device code for no load-bearing gain. Documented scoping decision (see notes).
            tag, bcs, bcl, _ = ex.read_tlv()
            if tag == TAG_BOOLEAN:
                tag, bcs, bcl, _ = ex.read_tlv()
            if tag != TAG_OCTETSTRING:
                raise DERError("extnValue is not an OCTET STRING")
            ex.expect_exhausted("Extension")
            if oid == OID_SAN:
                san_count += 1                                       # policy gate: must end == 1
                dns_names.extend(_collect_dns_names(der, bcs, bcl))

    # --- back in Certificate: outer signatureAlgorithm + signatureValue ---
    _, oacs, oacl, oastart = cert.read_tlv(TAG_SEQUENCE)             # signatureAlgorithm
    outer_sigalg = der[oastart:oacs + oacl]
    _, sigcs, sigcl, _ = cert.read_tlv(TAG_BITSTRING)               # signatureValue
    cert.expect_exhausted("Certificate body")
    if sigcl < 1 or der[sigcs] != 0x00:
        raise DERError("signature BIT STRING must have 0 unused bits")
    signature = der[sigcs + 1:sigcs + sigcl]

    return ParsedCert(
        tbs_span=tbs_span, serial=serial, inner_sigalg=inner_sigalg, outer_sigalg=outer_sigalg,
        validity=Validity(not_before, not_after), spki_modulus=modulus, spki_exponent=exponent,
        spki_bits=bits, dns_names=dns_names, san_count=san_count, signature=signature,
        issuer_der=issuer_der, subject_der=subject_der,
    )


# ---------------------------------------------------------------------------
# RSA-PKCS#1-v1.5 SHA-256 verify — reconstruct-and-compare (mirrors p256_module.asm)
# ---------------------------------------------------------------------------
def rsa_pkcs1_v15_sha256_verify(anchor_n: int, anchor_e: int, sig: bytes, message: bytes) -> bool:
    k = (anchor_n.bit_length() + 7) // 8
    if k != 256:
        raise DERError("anchor is not RSA-2048 (device modexp is fixed 128x16-bit limbs)")
    if len(sig) != k:
        return False                                                 # signature length != modulus length
    s = int.from_bytes(sig, "big")
    if s >= anchor_n:
        return False                                                 # signature representative out of range
    m = pow(s, anchor_e, anchor_n)
    em = m.to_bytes(k, "big")                                        # I2OSP, fixed 256 bytes
    h = hashlib.sha256(message).digest()
    expected = b"\x00\x01" + b"\xff" * 202 + b"\x00" + SHA256_DIGESTINFO + h
    assert len(expected) == 256
    return em == expected                                            # full-block compare, no lax re-parse


# ---------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------
@dataclass
class VerifyResult:
    accepted: bool
    reason: str
    cert: ParsedCert | None = None
    adopted_modulus: int | None = None                               # the leaf key to pin on success


def host_matches(dns_names: list[str], host: str) -> bool:
    """EXACT dNSName match against the connected host — wildcards are deliberately NOT honored.
    The pinned host is fixed (api.openai.com) and the real leaf carries that exact name in its SAN,
    so wildcard expansion would only add attack surface (and error-prone label-counting code on the
    286) for zero benefit. A case-insensitive byte-exact compare is all the device needs."""
    host = host.lower().rstrip(".")
    return any(raw.lower().rstrip(".") == host for raw in dns_names)


def verify_leaf(leaf_der: bytes, anchor_n: int, anchor_e: int = 65537, *,
                host: str = "api.openai.com", now: datetime | None = None) -> VerifyResult:
    """The trust gate. Fail CLOSED on any error. Order: parse -> algs -> signature(vs anchor) ->
    SAN -> validity. The signature check against the pinned WR1 key IS the issuer authentication
    (only WR1's private key yields a block that reconstructs); SAN+validity are independent gates."""
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        cert = parse_certificate(leaf_der)
    except DERError as e:
        return VerifyResult(False, f"parse: {e}")

    # 1. algorithm must be sha256WithRSAEncryption, inner==outer (no substitution)
    if cert.outer_sigalg != cert.inner_sigalg:
        return VerifyResult(False, "signatureAlgorithm mismatch (inner != outer)", cert)
    # the AlgorithmIdentifier SEQUENCE is { OID, NULL }; check the OID prefix exactly
    if not cert.outer_sigalg.startswith(TAG_SEQUENCE.to_bytes(1, "big")):
        return VerifyResult(False, "sigAlg not a SEQUENCE", cert)
    if OID_SHA256_RSA not in cert.outer_sigalg or not _sigalg_is_sha256rsa(cert.outer_sigalg):
        return VerifyResult(False, "signatureAlgorithm is not sha256WithRSAEncryption", cert)

    # 2. signature verifies against the PINNED anchor (WR1)
    try:
        ok = rsa_pkcs1_v15_sha256_verify(anchor_n, anchor_e, cert.signature, cert.tbs_span)
    except DERError as e:
        return VerifyResult(False, f"rsa: {e}", cert)
    if not ok:
        return VerifyResult(False, "signature does not verify against the pinned WR1 key", cert)

    # 3. the leaf key we would ADOPT must itself be a usable RSA-2048/e=65537 key
    if cert.spki_bits != 2048:
        return VerifyResult(False, f"leaf key is {cert.spki_bits}-bit, not RSA-2048", cert)
    if cert.spki_exponent != 65537:
        return VerifyResult(False, f"leaf exponent {cert.spki_exponent} != 65537", cert)

    # 4. exactly one SAN extension (a duplicate SAN is a parser-differential red flag — which one
    #    wins?), and it must carry the exact host as a dNSName
    if cert.san_count != 1:
        return VerifyResult(False, f"expected exactly 1 SubjectAltName extension, found {cert.san_count}", cert)
    if not host_matches(cert.dns_names, host):
        return VerifyResult(False, f"SAN {cert.dns_names} does not cover {host}", cert)

    # 5. validity window
    if now < cert.validity.not_before:
        return VerifyResult(False, "not yet valid (notBefore in the future)", cert)
    if now > cert.validity.not_after:
        return VerifyResult(False, "expired (past notAfter)", cert)

    return VerifyResult(True, "ok", cert, adopted_modulus=cert.spki_modulus)


def _sigalg_is_sha256rsa(sigalg: bytes) -> bool:
    """sigalg is the full AlgorithmIdentifier SEQUENCE bytes: { OID sha256RSA, NULL }. Require the
    content to be EXACTLY the OID followed by an optional NULL — nothing else."""
    rdr = DER(sigalg)
    _, cs, cl, _ = rdr.read_tlv(TAG_SEQUENCE)
    rdr.expect_exhausted("sigAlg")
    inner = DER(sigalg, cs, cs + cl)
    otag, ocs, ocl, ostart = inner.read_tlv(TAG_OID)
    if sigalg[ostart:ocs + ocl] != OID_SHA256_RSA:
        return False
    if not inner.at_end():
        ptag, pcs, pcl, _ = inner.read_tlv()
        if ptag != TAG_NULL or pcl != 0:
            return False
    inner.expect_exhausted("sigAlg params")
    return True


# ---------------------------------------------------------------------------
# CLI / helpers
# ---------------------------------------------------------------------------
def anchor_modulus_from_cert(anchor_der: bytes) -> tuple[int, int]:
    """Parse an anchor (WR1) certificate and return (modulus, exponent) from its SPKI.
    Dogfoods the parser on the CA cert too."""
    cert = parse_certificate(anchor_der)
    return cert.spki_modulus, cert.spki_exponent


def _load_der(path: str) -> bytes:
    raw = open(path, "rb").read()
    if raw[:1] == b"\x30":
        return raw                                                   # already DER
    # PEM
    import base64
    body = []
    keep = False
    for line in raw.decode("ascii").splitlines():
        if "BEGIN CERTIFICATE" in line:
            keep = True
            continue
        if "END CERTIFICATE" in line:
            break
        if keep:
            body.append(line.strip())
    return base64.b64decode("".join(body))


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--leaf", required=True, help="leaf cert (DER or PEM)")
    ap.add_argument("--anchor", required=True, help="anchor/WR1 cert (DER or PEM) — its SPKI is the pin")
    ap.add_argument("--host", default="api.openai.com")
    ap.add_argument("--now", help="reference time ISO8601 (default: real now)")
    a = ap.parse_args()
    leaf = _load_der(a.leaf)
    anchor_n, anchor_e = anchor_modulus_from_cert(_load_der(a.anchor))
    now = datetime.fromisoformat(a.now).replace(tzinfo=timezone.utc) if a.now else None
    res = verify_leaf(leaf, anchor_n, anchor_e, host=a.host, now=now)
    print(f"anchor: RSA-{anchor_n.bit_length()} e={anchor_e}")
    if res.cert:
        c = res.cert
        print(f"leaf:   serial={c.serial:#x} SAN={c.dns_names}")
        print(f"        validity {c.validity.not_before.isoformat()} .. {c.validity.not_after.isoformat()}")
        print(f"        SPKI RSA-{c.spki_bits} e={c.spki_exponent}")
    print(f"RESULT: {'ACCEPT' if res.accepted else 'REJECT'} — {res.reason}")
    if res.accepted:
        print(f"        would adopt leaf modulus {res.adopted_modulus:#x}"[:90] + " ...")
    return 0 if res.accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
