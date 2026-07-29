#!/usr/bin/env python3
"""Strict host oracle for the post-Finished TLS 1.3 authentication spike.

This is deliberately not product code.  It creates a deterministic two-level
credential fixture:

* an immutable Seed test WE1 P-256 public-key anchor;
* a leaf certificate for ``api.openai.com`` signed by that anchor; and
* a TLS 1.3 server CertificateVerify signed by the leaf key.

The parser is intentionally narrow and hostile.  It accepts only canonical DER
and the exact profile Seed needs: ECDSA-with-SHA256, id-ecPublicKey,
prime256v1, an uncompressed on-curve point, CA=false, digitalSignature,
serverAuth, and one exact dNSName.  Time validity is evaluated only when a
trusted ``datetime`` is supplied by the caller.  The target benchmark does not
solve that trusted-time problem.

The paired 8088 benchmark executes strict ECDSA signature DER/r/s parsing,
mod-n inversion and multiplication, point validation, and the actual two-base
P-256 verification equations.  X.509/SPKI/scheme/context/time checks and the
bounded Brotli experiment in this file remain host-oracle gates and are
reported as such.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
P256_SOURCE = ROOT / "tools" / "check-p256.py"
HOSTNAME = b"api.openai.com"
WE1_COMMON_NAME = b"Seed Test WE1"
LEAF_COMMON_NAME = HOSTNAME
CV_CONTEXT = b"TLS 1.3, server CertificateVerify"
CV_SCHEME = b"\x04\x03"
BROTLI_ALGORITHM = 2
MAX_CERTIFICATE_BODY = 4096
TRUSTED_NOW = dt.datetime(2026, 7, 25, 12, 0, 0, tzinfo=dt.timezone.utc)


def _load_p256():
    spec = importlib.util.spec_from_file_location(
        "seed_auth_integrated_p256", P256_SOURCE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the independent P-256 oracle")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


P256 = _load_p256()
P = P256.P
N = P256.N
G = P256.G
B = P256.B
Point = tuple[int, int]


OID_COMMON_NAME = "2.5.4.3"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_PRIME256V1 = "1.2.840.10045.3.1.7"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_EXTENDED_KEY_USAGE = "2.5.29.37"
OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"


def _der_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("negative DER length")
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _sequence(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def _integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative integer is outside this fixture")
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _tlv(0x02, encoded)


def _oid_value(text: str) -> bytes:
    arcs = [int(item) for item in text.split(".")]
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40):
        raise ValueError(f"invalid OID: {text}")
    out = bytearray([40 * arcs[0] + arcs[1]])
    for value in arcs[2:]:
        if value < 0:
            raise ValueError(f"invalid OID: {text}")
        groups = [value & 0x7F]
        value >>= 7
        while value:
            groups.append(0x80 | (value & 0x7F))
            value >>= 7
        out.extend(reversed(groups))
    return bytes(out)


def _oid(text: str) -> bytes:
    return _tlv(0x06, _oid_value(text))


def _algorithm(oid: str, parameter: bytes = b"") -> bytes:
    return _sequence(_oid(oid), parameter)


def _name(common_name: bytes) -> bytes:
    return _sequence(
        _set(_sequence(_oid(OID_COMMON_NAME), _tlv(0x0C, common_name)))
    )


def _utc_time(value: bytes) -> bytes:
    return _tlv(0x17, value)


def _extension(oid: str, value_der: bytes, *, critical: bool = False) -> bytes:
    critical_der = _tlv(0x01, b"\xff") if critical else b""
    return _sequence(_oid(oid), critical_der, _tlv(0x04, value_der))


def encode_signature(r: int, s: int) -> bytes:
    return _sequence(_integer(r), _integer(s))


class DerError(ValueError):
    """Canonical-DER or exact-profile rejection."""


class DerReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read(self, expected_tag: int | None = None) -> tuple[int, bytes, bytes]:
        start = self.offset
        if self.offset >= len(self.data):
            raise DerError("missing DER tag")
        tag = self.data[self.offset]
        self.offset += 1
        if self.offset >= len(self.data):
            raise DerError("missing DER length")
        first = self.data[self.offset]
        self.offset += 1
        if first < 0x80:
            length = first
        else:
            count = first & 0x7F
            if count == 0:
                raise DerError("indefinite DER length")
            if count > 4 or self.offset + count > len(self.data):
                raise DerError("invalid DER long length")
            encoded = self.data[self.offset : self.offset + count]
            self.offset += count
            if encoded[0] == 0:
                raise DerError("non-canonical DER length")
            length = int.from_bytes(encoded, "big")
            if length < 128:
                raise DerError("non-minimal DER long length")
        end = self.offset + length
        if end > len(self.data):
            raise DerError("truncated DER object")
        content = self.data[self.offset : end]
        self.offset = end
        if expected_tag is not None and tag != expected_tag:
            raise DerError(
                f"unexpected DER tag 0x{tag:02x}, expected 0x{expected_tag:02x}"
            )
        return tag, content, self.data[start:end]

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise DerError("trailing DER data")


def _single(data: bytes, tag: int) -> bytes:
    reader = DerReader(data)
    _, content, _ = reader.read(tag)
    reader.finish()
    return content


def _parse_positive_integer(encoded: bytes, *, scalar: bool) -> int:
    if not encoded:
        raise DerError("empty DER integer")
    if encoded[0] & 0x80:
        raise DerError("negative DER integer")
    if len(encoded) > 1 and encoded[0] == 0 and not (encoded[1] & 0x80):
        raise DerError("redundant DER integer zero")
    if encoded[0] == 0:
        encoded = encoded[1:]
    if len(encoded) > 32:
        raise DerError("oversized P-256 integer")
    value = int.from_bytes(encoded, "big")
    if scalar and not 1 <= value < N:
        raise DerError("ECDSA scalar outside [1,n)")
    return value


def parse_signature(encoded: bytes) -> tuple[int, int]:
    body = _single(encoded, 0x30)
    reader = DerReader(body)
    _, r_bytes, _ = reader.read(0x02)
    _, s_bytes, _ = reader.read(0x02)
    reader.finish()
    return (
        _parse_positive_integer(r_bytes, scalar=True),
        _parse_positive_integer(s_bytes, scalar=True),
    )


def _deterministic_scalar(label: bytes) -> int:
    value = int.from_bytes(hashlib.sha256(b"Seed auth spike|" + label).digest(), "big")
    return value % (N - 1) + 1


def _ecdsa_sign(private: int, digest: bytes, label: bytes) -> bytes:
    if len(digest) != 32 or not 1 <= private < N:
        raise ValueError("bad deterministic ECDSA input")
    z = int.from_bytes(digest, "big")
    counter = 0
    while True:
        k = _deterministic_scalar(label + counter.to_bytes(2, "big") + digest)
        point = P256.scalar_mult(k, G)
        r = point[0] % N
        if r:
            s = (pow(k, -1, N) * (z + r * private)) % N
            if s:
                return encode_signature(r, s)
        counter += 1


def ecdsa_verify(public: Point, digest: bytes, signature: bytes) -> bool:
    if len(digest) != 32 or not valid_public_point(public):
        return False
    try:
        r, s = parse_signature(signature)
    except DerError:
        return False
    w = pow(s, -1, N)
    u1 = (int.from_bytes(digest, "big") * w) % N
    u2 = (r * w) % N
    result = P256.point_add(
        P256.scalar_mult(u1, G) if u1 else None,
        P256.scalar_mult(u2, public) if u2 else None,
    )
    return result is not None and result[0] % N == r


def valid_public_point(point: Point) -> bool:
    if len(point) != 2:
        return False
    x, y = point
    return 0 <= x < P and 0 <= y < P and P256.is_on_curve(point)


def _sec1(point: Point) -> bytes:
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def _parse_oid(reader: DerReader, expected: str) -> None:
    _, content, _ = reader.read(0x06)
    if content != _oid_value(expected):
        raise DerError(f"unexpected OID, wanted {expected}")


def _parse_algorithm(encoded: bytes, expected: str) -> None:
    reader = DerReader(_single(encoded, 0x30))
    _parse_oid(reader, expected)
    reader.finish()  # Parameters must be absent for this profile.


def _parse_name(encoded: bytes, expected_cn: bytes) -> None:
    outer = DerReader(_single(encoded, 0x30))
    _, rdn, _ = outer.read(0x31)
    outer.finish()
    attribute = DerReader(_single(rdn, 0x30))
    _parse_oid(attribute, OID_COMMON_NAME)
    _, value, _ = attribute.read(0x0C)
    attribute.finish()
    if value != expected_cn:
        raise DerError("unexpected commonName")


def _parse_time(encoded: bytes) -> dt.datetime:
    if len(encoded) != 13 or encoded[-1:] != b"Z" or not encoded[:-1].isdigit():
        raise DerError("UTCTime is not YYMMDDHHMMSSZ")
    year = int(encoded[:2])
    year += 2000 if year < 50 else 1900
    try:
        return dt.datetime(
            year,
            int(encoded[2:4]),
            int(encoded[4:6]),
            int(encoded[6:8]),
            int(encoded[8:10]),
            int(encoded[10:12]),
            tzinfo=dt.timezone.utc,
        )
    except ValueError as error:
        raise DerError("invalid UTCTime") from error


def _parse_spki(encoded: bytes) -> Point:
    outer = DerReader(_single(encoded, 0x30))
    _, algorithm_body, algorithm_full = outer.read(0x30)
    algorithm = DerReader(algorithm_body)
    _parse_oid(algorithm, OID_EC_PUBLIC_KEY)
    _parse_oid(algorithm, OID_PRIME256V1)
    algorithm.finish()
    # Re-encoding equality makes the absent-parameter/exact-order requirement
    # explicit instead of treating the nested sequence as an unordered bag.
    if algorithm_full != _algorithm(OID_EC_PUBLIC_KEY, _oid(OID_PRIME256V1)):
        raise DerError("non-exact P-256 AlgorithmIdentifier")
    _, bit_string, _ = outer.read(0x03)
    outer.finish()
    if len(bit_string) != 66 or bit_string[0] != 0 or bit_string[1] != 4:
        raise DerError("SPKI is not exact uncompressed P-256")
    point = (
        int.from_bytes(bit_string[2:34], "big"),
        int.from_bytes(bit_string[34:66], "big"),
    )
    if not valid_public_point(point):
        raise DerError("SPKI point is infinity, out of range, or off curve")
    return point


def _parse_extensions(encoded: bytes, hostname: bytes) -> None:
    extensions = DerReader(_single(_single(encoded, 0xA3), 0x30))
    seen: set[str] = set()
    while extensions.offset < len(extensions.data):
        _, entry_body, _ = extensions.read(0x30)
        entry = DerReader(entry_body)
        _, oid_bytes, _ = entry.read(0x06)
        oid_map = {
            _oid_value(OID_BASIC_CONSTRAINTS): OID_BASIC_CONSTRAINTS,
            _oid_value(OID_KEY_USAGE): OID_KEY_USAGE,
            _oid_value(OID_EXTENDED_KEY_USAGE): OID_EXTENDED_KEY_USAGE,
            _oid_value(OID_SUBJECT_ALT_NAME): OID_SUBJECT_ALT_NAME,
        }
        if oid_bytes not in oid_map:
            raise DerError("unknown critical-profile extension")
        oid = oid_map[oid_bytes]
        if oid in seen:
            raise DerError("duplicate extension")
        seen.add(oid)
        critical = False
        if entry.offset < len(entry.data) and entry.data[entry.offset] == 0x01:
            _, boolean, _ = entry.read(0x01)
            if boolean != b"\xff":
                raise DerError("non-canonical critical boolean")
            critical = True
        _, value, _ = entry.read(0x04)
        entry.finish()
        if oid == OID_BASIC_CONSTRAINTS:
            if not critical or value != _sequence():
                raise DerError("leaf must have critical CA=false constraints")
        elif oid == OID_KEY_USAGE:
            if not critical or value != _tlv(0x03, b"\x07\x80"):
                raise DerError("leaf must permit only digitalSignature")
        elif oid == OID_EXTENDED_KEY_USAGE:
            if critical or value != _sequence(_oid(OID_SERVER_AUTH)):
                raise DerError("leaf EKU must be exact serverAuth")
        elif oid == OID_SUBJECT_ALT_NAME:
            if critical or value != _sequence(_tlv(0x82, hostname)):
                raise DerError("leaf SAN must be the exact DNS hostname")
    expected = {
        OID_BASIC_CONSTRAINTS,
        OID_KEY_USAGE,
        OID_EXTENDED_KEY_USAGE,
        OID_SUBJECT_ALT_NAME,
    }
    if seen != expected:
        raise DerError("missing required leaf extension")


@dataclass(frozen=True)
class ParsedLeaf:
    point: Point
    not_before: dt.datetime
    not_after: dt.datetime
    certificate_signature: bytes
    tbs_der: bytes


def parse_and_verify_leaf(
    certificate: bytes,
    *,
    anchor: Point,
    hostname: bytes,
    trusted_now: dt.datetime,
) -> ParsedLeaf:
    if trusted_now.tzinfo is None:
        raise ValueError("trusted_now must be timezone-aware")
    certificate_body = _single(certificate, 0x30)
    certificate_reader = DerReader(certificate_body)
    _, tbs_body, tbs_der = certificate_reader.read(0x30)
    _, _, signature_algorithm = certificate_reader.read(0x30)
    _parse_algorithm(signature_algorithm, OID_ECDSA_SHA256)
    _, signature_bits, _ = certificate_reader.read(0x03)
    certificate_reader.finish()
    if not signature_bits or signature_bits[0] != 0:
        raise DerError("certificate signature BIT STRING has unused bits")
    certificate_signature = signature_bits[1:]
    parse_signature(certificate_signature)

    tbs = DerReader(tbs_body)
    _, version_explicit, _ = tbs.read(0xA0)
    version = DerReader(version_explicit)
    _, version_integer, _ = version.read(0x02)
    version.finish()
    if _parse_positive_integer(version_integer, scalar=False) != 2:
        raise DerError("certificate is not X.509 v3")
    _, serial, _ = tbs.read(0x02)
    if _parse_positive_integer(serial, scalar=False) == 0:
        raise DerError("zero certificate serial")
    _, _, tbs_signature_algorithm = tbs.read(0x30)
    _parse_algorithm(tbs_signature_algorithm, OID_ECDSA_SHA256)
    _, _, issuer = tbs.read(0x30)
    _parse_name(issuer, WE1_COMMON_NAME)
    _, validity_body, _ = tbs.read(0x30)
    validity = DerReader(validity_body)
    _, not_before_raw, _ = validity.read(0x17)
    _, not_after_raw, _ = validity.read(0x17)
    validity.finish()
    not_before = _parse_time(not_before_raw)
    not_after = _parse_time(not_after_raw)
    if not not_before <= trusted_now <= not_after:
        raise DerError("leaf is outside trusted validity time")
    _, _, subject = tbs.read(0x30)
    _parse_name(subject, LEAF_COMMON_NAME)
    _, _, spki = tbs.read(0x30)
    point = _parse_spki(spki)
    _, _, extensions = tbs.read(0xA3)
    _parse_extensions(extensions, hostname)
    tbs.finish()

    digest = hashlib.sha256(tbs_der).digest()
    if not ecdsa_verify(anchor, digest, certificate_signature):
        raise DerError("leaf signature does not verify under pinned WE1")
    return ParsedLeaf(
        point=point,
        not_before=not_before,
        not_after=not_after,
        certificate_signature=certificate_signature,
        tbs_der=tbs_der,
    )


def _build_leaf(
    *,
    anchor_private: int,
    leaf_point_encoding: bytes,
    hostname: bytes = HOSTNAME,
    curve_oid: str = OID_PRIME256V1,
) -> tuple[bytes, bytes, bytes]:
    signature_algorithm = _algorithm(OID_ECDSA_SHA256)
    spki = _sequence(
        _algorithm(OID_EC_PUBLIC_KEY, _oid(curve_oid)),
        _tlv(0x03, b"\x00" + leaf_point_encoding),
    )
    extensions = _tlv(
        0xA3,
        _sequence(
            _extension(
                OID_BASIC_CONSTRAINTS, _sequence(), critical=True
            ),
            _extension(
                OID_KEY_USAGE,
                _tlv(0x03, b"\x07\x80"),
                critical=True,
            ),
            _extension(
                OID_EXTENDED_KEY_USAGE,
                _sequence(_oid(OID_SERVER_AUTH)),
            ),
            _extension(
                OID_SUBJECT_ALT_NAME,
                _sequence(_tlv(0x82, hostname)),
            ),
        ),
    )
    tbs = _sequence(
        _tlv(0xA0, _integer(2)),
        _integer(0x5EED13),
        signature_algorithm,
        _name(WE1_COMMON_NAME),
        _sequence(
            _utc_time(b"260101000000Z"),
            _utc_time(b"271231235959Z"),
        ),
        _name(LEAF_COMMON_NAME),
        spki,
        extensions,
    )
    signature = _ecdsa_sign(
        anchor_private,
        hashlib.sha256(tbs).digest(),
        b"leaf-certificate",
    )
    return (
        _sequence(
            tbs,
            signature_algorithm,
            _tlv(0x03, b"\x00" + signature),
        ),
        tbs,
        signature,
    )


def build_certificate_verify(
    *,
    leaf_private: int,
    transcript_digest: bytes,
    context: bytes = CV_CONTEXT,
    scheme: bytes = CV_SCHEME,
) -> tuple[bytes, bytes]:
    if len(transcript_digest) != 32 or len(scheme) != 2:
        raise ValueError("bad CertificateVerify fixture input")
    signed = b"\x20" * 64 + context + b"\x00" + transcript_digest
    signature = _ecdsa_sign(
        leaf_private,
        hashlib.sha256(signed).digest(),
        b"certificate-verify",
    )
    return scheme + len(signature).to_bytes(2, "big") + signature, signature


def verify_certificate_verify(
    body: bytes,
    *,
    leaf_point: Point,
    transcript_digest: bytes,
    expected_context: bytes = CV_CONTEXT,
) -> bytes:
    if len(body) < 4 or body[:2] != CV_SCHEME:
        raise DerError("wrong TLS 1.3 CertificateVerify scheme")
    signature_length = int.from_bytes(body[2:4], "big")
    if signature_length != len(body) - 4:
        raise DerError("CertificateVerify signature length mismatch")
    signature = body[4:]
    parse_signature(signature)
    signed = (
        b"\x20" * 64
        + expected_context
        + b"\x00"
        + transcript_digest
    )
    digest = hashlib.sha256(signed).digest()
    if not ecdsa_verify(leaf_point, digest, signature):
        raise DerError("CertificateVerify signature mismatch")
    return digest


def certificate_body(certificate: bytes) -> bytes:
    entry = len(certificate).to_bytes(3, "big") + certificate + b"\x00\x00"
    return b"\x00" + len(entry).to_bytes(3, "big") + entry


def _brotli_binary() -> str:
    binary = shutil.which("brotli")
    if binary is None:
        raise RuntimeError("brotli CLI is unavailable")
    return binary


def brotli_compress(value: bytes) -> bytes:
    result = subprocess.run(
        [_brotli_binary(), "-q", "5", "-c"],
        input=value,
        capture_output=True,
        check=True,
    )
    return result.stdout


def bounded_brotli_decompress(
    compressed: bytes,
    *,
    algorithm: int,
    declared_output_length: int,
    output_cap: int = MAX_CERTIFICATE_BODY,
) -> bytes:
    """Host-only bounded-output decoder for an exact TLS compressed body.

    The parent validates the TLS field length before this function is called.
    This wrapper additionally refuses an oversized declaration and never
    retains more than ``output_cap + 1`` decoded bytes in the parent process.
    It does not claim that the stock Brotli child has a 16 KiB heap.
    """

    if algorithm != BROTLI_ALGORITHM:
        raise ValueError("unsupported certificate compression algorithm")
    if not 0 <= declared_output_length <= output_cap:
        raise ValueError("declared Brotli output exceeds cap")
    process = subprocess.Popen(
        [_brotli_binary(), "-d", "-c"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(compressed)
    process.stdin.close()
    output = process.stdout.read(output_cap + 1)
    if len(output) > output_cap:
        process.kill()
        process.wait()
        raise ValueError("Brotli output exceeds cap")
    stderr = process.stderr.read() if process.stderr is not None else b""
    status = process.wait()
    if status:
        raise ValueError(
            "invalid Brotli stream: "
            + stderr.decode("utf-8", errors="replace").strip()
        )
    if len(output) != declared_output_length:
        raise ValueError("Brotli output length differs from declaration")
    return output


@dataclass(frozen=True)
class Fixture:
    anchor_private: int
    leaf_private: int
    anchor_point: Point
    leaf_point: Point
    certificate: bytes
    tbs_der: bytes
    certificate_signature: bytes
    certificate_digest: bytes
    transcript_digest: bytes
    certificate_verify_body: bytes
    certificate_verify_signature: bytes
    certificate_verify_digest: bytes
    certificate_body: bytes
    compressed_certificate_body: bytes


def make_fixture() -> Fixture:
    anchor_private = _deterministic_scalar(b"WE1 private")
    leaf_private = _deterministic_scalar(b"leaf private")
    anchor_point = P256.scalar_mult(anchor_private, G)
    leaf_point = P256.scalar_mult(leaf_private, G)
    certificate, tbs_der, certificate_signature = _build_leaf(
        anchor_private=anchor_private,
        leaf_point_encoding=_sec1(leaf_point),
    )
    transcript_digest = hashlib.sha256(
        b"Seed deterministic TLS 1.3 transcript through Certificate"
    ).digest()
    certificate_verify_body, certificate_verify_signature = (
        build_certificate_verify(
            leaf_private=leaf_private,
            transcript_digest=transcript_digest,
        )
    )
    certificate_verify_digest = hashlib.sha256(
        b"\x20" * 64 + CV_CONTEXT + b"\x00" + transcript_digest
    ).digest()
    body = certificate_body(certificate)
    return Fixture(
        anchor_private=anchor_private,
        leaf_private=leaf_private,
        anchor_point=anchor_point,
        leaf_point=leaf_point,
        certificate=certificate,
        tbs_der=tbs_der,
        certificate_signature=certificate_signature,
        certificate_digest=hashlib.sha256(tbs_der).digest(),
        transcript_digest=transcript_digest,
        certificate_verify_body=certificate_verify_body,
        certificate_verify_signature=certificate_verify_signature,
        certificate_verify_digest=certificate_verify_digest,
        certificate_body=body,
        compressed_certificate_body=brotli_compress(body),
    )


def _expect_reject(name: str, operation) -> str:
    try:
        operation()
    except (DerError, ValueError):
        return name
    raise AssertionError(f"tamper was accepted: {name}")


def hostile_matrix(fixture: Fixture) -> list[str]:
    accepted = parse_and_verify_leaf(
        fixture.certificate,
        anchor=fixture.anchor_point,
        hostname=HOSTNAME,
        trusted_now=TRUSTED_NOW,
    )
    verify_certificate_verify(
        fixture.certificate_verify_body,
        leaf_point=accepted.point,
        transcript_digest=fixture.transcript_digest,
    )

    matrix: list[str] = []
    matrix.append(
        _expect_reject(
            "signature-nonminimal-length",
            lambda: parse_signature(b"\x30\x81\x06\x02\x01\x01\x02\x01\x01"),
        )
    )
    matrix.append(
        _expect_reject(
            "signature-r-zero",
            lambda: parse_signature(_sequence(_integer(0), _integer(1))),
        )
    )
    matrix.append(
        _expect_reject(
            "signature-s-at-n",
            lambda: parse_signature(_sequence(_integer(1), _integer(N))),
        )
    )
    matrix.append(
        _expect_reject(
            "certificate-signature-flip",
            lambda: parse_and_verify_leaf(
                fixture.certificate[:-1]
                + bytes([fixture.certificate[-1] ^ 1]),
                anchor=fixture.anchor_point,
                hostname=HOSTNAME,
                trusted_now=TRUSTED_NOW,
            ),
        )
    )
    matrix.append(
        _expect_reject(
            "hostname-mismatch",
            lambda: parse_and_verify_leaf(
                fixture.certificate,
                anchor=fixture.anchor_point,
                hostname=b"other.example",
                trusted_now=TRUSTED_NOW,
            ),
        )
    )
    matrix.append(
        _expect_reject(
            "untrusted-expired-time",
            lambda: parse_and_verify_leaf(
                fixture.certificate,
                anchor=fixture.anchor_point,
                hostname=HOSTNAME,
                trusted_now=dt.datetime(
                    2028, 1, 1, tzinfo=dt.timezone.utc
                ),
            ),
        )
    )
    offcurve_certificate, _, _ = _build_leaf(
        anchor_private=fixture.anchor_private,
        leaf_point_encoding=b"\x04" + (1).to_bytes(32, "big") * 2,
    )
    matrix.append(
        _expect_reject(
            "spki-off-curve",
            lambda: parse_and_verify_leaf(
                offcurve_certificate,
                anchor=fixture.anchor_point,
                hostname=HOSTNAME,
                trusted_now=TRUSTED_NOW,
            ),
        )
    )
    infinity_certificate, _, _ = _build_leaf(
        anchor_private=fixture.anchor_private,
        leaf_point_encoding=b"\x00",
    )
    matrix.append(
        _expect_reject(
            "spki-infinity-encoding",
            lambda: parse_and_verify_leaf(
                infinity_certificate,
                anchor=fixture.anchor_point,
                hostname=HOSTNAME,
                trusted_now=TRUSTED_NOW,
            ),
        )
    )
    wrong_curve_certificate, _, _ = _build_leaf(
        anchor_private=fixture.anchor_private,
        leaf_point_encoding=_sec1(fixture.leaf_point),
        curve_oid="1.3.132.0.34",
    )
    matrix.append(
        _expect_reject(
            "spki-wrong-curve",
            lambda: parse_and_verify_leaf(
                wrong_curve_certificate,
                anchor=fixture.anchor_point,
                hostname=HOSTNAME,
                trusted_now=TRUSTED_NOW,
            ),
        )
    )
    wrong_scheme = (
        b"\x08\x04" + fixture.certificate_verify_body[2:]
    )
    matrix.append(
        _expect_reject(
            "certificate-verify-wrong-scheme",
            lambda: verify_certificate_verify(
                wrong_scheme,
                leaf_point=fixture.leaf_point,
                transcript_digest=fixture.transcript_digest,
            ),
        )
    )
    wrong_context_body, _ = build_certificate_verify(
        leaf_private=fixture.leaf_private,
        transcript_digest=fixture.transcript_digest,
        context=b"TLS 1.3, client CertificateVerify",
    )
    matrix.append(
        _expect_reject(
            "certificate-verify-wrong-context",
            lambda: verify_certificate_verify(
                wrong_context_body,
                leaf_point=fixture.leaf_point,
                transcript_digest=fixture.transcript_digest,
            ),
        )
    )
    matrix.append(
        _expect_reject(
            "certificate-verify-wrong-transcript",
            lambda: verify_certificate_verify(
                fixture.certificate_verify_body,
                leaf_point=fixture.leaf_point,
                transcript_digest=bytes(32),
            ),
        )
    )
    cv_flip = (
        fixture.certificate_verify_body[:-1]
        + bytes([fixture.certificate_verify_body[-1] ^ 1])
    )
    matrix.append(
        _expect_reject(
            "certificate-verify-signature-flip",
            lambda: verify_certificate_verify(
                cv_flip,
                leaf_point=fixture.leaf_point,
                transcript_digest=fixture.transcript_digest,
            ),
        )
    )
    matrix.append(
        _expect_reject(
            "brotli-wrong-algorithm",
            lambda: bounded_brotli_decompress(
                fixture.compressed_certificate_body,
                algorithm=1,
                declared_output_length=len(fixture.certificate_body),
            ),
        )
    )
    matrix.append(
        _expect_reject(
            "brotli-declared-bomb",
            lambda: bounded_brotli_decompress(
                fixture.compressed_certificate_body,
                algorithm=BROTLI_ALGORITHM,
                declared_output_length=MAX_CERTIFICATE_BODY + 1,
            ),
        )
    )
    matrix.append(
        _expect_reject(
            "brotli-truncated",
            lambda: bounded_brotli_decompress(
                fixture.compressed_certificate_body[:-1],
                algorithm=BROTLI_ALGORITHM,
                declared_output_length=len(fixture.certificate_body),
            ),
        )
    )
    return matrix


def ecdsa_intermediates(digest: bytes, signature: bytes) -> dict[str, int]:
    r, s = parse_signature(signature)
    w = pow(s, -1, N)
    return {
        "r": r,
        "s": s,
        "z": int.from_bytes(digest, "big"),
        "w": w,
        "u1": (int.from_bytes(digest, "big") * w) % N,
        "u2": (r * w) % N,
    }


def _words(value: int) -> str:
    return ",".join(str(item) for item in P256.to_words_le(value))


def _bytes(encoded: bytes, width: int = 16) -> list[str]:
    lines: list[str] = []
    for offset in range(0, len(encoded), width):
        lines.append("    db " + ",".join(str(item) for item in encoded[offset : offset + width]))
    return lines


def vectors_include(fixture: Fixture) -> str:
    lines = [
        "; generated by auth_integrated_oracle.py -- deterministic spike fixture",
        f"auth_order_n: dw {_words(N)}",
        f"auth_curve_b: dw {_words(B)}",
        f"auth_generator_x: dw {_words(G[0])}",
        f"auth_generator_y: dw {_words(G[1])}",
        f"auth_anchor_x: dw {_words(fixture.anchor_point[0])}",
        f"auth_anchor_y: dw {_words(fixture.anchor_point[1])}",
        f"auth_leaf_x: dw {_words(fixture.leaf_point[0])}",
        f"auth_leaf_y: dw {_words(fixture.leaf_point[1])}",
        "auth_certificate_digest_be:",
        *_bytes(fixture.certificate_digest),
        "auth_certificate_signature:",
        *_bytes(fixture.certificate_signature),
        (
            "auth_certificate_signature_len equ "
            "$ - auth_certificate_signature"
        ),
        "auth_cv_digest_be:",
        *_bytes(fixture.certificate_verify_digest),
        "auth_cv_signature:",
        *_bytes(fixture.certificate_verify_signature),
        "auth_cv_signature_len equ $ - auth_cv_signature",
    ]
    return "\n".join(lines) + "\n"


def report(fixture: Fixture) -> dict[str, object]:
    parsed = parse_and_verify_leaf(
        fixture.certificate,
        anchor=fixture.anchor_point,
        hostname=HOSTNAME,
        trusted_now=TRUSTED_NOW,
    )
    cv_digest = verify_certificate_verify(
        fixture.certificate_verify_body,
        leaf_point=parsed.point,
        transcript_digest=fixture.transcript_digest,
    )
    decoded = bounded_brotli_decompress(
        fixture.compressed_certificate_body,
        algorithm=BROTLI_ALGORITHM,
        declared_output_length=len(fixture.certificate_body),
    )
    if decoded != fixture.certificate_body:
        raise AssertionError("Brotli round trip mismatch")
    matrix = hostile_matrix(fixture)
    return {
        "host_oracle": {
            "canonical_der_and_scalar_ranges": True,
            "leaf_we1_signature": True,
            "spki_exact_p256_uncompressed_on_curve": True,
            "leaf_profile": {
                "hostname": HOSTNAME.decode(),
                "ca": False,
                "key_usage": "digitalSignature",
                "extended_key_usage": "serverAuth",
            },
            "certificate_verify_scheme": CV_SCHEME.hex(),
            "certificate_verify_context": CV_CONTEXT.decode(),
            "certificate_verify_signature": True,
            "trusted_time_fixture_only": TRUSTED_NOW.isoformat(),
            "hostile_rejections": matrix,
        },
        "fixture": {
            "certificate_der_bytes": len(fixture.certificate),
            "certificate_body_bytes": len(fixture.certificate_body),
            "brotli_bytes": len(fixture.compressed_certificate_body),
            "certificate_signature_der_bytes": len(
                fixture.certificate_signature
            ),
            "certificate_verify_signature_der_bytes": len(
                fixture.certificate_verify_signature
            ),
            "certificate_digest": fixture.certificate_digest.hex(),
            "certificate_verify_digest": cv_digest.hex(),
            "anchor_point": [hex(item) for item in fixture.anchor_point],
            "leaf_point": [hex(item) for item in fixture.leaf_point],
            "certificate_intermediates": {
                key: hex(value)
                for key, value in ecdsa_intermediates(
                    fixture.certificate_digest,
                    fixture.certificate_signature,
                ).items()
            },
            "certificate_verify_intermediates": {
                key: hex(value)
                for key, value in ecdsa_intermediates(
                    fixture.certificate_verify_digest,
                    fixture.certificate_verify_signature,
                ).items()
            },
        },
        "brotli_scope": {
            "host_cli_round_trip": True,
            "parent_output_cap_bytes": MAX_CERTIFICATE_BODY,
            "target_decoder": False,
            "stock_decoder_16k_heap_claim": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--print-vectors",
        action="store_true",
        help="print the deterministic NASM include after the oracle passes",
    )
    args = parser.parse_args()
    fixture = make_fixture()
    result = report(fixture)
    if args.print_vectors:
        print(vectors_include(fixture), end="")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
