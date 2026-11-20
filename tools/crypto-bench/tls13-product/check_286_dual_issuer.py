#!/usr/bin/env python3
"""Execute both issuer routes and their captured-TBS boundary on target code.

The protected-flight fixture and the real captured CertificateVerify fixture
have distinct transcripts. Their shared TBS evidence is byte-bound here; full
provider handoff acceptance additionally requires the live VM gate.
"""
from __future__ import annotations

import binascii
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A = load("check_286_auth")
F = load("check_286_flight")
TBS_OFF = F.TICKET_TRUNCATED_HASH
NOW = (2026, 11, 8, 12, 0, 0)
ANCHORS = {
    "ye2": "b3fb5d00e994cddf2cc9a4eea9f806bc5727e83cc0e4299bf956f2d524fe5376",
    "we1": "908769e8d34477cc2cba0632c88605b22d7294c0840f78596d247c645b1afc0e",
}


def point_bytes(key) -> bytes:
    q = key.public_numbers()
    width = key.key_size // 8
    return q.x.to_bytes(width, "little") + q.y.to_bytes(width, "little")


def evidence(leaf: bytes) -> bytes:
    tbs = x509.load_der_x509_certificate(leaf).tbs_certificate_bytes
    offset = leaf.index(tbs)
    return (hashlib.sha256(tbs).digest() +
            struct.pack("<HHH", 0x800 + offset, len(tbs),
                        binascii.crc_hqx(tbs, 0xffff)))


def assert_no_authority(target, label: str) -> None:
    assert target.aborted and target.chain_kind is None, label
    assert target.authority_writes == [
        (A.AUTH_STATUS_OFF, 2, 0), (A.TICKET_STATUS_OFF, 2, 0)
    ], (label, target.authority_writes)
    assert bytes(target.machine.mem_read(A.CRYPTO_BASE, A.PACK_CACHE_BYTES)) == target.pack_cache


def main() -> None:
    fixtures = {}
    for name, prefix in (("ye2", "provider_auth_live"), ("we1", "provider_we1_live")):
        chain = x509.load_pem_x509_certificates((HERE / "fixtures" / (prefix + "_chain.pem")).read_bytes())
        leaf, issuer = chain[:2]
        spki = issuer.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        assert hashlib.sha256(spki).hexdigest() == ANCHORS[name]
        issuer.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                                   ec.ECDSA(leaf.signature_hash_algorithm))
        fixtures[name] = (prefix, chain)
    points = (point_bytes(ec.derive_private_key(1, ec.SECP384R1()).public_key()) +
              point_bytes(fixtures["ye2"][1][1].public_key()) +
              point_bytes(fixtures["we1"][1][1].public_key()) +
              point_bytes(ec.derive_private_key(1, ec.SECP256R1()).public_key()))
    assert len(points) == 320
    assert (BUILD / "crypto-bench/tls13-286-auth-points.bin").read_bytes() == points
    pack = (BUILD / "crypto-bench/tls13-286-modules.bin").read_bytes()
    assert pack[140:144] == b"IA02" and pack[144:464] == points
    assert pack[464:512] == bytes(48) and len(pack) == A.PACK_CACHE_BYTES

    accepted = {}
    captures = {}
    for name, (prefix, chain) in fixtures.items():
        fixture = F.build_fixture(fixture_prefix=prefix)
        flight = F.FlightMachine(fixture, resumed=False)
        flight.run()
        assert flight.chain_kind == 6 and not flight.aborted, (name, flight.events)
        F.assert_capture_memory_boundary(flight, name)
        captured = bytes(flight.machine.mem_read(F.CRYPTO_BASE + TBS_OFF, 38))
        leaf = chain[0].public_bytes(Encoding.DER)
        assert captured == evidence(leaf), name
        captures[name] = captured
        vector = json.loads((HERE / "fixtures" / (prefix + "_vector.json")).read_text())
        cv = vector["certificate_verify"]
        digest = bytes.fromhex(cv["signed_input_sha256"])
        signature = bytes.fromhex(cv["signature_der"])
        cert = A.certificate_message(leaf, [c.public_bytes(Encoding.DER) for c in chain[1:]])
        target = A.AuthMachine(cert, digest, signature, captured_tbs=captured, rtc=NOW)
        target.run()
        assert target.chain_kind == 4 and not target.aborted, (name, target.decode_kinds)
        expected = [2, 4, 4, 5] if name == "ye2" else [2, 4, 4, 5, 4, 5]
        assert target.decode_kinds == expected, (name, target.decode_kinds)
        assert target.authority_writes == [
            (A.AUTH_STATUS_OFF, 2, 0), (A.TICKET_STATUS_OFF, 2, 0),
            (A.AUTH_STATUS_OFF, 1, 0x5a), (A.AUTH_STATUS_OFF + 1, 1, 0xa5),
            (A.TICKET_STATUS_OFF, 1, 0xc3), (A.TICKET_STATUS_OFF + 1, 1, 0x3c)
        ]
        assert bytes(target.machine.mem_read(A.CRYPTO_BASE + TBS_OFF, 64)) == bytes(64)
        assert bytes(target.machine.mem_read(A.CRYPTO_BASE, A.PACK_CACHE_BYTES)) == pack
        for offset, size in ((A.MLKEM_DK_OFF, A.MLKEM_DK_BYTES),
                             (A.HYBRID_SECRET_OFF, A.HYBRID_SECRET_BYTES)):
            assert bytes(target.machine.mem_read(A.CRYPTO_BASE + offset, size)) == bytes(size)
        expected_leaf = A.WIDTH7.serialize_table(A.WIDTH7.build_comb(A.ORACLE, A.point(leaf)))
        assert bytes(target.machine.mem_read(A.CRYPTO_BASE + A.LEAF_TABLE_OFF, A.TABLE_BYTES)) == expected_leaf
        accepted[name] = dict(certificate_bytes=len(cert), module_sequence=target.decode_kinds,
                              target_tbs_sha256=captured[:32].hex(),
                              leaf_sha256=hashlib.sha256(leaf).hexdigest())
        print(name, "target capture, full FO, issuer, CV and status-last PASS", flush=True)

    prefix, chain = fixtures["we1"]
    leaf = chain[0].public_bytes(Encoding.DER)
    rest = [c.public_bytes(Encoding.DER) for c in chain[1:]]
    cert = A.certificate_message(leaf, rest)
    cv = json.loads((HERE / "fixtures" / (prefix + "_vector.json")).read_text())["certificate_verify"]
    digest, signature = (bytes.fromhex(cv[x]) for x in ("signed_input_sha256", "signature_der"))
    captured = captures["we1"]
    rejections = []

    def early(label, changed_leaf=leaf, changed_capture=captured, **kwargs):
        A.expect_post_fo_reject(label, A.certificate_message(changed_leaf, rest), digest,
                               signature, captured_tbs=changed_capture, rtc=NOW, **kwargs)
        rejections.append(label)

    for index, label in ((32, "TBS offset"), (34, "TBS length"), (36, "TBS integrity guard")):
        changed = bytearray(captured)
        changed[index] ^= 1
        early(label, changed_capture=bytes(changed))
    # Preserve the captured digest while corrupting signed fields in RAM.
    # Even parseable changes must stop before any issuer module executes.
    tbs = chain[0].tbs_certificate_bytes
    start = leaf.index(tbs)
    for index in (start + 12, start + 24, start + len(tbs) - 1):
        changed = bytearray(leaf)
        changed[index] ^= 1
        early("retained TBS corruption " + str(index), changed_leaf=bytes(changed))
    oid = bytes.fromhex("06082a8648ce3d040302")
    assert leaf.count(oid) == 2
    early("inner/outer issuer mismatch", leaf.replace(oid, oid[:-1] + b"\x03", 1))
    early("unsupported issuer algorithm", leaf.replace(oid, oid[:-1] + b"\x04"))
    early("WE1 certificate under YE2 profile", leaf.replace(oid, oid[:-1] + b"\x03"))
    for index, label in ((0, "corrupted digest"),):
        changed = bytearray(captured)
        changed[index] ^= 1
        target = A.AuthMachine(cert, digest, signature, captured_tbs=bytes(changed), rtc=NOW)
        target.run()
        assert_no_authority(target, label)
        rejections.append(label)
    for label, changed_cert, changed_sig in (
        ("wrong WE1 signature", A.certificate_message(leaf[:-1] + bytes([leaf[-1] ^ 1]), rest), signature),
        ("wrong CertificateVerify", cert, signature[:-1] + bytes([signature[-1] ^ 1])),
    ):
        target = A.AuthMachine(changed_cert, digest, changed_sig, captured_tbs=captured, rtc=NOW)
        target.run()
        assert_no_authority(target, label)
        rejections.append(label)
    # A fresh digest/CRC for an altered certificate still needs a valid issuer
    # signature. The integrity guard never substitutes for authentication.
    changed = bytearray(leaf)
    changed[start + 24] ^= 1
    changed = bytes(changed)
    target = A.AuthMachine(A.certificate_message(changed, rest), digest, signature,
                           captured_tbs=evidence(changed), rtc=NOW)
    target.run()
    assert_no_authority(target, "rehashed unsigned certificate")
    rejections.append("rehashed unsigned certificate")
    for offset, label in ((140, "missing point-object format"), (336, "corrupted WE1 point")):
        target = A.AuthMachine(cert, digest, signature, captured_tbs=captured, rtc=NOW)
        changed = bytearray(target.pack_cache)
        changed[offset] ^= 1
        target.pack_cache = bytes(changed)
        target.machine.mem_write(A.CRYPTO_BASE, target.pack_cache)
        target.run()
        assert_no_authority(target, label)
        rejections.append(label)
    report = dict(passed=True, profiles=accepted, rejections=rejections,
                  immutable_point_bytes=len(points), unchanged_pack_bytes=len(pack),
                  scope="real target capture and auth components; live handoff remains separately required")
    (BUILD / "crypto-bench/tls13-286-dual-issuer.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
