#!/usr/bin/env python3
"""Deterministic TLS 1.3 oracle for Seed's replacement-only protocol spike.

This is deliberately a host-side reference, not a TLS library and not runtime
code.  It models exactly one profile:

    TLS_CHACHA20_POLY1305_SHA256 + secp256r1 + rsa_pss_rsae_sha256

The vector contains both Seed ECDH tiers:

* the 8088 functional tier's scalar-one shortcut; and
* a deterministic nontrivial P-256 client scalar for the authenticated tier.

The replay uses the authenticated tier.  It constructs a coherent synthetic
RSA-2048 certificate and CertificateVerify, encrypts the TLS 1.3 server flight,
then replays it through deliberately awkward TCP fragmentation.  All crypto is
stdlib-only; the existing strict X.509 oracle supplies deterministic test
certificate construction and parsing.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import hmac
import json
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[3]
X509_TOOLS = ROOT / "tools" / "x509"
sys.path.insert(0, str(X509_TOOLS))
import der_build  # type: ignore  # local project oracle
import x509_verify  # type: ignore  # local project oracle


HASH_LEN = 32
CHACHA_KEY_LEN = 32
CHACHA_IV_LEN = 12
RECORD_SEQ_LEN = 8
AEAD_TAG_LEN = 16

TLS_LEGACY_VERSION = b"\x03\x03"
TLS13_VERSION = b"\x03\x04"
TLS13_CIPHER = b"\x13\x03"  # TLS_CHACHA20_POLY1305_SHA256
SECP256R1_GROUP = b"\x00\x17"
RSA_PSS_RSAE_SHA256 = b"\x08\x04"

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_ENCRYPTED_EXTENSIONS = 8
HS_CERTIFICATE = 11
HS_CERTIFICATE_VERIFY = 15
HS_FINISHED = 20

HOSTNAME = b"api.openai.com"
CLIENT_RANDOM = hashlib.sha256(b"Seed TLS 1.3 spike client random").digest()
SERVER_RANDOM = hashlib.sha256(b"Seed TLS 1.3 spike server random").digest()
PSS_SALT = hashlib.sha256(b"Seed TLS 1.3 spike fixed PSS salt").digest()
SAMPLE_APPLICATION_DATA = b'{"type":"response.output_text.delta","delta":"ok"}'

# The synthetic fixture is deterministic and test-only.  This seed is not an
# entropy source and the generated private key must never leave this harness.
RSA_FIXTURE_SEED = 0x71313
RSA_PUBLIC_EXPONENT = 65537


# NIST P-256 / secp256r1.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
Point = tuple[int, int] | None


def _scalar(label: bytes) -> int:
    return (int.from_bytes(hashlib.sha256(label).digest(), "big") % (P256_N - 1)) + 1


SECURE_CLIENT_SCALAR = _scalar(b"Seed TLS 1.3 spike secure client scalar")
SERVER_SCALAR = _scalar(b"Seed TLS 1.3 spike server scalar")
FUNCTIONAL_CLIENT_SCALAR = 1


class TLS13Error(ValueError):
    """Fail-closed vector/replay error."""


def _u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise TLS13Error(f"value does not fit u16: {value}")
    return value.to_bytes(2, "big")


def _u24(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise TLS13Error(f"value does not fit u24: {value}")
    return value.to_bytes(3, "big")


def _take_u16(buf: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(buf):
        raise TLS13Error("truncated u16")
    return int.from_bytes(buf[offset : offset + 2], "big"), offset + 2


def _take_u24(buf: bytes, offset: int) -> tuple[int, int]:
    if offset + 3 > len(buf):
        raise TLS13Error("truncated u24")
    return int.from_bytes(buf[offset : offset + 3], "big"), offset + 3


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + _u24(len(body)) + body


def _parse_handshake(message: bytes, expected_type: int) -> bytes:
    if len(message) < 4 or message[0] != expected_type:
        raise TLS13Error(f"expected handshake type {expected_type}")
    body_len = int.from_bytes(message[1:4], "big")
    if body_len != len(message) - 4:
        raise TLS13Error("handshake length mismatch")
    return message[4:]


def split_handshake_messages(content: bytes) -> tuple[bytes, ...]:
    messages: list[bytes] = []
    offset = 0
    while offset < len(content):
        if offset + 4 > len(content):
            raise TLS13Error("truncated combined handshake header")
        body_len = int.from_bytes(content[offset + 1 : offset + 4], "big")
        end = offset + 4 + body_len
        if end > len(content):
            raise TLS13Error("truncated combined handshake message")
        messages.append(content[offset:end])
        offset = end
    if offset != len(content):
        raise TLS13Error("combined handshake content length mismatch")
    return tuple(messages)


def _extension(extension_type: int, body: bytes) -> bytes:
    return _u16(extension_type) + _u16(len(body)) + body


def _iter_extensions(encoded: bytes) -> Iterable[tuple[int, bytes]]:
    offset = 0
    while offset < len(encoded):
        extension_type, offset = _take_u16(encoded, offset)
        extension_len, offset = _take_u16(encoded, offset)
        end = offset + extension_len
        if end > len(encoded):
            raise TLS13Error("truncated extension")
        yield extension_type, encoded[offset:end]
        offset = end
    if offset != len(encoded):
        raise TLS13Error("extension vector length mismatch")


# ---- P-256 -----------------------------------------------------------------

def _p256_inverse(value: int) -> int:
    if value % P256_P == 0:
        raise TLS13Error("P-256 inverse of zero")
    return pow(value, P256_P - 2, P256_P)


def p256_is_on_curve(point: Point) -> bool:
    if point is None:
        return True
    x_coord, y_coord = point
    if not (0 <= x_coord < P256_P and 0 <= y_coord < P256_P):
        return False
    return (
        (y_coord * y_coord)
        - ((x_coord * x_coord * x_coord) + (P256_A * x_coord) + P256_B)
    ) % P256_P == 0


def p256_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if left == right:
        slope = ((3 * x1 * x1 + P256_A) * _p256_inverse(2 * y1)) % P256_P
    else:
        slope = ((y2 - y1) * _p256_inverse(x2 - x1)) % P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    y3 = (slope * (x1 - x3) - y1) % P256_P
    result = (x3, y3)
    if not p256_is_on_curve(result):
        raise TLS13Error("P-256 point addition produced an invalid point")
    return result


def p256_multiply(scalar: int, point: Point = P256_G) -> Point:
    if not 0 <= scalar < P256_N:
        raise TLS13Error("P-256 scalar out of range")
    if not p256_is_on_curve(point):
        raise TLS13Error("P-256 input point is not on the curve")
    result: Point = None
    addend = point
    value = scalar
    while value:
        if value & 1:
            result = p256_add(result, addend)
        addend = p256_add(addend, addend)
        value >>= 1
    return result


def p256_encode(point: Point) -> bytes:
    if point is None or not p256_is_on_curve(point):
        raise TLS13Error("cannot encode invalid P-256 point")
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def p256_decode(encoded: bytes) -> Point:
    if len(encoded) != 65 or encoded[0] != 4:
        raise TLS13Error("only uncompressed P-256 points are accepted")
    point = (int.from_bytes(encoded[1:33], "big"), int.from_bytes(encoded[33:], "big"))
    if not p256_is_on_curve(point):
        raise TLS13Error("wire P-256 point is not on the curve")
    return point


def p256_shared_x(private_scalar: int, peer_public: Point) -> bytes:
    shared = p256_multiply(private_scalar, peer_public)
    if shared is None:
        raise TLS13Error("P-256 ECDH reached infinity")
    return shared[0].to_bytes(32, "big")


# ---- SHA-256 HKDF -----------------------------------------------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, output_len: int) -> bytes:
    if output_len < 0 or output_len > 255 * HASH_LEN:
        raise TLS13Error("HKDF output length out of range")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < output_len:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:output_len])


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, output_len: int) -> bytes:
    full_label = b"tls13 " + label
    if len(full_label) > 255 or len(context) > 255:
        raise TLS13Error("HKDF label/context too large")
    info = _u16(output_len) + bytes([len(full_label)]) + full_label
    info += bytes([len(context)]) + context
    return hkdf_expand(secret, info, output_len)


def derive_secret(secret: bytes, label: bytes, transcript: bytes) -> bytes:
    return hkdf_expand_label(secret, label, hashlib.sha256(transcript).digest(), HASH_LEN)


# ---- ChaCha20-Poly1305 ------------------------------------------------------

def _rotl32(value: int, count: int) -> int:
    return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != CHACHA_KEY_LEN or len(nonce) != CHACHA_IV_LEN:
        raise TLS13Error("bad ChaCha20 key or nonce length")
    if not 0 <= counter <= 0xFFFFFFFF:
        raise TLS13Error("ChaCha20 counter out of range")
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state.extend(struct.unpack("<8I", key))
    state.append(counter)
    state.extend(struct.unpack("<3I", nonce))
    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return b"".join(
        struct.pack("<I", (working[index] + state[index]) & 0xFFFFFFFF)
        for index in range(16)
    )


def _chacha20_xor(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    output = bytearray()
    counter = 1
    for offset in range(0, len(plaintext), 64):
        block = chacha20_block(key, counter, nonce)
        chunk = plaintext[offset : offset + 64]
        output.extend(left ^ right for left, right in zip(chunk, block))
        counter += 1
        if counter > 0xFFFFFFFF and offset + 64 < len(plaintext):
            raise TLS13Error("ChaCha20 counter exhausted")
    return bytes(output)


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise TLS13Error("bad Poly1305 one-time key length")
    r_value = int.from_bytes(key[:16], "little")
    r_value &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s_value = int.from_bytes(key[16:], "little")
    modulus = (1 << 130) - 5
    accumulator = 0
    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        accumulator += int.from_bytes(block + b"\x01", "little")
        accumulator = (accumulator * r_value) % modulus
    return ((accumulator + s_value) % (1 << 128)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"\x00" * ((16 - len(data) % 16) % 16)


def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = _chacha20_xor(key, nonce, plaintext)
    mac_input = aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
    mac_input += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    return ciphertext + poly1305_mac(mac_input, one_time_key)


def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, sealed: bytes) -> bytes:
    if len(sealed) < AEAD_TAG_LEN:
        raise TLS13Error("truncated ChaCha20-Poly1305 value")
    ciphertext, received_tag = sealed[:-AEAD_TAG_LEN], sealed[-AEAD_TAG_LEN:]
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    mac_input = aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
    mac_input += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    expected_tag = poly1305_mac(mac_input, one_time_key)
    if not hmac.compare_digest(received_tag, expected_tag):
        raise TLS13Error("ChaCha20-Poly1305 tag mismatch")
    return _chacha20_xor(key, nonce, ciphertext)


def tls13_nonce(iv: bytes, sequence_number: int) -> bytes:
    if len(iv) != CHACHA_IV_LEN or not 0 <= sequence_number < (1 << 64):
        raise TLS13Error("bad TLS 1.3 IV or sequence number")
    padded_sequence = b"\x00" * 4 + sequence_number.to_bytes(8, "big")
    return bytes(left ^ right for left, right in zip(iv, padded_sequence))


# ---- RSA-PSS ---------------------------------------------------------------

def mgf1_sha256(seed: bytes, output_len: int) -> bytes:
    output = bytearray()
    for counter in range((output_len + HASH_LEN - 1) // HASH_LEN):
        output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
    return bytes(output[:output_len])


def emsa_pss_encode(message: bytes, salt: bytes, em_bits: int) -> bytes:
    em_len = (em_bits + 7) // 8
    if len(salt) != HASH_LEN or em_len < (HASH_LEN * 2) + 2:
        raise TLS13Error("unsupported RSA-PSS shape")
    message_hash = hashlib.sha256(message).digest()
    h_value = hashlib.sha256(b"\x00" * 8 + message_hash + salt).digest()
    padding = b"\x00" * (em_len - HASH_LEN - len(salt) - 2)
    data_block = padding + b"\x01" + salt
    mask = mgf1_sha256(h_value, em_len - HASH_LEN - 1)
    masked_block = bytearray(left ^ right for left, right in zip(data_block, mask))
    unused_bits = (8 * em_len) - em_bits
    masked_block[0] &= 0xFF >> unused_bits
    return bytes(masked_block) + h_value + b"\xbc"


def rsa_pss_sign_fixture(message: bytes, modulus: int, private_exponent: int) -> bytes:
    encoded = emsa_pss_encode(message, PSS_SALT, modulus.bit_length() - 1)
    signature = pow(int.from_bytes(encoded, "big"), private_exponent, modulus)
    return signature.to_bytes((modulus.bit_length() + 7) // 8, "big")


def rsa_pss_verify_sha256(message: bytes, signature: bytes, modulus: int, exponent: int) -> bool:
    modulus_len = (modulus.bit_length() + 7) // 8
    em_bits = modulus.bit_length() - 1
    em_len = (em_bits + 7) // 8
    if len(signature) != modulus_len:
        return False
    signature_value = int.from_bytes(signature, "big")
    if signature_value >= modulus:
        return False
    encoded = pow(signature_value, exponent, modulus).to_bytes(modulus_len, "big")
    if len(encoded) != em_len or encoded[-1] != 0xBC:
        return False
    masked_block = bytearray(encoded[: em_len - HASH_LEN - 1])
    h_value = encoded[em_len - HASH_LEN - 1 : -1]
    unused_bits = (8 * em_len) - em_bits
    if masked_block[0] & (0xFF << (8 - unused_bits)):
        return False
    mask = mgf1_sha256(h_value, len(masked_block))
    data_block = bytearray(left ^ right for left, right in zip(masked_block, mask))
    data_block[0] &= 0xFF >> unused_bits
    padding_len = em_len - HASH_LEN - HASH_LEN - 2
    if data_block[:padding_len] != b"\x00" * padding_len:
        return False
    if data_block[padding_len] != 1:
        return False
    salt = bytes(data_block[-HASH_LEN:])
    message_hash = hashlib.sha256(message).digest()
    expected_h = hashlib.sha256(b"\x00" * 8 + message_hash + salt).digest()
    return hmac.compare_digest(h_value, expected_h)


def certificate_verify_input(transcript: bytes) -> bytes:
    return (
        b"\x20" * 64
        + b"TLS 1.3, server CertificateVerify"
        + b"\x00"
        + hashlib.sha256(transcript).digest()
    )


# ---- Handshake and record construction -------------------------------------

def build_client_hello(client_public: Point) -> bytes:
    name = b"\x00" + _u16(len(HOSTNAME)) + HOSTNAME
    server_name = _extension(0, _u16(len(name)) + name)
    supported_groups = _extension(10, _u16(2) + SECP256R1_GROUP)
    signature_algorithms = _extension(13, _u16(2) + RSA_PSS_RSAE_SHA256)
    supported_versions = _extension(43, b"\x02" + TLS13_VERSION)
    share = SECP256R1_GROUP + _u16(65) + p256_encode(client_public)
    key_share = _extension(51, _u16(len(share)) + share)
    extensions = (
        server_name
        + supported_groups
        + signature_algorithms
        + supported_versions
        + key_share
    )
    body = TLS_LEGACY_VERSION + CLIENT_RANDOM
    body += b"\x00"  # no legacy session ID
    body += _u16(2) + TLS13_CIPHER
    body += b"\x01\x00"  # one null compression method
    body += _u16(len(extensions)) + extensions
    return _handshake(HS_CLIENT_HELLO, body)


def build_server_hello(server_public: Point) -> bytes:
    supported_versions = _extension(43, TLS13_VERSION)
    key_share = _extension(51, SECP256R1_GROUP + _u16(65) + p256_encode(server_public))
    extensions = supported_versions + key_share
    body = TLS_LEGACY_VERSION + SERVER_RANDOM
    body += b"\x00" + TLS13_CIPHER + b"\x00"
    body += _u16(len(extensions)) + extensions
    return _handshake(HS_SERVER_HELLO, body)


def parse_server_hello(message: bytes) -> Point:
    body = _parse_handshake(message, HS_SERVER_HELLO)
    if len(body) < 38 or body[:2] != TLS_LEGACY_VERSION:
        raise TLS13Error("bad ServerHello legacy version/shape")
    offset = 34
    session_id_len = body[offset]
    offset += 1
    if offset + session_id_len + 5 > len(body):
        raise TLS13Error("truncated ServerHello session ID")
    offset += session_id_len
    if body[offset : offset + 2] != TLS13_CIPHER:
        raise TLS13Error("ServerHello selected an unsupported cipher")
    offset += 2
    if body[offset] != 0:
        raise TLS13Error("ServerHello selected non-null compression")
    offset += 1
    extensions_len, offset = _take_u16(body, offset)
    if offset + extensions_len != len(body):
        raise TLS13Error("ServerHello extensions length mismatch")
    selected_version = None
    peer_share = None
    for extension_type, extension_body in _iter_extensions(body[offset:]):
        if extension_type == 43:
            if selected_version is not None or extension_body != TLS13_VERSION:
                raise TLS13Error("bad/duplicate supported_versions")
            selected_version = extension_body
        elif extension_type == 51:
            if peer_share is not None or len(extension_body) != 69:
                raise TLS13Error("bad/duplicate ServerHello key_share")
            if extension_body[:2] != SECP256R1_GROUP:
                raise TLS13Error("ServerHello selected an unsupported group")
            share_len = int.from_bytes(extension_body[2:4], "big")
            if share_len != 65:
                raise TLS13Error("bad P-256 key-share length")
            peer_share = p256_decode(extension_body[4:])
        else:
            raise TLS13Error(f"unsupported ServerHello extension {extension_type}")
    if selected_version != TLS13_VERSION or peer_share is None:
        raise TLS13Error("ServerHello omitted a required extension")
    return peer_share


def build_encrypted_extensions() -> bytes:
    return _handshake(HS_ENCRYPTED_EXTENSIONS, b"\x00\x00")


def build_observed_encrypted_extensions() -> bytes:
    # The observed OpenAI flight carried a 10-byte EncryptedExtensions handshake
    # message.  An empty server_name response is a legal four-byte extension and
    # gives the same exact message geometry: 4-byte handshake header + 2-byte
    # extensions vector length + 4-byte extension.
    extensions = _extension(0, b"")
    message = _handshake(HS_ENCRYPTED_EXTENSIONS, _u16(len(extensions)) + extensions)
    if len(message) != 10:
        raise TLS13Error("observed EncryptedExtensions geometry drifted")
    return message


def _certificate_entry(certificate_der: bytes, extensions: bytes = b"") -> bytes:
    return _u24(len(certificate_der)) + certificate_der + _u16(len(extensions)) + extensions


def build_certificate_chain(certificates: Iterable[bytes]) -> bytes:
    entries = b"".join(_certificate_entry(certificate_der) for certificate_der in certificates)
    if not entries:
        raise TLS13Error("TLS 1.3 Certificate list cannot be empty")
    return _handshake(HS_CERTIFICATE, b"\x00" + _u24(len(entries)) + entries)


def build_certificate(certificate_der: bytes) -> bytes:
    return build_certificate_chain((certificate_der,))


def deterministic_filler(length: int, label: bytes) -> bytes:
    if length < 0:
        raise TLS13Error("negative deterministic filler length")
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(label + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


@functools.lru_cache(maxsize=1)
def build_observed_chain_filler_certificate() -> bytes:
    # Build a real, strictly parseable 3,257-byte X.509 entry rather than putting
    # arbitrary bytes in the TLS Certificate list.  A deterministic private
    # extension supplies the otherwise irrelevant observed chain bulk.
    target_len = 3257
    modulus, exponent, private_exponent, _ = rsa_fixture()
    filler = deterministic_filler(
        target_len,
        b"Seed TLS 1.3 observed OpenAI chain certificate extension",
    )
    private_test_oid = bytes.fromhex("06032a0304")  # 1.2.3.4, test-only
    for filler_len in range(target_len + 1):
        extension = der_build.enc_ext(
            private_test_oid,
            filler[:filler_len],
        )
        tbs = der_build.build_tbs(
            serial=b"\x02",
            issuer_cn="Seed TLS 1.3 Spike CA",
            subject_cn="Seed TLS 1.3 Chain Filler",
            not_before="250101000000Z",
            not_after="290101000000Z",
            leaf_n=modulus,
            leaf_e=exponent,
            extensions=[
                der_build.san_ext([HOSTNAME.decode("ascii")]),
                extension,
            ],
        )
        unsigned = der_build.build_cert(tbs, b"\x00" * 256)
        if len(unsigned) != target_len:
            continue
        signature = der_build.rsa_sign_pkcs1_sha256(
            tbs,
            private_exponent,
            modulus,
        )
        certificate = der_build.build_cert(tbs, signature)
        if len(certificate) != target_len:
            raise TLS13Error("signed observed chain filler changed DER length")
        result = x509_verify.verify_leaf(
            certificate,
            modulus,
            exponent,
            host=HOSTNAME.decode("ascii"),
            now=datetime(2026, 7, 25, tzinfo=timezone.utc),
        )
        if not result.accepted:
            raise TLS13Error(
                f"observed chain filler certificate rejected: {result.reason}"
            )
        return certificate
    raise TLS13Error("could not construct exact observed chain filler certificate")


def build_observed_certificate(certificate_der: bytes) -> bytes:
    # Exact observed geometry: the complete Certificate handshake message was
    # 4,000 bytes.  Keep entry zero as the coherent, strictly parsed leaf and
    # represent the remainder as one opaque chain entry.  Seed only authenticates
    # the leaf against WR1; later entries still have to be length-checked,
    # transcript-hashed, decrypted, MACed, and drained.
    target_message_len = 4000
    fixed_len = 4 + 1 + 3 + len(_certificate_entry(certificate_der))
    chain_entry_len = target_message_len - fixed_len
    chain_certificate_len = chain_entry_len - 3 - 2
    if chain_certificate_len <= 0:
        raise TLS13Error("observed Certificate target leaves no chain filler")
    chain_certificate = build_observed_chain_filler_certificate()
    if len(chain_certificate) != chain_certificate_len:
        raise TLS13Error("observed chain certificate has the wrong exact length")
    message = build_certificate_chain((certificate_der, chain_certificate))
    if len(message) != target_message_len:
        raise TLS13Error("observed Certificate geometry drifted")
    return message


def extract_certificate_entries(message: bytes) -> tuple[bytes, ...]:
    body = _parse_handshake(message, HS_CERTIFICATE)
    if not body:
        raise TLS13Error("empty Certificate message")
    context_len = body[0]
    offset = 1 + context_len
    if offset > len(body):
        raise TLS13Error("truncated certificate_request_context")
    list_len, offset = _take_u24(body, offset)
    if offset + list_len != len(body):
        raise TLS13Error("Certificate list length mismatch")
    entries: list[bytes] = []
    list_end = offset + list_len
    while offset < list_end:
        cert_len, offset = _take_u24(body, offset)
        end = offset + cert_len
        if end + 2 > list_end:
            raise TLS13Error("truncated certificate entry")
        entries.append(body[offset:end])
        offset = end
        extensions_len, offset = _take_u16(body, offset)
        extensions_end = offset + extensions_len
        if extensions_end > list_end:
            raise TLS13Error("certificate entry extensions length mismatch")
        offset = extensions_end
    if offset != list_end or not entries:
        raise TLS13Error("Certificate list did not contain complete entries")
    return tuple(entries)


def extract_leaf_certificate(message: bytes) -> bytes:
    return extract_certificate_entries(message)[0]


def build_certificate_verify(signature: bytes) -> bytes:
    return _handshake(
        HS_CERTIFICATE_VERIFY,
        RSA_PSS_RSAE_SHA256 + _u16(len(signature)) + signature,
    )


def parse_certificate_verify(message: bytes) -> bytes:
    body = _parse_handshake(message, HS_CERTIFICATE_VERIFY)
    if len(body) < 4 or body[:2] != RSA_PSS_RSAE_SHA256:
        raise TLS13Error("unsupported CertificateVerify signature scheme")
    signature_len = int.from_bytes(body[2:4], "big")
    if signature_len != 256 or len(body) != 4 + signature_len:
        raise TLS13Error("bad RSA-2048 CertificateVerify length")
    return body[4:]


def build_finished(verify_data: bytes) -> bytes:
    if len(verify_data) != HASH_LEN:
        raise TLS13Error("TLS 1.3 Finished must be a SHA-256 digest")
    return _handshake(HS_FINISHED, verify_data)


def plaintext_record(content_type: int, content: bytes, legacy_version: bytes) -> bytes:
    return bytes([content_type]) + legacy_version + _u16(len(content)) + content


def encrypted_record(
    key: bytes,
    iv: bytes,
    sequence_number: int,
    inner_type: int,
    content: bytes,
    padding_len: int = 0,
) -> bytes:
    if padding_len < 0:
        raise TLS13Error("negative TLSInnerPlaintext padding")
    inner_plaintext = content + bytes([inner_type]) + (b"\x00" * padding_len)
    sealed_len = len(inner_plaintext) + AEAD_TAG_LEN
    header = bytes([CONTENT_APPLICATION_DATA]) + TLS_LEGACY_VERSION + _u16(sealed_len)
    sealed = aead_encrypt(
        key,
        tls13_nonce(iv, sequence_number),
        header,
        inner_plaintext,
    )
    return header + sealed


def decrypt_record(key: bytes, iv: bytes, sequence_number: int, record: bytes) -> tuple[int, bytes]:
    content_type, legacy_version, payload = parse_plaintext_record(record)
    if content_type != CONTENT_APPLICATION_DATA or legacy_version != TLS_LEGACY_VERSION:
        raise TLS13Error("TLS 1.3 protected record has a bad outer header")
    plaintext = aead_decrypt(
        key,
        tls13_nonce(iv, sequence_number),
        record[:5],
        payload,
    )
    offset = len(plaintext) - 1
    while offset >= 0 and plaintext[offset] == 0:
        offset -= 1
    if offset < 0:
        raise TLS13Error("TLSInnerPlaintext contains only padding")
    return plaintext[offset], plaintext[:offset]


def parse_plaintext_record(record: bytes) -> tuple[int, bytes, bytes]:
    if len(record) < 5:
        raise TLS13Error("truncated TLS record header")
    payload_len = int.from_bytes(record[3:5], "big")
    if payload_len != len(record) - 5:
        raise TLS13Error("TLS record length mismatch")
    return record[0], record[1:3], record[5:]


# ---- Key schedule -----------------------------------------------------------

@dataclass(frozen=True)
class HandshakeKeys:
    early_secret: bytes
    handshake_secret: bytes
    client_traffic_secret: bytes
    server_traffic_secret: bytes
    client_key: bytes
    server_key: bytes
    client_iv: bytes
    server_iv: bytes
    client_finished_key: bytes
    server_finished_key: bytes


@dataclass(frozen=True)
class ApplicationKeys:
    master_secret: bytes
    client_traffic_secret: bytes
    server_traffic_secret: bytes
    client_key: bytes
    server_key: bytes
    client_iv: bytes
    server_iv: bytes


def derive_handshake_keys(shared_secret: bytes, hello_transcript: bytes) -> HandshakeKeys:
    if len(shared_secret) != HASH_LEN:
        raise TLS13Error("P-256 shared X must be 32 bytes")
    zeros = b"\x00" * HASH_LEN
    empty_hash = hashlib.sha256(b"").digest()
    early_secret = hkdf_extract(zeros, zeros)
    derived = hkdf_expand_label(early_secret, b"derived", empty_hash, HASH_LEN)
    handshake_secret = hkdf_extract(derived, shared_secret)
    client_traffic = derive_secret(handshake_secret, b"c hs traffic", hello_transcript)
    server_traffic = derive_secret(handshake_secret, b"s hs traffic", hello_transcript)
    return HandshakeKeys(
        early_secret=early_secret,
        handshake_secret=handshake_secret,
        client_traffic_secret=client_traffic,
        server_traffic_secret=server_traffic,
        client_key=hkdf_expand_label(client_traffic, b"key", b"", CHACHA_KEY_LEN),
        server_key=hkdf_expand_label(server_traffic, b"key", b"", CHACHA_KEY_LEN),
        client_iv=hkdf_expand_label(client_traffic, b"iv", b"", CHACHA_IV_LEN),
        server_iv=hkdf_expand_label(server_traffic, b"iv", b"", CHACHA_IV_LEN),
        client_finished_key=hkdf_expand_label(client_traffic, b"finished", b"", HASH_LEN),
        server_finished_key=hkdf_expand_label(server_traffic, b"finished", b"", HASH_LEN),
    )


def derive_application_keys(
    handshake_secret: bytes, server_finished_transcript: bytes
) -> ApplicationKeys:
    empty_hash = hashlib.sha256(b"").digest()
    derived = hkdf_expand_label(handshake_secret, b"derived", empty_hash, HASH_LEN)
    master_secret = hkdf_extract(derived, b"\x00" * HASH_LEN)
    client_traffic = derive_secret(master_secret, b"c ap traffic", server_finished_transcript)
    server_traffic = derive_secret(master_secret, b"s ap traffic", server_finished_transcript)
    return ApplicationKeys(
        master_secret=master_secret,
        client_traffic_secret=client_traffic,
        server_traffic_secret=server_traffic,
        client_key=hkdf_expand_label(client_traffic, b"key", b"", CHACHA_KEY_LEN),
        server_key=hkdf_expand_label(server_traffic, b"key", b"", CHACHA_KEY_LEN),
        client_iv=hkdf_expand_label(client_traffic, b"iv", b"", CHACHA_IV_LEN),
        server_iv=hkdf_expand_label(server_traffic, b"iv", b"", CHACHA_IV_LEN),
    )


# ---- Deterministic fixture and replay --------------------------------------

@functools.lru_cache(maxsize=1)
def rsa_fixture() -> tuple[int, int, int, bytes]:
    modulus, exponent, private_exponent = der_build.gen_rsa(
        2048, seed=RSA_FIXTURE_SEED, e=RSA_PUBLIC_EXPONENT
    )
    certificate_der = der_build.mint_cert(
        ca_n=modulus,
        ca_d=private_exponent,
        leaf_n=modulus,
        leaf_e=exponent,
        issuer_cn="Seed TLS 1.3 Spike CA",
        subject_cn=HOSTNAME.decode("ascii"),
        dns_names=[HOSTNAME.decode("ascii")],
        not_before="250101000000Z",
        not_after="290101000000Z",
    )
    return modulus, exponent, private_exponent, certificate_der


@dataclass(frozen=True)
class Vector:
    client_scalar: int
    client_public: Point
    server_public: Point
    shared_secret: bytes
    client_hello: bytes
    client_hello_record: bytes
    server_hello: bytes
    server_hello_record: bytes
    encrypted_extensions: bytes
    certificate: bytes
    certificate_verify: bytes
    server_finished: bytes
    encrypted_server_records: tuple[bytes, ...]
    server_flight: bytes
    client_finished: bytes
    client_finished_record: bytes
    sample_application_record: bytes
    handshake_keys: HandshakeKeys
    application_keys: ApplicationKeys
    certificate_der: bytes
    certificate_verify_signature: bytes


@dataclass(frozen=True)
class ObservedGeometryVector:
    base: Vector
    encrypted_extensions: bytes
    certificate: bytes
    certificate_verify: bytes
    server_finished: bytes
    combined_handshake: bytes
    protected_record: bytes
    server_flight: bytes
    certificate_verify_signature: bytes


def build_vector(client_scalar: int = SECURE_CLIENT_SCALAR) -> Vector:
    client_public = p256_multiply(client_scalar)
    server_public = p256_multiply(SERVER_SCALAR)
    if client_public is None or server_public is None:
        raise TLS13Error("fixture P-256 public key is infinity")
    client_hello = build_client_hello(client_public)
    server_hello = build_server_hello(server_public)
    shared_secret = p256_shared_x(client_scalar, server_public)
    if shared_secret != p256_shared_x(SERVER_SCALAR, client_public):
        raise TLS13Error("P-256 ECDH agreement mismatch")
    hello_transcript = client_hello + server_hello
    handshake_keys = derive_handshake_keys(shared_secret, hello_transcript)

    encrypted_extensions = build_encrypted_extensions()
    modulus, exponent, private_exponent, certificate_der = rsa_fixture()
    certificate = build_certificate(certificate_der)
    before_certificate_verify = hello_transcript + encrypted_extensions + certificate
    verify_input = certificate_verify_input(before_certificate_verify)
    signature = rsa_pss_sign_fixture(verify_input, modulus, private_exponent)
    if not rsa_pss_verify_sha256(verify_input, signature, modulus, exponent):
        raise TLS13Error("generated CertificateVerify signature did not verify")
    certificate_verify = build_certificate_verify(signature)
    before_server_finished = before_certificate_verify + certificate_verify
    server_verify_data = hmac.new(
        handshake_keys.server_finished_key,
        hashlib.sha256(before_server_finished).digest(),
        hashlib.sha256,
    ).digest()
    server_finished = build_finished(server_verify_data)

    server_messages = (
        encrypted_extensions,
        certificate,
        certificate_verify,
        server_finished,
    )
    encrypted_server_records = tuple(
        encrypted_record(
            handshake_keys.server_key,
            handshake_keys.server_iv,
            sequence_number,
            CONTENT_HANDSHAKE,
            message,
        )
        for sequence_number, message in enumerate(server_messages)
    )
    server_hello_record = plaintext_record(
        CONTENT_HANDSHAKE, server_hello, TLS_LEGACY_VERSION
    )
    server_flight = server_hello_record + b"".join(encrypted_server_records)

    through_server_finished = before_server_finished + server_finished
    client_verify_data = hmac.new(
        handshake_keys.client_finished_key,
        hashlib.sha256(through_server_finished).digest(),
        hashlib.sha256,
    ).digest()
    client_finished = build_finished(client_verify_data)
    client_finished_record = encrypted_record(
        handshake_keys.client_key,
        handshake_keys.client_iv,
        0,
        CONTENT_HANDSHAKE,
        client_finished,
    )
    application_keys = derive_application_keys(
        handshake_keys.handshake_secret, through_server_finished
    )
    sample_application_record = encrypted_record(
        application_keys.server_key,
        application_keys.server_iv,
        0,
        CONTENT_APPLICATION_DATA,
        SAMPLE_APPLICATION_DATA,
    )
    client_hello_record = plaintext_record(
        CONTENT_HANDSHAKE, client_hello, b"\x03\x01"
    )
    return Vector(
        client_scalar=client_scalar,
        client_public=client_public,
        server_public=server_public,
        shared_secret=shared_secret,
        client_hello=client_hello,
        client_hello_record=client_hello_record,
        server_hello=server_hello,
        server_hello_record=server_hello_record,
        encrypted_extensions=encrypted_extensions,
        certificate=certificate,
        certificate_verify=certificate_verify,
        server_finished=server_finished,
        encrypted_server_records=encrypted_server_records,
        server_flight=server_flight,
        client_finished=client_finished,
        client_finished_record=client_finished_record,
        sample_application_record=sample_application_record,
        handshake_keys=handshake_keys,
        application_keys=application_keys,
        certificate_der=certificate_der,
        certificate_verify_signature=signature,
    )


def build_observed_geometry_vector(base: Vector | None = None) -> ObservedGeometryVector:
    if base is None:
        base = build_vector()
    encrypted_extensions = build_observed_encrypted_extensions()
    certificate = build_observed_certificate(base.certificate_der)
    before_certificate_verify = (
        base.client_hello
        + base.server_hello
        + encrypted_extensions
        + certificate
    )
    modulus, exponent, private_exponent, _ = rsa_fixture()
    verify_input = certificate_verify_input(before_certificate_verify)
    signature = rsa_pss_sign_fixture(verify_input, modulus, private_exponent)
    if not rsa_pss_verify_sha256(verify_input, signature, modulus, exponent):
        raise TLS13Error("observed-geometry CertificateVerify signature did not verify")
    certificate_verify = build_certificate_verify(signature)
    before_server_finished = before_certificate_verify + certificate_verify
    server_verify_data = hmac.new(
        base.handshake_keys.server_finished_key,
        hashlib.sha256(before_server_finished).digest(),
        hashlib.sha256,
    ).digest()
    server_finished = build_finished(server_verify_data)
    combined_handshake = (
        encrypted_extensions
        + certificate
        + certificate_verify
        + server_finished
    )
    protected_record = encrypted_record(
        base.handshake_keys.server_key,
        base.handshake_keys.server_iv,
        0,
        CONTENT_HANDSHAKE,
        combined_handshake,
    )
    server_flight = base.server_hello_record + protected_record

    expected_message_lengths = (10, 4000, 264, 36)
    actual_message_lengths = tuple(
        len(message) for message in split_handshake_messages(combined_handshake)
    )
    if actual_message_lengths != expected_message_lengths:
        raise TLS13Error(
            "observed combined-handshake geometry mismatch: "
            f"{actual_message_lengths} != {expected_message_lengths}"
        )
    if len(combined_handshake) != 4310:
        raise TLS13Error("observed combined handshake must be exactly 4310 bytes")
    if int.from_bytes(protected_record[3:5], "big") != 4327:
        raise TLS13Error("observed protected record payload must be exactly 4327 bytes")
    if len(protected_record) != 4332:
        raise TLS13Error("observed protected record wire size must be exactly 4332 bytes")
    return ObservedGeometryVector(
        base=base,
        encrypted_extensions=encrypted_extensions,
        certificate=certificate,
        certificate_verify=certificate_verify,
        server_finished=server_finished,
        combined_handshake=combined_handshake,
        protected_record=protected_record,
        server_flight=server_flight,
        certificate_verify_signature=signature,
    )


class TLSRecordFramer:
    """Host replay framer.

    This intentionally buffers a whole record to keep the oracle simple.  The
    reported peak is not a proposed Seed allocation; the device should retain
    its existing incremental decrypt/MAC path for the large Certificate record.
    """

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.peak_buffered = 0

    def feed(self, chunk: bytes) -> list[bytes]:
        self.buffer.extend(chunk)
        self.peak_buffered = max(self.peak_buffered, len(self.buffer))
        records: list[bytes] = []
        while len(self.buffer) >= 5:
            record_len = 5 + int.from_bytes(self.buffer[3:5], "big")
            if record_len > 5 + (1 << 14) + 256:
                raise TLS13Error("record exceeds TLS 1.3 protected-record allowance")
            if len(self.buffer) < record_len:
                break
            records.append(bytes(self.buffer[:record_len]))
            del self.buffer[:record_len]
        return records

    def finish(self) -> None:
        if self.buffer:
            raise TLS13Error("truncated TLS record stream")


def fragment_bytes(data: bytes, schedule: tuple[int, ...]) -> Iterable[bytes]:
    if not schedule or any(size <= 0 for size in schedule):
        raise TLS13Error("fragment schedule must contain positive sizes")
    offset = 0
    index = 0
    while offset < len(data):
        size = schedule[index % len(schedule)]
        yield data[offset : offset + size]
        offset += size
        index += 1


@dataclass(frozen=True)
class ReplayResult:
    record_count: int
    peak_host_record_buffer: int
    certificate_bytes: int
    certificate_entry_count: int
    server_finished_verified: bool
    certificate_verify_verified: bool
    application_plaintext: bytes


@dataclass(frozen=True)
class ObservedReplayResult:
    record_count: int
    peak_host_record_buffer: int
    combined_handshake_bytes: int
    protected_record_payload_bytes: int
    protected_record_wire_bytes: int
    certificate_bytes: int
    certificate_entry_count: int
    server_finished_verified: bool
    certificate_verify_verified: bool


@dataclass(frozen=True)
class HandshakeVerification:
    certificate_bytes: int
    certificate_entry_count: int
    server_finished_verified: bool
    certificate_verify_verified: bool


def verify_server_handshake_messages(
    messages: tuple[bytes, ...],
    initial_transcript: bytes,
    handshake_keys: HandshakeKeys,
) -> HandshakeVerification:
    expected_types = (
        HS_ENCRYPTED_EXTENSIONS,
        HS_CERTIFICATE,
        HS_CERTIFICATE_VERIFY,
        HS_FINISHED,
    )
    if len(messages) != len(expected_types):
        raise TLS13Error(
            f"expected {len(expected_types)} server handshake messages, got {len(messages)}"
        )
    transcript = initial_transcript
    certificate_der = b""
    certificate_entry_count = 0
    certificate_verify_ok = False
    finished_ok = False
    for message, expected_type in zip(messages, expected_types):
        _parse_handshake(message, expected_type)
        if expected_type == HS_CERTIFICATE:
            certificate_entries = extract_certificate_entries(message)
            certificate_entry_count = len(certificate_entries)
            certificate_der = certificate_entries[0]
            parsed = x509_verify.parse_certificate(certificate_der)
            if (
                parsed.spki_bits != 2048
                or parsed.spki_exponent != RSA_PUBLIC_EXPONENT
                or HOSTNAME.decode("ascii") not in parsed.dns_names
            ):
                raise TLS13Error("synthetic leaf key/host policy mismatch")
            cert_result = x509_verify.verify_leaf(
                certificate_der,
                parsed.spki_modulus,
                parsed.spki_exponent,
                host=HOSTNAME.decode("ascii"),
                now=datetime(2026, 7, 25, tzinfo=timezone.utc),
            )
            if not cert_result.accepted:
                raise TLS13Error(f"synthetic certificate rejected: {cert_result.reason}")
        elif expected_type == HS_CERTIFICATE_VERIFY:
            if not certificate_der:
                raise TLS13Error("CertificateVerify arrived before Certificate")
            parsed = x509_verify.parse_certificate(certificate_der)
            signature = parse_certificate_verify(message)
            certificate_verify_ok = rsa_pss_verify_sha256(
                certificate_verify_input(transcript),
                signature,
                parsed.spki_modulus,
                parsed.spki_exponent,
            )
            if not certificate_verify_ok:
                raise TLS13Error("RSA-PSS CertificateVerify rejected")
        elif expected_type == HS_FINISHED:
            verify_data = _parse_handshake(message, HS_FINISHED)
            expected_verify_data = hmac.new(
                handshake_keys.server_finished_key,
                hashlib.sha256(transcript).digest(),
                hashlib.sha256,
            ).digest()
            finished_ok = hmac.compare_digest(verify_data, expected_verify_data)
            if not finished_ok:
                raise TLS13Error("server Finished mismatch")
        transcript += message
    return HandshakeVerification(
        certificate_bytes=len(certificate_der),
        certificate_entry_count=certificate_entry_count,
        server_finished_verified=finished_ok,
        certificate_verify_verified=certificate_verify_ok,
    )


def replay_server_flight(
    vector: Vector,
    fragment_schedule: tuple[int, ...] = (1, 2, 5, 13, 64, 127, 383),
) -> ReplayResult:
    framer = TLSRecordFramer()
    records: list[bytes] = []
    for chunk in fragment_bytes(vector.server_flight, fragment_schedule):
        records.extend(framer.feed(chunk))
    framer.finish()
    if len(records) != 5:
        raise TLS13Error(f"expected 5 server records, got {len(records)}")

    content_type, version, server_hello = parse_plaintext_record(records[0])
    if content_type != CONTENT_HANDSHAKE or version != TLS_LEGACY_VERSION:
        raise TLS13Error("bad plaintext ServerHello record")
    server_public = parse_server_hello(server_hello)
    shared_secret = p256_shared_x(vector.client_scalar, server_public)
    transcript = vector.client_hello + server_hello
    handshake_keys = derive_handshake_keys(shared_secret, transcript)

    messages: list[bytes] = []
    for sequence_number, record in enumerate(records[1:]):
        inner_type, message = decrypt_record(
            handshake_keys.server_key,
            handshake_keys.server_iv,
            sequence_number,
            record,
        )
        if inner_type != CONTENT_HANDSHAKE:
            raise TLS13Error("server handshake record has a bad inner content type")
        messages.append(message)
    verification = verify_server_handshake_messages(
        tuple(messages),
        transcript,
        handshake_keys,
    )

    app_inner_type, application_plaintext = decrypt_record(
        vector.application_keys.server_key,
        vector.application_keys.server_iv,
        0,
        vector.sample_application_record,
    )
    if app_inner_type != CONTENT_APPLICATION_DATA:
        raise TLS13Error("sample application record has a bad inner content type")
    return ReplayResult(
        record_count=len(records),
        peak_host_record_buffer=framer.peak_buffered,
        certificate_bytes=verification.certificate_bytes,
        certificate_entry_count=verification.certificate_entry_count,
        server_finished_verified=verification.server_finished_verified,
        certificate_verify_verified=verification.certificate_verify_verified,
        application_plaintext=application_plaintext,
    )


def replay_observed_geometry(
    vector: ObservedGeometryVector,
    fragment_schedule: tuple[int, ...] = (1, 2, 5, 13, 64, 127, 383),
) -> ObservedReplayResult:
    framer = TLSRecordFramer()
    records: list[bytes] = []
    for chunk in fragment_bytes(vector.server_flight, fragment_schedule):
        records.extend(framer.feed(chunk))
    framer.finish()
    if len(records) != 2:
        raise TLS13Error(f"expected 2 observed-geometry records, got {len(records)}")

    content_type, version, server_hello = parse_plaintext_record(records[0])
    if content_type != CONTENT_HANDSHAKE or version != TLS_LEGACY_VERSION:
        raise TLS13Error("bad observed-geometry ServerHello record")
    server_public = parse_server_hello(server_hello)
    shared_secret = p256_shared_x(vector.base.client_scalar, server_public)
    initial_transcript = vector.base.client_hello + server_hello
    handshake_keys = derive_handshake_keys(shared_secret, initial_transcript)

    inner_type, combined_handshake = decrypt_record(
        handshake_keys.server_key,
        handshake_keys.server_iv,
        0,
        records[1],
    )
    if inner_type != CONTENT_HANDSHAKE:
        raise TLS13Error("observed protected record has a bad inner content type")
    messages = split_handshake_messages(combined_handshake)
    verification = verify_server_handshake_messages(
        messages,
        initial_transcript,
        handshake_keys,
    )
    _, _, protected_payload = parse_plaintext_record(records[1])
    return ObservedReplayResult(
        record_count=len(records),
        peak_host_record_buffer=framer.peak_buffered,
        combined_handshake_bytes=len(combined_handshake),
        protected_record_payload_bytes=len(protected_payload),
        protected_record_wire_bytes=len(records[1]),
        certificate_bytes=verification.certificate_bytes,
        certificate_entry_count=verification.certificate_entry_count,
        server_finished_verified=verification.server_finished_verified,
        certificate_verify_verified=verification.certificate_verify_verified,
    )


# ---- Frozen vector and reporting -------------------------------------------

# Filled from the deterministic construction above.  These are intentionally
# fingerprints rather than a multi-kilobyte hex fixture: they freeze every
# protocol boundary while keeping the source reviewable.
EXPECTED: dict[str, str | int] = {
    "certificate_record_bytes": 760,
    "certificate_sha256": "21eb10cd871b6445df6cd3a54848b938e3c333aa84300fad688f3c0e2f3352c8",
    "certificate_verify_signature_sha256": "b9ae13a4da988501373037d7d03fee51e1ce7d62fd304984b47ac6064c5d4ed9",
    "client_finished_record_bytes": 58,
    "client_finished_record_sha256": "0c7d8bce401e7d243edc155bed2d8290f443841ba34a023ad20ab839b5b4e982",
    "client_handshake_traffic_secret": "c98463ef2ca78ee6a5764bf12238509f9c6cc322cb4ff139f40c8191c59bceb1",
    "client_hello_record_bytes": 173,
    "client_hello_sha256": "f2c5cb24c2868b858cdc67b6cfa18ca91ecc343baed9cb7f2cd03965d8b81c25",
    "functional_scalar_one_shared_secret": "24d63ceb19a489ac1ee63aa7c8afdf0bf3e8cfb5395193685d0f7fff214a0606",
    "handshake_secret": "e33d785c1c268fd5fe59b5a1acf59eb7a6b326ada5d5e36b3a6399724e97b0e5",
    "hello_transcript_sha256": "de30cb4d6eaec052f3cbe504611cd277f2aa322ed7386cd6181153b35ff2c468",
    "sample_application_record_sha256": "4d2a428ff2a95a062ca21645897a198df87d564f25c047ff014c0b32ef53ead2",
    "secure_client_public_sha256": "0371bcdcfbaa3ffeba31e2fbbd50b1328e294d56ea0b5bae864c3f5ea4b93f3a",
    "secure_shared_secret": "14e9172de15ef5c50fb35f4f7ab680ed40098d5be624af512b73de6995a28018",
    "server_application_iv": "5af32579b3d7709a553d3e54",
    "server_application_key": "f8a19646b0d82db56fdc2fd9cba2608629d9f278d86d8c2e73e73a3081da5c30",
    "server_finished_verify_data": "d32890b4a3c6d2947036348351509d4c130d5994c195c5aed431e0e8186e607b",
    "server_flight_bytes": 1260,
    "server_flight_sha256": "8e1b10f3e9743dc0f7e285414b6a7a86403449bc561c2285395a7bf5acc5da19",
    "server_handshake_iv": "d3b27aa5026babd4798d572d",
    "server_handshake_key": "8e7233ba0e99bc691cc9352653912402f94e87723009528af113bc3dd54629a3",
    "server_handshake_traffic_secret": "95d7d7cfa921b1691819fe5f59ba804f48251c1787b6be291fe940d36ac84814",
    "server_hello_record_bytes": 128,
    "server_hello_sha256": "622f517021f9024fd37056dc688bc0c57bc267ff8df2d1bdf412a440ea795e5e",
    "server_public_sha256": "9d0a6059505341ebf664be34f545ba18ba790bdf8944bb56279c979d719951a8",
}

OBSERVED_EXPECTED: dict[str, str | int] = {
    "certificate_entry_count": 2,
    "certificate_handshake_bytes": 4000,
    "certificate_verify_bytes": 264,
    "certificate_verify_signature_sha256": "8fe8edf7f124349db8d6dfab345ddb0e0993286e1336d5b8d90dfdf8b5025aad",
    "chain_filler_bytes": 3257,
    "chain_filler_sha256": "21325ff845aa8aeb53d1e2f4b8bcd0416d067a9f423dad9d9f9efa0e3cccfadb",
    "combined_handshake_bytes": 4310,
    "combined_handshake_sha256": "4c9375ecb09c088d00e804ce8bdbcfc27eae4cd658fd1b5263bc0d10e70231cb",
    "encrypted_extensions_bytes": 10,
    "leaf_certificate_sha256": "21eb10cd871b6445df6cd3a54848b938e3c333aa84300fad688f3c0e2f3352c8",
    "protected_record_payload_bytes": 4327,
    "protected_record_sha256": "fa207ead4ab1ba650ef3958df2cc202bf7557d67d3cfadf207fc05d8e3ee5bc7",
    "protected_record_wire_bytes": 4332,
    "server_finished_bytes": 36,
    "server_flight_with_server_hello_bytes": 4460,
    "server_flight_with_server_hello_sha256": "8167c7a6908033b812ead9776304fc0a90417510c06e60d36a6842d2cfde9289",
}


def vector_fingerprints(vector: Vector) -> dict[str, str | int]:
    floor_server_public = p256_multiply(SERVER_SCALAR)
    if floor_server_public is None:
        raise TLS13Error("server public key is infinity")
    floor_shared = p256_shared_x(FUNCTIONAL_CLIENT_SCALAR, floor_server_public)
    return {
        "secure_client_public_sha256": hashlib.sha256(
            p256_encode(vector.client_public)
        ).hexdigest(),
        "server_public_sha256": hashlib.sha256(
            p256_encode(vector.server_public)
        ).hexdigest(),
        "secure_shared_secret": vector.shared_secret.hex(),
        "functional_scalar_one_shared_secret": floor_shared.hex(),
        "client_hello_sha256": hashlib.sha256(vector.client_hello).hexdigest(),
        "server_hello_sha256": hashlib.sha256(vector.server_hello).hexdigest(),
        "hello_transcript_sha256": hashlib.sha256(
            vector.client_hello + vector.server_hello
        ).hexdigest(),
        "handshake_secret": vector.handshake_keys.handshake_secret.hex(),
        "client_handshake_traffic_secret": (
            vector.handshake_keys.client_traffic_secret.hex()
        ),
        "server_handshake_traffic_secret": (
            vector.handshake_keys.server_traffic_secret.hex()
        ),
        "server_handshake_key": vector.handshake_keys.server_key.hex(),
        "server_handshake_iv": vector.handshake_keys.server_iv.hex(),
        "certificate_sha256": hashlib.sha256(vector.certificate_der).hexdigest(),
        "certificate_verify_signature_sha256": hashlib.sha256(
            vector.certificate_verify_signature
        ).hexdigest(),
        "server_finished_verify_data": vector.server_finished[4:].hex(),
        "server_flight_sha256": hashlib.sha256(vector.server_flight).hexdigest(),
        "client_finished_record_sha256": hashlib.sha256(
            vector.client_finished_record
        ).hexdigest(),
        "server_application_key": vector.application_keys.server_key.hex(),
        "server_application_iv": vector.application_keys.server_iv.hex(),
        "sample_application_record_sha256": hashlib.sha256(
            vector.sample_application_record
        ).hexdigest(),
        "client_hello_record_bytes": len(vector.client_hello_record),
        "server_hello_record_bytes": len(vector.server_hello_record),
        "certificate_record_bytes": len(vector.encrypted_server_records[1]),
        "server_flight_bytes": len(vector.server_flight),
        "client_finished_record_bytes": len(vector.client_finished_record),
    }


def observed_geometry_fingerprints(
    vector: ObservedGeometryVector,
) -> dict[str, str | int]:
    entries = extract_certificate_entries(vector.certificate)
    return {
        "encrypted_extensions_bytes": len(vector.encrypted_extensions),
        "certificate_handshake_bytes": len(vector.certificate),
        "certificate_entry_count": len(entries),
        "leaf_certificate_sha256": hashlib.sha256(entries[0]).hexdigest(),
        "chain_filler_bytes": len(entries[1]),
        "chain_filler_sha256": hashlib.sha256(entries[1]).hexdigest(),
        "certificate_verify_bytes": len(vector.certificate_verify),
        "certificate_verify_signature_sha256": hashlib.sha256(
            vector.certificate_verify_signature
        ).hexdigest(),
        "server_finished_bytes": len(vector.server_finished),
        "combined_handshake_bytes": len(vector.combined_handshake),
        "combined_handshake_sha256": hashlib.sha256(
            vector.combined_handshake
        ).hexdigest(),
        "protected_record_payload_bytes": int.from_bytes(
            vector.protected_record[3:5], "big"
        ),
        "protected_record_wire_bytes": len(vector.protected_record),
        "protected_record_sha256": hashlib.sha256(
            vector.protected_record
        ).hexdigest(),
        "server_flight_with_server_hello_bytes": len(vector.server_flight),
        "server_flight_with_server_hello_sha256": hashlib.sha256(
            vector.server_flight
        ).hexdigest(),
    }


def check_frozen_vector(vector: Vector) -> None:
    actual = vector_fingerprints(vector)
    if not EXPECTED:
        raise TLS13Error("EXPECTED vector is empty; run --dump-vector during development")
    missing = set(EXPECTED) ^ set(actual)
    if missing:
        raise TLS13Error(f"frozen vector key mismatch: {sorted(missing)}")
    mismatches = {
        key: {"expected": EXPECTED[key], "actual": actual[key]}
        for key in EXPECTED
        if EXPECTED[key] != actual[key]
    }
    if mismatches:
        raise TLS13Error(f"frozen TLS 1.3 vector mismatch: {mismatches}")


def check_frozen_observed_geometry(vector: ObservedGeometryVector) -> None:
    actual = observed_geometry_fingerprints(vector)
    if not OBSERVED_EXPECTED:
        raise TLS13Error(
            "OBSERVED_EXPECTED vector is empty; run --dump-vector during development"
        )
    missing = set(OBSERVED_EXPECTED) ^ set(actual)
    if missing:
        raise TLS13Error(f"observed frozen vector key mismatch: {sorted(missing)}")
    mismatches = {
        key: {"expected": OBSERVED_EXPECTED[key], "actual": actual[key]}
        for key in OBSERVED_EXPECTED
        if OBSERVED_EXPECTED[key] != actual[key]
    }
    if mismatches:
        raise TLS13Error(f"observed OpenAI geometry vector mismatch: {mismatches}")


def check_rfc_primitives() -> None:
    # RFC 5869 test case 1.
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = hkdf_extract(salt, ikm)
    okm = hkdf_expand(prk, info, 42)
    if prk.hex() != "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5":
        raise TLS13Error("RFC 5869 HKDF-Extract vector mismatch")
    if okm.hex() != (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ):
        raise TLS13Error("RFC 5869 HKDF-Expand vector mismatch")

    # RFC 8439 section 2.3.2.
    block = chacha20_block(
        bytes(range(32)),
        1,
        bytes.fromhex("000000090000004a00000000"),
    )
    if block.hex() != (
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    ):
        raise TLS13Error("RFC 8439 ChaCha20 block vector mismatch")


def check_tamper_gates(vector: Vector) -> None:
    # AEAD corruption must fail before plaintext is used.
    corrupted = bytearray(vector.sample_application_record)
    corrupted[-1] ^= 1
    try:
        decrypt_record(
            vector.application_keys.server_key,
            vector.application_keys.server_iv,
            0,
            bytes(corrupted),
        )
    except TLS13Error as error:
        if "tag mismatch" not in str(error):
            raise
    else:
        raise TLS13Error("corrupted application tag was accepted")

    modulus, exponent, _, _ = rsa_fixture()
    transcript = (
        vector.client_hello
        + vector.server_hello
        + vector.encrypted_extensions
        + vector.certificate
    )
    signature = bytearray(vector.certificate_verify_signature)
    signature[len(signature) // 2] ^= 1
    if rsa_pss_verify_sha256(
        certificate_verify_input(transcript),
        bytes(signature),
        modulus,
        exponent,
    ):
        raise TLS13Error("corrupted RSA-PSS CertificateVerify was accepted")

    wrong_context = certificate_verify_input(transcript + b"\x00")
    if rsa_pss_verify_sha256(
        wrong_context,
        vector.certificate_verify_signature,
        modulus,
        exponent,
    ):
        raise TLS13Error("RSA-PSS CertificateVerify accepted the wrong transcript")

    finished = bytearray(vector.server_finished[4:])
    finished[0] ^= 1
    before_finished = (
        vector.client_hello
        + vector.server_hello
        + vector.encrypted_extensions
        + vector.certificate
        + vector.certificate_verify
    )
    expected = hmac.new(
        vector.handshake_keys.server_finished_key,
        hashlib.sha256(before_finished).digest(),
        hashlib.sha256,
    ).digest()
    if hmac.compare_digest(finished, expected):
        raise TLS13Error("corrupted server Finished was accepted")


def check_observed_geometry_tamper_gate(vector: ObservedGeometryVector) -> None:
    corrupted = bytearray(vector.protected_record)
    corrupted[-1] ^= 1
    try:
        decrypt_record(
            vector.base.handshake_keys.server_key,
            vector.base.handshake_keys.server_iv,
            0,
            bytes(corrupted),
        )
    except TLS13Error as error:
        if "tag mismatch" not in str(error):
            raise
    else:
        raise TLS13Error("corrupted observed OpenAI protected record was accepted")


def sizing_report(
    vector: Vector,
    replay: ReplayResult,
    observed: ObservedGeometryVector,
    observed_replay: ObservedReplayResult,
) -> dict[str, object]:
    encrypted_names = (
        "encrypted_extensions",
        "certificate",
        "certificate_verify",
        "server_finished",
    )
    encrypted_sizes = {
        name: len(record)
        for name, record in zip(encrypted_names, vector.encrypted_server_records)
    }
    per_direction_persistent = CHACHA_KEY_LEN + CHACHA_IV_LEN + RECORD_SEQ_LEN
    return {
        "profile": {
            "version": "TLS 1.3",
            "cipher": "TLS_CHACHA20_POLY1305_SHA256",
            "group": "secp256r1",
            "signature": "rsa_pss_rsae_sha256",
        },
        "wire_bytes": {
            "client_hello_record": len(vector.client_hello_record),
            "server_hello_record": len(vector.server_hello_record),
            **encrypted_sizes,
            "server_flight_total": len(vector.server_flight),
            "client_finished_record": len(vector.client_finished_record),
            "sample_application_record": len(vector.sample_application_record),
        },
        "handshake_message_bytes": {
            "client_hello": len(vector.client_hello),
            "server_hello": len(vector.server_hello),
            "encrypted_extensions": len(vector.encrypted_extensions),
            "certificate": len(vector.certificate),
            "certificate_der": len(vector.certificate_der),
            "certificate_verify": len(vector.certificate_verify),
            "server_finished": len(vector.server_finished),
            "client_finished": len(vector.client_finished),
        },
        "semantic_state_bytes": {
            "hash_or_traffic_secret": HASH_LEN,
            "p256_shared_x": HASH_LEN,
            "chacha_key": CHACHA_KEY_LEN,
            "chacha_iv": CHACHA_IV_LEN,
            "record_sequence": RECORD_SEQ_LEN,
            "post_handshake_per_direction_key_iv_seq": per_direction_persistent,
            "post_handshake_bidirectional_key_iv_seq": per_direction_persistent * 2,
            "handshake_bidirectional_key_iv": (
                (CHACHA_KEY_LEN + CHACHA_IV_LEN) * 2
            ),
        },
        "streaming_pressure": {
            "advertised_seed_tcp_mss": 384,
            "largest_protected_record": max(
                len(record) for record in vector.encrypted_server_records
            ),
            "certificate_record_tcp_segments_at_mss": (
                len(vector.encrypted_server_records[1]) + 383
            )
            // 384,
            "host_oracle_whole_record_peak": replay.peak_host_record_buffer,
            "device_requirement": (
                "stream decrypt/MAC the Certificate record; do not allocate the host peak"
            ),
        },
        "observed_openai_flight_geometry": {
            "encrypted_extensions_handshake": len(observed.encrypted_extensions),
            "certificate_handshake": len(observed.certificate),
            "certificate_entries": observed_replay.certificate_entry_count,
            "certificate_verify_handshake": len(observed.certificate_verify),
            "server_finished_handshake": len(observed.server_finished),
            "combined_handshake_plaintext": len(observed.combined_handshake),
            "tls_inner_content_type_bytes": 1,
            "aead_tag_bytes": AEAD_TAG_LEN,
            "protected_record_payload": observed_replay.protected_record_payload_bytes,
            "protected_record_wire": observed_replay.protected_record_wire_bytes,
            "server_flight_with_server_hello": len(observed.server_flight),
            "protected_record_tcp_segments_at_mss": (
                observed_replay.protected_record_wire_bytes + 383
            )
            // 384,
            "host_oracle_whole_record_peak": (
                observed_replay.peak_host_record_buffer
            ),
        },
    }


def run_checks() -> tuple[
    Vector,
    ReplayResult,
    ObservedGeometryVector,
    ObservedReplayResult,
]:
    check_rfc_primitives()
    vector = build_vector()
    check_frozen_vector(vector)

    floor_vector = build_vector(FUNCTIONAL_CLIENT_SCALAR)
    if floor_vector.shared_secret != p256_encode(floor_vector.server_public)[1:33]:
        raise TLS13Error("scalar-one shared secret is not the server public X coordinate")

    replay = replay_server_flight(vector)
    if (
        not replay.certificate_verify_verified
        or not replay.server_finished_verified
        or replay.application_plaintext != SAMPLE_APPLICATION_DATA
    ):
        raise TLS13Error("authenticated replay did not reach application data")

    # Record parsing must be independent of TCP segmentation.
    for schedule in ((1,), (384,), (37, 383, 2, 127, 1)):
        alternate = replay_server_flight(vector, schedule)
        if alternate.application_plaintext != SAMPLE_APPLICATION_DATA:
            raise TLS13Error(f"fragment replay failed for schedule {schedule}")

    check_tamper_gates(vector)
    observed = build_observed_geometry_vector(vector)
    check_frozen_observed_geometry(observed)
    observed_replay = replay_observed_geometry(observed)
    if (
        not observed_replay.certificate_verify_verified
        or not observed_replay.server_finished_verified
        or observed_replay.certificate_entry_count != 2
    ):
        raise TLS13Error("observed OpenAI geometry replay did not authenticate")
    for schedule in ((1,), (384,), (37, 383, 2, 127, 1)):
        alternate = replay_observed_geometry(observed, schedule)
        if (
            not alternate.certificate_verify_verified
            or not alternate.server_finished_verified
            or alternate.protected_record_wire_bytes != 4332
        ):
            raise TLS13Error(
                f"observed geometry fragment replay failed for schedule {schedule}"
            )
    check_observed_geometry_tamper_gate(observed)
    return vector, replay, observed, observed_replay


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the checked sizing report as JSON",
    )
    parser.add_argument(
        "--dump-vector",
        action="store_true",
        help="development helper: print generated frozen-vector fingerprints",
    )
    args = parser.parse_args()

    if args.dump_vector:
        compact = build_vector()
        observed = build_observed_geometry_vector(compact)
        print(
            json.dumps(
                {
                    "compact": vector_fingerprints(compact),
                    "observed_openai_geometry": observed_geometry_fingerprints(
                        observed
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    vector, replay, observed, observed_replay = run_checks()
    report = sizing_report(vector, replay, observed, observed_replay)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        wire = report["wire_bytes"]
        state = report["semantic_state_bytes"]
        pressure = report["streaming_pressure"]
        observed_geometry = report["observed_openai_flight_geometry"]
        assert isinstance(wire, dict)
        assert isinstance(state, dict)
        assert isinstance(pressure, dict)
        assert isinstance(observed_geometry, dict)
        print("TLS 1.3 single-profile oracle: PASS")
        print(
            "  profile: TLS_CHACHA20_POLY1305_SHA256 / "
            "secp256r1 / rsa_pss_rsae_sha256"
        )
        print(
            f"  server flight: {wire['server_flight_total']} B; "
            f"certificate record: {wire['certificate']} B"
        )
        print(
            "  post-handshake key+IV+sequence minimum: "
            f"{state['post_handshake_bidirectional_key_iv_seq']} B bidirectional"
        )
        print(
            f"  certificate record spans "
            f"{pressure['certificate_record_tcp_segments_at_mss']} x 384-B MSS segments"
        )
        print(
            "  observed OpenAI geometry: "
            f"{observed_geometry['combined_handshake_plaintext']} B handshake -> "
            f"{observed_geometry['protected_record_payload']} B payload / "
            f"{observed_geometry['protected_record_wire']} B wire, "
            f"{observed_geometry['protected_record_tcp_segments_at_mss']} x 384-B MSS"
        )
        print("  fragmented replay + RSA-PSS/Finished/AEAD tamper gates: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
