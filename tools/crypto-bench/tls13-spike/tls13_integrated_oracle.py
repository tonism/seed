#!/usr/bin/env python3
"""Hostile offline oracle for Seed's provisional TLS 1.3 state machine.

This file is deliberately independent from the product runtime.  It models the
exact security boundary proposed by the Build 13 rearchitecture spike:

* an X25519MLKEM768 ClientHello whose X25519 share is the fixed coordinate u=9;
* provisional use of an ML-KEM shared-secret candidate;
* full-record AEAD verification and server Finished verification before the
  client emits Finished;
* at most one immutable credential-free HEAD request in flight;
* deferred, transcript-bound KEM and server-identity proof results;
* one atomic promotion gate for either the live connection or a tentative
  same-boot ticket; and
* no API credential object reachable from the state machine before promotion.

The deterministic TLS records use the live-observed OpenAI geometry.  The
ML-KEM and ECDSA proof *results* are explicit hostile inputs: this is a state
machine oracle, not a substitute for their independent known-answer tests.
Live-provider observations are kept in ``tls13_integrated_live.py`` and never
influence a deterministic acceptance decision here.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import re
import sys
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
HOST = b"api.openai.com"
APPLICATION_PROTOCOL = b"http/1.1"
TLS13_CIPHER = b"\x13\x03"  # TLS_CHACHA20_POLY1305_SHA256
TLS13_VERSION = b"\x03\x04"
TLS_LEGACY_VERSION = b"\x03\x03"
HYBRID_GROUP = 0x11EC
ECDSA_SECP256R1_SHA256 = b"\x04\x03"
BROTLI_CERTIFICATE_COMPRESSION = 2
COMPRESSED_CERTIFICATE_BODY_LEN = 2491
COMPRESSED_CERTIFICATE_DATA_LEN = 1787

MLKEM_PUBLIC_LEN = 1184
MLKEM_CIPHERTEXT_LEN = 1088
X25519_LEN = 32
HASH_LEN = 32

CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_NEW_SESSION_TICKET = 4
HS_ENCRYPTED_EXTENSIONS = 8
HS_CERTIFICATE = 11
HS_CERTIFICATE_REQUEST = 13
HS_CERTIFICATE_VERIFY = 15
HS_FINISHED = 20
HS_KEY_UPDATE = 24
HS_COMPRESSED_CERTIFICATE = 25

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_COMPRESS_CERTIFICATE = 27
EXT_KEY_SHARE = 51
EXT_PADDING = 21
EXT_EARLY_DATA = 42

OBSERVED_CLIENT_HELLO_LEN = 1376
OBSERVED_SERVER_HELLO_LEN = 1210
OBSERVED_SERVER_FLIGHT_RECORD_LEN = 1947
OBSERVED_CLIENT_FINISHED_RECORD_LEN = 58
OBSERVED_MESSAGE_LENGTHS = (10, 1799, 80, 36)
MIN_ECDSA_DER_LEN = 8
MAX_ECDSA_DER_LEN = 72
MIN_CERTIFICATE_VERIFY_LEN = 8 + MIN_ECDSA_DER_LEN
MAX_CERTIFICATE_VERIFY_LEN = 8 + MAX_ECDSA_DER_LEN
MIN_SERVER_FLIGHT_RECORD_LEN = 1875 + MIN_ECDSA_DER_LEN
MAX_SERVER_FLIGHT_RECORD_LEN = 1875 + MAX_ECDSA_DER_LEN

HEAD_REQUEST = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)
MAX_HEAD_RESPONSE_HEADER = 2048
MAX_TICKET_IDENTITY = 256
MAX_TICKET_NONCE = 32
MAX_TICKET_LIFETIME = 7 * 24 * 60 * 60
MAX_NST_MESSAGES_PER_RECORD = 4
FIXED_FAILURE_ACTION = "close"


def _load_base_oracle():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_integrated_base", HERE / "tls13_spike.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load TLS 1.3 base oracle")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASE = _load_base_oracle()


class ProtocolAbort(RuntimeError):
    """The externally visible failure is deliberately always the same."""

    def __init__(self) -> None:
        super().__init__("provisional TLS connection closed")


class CredentialLocked(RuntimeError):
    """A caller attempted to obtain a credential before live commit."""


class Phase(Enum):
    NEW = auto()
    HANDSHAKE_KEYS = auto()
    SERVER_FINISHED_VERIFIED = auto()
    PROVISIONAL = auto()
    COMMITTED_LIVE = auto()
    COMMITTED_TICKET_ONLY = auto()
    CLOSED = auto()


@dataclass(frozen=True)
class FixedProfile:
    host: bytes = HOST
    cipher: bytes = TLS13_CIPHER
    version: bytes = TLS13_VERSION
    group: int = HYBRID_GROUP
    signature_scheme: bytes = ECDSA_SECP256R1_SHA256
    certificate_compression: int = BROTLI_CERTIFICATE_COMPRESSION
    x25519_client_share: bytes = b"\x09" + (b"\x00" * 31)


PROFILE = FixedProfile()


@dataclass(frozen=True)
class ParsedClientHello:
    mlkem_public: bytes
    session_id: bytes


@dataclass(frozen=True)
class ParsedServerHello:
    mlkem_ciphertext: bytes
    x25519_public: bytes


@dataclass(frozen=True)
class TentativeTicket:
    identity: bytes
    nonce: bytes
    lifetime: int
    age_add: int
    psk: bytes
    endpoint: bytes
    profile_digest: bytes
    original_transcript_digest: bytes


@dataclass(frozen=True)
class PromotedTicket:
    identity: bytes
    nonce: bytes
    lifetime: int
    age_add: int
    psk: bytes
    endpoint: bytes
    profile_digest: bytes
    original_transcript_digest: bytes
    leaf_spki_digest: bytes
    requires_psk_dhe: bool = True
    permits_early_data: bool = False


@dataclass(frozen=True)
class IntegratedFixture:
    client_hello: bytes
    server_hello: bytes
    mlkem_public: bytes
    mlkem_ciphertext: bytes
    server_x25519_public: bytes
    candidate_mlkem_secret: bytes
    server_flight_messages: tuple[bytes, bytes, bytes, bytes]
    server_flight_record: bytes
    certificate_verify_transcript_digest: bytes
    server_finished_transcript_digest: bytes
    profile_digest: bytes


def _u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise ValueError("uint16 overflow")
    return value.to_bytes(2, "big")


def _u24(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("uint24 overflow")
    return value.to_bytes(3, "big")


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + _u24(len(body)) + body


def _extension(extension_type: int, body: bytes) -> bytes:
    return _u16(extension_type) + _u16(len(body)) + body


def _deterministic_bytes(label: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"Seed integrated TLS 1.3|" + label).digest(length)


def _parse_handshake_messages(data: bytes) -> tuple[bytes, ...]:
    messages: list[bytes] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("truncated handshake header")
        length = int.from_bytes(data[offset + 1 : offset + 4], "big")
        end = offset + 4 + length
        if end > len(data):
            raise ValueError("truncated handshake message")
        messages.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise ValueError("handshake framing mismatch")
    return tuple(messages)


def _parse_extensions(encoded: bytes) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    offset = 0
    while offset < len(encoded):
        if len(encoded) - offset < 4:
            raise ValueError("truncated extension header")
        extension_type = int.from_bytes(encoded[offset : offset + 2], "big")
        length = int.from_bytes(encoded[offset + 2 : offset + 4], "big")
        offset += 4
        end = offset + length
        if end > len(encoded):
            raise ValueError("truncated extension body")
        if extension_type in result:
            raise ValueError("duplicate extension")
        result[extension_type] = encoded[offset:end]
        offset = end
    if offset != len(encoded):
        raise ValueError("extension framing mismatch")
    return result


def _parse_exact_message(message: bytes, expected_type: int) -> bytes:
    if len(message) < 4 or message[0] != expected_type:
        raise ValueError("unexpected handshake message")
    length = int.from_bytes(message[1:4], "big")
    if length != len(message) - 4:
        raise ValueError("handshake length mismatch")
    return message[4:]


def build_fixed_client_hello(
    mlkem_public: bytes, session_id: bytes | None = None
) -> bytes:
    """Build the exact 1,376-byte fixed-profile ClientHello."""

    if len(mlkem_public) != MLKEM_PUBLIC_LEN:
        raise ValueError("bad ML-KEM-768 public-key length")
    if session_id is None:
        session_id = _deterministic_bytes(b"session-id", 32)
    if len(session_id) != 32:
        raise ValueError("fixed profile requires a 32-byte session id")

    server_name = (
        _u16(1 + 2 + len(HOST)) + b"\x00" + _u16(len(HOST)) + HOST
    )
    key_exchange = mlkem_public + PROFILE.x25519_client_share
    key_share_entry = _u16(HYBRID_GROUP) + _u16(len(key_exchange)) + key_exchange
    extensions = b"".join(
        (
            _extension(EXT_SERVER_NAME, server_name),
            _extension(EXT_SUPPORTED_VERSIONS, b"\x02" + TLS13_VERSION),
            _extension(
                EXT_SUPPORTED_GROUPS, _u16(2) + _u16(HYBRID_GROUP)
            ),
            _extension(
                EXT_SIGNATURE_ALGORITHMS,
                _u16(len(ECDSA_SECP256R1_SHA256))
                + ECDSA_SECP256R1_SHA256,
            ),
            _extension(
                EXT_COMPRESS_CERTIFICATE,
                b"\x02" + _u16(BROTLI_CERTIFICATE_COMPRESSION),
            ),
            _extension(
                EXT_KEY_SHARE, _u16(len(key_share_entry)) + key_share_entry
            ),
            _extension(EXT_PADDING, b"\x00" * 14),
        )
    )
    body = b"".join(
        (
            TLS_LEGACY_VERSION,
            _deterministic_bytes(b"client-random", 32),
            bytes([len(session_id)]),
            session_id,
            _u16(len(TLS13_CIPHER)),
            TLS13_CIPHER,
            b"\x01\x00",
            _u16(len(extensions)),
            extensions,
        )
    )
    message = _handshake(HS_CLIENT_HELLO, body)
    if len(message) != OBSERVED_CLIENT_HELLO_LEN:
        raise AssertionError(f"ClientHello geometry drifted: {len(message)}")
    return message


def parse_fixed_client_hello(message: bytes) -> ParsedClientHello:
    body = _parse_exact_message(message, HS_CLIENT_HELLO)
    if len(message) != OBSERVED_CLIENT_HELLO_LEN:
        raise ValueError("unexpected ClientHello geometry")
    offset = 0
    if body[offset : offset + 2] != TLS_LEGACY_VERSION:
        raise ValueError("bad ClientHello legacy version")
    offset += 2 + 32
    if offset >= len(body):
        raise ValueError("truncated ClientHello session id")
    session_len = body[offset]
    offset += 1
    session_id = body[offset : offset + session_len]
    offset += session_len
    if len(session_id) != 32:
        raise ValueError("unexpected ClientHello session id")
    if offset + 2 > len(body):
        raise ValueError("truncated ClientHello cipher vector")
    cipher_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if body[offset : offset + cipher_len] != TLS13_CIPHER:
        raise ValueError("fixed ClientHello offered a different cipher")
    offset += cipher_len
    if body[offset : offset + 2] != b"\x01\x00":
        raise ValueError("bad ClientHello compression vector")
    offset += 2
    extension_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if offset + extension_len != len(body):
        raise ValueError("ClientHello extension length mismatch")
    extensions = _parse_extensions(body[offset:])
    required = {
        EXT_SERVER_NAME,
        EXT_SUPPORTED_VERSIONS,
        EXT_SUPPORTED_GROUPS,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_COMPRESS_CERTIFICATE,
        EXT_KEY_SHARE,
        EXT_PADDING,
    }
    if set(extensions) != required:
        raise ValueError("fixed ClientHello extension set changed")
    expected_name = (
        _u16(1 + 2 + len(HOST)) + b"\x00" + _u16(len(HOST)) + HOST
    )
    if extensions[EXT_SERVER_NAME] != expected_name:
        raise ValueError("fixed ClientHello SNI changed")
    if extensions[EXT_SUPPORTED_VERSIONS] != b"\x02" + TLS13_VERSION:
        raise ValueError("fixed ClientHello TLS version changed")
    if extensions[EXT_SUPPORTED_GROUPS] != _u16(2) + _u16(HYBRID_GROUP):
        raise ValueError("fixed ClientHello group changed")
    if extensions[EXT_SIGNATURE_ALGORITHMS] != (
        _u16(2) + ECDSA_SECP256R1_SHA256
    ):
        raise ValueError("fixed ClientHello signature scheme changed")
    if extensions[EXT_COMPRESS_CERTIFICATE] != (
        b"\x02" + _u16(BROTLI_CERTIFICATE_COMPRESSION)
    ):
        raise ValueError("fixed ClientHello certificate compression changed")

    key_shares = extensions[EXT_KEY_SHARE]
    if len(key_shares) < 2:
        raise ValueError("short ClientHello key_share")
    vector_len = int.from_bytes(key_shares[:2], "big")
    if vector_len != len(key_shares) - 2:
        raise ValueError("ClientHello key_share vector mismatch")
    entry = key_shares[2:]
    if len(entry) != 4 + MLKEM_PUBLIC_LEN + X25519_LEN:
        raise ValueError("unexpected ClientHello key_share size")
    if int.from_bytes(entry[:2], "big") != HYBRID_GROUP:
        raise ValueError("unexpected ClientHello key_share group")
    exchange_len = int.from_bytes(entry[2:4], "big")
    if exchange_len != MLKEM_PUBLIC_LEN + X25519_LEN:
        raise ValueError("unexpected ClientHello exchange length")
    exchange = entry[4:]
    if exchange[-X25519_LEN:] != PROFILE.x25519_client_share:
        raise ValueError("ClientHello did not use fixed X25519 u=9")
    return ParsedClientHello(exchange[:MLKEM_PUBLIC_LEN], session_id)


def build_fixed_server_hello(
    session_id: bytes, mlkem_ciphertext: bytes, server_x25519_public: bytes
) -> bytes:
    if len(session_id) != 32:
        raise ValueError("fixed profile requires a 32-byte session id")
    if len(mlkem_ciphertext) != MLKEM_CIPHERTEXT_LEN:
        raise ValueError("bad ML-KEM-768 ciphertext length")
    if len(server_x25519_public) != X25519_LEN:
        raise ValueError("bad X25519 public-share length")
    if not any(server_x25519_public):
        raise ValueError("all-zero X25519 server share")
    exchange = mlkem_ciphertext + server_x25519_public
    extensions = b"".join(
        (
            _extension(EXT_SUPPORTED_VERSIONS, TLS13_VERSION),
            _extension(
                EXT_KEY_SHARE,
                _u16(HYBRID_GROUP) + _u16(len(exchange)) + exchange,
            ),
        )
    )
    body = b"".join(
        (
            TLS_LEGACY_VERSION,
            _deterministic_bytes(b"server-random", 32),
            bytes([len(session_id)]),
            session_id,
            TLS13_CIPHER,
            b"\x00",
            _u16(len(extensions)),
            extensions,
        )
    )
    message = _handshake(HS_SERVER_HELLO, body)
    if len(message) != OBSERVED_SERVER_HELLO_LEN:
        raise AssertionError(f"ServerHello geometry drifted: {len(message)}")
    return message


def parse_fixed_server_hello(
    message: bytes, expected_session_id: bytes
) -> ParsedServerHello:
    body = _parse_exact_message(message, HS_SERVER_HELLO)
    if len(message) != OBSERVED_SERVER_HELLO_LEN:
        raise ValueError("unexpected ServerHello geometry")
    offset = 0
    if body[offset : offset + 2] != TLS_LEGACY_VERSION:
        raise ValueError("bad ServerHello legacy version")
    offset += 2 + 32
    session_len = body[offset]
    offset += 1
    session_id = body[offset : offset + session_len]
    offset += session_len
    if session_id != expected_session_id:
        raise ValueError("ServerHello session id mismatch")
    if body[offset : offset + 2] != TLS13_CIPHER:
        raise ValueError("ServerHello selected a different cipher")
    offset += 2
    if body[offset : offset + 1] != b"\x00":
        raise ValueError("ServerHello selected legacy compression")
    offset += 1
    extension_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if offset + extension_len != len(body):
        raise ValueError("ServerHello extension length mismatch")
    extensions = _parse_extensions(body[offset:])
    if set(extensions) != {EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE}:
        raise ValueError("unexpected ServerHello extensions")
    if extensions[EXT_SUPPORTED_VERSIONS] != TLS13_VERSION:
        raise ValueError("ServerHello did not select TLS 1.3")
    key_share = extensions[EXT_KEY_SHARE]
    if len(key_share) < 4:
        raise ValueError("short ServerHello key_share")
    if int.from_bytes(key_share[:2], "big") != HYBRID_GROUP:
        raise ValueError("ServerHello selected a different group")
    exchange_len = int.from_bytes(key_share[2:4], "big")
    exchange = key_share[4:]
    if exchange_len != len(exchange):
        raise ValueError("ServerHello key_share length mismatch")
    if len(exchange) != MLKEM_CIPHERTEXT_LEN + X25519_LEN:
        raise ValueError("unexpected hybrid ServerHello share size")
    server_public = exchange[-X25519_LEN:]
    if not any(server_public):
        raise ValueError("all-zero X25519 server share")
    return ParsedServerHello(exchange[:MLKEM_CIPHERTEXT_LEN], server_public)


def _derive_handshake(
    mlkem_secret: bytes, server_x25519_public: bytes, hello_transcript: bytes
) -> dict[str, bytes]:
    if len(mlkem_secret) != HASH_LEN or len(server_x25519_public) != X25519_LEN:
        raise ValueError("bad hybrid shared-secret component")
    shared_secret = mlkem_secret + server_x25519_public
    zeros = b"\x00" * HASH_LEN
    empty_hash = hashlib.sha256(b"").digest()
    early = BASE.hkdf_extract(zeros, zeros)
    derived = BASE.hkdf_expand_label(early, b"derived", empty_hash, HASH_LEN)
    handshake = BASE.hkdf_extract(derived, shared_secret)
    client_traffic = BASE.derive_secret(
        handshake, b"c hs traffic", hello_transcript
    )
    server_traffic = BASE.derive_secret(
        handshake, b"s hs traffic", hello_transcript
    )
    return {
        "handshake_secret": handshake,
        "client_key": BASE.hkdf_expand_label(client_traffic, b"key", b"", 32),
        "client_iv": BASE.hkdf_expand_label(client_traffic, b"iv", b"", 12),
        "client_finished": BASE.hkdf_expand_label(
            client_traffic, b"finished", b"", HASH_LEN
        ),
        "server_key": BASE.hkdf_expand_label(server_traffic, b"key", b"", 32),
        "server_iv": BASE.hkdf_expand_label(server_traffic, b"iv", b"", 12),
        "server_finished": BASE.hkdf_expand_label(
            server_traffic, b"finished", b"", HASH_LEN
        ),
    }


def _derive_application(
    handshake_secret: bytes, through_server_finished: bytes
) -> dict[str, bytes]:
    empty_hash = hashlib.sha256(b"").digest()
    derived = BASE.hkdf_expand_label(
        handshake_secret, b"derived", empty_hash, HASH_LEN
    )
    master = BASE.hkdf_extract(derived, b"\x00" * HASH_LEN)
    client_traffic = BASE.derive_secret(
        master, b"c ap traffic", through_server_finished
    )
    server_traffic = BASE.derive_secret(
        master, b"s ap traffic", through_server_finished
    )
    return {
        "master_secret": master,
        "client_key": BASE.hkdf_expand_label(client_traffic, b"key", b"", 32),
        "client_iv": BASE.hkdf_expand_label(client_traffic, b"iv", b"", 12),
        "server_key": BASE.hkdf_expand_label(server_traffic, b"key", b"", 32),
        "server_iv": BASE.hkdf_expand_label(server_traffic, b"iv", b"", 12),
    }


def _strict_ecdsa_der(signature: bytes) -> bool:
    """Check strict DER encoding and the mathematical P-256 scalar bounds."""

    if not MIN_ECDSA_DER_LEN <= len(signature) <= MAX_ECDSA_DER_LEN:
        return False
    if signature[0] != 0x30:
        return False
    if signature[1] != len(signature) - 2:
        return False
    offset = 2
    values: list[int] = []
    for _ in range(2):
        if offset + 2 > len(signature) or signature[offset] != 0x02:
            return False
        length = signature[offset + 1]
        offset += 2
        if not 1 <= length <= 33 or offset + length > len(signature):
            return False
        encoded = signature[offset : offset + length]
        offset += length
        if encoded[0] & 0x80:
            return False
        if length > 1 and encoded[0] == 0 and not (encoded[1] & 0x80):
            return False
        value = int.from_bytes(encoded, "big")
        if not 1 <= value < BASE.P256_N:
            return False
        values.append(value)
    return offset == len(signature) and len(values) == 2


def _fixture_ecdsa_signature(target_len: int = 72) -> bytes:
    if not MIN_ECDSA_DER_LEN <= target_len <= MAX_ECDSA_DER_LEN:
        raise ValueError("P-256 ECDSA DER fixture must be 8..72 bytes")

    # DER length is 6 + the two INTEGER content lengths.  Exercise every
    # mathematically possible strict encoding, including rare short scalars
    # and 33-byte positive INTEGERs with a required leading zero.
    integer_total = target_len - 6
    r_len = min(33, integer_total - 1)
    s_len = integer_total - r_len

    def integer_content(length: int, label: bytes) -> bytes:
        if length == 33:
            return b"\x00\x80" + (b"\x00" * 31)
        material = _deterministic_bytes(label, length)
        return bytes([(material[0] & 0x7F) or 1]) + material[1:]

    r = integer_content(r_len, b"fixture-r")
    s = integer_content(s_len, b"fixture-s")
    r_encoded = b"\x02" + bytes([len(r)]) + r
    s_encoded = b"\x02" + bytes([len(s)]) + s
    content = r_encoded + s_encoded
    signature = b"\x30" + bytes([len(content)]) + content
    if len(signature) != target_len or not _strict_ecdsa_der(signature):
        raise AssertionError("fixture ECDSA signature is not strict DER")
    return signature


def _profile_digest() -> bytes:
    return hashlib.sha256(
        b"|".join(
            (
                HOST,
                APPLICATION_PROTOCOL,
                TLS13_CIPHER,
                TLS13_VERSION,
                _u16(HYBRID_GROUP),
                ECDSA_SECP256R1_SHA256,
                _u16(BROTLI_CERTIFICATE_COMPRESSION),
                PROFILE.x25519_client_share,
            )
        )
    ).digest()


def build_integrated_fixture(signature_len: int = 72) -> IntegratedFixture:
    mlkem_public = _deterministic_bytes(b"mlkem-public", MLKEM_PUBLIC_LEN)
    mlkem_ciphertext = _deterministic_bytes(
        b"mlkem-ciphertext", MLKEM_CIPHERTEXT_LEN
    )
    server_public = _deterministic_bytes(b"server-x25519-public", X25519_LEN)
    candidate = _deterministic_bytes(b"candidate-mlkem-secret", HASH_LEN)
    client_hello = build_fixed_client_hello(mlkem_public)
    parsed_client = parse_fixed_client_hello(client_hello)
    server_hello = build_fixed_server_hello(
        parsed_client.session_id, mlkem_ciphertext, server_public
    )
    parse_fixed_server_hello(server_hello, parsed_client.session_id)
    hello_transcript = client_hello + server_hello
    handshake = _derive_handshake(candidate, server_public, hello_transcript)

    encrypted_extensions = _handshake(
        HS_ENCRYPTED_EXTENSIONS, b"\x00\x04\x00\x10\x00\x00"
    )
    compressed_certificate = _handshake(
        HS_COMPRESSED_CERTIFICATE,
        _u16(BROTLI_CERTIFICATE_COMPRESSION)
        + _u24(COMPRESSED_CERTIFICATE_BODY_LEN)
        + _u24(COMPRESSED_CERTIFICATE_DATA_LEN)
        + _deterministic_bytes(
            b"compressed-certificate", COMPRESSED_CERTIFICATE_DATA_LEN
        ),
    )
    signature = _fixture_ecdsa_signature(signature_len)
    certificate_verify = _handshake(
        HS_CERTIFICATE_VERIFY,
        ECDSA_SECP256R1_SHA256 + _u16(len(signature)) + signature,
    )
    before_finished = (
        hello_transcript
        + encrypted_extensions
        + compressed_certificate
        + certificate_verify
    )
    verify_data = hmac.new(
        handshake["server_finished"],
        hashlib.sha256(before_finished).digest(),
        hashlib.sha256,
    ).digest()
    server_finished = _handshake(HS_FINISHED, verify_data)
    messages = (
        encrypted_extensions,
        compressed_certificate,
        certificate_verify,
        server_finished,
    )
    if tuple(map(len, messages)) != (
        10,
        1799,
        signature_len + 8,
        36,
    ):
        raise AssertionError("protected-flight message geometry drifted")
    record = BASE.encrypted_record(
        handshake["server_key"],
        handshake["server_iv"],
        0,
        CONTENT_HANDSHAKE,
        b"".join(messages),
    )
    if len(record) != 1875 + signature_len:
        raise AssertionError("protected-flight record geometry drifted")
    return IntegratedFixture(
        client_hello=client_hello,
        server_hello=server_hello,
        mlkem_public=mlkem_public,
        mlkem_ciphertext=mlkem_ciphertext,
        server_x25519_public=server_public,
        candidate_mlkem_secret=candidate,
        server_flight_messages=messages,
        server_flight_record=record,
        certificate_verify_transcript_digest=hashlib.sha256(
            hello_transcript + encrypted_extensions + compressed_certificate
        ).digest(),
        server_finished_transcript_digest=hashlib.sha256(
            before_finished
        ).digest(),
        profile_digest=_profile_digest(),
    )


class _HeadResponseDrain:
    def __init__(self) -> None:
        self._buffer = bytearray()

    @property
    def empty(self) -> bool:
        return not self._buffer

    def clear(self) -> None:
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._buffer.clear()

    def feed(self, content: bytes) -> bool:
        if len(self._buffer) + len(content) > MAX_HEAD_RESPONSE_HEADER:
            raise ValueError("HEAD response headers exceed fixed bound")
        self._buffer.extend(content)
        marker = self._buffer.find(b"\r\n\r\n")
        if marker < 0:
            return False
        end = marker + 4
        if end != len(self._buffer):
            raise ValueError("HEAD response carried a body or overlapping response")
        header = bytes(self._buffer[:marker])
        lines = header.split(b"\r\n")
        if not lines or not re.fullmatch(rb"HTTP/1\.1 [0-9]{3} [\x20-\x7e]*", lines[0]):
            raise ValueError("malformed HEAD response status line")
        status = int(lines[0][9:12])
        if 100 <= status < 200:
            raise ValueError("interim/upgrade response is forbidden")
        if 300 <= status < 400:
            raise ValueError("redirect response is forbidden")
        names: set[bytes] = set()
        singleton_names = {
            b"connection",
            b"content-length",
            b"transfer-encoding",
            b"upgrade",
            b"location",
        }
        for line in lines[1:]:
            if not line or b":" not in line:
                raise ValueError("malformed HEAD response header")
            name, value = line.split(b":", 1)
            name = name.strip().lower()
            value = value.strip()
            if not re.fullmatch(rb"[!#$%&'*+\-.^_`|~0-9a-z]+", name):
                raise ValueError("invalid HEAD response header name")
            if name in names and name in singleton_names:
                raise ValueError("duplicate HEAD response control header")
            names.add(name)
            if b"\r" in value or b"\n" in value:
                raise ValueError("embedded HEAD response newline")
            if name in {b"transfer-encoding", b"upgrade", b"location"}:
                raise ValueError("forbidden HEAD response semantics")
            if name == b"connection" and value.lower() == b"close":
                raise ValueError("HEAD response does not preserve the connection")
        self.clear()
        return True


def build_new_session_ticket(
    *,
    identity: bytes | None = None,
    nonce: bytes = b"\x00",
    lifetime: int = 64800,
    age_add: int = 0x10203040,
    advertise_early_data: bool = True,
) -> bytes:
    if identity is None:
        identity = _deterministic_bytes(b"ticket-identity", 192)
    if not 1 <= len(identity) <= MAX_TICKET_IDENTITY:
        raise ValueError("ticket identity outside fixed bound")
    if not 1 <= len(nonce) <= MAX_TICKET_NONCE:
        raise ValueError("ticket nonce outside fixed bound")
    extensions = b""
    if advertise_early_data:
        extensions = _extension(EXT_EARLY_DATA, (14336).to_bytes(4, "big"))
    body = b"".join(
        (
            lifetime.to_bytes(4, "big"),
            age_add.to_bytes(4, "big"),
            bytes([len(nonce)]),
            nonce,
            _u16(len(identity)),
            identity,
            _u16(len(extensions)),
            extensions,
        )
    )
    return _handshake(HS_NEW_SESSION_TICKET, body)


def _parse_new_session_ticket(message: bytes) -> tuple[int, int, bytes, bytes]:
    body = _parse_exact_message(message, HS_NEW_SESSION_TICKET)
    if len(body) < 13:
        raise ValueError("short NewSessionTicket")
    lifetime = int.from_bytes(body[:4], "big")
    age_add = int.from_bytes(body[4:8], "big")
    if not 1 <= lifetime <= MAX_TICKET_LIFETIME:
        raise ValueError("NewSessionTicket lifetime outside fixed bound")
    nonce_len = body[8]
    offset = 9
    if not 1 <= nonce_len <= MAX_TICKET_NONCE:
        raise ValueError("NewSessionTicket nonce outside fixed bound")
    nonce = body[offset : offset + nonce_len]
    offset += nonce_len
    if len(nonce) != nonce_len or offset + 2 > len(body):
        raise ValueError("truncated NewSessionTicket nonce")
    ticket_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if not 1 <= ticket_len <= MAX_TICKET_IDENTITY:
        raise ValueError("NewSessionTicket identity outside fixed bound")
    identity = body[offset : offset + ticket_len]
    offset += ticket_len
    if len(identity) != ticket_len or offset + 2 > len(body):
        raise ValueError("truncated NewSessionTicket identity")
    extension_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if offset + extension_len != len(body):
        raise ValueError("NewSessionTicket extension length mismatch")
    extensions = _parse_extensions(body[offset:])
    if set(extensions) - {EXT_EARLY_DATA}:
        raise ValueError("unexpected NewSessionTicket extension")
    if EXT_EARLY_DATA in extensions and len(extensions[EXT_EARLY_DATA]) != 4:
        raise ValueError("malformed early_data ticket extension")
    return lifetime, age_add, nonce, identity


class CredentialVault:
    """Separate credential authority; the TLS machine never owns this object."""

    def __init__(self, api_key: bytes) -> None:
        if not api_key or b"\r" in api_key or b"\n" in api_key:
            raise ValueError("invalid API key fixture")
        self._api_key = bytes(api_key)

    def reveal(self, machine: "IntegratedClient") -> bytes:
        if machine.phase is not Phase.COMMITTED_LIVE:
            raise CredentialLocked("credential remains unavailable before live commit")
        return self._api_key


class IntegratedClient:
    """Fail-closed model of the proposed provisional connection."""

    def __init__(self, client_hello: bytes, candidate_mlkem_secret: bytes) -> None:
        parsed = parse_fixed_client_hello(client_hello)
        if len(candidate_mlkem_secret) != HASH_LEN:
            raise ValueError("bad provisional ML-KEM candidate length")
        self.phase = Phase.NEW
        self._client_hello = client_hello
        self._client = parsed
        self._candidate = bytearray(candidate_mlkem_secret)
        self._server_hello: bytes | None = None
        self._server: ParsedServerHello | None = None
        self._handshake: dict[str, bytes] | None = None
        self._application: dict[str, bytes] | None = None
        self._through_server_finished: bytes | None = None
        self._client_finished: bytes | None = None
        self._cv_transcript_digest: bytes | None = None
        self._server_finished_transcript_digest: bytes | None = None
        self._staged_cv_digest: bytes | None = None
        self._profile_digest = _profile_digest()
        self._client_application_sequence = 0
        self._server_application_sequence = 0
        self._probe_outstanding = False
        self._head_drain = _HeadResponseDrain()
        self._tentative_ticket: TentativeTicket | None = None
        self._promoted_ticket: PromotedTicket | None = None
        self._kem_proof_submitted = False
        self._kem_proof_ok = False
        self._identity_proof_submitted = False
        self._identity_proof_ok = False
        self._leaf_spki_digest: bytes | None = None
        self._socket_alive = True
        self.public_trace: list[tuple[str, Any]] = []

    @property
    def probe_outstanding(self) -> bool:
        return self._probe_outstanding

    @property
    def server_application_sequence(self) -> int:
        return self._server_application_sequence

    @property
    def client_application_sequence(self) -> int:
        return self._client_application_sequence

    @property
    def tentative_ticket_available(self) -> bool:
        return self._tentative_ticket is not None and self.phase is Phase.PROVISIONAL

    @property
    def promoted_ticket(self) -> PromotedTicket | None:
        if self.phase not in {Phase.COMMITTED_LIVE, Phase.COMMITTED_TICKET_ONLY}:
            return None
        return self._promoted_ticket

    @property
    def certificate_verify_transcript_digest(self) -> bytes:
        if self._cv_transcript_digest is None:
            raise RuntimeError("server flight has not been verified")
        return self._cv_transcript_digest

    @property
    def staged_certificate_verify_digest(self) -> bytes:
        if self._staged_cv_digest is None:
            raise RuntimeError("server flight has not been verified")
        return self._staged_cv_digest

    def _zeroize_tentative(self, *, retain_application: bool = False) -> None:
        if self._candidate is not None:
            for index in range(len(self._candidate)):
                self._candidate[index] = 0
        self._candidate = None  # type: ignore[assignment]
        self._handshake = None
        self._through_server_finished = None
        self._client_finished = None
        self._kem_proof_ok = False
        self._identity_proof_ok = False
        self._head_drain.clear()
        if not retain_application:
            self._application = None

    def _abort(self) -> None:
        if self.phase is not Phase.CLOSED:
            self.public_trace.append((FIXED_FAILURE_ACTION,))
        self.phase = Phase.CLOSED
        self._socket_alive = False
        self._probe_outstanding = False
        self._tentative_ticket = None
        self._promoted_ticket = None
        self._zeroize_tentative()
        raise ProtocolAbort()

    def accept_server_hello(self, server_hello: bytes) -> None:
        if self.phase is not Phase.NEW:
            self._abort()
        try:
            parsed = parse_fixed_server_hello(
                server_hello, self._client.session_id
            )
        except (ValueError, IndexError):
            self._abort()
        self._server_hello = server_hello
        self._server = parsed
        hello_transcript = self._client_hello + server_hello
        self._handshake = _derive_handshake(
            bytes(self._candidate), parsed.x25519_public, hello_transcript
        )
        self.phase = Phase.HANDSHAKE_KEYS

    def receive_server_flight(self, record: bytes) -> None:
        if self.phase is not Phase.HANDSHAKE_KEYS or self._handshake is None:
            self._abort()
        try:
            if not (
                MIN_SERVER_FLIGHT_RECORD_LEN
                <= len(record)
                <= MAX_SERVER_FLIGHT_RECORD_LEN
            ):
                raise ValueError("unexpected protected-flight geometry")
            inner_type, content = BASE.decrypt_record(
                self._handshake["server_key"],
                self._handshake["server_iv"],
                0,
                record,
            )
            # BASE.decrypt_record performs the complete AEAD tag comparison
            # before returning any plaintext to this parser.
            if inner_type != CONTENT_HANDSHAKE:
                raise ValueError("server flight used the wrong inner type")
            messages = _parse_handshake_messages(content)
            message_lengths = tuple(map(len, messages))
            if (
                message_lengths[0] != 10
                or message_lengths[1] != 1799
                or not (
                    MIN_CERTIFICATE_VERIFY_LEN
                    <= message_lengths[2]
                    <= MAX_CERTIFICATE_VERIFY_LEN
                )
                or message_lengths[3] != 36
                or len(record) != sum(message_lengths) + 22
            ):
                raise ValueError("server flight geometry changed")
            if tuple(message[0] for message in messages) != (
                HS_ENCRYPTED_EXTENSIONS,
                HS_COMPRESSED_CERTIFICATE,
                HS_CERTIFICATE_VERIFY,
                HS_FINISHED,
            ):
                raise ValueError("server flight message order changed")
            compressed_body = _parse_exact_message(
                messages[1], HS_COMPRESSED_CERTIFICATE
            )
            compressed_len = int.from_bytes(compressed_body[5:8], "big")
            if (
                int.from_bytes(compressed_body[:2], "big")
                != BROTLI_CERTIFICATE_COMPRESSION
                or int.from_bytes(compressed_body[2:5], "big")
                != COMPRESSED_CERTIFICATE_BODY_LEN
                or compressed_len != COMPRESSED_CERTIFICATE_DATA_LEN
                or len(compressed_body[8:]) != compressed_len
            ):
                raise ValueError("compressed certificate profile changed")
            cv_body = _parse_exact_message(messages[2], HS_CERTIFICATE_VERIFY)
            if cv_body[:2] != ECDSA_SECP256R1_SHA256:
                raise ValueError("CertificateVerify scheme changed")
            signature_len = int.from_bytes(cv_body[2:4], "big")
            signature = cv_body[4:]
            if signature_len != len(signature) or not _strict_ecdsa_der(signature):
                raise ValueError("CertificateVerify signature is not strict DER")
            before_finished = (
                self._client_hello
                + self._server_hello
                + messages[0]
                + messages[1]
                + messages[2]
            )
            finished_body = _parse_exact_message(messages[3], HS_FINISHED)
            expected = hmac.new(
                self._handshake["server_finished"],
                hashlib.sha256(before_finished).digest(),
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(finished_body, expected):
                raise ValueError("server Finished mismatch")
        except (ValueError, IndexError, BASE.TLS13Error):
            self._abort()

        self._cv_transcript_digest = hashlib.sha256(
            self._client_hello
            + self._server_hello
            + messages[0]
            + messages[1]
        ).digest()
        self._server_finished_transcript_digest = hashlib.sha256(
            before_finished
        ).digest()
        self._staged_cv_digest = hashlib.sha256(messages[2]).digest()
        self._through_server_finished = before_finished + messages[3]
        self.phase = Phase.SERVER_FINISHED_VERIFIED

    def send_client_finished(self) -> bytes:
        if (
            self.phase is not Phase.SERVER_FINISHED_VERIFIED
            or self._handshake is None
            or self._through_server_finished is None
        ):
            self._abort()
        verify_data = hmac.new(
            self._handshake["client_finished"],
            hashlib.sha256(self._through_server_finished).digest(),
            hashlib.sha256,
        ).digest()
        message = _handshake(HS_FINISHED, verify_data)
        record = BASE.encrypted_record(
            self._handshake["client_key"],
            self._handshake["client_iv"],
            0,
            CONTENT_HANDSHAKE,
            message,
        )
        if len(record) != OBSERVED_CLIENT_FINISHED_RECORD_LEN:
            raise AssertionError("client Finished geometry drifted")
        self._application = _derive_application(
            self._handshake["handshake_secret"],
            self._through_server_finished,
        )
        self._client_finished = message
        self.phase = Phase.PROVISIONAL
        self.public_trace.append(
            ("send_client_finished", hashlib.sha256(record).digest())
        )
        return record

    def send_head_probe(self) -> bytes:
        if (
            self.phase is not Phase.PROVISIONAL
            or not self._socket_alive
            or self._probe_outstanding
            or self._application is None
        ):
            self._abort()
        forbidden = (
            b"authorization:",
            b"cookie:",
            b"bearer ",
            b"content-length:",
            b"transfer-encoding:",
        )
        lowered = HEAD_REQUEST.lower()
        if any(value in lowered for value in forbidden):
            raise AssertionError("compiled HEAD literal gained credential/body state")
        record = BASE.encrypted_record(
            self._application["client_key"],
            self._application["client_iv"],
            self._client_application_sequence,
            CONTENT_APPLICATION_DATA,
            HEAD_REQUEST,
        )
        self._client_application_sequence += 1
        self._probe_outstanding = True
        self.public_trace.append(("send_head", HEAD_REQUEST))
        return record

    def _capture_or_drain_ticket(self, message: bytes) -> bool:
        if (
            self._application is None
            or self._through_server_finished is None
            or self._client_finished is None
        ):
            raise ValueError("ticket arrived before Finished state")
        lifetime, age_add, nonce, identity = _parse_new_session_ticket(message)
        if self._tentative_ticket is not None:
            # TLS permits multiple NSTs.  Keep exactly one tentative ticket,
            # but structurally validate and discard later tickets instead of
            # treating a standards-permitted message as a key-epoch change.
            return False
        full_transcript = self._through_server_finished + self._client_finished
        resumption_master = BASE.derive_secret(
            self._application["master_secret"], b"res master", full_transcript
        )
        psk = BASE.hkdf_expand_label(
            resumption_master, b"resumption", nonce, HASH_LEN
        )
        self._tentative_ticket = TentativeTicket(
            identity=identity,
            nonce=nonce,
            lifetime=lifetime,
            age_add=age_add,
            psk=psk,
            endpoint=HOST,
            profile_digest=self._profile_digest,
            original_transcript_digest=hashlib.sha256(
                full_transcript
            ).digest(),
        )
        return True

    def receive_provisional_record(self, record: bytes) -> None:
        if self.phase is not Phase.PROVISIONAL or self._application is None:
            self._abort()
        try:
            inner_type, content = BASE.decrypt_record(
                self._application["server_key"],
                self._application["server_iv"],
                self._server_application_sequence,
                record,
            )
            self._server_application_sequence += 1
            if inner_type == CONTENT_APPLICATION_DATA:
                if not self._probe_outstanding:
                    raise ValueError("unsolicited application data")
                if self._head_drain.feed(content):
                    self._probe_outstanding = False
                    self.public_trace.append(("head_complete",))
                return
            if inner_type == CONTENT_HANDSHAKE:
                messages = _parse_handshake_messages(content)
                if not 1 <= len(messages) <= MAX_NST_MESSAGES_PER_RECORD:
                    raise ValueError("post-handshake message packing is forbidden")
                captured = False
                for message in messages:
                    if message[0] in {
                        HS_KEY_UPDATE,
                        HS_CERTIFICATE_REQUEST,
                        HS_CERTIFICATE,
                        HS_CERTIFICATE_VERIFY,
                    }:
                        raise ValueError("forbidden post-handshake transition")
                    if message[0] != HS_NEW_SESSION_TICKET:
                        raise ValueError("unexpected post-handshake message")
                    captured = self._capture_or_drain_ticket(message) or captured
                if captured:
                    self.public_trace.append(("tentative_ticket",))
                return
            if inner_type == CONTENT_ALERT:
                raise ValueError("alert terminates provisional connection")
            raise ValueError("unexpected provisional TLS inner type")
        except (ValueError, IndexError, BASE.TLS13Error):
            self._abort()

    def submit_kem_proof(
        self,
        *,
        public_key_digest: bytes,
        ciphertext_digest: bytes,
        ciphertext_equal: bool,
        selected_mlkem_secret: bytes,
    ) -> None:
        if self.phase is not Phase.PROVISIONAL or self._kem_proof_submitted:
            self._abort()
        self._kem_proof_submitted = True
        expected_public = hashlib.sha256(self._client.mlkem_public).digest()
        expected_ciphertext = hashlib.sha256(
            self._server.mlkem_ciphertext if self._server else b""
        ).digest()
        candidate = bytes(self._candidate)
        base_ok = bool(
            ciphertext_equal
            and hmac.compare_digest(public_key_digest, expected_public)
            and hmac.compare_digest(ciphertext_digest, expected_ciphertext)
            and len(selected_mlkem_secret) == HASH_LEN
            and hmac.compare_digest(selected_mlkem_secret, candidate)
        )
        rederived_ok = False
        if (
            base_ok
            and self._server is not None
            and self._server_hello is not None
            and self._through_server_finished is not None
            and self._handshake is not None
            and self._application is not None
        ):
            hello_transcript = self._client_hello + self._server_hello
            rederived_handshake = _derive_handshake(
                selected_mlkem_secret,
                self._server.x25519_public,
                hello_transcript,
            )
            rederived_application = _derive_application(
                rederived_handshake["handshake_secret"],
                self._through_server_finished,
            )
            handshake_fields = (
                "client_key",
                "client_iv",
                "client_finished",
                "server_key",
                "server_iv",
                "server_finished",
            )
            application_fields = (
                "client_key",
                "client_iv",
                "server_key",
                "server_iv",
            )
            rederived_ok = all(
                hmac.compare_digest(
                    rederived_handshake[field], self._handshake[field]
                )
                for field in handshake_fields
            ) and all(
                hmac.compare_digest(
                    rederived_application[field], self._application[field]
                )
                for field in application_fields
            )
        self._kem_proof_ok = base_ok and rederived_ok

    def submit_identity_proof(
        self,
        *,
        certificate_verify_transcript_digest: bytes,
        staged_certificate_verify_digest: bytes,
        leaf_policy_ok: bool,
        certificate_verify_ok: bool,
        time_policy_ok: bool,
        leaf_spki_digest: bytes,
    ) -> None:
        if self.phase is not Phase.PROVISIONAL or self._identity_proof_submitted:
            self._abort()
        self._identity_proof_submitted = True
        if len(leaf_spki_digest) != HASH_LEN:
            self._identity_proof_ok = False
            return
        self._identity_proof_ok = bool(
            self._cv_transcript_digest is not None
            and self._staged_cv_digest is not None
            and hmac.compare_digest(
                certificate_verify_transcript_digest,
                self._cv_transcript_digest,
            )
            and hmac.compare_digest(
                staged_certificate_verify_digest,
                self._staged_cv_digest,
            )
            and leaf_policy_ok
            and certificate_verify_ok
            and time_policy_ok
        )
        self._leaf_spki_digest = bytes(leaf_spki_digest)

    def peer_closed(self) -> None:
        if self.phase is not Phase.PROVISIONAL:
            self._abort()
        self._socket_alive = False
        self._probe_outstanding = False
        self._head_drain.clear()
        self.public_trace.append(("peer_close",))

    def finalize_proofs(self) -> Phase:
        if self.phase is not Phase.PROVISIONAL:
            self._abort()
        success = bool(
            self._kem_proof_submitted
            and self._kem_proof_ok
            and self._identity_proof_submitted
            and self._identity_proof_ok
            and not self._probe_outstanding
            and self._head_drain.empty
            and self._leaf_spki_digest is not None
        )
        if not success:
            self._abort()

        promoted: PromotedTicket | None = None
        if self._tentative_ticket is not None:
            ticket = self._tentative_ticket
            promoted = PromotedTicket(
                identity=ticket.identity,
                nonce=ticket.nonce,
                lifetime=ticket.lifetime,
                age_add=ticket.age_add,
                psk=ticket.psk,
                endpoint=ticket.endpoint,
                profile_digest=ticket.profile_digest,
                original_transcript_digest=ticket.original_transcript_digest,
                leaf_spki_digest=self._leaf_spki_digest,
            )

        self._promoted_ticket = promoted
        self._tentative_ticket = None
        if self._socket_alive:
            self.phase = Phase.COMMITTED_LIVE
            self.public_trace.append(("commit_live",))
            self._zeroize_tentative(retain_application=True)
            if self._application is not None:
                self._application = {
                    field: self._application[field]
                    for field in (
                        "client_key",
                        "client_iv",
                        "server_key",
                        "server_iv",
                    )
                }
            return self.phase
        if promoted is not None:
            self.phase = Phase.COMMITTED_TICKET_ONLY
            self.public_trace.append(("commit_ticket_only",))
            self._zeroize_tentative()
            return self.phase
        self._abort()
        raise AssertionError("unreachable")

    def build_real_request(
        self, vault: CredentialVault, body: bytes = b'{"model":"gpt-5"}'
    ) -> bytes:
        if self.phase is not Phase.COMMITTED_LIVE or self._application is None:
            raise CredentialLocked("real request is forbidden before live commit")
        key = vault.reveal(self)
        request = b"".join(
            (
                b"POST /v1/responses HTTP/1.1\r\n",
                b"Host: api.openai.com\r\n",
                b"Authorization: Bearer ",
                key,
                b"\r\nContent-Type: application/json\r\nContent-Length: ",
                str(len(body)).encode("ascii"),
                b"\r\n\r\n",
                body,
            )
        )
        record = BASE.encrypted_record(
            self._application["client_key"],
            self._application["client_iv"],
            self._client_application_sequence,
            CONTENT_APPLICATION_DATA,
            request,
        )
        self._client_application_sequence += 1
        self.public_trace.append(("send_real", hashlib.sha256(record).digest()))
        return record


def encrypt_server_application_record(
    fixture: IntegratedFixture,
    sequence_number: int,
    inner_type: int,
    content: bytes,
) -> bytes:
    hello_transcript = fixture.client_hello + fixture.server_hello
    handshake = _derive_handshake(
        fixture.candidate_mlkem_secret,
        fixture.server_x25519_public,
        hello_transcript,
    )
    through_finished = (
        hello_transcript + b"".join(fixture.server_flight_messages)
    )
    application = _derive_application(
        handshake["handshake_secret"], through_finished
    )
    return BASE.encrypted_record(
        application["server_key"],
        application["server_iv"],
        sequence_number,
        inner_type,
        content,
    )


def decrypt_client_application_record(
    fixture: IntegratedFixture, sequence_number: int, record: bytes
) -> tuple[int, bytes]:
    hello_transcript = fixture.client_hello + fixture.server_hello
    handshake = _derive_handshake(
        fixture.candidate_mlkem_secret,
        fixture.server_x25519_public,
        hello_transcript,
    )
    through_finished = (
        hello_transcript + b"".join(fixture.server_flight_messages)
    )
    application = _derive_application(
        handshake["handshake_secret"], through_finished
    )
    return BASE.decrypt_record(
        application["client_key"],
        application["client_iv"],
        sequence_number,
        record,
    )


def valid_kem_proof(machine: IntegratedClient, fixture: IntegratedFixture) -> None:
    machine.submit_kem_proof(
        public_key_digest=hashlib.sha256(fixture.mlkem_public).digest(),
        ciphertext_digest=hashlib.sha256(fixture.mlkem_ciphertext).digest(),
        ciphertext_equal=True,
        selected_mlkem_secret=fixture.candidate_mlkem_secret,
    )


def valid_identity_proof(
    machine: IntegratedClient, fixture: IntegratedFixture
) -> bytes:
    leaf_spki_digest = hashlib.sha256(
        b"immutable WE1-authorized fixture leaf SPKI"
    ).digest()
    machine.submit_identity_proof(
        certificate_verify_transcript_digest=(
            fixture.certificate_verify_transcript_digest
        ),
        staged_certificate_verify_digest=hashlib.sha256(
            fixture.server_flight_messages[2]
        ).digest(),
        leaf_policy_ok=True,
        certificate_verify_ok=True,
        time_policy_ok=True,
        leaf_spki_digest=leaf_spki_digest,
    )
    return leaf_spki_digest


def object_contains_bytes(root: object, needle: bytes) -> bool:
    """Recursively check that a secret is absent from an object graph."""

    if not needle:
        raise ValueError("needle must not be empty")
    seen: set[int] = set()

    def visit(value: object) -> bool:
        value_id = id(value)
        if value_id in seen:
            return False
        seen.add(value_id)
        if isinstance(value, bytes):
            return needle in value
        if isinstance(value, bytearray):
            return needle in bytes(value)
        if isinstance(value, str):
            try:
                return needle.decode("ascii") in value
            except UnicodeDecodeError:
                return False
        if isinstance(value, dict):
            return any(visit(key) or visit(item) for key, item in value.items())
        if isinstance(value, (list, tuple, set, frozenset)):
            return any(visit(item) for item in value)
        if hasattr(value, "__dict__"):
            return visit(vars(value))
        return False

    return visit(root)


def deterministic_summary() -> dict[str, object]:
    fixture = build_integrated_fixture()
    return {
        "kind": "deterministic_offline_security_gate",
        "uses_live_provider_as_acceptance_input": False,
        "execution_provenance": {
            "host_python_reference_model": True,
            "seed_8088_target_code_executed": False,
            "claim_scope": (
                "state-machine and hostile-input oracle only; not a target "
                "runtime implementation or cycle/RAM measurement"
            ),
        },
        "profile": {
            "wire_group": "X25519MLKEM768",
            "x25519_client_share": "u=9",
            "effective_key_exchange": "ML-KEM-only research profile",
            "cipher": "TLS_CHACHA20_POLY1305_SHA256",
            "signature": "ecdsa_secp256r1_sha256",
            "certificate_compression": "brotli",
        },
        "geometry": {
            "client_hello": len(fixture.client_hello),
            "server_hello": len(fixture.server_hello),
            "server_flight_record_fixture": len(fixture.server_flight_record),
            "server_flight_record_accepted_range": [
                MIN_SERVER_FLIGHT_RECORD_LEN,
                MAX_SERVER_FLIGHT_RECORD_LEN,
            ],
            "server_messages_fixture": list(
                map(len, fixture.server_flight_messages)
            ),
            "certificate_verify_accepted_range": [
                MIN_CERTIFICATE_VERIFY_LEN,
                MAX_CERTIFICATE_VERIFY_LEN,
            ],
            "client_finished": OBSERVED_CLIENT_FINISHED_RECORD_LEN,
        },
        "provisional_request_sha256": hashlib.sha256(HEAD_REQUEST).hexdigest(),
        "failure_action": FIXED_FAILURE_ACTION,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(deterministic_summary(), indent=2))
