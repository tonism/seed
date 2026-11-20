#!/usr/bin/env python3
"""Validate Seed's exact 286 TLS 1.3 route topology from a classic pcap.

The 286 route uses two X25519MLKEM768 connections.  The acquisition connection
offers ``psk_dhe_ke`` without a PSK, sends client Finished plus one encrypted
credential-free HEAD, receives protected post-handshake traffic, and closes.
After offline authentication, the final connection offers one last-position
``pre_shared_key`` with fresh hybrid key material, no ``early_data``, and
requires the server to select PSK identity zero.

This analyzer validates only observable wire facts: exact hello profiles,
independent public shares/session IDs, all relevant same-endpoint TCP
attempts, the 58-byte client-Finished record position, protected-record
ordering, both 15-second ServerHello-to-client-Finished intervals, clean
acquisition close before resumption, completed encrypted dialogue, connection
reuse, and the bounded one-reconnect shape.

Certificate, CertificateVerify, Finished, HEAD, NewSessionTicket, and
application plaintext are encrypted.  They require target-side nonsecret
evidence in addition to this report; ciphertext shape is never presented as a
standards or semantic proof.  The script performs no network I/O and supports
the classic pcap emitted by the 86Box harness.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


DEADLINE_SECONDS = 15.0
SNI = b"api.openai.com"
TLS10_RECORD_VERSION = b"\x03\x01"
TLS12_LEGACY_VERSION = b"\x03\x03"
TLS13_VERSION = b"\x03\x04"
TLS13_CIPHER = b"\x13\x03"
HYBRID_GROUP_ID = 0x11EC
CLIENT_MLKEM_BYTES = 1184
CLIENT_X25519_BYTES = 32
CLIENT_KEY_EXCHANGE_BYTES = CLIENT_MLKEM_BYTES + CLIENT_X25519_BYTES
SERVER_MLKEM_BYTES = 1088
SERVER_X25519_BYTES = 32
SERVER_KEY_EXCHANGE_BYTES = SERVER_MLKEM_BYTES + SERVER_X25519_BYTES
ACQUISITION_CLIENT_HELLO_HANDSHAKE_BYTES = 1381
ACQUISITION_CLIENT_HELLO_RECORD_BYTES = 1386
RESUMPTION_CLIENT_HELLO_FIXED_HANDSHAKE_BYTES = 1428
SERVER_HELLO_HANDSHAKE_BYTES = 1210
SERVER_HELLO_RECORD_BYTES = 1215
RESUMPTION_SERVER_HELLO_HANDSHAKE_BYTES = 1216
RESUMPTION_SERVER_HELLO_RECORD_BYTES = 1221
CLIENT_FINISHED_RECORD_BYTES = 58
CLIENT_FINISHED_HEADER = bytes.fromhex("1703030035")
EXACT_CCS_RECORD = bytes.fromhex("140303000101")
MAX_TLS_CIPHERTEXT_BYTES = (1 << 14) + 256
ACQUISITION_CLIENT_EXTENSION_ORDER = (0, 43, 10, 13, 51, 28, 21, 45)
RESUMPTION_CLIENT_EXTENSION_ORDER = (
    *ACQUISITION_CLIENT_EXTENSION_ORDER,
    41,
)
FORBIDDEN_CLIENT_EXTENSIONS = frozenset((27, 42))
PSK_DHE_KE = b"\x01\x01"
MAX_TICKET_IDENTITY_BYTES = 192
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891"
    "c2a211167abb8c5e079e09e2c8a8339c"
)


def read_pcap(path: Path):
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("pcap is shorter than its global header")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError(
            f"not a classic pcap (magic {magic.hex()}); pcapng is unsupported"
        )
    nanoseconds = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    offset = 24
    scale = 1_000_000_000 if nanoseconds else 1_000_000
    while offset + 16 <= len(data):
        seconds, fraction, captured, original = struct.unpack_from(
            endian + "4I", data, offset
        )
        offset += 16
        if captured > original or offset + captured > len(data):
            raise ValueError("truncated or malformed pcap packet")
        packet = data[offset : offset + captured]
        offset += captured
        yield seconds + fraction / scale, linktype, packet
    if offset != len(data):
        raise ValueError("pcap has trailing partial packet metadata")


def ipv4_tcp(linktype: int, packet: bytes):
    if linktype == 1:  # Ethernet
        if len(packet) < 14:
            return None
        ethertype = struct.unpack_from(">H", packet, 12)[0]
        link_header = 14
        if ethertype == 0x8100:
            if len(packet) < 18:
                return None
            ethertype = struct.unpack_from(">H", packet, 16)[0]
            link_header = 18
        if ethertype != 0x0800:
            return None
        ip = packet[link_header:]
    elif linktype in (0, 108):  # BSD NULL / LOOP
        if len(packet) < 4:
            return None
        ip = packet[4:]
    elif linktype == 101:  # raw IPv4
        ip = packet
    elif linktype == 113:  # Linux cooked v1
        if len(packet) < 16 or struct.unpack_from(">H", packet, 14)[0] != 0x0800:
            return None
        ip = packet[16:]
    else:
        raise ValueError(f"unsupported pcap link type {linktype}")

    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack_from(">H", ip, 2)[0]
    fragment = struct.unpack_from(">H", ip, 6)[0]
    if ihl < 20 or total < ihl or len(ip) < total or fragment & 0x3FFF:
        return None
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        return None
    sport, dport, sequence = struct.unpack_from(">HHI", tcp, 0)
    data_offset = (tcp[12] >> 4) * 4
    if data_offset < 20 or data_offset > len(tcp):
        return None
    source = ".".join(str(byte) for byte in ip[12:16])
    destination = ".".join(str(byte) for byte in ip[16:20])
    return (
        source,
        sport,
        destination,
        dport,
        sequence,
        tcp[13],
        tcp[data_offset:],
    )


@dataclass
class TimedStream:
    isn: int | None = None
    syn_seen: bool = False
    values: dict[int, int] = field(default_factory=dict)
    times: dict[int, float] = field(default_factory=dict)
    conflict: bool = False
    retransmit_payloads: int = 0

    def add(self, sequence: int, flags: int, payload: bytes, timestamp: float) -> None:
        if flags & 0x02 and self.isn is None:
            self.isn = sequence
            self.syn_seen = True
        if not payload:
            return
        if self.isn is None:
            self.isn = sequence
            self.syn_seen = False
        origin = self.isn + (1 if self.syn_seen else 0)
        relative = (sequence - origin) & 0xFFFFFFFF
        if relative > 0x7FFFFFFF:
            relative -= 0x100000000
        if relative < 0:
            return
        repeated = True
        for index, byte in enumerate(payload):
            position = relative + index
            if position not in self.values:
                repeated = False
                self.values[position] = byte
                self.times[position] = timestamp
            elif self.values[position] != byte:
                self.conflict = True
            elif timestamp < self.times[position]:
                self.times[position] = timestamp
        if repeated:
            self.retransmit_payloads += 1

    def contiguous(self) -> tuple[bytes, list[float]]:
        output = bytearray()
        timestamps: list[float] = []
        position = 0
        while position in self.values:
            output.append(self.values[position])
            timestamps.append(self.times[position])
            position += 1
        return bytes(output), timestamps


@dataclass
class Flow:
    client: tuple[str, int]
    server: tuple[str, int]
    first_timestamp: float
    client_stream: TimedStream = field(default_factory=TimedStream)
    server_stream: TimedStream = field(default_factory=TimedStream)
    client_syn_timestamp: float | None = None
    client_close_timestamp: float | None = None
    server_close_timestamp: float | None = None
    client_fin_timestamp: float | None = None
    server_fin_timestamp: float | None = None
    client_reset_timestamp: float | None = None
    server_reset_timestamp: float | None = None

    @property
    def close_timestamp(self) -> float | None:
        candidates = [
            timestamp
            for timestamp in (
                self.client_close_timestamp,
                self.server_close_timestamp,
            )
            if timestamp is not None
        ]
        return min(candidates) if candidates else None


def collect_flows(path: Path) -> list[Flow]:
    flows: dict[tuple[str, int, str, int], Flow] = {}
    observed: list[Flow] = []
    for timestamp, linktype, packet in read_pcap(path):
        parsed = ipv4_tcp(linktype, packet)
        if parsed is None:
            continue
        source, sport, destination, dport, sequence, flags, payload = parsed
        if dport == 443:
            key = (source, sport, destination, dport)
            from_client = True
        elif sport == 443:
            key = (destination, dport, source, sport)
            from_client = False
        else:
            continue
        flow = flows.get(key)
        new_client_syn = from_client and bool(flags & 0x02)
        if (
            flow is None
            or (
                new_client_syn
                and flow.client_syn_timestamp is not None
                and (
                    flow.close_timestamp is not None
                    or flow.client_stream.isn != sequence
                )
            )
        ):
            flow = flows[key] = Flow(
                client=(key[0], key[1]),
                server=(key[2], key[3]),
                first_timestamp=timestamp,
            )
            observed.append(flow)
        flow.first_timestamp = min(flow.first_timestamp, timestamp)
        if from_client and flags & 0x02:
            flow.client_syn_timestamp = (
                timestamp
                if flow.client_syn_timestamp is None
                else min(flow.client_syn_timestamp, timestamp)
            )
        if flags & (0x01 | 0x04):
            if from_client:
                flow.client_close_timestamp = (
                    timestamp
                    if flow.client_close_timestamp is None
                    else min(flow.client_close_timestamp, timestamp)
                )
            else:
                flow.server_close_timestamp = (
                    timestamp
                    if flow.server_close_timestamp is None
                    else min(flow.server_close_timestamp, timestamp)
                )
        if flags & 0x01:
            if from_client:
                flow.client_fin_timestamp = (
                    timestamp
                    if flow.client_fin_timestamp is None
                    else min(flow.client_fin_timestamp, timestamp)
                )
            else:
                flow.server_fin_timestamp = (
                    timestamp
                    if flow.server_fin_timestamp is None
                    else min(flow.server_fin_timestamp, timestamp)
                )
        if flags & 0x04:
            if from_client:
                flow.client_reset_timestamp = (
                    timestamp
                    if flow.client_reset_timestamp is None
                    else min(flow.client_reset_timestamp, timestamp)
                )
            else:
                flow.server_reset_timestamp = (
                    timestamp
                    if flow.server_reset_timestamp is None
                    else min(flow.server_reset_timestamp, timestamp)
                )
        stream = flow.client_stream if from_client else flow.server_stream
        stream.add(sequence, flags, payload, timestamp)
    return sorted(observed, key=lambda flow: flow.first_timestamp)


def walk_records(stream: bytes):
    offset = 0
    while offset + 5 <= len(stream):
        record_type = stream[offset]
        version = stream[offset + 1 : offset + 3]
        length = struct.unpack_from(">H", stream, offset + 3)[0]
        end = offset + 5 + length
        if record_type not in (20, 21, 22, 23) or version[0] != 3:
            break
        if end > len(stream):
            break
        yield offset, record_type, version, length, stream[offset + 5 : end]
        offset = end


def _u16(encoded: bytes, offset: int, label: str) -> int:
    if offset + 2 > len(encoded):
        raise ValueError(f"truncated {label}")
    return struct.unpack_from(">H", encoded, offset)[0]


def _parse_extensions(encoded: bytes) -> list[tuple[int, bytes]]:
    extensions: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(encoded):
        if offset + 4 > len(encoded):
            raise ValueError("truncated extension header")
        kind, length = struct.unpack_from(">HH", encoded, offset)
        offset += 4
        end = offset + length
        if end > len(encoded):
            raise ValueError(f"truncated extension {kind}")
        extensions.append((kind, encoded[offset:end]))
        offset = end
    kinds = [kind for kind, _value in extensions]
    if len(kinds) != len(set(kinds)):
        raise ValueError("duplicate extension")
    return extensions


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_client_hello(stream: bytes) -> dict[str, object]:
    records = list(walk_records(stream))
    if not records:
        raise ValueError("missing complete ClientHello record")
    offset, record_type, version, record_length, message = records[0]
    if offset != 0 or record_type != 22 or version != TLS10_RECORD_VERSION:
        raise ValueError("wrong ClientHello record header")
    if len(message) < 4 or message[0] != 1:
        raise ValueError("wrong ClientHello handshake type")
    if int.from_bytes(message[1:4], "big") != len(message) - 4:
        raise ValueError("wrong ClientHello handshake length")

    position = 4
    if message[position : position + 2] != TLS12_LEGACY_VERSION:
        raise ValueError("wrong ClientHello legacy version")
    position += 2
    client_random = message[position : position + 32]
    if len(client_random) != 32 or not any(client_random):
        raise ValueError("missing/zero ClientHello random")
    position += 32
    if position >= len(message):
        raise ValueError("truncated ClientHello session ID length")
    session_id_length = message[position]
    position += 1
    if session_id_length != 32 or position + 32 > len(message):
        raise ValueError("wrong ClientHello session ID geometry")
    session_id = message[position : position + 32]
    if not any(session_id):
        raise ValueError("zero ClientHello session ID")
    position += 32

    cipher_length = _u16(message, position, "ClientHello cipher vector")
    position += 2
    if cipher_length != 2 or message[position : position + 2] != TLS13_CIPHER:
        raise ValueError("wrong ClientHello cipher profile")
    position += cipher_length
    if message[position : position + 2] != b"\x01\x00":
        raise ValueError("wrong ClientHello compression profile")
    position += 2
    extensions_length = _u16(message, position, "ClientHello extensions length")
    position += 2
    if position + extensions_length != len(message):
        raise ValueError("wrong ClientHello extensions length")
    extensions = _parse_extensions(message[position:])
    kinds = tuple(kind for kind, _value in extensions)
    if FORBIDDEN_CLIENT_EXTENSIONS.intersection(kinds):
        raise ValueError("ClientHello exposed compression or early_data")

    alpn_h2 = 16 in kinds
    acquisition_order = tuple(16 if k == 28 else k for k in
                              ACQUISITION_CLIENT_EXTENSION_ORDER) if alpn_h2 else ACQUISITION_CLIENT_EXTENSION_ORDER
    issuer_p384 = alpn_h2 and 50 in kinds
    issuer_dual = issuer_p384 and 21 not in kinds
    if issuer_p384:
        acquisition_order = ((0, 43, 10, 13, 51, 16, 50, 45) if issuer_dual
                             else (0, 43, 10, 13, 51, 16, 50, 21, 45))
    if kinds == acquisition_order:
        hello_profile = "acquisition"
    elif kinds == acquisition_order + (41,):
        hello_profile = "resumption"
    else:
        raise ValueError(f"wrong ClientHello extension order {kinds}")

    expected_server_name = (
        struct.pack(">H", 1 + 2 + len(SNI))
        + b"\x00"
        + struct.pack(">H", len(SNI))
        + SNI
    )
    expected_values = {
        0: expected_server_name,
        43: b"\x02" + TLS13_VERSION,
        10: b"\x00\x02" + struct.pack(">H", HYBRID_GROUP_ID),
        13: b"\x00\x02\x04\x03",
        28: b"\x08\x00",
        21: b"\x00" * 14,
        45: PSK_DHE_KE,
    }
    values = dict(extensions)
    if alpn_h2:
        del expected_values[28]
        expected_values[16] = b"\x00\x03\x02h2"
    if issuer_p384:
        if issuer_dual:
            expected_values[50] = b"\x00\x04\x04\x03\x05\x03"
            del expected_values[21]
        else:
            expected_values[50] = b"\x00\x02\x05\x03"
            expected_values[21] = bytes(6)
    for kind, expected in expected_values.items():
        if values.get(kind) != expected:
            raise ValueError(f"wrong ClientHello extension {kind}")

    ticket_identity = b""
    binder = b""
    obfuscated_ticket_age: int | None = None
    profile_delta = (3 if alpn_h2 else 0) - (8 if issuer_dual else 0)
    if hello_profile == "acquisition":
        if len(message) != ACQUISITION_CLIENT_HELLO_HANDSHAKE_BYTES + profile_delta:
            raise ValueError(
                f"wrong acquisition ClientHello length {len(message)}"
            )
        if 5 + record_length != ACQUISITION_CLIENT_HELLO_RECORD_BYTES + profile_delta:
            raise ValueError(
                "wrong acquisition ClientHello record length "
                f"{5 + record_length}"
            )
    else:
        psk = values[41]
        identities_length = _u16(psk, 0, "PSK identities vector")
        identities_end = 2 + identities_length
        if identities_length < 7 or identities_end + 2 > len(psk):
            raise ValueError("wrong PSK identities vector length")
        identity_length = _u16(psk, 2, "PSK identity")
        identity_start = 4
        identity_end = identity_start + identity_length
        if not 1 <= identity_length <= MAX_TICKET_IDENTITY_BYTES:
            raise ValueError("wrong PSK identity length")
        if identity_end + 4 != identities_end:
            raise ValueError("PSK must contain exactly one identity")
        ticket_identity = psk[identity_start:identity_end]
        if not any(ticket_identity):
            raise ValueError("zero PSK identity")
        obfuscated_ticket_age = int.from_bytes(
            psk[identity_end:identities_end],
            "big",
        )
        binders_length = _u16(psk, identities_end, "PSK binders vector")
        binders_start = identities_end + 2
        if binders_start + binders_length != len(psk):
            raise ValueError("wrong PSK binders vector length")
        if binders_length != 33 or psk[binders_start] != 32:
            raise ValueError("PSK must contain one SHA-256 binder")
        binder = psk[binders_start + 1 :]
        if len(binder) != 32 or not any(binder):
            raise ValueError("missing/zero PSK binder")

        expected_handshake_bytes = (
            RESUMPTION_CLIENT_HELLO_FIXED_HANDSHAKE_BYTES
            + identity_length
            + profile_delta
        )
        if len(message) != expected_handshake_bytes:
            raise ValueError(
                f"wrong resumption ClientHello length {len(message)}"
            )
        if 5 + record_length != expected_handshake_bytes + 5:
            raise ValueError(
                "wrong resumption ClientHello record length "
                f"{5 + record_length}"
            )

    key_share = values[51]
    expected_key_share_bytes = 2 + 2 + 2 + CLIENT_KEY_EXCHANGE_BYTES
    if len(key_share) != expected_key_share_bytes:
        raise ValueError("wrong client key_share geometry")
    if _u16(key_share, 0, "client key_share vector") != len(key_share) - 2:
        raise ValueError("wrong client key_share vector length")
    if _u16(key_share, 2, "client key_share group") != HYBRID_GROUP_ID:
        raise ValueError("wrong client hybrid group")
    if _u16(key_share, 4, "client key_exchange length") != CLIENT_KEY_EXCHANGE_BYTES:
        raise ValueError("wrong client hybrid key_exchange length")
    exchange = key_share[6:]
    mlkem_public = exchange[:CLIENT_MLKEM_BYTES]
    x25519_public = exchange[CLIENT_MLKEM_BYTES:]
    if not any(mlkem_public):
        raise ValueError("zero ML-KEM-768 encapsulation key")
    if not any(x25519_public):
        raise ValueError("zero X25519 public share")
    if x25519_public == b"\x09" + b"\x00" * 31:
        raise ValueError("8088-profile fixed X25519 share on 286 route")

    return {
        "_client_random": client_random,
        "_session_id": session_id,
        "_mlkem_public": mlkem_public,
        "_x25519_public": x25519_public,
        "_ticket_identity": ticket_identity,
        "_psk_binder": binder,
        "hello_profile": hello_profile,
        "client_random_sha256": _digest(client_random),
        "session_id_sha256": _digest(session_id),
        "mlkem_public_sha256": _digest(mlkem_public),
        "x25519_public_sha256": _digest(x25519_public),
        "extension_order": list(kinds),
        "handshake_bytes": len(message),
        "record_bytes": 5 + len(message),
        "record_size_limit": None if alpn_h2 else 2048,
        "alpn": "h2" if alpn_h2 else None,
        "certificate_signature_scheme": (
            None if issuer_dual else
            "ecdsa_secp384r1_sha384" if issuer_p384 else "ecdsa_secp256r1_sha256"
        ),
        "certificate_signature_schemes": (
            ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384"] if issuer_dual else
            ["ecdsa_secp384r1_sha384" if issuer_p384 else "ecdsa_secp256r1_sha256"]
        ),
        "psk_dhe_ke_offered": True,
        "pre_shared_key_offered": hello_profile == "resumption",
        "pre_shared_key_is_final": kinds[-1] == 41,
        "early_data_offered": False,
        "psk_identity_count": 1 if ticket_identity else 0,
        "ticket_identity_sha256": (
            _digest(ticket_identity) if ticket_identity else None
        ),
        "psk_binder_sha256": _digest(binder) if binder else None,
        "obfuscated_ticket_age": obfuscated_ticket_age,
        "compressed_certificate": False,
    }


def parse_server_hello(
    record: tuple[int, int, bytes, int, bytes],
    client_session_id: bytes,
    *,
    expect_resumption: bool,
) -> dict[str, object]:
    offset, record_type, version, record_length, message = record
    if offset != 0 or record_type != 22 or version != TLS12_LEGACY_VERSION:
        raise ValueError("wrong ServerHello record header")
    expected_handshake_bytes = (
        RESUMPTION_SERVER_HELLO_HANDSHAKE_BYTES
        if expect_resumption
        else SERVER_HELLO_HANDSHAKE_BYTES
    )
    expected_record_bytes = (
        RESUMPTION_SERVER_HELLO_RECORD_BYTES
        if expect_resumption
        else SERVER_HELLO_RECORD_BYTES
    )
    if 5 + record_length != expected_record_bytes:
        raise ValueError(f"wrong ServerHello record length {5 + record_length}")
    if len(message) != expected_handshake_bytes:
        raise ValueError(f"wrong ServerHello length {len(message)}")
    if len(message) < 4 or message[0] != 2:
        raise ValueError("wrong ServerHello handshake type")
    if int.from_bytes(message[1:4], "big") != len(message) - 4:
        raise ValueError("wrong ServerHello handshake length")

    position = 4
    if message[position : position + 2] != TLS12_LEGACY_VERSION:
        raise ValueError("wrong ServerHello legacy version")
    position += 2
    server_random = message[position : position + 32]
    if len(server_random) != 32 or not any(server_random):
        raise ValueError("missing/zero ServerHello random")
    if server_random == HELLO_RETRY_REQUEST_RANDOM:
        raise ValueError("HelloRetryRequest is outside the fixed 286 profile")
    position += 32
    if position >= len(message) or message[position] != 32:
        raise ValueError("wrong ServerHello session ID geometry")
    position += 1
    session_id = message[position : position + 32]
    position += 32
    if session_id != client_session_id:
        raise ValueError("ServerHello session ID does not echo ClientHello")
    if message[position : position + 3] != TLS13_CIPHER + b"\x00":
        raise ValueError("wrong ServerHello cipher/compression profile")
    position += 3
    extensions_length = _u16(message, position, "ServerHello extensions length")
    position += 2
    if position + extensions_length != len(message):
        raise ValueError("wrong ServerHello extensions length")
    extensions = _parse_extensions(message[position:])
    kinds = tuple(kind for kind, _value in extensions)
    expected_kinds = {43, 51, 41} if expect_resumption else {43, 51}
    if len(kinds) != len(expected_kinds) or set(kinds) != expected_kinds:
        raise ValueError(f"wrong ServerHello extension order {kinds}")
    values = dict(extensions)
    if values[43] != TLS13_VERSION:
        raise ValueError("wrong ServerHello selected version")
    if expect_resumption:
        if values[41] != b"\x00\x00":
            raise ValueError("ServerHello did not select PSK identity zero")
    elif 41 in values:
        raise ValueError("acquisition ServerHello selected an unexpected PSK")

    key_share = values[51]
    if len(key_share) != 2 + 2 + SERVER_KEY_EXCHANGE_BYTES:
        raise ValueError("wrong server key_share geometry")
    if _u16(key_share, 0, "server key_share group") != HYBRID_GROUP_ID:
        raise ValueError("wrong server hybrid group")
    if _u16(key_share, 2, "server key_exchange length") != SERVER_KEY_EXCHANGE_BYTES:
        raise ValueError("wrong server hybrid key_exchange length")
    exchange = key_share[4:]
    mlkem_ciphertext = exchange[:SERVER_MLKEM_BYTES]
    x25519_public = exchange[SERVER_MLKEM_BYTES:]
    if not any(mlkem_ciphertext):
        raise ValueError("zero ML-KEM-768 ciphertext")
    if not any(x25519_public):
        raise ValueError("zero server X25519 public share")

    return {
        "server_random_sha256": _digest(server_random),
        "mlkem_ciphertext_sha256": _digest(mlkem_ciphertext),
        "x25519_public_sha256": _digest(x25519_public),
        "extension_order": list(kinds),
        "handshake_bytes": len(message),
        "record_bytes": 5 + len(message),
        "psk_resumption_selected": expect_resumption,
        "selected_psk_identity": 0 if expect_resumption else None,
    }


def is_286_candidate(stream: bytes) -> bool:
    records = list(walk_records(stream))
    if not records:
        return False
    _offset, record_type, version, length, body = records[0]
    return (
        record_type == 22
        and version == TLS10_RECORD_VERSION
        and ACQUISITION_CLIENT_HELLO_RECORD_BYTES - 5  # dual issuer, no padding
        <= 5 + length
        <= (
            RESUMPTION_CLIENT_HELLO_FIXED_HANDSHAKE_BYTES
            + MAX_TICKET_IDENTITY_BYTES
            + 5
            + 3  # h2 ALPN replaces the six-byte legacy record-size extension
        )
        and body[:1] == b"\x01"
        and SNI in body
        and struct.pack(">H", HYBRID_GROUP_ID) in body
        and bytes.fromhex("003304c604c411ec04c0") in body
    )


def _record_time(times: list[float], offset: int) -> float | None:
    return times[offset] if 0 <= offset < len(times) else None


def _encrypted_record_valid(record: tuple[int, int, bytes, int, bytes]) -> bool:
    _offset, record_type, version, length, _body = record
    return (
        record_type == 23
        and version == TLS12_LEGACY_VERSION
        and 1 <= length <= MAX_TLS_CIPHERTEXT_BYTES
    )


def records_cover_stream(
    records: list[tuple[int, int, bytes, int, bytes]],
    stream: bytes,
) -> bool:
    if not records:
        return False
    last = records[-1]
    return last[0] + 5 + last[3] == len(stream)


def _application_dialogue(
    client_times: list[float],
    server_times: list[float],
    client_records: list[tuple[int, int, bytes, int, bytes]],
    server_records: list[tuple[int, int, bytes, int, bytes]],
) -> tuple[int, bool]:
    events: list[tuple[float, str]] = []
    for record in client_records:
        timestamp = _record_time(client_times, record[0])
        if timestamp is not None:
            events.append((timestamp, "client"))
    for record in server_records:
        timestamp = _record_time(server_times, record[0])
        if timestamp is not None:
            events.append((timestamp, "server"))
    events.sort(key=lambda item: (item[0], 0 if item[1] == "client" else 1))
    completed_rounds = 0
    awaiting_server = False
    for _timestamp, direction in events:
        if direction == "client" and not awaiting_server:
            awaiting_server = True
        elif direction == "server" and awaiting_server:
            completed_rounds += 1
            awaiting_server = False
    return completed_rounds, awaiting_server


def _public_client_hello(client_hello: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in client_hello.items()
        if not key.startswith("_")
    }


def analyze_flow(flow: Flow) -> dict[str, object] | None:
    client, client_times = flow.client_stream.contiguous()
    server, server_times = flow.server_stream.contiguous()
    if not is_286_candidate(client):
        return None
    client_gap = (
        bool(flow.client_stream.values)
        and len(client) != max(flow.client_stream.values) + 1
    )
    server_gap = (
        bool(flow.server_stream.values)
        and len(server) != max(flow.server_stream.values) + 1
    )
    result: dict[str, object] = {
        "client": f"{flow.client[0]}:{flow.client[1]}",
        "server": f"{flow.server[0]}:{flow.server[1]}",
        "first_timestamp": flow.first_timestamp,
        "client_syn_timestamp": flow.client_syn_timestamp,
        "client_close_timestamp": flow.client_close_timestamp,
        "server_close_timestamp": flow.server_close_timestamp,
        "client_fin_timestamp": flow.client_fin_timestamp,
        "server_fin_timestamp": flow.server_fin_timestamp,
        "client_reset_timestamp": flow.client_reset_timestamp,
        "server_reset_timestamp": flow.server_reset_timestamp,
        "close_timestamp": flow.close_timestamp,
        "client_stream_bytes": len(client),
        "server_stream_bytes": len(server),
        "client_retransmit_payloads": flow.client_stream.retransmit_payloads,
        "server_retransmit_payloads": flow.server_stream.retransmit_payloads,
        "stream_conflict": flow.client_stream.conflict or flow.server_stream.conflict,
        "stream_gap": client_gap or server_gap,
        "passed": False,
    }
    try:
        client_hello = parse_client_hello(client)
    except ValueError as error:
        result.update(status="invalid-client-hello", detail=str(error))
        return result
    result["client_hello"] = _public_client_hello(client_hello)
    result["_uniqueness"] = {
        "random": client_hello["_client_random"],
        "session": client_hello["_session_id"],
        "mlkem": client_hello["_mlkem_public"],
        "x25519": client_hello["_x25519_public"],
    }
    result["_ticket_identity"] = client_hello["_ticket_identity"]
    is_resumption = client_hello["hello_profile"] == "resumption"

    client_records = list(walk_records(client))
    server_records = list(walk_records(server))
    if not server_records:
        result["status"] = "missing-server-hello"
        return result
    try:
        server_hello = parse_server_hello(
            server_records[0],
            bytes(client_hello["_session_id"]),
            expect_resumption=is_resumption,
        )
    except ValueError as error:
        result.update(status="invalid-server-hello", detail=str(error))
        return result
    result["server_hello"] = server_hello
    if not records_cover_stream(client_records, client):
        result["status"] = "trailing-or-partial-client-record"
        return result
    if not records_cover_stream(server_records, server):
        result["status"] = "trailing-or-partial-server-record"
        return result

    server_index = 1
    ccs_present = False
    if server_index < len(server_records) and server_records[server_index][1] == 20:
        candidate = server_records[server_index]
        start = candidate[0]
        end = start + 5 + candidate[3]
        if server[start:end] != EXACT_CCS_RECORD:
            result["status"] = "invalid-server-ccs"
            return result
        ccs_present = True
        server_index += 1
    server_protected = server_records[server_index:]
    if not server_protected:
        result["status"] = "missing-server-protected-flight"
        return result
    if not all(_encrypted_record_valid(record) for record in server_protected):
        result["status"] = "invalid-server-protected-record"
        return result
    result["server_ccs_present"] = ccs_present

    post_hello_client = client_records[1:]
    if not post_hello_client:
        result["status"] = "missing-client-finished"
        return result
    first_post = post_hello_client[0]
    first_post_start = first_post[0]
    first_post_end = first_post_start + 5 + first_post[3]
    if client[first_post_start:first_post_end][:5] != CLIENT_FINISHED_HEADER:
        result["status"] = "first-client-record-is-not-exact-finished"
        return result
    if 5 + first_post[3] != CLIENT_FINISHED_RECORD_BYTES:
        result["status"] = "wrong-client-finished-record-length"
        return result
    client_finished_time = _record_time(client_times, first_post_start)
    server_hello_time = _record_time(server_times, server_records[0][0])
    if client_finished_time is None or server_hello_time is None:
        result["status"] = "missing-wire-timestamp"
        return result
    pre_finished_server = []
    post_finished_server = []
    for record in server_protected:
        timestamp = _record_time(server_times, record[0])
        if timestamp is None:
            result["status"] = "missing-wire-timestamp"
            return result
        if timestamp <= client_finished_time:
            pre_finished_server.append(record)
        else:
            post_finished_server.append(record)
    if not pre_finished_server:
        result["status"] = "client-finished-before-server-protected-flight"
        return result

    client_application = post_hello_client[1:]
    if not client_application or not all(
        _encrypted_record_valid(record) for record in client_application
    ):
        result["status"] = "missing-or-invalid-client-application-record"
        return result
    if not post_finished_server:
        result["status"] = "missing-post-finished-server-record"
        return result

    interval = client_finished_time - server_hello_time
    if interval < 0:
        result["status"] = "client-finished-before-server-hello"
        return result
    deadline_met = interval <= DEADLINE_SECONDS
    rounds, response_pending = _application_dialogue(
        client_times,
        server_times,
        client_application,
        post_finished_server,
    )
    role = "resumption-use" if is_resumption else "acquisition"
    acquisition_single_head_shape = (
        is_resumption or len(client_application) == 1
    )
    post_finished_times = [
        _record_time(server_times, record[0])
        for record in post_finished_server
    ]
    if any(timestamp is None for timestamp in post_finished_times):
        result["status"] = "missing-wire-timestamp"
        return result
    last_post_finished_time = max(
        float(timestamp)
        for timestamp in post_finished_times
        if timestamp is not None
    )
    clean_acquisition_close = (
        is_resumption
        or (
            flow.client_fin_timestamp is not None
            and flow.client_fin_timestamp > last_post_finished_time
            and flow.client_reset_timestamp is None
            and flow.server_reset_timestamp is None
        )
    )
    record_and_deadline_profile_passed = (
        deadline_met
        and not bool(result["stream_conflict"])
        and not bool(result["stream_gap"])
        and rounds >= 1
        and acquisition_single_head_shape
        and clean_acquisition_close
    )
    flow_passed = record_and_deadline_profile_passed and not response_pending
    if not acquisition_single_head_shape:
        status = "acquisition-client-application-shape-is-not-one-record"
    elif not clean_acquisition_close:
        status = "acquisition-did-not-cleanly-close-after-post-handshake-traffic"
    elif response_pending:
        status = "pending-application-response"
    elif not deadline_met:
        status = "client-finished-missed-deadline"
    elif rounds < 1:
        status = "missing-encrypted-application-dialogue"
    elif result["stream_conflict"] or result["stream_gap"]:
        status = "stream-conflict-or-gap"
    else:
        status = "pass"
    result.update(
        role=role,
        client_finished_present=True,
        client_finished_record_bytes=CLIENT_FINISHED_RECORD_BYTES,
        server_protected_records=len(server_protected),
        server_protected_before_finished=len(pre_finished_server),
        server_records_after_finished=len(post_finished_server),
        client_application_records=len(client_application),
        encrypted_application_rounds=rounds,
        encrypted_application_response_pending=response_pending,
        record_and_deadline_profile_passed=(
            record_and_deadline_profile_passed
        ),
        credential_free_head_ciphertext_shape_observed=(
            not is_resumption and len(client_application) == 1
        ),
        post_handshake_ciphertext_observed=bool(post_finished_server),
        credential_free_head_plaintext_visible_in_pcap=False,
        new_session_ticket_plaintext_visible_in_pcap=False,
        client_initiated_clean_close=(
            not is_resumption and clean_acquisition_close
        ),
        clean_close_timestamp=(
            flow.client_fin_timestamp
            if not is_resumption and clean_acquisition_close
            else None
        ),
        server_hello_timestamp=server_hello_time,
        client_finished_timestamp=client_finished_time,
        server_hello_to_client_finished_seconds=interval,
        deadline_seconds=DEADLINE_SECONDS,
        deadline_met=deadline_met,
        status=status,
        passed=flow_passed,
    )
    return result


def _all_unique(
    flows: list[dict[str, object]],
    field: str,
) -> bool:
    values = [
        bytes(flow["_uniqueness"][field])  # type: ignore[index]
        for flow in flows
        if "_uniqueness" in flow
    ]
    return len(values) == len(flows) and len(set(values)) == len(values)


def _pair_topology_valid(
    acquisition: dict[str, object],
    resumption: dict[str, object],
) -> bool:
    acquisition_close = acquisition.get("clean_close_timestamp")
    resumption_syn = resumption.get("client_syn_timestamp")
    return (
        isinstance(acquisition_close, (int, float))
        and isinstance(resumption_syn, (int, float))
        and float(acquisition_close) < float(resumption_syn)
    )


def _parse_server_ips(
    server_ip: str | Iterable[str] | None,
) -> frozenset[ipaddress.IPv4Address] | None:
    if server_ip is None:
        return None
    values = (server_ip,) if isinstance(server_ip, str) else tuple(server_ip)
    if not values:
        return None
    parsed: set[ipaddress.IPv4Address] = set()
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError(f"invalid --server-ip IPv4 address {value!r}") from error
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValueError(f"--server-ip requires IPv4, got {value!r}")
        parsed.add(address)
    return frozenset(parsed)


def _flow_server_ip(flow: Flow) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(flow.server[0])


def _public_attempt(
    flow: Flow,
    analyzed: dict[str, object] | None,
) -> dict[str, object]:
    client, _client_times = flow.client_stream.contiguous()
    server, _server_times = flow.server_stream.contiguous()
    return {
        "client": f"{flow.client[0]}:{flow.client[1]}",
        "server": f"{flow.server[0]}:{flow.server[1]}",
        "first_timestamp": flow.first_timestamp,
        "client_syn_timestamp": flow.client_syn_timestamp,
        "client_stream_bytes": len(client),
        "server_stream_bytes": len(server),
        "recognized_286_client_hello": analyzed is not None,
        "status": (
            str(analyzed.get("status", "unknown"))
            if analyzed is not None
            else "syn-only-incomplete-or-unrecognized"
        ),
    }


def analyze(
    path: Path,
    *,
    expect: str,
    server_ip: str | Iterable[str] | None = None,
) -> dict[str, object]:
    server_ip_filter = _parse_server_ips(server_ip)
    scoped_flows = [
        flow
        for flow in collect_flows(path)
        if server_ip_filter is None or _flow_server_ip(flow) in server_ip_filter
    ]
    analyzed_flows = [
        (flow, analyze_flow(flow))
        for flow in scoped_flows
    ]
    recognized = [
        (flow, result)
        for flow, result in analyzed_flows
        if result is not None
    ]

    seed_client_ips = {flow.client[0] for flow, _result in recognized}
    if server_ip_filter is None:
        relevant_server_ips = {
            _flow_server_ip(flow)
            for flow, _result in recognized
        }
    else:
        relevant_server_ips = set(server_ip_filter)
    if seed_client_ips:
        relevant_attempts = [
            (flow, result)
            for flow, result in analyzed_flows
            if flow.client[0] in seed_client_ips
            and _flow_server_ip(flow) in relevant_server_ips
        ]
    elif server_ip_filter is not None:
        relevant_attempts = analyzed_flows
    else:
        relevant_attempts = []

    identified: list[dict[str, object]] = []
    for _flow, result in recognized:
        if result is not None:
            identified.append(result)

    topology_errors: list[str] = []
    expected_roles = (
        ["acquisition", "resumption-use"]
        if expect == "reuse"
        else [
            "acquisition",
            "resumption-use",
            "acquisition",
            "resumption-use",
        ]
    )
    actual_roles = [flow.get("role") for flow in identified]
    if actual_roles != expected_roles:
        topology_errors.append(
            f"expected roles {expected_roles!r}, observed {actual_roles!r}"
        )
    if len(identified) != len(expected_roles):
        topology_errors.append(
            f"expected {len(expected_roles)} Seed handshakes, observed {len(identified)}"
        )
    if len(relevant_attempts) != len(expected_roles):
        topology_errors.append(
            "expected exactly "
            f"{len(expected_roles)} same-endpoint TCP connection attempts, "
            f"observed {len(relevant_attempts)}"
        )
    pending_stale_reuse_accepted = False
    if expect == "reconnect" and len(identified) == 4:
        first_resumption = identified[1]
        second_acquisition = identified[2]
        first_close = first_resumption.get("close_timestamp")
        second_syn = second_acquisition.get("client_syn_timestamp")
        pending_stale_reuse_accepted = (
            first_resumption.get("role") == "resumption-use"
            and bool(
                first_resumption.get("record_and_deadline_profile_passed")
            )
            and bool(
                first_resumption.get(
                    "encrypted_application_response_pending"
                )
            )
            and int(
                first_resumption.get("encrypted_application_rounds", 0)
            )
            >= 1
            and isinstance(first_close, (int, float))
            and isinstance(second_syn, (int, float))
            and float(first_close) < float(second_syn)
        )
    required_flow_results = [bool(flow.get("passed")) for flow in identified]
    if pending_stale_reuse_accepted:
        required_flow_results[1] = True
    if not all(required_flow_results):
        topology_errors.append("one or more identified flows failed its wire profile")

    for field in ("random", "session", "mlkem", "x25519"):
        if not _all_unique(identified, field):
            topology_errors.append(f"ClientHello {field} values are not all independent")

    pairs: list[tuple[dict[str, object], dict[str, object]]] = []
    if len(identified) >= 2:
        pairs.append((identified[0], identified[1]))
    if expect == "reconnect" and len(identified) >= 4:
        pairs.append((identified[2], identified[3]))
    for index, (acquisition, resumption) in enumerate(pairs, start=1):
        if not _pair_topology_valid(acquisition, resumption):
            topology_errors.append(
                f"route pair {index} resumption SYN did not follow clean acquisition close"
            )

    if expect == "reuse" and len(identified) == 2:
        rounds = int(identified[1].get("encrypted_application_rounds", 0))
        if rounds < 2:
            topology_errors.append(
                f"reuse needs at least 2 encrypted dialogue rounds, observed {rounds}"
            )
    elif expect == "reconnect" and len(identified) == 4:
        first_resumption_close = identified[1].get("close_timestamp")
        second_acquisition_syn = identified[2].get("client_syn_timestamp")
        if not (
            isinstance(first_resumption_close, (int, float))
            and isinstance(second_acquisition_syn, (int, float))
            and float(first_resumption_close) < float(second_acquisition_syn)
        ):
            topology_errors.append(
                "second acquisition did not follow closure of the first resumption-use flow"
            )
        for index in (1, 3):
            rounds = int(identified[index].get("encrypted_application_rounds", 0))
            if rounds < 1:
                topology_errors.append(
                    f"resumption-use flow {(index + 1) // 2} has no encrypted dialogue"
                )

    expected_handshake_flows = 2 if expect == "reuse" else 4
    deadlines_met = (
        len(identified) == expected_handshake_flows
        and all(bool(flow.get("deadline_met")) for flow in identified)
    )
    resumed_identities = [
        bytes(flow["_ticket_identity"])
        for flow in identified
        if flow.get("role") == "resumption-use"
        and flow.get("_ticket_identity")
    ]
    expected_resumptions = 1 if expect == "reuse" else 2
    resumption_identities_independent = (
        len(resumed_identities) == expected_resumptions
        and len(set(resumed_identities)) == len(resumed_identities)
    )
    if not resumption_identities_independent:
        topology_errors.append(
            "resumption ticket identities are missing or reused across route pairs"
        )
    passed = not topology_errors and deadlines_met

    public_flows: list[dict[str, object]] = []
    for index, flow in enumerate(identified):
        public = dict(flow)
        public.pop("_uniqueness", None)
        public.pop("_ticket_identity", None)
        public["accepted_as_stale_reuse_trigger"] = (
            pending_stale_reuse_accepted and index == 1
        )
        public_flows.append(public)
    return {
        "schema": "seed-tls13-286-live-pcap-v3",
        "pcap": str(path),
        "expectation": expect,
        "status": "pass" if passed else "failure",
        "passed": passed,
        "deadline_seconds": DEADLINE_SECONDS,
        "handshake_deadlines_met": deadlines_met,
        "identified_seed_flows": len(identified),
        "relevant_connection_attempts": len(relevant_attempts),
        "server_ip_filter": (
            sorted(str(address) for address in server_ip_filter)
            if server_ip_filter is not None
            else None
        ),
        "actual_roles": actual_roles,
        "client_hello_independence": {
            field: _all_unique(identified, field)
            for field in ("random", "session", "mlkem", "x25519")
        },
        "resumption_ticket_identities_independent": (
            resumption_identities_independent
        ),
        "application_connection_reuse_observed": (
            passed
            and expect == "reuse"
            and len(identified) == 2
            and int(identified[1].get("encrypted_application_rounds", 0)) >= 2
        ),
        "bounded_one_reconnect_observed": (
            passed
            and expect == "reconnect"
            and len(identified) == 4
            and len(relevant_attempts) == 4
            and actual_roles == expected_roles
        ),
        "pending_stale_reuse_accepted": pending_stale_reuse_accepted,
        "tls_ticket_resumption_expected": True,
        "observable_resumption_shape_required": {
            "client_psk_dhe_ke": True,
            "client_pre_shared_key_final": True,
            "client_early_data_absent": True,
            "server_selected_identity_zero": True,
            "fresh_hybrid_key_share": True,
        },
        "certificate_and_finished_plaintext_visible_in_pcap": False,
        "head_and_new_session_ticket_plaintext_visible_in_pcap": False,
        "ciphertext_semantics_or_standards_conformance_proven_by_pcap": False,
        "pcap_claim_boundary": (
            "the report proves record and hello topology only; encrypted "
            "Certificate/CV/Finished/HEAD/NST/application semantics and full "
            "standards conformance require target-side cryptographic evidence"
        ),
        "target_nonsecret_evidence_required": [
            "acquisition ordinary Certificate and CertificateVerify authenticated",
            "acquisition server Finished authenticated",
            "first 58-byte client record is the correct Finished plaintext",
            "next acquisition ciphertext is exactly the credential-free HEAD",
            "post-handshake ciphertext contains an authenticated HEAD response and bounded NewSessionTicket",
            "ticket remains tentative until full offline FO, X.509, hostname, UTC-validity, and CertificateVerify checks promote it",
            "resumption binder, selected PSK, fresh hybrid secret, and server Finished authenticated",
            "resumption 58-byte client record is the correct Finished plaintext",
            "OpenAI response plaintext authenticated and rendered",
        ],
        "topology_errors": topology_errors,
        "flows": public_flows,
        "connection_attempts": [
            _public_attempt(flow, result)
            for flow, result in relevant_attempts
        ],
    }


def make_tcp_packet(
    source: bytes,
    destination: bytes,
    sport: int,
    dport: int,
    sequence: int,
    flags: int,
    payload: bytes,
) -> bytes:
    tcp = struct.pack(
        ">HHIIBBHHH",
        sport,
        dport,
        sequence,
        0,
        0x50,
        flags,
        256,
        0,
        0,
    ) + payload
    total = 20 + len(tcp)
    ip = (
        b"\x45\x00"
        + struct.pack(">H", total)
        + b"\0\0\0\0\x40\x06\0\0"
        + source
        + destination
        + tcp
    )
    return b"\0" * 12 + b"\x08\x00" + ip


def _fixture_extension(kind: int, value: bytes) -> bytes:
    return struct.pack(">HH", kind, len(value)) + value


def _fixture_handshake(kind: int, body: bytes) -> bytes:
    return bytes((kind,)) + len(body).to_bytes(3, "big") + body


def _fixture_record(kind: int, version: bytes, body: bytes) -> bytes:
    return bytes((kind,)) + version + struct.pack(">H", len(body)) + body


def _fixture_bytes(length: int, seed: int) -> bytes:
    return bytes(((seed + index * 29) % 255) + 1 for index in range(length))


def fixture_client_hello(
    seed: int,
    *,
    resumed: bool = False,
    ticket_identity: bytes | None = None,
    extension_order: tuple[int, ...] | None = None,
) -> bytes:
    random = _fixture_bytes(32, seed)
    session_id = _fixture_bytes(32, seed + 17)
    mlkem_public = _fixture_bytes(CLIENT_MLKEM_BYTES, seed + 31)
    x25519_public = _fixture_bytes(CLIENT_X25519_BYTES, seed + 47)
    exchange = mlkem_public + x25519_public
    key_share_entry = struct.pack(
        ">HH",
        HYBRID_GROUP_ID,
        len(exchange),
    ) + exchange
    server_name = (
        struct.pack(">H", 1 + 2 + len(SNI))
        + b"\x00"
        + struct.pack(">H", len(SNI))
        + SNI
    )
    values = {
        0: server_name,
        43: b"\x02" + TLS13_VERSION,
        10: b"\x00\x02" + struct.pack(">H", HYBRID_GROUP_ID),
        13: b"\x00\x02\x04\x03",
        27: b"\x02\x00\x02",
        51: struct.pack(">H", len(key_share_entry)) + key_share_entry,
        16: b"\x00\x03\x02h2",
        50: b"\x00\x02\x05\x03",
        28: b"\x08\x00",
        21: b"\x00" * 14,
        45: PSK_DHE_KE,
    }
    if resumed:
        identity = (
            ticket_identity
            if ticket_identity is not None
            else _fixture_bytes(96, seed + 59)
        )
        age = _fixture_bytes(4, seed + 67)
        binder = _fixture_bytes(32, seed + 73)
        identities = (
            struct.pack(">H", len(identity))
            + identity
            + age
        )
        binders = bytes((len(binder),)) + binder
        values[41] = (
            struct.pack(">H", len(identities))
            + identities
            + struct.pack(">H", len(binders))
            + binders
        )
    if extension_order is None:
        extension_order = (
            RESUMPTION_CLIENT_EXTENSION_ORDER
            if resumed
            else ACQUISITION_CLIENT_EXTENSION_ORDER
        )
    if 50 in extension_order:
        if 21 in extension_order:
            values[21] = bytes(6)
        else:
            values[50] = b"\x00\x04\x04\x03\x05\x03"
    extensions = b"".join(
        _fixture_extension(kind, values[kind])
        for kind in extension_order
    )
    body = b"".join(
        (
            TLS12_LEGACY_VERSION,
            random,
            b"\x20",
            session_id,
            b"\x00\x02",
            TLS13_CIPHER,
            b"\x01\x00",
            struct.pack(">H", len(extensions)),
            extensions,
        )
    )
    message = _fixture_handshake(1, body)
    return _fixture_record(22, TLS10_RECORD_VERSION, message)


def fixture_server_hello(
    seed: int,
    client_hello: bytes,
    *,
    select_psk: bool | None = None,
) -> bytes:
    parsed = parse_client_hello(client_hello)
    session_id = bytes(parsed["_session_id"])
    resumed = parsed["hello_profile"] == "resumption"
    if select_psk is None:
        select_psk = resumed
    server_random = _fixture_bytes(32, seed + 71)
    exchange = (
        _fixture_bytes(SERVER_MLKEM_BYTES, seed + 83)
        + _fixture_bytes(SERVER_X25519_BYTES, seed + 97)
    )
    versions = _fixture_extension(43, TLS13_VERSION)
    key_share = _fixture_extension(
        51,
        struct.pack(">HH", HYBRID_GROUP_ID, len(exchange)) + exchange,
    )
    extensions = versions + key_share
    if select_psk:
        extensions += _fixture_extension(41, b"\x00\x00")
    body = b"".join(
        (
            TLS12_LEGACY_VERSION,
            server_random,
            b"\x20",
            session_id,
            TLS13_CIPHER,
            b"\x00",
            struct.pack(">H", len(extensions)),
            extensions,
        )
    )
    message = _fixture_handshake(2, body)
    return _fixture_record(22, TLS12_LEGACY_VERSION, message)


def fixture_encrypted_record(length: int, seed: int) -> bytes:
    return _fixture_record(
        23,
        TLS12_LEGACY_VERSION,
        _fixture_bytes(length, seed),
    )


def fixture_client_finished(seed: int) -> bytes:
    return fixture_encrypted_record(CLIENT_FINISHED_RECORD_BYTES - 5, seed)


def fixture_flow_packets(
    *,
    seed: int,
    start: float,
    port: int,
    role: str,
    rounds: int = 1,
    close: bool = True,
    deadline: float = 9.0,
    extension_order: tuple[int, ...] | None = None,
    ticket_identity: bytes | None = None,
    server_select_psk: bool | None = None,
    server_ip: bytes = bytes((104, 18, 33, 45)),
    acquisition_close_from_server: bool = False,
    omit_client_finished: bool = False,
    omit_final_response: bool = False,
) -> list[tuple[float, bytes]]:
    if role not in ("acquisition", "resumption-use"):
        raise ValueError(f"unknown fixture role {role}")
    resumed = role == "resumption-use"
    client_ip = bytes((10, 0, 2, 15))
    client_sequence = 100_000 + seed * 10_000
    server_sequence = 700_000 + seed * 10_000
    client_hello = fixture_client_hello(
        seed,
        resumed=resumed,
        ticket_identity=ticket_identity,
        extension_order=extension_order,
    )
    try:
        server_hello = fixture_server_hello(
            seed,
            client_hello,
            select_psk=server_select_psk,
        )
    except ValueError:
        server_hello = b""
    packets: list[tuple[float, bytes]] = [
        (
            start,
            make_tcp_packet(
                client_ip,
                server_ip,
                port,
                443,
                client_sequence,
                0x02,
                b"",
            ),
        ),
        (
            start + 0.05,
            make_tcp_packet(
                server_ip,
                client_ip,
                443,
                port,
                server_sequence,
                0x12,
                b"",
            ),
        ),
    ]
    split = 500
    packets.extend(
        (
            (
                start + 0.2,
                make_tcp_packet(
                    client_ip,
                    server_ip,
                    port,
                    443,
                    client_sequence + 1,
                    0x18,
                    client_hello[:split],
                ),
            ),
            (
                start + 0.3,
                make_tcp_packet(
                    client_ip,
                    server_ip,
                    port,
                    443,
                    client_sequence + 1 + split,
                    0x18,
                    client_hello[split:],
                ),
            ),
        )
    )
    if not server_hello:
        return packets

    packets.append(
        (
            start + 1.0,
            make_tcp_packet(
                server_ip,
                client_ip,
                443,
                port,
                server_sequence + 1,
                0x18,
                server_hello,
            ),
        )
    )
    server_offset = len(server_hello)
    protected = fixture_encrypted_record(59, seed + 101)
    packets.append(
        (
            start + 2.0,
            make_tcp_packet(
                server_ip,
                client_ip,
                443,
                port,
                server_sequence + 1 + server_offset,
                0x18,
                protected,
            ),
        )
    )
    server_offset += len(protected)
    client_offset = len(client_hello)

    if omit_client_finished:
        if close:
            packets.append(
                (
                    start + 3.0,
                    make_tcp_packet(
                        client_ip,
                        server_ip,
                        port,
                        443,
                        client_sequence + 1 + client_offset,
                        0x11,
                        b"",
                    ),
                )
            )
        return packets

    finished_time = start + 1.0 + deadline
    finished = fixture_client_finished(seed + 113)
    packets.append(
        (
            finished_time,
            make_tcp_packet(
                client_ip,
                server_ip,
                port,
                443,
                client_sequence + 1 + client_offset,
                0x18,
                finished,
            ),
        )
    )
    client_offset += len(finished)
    for round_index in range(rounds):
        client_app = fixture_encrypted_record(67 + round_index, seed + 127 + round_index)
        client_time = finished_time + 0.2 + round_index * 2.0
        packets.append(
            (
                client_time,
                make_tcp_packet(
                    client_ip,
                    server_ip,
                    port,
                    443,
                    client_sequence + 1 + client_offset,
                    0x18,
                    client_app,
                ),
            )
        )
        client_offset += len(client_app)
        if omit_final_response and round_index == rounds - 1:
            continue
        server_app = fixture_encrypted_record(79 + round_index, seed + 149 + round_index)
        packets.append(
            (
                client_time + 0.8,
                make_tcp_packet(
                    server_ip,
                    client_ip,
                    443,
                    port,
                    server_sequence + 1 + server_offset,
                    0x18,
                    server_app,
                ),
            )
        )
        server_offset += len(server_app)
        if role == "acquisition" and round_index == rounds - 1:
            ticket_candidate = fixture_encrypted_record(83, seed + 181)
            packets.append(
                (
                    client_time + 1.0,
                    make_tcp_packet(
                        server_ip,
                        client_ip,
                        443,
                        port,
                        server_sequence + 1 + server_offset,
                        0x18,
                        ticket_candidate,
                    ),
                )
            )
            server_offset += len(ticket_candidate)
    if close:
        close_from_server = (
            role == "acquisition" and acquisition_close_from_server
        )
        close_source = server_ip if close_from_server else client_ip
        close_destination = client_ip if close_from_server else server_ip
        close_sport = 443 if close_from_server else port
        close_dport = port if close_from_server else 443
        close_sequence = (
            server_sequence + 1 + server_offset
            if close_from_server
            else client_sequence + 1 + client_offset
        )
        packets.append(
            (
                finished_time + rounds * 2.0 + 0.5,
                make_tcp_packet(
                    close_source,
                    close_destination,
                    close_sport,
                    close_dport,
                    close_sequence,
                    0x11,
                    b"",
                ),
            )
        )
    return packets


def fixture_extra_attempt_packets(
    *,
    seed: int,
    start: float,
    port: int,
    kind: str,
    server_ip: bytes = bytes((104, 18, 33, 45)),
) -> list[tuple[float, bytes]]:
    client_ip = bytes((10, 0, 2, 15))
    client_sequence = 1_500_000 + seed * 10_000
    packets = [
        (
            start,
            make_tcp_packet(
                client_ip,
                server_ip,
                port,
                443,
                client_sequence,
                0x02,
                b"",
            ),
        )
    ]
    if kind == "syn-only":
        return packets
    client_hello = fixture_client_hello(seed)
    if kind == "incomplete":
        payload = client_hello[:100]
    elif kind == "malformed":
        malformed = bytearray(client_hello)
        malformed[79] ^= 0x01
        payload = bytes(malformed)
    else:
        raise ValueError(f"unknown fixture extra-attempt kind {kind}")
    packets.append(
        (
            start + 0.2,
            make_tcp_packet(
                client_ip,
                server_ip,
                port,
                443,
                client_sequence + 1,
                0x18,
                payload,
            ),
        )
    )
    return packets


def write_fixture_pcap(
    path: Path,
    packets: list[tuple[float, bytes]],
) -> None:
    encoded = bytearray(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    for timestamp, packet in sorted(packets, key=lambda item: item[0]):
        seconds = int(timestamp)
        micros = int(round((timestamp - seconds) * 1_000_000))
        encoded.extend(
            struct.pack("<IIII", seconds, micros, len(packet), len(packet))
        )
        encoded.extend(packet)
    path.write_bytes(encoded)


def fixture_capture(
    path: Path,
    *,
    expect: str,
    late: bool = False,
    duplicate_shares: bool = False,
    missing_acquisition_close: bool = False,
    acquisition_server_close: bool = False,
    missing_acquisition_finished: bool = False,
    missing_acquisition_post_handshake: bool = False,
    pending_final_response: bool = False,
    extra_attempt: str | None = None,
    extra_attempt_port: int = 49200,
) -> None:
    deadline = 15.25 if late else 9.0
    if expect == "reuse":
        acquisition_seed = 1
        resumption_seed = acquisition_seed if duplicate_shares else 2
        ticket_identity = _fixture_bytes(96, acquisition_seed + 181)
        packets = fixture_flow_packets(
            seed=acquisition_seed,
            start=1.0,
            port=49152,
            role="acquisition",
            close=not missing_acquisition_close,
            acquisition_close_from_server=acquisition_server_close,
            omit_client_finished=missing_acquisition_finished,
            omit_final_response=missing_acquisition_post_handshake,
        )
        packets += fixture_flow_packets(
            seed=resumption_seed,
            start=20.0,
            port=49153,
            role="resumption-use",
            rounds=2,
            close=False,
            deadline=deadline,
            ticket_identity=ticket_identity,
            omit_final_response=pending_final_response,
        )
    elif expect == "reconnect":
        first_ticket = _fixture_bytes(96, 182)
        second_ticket = _fixture_bytes(96, 184)
        packets = fixture_flow_packets(
            seed=1,
            start=1.0,
            port=49152,
            role="acquisition",
        )
        packets += fixture_flow_packets(
            seed=2,
            start=20.0,
            port=49153,
            role="resumption-use",
            # One completed authenticated turn followed by the stale-channel
            # send that triggers the bounded reconnect.  The unanswered final
            # record belongs to the abandoned connection and is valid only in
            # this first resumption position.
            rounds=2,
            close=True,
            deadline=deadline,
            ticket_identity=first_ticket,
            omit_final_response=True,
        )
        packets += fixture_flow_packets(
            seed=3,
            start=40.0,
            port=49154,
            role="acquisition",
        )
        packets += fixture_flow_packets(
            seed=4,
            start=60.0,
            port=49155,
            role="resumption-use",
            rounds=2 if pending_final_response else 1,
            close=False,
            deadline=9.0,
            ticket_identity=second_ticket,
            omit_final_response=pending_final_response,
        )
    else:
        raise ValueError(f"unknown fixture expectation {expect}")
    if extra_attempt is not None:
        packets += fixture_extra_attempt_packets(
            seed=9,
            start=16.0,
            port=extra_attempt_port,
            kind=extra_attempt,
        )
    write_fixture_pcap(path, packets)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-live-286-pcap-") as temp:
        root = Path(temp)
        reuse_path = root / "reuse.pcap"
        fixture_capture(reuse_path, expect="reuse")
        reuse = analyze(reuse_path, expect="reuse")
        if not reuse["passed"]:
            raise AssertionError(f"reuse fixture failed: {reuse}")

        reconnect_path = root / "reconnect.pcap"
        fixture_capture(reconnect_path, expect="reconnect")
        reconnect = analyze(reconnect_path, expect="reconnect")
        if not reconnect["passed"]:
            raise AssertionError(f"reconnect fixture failed: {reconnect}")
        if not reconnect["pending_stale_reuse_accepted"]:
            raise AssertionError(
                "reconnect fixture did not classify the abandoned stale send"
            )

        late_path = root / "late.pcap"
        fixture_capture(late_path, expect="reuse", late=True)
        late = analyze(late_path, expect="reuse")
        if late["passed"] or late["handshake_deadlines_met"]:
            raise AssertionError(f"late fixture passed: {late}")

        duplicate_path = root / "duplicate.pcap"
        fixture_capture(duplicate_path, expect="reuse", duplicate_shares=True)
        duplicate = analyze(duplicate_path, expect="reuse")
        if duplicate["passed"]:
            raise AssertionError(f"duplicate-share fixture passed: {duplicate}")

        open_path = root / "open-acquisition.pcap"
        fixture_capture(
            open_path,
            expect="reuse",
            missing_acquisition_close=True,
        )
        open_result = analyze(open_path, expect="reuse")
        if open_result["passed"]:
            raise AssertionError(
                f"unclosed acquisition fixture passed: {open_result}"
            )

        server_close_path = root / "server-close-acquisition.pcap"
        fixture_capture(
            server_close_path,
            expect="reuse",
            acquisition_server_close=True,
        )
        server_close = analyze(server_close_path, expect="reuse")
        if server_close["passed"]:
            raise AssertionError(
                f"server-closed acquisition fixture passed: {server_close}"
            )

        pending_path = root / "pending-response.pcap"
        fixture_capture(
            pending_path,
            expect="reuse",
            pending_final_response=True,
        )
        pending = analyze(pending_path, expect="reuse")
        if pending["passed"]:
            raise AssertionError(f"pending-response fixture passed: {pending}")

        pending_reconnect_path = root / "pending-reconnect-final.pcap"
        fixture_capture(
            pending_reconnect_path,
            expect="reconnect",
            pending_final_response=True,
        )
        pending_reconnect = analyze(
            pending_reconnect_path,
            expect="reconnect",
        )
        if pending_reconnect["passed"]:
            raise AssertionError(
                "pending final reconnect response passed: "
                f"{pending_reconnect}"
            )

        for kind in ("syn-only", "incomplete", "malformed"):
            extra_path = root / f"extra-{kind}.pcap"
            fixture_capture(
                extra_path,
                expect="reconnect",
                extra_attempt=kind,
            )
            extra = analyze(extra_path, expect="reconnect")
            if extra["passed"] or extra["relevant_connection_attempts"] != 5:
                raise AssertionError(
                    f"extra {kind} attempt was not rejected: {extra}"
                )

        exact_filter = analyze(
            reuse_path,
            expect="reuse",
            server_ip="104.18.33.4",
        )
        if exact_filter["passed"] or exact_filter["identified_seed_flows"] != 0:
            raise AssertionError(
                f"server IPv4 substring matched exact filter: {exact_filter}"
            )

    print(
        "TLS 1.3 286 pcap analyzer self-test: PASS "
        "(acquisition HEAD/ticket ciphertext, PSK-DHE resumption, complete "
        "dialogue, bounded attempts, both deadlines, independent shares, "
        "clean acquisition close, exact server IPv4)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", type=Path)
    parser.add_argument(
        "--expect",
        choices=("reuse", "reconnect"),
        required=False,
        help="required route topology for a live capture",
    )
    parser.add_argument(
        "--server-ip",
        action="append",
        metavar="IPV4",
        help=(
            "exact server IPv4 address for a host-wide capture; repeat for "
            "multiple resolved addresses"
        ),
    )
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.pcap is None:
        parser.error("pcap is required unless --self-test is used")
    if args.expect is None:
        parser.error("--expect is required for a live capture")
    result = analyze(
        args.pcap,
        expect=args.expect,
        server_ip=args.server_ip,
    )
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(
        f"TLS 1.3 286 wire gate: {result['status'].upper()} "
        f"({result['identified_seed_flows']} Seed flow(s), "
        f"expect={result['expectation']})"
    )
    for flow in result["flows"]:
        timing = ""
        if "server_hello_to_client_finished_seconds" in flow:
            timing = (
                ", SH->Finished="
                f"{float(flow['server_hello_to_client_finished_seconds']):.6f}s"
            )
        print(
            f"  {flow['client']} -> {flow['server']}: "
            f"{flow.get('role', flow['status'])}/{flow['status']}{timing}"
        )
    for error in result["topology_errors"]:
        print(f"  error: {error}")
    if result["target_nonsecret_evidence_required"]:
        print(
            "  note: encrypted Certificate/CV/Finished/application semantics "
            "still require target-side nonsecret evidence"
        )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
