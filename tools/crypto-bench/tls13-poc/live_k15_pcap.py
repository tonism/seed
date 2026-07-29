#!/usr/bin/env python3
"""Measure the live TLS 1.3 ServerHello -> client Finished interval from pcap.

The guest tick counter is a useful conservative execution trace, but this
wire capture is authoritative for the requested interval.  It identifies
Seed's unusual X25519MLKEM768 fresh and resumed ClientHellos, reassembles
their TCP flows, validates the complete fixed-profile ServerHello records,
and maps each exact ServerHello and 58-byte client Finished back to their
first observed packet times.  A resumed flow must contain ServerHello,
optional exact compatibility CCS, and the fixed 64-byte protected flight
before that client Finished.
The live_k15 filename is historical; the analyzer is independent of the
guest's K-window geometry.

Only classic pcap is supported because the 86Box harness captures with
tcpdump's pcap writer.  This script is pure stdlib and performs no network I/O.
"""

from __future__ import annotations

import argparse
import json
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


DEADLINE_SECONDS = 15.0
SNI = b"api.openai.com"
TLS12_LEGACY_VERSION = b"\x03\x03"
TLS13_VERSION = b"\x03\x04"
TLS13_CIPHER = b"\x13\x03"
HYBRID_GROUP_ID = 0x11EC
HYBRID_GROUP = bytes.fromhex("000a0004000211ec")
HYBRID_KEY_SHARE = bytes.fromhex("003304c604c411ec04c0")
CLIENT_KEY_EXCHANGE_BYTES = 1216
SERVER_KEY_EXCHANGE_BYTES = 1120
FRESH_CLIENT_HELLO_BYTES = 1376
FRESH_TICKET_CLIENT_HELLO_BYTES = 1382
FRESH_SERVER_HELLO_BYTES = 1210
RESUMED_SERVER_HELLO_BYTES = 1216
EXACT_CCS_RECORD = bytes.fromhex("140303000101")
RESUMED_PROTECTED_HEADER = bytes.fromhex("170303003b")
RESUMED_PROTECTED_RECORD_BYTES = 64
CLIENT_FINISHED_HEADER = bytes.fromhex("1703030035")
CLIENT_FINISHED_RECORD_BYTES = 58
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891"
    "c2a211167abb8c5e079e09e2c8a8339c"
)

# Retained for import compatibility with older one-off capture helpers.  The
# analyzer itself validates complete records instead of searching this prefix.
SERVER_HELLO_PREFIX = bytes.fromhex("16030304ba020004b60303")


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
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    offset = 24
    while offset + 16 <= len(data):
        seconds, fraction, captured, original = struct.unpack_from(
            endian + "4I", data, offset
        )
        offset += 16
        if captured > original or offset + captured > len(data):
            raise ValueError("truncated or malformed pcap packet")
        packet = data[offset : offset + captured]
        offset += captured
        scale = 1_000_000_000 if nano else 1_000_000
        yield seconds + fraction / scale, linktype, packet
    if offset != len(data):
        raise ValueError("pcap has trailing partial packet metadata")


def ipv4_tcp(linktype: int, packet: bytes):
    if linktype == 1:  # Ethernet
        if len(packet) < 14:
            return None
        ethertype = struct.unpack_from(">H", packet, 12)[0]
        link_header = 14
        if ethertype == 0x8100:  # one 802.1Q tag
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


def collect_flows(path: Path) -> list[Flow]:
    flows: dict[tuple[str, int, str, int], Flow] = {}
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
        if flow is None:
            flow = flows[key] = Flow(
                (key[0], key[1]),
                (key[2], key[3]),
                timestamp,
            )
        flow.first_timestamp = min(flow.first_timestamp, timestamp)
        stream = flow.client_stream if from_client else flow.server_stream
        stream.add(sequence, flags, payload, timestamp)
    return sorted(flows.values(), key=lambda flow: flow.first_timestamp)


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


def _parse_client_key_share(value: bytes) -> None:
    if len(value) != 2 + 2 + 2 + CLIENT_KEY_EXCHANGE_BYTES:
        raise ValueError("wrong client key_share geometry")
    vector_length = _u16(value, 0, "client key_share vector length")
    group = _u16(value, 2, "client key_share group")
    exchange_length = _u16(value, 4, "client key_exchange length")
    if vector_length != len(value) - 2:
        raise ValueError("wrong client key_share vector length")
    if group != HYBRID_GROUP_ID or exchange_length != CLIENT_KEY_EXCHANGE_BYTES:
        raise ValueError("wrong client hybrid key_share")
    exchange = value[6:]
    if not any(exchange[:-32]):
        raise ValueError("zero ML-KEM public key")
    if exchange[-32:] != b"\x09" + b"\x00" * 31:
        raise ValueError("wrong client X25519 coordinate")


def _parse_client_psk(value: bytes) -> int:
    identities_length = _u16(value, 0, "PSK identities length")
    identities_end = 2 + identities_length
    if identities_end > len(value):
        raise ValueError("truncated PSK identities")
    identities = value[2:identities_end]
    identity_length = _u16(identities, 0, "PSK identity length")
    if not 1 <= identity_length <= 192:
        raise ValueError("PSK identity outside profile bound")
    if len(identities) != 2 + identity_length + 4:
        raise ValueError("PSK identities vector is not exactly one identity")
    binders = value[identities_end:]
    if len(binders) != 35 or binders[:3] != b"\x00\x21\x20":
        raise ValueError("wrong PSK binder geometry")
    if not any(binders[3:]):
        raise ValueError("zero PSK binder")
    return identity_length


def parse_client_hello(stream: bytes) -> dict[str, object]:
    records = list(walk_records(stream))
    if not records:
        raise ValueError("missing complete ClientHello record")
    offset, record_type, version, record_length, message = records[0]
    if offset != 0 or record_type != 22 or version != b"\x03\x01":
        raise ValueError("wrong ClientHello record header")
    if len(message) < 4 or message[0] != 1:
        raise ValueError("wrong ClientHello handshake type")
    handshake_length = int.from_bytes(message[1:4], "big")
    if handshake_length != len(message) - 4 or record_length != len(message):
        raise ValueError("wrong ClientHello handshake length")

    position = 4
    if message[position : position + 2] != TLS12_LEGACY_VERSION:
        raise ValueError("wrong ClientHello legacy version")
    position += 2
    if position + 32 > len(message):
        raise ValueError("truncated ClientHello random")
    position += 32
    if position >= len(message):
        raise ValueError("truncated ClientHello session ID length")
    session_id_length = message[position]
    position += 1
    if session_id_length != 32 or position + session_id_length > len(message):
        raise ValueError("wrong ClientHello session ID geometry")
    session_id = message[position : position + session_id_length]
    position += session_id_length

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

    base_kinds = (0, 43, 10, 13, 27, 51, 21)
    if kinds == base_kinds:
        profile = "fresh"
        requests_ticket = False
        expected_length = FRESH_CLIENT_HELLO_BYTES
    elif kinds == base_kinds + (45,):
        profile = "fresh"
        requests_ticket = True
        expected_length = FRESH_TICKET_CLIENT_HELLO_BYTES
    elif kinds == base_kinds + (45, 41):
        profile = "resumed"
        requests_ticket = True
        expected_length = None
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
        27: b"\x02\x00\x02",
        21: b"\x00" * 14,
        45: b"\x01\x01",
    }
    values = dict(extensions)
    for kind, expected in expected_values.items():
        if kind in values and values[kind] != expected:
            raise ValueError(f"wrong ClientHello extension {kind}")
    _parse_client_key_share(values[51])

    identity_length: int | None = None
    if profile == "resumed":
        identity_length = _parse_client_psk(values[41])
        expected_length = 1429 + identity_length
    if expected_length != len(message):
        raise ValueError(
            f"wrong {profile} ClientHello length {len(message)}"
        )
    return {
        "profile": profile,
        "requests_ticket": requests_ticket,
        "session_id": session_id,
        "handshake_bytes": len(message),
        "record_bytes": 5 + len(message),
        "identity_bytes": identity_length,
    }


def _parse_server_key_share(value: bytes) -> None:
    if len(value) != 2 + 2 + SERVER_KEY_EXCHANGE_BYTES:
        raise ValueError("wrong server key_share geometry")
    group = _u16(value, 0, "server key_share group")
    exchange_length = _u16(value, 2, "server key_exchange length")
    if group != HYBRID_GROUP_ID or exchange_length != SERVER_KEY_EXCHANGE_BYTES:
        raise ValueError("wrong server hybrid key_share")
    exchange = value[4:]
    if not any(exchange[:-32]):
        raise ValueError("zero ML-KEM ciphertext")
    if not any(exchange[-32:]):
        raise ValueError("zero server X25519 coordinate")


def parse_server_hello(
    record: tuple[int, int, bytes, int, bytes],
    client_session_id: bytes,
) -> dict[str, object]:
    offset, record_type, version, record_length, message = record
    if offset != 0 or record_type != 22 or version != TLS12_LEGACY_VERSION:
        raise ValueError("wrong ServerHello record header")
    if len(message) < 4 or message[0] != 2:
        raise ValueError("wrong ServerHello handshake type")
    handshake_length = int.from_bytes(message[1:4], "big")
    if handshake_length != len(message) - 4 or record_length != len(message):
        raise ValueError("wrong ServerHello handshake length")

    position = 4
    if message[position : position + 2] != TLS12_LEGACY_VERSION:
        raise ValueError("wrong ServerHello legacy version")
    position += 2
    server_random = message[position : position + 32]
    if len(server_random) != 32:
        raise ValueError("truncated ServerHello random")
    if server_random == HELLO_RETRY_REQUEST_RANDOM:
        raise ValueError("HelloRetryRequest is outside the fixed profile")
    position += 32
    if position >= len(message):
        raise ValueError("truncated ServerHello session ID length")
    session_id_length = message[position]
    position += 1
    if session_id_length != 32:
        raise ValueError("wrong ServerHello session ID geometry")
    session_id = message[position : position + session_id_length]
    position += session_id_length
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

    fresh_orders = ((43, 51), (51, 43))
    resumed_orders = ((43, 51, 41), (51, 43, 41), (41, 51, 43))
    if kinds in fresh_orders:
        profile = "fresh"
        expected_length = FRESH_SERVER_HELLO_BYTES
    elif kinds in resumed_orders:
        profile = "resumed"
        expected_length = RESUMED_SERVER_HELLO_BYTES
    else:
        raise ValueError(f"wrong ServerHello extension order {kinds}")
    if len(message) != expected_length:
        raise ValueError(f"wrong {profile} ServerHello length {len(message)}")

    values = dict(extensions)
    if values[43] != TLS13_VERSION:
        raise ValueError("wrong ServerHello selected version")
    _parse_server_key_share(values[51])
    if profile == "resumed" and values[41] != b"\x00\x00":
        raise ValueError("wrong ServerHello selected identity")
    return {
        "profile": profile,
        "extension_order": list(kinds),
        "handshake_bytes": len(message),
        "record_bytes": 5 + len(message),
    }


def is_live_client_hello(stream: bytes) -> bool:
    records = list(walk_records(stream))
    if not records:
        return False
    _offset, record_type, _version, _length, body = records[0]
    return (
        record_type == 22
        and body[:1] == b"\x01"
        and SNI in body
        and HYBRID_GROUP in body
        and HYBRID_KEY_SHARE in body
    )


def analyze_flow(flow: Flow) -> dict[str, object] | None:
    client, client_times = flow.client_stream.contiguous()
    server, server_times = flow.server_stream.contiguous()
    if not is_live_client_hello(client):
        return None
    result: dict[str, object] = {
        "client": f"{flow.client[0]}:{flow.client[1]}",
        "server": f"{flow.server[0]}:{flow.server[1]}",
        "client_stream_bytes": len(client),
        "server_stream_bytes": len(server),
        "client_retransmit_payloads": flow.client_stream.retransmit_payloads,
        "server_retransmit_payloads": flow.server_stream.retransmit_payloads,
        "stream_conflict": flow.client_stream.conflict or flow.server_stream.conflict,
    }

    try:
        client_hello = parse_client_hello(client)
    except ValueError as error:
        result.update(
            {
                "status": "invalid-client-hello",
                "detail": str(error),
                "passed": False,
            }
        )
        return result
    profile = str(client_hello["profile"])
    result.update(
        {
            "profile": profile,
            "client_hello_profile": profile,
            "client_hello_handshake_bytes": client_hello["handshake_bytes"],
            "client_hello_record_bytes": client_hello["record_bytes"],
            "client_requests_ticket": client_hello["requests_ticket"],
        }
    )
    if client_hello["identity_bytes"] is not None:
        result["ticket_identity_bytes"] = client_hello["identity_bytes"]

    server_records = list(walk_records(server))
    if not server_records:
        result.update({"status": "missing-server-hello", "passed": False})
        return result
    try:
        server_hello = parse_server_hello(
            server_records[0],
            bytes(client_hello["session_id"]),
        )
    except ValueError as error:
        result.update(
            {
                "status": "invalid-server-hello",
                "detail": str(error),
                "passed": False,
            }
        )
        return result
    result.update(
        {
            "server_hello_profile": server_hello["profile"],
            "server_hello_extension_order": server_hello["extension_order"],
            "server_hello_handshake_bytes": server_hello["handshake_bytes"],
            "server_hello_record_bytes": server_hello["record_bytes"],
        }
    )
    if server_hello["profile"] != profile:
        result.update(
            {
                "status": "client-server-profile-mismatch",
                "passed": False,
            }
        )
        return result

    client_records = list(walk_records(client))
    if len(client_records) < 2:
        result.update({"status": "missing-client-finished", "passed": False})
        return result
    client_finished = client_records[1]
    (
        client_finished_offset,
        client_finished_type,
        client_finished_version,
        client_finished_length,
        _client_finished_body,
    ) = client_finished
    if (
        client_finished_type != 23
        or client_finished_version != TLS12_LEGACY_VERSION
        or client_finished_length != CLIENT_FINISHED_RECORD_BYTES - 5
        or client[
            client_finished_offset : client_finished_offset + 5
        ] != CLIENT_FINISHED_HEADER
    ):
        result.update(
            {
                "status": "unexpected-client-record-before-finished",
                "passed": False,
            }
        )
        return result

    protected_offset: int | None = None
    ccs_present = False
    if profile == "resumed":
        server_record_index = 1
        if len(server_records) > server_record_index:
            candidate = server_records[server_record_index]
            if candidate[1] == 20:
                candidate_offset = candidate[0]
                candidate_end = candidate_offset + 5 + candidate[3]
                if server[candidate_offset:candidate_end] != EXACT_CCS_RECORD:
                    result.update(
                        {
                            "status": "invalid-resumed-server-ccs",
                            "passed": False,
                        }
                    )
                    return result
                ccs_present = True
                server_record_index += 1
        if len(server_records) <= server_record_index:
            result.update(
                {
                    "status": "missing-resumed-protected-record",
                    "passed": False,
                    "server_ccs_present": ccs_present,
                }
            )
            return result
        protected = server_records[server_record_index]
        protected_offset, protected_type, protected_version, protected_length, _ = (
            protected
        )
        if (
            protected_type != 23
            or protected_version != TLS12_LEGACY_VERSION
            or protected_length != RESUMED_PROTECTED_RECORD_BYTES - 5
            or server[protected_offset : protected_offset + 5]
            != RESUMED_PROTECTED_HEADER
        ):
            result.update(
                {
                    "status": "invalid-resumed-protected-record",
                    "passed": False,
                    "server_ccs_present": ccs_present,
                }
            )
            return result
        result.update(
            {
                "server_ccs_present": ccs_present,
                "server_protected_record_offset": protected_offset,
                "server_protected_record_bytes": RESUMED_PROTECTED_RECORD_BYTES,
            }
        )

    server_hello_offset = server_records[0][0]
    if (
        server_hello_offset >= len(server_times)
        or client_finished_offset >= len(client_times)
        or (
            protected_offset is not None
            and protected_offset >= len(server_times)
        )
    ):
        result.update({"status": "missing-wire-timestamp", "passed": False})
        return result
    server_hello_time = server_times[server_hello_offset]
    client_finished_time = client_times[client_finished_offset]
    if protected_offset is not None:
        protected_time = server_times[protected_offset]
        result["server_protected_record_timestamp"] = protected_time
        if client_finished_time < protected_time:
            result.update(
                {
                    "status": "client-finished-before-server-flight",
                    "passed": False,
                }
            )
            return result
        protected_index = next(
            index
            for index, record in enumerate(server_records)
            if record[0] == protected_offset
        )
        for later_record in server_records[protected_index + 1 :]:
            later_offset = later_record[0]
            if (
                later_offset < len(server_times)
                and server_times[later_offset] <= client_finished_time
            ):
                result.update(
                    {
                        "status": "unexpected-server-record-before-client-finished",
                        "passed": False,
                    }
                )
                return result

    interval = client_finished_time - server_hello_time
    passed = (
        not result["stream_conflict"]
        and interval >= 0
        and interval <= DEADLINE_SECONDS
    )
    result.update(
        {
            "status": "pass" if passed else "late-or-invalid",
            "passed": passed,
            "server_hello_offset": server_hello_offset,
            "client_finished_offset": client_finished_offset,
            "client_finished_record_bytes": CLIENT_FINISHED_RECORD_BYTES,
            "server_hello_timestamp": server_hello_time,
            "client_finished_timestamp": client_finished_time,
            "server_hello_to_client_finished_seconds": interval,
            "deadline_seconds": DEADLINE_SECONDS,
            "margin_seconds": DEADLINE_SECONDS - interval,
        }
    )
    return result


def analyze(path: Path, server_ip: str | None = None) -> dict[str, object]:
    identified: list[dict[str, object]] = []
    for flow in collect_flows(path):
        if server_ip is not None and server_ip not in flow.server[0]:
            continue
        result = analyze_flow(flow)
        if result is not None:
            identified.append(result)
    completed = [
        result
        for result in identified
        if "server_hello_to_client_finished_seconds" in result
    ]
    fresh = [
        result for result in identified if result.get("profile") == "fresh"
    ]
    resumed = [
        result for result in identified if result.get("profile") == "resumed"
    ]
    if len(identified) == 1 and len(fresh) == 1:
        capture_profile = "fresh"
        expected_profiles = True
    elif len(identified) == 1 and len(resumed) == 1:
        capture_profile = "resumed"
        expected_profiles = True
    elif len(identified) == 2 and len(fresh) == 1 and len(resumed) == 1:
        capture_profile = "fresh+resumed"
        expected_profiles = True
    else:
        capture_profile = "invalid"
        expected_profiles = False
    passed = (
        expected_profiles
        and len(completed) == len(identified)
        and all(bool(result["passed"]) for result in identified)
    )
    return {
        "pcap": str(path),
        "deadline_seconds": DEADLINE_SECONDS,
        "capture_profile": capture_profile,
        "identified_live_seed_flows": len(identified),
        "completed_live_seed_flows": len(completed),
        "fresh_live_seed_flows": len(fresh),
        "resumed_live_seed_flows": len(resumed),
        "passed": passed,
        "status": "pass" if passed else "failure",
        "flows": identified,
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


def _fixture_client_hello(
    session_id: bytes,
    *,
    resumed: bool,
    identity: bytes = b"T" * 192,
) -> bytes:
    public_key = bytes((index % 251) + 1 for index in range(1184))
    exchange = public_key + b"\x09" + b"\x00" * 31
    key_share_entry = (
        struct.pack(">HH", HYBRID_GROUP_ID, len(exchange)) + exchange
    )
    server_name = (
        struct.pack(">H", 1 + 2 + len(SNI))
        + b"\x00"
        + struct.pack(">H", len(SNI))
        + SNI
    )
    extensions = b"".join(
        (
            _fixture_extension(0, server_name),
            _fixture_extension(43, b"\x02" + TLS13_VERSION),
            _fixture_extension(
                10,
                b"\x00\x02" + struct.pack(">H", HYBRID_GROUP_ID),
            ),
            _fixture_extension(13, b"\x00\x02\x04\x03"),
            _fixture_extension(27, b"\x02\x00\x02"),
            _fixture_extension(
                51,
                struct.pack(">H", len(key_share_entry)) + key_share_entry,
            ),
            _fixture_extension(21, b"\x00" * 14),
            _fixture_extension(45, b"\x01\x01"),
        ),
    )
    if resumed:
        identities = (
            struct.pack(">H", 2 + len(identity) + 4)
            + struct.pack(">H", len(identity))
            + identity
            + b"\x00\x00\x00\x01"
        )
        binders = b"\x00\x21\x20" + bytes(range(1, 33))
        extensions += _fixture_extension(41, identities + binders)
    body = b"".join(
        (
            TLS12_LEGACY_VERSION,
            bytes(range(32)),
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
    expected = (
        1429 + len(identity)
        if resumed
        else FRESH_TICKET_CLIENT_HELLO_BYTES
    )
    if len(message) != expected:
        raise AssertionError(
            f"self-test ClientHello fixture length drifted: {len(message)}"
        )
    return _fixture_record(22, b"\x03\x01", message)


def _fixture_server_hello(
    session_id: bytes,
    *,
    resumed: bool,
) -> bytes:
    exchange = bytes((index % 251) + 1 for index in range(1088))
    exchange += b"\x05" + b"\x00" * 31
    supported_versions = _fixture_extension(43, TLS13_VERSION)
    key_share = _fixture_extension(
        51,
        struct.pack(">HH", HYBRID_GROUP_ID, len(exchange)) + exchange,
    )
    extensions = (
        _fixture_extension(41, b"\x00\x00") + key_share + supported_versions
        if resumed
        else supported_versions + key_share
    )
    body = b"".join(
        (
            TLS12_LEGACY_VERSION,
            bytes(range(32, 64)),
            b"\x20",
            session_id,
            TLS13_CIPHER,
            b"\x00",
            struct.pack(">H", len(extensions)),
            extensions,
        )
    )
    message = _fixture_handshake(2, body)
    expected = (
        RESUMED_SERVER_HELLO_BYTES
        if resumed
        else FRESH_SERVER_HELLO_BYTES
    )
    if len(message) != expected:
        raise AssertionError(
            f"self-test ServerHello fixture length drifted: {len(message)}"
        )
    return _fixture_record(22, TLS12_LEGACY_VERSION, message)


def _fixture_flow_packets(
    *,
    client_ip: bytes,
    server_ip: bytes,
    client_port: int,
    client_sequence: int,
    server_sequence: int,
    client_hello: bytes,
    server_flight: bytes,
    server_hello_time: float,
    client_finished_time: float,
) -> list[tuple[float, bytes]]:
    client_finished = CLIENT_FINISHED_HEADER + bytes(range(1, 54))
    client_split = min(384, len(client_hello))
    server_split = min(17, len(server_flight))
    return [
        (
            server_hello_time - 2.0,
            make_tcp_packet(
                client_ip,
                server_ip,
                client_port,
                443,
                client_sequence,
                0x02,
                b"",
            ),
        ),
        (
            server_hello_time - 1.9,
            make_tcp_packet(
                server_ip,
                client_ip,
                443,
                client_port,
                server_sequence,
                0x12,
                b"",
            ),
        ),
        (
            server_hello_time - 1.0,
            make_tcp_packet(
                client_ip,
                server_ip,
                client_port,
                443,
                client_sequence + 1,
                0x18,
                client_hello[:client_split],
            ),
        ),
        (
            server_hello_time - 0.9,
            make_tcp_packet(
                client_ip,
                server_ip,
                client_port,
                443,
                client_sequence + 1 + client_split,
                0x18,
                client_hello[client_split:],
            ),
        ),
        (
            server_hello_time,
            make_tcp_packet(
                server_ip,
                client_ip,
                443,
                client_port,
                server_sequence + 1,
                0x18,
                server_flight[:server_split],
            ),
        ),
        (
            server_hello_time + 0.1,
            make_tcp_packet(
                server_ip,
                client_ip,
                443,
                client_port,
                server_sequence + 1 + server_split,
                0x18,
                server_flight[server_split:],
            ),
        ),
        (
            client_finished_time,
            make_tcp_packet(
                client_ip,
                server_ip,
                client_port,
                443,
                client_sequence + 1 + len(client_hello),
                0x18,
                client_finished,
            ),
        ),
    ]


def _write_fixture_pcap(
    path: Path,
    packets: list[tuple[float, bytes]],
) -> None:
    encoded = bytearray(
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    for timestamp, packet in sorted(packets):
        seconds = int(timestamp)
        micros = int(round((timestamp - seconds) * 1_000_000))
        encoded.extend(
            struct.pack("<IIII", seconds, micros, len(packet), len(packet))
        )
        encoded.extend(packet)
    path.write_bytes(encoded)


def self_test() -> None:
    client_ip = bytes((10, 0, 2, 15))
    server_ip = bytes((104, 18, 33, 45))
    fresh_session = b"F" * 32
    resumed_session = b"R" * 32
    fresh_client = _fixture_client_hello(fresh_session, resumed=False)
    fresh_server = _fixture_server_hello(fresh_session, resumed=False)
    resumed_client = _fixture_client_hello(resumed_session, resumed=True)
    resumed_server = _fixture_server_hello(resumed_session, resumed=True)
    protected = RESUMED_PROTECTED_HEADER + bytes(range(1, 60))

    with tempfile.TemporaryDirectory(prefix="seed-live-k15-pcap-") as temp:
        temp_path = Path(temp)
        fresh_path = temp_path / "fresh.pcap"
        fresh_packets = _fixture_flow_packets(
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=49152,
            client_sequence=1000,
            server_sequence=7000,
            client_hello=fresh_client,
            server_flight=fresh_server,
            server_hello_time=3.0,
            client_finished_time=17.75,
        )
        _write_fixture_pcap(fresh_path, fresh_packets)
        fresh_result = analyze(fresh_path)

        dual_path = temp_path / "fresh-resumed.pcap"
        resumed_packets = _fixture_flow_packets(
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=49153,
            client_sequence=3000,
            server_sequence=9000,
            client_hello=resumed_client,
            server_flight=resumed_server + EXACT_CCS_RECORD + protected,
            server_hello_time=23.0,
            client_finished_time=31.0,
        )
        _write_fixture_pcap(dual_path, fresh_packets + resumed_packets)
        dual_result = analyze(dual_path)

        no_ccs_path = temp_path / "resumed-no-ccs.pcap"
        no_ccs_packets = _fixture_flow_packets(
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=49154,
            client_sequence=5000,
            server_sequence=11000,
            client_hello=resumed_client,
            server_flight=resumed_server + protected,
            server_hello_time=43.0,
            client_finished_time=51.0,
        )
        _write_fixture_pcap(no_ccs_path, no_ccs_packets)
        no_ccs_result = analyze(no_ccs_path)

        old_68_path = temp_path / "resumed-old-68.pcap"
        old_68_protected = b"\x17\x03\x03\x00\x3f" + bytes(range(1, 64))
        old_68_packets = _fixture_flow_packets(
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=49155,
            client_sequence=7000,
            server_sequence=13000,
            client_hello=resumed_client,
            server_flight=resumed_server + EXACT_CCS_RECORD + old_68_protected,
            server_hello_time=63.0,
            client_finished_time=71.0,
        )
        _write_fixture_pcap(old_68_path, old_68_packets)
        old_68_result = analyze(old_68_path)

    if not fresh_result["passed"]:
        raise AssertionError(
            f"fresh pcap self-test did not pass: {fresh_result}"
        )
    fresh_flow = fresh_result["flows"][0]
    interval = fresh_flow["server_hello_to_client_finished_seconds"]
    if abs(float(interval) - 14.75) > 0.000001:
        raise AssertionError(f"pcap self-test interval drifted: {interval}")

    if (
        not dual_result["passed"]
        or dual_result["capture_profile"] != "fresh+resumed"
        or dual_result["fresh_live_seed_flows"] != 1
        or dual_result["resumed_live_seed_flows"] != 1
    ):
        raise AssertionError(
            f"dual-flow pcap self-test did not pass: {dual_result}"
        )
    resumed_flow = next(
        flow for flow in dual_result["flows"] if flow["profile"] == "resumed"
    )
    if (
        resumed_flow["server_hello_record_bytes"] != 1221
        or not resumed_flow["server_ccs_present"]
        or resumed_flow["server_protected_record_bytes"] != 64
        or resumed_flow["client_finished_record_bytes"] != 58
    ):
        raise AssertionError(
            f"resumed geometry drifted: {resumed_flow}"
        )

    if not no_ccs_result["passed"]:
        raise AssertionError(
            f"optional-CCS pcap self-test did not pass: {no_ccs_result}"
        )
    if no_ccs_result["flows"][0]["server_ccs_present"]:
        raise AssertionError("optional-CCS fixture unexpectedly reported CCS")

    if old_68_result["passed"]:
        raise AssertionError("legacy 68-byte resumed protected record passed")
    if old_68_result["flows"][0]["status"] != "invalid-resumed-protected-record":
        raise AssertionError(
            f"legacy 68-byte rejection drifted: {old_68_result}"
        )
    print(
        "live TLS 1.3 pcap analyzer self-test: PASS "
        "(fresh + resumed, exact resumed 64/58-byte flight)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", type=Path)
    parser.add_argument(
        "--server-ip",
        help="optional server IPv4 substring, useful on a host-wide capture",
    )
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.pcap is None:
        parser.error("pcap is required unless --self-test is used")
    result = analyze(args.pcap, args.server_ip)
    if args.json_out is not None:
        args.json_out.write_text(
            json.dumps(result, indent=2) + "\n",
            encoding="utf-8",
        )
    print(
        f"live TLS 1.3 wire deadline: {result['status'].upper()} "
        f"({result['identified_live_seed_flows']} identified flow(s))"
    )
    for flow in result["flows"]:
        if "server_hello_to_client_finished_seconds" in flow:
            print(
                "  "
                f"{flow['client']} -> {flow['server']}: "
                f"{flow['server_hello_to_client_finished_seconds']:.6f}s, "
                f"margin={flow['margin_seconds']:.6f}s"
            )
        else:
            print(f"  {flow['client']} -> {flow['server']}: {flow['status']}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
