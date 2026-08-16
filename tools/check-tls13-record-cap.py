#!/usr/bin/env python3
"""Check Seed/OpenAI TLS 1.3 application-record geometry in a classic pcap.

The 16 KiB MDA receive backend can authenticate at most 2,064 bytes of
TLSCiphertext.fragment at once: a 2,048-byte TLSInnerPlaintext plus the
16-byte ChaCha20-Poly1305 tag.  That leaves at most 2,047 content bytes once
the mandatory inner content-type byte is included.

This checker imports the canonical live K14/K15 pcap parser for packet
decoding, TCP reassembly, TLS record walking, and identification of Seed's
X25519MLKEM768 ClientHello to api.openai.com.  Host-generated HTTPS noise is
therefore ignored.  For each complete Seed flow it recognizes the fixed
ServerHello, optional compatibility CCS, exactly one protected server
handshake record, and the fixed 53-byte encrypted client Finished.  Every
later server TLSCiphertext is checked, including a response to resumed 0-RTT
that a server could send before receiving client Finished.  The one protected
server handshake record is outside this application-receiver gate and is
covered by the handshake gates.

The tool reads captures but never decrypts or prints record contents.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import struct
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


TOOLS_DIR = Path(__file__).resolve().parent
LIVE_PCAP_PARSER = (
    TOOLS_DIR / "crypto-bench" / "tls13-poc" / "live_k15_pcap.py"
)

TLS_LEGACY_RECORD_VERSION = b"\x03\x03"
TLS_APPLICATION_DATA = 23
TLS13_TAG_BYTES = 16
TLS13_INNER_TYPE_BYTES = 1
MDA_INNER_LIMIT = 2048
MDA_TLSCIPHERTEXT_LIMIT = MDA_INNER_LIMIT + TLS13_TAG_BYTES
MDA_CONTENT_LIMIT = MDA_INNER_LIMIT - TLS13_INNER_TYPE_BYTES
CLIENT_FINISHED_LENGTH = 53


def load_live_pcap_parser() -> ModuleType:
    """Load the canonical parser despite its hyphenated source directory."""

    spec = importlib.util.spec_from_file_location(
        "seed_tls13_live_k15_pcap",
        LIVE_PCAP_PARSER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load pcap parser: {LIVE_PCAP_PARSER}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves postponed annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PCAP = load_live_pcap_parser()


def _u16(encoded: bytes, offset: int, label: str) -> int:
    if offset + 2 > len(encoded):
        raise ValueError(f"truncated {label}")
    return struct.unpack_from(">H", encoded, offset)[0]


def client_hello_extension_kinds(stream: bytes) -> tuple[int, ...]:
    """Return extension kinds from an already identified Seed ClientHello.

    This intentionally accepts both the research resumption ClientHello and
    the later early-data product variant.  Identification itself remains the
    canonical parser's exact SNI + hybrid-group/key-share test.
    """

    records = list(PCAP.walk_records(stream))
    if not records:
        raise ValueError("missing complete ClientHello")
    offset, record_type, _version, record_length, message = records[0]
    if offset != 0 or record_type != 22 or len(message) != record_length:
        raise ValueError("wrong ClientHello record")
    if len(message) < 4 or message[0] != 1:
        raise ValueError("wrong ClientHello handshake message")
    if int.from_bytes(message[1:4], "big") != len(message) - 4:
        raise ValueError("wrong ClientHello handshake length")

    position = 4 + 2 + 32
    if position >= len(message):
        raise ValueError("truncated ClientHello session ID")
    session_id_length = message[position]
    position += 1 + session_id_length
    cipher_length = _u16(message, position, "ClientHello cipher suites")
    position += 2 + cipher_length
    if position >= len(message):
        raise ValueError("truncated ClientHello compression vector")
    compression_length = message[position]
    position += 1 + compression_length
    extensions_length = _u16(message, position, "ClientHello extensions")
    position += 2
    if position + extensions_length != len(message):
        raise ValueError("wrong ClientHello extensions length")

    kinds: list[int] = []
    end = position + extensions_length
    while position < end:
        if position + 4 > end:
            raise ValueError("truncated ClientHello extension header")
        kind, length = struct.unpack_from(">HH", message, position)
        position += 4
        if position + length > end:
            raise ValueError(f"truncated ClientHello extension {kind}")
        kinds.append(kind)
        position += length
    if len(kinds) != len(set(kinds)):
        raise ValueError("duplicate ClientHello extension")
    return tuple(kinds)


def client_hello_session_id(stream: bytes) -> bytes:
    records = list(PCAP.walk_records(stream))
    if not records:
        raise ValueError("missing complete ClientHello")
    message = records[0][4]
    position = 4 + 2 + 32
    if position >= len(message):
        raise ValueError("truncated ClientHello session ID")
    length = message[position]
    position += 1
    if length != 32 or position + length > len(message):
        raise ValueError("wrong ClientHello session ID geometry")
    return message[position : position + length]


def _stream_has_gap(stream: Any, contiguous_length: int) -> bool:
    if not stream.values:
        return False
    return max(stream.values) + 1 != contiguous_length


def _wire_timestamp(times: list[float], offset: int, label: str) -> float:
    if offset >= len(times):
        raise ValueError(f"missing {label} wire timestamp")
    return times[offset]


def analyze_flow(flow: Any) -> dict[str, object] | None:
    client, client_times = flow.client_stream.contiguous()
    server, server_times = flow.server_stream.contiguous()
    if not PCAP.is_live_client_hello(client):
        return None

    result: dict[str, object] = {
        "client": f"{flow.client[0]}:{flow.client[1]}",
        "server": f"{flow.server[0]}:{flow.server[1]}",
        "client_stream_bytes": len(client),
        "server_stream_bytes": len(server),
        "client_retransmit_payloads": flow.client_stream.retransmit_payloads,
        "server_retransmit_payloads": flow.server_stream.retransmit_payloads,
        "stream_conflict": (
            flow.client_stream.conflict or flow.server_stream.conflict
        ),
        "stream_gap": (
            _stream_has_gap(flow.client_stream, len(client))
            or _stream_has_gap(flow.server_stream, len(server))
        ),
    }

    try:
        extension_kinds = client_hello_extension_kinds(client)
        client_session_id = client_hello_session_id(client)
    except ValueError as error:
        result.update(
            {
                "profile": "unknown",
                "status": "invalid-client-hello",
                "detail": str(error),
                "passed": False,
                "records": [],
            }
        )
        return result

    profile = "resumed" if 41 in extension_kinds else "fresh"
    result.update(
        {
            "profile": profile,
            "client_hello_extensions": list(extension_kinds),
        }
    )
    if result["stream_conflict"] or result["stream_gap"]:
        result.update(
            {
                "status": "incomplete-or-conflicting-tcp-stream",
                "passed": False,
                "records": [],
            }
        )
        return result

    client_records = list(PCAP.walk_records(client))
    server_records = list(PCAP.walk_records(server))
    if not server_records or server_records[0][1] != 22:
        result.update(
            {
                "status": "missing-server-hello",
                "passed": False,
                "records": [],
            }
        )
        return result
    try:
        server_hello = PCAP.parse_server_hello(
            server_records[0],
            client_session_id,
        )
    except ValueError as error:
        result.update(
            {
                "status": "invalid-server-hello",
                "detail": str(error),
                "passed": False,
                "records": [],
            }
        )
        return result
    if server_hello["profile"] != profile:
        result.update(
            {
                "status": "client-server-profile-mismatch",
                "passed": False,
                "records": [],
            }
        )
        return result
    protected_index = 1
    if (
        len(server_records) > protected_index
        and server_records[protected_index][1] == 20
    ):
        ccs_offset = server_records[protected_index][0]
        ccs_end = ccs_offset + 5 + server_records[protected_index][3]
        if server[ccs_offset:ccs_end] != PCAP.EXACT_CCS_RECORD:
            result.update(
                {
                    "status": "invalid-server-compatibility-ccs",
                    "passed": False,
                    "records": [],
                }
            )
            return result
        protected_index += 1
    if (
        len(server_records) <= protected_index
        or server_records[protected_index][1] != TLS_APPLICATION_DATA
        or server_records[protected_index][2] != TLS_LEGACY_RECORD_VERSION
    ):
        result.update(
            {
                "status": "missing-protected-server-handshake",
                "passed": False,
                "records": [],
            }
        )
        return result

    finished_candidates = [
        record
        for record in client_records[1:]
        if (
            record[1] == TLS_APPLICATION_DATA
            and record[2] == TLS_LEGACY_RECORD_VERSION
            and record[3] == CLIENT_FINISHED_LENGTH
        )
    ]
    if not finished_candidates:
        result.update(
            {
                "status": "missing-client-finished",
                "passed": False,
                "records": [],
            }
        )
        return result

    client_finished = finished_candidates[0]
    client_finished_offset = client_finished[0]
    try:
        client_finished_timestamp = _wire_timestamp(
            client_times,
            client_finished_offset,
            "client Finished",
        )
    except ValueError as error:
        result.update(
            {
                "status": "missing-wire-timestamp",
                "detail": str(error),
                "passed": False,
                "records": [],
            }
        )
        return result

    checked_records: list[dict[str, object]] = []
    for record_index, record in enumerate(
        server_records[protected_index + 1 :],
        start=protected_index + 1,
    ):
        offset, record_type, version, length, _body = record
        if (
            record_type != TLS_APPLICATION_DATA
            or version != TLS_LEGACY_RECORD_VERSION
        ):
            continue
        try:
            timestamp = _wire_timestamp(
                server_times,
                offset,
                f"server record {record_index}",
            )
        except ValueError as error:
            result.update(
                {
                    "status": "missing-wire-timestamp",
                    "detail": str(error),
                    "passed": False,
                    "records": checked_records,
                }
            )
            return result
        inner_bytes = length - TLS13_TAG_BYTES
        maximum_content_bytes = inner_bytes - TLS13_INNER_TYPE_BYTES
        within_bound = (
            inner_bytes >= TLS13_INNER_TYPE_BYTES
            and length <= MDA_TLSCIPHERTEXT_LIMIT
        )
        checked_records.append(
            {
                "server_record_index": record_index,
                "stream_offset": offset,
                "timestamp": timestamp,
                "tlsciphertext_length": length,
                "record_bytes": 5 + length,
                "tls_inner_plaintext_bytes": inner_bytes,
                "maximum_content_bytes": maximum_content_bytes,
                "within_mda_bound": within_bound,
            }
        )

    result.update(
        {
            "client_finished_offset": client_finished_offset,
            "client_finished_timestamp": client_finished_timestamp,
            "server_protected_handshake_record_index": protected_index,
            "server_protected_handshake_tlsciphertext_length": (
                server_records[protected_index][3]
            ),
            "post_handshake_tls13_records": len(checked_records),
            "maximum_tlsciphertext_length": max(
                (
                    int(record["tlsciphertext_length"])
                    for record in checked_records
                ),
                default=None,
            ),
            "records": checked_records,
        }
    )
    if not checked_records:
        result.update(
            {
                "status": "no-post-handshake-server-tlsciphertext",
                "passed": False,
            }
        )
        return result

    passed = all(bool(record["within_mda_bound"]) for record in checked_records)
    result.update(
        {
            "status": "pass" if passed else "record-cap-exceeded",
            "passed": passed,
        }
    )
    return result


def analyze(path: Path, server_ip: str | None = None) -> dict[str, object]:
    flows: list[dict[str, object]] = []
    for flow in PCAP.collect_flows(path):
        if server_ip is not None and server_ip not in flow.server[0]:
            continue
        result = analyze_flow(flow)
        if result is not None:
            flows.append(result)

    records = [
        record
        for flow in flows
        for record in flow.get("records", [])
    ]
    fresh = sum(flow.get("profile") == "fresh" for flow in flows)
    resumed = sum(flow.get("profile") == "resumed" for flow in flows)
    violations = [
        {
            "client": flow["client"],
            "server": flow["server"],
            "profile": flow["profile"],
            **record,
        }
        for flow in flows
        for record in flow.get("records", [])
        if not record["within_mda_bound"]
    ]
    passed = (
        bool(flows)
        and bool(records)
        and not violations
        and all(bool(flow["passed"]) for flow in flows)
    )
    return {
        "pcap": str(path),
        "limits": {
            "tlsciphertext_length": MDA_TLSCIPHERTEXT_LIMIT,
            "tls_inner_plaintext_bytes": MDA_INNER_LIMIT,
            "maximum_content_bytes": MDA_CONTENT_LIMIT,
            "aead_tag_bytes": TLS13_TAG_BYTES,
        },
        "identified_seed_hybrid_flows": len(flows),
        "fresh_flows": fresh,
        "resumed_flows": resumed,
        "post_handshake_tls13_records": len(records),
        "maximum_tlsciphertext_length": max(
            (int(record["tlsciphertext_length"]) for record in records),
            default=None,
        ),
        "violations": violations,
        "passed": passed,
        "status": "pass" if passed else "failure",
        "flows": flows,
    }


def _tls13_ciphertext(length: int, fill: int = 0xA5) -> bytes:
    return (
        bytes((TLS_APPLICATION_DATA,))
        + TLS_LEGACY_RECORD_VERSION
        + struct.pack(">H", length)
        + bytes((fill,)) * length
    )


def _append_server_record(
    packets: list[tuple[float, bytes]],
    *,
    client_ip: bytes,
    server_ip: bytes,
    client_port: int,
    server_sequence: int,
    prior_stream_bytes: int,
    timestamp: float,
    record: bytes,
) -> None:
    packets.append(
        (
            timestamp,
            PCAP.make_tcp_packet(
                server_ip,
                client_ip,
                443,
                client_port,
                server_sequence + 1 + prior_stream_bytes,
                0x18,
                record,
            ),
        )
    )


def _synthetic_flow(
    *,
    client_ip: bytes,
    server_ip: bytes,
    client_port: int,
    client_sequence: int,
    server_sequence: int,
    resumed: bool,
    post_handshake_lengths: tuple[int, ...],
    base_time: float,
) -> list[tuple[float, bytes]]:
    session_id = bytes((client_port & 0xFF,)) * 32
    client_hello = PCAP._fixture_client_hello(
        session_id,
        resumed=resumed,
    )
    server_hello = PCAP._fixture_server_hello(
        session_id,
        resumed=resumed,
    )
    # Deliberately over the MDA application cap: this is the encrypted server
    # handshake flight and must be excluded because it precedes client Finished.
    encrypted_handshake = _tls13_ciphertext(3000, 0x5A)
    server_flight = server_hello + PCAP.EXACT_CCS_RECORD + encrypted_handshake
    finished_time = base_time + 14.0
    packets = PCAP._fixture_flow_packets(
        client_ip=client_ip,
        server_ip=server_ip,
        client_port=client_port,
        client_sequence=client_sequence,
        server_sequence=server_sequence,
        client_hello=client_hello,
        server_flight=server_flight,
        server_hello_time=base_time,
        client_finished_time=finished_time,
    )

    prior_stream_bytes = len(server_flight)
    for index, length in enumerate(post_handshake_lengths):
        record = _tls13_ciphertext(length, 0x70 + index)
        # A resumed server may answer accepted 0-RTT after its Finished but
        # before receiving the client's Finished.  Record order, rather than
        # packet timestamp, defines the application-receiver boundary.
        timestamp = (
            finished_time - 0.25
            if resumed and index == 0
            else finished_time + 0.25 + index * 0.01
        )
        _append_server_record(
            packets,
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=client_port,
            server_sequence=server_sequence,
            prior_stream_bytes=prior_stream_bytes,
            timestamp=timestamp,
            record=record,
        )
        prior_stream_bytes += len(record)
    return packets


def self_test() -> None:
    client_ip = bytes((10, 0, 2, 15))
    server_ip = bytes((104, 18, 33, 45))
    safe_packets = _synthetic_flow(
        client_ip=client_ip,
        server_ip=server_ip,
        client_port=49152,
        client_sequence=1000,
        server_sequence=7000,
        resumed=False,
        post_handshake_lengths=(17, MDA_TLSCIPHERTEXT_LIMIT),
        base_time=3.0,
    )
    safe_packets += _synthetic_flow(
        client_ip=client_ip,
        server_ip=server_ip,
        client_port=49153,
        client_sequence=5000,
        server_sequence=12000,
        resumed=True,
        post_handshake_lengths=(1386,),
        base_time=23.0,
    )
    # Unrelated host HTTPS traffic must not become a Seed flow.
    safe_packets.append(
        (
            4.0,
            PCAP.make_tcp_packet(
                bytes((192, 0, 2, 10)),
                bytes((203, 0, 113, 20)),
                53000,
                443,
                100,
                0x18,
                b"ordinary host traffic",
            ),
        )
    )
    bad_packets = _synthetic_flow(
        client_ip=client_ip,
        server_ip=server_ip,
        client_port=49154,
        client_sequence=9000,
        server_sequence=17000,
        resumed=True,
        post_handshake_lengths=(MDA_TLSCIPHERTEXT_LIMIT + 1,),
        base_time=43.0,
    )

    with tempfile.TemporaryDirectory(prefix="seed-tls13-record-cap-") as temp:
        safe_path = Path(temp) / "safe.pcap"
        bad_path = Path(temp) / "oversize.pcap"
        PCAP._write_fixture_pcap(safe_path, safe_packets)
        PCAP._write_fixture_pcap(bad_path, bad_packets)
        safe = analyze(safe_path)
        bad = analyze(bad_path)

    if (
        not safe["passed"]
        or safe["identified_seed_hybrid_flows"] != 2
        or safe["fresh_flows"] != 1
        or safe["resumed_flows"] != 1
        or safe["post_handshake_tls13_records"] != 3
        or safe["maximum_tlsciphertext_length"]
        != MDA_TLSCIPHERTEXT_LIMIT
    ):
        raise AssertionError(f"safe record-cap fixture failed: {safe}")
    safe_resumed = next(
        flow for flow in safe["flows"] if flow["profile"] == "resumed"
    )
    if not (
        safe_resumed["records"][0]["timestamp"]
        < safe_resumed["client_finished_timestamp"]
    ):
        raise AssertionError(
            "resumed early-response fixture did not precede client Finished"
        )
    if bad["passed"] or len(bad["violations"]) != 1:
        raise AssertionError(f"oversize record-cap fixture passed: {bad}")
    violation = bad["violations"][0]
    if (
        violation["tlsciphertext_length"]
        != MDA_TLSCIPHERTEXT_LIMIT + 1
        or violation["tls_inner_plaintext_bytes"] != MDA_INNER_LIMIT + 1
    ):
        raise AssertionError(f"oversize geometry drifted: {violation}")
    print(
        "TLS 1.3 MDA record-cap self-test: PASS "
        f"(host noise ignored; fresh + resumed; "
        f"{MDA_TLSCIPHERTEXT_LIMIT} pass; "
        f"{MDA_TLSCIPHERTEXT_LIMIT + 1} fail)"
    )


def print_report(result: dict[str, object]) -> None:
    print(
        f"TLS 1.3 MDA record cap: {str(result['status']).upper()} "
        f"({result['identified_seed_hybrid_flows']} Seed flow(s), "
        f"{result['post_handshake_tls13_records']} post-handshake record(s), "
        f"max={result['maximum_tlsciphertext_length']}/"
        f"{MDA_TLSCIPHERTEXT_LIMIT})"
    )
    for flow in result["flows"]:
        lengths = ", ".join(
            str(record["tlsciphertext_length"])
            for record in flow["records"]
        )
        if not lengths:
            lengths = "-"
        print(
            f"  {flow['profile']:7} {flow['client']} -> {flow['server']}: "
            f"{flow['status']}; TLSCiphertext.length=[{lengths}]"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", type=Path)
    parser.add_argument(
        "--server-ip",
        help="optional server IPv4 substring for a host-wide capture",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the metadata-only report as JSON",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    if args.pcap is None:
        parser.error("pcap is required unless --self-test is used")

    result = analyze(args.pcap.resolve(), args.server_ip)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
