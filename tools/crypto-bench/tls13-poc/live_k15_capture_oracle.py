#!/usr/bin/env python3
"""Reconstruct the deterministic live K14 handshake from a captured pcap.

This is an offline diagnostic.  It derives the same ML-KEM key from the public
PoC fixture, checks the captured ClientHello key share, independently computes
the provisional ML-KEM secret and TLS schedule, compares the target's exact
client Finished record, and authenticates every captured post-Finished server
record in application-epoch sequence.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPIKE = HERE.parent / "tls13-spike"
DEFAULT_PCAP = ROOT / "build/crypto-bench/tls13-live-k15/live.pcap"
LIVE_BUILD = ROOT / "build/crypto-bench/tls13-live-k15"
LIVE_MANIFEST = LIVE_BUILD / "manifest.json"
LIVE_CORE = LIVE_BUILD / "SEED.SYS"
ENTROPY_FIXTURE = (
    ROOT / "build/crypto-bench/tls13-poc/entropy_meta_fixture.bin"
)
HELLO_FIXTURE = (
    ROOT / "build/crypto-bench/tls13-poc/hello_inputs_fixture.bin"
)

TLS_ALERT = 21
TLS_HANDSHAKE = 22
TLS_APPLICATION_DATA = 23
TLS_CHANGE_CIPHER_SPEC = 20
HS_NEW_SESSION_TICKET = 4
SEED_NST_MESSAGE_MAX = 384
SEED_NST_IDENTITY_MAX = 192
SEED_NST_NONCE_MAX = 32
SEED_NST_LIFETIME_MAX = 7 * 24 * 60 * 60
SEED_NST_CONNECTION_MAX = 4
POST_HANDSHAKE_MESSAGE_MAX = 1 << 20
COMPATIBILITY_CCS_RECORD = b"\x14\x03\x03\x00\x01\x01"

INNER_TYPE_NAMES = {
    TLS_ALERT: "alert",
    TLS_HANDSHAKE: "handshake",
    TLS_APPLICATION_DATA: "application_data",
}
HANDSHAKE_TYPE_NAMES = {
    HS_NEW_SESSION_TICKET: "new_session_ticket",
    24: "key_update",
}
ALERT_LEVEL_NAMES = {
    1: "warning",
    2: "fatal",
}
ALERT_DESCRIPTION_NAMES = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    22: "record_overflow",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    115: "unknown_psk_identity",
    116: "certificate_required",
    120: "no_application_protocol",
}


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PCAP = load_module("seed_live_capture_pcap", HERE / "live_k15_pcap.py")
PROBE = load_module(
    "seed_live_capture_hybrid_probe",
    SPIKE / "tls13_hybrid_u9_probe.py",
)
KEYGEN = load_module(
    "seed_live_capture_keygen",
    SPIKE / "mlkem768_integrated_keygen_check.py",
)
MLKEM = load_module(
    "seed_live_capture_mlkem",
    SPIKE / "mlkem768_integrated_check.py",
)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def full_records(stream: bytes) -> list[tuple[int, int, int, bytes]]:
    return [
        (
            offset,
            record_type,
            length,
            stream[offset : offset + 5 + length],
        )
        for offset, record_type, _version, length, _body in PCAP.walk_records(
            stream
        )
    ]


def split_target_server_flight(
    records_after_server_hello: list[tuple[int, int, int, bytes]],
) -> tuple[
    list[tuple[int, int, int, bytes]],
    tuple[int, int, int, bytes],
    list[tuple[int, int, int, bytes]],
]:
    """Select the protected flight without discarding TLS record order."""

    if not records_after_server_hello:
        raise ValueError("capture lacks a protected server flight")

    compatibility_ccs: list[tuple[int, int, int, bytes]] = []
    protected_index = 0
    first = records_after_server_hello[0]
    if first[1] == TLS_CHANGE_CIPHER_SPEC:
        if first[3] != COMPATIBILITY_CCS_RECORD:
            raise ValueError("server compatibility CCS is not exact")
        compatibility_ccs.append(first)
        protected_index = 1

    if protected_index >= len(records_after_server_hello):
        raise ValueError("capture lacks a protected server flight")
    protected = records_after_server_hello[protected_index]
    if protected[1] != TLS_APPLICATION_DATA:
        if protected[1] == TLS_CHANGE_CIPHER_SPEC:
            raise ValueError("duplicate server compatibility CCS")
        raise ValueError(
            "expected protected application-data record after ServerHello"
        )
    if protected[3][1:3] != b"\x03\x03":
        raise ValueError("protected server flight has a bad legacy version")

    return (
        compatibility_ccs,
        protected,
        records_after_server_hello[protected_index + 1 :],
    )


def manifest_phase(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    phases = manifest.get("live_phases")
    if not isinstance(phases, list):
        raise ValueError("live manifest lacks its phase ledger")
    matches = [
        phase
        for phase in phases
        if isinstance(phase, dict) and phase.get("name") == name
    ]
    if len(matches) != 1:
        raise ValueError(f"manifest has {len(matches)} {name!r} phases")
    return matches[0]


def client_hybrid_exchange(client_hello: bytes) -> bytes:
    extension_len_offset, extensions_end = PROBE.client_hello_extensions(
        client_hello
    )
    exchanges: list[bytes] = []
    for extension_type, value_start, value_end in PROBE.iter_extensions(
        client_hello,
        extension_len_offset + 2,
        extensions_end,
    ):
        if extension_type != PROBE.EXT_KEY_SHARE:
            continue
        value = client_hello[value_start:value_end]
        if len(value) < 6:
            raise ValueError("captured ClientHello has a short key_share")
        vector_len = int.from_bytes(value[:2], "big")
        group = int.from_bytes(value[2:4], "big")
        exchange_len = int.from_bytes(value[4:6], "big")
        exchange = value[6:]
        if (
            vector_len != len(value) - 2
            or group != PROBE.HYBRID_GROUP
            or exchange_len != len(exchange)
        ):
            raise ValueError("captured ClientHello key_share geometry drifted")
        exchanges.append(exchange)
    if len(exchanges) != 1:
        raise ValueError(
            f"expected one captured hybrid key share, found {len(exchanges)}"
        )
    return exchanges[0]


def decrypt_attempt(
    record: bytes,
    key: bytes,
    iv: bytes,
    sequence: int,
    *,
    reveal_content: bool = True,
) -> dict[str, Any]:
    try:
        inner_type, content = PROBE.ORACLE.decrypt_record(
            key,
            iv,
            sequence,
            record,
        )
    except Exception as error:  # diagnostic includes the rejected epoch
        return {
            "authenticated": False,
            "error": f"{type(error).__name__}: {error}",
        }
    result = {
        "authenticated": True,
        "inner_type": inner_type,
        "content_bytes": len(content),
        "content_sha256": sha256(content),
    }
    if reveal_content:
        result["content_hex"] = content.hex()
    else:
        result["content_redacted"] = True
    return result


def parse_new_session_ticket(message: bytes) -> dict[str, Any]:
    """Parse one exact NST while keeping its bearer material out of JSON."""

    if len(message) < 4 or message[0] != HS_NEW_SESSION_TICKET:
        raise ValueError("not a NewSessionTicket handshake message")
    declared = int.from_bytes(message[1:4], "big")
    if declared != len(message) - 4:
        raise ValueError("NewSessionTicket handshake length mismatch")
    body = message[4:]
    if len(body) < 13:
        raise ValueError("short NewSessionTicket")

    lifetime_bytes = body[:4]
    age_add_bytes = body[4:8]
    lifetime = int.from_bytes(lifetime_bytes, "big")
    nonce_len = body[8]
    offset = 9
    if offset + nonce_len + 2 > len(body):
        raise ValueError("truncated NewSessionTicket nonce")
    nonce = body[offset : offset + nonce_len]
    offset += nonce_len

    identity_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if offset + identity_len + 2 > len(body):
        raise ValueError("truncated NewSessionTicket identity")
    identity = body[offset : offset + identity_len]
    offset += identity_len

    extensions_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if offset + extensions_len != len(body):
        raise ValueError("NewSessionTicket extension length mismatch")
    extensions = body[offset:]
    extension_descriptors: list[dict[str, Any]] = []
    extension_offset = 0
    while extension_offset < len(extensions):
        if extension_offset + 4 > len(extensions):
            raise ValueError("truncated NewSessionTicket extension header")
        extension_type = int.from_bytes(
            extensions[extension_offset : extension_offset + 2], "big"
        )
        extension_len = int.from_bytes(
            extensions[extension_offset + 2 : extension_offset + 4], "big"
        )
        extension_offset += 4
        if extension_offset + extension_len > len(extensions):
            raise ValueError("truncated NewSessionTicket extension value")
        extension_value = extensions[
            extension_offset : extension_offset + extension_len
        ]
        extension_descriptors.append(
            {
                "type": extension_type,
                "value_bytes": extension_len,
                "value_sha256": sha256(extension_value),
            }
        )
        extension_offset += extension_len

    if not extension_descriptors:
        extension_profile = "empty"
        supported_extension_profile = True
    elif (
        len(extension_descriptors) == 1
        and extension_descriptors[0]["type"] == 42
        and extension_descriptors[0]["value_bytes"] == 4
    ):
        extension_profile = "early_data_only"
        supported_extension_profile = True
    elif (
        len(extension_descriptors) == 2
        and extension_descriptors[0]["type"] == 42
        and extension_descriptors[0]["value_bytes"] == 4
        and extension_descriptors[1]["type"] != 42
        and extension_descriptors[1]["value_bytes"] == 0
    ):
        extension_profile = "early_data_then_zero_length_unknown"
        supported_extension_profile = True
    else:
        extension_profile = "unsupported"
        supported_extension_profile = False

    message_bound_violations = []
    if len(message) > SEED_NST_MESSAGE_MAX:
        message_bound_violations.append("message_over_384_bytes")
    if not 1 <= lifetime <= SEED_NST_LIFETIME_MAX:
        message_bound_violations.append("lifetime_outside_1_to_604800")
    if not 1 <= nonce_len <= SEED_NST_NONCE_MAX:
        message_bound_violations.append("nonce_outside_1_to_32_bytes")
    if not 1 <= identity_len <= SEED_NST_IDENTITY_MAX:
        message_bound_violations.append("identity_outside_1_to_192_bytes")
    if not supported_extension_profile:
        message_bound_violations.append(
            "extensions_outside_selected_nst_profile"
        )

    return {
        "message_bytes": len(message),
        "message_sha256": sha256(message),
        "lifetime_seconds": lifetime,
        "lifetime_encoded_bytes": len(lifetime_bytes),
        "lifetime_encoded_sha256": sha256(lifetime_bytes),
        "age_add_bytes": len(age_add_bytes),
        "age_add_sha256": sha256(age_add_bytes),
        "nonce_bytes": nonce_len,
        "nonce_sha256": sha256(nonce),
        "identity_bytes": identity_len,
        "identity_sha256": sha256(identity),
        "extensions_bytes": extensions_len,
        "extensions_sha256": sha256(extensions),
        "extension_profile": extension_profile,
        "extension_types": [
            descriptor["type"] for descriptor in extension_descriptors
        ],
        "extensions": extension_descriptors,
        "message_within_seed_bounds": not message_bound_violations,
        "message_bound_violations": message_bound_violations,
    }


def describe_http(content: bytes) -> dict[str, Any]:
    first_line_end = content.find(b"\r\n", 0, 160)
    first_line = content[:first_line_end] if first_line_end >= 0 else b""
    starts_response = first_line.startswith(b"HTTP/")
    status_code = None
    if starts_response:
        fields = first_line.split(b" ", 2)
        if len(fields) >= 2 and len(fields[1]) == 3 and fields[1].isdigit():
            status_code = int(fields[1])
    return {
        "starts_http_response": starts_response,
        "status_code": status_code,
        "header_terminator_present": b"\r\n\r\n" in content,
    }


def describe_alert(content: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "well_formed": len(content) == 2,
    }
    if len(content) == 2:
        level, description = content
        result.update(
            {
                "level": level,
                "level_name": ALERT_LEVEL_NAMES.get(level, "unknown"),
                "description": description,
                "description_name": ALERT_DESCRIPTION_NAMES.get(
                    description, "unknown"
                ),
            }
        )
    return result


def post_finished_server_ledger(
    records: list[tuple[int, int, int, bytes]],
    *,
    key: bytes,
    iv: bytes,
    server_times: list[float],
    syn_time: float,
    client_finished_time: float,
    client_head_time: float | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Authenticate and classify every post-protected server record in order."""

    def append_reason(reasons: list[str], reason: str) -> None:
        if reason not in reasons:
            reasons.append(reason)

    ledger: list[dict[str, Any]] = []
    plaintexts: list[bytes | None] = []
    previous_time: float | None = None
    application_sequence = 0
    for order, (offset, record_type, payload_len, record) in enumerate(records):
        timestamp = server_times[offset]
        item: dict[str, Any] = {
            "order": order,
            "server_application_sequence": None,
            "stream_offset": offset,
            "outer_type": record_type,
            "record_bytes": len(record),
            "record_payload_bytes": payload_len,
            "record_sha256": sha256(record),
            "timestamp": timestamp,
            "syn_to_record_seconds": timestamp - syn_time,
            "client_finished_to_record_seconds": (
                timestamp - client_finished_time
            ),
            "previous_record_to_record_seconds": (
                None if previous_time is None else timestamp - previous_time
            ),
            "client_head_to_record_seconds": (
                None
                if client_head_time is None
                else timestamp - client_head_time
            ),
        }
        previous_time = timestamp

        if record_type != TLS_APPLICATION_DATA:
            item.update(
                {
                    "authentication_attempted": False,
                    "authenticated": False,
                    "classification": "target_incompatible_outer_record",
                    "target_acceptable": False,
                    "target_rejection_reasons": [
                        "post_protected_outer_type_not_application_data"
                    ],
                }
            )
            plaintexts.append(None)
            ledger.append(item)
            continue

        sequence = application_sequence
        application_sequence += 1
        item["server_application_sequence"] = sequence
        item["authentication_attempted"] = True
        try:
            inner_type, content = PROBE.ORACLE.decrypt_record(
                key,
                iv,
                sequence,
                record,
            )
        except Exception as error:
            item.update(
                {
                    "authenticated": False,
                    "error": f"{type(error).__name__}: {error}",
                    "classification": "authentication_failure",
                    "target_acceptable": False,
                    "target_rejection_reasons": ["authentication_failure"],
                }
            )
            plaintexts.append(None)
        else:
            item.update(
                {
                    "authenticated": True,
                    "inner_type": inner_type,
                    "inner_type_name": INNER_TYPE_NAMES.get(
                        inner_type, "unknown"
                    ),
                    "content_bytes": len(content),
                    "content_sha256": sha256(content),
                }
            )
            if inner_type == TLS_APPLICATION_DATA:
                item.update(
                    {
                        "classification": "http",
                        "http": describe_http(content),
                        "target_acceptable": True,
                        "target_rejection_reasons": [],
                    }
                )
            elif inner_type == TLS_ALERT:
                item.update(
                    {
                        "classification": "alert",
                        "alert": describe_alert(content),
                        "target_acceptable": False,
                        "target_rejection_reasons": [
                            "post_finished_alert_rejected"
                        ],
                    }
                )
            elif inner_type == TLS_HANDSHAKE:
                item["classification"] = "post_handshake"
            else:
                item.update(
                    {
                        "classification": "unknown_inner_type",
                        "target_acceptable": False,
                        "target_rejection_reasons": [
                            "unsupported_post_finished_inner_type"
                        ],
                    }
                )
            plaintexts.append(content)
        ledger.append(item)

    tickets: list[dict[str, Any]] = []
    observed_nst_count = 0
    for record_index, item in enumerate(ledger):
        if (
            not item.get("authenticated")
            or item.get("inner_type") != TLS_HANDSHAKE
        ):
            continue
        content = plaintexts[record_index]
        assert content is not None
        record_reasons: list[str] = []
        descriptors: list[dict[str, Any]] = []
        record_ticket_start = len(tickets)
        record_nst_count = 0
        message_offset = 0

        if not content:
            item["post_handshake_error"] = (
                "record contains no post-handshake message"
            )
            append_reason(
                record_reasons,
                "handshake_record_contains_no_complete_message",
            )

        while message_offset < len(content):
            remaining = len(content) - message_offset
            if remaining < 4:
                item["post_handshake_error"] = (
                    "record ends in a partial post-handshake header"
                )
                item["trailing_post_handshake_fragment_bytes"] = remaining
                append_reason(
                    record_reasons,
                    "post_handshake_message_incomplete_in_record",
                )
                break

            message_len = int.from_bytes(
                content[message_offset + 1 : message_offset + 4],
                "big",
            )
            total_len = 4 + message_len
            if total_len > POST_HANDSHAKE_MESSAGE_MAX:
                item["post_handshake_error"] = (
                    "declared message exceeds offline bound"
                )
                append_reason(
                    record_reasons,
                    "post_handshake_message_exceeds_offline_bound",
                )
                break
            message_end = message_offset + total_len
            if message_end > len(content):
                item["post_handshake_error"] = (
                    "post-handshake message crosses its record boundary"
                )
                item["trailing_post_handshake_fragment_bytes"] = remaining
                append_reason(
                    record_reasons,
                    "post_handshake_message_incomplete_in_record",
                )
                break

            message = content[message_offset:message_end]
            descriptor: dict[str, Any] = {
                "handshake_type": message[0],
                "handshake_type_name": HANDSHAKE_TYPE_NAMES.get(
                    message[0], "unknown"
                ),
                "message_bytes": len(message),
                "message_sha256": sha256(message),
                "server_application_sequence": item[
                    "server_application_sequence"
                ],
                "record_message_index": len(descriptors),
            }
            if message[0] != HS_NEW_SESSION_TICKET:
                append_reason(
                    record_reasons,
                    "post_handshake_record_contains_non_nst_message",
                )
            else:
                record_nst_count += 1
                observed_nst_count += 1
                descriptor["connection_ticket_number"] = observed_nst_count
                try:
                    ticket = parse_new_session_ticket(message)
                except ValueError as error:
                    descriptor["new_session_ticket_error"] = str(error)
                    append_reason(
                        record_reasons,
                        "malformed_new_session_ticket",
                    )
                else:
                    descriptor["new_session_ticket"] = ticket
                    if not ticket["message_within_seed_bounds"]:
                        append_reason(
                            record_reasons,
                            "new_session_ticket_outside_message_bounds",
                        )
                    tickets.append(
                        {
                            "ticket_order": len(tickets),
                            "connection_ticket_number": observed_nst_count,
                            "server_application_sequence": item[
                                "server_application_sequence"
                            ],
                            "record_message_index": len(descriptors),
                            **ticket,
                        }
                    )
            descriptors.append(descriptor)
            message_offset = message_end

        if descriptors:
            item["completed_post_handshake_messages"] = descriptors
        item["post_handshake_message_count"] = len(descriptors)
        item["new_session_ticket_message_count"] = record_nst_count
        item["cumulative_new_session_ticket_message_count"] = (
            observed_nst_count
        )
        if observed_nst_count > SEED_NST_CONNECTION_MAX:
            append_reason(
                record_reasons,
                "connection_new_session_ticket_limit_exceeded",
            )

        target_acceptable = not record_reasons and record_nst_count > 0
        item["target_acceptable"] = target_acceptable
        item["target_rejection_reasons"] = record_reasons
        item["classification"] = (
            "new_session_ticket"
            if target_acceptable
            else "target_incompatible_post_handshake"
        )
        for descriptor in descriptors:
            descriptor["target_acceptable"] = target_acceptable
            descriptor["target_rejection_reasons"] = list(record_reasons)
        for ticket in tickets[record_ticket_start:]:
            ticket["target_acceptable"] = target_acceptable
            ticket["target_rejection_reasons"] = list(record_reasons)

    return ledger, tickets


def analyze(
    path: Path,
    *,
    manifest_path: Path = LIVE_MANIFEST,
    core_path: Path = LIVE_CORE,
) -> dict[str, Any]:
    live_flows = []
    for flow in PCAP.collect_flows(path):
        client_stream, _client_times = flow.client_stream.contiguous()
        if PCAP.is_live_client_hello(client_stream):
            live_flows.append(flow)
    if len(live_flows) != 1:
        raise ValueError(
            f"expected exactly one live Seed flow, found {len(live_flows)}"
        )

    flow = live_flows[0]
    client_stream, client_times = flow.client_stream.contiguous()
    server_stream, server_times = flow.server_stream.contiguous()
    client_records = full_records(client_stream)
    server_records = full_records(server_stream)
    if (
        len(client_records) < 2
        or client_records[0][1] != PROBE.TLS_HANDSHAKE
        or len(server_records) < 3
        or server_records[0][1] != PROBE.TLS_HANDSHAKE
    ):
        raise ValueError("captured TLS record sequence is incomplete")

    client_hello = client_records[0][3][5:]
    server_hello = server_records[0][3][5:]
    exchange = client_hybrid_exchange(client_hello)
    if len(exchange) != PROBE.MLKEM_PUBLIC_LEN + PROBE.X25519_LEN:
        raise ValueError("captured client hybrid exchange length drifted")

    entropy_meta = ENTROPY_FIXTURE.read_bytes()
    hello_fixture = HELLO_FIXTURE.read_bytes()
    if len(entropy_meta) != 512 or len(hello_fixture) != 512:
        raise ValueError("public input fixture is not one sector")
    d_z = entropy_meta[98:162]
    random_session = hello_fixture[:64]
    public_fixture = (d_z + random_session).ljust(512, b"\0")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    public_phase = manifest_phase(manifest, "public_fixture")
    if (
        public_phase.get("bytes") != 512
        or public_phase.get("destination") != "0x0700"
        or public_phase.get("sha256") != sha256(public_fixture)
    ):
        raise ValueError("manifest public-fixture binding drifted")
    phase_offset = int(public_phase["start_sector"]) * 512
    core = core_path.read_bytes()
    if core[phase_offset : phase_offset + 512] != public_fixture:
        raise ValueError("live core public-fixture sector differs from manifest")

    if client_hello[6:38] != random_session[:32]:
        raise ValueError("captured ClientHello random differs from fixture")
    if client_hello[38] != 32 or client_hello[39:71] != random_session[32:]:
        raise ValueError("captured ClientHello session ID differs from fixture")

    dk = KEYGEN.fips_keygen_internal(d_z)
    expected_public = dk[1152:2336]
    expected_u9 = b"\x09" + bytes(31)
    if exchange[: PROBE.MLKEM_PUBLIC_LEN] != expected_public:
        raise ValueError("captured ClientHello does not use the fixture ML-KEM key")
    if exchange[PROBE.MLKEM_PUBLIC_LEN :] != expected_u9:
        raise ValueError("captured ClientHello does not use canonical u=9")

    ciphertext, server_x = PROBE.parse_server_hybrid_share(server_hello)
    _message, candidate_g = MLKEM.k_pke_decrypt(dk, ciphertext)
    shared_secret = candidate_g[:32] + server_x
    hello_transcript = client_hello + server_hello
    handshake = PROBE.derive_handshake(shared_secret, hello_transcript)

    (
        compatibility_ccs_entries,
        protected_entry,
        later_server_entries,
    ) = split_target_server_flight(server_records[1:])
    protected_offset, _protected_type, _protected_len, protected_record = (
        protected_entry
    )
    inner_type, protected_content = PROBE.ORACLE.decrypt_record(
        handshake["server_key"],
        handshake["server_iv"],
        0,
        protected_record,
    )
    if inner_type != PROBE.TLS_HANDSHAKE:
        raise ValueError("protected server flight is not handshake content")
    messages = PROBE.parse_handshake_messages(protected_content)
    if not messages or messages[-1][0] != PROBE.HS_FINISHED:
        raise ValueError("server Finished is not final in the protected flight")
    before_finished = hello_transcript + b"".join(messages[:-1])
    server_finished = messages[-1]
    expected_server_verify = hmac.new(
        handshake["server_finished"],
        hashlib.sha256(before_finished).digest(),
        hashlib.sha256,
    ).digest()
    server_finished_matches = hmac.compare_digest(
        server_finished[4:],
        expected_server_verify,
    )
    through_server_finished = before_finished + server_finished

    expected_client_verify = hmac.new(
        handshake["client_finished"],
        hashlib.sha256(through_server_finished).digest(),
        hashlib.sha256,
    ).digest()
    client_finished_message = PROBE.handshake_message(
        PROBE.HS_FINISHED,
        expected_client_verify,
    )
    expected_client_record = PROBE.ORACLE.encrypted_record(
        handshake["client_key"],
        handshake["client_iv"],
        0,
        PROBE.TLS_HANDSHAKE,
        client_finished_message,
    )
    captured_client_record = client_records[1][3]
    client_finished_offset = client_records[1][0]

    application = PROBE.derive_application(
        handshake["handshake"],
        through_server_finished,
    )

    captured_head = client_records[2][3] if len(client_records) >= 3 else None
    captured_head_offset = client_records[2][0] if len(client_records) >= 3 else None
    client_finished_time = client_times[client_finished_offset]
    client_head_time = (
        client_times[captured_head_offset]
        if captured_head_offset is not None
        else None
    )

    first_post_entry = (
        later_server_entries[0] if later_server_entries else None
    )
    first_post_offset = (
        first_post_entry[0] if first_post_entry is not None else None
    )
    first_post = first_post_entry[3] if first_post_entry is not None else None
    post_ledger, new_session_tickets = post_finished_server_ledger(
        later_server_entries,
        key=application["server_key"],
        iv=application["server_iv"],
        server_times=server_times,
        syn_time=flow.first_timestamp,
        client_finished_time=client_finished_time,
        client_head_time=client_head_time,
    )
    post_decrypt: dict[str, Any] | None = None
    if first_post is not None:
        post_decrypt = {
            "outer_type": first_post_entry[1],
            "record_bytes": len(first_post),
            "record_payload_bytes": len(first_post) - 5,
            "target_compatible_outer_type": (
                first_post_entry[1] == TLS_APPLICATION_DATA
            ),
        }
        if first_post_entry[1] == TLS_APPLICATION_DATA:
            post_decrypt.update(
                {
                    "server_application_sequence_0": decrypt_attempt(
                        first_post,
                        application["server_key"],
                        application["server_iv"],
                        0,
                        reveal_content=False,
                    ),
                    "server_handshake_sequence_1": decrypt_attempt(
                        first_post,
                        handshake["server_key"],
                        handshake["server_iv"],
                        1,
                        reveal_content=False,
                    ),
                }
            )

    head_decrypt = (
        decrypt_attempt(
            captured_head,
            application["client_key"],
            application["client_iv"],
            0,
        )
        if captured_head is not None
        else None
    )

    captured_matches = (
        len(captured_client_record) == len(expected_client_record)
        and hmac.compare_digest(captured_client_record, expected_client_record)
    )
    first_difference = next(
        (
            index
            for index, (captured, expected) in enumerate(
                zip(captured_client_record, expected_client_record)
            )
            if captured != expected
        ),
        None,
    )
    if (
        first_difference is None
        and len(captured_client_record) != len(expected_client_record)
    ):
        first_difference = min(
            len(captured_client_record),
            len(expected_client_record),
        )

    record_hashes = {
        "client_hello": sha256(client_records[0][3]),
        "server_hello": sha256(server_records[0][3]),
        "server_protected_flight": sha256(protected_record),
        "client_finished": sha256(captured_client_record),
        "first_post_finished_server": (
            sha256(first_post) if first_post is not None else None
        ),
        "client_head": sha256(captured_head) if captured_head is not None else None,
    }
    source_paths = (
        Path(__file__).resolve(),
        HERE / "live_k15_pcap.py",
        SPIKE / "tls13_hybrid_u9_probe.py",
        SPIKE / "tls13_spike.py",
        SPIKE / "mlkem768_integrated_keygen_check.py",
        SPIKE / "mlkem768_integrated_check.py",
    )
    timing: dict[str, Any] = {
        "tcp_syn": flow.first_timestamp,
        "client_finished": client_finished_time,
        "syn_to_client_finished_seconds": (
            client_finished_time - flow.first_timestamp
        ),
    }
    if first_post_offset is not None:
        timing.update(
            {
                "first_post_finished_server_record": server_times[
                    first_post_offset
                ],
                "client_finished_to_first_server_record_seconds": (
                    server_times[first_post_offset]
                    - client_finished_time
                ),
                "syn_to_first_server_record_seconds": (
                    server_times[first_post_offset] - flow.first_timestamp
                ),
            }
        )
    if captured_head_offset is not None:
        timing.update(
            {
                "client_head": client_head_time,
                "client_finished_to_head_seconds": (
                    client_head_time - client_finished_time
                ),
                "syn_to_head_seconds": (
                    client_head_time - flow.first_timestamp
                ),
            }
        )
        if first_post_offset is not None:
            timing["first_server_record_to_head_seconds"] = (
                client_head_time - server_times[first_post_offset]
            )

    classification_counts = {
        classification: sum(
            item.get("classification") == classification
            for item in post_ledger
        )
        for classification in sorted(
            {
                str(item.get("classification"))
                for item in post_ledger
            }
        )
    }
    observed_nst_count = sum(
        int(item.get("new_session_ticket_message_count", 0))
        for item in post_ledger
    )
    target_acceptable_ticket_count = sum(
        bool(ticket.get("target_acceptable"))
        for ticket in new_session_tickets
    )
    return {
        "schema": "seed-live-k14-capture-oracle-v3",
        "schema_compatibility": [],
        "scope": "offline reconstruction of one deterministic PoC pcap",
        "pcap": str(path),
        "pcap_sha256": sha256(path.read_bytes()),
        "flow": {
            "client": f"{flow.client[0]}:{flow.client[1]}",
            "server": f"{flow.server[0]}:{flow.server[1]}",
            "client_record_payload_lengths": [
                length for _offset, _type, length, _record in client_records
            ],
            "server_record_payload_lengths": [
                length for _offset, _type, length, _record in server_records
            ],
            "server_record_types": [
                record_type
                for _offset, record_type, _length, _record in server_records
            ],
            "record_sha256": record_hashes,
            "timing": timing,
        },
        "fixture": {
            "d_z_sha256": sha256(d_z),
            "random_session_sha256": sha256(random_session),
            "public_fixture_sha256": sha256(public_fixture),
            "manifest_public_fixture_sector": public_phase["start_sector"],
            "core_public_fixture_matches": True,
            "client_random_matches": True,
            "client_session_id_matches": True,
            "client_mlkem_public_matches": True,
            "client_x25519_u9_matches": True,
            "candidate_secret_sha256": sha256(candidate_g[:32]),
        },
        "server_finished": {
            "authenticated_record": True,
            "verify_data_matches": server_finished_matches,
        },
        "server_protected_flight_shape": {
            "target_compatible": True,
            "compatibility_ccs_count": len(compatibility_ccs_entries),
            "compatibility_ccs_stream_offsets": [
                entry[0] for entry in compatibility_ccs_entries
            ],
            "protected_application_stream_offset": protected_offset,
            "post_protected_record_count": len(later_server_entries),
        },
        "client_finished": {
            "captured_sha256": sha256(captured_client_record),
            "expected_sha256": sha256(expected_client_record),
            "exact_match": captured_matches,
            "first_difference": first_difference,
        },
        "first_post_finished_server_record": post_decrypt,
        "post_finished_server_epoch": {
            "protected_handshake_record_stream_offset": protected_offset,
            "record_count": len(post_ledger),
            "all_records_authenticated": (
                bool(post_ledger)
                and all(item["authenticated"] for item in post_ledger)
            ),
            "classification_counts": classification_counts,
            "new_session_ticket_count": len(new_session_tickets),
            "observed_new_session_ticket_message_count": observed_nst_count,
            "target_acceptable_new_session_ticket_count": (
                target_acceptable_ticket_count
            ),
            "all_outer_records_protected": all(
                item["outer_type"] == TLS_APPLICATION_DATA
                for item in post_ledger
            ),
            "target_acceptable": (
                bool(post_ledger)
                and all(item["target_acceptable"] for item in post_ledger)
            ),
            "target_rejection_count": sum(
                not item["target_acceptable"] for item in post_ledger
            ),
        },
        "post_finished_server_records": post_ledger,
        "new_session_tickets": new_session_tickets,
        "captured_head": head_decrypt,
        "provenance": {
            "manifest": str(manifest_path),
            "manifest_sha256": sha256(manifest_path.read_bytes()),
            "core": str(core_path),
            "core_sha256": sha256(core),
            "sources": {
                str(source.relative_to(ROOT)): sha256(source.read_bytes())
                for source in source_paths
            },
        },
        "nonclaims": [
            "No live connection or physical machine is exercised by this checker.",
            "The provisional ML-KEM secret is not a complete FO validation.",
            "A matching Finished does not establish certificate authentication.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", nargs="?", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--manifest", type=Path, default=LIVE_MANIFEST)
    parser.add_argument("--core", type=Path, default=LIVE_CORE)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = analyze(
        args.pcap.resolve(),
        manifest_path=args.manifest.resolve(),
        core_path=args.core.resolve(),
    )
    encoded = json.dumps(result, indent=2) + "\n"
    if args.json_out is not None:
        args.json_out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
