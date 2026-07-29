#!/usr/bin/env python3
"""Offline unit checks for the sequential live-capture oracle."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "seed_test_live_k15_capture_oracle",
    HERE / "live_k15_capture_oracle.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load live_k15_capture_oracle.py")
ORACLE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ORACLE
SPEC.loader.exec_module(ORACLE)


def handshake_message(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def new_session_ticket(
    *,
    nonce: bytes,
    identity: bytes,
    lifetime: int = 3600,
    age_add: int = 0x12345678,
    extensions: bytes = b"\x00\x2a\x00\x04\x00\x00\x38\x00",
) -> bytes:
    body = b"".join(
        (
            lifetime.to_bytes(4, "big"),
            age_add.to_bytes(4, "big"),
            bytes([len(nonce)]),
            nonce,
            len(identity).to_bytes(2, "big"),
            identity,
            len(extensions).to_bytes(2, "big"),
            extensions,
        )
    )
    return handshake_message(ORACLE.HS_NEW_SESSION_TICKET, body)


def record_entry(record: bytes, offset: int = 0) -> tuple[int, int, int, bytes]:
    return offset, record[0], len(record) - 5, record


def encrypted_entries(
    contents: tuple[tuple[int, bytes], ...],
    *,
    key: bytes,
    iv: bytes,
) -> tuple[list[tuple[int, int, int, bytes]], list[float]]:
    records = []
    server_times: list[float] = []
    offset = 0
    for sequence, (inner_type, content) in enumerate(contents):
        record = ORACLE.PROBE.ORACLE.encrypted_record(
            key,
            iv,
            sequence,
            inner_type,
            content,
        )
        records.append(record_entry(record, offset))
        server_times.extend([100.0 + sequence] * len(record))
        offset += len(record)
    return records, server_times


def ledger_records(
    records: list[tuple[int, int, int, bytes]],
    server_times: list[float],
    *,
    key: bytes,
    iv: bytes,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    return ORACLE.post_finished_server_ledger(
        records,
        key=key,
        iv=iv,
        server_times=server_times,
        syn_time=90.0,
        client_finished_time=98.0,
        client_head_time=99.0,
    )


class CaptureOracleTest(unittest.TestCase):
    def test_two_complete_tickets_in_one_record_then_http(self) -> None:
        key = bytes(range(32))
        iv = bytes(range(12))
        first_nonce = b"nonce-1"
        first_identity = b"opaque-ticket-identity-1"
        first_ticket = new_session_ticket(
            nonce=first_nonce,
            identity=first_identity,
        )
        second_ticket = new_session_ticket(
            nonce=b"nonce-2",
            identity=b"opaque-ticket-identity-2",
        )
        contents = (
            (ORACLE.TLS_HANDSHAKE, first_ticket + second_ticket),
            (ORACLE.TLS_APPLICATION_DATA, b"HTTP/1.1 401 Nope\r\n\r\n"),
        )
        records, server_times = encrypted_entries(
            contents,
            key=key,
            iv=iv,
        )
        ledger, tickets = ledger_records(
            records,
            server_times,
            key=key,
            iv=iv,
        )

        self.assertTrue(all(item["authenticated"] for item in ledger))
        self.assertEqual(
            [item["classification"] for item in ledger],
            ["new_session_ticket", "http"],
        )
        self.assertTrue(all(item["target_acceptable"] for item in ledger))
        self.assertEqual(ledger[0]["post_handshake_message_count"], 2)
        self.assertEqual(ledger[0]["new_session_ticket_message_count"], 2)
        self.assertTrue(
            all(
                descriptor["target_acceptable"]
                for descriptor in ledger[0][
                    "completed_post_handshake_messages"
                ]
            )
        )
        self.assertEqual(ledger[1]["http"]["status_code"], 401)
        self.assertEqual(len(tickets), 2)
        parsed = tickets[0]
        self.assertEqual(parsed["server_application_sequence"], 0)
        self.assertEqual(parsed["record_message_index"], 0)
        self.assertEqual(parsed["nonce_bytes"], len(first_nonce))
        self.assertEqual(parsed["nonce_sha256"], ORACLE.sha256(first_nonce))
        self.assertEqual(parsed["identity_bytes"], len(first_identity))
        self.assertEqual(
            parsed["identity_sha256"],
            ORACLE.sha256(first_identity),
        )
        self.assertTrue(parsed["message_within_seed_bounds"])
        self.assertTrue(parsed["target_acceptable"])
        for secret_field in ("nonce", "identity", "age_add"):
            self.assertNotIn(secret_field, parsed)

    def test_target_server_flight_accepts_only_exact_optional_ccs(self) -> None:
        protected = b"\x17\x03\x03\x00\x01x"
        later = b"\x15\x03\x03\x00\x02\x02\x00"
        protected_entry = record_entry(protected, 10)
        later_entry = record_entry(later, 16)
        ccs_entry = record_entry(ORACLE.COMPATIBILITY_CCS_RECORD, 4)

        ccs, selected, post = ORACLE.split_target_server_flight(
            [protected_entry, later_entry]
        )
        self.assertEqual(ccs, [])
        self.assertEqual(selected, protected_entry)
        self.assertEqual(post, [later_entry])

        ccs, selected, post = ORACLE.split_target_server_flight(
            [ccs_entry, protected_entry, later_entry]
        )
        self.assertEqual(ccs, [ccs_entry])
        self.assertEqual(selected, protected_entry)
        self.assertEqual(post, [later_entry])

        malformed_ccs = record_entry(b"\x14\x03\x03\x00\x01\x02")
        bad_version = record_entry(b"\x17\x03\x01\x00\x01x")
        cases = (
            ([malformed_ccs, protected_entry], "CCS is not exact"),
            ([ccs_entry, ccs_entry, protected_entry], "duplicate"),
            ([later_entry, protected_entry], "expected protected"),
            ([ccs_entry], "lacks a protected"),
            ([bad_version], "bad legacy version"),
        )
        for records, error in cases:
            with self.subTest(error=error):
                with self.assertRaisesRegex(ValueError, error):
                    ORACLE.split_target_server_flight(records)

    def test_post_protected_non_application_record_stays_in_ledger(self) -> None:
        key = bytes(range(32))
        iv = bytes(range(12))
        ticket = new_session_ticket(nonce=b"n", identity=b"opaque")
        first = ORACLE.PROBE.ORACLE.encrypted_record(
            key,
            iv,
            0,
            ORACLE.TLS_HANDSHAKE,
            ticket,
        )
        incompatible = b"\x15\x03\x03\x00\x02\x02\x00"
        third = ORACLE.PROBE.ORACLE.encrypted_record(
            key,
            iv,
            1,
            ORACLE.TLS_APPLICATION_DATA,
            b"HTTP/1.1 401 Nope\r\n\r\n",
        )
        records = []
        server_times: list[float] = []
        offset = 0
        for order, record in enumerate((first, incompatible, third)):
            records.append(record_entry(record, offset))
            server_times.extend([100.0 + order] * len(record))
            offset += len(record)

        ledger, tickets = ledger_records(
            records,
            server_times,
            key=key,
            iv=iv,
        )

        self.assertEqual([item["order"] for item in ledger], [0, 1, 2])
        self.assertEqual(
            [item["server_application_sequence"] for item in ledger],
            [0, None, 1],
        )
        self.assertEqual(
            [item["classification"] for item in ledger],
            [
                "new_session_ticket",
                "target_incompatible_outer_record",
                "http",
            ],
        )
        self.assertFalse(ledger[1]["authentication_attempted"])
        self.assertFalse(ledger[1]["target_acceptable"])
        self.assertIn(
            "post_protected_outer_type_not_application_data",
            ledger[1]["target_rejection_reasons"],
        )
        self.assertTrue(ledger[2]["authenticated"])
        self.assertEqual(len(tickets), 1)
        self.assertTrue(tickets[0]["target_acceptable"])

    def test_fragmented_ticket_is_not_target_acceptable(self) -> None:
        key = bytes(range(32))
        iv = bytes(range(12))
        ticket = new_session_ticket(nonce=b"nonce", identity=b"opaque")
        records, server_times = encrypted_entries(
            (
                (ORACLE.TLS_HANDSHAKE, ticket[:11]),
                (ORACLE.TLS_HANDSHAKE, ticket[11:]),
            ),
            key=key,
            iv=iv,
        )

        ledger, tickets = ledger_records(
            records,
            server_times,
            key=key,
            iv=iv,
        )

        self.assertEqual(tickets, [])
        self.assertEqual(
            [item["classification"] for item in ledger],
            [
                "target_incompatible_post_handshake",
                "target_incompatible_post_handshake",
            ],
        )
        self.assertTrue(
            all(not item["target_acceptable"] for item in ledger)
        )
        self.assertIn(
            "post_handshake_message_incomplete_in_record",
            ledger[0]["target_rejection_reasons"],
        )

    def test_post_handshake_record_must_be_nst_only(self) -> None:
        key = bytes(range(32))
        iv = bytes(range(12))
        ticket = new_session_ticket(nonce=b"n", identity=b"opaque")
        key_update = handshake_message(24, b"\x00")
        records, server_times = encrypted_entries(
            ((ORACLE.TLS_HANDSHAKE, ticket + key_update),),
            key=key,
            iv=iv,
        )

        ledger, tickets = ledger_records(
            records,
            server_times,
            key=key,
            iv=iv,
        )

        self.assertEqual(len(tickets), 1)
        self.assertTrue(tickets[0]["message_within_seed_bounds"])
        self.assertFalse(tickets[0]["target_acceptable"])
        self.assertFalse(ledger[0]["target_acceptable"])
        self.assertEqual(ledger[0]["post_handshake_message_count"], 2)
        self.assertTrue(
            all(
                not descriptor["target_acceptable"]
                for descriptor in ledger[0][
                    "completed_post_handshake_messages"
                ]
            )
        )
        self.assertIn(
            "post_handshake_record_contains_non_nst_message",
            ledger[0]["target_rejection_reasons"],
        )

    def test_connection_wide_four_ticket_limit(self) -> None:
        key = bytes(range(32))
        iv = bytes(range(12))
        tickets_on_wire = [
            new_session_ticket(
                nonce=bytes([number]),
                identity=f"ticket-{number}".encode(),
            )
            for number in range(1, 6)
        ]
        records, server_times = encrypted_entries(
            (
                (
                    ORACLE.TLS_HANDSHAKE,
                    b"".join(tickets_on_wire[:4]),
                ),
                (ORACLE.TLS_HANDSHAKE, tickets_on_wire[4]),
            ),
            key=key,
            iv=iv,
        )

        ledger, tickets = ledger_records(
            records,
            server_times,
            key=key,
            iv=iv,
        )

        self.assertEqual(len(tickets), 5)
        self.assertTrue(ledger[0]["target_acceptable"])
        self.assertFalse(ledger[1]["target_acceptable"])
        self.assertEqual(
            ledger[1]["cumulative_new_session_ticket_message_count"],
            5,
        )
        self.assertTrue(
            all(ticket["target_acceptable"] for ticket in tickets[:4])
        )
        self.assertFalse(tickets[4]["target_acceptable"])
        self.assertIn(
            "connection_new_session_ticket_limit_exceeded",
            tickets[4]["target_rejection_reasons"],
        )

    def test_target_bound_report_does_not_expose_identity(self) -> None:
        identity = bytes(range(193))
        ticket = new_session_ticket(nonce=b"n", identity=identity)
        parsed = ORACLE.parse_new_session_ticket(ticket)
        self.assertFalse(parsed["message_within_seed_bounds"])
        self.assertIn(
            "identity_outside_1_to_192_bytes",
            parsed["message_bound_violations"],
        )
        self.assertNotIn("within_seed_bounds", parsed)
        self.assertNotIn("seed_bound_violations", parsed)
        self.assertNotIn("target_acceptable", parsed)
        self.assertNotIn(identity.hex(), str(parsed))

        oversized = ORACLE.parse_new_session_ticket(
            new_session_ticket(nonce=b"n", identity=b"x" * 360)
        )
        self.assertGreater(
            oversized["message_bytes"],
            ORACLE.SEED_NST_MESSAGE_MAX,
        )
        self.assertIn(
            "message_over_384_bytes",
            oversized["message_bound_violations"],
        )

        key = bytes(range(32))
        iv = bytes(range(12))
        records, server_times = encrypted_entries(
            ((ORACLE.TLS_HANDSHAKE, ticket),),
            key=key,
            iv=iv,
        )
        ledger, tickets = ledger_records(
            records,
            server_times,
            key=key,
            iv=iv,
        )
        self.assertFalse(ledger[0]["target_acceptable"])
        self.assertFalse(tickets[0]["target_acceptable"])
        self.assertIn(
            "new_session_ticket_outside_message_bounds",
            tickets[0]["target_rejection_reasons"],
        )

    def test_early_data_then_zero_length_unknown_extension(self) -> None:
        unknown_type = 0x3A3A
        unknown_value = b""
        extensions = b"".join(
            (
                b"\x00\x2a\x00\x04\x00\x00\x38\x00",
                unknown_type.to_bytes(2, "big"),
                len(unknown_value).to_bytes(2, "big"),
                unknown_value,
            )
        )
        ticket = new_session_ticket(
            nonce=b"n",
            identity=b"opaque",
            extensions=extensions,
        )
        parsed = ORACLE.parse_new_session_ticket(ticket)
        self.assertTrue(parsed["message_within_seed_bounds"])
        self.assertEqual(
            parsed["extension_profile"],
            "early_data_then_zero_length_unknown",
        )
        self.assertEqual(parsed["extension_types"], [42, unknown_type])
        self.assertEqual(
            parsed["extensions"][1],
            {
                "type": unknown_type,
                "value_bytes": 0,
                "value_sha256": ORACLE.sha256(unknown_value),
            },
        )
        self.assertNotIn("value", parsed["extensions"][1])

        bad_extensions = (
            b"\x00\x2a\x00\x04\x00\x00\x38\x00"
            + unknown_type.to_bytes(2, "big")
            + b"\x00\x01x"
        )
        bad = ORACLE.parse_new_session_ticket(
            new_session_ticket(
                nonce=b"n",
                identity=b"opaque",
                extensions=bad_extensions,
            )
        )
        self.assertFalse(bad["message_within_seed_bounds"])
        self.assertEqual(bad["extension_profile"], "unsupported")


if __name__ == "__main__":
    unittest.main()
