#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ANALYZER_PATH = HERE / "live_286_pcap.py"
SPEC = importlib.util.spec_from_file_location("seed_live_286_pcap", ANALYZER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {ANALYZER_PATH}")
ANALYZER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ANALYZER
SPEC.loader.exec_module(ANALYZER)


class Live286PcapTests(unittest.TestCase):
    def analyze_fixture(self, expect: str, **options: object) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / f"{expect}.pcap"
            ANALYZER.fixture_capture(path, expect=expect, **options)
            result = ANALYZER.analyze(path, expect=expect)
            json.dumps(result)
            return result

    def test_reuse_requires_one_pair_and_two_dialogue_rounds(self) -> None:
        result = self.analyze_fixture("reuse")
        self.assertTrue(result["passed"], result)
        self.assertEqual(
            result["actual_roles"],
            ["acquisition", "resumption-use"],
        )
        self.assertTrue(result["application_connection_reuse_observed"])
        self.assertTrue(result["tls_ticket_resumption_expected"])
        self.assertTrue(result["handshake_deadlines_met"])
        acquisition = result["flows"][0]  # type: ignore[index]
        self.assertTrue(acquisition["client_finished_present"])
        self.assertTrue(
            acquisition["credential_free_head_ciphertext_shape_observed"]
        )
        self.assertTrue(acquisition["post_handshake_ciphertext_observed"])
        self.assertTrue(acquisition["client_initiated_clean_close"])
        resumed = result["flows"][1]  # type: ignore[index]
        self.assertTrue(
            resumed["client_hello"]["pre_shared_key_offered"]  # type: ignore[index]
        )
        self.assertTrue(resumed["server_hello"]["psk_resumption_selected"])  # type: ignore[index]
        self.assertEqual(
            resumed["encrypted_application_rounds"],
            2,
        )
        self.assertFalse(
            resumed["encrypted_application_response_pending"]
        )

    def test_pending_final_response_does_not_count_as_completed_round(self) -> None:
        result = self.analyze_fixture("reuse", pending_final_response=True)
        self.assertFalse(result["passed"])
        resumed = result["flows"][1]  # type: ignore[index]
        self.assertEqual(resumed["encrypted_application_rounds"], 1)
        self.assertTrue(resumed["encrypted_application_response_pending"])
        self.assertEqual(resumed["status"], "pending-application-response")

    def test_bounded_reconnect_is_exactly_two_route_pairs(self) -> None:
        result = self.analyze_fixture("reconnect")
        self.assertTrue(result["passed"], result)
        self.assertEqual(
            result["actual_roles"],
            [
                "acquisition",
                "resumption-use",
                "acquisition",
                "resumption-use",
            ],
        )
        self.assertEqual(result["identified_seed_flows"], 4)
        self.assertTrue(result["bounded_one_reconnect_observed"])

    def test_late_client_finished_fails_deadline(self) -> None:
        result = self.analyze_fixture("reuse", late=True)
        self.assertFalse(result["passed"])
        self.assertFalse(result["handshake_deadlines_met"])
        self.assertFalse(result["flows"][1]["deadline_met"])  # type: ignore[index]

    def test_reused_public_shares_fail_independence(self) -> None:
        result = self.analyze_fixture("reuse", duplicate_shares=True)
        self.assertFalse(result["passed"])
        independence = result["client_hello_independence"]
        self.assertFalse(independence["mlkem"])  # type: ignore[index]
        self.assertFalse(independence["x25519"])  # type: ignore[index]
        self.assertFalse(independence["session"])  # type: ignore[index]

    def test_acquisition_must_close_before_resumption_connection(self) -> None:
        result = self.analyze_fixture("reuse", missing_acquisition_close=True)
        self.assertFalse(result["passed"])
        self.assertEqual(
            result["flows"][0]["status"],  # type: ignore[index]
            "acquisition-did-not-cleanly-close-after-post-handshake-traffic",
        )

    def test_server_close_does_not_satisfy_acquisition_client_close(self) -> None:
        result = self.analyze_fixture("reuse", acquisition_server_close=True)
        self.assertFalse(result["passed"])
        acquisition = result["flows"][0]  # type: ignore[index]
        self.assertIsNone(acquisition["client_close_timestamp"])
        self.assertIsNotNone(acquisition["server_close_timestamp"])
        self.assertFalse(acquisition["client_initiated_clean_close"])
        self.assertEqual(
            acquisition["status"],
            "acquisition-did-not-cleanly-close-after-post-handshake-traffic",
        )

    def test_acquisition_requires_finished_head_and_post_handshake_traffic(self) -> None:
        missing_finished = self.analyze_fixture(
            "reuse",
            missing_acquisition_finished=True,
        )
        self.assertFalse(missing_finished["passed"])
        self.assertEqual(
            missing_finished["flows"][0]["status"],  # type: ignore[index]
            "missing-client-finished",
        )

        missing_post = self.analyze_fixture(
            "reuse",
            missing_acquisition_post_handshake=True,
        )
        self.assertFalse(missing_post["passed"])
        self.assertEqual(
            missing_post["flows"][0]["status"],  # type: ignore[index]
            "missing-post-finished-server-record",
        )

    def test_extra_same_endpoint_attempts_break_bounded_reconnect(self) -> None:
        for kind in ("syn-only", "incomplete", "malformed"):
            with self.subTest(kind=kind):
                result = self.analyze_fixture("reconnect", extra_attempt=kind)
                self.assertFalse(result["passed"])
                self.assertFalse(result["bounded_one_reconnect_observed"])
                self.assertEqual(result["relevant_connection_attempts"], 5)
                self.assertTrue(
                    any(
                        "same-endpoint TCP connection attempts" in error
                        for error in result["topology_errors"]  # type: ignore[union-attr]
                    ),
                    result,
                )

    def test_reused_tcp_tuple_does_not_hide_an_extra_attempt(self) -> None:
        result = self.analyze_fixture(
            "reconnect",
            extra_attempt="syn-only",
            extra_attempt_port=49153,
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["relevant_connection_attempts"], 5)

    def test_server_ip_filter_is_exact_not_substring(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reuse.pcap"
            ANALYZER.fixture_capture(path, expect="reuse")
            result = ANALYZER.analyze(
                path,
                expect="reuse",
                server_ip="104.18.33.4",
            )
        self.assertFalse(result["passed"])
        self.assertEqual(result["identified_seed_flows"], 0)
        self.assertEqual(result["relevant_connection_attempts"], 0)

    def test_server_ip_filter_accepts_multiple_exact_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "multi-ip.pcap"
            packets = ANALYZER.fixture_flow_packets(
                seed=1,
                start=1.0,
                port=49152,
                role="acquisition",
                server_ip=bytes((104, 18, 33, 45)),
            )
            packets += ANALYZER.fixture_flow_packets(
                seed=2,
                start=20.0,
                port=49153,
                role="resumption-use",
                rounds=2,
                close=False,
                ticket_identity=ANALYZER._fixture_bytes(96, 201),
                server_ip=bytes((104, 18, 33, 46)),
            )
            ANALYZER.write_fixture_pcap(path, packets)
            result = ANALYZER.analyze(
                path,
                expect="reuse",
                server_ip=("104.18.33.45", "104.18.33.46"),
            )
        self.assertTrue(result["passed"], result)
        self.assertEqual(
            result["server_ip_filter"],
            ["104.18.33.45", "104.18.33.46"],
        )
        self.assertEqual(result["relevant_connection_attempts"], 2)

    def test_exact_client_hello_profile_and_forbidden_extension(self) -> None:
        hello = ANALYZER.fixture_client_hello(7)
        parsed = ANALYZER.parse_client_hello(hello)
        self.assertEqual(parsed["hello_profile"], "acquisition")
        self.assertEqual(parsed["handshake_bytes"], 1381)
        self.assertEqual(parsed["record_bytes"], 1386)
        self.assertEqual(
            parsed["extension_order"],
            [0, 43, 10, 13, 51, 28, 21, 45],
        )
        self.assertTrue(parsed["psk_dhe_ke_offered"])
        self.assertFalse(parsed["pre_shared_key_offered"])
        self.assertFalse(parsed["early_data_offered"])

        identity = ANALYZER._fixture_bytes(96, 211)
        resumed = ANALYZER.parse_client_hello(
            ANALYZER.fixture_client_hello(
                8,
                resumed=True,
                ticket_identity=identity,
            )
        )
        self.assertEqual(resumed["hello_profile"], "resumption")
        self.assertEqual(resumed["handshake_bytes"], 1428 + len(identity))
        self.assertEqual(
            resumed["extension_order"],
            [0, 43, 10, 13, 51, 28, 21, 45, 41],
        )
        self.assertTrue(resumed["pre_shared_key_offered"])
        self.assertTrue(resumed["pre_shared_key_is_final"])
        self.assertEqual(resumed["psk_identity_count"], 1)
        self.assertFalse(resumed["early_data_offered"])

        bad = ANALYZER.fixture_client_hello(
            7,
            extension_order=(0, 43, 10, 13, 27, 51, 28, 21, 45),
        )
        with self.assertRaisesRegex(ValueError, "ClientHello"):
            ANALYZER.parse_client_hello(bad)

        psk_not_final = ANALYZER.fixture_client_hello(
            8,
            resumed=True,
            ticket_identity=identity,
            extension_order=(0, 43, 10, 13, 51, 28, 21, 41, 45),
        )
        with self.assertRaisesRegex(ValueError, "extension order"):
            ANALYZER.parse_client_hello(psk_not_final)

    def test_resumption_requires_server_psk_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing-selection.pcap"
            packets = ANALYZER.fixture_flow_packets(
                seed=1,
                start=1.0,
                port=49152,
                role="acquisition",
            )
            packets += ANALYZER.fixture_flow_packets(
                seed=2,
                start=20.0,
                port=49153,
                role="resumption-use",
                rounds=2,
                close=False,
                ticket_identity=ANALYZER._fixture_bytes(96, 201),
                server_select_psk=False,
            )
            ANALYZER.write_fixture_pcap(path, packets)
            result = ANALYZER.analyze(path, expect="reuse")
        self.assertFalse(result["passed"])
        self.assertEqual(
            result["flows"][1]["status"],  # type: ignore[index]
            "invalid-server-hello",
        )

    def test_report_states_encrypted_semantic_limit(self) -> None:
        result = self.analyze_fixture("reuse")
        self.assertFalse(
            result["certificate_and_finished_plaintext_visible_in_pcap"]
        )
        self.assertFalse(
            result["head_and_new_session_ticket_plaintext_visible_in_pcap"]
        )
        self.assertFalse(
            result["ciphertext_semantics_or_standards_conformance_proven_by_pcap"]
        )
        self.assertIn(
            "acquisition ordinary Certificate and CertificateVerify authenticated",
            result["target_nonsecret_evidence_required"],
        )


if __name__ == "__main__":
    unittest.main()
