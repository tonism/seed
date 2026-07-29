#!/usr/bin/env python3
"""Unit gates for the deterministic Seed TLS 1.3 spike oracle."""

from __future__ import annotations

import unittest

import tls13_spike as spike


class TLS13SpikeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vector = spike.build_vector()
        cls.observed = spike.build_observed_geometry_vector(cls.vector)

    def test_frozen_vector(self) -> None:
        spike.check_frozen_vector(self.vector)

    def test_rfc_primitives(self) -> None:
        spike.check_rfc_primitives()

    def test_p256_secure_and_scalar_one_agree(self) -> None:
        server_public = spike.p256_multiply(spike.SERVER_SCALAR)
        self.assertIsNotNone(server_public)
        assert server_public is not None
        secure_public = spike.p256_multiply(spike.SECURE_CLIENT_SCALAR)
        self.assertIsNotNone(secure_public)
        assert secure_public is not None
        self.assertEqual(
            spike.p256_shared_x(spike.SECURE_CLIENT_SCALAR, server_public),
            spike.p256_shared_x(spike.SERVER_SCALAR, secure_public),
        )
        self.assertEqual(
            spike.p256_shared_x(1, server_public),
            spike.p256_encode(server_public)[1:33],
        )

    def test_replay_survives_one_byte_tcp_fragments(self) -> None:
        replay = spike.replay_server_flight(self.vector, (1,))
        self.assertTrue(replay.certificate_verify_verified)
        self.assertTrue(replay.server_finished_verified)
        self.assertEqual(replay.application_plaintext, spike.SAMPLE_APPLICATION_DATA)

    def test_replay_survives_seed_mss_fragments(self) -> None:
        replay = spike.replay_server_flight(self.vector, (384,))
        self.assertTrue(replay.certificate_verify_verified)
        self.assertTrue(replay.server_finished_verified)

    def test_tamper_gates(self) -> None:
        spike.check_tamper_gates(self.vector)

    def test_observed_openai_geometry_is_exact(self) -> None:
        spike.check_frozen_observed_geometry(self.observed)
        self.assertEqual(len(self.observed.encrypted_extensions), 10)
        self.assertEqual(len(self.observed.certificate), 4000)
        self.assertEqual(len(self.observed.certificate_verify), 264)
        self.assertEqual(len(self.observed.server_finished), 36)
        self.assertEqual(len(self.observed.combined_handshake), 4310)
        self.assertEqual(
            int.from_bytes(self.observed.protected_record[3:5], "big"),
            4327,
        )
        self.assertEqual(len(self.observed.protected_record), 4332)

    def test_observed_openai_geometry_fragment_replays(self) -> None:
        for schedule in ((1,), (384,), (37, 383, 2, 127, 1)):
            with self.subTest(schedule=schedule):
                replay = spike.replay_observed_geometry(self.observed, schedule)
                self.assertTrue(replay.certificate_verify_verified)
                self.assertTrue(replay.server_finished_verified)
                self.assertEqual(replay.certificate_entry_count, 2)
                self.assertEqual(replay.protected_record_payload_bytes, 4327)
                self.assertEqual(replay.protected_record_wire_bytes, 4332)

    def test_observed_openai_geometry_tamper_gate(self) -> None:
        spike.check_observed_geometry_tamper_gate(self.observed)

    def test_full_check_and_sizing_report(self) -> None:
        vector, replay, observed, observed_replay = spike.run_checks()
        report = spike.sizing_report(
            vector,
            replay,
            observed,
            observed_replay,
        )
        state = report["semantic_state_bytes"]
        self.assertIsInstance(state, dict)
        assert isinstance(state, dict)
        self.assertEqual(state["post_handshake_bidirectional_key_iv_seq"], 104)
        geometry = report["observed_openai_flight_geometry"]
        self.assertIsInstance(geometry, dict)
        assert isinstance(geometry, dict)
        self.assertEqual(geometry["protected_record_wire"], 4332)
        self.assertEqual(geometry["protected_record_tcp_segments_at_mss"], 12)


if __name__ == "__main__":
    unittest.main()
