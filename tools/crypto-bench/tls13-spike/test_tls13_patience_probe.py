#!/usr/bin/env python3
"""Offline structural tests for the bounded TLS 1.3 patience relay."""

from __future__ import annotations

import time
import unittest

import tls13_patience_probe as probe


class TLS13PatienceProbeTests(unittest.TestCase):
    def test_record_reader_preserves_fragmented_and_coalesced_records(self) -> None:
        hello = bytes.fromhex("160301000401000000")
        application = bytes.fromhex("1703030000")
        reader = probe.TLSStreamReader()

        reader.buffer.extend(hello[:3])
        self.assertIsNone(reader._extract_one())
        reader.buffer.extend(hello[3:] + application)

        self.assertEqual(reader._extract_one(), hello)
        self.assertEqual(reader._extract_one(), application)
        self.assertIsNone(reader._extract_one())
        probe.validate_first_client_hello(hello)

    def test_first_record_must_be_client_hello(self) -> None:
        with self.assertRaises(probe.ProbeError):
            probe.validate_first_client_hello(bytes.fromhex("1703030000"))

    def test_command_forces_the_spike_profile(self) -> None:
        command = probe.build_openssl_command("/usr/bin/openssl", 12345)
        rendered = " ".join(command)
        self.assertIn("-connect 127.0.0.1:12345", rendered)
        self.assertIn("-servername api.openai.com", rendered)
        self.assertIn("-tls1_3", rendered)
        self.assertIn("TLS_CHACHA20_POLY1305_SHA256", rendered)
        self.assertIn("-groups P-256", rendered)
        self.assertIn("-sigalgs rsa_pss_rsae_sha256", rendered)

    def test_remote_acceptance_requires_new_session_ticket_marker(self) -> None:
        state = probe.SharedState(time.monotonic())
        output = probe.OpenSSLOutput(state)
        output._append(b"CONNECTION ESTAB")
        output._append(b"LISHED\n")
        self.assertIsNotNone(state.local_handshake_at)
        self.assertIsNone(state.server_acceptance_at)

        output._append(b"<<< TLS 1.3, Handshake, NewSession")
        output._append(b"Ticket\n")
        self.assertIsNotNone(state.server_acceptance_at)


if __name__ == "__main__":
    unittest.main()
