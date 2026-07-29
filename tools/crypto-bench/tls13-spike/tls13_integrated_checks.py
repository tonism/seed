#!/usr/bin/env python3
"""Adversarial checks for ``tls13_integrated_oracle.py``.

Run directly:

    python3 tools/crypto-bench/tls13-spike/tls13_integrated_checks.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent


def _load_oracle():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_integrated_oracle", HERE / "tls13_integrated_oracle.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load integrated TLS 1.3 oracle")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


O = _load_oracle()
API_KEY = b"sk-test-integrated-secret-that-must-not-exist-precommit"


def _load_live_evidence():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_integrated_live_evidence", HERE / "tls13_integrated_live.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load integrated live evidence helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ready_machine():
    fixture = O.build_integrated_fixture()
    machine = O.IntegratedClient(
        fixture.client_hello, fixture.candidate_mlkem_secret
    )
    machine.accept_server_hello(fixture.server_hello)
    machine.receive_server_flight(fixture.server_flight_record)
    client_finished = machine.send_client_finished()
    return fixture, machine, client_finished


def send_ticket(machine, fixture, sequence):
    ticket = O.build_new_session_ticket()
    record = O.encrypt_server_application_record(
        fixture, sequence, O.CONTENT_HANDSHAKE, ticket
    )
    machine.receive_provisional_record(record)
    return sequence + 1


def complete_head(machine, fixture, sequence, status=b"401 Unauthorized"):
    response = (
        b"HTTP/1.1 "
        + status
        + b"\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"
    )
    split = len(response) // 2
    for content in (response[:split], response[split:]):
        record = O.encrypt_server_application_record(
            fixture, sequence, O.CONTENT_APPLICATION_DATA, content
        )
        machine.receive_provisional_record(record)
        sequence += 1
    return sequence


class IntegratedStateMachineTests(unittest.TestCase):
    def test_checked_in_live_evidence_is_observational_only(self):
        live = _load_live_evidence()
        evidence = live.checked_in_observations()
        self.assertEqual(evidence["kind"], "dated_live_provider_observation")
        self.assertFalse(evidence["provider_sla"])
        self.assertFalse(evidence["feeds_offline_acceptance_gate"])
        self.assertIn("separate", evidence["connections"]["head_liveness_proof"])

    def test_exact_observed_geometry_and_fixed_u9(self):
        fixture = O.build_integrated_fixture()
        parsed = O.parse_fixed_client_hello(fixture.client_hello)
        server = O.parse_fixed_server_hello(
            fixture.server_hello, parsed.session_id
        )
        self.assertEqual(len(fixture.client_hello), 1376)
        self.assertEqual(len(fixture.server_hello), 1210)
        self.assertEqual(len(fixture.server_flight_record), 1947)
        self.assertEqual(
            tuple(map(len, fixture.server_flight_messages)),
            (10, 1799, 80, 36),
        )
        self.assertEqual(
            fixture.client_hello[-(32 + 18) : -18],
            O.PROFILE.x25519_client_share,
        )
        self.assertEqual(server.mlkem_ciphertext, fixture.mlkem_ciphertext)
        self.assertEqual(
            O.deterministic_summary()["kind"],
            "deterministic_offline_security_gate",
        )
        self.assertFalse(
            O.deterministic_summary()["uses_live_provider_as_acceptance_input"]
        )

    def test_all_strict_p256_der_length_variants_pass(self):
        for signature_len in range(
            O.MIN_ECDSA_DER_LEN, O.MAX_ECDSA_DER_LEN + 1
        ):
            with self.subTest(signature_len=signature_len):
                fixture = O.build_integrated_fixture(signature_len)
                machine = O.IntegratedClient(
                    fixture.client_hello, fixture.candidate_mlkem_secret
                )
                machine.accept_server_hello(fixture.server_hello)
                machine.receive_server_flight(fixture.server_flight_record)
                self.assertEqual(
                    len(fixture.server_flight_record), 1875 + signature_len
                )
                self.assertEqual(
                    len(fixture.server_flight_messages[2]), 8 + signature_len
                )

    def test_happy_path_atomic_commit_and_sequence_continuity(self):
        fixture, machine, client_finished = ready_machine()
        self.assertEqual(len(client_finished), 58)
        vault = O.CredentialVault(API_KEY)
        self.assertFalse(O.object_contains_bytes(machine, API_KEY))
        with self.assertRaises(O.CredentialLocked):
            machine.build_real_request(vault)
        self.assertFalse(O.object_contains_bytes(machine, API_KEY))

        head_record = machine.send_head_probe()
        inner_type, request = O.decrypt_client_application_record(
            fixture, 0, head_record
        )
        self.assertEqual(inner_type, O.CONTENT_APPLICATION_DATA)
        self.assertEqual(request, O.HEAD_REQUEST)
        self.assertNotIn(b"authorization", request.lower())
        self.assertEqual(machine.client_application_sequence, 1)

        server_sequence = 0
        server_sequence = send_ticket(machine, fixture, server_sequence)
        self.assertTrue(machine.tentative_ticket_available)
        self.assertIsNone(machine.promoted_ticket)
        server_sequence = complete_head(machine, fixture, server_sequence)
        self.assertFalse(machine.probe_outstanding)
        self.assertEqual(machine.server_application_sequence, server_sequence)

        O.valid_kem_proof(machine, fixture)
        O.valid_identity_proof(machine, fixture)
        self.assertEqual(machine.finalize_proofs(), O.Phase.COMMITTED_LIVE)
        self.assertIsNotNone(machine.promoted_ticket)
        self.assertNotIn("master_secret", machine._application)

        real_record = machine.build_real_request(vault)
        self.assertEqual(machine.client_application_sequence, 2)
        inner_type, real_request = O.decrypt_client_application_record(
            fixture, 1, real_record
        )
        self.assertEqual(inner_type, O.CONTENT_APPLICATION_DATA)
        self.assertIn(b"Authorization: Bearer " + API_KEY, real_request)

    def test_kem_commit_rederives_and_compares_tls_material(self):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        complete_head(machine, fixture, 0)
        machine._application["client_key"] = b"\x00" * 32
        O.valid_kem_proof(machine, fixture)
        O.valid_identity_proof(machine, fixture)
        with self.assertRaises(O.ProtocolAbort):
            machine.finalize_proofs()

    def test_full_record_aead_failure_prevents_client_finished(self):
        fixture = O.build_integrated_fixture()
        machine = O.IntegratedClient(
            fixture.client_hello, fixture.candidate_mlkem_secret
        )
        machine.accept_server_hello(fixture.server_hello)
        damaged = bytearray(fixture.server_flight_record)
        damaged[-1] ^= 1
        with self.assertRaises(O.ProtocolAbort):
            machine.receive_server_flight(bytes(damaged))
        self.assertEqual(machine.phase, O.Phase.CLOSED)
        self.assertNotIn("send_client_finished", [item[0] for item in machine.public_trace])

    def test_server_finished_failure_prevents_client_finished(self):
        fixture = O.build_integrated_fixture()
        machine = O.IntegratedClient(
            fixture.client_hello, fixture.candidate_mlkem_secret
        )
        machine.accept_server_hello(fixture.server_hello)
        messages = list(fixture.server_flight_messages)
        broken_finished = bytearray(messages[-1])
        broken_finished[-1] ^= 1
        messages[-1] = bytes(broken_finished)
        # Re-encrypt so AEAD succeeds and only Finished verification fails.
        hello = fixture.client_hello + fixture.server_hello
        handshake = O._derive_handshake(
            fixture.candidate_mlkem_secret,
            fixture.server_x25519_public,
            hello,
        )
        record = O.BASE.encrypted_record(
            handshake["server_key"],
            handshake["server_iv"],
            0,
            O.CONTENT_HANDSHAKE,
            b"".join(messages),
        )
        with self.assertRaises(O.ProtocolAbort):
            machine.receive_server_flight(record)
        self.assertEqual(machine.phase, O.Phase.CLOSED)

    def test_exactly_one_head_outstanding(self):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        with self.assertRaises(O.ProtocolAbort):
            machine.send_head_probe()
        self.assertEqual(machine.phase, O.Phase.CLOSED)

    def _unexpected_handshake_aborts(self, message_type):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        message = O._handshake(message_type, b"\x00")
        record = O.encrypt_server_application_record(
            fixture, 0, O.CONTENT_HANDSHAKE, message
        )
        with self.assertRaises(O.ProtocolAbort):
            machine.receive_provisional_record(record)
        self.assertEqual(machine.phase, O.Phase.CLOSED)
        self.assertFalse(machine.tentative_ticket_available)

    def test_keyupdate_rejected(self):
        self._unexpected_handshake_aborts(O.HS_KEY_UPDATE)

    def test_post_handshake_auth_rejected(self):
        self._unexpected_handshake_aborts(O.HS_CERTIFICATE_REQUEST)

    def test_unexpected_epoch_inner_type_rejected(self):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        record = O.encrypt_server_application_record(
            fixture, 0, O.CONTENT_ALERT, b"\x01\x00"
        )
        with self.assertRaises(O.ProtocolAbort):
            machine.receive_provisional_record(record)

    def test_tampered_provisional_response_rejected_before_drain(self):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        record = bytearray(
            O.encrypt_server_application_record(
                fixture,
                0,
                O.CONTENT_APPLICATION_DATA,
                b"HTTP/1.1 401 Unauthorized\r\n\r\n",
            )
        )
        record[-1] ^= 1
        with self.assertRaises(O.ProtocolAbort):
            machine.receive_provisional_record(bytes(record))
        self.assertEqual(machine.phase, O.Phase.CLOSED)

    def _hostile_head_response_aborts(self, response):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        record = O.encrypt_server_application_record(
            fixture, 0, O.CONTENT_APPLICATION_DATA, response
        )
        with self.assertRaises(O.ProtocolAbort):
            machine.receive_provisional_record(record)
        self.assertEqual(machine.phase, O.Phase.CLOSED)

    def test_redirect_rejected(self):
        self._hostile_head_response_aborts(
            b"HTTP/1.1 302 Found\r\nLocation: https://evil.invalid/\r\n\r\n"
        )

    def test_interim_response_rejected(self):
        self._hostile_head_response_aborts(
            b"HTTP/1.1 100 Continue\r\n\r\n"
        )

    def test_upgrade_rejected(self):
        self._hostile_head_response_aborts(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        )

    def test_body_or_overlapping_response_rejected(self):
        self._hostile_head_response_aborts(
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 1\r\n\r\nX"
        )

    def test_duplicate_discarded_cookie_headers_are_allowed(self):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        response = (
            b"HTTP/1.1 401 Unauthorized\r\n"
            b"Set-Cookie: discarded=one\r\n"
            b"Set-Cookie: discarded=two\r\n"
            b"Connection: keep-alive\r\n\r\n"
        )
        record = O.encrypt_server_application_record(
            fixture, 0, O.CONTENT_APPLICATION_DATA, response
        )
        machine.receive_provisional_record(record)
        self.assertFalse(machine.probe_outstanding)
        self.assertFalse(O.object_contains_bytes(machine, b"discarded=one"))

    def test_duplicate_control_header_rejected(self):
        self._hostile_head_response_aborts(
            b"HTTP/1.1 401 Unauthorized\r\n"
            b"Connection: keep-alive\r\n"
            b"Connection: keep-alive\r\n\r\n"
        )

    def test_oversized_header_rejected(self):
        self._hostile_head_response_aborts(
            b"HTTP/1.1 401 Unauthorized\r\nX-Fill: "
            + (b"A" * O.MAX_HEAD_RESPONSE_HEADER)
        )

    def test_unsolicited_application_data_rejected(self):
        fixture, machine, _ = ready_machine()
        record = O.encrypt_server_application_record(
            fixture,
            0,
            O.CONTENT_APPLICATION_DATA,
            b"HTTP/1.1 401 Unauthorized\r\n\r\n",
        )
        with self.assertRaises(O.ProtocolAbort):
            machine.receive_provisional_record(record)

    def test_tentative_ticket_fallback_after_peer_close(self):
        fixture, machine, _ = ready_machine()
        server_sequence = send_ticket(machine, fixture, 0)
        self.assertEqual(server_sequence, 1)
        self.assertTrue(machine.tentative_ticket_available)
        machine.peer_closed()
        O.valid_kem_proof(machine, fixture)
        leaf_digest = O.valid_identity_proof(machine, fixture)
        self.assertEqual(
            machine.finalize_proofs(), O.Phase.COMMITTED_TICKET_ONLY
        )
        ticket = machine.promoted_ticket
        self.assertIsNotNone(ticket)
        self.assertEqual(ticket.endpoint, O.HOST)
        self.assertEqual(ticket.profile_digest, fixture.profile_digest)
        self.assertEqual(ticket.leaf_spki_digest, leaf_digest)
        self.assertTrue(ticket.requires_psk_dhe)
        self.assertFalse(ticket.permits_early_data)
        with self.assertRaises(O.CredentialLocked):
            machine.build_real_request(O.CredentialVault(API_KEY))

    def test_ticket_is_destroyed_when_proof_fails(self):
        fixture, machine, _ = ready_machine()
        send_ticket(machine, fixture, 0)
        machine.submit_kem_proof(
            public_key_digest=hashlib.sha256(fixture.mlkem_public).digest(),
            ciphertext_digest=hashlib.sha256(
                fixture.mlkem_ciphertext
            ).digest(),
            ciphertext_equal=False,
            selected_mlkem_secret=fixture.candidate_mlkem_secret,
        )
        O.valid_identity_proof(machine, fixture)
        with self.assertRaises(O.ProtocolAbort):
            machine.finalize_proofs()
        self.assertIsNone(machine.promoted_ticket)
        self.assertFalse(machine.tentative_ticket_available)

    def test_multiple_bounded_tickets_keep_only_first(self):
        fixture, machine, _ = ready_machine()
        first = O.build_new_session_ticket(identity=b"A" * 32, nonce=b"\x01")
        second = O.build_new_session_ticket(identity=b"B" * 32, nonce=b"\x02")
        record = O.encrypt_server_application_record(
            fixture,
            0,
            O.CONTENT_HANDSHAKE,
            first + second,
        )
        machine.receive_provisional_record(record)
        self.assertTrue(machine.tentative_ticket_available)
        machine.peer_closed()
        O.valid_kem_proof(machine, fixture)
        O.valid_identity_proof(machine, fixture)
        machine.finalize_proofs()
        self.assertEqual(machine.promoted_ticket.identity, b"A" * 32)

    def _post_finished_failure_trace(self, failure):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        complete_head(machine, fixture, 0)
        if failure == "kem":
            machine.submit_kem_proof(
                public_key_digest=hashlib.sha256(fixture.mlkem_public).digest(),
                ciphertext_digest=hashlib.sha256(
                    fixture.mlkem_ciphertext
                ).digest(),
                ciphertext_equal=False,
                selected_mlkem_secret=fixture.candidate_mlkem_secret,
            )
            O.valid_identity_proof(machine, fixture)
        elif failure == "leaf":
            O.valid_kem_proof(machine, fixture)
            machine.submit_identity_proof(
                certificate_verify_transcript_digest=(
                    fixture.certificate_verify_transcript_digest
                ),
                staged_certificate_verify_digest=hashlib.sha256(
                    fixture.server_flight_messages[2]
                ).digest(),
                leaf_policy_ok=False,
                certificate_verify_ok=True,
                time_policy_ok=True,
                leaf_spki_digest=hashlib.sha256(b"leaf").digest(),
            )
        elif failure == "cv":
            O.valid_kem_proof(machine, fixture)
            machine.submit_identity_proof(
                certificate_verify_transcript_digest=(
                    fixture.certificate_verify_transcript_digest
                ),
                staged_certificate_verify_digest=hashlib.sha256(
                    fixture.server_flight_messages[2]
                ).digest(),
                leaf_policy_ok=True,
                certificate_verify_ok=False,
                time_policy_ok=True,
                leaf_spki_digest=hashlib.sha256(b"leaf").digest(),
            )
        else:
            raise AssertionError("unknown failure fixture")
        with self.assertRaises(O.ProtocolAbort) as caught:
            machine.finalize_proofs()
        self.assertEqual(str(caught.exception), "provisional TLS connection closed")
        self.assertIsNone(machine.promoted_ticket)
        self.assertFalse(O.object_contains_bytes(machine, API_KEY))
        return machine.public_trace

    def test_post_finished_failure_classes_are_indistinguishable(self):
        kem_trace = self._post_finished_failure_trace("kem")
        leaf_trace = self._post_finished_failure_trace("leaf")
        cv_trace = self._post_finished_failure_trace("cv")
        self.assertEqual(kem_trace, leaf_trace)
        self.assertEqual(leaf_trace, cv_trace)
        self.assertEqual(kem_trace[-1], (O.FIXED_FAILURE_ACTION,))

    def test_wrong_proof_transcript_cannot_commit(self):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        complete_head(machine, fixture, 0)
        O.valid_kem_proof(machine, fixture)
        machine.submit_identity_proof(
            certificate_verify_transcript_digest=b"\x00" * 32,
            staged_certificate_verify_digest=hashlib.sha256(
                fixture.server_flight_messages[2]
            ).digest(),
            leaf_policy_ok=True,
            certificate_verify_ok=True,
            time_policy_ok=True,
            leaf_spki_digest=hashlib.sha256(b"leaf").digest(),
        )
        with self.assertRaises(O.ProtocolAbort):
            machine.finalize_proofs()

    def test_commit_forbidden_with_outstanding_probe(self):
        fixture, machine, _ = ready_machine()
        machine.send_head_probe()
        O.valid_kem_proof(machine, fixture)
        O.valid_identity_proof(machine, fixture)
        with self.assertRaises(O.ProtocolAbort):
            machine.finalize_proofs()

    def test_wrong_server_profile_rejected(self):
        fixture = O.build_integrated_fixture()
        machine = O.IntegratedClient(
            fixture.client_hello, fixture.candidate_mlkem_secret
        )
        wrong = bytearray(fixture.server_hello)
        # CipherSuite sits before compression and the extension vector.
        cipher_offset = 4 + 2 + 32 + 1 + 32
        wrong[cipher_offset : cipher_offset + 2] = b"\x13\x01"
        with self.assertRaises(O.ProtocolAbort):
            machine.accept_server_hello(bytes(wrong))
        self.assertEqual(machine.phase, O.Phase.CLOSED)

    def test_machine_object_graph_never_contains_vault_secret_precommit(self):
        fixture, machine, _ = ready_machine()
        vault = O.CredentialVault(API_KEY)
        self.assertFalse(O.object_contains_bytes(machine, API_KEY))
        machine.send_head_probe()
        complete_head(machine, fixture, 0)
        self.assertFalse(O.object_contains_bytes(machine, API_KEY))
        with self.assertRaises(O.CredentialLocked):
            vault.reveal(machine)
        self.assertFalse(O.object_contains_bytes(machine, API_KEY))


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        IntegratedStateMachineTests
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = O.deterministic_summary()
    summary["tests_run"] = result.testsRun
    summary["failures"] = len(result.failures)
    summary["errors"] = len(result.errors)
    print(json.dumps(summary, indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
