#!/usr/bin/env python3
"""Optional live evidence for the integrated TLS 1.3 quarantine spike.

The default mode only reports checked-in, dated observations.  ``--live``
opens a new connection to api.openai.com and exercises the fixed-u=9 wire
profile through:

    full protected-flight AEAD -> server Finished -> client Finished
    -> one literal HEAD -> bounded response drain -> certificate/CV proof

The host OpenSSL command performs *standard, complete* ML-KEM decapsulation
before client Finished.  Consequently, a successful live run establishes
current wire geometry, provider behavior, and the post-Finished parser/proof
path; it does not establish the security of Seed's provisional pre-FO split.
That split is kept in the deterministic hostile state-machine gate.

No API-key argument exists and this file never reads an API-key environment
variable or configuration file.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[3]
LIVE_CHAIN = ROOT / "tools" / "x509" / "certs" / "ecdsa_live_chain.pem"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


I = _load("seed_tls13_integrated_live_oracle", HERE / "tls13_integrated_oracle.py")
H = _load("seed_tls13_integrated_live_hybrid", HERE / "tls13_hybrid_u9_probe.py")


def checked_in_observations() -> dict[str, object]:
    hybrid = json.loads((HERE / "hybrid_u9_live_results.json").read_text())
    liveness = json.loads(
        (HERE / "post_finished_dialogue_results.json").read_text()
    )
    wire = hybrid["wire"]
    proofs = hybrid["proofs"]
    heads = liveness["experiments"]["complete_unauthorized_heads_long"]
    if (
        wire["client_hello_handshake_bytes"] != I.OBSERVED_CLIENT_HELLO_LEN
        or wire["server_hello_handshake_bytes"] != I.OBSERVED_SERVER_HELLO_LEN
        or wire["protected_server_record_wire_bytes"]
        != I.OBSERVED_SERVER_FLIGHT_RECORD_LEN
        or wire["client_finished_record_wire_bytes"]
        != I.OBSERVED_CLIENT_FINISHED_RECORD_LEN
    ):
        raise ValueError("checked-in live wire geometry no longer matches gate")
    if not (
        proofs["server_flight_aead_verified"]
        and proofs["server_finished_verified"]
        and proofs["client_finished_sent"]
        and not proofs["application_data_sent"]
        and not proofs["credentials_sent"]
    ):
        raise ValueError("checked-in hybrid proof lost a required property")
    if not (
        heads["responses"] == 7
        and heads["alive_when_client_stopped_seconds"] >= 155
        and liveness["privacy"]["authorization_header_sent"] is False
        and liveness["privacy"]["api_key_sent"] is False
    ):
        raise ValueError("checked-in HEAD liveness evidence changed")
    return {
        "kind": "dated_live_provider_observation",
        "date": hybrid["date"],
        "target": hybrid["target"],
        "provider_sla": False,
        "feeds_offline_acceptance_gate": False,
        "connections": {
            "fixed_u9_wire_proof": "one connection; standard ML-KEM decapsulation",
            "head_liveness_proof": "separate ordinary host TLS connection",
        },
        "wire_geometry": {
            "client_hello": wire["client_hello_handshake_bytes"],
            "server_hello": wire["server_hello_handshake_bytes"],
            "server_flight_record": wire[
                "protected_server_record_wire_bytes"
            ],
            "client_finished": wire["client_finished_record_wire_bytes"],
        },
        "head_liveness_seconds": heads["alive_when_client_stopped_seconds"],
        "warning": (
            "These are provider observations, not a deterministic security "
            "gate and not an integrated live provisional-decapsulation proof."
        ),
    }


def _validate_live_server_hello(
    message: bytes, expected_session_id: bytes
) -> tuple[bytes, bytes]:
    if len(message) != I.OBSERVED_SERVER_HELLO_LEN:
        raise ValueError("live ServerHello geometry changed")
    if message[0] != I.HS_SERVER_HELLO:
        raise ValueError("not a ServerHello")
    body = message[4:]
    if int.from_bytes(message[1:4], "big") != len(body):
        raise ValueError("ServerHello length mismatch")
    offset = 0
    if body[:2] != I.TLS_LEGACY_VERSION:
        raise ValueError("ServerHello legacy version changed")
    offset += 2 + 32
    session_len = body[offset]
    offset += 1
    session_id = body[offset : offset + session_len]
    offset += session_len
    if session_id != expected_session_id:
        raise ValueError("ServerHello session id mismatch")
    if body[offset : offset + 2] != I.TLS13_CIPHER:
        raise ValueError("ServerHello cipher changed")
    offset += 2
    if body[offset : offset + 1] != b"\x00":
        raise ValueError("ServerHello compression changed")
    offset += 1
    extension_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if offset + extension_len != len(body):
        raise ValueError("ServerHello extension length mismatch")
    extensions = I._parse_extensions(body[offset:])
    if set(extensions) != {I.EXT_SUPPORTED_VERSIONS, I.EXT_KEY_SHARE}:
        raise ValueError("ServerHello extension profile changed")
    if extensions[I.EXT_SUPPORTED_VERSIONS] != I.TLS13_VERSION:
        raise ValueError("ServerHello did not select TLS 1.3")
    key_share = extensions[I.EXT_KEY_SHARE]
    if (
        len(key_share) != 4 + I.MLKEM_CIPHERTEXT_LEN + I.X25519_LEN
        or int.from_bytes(key_share[:2], "big") != I.HYBRID_GROUP
        or int.from_bytes(key_share[2:4], "big") != len(key_share) - 4
    ):
        raise ValueError("ServerHello hybrid share changed")
    ciphertext = key_share[4 : 4 + I.MLKEM_CIPHERTEXT_LEN]
    server_public = key_share[-I.X25519_LEN :]
    if not any(server_public):
        raise ValueError("ServerHello supplied an all-zero X25519 share")
    return ciphertext, server_public


def _client_session_id(client_hello: bytes) -> bytes:
    body = client_hello[4:]
    offset = 2 + 32
    length = body[offset]
    session_id = body[offset + 1 : offset + 1 + length]
    if len(session_id) != length:
        raise ValueError("truncated ClientHello session id")
    return session_id


def _parse_certificate_body(body: bytes) -> tuple[bytes, ...]:
    if not body:
        raise ValueError("empty Certificate body")
    context_len = body[0]
    offset = 1
    if context_len != 0:
        raise ValueError("server Certificate request_context was not empty")
    if offset + 3 > len(body):
        raise ValueError("truncated Certificate list")
    list_len = int.from_bytes(body[offset : offset + 3], "big")
    offset += 3
    if offset + list_len != len(body):
        raise ValueError("Certificate list length mismatch")
    certificates: list[bytes] = []
    end = offset + list_len
    while offset < end:
        if offset + 3 > end:
            raise ValueError("truncated certificate entry")
        cert_len = int.from_bytes(body[offset : offset + 3], "big")
        offset += 3
        if not 1 <= cert_len <= 4096 or offset + cert_len > end:
            raise ValueError("certificate entry outside fixed bound")
        certificates.append(body[offset : offset + cert_len])
        offset += cert_len
        if offset + 2 > end:
            raise ValueError("truncated per-certificate extensions")
        extension_len = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        if extension_len > 1024 or offset + extension_len > end:
            raise ValueError("certificate extensions outside fixed bound")
        # Extension contents remain part of the already authenticated and
        # transcript-bound Certificate message, but this narrow verifier does
        # not accept any of them as policy input.
        offset += extension_len
    if offset != end or not certificates:
        raise ValueError("bad Certificate entry framing")
    return tuple(certificates)


def _split_pem_chain(chain: bytes) -> tuple[bytes, ...]:
    return tuple(
        match.group(0) + b"\n"
        for match in re.finditer(
            rb"-----BEGIN CERTIFICATE-----\n.*?"
            rb"-----END CERTIFICATE-----",
            chain,
            re.DOTALL,
        )
    )


def _verify_live_identity(
    *,
    client_hello: bytes,
    server_hello: bytes,
    flight_messages: tuple[bytes, ...],
    temp: Path,
) -> dict[str, object]:
    if tuple(message[0] for message in flight_messages) != (
        I.HS_ENCRYPTED_EXTENSIONS,
        I.HS_COMPRESSED_CERTIFICATE,
        I.HS_CERTIFICATE_VERIFY,
        I.HS_FINISHED,
    ):
        raise ValueError("live protected-flight message order changed")
    compressed_body = I._parse_exact_message(
        flight_messages[1], I.HS_COMPRESSED_CERTIFICATE
    )
    algorithm = int.from_bytes(compressed_body[:2], "big")
    uncompressed_len = int.from_bytes(compressed_body[2:5], "big")
    compressed_len = int.from_bytes(compressed_body[5:8], "big")
    compressed = compressed_body[8:]
    if (
        algorithm != I.BROTLI_CERTIFICATE_COMPRESSION
        or uncompressed_len != I.COMPRESSED_CERTIFICATE_BODY_LEN
        or compressed_len != I.COMPRESSED_CERTIFICATE_DATA_LEN
        or len(compressed) != compressed_len
    ):
        raise ValueError("live CompressedCertificate geometry changed")
    brotli = shutil.which("brotli")
    if brotli is None:
        raise RuntimeError("brotli command is required for --live")
    decoded = subprocess.run(
        [brotli, "--decompress", "--stdout"],
        input=compressed,
        capture_output=True,
        check=False,
    )
    if decoded.returncode:
        raise RuntimeError(
            "Brotli certificate decompression failed: "
            + decoded.stderr.decode("utf-8", "replace")
        )
    certificate_body = decoded.stdout
    if len(certificate_body) != uncompressed_len:
        raise ValueError("decompressed Certificate length mismatch")
    certificates = _parse_certificate_body(certificate_body)

    leaf_der = temp / "live-leaf.der"
    leaf_pem = temp / "live-leaf.pem"
    leaf_public = temp / "live-leaf-public.pem"
    we1_pem = temp / "pinned-we1.pem"
    leaf_der.write_bytes(certificates[0])
    subprocess.run(
        [
            "openssl",
            "x509",
            "-inform",
            "DER",
            "-in",
            str(leaf_der),
            "-out",
            str(leaf_pem),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(leaf_pem),
            "-pubkey",
            "-noout",
            "-out",
            str(leaf_public),
        ],
        check=True,
        capture_output=True,
    )
    chain = _split_pem_chain(LIVE_CHAIN.read_bytes())
    if len(chain) < 2:
        raise RuntimeError("tracked ECDSA chain does not contain WE1")
    we1_pem.write_bytes(chain[1])
    verify = subprocess.run(
        [
            "openssl",
            "verify",
            "-trusted",
            str(we1_pem),
            "-partial_chain",
            "-verify_hostname",
            I.HOST.decode("ascii"),
            "-purpose",
            "sslserver",
            str(leaf_pem),
        ],
        capture_output=True,
        text=True,
    )
    if verify.returncode:
        raise RuntimeError(
            "live leaf/WE1/name/time policy failed: "
            + (verify.stderr or verify.stdout).strip()
        )

    cv_body = I._parse_exact_message(
        flight_messages[2], I.HS_CERTIFICATE_VERIFY
    )
    if cv_body[:2] != I.ECDSA_SECP256R1_SHA256:
        raise ValueError("live CertificateVerify scheme changed")
    signature_len = int.from_bytes(cv_body[2:4], "big")
    signature = cv_body[4:]
    if signature_len != len(signature) or not I._strict_ecdsa_der(signature):
        raise ValueError("live CertificateVerify signature is not strict DER")
    cv_transcript = (
        client_hello
        + server_hello
        + flight_messages[0]
        + flight_messages[1]
    )
    signed_input = I.BASE.certificate_verify_input(cv_transcript)
    signed_path = temp / "certificate-verify-input.bin"
    signature_path = temp / "certificate-verify.der"
    signed_path.write_bytes(signed_input)
    signature_path.write_bytes(signature)
    cv_verify = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(leaf_public),
            "-signature",
            str(signature_path),
            str(signed_path),
        ],
        capture_output=True,
        text=True,
    )
    if cv_verify.returncode:
        raise RuntimeError(
            "live CertificateVerify failed: "
            + (cv_verify.stderr or cv_verify.stdout).strip()
        )
    spki_der = subprocess.run(
        [
            "openssl",
            "pkey",
            "-pubin",
            "-in",
            str(leaf_public),
            "-outform",
            "DER",
        ],
        check=True,
        capture_output=True,
    ).stdout
    return {
        "certificate_body_bytes": len(certificate_body),
        "certificate_entries": len(certificates),
        "leaf_der_bytes": len(certificates[0]),
        "leaf_we1_hostname_host_time_policy": True,
        "certificate_verify": True,
        "leaf_spki_sha256": hashlib.sha256(spki_der).hexdigest(),
        "certificate_verify_transcript_sha256": hashlib.sha256(
            cv_transcript
        ).hexdigest(),
    }


def run_live(timeout: float) -> dict[str, object]:
    """Run one combined live connection without ever loading a credential."""

    if timeout < 20:
        raise ValueError("live timeout must leave room for provider flight/response")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="seed-integrated-live-") as temp_name:
        temp = Path(temp_name)
        private_key, public_key = H.generate_mlkem_key(temp)
        template = H.capture_openssl_client_hello(timeout)
        client_hello = H.patch_client_hello(template, public_key)
        if len(client_hello) != I.OBSERVED_CLIENT_HELLO_LEN:
            raise ValueError("live ClientHello geometry changed")
        # Verify the patched share itself even though the OpenSSL template has
        # a broader extension set than the deterministic PC16 profile.
        extension_len_offset, extensions_end = H.client_hello_extensions(
            client_hello
        )
        fixed_u9 = False
        for extension_type, value_start, value_end in H.iter_extensions(
            client_hello, extension_len_offset + 2, extensions_end
        ):
            if extension_type != H.EXT_KEY_SHARE:
                continue
            value = client_hello[value_start:value_end]
            fixed_u9 = value[-I.X25519_LEN :] == I.PROFILE.x25519_client_share
        if not fixed_u9:
            raise ValueError("live ClientHello did not carry fixed u=9")
        client_record = (
            bytes([H.TLS_HANDSHAKE])
            + b"\x03\x01"
            + len(client_hello).to_bytes(2, "big")
            + client_hello
        )

        with socket.create_connection((H.HOST, H.PORT), timeout=timeout) as peer:
            peer.settimeout(timeout)
            peer.sendall(client_record)
            server_hello: bytes | None = None
            while server_hello is None:
                record = H.recv_record(peer)
                if record[0] == H.TLS_CHANGE_CIPHER_SPEC:
                    continue
                if record[0] != H.TLS_HANDSHAKE:
                    raise ValueError("expected plaintext ServerHello")
                for message in H.parse_handshake_messages(record[5:]):
                    if message[0] == H.HS_SERVER_HELLO:
                        server_hello = message
            session_id = _client_session_id(client_hello)
            ciphertext, server_public = _validate_live_server_hello(
                server_hello, session_id
            )

            # Important limitation: OpenSSL completes standard decapsulation
            # here.  This live path cannot evidence provisional pre-FO use.
            mlkem_secret = H.decapsulate(private_key, ciphertext, temp)
            handshake = H.derive_handshake(
                mlkem_secret + server_public, client_hello + server_hello
            )

            record = H.recv_record(peer)
            while record[0] == H.TLS_CHANGE_CIPHER_SPEC:
                record = H.recv_record(peer)
            server_flight_record_len = len(record)
            if (
                record[0] != H.TLS_APPLICATION_DATA
                or not (
                    I.MIN_SERVER_FLIGHT_RECORD_LEN
                    <= server_flight_record_len
                    <= I.MAX_SERVER_FLIGHT_RECORD_LEN
                )
            ):
                raise ValueError("live protected-flight record geometry changed")
            inner_type, content = H.ORACLE.decrypt_record(
                handshake["server_key"],
                handshake["server_iv"],
                0,
                record,
            )
            if inner_type != H.TLS_HANDSHAKE:
                raise ValueError("live protected flight used wrong inner type")
            messages = tuple(H.parse_handshake_messages(content))
            message_lengths = tuple(map(len, messages))
            if (
                message_lengths[0] != 10
                or message_lengths[1] != 1799
                or not (
                    I.MIN_CERTIFICATE_VERIFY_LEN
                    <= message_lengths[2]
                    <= I.MAX_CERTIFICATE_VERIFY_LEN
                )
                or message_lengths[3] != 36
                or server_flight_record_len != sum(message_lengths) + 22
                or tuple(message[0] for message in messages)
                != (
                    I.HS_ENCRYPTED_EXTENSIONS,
                    I.HS_COMPRESSED_CERTIFICATE,
                    I.HS_CERTIFICATE_VERIFY,
                    I.HS_FINISHED,
                )
            ):
                raise ValueError("live protected-flight messages changed")
            before_finished = (
                client_hello + server_hello + b"".join(messages[:-1])
            )
            finished = I._parse_exact_message(messages[-1], I.HS_FINISHED)
            expected_finished = hmac.new(
                handshake["server_finished"],
                hashlib.sha256(before_finished).digest(),
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(finished, expected_finished):
                raise ValueError("live server Finished verification failed")

            through_server_finished = before_finished + messages[-1]
            client_verify_data = hmac.new(
                handshake["client_finished"],
                hashlib.sha256(through_server_finished).digest(),
                hashlib.sha256,
            ).digest()
            client_finished = H.handshake_message(
                H.HS_FINISHED, client_verify_data
            )
            client_finished_record = H.ORACLE.encrypted_record(
                handshake["client_key"],
                handshake["client_iv"],
                0,
                H.TLS_HANDSHAKE,
                client_finished,
            )
            if len(client_finished_record) != I.OBSERVED_CLIENT_FINISHED_RECORD_LEN:
                raise ValueError("live client Finished geometry changed")
            peer.sendall(b"\x14\x03\x03\x00\x01\x01")
            peer.sendall(client_finished_record)

            application = H.derive_application(
                handshake["handshake"], through_server_finished
            )
            head_record = H.ORACLE.encrypted_record(
                application["client_key"],
                application["client_iv"],
                0,
                H.TLS_APPLICATION_DATA,
                I.HEAD_REQUEST,
            )
            peer.sendall(head_record)

            drain = I._HeadResponseDrain()
            response_complete = False
            ticket: dict[str, object] | None = None
            tickets_drained = 0
            server_sequence = 0
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and not response_complete:
                record = H.recv_record(peer)
                if record[0] != H.TLS_APPLICATION_DATA:
                    raise ValueError("unexpected live post-Finished outer record")
                inner_type, plaintext = H.ORACLE.decrypt_record(
                    application["server_key"],
                    application["server_iv"],
                    server_sequence,
                    record,
                )
                server_sequence += 1
                if inner_type == H.TLS_APPLICATION_DATA:
                    if response_complete:
                        raise ValueError("unsolicited live application data")
                    response_complete = drain.feed(plaintext)
                    continue
                if inner_type == H.TLS_HANDSHAKE:
                    parsed = H.parse_handshake_messages(plaintext)
                    if not 1 <= len(parsed) <= I.MAX_NST_MESSAGES_PER_RECORD:
                        raise ValueError("unexpected post-handshake packing")
                    for message in parsed:
                        if message[0] != H.HS_NEW_SESSION_TICKET:
                            raise ValueError(
                                "KeyUpdate/PHA/unexpected handshake rejected"
                            )
                        parsed_ticket = H.parse_ticket(message)
                        tickets_drained += 1
                        if ticket is None:
                            ticket = parsed_ticket
                    continue
                raise ValueError("unexpected post-Finished TLS inner type")

            if not response_complete:
                raise TimeoutError("complete bounded HEAD response not received")

            identity = _verify_live_identity(
                client_hello=client_hello,
                server_hello=server_hello,
                flight_messages=messages,
                temp=temp,
            )
            ticket_result: dict[str, object]
            if ticket is None:
                ticket_result = {
                    "received": False,
                    "promoted": False,
                    "required_for_live_commit": False,
                }
            else:
                full_transcript = through_server_finished + client_finished
                resumption_master = H.ORACLE.derive_secret(
                    application["master"], b"res master", full_transcript
                )
                psk = H.ORACLE.hkdf_expand_label(
                    resumption_master,
                    b"resumption",
                    ticket["nonce"],
                    I.HASH_LEN,
                )
                ticket_result = {
                    "received": True,
                    "tentative_until_identity_proof": True,
                    "promoted": True,
                    "identity_bytes": len(ticket["ticket"]),
                    "nonce_bytes": len(ticket["nonce"]),
                    "psk_bytes": len(psk),
                    "lifetime_seconds": ticket["lifetime"],
                    "requires_psk_dhe": True,
                    "permits_early_data": False,
                    "required_for_live_commit": False,
                }

            return {
                "kind": "new_combined_live_provider_observation",
                "target": f"{H.HOST}:{H.PORT}",
                "provider_sla": False,
                "feeds_offline_acceptance_gate": False,
                "execution_provenance": {
                    "seed_8088_target_code_executed": False,
                    "tls_state_machine": "host Python research model",
                    "mlkem_decapsulation": "host OpenSSL subprocess",
                    "certificate_path_and_cv_verification": (
                        "host OpenSSL subprocess"
                    ),
                    "certificate_decompression": "host brotli subprocess",
                    "live_transport_identity_authentication": (
                        "performed entirely by host tools/model, not by Seed "
                        "8088 target code"
                    ),
                    "openai_api_authentication_attempted": False,
                },
                "wire_profile": {
                    "group": "X25519MLKEM768",
                    "x25519_client_share": "fixed u=9",
                    "effective_secrecy": "ML-KEM-only research profile",
                    "mlkem_decapsulation": (
                        "standard OpenSSL decapsulation completed before "
                        "client Finished"
                    ),
                    "provisional_pre_fo_split_exercised": False,
                },
                "gates": {
                    "full_server_record_aead_before_parse": True,
                    "server_finished_before_client_finished": True,
                    "one_literal_head": True,
                    "head_response_complete_and_bounded": True,
                    "leaf_we1_name_host_time_policy": identity[
                        "leaf_we1_hostname_host_time_policy"
                    ],
                    "certificate_verify": identity["certificate_verify"],
                    "credential_loaded": False,
                    "real_request_sent": False,
                    "atomic_host_commit_reached": True,
                },
                "geometry": {
                    "client_hello": len(client_hello),
                    "server_hello": len(server_hello),
                    "server_flight_record": server_flight_record_len,
                    "server_messages": list(map(len, messages)),
                    "client_finished": len(client_finished_record),
                    "head_request_plaintext": len(I.HEAD_REQUEST),
                    "server_application_records_consumed": server_sequence,
                    "new_session_tickets_drained": tickets_drained,
                },
                "identity": identity,
                "ticket": ticket_result,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "warning": (
                    "Live success does not validate provisional pre-FO KEM "
                    "use; only the deterministic hostile oracle covers that "
                    "state transition."
                ),
            }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="open a new combined research connection to api.openai.com",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="live socket/subprocess timeout in seconds (default: 30)",
    )
    args = parser.parse_args()
    if not 20 <= args.timeout <= 120:
        parser.error("--timeout must be between 20 and 120 seconds")
    result: dict[str, object] = {
        "offline_gate": I.deterministic_summary(),
        "checked_in_live_observation": checked_in_observations(),
    }
    if args.live:
        result["new_live_observation"] = run_live(args.timeout)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
