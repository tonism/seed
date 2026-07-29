#!/usr/bin/env python3
"""Complete a quarantined OpenAI TLS 1.3 handshake with ML-KEM + X25519 u=9.

This is a live research probe, not a proposed standards-conforming TLS profile.
It asks the local OpenSSL command to construct a current ClientHello template,
replaces the hybrid key share with:

    genuine ML-KEM-768 public key || canonical X25519 base point u=9

and completes the handshake itself.  For the X25519 half it deliberately uses
the server's public share as the shared value.  That matches what the server
computes against u=9 but does not perform the client-side X25519 operation
required by the hybrid-group draft.

No application data or credential is sent.  Success requires:

* ML-KEM decapsulation through the local OpenSSL FIPS 203 implementation;
* AEAD authentication of the protected server flight;
* server Finished verification;
* an accepted client Finished; and
* receipt and decryption of a NewSessionTicket.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
HOST = "api.openai.com"
PORT = 443
HYBRID_GROUP = 0x11EC
MLKEM_PUBLIC_LEN = 1184
MLKEM_CIPHERTEXT_LEN = 1088
X25519_LEN = 32
TLS_HANDSHAKE = 22
TLS_CHANGE_CIPHER_SPEC = 20
TLS_APPLICATION_DATA = 23
TLS_LEGACY_VERSION = b"\x03\x03"
HS_SERVER_HELLO = 2
HS_NEW_SESSION_TICKET = 4
HS_ENCRYPTED_EXTENSIONS = 8
HS_CERTIFICATE = 11
HS_CERTIFICATE_VERIFY = 15
HS_FINISHED = 20
HS_COMPRESSED_CERTIFICATE = 25
EXT_COMPRESS_CERTIFICATE = 27
EXT_KEY_SHARE = 51
HASH_LEN = 32


def load_oracle():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_hybrid_probe_oracle", HERE / "tls13_spike.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load TLS 1.3 spike oracle")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ORACLE = load_oracle()


def exact_recv(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise EOFError("TLS peer closed mid-record")
        chunks.extend(chunk)
    return bytes(chunks)


def recv_record(sock: socket.socket) -> bytes:
    header = exact_recv(sock, 5)
    length = int.from_bytes(header[3:5], "big")
    if length > 0x5000:
        raise ValueError(f"unreasonably large TLS record: {length}")
    return header + exact_recv(sock, length)


def handshake_message(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def parse_handshake_messages(data: bytes) -> list[bytes]:
    messages: list[bytes] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("truncated handshake header")
        length = int.from_bytes(data[offset + 1 : offset + 4], "big")
        end = offset + 4 + length
        if end > len(data):
            raise ValueError("truncated handshake body")
        messages.append(data[offset:end])
        offset = end
    return messages


def client_hello_extensions(message: bytes) -> tuple[int, int]:
    if not message or message[0] != 1:
        raise ValueError("not a ClientHello")
    body = message[4:]
    offset = 2 + 32
    session_id_len = body[offset]
    offset += 1 + session_id_len
    cipher_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2 + cipher_len
    compression_len = body[offset]
    offset += 1 + compression_len
    extension_len_offset = 4 + offset
    extension_len = int.from_bytes(
        message[extension_len_offset : extension_len_offset + 2], "big"
    )
    return extension_len_offset, extension_len_offset + 2 + extension_len


def iter_extensions(message: bytes, start: int, end: int):
    offset = start
    while offset < end:
        if offset + 4 > end:
            raise ValueError("truncated extension header")
        extension_type = int.from_bytes(message[offset : offset + 2], "big")
        length = int.from_bytes(message[offset + 2 : offset + 4], "big")
        value_start = offset + 4
        value_end = value_start + length
        if value_end > end:
            raise ValueError("truncated extension value")
        yield extension_type, value_start, value_end
        offset = value_end
    if offset != end:
        raise ValueError("extension list length mismatch")


def capture_openssl_client_hello(timeout: float) -> bytes:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(timeout)
    port = listener.getsockname()[1]
    command = [
        "openssl",
        "s_client",
        "-connect",
        f"127.0.0.1:{port}",
        "-servername",
        HOST,
        "-tls1_3",
        "-ciphersuites",
        "TLS_CHACHA20_POLY1305_SHA256",
        "-groups",
        "X25519MLKEM768",
        "-sigalgs",
        "ecdsa_secp256r1_sha256",
        "-brief",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    connection: socket.socket | None = None
    try:
        connection, _ = listener.accept()
        connection.settimeout(timeout)
        record = recv_record(connection)
    finally:
        if connection is not None:
            connection.close()
        listener.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=2)
    if record[0] != TLS_HANDSHAKE:
        raise ValueError("OpenSSL template did not start with a handshake record")
    messages = parse_handshake_messages(record[5:])
    if len(messages) != 1 or messages[0][0] != 1:
        raise ValueError("OpenSSL template did not contain one ClientHello")
    return messages[0]


def generate_mlkem_key(temp: Path) -> tuple[Path, bytes]:
    private_key = temp / "mlkem768.pem"
    public_der = temp / "mlkem768-public.der"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ML-KEM-768", "-out", private_key],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            private_key,
            "-pubout",
            "-outform",
            "DER",
            "-out",
            public_der,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    encoded = public_der.read_bytes()
    if len(encoded) != 1206 or encoded[-MLKEM_PUBLIC_LEN - 1] != 0:
        raise ValueError("unexpected OpenSSL ML-KEM-768 SubjectPublicKeyInfo")
    return private_key, encoded[-MLKEM_PUBLIC_LEN:]


def patch_client_hello(template: bytes, mlkem_public: bytes) -> bytes:
    message = bytearray(template)
    extension_len_offset, extensions_end = client_hello_extensions(message)
    extensions_start = extension_len_offset + 2
    key_share_found = False
    compression_found = False
    for extension_type, value_start, value_end in iter_extensions(
        message, extensions_start, extensions_end
    ):
        if extension_type == EXT_COMPRESS_CERTIFICATE:
            compression_found = True
        if extension_type != EXT_KEY_SHARE:
            continue
        value = message[value_start:value_end]
        if len(value) < 6:
            raise ValueError("short ClientHello key_share")
        vector_len = int.from_bytes(value[:2], "big")
        if vector_len != len(value) - 2:
            raise ValueError("ClientHello key_share vector length mismatch")
        group = int.from_bytes(value[2:4], "big")
        exchange_len = int.from_bytes(value[4:6], "big")
        if group != HYBRID_GROUP or exchange_len != MLKEM_PUBLIC_LEN + X25519_LEN:
            raise ValueError("unexpected OpenSSL hybrid key_share")
        exchange_start = value_start + 6
        exchange_end = exchange_start + exchange_len
        if exchange_end != value_end:
            raise ValueError("unexpected extra ClientHello key shares")
        message[exchange_start:exchange_end] = (
            mlkem_public + b"\x09" + (b"\x00" * 31)
        )
        key_share_found = True
    if not key_share_found:
        raise ValueError("ClientHello omitted X25519MLKEM768")

    if not compression_found:
        # RFC 8879 extension data is a one-byte vector length followed by the
        # uint16 Brotli algorithm identifier (2).
        extension = b"\x00\x1b\x00\x03\x02\x00\x02"
        old_extension_len = int.from_bytes(
            message[extension_len_offset : extension_len_offset + 2], "big"
        )
        message[extension_len_offset : extension_len_offset + 2] = (
            old_extension_len + len(extension)
        ).to_bytes(2, "big")
        message[extensions_end:extensions_end] = extension

    body_len = len(message) - 4
    message[1:4] = body_len.to_bytes(3, "big")
    return bytes(message)


def parse_server_hybrid_share(server_hello: bytes) -> tuple[bytes, bytes]:
    if server_hello[0] != HS_SERVER_HELLO:
        raise ValueError("not a ServerHello")
    body = server_hello[4:]
    offset = 2 + 32
    session_id_len = body[offset]
    offset += 1 + session_id_len
    offset += 2 + 1
    extension_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    extension_end = offset + extension_len
    message_offset = 4 + offset
    for extension_type, value_start, value_end in iter_extensions(
        server_hello, message_offset, 4 + extension_end
    ):
        if extension_type != EXT_KEY_SHARE:
            continue
        value = server_hello[value_start:value_end]
        if len(value) < 4:
            raise ValueError("short ServerHello key_share")
        group = int.from_bytes(value[:2], "big")
        exchange_len = int.from_bytes(value[2:4], "big")
        exchange = bytes(value[4:])
        if group != HYBRID_GROUP or exchange_len != len(exchange):
            raise ValueError("unexpected ServerHello key_share")
        if len(exchange) != MLKEM_CIPHERTEXT_LEN + X25519_LEN:
            raise ValueError("unexpected hybrid server exchange length")
        return (
            exchange[:MLKEM_CIPHERTEXT_LEN],
            exchange[MLKEM_CIPHERTEXT_LEN:],
        )
    raise ValueError("ServerHello omitted hybrid key_share")


def decapsulate(private_key: Path, ciphertext: bytes, temp: Path) -> bytes:
    ciphertext_path = temp / "ciphertext.bin"
    secret_path = temp / "shared-secret.bin"
    ciphertext_path.write_bytes(ciphertext)
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-decap",
            "-inkey",
            private_key,
            "-in",
            ciphertext_path,
            "-out",
            secret_path,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    secret = secret_path.read_bytes()
    if len(secret) != HASH_LEN:
        raise ValueError("unexpected ML-KEM-768 shared-secret length")
    return secret


def derive_handshake(shared_secret: bytes, hello_transcript: bytes) -> dict[str, bytes]:
    zeros = b"\x00" * HASH_LEN
    empty_hash = hashlib.sha256(b"").digest()
    early = ORACLE.hkdf_extract(zeros, zeros)
    derived = ORACLE.hkdf_expand_label(early, b"derived", empty_hash, HASH_LEN)
    handshake = ORACLE.hkdf_extract(derived, shared_secret)
    client_traffic = ORACLE.derive_secret(
        handshake, b"c hs traffic", hello_transcript
    )
    server_traffic = ORACLE.derive_secret(
        handshake, b"s hs traffic", hello_transcript
    )
    return {
        "handshake": handshake,
        "client_key": ORACLE.hkdf_expand_label(
            client_traffic, b"key", b"", 32
        ),
        "client_iv": ORACLE.hkdf_expand_label(
            client_traffic, b"iv", b"", 12
        ),
        "client_finished": ORACLE.hkdf_expand_label(
            client_traffic, b"finished", b"", 32
        ),
        "server_key": ORACLE.hkdf_expand_label(
            server_traffic, b"key", b"", 32
        ),
        "server_iv": ORACLE.hkdf_expand_label(
            server_traffic, b"iv", b"", 12
        ),
        "server_finished": ORACLE.hkdf_expand_label(
            server_traffic, b"finished", b"", 32
        ),
    }


def derive_application(handshake_secret: bytes, through_server_finished: bytes):
    empty_hash = hashlib.sha256(b"").digest()
    derived = ORACLE.hkdf_expand_label(
        handshake_secret, b"derived", empty_hash, HASH_LEN
    )
    master = ORACLE.hkdf_extract(derived, b"\x00" * HASH_LEN)
    client_traffic = ORACLE.derive_secret(
        master, b"c ap traffic", through_server_finished
    )
    server_traffic = ORACLE.derive_secret(
        master, b"s ap traffic", through_server_finished
    )
    return {
        "master": master,
        "client_key": ORACLE.hkdf_expand_label(
            client_traffic, b"key", b"", 32
        ),
        "client_iv": ORACLE.hkdf_expand_label(
            client_traffic, b"iv", b"", 12
        ),
        "server_key": ORACLE.hkdf_expand_label(
            server_traffic, b"key", b"", 32
        ),
        "server_iv": ORACLE.hkdf_expand_label(
            server_traffic, b"iv", b"", 12
        ),
    }


def parse_ticket(message: bytes) -> dict[str, object]:
    if message[0] != HS_NEW_SESSION_TICKET:
        raise ValueError("not a NewSessionTicket")
    body = message[4:]
    if len(body) < 11:
        raise ValueError("short NewSessionTicket")
    lifetime = int.from_bytes(body[:4], "big")
    age_add = int.from_bytes(body[4:8], "big")
    nonce_len = body[8]
    offset = 9
    nonce = body[offset : offset + nonce_len]
    offset += nonce_len
    ticket_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    ticket = body[offset : offset + ticket_len]
    offset += ticket_len
    if offset + 2 > len(body):
        raise ValueError("truncated NewSessionTicket extensions")
    extension_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    if offset + extension_len != len(body):
        raise ValueError("NewSessionTicket extension length mismatch")
    max_early_data = None
    for extension_type, value_start, value_end in iter_extensions(
        message, 4 + offset, len(message)
    ):
        if extension_type == 42 and value_end - value_start == 4:
            max_early_data = int.from_bytes(
                message[value_start:value_end], "big"
            )
    return {
        "lifetime": lifetime,
        "age_add": age_add,
        "nonce": nonce,
        "ticket": ticket,
        "max_early_data": max_early_data,
    }


def run(timeout: float) -> dict[str, object]:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="seed-hybrid-u9-") as temp_name:
        temp = Path(temp_name)
        private_key, public_key = generate_mlkem_key(temp)
        template = capture_openssl_client_hello(timeout)
        client_hello = patch_client_hello(template, public_key)
        client_record = (
            bytes([TLS_HANDSHAKE])
            + b"\x03\x01"
            + len(client_hello).to_bytes(2, "big")
            + client_hello
        )

        with socket.create_connection((HOST, PORT), timeout=timeout) as peer:
            peer.settimeout(timeout)
            peer.sendall(client_record)

            server_hello = None
            while server_hello is None:
                record = recv_record(peer)
                content_type = record[0]
                if content_type == TLS_CHANGE_CIPHER_SPEC:
                    continue
                if content_type != TLS_HANDSHAKE:
                    raise ValueError("expected plaintext ServerHello")
                messages = parse_handshake_messages(record[5:])
                for message in messages:
                    if message[0] == HS_SERVER_HELLO:
                        server_hello = message
            mlkem_ciphertext, server_x25519_public = parse_server_hybrid_share(
                server_hello
            )
            mlkem_secret = decapsulate(private_key, mlkem_ciphertext, temp)
            shared_secret = mlkem_secret + server_x25519_public
            hello_transcript = client_hello + server_hello
            handshake = derive_handshake(shared_secret, hello_transcript)

            server_sequence = 0
            flight_content = bytearray()
            flight_record_lengths: list[int] = []
            messages: list[bytes] = []
            while not any(message[0] == HS_FINISHED for message in messages):
                record = recv_record(peer)
                if record[0] == TLS_CHANGE_CIPHER_SPEC:
                    continue
                if record[0] != TLS_APPLICATION_DATA:
                    raise ValueError("unexpected protected-flight record type")
                inner_type, content = ORACLE.decrypt_record(
                    handshake["server_key"],
                    handshake["server_iv"],
                    server_sequence,
                    record,
                )
                server_sequence += 1
                if inner_type != TLS_HANDSHAKE:
                    raise ValueError("protected server flight was not handshake")
                flight_record_lengths.append(len(record))
                flight_content.extend(content)
                messages = parse_handshake_messages(bytes(flight_content))

            message_types = [message[0] for message in messages]
            finished_index = message_types.index(HS_FINISHED)
            if finished_index != len(messages) - 1:
                raise ValueError("server Finished was not final flight message")
            before_finished_messages = messages[:finished_index]
            server_finished = messages[finished_index]
            if len(server_finished) != 36:
                raise ValueError("unexpected server Finished length")
            before_server_finished = (
                hello_transcript + b"".join(before_finished_messages)
            )
            expected_server_finished = hmac.new(
                handshake["server_finished"],
                hashlib.sha256(before_server_finished).digest(),
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(
                server_finished[4:], expected_server_finished
            ):
                raise ValueError("server Finished verification failed")

            through_server_finished = before_server_finished + server_finished
            client_verify_data = hmac.new(
                handshake["client_finished"],
                hashlib.sha256(through_server_finished).digest(),
                hashlib.sha256,
            ).digest()
            client_finished = handshake_message(
                HS_FINISHED, client_verify_data
            )
            client_finished_record = ORACLE.encrypted_record(
                handshake["client_key"],
                handshake["client_iv"],
                0,
                TLS_HANDSHAKE,
                client_finished,
            )
            peer.sendall(b"\x14\x03\x03\x00\x01\x01")
            peer.sendall(client_finished_record)
            client_finished_sent = time.monotonic()

            application = derive_application(
                handshake["handshake"], through_server_finished
            )
            full_transcript = through_server_finished + client_finished
            resumption_master = ORACLE.derive_secret(
                application["master"], b"res master", full_transcript
            )

            tickets: list[dict[str, object]] = []
            app_handshake_buffer = bytearray()
            application_sequence = 0
            while len(tickets) < 1:
                record = recv_record(peer)
                if record[0] != TLS_APPLICATION_DATA:
                    continue
                inner_type, content = ORACLE.decrypt_record(
                    application["server_key"],
                    application["server_iv"],
                    application_sequence,
                    record,
                )
                application_sequence += 1
                if inner_type != TLS_HANDSHAKE:
                    continue
                app_handshake_buffer.extend(content)
                for message in parse_handshake_messages(
                    bytes(app_handshake_buffer)
                ):
                    if message[0] == HS_NEW_SESSION_TICKET:
                        tickets.append(parse_ticket(message))

            ticket = tickets[0]
            psk = ORACLE.hkdf_expand_label(
                resumption_master,
                b"resumption",
                ticket["nonce"],
                HASH_LEN,
            )
            return {
                "profile": "X25519MLKEM768 with nonstandard client u=9",
                "standard_mlkem_decapsulation": True,
                "standard_x25519_client_operation": False,
                "client_hello_handshake_bytes": len(client_hello),
                "server_hello_handshake_bytes": len(server_hello),
                "server_flight_record_bytes": flight_record_lengths,
                "server_flight_message_types": message_types,
                "compressed_certificate": HS_COMPRESSED_CERTIFICATE
                in message_types,
                "ordinary_certificate": HS_CERTIFICATE in message_types,
                "certificate_verify_bytes": next(
                    (
                        len(message)
                        for message in messages
                        if message[0] == HS_CERTIFICATE_VERIFY
                    ),
                    None,
                ),
                "server_finished_verified": True,
                "client_finished_record_bytes": len(client_finished_record),
                "ticket_received": True,
                "ticket_seconds_after_client_finished": round(
                    time.monotonic() - client_finished_sent, 3
                ),
                "ticket_identity_bytes": len(ticket["ticket"]),
                "ticket_nonce_bytes": len(ticket["nonce"]),
                "ticket_lifetime_seconds": ticket["lifetime"],
                "ticket_max_early_data": ticket["max_early_data"],
                "resumption_psk_bytes": len(psk),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "warning": (
                    "Wire-complete research result only; the u=9/copy-server-share "
                    "client is not the X25519 operation required by the hybrid draft."
                ),
            }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="socket/subprocess timeout in seconds (default: 30)",
    )
    args = parser.parse_args()
    if not 5 <= args.timeout <= 120:
        parser.error("--timeout must be between 5 and 120 seconds")
    print(json.dumps(run(args.timeout), indent=2))


if __name__ == "__main__":
    main()
