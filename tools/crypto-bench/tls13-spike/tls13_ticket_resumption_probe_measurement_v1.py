#!/usr/bin/env python3
"""Credential-free live TLS 1.3 ticket-resumption observation.

This is a host/OpenSSL provider probe, not Seed target code.  It establishes a
fresh TLS 1.3 connection, waits for a session ticket, and then reconnects with
that ticket.  The fixed request contains no credential and early data is never
enabled.

The architecture question is narrow: after a retrospectively authenticated
first connection has closed, can a promoted same-boot ticket establish a new
connection, and does that resumed handshake still require a key share?
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).resolve()
BUILD = ROOT / "build/crypto-bench/tls13-ticket-live"
SESSION = BUILD / "session.pem"
HOST = "api.openai.com"
PORT = 443
CIPHER = "TLS_CHACHA20_POLY1305_SHA256"
GROUP = "X25519MLKEM768"
REQUEST = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

HANDSHAKE_RE = re.compile(
    r"^(<<<|>>>) TLS 1\.3, Handshake "
    r"\[length ([0-9a-fA-F]+)\], ([A-Za-z]+)$",
    re.MULTILINE,
)
HTTP_RE = re.compile(r"^HTTP/\d\.\d (\d{3})\b", re.MULTILINE)
EXTENSION_RE = re.compile(
    r'^TLS server extension "([^"]+)" \(id=(\d+)\), len=(\d+)$',
    re.MULTILINE,
)


def openssl_version() -> str:
    result = subprocess.run(
        ["openssl", "version"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def run_client(*, session_in: bool, settle_seconds: float) -> str:
    args = [
        "openssl",
        "s_client",
        "-connect",
        f"{HOST}:{PORT}",
        "-servername",
        HOST,
        "-tls1_3",
        "-ciphersuites",
        CIPHER,
        "-groups",
        GROUP,
        "-alpn",
        "http/1.1",
        "-no_ign_eof",
        "-msg",
        "-tlsextdebug",
        "-prexit",
    ]
    if session_in:
        args.extend(["-sess_in", str(SESSION)])
    else:
        args.extend(["-sess_out", str(SESSION)])

    process = subprocess.Popen(
        args,
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert process.stdin is not None
    process.stdin.write(REQUEST)
    process.stdin.flush()
    time.sleep(settle_seconds)
    process.stdin.close()
    process.stdin = None
    output, _ = process.communicate(timeout=30)
    text = output.decode("utf-8", errors="replace")
    if process.returncode != 0:
        raise RuntimeError(
            f"openssl s_client exited {process.returncode}\n{text[-2000:]}"
        )
    return text


def handshake_messages(output: str) -> list[dict[str, object]]:
    return [
        {
            "direction": "server_to_client" if marker == "<<<" else "client_to_server",
            "name": name,
            "bytes": int(length, 16),
        }
        for marker, length, name in HANDSHAKE_RE.findall(output)
    ]


def first_sequence(messages: list[dict[str, object]]) -> list[str]:
    names: list[str] = []
    for message in messages:
        name = str(message["name"])
        names.append(name)
        if (
            message["direction"] == "client_to_server"
            and name == "Finished"
        ):
            break
    return names


def summarize(output: str, *, expected_reused: bool) -> dict[str, object]:
    reused = (
        f"Reused, TLSv1.3, Cipher is {CIPHER}" in output
    )
    fresh = f"New, TLSv1.3, Cipher is {CIPHER}" in output
    if expected_reused:
        if not reused:
            raise AssertionError("provider did not resume the supplied session")
    elif not fresh:
        raise AssertionError("fresh connection did not negotiate the fixed cipher")
    if f"Negotiated TLS1.3 group: {GROUP}" not in output:
        raise AssertionError("fixed X25519MLKEM768 group was not negotiated")
    if "ALPN protocol: http/1.1" not in output:
        raise AssertionError("HTTP/1.1 ALPN was not negotiated")

    statuses = [int(item) for item in HTTP_RE.findall(output)]
    if not statuses:
        raise AssertionError("credential-free HEAD response was not observed")
    messages = handshake_messages(output)
    sequence = first_sequence(messages)
    if expected_reused:
        forbidden = {"Certificate", "CertificateVerify"}
        if forbidden.intersection(sequence):
            raise AssertionError("resumed handshake unexpectedly carried a certificate proof")
        required = ["ClientHello", "ServerHello", "EncryptedExtensions", "Finished", "Finished"]
        if sequence != required:
            raise AssertionError(f"unexpected resumed handshake sequence: {sequence}")

    extensions = [
        {"name": name, "id": int(number), "bytes": int(length)}
        for name, number, length in EXTENSION_RE.findall(output)
    ]
    if expected_reused:
        names = {str(item["name"]) for item in extensions}
        if not {"psk", "key share"}.issubset(names):
            raise AssertionError("resumed ServerHello did not contain both PSK and key_share")

    return {
        "reused": reused,
        "fixed_cipher": CIPHER,
        "fixed_group": GROUP,
        "alpn": "http/1.1",
        "http_status": statuses[0],
        "first_handshake_sequence": sequence,
        "handshake_messages": messages,
        "server_extensions": extensions,
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
    }


def run_probe(settle_seconds: float) -> dict[str, object]:
    BUILD.mkdir(parents=True, exist_ok=True)
    if SESSION.exists():
        SESSION.unlink()
    try:
        fresh_output = run_client(
            session_in=False,
            settle_seconds=settle_seconds,
        )
        if not SESSION.is_file() or SESSION.stat().st_size == 0:
            raise AssertionError("fresh connection did not produce a session file")
        resumed_output = run_client(
            session_in=True,
            settle_seconds=settle_seconds,
        )
    finally:
        # The OpenSSL session file contains the resumption PSK.  It is a
        # transient probe input, never a checked-in result or cold-start
        # dependency.
        if SESSION.exists():
            SESSION.unlink()
    return {
        "schema": "seed-tls13-ticket-live-v1",
        "recorded_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "kind": "credential-free host/OpenSSL provider observation",
        "provenance": {
            "source": str(SOURCE.relative_to(ROOT)),
            "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "settle_seconds": settle_seconds,
            "session_psk_file_destroyed_after_probe": not SESSION.exists(),
        },
        "openssl": openssl_version(),
        "request": {
            "method": "HEAD",
            "path": "/v1/models",
            "host": HOST,
            "bytes": len(REQUEST),
            "authorization": False,
            "cookie": False,
            "body": False,
            "early_data": False,
        },
        "fresh": summarize(fresh_output, expected_reused=False),
        "resumed": summarize(resumed_output, expected_reused=True),
        "conclusion": {
            "ticket_resumption_accepted": True,
            "certificate_and_certificate_verify_omitted_on_resume": True,
            "resumed_key_share_still_required": True,
            "resumed_profile": "PSK-DHE with X25519MLKEM768",
            "architecture_effect": (
                "after retrospective proof promotes a same-boot ticket, a "
                "closed first socket can be replaced without repeating "
                "certificate/Brotli/ECDSA authentication; the resumed "
                "connection still needs fresh KEM work"
            ),
            "not_established": [
                "Seed target ticket binder/resumption implementation",
                "fixed-u=9 or provisional-decapsulation resumption on target",
                "provider SLA or future ticket/profile stability",
                "persistent/cross-boot ticket safety",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--settle-seconds", type=float, default=3.0)
    args = parser.parse_args()
    if not 1.0 <= args.settle_seconds <= 15.0:
        parser.error("--settle-seconds must be between 1 and 15")
    result = run_probe(args.settle_seconds)
    encoded = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        path = args.json_out
        if not path.is_absolute():
            path = ROOT / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
