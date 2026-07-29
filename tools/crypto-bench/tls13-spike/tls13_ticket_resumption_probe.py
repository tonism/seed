#!/usr/bin/env python3
"""Credential-free TLS 1.3 ticket-resumption probe with qualified extensions.

The 25 July observation was recorded with
``tls13_ticket_resumption_probe_measurement_v1.py``.  That source flattened
OpenSSL extension reports from all server handshake messages but labeled them
as ServerHello extensions.  This current probe preserves the same wire
experiment while making the parser scope explicit.  It does not infer a
containing handshake message from OpenSSL's flattened ``-tlsextdebug`` lines.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

import tls13_ticket_resumption_probe_measurement_v1 as measurement_v1


ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).resolve()


def summarize(output: str, *, expected_reused: bool) -> dict[str, object]:
    reused = (
        f"Reused, TLSv1.3, Cipher is {measurement_v1.CIPHER}" in output
    )
    fresh = f"New, TLSv1.3, Cipher is {measurement_v1.CIPHER}" in output
    if expected_reused:
        if not reused:
            raise AssertionError("provider did not resume the supplied session")
    elif not fresh:
        raise AssertionError("fresh connection did not negotiate the fixed cipher")
    if f"Negotiated TLS1.3 group: {measurement_v1.GROUP}" not in output:
        raise AssertionError("fixed X25519MLKEM768 group was not negotiated")
    if "ALPN protocol: http/1.1" not in output:
        raise AssertionError("HTTP/1.1 ALPN was not negotiated")

    statuses = [
        int(item)
        for item in measurement_v1.HTTP_RE.findall(output)
    ]
    if not statuses:
        raise AssertionError("credential-free HEAD response was not observed")
    messages = measurement_v1.handshake_messages(output)
    sequence = measurement_v1.first_sequence(messages)
    if expected_reused:
        forbidden = {"Certificate", "CertificateVerify"}
        if forbidden.intersection(sequence):
            raise AssertionError(
                "resumed handshake unexpectedly carried a certificate proof"
            )
        required = [
            "ClientHello",
            "ServerHello",
            "EncryptedExtensions",
            "Finished",
            "Finished",
        ]
        if sequence != required:
            raise AssertionError(
                f"unexpected resumed handshake sequence: {sequence}"
            )

    extensions = [
        {"name": name, "id": int(number), "bytes": int(length)}
        for name, number, length in measurement_v1.EXTENSION_RE.findall(output)
    ]
    if expected_reused:
        names = {str(item["name"]) for item in extensions}
        if not {"psk", "key share"}.issubset(names):
            raise AssertionError(
                "resumed server-handshake extension reports did not include "
                "both PSK and key share"
            )

    return {
        "reused": reused,
        "fixed_cipher": measurement_v1.CIPHER,
        "fixed_group": measurement_v1.GROUP,
        "alpn": "http/1.1",
        "http_status": statuses[0],
        "first_handshake_sequence": sequence,
        "handshake_messages": messages,
        "observed_extensions_across_server_handshake": extensions,
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
    }


def run_probe(settle_seconds: float) -> dict[str, object]:
    measurement_v1.BUILD.mkdir(parents=True, exist_ok=True)
    if measurement_v1.SESSION.exists():
        measurement_v1.SESSION.unlink()
    try:
        fresh_output = measurement_v1.run_client(
            session_in=False,
            settle_seconds=settle_seconds,
        )
        if (
            not measurement_v1.SESSION.is_file()
            or measurement_v1.SESSION.stat().st_size == 0
        ):
            raise AssertionError(
                "fresh connection did not produce a session file"
            )
        resumed_output = measurement_v1.run_client(
            session_in=True,
            settle_seconds=settle_seconds,
        )
    finally:
        if measurement_v1.SESSION.exists():
            measurement_v1.SESSION.unlink()

    return {
        "schema": "seed-tls13-ticket-live-v2",
        "recorded_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "kind": "credential-free host/OpenSSL provider observation",
        "provenance": {
            "source": str(SOURCE.relative_to(ROOT)),
            "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "parser_ancestor": str(
                measurement_v1.SOURCE.relative_to(ROOT)
            ),
            "parser_ancestor_sha256": hashlib.sha256(
                measurement_v1.SOURCE.read_bytes()
            ).hexdigest(),
            "settle_seconds": settle_seconds,
            "session_psk_file_destroyed_after_probe": (
                not measurement_v1.SESSION.exists()
            ),
            "extension_parser_scope": (
                "OpenSSL text extension reports are flattened across all "
                "server handshake messages; containing-message attribution "
                "is not preserved"
            ),
        },
        "openssl": measurement_v1.openssl_version(),
        "request": {
            "method": "HEAD",
            "path": "/v1/models",
            "host": measurement_v1.HOST,
            "bytes": len(measurement_v1.REQUEST),
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
            "extension_message_attribution_preserved": False,
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
