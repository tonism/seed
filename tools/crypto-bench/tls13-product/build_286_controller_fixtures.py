#!/usr/bin/env python3
"""Build deterministic inputs for the 286 TLS 1.3 controller smoke gate.

The symmetric overlay and wire fixtures come from the already oracle-gated
literal-16-KiB PoC.  This builder adds the exact boundaries that the 286
controller must expose around that overlay:

* the post-receive ServerHello transcript update;
* the authenticated compressed-Certificate byte pin;
* the RFC 8446 CertificateVerify signed input and digest; and
* the four-message protected-flight layout used by the strict parser.

All outputs are ignored build artifacts.  No generated fixture is a trust
anchor: the controller smoke uses them only as deterministic target vectors.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
POC = HERE.parent / "tls13-poc"
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench/tls13-286-controller"
POC_BUILD = ROOT / "build/crypto-bench/tls13-sym-literal16k"
POC_BUILDER = POC / "build_tls13_sym_literal16k_timing.py"
POC_CHECKER = POC / "check_tls13_sym_overlay.py"
REPORT = BUILD / "fixtures.json"


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def write(name: str, value: bytes) -> dict[str, object]:
    path = BUILD / name
    path.write_bytes(value)
    return {
        "path": str(path.relative_to(ROOT)),
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }


def checksum16(value: bytes) -> int:
    return sum(value) & 0xFFFF


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)

    # Rebuild the exact PoC overlay/fixtures, including its independent
    # Unicorn gate.  The command does not launch 86Box without --run-16k.
    subprocess.run(
        [
            sys.executable,
            str(POC_BUILDER),
            "--json-out",
            str(BUILD / "poc-build.json"),
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    checker = load_module(POC_CHECKER, "seed_tls13_286_controller_checker")
    fixture = checker.O.build_integrated_fixture()

    messages = tuple(fixture.server_flight_messages)
    if [len(message) for message in messages] != [10, 1799, 80, 36]:
        raise AssertionError("OpenAI compact protected-flight geometry drifted")
    if [message[0] for message in messages] != [8, 25, 15, 20]:
        raise AssertionError("protected-flight message order drifted")

    client_hello = fixture.client_hello
    server_hello = fixture.server_hello
    hello = client_hello + server_hello
    ee, compressed_certificate, certificate_verify, finished = messages
    flight_plaintext = b"".join(messages)
    before_cv = hello + ee + compressed_certificate
    cv_signed_input = checker.BASE.certificate_verify_input(before_cv)
    cv_digest = hashlib.sha256(cv_signed_input).digest()

    # A handoff after only ClientHello lets the target gate the unavoidable
    # post-ServerHello SHA work.  A second handoff restores the complete
    # ClientHello..ServerHello state for the symmetric controller path.
    client_handoff = checker.build_hello_handoff(
        client_hello, fixture.server_x25519_public
    )
    full_handoff = checker.build_hello_handoff(
        hello, fixture.server_x25519_public
    )
    if len(client_handoff) != 171 or len(full_handoff) != 171:
        raise AssertionError("HELLO handoff ABI drifted")

    record_meta = (POC_BUILD / "record_meta.bin").read_bytes()
    initial_cipher = (POC_BUILD / "initial_flight_cipher.bin").read_bytes()
    if len(record_meta) != 63 or len(initial_cipher) != 1926:
        raise AssertionError("symmetric PoC record fixture drifted")

    outputs = {
        "sym_overlay": write(
            "tls13_sym_overlay.bin",
            (POC_BUILD / "tls13_sym_overlay.bin").read_bytes(),
        ),
        "client_hello_handoff": write(
            "client-hello-handoff.bin", client_handoff
        ),
        "full_hello_handoff": write("full-hello-handoff.bin", full_handoff),
        "server_hello": write("server-hello.bin", server_hello),
        "hello_digest": write("hello-digest.bin", hashlib.sha256(hello).digest()),
        "mlkem_secret": write(
            "mlkem-secret.bin", fixture.candidate_mlkem_secret
        ),
        "record_meta": write("record-meta.bin", record_meta),
        "flight_cipher": write("flight-cipher.bin", initial_cipher),
        "flight_plaintext": write("flight-plaintext.bin", flight_plaintext),
        "compressed_certificate_pin": write(
            "compressed-certificate-pin.bin", compressed_certificate
        ),
        "cv_signed_input": write("cv-signed-input.bin", cv_signed_input),
        "cv_digest": write("cv-digest.bin", cv_digest),
    }

    metadata = {
        "client_hello_bytes": len(client_hello),
        "server_hello_bytes": len(server_hello),
        "hello_handoff_bytes": len(full_handoff),
        "flight_cipher_bytes": len(initial_cipher),
        "flight_plaintext_bytes": len(flight_plaintext),
        "encrypted_extensions_bytes": len(ee),
        "compressed_certificate_bytes": len(compressed_certificate),
        "certificate_verify_bytes": len(certificate_verify),
        "finished_bytes": len(finished),
        "pre_cv_plaintext_bytes": len(ee) + len(compressed_certificate),
        "pre_finished_plaintext_bytes": (
            len(ee) + len(compressed_certificate) + len(certificate_verify)
        ),
        "cv_signed_input_bytes": len(cv_signed_input),
        "client_finished_record_bytes": 58,
        "client_finished_checksum": 7092,
        "flight_plaintext_checksum": checksum16(flight_plaintext),
        "compressed_certificate_checksum": checksum16(compressed_certificate),
        "cv_digest_checksum": checksum16(cv_digest),
    }
    include = "".join(
        f"controller_{key} equ {value}\n" for key, value in metadata.items()
    )
    (BUILD / "fixture_meta.inc").write_text(include, encoding="ascii")

    report = {
        "kind": "seed-286-tls13-controller-fixtures-v1",
        "security_scope": (
            "deterministic target smoke vectors only; no generated byte is a "
            "product trust anchor"
        ),
        "geometry": metadata,
        "outputs": outputs,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
