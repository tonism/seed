#!/usr/bin/env python3
"""Build and run the full TLS 1.3 symmetric overlay on a literal 16 KiB PC."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HEAD_REQUEST = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"\r\n"
)
BUILD = ROOT / "build/crypto-bench/tls13-sym-literal16k"
ASM = HERE / "tls13_sym_literal16k_harness.asm"
OVERLAY_ASM = HERE / "tls13_sym_overlay.asm"
CHECKER = HERE / "check_tls13_sym_overlay.py"
RUNNER = HERE.parent / "tls13-spike" / "run_8088_16k.py"
DEFAULT_RESULTS = HERE / "tls13_sym_literal16k_results.json"

TIMING_RE = re.compile(
    r"^(IFIN|INIT|RESUME) PASS t=(\d+) i=(\d+) c=(\d+)$",
    re.MULTILINE,
)
LOAD_RE = re.compile(r"^LOAD PASS t=(\d+) s=(\d+)$", re.MULTILINE)
TICK_SECONDS = 1.0 / 18.20648193


def run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=capture,
    )


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_sym_literal16k_checker", CHECKER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECKER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def checksum_bytes(value: bytes) -> int:
    return sum(value) & 0xFFFF


def write_fixture(name: str, value: bytes) -> Path:
    path = BUILD / name
    path.write_bytes(value)
    return path


def make_fixtures() -> dict[str, object]:
    check = load_checker()
    oracle = check.O
    base = check.BASE
    fixture = oracle.build_integrated_fixture()

    hello = fixture.client_hello + fixture.server_hello
    shared = fixture.candidate_mlkem_secret + fixture.server_x25519_public
    zeros = b"\0" * 32
    empty_hash = hashlib.sha256(b"").digest()
    initial = check.derive_handshake(shared, hello)
    messages = list(fixture.server_flight_messages)
    before_finished = b"".join(messages[:-1])
    server_verify = hmac.new(
        initial["server_finished"],
        hashlib.sha256(hello + before_finished).digest(),
        hashlib.sha256,
    ).digest()
    messages[-1] = b"\x14\x00\x00\x20" + server_verify
    flight_content = b"".join(messages)
    flight_record = base.encrypted_record(
        initial["server_key"],
        initial["server_iv"],
        0,
        oracle.CONTENT_HANDSHAKE,
        flight_content,
    )
    through_server_finished = hello + flight_content
    initial_server_hash = hashlib.sha256(through_server_finished).digest()
    initial_client_verify = hmac.new(
        initial["client_finished"], initial_server_hash, hashlib.sha256
    ).digest()
    initial_client_message = b"\x14\x00\x00\x20" + initial_client_verify
    initial_client_record = base.encrypted_record(
        initial["client_key"],
        initial["client_iv"],
        0,
        oracle.CONTENT_HANDSHAKE,
        initial_client_message,
    )
    initial_application = oracle._derive_application(
        initial["handshake_secret"], through_server_finished
    )
    initial_derived = base.hkdf_expand_label(
        initial["handshake_secret"], b"derived", empty_hash, 32
    )
    initial_master = base.hkdf_extract(initial_derived, zeros)
    initial_client_app_secret = base.derive_secret(
        initial_master, b"c ap traffic", through_server_finished
    )
    initial_server_app_secret = base.derive_secret(
        initial_master, b"s ap traffic", through_server_finished
    )
    full_initial_transcript = through_server_finished + initial_client_message
    resumption_master = base.derive_secret(
        initial_application["master_secret"],
        b"res master",
        full_initial_transcript,
    )
    initial_head = base.encrypted_record(
        initial_application["client_key"],
        initial_application["client_iv"],
        0,
        oracle.CONTENT_APPLICATION_DATA,
        HEAD_REQUEST,
    )

    identity = hashlib.shake_256(b"Seed TLS13 overlay ticket").digest(192)
    nonce = bytes(range(1, 9))
    nst = oracle.build_new_session_ticket(identity=identity, nonce=nonce)
    nst_record = base.encrypted_record(
        initial_application["server_key"],
        initial_application["server_iv"],
        0,
        oracle.CONTENT_HANDSHAKE,
        nst,
    )
    ticket_psk = base.hkdf_expand_label(
        resumption_master, b"resumption", nonce, 32
    )

    placeholder_ch, truncated_ch = check.build_resumption_client_hello(
        fixture.client_hello, identity, 0x10203040, b"\0" * 32
    )
    binder_hash = hashlib.sha256(truncated_ch).digest()
    early = base.hkdf_extract(zeros, ticket_psk)
    binder_key = base.hkdf_expand_label(early, b"res binder", empty_hash, 32)
    binder_finished = base.hkdf_expand_label(binder_key, b"finished", b"", 32)
    binder = hmac.new(binder_finished, binder_hash, hashlib.sha256).digest()
    early_derived = base.hkdf_expand_label(early, b"derived", empty_hash, 32)
    resumed_ch, resumed_truncated = check.build_resumption_client_hello(
        fixture.client_hello, identity, 0x10203040, binder
    )
    if resumed_truncated != truncated_ch or placeholder_ch[:-32] != resumed_ch[:-32]:
        raise AssertionError("resumption binder geometry drifted")
    resumed_sh = check.build_resumption_server_hello(fixture.server_hello)
    resumed_hello = resumed_ch + resumed_sh
    resumed_handshake_secret = base.hkdf_extract(early_derived, shared)
    resumed = check.derive_traffic(resumed_handshake_secret, resumed_hello)
    resumed_ee = check.RESUMED_ENCRYPTED_EXTENSIONS
    resumed_server_verify = hmac.new(
        resumed["server_finished"],
        hashlib.sha256(resumed_hello + resumed_ee).digest(),
        hashlib.sha256,
    ).digest()
    resumed_finished = b"\x14\x00\x00\x20" + resumed_server_verify
    resumed_flight_content = resumed_ee + resumed_finished
    resumed_flight_record = base.encrypted_record(
        resumed["server_key"],
        resumed["server_iv"],
        0,
        oracle.CONTENT_HANDSHAKE,
        resumed_flight_content,
    )
    resumed_through_finished = resumed_hello + resumed_flight_content
    resumed_server_hash = hashlib.sha256(resumed_through_finished).digest()
    resumed_client_verify = hmac.new(
        resumed["client_finished"], resumed_server_hash, hashlib.sha256
    ).digest()
    resumed_client_message = b"\x14\x00\x00\x20" + resumed_client_verify
    resumed_client_record = base.encrypted_record(
        resumed["client_key"],
        resumed["client_iv"],
        0,
        oracle.CONTENT_HANDSHAKE,
        resumed_client_message,
    )
    resumed_application = oracle._derive_application(
        resumed_handshake_secret, resumed_through_finished
    )
    resumed_derived = base.hkdf_expand_label(
        resumed_handshake_secret, b"derived", empty_hash, 32
    )
    resumed_master = base.hkdf_extract(resumed_derived, zeros)
    resumed_client_app_secret = base.derive_secret(
        resumed_master, b"c ap traffic", resumed_through_finished
    )
    resumed_server_app_secret = base.derive_secret(
        resumed_master, b"s ap traffic", resumed_through_finished
    )
    resumed_full_transcript = resumed_through_finished + resumed_client_message
    resumed_resumption_master = base.derive_secret(
        resumed_master, b"res master", resumed_full_transcript
    )
    resumed_head = base.encrypted_record(
        resumed_application["client_key"],
        resumed_application["client_iv"],
        0,
        oracle.CONTENT_APPLICATION_DATA,
        HEAD_REQUEST,
    )

    def split_record(record: bytes) -> tuple[bytes, bytes, bytes]:
        return record[:5], record[5:-16], record[-16:]

    init_header, init_cipher, init_tag = split_record(flight_record)
    nst_header, nst_cipher, nst_tag = split_record(nst_record)
    resumed_header, resumed_cipher, resumed_tag = split_record(
        resumed_flight_record
    )

    initial_handoff = bytearray(
        check.build_hello_handoff(hello, fixture.server_x25519_public)
    )
    initial_candidate_k_offset = len(initial_handoff)
    initial_handoff.extend(fixture.candidate_mlkem_secret)
    initial_finished_offset = len(initial_handoff)
    initial_handoff.extend(server_verify)

    resumed_handoff = bytearray(
        check.build_hello_handoff(
            resumed_hello, fixture.server_x25519_public
        )
    )
    resumed_candidate_k_offset = len(resumed_handoff)
    resumed_handoff.extend(fixture.candidate_mlkem_secret)
    resumed_binder_hash_offset = len(resumed_handoff)
    resumed_handoff.extend(binder_hash)
    resumed_finished_offset = len(resumed_handoff)
    resumed_handoff.extend(resumed_server_verify)
    if initial_candidate_k_offset != 171 or resumed_candidate_k_offset != 171:
        raise AssertionError("HELLO low handoff ABI drifted")

    record_meta = init_header + init_tag + nst_header + nst_tag
    record_meta += resumed_header + resumed_tag
    if len(record_meta) != 63:
        raise AssertionError("record metadata geometry drifted")

    paths = {
        "initial_handoff": write_fixture(
            "initial_handoff.bin", bytes(initial_handoff)
        ),
        "resumed_handoff": write_fixture(
            "resumed_handoff.bin", bytes(resumed_handoff)
        ),
        "record_meta": write_fixture("record_meta.bin", record_meta),
        "initial_flight_cipher": write_fixture(
            "initial_flight_cipher.bin", init_cipher
        ),
        "nst_cipher": write_fixture("nst_cipher.bin", nst_cipher),
        "resumed_flight_cipher": write_fixture(
            "resumed_flight_cipher.bin", resumed_cipher
        ),
    }
    initial_security_state = (
        initial["handshake_secret"]
        + initial["client_secret"]
        + initial["server_secret"]
        + initial["client_key"]
        + initial["client_iv"]
        + initial["client_finished"]
        + initial["server_key"]
        + initial["server_iv"]
        + initial["server_finished"]
        + initial_derived
        + initial_master
        + initial_client_app_secret
        + initial_server_app_secret
        + initial_application["client_key"]
        + initial_application["client_iv"]
        + initial_application["server_key"]
        + initial_application["server_iv"]
        + resumption_master
        + ticket_psk
    )
    resumed_security_state = (
        resumed["handshake_secret"]
        + resumed["client_secret"]
        + resumed["server_secret"]
        + resumed["client_key"]
        + resumed["client_iv"]
        + resumed["client_finished"]
        + resumed["server_key"]
        + resumed["server_iv"]
        + resumed["server_finished"]
        + resumed_derived
        + resumed_master
        + resumed_client_app_secret
        + resumed_server_app_secret
        + resumed_application["client_key"]
        + resumed_application["client_iv"]
        + resumed_application["server_key"]
        + resumed_application["server_iv"]
        + resumed_resumption_master
        + ticket_psk
    )
    if len(initial_security_state) != 528 or len(resumed_security_state) != 528:
        raise AssertionError("contiguous symmetric security-state geometry drifted")
    metadata = {
        "initial_hello_bytes": len(hello),
        "hello_handoff_bytes": initial_candidate_k_offset,
        "initial_candidate_k_offset": initial_candidate_k_offset,
        "initial_finished_offset": initial_finished_offset,
        "initial_flight_cipher_bytes": len(init_cipher),
        "initial_flight_hash_prefix": len(flight_content) - 36,
        "initial_client_finished_record_bytes": len(initial_client_record),
        "initial_client_finished_checksum": checksum_bytes(initial_client_record),
        "initial_security_state_checksum": checksum_bytes(initial_security_state),
        "initial_head_record_bytes": len(initial_head),
        "initial_head_checksum_expected": checksum_bytes(initial_head),
        "nst_cipher_bytes": len(nst_cipher),
        "nst_message_bytes": len(nst),
        "nst_message_checksum": checksum_bytes(nst),
        "resumed_hello_bytes": len(resumed_hello),
        "resumed_candidate_k_offset": resumed_candidate_k_offset,
        "resumed_binder_hash_offset": resumed_binder_hash_offset,
        "resumed_finished_offset": resumed_finished_offset,
        "resumed_flight_cipher_bytes": len(resumed_cipher),
        "resumed_flight_hash_prefix": len(resumed_ee),
        "resumed_client_finished_record_bytes": len(resumed_client_record),
        "resumed_client_finished_checksum": checksum_bytes(resumed_client_record),
        "resumed_security_state_checksum": checksum_bytes(resumed_security_state),
        "resumed_head_record_bytes": len(resumed_head),
        "resumed_head_checksum_expected": checksum_bytes(resumed_head),
        "resumption_binder_checksum": checksum_bytes(binder),
        "record_meta_content_bytes": len(record_meta),
    }
    include = "".join(f"{key} equ {value}\n" for key, value in metadata.items())
    (BUILD / "fixture_meta.inc").write_text(include, encoding="ascii")
    return {
        "metadata": metadata,
        "paths": {
            key: {
                "path": str(path.relative_to(ROOT)),
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for key, path in paths.items()
        },
    }


def assemble_overlay() -> Path:
    output = BUILD / "tls13_sym_overlay.bin"
    listing = BUILD / "tls13_sym_overlay.lst"
    run(
        [
            "nasm",
            "-f",
            "bin",
            "-DTLS13_SHARED_SECRET_LEN=64",
            f"-I{ROOT}/",
            f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
            "-l",
            str(listing),
            "-o",
            str(output),
            str(OVERLAY_ASM),
        ]
    )
    return output


def assemble_harness() -> Path:
    output = BUILD / "tls13_sym_literal16k_harness.bin"
    listing = BUILD / "tls13_sym_literal16k_harness.lst"
    run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT}/",
            "-l",
            str(listing),
            "-o",
            str(output),
            str(ASM),
        ]
    )
    return output


def parse_timings(serial_text: str) -> dict[str, object]:
    load_match = LOAD_RE.search(serial_text)
    timing_matches = {
        {"ifin": "initial_finished", "init": "initial", "resume": "resumed"}[
            match.group(1).lower()
        ]: match
        for match in TIMING_RE.finditer(serial_text)
    }
    if load_match is None or set(timing_matches) != {
        "initial_finished",
        "initial",
        "resumed",
    }:
        raise AssertionError(f"missing timing lines in target output:\n{serial_text}")

    def seconds(ticks: int) -> float:
        return round(ticks * TICK_SECONDS, 3)

    result: dict[str, object] = {
        "tick_hz": 18.20648193,
        "overlay_load": {
            "ticks": int(load_match.group(1)),
            "seconds": seconds(int(load_match.group(1))),
            "sectors": int(load_match.group(2)),
        },
    }
    for name, match in timing_matches.items():
        total, io, compute = (int(match.group(index)) for index in range(2, 5))
        if total - io != compute:
            raise AssertionError(f"{name} timing arithmetic drifted")
        result[name] = {
            "total_ticks": total,
            "total_seconds": seconds(total),
            "fixture_disk_ticks": io,
            "fixture_disk_seconds": seconds(io),
            "target_compute_residual_ticks": compute,
            "target_compute_residual_seconds": seconds(compute),
        }
    initial = result["initial"]
    finished = result["initial_finished"]
    assert isinstance(initial, dict) and isinstance(finished, dict)
    post_total = int(initial["total_ticks"]) - int(finished["total_ticks"])
    post_io = int(initial["fixture_disk_ticks"]) - int(
        finished["fixture_disk_ticks"]
    )
    post_compute = post_total - post_io
    result["initial_post_client_finished"] = {
        "total_ticks": post_total,
        "total_seconds": seconds(post_total),
        "fixture_disk_ticks": post_io,
        "fixture_disk_seconds": seconds(post_io),
        "target_compute_residual_ticks": post_compute,
        "target_compute_residual_seconds": seconds(post_compute),
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-16k", action="store_true")
    parser.add_argument("--profile", default="vm-net-ne2k8")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--json-out", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args()

    BUILD.mkdir(parents=True, exist_ok=True)
    fixtures = make_fixtures()
    overlay = assemble_overlay()
    harness = assemble_harness()
    if overlay.stat().st_size > 15 * 512:
        raise AssertionError("symmetric overlay escaped the 15-sector K window")
    image = harness.read_bytes()
    if int.from_bytes(image[15:17], "little") != 4:
        raise AssertionError("literal harness no longer has four resident sectors")

    offline = run(
        [sys.executable, str(CHECKER)],
        capture=True,
    )
    offline_result = json.loads(offline.stdout)
    if offline_result["status"] != "pass":
        raise AssertionError("symmetric Unicorn gate did not pass")

    summary: dict[str, object] = {
        "kind": "literal_16k_477mhz_tls13_symmetric_full_path_timing",
        "status": "offline-pass",
        "actual_target_run": False,
        "harness": {
            "source": str(ASM.relative_to(ROOT)),
            "image_bytes": len(image),
            "image_sectors": (len(image) + 511) // 512,
            "resident_sectors": 4,
            "resident_bytes": 2048,
            "sha256": hashlib.sha256(image).hexdigest(),
        },
        "overlay": {
            "bytes": overlay.stat().st_size,
            "sectors": (overlay.stat().st_size + 511) // 512,
            "sha256": hashlib.sha256(overlay.read_bytes()).hexdigest(),
        },
        "fixtures": fixtures,
        "offline_oracle": {
            "status": offline_result["status"],
            "coverage": offline_result["coverage"],
            "image_sha256": offline_result["image_sha256"],
        },
        "timing_scope": {
            "actual": (
                "BIOS-tick measurements on the literal target; total includes "
                "fixture-sector reads and resident orchestration"
            ),
            "compute_residual": (
                "total minus BIOS ticks observed inside fixture-sector reads; "
                "includes resident copies/loops and has 54.925 ms tick granularity"
            ),
            "modeled": [],
            "excluded": [
                "TCP/IP and NIC transfer",
                "real server latency",
                "ML-KEM key generation/candidate work",
                "X.509/CertificateVerify authentication",
            ],
        },
    }

    if args.run_16k:
        runner_json = BUILD / "runner_result.json"
        command = [
            sys.executable,
            str(RUNNER),
            "--asm",
            str(ASM),
            "--resident-sectors",
            "4",
            "--profile",
            args.profile,
            "--timeout",
            str(args.timeout),
            "--done-token",
            "DONE",
            "--json-out",
            str(runner_json),
        ]
        run(command)
        target = json.loads(runner_json.read_text(encoding="utf-8"))
        if not target.get("done"):
            raise AssertionError("literal target did not complete")
        if "FAIL" in target.get("serial_text", ""):
            raise AssertionError(f"literal target failed:\n{target['serial_text']}")
        summary["status"] = "pass"
        summary["actual_target_run"] = True
        summary["target"] = target
        summary["timings"] = parse_timings(target["serial_text"])

    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
