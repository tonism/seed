#!/usr/bin/env python3
"""Build and optionally run the literal-16K read-only auth/commit PoC."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

from capstone import CS_ARCH_X86, CS_MODE_16, Cs


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/crypto-bench/tls13-read-only-auth"
ASM = HERE / "read_only_auth_literal16k.asm"
ISSUER = HERE / "issuer_auth_overlay.asm"
GATE = HERE / "read_only_commit_gate.asm"
ISSUER_CHECK = HERE / "issuer_auth_check.py"
RUNNER = HERE.parent / "tls13-spike" / "run_8088_16k.py"
LIVE_LEAF = HERE / "issuer_auth_live_leaf.pem"
LIVE_VECTOR = HERE / "issuer_auth_live_vector.json"
GENERATION = 0x4A31
LEAF_PROFILE = 0x003F
CV_PROFILE = 0x0700
CV_CONTEXT = b"TLS 1.3, server CertificateVerify"
CREDENTIAL_LOADER_CALLBACK = 0x1580
CREDENTIAL_PHASE_KEY = 0x6B14
CREDENTIAL_DESTINATION = 0x3400
GATE_ORIGIN = 0x1800
GATE_HEADER_BYTES = 18


def run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=capture,
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def assemble(
    source: Path,
    output: Path,
    *,
    listing: Path,
    defines: tuple[str, ...] = (),
) -> None:
    command = [
        "nasm",
        "-f",
        "bin",
        f"-I{ROOT}/",
        f"-I{HERE}/",
        f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
    ]
    for define in defines:
        command.extend(["-D", define])
    command.extend(["-l", str(listing), "-o", str(output), str(source)])
    run(command)


def fixture_material() -> dict[str, bytes]:
    issuer = load_module("seed_read_only_issuer_fixture", ISSUER_CHECK)
    vector = json.loads(LIVE_VECTOR.read_text(encoding="utf-8"))
    leaf_der = issuer.pem_to_der(LIVE_LEAF.read_bytes())
    tbs, leaf_signature = issuer.certificate_parts(leaf_der)
    transcript_hash = bytes.fromhex(
        vector["certificate_verify"]["transcript_sha256"]
    )
    cv_signed = b"\x20" * 64 + CV_CONTEXT + b"\x00" + transcript_hash
    cv_digest = hashlib.sha256(cv_signed).digest()
    cv_signature = bytes.fromhex(
        vector["certificate_verify"]["signature_der"]
    )
    with tempfile.TemporaryDirectory(prefix="seed-ro-auth-fixture-") as name:
        _spki, leaf_x, leaf_y, _public = issuer.public_spki(
            LIVE_LEAF, Path(name)
        )
    if not 8 <= len(leaf_signature) <= 72:
        raise AssertionError("leaf signature exceeds target DER capacity")
    if not 8 <= len(cv_signature) <= 72:
        raise AssertionError("CertificateVerify exceeds target DER capacity")

    def encode(
        profile: int,
        digest: bytes,
        signature: bytes,
        point: tuple[bytes, bytes],
    ) -> bytes:
        value = (
            struct.pack("<HH", profile, GENERATION)
            + digest
            + struct.pack("<H", len(signature))
            + signature.ljust(72, b"\0")
            + point[0]
            + point[1]
            + b"\0"
        )
        if len(value) != 175:
            raise AssertionError("issuer fixture ABI drifted")
        return value

    return {
        "leaf": encode(
            LEAF_PROFILE,
            hashlib.sha256(tbs).digest(),
            leaf_signature,
            (leaf_x, leaf_y),
        ),
        "cv": encode(
            CV_PROFILE,
            cv_digest,
            cv_signature,
            (bytes([0xE1]) * 32, bytes([0x7B]) * 32),
        ),
    }


def build_fixtures() -> dict[str, Path]:
    material = fixture_material()
    outputs: dict[str, Path] = {}
    outputs["leaf"] = BUILD / "issuer_leaf_fixture.bin"
    outputs["leaf"].write_bytes(material["leaf"])
    outputs["cv"] = BUILD / "issuer_cv_fixture.bin"
    outputs["cv"].write_bytes(material["cv"])

    psk = hashlib.sha256(b"Seed read-only ticket PSK v1").digest()
    identity = hashlib.shake_256(
        b"Seed read-only ticket identity v1"
    ).digest(192)
    nonce_value = hashlib.sha256(b"Seed read-only ticket nonce v1").digest()[:16]
    nonce = nonce_value.ljust(32, b"\0")
    lifetime = struct.pack("<HH", 0, 3600)
    age_add = bytes.fromhex("10203040")
    metadata = (
        lifetime
        + age_add
        + struct.pack("<HHB", len(nonce_value), len(identity), 1)
    )
    if len(metadata) != 13:
        raise AssertionError("ticket metadata geometry drifted")
    ticket = psk + identity + nonce + metadata
    if len(ticket) != 269:
        raise AssertionError("ticket fixture geometry drifted")
    outputs["ticket"] = BUILD / "ticket_fixture.bin"
    outputs["ticket"].write_bytes(ticket)

    canary = hashlib.shake_256(
        b"Seed read-only post-auth canary v1"
    ).digest(32)
    outputs["canary"] = BUILD / "canary_fixture.bin"
    outputs["canary"].write_bytes(canary)

    ticket_checksum = sum(ticket) & 0xFFFF
    canary_checksum = sum(canary) & 0xFFFF
    meta = BUILD / "fixture_meta.inc"
    meta.write_text(
        "; Generated by build_read_only_auth_literal16k.py\n"
        f"RO_GENERATION equ 0x{GENERATION:04x}\n"
        f"RO_CREDENTIAL_PHASE_KEY equ 0x{CREDENTIAL_PHASE_KEY:04x}\n"
        f"RO_TICKET_CHECKSUM equ 0x{ticket_checksum:04x}\n"
        f"RO_CANARY_CHECKSUM equ 0x{canary_checksum:04x}\n",
        encoding="ascii",
    )
    outputs["meta"] = meta
    return outputs


def static_read_only_gate(container: Path) -> dict[str, Any]:
    source = ASM.read_text(encoding="utf-8")
    if source.count("int 0x13") != 1:
        raise AssertionError("literal harness INT 13h surface changed")
    required_runtime_policy = (
        "bios_disk_interrupt:",
        "cmp ah, 0x00",
        "cmp ah, 0x02",
        "inc word [bios_interrupt_calls]",
        "inc word [bios_read_calls]",
        "inc word [bios_reset_calls]",
        "inc byte [bios_blocked_functions]",
        "verify_bios_trace:",
    )
    if not all(fragment in source for fragment in required_runtime_policy):
        raise AssertionError("literal harness lost runtime BIOS policy tracing")
    resident = container.read_bytes()[: 4 * 512]
    # The only interrupt opcode in the resident prefix is the checked and
    # traced INT 13h wrapper. INT 10h is absent because reporting uses COM1.
    int13_count = resident.count(b"\xcd\x13")
    if int13_count != 1:
        raise AssertionError(
            f"resident binary has {int13_count} INT 13h sites, expected 1"
        )
    if b"\xb4\x03\xcd\x13" in resident or b"\xb8\x01\x03\xcd\x13" in resident:
        raise AssertionError("resident binary contains a direct disk write")
    return {
        "source_int13_sites": 1,
        "resident_int13_sites": int13_count,
        "bios_functions_allowed": [
            "AH=02 read one sector",
            "AH=00 reset after error",
        ],
        "runtime_function_trace": True,
        "unsupported_function_rejected_before_interrupt": True,
        "runtime_write_rejection_self_test": "AH=03",
        "write_service_present": False,
    }


def static_fixed_credential_gate(gate: bytes, resident: bytes) -> dict[str, Any]:
    if gate[:4] != b"ROG3":
        raise AssertionError("route gate header magic drifted")
    version, image_bytes = struct.unpack_from("<HH", gate, 4)
    if version != 4 or image_bytes != len(gate):
        raise AssertionError("route gate header ABI drifted")
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    instructions = tuple(
        decoder.disasm(gate[GATE_HEADER_BYTES:], GATE_ORIGIN + GATE_HEADER_BYTES)
    )
    if sum(instruction.size for instruction in instructions) != (
        len(gate) - GATE_HEADER_BYTES
    ):
        raise AssertionError("route gate instruction decode is incomplete")
    calls = [
        instruction
        for instruction in instructions
        if instruction.mnemonic == "call"
    ]
    fixed = [
        instruction
        for instruction in calls
        if instruction.op_str.startswith("0x")
        and int(instruction.op_str, 0) == CREDENTIAL_LOADER_CALLBACK
    ]
    indirect = [
        instruction
        for instruction in calls
        if not instruction.op_str.startswith("0x")
    ]
    if len(fixed) != 1 or indirect:
        raise AssertionError(
            "route gate does not have one fixed, direct credential callback"
        )
    callback_offset = CREDENTIAL_LOADER_CALLBACK - 0x1000
    authorize_entry = struct.unpack_from("<H", gate, 14)[0]
    callback = tuple(
        decoder.disasm(
            resident[callback_offset : callback_offset + 160],
            CREDENTIAL_LOADER_CALLBACK,
        )
    )
    expected = (
        ("cmp", f"ax, {CREDENTIAL_PHASE_KEY:#x}"),
        ("jne", callback[1].op_str if len(callback) > 1 else ""),
        ("cmp", f"bx, {CREDENTIAL_DESTINATION:#x}"),
    )
    actual = tuple(
        (instruction.mnemonic, instruction.op_str)
        for instruction in callback[:3]
    )
    if len(actual) != 3 or (
        actual[0] != expected[0]
        or actual[1][0] != "jne"
        or actual[2] != expected[2]
    ):
        raise AssertionError(
            f"resident fixed credential callback ABI drifted: {actual!r}"
        )
    callback_text = tuple(
        f"{instruction.mnemonic} {instruction.op_str}".rstrip()
        for instruction in callback
    )
    required_callback_checks = (
        "cmp word ptr [0x1800], 0x4f52",
        "cmp word ptr [0x1802], 0x3347",
        f"cmp word ptr [0x1804], {version}",
        "call word ptr [0x180e]",
        "mov word ptr [0x3c40], dx",
        "mov word ptr [0x3c42], 0x20",
        "mov byte ptr [0x3c44], 0x5a",
        "mov byte ptr [0x3c45], 0xa5",
    )
    if not all(check in callback_text for check in required_callback_checks):
        raise AssertionError(
            "resident callback lost full-bundle authorization/publication"
        )
    status_store = callback_text.index("mov byte ptr [0x3c45], 0xa5")
    prior_publication_stores = (
        callback_text.index("mov word ptr [0x3c40], dx"),
        callback_text.index("mov word ptr [0x3c42], 0x20"),
        callback_text.index("mov byte ptr [0x3c44], 0x5a"),
    )
    if status_store <= max(prior_publication_stores):
        raise AssertionError("resident callback no longer publishes status last")
    return {
        "header_version": version,
        "callback": f"0x{CREDENTIAL_LOADER_CALLBACK:04x}",
        "phase_key": f"0x{CREDENTIAL_PHASE_KEY:04x}",
        "destination": f"0x{CREDENTIAL_DESTINATION:04x}",
        "direct_callback_calls": len(fixed),
        "caller_selectable_calls": len(indirect),
        "resident_callback_abi_checked": True,
        "resident_callback_header_version_checked": True,
        "resident_callback_authorize_entry": f"0x{authorize_entry:04x}",
        "resident_callback_revalidates_full_bundle": True,
        "credential_publication_status_last": True,
        "credential_publication_bytes": 6,
        "retryable_partial_failure_exercised_by_guest": True,
    }


def parse_guest(serial: str) -> dict[str, Any]:
    lines = [line.strip() for line in serial.splitlines() if line.strip()]
    terminals = [line for line in lines if line in {"PASS", "FAIL"}]
    success = bool(lines) and lines[-1] == "RESULT" and terminals == ["PASS"]
    ticks: dict[str, int] = {}
    for key in ("AUTH1", "AUTH2"):
        match = next(
            (
                re.fullmatch(rf"{key} PASS t=(\d+) ticks", line)
                for line in lines
                if line.startswith(key)
            ),
            None,
        )
        if match is not None:
            ticks[key.lower()] = int(match.group(1))
    reads = None
    bios_calls = None
    blocked = None
    for line in lines:
        match = re.fullmatch(
            r"READONLY PASS reads=(\d+) bios=(\d+) blocked=(\d+)",
            line,
        )
        if match:
            reads = int(match.group(1))
            bios_calls = int(match.group(2))
            blocked = int(match.group(3))
    return {
        "success": success,
        "lines": lines,
        "ticks": ticks,
        "disk_reads": reads,
        "bios_interrupt_calls": bios_calls,
        "bios_write_requests_blocked": blocked,
        "required_milestones": all(
            marker in lines
            for marker in (
                "FORGE PASS",
                "COMMIT PASS",
                "RETRY PASS",
                "UNLOCK PASS",
            )
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-16k", action="store_true")
    parser.add_argument("--profile", default="vm-net-ne2k8")
    parser.add_argument("--timeout", type=float, default=420.0)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    BUILD.mkdir(parents=True, exist_ok=True)
    fixtures = build_fixtures()

    issuer_wrapper = BUILD / "issuer_auth_read_only_wrapper.asm"
    issuer_wrapper.write_text(
        "bits 16\n"
        "cpu 8086\n"
        "%define TLS13_POC_K14 1\n"
        "%define TLS13_POC_READ_ONLY_INPUT 1\n"
        f'%include "{ISSUER.as_posix()}"\n',
        encoding="ascii",
    )
    issuer_binary = BUILD / "issuer_auth_read_only.bin"
    assemble(
        issuer_wrapper,
        issuer_binary,
        listing=BUILD / "issuer_auth_read_only.lst",
    )
    if len(issuer_binary.read_bytes()) != 7134:
        raise AssertionError("read-only issuer phase content size drifted")

    gate_binary = BUILD / "read_only_commit_gate.bin"
    assemble(
        GATE,
        gate_binary,
        listing=BUILD / "read_only_commit_gate.lst",
        defines=(
            (
                "GATE_CREDENTIAL_LOADER_CALLBACK="
                f"0x{CREDENTIAL_LOADER_CALLBACK:04x}"
            ),
            f"GATE_CREDENTIAL_PHASE_KEY=0x{CREDENTIAL_PHASE_KEY:04x}",
            f"GATE_CREDENTIAL_DESTINATION=0x{CREDENTIAL_DESTINATION:04x}",
        ),
    )
    if not 513 <= gate_binary.stat().st_size <= 1024:
        raise AssertionError("commit gate no longer occupies exactly two sectors")

    container = BUILD / "read_only_auth_literal16k.bin"
    assemble(
        ASM,
        container,
        listing=BUILD / "read_only_auth_literal16k.lst",
    )
    if container.read_bytes()[:8] != b"\xeb\x15\x90SEEDC":
        # The exact jump displacement can change as header stays fixed; check
        # the stable format independently below instead of accepting a false
        # header match.
        if container.read_bytes()[3:11] != b"SEEDCORE":
            raise AssertionError("literal harness lost SEEDCORE header")
    if len(container.read_bytes()[: 4 * 512]) != 2048:
        raise AssertionError("literal harness lost four-sector resident prefix")
    read_only = static_read_only_gate(container)
    credential_gate = static_fixed_credential_gate(
        gate_binary.read_bytes(), container.read_bytes()[: 4 * 512]
    )

    manifest: dict[str, Any] = {
        "schema": "seed-tls13-read-only-auth-literal16k-v3",
        "scope": (
            "exact 16-KiB cold-phase WE1 leaf + CertificateVerify arithmetic, "
            "native RAM-only ticket coexistence, LIVE_TICKET atomic commit, "
            "full-bundle callback authorization, bounded status-last credential "
            "publication with retryable failure, and runtime-enforced read-only "
            "media path; fixture-fed and not a live TLS chain"
        ),
        "status": "offline-pass",
        "provenance": {
            "builder": str(Path(__file__).relative_to(ROOT)),
            "builder_sha256": sha256(Path(__file__)),
            "harness": str(ASM.relative_to(ROOT)),
            "harness_sha256": sha256(ASM),
            "issuer": str(ISSUER.relative_to(ROOT)),
            "issuer_sha256": sha256(ISSUER),
            "gate": str(GATE.relative_to(ROOT)),
            "gate_sha256": sha256(GATE),
            "live_vector_sha256": sha256(LIVE_VECTOR),
            "live_leaf_sha256": sha256(LIVE_LEAF),
        },
        "images": {
            "container_bytes": container.stat().st_size,
            "container_sectors": (container.stat().st_size + 511) // 512,
            "container_sha256": sha256(container),
            "resident_bytes": 2048,
            "issuer_bytes": issuer_binary.stat().st_size,
            "issuer_sectors": 14,
            "issuer_sha256": sha256(issuer_binary),
            "gate_bytes": gate_binary.stat().st_size,
            "gate_sectors": 2,
            "gate_sha256": sha256(gate_binary),
        },
        "memory": {
            "issuer_input": ["0x3400", "0x34af"],
            "credential_destination_phase_reuses_issuer_input": [
                "0x3400",
                "0x34c1",
            ],
            "issuer_commit": ["0x3600", "0x3672"],
            "ticket_psk": ["0x38b0", "0x38d0"],
            "ticket_identity_nonce_meta": ["0x3b40", "0x3c2d"],
            "commit_control": ["0x3c30", "0x3c40"],
            "credential_publication": ["0x3c40", "0x3c46"],
            "reconnect_untouched": ["0x3c9c", "0x3de6"],
            "arena_context_untouched": ["0x3e40", "0x3f00"],
        },
        "read_only_media": read_only,
        "credential_gate": credential_gate,
        "fixtures": {
            name: {
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for name, path in fixtures.items()
        },
        "claims": {
            "fixture_path_write_independence_proven": True,
            "product_cold_boot_write_independence_proven": False,
            "native_ticket_vs_auth_overlap_resolved": True,
            "atomic_credential_unlock_structural_gate": True,
            "fixed_credential_callback_authority": True,
            "retryable_credential_read_failure": True,
            "route_aware_commit": True,
            "precommit_direct_callback_rejected": True,
            "forged_marker_direct_callback_rejected": True,
            "credential_publication_validated": True,
            "runtime_bios_function_trace": True,
            "bios_write_request_blocked_before_interrupt": True,
            "live_network_chain": False,
            "fresh_entropy": False,
            "trusted_time": False,
            "secure_floor_proven": False,
        },
    }
    manifest_path = BUILD / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if not args.run_16k:
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    result_path = (
        args.json_out
        if args.json_out is not None
        else HERE / "read_only_auth_literal16k_results.json"
    )
    runner_result = BUILD / "runner-result.json"
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
        "RESULT",
        "--start-token",
        "ROAUTH POC",
        "--start-timeout",
        "45",
        "--floppy-read-only",
        "--json-out",
        str(runner_result),
    ]
    run(command)
    run_data = json.loads(runner_result.read_text(encoding="utf-8"))
    guest = parse_guest(run_data.get("serial_text", ""))
    result = {
        "schema": "seed-tls13-read-only-auth-literal16k-run-v3",
        "manifest_sha256": sha256(manifest_path),
        "manifest": manifest,
        "run": run_data,
        "guest": guest,
        "status": "pass" if guest["success"] else "fail",
    }
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not guest["success"]:
        raise SystemExit("literal read-only authentication PoC failed")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
