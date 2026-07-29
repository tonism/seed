#!/usr/bin/env python3
"""Audit the frozen exact-speed read-only authentication PoC offline."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RESULT = HERE / "read_only_auth_literal16k_results.json"
BUILDER = HERE / "build_read_only_auth_literal16k.py"
HARNESS = HERE / "read_only_auth_literal16k.asm"
ISSUER = HERE / "issuer_auth_overlay.asm"
GATE = HERE / "read_only_commit_gate.asm"
LIVE_LEAF = HERE / "issuer_auth_live_leaf.pem"
LIVE_VECTOR = HERE / "issuer_auth_live_vector.json"
RUNNER = HERE.parent / "tls13-spike" / "run_8088_16k.py"
BOOTSTRAP = ROOT / "targets/ibm_pc_5150/basic/bootstrap.asm"
BASIC_BUILDER = ROOT / "tools/build-basic-bootstrap.py"
VM_HARNESS = ROOT / "tools/run-basic-bootstrap-86box.py"
BUILD = ROOT / "build/crypto-bench/tls13-read-only-auth"

SECTOR_BYTES = 512
CONTAINER_SECTORS = 24
RESIDENT_SECTORS = 4
ISSUER_SECTORS = 14
GATE_SECTORS = 2
CORE_START_LBA = 11
FLOPPY_BYTES = 160 * 1024
TICK_SECONDS = 65536.0 / 1193182.0

EXPECTED_SERIAL = (
    "AUTH1 PASS t=984 ticks\n"
    "AUTH2 PASS t=986 ticks\n"
    "FORGE PASS\n"
    "COMMIT PASS\n"
    "RETRY PASS\n"
    "UNLOCK PASS\n"
    "READONLY PASS reads=34 bios=34 blocked=1\n"
    "PASS\n"
    "RESULT\n"
)
EXPECTED_LINES = EXPECTED_SERIAL.splitlines()
EXPECTED_CLAIMS = {
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
}
EXPECTED_MEMORY = {
    "issuer_input": ["0x3400", "0x34af"],
    "credential_destination_phase_reuses_issuer_input": ["0x3400", "0x34c1"],
    "issuer_commit": ["0x3600", "0x3672"],
    "ticket_psk": ["0x38b0", "0x38d0"],
    "ticket_identity_nonce_meta": ["0x3b40", "0x3c2d"],
    "commit_control": ["0x3c30", "0x3c40"],
    "credential_publication": ["0x3c40", "0x3c46"],
    "reconnect_untouched": ["0x3c9c", "0x3de6"],
    "arena_context_untouched": ["0x3e40", "0x3f00"],
}
EXPECTED_SCOPE = (
    "exact 16-KiB cold-phase WE1 leaf + CertificateVerify arithmetic, "
    "native RAM-only ticket coexistence, LIVE_TICKET atomic commit, "
    "full-bundle callback authorization, bounded status-last credential "
    "publication with retryable failure, and runtime-enforced read-only "
    "media path; fixture-fed and not a live TLS chain"
)
EXPECTED_CREDENTIAL_GATE = {
    "header_version": 4,
    "callback": "0x1580",
    "phase_key": "0x6b14",
    "destination": "0x3400",
    "direct_callback_calls": 1,
    "caller_selectable_calls": 0,
    "resident_callback_abi_checked": True,
    "resident_callback_header_version_checked": True,
    "resident_callback_authorize_entry": "0x195d",
    "resident_callback_revalidates_full_bundle": True,
    "credential_publication_status_last": True,
    "credential_publication_bytes": 6,
    "retryable_partial_failure_exercised_by_guest": True,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path}: top level is not an object")
    return value


def checked_repo_path(value: str, label: str) -> Path:
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise AssertionError(f"{label}: path escapes repository: {value}") from exc
    require(path.is_file(), f"{label}: missing {value}")
    return path


def require_current_hash(
    path: Path, expected: str, label: str
) -> None:
    actual = sha256_file(path)
    require(
        actual == expected,
        f"{label}: current SHA-256 {actual}, frozen record has {expected}",
    )


def validate_machine(run: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "model": "IBM PC 5150",
        "cpu": "8088",
        "cpu_hz": 4_772_728,
        "installed_ram_kib": 16,
        "dynarec": False,
        "entry": "ROM BASIC sidecar",
    }
    require(run.get("machine") == expected, "exact floor-machine evidence drifted")
    require(run.get("global_config_override") is None, "unexpected config override")
    require(
        run.get("emulator_launch")
        == "LaunchServices --vmpath + fixed COM FIFO",
        "unexpected emulator launch path",
    )
    require(run.get("done") is True, "runner did not reach RESULT")
    require(run.get("start_seen") is True, "runner did not see ROAUTH start")
    require(
        run.get("start_timeout_hit") is False,
        "runner recorded a start timeout",
    )
    require(
        run.get("startup_failure_screenshot") is None,
        "runner recorded a startup failure screenshot",
    )
    require(run.get("load_start") == "0x1000", "resident load start drifted")
    require(run.get("loaded_end") == "0x1800", "resident load end drifted")
    require(run.get("bootstrap_start") == "0x3a00", "bootstrap address drifted")
    require(run.get("ram_top") == "0x4000", "16 KiB RAM ceiling drifted")
    require(run.get("stack_guard_bytes") == 256, "stack guard drifted")
    require(
        run.get("resident_sectors") == RESIDENT_SECTORS,
        "resident sector count drifted",
    )
    return expected


def validate_serial(
    result: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    run = result["run"]
    guest = result["guest"]
    require(isinstance(run, dict) and isinstance(guest, dict), "run/guest shape")
    serial = run.get("serial_text")
    require(serial == EXPECTED_SERIAL, "serial milestone stream drifted")
    require(guest.get("lines") == EXPECTED_LINES, "guest line parse drifted")
    require(guest.get("success") is True, "guest success is false")
    require(
        guest.get("required_milestones") is True,
        "FORGE/COMMIT/RETRY/UNLOCK milestone evidence is absent",
    )
    require(
        guest.get("ticks") == {"auth1": 984, "auth2": 986},
        "authentication tick evidence drifted",
    )
    expected_reads = (
        2 * int(manifest["images"]["issuer_sectors"])
        + int(manifest["images"]["gate_sectors"])
        + 4
    )
    require(expected_reads == 34, "derived cold-phase read count drifted")
    require(guest.get("disk_reads") == expected_reads, "disk read count drifted")
    require(
        guest.get("bios_interrupt_calls") == expected_reads,
        "runtime-traced BIOS interrupt count drifted",
    )
    require(
        guest.get("bios_write_requests_blocked") == 1,
        "runtime BIOS write-rejection self-test drifted",
    )
    require(
        run.get("emulator_stdout_bytes")
        == len(("ROAUTH POC\n" + EXPECTED_SERIAL).encode("ascii")),
        "captured emulator byte count drifted",
    )
    auth_seconds = {
        "auth1": round(984 * TICK_SECONDS, 6),
        "auth2": round(986 * TICK_SECONDS, 6),
    }
    require(
        float(run.get("elapsed_wall_seconds", 0))
        > (984 + 986) * TICK_SECONDS,
        "wall time is shorter than both recorded authentication passes",
    )
    return {
        "lines": EXPECTED_LINES,
        "ticks": {"auth1": 984, "auth2": 986},
        "seconds": auth_seconds,
        "disk_reads": expected_reads,
        "bios_interrupt_calls": expected_reads,
        "bios_write_requests_blocked": 1,
    }


def validate_read_only_evidence(run: dict[str, Any]) -> dict[str, Any]:
    media = run.get("floppy_media")
    require(isinstance(media, dict), "run lacks floppy-media evidence")
    require(media.get("read_only_requested") is True, "read-only flag absent")
    require(media.get("mode_during_run") == "0o444", "run mode was not 0444")
    require(
        media.get("host_write_open_denied") is True,
        "host write-open denial was not observed",
    )
    before = media.get("sha256_before")
    after = media.get("sha256_after")
    require(
        isinstance(before, str)
        and re.fullmatch(r"[0-9a-f]{64}", before) is not None,
        "invalid before-run floppy SHA-256",
    )
    require(before == after, "floppy hash changed during the VM run")
    require(media.get("unchanged") is True, "unchanged flag is false")
    require(media.get("mode_restored") is True, "floppy mode was not restored")
    command = shlex.split(str(run.get("command", "")))
    require(
        command.count("--floppy-read-only") == 1,
        "frozen runner command lacks one --floppy-read-only flag",
    )
    return {
        "requested": True,
        "mode_during_run": "0o444",
        "host_write_open_denied": True,
        "before_after_sha256": before,
        "unchanged": True,
        "mode_restored": True,
    }


def validate_source_hashes(result: dict[str, Any]) -> list[str]:
    manifest = result["manifest"]
    provenance = manifest["provenance"]
    current: list[tuple[str, Path, str]] = [
        ("builder", BUILDER, provenance["builder_sha256"]),
        ("harness", HARNESS, provenance["harness_sha256"]),
        ("issuer", ISSUER, provenance["issuer_sha256"]),
        ("gate", GATE, provenance["gate_sha256"]),
        ("live leaf", LIVE_LEAF, provenance["live_leaf_sha256"]),
        ("live vector", LIVE_VECTOR, provenance["live_vector_sha256"]),
    ]
    run = result["run"]
    path_hash_fields = (
        ("source", "source_sha256"),
        ("runner", "runner_sha256"),
        ("bootstrap_source", "bootstrap_source_sha256"),
        ("basic_builder", "basic_builder_sha256"),
        ("vm_harness", "vm_harness_sha256"),
    )
    for path_field, hash_field in path_hash_fields:
        path = checked_repo_path(str(run[path_field]), f"run {path_field}")
        current.append((f"run {path_field}", path, str(run[hash_field])))
    require(
        run["source"] == provenance["harness"],
        "run source and manifest harness differ",
    )
    require(
        run["source_sha256"] == provenance["harness_sha256"],
        "run and manifest harness hashes differ",
    )
    for label, path, expected in current:
        require_current_hash(path, expected, label)

    encoded_manifest = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    require(
        sha256_bytes(encoded_manifest) == result["manifest_sha256"],
        "embedded manifest hash does not match frozen manifest_sha256",
    )
    return [label for label, _path, _expected in current]


def parse_range(value: object, label: str) -> tuple[int, int]:
    require(
        isinstance(value, list) and len(value) == 2,
        f"{label}: expected one half-open range",
    )
    start, end = (int(str(part), 0) for part in value)
    require(start < end, f"{label}: empty or reversed range")
    return start, end


def validate_manifest(manifest: dict[str, Any], run: dict[str, Any]) -> None:
    require(
        manifest.get("schema") == "seed-tls13-read-only-auth-literal16k-v3",
        "manifest schema drifted",
    )
    require(manifest.get("status") == "offline-pass", "manifest status drifted")
    require(manifest.get("scope") == EXPECTED_SCOPE, "manifest scope drifted")
    require(manifest.get("claims") == EXPECTED_CLAIMS, "claim boundary drifted")
    require(manifest.get("memory") == EXPECTED_MEMORY, "memory ledger drifted")
    require(
        manifest.get("credential_gate") == EXPECTED_CREDENTIAL_GATE,
        "fixed credential gate ABI drifted",
    )

    images = manifest["images"]
    require(
        images["container_bytes"] == CONTAINER_SECTORS * SECTOR_BYTES
        and images["container_sectors"] == CONTAINER_SECTORS,
        "container geometry drifted",
    )
    require(
        images["resident_bytes"] == RESIDENT_SECTORS * SECTOR_BYTES,
        "resident geometry drifted",
    )
    require(
        13 * SECTOR_BYTES < images["issuer_bytes"] <= 14 * SECTOR_BYTES
        and images["issuer_sectors"] == ISSUER_SECTORS,
        "issuer phase geometry drifted",
    )
    require(
        SECTOR_BYTES < images["gate_bytes"] <= 2 * SECTOR_BYTES
        and images["gate_sectors"] == GATE_SECTORS,
        "commit-gate geometry drifted",
    )
    require(
        run["image_bytes"] == images["container_bytes"]
        and run["image_sectors"] == images["container_sectors"]
        and run["image_sha256"] == images["container_sha256"],
        "runner image and manifest container differ",
    )

    issuer_input = parse_range(EXPECTED_MEMORY["issuer_input"], "issuer_input")
    credential_destination = parse_range(
        EXPECTED_MEMORY["credential_destination_phase_reuses_issuer_input"],
        "credential_destination_phase_reuses_issuer_input",
    )
    ranges = [
        parse_range(EXPECTED_MEMORY[name], name)
        for name in (
            "issuer_commit",
            "ticket_psk",
            "ticket_identity_nonce_meta",
            "commit_control",
            "credential_publication",
            "reconnect_untouched",
            "arena_context_untouched",
        )
    ]
    require(
        issuer_input[0] == credential_destination[0]
        and issuer_input[1] <= credential_destination[1] <= 0x3510,
        "credential slot does not safely phase-reuse relocated issuer input",
    )
    require(
        all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])),
        "manifest memory ranges overlap",
    )
    require(ranges[-1][1] == 0x3F00, "arena/context tail reaches stack guard")
    require(
        0x1800 + ISSUER_SECTORS * SECTOR_BYTES == issuer_input[0],
        "14-sector issuer reload does not end at relocated input",
    )
    require(
        0x1800 + GATE_SECTORS * SECTOR_BYTES <= issuer_input[0],
        "commit-gate load reaches relocated issuer input",
    )
    require(
        int(run["load_start"], 0) + images["resident_bytes"]
        == int(run["loaded_end"], 0),
        "resident prefix/load range mismatch",
    )

    read_only = manifest["read_only_media"]
    require(
        read_only
        == {
            "source_int13_sites": 1,
            "resident_int13_sites": 1,
            "bios_functions_allowed": [
                "AH=02 read one sector",
                "AH=00 reset after error",
            ],
            "runtime_function_trace": True,
            "unsupported_function_rejected_before_interrupt": True,
            "runtime_write_rejection_self_test": "AH=03",
            "write_service_present": False,
        },
        "manifest read-only BIOS surface drifted",
    )


def fingerprint(path: Path) -> tuple[bool, int | None, str | None]:
    if not path.exists():
        return False, None, None
    return True, path.stat().st_mtime_ns, sha256_file(path)


def require_padded(
    container: bytes,
    offset: int,
    capacity: int,
    payload: bytes,
    label: str,
) -> None:
    require(len(payload) <= capacity, f"{label}: payload exceeds capacity")
    require(
        container[offset : offset + len(payload)] == payload,
        f"{label}: container payload differs",
    )
    require(
        container[offset + len(payload) : offset + capacity]
        == bytes(capacity - len(payload)),
        f"{label}: nonzero sector padding",
    )


def rebuild_builder_output(
    frozen_manifest: dict[str, Any],
    frozen_manifest_sha256: str,
) -> dict[str, Any]:
    runner_record = BUILD / "runner-result.json"
    record_before = fingerprint(runner_record)
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    process = subprocess.run(
        [sys.executable, str(BUILDER)],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
        env=environment,
    )
    regenerated_stdout = json.loads(process.stdout)
    regenerated_path = BUILD / "manifest.json"
    regenerated = load_object(regenerated_path)
    require(
        regenerated_stdout == regenerated == frozen_manifest,
        "offline builder manifest is not reproducible",
    )
    require(
        sha256_file(regenerated_path) == frozen_manifest_sha256,
        "offline builder manifest byte hash drifted",
    )
    require(
        fingerprint(runner_record) == record_before,
        "offline builder touched the saved 86Box runner record",
    )

    artifact_names = {
        "container": "read_only_auth_literal16k.bin",
        "issuer": "issuer_auth_read_only.bin",
        "gate": "read_only_commit_gate.bin",
        "leaf": "issuer_leaf_fixture.bin",
        "cv": "issuer_cv_fixture.bin",
        "ticket": "ticket_fixture.bin",
        "canary": "canary_fixture.bin",
        "meta": "fixture_meta.inc",
    }
    artifacts = {
        name: BUILD / filename for name, filename in artifact_names.items()
    }
    for label, path in artifacts.items():
        require(path.is_file(), f"offline builder omitted {label}")

    images = regenerated["images"]
    require(
        artifacts["container"].stat().st_size == images["container_bytes"]
        and sha256_file(artifacts["container"]) == images["container_sha256"],
        "rebuilt container differs from manifest",
    )
    require(
        artifacts["issuer"].stat().st_size == images["issuer_bytes"]
        and sha256_file(artifacts["issuer"]) == images["issuer_sha256"],
        "rebuilt issuer phase differs from manifest",
    )
    require(
        artifacts["gate"].stat().st_size == images["gate_bytes"]
        and sha256_file(artifacts["gate"]) == images["gate_sha256"],
        "rebuilt commit gate differs from manifest",
    )
    for name in ("leaf", "cv", "ticket", "canary", "meta"):
        expected = regenerated["fixtures"][name]
        require(
            artifacts[name].stat().st_size == expected["bytes"]
            and sha256_file(artifacts[name]) == expected["sha256"],
            f"rebuilt {name} fixture differs from manifest",
        )

    container = artifacts["container"].read_bytes()
    require(
        len(container) == CONTAINER_SECTORS * SECTOR_BYTES,
        "rebuilt container length drifted",
    )
    require(container[3:11] == b"SEEDCORE", "resident SEEDCORE header drifted")
    offset = RESIDENT_SECTORS * SECTOR_BYTES
    require_padded(
        container,
        offset,
        ISSUER_SECTORS * SECTOR_BYTES,
        artifacts["issuer"].read_bytes(),
        "issuer phase",
    )
    offset += ISSUER_SECTORS * SECTOR_BYTES
    for name in ("leaf", "cv", "ticket"):
        require_padded(
            container,
            offset,
            SECTOR_BYTES,
            artifacts[name].read_bytes(),
            f"{name} fixture",
        )
        offset += SECTOR_BYTES
    require_padded(
        container,
        offset,
        GATE_SECTORS * SECTOR_BYTES,
        artifacts["gate"].read_bytes(),
        "commit gate",
    )
    offset += GATE_SECTORS * SECTOR_BYTES
    require_padded(
        container,
        offset,
        SECTOR_BYTES,
        artifacts["canary"].read_bytes(),
        "canary fixture",
    )
    offset += SECTOR_BYTES
    require(offset == len(container), "container phase ledger is incomplete")
    return {
        "manifest_exact": True,
        "manifest_sha256": frozen_manifest_sha256,
        "container_sha256": images["container_sha256"],
        "container_layout_exact": True,
        "runner_record_untouched": True,
        "emulator_rerun": False,
    }


def load_runner_module() -> ModuleType:
    name = "seed_read_only_literal16k_offline_runner"
    spec = importlib.util.spec_from_file_location(name, RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {RUNNER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def rebuild_runner_floppy(
    expected_container_sha256: str,
    expected_floppy_sha256: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="seed-read-only-literal16k-"
    ) as temp_name:
        runner = load_runner_module()
        runner.BUILD = Path(temp_name)
        artifacts = runner.build_artifacts(
            HARNESS,
            [],
            resident_sectors=RESIDENT_SECTORS,
        )
        require(
            artifacts["core_bytes"] == CONTAINER_SECTORS * SECTOR_BYTES
            and artifacts["core_sha256"] == expected_container_sha256,
            "runner's offline core build differs from frozen container",
        )
        require(
            artifacts["core_sectors"] == CONTAINER_SECTORS
            and artifacts["resident_sectors"] == RESIDENT_SECTORS
            and artifacts["loaded_end"] == 0x1800,
            "runner's offline resident geometry drifted",
        )
        floppy_path = artifacts["floppy"]
        floppy = floppy_path.read_bytes()
        core = artifacts["core"].read_bytes()
        core_offset = CORE_START_LBA * SECTOR_BYTES
        require(len(floppy) == FLOPPY_BYTES, "runner floppy size drifted")
        require(
            floppy[:core_offset] == bytes(core_offset),
            "runner floppy prefix is not empty",
        )
        require(
            floppy[core_offset : core_offset + len(core)] == core,
            "runner floppy does not contain the exact core",
        )
        require(
            floppy[core_offset + len(core) :]
            == bytes(FLOPPY_BYTES - core_offset - len(core)),
            "runner floppy tail is not empty",
        )
        actual_floppy_sha256 = sha256_bytes(floppy)
        require(
            actual_floppy_sha256 == expected_floppy_sha256,
            "offline runner floppy differs from physical-run evidence",
        )
    return {
        "container_sha256": expected_container_sha256,
        "floppy_bytes": FLOPPY_BYTES,
        "floppy_sha256": expected_floppy_sha256,
        "86box_started": False,
    }


def runner_option_contract() -> dict[str, Any]:
    process = subprocess.run(
        [sys.executable, str(RUNNER), "--help"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    require(
        "--floppy-read-only" in process.stdout,
        "runner help does not expose --floppy-read-only",
    )
    source = RUNNER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    option_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        and any(
            isinstance(argument, ast.Constant)
            and argument.value == "--floppy-read-only"
            for argument in node.args
        )
    ]
    require(len(option_calls) == 1, "runner option declaration is not unique")
    actions = {
        keyword.arg: keyword.value
        for keyword in option_calls[0].keywords
        if keyword.arg is not None
    }
    require(
        isinstance(actions.get("action"), ast.Constant)
        and actions["action"].value == "store_true",
        "--floppy-read-only is not a store_true option",
    )

    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    run_function = functions.get("run_literal_16k")
    require(run_function is not None, "runner lacks run_literal_16k")
    arguments = [argument.arg for argument in run_function.args.args]
    arguments.extend(argument.arg for argument in run_function.args.kwonlyargs)
    require(
        "floppy_read_only" in arguments,
        "run_literal_16k does not accept the read-only flag",
    )
    run_source = ast.get_source_segment(source, run_function) or ""
    enforcement_fragments = (
        "if floppy_read_only:",
        "floppy.chmod(0o444)",
        "os.open(floppy, os.O_WRONLY)",
        "except PermissionError:",
        'raise RuntimeError("read-only floppy still permits a write open")',
        "floppy_hash_after = hashlib.sha256(floppy.read_bytes()).hexdigest()",
        "floppy.chmod(original_floppy_mode)",
        '"unchanged": floppy_hash_before == floppy_hash_after',
        "stat.S_IMODE(floppy.stat().st_mode) == original_floppy_mode",
    )
    for fragment in enforcement_fragments:
        require(
            fragment in run_source,
            f"runner read-only enforcement lost {fragment!r}",
        )

    forwarding = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_literal_16k"
    ]
    require(len(forwarding) == 1, "runner call to run_literal_16k drifted")
    keyword = next(
        (
            item
            for item in forwarding[0].keywords
            if item.arg == "floppy_read_only"
        ),
        None,
    )
    require(
        keyword is not None
        and isinstance(keyword.value, ast.Attribute)
        and isinstance(keyword.value.value, ast.Name)
        and keyword.value.value.id == "args"
        and keyword.value.attr == "floppy_read_only",
        "CLI read-only option is not forwarded to the run",
    )
    builder_source = BUILDER.read_text(encoding="utf-8")
    require(
        '"--floppy-read-only"' in builder_source,
        "read-only PoC builder does not request runner protection",
    )
    return {
        "help_exposes_option": True,
        "store_true_option": True,
        "forwarded_to_run": True,
        "chmod_0444_before_launch": True,
        "host_write_open_must_fail": True,
        "before_after_hash_recorded": True,
        "original_mode_restored": True,
    }


def audit() -> dict[str, Any]:
    result = load_object(RESULT)
    require(
        result.get("schema")
        == "seed-tls13-read-only-auth-literal16k-run-v3",
        "result schema drifted",
    )
    require(result.get("status") == "pass", "result status is not pass")
    manifest = result.get("manifest")
    run = result.get("run")
    require(isinstance(manifest, dict), "result lacks embedded manifest")
    require(isinstance(run, dict), "result lacks run evidence")

    machine = validate_machine(run)
    validate_manifest(manifest, run)
    serial = validate_serial(result, manifest)
    read_only = validate_read_only_evidence(run)
    current_sources = validate_source_hashes(result)
    runner_contract = runner_option_contract()
    builder_rebuild = rebuild_builder_output(
        manifest, str(result["manifest_sha256"])
    )
    runner_rebuild = rebuild_runner_floppy(
        str(manifest["images"]["container_sha256"]),
        str(read_only["before_after_sha256"]),
    )

    return {
        "schema": "seed-tls13-read-only-auth-literal16k-offline-audit-v1",
        "status": "PASS",
        "frozen_result": str(RESULT.relative_to(ROOT)),
        "frozen_result_sha256": sha256_file(RESULT),
        "machine": machine,
        "serial": serial,
        "physical_read_only_evidence": read_only,
        "current_source_hashes": {
            "validated": len(current_sources),
            "labels": current_sources,
        },
        "manifest": {
            "schema": manifest["schema"],
            "geometry_and_ranges": "pass",
            "read_only_media_surface": "pass",
            "claims": EXPECTED_CLAIMS,
        },
        "runner_read_only_contract": runner_contract,
        "offline_builder_rebuild": builder_rebuild,
        "offline_runner_floppy_rebuild": runner_rebuild,
        "claim_boundary": {
            "fixture_fed": True,
            "live_network_chain": False,
            "fresh_entropy": False,
            "trusted_time": False,
            "secure_floor_proven": False,
            "86box_rerun_by_checker": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = audit()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("READ-ONLY AUTH LITERAL 16K OFFLINE AUDIT: PASS")
        print(
            "  exact-speed 86Box configuration: 8088 @ 4.772728 MHz, 16 KiB, "
            "dynarec off, ROM BASIC"
        )
        print(
            "  guest: AUTH1=984 ticks, AUTH2=986 ticks, "
            "34 runtime-traced read-only BIOS calls, AH=03 blocked before INT"
        )
        print(
            "  host read-only evidence: mode 0444, host write-open denied, "
            "before/after image hashes identical, mode restored"
        )
        print(
            "  offline rebuild: manifest, 24-sector container, and "
            "160 KiB runner floppy reproduced; 86Box not started"
        )
        print("  secure floor proven: no")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
