#!/usr/bin/env python3
"""Publish the validated product-mode 8088 K14 phase pack and its ABI.

This is an offline source-integration gate.  Before it can publish anything it
runs the state-guard execution matrix and the complete product-route gate
(including config-escrow tamper rejection), asks both checked builders for a
fresh product-mode composition, and proves every padded phase slot plus the
complete flat pack byte-for-byte through the product-owned cpu-8086 pack root.

The ABI and pack are staged together in their destination directory.  The ABI
is replaced first and the pack is replaced last as the pair's commit marker.
The gate never launches a VM or network operation, packages USER.CFG, or
depends on a NIC driver or writable floppy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PRODUCT_BUILD = ROOT / "build/ibm_pc_5150"
PRODUCT_PACK_SOURCE = (
    ROOT
    / "targets/ibm_pc_5150/boot/tls13/k14_product_pack.asm"
)
PRODUCT_SOURCE_DIR = PRODUCT_PACK_SOURCE.parent
POC = ROOT / "tools/crypto-bench/tls13-poc"
BUILD_SECURE = POC / "build_live_k15.py"
BUILD_POST_AUTH = POC / "build_post_auth_live.py"
PRODUCT_ROUTE_GATE = (
    ROOT
    / "tools/crypto-bench/tls13-product/check_k14_product_route.py"
)
STATE_GUARD_GATE = ROOT / "tools/check-tls13-k14-state-guard.py"
SECTOR = 512
RESIDENT_BASE_SECTORS = 45

PRODUCT_ABI_DEFINES = {
    "TLS13_K14_PRODUCT_TOTAL_SECTORS",
    "TLS13_K14_PRODUCT_PACK_SECTORS",
    "TLS13_K14_PRODUCT_ROOT_PHASE_KEY",
    "TLS13_K14_PRODUCT_ROOT_DESTINATION",
    "TLS13_K14_PRODUCT_ROOT_ENTRY",
    "TLS13_K14_PRODUCT_STATE_GUARD_PHASE_KEY",
    "TLS13_K14_PRODUCT_STATE_GUARD_DESTINATION",
    "TLS13_K14_PRODUCT_STATE_GUARD_ENTRY",
    "TLS13_K14_PRODUCT_PUBLICATION_PHASE_KEY",
    "TLS13_K14_PRODUCT_PUBLICATION_ENTRY",
}

STATE_GUARD_CHECKS = (
    "abi_and_size",
    "pre_cold",
    "pre_cga",
    "pre_mda_wrap",
    "pre_mda_max255",
    "pre_ineligible",
    "post_mda_scrub_recovery",
    "post_cga_preservation",
    "post_hostile_state",
    "abort_and_unknown",
)

FORBIDDEN_PRODUCT_PHASES = {
    "post_auth_auth_callbacks",
    "post_auth_user_loader",
    "post_auth_request_callbacks",
    "post_auth_request",
    "post_auth_request_adapter",
    "post_auth_response",
    "post_auth_response_literals",
}

DIAGNOSTIC_DEFINES = (
    "HELLO_BINDER_DIAGNOSTIC",
    "LIVE_K15_TIMING_DIAGNOSTIC",
    "RESUME_CONTROLLER_DIAGNOSTIC",
    "RESUME_DIRECT_REPLAY_DIAGNOSTIC",
    "RESUME_EXCHANGE_DIAGNOSTIC",
    "RESUME_PREPARE_BINDER_DIAGNOSTIC",
    "RESUME_SYM_IO_DIAGNOSTIC",
)


@dataclass(frozen=True)
class Phase:
    name: str
    start: int
    sectors: int
    destination: int
    payload_bytes: int
    payload_sha256: str | None
    source: str

    @property
    def end(self) -> int:
        return self.start + self.sectors

    @property
    def key(self) -> int:
        return (self.sectors << 8) | self.start


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fail(message: str) -> None:
    raise AssertionError(message)


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise SystemExit(f"missing {label}: {path}")


def run(
    command: list[str],
    *,
    environment: dict[str, str] | None = None,
) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
    )
    if result.returncode:
        if result.stdout:
            print(result.stdout, end="")
        raise subprocess.CalledProcessError(result.returncode, command)
    return result.stdout


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path} does not contain a JSON object")
    return value


def parse_hex(value: object, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(
        r"0x[0-9a-fA-F]+", value
    ):
        fail(f"{label} is not a hexadecimal address")
    return int(value, 16)


def phase_from_manifest(
    value: object,
    *,
    source: str,
    destination_field: str,
) -> Phase:
    if not isinstance(value, dict):
        fail(f"{source} phase ledger contains a non-object")
    name = value.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]+", name):
        fail(f"{source} phase has an unsafe name")
    start = value.get("start_sector")
    sectors = value.get("sectors")
    payload_bytes = value.get("bytes")
    if (
        not isinstance(start, int)
        or not isinstance(sectors, int)
        or not isinstance(payload_bytes, int)
        or not 0 <= start <= 0xFF
        or not 1 <= sectors <= 0xFF
        or not 0 <= payload_bytes <= sectors * SECTOR
    ):
        fail(f"{name} has invalid sector/payload geometry")
    expected_key = (sectors << 8) | start
    if parse_hex(value.get("key"), f"{name} key") != expected_key:
        fail(f"{name} phase key does not encode its geometry")
    destination = parse_hex(
        value.get(destination_field), f"{name} load destination"
    )
    payload_hash = value.get("sha256")
    if payload_hash is not None and (
        not isinstance(payload_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", payload_hash)
    ):
        fail(f"{name} has an invalid payload digest")
    return Phase(
        name=name,
        start=start,
        sectors=sectors,
        destination=destination,
        payload_bytes=payload_bytes,
        payload_sha256=payload_hash,
        source=source,
    )


def assert_cpu_8086_sources() -> int:
    sources = sorted(
        {*POC.glob("*.asm"), *PRODUCT_SOURCE_DIR.glob("*.asm")}
    )
    if not sources:
        fail("TLS 1.3 assembly sources are missing")
    cpu_pattern = re.compile(r"(?m)^\s*cpu\s+8086\s*(?:;.*)?$")
    for source in sources:
        if not cpu_pattern.search(source.read_text(encoding="utf-8")):
            fail(f"TLS 1.3 assembly root is not locked to cpu 8086: {source}")
    return len(sources)


def validate_product_mode(
    base_manifest: dict[str, Any],
    post_manifest: dict[str, Any],
) -> None:
    base_mode = base_manifest.get("mode")
    identity = base_manifest.get("identity_checkpoint")
    secure_fo = base_manifest.get("secure_fo_checkpoint")
    product_abi = base_manifest.get("product_abi")
    persistent = base_manifest.get("persistent_services")
    if (
        not isinstance(base_mode, dict)
        or base_mode.get("product") is not True
        or base_mode.get("generic_vault") is not True
        or base_mode.get("patched_harness") is not False
    ):
        fail("base builder did not produce the product-mode generic-vault route")
    if (
        not isinstance(identity, dict)
        or identity.get("enabled") is not True
        or identity.get("credential_unlock") is not False
    ):
        fail("product base is not the credential-free identity checkpoint")
    if (
        not isinstance(secure_fo, dict)
        or secure_fo.get("enabled") is not True
        or secure_fo.get("credential_unlock") is not False
        or secure_fo.get("read_only_floppy_compatible") is not True
        or secure_fo.get("required_nic_family") is not None
        or secure_fo.get("packaged_driver") is not None
        or secure_fo.get("card_vault") is not None
    ):
        fail("product base is not the NIC-independent secure-FO/read-only route")
    if (
        not isinstance(product_abi, dict)
        or not all(
            isinstance(product_abi.get(name), dict)
            for name in ("root_entry", "vault", "config_escrow", "state_guard")
        )
        or not isinstance(persistent, dict)
        or not isinstance(persistent.get("root_frame_snapshot"), dict)
    ):
        fail(
            "product base lacks its root/vault/escrow/state-guard/"
            "root-frame ABI"
        )

    base_vault = product_abi["vault"]
    post_vault = post_manifest.get("vault_abi")
    raw_epoch = (
        post_vault.get("acquisition_raw_epoch")
        if isinstance(post_vault, dict)
        else None
    )
    raw_writer = (
        raw_epoch.get("deadline_raw_writer")
        if isinstance(raw_epoch, dict)
        else None
    )
    root_seed = (
        raw_epoch.get("root_symmetric_seed")
        if isinstance(raw_epoch, dict)
        else None
    )
    tail_restore = (
        raw_epoch.get("off_window_tail_restore")
        if isinstance(raw_epoch, dict)
        else None
    )
    critical_restore = (
        raw_epoch.get("critical_symmetric_restore")
        if isinstance(raw_epoch, dict)
        else None
    )
    expected_raw_writes = [
        {"page": "0x79", "source": "0x08c0", "bytes": 1088},
        {"page": "0x7e", "source": "0x0dab", "bytes": 128},
        {"page": "0x7f", "source": "0x0dab", "bytes": 128},
    ]
    if (
        not isinstance(base_vault, dict)
        or not isinstance(post_vault, dict)
        or post_vault.get("access_modes") != base_vault.get("access_modes")
        or not isinstance(raw_epoch, dict)
        or raw_epoch.get("enter_raw")
        != base_vault.get("enter_raw_preconnect")
        or raw_epoch.get("enter_raw_before_live_socket") is not True
        or raw_epoch.get("receipt_rebind")
        != base_vault.get("rebind_raw_receipt")
        or not isinstance(root_seed, dict)
        or root_seed.get("sectors") != 12
        or root_seed.get("load_span") != "0x1800..0x3000"
        or root_seed.get("preserved_critical_tail") != "0x2ee0..0x3000"
        or not isinstance(tail_restore, dict)
        or tail_restore.get("sectors") != 2
        or tail_restore.get("batch_calls") != 1
        or tail_restore.get("load_span") != "0x2800..0x2c00"
        or not isinstance(critical_restore, dict)
        or critical_restore.get("sectors") != 8
        or critical_restore.get("batch_calls") != 1
        or critical_restore.get("load_span") != "0x1800..0x2800"
        or not isinstance(raw_writer, dict)
        or raw_writer.get("entry")
        != base_vault.get("deadline_raw_writer", {}).get("entry")
        or raw_writer.get("range") != "0x2ee0..0x2f80"
        or raw_writer.get("image_bytes") != 160
        or raw_writer.get("code_bytes") != 159
        or raw_writer.get("embedded_continuation_source") != "0x2f80"
        or raw_writer.get("embedded_continuation_bytes") != 128
        or raw_writer.get("status_written_last") is not True
        or raw_writer.get("page_crc_tags_deliberately_stale") is not True
        or raw_writer.get("ordinary_access_forbidden_until_rebind") is not True
        or raw_writer.get("authority_granted") is not False
        or raw_writer.get("writes") != expected_raw_writes
        or raw_epoch.get("authority_gates")
        != [
            "TLS Server Finished",
            "full ML-KEM FO compare",
            "dated exact-leaf CertificateVerify",
        ]
    ):
        fail("product manifest lost the checked-to-raw acquisition boundary")

    mode = post_manifest.get("mode")
    security = post_manifest.get("security_chain")
    offline = post_manifest.get("offline_gates")
    publication = post_manifest.get("publication_abi")
    return_stack = (
        publication.get("return_stack")
        if isinstance(publication, dict)
        else None
    )
    if (
        post_manifest.get("schema") != "seed-tls13-k14-product-route-v1"
        or not isinstance(mode, dict)
        or mode.get("product") is not True
        or mode.get("tls") != "TLS 1.3 only"
        or mode.get("tier") != "8088 defensible Seed security boundary"
        or mode.get("same_boot_resumption_required") is not True
        or mode.get("read_only_media_compatible") is not True
        or mode.get("user_cfg") is not False
        or mode.get("fixed_lba_credential_loader") is not False
        or mode.get("one_shot_request_response") is not False
        or "diagnostic_state" in post_manifest
    ):
        fail("post builder did not produce the bounded TLS 1.3 product route")
    required_security = (
        "fresh_hello_product_tls13",
        "resumed_hello_product_tls13",
        "mlkem768_keygen_on_target",
        "fo_reencrypt_compare",
        "exact_leaf_p256",
        "authenticated_ticket_receipt",
        "fresh_psk_dhe_resumption",
        "authenticated_resumed_liveness",
        "route_authorized_before_publication",
    )
    if (
        not isinstance(security, dict)
        or any(security.get(name) is not True for name in required_security)
        or security.get("external_precomputation_required") is not False
    ):
        fail("product security chain is incomplete")
    if (
        not isinstance(offline, dict)
        or offline.get("base_manifest_and_core_unchanged") is not True
        or offline.get("phase_ledger_contiguous") is not True
        or offline.get("phase_tail_encodable") is not True
        or offline.get("generated_abi_include_bound_to_pack") is not True
        or offline.get("forbidden_product_phases_absent") is not True
        or offline.get("credential_shaped_literals_in_core") != 0
        or offline.get("one_shot_request_prefix_occurrences_in_core") != 0
        or offline.get("vm_or_network_launched") is not False
    ):
        fail("product reference does not satisfy its offline composition gate")

    assert isinstance(product_abi, dict)
    assert isinstance(persistent, dict)
    root_entry = product_abi["root_entry"]
    root_frame = persistent["root_frame_snapshot"]
    if (
        not isinstance(root_entry, dict)
        or not isinstance(root_frame, dict)
        or not isinstance(return_stack, dict)
        or parse_hex(
            return_stack.get("snapshot_start"),
            "publication root-frame snapshot start",
        )
        != parse_hex(root_frame.get("start"), "base root-frame snapshot start")
        or parse_hex(
            return_stack.get("snapshot_end"),
            "publication root-frame snapshot end",
        )
        != parse_hex(root_frame.get("end"), "base root-frame snapshot end")
        or parse_hex(return_stack.get("sp"), "publication root-frame SP")
        != parse_hex(root_frame.get("sp"), "base root-frame SP")
        or parse_hex(
            return_stack.get("sp_inverse"),
            "publication root-frame SP inverse",
        )
        != parse_hex(root_frame.get("sp_inverse"), "base root-frame SP inverse")
        or parse_hex(
            return_stack.get("status_word"),
            "publication root-frame status word",
        )
        != parse_hex(root_frame.get("inverse"), "base root-frame status inverse")
        or return_stack.get("status_value") != "0xa55a"
        or parse_hex(
            return_stack.get("expected_return"),
            "publication root-frame return",
        )
        != parse_hex(root_entry.get("resident_return"), "base root return")
        or return_stack.get("expected_sp_delta") != 6
        or return_stack.get("validates_before_first_stack_access") is not True
        or return_stack.get("adopts_validated_snapshot") is not True
        or parse_hex(
            return_stack.get("invalid_jumps_to_stackless_emergency_reset"),
            "publication root-frame emergency reset",
        )
        != parse_hex(persistent.get("emergency_reset"), "base emergency reset")
    ):
        fail("publication does not bind the status-last root-frame ABI")


def parse_nasm_defines(data: bytes) -> dict[str, int]:
    result: dict[str, int] = {}
    for raw in data.decode("ascii").splitlines():
        words = raw.split()
        if len(words) != 3 or words[0] != "%define":
            continue
        name = words[1]
        if name in result:
            fail(f"generated product ABI repeats {name}")
        try:
            result[name] = int(words[2], 0)
        except ValueError:
            fail(f"generated product ABI has a non-integer value for {name}")
    if set(result) != PRODUCT_ABI_DEFINES:
        missing = sorted(PRODUCT_ABI_DEFINES.difference(result))
        extra = sorted(set(result).difference(PRODUCT_ABI_DEFINES))
        fail(
            "generated product ABI definitions drifted: "
            f"missing={missing} extra={extra}"
        )
    return result


def validate_product_abi(
    abi_data: bytes,
    *,
    manifest: dict[str, Any],
    core: bytes,
    pack: bytes,
) -> dict[str, int]:
    defines = parse_nasm_defines(abi_data)
    root = manifest.get("root_abi")
    guard = manifest.get("state_guard_abi")
    publication = manifest.get("publication_abi")
    if (
        not isinstance(root, dict)
        or not isinstance(guard, dict)
        or not isinstance(publication, dict)
    ):
        fail("product manifest lacks an ABI bound by the generated include")
    expected = {
        "TLS13_K14_PRODUCT_TOTAL_SECTORS": len(core) // SECTOR,
        "TLS13_K14_PRODUCT_PACK_SECTORS": len(pack) // SECTOR,
        "TLS13_K14_PRODUCT_ROOT_PHASE_KEY": parse_hex(
            root.get("phase_key"), "root phase key"
        ),
        "TLS13_K14_PRODUCT_ROOT_DESTINATION": parse_hex(
            root.get("load_destination"), "root load destination"
        ),
        "TLS13_K14_PRODUCT_ROOT_ENTRY": parse_hex(
            root.get("call_address"), "root entry"
        ),
        "TLS13_K14_PRODUCT_STATE_GUARD_PHASE_KEY": parse_hex(
            guard.get("phase_key"), "state-guard phase key"
        ),
        "TLS13_K14_PRODUCT_STATE_GUARD_DESTINATION": parse_hex(
            guard.get("load_destination"), "state-guard destination"
        ),
        "TLS13_K14_PRODUCT_STATE_GUARD_ENTRY": parse_hex(
            guard.get("entry"), "state-guard entry"
        ),
        "TLS13_K14_PRODUCT_PUBLICATION_PHASE_KEY": parse_hex(
            publication.get("phase_key"), "publication phase key"
        ),
        "TLS13_K14_PRODUCT_PUBLICATION_ENTRY": parse_hex(
            publication.get("entry"), "publication entry"
        ),
    }
    if defines != expected:
        fail(f"generated product ABI values drifted: {defines} != {expected}")
    return defines


def stage_output(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    staged = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return staged


def publish_pack_and_abi(
    pack_path: Path,
    pack: bytes,
    abi_path: Path,
    abi: bytes,
) -> None:
    if pack_path.resolve() == abi_path.resolve():
        fail("product pack and ABI outputs must be distinct")
    if pack_path.parent.resolve() != abi_path.parent.resolve():
        fail("product pack and ABI must be published as sibling files")
    staged_abi = stage_output(abi_path, abi)
    staged_pack = stage_output(pack_path, pack)
    try:
        os.replace(staged_abi, abi_path)
        os.replace(staged_pack, pack_path)
        directory = os.open(pack_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        staged_abi.unlink(missing_ok=True)
        staged_pack.unlink(missing_ok=True)


def validate_payload(
    phase: Phase,
    slot: bytes,
    *,
    payload_hash: str | None = None,
) -> None:
    expected_size = phase.sectors * SECTOR
    if len(slot) != expected_size:
        fail(f"{phase.name} slot has the wrong extent")
    measured_hash = payload_hash or phase.payload_sha256
    if measured_hash is not None:
        if digest(slot[: phase.payload_bytes]) != measured_hash:
            fail(f"{phase.name} payload digest differs from its manifest")
    if any(slot[phase.payload_bytes :]):
        fail(f"{phase.name} has nonzero bytes after its measured payload")


def nasm_string(path: Path) -> str:
    value = str(path)
    if '"' in value or "\n" in value or "\r" in value:
        fail("temporary path cannot be represented as a NASM string")
    return f'"{value}"'


def write_generated_include(
    path: Path,
    phases: list[Phase],
    slots: dict[str, Path],
) -> None:
    pack_start = phases[0].start
    pack_end = phases[-1].end
    lines = [
        "; Generated by tools/check-tls13-product-pack.py.",
        "; Build-time phase slots only; not a runtime module table.",
        f"tls13_product_reference_start_sector equ {pack_start}",
        f"tls13_product_reference_end_sector equ {pack_end}",
        f"tls13_product_reference_phase_count equ {len(phases)}",
        "",
    ]
    for phase in phases:
        prefix = f"tls13_product_{phase.name}"
        lines.extend(
            [
                f"{prefix}_reference_sector equ {phase.start}",
                f"{prefix}_sectors equ {phase.sectors}",
                f"{prefix}_reference_key equ 0x{phase.key:04x}",
                f"{prefix}_load_destination equ 0x{phase.destination:04x}",
                f"{prefix}_start:",
                f"    incbin {nasm_string(slots[phase.name])}",
                f"{prefix}_end:",
                (
                    f"%if ({prefix}_end - {prefix}_start) "
                    f"!= {phase.sectors * SECTOR}"
                ),
                f'%error "{phase.name} product slot extent drifted"',
                "%endif",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "gate, build, compare, and optionally publish the product-owned "
            "8088/K14 TLS 1.3 flat pack and generated ABI"
        )
    )
    parser.add_argument(
        "--product-core",
        type=Path,
        default=PRODUCT_BUILD / "SEED.SYS",
    )
    parser.add_argument(
        "--product-listing",
        type=Path,
        default=PRODUCT_BUILD / "SEED.SYS.lst",
    )
    parser.add_argument(
        "--boot",
        type=Path,
        default=PRODUCT_BUILD / "boot.bin",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--loader",
        type=Path,
        default=PRODUCT_BUILD / "loader.bin",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--ne-driver",
        type=Path,
        default=PRODUCT_BUILD / "drivers/NE.DRV",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--json-out", type=Path)
    parser.add_argument(
        "--pack-out",
        type=Path,
        help=(
            "after every equivalence gate passes, publish the validated flat "
            "phase pack at this path for inclusion in product SEED.SYS"
        ),
    )
    parser.add_argument(
        "--abi-out",
        type=Path,
        help=(
            "publish the generated ABI beside --pack-out; defaults to "
            "tls13-k14-product-abi.inc in the pack directory"
        ),
    )
    parser.add_argument(
        "--keep-build",
        type=Path,
        help="retain the offline reference/pack build at this path",
    )
    args = parser.parse_args()
    if args.abi_out is not None and args.pack_out is None:
        parser.error("--abi-out requires --pack-out")
    abi_out = args.abi_out
    if args.pack_out is not None and abi_out is None:
        abi_out = args.pack_out.with_name("tls13-k14-product-abi.inc")
    if (
        args.pack_out is not None
        and abi_out is not None
        and args.pack_out.parent.resolve() != abi_out.parent.resolve()
    ):
        parser.error("--pack-out and --abi-out must be sibling files")

    for path, label in (
        (PRODUCT_PACK_SOURCE, "product TLS 1.3 pack root"),
        (BUILD_SECURE, "product base builder"),
        (BUILD_POST_AUTH, "product post-auth builder"),
        (PRODUCT_ROUTE_GATE, "product-route gate"),
        (STATE_GUARD_GATE, "state-guard gate"),
        (args.product_core, "product SEED.SYS"),
        (args.product_listing, "product SEED.SYS listing"),
    ):
        require_file(path, label)
    if shutil.which("nasm") is None:
        raise SystemExit("nasm is required")

    source_count = assert_cpu_8086_sources()
    temp_owner: tempfile.TemporaryDirectory[str] | None = None
    if args.keep_build is None:
        temp_owner = tempfile.TemporaryDirectory(
            prefix="seed-tls13-product-pack-"
        )
        work = Path(temp_owner.name)
    else:
        work = args.keep_build.resolve()
        if work.exists() and any(work.iterdir()):
            raise SystemExit(f"--keep-build directory is not empty: {work}")
        work.mkdir(parents=True, exist_ok=True)

    try:
        state_guard_stdout = run([sys.executable, str(STATE_GUARD_GATE)])
        try:
            state_guard_report = json.loads(state_guard_stdout)
        except json.JSONDecodeError as exc:
            fail(f"state-guard gate did not emit its JSON report: {exc}")
        if (
            not isinstance(state_guard_report, dict)
            or state_guard_report.get("status") != "ok"
            or state_guard_report.get("phase") != "k14_product_state_guard"
            or state_guard_report.get("checks") != list(STATE_GUARD_CHECKS)
        ):
            fail("state-guard prerequisite did not return its complete PASS")
        state_guard_report_path = work / "state-guard-gate.json"
        state_guard_report_path.write_text(
            json.dumps(state_guard_report, indent=2) + "\n",
            encoding="utf-8",
        )

        route_report_path = work / "product-route-gate.json"
        run(
            [
                sys.executable,
                str(PRODUCT_ROUTE_GATE),
                "--product-core",
                str(args.product_core),
                "--product-listing",
                str(args.product_listing),
                "--report",
                str(route_report_path),
            ]
        )
        route_report = read_json(route_report_path)
        config_gate = route_report.get("config_escrow_gate")
        tcp_close_gate = route_report.get("tcp_close_call_binding_gate")
        lease_gate = route_report.get("resumption_access_lease_gate")
        vault_schedule_gate = route_report.get("vault_access_schedule_gate")
        raw_epoch_gate = (
            vault_schedule_gate.get("critical_raw_epoch")
            if isinstance(vault_schedule_gate, dict)
            else None
        )
        deadline_gate = route_report.get("deadline_observation_gate")
        trace_absence_gate = route_report.get(
            "integrated_trace_absence_gate"
        )
        if (
            route_report.get("schema")
            != "seed-tls13-k14-product-route-gate-v1"
            or route_report.get("passed") is not True
            or route_report.get("read_only_media_compatible") is not True
            or route_report.get("credential_or_one_shot_phases") != 0
            or route_report.get("generated_abi_include") is not True
            or route_report.get("vm_or_network_launched") is not False
            or not isinstance(tcp_close_gate, dict)
            or tcp_close_gate.get("controller")
            != "secure_preconnect_controller"
            or tcp_close_gate.get("shipped_phase_bound") is not True
            or tcp_close_gate.get("binary_decoded") is not True
            or tcp_close_gate.get("manifest_target")
            != tcp_close_gate.get("resolved_target")
            or not isinstance(trace_absence_gate, dict)
            or trace_absence_gate.get("environment_selected_trace")
            is not False
            or trace_absence_gate.get(
                "retired_trace_tokens_in_product_sources"
            )
            != 0
            or trace_absence_gate.get("manifest_diagnostic_mode")
            is not False
            or trace_absence_gate.get("checker_only_timing_diagnostic")
            != "LIVE_K15_TIMING_DIAGNOSTIC"
            or not isinstance(config_gate, dict)
            or config_gate.get("success_cases") != 4
            or config_gate.get(
                "cold_and_reconnect_nonzero_cache_restored"
            )
            is not True
            or config_gate.get("status_last_cases") != 4
            or config_gate.get("tamper_rejections") != 28
            or config_gate.get(
                "zero_conventional_publication_on_rejection"
            )
            is not True
            or config_gate.get("complete_video_scrub_on_rejection")
            is not True
            or not isinstance(deadline_gate, dict)
            or deadline_gate.get("historical_deadline_ticks") != 273
            or deadline_gate.get("untraced_boundary_ticks") != [273, 274]
            or deadline_gate.get("timing_diagnostic_boundary_markers")
            != {"273": "d", "274": "l"}
            or deadline_gate.get("identical_non_uart_behavior") is not True
            or deadline_gate.get("status") != "pass"
            or not isinstance(
                deadline_gate.get("late_head_send_failure"), dict
            )
            or deadline_gate["late_head_send_failure"].get("status")
            != "rejected"
            or not isinstance(lease_gate, dict)
            or lease_gate.get("consumer_binaries") != 15
            or lease_gate.get("direct_callbacks_checked") != 50
            or lease_gate.get("lease_generations") != 8
            or len(lease_gate.get("full_symmetric_sites", {})) != 6
            or len(lease_gate.get("overlap_invalidations", [])) != 6
            or lease_gate.get("hostile_stale_callback_rejected") is not True
        ):
            fail("product-route/tamper prerequisite did not return its full PASS")
        if (
            not isinstance(vault_schedule_gate, dict)
            or vault_schedule_gate.get("initial_access_loads") != 1
            or vault_schedule_gate.get("initial_fresh_callbacks") != 5
            or vault_schedule_gate.get("pre_hello_lifecycle_placement")
            != {
                "load_span": "0x1800..0x1e00",
                "retired_owner": "KeyGen code",
                "public_key_span": "0x08c0..0x0d60",
                "public_key_disjoint": True,
                "live_controller_span": "0x2400..0x2800",
                "live_controller_disjoint": True,
            }
            or vault_schedule_gate.get("initial_access_retired_after_final_read")
            != "enter-raw"
            or vault_schedule_gate.get("receipt_raw_rebind_count") != 1
            or vault_schedule_gate.get("fo_self_reload_count") != 1
            or vault_schedule_gate.get("fo_fresh_callbacks_checked") != 11
            or not isinstance(raw_epoch_gate, dict)
            or raw_epoch_gate.get("ordinary_access_callbacks_after_enter") != 0
            or raw_epoch_gate.get("off_window_tail_restore_sectors") != 2
            or raw_epoch_gate.get("deadline_writer") != "0x2ee0"
            or raw_epoch_gate.get("deadline_writer_bytes") != 160
            or raw_epoch_gate.get("deadline_writer_code_bytes") != 159
            or raw_epoch_gate.get("deadline_writes")
            != [
                {"page": "0x79", "source": "0x08c0", "bytes": 1088},
                {"page": "0x7e", "source": "0x0dab", "bytes": 128},
                {"page": "0x7f", "source": "0x0dab", "bytes": 128},
            ]
            or raw_epoch_gate.get(
                "raw_writer_es_normalized_before_candidate"
            )
            is not True
            or raw_epoch_gate.get("embedded_controller_bytes") != 128
            or raw_epoch_gate.get("symmetric_critical_tail_seeded_by_root")
            is not True
            or raw_epoch_gate.get("symmetric_critical_tail_root_loads") != 1
            or raw_epoch_gate.get(
                "symmetric_critical_tail_overwrites_after_root"
            )
            != []
            or raw_epoch_gate.get("symmetric_tail_byte_bound") is not True
            or raw_epoch_gate.get(
                "generic_access_callbacks_in_deadline_controllers"
            )
            != 0
            or raw_epoch_gate.get("critical_symmetric_restore_sectors") != 8
            or raw_epoch_gate.get("authority_granted_by_raw_epoch") is not False
        ):
            fail("product route lost its checked-to-raw vault epoch proof")

        secure_dir = work / "reference-product-base"
        post_dir = work / "reference-product-route"
        run(
            [
                sys.executable,
                str(BUILD_SECURE),
                "--product-mode",
                "--build-dir",
                str(secure_dir),
                "--product-core",
                str(args.product_core),
                "--product-listing",
                str(args.product_listing),
            ]
        )
        run(
            [
                sys.executable,
                str(BUILD_POST_AUTH),
                "--product-mode",
                "--base-build",
                str(secure_dir),
                "--build-dir",
                str(post_dir),
            ]
        )

        base_manifest = read_json(secure_dir / "manifest.json")
        post_manifest = read_json(post_dir / "manifest.json")
        validate_product_mode(base_manifest, post_manifest)
        base_core = (secure_dir / "SEED.SYS").read_bytes()
        final_core = (post_dir / "SEED.SYS").read_bytes()
        if len(base_core) % SECTOR or len(final_core) % SECTOR:
            fail("product builder emitted a non-sector-aligned core")
        if (
            int.from_bytes(base_core[0x11:0x13], "little")
            != len(base_core) // SECTOR
            or int.from_bytes(final_core[0x11:0x13], "little")
            != len(final_core) // SECTOR
        ):
            fail("product builder emitted a stale total-sector header")

        base_output = base_manifest.get("output")
        if (
            not isinstance(base_output, dict)
            or base_output.get("core_bytes") != len(base_core)
            or base_output.get("core_sectors") != len(base_core) // SECTOR
            or base_output.get("core_sha256") != digest(base_core)
            or base_output.get("image") is not None
        ):
            fail("product base output is not bound to its manifest")
        base_pack = (
            secure_dir / "tls13-k14-product-base-pack.bin"
        ).read_bytes()
        if base_pack != base_core[RESIDENT_BASE_SECTORS * SECTOR :]:
            fail("product base phase pack is not its resident phase suffix")

        output = post_manifest.get("output")
        builder_pack_path = post_dir / "tls13-k14-product-pack.bin"
        builder_abi_path = post_dir / "tls13-k14-product-abi.inc"
        builder_pack = builder_pack_path.read_bytes()
        builder_abi = builder_abi_path.read_bytes()
        if (
            not isinstance(output, dict)
            or output.get("core_bytes") != len(final_core)
            or output.get("core_sectors") != len(final_core) // SECTOR
            or output.get("core_sha256") != digest(final_core)
            or output.get("phase_pack_bytes") != len(builder_pack)
            or output.get("phase_pack_sha256") != digest(builder_pack)
            or output.get("abi_include_sha256") != digest(builder_abi)
            or output.get("floppy_image") is not None
            or output.get("basic_sidecar") is not None
            or Path(str(output.get("phase_pack"))).resolve()
            != builder_pack_path.resolve()
            or Path(str(output.get("abi_include"))).resolve()
            != builder_abi_path.resolve()
        ):
            fail("product route output is not bound to its pack and ABI")
        base_binding = post_manifest.get("base")
        base_manifest_data = (secure_dir / "manifest.json").read_bytes()
        if (
            not isinstance(base_binding, dict)
            or base_binding.get("manifest_sha256")
            != digest(base_manifest_data)
            or base_binding.get("core_sha256") != digest(base_core)
            or base_binding.get("unchanged_during_composition") is not True
        ):
            fail("product route is not bound to its unchanged product base")

        base_values = base_manifest.get("live_phases")
        post_values = post_manifest.get("phases")
        if not isinstance(base_values, list) or not isinstance(post_values, list):
            fail("product manifests lack their phase ledgers")
        base_phases = [
            phase_from_manifest(
                value,
                source="product-base",
                destination_field="destination",
            )
            for value in base_values
        ]
        post_phases = [
            phase_from_manifest(
                value,
                source="product-route",
                destination_field="file_load_stage",
            )
            for value in post_values
        ]
        phases = base_phases + post_phases
        if not base_phases or not post_phases:
            fail("product base or route phase ledger is empty")
        if phases[0].start != RESIDENT_BASE_SECTORS:
            fail(
                "product phase pack no longer begins at the resident boundary"
            )
        expected_start = phases[0].start
        names: set[str] = set()
        keys: set[int] = set()
        for phase in phases:
            if phase.name in names:
                fail(f"duplicate phase name: {phase.name}")
            if phase.key in keys:
                fail(f"duplicate phase key: 0x{phase.key:04x}")
            if phase.start != expected_start:
                fail(
                    f"phase pack is not contiguous at {phase.name}: "
                    f"expected sector {expected_start}, got {phase.start}"
                )
            names.add(phase.name)
            keys.add(phase.key)
            expected_start = phase.end
        if base_phases[-1].end * SECTOR != len(base_core):
            fail("product base ledger does not cover its complete core")
        if post_phases[0].start != len(base_core) // SECTOR:
            fail("product-route phases do not begin after the product base")
        if expected_start * SECTOR != len(final_core):
            fail("product phase ledger does not cover its complete final core")
        if expected_start >= 256:
            fail("phase pack tail no longer fits the 8-bit sector-key contract")
        if names.intersection(FORBIDDEN_PRODUCT_PHASES):
            fail("credential or one-shot phase entered the product pack")
        if b"sk-" in final_core.lower():
            fail("credential-shaped literal entered the product core")

        replacements = post_manifest.get("replacements")
        replaced_post = (
            replacements.get("post_controller")
            if isinstance(replacements, dict)
            else None
        )
        replaced_auth = (
            replacements.get("auth_controller")
            if isinstance(replacements, dict)
            else None
        )
        if not isinstance(replaced_post, dict) or not isinstance(
            replaced_auth, dict
        ):
            fail("product route manifest lacks its fixed phase replacements")
        replaced = {"post_controller", "auth_controller"}
        receipt_controller = (
            post_dir / "post_auth_receipt_post_controller.bin"
        ).read_bytes()
        auth_entry = (post_dir / "post_auth_live_entry.bin").read_bytes()

        for phase in base_phases:
            start = phase.start * SECTOR
            end = phase.end * SECTOR
            base_slot = base_core[start:end]
            final_slot = final_core[start:end]
            validate_payload(phase, base_slot)
            if phase.name not in replaced:
                if final_slot != base_slot:
                    fail(f"product route changed fixed base phase {phase.name}")
            elif phase.name == "post_controller":
                if (
                    parse_hex(
                        replaced_post.get("phase_key"),
                        "post-controller replacement key",
                    )
                    != phase.key
                    or replaced_post.get("base_bytes") != phase.payload_bytes
                    or replaced_post.get("receipt_hooked_bytes")
                    != len(receipt_controller)
                    or replaced_post.get("slot_bytes") != len(final_slot)
                    or replaced_post.get("padded_in_core") is not True
                    or final_slot
                    != receipt_controller
                    + bytes(len(final_slot) - len(receipt_controller))
                ):
                    fail("post-controller replacement/padding drifted")
            else:
                if (
                    parse_hex(
                        replaced_auth.get("phase_key"),
                        "auth-controller replacement key",
                    )
                    != phase.key
                    or replaced_auth.get("entry_bytes") != len(auth_entry)
                    or replaced_auth.get("entry_sha256") != digest(auth_entry)
                    or final_slot
                    != auth_entry + bytes(len(final_slot) - len(auth_entry))
                ):
                    fail("auth-controller replacement/padding drifted")

        for phase in post_phases:
            start = phase.start * SECTOR
            end = phase.end * SECTOR
            validate_payload(phase, final_core[start:end])

        pack_start = phases[0].start
        pack_end = phases[-1].end
        reference_pack = final_core[
            pack_start * SECTOR : pack_end * SECTOR
        ]
        if (
            builder_pack != reference_pack
            or len(builder_pack) != (pack_end - pack_start) * SECTOR
        ):
            fail("product builder pack differs from its final core phase suffix")
        abi_defines = validate_product_abi(
            builder_abi,
            manifest=post_manifest,
            core=final_core,
            pack=builder_pack,
        )
        if (
            route_report.get("core_bytes") != len(final_core)
            or route_report.get("core_sectors") != len(final_core) // SECTOR
            or route_report.get("core_sha256") != digest(final_core)
            or route_report.get("phase_pack_bytes") != len(builder_pack)
            or route_report.get("phase_pack_sha256") != digest(builder_pack)
            or route_report.get("phase_count") != len(post_phases)
        ):
            fail("independent product-route prerequisite differs from reference")
        slot_dir = work / "product-phase-slots"
        slot_dir.mkdir()
        slot_paths: dict[str, Path] = {}
        for phase in phases:
            slot = final_core[phase.start * SECTOR : phase.end * SECTOR]
            path = slot_dir / f"{phase.name}.bin"
            path.write_bytes(slot)
            slot_paths[phase.name] = path

        generated_include = work / "k14-product-pack.generated.inc"
        write_generated_include(generated_include, phases, slot_paths)
        pack_bin = work / "k14-product-pack.bin"
        pack_listing = work / "k14-product-pack.lst"
        define = (
            "-DTLS13_PRODUCT_GENERATED_INCLUDE="
            + nasm_string(generated_include)
        )
        run(
            [
                "nasm",
                "-f",
                "bin",
                define,
                "-l",
                str(pack_listing),
                "-o",
                str(pack_bin),
                str(PRODUCT_PACK_SOURCE),
            ]
        )
        product_pack = pack_bin.read_bytes()
        if product_pack != reference_pack:
            mismatch = next(
                (
                    index
                    for index, pair in enumerate(
                        zip(product_pack, reference_pack, strict=False)
                    )
                    if pair[0] != pair[1]
                ),
                min(len(product_pack), len(reference_pack)),
            )
            fail(
                "product flat pack differs from product-builder reference at "
                f"pack offset 0x{mismatch:04x}"
            )

        for phase in phases:
            relative = (phase.start - pack_start) * SECTOR
            expected = final_core[
                phase.start * SECTOR : phase.end * SECTOR
            ]
            actual = product_pack[
                relative : relative + phase.sectors * SECTOR
            ]
            if actual != expected:
                fail(f"product phase slot differs: {phase.name}")

        result = {
            "schema": "seed-tls13-product-k14-pack-v2",
            "result": "PASS",
            "scope": (
                "offline product-mode route/tamper/state-guard prerequisites "
                "plus source-link flat-pack and generated-ABI equivalence"
            ),
            "product_mode": True,
            "tls": "TLS 1.3 only",
            "tier": "8088 defensible Seed security boundary",
            "cpu": "8086",
            "asm_roots_checked": source_count,
            "diagnostic_defines_enabled": [],
            "diagnostic_defines_forbidden": list(DIAGNOSTIC_DEFINES),
            "integrated_trace_absence_gate": trace_absence_gate,
            "prerequisites": {
                "state_guard": state_guard_report,
                "product_route": {
                    "schema": route_report["schema"],
                    "passed": True,
                    "report_sha256": digest(route_report_path.read_bytes()),
                    "config_escrow_gate": config_gate,
                    "critical_raw_epoch": raw_epoch_gate,
                },
                "run_before_reference_build_and_publication": True,
            },
            "product_base_phases": len(base_phases),
            "product_route_phases": len(post_phases),
            "phase_count": len(phases),
            "reference_start_sector": pack_start,
            "reference_end_sector": pack_end,
            "pack_sectors": pack_end - pack_start,
            "pack_bytes": len(product_pack),
            "pack_sha256": digest(product_pack),
            "abi_bytes": len(builder_abi),
            "abi_sha256": digest(builder_abi),
            "abi_defines": abi_defines,
            "phase_tail_encodable": pack_end < 256,
            "byte_equivalent": True,
            "slot_equivalent": True,
            "builder_pack_equivalent": True,
            "generated_abi_equivalent": True,
            "credential_material_in_pack": False,
            "user_cfg_packaged": False,
            "nic_driver_dependency": False,
            "writable_media_dependency": False,
            "runtime_modules_added": False,
            "vm_or_network_launched": False,
            "publication": {
                "requested": args.pack_out is not None,
                "pack": None if args.pack_out is None else str(args.pack_out),
                "abi": None if abi_out is None else str(abi_out),
                "same_directory_staging": args.pack_out is not None,
                "pack_replaced_last": args.pack_out is not None,
            },
        }
        if args.pack_out is not None:
            assert abi_out is not None
            publish_pack_and_abi(
                args.pack_out,
                product_pack,
                abi_out,
                builder_abi,
            )
        if args.json_out is not None:
            report_data = (
                json.dumps(result, indent=2) + "\n"
            ).encode("utf-8")
            staged_report = stage_output(args.json_out, report_data)
            os.replace(staged_report, args.json_out)
        print("TLS 1.3 product K14 phase pack: PASS")
        print(
            f"  phases={len(phases)} "
            f"({len(base_phases)} product-base + "
            f"{len(post_phases)} product-route)"
        )
        print(
            f"  reference sectors={pack_start}..{pack_end - 1} "
            f"pack={len(product_pack)} bytes/{pack_end - pack_start} sectors"
        )
        print(f"  sha256={result['pack_sha256']}")
        print(f"  abi_sha256={result['abi_sha256']}")
        print(
            "  prerequisites=state-guard+route+28-tamper-rejections "
            "cpu=8086 diagnostics=none credentials=none"
        )
        if args.pack_out is not None:
            print(f"  published_pack={args.pack_out}")
            print(f"  published_abi={abi_out} (pack replaced last)")
    finally:
        if temp_owner is not None:
            temp_owner.cleanup()


if __name__ == "__main__":
    main()
