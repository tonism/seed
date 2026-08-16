#!/usr/bin/env python3
"""Build and validate the generic-vault 8088 TLS 1.3 product phase chain."""

from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BP,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
POC = HERE.parent / "tls13-poc"
BASE_BUILDER = POC / "build_live_k15.py"
POST_BUILDER = POC / "build_post_auth_live.py"
LIVE_CONTROLLER_GATE = POC / "live_k15_check.py"
DEFAULT_PRODUCT_CORE = ROOT / "build/ibm_pc_5150/tls13-pack-base/SEED.SYS"
DEFAULT_PRODUCT_LISTING = (
    ROOT / "build/ibm_pc_5150/tls13-pack-base/SEED.SYS.lst"
)
SECTOR = 512
RESIDENT_BASE_SECTORS = 45
CONFIG_ESCROW_ORIGIN = 0x2C00
CONFIG_CACHE = 0x3B9C
CONFIG_CACHE_BYTES = 256
CONFIG_SENSITIVE_START = 0x3B2B
CONFIG_SENSITIVE_END = CONFIG_CACHE + CONFIG_CACHE_BYTES
CONFIG_UI = (0x0F55, 0x0F56, 0x0F33, 0x0F66, 0x0F67)
CONFIG_ESCROW_BYTES = 416
CONFIG_ESCROW_CGA = 0xB8000 + 0x1E00
CONFIG_ESCROW_MDA = 0xB0000 + 0x0E00
BDA_CRT_PORT = 0x0463
CGA_CRT_PORT = 0x03D4
MDA_CRT_PORT = 0x03B4
RETURN = 0x0520
STACK_TOP = 0x4000
FORBIDDEN_PHASES = {
    "post_auth_auth_callbacks",
    "post_auth_user_loader",
    "post_auth_request_callbacks",
    "post_auth_request",
    "post_auth_request_adapter",
    "post_auth_response",
    "post_auth_response_literals",
}
RES_LOAD_PHASE = 0x10C4
NIC_VT_ENTER = 0x15DB
ACCESS_INITIAL_STAGE = 0x2800
SECURE_PRECONNECT_ORIGIN = 0x2400
RECONNECT_TELEMETRY_OVERLAP_START = 0x3CA0
RECONNECT_TELEMETRY_OVERLAP_END = 0x3CA7
SCHEDULER_STATE_SYMBOLS = ("reconnect_retries", "compacting_msg")
TIMING_TELEMETRY_SYMBOLS = {
    "hello_controller": (
        "timing_first_tick",
        "timing_commit_tick",
        "timing_tx_tick",
        "timing_first_seen",
    ),
    "protected_controller": (
        "timing_first_tick",
        "timing_commit_tick",
        "timing_finished_return",
    ),
}
ACTIVE_LISTING_LINE = re.compile(
    r"^\s*\d+\s+([0-9A-F]{8})\s+(\S+)\s+"
    r"(?:<\d+>\s+)?(.*\S)\s*$"
)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} is not a JSON object")
    return value


def parse_hex(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise AssertionError(f"{label} is not a hexadecimal ABI value")
    return int(value, 16)


def set_carry(uc: Uc, value: bool) -> None:
    flags = uc.reg_read(UC_X86_REG_EFLAGS)
    if value:
        flags |= 1
    else:
        flags &= ~1
    uc.reg_write(UC_X86_REG_EFLAGS, flags)


def return_from_near_call(uc: Uc) -> None:
    ss = uc.reg_read(UC_X86_REG_SS) & 0xFFFF
    sp = uc.reg_read(UC_X86_REG_SP) & 0xFFFF
    physical = (ss << 4) + sp
    target = struct.unpack("<H", bytes(uc.mem_read(physical, 2)))[0]
    uc.reg_write(UC_X86_REG_SP, (sp + 2) & 0xFFFF)
    uc.reg_write(UC_X86_REG_IP, target)


def publication_return_stack_abi(
    publication: dict[str, Any],
) -> dict[str, int]:
    value = publication.get("return_stack")
    if not isinstance(value, dict):
        raise AssertionError("publication lacks its root-frame return ABI")
    parsed = {
        "snapshot_start": parse_hex(
            value.get("snapshot_start"),
            "publication root-frame snapshot start",
        ),
        "snapshot_end": parse_hex(
            value.get("snapshot_end"),
            "publication root-frame snapshot end",
        ),
        "snapshot_sp": parse_hex(
            value.get("sp"), "publication root-frame SP"
        ),
        "snapshot_sp_inverse": parse_hex(
            value.get("sp_inverse"),
            "publication root-frame SP inverse",
        ),
        "snapshot_status_word": parse_hex(
            value.get("status_word"),
            "publication root-frame status word",
        ),
        "status_value": parse_hex(
            value.get("status_value"),
            "publication root-frame status value",
        ),
        "handoff_ram_top": parse_hex(
            value.get("handoff_ram_top"),
            "publication RAM-top handoff",
        ),
        "expected_return": parse_hex(
            value.get("expected_return"),
            "publication root-frame return",
        ),
        "emergency_reset": parse_hex(
            value.get("invalid_jumps_to_stackless_emergency_reset"),
            "publication stackless emergency reset",
        ),
    }
    expected_sp_delta = value.get("expected_sp_delta")
    if (
        parsed["snapshot_end"] - parsed["snapshot_start"] != 6
        or parsed["snapshot_sp"] != parsed["snapshot_start"]
        or parsed["snapshot_sp_inverse"] != parsed["snapshot_sp"] + 2
        or parsed["snapshot_status_word"]
        != parsed["snapshot_sp_inverse"] + 2
        or parsed["snapshot_end"]
        != parsed["snapshot_status_word"] + 2
        or parsed["status_value"] != 0xA55A
        or parsed["handoff_ram_top"] != 0x062C
        or expected_sp_delta != 6
        or parsed["expected_return"] != 0x12F8
        or not 0x355D <= parsed["emergency_reset"] < 0x3600
        or value.get("validates_before_first_stack_access") is not True
        or value.get("adopts_validated_snapshot") is not True
    ):
        raise AssertionError("publication root-frame return ABI drifted")
    parsed["expected_sp_delta"] = expected_sp_delta
    return parsed


def seed_publication_root_frame(
    uc: Uc,
    stack_abi: dict[str, int],
    *,
    ram_top: int = STACK_TOP,
) -> int:
    root_sp = ram_top - stack_abi["expected_sp_delta"]
    if root_sp < 0 or root_sp + 2 > ram_top:
        raise AssertionError("publication root-frame stack geometry is invalid")
    uc.mem_write(
        stack_abi["handoff_ram_top"], struct.pack("<H", ram_top)
    )
    uc.mem_write(
        stack_abi["snapshot_sp"], struct.pack("<H", root_sp)
    )
    uc.mem_write(
        stack_abi["snapshot_sp_inverse"],
        struct.pack("<H", (~root_sp) & 0xFFFF),
    )
    uc.mem_write(
        stack_abi["snapshot_status_word"],
        struct.pack("<H", stack_abi["status_value"]),
    )
    uc.mem_write(
        root_sp, struct.pack("<H", stack_abi["expected_return"])
    )
    return root_sp


def run_root_dispatch_gate(
    base: Path,
    base_manifest: dict[str, Any],
) -> dict[str, Any]:
    """Exercise the root's register-only dispatcher contracts.

    The resident phase loader is deliberately modeled with its real destructive
    DX contract.  The NIC enter hook is tested with both carry values and a
    clobbered AX, because enter/restore hooks do not publish status and may
    clobber every general register.
    """

    product = base_manifest.get("product_abi")
    root = product.get("root_entry") if isinstance(product, dict) else None
    vault = product.get("vault") if isinstance(product, dict) else None
    escrow = (
        product.get("config_escrow") if isinstance(product, dict) else None
    )
    if not isinstance(root, dict) or not isinstance(vault, dict):
        raise AssertionError("base manifest lacks root/vault ABI")
    if not isinstance(escrow, dict):
        raise AssertionError("base manifest lacks root config-escrow ABI")

    root_entry = parse_hex(root.get("call_address"), "root call address")
    lifecycle_key = parse_hex(
        vault.get("lifecycle_phase_key"), "vault lifecycle phase key"
    )
    lifecycle_stage = parse_hex(
        vault.get("lifecycle_stage"), "vault lifecycle stage"
    )
    vault_begin = parse_hex(vault.get("begin"), "vault begin")
    config_save = parse_hex(escrow.get("save"), "config escrow save")
    root_image = (base / "live_boot_controller.bin").read_bytes()
    if not root_image or len(root_image) > SECTOR:
        raise AssertionError("product root escaped its one-sector phase")

    tick_generation = 0x4D31
    loader_dx_clobber = 0xD15C
    cases = 0
    for mode in (0, 1):
        for enter_carry in (False, True):
            uc = Uc(UC_ARCH_X86, UC_MODE_16)
            uc.mem_map(0, 0x10000)
            uc.mem_write(root_entry, root_image)
            uc.mem_write(NIC_VT_ENTER, struct.pack("<H", 0x0500))
            uc.mem_write(0x046C, struct.pack("<H", tick_generation))
            for register in (
                UC_X86_REG_CS,
                UC_X86_REG_DS,
                UC_X86_REG_ES,
                UC_X86_REG_SS,
            ):
                uc.reg_write(register, 0)
            uc.reg_write(UC_X86_REG_SP, 0x3F00)
            uc.reg_write(UC_X86_REG_AX, mode)
            uc.reg_write(UC_X86_REG_EFLAGS, 2)

            loads: list[tuple[int, int]] = []
            begin_generation: int | None = None
            save_generation: int | None = None

            def hook(
                machine: Uc,
                address: int,
                _size: int,
                _user: object,
            ) -> None:
                nonlocal begin_generation, save_generation
                if address == 0x0500:
                    machine.reg_write(UC_X86_REG_AX, 0xA5FE)
                    machine.reg_write(UC_X86_REG_BX, 0xB6ED)
                    machine.reg_write(UC_X86_REG_CX, 0xC7DC)
                    machine.reg_write(UC_X86_REG_DX, 0xD8CB)
                    machine.reg_write(UC_X86_REG_SI, 0xE9BA)
                    machine.reg_write(UC_X86_REG_DI, 0xFA09)
                    machine.reg_write(UC_X86_REG_BP, 0x8B78)
                    set_carry(machine, enter_carry)
                    return_from_near_call(machine)
                    return
                if address == RES_LOAD_PHASE:
                    key = machine.reg_read(UC_X86_REG_AX) & 0xFFFF
                    destination = machine.reg_read(UC_X86_REG_BX) & 0xFFFF
                    loads.append((key, destination))
                    machine.reg_write(UC_X86_REG_DX, loader_dx_clobber)
                    set_carry(machine, False)
                    return_from_near_call(machine)
                    return
                if address == vault_begin:
                    begin_generation = (
                        machine.reg_read(UC_X86_REG_DX) & 0xFFFF
                    )
                    set_carry(machine, False)
                    return_from_near_call(machine)
                    return
                if address == config_save:
                    save_generation = (
                        machine.reg_read(UC_X86_REG_DX) & 0xFFFF
                    )
                    machine.emu_stop()

            handle = uc.hook_add(UC_HOOK_CODE, hook)
            try:
                uc.emu_start(root_entry, 0, count=20_000)
            finally:
                uc.hook_del(handle)
            if not loads or loads[0] != (lifecycle_key, lifecycle_stage):
                raise AssertionError(
                    "product root consumed NIC enter carry or lost dispatcher "
                    "AL before the lifecycle load"
                )
            if begin_generation != tick_generation:
                raise AssertionError("vault begin did not receive BDA generation")
            if save_generation != begin_generation:
                raise AssertionError(
                    "config phase load lost the vault lifecycle generation in DX"
                )
            if save_generation == loader_dx_clobber:
                raise AssertionError(
                    "config escrow received the phase loader's clobbered DX"
                )
            cases += 1
    return {
        "cases": cases,
        "dispatcher_modes": [0, 1],
        "nic_enter_carry_inputs": [0, 1],
        "dispatcher_al_preserved_across_enter": True,
        "nic_enter_carry_ignored": True,
        "generation_preserved_across_config_load": True,
    }


def active_listing_instructions(path: Path) -> list[tuple[int, str, str]]:
    result: list[tuple[int, str, str]] = []
    for raw in path.read_text(encoding="ascii").splitlines():
        matched = ACTIVE_LISTING_LINE.match(raw)
        if matched is None:
            continue
        offset_text, encoded, source = matched.groups()
        result.append((int(offset_text, 16), encoded, source.strip()))
    if not result:
        raise AssertionError(f"{path} has no assembled listing instructions")
    return result


def check_tcp_close_call_binding(
    base: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Bind the shipped preconnect CALL to the product C-phase close leaf."""

    product_input = manifest.get("product_input")
    phases = manifest.get("live_phases")
    output = manifest.get("output")
    if (
        not isinstance(product_input, dict)
        or not isinstance(phases, list)
        or not isinstance(output, dict)
    ):
        raise AssertionError(
            "base manifest lacks product input/phase/output metadata"
        )
    expected_target = parse_hex(
        product_input.get("tcp_close_cached_entry"),
        "base product cached TCP close entry",
    )
    phase = next(
        (
            value
            for value in phases
            if isinstance(value, dict)
            and value.get("name") == "secure_preconnect_controller"
        ),
        None,
    )
    if not isinstance(phase, dict):
        raise AssertionError(
            "base manifest lacks the secure preconnect controller phase"
        )

    listing = base / "live_secure_preconnect_controller.lst"
    artifact = (base / "live_secure_preconnect_controller.bin").read_bytes()
    call_sites = [
        offset
        for offset, _encoded, source in active_listing_instructions(listing)
        if source == "call tcp_close_cached_entry"
    ]
    if len(call_sites) != 1:
        raise AssertionError(
            "secure preconnect controller does not contain exactly one active "
            f"cached-close CALL: {call_sites!r}"
        )

    start_sector = phase.get("start_sector")
    phase_bytes = phase.get("bytes")
    phase_sectors = phase.get("sectors")
    phase_destination = parse_hex(
        phase.get("destination"), "secure preconnect phase destination"
    )
    if (
        not isinstance(start_sector, int)
        or not isinstance(phase_bytes, int)
        or not isinstance(phase_sectors, int)
        or phase_destination != SECURE_PRECONNECT_ORIGIN
        or phase_bytes != len(artifact)
        or phase_bytes > phase_sectors * SECTOR
        or phase.get("sha256") != sha256(artifact)
    ):
        raise AssertionError(
            "secure preconnect controller artifact is not manifest-bound"
        )

    core_path = Path(str(output.get("core")))
    if not core_path.is_absolute():
        core_path = ROOT / core_path
    core = core_path.read_bytes()
    phase_start = start_sector * SECTOR
    shipped = core[phase_start : phase_start + phase_bytes]
    if shipped != artifact:
        raise AssertionError(
            "secure preconnect controller artifact differs from shipped phase"
        )

    call_offset = call_sites[0]
    if call_offset + 3 > len(shipped) or shipped[call_offset] != 0xE8:
        raise AssertionError(
            "secure preconnect cached-close edge is not a near CALL"
        )
    encoded = shipped[call_offset : call_offset + 3]
    displacement = struct.unpack_from("<h", encoded, 1)[0]
    resolved_target = (
        phase_destination + call_offset + len(encoded) + displacement
    ) & 0xFFFF
    if resolved_target != expected_target:
        raise AssertionError(
            "shipped secure preconnect cached-close CALL target drifted: "
            f"{resolved_target:#06x} != manifest {expected_target:#06x}"
        )

    return {
        "controller": "secure_preconnect_controller",
        "phase_start_sector": start_sector,
        "load_origin": f"0x{phase_destination:04x}",
        "call_offset": f"0x{call_offset:04x}",
        "call_encoding": encoded.hex(),
        "manifest_target": f"0x{expected_target:04x}",
        "resolved_target": f"0x{resolved_target:04x}",
        "shipped_phase_bound": True,
        "binary_decoded": True,
    }


def check_scheduler_state_preserved(
    base: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Keep the product root subordinate to the resident replay scheduler.

    The standalone PoC initializes its own retry and compaction bytes.  The
    integrated product route must not initialize either value.  The secure
    preconnect controller may temporarily present retry=1 to the legacy E
    phase so a consumed replay budget does not enter E's terminal-rendering
    path while video RAM is the vault, but it must save and restore the exact
    scheduler byte around that one call before branching on CF.  Inspect the
    exact manifest-bound controller listings so an inactive source branch
    cannot satisfy this gate.
    """

    phases = manifest.get("live_phases")
    if not isinstance(phases, list):
        raise AssertionError("base manifest lacks its live phase ledger")
    phase_by_name = {
        str(phase.get("name")): phase
        for phase in phases
        if isinstance(phase, dict)
    }
    controllers: dict[str, Any] = {}
    for name in ("boot_controller", "secure_preconnect_controller"):
        listing = base / f"live_{name}.lst"
        image = (base / f"live_{name}.bin").read_bytes()
        phase = phase_by_name.get(name)
        if (
            not isinstance(phase, dict)
            or phase.get("bytes") != len(image)
            or phase.get("sha256") != sha256(image)
        ):
            raise AssertionError(
                f"authoritative {name} artifact is not manifest-bound"
            )
        definitions = {
            symbol: listing_constant(listing, symbol)
            for symbol in SCHEDULER_STATE_SYMBOLS
        }
        instructions = active_listing_instructions(listing)
        accesses = [
            {
                "offset": f"0x{offset:04x}",
                "encoding": encoded,
                "source": source,
            }
            for offset, encoded, source in instructions
            if any(
                re.search(rf"\[\s*{re.escape(symbol)}\b", source)
                for symbol in SCHEDULER_STATE_SYMBOLS
            )
        ]
        endpoint_override = False
        if name == "boot_controller":
            if accesses:
                raise AssertionError(
                    "authoritative boot controller accessed resident "
                    f"scheduler-owned state: {accesses!r}"
                )
        else:
            access_sources = [access["source"] for access in accesses]
            expected_accesses = [
                "mov al, [reconnect_retries]",
                "mov byte [reconnect_retries], 1",
                "mov [reconnect_retries], al",
            ]
            if access_sources != expected_accesses:
                raise AssertionError(
                    "secure preconnect scheduler-state accesses are not the "
                    f"bounded endpoint override: {accesses!r}"
                )
            call_indexes = [
                index
                for index, (_offset, _encoded, source) in enumerate(instructions)
                if source == "call 0x0700"
            ]
            if len(call_indexes) != 1:
                raise AssertionError(
                    "secure preconnect must contain exactly one E-phase call"
                )
            call_index = call_indexes[0]
            boundary = [
                source
                for _offset, _encoded, source in instructions[
                    call_index - 3 : call_index + 4
                ]
            ]
            expected_boundary = [
                "mov al, [reconnect_retries]",
                "push ax",
                "mov byte [reconnect_retries], 1",
                "call 0x0700",
                "pop ax",
                "mov [reconnect_retries], al",
                "jc preconnect_failed",
            ]
            if boundary != expected_boundary:
                raise AssertionError(
                    "secure preconnect does not restore the replay counter "
                    f"status-preservingly around E: {boundary!r}"
                )
            endpoint_override = True
        controllers[name] = {
            "artifact_sha256": sha256(image),
            "manifest_bound": True,
            "scheduler_state_addresses": {
                symbol: f"0x{address:04x}"
                for symbol, address in definitions.items()
            },
            "compiled_scheduler_state_accesses": len(accesses),
            "endpoint_retry_override_save_restore": endpoint_override,
        }

    return {
        "owner": "resident prepare_agent_endpoint_path scheduler",
        "one_replay_budget_preserved": True,
        "consumed_budget_bypasses_legacy_endpoint_ui": True,
        "compaction_turn_state_preserved": True,
        "controllers": controllers,
    }


def check_authoritative_timing_telemetry_absent(
    base: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Reject PoC tick telemetry in the authoritative product controllers.

    The historical 0x3ca0..0x3ca6 scratch aliases Seed's resident
    reconnect/ESC/DPI/context state.  Listing inspection is intentional here:
    it proves both reads and writes were removed from the exact controller
    binaries that the manifest binds into the authoritative phase pack.
    """

    phases = manifest.get("live_phases")
    if not isinstance(phases, list):
        raise AssertionError("base manifest lacks its live phase ledger")
    phase_by_name = {
        str(phase.get("name")): phase
        for phase in phases
        if isinstance(phase, dict)
    }
    controllers: dict[str, Any] = {}
    for name, symbols in TIMING_TELEMETRY_SYMBOLS.items():
        listing = base / f"live_{name}.lst"
        image_path = base / f"live_{name}.bin"
        image = image_path.read_bytes()
        phase = phase_by_name.get(name)
        if (
            not isinstance(phase, dict)
            or phase.get("bytes") != len(image)
            or phase.get("sha256") != sha256(image)
        ):
            raise AssertionError(
                f"authoritative {name} artifact is not manifest-bound"
            )

        definitions = {
            symbol: listing_constant(listing, symbol) for symbol in symbols
        }
        outside_overlap = {
            symbol: address
            for symbol, address in definitions.items()
            if not (
                RECONNECT_TELEMETRY_OVERLAP_START
                <= address
                < RECONNECT_TELEMETRY_OVERLAP_END
            )
        }
        if outside_overlap:
            raise AssertionError(
                f"{name} timing telemetry no longer maps to the resident "
                f"overlap: {outside_overlap!r}"
            )

        accesses = [
            {
                "offset": f"0x{offset:04x}",
                "encoding": encoded,
                "source": source,
            }
            for offset, encoded, source in active_listing_instructions(listing)
            if any(
                re.search(rf"\[\s*{re.escape(symbol)}\b", source)
                for symbol in symbols
            )
        ]
        if accesses:
            raise AssertionError(
                f"authoritative {name} still accesses PoC timing telemetry "
                f"in resident reconnect state: {accesses!r}"
            )
        controllers[name] = {
            "artifact_sha256": sha256(image),
            "manifest_bound": True,
            "timing_symbol_addresses": {
                symbol: f"0x{address:04x}"
                for symbol, address in definitions.items()
            },
            "compiled_timing_reads_or_writes": 0,
        }

    return {
        "overlap": (
            f"0x{RECONNECT_TELEMETRY_OVERLAP_START:04x}.."
            f"0x{RECONNECT_TELEMETRY_OVERLAP_END - 1:04x}"
        ),
        "authoritative_product": True,
        "controllers": controllers,
        "compiled_timing_reads_or_writes": 0,
    }


def listing_label_offset(path: Path, label: str) -> int:
    lines = path.read_text(encoding="ascii").splitlines()
    label_pattern = re.compile(
        rf"(?<![A-Za-z0-9_.$?]){re.escape(label)}"
        rf"(?::|\s+(?:db|dw|dd|equ)\b)"
    )
    offset_pattern = re.compile(
        r"^\s*\d+\s+(?:<\d+>\s+)?([0-9A-Fa-f]{8})\s"
    )
    for index, line in enumerate(lines):
        if not label_pattern.search(line):
            continue
        for candidate in lines[index : index + 24]:
            matched = offset_pattern.search(candidate)
            if matched is not None:
                return int(matched.group(1), 16)
        # The shared controller source contains the same local-service label
        # in mutually exclusive assembly roots.  Keep looking when the first
        # textual occurrence belongs to an inactive %ifdef branch.
        continue
    raise AssertionError(f"cannot resolve listing label {label!r} in {path}")


def listing_definitions(path: Path) -> dict[str, str]:
    definitions: dict[str, str] = {}
    defines: set[str] = set()
    for raw in path.read_text(encoding="ascii").splitlines():
        source = raw.split(";", 1)[0]
        matched = re.search(
            r"%define\s+([A-Za-z_.$?][A-Za-z0-9_.$?]*)\s+(.+?)\s*$",
            source,
        )
        if matched is not None:
            name, expression = matched.groups()
            definitions[name] = expression.strip()
            defines.add(name)
            continue
        matched = re.search(
            r"\b([A-Za-z_.$?][A-Za-z0-9_.$?]*)\s+equ\s+(.+?)\s*$",
            source,
        )
        if matched is not None:
            name, expression = matched.groups()
            if name not in defines:
                definitions.setdefault(name, expression.strip())
    return definitions


def listing_constant(path: Path, name: str) -> int:
    definitions = listing_definitions(path)
    resolved: dict[str, int] = {}
    resolving: set[str] = set()

    def evaluate(symbol: str) -> int:
        if symbol in resolved:
            return resolved[symbol]
        if symbol in resolving or symbol not in definitions:
            raise AssertionError(
                f"cannot resolve listing constant {symbol!r} in {path}"
            )
        resolving.add(symbol)
        expression = definitions[symbol]
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError as error:
            raise AssertionError(
                f"unsupported listing expression for {symbol}: {expression}"
            ) from error

        def node_value(node: ast.AST) -> int:
            if isinstance(node, ast.Expression):
                return node_value(node.body)
            if isinstance(node, ast.Constant) and isinstance(node.value, int):
                return int(node.value)
            if isinstance(node, ast.Name):
                return evaluate(node.id)
            if isinstance(node, ast.UnaryOp):
                value = node_value(node.operand)
                if isinstance(node.op, ast.UAdd):
                    return value
                if isinstance(node.op, ast.USub):
                    return -value
            if isinstance(node, ast.BinOp):
                left = node_value(node.left)
                right = node_value(node.right)
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, (ast.Div, ast.FloorDiv)):
                    return left // right
            raise AssertionError(
                f"unsupported listing expression for {symbol}: {expression}"
            )

        value = node_value(tree)
        resolving.remove(symbol)
        resolved[symbol] = value
        return value

    return evaluate(name)


def k14_polynomial_span(path: Path, label: str) -> tuple[int, int]:
    start = listing_constant(path, "poc_poly_u")
    accumulator = listing_constant(path, "poc_poly_acc")
    poly_bytes = listing_constant(path, "poc_poly_bytes")
    if accumulator != start + poly_bytes:
        raise AssertionError(f"{label} polynomial buffers are not contiguous")
    instructions = active_listing_instructions(path)
    destinations = {
        immediate16(encoded, "BF")
        for _offset, encoded, source in instructions
        if source in {"mov di, poly_s", "mov di, mlkem_poly_u"}
    }
    accumulators = {
        immediate16(encoded, "BF")
        for _offset, encoded, source in instructions
        if source in {"mov di, poly_acc", "mov di, mlkem_poly_acc"}
    }
    if start not in destinations or accumulator not in accumulators:
        raise AssertionError(f"{label} listing lacks its actual work writes")
    return start, accumulator + poly_bytes


def listing_routine(
    path: Path,
    instructions: list[tuple[int, str, str]],
    label: str,
) -> list[tuple[int, str, str]]:
    start_offset = listing_label_offset(path, label)
    start = None
    for index, instruction in enumerate(instructions):
        if instruction[0] == start_offset:
            start = index
            break
    if start is None:
        raise AssertionError(f"{path} lacks active routine {label}")
    routine, _ = instructions_through(instructions, "ret", start=start)
    return routine


def immediate16(encoded: str, opcode: str) -> int | None:
    if not encoded.startswith(opcode) or len(encoded) < len(opcode) + 4:
        return None
    raw = encoded[len(opcode) : len(opcode) + 4]
    if not all(character in "0123456789ABCDEF" for character in raw):
        return None
    return int.from_bytes(bytes.fromhex(raw), "little")


def immediate8(encoded: str, opcode: str) -> int | None:
    if not encoded.startswith(opcode) or len(encoded) < len(opcode) + 2:
        return None
    raw = encoded[len(opcode) : len(opcode) + 2]
    if not all(character in "0123456789ABCDEF" for character in raw):
        return None
    return int(raw, 16)


def absolute_listing_target(encoded: str, source: str) -> int:
    matched = re.fullmatch(r"E8\(([0-9A-F]{4})\)", encoded)
    if matched is None:
        raise AssertionError(
            f"call is not bound to an absolute listing target: {source}"
        )
    return int.from_bytes(bytes.fromhex(matched.group(1)), "little")


def instructions_through(
    instructions: list[tuple[int, str, str]],
    source: str,
    *,
    start: int = 0,
) -> tuple[list[tuple[int, str, str]], int]:
    for index in range(start, len(instructions)):
        if instructions[index][2] == source:
            return instructions[start : index + 1], index + 1
    raise AssertionError(f"assembled listing lacks route edge: {source}")


def collect_lifetime_events(
    controller: str,
    instructions: list[tuple[int, str, str]],
    *,
    initial_ax: int | None = None,
    initial_bx: int | None = None,
    initial_dx: int | None = None,
    source_writes: dict[str, tuple[str, int, int]] | None = None,
) -> tuple[list[dict[str, Any]], tuple[int | None, int | None, int | None]]:
    events: list[dict[str, Any]] = []
    ax = initial_ax
    bx = initial_bx
    dx = initial_dx
    write_calls = {
        "call live_secure_card_write",
        "call LIVE_K15_BOOT_CARD_WRITE",
        "call LIVE_K15_NE_BUF_LOAD",
        "call RESUME_RECEIPT_VAULT_WRITE",
    }
    read_calls = {
        "call LIVE_K15_NE_BUF_READ",
        "call RESUME_RECEIPT_VAULT_READ",
    }
    phase_calls = {
        "call res_load_phase",
        "call resident_load_phase",
        "call live_secure_batch_phase",
        "call live_secure_sym_batch_phase",
    }

    for offset, encoded, source in instructions:
        value = immediate16(encoded, "B8")
        if value is not None and source.startswith("mov ax,"):
            ax = value
        value = immediate16(encoded, "BB")
        if value is not None and source.startswith("mov bx,"):
            bx = value
        value = immediate16(encoded, "BA")
        if value is not None and source.startswith("mov dx,"):
            dx = value

        if source in phase_calls or (
            source == "call dx" and dx == RES_LOAD_PHASE
        ):
            if ax is None or bx is None:
                raise AssertionError(
                    f"{controller} phase load has unknown AX/BX"
                )
            events.append(
                {
                    "kind": "load",
                    "controller": controller,
                    "offset": offset,
                    "key": ax,
                    "start": bx,
                    "end": bx + ((ax >> 8) * SECTOR),
                }
            )
        elif source in write_calls:
            events.append(
                {
                    "kind": "write",
                    "controller": controller,
                    "offset": offset,
                }
            )
        elif source in read_calls:
            events.append(
                {
                    "kind": "read",
                    "controller": controller,
                    "offset": offset,
                }
            )
        elif source == "call tcp_connect_entry":
            events.append(
                {
                    "kind": "marker",
                    "controller": controller,
                    "offset": offset,
                    "name": "tcp-connect",
                }
            )
        elif source == "call tcp_close_cached_entry":
            events.append(
                {
                    "kind": "marker",
                    "controller": controller,
                    "offset": offset,
                    "name": "tcp-close",
                }
            )
        elif source == "call 0x1800 + LIVE_K15_VAULT_ENTER_RAW_OFFSET":
            events.append(
                {
                    "kind": "marker",
                    "controller": controller,
                    "offset": offset,
                    "name": "enter-raw",
                    "target": absolute_listing_target(encoded, source),
                }
            )
        elif source in {
            "call LIVE_K15_VAULT_REBIND_RAW",
            "call RESUME_RECEIPT_VAULT_REBIND_RAW",
        }:
            events.append(
                {
                    "kind": "marker",
                    "controller": controller,
                    "offset": offset,
                    "name": "rebind-raw",
                    "target": absolute_listing_target(encoded, source),
                }
            )
        elif source_writes is not None and source in source_writes:
            label, start, end = source_writes[source]
            events.append(
                {
                    "kind": "source-write",
                    "controller": controller,
                    "offset": offset,
                    "name": label,
                    "start": start,
                    "end": end,
                }
            )
    return events, (ax, bx, dx)


def product_input_phase_names(
    base_manifest: dict[str, Any],
) -> dict[int, str]:
    product_input = base_manifest.get("product_input")
    if not isinstance(product_input, dict):
        raise AssertionError("base manifest lacks product-input metadata")
    endpoint_entry = parse_hex(
        product_input.get("endpoint_entry"),
        "base product endpoint entry",
    )
    tcp_connect_entry = parse_hex(
        product_input.get("tcp_connect_entry"),
        "base product TCP connect entry",
    )
    tcp_close_cached_entry = parse_hex(
        product_input.get("tcp_close_cached_entry"),
        "base product cached TCP close entry",
    )
    if (
        endpoint_entry != 0x0700
        or tcp_connect_entry != 0x0900
        or not 0x0900 < tcp_close_cached_entry < 0x0F00
    ):
        raise AssertionError("base product endpoint/TCP phase ABI drifted")
    core_path = Path(str(product_input.get("path")))
    if not core_path.is_absolute():
        core_path = ROOT / core_path
    core = core_path.read_bytes()
    if core[3:11] != b"SEEDCORE":
        raise AssertionError("product-input SEED.SYS magic drifted")
    _header, _resident, _total, table_offset, count = struct.unpack_from(
        "<5H", core, 0x0D
    )
    if table_offset + count * 10 > len(core):
        raise AssertionError("product-input phase table escapes SEED.SYS")
    tag_names = {"D": "dhcp", "E": "endpoint", "C": "tcp"}
    result: dict[int, str] = {}
    for index in range(count):
        offset = table_offset + index * 10
        raw_tag, start, sectors, _destination, _flags = struct.unpack_from(
            "<2s4H", core, offset
        )
        tag = raw_tag.rstrip(b"\0").decode("ascii")
        name = tag_names.get(tag)
        if name is not None:
            result[phase_key(start, sectors)] = name
    if set(result.values()) != set(tag_names.values()):
        raise AssertionError("product-input phase table lacks DHCP/TCP")
    return result


def run_vault_access_schedule_gate(
    base: Path,
    base_manifest: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    vault = manifest.get("vault_abi")
    if not isinstance(vault, dict):
        raise AssertionError("product manifest lacks generic-vault ABI")
    initial = vault.get("initial")
    if not isinstance(initial, dict):
        raise AssertionError("product manifest lacks initial vault ABI")
    access_key = parse_hex(
        vault.get("access_phase_key"), "vault access phase key"
    )
    access_stage = parse_hex(initial.get("stage"), "initial vault stage")
    access_write = parse_hex(initial.get("write"), "initial vault write")
    access_read = parse_hex(initial.get("read"), "initial vault read")
    access_image = (base / "product_vault_access.bin").read_bytes()
    access_listing = base / "product_vault_access.lst"
    write_offset = listing_label_offset(access_listing, "pv_write")
    read_offset = listing_label_offset(access_listing, "pv_read")
    table_write, table_read = struct.unpack_from("<2H", access_image)
    if (
        access_stage != ACCESS_INITIAL_STAGE
        or access_write != access_stage + write_offset
        or access_read != access_stage + read_offset
        or (table_write, table_read) != (write_offset, read_offset)
        or (access_key >> 8) * SECTOR < len(access_image)
    ):
        raise AssertionError("initial public-vault access geometry drifted")

    base_product = base_manifest.get("product_abi")
    base_vault = (
        base_product.get("vault") if isinstance(base_product, dict) else None
    )
    if not isinstance(base_vault, dict):
        raise AssertionError("base manifest lacks its raw-epoch vault ABI")
    access_modes = base_vault.get("access_modes")
    raw_writer_abi = base_vault.get("deadline_raw_writer")
    lifecycle_image = (base / "product_vault_lifecycle.bin").read_bytes()
    lifecycle_listing = base / "product_vault_lifecycle.lst"
    enter_raw_offset = listing_label_offset(lifecycle_listing, "pv_enter_raw")
    rebind_raw_offset = listing_label_offset(lifecycle_listing, "pv_rebind_raw")
    lifecycle_write_offset = listing_label_offset(lifecycle_listing, "pv_write")
    lifecycle_read_offset = listing_label_offset(lifecycle_listing, "pv_read")
    lifecycle_entries = struct.unpack_from("<9H", lifecycle_image)
    if (
        not isinstance(access_modes, dict)
        or access_modes.get("checked") != "3cc3"
        or access_modes.get("raw") != "a55a"
        or access_modes.get("ordinary_access_requires_checked") is not True
        or access_modes.get("enter_raw_validates_every_page") is not True
        or access_modes.get("enter_raw_status_last") is not True
        or access_modes.get("rebind_rebuilds_every_page_tag") is not True
        or access_modes.get("rebind_checked_status_last") is not True
        or lifecycle_entries[7:] != (enter_raw_offset, rebind_raw_offset)
        or parse_hex(base_vault.get("enter_raw_offset"), "raw entry offset")
        != enter_raw_offset
        or parse_hex(base_vault.get("rebind_raw_offset"), "raw rebind offset")
        != rebind_raw_offset
        or parse_hex(
            base_vault.get("enter_raw_preconnect"), "preconnect raw entry"
        )
        != 0x1800 + enter_raw_offset
        or parse_hex(
            base_vault.get("rebind_raw_receipt"), "receipt raw rebind"
        )
        != 0x2800 + rebind_raw_offset
        or parse_hex(
            base_vault.get("receipt_lifecycle_stage"),
            "receipt lifecycle stage",
        )
        != 0x2800
        or parse_hex(
            base_vault.get("receipt_lifecycle_write"),
            "receipt lifecycle write",
        )
        != 0x2800 + lifecycle_write_offset
        or parse_hex(
            base_vault.get("receipt_lifecycle_read"),
            "receipt lifecycle read",
        )
        != 0x2800 + lifecycle_read_offset
    ):
        raise AssertionError("checked/raw lifecycle ABI drifted")

    critical_image = (base / "k14_product_critical_vault.bin").read_bytes()
    critical_listing = base / "k14_product_critical_vault.lst"
    critical_entry = 0x2EE0 + listing_label_offset(
        critical_listing, "k14_product_critical_vault_write"
    )
    critical_code_bytes = listing_label_offset(
        critical_listing, "k14_product_critical_vault_write_end"
    )
    sym_image = (base / "sym_k14.bin").read_bytes()
    embedded_controller = (base / "live_secure_sym_controller.bin").read_bytes()
    critical_tail = sym_image[0x2EE0 - 0x1800 : 0x3000 - 0x1800]
    if (
        not isinstance(raw_writer_abi, dict)
        or len(critical_image) != 160
        or len(embedded_controller) != 128
        or critical_tail != critical_image + embedded_controller
        or raw_writer_abi.get("image_bytes") != len(critical_image)
        or raw_writer_abi.get("image_sha256") != sha256(critical_image)
        or parse_hex(raw_writer_abi.get("entry"), "critical raw writer entry")
        != critical_entry
        or raw_writer_abi.get("code_bytes") != critical_code_bytes
        or raw_writer_abi.get("requires_raw_mode") is not True
        or raw_writer_abi.get("status_written_last") is not True
        or raw_writer_abi.get("page_crc_tags_deliberately_stale") is not True
        or raw_writer_abi.get("ordinary_access_forbidden_until_rebind")
        is not True
        or raw_writer_abi.get("authority_granted") is not False
    ):
        raise AssertionError("deadline raw-writer/tail binding drifted")

    keygen_span = k14_polynomial_span(
        base / "keygen_k14.lst", "KeyGen"
    )
    candidate_span = k14_polynomial_span(
        base / "candidate_k14.lst", "candidate"
    )
    hello_listing = base / "hello_cached_k14.lst"
    hello_span = (
        listing_constant(hello_listing, "poc_ticket_identity"),
        listing_constant(hello_listing, "hello_sha_work_end"),
    )
    if hello_span[0] >= hello_span[1]:
        raise AssertionError("HELLO mutable K span is empty")

    phase_names: dict[int, str] = {}
    for source_manifest in (base_manifest, manifest):
        for field in ("live_phases", "phases"):
            phases = source_manifest.get(field)
            if not isinstance(phases, list):
                continue
            for phase in phases:
                if isinstance(phase, dict) and isinstance(
                    phase.get("name"), str
                ):
                    phase_names[
                        parse_hex(phase.get("key"), "phase ledger key")
                    ] = str(phase["name"])
    phase_names.update(product_input_phase_names(base_manifest))
    sym_phase = next(
        (
            phase
            for phase in base_manifest.get("live_phases", [])
            if isinstance(phase, dict) and phase.get("name") == "sym"
        ),
        None,
    )
    if not isinstance(sym_phase, dict):
        raise AssertionError("base manifest lacks symmetric phase")
    sym_start = int(sym_phase["start_sector"])
    sym_full_key = phase_key(sym_start, 12)
    sym_prefix_key = phase_key(sym_start, 8)
    sym_tail_key = phase_key(sym_start + 8, 2)
    phase_names[sym_full_key] = "sym"
    phase_names[sym_prefix_key] = "sym-critical-prefix-8"
    phase_names[sym_tail_key] = "sym-off-window-tail-2"

    root_instructions = active_listing_instructions(
        base / "live_boot_controller.lst"
    )
    root_main, _ = instructions_through(root_instructions, "jmp 0x2400")
    root_events, _ = collect_lifetime_events("root", root_main)

    pre_instructions = active_listing_instructions(
        base / "live_secure_preconnect_controller.lst"
    )
    pre_main, next_index = instructions_through(
        pre_instructions, "jmp pre_sym_transition"
    )
    pre_events, pre_state = collect_lifetime_events(
        "preconnect",
        pre_main,
        source_writes={
            "call 0x1800": (
                "keygen-polynomial-work",
                keygen_span[0],
                keygen_span[1],
            )
        },
    )
    if any(
        source == "call LIVE_K15_DHCP_ENTRY"
        for _offset, _encoded, source in pre_main
    ):
        raise AssertionError(
            "product preconnect re-entered DHCP instead of reusing the "
            "boot-acquired same-boot lease"
        )
    transition_start = next(
        (
            index
            for index in range(next_index, len(pre_instructions))
            if pre_instructions[index][2] == "mov dx, res_load_phase"
        ),
        None,
    )
    if transition_start is None:
        raise AssertionError("preconnect transition lost its phase loader")
    pre_transition, _ = instructions_through(
        pre_instructions, "jmp dx", start=transition_start
    )
    transition_events, _ = collect_lifetime_events(
        "preconnect-transition",
        pre_transition,
        initial_ax=pre_state[0],
        initial_bx=pre_state[1],
        initial_dx=pre_state[2],
    )

    hello_instructions = active_listing_instructions(
        base / "live_hello_controller.lst"
    )
    hello_main, _ = instructions_through(
        hello_instructions, "jmp pre_sym_transition"
    )
    hello_events, hello_state = collect_lifetime_events("hello", hello_main)
    generic_start = next(
        (
            index
            for index in range(next_index, len(pre_instructions))
            if pre_instructions[index][2] == "mov bx, 0x3000"
        ),
        None,
    )
    if generic_start is None:
        raise AssertionError("HELLO transition lost its generic phase loader")
    generic_transition, _ = instructions_through(
        pre_instructions, "jmp dx", start=generic_start
    )
    generic_events, _ = collect_lifetime_events(
        "hello-transition",
        generic_transition,
        initial_ax=hello_state[0],
        initial_bx=hello_state[1],
        initial_dx=hello_state[2],
    )

    def copy_triples(
        instructions: list[tuple[int, str, str]],
    ) -> list[tuple[int, int, int, int]]:
        si = di = cx = None
        copies: list[tuple[int, int, int, int]] = []
        for offset, encoded, source in instructions:
            value = immediate16(encoded, "BE")
            if value is not None and source.startswith("mov si,"):
                si = value
            value = immediate16(encoded, "BF")
            if value is not None and source.startswith("mov di,"):
                di = value
            value = immediate16(encoded, "B9")
            if value is not None and source.startswith("mov cx,"):
                cx = value
            if source == "rep movsw" and None not in (si, di, cx):
                copies.append((int(si), int(di), int(cx), offset))
        return copies

    hello_initial_state = 0x1800 + listing_label_offset(
        hello_listing, "sha256_initial_state"
    )
    hello_k = 0x1800 + listing_label_offset(hello_listing, "sha256_k")
    hello_copies = copy_triples(hello_main)
    finish_offset = next(
        offset
        for offset, _encoded, source in hello_main
        if source == "call word [hello_server_finish_entry]"
    )
    required_hello_copies = [
        (hello_initial_state, 0x0FC2, 16),
        (hello_k, 0x0500, 128),
    ]
    actual_hello_copies = [item[:3] for item in hello_copies if item[3] > finish_offset]
    if actual_hello_copies[-2:] != required_hello_copies:
        raise AssertionError("HELLO immutable SHA staging drifted")

    crypto_instructions = active_listing_instructions(
        base / "live_crypto_controller.lst"
    )
    crypto_main, _ = instructions_through(crypto_instructions, "jmp 0x3400")
    crypto_events, _ = collect_lifetime_events(
        "secure-crypto",
        crypto_main,
        source_writes={
            "call 0x1800": (
                "candidate-polynomial-work",
                candidate_span[0],
                candidate_span[1],
            )
        },
    )
    raw_writes: list[tuple[int, int, int]] = []
    raw_call_indices: list[int] = []
    raw_al = raw_si = raw_bp = None
    for index, (_offset, encoded, source) in enumerate(crypto_main):
        value8 = immediate8(encoded, "B0")
        if value8 is not None and source.startswith("mov al,"):
            raw_al = value8
        value16 = immediate16(encoded, "BE")
        if value16 is not None and source.startswith("mov si,"):
            raw_si = value16
        value16 = immediate16(encoded, "BD")
        if value16 is not None and source.startswith("mov bp,"):
            raw_bp = value16
        if source == "call live_secure_card_write":
            if None in (raw_al, raw_si, raw_bp):
                raise AssertionError("raw vault write has an unknown ABI input")
            if (
                index + 1 >= len(crypto_main)
                or crypto_main[index + 1][2] != "jc live_secure_persist_fail"
            ):
                raise AssertionError("raw vault write carry is not fail-closed")
            raw_writes.append((int(raw_al), int(raw_si), int(raw_bp)))
            raw_call_indices.append(index)
    if raw_writes != [
        (0x79, 0x08C0, 1088),
        (0x7E, 0x0DAB, 128),
        (0x7F, 0x0DAB, 128),
    ]:
        raise AssertionError(f"deadline raw-vault write set drifted: {raw_writes!r}")
    first_raw_call = raw_call_indices[0]
    if [
        source
        for _offset, _encoded, source in crypto_main[
            first_raw_call + 1 : first_raw_call + 5
        ]
    ] != [
        "jc live_secure_persist_fail",
        "push ds",
        "pop es",
        "mov ax, LIVE_K15_CANDIDATE_KEY",
    ]:
        raise AssertionError(
            "critical raw writer did not normalize ES before the candidate"
        )
    if (0x2F80, 0x3400, 64) not in [item[:3] for item in copy_triples(crypto_main)]:
        raise AssertionError("embedded symmetric continuation copy drifted")
    critical_helper = listing_routine(
        base / "live_crypto_controller.lst",
        crypto_instructions,
        "live_secure_card_write",
    )
    helper_calls = [
        absolute_listing_target(encoded, source)
        for _offset, encoded, source in critical_helper
        if source == "call LIVE_K15_CRITICAL_VAULT_WRITE"
    ]
    if helper_calls != [critical_entry] or any(
        source in {"call LIVE_K15_NE_BUF_LOAD", "call LIVE_K15_NE_BUF_READ"}
        for _offset, _encoded, source in crypto_main + critical_helper
    ):
        raise AssertionError("critical path retained a generic-vault callback")

    sym_instructions = active_listing_instructions(
        base / "live_secure_sym_controller.lst"
    )
    sym_main, _ = instructions_through(sym_instructions, "jmp 0x0900")
    sym_events, _ = collect_lifetime_events("secure-sym", sym_main)
    sym_loads = [
        (int(event["key"]), int(event["start"]), int(event["end"]))
        for event in sym_events
        if event["kind"] == "load"
    ]
    if (
        sym_loads[0] != (sym_prefix_key, 0x1800, 0x2800)
        or [item[:3] for item in copy_triples(sym_main)][:2]
        != [
            (0x0FC2, 0x2EE0, 16),
            (0x0500, 0x2F00, 128),
        ]
        or any(
            source in {"call LIVE_K15_NE_BUF_LOAD", "call LIVE_K15_NE_BUF_READ"}
            for _offset, _encoded, source in sym_main
        )
    ):
        raise AssertionError("eight-sector embedded symmetric restore drifted")

    preconnect_network_loads = [
        phase_names.get(int(event["key"]), f"phase-{int(event['key']):04x}")
        for event in pre_events
        if event["kind"] == "load"
        and phase_names.get(int(event["key"])) in {"dhcp", "endpoint", "tcp"}
    ]
    if preconnect_network_loads != ["endpoint", "tcp"]:
        raise AssertionError(
            "product preconnect endpoint/TCP ordering drifted: "
            f"{preconnect_network_loads!r}"
        )

    initial_events = (
        root_events
        + pre_events
        + transition_events
        + hello_events
        + generic_events
    )
    critical_tail_start = 0x2EE0
    critical_tail_end = 0x3000
    critical_tail_live = False
    critical_tail_root_loads = 0
    critical_tail_overwrites: list[str] = []
    for event in initial_events:
        if event["kind"] != "load":
            continue
        key = int(event["key"])
        start = int(event["start"])
        end = int(event["end"])
        if (
            key == sym_full_key
            and start == 0x1800
            and end == 0x3000
            and event["controller"] == "root"
        ):
            critical_tail_live = True
            critical_tail_root_loads += 1
        elif start < critical_tail_end and critical_tail_start < end:
            if critical_tail_live:
                critical_tail_overwrites.append(
                    phase_names.get(key, f"phase-{key:04x}")
                )
            critical_tail_live = False
    if (
        critical_tail_root_loads != 1
        or not critical_tail_live
        or critical_tail_overwrites
    ):
        raise AssertionError(
            "root-seeded symmetric critical tail is not live at the raw "
            "writer boundary"
        )
    access_end = access_stage + len(access_image)
    fresh = False
    raw_epoch = False
    initial_uses = 0
    access_load_controllers: list[str] = []
    overlap_writes: list[str] = []
    event_report: list[str] = []
    for event in initial_events:
        if event["kind"] == "load":
            key = int(event["key"])
            start = int(event["start"])
            end = int(event["end"])
            label = phase_names.get(key, f"phase-{key:04x}")
            if key == access_key:
                if raw_epoch or start != access_stage or end < access_end:
                    raise AssertionError("checked access loaded inside raw epoch")
                fresh = True
                access_load_controllers.append(str(event["controller"]))
                event_report.append(f"{event['controller']}:load-access@{start:04x}")
            elif start < access_end and access_stage < end:
                overlap_writes.append(label)
                fresh = False
                event_report.append(
                    f"{event['controller']}:overwrite-{label}@{start:04x}"
                )
        elif event["kind"] in {"read", "write"}:
            if raw_epoch or not fresh:
                raise AssertionError("ordinary vault callback escaped checked epoch")
            initial_uses += 1
            event_report.append(f"{event['controller']}:{event['kind']}-checked")
        elif event["kind"] == "marker":
            marker = str(event["name"])
            if marker == "enter-raw":
                if raw_epoch or not fresh:
                    raise AssertionError("raw epoch did not retire a valid checked leaf")
                if int(event["target"]) != 0x1800 + enter_raw_offset:
                    raise AssertionError("preconnect raw entry target drifted")
                raw_epoch = True
                fresh = False
            event_report.append(f"{event['controller']}:{marker}")

    pre_markers = [
        str(event["name"])
        for event in pre_events
        if event["kind"] == "marker"
    ]
    pre_loads = [
        (int(event["key"]), int(event["start"]))
        for event in pre_events
        if event["kind"] == "load"
    ]
    if (
        access_load_controllers != ["root"]
        or initial_uses != 5
        or not raw_epoch
        or pre_markers != ["tcp-connect", "tcp-close", "enter-raw"]
        or pre_loads[-2:] != [
            (parse_hex(base_vault.get("lifecycle_phase_key"), "lifecycle key"), 0x1800),
            (sym_tail_key, 0x2800),
        ]
        or overlap_writes[-1:] != ["sym-off-window-tail-2"]
    ):
        raise AssertionError("checked-to-raw preconnect schedule drifted")
    if len([event for event in crypto_events if event["kind"] == "write"]) != 3:
        raise AssertionError("critical raw epoch lost a deadline write")

    fo = vault.get("fo")
    if not isinstance(fo, dict):
        raise AssertionError("product manifest lacks independent FO vault ABI")
    fo_stage = parse_hex(fo.get("stage"), "FO vault stage")
    fo_write = parse_hex(fo.get("write"), "FO vault write")
    fo_read = parse_hex(fo.get("read"), "FO vault read")
    if (
        fo_stage != 0x2800
        or fo_write != fo_stage + write_offset
        or fo_read != fo_stage + read_offset
    ):
        raise AssertionError("independent FO public-vault geometry drifted")

    fo_instructions = active_listing_instructions(
        base / "live_fo_controller.lst"
    )
    fo_prefix, fo_after_kernel = instructions_through(
        fo_instructions, "call fo_kernel_entry"
    )
    fo_prefix_events, _ = collect_lifetime_events("fo", fo_prefix)
    fo_suffix, _ = instructions_through(
        fo_instructions,
        "call fo_cleanup_handoffs",
        start=fo_after_kernel,
    )
    fo_suffix_events, _ = collect_lifetime_events("fo", fo_suffix)
    read_routine = listing_routine(
        base / "live_fo_controller.lst",
        fo_instructions,
        "fo_card_read_callback",
    )
    read_callback_events, _ = collect_lifetime_events(
        "fo-kernel-callback", read_routine
    )
    write_routine = listing_routine(
        base / "live_fo_controller.lst",
        fo_instructions,
        "fo_card_write",
    )
    write_callback_events, _ = collect_lifetime_events(
        "fo-cleanup-callback", write_routine
    )

    fo_kernel_listing = base / "fo_tail_live.lst"
    fo_kernel_instructions = active_listing_instructions(fo_kernel_listing)
    fo_keccak_span = (
        listing_constant(fo_kernel_listing, "fo_keccak_state"),
        listing_constant(fo_kernel_listing, "fo_keccak_work_end"),
    )
    fo_poly_start = listing_constant(fo_kernel_listing, "fo_poly_acc")
    fo_poly_span = (
        fo_poly_start,
        fo_poly_start
        + listing_constant(fo_kernel_listing, "fo_poly_bytes"),
    )
    fo_kernel_events: list[dict[str, Any]] = []
    keccak_write_seen = False
    poly_write_seen = False
    kernel_callback_sites = 0
    for offset, _encoded, source in fo_kernel_instructions:
        if source == "call fo_read_public":
            fo_kernel_events.extend(read_callback_events)
            kernel_callback_sites += 1
        elif source == "call fo_noise_to_poly" and not keccak_write_seen:
            fo_kernel_events.append(
                {
                    "kind": "source-write",
                    "controller": "fo-kernel",
                    "offset": offset,
                    "name": "fo-keccak-work",
                    "start": fo_keccak_span[0],
                    "end": fo_keccak_span[1],
                }
            )
            keccak_write_seen = True
        elif source == "call fo_zero_acc" and not poly_write_seen:
            fo_kernel_events.append(
                {
                    "kind": "source-write",
                    "controller": "fo-kernel",
                    "offset": offset,
                    "name": "fo-polynomial-work",
                    "start": fo_poly_span[0],
                    "end": fo_poly_span[1],
                }
            )
            poly_write_seen = True
    if (
        kernel_callback_sites < 2
        or not keccak_write_seen
        or not poly_write_seen
    ):
        raise AssertionError("FO kernel lifetime sources drifted")
    fo_events = (
        fo_prefix_events
        + fo_kernel_events
        + fo_suffix_events
        + write_callback_events
        + write_callback_events
    )

    fo_access_end = fo_stage + len(access_image)
    fo_fresh = False
    fo_uses = 0
    fo_access_loads = 0
    fo_overlap_writes: list[str] = []
    for event in fo_events:
        if event["kind"] == "load":
            key = int(event["key"])
            start = int(event["start"])
            end = int(event["end"])
            if key == access_key:
                if start != fo_stage or end < fo_access_end:
                    raise AssertionError("FO access reload is incomplete")
                fo_fresh = True
                fo_access_loads += 1
            elif start < fo_access_end and fo_stage < end:
                fo_fresh = False
                fo_overlap_writes.append(
                    phase_names.get(key, f"phase-{key:04x}")
                )
        elif event["kind"] == "source-write":
            start = int(event["start"])
            end = int(event["end"])
            if start < fo_access_end and fo_stage < end:
                fo_fresh = False
                fo_overlap_writes.append(str(event["name"]))
        elif event["kind"] in {"read", "write"}:
            if not fo_fresh:
                raise AssertionError("product FO called a stale vault leaf")
            fo_uses += 1
    if (
        fo_access_loads != 1
        or fo_uses < 11
        or fo_overlap_writes
    ):
        raise AssertionError("product FO did not reload checked access before use")

    receipt = vault.get("receipt")
    if not isinstance(receipt, dict):
        raise AssertionError("product manifest lacks receipt vault ABI")
    receipt_stage = parse_hex(receipt.get("stage"), "receipt vault stage")
    receipt_write = parse_hex(receipt.get("write"), "receipt vault write")
    receipt_read = parse_hex(receipt.get("read"), "receipt vault read")
    receipt_rebind = parse_hex(receipt.get("rebind"), "receipt raw rebind")
    lifecycle_key = parse_hex(
        vault.get("lifecycle_phase_key"), "vault lifecycle phase key"
    )
    if (
        receipt_stage != 0x2800
        or receipt_write != receipt_stage + lifecycle_write_offset
        or receipt_read != receipt_stage + lifecycle_read_offset
        or receipt_rebind != receipt_stage + rebind_raw_offset
        or receipt.get("loaded_after_symmetric_work_retires") is not True
        or receipt.get("loaded_after_receipt_digest") is not True
        or receipt.get("raw_epoch_rebound_before_write") is not True
        or receipt_stage + (lifecycle_key >> 8) * SECTOR != 0x2E00
    ):
        raise AssertionError("receipt public-vault geometry drifted")

    receipt_phase = next(
        (
            phase
            for phase in manifest.get("phases", [])
            if isinstance(phase, dict)
            and phase.get("name") == "post_auth_resume_receipt"
        ),
        None,
    )
    if not isinstance(receipt_phase, dict):
        raise AssertionError("product manifest lacks receipt worker phase")
    receipt_key = parse_hex(receipt_phase.get("key"), "receipt phase key")
    output = manifest.get("output")
    if not isinstance(output, dict):
        raise AssertionError("product manifest lacks receipt output binding")
    route_dir = Path(str(output.get("core"))).parent
    receipt_post_listing = (
        route_dir / "post_auth_receipt_post_controller.lst"
    )
    receipt_post_instructions = active_listing_instructions(
        receipt_post_listing
    )
    receipt_edge_offset = listing_label_offset(
        receipt_post_listing, ".resume_receipt_edge"
    )
    receipt_edge_index = next(
        (
            index
            for index, instruction in enumerate(receipt_post_instructions)
            if instruction[0] == receipt_edge_offset
        ),
        None,
    )
    if receipt_edge_index is None:
        raise AssertionError("receipt controller lost its exact entry edge")
    receipt_edge, _ = instructions_through(
        receipt_post_instructions, "jmp 0x3400", start=receipt_edge_index
    )
    receipt_events, _ = collect_lifetime_events(
        "receipt-edge", receipt_edge
    )
    receipt_loads = [
        (
            int(event["key"]),
            int(event["start"]),
            int(event["end"]),
        )
        for event in receipt_events
        if event["kind"] == "load"
    ]
    if receipt_loads != [(receipt_key, 0x0D00, 0x0F00)]:
        raise AssertionError(
            "receipt edge performed an unmeasured pre-digest access load: "
            f"{receipt_loads!r}"
        )

    receipt_worker_instructions = active_listing_instructions(
        route_dir / "post_auth_resume_receipt.lst"
    )
    receipt_worker_events, _ = collect_lifetime_events(
        "receipt-worker", receipt_worker_instructions
    )
    receipt_worker_loads = [
        (
            int(event["key"]),
            int(event["start"]),
            int(event["end"]),
            int(event["offset"]),
        )
        for event in receipt_worker_events
        if event["kind"] == "load"
    ]
    receipt_rebind_events = [
        event
        for event in receipt_worker_events
        if event["kind"] == "marker" and event["name"] == "rebind-raw"
    ]
    if len(receipt_worker_loads) != 2:
        raise AssertionError(
            "receipt worker lost its exact lifecycle/FO load schedule: "
            f"{receipt_worker_loads!r}"
        )
    if (
        len(receipt_rebind_events) != 1
        or int(receipt_rebind_events[0]["target"]) != receipt_rebind
    ):
        raise AssertionError(
            "receipt worker raw-to-checked rebind drifted: "
            f"{receipt_rebind_events!r}"
        )
    receipt_lifecycle_load, receipt_fo_load = receipt_worker_loads
    if (
        receipt_lifecycle_load[:3]
        != (lifecycle_key, receipt_stage, 0x2E00)
        or receipt_fo_load[0] in {access_key, lifecycle_key}
        or receipt_fo_load[1:3] != (0x2400, 0x2600)
    ):
        raise AssertionError(
            "receipt worker access/FO phase geometry drifted: "
            f"{receipt_worker_loads!r}"
        )
    digest_finish_offset = next(
        (
            offset
            for offset, _encoded, source in receipt_worker_instructions
            if source == "call RESUME_RECEIPT_SHA256_FINISH"
        ),
        None,
    )
    first_vault_callback_offset = next(
        (
            offset
            for offset, _encoded, source in receipt_worker_instructions
            if source
            in {
                "call RESUME_RECEIPT_VAULT_WRITE",
                "call RESUME_RECEIPT_VAULT_READ",
            }
        ),
        None,
    )
    receipt_rebind_offset = int(receipt_rebind_events[0]["offset"])
    if (
        digest_finish_offset is None
        or first_vault_callback_offset is None
        or not (
            digest_finish_offset
            < receipt_lifecycle_load[3]
            < receipt_rebind_offset
            < first_vault_callback_offset
        )
    ):
        raise AssertionError(
            "receipt access reload is not ordered after SHA and before DMA"
        )

    callback_targets: dict[str, set[int]] = {
        "call RESUME_RECEIPT_VAULT_WRITE": set(),
        "call RESUME_RECEIPT_VAULT_READ": set(),
    }
    for _offset, encoded, source in receipt_worker_instructions:
        if source in callback_targets:
            callback_targets[source].add(
                absolute_listing_target(encoded, source)
            )
    if callback_targets != {
        "call RESUME_RECEIPT_VAULT_WRITE": {receipt_write},
        "call RESUME_RECEIPT_VAULT_READ": {receipt_read},
    }:
        raise AssertionError(
            "receipt worker retained stale generic-vault callbacks: "
            f"{callback_targets!r}"
        )

    return {
        "initial_stage": f"0x{access_stage:04x}",
        "initial_write": f"0x{access_write:04x}",
        "initial_read": f"0x{access_read:04x}",
        "access_image_bytes": len(access_image),
        "initial_access_loads": len(access_load_controllers),
        "initial_access_load_controllers": access_load_controllers,
        "initial_fresh_callbacks": initial_uses,
        "pre_hello_lifecycle_placement": {
            "load_span": "0x1800..0x1e00",
            "retired_owner": "KeyGen code",
            "public_key_span": "0x08c0..0x0d60",
            "public_key_disjoint": True,
            "live_controller_span": "0x2400..0x2800",
            "live_controller_disjoint": True,
        },
        "overlap_invalidations": ["sym-off-window-tail-2"],
        "overlap_writes": overlap_writes,
        "required_recoveries": [],
        "critical_raw_epoch": {
            "enter_raw": f"0x{0x1800 + enter_raw_offset:04x}",
            "ordinary_access_callbacks_after_enter": 0,
            "off_window_tail_restore_key": f"0x{sym_tail_key:04x}",
            "off_window_tail_restore_sectors": 2,
            "deadline_writer": f"0x{critical_entry:04x}",
            "deadline_writer_bytes": len(critical_image),
            "deadline_writer_code_bytes": critical_code_bytes,
            "deadline_writes": [
                {"page": f"0x{page:02x}", "source": f"0x{source:04x}", "bytes": count}
                for page, source, count in raw_writes
            ],
            "raw_writer_es_normalized_before_candidate": True,
            "embedded_controller_bytes": len(embedded_controller),
            "symmetric_critical_tail_seeded_by_root": True,
            "symmetric_critical_tail_root_loads": critical_tail_root_loads,
            "symmetric_critical_tail_overwrites_after_root": (
                critical_tail_overwrites
            ),
            "symmetric_tail_byte_bound": True,
            "generic_access_callbacks_in_deadline_controllers": 0,
            "hello_sha_initial_stage": "0x0fc2..0x0fe2",
            "hello_sha_k_stage": "0x0500..0x0600",
            "symmetric_sha_initial_restore": (
                "0x0fc2..0x0fe2 -> 0x2ee0..0x2f00"
            ),
            "symmetric_sha_k_restore": "0x0500..0x0600 -> 0x2f00..0x3000",
            "critical_symmetric_restore_key": f"0x{sym_prefix_key:04x}",
            "critical_symmetric_restore_sectors": 8,
            "receipt_rebind": f"0x{receipt_rebind:04x}",
            "authority_granted_by_raw_epoch": False,
        },
        "source_write_spans": {
            "keygen": f"0x{keygen_span[0]:04x}..0x{keygen_span[1]:04x}",
            "hello": f"0x{hello_span[0]:04x}..0x{hello_span[1]:04x}",
            "candidate": (
                f"0x{candidate_span[0]:04x}..0x{candidate_span[1]:04x}"
            ),
            "fo_keccak": (
                f"0x{fo_keccak_span[0]:04x}..0x{fo_keccak_span[1]:04x}"
            ),
            "fo_polynomial": (
                f"0x{fo_poly_span[0]:04x}..0x{fo_poly_span[1]:04x}"
            ),
        },
        "hello_transition_checked": True,
        "boot_lease_reuse": {
            "product_dhcp_phase_loads": 0,
            "network_phase_order": preconnect_network_loads,
        },
        "initial_access_retired_after_final_read": "enter-raw",
        "fo_stage": f"0x{fo_stage:04x}",
        "receipt_raw_rebind_count": len(receipt_rebind_events),
        "fo_self_reload_count": fo_access_loads,
        "fo_fresh_callbacks_checked": fo_uses,
        "fo_kernel_callback_sites": kernel_callback_sites,
        "fo_pre_access_overwrites": fo_overlap_writes,
        "receipt_stage": f"0x{receipt_stage:04x}",
        "receipt_write": f"0x{receipt_write:04x}",
        "receipt_read": f"0x{receipt_read:04x}",
        "receipt_lifecycle_rebind_after_digest_before_access": True,
        "ordered_events": event_report,
    }


def run_resumption_access_lease_gate(
    base: Path,
    base_manifest: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Bind every resumed vault callback to a fresh measured access lease.

    K14's complete symmetric image owns 0x1800..0x2fff, including the resumed
    public-vault leaf at 0x2c00.  This gate inventories the actual calls in
    every generated route binary, proves the six complete-image restore seams
    reconstruct the canonical tail before use and have the required
    callback/re-pin ordering, and replays those seams through an exact-byte
    lease model.  The model deliberately attempts one hostile stale callback
    so a broken invalidation check cannot pass vacuously.
    """

    vault = manifest.get("vault_abi")
    output = manifest.get("output")
    if not isinstance(vault, dict) or not isinstance(output, dict):
        raise AssertionError("product manifest lacks resumption lease metadata")
    resumed = vault.get("resumption")
    receipt = vault.get("receipt")
    if not isinstance(resumed, dict) or not isinstance(receipt, dict):
        raise AssertionError("product manifest lacks resumed/receipt vault ABI")

    route_core = Path(str(output.get("core")))
    if not route_core.is_absolute():
        route_core = ROOT / route_core
    route_dir = route_core.parent

    access_key = parse_hex(
        vault.get("access_phase_key"), "vault access phase key"
    )
    access_capacity = (access_key >> 8) * SECTOR
    access_image = (base / "product_vault_access.bin").read_bytes()
    if not access_image or len(access_image) > access_capacity:
        raise AssertionError("public-vault access image escaped its phase")
    access_phase = access_image.ljust(access_capacity, b"\0")
    access_listing = base / "product_vault_access.lst"
    write_offset = listing_label_offset(access_listing, "pv_write")
    read_offset = listing_label_offset(access_listing, "pv_read")
    lifecycle_key = parse_hex(
        vault.get("lifecycle_phase_key"), "vault lifecycle phase key"
    )
    lifecycle_capacity = (lifecycle_key >> 8) * SECTOR
    lifecycle_image_raw = (base / "product_vault_lifecycle.bin").read_bytes()
    if not lifecycle_image_raw or len(lifecycle_image_raw) > lifecycle_capacity:
        raise AssertionError("public-vault lifecycle image escaped its phase")
    lifecycle_phase = lifecycle_image_raw.ljust(lifecycle_capacity, b"\0")
    lifecycle_listing = base / "product_vault_lifecycle.lst"
    lifecycle_write_offset = listing_label_offset(
        lifecycle_listing, "pv_write"
    )
    lifecycle_read_offset = listing_label_offset(
        lifecycle_listing, "pv_read"
    )
    rebind_raw_offset = listing_label_offset(
        lifecycle_listing, "pv_rebind_raw"
    )
    resumption_stage = parse_hex(
        resumed.get("stage"), "resumption vault stage"
    )
    receipt_stage = parse_hex(receipt.get("stage"), "receipt vault stage")
    resumption_write = parse_hex(
        resumed.get("write"), "resumption vault write"
    )
    resumption_read = parse_hex(
        resumed.get("read"), "resumption vault read"
    )
    receipt_write = parse_hex(receipt.get("write"), "receipt vault write")
    receipt_read = parse_hex(receipt.get("read"), "receipt vault read")
    receipt_rebind = parse_hex(receipt.get("rebind"), "receipt raw rebind")
    if (
        resumption_stage != 0x2C00
        or receipt_stage != 0x2800
        or resumption_write != resumption_stage + write_offset
        or resumption_read != resumption_stage + read_offset
        or receipt_write != receipt_stage + lifecycle_write_offset
        or receipt_read != receipt_stage + lifecycle_read_offset
        or receipt_rebind != receipt_stage + rebind_raw_offset
        or receipt.get("raw_epoch_rebound_before_write") is not True
    ):
        raise AssertionError("resumption public-vault callback geometry drifted")

    sym_phase = next(
        (
            phase
            for phase in base_manifest.get("live_phases", [])
            if isinstance(phase, dict) and phase.get("name") == "sym"
        ),
        None,
    )
    if not isinstance(sym_phase, dict):
        raise AssertionError("base manifest lacks complete symmetric phase")
    sym_key = parse_hex(sym_phase.get("key"), "symmetric phase key")
    sym_start = parse_hex(
        sym_phase.get("destination"), "symmetric phase destination"
    )
    sym_sectors = int(sym_phase.get("sectors", 0))
    sym_image = (base / "sym_k14.bin").read_bytes()
    sym_end = sym_start + len(sym_image)
    if (
        sym_sectors != 12
        or sym_key != phase_key(int(sym_phase["start_sector"]), sym_sectors)
        or len(sym_image) != sym_sectors * SECTOR
        or sym_start != 0x1800
        or sym_end != 0x3000
        or (route_dir / "sym_k14.bin").read_bytes() != sym_image
        or not (
            sym_start <= resumption_stage
            and resumption_stage + access_capacity <= sym_end
        )
    ):
        raise AssertionError("complete symmetric/access overlap geometry drifted")
    if sym_image[:8] != b"T13SYM02":
        raise AssertionError("symmetric image header drifted")
    tail_phase = next(
        (
            phase
            for phase in base_manifest.get("live_phases", [])
            if isinstance(phase, dict)
            and phase.get("name") == "sym_tail_restore"
        ),
        None,
    )
    if not isinstance(tail_phase, dict):
        raise AssertionError("base manifest lacks canonical symmetric tail")
    canonical_tail_key = parse_hex(
        tail_phase.get("key"), "symmetric tail phase key"
    )
    canonical_tail_start = parse_hex(
        tail_phase.get("destination"), "symmetric tail destination"
    )
    canonical_tail_sectors = int(tail_phase.get("sectors", 0))
    canonical_tail = (base / "sym_k14_runtime_tail.bin").read_bytes()
    canonical_sym = (base / "sym_k14_runtime_canonical.bin").read_bytes()
    runtime_sym = sym_image[: canonical_tail_start - sym_start] + canonical_tail
    if (
        canonical_tail_start != 0x2E00
        or canonical_tail_sectors != 1
        or canonical_tail_key
        != phase_key(int(tail_phase["start_sector"]), canonical_tail_sectors)
        or len(canonical_tail) != SECTOR
        or len(canonical_sym) != len(sym_image)
        or runtime_sym != canonical_sym
    ):
        raise AssertionError(
            "symmetric tail phase does not reconstruct canonical K14"
        )
    sha_work_start, sha_work_end = struct.unpack_from("<2H", sym_image, 0x0C)
    if (sha_work_start, sha_work_end) != (0x3000, 0x33F8):
        raise AssertionError("K14 SHA mutable interval drifted")

    def decoded_listing_target(encoded: str) -> int | None:
        matched = re.fullmatch(r"E8\(([0-9A-F]{4})\)", encoded)
        if matched is None:
            return None
        return int.from_bytes(bytes.fromhex(matched.group(1)), "little")

    def ordered_sources(path: Path, sources: tuple[str, ...]) -> list[int]:
        instructions = active_listing_instructions(path)
        offsets: list[int] = []
        cursor = 0
        for wanted in sources:
            found = next(
                (
                    index
                    for index in range(cursor, len(instructions))
                    if instructions[index][2] == wanted
                ),
                None,
            )
            if found is None:
                raise AssertionError(
                    f"{path.name} lost ordered lease edge: {wanted}"
                )
            offsets.append(instructions[found][0])
            cursor = found + 1
        if offsets != sorted(offsets):
            raise AssertionError(f"{path.name} lease edges wrapped")
        return offsets

    # This table is the fail-closed inventory of every direct access-leaf call
    # in the generated route.  The binary scan independently verifies the
    # listing's absolute targets and catches accidental call-shaped bytes.
    expected_consumers: dict[str, tuple[int, Counter[int]]] = {
        "post_auth_resume_receipt": (
            0x3400,
            Counter({receipt_write: 1, receipt_read: 1}),
        ),
        "post_auth_resume_lifecycle": (
            0x3000,
            Counter({resumption_read: 3}),
        ),
        "post_auth_resume_prepare": (
            0x3000,
            Counter({resumption_read: 4, resumption_write: 1}),
        ),
        "post_auth_resume_prepare_hash": (
            0x3400,
            Counter({resumption_read: 2}),
        ),
        "post_auth_resume_prepare_commit": (
            0x3400,
            Counter({resumption_read: 1, resumption_write: 1}),
        ),
        "post_auth_resume_prepare_crypto": (
            0x3400,
            Counter({resumption_read: 5, resumption_write: 1}),
        ),
        "post_auth_resume_prepare_age": (
            0x2800,
            Counter({resumption_read: 1}),
        ),
        "post_auth_resume_prepare_binder": (
            0x3400,
            Counter({resumption_read: 2}),
        ),
        "post_auth_resume_prepare_sym_binder": (
            0x3400,
            Counter({resumption_read: 1}),
        ),
        "post_auth_resume_prepare_restore": (
            0x3000,
            Counter({resumption_write: 1, resumption_read: 1}),
        ),
        "post_auth_resume_exchange": (
            0x3000,
            Counter({resumption_read: 5}),
        ),
        "post_auth_resume_exchange_tx": (
            0x3400,
            Counter({resumption_read: 3}),
        ),
        "post_auth_resume_exchange_crypto": (
            0x3000,
            Counter({resumption_read: 6, resumption_write: 1}),
        ),
        "post_auth_resume_exchange_post": (
            0x2400,
            Counter({resumption_read: 1, resumption_write: 1}),
        ),
        "post_auth_resume_fo_controller": (
            0x2400,
            Counter({resumption_read: 6, resumption_write: 1}),
        ),
    }
    access_targets = {
        resumption_write,
        resumption_read,
        receipt_write,
        receipt_read,
    }
    listing_calls: dict[str, list[tuple[int, int]]] = {}
    discovered_consumers: dict[str, Counter[int]] = {}
    for path in sorted(route_dir.glob("*.lst")):
        calls = [
            (offset, target)
            for offset, encoded, _source in active_listing_instructions(path)
            if (target := decoded_listing_target(encoded)) in access_targets
        ]
        if calls:
            name = path.stem
            listing_calls[name] = calls
            discovered_consumers[name] = Counter(
                target for _offset, target in calls
            )
    expected_counts = {
        name: counts for name, (_origin, counts) in expected_consumers.items()
    }
    if discovered_consumers != expected_counts:
        raise AssertionError(
            "resumption access consumer inventory drifted: "
            f"{discovered_consumers!r}"
        )
    for name, (origin, counts) in expected_consumers.items():
        image = (route_dir / f"{name}.bin").read_bytes()
        for target, expected_count in counts.items():
            listing_offsets = [
                offset
                for offset, actual_target in listing_calls[name]
                if actual_target == target
            ]
            binary_offsets = calls_to_address(image, origin, target)
            if (
                len(listing_offsets) != expected_count
                or binary_offsets != listing_offsets
            ):
                raise AssertionError(
                    f"{name} binary/listing access calls diverged at "
                    f"0x{target:04x}"
                )

    # Inventory every complete symmetric-image request.  Six workers use one
    # twelve-sector loader call; the binder deliberately loops over twelve
    # one-sector quarantine reads before copying them into 0x1800..0x2fff.
    full_sym_sites: dict[str, list[tuple[str, str, int]]] = {}
    for path in sorted(route_dir.glob("*.lst")):
        sites: list[tuple[str, str, int]] = []
        for offset, encoded, source in active_listing_instructions(path):
            opcode = ""
            if immediate16(encoded, "B8") == sym_key:
                opcode = "B8"
            elif immediate16(encoded, "BA") == sym_key:
                opcode = "BA"
            if opcode:
                sites.append((opcode, source, offset))
        if sites:
            full_sym_sites[path.stem] = sites
    expected_full_sym_signatures = {
        "post_auth_resume_lifecycle_receipt_hash": [
            ("B8", "mov ax, RESUME_LIFECYCLE_SYM_KEY")
        ],
        "post_auth_resume_lifecycle_vault_hash": [
            ("B8", "mov ax, RESUME_LIFECYCLE_SYM_KEY")
        ],
        "post_auth_resume_prepare_hash": [
            ("B8", "mov ax, RESUME_PREPARE_SYM_KEY")
        ],
        "post_auth_resume_prepare_sym_binder": [
            ("BA", "mov dx, RESUME_PREPARE_SYM_KEY")
        ],
        "post_auth_resume_exchange_post": [
            ("B8", "mov ax, RESUME_EXCHANGE_SYM_RESTORE_KEY")
        ],
        "post_auth_resume_fo_controller": [
            ("B8", "mov ax, RESUME_FO_SYM_RESTORE_KEY")
        ],
    }
    actual_full_sym_signatures = {
        name: [(opcode, source) for opcode, source, _offset in sites]
        for name, sites in full_sym_sites.items()
    }
    if actual_full_sym_signatures != expected_full_sym_signatures:
        raise AssertionError(
            "complete symmetric-image invalidator inventory drifted: "
            f"{actual_full_sym_signatures!r}"
        )

    tail_restore_sites: dict[str, list[tuple[str, int]]] = {}
    for path in sorted(route_dir.glob("*.lst")):
        sites = [
            (source, offset)
            for offset, encoded, source in active_listing_instructions(path)
            if immediate16(encoded, "B8") == canonical_tail_key
        ]
        if sites:
            tail_restore_sites[path.stem] = sites
    expected_tail_signatures = {
        "post_auth_resume_lifecycle_receipt_hash": [
            "mov ax, RESUME_LIFECYCLE_SYM_TAIL_KEY"
        ],
        "post_auth_resume_lifecycle_vault_hash": [
            "mov ax, RESUME_LIFECYCLE_SYM_TAIL_KEY"
        ],
        "post_auth_resume_prepare_hash": [
            "mov ax, RESUME_PREPARE_SYM_TAIL_KEY"
        ],
        "post_auth_resume_prepare_sym_binder": [
            "mov ax, RESUME_PREPARE_SYM_TAIL_KEY"
        ],
        "post_auth_resume_exchange_post": [
            "mov ax, RESUME_EXCHANGE_SYM_TAIL_KEY"
        ],
        "post_auth_resume_fo_controller": [
            "mov ax, RESUME_FO_SYM_TAIL_KEY"
        ],
    }
    actual_tail_signatures = {
        name: [source for source, _offset in sites]
        for name, sites in tail_restore_sites.items()
    }
    if actual_tail_signatures != expected_tail_signatures:
        raise AssertionError(
            "canonical symmetric-tail restore inventory drifted: "
            f"{actual_tail_signatures!r}"
        )

    supervisor_order = ordered_sources(
        route_dir / "post_auth_live_supervisor.lst",
        (
            "mov ax, POST_AUTH_PRODUCT_VAULT_ACCESS_KEY",
            "mov bx, POST_AUTH_PRODUCT_VAULT_ACCESS_STAGE",
            "call resident_load_phase",
            "mov ax, POST_AUTH_PRODUCT_VAULT_ACCESS_KEY",
            "mov bx, POST_AUTH_PRODUCT_VAULT_ACCESS_STAGE",
            "mov dx, resident_load_phase",
            "call dx",
            "mov ax, POST_AUTH_PRODUCT_VAULT_ACCESS_KEY",
            "mov bx, POST_AUTH_PRODUCT_VAULT_ACCESS_STAGE",
            "mov dx, resident_load_phase",
            "call dx",
        ),
    )
    receipt_order = ordered_sources(
        route_dir / "post_auth_resume_receipt.lst",
        (
            "call RESUME_RECEIPT_SHA256_FINISH",
            "mov ax, RESUME_RECEIPT_VAULT_LIFECYCLE_KEY",
            "mov bx, RESUME_RECEIPT_VAULT_LIFECYCLE_STAGE",
            "call resident_load_phase",
            "call RESUME_RECEIPT_VAULT_REBIND_RAW",
            "push ds",
            "pop es",
            "call RESUME_RECEIPT_VAULT_WRITE",
            "call RESUME_RECEIPT_VAULT_READ",
        ),
    )
    lifecycle_orders: dict[str, list[int]] = {}
    for name in (
        "post_auth_resume_lifecycle_receipt_hash",
        "post_auth_resume_lifecycle_vault_hash",
    ):
        lifecycle_orders[name] = ordered_sources(
            route_dir / f"{name}.lst",
            (
                "mov ax, RESUME_LIFECYCLE_SYM_KEY",
                "mov bx, 0x1800",
                "call resident_load_phase",
                "mov ax, RESUME_LIFECYCLE_SYM_TAIL_KEY",
                "mov bx, 0x2e00",
                "call resident_load_phase",
                "call RESUME_LIFECYCLE_SHA256_FINISH",
                "mov ax, RESUME_LIFECYCLE_SELF_KEY",
                "mov bx, 0x3000",
                "call resident_load_phase",
                "mov ax, RESUME_LIFECYCLE_VAULT_ACCESS_KEY",
                "mov bx, RESUME_LIFECYCLE_VAULT_ACCESS_STAGE",
                "call resident_load_phase",
            ),
        )
    prepare_hash_order = ordered_sources(
        route_dir / "post_auth_resume_prepare_hash.lst",
        (
            "call RESUME_PREPARE_NE_BUF_READ",
            "call RESUME_PREPARE_NE_BUF_READ",
            "mov ax, RESUME_PREPARE_SYM_KEY",
            "mov bx, 0x1800",
            "call RESUME_PREPARE_LOAD_PHASE",
            "mov ax, RESUME_PREPARE_SYM_TAIL_KEY",
            "mov bx, 0x2e00",
            "call RESUME_PREPARE_LOAD_PHASE",
            "call RESUME_PREPARE_SYM_SHA_FINISH",
        ),
    )
    prepare_commit_order = ordered_sources(
        route_dir / "post_auth_resume_prepare_commit.lst",
        (
            "mov ax, RESUME_PREPARE_VAULT_ACCESS_KEY",
            "mov bx, RESUME_PREPARE_VAULT_ACCESS_STAGE",
            "call RESUME_PREPARE_LOAD_PHASE",
            "call RESUME_PREPARE_NE_BUF_READ",
            "call RESUME_PREPARE_NE_BUF_LOAD",
        ),
    )
    prepare_sym_order = ordered_sources(
        route_dir / "post_auth_resume_prepare_sym_binder.lst",
        (
            "call RESUME_PREPARE_NE_BUF_READ",
            "mov dx, RESUME_PREPARE_SYM_KEY",
            "xor dh, dh",
            "mov bp, RESUME_PREPARE_SYM_IMAGE_SECTORS",
            "mov di, 0x1800",
            "mov ax, dx",
            "mov ah, 1",
            "mov bx, 0x0d00",
            "call RESUME_PREPARE_LOAD_PHASE",
            "mov si, 0x0d00",
            "mov cx, 256",
            "rep movsw",
            "inc dl",
            "dec bp",
            "jnz .load_sym_sector",
            "mov ax, RESUME_PREPARE_SYM_TAIL_KEY",
            "mov bx, 0x2e00",
            "call RESUME_PREPARE_LOAD_PHASE",
            "mov si, 0x1800",
            "mov cx, RESUME_PREPARE_SYM_IMAGE_BYTES",
            "cmp dx, RESUME_PREPARE_SYM_IMAGE_CRC16",
        ),
    )
    sym_binder_instructions = active_listing_instructions(
        route_dir / "post_auth_resume_prepare_sym_binder.lst"
    )
    sym_loop_sectors = next(
        (
            immediate16(encoded, "BD")
            for _offset, encoded, source in sym_binder_instructions
            if source == "mov bp, RESUME_PREPARE_SYM_IMAGE_SECTORS"
        ),
        None,
    )
    sym_crc_bytes = next(
        (
            immediate16(encoded, "B9")
            for _offset, encoded, source in sym_binder_instructions
            if source == "mov cx, RESUME_PREPARE_SYM_IMAGE_BYTES"
        ),
        None,
    )
    if sym_loop_sectors != sym_sectors or sym_crc_bytes != len(sym_image):
        raise AssertionError("PREPARE one-sector symmetric loop is incomplete")
    prepare_restore_order = ordered_sources(
        route_dir / "post_auth_resume_prepare_restore.lst",
        (
            "mov ax, RESUME_PREPARE_VAULT_ACCESS_KEY",
            "mov bx, RESUME_PREPARE_VAULT_ACCESS_STAGE",
            "call RESUME_PREPARE_LOAD_PHASE",
            "call RESUME_PREPARE_NE_BUF_LOAD",
            "call RESUME_PREPARE_NE_BUF_READ",
        ),
    )

    complete_restore_sources = {
        "post_auth_resume_exchange_post": (
            "mov ax, RESUME_EXCHANGE_SYM_RESTORE_KEY"
        ),
        "post_auth_resume_fo_controller": (
            "mov ax, RESUME_FO_SYM_RESTORE_KEY"
        ),
    }
    complete_restore_orders: dict[str, list[int]] = {}
    for name, source in complete_restore_sources.items():
        instructions = active_listing_instructions(route_dir / f"{name}.lst")
        keys = [
            immediate16(encoded, "B8")
            for _offset, encoded, actual_source in instructions
            if actual_source == source
        ]
        if keys != [sym_key]:
            raise AssertionError(
                f"{name} did not request the complete symmetric image"
            )
        tail_source = (
            "mov ax, RESUME_EXCHANGE_SYM_TAIL_KEY"
            if name == "post_auth_resume_exchange_post"
            else "mov ax, RESUME_FO_SYM_TAIL_KEY"
        )
        restore_sources = (
            source,
            "mov bx, 0x1800",
            "call dx",
            tail_source,
            "mov bx, 0x2e00",
            "call dx",
        )
        if name == "post_auth_resume_fo_controller":
            restore_sources = (
                source,
                "mov bx, 0x1800",
                "mov dx, RESUME_FO_LOAD_PHASE",
                "call dx",
                tail_source,
                "mov bx, 0x2e00",
                "mov dx, RESUME_FO_LOAD_PHASE",
                "call dx",
            )
        order = ordered_sources(
            route_dir / f"{name}.lst", restore_sources
        )
        if order != sorted(order):
            raise AssertionError(f"{name} complete restore order drifted")
        complete_restore_orders[name] = order

    # After candidate publication, EXCHANGE rereads the already-sealed EOED
    # into dead low candidate space while the access lease is still valid.
    # Only then may it restore all twelve symmetric sectors, run sym_init, and
    # carry the validated bytes into the dead tail after every live resumed
    # record/Finished/HEAD span.  No access callback is legal after that
    # complete restore and before FO explicitly repins the access phase.
    eoed_hold = 0x39E8
    eoed_bytes = 26
    resumed_record_end = 0x39A0 + 68
    client_finished_end = 0x39A0 + 58
    head_end = 0x39A0 + 72
    ticket_identity = 0x3B40
    if (
        eoed_hold < resumed_record_end
        or eoed_hold < client_finished_end
        or eoed_hold < head_end
        or eoed_hold + eoed_bytes > ticket_identity
    ):
        raise AssertionError("RAM-held EOED overlaps live symmetric state")
    exchange_eoed_order = ordered_sources(
        route_dir / "post_auth_resume_exchange_post.lst",
        (
            "call resume_exchange_post_card_write_offset",
            "mov bx, resume_card_c + resume_card_c_len",
            "mov cx, resume_early_eoed_len",
            "mov di, 0x0740",
            "call RESUME_EXCHANGE_NE_BUF_READ",
            "cmp byte [0x0740], 0x17",
            "cmp word [0x0741], 0x0303",
            "cmp word [0x0743], 0x1500",
            "mov ax, RESUME_EXCHANGE_SYM_RESTORE_KEY",
            "mov bx, 0x1800",
            "call dx",
            "mov ax, RESUME_EXCHANGE_SYM_TAIL_KEY",
            "mov bx, 0x2e00",
            "call dx",
            "mov si, 0x0740",
            "mov di, exchange_early_eoed_hold",
            "mov cx, resume_early_eoed_len / 2",
            "rep movsw",
        ),
    )
    sym_io_eoed_order = ordered_sources(
        route_dir / "post_auth_resume_sym_io.lst",
        (
            "cmp byte [early_eoed_hold], 0x17",
            "cmp word [early_eoed_hold + 1], 0x0303",
            "cmp word [early_eoed_hold + 3], 0x1500",
            "mov si, early_eoed_hold",
            "mov cx, early_eoed_bytes",
            "call RESUME_SYM_IO_TCP_SEND",
            "mov di, early_eoed_hold",
            "mov cx, early_eoed_bytes / 2",
            "rep stosw",
        ),
    )
    exchange_post_instructions = active_listing_instructions(
        route_dir / "post_auth_resume_exchange_post.lst"
    )
    exchange_hold_values = [
        immediate16(encoded, "BF")
        for _offset, encoded, source in exchange_post_instructions
        if source == "mov di, exchange_early_eoed_hold"
    ]
    sym_io_instructions = active_listing_instructions(
        route_dir / "post_auth_resume_sym_io.lst"
    )
    sym_io_hold_sources = {
        source: [
            immediate16(encoded, opcode)
            for _offset, encoded, actual_source in sym_io_instructions
            if actual_source == source
        ]
        for source, opcode in (
            ("mov si, early_eoed_hold", "BE"),
            ("mov di, early_eoed_hold", "BF"),
        )
    }
    if (
        exchange_hold_values != [eoed_hold]
        or sym_io_hold_sources
        != {
            "mov si, early_eoed_hold": [eoed_hold],
            "mov di, early_eoed_hold": [eoed_hold],
        }
    ):
        raise AssertionError("RAM-held EOED address drifted across workers")
    fo_repin_order = ordered_sources(
        route_dir / "post_auth_resume_fo.lst",
        (
            "mov ax, RESUME_FO_VAULT_ACCESS_KEY",
            "mov bx, RESUME_FO_VAULT_ACCESS_STAGE",
            "call RESUME_FO_LOAD_PHASE",
            "mov ax, RESUME_FO_CONTROLLER_KEY",
            "mov bx, RESUME_FO_CONTROLLER_ENTRY",
            "call RESUME_FO_LOAD_PHASE",
        ),
    )

    class AccessLease:
        def __init__(self) -> None:
            self.memory = bytearray(0x10000)
            self.generation = 0
            self.stage: int | None = None
            self.valid_generation: int | None = None
            self.phase_image = b""
            self.write_offset = 0
            self.read_offset = 0
            self.callbacks = 0
            self.invalidations: list[str] = []
            self.pins: list[str] = []

        def pin(
            self,
            stage: int,
            label: str,
            *,
            phase_image: bytes | None = None,
            phase_write_offset: int | None = None,
            phase_read_offset: int | None = None,
        ) -> None:
            image = access_phase if phase_image is None else phase_image
            write = write_offset if phase_write_offset is None else phase_write_offset
            read = read_offset if phase_read_offset is None else phase_read_offset
            self.memory[stage : stage + len(image)] = image
            self.generation += 1
            self.stage = stage
            self.valid_generation = self.generation
            self.phase_image = image
            self.write_offset = write
            self.read_offset = read
            self.pins.append(f"{self.generation}:{label}@{stage:04x}")

        def write(self, start: int, data: bytes, label: str) -> None:
            end = start + len(data)
            self.memory[start:end] = data
            if self.stage is None or self.valid_generation is None:
                return
            lease_end = self.stage + len(self.phase_image)
            if start < lease_end and self.stage < end:
                self.invalidations.append(
                    f"{self.valid_generation}:{label}@{start:04x}..{end:04x}"
                )
                self.valid_generation = None

        def poison(self, start: int, end: int, label: str) -> None:
            self.write(start, bytes([0xA5]) * (end - start), label)

        def call(self, target: int, label: str) -> None:
            if self.stage is None or self.valid_generation is None:
                raise AssertionError(f"{label} called a stale access lease")
            if target not in {
                self.stage + self.write_offset,
                self.stage + self.read_offset,
            }:
                raise AssertionError(
                    f"{label} targeted a different access generation"
                )
            actual = bytes(
                self.memory[self.stage : self.stage + len(self.phase_image)]
            )
            if actual != self.phase_image:
                raise AssertionError(f"{label} called corrupted access bytes")
            self.callbacks += 1

    def consume(
        lease: AccessLease,
        names: tuple[str, ...],
    ) -> None:
        for name in names:
            for _offset, target in listing_calls[name]:
                lease.call(target, name)

    def consume_slice(
        lease: AccessLease,
        name: str,
        start: int,
        count: int,
        label: str,
    ) -> None:
        calls = listing_calls[name][start : start + count]
        if len(calls) != count:
            raise AssertionError(f"{label} omitted an access callback")
        for _offset, target in calls:
            lease.call(target, label)

    lease = AccessLease()
    lease.poison(
        sha_work_start, sha_work_end, "receipt-sha-before-access"
    )
    lease.pin(
        receipt_stage,
        "receipt-lifecycle-after-sha",
        phase_image=lifecycle_phase,
        phase_write_offset=lifecycle_write_offset,
        phase_read_offset=lifecycle_read_offset,
    )
    consume(lease, ("post_auth_resume_receipt",))
    lease.pin(resumption_stage, "supervisor-resumption")
    # The first RVLW access call is operation 10's receipt read.  Its two
    # later calls belong to operation 9 after FO has restored the overlapping
    # complete symmetric image for authenticated liveness.
    consume_slice(
        lease,
        "post_auth_resume_lifecycle",
        0,
        1,
        "lifecycle-nst",
    )

    lease.write(sym_start, sym_image, "lifecycle-receipt-full-sym")
    lease.write(
        canonical_tail_start,
        canonical_tail,
        "lifecycle-receipt-canonical-tail",
    )
    lease.poison(sha_work_start, sha_work_end, "lifecycle-receipt-sha")
    lease.pin(resumption_stage, "lifecycle-receipt-repin")
    consume(
        lease,
        (
            "post_auth_resume_prepare",
            "post_auth_resume_prepare_age",
            "post_auth_resume_prepare_binder",
            "post_auth_resume_prepare_hash",
        ),
    )

    lease.write(sym_start, sym_image, "prepare-hash-full-sym")
    lease.write(
        canonical_tail_start,
        canonical_tail,
        "prepare-hash-canonical-tail",
    )
    lease.poison(sha_work_start, sha_work_end, "prepare-hash-sha")
    lease.pin(resumption_stage, "prepare-commit-repin")
    consume(
        lease,
        (
            "post_auth_resume_prepare_commit",
            "post_auth_resume_prepare_crypto",
            "post_auth_resume_prepare_sym_binder",
        ),
    )
    for sector in range(sym_sectors):
        start = sym_start + sector * SECTOR
        lease.write(
            start,
            sym_image[sector * SECTOR : (sector + 1) * SECTOR],
            f"prepare-binder-sym-sector-{sector}",
        )
    lease.write(
        canonical_tail_start,
        canonical_tail,
        "prepare-binder-canonical-tail",
    )
    if not lease.invalidations[-1].startswith(
        "4:prepare-binder-sym-sector-10@"
    ):
        raise AssertionError(
            "PREPARE sector loop did not retire access at sector ten"
        )
    lease.pin(resumption_stage, "prepare-restore-repin")
    consume(lease, ("post_auth_resume_prepare_restore",))
    consume(
        lease,
        (
            "post_auth_resume_exchange",
            "post_auth_resume_exchange_tx",
            "post_auth_resume_exchange_crypto",
            "post_auth_resume_exchange_post",
        ),
    )
    lease.write(sym_start, sym_image, "exchange-full-sym-restore")
    lease.write(
        canonical_tail_start,
        canonical_tail,
        "exchange-canonical-tail",
    )
    if bytes(lease.memory[sym_start:sym_end]) != runtime_sym:
        raise AssertionError(
            "post-EXCHANGE memory is not the complete symmetric image"
        )
    lease.pin(resumption_stage, "fo-broker-repin")
    consume(lease, ("post_auth_resume_fo_controller",))
    lease.write(sym_start, sym_image, "fo-full-sym-restore")
    lease.write(canonical_tail_start, canonical_tail, "fo-canonical-tail")
    if bytes(lease.memory[sym_start:sym_end]) != runtime_sym:
        raise AssertionError(
            "pre-liveness memory is not the complete symmetric image"
        )
    lease.pin(resumption_stage, "post-liveness-repin")
    consume_slice(
        lease,
        "post_auth_resume_lifecycle",
        1,
        2,
        "lifecycle-vault",
    )
    lease.write(sym_start, sym_image, "lifecycle-vault-full-sym")
    lease.write(
        canonical_tail_start,
        canonical_tail,
        "lifecycle-vault-canonical-tail",
    )
    lease.poison(sha_work_start, sha_work_end, "lifecycle-vault-sha")
    lease.pin(resumption_stage, "lifecycle-vault-repin")

    expected_callbacks = sum(
        sum(counts.values())
        for _origin, counts in expected_consumers.values()
    )
    if lease.callbacks != expected_callbacks:
        raise AssertionError("lease replay omitted a generated access callback")
    if lease.generation != 8 or lease.valid_generation != 8:
        raise AssertionError("resumption lease generation schedule drifted")

    # Failure after FO/liveness must never enter RVLW operation 11 through
    # the symmetric bytes that replaced the resumption access phase.  Model
    # the dedicated failure repin and both fixed vault reads.  A failed repin
    # is intentionally represented by the persistent-cleanup branch and
    # therefore performs no access callback at all.
    cleanup = AccessLease()
    cleanup.pin(resumption_stage, "fo-broker-repin")
    cleanup.write(sym_start, sym_image, "fo-full-sym-restore")
    cleanup.write(canonical_tail_start, canonical_tail, "fo-canonical-tail")
    cleanup.pin(resumption_stage, "failure-cleanup-repin")
    consume_slice(
        cleanup,
        "post_auth_resume_lifecycle",
        1,
        2,
        "lifecycle-failure-restore",
    )
    if cleanup.callbacks != 2 or cleanup.valid_generation != 2:
        raise AssertionError("failure cleanup used a stale access lease")
    failed_repin_callbacks = 0

    hostile = AccessLease()
    hostile.pin(resumption_stage, "hostile-probe")
    hostile.write(sym_start, sym_image, "hostile-full-sym")
    hostile_rejected = False
    try:
        hostile.call(resumption_read, "hostile-stale-callback")
    except AssertionError:
        hostile_rejected = True
    if not hostile_rejected:
        raise AssertionError("lease model accepted a deliberately stale call")

    return {
        "access_phase_key": f"0x{access_key:04x}",
        "access_image_bytes": len(access_image),
        "access_phase_bytes": len(access_phase),
        "resumption_stage": f"0x{resumption_stage:04x}",
        "receipt_stage": f"0x{receipt_stage:04x}",
        "symmetric_phase_key": f"0x{sym_key:04x}",
        "symmetric_span": f"0x{sym_start:04x}..0x{sym_end:04x}",
        "canonical_tail_phase_key": f"0x{canonical_tail_key:04x}",
        "canonical_tail_span": (
            f"0x{canonical_tail_start:04x}.."
            f"0x{canonical_tail_start + len(canonical_tail):04x}"
        ),
        "canonical_runtime_matches_plain_k14": True,
        "sha_mutable_span": (
            f"0x{sha_work_start:04x}..0x{sha_work_end:04x}"
        ),
        "full_symmetric_sites": {
            name: [f"0x{offset:04x}" for _op, _source, offset in sites]
            for name, sites in full_sym_sites.items()
        },
        "canonical_tail_restore_sites": {
            name: [f"0x{offset:04x}" for _source, offset in sites]
            for name, sites in tail_restore_sites.items()
        },
        "complete_restore_orders": complete_restore_orders,
        "eoed_hold": f"0x{eoed_hold:04x}..0x{eoed_hold + eoed_bytes - 1:04x}",
        "eoed_nonoverlap": {
            "resumed_record_end": f"0x{resumed_record_end:04x}",
            "client_finished_end": f"0x{client_finished_end:04x}",
            "head_end": f"0x{head_end:04x}",
            "ticket_identity": f"0x{ticket_identity:04x}",
        },
        "exchange_eoed_order": exchange_eoed_order,
        "sym_io_eoed_order": sym_io_eoed_order,
        "fo_repin_order": fo_repin_order,
        "consumer_binaries": len(expected_consumers),
        "direct_callbacks_checked": lease.callbacks,
        "lease_generations": lease.generation,
        "lease_pins": lease.pins,
        "overlap_invalidations": lease.invalidations,
        "supervisor_pin_order": supervisor_order,
        "receipt_repin_order": receipt_order,
        "lifecycle_repin_orders": lifecycle_orders,
        "prepare_hash_order": prepare_hash_order,
        "prepare_commit_order": prepare_commit_order,
        "prepare_sym_loop_order": prepare_sym_order,
        "prepare_restore_order": prepare_restore_order,
        "failure_cleanup": {
            "replayed_callbacks": cleanup.callbacks,
            "lease_pins": cleanup.pins,
            "overlap_invalidations": cleanup.invalidations,
            "failed_repin_callbacks": failed_repin_callbacks,
            "failed_repin_uses_persistent_cleanup": True,
        },
        "hostile_stale_callback_rejected": hostile_rejected,
    }


def run_symmetric_tail_restore_hash_gate(
    base: Path,
    final: Path,
    base_manifest: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Execute the shipped post-deadline SHA bridge with real K14 code."""

    base_phases = base_manifest.get("live_phases")
    route_phases = manifest.get("phases")
    if not isinstance(base_phases, list) or not isinstance(route_phases, list):
        raise AssertionError("product manifests lack the combined phase ledger")
    phase_items = [*base_phases, *route_phases]
    phase_by_name = {
        str(item.get("name")): item
        for item in phase_items
        if isinstance(item, dict)
    }
    required_names = (
        "sym",
        "sym_tail_restore",
        "post_auth_resume_lifecycle",
        "vault_access",
    )
    if any(name not in phase_by_name for name in required_names):
        raise AssertionError("symmetric tail hash gate lacks a required phase")

    core = (final / "SEED.SYS").read_bytes()
    phase_images: dict[int, bytes] = {}
    phase_keys: dict[str, int] = {}
    for name, item in phase_by_name.items():
        start = int(item["start_sector"])
        sectors = int(item["sectors"])
        key = parse_hex(item.get("key"), f"{name} phase key")
        if key != phase_key(start, sectors):
            raise AssertionError(f"{name} phase key/geometry diverged")
        image = core[start * SECTOR : (start + sectors) * SECTOR]
        if len(image) != sectors * SECTOR:
            raise AssertionError(f"{name} phase escaped the combined core")
        phase_images[key] = image
        phase_keys[name] = key

    tail = phase_images[phase_keys["sym_tail_restore"]]
    canonical = (base / "sym_k14_runtime_canonical.bin").read_bytes()
    tail_artifact = (base / "sym_k14_runtime_tail.bin").read_bytes()
    product_sym = phase_images[phase_keys["sym"]]
    runtime_sym = product_sym[:0x1600] + tail
    memory_lifetimes = base_manifest.get("memory_lifetimes")
    product_tail = (
        memory_lifetimes.get("product_symmetric_tail")
        if isinstance(memory_lifetimes, dict)
        else None
    )
    tail_binding = (
        product_tail.get("runtime_tail_phase")
        if isinstance(product_tail, dict)
        else None
    )
    if (
        len(tail) != SECTOR
        or tail_artifact != tail
        or parse_hex(
            phase_by_name["sym_tail_restore"].get("destination"),
            "symmetric tail destination",
        )
        != 0x2E00
        or not isinstance(tail_binding, dict)
        or tail_binding.get("name") != "sym_tail_restore"
        or parse_hex(tail_binding.get("key"), "tail binding key")
        != phase_keys["sym_tail_restore"]
        or parse_hex(
            tail_binding.get("destination"), "tail binding destination"
        )
        != 0x2E00
        or tail_binding.get("range") != "0x2e00..0x3000"
        or tail_binding.get("bytes") != len(tail)
        or tail_binding.get("sha256") != sha256(tail)
        or tail_binding.get("reuses_former_relocation_pad") is not True
        or tail_binding.get("required_after_post_deadline_sym_reload")
        is not True
        or runtime_sym != canonical
    ):
        raise AssertionError("tail restore does not reconstruct canonical K14")

    ticket = bytes(((index * 73 + 19) & 0xFF) for index in range(268))
    receipt = bytearray(46)
    receipt[:4] = b"NTR1"
    receipt[4:8] = bytes(value ^ 0xFF for value in receipt[:4])
    receipt[8:14] = bytes.fromhex("34127856bc9a")
    expected = hashlib.sha256(receipt[:4] + receipt[8:14] + ticket).digest()
    receipt[14:46] = expected
    bridge = (final / "post_auth_resume_lifecycle_receipt_hash.bin").read_bytes()
    if not bridge or len(bridge) > 0x110:
        raise AssertionError("receipt hash bridge escaped its fixed slot")

    sentinel = 0x0400
    tail_key = phase_keys["sym_tail_restore"]
    expected_loads = [
        (phase_keys["sym"], 0x1800),
        (tail_key, 0x2E00),
        (phase_keys["post_auth_resume_lifecycle"], 0x3000),
        (phase_keys["vault_access"], 0x2C00),
    ]

    def execute(*, suppress_tail: bool) -> tuple[bytes, list[tuple[int, int]]]:
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, 0x10000)
        uc.mem_write(0x3400, bridge)
        uc.mem_write(0x0D00, bytes(receipt))
        uc.mem_write(0x38B0, ticket[:32])
        uc.mem_write(0x3B40, ticket[32:224])
        uc.mem_write(0x3C00, ticket[224:])
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            uc.reg_write(register, 0)
        uc.reg_write(UC_X86_REG_SP, 0x3EFE)
        uc.mem_write(0x3EFE, struct.pack("<H", sentinel))
        uc.reg_write(UC_X86_REG_EFLAGS, 2)
        loads: list[tuple[int, int]] = []
        returned = False

        def hook(
            machine: Uc,
            address: int,
            _size: int,
            _user: object,
        ) -> None:
            nonlocal returned
            if address == sentinel:
                returned = True
                machine.emu_stop()
                return
            if address != RES_LOAD_PHASE:
                return
            key = machine.reg_read(UC_X86_REG_AX) & 0xFFFF
            destination = machine.reg_read(UC_X86_REG_BX) & 0xFFFF
            loads.append((key, destination))
            image = phase_images.get(key)
            if image is None:
                raise AssertionError(f"hash bridge loaded unknown phase {key:#x}")
            if not (suppress_tail and key == tail_key):
                machine.mem_write(destination, image)
            set_carry(machine, False)
            return_from_near_call(machine)

        handle = uc.hook_add(UC_HOOK_CODE, hook)
        try:
            uc.emu_start(0x3400, 0, count=5_000_000)
        finally:
            uc.hook_del(handle)
        if not returned or loads != expected_loads:
            raise AssertionError(
                f"receipt hash restore sequence drifted: {loads!r}"
            )
        return bytes(uc.mem_read(0x3920, 32)), loads

    restored_digest, loads = execute(suppress_tail=False)
    unpatched_digest, _ = execute(suppress_tail=True)
    if restored_digest != expected or unpatched_digest == expected:
        raise AssertionError("real K14 tail-restore SHA regression failed")
    return {
        "runtime_image_byte_identical_to_canonical": True,
        "tail_artifact_and_manifest_bound": True,
        "real_k14_receipt_digest": restored_digest.hex(),
        "host_sha256": expected.hex(),
        "missing_restore_rejected": True,
        "phase_loads": [
            {"key": f"0x{key:04x}", "destination": f"0x{destination:04x}"}
            for key, destination in loads
        ],
        "vm_or_network_launched": False,
    }


def phase_key(start: int, count: int) -> int:
    if not 1 <= count <= 0xFF or not 0 <= start <= 0xFF:
        raise AssertionError("phase geometry is not 8-bit encodable")
    return (count << 8) | start


def check_phase_ledger(
    manifest: dict[str, Any], core: bytes
) -> list[dict[str, Any]]:
    phases = manifest.get("phases")
    if not isinstance(phases, list) or not phases:
        raise AssertionError("product manifest lacks its phase ledger")
    base = manifest.get("base")
    if not isinstance(base, dict):
        raise AssertionError("product manifest lacks base metadata")
    base_core = Path(str(base.get("core"))).read_bytes()
    cursor = len(base_core) // SECTOR
    for phase in phases:
        if not isinstance(phase, dict):
            raise AssertionError("product phase ledger entry is not an object")
        name = phase.get("name")
        start = phase.get("start_sector")
        count = phase.get("sectors")
        if (
            not isinstance(name, str)
            or not isinstance(start, int)
            or not isinstance(count, int)
        ):
            raise AssertionError("product phase ledger entry is malformed")
        if start != cursor:
            raise AssertionError(f"{name} breaks phase contiguity")
        if parse_hex(phase.get("key"), f"{name} key") != phase_key(
            start, count
        ):
            raise AssertionError(f"{name} key does not bind its geometry")
        begin = start * SECTOR
        end = begin + count * SECTOR
        if end > len(core):
            raise AssertionError(f"{name} extends beyond SEED.SYS")
        cursor += count
    if cursor * SECTOR != len(core):
        raise AssertionError("product phase ledger does not cover SEED.SYS")
    return phases


def calls_to_address(image: bytes, origin: int, target: int) -> list[int]:
    """Return every byte offset encoding a near CALL to the fixed target.

    The controllers are flat executable images without relocation after
    assembly. Scanning every E8 byte is intentionally conservative.
    """

    calls: list[int] = []
    for offset in range(len(image) - 2):
        if image[offset] != 0xE8:
            continue
        displacement = struct.unpack_from("<h", image, offset + 1)[0]
        destination = (origin + offset + 3 + displacement) & 0xFFFF
        if destination == target:
            calls.append(offset)
    return calls


def check_integrated_trace_absent(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Reject the retired environment-selectable product trace surface."""

    sources = (
        BASE_BUILDER,
        POST_BUILDER,
        POC / "live_k15_controllers.asm",
        POC / "post_auth_live_controller.asm",
        POC / "post_auth_resumption_dispatcher.asm",
        POC / "post_auth_resume_prepare_worker.asm",
        POC / "post_auth_resume_liveness_worker.asm",
        POC / "post_auth_resume_fo_worker.asm",
        ROOT
        / "targets/ibm_pc_5150/boot/tls13/k14_product_publication.asm",
    )
    retired_tokens = (
        "SEED_K14_" + "PRODUCT_TRACE",
        "LIVE_K15_" + "PRODUCT_TRACE",
        "PRODUCT_PUBLICATION_" + "DIAGNOSTIC",
        "POST_AUTH_LIVE_" + "DIAGNOSTIC",
        "RESUME_DISPATCH_" + "DIAGNOSTIC",
        "RESUME_PREPARE_" + "DIAGNOSTIC",
        "RESUME_FO_" + "DIAGNOSTIC",
        "RESUME_FO_PRE_" + "DIAGNOSTIC",
        "RESUME_LIVENESS_" + "DIAGNOSTIC",
    )
    hits: dict[str, list[str]] = {}
    for source in sources:
        text = source.read_text(encoding="utf-8")
        present = [token for token in retired_tokens if token in text]
        if present:
            hits[str(source.relative_to(ROOT))] = present
    if hits:
        raise AssertionError(
            f"retired integrated product trace surface remains: {hits!r}"
        )
    if "diagnostic_state" in manifest:
        raise AssertionError(
            "authoritative manifest still advertises a product trace mode"
        )
    return {
        "environment_selected_trace": False,
        "retired_trace_tokens_in_product_sources": 0,
        "manifest_diagnostic_mode": False,
        "checker_only_timing_diagnostic": "LIVE_K15_TIMING_DIAGNOSTIC",
    }


def run(command: list[str]) -> None:
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
    )


def parse_nasm_defines(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for raw in path.read_text(encoding="ascii").splitlines():
        words = raw.split()
        if len(words) == 3 and words[0] == "%define":
            result[words[1]] = int(words[2], 0)
    return result


def call_escrow(
    uc: Uc,
    entry: int,
    *,
    ax: int,
    dx: int,
) -> tuple[bool, tuple[tuple[int, int, int], ...]]:
    inputs = (
        (UC_X86_REG_AX, ax),
        (UC_X86_REG_BX, 0xB257),
        (UC_X86_REG_CX, 0xC35B),
        (UC_X86_REG_DX, dx),
        (UC_X86_REG_SI, 0x0861),
        (UC_X86_REG_DI, 0x0967),
        (UC_X86_REG_BP, 0xB56D),
        (UC_X86_REG_DS, 0),
        (UC_X86_REG_ES, 0),
        (UC_X86_REG_SS, 0),
        (UC_X86_REG_SP, STACK_TOP - 2),
        (UC_X86_REG_EFLAGS, 2 | (1 << 10)),
    )
    uc.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))
    for register, value in inputs:
        uc.reg_write(register, value)
    returned = False
    writes: list[tuple[int, int, int]] = []

    def stop(machine: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        machine.emu_stop()

    def track(
        _machine: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        writes.append((address, size, value))

    stop_hook = uc.hook_add(
        UC_HOOK_CODE, stop, begin=RETURN, end=RETURN
    )
    write_hook = uc.hook_add(UC_HOOK_MEM_WRITE, track)
    try:
        uc.emu_start(entry, 0, count=2_000_000)
    finally:
        uc.hook_del(stop_hook)
        uc.hook_del(write_hook)
    if not returned:
        raise AssertionError(f"config escrow call {entry:#x} did not return")
    expected = dict(inputs)
    for register, value in inputs:
        if register in (UC_X86_REG_SP, UC_X86_REG_EFLAGS):
            continue
        actual = uc.reg_read(register) & 0xFFFF
        if actual != (value & 0xFFFF):
            raise AssertionError(
                f"config escrow did not preserve register {register}: "
                f"{actual:#x} != {value:#x}"
            )
    if (uc.reg_read(UC_X86_REG_SP) & 0xFFFF) != STACK_TOP:
        raise AssertionError("config escrow did not balance its caller stack")
    flags = uc.reg_read(UC_X86_REG_EFLAGS)
    if flags & (1 << 10):
        raise AssertionError("config escrow returned with DF set")
    return bool(flags & 1), tuple(writes)


def new_escrow_machine(
    image: bytes,
    backend: str,
) -> tuple[Uc, int]:
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0xC0000)
    uc.mem_write(CONFIG_ESCROW_ORIGIN, image)
    port = MDA_CRT_PORT if backend == "MDA" else CGA_CRT_PORT
    base = CONFIG_ESCROW_MDA if backend == "MDA" else CONFIG_ESCROW_CGA
    uc.mem_write(BDA_CRT_PORT, struct.pack("<H", port))
    uc.mem_write(base, b"\xD6" * CONFIG_ESCROW_BYTES)
    for register in (
        UC_X86_REG_CS,
        UC_X86_REG_DS,
        UC_X86_REG_ES,
        UC_X86_REG_SS,
    ):
        uc.reg_write(register, 0)
    return uc, base


def install_config_state(uc: Uc, salt: int) -> tuple[bytes, bytes]:
    prefix = bytes(
        ((index * 61 + salt * 37 + 1) & 0xFF) or 0xA5
        for index in range(CONFIG_CACHE - CONFIG_SENSITIVE_START)
    )
    cache = bytes(
        ((index * 73 + salt * 29 + 1) & 0xFF)
        for index in range(CONFIG_CACHE_BYTES)
    )
    if not all(prefix) or not any(cache):
        raise AssertionError("config fixture unexpectedly became all zero")
    ui = bytes(((salt * 17 + index * 31 + 3) & 0x7F) for index in range(5))
    uc.mem_write(CONFIG_SENSITIVE_START, prefix)
    uc.mem_write(CONFIG_CACHE, cache)
    for address, value in zip(CONFIG_UI, ui, strict=True):
        uc.mem_write(address, bytes([value]))
    return cache, ui


def read_config_state(uc: Uc) -> tuple[bytes, bytes]:
    cache = bytes(uc.mem_read(CONFIG_CACHE, CONFIG_CACHE_BYTES))
    ui = bytes(uc.mem_read(address, 1)[0] for address in CONFIG_UI)
    return cache, ui


def run_config_escrow_gate(base: Path) -> dict[str, Any]:
    image = (base / "product_config_escrow.bin").read_bytes()
    if not 0 < len(image) <= 2 * SECTOR:
        raise AssertionError("config escrow binary escaped its phase")
    save, restore = struct.unpack_from("<2H", image)
    if save != CONFIG_ESCROW_ORIGIN + 4 or not (
        CONFIG_ESCROW_ORIGIN < restore < CONFIG_ESCROW_ORIGIN + len(image)
    ):
        raise AssertionError("config escrow entry table drifted")

    success_cases = 0
    status_last_cases = 0
    source_zeroed_before_status_cases = 0
    for backend in ("CGA", "MDA"):
        for mode in (0, 1):
            uc, physical = new_escrow_machine(image, backend)
            expected = install_config_state(uc, 0x20 + mode)
            carry, writes = call_escrow(
                uc, save, ax=mode, dx=0x4D31 + mode
            )
            if carry:
                raise AssertionError(
                    f"{backend} mode {mode} config save failed"
                )
            object_writes = [
                item
                for item in writes
                if physical <= item[0] < physical + CONFIG_ESCROW_BYTES
            ]
            if (
                len(object_writes) < 2
                or object_writes[-2][0] != physical + 0x19E
                or object_writes[-1][0] != physical + 0x19F
            ):
                raise AssertionError("config escrow status was not written last")
            status_last_cases += 1
            sensitive_write_indexes = [
                index
                for index, (address, size, _value) in enumerate(writes)
                if address < CONFIG_SENSITIVE_END
                and address + size > CONFIG_SENSITIVE_START
            ]
            status_index = max(
                index
                for index, (address, _size, _value) in enumerate(writes)
                if address == physical + 0x19F
            )
            if (
                not sensitive_write_indexes
                or max(sensitive_write_indexes) >= status_index
                or bytes(
                    uc.mem_read(
                        CONFIG_SENSITIVE_START,
                        CONFIG_SENSITIVE_END - CONFIG_SENSITIVE_START,
                    )
                )
                != bytes(CONFIG_SENSITIVE_END - CONFIG_SENSITIVE_START)
            ):
                raise AssertionError(
                    "config source/cache was not zero before status publication"
                )
            source_zeroed_before_status_cases += 1
            uc.mem_write(CONFIG_CACHE, b"\xE1" * CONFIG_CACHE_BYTES)
            for address in CONFIG_UI:
                uc.mem_write(address, b"\xE2")
            carry, _writes = call_escrow(
                uc, restore, ax=0xA153, dx=0xD45F
            )
            if carry or read_config_state(uc) != expected:
                raise AssertionError(
                    f"{backend} mode {mode} config restore failed"
                )
            if bytes(uc.mem_read(physical, CONFIG_ESCROW_BYTES)) != bytes(
                CONFIG_ESCROW_BYTES
            ):
                raise AssertionError("successful restore did not scrub escrow")
            success_cases += 1

    tamper_offsets = {
        "cache": 0x000,
        "ui_cursor_row": 0x100,
        "ui_cursor_col": 0x101,
        "ui_prompt_row": 0x102,
        "ui_loop_pending": 0x103,
        "ui_loop_count": 0x104,
        "magic": 0x108,
        "magic_inverse": 0x10C,
        "generation": 0x110,
        "generation_inverse": 0x112,
        "crc32": 0x114,
        "crc32c": 0x118,
        "inverse_status": 0x19E,
        "status": 0x19F,
    }
    rejected = 0
    for backend in ("CGA", "MDA"):
        for index, (label, offset) in enumerate(tamper_offsets.items()):
            uc, physical = new_escrow_machine(image, backend)
            install_config_state(uc, 0x50 + index)
            carry, _writes = call_escrow(
                uc, save, ax=index & 1, dx=0x6100 + index
            )
            if carry:
                raise AssertionError(f"{backend} {label} setup save failed")
            original = bytes(uc.mem_read(physical + offset, 1))[0]
            uc.mem_write(physical + offset, bytes([original ^ 0x5A]))
            unpublished = (
                b"\xE7" * CONFIG_CACHE_BYTES,
                b"\xE8" * len(CONFIG_UI),
            )
            uc.mem_write(CONFIG_CACHE, unpublished[0])
            for address, value in zip(
                CONFIG_UI, unpublished[1], strict=True
            ):
                uc.mem_write(address, bytes([value]))
            carry, _writes = call_escrow(
                uc, restore, ax=0xA153, dx=0xD45F
            )
            if not carry:
                raise AssertionError(f"{backend} {label} tamper was accepted")
            if read_config_state(uc) != unpublished:
                raise AssertionError(
                    f"{backend} {label} published conventional bytes"
                )
            if bytes(uc.mem_read(physical, CONFIG_ESCROW_BYTES)) != bytes(
                CONFIG_ESCROW_BYTES
            ):
                raise AssertionError(
                    f"{backend} {label} rejection did not scrub escrow"
                )
            rejected += 1
    return {
        "success_cases": success_cases,
        "cold_and_reconnect_nonzero_cache_restored": True,
        "status_last_cases": status_last_cases,
        "source_zeroed_before_status_cases": (
            source_zeroed_before_status_cases
        ),
        "conventional_sensitive_span_zero_after_save": True,
        "tamper_rejections": rejected,
        "tamper_fields": list(tamper_offsets),
        "zero_conventional_publication_on_rejection": True,
        "complete_video_scrub_on_rejection": True,
    }


def run_publication_gate(
    final: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Execute the successful final publication with a hostile resident tail.

    The K14 record path does not initialize the resident application's
    ephemeral TCP/TLS cursor state.  Model the two phase loads and their
    already-independently-gated callbacks, then require publication to turn a
    fully nonzero 0x0fe2..0x0fff tail into the canonical zero handoff before
    READY can become observable.
    """

    publication = manifest.get("publication_abi")
    vault = manifest.get("vault_abi")
    escrow = manifest.get("config_escrow_abi")
    if (
        not isinstance(publication, dict)
        or not isinstance(vault, dict)
        or not isinstance(escrow, dict)
    ):
        raise AssertionError("product manifest lacks publication dependencies")
    source = publication.get("source")
    destination = publication.get("destination")
    cursor = publication.get("application_cursor")
    if (
        not isinstance(source, dict)
        or not isinstance(destination, dict)
        or not isinstance(cursor, dict)
    ):
        raise AssertionError("publication manifest lacks state geometry")

    entry = parse_hex(publication.get("entry"), "publication entry")
    ready = parse_hex(destination.get("ready"), "publication READY")
    stack_abi = publication_return_stack_abi(publication)
    cursor_start = parse_hex(cursor.get("start"), "application cursor start")
    cursor_end = parse_hex(cursor.get("end"), "application cursor end")
    if (
        cursor_start != 0x0FE2
        or cursor_end != 0x1000
        or cursor.get("ephemeral_tcp_and_tls_tail_zeroed") is not True
        or cursor.get("zeroed_before_ready") is not True
    ):
        raise AssertionError("publication application-cursor contract drifted")

    image = (final / "post_auth_product_publication.bin").read_bytes()
    if (
        not image
        or len(image) > SECTOR
        or len(image) != publication.get("bytes")
        or sha256(image) != publication.get("sha256")
    ):
        raise AssertionError("publication executable is not manifest-bound")

    fields = (
        ("client_key", 32),
        ("server_key", 32),
        ("client_iv", 12),
        ("server_iv", 12),
        ("client_sequence", 8),
        ("server_sequence", 8),
    )
    sources = {
        name: parse_hex(source.get(name), f"publication {name} source")
        for name, _size in fields
    }
    destinations = {
        name: parse_hex(
            destination.get(name), f"publication {name} destination"
        )
        for name, _size in fields
    }
    expected_fields = {
        name: bytes(
            ((index * 73 + field_index * 41 + 1) & 0xFF) or 0xA5
            for index in range(size)
        )
        for field_index, (name, size) in enumerate(fields)
    }

    config_key = parse_hex(
        escrow.get("phase_key"), "config-escrow phase key"
    )
    config_stage = parse_hex(escrow.get("stage"), "config-escrow stage")
    config_restore = parse_hex(
        escrow.get("restore"), "config-escrow restore callback"
    )
    lifecycle_key = parse_hex(
        vault.get("lifecycle_phase_key"), "vault lifecycle phase key"
    )
    lifecycle_stage = parse_hex(
        vault.get("lifecycle_stage"), "vault lifecycle stage"
    )
    vault_zeroize = parse_hex(
        vault.get("zeroize"), "vault zeroize callback"
    )

    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x10000)
    uc.mem_write(entry, image)
    for start, end in (
        (0x0700, 0x0900),
        (0x0D00, cursor_start),
        (0x1800, 0x3600),
        (0x3668, CONFIG_CACHE),
    ):
        uc.mem_write(start, b"\xA5" * (end - start))
    for name, _size in fields:
        uc.mem_write(sources[name], expected_fields[name])
        uc.mem_write(
            destinations[name], b"\xC7" * len(expected_fields[name])
        )

    expected_cache = bytes(
        ((index * 67 + 19) & 0xFF) for index in range(CONFIG_CACHE_BYTES)
    )
    expected_ui = bytes((0x12, 0x23, 0x34, 0x45, 0x56))
    uc.mem_write(CONFIG_CACHE, b"\xD8" * CONFIG_CACHE_BYTES)
    for address in CONFIG_UI:
        uc.mem_write(address, b"\xD9")

    poison = bytes(
        ((index * 29 + 0x51) & 0xFF) or 0xE3
        for index in range(cursor_end - cursor_start)
    )
    if not all(poison):
        raise AssertionError("publication cursor poison contains a zero byte")
    uc.mem_write(cursor_start, poison)

    connection_start = 0x0600
    connection_end = 0x0700
    connection_before = bytes(
        ((index * 43 + 7) & 0xFF) for index in range(
            connection_end - connection_start
        )
    )
    uc.mem_write(connection_start, connection_before)
    uc.mem_write(ready, b"\x7F")
    root_sp = seed_publication_root_frame(uc, stack_abi)
    connection_expected = bytearray(
        uc.mem_read(connection_start, connection_end - connection_start)
    )
    connection_expected[ready - connection_start] = 1

    hostile_active_sp = root_sp - 0x0080
    uc.mem_write(hostile_active_sp, struct.pack("<H", RETURN))
    for register in (
        UC_X86_REG_CS,
        UC_X86_REG_DS,
        UC_X86_REG_ES,
        UC_X86_REG_SS,
    ):
        uc.reg_write(register, 0)
    uc.reg_write(UC_X86_REG_SP, hostile_active_sp)
    uc.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))

    loads: list[tuple[int, int]] = []
    milestones: list[str] = []
    writes: list[tuple[int, int, int]] = []
    ready_observed = False
    returned = False
    hostile_returned = False

    def hook(
        machine: Uc,
        address: int,
        _size: int,
        _user: object,
    ) -> None:
        nonlocal hostile_returned, returned
        if address == stack_abi["expected_return"]:
            returned = True
            machine.emu_stop()
            return
        if address == RETURN:
            hostile_returned = True
            machine.emu_stop()
            return
        if address == RES_LOAD_PHASE:
            phase = (
                machine.reg_read(UC_X86_REG_AX) & 0xFFFF,
                machine.reg_read(UC_X86_REG_BX) & 0xFFFF,
            )
            loads.append(phase)
            milestones.append(
                "load-config"
                if phase == (config_key, config_stage)
                else "load-lifecycle"
                if phase == (lifecycle_key, lifecycle_stage)
                else "load-unexpected"
            )
            machine.reg_write(UC_X86_REG_DX, 0xD15C)
            set_carry(machine, False)
            return_from_near_call(machine)
            return
        if address == config_restore:
            if (
                loads != [(config_key, config_stage)]
                or bytes(machine.mem_read(ready, 1)) != b"\0"
            ):
                raise AssertionError(
                    "config restore ran outside its loaded pre-READY phase"
                )
            machine.mem_write(CONFIG_CACHE, expected_cache)
            for ui_address, value in zip(
                CONFIG_UI, expected_ui, strict=True
            ):
                machine.mem_write(ui_address, bytes([value]))
            milestones.append("restore-config")
            set_carry(machine, False)
            return_from_near_call(machine)
            return
        if address == vault_zeroize:
            if (
                loads
                != [
                    (config_key, config_stage),
                    (lifecycle_key, lifecycle_stage),
                ]
                or milestones[-1] != "load-lifecycle"
                or bytes(machine.mem_read(ready, 1)) != b"\0"
            ):
                raise AssertionError(
                    "vault zeroize ran outside its loaded pre-READY phase"
                )
            milestones.append("zeroize-vault")
            set_carry(machine, False)
            return_from_near_call(machine)

    def track_write(
        machine: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        nonlocal ready_observed
        writes.append((address, size, value))
        if address == ready and size == 1 and (value & 0xFF) == 1:
            if milestones != [
                "load-config",
                "restore-config",
                "load-lifecycle",
                "zeroize-vault",
            ]:
                raise AssertionError("READY preceded a publication dependency")
            if any(
                machine.mem_read(cursor_start, cursor_end - cursor_start)
            ):
                raise AssertionError(
                    "READY preceded application-cursor zeroization"
                )
            for name, _size in fields:
                if (
                    bytes(
                        machine.mem_read(
                            destinations[name], len(expected_fields[name])
                        )
                    )
                    != expected_fields[name]
                ):
                    raise AssertionError(
                        f"READY preceded {name} publication"
                    )
            ready_observed = True

    code_hook = uc.hook_add(UC_HOOK_CODE, hook)
    write_hook = uc.hook_add(UC_HOOK_MEM_WRITE, track_write)
    try:
        uc.emu_start(entry, 0, count=2_000_000)
    finally:
        uc.hook_del(code_hook)
        uc.hook_del(write_hook)

    if hostile_returned:
        raise AssertionError(
            "successful publication trusted its hostile active stack"
        )
    if not returned or not ready_observed:
        raise AssertionError("successful publication did not return READY")
    if (
        (uc.reg_read(UC_X86_REG_AX) & 0xFFFF) != 1
        or uc.reg_read(UC_X86_REG_EFLAGS) & 1
        or (uc.reg_read(UC_X86_REG_SP) & 0xFFFF) != root_sp + 2
        or uc.reg_read(UC_X86_REG_EFLAGS) & (1 << 10)
    ):
        raise AssertionError("successful publication return ABI drifted")
    if loads != [
        (config_key, config_stage),
        (lifecycle_key, lifecycle_stage),
    ]:
        raise AssertionError("publication phase-load order drifted")
    if not writes or writes[-1] != (ready, 1, 1):
        raise AssertionError("READY was not the final emulated memory write")
    if bytes(uc.mem_read(cursor_start, cursor_end - cursor_start)) != bytes(
        cursor_end - cursor_start
    ):
        raise AssertionError("publication left poisoned cursor bytes live")
    if bytes(
        uc.mem_read(connection_start, connection_end - connection_start)
    ) != bytes(connection_expected):
        raise AssertionError("publication corrupted live connection state")
    if read_config_state(uc) != (expected_cache, expected_ui):
        raise AssertionError("publication did not retain restored config state")
    for name, _size in fields:
        if (
            bytes(
                uc.mem_read(
                    destinations[name], len(expected_fields[name])
                )
            )
            != expected_fields[name]
        ):
            raise AssertionError(f"publication corrupted {name}")
        if bytes(
            uc.mem_read(sources[name], len(expected_fields[name]))
        ) != bytes(len(expected_fields[name])):
            raise AssertionError(f"publication retained {name} source")

    if bytes(
        uc.mem_read(
            stack_abi["snapshot_start"],
            stack_abi["snapshot_end"] - stack_abi["snapshot_start"],
        )
    ) != bytes(stack_abi["snapshot_end"] - stack_abi["snapshot_start"]):
        raise AssertionError(
            "publication retained its consumed root-frame snapshot"
        )

    tamper_fields = (
        ("snapshot_sp_low", stack_abi["snapshot_sp"]),
        ("snapshot_sp_high", stack_abi["snapshot_sp"] + 1),
        ("snapshot_sp_inverse_low", stack_abi["snapshot_sp_inverse"]),
        (
            "snapshot_sp_inverse_high",
            stack_abi["snapshot_sp_inverse"] + 1,
        ),
        ("snapshot_status_inverse", stack_abi["snapshot_status_word"]),
        ("snapshot_status", stack_abi["snapshot_status_word"] + 1),
        ("handoff_ram_top_low", stack_abi["handoff_ram_top"]),
        ("handoff_ram_top_high", stack_abi["handoff_ram_top"] + 1),
        ("root_return_low", root_sp),
        ("root_return_high", root_sp + 1),
    )
    rejected = 0
    for label, tamper_address in tamper_fields:
        reject_uc = Uc(UC_ARCH_X86, UC_MODE_16)
        reject_uc.mem_map(0, 0x10000)
        reject_uc.mem_write(entry, image)
        rejected_root_sp = seed_publication_root_frame(
            reject_uc, stack_abi
        )
        if rejected_root_sp != root_sp:
            raise AssertionError(
                "publication tamper matrix changed root-stack geometry"
            )
        original = bytes(reject_uc.mem_read(tamper_address, 1))[0]
        reject_uc.mem_write(tamper_address, bytes([original ^ 0x01]))

        reject_active_sp = root_sp - 0x0100
        stack_guard_start = reject_active_sp - 0x20
        stack_guard_len = 0x40
        stack_guard = bytes(
            ((index * 37 + 0x55) & 0xFF)
            for index in range(stack_guard_len)
        )
        reject_uc.mem_write(stack_guard_start, stack_guard)
        reject_uc.mem_write(ready, b"\x7F")
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            reject_uc.reg_write(register, 0)
        reject_uc.reg_write(UC_X86_REG_SP, reject_active_sp)
        reject_uc.reg_write(
            UC_X86_REG_EFLAGS, 2 | (1 << 9) | (1 << 10)
        )

        emergency_reached = False
        unexpected_callback = False
        stack_writes: list[tuple[int, int]] = []

        def reject_hook(
            machine: Uc,
            address: int,
            _size: int,
            _user: object,
        ) -> None:
            nonlocal emergency_reached, unexpected_callback
            if address == stack_abi["emergency_reset"]:
                emergency_reached = True
                machine.emu_stop()
                return
            if address in (
                RES_LOAD_PHASE,
                config_restore,
                vault_zeroize,
                stack_abi["expected_return"],
                RETURN,
            ):
                unexpected_callback = True
                machine.emu_stop()

        def reject_write_hook(
            _machine: Uc,
            _access: int,
            address: int,
            size: int,
            _value: int,
            _user: object,
        ) -> None:
            if (
                address < stack_guard_start + stack_guard_len
                and address + size > stack_guard_start
            ):
                stack_writes.append((address, size))

        reject_code_hook = reject_uc.hook_add(
            UC_HOOK_CODE, reject_hook
        )
        reject_mem_hook = reject_uc.hook_add(
            UC_HOOK_MEM_WRITE, reject_write_hook
        )
        try:
            reject_uc.emu_start(entry, 0, count=1_000)
        finally:
            reject_uc.hook_del(reject_code_hook)
            reject_uc.hook_del(reject_mem_hook)

        reject_flags = reject_uc.reg_read(UC_X86_REG_EFLAGS)
        if (
            not emergency_reached
            or unexpected_callback
            or (reject_uc.reg_read(UC_X86_REG_SP) & 0xFFFF)
            != reject_active_sp
            or stack_writes
            or bytes(
                reject_uc.mem_read(stack_guard_start, stack_guard_len)
            )
            != stack_guard
            or bytes(reject_uc.mem_read(ready, 1)) != b"\0"
            or reject_flags & (1 << 9)
            or reject_flags & (1 << 10)
        ):
            raise AssertionError(
                f"publication {label} tamper did not reach the stackless "
                "emergency reset"
            )
        rejected += 1

    return {
        "successful_execution_cases": 1,
        "modeled_phase_loads": [
            {
                "key": f"0x{phase_key_value:04x}",
                "stage": f"0x{stage:04x}",
            }
            for phase_key_value, stage in loads
        ],
        "poisoned_application_cursor": (
            f"0x{cursor_start:04x}..0x{cursor_end - 1:04x}"
        ),
        "application_cursor_zero_before_ready": True,
        "live_connection_state_preserved": True,
        "keys_ivs_and_sequences_copied": True,
        "source_state_retired": True,
        "config_restored_before_vault_zeroize": True,
        "ready_final_memory_write": True,
        "return_abi": "CF=0, AX=1",
        "root_frame": {
            "hostile_active_sp": f"0x{hostile_active_sp:04x}",
            "validated_sp": f"0x{root_sp:04x}",
            "publication_return": (
                f"0x{stack_abi['expected_return']:04x}"
            ),
            "valid_snapshot_adopted": True,
            "consumed_snapshot_retired": True,
            "tamper_rejections": rejected,
            "tamper_fields": [label for label, _address in tamper_fields],
            "all_rejections_jump_to_emergency_reset": (
                f"0x{stack_abi['emergency_reset']:04x}"
            ),
            "rejection_uses_no_active_stack": True,
        },
    }


def run_publication_return_stack_gate(final: Path) -> dict[str, Any]:
    """Prove the terminal receipt edge preserves the resident root frame."""

    post_origin = 0x0900
    worker_entry = 0x3400

    post_listing = final / "post_auth_receipt_post_controller.lst"
    post_instructions = active_listing_instructions(post_listing)
    commit_calls = [
        (offset, encoded)
        for offset, encoded, source in post_instructions
        if source == "call post_check_commit"
    ]
    if len(commit_calls) != 1:
        raise AssertionError(
            "authoritative post controller lost its sole commit call"
        )
    commit_call_offset, commit_call_encoded = commit_calls[0]
    if re.fullmatch(r"[0-9A-Fa-f]{6}", commit_call_encoded) is None:
        raise AssertionError("post-check commit call encoding drifted")
    actual_stale_return = (
        post_origin
        + commit_call_offset
        + len(bytes.fromhex(commit_call_encoded))
    )
    if not post_origin < actual_stale_return < 0x0D00:
        raise AssertionError(
            "authoritative post-check return escaped its retired controller: "
            f"{actual_stale_return:#06x}"
        )
    stale_return = actual_stale_return

    receipt_entry = (
        post_origin
        + listing_label_offset(post_listing, ".resume_receipt_edge")
    )
    post_image = (
        final / "post_auth_receipt_post_controller.bin"
    ).read_bytes()
    publication_image = (
        final / "post_auth_product_publication.bin"
    ).read_bytes()
    manifest = load_json(final / "manifest.json")
    publication = manifest.get("publication_abi")
    escrow = manifest.get("config_escrow_abi")
    vault = manifest.get("vault_abi")
    if (
        not isinstance(publication, dict)
        or not isinstance(escrow, dict)
        or not isinstance(vault, dict)
    ):
        raise AssertionError(
            "authoritative manifest lacks publication dependencies"
        )
    destination = publication.get("destination")
    if not isinstance(destination, dict):
        raise AssertionError(
            "authoritative publication lacks destination ABI"
        )
    publication_entry = parse_hex(
        publication.get("entry"), "authoritative publication entry"
    )
    stack_abi = publication_return_stack_abi(publication)
    resident_return = stack_abi["expected_return"]
    root_sp = STACK_TOP - stack_abi["expected_sp_delta"]
    initial_sp = root_sp - 2
    config_restore = parse_hex(
        escrow.get("restore"), "authoritative config restore"
    )
    vault_zeroize = parse_hex(
        vault.get("zeroize"), "authoritative vault zeroize"
    )
    ready = parse_hex(
        destination.get("ready"), "authoritative publication READY"
    )

    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0xC0000)
    uc.mem_write(post_origin, post_image)
    seed_publication_root_frame(uc, stack_abi)
    uc.mem_write(initial_sp, struct.pack("<H", stale_return))
    for register in (
        UC_X86_REG_CS,
        UC_X86_REG_DS,
        UC_X86_REG_ES,
        UC_X86_REG_SS,
    ):
        uc.reg_write(register, 0)
    uc.reg_write(UC_X86_REG_SP, initial_sp)
    uc.reg_write(UC_X86_REG_EFLAGS, 2)

    reached_worker = False

    def receipt_hook(
        machine: Uc,
        address: int,
        _size: int,
        _user: object,
    ) -> None:
        nonlocal reached_worker
        if address == RES_LOAD_PHASE:
            set_carry(machine, False)
            return_from_near_call(machine)
            return
        if address == worker_entry:
            reached_worker = True
            machine.emu_stop()

    hook = uc.hook_add(UC_HOOK_CODE, receipt_hook)
    try:
        uc.emu_start(receipt_entry, 0, count=100_000)
    finally:
        uc.hook_del(hook)
    if not reached_worker:
        raise AssertionError("terminal receipt edge did not reach NTR1")
    if (
        (uc.reg_read(UC_X86_REG_SP) & 0xFFFF) != root_sp
        or (uc.reg_read(UC_X86_REG_AX) & 0xFFFF) != stale_return
        or bytes(uc.mem_read(root_sp, 2))
        != struct.pack("<H", resident_return)
    ):
        raise AssertionError(
            "terminal receipt edge did not retire exactly its call frame"
        )

    uc.mem_write(post_origin, publication_image)
    uc.reg_write(UC_X86_REG_IP, publication_entry)
    returned = False
    stale_executed = False

    def publication_hook(
        machine: Uc,
        address: int,
        _size: int,
        _user: object,
    ) -> None:
        nonlocal returned, stale_executed
        # The next overlay legitimately reuses the retired controller's
        # numeric address.  It is a stale return only when RET has already
        # consumed the resident root slot; ordinary publication execution
        # reaches the same IP with SP at or below root_sp.
        if (
            address == stale_return
            and (machine.reg_read(UC_X86_REG_SP) & 0xFFFF) == root_sp + 2
        ):
            stale_executed = True
            machine.emu_stop()
            return
        if address == resident_return:
            returned = True
            machine.emu_stop()
            return
        if address in (RES_LOAD_PHASE, config_restore, vault_zeroize):
            set_carry(machine, False)
            return_from_near_call(machine)

    hook = uc.hook_add(UC_HOOK_CODE, publication_hook)
    try:
        uc.emu_start(publication_entry, 0, count=2_000_000)
    finally:
        uc.hook_del(hook)
    if stale_executed:
        raise AssertionError(
            "publication returned through retired post-check continuation"
        )
    if (
        not returned
        or (uc.reg_read(UC_X86_REG_SP) & 0xFFFF) != root_sp + 2
        or (uc.reg_read(UC_X86_REG_AX) & 0xFFFF) != 1
        or uc.reg_read(UC_X86_REG_EFLAGS) & 1
        or bytes(uc.mem_read(ready, 1)) != b"\x01"
    ):
        raise AssertionError(
            "publication did not return through the resident root frame"
        )

    return {
        "initial_stack_top_first": [
            f"0x{stale_return:04x}",
            f"0x{resident_return:04x}",
        ],
        "terminal_receipt_consumed": f"0x{stale_return:04x}",
        "validated_snapshot_sp": f"0x{root_sp:04x}",
        "publication_return": f"0x{resident_return:04x}",
        "final_sp": f"0x{root_sp + 2:04x}",
        "retired_continuation_executed": False,
        "valid_snapshot_adopted": True,
        "return_abi": "CF=0, AX=1",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--product-core",
        type=Path,
        default=DEFAULT_PRODUCT_CORE,
    )
    parser.add_argument(
        "--product-listing",
        type=Path,
        default=DEFAULT_PRODUCT_LISTING,
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="optional path for the stable validation report",
    )
    args = parser.parse_args()

    for path in (args.product_core, args.product_listing):
        if not path.is_file():
            raise SystemExit(f"required product input is missing: {path}")

    with tempfile.TemporaryDirectory(prefix="seed-k14-product-gate-") as name:
        work = Path(name)
        base = work / "base"
        final = work / "final"
        run(
            [
                sys.executable,
                str(BASE_BUILDER),
                "--product-mode",
                "--product-core",
                str(args.product_core),
                "--product-listing",
                str(args.product_listing),
                "--build-dir",
                str(base),
            ]
        )
        deadline_report_path = work / "deadline-observation.json"
        run(
            [
                sys.executable,
                str(LIVE_CONTROLLER_GATE),
                "--deadline-only",
                "--build-dir",
                str(base),
                "--json-out",
                str(deadline_report_path),
            ]
        )
        run(
            [
                sys.executable,
                str(POST_BUILDER),
                "--product-mode",
                "--base-build",
                str(base),
                "--build-dir",
                str(final),
            ]
        )

        base_manifest = load_json(base / "manifest.json")
        tcp_close_call_binding_gate = check_tcp_close_call_binding(
            base, base_manifest
        )
        scheduler_state_gate = check_scheduler_state_preserved(
            base, base_manifest
        )
        timing_telemetry_gate = check_authoritative_timing_telemetry_absent(
            base, base_manifest
        )
        deadline_report = load_json(deadline_report_path)
        if (
            deadline_report.get("schema")
            != "seed-tls13-k14-deadline-observation-v1"
            or deadline_report.get("passed") is not True
            or deadline_report.get("vm_or_network_launched") is not False
        ):
            raise AssertionError(
                "product deadline-observation source parity gate failed"
            )
        deadline_parity = deadline_report.get(
            "deadline_observation_parity"
        )
        deadline_overlap = (
            deadline_parity.get(
                "authoritative_reconnect_telemetry_overlap"
            )
            if isinstance(deadline_parity, dict)
            else None
        )
        if (
            not isinstance(deadline_overlap, dict)
            or deadline_overlap.get("range") != "0x3ca0..0x3ca6"
            or deadline_overlap.get("protected_writes_at_273") != 0
            or deadline_overlap.get("protected_writes_at_274") != 0
        ):
            raise AssertionError(
                "clean deadline controller touched resident reconnect state"
            )
        manifest = load_json(final / "manifest.json")
        if manifest.get("schema") != "seed-tls13-k14-product-route-v1":
            raise AssertionError("unexpected product-route manifest schema")
        integrated_trace_gate = check_integrated_trace_absent(manifest)
        mode = manifest.get("mode")
        if (
            not isinstance(mode, dict)
            or mode.get("product") is not True
            or mode.get("tls") != "TLS 1.3 only"
            or mode.get("read_only_media_compatible") is not True
            or mode.get("user_cfg") is not False
            or mode.get("fixed_lba_credential_loader") is not False
            or mode.get("one_shot_request_response") is not False
        ):
            raise AssertionError("product mode contract drifted")

        output = manifest.get("output")
        if not isinstance(output, dict):
            raise AssertionError("product manifest lacks output metadata")
        core_path = Path(str(output.get("core")))
        pack_path = Path(str(output.get("phase_pack")))
        abi_path = Path(str(output.get("abi_include")))
        core = core_path.read_bytes()
        pack = pack_path.read_bytes()
        abi_defines = parse_nasm_defines(abi_path)
        if (
            output.get("core_bytes") != len(core)
            or output.get("core_sha256") != sha256(core)
            or output.get("phase_pack_bytes") != len(pack)
            or output.get("phase_pack_sha256") != sha256(pack)
            or output.get("abi_include_sha256")
            != sha256(abi_path.read_bytes())
            or pack != core[RESIDENT_BASE_SECTORS * SECTOR :]
            or output.get("floppy_image") is not None
            or output.get("basic_sidecar") is not None
        ):
            raise AssertionError("product output binding drifted")
        if (
            abi_defines.get("TLS13_K14_PRODUCT_TOTAL_SECTORS")
            != len(core) // SECTOR
            or abi_defines.get("TLS13_K14_PRODUCT_PACK_SECTORS")
            != len(pack) // SECTOR
        ):
            raise AssertionError("generated product ABI pack geometry drifted")
        header_sectors = struct.unpack_from("<H", core, 0x11)[0]
        if header_sectors * SECTOR != len(core):
            raise AssertionError("SEED.SYS total-sector header is stale")

        phases = check_phase_ledger(manifest, core)
        names = {str(phase["name"]) for phase in phases}
        if names.intersection(FORBIDDEN_PHASES):
            raise AssertionError("credential/one-shot phase entered product pack")
        if "post_auth_product_publication" not in names:
            raise AssertionError("product publication phase is absent")
        if b"sk-" in core.lower():
            raise AssertionError("credential-shaped literal entered product core")

        root = manifest.get("root_abi")
        nic = root.get("nic_vtable") if isinstance(root, dict) else None
        if (
            not isinstance(root, dict)
            or root.get("call_address") != "0x3400"
            or root.get("input")
            != "AL=0 cold post-config setup; AL=1 human reconnect"
            or not isinstance(nic, dict)
            or nic.get("controller_calls_enter") is not True
            or nic.get("reuses_boot_acquired_dhcp_lease") is not True
            or nic.get("caller_restores_after_every_return") is not True
            or nic.get("restore_preserves_tcp_tls_session") is not True
            or nic.get("second_enter_before_restore_forbidden") is not True
            or "CF=0, AX=1" not in str(root.get("success"))
            or "CF=1, AX=0" not in str(root.get("failure"))
        ):
            raise AssertionError("root call/return ownership ABI drifted")
        if (
            abi_defines.get("TLS13_K14_PRODUCT_ROOT_PHASE_KEY")
            != parse_hex(root.get("phase_key"), "root phase key")
            or abi_defines.get("TLS13_K14_PRODUCT_ROOT_DESTINATION")
            != 0x3400
            or abi_defines.get("TLS13_K14_PRODUCT_ROOT_ENTRY") != 0x3400
        ):
            raise AssertionError("generated root ABI drifted")

        state_guard = manifest.get("state_guard_abi")
        if (
            not isinstance(state_guard, dict)
            or state_guard.get("load_destination") != "0x0700"
            or state_guard.get("entry") != "0x0700"
            or state_guard.get("pre_before_root") is not True
            or state_guard.get("post_after_root_and_nic_restore") is not True
            or state_guard.get("human_mda_requires_prompt_valid") is not True
            or abi_defines.get(
                "TLS13_K14_PRODUCT_STATE_GUARD_PHASE_KEY"
            )
            != parse_hex(state_guard.get("phase_key"), "state-guard key")
            or abi_defines.get(
                "TLS13_K14_PRODUCT_STATE_GUARD_DESTINATION"
            )
            != 0x0700
            or abi_defines.get("TLS13_K14_PRODUCT_STATE_GUARD_ENTRY")
            != 0x0700
        ):
            raise AssertionError("state-guard dispatcher ABI drifted")

        escrow = manifest.get("config_escrow_abi")
        if (
            not isinstance(escrow, dict)
            or escrow.get("stage") != "0x2c00"
            or escrow.get("cache_bytes") != 256
            or escrow.get("cache_preserved_in_modes") != [0, 1]
            or escrow.get("object_bytes") != 416
            or escrow.get("status_written_last") is not True
            or escrow.get("validates_before_conventional_write") is not True
            or escrow.get("scrubs_before_vault_zeroize") is not True
        ):
            raise AssertionError("config-escrow product ABI drifted")
        escrow_gate = run_config_escrow_gate(base)

        vault = manifest.get("vault_abi")
        if not isinstance(vault, dict):
            raise AssertionError("product manifest lacks generic-vault ABI")
        initial = vault.get("initial")
        fo = vault.get("fo")
        resumed = vault.get("resumption")
        receipt = vault.get("receipt")
        vault_access_listing = base / "product_vault_access.lst"
        vault_write_offset = listing_label_offset(
            vault_access_listing, "pv_write"
        )
        vault_read_offset = listing_label_offset(
            vault_access_listing, "pv_read"
        )
        vault_lifecycle_listing = base / "product_vault_lifecycle.lst"
        vault_lifecycle_write_offset = listing_label_offset(
            vault_lifecycle_listing, "pv_write"
        )
        vault_lifecycle_read_offset = listing_label_offset(
            vault_lifecycle_listing, "pv_read"
        )
        vault_lifecycle_rebind_offset = listing_label_offset(
            vault_lifecycle_listing, "pv_rebind_raw"
        )
        initial_stage = ACCESS_INITIAL_STAGE
        fo_stage = 0x2800
        resumed_stage = 0x2C00
        receipt_stage = 0x2800
        if (
            not isinstance(initial, dict)
            or initial.get("stage") != f"0x{initial_stage:04x}"
            or initial.get("write")
            != f"0x{initial_stage + vault_write_offset:04x}"
            or initial.get("read")
            != f"0x{initial_stage + vault_read_offset:04x}"
            or not isinstance(fo, dict)
            or fo.get("stage") != f"0x{fo_stage:04x}"
            or fo.get("write")
            != f"0x{fo_stage + vault_write_offset:04x}"
            or fo.get("read")
            != f"0x{fo_stage + vault_read_offset:04x}"
            or not isinstance(resumed, dict)
            or resumed.get("stage") != f"0x{resumed_stage:04x}"
            or resumed.get("write")
            != f"0x{resumed_stage + vault_write_offset:04x}"
            or resumed.get("read")
            != f"0x{resumed_stage + vault_read_offset:04x}"
            or not isinstance(receipt, dict)
            or receipt.get("stage") != f"0x{receipt_stage:04x}"
            or receipt.get("write")
            != f"0x{receipt_stage + vault_lifecycle_write_offset:04x}"
            or receipt.get("read")
            != f"0x{receipt_stage + vault_lifecycle_read_offset:04x}"
            or receipt.get("rebind")
            != f"0x{receipt_stage + vault_lifecycle_rebind_offset:04x}"
            or receipt.get("loaded_after_symmetric_work_retires") is not True
            or receipt.get("loaded_after_receipt_digest") is not True
            or receipt.get("raw_epoch_rebound_before_write") is not True
            or vault.get("no_nic_ram_or_writable_floppy_dependency") is not True
        ):
            raise AssertionError("generic-vault access schedule drifted")
        root_dispatch_gate = run_root_dispatch_gate(base, base_manifest)
        vault_access_schedule_gate = run_vault_access_schedule_gate(
            base, base_manifest, manifest
        )
        resumption_access_lease_gate = run_resumption_access_lease_gate(
            base, base_manifest, manifest
        )
        symmetric_tail_restore_hash_gate = run_symmetric_tail_restore_hash_gate(
            base, final, base_manifest, manifest
        )
        publication_return_stack_gate = run_publication_return_stack_gate(
            final
        )

        publication = manifest.get("publication_abi")
        if (
            not isinstance(publication, dict)
            or publication.get("zeroizes_vault_before_ready") is not True
            or publication.get("scrubs_retired_secret_workspace_before_ready")
            is not True
            or publication.get("ready_written_last") is not True
            or publication.get(
                "restores_config_escrow_before_vault_zeroize"
            )
            is not True
            or publication.get(
                "scrubs_config_escrow_before_vault_zeroize"
            )
            is not True
            or publication.get("retired_scrub_excludes_restored_cache")
            is not True
        ):
            raise AssertionError("status-last publication contract drifted")
        publication_gate = run_publication_gate(final, manifest)

        cleanup = manifest.get("failure_cleanup")
        if (
            not isinstance(cleanup, dict)
            or cleanup.get(
                "local_scrub_returns_to_persistent_code_before_0x2400_reload"
            )
            is not True
            or cleanup.get("never_calls_retired_access_leaf") is not True
            or cleanup.get("no_diagnostic_or_halt_path") is not True
        ):
            raise AssertionError("product failure cleanup contract drifted")

        security = manifest.get("security_chain")
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
            "external_precomputation_required",
        )
        if not isinstance(security, dict):
            raise AssertionError("product manifest lacks security chain")
        for field in required_security[:-1]:
            if security.get(field) is not True:
                raise AssertionError(f"security-chain field failed: {field}")
        if security.get("external_precomputation_required") is not False:
            raise AssertionError("product route acquired external precomputation")

        base_output = base_manifest.get("output")
        if (
            not isinstance(base_output, dict)
            or base_output.get("core_sha256")
            != manifest["base"]["core_sha256"]
        ):
            raise AssertionError("post composition did not bind its base core")

        report = {
            "schema": "seed-tls13-k14-product-route-gate-v1",
            "passed": True,
            "core_bytes": len(core),
            "core_sectors": len(core) // SECTOR,
            "core_sha256": sha256(core),
            "phase_pack_bytes": len(pack),
            "phase_pack_sha256": sha256(pack),
            "phase_count": len(phases),
            "read_only_media_compatible": True,
            "credential_or_one_shot_phases": 0,
            "config_escrow_gate": escrow_gate,
            "publication_gate": publication_gate,
            "publication_return_stack_gate": publication_return_stack_gate,
            "root_dispatch_gate": root_dispatch_gate,
            "tcp_close_call_binding_gate": tcp_close_call_binding_gate,
            "scheduler_state_gate": scheduler_state_gate,
            "vault_access_schedule_gate": vault_access_schedule_gate,
            "resumption_access_lease_gate": resumption_access_lease_gate,
            "symmetric_tail_restore_hash_gate": (
                symmetric_tail_restore_hash_gate
            ),
            "deadline_observation_gate": deadline_report[
                "deadline_observation_parity"
            ],
            "timing_telemetry_overlap_gate": {
                **timing_telemetry_gate,
                "clean_deadline_dynamic_writes": deadline_overlap,
            },
            "integrated_trace_absence_gate": integrated_trace_gate,
            "generated_abi_include": True,
            "vm_or_network_launched": False,
        }

    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
