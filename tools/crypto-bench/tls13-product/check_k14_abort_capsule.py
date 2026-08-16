#!/usr/bin/env python3
"""Executable gate for the 16 KiB K14 product abort capsule."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MEM_WRITE,
    UC_MODE_16,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
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
BUILDER = POC / "build_live_k15.py"
DEFAULT_PRODUCT_CORE = ROOT / "build/ibm_pc_5150/tls13-pack-base/SEED.SYS"
DEFAULT_PRODUCT_LISTING = (
    ROOT / "build/ibm_pc_5150/tls13-pack-base/SEED.SYS.lst"
)

SECTOR = 512
MAP_BYTES = 0x100000
CORE_ORIGIN = 0x1000
RESIDENT_BYTES = 0x0800
CRYPTO_ORIGIN = 0x3400
RES_LOAD_PHASE = 0x10C4
READY = 0x06C4
HANDOFF_RAM_TOP = 0x062C
RAM_TOP = 0x4000
SAVED_SP = RAM_TOP - 6
K14_RAM_TOPS = (0x4000, 0x6000, 0x8000)
RESET_PHYSICAL = 0xFFFF0
WARM_FLAG = 0x0472

CONFIG_CACHE = 0x3B9C
CONFIG_CACHE_BYTES = 256
CONFIG_SENSITIVE_START = 0x3B2B
CONFIG_SENSITIVE_END = CONFIG_CACHE + CONFIG_CACHE_BYTES
CONFIG_UI = (0x0F55, 0x0F56, 0x0F33, 0x0F66, 0x0F67)
CONFIG_ESCROW_BYTES = 416
CONFIG_ESCROW_CGA = 0xB8000 + 0x1E00
CONFIG_ESCROW_MDA = 0xB0000 + 0x0E00

BDA_CRT_PORT = 0x0463
BDA_MODE_CONTROL = 0x0465
CGA_CRT_PORT = 0x03D4
MDA_CRT_PORT = 0x03B4
MDA_CRTC_DATA_PORT = 0x03B5
MDA_MODE_PORT = 0x03B8
MDA_MODE = 0x29
MDA_HDISPLAY_REG = 0x01
MDA_START_HIGH_REG = 0x0C
MDA_START_LOW_REG = 0x0D
MDA_NORMAL_COLUMNS = 80
CGA_VAULT = 0xB8000 + 0x1000
MDA_VAULT = 0xB0000
VAULT_PAYLOAD_BYTES = 13 * 256
VAULT_OWNED_BYTES = VAULT_PAYLOAD_BYTES + 256
MDA_VISIBLE_BYTES = 4000
VIDEO_GUARD_BYTES = 96

HELPER_RETURN = 0x0520
HELPER_STACK_TOP = 0x3F00
HOSTILE_SS = 0x9000
HOSTILE_SP = 0x0100
HOSTILE_STACK_RANGES = (
    ((HOSTILE_SS << 4) + HOSTILE_SP - 64, (HOSTILE_SS << 4) + HOSTILE_SP + 64),
    (HOSTILE_SP - 64, HOSTILE_SP + 64),
)
NIC_STUBS = (0x0500, 0x0504, 0x0508, 0x050C, 0x0510)

ACTIVE_LISTING_LINE = re.compile(
    r"^\s*\d+\s+([0-9A-F]{8})\s+(\S+)\s+"
    r"(?:<\d+>\s+)?(.*\S)\s*$"
)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_hex(value: object, label: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise AssertionError(f"{label} is not a hexadecimal ABI value")
    return int(value, 16)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} is not a JSON object")
    return value


def deterministic(length: int, salt: int) -> bytes:
    return bytes(
        ((index * 73 + salt * 41 + 1) & 0xFF) or 0xA5
        for index in range(length)
    )


def active_listing_instructions(path: Path) -> list[tuple[int, str, str]]:
    result: list[tuple[int, str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        matched = ACTIVE_LISTING_LINE.match(raw)
        if matched is None:
            continue
        offset_text, encoded, source = matched.groups()
        result.append((int(offset_text, 16), encoded, source.strip()))
    if not result:
        raise AssertionError(f"{path} has no active assembled instructions")
    return result


def listing_label_offset(path: Path, label: str) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
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
        break
    raise AssertionError(f"cannot resolve listing label {label!r} in {path}")


def derive_resident_return(
    product_listing: Path,
    product_core: bytes,
) -> int:
    calls = [
        (offset, encoded)
        for offset, encoded, source in active_listing_instructions(product_listing)
        if source == "call TLS13_K14_PRODUCT_ROOT_ENTRY"
    ]
    if len(calls) != 1:
        raise AssertionError(
            "product listing must contain exactly one active K14 root call"
        )
    call_offset, encoded = calls[0]
    if not encoded.startswith("E8"):
        raise AssertionError("K14 root dispatch is no longer a near CALL")
    if call_offset + 3 > len(product_core) or product_core[call_offset] != 0xE8:
        raise AssertionError("product listing root CALL is not bound to its core")
    displacement = struct.unpack_from("<H", product_core, call_offset + 1)[0]
    call_return = CORE_ORIGIN + call_offset + 3
    if (call_return + displacement) & 0xFFFF != CRYPTO_ORIGIN:
        raise AssertionError("product core root CALL no longer targets 0x3400")
    instructions = active_listing_instructions(product_listing)
    if not any(
        offset == call_offset + 3 and source == "pushf"
        for offset, _encoded, source in instructions
    ):
        raise AssertionError("resident root return no longer lands on PUSHF")
    return call_return


@dataclass(frozen=True)
class Phase:
    name: str
    key: int
    destination: int
    sectors: int
    image: bytes

    @property
    def padded(self) -> bytes:
        return self.image + bytes(self.sectors * SECTOR - len(self.image))


@dataclass(frozen=True)
class Artifacts:
    build: Path
    core: bytes
    crypto: bytes
    crypto_listing: Path
    scrub_listing: Path
    phases: dict[str, Phase]
    capsule_start: int
    snapshot_start: int
    snapshot_end: int
    snapshot_sp: int
    snapshot_sp_inverse: int
    snapshot_inverse: int
    snapshot_status: int
    fail_entry: int
    product_zeroize: int
    emergency_entry: int
    vault_begin: int
    vault_zeroize: int
    config_save: int
    config_restore: int
    resident_return: int
    nic_vtable: tuple[int, ...]


def phase_from_manifest(
    build: Path,
    entries: dict[str, dict[str, Any]],
    name: str,
    filename: str,
) -> Phase:
    entry = entries.get(name)
    if not isinstance(entry, dict):
        raise AssertionError(f"manifest lacks live phase {name}")
    image = (build / filename).read_bytes()
    image_bytes = entry.get("bytes")
    sectors = entry.get("sectors")
    if (
        not isinstance(image_bytes, int)
        or not isinstance(sectors, int)
        or image_bytes != len(image)
        or not 0 < len(image) <= sectors * SECTOR
        or entry.get("sha256") != sha256(image)
    ):
        raise AssertionError(f"{name} artifact is not bound to its manifest")
    return Phase(
        name=name,
        key=parse_hex(entry.get("key"), f"{name} key"),
        destination=parse_hex(entry.get("destination"), f"{name} destination"),
        sectors=sectors,
        image=image,
    )


def load_artifacts(
    build: Path,
    product_core_path: Path,
    product_listing: Path,
) -> Artifacts:
    manifest = load_json(build / "manifest.json")
    output = manifest.get("output")
    persistent = manifest.get("persistent_services")
    product = manifest.get("product_abi")
    live_phases = manifest.get("live_phases")
    if (
        not isinstance(output, dict)
        or not isinstance(persistent, dict)
        or not isinstance(product, dict)
        or not isinstance(live_phases, list)
    ):
        raise AssertionError("product build manifest lacks abort-capsule ABI")

    product_input = manifest.get("product_input")
    product_core = product_core_path.read_bytes()
    if (
        not isinstance(product_input, dict)
        or product_input.get("bytes") != len(product_core)
        or product_input.get("sha256") != sha256(product_core)
    ):
        raise AssertionError("product input core is not bound to base manifest")

    core = (build / "SEED.SYS").read_bytes()
    crypto = (build / "live_crypto_controller.bin").read_bytes()
    crypto_listing = build / "live_crypto_controller.lst"
    scrub_listing = build / "live_scrub_controller.lst"
    if (
        output.get("core_bytes") != len(core)
        or output.get("core_sha256") != sha256(core)
        or len(crypto) != SECTOR
    ):
        raise AssertionError("product core/controller output binding drifted")

    snapshot = persistent.get("root_frame_snapshot")
    if not isinstance(snapshot, dict):
        raise AssertionError("manifest lacks root-frame snapshot")
    snapshot_start = parse_hex(snapshot.get("start"), "snapshot start")
    snapshot_end = parse_hex(snapshot.get("end"), "snapshot end")
    snapshot_sp = parse_hex(snapshot.get("sp"), "snapshot SP")
    snapshot_sp_inverse = parse_hex(
        snapshot.get("sp_inverse"), "snapshot SP inverse"
    )
    snapshot_inverse = parse_hex(snapshot.get("inverse"), "snapshot inverse")
    snapshot_status = parse_hex(snapshot.get("status"), "snapshot status")
    if (
        snapshot_start != 0x35FA
        or snapshot_end != 0x3600
        or snapshot_end - snapshot_start != 6
        or (
            snapshot_sp,
            snapshot_sp_inverse,
            snapshot_inverse,
            snapshot_status,
        )
        != (0x35FA, 0x35FC, 0x35FE, 0x35FF)
    ):
        raise AssertionError("K14 abort snapshot is not the current six-byte ABI")

    capsule_start = parse_hex(persistent.get("runtime_start"), "capsule start")
    capsule_end = parse_hex(persistent.get("runtime_end"), "capsule end")
    if (
        capsule_start != 0x355D
        or capsule_end != snapshot_end
        or persistent.get("bytes") != capsule_end - capsule_start
    ):
        raise AssertionError("persistent abort-capsule geometry drifted")
    capsule = crypto[capsule_start - CRYPTO_ORIGIN : capsule_end - CRYPTO_ORIGIN]
    if persistent.get("sha256") != sha256(capsule):
        raise AssertionError("persistent abort capsule is not hash-bound")

    fail_entry = CRYPTO_ORIGIN + listing_label_offset(
        crypto_listing, "live_secure_persist_fail"
    )
    product_zeroize = CRYPTO_ORIGIN + listing_label_offset(
        crypto_listing, "live_secure_persist_product_zeroize"
    )
    emergency_entry = CRYPTO_ORIGIN + listing_label_offset(
        crypto_listing, "live_secure_persist_emergency_reset"
    )
    if (
        fail_entry != parse_hex(persistent.get("fail"), "failure entry")
        or product_zeroize
        != parse_hex(persistent.get("product_zeroize"), "zeroize entry")
        or emergency_entry
        != parse_hex(persistent.get("emergency_reset"), "emergency entry")
    ):
        raise AssertionError("persistent entry labels disagree with manifest")

    resident_return = derive_resident_return(product_listing, product_core)
    root = product.get("root_entry")
    vault = product.get("vault")
    config = product.get("config_escrow")
    if (
        not isinstance(root, dict)
        or not isinstance(vault, dict)
        or not isinstance(config, dict)
    ):
        raise AssertionError("product ABI lacks root/vault/config contracts")
    declared_returns = (
        parse_hex(snapshot.get("expected_return"), "snapshot expected return"),
        parse_hex(root.get("resident_return"), "root resident return"),
    )
    if declared_returns != (resident_return, resident_return):
        raise AssertionError(
            "generated manifest return is not the listing-derived CALL return"
        )

    entries = {
        str(item.get("name")): item
        for item in live_phases
        if isinstance(item, dict)
    }
    phases = {
        "scrub_controller": phase_from_manifest(
            build,
            entries,
            "scrub_controller",
            "live_scrub_controller.bin",
        ),
        "config_escrow": phase_from_manifest(
            build,
            entries,
            "config_escrow",
            "product_config_escrow.bin",
        ),
        "vault_lifecycle": phase_from_manifest(
            build,
            entries,
            "vault_lifecycle",
            "product_vault_lifecycle.bin",
        ),
    }
    if (
        phases["scrub_controller"].destination != 0x2400
        or phases["config_escrow"].destination
        != parse_hex(config.get("stage"), "config stage")
        or phases["vault_lifecycle"].destination
        != parse_hex(vault.get("lifecycle_stage"), "vault lifecycle stage")
    ):
        raise AssertionError("abort recovery phase destinations drifted")

    vault_begin = parse_hex(vault.get("begin"), "vault begin")
    vault_zeroize = (
        phases["vault_lifecycle"].destination
        + parse_hex(vault.get("zeroize_offset"), "vault zeroize offset")
    )
    config_save = parse_hex(config.get("save"), "config save")
    config_restore = parse_hex(config.get("restore"), "config restore")
    vault_table = struct.unpack_from("<6H", phases["vault_lifecycle"].image)
    if (
        phases["vault_lifecycle"].destination + vault_table[0] != vault_begin
        or phases["vault_lifecycle"].destination + vault_table[5]
        != vault_zeroize
    ):
        raise AssertionError("vault lifecycle entry table drifted")
    if struct.unpack_from("<2H", phases["config_escrow"].image) != (
        config_save,
        config_restore,
    ):
        raise AssertionError("config escrow entry table drifted")

    nic_labels = (
        "nic_vt_enter",
        "nic_vt_restore",
        "nic_vt_transmit",
        "nic_vt_receive",
        "nic_vt_rx_fallback",
    )
    nic_vtable = tuple(
        CORE_ORIGIN + listing_label_offset(product_listing, label)
        for label in nic_labels
    )
    if nic_vtable != tuple(range(nic_vtable[0], nic_vtable[0] + 10, 2)):
        raise AssertionError("resident NIC vtable is no longer five contiguous words")

    active_abort_sources = [
        source
        for offset, _encoded, source in active_listing_instructions(crypto_listing)
        if fail_entry - CRYPTO_ORIGIN <= offset < snapshot_start - CRYPTO_ORIGIN
    ]
    active_scrub_sources = [
        source
        for _offset, _encoded, source in active_listing_instructions(scrub_listing)
    ]
    for source in active_abort_sources + active_scrub_sources:
        if "nic_vt" in source.lower() or "LIVE_K15_NE_BUF" in source:
            raise AssertionError("abort capsule acquired a NIC callback")

    return Artifacts(
        build=build,
        core=core,
        crypto=crypto,
        crypto_listing=crypto_listing,
        scrub_listing=scrub_listing,
        phases=phases,
        capsule_start=capsule_start,
        snapshot_start=snapshot_start,
        snapshot_end=snapshot_end,
        snapshot_sp=snapshot_sp,
        snapshot_sp_inverse=snapshot_sp_inverse,
        snapshot_inverse=snapshot_inverse,
        snapshot_status=snapshot_status,
        fail_entry=fail_entry,
        product_zeroize=product_zeroize,
        emergency_entry=emergency_entry,
        vault_begin=vault_begin,
        vault_zeroize=vault_zeroize,
        config_save=config_save,
        config_restore=config_restore,
        resident_return=resident_return,
        nic_vtable=nic_vtable,
    )


class IoState:
    def __init__(self, uc: Uc) -> None:
        self.mode = MDA_MODE
        self.crtc_index = 0
        self.crtc = bytearray(32)
        self.crtc[MDA_HDISPLAY_REG] = MDA_NORMAL_COLUMNS
        self.events: list[tuple[str, int, int, int]] = []
        uc.hook_add(UC_HOOK_INSN, self._input, None, 1, 0, UC_X86_INS_IN)
        uc.hook_add(UC_HOOK_INSN, self._output, None, 1, 0, UC_X86_INS_OUT)

    def _input(self, _uc: Uc, port: int, size: int, _user: object) -> int:
        raise AssertionError(f"unexpected IN {port:04x}/{size}")

    def _output(
        self,
        _uc: Uc,
        port: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        if size != 1:
            raise AssertionError(
                f"unexpected OUT {port:04x}/{size}={value:02x}"
            )
        value &= 0xFF
        if port == MDA_MODE_PORT:
            self.mode = value
        elif port == MDA_CRT_PORT:
            self.crtc_index = value & 0x1F
        elif port == MDA_CRTC_DATA_PORT:
            self.crtc[self.crtc_index] = value
        else:
            raise AssertionError(
                f"unexpected OUT {port:04x}/{size}={value:02x}"
            )
        self.events.append(("out", port, size, value))


def mda_restore_io(mode: int = MDA_MODE) -> tuple[tuple[str, int, int, int], ...]:
    return (
        ("out", MDA_CRT_PORT, 1, MDA_START_HIGH_REG),
        ("out", MDA_CRTC_DATA_PORT, 1, 0),
        ("out", MDA_CRT_PORT, 1, MDA_START_LOW_REG),
        ("out", MDA_CRTC_DATA_PORT, 1, 0),
        ("out", MDA_CRT_PORT, 1, MDA_HDISPLAY_REG),
        ("out", MDA_CRTC_DATA_PORT, 1, MDA_NORMAL_COLUMNS),
        ("out", MDA_MODE_PORT, 1, mode | 0x08),
    )


def set_carry(uc: Uc, value: bool) -> None:
    flags = uc.reg_read(UC_X86_REG_EFLAGS)
    uc.reg_write(
        UC_X86_REG_EFLAGS,
        flags | 1 if value else flags & ~1,
    )


def return_from_near_call(uc: Uc) -> None:
    ss = uc.reg_read(UC_X86_REG_SS) & 0xFFFF
    sp = uc.reg_read(UC_X86_REG_SP) & 0xFFFF
    physical = (ss << 4) + sp
    target = struct.unpack("<H", bytes(uc.mem_read(physical, 2)))[0]
    uc.reg_write(UC_X86_REG_SP, (sp + 2) & 0xFFFF)
    uc.reg_write(UC_X86_REG_IP, target)


def new_machine(backend: str) -> tuple[Uc, IoState]:
    if backend not in {"CGA", "MDA"}:
        raise AssertionError(f"unknown video backend {backend}")
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, MAP_BYTES)
    io = IoState(uc)
    port = MDA_CRT_PORT if backend == "MDA" else CGA_CRT_PORT
    uc.mem_write(BDA_CRT_PORT, struct.pack("<H", port))
    uc.mem_write(BDA_MODE_CONTROL, bytes((MDA_MODE,)))
    uc.mem_write(CGA_VAULT, deterministic(MDA_VISIBLE_BYTES, 0x31))
    uc.mem_write(
        CGA_VAULT + MDA_VISIBLE_BYTES,
        deterministic(VIDEO_GUARD_BYTES, 0x32),
    )
    uc.mem_write(MDA_VAULT, deterministic(MDA_VISIBLE_BYTES, 0x41))
    uc.mem_write(
        MDA_VAULT + MDA_VISIBLE_BYTES,
        deterministic(VIDEO_GUARD_BYTES, 0x42),
    )
    for start, end in HOSTILE_STACK_RANGES:
        uc.mem_write(start, deterministic(end - start, 0x51 + start))
    return uc, io


def call_helper(
    uc: Uc,
    entry: int,
    *,
    ax: int = 0xA153,
    dx: int = 0xD45F,
) -> bool:
    uc.mem_write(HELPER_STACK_TOP - 2, struct.pack("<H", HELPER_RETURN))
    for register, value in (
        (UC_X86_REG_AX, ax),
        (UC_X86_REG_BX, 0xB257),
        (UC_X86_REG_CX, 0xC35B),
        (UC_X86_REG_DX, dx),
        (UC_X86_REG_SI, 0x0861),
        (UC_X86_REG_DI, 0x0967),
        (UC_X86_REG_BP, 0xB56D),
        (UC_X86_REG_CS, 0),
        (UC_X86_REG_DS, 0),
        (UC_X86_REG_ES, 0),
        (UC_X86_REG_SS, 0),
        (UC_X86_REG_SP, HELPER_STACK_TOP - 2),
        (UC_X86_REG_EFLAGS, 2 | (1 << 10)),
    ):
        uc.reg_write(register, value)
    returned = False

    def stop(machine: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        machine.emu_stop()

    handle = uc.hook_add(
        UC_HOOK_CODE, stop, begin=HELPER_RETURN, end=HELPER_RETURN
    )
    try:
        uc.emu_start(entry, 0, count=5_000_000)
    finally:
        uc.hook_del(handle)
    if not returned:
        raise AssertionError(f"fixture helper {entry:04x} did not return")
    if (uc.reg_read(UC_X86_REG_SP) & 0xFFFF) != HELPER_STACK_TOP:
        raise AssertionError(f"fixture helper {entry:04x} unbalanced its stack")
    if uc.reg_read(UC_X86_REG_EFLAGS) & (1 << 10):
        raise AssertionError(f"fixture helper {entry:04x} returned with DF set")
    return bool(uc.reg_read(UC_X86_REG_EFLAGS) & 1)


def install_config_state(uc: Uc, salt: int) -> tuple[bytes, bytes]:
    cache = deterministic(CONFIG_CACHE_BYTES, salt)
    ui = bytes(
        (((salt * 17 + index * 31 + 3) & 0x7F) or 1)
        for index in range(len(CONFIG_UI))
    )
    uc.mem_write(
        CONFIG_SENSITIVE_START,
        deterministic(CONFIG_CACHE - CONFIG_SENSITIVE_START, salt + 1),
    )
    uc.mem_write(CONFIG_CACHE, cache)
    for address, value in zip(CONFIG_UI, ui, strict=True):
        uc.mem_write(address, bytes([value]))
    return cache, ui


@dataclass
class Fixture:
    uc: Uc
    io: IoState
    backend: str
    config_cache: bytes | None
    config_ui: bytes | None
    ram_top: int
    saved_sp: int
    handoff_before: bytes
    low_tail_before: bytes
    nucleus_before: bytes
    preserved_high_before: bytes
    preserved_high_start: int
    preserved_high_end: int
    snapshot_before: bytes
    active_video: int
    active_video_guard: bytes
    io_start: int
    mda_mode_before: int


def snapshot_bytes(saved_sp: int = SAVED_SP) -> bytes:
    return struct.pack("<HHBB", saved_sp, (~saved_sp) & 0xFFFF, 0x5A, 0xA5)


def prepare_fixture(
    artifacts: Artifacts,
    backend: str,
    *,
    valid_recovery_state: bool,
    snapshot: bytes | None = None,
    root_return: int | None = None,
    ram_top: int = RAM_TOP,
    corrupt_escrow: bool = False,
) -> Fixture:
    uc, io = new_machine(backend)
    saved_sp = ram_top - 6
    preserved_high_start = 0x3C9C
    preserved_high_end = ram_top - 0x100
    if preserved_high_end < preserved_high_start:
        raise AssertionError(f"K14 RAM top is too low: {ram_top:04x}")
    active_video = MDA_VAULT if backend == "MDA" else CGA_VAULT
    config_cache: bytes | None = None
    config_ui: bytes | None = None

    if valid_recovery_state:
        lifecycle = artifacts.phases["vault_lifecycle"]
        uc.mem_write(lifecycle.destination, lifecycle.padded)
        if call_helper(uc, artifacts.vault_begin, dx=0x4D31):
            raise AssertionError(f"{backend} vault fixture begin failed")
        config = artifacts.phases["config_escrow"]
        uc.mem_write(config.destination, config.padded)
        config_cache, config_ui = install_config_state(uc, 0x61)
        if call_helper(uc, artifacts.config_save, ax=1, dx=0x4D31):
            raise AssertionError(f"{backend} config fixture save failed")
        if any(
            bytes(
                uc.mem_read(
                    CONFIG_SENSITIVE_START,
                    CONFIG_SENSITIVE_END - CONFIG_SENSITIVE_START,
                )
            )
        ):
            raise AssertionError("config save did not retire conventional source")
        escrow = CONFIG_ESCROW_MDA if backend == "MDA" else CONFIG_ESCROW_CGA
        if corrupt_escrow:
            status = bytes(uc.mem_read(escrow + 0x19F, 1))[0]
            uc.mem_write(escrow + 0x19F, bytes([status ^ 1]))
        uc.mem_write(
            active_video,
            deterministic(VAULT_PAYLOAD_BYTES, 0x71),
        )

    uc.mem_write(0x0600, deterministic(0x100, 0x11))
    uc.mem_write(HANDOFF_RAM_TOP, struct.pack("<H", ram_top))
    uc.mem_write(READY, b"\xA5")
    uc.mem_write(0x0700, deterministic(0x0FE2 - 0x0700, 0x12))
    uc.mem_write(0x0FE2, deterministic(0x1000 - 0x0FE2, 0x13))
    uc.mem_write(0x1000, artifacts.core[:RESIDENT_BYTES])
    uc.mem_write(0x1800, deterministic(0x355D - 0x1800, 0x14))
    uc.mem_write(0x3600, deterministic(0x3C9C - 0x3600, 0x15))
    uc.mem_write(
        preserved_high_start,
        deterministic(preserved_high_end - preserved_high_start, 0x16),
    )
    uc.mem_write(
        ram_top - 0x100,
        deterministic(0x100, 0x17 + (ram_top >> 13)),
    )
    uc.mem_write(CRYPTO_ORIGIN, artifacts.crypto)
    uc.mem_write(
        artifacts.snapshot_start,
        snapshot if snapshot is not None else snapshot_bytes(saved_sp),
    )
    uc.mem_write(
        saved_sp,
        struct.pack(
            "<H",
            artifacts.resident_return if root_return is None else root_return,
        ),
    )
    uc.mem_write(RES_LOAD_PHASE, b"\xC3")
    for slot, target in zip(artifacts.nic_vtable, NIC_STUBS, strict=True):
        uc.mem_write(slot, struct.pack("<H", target))
        uc.mem_write(target, b"\xC3")

    handoff_before = bytes(uc.mem_read(0x0600, 0x100))
    low_tail_before = bytes(uc.mem_read(0x0FE2, 0x1E))
    nucleus_before = bytes(uc.mem_read(0x1000, RESIDENT_BYTES))
    preserved_high_before = bytes(
        uc.mem_read(
            preserved_high_start,
            preserved_high_end - preserved_high_start,
        )
    )
    snapshot_before = bytes(uc.mem_read(artifacts.snapshot_start, 6))
    active_video_guard = bytes(
        uc.mem_read(active_video + MDA_VISIBLE_BYTES, VIDEO_GUARD_BYTES)
    )
    return Fixture(
        uc=uc,
        io=io,
        backend=backend,
        config_cache=config_cache,
        config_ui=config_ui,
        ram_top=ram_top,
        saved_sp=saved_sp,
        handoff_before=handoff_before,
        low_tail_before=low_tail_before,
        nucleus_before=nucleus_before,
        preserved_high_before=preserved_high_before,
        preserved_high_start=preserved_high_start,
        preserved_high_end=preserved_high_end,
        snapshot_before=snapshot_before,
        active_video=active_video,
        active_video_guard=active_video_guard,
        io_start=len(io.events),
        mda_mode_before=io.mode,
    )


@dataclass(frozen=True)
class RunResult:
    outcome: str
    writes: tuple[tuple[int, int, int], ...]
    hostile_accesses: tuple[tuple[str, int, int], ...]
    emergency_reads: tuple[tuple[int, int], ...]
    load_names: tuple[str, ...]
    nic_hits: tuple[int, ...]
    emergency_sp: int | None
    final_sp: int
    final_flags: int
    final_ax: int
    final_cs: int
    final_ip: int


class AbortRunner:
    def __init__(
        self,
        fixture: Fixture,
        artifacts: Artifacts,
        *,
        fail_load: str | None = None,
        fail_vault_zeroize: bool = False,
    ) -> None:
        self.fixture = fixture
        self.artifacts = artifacts
        self.fail_load = fail_load
        self.fail_vault_zeroize = fail_vault_zeroize
        self.outcome: str | None = None
        self.writes: list[tuple[int, int, int]] = []
        self.hostile_accesses: list[tuple[str, int, int]] = []
        self.emergency_reads: list[tuple[int, int]] = []
        self.load_names: list[str] = []
        self.nic_hits: list[int] = []
        self.emergency_sp: int | None = None
        self.in_emergency = False

    def _code(self, uc: Uc, address: int, _size: int, _user: object) -> None:
        if address == self.artifacts.emergency_entry:
            self.in_emergency = True
            self.emergency_sp = uc.reg_read(UC_X86_REG_SP) & 0xFFFF
            return
        if address == self.artifacts.resident_return:
            self.outcome = "return"
            uc.emu_stop()
            return
        if address == RESET_PHYSICAL:
            self.outcome = "reset"
            uc.emu_stop()
            return
        if address in NIC_STUBS:
            self.nic_hits.append(address)
            self.outcome = "nic"
            uc.emu_stop()
            return
        if address == RES_LOAD_PHASE:
            if bytes(uc.mem_read(READY, 1)) != b"\x00":
                raise AssertionError("recovery phase load observed READY != 0")
            key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            matches = [
                phase
                for phase in self.artifacts.phases.values()
                if phase.key == key and phase.destination == destination
            ]
            if len(matches) != 1:
                raise AssertionError(
                    f"unexpected recovery phase load {key:04x}@{destination:04x}"
                )
            phase = matches[0]
            self.load_names.append(phase.name)
            if self.fail_load == phase.name:
                set_carry(uc, True)
            else:
                uc.mem_write(destination, phase.padded)
                uc.ctl_flush_tb()
                uc.reg_write(UC_X86_REG_DX, 0xD15C)
                set_carry(uc, False)
            return_from_near_call(uc)
            return
        if (
            self.fail_vault_zeroize
            and address == self.artifacts.vault_zeroize
        ):
            set_carry(uc, True)
            return_from_near_call(uc)

    def _memory(
        self,
        _uc: Uc,
        access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        kind = "write" if access == UC_MEM_WRITE else "read"
        if any(
            address < end and address + size > start
            for start, end in HOSTILE_STACK_RANGES
        ):
            self.hostile_accesses.append((kind, address, size))
        if access == UC_MEM_WRITE:
            self.writes.append((address, size, value))
        elif self.in_emergency:
            self.emergency_reads.append((address, size))

    def run(self) -> RunResult:
        uc = self.fixture.uc
        code_hook = uc.hook_add(UC_HOOK_CODE, self._code)
        memory_hook = uc.hook_add(
            UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
            self._memory,
        )
        for register, value in (
            (UC_X86_REG_AX, 0xA153),
            (UC_X86_REG_BX, 0xB257),
            (UC_X86_REG_CX, 0xC35B),
            (UC_X86_REG_DX, 0xD45F),
            (UC_X86_REG_SI, 0x0861),
            (UC_X86_REG_DI, 0x0967),
            (UC_X86_REG_BP, 0xB56D),
            (UC_X86_REG_CS, 0),
            (UC_X86_REG_DS, 0x8765),
            (UC_X86_REG_ES, 0x7654),
            (UC_X86_REG_SS, HOSTILE_SS),
            (UC_X86_REG_SP, HOSTILE_SP),
            (UC_X86_REG_EFLAGS, 2 | 0x0200 | (1 << 10)),
        ):
            uc.reg_write(register, value)
        try:
            uc.emu_start(self.artifacts.fail_entry, 0, count=5_000_000)
        except UcError as error:
            cs = uc.reg_read(UC_X86_REG_CS) & 0xFFFF
            ip = uc.reg_read(UC_X86_REG_IP) & 0xFFFF
            # Unicorn's 16-bit x86 backend leaves the hidden CS base at its
            # reset-style value for this far jump and can report an unmapped
            # fetch before the physical FFFF0 code hook.  The architectural
            # CS:IP is nevertheless the authoritative reset transfer.
            if cs == 0xFFFF and ip == 0:
                self.outcome = "reset"
            else:
                raise AssertionError(
                    f"abort capsule failed at {cs:04x}:{ip:04x}: {error}"
                ) from error
        finally:
            uc.hook_del(code_hook)
            uc.hook_del(memory_hook)
        if self.outcome is None:
            raise AssertionError("abort capsule reached no terminal outcome")
        return RunResult(
            outcome=self.outcome,
            writes=tuple(self.writes),
            hostile_accesses=tuple(self.hostile_accesses),
            emergency_reads=tuple(self.emergency_reads),
            load_names=tuple(self.load_names),
            nic_hits=tuple(self.nic_hits),
            emergency_sp=self.emergency_sp,
            final_sp=uc.reg_read(UC_X86_REG_SP) & 0xFFFF,
            final_flags=uc.reg_read(UC_X86_REG_EFLAGS),
            final_ax=uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
            final_cs=uc.reg_read(UC_X86_REG_CS) & 0xFFFF,
            final_ip=uc.reg_read(UC_X86_REG_IP) & 0xFFFF,
        )


def span_allowed(
    address: int,
    size: int,
    ranges: tuple[tuple[int, int], ...],
) -> bool:
    return any(start <= address and address + size <= end for start, end in ranges)


def assert_write_whitelist(
    result: RunResult,
    ranges: tuple[tuple[int, int], ...],
    label: str,
) -> None:
    rejected = [
        (address, size, value)
        for address, size, value in result.writes
        if not span_allowed(address, size, ranges)
    ]
    if rejected:
        raise AssertionError(f"{label} wrote outside whitelist: {rejected[:8]!r}")


def capsule_bytes(fixture: Fixture, artifacts: Artifacts) -> bytes:
    return bytes(
        fixture.uc.mem_read(
            artifacts.capsule_start,
            artifacts.snapshot_start - artifacts.capsule_start,
        )
    )


def assert_common_run(result: RunResult, label: str) -> None:
    if result.nic_hits:
        raise AssertionError(f"{label} reached NIC callback(s): {result.nic_hits!r}")
    if result.hostile_accesses:
        raise AssertionError(
            f"{label} touched hostile current stack: {result.hostile_accesses!r}"
        )


def assert_valid(
    fixture: Fixture,
    artifacts: Artifacts,
    result: RunResult,
) -> dict[str, Any]:
    uc = fixture.uc
    label = f"valid {fixture.backend} abort"
    assert_common_run(result, label)
    if result.outcome != "return":
        raise AssertionError(f"{label} did not return to resident continuation")
    if (
        result.final_cs != 0
        or result.final_ip != artifacts.resident_return
        or result.final_sp != fixture.saved_sp + 2
        or not result.final_flags & 1
        or result.final_ax != 0
        or result.final_flags & (1 << 10)
    ):
        raise AssertionError(
            f"{label} return ABI failed: "
            f"{result.final_cs:04x}:{result.final_ip:04x} "
            f"SP={result.final_sp:04x} FLAGS={result.final_flags:04x} "
            f"AX={result.final_ax:04x}"
        )
    if result.load_names != (
        "scrub_controller",
        "config_escrow",
        "vault_lifecycle",
    ):
        raise AssertionError(f"{label} recovery load order drifted")

    expected_low = bytearray(0x0FE2 - 0x0700)
    assert fixture.config_ui is not None and fixture.config_cache is not None
    for address, value in zip(CONFIG_UI, fixture.config_ui, strict=True):
        expected_low[address - 0x0700] = value
    if bytes(uc.mem_read(0x0700, len(expected_low))) != bytes(expected_low):
        raise AssertionError(f"{label} did not scrub low state/restore UI exactly")
    if bytes(uc.mem_read(CONFIG_CACHE, CONFIG_CACHE_BYTES)) != fixture.config_cache:
        raise AssertionError(f"{label} did not restore config cache")
    if any(
        bytes(
            uc.mem_read(
                CONFIG_SENSITIVE_START,
                CONFIG_CACHE - CONFIG_SENSITIVE_START,
            )
        )
    ):
        raise AssertionError(f"{label} retained parsed config outside cache")
    if any(bytes(uc.mem_read(0x3600, CONFIG_CACHE - 0x3600))):
        raise AssertionError(f"{label} retained high secret workspace")

    lifecycle = artifacts.phases["vault_lifecycle"]
    config = artifacts.phases["config_escrow"]
    exact_ranges = (
        (0x1800, bytes(0x2400 - 0x1800)),
        (0x2400, lifecycle.padded),
        (0x2A00, bytes(0x2C00 - 0x2A00)),
        (0x2C00, config.padded),
        (0x3000, bytes(artifacts.capsule_start - 0x3000)),
    )
    for start, expected in exact_ranges:
        if bytes(uc.mem_read(start, len(expected))) != expected:
            raise AssertionError(
                f"{label} conventional result differs at {start:04x}"
            )

    expected_handoff = bytearray(fixture.handoff_before)
    expected_handoff[READY - 0x0600] = 0
    if bytes(uc.mem_read(0x0600, 0x100)) != bytes(expected_handoff):
        raise AssertionError(f"{label} changed handoff outside READY")
    if bytes(uc.mem_read(0x0FE2, 0x1E)) != fixture.low_tail_before:
        raise AssertionError(f"{label} overran preserved TCP tail")
    if bytes(uc.mem_read(0x1000, RESIDENT_BYTES)) != fixture.nucleus_before:
        raise AssertionError(f"{label} changed resident nucleus")
    if (
        bytes(
            uc.mem_read(
                fixture.preserved_high_start,
                fixture.preserved_high_end - fixture.preserved_high_start,
            )
        )
        != fixture.preserved_high_before
    ):
        raise AssertionError(f"{label} changed preserved high context")
    if capsule_bytes(fixture, artifacts) != artifacts.crypto[
        artifacts.capsule_start - CRYPTO_ORIGIN :
        artifacts.snapshot_start - CRYPTO_ORIGIN
    ]:
        raise AssertionError(f"{label} modified immutable capsule code")
    if (
        bytes(uc.mem_read(artifacts.snapshot_start, 5))
        != fixture.snapshot_before[:5]
    ):
        raise AssertionError(f"{label} modified immutable snapshot fields")
    if bytes(uc.mem_read(artifacts.snapshot_status, 1)) != b"\x00":
        raise AssertionError(f"{label} did not invalidate snapshot status")

    if any(bytes(uc.mem_read(fixture.active_video, VAULT_OWNED_BYTES))):
        raise AssertionError(f"{label} retained public-vault bytes")
    escrow = (
        CONFIG_ESCROW_MDA if fixture.backend == "MDA" else CONFIG_ESCROW_CGA
    )
    if any(bytes(uc.mem_read(escrow, CONFIG_ESCROW_BYTES))):
        raise AssertionError(f"{label} retained config escrow")
    if fixture.backend == "MDA":
        if any(bytes(uc.mem_read(MDA_VAULT, MDA_VISIBLE_BYTES))):
            raise AssertionError("valid MDA abort did not clear visible page")
        if fixture.io.mode != MDA_MODE:
            raise AssertionError("valid MDA abort did not restore mode byte")
        expected_io = mda_restore_io()
        if tuple(fixture.io.events[fixture.io_start :]) != expected_io:
            raise AssertionError("valid MDA abort mode restore sequence drifted")
        if (
            fixture.io.crtc[MDA_START_HIGH_REG] != 0
            or fixture.io.crtc[MDA_START_LOW_REG] != 0
            or fixture.io.crtc[MDA_HDISPLAY_REG] != MDA_NORMAL_COLUMNS
        ):
            raise AssertionError("valid MDA abort did not restore scanout geometry")
    elif fixture.io.events[fixture.io_start :]:
        raise AssertionError("valid CGA abort unexpectedly used MDA I/O")
    if (
        bytes(
            uc.mem_read(
                fixture.active_video + MDA_VISIBLE_BYTES,
                VIDEO_GUARD_BYTES,
            )
        )
        != fixture.active_video_guard
    ):
        raise AssertionError(f"{label} overran active video boundary")

    status_writes = [
        write
        for write in result.writes
        if write[0] < artifacts.snapshot_end
        and write[0] + write[1] > artifacts.snapshot_start
    ]
    if status_writes != [(artifacts.snapshot_status, 1, 0)]:
        raise AssertionError(f"{label} snapshot write whitelist drifted")
    valid_ranges = (
        (READY, READY + 1),
        (0x0700, 0x0FE2),
        (0x1800, artifacts.capsule_start),
        (artifacts.snapshot_status, artifacts.snapshot_end),
        (0x3600, CONFIG_SENSITIVE_END),
        (fixture.ram_top - 0x100, fixture.ram_top),
        (
            fixture.active_video,
            fixture.active_video + MDA_VISIBLE_BYTES,
        ),
    )
    assert_write_whitelist(result, valid_ranges, label)
    return {
        "returned_to": f"0x{artifacts.resident_return:04x}",
        "ram_top": f"0x{fixture.ram_top:04x}",
        "saved_sp": f"0x{fixture.saved_sp:04x}",
        "carry": 1,
        "ax": result.final_ax,
        "phase_loads": list(result.load_names),
        "config_cache_restored": True,
        "ui_vector_restored": True,
        "video_zeroized": True,
        "mda_mode_restored": fixture.backend == "MDA",
        "hostile_stack_accesses": 0,
        "nic_callbacks": 0,
    }


def emergency_ranges(
    fixture: Fixture,
    artifacts: Artifacts,
) -> tuple[tuple[int, int], ...]:
    return (
        (WARM_FLAG, WARM_FLAG + 2),
        (READY, READY + 1),
        (0x0700, 0x0FE2),
        (0x1800, artifacts.capsule_start),
        (artifacts.snapshot_status, artifacts.snapshot_end),
        (0x3600, 0x8000),
        (MDA_VAULT, MDA_VAULT + MDA_VISIBLE_BYTES),
        (CGA_VAULT, CGA_VAULT + MDA_VISIBLE_BYTES),
    )


def assert_emergency(
    fixture: Fixture,
    artifacts: Artifacts,
    result: RunResult,
    label: str,
) -> None:
    uc = fixture.uc
    assert_common_run(result, label)
    if (
        result.outcome != "reset"
        or result.final_cs != 0xFFFF
        or result.final_ip != 0
    ):
        raise AssertionError(
            f"{label} did not far-reset: "
            f"{result.outcome}/{result.final_cs:04x}:{result.final_ip:04x}"
        )
    if bytes(uc.mem_read(WARM_FLAG, 2)) != struct.pack("<H", 0x1234):
        raise AssertionError(f"{label} did not publish BIOS warm-reset flag")
    if not result.writes or result.writes[-1] != (WARM_FLAG, 2, 0x1234):
        raise AssertionError(f"{label} warm-reset flag was not the final write")
    for start, end in (
        (0x0700, 0x0FE2),
        (0x1800, artifacts.capsule_start),
        (0x3600, 0x8000),
        (MDA_VAULT, MDA_VAULT + MDA_VISIBLE_BYTES),
        (CGA_VAULT, CGA_VAULT + MDA_VISIBLE_BYTES),
    ):
        if any(bytes(uc.mem_read(start, end - start))):
            raise AssertionError(f"{label} did not wipe {start:05x}..{end:05x}")
    if capsule_bytes(fixture, artifacts) != artifacts.crypto[
        artifacts.capsule_start - CRYPTO_ORIGIN :
        artifacts.snapshot_start - CRYPTO_ORIGIN
    ]:
        raise AssertionError(f"{label} modified immutable capsule code")
    if bytes(uc.mem_read(artifacts.snapshot_status, 1)) != b"\x00":
        raise AssertionError(f"{label} left abort snapshot published")
    if (
        bytes(uc.mem_read(artifacts.snapshot_start, 5))
        != fixture.snapshot_before[:5]
    ):
        raise AssertionError(f"{label} modified immutable snapshot fields")
    video_guards = (
        (MDA_VAULT, deterministic(VIDEO_GUARD_BYTES, 0x42)),
        (CGA_VAULT, deterministic(VIDEO_GUARD_BYTES, 0x32)),
    )
    for video, expected_guard in video_guards:
        if (
            bytes(
                uc.mem_read(
                    video + MDA_VISIBLE_BYTES,
                    VIDEO_GUARD_BYTES,
                )
            )
            != expected_guard
        ):
            raise AssertionError(
                f"{label} overran video boundary at {video:05x}"
            )
    if result.emergency_sp is None or result.final_sp != result.emergency_sp:
        raise AssertionError(f"{label} emergency branch used a stack")
    if result.emergency_reads:
        raise AssertionError(
            f"{label} emergency branch trusted mutable memory: "
            f"{result.emergency_reads!r}"
        )
    assert_write_whitelist(result, emergency_ranges(fixture, artifacts), label)


def publication_gate(
    artifacts: Artifacts,
    saved_sp: int,
) -> tuple[list[tuple[int, int, int]], bytes]:
    uc, _io = new_machine("CGA")
    uc.mem_write(CRYPTO_ORIGIN, artifacts.crypto)
    uc.mem_write(artifacts.snapshot_start, b"\xD1\xE2\xF3\xA4\x5A\xA5")
    writes: list[tuple[int, int, int]] = []
    instructions = active_listing_instructions(artifacts.crypto_listing)
    stop_offsets = [
        offset
        for offset, _encoded, source in instructions
        if source == "cld" and offset > 0
    ]
    if not stop_offsets:
        raise AssertionError("cannot find post-publication CLD")
    stop_address = CRYPTO_ORIGIN + min(stop_offsets)
    stopped = False

    def stop(machine: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal stopped
        stopped = True
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

    h_stop = uc.hook_add(
        UC_HOOK_CODE, stop, begin=stop_address, end=stop_address
    )
    h_write = uc.hook_add(UC_HOOK_MEM_WRITE, track)
    for register, value in (
        (UC_X86_REG_CS, 0),
        (UC_X86_REG_DS, 0),
        (UC_X86_REG_ES, 0x7654),
        (UC_X86_REG_SS, 0),
        (UC_X86_REG_SP, saved_sp),
        (UC_X86_REG_EFLAGS, 2 | (1 << 10)),
    ):
        uc.reg_write(register, value)
    try:
        uc.emu_start(CRYPTO_ORIGIN, 0, count=100)
    finally:
        uc.hook_del(h_stop)
        uc.hook_del(h_write)
    if not stopped:
        raise AssertionError("controller publication did not reach crypto body")
    expected = [
        (artifacts.snapshot_status, 1, 0),
        (artifacts.snapshot_sp, 2, saved_sp),
        (artifacts.snapshot_sp_inverse, 2, (~saved_sp) & 0xFFFF),
        (artifacts.snapshot_inverse, 1, 0x5A),
        (artifacts.snapshot_status, 1, 0xA5),
    ]
    if writes != expected:
        raise AssertionError(f"snapshot publication order drifted: {writes!r}")
    if any(
        not (
            artifacts.snapshot_start <= address
            and address + size <= artifacts.snapshot_end
        )
        for address, size, _value in writes
    ):
        raise AssertionError("snapshot publisher wrote outside six-byte capsule")
    final = bytes(uc.mem_read(artifacts.snapshot_start, 6))
    if final != snapshot_bytes(saved_sp):
        raise AssertionError("snapshot publication value drifted")
    return writes, final


def apply_publication_prefix(
    initial: bytes,
    writes: list[tuple[int, int, int]],
    count: int,
    snapshot_start: int,
) -> bytes:
    value = bytearray(initial)
    for address, size, item in writes[:count]:
        offset = address - snapshot_start
        value[offset : offset + size] = item.to_bytes(size, "little")
    return bytes(value)


def run_gate(artifacts: Artifacts) -> dict[str, Any]:
    publications: dict[int, tuple[list[tuple[int, int, int]], bytes]] = {
        ram_top: publication_gate(artifacts, ram_top - 6)
        for ram_top in K14_RAM_TOPS
    }
    publication_writes, published = publications[RAM_TOP]
    valid_results: dict[str, dict[str, Any]] = {}
    for ram_top in K14_RAM_TOPS:
        by_backend: dict[str, Any] = {}
        for backend in ("CGA", "MDA"):
            fixture = prepare_fixture(
                artifacts,
                backend,
                valid_recovery_state=True,
                snapshot=publications[ram_top][1],
                ram_top=ram_top,
            )
            result = AbortRunner(fixture, artifacts).run()
            by_backend[backend] = assert_valid(fixture, artifacts, result)
        valid_results[f"0x{ram_top:04x}"] = by_backend

    torn_cases: list[str] = []
    initial_states = {
        "fresh": bytes(6),
        "republish": snapshot_bytes(),
    }
    for initial_name, initial in initial_states.items():
        first = 0 if initial_name == "fresh" else 1
        for prefix in range(first, len(publication_writes)):
            value = apply_publication_prefix(
                initial,
                publication_writes,
                prefix,
                artifacts.snapshot_start,
            )
            label = f"{initial_name}-publication-prefix-{prefix}"
            fixture = prepare_fixture(
                artifacts,
                "MDA" if len(torn_cases) & 1 else "CGA",
                valid_recovery_state=False,
                snapshot=value,
            )
            result = AbortRunner(fixture, artifacts).run()
            assert_emergency(fixture, artifacts, result, label)
            torn_cases.append(label)

    corruptions: list[str] = []
    for index in range(6):
        value = bytearray(published)
        value[index] ^= 1
        label = f"snapshot-byte-{index}-corrupt"
        fixture = prepare_fixture(
            artifacts,
            "MDA" if index & 1 else "CGA",
            valid_recovery_state=False,
            snapshot=bytes(value),
        )
        result = AbortRunner(fixture, artifacts).run()
        assert_emergency(fixture, artifacts, result, label)
        corruptions.append(label)

    boundary_cases = (
        ("wrong-resident-return", artifacts.resident_return ^ 1, RAM_TOP),
        ("wrong-handoff-ram-top", None, RAM_TOP + 2),
    )
    for label, root_return, ram_top in boundary_cases:
        fixture = prepare_fixture(
            artifacts,
            "CGA",
            valid_recovery_state=False,
            snapshot=published,
            root_return=root_return,
            ram_top=ram_top,
        )
        result = AbortRunner(fixture, artifacts).run()
        assert_emergency(fixture, artifacts, result, label)
        corruptions.append(label)

    # The emergency branch must be independent of the mutable BIOS video
    # selector: erase both possible vault mappings even when the BDA claims
    # the opposite adapter or contains an invalid value.
    bda_cases = (
        ("cga-with-mda-bda", "CGA", MDA_CRT_PORT),
        ("mda-with-cga-bda", "MDA", CGA_CRT_PORT),
        ("cga-with-corrupt-bda", "CGA", 0xFFFF),
    )
    invalid_snapshot = bytearray(published)
    invalid_snapshot[-2] ^= 1
    for label, backend, bda_port in bda_cases:
        fixture = prepare_fixture(
            artifacts,
            backend,
            valid_recovery_state=False,
            snapshot=bytes(invalid_snapshot),
        )
        fixture.uc.mem_write(BDA_CRT_PORT, struct.pack("<H", bda_port))
        result = AbortRunner(fixture, artifacts).run()
        assert_emergency(fixture, artifacts, result, label)
        corruptions.append(label)

    failure_specs = (
        ("scrub-load-failure", "scrub_controller", False, False),
        ("config-load-failure", "config_escrow", False, False),
        ("config-restore-failure", None, False, True),
        ("vault-load-failure", "vault_lifecycle", False, False),
        ("vault-zeroize-failure", None, True, False),
    )
    failure_results: dict[str, list[str]] = {}
    for label, fail_load, fail_zeroize, corrupt_escrow in failure_specs:
        fixture = prepare_fixture(
            artifacts,
            "CGA",
            valid_recovery_state=True,
            snapshot=published,
            corrupt_escrow=corrupt_escrow,
        )
        result = AbortRunner(
            fixture,
            artifacts,
            fail_load=fail_load,
            fail_vault_zeroize=fail_zeroize,
        ).run()
        assert_emergency(fixture, artifacts, result, label)
        failure_results[label] = list(result.load_names)

    return {
        "schema": "seed-tls13-k14-abort-capsule-gate-v1",
        "passed": True,
        "build_dir": str(artifacts.build),
        "capsule": {
            "immutable_code": (
                f"0x{artifacts.capsule_start:04x}.."
                f"0x{artifacts.snapshot_start:04x}"
            ),
            "snapshot": (
                f"0x{artifacts.snapshot_start:04x}.."
                f"0x{artifacts.snapshot_end:04x}"
            ),
            "snapshot_bytes": artifacts.snapshot_end - artifacts.snapshot_start,
            "derived_resident_return": f"0x{artifacts.resident_return:04x}",
        },
        "publication": {
            "writes_by_ram_top": {
                f"0x{ram_top:04x}": [
                    {
                        "address": f"0x{address:04x}",
                        "bytes": size,
                        "value": f"0x{value:0{size * 2}x}",
                    }
                    for address, size, value in writes
                ]
                for ram_top, (writes, _snapshot) in publications.items()
            },
            "status_written_last": True,
            "torn_prefix_rejections": len(torn_cases),
            "torn_cases": torn_cases,
        },
        "valid_abort": valid_results,
        "invalid_snapshot": {
            "rejections": len(corruptions),
            "cases": corruptions,
        },
        "recovery_failures": failure_results,
        "stackless_emergency_reset": True,
        "emergency_bda_independent": True,
        "ready_zero_before_every_recovery_load": True,
        "warm_flag_is_final_memory_write": True,
        "warm_far_reset": "FFFF:0000",
        "capsule_code_immutable": True,
        "snapshot_write_whitelist": True,
        "hostile_current_stack_and_df": True,
        "nic_callbacks_before_safe_return": 0,
        "vm_or_network_launched": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=Path,
        help="use an existing product-mode build instead of a temporary build",
    )
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
        help="optional stable JSON report path",
    )
    args = parser.parse_args()
    for path in (args.product_core, args.product_listing):
        if not path.is_file():
            raise SystemExit(f"required product input is missing: {path}")

    if args.build_dir is not None:
        artifacts = load_artifacts(
            args.build_dir.resolve(),
            args.product_core,
            args.product_listing,
        )
        report = run_gate(artifacts)
    else:
        with tempfile.TemporaryDirectory(
            prefix="seed-k14-abort-capsule-"
        ) as name:
            build = Path(name)
            subprocess.run(
                [
                    sys.executable,
                    str(BUILDER),
                    "--product-mode",
                    "--product-core",
                    str(args.product_core),
                    "--product-listing",
                    str(args.product_listing),
                    "--build-dir",
                    str(build),
                ],
                cwd=ROOT,
                check=True,
            )
            report = run_gate(
                load_artifacts(
                    build,
                    args.product_core,
                    args.product_listing,
                )
            )

    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )
    print("TLS 1.3 K14 abort-capsule gate: PASS")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
