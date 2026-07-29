#!/usr/bin/env python3
"""Offline Unicorn gate for the logical-K14 live controller state machines.

The cryptographic overlays already have exhaustive bit-exact gates.  This
checker targets the new glue around them: fragmented TCP records, ACK rewind,
zero-window boundary, register-clobber contracts, protected-flight parsing,
post-sym low-controller transition, Finished transmission, and terminal timing
output.  The live_k15 filename is historical and is not a 15-sector-K claim.
It never starts 86Box and performs no network I/O.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
    Uc,
)
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
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
DEFAULT_BUILD = ROOT / "build/crypto-bench/tls13-live-k15"
DEFAULT_IDENTITY_BUILD = ROOT / "build/crypto-bench/tls13-live-identity"
ATTEMPT6_BUILD = ROOT / "build/crypto-bench/tls13-live-k15-attempt6"
ATTEMPT6_PCAP = ATTEMPT6_BUILD / "live.pcap"
ATTEMPT6_ORACLE = ATTEMPT6_BUILD / "live-oracle.json"
LIVE_AUTH_LEAF = HERE / "issuer_auth_live_leaf.pem"
CONTROLLER_ADDR = 0x3400
AUTH_CONTROLLER_ADDR = 0x3200
AUTH_CONTROLLER_END = CONTROLLER_ADDR
AUTH_IMAGE_ADDR = 0x1800
AUTH_IMAGE_BYTES = 6592
AUTH_IMAGE_END = AUTH_IMAGE_ADDR + AUTH_IMAGE_BYTES
AUTH_IMAGE_LOAD_END = AUTH_CONTROLLER_ADDR
PROTECTED_CONTROLLER_ADDR = 0x0900
PROTECTED_CONTROLLER_END = 0x0D00
POST_CONTROLLER_ADDR = PROTECTED_CONTROLLER_ADDR
POST_CONTROLLER_END = PROTECTED_CONTROLLER_END
TRANSCRIPT_HANDOFF = 0x0D00
TRANSCRIPT_HANDOFF_END = 0x0DAB
POST_QUARANTINE = 0x0D00
POST_QUARANTINE_END = 0x0F00
POST_SCATTER_MID = 0x3600
POST_SCATTER_MID_END = 0x3838
POST_CLIENT_APP_STATE = POST_SCATTER_MID_END
POST_RECEIVED_TAG = 0x3910
POST_SCATTER_HIGH = 0x3920
POST_SCATTER_HIGH_END = 0x3B40
POST_RECORD_PLAIN_MAX = (
    POST_QUARANTINE_END
    - POST_QUARANTINE
    + POST_SCATTER_MID_END
    - POST_SCATTER_MID
    + POST_SCATTER_HIGH_END
    - POST_SCATTER_HIGH
)
POST_HEAD_COMPLETE = 0x3C41
POST_TICKET_MILESTONE = 0x3C42
POST_HTTP_TOTAL = 0x3C43
POST_HTTP_MATCH = 0x3C45
POST_HTTP_DONE = 0x3C4D
PROTECTED_LOW_GUARD_END = 0x0F00
IDENTITY_TAIL = 0x0E00
IDENTITY_TAIL_LEN = 117
IDENTITY_CV_END = IDENTITY_TAIL + 80
IDENTITY_CERT_HASH = 0x0E80
IDENTITY_SPACES = 0x0EA0
IDENTITY_CV_PTR = 0x0EC0
IDENTITY_CV_DER_LEN = 0x0EC2
IDENTITY_CV_TEMP_END = 0x0EC4
IDENTITY_DIGEST_HOLD = 0x0EE0
AUTH_INPUT_DIGEST = 0x3C30
AUTH_INPUT_SIGNATURE_LEN = 0x3C50
AUTH_INPUT_SIGNATURE = 0x3C52
AUTH_INPUT_SIGNATURE_MAX = 72
AUTH_OUTPUT_STATUS = 0x3C9A
AUTH_INPUT_END = AUTH_OUTPUT_STATUS + 1
DELTA_LOADER_ADDR = 0x0F00
TCP_TAIL_STATE_START = 0x0FE2
CORE_START_LBA = 11
PRODUCT_LOW_STATE_START = 0x0D0E
PRODUCT_LOW_STATE_END = 0x1000
HELLO_TX_STAGE_START = 0x2700
HELLO_TX_STAGE_END = 0x2800
K14_EXTENSION_START = 0x3400
K14_RUNTIME_START = 0x3510
K14_RUNTIME_END = 0x355D
K14_EXTENSION_END = 0x3600
PROTECTED_HIGH_STATE_END = 0x3CAC
PERSISTENT_SERVICES = K14_RUNTIME_END
PERSISTENT_SERVICES_LIMIT = K14_EXTENSION_END
PRODUCT_POOL_START = 0x3E40
PRODUCT_POOL_END = 0x3F00
TCP_REMOTE_ACK = 0x06F1
TCP_LOCAL_SEQ = 0x06ED
TCP_RX_PTR = 0x0FE2
TCP_RX_LEN = 0x0FE4
PARSE_TCP_PAYLOAD = 0x1522
NIC_VT_RECEIVE = 0x15E1
NIC_VT_RX_FALLBACK = 0x15E3
NE_RX_SAMPLE_COUNT = 0x06D5
RX_BUFFER = 0x0700
RX_BUFFER_END = 0x08B6
BIOS_TICK = 0x046C
NST_EARLY_DATA_EXTENSION = b"\x00\x2a\x00\x04\x00\x00\x38\x00"
NST_LIVE_UNKNOWN_EXTENSION = b"\x3a\x3a\x00\x00"
NST_LIVE_EXTENSIONS = NST_EARLY_DATA_EXTENSION + NST_LIVE_UNKNOWN_EXTENSION
NST_EXTENSION_NEGATIVES = {
    "bad-second-length": NST_EARLY_DATA_EXTENSION + b"\x3a\x3a\x00\x01",
    "truncated-second": NST_EARLY_DATA_EXTENSION + b"\x3a\x3a\x00",
    "duplicate-early-data": NST_EARLY_DATA_EXTENSION + b"\x00\x2a\x00\x00",
    "wrong-early-data-type": (
        b"\x00\x2b\x00\x04\x00\x00\x38\x00" + NST_LIVE_UNKNOWN_EXTENSION
    ),
    "wrong-early-data-length": (
        b"\x00\x2a\x00\x03\x00\x00\x38\x00" + NST_LIVE_UNKNOWN_EXTENSION
    ),
    "extra-byte": NST_LIVE_EXTENSIONS + b"\x00",
}


def load_symmetric_checker():
    """Load the existing bit-exact symmetric checker as a local oracle."""

    name = "seed_tls13_live_real_symmetric_checker"
    loaded = sys.modules.get(name)
    if loaded is not None:
        return loaded
    path = HERE / "check_tls13_sym_overlay.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load symmetric checker {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_capture_oracle():
    """Load the checked attempt-capture reconstructor without network I/O."""

    name = "seed_tls13_live_identity_capture_oracle"
    loaded = sys.modules.get(name)
    if loaded is not None:
        return loaded
    path = HERE / "live_k15_capture_oracle.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load capture oracle {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def word(machine: Uc, address: int) -> int:
    return struct.unpack("<H", machine.mem_read(address, 2))[0]


def write_word(machine: Uc, address: int, value: int) -> None:
    machine.mem_write(address, struct.pack("<H", value & 0xFFFF))


def set_carry(machine: Uc, carry: bool) -> None:
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    machine.reg_write(
        UC_X86_REG_EFLAGS,
        (flags | 1) if carry else (flags & ~1),
    )


def return_call(machine: Uc, *, carry: bool = False) -> None:
    sp = machine.reg_read(UC_X86_REG_SP) & 0xFFFF
    return_ip = word(machine, sp)
    machine.reg_write(UC_X86_REG_SP, (sp + 2) & 0xFFFF)
    set_carry(machine, carry)
    machine.reg_write(UC_X86_REG_IP, return_ip)


def read_z(machine: Uc, address: int, limit: int = 256) -> str:
    raw = bytearray()
    for offset in range(limit):
        byte = machine.mem_read(address + offset, 1)[0]
        if byte == 0:
            return raw.decode("ascii")
        raw.append(byte)
    raise AssertionError(f"unterminated controller string at {address:#x}")


def nst_extensions_are_accepted(message: bytes) -> bool:
    """Mirror the symmetric entry's narrow post-handshake extension grammar."""

    if (
        len(message) < 17
        or message[0] != 4
        or int.from_bytes(message[1:4], "big") != len(message) - 4
    ):
        return False
    nonce_len = message[12]
    offset = 13 + nonce_len
    if offset + 2 > len(message):
        return False
    identity_len = int.from_bytes(message[offset : offset + 2], "big")
    offset += 2 + identity_len
    if offset + 2 > len(message):
        return False
    extensions_len = int.from_bytes(message[offset : offset + 2], "big")
    extensions = message[offset + 2 :]
    if len(extensions) != extensions_len:
        return False
    if not extensions:
        return True
    if len(extensions) not in (8, 12):
        return False
    if (
        extensions[:2] != b"\x00\x2a"
        or extensions[2:4] != b"\x00\x04"
    ):
        return False
    return len(extensions) == 8 or (
        extensions[8:10] != b"\x00\x2a"
        and extensions[10:12] == b"\x00\x00"
    )


class Machine:
    def __init__(self, controller: bytes, *, entry: int = CONTROLLER_ADDR):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 0x10000)
        self.uc.mem_write(0, bytes(0x10000))
        self.uc.mem_write(entry, controller)
        self.entry = entry
        self.uc.reg_write(UC_X86_REG_DS, 0)
        self.uc.reg_write(UC_X86_REG_ES, 0)
        self.uc.reg_write(UC_X86_REG_SS, 0)
        self.uc.reg_write(UC_X86_REG_SP, 0x3FF0)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 2)
        self.handlers: dict[int, object] = {}
        self.failed = False
        self.done = False
        self.sym_initialized = False
        self.post_sym_writes: list[tuple[int, int, int]] = []
        self.uc.hook_add(UC_HOOK_CODE, self._dispatch)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write)
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt)

    def _dispatch(self, machine: Uc, address: int, _size: int, _user) -> None:
        handler = self.handlers.get(address)
        if handler is not None:
            handler(machine)

    def _write(
        self,
        machine: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user,
    ) -> None:
        if self.sym_initialized:
            self.post_sym_writes.append(
                (machine.reg_read(UC_X86_REG_IP) & 0xFFFF, address, size)
            )

    def _interrupt(self, _machine: Uc, intno: int, _user) -> None:
        if intno != 0x10:
            raise AssertionError(f"unexpected real-mode interrupt {intno:#x}")

    def call_handler(self, address: int, handler) -> None:
        self.handlers[address] = handler

    def fail_handler(self, address: int) -> None:
        def failed(machine: Uc) -> None:
            self.failed = True
            machine.emu_stop()

        self.handlers[address] = failed

    def run(self, count: int = 2_000_000) -> None:
        self.uc.emu_start(self.entry, 0xFFFF, count=count)


def parse_key(manifest: dict[str, object], name: str) -> int:
    phases = manifest["live_phases"]
    assert isinstance(phases, list)
    for phase in phases:
        if phase["name"] == name:
            return int(phase["key"], 0)
    raise AssertionError(f"manifest lacks {name}")


def parse_phase(manifest: dict[str, object], name: str) -> dict[str, object]:
    phases = manifest["live_phases"]
    assert isinstance(phases, list)
    for phase in phases:
        if phase["name"] == name:
            assert isinstance(phase, dict)
            return phase
    raise AssertionError(f"manifest lacks {name}")


def listing_label_address(listing: Path, label: str, origin: int) -> int:
    lines = listing.read_text(encoding="utf-8", errors="replace").splitlines()
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
            match = offset_pattern.search(candidate)
            if match:
                return origin + int(match.group(1), 16)
        break
    raise AssertionError(f"cannot resolve listing label {label!r} in {listing}")


def ranges_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def read_post_scatter(machine: Uc, length: int) -> bytes:
    if not 0 <= length <= POST_RECORD_PLAIN_MAX:
        raise AssertionError(f"post scatter read length escaped cap: {length}")
    remaining = length
    result = bytearray()
    for start, end in (
        (POST_QUARANTINE, POST_QUARANTINE_END),
        (POST_SCATTER_MID, POST_SCATTER_MID_END),
        (POST_SCATTER_HIGH, POST_SCATTER_HIGH_END),
    ):
        count = min(remaining, end - start)
        result.extend(machine.mem_read(start, count))
        remaining -= count
        if remaining == 0:
            return bytes(result)
    raise AssertionError(f"post scatter geometry lost {remaining} byte(s)")


def validate_lifetime_manifest(manifest: dict[str, object]) -> None:
    for name in ("protected_controller", "post_controller"):
        phase = parse_phase(manifest, name)
        start = int(str(phase["destination"]), 0)
        end = start + int(phase["sectors"]) * 512
        if (start, end) != (PROTECTED_CONTROLLER_ADDR, PROTECTED_CONTROLLER_END):
            raise AssertionError(
                f"{name} slot drifted: {start:#x}..{end:#x}"
            )
        if ranges_overlap((start, end), (RX_BUFFER, RX_BUFFER_END)):
            raise AssertionError(f"{name} overlaps the live NIC RX frame")
        if end > TRANSCRIPT_HANDOFF:
            raise AssertionError(f"{name} overwrites transcript/quarantine")
        if ranges_overlap((start, end), (K14_EXTENSION_START, K14_EXTENSION_END)):
            raise AssertionError(f"{name} load overwrites K14 extension")

    lifetimes = manifest.get("memory_lifetimes")
    if not isinstance(lifetimes, dict):
        raise AssertionError("manifest lacks explicit memory lifetime ledger")
    expected_loads = [
        {
            "phase": "protected_controller",
            "destination": "0x0900",
            "bytes": 1024,
        },
        {
            "phase": "post_controller",
            "destination": "0x0900",
            "bytes": 1024,
        },
    ]
    if lifetimes.get("post_sym_phase_loads") != expected_loads:
        raise AssertionError("post-sym phase-load ledger drifted")
    if lifetimes.get("product_arena_context_writes") != 0:
        raise AssertionError("manifest permits product arena/context writes")
    hello = parse_phase(manifest, "hello")
    hello_start = int(str(hello["destination"]), 0)
    hello_end = hello_start + int(hello["bytes"])
    if hello_start != 0x1800 or hello_end > HELLO_TX_STAGE_START:
        raise AssertionError(
            f"HELLO image reaches transmit stage: {hello_start:#x}..{hello_end:#x}"
        )
    expected_restore = {
        "phase": "sym",
        "destination": "0x1800",
        "bytes": HELLO_TX_STAGE_END - 0x1800,
    }
    if lifetimes.get("hello_tx_stage_restore") != expected_restore:
        raise AssertionError("HELLO transmit-stage restore ledger drifted")

    services = manifest.get("persistent_services")
    if not isinstance(services, dict):
        raise AssertionError("manifest lacks persistent service geometry")
    service_start = int(str(services["runtime_start"]), 0)
    service_end = int(str(services["runtime_end"]), 0)
    service_limit = int(str(services["runtime_limit"]), 0)
    service_bytes = int(services["bytes"])
    if not (
        service_start == PERSISTENT_SERVICES
        and service_end == service_start + service_bytes
        and service_end <= service_limit == PERSISTENT_SERVICES_LIMIT
    ):
        raise AssertionError(
            f"persistent service geometry drifted: "
            f"{service_start:#x}..{service_end:#x}/{service_limit:#x}"
        )
    if (
        services.get("borrowed_product_region") is not None
        or services.get("product_arena_context_writes") != 0
    ):
        raise AssertionError("persistent services borrow the product pool")
    if ranges_overlap((service_start, service_end), (PRODUCT_POOL_START, PRODUCT_POOL_END)):
        raise AssertionError("persistent services overlap product arena/context")
    if ranges_overlap((service_start, service_end), (K14_RUNTIME_START, K14_RUNTIME_END)):
        raise AssertionError("persistent services overlap symmetric runtime")

    pre_sym = manifest.get("pre_sym_transition")
    if not isinstance(pre_sym, dict):
        raise AssertionError("manifest lacks pre-sym transition geometry")
    pre_start = int(str(pre_sym["runtime_start"]), 0)
    pre_end = int(str(pre_sym["runtime_end"]), 0)
    if not (
        pre_start == DELTA_LOADER_ADDR
        and pre_start < pre_end <= TCP_TAIL_STATE_START
        and pre_sym.get("installed_after_endpoint_dns") is True
        and pre_sym.get("loads_only_0x3400_controllers") is True
    ):
        raise AssertionError("pre-sym transition geometry drifted")

    delta = manifest.get("critical_delta_loader")
    if not isinstance(delta, dict):
        raise AssertionError("manifest lacks critical delta-loader geometry")
    runtime_start_text, runtime_end_text = str(delta["runtime_range"]).split("..")
    runtime_start = int(runtime_start_text, 0)
    runtime_end = int(runtime_end_text, 0)
    source_start_text, source_end_text = str(
        delta["embedded_controller_range"]
    ).split("..")
    source_start = int(source_start_text, 0)
    source_end = int(source_end_text, 0)
    if not (
        runtime_start == DELTA_LOADER_ADDR
        and TRANSCRIPT_HANDOFF_END <= runtime_start < runtime_end
        and runtime_end <= TCP_TAIL_STATE_START
        and source_start >= K14_EXTENSION_START
        and source_end <= K14_EXTENSION_END
        and source_end - source_start == runtime_end - runtime_start
    ):
        raise AssertionError(
            "critical delta-loader source/runtime geometry is unsafe"
        )
    required_delta_flags = (
        "resident_phase_key_input",
        "track_batched",
        "single_sector_fallback",
        "copied_before_candidate_load",
        "embedded_source_dead_before_sym_init",
    )
    if (
        any(delta.get(name) is not True for name in required_delta_flags)
        or delta.get("absolute_lba_base") != CORE_START_LBA
    ):
        raise AssertionError("critical delta-loader contract drifted")
    disk = delta.get("critical_disk_layout")
    if not isinstance(disk, dict):
        raise AssertionError("manifest lacks critical track layout")
    candidate = parse_phase(manifest, "candidate")
    sym = parse_phase(manifest, "sym")
    protected = parse_phase(manifest, "protected_controller")
    post = parse_phase(manifest, "post_controller")
    candidate_lba = CORE_START_LBA + int(candidate["start_sector"])
    sym_lba = CORE_START_LBA + int(sym["start_sector"])
    protected_lba = CORE_START_LBA + int(protected["start_sector"])
    post_lba = CORE_START_LBA + int(post["start_sector"])
    if disk != {
        "sectors_per_track": 8,
        "alignment_padding_sectors": 5,
        "candidate_absolute_lba": candidate_lba,
        "candidate_batch_calls": 1,
        "symmetric_restore_absolute_lba": sym_lba,
        "symmetric_restore_sectors": 8,
        "symmetric_restore_batch_calls": 1,
        "protected_controller_absolute_lba": protected_lba,
        "protected_controller_batch_calls": 1,
        "post_controller_absolute_lba": post_lba,
        "post_controller_batch_calls": 1,
    }:
        raise AssertionError(f"critical track layout drifted: {disk!r}")
    if (
        candidate_lba % 8
        or sym_lba % 8
        or protected_lba % 8 + int(protected["sectors"]) > 8
        or post_lba % 8 + int(post["sectors"]) > 8
    ):
        raise AssertionError("critical phase crosses an advertised track batch")


def validate_identity_manifest(
    manifest: dict[str, object],
) -> dict[str, object]:
    """Validate the opt-in three-sector capture and post-socket auth phases."""

    phases = manifest.get("live_phases")
    if not isinstance(phases, list):
        raise AssertionError("identity manifest lacks phase ledger")
    names = [phase.get("name") for phase in phases if isinstance(phase, dict)]
    required_names = (
        "protected_controller",
        "post_controller",
        "sym",
        "auth_controller",
        "auth_track_pad",
        "auth",
    )
    if any(names.count(name) != 1 for name in required_names):
        raise AssertionError("identity manifest lacks unique auth/capture phases")
    for left, right in zip(phases, phases[1:]):
        if not isinstance(left, dict) or not isinstance(right, dict):
            raise AssertionError("identity manifest contains a non-object phase")
        if int(left["start_sector"]) + int(left["sectors"]) != int(
            right["start_sector"]
        ):
            raise AssertionError("identity phase ledger is not contiguous")
    for phase in phases:
        assert isinstance(phase, dict)
        start = int(phase["start_sector"])
        sectors = int(phase["sectors"])
        expected_key = (sectors << 8) | start
        if int(str(phase["key"]), 0) != expected_key:
            raise AssertionError(f"identity phase key drifted: {phase['name']}")

    protected = parse_phase(manifest, "protected_controller")
    post = parse_phase(manifest, "post_controller")
    sym = parse_phase(manifest, "sym")
    auth_controller = parse_phase(manifest, "auth_controller")
    auth = parse_phase(manifest, "auth")
    expected_geometry = {
        "protected_controller": (0x0900, 3, 1536),
        "post_controller": (0x0900, 2, 1024),
        "auth_controller": (AUTH_CONTROLLER_ADDR, 1, 512),
        "auth": (AUTH_IMAGE_ADDR, 13, 13 * 512),
    }
    for name, phase in (
        ("protected_controller", protected),
        ("post_controller", post),
        ("auth_controller", auth_controller),
        ("auth", auth),
    ):
        destination, sectors, capacity = expected_geometry[name]
        if (
            int(str(phase["destination"]), 0) != destination
            or int(phase["sectors"]) != sectors
            or not 0 < int(phase["bytes"]) <= capacity
        ):
            raise AssertionError(f"identity {name} geometry drifted")
    if (
        int(sym["start_sector"]) + int(sym["sectors"])
        != int(auth_controller["start_sector"])
    ):
        raise AssertionError("identity auth controller does not follow symmetric phase")
    if not (
        int(auth_controller["start_sector"])
        + int(auth_controller["sectors"])
        <= int(auth["start_sector"])
    ):
        raise AssertionError("identity auth image overlaps its controller")
    auth_image_start = int(str(auth["destination"]), 0)
    auth_image_end = auth_image_start + int(auth["bytes"])
    auth_load_end = auth_image_start + int(auth["sectors"]) * 512
    auth_controller_start = int(str(auth_controller["destination"]), 0)
    auth_controller_end = (
        auth_controller_start + int(auth_controller["sectors"]) * 512
    )
    if (
        int(auth["bytes"]) != AUTH_IMAGE_BYTES
        or auth_image_end != AUTH_IMAGE_END
        or auth_load_end != AUTH_IMAGE_LOAD_END
    ):
        raise AssertionError(
            "identity auth executable/load boundary drifted: "
            f"image={auth_image_start:#x}..{auth_image_end:#x} "
            f"load_end={auth_load_end:#x}"
        )
    if ranges_overlap(
        (auth_controller_start, auth_controller_end),
        (auth_image_start, auth_image_end),
    ):
        raise AssertionError("identity auth controller overlaps auth executable")
    if auth_load_end > auth_controller_start:
        raise AssertionError("identity auth sector load overwrites its controller")

    lifetimes = manifest.get("memory_lifetimes")
    if not isinstance(lifetimes, dict):
        raise AssertionError("identity manifest lacks memory lifetime ledger")
    if lifetimes.get("product_arena_context_writes") != 0:
        raise AssertionError("identity manifest permits product pool writes")
    expected_loads = [
        {
            "phase": "protected_controller",
            "destination": "0x0900",
            "bytes": 1536,
        },
        {
            "phase": "post_controller",
            "destination": "0x0900",
            "bytes": 1024,
        },
    ]
    if lifetimes.get("post_sym_phase_loads") != expected_loads:
        raise AssertionError("identity post-sym load ledger drifted")

    services = manifest.get("persistent_services")
    if not isinstance(services, dict):
        raise AssertionError("identity manifest lacks persistent services")
    service_start = int(str(services["runtime_start"]), 0)
    service_end = int(str(services["runtime_end"]), 0)
    if not (
        service_start == PERSISTENT_SERVICES
        and service_start < service_end <= PERSISTENT_SERVICES_LIMIT
        and int(services["bytes"]) == service_end - service_start
        and services.get("product_arena_context_writes") == 0
        and services.get("borrowed_product_region") is None
    ):
        raise AssertionError("identity persistent service geometry drifted")
    if ranges_overlap(
        (auth_controller_start, auth_controller_end),
        (service_start, service_end),
    ):
        raise AssertionError(
            "identity auth controller load overwrites persistent transition"
        )

    delta = manifest.get("critical_delta_loader")
    if not isinstance(delta, dict):
        raise AssertionError("identity manifest lacks delta loader")
    runtime_start_text, runtime_end_text = str(delta["runtime_range"]).split("..")
    runtime_start = int(runtime_start_text, 0)
    runtime_end = int(runtime_end_text, 0)
    if not (
        runtime_start == DELTA_LOADER_ADDR
        and runtime_start < runtime_end <= TCP_TAIL_STATE_START
        and delta.get("track_batched") is True
        and delta.get("single_sector_fallback") is True
    ):
        raise AssertionError("identity delta loader geometry drifted")

    disk = delta.get("critical_disk_layout")
    if not isinstance(disk, dict):
        raise AssertionError("identity manifest lacks disk layout")
    protected_lba = CORE_START_LBA + int(protected["start_sector"])
    post_lba = CORE_START_LBA + int(post["start_sector"])
    auth_lba = CORE_START_LBA + int(auth["start_sector"])
    if (
        disk.get("protected_controller_absolute_lba") != protected_lba
        or disk.get("post_controller_absolute_lba") != post_lba
        or protected_lba % 8 + int(protected["sectors"]) > 8
        or post_lba % 8 + int(post["sectors"]) > 8
        or auth_lba % 8
    ):
        raise AssertionError("identity track-batched phase geometry drifted")

    return {
        "detected_from_auth_phases": True,
        "protected_slot": "0x0900..0x0f00",
        "tail_quarantine": "0x0e00..0x0e75",
        "post_controller_slot": "0x0900..0x0d00",
        "auth_controller_key": auth_controller["key"],
        "auth_controller_slot": (
            f"0x{auth_controller_start:04x}..0x{auth_controller_end:04x}"
        ),
        "auth_image_key": auth["key"],
        "auth_image_executable": (
            f"0x{auth_image_start:04x}..0x{auth_image_end:04x}"
        ),
        "auth_image_sector_load": (
            f"0x{auth_image_start:04x}..0x{auth_load_end:04x}"
        ),
        "persistent_caller_disjoint": True,
        "auth_absolute_lba": auth_lba,
        "auth_sectors": int(auth["sectors"]),
        "product_arena_context_writes": 0,
    }


def identity_manifest_negative_controls(
    manifest: dict[str, object],
) -> list[str]:
    """Require the manifest gate to reject both old and low overlap slots."""

    rejected: list[str] = []
    for name, destination in (
        ("legacy-auth-controller-overwrites-persistent-caller", "0x3400"),
        ("low-auth-controller-overlaps-auth-image", "0x3100"),
    ):
        mutated = copy.deepcopy(manifest)
        parse_phase(mutated, "auth_controller")["destination"] = destination
        try:
            validate_identity_manifest(mutated)
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError(
                f"identity manifest negative control {name!r} was accepted"
            )

    short_auth = copy.deepcopy(manifest)
    parse_phase(short_auth, "auth")["bytes"] = AUTH_IMAGE_BYTES - 1
    try:
        validate_identity_manifest(short_auth)
    except AssertionError:
        rejected.append("auth-executable-end-before-0x31c0")
    else:
        raise AssertionError(
            "identity manifest accepted auth executable ending before 0x31c0"
        )
    return rejected


def lifetime_negative_controls(manifest: dict[str, object]) -> list[str]:
    controls = (
        ("legacy-extension-reload", "0x3400", 2),
        ("rx-overlap", "0x0800", 2),
        ("transcript-overlap", "0x0c00", 2),
    )
    rejected: list[str] = []
    for name, destination, sectors in controls:
        mutated = copy.deepcopy(manifest)
        phase = parse_phase(mutated, "protected_controller")
        phase["destination"] = destination
        phase["sectors"] = sectors
        try:
            validate_lifetime_manifest(mutated)
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError(f"lifetime negative control {name!r} was accepted")
    arena_services = copy.deepcopy(manifest)
    services = arena_services["persistent_services"]
    assert isinstance(services, dict)
    services["runtime_start"] = "0x3e40"
    services["runtime_end"] = f"0x{0x3E40 + int(services['bytes']):04x}"
    services["runtime_limit"] = "0x3f00"
    services["borrowed_product_region"] = "chat arena/context pool"
    services["product_arena_context_writes"] = int(services["bytes"])
    try:
        validate_lifetime_manifest(arena_services)
    except AssertionError:
        rejected.append("legacy-arena-service-placement")
    else:
        raise AssertionError("legacy arena-service negative control was accepted")

    quarantine_overlap = copy.deepcopy(manifest)
    phase = parse_phase(quarantine_overlap, "post_controller")
    phase["sectors"] = 3
    try:
        validate_lifetime_manifest(quarantine_overlap)
    except AssertionError:
        rejected.append("post-controller-quarantine-overlap")
    else:
        raise AssertionError("post-controller quarantine overlap was accepted")
    hello_growth = copy.deepcopy(manifest)
    phase = parse_phase(hello_growth, "hello")
    phase["bytes"] = HELLO_TX_STAGE_START - 0x1800 + 1
    try:
        validate_lifetime_manifest(hello_growth)
    except AssertionError:
        rejected.append("hello-image-growth-into-tx-stage")
    else:
        raise AssertionError("HELLO image-growth negative control was accepted")

    short_restore = copy.deepcopy(manifest)
    lifetimes = short_restore["memory_lifetimes"]
    assert isinstance(lifetimes, dict)
    restore = lifetimes["hello_tx_stage_restore"]
    assert isinstance(restore, dict)
    restore["bytes"] = int(restore["bytes"]) - 1
    try:
        validate_lifetime_manifest(short_restore)
    except AssertionError:
        rejected.append("short-hello-tx-stage-restore")
    else:
        raise AssertionError("short HELLO-stage restore negative control was accepted")
    return rejected


def diagnostic_service_island_gate(
    low_services: bytes,
    manifest: dict[str, object],
) -> dict[str, object]:
    services = manifest["persistent_services"]
    assert isinstance(services, dict)
    start = int(str(services["runtime_start"]), 0)
    end = int(str(services["runtime_end"]), 0)
    if end - start != len(low_services):
        raise AssertionError("persistent service artifact length drifted")
    if start != K14_RUNTIME_END or end > K14_EXTENSION_END:
        raise AssertionError("persistent services escaped K14 extension tail")
    if ranges_overlap((start, end), (K14_RUNTIME_START, K14_RUNTIME_END)):
        raise AssertionError("persistent services overlap symmetric runtime")
    if ranges_overlap((start, end), (PRODUCT_POOL_START, PRODUCT_POOL_END)):
        raise AssertionError("persistent services overlap arena/context")
    return {
        "runtime_range": f"0x{start:04x}..0x{end:04x}",
        "symmetric_runtime_disjoint": True,
        "product_arena_context_disjoint": True,
        "status": "pass",
    }


def run_low_next_transition(
    low_services: bytes,
    manifest: dict[str, object],
    *,
    inject_legacy_rx_stage: bool = False,
) -> dict[str, object]:
    low = manifest["pre_sym_transition"]
    assert isinstance(low, dict)
    entry = int(str(low["runtime_start"]), 0)
    if entry != DELTA_LOADER_ADDR:
        raise AssertionError(f"pre-sym transition entry drifted: {entry:#x}")
    if int(low["bytes"]) != len(low_services):
        raise AssertionError("pre-sym transition artifact length drifted")

    machine = Machine(low_services, entry=entry)
    raw_c = bytes((index * 31 + 9) & 0xFF for index in range(0x0D00 - 0x08C0))
    machine.uc.mem_write(0x08C0, raw_c)
    machine.uc.reg_write(UC_X86_REG_AX, parse_key(manifest, "crypto_controller"))
    loaded_destination: int | None = None
    legacy_guard_triggered = False

    def load_phase(machine_uc: Uc) -> None:
        nonlocal loaded_destination, legacy_guard_triggered
        loaded_destination = machine_uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        if loaded_destination != CONTROLLER_ADDR:
            machine.failed = True
            machine_uc.emu_stop()
            return
        if inject_legacy_rx_stage:
            machine_uc.mem_write(RX_BUFFER, bytes(512))
            legacy_guard_triggered = (
                bytes(machine_uc.mem_read(0x08C0, len(raw_c))) != raw_c
            )
            machine.done = True
            machine_uc.emu_stop()
            return
        machine_uc.mem_write(CONTROLLER_ADDR, b"\x90" * 512)
        return_call(machine_uc)

    machine.call_handler(0x10C4, load_phase)

    def next_entry(machine_uc: Uc) -> None:
        machine.done = True
        machine_uc.emu_stop()

    machine.call_handler(CONTROLLER_ADDR, next_entry)
    machine.run()

    if inject_legacy_rx_stage:
        if not legacy_guard_triggered:
            raise AssertionError("legacy 0x0700 staging negative did not corrupt sentinel")
        return {
            "legacy_0x0700_sector_stage_rejected": True,
            "status": "pass",
        }
    if machine.failed or not machine.done:
        raise AssertionError("pre-sym next-controller transition failed")
    if bytes(machine.uc.mem_read(0x08C0, len(raw_c))) != raw_c:
        raise AssertionError("HELLO-to-crypto transition changed raw ML-KEM ciphertext")
    return {
        "load_destination": f"0x{loaded_destination:04x}",
        "candidate_ciphertext": "0x08c0..0x0d00 preserved",
        "arena_context_writes": 0,
        "status": "pass",
    }


def test_hello(
    controller: bytes,
    manifest: dict[str, object],
) -> dict[str, object]:
    machine = Machine(controller)
    pre_sym = manifest["pre_sym_transition"]
    assert isinstance(pre_sym, dict)
    low_next = int(pre_sym["runtime_start"], 0)

    stubs = {
        "fresh": 0x0500,
        "next_fragment": 0x0502,
        "fragment_done": 0x0504,
        "rewind": 0x0506,
        "server_begin": 0x0508,
        "server_feed": 0x050A,
        "server_finish": 0x050C,
        "cached_connect": 0x050E,
        "zero_window": 0x0510,
        "relocate_pending": 0x0512,
        "fragment_prehashed": 0x0514,
    }
    table = [0] * 14
    table[0] = stubs["fresh"]
    table[2] = stubs["next_fragment"]
    table[3] = stubs["fragment_done"]
    table[4] = stubs["rewind"]
    table[5] = stubs["server_begin"]
    table[6] = stubs["server_feed"]
    table[7] = stubs["server_finish"]
    table[9] = stubs["cached_connect"]
    table[10] = stubs["zero_window"]
    table[12] = stubs["relocate_pending"]
    table[13] = stubs["fragment_prehashed"]
    machine.uc.mem_write(0x1830, struct.pack("<14H", *table))

    fragments = (
        bytes((index * 13 + 5) & 0xFF for index in range(147)),
        bytes((index * 17 + 9) & 0xFF for index in range(32)),
    )
    fragment_sources = (RX_BUFFER, 0x08C0)
    fragment_index = 0
    pending_pointer: int | None = None
    pending_length = 0
    rewind_calls = 0
    published: list[tuple[int, int]] = []
    ordered_events: list[str] = []
    sent: list[bytes] = []
    sent_pointers: list[int] = []
    fed = bytearray()
    zero_ack: int | None = None
    transitioned_key: int | None = None
    acknowledgements = 0

    body = bytes((index * 37 + 11) & 0xFF for index in range(1210))
    record = b"\x16\x03\x03\x04\xba" + body
    protected_tail = b"\x17\x03\x03\x00\x35TAIL!"
    cuts = (2, 401, 887, len(record) + len(protected_tail))
    combined = record + protected_tail
    frames: list[bytes] = []
    start = 0
    for end in cuts:
        frames.append(combined[start:end])
        start = end
    initial_ack = 0x12345678
    machine.uc.mem_write(TCP_REMOTE_ACK, initial_ack.to_bytes(4, "big"))
    receive_index = 0

    def ok(machine_uc: Uc) -> None:
        return_call(machine_uc)

    def fresh(machine_uc: Uc) -> None:
        ordered_events.append("fresh")
        return_call(machine_uc)

    machine.call_handler(stubs["fresh"], fresh)

    def cached_connect(machine_uc: Uc) -> None:
        ordered_events.append("connect")
        if fragment_index != 0 or pending_pointer != HELLO_TX_STAGE_START:
            return_call(machine_uc, carry=True)
            return
        if (
            bytes(
                machine_uc.mem_read(
                    HELLO_TX_STAGE_START,
                    len(fragments[0]),
                )
            )
            != fragments[0]
        ):
            return_call(machine_uc, carry=True)
            return
        # The real cached opener builds SYN and receives SYN-ACK at 0x0700.
        machine_uc.mem_write(
            RX_BUFFER,
            b"SYN-SYNACK-FRAME".ljust(len(fragments[0]), b"\xCC"),
        )
        return_call(machine_uc)

    machine.call_handler(stubs["cached_connect"], cached_connect)
    machine.call_handler(stubs["server_begin"], ok)

    def next_fragment(machine_uc: Uc) -> None:
        nonlocal pending_pointer, pending_length
        if pending_pointer is not None:
            machine_uc.reg_write(UC_X86_REG_SI, pending_pointer)
            machine_uc.reg_write(UC_X86_REG_CX, pending_length)
            machine_uc.reg_write(UC_X86_REG_AX, 1)
        elif fragment_index >= len(fragments):
            machine_uc.reg_write(UC_X86_REG_AX, 0)
            machine_uc.reg_write(UC_X86_REG_CX, 0)
        else:
            payload = fragments[fragment_index]
            source = fragment_sources[fragment_index]
            published.append((rewind_calls, fragment_index))
            ordered_events.append(
                f"{'replay' if rewind_calls else 'prehash'}-{fragment_index}"
            )
            machine_uc.mem_write(source, payload)
            pending_pointer = source
            pending_length = len(payload)
            machine_uc.reg_write(UC_X86_REG_SI, source)
            machine_uc.reg_write(UC_X86_REG_CX, len(payload))
            machine_uc.reg_write(UC_X86_REG_AX, 1)
        return_call(machine_uc)

    machine.call_handler(stubs["next_fragment"], next_fragment)

    def fragment_done(machine_uc: Uc) -> None:
        nonlocal fragment_index, pending_pointer, pending_length
        if pending_pointer is None or rewind_calls == 0:
            return_call(machine_uc, carry=True)
            return
        ordered_events.append(
            f"sent-{fragment_index}"
        )
        pending_pointer = None
        pending_length = 0
        fragment_index += 1
        return_call(machine_uc)

    machine.call_handler(stubs["fragment_done"], fragment_done)

    def fragment_prehashed(machine_uc: Uc) -> None:
        nonlocal fragment_index, pending_pointer, pending_length
        if pending_pointer is None or rewind_calls != 0:
            return_call(machine_uc, carry=True)
            return
        ordered_events.append(f"hashed-{fragment_index}")
        pending_pointer = None
        pending_length = 0
        fragment_index += 1
        return_call(machine_uc)

    machine.call_handler(stubs["fragment_prehashed"], fragment_prehashed)

    def rewind(machine_uc: Uc) -> None:
        nonlocal fragment_index, rewind_calls, pending_pointer, pending_length
        if fragment_index != len(fragments) or pending_pointer is not None:
            return_call(machine_uc, carry=True)
            return
        rewind_calls += 1
        fragment_index = 0
        pending_pointer = None
        pending_length = 0
        ordered_events.append("rewind")
        return_call(machine_uc)

    machine.call_handler(stubs["rewind"], rewind)

    def relocate_pending(machine_uc: Uc) -> None:
        nonlocal pending_pointer
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        if (
            pending_pointer is None
            or pointer != HELLO_TX_STAGE_START
            or count != pending_length
            or bytes(machine_uc.mem_read(pointer, count)) != fragments[0]
        ):
            return_call(machine_uc, carry=True)
            return
        pending_pointer = pointer
        ordered_events.append("relocate-pending")
        return_call(machine_uc)

    machine.call_handler(stubs["relocate_pending"], relocate_pending)

    def server_feed(machine_uc: Uc) -> None:
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        fed.extend(machine_uc.mem_read(pointer, count))
        # Match the real HELLO feed contract: SHA update consumes SI/CX and
        # its parser clobbers DX.
        machine_uc.reg_write(UC_X86_REG_SI, (pointer + count) & 0xFFFF)
        machine_uc.reg_write(UC_X86_REG_CX, 0)
        machine_uc.reg_write(UC_X86_REG_DX, 0xDEAD)
        return_call(machine_uc)

    machine.call_handler(stubs["server_feed"], server_feed)

    def server_finish(machine_uc: Uc) -> None:
        if bytes(fed) != body:
            return_call(machine_uc, carry=True)
            return
        return_call(machine_uc)

    machine.call_handler(stubs["server_finish"], server_finish)

    def tcp_send(machine_uc: Uc) -> None:
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        sent_pointers.append(pointer)
        # Match the dangerous first action in the real resident send path:
        # Ethernet/IP/TCP headers are built at 0x0700 before the payload copy.
        # A source still pointing at 0x0700 would therefore become a nested
        # guest frame rather than the ClientHello prefix.
        machine_uc.mem_write(RX_BUFFER, b"OUTER-FRAME-HEADER".ljust(54, b"\xA5"))
        sent.append(bytes(machine_uc.mem_read(pointer, count)))
        return_call(machine_uc)

    machine.call_handler(0x13BF, tcp_send)

    def tcp_receive(machine_uc: Uc) -> None:
        nonlocal receive_index
        if receive_index >= len(frames):
            return_call(machine_uc, carry=True)
            return
        payload = frames[receive_index]
        receive_index += 1
        machine_uc.mem_write(RX_BUFFER, payload)
        write_word(machine_uc, TCP_RX_PTR, RX_BUFFER)
        write_word(machine_uc, TCP_RX_LEN, len(payload))
        ack = int.from_bytes(machine_uc.mem_read(TCP_REMOTE_ACK, 4), "big")
        machine_uc.mem_write(
            TCP_REMOTE_ACK,
            ((ack + len(payload)) & 0xFFFFFFFF).to_bytes(4, "big"),
        )
        write_word(machine_uc, BIOS_TICK, 0x0100 + receive_index)
        return_call(machine_uc)

    machine.call_handler(0x14ED, tcp_receive)

    def tcp_ack(machine_uc: Uc) -> None:
        nonlocal acknowledgements
        acknowledgements += 1
        return_call(machine_uc)

    machine.call_handler(0x13A6, tcp_ack)

    def zero_window(machine_uc: Uc) -> None:
        nonlocal zero_ack
        zero_ack = int.from_bytes(machine_uc.mem_read(TCP_REMOTE_ACK, 4), "big")
        return_call(machine_uc)

    machine.call_handler(stubs["zero_window"], zero_window)

    def next_controller(machine_uc: Uc) -> None:
        nonlocal transitioned_key
        transitioned_key = machine_uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        machine.done = True
        machine_uc.emu_stop()

    machine.call_handler(low_next, next_controller)
    machine.run()
    expected_key = parse_key(manifest, "crypto_controller")
    expected_ack = (initial_ack + len(record)) & 0xFFFFFFFF
    if machine.failed or not machine.done:
        raise AssertionError("HELLO controller reached the low fail path")
    if sent != list(fragments):
        raise AssertionError("HELLO controller send/consume sequencing drifted")
    if published != [(0, 0), (0, 1), (1, 0), (1, 1)]:
        raise AssertionError(
            f"HELLO prehash/replay iterator sequencing drifted: {published!r}"
        )
    if ordered_events.index("connect") < ordered_events.index("rewind"):
        raise AssertionError("cached TCP connect ran before offline ClientHello hash")
    if ordered_events.index("connect") < ordered_events.index("replay-0"):
        raise AssertionError("first replay fragment was not staged before SYN")
    if ordered_events.index("connect") < ordered_events.index("relocate-pending"):
        raise AssertionError("pending replay ownership was not relocated before SYN")
    if ordered_events.index("sent-0") < ordered_events.index("connect"):
        raise AssertionError("ClientHello transmitted before cached TCP connect")
    if sent_pointers != [HELLO_TX_STAGE_START, fragment_sources[1]]:
        raise AssertionError(
            f"HELLO transmit staging drifted: {sent_pointers!r}"
        )
    if (
        bytes(machine.uc.mem_read(HELLO_TX_STAGE_START, len(fragments[0])))
        != fragments[0]
    ):
        raise AssertionError("HELLO prefix staging was not preserved")
    legacy = bytearray(fragments[0])
    legacy[:54] = b"OUTER-FRAME-HEADER".ljust(54, b"\xA5")
    if bytes(legacy) == fragments[0]:
        raise AssertionError("legacy overlapping-source negative did not corrupt prefix")
    if bytes(fed) != body:
        raise AssertionError("HELLO controller did not feed the exact ServerHello body")
    if zero_ack != expected_ack:
        raise AssertionError(
            f"HELLO zero-window ACK={zero_ack!r}, expected {expected_ack:#x}"
        )
    if transitioned_key != expected_key:
        raise AssertionError("HELLO controller selected the wrong successor")
    return {
        "fragmented_server_hello_bytes": len(record),
        "coalesced_protected_tail_bytes": len(protected_tail),
        "zero_window_ack": f"0x{zero_ack:08x}",
        "ordinary_ack_calls": acknowledgements,
        "feed_clobbered_si_cx_dx": True,
        "client_prefix_stage": (
            f"0x{HELLO_TX_STAGE_START:04x}.."
            f"0x{HELLO_TX_STAGE_START + len(fragments[0]):04x}"
        ),
        "client_hello_full_offline_hash_passes": 1,
        "client_hello_replay_hash_disabled": True,
        "first_replay_fragment_staged_before_syn": True,
        "pending_replay_pointer_after_syn": (
            f"0x{sent_pointers[0]:04x}"
        ),
        "iterator_publications": [
            "prehash-0",
            "prehash-1",
            "replay-0",
            "replay-1",
        ],
        "overlapping_tx_source_negative": "rejected",
        "status": "pass",
    }


def test_hello_oversized_stage_rejected(
    controller: bytes,
    manifest: dict[str, object],
) -> dict[str, object]:
    machine = Machine(controller)

    fresh = 0x0500
    next_fragment = 0x0502
    fragment_done = 0x0504
    rewind = 0x0506
    cached_connect = 0x0508
    fragment_prehashed = 0x050A
    table = [0] * 14
    table[0] = fresh
    table[2] = next_fragment
    table[3] = fragment_done
    table[4] = rewind
    table[9] = cached_connect
    table[13] = fragment_prehashed
    machine.uc.mem_write(0x1830, struct.pack("<14H", *table))

    def ok(machine_uc: Uc) -> None:
        return_call(machine_uc)

    machine.call_handler(fresh, ok)
    replay = False
    consumed = False

    def oversized(machine_uc: Uc) -> None:
        if replay:
            machine_uc.mem_write(RX_BUFFER, bytes(257))
            machine_uc.reg_write(UC_X86_REG_SI, RX_BUFFER)
            machine_uc.reg_write(UC_X86_REG_CX, 257)
            machine_uc.reg_write(UC_X86_REG_AX, 1)
        elif consumed:
            machine_uc.reg_write(UC_X86_REG_AX, 0)
            machine_uc.reg_write(UC_X86_REG_CX, 0)
        else:
            machine_uc.mem_write(RX_BUFFER, b"x")
            machine_uc.reg_write(UC_X86_REG_SI, RX_BUFFER)
            machine_uc.reg_write(UC_X86_REG_CX, 1)
            machine_uc.reg_write(UC_X86_REG_AX, 1)
        return_call(machine_uc)

    machine.call_handler(next_fragment, oversized)

    def consumed_fragment(machine_uc: Uc) -> None:
        nonlocal consumed
        consumed = True
        return_call(machine_uc)

    machine.call_handler(fragment_done, consumed_fragment)
    machine.call_handler(fragment_prehashed, consumed_fragment)

    def rewind_iterator(machine_uc: Uc) -> None:
        nonlocal replay
        replay = True
        return_call(machine_uc)

    machine.call_handler(rewind, rewind_iterator)

    def unexpected_send(machine_uc: Uc) -> None:
        machine.done = True
        machine_uc.emu_stop()

    machine.call_handler(0x13BF, unexpected_send)
    machine.run()
    if machine.done:
        raise AssertionError("257-byte overlapping HELLO source was not rejected")
    return {
        "overlapping_source_bytes": 257,
        "stage_capacity_bytes": HELLO_TX_STAGE_END - HELLO_TX_STAGE_START,
        "tcp_send_called": False,
        "status": "pass",
    }


def run_crypto_transition(
    crypto_controller: bytes,
    protected_controller: bytes,
    delta_loader: bytes,
    manifest: dict[str, object],
    *,
    inject_legacy_extension_reload: bool = False,
) -> dict[str, object]:
    machine = Machine(crypto_controller)
    delta_meta = manifest["critical_delta_loader"]
    assert isinstance(delta_meta, dict)
    if (
        len(delta_loader) != int(delta_meta["source_image_bytes"])
        or hashlib.sha256(delta_loader).hexdigest()
        != delta_meta["source_image_sha256"]
    ):
        raise AssertionError("critical delta-loader artifact hash drifted")
    low = manifest["persistent_services"]
    assert isinstance(low, dict)
    low_fail = int(low["fail"], 0)
    machine.fail_handler(low_fail)

    stubs = {
        "candidate": 0x1800,
        "init": 0x0520,
        "critical": 0x0522,
        "import": 0x0524,
        "receive": 0x0526,
    }
    table = [0] * 16
    table[0] = stubs["init"]
    table[3] = stubs["critical"]
    table[15] = stubs["import"]
    machine.uc.mem_write(0x1820, struct.pack("<16H", *table))
    write_word(machine.uc, 0x15E1, stubs["receive"])

    rx_guard = bytes([0xA5]) * (0x08C0 - RX_BUFFER_END)
    controller_guard = bytes([0xA6]) * (PROTECTED_CONTROLLER_ADDR - 0x08E0)
    after_guard = bytes([0x5A]) * (
        PROTECTED_LOW_GUARD_END - PROTECTED_CONTROLLER_END
    )
    machine.uc.mem_write(RX_BUFFER_END, rx_guard)
    machine.uc.mem_write(0x08E0, controller_guard)
    machine.uc.mem_write(PROTECTED_CONTROLLER_END, after_guard)
    service_start = int(str(low["runtime_start"]), 0)
    service_end = int(str(low["runtime_end"]), 0)
    service_guard = bytes(
        machine.uc.mem_read(service_start, service_end - service_start)
    )

    events: list[str] = []
    loads: list[tuple[int, int, int]] = []
    candidate_secret = bytes((index * 29 + 7) & 0xFF for index in range(32))
    runtime_pattern = bytes((index * 11 + 3) & 0xFF for index in range(
        K14_RUNTIME_END - K14_RUNTIME_START
    ))
    extension_snapshot: bytes | None = None
    negative_guard_triggered = False

    candidate_phase = parse_phase(manifest, "candidate")
    sym_phase = parse_phase(manifest, "sym")
    protected_phase = parse_phase(manifest, "protected_controller")
    expected_loads = [
        (
            CORE_START_LBA + int(candidate_phase["start_sector"]),
            int(candidate_phase["sectors"]),
            0x1800,
        ),
        (
            CORE_START_LBA + int(sym_phase["start_sector"]),
            8,
            0x1800,
        ),
        (
            CORE_START_LBA + int(protected_phase["start_sector"]),
            int(protected_phase["sectors"]),
            PROTECTED_CONTROLLER_ADDR,
        ),
    ]

    def unexpected_resident_load(machine_uc: Uc) -> None:
        machine.failed = True
        machine_uc.emu_stop()

    machine.call_handler(0x10C4, unexpected_resident_load)

    def load_phase(machine_uc: Uc) -> None:
        nonlocal negative_guard_triggered
        absolute_lba = machine_uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        sectors = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        destination = machine_uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        loads.append((absolute_lba, sectors, destination))
        if len(loads) > len(expected_loads) or loads[-1] != expected_loads[len(loads) - 1]:
            machine.failed = True
            machine_uc.emu_stop()
            return
        if len(loads) == 1 and bytes(
            machine_uc.mem_read(DELTA_LOADER_ADDR, len(delta_loader))
        ) != delta_loader:
            machine.failed = True
            machine_uc.emu_stop()
            return
        if loads[-1] == expected_loads[0]:
            events.append("load:candidate")
        elif loads[-1] == expected_loads[1]:
            events.append("load:sym-prefix")
        elif loads[-1] == expected_loads[2]:
            events.append("load:protected-low")
            payload = protected_controller.ljust(
                PROTECTED_CONTROLLER_END - PROTECTED_CONTROLLER_ADDR,
                b"\0",
            )
            if inject_legacy_extension_reload:
                machine_uc.mem_write(K14_EXTENSION_START, payload)
                assert extension_snapshot is not None
                negative_guard_triggered = (
                    bytes(
                        machine_uc.mem_read(
                            K14_EXTENSION_START,
                            K14_EXTENSION_END - K14_EXTENSION_START,
                        )
                    )
                    != extension_snapshot
                )
                machine.done = True
                machine_uc.emu_stop()
                return
            machine_uc.mem_write(PROTECTED_CONTROLLER_ADDR, payload)
        return_call(machine_uc)

    machine.call_handler(DELTA_LOADER_ADDR, load_phase)

    def candidate(machine_uc: Uc) -> None:
        events.append("candidate")
        machine_uc.mem_write(0x3B9C, candidate_secret)
        return_call(machine_uc)

    machine.call_handler(stubs["candidate"], candidate)

    def init(machine_uc: Uc) -> None:
        nonlocal extension_snapshot
        events.append("sym-init")
        if bytes(machine_uc.mem_read(0x08C0, 32)) != candidate_secret:
            return_call(machine_uc, carry=True)
            return
        # Match the real sym_init high-state clear that destroys the original
        # candidate output at 0x3b9c before the caller can use it.
        machine_uc.mem_write(0x3B9C, bytes(32))
        machine_uc.mem_write(K14_RUNTIME_START, runtime_pattern)
        extension_snapshot = bytes(
            machine_uc.mem_read(
                K14_EXTENSION_START,
                K14_EXTENSION_END - K14_EXTENSION_START,
            )
        )
        machine.sym_initialized = True
        return_call(machine_uc)

    machine.call_handler(stubs["init"], init)

    def import_transcript(machine_uc: Uc) -> None:
        events.append("sym-import")
        if bytes(machine_uc.mem_read(0x3600, 32)) != candidate_secret:
            return_call(machine_uc, carry=True)
            return
        if any(machine_uc.mem_read(0x08C0, 32)):
            return_call(machine_uc, carry=True)
            return
        return_call(machine_uc)

    machine.call_handler(stubs["import"], import_transcript)

    def critical(machine_uc: Uc) -> None:
        events.append("sym-critical")
        return_call(machine_uc)

    machine.call_handler(stubs["critical"], critical)

    def receive_empty(machine_uc: Uc) -> None:
        events.append("flush-empty")
        write_word(machine_uc, 0x06D5, 0)
        return_call(machine_uc)

    machine.call_handler(stubs["receive"], receive_empty)

    def window_ack(machine_uc: Uc) -> None:
        events.append("window-ack")
        return_call(machine_uc)

    machine.call_handler(0x13A6, window_ack)

    def protected_entry(machine_uc: Uc) -> None:
        events.append("jump:protected-low")
        machine.done = True
        machine_uc.emu_stop()

    machine.call_handler(PROTECTED_CONTROLLER_ADDR, protected_entry)
    machine.run()

    if inject_legacy_extension_reload:
        if not negative_guard_triggered:
            raise AssertionError("legacy extension-reload sentinel negative did not fire")
        return {
            "legacy_extension_reload_rejected": True,
            "status": "pass",
        }
    if bytes(machine.uc.mem_read(service_start, len(service_guard))) != service_guard:
        raise AssertionError("crypto transition changed persistent services")
    if bytes(
        machine.uc.mem_read(DELTA_LOADER_ADDR, len(delta_loader))
    ) != delta_loader:
        raise AssertionError("relocated track-batched loader changed")
    service_writes = [
        (ip, address, size)
        for ip, address, size in machine.post_sym_writes
        if ranges_overlap(
            (address, address + size),
            (service_start, service_end),
        )
    ]
    if service_writes:
        raise AssertionError(
            f"crypto transition wrote persistent services: {service_writes!r}"
        )
    expected_events = [
        "load:candidate",
        "candidate",
        "load:sym-prefix",
        "sym-init",
        "sym-import",
        "sym-critical",
        "load:protected-low",
        "flush-empty",
        "window-ack",
        "jump:protected-low",
    ]
    if machine.failed or not machine.done:
        raise AssertionError("crypto transition reached the low fail path")
    if loads != expected_loads or events != expected_events:
        raise AssertionError(
            f"crypto transition order drifted: loads={loads!r} events={events!r}"
        )
    if extension_snapshot is None:
        raise AssertionError("crypto transition never initialized symmetric state")
    extension_after = bytes(
        machine.uc.mem_read(
            K14_EXTENSION_START,
            K14_EXTENSION_END - K14_EXTENSION_START,
        )
    )
    if extension_after != extension_snapshot:
        raise AssertionError("post-sym controller transition changed K14 extension")
    extension_writes = [
        (ip, address, size)
        for ip, address, size in machine.post_sym_writes
        if ranges_overlap(
            (address, address + size),
            (K14_EXTENSION_START, K14_EXTENSION_END),
        )
    ]
    if extension_writes:
        raise AssertionError(
            f"controller glue wrote K14 extension after sym_init: {extension_writes!r}"
        )
    if bytes(machine.uc.mem_read(RX_BUFFER_END, len(rx_guard))) != rx_guard:
        raise AssertionError("K-prime handoff crossed into NIC RX guard")
    if (
        bytes(machine.uc.mem_read(0x08E0, len(controller_guard)))
        != controller_guard
    ):
        raise AssertionError("K-prime handoff crossed into controller guard")
    if any(machine.uc.mem_read(0x08C0, 32)):
        raise AssertionError("temporary low K-prime handoff was not zeroized")
    if (
        bytes(machine.uc.mem_read(PROTECTED_CONTROLLER_END, len(after_guard)))
        != after_guard
    ):
        raise AssertionError("protected controller load crossed into transcript/low guard")
    if bytes(
        machine.uc.mem_read(
            PROTECTED_CONTROLLER_ADDR,
            PROTECTED_CONTROLLER_END - PROTECTED_CONTROLLER_ADDR,
        )
    ) != protected_controller.ljust(
        PROTECTED_CONTROLLER_END - PROTECTED_CONTROLLER_ADDR,
        b"\0",
    ):
        raise AssertionError("protected controller low-slot load is not byte exact")
    return {
        "ordered_events": events,
        "phase_loads": [
            {
                "absolute_lba": lba,
                "sectors": sectors,
                "destination": f"0x{destination:04x}",
            }
            for lba, sectors, destination in loads
        ],
        "critical_loader": (
            f"0x{DELTA_LOADER_ADDR:04x}.."
            f"0x{DELTA_LOADER_ADDR + len(delta_loader):04x} "
            "copied before candidate and used for all three loads"
        ),
        "protected_slot": "0x0900..0x0d00",
        "k_prime_handoff": "0x08c0..0x08e0 consumed and zeroized",
        "post_sym_extension_writes": 0,
        "post_sym_persistent_service_writes": 0,
        "rx_and_transcript_sentinels": "pass",
        "status": "pass",
    }


def test_protected(
    protected_controller: bytes,
    manifest: dict[str, object],
    *,
    fail_head_send: bool = False,
    compatibility_ccs_count: int = 1,
    coalesced_tail: bytes = b"",
    later_frame_tail: bytes = b"",
    expected_shape_failure: str | None = None,
) -> dict[str, object]:
    machine = Machine(protected_controller, entry=PROTECTED_CONTROLLER_ADDR)
    low = manifest["persistent_services"]
    assert isinstance(low, dict)
    low_emit = int(low["emit"], 0)
    low_fail = int(low["fail"], 0)
    zero_window = int(low["zero_window"], 0)
    transition = int(low["transition"], 0)
    machine.fail_handler(low_fail)

    stubs = {
        "open_begin": 0x0520,
        "open_chunk": 0x0522,
        "open_finish": 0x0524,
        "verify_finish": 0x0526,
        "build_finish": 0x0528,
        "nic_receive": 0x052A,
        "nic_fallback": 0x052C,
        "derive_client_application": 0x052E,
        "build_head": 0x0530,
    }
    table = [0] * 18
    table[4] = stubs["open_begin"]
    table[6] = stubs["open_chunk"]
    table[7] = stubs["open_finish"]
    table[8] = stubs["verify_finish"]
    table[9] = stubs["build_finish"]
    table[11] = stubs["build_head"]
    table[16] = stubs["derive_client_application"]
    machine.uc.mem_write(0x1820, struct.pack("<18H", *table))
    write_word(machine.uc, NIC_VT_RECEIVE, stubs["nic_receive"])
    write_word(machine.uc, NIC_VT_RX_FALLBACK, stubs["nic_fallback"])
    before_guard = bytes([0xC3]) * (PROTECTED_CONTROLLER_ADDR - RX_BUFFER_END)
    after_guard = bytes([0x3C]) * (
        PROTECTED_LOW_GUARD_END - PROTECTED_CONTROLLER_END
    )
    extension_pattern = bytes(
        (index * 7 + 1) & 0xFF
        for index in range(K14_EXTENSION_END - K14_EXTENSION_START)
    )
    machine.uc.mem_write(RX_BUFFER_END, before_guard)
    machine.uc.mem_write(PROTECTED_CONTROLLER_END, after_guard)
    machine.uc.mem_write(K14_EXTENSION_START, extension_pattern)
    service_start = int(str(low["runtime_start"]), 0)
    service_end = int(str(low["runtime_end"]), 0)
    service_guard = bytes(
        (index * 29 + 0x47) & 0xFF
        for index in range(service_end - service_start)
    )
    machine.uc.mem_write(service_start, service_guard)
    extension_guard = bytes(
        machine.uc.mem_read(
            K14_EXTENSION_START,
            K14_EXTENSION_END - K14_EXTENSION_START,
        )
    )
    product_pool_guard = bytes(
        (index * 17 + 0x23) & 0xFF
        for index in range(PRODUCT_POOL_END - PRODUCT_POOL_START)
    )
    machine.uc.mem_write(PRODUCT_POOL_START, product_pool_guard)

    prefix = bytes((index * 19 + 7) & 0xFF for index in range(600))
    verify_data = bytes((index * 13 + 3) & 0xFF for index in range(32))
    finished = b"\x14\x00\x00\x20" + verify_data
    plaintext = prefix + finished + b"\x16"
    tag = bytes(range(0xA0, 0xB0))
    protected = (
        b"\x17\x03\x03"
        + struct.pack(">H", len(plaintext) + len(tag))
        + plaintext
        + tag
    )
    compatibility_ccs = b"\x14\x03\x03\x00\x01\x01"
    wire = compatibility_ccs * compatibility_ccs_count + protected + coalesced_tail
    cuts = (2, 9, 171, 427, len(wire))
    frames: list[bytes] = []
    start = 0
    for end in cuts:
        frames.append(wire[start:end])
        start = end
    receive_index = 0
    opened_prefix: int | None = None
    chunk_calls = 0
    chunk_lengths: list[int] = []
    open_finished = False
    ack_calls = 0
    send_attempts: list[tuple[bytes, bytes]] = []
    wait_calls: list[int] = []
    emitted: list[str] = []
    verify_called = False
    build_called = False
    derive_client_called = False
    build_head_called = False
    zero_window_calls = 0
    transitioned: tuple[int, int] | None = None
    queued_receive_calls = 0
    queued_parse_calls = 0
    queued_payloads = [later_frame_tail] if later_frame_tail else []
    parsed_queued_payloads: list[bytes] = []
    current_queued_payload: bytes | None = None
    initial_seq = bytes.fromhex("01234567")
    machine.uc.mem_write(TCP_LOCAL_SEQ, initial_seq)

    write_word(machine.uc, 0x3CA0, 0x0100)
    write_word(machine.uc, 0x3CA2, 0x0103)

    def tcp_receive(machine_uc: Uc) -> None:
        nonlocal receive_index
        if receive_index >= len(frames):
            return_call(machine_uc, carry=True)
            return
        payload = frames[receive_index]
        receive_index += 1
        machine_uc.mem_write(RX_BUFFER, payload)
        write_word(machine_uc, TCP_RX_PTR, RX_BUFFER)
        write_word(machine_uc, TCP_RX_LEN, len(payload))
        return_call(machine_uc)

    machine.call_handler(0x14ED, tcp_receive)

    def tcp_ack(machine_uc: Uc) -> None:
        nonlocal ack_calls
        ack_calls += 1
        return_call(machine_uc)

    machine.call_handler(0x13A6, tcp_ack)

    def nic_receive(machine_uc: Uc) -> None:
        nonlocal queued_receive_calls, current_queued_payload
        queued_receive_calls += 1
        if queued_payloads:
            current_queued_payload = queued_payloads.pop(0)
            machine_uc.mem_write(RX_BUFFER, current_queued_payload)
            write_word(
                machine_uc,
                NE_RX_SAMPLE_COUNT,
                len(current_queued_payload) + 54,
            )
        else:
            current_queued_payload = None
            write_word(machine_uc, NE_RX_SAMPLE_COUNT, 0)
        return_call(machine_uc)

    machine.call_handler(stubs["nic_receive"], nic_receive)

    def parse_tcp_payload(machine_uc: Uc) -> None:
        nonlocal queued_parse_calls, current_queued_payload
        queued_parse_calls += 1
        if current_queued_payload is None:
            return_call(machine_uc, carry=True)
            return
        parsed_queued_payloads.append(current_queued_payload)
        current_queued_payload = None
        return_call(machine_uc)

    machine.call_handler(PARSE_TCP_PAYLOAD, parse_tcp_payload)

    def nic_fallback(machine_uc: Uc) -> None:
        return_call(machine_uc, carry=True)

    machine.call_handler(stubs["nic_fallback"], nic_fallback)

    def open_begin(machine_uc: Uc) -> None:
        nonlocal opened_prefix
        opened_prefix = machine_uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        expected_header = protected[:5]
        if bytes(machine_uc.mem_read(0x39A0, 5)) != expected_header:
            return_call(machine_uc, carry=True)
            return
        return_call(machine_uc)

    machine.call_handler(stubs["open_begin"], open_begin)

    def open_chunk(machine_uc: Uc) -> None:
        nonlocal chunk_calls
        chunk_calls += 1
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        chunk_lengths.append(count)
        # Deliberately exercise the real overlay's clobber envelope.
        machine_uc.reg_write(UC_X86_REG_SI, (pointer + count) & 0xFFFF)
        machine_uc.reg_write(UC_X86_REG_CX, 0)
        machine_uc.reg_write(UC_X86_REG_DX, 0xBEEF)
        return_call(machine_uc)

    machine.call_handler(stubs["open_chunk"], open_chunk)

    def open_finish(machine_uc: Uc) -> None:
        nonlocal open_finished
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        if bytes(machine_uc.mem_read(pointer, 16)) != tag:
            return_call(machine_uc, carry=True)
            return
        open_finished = True
        return_call(machine_uc)

    machine.call_handler(stubs["open_finish"], open_finish)

    def verify_finish(machine_uc: Uc) -> None:
        nonlocal verify_called
        verify_called = True
        if bytes(machine_uc.mem_read(0x38F0, 32)) != verify_data:
            return_call(machine_uc, carry=True)
            return
        return_call(machine_uc)

    machine.call_handler(stubs["verify_finish"], verify_finish)
    finished_record = b"\x17\x03\x03\x00\x35" + bytes(range(53))

    def build_finish(machine_uc: Uc) -> None:
        nonlocal build_called
        build_called = True
        machine_uc.mem_write(0x39A0, finished_record)
        machine_uc.reg_write(UC_X86_REG_AX, 58)
        return_call(machine_uc)

    machine.call_handler(stubs["build_finish"], build_finish)

    def derive_client_application(machine_uc: Uc) -> None:
        nonlocal derive_client_called
        derive_client_called = True
        write_word(machine_uc, BIOS_TICK, 0x011B)
        return_call(machine_uc)

    machine.call_handler(
        stubs["derive_client_application"],
        derive_client_application,
    )

    head_record = b"\x17\x03\x03\x00\x43" + bytes(range(67))

    def build_head(machine_uc: Uc) -> None:
        nonlocal build_head_called
        build_head_called = True
        machine_uc.mem_write(0x39A0, head_record)
        machine_uc.reg_write(UC_X86_REG_AX, 72)
        return_call(machine_uc)

    machine.call_handler(stubs["build_head"], build_head)

    def add_tcp_seq(machine_uc: Uc, address: int, count: int) -> None:
        current = int.from_bytes(machine_uc.mem_read(address, 4), "big")
        machine_uc.mem_write(
            address,
            ((current + count) & 0xFFFFFFFF).to_bytes(4, "big"),
        )

    def tcp_send(machine_uc: Uc) -> None:
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        send_attempts.append(
            (
                bytes(machine_uc.mem_read(TCP_LOCAL_SEQ, 4)),
                bytes(machine_uc.mem_read(pointer, count)),
            )
        )
        if fail_head_send and len(send_attempts) == 2:
            return_call(machine_uc, carry=True)
            return
        add_tcp_seq(machine_uc, TCP_LOCAL_SEQ, count)
        if len(send_attempts) == 1:
            write_word(machine_uc, BIOS_TICK, 0x010F)
        elif len(send_attempts) == 2:
            write_word(machine_uc, BIOS_TICK, 0x0122)
        return_call(machine_uc)

    machine.call_handler(0x13BF, tcp_send)

    def wait_ticks(machine_uc: Uc) -> None:
        count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        wait_calls.append(count)
        write_word(machine_uc, BIOS_TICK, word(machine_uc, BIOS_TICK) + count)
        return_call(machine_uc)

    machine.call_handler(0x11E5, wait_ticks)

    def send_zero_window(machine_uc: Uc) -> None:
        nonlocal zero_window_calls
        zero_window_calls += 1
        return_call(machine_uc)

    machine.call_handler(zero_window, send_zero_window)

    def phase_transition(machine_uc: Uc) -> None:
        nonlocal transitioned
        transitioned = (
            machine_uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
            machine_uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
        )
        machine.done = True
        machine_uc.emu_stop()

    machine.call_handler(transition, phase_transition)

    def emit(machine_uc: Uc) -> None:
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        text = read_z(machine_uc, pointer)
        emitted.append(text)
        return_call(machine_uc)

    machine.call_handler(low_emit, emit)
    machine.sym_initialized = True
    machine.run()
    output = "".join(emitted)
    if expected_shape_failure is not None:
        if not machine.failed or machine.done:
            raise AssertionError(
                f"{expected_shape_failure} was not rejected: "
                f"failed={machine.failed} done={machine.done}"
            )
        if send_attempts or wait_calls or output:
            raise AssertionError(
                f"{expected_shape_failure} escaped into Finished/report output"
            )
        if later_frame_tail and parsed_queued_payloads != [later_frame_tail]:
            raise AssertionError(
                "later-frame tail did not reach the queued TCP payload guard"
            )
        if not later_frame_tail and parsed_queued_payloads:
            raise AssertionError(
                f"{expected_shape_failure} unexpectedly reached queued-tail parsing"
            )
        if (
            bytes(machine.uc.mem_read(K14_EXTENSION_START, len(extension_guard)))
            != extension_guard
            or bytes(machine.uc.mem_read(service_start, len(service_guard)))
            != service_guard
            or bytes(machine.uc.mem_read(PRODUCT_POOL_START, len(product_pool_guard)))
            != product_pool_guard
            or bytes(machine.uc.mem_read(RX_BUFFER_END, len(before_guard)))
            != before_guard
            or bytes(
                machine.uc.mem_read(PROTECTED_CONTROLLER_END, len(after_guard))
            )
            != after_guard
        ):
            raise AssertionError(
                f"{expected_shape_failure} changed a protected memory sentinel"
            )
        return {
            "negative": expected_shape_failure,
            "compatibility_ccs_records": compatibility_ccs_count,
            "coalesced_tail_bytes": len(coalesced_tail),
            "later_frame_tail_bytes": len(later_frame_tail),
            "receive_frames": receive_index,
            "queued_receive_callbacks": queued_receive_calls,
            "queued_parse_callbacks": queued_parse_calls,
            "finished_transmit_attempts": 0,
            "status": "rejected",
        }
    if fail_head_send:
        if not machine.failed or machine.done:
            raise AssertionError("HEAD-send failure did not fail closed")
        if (
            len(send_attempts) != 2
            or send_attempts[0] != (initial_seq, finished_record)
            or send_attempts[1][0]
            != (
                (int.from_bytes(initial_seq, "big") + len(finished_record))
                & 0xFFFFFFFF
            ).to_bytes(4, "big")
            or send_attempts[1][1] != head_record
        ):
            raise AssertionError("HEAD-send failure sequence/payload drifted")
        if wait_calls or zero_window_calls or transitioned is not None or output:
            raise AssertionError("HEAD-send failure escaped past liveness boundary")
        return {
            "negative": "head-send-failure",
            "finished_transmit_bytes": len(finished_record),
            "head_transmit_bytes": len(head_record),
            "status": "rejected",
        }
    if machine.failed or not machine.done:
        raise AssertionError(
            "SYM/Finished controller reached the low fail path: "
            f"failed={machine.failed} done={machine.done} "
            f"receives={receive_index}/{len(frames)} chunks={chunk_calls} "
            f"chunk_lengths={chunk_lengths} "
            f"open_prefix={opened_prefix} open_finished={open_finished} "
            f"acks={ack_calls} state={machine.uc.mem_read(0x3c35, 16).hex()} "
            f"tag={machine.uc.mem_read(0x3910, 16).hex()} "
            f"finish={machine.uc.mem_read(0x38f0, 32).hex()} "
            f"verify={verify_called} build={build_called} "
            f"sends={len(send_attempts)} output={output!r}"
        )
    if opened_prefix != len(prefix):
        raise AssertionError("protected record transcript prefix length drifted")
    if not open_finished or bytes(machine.uc.mem_read(0x3910, 16)) != tag:
        raise AssertionError("protected record tag collection drifted")
    if queued_receive_calls != 1 or queued_parse_calls != 0:
        raise AssertionError(
            "clean queued-tail probe drifted: "
            f"receive={queued_receive_calls} parse={queued_parse_calls}"
        )
    if len(send_attempts) != 2:
        raise AssertionError(
            f"Finished/HEAD transmit count drifted: {len(send_attempts)}"
        )
    if send_attempts[0] != (initial_seq, finished_record):
        raise AssertionError("Finished transmit bytes/sequence drifted")
    head_seq = (
        (int.from_bytes(initial_seq, "big") + len(finished_record))
        & 0xFFFFFFFF
    ).to_bytes(4, "big")
    if send_attempts[1] != (head_seq, head_record):
        raise AssertionError("HEAD transmit bytes/sequence drifted")
    if wait_calls != [1]:
        raise AssertionError(f"post-HEAD pacing delay drifted: {wait_calls!r}")
    expected_final_seq = (
        (
            int.from_bytes(initial_seq, "big")
            + len(finished_record)
            + len(head_record)
        )
        & 0xFFFFFFFF
    ).to_bytes(4, "big")
    if bytes(machine.uc.mem_read(TCP_LOCAL_SEQ, 4)) != expected_final_seq:
        raise AssertionError("post-Finished TCP sequence drifted")
    output_lines = [line.strip() for line in output.splitlines()]
    if (
        "DEADLINE PASS" not in output_lines
        or "HEAD TX" not in output_lines
        or any(line.startswith("T F/A/H=") for line in output_lines)
        or "PASS" in output_lines
        or "RESULT" in output_lines
    ):
        raise AssertionError(f"pre-canary timing milestone drifted: {output!r}")
    expected_transition = (
        parse_key(manifest, "post_controller"),
        POST_CONTROLLER_ADDR,
    )
    if (
        not derive_client_called
        or not build_head_called
        or zero_window_calls != 1
        or transitioned != expected_transition
    ):
        raise AssertionError(
            "post-Finished handoff drifted: "
            f"derive_client={derive_client_called} "
            f"build_head={build_head_called} zero={zero_window_calls} "
            f"transition={transitioned!r}"
        )
    if bytes(machine.uc.mem_read(K14_EXTENSION_START, len(extension_guard))) != extension_guard:
        raise AssertionError("protected-flight controller changed K14 extension")
    extension_writes = [
        (ip, address, size)
        for ip, address, size in machine.post_sym_writes
        if ranges_overlap(
            (address, address + size),
            (K14_EXTENSION_START, K14_EXTENSION_END),
        )
    ]
    if extension_writes:
        raise AssertionError(
            f"protected-flight glue wrote K14 extension: {extension_writes!r}"
        )
    if bytes(machine.uc.mem_read(service_start, len(service_guard))) != service_guard:
        raise AssertionError("protected flight changed persistent services")
    service_writes = [
        (ip, address, size)
        for ip, address, size in machine.post_sym_writes
        if ranges_overlap(
            (address, address + size),
            (service_start, service_end),
        )
    ]
    if service_writes:
        raise AssertionError(
            f"protected-flight glue wrote diagnostic service island: "
            f"{service_writes!r}"
        )
    if bytes(machine.uc.mem_read(PRODUCT_POOL_START, len(product_pool_guard))) != product_pool_guard:
        raise AssertionError("protected flight changed product arena/context")
    pool_writes = [
        (ip, address, size)
        for ip, address, size in machine.post_sym_writes
        if ranges_overlap(
            (address, address + size),
            (PRODUCT_POOL_START, PRODUCT_POOL_END),
        )
    ]
    if pool_writes:
        raise AssertionError(
            f"protected-flight glue wrote product arena/context: {pool_writes!r}"
        )
    if bytes(machine.uc.mem_read(RX_BUFFER_END, len(before_guard))) != before_guard:
        raise AssertionError("NIC RX crossed into protected-controller guard")
    if (
        bytes(machine.uc.mem_read(PROTECTED_CONTROLLER_END, len(after_guard)))
        != after_guard
    ):
        raise AssertionError("protected controller crossed its upper guard")
    return {
        "fragmented_wire_bytes": len(wire),
        "compatibility_ccs_records": compatibility_ccs_count,
        "receive_frames": len(frames),
        "queued_tail_probe_callbacks": queued_receive_calls,
        "open_chunk_calls": chunk_calls,
        "ordinary_ack_calls": ack_calls,
        "finished_transmit_bytes": len(finished_record),
        "finished_transmit_attempts": 1,
        "head_transmit_bytes": len(head_record),
        "head_transmit_attempts": 1,
        "tx_tick_after_send_return": word(machine.uc, 0x3CA4) == 0x010F,
        "app_ready_tick": f"0x{word(machine.uc, 0x3CA6):04x}",
        "head_return_tick": f"0x{word(machine.uc, 0x3CA8):04x}",
        "post_sym_extension_writes": 0,
        "client_application_write_key_derived": True,
        "head_before_zero_window_and_cold_load": True,
        "post_controller_transition": "0x0900",
        "post_sym_persistent_service_writes": 0,
        "product_arena_context_writes": 0,
        "rx_and_upper_sentinels": "pass",
        "terminal": output,
        "status": "pass",
    }


def test_protected_real_k14_aead(
    protected_controller: bytes,
    sym_image: bytes,
    manifest: dict[str, object],
) -> dict[str, object]:
    """Prove protected-flight plaintext stays provisional until real AEAD finish."""

    symmetric = load_symmetric_checker()
    header = symmetric.parse_header(sym_image)
    sym_phase = parse_phase(manifest, "sym")
    if (
        int(str(sym_phase["destination"]), 0) != symmetric.OVERLAY_BASE
        or int(sym_phase["bytes"]) != len(sym_image)
        or sym_phase["sha256"] != hashlib.sha256(sym_image).hexdigest()
        or header.image_bytes != len(sym_image)
        or len(header.entries) != 19
    ):
        raise AssertionError("real-AEAD protected artifact/manifest geometry drifted")

    services = manifest["persistent_services"]
    assert isinstance(services, dict)
    emit_entry = int(services["emit"], 0)
    fail_entry = int(services["fail"], 0)
    server_key = hashlib.sha256(
        b"Seed live K14 protected-flight server handshake key"
    ).digest()
    server_iv = hashlib.sha256(
        b"Seed live K14 protected-flight server handshake IV"
    ).digest()[:12]
    initial_sequence = 0x0102030405060708
    verify_data = hashlib.sha256(
        b"Seed live K14 provisional server Finished"
    ).digest()
    clean_record = symmetric.BASE.encrypted_record(
        server_key,
        server_iv,
        initial_sequence,
        symmetric.O.CONTENT_HANDSHAKE,
        b"\x14\x00\x00\x20" + verify_data,
    )
    if len(clean_record) != 58:
        raise AssertionError("real-AEAD protected record geometry drifted")

    def run_case(kind: str) -> dict[str, object]:
        wire = bytearray(clean_record)
        if kind == "bad-tag":
            wire[-1] ^= 1
        elif kind == "tampered-tail":
            # Corrupt the provisional TLSInnerPlaintext content type while
            # retaining the original tag.  Old glue branched here before the
            # tag bytes had even arrived.
            wire[5 + 36] ^= 1
        else:
            raise AssertionError(f"unknown protected real-AEAD case {kind!r}")

        cipher_end = len(wire) - 16
        frames = (
            bytes(wire[:5]),
            bytes(wire[5:cipher_end]),
            bytes(wire[cipher_end : cipher_end + 8]),
            bytes(wire[cipher_end + 8 :]),
        )
        if any(not frame for frame in frames):
            raise AssertionError("protected real-AEAD fragment geometry drifted")

        machine = Machine(protected_controller, entry=PROTECTED_CONTROLLER_ADDR)
        machine.uc.mem_write(symmetric.OVERLAY_BASE, sym_image)
        loaded_entries = tuple(
            word(machine.uc, 0x1820 + index * 2)
            for index in range(len(header.entries))
        )
        if loaded_entries != header.entries:
            raise AssertionError(
                "protected controller does not see the real K14 entry table"
            )

        receive_index = 0
        ack_calls = 0
        failure_receive_index: int | None = None
        emitted: list[str] = []
        entry_counts = {4: 0, 6: 0, 7: 0, 8: 0}

        def tcp_receive(machine_uc: Uc) -> None:
            nonlocal receive_index
            if receive_index >= len(frames):
                return_call(machine_uc, carry=True)
                return
            payload = frames[receive_index]
            receive_index += 1
            machine_uc.mem_write(RX_BUFFER, payload)
            write_word(machine_uc, TCP_RX_PTR, RX_BUFFER)
            write_word(machine_uc, TCP_RX_LEN, len(payload))
            return_call(machine_uc)

        machine.call_handler(0x14ED, tcp_receive)

        def tcp_ack(machine_uc: Uc) -> None:
            nonlocal ack_calls
            ack_calls += 1
            return_call(machine_uc)

        machine.call_handler(0x13A6, tcp_ack)

        def emit(machine_uc: Uc) -> None:
            emitted.append(
                read_z(
                    machine_uc,
                    machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
                )
            )
            return_call(machine_uc)

        machine.call_handler(emit_entry, emit)

        def fail(machine_uc: Uc) -> None:
            nonlocal failure_receive_index
            failure_receive_index = receive_index
            machine.failed = True
            machine_uc.emu_stop()

        machine.call_handler(fail_entry, fail)

        def observe_entries(
            _machine_uc: Uc,
            address: int,
            _size: int,
            _user,
        ) -> None:
            for entry_index in entry_counts:
                if address == header.entries[entry_index]:
                    entry_counts[entry_index] += 1

        machine.uc.hook_add(UC_HOOK_CODE, observe_entries)
        machine.uc.mem_write(symmetric.SERVER_HS_KEY, server_key)
        machine.uc.mem_write(symmetric.SERVER_HS_IV, server_iv)
        machine.uc.mem_write(
            symmetric.SERVER_HS_SEQ,
            initial_sequence.to_bytes(8, "big"),
        )
        received_finished_guard = bytes(
            (index * 17 + 0x51) & 0xFF for index in range(32)
        )
        machine.uc.mem_write(
            symmetric.RECEIVED_SERVER_FINISHED,
            received_finished_guard,
        )
        machine.sym_initialized = True
        machine.run(count=20_000_000)

        if not machine.failed or machine.done:
            raise AssertionError(f"protected real-AEAD {kind} was not rejected")
        if failure_receive_index != len(frames) or receive_index != len(frames):
            raise AssertionError(
                f"protected real-AEAD {kind} branched before the complete tag: "
                f"failed_at={failure_receive_index} receives={receive_index}"
            )
        if (
            entry_counts[4] != 1
            or entry_counts[6] != 1
            or entry_counts[7] != 1
            or entry_counts[8] != 0
        ):
            raise AssertionError(
                f"protected real-AEAD {kind} entry coverage drifted: "
                f"{entry_counts!r}"
            )
        if emitted:
            raise AssertionError(
                f"protected real-AEAD {kind} emitted before rejection: {emitted!r}"
            )
        if (
            bytes(
                machine.uc.mem_read(
                    symmetric.RECEIVED_SERVER_FINISHED,
                    len(received_finished_guard),
                )
            )
            != received_finished_guard
        ):
            raise AssertionError(
                f"protected real-AEAD {kind} committed unauthenticated Finished"
            )
        finish_writes = [
            (ip, address, size)
            for ip, address, size in machine.post_sym_writes
            if ranges_overlap(
                (address, address + size),
                (
                    symmetric.RECEIVED_SERVER_FINISHED,
                    symmetric.RECEIVED_SERVER_FINISHED
                    + len(received_finished_guard),
                ),
            )
        ]
        if finish_writes:
            raise AssertionError(
                f"protected real-AEAD {kind} touched retained Finished state: "
                f"{finish_writes!r}"
            )
        if (
            bytes(machine.uc.mem_read(symmetric.SERVER_HS_SEQ, 8))
            != initial_sequence.to_bytes(8, "big")
        ):
            raise AssertionError(
                f"protected real-AEAD {kind} advanced server sequence"
            )

        return {
            "negative": kind,
            "receive_frames": len(frames),
            "failure_after_complete_tag": True,
            "real_open_begin_calls": entry_counts[4],
            "real_open_chunk_calls": entry_counts[6],
            "real_open_finish_calls": entry_counts[7],
            "verify_finish_calls": entry_counts[8],
            "retained_finished_writes": 0,
            "server_sequence_increment": 0,
            "status": "rejected",
        }

    return {
        "kind": "real_k14_chacha20_poly1305_protected_quarantine_gate",
        "symmetric_image_sha256": hashlib.sha256(sym_image).hexdigest(),
        "record_bytes": len(clean_record),
        "bad_tag": run_case("bad-tag"),
        "tampered_tail": run_case("tampered-tail"),
        "status": "pass",
    }


def attempt6_identity_fixture() -> dict[str, object]:
    """Reconstruct the exact authenticated attempt-6 protected plaintext."""

    for path in (ATTEMPT6_PCAP, ATTEMPT6_ORACLE, LIVE_AUTH_LEAF):
        if not path.is_file():
            raise AssertionError(f"identity checker fixture is missing: {path}")
    capture = load_capture_oracle()
    oracle = json.loads(ATTEMPT6_ORACLE.read_text(encoding="utf-8"))
    pcap_sha256 = hashlib.sha256(ATTEMPT6_PCAP.read_bytes()).hexdigest()
    if oracle.get("pcap_sha256") != pcap_sha256:
        raise AssertionError("attempt-6 pcap differs from its checked oracle")

    flows = []
    for flow in capture.PCAP.collect_flows(ATTEMPT6_PCAP):
        client_stream, _times = flow.client_stream.contiguous()
        if capture.PCAP.is_live_client_hello(client_stream):
            flows.append(flow)
    if len(flows) != 1:
        raise AssertionError(
            f"attempt-6 fixture has {len(flows)} live Seed flows"
        )
    client_stream, _client_times = flows[0].client_stream.contiguous()
    server_stream, _server_times = flows[0].server_stream.contiguous()
    client_records = capture.full_records(client_stream)
    server_records = capture.full_records(server_stream)
    client_hello = client_records[0][3][5:]
    server_hello = server_records[0][3][5:]

    entropy_meta = capture.ENTROPY_FIXTURE.read_bytes()
    d_z = entropy_meta[98:162]
    private_key = capture.KEYGEN.fips_keygen_internal(d_z)
    ciphertext, server_x = capture.PROBE.parse_server_hybrid_share(server_hello)
    _message, candidate_g = capture.MLKEM.k_pke_decrypt(
        private_key,
        ciphertext,
    )
    handshake = capture.PROBE.derive_handshake(
        candidate_g[:32] + server_x,
        client_hello + server_hello,
    )
    compatibility_ccs, protected_entry, _later = (
        capture.split_target_server_flight(server_records[1:])
    )
    protected_record = protected_entry[3]
    expected_record_sha256 = oracle["flow"]["record_sha256"][
        "server_protected_flight"
    ]
    if hashlib.sha256(protected_record).hexdigest() != expected_record_sha256:
        raise AssertionError("attempt-6 protected record differs from oracle")
    inner_type, content = capture.PROBE.ORACLE.decrypt_record(
        handshake["server_key"],
        handshake["server_iv"],
        0,
        protected_record,
    )
    if inner_type != 0x16:
        raise AssertionError("attempt-6 protected record is not handshake content")
    messages = capture.PROBE.parse_handshake_messages(content)
    if [message[0] for message in messages] != [0x08, 0x19, 0x0F, 0x14]:
        raise AssertionError("attempt-6 protected message sequence changed")
    if [len(message) for message in messages] != [10, 1799, 79, 36]:
        raise AssertionError("attempt-6 protected message lengths changed")

    certificate_verify = messages[-2]
    finished = messages[-1]
    if (
        certificate_verify[4:6] != b"\x04\x03"
        or int.from_bytes(certificate_verify[6:8], "big")
        != len(certificate_verify) - 8
    ):
        raise AssertionError("attempt-6 CertificateVerify shape changed")
    signature = certificate_verify[8:]
    plaintext = content + bytes([inner_type])
    tail = plaintext[-IDENTITY_TAIL_LEN:]
    cv_offset = tail.find(certificate_verify)
    if (
        len(plaintext) != 1925
        or cv_offset != 1
        or tail[IDENTITY_CV_END - IDENTITY_TAIL :] != finished + b"\x16"
    ):
        raise AssertionError("attempt-6 117-byte tail geometry changed")
    certificate_hash = hashlib.sha256(
        client_hello + server_hello + b"".join(messages[:-2])
    ).digest()
    signed_input = (
        b"\x20" * 64
        + b"TLS 1.3, server CertificateVerify\x00"
        + certificate_hash
    )
    digest = hashlib.sha256(signed_input).digest()
    expected = {
        "tail_sha256": (
            "d1d39d5789204ef2b3da7638d721fed3a35948adb13a132fa503c86226a17608"
        ),
        "certificate_hash": (
            "f282b3264db1749156abd98a33b08f2bfd0077b1c796022d7853059db5b8a94c"
        ),
        "signed_input_digest": (
            "30940a73d9741ce88690e05f4b159131e51b54738b975102d8b3f39b2abdc548"
        ),
        "signature_sha256": (
            "595a1984c27589227c9b767bbacdd242acf82121885165cfc215c6199f2f6ee3"
        ),
    }
    actual = {
        "tail_sha256": hashlib.sha256(tail).hexdigest(),
        "certificate_hash": certificate_hash.hex(),
        "signed_input_digest": digest.hex(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }
    if actual != expected:
        raise AssertionError(f"attempt-6 identity oracle drifted: {actual!r}")

    public_pem = subprocess.run(
        ["openssl", "x509", "-in", str(LIVE_AUTH_LEAF), "-pubkey", "-noout"],
        check=True,
        capture_output=True,
    ).stdout
    with tempfile.TemporaryDirectory(
        prefix="seed-live-k15-identity-cv-"
    ) as temp_name:
        temp = Path(temp_name)
        public_path = temp / "leaf-public.pem"
        signed_path = temp / "signed.bin"
        signature_path = temp / "signature.der"
        public_path.write_bytes(public_pem)
        signed_path.write_bytes(signed_input)
        signature_path.write_bytes(signature)
        verify = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_path),
                "-signature",
                str(signature_path),
                str(signed_path),
            ],
            capture_output=True,
            text=True,
        )
    if verify.returncode:
        raise AssertionError("host rejected attempt-6 CertificateVerify")

    return {
        "pcap_sha256": pcap_sha256,
        "protected_record_sha256": expected_record_sha256,
        "compatibility_ccs": b"".join(entry[3] for entry in compatibility_ccs),
        "protected_header": protected_record[:5],
        "protected_tag": protected_record[-16:],
        "plaintext": plaintext,
        "tail": tail,
        "initial_transcript": client_hello + server_hello,
        "certificate_hash": certificate_hash,
        "digest": digest,
        "signature": signature,
        "finished_verify_data": finished[4:],
        "message_lengths": [len(message) for message in messages],
        "cv_offset_in_tail": cv_offset,
        "host_signature_verified": True,
    }


def test_identity_auth_transition(
    post_controller: bytes,
    post_listing: Path,
    crypto_controller: bytes,
    persistent_services: bytes,
    auth_controller: bytes,
    auth_listing: Path,
    auth_image: bytes,
    manifest: dict[str, object],
) -> dict[str, object]:
    """Execute post commit through both disk loads and the auth result branch."""

    services = manifest["persistent_services"]
    assert isinstance(services, dict)
    service_start = int(str(services["runtime_start"]), 0)
    service_end = int(str(services["runtime_end"]), 0)
    service_offset = service_start - CONTROLLER_ADDR
    if (
        service_offset < 0
        or service_offset + len(persistent_services) > len(crypto_controller)
        or service_end - service_start != len(persistent_services)
        or crypto_controller[
            service_offset : service_offset + len(persistent_services)
        ]
        != persistent_services
    ):
        raise AssertionError(
            "identity transition cannot bind persistent caller to crypto image"
        )
    if (
        len(auth_controller) > AUTH_CONTROLLER_END - AUTH_CONTROLLER_ADDR
        or len(auth_image) != AUTH_IMAGE_BYTES
        or AUTH_IMAGE_ADDR + len(auth_image) != AUTH_IMAGE_END
    ):
        raise AssertionError("identity auth controller/image artifact geometry drifted")

    post_commit = listing_label_address(
        post_listing,
        "post_check_commit",
        POST_CONTROLLER_ADDR,
    )
    auth_emit = listing_label_address(
        auth_listing,
        "auth_emit",
        AUTH_CONTROLLER_ADDR,
    )
    auth_entry = int.from_bytes(auth_image[:2], "little")
    if not AUTH_IMAGE_ADDR <= auth_entry < AUTH_IMAGE_END:
        raise AssertionError(f"identity auth entry escaped image: {auth_entry:#x}")
    pass_text = b"\r\nIDENTITY PASS\r\nPASS\r\nRESULT\r\n\0"
    pass_offset = auth_controller.find(pass_text)
    if pass_offset < 0:
        raise AssertionError("identity auth controller lacks exact PASS text")
    expected_pass_pointer = AUTH_CONTROLLER_ADDR + pass_offset

    auth_controller_phase = parse_phase(manifest, "auth_controller")
    auth_phase = parse_phase(manifest, "auth")
    expected_loads = (
        (
            CORE_START_LBA + int(auth_controller_phase["start_sector"]),
            int(auth_controller_phase["sectors"]),
            AUTH_CONTROLLER_ADDR,
        ),
        (
            CORE_START_LBA + int(auth_phase["start_sector"]),
            int(auth_phase["sectors"]),
            AUTH_IMAGE_ADDR,
        ),
    )

    def run_case(
        controller: bytes,
        *,
        expect_self_overwrite: bool,
    ) -> dict[str, object]:
        machine = Machine(controller, entry=POST_CONTROLLER_ADDR)
        machine.entry = post_commit
        machine.uc.mem_write(CONTROLLER_ADDR, crypto_controller)
        digest = bytes((index * 23 + 5) & 0xFF for index in range(32))
        machine.uc.mem_write(IDENTITY_DIGEST_HOLD, digest)
        digest_guard = bytes([0xA9]) * 32
        machine.uc.mem_write(AUTH_INPUT_DIGEST, digest_guard)
        # The compact digest destination aliases retired post-parser state.
        # Seed the commit predicate after its pre-copy sentinel.
        write_word(machine.uc, 0x3C35, 0)
        machine.uc.mem_write(POST_HEAD_COMPLETE, b"\x01")
        machine.uc.mem_write(POST_TICKET_MILESTONE, b"\x01")
        product_guard = bytes(
            (index * 13 + 0x41) & 0xFF
            for index in range(PRODUCT_POOL_END - PRODUCT_POOL_START)
        )
        machine.uc.mem_write(PRODUCT_POOL_START, product_guard)
        initial_services = bytes(
            machine.uc.mem_read(service_start, service_end - service_start)
        )

        events: list[str] = []
        emitted: list[str] = []
        loads: list[tuple[int, int, int]] = []
        pending_returns: list[int] = []
        pass_pointer: int | None = None
        self_overwrite: dict[str, object] | None = None

        zero_window = int(str(services["zero_window"]), 0)
        emit = int(str(services["emit"]), 0)
        fail = int(str(services["fail"]), 0)

        def zero_window_handler(machine_uc: Uc) -> None:
            events.append("zero-window")
            return_call(machine_uc)

        machine.call_handler(zero_window, zero_window_handler)

        def emit_handler(machine_uc: Uc) -> None:
            pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            emitted.append(read_z(machine_uc, pointer))
            events.append("auth-begin")
            return_call(machine_uc)

        machine.call_handler(emit, emit_handler)
        machine.fail_handler(fail)

        def load_phase(machine_uc: Uc) -> None:
            nonlocal self_overwrite
            absolute_lba = machine_uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            sectors = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            destination = machine_uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            pending_return = word(
                machine_uc,
                machine_uc.reg_read(UC_X86_REG_SP) & 0xFFFF,
            )
            load = (absolute_lba, sectors, destination)
            loads.append(load)
            pending_returns.append(pending_return)
            load_range = (destination, destination + sectors * 512)
            caller_overlap = ranges_overlap(
                load_range,
                (service_start, service_end),
            )
            return_overlap = load_range[0] <= pending_return < load_range[1]

            if len(loads) == 1:
                payload = auth_controller.ljust(sectors * 512, b"\0")
                machine_uc.mem_write(destination, payload)
                events.append("load-auth-controller")
                if caller_overlap or return_overlap:
                    self_overwrite = {
                        "destination": f"0x{destination:04x}",
                        "load_end": f"0x{load_range[1]:04x}",
                        "pending_return": f"0x{pending_return:04x}",
                        "persistent_caller_overlap": caller_overlap,
                        "pending_return_overwritten": return_overlap,
                        "persistent_bytes_changed": bytes(
                            machine_uc.mem_read(
                                service_start,
                                service_end - service_start,
                            )
                        )
                        != initial_services,
                    }
                    machine.done = True
                    machine_uc.emu_stop()
                    return
            elif len(loads) == 2:
                payload = auth_image.ljust(sectors * 512, b"\0")
                machine_uc.mem_write(destination, payload)
                events.append("load-auth-image")
                if caller_overlap or return_overlap:
                    machine.failed = True
                    machine_uc.emu_stop()
                    return
            else:
                machine.failed = True
                machine_uc.emu_stop()
                return

            if load != expected_loads[len(loads) - 1]:
                machine.failed = True
                machine_uc.emu_stop()
                return
            return_call(machine_uc)

        machine.call_handler(DELTA_LOADER_ADDR, load_phase)

        def auth_overlay_handler(machine_uc: Uc) -> None:
            events.append("auth-overlay")
            machine_uc.reg_write(UC_X86_REG_AX, 1)
            machine_uc.mem_write(AUTH_OUTPUT_STATUS, b"\x01")
            return_call(machine_uc)

        machine.call_handler(auth_entry, auth_overlay_handler)

        def auth_emit_handler(machine_uc: Uc) -> None:
            nonlocal pass_pointer
            pass_pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            events.append("auth-result")
            machine.done = True
            machine_uc.emu_stop()

        machine.call_handler(auth_emit, auth_emit_handler)
        machine.run(count=100_000)

        if expect_self_overwrite:
            if (
                machine.failed
                or not machine.done
                or len(loads) != 1
                or self_overwrite is None
                or not self_overwrite["persistent_caller_overlap"]
                or not self_overwrite["pending_return_overwritten"]
                or not self_overwrite["persistent_bytes_changed"]
            ):
                raise AssertionError(
                    "legacy 0x3400 auth transition did not reproduce "
                    f"self-overwrite: loads={loads!r} overlap={self_overwrite!r}"
                )
            return {
                "legacy_destination": "0x3400",
                "executed_through_delta_load": True,
                "self_overwrite": self_overwrite,
                "status": "rejected",
            }

        if (
            machine.failed
            or not machine.done
            or self_overwrite is not None
            or tuple(loads) != expected_loads
            or pending_returns[0] != int(str(services["transition"]), 0) + 3
            or bytes(
                machine.uc.mem_read(service_start, service_end - service_start)
            )
            != initial_services
            or bytes(machine.uc.mem_read(AUTH_IMAGE_ADDR, len(auth_image)))
            != auth_image
            or bytes(
                machine.uc.mem_read(
                    AUTH_CONTROLLER_ADDR,
                    len(auth_controller),
                )
            )
            != auth_controller
            or bytes(machine.uc.mem_read(AUTH_INPUT_DIGEST, 32)) != digest
            or bytes(
                machine.uc.mem_read(PRODUCT_POOL_START, len(product_guard))
            )
            != product_guard
            or pass_pointer != expected_pass_pointer
            or emitted != ["\r\nAUTH BEGIN\r\n"]
        ):
            raise AssertionError(
                "identity auth transition/load/link gate drifted: "
                f"failed={machine.failed} done={machine.done} "
                f"loads={loads!r} pending={pending_returns!r} "
                f"pass_pointer={pass_pointer!r} expected={expected_pass_pointer:#x} "
                f"events={events!r} emitted={emitted!r}"
            )
        expected_events = (
            "zero-window",
            "auth-begin",
            "load-auth-controller",
            "load-auth-image",
            "auth-overlay",
            "auth-result",
        )
        if tuple(events) != expected_events:
            raise AssertionError(
                f"identity auth transition ordering drifted: {events!r}"
            )
        return {
            "auth_controller_load": {
                "absolute_lba": loads[0][0],
                "sectors": loads[0][1],
                "destination": f"0x{loads[0][2]:04x}",
                "pending_return": f"0x{pending_returns[0]:04x}",
            },
            "auth_image_load": {
                "absolute_lba": loads[1][0],
                "sectors": loads[1][1],
                "destination": f"0x{loads[1][2]:04x}",
                "executable_end": f"0x{AUTH_IMAGE_END:04x}",
                "sector_load_end": f"0x{AUTH_IMAGE_LOAD_END:04x}",
                "pending_return": f"0x{pending_returns[1]:04x}",
            },
            "linked_pass_pointer": f"0x{pass_pointer:04x}",
            "persistent_caller_preserved": True,
            "ordered_events": events,
            "status": "pass",
        }

    good = run_case(post_controller, expect_self_overwrite=False)
    legacy_pattern = b"\xBB\x00\x32"
    positions = [
        offset
        for offset in range(len(post_controller))
        if post_controller.startswith(legacy_pattern, offset)
    ]
    if len(positions) != 1:
        raise AssertionError(
            "cannot isolate post auth-controller destination immediate"
        )
    legacy_post = bytearray(post_controller)
    legacy_post[positions[0] + 2] = 0x34
    legacy = run_case(bytes(legacy_post), expect_self_overwrite=True)
    return {
        "kind": "identity_auth_transition_self_overwrite_gate",
        "good": good,
        "legacy_0x3400_negative": legacy,
        "status": "pass",
    }


def test_identity_protected_capture(
    protected_controller: bytes,
    sym_listing: Path,
    manifest: dict[str, object],
    fixture: dict[str, object],
) -> dict[str, object]:
    """Execute the authenticated 117-byte capture against attempt-6 shape."""

    direct = {
        name: listing_label_address(sym_listing, name, 0x1800)
        for name in (
            "sym_transcript_snapshot",
            "sha256_init",
            "sha256_update",
            "sha256_finish",
            "sha256_save_context",
            "sha256_restore_context",
        )
    }
    plaintext_original = bytes(fixture["plaintext"])
    tail_original = bytes(fixture["tail"])
    initial_transcript = bytes(fixture["initial_transcript"])
    expected_certificate_hash = bytes(fixture["certificate_hash"])
    expected_digest = bytes(fixture["digest"])
    expected_signature = bytes(fixture["signature"])
    expected_finished = bytes(fixture["finished_verify_data"])
    compatibility_ccs = bytes(fixture["compatibility_ccs"])
    protected_header = bytes(fixture["protected_header"])
    protected_tag = bytes(fixture["protected_tag"])

    if (
        len(protected_controller) > 3 * 512
        or len(plaintext_original) != 1925
        or len(tail_original) != IDENTITY_TAIL_LEN
        or len(expected_signature) > AUTH_INPUT_SIGNATURE_MAX
    ):
        raise AssertionError("identity protected fixture/controller geometry drifted")

    def run_case(kind: str) -> dict[str, object]:
        plaintext = bytearray(plaintext_original)
        tail_start = len(plaintext) - IDENTITY_TAIL_LEN
        cv_offset = int(fixture["cv_offset_in_tail"])
        if kind == "wrong-scheme":
            plaintext[tail_start + cv_offset + 5] ^= 1
        elif kind == "bad-signature-length":
            plaintext[tail_start + cv_offset + 7] -= 1
        elif kind not in ("good", "bad-tag"):
            raise AssertionError(f"unknown identity protected case {kind!r}")
        expected_tail = bytes(plaintext[-IDENTITY_TAIL_LEN:])
        wire = (
            compatibility_ccs
            + protected_header
            + bytes(plaintext)
            + protected_tag
        )
        fragment_sizes = (1, 2, 3, 17, 383, 29, 271, 4, 384, 11)
        frames: list[bytes] = []
        cursor = 0
        fragment_index = 0
        while cursor < len(wire):
            end = min(
                len(wire),
                cursor + fragment_sizes[fragment_index % len(fragment_sizes)],
            )
            frames.append(wire[cursor:end])
            cursor = end
            fragment_index += 1

        machine = Machine(
            protected_controller,
            entry=PROTECTED_CONTROLLER_ADDR,
        )
        services = manifest["persistent_services"]
        assert isinstance(services, dict)
        emit_entry = int(str(services["emit"]), 0)
        fail_entry = int(str(services["fail"]), 0)
        zero_window_entry = int(str(services["zero_window"]), 0)
        transition_entry = int(str(services["transition"]), 0)

        stubs = {
            "transcript_update": 0x0560,
            "open_begin": 0x0562,
            "open_chunk": 0x0564,
            "open_finish": 0x0566,
            "verify_finish": 0x0568,
            "build_finish": 0x056A,
            "build_head": 0x056C,
            "derive_client_application": 0x056E,
            "nic_receive": 0x0570,
            "nic_fallback": 0x0572,
        }
        table = [0] * 18
        table[2] = stubs["transcript_update"]
        table[4] = stubs["open_begin"]
        table[6] = stubs["open_chunk"]
        table[7] = stubs["open_finish"]
        table[8] = stubs["verify_finish"]
        table[9] = stubs["build_finish"]
        table[11] = stubs["build_head"]
        table[16] = stubs["derive_client_application"]
        machine.uc.mem_write(0x1820, struct.pack("<18H", *table))
        write_word(machine.uc, NIC_VT_RECEIVE, stubs["nic_receive"])
        write_word(machine.uc, NIC_VT_RX_FALLBACK, stubs["nic_fallback"])

        before_guard = bytes([0xC3]) * (
            PROTECTED_CONTROLLER_ADDR - RX_BUFFER_END
        )
        machine.uc.mem_write(RX_BUFFER_END, before_guard)
        cv_temp_guard = bytes([0x95]) * (
            IDENTITY_CV_TEMP_END - IDENTITY_CV_PTR
        )
        machine.uc.mem_write(IDENTITY_CV_PTR, cv_temp_guard)
        post_tail_guard = bytes([0xD7]) * (
            IDENTITY_DIGEST_HOLD - IDENTITY_CV_TEMP_END
        )
        machine.uc.mem_write(IDENTITY_CV_TEMP_END, post_tail_guard)
        digest_hold_guard = bytes([0x4B]) * 32
        machine.uc.mem_write(IDENTITY_DIGEST_HOLD, digest_hold_guard)
        delta_guard = bytes([0x6D]) * (
            TCP_TAIL_STATE_START - DELTA_LOADER_ADDR
        )
        machine.uc.mem_write(DELTA_LOADER_ADDR, delta_guard)
        compact_publication_guard = bytes([0xA7]) * (
            AUTH_INPUT_END - AUTH_INPUT_SIGNATURE_LEN
        )
        machine.uc.mem_write(
            AUTH_INPUT_SIGNATURE_LEN,
            compact_publication_guard,
        )
        certificate_hash_guard = bytes([0xB6]) * 32
        machine.uc.mem_write(IDENTITY_CERT_HASH, certificate_hash_guard)
        received_finished_guard = bytes([0xE5]) * 32
        machine.uc.mem_write(0x38F0, received_finished_guard)
        product_guard = bytes(
            (index * 17 + 0x31) & 0xFF
            for index in range(PRODUCT_POOL_END - PRODUCT_POOL_START)
        )
        machine.uc.mem_write(PRODUCT_POOL_START, product_guard)

        receive_index = 0
        ack_calls = 0
        streamed = bytearray()
        hash_remaining = 0
        transcript = hashlib.sha256(initial_transcript)
        transcript_len = len(initial_transcript)
        scratch = hashlib.sha256()
        scratch_len = 0
        saved_transcript = None
        saved_transcript_len = 0
        transcript_updates: list[bytes] = []
        events: list[str] = []
        emitted: list[str] = []
        send_attempts: list[bytes] = []
        transition: tuple[int, int] | None = None
        zero_window_calls = 0
        open_finish_calls = 0
        queued_receive_calls = 0

        def tcp_receive(machine_uc: Uc) -> None:
            nonlocal receive_index
            if receive_index >= len(frames):
                return_call(machine_uc, carry=True)
                return
            payload = frames[receive_index]
            receive_index += 1
            machine_uc.mem_write(RX_BUFFER, payload)
            write_word(machine_uc, TCP_RX_PTR, RX_BUFFER)
            write_word(machine_uc, TCP_RX_LEN, len(payload))
            return_call(machine_uc)

        machine.call_handler(0x14ED, tcp_receive)

        def tcp_ack(machine_uc: Uc) -> None:
            nonlocal ack_calls
            ack_calls += 1
            return_call(machine_uc)

        machine.call_handler(0x13A6, tcp_ack)

        def open_begin(machine_uc: Uc) -> None:
            nonlocal hash_remaining
            hash_remaining = machine_uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            if (
                hash_remaining != len(plaintext) - IDENTITY_TAIL_LEN
                or bytes(machine_uc.mem_read(0x39A0, 5)) != protected_header
            ):
                return_call(machine_uc, carry=True)
                return
            events.append("open-begin")
            return_call(machine_uc)

        machine.call_handler(stubs["open_begin"], open_begin)

        def open_chunk(machine_uc: Uc) -> None:
            nonlocal hash_remaining, transcript_len
            pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            chunk = bytes(machine_uc.mem_read(pointer, count))
            streamed.extend(chunk)
            hash_count = min(count, hash_remaining)
            transcript.update(chunk[:hash_count])
            transcript_len += hash_count
            hash_remaining -= hash_count
            machine_uc.reg_write(
                UC_X86_REG_SI,
                (pointer + hash_count) & 0xFFFF,
            )
            machine_uc.reg_write(UC_X86_REG_CX, count)
            machine_uc.reg_write(UC_X86_REG_DX, hash_count & 0x3F)
            return_call(machine_uc)

        machine.call_handler(stubs["open_chunk"], open_chunk)

        def open_finish(machine_uc: Uc) -> None:
            nonlocal open_finish_calls
            open_finish_calls += 1
            events.append("aead-finish")
            pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            if (
                bytes(machine_uc.mem_read(pointer, 16)) != protected_tag
                or bytes(streamed) != bytes(plaintext)
                or hash_remaining != 0
                or bytes(
                    machine_uc.mem_read(IDENTITY_TAIL, IDENTITY_TAIL_LEN)
                )
                != expected_tail
            ):
                return_call(machine_uc, carry=True)
                return
            if transition is not None or transcript_updates:
                raise AssertionError(
                    "identity capture transitioned/parsed before AEAD finish"
                )
            if bytes(
                machine_uc.mem_read(
                    AUTH_INPUT_SIGNATURE_LEN,
                    len(compact_publication_guard),
                )
            ) != compact_publication_guard:
                raise AssertionError(
                    "identity compact auth publication occurred before AEAD"
                )
            if bytes(
                machine_uc.mem_read(IDENTITY_CERT_HASH, 32)
            ) != certificate_hash_guard:
                raise AssertionError(
                    "identity certificate hash published before AEAD"
                )
            if bytes(
                machine_uc.mem_read(IDENTITY_DIGEST_HOLD, 32)
            ) != digest_hold_guard:
                raise AssertionError(
                    "identity digest hold changed before AEAD"
                )
            if bytes(
                machine_uc.mem_read(IDENTITY_CV_PTR, len(cv_temp_guard))
            ) != cv_temp_guard:
                raise AssertionError(
                    "identity CV temporary state changed before AEAD"
                )
            if kind == "bad-tag":
                return_call(machine_uc, carry=True)
                return
            events.append("aead-success")
            return_call(machine_uc)

        machine.call_handler(stubs["open_finish"], open_finish)

        def sha_style_update(
            machine_uc: Uc,
            active,
            active_len: int,
        ) -> tuple[object, int]:
            pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            payload = bytes(machine_uc.mem_read(pointer, count))
            active.update(payload)
            if count:
                machine_uc.reg_write(
                    UC_X86_REG_DX,
                    (active_len + count - 1) & 0x3F,
                )
            machine_uc.reg_write(
                UC_X86_REG_SI,
                (pointer + count) & 0xFFFF,
            )
            machine_uc.reg_write(UC_X86_REG_CX, 0)
            return active, active_len + count

        def transcript_update(machine_uc: Uc) -> None:
            nonlocal transcript, transcript_len
            pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            transcript_updates.append(
                bytes(machine_uc.mem_read(pointer, count))
            )
            events.append(f"transcript-update-{count}")
            transcript, transcript_len = sha_style_update(
                machine_uc,
                transcript,
                transcript_len,
            )
            return_call(machine_uc)

        machine.call_handler(stubs["transcript_update"], transcript_update)

        def transcript_snapshot(machine_uc: Uc) -> None:
            destination = machine_uc.reg_read(UC_X86_REG_DI) & 0xFFFF
            machine_uc.mem_write(destination, transcript.copy().digest())
            events.append("transcript-snapshot")
            return_call(machine_uc)

        machine.call_handler(
            direct["sym_transcript_snapshot"],
            transcript_snapshot,
        )

        def save_context(machine_uc: Uc) -> None:
            nonlocal saved_transcript, saved_transcript_len
            saved_transcript = transcript.copy()
            saved_transcript_len = transcript_len
            events.append("sha-save")
            return_call(machine_uc)

        machine.call_handler(direct["sha256_save_context"], save_context)

        def sha_init(machine_uc: Uc) -> None:
            nonlocal scratch, scratch_len
            scratch = hashlib.sha256()
            scratch_len = 0
            events.append("sha-init")
            return_call(machine_uc)

        machine.call_handler(direct["sha256_init"], sha_init)

        def sha_update(machine_uc: Uc) -> None:
            nonlocal scratch, scratch_len
            scratch, scratch_len = sha_style_update(
                machine_uc,
                scratch,
                scratch_len,
            )
            return_call(machine_uc)

        machine.call_handler(direct["sha256_update"], sha_update)

        def sha_finish(machine_uc: Uc) -> None:
            destination = machine_uc.reg_read(UC_X86_REG_DI) & 0xFFFF
            machine_uc.mem_write(destination, scratch.copy().digest())
            events.append("sha-finish")
            return_call(machine_uc)

        machine.call_handler(direct["sha256_finish"], sha_finish)

        def restore_context(machine_uc: Uc) -> None:
            nonlocal transcript, transcript_len
            if saved_transcript is None:
                return_call(machine_uc, carry=True)
                return
            transcript = saved_transcript.copy()
            transcript_len = saved_transcript_len
            events.append("sha-restore")
            return_call(machine_uc)

        machine.call_handler(direct["sha256_restore_context"], restore_context)

        def verify_finish(machine_uc: Uc) -> None:
            if (
                bytes(machine_uc.mem_read(0x38F0, 32)) != expected_finished
                or transcript.copy().digest()
                != hashlib.sha256(
                    initial_transcript
                    + bytes(plaintext[:-37])
                ).digest()
            ):
                return_call(machine_uc, carry=True)
                return
            events.append("verify-finished")
            return_call(machine_uc)

        machine.call_handler(stubs["verify_finish"], verify_finish)
        finished_record = b"\x17\x03\x03\x00\x35" + bytes(range(53))

        def build_finish(machine_uc: Uc) -> None:
            machine_uc.mem_write(0x39A0, finished_record)
            machine_uc.reg_write(UC_X86_REG_AX, 58)
            events.append("build-client-finished")
            return_call(machine_uc)

        machine.call_handler(stubs["build_finish"], build_finish)

        def derive_client_application(machine_uc: Uc) -> None:
            events.append("derive-client-application")
            write_word(machine_uc, BIOS_TICK, 0x011B)
            return_call(machine_uc)

        machine.call_handler(
            stubs["derive_client_application"],
            derive_client_application,
        )
        head_record = b"\x17\x03\x03\x00\x43" + bytes(range(67))

        def build_head(machine_uc: Uc) -> None:
            machine_uc.mem_write(0x39A0, head_record)
            machine_uc.reg_write(UC_X86_REG_AX, 72)
            events.append("build-head")
            return_call(machine_uc)

        machine.call_handler(stubs["build_head"], build_head)

        def tcp_send(machine_uc: Uc) -> None:
            pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            send_attempts.append(bytes(machine_uc.mem_read(pointer, count)))
            events.append(
                "send-client-finished"
                if len(send_attempts) == 1
                else "send-head"
            )
            write_word(
                machine_uc,
                BIOS_TICK,
                0x010F if len(send_attempts) == 1 else 0x0122,
            )
            return_call(machine_uc)

        machine.call_handler(0x13BF, tcp_send)

        def wait_ticks(machine_uc: Uc) -> None:
            return_call(machine_uc)

        machine.call_handler(0x11E5, wait_ticks)

        def nic_receive(machine_uc: Uc) -> None:
            nonlocal queued_receive_calls
            queued_receive_calls += 1
            write_word(machine_uc, NE_RX_SAMPLE_COUNT, 0)
            return_call(machine_uc)

        machine.call_handler(stubs["nic_receive"], nic_receive)
        machine.call_handler(
            stubs["nic_fallback"],
            lambda machine_uc: return_call(machine_uc, carry=True),
        )

        def parse_tcp_payload(machine_uc: Uc) -> None:
            return_call(machine_uc, carry=True)

        machine.call_handler(PARSE_TCP_PAYLOAD, parse_tcp_payload)

        def emit(machine_uc: Uc) -> None:
            emitted.append(
                read_z(
                    machine_uc,
                    machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
                )
            )
            return_call(machine_uc)

        machine.call_handler(emit_entry, emit)

        def zero_window(machine_uc: Uc) -> None:
            nonlocal zero_window_calls
            zero_window_calls += 1
            events.append("zero-window")
            return_call(machine_uc)

        machine.call_handler(zero_window_entry, zero_window)

        def transition_handler(machine_uc: Uc) -> None:
            nonlocal transition
            transition = (
                machine_uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
                machine_uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
            )
            events.append("post-controller-transition")
            machine.done = True
            machine_uc.emu_stop()

        machine.call_handler(transition_entry, transition_handler)

        def fail(machine_uc: Uc) -> None:
            events.append("fail")
            machine.failed = True
            machine_uc.emu_stop()

        machine.call_handler(fail_entry, fail)
        write_word(machine.uc, 0x3CA0, 0x0100)
        write_word(machine.uc, 0x3CA2, 0x0103)
        machine.sym_initialized = True
        machine.run(count=20_000_000)

        sentinel_failures = []
        for label, address, expected_bytes in (
            ("rx-upper", RX_BUFFER_END, before_guard),
            ("identity-tail-upper", IDENTITY_CV_TEMP_END, post_tail_guard),
            ("delta-loader", DELTA_LOADER_ADDR, delta_guard),
            ("product-pool", PRODUCT_POOL_START, product_guard),
        ):
            if bytes(
                machine.uc.mem_read(address, len(expected_bytes))
            ) != expected_bytes:
                sentinel_failures.append(label)
        if sentinel_failures:
            raise AssertionError(
                f"identity {kind} crossed memory sentinel(s): "
                f"{sentinel_failures!r}"
            )

        if kind != "good":
            if not machine.failed or machine.done:
                raise AssertionError(f"identity {kind} did not fail closed")
            if open_finish_calls != 1 or receive_index != len(frames):
                raise AssertionError(
                    f"identity {kind} failed before complete AEAD/tag input"
                )
            if transition is not None or zero_window_calls or send_attempts:
                raise AssertionError(
                    f"identity {kind} escaped into post-controller dialogue"
                )
            if transcript_updates:
                raise AssertionError(
                    f"identity {kind} parsed tail before authenticated shape"
                )
            if bytes(
                machine.uc.mem_read(
                    AUTH_INPUT_SIGNATURE_LEN,
                    len(compact_publication_guard),
                )
            ) != compact_publication_guard:
                raise AssertionError(
                    f"identity {kind} published compact auth input"
                )
            if bytes(
                machine.uc.mem_read(IDENTITY_CERT_HASH, 32)
            ) != certificate_hash_guard:
                raise AssertionError(
                    f"identity {kind} published a certificate hash"
                )
            if bytes(
                machine.uc.mem_read(IDENTITY_DIGEST_HOLD, 32)
            ) != digest_hold_guard:
                raise AssertionError(
                    f"identity {kind} published a digest hold"
                )
            if bytes(
                machine.uc.mem_read(IDENTITY_CV_PTR, len(cv_temp_guard))
            ) != cv_temp_guard:
                raise AssertionError(
                    f"identity {kind} published CV temporary state"
                )
            if bytes(machine.uc.mem_read(0x38F0, 32)) != received_finished_guard:
                raise AssertionError(
                    f"identity {kind} published server Finished"
                )
            return {
                "negative": kind,
                "fragmented_frames": len(frames),
                "failure_after_complete_tag": True,
                "tail_quarantined_bytes": IDENTITY_TAIL_LEN,
                "transcript_updates": 0,
                "compact_auth_publication_bytes": 0,
                "post_controller_transitions": 0,
                "status": "rejected",
            }

        if machine.failed or not machine.done:
            raise AssertionError(
                "identity protected controller failed before transition: "
                f"events={events!r}"
            )
        compact_length = word(machine.uc, AUTH_INPUT_SIGNATURE_LEN)
        compact_signature = bytes(
            machine.uc.mem_read(AUTH_INPUT_SIGNATURE, AUTH_INPUT_SIGNATURE_MAX)
        )
        compact_digest = bytes(machine.uc.mem_read(AUTH_INPUT_DIGEST, 32))
        compact_status = machine.uc.mem_read(AUTH_OUTPUT_STATUS, 1)[0]
        if compact_length != len(expected_signature):
            raise AssertionError(
                "identity compact signature length differs from attempt-6: "
                f"{compact_length} != {len(expected_signature)}"
            )
        if (
            compact_signature[:compact_length] != expected_signature
            or any(compact_signature[compact_length:])
        ):
            raise AssertionError(
                "identity compact signature bytes differ from attempt-6"
            )
        if compact_digest != expected_digest:
            raise AssertionError(
                "identity compact digest differs from host transcript oracle: "
                f"{compact_digest.hex()} != {expected_digest.hex()}"
            )
        if compact_status != 0:
            raise AssertionError("identity capture prematurely committed auth status")
        if (
            bytes(machine.uc.mem_read(IDENTITY_CERT_HASH, 32))
            != expected_certificate_hash
            or bytes(machine.uc.mem_read(IDENTITY_TAIL, IDENTITY_TAIL_LEN))
            != tail_original
            or bytes(machine.uc.mem_read(IDENTITY_DIGEST_HOLD, 32))
            != expected_digest
        ):
            raise AssertionError("identity authenticated quarantine publication drifted")
        if (
            word(machine.uc, IDENTITY_CV_PTR)
            != IDENTITY_TAIL + int(fixture["cv_offset_in_tail"])
            or word(machine.uc, IDENTITY_CV_DER_LEN)
            != len(expected_signature)
        ):
            raise AssertionError("identity frozen CV pointer/length drifted")
        if transcript_updates != [tail_original[:1], tail_original[1:80]]:
            raise AssertionError(
                f"identity transcript boundary drifted: "
                f"{list(map(len, transcript_updates))!r}"
            )
        expected_transition = (
            parse_key(manifest, "post_controller"),
            POST_CONTROLLER_ADDR,
        )
        if transition != expected_transition or zero_window_calls != 1:
            raise AssertionError(
                f"identity post-controller transition drifted: {transition!r}"
            )
        required_order = (
            "aead-success",
            "transcript-update-1",
            "transcript-snapshot",
            "transcript-update-79",
            "verify-finished",
            "send-client-finished",
            "derive-client-application",
            "send-head",
            "zero-window",
            "post-controller-transition",
        )
        positions = [events.index(event) for event in required_order]
        if positions != sorted(positions):
            raise AssertionError(f"identity transition ordering drifted: {events!r}")
        if (
            len(send_attempts) != 2
            or send_attempts != [finished_record, head_record]
            or queued_receive_calls != 1
        ):
            raise AssertionError("identity Finished/HEAD dialogue drifted")
        return {
            "fragmented_wire_bytes": len(wire),
            "fragmented_frames": len(frames),
            "attempt6_plaintext_bytes": len(plaintext),
            "tail_quarantine_bytes": IDENTITY_TAIL_LEN,
            "tail_sha256": hashlib.sha256(tail_original).hexdigest(),
            "certificate_hash": expected_certificate_hash.hex(),
            "compact_digest": compact_digest.hex(),
            "compact_signature_bytes": compact_length,
            "compact_signature_sha256": hashlib.sha256(
                compact_signature[:compact_length]
            ).hexdigest(),
            "status_before_auth_overlay": compact_status,
            "post_controller_transition": {
                "key": f"0x{transition[0]:04x}",
                "destination": f"0x{transition[1]:04x}",
            },
            "ordered_events": events,
            "status": "pass",
        }

    good = run_case("good")
    bad_tag = run_case("bad-tag")
    wrong_scheme = run_case("wrong-scheme")
    bad_signature_length = run_case("bad-signature-length")
    return {
        "kind": "attempt6_fragmented_identity_quarantine_gate",
        "host_signature_verified": fixture["host_signature_verified"],
        "message_lengths": fixture["message_lengths"],
        "cv_offset_in_117_byte_tail": fixture["cv_offset_in_tail"],
        "good": good,
        "bad_tag": bad_tag,
        "wrong_scheme": wrong_scheme,
        "bad_signature_length": bad_signature_length,
        "status": "pass",
    }


def test_post_finished(
    post_controller: bytes,
    manifest: dict[str, object],
    *,
    record_order: str = "ticket-http",
    reject_tag_index: int | None = None,
    authenticated_alert: bytes | None = None,
    oversized_record: bool = False,
    wrong_inner_type: str | None = None,
    split_http: bool = False,
    padded_record: bool = False,
    coalesced_trailing: bool = False,
    trailing_header_bytes: int | None = None,
    http_plaintext_bytes: int = 1124,
    ticket_limit_layout: tuple[int, ...] | None = None,
    authenticated_key_update: bool = False,
    nst_extension_negative: str | None = None,
) -> dict[str, object]:
    machine = Machine(post_controller, entry=POST_CONTROLLER_ADDR)
    services = manifest["persistent_services"]
    assert isinstance(services, dict)
    emit_entry = int(services["emit"], 0)
    fail_entry = int(services["fail"], 0)
    machine.fail_handler(fail_entry)

    stubs = {
        "open_begin": 0x0540,
        "open_chunk": 0x0542,
        "open_finish": 0x0544,
        "parse_nst": 0x0546,
        "nic_receive": 0x0548,
        "derive_server_application": 0x054A,
    }
    table = [0] * 18
    table[5] = stubs["open_begin"]
    table[6] = stubs["open_chunk"]
    table[7] = stubs["open_finish"]
    table[12] = stubs["parse_nst"]
    table[17] = stubs["derive_server_application"]
    machine.uc.mem_write(0x1820, struct.pack("<18H", *table))
    write_word(machine.uc, NIC_VT_RECEIVE, stubs["nic_receive"])
    ticket_extensions = (
        NST_LIVE_EXTENSIONS
        if nst_extension_negative is None
        else NST_EXTENSION_NEGATIVES[nst_extension_negative]
    )

    def nst(seed: int, identity_len: int = 192) -> bytes:
        identity = bytes(
            (index * 7 + seed) & 0xFF for index in range(identity_len)
        )
        body = (
            (64800).to_bytes(4, "big")
            + (0x12345678 + seed).to_bytes(4, "big")
            + b"\x01"
            + bytes([seed])
            + len(identity).to_bytes(2, "big")
            + identity
            + len(ticket_extensions).to_bytes(2, "big")
            + ticket_extensions
        )
        return b"\x04" + len(body).to_bytes(3, "big") + body

    tickets = (
        tuple(nst(seed, 16) for seed in range(1, 6))
        if ticket_limit_layout is not None
        else (nst(1), nst(2))
    )
    ticket_plain = b"".join(tickets) + b"\x16"
    response_prefix = b"HTTP/1.1 401 Unauthorized\r\nX-Fill: "
    response_suffix = b"\r\n\r\n"
    response_content_bytes = http_plaintext_bytes - 1
    if response_content_bytes < len(response_prefix) + len(response_suffix):
        raise AssertionError("HTTP scatter fixture is too short")
    printable = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-._~"
    response = (
        response_prefix
        + bytes(
            printable[index % len(printable)]
            for index in range(
                response_content_bytes
                - len(response_prefix)
                - len(response_suffix)
            )
        )
        + response_suffix
    )
    if len(response) != response_content_bytes:
        raise AssertionError("HTTP scatter fixture drifted")

    def record(plaintext: bytes, tag: bytes) -> bytes:
        return (
            b"\x17\x03\x03"
            + (len(plaintext) + len(tag)).to_bytes(2, "big")
            + plaintext
            + tag
        )

    if authenticated_alert is not None:
        plaintext_records = [authenticated_alert + b"\x15"]
        case = "alert"
    elif authenticated_key_update:
        plaintext_records = [b"\x18\x00\x00\x01\x00\x16"]
        case = "authenticated-key-update"
    elif ticket_limit_layout is not None:
        if (
            sum(ticket_limit_layout) != len(tickets)
            or not ticket_limit_layout
            or any(count <= 0 for count in ticket_limit_layout)
        ):
            raise AssertionError(
                f"invalid ticket-limit layout {ticket_limit_layout!r}"
            )
        plaintext_records = []
        ticket_index = 0
        for count in ticket_limit_layout:
            plaintext_records.append(
                b"".join(tickets[ticket_index : ticket_index + count])
                + b"\x16"
            )
            ticket_index += count
        case = "ticket-limit-" + "+".join(map(str, ticket_limit_layout))
    elif oversized_record:
        plaintext_records = [b"H" * POST_RECORD_PLAIN_MAX + b"\x17"]
        case = "oversized"
    elif wrong_inner_type == "http-as-handshake":
        plaintext_records = [response + b"\x16"]
        case = wrong_inner_type
    elif wrong_inner_type == "ticket-as-application":
        plaintext_records = [ticket_plain[:-1] + b"\x17"]
        case = wrong_inner_type
    elif padded_record:
        plaintext_records = [response + b"\x17\x00"]
        case = "tls-inner-plaintext-padding"
    else:
        http_records = (
            [response[:600] + b"\x17", response[600:] + b"\x17"]
            if split_http
            else [response + b"\x17"]
        )
        if record_order == "ticket-http":
            plaintext_records = [ticket_plain, *http_records]
        elif record_order == "http-ticket":
            plaintext_records = [*http_records, ticket_plain]
        else:
            raise AssertionError(f"unknown post-Finished order {record_order!r}")
        case = f"{record_order}{'-split' if split_http else ''}"

    tags = [
        bytes((0xA0 + record_index * 16 + offset) & 0xFF for offset in range(16))
        for record_index in range(len(plaintext_records))
    ]
    wire = b"".join(
        record(plaintext, tag)
        for plaintext, tag in zip(plaintext_records, tags, strict=True)
    )
    if trailing_header_bytes is not None:
        if trailing_header_bytes not in range(1, 6):
            raise AssertionError("trailing TLS header prefix must be 1..5 bytes")
        wire += b"\x17\x03\x03\x00\x11"[:trailing_header_bytes]
        case += f"-trailing-header-{trailing_header_bytes}"
    elif coalesced_trailing:
        wire += b"\x17\x03\x03\x00\x01\x00"
        case += "-coalesced-trailing"
    fragment_sizes = (3, 94, 211, 1, 377, 83, 256, 17)
    cuts: list[int] = []
    cursor = 0
    fragment_index = 0
    while cursor < len(wire):
        cursor = min(
            len(wire),
            cursor + fragment_sizes[fragment_index % len(fragment_sizes)],
        )
        cuts.append(cursor)
        fragment_index += 1
    frames: list[bytes] = []
    start = 0
    for end in cuts:
        frames.append(wire[start:end])
        start = end
    receive_index = 0
    open_calls = 0
    chunk_lengths: list[int] = []
    finish_calls = 0
    parsed_tickets: list[bytes] = []
    retained_ticket: bytes | None = None
    emitted: list[str] = []
    ack_calls = 0
    flush_calls = 0
    derive_server_calls = 0
    ordered_events: list[str] = []

    product_pool_guard = bytes(
        (index * 19 + 0x51) & 0xFF
        for index in range(PRODUCT_POOL_END - PRODUCT_POOL_START)
    )
    machine.uc.mem_write(PRODUCT_POOL_START, product_pool_guard)
    loader_guard = bytes(
        (index * 13 + 0x31) & 0xFF
        for index in range(TCP_TAIL_STATE_START - DELTA_LOADER_ADDR)
    )
    machine.uc.mem_write(DELTA_LOADER_ADDR, loader_guard)
    client_state_guard = bytes(
        (index * 29 + 0x67) & 0xFF
        for index in range(POST_RECEIVED_TAG - POST_CLIENT_APP_STATE)
    )
    machine.uc.mem_write(POST_CLIENT_APP_STATE, client_state_guard)
    ticket_boundary_guard = bytes(
        (index * 31 + 0x2B) & 0xFF
        for index in range(POST_SCATTER_HIGH_END, 0x3C2C)
    )
    machine.uc.mem_write(POST_SCATTER_HIGH_END, ticket_boundary_guard)
    write_word(machine.uc, BIOS_TICK, 0x0130)
    write_word(machine.uc, 0x3CA4, 0x010F)
    write_word(machine.uc, 0x3CA6, 0x011B)
    write_word(machine.uc, 0x3CA8, 0x0122)

    def nic_receive(machine_uc: Uc) -> None:
        nonlocal flush_calls
        flush_calls += 1
        ordered_events.append("flush")
        write_word(machine_uc, NE_RX_SAMPLE_COUNT, 0)
        return_call(machine_uc)

    machine.call_handler(stubs["nic_receive"], nic_receive)

    def tcp_ack(machine_uc: Uc) -> None:
        nonlocal ack_calls
        ack_calls += 1
        return_call(machine_uc)

    machine.call_handler(0x13A6, tcp_ack)

    def tcp_receive(machine_uc: Uc) -> None:
        nonlocal receive_index
        if receive_index >= len(frames):
            return_call(machine_uc, carry=True)
            return
        payload = frames[receive_index]
        receive_index += 1
        machine_uc.mem_write(RX_BUFFER, payload)
        write_word(machine_uc, TCP_RX_PTR, RX_BUFFER)
        write_word(machine_uc, TCP_RX_LEN, len(payload))
        return_call(machine_uc)

    machine.call_handler(0x14ED, tcp_receive)

    def open_begin(machine_uc: Uc) -> None:
        nonlocal open_calls
        open_calls += 1
        return_call(machine_uc)

    machine.call_handler(stubs["open_begin"], open_begin)

    def open_chunk(machine_uc: Uc) -> None:
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        chunk_lengths.append(count)
        machine_uc.reg_write(UC_X86_REG_SI, (pointer + count) & 0xFFFF)
        machine_uc.reg_write(UC_X86_REG_CX, 0)
        machine_uc.reg_write(UC_X86_REG_DX, 0xD00D)
        return_call(machine_uc)

    machine.call_handler(stubs["open_chunk"], open_chunk)

    def open_finish(machine_uc: Uc) -> None:
        nonlocal finish_calls
        finish_calls += 1
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        received = bytes(machine_uc.mem_read(pointer, 16))
        expected = tags[finish_calls - 1]
        if received != expected or reject_tag_index == finish_calls:
            return_call(machine_uc, carry=True)
            return
        return_call(machine_uc)

    machine.call_handler(stubs["open_finish"], open_finish)

    def parse_nst(machine_uc: Uc) -> None:
        nonlocal retained_ticket
        pointer = machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = machine_uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        message = bytes(machine_uc.mem_read(pointer, count))
        if message not in tickets or not nst_extensions_are_accepted(message):
            return_call(machine_uc, carry=True)
            return
        parsed_tickets.append(message)
        if retained_ticket is None:
            retained_ticket = message
        machine_uc.mem_write(0x3C2C, b"\x01")
        return_call(machine_uc)

    machine.call_handler(stubs["parse_nst"], parse_nst)

    def derive_server_application(machine_uc: Uc) -> None:
        nonlocal derive_server_calls
        derive_server_calls += 1
        ordered_events.append("derive-server")
        return_call(machine_uc)

    machine.call_handler(
        stubs["derive_server_application"],
        derive_server_application,
    )

    def emit(machine_uc: Uc) -> None:
        text = read_z(
            machine_uc,
            machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
        )
        emitted.append(text)
        if "RESULT" in text:
            machine.done = True
            machine_uc.emu_stop()
            return
        return_call(machine_uc)

    machine.call_handler(emit_entry, emit)
    machine.sym_initialized = True
    machine.run()
    output = "".join(emitted)

    if derive_server_calls != 1 or ordered_events[:2] != [
        "derive-server",
        "flush",
    ]:
        raise AssertionError(
            f"deferred server-key ordering drifted: {ordered_events!r}"
        )
    if flush_calls != 1:
        raise AssertionError("post-Finished zero-window recovery drifted")
    if (
        bytes(machine.uc.mem_read(PRODUCT_POOL_START, len(product_pool_guard)))
        != product_pool_guard
    ):
        raise AssertionError("post-Finished controller changed product arena/context")
    if (
        bytes(machine.uc.mem_read(DELTA_LOADER_ADDR, len(loader_guard)))
        != loader_guard
    ):
        raise AssertionError("post-Finished scatter crossed into delta loader")
    if (
        bytes(
            machine.uc.mem_read(
                POST_CLIENT_APP_STATE,
                len(client_state_guard),
            )
        )
        != client_state_guard
    ):
        raise AssertionError("post-Finished scatter changed retained application state")
    if (
        bytes(
            machine.uc.mem_read(
                POST_SCATTER_HIGH_END,
                len(ticket_boundary_guard),
            )
        )
        != ticket_boundary_guard
    ):
        raise AssertionError("post-Finished scatter crossed ticket start 0x3b40")
    forbidden_writes = [
        (ip, address, size)
        for ip, address, size in machine.post_sym_writes
        if ranges_overlap(
            (address, address + size),
            (PRODUCT_POOL_START, PRODUCT_POOL_END),
        )
        or ranges_overlap(
            (address, address + size),
            (POST_CLIENT_APP_STATE, POST_RECEIVED_TAG),
        )
        or ranges_overlap(
            (address, address + size),
            (POST_SCATTER_HIGH_END, 0x3C2C),
        )
    ]
    if forbidden_writes:
        raise AssertionError(
            f"post-Finished controller crossed a retained range: {forbidden_writes!r}"
        )

    if reject_tag_index is not None:
        if not machine.failed or machine.done:
            raise AssertionError("bad post-Finished tag was not rejected")
        rejected_plaintext = plaintext_records[reject_tag_index - 1]
        if (
            read_post_scatter(machine.uc, len(rejected_plaintext))
            != rejected_plaintext
        ):
            raise AssertionError(
                "bad-tag plaintext was not reconstructed exactly in quarantine"
            )
        if parsed_tickets or any(
            marker in output for marker in ("TICKET", "HEAD OK", "CANARY COMMIT")
        ):
            raise AssertionError("unauthenticated plaintext escaped scatter quarantine")
        if (
            word(machine.uc, POST_HTTP_TOTAL) != 0
            or machine.uc.mem_read(POST_HTTP_MATCH, 1) != b"\x00"
            or machine.uc.mem_read(POST_HTTP_DONE, 1) != b"\x00"
            or machine.uc.mem_read(POST_HEAD_COMPLETE, 1) != b"\x00"
        ):
            raise AssertionError("bad-tag HTTP mutated tentative/committed DFA state")
        return {
            "negative": "bad-tag-no-plaintext-dependent-commit",
            "authenticated_ticket_messages": 0,
            "http_state_changes": 0,
            "status": "rejected",
        }
    if authenticated_key_update:
        if not machine.failed or machine.done:
            raise AssertionError("authenticated KeyUpdate was not rejected")
        if parsed_tickets or any(
            marker in output for marker in ("TICKET", "HEAD OK", "CANARY COMMIT")
        ):
            raise AssertionError("authenticated KeyUpdate reached a success milestone")
        return {
            "negative": "authenticated-key-update-unsupported",
            "plaintext_authenticated_before_rejection": True,
            "status": "rejected",
        }
    if authenticated_alert is not None:
        if not machine.failed or machine.done:
            raise AssertionError("authenticated post-Finished alert did not fail closed")
        if any(marker in output for marker in ("HEAD OK", "TICKET", "CANARY COMMIT")):
            raise AssertionError("authenticated alert reached a success milestone")
        return {
            "negative": (
                "authenticated-close-notify"
                if authenticated_alert == b"\x01\x00"
                else "authenticated-other-alert"
            ),
            "classification": "level-byte-accepted/type-checked/fail-closed",
            "status": "rejected",
        }
    if nst_extension_negative is not None:
        if not machine.failed or machine.done:
            raise AssertionError(
                f"malformed NST extension {nst_extension_negative} was not rejected"
            )
        if parsed_tickets or any(
            marker in output for marker in ("HEAD OK", "TICKET", "CANARY COMMIT")
        ):
            raise AssertionError(
                f"malformed NST extension {nst_extension_negative} reached a milestone"
            )
        return {
            "negative": f"nst-extension-{nst_extension_negative}",
            "authenticated_before_parser_rejection": True,
            "ticket_state_commits": 0,
            "status": "rejected",
        }
    if ticket_limit_layout is not None:
        if not machine.failed or machine.done:
            raise AssertionError("fifth ticket was not rejected connection-wide")
        if parsed_tickets != list(tickets[:4]):
            raise AssertionError(
                f"ticket-limit parser calls drifted: {len(parsed_tickets)}"
            )
        if retained_ticket != tickets[0]:
            raise AssertionError("fifth-ticket rejection changed retained first ticket")
        if (
            "HEAD OK" in output
            or "CANARY COMMIT" in output
            or machine.uc.mem_read(POST_HEAD_COMPLETE, 1) != b"\x00"
        ):
            raise AssertionError("fifth ticket escaped into HTTP/canary commit")
        return {
            "negative": "fifth-ticket-connection-wide",
            "record_layout": list(ticket_limit_layout),
            "authenticated_records": finish_calls,
            "tickets_parsed": len(parsed_tickets),
            "retained_first_ticket_stable": True,
            "status": "rejected",
        }
    if oversized_record:
        if not machine.failed or machine.done or open_calls or finish_calls:
            raise AssertionError("oversized post-Finished record was not rejected at header")
        return {
            "negative": "plaintext-cap-plus-one",
            "cap_bytes": POST_RECORD_PLAIN_MAX,
            "status": "rejected",
        }
    if wrong_inner_type is not None or padded_record:
        if not machine.failed or machine.done:
            raise AssertionError(f"{case} was not rejected")
        if parsed_tickets or any(
            marker in output for marker in ("HEAD OK", "TICKET", "CANARY COMMIT")
        ):
            raise AssertionError(f"{case} committed mismatched plaintext")
        return {
            "negative": case,
            "status": "rejected",
        }
    if coalesced_trailing or trailing_header_bytes is not None:
        if not machine.failed or machine.done or "CANARY COMMIT" in output:
            raise AssertionError("coalesced trailing record bypassed clean-boundary gate")
        pending_word = word(machine.uc, 0x3C35)
        if trailing_header_bytes is not None:
            expected_pending = (
                trailing_header_bytes
                if trailing_header_bytes < 5
                else 0x0105
            )
            if pending_word != expected_pending:
                raise AssertionError(
                    "partial trailing-header state drifted: "
                    f"{pending_word:#06x} != {expected_pending:#06x}"
                )
        return {
            "negative": (
                f"trailing-header-{trailing_header_bytes}-before-canary"
                if trailing_header_bytes is not None
                else "coalesced-trailing-before-canary"
            ),
            "authenticated_records": finish_calls,
            "pending_record_state": f"0x{pending_word:04x}",
            "status": "rejected",
        }

    required_markers = (
        "TICKET",
        "HEAD OK",
        "CANARY COMMIT",
        "PASS",
        "RESULT",
    )
    if machine.failed or not machine.done:
        raise AssertionError(
            f"post-Finished controller failed: output={output!r} "
            f"frames={receive_index}/{len(frames)}"
        )
    if parsed_tickets != list(tickets):
        raise AssertionError("coalesced ticket parsing/drain drifted")
    if any(marker not in output for marker in required_markers):
        raise AssertionError(f"post-Finished milestone protocol drifted: {output!r}")
    if open_calls != len(plaintext_records) or finish_calls != len(plaintext_records):
        raise AssertionError("post-Finished record epoch/count drifted")
    if ack_calls < 1:
        raise AssertionError("post-Finished zero-window recovery drifted")
    head_index = output.index("HEAD OK")
    ticket_index = output.index("TICKET")
    if (record_order == "ticket-http") != (ticket_index < head_index):
        raise AssertionError(f"ticket/HTTP record order drifted: {output!r}")
    if record_order == "ticket-http" and not split_http:
        expected_scatter = response + b"\x17"
        if (
            read_post_scatter(machine.uc, len(expected_scatter))
            != expected_scatter
        ):
            raise AssertionError(
                "authenticated HTTP plaintext did not cross scatter seams exactly"
            )
    return {
        "head_record_bytes": 72,
        "head_already_outstanding_at_entry": True,
        "server_application_read_key_derived_before_window_reopen": True,
        "server_records_authenticated": finish_calls,
        "coalesced_ticket_messages": len(parsed_tickets),
        "nst_extensions_hex": ticket_extensions.hex(),
        "nst_extension_profile": (
            "early_data_then_zero_length_unknown"
        ),
        "http_content_bytes": len(response),
        "largest_plaintext_record_bytes": max(map(len, plaintext_records)),
        "record_order": record_order,
        "http_records": 2 if split_http else 1,
        "scatter": (
            "0x0d00..0x0f00 + 0x3600..0x3838 + "
            "0x3920..0x3b40 = 1624 bytes"
        ),
        "retained_client_application_state": "0x3838..0x3910",
        "milestones": list(required_markers),
        "product_arena_context_writes": 0,
        "terminal": output,
        "status": "pass",
    }


def test_post_finished_real_k14_aead(
    post_controller: bytes,
    sym_image: bytes,
    manifest: dict[str, object],
) -> dict[str, object]:
    """Run the post controller against the actual K14 server-open entries."""

    symmetric = load_symmetric_checker()
    header = symmetric.parse_header(sym_image)
    sym_phase = parse_phase(manifest, "sym")
    if (
        int(str(sym_phase["destination"]), 0) != symmetric.OVERLAY_BASE
        or int(sym_phase["bytes"]) != len(sym_image)
        or sym_phase["sha256"] != hashlib.sha256(sym_image).hexdigest()
        or header.image_bytes != len(sym_image)
        or header.low_end > 0x3400
        or len(header.entries) != 19
    ):
        raise AssertionError("real-AEAD K14 artifact/manifest geometry drifted")

    response_prefix = b"HTTP/1.1 401 Unauthorized\r\nX-Fill: "
    response_suffix = b"\r\n\r\n"
    printable = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-._~"
    response = (
        response_prefix
        + bytes(
            printable[index % len(printable)]
            for index in range(
                1123 - len(response_prefix) - len(response_suffix)
            )
        )
        + response_suffix
    )
    plaintext = response + bytes([symmetric.O.CONTENT_APPLICATION_DATA])
    if len(response) != 1123 or len(plaintext) != 1124:
        raise AssertionError("real-AEAD 1,124-byte plaintext fixture drifted")

    server_key = hashlib.sha256(b"Seed live K14 real server application key").digest()
    server_iv = hashlib.sha256(b"Seed live K14 real server application IV").digest()[:12]
    initial_sequence = 0x00010203040506FE
    clean_record = symmetric.BASE.encrypted_record(
        server_key,
        server_iv,
        initial_sequence,
        symmetric.O.CONTENT_APPLICATION_DATA,
        response,
    )
    if len(clean_record) != 5 + len(plaintext) + 16:
        raise AssertionError("real-AEAD record geometry drifted")

    services = manifest["persistent_services"]
    assert isinstance(services, dict)
    emit_entry = int(services["emit"], 0)
    fail_entry = int(services["fail"], 0)
    service_start = int(str(services["runtime_start"]), 0)
    service_end = int(str(services["runtime_end"]), 0)
    entry_counts_by_case: dict[str, dict[int, int]] = {}

    def run_case(*, bad_tag: bool) -> dict[str, object]:
        machine = Machine(post_controller, entry=POST_CONTROLLER_ADDR)
        machine.uc.mem_write(symmetric.OVERLAY_BASE, sym_image)
        loaded_entries = tuple(
            word(machine.uc, 0x1820 + index * 2)
            for index in range(len(header.entries))
        )
        if loaded_entries != header.entries:
            raise AssertionError("post controller does not see the real K14 entry table")

        machine.fail_handler(fail_entry)
        derive_server_calls = 0
        flush_calls = 0
        ack_calls = 0
        receive_index = 0
        emitted: list[str] = []
        entry_counts = {5: 0, 6: 0, 7: 0}
        plaintext_at_finish: bytes | None = None
        sequence_at_finish: bytes | None = None

        # The focused gate seeds an already-derived server application epoch.
        # Only entry 17 is intercepted; entries 5/6/7 execute from sym_k14.bin.
        def derive_server_application(machine_uc: Uc) -> None:
            nonlocal derive_server_calls
            derive_server_calls += 1
            return_call(machine_uc)

        machine.call_handler(
            header.entries[17],
            derive_server_application,
        )

        def nic_receive(machine_uc: Uc) -> None:
            nonlocal flush_calls
            flush_calls += 1
            write_word(machine_uc, NE_RX_SAMPLE_COUNT, 0)
            return_call(machine_uc)

        nic_receive_stub = 0x0548
        machine.call_handler(nic_receive_stub, nic_receive)
        write_word(machine.uc, NIC_VT_RECEIVE, nic_receive_stub)

        def tcp_ack(machine_uc: Uc) -> None:
            nonlocal ack_calls
            ack_calls += 1
            return_call(machine_uc)

        machine.call_handler(0x13A6, tcp_ack)

        wire = bytearray(clean_record)
        if bad_tag:
            wire[-1] ^= 1
        fragment_sizes = (2, 71, 383, 19, 384, 7, 270, 9)
        frames: list[bytes] = []
        cursor = 0
        for count in fragment_sizes:
            end = min(len(wire), cursor + count)
            frames.append(bytes(wire[cursor:end]))
            cursor = end
        if cursor != len(wire) or any(not frame for frame in frames):
            raise AssertionError("real-AEAD fragmented record geometry drifted")

        def tcp_receive(machine_uc: Uc) -> None:
            nonlocal receive_index
            if receive_index >= len(frames):
                return_call(machine_uc, carry=True)
                return
            payload = frames[receive_index]
            receive_index += 1
            machine_uc.mem_write(RX_BUFFER, payload)
            write_word(machine_uc, TCP_RX_PTR, RX_BUFFER)
            write_word(machine_uc, TCP_RX_LEN, len(payload))
            return_call(machine_uc)

        machine.call_handler(0x14ED, tcp_receive)

        def emit(machine_uc: Uc) -> None:
            text = read_z(
                machine_uc,
                machine_uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
            )
            emitted.append(text)
            if "HEAD OK" in text:
                machine.done = True
                machine_uc.emu_stop()
                return
            return_call(machine_uc)

        machine.call_handler(emit_entry, emit)

        def observe_real_entries(
            machine_uc: Uc,
            address: int,
            _size: int,
            _user,
        ) -> None:
            nonlocal plaintext_at_finish, sequence_at_finish
            for entry_index in entry_counts:
                if address == header.entries[entry_index]:
                    entry_counts[entry_index] += 1
                    if entry_index == 7:
                        plaintext_at_finish = read_post_scatter(
                            machine_uc,
                            len(plaintext),
                        )
                        sequence_at_finish = bytes(
                            machine_uc.mem_read(
                                symmetric.SERVER_APP_SEQ,
                                8,
                            )
                        )

        machine.uc.hook_add(UC_HOOK_CODE, observe_real_entries)

        controller_before = bytes(
            machine.uc.mem_read(POST_CONTROLLER_ADDR, len(post_controller))
        )
        sym_code_before = bytes(
            machine.uc.mem_read(symmetric.OVERLAY_BASE, len(sym_image))
        )
        extension_prefix_guard = bytes(
            (index * 11 + 0x29) & 0xFF
            for index in range(K14_RUNTIME_START - K14_EXTENSION_START)
        )
        machine.uc.mem_write(K14_EXTENSION_START, extension_prefix_guard)
        service_guard = bytes(
            (index * 23 + 0x41) & 0xFF
            for index in range(service_end - service_start)
        )
        machine.uc.mem_write(service_start, service_guard)
        delta_guard = bytes(
            (index * 13 + 0x37) & 0xFF
            for index in range(TCP_TAIL_STATE_START - DELTA_LOADER_ADDR)
        )
        machine.uc.mem_write(DELTA_LOADER_ADDR, delta_guard)
        retained_guard = bytes(
            (index * 29 + 0x55) & 0xFF
            for index in range(
                symmetric.SERVER_APP_SEQ - symmetric.CLIENT_APP_KEY
            )
        )
        machine.uc.mem_write(symmetric.CLIENT_APP_KEY, retained_guard)
        machine.uc.mem_write(symmetric.SERVER_APP_KEY, server_key)
        machine.uc.mem_write(symmetric.SERVER_APP_IV, server_iv)
        retained_before = bytes(
            machine.uc.mem_read(
                symmetric.CLIENT_APP_KEY,
                symmetric.SERVER_APP_SEQ - symmetric.CLIENT_APP_KEY,
            )
        )
        machine.uc.mem_write(
            symmetric.SERVER_APP_SEQ,
            initial_sequence.to_bytes(8, "big"),
        )
        received_finished_guard = bytes(
            (index * 17 + 0x63) & 0xFF
            for index in range(
                symmetric.RECEIVED_SERVER_FINISHED,
                symmetric.RECEIVED_SERVER_FINISHED + 32,
            )
        )
        machine.uc.mem_write(
            symmetric.RECEIVED_SERVER_FINISHED,
            received_finished_guard,
        )
        ticket_guard = bytes(
            (index * 31 + 0x19) & 0xFF
            for index in range(header.high_end - symmetric.TICKET_IDENTITY)
        )
        machine.uc.mem_write(symmetric.TICKET_IDENTITY, ticket_guard)
        product_guard = bytes(
            (index * 19 + 0x71) & 0xFF
            for index in range(PRODUCT_POOL_END - PRODUCT_POOL_START)
        )
        machine.uc.mem_write(PRODUCT_POOL_START, product_guard)

        machine.sym_initialized = True
        machine.run(count=80_000_000)
        output = "".join(emitted)
        expected_sequence = (
            initial_sequence + (0 if bad_tag else 1)
        ).to_bytes(8, "big")

        if entry_counts[5] != 1 or entry_counts[7] != 1 or entry_counts[6] < 3:
            raise AssertionError(
                f"real K14 open-entry coverage drifted: {entry_counts!r}"
            )
        if plaintext_at_finish != plaintext:
            raise AssertionError(
                "real K14 open did not reconstruct exact scatter plaintext "
                "before tag verification"
            )
        if sequence_at_finish != initial_sequence.to_bytes(8, "big"):
            raise AssertionError("server sequence advanced before tag verification")
        if (
            bytes(machine.uc.mem_read(symmetric.SERVER_APP_SEQ, 8))
            != expected_sequence
        ):
            raise AssertionError(
                "real K14 open sequence did not advance exactly once on success only"
            )
        if (
            bytes(
                machine.uc.mem_read(
                    symmetric.CLIENT_APP_KEY,
                    len(retained_before),
                )
            )
            != retained_before
            or bytes(
                machine.uc.mem_read(
                    symmetric.RECEIVED_SERVER_FINISHED,
                    len(received_finished_guard),
                )
            )
            != received_finished_guard
            or bytes(
                machine.uc.mem_read(
                    symmetric.TICKET_IDENTITY,
                    len(ticket_guard),
                )
            )
            != ticket_guard
        ):
            raise AssertionError("real K14 open changed a retained TLS state boundary")
        if (
            bytes(machine.uc.mem_read(PRODUCT_POOL_START, len(product_guard)))
            != product_guard
            or bytes(machine.uc.mem_read(DELTA_LOADER_ADDR, len(delta_guard)))
            != delta_guard
            or bytes(machine.uc.mem_read(K14_EXTENSION_START, len(extension_prefix_guard)))
            != extension_prefix_guard
            or bytes(machine.uc.mem_read(service_start, len(service_guard)))
            != service_guard
            or bytes(machine.uc.mem_read(POST_CONTROLLER_ADDR, len(controller_before)))
            != controller_before
            or bytes(machine.uc.mem_read(symmetric.OVERLAY_BASE, len(sym_code_before)))
            != sym_code_before
        ):
            raise AssertionError("real K14 open crossed an executable/product sentinel")
        forbidden_writes = [
            (ip, address, size)
            for ip, address, size in machine.post_sym_writes
            if any(
                ranges_overlap((address, address + size), protected)
                for protected in (
                    (
                        symmetric.CLIENT_APP_KEY,
                        symmetric.SERVER_APP_SEQ,
                    ),
                    (
                        symmetric.RECEIVED_SERVER_FINISHED,
                        symmetric.RECEIVED_SERVER_FINISHED + 32,
                    ),
                    (symmetric.TICKET_IDENTITY, header.high_end),
                    (PRODUCT_POOL_START, PRODUCT_POOL_END),
                )
            )
        ]
        if forbidden_writes:
            raise AssertionError(
                f"real K14 open wrote a retained boundary: {forbidden_writes[:8]!r}"
            )
        if derive_server_calls != 1 or flush_calls != 1 or ack_calls < 1:
            raise AssertionError(
                "real K14 post-controller setup/fragment progression drifted"
            )

        if bad_tag:
            if not machine.failed or machine.done or output:
                raise AssertionError(
                    "real K14 bad tag escaped into an HTTP milestone"
                )
            if (
                word(machine.uc, POST_HTTP_TOTAL) != 0
                or machine.uc.mem_read(POST_HTTP_MATCH, 1) != b"\x00"
                or machine.uc.mem_read(POST_HTTP_DONE, 1) != b"\x00"
                or machine.uc.mem_read(POST_HEAD_COMPLETE, 1) != b"\x00"
            ):
                raise AssertionError(
                    "real K14 bad tag mutated HTTP tentative/commit state"
                )
        else:
            if machine.failed or not machine.done or "HEAD OK" not in output:
                raise AssertionError(
                    f"real K14 valid record missed HTTP milestone: {output!r}"
                )
            if (
                word(machine.uc, POST_HTTP_TOTAL) != len(response)
                or machine.uc.mem_read(POST_HTTP_DONE, 1) != b"\x01"
                or machine.uc.mem_read(POST_HEAD_COMPLETE, 1) != b"\x01"
            ):
                raise AssertionError("real K14 authenticated HTTP state drifted")

        entry_counts_by_case["bad" if bad_tag else "good"] = entry_counts
        return {
            "result": "rejected" if bad_tag else "accepted",
            "server_sequence_before": f"0x{initial_sequence:016x}",
            "server_sequence_after": (
                "0x"
                + bytes(
                    machine.uc.mem_read(symmetric.SERVER_APP_SEQ, 8)
                ).hex()
            ),
            "http_state_changes": (
                word(machine.uc, POST_HTTP_TOTAL)
                + int.from_bytes(
                    machine.uc.mem_read(POST_HEAD_COMPLETE, 1),
                    "little",
                )
            ),
            "http_milestone": "HEAD OK" in output,
        }

    good = run_case(bad_tag=False)
    bad = run_case(bad_tag=True)
    return {
        "kind": "real_k14_chacha20_poly1305_post_controller_gate",
        "symmetric_image_sha256": hashlib.sha256(sym_image).hexdigest(),
        "symmetric_entry_addresses": {
            "server_app_open_begin": f"0x{header.entries[5]:04x}",
            "open_chunk": f"0x{header.entries[6]:04x}",
            "open_finish": f"0x{header.entries[7]:04x}",
        },
        "entry_calls": {
            label: {str(index): count for index, count in counts.items()}
            for label, counts in entry_counts_by_case.items()
        },
        "record_bytes": len(clean_record),
        "tls_inner_plaintext_bytes": len(plaintext),
        "http_content_bytes": len(response),
        "scatter_seams_crossed": [POST_QUARANTINE_END - POST_QUARANTINE, 1080],
        "scatter_plaintext_exact_at_open_finish": True,
        "retained_client_server_state": "0x3838..0x38e8 preserved",
        "ticket_state_start": "0x3b40 preserved",
        "good_tag": good,
        "bad_tag": bad,
        "server_sequence_success_increment": 1,
        "server_sequence_bad_tag_increment": 0,
        "product_arena_context_writes": 0,
        "status": "pass",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument(
        "--identity",
        action="store_true",
        help=(
            "gate the opt-in attempt-6 CertificateVerify capture and compact "
            "post-socket authentication handoff"
        ),
    )
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    selected_build = args.build_dir or (
        DEFAULT_IDENTITY_BUILD if args.identity else DEFAULT_BUILD
    )
    build = (
        selected_build
        if selected_build.is_absolute()
        else ROOT / selected_build
    )
    required = {
        "manifest": build / "manifest.json",
        "pre_sym": build / "live_pre_sym_transition.bin",
        "persistent": build / "live_persistent_services.bin",
        "hello": build / "live_hello_controller.bin",
        "crypto": build / "live_crypto_controller.bin",
        "protected": build / "live_protected_controller.bin",
        "post": build / "live_post_controller.bin",
        "sym": build / "sym_k14.bin",
        "delta": build / "live_delta_loader.bin",
    }
    if args.identity:
        required.update(
            {
                "sym_listing": build / "sym_k14.lst",
                "post_listing": build / "live_post_controller.lst",
                "auth_controller": build / "live_auth_controller.bin",
                "auth_listing": build / "live_auth_controller.lst",
                "auth": build / "auth_p256_live.bin",
            }
        )
    missing = [str(path) for path in required.values() if not path.is_file()]
    if missing:
        raise SystemExit(
            "missing live logical-K14 build artifact(s):\n  "
            + "\n  ".join(missing)
            + "\nRun build_live_k15.py first."
    )
    manifest = json.loads(required["manifest"].read_text(encoding="utf-8"))
    phase_names = {
        phase.get("name")
        for phase in manifest.get("live_phases", [])
        if isinstance(phase, dict)
    }
    if args.identity:
        identity_manifest = validate_identity_manifest(manifest)
        identity_manifest_negatives = identity_manifest_negative_controls(
            manifest
        )
        artifact_bindings = {}
        for artifact_name, phase_name in (
            ("protected", "protected_controller"),
            ("post", "post_controller"),
            ("sym", "sym"),
            ("auth_controller", "auth_controller"),
            ("auth", "auth"),
        ):
            data = required[artifact_name].read_bytes()
            phase = parse_phase(manifest, phase_name)
            digest = hashlib.sha256(data).hexdigest()
            if int(phase["bytes"]) != len(data) or phase["sha256"] != digest:
                raise AssertionError(
                    f"identity artifact differs from manifest: {phase_name}"
                )
            artifact_bindings[phase_name] = {
                "bytes": len(data),
                "sha256": digest,
                "destination": phase["destination"],
                "sectors": phase["sectors"],
            }
        attempt6 = attempt6_identity_fixture()
        protected_identity = test_identity_protected_capture(
            required["protected"].read_bytes(),
            required["sym_listing"],
            manifest,
            attempt6,
        )
        auth_transition = test_identity_auth_transition(
            required["post"].read_bytes(),
            required["post_listing"],
            required["crypto"].read_bytes(),
            required["persistent"].read_bytes(),
            required["auth_controller"].read_bytes(),
            required["auth_listing"],
            required["auth"].read_bytes(),
            manifest,
        )
        result = {
            "scope": (
                "offline Unicorn logical-K14 identity-controller gate using "
                "the authenticated attempt-6 protected-flight shape; no "
                "86Box and no network I/O"
            ),
            "status": "pass",
            "identity_manifest": identity_manifest,
            "identity_manifest_negative_controls": (
                identity_manifest_negatives
            ),
            "artifact_bindings": artifact_bindings,
            "attempt6_oracle": {
                "pcap": str(ATTEMPT6_PCAP.relative_to(ROOT)),
                "pcap_sha256": attempt6["pcap_sha256"],
                "protected_record_sha256": attempt6[
                    "protected_record_sha256"
                ],
                "message_lengths": attempt6["message_lengths"],
                "host_signature_verified": attempt6[
                    "host_signature_verified"
                ],
            },
            "protected_identity_capture": protected_identity,
            "auth_transition": auth_transition,
        }
        output = args.json_out or build / "identity_controller_check.json"
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("live TLS 1.3 logical-K14 identity controller gate: PASS")
        print(
            "  attempt-6 protected plaintext=1925B; "
            "117B authenticated tail quarantine PASS"
        )
        print(
            "  compact CertificateVerify digest/signature exact; "
            "bad tag/scheme/length fail closed PASS"
        )
        print(
            "  AEAD -> transcript snapshot -> Finished/HEAD -> "
            "post-controller transition ordering PASS"
        )
        print(
            "  auth controller=0x3200; auth executable ends=0x31c0; "
            "executed legacy 0x3400 caller-overwrite negative PASS"
        )
        print(f"  result={output}")
        return
    if {"auth_controller", "auth"} & phase_names:
        raise AssertionError(
            "identity manifest requires the live_k15_check.py --identity gate"
        )
    validate_lifetime_manifest(manifest)
    lifetime_negatives = lifetime_negative_controls(manifest)
    persistent_services = required["persistent"].read_bytes()
    service_result = diagnostic_service_island_gate(
        persistent_services,
        manifest,
    )
    pre_sym_transition = required["pre_sym"].read_bytes()
    low_result = run_low_next_transition(pre_sym_transition, manifest)
    low_negative = run_low_next_transition(
        pre_sym_transition,
        manifest,
        inject_legacy_rx_stage=True,
    )
    hello_controller = required["hello"].read_bytes()
    hello_result = test_hello(hello_controller, manifest)
    hello_oversized = test_hello_oversized_stage_rejected(
        hello_controller,
        manifest,
    )
    crypto_result = run_crypto_transition(
        required["crypto"].read_bytes(),
        required["protected"].read_bytes(),
        required["delta"].read_bytes(),
        manifest,
    )
    sentinel_negative = run_crypto_transition(
        required["crypto"].read_bytes(),
        required["protected"].read_bytes(),
        required["delta"].read_bytes(),
        manifest,
        inject_legacy_extension_reload=True,
    )
    protected_result = test_protected(required["protected"].read_bytes(), manifest)
    protected_real_k14_aead = test_protected_real_k14_aead(
        required["protected"].read_bytes(),
        required["sym"].read_bytes(),
        manifest,
    )
    protected_without_ccs = test_protected(
        required["protected"].read_bytes(),
        manifest,
        compatibility_ccs_count=0,
    )
    protected_head_send_failure = test_protected(
        required["protected"].read_bytes(),
        manifest,
        fail_head_send=True,
    )
    trailing_record = b"\x17\x03\x03\x00\x01\x00"
    duplicate_ccs_negative = test_protected(
        required["protected"].read_bytes(),
        manifest,
        compatibility_ccs_count=2,
        expected_shape_failure="duplicate-compatibility-ccs",
    )
    coalesced_tail_negative = test_protected(
        required["protected"].read_bytes(),
        manifest,
        coalesced_tail=trailing_record,
        expected_shape_failure="coalesced-trailing-record",
    )
    later_frame_tail_negative = test_protected(
        required["protected"].read_bytes(),
        manifest,
        later_frame_tail=trailing_record,
        expected_shape_failure="later-frame-trailing-record",
    )
    post_result = test_post_finished(
        required["post"].read_bytes(),
        manifest,
    )
    real_k14_aead = test_post_finished_real_k14_aead(
        required["post"].read_bytes(),
        required["sym"].read_bytes(),
        manifest,
    )
    post_reverse_order = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        record_order="http-ticket",
    )
    post_split_http = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        record_order="http-ticket",
        split_http=True,
    )
    post_bad_tag = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        record_order="http-ticket",
        reject_tag_index=1,
    )
    post_oversized = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        oversized_record=True,
    )
    post_http_wrong_type = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        wrong_inner_type="http-as-handshake",
    )
    post_ticket_wrong_type = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        wrong_inner_type="ticket-as-application",
    )
    post_padding = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        padded_record=True,
    )
    post_coalesced_trailing = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        coalesced_trailing=True,
    )
    post_trailing_header_prefixes = {
        str(length): test_post_finished(
            required["post"].read_bytes(),
            manifest,
            trailing_header_bytes=length,
        )
        for length in range(1, 6)
    }
    post_scatter_seams = {
        str(length): test_post_finished(
            required["post"].read_bytes(),
            manifest,
            http_plaintext_bytes=length,
        )
        for length in (511, 512, 513, 1079, 1080, 1081, 1623, 1624)
    }
    post_fifth_ticket_coalesced = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        ticket_limit_layout=(5,),
    )
    post_fifth_ticket_split = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        ticket_limit_layout=(4, 1),
    )
    post_nst_extension_negatives = {
        label: test_post_finished(
            required["post"].read_bytes(),
            manifest,
            nst_extension_negative=label,
        )
        for label in NST_EXTENSION_NEGATIVES
    }
    post_key_update = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        authenticated_key_update=True,
    )
    post_close_notify = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        authenticated_alert=b"\x01\x00",
    )
    post_other_alert = test_post_finished(
        required["post"].read_bytes(),
        manifest,
        authenticated_alert=b"\x02\x28",
    )
    result = {
        "scope": (
            "offline Unicorn logical-K14 live-controller glue gate; "
            "no 86Box and no network I/O"
        ),
        "status": "pass",
        "lifetime_manifest": {
            "status": "pass",
            "negative_controls_rejected": lifetime_negatives,
        },
        "persistent_service_island": service_result,
        "hello_to_crypto_transition": low_result,
        "legacy_rx_stage_sentinel_negative": low_negative,
        "hello": hello_result,
        "hello_oversized_stage_negative": hello_oversized,
        "candidate_to_protected_transition": crypto_result,
        "extension_reload_sentinel_negative": sentinel_negative,
        "protected_flight_and_finished": protected_result,
        "protected_flight_real_k14_aead_quarantine": protected_real_k14_aead,
        "protected_flight_without_compatibility_ccs": protected_without_ccs,
        "head_send_failure_negative": protected_head_send_failure,
        "duplicate_compatibility_ccs_negative": duplicate_ccs_negative,
        "coalesced_trailing_record_negative": coalesced_tail_negative,
        "later_frame_trailing_record_negative": later_frame_tail_negative,
        "post_finished_head_ticket_canary": post_result,
        "post_finished_real_k14_aead": real_k14_aead,
        "post_finished_reverse_order": post_reverse_order,
        "post_finished_multirecord_http": post_split_http,
        "post_finished_bad_tag_negative": post_bad_tag,
        "post_finished_oversized_record_negative": post_oversized,
        "post_finished_http_wrong_inner_type_negative": post_http_wrong_type,
        "post_finished_ticket_wrong_inner_type_negative": post_ticket_wrong_type,
        "post_finished_padding_negative": post_padding,
        "post_finished_coalesced_trailing_negative": post_coalesced_trailing,
        "post_finished_trailing_header_prefix_negatives": (
            post_trailing_header_prefixes
        ),
        "post_finished_scatter_seam_lengths": post_scatter_seams,
        "post_finished_fifth_ticket_coalesced_negative": (
            post_fifth_ticket_coalesced
        ),
        "post_finished_fifth_ticket_split_negative": post_fifth_ticket_split,
        "post_finished_nst_extension_negatives": post_nst_extension_negatives,
        "post_finished_key_update_negative": post_key_update,
        "post_finished_close_notify_negative": post_close_notify,
        "post_finished_other_alert_negative": post_other_alert,
    }
    output = args.json_out or build / "controller_check.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("live TLS 1.3 logical-K14 controller gate: PASS")
    print(
        "  HELLO fragmented receive/ACK rewind/zero-window="
        f"{hello_result['fragmented_server_hello_bytes']}B PASS"
    )
    print("  HELLO overlapping TX source 257B > 256B rejected PASS")
    print(
        "  protected flight/Finished="
        f"{protected_result['fragmented_wire_bytes']}B -> "
        f"{protected_result['finished_transmit_bytes']}B x"
        f"{protected_result['finished_transmit_attempts']} + "
        f"{protected_result['head_transmit_bytes']}B HEAD; "
        "client-app derive/HEAD/zero-window/cold-load PASS"
    )
    print(
        "  protected real K14 AEAD quarantine="
        "bad tag + tampered tail reach open_finish before fail; "
        "zero verify/retained-state writes PASS"
    )
    print("  HEAD-send failure fails before window/load transition PASS")
    print(
        "  strict protected shape=optional 0/1 CCS accepted; duplicate CCS, "
        "coalesced tail, and later-frame tail rejected PASS"
    )
    print(
        "  post-Finished authenticated scatter="
        f"{post_result['http_content_bytes']}B HTTP, "
        f"{post_result['coalesced_ticket_messages']} coalesced NSTs; "
        "both orders/multi-record/bad-tag/cap/type/padding/boundary PASS"
    )
    print(
        "  real K14 ChaCha20-Poly1305 open="
        f"{real_k14_aead['tls_inner_plaintext_bytes']}B plaintext/"
        f"{real_k14_aead['record_bytes']}B record; "
        "exact two-seam scatter, good +1/bad +0 server sequence PASS"
    )
    print(
        "  scatter seam lengths=511/512/513, 1079/1080/1081, "
        "1623/1624B PASS"
    )
    print(
        "  clean-boundary pending header=1/2/3/4/5B rejected; "
        "fifth NST coalesced and 4+1 split rejected PASS"
    )
    print(
        "  exact live NST early_data+zero-length-unknown accepted; "
        "duplicate early_data/bad length/truncation/type/extra bytes rejected PASS"
    )
    print("  authenticated unsupported KeyUpdate=fail closed PASS")
    print("  authenticated alert level/type classification=fail closed PASS")
    print(
        "  critical track-batched loader=0x0f00..0x0f91; "
        "candidate/sym/protected loads PASS"
    )
    print("  HELLO->crypto direct load=0x3400; raw c preserved PASS")
    print(
        "  persistent service island="
        f"{service_result['runtime_range']}; product arena/context writes=0 PASS"
    )
    print(
        "  lifetime/sentinel negative controls="
        f"{len(lifetime_negatives) + 2} rejected PASS"
    )
    print("  VM/network launch=NOT PERFORMED")
    print(f"  result={output}")


if __name__ == "__main__":
    main()
