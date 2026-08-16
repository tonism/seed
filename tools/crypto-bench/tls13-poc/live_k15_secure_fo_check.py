#!/usr/bin/env python3
"""Offline gate for the live logical-K14 secure FO integration.

This checker binds the secure artifact to its phase ledger and unchanged
ML-KEM FO kernel, then executes the card-vault controller edges under Unicorn.
It performs no network I/O and never starts 86Box.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BP,
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

import check_keygen_overlay as KEYGEN_CHECK


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEFAULT_BUILD = ROOT / "build/crypto-bench/tls13-live-secure"
SECTOR = 512
CORE_START_LBA = 11
RAM_BYTES = 0x10000

BOOT_CONTROLLER = 0x3400
PRECONNECT_CONTROLLER = 0x2400
GENERIC_TRANSITION_INSTALLER = 0x0E80
PRE_SYM_TRANSITION = 0x0F00
PROTECTED_CONTROLLER = 0x0900
SYM_OVERLAY = 0x1800
FO_CONTROLLER = 0x2400
FO_KERNEL = 0x1800
RES_LOAD_PHASE = 0x10C4
RES_PREPARE_INTERNET = 0x11F6
NE_BUF_LOAD = 0x1724
NE_BUF_READ = 0x175B
NE_TX_START = 0x06CB
NE_RX_SAMPLE_COUNT = 0x06D5
NIC_FAMILY = 0x0610
NE_RX_STOP = 0x06CD
RES_TCP_ACK = 0x13A6
RES_NIC_VT_RECEIVE = 0x15E1

CARD_CONTROLLER = 0x7300
CARD_EK = 0x7400
CARD_EK_LEN = 1184
CARD_C = 0x7900
CARD_C_LEN = 1088
CARD_HANDOFF_A = 0x7E00
CARD_HANDOFF_B = 0x7F00
CARD_PAGE_LEN = 256
CARD_RESERVED_PAGES = tuple(
    range(CARD_CONTROLLER, CARD_HANDOFF_B + CARD_PAGE_LEN, CARD_PAGE_LEN)
)
CARD_WARM_CLEAR_PAGES = CARD_RESERVED_PAGES[1:]

TICKET_HOLD = (0x0700, 0x080E)
EXPECTED_K = (0x080E, 0x082E)
FO_KERNEL_HOLD_END = 0x0830
LOW_HANDOFFS = (0x0D00, 0x0E00)
HIGH_CIPHERTEXT = (0x3600, 0x3A40)
HIGH_MESSAGE = (0x3A40, 0x3A60)
HIGH_G_Z = (0x3B9C, 0x3BFC)
TICKET_PSK = (0x38B0, 0x38D0)
TICKET_IDENTITY_TAIL = (0x3B40, 0x3C2E)
IDENTITY_TAIL = 0x0E00
IDENTITY_CV_END = IDENTITY_TAIL + 80
IDENTITY_CV_PTR = 0x0EC0
IDENTITY_CV_DER_LEN = 0x0EC2
AUTH_INPUT_SIGNATURE_LEN = 0x3C50
AUTH_INPUT_SIGNATURE = 0x3C52
SYM_RECEIVED_FINISH = 0x38F0

SUCCESS_MARKERS = [
    "FO BEGIN",
    "KEM VALID",
    "AUTH BEGIN",
    "IDENTITY PASS",
    "PASS",
    "RESULT",
]

EXPECTED_PHASES = [
    ("boot_controller", 45, 1, 0x3400),
    ("hello_controller", 46, 1, 0x3400),
    ("crypto_controller", 47, 1, 0x3400),
    ("secure_sym_controller", 48, 1, 0x3400),
    ("secure_preconnect_controller", 49, 1, PRECONNECT_CONTROLLER),
    ("protected_controller", 50, 3, 0x0900),
    ("post_controller", 53, 2, 0x0900),
    ("fo_controller", 55, 1, 0x2400),
    ("scrub_controller", 56, 1, 0x2400),
    ("entropy_controller", 57, 1, 0x0900),
    ("keygen", 58, 6, 0x1800),
    ("hello", 64, 8, 0x1800),
    ("candidate_track_pad", 72, 5, 0x0000),
    ("candidate", 77, 5, 0x1800),
    ("sym_track_pad", 82, 3, 0x0000),
    ("sym", 85, 12, 0x1800),
    ("fo_track_pad", 97, 4, 0x0000),
    ("fo", 101, 6, 0x1800),
    ("auth_controller", 107, 1, 0x3200),
    ("auth_track_pad", 108, 1, 0x0000),
    ("auth", 109, 13, 0x1800),
]

PHASE_ARTIFACTS = {
    "boot_controller": "live_boot_controller.bin",
    "hello_controller": "live_hello_controller.bin",
    "crypto_controller": "live_crypto_controller.bin",
    "secure_sym_controller": "live_secure_sym_controller.bin",
    "secure_preconnect_controller": "live_secure_preconnect_controller.bin",
    "protected_controller": "live_protected_controller.bin",
    "post_controller": "live_post_controller.bin",
    "fo_controller": "live_fo_controller.bin",
    "scrub_controller": "live_scrub_controller.bin",
    "entropy_controller": "floppy_entropy_controller.bin",
    "keygen": "keygen_k14.bin",
    "hello": "hello_cached_k14.bin",
    "candidate": "candidate_k14.bin",
    "sym": "sym_k14.bin",
    "fo": "fo_tail_live.bin",
    "auth_controller": "live_auth_controller.bin",
    "auth": "auth_p256_live.bin",
}

FORBIDDEN_LITERALS = (
    b"authorization",
    b"bearer ",
    b"content-type:",
    b"openai-beta",
    b"x-api-key",
    b"api-key",
    b"post ",
    b"get /",
    b"/v1/",
    b'"input"',
    b'"model"',
    b"sk-",
)
HEAD = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"\r\n"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def word(machine: Uc, address: int) -> int:
    return struct.unpack("<H", machine.mem_read(address, 2))[0]


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
    data = bytearray()
    for offset in range(limit):
        value = machine.mem_read(address + offset, 1)[0]
        if value == 0:
            return data.decode("ascii")
        data.append(value)
    raise AssertionError(f"unterminated string at {address:#x}")


def label_address(listing: Path, label: str, origin: int) -> int:
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
    raise AssertionError(f"cannot resolve {label!r} in {listing}")


def phase_map(manifest: dict[str, object]) -> dict[str, dict[str, object]]:
    phases = manifest.get("live_phases")
    if not isinstance(phases, list):
        raise AssertionError("secure manifest lacks phase ledger")
    result: dict[str, dict[str, object]] = {}
    for phase in phases:
        if not isinstance(phase, dict) or not isinstance(phase.get("name"), str):
            raise AssertionError("secure phase ledger contains malformed entry")
        name = str(phase["name"])
        if name in result:
            raise AssertionError(f"duplicate secure phase {name}")
        result[name] = phase
    return result


def validate_artifact(
    build: Path,
    manifest: dict[str, object],
) -> dict[str, object]:
    core_path = build / "SEED.SYS"
    image_path = build / "floppy-160k-live-k15.img"
    if not core_path.is_file() or not image_path.is_file():
        raise AssertionError("secure core/image artifact is missing")
    core = core_path.read_bytes()
    image = image_path.read_bytes()
    output = manifest.get("output")
    if not isinstance(output, dict):
        raise AssertionError("secure manifest lacks output hashes")
    if (
        len(core) != 122 * SECTOR
        or len(core) != int(output.get("core_bytes", -1))
        or sha256(core) != output.get("core_sha256")
        or len(image) != int(output.get("image_bytes", -1))
        or sha256(image) != output.get("image_sha256")
        or word_bytes(core, 0x11) != 122
    ):
        raise AssertionError("secure core/image hash or sector ledger drifted")
    if image.find(core) != CORE_START_LBA * SECTOR or image.count(core) != 1:
        raise AssertionError("secure SEED.SYS is not the exact first FAT data file")

    phases = phase_map(manifest)
    if list(phases) != [item[0] for item in EXPECTED_PHASES]:
        raise AssertionError("secure phase order drifted")
    artifact_bindings: dict[str, object] = {}
    cursor = 45
    for name, start, sectors, destination in EXPECTED_PHASES:
        phase = phases[name]
        if (
            start != cursor
            or int(phase["start_sector"]) != start
            or int(phase["sectors"]) != sectors
            or int(str(phase["destination"]), 0) != destination
            or int(str(phase["key"]), 0) != ((sectors << 8) | start)
        ):
            raise AssertionError(f"secure phase geometry drifted: {name}")
        cursor += sectors
        raw = core[start * SECTOR : (start + sectors) * SECTOR]
        byte_count = int(phase["bytes"])
        if not 0 <= byte_count <= len(raw):
            raise AssertionError(f"secure phase byte count escaped slot: {name}")
        if sha256(raw[:byte_count]) != phase["sha256"]:
            raise AssertionError(f"secure phase/core hash drifted: {name}")
        if any(raw[byte_count:]):
            raise AssertionError(f"secure phase padding is not zero: {name}")
        artifact_name = PHASE_ARTIFACTS.get(name)
        if artifact_name is not None:
            artifact = (build / artifact_name).read_bytes()
            if artifact != raw[:byte_count]:
                raise AssertionError(f"secure phase artifact differs: {name}")
            artifact_bindings[name] = {
                "bytes": len(artifact),
                "sha256": sha256(artifact),
            }
    if cursor != 122:
        raise AssertionError("secure phase ledger does not end at core sector 122")

    patches = manifest.get("patches")
    product_info = manifest.get("product_input")
    if not isinstance(patches, dict) or not isinstance(product_info, dict):
        raise AssertionError("secure patch/product ledger is missing")
    product_path = Path(str(product_info["path"]))
    product = product_path.read_bytes()
    pre_network_patch = patches.get("pre_dhcp_detour")
    network_preimage = bytes.fromhex("e88a017242")
    network_postimage = bytes.fromhex("e994239090")
    if (
        pre_network_patch
        != (
            "file 0x0069..0x006d -> 0x3400 controller, after local "
            "packet-I/O init and before first network transmission"
        )
        or product[0x0069:0x006E] != network_preimage
        or core[0x0069:0x006E] != network_postimage
    ):
        raise AssertionError("secure pre-network entropy detour drifted")

    patch = patches.get("secure_ne2000_pstop")
    if not isinstance(patch, dict):
        raise AssertionError("secure PSTOP patch ledger is missing")
    preimage = bytes.fromhex("c606cd0680")
    postimage = bytes.fromhex("c606cd0673")
    if (
        sha256(product) != product_info["sha256"]
        or product[0x4081 : 0x4086] != preimage
        or core[0x4081 : 0x4086] != postimage
        or patch.get("instruction_preimage") != preimage.hex()
        or patch.get("instruction_postimage") != postimage.hex()
        or patch.get("immediate_offset") != "0x4085"
        or patch.get("live_artifact_only") is not True
        or patch.get("product_source_edited") is not False
    ):
        raise AssertionError("secure artifact-only NE2000 PSTOP patch drifted")

    checkpoint = manifest.get("secure_fo_checkpoint")
    if not isinstance(checkpoint, dict) or checkpoint.get("enabled") is not True:
        raise AssertionError("secure FO checkpoint is not enabled")
    driver = checkpoint.get("packaged_driver")
    if not isinstance(driver, dict):
        raise AssertionError("secure driver probe ledger is missing")
    packaged_driver = Path(str(driver["path"])).read_bytes()
    probe = (build / "secure_ne_driver_probe.bin").read_bytes()
    if (
        packaged_driver != probe
        or len(probe) != SECTOR
        or sha256(probe)
        != "0288088de727dc62879f480a87dac9fcff78be567d7484d6534937be6b629baa"
        or driver.get("byte_identical") is not True
        or driver.get("remote_dma_write") != f"0x{NE_BUF_LOAD:04x}"
        or driver.get("remote_dma_read") != f"0x{NE_BUF_READ:04x}"
    ):
        raise AssertionError("secure packaged NE.DRV probe drifted")

    if core.count(HEAD) != 1:
        raise AssertionError("secure credential-free HEAD literal count drifted")
    lowered = core.replace(HEAD, bytes(len(HEAD)), 1).lower()
    hits = [
        token.decode("ascii", errors="replace")
        for token in FORBIDDEN_LITERALS
        if token in lowered
    ]
    if hits:
        raise AssertionError(
            f"secure credential/request literal gate drifted: hits={hits!r}"
        )
    literal_gate = manifest.get("literal_gate")
    if (
        not isinstance(literal_gate, dict)
        or literal_gate.get("forbidden_hits") != 0
        or literal_gate.get("exact_allowed_head_occurrences") != 1
        or literal_gate.get("credential_files_packaged") is not False
    ):
        raise AssertionError("secure literal manifest drifted")

    return {
        "core_bytes": len(core),
        "core_sectors": len(core) // SECTOR,
        "core_sha256": sha256(core),
        "image_sha256": sha256(image),
        "phase_artifacts": artifact_bindings,
        "pre_network_entropy_detour": (
            "exact product preimage; after packet I/O and before DHCP"
        ),
        "pstop_patch": "exact product preimage/live postimage",
        "driver_probe": "byte-identical",
        "credential_literal_gate": "pass",
    }


def word_bytes(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def run_fo_oracle(build: Path) -> dict[str, object]:
    env = os.environ.copy()
    env["TLS13_POC_K14"] = "1"
    completed = subprocess.run(
        [sys.executable, str(HERE / "fo_tail_check.py")],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    result = json.loads(completed.stdout)
    correctness = result.get("correctness")
    if (
        not isinstance(correctness, dict)
        or any(value != "pass" for value in correctness.values())
        or correctness.get("product_address_sentinels") != "pass"
    ):
        raise AssertionError("K14 FO oracle did not pass every correctness gate")
    fo = (build / "fo_tail_live.bin").read_bytes()
    expected_image_hash = result["hashes_sha256"]["image_origin_1800"]
    if sha256(fo) != expected_image_hash:
        raise AssertionError("live FO image differs from K14 oracle image")
    fixed = result.get("fixed_addresses")
    if (
        not isinstance(fixed, dict)
        or fixed.get("saved_ciphertext_mirror_preserved") != "0x3600..0x3a40"
        or not (
            HIGH_CIPHERTEXT[0] <= TICKET_PSK[0]
            and TICKET_PSK[1] <= HIGH_CIPHERTEXT[1]
        )
    ):
        raise AssertionError("ticket PSK sentinel is not inside FO-preserved state")
    return {
        "source_sha256": result["hashes_sha256"]["kernel_source"],
        "image_sha256": expected_image_hash,
        "correctness": correctness,
        "ticket_psk_sentinel": "0x38b0..0x38d0 preserved inside 0x3600..0x3a40",
        "stream_abi": result["stream_abi"],
    }


def run_entropy_oracle(
    build: Path,
    manifest: dict[str, object],
) -> dict[str, object]:
    """Bind the live entropy phase to the standalone hostile oracle."""

    with tempfile.TemporaryDirectory(prefix="seed-live-floppy-check-") as raw:
        result_path = Path(raw) / "result.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(HERE / "floppy_entropy_check.py"),
                "--results",
                str(result_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        result = json.loads(result_path.read_text(encoding="utf-8"))
    controller = (build / "floppy_entropy_controller.bin").read_bytes()
    keygen = (build / "keygen_k14.bin").read_bytes()
    gates = result.get("gates")
    checker_source = result.get("source_model")
    checker_health = result.get("health_model")
    ceremony = manifest.get("entropy_ceremony")
    phases = phase_map(manifest)
    required_gates = {
        "host_sha3_oracle",
        "same_input_replay",
        "timing_diversity",
        "read_failure_fail_closed",
        "repetition_count_fail_closed",
        "insufficient_changes_fail_closed",
        "explicit_abort_zeroizes",
        "exact_keccak_mutable_bounds",
        "keccak_outside_guards_preserved",
        "real_keygen_after_entropy_fips_oracle",
        "chs_schedule",
        "bios_drive_forwarding",
        "disk_writes",
        "bios_services",
    }
    if (
        result.get("schema") != "seed-tls13-floppy-entropy-v1"
        or result.get("controller_bytes") != SECTOR
        or result.get("controller_sha256") != sha256(controller)
        or result.get("keygen_sha256") != sha256(keygen)
        or result.get("samples") != 256
        or result.get("one_shot_attempt_bundles") != 2
        or not isinstance(gates, dict)
        or not required_gates.issubset(gates)
        or any(
            value != "PASS"
            for name, value in gates.items()
            if name not in {"disk_writes", "bios_services", "chs_schedule"}
        )
        or gates.get("chs_schedule") != "alternating 0/0/1 and 39/0/8"
        or gates.get("disk_writes") != 0
        or gates.get("bios_services")
        != ["int 13h AH=02h one-sector reads only"]
        or not isinstance(checker_source, dict)
        or checker_source.get("source")
        != "physical floppy read/seek/rotation completion timing measured by PIT"
        or checker_source.get("emulator_security_credit_bits") != 0
        or checker_source.get("physical_security_credit_bits")
        != "pending real-hardware characterization"
        or not isinstance(checker_source.get("qualification"), str)
        or not checker_source["qualification"]
        or not isinstance(checker_health, dict)
        or checker_health.get("status")
        != "provisional stuck-source screening only"
        or checker_health.get("max_identical_symbol_run") != 64
        or checker_health.get("minimum_symbol_changes") != 8
        or checker_health.get("calibration")
        != "pending representative physical hardware"
    ):
        raise AssertionError(
            "live entropy image differs from the standalone hostile oracle"
        )
    if (
        not isinstance(ceremony, dict)
        or ceremony.get("enabled") is not True
        or ceremony.get("public_fixture_phase_present") is not False
        or ceremony.get("disk_writes") != 0
        or ceremony.get("read_only_floppy_compatible") is not True
        or "public_fixture" in phases
    ):
        raise AssertionError("secure entropy/public-fixture policy drifted")
    source = ceremony.get("source_model")
    output = ceremony.get("output")
    mode = ceremony.get("operational_mode")
    controller_meta = ceremony.get("controller")
    primitive = ceremony.get("primitive")
    if (
        not isinstance(source, dict)
        or source.get("source")
        != (
            "completion timing of 256 alternating read-only BIOS floppy "
            "reads between cylinders 0 and 39"
        )
        or source.get("samples") != 256
        or source.get("measurement_clock")
        != "PIT channel 0 latched before and after"
        or source.get("credited_entropy_bits") != 0
        or source.get("credit_status")
        != (
            "pending representative physical-drive min-entropy "
            "characterization; emulator timing receives zero credit"
        )
        or source.get("health_checks")
        != [
            "all 256 BIOS reads must succeed",
            "maximum identical folded-interval run length 64",
            "at least eight folded-interval symbol changes",
        ]
        or source.get("health_check_status")
        != (
            "provisional stuck-source mechanics gate, not an entropy "
            "estimate or NIST SP 800-90B validation"
        )
        or not isinstance(output, dict)
        or output.get("bytes") != 256
        or not isinstance(output.get("initial_attempt"), dict)
        or output["initial_attempt"].get("range") != "0x0700..0x0780"
        or not isinstance(output.get("resumption_attempt"), dict)
        or output["resumption_attempt"].get("range") != "0x0780..0x0800"
        or output["resumption_attempt"].get("domain_separated") is not True
        or output["resumption_attempt"].get("one_shot") is not True
        or not isinstance(mode, dict)
        or mode.get("manual_operator_entry_required") is not False
        or mode.get("unattended_collection") is not True
        or mode.get("collection_before_first_network_transmission") is not True
        or mode.get("automated_security_credit_bits") != 0
        or mode.get("physical_security_credit_pending") is not True
        or not isinstance(controller_meta, dict)
        or controller_meta.get("bytes") != len(controller)
        or controller_meta.get("sha256") != sha256(controller)
        or not isinstance(primitive, dict)
        or primitive.get("sha256") != sha256(keygen)
    ):
        raise AssertionError("secure entropy ceremony manifest drifted")
    return {
        "controller_bytes": len(controller),
        "controller_sha256": sha256(controller),
        "keygen_sha256": sha256(keygen),
        "samples": 256,
        "source": checker_source["source"],
        "emulator_security_credit_bits": 0,
        "physical_security_credit": "pending real-hardware characterization",
        "health_model": checker_health,
        "attempt_bundles": {
            "initial": "0x0700..0x0780",
            "resumption": "0x0780..0x0800",
        },
        "unattended_collection": True,
        "collection_before_first_network_transmission": True,
        "host_sha3_and_hostile_gates": "pass",
        "public_fixture_absent": True,
        "disk_writes": 0,
        "checker_stdout": completed.stdout.strip(),
    }


class Emulator:
    def __init__(self) -> None:
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, RAM_BYTES)
        self.uc.mem_write(0, bytes(RAM_BYTES))
        self.handlers: dict[int, object] = {}
        self.uc.reg_write(UC_X86_REG_DS, 0)
        self.uc.reg_write(UC_X86_REG_ES, 0)
        self.uc.reg_write(UC_X86_REG_SS, 0)
        self.uc.reg_write(UC_X86_REG_SP, 0x3FF0)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 2)
        self.uc.hook_add(UC_HOOK_CODE, self._dispatch)

    def _dispatch(self, machine: Uc, address: int, _size: int, _user) -> None:
        handler = self.handlers.get(address)
        if handler is not None:
            handler(machine)

    def run(self, entry: int, *, count: int = 2_000_000) -> None:
        self.uc.emu_start(entry, 0xFFFF, count=count)


def run_near_call(
    machine: Emulator,
    entry: int,
    *,
    registers: dict[int, int] | None = None,
    count: int = 20_000_000,
) -> bool:
    """Invoke one real-mode near entry and return its carry result."""

    sentinel = 0x0500
    returned = False

    def stop(uc: Uc) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    machine.handlers[sentinel] = stop
    stack = 0x3FEE
    machine.uc.mem_write(stack, struct.pack("<H", sentinel))
    machine.uc.reg_write(UC_X86_REG_SP, stack)
    machine.uc.reg_write(UC_X86_REG_EFLAGS, 2)
    for register, value in (registers or {}).items():
        machine.uc.reg_write(register, value)
    machine.run(entry, count=count)
    machine.handlers.pop(sentinel, None)
    if not returned:
        raise AssertionError(f"near call 0x{entry:04x} did not return")
    if machine.uc.reg_read(UC_X86_REG_SP) != 0x3FF0:
        raise AssertionError(f"near call 0x{entry:04x} unbalanced the stack")
    return bool(machine.uc.reg_read(UC_X86_REG_EFLAGS) & 1)


def test_complete_ticket_restore(build: Path) -> dict[str, object]:
    """Execute the exact post-FO restore of PSK, identity, and metadata."""

    controller = (build / "live_fo_controller.bin").read_bytes()
    listing = build / "live_fo_controller.lst"
    park = label_address(listing, "fo_park_ticket_psk", FO_CONTROLLER)
    restore = label_address(listing, "fo_restore_ticket_hold", FO_CONTROLLER)
    machine = Emulator()
    machine.uc.mem_write(FO_CONTROLLER, controller)

    psk = bytes((index * 29 + 7) & 0xFF for index in range(32))
    identity_tail = bytes(
        (index * 17 + 11) & 0xFF
        for index in range(TICKET_IDENTITY_TAIL[1] - TICKET_IDENTITY_TAIL[0])
    )
    parked = identity_tail + psk
    if len(parked) != TICKET_HOLD[1] - TICKET_HOLD[0]:
        raise AssertionError("complete native ticket hold geometry drifted")
    machine.uc.mem_write(TICKET_HOLD[0], identity_tail)
    machine.uc.mem_write(TICKET_PSK[0], psk)
    machine.uc.mem_write(TICKET_HOLD[0] + len(identity_tail), b"\xA5" * len(psk))
    if run_near_call(machine, park):
        raise AssertionError("native ticket PSK park returned carry")
    if bytes(machine.uc.mem_read(TICKET_HOLD[0], len(parked))) != parked:
        raise AssertionError("FO controller did not complete the native ticket hold")

    machine.uc.mem_write(TICKET_PSK[0], b"\xA5" * len(psk))
    machine.uc.mem_write(
        TICKET_IDENTITY_TAIL[0], b"\x5A" * len(identity_tail)
    )
    expected_k = bytes((index * 13 + 3) & 0xFF for index in range(32))
    guard = b"\xC3\x3C"
    machine.uc.mem_write(EXPECTED_K[0], expected_k)
    machine.uc.mem_write(EXPECTED_K[1], guard)

    if run_near_call(machine, restore):
        raise AssertionError("complete native ticket restore returned carry")
    if bytes(machine.uc.mem_read(TICKET_PSK[0], len(psk))) != psk:
        raise AssertionError("post-FO restore omitted or changed ticket PSK")
    if (
        bytes(machine.uc.mem_read(TICKET_IDENTITY_TAIL[0], len(identity_tail)))
        != identity_tail
    ):
        raise AssertionError("post-FO restore changed ticket identity/metadata")
    if bytes(machine.uc.mem_read(TICKET_HOLD[0], len(parked))) != parked:
        raise AssertionError("post-FO restore mutated its parked ticket source")
    if bytes(machine.uc.mem_read(EXPECTED_K[0], len(expected_k))) != expected_k:
        raise AssertionError("complete ticket hold overlaps independent K prime")
    if bytes(machine.uc.mem_read(EXPECTED_K[1], len(guard))) != guard:
        raise AssertionError("complete ticket/K hold crossed the kernel guard")

    return {
        "parked_ticket": "0x0700..0x080e",
        "ticket_bytes": len(parked),
        "psk_restored": "0x38b0..0x38d0",
        "identity_metadata_restored": "0x3b40..0x3c2e",
        "expected_k_preserved": "0x080e..0x082e",
        "kernel_guard_preserved": "0x082e..0x0830",
        "status": "pass",
    }


def strict_der_signature(size: int) -> bytes:
    """Build a canonical P-256-sized DER signature of 70, 71, or 72 bytes."""

    if size not in (70, 71, 72):
        raise AssertionError(f"unsupported identity-tail DER size {size}")
    first_padded = size >= 71
    second_padded = size == 72
    first = (
        b"\x00\x80" + bytes(range(1, 32))
        if first_padded
        else b"\x01" + bytes(range(2, 33))
    )
    second = (
        b"\x00\x80" + bytes(range(33, 64))
        if second_padded
        else b"\x01" + bytes(range(34, 65))
    )
    body = b"\x02" + bytes([len(first)]) + first
    body += b"\x02" + bytes([len(second)]) + second
    encoded = b"\x30" + bytes([len(body)]) + body
    if len(encoded) != size:
        raise AssertionError(
            f"constructed DER length {len(encoded)} differs from {size}"
        )
    return encoded


def identity_tail_fixture(signature_size: int) -> tuple[bytes, bytes, int]:
    signature = strict_der_signature(signature_size)
    cv = (
        b"\x0f"
        + (4 + len(signature)).to_bytes(3, "big")
        + b"\x04\x03"
        + len(signature).to_bytes(2, "big")
        + signature
    )
    offset = 80 - len(cv)
    prefix = bytes([0xA0 + index for index in range(offset)])
    finished = b"\x14\x00\x00\x20" + bytes(range(32))
    tail = prefix + cv + finished + b"\x16"
    if len(tail) != 117 or offset not in (0, 1, 2):
        raise AssertionError("identity-tail fixture geometry drifted")
    return tail, signature, offset


def test_identity_tail_boundaries(build: Path) -> dict[str, object]:
    """Execute the real SHA ABI across the observed CV79/CV80 boundary."""

    protected = (build / "live_protected_controller.bin").read_bytes()
    sym = (build / "sym_k14.bin").read_bytes()
    protected_listing = build / "live_protected_controller.lst"
    sym_listing = build / "sym_k14.lst"
    commit = label_address(
        protected_listing,
        "commit_identity_tail",
        PROTECTED_CONTROLLER,
    )
    transcript_init = label_address(
        sym_listing,
        "sym_transcript_init",
        SYM_OVERLAY,
    )
    transcript_update = label_address(
        sym_listing,
        "sym_transcript_update",
        SYM_OVERLAY,
    )
    transcript_snapshot = label_address(
        sym_listing,
        "sym_transcript_snapshot",
        SYM_OVERLAY,
    )
    initial = bytes((index * 37 + 11) & 0xFF for index in range(53))
    cases: list[dict[str, object]] = []

    for signature_size in (70, 71, 72):
        tail, signature, offset = identity_tail_fixture(signature_size)
        machine = Emulator()
        machine.uc.mem_write(PROTECTED_CONTROLLER, protected)
        machine.uc.mem_write(SYM_OVERLAY, sym)
        if run_near_call(machine, transcript_init):
            raise AssertionError("real transcript init rejected identity fixture")
        machine.uc.mem_write(0x0700, initial)
        if run_near_call(
            machine,
            transcript_update,
            registers={
                UC_X86_REG_SI: 0x0700,
                UC_X86_REG_CX: len(initial),
            },
        ):
            raise AssertionError("real initial transcript update rejected")
        machine.uc.mem_write(IDENTITY_TAIL, tail)
        if run_near_call(machine, commit):
            raise AssertionError(
                f"identity tail CV{len(tail[offset:80])} / DER{signature_size} "
                "was rejected by the real SHA ABI"
            )

        pointer = struct.unpack(
            "<H", machine.uc.mem_read(IDENTITY_CV_PTR, 2)
        )[0]
        der_len = struct.unpack(
            "<H", machine.uc.mem_read(IDENTITY_CV_DER_LEN, 2)
        )[0]
        published_len = struct.unpack(
            "<H", machine.uc.mem_read(AUTH_INPUT_SIGNATURE_LEN, 2)
        )[0]
        published = bytes(
            machine.uc.mem_read(AUTH_INPUT_SIGNATURE, signature_size)
        )
        received_finish = bytes(
            machine.uc.mem_read(SYM_RECEIVED_FINISH, 32)
        )
        if (
            pointer != IDENTITY_TAIL + offset
            or der_len != signature_size
            or published_len != signature_size
            or published != signature
            or received_finish != bytes(range(32))
        ):
            raise AssertionError(
                f"identity tail CV boundary publication drifted for DER{signature_size}"
            )

        digest_out = 0x0EE0
        if run_near_call(
            machine,
            transcript_snapshot,
            registers={UC_X86_REG_DI: digest_out},
        ):
            raise AssertionError("real transcript snapshot rejected")
        actual_digest = bytes(machine.uc.mem_read(digest_out, 32))
        expected_digest = hashlib.sha256(initial + tail[:80]).digest()
        if actual_digest != expected_digest:
            raise AssertionError(
                f"identity transcript boundary differs for DER{signature_size}"
            )
        cases.append(
            {
                "cv_bytes": 80 - offset,
                "der_bytes": signature_size,
                "prefix_bytes": offset,
                "real_sha_register_clobber": "pass",
            }
        )

    return {
        "cases": cases,
        "observed_live_boundaries": ["CV79/prefix1", "CV80/prefix0"],
        "real_symmetric_overlay": True,
    }


def secure_services(manifest: dict[str, object]) -> tuple[int, int]:
    services = manifest.get("persistent_services")
    if not isinstance(services, dict):
        raise AssertionError("secure persistent service ledger is missing")
    return int(str(services["emit"]), 0), int(str(services["fail"]), 0)


def test_preconnect_entropy_lifetime(
    build: Path,
    manifest: dict[str, object],
) -> dict[str, object]:
    """Execute the target continuation across destructive endpoint overlays."""

    controller = (build / "live_secure_preconnect_controller.bin").read_bytes()
    preconnect_listing = build / "live_secure_preconnect_controller.lst"
    hello_controller = (build / "live_hello_controller.bin").read_bytes()
    crypto_controller = (build / "live_crypto_controller.bin").read_bytes()
    installer_source = label_address(
        preconnect_listing,
        "preconnect_generic_installer_source",
        PRECONNECT_CONTROLLER,
    )
    generic_source = label_address(
        preconnect_listing,
        "preconnect_generic_template_source",
        PRECONNECT_CONTROLLER,
    )
    installer_end = label_address(
        preconnect_listing,
        "preconnect_generic_installer_end",
        PRECONNECT_CONTROLLER,
    )
    installer_image = controller[
        installer_source - PRECONNECT_CONTROLLER :
        installer_end - PRECONNECT_CONTROLLER
    ]
    generic_image = controller[
        generic_source - PRECONNECT_CONTROLLER :
        installer_end - PRECONNECT_CONTROLLER
    ]
    boot_listing = build / "live_boot_controller.lst"
    emit_address = label_address(boot_listing, "live_emit", BOOT_CONTROLLER)
    fail_address = label_address(boot_listing, "live_fail", BOOT_CONTROLLER)
    card_write_address = label_address(
        boot_listing,
        "live_secure_card_write",
        BOOT_CONTROLLER,
    )
    phases = phase_map(manifest)
    product_info = manifest.get("product_input")
    if not isinstance(product_info, dict):
        raise AssertionError("secure manifest lacks product-input metadata")
    tcp_close_cached_entry = int(
        str(product_info.get("tcp_close_cached_entry")), 0
    )
    if not 0x0900 <= tcp_close_cached_entry < 0x0F00:
        raise AssertionError(
            "secure manifest cached TCP close escaped the C phase window"
        )
    checkpoint = manifest.get("secure_fo_checkpoint")
    cleanup_meta = (
        checkpoint.get("preconnect_failure_cleanup")
        if isinstance(checkpoint, dict)
        else None
    )
    if (
        not isinstance(cleanup_meta, dict)
        or cleanup_meta.get("local_secret_ranges")
        != [
            "0x0700..0x0800",
            "0x1800..0x2337",
            "0x3000..0x3400",
            "0x3600..0x3b00",
            "0x3b9c..0x3bdc",
        ]
        or cleanup_meta.get("full_card_handoffs")
        != ["0x7e00..0x7f00", "0x7f00..0x8000"]
        or cleanup_meta.get("both_card_writes_attempted") is not True
        or cleanup_meta.get("ne_tx_page_restored") is not True
        or cleanup_meta.get("hello_controller_read_staging")
        != "0x3000..0x3200"
        or cleanup_meta.get("boot_fail_service_preserved_on_partial_read")
        is not True
    ):
        raise AssertionError("preconnect failure-cleanup manifest drifted")
    hello_key = int(str(phases["hello"]["key"]), 0)
    keygen_key = int(str(phases["keygen"]["key"]), 0)
    hello_controller_key = int(
        str(phases["hello_controller"]["key"]), 0
    )
    crypto_controller_key = int(
        str(phases["crypto_controller"]["key"]), 0
    )
    # These are the frozen Build-13 product-phase geometries checked by the
    # live builder: E is one sector and C is three sectors.
    endpoint_bytes = SECTOR
    tcp_bytes = 3 * SECTOR
    product_high_scratch = (0x36C2, 0x3B8F)
    initial = bytes((index * 29 + 17) & 0xFF for index in range(256))
    stub_ek = bytes((index * 43 + 5) & 0xFF for index in range(CARD_EK_LEN))
    keygen_image = (build / "keygen_k14.bin").read_bytes()
    exact_dk = KEYGEN_CHECK.ORACLE.fips_keygen_internal(initial[:64])
    exact_ek = exact_dk[1152:2336]

    class StopAtTransition(Exception):
        pass

    def run_case(
        *,
        mutate_duplicate: bool,
        real_keygen: bool,
        fail_ek_write: bool = False,
        fail_keygen_load: bool = False,
        fail_hello_controller_load: bool = False,
        fail_crypto_controller_load: bool = False,
    ) -> dict[str, object]:
        machine = Emulator()
        machine.uc.mem_write(PRECONNECT_CONTROLLER, controller)
        if real_keygen:
            machine.uc.mem_write(SYM_OVERLAY, keygen_image)
        machine.uc.mem_write(0x0700, initial)
        machine.uc.mem_write(NE_TX_START, b"\x40")
        guard_ranges = (
            (0x17F0, 0x1800),
            (0x2337, 0x2400),
            (0x2FF0, 0x3000),
            (0x3400, 0x3600),
            (0x3B8F, 0x3B9C),
            (0x3BDC, 0x3C00),
        )
        guards: dict[tuple[int, int], bytes] = {}
        for index, (start, end) in enumerate(guard_ranges, 1):
            value = bytes([0x80 + index]) * (end - start)
            machine.uc.mem_write(start, value)
            guards[(start, end)] = value
        card = bytearray(RAM_BYTES)
        output: list[str] = []
        loads: list[tuple[int, int]] = []
        card_writes: list[tuple[int, int]] = []
        card_reads: list[tuple[int, int, int]] = []
        keygen_called = False
        endpoint_overwrote = False
        tcp_overwrote = False
        endpoint_high_poisoned = False
        tcp_high_poisoned = False
        transitioned = False
        hello_transitioned = False
        failed = False
        prepare_internet_calls = 0
        entropy_vaulted_before_network = False

        def poison_retired_secrets(uc: Uc) -> None:
            for start, end in (
                (0x0700, 0x0800),
                (0x1800, 0x2337),
                (0x3000, 0x3400),
                (0x3600, 0x3B00),
                (0x3B9C, 0x3BDC),
            ):
                uc.mem_write(start, b"\xA5" * (end - start))

        def emit(uc: Uc) -> None:
            output.append(read_z(uc, uc.reg_read(UC_X86_REG_SI) & 0xFFFF))
            return_call(uc)

        def fail(uc: Uc) -> None:
            nonlocal failed
            failed = True
            uc.emu_stop()

        def card_write(uc: Uc) -> None:
            address = (uc.reg_read(UC_X86_REG_AX) & 0xFF) << 8
            source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
            if address + count > len(card):
                raise AssertionError("preconnect card write escaped card RAM")
            card_writes.append((address, count))
            if fail_ek_write and address == CARD_EK:
                poison_retired_secrets(uc)
                return_call(uc, carry=True)
                return
            card[address : address + count] = uc.mem_read(source, count)
            return_call(uc)

        def direct_card_write(uc: Uc) -> None:
            address = uc.mem_read(NE_TX_START, 1)[0] << 8
            source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
            if address + count > len(card):
                raise AssertionError("preconnect direct card write escaped card RAM")
            card[address : address + count] = uc.mem_read(source, count)
            card_writes.append((address, count))
            return_call(uc)

        def keygen(uc: Uc) -> None:
            nonlocal keygen_called
            keygen_called = True
            if bytes(uc.mem_read(0x3B9C, 64)) != initial[:64]:
                raise AssertionError("KeyGen did not receive target d||z")
            uc.mem_write(0x08C0, stub_ek)
            return_call(uc)

        def load(uc: Uc) -> None:
            key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            loads.append((key, destination))
            if len(loads) > 8:
                raise AssertionError(
                    f"preconnect transition repeated phase loads: {loads}"
                )
            if destination == 0x0700:
                # Model the real endpoint/DNS phase reusing the complete low
                # sector-rounded window.  Only card-vaulted copies survive.
                uc.mem_write(0x0700, b"\xCC" * endpoint_bytes)
            if destination == 0x0900:
                # The real three-sector TCP phase destroys the remainder of
                # the public-key window through 0x0f00.
                uc.mem_write(0x0900, b"\xCE" * tcp_bytes)
            if key == hello_key and destination == 0x1800:
                # The phase loader writes all eight reserved sectors, not only
                # HELLO's content bytes.  This deliberately destroys the old
                # 0x2400 caller after it has relocated the transition.
                uc.mem_write(0x1800, b"\xDD" * (8 * SECTOR))
            fail_load = (
                fail_keygen_load
                and key == keygen_key
                and destination == 0x1800
            ) or (
                fail_hello_controller_load
                and key == hello_controller_key
                and destination == 0x3000
            ) or (
                fail_crypto_controller_load
                and key == crypto_controller_key
                and destination == 0x3000
            )
            if fail_load:
                if (
                    key == crypto_controller_key
                    and destination == 0x3000
                ):
                    uc.mem_write(0x3000, crypto_controller[:137])
                elif key == keygen_key and destination == 0x1800:
                    uc.mem_write(0x1800, keygen_image[:137])
                poison_retired_secrets(uc)
            elif key == keygen_key and destination == 0x1800:
                if real_keygen:
                    uc.mem_write(0x1800, keygen_image)
            elif key == hello_controller_key and destination == 0x3000:
                uc.mem_write(
                    0x3000,
                    hello_controller.ljust(SECTOR, b"\0"),
                )
            elif key == crypto_controller_key and destination == 0x3000:
                uc.mem_write(
                    0x3000,
                    crypto_controller.ljust(SECTOR, b"\0"),
                )
            uc.reg_write(UC_X86_REG_DX, 0xA55A)
            return_call(uc, carry=fail_load)

        def endpoint(uc: Uc) -> None:
            nonlocal endpoint_overwrote, endpoint_high_poisoned
            endpoint_overwrote = (
                bytes(uc.mem_read(0x0700, endpoint_bytes))
                == b"\xCC" * endpoint_bytes
            )
            start, end = product_high_scratch
            uc.mem_write(start, b"\xCD" * (end - start))
            endpoint_high_poisoned = True
            return_call(uc)

        def prepare_internet(uc: Uc) -> None:
            nonlocal prepare_internet_calls, entropy_vaulted_before_network
            prepare_internet_calls += 1
            entropy_vaulted_before_network = (
                card_writes[:2]
                == [
                    (CARD_HANDOFF_A, CARD_PAGE_LEN),
                    (CARD_HANDOFF_B, CARD_PAGE_LEN),
                ]
                and bytes(
                    card[CARD_HANDOFF_A : CARD_HANDOFF_A + CARD_PAGE_LEN]
                )
                == initial
                and bytes(
                    card[CARD_HANDOFF_B : CARD_HANDOFF_B + CARD_PAGE_LEN]
                )
                == initial
            )
            if not entropy_vaulted_before_network:
                raise AssertionError(
                    "product internet preparation preceded entropy card vault"
                )
            return_call(uc)

        def tcp(uc: Uc) -> None:
            nonlocal tcp_overwrote, tcp_high_poisoned
            tcp_overwrote = (
                bytes(uc.mem_read(0x0900, tcp_bytes)) == b"\xCE" * tcp_bytes
            )
            start, end = product_high_scratch
            uc.mem_write(start, b"\xCF" * (end - start))
            tcp_high_poisoned = True
            return_call(uc)

        def card_read(uc: Uc) -> None:
            address = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            destination = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
            if address + count > len(card):
                raise AssertionError("preconnect card read escaped card RAM")
            data = bytearray(card[address : address + count])
            if mutate_duplicate and address == CARD_HANDOFF_B:
                data[37] ^= 1
            uc.mem_write(destination, bytes(data))
            card_reads.append((address, count, destination))
            return_call(uc)

        def transitioned_to_hello(uc: Uc) -> None:
            nonlocal transitioned, hello_transitioned
            if not hello_transitioned:
                if (
                    bytes(uc.mem_read(0x3400, SECTOR))
                    != hello_controller.ljust(SECTOR, b"\0")
                ):
                    raise AssertionError(
                        "staged HELLO controller was not copied exactly to 0x3400"
                    )
                if (
                    bytes(
                        uc.mem_read(
                            GENERIC_TRANSITION_INSTALLER,
                            len(installer_image),
                        )
                    )
                    != installer_image
                    or bytes(uc.mem_read(PRE_SYM_TRANSITION, len(generic_image)))
                    != generic_image
                ):
                    raise AssertionError(
                        "HELLO-specific transition did not install the generic successor"
                    )
                hello_transitioned = True
                raise StopAtTransition
            if (
                bytes(uc.mem_read(0x3400, SECTOR))
                != crypto_controller.ljust(SECTOR, b"\0")
            ):
                raise AssertionError(
                    "generic transition did not stage/copy the crypto controller"
                )
            transitioned = True
            raise StopAtTransition

        handlers = {
            emit_address: emit,
            fail_address: fail,
            card_write_address: card_write,
            RES_LOAD_PHASE: load,
            RES_PREPARE_INTERNET: prepare_internet,
            0x0700: endpoint,
            0x0900: tcp,
            tcp_close_cached_entry: tcp,
            NE_BUF_READ: card_read,
            NE_BUF_LOAD: direct_card_write,
            0x3400: transitioned_to_hello,
        }
        if not real_keygen:
            handlers[0x1800] = keygen
        def install_hooks(target: Emulator) -> None:
            target.handlers.update(handlers)

        install_hooks(machine)
        try:
            machine.run(
                PRECONNECT_CONTROLLER,
                count=500_000_000 if real_keygen else 2_000_000,
            )
        except StopAtTransition:
            pass
        if hello_transitioned and not transitioned and not failed:
            # Unicorn stops from inside the destination hook before the
            # controller's first instruction.  Resume the successor from an
            # exact RAM/register snapshot in a fresh engine so no cached
            # translation block can execute the stopped HELLO instruction.
            snapshot = bytes(machine.uc.mem_read(0, RAM_BYTES))
            stack_pointer = machine.uc.reg_read(UC_X86_REG_SP) & 0xFFFF
            successor = Emulator()
            successor.uc.mem_write(0, snapshot)
            successor.uc.reg_write(UC_X86_REG_SP, stack_pointer)
            install_hooks(successor)
            machine = successor
            machine.uc.reg_write(UC_X86_REG_AX, crypto_controller_key)
            try:
                machine.run(PRE_SYM_TRANSITION, count=2_000_000)
            except StopAtTransition:
                pass
        return {
            "machine": machine,
            "card": card,
            "output": output,
            "loads": loads,
            "card_writes": card_writes,
            "card_reads": card_reads,
            "keygen_called": keygen_called or real_keygen,
            "endpoint_overwrote": endpoint_overwrote,
            "tcp_overwrote": tcp_overwrote,
            "endpoint_high_poisoned": endpoint_high_poisoned,
            "tcp_high_poisoned": tcp_high_poisoned,
            "transitioned": transitioned,
            "hello_transitioned": hello_transitioned,
            "failed": failed,
            "prepare_internet_calls": prepare_internet_calls,
            "entropy_vaulted_before_network": entropy_vaulted_before_network,
            "guards": guards,
        }

    passed = run_case(mutate_duplicate=False, real_keygen=True)
    machine = passed["machine"]
    card = passed["card"]
    loads = passed["loads"]
    split_dk = (
        bytes(machine.uc.mem_read(0x3600, 384))
        + bytes(machine.uc.mem_read(0x3800, 384))
        + bytes(machine.uc.mem_read(0x3980, 384))
        + bytes(machine.uc.mem_read(0x08C0, 1184))
        + bytes(machine.uc.mem_read(0x3780, 32))
        + bytes(machine.uc.mem_read(0x37A0, 32))
    )
    if (
        passed["failed"]
        or not passed["transitioned"]
        or not passed["keygen_called"]
        or not passed["endpoint_overwrote"]
        or not passed["tcp_overwrote"]
        or not passed["endpoint_high_poisoned"]
        or not passed["tcp_high_poisoned"]
        or passed["prepare_internet_calls"] != 1
        or not passed["entropy_vaulted_before_network"]
        or passed["output"]
        != ["preflight cache\r\n", "offline keygen\r\n", "live connect\r\n"]
        or passed["card_writes"]
        != [
            (CARD_HANDOFF_A, CARD_PAGE_LEN),
            (CARD_HANDOFF_B, CARD_PAGE_LEN),
            (CARD_EK, CARD_EK_LEN),
        ]
        or passed["card_reads"]
        != [
            (CARD_HANDOFF_A, 128, 0x0700),
            (CARD_HANDOFF_B, 128, 0x0780),
        ]
        or loads[-4:]
        != [
            (keygen_key, 0x1800),
            (hello_key, 0x1800),
            (hello_controller_key, 0x3000),
            (crypto_controller_key, 0x3000),
        ]
        or bytes(card[CARD_HANDOFF_A : CARD_HANDOFF_A + CARD_PAGE_LEN])
        != initial
        or bytes(card[CARD_HANDOFF_B : CARD_HANDOFF_B + CARD_PAGE_LEN])
        != initial
        or bytes(card[CARD_EK : CARD_EK + CARD_EK_LEN]) != exact_ek
        or split_dk != exact_dk
        or bytes(machine.uc.mem_read(0x08C0, CARD_EK_LEN)) != exact_ek
        or bytes(machine.uc.mem_read(0x3B9C, 64)) != initial[64:128]
        or bytes(
            card[CARD_HANDOFF_A + 128 : CARD_HANDOFF_A + CARD_PAGE_LEN]
        )
        != initial[128:]
        or bytes(
            card[CARD_HANDOFF_B + 128 : CARD_HANDOFF_B + CARD_PAGE_LEN]
        )
        != initial[128:]
    ):
        raise AssertionError(
            "secure preconnect did not preserve target entropy across overlays"
        )

    rejected = run_case(mutate_duplicate=True, real_keygen=False)
    if (
        not rejected["failed"]
        or rejected["transitioned"]
        or rejected["output"]
        != ["preflight cache\r\n"]
        or any(
            any(rejected["card"][page : page + CARD_PAGE_LEN])
            for page in (CARD_HANDOFF_A, CARD_HANDOFF_B)
        )
        or any(rejected["machine"].uc.mem_read(0x0700, 256))
    ):
        raise AssertionError(
            "secure preconnect accepted a hostile duplicate mismatch"
        )

    def require_full_failure_scrub(
        case: dict[str, object],
        *,
        overwritten_guard_ranges: tuple[tuple[int, int], ...] = (),
    ) -> None:
        failed_machine = case["machine"]
        if not case["failed"] or case["transitioned"]:
            raise AssertionError("injected preconnect failure did not fail closed")
        for start, end in (
            (0x0700, 0x0800),
            (0x1800, 0x2337),
            (0x3000, 0x3400),
            (0x3600, 0x3B00),
            (0x3B9C, 0x3BDC),
        ):
            if any(failed_machine.uc.mem_read(start, end - start)):
                raise AssertionError(
                    f"preconnect failure left secret {start:#x}..{end:#x}"
                )
        if any(
            any(case["card"][page : page + CARD_PAGE_LEN])
            for page in (CARD_HANDOFF_A, CARD_HANDOFF_B)
        ):
            raise AssertionError("preconnect failure left card entropy")
        if case["card_writes"][-2:] != [
            (CARD_HANDOFF_A, CARD_PAGE_LEN),
            (CARD_HANDOFF_B, CARD_PAGE_LEN),
        ]:
            raise AssertionError("preconnect failure skipped a card scrub write")
        if failed_machine.uc.mem_read(NE_TX_START, 1)[0] != 0x40:
            raise AssertionError("preconnect failure did not restore NE TX page")
        for bounds, before in case["guards"].items():
            if bounds in overwritten_guard_ranges:
                continue
            start, end = bounds
            after = bytes(failed_machine.uc.mem_read(start, end - start))
            if after != before:
                raise AssertionError(
                    f"preconnect scrub changed guard {start:#x}..{end:#x}"
                )

    keygen_load_failure = run_case(
        mutate_duplicate=False,
        real_keygen=True,
        fail_keygen_load=True,
    )
    require_full_failure_scrub(keygen_load_failure)
    if keygen_load_failure["output"] != ["preflight cache\r\n"]:
        raise AssertionError("KeyGen-load failure progressed into KeyGen")

    ek_write_failure = run_case(
        mutate_duplicate=False,
        real_keygen=True,
        fail_ek_write=True,
    )
    require_full_failure_scrub(ek_write_failure)
    if ek_write_failure["output"] != [
        "preflight cache\r\n",
        "offline keygen\r\n",
    ]:
        raise AssertionError("EK-write failure progressed to live HELLO")

    transition_failure = run_case(
        mutate_duplicate=False,
        real_keygen=True,
        fail_hello_controller_load=True,
    )
    require_full_failure_scrub(
        transition_failure,
        overwritten_guard_ranges=((0x2337, 0x2400),),
    )
    if transition_failure["output"] != [
        "preflight cache\r\n",
        "offline keygen\r\n",
        "live connect\r\n",
    ]:
        raise AssertionError("transition-load failure marker order drifted")

    crypto_transition_failure = run_case(
        mutate_duplicate=False,
        real_keygen=True,
        fail_crypto_controller_load=True,
    )
    require_full_failure_scrub(
        crypto_transition_failure,
        overwritten_guard_ranges=(
            (0x2337, 0x2400),
            (0x3400, 0x3600),
        ),
    )
    if (
        not crypto_transition_failure["hello_transitioned"]
        or crypto_transition_failure["transitioned"]
        or crypto_transition_failure["output"]
        != [
            "preflight cache\r\n",
            "offline keygen\r\n",
            "live connect\r\n",
        ]
    ):
        raise AssertionError(
            "second staged transition failure did not fail closed"
        )
    return {
        "target_entropy_bytes": 256,
        "collection_before_first_network_transmission": True,
        "entropy_card_vaulted_before_product_dhcp": True,
        "duplicate_card_pages": ["0x7e00..0x7f00", "0x7f00..0x8000"],
        "endpoint_overwrite": (
            f"0x0700..0x{0x0700 + endpoint_bytes:04x}"
        ),
        "tcp_overwrite": f"0x0900..0x{0x0900 + tcp_bytes:04x}",
        "product_high_scratch_before_keygen": "0x36c2..0x3b8f",
        "initial_bundle_restored_and_compared": True,
        "resumption_bundle_survived": True,
        "target_generated_ek_card_bytes": CARD_EK_LEN,
        "real_keygen_exact_fips_oracle": True,
        "keygen_poly_work_poison_boundary": "0x3000..0x3400",
        "padded_hello_self_overwrite": "0x1800..0x2800",
        "hostile_duplicate_mismatch_failed_closed": True,
        "partial_keygen_reload_failure_full_scrub": True,
        "target_generated_ek_write_failure_full_scrub": True,
        "relocated_transition_load_failure_full_scrub": True,
        "hello_to_crypto_transition_failure_full_scrub": True,
        "local_secret_scrub_ranges": [
            "0x0700..0x0800",
            "0x1800..0x2337",
            "0x3000..0x3400",
            "0x3600..0x3b00",
            "0x3b9c..0x3bdc",
        ],
        "guard_preservation": True,
        "loader_register_clobber": "DX=0xa55a after every phase load",
        "transition": (
            "HELLO controller staged at 0x3000/copy 0x3400; low installer "
            "replaces 0x0f00 with generic crypto stage/copy transition"
        ),
        "status": "pass",
    }


def test_fo_cleanup_lifetimes(build: Path) -> dict[str, object]:
    """Prove success preserves only the one-shot resumption half."""

    controller = (build / "live_fo_controller.bin").read_bytes()
    listing = build / "live_fo_controller.lst"
    success_entry = label_address(
        listing,
        "fo_cleanup_handoffs",
        FO_CONTROLLER,
    )
    failure_entry = label_address(
        listing,
        "fo_cleanup_handoffs_full",
        FO_CONTROLLER,
    )

    def run_case(entry: int) -> tuple[dict[int, bytearray], list[tuple[int, int]]]:
        machine = Emulator()
        machine.uc.mem_write(FO_CONTROLLER, controller)
        machine.uc.mem_write(NE_TX_START, b"\x40")
        first = bytearray((index * 7 + 3) & 0xFF for index in range(256))
        second = bytearray((index * 11 + 9) & 0xFF for index in range(256))
        card = {CARD_HANDOFF_A: first, CARD_HANDOFF_B: second}
        writes: list[tuple[int, int]] = []

        def card_write(uc: Uc) -> None:
            address = uc.mem_read(NE_TX_START, 1)[0] << 8
            source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
            if address not in card or count not in (128, 256):
                raise AssertionError("FO cleanup card-write geometry drifted")
            card[address][:count] = uc.mem_read(source, count)
            writes.append((address, count))
            return_call(uc)

        machine.handlers[NE_BUF_LOAD] = card_write
        for start, end in (LOW_HANDOFFS, EXPECTED_K, HIGH_MESSAGE):
            machine.uc.mem_write(start, b"\xA5" * (end - start))
        if run_near_call(machine, entry):
            raise AssertionError("FO cleanup unexpectedly returned carry")
        if machine.uc.mem_read(NE_TX_START, 1)[0] != 0x40:
            raise AssertionError("FO cleanup did not restore NE TX page")
        for start, end in (LOW_HANDOFFS, EXPECTED_K, HIGH_MESSAGE):
            if any(machine.uc.mem_read(start, end - start)):
                raise AssertionError(
                    f"FO cleanup left local secret {start:#x}..{end:#x}"
                )
        return card, writes

    success_card, success_writes = run_case(success_entry)
    success_tails = {
        CARD_HANDOFF_A: bytes(
            (index * 7 + 3) & 0xFF for index in range(128, 256)
        ),
        CARD_HANDOFF_B: bytes(
            (index * 11 + 9) & 0xFF for index in range(128, 256)
        ),
    }
    if (
        success_writes
        != [(CARD_HANDOFF_A, 128), (CARD_HANDOFF_B, 128)]
        or any(any(success_card[page][:128]) for page in success_card)
        or any(
            bytes(success_card[page][128:]) != success_tails[page]
            for page in success_card
        )
    ):
        raise AssertionError("FO success cleanup erased or exposed wrong lifetime")

    failed_card, failure_writes = run_case(failure_entry)
    if (
        failure_writes
        != [(CARD_HANDOFF_A, 256), (CARD_HANDOFF_B, 256)]
        or any(any(value) for value in failed_card.values())
    ):
        raise AssertionError("FO failure cleanup did not erase complete pages")
    return {
        "success": {
            "initial_halves_zeroized": True,
            "resumption_halves_preserved": True,
            "card_writes": ["0x7e00+128", "0x7f00+128"],
        },
        "failure": {
            "complete_pages_zeroized": True,
            "card_writes": ["0x7e00+256", "0x7f00+256"],
        },
        "local_secret_ranges_zeroized": True,
        "ne_tx_start_restored": True,
        "status": "pass",
    }


def test_duplicate_mismatch(
    build: Path,
    manifest: dict[str, object],
) -> dict[str, object]:
    machine = Emulator()
    controller = (build / "live_fo_controller.bin").read_bytes()
    machine.uc.mem_write(FO_CONTROLLER, controller)
    emit_address, fail_address = secure_services(manifest)
    handoff_a = bytes((index * 19 + 7) & 0xFF for index in range(128))
    handoff_b = bytearray(handoff_a)
    handoff_b[73] ^= 0x01
    card = {
        CARD_HANDOFF_A: bytearray(handoff_a + bytes(128)),
        CARD_HANDOFF_B: bytearray(handoff_b + bytes(128)),
    }
    output: list[str] = []
    writes: list[tuple[int, bytes]] = []
    kernel_called = False
    failed = False

    def emit(uc: Uc) -> None:
        output.append(read_z(uc, uc.reg_read(UC_X86_REG_SI) & 0xFFFF))
        return_call(uc)

    def load(uc: Uc) -> None:
        return_call(uc)

    def card_read(uc: Uc) -> None:
        address = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
        page = CARD_HANDOFF_A if address < CARD_HANDOFF_B else CARD_HANDOFF_B
        offset = address - page
        source = card[page]
        if offset < 0 or offset + count > len(source):
            raise AssertionError("FO controller requested out-of-range handoff data")
        uc.mem_write(destination, bytes(source[offset : offset + count]))
        return_call(uc)

    def card_write(uc: Uc) -> None:
        page = uc.mem_read(NE_TX_START, 1)[0] << 8
        source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
        data = bytes(uc.mem_read(source, count))
        writes.append((page, data))
        if page in card:
            card[page][:count] = data
        return_call(uc)

    def kernel(uc: Uc) -> None:
        nonlocal kernel_called
        kernel_called = True
        uc.emu_stop()

    def fail(uc: Uc) -> None:
        nonlocal failed
        failed = True
        uc.emu_stop()

    machine.handlers.update(
        {
            emit_address: emit,
            RES_LOAD_PHASE: load,
            NE_BUF_READ: card_read,
            NE_BUF_LOAD: card_write,
            FO_KERNEL: kernel,
            fail_address: fail,
        }
    )
    machine.uc.mem_write(NE_TX_START, b"\x40")
    for start, end in (EXPECTED_K, LOW_HANDOFFS, HIGH_MESSAGE, HIGH_G_Z):
        machine.uc.mem_write(start, b"\xA5" * (end - start))
    machine.run(FO_CONTROLLER)

    if (
        not failed
        or kernel_called
        or "".join(output).split() != ["FO", "BEGIN"]
        or [page for page, _data in writes] != [CARD_HANDOFF_A, CARD_HANDOFF_B]
        or any(data != bytes(CARD_PAGE_LEN) for _page, data in writes)
        or any(card[page] != bytes(CARD_PAGE_LEN) for page in card)
        or machine.uc.mem_read(NE_TX_START, 1)[0] != 0x40
    ):
        raise AssertionError("hostile duplicate mismatch did not fail/scrub closed")
    for start, end in (EXPECTED_K, LOW_HANDOFFS, HIGH_MESSAGE, HIGH_G_Z):
        if bytes(machine.uc.mem_read(start, end - start)) != bytes(end - start):
            raise AssertionError(
                f"duplicate mismatch left local secret at {start:#x}..{end:#x}"
            )
    return {
        "mutated_duplicate_byte": 73,
        "kernel_called": kernel_called,
        "failed_before_scatter": True,
        "full_card_pages_zeroized": ["0x7e00..0x7f00", "0x7f00..0x8000"],
        "local_secret_ranges_zeroized": True,
        "ne_tx_start_restored": True,
        "status": "pass",
    }


def invoke_callback(
    build: Path,
    *,
    object_id: int,
    offset: int,
    count: int,
    expect_read: tuple[int, int] | None,
) -> dict[str, object]:
    machine = Emulator()
    controller = (build / "live_fo_controller.bin").read_bytes()
    machine.uc.mem_write(FO_CONTROLLER, controller)
    callback = label_address(
        build / "live_fo_controller.lst",
        "fo_card_read_callback",
        FO_CONTROLLER,
    )
    sentinel = 0x0500
    initial = {
        "bx": 0xA113,
        "bp": 0xB227,
        "ds": 0x0011,
        "es": 0x0022,
        "ss": 0x0000,
    }
    machine.uc.reg_write(UC_X86_REG_AX, object_id & 0xFF)
    machine.uc.reg_write(UC_X86_REG_DX, offset & 0xFFFF)
    machine.uc.reg_write(UC_X86_REG_CX, count & 0xFFFF)
    machine.uc.reg_write(UC_X86_REG_DI, 0x0800)
    machine.uc.reg_write(UC_X86_REG_BX, initial["bx"])
    machine.uc.reg_write(UC_X86_REG_BP, initial["bp"])
    machine.uc.reg_write(UC_X86_REG_DS, initial["ds"])
    machine.uc.reg_write(UC_X86_REG_ES, initial["es"])
    machine.uc.reg_write(UC_X86_REG_SS, initial["ss"])
    machine.uc.reg_write(UC_X86_REG_SP, 0x3F00)
    machine.uc.mem_write(0x3F00, struct.pack("<H", sentinel))
    machine.uc.reg_write(UC_X86_REG_EFLAGS, 2 | 0x400)
    reads: list[tuple[int, int]] = []
    returned = False

    def card_read(uc: Uc) -> None:
        reads.append(
            (
                uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
                uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
            )
        )
        return_call(uc)

    def done(uc: Uc) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    machine.handlers[NE_BUF_READ] = card_read
    machine.handlers[sentinel] = done
    machine.run(callback, count=2000)
    carry = bool(machine.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
    preserved = {
        "bx": machine.uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
        "bp": machine.uc.reg_read(UC_X86_REG_BP) & 0xFFFF,
        "ds": machine.uc.reg_read(UC_X86_REG_DS) & 0xFFFF,
        "es": machine.uc.reg_read(UC_X86_REG_ES) & 0xFFFF,
        "ss": machine.uc.reg_read(UC_X86_REG_SS) & 0xFFFF,
    }
    if (
        not returned
        or preserved != initial
        or machine.uc.reg_read(UC_X86_REG_EFLAGS) & 0x400
        or reads != ([] if expect_read is None else [expect_read])
        or carry != (expect_read is None)
    ):
        raise AssertionError(
            "FO card callback bound/register contract drifted: "
            f"reads={reads!r} carry={carry} preserved={preserved!r}"
        )
    return {
        "object": object_id,
        "offset": offset,
        "count": count,
        "read": reads,
        "carry": carry,
    }


def test_callback_bounds(build: Path) -> dict[str, object]:
    cases = [
        invoke_callback(
            build,
            object_id=2,
            offset=0,
            count=1,
            expect_read=None,
        ),
        invoke_callback(
            build,
            object_id=0,
            offset=1183,
            count=2,
            expect_read=None,
        ),
        invoke_callback(
            build,
            object_id=1,
            offset=1087,
            count=2,
            expect_read=None,
        ),
        invoke_callback(
            build,
            object_id=1,
            offset=0xFFF0,
            count=0x20,
            expect_read=None,
        ),
        invoke_callback(
            build,
            object_id=0,
            offset=0,
            count=384,
            expect_read=(CARD_EK, 384),
        ),
        invoke_callback(
            build,
            object_id=0,
            offset=1152,
            count=32,
            expect_read=(CARD_EK + 1152, 32),
        ),
        invoke_callback(
            build,
            object_id=1,
            offset=960,
            count=128,
            expect_read=(CARD_C + 960, 128),
        ),
    ]
    return {
        "cases": cases,
        "invalid_or_overflow_reads": 0,
        "max_valid_read_bytes": 384,
        "preserves": ["BX", "BP", "DS", "ES", "SS"],
        "returns_df_clear": True,
        "status": "pass",
    }


def test_transition_segment_normalization(build: Path) -> dict[str, object]:
    """Catch candidate overlays leaving ES nonzero before the card restore."""

    machine = Emulator()
    crypto = (build / "live_crypto_controller.bin").read_bytes()
    listing = build / "live_crypto_controller.lst"
    machine.uc.mem_write(BOOT_CONTROLLER, crypto)
    entry = label_address(
        listing,
        "live_secure_transition_prepare",
        BOOT_CONTROLLER,
    )
    reached_card_read = False
    reached_controller = False

    def card_read(uc: Uc) -> None:
        nonlocal reached_card_read
        reached_card_read = True
        actual = {
            "es": uc.reg_read(UC_X86_REG_ES) & 0xFFFF,
            "bx": uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
            "cx": uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
            "di": uc.reg_read(UC_X86_REG_DI) & 0xFFFF,
        }
        if actual != {"es": 0, "bx": CARD_CONTROLLER, "cx": 256, "di": 0x3400}:
            raise AssertionError(
                f"secure card continuation restore segment drifted: {actual!r}"
            )
        return_call(uc)

    def controller(uc: Uc) -> None:
        nonlocal reached_controller
        reached_controller = True
        uc.emu_stop()

    machine.handlers[NE_BUF_READ] = card_read
    machine.handlers[BOOT_CONTROLLER] = controller
    machine.uc.reg_write(UC_X86_REG_DS, 0)
    machine.uc.reg_write(UC_X86_REG_ES, 0x0123)
    machine.run(entry, count=5000)
    if not reached_card_read or not reached_controller:
        raise AssertionError("secure card continuation transition did not complete")
    return {
        "candidate_dirty_es": "0x0123",
        "card_read_es": "0x0000",
        "card_read": "0x7300..0x7400 -> 0x3400..0x3500",
        "controller_reached": True,
        "status": "pass",
    }


def test_protected_handoff_segment_normalization(
    build: Path,
) -> dict[str, object]:
    machine = Emulator()
    controller = (build / "live_secure_sym_controller.bin").read_bytes()
    listing = build / "live_secure_sym_controller.lst"
    machine.uc.mem_write(BOOT_CONTROLLER, controller)
    entry = label_address(
        listing,
        "live_secure_sym_nic_prepare",
        BOOT_CONTROLLER,
    )
    receive_stub = 0x0500
    machine.uc.mem_write(
        RES_NIC_VT_RECEIVE,
        struct.pack("<H", receive_stub),
    )
    receive_es: list[int] = []
    ack_es: list[int] = []
    protected_es: list[int] = []

    def receive(uc: Uc) -> None:
        receive_es.append(uc.reg_read(UC_X86_REG_ES) & 0xFFFF)
        uc.reg_write(UC_X86_REG_ES, 0x2222)
        uc.mem_write(NE_RX_SAMPLE_COUNT, b"\0\0")
        return_call(uc)

    def ack(uc: Uc) -> None:
        ack_es.append(uc.reg_read(UC_X86_REG_ES) & 0xFFFF)
        uc.reg_write(UC_X86_REG_ES, 0x3333)
        return_call(uc)

    def protected(uc: Uc) -> None:
        protected_es.append(uc.reg_read(UC_X86_REG_ES) & 0xFFFF)
        uc.emu_stop()

    machine.handlers.update(
        {
            receive_stub: receive,
            RES_TCP_ACK: ack,
            0x0900: protected,
        }
    )
    machine.uc.reg_write(UC_X86_REG_DS, 0)
    machine.uc.reg_write(UC_X86_REG_ES, 0x1111)
    machine.run(entry, count=5000)
    if (
        receive_es != [0]
        or ack_es != [0x2222]
        or protected_es != [0]
    ):
        raise AssertionError(
            "secure symmetric/protected segment normalization drifted: "
            f"receive={receive_es!r} ack={ack_es!r} protected={protected_es!r}"
        )
    return {
        "dirty_es_at_nic_prepare": "0x1111",
        "nic_receive_es": "0x0000",
        "receive_dirties_es": "0x2222",
        "ack_dirties_es": "0x3333",
        "protected_entry_es": "0x0000",
        "status": "pass",
    }


def test_boot_cold_clear(
    build: Path,
    manifest: dict[str, object],
) -> dict[str, object]:
    boot = (build / "live_boot_controller.bin").read_bytes()
    sym_controller = (build / "live_secure_sym_controller.bin").read_bytes()
    phases = phase_map(manifest)
    sym_key = int(str(phases["secure_sym_controller"]["key"]), 0)
    later_sym_key = int(str(phases["sym"]["key"]), 0)
    listing = build / "live_boot_controller.lst"
    emit = label_address(listing, "live_emit", BOOT_CONTROLLER)
    fail = label_address(listing, "live_fail", BOOT_CONTROLLER)
    restored = label_address(
        listing,
        "live_secure_card_write_restored",
        BOOT_CONTROLLER,
    )

    def run_case(
        failed_pages: frozenset[int],
    ) -> dict[str, object]:
        machine = Emulator()
        machine.uc.mem_write(BOOT_CONTROLLER, boot)
        writes: list[tuple[int, bytes]] = []
        restorations: list[int] = []
        later_load_reached = False
        failed = False

        def emit_handler(uc: Uc) -> None:
            return_call(uc)

        def nic_enter(uc: Uc) -> None:
            return_call(uc)

        def load(uc: Uc) -> None:
            nonlocal later_load_reached
            key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            if key == sym_key:
                if destination != 0x0700:
                    raise AssertionError(
                        "secure continuation preload destination drifted"
                    )
                uc.mem_write(destination, sym_controller)
                return_call(uc)
                return
            if key == later_sym_key:
                later_load_reached = True
                uc.emu_stop()
                return
            raise AssertionError(f"unexpected boot preload key {key:#x}")

        def card_write(uc: Uc) -> None:
            page = uc.mem_read(NE_TX_START, 1)[0] << 8
            source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
            writes.append((page, bytes(uc.mem_read(source, count))))
            # Match the real DMA leaf's volatile register contract.  In
            # particular AX cannot be used as an implicit loop variable
            # unless the wrapper restores it.
            uc.reg_write(UC_X86_REG_AX, 0xDEAD)
            uc.reg_write(UC_X86_REG_CX, 0xA55A)
            uc.reg_write(UC_X86_REG_DX, 0x5AA5)
            uc.reg_write(UC_X86_REG_SI, 0xBEEF)
            return_call(uc, carry=page in failed_pages)

        def card_write_restored(uc: Uc) -> None:
            restorations.append(uc.mem_read(NE_TX_START, 1)[0])

        def card_read(uc: Uc) -> None:
            raise AssertionError("secure boot read card vault before stale clear")

        def boot_failed(uc: Uc) -> None:
            nonlocal failed
            failed = True
            uc.emu_stop()

        machine.handlers.update(
            {
                emit: emit_handler,
                0x15DB: nic_enter,
                RES_LOAD_PHASE: load,
                NE_BUF_LOAD: card_write,
                NE_BUF_READ: card_read,
                restored: card_write_restored,
                fail: boot_failed,
            }
        )
        machine.uc.mem_write(NIC_FAMILY, b"\x02")
        machine.uc.mem_write(NE_RX_STOP, b"\x73")
        machine.uc.mem_write(NE_TX_START, b"\x40")
        machine.run(BOOT_CONTROLLER)
        return {
            "machine": machine,
            "writes": writes,
            "restorations": restorations,
            "later_load_reached": later_load_reached,
            "failed": failed,
        }

    expected_pages = [CARD_CONTROLLER, *CARD_WARM_CLEAR_PAGES]
    success = run_case(frozenset())
    if (
        not success["later_load_reached"]
        or success["failed"]
        or [page for page, _data in success["writes"]] != expected_pages
        or success["writes"][0][1] != sym_controller
        or any(
            data != bytes(CARD_PAGE_LEN)
            for _page, data in success["writes"][1:]
        )
        or success["restorations"] != [0x40] * len(expected_pages)
        or success["machine"].uc.mem_read(NE_TX_START, 1)[0] != 0x40
    ):
        raise AssertionError(
            "secure boot did not clear the complete resumed vault before use"
        )

    hostile_cases = [
        frozenset((page,)) for page in CARD_WARM_CLEAR_PAGES
    ] + [
        frozenset(
            (
                CARD_WARM_CLEAR_PAGES[0],
                CARD_WARM_CLEAR_PAGES[len(CARD_WARM_CLEAR_PAGES) // 2],
                CARD_WARM_CLEAR_PAGES[-1],
            )
        )
    ]
    for failed_pages in hostile_cases:
        rejected = run_case(failed_pages)
        if (
            not rejected["failed"]
            or rejected["later_load_reached"]
            or [page for page, _data in rejected["writes"]] != expected_pages
            or rejected["restorations"] != [0x40] * len(expected_pages)
            or rejected["machine"].uc.mem_read(NE_TX_START, 1)[0] != 0x40
        ):
            raise AssertionError(
                "warm stale-clear DMA failure did not aggregate/fail closed: "
                f"{sorted(failed_pages)!r}"
            )
    return {
        "write_order": [
            "0x7300 continuation controller",
            "0x7400..0x8000 zeros in ascending pages",
        ],
        "cleared_pages": [
            f"0x{page:04x}..0x{page + CARD_PAGE_LEN:04x}"
            for page in CARD_WARM_CLEAR_PAGES
        ],
        "full_page_bytes": CARD_PAGE_LEN,
        "before_next_phase_load": True,
        "card_reads_before_clear": 0,
        "warm_restart_stale_vault_read": "impossible before mandatory overwrite",
        "single_page_dma_failures_tested": len(CARD_WARM_CLEAR_PAGES),
        "multi_page_dma_failure_tested": True,
        "all_pages_attempted_after_dma_failure": True,
        "ne_tx_start_restored_after_every_write": True,
        "status": "pass",
    }


def test_scrub_card_sweep(build: Path) -> dict[str, object]:
    """Prove the reusable cold sweep attempts every page and aggregates CF."""

    controller = (build / "live_scrub_controller.bin").read_bytes()
    listing = build / "live_scrub_controller.lst"
    entry = label_address(listing, "scrub_card_pages", FO_CONTROLLER)
    restored = label_address(
        listing,
        "scrub_card_page_restored",
        FO_CONTROLLER,
    )
    expected_pages = list(CARD_RESERVED_PAGES)

    def run_case(failed_pages: frozenset[int]) -> dict[str, object]:
        machine = Emulator()
        machine.uc.mem_write(FO_CONTROLLER, controller)
        machine.uc.mem_write(NE_TX_START, b"\x40")
        initial = {
            page: bytes(
                ((page >> 8) * 17 + offset * 13 + 5) & 0xFF
                for offset in range(CARD_PAGE_LEN)
            )
            for page in CARD_RESERVED_PAGES
        }
        card = {
            page: bytearray(value)
            for page, value in initial.items()
        }
        writes: list[tuple[int, int]] = []
        restorations: list[int] = []

        def card_write(uc: Uc) -> None:
            page = uc.mem_read(NE_TX_START, 1)[0] << 8
            source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
            if page not in card or count != CARD_PAGE_LEN:
                raise AssertionError("cold sweep escaped reserved card pages")
            writes.append((page, count))
            if page not in failed_pages:
                card[page][:] = uc.mem_read(source, count)
            # ne_buf_load clobbers AX/CX/DX/SI.  Exercise the wrapper against
            # that real ABI so the page loop cannot accidentally rely on AL.
            uc.reg_write(UC_X86_REG_AX, 0xDEAD)
            uc.reg_write(UC_X86_REG_CX, 0xA55A)
            uc.reg_write(UC_X86_REG_DX, 0x5AA5)
            uc.reg_write(UC_X86_REG_SI, 0xBEEF)
            return_call(uc, carry=page in failed_pages)

        def card_write_restored(uc: Uc) -> None:
            restorations.append(uc.mem_read(NE_TX_START, 1)[0])

        machine.handlers.update(
            {
                NE_BUF_LOAD: card_write,
                restored: card_write_restored,
            }
        )
        carry = run_near_call(machine, entry)
        if (
            writes != [(page, CARD_PAGE_LEN) for page in expected_pages]
            or restorations != [0x40] * len(expected_pages)
            or machine.uc.mem_read(NE_TX_START, 1)[0] != 0x40
            or carry != bool(failed_pages)
        ):
            raise AssertionError(
                "cold sweep order/aggregate/restore contract drifted: "
                f"{sorted(failed_pages)!r}"
            )
        for page in expected_pages:
            expected = (
                initial[page]
                if page in failed_pages
                else bytes(CARD_PAGE_LEN)
            )
            if bytes(card[page]) != expected:
                raise AssertionError(
                    f"cold sweep page result drifted at {page:#06x}"
                )
        return {
            "carry": carry,
            "writes": writes,
            "restorations": restorations,
        }

    success = run_case(frozenset())
    hostile_cases = [
        frozenset((page,)) for page in CARD_RESERVED_PAGES
    ] + [
        frozenset(
            (
                CARD_RESERVED_PAGES[0],
                CARD_RESERVED_PAGES[len(CARD_RESERVED_PAGES) // 2],
                CARD_RESERVED_PAGES[-1],
            )
        )
    ]
    for failed_pages in hostile_cases:
        run_case(failed_pages)
    return {
        "pages_attempted": [
            f"0x{page:04x}..0x{page + CARD_PAGE_LEN:04x}"
            for page in CARD_RESERVED_PAGES
        ],
        "all_success_carry": success["carry"],
        "single_page_dma_failures_tested": len(CARD_RESERVED_PAGES),
        "multi_page_dma_failure_tested": True,
        "all_pages_attempted_after_dma_failure": True,
        "aggregate_failure_carry": True,
        "ne_tx_start_restored_after_every_write": True,
        "dma_leaf_ax_clobber_tested": True,
        "status": "pass",
    }


def test_failure_scrub(
    build: Path,
    manifest: dict[str, object],
    *,
    load_fails: bool,
    dma_fail_pages: frozenset[int] = frozenset(),
) -> dict[str, object]:
    if load_fails and dma_fail_pages:
        raise AssertionError("scrub DMA failures require a loaded scrub phase")
    machine = Emulator()
    crypto = (build / "live_crypto_controller.bin").read_bytes()
    scrub = (build / "live_scrub_controller.bin").read_bytes()
    machine.uc.mem_write(BOOT_CONTROLLER, crypto)
    emit_address, fail_address = secure_services(manifest)
    phases = phase_map(manifest)
    scrub_key = int(str(phases["scrub_controller"]["key"]), 0)
    initial_card = {
        page: bytes(
            ((page >> 8) * 19 + offset * 7 + 3) & 0xFF
            for offset in range(CARD_PAGE_LEN)
        )
        for page in CARD_RESERVED_PAGES
    }
    card = {
        page: bytearray(value)
        for page, value in initial_card.items()
    }
    writes: list[int] = []
    output: list[str] = []
    load_calls: list[tuple[int, int]] = []

    def load(uc: Uc) -> None:
        key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        load_calls.append((key, destination))
        if load_fails:
            return_call(uc, carry=True)
        else:
            if (key, destination) != (scrub_key, FO_CONTROLLER):
                raise AssertionError("persistent fail requested wrong scrub phase")
            uc.mem_write(destination, scrub)
            return_call(uc)

    def card_write(uc: Uc) -> None:
        page = uc.mem_read(NE_TX_START, 1)[0] << 8
        source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
        data = bytes(uc.mem_read(source, count))
        writes.append(page)
        if page not in card or count != CARD_PAGE_LEN:
            raise AssertionError("cold scrub escaped secret card pages")
        if page not in dma_fail_pages:
            card[page][:] = data
        uc.reg_write(UC_X86_REG_AX, 0xDEAD)
        uc.reg_write(UC_X86_REG_CX, 0xA55A)
        uc.reg_write(UC_X86_REG_DX, 0x5AA5)
        uc.reg_write(UC_X86_REG_SI, 0xBEEF)
        return_call(uc, carry=page in dma_fail_pages)

    def emit(uc: Uc) -> None:
        output.append(read_z(uc, uc.reg_read(UC_X86_REG_SI) & 0xFFFF))
        return_call(uc)

    machine.handlers.update(
        {
            RES_LOAD_PHASE: load,
            NE_BUF_LOAD: card_write,
            emit_address: emit,
        }
    )
    machine.uc.mem_write(NE_TX_START, b"\x40")
    for start, end in (EXPECTED_K, LOW_HANDOFFS, HIGH_MESSAGE, HIGH_G_Z):
        machine.uc.mem_write(start, b"\xA5" * (end - start))
    machine.run(fail_address, count=100_000)
    if load_calls != [(scrub_key, FO_CONTROLLER)] or "FAIL" not in "".join(output):
        raise AssertionError("persistent fail did not take the cold scrub boundary")
    if load_fails:
        if writes or any(card[page] == bytes(CARD_PAGE_LEN) for page in card):
            raise AssertionError("failed scrub load claimed card erasure")
        return {
            "scrub_phase_load": "failed",
            "card_cleanup": "best-effort only; not claimed",
            "failed_closed": True,
            "status": "pass",
        }
    if writes != list(CARD_RESERVED_PAGES):
        raise AssertionError("injected protected/post failure did not scrub card pages")
    for page in CARD_RESERVED_PAGES:
        expected = (
            initial_card[page]
            if page in dma_fail_pages
            else bytes(CARD_PAGE_LEN)
        )
        if bytes(card[page]) != expected:
            raise AssertionError(
                f"terminal cold scrub result drifted at {page:#06x}"
            )
    if machine.uc.mem_read(NE_TX_START, 1)[0] != 0x40:
        raise AssertionError("terminal cold scrub did not restore NE TX page")
    for start, end in (EXPECTED_K, LOW_HANDOFFS, HIGH_MESSAGE, HIGH_G_Z):
        if bytes(machine.uc.mem_read(start, end - start)) != bytes(end - start):
            raise AssertionError(
                f"cold scrub left local secret at {start:#x}..{end:#x}"
            )
    result = {
        "injected_sources": ["protected failure", "post failure"],
        "shared_persistent_fail_entry": f"0x{fail_address:04x}",
        "scrub_phase_load": "success",
        "all_reserved_pages_attempted": True,
        "local_secret_ranges_zeroized": True,
        "ne_tx_start_restored": True,
        "status": "pass",
    }
    if dma_fail_pages:
        result.update(
            {
                "injected_dma_failure_pages": [
                    f"0x{page:04x}" for page in sorted(dma_fail_pages)
                ],
                "failed_pages_not_claimed_erased": True,
                "remaining_pages_zeroized": True,
            }
        )
    else:
        result["full_card_pages_zeroized"] = [
            f"0x{page:04x}..0x{page + CARD_PAGE_LEN:04x}"
            for page in CARD_RESERVED_PAGES
        ]
    return result


def validate_success_semantics(
    build: Path,
    manifest: dict[str, object],
) -> dict[str, object]:
    checkpoint = manifest.get("secure_fo_checkpoint")
    if not isinstance(checkpoint, dict):
        raise AssertionError("secure checkpoint missing")
    if checkpoint.get("marker_order") != SUCCESS_MARKERS:
        raise AssertionError("secure success marker order drifted")
    fo = (build / "live_fo_controller.bin").read_bytes()
    auth = (build / "live_auth_controller.bin").read_bytes()
    positions = [
        fo.find(b"FO BEGIN"),
        fo.find(b"KEM VALID"),
        fo.find(b"AUTH BEGIN"),
        auth.find(b"IDENTITY PASS"),
        auth.find(b"PASS"),
        auth.find(b"RESULT"),
    ]
    if any(position < 0 for position in positions):
        raise AssertionError("secure success marker literal is missing")
    if not positions[0] < positions[1] < positions[2]:
        raise AssertionError("FO success markers are not in controller order")
    if not positions[3] < positions[4] < positions[5]:
        raise AssertionError("identity success markers are not in controller order")
    return {
        "required_exact_order": SUCCESS_MARKERS,
        "identity_only_is_success": False,
        "status": "pass",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    build = args.build_dir if args.build_dir.is_absolute() else ROOT / args.build_dir
    required = [
        build / "manifest.json",
        build / "SEED.SYS",
        build / "floppy-160k-live-k15.img",
        build / "live_fo_controller.bin",
        build / "live_fo_controller.lst",
        build / "live_scrub_controller.bin",
        build / "live_scrub_controller.lst",
        build / "live_crypto_controller.bin",
        build / "live_protected_controller.bin",
        build / "live_protected_controller.lst",
        build / "live_boot_controller.bin",
        build / "live_boot_controller.lst",
        build / "live_secure_preconnect_controller.bin",
        build / "live_secure_preconnect_controller.lst",
        build / "live_secure_sym_controller.bin",
        build / "floppy_entropy_controller.bin",
        build / "floppy_entropy_controller.lst",
        build / "keygen_k14.bin",
        build / "sym_k14.bin",
        build / "sym_k14.lst",
        build / "fo_tail_live.bin",
        build / "secure_ne_driver_probe.bin",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SystemExit(
            "missing secure live artifact(s):\n  "
            + "\n  ".join(missing)
            + "\nRun build_live_k15.py --secure first."
        )
    manifest = json.loads((build / "manifest.json").read_text(encoding="utf-8"))
    result = {
        "scope": (
            "offline secure logical-K14 live integration gate; exact artifact/"
            "phase binding, unchanged FO oracle, card-vault failure controls, "
            "no 86Box and no network I/O"
        ),
        "status": "pass",
        "artifact": validate_artifact(build, manifest),
        "entropy_oracle": run_entropy_oracle(build, manifest),
        "preconnect_entropy_lifetime": test_preconnect_entropy_lifetime(
            build, manifest
        ),
        "fo_oracle": run_fo_oracle(build),
        "complete_ticket_restore": test_complete_ticket_restore(build),
        "identity_tail_boundaries": test_identity_tail_boundaries(build),
        "fo_cleanup_lifetimes": test_fo_cleanup_lifetimes(build),
        "duplicate_mismatch": test_duplicate_mismatch(build, manifest),
        "callback_bounds": test_callback_bounds(build),
        "transition_segment_normalization": (
            test_transition_segment_normalization(build)
        ),
        "protected_handoff_segment_normalization": (
            test_protected_handoff_segment_normalization(build)
        ),
        "boot_cold_clear": test_boot_cold_clear(build, manifest),
        "cold_scrub_sweep": test_scrub_card_sweep(build),
        "injected_protected_post_failure": test_failure_scrub(
            build, manifest, load_fails=False
        ),
        "injected_terminal_scrub_dma_failure": test_failure_scrub(
            build,
            manifest,
            load_fails=False,
            dma_fail_pages=frozenset(
                (
                    CARD_RESERVED_PAGES[0],
                    CARD_RESERVED_PAGES[len(CARD_RESERVED_PAGES) // 2],
                    CARD_RESERVED_PAGES[-1],
                )
            ),
        ),
        "scrub_load_failure": test_failure_scrub(
            build, manifest, load_fails=True
        ),
        "success_semantics": validate_success_semantics(build, manifest),
    }
    output = args.json_out or build / "secure_fo_check.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("live TLS 1.3 logical-K14 secure FO integration gate: PASS")
    print("  122-sector artifact/phase/PSTOP/NE.DRV binding PASS")
    print(
        "  unattended pre-network floppy entropy oracle + "
        "no-public-fixture binding PASS"
    )
    print("  destructive-overlay entropy lifetime + duplicate compare PASS")
    print("  unchanged K14 FO oracle + ticket-PSK sentinel PASS")
    print("  complete 270-byte native ticket park/restore + guard PASS")
    print("  FO success/failure resumption-tail cleanup lifetimes PASS")
    print("  real-SHA CV79/CV80 identity-tail boundary regression PASS")
    print("  duplicate mismatch + callback bounds fail closed PASS")
    print("  dirty-ES card + protected-boundary normalization PASS")
    print("  boot 0x74..0x7f stale-page clear + hostile DMA failures PASS")
    print("  cold scrub 0x73..0x7f aggregate/restore sweep PASS")
    print("  protected/post terminal cold scrub + DMA failure sweep PASS")
    print("  scrub-phase load failure is explicitly best-effort only PASS")
    print("  secure success requires FO -> KEM -> auth -> identity order PASS")
    print(f"  result={output}")


if __name__ == "__main__":
    main()
