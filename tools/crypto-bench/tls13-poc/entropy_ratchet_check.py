#!/usr/bin/env python3
"""Execute the 8086 two-slot attempt-seed ratchet overlay in Unicorn.

This checker compares the target implementation byte-for-byte with the
existing host crash oracle.  It is deliberately an architecture-spike gate:
real BIOS/FAT allocation, sector writes, and physical entropy remain outside
its claims.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_INSN, UC_MODE_16, Uc, UcError
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_AX,
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
SPIKE = HERE.parent / "tls13-spike"
ASM = HERE / "entropy_ratchet_overlay.asm"

OVERLAY_BASE = 0x1800
OVERLAY_LIMIT = 0x3600
RETURN_SENTINEL = 0x0500
STACK_TOP = 0x3FF0
SCRATCH = 0x1000

SLOT0 = 0x0700
SLOT1 = 0x0900
SUPPLEMENT = 0x0B00
TIMING_SAMPLE = 0x0B80
WRITE_RECORD = 0x0C00
READBACK = 0x0E00
HIGH_LIMIT = 0x3C9C
SUPPLEMENT_LEN = 0x3748

ENTRY_RESET = 0
ENTRY_SELECT = 1
ENTRY_SUPPLEMENT_RESET = 2
ENTRY_SUPPLEMENT_APPEND = 3
ENTRY_COLLECT_TIMING = 4
ENTRY_PREPARE = 5
ENTRY_VERIFY = 6
ENTRY_GET_DZ = 7
ENTRY_ABORT = 8

D_DOMAIN = b"Seed ML-KEM d from attempt v1\0"
Z_DOMAIN = b"Seed ML-KEM z from attempt v1\0"


def _load_host_oracle():
    path = SPIKE / "entropy_ratchet_oracle.py"
    spec = importlib.util.spec_from_file_location(
        "seed_entropy_ratchet_host_oracle", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


HOST = _load_host_oracle()


def sha3(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_256()
    digest.update(domain)
    for part in parts:
        digest.update(part)
    return digest.digest()


def expand_dz(attempt_seed: bytes) -> bytes:
    return sha3(D_DOMAIN, attempt_seed) + sha3(Z_DOMAIN, attempt_seed)


@dataclass(frozen=True)
class Header:
    version: int
    image_bytes: int
    slot0: int
    slot1: int
    supplement: int
    supplement_max: int
    write_record: int
    readback: int
    high_start: int
    high_end: int
    dz: int
    entries: tuple[int, ...]


def parse_header(image: bytes) -> Header:
    if image[:8] != b"ENTRT001":
        raise AssertionError("entropy overlay header magic mismatch")
    fields = struct.unpack_from("<12H", image, 8)
    (
        version,
        image_bytes,
        slot0,
        slot1,
        supplement,
        supplement_max,
        write_record,
        readback,
        high_start,
        high_end,
        dz,
        entry_count,
    ) = fields
    entries = struct.unpack_from(f"<{entry_count}H", image, 32)
    return Header(
        version,
        image_bytes,
        slot0,
        slot1,
        supplement,
        supplement_max,
        write_record,
        readback,
        high_start,
        high_end,
        dz,
        tuple(entries),
    )


class Overlay:
    def __init__(self, image: bytes, header: Header) -> None:
        self.header = header
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 0x10000)
        self.uc.mem_write(OVERLAY_BASE, image)
        self.uc.mem_write(RETURN_SENTINEL, b"\xf4")
        self.pit_bytes = [0x34, 0x12]
        self.pit_index = 0
        self.outs: list[tuple[int, int, int]] = []
        self.uc.hook_add(
            UC_HOOK_INSN, self._in_hook, None, 1, 0, UC_X86_INS_IN
        )
        self.uc.hook_add(
            UC_HOOK_INSN, self._out_hook, None, 1, 0, UC_X86_INS_OUT
        )
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)

    def _in_hook(self, _uc: Uc, port: int, size: int, _user: object) -> int:
        if port != 0x40 or size != 1:
            raise AssertionError(f"unexpected IN port={port:04x} size={size}")
        value = self.pit_bytes[self.pit_index % len(self.pit_bytes)]
        self.pit_index += 1
        return value

    def _out_hook(
        self, _uc: Uc, port: int, size: int, value: int, _user: object
    ) -> None:
        self.outs.append((port, size, value))

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(address, length))

    def write(self, address: int, value: bytes) -> None:
        self.uc.mem_write(address, bytes(value))

    def word(self, address: int) -> int:
        return int.from_bytes(self.read(address, 2), "little")

    def call(
        self,
        entry: int,
        *,
        ax: int = 0,
        bx: int = 0,
        cx: int = 0,
        dx: int = 0,
        si: int = 0,
        di: int = 0,
        expect_success: bool = True,
    ) -> dict[str, int | bool]:
        address = self.header.entries[entry]
        self.write(STACK_TOP - 2, RETURN_SENTINEL.to_bytes(2, "little"))
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        self.uc.reg_write(UC_X86_REG_IP, address)
        self.uc.reg_write(UC_X86_REG_AX, ax)
        self.uc.reg_write(UC_X86_REG_BX, bx)
        self.uc.reg_write(UC_X86_REG_CX, cx)
        self.uc.reg_write(UC_X86_REG_DX, dx)
        self.uc.reg_write(UC_X86_REG_SI, si)
        self.uc.reg_write(UC_X86_REG_DI, di)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x2)
        try:
            self.uc.emu_start(address, RETURN_SENTINEL, count=80_000_000)
        except UcError as exc:
            ip = self.uc.reg_read(UC_X86_REG_IP)
            raise AssertionError(
                f"Unicorn failed in entry {entry} at {ip:04x}: {exc}"
            ) from exc
        carry = bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
        if expect_success and carry:
            raise AssertionError(f"overlay entry {entry} returned failure")
        if not expect_success and not carry:
            raise AssertionError(f"overlay entry {entry} accepted hostile input")
        return {
            "ax": self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
            "bx": self.uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
            "cx": self.uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
            "dx": self.uc.reg_read(UC_X86_REG_DX) & 0xFFFF,
            "si": self.uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
            "di": self.uc.reg_read(UC_X86_REG_DI) & 0xFFFF,
            "carry": carry,
        }

    def load_media(self, media) -> None:
        self.write(SLOT0, media.slots[0])
        self.write(SLOT1, media.slots[1])

    def select_media(self, media) -> int:
        self.call(ENTRY_RESET)
        self.load_media(media)
        result = self.call(ENTRY_SELECT)
        return int(result["ax"])

    def set_supplement(self, value: bytes) -> None:
        if len(value) > self.header.supplement_max:
            raise ValueError("supplement exceeds target cap")
        self.call(ENTRY_SUPPLEMENT_RESET)
        self.write(SCRATCH, value)
        self.call(ENTRY_SUPPLEMENT_APPEND, si=SCRATCH, cx=len(value))

    def prepare(self) -> tuple[int, bytes]:
        result = self.call(ENTRY_PREPARE)
        if result["si"] != WRITE_RECORD or result["cx"] != HOST.SECTOR_BYTES:
            raise AssertionError("prepare ABI returned unexpected record geometry")
        return int(result["ax"]), self.read(WRITE_RECORD, HOST.SECTOR_BYTES)

    def assert_dz_inaccessible(self) -> None:
        self.call(ENTRY_GET_DZ, expect_success=False)
        if self.read(self.header.dz, 64) != bytes(64):
            raise AssertionError("d||z became observable before durable verification")

    def verify_and_get_dz(self, readback: bytes) -> bytes:
        self.write(READBACK, readback)
        self.call(ENTRY_VERIFY)
        result = self.call(ENTRY_GET_DZ)
        if result["si"] != self.header.dz or result["cx"] != 64:
            raise AssertionError("get_dz returned unexpected ABI geometry")
        return self.read(self.header.dz, 64)


def build_image() -> tuple[bytes, Header]:
    with tempfile.TemporaryDirectory(prefix="seed-entropy-ratchet-") as temp:
        output = Path(temp) / "entropy_ratchet_overlay.bin"
        subprocess.run(
            ["nasm", "-f", "bin", "-o", str(output), str(ASM)],
            cwd=HERE,
            check=True,
        )
        image = output.read_bytes()
    header = parse_header(image)
    expected = (
        header.version == 1
        and header.image_bytes == len(image)
        and header.slot0 == SLOT0
        and header.slot1 == SLOT1
        and header.supplement == SUPPLEMENT
        and header.supplement_max == 96
        and header.write_record == WRITE_RECORD
        and header.readback == READBACK
        and header.high_start == 0x3600
        and header.high_end <= HIGH_LIMIT
        and len(header.entries) == 9
    )
    if not expected:
        raise AssertionError(f"unexpected entropy overlay header: {header}")
    if OVERLAY_BASE + len(image) > OVERLAY_LIMIT:
        raise AssertionError("entropy overlay exceeds phase-overlay window")
    if header.high_end >= STACK_TOP:
        raise AssertionError("entropy state collides with 16 KiB stack")
    return image, header


def target_attempt(
    image: bytes,
    header: Header,
    media,
    supplement: bytes,
    *,
    commit: bool = True,
) -> tuple[Overlay, object, bytes | None]:
    overlay = Overlay(image, header)
    selected = overlay.select_media(media)
    host_slot, _host_record = media.current()
    if selected != host_slot:
        raise AssertionError(
            f"target selected slot {selected}; host selected {host_slot}"
        )
    overlay.set_supplement(supplement)
    host_prepared = HOST.prepare_attempt(media, supplement)
    target_slot, target_record = overlay.prepare()
    if target_slot != host_prepared.target_slot:
        raise AssertionError("target alternate-slot selection differs from host")
    if target_record != host_prepared.encoded_record:
        raise AssertionError("target record differs byte-for-byte from host oracle")
    overlay.assert_dz_inaccessible()
    if not commit:
        return overlay, host_prepared, None
    dz = overlay.verify_and_get_dz(target_record)
    expected_dz = expand_dz(host_prepared.attempt_seed)
    if dz != expected_dz:
        raise AssertionError("target d||z differs from domain-separated host result")
    return overlay, host_prepared, dz


def check_timing_collector(image: bytes, header: Header) -> dict[str, object]:
    overlay = Overlay(image, header)
    overlay.call(ENTRY_RESET)
    overlay.call(ENTRY_SUPPLEMENT_RESET)
    overlay.write(0x046C, struct.pack("<I", 0x12345678))
    overlay.write(0x041A, struct.pack("<H", 0x001E))
    overlay.write(0x041C, struct.pack("<H", 0x0020))
    overlay.write(0x041E, struct.pack("<H", 0x1E61))
    overlay.call(ENTRY_COLLECT_TIMING)
    expected = bytes.fromhex("3412785634121e002000611e")
    if overlay.read(TIMING_SAMPLE, 12) != expected:
        raise AssertionError("target timing collector emitted unexpected bytes")
    if overlay.read(SUPPLEMENT, 12) != expected:
        raise AssertionError("target timing collector did not append its sample")
    if overlay.outs != [(0x43, 1, 0)]:
        raise AssertionError(f"unexpected PIT programming: {overlay.outs}")

    # The fixed collector can append eight 12-byte snapshots into the 96-byte
    # supplemental buffer; the ninth must fail without changing its length.
    for _ in range(7):
        overlay.call(ENTRY_COLLECT_TIMING)
    if overlay.word(SUPPLEMENT_LEN) != 96:
        raise AssertionError("collector did not fill the supplemental buffer")
    overlay.call(ENTRY_COLLECT_TIMING, expect_success=False)
    if overlay.word(SUPPLEMENT_LEN) != 96:
        raise AssertionError("failed collector append changed supplemental length")
    return {
        "sample_bytes": 12,
        "sample_sources": [
            "latched PIT channel 0 count",
            "BIOS tick snapshot",
            "BIOS keyboard ring head/tail",
            "nonconsuming queued-key peek",
        ],
        "buffer_cap_bytes": 96,
        "entropy_credit_claimed_bits": 0,
    }


def check_readback_gate(
    image: bytes, header: Header, base, supplement: bytes
) -> dict[str, int]:
    overlay, prepared, _unused = target_attempt(
        image, header, base, supplement, commit=False
    )
    old = base.slots[prepared.target_slot]
    for written in range(HOST.SECTOR_BYTES):
        readback = HOST.torn_prefix(old, prepared.encoded_record, written)
        overlay.write(READBACK, readback)
        overlay.call(ENTRY_VERIFY, expect_success=False)
        overlay.assert_dz_inaccessible()
    dz = overlay.verify_and_get_dz(prepared.encoded_record)
    if dz != expand_dz(prepared.attempt_seed):
        raise AssertionError("complete readback did not release expected d||z")
    return {
        "rejected_prefix_readbacks": HOST.SECTOR_BYTES,
        "accepted_complete_readbacks": 1,
    }


def check_prefix_crashes(
    image: bytes,
    header: Header,
    base,
    entropy_a: bytes,
    entropy_b: bytes,
) -> dict[str, int]:
    first = HOST.prepare_attempt(base, entropy_a)
    first_dz = expand_dz(first.attempt_seed)
    examined = 0
    for written in range(HOST.SECTOR_BYTES + 1):
        crashed = base.clone()
        old = crashed.slots[first.target_slot]
        crashed.slots[first.target_slot] = HOST.torn_prefix(
            old, first.encoded_record, written
        )
        _overlay, next_prepared, next_dz = target_attempt(
            image, header, crashed, entropy_b
        )
        if next_dz == first_dz:
            raise AssertionError(f"target reused d||z after prefix tear {written}")
        expected_generation = 1 if written == HOST.SECTOR_BYTES else 0
        if crashed.current()[1].generation != expected_generation:
            raise AssertionError("host/target crash fixture generation mismatch")
        if next_prepared.next_record.generation != expected_generation + 1:
            raise AssertionError("target prepared from the wrong generation")
        examined += 1

    boundary_names = (
        "after-sector-before-readback",
        "after-readback-before-emission",
        "after-emission",
    )
    for boundary in boundary_names:
        crashed = base.clone()
        crashed.slots[first.target_slot] = first.encoded_record
        _overlay, _next_prepared, next_dz = target_attempt(
            image, header, crashed, entropy_b
        )
        if next_dz == first_dz:
            raise AssertionError(f"target reused d||z at {boundary}")
    return {
        "target_prefix_torn_write_cases": examined,
        "target_post_write_boundary_cases": len(boundary_names),
    }


def check_single_byte_corruption(
    image: bytes, header: Header, encoded: bytes
) -> dict[str, int]:
    rejected = 0
    for index in range(HOST.SECTOR_BYTES):
        corrupted = bytearray(encoded)
        corrupted[index] ^= 0x01
        media = HOST.Media([bytes(corrupted), HOST.ERASED])
        overlay = Overlay(image, header)
        overlay.call(ENTRY_RESET)
        overlay.load_media(media)
        overlay.call(ENTRY_SELECT, expect_success=False)
        rejected += 1
    return {"target_single_byte_corruptions_rejected": rejected}


def check_equal_generation(
    image: bytes, header: Header
) -> dict[str, object]:
    state_a = sha3(b"Seed equal-generation state A\0")
    state_b = sha3(b"Seed equal-generation state B\0")
    ambiguous = HOST.Media(
        [HOST.Record(7, state_a).encode(), HOST.Record(7, state_b).encode()]
    )
    overlay = Overlay(image, header)
    overlay.call(ENTRY_RESET)
    overlay.load_media(ambiguous)
    overlay.call(ENTRY_SELECT, expect_success=False)
    try:
        ambiguous.current()
    except ValueError:
        pass
    else:
        raise AssertionError("host accepted equal-generation state ambiguity")

    duplicate = HOST.Media(
        [HOST.Record(7, state_a).encode(), HOST.Record(7, state_a).encode()]
    )
    overlay = Overlay(image, header)
    selected = overlay.select_media(duplicate)
    if selected != 1 or duplicate.current()[0] != 1:
        raise AssertionError("duplicate equal-generation tie-break differs from host")
    return {
        "different_state": "rejected",
        "identical_state_tiebreak_slot": 1,
    }


def check_identical_supplement_sequence(
    image: bytes, header: Header, initial: bytes, attempts: int
) -> dict[str, int]:
    media = HOST.Media.initialized(initial)
    overlay = Overlay(image, header)
    selected = overlay.select_media(media)
    if selected != 0:
        raise AssertionError("initialized media did not select slot 0")
    seen: set[bytes] = set()
    supplement = b"identical supplemental input"
    for _ in range(attempts):
        overlay.set_supplement(supplement)
        prepared = HOST.prepare_attempt(media, supplement)
        target_slot, target_record = overlay.prepare()
        if target_slot != prepared.target_slot:
            raise AssertionError("sequence target-slot mismatch")
        if target_record != prepared.encoded_record:
            raise AssertionError("sequence target record differs from host")
        overlay.assert_dz_inaccessible()
        dz = overlay.verify_and_get_dz(target_record)
        if dz != expand_dz(prepared.attempt_seed):
            raise AssertionError("sequence target d||z differs from host")
        if dz in seen:
            raise AssertionError("identical supplemental input repeated target d||z")
        seen.add(dz)
        media.slots[prepared.target_slot] = prepared.encoded_record
    return {"target_identical_supplement_attempts": attempts}


def check_rollback_copy_caveat(
    image: bytes, header: Header, base
) -> dict[str, object]:
    supplement = b"same copied-media timing"
    _oa, pa, dza = target_attempt(image, header, base.clone(), supplement)
    _ob, pb, dzb = target_attempt(image, header, base.clone(), supplement)
    if pa.encoded_record != pb.encoded_record or dza != dzb:
        raise AssertionError("copied media unexpectedly diverged deterministically")
    return {
        "copied_media_same_input_repeats_dz": True,
        "rollback_safety_established": False,
    }


def run(attempts: int) -> dict[str, object]:
    image, header = build_image()
    initial = sha3(b"Seed ratchet oracle initial state v1\0")
    entropy_a = b"physical timing sample A"
    entropy_b = b"physical timing sample B"
    base = HOST.Media.initialized(initial)

    # One literal happy path establishes exact record and d||z parity first.
    _overlay, first, _dz = target_attempt(
        image, header, base.clone(), entropy_a
    )
    collector = check_timing_collector(image, header)
    readback = check_readback_gate(image, header, base.clone(), entropy_a)
    torn = check_prefix_crashes(
        image, header, base.clone(), entropy_a, entropy_b
    )
    corruptions = check_single_byte_corruption(
        image, header, first.encoded_record
    )
    equal_generation = check_equal_generation(image, header)
    sequence = check_identical_supplement_sequence(
        image, header, initial, attempts
    )
    rollback = check_rollback_copy_caveat(image, header, base)

    # Keep the original, independently maintained host model as an explicit
    # regression gate, including its longer 4096-attempt deterministic run.
    host_result = HOST.crash_matrix()
    if host_result["status"] != "PASS":
        raise AssertionError("existing host crash oracle failed")

    return {
        "status": "PASS",
        "runtime_integration": False,
        "target": "8086 real mode under Unicorn",
        "assembly": ASM.name,
        "static_bytes": len(image),
        "static_sectors_rounded": (len(image) + 511) // 512,
        "overlay_window": [OVERLAY_BASE, OVERLAY_LIMIT],
        "high_state_window": [header.high_start, header.high_end],
        "stack_top": STACK_TOP,
        "external_buffers": {
            "slot0": [header.slot0, header.slot0 + HOST.SECTOR_BYTES],
            "slot1": [header.slot1, header.slot1 + HOST.SECTOR_BYTES],
            "supplement": [
                header.supplement,
                header.supplement + header.supplement_max,
            ],
            "write_record": [
                header.write_record,
                header.write_record + HOST.SECTOR_BYTES,
            ],
            "readback": [
                header.readback,
                header.readback + HOST.SECTOR_BYTES,
            ],
            "d_z": [header.dz, header.dz + 64],
        },
        "record_format": {
            "slot_bytes": HOST.SECTOR_BYTES,
            "generation_bits": 64,
            "state_bytes": HOST.STATE_BYTES,
            "integrity": "domain-separated SHA3-256",
            "integrity_is_authentication": False,
        },
        "host_record_and_derivation_parity": True,
        "d_z_release_requires_exact_verified_readback": True,
        "collector": collector,
        "readback_gate": readback,
        "crash_gate": torn,
        "corruption_gate": corruptions,
        "equal_generation_gate": equal_generation,
        "identical_supplement_gate": sequence,
        "rollback_copy_caveat": rollback,
        "existing_host_oracle": {
            "status": host_result["status"],
            "prefix_torn_write_cases": host_result[
                "prefix_torn_write_cases"
            ],
            "post_write_boundary_cases": host_result[
                "post_write_boundary_cases"
            ],
            "successful_sequence_attempts": host_result[
                "successful_sequence_attempts"
            ],
            "single_byte_corruptions_rejected": host_result[
                "single_byte_corruptions_rejected"
            ],
        },
        "physical_assumptions_not_established": [
            "which BIOS/FAT sectors are safely preallocated to the two slots",
            "BIOS write/readback behavior on target floppy controllers and media",
            "power-failure atomicity beyond exhaustive prefix tears",
            "active mutable-media authenticity",
            "copied or rolled-back floppy safety",
            "min-entropy in PIT/tick/keyboard timing samples",
            "freshness when media is write-protected",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target-identical-attempts",
        type=int,
        default=128,
        help="successful target-assembly sequence length (host gate remains 4096)",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.target_identical_attempts < 1:
        parser.error("--target-identical-attempts must be positive")
    result = run(args.target_identical_attempts)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("8086 attempt-seed ratchet overlay: PASS")
        print(
            f"  static: {result['static_bytes']} bytes / "
            f"{result['static_sectors_rounded']} rounded sectors"
        )
        print(
            "  target: "
            f"{result['crash_gate']['target_prefix_torn_write_cases']} "
            "prefix-crash cases; "
            f"{result['corruption_gate']['target_single_byte_corruptions_rejected']} "
            "single-byte corruptions; "
            f"{result['identical_supplement_gate']['target_identical_supplement_attempts']} "
            "identical-input attempts"
        )
        print("  d||z release remained gated on exact durable readback")
        print("  copied/rolled-back media and physical entropy remain unresolved")


if __name__ == "__main__":
    main()
