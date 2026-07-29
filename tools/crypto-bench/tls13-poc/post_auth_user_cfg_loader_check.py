#!/usr/bin/env python3
"""Build and hostile-test the fixed post-auth USER.CFG loader.

Every credential used here is synthetic and exists only in a temporary FAT12
fixture.  The checker resolves the directory entry and cluster chain produced
by the real image builder, compiles that immutable geometry into the loader,
executes the cpu-8086 binary under Unicorn, and finally runs the loader as the
real fixed callback of the post-auth request controller.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from capstone.x86_const import X86_OP_IMM
from unicorn import Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_ES,
    UC_X86_REG_SI,
)

import post_auth_application_check as APP


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "post_auth_user_cfg_loader.asm"
IMAGE_BUILDER = ROOT / "tools/build-fat12-image.py"

LOADER_ENTRY = 0x0520
LOADER_LIMIT = 0x0900
FULL_AUTHORIZE_ENTRY = 0x1500
AUTH_GENERATION = 0x3C30
RAW_SECTOR = 0x0E00
RAW_SECTOR_END = 0x1000
TEMP_START = 0x1C00
TEMP_END = (
    TEMP_START
    + 2
    + APP.PUBLICATION_KEY_MAX
    + 1
    + 2
    + APP.PUBLICATION_MODEL_MAX
    + 1
)
ISSUER_START = 0x3600
ISSUER_END = 0x3673

INT13_TOTAL = 0x3C62
INT13_READ = 0x3C64
INT13_RESET = 0x3C66
INT13_DENIED = 0x3C68
AUTHORIZE_COUNT = 0x3C6A
PARSE_STATE = 0x3C6C
PARSE_STATE_END = 0x3C71

SECTOR_BYTES = 512
SECTORS_PER_TRACK = 8
HEAD_COUNT = 1
RESERVED_SECTORS = 5
FAT_COUNT = 2
ROOT_ENTRIES = 64
SECTORS_PER_FAT = 1
TOTAL_SECTORS = 320
MEDIA = 0xFC


@dataclass(frozen=True)
class FatFixture:
    config: bytes
    image: bytes
    sector: bytes
    absolute_lba: int
    file_size: int
    cluster_count: int
    sectors_per_track: int
    head_count: int
    cylinder: int
    head: int
    sector_number: int


@dataclass(frozen=True)
class LoaderArtifact:
    image: bytes
    listing: Path
    entry: int
    limit: int
    checked_int13: int
    code_end: int


def word(image: bytes, offset: int) -> int:
    return int.from_bytes(image[offset : offset + 2], "little")


def fat12_entry(fat: bytes, cluster: int) -> int:
    offset = cluster + cluster // 2
    value = word(fat, offset)
    return (value >> 4) & 0x0FFF if cluster & 1 else value & 0x0FFF


def find_entry(directory: bytes, raw_name: bytes) -> tuple[int, int, int]:
    for offset in range(0, len(directory), 32):
        first = directory[offset]
        if first == 0:
            break
        if first == 0xE5 or directory[offset + 11] & 0x08:
            continue
        if directory[offset : offset + 11] == raw_name:
            return (
                directory[offset + 11],
                word(directory, offset + 26),
                int.from_bytes(directory[offset + 28 : offset + 32], "little"),
            )
    raise AssertionError(f"FAT entry {raw_name!r} not found")


def make_boot_sector() -> bytes:
    boot = bytearray(SECTOR_BYTES)
    boot[:3] = b"\xEB\x3C\x90"
    boot[3:11] = b"SEEDPOC "
    boot[11:13] = SECTOR_BYTES.to_bytes(2, "little")
    boot[13] = 1
    boot[14:16] = RESERVED_SECTORS.to_bytes(2, "little")
    boot[16] = FAT_COUNT
    boot[17:19] = ROOT_ENTRIES.to_bytes(2, "little")
    boot[19:21] = TOTAL_SECTORS.to_bytes(2, "little")
    boot[21] = MEDIA
    boot[22:24] = SECTORS_PER_FAT.to_bytes(2, "little")
    boot[24:26] = SECTORS_PER_TRACK.to_bytes(2, "little")
    boot[26:28] = HEAD_COUNT.to_bytes(2, "little")
    boot[-2:] = b"\x55\xAA"
    return bytes(boot)


def build_fat_fixture(config: bytes, directory: Path, name: str) -> FatFixture:
    directory.mkdir(parents=True, exist_ok=True)
    boot = directory / f"{name}.boot"
    reserved_loader = directory / f"{name}.reserved"
    source = directory / f"{name}.cfg"
    output = directory / f"{name}.img"
    boot.write_bytes(make_boot_sector())
    reserved_loader.write_bytes(b"\xC3")
    source.write_bytes(config)
    subprocess.run(
        [
            sys.executable,
            str(IMAGE_BUILDER),
            "build",
            "--boot",
            str(boot),
            "--loader",
            str(reserved_loader),
            "--loader-sectors",
            "4",
            "--output",
            str(output),
            "--file",
            f"{source}:SEED/USER.CFG",
        ],
        cwd=ROOT,
        check=True,
    )
    image = output.read_bytes()

    reserved = word(image, 14)
    fat_count = image[16]
    root_entries = word(image, 17)
    sectors_per_fat = word(image, 22)
    sectors_per_track = word(image, 24)
    head_count = word(image, 26)
    if (
        reserved != RESERVED_SECTORS
        or fat_count != FAT_COUNT
        or root_entries != ROOT_ENTRIES
        or sectors_per_fat != SECTORS_PER_FAT
        or sectors_per_track != SECTORS_PER_TRACK
        or head_count != HEAD_COUNT
    ):
        raise AssertionError("synthetic FAT12 BPB changed unexpectedly")

    root_sectors = (root_entries * 32 + SECTOR_BYTES - 1) // SECTOR_BYTES
    fat_start = reserved
    root_start = fat_start + fat_count * sectors_per_fat
    data_start = root_start + root_sectors
    fat = image[
        fat_start * SECTOR_BYTES : (fat_start + sectors_per_fat) * SECTOR_BYTES
    ]
    root = image[
        root_start * SECTOR_BYTES : (root_start + root_sectors) * SECTOR_BYTES
    ]
    attr, seed_cluster, _ = find_entry(root, b"SEED       ")
    if not attr & 0x10:
        raise AssertionError("SEED fixture entry is not a directory")
    seed_lba = data_start + seed_cluster - 2
    seed_dir = image[seed_lba * SECTOR_BYTES : (seed_lba + 1) * SECTOR_BYTES]
    attr, first_cluster, file_size = find_entry(seed_dir, b"USER    CFG")
    if attr & 0x10:
        raise AssertionError("USER.CFG fixture entry is a directory")

    clusters: list[int] = []
    cluster = first_cluster
    while True:
        if cluster < 2 or cluster in clusters:
            raise AssertionError("invalid synthetic FAT chain")
        clusters.append(cluster)
        next_cluster = fat12_entry(fat, cluster)
        if next_cluster >= 0xFF8:
            break
        cluster = next_cluster
    absolute_lba = data_start + first_cluster - 2
    sector = image[
        absolute_lba * SECTOR_BYTES : (absolute_lba + 1) * SECTOR_BYTES
    ]
    if file_size != len(config) or sector[: min(file_size, 512)] != config[:512]:
        raise AssertionError("builder-resolved USER.CFG content mismatch")

    cylinder = absolute_lba // (sectors_per_track * head_count)
    remainder = absolute_lba % (sectors_per_track * head_count)
    head = remainder // sectors_per_track
    sector_number = remainder % sectors_per_track + 1
    return FatFixture(
        config=config,
        image=image,
        sector=sector,
        absolute_lba=absolute_lba,
        file_size=file_size,
        cluster_count=len(clusters),
        sectors_per_track=sectors_per_track,
        head_count=head_count,
        cylinder=cylinder,
        head=head,
        sector_number=sector_number,
    )


def assemble_loader(
    fixture: FatFixture,
    directory: Path,
    name: str,
    *,
    file_size: int | None = None,
    cluster_count: int | None = None,
    origin: int = LOADER_ENTRY,
    limit: int = LOADER_LIMIT,
) -> LoaderArtifact:
    binary = directory / f"{name}.bin"
    listing = directory / f"{name}.lst"
    defines = {
        "USER_CFG_FULL_AUTHORIZE_ENTRY": FULL_AUTHORIZE_ENTRY,
        "USER_CFG_AUTH_GENERATION_ADDR": AUTH_GENERATION,
        "USER_CFG_LOADER_ORIGIN": origin,
        "USER_CFG_LOADER_LIMIT": limit,
        "USER_CFG_ABSOLUTE_LBA": fixture.absolute_lba,
        "USER_CFG_FILE_SIZE": fixture.file_size if file_size is None else file_size,
        "USER_CFG_CLUSTER_COUNT": (
            fixture.cluster_count if cluster_count is None else cluster_count
        ),
        "USER_CFG_SECTORS_PER_TRACK": fixture.sectors_per_track,
        "USER_CFG_HEAD_COUNT": fixture.head_count,
        "USER_CFG_DRIVE": 0,
    }
    image = APP.run_nasm(SOURCE, binary, listing, defines=defines)
    if origin + len(image) > limit:
        raise AssertionError("USER.CFG loader exceeds its fixed cold slot")
    header = image.find(b"UCL1")
    if header < 0:
        raise AssertionError("USER.CFG loader header is absent")
    version, declared_size, entry, checked_int13 = struct.unpack_from(
        "<4H", image, header + 4
    )
    if version != 1 or declared_size != len(image) or entry != origin:
        raise AssertionError("USER.CFG loader header mismatch")
    code_end = APP.blob_address(image, b"model ", origin=origin)
    return LoaderArtifact(image, listing, origin, limit, checked_int13, code_end)


class LoaderMachine(APP.Machine):
    def __init__(
        self,
        app_artifacts: APP.Artifacts,
        loader: LoaderArtifact,
        fixture: FatFixture,
        *,
        auth_schedule: tuple[bool, ...] = (),
        disk_mode: str = "success",
    ) -> None:
        self.loader = loader
        self.fixture = fixture
        self.auth_schedule = auth_schedule
        self.disk_mode = disk_mode
        self.authorizations: list[dict[str, int | bool]] = []
        self.bios_calls: list[dict[str, int]] = []
        self.publication_writes: list[tuple[int, int, int]] = []
        self.read_attempts = 0
        super().__init__(app_artifacts, publication_mode="external")
        self.write(loader.entry, loader.image)
        self.write(FULL_AUTHORIZE_ENTRY, b"\xC3")
        self.write(AUTH_GENERATION, APP.TEST_GENERATION.to_bytes(2, "little"))
        self._invalidate(loader.entry, loader.limit)
        self._invalidate(FULL_AUTHORIZE_ENTRY, FULL_AUTHORIZE_ENTRY + 1)

    def _code_hook(
        self, uc: Uc, address: int, size: int, user: object
    ) -> None:
        super()._code_hook(uc, address, size, user)
        if address != FULL_AUTHORIZE_ENTRY:
            return
        registers = {
            "ax": uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
            "bx": uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
            "cx": uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
            "dx": uc.reg_read(UC_X86_REG_DX) & 0xFFFF,
            "si": uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
            "di": uc.reg_read(UC_X86_REG_DI) & 0xFFFF,
        }
        if any(registers.values()):
            raise AssertionError("full-authorize entry received caller authority")
        index = len(self.authorizations)
        allowed = self.auth_schedule[index] if index < len(self.auth_schedule) else True
        self.authorizations.append(
            {
                **registers,
                "allowed": allowed,
                "bios_calls_before": len(self.bios_calls),
            }
        )
        uc.reg_write(UC_X86_REG_AX, 1 if allowed else 0)
        self._set_carry(not allowed)

    def _interrupt_hook(self, uc: Uc, number: int, _user: object) -> None:
        if number != 0x13:
            raise AssertionError(f"unexpected interrupt {number:#x}")
        ax = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        bx = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        cx = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        dx = uc.reg_read(UC_X86_REG_DX) & 0xFFFF
        es = uc.reg_read(UC_X86_REG_ES) & 0xFFFF
        ah, al = ax >> 8, ax & 0xFF
        call = {
            "ah": ah,
            "al": al,
            "bx": bx,
            "cx": cx,
            "dx": dx,
            "es": es,
            "authorization_count": len(self.authorizations),
        }
        self.bios_calls.append(call)
        if ah == 0:
            if al or bx or cx or dx != 0 or es:
                raise AssertionError("INT 13h reset arguments were not fixed")
            self._set_carry(False)
            uc.reg_write(UC_X86_REG_AX, 0)
            return
        if ah != 2 or al != 1 or bx != RAW_SECTOR or es:
            raise AssertionError("INT 13h read arguments were not fixed")
        cylinder = ((cx >> 8) & 0xFF) | ((cx & 0xC0) << 2)
        sector_number = cx & 0x3F
        head = (dx >> 8) & 0xFF
        drive = dx & 0xFF
        lba = (
            (cylinder * self.fixture.head_count + head)
            * self.fixture.sectors_per_track
            + sector_number
            - 1
        )
        if (
            drive != 0
            or lba != self.fixture.absolute_lba
            or cylinder != self.fixture.cylinder
            or head != self.fixture.head
            or sector_number != self.fixture.sector_number
        ):
            raise AssertionError("loader read outside builder-resolved USER.CFG sector")
        self.read_attempts += 1
        fails = self.disk_mode == "permanent_failure" or (
            self.disk_mode == "transient_failure" and self.read_attempts == 1
        )
        if fails:
            uc.reg_write(UC_X86_REG_AX, 0x200)
            self._set_carry(True)
            return
        self.write(RAW_SECTOR, self.fixture.sector)
        uc.reg_write(UC_X86_REG_AX, 1)
        self._set_carry(False)

    def _write_hook(
        self,
        uc: Uc,
        access: int,
        address: int,
        size: int,
        value: int,
        user: object,
    ) -> None:
        super()._write_hook(uc, access, address, size, value, user)
        if (
            self.active_label
            and address < APP.PUBLICATION_END
            and address + size > APP.PUBLICATION_START
        ):
            self.publication_writes.append((address, size, value))


def counter(machine: LoaderMachine, address: int) -> int:
    return word(machine.read(address, 2), 0)


def assert_failure_scrubbed(machine: LoaderMachine) -> None:
    if any(
        machine.read(
            APP.PUBLICATION_START,
            APP.PUBLICATION_END - APP.PUBLICATION_START,
        )
    ):
        raise AssertionError("failed loader retained a partial publication")
    if any(machine.read(RAW_SECTOR, RAW_SECTOR_END - RAW_SECTOR)):
        raise AssertionError("failed loader retained raw sector plaintext")
    if any(machine.read(TEMP_START, TEMP_END - TEMP_START)):
        raise AssertionError("failed loader retained parsed plaintext")
    if any(machine.read(PARSE_STATE, PARSE_STATE_END - PARSE_STATE)):
        raise AssertionError("failed loader retained parser state")


def assert_success(
    machine: LoaderMachine,
    key: bytes,
    model: bytes,
    *,
    transient: bool = False,
) -> None:
    expected = APP.build_publication(key, model=model)
    actual = machine.read(
        APP.PUBLICATION_START,
        APP.PUBLICATION_END - APP.PUBLICATION_START,
    )
    if actual != expected:
        raise AssertionError("loader publication is not byte-exact PAK1")
    if APP.publication_checksum(
        actual[
            APP.PUBLICATION_CHECK_START
            - APP.PUBLICATION_START : APP.PUBLICATION_CHECKSUM_A
            - APP.PUBLICATION_START
        ]
    ) != struct.unpack_from(
        "<2H", actual, APP.PUBLICATION_CHECKSUM_A - APP.PUBLICATION_START
    ):
        raise AssertionError("loader PAK1 checksum mismatch")
    if any(machine.read(APP.PUBLICATION_END, RAW_SECTOR_END - APP.PUBLICATION_END)):
        raise AssertionError("loader retained raw sector plaintext")
    if any(machine.read(TEMP_START, TEMP_END - TEMP_START)):
        raise AssertionError("loader retained parsed plaintext")
    if any(machine.read(PARSE_STATE, PARSE_STATE_END - PARSE_STATE)):
        raise AssertionError("loader retained parser state")
    if not machine.publication_writes:
        raise AssertionError("publication write trace is empty")
    address, size, value = machine.publication_writes[-1]
    if address != APP.PUBLICATION_STATUS or size != 1 or value != 1:
        raise AssertionError("PAK1 status was not the final publication write")
    expected_counts = (3, 2, 1, 0, 4) if transient else (1, 1, 0, 0, 2)
    actual_counts = (
        counter(machine, INT13_TOTAL),
        counter(machine, INT13_READ),
        counter(machine, INT13_RESET),
        counter(machine, INT13_DENIED),
        counter(machine, AUTHORIZE_COUNT),
    )
    if actual_counts != expected_counts:
        raise AssertionError(
            f"loader counters {actual_counts!r} != {expected_counts!r}"
        )
    expected_auth_before = [2, 3, 4] if transient else [2]
    if [call["authorization_count"] for call in machine.bios_calls] != expected_auth_before:
        raise AssertionError("INT 13h did not immediately follow fixed authorization")


def execute_loader(
    app_artifacts: APP.Artifacts,
    loader: LoaderArtifact,
    fixture: FatFixture,
    *,
    label: str,
    expect_success: bool,
    key: bytes = APP.TEST_CREDENTIAL,
    model: bytes = APP.TEST_MODEL,
    auth_schedule: tuple[bool, ...] = (),
    disk_mode: str = "success",
) -> LoaderMachine:
    machine = LoaderMachine(
        app_artifacts,
        loader,
        fixture,
        auth_schedule=auth_schedule,
        disk_mode=disk_mode,
    )
    machine.write(APP.PUBLICATION_START, b"\xA5" * (APP.PUBLICATION_END - APP.PUBLICATION_START))
    machine.write(RAW_SECTOR, b"\xB6" * (RAW_SECTOR_END - RAW_SECTOR))
    machine.write(TEMP_START, b"\xC7" * (TEMP_END - TEMP_START))
    issuer_poison = bytes(
        (0x4D + index * 31) & 0xFF
        for index in range(ISSUER_END - ISSUER_START)
    )
    machine.write(ISSUER_START, issuer_poison)
    machine.call(
        loader.entry,
        label=label,
        expect_success=expect_success,
        expect_ax=1 if expect_success else 0,
    )
    if machine.read(ISSUER_START, len(issuer_poison)) != issuer_poison:
        raise AssertionError("USER.CFG loader changed durable issuer state")
    if expect_success:
        assert_success(machine, key, model, transient=disk_mode == "transient_failure")
    else:
        assert_failure_scrubbed(machine)
    return machine


def static_gate(loader: LoaderArtifact) -> dict[str, object]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    first = next(decoder.disasm(loader.image[:3], loader.entry))
    if (
        first.mnemonic != "jmp"
        or len(first.operands) != 1
        or first.operands[0].type != X86_OP_IMM
    ):
        raise AssertionError("USER.CFG loader entry is not a fixed direct jump")
    start = first.operands[0].imm & 0xFFFF
    instructions = list(
        decoder.disasm(
            loader.image[start - loader.entry : loader.code_end - loader.entry],
            start,
        )
    )
    interrupts: list[int] = []
    calls: list[int] = []
    for instruction in instructions:
        if instruction.mnemonic == "int":
            interrupts.append(instruction.operands[0].imm & 0xFF)
        elif instruction.mnemonic == "call":
            if (
                len(instruction.operands) != 1
                or instruction.operands[0].type != X86_OP_IMM
            ):
                raise AssertionError("USER.CFG loader contains an indirect call")
            calls.append(instruction.operands[0].imm & 0xFFFF)
        elif instruction.mnemonic in {
            "int1",
            "int3",
            "into",
            "in",
            "insb",
            "insw",
            "out",
            "outsb",
            "outsw",
        }:
            raise AssertionError("USER.CFG loader contains unexpected direct I/O")
    if interrupts != [0x13]:
        raise AssertionError(f"USER.CFG loader interrupt set is {interrupts!r}")
    if calls.count(FULL_AUTHORIZE_ENTRY) != 1:
        raise AssertionError("loader does not have one fixed full-authorize call site")
    return {
        "decoded_instructions": len(instructions),
        "interrupts": ["0x13"],
        "full_authorize_call_site": f"{FULL_AUTHORIZE_ENTRY:#06x}",
        "indirect_calls": 0,
    }


def integrated_request_gate(
    app_artifacts: APP.Artifacts,
    loader: LoaderArtifact,
    fixture: FatFixture,
) -> dict[str, object]:
    machine = LoaderMachine(app_artifacts, loader, fixture)
    machine.install_request_phase()
    machine.call(
        app_artifacts.request_entries[0],
        label="integrated_loader_request",
        expect_success=True,
        expect_ax=1,
    )
    plaintext, fragment_lengths = APP.decrypt_request(machine.sent_records)
    body = APP.REQUEST_BODY_PREFIX + APP.TEST_MODEL + APP.REQUEST_BODY_SUFFIX
    expected = (
        APP.REQUEST_PREFIX
        + APP.TEST_CREDENTIAL
        + APP.REQUEST_AFTER_KEY
        + str(len(body)).encode()
        + APP.REQUEST_HEADER_END
        + body
    )
    if plaintext != expected:
        raise AssertionError("loader-to-request bridge changed request bytes")
    if len(machine.unlock_calls) != 1 or any(machine.unlock_calls[0].values()):
        raise AssertionError("request did not invoke loader with zero authority")
    if machine.publication_clear_at_unlock != [True]:
        raise AssertionError("request publication was not empty before loader")
    machine.assert_request_scratch_clear()
    if APP.TEST_CREDENTIAL in machine.read(0, APP.RAM_BYTES):
        raise AssertionError("credential survived integrated request sealing")
    return {
        "sealed_records": len(machine.sent_records),
        "fragment_lengths": fragment_lengths,
        "plaintext_bytes": len(plaintext),
        "fixed_loader_arguments_zero": True,
        "credential_absent_after_send": True,
    }


def run(build_dir: Path) -> dict[str, object]:
    build_dir.mkdir(parents=True, exist_ok=True)
    app_artifacts = APP.build_artifacts(build_dir)
    passed_success: list[str] = []
    passed_hostile: list[str] = []

    with tempfile.TemporaryDirectory(prefix="seed-user-cfg-poc-") as temp_name:
        temp = Path(temp_name)
        canonical_config = (
            b"agent openai\n"
            b"reasoning low\n"
            b"endpoint ignored.example\n"
            b"model "
            + APP.TEST_MODEL
            + b"\nkey "
            + APP.TEST_CREDENTIAL
            + b"\n"
        )
        canonical_fixture = build_fat_fixture(
            canonical_config, temp, "canonical"
        )
        canonical_loader = assemble_loader(
            canonical_fixture, build_dir, "post_auth_user_cfg_loader"
        )
        static_report = static_gate(canonical_loader)
        relocated_loader = assemble_loader(
            canonical_fixture,
            build_dir,
            "post_auth_user_cfg_loader_live_0900",
            origin=0x0900,
            limit=0x0D00,
        )
        relocated_static_report = static_gate(relocated_loader)
        execute_loader(
            app_artifacts,
            relocated_loader,
            canonical_fixture,
            label="user_cfg_live_0900",
            expect_success=True,
        )
        passed_success.append("live_relocated_0x0900")

        positive_cases = {
            "lf_openai": canonical_config,
            "crlf_openai": canonical_config.replace(b"\n", b"\r\n"),
            "agent_absent": (
                b"model " + APP.TEST_MODEL + b"\nkey " + APP.TEST_CREDENTIAL + b"\n"
            ),
            "line_order": (
                b"key "
                + APP.TEST_CREDENTIAL
                + b"\nagent openai\nmodel "
                + APP.TEST_MODEL
                + b"\n"
            ),
            "max_key_model": b"model "
            + b"m" * APP.PUBLICATION_MODEL_MAX
            + b"\nkey "
            + b"K" * APP.PUBLICATION_KEY_MAX
            + b"\n",
        }
        base_512 = (
            b"model " + APP.TEST_MODEL + b"\nkey " + APP.TEST_CREDENTIAL + b"\n"
        )
        positive_cases["exact_512_bytes"] = (
            base_512 + b"x" * (511 - len(base_512)) + b"\n"
        )

        for index, (name, config) in enumerate(positive_cases.items()):
            fixture = build_fat_fixture(config, temp, f"positive-{index}")
            loader = assemble_loader(fixture, temp, f"positive-{index}")
            if name == "max_key_model":
                key, model = b"K" * APP.PUBLICATION_KEY_MAX, b"m" * APP.PUBLICATION_MODEL_MAX
            else:
                key, model = APP.TEST_CREDENTIAL, APP.TEST_MODEL
            execute_loader(
                app_artifacts,
                loader,
                fixture,
                label=f"user_cfg_{name}",
                expect_success=True,
                key=key,
                model=model,
            )
            passed_success.append(name)

        transient = execute_loader(
            app_artifacts,
            canonical_loader,
            canonical_fixture,
            label="user_cfg_transient_read",
            expect_success=True,
            disk_mode="transient_failure",
        )
        if [call["ah"] for call in transient.bios_calls] != [2, 0, 2]:
            raise AssertionError("transient read did not use read/reset/read")
        passed_success.append("transient_read_retry")

        failure_configs = {
            "wrong_agent": canonical_config.replace(b"agent openai", b"agent anthropic"),
            "duplicate_model": canonical_config + b"model duplicate\n",
            "duplicate_key": canonical_config + b"key duplicate\n",
            "duplicate_agent": canonical_config + b"agent openai\n",
            "overlength_model": b"model "
            + b"m" * (APP.PUBLICATION_MODEL_MAX + 1)
            + b"\nkey "
            + APP.TEST_CREDENTIAL
            + b"\n",
            "overlength_key": b"model "
            + APP.TEST_MODEL
            + b"\nkey "
            + b"K" * (APP.PUBLICATION_KEY_MAX + 1)
            + b"\n",
            "empty_model": b"model \nkey " + APP.TEST_CREDENTIAL + b"\n",
            "empty_key": b"model " + APP.TEST_MODEL + b"\nkey \n",
            "missing_model": b"key " + APP.TEST_CREDENTIAL + b"\n",
            "missing_key": b"model " + APP.TEST_MODEL + b"\n",
            "missing_final_newline": canonical_config[:-1],
            "bare_cr": canonical_config.replace(b"model ", b"model ", 1).replace(
                b"\n", b"\r", 1
            ),
            "embedded_nul": canonical_config.replace(b"reasoning", b"reas\x00ning"),
            "embedded_control": canonical_config.replace(
                b"reasoning", b"reas\x1fning"
            ),
        }
        for index, (name, config) in enumerate(failure_configs.items()):
            fixture = build_fat_fixture(config, temp, f"failure-{index}")
            loader = assemble_loader(fixture, temp, f"failure-{index}")
            execute_loader(
                app_artifacts,
                loader,
                fixture,
                label=f"user_cfg_{name}",
                expect_success=False,
            )
            passed_hostile.append(name)

        machine = execute_loader(
            app_artifacts,
            canonical_loader,
            canonical_fixture,
            label="user_cfg_initial_authorization_failure",
            expect_success=False,
            auth_schedule=(False,),
        )
        if machine.bios_calls:
            raise AssertionError("initial authorization failure reached disk")
        passed_hostile.append("initial_authorization_failure")

        machine = execute_loader(
            app_artifacts,
            canonical_loader,
            canonical_fixture,
            label="user_cfg_wrapper_reauthorization_failure",
            expect_success=False,
            auth_schedule=(True, False, False),
        )
        if machine.bios_calls:
            raise AssertionError("wrapper authorization failure reached disk")
        passed_hostile.append("wrapper_reauthorization_failure")

        machine = execute_loader(
            app_artifacts,
            canonical_loader,
            canonical_fixture,
            label="user_cfg_permanent_read_failure",
            expect_success=False,
            disk_mode="permanent_failure",
        )
        if [call["ah"] for call in machine.bios_calls] != [2, 0, 2]:
            raise AssertionError("permanent failure did not use bounded retry")
        passed_hostile.append("permanent_read_failure")

        invalid_layouts = (
            ("multi_cluster_descriptor", None, 2),
            ("size_over_sector", 513, 1),
            ("zero_size", 0, 1),
        )
        for name, size_override, cluster_override in invalid_layouts:
            loader = assemble_loader(
                canonical_fixture,
                temp,
                name,
                file_size=size_override,
                cluster_count=cluster_override,
            )
            machine = execute_loader(
                app_artifacts,
                loader,
                canonical_fixture,
                label=f"user_cfg_{name}",
                expect_success=False,
            )
            if machine.bios_calls:
                raise AssertionError(f"{name} reached disk")
            passed_hostile.append(name)

        wrapper_machine = LoaderMachine(
            app_artifacts, canonical_loader, canonical_fixture
        )
        wrapper_machine.call(
            canonical_loader.checked_int13,
            label="user_cfg_unsupported_int13",
            ax=0x0300,
            expect_success=False,
            expect_ax=0x0300,
        )
        if wrapper_machine.bios_calls:
            raise AssertionError("unsupported wrapper operation reached INT 13h")
        if counter(wrapper_machine, INT13_DENIED) != 1:
            raise AssertionError("unsupported wrapper operation was not counted")
        passed_hostile.append("unsupported_int13_operation")

        integration = integrated_request_gate(
            app_artifacts, canonical_loader, canonical_fixture
        )

        source_and_image = SOURCE.read_bytes() + canonical_loader.image
        if APP.TEST_CREDENTIAL in source_and_image or APP.TEST_MODEL in canonical_loader.image:
            raise AssertionError("fixture key/model leaked into loader source/image")

        canonical_binary = build_dir / "post_auth_user_cfg_loader.bin"
        return {
            "status": "PASS",
            "profile": "cpu-8086 fixed read-only post-auth USER.CFG loader",
            "layout": {
                "loader_bytes": len(canonical_loader.image),
                "loader_slot": "0x0520..0x0900",
                "loader_headroom_bytes": canonical_loader.limit
                - canonical_loader.entry
                - len(canonical_loader.image),
                "send_callback": f"{APP.SEND_CALLBACK:#06x}",
                "raw_sector": "0x0e00..0x1000",
                "temporary_fields": f"{TEMP_START:#06x}..{TEMP_END:#06x}",
                "publication": (
                    f"{APP.PUBLICATION_START:#06x}..{APP.PUBLICATION_END:#06x}"
                ),
            },
            "builder_resolved_fixture": {
                "absolute_lba": canonical_fixture.absolute_lba,
                "file_size": canonical_fixture.file_size,
                "cluster_count": canonical_fixture.cluster_count,
                "chs": [
                    canonical_fixture.cylinder,
                    canonical_fixture.head,
                    canonical_fixture.sector_number,
                ],
                "geometry": [
                    canonical_fixture.sectors_per_track,
                    canonical_fixture.head_count,
                ],
            },
            "success_cases": passed_success,
            "hostile_cases": passed_hostile,
            "static_gate": static_report,
            "live_relocated_gate": {
                **relocated_static_report,
                "entry": "0x0900",
                "slot": "0x0900..0x0d00",
                "executes_byte_exact_pak1": True,
            },
            "integrated_request": integration,
            "policy": {
                "fixed_full_authorize_before_io": True,
                "checked_int13_operations": ["reset", "one_sector_read"],
                "builder_resolved_single_sector_only": True,
                "fixed_openai_route": True,
                "status_last_publication": True,
                "failure_scrub": True,
                "durable_issuer_0x3600_0x3673_preserved": True,
                "real_user_config_opened": False,
            },
            "sha256": {
                "loader": hashlib.sha256(canonical_binary.read_bytes()).hexdigest(),
                "source": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            },
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=ROOT / "build/crypto-bench/tls13-post-auth-request",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "post_auth_user_cfg_loader_results.json",
    )
    args = parser.parse_args()
    result = run(args.build_dir)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
