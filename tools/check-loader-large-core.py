#!/usr/bin/env python3
"""Regression-gate the real FAT12 loader's 32-bit SEED.SYS size handling.

The loader is assembled from targets/ibm_pc_5150/boot/loader.asm, installed at
its real 0000:0600 address, and run in Unicorn.  INT 13h reads are served from a
deterministic synthetic 160 KiB FAT12 image.

This checks both sides of the loader contract:

* A SEED.SYS larger than 64 KiB with a four-sector resident prefix boots after
  reading exactly those four data sectors.
* A stack-safe SEED.SYS whose header declares a resident extent larger than its
  sector-rounded directory size reaches the normal "seed load error" path.
* A partially occupied final resident sector retains the baseline loader
  contract and reaches the entry point.
* A large file whose nominally in-file resident extent reaches the loader stack
  is rejected from its header before a second data-sector read.
* The maximum safe 55-sector resident prefix still loads and reaches its entry
  point, so the stack guard is not an accidental off-by-one reduction.
"""

from __future__ import annotations

import math
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

try:
    from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INTR, UC_MODE_16, Uc
    from unicorn.x86_const import (
        UC_X86_REG_AX,
        UC_X86_REG_BX,
        UC_X86_REG_CH,
        UC_X86_REG_CL,
        UC_X86_REG_CS,
        UC_X86_REG_DH,
        UC_X86_REG_DL,
        UC_X86_REG_DS,
        UC_X86_REG_ES,
        UC_X86_REG_FLAGS,
        UC_X86_REG_IP,
        UC_X86_REG_SP,
        UC_X86_REG_SS,
    )
except ImportError as exc:
    raise SystemExit("error: Unicorn is required (python3 -m pip install unicorn)") from exc


ROOT = Path(__file__).resolve().parents[1]
LOADER_SOURCE = ROOT / "targets" / "ibm_pc_5150" / "boot" / "loader.asm"

SECTOR_SIZE = 512
TOTAL_SECTORS = 320
LOADER_SECTORS = 4
SECTORS_PER_TRACK = 8
HEADS = 1
FAT_START_LBA = 1 + LOADER_SECTORS
ROOT_START_LBA = FAT_START_LBA + 2
ROOT_SECTORS = 4
DATA_START_LBA = ROOT_START_LBA + ROOT_SECTORS

LOADER_ADDR = 0x0600
CORE_ADDR = 0x1000
LOADER_STACK_TOP = 0x8000
MEM_SIZE = 0x10000
UNTOUCHED = 0xA5


def set_fat12_entry(fat: bytearray, cluster: int, value: int) -> None:
    offset = cluster + cluster // 2
    value &= 0x0FFF
    if cluster & 1:
        fat[offset] = (fat[offset] & 0x0F) | ((value << 4) & 0xF0)
        fat[offset + 1] = (value >> 4) & 0xFF
    else:
        fat[offset] = value & 0xFF
        fat[offset + 1] = (fat[offset + 1] & 0xF0) | ((value >> 8) & 0x0F)


def make_core(file_size: int, resident_sectors: int) -> bytes:
    if file_size < 23:
        raise ValueError("test core is too small for the SEEDCORE header")

    core = bytearray(((index * 73) + 19) & 0xFF for index in range(file_size))
    core[0:3] = b"\xEB\x15\x90"
    core[3:11] = b"SEEDCORE"
    core[11] = 1
    core[12] = 0
    core[13:15] = (23).to_bytes(2, "little")
    core[15:17] = resident_sectors.to_bytes(2, "little")
    core[17:19] = math.ceil(file_size / SECTOR_SIZE).to_bytes(2, "little")
    core[19:23] = b"\x00\x00\x00\x00"
    return bytes(core)


def make_fat12_image(loader: bytes, core: bytes) -> bytes:
    image = bytearray(TOTAL_SECTORS * SECTOR_SIZE)
    image[510:512] = b"\x55\xAA"
    image[SECTOR_SIZE:SECTOR_SIZE + len(loader)] = loader

    cluster_count = math.ceil(len(core) / SECTOR_SIZE)
    first_cluster = 2
    last_cluster = first_cluster + cluster_count - 1
    if DATA_START_LBA + cluster_count > TOTAL_SECTORS:
        raise ValueError("test core does not fit the synthetic FAT12 image")

    fat = bytearray(SECTOR_SIZE)
    fat[0:3] = b"\xFC\xFF\xFF"
    for cluster in range(first_cluster, last_cluster + 1):
        set_fat12_entry(fat, cluster, 0xFFF if cluster == last_cluster else cluster + 1)
    for copy in range(2):
        start = (FAT_START_LBA + copy) * SECTOR_SIZE
        image[start:start + SECTOR_SIZE] = fat

    root = ROOT_START_LBA * SECTOR_SIZE
    image[root:root + 11] = b"SEED    SYS"
    image[root + 11] = 0x20
    image[root + 26:root + 28] = first_cluster.to_bytes(2, "little")
    image[root + 28:root + 32] = len(core).to_bytes(4, "little")

    data = DATA_START_LBA * SECTOR_SIZE
    image[data:data + len(core)] = core
    return bytes(image)


def assemble_loader() -> bytes:
    with tempfile.TemporaryDirectory() as temp_dir:
        output = Path(temp_dir) / "loader.bin"
        result = subprocess.run(
            [
                "nasm",
                f"-DLOADER_SECTORS={LOADER_SECTORS}",
                "-f",
                "bin",
                "-o",
                str(output),
                str(LOADER_SOURCE),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise RuntimeError(f"nasm failed:\n{result.stderr}")
        loader = output.read_bytes()

    expected_size = LOADER_SECTORS * SECTOR_SIZE
    if len(loader) != expected_size:
        raise AssertionError(f"loader is {len(loader)} bytes, expected {expected_size}")
    return loader


@dataclass
class RunResult:
    disk_reads: list[int] = field(default_factory=list)
    tty: bytearray = field(default_factory=bytearray)
    reached_core: bool = False
    halted: bool = False
    memory: bytes = b""


def run_loader(loader: bytes, image: bytes) -> RunResult:
    result = RunResult()
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, MEM_SIZE)
    uc.mem_write(LOADER_ADDR, loader)
    uc.mem_write(
        CORE_ADDR,
        bytes([UNTOUCHED]) * (LOADER_STACK_TOP - CORE_ADDR),
    )

    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        uc.reg_write(register, 0)
    uc.reg_write(UC_X86_REG_IP, LOADER_ADDR)
    uc.reg_write(UC_X86_REG_SP, 0x8000)
    uc.reg_write(UC_X86_REG_DL, 0)
    uc.reg_write(UC_X86_REG_FLAGS, 0x0002)

    def interrupt_hook(machine: Uc, interrupt: int, _user_data: object) -> None:
        if interrupt == 0x12:
            machine.reg_write(UC_X86_REG_AX, 32)
            return

        if interrupt == 0x10:
            result.tty.append(machine.reg_read(UC_X86_REG_AX) & 0xFF)
            return

        if interrupt != 0x13:
            raise AssertionError(f"unexpected BIOS interrupt 0x{interrupt:02x}")

        ax = machine.reg_read(UC_X86_REG_AX)
        if (ax >> 8, ax & 0xFF) != (0x02, 0x01):
            raise AssertionError(f"unexpected INT 13h request AX=0x{ax:04x}")

        cylinder = machine.reg_read(UC_X86_REG_CH)
        sector = machine.reg_read(UC_X86_REG_CL) & 0x3F
        head = machine.reg_read(UC_X86_REG_DH)
        drive = machine.reg_read(UC_X86_REG_DL)
        if drive != 0 or sector == 0 or head >= HEADS:
            raise AssertionError(
                f"invalid CHS request C={cylinder} H={head} S={sector} drive={drive}"
            )

        lba = ((cylinder * HEADS) + head) * SECTORS_PER_TRACK + sector - 1
        start = lba * SECTOR_SIZE
        end = start + SECTOR_SIZE
        if end > len(image):
            raise AssertionError(f"loader read beyond image at LBA {lba}")

        destination = (machine.reg_read(UC_X86_REG_ES) << 4) + machine.reg_read(UC_X86_REG_BX)
        machine.mem_write(destination, image[start:end])
        machine.reg_write(UC_X86_REG_FLAGS, machine.reg_read(UC_X86_REG_FLAGS) & ~1)
        result.disk_reads.append(lba)

    def code_hook(machine: Uc, address: int, _size: int, _user_data: object) -> None:
        if address == CORE_ADDR:
            result.reached_core = True
            machine.emu_stop()
            return
        if machine.mem_read(address, 1) == b"\xF4":
            result.halted = True
            machine.emu_stop()

    uc.hook_add(UC_HOOK_INTR, interrupt_hook)
    uc.hook_add(UC_HOOK_CODE, code_hook)
    uc.emu_start(LOADER_ADDR, MEM_SIZE - 1, count=200_000)
    result.memory = bytes(
        uc.mem_read(CORE_ADDR, LOADER_STACK_TOP - CORE_ADDR)
    )
    return result


def check_large_file_loads_resident_prefix(loader: bytes) -> tuple[int, RunResult]:
    file_size = 70_000
    resident_sectors = 4
    core = make_core(file_size, resident_sectors)
    result = run_loader(loader, make_fat12_image(loader, core))

    expected_reads = [
        ROOT_START_LBA,
        FAT_START_LBA,
        *range(DATA_START_LBA, DATA_START_LBA + resident_sectors),
    ]
    assert result.reached_core, "large valid SEED.SYS did not reach its entry point"
    assert not result.halted, "large valid SEED.SYS entered the loader failure halt"
    assert result.tty == b"", f"large valid SEED.SYS printed an error: {result.tty!r}"
    assert result.disk_reads == expected_reads, (
        f"loader reads {result.disk_reads}, expected resident-only reads {expected_reads}"
    )

    resident_bytes = resident_sectors * SECTOR_SIZE
    assert result.memory[:resident_bytes] == core[:resident_bytes], (
        "loaded resident prefix differs from SEED.SYS"
    )
    assert result.memory[resident_bytes:resident_bytes + SECTOR_SIZE] == (
        bytes([UNTOUCHED]) * SECTOR_SIZE
    ), "loader overwrote the first cold-tail destination sector"
    return file_size, result


def check_oversized_resident_extent_fails(loader: bytes) -> tuple[int, int, RunResult]:
    resident_sectors = 4
    file_size = (resident_sectors - 1) * SECTOR_SIZE
    assert resident_sectors <= 55
    assert math.ceil(file_size / SECTOR_SIZE) < resident_sectors
    core = make_core(file_size, resident_sectors)
    result = run_loader(loader, make_fat12_image(loader, core))

    expected_reads = [ROOT_START_LBA, FAT_START_LBA, DATA_START_LBA]
    assert not result.reached_core, "invalid resident extent reached the core entry point"
    assert result.halted, "invalid resident extent did not enter the loader failure halt"
    assert result.tty == b"seed load error", (
        f"invalid resident extent produced {result.tty!r}, expected b'seed load error'"
    )
    assert result.disk_reads == expected_reads, (
        f"invalid resident extent reads {result.disk_reads}, expected header-only {expected_reads}"
    )
    assert result.memory[SECTOR_SIZE:2 * SECTOR_SIZE] == bytes([UNTOUCHED]) * SECTOR_SIZE, (
        "loader continued reading after rejecting the resident extent"
    )
    return file_size, resident_sectors, result


def check_partial_final_resident_sector_loads(
    loader: bytes,
) -> tuple[int, int, RunResult]:
    resident_sectors = 4
    file_size = resident_sectors * SECTOR_SIZE - 1
    assert math.ceil(file_size / SECTOR_SIZE) == resident_sectors
    core = make_core(file_size, resident_sectors)
    result = run_loader(loader, make_fat12_image(loader, core))

    expected_reads = [
        ROOT_START_LBA,
        FAT_START_LBA,
        *range(DATA_START_LBA, DATA_START_LBA + resident_sectors),
    ]
    assert result.reached_core, "partial final resident sector did not reach the core"
    assert not result.halted, "partial final resident sector entered the failure halt"
    assert result.tty == b"", (
        f"partial final resident sector printed an error: {result.tty!r}"
    )
    assert result.disk_reads == expected_reads, (
        f"partial final resident reads {result.disk_reads}, expected {expected_reads}"
    )
    assert result.memory[:file_size] == core, (
        "partial final resident file bytes differ from SEED.SYS"
    )
    assert result.memory[file_size:resident_sectors * SECTOR_SIZE] == b"\x00", (
        "partial final resident sector padding is not the FAT image's zero fill"
    )
    return file_size, resident_sectors, result


def check_stack_collision_resident_extent_fails(
    loader: bytes,
) -> tuple[int, int, RunResult]:
    file_size = 70_000
    resident_sectors = (LOADER_STACK_TOP - CORE_ADDR) // SECTOR_SIZE
    assert resident_sectors * SECTOR_SIZE <= file_size
    core = make_core(file_size, resident_sectors)
    result = run_loader(loader, make_fat12_image(loader, core))

    expected_reads = [ROOT_START_LBA, FAT_START_LBA, DATA_START_LBA]
    assert not result.reached_core, "stack-colliding resident extent reached the core"
    assert result.halted, "stack-colliding resident extent did not enter the failure halt"
    assert result.tty == b"seed load error", (
        f"stack-colliding resident extent produced {result.tty!r}, "
        "expected b'seed load error'"
    )
    assert result.disk_reads == expected_reads, (
        f"stack-colliding extent reads {result.disk_reads}, "
        f"expected header-only {expected_reads}"
    )
    assert result.memory[SECTOR_SIZE:2 * SECTOR_SIZE] == (
        bytes([UNTOUCHED]) * SECTOR_SIZE
    ), "loader continued reading after rejecting the stack-colliding extent"
    return file_size, resident_sectors, result


def check_max_safe_resident_extent_loads(
    loader: bytes,
) -> tuple[int, int, RunResult]:
    file_size = 70_000
    resident_sectors = (
        LOADER_STACK_TOP - SECTOR_SIZE - CORE_ADDR
    ) // SECTOR_SIZE
    assert resident_sectors == 55
    core = make_core(file_size, resident_sectors)
    result = run_loader(loader, make_fat12_image(loader, core))

    expected_reads = [
        ROOT_START_LBA,
        FAT_START_LBA,
        *range(DATA_START_LBA, DATA_START_LBA + resident_sectors),
    ]
    assert result.reached_core, "maximum safe resident extent did not reach the core"
    assert not result.halted, "maximum safe resident extent entered the failure halt"
    assert result.tty == b"", (
        f"maximum safe resident extent printed an error: {result.tty!r}"
    )
    assert result.disk_reads == expected_reads, (
        f"maximum safe extent reads {result.disk_reads}, expected {expected_reads}"
    )
    resident_bytes = resident_sectors * SECTOR_SIZE
    assert result.memory[:resident_bytes] == core[:resident_bytes], (
        "maximum safe resident prefix differs from SEED.SYS"
    )
    return file_size, resident_sectors, result


def main() -> None:
    loader = assemble_loader()
    valid_size, valid = check_large_file_loads_resident_prefix(loader)
    invalid_size, invalid_resident, invalid = check_oversized_resident_extent_fails(loader)
    partial_size, partial_resident, partial = (
        check_partial_final_resident_sector_loads(loader)
    )
    stack_size, stack_resident, stack_invalid = (
        check_stack_collision_resident_extent_fails(loader)
    )
    safe_size, safe_resident, safe = check_max_safe_resident_extent_loads(loader)

    print("loader large-core regression gate: PASS")
    print(
        f"  accepted {valid_size}-byte SEED.SYS; "
        f"read data LBAs {valid.disk_reads[2:]} and left its cold tail untouched"
    )
    print(
        f"  rejected {invalid_resident}-sector resident extent in "
        f"{invalid_size}-byte SEED.SYS because its rounded file is smaller"
    )
    print(
        f"  accepted partial {partial_size}-byte extent across "
        f"{partial_resident} resident sectors through data LBA "
        f"{partial.disk_reads[-1]}"
    )
    print(
        f"  rejected stack-colliding {stack_resident}-sector resident extent in "
        f"{stack_size}-byte SEED.SYS after data LBAs {stack_invalid.disk_reads[2:]}"
    )
    print(
        f"  accepted maximum safe {safe_resident}-sector resident extent in "
        f"{safe_size}-byte SEED.SYS through data LBA {safe.disk_reads[-1]}"
    )


if __name__ == "__main__":
    main()
