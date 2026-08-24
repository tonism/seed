#!/usr/bin/env python3
"""Execute the offline RAM-only acquisition/resumption lifecycle."""

from __future__ import annotations

import hashlib
import struct
import subprocess
import tempfile
from pathlib import Path

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_INTR,
    UC_MODE_16,
    Uc,
)
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_AX,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "system_ram_lifecycle_controller.asm"
READY_SOURCE = HERE / "system_ram_resume_ready_controller.asm"
ORIGIN = 0x0900
READY_ORIGIN = 0x0F00
RETURN = 0x0480
STACK_TOP = 0x4000
CAPSULE_LOW = 0x0700
CAPSULE_HIGH = 0x3400
CAPSULE_LEN = 440
ABORT = (0x35C0, 0x3600)
CONFIG = (0x3B9C, 0x3C9C)
FO_SELECTED = 0x3A60
PSK_HOLD = 0x0DC0

RESUMPTION_C = (
    (0x3400, 272),
    (0x3640, 13),
    (0x3B40, 80),
    (0x355D, 99),
    (0x0500, 256),
    (0x33F8, 8),
    (0x08B8, 72),
    (0x0DE0, 288),
)
KEYGEN_C = (
    (0x3400, 448),
    (0x0500, 256),
    (0x0D60, 96),
    (0x0DE0, 288),
)

SYM_ROOT = 0x3600
SYM_PROVISIONAL = 0x3620
SYM_CLIENT_KEY = 0x3838
SYM_CLIENT_IV = 0x3858
SYM_SERVER_KEY = 0x3864
SYM_SERVER_IV = 0x3884
SYM_CLIENT_SEQ = 0x38E0
SYM_SERVER_SEQ = 0x38E8


def deterministic(label: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"Seed RAM lifecycle|" + label).digest(length)


def assemble(directory: Path) -> tuple[bytes, tuple[int, ...], bytes]:
    image_path = directory / "lifecycle.bin"
    ready_path = directory / "ready.bin"
    subprocess.run(
        ("nasm", "-f", "bin", "-o", str(image_path), str(SOURCE)),
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        ("nasm", "-f", "bin", "-o", str(ready_path), str(READY_SOURCE)),
        cwd=ROOT,
        check=True,
    )
    image = image_path.read_bytes()
    ready = ready_path.read_bytes()
    if image[:4] != b"SRL1":
        raise AssertionError("lifecycle header magic changed")
    version, size, count = struct.unpack_from("<3H", image, 4)
    if version != 1 or size != len(image) or count != 4:
        raise AssertionError("lifecycle header changed")
    entries = struct.unpack_from("<4H", image, 10)
    if not all(ORIGIN <= entry < ORIGIN + len(image) for entry in entries):
        raise AssertionError("lifecycle entry escaped its image")
    if len(image) > 0x400 or len(ready) > 0x0FE2 - READY_ORIGIN:
        raise AssertionError("RAM lifecycle phase exceeds its low-memory slot")
    return image, entries, ready


def new_machine(image: bytes) -> Uc:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, deterministic(b"initial RAM", 0x10000))
    machine.mem_write(ORIGIN, image)

    def reject_interrupt(_uc: Uc, number: int, _user: object) -> None:
        raise AssertionError(f"lifecycle issued BIOS interrupt {number:#x}")

    def reject_in(_uc: Uc, port: int, size: int, _user: object) -> int:
        raise AssertionError(f"lifecycle read I/O port {port:#x}/{size}")

    def reject_out(_uc: Uc, port: int, size: int, value: int, _user: object) -> None:
        raise AssertionError(f"lifecycle wrote I/O port {port:#x}/{size}={value:#x}")

    machine.hook_add(UC_HOOK_INTR, reject_interrupt)
    machine.hook_add(UC_HOOK_INSN, reject_in, None, 1, 0, UC_X86_INS_IN)
    machine.hook_add(UC_HOOK_INSN, reject_out, None, 1, 0, UC_X86_INS_OUT)
    return machine


def invoke(machine: Uc, entry: int, *, ax: int = 0, dx: int = 0) -> bool:
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_AX, ax)
    machine.reg_write(UC_X86_REG_DX, dx)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))
    returned = False

    def stop(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    hook = machine.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
    machine.emu_start(entry, 0, count=3_000_000)
    machine.hook_del(hook)
    if not returned or machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("lifecycle did not return with a balanced stack")
    if machine.reg_read(UC_X86_REG_EFLAGS) & (1 << 10):
        raise AssertionError("lifecycle returned with DF set")
    return bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1)


def scatter(machine: Uc, value: bytes, segments: tuple[tuple[int, int], ...]) -> None:
    offset = 0
    for address, length in segments:
        machine.mem_write(address, value[offset : offset + length])
        offset += length
    if offset != len(value):
        raise AssertionError("test scatter length changed")


def gather(machine: Uc, segments: tuple[tuple[int, int], ...]) -> bytes:
    return b"".join(
        bytes(machine.mem_read(address, length)) for address, length in segments
    )


def acquisition_capsule() -> tuple[bytes, dict[str, bytes]]:
    fields = {
        "root": deterministic(b"root", 32),
        "provisional": deterministic(b"acquisition provisional", 32),
        "digest": deterministic(b"CV digest", 32),
        "signature": deterministic(b"CV signature", 72),
        "psk": deterministic(b"ticket PSK", 32),
        "identity": deterministic(b"ticket identity", 192),
        "nonce": deterministic(b"ticket nonce", 32),
    }
    capsule = bytearray(CAPSULE_LEN)
    capsule[0:32] = fields["root"]
    capsule[32:64] = fields["provisional"]
    capsule[64:96] = fields["digest"]
    capsule[96:98] = struct.pack("<H", len(fields["signature"]))
    capsule[98:170] = fields["signature"]
    capsule[170] = 1
    capsule[171:203] = fields["psk"]
    capsule[203:395] = fields["identity"]
    capsule[395:427] = fields["nonce"]
    capsule[427:439] = (
        b"\x00\x00\x20\xfd"
        + b"\x10\x20\x30\x40"
        + struct.pack("<HH", 32, len(fields["identity"]))
    )
    capsule[439] = 2
    return bytes(capsule), fields


def install_guards(machine: Uc) -> dict[str, tuple[int, bytes]]:
    guards = {
        "abort": (ABORT[0], deterministic(b"abort", ABORT[1] - ABORT[0])),
        "config": (CONFIG[0], deterministic(b"config", CONFIG[1] - CONFIG[0])),
        "video": (0xB000, deterministic(b"video", 0x1000)),
        "NIC/card RAM": (0xD000, deterministic(b"NIC", 0x1000)),
    }
    for address, value in guards.values():
        machine.mem_write(address, value)
    return guards


def assert_guards(machine: Uc, guards: dict[str, tuple[int, bytes]]) -> None:
    for name, (address, expected) in guards.items():
        if bytes(machine.mem_read(address, len(expected))) != expected:
            raise AssertionError(f"lifecycle changed {name}")


def check_acquisition_prepare(
    image: bytes, entries: tuple[int, ...], ready: bytes
) -> None:
    capsule, fields = acquisition_capsule()
    age = b"\x10\x20\x30\x40"
    age_ax, age_dx = struct.unpack("<HH", age)
    machine = new_machine(image)
    machine.mem_write(CAPSULE_HIGH, capsule)
    machine.mem_write(FO_SELECTED, fields["provisional"])
    guards = install_guards(machine)
    if invoke(machine, entries[0], ax=age_ax, dx=age_dx):
        raise AssertionError("valid acquisition capsule was rejected")
    if bytes(machine.mem_read(CAPSULE_HIGH, 32)) != fields["root"]:
        raise AssertionError("acquisition preparation changed the entropy root")
    if bytes(machine.mem_read(0x3420, 64)) != bytes(64):
        raise AssertionError("acquisition preparation did not reserve nonce outputs")
    if bytes(machine.mem_read(0x3460, 32)) != fields["psk"]:
        raise AssertionError("acquisition preparation copied the wrong PSK")
    if bytes(machine.mem_read(0x3480, 4)) != age:
        raise AssertionError("acquisition preparation copied the wrong ticket age")
    if bytes(machine.mem_read(0x3484, 2)) != struct.pack("<H", 192):
        raise AssertionError("acquisition preparation copied the wrong identity length")
    if bytes(machine.mem_read(0x3486, 192)) != fields["identity"]:
        raise AssertionError("acquisition preparation copied the wrong identity")
    if bytes(machine.mem_read(0x3546, ABORT[0] - 0x3546)) != bytes(ABORT[0] - 0x3546):
        raise AssertionError("acquisition preparation retained dead capsule bytes")
    if bytes(machine.mem_read(0x3A40, 128)) != bytes(128):
        raise AssertionError("acquisition preparation retained FO candidate state")
    assert_guards(machine, guards)

    # KeyGen fills the two epoch-1 nonce fields, then the resident ready tail
    # publishes the bounded identity into HELLO's decoded-polynomial sector.
    random_session = deterministic(b"epoch-1 random/session", 64)
    machine.mem_write(0x3420, random_session)
    machine.mem_write(READY_ORIGIN, ready)
    if invoke(machine, READY_ORIGIN):
        raise AssertionError("valid resumption identity was rejected")
    if bytes(machine.mem_read(0x3000, 192)) != fields["identity"]:
        raise AssertionError("resume-ready tail published the wrong identity")
    if bytes(machine.mem_read(0x3486, 192)) != bytes(192):
        raise AssertionError("resume-ready tail retained the staged identity")
    if bytes(machine.mem_read(0x3420, 64)) != random_session:
        raise AssertionError("resume-ready tail changed KeyGen nonce output")
    assert_guards(machine, guards)

    rejected = new_machine(image)
    rejected.mem_write(CAPSULE_HIGH, capsule)
    rejected.mem_write(FO_SELECTED, bytes((fields["provisional"][0] ^ 1,)) + fields["provisional"][1:])
    before = bytes(rejected.mem_read(CAPSULE_HIGH, 0x6C0))
    if not invoke(rejected, entries[0], ax=age_ax, dx=age_dx):
        raise AssertionError("mismatched acquisition FO was accepted")
    if bytes(rejected.mem_read(CAPSULE_HIGH, 0x6C0)) != before:
        raise AssertionError("rejected acquisition preparation changed high state")


def check_resumption_regeneration(image: bytes, entries: tuple[int, ...]) -> None:
    machine = new_machine(image)
    ciphertext = deterministic(b"resumption ciphertext", 1088)
    scatter(machine, ciphertext, RESUMPTION_C)
    state = {
        "root": deterministic(b"resumption root", 32),
        "provisional": deterministic(b"resumption provisional", 32),
        "client_key": deterministic(b"client key", 32),
        "client_iv": deterministic(b"client iv", 12),
        "client_seq": struct.pack("<Q", 1),
        "server_key": deterministic(b"server key", 32),
        "server_iv": deterministic(b"server iv", 12),
        "server_seq": struct.pack("<Q", 0),
    }
    for address, value in (
        (SYM_ROOT, state["root"]),
        (SYM_PROVISIONAL, state["provisional"]),
        (SYM_CLIENT_KEY, state["client_key"]),
        (SYM_CLIENT_IV, state["client_iv"]),
        (SYM_CLIENT_SEQ, state["client_seq"]),
        (SYM_SERVER_KEY, state["server_key"]),
        (SYM_SERVER_IV, state["server_iv"]),
        (SYM_SERVER_SEQ, state["server_seq"]),
    ):
        machine.mem_write(address, value)
    guards = install_guards(machine)
    if invoke(machine, entries[1]):
        raise AssertionError("valid resumption state was rejected")
    expected = bytearray(CAPSULE_LEN)
    expected[0:32] = state["root"]
    expected[32:64] = state["provisional"]
    expected[64:96] = state["client_key"]
    expected[96:108] = state["client_iv"]
    expected[108:116] = state["client_seq"]
    expected[116:148] = state["server_key"]
    expected[148:160] = state["server_iv"]
    expected[160:168] = state["server_seq"]
    expected[168:170] = b"\x5a\xa5"
    if bytes(machine.mem_read(CAPSULE_LOW, CAPSULE_LEN)) != bytes(expected):
        raise AssertionError("resumption regeneration packed the wrong capsule")
    if gather(machine, KEYGEN_C) != ciphertext:
        raise AssertionError("resumption regeneration changed logical ciphertext")
    if bytes(machine.mem_read(SYM_ROOT, CONFIG[0] - SYM_ROOT)) != bytes(CONFIG[0] - SYM_ROOT):
        raise AssertionError("resumption regeneration retained old symmetric state")
    if bytes(machine.mem_read(0x08B8, 72)) != bytes(72):
        raise AssertionError("resumption regeneration retained the old c overlap")
    assert_guards(machine, guards)

    # Model the existing generic to-FO transition, then validate the selected
    # FO secret and restore application state after sym_init clears high RAM.
    machine.mem_write(CAPSULE_HIGH, bytes(expected))
    machine.mem_write(FO_SELECTED, state["provisional"])
    if invoke(machine, entries[2]):
        raise AssertionError("valid resumption FO was rejected")
    if bytes(machine.mem_read(CAPSULE_HIGH + 168, 2)) != b"\x3c\xc3":
        raise AssertionError("resumption FO did not publish validation status-last")
    machine.mem_write(0x3600, bytes(0x3B37 - 0x3600))
    machine.mem_write(PSK_HOLD, deterministic(b"retired PSK", 32))
    if invoke(machine, entries[3]):
        raise AssertionError("validated application capsule was not restored")
    for name, address in (
        ("client_key", SYM_CLIENT_KEY),
        ("client_iv", SYM_CLIENT_IV),
        ("client_seq", SYM_CLIENT_SEQ),
        ("server_key", SYM_SERVER_KEY),
        ("server_iv", SYM_SERVER_IV),
        ("server_seq", SYM_SERVER_SEQ),
    ):
        if bytes(machine.mem_read(address, len(state[name]))) != state[name]:
            raise AssertionError(f"resumption restore changed {name}")
    if bytes(machine.mem_read(CAPSULE_HIGH, ABORT[0] - CAPSULE_HIGH)) != bytes(ABORT[0] - CAPSULE_HIGH):
        raise AssertionError("resumption restore retained its high capsule")
    if bytes(machine.mem_read(PSK_HOLD, 32)) != bytes(32):
        raise AssertionError("resumption restore retained the ticket PSK")
    assert_guards(machine, guards)

    rejected = new_machine(image)
    rejected.mem_write(CAPSULE_HIGH, bytes(expected))
    rejected.mem_write(FO_SELECTED, bytes((state["provisional"][0] ^ 1,)) + state["provisional"][1:])
    if not invoke(rejected, entries[2]):
        raise AssertionError("mismatched resumption FO was accepted")
    if bytes(rejected.mem_read(CAPSULE_HIGH + 168, 2)) != b"\x5a\xa5":
        raise AssertionError("rejected resumption FO published validation")


def main() -> int:
    for path in (SOURCE, READY_SOURCE):
        source = path.read_text(encoding="utf-8").lower()
        if "cpu 8086" not in source or "int 0x13" in source:
            raise AssertionError(f"{path.name} lost its 8086/no-disk boundary")
    with tempfile.TemporaryDirectory(prefix="seed-system-lifecycle-") as raw:
        image, entries, ready = assemble(Path(raw))
    check_acquisition_prepare(image, entries, ready)
    check_resumption_regeneration(image, entries)
    print("TLS 1.3 system-RAM acquisition/resumption lifecycle: PASS")
    print(f"  offline controller={len(image)} bytes; resident ready tail={len(ready)} bytes")
    print("  acquisition FO/auth/ticket -> epoch-1 HELLO inputs")
    print("  resumed app keys + c -> regenerated FO -> delayed-response restore")
    print("  mismatched FO rejected; config/abort/video/NIC RAM unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
