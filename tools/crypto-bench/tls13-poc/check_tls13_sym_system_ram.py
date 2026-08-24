#!/usr/bin/env python3
"""Focused executable gate for the 16 KiB RAM-only acquisition image."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from pathlib import Path


os.environ["TLS13_POC_K14"] = "1"

import check_tls13_sym_overlay as sym  # noqa: E402


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "tls13_sym_overlay.asm"

SYSTEM_HOLD_LEN = 171
SYSTEM_WORK_END_MAX = 0x33E8
SYSTEM_K_END = 0x3400
SYSTEM_C_SEGMENTS = (
    (0x3400, 272),
    (0x3600, 77),
    (0x355D, 99),
    (0x0500, 256),
    (0x33E8, 24),
    (0x08B8, 72),
    (0x0DE0, 288),
)
ABORT_CAPSULE_START = 0x35C0
ABORT_CAPSULE_END = 0x3600
SYSTEM_TICKET_IDENTITY = sym.IO_BASE
SYSTEM_TICKET_NONCE = SYSTEM_TICKET_IDENTITY + 192
SYSTEM_TICKET_METADATA = SYSTEM_TICKET_NONCE + 32
SYSTEM_TICKET_END = SYSTEM_TICKET_METADATA + 12
CONFIG_START = 0x3B9C


def assemble(directory: Path) -> tuple[bytes, list[str]]:
    output = directory / "sym-system.bin"
    listing = directory / "sym-system.lst"
    subprocess.run(
        (
            "nasm",
            "-f",
            "bin",
            "-DTLS13_POC_K14=1",
            "-DTLS13_SYM_ACQUISITION_ONLY=1",
            "-DTLS13_SYM_SYSTEM_RAM=1",
            "-DTLS13_SHARED_SECRET_LEN=64",
            "-I",
            str(ROOT / "targets/ibm_pc_5150/boot") + "/",
            "-o",
            str(output),
            "-l",
            str(listing),
            str(SOURCE),
        ),
        cwd=ROOT,
        check=True,
    )
    return output.read_bytes(), listing.read_text(encoding="utf-8").splitlines()


def label_address(listing: list[str], label: str) -> int:
    definition = next(
        (
            index
            for index, line in enumerate(listing)
            if re.search(rf"\b{re.escape(label)}:\s*$", line)
        ),
        None,
    )
    if definition is None:
        raise AssertionError(f"missing system symmetric label {label}")
    for line in listing[definition + 1 :]:
        match = re.search(r"\b([0-9A-F]{8})\b", line)
        if match:
            return sym.OVERLAY_BASE + int(match.group(1), 16)
    raise AssertionError(f"system symmetric label {label} has no address")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="seed-tls13-sym-system-") as temp:
        image, listing = assemble(Path(temp))
    header = sym.parse_header(image, expected_magic=b"T13SRA2!")
    if header.version != 2 or len(header.entries) != 19:
        raise AssertionError("system symmetric header/entry ABI drifted")
    if header.low_end > SYSTEM_WORK_END_MAX:
        raise AssertionError(
            f"system symmetric work end is {header.low_end:04x}, above 33e8"
        )
    if header.high_end != sym.IO_BASE + 5 + sym.MSS + 16:
        raise AssertionError("system symmetric high-state packing drifted")
    if header.high_end > CONFIG_START:
        raise AssertionError("system symmetric state reaches product config")
    hold_start = label_address(listing, "sym_system_hold")
    hold_end = hold_start + SYSTEM_HOLD_LEN
    if not (
        sym.OVERLAY_BASE <= hold_start < hold_end <= sym.OVERLAY_BASE + len(image)
        and hold_end <= header.low_start
    ):
        raise AssertionError("system retained object is not inert image storage")

    fixture = sym.O.build_integrated_fixture()
    transcript = fixture.client_hello + fixture.server_hello
    shared = fixture.candidate_mlkem_secret + fixture.server_x25519_public
    expected = sym.derive_handshake(shared, transcript)

    vm = sym.Overlay(image, header)
    # Keep the resident entropy/ciphertext band independent from the checker's
    # synthetic return trampoline.
    sym.RETURN_SENTINEL = 0x0480
    retained = hashlib.shake_256(b"Seed RAM-only retained acquisition facts").digest(
        SYSTEM_HOLD_LEN
    )
    vm.write(hold_start, retained)
    config_guard = hashlib.shake_256(b"Seed product config guard").digest(
        0x3C9C - CONFIG_START
    )
    video_guard = hashlib.shake_256(b"Seed video guard").digest(0x1000)
    nic_guard = hashlib.shake_256(b"Seed NIC RAM guard").digest(0x1000)
    abort_guard = hashlib.shake_256(b"Seed system abort capsule").digest(
        ABORT_CAPSULE_END - ABORT_CAPSULE_START
    )
    vm.write(CONFIG_START, config_guard)
    vm.write(0xB000, video_guard)
    vm.write(0xD000, nic_guard)
    vm.write(ABORT_CAPSULE_START, abort_guard)

    vm.call(0)
    vm.write(sym.SHARED_SECRET, shared)
    vm.write(sym.HELLO_HASH, hashlib.sha256(transcript).digest())
    vm.call(3)
    sym.assert_equal(
        "system handshake secret",
        vm.read(sym.HANDSHAKE_SECRET, 32),
        expected["handshake_secret"],
    )
    sym.assert_equal(
        "system client handshake key",
        vm.read(sym.CLIENT_HS_KEY, 32),
        expected["client_key"],
    )
    sym.assert_equal(
        "system server handshake key",
        vm.read(sym.SERVER_HS_KEY, 32),
        expected["server_key"],
    )

    ciphertext = fixture.mlkem_ciphertext
    offset = 0
    for address, length in SYSTEM_C_SEGMENTS:
        vm.write(address, ciphertext[offset : offset + length])
        offset += length
    if offset != len(ciphertext):
        raise AssertionError("system symmetric c scatter is not exactly 1088 bytes")

    # The acquisition image retains its public ABI but must reject every
    # resumption-only entry.
    for entry in (13, 14, 18):
        vm.call(entry, expect_success=False)

    resumption_master = hashlib.sha256(b"Seed system resumption master").digest()
    identity = hashlib.shake_256(b"Seed maximum system ticket").digest(192)
    nonce = hashlib.sha256(b"Seed maximum system ticket nonce").digest()
    nst = sym.build_nst_with_extensions(
        identity=identity,
        nonce=nonce,
        extensions=sym.NST_LIVE_EXTENSIONS,
    )
    if len(nst) > sym.MSS:
        raise AssertionError("system NST fixture exceeds one authenticated quarantine")
    vm.write(sym.RESUMPTION_MASTER, resumption_master)
    vm.write(sym.IO_BASE, nst)
    vm.call(12, si=sym.IO_BASE, cx=len(nst))
    ticket_status = vm.read(hold_end, 1)
    if ticket_status != b"\x02":
        raise AssertionError(
            "system early-data-capable ticket did not commit status last: "
            f"status={ticket_status.hex()} metadata="
            f"{vm.read(SYSTEM_TICKET_METADATA, 12).hex()}"
        )
    sym.assert_equal(
        "overlap-safe system ticket identity",
        vm.read(SYSTEM_TICKET_IDENTITY, len(identity)),
        identity,
    )
    sym.assert_equal(
        "overlap-safe system ticket nonce",
        vm.read(SYSTEM_TICKET_NONCE, len(nonce)),
        nonce,
    )
    sym.assert_equal(
        "system ticket metadata length",
        vm.read(SYSTEM_TICKET_METADATA + 8, 4),
        len(nonce).to_bytes(2, "little") + len(identity).to_bytes(2, "little"),
    )
    expected_psk = sym.BASE.hkdf_expand_label(
        resumption_master, b"resumption", nonce, 32
    )
    sym.assert_equal("system ticket PSK", vm.read(sym.TICKET_PSK, 32), expected_psk)

    sym.assert_equal("retained acquisition facts", vm.read(hold_start, len(retained)), retained)
    offset = 0
    for index, (address, length) in enumerate(SYSTEM_C_SEGMENTS):
        sym.assert_equal(
            f"live ciphertext slice {index}",
            vm.read(address, length),
            ciphertext[offset : offset + length],
        )
        offset += length
    sym.assert_equal(
        "disk-independent abort capsule",
        vm.read(ABORT_CAPSULE_START, len(abort_guard)),
        abort_guard,
    )
    sym.assert_equal("product config", vm.read(CONFIG_START, len(config_guard)), config_guard)
    sym.assert_equal("MDA/CGA video RAM", vm.read(0xB000, len(video_guard)), video_guard)
    sym.assert_equal("NIC/card RAM", vm.read(0xD000, len(nic_guard)), nic_guard)

    allowed = (
        (header.low_start, header.low_end),
        (sym.K14_RUNTIME_START, sym.K14_RUNTIME_END),
        (header.high_start, header.high_end),
        (hold_end, hold_end + 2),
        (sym.STACK_GUARD, 0x4000),
    )
    escaped = [
        (address, size)
        for address, size in vm.emulated_writes
        if not any(start <= address and address + size <= end for start, end in allowed)
    ]
    if escaped:
        raise AssertionError(f"system symmetric write escaped: {escaped[:8]}")

    print("TLS 1.3 system-RAM acquisition symmetric overlay: PASS")
    print(
        f"  image={len(image)} bytes, retained={hold_start:04x}..{hold_end:04x}, "
        f"primitive-tail={header.low_end:04x}..{SYSTEM_K_END:04x}"
    )
    print(
        f"  ticket={SYSTEM_TICKET_IDENTITY:04x}..{SYSTEM_TICKET_END:04x}, "
        f"high-state-end={header.high_end:04x}, config starts {CONFIG_START:04x}"
    )
    print(
        "  full key schedule + live seven-slice c + overlap-safe max NST; "
        "video/NIC RAM unchanged"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
