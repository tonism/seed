#!/usr/bin/env python3
"""Execute the full resumed TLS schedule with only conventional-RAM state."""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import tempfile
from pathlib import Path


os.environ["TLS13_POC_K14"] = "1"

import check_tls13_sym_overlay as sym  # noqa: E402


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "tls13_sym_overlay.asm"

SYSTEM_TICKET_PSK = 0x0DC0
ROOT_HOLD = 0x3600
PROVISIONAL_HOLD = 0x3620
CONFIG = 0x3B9C
CONFIG_END = 0x3C9C
ABORT = 0x35C0
ABORT_END = 0x3600
CIPHERTEXT_SEGMENTS = (
    (0x3400, 272),
    (0x3640, 13),
    (0x3B40, 80),
    (0x355D, 99),
    (0x0500, 256),
    (0x33F8, 8),
    (0x08B8, 72),
    (0x0DE0, 288),
)


def assemble(directory: Path) -> bytes:
    output = directory / "sym-system-resume.bin"
    subprocess.run(
        (
            "nasm",
            "-f",
            "bin",
            "-DTLS13_POC_K14=1",
            "-DTLS13_SYM_SYSTEM_RAM_RESUMPTION=1",
            "-DTLS13_SHARED_SECRET_LEN=64",
            "-I",
            str(ROOT / "targets/ibm_pc_5150/boot") + "/",
            "-o",
            str(output),
            str(SOURCE),
        ),
        cwd=ROOT,
        check=True,
    )
    return output.read_bytes()


def deterministic(label: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"Seed system resumption|" + label).digest(length)


def scatter(vm: sym.Overlay, value: bytes) -> None:
    offset = 0
    for address, length in CIPHERTEXT_SEGMENTS:
        vm.write(address, value[offset : offset + length])
        offset += length
    if offset != len(value):
        raise AssertionError("resumption ciphertext scatter is not exactly 1088 bytes")


def gather(vm: sym.Overlay) -> bytes:
    return b"".join(vm.read(address, length) for address, length in CIPHERTEXT_SEGMENTS)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="seed-system-sym-resume-") as temp:
        image = assemble(Path(temp))
    header = sym.parse_header(image, expected_magic=b"T13SRR2!")
    if len(image) != 12 * 512 or len(header.entries) != 19:
        raise AssertionError("system resumption image lost its 12-sector/19-entry ABI")
    if header.low_end > 0x33F8:
        raise AssertionError("system resumption primitive work reaches ciphertext tail")
    if not 0x3B35 <= header.high_end <= 0x3B40:
        raise AssertionError(
            f"system resumption high state cannot free 3b40: {header.high_end:#x}"
        )

    fixture = sym.O.build_integrated_fixture()
    shared = fixture.candidate_mlkem_secret + fixture.server_x25519_public
    identity = deterministic(b"ticket identity", 192)
    psk = deterministic(b"ticket PSK", 32)
    ticket_age = 0x10203040
    placeholder, truncated = sym.build_resumption_client_hello(
        fixture.client_hello, identity, ticket_age, bytes(32)
    )
    binder_hash = hashlib.sha256(truncated).digest()
    zeros = bytes(32)
    empty_hash = hashlib.sha256(b"").digest()
    early_secret = sym.BASE.hkdf_extract(zeros, psk)
    binder_key = sym.BASE.hkdf_expand_label(
        early_secret, b"res binder", empty_hash, 32
    )
    finished_key = sym.BASE.hkdf_expand_label(binder_key, b"finished", b"", 32)
    expected_binder = hmac.new(finished_key, binder_hash, hashlib.sha256).digest()
    early_derived = sym.BASE.hkdf_expand_label(
        early_secret, b"derived", empty_hash, 32
    )
    client_hello, repeated_truncated = sym.build_resumption_client_hello(
        fixture.client_hello, identity, ticket_age, expected_binder
    )
    if repeated_truncated != truncated or placeholder[:-32] != client_hello[:-32]:
        raise AssertionError("resumption binder changed its truncated ClientHello")
    server_hello = sym.build_resumption_server_hello(fixture.server_hello)
    hello = client_hello + server_hello
    handshake_secret = sym.BASE.hkdf_extract(early_derived, shared)
    handshake = sym.derive_traffic(handshake_secret, hello)

    vm = sym.Overlay(image, header)
    sym.RETURN_SENTINEL = 0x0480
    config_guard = deterministic(b"config", CONFIG_END - CONFIG)
    video_guard = deterministic(b"video RAM", 0x1000)
    nic_guard = deterministic(b"NIC/card RAM", 0x1000)
    abort_guard = deterministic(b"abort capsule", ABORT_END - ABORT)
    vm.write(CONFIG, config_guard)
    vm.write(0xB000, video_guard)
    vm.write(0xD000, nic_guard)
    vm.write(ABORT, abort_guard)
    vm.call(0)
    vm.write(SYSTEM_TICKET_PSK, psk)
    vm.call(13)
    sym.assert_equal("system early-derived", vm.read(sym.HANDSHAKE_DERIVED, 32), early_derived)

    handoff = sym.build_hello_handoff(hello, fixture.server_x25519_public)
    vm.write(sym.HELLO_SERVER_X, handoff)
    vm.write(sym.SHARED_SECRET, shared[:32] + bytes(32))
    vm.write(sym.HELLO_HASH, bytes(32))
    vm.call(15)
    vm.call(14)
    for label, address, expected in (
        ("handshake secret", sym.HANDSHAKE_SECRET, handshake["handshake_secret"]),
        ("client handshake key", sym.CLIENT_HS_KEY, handshake["client_key"]),
        ("server handshake key", sym.SERVER_HS_KEY, handshake["server_key"]),
    ):
        sym.assert_equal(label, vm.read(address, len(expected)), expected)

    root = deterministic(b"entropy root", 32)
    provisional = shared[:32]
    vm.write(ROOT_HOLD, root)
    vm.write(PROVISIONAL_HOLD, provisional)
    ciphertext = fixture.mlkem_ciphertext
    scatter(vm, ciphertext)

    resumed_ee = sym.RESUMED_ENCRYPTED_EXTENSIONS
    server_verify = hmac.new(
        handshake["server_finished"],
        hashlib.sha256(hello + resumed_ee).digest(),
        hashlib.sha256,
    ).digest()
    server_finished = b"\x14\x00\x00\x20" + server_verify
    flight = resumed_ee + server_finished
    record = sym.BASE.encrypted_record(
        handshake["server_key"],
        handshake["server_iv"],
        0,
        sym.O.CONTENT_HANDSHAKE,
        flight,
    )
    vm.write(sym.IO_BASE, record)
    disposition, _carry = vm.call(18)
    if disposition != 2:
        raise AssertionError("no-early-data resumed flight returned wrong disposition")
    vm.write(sym.RECEIVED_SERVER_FINISHED, server_verify)
    vm.call(8)
    finished_len, _ = vm.call(9)
    if finished_len != 58:
        raise AssertionError("system resumption built a noncanonical client Finished")
    vm.call(16)
    head_len, _ = vm.call(11)
    if head_len != 72:
        raise AssertionError(
            f"system resumption built a noncanonical HEAD record: {head_len}"
        )
    vm.call(17)

    sym.assert_equal("retained entropy root", vm.read(ROOT_HOLD, 32), root)
    sym.assert_equal("retained provisional K", vm.read(PROVISIONAL_HOLD, 32), provisional)
    sym.assert_equal("retained split ciphertext", gather(vm), ciphertext)
    sym.assert_equal("product config", vm.read(CONFIG, len(config_guard)), config_guard)
    sym.assert_equal("abort capsule", vm.read(ABORT, len(abort_guard)), abort_guard)
    sym.assert_equal("MDA/CGA video RAM", vm.read(0xB000, len(video_guard)), video_guard)
    sym.assert_equal("NIC/card RAM", vm.read(0xD000, len(nic_guard)), nic_guard)

    print("TLS 1.3 system-RAM resumption symmetric overlay: PASS")
    print(
        f"  image={len(image)} bytes, work-end={header.low_end:04x}, "
        f"high-end={header.high_end:04x}"
    )
    print("  binder + resumed Finished + client Finished + application HEAD")
    print("  root/K/c retained; abort/config/video/NIC RAM unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
