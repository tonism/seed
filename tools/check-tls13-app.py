#!/usr/bin/env python3
"""Execute Seed's cpu-8086 TLS 1.3 record sealer against the host oracle."""

from __future__ import annotations

import hashlib
import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


ROOT = Path(__file__).resolve().parents[1]
BOOT = ROOT / "targets/ibm_pc_5150/boot"
CORE = BOOT / "core.asm"
LAYOUT = BOOT / "core/layout.inc"
DATA = BOOT / "core/data.inc"
SPIKE = ROOT / "tools/crypto-bench/tls13-spike/tls13_spike.py"
LAYOUT_CHECK = ROOT / "tools/check-layout.py"
BUILD_DIR = ROOT / "build/ibm_pc_5150"
ORIGIN = 0x1000
RETURN_SENTINEL = 0x04F0
INPUT_ADDR = 0x0500
RX_INPUT_ADDR = 0x4000
RX_OUTPUT_ADDR = 0x8000
STACK_TOP = 0xFFF0
RAM_BYTES = 0x10000
CGA_VIDEO_ADDR = 0xB8000
MDA_VIDEO_ADDR = 0xB0000
VIDEO_BYTES = 0x4000
AUTH_SPOOL_ADDR = 0x2E00
AUTH_SPOOL_LEN = 0x0800
AUTH_SPOOL_GUARD_LEN = 16
AUTH_SPOOL_PREFIX_GUARD = bytes([0x6D]) * AUTH_SPOOL_GUARD_LEN
AUTH_SPOOL_SUFFIX_GUARD = bytes([0xA6]) * AUTH_SPOOL_GUARD_LEN
AUTH_SPOOL_FILL = bytes([0xE1]) * AUTH_SPOOL_LEN
VIDEO_FILL = bytes([0x93]) * VIDEO_BYTES


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TLS = load_module("seed_tls13_app_oracle", SPIKE)
CHECK_LAYOUT = load_module("seed_tls13_layout_parser", LAYOUT_CHECK)


def listing_symbol_address(path: Path, label: str) -> int:
    lines = path.read_text().splitlines()
    marker = re.compile(
        rf"\b{re.escape(label)}(?::|\s+(?:d[wbqd]|res[wbqd])\b)"
    )
    offset_pattern = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+")
    for index, line in enumerate(lines):
        if not marker.search(line):
            continue
        for candidate in lines[index : index + 40]:
            match = offset_pattern.match(candidate)
            if match:
                return ORIGIN + int(match.group(1), 16)
    raise AssertionError(f"cannot resolve {label} in {path}")


def write_u16(machine: Uc, address: int, value: int) -> None:
    machine.mem_write(address, value.to_bytes(2, "little"))


def read_u16(machine: Uc, address: int) -> int:
    return int.from_bytes(machine.mem_read(address, 2), "little")


def execute_returning(machine: Uc, entry: int) -> int:
    stack_pointer = STACK_TOP - 2
    machine.mem_write(stack_pointer, RETURN_SENTINEL.to_bytes(2, "little"))
    machine.reg_write(UC_X86_REG_SP, stack_pointer)
    machine.reg_write(UC_X86_REG_IP, entry)
    returned = False

    def stop_on_return(uc: Uc, address: int, _size: int, _user: object) -> None:
        nonlocal returned
        if address == RETURN_SENTINEL:
            returned = True
            uc.emu_stop()

    hook = machine.hook_add(UC_HOOK_CODE, stop_on_return)
    try:
        machine.emu_start(entry, RAM_BYTES, count=25_000_000)
    finally:
        machine.hook_del(hook)
    if not returned:
        raise AssertionError(
            f"routine at {entry:#x} did not return "
            f"(ip={machine.reg_read(UC_X86_REG_IP):#x}, "
            f"sp={machine.reg_read(UC_X86_REG_SP):#x})"
        )
    return machine.reg_read(UC_X86_REG_EFLAGS) & 1


def make_machine(image: bytes) -> Uc:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_map(MDA_VIDEO_ADDR, 0x10000)
    machine.mem_write(ORIGIN, image)
    machine.mem_write(MDA_VIDEO_ADDR, VIDEO_FILL)
    machine.mem_write(CGA_VIDEO_ADDR, VIDEO_FILL)
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    return machine


def initialize_runtime_constants(machine: Uc, constants: dict[str, int]) -> None:
    """Mirror the client-hello phase's low-constant publication."""
    sha_words = (
        0xE667,
        0x6A09,
        0xAE85,
        0xBB67,
        0xF372,
        0x3C6E,
        0xF53A,
        0xA54F,
        0x527F,
        0x510E,
        0x688C,
        0x9B05,
        0xD9AB,
        0x1F83,
        0xCD19,
        0x5BE0,
    )
    block = (
        b"master secret"
        + b"client finished"
        + b"server finished"
        + b"key expansion"
        + b"expand 32-byte k"
        + b"\xfb"
        + (b"\xff" * 15)
        + b"\x03"
        + b"".join(word.to_bytes(2, "little") for word in sha_words)
    )
    if len(block) != constants["low_static_constants_len"]:
        raise AssertionError("host runtime-constant fixture length drifted")
    machine.mem_write(constants["low_static_constants_start"], block)


def expected_record(key: bytes, iv: bytes, sequence: int, plain: bytes) -> bytes:
    inner = plain + bytes([TLS.CONTENT_APPLICATION_DATA])
    header = (
        bytes([TLS.CONTENT_APPLICATION_DATA])
        + TLS.TLS_LEGACY_VERSION
        + (len(inner) + TLS.AEAD_TAG_LEN).to_bytes(2, "big")
    )
    nonce = TLS.tls13_nonce(iv, sequence)
    return header + TLS.aead_encrypt(key, nonce, header, inner)


def server_record(
    key: bytes,
    iv: bytes,
    sequence: int,
    plain: bytes,
    inner_type: int = TLS.CONTENT_APPLICATION_DATA,
    padding_len: int = 0,
) -> bytes:
    if padding_len < 0:
        raise ValueError("negative TLSInnerPlaintext padding")
    inner = plain + bytes([inner_type]) + bytes(padding_len)
    header = (
        bytes([TLS.CONTENT_APPLICATION_DATA])
        + TLS.TLS_LEGACY_VERSION
        + (len(inner) + TLS.AEAD_TAG_LEN).to_bytes(2, "big")
    )
    return header + TLS.aead_encrypt(
        key, TLS.tls13_nonce(iv, sequence), header, inner
    )


def new_session_ticket(
    identity: bytes,
    *,
    nonce: bytes = b"seed-nst",
    lifetime: int = 604800,
    age_add: int = 0x12345678,
    extensions: tuple[tuple[int, bytes], ...] = (),
) -> bytes:
    encoded_extensions = b"".join(
        kind.to_bytes(2, "big")
        + len(value).to_bytes(2, "big")
        + value
        for kind, value in extensions
    )
    body = (
        lifetime.to_bytes(4, "big")
        + age_add.to_bytes(4, "big")
        + bytes((len(nonce),))
        + nonce
        + len(identity).to_bytes(2, "big")
        + identity
        + len(encoded_extensions).to_bytes(2, "big")
        + encoded_extensions
    )
    return bytes((4,)) + len(body).to_bytes(3, "big") + body


def run_case(
    image: bytes,
    entry: int,
    labels: dict[str, int],
    constants: dict[str, int],
    plain_len: int,
    sequence: int,
) -> str:
    machine = make_machine(image)
    initialize_runtime_constants(machine, constants)
    key = hashlib.sha256(b"Seed TLS 1.3 application sealer key").digest()
    iv = hashlib.sha256(b"Seed TLS 1.3 application sealer iv").digest()[:12]
    plain = bytes(((index * 197) + plain_len) & 0xFF for index in range(plain_len))
    expected = expected_record(key, iv, sequence, plain)

    record_addr = constants["tls_app_record_buffer"]
    record_cap = constants["tls13_app_record_buffer_len"]
    guard = bytes([0xA5]) * 16
    machine.mem_write(record_addr - len(guard), guard)
    machine.mem_write(record_addr, bytes([0xCC]) * record_cap)
    machine.mem_write(record_addr + record_cap, guard)
    machine.mem_write(INPUT_ADDR, plain)
    machine.mem_write(constants["tls_client_write_key"], key)
    machine.mem_write(constants["tls_client_write_iv"], iv)
    machine.mem_write(
        constants["tls_client_record_seq"], sequence.to_bytes(8, "big")
    )
    machine.mem_write(labels["tls_app_plain_ptr"], INPUT_ADDR.to_bytes(2, "little"))
    write_u16(machine, constants["tls_app_len"], plain_len)

    carry = execute_returning(machine, entry)
    if carry:
        raise AssertionError(f"sealer rejected len={plain_len}, seq={sequence:#x}")
    actual_len = read_u16(machine, constants["tls_app_record_len"])
    tx_len = read_u16(machine, constants["tls_tx_len"])
    if actual_len != len(expected) or tx_len != len(expected):
        raise AssertionError(
            f"length mismatch len={plain_len}: record={actual_len}, tx={tx_len}, "
            f"expected={len(expected)}"
        )
    actual = bytes(machine.mem_read(record_addr, actual_len))
    if actual != expected:
        raise AssertionError(
            f"oracle mismatch len={plain_len}, seq={sequence:#x}: "
            f"actual={hashlib.sha256(actual).hexdigest()} "
            f"expected={hashlib.sha256(expected).hexdigest()}; "
            f"wire={actual.hex()} oracle={expected.hex()}"
        )
    if bytes(machine.mem_read(record_addr - len(guard), len(guard))) != guard:
        raise AssertionError(f"record prefix canary changed at len={plain_len}")
    if bytes(machine.mem_read(record_addr + record_cap, len(guard))) != guard:
        raise AssertionError(f"record suffix canary changed at len={plain_len}")
    if (
        bytes(machine.mem_read(constants["tls_client_record_seq"], 8))
        != sequence.to_bytes(8, "big")
    ):
        raise AssertionError("record builder mutated the caller-owned sequence")
    return hashlib.sha256(actual).hexdigest()










def main() -> int:
    """Seal with the exact emitted K; HTTP/2 receive gates check publication."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, default=BUILD_DIR / "tls13-pack-base/SEED.SYS")
    parser.add_argument("--listing", type=Path)
    args = parser.parse_args()
    listing = args.listing or args.core.with_suffix(".SYS.lst")
    image = args.core.read_bytes()
    constants = CHECK_LAYOUT.parse_equates([LAYOUT, DATA])
    k_end = listing_symbol_address(listing, "core_link_window_end")
    if k_end > 0x2800:
        raise AssertionError("K escaped its eight-sector slot")
    image = image[:k_end - ORIGIN]
    entry = listing_symbol_address(listing, "tls_build_application_data_record")
    labels = {"tls_app_plain_ptr": listing_symbol_address(listing, "tls_app_plain_ptr")}
    cases = [(0,0),(1,1),(15,0x0102030405060708),(16,0x8877665544332211),
             (17,2),(63,3),(64,4),(65,5),(360,1),
             (constants["api_request_send_len"]-1,0x7fffffffffffffff),
             (constants["api_request_send_len"],0xffffffffffffffff)]
    for length, sequence in cases:
        run_case(image, entry, labels, constants, length, sequence)
    print(f"TLS 1.3 product AEAD seal: PASS ({len(cases)} oracle cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
