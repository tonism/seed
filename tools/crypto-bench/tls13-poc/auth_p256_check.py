#!/usr/bin/env python3
"""Assemble and execute the product-shaped TLS 1.3 P-256 auth overlay.

The production image carries the exact current tracked api.openai.com P-256
leaf point/SPKI pin.  A byte-identical-layout test build substitutes the
deterministic private-key-backed fixture from the earlier integrated spike so
Unicorn can execute a complete known-valid CertificateVerify equation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CHECKER = Path(__file__).resolve()
SOURCE = HERE / "auth_p256_overlay.asm"
PINS = HERE / "auth_p256_pins.inc"
LAYOUT = HERE / "layout.inc"
P256 = ROOT / "targets/ibm_pc_5150/boot/core/p256.inc"
ORACLE_SOURCE = (
    ROOT / "tools/crypto-bench/tls13-spike/auth_integrated_oracle.py"
)
LIVE_CHAIN = ROOT / "tools/x509/certs/ecdsa_live_chain.pem"
LIVE_LEAF = HERE / "issuer_auth_live_leaf.pem"
LIVE_VECTOR = HERE / "issuer_auth_live_vector.json"

ORIGIN = 0x1800
K_END = 0x3600
RAM_END = 0x4000
STACK_GUARD_START = 0x3F00
STACK_TOP = 0x3FF0
RETURN_SENTINEL = 0x06FE
PATTERN = 0xA5

LOW_START = 0x0700
LOW_END = 0x1000
ATTEMPT_START = 0x3B9C
ATTEMPT_END = 0x3C9C
RECONNECT_START = 0x3C9C
PRODUCT_POOL_START = 0x3E40
CV_CONTEXT = b"TLS 1.3, server CertificateVerify"

INPUT_GUARD_LO = ATTEMPT_START
INPUT_DIGEST = INPUT_GUARD_LO + 8
INPUT_SIGNATURE_LEN = INPUT_DIGEST + 32
INPUT_SIGNATURE = INPUT_SIGNATURE_LEN + 2
INPUT_SIGNATURE_MAX = 72
INPUT_LEAF_X = INPUT_SIGNATURE + INPUT_SIGNATURE_MAX
INPUT_LEAF_Y = INPUT_LEAF_X + 32
OUTPUT_STATUS = INPUT_LEAF_Y + 32
INPUT_END = OUTPUT_STATUS + 1
INPUT_GUARD_HI = ATTEMPT_END - 8


def load_oracle():
    spec = importlib.util.spec_from_file_location(
        "seed_auth_p256_overlay_oracle", ORACLE_SOURCE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ORACLE_SOURCE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ORACLE = load_oracle()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def split_pem_chain(data: bytes) -> tuple[bytes, ...]:
    return tuple(
        match.group(0) + b"\n"
        for match in re.finditer(
            rb"-----BEGIN CERTIFICATE-----\r?\n.*?"
            rb"-----END CERTIFICATE-----",
            data,
            re.DOTALL,
        )
    )


def extract_p256_spki(
    certificate: Path,
) -> tuple[bytes, bytes, tuple[int, int], bytes]:
    public_pem = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
        check=True,
        capture_output=True,
    ).stdout
    spki = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=public_pem,
        check=True,
        capture_output=True,
    ).stdout
    certificate_der = subprocess.run(
        ["openssl", "x509", "-in", str(certificate), "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    if len(spki) != 91 or spki[-65] != 4:
        raise AssertionError("live leaf is not exact uncompressed P-256 SPKI")
    point = (
        int.from_bytes(spki[-64:-32], "big"),
        int.from_bytes(spki[-32:], "big"),
    )
    return certificate_der, spki, point, public_pem


def assemble(
    directory: Path,
    *,
    synthetic_pin: bool = False,
    live_compact: bool = False,
) -> tuple[bytes, list[str]]:
    if synthetic_pin and live_compact:
        raise ValueError("synthetic and live compact pins are mutually exclusive")
    suffix = (
        "live_compact"
        if live_compact
        else "synthetic"
        if synthetic_pin
        else "production"
    )
    binary = directory / f"auth_p256_{suffix}.bin"
    listing = directory / f"auth_p256_{suffix}.lst"
    command = [
        "nasm",
        "-f",
        "bin",
        f"-I{HERE}/",
        f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
        "-l",
        str(listing),
        "-o",
        str(binary),
    ]
    if synthetic_pin:
        command.extend(["-D", "AUTH_P256_SYNTHETIC_PIN"])
    if live_compact:
        command.extend(
            [
                "-D",
                "AUTH_P256_LIVE_COMPACT_INPUT",
                "-D",
                "AUTH_P256_LIVE_202607_PIN",
            ]
        )
    command.append(str(SOURCE))
    subprocess.run(command, cwd=ROOT, check=True)
    return binary.read_bytes(), listing.read_text().splitlines()


def compact_abi_probe(
    directory: Path, image: bytes
) -> dict[str, int]:
    """Ask NASM for the exact conditional compact-input equates."""

    names = (
        "auth_input_digest",
        "auth_input_signature_len",
        "auth_input_signature",
        "auth_input_signature_max",
        "auth_output_status",
        "auth_input_end",
        "poc_reconnect_state_start",
    )
    wrapper = directory / "auth_p256_live_compact_abi_probe.asm"
    binary = wrapper.with_suffix(".bin")
    emitted = "\n".join(f"    dw {name}" for name in names)
    wrapper.write_text(
        "bits 16\n"
        "cpu 8086\n"
        "%define AUTH_P256_LIVE_COMPACT_INPUT 1\n"
        "%define AUTH_P256_LIVE_202607_PIN 1\n"
        f'%include "{SOURCE.as_posix()}"\n'
        "__auth_p256_live_compact_abi_probe:\n"
        f"{emitted}\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{HERE}/",
            f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
            "-o",
            str(binary),
            str(wrapper),
        ],
        cwd=ROOT,
        check=True,
    )
    blob = binary.read_bytes()
    probe_bytes = len(names) * 2
    if blob[:-probe_bytes] != image:
        raise AssertionError("compact ABI probe changed the assembled image")
    values = struct.unpack(f"<{len(names)}H", blob[-probe_bytes:])
    return dict(zip(names, values))


def label_address(listing: list[str], label: str) -> int:
    pattern = re.compile(
        rf"\b{re.escape(label)}(?::|\s+(?:db|dw|dd|times)\b)"
    )
    offset = re.compile(r"\s([0-9A-F]{8})\s")
    any_label = re.compile(r"\b[A-Za-z_.$?][A-Za-z0-9_.$?]*:")
    for index, line in enumerate(listing):
        if not pattern.search(line):
            continue
        for relative, candidate in enumerate(listing[index : index + 24]):
            if relative and any_label.search(candidate):
                break
            match = offset.search(candidate)
            if match:
                return ORIGIN + int(match.group(1), 16)
    raise RuntimeError(f"missing NASM listing label: {label}")


def external_addresses() -> dict[str, int]:
    """Mirror the asserted sequential low-scratch equates in the assembly."""

    address: dict[str, int] = {}
    cursor = LOW_START
    for name in ("p256_jac_x", "p256_jac_y", "p256_jac_z"):
        address[name] = cursor
        cursor += 32
    for index in range(9):
        address[f"p256_s{index}"] = cursor
        cursor += 32
    address["p256_product"] = cursor
    cursor += 72
    address["p256_carry"] = cursor
    cursor = (cursor + 2) & ~1
    for name in (
        "p256_left_ptr",
        "p256_right_ptr",
        "p256_result_ptr",
        "p256_inv_output_ptr",
        "p256_affine_x_ptr",
        "p256_affine_y_ptr",
        "p256_scalar_ptr",
    ):
        address[name] = cursor
        cursor += 2
    address["auth_g_table_x"] = cursor
    cursor += 128
    address["auth_g_table_y"] = cursor
    cursor += 128
    address["auth_g_digits"] = cursor
    cursor += 264
    address["auth_g_count"] = cursor
    cursor += 2
    address["auth_loop_index"] = cursor
    cursor += 2
    for name in (
        "auth_leaf_x",
        "auth_leaf_y",
        "auth_r",
        "auth_s",
        "auth_z",
        "auth_w",
        "auth_u1",
        "auth_u2",
        "auth_result_x",
        "auth_result_y",
    ):
        address[name] = cursor
        cursor += 32
    for name in (
        "auth_signature_ptr",
        "auth_signature_len",
        "auth_digest_ptr",
        "auth_der_end",
        "auth_der_output_ptr",
        "auth_der_next_ptr",
        "auth_n_inverse_output_ptr",
        "auth_n_multiply_output_ptr",
        "auth_n_multiply_right_ptr",
    ):
        address[name] = cursor
        cursor += 2
    address["auth_private_work_end"] = cursor
    cursor = (cursor + 1) & ~1
    address["p256_mutable_work_start"] = cursor
    address["p256_w_tableX"] = cursor
    cursor += 128
    address["p256_w_tableY"] = cursor
    cursor += 128
    for name in (
        "p256_w_p2x",
        "p256_w_p2y",
        "p256_w_negy",
        "p256_w_scalar",
    ):
        address[name] = cursor
        cursor += 32
    address["p256_w_digits"] = cursor
    cursor += 264
    address["p256_w_count"] = cursor
    cursor += 2
    address["p256_w_tmp"] = cursor
    cursor += 1
    for name in (
        "p256_w_basex_ptr",
        "p256_w_basey_ptr",
        "p256_w_outx_ptr",
        "p256_w_outy_ptr",
    ):
        address[name] = cursor
        cursor += 2
    cursor = (cursor + 1) & ~1
    for name, size in (
        ("p256_kprod", 32),
        ("p256_kmid", 36),
        ("p256_kz0", 32),
        ("p256_kz2", 32),
        ("p256_km", 32),
        ("p256_kda", 16),
        ("p256_kdb", 16),
        ("p256_ksign", 2),
        ("p256_kdest", 2),
    ):
        address[name] = cursor
        cursor += size
    cursor = (cursor + 1) & ~1
    address["sol_acc"] = cursor
    cursor += 36
    address["p256_mutable_work_end"] = cursor
    address["auth_work_end"] = cursor
    if address["p256_mutable_work_end"] - address["p256_mutable_work_start"] != 896:
        raise AssertionError("checker P-256 external-work mirror changed size")
    if cursor > LOW_END:
        raise AssertionError("checker low-work mirror exceeds layout")
    return address


EXTERNAL = external_addresses()


def new_machine(image: bytes) -> Uc:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, bytes([PATTERN]) * 0x10000)
    machine.mem_write(ORIGIN, image)
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    return machine


def invoke(
    machine: Uc,
    entry: int,
    *,
    instruction_limit: int = 700_000_000,
) -> tuple[int, bool]:
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))

    def stop_at_return(
        emulator: Uc, _address: int, _size: int, _data: object
    ) -> None:
        emulator.emu_stop()

    hook = machine.hook_add(
        UC_HOOK_CODE,
        stop_at_return,
        begin=RETURN_SENTINEL,
        end=RETURN_SENTINEL,
    )
    try:
        machine.emu_start(entry, 0, count=instruction_limit)
    finally:
        machine.hook_del(hook)
    if machine.reg_read(UC_X86_REG_IP) != RETURN_SENTINEL:
        raise AssertionError("overlay stopped anywhere except the exact return IP")
    if machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("overlay did not restore the exact caller SP")
    if bytes(machine.mem_read(STACK_TOP - 2, 2)) != struct.pack(
        "<H", RETURN_SENTINEL
    ):
        raise AssertionError("overlay changed the caller return word")
    return (
        machine.reg_read(UC_X86_REG_AX),
        bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1),
    )


def write_inputs(
    machine: Uc,
    *,
    digest: bytes,
    signature: bytes,
    point: tuple[int, int],
) -> None:
    if len(digest) != 32 or len(signature) > INPUT_SIGNATURE_MAX:
        raise ValueError("bad checker input")
    x, y = point
    machine.mem_write(INPUT_GUARD_LO, b"LOWGUARD")
    machine.mem_write(INPUT_GUARD_HI, b"HIGHGU!!")
    machine.mem_write(INPUT_DIGEST, digest)
    machine.mem_write(INPUT_SIGNATURE_LEN, struct.pack("<H", len(signature)))
    machine.mem_write(
        INPUT_SIGNATURE,
        signature + bytes(INPUT_SIGNATURE_MAX - len(signature)),
    )
    machine.mem_write(INPUT_LEAF_X, x.to_bytes(32, "big"))
    machine.mem_write(INPUT_LEAF_Y, y.to_bytes(32, "big"))
    machine.mem_write(OUTPUT_STATUS, b"\x7f")


def write_compact_inputs(
    machine: Uc,
    abi: dict[str, int],
    *,
    digest: bytes,
    signature: bytes,
) -> tuple[int, bytes, bytes]:
    signature_max = abi["auth_input_signature_max"]
    if len(digest) != 32 or len(signature) > signature_max:
        raise ValueError("bad compact checker input")
    guard_lo = abi["auth_input_digest"] - 8
    guard_lo_bytes = b"LIVECV!!"
    guard_hi_bytes = b"\xd3" * (
        abi["poc_reconnect_state_start"] - abi["auth_input_end"]
    )
    if guard_lo < ATTEMPT_START or len(guard_hi_bytes) != 1:
        raise AssertionError("compact input lost its expected overrun sentinels")
    machine.mem_write(guard_lo, guard_lo_bytes)
    machine.mem_write(abi["auth_input_end"], guard_hi_bytes)
    machine.mem_write(
        abi["auth_input_digest"],
        bytes(abi["auth_input_end"] - abi["auth_input_digest"]),
    )
    machine.mem_write(abi["auth_input_digest"], digest)
    machine.mem_write(
        abi["auth_input_signature_len"],
        struct.pack("<H", len(signature)),
    )
    machine.mem_write(
        abi["auth_input_signature"],
        signature + bytes(signature_max - len(signature)),
    )
    machine.mem_write(abi["auth_output_status"], b"\x7f")
    return guard_lo, guard_lo_bytes, guard_hi_bytes


def words(machine: Uc, address: int) -> int:
    return int.from_bytes(machine.mem_read(address, 32), "little")


def stack_high_water(machine: Uc) -> int:
    guard = bytes(
        machine.mem_read(STACK_GUARD_START, STACK_TOP - STACK_GUARD_START)
    )
    touched = [index for index, byte in enumerate(guard) if byte != PATTERN]
    return len(guard) - min(touched) if touched else 0


def assert_sentinels(
    machine: Uc,
    image: bytes,
    addresses: dict[str, int],
    *,
    original_code: bytes,
    original_constants: bytes,
) -> dict[str, Any]:
    if bytes(machine.mem_read(INPUT_GUARD_LO, 8)) != b"LOWGUARD":
        raise AssertionError("low input sentinel changed")
    if bytes(machine.mem_read(INPUT_GUARD_HI, 8)) != b"HIGHGU!!":
        raise AssertionError("high input sentinel changed")
    code_len = addresses["auth_p256_code_end"] - ORIGIN
    if bytes(machine.mem_read(ORIGIN, code_len)) != original_code:
        raise AssertionError("overlay executable bytes changed")
    constant_start = addresses["p256_prime"]
    if bytes(
        machine.mem_read(constant_start, ORIGIN + len(image) - constant_start)
    ) != original_constants:
        raise AssertionError("overlay immutable constants/pin changed")
    tail = bytes(machine.mem_read(ORIGIN + len(image), K_END - ORIGIN - len(image)))
    if tail != bytes([PATTERN]) * len(tail):
        raise AssertionError("overlay wrote beyond image into K tail")
    low_tail = bytes(
        machine.mem_read(EXTERNAL["auth_work_end"], LOW_END - EXTERNAL["auth_work_end"])
    )
    # RETURN_SENTINEL is below LOW_START, so the unused low tail is pristine.
    if low_tail != bytes([PATTERN]) * len(low_tail):
        raise AssertionError("authentication work exceeded declared low scratch")
    resident = bytes(machine.mem_read(0x1000, ORIGIN - 0x1000))
    if resident != bytes([PATTERN]) * len(resident):
        raise AssertionError("authentication touched resident nucleus/driver slot")
    high = bytes(machine.mem_read(K_END, ATTEMPT_START - K_END))
    if high != bytes([PATTERN]) * len(high):
        raise AssertionError("authentication touched high FO/TLS vault")
    reconnect = bytes(
        machine.mem_read(RECONNECT_START, PRODUCT_POOL_START - RECONNECT_START)
    )
    if reconnect != bytes([PATTERN]) * len(reconnect):
        raise AssertionError("authentication touched reconnect/ESC state")
    arena_context = bytes(
        machine.mem_read(PRODUCT_POOL_START, STACK_GUARD_START - PRODUCT_POOL_START)
    )
    if arena_context != bytes([PATTERN]) * len(arena_context):
        raise AssertionError("authentication touched arena/context")
    return {
        "input_guard_bytes_each": 8,
        "k_tail_bytes": len(tail),
        "unused_low_tail_bytes": len(low_tail),
        "resident_driver_bytes_untouched": len(resident),
        "high_vault_bytes_untouched": len(high),
        "reconnect_esc_bytes_untouched": len(reconnect),
        "arena_context_bytes_untouched": len(arena_context),
    }


def assert_compact_sentinels(
    machine: Uc,
    image: bytes,
    addresses: dict[str, int],
    abi: dict[str, int],
    *,
    original_code: bytes,
    original_constants: bytes,
    guard_lo: int,
    guard_lo_bytes: bytes,
    guard_hi_bytes: bytes,
) -> dict[str, Any]:
    if bytes(machine.mem_read(guard_lo, len(guard_lo_bytes))) != guard_lo_bytes:
        raise AssertionError("compact low input sentinel changed")
    if bytes(
        machine.mem_read(abi["auth_input_end"], len(guard_hi_bytes))
    ) != guard_hi_bytes:
        raise AssertionError("compact high input sentinel changed")
    attempt_prefix = bytes(
        machine.mem_read(ATTEMPT_START, guard_lo - ATTEMPT_START)
    )
    if attempt_prefix != bytes([PATTERN]) * len(attempt_prefix):
        raise AssertionError("compact authentication touched attempt-cache prefix")
    code_len = addresses["auth_p256_code_end"] - ORIGIN
    if bytes(machine.mem_read(ORIGIN, code_len)) != original_code:
        raise AssertionError("compact overlay executable bytes changed")
    constant_start = addresses["p256_prime"]
    if bytes(
        machine.mem_read(constant_start, ORIGIN + len(image) - constant_start)
    ) != original_constants:
        raise AssertionError("compact overlay immutable constants/pin changed")
    tail = bytes(machine.mem_read(ORIGIN + len(image), K_END - ORIGIN - len(image)))
    if tail != bytes([PATTERN]) * len(tail):
        raise AssertionError("compact overlay wrote beyond image into K tail")
    low_tail = bytes(
        machine.mem_read(EXTERNAL["auth_work_end"], LOW_END - EXTERNAL["auth_work_end"])
    )
    if low_tail != bytes([PATTERN]) * len(low_tail):
        raise AssertionError("compact authentication exceeded low scratch")
    resident = bytes(machine.mem_read(0x1000, ORIGIN - 0x1000))
    if resident != bytes([PATTERN]) * len(resident):
        raise AssertionError("compact authentication touched resident nucleus/driver")
    high = bytes(machine.mem_read(K_END, ATTEMPT_START - K_END))
    if high != bytes([PATTERN]) * len(high):
        raise AssertionError("compact authentication touched high FO/TLS vault")
    reconnect = bytes(
        machine.mem_read(RECONNECT_START, PRODUCT_POOL_START - RECONNECT_START)
    )
    if reconnect != bytes([PATTERN]) * len(reconnect):
        raise AssertionError("compact authentication touched reconnect/ESC state")
    arena_context = bytes(
        machine.mem_read(PRODUCT_POOL_START, STACK_GUARD_START - PRODUCT_POOL_START)
    )
    if arena_context != bytes([PATTERN]) * len(arena_context):
        raise AssertionError("compact authentication touched arena/context")
    return {
        "low_input_guard_bytes": len(guard_lo_bytes),
        "high_input_guard_bytes": len(guard_hi_bytes),
        "attempt_prefix_bytes_untouched": len(attempt_prefix),
        "k_tail_bytes": len(tail),
        "unused_low_tail_bytes": len(low_tail),
        "resident_driver_bytes_untouched": len(resident),
        "high_vault_bytes_untouched": len(high),
        "reconnect_esc_bytes_untouched": len(reconnect),
        "arena_context_bytes_untouched": len(arena_context),
    }


def image_addresses(listing: list[str]) -> dict[str, int]:
    labels = (
        "auth_overlay_table",
        "auth_overlay_verify",
        "auth_overlay_pin_match",
        "auth_overlay_clear",
        "auth_ecdsa_verify",
        "auth_parse_signature",
        "p256_from_be32",
        "p256_prime",
        "auth_order_n",
        "auth_pinned_leaf_x_be",
        "auth_pinned_leaf_y_be",
        "auth_pinned_spki_sha256",
    )
    result = {name: label_address(listing, name) for name in labels}
    # The source has a NASM-time equality assertion between this marker and
    # p256_prime; the marker itself intentionally emits no listing bytes.
    result["auth_p256_code_end"] = result["p256_prime"]
    result.update(EXTERNAL)
    return result


def production_pin_gate(
    image: bytes, listing: list[str], directory: Path
) -> dict[str, Any]:
    if not LIVE_CHAIN.exists():
        raise AssertionError(f"missing tracked live chain: {LIVE_CHAIN}")
    leaf_pem = directory / "leaf.pem"
    public_pem = directory / "leaf-public.pem"
    first = LIVE_CHAIN.read_bytes().split(b"-----END CERTIFICATE-----", 1)[0]
    leaf_pem.write_bytes(first + b"-----END CERTIFICATE-----\n")
    subprocess.run(
        ["openssl", "x509", "-in", str(leaf_pem), "-pubkey", "-noout", "-out", str(public_pem)],
        check=True,
        capture_output=True,
    )
    spki = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_pem), "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    if len(spki) != 91 or spki[-65] != 4:
        raise AssertionError("tracked leaf is not exact uncompressed P-256 SPKI")
    point = (int.from_bytes(spki[-64:-32], "big"), int.from_bytes(spki[-32:], "big"))
    digest = hashlib.sha256(spki).digest()
    addresses = image_addresses(listing)
    embedded_point = (
        int.from_bytes(
            image[
                addresses["auth_pinned_leaf_x_be"] - ORIGIN :
                addresses["auth_pinned_leaf_x_be"] - ORIGIN + 32
            ],
            "big",
        ),
        int.from_bytes(
            image[
                addresses["auth_pinned_leaf_y_be"] - ORIGIN :
                addresses["auth_pinned_leaf_y_be"] - ORIGIN + 32
            ],
            "big",
        ),
    )
    embedded_digest = image[
        addresses["auth_pinned_spki_sha256"] - ORIGIN :
        addresses["auth_pinned_spki_sha256"] - ORIGIN + 32
    ]
    if embedded_point != point or embedded_digest != digest:
        raise AssertionError("production exact point/SPKI pin differs from tracked leaf")

    machine = new_machine(image)
    write_inputs(
        machine,
        digest=bytes(32),
        signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
        point=point,
    )
    _, carry = invoke(machine, addresses["auth_overlay_pin_match"])
    if carry:
        raise AssertionError("production pin helper rejected tracked leaf")
    machine.mem_write(INPUT_LEAF_X, ((point[0] ^ 1).to_bytes(32, "big")))
    _, carry = invoke(machine, addresses["auth_overlay_pin_match"])
    if not carry:
        raise AssertionError("production pin helper accepted a changed point")
    metadata = subprocess.run(
        ["openssl", "x509", "-in", str(leaf_pem), "-noout", "-subject", "-issuer", "-enddate"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip().splitlines()
    return {
        "tracked_certificate": str(LIVE_CHAIN.relative_to(ROOT)),
        "point_match_executed": True,
        "changed_point_rejected": True,
        "spki_sha256": digest.hex(),
        "metadata": metadata,
    }


def run_overlay_case(
    image: bytes,
    addresses: dict[str, int],
    *,
    digest: bytes,
    signature: bytes,
    point: tuple[int, int],
    expect_success: bool,
) -> tuple[Uc, int]:
    machine = new_machine(image)
    write_inputs(machine, digest=digest, signature=signature, point=point)
    original_code = bytes(
        machine.mem_read(ORIGIN, addresses["auth_p256_code_end"] - ORIGIN)
    )
    original_constants = bytes(
        machine.mem_read(
            addresses["p256_prime"],
            ORIGIN + len(image) - addresses["p256_prime"],
        )
    )
    ax, carry = invoke(machine, addresses["auth_overlay_verify"])
    status = bytes(machine.mem_read(OUTPUT_STATUS, 1))[0]
    success = not carry and ax == 1 and status == 1
    if success != expect_success:
        raise AssertionError(
            f"overlay case success={success}, expected={expect_success}; "
            f"AX={ax:#x}, CF={carry}, status={status}"
        )
    if not expect_success and status != 0:
        raise AssertionError("rejected overlay case left committed status")
    assert_sentinels(
        machine,
        image,
        addresses,
        original_code=original_code,
        original_constants=original_constants,
    )
    return machine, stack_high_water(machine)


def run_compact_overlay_case(
    image: bytes,
    addresses: dict[str, int],
    abi: dict[str, int],
    *,
    digest: bytes,
    signature: bytes,
    expect_success: bool,
) -> tuple[Uc, int, dict[str, Any]]:
    machine = new_machine(image)
    guard_lo, guard_lo_bytes, guard_hi_bytes = write_compact_inputs(
        machine,
        abi,
        digest=digest,
        signature=signature,
    )
    original_code = bytes(
        machine.mem_read(ORIGIN, addresses["auth_p256_code_end"] - ORIGIN)
    )
    original_constants = bytes(
        machine.mem_read(
            addresses["p256_prime"],
            ORIGIN + len(image) - addresses["p256_prime"],
        )
    )
    ax, carry = invoke(machine, addresses["auth_overlay_verify"])
    status = bytes(machine.mem_read(abi["auth_output_status"], 1))[0]
    success = not carry and ax == 1 and status == 1
    if success != expect_success:
        raise AssertionError(
            f"compact overlay case success={success}, "
            f"expected={expect_success}; AX={ax:#x}, CF={carry}, "
            f"status={status}"
        )
    if not expect_success and status != 0:
        raise AssertionError("rejected compact overlay case left committed status")
    sentinels = assert_compact_sentinels(
        machine,
        image,
        addresses,
        abi,
        original_code=original_code,
        original_constants=original_constants,
        guard_lo=guard_lo,
        guard_lo_bytes=guard_lo_bytes,
        guard_hi_bytes=guard_hi_bytes,
    )
    return machine, stack_high_water(machine), sentinels


def synthetic_equation_gate(
    image: bytes, listing: list[str]
) -> dict[str, Any]:
    fixture = ORACLE.make_fixture()
    addresses = image_addresses(listing)
    valid, valid_stack = run_overlay_case(
        image,
        addresses,
        digest=fixture.certificate_verify_digest,
        signature=fixture.certificate_verify_signature,
        point=fixture.leaf_point,
        expect_success=True,
    )
    expected = ORACLE.ecdsa_intermediates(
        fixture.certificate_verify_digest,
        fixture.certificate_verify_signature,
    )
    actual = {
        name: words(valid, addresses[f"auth_{name}"])
        for name in ("r", "s", "z", "w", "u1", "u2")
    }
    for name, value in expected.items():
        if actual[name] != value:
            raise AssertionError(f"target ECDSA intermediate mismatch: {name}")
    if words(valid, addresses["auth_result_x"]) != expected["r"]:
        raise AssertionError("target x mod n differs from signature r")

    bad_digest = bytearray(fixture.certificate_verify_digest)
    bad_digest[0] ^= 1
    _, digest_stack = run_overlay_case(
        image,
        addresses,
        digest=bytes(bad_digest),
        signature=fixture.certificate_verify_signature,
        point=fixture.leaf_point,
        expect_success=False,
    )
    bad_signature = bytearray(fixture.certificate_verify_signature)
    bad_signature[-1] ^= 1
    _, signature_stack = run_overlay_case(
        image,
        addresses,
        digest=fixture.certificate_verify_digest,
        signature=bytes(bad_signature),
        point=fixture.leaf_point,
        expect_success=False,
    )
    bad_point = (fixture.leaf_point[0] ^ 1, fixture.leaf_point[1])
    _, point_stack = run_overlay_case(
        image,
        addresses,
        digest=fixture.certificate_verify_digest,
        signature=fixture.certificate_verify_signature,
        point=bad_point,
        expect_success=False,
    )
    malformed = b"\x30\x81\x06\x02\x01\x01\x02\x01\x01"
    _, der_stack = run_overlay_case(
        image,
        addresses,
        digest=fixture.certificate_verify_digest,
        signature=malformed,
        point=fixture.leaf_point,
        expect_success=False,
    )

    clear_machine = valid
    _, carry = invoke(clear_machine, addresses["auth_overlay_clear"])
    if carry:
        raise AssertionError("clear routine unexpectedly returned carry")
    if any(clear_machine.mem_read(LOW_START, EXTERNAL["auth_work_end"] - LOW_START)):
        raise AssertionError("clear routine left external work bytes")
    if bytes(clear_machine.mem_read(ORIGIN, len(image))) != image:
        raise AssertionError("clear routine changed executable or immutable K bytes")
    if any(clear_machine.mem_read(INPUT_DIGEST, INPUT_END - INPUT_DIGEST)):
        raise AssertionError("clear routine left quarantined inputs/status")
    if bytes(clear_machine.mem_read(INPUT_GUARD_LO, 8)) != b"LOWGUARD":
        raise AssertionError("clear routine crossed low input guard")
    if bytes(clear_machine.mem_read(INPUT_GUARD_HI, 8)) != b"HIGHGU!!":
        raise AssertionError("clear routine crossed high input guard")

    return {
        "known_private_fixture": "tls13-spike/auth_integrated_oracle.py",
        "valid_equation": True,
        "intermediates_match_independent_oracle": True,
        "strict_der_bytes": len(fixture.certificate_verify_signature),
        "invalid_digest_rejected": True,
        "canonical_but_wrong_signature_rejected": True,
        "changed_exact_point_rejected": True,
        "malformed_der_rejected": True,
        "zeroization_gate": True,
        "exact_return_ip": True,
        "exact_caller_sp": True,
        "caller_return_word_preserved": True,
        "stack_high_water_bytes": max(
            valid_stack, digest_stack, signature_stack, point_stack, der_stack
        ),
    }


def live_compact_gate(
    image: bytes,
    listing: list[str],
    abi: dict[str, int],
    directory: Path,
) -> dict[str, Any]:
    if not LIVE_VECTOR.exists() or not LIVE_LEAF.exists():
        raise AssertionError("checked-in live CertificateVerify fixture is missing")
    vector = json.loads(LIVE_VECTOR.read_text())
    if vector.get("schema") != "seed-tls13-issuer-auth-live-vector-v1":
        raise AssertionError("unexpected live CertificateVerify vector schema")
    if vector.get("target") != "api.openai.com:443":
        raise AssertionError("live CertificateVerify vector target changed")
    if vector.get("credential_sent") is not False:
        raise AssertionError("live CertificateVerify vector is not credential-free")
    if vector["leaf"].get("pem") != LIVE_LEAF.name:
        raise AssertionError("live CertificateVerify vector names another leaf")
    cv = vector["certificate_verify"]
    if cv.get("signature_scheme") != "ecdsa_secp256r1_sha256":
        raise AssertionError("live CertificateVerify scheme is not P-256/SHA-256")

    transcript_hash = bytes.fromhex(cv["transcript_sha256"])
    signature = bytes.fromhex(cv["signature_der"])
    if len(transcript_hash) != 32:
        raise AssertionError("live transcript hash is not SHA-256 width")
    signed_input = b"\x20" * 64 + CV_CONTEXT + b"\x00" + transcript_hash
    digest = hashlib.sha256(signed_input).digest()
    if digest.hex() != cv["signed_input_sha256"]:
        raise AssertionError("live CertificateVerify signed-input digest changed")

    certificate_der, spki, point, public_pem = extract_p256_spki(LIVE_LEAF)
    if (
        hashlib.sha256(certificate_der).hexdigest()
        != vector["leaf"]["sha256_fingerprint"]
    ):
        raise AssertionError("live leaf fingerprint differs from vector")
    spki_digest = hashlib.sha256(spki).digest()
    if spki_digest.hex() != vector["leaf"]["spki_sha256"]:
        raise AssertionError("live leaf SPKI differs from vector")

    chain = split_pem_chain(LIVE_CHAIN.read_bytes())
    if len(chain) < 2:
        raise AssertionError("tracked ECDSA chain no longer contains WE1")
    capture = dt.datetime.fromisoformat(vector["captured_utc"])
    if capture.tzinfo is None:
        raise AssertionError("live capture time lost its UTC offset")
    we1_path = directory / "auth-p256-live-we1.pem"
    public_path = directory / "auth-p256-live-public.pem"
    signed_path = directory / "auth-p256-live-cv-signed.bin"
    signature_path = directory / "auth-p256-live-cv.der"
    we1_path.write_bytes(chain[1])
    public_path.write_bytes(public_pem)
    signed_path.write_bytes(signed_input)
    signature_path.write_bytes(signature)

    leaf_verify = subprocess.run(
        [
            "openssl",
            "verify",
            "-no-CAfile",
            "-no-CApath",
            "-trusted",
            str(we1_path),
            "-partial_chain",
            "-verify_hostname",
            "api.openai.com",
            "-purpose",
            "sslserver",
            "-attime",
            str(int(capture.timestamp())),
            str(LIVE_LEAF),
        ],
        capture_output=True,
        text=True,
    )
    if leaf_verify.returncode:
        raise AssertionError(
            "live leaf fails WE1/name/time/purpose validation: "
            + (leaf_verify.stderr or leaf_verify.stdout).strip()
        )
    leaf_text = subprocess.run(
        ["openssl", "x509", "-in", str(LIVE_LEAF), "-text", "-noout"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for required in (
        "Signature Algorithm: ecdsa-with-SHA256",
        "Public Key Algorithm: id-ecPublicKey",
        "ASN1 OID: prime256v1",
        "TLS Web Server Authentication",
        "Digital Signature",
        "CA:FALSE",
        "DNS:api.openai.com",
    ):
        if required not in leaf_text:
            raise AssertionError(f"live leaf lost exact profile: {required}")
    cv_verify = subprocess.run(
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
    if cv_verify.returncode:
        raise AssertionError("host rejected checked-in live CertificateVerify")

    addresses = image_addresses(listing)
    embedded_point = (
        int.from_bytes(
            image[
                addresses["auth_pinned_leaf_x_be"] - ORIGIN :
                addresses["auth_pinned_leaf_x_be"] - ORIGIN + 32
            ],
            "big",
        ),
        int.from_bytes(
            image[
                addresses["auth_pinned_leaf_y_be"] - ORIGIN :
                addresses["auth_pinned_leaf_y_be"] - ORIGIN + 32
            ],
            "big",
        ),
    )
    embedded_spki = image[
        addresses["auth_pinned_spki_sha256"] - ORIGIN :
        addresses["auth_pinned_spki_sha256"] - ORIGIN + 32
    ]
    if embedded_point != point or embedded_spki != spki_digest:
        raise AssertionError("compact live pin differs from host-validated leaf")

    expected_abi = {
        "auth_input_digest": 0x3C30,
        "auth_input_signature_len": 0x3C50,
        "auth_input_signature": 0x3C52,
        "auth_input_signature_max": 72,
        "auth_output_status": 0x3C9A,
        "auth_input_end": 0x3C9B,
        "poc_reconnect_state_start": RECONNECT_START,
    }
    if abi != expected_abi:
        raise AssertionError(f"compact live ABI changed: {abi!r}")
    table = struct.unpack("<5H", image[:10])
    expected_table = (
        addresses["auth_overlay_verify"],
        addresses["auth_overlay_pin_match"],
        addresses["auth_overlay_clear"],
        addresses["auth_pinned_spki_sha256"],
        len(image),
    )
    if table != expected_table:
        raise AssertionError("compact live entry table changed")
    sector_bytes = ((len(image) + 511) // 512) * 512
    if sector_bytes > 13 * 512:
        raise AssertionError("compact live overlay exceeds 13 sectors")

    valid, valid_stack, sentinels = run_compact_overlay_case(
        image,
        addresses,
        abi,
        digest=digest,
        signature=signature,
        expect_success=True,
    )
    bad_digest = bytearray(digest)
    bad_digest[0] ^= 1
    _, digest_stack, _ = run_compact_overlay_case(
        image,
        addresses,
        abi,
        digest=bytes(bad_digest),
        signature=signature,
        expect_success=False,
    )
    bad_signature = bytearray(signature)
    bad_signature[-1] ^= 1
    _, signature_stack, _ = run_compact_overlay_case(
        image,
        addresses,
        abi,
        digest=digest,
        signature=bytes(bad_signature),
        expect_success=False,
    )

    _, carry = invoke(valid, addresses["auth_overlay_clear"])
    if carry:
        raise AssertionError("compact clear routine unexpectedly returned carry")
    if any(valid.mem_read(LOW_START, EXTERNAL["auth_work_end"] - LOW_START)):
        raise AssertionError("compact clear left external work bytes")
    if any(
        valid.mem_read(
            abi["auth_input_digest"],
            abi["auth_input_end"] - abi["auth_input_digest"],
        )
    ):
        raise AssertionError("compact clear left digest/signature/status bytes")
    if bytes(valid.mem_read(ORIGIN, len(image))) != image:
        raise AssertionError("compact clear changed executable or immutable K bytes")
    clear_sentinels = assert_compact_sentinels(
        valid,
        image,
        addresses,
        abi,
        original_code=image[: addresses["auth_p256_code_end"] - ORIGIN],
        original_constants=image[addresses["p256_prime"] - ORIGIN :],
        guard_lo=abi["auth_input_digest"] - 8,
        guard_lo_bytes=b"LIVECV!!",
        guard_hi_bytes=b"\xd3",
    )

    return {
        "available": True,
        "vector": str(LIVE_VECTOR.relative_to(ROOT)),
        "leaf": str(LIVE_LEAF.relative_to(ROOT)),
        "captured_utc": vector["captured_utc"],
        "credential_sent": False,
        "host_validation": {
            "we1_chain": True,
            "hostname": "api.openai.com",
            "capture_time": True,
            "server_purpose_and_leaf_profile": True,
            "certificate_verify": True,
            "leaf_sha256": hashlib.sha256(certificate_der).hexdigest(),
            "spki_sha256": spki_digest.hex(),
        },
        "assembly_defines": [
            "AUTH_P256_LIVE_COMPACT_INPUT",
            "AUTH_P256_LIVE_202607_PIN",
        ],
        "image": {
            "content_bytes": len(image),
            "sector_rounded_bytes": sector_bytes,
            "sector_count": sector_bytes // 512,
            "sha256": hashlib.sha256(image).hexdigest(),
        },
        "abi": {
            "digest": f"0x{abi['auth_input_digest']:04x}",
            "signature_length": f"0x{abi['auth_input_signature_len']:04x}",
            "signature": f"0x{abi['auth_input_signature']:04x}",
            "signature_capacity_bytes": abi["auth_input_signature_max"],
            "status": f"0x{abi['auth_output_status']:04x}",
            "end": f"0x{abi['auth_input_end']:04x}",
        },
        "target_gates": {
            "real_certificate_verify_accepted": True,
            "altered_digest_rejected": True,
            "altered_signature_rejected": True,
            "status_committed_only_on_success": True,
            "clear_zeroized_compact_input_and_work": True,
            "stack_high_water_bytes": max(
                valid_stack,
                digest_stack,
                signature_stack,
                stack_high_water(valid),
            ),
        },
        "sentinels": sentinels,
        "clear_sentinels": clear_sentinels,
    }


def layout_ledger(
    image: bytes, listing: list[str], synthetic_image: bytes
) -> dict[str, Any]:
    addresses = image_addresses(listing)
    if len(image) > K_END - ORIGIN:
        raise AssertionError("production overlay exceeds K")
    if len(synthetic_image) != len(image):
        raise AssertionError("synthetic pin changed image layout")
    table = struct.unpack("<5H", image[:10])
    expected = (
        addresses["auth_overlay_verify"],
        addresses["auth_overlay_pin_match"],
        addresses["auth_overlay_clear"],
        addresses["auth_pinned_spki_sha256"],
        len(image),
    )
    if table != expected:
        raise AssertionError(f"entry table mismatch: {table!r} != {expected!r}")
    executable_end = addresses["auth_p256_code_end"]
    constants_start = addresses["p256_prime"]
    if constants_start != executable_end:
        raise AssertionError("auth image still embeds mutable/padding bytes after P-256 code")
    sector_bytes = ((len(image) + 511) // 512) * 512
    if sector_bytes > 13 * 512:
        raise AssertionError("overlay exceeds the 13-sector optimized auth cap")
    return {
        "load_address": f"0x{ORIGIN:04x}",
        "content_bytes": len(image),
        "content_end": f"0x{ORIGIN + len(image):04x}",
        "sector_rounded_bytes": sector_bytes,
        "sector_count": sector_bytes // 512,
        "k_capacity_bytes": K_END - ORIGIN,
        "k_free_bytes": K_END - ORIGIN - len(image),
        "entry_table_bytes": 10,
        "auth_wrapper_executable_bytes": addresses["p256_from_be32"] - ORIGIN,
        "included_p256_executable_bytes": executable_end - addresses["p256_from_be32"],
        "included_p256_mutable_bytes": constants_start - executable_end,
        "immutable_curve_and_pin_bytes": ORIGIN + len(image) - constants_start,
        "external_low_work": {
            "start": f"0x{LOW_START:04x}",
            "end": f"0x{EXTERNAL['auth_work_end']:04x}",
            "bytes": EXTERNAL["auth_work_end"] - LOW_START,
            "capacity": LOW_END - LOW_START,
            "remaining_bytes": LOW_END - EXTERNAL["auth_work_end"],
            "auth_private_bytes": (
                EXTERNAL["auth_private_work_end"] - LOW_START
            ),
            "p256_mutable": {
                "start": f"0x{EXTERNAL['p256_mutable_work_start']:04x}",
                "end": f"0x{EXTERNAL['p256_mutable_work_end']:04x}",
                "bytes": (
                    EXTERNAL["p256_mutable_work_end"]
                    - EXTERNAL["p256_mutable_work_start"]
                ),
            },
        },
        "quarantined_input": {
            "start": f"0x{INPUT_DIGEST:04x}",
            "end": f"0x{INPUT_END:04x}",
            "bytes": INPUT_END - INPUT_DIGEST,
            "guard_bytes_each": 8,
        },
        "product_pool_untouched": f"0x{PRODUCT_POOL_START:04x}..0x{STACK_GUARD_START:04x}",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="seed-auth-p256-overlay-") as name:
        directory = Path(name)
        production, production_listing = assemble(
            directory, synthetic_pin=False
        )
        synthetic, synthetic_listing = assemble(
            directory, synthetic_pin=True
        )
        live_compact, live_compact_listing = assemble(
            directory, live_compact=True
        )
        live_compact_abi = compact_abi_probe(directory, live_compact)
        production_pin = production_pin_gate(
            production, production_listing, directory
        )
        live_certificate_verify = live_compact_gate(
            live_compact,
            live_compact_listing,
            live_compact_abi,
            directory,
        )

    result = {
        "schema": "seed-tls13-poc-auth-p256-v1",
        "scope": (
            "isolated exact-leaf-pinned TLS 1.3 P-256 CertificateVerify "
            "overlay; no runtime integration"
        ),
        "provenance": {
            "source": str(SOURCE.relative_to(ROOT)),
            "source_sha256": sha256_file(SOURCE),
            "checker": str(CHECKER.relative_to(ROOT)),
            "checker_sha256": sha256_file(CHECKER),
            "pins": str(PINS.relative_to(ROOT)),
            "pins_sha256": sha256_file(PINS),
            "layout": str(LAYOUT.relative_to(ROOT)),
            "layout_sha256": sha256_file(LAYOUT),
            "p256_source": str(P256.relative_to(ROOT)),
            "p256_source_sha256": sha256_file(P256),
            "live_vector": str(LIVE_VECTOR.relative_to(ROOT)),
            "live_vector_sha256": sha256_file(LIVE_VECTOR),
            "live_leaf": str(LIVE_LEAF.relative_to(ROOT)),
            "live_leaf_sha256": sha256_file(LIVE_LEAF),
            "production_image_sha256": hashlib.sha256(production).hexdigest(),
            "synthetic_image_sha256": hashlib.sha256(synthetic).hexdigest(),
            "live_compact_image_sha256": hashlib.sha256(
                live_compact
            ).hexdigest(),
            "nasm_cpu": "8086",
        },
        "layout": layout_ledger(
            production, production_listing, synthetic
        ),
        "production_pin": production_pin,
        "target_gates": synthetic_equation_gate(
            synthetic, synthetic_listing
        ),
        "sentinels": {
            "executable_and_immutable_data": "unchanged",
            "k_tail": "unchanged",
            "resident_nucleus_and_driver_slot": "unchanged",
            "high_fo_tls_vault": "unchanged",
            "reconnect_esc_arena_context": "unchanged",
            "input_guards": "unchanged",
        },
        "live_certificate_verify_fixture": live_certificate_verify,
        "limitations": [
            "The standalone default pin uses the historical first leaf in ecdsa_live_chain.pem, valid through 8 August 2026.",
            "The compact live pin is an image-dated checkpoint; its validity interval is recorded in the checked-in leaf fixture.",
            "No Brotli, X.509, hostname, validity-time, WE1 recertification, TLS transcript construction, or socket code is part of this overlay.",
            "Exact-leaf rotation must fail closed until a separately authenticated pin update is designed.",
        ],
    }

    rendered = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        output = args.json_out
        if not output.is_absolute():
            output = ROOT / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
