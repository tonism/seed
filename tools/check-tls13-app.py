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
VIDEO_ADDR = 0xB8000
VIDEO_BYTES = 0x4000
AUTH_SPOOL_LEN = 0x3000
MDA_SPOOL_ADDR = 0x2E00
MDA_SPOOL_LEN = 0x0800
MDA_GUARD_LEN = 16
MDA_PREFIX_GUARD = bytes([0x6D]) * MDA_GUARD_LEN
MDA_SUFFIX_GUARD = bytes([0xA6]) * MDA_GUARD_LEN
MDA_SPOOL_FILL = bytes([0xE1]) * MDA_SPOOL_LEN


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


def build_image(work: Path) -> tuple[bytes, Path]:
    subprocess.run(
        ["make", str(BUILD_DIR / "p256_module.bin")],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    image_path = work / "SEED.SYS"
    listing_path = work / "SEED.SYS.lst"
    subprocess.run(
        [
            "nasm",
            "-DLOADER_SECTORS=4",
            "-DTLS13_APP_COMPILE_CHECK=1",
            "-DTLS13_APP_ORACLE_CHECK=1",
            "-DTLS13_PRODUCT_PACK_BASE=1",
            f"-I{BOOT}/",
            f"-I{BUILD_DIR}/",
            "-f",
            "bin",
            "-l",
            str(listing_path),
            "-o",
            str(image_path),
            str(CORE),
        ],
        cwd=ROOT,
        check=True,
    )
    return image_path.read_bytes(), listing_path


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
    machine.mem_map(VIDEO_ADDR, VIDEO_BYTES)
    machine.mem_write(ORIGIN, image)
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


def next_sequence(sequence: int) -> int:
    return (sequence + 1) & 0xFFFFFFFFFFFFFFFF


def initialize_receive_case(
    machine: Uc,
    labels: dict[str, int],
    constants: dict[str, int],
    wire: bytes,
    key: bytes,
    iv: bytes,
    sequence: int,
    chunk: int,
    video_segment: int = 0xB800,
) -> tuple[bytes, bytes]:
    output_cap = AUTH_SPOOL_LEN
    output_guard = bytes([0xA7]) * 16
    output_fill = bytes([0xD3]) * output_cap
    machine.mem_write(RX_INPUT_ADDR, wire)
    machine.mem_write(RX_OUTPUT_ADDR - len(output_guard), output_guard)
    machine.mem_write(RX_OUTPUT_ADDR, output_fill)
    machine.mem_write(RX_OUTPUT_ADDR + output_cap, output_guard)
    machine.mem_write(constants["tls_server_write_key"], key)
    machine.mem_write(constants["tls_server_write_iv"], iv)
    machine.mem_write(
        constants["tls_server_record_seq"], sequence.to_bytes(8, "big")
    )
    machine.mem_write(
        MDA_SPOOL_ADDR - MDA_GUARD_LEN, MDA_PREFIX_GUARD
    )
    machine.mem_write(MDA_SPOOL_ADDR, MDA_SPOOL_FILL)
    machine.mem_write(MDA_SPOOL_ADDR + MDA_SPOOL_LEN, MDA_SUFFIX_GUARD)
    write_u16(machine, constants["video_seg"], video_segment)
    write_u16(
        machine, labels["nic_vt_rx_fallback"], labels["tls13_test_rx_fallback"]
    )
    write_u16(machine, labels["tls13_test_stream_ptr"], RX_INPUT_ADDR)
    write_u16(machine, labels["tls13_test_stream_remaining"], len(wire))
    write_u16(machine, labels["tls13_test_stream_chunk"], chunk)
    write_u16(machine, labels["tls13_test_publish_ptr"], RX_OUTPUT_ADDR)
    write_u16(machine, labels["tls13_test_publish_len"], 0)
    write_u16(machine, labels["tls13_test_publish_calls"], 0)
    write_u16(machine, constants["tls_buffered_payload_ptr"], 0)
    write_u16(machine, constants["tls_buffered_payload_len"], 0)
    return output_fill, output_guard


def assert_mda_spool_guards(machine: Uc, case: str) -> None:
    if (
        bytes(
            machine.mem_read(
                MDA_SPOOL_ADDR - MDA_GUARD_LEN, MDA_GUARD_LEN
            )
        )
        != MDA_PREFIX_GUARD
    ):
        raise AssertionError(f"{case}: MDA spool prefix guard changed")
    if (
        bytes(
            machine.mem_read(
                MDA_SPOOL_ADDR + MDA_SPOOL_LEN, MDA_GUARD_LEN
            )
        )
        != MDA_SUFFIX_GUARD
    ):
        raise AssertionError(f"{case}: MDA spool suffix guard changed")


def assert_rejected_without_publish(
    machine: Uc,
    entry: int,
    labels: dict[str, int],
    constants: dict[str, int],
    sequence: int,
    output_fill: bytes,
    output_guard: bytes,
    case: str,
) -> None:
    carry = execute_returning(machine, entry)
    if not carry:
        raise AssertionError(f"{case}: forged/unsupported record was accepted")
    if read_u16(machine, labels["tls13_test_publish_len"]) != 0:
        raise AssertionError(f"{case}: rejected record published plaintext bytes")
    if read_u16(machine, labels["tls13_test_publish_calls"]) != 0:
        raise AssertionError(f"{case}: rejected record entered the product parser")
    if bytes(machine.mem_read(RX_OUTPUT_ADDR, len(output_fill))) != output_fill:
        raise AssertionError(f"{case}: rejected record changed parser output state")
    if (
        bytes(machine.mem_read(RX_OUTPUT_ADDR - len(output_guard), len(output_guard)))
        != output_guard
    ):
        raise AssertionError(f"{case}: rejected record changed output prefix canary")
    if (
        bytes(machine.mem_read(RX_OUTPUT_ADDR + len(output_fill), len(output_guard)))
        != output_guard
    ):
        raise AssertionError(f"{case}: rejected record changed output suffix canary")
    if (
        bytes(machine.mem_read(constants["tls_server_record_seq"], 8))
        != sequence.to_bytes(8, "big")
    ):
        raise AssertionError(f"{case}: rejected record consumed a server sequence")
    assert_mda_spool_guards(machine, case)


def run_receive_valid_case(
    image: bytes,
    entry: int,
    labels: dict[str, int],
    constants: dict[str, int],
    plain_len: int,
    sequence: int,
    chunk: int,
    video_segment: int = 0xB800,
    padding_len: int = 0,
) -> str:
    machine = make_machine(image)
    initialize_runtime_constants(machine, constants)
    key = hashlib.sha256(b"Seed TLS 1.3 application opener key").digest()
    iv = hashlib.sha256(b"Seed TLS 1.3 application opener iv").digest()[:12]
    plain = bytes(((index * 149) + plain_len) & 0xFF for index in range(plain_len))
    wire = server_record(
        key, iv, sequence, plain, padding_len=padding_len
    )
    output_fill, output_guard = initialize_receive_case(
        machine,
        labels,
        constants,
        wire,
        key,
        iv,
        sequence,
        chunk,
        video_segment,
    )
    carry = execute_returning(machine, entry)
    if carry:
        raise AssertionError(
            f"opener rejected len={plain_len}, pad={padding_len}, "
            f"seq={sequence:#x}, chunk={chunk}"
        )
    published_len = read_u16(machine, labels["tls13_test_publish_len"])
    if published_len != plain_len:
        raise AssertionError(
            f"opener length mismatch len={plain_len}: published={published_len}"
        )
    actual = bytes(machine.mem_read(RX_OUTPUT_ADDR, plain_len))
    if actual != plain:
        raise AssertionError(
            f"opener plaintext mismatch len={plain_len}, pad={padding_len}, "
            f"chunk={chunk}"
        )
    if bytes(
        machine.mem_read(
            RX_OUTPUT_ADDR + plain_len,
            AUTH_SPOOL_LEN - plain_len,
        )
    ) != output_fill[plain_len:]:
        raise AssertionError(f"opener wrote beyond published len={plain_len}")
    if (
        bytes(machine.mem_read(RX_OUTPUT_ADDR - len(output_guard), len(output_guard)))
        != output_guard
    ):
        raise AssertionError(f"opener prefix canary changed at len={plain_len}")
    if (
        bytes(
            machine.mem_read(
                RX_OUTPUT_ADDR + AUTH_SPOOL_LEN,
                len(output_guard),
            )
        )
        != output_guard
    ):
        raise AssertionError(f"opener suffix canary changed at len={plain_len}")
    expected_seq = next_sequence(sequence)
    if (
        bytes(machine.mem_read(constants["tls_server_record_seq"], 8))
        != expected_seq.to_bytes(8, "big")
    ):
        raise AssertionError(
            f"opener sequence mismatch len={plain_len}, seq={sequence:#x}"
        )
    assert_mda_spool_guards(
        machine,
        f"valid len={plain_len}, pad={padding_len}, video={video_segment:#x}",
    )
    if video_segment == 0xB000:
        inner_len = plain_len + 1 + padding_len
        if bytes(
            machine.mem_read(
                MDA_SPOOL_ADDR + inner_len, MDA_SPOOL_LEN - inner_len
            )
        ) != MDA_SPOOL_FILL[inner_len:]:
            raise AssertionError(
                f"MDA opener wrote beyond inner len={inner_len}"
            )
    elif bytes(machine.mem_read(MDA_SPOOL_ADDR, MDA_SPOOL_LEN)) != MDA_SPOOL_FILL:
        raise AssertionError("CGA opener unexpectedly touched conventional MDA spool")
    return hashlib.sha256(actual).hexdigest()


def run_receive_valid_nst_case(
    image: bytes,
    entry: int,
    labels: dict[str, int],
    constants: dict[str, int],
    messages: tuple[bytes, ...],
    sequence: int,
    chunk: int,
    video_segment: int = 0xB800,
    padding_len: int = 0,
) -> str:
    machine = make_machine(image)
    initialize_runtime_constants(machine, constants)
    key = hashlib.sha256(b"Seed TLS 1.3 NST drain key").digest()
    iv = hashlib.sha256(b"Seed TLS 1.3 NST drain iv").digest()[:12]
    plain = b"".join(messages)
    wire = server_record(
        key,
        iv,
        sequence,
        plain,
        inner_type=TLS.CONTENT_HANDSHAKE,
        padding_len=padding_len,
    )
    output_fill, output_guard = initialize_receive_case(
        machine,
        labels,
        constants,
        wire,
        key,
        iv,
        sequence,
        chunk,
        video_segment,
    )
    if execute_returning(machine, entry):
        raise AssertionError(
            f"NST drain rejected messages={len(messages)}, pad={padding_len}, "
            f"chunk={chunk}, video={video_segment:#x}"
        )
    if read_u16(machine, labels["tls13_test_publish_len"]) != 0:
        raise AssertionError("NST drain published handshake bytes as application data")
    if read_u16(machine, labels["tls13_test_publish_calls"]) != 0:
        raise AssertionError("NST drain entered the product response parser")
    if read_u16(machine, constants["tls_app_len"]) != 0:
        raise AssertionError("NST drain left application bytes published")
    if bytes(machine.mem_read(RX_OUTPUT_ADDR, len(output_fill))) != output_fill:
        raise AssertionError("NST drain changed parser output state")
    if (
        bytes(machine.mem_read(RX_OUTPUT_ADDR - len(output_guard), len(output_guard)))
        != output_guard
        or bytes(
            machine.mem_read(RX_OUTPUT_ADDR + len(output_fill), len(output_guard))
        )
        != output_guard
    ):
        raise AssertionError("NST drain changed an output canary")
    if (
        bytes(machine.mem_read(constants["tls_server_record_seq"], 8))
        != next_sequence(sequence).to_bytes(8, "big")
    ):
        raise AssertionError("NST drain did not consume exactly one server record")
    assert_mda_spool_guards(machine, "valid NST drain")
    return hashlib.sha256(plain).hexdigest()


def run_receive_rejection_cases(
    image: bytes,
    entry: int,
    labels: dict[str, int],
    constants: dict[str, int],
) -> list[str]:
    key = hashlib.sha256(b"Seed TLS 1.3 rejected opener key").digest()
    iv = hashlib.sha256(b"Seed TLS 1.3 rejected opener iv").digest()[:12]
    sequence = 0x0102030405060708
    plain = bytes((index * 73 + 9) & 0xFF for index in range(701))
    valid = server_record(key, iv, sequence, plain)
    cases: list[tuple[str, bytes, int, int]] = []
    for name, offset, chunk in (
        ("ciphertext-first", 5, 1),
        ("ciphertext-middle", 5 + len(plain) // 2, 63),
        ("tag-first", len(valid) - TLS.AEAD_TAG_LEN, 384),
        ("tag-last", len(valid) - 1, 577),
    ):
        tampered = bytearray(valid)
        tampered[offset] ^= 0x80
        cases.append((name, bytes(tampered), chunk, 0xB800))
    valid_nst = new_session_ticket(b"N" * 32)
    bad_nst_messages: list[tuple[str, bytes]] = []
    wrong_message_type = bytearray(valid_nst)
    wrong_message_type[0] = 5
    bad_nst_messages.append(("wrong-post-handshake-message", bytes(wrong_message_type)))
    high_handshake_length = bytearray(valid_nst)
    high_handshake_length[1] = 1
    bad_nst_messages.append(("unbounded-NST-length", bytes(high_handshake_length)))
    bad_nst_messages.append(("truncated-NST", valid_nst[:-1]))
    zero_lifetime = bytearray(valid_nst)
    zero_lifetime[4:8] = bytes(4)
    bad_nst_messages.append(("zero-NST-lifetime", bytes(zero_lifetime)))
    long_lifetime = bytearray(valid_nst)
    long_lifetime[4:8] = (604801).to_bytes(4, "big")
    bad_nst_messages.append(("long-NST-lifetime", bytes(long_lifetime)))
    zero_nonce = bytearray(valid_nst)
    zero_nonce[12] = 0
    bad_nst_messages.append(("zero-NST-nonce", bytes(zero_nonce)))
    identity_length_offset = 13 + len(b"seed-nst")
    zero_identity = bytearray(valid_nst)
    zero_identity[identity_length_offset : identity_length_offset + 2] = bytes(2)
    bad_nst_messages.append(("zero-NST-identity", bytes(zero_identity)))
    long_identity = bytearray(valid_nst)
    long_identity[identity_length_offset : identity_length_offset + 2] = (
        193
    ).to_bytes(2, "big")
    bad_nst_messages.append(("long-NST-identity", bytes(long_identity)))
    extension_length_offset = identity_length_offset + 2 + 32
    wrong_extension_vector = bytearray(valid_nst)
    wrong_extension_vector[
        extension_length_offset : extension_length_offset + 2
    ] = (1).to_bytes(2, "big")
    bad_nst_messages.append(
        ("wrong-NST-extension-vector", bytes(wrong_extension_vector))
    )
    bad_nst_messages.append(
        (
            "malformed-NST-early-data",
            new_session_ticket(
                b"N" * 32,
                extensions=((42, bytes(3)),),
            ),
        )
    )
    for index, (name, message) in enumerate(bad_nst_messages):
        cases.append(
            (
                name,
                server_record(
                    key,
                    iv,
                    sequence,
                    message,
                    inner_type=TLS.CONTENT_HANDSHAKE,
                    padding_len=index % 3,
                ),
                (1, 127, 384)[index % 3],
                0xB800,
            )
        )
    oversized_nst = b"".join(
        new_session_ticket(b"O" * 192) for _ in range(3)
    )
    cases.append(
        (
            "oversized-NST-record",
            server_record(
                key,
                iv,
                sequence,
                oversized_nst,
                inner_type=TLS.CONTENT_HANDSHAKE,
            ),
            384,
            0xB800,
        )
    )
    cases.append(
        (
            "authenticated-all-zero-inner",
            server_record(
                key, iv, sequence, b"", inner_type=0, padding_len=16
            ),
            3,
            0xB800,
        )
    )
    mda_cipher_tampered = bytearray(valid)
    mda_cipher_tampered[5 + len(plain) // 3] ^= 0x20
    cases.append(
        (
            "mda-ciphertext-tamper",
            bytes(mda_cipher_tampered),
            37,
            0xB000,
        )
    )
    mda_tag_tampered = bytearray(valid)
    mda_tag_tampered[-3] ^= 0x04
    cases.append(
        ("mda-tag-tamper", bytes(mda_tag_tampered), 191, 0xB000)
    )
    cases.append(
        (
            "mda-wrong-post-handshake-message",
            server_record(
                key,
                iv,
                sequence,
                bytes(wrong_message_type),
                inner_type=TLS.CONTENT_HANDSHAKE,
                padding_len=5,
            ),
            1,
            0xB000,
        )
    )

    fingerprints: list[str] = []
    for name, wire, chunk, video_segment in cases:
        machine = make_machine(image)
        initialize_runtime_constants(machine, constants)
        output_fill, output_guard = initialize_receive_case(
            machine,
            labels,
            constants,
            wire,
            key,
            iv,
            sequence,
            chunk,
            video_segment,
        )
        assert_rejected_without_publish(
            machine,
            entry,
            labels,
            constants,
            sequence,
            output_fill,
            output_guard,
            name,
        )
        fingerprints.append(hashlib.sha256(wire).hexdigest())

    # Sequence exhaustion is rejected before consuming transport or publishing.
    machine = make_machine(image)
    initialize_runtime_constants(machine, constants)
    exhausted = 0xFFFFFFFFFFFFFFFF
    output_fill, output_guard = initialize_receive_case(
        machine, labels, constants, valid, key, iv, exhausted, 384
    )
    stream_before = read_u16(machine, labels["tls13_test_stream_remaining"])
    assert_rejected_without_publish(
        machine,
        entry,
        labels,
        constants,
        exhausted,
        output_fill,
        output_guard,
        "server-sequence-exhausted",
    )
    if read_u16(machine, labels["tls13_test_stream_remaining"]) != stream_before:
        raise AssertionError("server-sequence-exhausted: consumed transport bytes")
    fingerprints.append(hashlib.sha256(b"sequence-exhausted").hexdigest())

    # A legal but unsupported oversized unpadded inner record is rejected from
    # its authenticated length before any ciphertext is staged or published.
    oversized_plain = bytes(AUTH_SPOOL_LEN + 1)
    oversized = server_record(key, iv, sequence, oversized_plain)
    machine = make_machine(image)
    initialize_runtime_constants(machine, constants)
    output_fill, output_guard = initialize_receive_case(
        machine, labels, constants, oversized, key, iv, sequence, 384
    )
    assert_rejected_without_publish(
        machine,
        entry,
        labels,
        constants,
        sequence,
        output_fill,
        output_guard,
        "oversized-inner",
    )
    fingerprints.append(hashlib.sha256(oversized).hexdigest())

    mda_oversized_plain = bytes(MDA_SPOOL_LEN)
    mda_oversized = server_record(
        key, iv, sequence, mda_oversized_plain
    )
    machine = make_machine(image)
    initialize_runtime_constants(machine, constants)
    output_fill, output_guard = initialize_receive_case(
        machine,
        labels,
        constants,
        mda_oversized,
        key,
        iv,
        sequence,
        383,
        0xB000,
    )
    assert_rejected_without_publish(
        machine,
        entry,
        labels,
        constants,
        sequence,
        output_fill,
        output_guard,
        "mda-oversized-inner",
    )
    if bytes(machine.mem_read(MDA_SPOOL_ADDR, MDA_SPOOL_LEN)) != MDA_SPOOL_FILL:
        raise AssertionError("MDA oversized record touched the conventional spool")
    fingerprints.append(hashlib.sha256(mda_oversized).hexdigest())

    # The first TCP payload may contain a complete authenticated record followed
    # by bytes from the next record.  That tail is copied into retired handshake
    # scratch before replay, so an over-advertised transport length must fail
    # before the first record is published or its sequence is consumed.
    tail_limit = constants["tls_pre_response_tail_len"]
    valid_first = server_record(key, iv, sequence, b"valid first record")
    oversized_tail = valid_first + bytes([0x5A]) * (tail_limit + 1)
    machine = make_machine(image)
    initialize_runtime_constants(machine, constants)
    output_fill, output_guard = initialize_receive_case(
        machine,
        labels,
        constants,
        oversized_tail,
        key,
        iv,
        sequence,
        len(oversized_tail),
    )
    assert_rejected_without_publish(
        machine,
        entry,
        labels,
        constants,
        sequence,
        output_fill,
        output_guard,
        "oversized-buffered-tail",
    )
    fingerprints.append(hashlib.sha256(oversized_tail).hexdigest())
    return fingerprints


def run_receive_buffered_pair(
    image: bytes,
    entry: int,
    labels: dict[str, int],
    constants: dict[str, int],
    chunk: int,
    padding_len: int,
) -> str:
    machine = make_machine(image)
    initialize_runtime_constants(machine, constants)
    key = hashlib.sha256(b"Seed TLS 1.3 buffered opener key").digest()
    iv = hashlib.sha256(b"Seed TLS 1.3 buffered opener iv").digest()[:12]
    sequence = 9
    # Match the exact first live OpenAI response geometry seen on the
    # conforming-floor wire: a 466-byte post-handshake record (444 content
    # bytes) followed in the same 490-byte TCP payload by one 24-byte
    # application record.  Two complete bounded NSTs deliberately occupy the
    # first record, so the test covers both the authenticated disposable drain
    # and preservation of the following application record.
    one_nst = new_session_ticket(
        b"T" * 192,
        extensions=((0x1234, b"x"),),
    )
    first = one_nst + one_nst
    if len(first) != 444:
        raise AssertionError("exact live NST fixture geometry drifted")
    second = b"ok"
    wire = (
        server_record(
            key,
            iv,
            sequence,
            first,
            inner_type=TLS.CONTENT_HANDSHAKE,
            padding_len=padding_len,
        )
        + server_record(key, iv, sequence + 1, second)
    )
    initialize_receive_case(
        machine, labels, constants, wire, key, iv, sequence, chunk
    )
    if execute_returning(machine, entry):
        raise AssertionError(
            f"buffered pair chunk={chunk}, pad={padding_len}: "
            "first record rejected"
        )
    if read_u16(machine, labels["tls13_test_publish_calls"]) != 0:
        raise AssertionError(
            f"buffered pair chunk={chunk}, pad={padding_len}: "
            "NST entered response parser"
        )
    if execute_returning(machine, entry):
        raise AssertionError(
            f"buffered pair chunk={chunk}, pad={padding_len}: "
            "second record rejected"
        )
    published_len = read_u16(machine, labels["tls13_test_publish_len"])
    actual = bytes(machine.mem_read(RX_OUTPUT_ADDR, published_len))
    if actual != second:
        raise AssertionError(
            f"buffered pair chunk={chunk}, pad={padding_len}: "
            "NST drain or application tail preservation failed"
        )
    if (
        bytes(machine.mem_read(constants["tls_server_record_seq"], 8))
        != (sequence + 2).to_bytes(8, "big")
    ):
        raise AssertionError(
            f"buffered pair chunk={chunk}, pad={padding_len}: "
            "sequence did not advance twice"
        )
    assert_mda_spool_guards(
        machine, f"buffered pair chunk={chunk}, pad={padding_len}"
    )
    return hashlib.sha256(actual).hexdigest()


def main() -> int:
    constants = CHECK_LAYOUT.parse_equates([LAYOUT, DATA])
    required = (
        "tls_app_record_buffer",
        "tls_app_record_buffer_len",
        "tls13_app_record_buffer_len",
        "hmac_prepared_inner_state",
        "tls_app_len",
        "tls_app_record_len",
        "tls_tx_len",
        "tls_client_write_key",
        "tls_client_write_iv",
        "tls_client_record_seq",
        "tls_server_write_key",
        "tls_server_write_iv",
        "tls_server_record_seq",
        "tls_buffered_payload_ptr",
        "tls_buffered_payload_len",
        "tls_pre_response_tail_len",
        "video_seg",
        "low_static_constants_start",
        "low_static_constants_len",
    )
    missing = [name for name in required if name not in constants]
    if missing:
        raise AssertionError(f"unresolved layout constants: {', '.join(missing)}")
    expected_capacity = (
        constants["api_request_plain_len"]
        + constants["tls_record_header_len"]
        + constants["tls_aead_tag_len"]
        + constants["tls13_inner_type_len"]
    )
    if constants["tls13_app_record_buffer_len"] != expected_capacity:
        raise AssertionError("TLS 1.3 record buffer capacity is stale")
    record_end = (
        constants["tls_app_record_buffer"] + constants["tls13_app_record_buffer_len"]
    )
    if record_end != (
        constants["hmac_prepared_inner_state"] + constants["tls13_inner_type_len"]
    ):
        raise AssertionError("TLS 1.3 inner-type/HMAC lifetime alias drifted")
    tls13_source = (BOOT / "core/tls13_app.inc").read_text()
    if not re.search(
        rf"^tls13_auth_spool_len\s+equ\s+{AUTH_SPOOL_LEN:#x}\s*$",
        tls13_source,
        re.MULTILINE,
    ):
        raise AssertionError("authenticated receive spool/checker capacity drifted")
    if not re.search(
        rf"^tls13_mda_auth_spool_offset\s+equ\s+{MDA_SPOOL_ADDR:#x}\s*$",
        tls13_source,
        re.MULTILINE,
    ) or not re.search(
        rf"^tls13_mda_auth_spool_len\s+equ\s+{MDA_SPOOL_LEN:#x}\s*$",
        tls13_source,
        re.MULTILINE,
    ):
        raise AssertionError("MDA authenticated spool/checker geometry drifted")

    with tempfile.TemporaryDirectory(prefix="seed-tls13-app-") as raw_work:
        work = Path(raw_work)
        image, listing = build_image(work)
        app_code_end = listing_symbol_address(listing, "tls13_app_code_end")
        linked_k_end = listing_symbol_address(listing, "core_link_window_end")
        if app_code_end > MDA_SPOOL_ADDR:
            raise AssertionError(
                f"TLS 1.3 app ends at {app_code_end:#x}, inside MDA spool"
            )
        if linked_k_end > (MDA_SPOOL_ADDR - MDA_GUARD_LEN):
            raise AssertionError(
                f"oracle K ends at {linked_k_end:#x}, inside MDA prefix guard"
            )
        seal_entry = listing_symbol_address(
            listing, "tls_build_application_data_record"
        )
        open_entry = listing_symbol_address(listing, "tls_receive_application_data")
        labels = {
            name: listing_symbol_address(listing, name)
            for name in (
                "tls_app_plain_ptr",
                "nic_vt_rx_fallback",
                "tls13_test_rx_fallback",
                "tls13_test_stream_ptr",
                "tls13_test_stream_remaining",
                "tls13_test_stream_chunk",
                "tls13_test_publish_ptr",
                "tls13_test_publish_len",
                "tls13_test_publish_calls",
            )
        }
        seal_cases = (
            (0, 0),
            (1, 1),
            (15, 0x0102030405060708),
            (16, 0x8877665544332211),
            (17, 2),
            (63, 3),
            (64, 4),
            (65, 5),
            (439, 0x7FFFFFFFFFFFFFFF),
            (440, 0xFFFFFFFFFFFFFFFF),
        )
        seal_fingerprints = [
            run_case(image, seal_entry, labels, constants, length, sequence)
            for length, sequence in seal_cases
        ]
        open_cases = (
            (0, 0, 1, 0xB800),
            (1, 1, 5, 0xB800),
            (63, 0x0102030405060708, 17, 0xB800),
            (64, 2, 64, 0xB800),
            (65, 3, 65, 0xB800),
            (575, 4, 127, 0xB800),
            (576, 5, 191, 0xB800),
            (577, 6, 384, 0xB800),
            (1024, 0x7FFFFFFFFFFFFFFF, 577, 0xB800),
            (AUTH_SPOOL_LEN - 1, 0xFFFFFFFFFFFFFFFE, 384, 0xB800),
            (AUTH_SPOOL_LEN, 7, 383, 0xB800),
            (0, 11, 1, 0xB000),
            (1, 12, 5, 0xB000),
            (63, 13, 17, 0xB000),
            (575, 14, 127, 0xB000),
            (2047, 15, 191, 0xB000),
            (MDA_SPOOL_LEN - 1, 16, 383, 0xB000),
        )
        open_fingerprints = [
            run_receive_valid_case(
                image,
                open_entry,
                labels,
                constants,
                length,
                sequence,
                chunk,
                video_segment,
            )
            for length, sequence, chunk, video_segment in open_cases
        ]
        padded_open_cases = (
            (0, 17, 1, 1, 0xB800),
            (1, 18, 5, 63, 0xB800),
            (63, 19, 17, 64, 0xB800),
            (64, 20, 64, 65, 0xB800),
            (443, 21, 384, 1, 0xB800),
            (1024, 22, 577, 127, 0xB800),
            (AUTH_SPOOL_LEN - 1, 23, 383, 1, 0xB800),
            (0, 24, 1, 1, 0xB000),
            (63, 25, 17, 64, 0xB000),
            (1536, 26, 191, 511, 0xB000),
            (MDA_SPOOL_LEN - 2, 27, 383, 1, 0xB000),
        )
        padded_open_fingerprints = [
            run_receive_valid_case(
                image,
                open_entry,
                labels,
                constants,
                length,
                sequence,
                chunk,
                video_segment,
                padding_len,
            )
            for (
                length,
                sequence,
                chunk,
                padding_len,
                video_segment,
            ) in padded_open_cases
        ]
        nst_messages = (
            (
                new_session_ticket(b"A"),
            ),
            (
                new_session_ticket(
                    b"B" * 192,
                    nonce=b"n" * 32,
                    lifetime=1,
                    extensions=((42, (2048).to_bytes(4, "big")),),
                ),
            ),
            (
                new_session_ticket(
                    b"C" * 96,
                    extensions=((0x1234, b"unknown"),),
                ),
                new_session_ticket(b"D" * 128, lifetime=86400),
            ),
        )
        nst_open_cases = (
            (nst_messages[0], 28, 1, 0xB800, 0),
            (nst_messages[1], 29, 127, 0xB800, 17),
            (nst_messages[2], 30, 384, 0xB800, 1),
            (nst_messages[0], 31, 5, 0xB000, 0),
            (nst_messages[1], 32, 191, 0xB000, 31),
            (nst_messages[2], 33, 383, 0xB000, 1),
        )
        nst_open_fingerprints = [
            run_receive_valid_nst_case(
                image,
                open_entry,
                labels,
                constants,
                messages,
                sequence,
                chunk,
                video_segment,
                padding_len,
            )
            for (
                messages,
                sequence,
                chunk,
                video_segment,
                padding_len,
            ) in nst_open_cases
        ]
        rejection_fingerprints = run_receive_rejection_cases(
            image, open_entry, labels, constants
        )
        # Exercise both the host-capture shape and the guest's advertised-MSS
        # split.  The first TLS record spans the 384-byte boundary while the
        # second record is coalesced into the final 106-byte TCP payload.
        buffered_fingerprints = [
            run_receive_buffered_pair(
                image, open_entry, labels, constants, chunk, padding_len
            )
            for chunk in (490, 384)
            for padding_len in (0, 1, 17)
        ]

    aggregate = hashlib.sha256(
        "".join(
            seal_fingerprints
            + open_fingerprints
            + padded_open_fingerprints
            + nst_open_fingerprints
            + rejection_fingerprints
            + buffered_fingerprints
        ).encode()
    ).hexdigest()
    print("TLS 1.3 product application-record seal/open: PASS")
    print(
        f"  cpu: 8086 ({len(seal_cases)} seal + {len(open_cases)} unpadded open "
        f"+ {len(padded_open_cases)} padded open "
        f"+ {len(nst_open_cases)} NST drain "
        f"+ {len(rejection_fingerprints)} reject + buffered-pair cases)"
    )
    print(
        f"  outbound plaintext: 0..{constants['api_request_plain_len']} bytes"
    )
    print(f"  record capacity: {constants['tls13_app_record_buffer_len']} bytes")
    print(f"  authenticated CGA plaintext: 0..{AUTH_SPOOL_LEN} bytes")
    print(
        f"  authenticated MDA plaintext: 0..{MDA_SPOOL_LEN - 1} bytes "
        f"(inner <= {MDA_SPOOL_LEN})"
    )
    print(
        f"  linked app/oracle K end: {app_code_end:#x}/{linked_k_end:#x}; "
        f"MDA spool: {MDA_SPOOL_ADDR:#x}.."
        f"{MDA_SPOOL_ADDR + MDA_SPOOL_LEN:#x}"
    )
    print(
        "  peer hint: advertise record_size_limit=2048; "
        "local authenticated-spool limits remain authoritative"
    )
    print(
        "  reject invariant: zero parser calls/bytes/state change; "
        "server sequence unchanged"
    )
    print(f"  aggregate: {aggregate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
