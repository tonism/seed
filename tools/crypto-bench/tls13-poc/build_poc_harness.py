#!/usr/bin/env python3
"""Assemble the product-shaped TLS 1.3 phase container and its K overlays."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/crypto-bench/tls13-poc"
HARNESS = HERE / "poc_harness.asm"
LITERAL_RUNNER = HERE.parent / "tls13-spike" / "run_8088_16k.py"
ENTROPY_MODE = "deterministic-coherent-chain-durability"
ENTROPY_LIMITATION = (
    "Byte-exact chain fixture: skips PIT/BDA collector mixing. It proves the "
    "BIOS write/reset/reread gate, not physical min-entropy or secure entropy."
)
K14 = False

OVERLAYS = (
    ("entropy_ratchet", HERE / "entropy_ratchet_overlay.asm", ()),
    ("keygen", HERE / "keygen_overlay.asm", ()),
    ("hello", HERE / "hello_overlay.asm", ()),
    (
        "auth_p256",
        HERE / "auth_p256_overlay.asm",
        ("AUTH_P256_SYNTHETIC_PIN",),
    ),
    ("mlkem_candidate", HERE / "mlkem_candidate_kernel.asm", ()),
    ("tls13_sym", HERE / "tls13_sym_overlay.asm", ()),
    ("fo_tail", HERE / "fo_tail_kernel.asm", ()),
)


def run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def assemble(
    source: Path, stem: str, *, defines: tuple[str, ...] = ()
) -> Path:
    binary = BUILD / f"{stem}.bin"
    listing = BUILD / f"{stem}.lst"
    command = [
        "nasm",
        "-f",
        "bin",
        f"-I{ROOT}/",
        f"-I{HERE}/",
        f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
    ]
    active_defines = (("TLS13_POC_K14",) if K14 else ()) + defines
    for define in active_defines:
        command.extend(["-D", define])
    command.extend(
        [
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(source),
        ]
    )
    run(command)
    return binary


def load_module(name: str, source: Path):
    spec = importlib.util.spec_from_file_location(name, source)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_fixture(name: str, value: bytes) -> Path:
    output = BUILD / name
    output.write_bytes(value)
    return output


def build_composite(
    name: str,
    overlay: Path,
    controller: Path,
    *,
    controller_address: int,
) -> Path:
    offset = controller_address - 0x1800
    overlay_bytes = overlay.read_bytes()
    controller_bytes = controller.read_bytes()
    if offset < len(overlay_bytes):
        raise AssertionError(
            f"{name} controller overlaps overlay: {len(overlay_bytes)} > {offset}"
        )
    encoded = overlay_bytes + bytes(offset - len(overlay_bytes)) + controller_bytes
    k_end = 0x3400 if K14 else 0x3600
    if len(encoded) > k_end - 0x1800:
        raise AssertionError(f"{name} composite exceeds K")
    return write_fixture(name, encoded)


def build_hello_controller_stage(controller: Path) -> Path:
    raw = controller.read_bytes()
    stage_address = 0x0D60
    target_address = 0x0F00
    if len(raw) > 0x100:
        raise AssertionError("HELLO low controller exceeds 0f00..1000")
    stub_len = 14
    source_address = stage_address + stub_len
    jump_from = stage_address + stub_len
    displacement = (target_address - jump_from) & 0xFFFF
    stub = (
        b"\xBE"
        + struct.pack("<H", source_address)
        + b"\xBF"
        + struct.pack("<H", target_address)
        + b"\xB9"
        + struct.pack("<H", len(raw))
        + b"\xF3\xA4\xE9"
        + struct.pack("<H", displacement)
    )
    if len(stub) != stub_len or len(stub) + len(raw) > 512:
        raise AssertionError("HELLO low controller no longer fits one stage sector")
    return write_fixture("hello_controller.bin", stub + raw)


def verify_resident_telemetry_contract(container: Path) -> None:
    resident_scheduler = container.read_bytes()[:0x600]
    bios_first = b"\xB4\x0E\xBB\x07\x00\xCD\x10"
    bounded_serial = (
        b"\xB5\x01\xBA\xFD\x03\xEC\xA8\x20\x75\x04\xE2\xF9"
        b"\xEB\x06\xBA\xF8\x03\x88\xE0\xEE"
    )
    bios_at = resident_scheduler.find(bios_first)
    serial_at = resident_scheduler.find(bounded_serial)
    if bios_at < 0 or serial_at < 0 or bios_at >= serial_at:
        raise AssertionError(
            "resident progress must BIOS-print before bounded COM1 telemetry"
        )
    if b"\xEC\xA8\x20\x74\xFB" in resident_scheduler:
        raise AssertionError("resident progress regained an unbounded COM1 poll")


def parse_phase_output(raw: str) -> tuple[str, bool, str]:
    source_lines = raw.splitlines()
    phase_lines: list[str] = []
    started = False
    for source_line in source_lines:
        line = source_line.strip()
        if not started:
            marker_at = line.find("TLS13 POC")
            if marker_at < 0:
                continue
            line = line[marker_at:]
            started = True
        phase_lines.append(line)
        if line == "RESULT":
            break
    phase_text = "\n".join(phase_lines) + ("\n" if phase_lines else "")
    terminals = [line for line in phase_lines if line in {"PASS", "FAIL"}]
    has_result = bool(phase_lines) and phase_lines[-1] == "RESULT"
    success = has_result and terminals == ["PASS"]
    failed = has_result and "FAIL" in terminals
    status = "pass" if success else "failure" if failed else "invalid-terminal"
    return phase_text, success, status


def verify_terminal_contract(container: Path) -> None:
    resident_scheduler = container.read_bytes()[:0x600]
    for token in (b"PASS\0", b"FAIL\0", b"RESULT\0"):
        if token not in resident_scheduler:
            raise AssertionError(f"resident terminal token drifted: {token!r}")
    if b"DONE\0" in resident_scheduler:
        raise AssertionError("obsolete ambiguous DONE token returned")
    cases = (
        ("TLS13 POC\nPASS\nRESULT\n", True, "pass"),
        ("TLS13 POC\nENT!\nFAIL\nRESULT\n", False, "failure"),
        ("TLS13 POC\nDONE\n", False, "invalid-terminal"),
        ("TLS13 POC\nPASS\nFAIL\nRESULT\n", False, "failure"),
    )
    for raw, expected_success, expected_status in cases:
        _phase, success, status = parse_phase_output(raw)
        if (success, status) != (expected_success, expected_status):
            raise AssertionError("phase terminal parser contract drifted")


def verify_deterministic_entropy_controller(controller: Path) -> None:
    image = controller.read_bytes()
    calls = {
        "supplement_reset": b"\xFF\x16\x24\x18",
        "supplement_append": b"\xFF\x16\x26\x18",
        "collector": b"\xFF\x16\x28\x18",
        "prepare": b"\xFF\x16\x2A\x18",
        "verify": b"\xFF\x16\x2C\x18",
        "get_dz": b"\xFF\x16\x2E\x18",
        "bios_write": b"\xFF\x16\x19\x10",
        "disk_reset": b"\xFF\x16\x1B\x10",
        "phase_read": b"\xFF\x16\x17\x10",
    }
    if calls["collector"] in image:
        raise AssertionError("deterministic chain unexpectedly mixes timing collector")
    reset_at = image.find(calls["supplement_reset"])
    append_at = image.find(calls["supplement_append"])
    prepare_at = image.find(calls["prepare"])
    write_at = image.find(calls["bios_write"])
    flush_at = image.find(calls["disk_reset"], write_at + 1)
    reread_at = image.find(calls["phase_read"], flush_at + 1)
    verify_at = image.find(calls["verify"], reread_at + 1)
    release_at = image.find(calls["get_dz"], verify_at + 1)
    if not (
        0 <= reset_at < append_at < prepare_at < write_at
        < flush_at < reread_at < verify_at < release_at
    ):
        raise AssertionError(
            "deterministic entropy durability/release call order drifted"
        )


def listing_label_address(listing: Path, label: str, origin: int) -> int:
    lines = listing.read_text(encoding="utf-8").splitlines()
    label_pattern = re.compile(
        rf"(?<![A-Za-z0-9_.$?]){re.escape(label)}:"
    )
    offset_pattern = re.compile(r"\s([0-9A-F]{8})\s")
    for index, line in enumerate(lines):
        if not label_pattern.search(line):
            continue
        for candidate in lines[index:]:
            match = offset_pattern.search(candidate)
            if match:
                return origin + int(match.group(1), 16)
    raise AssertionError(f"missing NASM listing label: {label}")


def verify_full_memory_hello_handoff(
    container: Path, chain: "ChainFixtures"
) -> None:
    """Execute the active resident KeyGen-to-HELLO stager over a 16 KiB map."""

    from unicorn import UC_ARCH_X86, UC_MODE_16, Uc
    from unicorn.x86_const import (
        UC_X86_REG_DS,
        UC_X86_REG_EFLAGS,
        UC_X86_REG_ES,
        UC_X86_REG_IP,
        UC_X86_REG_SS,
    )

    listing = container.with_suffix(".lst")
    stage_start = listing_label_address(
        listing, ".hello_full_memory_stage_begin", 0x1000
    )
    stage_end = listing_label_address(
        listing, ".hello_full_memory_stage_end", 0x1000
    )
    if not 0x1000 <= stage_start < stage_end <= 0x1800:
        raise AssertionError("active HELLO stager escaped the resident prefix")

    attempt_start = 0x3B9C
    attempt_bytes = 32 + 32 + 32 + 4 + 2
    ticket_start = 0x3000 if K14 else 0x3200
    ticket_bytes = 192
    publication_start = 0x0700
    publication_bytes = 32 + 32
    fixture = chain.hello_inputs_sector
    if len(fixture) != 512:
        raise AssertionError("HELLO input fixture is not exactly one sector")
    if attempt_bytes + ticket_bytes + publication_bytes > len(fixture):
        raise AssertionError("HELLO input fixture geometry is incomplete")
    if len(chain.keygen_dk) != 2400 or len(chain.entropy_d_z) != 64:
        raise AssertionError("post-KeyGen memory fixture geometry drifted")

    memory = bytearray(
        hashlib.shake_256(b"Seed full-memory KeyGen-to-HELLO gate").digest(
            0x10000
        )
    )
    resident = container.read_bytes()[:0x800]
    if len(resident) != 0x800:
        raise AssertionError("phase container lost its four-sector resident prefix")
    memory[0x1000:0x1800] = resident

    # Construct the literal post-KeyGen product layout before HELLO is loaded.
    dk = chain.keygen_dk
    memory[0x08C0:0x0D60] = dk[1152:2336]
    memory[0x3600:0x3780] = dk[0:384]
    memory[0x3780:0x37C0] = dk[2336:2400]
    memory[0x3800:0x3980] = dk[384:768]
    memory[0x3980:0x3B00] = dk[768:1152]
    memory[attempt_start : attempt_start + 64] = chain.entropy_d_z

    # Reproduce the phase loads immediately preceding the active resident
    # stager: the sector-rounded HELLO image into K and its input sector at
    # 0e00. The active assembled copy instructions below perform the handoff.
    hello_image = (BUILD / "hello_overlay.bin").read_bytes()
    hello_rounded = (len(hello_image) + 511) & ~511
    ticket_start = 0x3000 if K14 else 0x3200
    if hello_rounded > ticket_start - 0x1800:
        raise AssertionError("HELLO phase load reaches its ticket staging band")
    memory[0x1800 : 0x1800 + hello_rounded] = hello_image.ljust(
        hello_rounded, b"\0"
    )
    memory[0x0E00:0x1000] = fixture
    before = bytes(memory[:0x4000])

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, 0x10000)
    machine.mem_write(0, bytes(memory))
    machine.reg_write(UC_X86_REG_DS, 0)
    machine.reg_write(UC_X86_REG_ES, 0)
    machine.reg_write(UC_X86_REG_SS, 0)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    machine.emu_start(stage_start, stage_end, count=1024)
    if machine.reg_read(UC_X86_REG_IP) != stage_end:
        raise AssertionError("active HELLO stager did not reach its end label")

    after = bytes(machine.mem_read(0, 0x4000))
    expected = bytearray(before)
    expected[attempt_start : attempt_start + attempt_bytes] = fixture[
        :attempt_bytes
    ]
    expected[ticket_start : ticket_start + ticket_bytes] = fixture[
        attempt_bytes : attempt_bytes + ticket_bytes
    ]
    publication_offset = attempt_bytes + ticket_bytes
    expected[
        publication_start : publication_start + publication_bytes
    ] = fixture[publication_offset : publication_offset + publication_bytes]
    if after != bytes(expected):
        mismatch = next(
            index
            for index, (actual, wanted) in enumerate(
                zip(after, expected, strict=True)
            )
            if actual != wanted
        )
        raise AssertionError(
            f"active full-memory HELLO handoff changed {mismatch:#06x} "
            "outside or contrary to the exact transition"
        )
    if after[attempt_start : attempt_start + attempt_bytes] != fixture[:102]:
        raise AssertionError("HELLO random/session/PSK/age/length staging drifted")
    if after[ticket_start : ticket_start + ticket_bytes] != fixture[102:294]:
        raise AssertionError("HELLO ticket identity staging drifted")
    if after[publication_start : publication_start + publication_bytes] != fixture[
        294:358
    ]:
        raise AssertionError("HELLO expected server-X/digest staging drifted")


def annotate_literal_result(result_path: Path) -> bool:
    path = result_path if result_path.is_absolute() else ROOT / result_path
    result = json.loads(path.read_text(encoding="utf-8"))
    capture_path = Path(result["serial_path"])
    if not capture_path.is_absolute():
        capture_path = ROOT / capture_path
    raw = capture_path.read_text(encoding="utf-8", errors="replace")
    phase_text, success, status = parse_phase_output(raw)
    result.update(
        {
            "status": status,
            "passed": success,
            "failed": not success,
            "serial_text": phase_text,
            "raw_capture_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "phase_chain": {
                "terminal_protocol": "PASS|FAIL followed by neutral RESULT",
                "entropy_mode": ENTROPY_MODE,
                "collector_mixed_into_chain": False,
                "physical_min_entropy_established": False,
                "limitation": ENTROPY_LIMITATION,
                "durability_path": [
                    "prepare alternate ratchet record",
                    "BIOS sector write",
                    "BIOS disk reset/flush",
                    "physical sector reread",
                    "byte-exact durable-record verification",
                    "d||z release only after verified reread",
                ],
                "collector_and_ratchet_gate": str(
                    (HERE / "entropy_ratchet_check.py").relative_to(ROOT)
                ),
                "full_memory_keygen_to_hello_handoff": {
                    "gate": "pass",
                    "attempt_inputs": "0x3b9c..0x3c02 (102 bytes)",
                    "ticket_identity": (
                        "0x3000..0x30c0 (192 bytes)"
                        if K14
                        else "0x3200..0x32c0 (192 bytes)"
                    ),
                    "expected_server_x_and_digest": "0x0700..0x0740 (64 bytes)",
                },
            },
        }
    )
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return success


def sector_chunks(parts: list[bytes], *, prefix_length: bool = False) -> bytes:
    encoded = bytearray()
    for part in parts:
        header = struct.pack("<H", len(part)) if prefix_length else b""
        if len(header) + len(part) > 512:
            raise AssertionError("phase fixture chunk exceeds one sector")
        encoded.extend(header)
        encoded.extend(part)
        encoded.extend(bytes(512 - len(header) - len(part)))
    return bytes(encoded)


def word_checksum(value: bytes) -> int:
    if len(value) & 1:
        raise ValueError("word checksum requires an even byte count")
    return sum(
        int.from_bytes(value[index : index + 2], "little")
        for index in range(0, len(value), 2)
    ) & 0xFFFF


def literal_runner_defines(harness_defines: list[str]) -> tuple[str, ...]:
    """Return the exact define set used by the child literal-16K assembler."""

    variant = ("TLS13_POC_K14",) if K14 else ()
    result = variant + tuple(harness_defines)
    if K14 != ("TLS13_POC_K14" in result):
        raise AssertionError("literal runner K14 define propagation drifted")
    return result


@dataclass(frozen=True)
class ChainFixtures:
    paths: tuple[Path, ...]
    keygen_dk: bytes
    entropy_d_z: bytes
    hello_inputs_sector: bytes
    keygen_checksum: int
    entropy_target_slot: int
    entropy_supplement_len: int
    hello_state_start: int
    hello_state_end: int
    hello_fresh_chunks: int
    hello_resumed_chunks: int
    hello_server_chunks: int
    sym_flight_bytes: int
    sym_flight_prefix: int
    sym_client_finished_bytes: int
    fo_requests: int


def build_chain_fixtures() -> ChainFixtures:
    entropy_check = load_module(
        "seed_tls13_poc_chain_entropy",
        HERE / "entropy_ratchet_check.py",
    )
    keygen_check = load_module(
        "seed_tls13_poc_chain_keygen",
        HERE.parent / "tls13-spike" / "mlkem768_integrated_keygen_check.py",
    )
    mlkem = load_module(
        "seed_tls13_poc_chain_mlkem",
        HERE.parent / "tls13-spike" / "mlkem768_integrated_check.py",
    )
    hello = load_module(
        "seed_tls13_poc_chain_hello",
        HERE / "hello_check.py",
    )
    sym = load_module(
        "seed_tls13_poc_chain_sym",
        HERE / "check_tls13_sym_overlay.py",
    )
    fo = load_module(
        "seed_tls13_poc_chain_fo",
        HERE / "fo_tail_check.py",
    )

    initial_state = entropy_check.sha3(
        b"Seed phase-chain ratchet initial state v1\0"
    )
    supplement = b"literal-16k phase-chain fixture"
    media = entropy_check.HOST.Media.initialized(initial_state)
    prepared = entropy_check.HOST.prepare_attempt(media, supplement)
    d_z = entropy_check.expand_dz(prepared.attempt_seed)

    dk = keygen_check.fips_keygen_internal(d_z)
    if len(dk) != 2400 or dk[-32:] != d_z[32:]:
        raise AssertionError("dynamic KeyGen oracle geometry drifted")
    ek = dk[1152:2336]
    h_ek = dk[2336:2368]
    message = hashlib.shake_256(
        b"Seed literal-16k coherent ML-KEM message"
    ).digest(32)
    candidate_g = hashlib.sha3_512(message + h_ek).digest()
    ciphertext = mlkem.k_pke_encrypt(ek, message, candidate_g[32:])
    oracle_message, oracle_g = mlkem.k_pke_decrypt(dk, ciphertext)
    if oracle_message != message or oracle_g != candidate_g:
        raise AssertionError("dynamic ML-KEM candidate is not self-consistent")

    client_random = hello.deterministic(b"chain-client-random", 32)
    session_id = hello.deterministic(b"chain-session-id", 32)
    identity = hashlib.shake_256(b"Seed chain ticket identity").digest(192)
    ticket_age = bytes.fromhex("10203040")
    ticket_psk = hashlib.sha256(b"Seed chain ticket PSK").digest()
    fresh_message, fresh_record = hello.build_fresh_client(
        ek, client_random, session_id
    )
    resumed_message, resumed_record, _truncated, _binder = (
        hello.build_resumed_client(
            ek,
            client_random,
            session_id,
            identity,
            ticket_age,
            ticket_psk,
        )
    )
    server_x = hashlib.sha256(b"Seed chain server X25519").digest()
    fresh_server = hello.build_server(
        session_id, ciphertext, server_x, resumed=False
    )
    hello_digest = hashlib.sha256(fresh_message + fresh_server).digest()

    fresh_lengths = [147, 384, 384, 384, 32, 50]
    resumed_lengths = [147, 384, 384, 384, 32, 64, len(identity), 39]

    def split_exact(value: bytes, lengths: list[int]) -> list[bytes]:
        if sum(lengths) != len(value):
            raise AssertionError("hello fixture fragment geometry drifted")
        parts: list[bytes] = []
        offset = 0
        for length in lengths:
            parts.append(value[offset : offset + length])
            offset += length
        return parts

    server_parts = [
        fresh_server[index : index + 384]
        for index in range(0, len(fresh_server), 384)
    ]
    if [len(part) for part in server_parts] != [384, 384, 384, 58]:
        raise AssertionError("ServerHello fixture chunk geometry drifted")

    sym_hello = fresh_message + fresh_server
    sym_shared = candidate_g[:32] + server_x
    sym_handshake = sym.derive_handshake(sym_shared, sym_hello)
    sym_oracle_fixture = sym.O.build_integrated_fixture()
    sym_messages = list(sym_oracle_fixture.server_flight_messages)
    sym_before_finished = b"".join(sym_messages[:-1])
    sym_server_verify = hmac.new(
        sym_handshake["server_finished"],
        hashlib.sha256(sym_hello + sym_before_finished).digest(),
        hashlib.sha256,
    ).digest()
    sym_messages[-1] = b"\x14\x00\x00\x20" + sym_server_verify
    sym_flight_content = b"".join(sym_messages)
    sym_flight_record = sym.BASE.encrypted_record(
        sym_handshake["server_key"],
        sym_handshake["server_iv"],
        0,
        sym.O.CONTENT_HANDSHAKE,
        sym_flight_content,
    )
    sym_header = sym_flight_record[:5]
    sym_cipher = sym_flight_record[5:-16]
    sym_tag = sym_flight_record[-16:]
    sym_through_server_finished = sym_hello + sym_flight_content
    sym_client_verify = hmac.new(
        sym_handshake["client_finished"],
        hashlib.sha256(sym_through_server_finished).digest(),
        hashlib.sha256,
    ).digest()
    sym_client_message = b"\x14\x00\x00\x20" + sym_client_verify
    sym_client_record = sym.BASE.encrypted_record(
        sym_handshake["client_key"],
        sym_handshake["client_iv"],
        0,
        sym.O.CONTENT_HANDSHAKE,
        sym_client_message,
    )
    if len(sym_client_record) != 58:
        raise AssertionError("dynamic client Finished record geometry drifted")

    objects = {fo.OBJECT_EK: ek, fo.OBJECT_C: ciphertext}
    fo_sectors = bytearray()
    for object_id, offset, count, _destination in fo.expected_stream_log():
        part = objects[object_id][offset : offset + count]
        if len(part) != count:
            raise AssertionError("FO stream fixture request exceeds object")
        header = struct.pack("<BHH", object_id, offset, count)
        fo_sectors.extend(header + part)
        fo_sectors.extend(bytes(512 - len(header) - len(part)))

    hello_inputs = (
        client_random
        + session_id
        + ticket_psk
        + ticket_age
        + struct.pack("<H", len(identity))
        + identity
        + server_x
        + hello_digest
    )
    if len(hello_inputs) > 512:
        raise AssertionError("hello input fixture exceeds one sector")
    hello_inputs = hello_inputs.ljust(512, b"\0")

    entropy_meta = (
        struct.pack("<H", len(supplement))
        + supplement.ljust(96, b"\0")
        + d_z
    ).ljust(512, b"\0")

    paths = (
        write_fixture(
            "entropy_slots_fixture.bin",
            b"".join(media.slots),
        ),
        write_fixture("entropy_meta_fixture.bin", entropy_meta),
        write_fixture(
            "entropy_record_fixture.bin",
            prepared.encoded_record,
        ),
        write_fixture("hello_inputs_fixture.bin", hello_inputs),
        write_fixture(
            "hello_resumed_fixture.bin",
            sector_chunks(
                split_exact(resumed_record, resumed_lengths),
                prefix_length=True,
            ),
        ),
        write_fixture(
            "hello_fresh_fixture.bin",
            sector_chunks(
                split_exact(fresh_record, fresh_lengths),
                prefix_length=True,
            ),
        ),
        write_fixture(
            "hello_server_fixture.bin",
            sector_chunks(server_parts, prefix_length=True),
        ),
        write_fixture("candidate_fixture.bin", message + candidate_g),
        write_fixture(
            "sym_flight_meta_fixture.bin",
            sym_header + sym_tag + sym_server_verify,
        ),
        write_fixture("sym_flight_cipher_fixture.bin", sym_cipher),
        write_fixture(
            "sym_client_finished_fixture.bin",
            sym_client_record,
        ),
        write_fixture("fo_stream_fixture.bin", bytes(fo_sectors)),
        write_fixture("fo_expected_fixture.bin", candidate_g[:32]),
    )

    hello_image = (BUILD / "hello_overlay.bin").read_bytes()
    hello_header = hello.parse_header(hello_image)
    return ChainFixtures(
        paths=paths,
        keygen_dk=dk,
        entropy_d_z=d_z,
        hello_inputs_sector=hello_inputs,
        keygen_checksum=word_checksum(dk),
        entropy_target_slot=prepared.target_slot,
        entropy_supplement_len=len(supplement),
        hello_state_start=hello_header.state_start,
        hello_state_end=hello_header.state_end,
        hello_fresh_chunks=len(fresh_lengths),
        hello_resumed_chunks=len(resumed_lengths),
        hello_server_chunks=len(server_parts),
        sym_flight_bytes=len(sym_cipher),
        sym_flight_prefix=len(sym_before_finished),
        sym_client_finished_bytes=len(sym_client_record),
        fo_requests=len(fo.expected_stream_log()),
    )


def build_auth_fixture() -> Path:
    oracle_source = HERE.parent / "tls13-spike" / "auth_integrated_oracle.py"
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_poc_auth_harness_oracle", oracle_source
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {oracle_source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    fixture = module.make_fixture()
    signature = fixture.certificate_verify_signature
    if not 8 <= len(signature) <= 72:
        raise AssertionError("synthetic CertificateVerify signature outside product bound")
    encoded = (
        fixture.certificate_verify_digest
        + len(signature).to_bytes(2, "little")
        + signature.ljust(72, b"\x00")
        + fixture.leaf_point[0].to_bytes(32, "big")
        + fixture.leaf_point[1].to_bytes(32, "big")
    )
    if len(encoded) != 170:
        raise AssertionError("authentication harness fixture layout drifted")
    output = BUILD / "auth_fixture.bin"
    output.write_bytes(encoded)
    return output


def build_candidate_fixture() -> Path:
    checker_source = HERE / "mlkem_candidate_check.py"
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_poc_candidate_harness_oracle", checker_source
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {checker_source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    vectors, listing = module.assemble_vectors(BUILD)
    ciphertext = module.vector_slice(
        vectors, listing, "fixture_ciphertext", "fixture_ciphertext_end"
    )
    expected_g = module.vector_slice(
        vectors,
        listing,
        "fixture_expected_g",
        "fixture_expected_g_end",
        end_at_eof=True,
    )
    encoded = ciphertext + expected_g
    if len(encoded) != 1152:
        raise AssertionError("candidate harness fixture layout drifted")
    output = BUILD / "candidate_fixture.bin"
    output.write_bytes(encoded)
    return output


def build_sym_fixture() -> Path:
    checker_source = HERE / "check_tls13_sym_overlay.py"
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_poc_sym_harness_oracle", checker_source
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {checker_source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    fixture = module.O.build_integrated_fixture()
    hello = fixture.client_hello + fixture.server_hello
    shared = fixture.candidate_mlkem_secret + fixture.server_x25519_public
    expected = module.derive_handshake(shared, hello)["handshake_secret"]
    encoded = shared + hashlib.sha256(hello).digest() + expected
    if len(encoded) != 128:
        raise AssertionError("symmetric schedule harness fixture layout drifted")
    output = BUILD / "sym_fixture.bin"
    output.write_bytes(encoded)
    return output


def main() -> None:
    global K14
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--run-16k",
        action="store_true",
        help="also run the assembled phase container on original-speed 86Box",
    )
    parser.add_argument("--profile", default="vm-net-ne2k8")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument(
        "--compare-loaders",
        action="store_true",
        help="time one-sector and track-batched reads before the phase chain",
    )
    parser.add_argument(
        "--k14",
        action="store_true",
        help=(
            "build the opt-in 14-sector logical-K variant; high security "
            "bands remain fixed and 0x3400..0x3600 is phase-owned reclaimed "
            "controller/staging/runtime space"
        ),
    )
    args = parser.parse_args()
    K14 = args.k14

    BUILD.mkdir(parents=True, exist_ok=True)
    binaries: list[tuple[str, Path]] = []
    for stem, source, defines in OVERLAYS:
        binaries.append(
            (stem, assemble(source, f"{stem}_overlay", defines=defines))
        )
    auth_fixture = build_auth_fixture()
    chain = build_chain_fixtures()
    controller_defines = (
        f"POC_ENTROPY_TARGET_SLOT={chain.entropy_target_slot}",
        f"POC_ENTROPY_SUPPLEMENT_LEN={chain.entropy_supplement_len}",
        f"POC_HELLO_FRESH_CHUNKS={chain.hello_fresh_chunks}",
        f"POC_HELLO_RESUMED_CHUNKS={chain.hello_resumed_chunks}",
        f"POC_HELLO_SERVER_CHUNKS={chain.hello_server_chunks}",
        f"POC_FO_REQUESTS={chain.fo_requests}",
    )
    entropy_controller = assemble(
        HARNESS,
        "entropy_controller",
        defines=(
            "POC_BUILD_ENTROPY_CONTROLLER",
            "POC_DETERMINISTIC_COHERENT_CHAIN",
            *controller_defines,
        ),
    )
    verify_deterministic_entropy_controller(entropy_controller)
    keygen_controller = assemble(
        HARNESS,
        "keygen_controller",
        defines=(
            "POC_BUILD_KEYGEN_CONTROLLER",
            f"POC_KEYGEN_CHECKSUM=0x{chain.keygen_checksum:04x}",
        ),
    )
    hello_controller_raw = assemble(
        HARNESS,
        "hello_controller_raw",
        defines=("POC_BUILD_HELLO_CONTROLLER", *controller_defines),
    )
    hello_controller = build_hello_controller_stage(hello_controller_raw)
    sym_controller = assemble(
        HARNESS,
        "sym_controller",
        defines=(
            "POC_BUILD_SYM_CONTROLLER",
            f"POC_SYM_FLIGHT_BYTES={chain.sym_flight_bytes}",
            f"POC_SYM_FLIGHT_PREFIX={chain.sym_flight_prefix}",
        ),
    )
    if sym_controller.stat().st_size > 0x200:
        raise AssertionError("SYM flight controller exceeds 3400..35ff")
    candidate_controller = assemble(
        HARNESS,
        "candidate_controller",
        defines=("POC_BUILD_CANDIDATE_CONTROLLER", *controller_defines),
    )
    fo_controller = assemble(
        HARNESS,
        "fo_controller",
        defines=("POC_BUILD_FO_CONTROLLER", *controller_defines),
    )
    composites = (
        build_composite(
            "entropy_ratchet_composite.bin",
            BUILD / "entropy_ratchet_overlay.bin",
            entropy_controller,
            controller_address=0x2400,
        ),
        build_composite(
            "keygen_composite.bin",
            BUILD / "keygen_overlay.bin",
            keygen_controller,
            controller_address=0x2400,
        ),
        build_composite(
            "mlkem_candidate_composite.bin",
            BUILD / "mlkem_candidate_overlay.bin",
            candidate_controller,
            controller_address=0x2200,
        ),
        build_composite(
            "fo_tail_composite.bin",
            BUILD / "fo_tail_overlay.bin",
            fo_controller,
            controller_address=0x2400,
        ),
    )
    # Restore only HELLO writes that overlap SYM's immutable image.  HELLO's
    # relocated mutable state is in SYM's init-cleared work tail and therefore
    # does not force another disk sector into the critical restore.
    sym_static_end = 0x1800 + (BUILD / "tls13_sym_overlay.bin").stat().st_size
    hello_dirty_end = 0x1800 + (BUILD / "hello_overlay.bin").stat().st_size
    if (
        chain.hello_state_start < sym_static_end
        and chain.hello_state_end > 0x1800
    ):
        hello_dirty_end = max(
            hello_dirty_end,
            min(chain.hello_state_end, sym_static_end),
        )
    sym_restore_sectors = (hello_dirty_end - 0x1800 + 511) // 512
    if not 1 <= sym_restore_sectors <= 12:
        raise AssertionError("unexpected HELLO-to-SYM delta restore geometry")
    harness_defines = [
        "POC_INCLUDE_ENTROPY",
        "POC_INCLUDE_HELLO",
        "POC_INCLUDE_CANDIDATE",
        "POC_INCLUDE_AUTH",
        "POC_INCLUDE_SYM",
        "POC_INCLUDE_FO",
        "POC_DELTA_PRELOAD",
        "POC_DETERMINISTIC_COHERENT_CHAIN",
        f"POC_KEYGEN_CHECKSUM=0x{chain.keygen_checksum:04x}",
        f"POC_ENTROPY_TARGET_SLOT={chain.entropy_target_slot}",
        f"POC_ENTROPY_SUPPLEMENT_LEN={chain.entropy_supplement_len}",
        f"POC_HELLO_FRESH_CHUNKS={chain.hello_fresh_chunks}",
        f"POC_HELLO_RESUMED_CHUNKS={chain.hello_resumed_chunks}",
        f"POC_HELLO_SERVER_CHUNKS={chain.hello_server_chunks}",
        f"POC_SYM_CLIENT_FINISHED_BYTES={chain.sym_client_finished_bytes}",
        f"POC_FO_REQUESTS={chain.fo_requests}",
        f"POC_SYM_RESTORE_SECTORS={sym_restore_sectors}",
    ]
    if args.compare_loaders:
        harness_defines.append("POC_COMPARE_LOADERS")
    runner_defines = literal_runner_defines(harness_defines)
    container = assemble(
        HARNESS,
        "poc_harness",
        defines=tuple(harness_defines),
    )
    verify_full_memory_hello_handoff(container, chain)
    verify_resident_telemetry_contract(container)
    verify_terminal_contract(container)
    if K14:
        k14_container = BUILD / "poc_harness_k14.bin"
        shutil.copyfile(container, k14_container)
        if container.read_bytes()[:0x800] != k14_container.read_bytes()[:0x800]:
            raise AssertionError("K14 copied container changed its resident prefix")

    print("TLS13 PoC phase container: PASS")
    print(
        f"  variant={'K14' if K14 else 'K15'}; "
        f"resident=2048 bytes; total={container.stat().st_size} bytes "
        f"({(container.stat().st_size + 511) // 512} sectors)"
    )
    for stem, binary in binaries:
        print(
            f"  {stem}={binary.stat().st_size} bytes "
            f"sha256={hashlib.sha256(binary.read_bytes()).hexdigest()}"
        )
    for composite in composites:
        print(
            f"  {composite.stem}={composite.stat().st_size} bytes "
            f"sha256={hashlib.sha256(composite.read_bytes()).hexdigest()}"
        )
    print(
        f"  sym_controller={sym_controller.stat().st_size} bytes "
        f"sha256={hashlib.sha256(sym_controller.read_bytes()).hexdigest()}"
    )
    print(
        f"  auth-fixture={auth_fixture.stat().st_size} bytes "
        f"sha256={hashlib.sha256(auth_fixture.read_bytes()).hexdigest()}"
    )
    for fixture in chain.paths:
        print(
            f"  {fixture.stem}={fixture.stat().st_size} bytes "
            f"sha256={hashlib.sha256(fixture.read_bytes()).hexdigest()}"
        )
    print(
        f"  coherent-chain keygen-checksum=0x{chain.keygen_checksum:04x} "
        f"sym-delta-restore={sym_restore_sectors}/12 sectors"
    )
    print(
        "  full-memory KeyGen->HELLO handoff="
        "102B attempt@3b9c + 192B ticket@"
        f"{'3000' if K14 else '3200'} + 64B serverX/digest@0700 PASS"
    )
    if K14:
        print(
            "  phase-owned reclaimed space=0x3400..0x3600 "
            "(512 bytes; not user arena or reconnect-safe storage; high "
            "security state still begins at 0x3600)"
        )
    print(f"  entropy-mode={ENTROPY_MODE}")
    print(f"  LIMITATION: {ENTROPY_LIMITATION}")

    if not args.run_16k:
        return

    command = [
        sys.executable,
        str(LITERAL_RUNNER),
        "--asm",
        str(HARNESS),
        "--resident-sectors",
        "4",
        "--profile",
        args.profile,
        "--timeout",
        str(args.timeout),
        "--done-token",
        "RESULT",
        "--start-token",
        "TLS13 POC",
        "--start-timeout",
        "45",
    ]
    for define in runner_defines:
        command.extend(["--define", define])
    result_path = (
        args.json_out
        if args.json_out is not None
        else BUILD / "phase_chain_literal16k_results.json"
    )
    resolved_result_path = (
        result_path if result_path.is_absolute() else ROOT / result_path
    )
    resolved_result_path.unlink(missing_ok=True)
    command.extend(["--json-out", str(result_path)])
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if not resolved_result_path.is_file():
        raise RuntimeError("literal runner did not write its result JSON")
    success = annotate_literal_result(result_path)
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, command)
    if not success:
        raise SystemExit(
            "literal phase chain emitted FAIL or an invalid terminal sequence"
        )


if __name__ == "__main__":
    main()
