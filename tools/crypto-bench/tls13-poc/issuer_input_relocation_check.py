#!/usr/bin/env python3
"""Gate the K14 issuer-input relocation against the native ticket layout."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from unicorn.x86_const import UC_X86_REG_AX, UC_X86_REG_BX


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CHECKER = Path(__file__).resolve()
AUTH_SOURCE = HERE / "issuer_auth_overlay.asm"
BRIDGE_SOURCE = HERE / "issuer_input_relocation_bridge.asm"
COMMIT_GATE_SOURCE = HERE / "read_only_commit_gate.asm"
LAYOUT_SOURCE = HERE / "layout.inc"
SYM_SOURCE = HERE / "tls13_sym_overlay.asm"
LIVE_LEAF = HERE / "issuer_auth_live_leaf.pem"
LIVE_VECTOR = HERE / "issuer_auth_live_vector.json"

sys.path.insert(0, str(HERE))
import issuer_auth_check as auth_gate  # noqa: E402
import read_only_commit_gate_check as commit_gate_check  # noqa: E402


ORIGIN = 0x1800
K14_END = 0x3400
K14_SECTORS = 14
K14_BYTES = K14_SECTORS * 512
EXTENSION_START = 0x3400
EXTENSION_END = 0x3600
SYM_EXTENSION_WORK_START = 0x3510
SYM_EXTENSION_WORK_END = 0x355D

INPUT_PROFILE = 0x3400
INPUT_GENERATION = INPUT_PROFILE + 2
INPUT_DIGEST = INPUT_GENERATION + 2
INPUT_SIGNATURE_LEN = INPUT_DIGEST + 32
INPUT_SIGNATURE = INPUT_SIGNATURE_LEN + 2
INPUT_SIGNATURE_MAX = 72
INPUT_LEAF_X = INPUT_SIGNATURE + INPUT_SIGNATURE_MAX
INPUT_LEAF_Y = INPUT_LEAF_X + 32
OUTPUT_STATUS = INPUT_LEAF_Y + 32
INPUT_END = OUTPUT_STATUS + 1
INPUT_GUARD_HI = SYM_EXTENSION_WORK_START - 8
INPUT_GUARD_HI_END = SYM_EXTENSION_WORK_START

COMMIT_START = 0x3600
COMMIT_STATUS = COMMIT_START
COMMIT_GENERATION = COMMIT_START + 10
COMMIT_END = 0x3672

PARSER_LEAF_STATUS = 0x3600
PARSER_LEAF_PROFILE = 0x3601
PARSER_TBS_DIGEST = 0x3609
PARSER_CERT_SIG_LEN = 0x3629
PARSER_CERT_SIG = 0x362B
PARSER_LEAF_X = 0x3673
PARSER_LEAF_Y = 0x3693
PARSER_CV_STATUS = 0x3700
PARSER_CV_PROFILE = 0x3701
PARSER_TRANSCRIPT_STATUS = 0x3703
PARSER_CV_DIGEST = 0x3724
PARSER_CV_SIG_LEN = 0x3744
PARSER_CV_SIG = 0x3746
PARSER_HASH_STATUS = 0x378E
PARSER_TIME_STATUS = 0x378F

TICKET_PSK = 0x38B0
TICKET_PSK_END = TICKET_PSK + 32
TICKET_IDENTITY = 0x3B40
TICKET_IDENTITY_END = 0x3C00
TICKET_NONCE = 0x3C00
TICKET_NONCE_END = 0x3C20
TICKET_META = 0x3C20
TICKET_META_END = 0x3C2D

RECONNECT_START = 0x3C9C
ESC_START = 0x3DE6
PRODUCT_START = 0x3E40
STACK_START = 0x3F00

LEAF_PROFILE = 0x003F
CV_PROFILE = 0x0700
GENERATION = 0x4A31
PHASE_PATTERN = 0xA5
RUNTIME_PATTERN = 0xD7
GUARD = b"IRI1\xde\xad\xb6\xce"
FORBIDDEN_IO = {
    "in",
    "insb",
    "insd",
    "insw",
    "int",
    "int1",
    "int3",
    "into",
    "out",
    "outsb",
    "outsd",
    "outsw",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble_bridge(directory: Path) -> bytes:
    binary = directory / "issuer-input-relocation-bridge.bin"
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            "-l",
            str(binary.with_suffix(".lst")),
            "-o",
            str(binary),
            str(BRIDGE_SOURCE),
        ],
        cwd=ROOT,
        check=True,
    )
    return binary.read_bytes()


def assemble_commit_gate(directory: Path) -> bytes:
    binary = directory / "read-only-commit-gate.bin"
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            "-o",
            str(binary),
            str(COMMIT_GATE_SOURCE),
        ],
        cwd=ROOT,
        check=True,
    )
    return binary.read_bytes()


def assemble_native_relocated_auth(directory: Path) -> tuple[bytes, tuple[int, ...]]:
    wrapper = directory / "issuer-input-relocation-auth-probe.asm"
    probe_names = (
        "issuer_input_guard_lo",
        "issuer_input_profile_flags",
        "issuer_input_end",
        "issuer_input_guard_hi",
        "poc_k_extension_sym_work_start",
        "poc_k_extension_sym_work_end",
    )
    wrapper.write_text(
        "bits 16\n"
        "cpu 8086\n"
        "%define TLS13_POC_K14 1\n"
        "%define TLS13_POC_READ_ONLY_INPUT 1\n"
        f'%include "{AUTH_SOURCE.as_posix()}"\n'
        "__issuer_input_relocation_probe:\n"
        + "".join(f"    dw {name}\n" for name in probe_names),
        encoding="utf-8",
    )
    binary = wrapper.with_suffix(".bin")
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
    probe_bytes = 2 * len(probe_names)
    if len(blob) <= probe_bytes:
        raise AssertionError("native relocated issuer probe has no image")
    return blob[:-probe_bytes], struct.unpack(
        f"<{len(probe_names)}H", blob[-probe_bytes:]
    )


def bridge_static_instruction_gate(image: bytes) -> dict[str, int]:
    header_bytes = 10
    instructions = tuple(
        Cs(CS_ARCH_X86, CS_MODE_16).disasm(
            image[header_bytes:], ORIGIN + header_bytes
        )
    )
    decoded = sum(instruction.size for instruction in instructions)
    if decoded != len(image) - header_bytes:
        raise AssertionError("bridge contains undecoded bytes")
    forbidden = [
        instruction
        for instruction in instructions
        if instruction.mnemonic in FORBIDDEN_IO
    ]
    if forbidden:
        raise AssertionError(
            "bridge contains interrupt/port I/O: "
            + ", ".join(
                f"{instruction.address:#x}:{instruction.mnemonic}"
                for instruction in forbidden
            )
        )
    return {
        "decoded_instructions": len(instructions),
        "decoded_code_bytes": decoded,
        "interrupt_or_port_io_instructions": 0,
    }


def phase_load(machine: Any, image: bytes, sectors: int) -> None:
    capacity = sectors * 512
    if len(image) > capacity:
        raise AssertionError("phase image exceeds declared sector load")
    machine.mem_write(ORIGIN, image + bytes(capacity - len(image)))
    machine.ctl_remove_cache(ORIGIN, ORIGIN + capacity)


def ticket_snapshot(machine: Any) -> tuple[bytes, bytes, bytes, bytes]:
    return (
        bytes(machine.mem_read(TICKET_PSK, TICKET_PSK_END - TICKET_PSK)),
        bytes(
            machine.mem_read(
                TICKET_IDENTITY, TICKET_IDENTITY_END - TICKET_IDENTITY
            )
        ),
        bytes(machine.mem_read(TICKET_NONCE, TICKET_NONCE_END - TICKET_NONCE)),
        bytes(machine.mem_read(TICKET_META, TICKET_META_END - TICKET_META)),
    )


def seed_ticket(machine: Any) -> tuple[bytes, bytes, bytes, bytes]:
    values = (
        hashlib.sha256(b"issuer relocation PSK").digest(),
        hashlib.shake_256(b"issuer relocation identity").digest(
            TICKET_IDENTITY_END - TICKET_IDENTITY
        ),
        hashlib.sha256(b"issuer relocation nonce").digest(),
        struct.pack("<HHIHHB", 0, 7200, 0x78563412, 32, 192, 1),
    )
    for start, value in zip(
        (TICKET_PSK, TICKET_IDENTITY, TICKET_NONCE, TICKET_META), values
    ):
        machine.mem_write(start, value)
    return values


def populate_parser_outputs(
    machine: Any,
    *,
    tbs_digest: bytes,
    certificate_signature: bytes,
    leaf_x: bytes,
    leaf_y: bytes,
    cv_digest: bytes,
    cv_signature: bytes,
    trusted_time: bool = True,
) -> None:
    if (
        len(tbs_digest) != 32
        or len(leaf_x) != 32
        or len(leaf_y) != 32
        or len(cv_digest) != 32
        or not 8 <= len(certificate_signature) <= INPUT_SIGNATURE_MAX
        or not 8 <= len(cv_signature) <= INPUT_SIGNATURE_MAX
    ):
        raise ValueError("invalid relocation fixture geometry")
    machine.mem_write(PARSER_LEAF_STATUS, b"\x02")
    machine.mem_write(PARSER_LEAF_PROFILE, struct.pack("<H", LEAF_PROFILE))
    machine.mem_write(PARSER_TBS_DIGEST, tbs_digest)
    machine.mem_write(
        PARSER_CERT_SIG_LEN, struct.pack("<H", len(certificate_signature))
    )
    machine.mem_write(PARSER_CERT_SIG, certificate_signature)
    machine.mem_write(PARSER_LEAF_X, leaf_x)
    machine.mem_write(PARSER_LEAF_Y, leaf_y)
    machine.mem_write(PARSER_CV_STATUS, b"\x01")
    machine.mem_write(PARSER_CV_PROFILE, struct.pack("<H", CV_PROFILE))
    machine.mem_write(PARSER_TRANSCRIPT_STATUS, b"\x01")
    machine.mem_write(PARSER_CV_DIGEST, cv_digest)
    machine.mem_write(PARSER_CV_SIG_LEN, struct.pack("<H", len(cv_signature)))
    machine.mem_write(PARSER_CV_SIG, cv_signature)
    machine.mem_write(PARSER_HASH_STATUS, b"\x01")
    machine.mem_write(PARSER_TIME_STATUS, b"\x01" if trusted_time else b"\x00")


def invoke_success(machine: Any, entry: int, generation: int = GENERATION) -> int:
    ax, carry, stack_bytes = auth_gate.invoke(
        machine, entry, registers={UC_X86_REG_AX: generation}
    )
    if (ax, carry) != (1, False):
        raise AssertionError(f"entry 0x{entry:04x} rejected: AX={ax} CF={carry}")
    return stack_bytes


def invoke_rejection(
    machine: Any, entry: int, generation: int = GENERATION
) -> int:
    ax, carry, stack_bytes = auth_gate.invoke(
        machine, entry, registers={UC_X86_REG_AX: generation}
    )
    if (ax, carry) != (0, True):
        raise AssertionError(f"entry 0x{entry:04x} accepted: AX={ax} CF={carry}")
    return stack_bytes


def assert_auth_result(machine: Any, result: tuple[int, bool, int]) -> int:
    ax, carry, stack_bytes = result
    status = bytes(machine.mem_read(OUTPUT_STATUS, 1))[0]
    if (ax, carry, status) != (1, False, 1):
        raise AssertionError(
            f"issuer pass rejected: AX={ax} CF={carry} status={status}"
        )
    return stack_bytes


def main_gate() -> dict[str, Any]:
    vector = json.loads(LIVE_VECTOR.read_text())
    leaf_der = auth_gate.pem_to_der(LIVE_LEAF.read_bytes())
    tbs, certificate_signature = auth_gate.certificate_parts(leaf_der)
    tbs_digest = hashlib.sha256(tbs).digest()
    cv_digest = bytes.fromhex(
        vector["certificate_verify"]["signed_input_sha256"]
    )
    cv_signature = bytes.fromhex(
        vector["certificate_verify"]["signature_der"]
    )

    with tempfile.TemporaryDirectory(
        prefix="seed-issuer-input-relocation-"
    ) as temp_name:
        temp = Path(temp_name)
        bridge = assemble_bridge(temp)
        commit_gate = assemble_commit_gate(temp)
        auth, probe = assemble_native_relocated_auth(temp)
        _spki, leaf_x, leaf_y, _public = auth_gate.public_spki(LIVE_LEAF, temp)

    (
        native_guard_lo,
        native_input_start,
        native_input_end,
        native_guard_hi,
        native_sym_work_start,
        native_sym_work_end,
    ) = probe
    if probe != (
        K14_END - 8,
        INPUT_PROFILE,
        INPUT_END,
        INPUT_GUARD_HI,
        SYM_EXTENSION_WORK_START,
        SYM_EXTENSION_WORK_END,
    ):
        raise AssertionError(f"native relocated issuer layout drifted: {probe!r}")
    if len(auth) > K14_BYTES or (len(auth) + 511) // 512 != K14_SECTORS:
        raise AssertionError("native relocated issuer phase is not exact K14")
    if ORIGIN + K14_BYTES != INPUT_PROFILE:
        raise AssertionError("K14 phase load does not stop at relocated input")
    if INPUT_END > INPUT_GUARD_HI:
        raise AssertionError("relocated input reaches its high guard")
    if INPUT_GUARD_HI_END != SYM_EXTENSION_WORK_START:
        raise AssertionError("relocated high guard does not end at sym work")
    if len(bridge) > 512:
        raise AssertionError("relocation bridge exceeds one sector")
    if len(commit_gate) > 1024:
        raise AssertionError("read-only commit gate exceeds two sectors")
    bridge_static = bridge_static_instruction_gate(bridge)
    commit_static = commit_gate_check.static_instruction_gate(commit_gate)

    auth_entries = struct.unpack_from("<6H", auth)
    leaf_entry, cv_entry, auth_clear, _anchor, auth_len, auth_abi = auth_entries
    if auth_len != len(auth) or auth_abi != 1:
        raise AssertionError("native relocated issuer entry table drifted")
    bridge_entries = struct.unpack_from("<5H", bridge)
    (
        bridge_leaf,
        bridge_cv,
        bridge_clear,
        bridge_len,
        bridge_abi,
    ) = bridge_entries
    if bridge_len != len(bridge) or bridge_abi != 1:
        raise AssertionError("relocation bridge entry table drifted")
    if commit_gate[:4] != b"ROG3":
        raise AssertionError("read-only commit gate magic drifted")
    commit_version, commit_len = struct.unpack_from("<HH", commit_gate, 4)
    (
        commit_entry,
        _unlock_entry,
        _abort_entry,
        _authorize_entry,
        validate_ticket_only_entry,
    ) = struct.unpack_from(
        "<5H", commit_gate, 8
    )
    if commit_version != 4 or commit_len != len(commit_gate):
        raise AssertionError("read-only commit gate header drifted")
    if (
        commit_entry != ORIGIN + 18
        or validate_ticket_only_entry == 0
        or validate_ticket_only_entry == _authorize_entry
    ):
        raise AssertionError("read-only commit gate v4 entry table drifted")

    machine = auth_gate.new_machine(bridge)
    phase_load(machine, bridge, 1)
    machine.mem_write(
        EXTENSION_START,
        bytes([PHASE_PATTERN]) * (EXTENSION_END - EXTENSION_START),
    )
    machine.mem_write(
        SYM_EXTENSION_WORK_START,
        bytes([RUNTIME_PATTERN])
        * (SYM_EXTENSION_WORK_END - SYM_EXTENSION_WORK_START),
    )
    stable_regions = {
        "resident_driver": (
            0x1000,
            ORIGIN,
            bytes(machine.mem_read(0x1000, ORIGIN - 0x1000)),
        ),
        "reconnect_esc": (
            RECONNECT_START,
            PRODUCT_START,
            bytes(
                machine.mem_read(
                    RECONNECT_START, PRODUCT_START - RECONNECT_START
                )
            ),
        ),
        "arena_context": (
            PRODUCT_START,
            STACK_START,
            bytes(machine.mem_read(PRODUCT_START, STACK_START - PRODUCT_START)),
        ),
    }
    expected_ticket = seed_ticket(machine)
    populate_parser_outputs(
        machine,
        tbs_digest=tbs_digest,
        certificate_signature=certificate_signature,
        leaf_x=leaf_x,
        leaf_y=leaf_y,
        cv_digest=cv_digest,
        cv_signature=cv_signature,
    )
    expected_cv_tail = bytes(
        machine.mem_read(PARSER_CV_STATUS, PARSER_TIME_STATUS + 1 - PARSER_CV_STATUS)
    )

    stack_high = invoke_success(machine, bridge_leaf)
    if ticket_snapshot(machine) != expected_ticket:
        raise AssertionError("leaf staging changed native ticket state")
    if bytes(machine.mem_read(INPUT_PROFILE, 2)) != struct.pack(
        "<H", LEAF_PROFILE
    ):
        raise AssertionError("leaf bridge did not publish relocated profile")
    if bytes(machine.mem_read(INPUT_GENERATION, 2)) != struct.pack(
        "<H", GENERATION
    ):
        raise AssertionError("leaf bridge did not publish generation")
    if bytes(machine.mem_read(INPUT_DIGEST, 32)) != tbs_digest:
        raise AssertionError("leaf bridge changed TBS digest")
    if bytes(machine.mem_read(INPUT_SIGNATURE, len(certificate_signature))) != certificate_signature:
        raise AssertionError("leaf bridge changed certificate signature")
    if bytes(machine.mem_read(INPUT_LEAF_X, 64)) != leaf_x + leaf_y:
        raise AssertionError("leaf bridge changed dynamic leaf point")
    if bytes(machine.mem_read(INPUT_GUARD_HI, 8)) != GUARD:
        raise AssertionError("leaf bridge high guard mismatch")
    if bytes(
        machine.mem_read(
            SYM_EXTENSION_WORK_START,
            SYM_EXTENSION_WORK_END - SYM_EXTENSION_WORK_START,
        )
    ) != bytes([RUNTIME_PATTERN]) * (
        SYM_EXTENSION_WORK_END - SYM_EXTENSION_WORK_START
    ):
        raise AssertionError("leaf staging reached retired sym runtime suffix")

    staged_leaf = bytes(
        machine.mem_read(INPUT_PROFILE, INPUT_GUARD_HI_END - INPUT_PROFILE)
    )
    phase_load(machine, auth, K14_SECTORS)
    if bytes(
        machine.mem_read(INPUT_PROFILE, INPUT_GUARD_HI_END - INPUT_PROFILE)
    ) != staged_leaf:
        raise AssertionError("exact 14-sector issuer load changed relocated input")
    stack_high = max(
        stack_high,
        assert_auth_result(machine, auth_gate.invoke(machine, leaf_entry)),
    )
    if ticket_snapshot(machine) != expected_ticket:
        raise AssertionError("issuer leaf proof changed native ticket state")
    if bytes(machine.mem_read(COMMIT_STATUS, 1)) != b"\x01":
        raise AssertionError("issuer leaf proof did not commit")
    committed = bytes(machine.mem_read(COMMIT_START, COMMIT_END - COMMIT_START))

    phase_load(machine, bridge, 1)
    stack_high = max(stack_high, invoke_success(machine, bridge_cv))
    if ticket_snapshot(machine) != expected_ticket:
        raise AssertionError("CV staging changed native ticket state")
    if bytes(machine.mem_read(PARSER_CV_STATUS, len(expected_cv_tail))) != expected_cv_tail:
        raise AssertionError("CV staging changed parser CV/hash/time output")
    if bytes(machine.mem_read(INPUT_PROFILE, 2)) != struct.pack(
        "<H", CV_PROFILE
    ):
        raise AssertionError("CV bridge did not publish relocated profile")
    if bytes(machine.mem_read(INPUT_DIGEST, 32)) != cv_digest:
        raise AssertionError("CV bridge changed signed-input digest")
    if bytes(machine.mem_read(INPUT_SIGNATURE, len(cv_signature))) != cv_signature:
        raise AssertionError("CV bridge changed signature")
    if bytes(machine.mem_read(INPUT_LEAF_X, 64)) != bytes(64):
        raise AssertionError("CV bridge exposed point-shaped parser capacity")

    staged_cv = bytes(
        machine.mem_read(INPUT_PROFILE, INPUT_GUARD_HI_END - INPUT_PROFILE)
    )
    phase_load(machine, auth, K14_SECTORS)
    if bytes(
        machine.mem_read(INPUT_PROFILE, INPUT_GUARD_HI_END - INPUT_PROFILE)
    ) != staged_cv:
        raise AssertionError("pass-2 phase reload changed relocated input")
    machine.mem_write(
        auth_gate.LOW_START,
        bytes([0x5C])
        * (
            auth_gate.EXTERNAL["p256_mutable_work_end"]
            - auth_gate.LOW_START
        ),
    )
    stack_high = max(
        stack_high,
        assert_auth_result(machine, auth_gate.invoke(machine, cv_entry)),
    )
    if bytes(machine.mem_read(COMMIT_START, COMMIT_END - COMMIT_START)) != committed:
        raise AssertionError("CertificateVerify changed authenticated handoff")
    if ticket_snapshot(machine) != expected_ticket:
        raise AssertionError("CertificateVerify changed native ticket state")

    # The separate atomic gate owns normal retirement. It consumes the
    # authenticated pass-2 status before clearing the input and publishing its
    # committed state; the bridge's clear entry remains failure/abort only.
    phase_load(machine, commit_gate, 2)
    commit_result = auth_gate.invoke(
        machine,
        commit_entry,
        registers={
            UC_X86_REG_AX: GENERATION,
            UC_X86_REG_BX: commit_gate_check.ROUTE_LIVE_TICKET,
        },
    )
    if commit_result[:2] != (1, False):
        raise AssertionError(
            "atomic route gate rejected authenticated ticket state"
        )
    stack_high = max(stack_high, commit_result[2])
    if bytes(machine.mem_read(INPUT_PROFILE, INPUT_END - INPUT_PROFILE)) != bytes(
        INPUT_END - INPUT_PROFILE
    ):
        raise AssertionError("atomic gate did not retire relocated input")
    if bytes(machine.mem_read(COMMIT_START, COMMIT_END - COMMIT_START)) != committed:
        raise AssertionError("atomic gate changed authenticated handoff")
    if ticket_snapshot(machine) != expected_ticket:
        raise AssertionError("atomic gate changed native ticket state")
    if bytes(
        machine.mem_read(
            SYM_EXTENSION_WORK_START,
            SYM_EXTENSION_WORK_END - SYM_EXTENSION_WORK_START,
        )
    ) != bytes([RUNTIME_PATTERN]) * (
        SYM_EXTENSION_WORK_END - SYM_EXTENSION_WORK_START
    ):
        raise AssertionError("atomic gate reached symmetric extension suffix")

    for name, (start, end, expected) in stable_regions.items():
        if bytes(machine.mem_read(start, end - start)) != expected:
            raise AssertionError(f"{name} changed across relocated auth chain")

    # Ordering controls: parser time must be proven, and pass 2 cannot be
    # staged before the issuer handoff commits.
    no_time = auth_gate.new_machine(bridge)
    phase_load(no_time, bridge, 1)
    expected_no_time_ticket = seed_ticket(no_time)
    populate_parser_outputs(
        no_time,
        tbs_digest=tbs_digest,
        certificate_signature=certificate_signature,
        leaf_x=leaf_x,
        leaf_y=leaf_y,
        cv_digest=cv_digest,
        cv_signature=cv_signature,
        trusted_time=False,
    )
    stack_high = max(stack_high, invoke_rejection(no_time, bridge_leaf))
    if ticket_snapshot(no_time) != expected_no_time_ticket:
        raise AssertionError("time rejection changed native ticket state")

    early_cv = auth_gate.new_machine(bridge)
    phase_load(early_cv, bridge, 1)
    expected_early_ticket = seed_ticket(early_cv)
    populate_parser_outputs(
        early_cv,
        tbs_digest=tbs_digest,
        certificate_signature=certificate_signature,
        leaf_x=leaf_x,
        leaf_y=leaf_y,
        cv_digest=cv_digest,
        cv_signature=cv_signature,
    )
    stack_high = max(stack_high, invoke_rejection(early_cv, bridge_cv))
    if ticket_snapshot(early_cv) != expected_early_ticket:
        raise AssertionError("early CV rejection changed native ticket state")

    return {
        "schema": "seed-tls13-poc-issuer-input-relocation-v1",
        "scope": (
            "isolated read-only-memory lifetime gate for the native K14 "
            "issuer-input relocation; no product/runtime linkage"
        ),
        "provenance": {
            "auth_source": str(AUTH_SOURCE.relative_to(ROOT)),
            "auth_source_sha256": sha256_file(AUTH_SOURCE),
            "bridge_source": str(BRIDGE_SOURCE.relative_to(ROOT)),
            "bridge_source_sha256": sha256_file(BRIDGE_SOURCE),
            "commit_gate_source": str(COMMIT_GATE_SOURCE.relative_to(ROOT)),
            "commit_gate_source_sha256": sha256_file(COMMIT_GATE_SOURCE),
            "checker": str(CHECKER.relative_to(ROOT)),
            "checker_sha256": sha256_file(CHECKER),
            "layout": str(LAYOUT_SOURCE.relative_to(ROOT)),
            "layout_sha256": sha256_file(LAYOUT_SOURCE),
            "symmetric_source": str(SYM_SOURCE.relative_to(ROOT)),
            "symmetric_source_sha256": sha256_file(SYM_SOURCE),
            "auth_image_sha256": hashlib.sha256(auth).hexdigest(),
            "bridge_image_sha256": hashlib.sha256(bridge).hexdigest(),
            "commit_gate_image_sha256": hashlib.sha256(commit_gate).hexdigest(),
            "nasm_defines": [
                "TLS13_POC_K14=1",
                "TLS13_POC_READ_ONLY_INPUT=1",
            ],
            "nasm_cpu": "8086",
        },
        "layout": {
            "issuer_image": {
                "load": ["0x1800", "0x3400"],
                "content_bytes": len(auth),
                "rounded_sectors": K14_SECTORS,
                "rounded_bytes": K14_BYTES,
                "slack_bytes": K14_BYTES - len(auth),
            },
            "bridge_image": {
                "content_bytes": len(bridge),
                "rounded_sectors": 1,
                "slack_bytes": 512 - len(bridge),
            },
            "commit_gate_image": {
                "content_bytes": len(commit_gate),
                "rounded_sectors": 2,
                "slack_bytes": 1024 - len(commit_gate),
                "header_version": commit_version,
                "commit_entry": f"0x{commit_entry:04x}",
                "validate_ticket_only_entry": (
                    f"0x{validate_ticket_only_entry:04x}"
                ),
            },
            "relocated_input": {
                "start": f"0x{native_input_start:04x}",
                "end": f"0x{native_input_end:04x}",
                "bytes": native_input_end - native_input_start,
                "low_reload_boundary_guard": f"0x{native_guard_lo:04x}",
                "high_guard": [
                    f"0x{native_guard_hi:04x}",
                    f"0x{native_guard_hi + 8:04x}",
                ],
            },
            "symmetric_extension_work": [
                f"0x{native_sym_work_start:04x}",
                f"0x{native_sym_work_end:04x}",
            ],
            "ticket_state": {
                "psk": ["0x38b0", "0x38d0"],
                "identity_nonce_meta": ["0x3b40", "0x3c2d"],
                "relocated_bytes": 0,
            },
            "reconnect_bytes_consumed": 0,
            "relocated_input_retired_by_atomic_gate_bytes": 175,
            "stack_high_water_bytes": stack_high,
        },
        "static_instruction_gates": {
            "bridge": bridge_static,
            "atomic_commit_gate": commit_static,
        },
        "gates": {
            "actual_native_read_only_define": True,
            "exact_14_sector_load_stops_at_input": True,
            "real_live_leaf_signature_under_we1": True,
            "real_live_certificate_verify_under_committed_leaf": True,
            "parser_hash_and_trusted_time_required": True,
            "cv_staging_requires_same_generation_issuer_commit": True,
            "phase_reload_between_both_passes": True,
            "low_work_poisoned_between_passes": True,
            "ticket_psk_identity_nonce_meta_byte_stable": True,
            "symmetric_runtime_suffix_untouched_through_atomic_commit": True,
            "real_auth_output_accepted_by_atomic_commit_gate": True,
            "v4_ticket_only_validation_entry_present": True,
            "relocated_input_retired_before_atomic_commit": True,
            "resident_driver_reconnect_esc_arena_context_unchanged": True,
            "no_floppy_write_or_ticket_persistence_required": True,
            "bridge_and_atomic_gate_have_no_interrupt_or_port_io": True,
        },
        "comparison": {
            "issuer_input_relocation": {
                "bridge_content_bytes": len(bridge),
                "cold_sectors": 1,
                "atomic_gate_content_bytes": len(commit_gate),
                "combined_content_bytes": len(bridge) + len(commit_gate),
                "combined_cold_sectors": 3,
                "volatile_copy_bytes": 175,
                "ticket_copy_bytes": 0,
                "reconnect_bytes": 0,
                "product_area_impact": (
                    "0x3400 input unavailable through authentication; atomic "
                    "gate retires it before product reuse"
                ),
            },
            "ticket_relocation": {
                "volatile_ticket_bundle_bytes": 269,
                "copy_directions": 2,
                "reconnect_bytes": 330,
                "product_area_impact": (
                    "precommit reconnect block 0x3c9c..0x3de6 unavailable"
                ),
            },
            "recommendation": (
                "prefer issuer-input relocation while the exact K14 image and "
                "post-FO/post-parser phase order remain invariant"
            ),
        },
        "hard_dependencies": [
            "The symmetric 0x3400 controller and FO stream stage must retire before leaf staging.",
            "The parser/hash/trusted-time outputs must be complete before their overlapping 0x3600 leaf output is replaced by the issuer commit.",
            "Every issuer phase load must remain exactly 14 sectors and end at 0x3400.",
            "Future issuer growth beyond 7168 rounded bytes requires a new relocation decision.",
        ],
        "limitations": [
            "This is an isolated target-memory and exact-crypto gate, not live protected-flight/parser/TCP linkage.",
            "Trusted time establishment, bounded certificate decompression, session entropy, and cold restart remain open.",
            "The phase-order contract relies on trusted scheduler control flow; the guard bytes are overwrite sentinels, not a RAM MAC.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = main_gate()
    encoded = json.dumps(result, indent=2) + "\n"
    if args.json_out is not None:
        args.json_out.write_text(encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
