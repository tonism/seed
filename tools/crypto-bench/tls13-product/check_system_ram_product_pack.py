#!/usr/bin/env python3
"""Execute the orchestration boundaries in the shipped 16 KiB TLS 1.3 pack.

The primitive gates prove their individual arithmetic.  This gate covers the
composition that those tests cannot see: phase-key/destination binding, the
deadline ciphertext lifetime, both eight-entry lifecycle paths, authenticated
multi-record post processing, and the conventional-RAM-only write boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import struct
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_INTR,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_INS_IN,
    UC_X86_INS_OUT,
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DI,
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
POC = ROOT / "tools/crypto-bench/tls13-poc"
PACK_START_SECTOR = 45
SECTOR = 512
RAM_BYTES = 0x10000
STACK_TOP = 0x4000
RETURN = 0x0480

ACQUISITION_LIVE_C = (
    (0x3400, 272),
    (0x3600, 77),
    (0x355D, 99),
    (0x0500, 256),
    (0x33E8, 24),
    (0x3B40, 72),
    (0x0DE0, 288),
)
RESUMPTION_LIVE_C = (
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

CAPSULE_LOW = 0x0700
CAPSULE_HIGH = 0x3400
CAPSULE_LEN = 336
ACQ_HOLD = 0x2F40
COMPACT_ROOT = 0x35C0
FO_SELECTED = 0x3A60
SYM_ROOT = 0x3600
SYM_PROVISIONAL = 0x3620
SYM_CLIENT_KEY = 0x3838
SYM_CLIENT_IV = 0x3858
SYM_SERVER_KEY = 0x3864
SYM_SERVER_IV = 0x3884
SYM_RESUMPTION_MASTER = 0x3890
SYM_TICKET_PSK = 0x38B0
SYM_CLIENT_SEQ = 0x38E0
SYM_SERVER_SEQ = 0x38E8
SYM_IO = 0x39A0
SYM_TICKET_IDENTITY = 0x39A0
SYM_TICKET_LIFETIME = 0x3A80
SYM_TICKET_AGE_ADD = 0x3A84
SYM_TICKET_IDENTITY_LEN = 0x3A8A
POST_TICKET_TICK = 0x35FC
RESUME_AGE_STATE = 0x35C0
BIOS_TICKS = 0x046C
CONFIG_START = 0x3B9C
CONFIG_END = 0x3E40
ARENA_START = 0x3E40
ARENA_END = 0x3F00
ROOT_FRAME_START = 0x3F00
ROOT_FRAME_STATE = 0x3F06
ROOT_FRAME_PROMPT_MARKER = 0x3F1A
ROOT_FRAME_END = 0x3F1C
HANDOFF_RAM_TOP = 0x062C
DIRECT_STACK_TOP = 0x8000
DIRECT_ROOT_SHADOW = 0x7A00
DIRECT_ROOT_RETURN = DIRECT_ROOT_SHADOW + (ROOT_FRAME_END - ROOT_FRAME_START)
DIRECT_ROOT_TRAMPOLINE = DIRECT_ROOT_RETURN + 2
DIRECT_ARENA_END = 0x4000
RUNTIME_STATE_START = 0x0F55
RUNTIME_STATE_END = 0x0F69
DPI_PROMPT_MARKER_ROW = 0x0F33
LOW_STATIC_CONSTANTS_START = 0x0F69
LOW_STATIC_CRYPTO_OFFSET = 56
LOW_TAIL_STATE_START = 0x0FE2
LOW_TAIL_STATE_END = 0x1000
LOW_STATIC_CONSTANTS = (
    b"master secret"
    b"client finished"
    b"server finished"
    b"key expansion"
    + struct.pack(
        "<8H",
        0x7865,
        0x6170,
        0x646E,
        0x3320,
        0x2D32,
        0x7962,
        0x6574,
        0x6B20,
    )
    + b"\xfb"
    + b"\xff" * 15
    + b"\x03"
    + struct.pack(
        "<16H",
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
)
assert len(LOW_STATIC_CONSTANTS) == 121


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BUILDER = load_module(
    "seed_system_ram_product_builder",
    HERE / "build_system_ram_product_pack.py",
)
os.environ["TLS13_POC_K14"] = "1"
sys.path.insert(0, str(POC))
SYM = load_module(
    "seed_system_ram_sym_oracle",
    POC / "check_tls13_sym_overlay.py",
)
HELLO = load_module(
    "seed_system_ram_hello_oracle",
    POC / "hello_check.py",
)
FO = load_module(
    "seed_system_ram_fo_oracle",
    POC / "fo_tail_check.py",
)
KEYGEN = load_module(
    "seed_system_ram_keygen_oracle",
    POC.parent / "tls13-spike" / "mlkem768_integrated_keygen_check.py",
)
SYSTEM_AUTH = load_module(
    "seed_system_ram_auth_oracle",
    POC / "system_ram_auth_check.py",
)

SYSTEM_REGENERATE_DOMAIN = b"S13 8088 attempt v2\0"

# Product deadline fixtures negotiate h2 and use credential-free SETTINGS.
SYM.RESUMED_ENCRYPTED_EXTENSIONS = bytes.fromhex("0800000f000d00000000001000050003026832")
SYM.HEAD_REQUEST = (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes.fromhex("000018040000000000") +
                    b"".join(struct.pack(">HI", k, v) for k,v in ((1,0),(2,0),(4,0),(6,4096))))


def deterministic(label: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"Seed shipped RAM-only pack|" + label).digest(length)


def noncanonical_mlkem768_public_coefficients(public_key: bytes) -> list[int]:
    """Return coefficient indexes that violate ML-KEM-768's 12-bit encoding."""

    if len(public_key) != 1184:
        raise AssertionError("ML-KEM-768 public key length drifted")
    invalid: list[int] = []
    for offset in range(0, 1152, 3):
        first = public_key[offset] | ((public_key[offset + 1] & 0x0F) << 8)
        second = (public_key[offset + 1] >> 4) | (public_key[offset + 2] << 4)
        if first >= 3329:
            invalid.append((offset // 3) * 2)
        if second >= 3329:
            invalid.append((offset // 3) * 2 + 1)
    return invalid


def padded(value: bytes, sectors: int) -> bytes:
    if len(value) > sectors * SECTOR:
        raise AssertionError("phase exceeds its declared slot")
    return value + bytes(sectors * SECTOR - len(value))


def invalidate_code(machine: Uc, start: int, end: int) -> None:
    """Discard translated code after replacing a phase in conventional RAM."""
    machine.ctl_remove_cache(start, end)


def scatter(machine: Uc, value: bytes, spans: tuple[tuple[int, int], ...]) -> None:
    offset = 0
    for address, length in spans:
        machine.mem_write(address, value[offset : offset + length])
        offset += length
    if offset != len(value):
        raise AssertionError("scatter does not cover its exact object")


def gather(machine: Uc, spans: tuple[tuple[int, int], ...]) -> bytes:
    return b"".join(
        bytes(machine.mem_read(address, length)) for address, length in spans
    )


def set_carry(machine: Uc, carry: bool) -> None:
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    machine.reg_write(
        UC_X86_REG_EFLAGS,
        (flags | 1) if carry else (flags & ~1),
    )


def near_return(machine: Uc, *, carry: bool = False) -> None:
    sp = machine.reg_read(UC_X86_REG_SP) & 0xFFFF
    target = struct.unpack("<H", bytes(machine.mem_read(sp, 2)))[0]
    machine.reg_write(UC_X86_REG_SP, (sp + 2) & 0xFFFF)
    set_carry(machine, carry)
    machine.reg_write(UC_X86_REG_IP, target)


def install_io_rejection(machine: Uc) -> None:
    def reject_interrupt(_uc: Uc, number: int, _user: object) -> None:
        raise AssertionError(f"orchestration issued BIOS interrupt {number:#x}")

    def reject_in(_uc: Uc, port: int, size: int, _user: object) -> int:
        raise AssertionError(f"orchestration read I/O port {port:#x}/{size}")

    def reject_out(
        _uc: Uc,
        port: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        raise AssertionError(
            f"orchestration wrote I/O port {port:#x}/{size}={value:#x}"
        )

    machine.hook_add(UC_HOOK_INTR, reject_interrupt)
    machine.hook_add(UC_HOOK_INSN, reject_in, None, 1, 0, UC_X86_INS_IN)
    machine.hook_add(UC_HOOK_INSN, reject_out, None, 1, 0, UC_X86_INS_OUT)


def install_machine_guards(machine: Uc) -> dict[str, tuple[int, bytes]]:
    guards = {
        "config/cache": (
            CONFIG_START,
            deterministic(b"config", CONFIG_END - CONFIG_START),
        ),
        "arena/context": (
            ARENA_START,
            deterministic(b"arena", ARENA_END - ARENA_START),
        ),
        # The product root publishes return metadata plus the resident
        # UI/control snapshot once, before any cold overlay may replace its
        # active stack.  Every phase except the final success/abort consumer
        # must preserve the complete frame exactly.
        "root return frame": (
            ROOT_FRAME_START,
            deterministic(b"root return frame", ROOT_FRAME_END - ROOT_FRAME_START),
        ),
        "MDA/CGA video": (0xB000, deterministic(b"video", 0x1000)),
        "adapter RAM": (0xD000, deterministic(b"adapter", 0x1000)),
    }
    for address, value in guards.values():
        machine.mem_write(address, value)
    return guards


def assert_machine_guards(
    machine: Uc, guards: dict[str, tuple[int, bytes]]
) -> None:
    for name, (address, expected) in guards.items():
        actual = bytes(machine.mem_read(address, len(expected)))
        if actual != expected:
            raise AssertionError(f"orchestration changed {name}")


def build_exact(
    core: Path,
    listing: Path,
    work: Path,
) -> tuple[dict[str, Any], list[Any], dict[str, Any], bytes]:
    images = BUILDER.build_independent(work)
    slots, named = BUILDER.make_layout(images)
    BUILDER.build_dependent(
        work,
        images,
        named,
        core.read_bytes(),
        listing,
    )
    pack = BUILDER.build_pack(work, slots)
    return images, slots, named, pack


def build_mlkem_composition_vector(work: Path) -> dict[str, bytes]:
    """Load the frozen FIPS-derived key/ciphertext pair used by the real gate."""

    image = BUILDER.assemble(
        work,
        "system_ram_composition_vectors",
        POC / "mlkem_candidate_vectors.asm",
    )

    def value(start: str, end: str | None = None, length: int | None = None) -> bytes:
        offset = BUILDER.label_offset(image.listing, start)
        if end is not None:
            finish = BUILDER.label_offset(image.listing, end)
        elif length is not None:
            finish = offset + length
        else:
            raise AssertionError("composition vector needs an end or length")
        return image.data[offset:finish]

    dk = value("fixture_dk", "fixture_dk_end")
    ciphertext = value("fixture_ciphertext", "fixture_ciphertext_end")
    candidate_g = value("fixture_expected_g", length=64)
    if len(dk) != 2400 or len(ciphertext) != 1088 or len(candidate_g) != 64:
        raise AssertionError("frozen ML-KEM composition vector geometry drifted")
    return {
        "dk": dk,
        "public_key": dk[1152:2336],
        "ciphertext": ciphertext,
        "candidate_g": candidate_g,
    }


def deadline_fixture(
    vector: dict[str, bytes], *, resumed: bool
) -> dict[str, bytes]:
    """Construct a transcript whose ML-KEM share is the frozen real vector."""

    client_hello = SYM.O.build_fixed_client_hello(vector["public_key"])
    parsed = SYM.O.parse_fixed_client_hello(client_hello)
    server_x = deterministic(
        (b"resumption" if resumed else b"acquisition") + b" server X",
        32,
    )
    server_hello = SYM.O.build_fixed_server_hello(
        parsed.session_id,
        vector["ciphertext"],
        server_x,
    )
    shared = vector["candidate_g"][:32] + server_x
    psk = deterministic(b"composed resumption ticket PSK", 32)
    application: dict[str, bytes] = {}
    resumption_master = b""
    if resumed:
        identity = deterministic(b"composed resumption ticket identity", 64)
        placeholder, truncated = SYM.build_resumption_client_hello(
            client_hello,
            identity,
            0x10203040,
            bytes(32),
        )
        zeros = bytes(32)
        empty_hash = hashlib.sha256(b"").digest()
        early = SYM.BASE.hkdf_extract(zeros, psk)
        binder_key = SYM.BASE.hkdf_expand_label(
            early, b"res binder", empty_hash, 32
        )
        binder_finished = SYM.BASE.hkdf_expand_label(
            binder_key, b"finished", b"", 32
        )
        binder = hmac.new(
            binder_finished,
            hashlib.sha256(truncated).digest(),
            hashlib.sha256,
        ).digest()
        client_hello, rebuilt_truncated = SYM.build_resumption_client_hello(
            client_hello,
            identity,
            0x10203040,
            binder,
        )
        if rebuilt_truncated != truncated or placeholder[:-32] != client_hello[:-32]:
            raise AssertionError("composed resumption binder changed its transcript")
        server_hello = SYM.build_resumption_server_hello(server_hello)
        transcript = client_hello + server_hello
        early_derived = SYM.BASE.hkdf_expand_label(
            early, b"derived", empty_hash, 32
        )
        handshake_secret = SYM.BASE.hkdf_extract(early_derived, shared)
        expected = SYM.derive_traffic(handshake_secret, transcript)
        resumed_ee = SYM.RESUMED_ENCRYPTED_EXTENSIONS
        server_verify = hmac.new(
            expected["server_finished"],
            hashlib.sha256(transcript + resumed_ee).digest(),
            hashlib.sha256,
        ).digest()
        server_finished = b"\x14\x00\x00\x20" + server_verify
        through_server_finished = transcript + resumed_ee + server_finished
        resumed_record = SYM.BASE.encrypted_record(
            expected["server_key"],
            expected["server_iv"],
            0,
            SYM.O.CONTENT_HANDSHAKE,
            resumed_ee + server_finished,
        )
        client_verify = hmac.new(
            expected["client_finished"],
            hashlib.sha256(through_server_finished).digest(),
            hashlib.sha256,
        ).digest()
        client_message = b"\x14\x00\x00\x20" + client_verify
        client_finished_record = SYM.BASE.encrypted_record(
            expected["client_key"],
            expected["client_iv"],
            0,
            SYM.O.CONTENT_HANDSHAKE,
            client_message,
        )
        application = SYM.O._derive_application(
            expected["handshake_secret"], through_server_finished
        )
        resumption_master = SYM.BASE.derive_secret(
            application["master_secret"],
            b"res master",
            through_server_finished + client_message,
        )
        head_record = SYM.BASE.encrypted_record(
            application["client_key"],
            application["client_iv"],
            0,
            SYM.O.CONTENT_APPLICATION_DATA,
            SYM.HEAD_REQUEST,
        )
    else:
        early_derived = b""
        transcript = client_hello + server_hello
        expected = SYM.derive_handshake(shared, transcript)
        server_verify = b""
        resumed_record = b""
        client_finished_record = b""
        head_record = b""
    return {
        "transcript": transcript,
        "handoff": SYM.build_hello_handoff(transcript, server_x),
        "psk": psk,
        "early_derived": early_derived,
        "shared": shared,
        "handshake_secret": expected["handshake_secret"],
        "client_key": expected["client_key"],
        "client_iv": expected["client_iv"],
        "server_key": expected["server_key"],
        "server_iv": expected["server_iv"],
        "server_verify": server_verify,
        "resumed_tail": b"\x14\x03\x03\x00\x01\x01" + resumed_record,
        "client_finished_record": client_finished_record,
        "head_record": head_record,
        "client_app_key": application.get("client_key", b""),
        "client_app_iv": application.get("client_iv", b""),
        "server_app_key": application.get("server_key", b""),
        "server_app_iv": application.get("server_iv", b""),
        "resumption_master": resumption_master,
    }


def check_shipped_pack(
    expected: bytes,
    slots: list[Any],
    shipped_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    shipped = shipped_path.read_bytes()
    if shipped != expected:
        raise AssertionError("shipped RAM-only pack differs from exact rebuild")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema") != "seed-tls13-system-ram-product-pack-v1":
        raise AssertionError("RAM-only pack report schema drifted")
    boundary = report.get("security_boundary", {})
    required_false = (
        "display_ram",
        "adapter_ram",
        "config_escrow",
        "writable_media",
        "entropy_only_reads",
    )
    if any(boundary.get(name) is not False for name in required_false):
        raise AssertionError("RAM-only pack report weakened its security boundary")
    if hashlib.sha256(shipped).hexdigest() != report["pack"]["sha256"]:
        raise AssertionError("RAM-only pack report hash is stale")
    if shipped.count(b"T13SYM02") != 1:
        raise AssertionError("shipped pack lost its sole canonical 286 image")
    for slot in slots:
        start = (slot.start - PACK_START_SECTOR) * SECTOR
        value = shipped[start : start + slot.sectors * SECTOR]
        expected_slot = padded(
            slot.image.data if slot.image is not None else b"",
            slot.sectors,
        )
        if value != expected_slot:
            raise AssertionError(f"shipped phase {slot.name} differs from ledger")
    return report


def root_state_gate(images: dict[str, Any]) -> dict[str, Any]:
    """Prove the cold root snapshots and both normal failure cleanup restores UI state."""

    expected_state = deterministic(
        b"root resident UI/control state", RUNTIME_STATE_END - RUNTIME_STATE_START
    )
    expected_prompt_marker = b"\x93"
    root_sp = STACK_TOP - 2

    root_machine = Uc(UC_ARCH_X86, UC_MODE_16)
    root_machine.mem_map(0, RAM_BYTES)
    root_machine.mem_write(0, bytes(RAM_BYTES))
    root_machine.mem_write(0x3400, padded(images["root"].data, 1))
    root_machine.mem_write(RUNTIME_STATE_START, expected_state)
    root_machine.mem_write(DPI_PROMPT_MARKER_ROW, expected_prompt_marker)
    root_machine.mem_write(0x15DB, struct.pack("<H", 0x04A0))
    root_guards = install_machine_guards(root_machine)
    root_guards.pop("root return frame")
    root_machine.mem_write(root_sp, struct.pack("<H", RETURN))
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        root_machine.reg_write(register, 0)
    root_machine.reg_write(UC_X86_REG_SP, root_sp)
    root_machine.reg_write(UC_X86_REG_EFLAGS, 2)
    root_machine.reg_write(UC_X86_REG_AX, 0)
    reached_load = False

    def nic_return(uc: Uc, _address: int, _size: int, _user: object) -> None:
        near_return(uc)

    def stop_at_first_load(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal reached_load
        reached_load = True
        uc.emu_stop()

    root_machine.hook_add(UC_HOOK_CODE, nic_return, begin=0x04A0, end=0x04A0)
    root_machine.hook_add(
        UC_HOOK_CODE,
        stop_at_first_load,
        begin=0x10C4,
        end=0x10C4,
    )
    install_io_rejection(root_machine)
    root_machine.emu_start(0x3400, 0, count=20_000)
    if not reached_load:
        raise AssertionError("product root did not reach its first phase load")
    if bytes(root_machine.mem_read(ROOT_FRAME_STATE, len(expected_state))) != expected_state:
        raise AssertionError("product root captured the wrong resident UI/control state")
    if root_machine.mem_read(ROOT_FRAME_PROMPT_MARKER, 1) != expected_prompt_marker:
        raise AssertionError("product root did not capture the DPI prompt marker row")
    if bytes(root_machine.mem_read(ROOT_FRAME_START, 6)) != struct.pack(
        "<3H", root_sp, (~root_sp) & 0xFFFF, 0xA55A
    ):
        raise AssertionError("product root did not publish a coherent return frame")
    if bytes(root_machine.mem_read(0x0F60, len(images["abort"].data))) != images[
        "abort"
    ].data:
        raise AssertionError("product root did not install its checked low abort")
    assert_machine_guards(root_machine, root_guards)

    abort_machine = Uc(UC_ARCH_X86, UC_MODE_16)
    abort_machine.mem_map(0, RAM_BYTES)
    abort_machine.mem_write(0, bytes(RAM_BYTES))
    abort_machine.mem_write(
        RUNTIME_STATE_START,
        deterministic(b"overwritten abort UI/control state", len(expected_state)),
    )
    abort_machine.mem_write(DPI_PROMPT_MARKER_ROW, b"\x2a")
    # Match the real order: the root snapshots state, then installing abort at
    # 0f60 overwrites the tail of the live low band.
    abort_machine.mem_write(0x0F60, images["abort"].data)
    abort_guards = install_machine_guards(abort_machine)
    abort_guards.pop("root return frame")
    abort_machine.mem_write(
        ROOT_FRAME_START,
        struct.pack("<3H", root_sp, (~root_sp) & 0xFFFF, 0xA55A),
    )
    abort_machine.mem_write(ROOT_FRAME_STATE, expected_state)
    abort_machine.mem_write(ROOT_FRAME_PROMPT_MARKER, expected_prompt_marker)
    abort_machine.mem_write(root_sp, struct.pack("<H", RETURN))
    for start, end in ((0x0500, 0x0600), (0x0700, 0x0F60), (0x1800, 0x3B9C)):
        abort_machine.mem_write(
            start,
            deterministic(f"abort private {start:04x}".encode(), end - start),
        )
    abort_machine.mem_write(0x06C4, b"\x7f")
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        abort_machine.reg_write(register, 0)
    abort_machine.reg_write(UC_X86_REG_SP, 0x3F80)
    abort_machine.reg_write(UC_X86_REG_EFLAGS, 2)
    returned = False

    def stop_return(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    abort_machine.hook_add(UC_HOOK_CODE, stop_return, begin=RETURN, end=RETURN)
    install_io_rejection(abort_machine)
    abort_machine.emu_start(0x0F60, 0, count=100_000)
    if not returned or abort_machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("low abort did not return on the captured root stack")
    if not (abort_machine.reg_read(UC_X86_REG_EFLAGS) & 1):
        raise AssertionError("low abort returned without carry")
    if bytes(abort_machine.mem_read(RUNTIME_STATE_START, len(expected_state))) != expected_state:
        raise AssertionError("low abort did not restore resident UI/control state")
    if abort_machine.mem_read(DPI_PROMPT_MARKER_ROW, 1) != expected_prompt_marker:
        raise AssertionError("low abort did not restore the DPI prompt marker row")
    if bytes(
        abort_machine.mem_read(ROOT_FRAME_START, ROOT_FRAME_END - ROOT_FRAME_START)
    ) != bytes(ROOT_FRAME_END - ROOT_FRAME_START):
        raise AssertionError("low abort retained its return/state frame")
    for start, end, name in (
        (0x0500, 0x0600, "SHA workspace"),
        (0x0700, DPI_PROMPT_MARKER_ROW, "low TLS scratch prefix"),
        (DPI_PROMPT_MARKER_ROW + 1, RUNTIME_STATE_START, "low TLS scratch suffix"),
        (0x1800, 0x3B9C, "high TLS scratch"),
    ):
        if bytes(abort_machine.mem_read(start, end - start)) != bytes(end - start):
            raise AssertionError(f"low abort retained {name}")
    if abort_machine.mem_read(0x06C4, 1) != b"\x00":
        raise AssertionError("low abort retained the route capability")
    assert_machine_guards(abort_machine, abort_guards)

    direct_arena = deterministic(
        b"direct-tier arena and context",
        DIRECT_ARENA_END - ARENA_START,
    )
    trampoline_start = BUILDER.label_address(
        images["root"].listing,
        "direct_root_trampoline_image",
        0x3400,
    )
    trampoline_end = BUILDER.label_address(
        images["root"].listing,
        "direct_root_trampoline_image_end",
        0x3400,
    )
    trampoline = images["root"].data[
        trampoline_start - 0x3400 : trampoline_end - 0x3400
    ]

    def direct_root_machine() -> Uc:
        machine = Uc(UC_ARCH_X86, UC_MODE_16)
        machine.mem_map(0, RAM_BYTES)
        machine.mem_write(0, bytes(RAM_BYTES))
        machine.mem_write(0x3400, padded(images["root"].data, 1))
        machine.mem_write(ARENA_START, direct_arena)
        machine.mem_write(RUNTIME_STATE_START, expected_state)
        machine.mem_write(DPI_PROMPT_MARKER_ROW, expected_prompt_marker)
        machine.mem_write(HANDOFF_RAM_TOP, struct.pack("<H", DIRECT_STACK_TOP))
        machine.mem_write(0x15DB, struct.pack("<H", 0x04A0))
        machine.mem_write(DIRECT_STACK_TOP - 2, struct.pack("<H", RETURN))
        guards = install_machine_guards(machine)
        guards.pop("arena/context")
        guards.pop("root return frame")
        # install_machine_guards writes its 16 KiB sentinels after the direct
        # arena.  Restore the exact larger-tier input before entering root.
        machine.mem_write(ARENA_START, direct_arena)
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            machine.reg_write(register, 0)
        machine.reg_write(UC_X86_REG_SP, DIRECT_STACK_TOP - 2)
        machine.reg_write(UC_X86_REG_EFLAGS, 2)
        machine.reg_write(UC_X86_REG_AX, 1)
        reached_load = False

        def direct_nic_return(
            uc: Uc, _address: int, _size: int, _user: object
        ) -> None:
            near_return(uc)

        def direct_stop_at_first_load(
            uc: Uc, _address: int, _size: int, _user: object
        ) -> None:
            nonlocal reached_load
            reached_load = True
            uc.emu_stop()

        machine.hook_add(
            UC_HOOK_CODE,
            direct_nic_return,
            begin=0x04A0,
            end=0x04A0,
        )
        machine.hook_add(
            UC_HOOK_CODE,
            direct_stop_at_first_load,
            begin=0x10C4,
            end=0x10C4,
        )
        install_io_rejection(machine)
        machine.emu_start(0x3400, 0, count=20_000)
        if not reached_load:
            raise AssertionError("direct-tier root did not reach its first phase load")
        original_overlap = direct_arena[
            ROOT_FRAME_START - ARENA_START : ROOT_FRAME_END - ARENA_START
        ]
        if bytes(
            machine.mem_read(DIRECT_ROOT_SHADOW, len(original_overlap))
        ) != original_overlap:
            raise AssertionError("direct-tier root shadowed the wrong arena bytes")
        if bytes(machine.mem_read(DIRECT_ROOT_RETURN, 2)) != struct.pack(
            "<H", RETURN
        ):
            raise AssertionError("direct-tier root did not preserve its caller return")
        if bytes(
            machine.mem_read(DIRECT_ROOT_TRAMPOLINE, len(trampoline))
        ) != trampoline:
            raise AssertionError("direct-tier root installed the wrong return trampoline")
        if bytes(machine.mem_read(DIRECT_STACK_TOP - 2, 2)) != struct.pack(
            "<H", DIRECT_ROOT_TRAMPOLINE
        ):
            raise AssertionError("direct-tier root did not chain its caller return")
        if bytes(machine.mem_read(ROOT_FRAME_STATE, len(expected_state))) != expected_state:
            raise AssertionError("direct-tier root captured the wrong UI/control state")
        if machine.mem_read(ROOT_FRAME_PROMPT_MARKER, 1) != expected_prompt_marker:
            raise AssertionError("direct-tier root did not capture the DPI prompt marker row")
        assert_machine_guards(machine, guards)
        return machine

    def finish_direct_return(machine: Uc, entry: int, carry: bool) -> None:
        returned = False

        def stop_direct_return(
            uc: Uc, _address: int, _size: int, _user: object
        ) -> None:
            nonlocal returned
            returned = True
            uc.emu_stop()

        machine.hook_add(
            UC_HOOK_CODE,
            stop_direct_return,
            begin=RETURN,
            end=RETURN,
        )
        machine.reg_write(UC_X86_REG_SP, 0x7F80)
        machine.reg_write(UC_X86_REG_EFLAGS, 2)
        machine.reg_write(UC_X86_REG_DX, expected_prompt_marker[0])
        machine.emu_start(entry, 0, count=100_000)
        if not returned or machine.reg_read(UC_X86_REG_SP) != DIRECT_STACK_TOP:
            raise AssertionError("direct-tier cleanup did not return on its root stack")
        actual_carry = bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1)
        if actual_carry != carry:
            raise AssertionError("direct-tier trampoline changed the cleanup carry")
        if bytes(machine.mem_read(ARENA_START, len(direct_arena))) != direct_arena:
            raise AssertionError("direct-tier cleanup did not restore arena/context")
        if bytes(
            machine.mem_read(
                DIRECT_ROOT_SHADOW,
                DIRECT_ROOT_TRAMPOLINE - DIRECT_ROOT_SHADOW,
            )
        ) != bytes(DIRECT_ROOT_TRAMPOLINE - DIRECT_ROOT_SHADOW):
            raise AssertionError("direct-tier cleanup retained its arena shadow")

    high_abort_entry = BUILDER.label_address(
        images["auth_return"].listing, "sysram_high_abort", 0x3550
    )
    for abort_origin, abort_entry, abort_image in (
        (0x0F60, 0x0F60, images["abort"]),
        (0x3550, high_abort_entry, images["auth_return"]),
    ):
        direct_abort = direct_root_machine()
        direct_abort.mem_write(
            RUNTIME_STATE_START,
            deterministic(b"direct overwritten UI/control state", len(expected_state)),
        )
        direct_abort.mem_write(DPI_PROMPT_MARKER_ROW, b"\x2a")
        for start, end in ((0x0500, 0x0600), (0x0700, 0x0F60), (0x1800, 0x3B9C)):
            direct_abort.mem_write(
                start,
                deterministic(f"direct abort private {start:04x}".encode(), end - start),
            )
        direct_abort.mem_write(abort_origin, abort_image.data)
        finish_direct_return(direct_abort, abort_entry, True)
        if bytes(direct_abort.mem_read(RUNTIME_STATE_START, len(expected_state))) != expected_state:
            raise AssertionError("direct-tier abort did not restore UI/control state")
        if direct_abort.mem_read(DPI_PROMPT_MARKER_ROW, 1) != expected_prompt_marker:
            raise AssertionError("direct-tier abort did not restore the DPI prompt marker row")

    direct_success = direct_root_machine()
    direct_success.mem_write(0x0F00, images["success"].data)
    finish_direct_return(direct_success, 0x0F00, False)

    return {
        "resident_state": f"{RUNTIME_STATE_START:#06x}..{RUNTIME_STATE_END:#06x}",
        "root_frame": f"{ROOT_FRAME_START:#06x}..{ROOT_FRAME_END:#06x}",
        "root_snapshot_status_last": True,
        "low_abort_restored_state": True,
        "direct_high_auth_abort_restored_state": True,
        "direct_arena_shadow": (
            f"{DIRECT_ROOT_SHADOW:#06x}..{DIRECT_ROOT_RETURN + 2:#06x}"
        ),
        "direct_success_abort_restored_arena": True,
        "direct_trampoline_preserved_carry": True,
    }


def high_auth_abort_gate(
    images: dict[str, Any], named: dict[str, Any]
) -> dict[str, Any]:
    """Execute rejected authentication through the real high cleanup capsule."""
    origin = named["auth_return"].destination
    entry = BUILDER.label_address(
        images["auth_return"].listing, "sysram_high_abort", origin
    )
    expected_state = deterministic(b"high abort UI", RUNTIME_STATE_END - RUNTIME_STATE_START)
    expected_prompt = b"\x93"
    cases = (
        ("certificate_verify_rejected", origin, 0, 0, True),
        ("wrong_result", origin, 0, 1, False),
        ("uncommitted_status", origin, 1, 0, False),
        ("auth_image_load_failed", entry, 0, 0, True),
        ("symmetric_reload_failed", origin, 1, 1, False),
    )
    for name, start_ip, result_ax, status, carry in cases:
        machine = Uc(UC_ARCH_X86, UC_MODE_16)
        machine.mem_map(0, RAM_BYTES)
        machine.mem_write(0, bytes(RAM_BYTES))
        for start, end in ((0x0500, 0x0600), (0x0700, 0x1000), (0x1800, 0x3B9C)):
            machine.mem_write(start, deterministic(name.encode(), end - start))
        machine.mem_write(origin, images["auth_return"].data)
        guards = install_machine_guards(machine)
        guards.pop("root return frame")
        resident = deterministic(b"high abort resident/driver", 0x800)
        machine.mem_write(0x1000, resident)
        guards["resident/driver"] = (0x1000, resident)
        root_sp = STACK_TOP - 2
        machine.mem_write(ROOT_FRAME_START, struct.pack("<3H", root_sp, (~root_sp) & 0xFFFF, 0xA55A))
        machine.mem_write(ROOT_FRAME_STATE, expected_state)
        machine.mem_write(ROOT_FRAME_PROMPT_MARKER, expected_prompt)
        machine.mem_write(root_sp, struct.pack("<H", RETURN))
        machine.mem_write(0x34AA, bytes([status]))
        machine.mem_write(0x06C4, b"\x7f")
        for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            machine.reg_write(register, 0)
        machine.reg_write(UC_X86_REG_SP, 0x3F80)
        machine.reg_write(UC_X86_REG_AX, result_ax)
        machine.reg_write(UC_X86_REG_EFLAGS, 2 | int(carry))
        returned = False
        loads = []
        erased = set()

        def stop_return(uc: Uc, _address: int, _size: int, _user: object) -> None:
            nonlocal returned
            returned = True
            uc.emu_stop()

        def fail_reload(uc: Uc, _address: int, _size: int, _user: object) -> None:
            loads.append((uc.reg_read(UC_X86_REG_AX), uc.reg_read(UC_X86_REG_BX)))
            # A partial failed read may have overwritten the old K image.
            uc.mem_write(0x1800, bytes(64))
            near_return(uc, carry=True)

        def record_erase(
            _uc: Uc, _access: int, address: int, size: int, value: int, _user: object
        ) -> None:
            if value == 0:
                erased.update(range(address, address + size))

        def reject_erased_code(uc: Uc, address: int, _size: int, _user: object) -> None:
            if address in erased:
                raise AssertionError(f"{name} executed zeroized auth-return code at {address:#06x}")

        machine.hook_add(UC_HOOK_CODE, stop_return, begin=RETURN, end=RETURN)
        machine.hook_add(UC_HOOK_CODE, fail_reload, begin=0x10C4, end=0x10C4)
        machine.hook_add(UC_HOOK_MEM_WRITE, record_erase, begin=origin, end=entry - 1)
        machine.hook_add(UC_HOOK_CODE, reject_erased_code, begin=origin, end=entry - 1)
        install_io_rejection(machine)
        machine.emu_start(start_ip, 0, count=100_000)
        if not returned or machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
            raise AssertionError(f"{name} did not return on the captured root stack")
        if not machine.reg_read(UC_X86_REG_EFLAGS) & 1:
            raise AssertionError(f"{name} lost its failure carry")
        expected_loads = [(named["acq_sym"].key, 0x1800)] if name == "symmetric_reload_failed" else []
        if loads != expected_loads:
            raise AssertionError(f"{name} requested unexpected phase loads: {loads}")
        if bytes(machine.mem_read(RUNTIME_STATE_START, len(expected_state))) != expected_state:
            raise AssertionError(f"{name} did not restore resident UI/control state")
        if machine.mem_read(DPI_PROMPT_MARKER_ROW, 1) != expected_prompt:
            raise AssertionError(f"{name} did not restore the prompt marker")
        for start, end in (
            (0x0500, 0x0600),
            (0x0700, DPI_PROMPT_MARKER_ROW),
            (DPI_PROMPT_MARKER_ROW + 1, RUNTIME_STATE_START),
            (RUNTIME_STATE_END, 0x1000),
            (0x1800, entry),
            (0x3600, 0x3B9C),
            (ROOT_FRAME_START, ROOT_FRAME_END),
        ):
            if any(machine.mem_read(start, end - start)):
                raise AssertionError(f"{name} retained private bytes at {start:#06x}..{end:#06x}")
        if machine.mem_read(0x06C4, 1) != b"\0":
            raise AssertionError(f"{name} retained the route capability")
        assert_machine_guards(machine, guards)
    return {
        "cases": [case[0] for case in cases],
        "disk_independent_cleanup": True,
        "zeroized_code_never_executed": True,
        "private_state_retired": True,
        "resident_config_arena_video_adapter_unchanged": True,
    }


def deadline_gate(
    images: dict[str, Any],
    named: dict[str, Any],
    vector: dict[str, bytes],
    *,
    resumed: bool,
) -> dict[str, Any]:
    prefix = "resumption" if resumed else "acquisition"
    high = images[f"{prefix}_deadline"]
    terminal = images[f"{prefix}_deadline_terminal"]
    sym_name = "res_sym" if resumed else "acq_sym"
    protected_name = "resumed_protected" if resumed else "fresh_protected"
    sym_image = images[sym_name]
    protected = images[protected_name]
    live_spans = RESUMPTION_LIVE_C if resumed else ACQUISITION_LIVE_C
    fixture = deadline_fixture(vector, resumed=resumed)
    ciphertext = vector["ciphertext"]
    provisional = vector["candidate_g"][:32]
    root = deterministic(prefix.encode() + b" root", 32)

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes(RAM_BYTES))
    machine.mem_write(0x3400, padded(high.data, named[f"{prefix}_deadline"].sectors))
    # The product predecessor loaded the complete route-specific symmetric
    # image before TCP.  KeyGen and HELLO replace its prefix and use work above
    # 0x3000, but leave this immutable final-sector prefix intact.  Its endpoint
    # is also the exact start of the retained acquisition/resumption root.
    # Seed it here so the deadline gate proves that the controller consumes the
    # pre-staged bytes and never silently reintroduces a critical-window read.
    sym_tail_bytes = 0x01E0 if resumed else 0x0140
    sym_tail = sym_image.data[11 * SECTOR : 11 * SECTOR + sym_tail_bytes]
    if len(sym_tail) != sym_tail_bytes:
        raise AssertionError(f"{prefix} immutable symmetric tail is truncated")
    machine.mem_write(0x2E00, sym_tail)
    machine.mem_write(0x08C0, ciphertext)
    dk = vector["dk"]
    machine.mem_write(0x3600, dk[0:384])
    machine.mem_write(0x3780, dk[2336:2368])
    machine.mem_write(0x37A0, dk[2368:2400])
    machine.mem_write(0x3800, dk[384:768])
    machine.mem_write(0x3980, dk[768:1152])
    machine.mem_write(SYM.HELLO_SERVER_X, fixture["handoff"])
    if resumed:
        machine.mem_write(0x0DC0, fixture["psk"])
    machine.mem_write(0x2FE0 if resumed else 0x2F40, root)
    if resumed:
        tail = fixture["resumed_tail"]
        if len(tail) != 83:
            raise AssertionError(
                f"resumed coalesced-tail fixture is {len(tail)} bytes"
            )
        machine.mem_write(0x0F16, struct.pack("<H", len(tail)))
        machine.mem_write(0x0F18, tail[:72])
        machine.mem_write(0x3B90, tail[72:])
    guards = install_machine_guards(machine)
    install_io_rejection(machine)
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))

    batch = 0x0700 + BUILDER.label_offset(terminal.listing, "batch_phase")
    sym_entries = struct.unpack_from("<19H", sym_image.data, 32)
    loads: list[tuple[int, int]] = []
    reached_protected = False
    protected_complete = False
    sent_records: list[bytes] = []
    protected_trace: list[str] = []
    writes_above_floor: list[tuple[int, int]] = []
    resumed_pre_schedule: dict[str, bytes] = {}

    candidate_key = named["candidate_live"].key
    expected_sym_key = (
        BUILDER.key(named["res_sym"].start, 11)
        if resumed
        else BUILDER.key(named["acq_sym"].start, 11)
    )
    protected_key = named[protected_name].key
    protected_batch_key = (
        protected_key
        if named[protected_name].sectors <= 2
        else BUILDER.key(named[protected_name].start, 2)
    )

    def load_phase(uc: Uc, _address: int, _size: int, _user: object) -> None:
        phase_key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        loads.append((phase_key, destination))
        if phase_key == candidate_key:
            payload = padded(
                images["candidate_live"].data,
                named["candidate_live"].sectors,
            )
        elif phase_key == expected_sym_key:
            count = phase_key >> 8
            payload = padded(sym_image.data, named[sym_name].sectors)[: count * SECTOR]
        elif phase_key == protected_batch_key:
            payload = padded(protected.data, named[protected_name].sectors)[
                : (phase_key >> 8) * SECTOR
            ]
        else:
            raise AssertionError(f"deadline requested unexpected phase {phase_key:#06x}")
        uc.mem_write(destination, payload)
        invalidate_code(uc, destination, destination + len(payload))
        near_return(uc)

    def resident_load(uc: Uc, _address: int, _size: int, _user: object) -> None:
        phase_key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        protected_tail_key = BUILDER.key(named[protected_name].start + 2, 1)
        if (
            not resumed
            and phase_key == protected_tail_key
            and destination == 0x0700
        ):
            payload = padded(protected.data, named[protected_name].sectors)[
                2 * SECTOR : 3 * SECTOR
            ]
        else:
            raise AssertionError(
                f"deadline requested unexpected resident phase {phase_key:#06x}"
            )
        loads.append((phase_key, destination))
        uc.mem_write(destination, payload)
        invalidate_code(uc, destination, destination + len(payload))
        near_return(uc)

    def stop_protected(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal reached_protected
        reached_protected = True
        if resumed:
            retained_len = struct.unpack(
                "<H", bytes(uc.mem_read(0x0F16, 2))
            )[0]
            retained_tail = bytes(uc.mem_read(0x0F18, min(retained_len, 72))) + bytes(uc.mem_read(0x3B90, max(0, retained_len - 72)))
            if (
                retained_len != len(fixture["resumed_tail"])
                or retained_tail != fixture["resumed_tail"]
            ):
                raise AssertionError(
                    "deadline changed the coalesced resumed tail: "
                    f"len={retained_len} data={retained_tail.hex()}"
                )
        if not resumed:
            uc.emu_stop()

    def stop_after_resumed_protected(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal protected_complete
        if not reached_protected:
            return
        protected_complete = True
        uc.emu_stop()

    def network_return(uc: Uc, _address: int, _size: int, _user: object) -> None:
        near_return(uc)

    def nic_receive(uc: Uc, _address: int, _size: int, _user: object) -> None:
        uc.mem_write(0x06D5, b"\x00\x00")
        near_return(uc)

    def unexpected_receive(
        uc: Uc, address: int, _size: int, _user: object
    ) -> None:
        def protected_word(label: str) -> int:
            offset = BUILDER.label_offset(protected.listing, label)
            return struct.unpack(
                "<H", bytes(uc.mem_read(0x0900 + offset, 2))
            )[0]

        raise AssertionError(
            "full coalesced resumed flight unexpectedly entered network receive "
            f"at {address:#06x}; "
            f"state={protected_word('resumed_state') & 0xff} "
            f"header={protected_word('resumed_header_pos') & 0xff} "
            f"remaining={protected_word('resumed_remaining')} "
            f"record={protected_word('resumed_record_pos')} "
            f"sent={len(sent_records)}"
        )

    def tcp_send(uc: Uc, _address: int, _size: int, _user: object) -> None:
        source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        length = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        sent_records.append(bytes(uc.mem_read(source, length)))
        near_return(uc)

    def protected_abort(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        raise AssertionError(
            "resumed protected controller entered low abort after "
            f"{protected_trace}; sent={len(sent_records)} "
            f"ax={uc.reg_read(UC_X86_REG_AX) & 0xffff:#06x} "
            f"cf={uc.reg_read(UC_X86_REG_EFLAGS) & 1}"
        )

    def record_protected_stage(
        _uc: Uc, _address: int, _size: int, user: object
    ) -> None:
        protected_trace.append(str(user))

    def observe_resumption_early(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        if (expected_sym_key, 0x1800) not in loads:
            return
        resumed_pre_schedule["psk"] = bytes(uc.mem_read(0x0DC0, 32))
        immutable_len = 0x2FE0 - 0x1800
        actual = bytes(uc.mem_read(0x1800, immutable_len))
        expected = sym_image.data[:immutable_len]
        if actual != expected:
            mismatch = next(
                index
                for index, pair in enumerate(zip(actual, expected, strict=True))
                if pair[0] != pair[1]
            )
            raise AssertionError(
                "resumption immutable symmetric prefix differs before early schedule "
                f"at {0x1800 + mismatch:#06x}: "
                f"{actual[mismatch]:#04x} != {expected[mismatch]:#04x}"
            )

    def observe_resumption_import(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        if (expected_sym_key, 0x1800) not in loads:
            return
        resumed_pre_schedule["early_derived"] = bytes(
            uc.mem_read(SYM.HANDSHAKE_DERIVED, 32)
        )

    sym_tail_observed = False

    def observe_prestaged_sym_tail(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal sym_tail_observed
        actual = bytes(uc.mem_read(0x2E00, sym_tail_bytes))
        if actual != sym_tail:
            mismatch = next(
                index
                for index, pair in enumerate(zip(actual, sym_tail, strict=True))
                if pair[0] != pair[1]
            )
            raise AssertionError(
                f"{prefix} pre-staged symmetric tail changed at "
                f"{0x2E00 + mismatch:#06x} before symmetric init"
            )
        sym_tail_observed = True

    def track_write(
        uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        if address < ROOT_FRAME_END and address + size > ROOT_FRAME_START:
            raise AssertionError(
                f"{prefix} deadline wrote the root return frame at "
                f"{address:#06x}+{size} from "
                f"{uc.reg_read(UC_X86_REG_IP) & 0xffff:#06x}; "
                f"loads={loads}"
            )
        if address + size > 0x4000:
            writes_above_floor.append((address, size))

    machine.hook_add(UC_HOOK_CODE, load_phase, begin=batch, end=batch)
    machine.hook_add(UC_HOOK_CODE, resident_load, begin=0x10C4, end=0x10C4)
    if resumed:
        machine.hook_add(
            UC_HOOK_CODE,
            observe_resumption_early,
            begin=sym_entries[13],
            end=sym_entries[13],
        )
        machine.hook_add(
            UC_HOOK_CODE,
            observe_resumption_import,
            begin=sym_entries[15],
            end=sym_entries[15],
        )
    machine.hook_add(UC_HOOK_CODE, stop_protected, begin=0x0900, end=0x0900)
    machine.hook_add(
        UC_HOOK_CODE,
        observe_prestaged_sym_tail,
        begin=sym_entries[0],
        end=sym_entries[0],
    )
    if resumed:
        # The real controller reaches NIC callbacks through the resident
        # vtable.  Install inert conventional-RAM stubs: the complete flight
        # is already quarantined, so receive must never block or supply bytes.
        machine.mem_write(0x15DF, struct.pack("<HHH", 0x04A0, 0x04A2, 0x04A4))
        machine.hook_add(UC_HOOK_CODE, network_return, begin=0x04A0, end=0x04A0)
        machine.hook_add(UC_HOOK_CODE, nic_receive, begin=0x04A2, end=0x04A2)
        machine.hook_add(
            UC_HOOK_CODE,
            unexpected_receive,
            begin=0x04A4,
            end=0x04A4,
        )
        machine.hook_add(UC_HOOK_CODE, network_return, begin=0x11E5, end=0x11E5)
        machine.hook_add(UC_HOOK_CODE, network_return, begin=0x13A6, end=0x13A6)
        machine.hook_add(UC_HOOK_CODE, tcp_send, begin=0x13BF, end=0x13BF)
        machine.hook_add(UC_HOOK_CODE, network_return, begin=0x13E2, end=0x13E2)
        machine.hook_add(
            UC_HOOK_CODE,
            unexpected_receive,
            begin=0x14ED,
            end=0x14ED,
        )
        machine.hook_add(
            UC_HOOK_CODE,
            unexpected_receive,
            begin=0x1522,
            end=0x1522,
        )
        machine.hook_add(
            UC_HOOK_CODE,
            stop_after_resumed_protected,
            begin=0x0700,
            end=0x0700,
        )
        machine.hook_add(UC_HOOK_CODE, protected_abort, begin=0x0F60, end=0x0F60)
        for stage in (
            "resumed_record_authenticated",
            "resumed_structure_valid",
            "resumed_finished_verified",
            "resumed_finished_build_returned",
            "resumed_finished_built",
            "resumed_queue_clean",
            "resumed_finished_sent",
        ):
            address = 0x0900 + BUILDER.label_offset(protected.listing, stage)
            machine.hook_add(
                UC_HOOK_CODE,
                record_protected_stage,
                stage,
                begin=address,
                end=address,
            )
    machine.hook_add(UC_HOOK_MEM_WRITE, track_write)
    try:
        machine.emu_start(0x3400, 0, count=120_000_000)
    except UcError as exc:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(f"{prefix} deadline failed at {ip:#06x}: {exc}") from exc
    if not reached_protected:
        raise AssertionError(f"{prefix} deadline did not reach protected flight")
    if not sym_tail_observed:
        raise AssertionError(f"{prefix} deadline did not consume pre-staged symmetric tail")
    if resumed and not protected_complete:
        raise AssertionError("resumption did not consume its coalesced protected flight")
    if writes_above_floor:
        raise AssertionError(f"{prefix} deadline escaped 16 KiB: {writes_above_floor[:4]}")
    retained_c = gather(machine, live_spans)
    if retained_c != ciphertext:
        mismatch = next(
            index
            for index, (actual, expected) in enumerate(
                zip(retained_c, ciphertext, strict=True)
            )
            if actual != expected
        )
        raise AssertionError(
            f"{prefix} deadline lost ciphertext byte {mismatch}: "
            f"{retained_c[mismatch]:#04x} != {ciphertext[mismatch]:#04x}"
        )
    if resumed:
        if resumed_pre_schedule.get("psk") != fixture["psk"]:
            raise AssertionError(
                "resumption early schedule saw the wrong PSK: "
                f"{resumed_pre_schedule.get('psk', b'').hex()}"
            )
        if resumed_pre_schedule.get("early_derived") != fixture["early_derived"]:
            raise AssertionError(
                "resumption early schedule produced the wrong salt before import: "
                f"{resumed_pre_schedule.get('early_derived', b'').hex()} != "
                f"{fixture['early_derived'].hex()}"
            )
        actual_psk = bytes(machine.mem_read(0x0DC0, 32))
        if actual_psk != fixture["psk"]:
            raise AssertionError(
                "resumption deadline changed the retained PSK: "
                f"{actual_psk.hex()} != {fixture['psk'].hex()}"
            )
        actual_derived = bytes(machine.mem_read(SYM.HANDSHAKE_DERIVED, 32))
        expected_derived = SYM.BASE.hkdf_expand_label(
            fixture["handshake_secret"],
            b"derived",
            hashlib.sha256(b"").digest(),
            32,
        )
        if actual_derived != expected_derived:
            raise AssertionError(
                "resumption protected flight derived the wrong handshake salt: "
                f"{actual_derived.hex()} != {expected_derived.hex()}"
            )
        if bytes(machine.mem_read(0x3600, 64)) != root + provisional:
            raise AssertionError("resumption deadline lost root/K prime")
        if bytes(machine.mem_read(0x0DAB, 13)) != bytes(13):
            raise AssertionError("resumption deadline retained its temporary c save")
        if bytes(machine.mem_read(0x2FE0, 32)) != bytes(32):
            raise AssertionError("resumption deadline retained its root padding hold")
        if bytes(machine.mem_read(0x0F16, 0x0F60 - 0x0F16)) != bytes(
            0x0F60 - 0x0F16
        ):
            raise AssertionError("resumption retained its coalesced-flight quarantine")
        if any(machine.mem_read(0x3B90, 12)):
            raise AssertionError("resumption retained its extra ciphertext quarantine")
        expected_records = [
            fixture["client_finished_record"],
            fixture["head_record"],
        ]
        if sent_records != expected_records:
            raise AssertionError(
                "resumption emitted the wrong post-handoff records: "
                f"{[value.hex() for value in sent_records]}"
            )
        for label, address, expected in (
            ("client application key", SYM_CLIENT_KEY, fixture["client_app_key"]),
            ("client application IV", SYM_CLIENT_IV, fixture["client_app_iv"]),
            ("server application key", SYM_SERVER_KEY, fixture["server_app_key"]),
            ("server application IV", SYM_SERVER_IV, fixture["server_app_iv"]),
            (
                "resumption master",
                SYM_RESUMPTION_MASTER,
                fixture["resumption_master"],
            ),
        ):
            actual = bytes(machine.mem_read(address, len(expected)))
            if actual != expected:
                raise AssertionError(
                    f"resumption protected controller composed the wrong {label}: "
                    f"{actual.hex()} != {expected.hex()}"
                )
        if bytes(machine.mem_read(SYM_CLIENT_SEQ, 8)) != (1).to_bytes(8, "big"):
            raise AssertionError("resumption HEAD advanced the wrong client sequence")
        if bytes(machine.mem_read(SYM_SERVER_SEQ, 8)) != bytes(8):
            raise AssertionError("resumption protected controller changed server sequence")
    elif bytes(machine.mem_read(0x2F60, 32)) != provisional:
        raise AssertionError("acquisition deadline retained the wrong K prime")
    for label, address in (
        ("handshake secret", SYM.HANDSHAKE_SECRET),
        ("client handshake key", SYM.CLIENT_HS_KEY),
        ("client handshake IV", SYM.CLIENT_HS_IV),
        ("server handshake key", SYM.SERVER_HS_KEY),
        ("server handshake IV", SYM.SERVER_HS_IV),
    ):
        expected = fixture[
            {
                "handshake secret": "handshake_secret",
                "client handshake key": "client_key",
                "client handshake IV": "client_iv",
                "server handshake key": "server_key",
                "server handshake IV": "server_iv",
            }[label]
        ]
        actual = bytes(machine.mem_read(address, len(expected)))
        if actual != expected:
            raise AssertionError(
                f"{prefix} composed {label} mismatch: "
                f"{actual.hex()} != {expected.hex()}"
            )
    expected_loads = [
        (candidate_key, 0x1800),
        (expected_sym_key, 0x1800),
        (protected_batch_key, 0x0900),
    ]
    if not resumed:
        expected_loads.append(
            (BUILDER.key(named[protected_name].start + 2, 1), 0x0700)
        )
    if loads != expected_loads:
        raise AssertionError(f"{prefix} deadline phase sequence changed: {loads}")
    assert_machine_guards(machine, guards)
    return {
        "phase_loads": [f"{key:#06x}@{destination:#06x}" for key, destination in loads],
        "ciphertext_bytes": len(ciphertext),
        "real_mlkem_candidate": True,
        "real_symmetric_schedule": True,
        "transcript_bytes": len(fixture["transcript"]),
        "schedule_alias_lifetime": (
            "scrubbed before protected flight"
            if resumed
            else "reused as live c; scrubbed by acquisition lifecycle"
        ),
        "coalesced_tail_bytes": len(fixture["resumed_tail"]) if resumed else 0,
        "protected_client_records": [len(value) for value in sent_records],
    }


def fo_composition_gate(
    images: dict[str, Any],
    named: dict[str, Any],
    *,
    resumed: bool,
) -> dict[str, Any]:
    """Execute one real offline chain through full FO validation.

    The primitive FO gate deliberately puts its callback at 0480.  Product
    composition is stricter: lifecycle, KeyGen, candidate, the FO controller,
    the streaming callback, and FO all replace overlapping conventional-RAM
    phases.  Execute that exact chain so no phase can overwrite code which a
    later callback or continuation still needs.
    """

    prefix = "resumption" if resumed else "acquisition"
    epoch = 1 if resumed else 0
    offline_name = f"{prefix}_offline"
    controller_name = f"{prefix}_fo"
    runner_name = "res_fo_runner" if resumed else "acq_fo_runner"
    next_name = "final_post" if resumed else "fresh_post"
    live_c = RESUMPTION_LIVE_C if resumed else ACQUISITION_LIVE_C
    root = hashlib.sha256(
        f"Seed product {prefix} FO composed regeneration root".encode()
    ).digest()
    seed = b"".join(
        hashlib.sha3_256(
            SYSTEM_REGENERATE_DOMAIN + bytes((epoch, index)) + root
        ).digest()
        for index in range(2)
    )
    dk = KEYGEN.fips_keygen_internal(seed)
    ek = dk[1152:2336]
    message = hashlib.sha3_256(
        f"Seed product {prefix} FO composed message".encode()
    ).digest()
    candidate_g = hashlib.sha3_512(
        message + hashlib.sha3_256(ek).digest()
    ).digest()
    ciphertext = FO.REFERENCE.k_pke_encrypt(ek, message, candidate_g[32:])
    decrypted, checked_g = FO.REFERENCE.k_pke_decrypt(dk, ciphertext)
    if decrypted != message or checked_g != candidate_g:
        raise AssertionError("composed FO vector is not a valid ML-KEM candidate")

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes(RAM_BYTES))
    machine.mem_write(
        named[offline_name].destination,
        padded(images[offline_name].data, named[offline_name].sectors),
    )
    scatter(machine, ciphertext, live_c)
    if resumed:
        machine.mem_write(SYM_ROOT, root)
        machine.mem_write(SYM_PROVISIONAL, candidate_g[:32])
    else:
        machine.mem_write(
            named["acq_sym"].destination,
            padded(images["acq_sym"].data, named["acq_sym"].sectors),
        )
        # State published by the authenticated fresh protected-flight
        # controller before its retained c aliases the symmetric root.
        auth_digest, auth_signature, _point, _spki = SYSTEM_AUTH.live_fixture()
        hold = bytearray(172)
        hold[0:32] = root
        hold[32:64] = candidate_g[:32]
        hold[64:96] = auth_digest
        hold[96:98] = len(auth_signature).to_bytes(2, "little")
        hold[98 : 98 + len(auth_signature)] = auth_signature
        hold[170] = 0x5A
        machine.mem_write(ACQ_HOLD, bytes(hold))
    state = application_state(f"composed {prefix}".encode())
    write_application_state(machine, state)
    machine.mem_write(0x0F60, images["abort"].data)
    low_runtime_guard = deterministic(f"{prefix} low runtime guard".encode(), 0x100)
    machine.mem_write(0x0600, low_runtime_guard)
    guards = install_machine_guards(machine)
    install_io_rejection(machine)

    server_read_entry = (
        struct.unpack_from("<19H", images["acq_sym"].data, 32)[17]
        if not resumed
        else None
    )
    controller_destination = named[controller_name].destination
    runner_origin = 0x0500
    callback = BUILDER.label_address(
        images[runner_name].listing,
        "sysram_fo_public_object_read",
        runner_origin,
    )
    expected_next_key = named[next_name].key
    phase_names = [
        "lifecycle",
        "keygen",
        "candidate",
        controller_name,
        "fo",
    ]
    if resumed:
        phase_names.append("res_sym")
    else:
        phase_names.extend(("auth_return", "auth", "acq_sym", "fresh_post"))
    phase_images = {named[name].key: name for name in phase_names}
    expected_loads = [
        (named["lifecycle"].key, named["lifecycle"].destination),
        (named["keygen"].key, named["keygen"].destination),
        (named["candidate"].key, named["candidate"].destination),
        (named["lifecycle"].key, named["lifecycle"].destination),
        (named[controller_name].key, controller_destination),
        (named["fo"].key, named["fo"].destination),
        (named["lifecycle"].key, named["lifecycle"].destination),
    ]
    if resumed:
        expected_loads.extend(
            (
                (named["res_sym"].key, named["res_sym"].destination),
                (named["lifecycle"].key, named["lifecycle"].destination),
                (expected_next_key, named[next_name].destination),
            )
        )
    else:
        expected_loads.extend(
            (
                (named["auth_return"].key, named["auth_return"].destination),
                (named["auth"].key, named["auth"].destination),
                (named["acq_sym"].key, named["acq_sym"].destination),
                (named["lifecycle"].key, named["lifecycle"].destination),
                (expected_next_key, named[next_name].destination),
            )
        )
    loads: list[tuple[int, int]] = []
    reads: list[tuple[int, int, int, int]] = []
    reached_next = False
    aborted = False
    validated_fo_snapshot: tuple[bytes, int, int] | None = None
    writes_above_floor: list[tuple[int, int]] = []

    def load_phase(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal reached_next, validated_fo_snapshot
        phase_key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        loads.append((phase_key, destination))
        if phase_key == expected_next_key:
            if destination != named[next_name].destination:
                raise AssertionError(
                    f"composed {prefix} FO requested {next_name} at wrong address"
                )
            reached_next = True
            uc.emu_stop()
            return
        name = phase_images.get(phase_key)
        if name is None:
            raise AssertionError(f"composed FO requested unexpected phase {phase_key:#06x}")
        if destination != named[name].destination:
            raise AssertionError(
                f"composed FO loaded {name} at {destination:#06x}, "
                f"expected {named[name].destination:#06x}"
            )
        if name == "auth_return" or (resumed and name == "res_sym"):
            validated_fo_snapshot = (
                bytes(uc.mem_read(FO_SELECTED, 32)),
                uc.mem_read(CAPSULE_HIGH + 307, 1)[0],
                uc.mem_read(CAPSULE_HIGH + 308, 1)[0],
            )
        payload = padded(images[name].data, named[name].sectors)
        uc.mem_write(destination, payload)
        invalidate_code(uc, destination, destination + len(payload))
        near_return(uc)

    sym_hook: int | None = None

    def finish_server_read(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal sym_hook
        if sym_hook is not None:
            uc.hook_del(sym_hook)
            sym_hook = None
        near_return(uc)

    def observe_public_read(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        reads.append(
            (
                uc.reg_read(UC_X86_REG_AX) & 0xFF,
                uc.reg_read(UC_X86_REG_DX) & 0xFFFF,
                uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
                uc.reg_read(UC_X86_REG_DI) & 0xFFFF,
            )
        )

    def stop_abort(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal aborted
        aborted = True
        uc.emu_stop()

    def track_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        if address + size > 0x4000:
            writes_above_floor.append((address, size))

    machine.hook_add(UC_HOOK_CODE, load_phase, begin=0x10C4, end=0x10C4)
    if server_read_entry is not None:
        sym_hook = machine.hook_add(
            UC_HOOK_CODE,
            finish_server_read,
            begin=server_read_entry,
            end=server_read_entry,
        )
    machine.hook_add(UC_HOOK_CODE, observe_public_read, begin=callback, end=callback)
    machine.hook_add(UC_HOOK_CODE, stop_abort, begin=0x0F60, end=0x0F60)
    if not resumed:
        machine.hook_add(UC_HOOK_CODE, stop_abort, begin=0x35A0, end=0x35A0)
    machine.hook_add(UC_HOOK_MEM_WRITE, track_write)
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))
    start = named[offline_name].destination
    try:
        machine.emu_start(start, 0, count=900_000_000)
    except UcError as exc:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(
            f"{prefix} FO composition failed at {ip:#06x}: {exc}"
        ) from exc
    if aborted or not reached_next:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        capsule_state = {
            "auth": machine.mem_read(CAPSULE_HIGH + 170, 1)[0],
            "fo": machine.mem_read(CAPSULE_HIGH + 307, 1)[0],
            "lifecycle": machine.mem_read(CAPSULE_HIGH + 308, 1)[0],
        }
        raise AssertionError(
            f"{prefix} FO composition did not reach its next continuation: "
            f"aborted={aborted}, ip={ip:#06x}, loads={loads}, reads={len(reads)}, "
            f"capsule={capsule_state}"
        )
    if loads != expected_loads:
        raise AssertionError(f"{prefix} FO phase sequence changed: {loads}")
    if reads != FO.expected_stream_log():
        raise AssertionError(f"{prefix} FO product callback stream schedule drifted")
    if resumed:
        if validated_fo_snapshot != (candidate_g[:32], 0xC3, 0x3C):
            raise AssertionError(
                f"{prefix} FO validation was not intact before sym_init: "
                f"{validated_fo_snapshot}"
            )
    elif validated_fo_snapshot != (candidate_g[:32], 0xA5, 0x5A):
        raise AssertionError(
            f"{prefix} FO validation was not intact at authentication transition: "
            f"{validated_fo_snapshot}"
        )
    if bytes(machine.mem_read(0x0F60, len(images["abort"].data))) != images["abort"].data:
        raise AssertionError(f"{prefix} FO did not restore the low abort image")
    runner = images[runner_name].data
    actual_runner = bytes(machine.mem_read(runner_origin, len(runner)))
    if resumed:
        if actual_runner[:0x40] != bytes(0x40) or actual_runner[0x40:] != runner[0x40:]:
            raise AssertionError(
                "resumption did not erase only the retired runner-prefix capsule copy"
            )
    else:
        if actual_runner[:0x40] != bytes(0x40) or actual_runner[0x40:] != runner[0x40:]:
            raise AssertionError(
                "authentication did not erase only the retired runner-prefix capsule copy"
            )
    if bytes(machine.mem_read(0x0600, len(low_runtime_guard))) != low_runtime_guard:
        raise AssertionError("FO runner crossed into the handoff/low runtime state")
    if resumed:
        assert_application_state(machine, state, master=False)
    else:
        assert_application_state(machine, state, master=True)
        if bytes(machine.mem_read(COMPACT_ROOT, 34)) != root + b"\xa5\x5a":
            raise AssertionError("authenticated FO composition lost compact root")
        if bytes(machine.mem_read(0x0F60, len(images["abort"].data))) != images[
            "abort"
        ].data:
            raise AssertionError("authentication restore did not reinstall low abort")
    if writes_above_floor:
        raise AssertionError(
            f"{prefix} FO composition escaped 16 KiB: {writes_above_floor[:4]}"
        )
    assert_machine_guards(machine, guards)
    return {
        "phase_loads": [
            f"{phase_key:#06x}@{destination:#06x}"
            for phase_key, destination in loads
        ],
        "controller": f"{controller_destination:#06x}",
        "runner": f"{runner_origin:#06x}..{runner_origin + len(runner):#06x}",
        "workspace": "0x0700..0x0fd0",
        "public_reads": len(reads),
        "real_keygen_candidate_and_full_fo": True,
        "exact_leaf_authentication_and_restore": not resumed,
        "low_abort_restored": True,
    }


def lifecycle_entries(image: bytes) -> tuple[int, ...]:
    if image[:4] != b"SRP1":
        raise AssertionError("product lifecycle magic drifted")
    version, size, count = struct.unpack_from("<3H", image, 4)
    if version != 1 or size != len(image) or count != 8:
        raise AssertionError("product lifecycle header drifted")
    entries = struct.unpack_from("<8H", image, 10)
    if any(not 0x0900 <= entry < 0x0900 + len(image) for entry in entries):
        raise AssertionError("product lifecycle entry escaped its phase")
    return entries


def new_lifecycle_machine(image: bytes) -> tuple[Uc, dict[str, tuple[int, bytes]]]:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes(RAM_BYTES))
    machine.mem_write(0x0900, padded(image, 2))
    guards = install_machine_guards(machine)
    install_io_rejection(machine)
    return machine, guards


def invoke_lifecycle(machine: Uc, entry: int, *, success: bool = True) -> None:
    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | (1 << 10))
    returned = False

    def stop(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    hook = machine.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
    try:
        machine.emu_start(entry, 0, count=5_000_000)
    except UcError as exc:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(f"lifecycle failed at {ip:#06x}: {exc}") from exc
    finally:
        machine.hook_del(hook)
    carry = bool(machine.reg_read(UC_X86_REG_EFLAGS) & 1)
    if not returned or machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("lifecycle violated its return contract")
    if carry == success:
        raise AssertionError("lifecycle returned the wrong carry state")
    if machine.reg_read(UC_X86_REG_EFLAGS) & (1 << 10):
        raise AssertionError("lifecycle returned with DF set")


def invoke_hello_entry(machine: Uc, entry: int) -> tuple[int, int, int]:
    """Call one near HELLO entry in the full-transition machine."""

    machine.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN))
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    returned = False

    def stop(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal returned
        returned = True
        uc.emu_stop()

    hook = machine.hook_add(UC_HOOK_CODE, stop, begin=RETURN, end=RETURN)
    try:
        machine.emu_start(entry, 0, count=50_000_000)
    except UcError as exc:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(f"resumed HELLO entry failed at {ip:#06x}: {exc}") from exc
    finally:
        machine.hook_del(hook)
    if not returned or machine.reg_read(UC_X86_REG_SP) != STACK_TOP:
        raise AssertionError("resumed HELLO entry violated its return contract")
    if machine.reg_read(UC_X86_REG_EFLAGS) & 1:
        raise AssertionError("resumed HELLO entry returned carry")
    if machine.reg_read(UC_X86_REG_EFLAGS) & (1 << 10):
        raise AssertionError("resumed HELLO entry returned with DF set")
    return (
        machine.reg_read(UC_X86_REG_AX) & 0xFFFF,
        machine.reg_read(UC_X86_REG_SI) & 0xFFFF,
        machine.reg_read(UC_X86_REG_CX) & 0xFFFF,
    )


def resumed_hello_preconnect_gate(
    images: dict[str, Any], named: dict[str, Any]
) -> dict[str, Any]:
    """Prove cached connect cannot consume the pre-staged symmetric tail."""

    hello = images["resumed_hello"]
    controller = images["resumed_hello_controller"]
    sym_image = images["res_sym"]
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes(RAM_BYTES))
    machine.mem_write(0x1800, padded(hello.data, named["resumed_hello"].sectors))
    machine.mem_write(
        named["resumed_hello_controller"].destination,
        padded(controller.data, named["resumed_hello_controller"].sectors),
    )

    sym_tail = sym_image.data[11 * SECTOR : 11 * SECTOR + 0x01E0]
    if len(sym_tail) != 0x01E0:
        raise AssertionError("resumption symmetric tail fixture is truncated")
    machine.mem_write(0x2E00, sym_tail)

    ek = deterministic(b"resumed preconnect ek", HELLO.EK_LEN)
    random = deterministic(b"resumed preconnect random", 32)
    session = deterministic(b"resumed preconnect session", 32)
    psk = deterministic(b"resumed preconnect psk", 32)
    age = deterministic(b"resumed preconnect age", 4)
    identity = deterministic(b"resumed preconnect identity", 192)
    machine.mem_write(0x08C0, ek)
    machine.mem_write(0x3420, random)
    machine.mem_write(0x3440, session)
    machine.mem_write(0x3460, psk)
    machine.mem_write(0x3480, age)
    machine.mem_write(0x3484, struct.pack("<H", len(identity)))
    machine.mem_write(0x3000, identity)
    _message, expected_record, _truncated, _binder = HELLO.build_resumed_client(
        ek,
        random,
        session,
        identity,
        age,
        psk,
        alpn=b"h2",
    )

    entries = struct.unpack_from("<14H", hello.data, 0x30)
    cached_connect = entries[9]
    server_begin = entries[5]
    sent: list[bytes] = []
    reached_server_begin = False
    aborted = False
    phase_read = False
    last_controller_ip: int | None = None

    def ticket_age_return(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        near_return(uc)

    def cached_connect_clobber(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        # hello_cached_connect.inc hard-bounds its receive copy at 96 bytes.
        # Replace that complete region, including the 42-byte overlap with the
        # first ClientHello fragment, so the controller must restore it.
        uc.mem_write(0x0700, deterministic(b"cached SYN ACK frame", 96))
        near_return(uc)

    def tcp_send(uc: Uc, _address: int, _size: int, _user: object) -> None:
        source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        length = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        sent.append(bytes(uc.mem_read(source, length)))
        near_return(uc)

    def stop_server_begin(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal reached_server_begin
        reached_server_begin = True
        uc.emu_stop()

    def stop_abort(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal aborted
        aborted = True
        uc.emu_stop()

    def reject_phase_read(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal phase_read
        phase_read = True
        uc.emu_stop()

    def track_controller(
        _uc: Uc, address: int, _size: int, _user: object
    ) -> None:
        nonlocal last_controller_ip
        last_controller_ip = address

    machine.hook_add(UC_HOOK_CODE, ticket_age_return, begin=0x2C00, end=0x2C00)
    machine.hook_add(
        UC_HOOK_CODE,
        cached_connect_clobber,
        begin=cached_connect,
        end=cached_connect,
    )
    machine.hook_add(UC_HOOK_CODE, tcp_send, begin=0x13BF, end=0x13BF)
    machine.hook_add(
        UC_HOOK_CODE,
        stop_server_begin,
        begin=server_begin,
        end=server_begin,
    )
    machine.hook_add(UC_HOOK_CODE, stop_abort, begin=0x0F60, end=0x0F60)
    machine.hook_add(
        UC_HOOK_CODE,
        reject_phase_read,
        begin=0x10C4,
        end=0x10C4,
    )
    machine.hook_add(
        UC_HOOK_CODE,
        track_controller,
        begin=named["resumed_hello_controller"].destination,
        end=(
            named["resumed_hello_controller"].destination
            + len(controller.data)
            - 1
        ),
    )
    guards = install_machine_guards(machine)
    install_io_rejection(machine)
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    try:
        machine.emu_start(
            named["resumed_hello_controller"].destination,
            0,
            count=200_000_000,
        )
    except UcError as exc:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(
            f"resumed HELLO preconnect controller failed at {ip:#06x}: {exc}"
        ) from exc

    if aborted or phase_read or not reached_server_begin:
        raise AssertionError(
            "resumed HELLO did not reach ServerHello without a phase read: "
            f"aborted={aborted}, phase_read={phase_read}, "
            f"server_begin={reached_server_begin}, "
            f"last_controller_ip={last_controller_ip!r}, "
            f"sent={[len(fragment) for fragment in sent]}, "
            f"hello_state={bytes(machine.mem_read(0x0DC0, 16)).hex()}, "
            f"hello_status={machine.mem_read(0x0DAA, 1)[0]:#04x}"
        )
    emitted = b"".join(sent)
    if emitted != expected_record:
        difference = next(
            (
                index
                for index, (actual, expected) in enumerate(
                    zip(emitted, expected_record)
                )
                if actual != expected
            ),
            min(len(emitted), len(expected_record)),
        )
        raise AssertionError(
            "resumed HELLO cached-connect restoration changed ClientHello at "
            f"byte {difference} ({len(emitted)} != {len(expected_record)})"
        )
    if bytes(machine.mem_read(0x2E00, len(sym_tail))) != sym_tail:
        raise AssertionError("resumed HELLO overwrote the pre-staged symmetric tail")
    if bytes(machine.mem_read(0x0F16, 0x0F60 - 0x0F16)) != bytes(
        0x0F60 - 0x0F16
    ):
        raise AssertionError("resumed HELLO retained its SYN-overlap quarantine")
    assert_machine_guards(machine, guards)
    return {
        "client_hello_bytes": len(emitted),
        "fragments": [len(fragment) for fragment in sent],
        "cached_frame_bytes": 96,
        "quarantined_overlap_bytes": 42,
        "critical_phase_reads": 0,
        "pre_staged_symmetric_tail_bytes": len(sym_tail),
    }


def application_state(label: bytes) -> dict[str, bytes]:
    return {
        "client_key": deterministic(label + b" client key", 32),
        "client_iv": deterministic(label + b" client iv", 12),
        "client_seq": deterministic(label + b" client seq", 8),
        "server_key": deterministic(label + b" server key", 32),
        "server_iv": deterministic(label + b" server iv", 12),
        "server_seq": deterministic(label + b" server seq", 8),
        "resumption_master": deterministic(label + b" res master", 32),
    }


def write_application_state(machine: Uc, state: dict[str, bytes]) -> None:
    for address, name in (
        (SYM_CLIENT_KEY, "client_key"),
        (SYM_CLIENT_IV, "client_iv"),
        (SYM_CLIENT_SEQ, "client_seq"),
        (SYM_SERVER_KEY, "server_key"),
        (SYM_SERVER_IV, "server_iv"),
        (SYM_SERVER_SEQ, "server_seq"),
        (SYM_RESUMPTION_MASTER, "resumption_master"),
    ):
        machine.mem_write(address, state[name])


def assert_application_state(machine: Uc, state: dict[str, bytes], *, master: bool) -> None:
    names = (
        (SYM_CLIENT_KEY, "client_key"),
        (SYM_CLIENT_IV, "client_iv"),
        (SYM_CLIENT_SEQ, "client_seq"),
        (SYM_SERVER_KEY, "server_key"),
        (SYM_SERVER_IV, "server_iv"),
        (SYM_SERVER_SEQ, "server_seq"),
    )
    if master:
        names += ((SYM_RESUMPTION_MASTER, "resumption_master"),)
    for address, name in names:
        if bytes(machine.mem_read(address, len(state[name]))) != state[name]:
            raise AssertionError(f"lifecycle restored the wrong {name}")


def lifecycle_gate(image: bytes, ticket_age: bytes) -> dict[str, Any]:
    entries = lifecycle_entries(image)
    ciphertext = deterministic(b"lifecycle acquisition c", 1088)
    root = deterministic(b"acquisition root", 32)
    provisional = deterministic(b"acquisition K prime", 32)
    digest = deterministic(b"CV digest", 32)
    signature = deterministic(b"CV signature", 64)
    hold = (
        root
        + provisional
        + digest
        + struct.pack("<H", len(signature))
        + signature
        + bytes(72 - len(signature))
        + b"\x5a"
    )
    if len(hold) != 171:
        raise AssertionError("acquisition hold fixture drifted")
    state = application_state(b"acquisition")
    machine, guards = new_lifecycle_machine(image)
    scatter(machine, ciphertext, ACQUISITION_LIVE_C)
    machine.mem_write(ACQ_HOLD, hold)
    write_application_state(machine, state)
    invoke_lifecycle(machine, entries[0])
    if gather(machine, KEYGEN_C) != ciphertext:
        raise AssertionError("acquisition pack changed ciphertext")
    expected_capsule = bytearray(CAPSULE_LEN)
    expected_capsule[:171] = hold
    offset = 171
    for name in (
        "client_key",
        "client_iv",
        "client_seq",
        "server_key",
        "server_iv",
        "server_seq",
        "resumption_master",
    ):
        value = state[name]
        expected_capsule[offset : offset + len(value)] = value
        offset += len(value)
    expected_capsule[308] = 0x5A
    if bytes(machine.mem_read(CAPSULE_LOW, CAPSULE_LEN)) != bytes(expected_capsule):
        raise AssertionError("acquisition pack produced the wrong capsule")

    ek = deterministic(b"regenerated ek", 1184)
    machine.mem_write(0x08C0, ek)
    machine.mem_write(0x2440, ek[64:1088])
    machine.mem_write(0x0900, padded(image, 2))
    invalidate_code(machine, 0x0900, 0x0D00)
    invoke_lifecycle(machine, entries[1])
    if bytes(machine.mem_read(0x2400, len(ek))) != ek:
        raise AssertionError("to-FO transition copied the wrong ek")
    if bytes(machine.mem_read(0x3600, 1088)) != ciphertext:
        raise AssertionError("to-FO transition copied the wrong ciphertext")
    if bytes(machine.mem_read(CAPSULE_HIGH + 32, 32)) != provisional:
        raise AssertionError("to-FO transition copied the wrong provisional capsule")
    if machine.mem_read(CAPSULE_HIGH + 308, 1)[0] != 0x5A:
        raise AssertionError("to-FO transition lost acquisition lifecycle status")
    machine.mem_write(FO_SELECTED, provisional)
    invoke_lifecycle(machine, entries[2])
    if bytes(machine.mem_read(CAPSULE_HIGH + 307, 2)) != b"\xa5\x5a":
        raise AssertionError("acquisition FO status was not published last")
    machine.mem_write(CAPSULE_HIGH + 170, b"\x01")
    machine.mem_write(0x3600, bytes(0x3B37 - 0x3600))
    invoke_lifecycle(machine, entries[3])
    assert_application_state(machine, state, master=True)
    if bytes(machine.mem_read(COMPACT_ROOT, 34)) != root + b"\xa5\x5a":
        raise AssertionError("acquisition restore lost compact root")

    psk = deterministic(b"ticket PSK", 32)
    identity = deterministic(b"ticket identity", 64)
    age_add = deterministic(b"ticket age", 4)
    receipt_ticks = 0x00012345
    elapsed_ticks = 2820
    current_ticks = receipt_ticks + elapsed_ticks
    lifetime = 64800
    machine.mem_write(ACQ_HOLD + 171, b"\x02")
    machine.mem_write(SYM_TICKET_PSK, psk)
    machine.mem_write(SYM_TICKET_IDENTITY, identity)
    machine.mem_write(SYM_TICKET_LIFETIME, struct.pack("<HH", 0, lifetime))
    machine.mem_write(SYM_TICKET_AGE_ADD, age_add)
    machine.mem_write(SYM_TICKET_IDENTITY_LEN, struct.pack("<H", len(identity)))
    machine.mem_write(POST_TICKET_TICK, struct.pack("<I", receipt_ticks))
    invoke_lifecycle(machine, entries[4])
    if bytes(machine.mem_read(CAPSULE_HIGH, 32)) != root:
        raise AssertionError("resumption preparation lost root")
    if bytes(machine.mem_read(0x3460, 32)) != psk:
        raise AssertionError("resumption preparation copied the wrong PSK")
    if bytes(machine.mem_read(0x3480, 4)) != age_add:
        raise AssertionError("resumption preparation copied the wrong age")
    if bytes(machine.mem_read(0x3486, len(identity))) != identity:
        raise AssertionError("resumption preparation copied the wrong identity")
    if bytes(machine.mem_read(RESUME_AGE_STATE, 8)) != (
        struct.pack("<I", receipt_ticks) + struct.pack("<HH", 0, lifetime)
    ):
        raise AssertionError("resumption preparation lost its monotonic age state")
    if bytes(machine.mem_read(POST_TICKET_TICK, 4)) != bytes(4):
        raise AssertionError("resumption preparation retained the ticket tick handoff")
    machine.mem_write(BIOS_TICKS, struct.pack("<I", current_ticks))
    machine.mem_write(0x0900, padded(ticket_age, 1))
    invalidate_code(machine, 0x0900, 0x0B00)
    invoke_lifecycle(machine, 0x0900)
    elapsed_ms = elapsed_ticks * 55 - ((elapsed_ticks * 611) >> 13)
    expected_age = (
        int.from_bytes(age_add, "big") + elapsed_ms
    ) & 0xFFFFFFFF
    actual_age = bytes(machine.mem_read(0x3480, 4))
    if actual_age != expected_age.to_bytes(4, "big"):
        raise AssertionError(
            "resumption age omitted measured KeyGen elapsed time: "
            f"{actual_age.hex()} != {expected_age:08x}"
        )
    if bytes(machine.mem_read(RESUME_AGE_STATE, 12)) != bytes(12):
        raise AssertionError("resumption age finalization retained timing state")
    assert_machine_guards(machine, guards)

    res_machine, res_guards = new_lifecycle_machine(image)
    res_c = deterministic(b"lifecycle resumption c", 1088)
    res_root = deterministic(b"resumption root", 32)
    res_provisional = deterministic(b"resumption K prime", 32)
    res_state = application_state(b"resumption")
    res_machine.mem_write(SYM_ROOT, res_root)
    res_machine.mem_write(SYM_PROVISIONAL, res_provisional)
    write_application_state(res_machine, res_state)
    scatter(res_machine, res_c, RESUMPTION_LIVE_C)
    invoke_lifecycle(res_machine, entries[5])
    if gather(res_machine, KEYGEN_C) != res_c:
        raise AssertionError("resumption pack changed ciphertext")
    res_ek = deterministic(b"resumption ek", 1184)
    res_machine.mem_write(0x08C0, res_ek)
    res_machine.mem_write(0x2440, res_ek[64:1088])
    res_machine.mem_write(0x0900, padded(image, 2))
    invalidate_code(res_machine, 0x0900, 0x0D00)
    invoke_lifecycle(res_machine, entries[1])
    res_machine.mem_write(FO_SELECTED, res_provisional)
    invoke_lifecycle(res_machine, entries[6])
    if bytes(res_machine.mem_read(CAPSULE_HIGH + 307, 2)) != b"\xc3\x3c":
        raise AssertionError("resumption FO status was not published last")
    res_machine.mem_write(0x3600, bytes(0x3B37 - 0x3600))
    res_machine.mem_write(0x0DC0, deterministic(b"retired PSK", 32))
    invoke_lifecycle(res_machine, entries[7])
    assert_application_state(res_machine, res_state, master=False)
    if bytes(res_machine.mem_read(0x0DC0, 32)) != bytes(32):
        raise AssertionError("resumption restore retained the ticket PSK")
    assert_machine_guards(res_machine, res_guards)
    return {
        "entries": len(entries),
        "acquisition": "pack -> FO -> auth restore -> measured-age resume inputs",
        "resumption": "pack -> FO -> final application restore",
        "ticket_age_elapsed_ticks": elapsed_ticks,
        "ticket_age_elapsed_ms": elapsed_ms,
    }


def segment_stream(value: bytes) -> list[bytes]:
    cuts = (1, 2, 7, 3, 31, 5, 127, 11, 383)
    result: list[bytes] = []
    offset = 0
    index = 0
    while offset < len(value):
        count = min(cuts[index % len(cuts)], len(value) - offset)
        result.append(value[offset : offset + count])
        offset += count
        index += 1
    return result


def post_gate(
    images: dict[str, Any],
    named: dict[str, Any],
    *,
    fresh: bool,
    http_content_length: int = 1432,
    corrupt_http_tag: bool = False,
) -> dict[str, Any]:
    controller_name = "fresh_post" if fresh else "final_post"
    sym_name = "acq_sym" if fresh else "res_sym"
    controller = images[controller_name]
    sym_image = images[sym_name]
    key = deterministic((b"fresh" if fresh else b"final") + b" server key", 32)
    iv = deterministic((b"fresh" if fresh else b"final") + b" server iv", 12)
    first = b"HTTP/1.1 200 OK\r\nContent-"
    second = b"Length: 0\r\n\r\n"
    contents: list[tuple[int, bytes]] = [
        (SYM.O.CONTENT_APPLICATION_DATA, first),
        (SYM.O.CONTENT_APPLICATION_DATA, second),
    ]
    # Exercise the maximum identity accepted by the shipped parser/lifecycle,
    # not a conveniently short synthetic ticket.  This catches lifetime bugs
    # at the exact 0x3000/0x3486 staging boundaries used by live resumption.
    identity = deterministic(b"authenticated product NST identity", 192)
    # OpenAI's current 222-byte NST profile uses a one-byte nonce with its
    # 192-byte identity.  Exercise that exact lower bound through the complete
    # post-response copy/derivation/lifecycle path; the symmetric unit gate
    # separately covers larger bounded nonces.
    nonce = deterministic(b"authenticated product NST nonce", 1)
    resumption_master = deterministic(b"product resumption master", 32)
    nst = SYM.build_nst_with_extensions(
        identity=identity,
        nonce=nonce,
        extensions=SYM.NST_LIVE_EXTENSIONS,
    )
    second_identity = deterministic(
        b"authenticated product second NST identity", 192
    )
    second_nst = SYM.build_nst_with_extensions(
        identity=second_identity,
        nonce=deterministic(b"authenticated product second NST nonce", 1),
        extensions=SYM.NST_LIVE_EXTENSIONS,
    )
    # Keep the observed two-ticket batch, then exercise the entire supported
    # HEAD quarantine.  The old 1,125-byte fixture stopped just before a live
    # symmetric-state overlap at 3510; a 1,162-byte response exposed it.
    # The default reaches the 1,433-byte inner limit, including its type byte.
    # Fresh retains the first authenticated ticket; final authenticates and
    # discards both tickets before publishing the resumed application state.
    http_prefix = b"HTTP/1.1 200 OK\r\nX-Fill: "
    http = (
        http_prefix
        + b"a" * (http_content_length - len(http_prefix) - len(b"\r\n\r\n"))
        + b"\r\n\r\n"
    )
    contents = [
        (SYM.O.CONTENT_HANDSHAKE, nst + second_nst),
        (SYM.O.CONTENT_APPLICATION_DATA, http),
    ]
    record_list = [
        SYM.BASE.encrypted_record(key, iv, sequence, inner_type, content)
        for sequence, (inner_type, content) in enumerate(contents)
    ]
    if corrupt_http_tag:
        last = record_list[-1]
        record_list[-1] = last[:-1] + bytes([last[-1] ^ 1])
    records = b"".join(record_list)
    queue = (
        segment_stream(records)
        if fresh
        else [record_list[0], *segment_stream(record_list[1])]
    )
    fragment_count = len(queue)
    expected_ticket_plaintext = nst + second_nst if fresh else None
    expected_psk = (
        SYM.BASE.hkdf_expand_label(
            resumption_master,
            b"resumption",
            nonce,
            32,
        )
        if fresh
        else None
    )

    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes(RAM_BYTES))
    machine.mem_write(0x1800, padded(sym_image.data, named[sym_name].sectors))
    machine.mem_write(0x0900, padded(controller.data, named[controller_name].sectors))
    # Reproduce the real cold-route lifetime: its disk-independent abort
    # aliases the resident low-constant band until final publication.  A
    # component-only application test starts with canonical constants and
    # cannot catch a missing terminal restore.
    machine.mem_write(0x0F60, images["abort"].data)
    if not fresh:
        # The real handshake leaves private receive cursors in this resident
        # tail.  Poison every byte so the final success path must publish the
        # canonical empty application framing state, rather than passing only
        # because Unicorn began with zeroed RAM.
        machine.mem_write(
            LOW_TAIL_STATE_START,
            bytes(range(1, LOW_TAIL_STATE_END - LOW_TAIL_STATE_START + 1)),
        )
    machine.mem_write(SYM_SERVER_KEY, key)
    machine.mem_write(SYM_SERVER_IV, iv)
    machine.mem_write(SYM_SERVER_SEQ, bytes(8))
    machine.mem_write(SYM_RESUMPTION_MASTER, resumption_master)
    client_key = deterministic(b"authenticated product client app key", 32)
    client_iv = deterministic(b"authenticated product client app iv", 12)
    client_sequence = deterministic(b"authenticated product client app sequence", 8)
    if not fresh:
        machine.mem_write(SYM_CLIENT_KEY, client_key)
        machine.mem_write(SYM_CLIENT_IV, client_iv)
        machine.mem_write(SYM_CLIENT_SEQ, client_sequence)
    machine.mem_write(0x06F9, b"\x34\x12")
    machine.mem_write(0x15DF, struct.pack("<H", 0x1700))
    receipt_ticks = 0x00023456
    processing_ticks = 2260
    elapsed_ticks = 2820
    current_ticks = receipt_ticks + elapsed_ticks
    machine.mem_write(BIOS_TICKS, struct.pack("<I", receipt_ticks))
    transition_root = deterministic(b"authenticated post transition root", 32)
    if fresh:
        # This is the compact root published by the real acquisition-auth
        # restore immediately before the fresh post-response controller.  The
        # authenticated NST below supplies the other half of the resumption
        # preparation contract.
        machine.mem_write(COMPACT_ROOT, transition_root + b"\xa5\x5a")
    else:
        root_return_sp = STACK_TOP - 2
        machine.mem_write(root_return_sp, struct.pack("<H", RETURN))
        machine.mem_write(ROOT_FRAME_START, struct.pack("<H", root_return_sp))
        machine.mem_write(ROOT_FRAME_START + 2, struct.pack("<H", (~root_return_sp) & 0xFFFF))
        machine.mem_write(ROOT_FRAME_START + 4, struct.pack("<H", 0xA55A))
    guards = install_machine_guards(machine)
    if not fresh:
        # Final success is the sole normal consumer: replace the generic guard
        # with its real root frame, which the capsule must validate and erase.
        guards.pop("root return frame")
        expected_runtime_state = deterministic(
            b"resident UI/control state", RUNTIME_STATE_END - RUNTIME_STATE_START
        )
        expected_prompt_marker = b"\x93"
        machine.mem_write(ROOT_FRAME_START, struct.pack("<H", root_return_sp))
        machine.mem_write(
            ROOT_FRAME_START + 2,
            struct.pack("<H", (~root_return_sp) & 0xFFFF),
        )
        machine.mem_write(ROOT_FRAME_START + 4, struct.pack("<H", 0xA55A))
        machine.mem_write(ROOT_FRAME_STATE, expected_runtime_state)
        machine.mem_write(ROOT_FRAME_PROMPT_MARKER, expected_prompt_marker)
        machine.mem_write(
            RUNTIME_STATE_START,
            deterministic(b"overwritten UI/control state", len(expected_runtime_state)),
        )
        machine.mem_write(DPI_PROMPT_MARKER_ROW, b"\x2a")
    install_io_rejection(machine)

    commit_label = "post_commit_fresh" if fresh else "post_commit_final"
    commit = BUILDER.label_address(controller.listing, commit_label, 0x0900)
    failed_entry = BUILDER.label_address(controller.listing, "post_failed", 0x0900)
    low_abort = 0x0F60
    reached_commit = False
    reached_return = False
    reached_resumption_controller = False
    failed = False
    acknowledgements = 0
    transmissions = 0
    last_controller_ip: int | None = None
    failed_from: int | None = None
    last_sym_ip: int | None = None
    nst_failed_from: int | None = None
    writes_above_floor: list[tuple[int, int]] = []
    transition_loads: list[tuple[int, int]] = []
    commit_state: dict[str, Any] = {}
    response_ingress_samples: list[int] = []
    resumed_controller_loaded = False
    response_ingress_sampler = BUILDER.label_address(
        images["resume_ready"].listing,
        "system_ram_record_tick",
        0x0F00,
    )
    resumed_ticket_age_ready = BUILDER.label_address(
        images["resumed_hello_controller"].listing,
        "live_hello_ticket_age_ready",
        named["resumed_hello_controller"].destination,
    )

    def return_ok(uc: Uc, _address: int, _size: int, _user: object) -> None:
        near_return(uc)

    def receive(uc: Uc, _address: int, _size: int, _user: object) -> None:
        if not queue:
            near_return(uc, carry=True)
            return
        fragment = queue.pop(0)
        uc.mem_write(0x0700, fragment)
        uc.mem_write(0x0FE2, struct.pack("<HH", 0x0700, len(fragment)))
        near_return(uc)

    def ack(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal acknowledgements
        acknowledgements += 1
        if fresh and not queue:
            # Model the large 4.77 MHz gap between the first encrypted
            # response/NST batch ingress and authenticated post-processing
            # commit.  Sampling at ticket-parser or commit time would omit
            # this interval when OpenAI coalesces the response and NST.
            uc.mem_write(
                BIOS_TICKS,
                struct.pack("<I", receipt_ticks + processing_ticks),
            )
        near_return(uc)

    def observe_response_ingress_sample(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        response_ingress_samples.append(
            struct.unpack("<I", uc.mem_read(BIOS_TICKS, 4))[0]
        )

    def transmit(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal transmissions
        transmissions += 1
        near_return(uc)

    def observe_commit(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal reached_commit
        reached_commit = True
        for label in (
            "post_record_active",
            "post_header_pos",
            "post_head_complete",
            "post_http_done",
            "post_ticket_complete",
        ):
            address = BUILDER.label_address(controller.listing, label, 0x0900)
            commit_state[label] = uc.mem_read(address, 1)[0]
        for label in (
            "post_plain_len",
            "post_cipher_remaining",
            "post_message_len",
        ):
            address = BUILDER.label_address(controller.listing, label, 0x0900)
            commit_state[label] = struct.unpack("<H", uc.mem_read(address, 2))[0]
        commit_state["server_sequence"] = bytes(uc.mem_read(SYM_SERVER_SEQ, 8))
        if expected_ticket_plaintext is not None:
            commit_state["ticket_plaintext_matches"] = (
                bytes(uc.mem_read(0x0D00, len(expected_ticket_plaintext)))
                == expected_ticket_plaintext
            )
            commit_state["ticket_identity"] = bytes(
                uc.mem_read(SYM_TICKET_IDENTITY, len(identity))
            )
            commit_state["ticket_psk"] = bytes(uc.mem_read(SYM_TICKET_PSK, 32))

    def stop_return(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal reached_return
        reached_return = True
        commit_state["return_sp"] = uc.reg_read(UC_X86_REG_SP) & 0xFFFF
        commit_state["return_flags"] = uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
        uc.emu_stop()

    transition_phase_names = (
        "lifecycle",
        "res_sym",
        "keygen",
        "ticket_age",
        "resumed_hello",
        "resumed_hello_controller",
    )
    transition_phases = {
        named[name].key: name for name in transition_phase_names
    }

    def load_transition_phase(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal resumed_controller_loaded
        phase_key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        name = transition_phases.get(phase_key)
        if name is None:
            raise AssertionError(
                f"fresh post transition requested unexpected phase {phase_key:#06x}"
            )
        if destination != named[name].destination:
            raise AssertionError(
                f"fresh post transition loaded {name} at {destination:#06x}, "
                f"expected {named[name].destination:#06x}"
            )
        transition_loads.append((phase_key, destination))
        payload = padded(images[name].data, named[name].sectors)
        uc.mem_write(destination, payload)
        invalidate_code(uc, destination, destination + len(payload))
        if name == "resumed_hello_controller":
            resumed_controller_loaded = True
        if name == "keygen":
            # The real 4.77 MHz KeyGen advances the BIOS counter while the
            # lifecycle image remains resident at 0900.  Unicorn has no PIT,
            # so advance it explicitly and require the shipped late-age entry
            # to account for the full delay before HELLO is loaded.
            uc.mem_write(BIOS_TICKS, struct.pack("<I", current_ticks))
        near_return(uc)

    def stop_resumption_controller(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal reached_resumption_controller
        # The acquisition symmetric image also covers 0x2a00.  Only stop
        # after the transition has replaced that byte range with the exact
        # resumed HELLO controller.  Let its first action call the resident
        # ticket-age helper, then stop at the labelled post-age boundary.
        if not resumed_controller_loaded:
            return
        reached_resumption_controller = True
        uc.emu_stop()

    def stop_abort(uc: Uc, _address: int, _size: int, _user: object) -> None:
        nonlocal failed
        failed = True
        uc.emu_stop()

    def track_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        if address + size > 0x4000:
            writes_above_floor.append((address, size))

    def track_controller(
        _uc: Uc, address: int, _size: int, _user: object
    ) -> None:
        nonlocal last_controller_ip, failed_from
        if address == failed_entry:
            failed_from = last_controller_ip
        last_controller_ip = address

    parse_start = BUILDER.label_address(sym_image.listing, "sym_parse_nst", 0x1800)
    open_start = BUILDER.label_address(sym_image.listing, "sym_open_begin", 0x1800)
    parse_region = sym_image.data[parse_start - 0x1800 : open_start - 0x1800]
    parse_failed_offset = parse_region.rfind(b"\xf9\xc3")
    if parse_failed_offset < 0:
        raise AssertionError("cannot locate the NST parser failure return")
    parse_failed = parse_start + parse_failed_offset

    def track_sym(_uc: Uc, address: int, _size: int, _user: object) -> None:
        nonlocal last_sym_ip, nst_failed_from
        if address == parse_failed:
            nst_failed_from = last_sym_ip
        last_sym_ip = address

    machine.hook_add(UC_HOOK_CODE, ack, begin=0x13A6, end=0x13A6)
    machine.hook_add(UC_HOOK_CODE, return_ok, begin=0x13E2, end=0x13E2)
    machine.hook_add(UC_HOOK_CODE, receive, begin=0x14ED, end=0x14ED)
    machine.hook_add(UC_HOOK_CODE, transmit, begin=0x1700, end=0x1700)
    machine.hook_add(UC_HOOK_CODE, observe_commit, begin=commit, end=commit)
    if fresh:
        machine.hook_add(
            UC_HOOK_CODE,
            observe_response_ingress_sample,
            begin=response_ingress_sampler,
            end=response_ingress_sampler,
        )
        machine.hook_add(
            UC_HOOK_CODE,
            load_transition_phase,
            begin=0x10C4,
            end=0x10C4,
        )
        machine.hook_add(
            UC_HOOK_CODE,
            stop_resumption_controller,
            begin=resumed_ticket_age_ready,
            end=resumed_ticket_age_ready,
        )
    else:
        machine.hook_add(UC_HOOK_CODE, stop_return, begin=RETURN, end=RETURN)
    machine.hook_add(UC_HOOK_CODE, stop_abort, begin=low_abort, end=low_abort)
    machine.hook_add(
        UC_HOOK_CODE,
        track_controller,
        begin=0x0900,
        end=0x0900 + len(controller.data) - 1,
    )
    machine.hook_add(
        UC_HOOK_CODE,
        track_sym,
        begin=0x1800,
        end=0x1800 + len(sym_image.data) - 1,
    )
    machine.hook_add(UC_HOOK_MEM_WRITE, track_write)
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP if fresh else STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_EFLAGS, 2)
    try:
        machine.emu_start(0x0900, 0, count=300_000_000)
    except UcError as exc:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(f"{controller_name} failed at {ip:#06x}: {exc}") from exc
    transition_incomplete = fresh and not reached_resumption_controller
    publication_incomplete = not fresh and not reached_return
    if corrupt_http_tag:
        if not failed or reached_commit or reached_return or reached_resumption_controller:
            raise AssertionError(f"{controller_name} published a forged HEAD")
        if transition_loads or bytes(machine.mem_read(SYM_SERVER_SEQ, 8)) != (1).to_bytes(8, "big"):
            raise AssertionError(f"{controller_name} consumed a forged HEAD")
        for label in ("post_head_complete", "post_http_done"):
            address = BUILDER.label_address(controller.listing, label, 0x0900)
            if machine.mem_read(address, 1) != b"\x00":
                raise AssertionError(f"{controller_name} parsed unauthenticated HTTP")
        assert_machine_guards(machine, guards)
        return {
            "http_inner_bytes": len(http) + 1,
            "forged_tag_rejected_before_http_or_publication": True,
            "disk_independent_abort_reached": True,
        }
    if failed or not reached_commit or transition_incomplete or publication_incomplete:
        state = dict(commit_state)
        state["compact_root"] = bytes(machine.mem_read(COMPACT_ROOT, 34)).hex()
        state["resume_identity_len"] = struct.unpack(
            "<H", machine.mem_read(0x3484, 2)
        )[0]
        state["root_frame"] = bytes(
            machine.mem_read(ROOT_FRAME_START, ROOT_FRAME_END - ROOT_FRAME_START)
        ).hex()
        state["root_return"] = bytes(machine.mem_read(STACK_TOP - 2, 2)).hex()
        state["sp"] = machine.reg_read(UC_X86_REG_SP) & 0xFFFF
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(
            f"{controller_name} did not reach its authenticated continuation: "
            f"aborted={failed}, ip={ip:#06x}, unread_fragments={len(queue)}, "
            f"failed_from={failed_from!r}, nst_failed_from={nst_failed_from!r}, "
            f"loads={transition_loads}, state={state}"
        )
    if queue:
        raise AssertionError(f"{controller_name} committed before draining input")
    if writes_above_floor:
        raise AssertionError(f"{controller_name} escaped 16 KiB: {writes_above_floor[:4]}")
    for label, expected in (
        ("post_record_active", 0),
        ("post_header_pos", 0),
        ("post_head_complete", 1),
        ("post_http_done", 1),
    ):
        if commit_state.get(label) != expected:
            raise AssertionError(f"{controller_name} left {label} invalid")
    if fresh:
        if response_ingress_samples != [receipt_ticks]:
            raise AssertionError(
                "fresh post did not snapshot the first response batch exactly once: "
                f"{response_ingress_samples}"
            )
        if commit_state.get("post_ticket_complete") != 1:
            raise AssertionError("fresh post committed without an authenticated ticket")
        if commit_state.get("ticket_identity") != identity:
            actual_identity = bytes(commit_state.get("ticket_identity", b""))
            classification = (
                "second ticket"
                if actual_identity == second_identity
                else "corrupt/partial ticket"
            )
            raise AssertionError(
                "fresh post retained the wrong ticket identity "
                f"({classification}; actual_sha256="
                f"{hashlib.sha256(actual_identity).hexdigest()}, expected_sha256="
                f"{hashlib.sha256(identity).hexdigest()})"
            )
        if commit_state.get("ticket_psk") != expected_psk:
            raise AssertionError("fresh post retained the wrong ticket PSK")
        expected_loads = [
            (named[name].key, named[name].destination)
            for name in transition_phase_names
        ]
        if transition_loads != expected_loads:
            raise AssertionError(
                f"fresh post resumption phase sequence changed: {transition_loads}"
            )
        if bytes(machine.mem_read(CAPSULE_HIGH, 32)) != transition_root:
            raise AssertionError("fresh post resumption preparation lost its root")
        if bytes(machine.mem_read(0x3460, 32)) != expected_psk:
            raise AssertionError("fresh post resumption preparation lost its ticket PSK")
        if bytes(machine.mem_read(0x3000, len(identity))) != identity:
            raise AssertionError("fresh post resume-ready publication lost its identity")
        if bytes(machine.mem_read(0x3486, 192)) != bytes(192):
            raise AssertionError("fresh post retained its staged ticket identity")
        elapsed_ms = elapsed_ticks * 55 - ((elapsed_ticks * 611) >> 13)
        expected_age = (
            int.from_bytes(nst[8:12], "big") + elapsed_ms
        ) & 0xFFFFFFFF
        if bytes(machine.mem_read(0x3480, 4)) != expected_age.to_bytes(4, "big"):
            raise AssertionError("fresh post transition encoded stale ticket age")
        if bytes(machine.mem_read(RESUME_AGE_STATE, 12)) != bytes(12):
            raise AssertionError("fresh post transition retained ticket timing state")

        # Exercise the exact resumed HELLO image after the complete product
        # transition.  Component gates seed its inputs directly and therefore
        # cannot catch a ticket/PSK/age/key-share handoff damaged by KeyGen or
        # phase replacement.  Compare every emitted byte, including the
        # assembly-computed binder, with the independent Python oracle.
        hello_entries = struct.unpack(
            "<14H", bytes(machine.mem_read(0x1830, 14 * 2))
        )
        if any(not 0x1800 <= entry < 0x2800 for entry in hello_entries):
            raise AssertionError("resumed HELLO entry table escaped its phase")
        hello_ek = bytes(machine.mem_read(0x08C0, HELLO.EK_LEN))
        invalid_coefficients = noncanonical_mlkem768_public_coefficients(hello_ek)
        if invalid_coefficients:
            raise AssertionError(
                "full transition emitted a non-canonical ML-KEM public key: "
                f"coefficients {invalid_coefficients[:16]}"
            )
        hello_random = bytes(machine.mem_read(0x3420, 32))
        hello_session = bytes(machine.mem_read(0x3440, 32))
        hello_psk = bytes(machine.mem_read(0x3460, 32))
        hello_age = bytes(machine.mem_read(0x3480, 4))
        hello_identity_len = struct.unpack(
            "<H", bytes(machine.mem_read(0x3484, 2))
        )[0]
        hello_identity = bytes(machine.mem_read(0x3000, hello_identity_len))
        if hello_psk != expected_psk:
            raise AssertionError("full transition changed the resumed HELLO PSK")
        if hello_identity != identity:
            raise AssertionError("full transition changed the resumed HELLO identity")
        if not any(hello_random) or not any(hello_session) or not any(hello_ek):
            raise AssertionError("full transition published a zero HELLO input")
        _message, expected_record, truncated, expected_binder = (
            HELLO.build_resumed_client(
                hello_ek,
                hello_random,
                hello_session,
                hello_identity,
                hello_age,
                hello_psk,
                alpn=b"h2",
            )
        )
        if expected_binder != HELLO.resumption_binder(hello_psk, truncated):
            raise AssertionError("independent resumed HELLO binder oracle drifted")

        invoke_hello_entry(machine, hello_entries[1])
        emitted = bytearray()
        fragment_lengths: list[int] = []
        while True:
            ax, si, cx = invoke_hello_entry(machine, hello_entries[2])
            if ax == 0:
                break
            if ax != 1 or cx == 0 or len(fragment_lengths) >= 8:
                raise AssertionError("resumed HELLO iterator geometry changed")
            emitted.extend(machine.mem_read(si, cx))
            fragment_lengths.append(cx)
            invoke_hello_entry(machine, hello_entries[3])
        if bytes(emitted) != expected_record:
            difference = next(
                (
                    index
                    for index, (actual, expected) in enumerate(
                        zip(emitted, expected_record)
                    )
                    if actual != expected
                ),
                min(len(emitted), len(expected_record)),
            )
            raise AssertionError(
                "full-transition resumed ClientHello differs from oracle at "
                f"byte {difference} ({len(emitted)} != {len(expected_record)})"
            )
        if fragment_lengths != [147, 384, 384, 384, 32, 70, 192, 39]:
            raise AssertionError(
                f"full-transition resumed HELLO fragments changed: {fragment_lengths}"
            )
        commit_state["resumed_hello_record_sha256"] = hashlib.sha256(
            emitted
        ).hexdigest()
        commit_state["resumed_hello_binder_sha256"] = hashlib.sha256(
            expected_binder
        ).hexdigest()
    else:
        expected_published = (
            client_key
            + key
            + client_iv
            + iv
            + client_sequence
            + len(contents).to_bytes(8, "big")
        )
        if bytes(machine.mem_read(0x3600, len(expected_published))) != expected_published:
            raise AssertionError("final post published the wrong application capability")
        for start, end, name in (
            (0x0500, 0x0600, "SHA workspace"),
            (0x0700, 0x0F00, "low TLS scratch"),
            (0x1800, 0x3600, "crypto window"),
            (0x3668, 0x3B9C, "high TLS scratch"),
            (ROOT_FRAME_START, ROOT_FRAME_END, "root return frame"),
        ):
            if bytes(machine.mem_read(start, end - start)) != bytes(end - start):
                raise AssertionError(f"final post retained {name}")
        if machine.mem_read(0x06C4, 1) != b"\x00":
            raise AssertionError("final post exposed READY before its resident caller")
        if bytes(
            machine.mem_read(
                RUNTIME_STATE_START,
                RUNTIME_STATE_END - RUNTIME_STATE_START,
            )
        ) != expected_runtime_state:
            raise AssertionError("final post did not restore resident UI/control state")
        if machine.mem_read(DPI_PROMPT_MARKER_ROW, 1) != expected_prompt_marker:
            raise AssertionError("final post did not restore the DPI prompt marker row")
        expected_crypto_constants = LOW_STATIC_CONSTANTS[LOW_STATIC_CRYPTO_OFFSET:]
        actual_crypto_constants = bytes(
            machine.mem_read(
                LOW_STATIC_CONSTANTS_START + LOW_STATIC_CRYPTO_OFFSET,
                len(expected_crypto_constants),
            )
        )
        if actual_crypto_constants != expected_crypto_constants:
            difference = next(
                index
                for index, (actual, expected) in enumerate(
                    zip(
                        actual_crypto_constants,
                        expected_crypto_constants,
                        strict=True,
                    )
                )
                if actual != expected
            )
            raise AssertionError(
                "final post did not restore the resident TLS crypto constants: "
                f"byte {difference} is {actual_crypto_constants[difference]:#04x}, "
                f"expected {expected_crypto_constants[difference]:#04x}"
            )
        if bytes(
            machine.mem_read(
                LOW_TAIL_STATE_START,
                LOW_TAIL_STATE_END - LOW_TAIL_STATE_START,
            )
        ) != bytes(LOW_TAIL_STATE_END - LOW_TAIL_STATE_START):
            raise AssertionError(
                "final post retained stale resident TCP/TLS cursor state"
            )
        if commit_state.get("return_sp") != STACK_TOP:
            raise AssertionError("final post returned on the wrong root stack")
        if int(commit_state.get("return_flags", 1)) & 1:
            raise AssertionError("final post returned with carry set")
        commit_state["publication_returned"] = True
    if commit_state.get("server_sequence") != len(contents).to_bytes(8, "big"):
        raise AssertionError(f"{controller_name} advanced the wrong server sequence")
    expected_transmissions = 2 if fresh else 0
    if acknowledgements < fragment_count or transmissions != expected_transmissions:
        # Fresh emits a zero-window ACK followed by embedded FIN/RST.  Final
        # retains its authenticated socket for the resident chat loop.
        raise AssertionError(
            f"{controller_name} close trace changed: ack={acknowledgements}, tx={transmissions}"
        )
    assert_machine_guards(machine, guards)
    return {
        "tls_records": len(contents),
        "http_content_bytes": len(http),
        "http_inner_bytes": len(http) + 1,
        "tcp_fragments": fragment_count,
        "multi_record_http": True,
        "authenticated_ticket": fresh,
        "response_batch_ingress_to_authenticated_commit_ticks": (
            processing_ticks if fresh else None
        ),
        "embedded_close_frames": transmissions,
        "connection_retained": not fresh,
        "resident_application_cursor_zeroed": not fresh,
        "publication_returned": commit_state.get("publication_returned", False),
        "resumption_transition": (
            [
                f"{phase_key:#06x}@{destination:#06x}"
                for phase_key, destination in transition_loads
            ]
            if fresh
            else None
        ),
        "full_transition_resumed_hello": (
            {
                "record_sha256": commit_state.get("resumed_hello_record_sha256"),
                "binder_sha256": commit_state.get("resumed_hello_binder_sha256"),
                "oracle_match": True,
            }
            if fresh
            else None
        ),
    }


def post_h2_gate(work, images, slots, pack):
    import prepare_http2_tests
    out = ROOT / "build/ibm_pc_5150/http2-tests"
    metadata = prepare_http2_tests.prepare(out, work, images, slots, pack)
    os.environ["SEED_HTTP2_TEST_IMAGE"] = str(out)
    sys.path.insert(0, str(HERE / "http2"))
    import check_h2_liveness
    check_h2_liveness.main()
    result = json.loads((out / "liveness-gate.json").read_text())
    if result["core_sha256"] != metadata["core_sha256"]:
        raise AssertionError("cold H2 test image changed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product-core", type=Path, required=True)
    parser.add_argument("--product-listing", type=Path, required=True)
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="seed-shipped-system-pack-") as raw:
        work = Path(raw)
        images, slots, named, exact_pack = build_exact(
            args.product_core.resolve(),
            args.product_listing.resolve(),
            work,
        )
        vector = build_mlkem_composition_vector(work)
        report = check_shipped_pack(
            exact_pack,
            slots,
            args.pack.resolve(),
            args.report.resolve(),
        )
        result = {
            "schema": "seed-tls13-system-ram-product-integration-v1",
            "pack_sha256": report["pack"]["sha256"],
            "root_state": root_state_gate(images),
            "high_auth_abort": high_auth_abort_gate(images, named),
            "preconnect": {
                "resumption": resumed_hello_preconnect_gate(images, named),
            },
            "deadline": {
                "acquisition": deadline_gate(
                    images, named, vector, resumed=False
                ),
                "resumption": deadline_gate(
                    images, named, vector, resumed=True
                ),
            },
            "offline_fo_composition": {
                "acquisition": fo_composition_gate(
                    images, named, resumed=False
                ),
                "resumption": fo_composition_gate(
                    images, named, resumed=True
                ),
            },
            "lifecycle": lifecycle_gate(
                images["lifecycle"].data,
                images["ticket_age"].data,
            ),
            "post": post_h2_gate(work, images, slots, exact_pack),
            "security_boundary": {
                "display_ram": False,
                "adapter_ram": False,
                "config_or_arena": False,
                "bios_or_port_io_in_offline_orchestration": False,
                "silent_monotonic_bda_ticket_age": True,
            },
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
