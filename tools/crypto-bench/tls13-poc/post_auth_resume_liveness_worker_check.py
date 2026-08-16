#!/usr/bin/env python3
"""Executable hostile gate for the MODE_LOW resumed liveness worker.

The gate runs the real cpu-8086 worker and the real K14
ChaCha20-Poly1305/NewSessionTicket entries under Unicorn.  Resident NIC/TCP
services are fixed-address test doubles which supply hostile retransmit,
fragmentation, failure, and return-stack schedules.
"""

from __future__ import annotations

import importlib.util
import json
import math
import re
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc, UcError
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "post_auth_resume_liveness_worker.asm"
SYM_SOURCE = HERE / "tls13_sym_overlay.asm"
APP_CHECK = HERE / "post_auth_application_check.py"
RESULTS = HERE / "post_auth_resume_liveness_worker_results.json"

RAM_BYTES = 0x10000
WORKER_ORIGIN = 0x0900
WORKER_LIMIT = 0x0F00
EXECUTABLE_LIMIT = 0x0D00
OUTER_START = 0x0F00
OUTER_END = 0x0FE2
AFTER_LIVENESS = 0x0F30
STALE_OUTER_RETURN = 0x0F10
TCP_PAYLOAD_PTR = 0x0FE2
TCP_PAYLOAD_LEN = 0x0FE4
TCP_ACK = 0x13A6
TCP_RECEIVE = 0x14ED
NIC_RECEIVE_SLOT = 0x15E1
NIC_RECEIVE = 0x1600
SYM_ORIGIN = 0x1800
SYM_ENTRY_TABLE = 0x1820
RX_STAGE = 0x3400
RX_STAGE_LIMIT = 0x3510
SYM_RECORD_ACTIVE = 0x3520
SERVER_APP_KEY = 0x3864
SERVER_APP_IV = 0x3884
SERVER_APP_SEQ = 0x38E8
SYM_RECEIVED_TAG = 0x3910
SYM_IO = 0x39A0
TICKET_PSK = 0x38B0
TICKET_IDENTITY = 0x3B40
TICKET_END = 0x3C2D
TICKET_PRESENT = 0x3C2C
ROUTE_CONTROL_START = 0x3C30
ROUTE_CONTROL_END = 0x3C46
WORKER_STATE_START = 0x3C46
WORKER_STATE_END = 0x3C76
LIFECYCLE_START = 0x3C76
LIFECYCLE_END = 0x3C9A
PROTECTED_START = 0x0600
PROTECTED_END = 0x08B6
RX_SAMPLE_COUNT = 0x06D5
RX_READ_LIMIT = 0x06D7
STACK_WORD = 0x3FEC
ORIGINAL_ES = 0x0020
DF = 1 << 10

QUARANTINE_RANGES = (
    (0x0D00, 0x0EE0),
    (0x3600, 0x3838),
    (0x3910, 0x3B40),
)

SERVER_KEY = bytes.fromhex(
    "b9f7f03e25744bbb0ffbe1f5ea73348b"
    "e2f0c0877fbbb9d40b37a4301a4c92af"
)
SERVER_IV = bytes.fromhex("e582b147ac7f9e94bd8ed9a2")


def load_app_check():
    spec = importlib.util.spec_from_file_location(
        "seed_resume_liveness_app_check", APP_CHECK
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {APP_CHECK}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


APP = load_app_check()
TLS = APP.TLS


def set_carry(machine: Uc, enabled: bool) -> None:
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    if enabled:
        flags |= 1
    else:
        flags &= ~1
    machine.reg_write(UC_X86_REG_EFLAGS, flags)


def set_df(machine: Uc, enabled: bool) -> None:
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    if enabled:
        flags |= DF
    else:
        flags &= ~DF
    machine.reg_write(UC_X86_REG_EFLAGS, flags)


def pattern(start: int, end: int, seed: int) -> bytes:
    return bytes((seed + index * 29) & 0xFF for index in range(end - start))


def build_nst(seed: int, *, identity_len: int = 32) -> bytes:
    lifetime = (3600 + seed).to_bytes(4, "big")
    age_add = (0x10203040 + seed).to_bytes(4, "big")
    nonce = bytes(((seed + index * 7) & 0xFF) for index in range(8))
    identity = bytes(
        ((0x80 + seed + index * 11) & 0xFF)
        for index in range(identity_len)
    )
    extensions = b"\x00\x2a\x00\x04\x00\x00\x10\x00"
    body = (
        lifetime
        + age_add
        + bytes([len(nonce)])
        + nonce
        + len(identity).to_bytes(2, "big")
        + identity
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return b"\x04" + len(body).to_bytes(3, "big") + body


def encrypt_records(
    items: tuple[tuple[int, bytes, int], ...],
) -> tuple[bytes, ...]:
    return tuple(
        TLS.encrypted_record(
            SERVER_KEY,
            SERVER_IV,
            sequence,
            inner_type,
            content,
            padding_len=padding,
        )
        for sequence, (inner_type, content, padding) in enumerate(items)
    )


def fragment_bytes(
    value: bytes, sizes: tuple[int, ...] = (1, 2, 5, 3, 17, 31, 7, 64, 11, 127)
) -> tuple[bytes, ...]:
    pieces: list[bytes] = []
    offset = 0
    index = 0
    while offset < len(value):
        size = sizes[index % len(sizes)]
        index += 1
        end = min(offset + size, len(value))
        pieces.append(value[offset:end])
        offset = end
    if not pieces or max(map(len, pieces)) > RX_STAGE_LIMIT - RX_STAGE:
        raise AssertionError("host fragmentation exceeds fixed RX test stage")
    return tuple(pieces)


def assemble(build: Path) -> tuple[bytes, tuple[int, ...], dict[str, int], Path]:
    build.mkdir(parents=True, exist_ok=True)
    sym_path = build / "sym-k14.bin"
    sym_listing = build / "sym-k14.lst"
    sym = APP.run_nasm(
        SYM_SOURCE,
        sym_path,
        sym_listing,
        defines={"TLS13_POC_K14": 1, "TLS13_SHARED_SECRET_LEN": 64},
        include_boot=True,
    )
    entries = APP.parse_sym_entries(sym)
    worker_path = build / "resume-liveness.bin"
    worker_listing = build / "resume-liveness.lst"
    defines = {
        "RESUME_LIVENESS_TCP_RECEIVE": TCP_RECEIVE,
        "RESUME_LIVENESS_TCP_ACK": TCP_ACK,
        "RESUME_LIVENESS_NIC_RECEIVE_SLOT": NIC_RECEIVE_SLOT,
        "RESUME_LIVENESS_RX_SAMPLE_COUNT": RX_SAMPLE_COUNT,
        "RESUME_LIVENESS_RX_READ_LIMIT": RX_READ_LIMIT,
        "RESUME_LIVENESS_TCP_PAYLOAD_PTR": TCP_PAYLOAD_PTR,
        "RESUME_LIVENESS_TCP_PAYLOAD_LEN": TCP_PAYLOAD_LEN,
        "RESUME_LIVENESS_SYM_OPEN_BEGIN_ENTRY": SYM_ENTRY_TABLE + 5 * 2,
        "RESUME_LIVENESS_SYM_OPEN_CHUNK_ENTRY": SYM_ENTRY_TABLE + 6 * 2,
        "RESUME_LIVENESS_SYM_OPEN_FINISH_ENTRY": SYM_ENTRY_TABLE + 7 * 2,
        "RESUME_LIVENESS_SYM_PARSE_NST_ENTRY": SYM_ENTRY_TABLE + 12 * 2,
        "RESUME_LIVENESS_SYM_RECORD_ACTIVE": SYM_RECORD_ACTIVE,
        "RESUME_LIVENESS_SYM_IO": SYM_IO,
        "RESUME_LIVENESS_SYM_RECEIVED_TAG": SYM_RECEIVED_TAG,
        "RESUME_LIVENESS_TICKET_PRESENT": TICKET_PRESENT,
    }
    worker = APP.run_nasm(
        SOURCE,
        worker_path,
        worker_listing,
        defines=defines,
    )
    symbols = {
        "resume_liveness_code_end": WORKER_ORIGIN + len(worker),
        "liveness_process_plaintext": APP.listing_symbol_address(
            worker_listing,
            "liveness_process_plaintext",
            origin=WORKER_ORIGIN,
        ),
        "liveness_process_http": APP.listing_symbol_address(
            worker_listing,
            "liveness_process_http",
            origin=WORKER_ORIGIN,
        ),
    }
    return worker, entries, symbols, worker_listing


def static_gate(worker: bytes, symbols: dict[str, int], build: Path) -> dict[str, int]:
    if len(worker) > WORKER_LIMIT - WORKER_ORIGIN:
        raise AssertionError("worker exceeds the MODE_LOW load window")
    if symbols["resume_liveness_code_end"] > EXECUTABLE_LIMIT:
        raise AssertionError("executable reaches its plaintext quarantine")
    if worker[2:6] != b"RSL1":
        raise AssertionError("worker magic drifted")
    version, image_bytes, origin, entry = struct.unpack_from("<4H", worker, 6)
    if (version, image_bytes, origin, entry) != (
        1,
        len(worker),
        WORKER_ORIGIN,
        WORKER_ORIGIN,
    ):
        raise AssertionError("worker header geometry drifted")
    source = SOURCE.read_text(encoding="utf-8")
    if re.search(
        r"(?m)^[ \t]*(int|in|out)[ \t]+",
        source,
    ):
        raise AssertionError("worker contains direct BIOS/port I/O")
    if not re.search(
        r"(?m)^resume_liveness_code:\n"
        r"(?:[ \t]*;[^\n]*\n)*[ \t]*sti\b",
        source,
    ):
        raise AssertionError("worker does not establish IF before HLT waits")

    disassembler = Cs(CS_ARCH_X86, CS_MODE_16)
    decoded = list(disassembler.disasm(worker, WORKER_ORIGIN))
    if not decoded:
        raise AssertionError("worker did not disassemble")
    covered = sum(instruction.size for instruction in decoded)
    if covered != len(worker):
        raise AssertionError("worker image has undecoded bytes")

    missing_path = build / "missing.bin"
    completed = subprocess.run(
        ["nasm", "-f", "bin", "-o", str(missing_path), str(SOURCE)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        raise AssertionError("worker assembled without its fixed ABI")
    return {
        "bytes": len(worker),
        "sectors": math.ceil(len(worker) / 512),
        "executable_bytes": symbols["resume_liveness_code_end"] - WORKER_ORIGIN,
        "mode_low_window_bytes": WORKER_LIMIT - WORKER_ORIGIN,
        "state_bytes": WORKER_STATE_END - WORKER_STATE_START,
    }


@dataclass(frozen=True)
class RunResult:
    ax: int
    carry: bool
    df: bool
    es: int
    ip: int
    sp: int
    stale_return: int
    events: tuple[str, ...]
    fragments_consumed: int
    ack_count: int
    parse_calls: int
    process_calls: int
    server_sequence: int
    ticket_marker: int
    ticket_unchanged: bool
    protected_unchanged: bool
    outer_unchanged: bool
    route_control_unchanged: bool
    lifecycle_unchanged: bool
    quarantine_clear: bool
    worker_state_clear: bool


def run_case(
    worker: bytes,
    sym: bytes,
    entries: tuple[int, ...],
    symbols: dict[str, int],
    fragments: tuple[bytes, ...],
    *,
    operation: int = 8,
    ticket_marker: int = 1,
    tcp_fail_at: int | None = None,
    ack_fail_at: int | None = None,
) -> RunResult:
    if not 0 <= ticket_marker <= 0xFF:
        raise ValueError("ticket marker must fit one byte")
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes(RAM_BYTES))

    protected = pattern(PROTECTED_START, PROTECTED_END, 0x31)
    outer = pattern(OUTER_START, OUTER_END, 0x52)
    route_control = pattern(ROUTE_CONTROL_START, ROUTE_CONTROL_END, 0x73)
    lifecycle = pattern(LIFECYCLE_START, LIFECYCLE_END, 0x94)
    machine.mem_write(PROTECTED_START, protected)
    machine.mem_write(OUTER_START, outer)
    machine.mem_write(ROUTE_CONTROL_START, route_control)
    machine.mem_write(LIFECYCLE_START, lifecycle)
    machine.mem_write(RX_SAMPLE_COUNT, b"\0\0")
    machine.mem_write(RX_READ_LIMIT, struct.pack("<H", 438))
    protected = bytes(machine.mem_read(PROTECTED_START, PROTECTED_END - PROTECTED_START))
    machine.mem_write(AFTER_LIVENESS, b"\xF4")
    outer = bytes(machine.mem_read(OUTER_START, OUTER_END - OUTER_START))

    machine.mem_write(WORKER_ORIGIN, bytes(WORKER_LIMIT - WORKER_ORIGIN))
    machine.mem_write(WORKER_ORIGIN, worker)
    machine.mem_write(SYM_ORIGIN, sym)
    machine.mem_write(TCP_ACK, b"\xC3")
    machine.mem_write(TCP_RECEIVE, b"\xC3")
    machine.mem_write(NIC_RECEIVE, b"\xC3")
    machine.mem_write(NIC_RECEIVE_SLOT, struct.pack("<H", NIC_RECEIVE))

    machine.mem_write(SERVER_APP_KEY, SERVER_KEY)
    machine.mem_write(SERVER_APP_IV, SERVER_IV)
    machine.mem_write(SERVER_APP_SEQ, bytes(8))
    ticket_psk = pattern(TICKET_PSK, TICKET_PSK + 32, 0xB5)
    ticket_identity = pattern(TICKET_IDENTITY, TICKET_END, 0xC6)
    machine.mem_write(TICKET_PSK, ticket_psk)
    machine.mem_write(TICKET_IDENTITY, ticket_identity)
    machine.mem_write(TICKET_PRESENT, bytes([ticket_marker]))
    ticket_value = (
        bytes(machine.mem_read(TICKET_PSK, 32))
        + bytes(
            machine.mem_read(
                TICKET_IDENTITY, TICKET_END - TICKET_IDENTITY
            )
        )
    )

    for start, end in QUARANTINE_RANGES:
        machine.mem_write(start, bytes([0xA5]) * (end - start))
    machine.mem_write(
        WORKER_STATE_START,
        bytes([0x5A]) * (WORKER_STATE_END - WORKER_STATE_START),
    )
    machine.mem_write(
        STACK_WORD,
        struct.pack("<2H", AFTER_LIVENESS, STALE_OUTER_RETURN),
    )

    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_ES, ORIGINAL_ES)
    machine.reg_write(UC_X86_REG_SP, STACK_WORD)
    machine.reg_write(UC_X86_REG_AX, operation)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | DF)

    events: list[str] = []
    fragment_index = 0
    ack_count = 0
    parse_calls = 0
    process_calls = 0
    reached_after = False

    def tcp_receive_hook(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal fragment_index
        events.append("receive")
        if tcp_fail_at == fragment_index or fragment_index >= len(fragments):
            set_carry(uc, True)
            fragment_index += 1
            set_df(uc, True)
            return
        fragment = fragments[fragment_index]
        fragment_index += 1
        if len(fragment) > RX_STAGE_LIMIT - RX_STAGE:
            raise AssertionError("fragment exceeds fixed RX stage")
        uc.mem_write(RX_STAGE, fragment or b"\0")
        uc.mem_write(TCP_PAYLOAD_PTR, struct.pack("<H", RX_STAGE))
        uc.mem_write(TCP_PAYLOAD_LEN, struct.pack("<H", len(fragment)))
        set_carry(uc, False)
        set_df(uc, True)

    def ack_hook(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal ack_count
        events.append("ack")
        set_carry(uc, ack_fail_at == ack_count)
        ack_count += 1
        set_df(uc, True)

    def parse_hook(
        _uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal parse_calls
        parse_calls += 1
        events.append("parse_nst")

    def process_hook(
        _uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal process_calls
        process_calls += 1
        events.append("authenticated_record")

    def after_hook(
        uc: Uc, _address: int, _size: int, _user: object
    ) -> None:
        nonlocal reached_after
        reached_after = True
        events.append("after_liveness")
        uc.emu_stop()

    for address, callback in (
        (TCP_RECEIVE, tcp_receive_hook),
        (TCP_ACK, ack_hook),
        (entries[12], parse_hook),
        (symbols["liveness_process_plaintext"], process_hook),
        (AFTER_LIVENESS, after_hook),
    ):
        machine.hook_add(UC_HOOK_CODE, callback, begin=address, end=address)

    try:
        machine.emu_start(WORKER_ORIGIN, RAM_BYTES, count=150_000_000)
    except UcError as error:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(f"liveness worker faulted at {ip:#06x}: {error}") from error
    if not reached_after:
        raise AssertionError("worker did not RET to fixed after-liveness")

    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    quarantine_clear = all(
        not any(bytes(machine.mem_read(start, end - start)))
        for start, end in QUARANTINE_RANGES
    )
    result = RunResult(
        ax=machine.reg_read(UC_X86_REG_AX) & 0xFFFF,
        carry=bool(flags & 1),
        df=bool(flags & DF),
        es=machine.reg_read(UC_X86_REG_ES) & 0xFFFF,
        ip=machine.reg_read(UC_X86_REG_IP) & 0xFFFF,
        sp=machine.reg_read(UC_X86_REG_SP) & 0xFFFF,
        stale_return=struct.unpack(
            "<H", bytes(machine.mem_read(STACK_WORD + 2, 2))
        )[0],
        events=tuple(events),
        fragments_consumed=min(fragment_index, len(fragments)),
        ack_count=ack_count,
        parse_calls=parse_calls,
        process_calls=process_calls,
        server_sequence=int.from_bytes(
            bytes(machine.mem_read(SERVER_APP_SEQ, 8)), "big"
        ),
        ticket_marker=bytes(machine.mem_read(TICKET_PRESENT, 1))[0],
        ticket_unchanged=(
            bytes(machine.mem_read(TICKET_PSK, 32))
            + bytes(
                machine.mem_read(
                    TICKET_IDENTITY, TICKET_END - TICKET_IDENTITY
                )
            )
            == ticket_value
        ),
        protected_unchanged=(
            bytes(machine.mem_read(PROTECTED_START, PROTECTED_END - PROTECTED_START))
            == protected
        ),
        outer_unchanged=(
            bytes(machine.mem_read(OUTER_START, OUTER_END - OUTER_START))
            == outer
        ),
        route_control_unchanged=(
            bytes(
                machine.mem_read(
                    ROUTE_CONTROL_START,
                    ROUTE_CONTROL_END - ROUTE_CONTROL_START,
                )
            )
            == route_control
        ),
        lifecycle_unchanged=(
            bytes(
                machine.mem_read(
                    LIFECYCLE_START, LIFECYCLE_END - LIFECYCLE_START
                )
            )
            == lifecycle
        ),
        quarantine_clear=quarantine_clear,
        worker_state_clear=not any(
            bytes(
                machine.mem_read(
                    WORKER_STATE_START, WORKER_STATE_END - WORKER_STATE_START
                )
            )
        ),
    )
    if (
        result.ip != AFTER_LIVENESS
        or result.sp != STACK_WORD + 2
        or result.stale_return != STALE_OUTER_RETURN
        or result.es != ORIGINAL_ES
        or result.df
    ):
        raise AssertionError(f"worker violated low-tail return ABI: {result}")
    if not all(
        (
            result.ticket_unchanged,
            result.protected_unchanged,
            result.outer_unchanged,
            result.route_control_unchanged,
            result.lifecycle_unchanged,
            result.quarantine_clear,
            result.worker_state_clear,
        )
    ):
        raise AssertionError(f"worker violated memory/scrub contract: {result}")
    return result


def assert_success(
    result: RunResult,
    *,
    records: int,
    fragments: int,
    parse_calls: int,
) -> None:
    if result.carry or result.ax != 1:
        raise AssertionError(f"expected liveness success, got {result}")
    if result.ticket_marker != 1:
        raise AssertionError("liveness succeeded without the spent ticket marker")
    if result.fragments_consumed != fragments:
        raise AssertionError("worker did not consume every successful fragment")
    if result.ack_count != 1 + fragments:
        raise AssertionError("worker did not ACK window-open plus every fragment")
    if result.parse_calls != parse_calls:
        raise AssertionError("unexpected authenticated NST parse count")
    if result.process_calls != records or result.server_sequence != records:
        raise AssertionError("authenticated TLS record count/sequence drifted")


def assert_failure(result: RunResult) -> None:
    if not result.carry or result.ax != 0:
        raise AssertionError(f"expected fail-closed result, got {result}")


def run_gate() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="seed-resume-liveness-") as raw:
        build = Path(raw)
        worker, entries, symbols, _listing = assemble(build)
        sym = (build / "sym-k14.bin").read_bytes()
        geometry = static_gate(worker, symbols, build)

        passed: list[str] = []

        nst1 = build_nst(1)
        nst2 = build_nst(2, identity_len=48)
        contents = (
            (TLS.CONTENT_HANDSHAKE, nst1 + nst2, 5),
            (TLS.CONTENT_APPLICATION_DATA, b"HTTP/1.1 4", 0),
            (TLS.CONTENT_APPLICATION_DATA, b"04 Missing\r", 3),
            (TLS.CONTENT_APPLICATION_DATA, b"\nX-Seed: yes\r\n\r", 0),
            (TLS.CONTENT_APPLICATION_DATA, b"\n", 7),
        )
        records = encrypt_records(contents)
        fragments = fragment_bytes(b"".join(records))
        result = run_case(worker, sym, entries, symbols, fragments)
        assert_success(
            result,
            records=len(records),
            fragments=len(fragments),
            parse_calls=2,
        )
        if not (
            len(fragments[0]) == 1
            and any(len(fragment) == 1 for fragment in fragments)
            and result.events[0] == "ack"
            and "flush" not in result.events
        ):
            raise AssertionError(
                "queued-response success did not open the window before receive"
            )
        passed.append("fragmented_headers_tags_two_nsts_404")

        for status in (b"200 OK", b"503 Busy"):
            records = encrypt_records(
                (
                    (
                        TLS.CONTENT_APPLICATION_DATA,
                        b"HTTP/1.1 " + status + b"\r\nServer: seed\r\n\r\n",
                        9,
                    ),
                )
            )
            fragments = fragment_bytes(b"".join(records), (1, 16, 2, 31))
            result = run_case(worker, sym, entries, symbols, fragments)
            assert_success(
                result,
                records=1,
                fragments=len(fragments),
                parse_calls=0,
            )
            passed.append(f"authenticated_{status[:3].decode()}_header")

        large_header = (
            b"HTTP/1.1 200 OK\r\nX-Large: "
            + b"A" * 1100
            + b"\r\nX-End: yes\r\n\r\n"
        )
        records = encrypt_records(
            ((TLS.CONTENT_APPLICATION_DATA, large_header, 11),)
        )
        fragments = fragment_bytes(b"".join(records), (256, 3, 127, 1, 64))
        result = run_case(worker, sym, entries, symbols, fragments)
        assert_success(
            result,
            records=1,
            fragments=len(fragments),
            parse_calls=0,
        )
        passed.append("authenticated_header_crosses_all_quarantine_spans")

        def hostile(
            name: str,
            records_value: tuple[bytes, ...],
            *,
            marker: int = 1,
            operation: int = 8,
            fragments_value: tuple[bytes, ...] | None = None,
            **options: object,
        ) -> RunResult:
            selected = (
                fragments_value
                if fragments_value is not None
                else fragment_bytes(b"".join(records_value))
            )
            failure = run_case(
                worker,
                sym,
                entries,
                symbols,
                selected,
                operation=operation,
                ticket_marker=marker,
                **options,
            )
            assert_failure(failure)
            passed.append(name)
            return failure

        valid_http = encrypt_records(
            (
                (
                    TLS.CONTENT_APPLICATION_DATA,
                    b"HTTP/1.1 200 OK\r\nX: y\r\n\r\n",
                    0,
                ),
            )
        )
        corrupted = bytearray(valid_http[0])
        corrupted[-1] ^= 1
        bad_tag = hostile("bad_tag_no_plaintext_parse", (bytes(corrupted),))
        if bad_tag.process_calls or bad_tag.server_sequence:
            raise AssertionError("bad tag reached authenticated parser/advanced sequence")

        bad_http_contents = {
            "authenticated_425_too_early": (
                b"HTTP/1.1 425 Too Early\r\n\r\n"
            ),
            "authenticated_3xx_status": b"HTTP/1.1 302 Found\r\n\r\n",
            "authenticated_bad_prefix": b"HTTP/1.0 200 OK\r\n\r\n",
            "authenticated_bare_lf": b"HTTP/1.1 200 OK\nX: y\r\n\r\n",
            "authenticated_wrong_delimiter": b"HTTP/1.1 200 OK\r\nX: y\r\n\n",
            "authenticated_head_body": b"HTTP/1.1 200 OK\r\n\r\nbody",
        }
        for name, content in bad_http_contents.items():
            hostile(
                name,
                encrypt_records(
                    ((TLS.CONTENT_APPLICATION_DATA, content, 0),)
                ),
            )

        hostile(
            "authenticated_425_split_across_tls_records",
            encrypt_records(
                (
                    (TLS.CONTENT_APPLICATION_DATA, b"HTTP/1.1 4", 0),
                    (
                        TLS.CONTENT_APPLICATION_DATA,
                        b"25 Too Early\r\n\r\n",
                        0,
                    ),
                )
            ),
        )

        hostile(
            "authenticated_wrong_inner_type",
            encrypt_records(((TLS.CONTENT_ALERT, b"\x01\x00", 0),)),
        )
        malformed_nst = bytearray(build_nst(9))
        malformed_nst[3] ^= 1
        hostile(
            "authenticated_malformed_nst",
            encrypt_records(
                ((TLS.CONTENT_HANDSHAKE, bytes(malformed_nst), 0),)
            ),
        )
        hostile(
            "authenticated_non_nst_handshake",
            encrypt_records(
                ((TLS.CONTENT_HANDSHAKE, b"\x08\x00\x00\x00", 0),)
            ),
        )
        oversized_nsts = b"".join(build_nst(index, identity_len=80) for index in range(5))
        if len(oversized_nsts) <= 0x1E0:
            raise AssertionError("oversized NST fixture does not cross low quarantine")
        hostile(
            "authenticated_nst_record_not_contiguous",
            encrypt_records(
                ((TLS.CONTENT_HANDSHAKE, oversized_nsts, 0),)
            ),
        )

        hostile("missing_spent_ticket_marker", valid_http, marker=0)
        hostile("unspent_early_ticket_marker", valid_http, marker=2)
        hostile("wrong_operation", valid_http, operation=7)
        hostile("window_ack_failure", valid_http, ack_fail_at=0)
        hostile("tcp_receive_failure", valid_http, tcp_fail_at=0)
        hostile("fragment_ack_failure", valid_http, ack_fail_at=1)
        hostile(
            "zero_length_tcp_payload",
            valid_http,
            fragments_value=(b"",),
        )
        raw_short_record = b"\x17\x03\x03\x00\x10" + bytes(16)
        hostile("short_tls_record", (raw_short_record,))
        raw_large_record = b"\x17\x03\x03\x06\x49"
        hostile("oversized_tls_record", (raw_large_record,))
        hostile(
            "partial_tls_header",
            valid_http,
            fragments_value=(valid_http[0][:3],),
        )
        hostile(
            "partial_tls_tag",
            valid_http,
            fragments_value=fragment_bytes(valid_http[0][:-1]),
        )
        incomplete = encrypt_records(
            (
                (
                    TLS.CONTENT_APPLICATION_DATA,
                    b"HTTP/1.1 200 OK\r\nX: unfinished",
                    0,
                ),
            )
        )
        hostile("authenticated_partial_http_then_tcp_end", incomplete)

        return {
            "schema": 1,
            "gate": "real_k14_resumed_liveness_mode_low",
            "geometry": geometry,
            "fixed_after_liveness": f"0x{AFTER_LIVENESS:04x}",
            "retained_ticket_range": (
                f"0x{TICKET_PSK:04x}..0x{TICKET_END:04x}"
            ),
            "route_control_preserved": (
                f"0x{ROUTE_CONTROL_START:04x}..0x{ROUTE_CONTROL_END:04x}"
            ),
            "worker_state_scrubbed": (
                f"0x{WORKER_STATE_START:04x}..0x{WORKER_STATE_END:04x}"
            ),
            "lifecycle_preserved": (
                f"0x{LIFECYCLE_START:04x}..0x{LIFECYCLE_END:04x}"
            ),
            "quarantine_ranges": [
                f"0x{start:04x}..0x{end:04x}"
                for start, end in QUARANTINE_RANGES
            ],
            "success_record_count": 5,
            "success_nst_count": 2,
            "required_ticket_marker": 1,
            "hostile_cases": passed,
            "hostile_case_count": len(passed),
            "claims": [
                "real K14 ChaCha20-Poly1305 authenticates every TLS record",
                "HTTP/NST parsing begins only after tag success",
                "retained ticket bytes never change while later NSTs drain",
                "liveness requires and preserves the spent normal-only ticket marker 1",
                "authenticated HTTP 425 is rejected across TLS/TCP fragmentation",
                "TLS headers, ciphertext, tags, HTTP fields, and CRLFCRLF may cross arbitrary TCP/TLS seams",
                "window-open precedes receive without discarding an already-queued exact-sequence response",
                "window-open and every fully consumed TCP fragment are ACKed",
                "failure scrubs quarantine/parser state and returns only to fixed 0x0f30",
            ],
        }


def main() -> int:
    result = run_gate()
    RESULTS.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    geometry = result["geometry"]
    print(
        "resume liveness worker gate: PASS "
        f"({geometry['bytes']} bytes, {geometry['sectors']} sectors; "
        f"{result['hostile_case_count']} success/hostile cases)"
    )
    print(f"wrote {RESULTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
