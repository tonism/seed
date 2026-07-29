#!/usr/bin/env python3
"""Executable hostile gate for the same-boot resumed deferred-FO worker."""

from __future__ import annotations

import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BP,
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
SOURCE = HERE / "post_auth_resume_fo_worker.asm"

RAM_BYTES = 0x10000
BROKER_ORIGIN = 0x3000
CONTROLLER_ORIGIN = 0x2400
STACK_TOP = 0x3FF0
RETURN_SENTINEL = 0x04F0
DF = 1 << 10

LOAD_PHASE = 0x1200
CARD_READ = 0x1210
CARD_WRITE = 0x1220
FO_COMPLETE = 0x1100

CONTROLLER_KEY = 0x0330
FO_KEY = 0x0665
SYM_KEY = 0x0855
RECOVERY_KEY = 0x012F
RSU_HEAD_KEY = 0x0170
RSU_TAIL_KEY = 0x0171
SUPERVISOR_KEY = 0x0272
RECOVERY_FAIL = 0x35D9

NIC_BASE = 0x060E
NE_TX_START = 0x06CB
FO_ENTRY = 0x1800
PERSISTENT_START = 0x3510
PERSISTENT_END = 0x3600

RSU_LOW_START = 0x0900
RSU_LOW_BYTES = 544
RSU_PREFIX_START = 0x0B20
RSU_PREFIX_BYTES = 271
RSU_SUFFIX_START = 0x0C30
RSU_SUFFIX_BYTES = 156
TRANSITION_SOURCE = 0x3200
TRANSITION_DEST = 0x0F00
TRANSITION_BYTES = 128

LIFECYCLE_GENERATION = 0x3C96
LIFECYCLE_INVERSE = 0x3C98
LIFECYCLE_STATUS = 0x3C99
CANDIDATE_GENERATION = 0x3C66
CANDIDATE_C_SUM = 0x3C68
CANDIDATE_EK_SUM = 0x3C6A
CANDIDATE_INVERSE = 0x3C6C
CANDIDATE_STATUS = 0x3C6D
FO_GENERATION = 0x3C6E
FO_C_SUM = 0x3C70
FO_EK_SUM = 0x3C72
FO_INVERSE = 0x3C74
FO_STATUS = 0x3C75

CARD_HEAD = 0x7300
CARD_EK = 0x7400
CARD_C = 0x7900
CARD_CANDIDATE_A = 0x7E00
CARD_CANDIDATE_B = 0x7E80
CARD_TAIL = 0x7F00
CARD_TICKET_MARKER = CARD_TAIL + 82 + 44
EK_LEN = 1184
C_LEN = 1088

TICKET_PSK = 0x38B0
TICKET_IDENTITY = 0x3B40
TICKET_TAIL = 0x3C00
TICKET_PRESENT = 0x3C2C
EXPECTED_K = 0x0700
FO_MESSAGE = 0x3A40
FO_CANDIDATE_G = 0x3B9C

COMMON_DEFINES = (
    f"RESUME_FO_LOAD_PHASE=0x{LOAD_PHASE:04x}",
    f"RESUME_FO_NE_BUF_READ=0x{CARD_READ:04x}",
    f"RESUME_FO_NE_BUF_LOAD=0x{CARD_WRITE:04x}",
    f"RESUME_FO_NIC_BASE=0x{NIC_BASE:04x}",
    f"RESUME_FO_NE_TX_START=0x{NE_TX_START:04x}",
)

FO_READS = (
    (0, 1152, 32),
    (0, 0, 384),
    (0, 384, 384),
    (0, 768, 384),
    (1, 0, 320),
    (1, 320, 320),
    (1, 640, 320),
    (1, 960, 128),
    (1, 0, 104),
    (1, 104, 136),
    (1, 240, 136),
    (1, 376, 136),
    (1, 512, 136),
    (1, 648, 136),
    (1, 784, 136),
    (1, 920, 136),
    (1, 1056, 32),
)


@dataclass(frozen=True)
class Images:
    broker: bytes
    controller: bytes
    fo_stub: bytes
    rsu: bytes
    supervisor: bytes
    transition: bytes


@dataclass(frozen=True)
class Fixture:
    generation: int
    ek: bytes
    c: bytes
    candidate: bytes
    persistent: bytes
    psk: bytes
    identity: bytes
    ticket_tail: bytes
    head: bytes
    tail: bytes


@dataclass(frozen=True)
class Result:
    ax: int
    carry: bool
    sp: int
    es: int
    df: bool
    ram: bytes
    card: bytes
    events: tuple[str, ...]
    reached_sentinel: bool
    terminal_recovery: bool
    terminal_halt: bool


def set_carry(machine: Uc, enabled: bool) -> None:
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    machine.reg_write(
        UC_X86_REG_EFLAGS,
        (flags | 1) if enabled else (flags & ~1),
    )


def padded(value: bytes, sectors: int | None = None) -> bytes:
    count = (-len(value)) % 512
    result = value + bytes(count)
    if sectors is not None:
        if len(result) > sectors * 512:
            raise AssertionError("phase exceeds fixed sector reservation")
        result += bytes(sectors * 512 - len(result))
    return result


def assemble(directory: Path, stem: str, defines: tuple[str, ...]) -> bytes:
    output = directory / f"{stem}.bin"
    command = [
        "nasm",
        "-f",
        "bin",
        "-I",
        str(HERE) + "/",
        *[f"-D{define}" for define in (*COMMON_DEFINES, *defines)],
        "-o",
        str(output),
        str(SOURCE),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        raise AssertionError(
            f"{stem} assembly failed:\n{completed.stdout}{completed.stderr}"
        )
    return output.read_bytes()


def make_fo_stub() -> bytes:
    code = bytearray()
    for obj, offset, count in FO_READS:
        code.extend((0xB0, obj))
        code.extend((0xBA, offset & 0xFF, offset >> 8))
        code.extend((0xB9, count & 0xFF, count >> 8))
        code.extend((0xBF, 0x50, 0x0E))
        code.extend((0xFF, 0xD3))  # call bx
        code.extend((0x73, 0x04))  # jnc past fixed rejection
        code.extend((0x31, 0xC0, 0xF9, 0xC3))
    displacement = (FO_COMPLETE - (FO_ENTRY + len(code) + 3)) & 0xFFFF
    code.extend((0xE8, displacement & 0xFF, displacement >> 8))
    code.extend((0xB8, 0x01, 0x00, 0xF8, 0xC3))
    if len(code) > 512:
        raise AssertionError("synthetic FO driver exceeds one sector")
    return bytes(code)


def build_images(directory: Path) -> Images:
    controller = assemble(
        directory,
        "resume-fo-controller",
        (
            "RESUME_FO_CONTROLLER",
            f"RESUME_FO_KERNEL_KEY=0x{FO_KEY:04x}",
            f"RESUME_FO_KERNEL_ENTRY=0x{FO_ENTRY:04x}",
            f"RESUME_FO_SYM_RESTORE_KEY=0x{SYM_KEY:04x}",
            f"RESUME_FO_RECOVERY_KEY=0x{RECOVERY_KEY:04x}",
            f"RESUME_FO_RECOVERY_FAIL=0x{RECOVERY_FAIL:04x}",
            f"RESUME_FO_RSU_HEAD_KEY=0x{RSU_HEAD_KEY:04x}",
            f"RESUME_FO_RSU_TAIL_KEY=0x{RSU_TAIL_KEY:04x}",
            f"RESUME_FO_RSU_LOW_BYTES={RSU_LOW_BYTES}",
            f"RESUME_FO_RSU_LOW_START=0x{RSU_LOW_START:04x}",
            f"RESUME_FO_RSU_PREFIX_BYTES={RSU_PREFIX_BYTES}",
            f"RESUME_FO_RSU_PREFIX_START=0x{RSU_PREFIX_START:04x}",
            f"RESUME_FO_RSU_SUFFIX_BYTES={RSU_SUFFIX_BYTES}",
            f"RESUME_FO_RSU_SUFFIX_START=0x{RSU_SUFFIX_START:04x}",
            f"RESUME_FO_SUPERVISOR_KEY=0x{SUPERVISOR_KEY:04x}",
            (
                "RESUME_FO_SUPERVISOR_TRANSITION_SOURCE="
                f"0x{TRANSITION_SOURCE:04x}"
            ),
            f"RESUME_FO_SUPERVISOR_TRANSITION_BYTES={TRANSITION_BYTES}",
            (
                "RESUME_FO_SUPERVISOR_TRANSITION_DEST="
                f"0x{TRANSITION_DEST:04x}"
            ),
        ),
    )
    broker = assemble(
        directory,
        "resume-fo-broker",
        (
            "RESUME_FO_BROKER",
            f"RESUME_FO_CONTROLLER_KEY=0x{CONTROLLER_KEY:04x}",
            f"RESUME_FO_CONTROLLER_ENTRY=0x{CONTROLLER_ORIGIN:04x}",
        ),
    )
    low = bytes((0x31 + index * 7) & 0xFF for index in range(RSU_LOW_BYTES))
    prefix = bytes(
        (0x53 + index * 11) & 0xFF for index in range(RSU_PREFIX_BYTES)
    )
    suffix = bytes(
        (0x79 + index * 13) & 0xFF for index in range(RSU_SUFFIX_BYTES)
    )
    rsu = low + prefix + suffix
    transition = bytes(
        (0xA7 + index * 19) & 0xFF for index in range(TRANSITION_BYTES)
    )
    supervisor = bytearray(1024)
    offset = TRANSITION_SOURCE - 0x3000
    supervisor[offset : offset + TRANSITION_BYTES] = transition
    return Images(
        broker=broker,
        controller=controller,
        fo_stub=make_fo_stub(),
        rsu=rsu,
        supervisor=bytes(supervisor),
        transition=transition,
    )


def validate_images(images: Images) -> None:
    for label, image, magic, origin, limit in (
        ("broker", images.broker, b"RFB1", BROKER_ORIGIN, 512),
        ("controller", images.controller, b"RFC1", CONTROLLER_ORIGIN, 1536),
    ):
        if len(image) > limit or image[2:6] != magic:
            raise AssertionError(f"{label} size/header geometry drifted")
        version, size, linked, entry = struct.unpack_from("<4H", image, 6)
        if (version, size, linked, entry) != (1, len(image), origin, origin):
            raise AssertionError(f"{label} measured header drifted")
    if len(padded(images.controller)) != 3 * 512:
        raise AssertionError("controller is not an exact three-sector phase")


def word_sum(value: bytes) -> int:
    return sum(struct.unpack(f"<{len(value) // 2}H", value)) & 0xFFFF


def make_fixture() -> Fixture:
    generation = 0x3456
    ek = bytes((0x17 + index * 29) & 0xFF for index in range(EK_LEN))
    c = bytes((0x2B + index * 31) & 0xFF for index in range(C_LEN))
    candidate = bytes(
        (0x41 + index * 23) & 0xFF for index in range(128)
    )
    persistent = bytes(
        (0x63 + index * 17) & 0xFF
        for index in range(PERSISTENT_END - PERSISTENT_START)
    )
    psk = bytes((0x85 + index * 9) & 0xFF for index in range(32))
    identity = bytes((0xA1 + index * 5) & 0xFF for index in range(192))
    ticket_tail = bytearray(
        (0xC3 + index * 3) & 0xFF for index in range(45)
    )
    ticket_tail[-1] = 2
    head = bytearray(256)
    head[:114] = bytes((0xD7 + index) & 0xFF for index in range(114))
    head[114:146] = psk
    head[146:256] = identity[:110]
    tail = bytearray(256)
    tail[:82] = identity[110:]
    tail[82:127] = ticket_tail
    tail[127:143] = bytes((0xE1 + index) & 0xFF for index in range(16))
    tail[143] = 0
    tail[0x90:0x94] = b"RVL1"
    tail[0x94:0x98] = bytes(value ^ 0xFF for value in b"RVL1")
    tail[0x98:0x9A] = struct.pack("<H", generation)
    tail[0x9A:0xBA] = bytes((0x37 + index) & 0xFF for index in range(32))
    tail[0xBA:0xDA] = bytes((0x59 + index) & 0xFF for index in range(32))
    tail[0xDA:0xFA] = bytes((0x7B + index) & 0xFF for index in range(32))
    tail[0xFA:0xFE] = bytes(4)
    tail[0xFE:0x100] = b"\x5a\xa5"
    return Fixture(
        generation,
        ek,
        c,
        candidate,
        persistent,
        psk,
        identity,
        bytes(ticket_tail),
        bytes(head),
        bytes(tail),
    )


def run(
    images: Images,
    fixture: Fixture,
    *,
    invalid_lifecycle: bool = False,
    corrupt_candidate: bool = False,
    corrupt_backup: bool = False,
    corrupt_public: bool = False,
    wrong_selected: bool = False,
    fail_post_backup_read: bool = False,
    fail_wipe: bool = False,
    fail_load_key: int | None = None,
    fail_recovery_load: bool = False,
    host_ticket_marker: int = 1,
    card_ticket_marker: int = 2,
) -> Result:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes([0xCC]) * RAM_BYTES)
    machine.mem_write(BROKER_ORIGIN, padded(images.broker, 1))
    for address in (
        LOAD_PHASE,
        CARD_READ,
        CARD_WRITE,
        FO_COMPLETE,
        RECOVERY_FAIL,
        RETURN_SENTINEL,
    ):
        machine.mem_write(address, b"\xC3")
    machine.mem_write(NIC_BASE, struct.pack("<H", 0x300))
    machine.mem_write(NE_TX_START, b"\x40")
    machine.mem_write(PERSISTENT_START, fixture.persistent)
    machine.mem_write(TICKET_PRESENT, bytes([host_ticket_marker]))
    machine.mem_write(
        LIFECYCLE_GENERATION,
        struct.pack("<H", fixture.generation),
    )
    machine.mem_write(
        LIFECYCLE_INVERSE,
        b"\x00\x00" if invalid_lifecycle else b"\x5a\xa5",
    )
    publication = struct.pack(
        "<3H",
        fixture.generation,
        word_sum(fixture.c),
        word_sum(fixture.ek),
    ) + b"\x5a\xa5"
    machine.mem_write(CANDIDATE_GENERATION, publication)
    machine.mem_write(RETURN_SENTINEL, b"\xF4")
    machine.mem_write(
        STACK_TOP - 2,
        struct.pack("<H", RETURN_SENTINEL),
    )

    card = bytearray(0x10000)
    card[CARD_HEAD : CARD_HEAD + 256] = fixture.head
    card[CARD_TAIL : CARD_TAIL + 256] = fixture.tail
    card[CARD_TICKET_MARKER] = card_ticket_marker
    card[CARD_EK : CARD_EK + EK_LEN] = fixture.ek
    card[CARD_C : CARD_C + C_LEN] = fixture.c
    card[CARD_CANDIDATE_A : CARD_CANDIDATE_A + 128] = fixture.candidate
    card[CARD_CANDIDATE_B : CARD_CANDIDATE_B + 128] = fixture.candidate
    if corrupt_candidate:
        card[CARD_CANDIDATE_B + 63] ^= 1
    if corrupt_public:
        card[CARD_C + 511] ^= 1

    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_ES, 0x0010)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_AX, 7)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | DF)

    rsu_head = padded(images.rsu[:512], 1)
    rsu_tail = padded(images.rsu[512:], 1)
    recovery = bytearray(512)
    recovery[RECOVERY_FAIL - 0x3400] = 0xC3
    phases = {
        CONTROLLER_KEY: padded(images.controller, 3),
        FO_KEY: padded(images.fo_stub, 6),
        SYM_KEY: bytes([0x6D]) * (8 * 512),
        RSU_HEAD_KEY: rsu_head,
        RSU_TAIL_KEY: rsu_tail,
        SUPERVISOR_KEY: images.supervisor,
        RECOVERY_KEY: bytes(recovery),
    }
    events: list[str] = []
    reached_sentinel = False
    terminal_recovery = False
    terminal_halt = False
    fo_started = False
    page7e_writes = 0

    def loader(uc: Uc, *_args: object) -> None:
        key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        events.append(f"load:{key:04x}:{destination:04x}")
        if (
            key == fail_load_key
            or (key == RECOVERY_KEY and fail_recovery_load)
        ):
            set_carry(uc, True)
            uc.reg_write(UC_X86_REG_DX, 0xDEAD)
            return
        image = phases.get(key)
        if image is None:
            set_carry(uc, True)
            uc.reg_write(UC_X86_REG_DX, 0xDEAD)
            return
        uc.mem_write(destination, image)
        uc.ctl_remove_cache(destination, destination + len(image))
        set_carry(uc, False)
        uc.reg_write(UC_X86_REG_DX, 0xDEAD)

    def card_read(uc: Uc, *_args: object) -> None:
        source = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        destination = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
        events.append(f"read:{source:04x}:{count}")
        if fail_post_backup_read and fo_started and source == CARD_CANDIDATE_A:
            set_carry(uc, True)
            return
        uc.mem_write(destination, bytes(card[source : source + count]))
        set_carry(uc, False)

    def card_write(uc: Uc, *_args: object) -> None:
        nonlocal page7e_writes
        page = bytes(uc.mem_read(NE_TX_START, 1))[0]
        destination = page << 8
        source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
        if destination == CARD_CANDIDATE_A:
            page7e_writes += 1
        events.append(f"write:{destination:04x}:{count}")
        if fail_wipe and destination == CARD_CANDIDATE_A and page7e_writes == 3:
            set_carry(uc, True)
            return
        card[destination : destination + count] = uc.mem_read(source, count)
        if corrupt_backup and page7e_writes == 2:
            card[destination + 17] ^= 1
        set_carry(uc, False)

    def fo_begin(uc: Uc, *_args: object) -> None:
        nonlocal fo_started
        fo_started = True
        events.append("fo:begin")
        uc.mem_write(0x0830, bytes([0xF1]) * (0x0FD0 - 0x0830))
        uc.mem_write(0x3000, bytes([0xF2]) * (0x3600 - 0x3000))
        uc.ctl_remove_cache(0x3000, 0x3600)

    def fo_complete(uc: Uc, *_args: object) -> None:
        selected = bytearray(fixture.candidate[32:64])
        if wrong_selected:
            selected[0] ^= 1
        uc.mem_write(FO_CANDIDATE_G, bytes(selected))
        events.append("fo:complete")
        set_carry(uc, False)

    def recovery_fail_hook(uc: Uc, *_args: object) -> None:
        nonlocal terminal_recovery
        terminal_recovery = True
        events.append("terminal:recovery")
        uc.emu_stop()

    def sentinel(uc: Uc, *_args: object) -> None:
        nonlocal reached_sentinel
        reached_sentinel = True
        uc.emu_stop()

    def publication_write(
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user_data: object,
    ) -> None:
        if size == 1 and address == FO_INVERSE:
            events.append(f"publish:inverse:{value & 0xff:02x}")
        elif size == 1 and address == FO_STATUS:
            events.append(f"publish:status:{value & 0xff:02x}")

    for address, callback in (
        (LOAD_PHASE, loader),
        (CARD_READ, card_read),
        (CARD_WRITE, card_write),
        (FO_ENTRY, fo_begin),
        (FO_COMPLETE, fo_complete),
        (RECOVERY_FAIL, recovery_fail_hook),
        (RETURN_SENTINEL, sentinel),
    ):
        machine.hook_add(UC_HOOK_CODE, callback, begin=address, end=address)
    machine.hook_add(
        UC_HOOK_MEM_WRITE,
        publication_write,
        begin=FO_INVERSE,
        end=FO_STATUS,
    )

    try:
        machine.emu_start(BROKER_ORIGIN, RAM_BYTES, count=2_000_000)
    except UcError as exc:
        ip = machine.reg_read(UC_X86_REG_IP) & 0xFFFF
        # CLI/HLT is the deliberate final fallback when recovery media fails.
        if fail_recovery_load and 0x2400 <= ip < 0x2A00:
            terminal_halt = True
        else:
            raise AssertionError(
                f"resumption FO faulted at {ip:#06x}; events={events!r}"
            ) from exc
    if (
        fail_recovery_load
        and not reached_sentinel
        and not terminal_recovery
        and f"load:{RECOVERY_KEY:04x}:3400" in events
    ):
        # Unicorn treats the deliberate CLI/HLT fallback as a clean stop.
        terminal_halt = True
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    return Result(
        ax=machine.reg_read(UC_X86_REG_AX) & 0xFFFF,
        carry=bool(flags & 1),
        sp=machine.reg_read(UC_X86_REG_SP) & 0xFFFF,
        es=machine.reg_read(UC_X86_REG_ES) & 0xFFFF,
        df=bool(flags & DF),
        ram=bytes(machine.mem_read(0, RAM_BYTES)),
        card=bytes(card),
        events=tuple(events),
        reached_sentinel=reached_sentinel,
        terminal_recovery=terminal_recovery,
        terminal_halt=terminal_halt,
    )


def assert_normal(result: Result, *, success: bool) -> None:
    if not result.reached_sentinel or result.terminal_recovery:
        raise AssertionError("FO did not return through the normal RSU1 edge")
    if result.sp != STACK_TOP or result.es != 0x0010 or result.df:
        raise AssertionError("FO normal return ABI drifted")
    if success:
        if result.ax != 1 or result.carry:
            raise AssertionError("FO success did not return AX=1/CF=0")
    elif result.ax != 0 or not result.carry:
        raise AssertionError("FO preflight rejection did not return AX=0/CF=1")


def assert_terminal(result: Result) -> None:
    if result.reached_sentinel:
        raise AssertionError("post-FO failure returned through overwritten RSU1")
    if not (result.terminal_recovery or result.terminal_halt):
        raise AssertionError("post-FO failure missed both terminal recovery paths")
    if result.ram[FO_STATUS] != 0:
        raise AssertionError("terminal FO failure published valid status")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="seed-resume-fo-") as name:
        images = build_images(Path(name))
        validate_images(images)
        fixture = make_fixture()

        success = run(images, fixture)
        assert_normal(success, success=True)
        expected_publication = struct.pack(
            "<3H",
            fixture.generation,
            word_sum(fixture.c),
            word_sum(fixture.ek),
        ) + b"\x5a\xa5"
        if success.ram[FO_GENERATION : FO_STATUS + 1] != expected_publication:
            raise AssertionError("FO proof publication differs from fresh ek/c")
        if success.ram[PERSISTENT_START:PERSISTENT_END] != fixture.persistent:
            raise AssertionError("K14 extension state was not restored exactly")
        if success.ram[TICKET_PSK : TICKET_PSK + 32] != fixture.psk:
            raise AssertionError("tentative ticket PSK was not restored")
        if success.ram[TICKET_IDENTITY : TICKET_IDENTITY + 192] != fixture.identity:
            raise AssertionError("tentative ticket identity was not restored")
        expected_host_tail = fixture.ticket_tail[:-1] + b"\x01"
        if (
            success.ram[TICKET_TAIL : TICKET_TAIL + 45]
            != expected_host_tail
        ):
            raise AssertionError(
                "tentative ticket body/one-shot host marker was not restored"
            )
        if success.ram[TICKET_PRESENT] != 1:
            raise AssertionError("spent liveness ticket marker was not preserved")
        if success.card[CARD_TICKET_MARKER] != 2:
            raise AssertionError("canonical card ticket marker was not preserved")
        if any(success.card[CARD_CANDIDATE_A:CARD_TAIL]):
            raise AssertionError("retired candidate/K14-backup page was not wiped")

        low = images.rsu[:RSU_LOW_BYTES]
        prefix_start = RSU_LOW_BYTES
        prefix = images.rsu[prefix_start : prefix_start + RSU_PREFIX_BYTES]
        suffix = images.rsu[prefix_start + RSU_PREFIX_BYTES :]
        if success.ram[RSU_LOW_START : RSU_LOW_START + RSU_LOW_BYTES] != low:
            raise AssertionError("RSU1 low span was not restored")
        if (
            success.ram[
                RSU_PREFIX_START : RSU_PREFIX_START + RSU_PREFIX_BYTES
            ]
            != prefix
        ):
            raise AssertionError("RSU1 prefix was not restored")
        if (
            success.ram[
                RSU_SUFFIX_START : RSU_SUFFIX_START + RSU_SUFFIX_BYTES
            ]
            != suffix
        ):
            raise AssertionError("RSU1 suffix was not restored")
        if (
            success.ram[TRANSITION_DEST : TRANSITION_DEST + TRANSITION_BYTES]
            != images.transition
        ):
            raise AssertionError("outer after-liveness transition was not restored")
        if success.ram[EXPECTED_K : EXPECTED_K + 32] != bytes(32):
            raise AssertionError("independent expected K' survived normal return")
        if success.ram[FO_MESSAGE : FO_MESSAGE + 32] != bytes(32):
            raise AssertionError("retired m' survived normal return")

        required_order = (
            "write:7e00:256",
            "fo:begin",
            "fo:complete",
            f"load:{RSU_TAIL_KEY:04x}:3000",
            f"load:{SUPERVISOR_KEY:04x}:3000",
            f"load:{SYM_KEY:04x}:1800",
            "publish:inverse:5a",
            "publish:status:a5",
        )
        positions = [success.events.index(event) for event in required_order]
        if positions != sorted(positions) or len(set(positions)) != len(positions):
            raise AssertionError("FO backup/restore/status order drifted")

        for kwargs in (
            {"invalid_lifecycle": True},
            {"corrupt_candidate": True},
            {"corrupt_backup": True},
        ):
            rejected = run(images, fixture, **kwargs)
            assert_normal(rejected, success=False)
            if "fo:begin" in rejected.events:
                raise AssertionError("preflight rejection entered FO")

        for host_ticket_marker in (0, 2, 3, 0xFF):
            rejected = run(
                images,
                fixture,
                host_ticket_marker=host_ticket_marker,
            )
            assert_normal(rejected, success=False)
            if "fo:begin" in rejected.events:
                raise AssertionError(
                    "non-spent host ticket marker entered deferred FO"
                )

        terminal_cases = (
            {"corrupt_public": True},
            {"wrong_selected": True},
            {"fail_post_backup_read": True},
            {"fail_wipe": True},
            {"fail_load_key": RSU_TAIL_KEY},
            {"fail_load_key": RSU_HEAD_KEY},
            {"fail_load_key": SUPERVISOR_KEY},
            {"fail_load_key": SYM_KEY},
        )
        for kwargs in terminal_cases:
            failed = run(images, fixture, **kwargs)
            assert_terminal(failed)

        for card_ticket_marker in (0, 1, 3, 0xFF):
            failed = run(
                images,
                fixture,
                card_ticket_marker=card_ticket_marker,
            )
            assert_terminal(failed)

        halted = run(
            images,
            fixture,
            wrong_selected=True,
            fail_recovery_load=True,
        )
        assert_terminal(halted)

        print(
            "post-auth resumption deferred-FO worker gate: PASS "
            f"(broker={len(images.broker)} controller={len(images.controller)} "
            "bytes; host marker 1/card marker 2 plus "
            "real clobber/backup/RSU/sym/recovery hostile cases)"
        )


if __name__ == "__main__":
    main()
