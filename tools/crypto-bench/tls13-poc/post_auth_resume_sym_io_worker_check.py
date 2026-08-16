#!/usr/bin/env python3
"""Focused executable gate for the resumed TLS symmetric I/O worker."""

from __future__ import annotations

import json
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CS,
    UC_X86_REG_CX,
    UC_X86_REG_DS,
    UC_X86_REG_DI,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)

import build_live_k15 as LIVE


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "post_auth_resume_sym_io_worker.asm"
SYM_SOURCE = HERE / "tls13_sym_overlay.asm"
RESULTS = HERE / "post_auth_resume_sym_io_worker_results.json"

RAM_BYTES = 0x10000
ORIGIN = 0x0D00
MAX_BYTES = 0x0200
STACK_TOP = 0x3FF0
RETURN_SENTINEL = 0x04F0
TCP_SEND = 0x1220
WAIT_TICKS = 0x1240
DERIVE_CLIENT_APP = 0x1260
SHA256_UPDATE = 0x12A0
TRANSCRIPT_SNAPSHOT = 0x12C0
BUILD_HEAD = 0x1840
ZERO_WINDOW = 0x3564
SYM_IO = 0x39A0
SYM_INPUT_HELLO_HASH = 0x3640
SYM_SERVER_FINISHED_HASH = 0x3680
SYM_CLIENT_FINISHED_STATE = 0x3C2D
EARLY_DISPOSITION = 0x3C5C
REJECTED_FINISHED_SENT = 0x82
EARLY_EOED_HOLD = SYM_IO + 72
EARLY_EOED_BYTES = 26
TICKET_IDENTITY = 0x3B40
PROTECTED_START = 0x0600
PROTECTED_END = 0x08B6
K14_MUTABLE_START = 0x3000
K14_MUTABLE_END = 0x33F8
K14_RECORD_AEAD_START = 0x32AF
K14_RECORD_AEAD_END = K14_MUTABLE_END
DF = 1 << 10
EOED_PLAINTEXT = b"\x05\x00\x00\x00"
SERVER_FINISHED_HASH = bytes(
    (0x21 + index * 11) & 0xFF for index in range(32)
)
RETIRED_INPUT_HASH = bytes(
    (0x87 + index * 3) & 0xFF for index in range(32)
)
EOED_TRANSCRIPT_HASH = bytes(
    (0xC4 + index * 7) & 0xFF for index in range(32)
)


@dataclass(frozen=True)
class Result:
    ax: int
    carry: bool
    df: bool
    sp: int
    es: int
    events: tuple[str, ...]
    sends: tuple[bytes, ...]
    sym_io: bytes
    eoed_hold: bytes
    input_hello_hash: bytes
    server_finished_hash: bytes
    derive_hash: bytes | None
    early_disposition: int
    transcript_updates: tuple[bytes, ...]
    protected_unchanged: bool
    k14_mutable_unchanged: bool
    reached_sentinel: bool


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


def assemble(directory: Path, *, expect_success: bool = True) -> bytes:
    output = directory / "post-auth-resume-sym-io-worker.bin"
    command = [
        "nasm",
        "-f",
        "bin",
        "-DRESUME_SYM_IO_ORIGIN=0x0d00",
        "-DRESUME_SYM_IO_TCP_SEND=0x1220",
        "-DRESUME_SYM_IO_WAIT_TICKS=0x1240",
        "-DRESUME_SYM_IO_DERIVE_CLIENT_APP=0x1260",
        "-DRESUME_SYM_IO_SHA256_UPDATE=0x12a0",
        "-DRESUME_SYM_IO_TRANSCRIPT_SNAPSHOT=0x12c0",
        "-DRESUME_SYM_IO_BUILD_HEAD=0x1840",
        "-DRESUME_SYM_IO_ZERO_WINDOW=0x3564",
        "-DRESUME_SYM_IO_EARLY_DATA=1",
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
    if expect_success:
        if completed.returncode:
            raise AssertionError(
                "resumed symmetric I/O worker assembly failed:\n"
                f"{completed.stdout}{completed.stderr}"
            )
        return output.read_bytes()
    if completed.returncode == 0:
        raise AssertionError("worker assembled without its fixed service ABI")
    return b""


def assert_k14_source_geometry(directory: Path) -> None:
    """Bind the preserved interval to the current K14 overlay source."""

    image, listing = LIVE.assemble(
        directory,
        SYM_SOURCE,
        "sym_io_k14_geometry",
        ("TLS13_POC_K14",),
    )
    if image[:8] != b"T13SYM02":
        raise AssertionError("K14 symmetric overlay header drifted")
    mutable_start, mutable_end = struct.unpack_from("<HH", image, 12)
    chacha_setup = LIVE.listing_source_offset(listing, "mov di, chacha_state")
    if image[chacha_setup : chacha_setup + 1] != b"\xbf":
        raise AssertionError("K14 ChaCha-state source probe drifted")
    record_aead_start = struct.unpack_from("<H", image, chacha_setup + 1)[0]
    got = (
        mutable_start,
        mutable_end,
        record_aead_start,
        mutable_end,
    )
    expected = (
        K14_MUTABLE_START,
        K14_MUTABLE_END,
        K14_RECORD_AEAD_START,
        K14_RECORD_AEAD_END,
    )
    if got != expected:
        raise AssertionError(
            "K14 mutable/record-AEAD source geometry drifted: "
            f"got={got!r}, expected={expected!r}"
        )


def validate_image(image: bytes) -> None:
    if len(image) > MAX_BYTES:
        raise AssertionError("worker exceeds the RSD1 exact-copy slot")
    if image[2:6] != b"RSI1":
        raise AssertionError("worker header magic drifted")
    version, image_bytes, origin, entry = struct.unpack_from("<4H", image, 6)
    if (version, image_bytes, origin, entry) != (1, len(image), ORIGIN, ORIGIN):
        raise AssertionError("worker header geometry drifted")

    instructions = list(
        Cs(CS_ARCH_X86, CS_MODE_16).disasm(
            image[14:],
            ORIGIN + 14,
        )
    )
    forbidden_machine_instructions = {
        "in",
        "insb",
        "insd",
        "insw",
        "int",
        "int3",
        "into",
        "out",
        "outsb",
        "outsd",
        "outsw",
    }
    forbidden = [
        instruction.mnemonic
        for instruction in instructions
        if instruction.mnemonic in forbidden_machine_instructions
    ]
    if forbidden:
        raise AssertionError(
            f"clean worker contains forbidden direct I/O: {forbidden}"
        )
    lowered = image.lower()
    for forbidden in (
        b"authorization",
        b"user.cfg",
        b"api-key",
        b"bearer ",
    ):
        if forbidden in lowered:
            raise AssertionError(f"worker embeds forbidden literal {forbidden!r}")


def run_worker(
    image: bytes,
    operation: int,
    *,
    card_eoed: bytes | None = None,
    early_disposition: int = 1,
    finished_state: int = 0,
    input_hello_hash: bytes | None = None,
    server_finished_hash: bytes | None = None,
    send_fail: bool = False,
    build_fail: bool = False,
    build_length: int = 72,
    derive_fail: bool = False,
    zero_fail: bool = False,
    wait_carry: bool = False,
) -> Result:
    machine = Uc(UC_ARCH_X86, UC_MODE_16)
    machine.mem_map(0, RAM_BYTES)
    machine.mem_write(0, bytes([0xCC]) * RAM_BYTES)
    machine.mem_write(ORIGIN, image)
    for service in (
        TCP_SEND,
        WAIT_TICKS,
        DERIVE_CLIENT_APP,
        SHA256_UPDATE,
        TRANSCRIPT_SNAPSHOT,
        BUILD_HEAD,
        ZERO_WINDOW,
    ):
        machine.mem_write(service, b"\xC3")
    machine.mem_write(RETURN_SENTINEL, b"\xF4")

    protected = bytes(
        (0x31 + index * 17) & 0xFF
        for index in range(PROTECTED_END - PROTECTED_START)
    )
    scratch = bytes(
        (0xA7 + index * 11) & 0xFF
        for index in range(K14_MUTABLE_END - K14_MUTABLE_START)
    )
    initial_sym = bytes((0x42 + index * 7) & 0xFF for index in range(96))
    if card_eoed is None:
        card_eoed = (
            b"\x17\x03\x03\x00\x15"
            + bytes((0x71 + index * 13) & 0xFF for index in range(21))
        )
    if input_hello_hash is None:
        input_hello_hash = (
            SERVER_FINISHED_HASH if operation == 5 else RETIRED_INPUT_HASH
        )
    if server_finished_hash is None:
        server_finished_hash = (
            EOED_TRANSCRIPT_HASH if operation == 5 else SERVER_FINISHED_HASH
        )
    machine.mem_write(PROTECTED_START, protected)
    machine.mem_write(K14_MUTABLE_START, scratch)
    machine.mem_write(SYM_IO, initial_sym)
    if operation == 7:
        machine.mem_write(EARLY_EOED_HOLD, card_eoed)
    machine.mem_write(SYM_INPUT_HELLO_HASH, input_hello_hash)
    machine.mem_write(SYM_SERVER_FINISHED_HASH, server_finished_hash)
    machine.mem_write(SYM_CLIENT_FINISHED_STATE, bytes([finished_state]))
    machine.mem_write(EARLY_DISPOSITION, bytes([early_disposition]))
    machine.mem_write(
        STACK_TOP - 2,
        struct.pack("<H", RETURN_SENTINEL),
    )

    original_es = 0x0010
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_SS):
        machine.reg_write(register, 0)
    machine.reg_write(UC_X86_REG_ES, original_es)
    machine.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    machine.reg_write(UC_X86_REG_AX, operation)
    machine.reg_write(UC_X86_REG_EFLAGS, 2 | DF)

    events: list[str] = []
    sends: list[bytes] = []
    transcript_updates: list[bytes] = []
    derive_hash: bytes | None = None
    reached_sentinel = False
    head = bytes((0x90 + index * 5) & 0xFF for index in range(72))

    def send(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        events.append("send")
        pointer = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        length = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        sends.append(bytes(uc.mem_read(pointer, length)))
        set_carry(uc, send_fail)
        if len(sends) == 1:
            uc.reg_write(UC_X86_REG_ES, 0x0020)
        set_df(uc, True)

    def build(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if uc.reg_read(UC_X86_REG_EFLAGS) & DF:
            raise AssertionError("HEAD builder entered with DF set")
        if (
            uc.reg_read(UC_X86_REG_ES) & 0xFFFF
            != uc.reg_read(UC_X86_REG_DS) & 0xFFFF
        ):
            raise AssertionError("HEAD builder entered without ES=DS")
        events.append("build_head")
        if not build_fail:
            uc.mem_write(SYM_IO, head)
            uc.reg_write(UC_X86_REG_AX, build_length)
        set_carry(uc, build_fail)
        set_df(uc, True)

    def derive(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal derive_hash
        if uc.reg_read(UC_X86_REG_EFLAGS) & DF:
            raise AssertionError("client application derive entered with DF set")
        if (
            uc.reg_read(UC_X86_REG_ES) & 0xFFFF
            != uc.reg_read(UC_X86_REG_DS) & 0xFFFF
        ):
            raise AssertionError(
                "client application derive entered without ES=DS"
            )
        derive_hash = bytes(
            uc.mem_read(SYM_SERVER_FINISHED_HASH, len(SERVER_FINISHED_HASH))
        )
        events.append("derive_client_app")
        set_carry(uc, derive_fail)
        uc.reg_write(UC_X86_REG_ES, 0x0020)
        set_df(uc, True)

    def sha_update(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if uc.reg_read(UC_X86_REG_EFLAGS) & DF:
            raise AssertionError("EOED transcript update entered with DF set")
        pointer = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
        length = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        update = bytes(uc.mem_read(pointer, length))
        events.append("sha_update")
        transcript_updates.append(update)
        if update != EOED_PLAINTEXT:
            raise AssertionError("EOED transcript plaintext drifted")
        if (
            bytes(
                uc.mem_read(
                    SYM_INPUT_HELLO_HASH,
                    len(SERVER_FINISHED_HASH),
                )
            )
            != SERVER_FINISHED_HASH
        ):
            raise AssertionError(
                "server-Finished-only hash was not preserved before EOED"
            )
        set_df(uc, False)

    def snapshot(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        destination = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
        events.append("snapshot")
        if destination != SYM_SERVER_FINISHED_HASH:
            raise AssertionError("EOED transcript snapshot destination drifted")
        if transcript_updates != [EOED_PLAINTEXT]:
            raise AssertionError("EOED snapshot preceded its transcript update")
        uc.mem_write(destination, EOED_TRANSCRIPT_HASH)
        set_df(uc, False)

    def wait(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        count = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
        events.append(f"wait:{count}")
        set_carry(uc, wait_carry)
        set_df(uc, True)

    def zero(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        events.append("zero_window")
        set_carry(uc, zero_fail)
        set_df(uc, True)

    def sentinel(
        uc: Uc,
        _address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        nonlocal reached_sentinel
        reached_sentinel = True
        uc.emu_stop()

    hooks = (
        (TCP_SEND, send),
        (DERIVE_CLIENT_APP, derive),
        (SHA256_UPDATE, sha_update),
        (TRANSCRIPT_SNAPSHOT, snapshot),
        (BUILD_HEAD, build),
        (WAIT_TICKS, wait),
        (ZERO_WINDOW, zero),
        (RETURN_SENTINEL, sentinel),
    )
    for address, callback in hooks:
        machine.hook_add(
            UC_HOOK_CODE,
            callback,
            begin=address,
            end=address,
        )

    machine.emu_start(ORIGIN, RAM_BYTES, count=100_000)
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    result = Result(
        ax=machine.reg_read(UC_X86_REG_AX) & 0xFFFF,
        carry=bool(flags & 1),
        df=bool(flags & DF),
        sp=machine.reg_read(UC_X86_REG_SP) & 0xFFFF,
        es=machine.reg_read(UC_X86_REG_ES) & 0xFFFF,
        events=tuple(events),
        sends=tuple(sends),
        sym_io=bytes(machine.mem_read(SYM_IO, len(initial_sym))),
        eoed_hold=bytes(
            machine.mem_read(EARLY_EOED_HOLD, EARLY_EOED_BYTES)
        ),
        input_hello_hash=bytes(
            machine.mem_read(SYM_INPUT_HELLO_HASH, len(SERVER_FINISHED_HASH))
        ),
        server_finished_hash=bytes(
            machine.mem_read(
                SYM_SERVER_FINISHED_HASH,
                len(SERVER_FINISHED_HASH),
            )
        ),
        derive_hash=derive_hash,
        early_disposition=machine.mem_read(EARLY_DISPOSITION, 1)[0],
        transcript_updates=tuple(transcript_updates),
        protected_unchanged=(
            bytes(
                machine.mem_read(
                    PROTECTED_START,
                    PROTECTED_END - PROTECTED_START,
                )
            )
            == protected
        ),
        k14_mutable_unchanged=(
            bytes(
                machine.mem_read(
                    K14_MUTABLE_START,
                    K14_MUTABLE_END - K14_MUTABLE_START,
                )
            )
            == scratch
        ),
        reached_sentinel=reached_sentinel,
    )
    if not result.reached_sentinel:
        raise AssertionError(
            "worker did not return to its caller: "
            f"ip={machine.reg_read(UC_X86_REG_IP) & 0xFFFF:#06x}"
        )
    if result.sp != STACK_TOP:
        raise AssertionError("worker did not balance its stack")
    if result.es != original_es:
        raise AssertionError("worker did not preserve ES")
    if result.df:
        raise AssertionError("worker returned with DF set")
    if not result.protected_unchanged:
        raise AssertionError("worker changed live 0x0600..0x08b6 state")
    if not result.k14_mutable_unchanged:
        raise AssertionError("worker changed K14 0x3000..0x33f8 mutable work")
    return result


def require_success(result: Result, *, expected_ax: int = 1) -> None:
    if result.ax != expected_ax or result.carry:
        raise AssertionError(
            f"expected AX={expected_ax}/CF=0 success, got {result}"
        )


def require_failure(result: Result) -> None:
    if result.ax != 0 or not result.carry:
        raise AssertionError(f"expected closed failure, got {result}")


def main() -> None:
    with tempfile.TemporaryDirectory(
        prefix="seed-post-auth-resume-sym-io-"
    ) as temp_name:
        directory = Path(temp_name)
        assert_k14_source_geometry(directory)
        image = assemble(directory)
        validate_image(image)
        if not (
            EARLY_EOED_HOLD >= SYM_IO + 68
            and EARLY_EOED_HOLD >= SYM_IO + 58
            and EARLY_EOED_HOLD >= SYM_IO + 72
            and EARLY_EOED_HOLD + EARLY_EOED_BYTES <= TICKET_IDENTITY
        ):
            raise AssertionError("RAM-held EOED overlaps a live symmetric span")

        preload = run_worker(image, 4)
        require_success(preload)
        if preload.events or preload.sends:
            raise AssertionError(
                "accepted preload-only operation reached a fixed service"
            )
        if preload.early_disposition != 1:
            raise AssertionError("accepted preload changed its disposition")
        initial_sym = bytes(
            (0x42 + index * 7) & 0xFF for index in range(96)
        )
        if preload.sym_io != initial_sym:
            raise AssertionError("accepted preload changed sym_io")

        for disposition in (0, 2, REJECTED_FINISHED_SENT, 0xFF):
            blocked_preload = run_worker(
                image,
                4,
                early_disposition=disposition,
            )
            require_failure(blocked_preload)
            if blocked_preload.events or blocked_preload.sends:
                raise AssertionError(
                    "invalid preload disposition reached a fixed service"
                )
        for finished_state in (1, 0xFF):
            blocked_preload = run_worker(
                image,
                4,
                finished_state=finished_state,
            )
            require_failure(blocked_preload)
            if blocked_preload.events or blocked_preload.sends:
                raise AssertionError(
                    "preload continued after client Finished became live"
                )

        eoed_record = (
            b"\x17\x03\x03\x00\x15"
            + bytes((0x71 + index * 13) & 0xFF for index in range(21))
        )
        eoed = run_worker(image, 7, card_eoed=eoed_record)
        require_success(eoed)
        if eoed.events != ("sha_update", "snapshot", "send"):
            raise AssertionError("accepted-0RTT EOED service order drifted")
        if eoed.sends != (eoed_record,):
            raise AssertionError("EOED operation did not send exactly 26 bytes")
        if eoed.eoed_hold != bytes(EARLY_EOED_BYTES):
            raise AssertionError("RAM-held EOED was not scrubbed after send")
        if eoed.transcript_updates != (EOED_PLAINTEXT,):
            raise AssertionError("EOED plaintext was not appended exactly once")
        if eoed.input_hello_hash != SERVER_FINISHED_HASH:
            raise AssertionError(
                "EOED did not preserve the server-Finished-only hash"
            )
        if eoed.server_finished_hash != EOED_TRANSCRIPT_HASH:
            raise AssertionError(
                "EOED did not snapshot the client-Finished transcript"
            )

        blocked_eoed = run_worker(
            image,
            7,
            card_eoed=eoed_record,
            finished_state=1,
        )
        require_failure(blocked_eoed)
        if blocked_eoed.events or blocked_eoed.sends:
            raise AssertionError(
                "EOED read started after client Finished became live"
            )
        malformed_eoed_records = (
            b"\x16" + eoed_record[1:],
            eoed_record[:1] + b"\x03\x02" + eoed_record[3:],
            eoed_record[:3] + b"\x00\x14" + eoed_record[5:],
        )
        for malformed in malformed_eoed_records:
            malformed_eoed = run_worker(
                image,
                7,
                card_eoed=malformed,
            )
            require_failure(malformed_eoed)
            if malformed_eoed.events:
                raise AssertionError(
                    "malformed EOED reached transcript or network services"
                )
        failed_eoed_send = run_worker(
            image,
            7,
            card_eoed=eoed_record,
            send_fail=True,
        )
        require_failure(failed_eoed_send)
        if failed_eoed_send.eoed_hold != bytes(EARLY_EOED_BYTES):
            raise AssertionError("failed EOED send retained its RAM copy")

        finished = bytes((0x42 + index * 7) & 0xFF for index in range(58))
        sent = run_worker(image, 5)
        require_success(sent)
        if sent.events != (
            "send",
            "derive_client_app",
            "zero_window",
        ) or sent.sends != (finished,):
            raise AssertionError(
                "accepted-0RTT Finished/application-key schedule drifted"
            )
        if sent.derive_hash != SERVER_FINISHED_HASH:
            raise AssertionError(
                "client application keys used the EOED-inclusive transcript"
            )
        if sent.server_finished_hash != SERVER_FINISHED_HASH:
            raise AssertionError(
                "server-Finished-only transcript was not restored"
            )
        if sent.early_disposition != 1:
            raise AssertionError(
                "accepted Finished path changed its disposition"
            )
        first_send_failed = run_worker(image, 5, send_fail=True)
        require_failure(first_send_failed)
        if (
            first_send_failed.events != ("send",)
            or first_send_failed.sends != (finished,)
        ):
            raise AssertionError(
                "failed Finished send continued into application derivation"
            )
        require_failure(run_worker(image, 5, derive_fail=True))
        require_failure(run_worker(image, 5, zero_fail=True))
        no_duplicate_head = run_worker(
            image,
            5,
            build_fail=True,
            build_length=71,
            wait_carry=True,
        )
        require_success(no_duplicate_head)
        if no_duplicate_head.events != (
            "send",
            "derive_client_app",
            "zero_window",
        ):
            raise AssertionError(
                "accepted-0RTT operation re-entered the 1-RTT HEAD path"
            )

        rejected_sent = run_worker(
            image,
            5,
            early_disposition=REJECTED_FINISHED_SENT,
            send_fail=True,
        )
        require_success(rejected_sent)
        if rejected_sent.events != (
            "derive_client_app",
            "zero_window",
        ) or rejected_sent.sends:
            raise AssertionError(
                "rejected-sent path retransmitted client Finished"
            )
        if rejected_sent.derive_hash != SERVER_FINISHED_HASH:
            raise AssertionError(
                "rejected-sent client app used the wrong transcript"
            )
        if rejected_sent.early_disposition != 2:
            raise AssertionError(
                "rejected-sent disposition was not normalized to 2"
            )

        rejected_derive_failed = run_worker(
            image,
            5,
            early_disposition=REJECTED_FINISHED_SENT,
            derive_fail=True,
        )
        require_failure(rejected_derive_failed)
        if (
            rejected_derive_failed.events != ("derive_client_app",)
            or rejected_derive_failed.sends
            or rejected_derive_failed.early_disposition
            != REJECTED_FINISHED_SENT
        ):
            raise AssertionError(
                "rejected-sent derive failure crossed its authority boundary"
            )
        rejected_zero_failed = run_worker(
            image,
            5,
            early_disposition=REJECTED_FINISHED_SENT,
            zero_fail=True,
        )
        require_failure(rejected_zero_failed)
        if (
            rejected_zero_failed.events
            != ("derive_client_app", "zero_window")
            or rejected_zero_failed.sends
            or rejected_zero_failed.early_disposition
            != REJECTED_FINISHED_SENT
        ):
            raise AssertionError(
                "rejected-sent zero-window failure published disposition 2"
            )

        for disposition in (0, 2, 3, 0x81, 0x83, 0xFF):
            invalid_disposition = run_worker(
                image,
                5,
                early_disposition=disposition,
            )
            require_failure(invalid_disposition)
            if (
                invalid_disposition.events
                or invalid_disposition.sends
                or invalid_disposition.early_disposition != disposition
            ):
                raise AssertionError(
                    "invalid Finished disposition reached a fixed service"
                )

        head = bytes((0x90 + index * 5) & 0xFF for index in range(72))
        head_result = run_worker(image, 6)
        require_success(head_result)
        if head_result.events != (
            "build_head",
            "send",
            "wait:1",
            "zero_window",
        ):
            raise AssertionError("HEAD dialogue order drifted")
        if head_result.sends != (head,):
            raise AssertionError("HEAD operation did not send exactly 72 bytes")

        incidental_carry = run_worker(image, 6, wait_carry=True)
        require_success(incidental_carry)
        if incidental_carry.events[-1] != "zero_window":
            raise AssertionError("wait_ticks incidental carry became authority")

        require_failure(run_worker(image, 6, build_fail=True))
        require_failure(run_worker(image, 6, build_length=71))
        require_failure(run_worker(image, 6, build_length=73))
        require_failure(run_worker(image, 6, send_fail=True))
        require_failure(run_worker(image, 6, zero_fail=True))

        for invalid in (0, 1, 3, 8, 0xFFFF):
            result = run_worker(image, invalid)
            require_failure(result)
            if result.events or result.sends:
                raise AssertionError("invalid selector reached a fixed service")

        # Missing fixed service definitions must be a build-time failure.
        bare_output = directory / "bare.bin"
        bare = subprocess.run(
            [
                "nasm",
                "-f",
                "bin",
                "-o",
                str(bare_output),
                str(SOURCE),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if bare.returncode == 0:
            raise AssertionError("worker assembled without fixed service definitions")

    report = {
        "status": "pass",
        "worker": {
            "bytes": len(image),
            "limit": MAX_BYTES,
            "operations": [4, 5, 6, 7],
        },
        "preservation": {
            "resident_range": [PROTECTED_START, PROTECTED_END],
            "k14_mutable_range": [K14_MUTABLE_START, K14_MUTABLE_END],
            "k14_record_aead_subspan": [
                K14_RECORD_AEAD_START,
                K14_RECORD_AEAD_END,
            ],
            "k14_bounds_source_derived": True,
            "stack_es_df": True,
        },
        "coverage": {
            "accepted_preload_only": True,
            "accepted_early_data_eoed": True,
            "ram_held_eoed_nonoverlap_and_scrub": True,
            "accepted_and_rejected_finished_paths": True,
            "compatibility_head": True,
            "invalid_dispositions_fail_closed": True,
            "missing_fixed_services_fail_build": True,
        },
    }
    RESULTS.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("post-auth resumed symmetric I/O worker: PASS")
    print(
        f"  bytes={len(image)}/{MAX_BYTES} shared operations=4,5,6,7"
    )
    print(
        "  operation4=accepted disposition/state preload-only; "
        "operation7=RAM-held EOED26 -> transcript append/snapshot -> send/scrub; "
        "operation5=accepted Finished58 / rejected-sent skip -> restore "
        "server-Finished hash -> client-app derive -> zero-window; "
        "operation6=1-RTT HEAD-only compatibility"
    )
    print(
        "  invalid preload/Finished dispositions fail closed; rejected-sent "
        "normalizes 0x82 -> 2 only after derive/zero-window; "
        "stack/ES/DF and 0x0600..0x08b6 plus "
        "K14 0x3000..0x33f8 preservation=PASS "
        "(record AEAD 0x32af..0x33f8)"
    )


if __name__ == "__main__":
    main()
