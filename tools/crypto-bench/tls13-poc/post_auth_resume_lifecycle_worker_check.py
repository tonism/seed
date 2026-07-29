#!/usr/bin/env python3
"""Executable gate for NTR1 capture and RVL1 lifecycle operations."""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
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

import build_live_k15 as LIVE


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RECEIPT_SOURCE = HERE / "post_auth_resume_receipt_worker.asm"
LIFECYCLE_SOURCE = HERE / "post_auth_resume_lifecycle_worker.asm"
CONTROLLERS_SOURCE = HERE / "live_k15_controllers.asm"
SYM_SOURCE = HERE / "tls13_sym_overlay.asm"

RAM_BYTES = 0x10000
RECEIPT_ORIGIN = 0x3400
LIFECYCLE_ORIGIN = 0x3000
RETURN_SENTINEL = 0x3E00
STACK_TOP = 0x3F00
FO_ENTRY = 0x2400
PERSIST_FAIL = 0x35D9
LOAD_PHASE = 0x10C4
NE_WRITE = 0x1724
NE_READ = 0x175B
SHA_INIT = 0x25A6
SHA_UPDATE = 0x25C6
SHA_FINISH = 0x25FC
SCRUB_ENTRY = 0x2432
GATE_VALIDATE = 0x197B

SYM_KEY = 0x0855
FO_KEY = 0x0137
SCRUB_KEY = 0x0138
GATE_KEY = 0x02A0
RECEIPT_KEY = 0x02A2
LIFECYCLE_KEY = 0x02A3
RECEIPT_HASH_KEY = 0x01A4
VAULT_HASH_KEY = 0x01A5

NIC_BASE = 0x060E
NE_TX_START = 0x06CB
RECEIPT_BUILD = 0x0700
HEAD_BUFFER = 0x0D00
TAIL_BUFFER = 0x0E00
HASH_STAGE = 0x2400
HASH_ORIGIN = 0x3400
HASH_LIMIT = 0x3510
K14_MUTABLE_START = 0x3000
K14_MUTABLE_END = 0x33F8
K14_RECORD_AEAD_START = 0x32AF
K14_RECORD_AEAD_END = K14_MUTABLE_END

ISSUER = 0x3600
PSK = 0x38B0
IDENTITY = 0x3B40
TICKET_TAIL = 0x3C00
CONTROL = 0x3C30
LIFECYCLE_DIGEST = 0x3C76
LIFECYCLE_GENERATION = 0x3C96
LIFECYCLE_INVERSE = 0x3C98
LIFECYCLE_STATUS = 0x3C99
LIFECYCLE_END = 0x3C9A
LIFECYCLE_PREFILL = 0xD7

CARD_HEAD = 0x7300
CARD_TAIL = 0x7F00
GENERATION = 0x4D21

NTR_MAGIC = b"NTR1"
NTR_INVERSE = bytes(byte ^ 0xFF for byte in NTR_MAGIC)
NTR_DIGEST = 0x0E
NTR_ZERO = 0x2E
NTR_INV_STATUS = 0xFE
NTR_STATUS = 0xFF

RVL_CANONICAL_END = 0x90
RVL_MAGIC = 0x90
RVL_INVERSE = 0x94
RVL_GENERATION = 0x98
RVL_DIGEST = 0x9A
RVL_RANDOM = 0xBA
RVL_SESSION = 0xDA
RVL_PAD = 0xFA
RVL_INV_STATUS = 0xFE
RVL_STATUS = 0xFF


# Populated by main after all three lifecycle images have been assembled.
# key -> (fixed destination, padded sector count, measured image)
LIFECYCLE_PHASE_IMAGES: dict[int, tuple[int, int, bytes]] = {}


@dataclass(frozen=True)
class Header:
    magic: bytes
    version: int
    image_bytes: int
    entry: int


@dataclass(frozen=True)
class Fixture:
    issuer: bytes
    psk: bytes
    identity: bytes
    ticket_tail: bytes
    control: bytes

    @property
    def native_ticket(self) -> bytes:
        return self.psk + self.identity + self.ticket_tail

    @property
    def canonical(self) -> bytes:
        return self.issuer + self.psk + self.identity + self.ticket_tail + self.control + b"\0"


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def assemble(
    source: Path,
    output: Path,
    listing: Path,
    defines: dict[str, int],
) -> bytes:
    command = [
        "nasm",
        "-f",
        "bin",
        f"-I{HERE}/",
        f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
    ]
    for name, value in defines.items():
        command.append(f"-D{name}=0x{value:x}")
    command.extend(["-l", str(listing), "-o", str(output), str(source)])
    run(command)
    return output.read_bytes()


def assert_k14_source_geometry(build: Path) -> None:
    """Bind lifecycle poison bounds to the current K14 overlay source."""

    image, listing = LIVE.assemble(
        build,
        SYM_SOURCE,
        "lifecycle_sym_k14_geometry",
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


def parse_header(image: bytes, magic: bytes, origin: int) -> Header:
    if len(image) < 12 or image[0] != 0xEB:
        raise AssertionError(f"{magic.decode()} worker lacks short header jump")
    got_magic, version, image_bytes, entry = struct.unpack_from("<4s3H", image, 2)
    if (
        got_magic != magic
        or version != 1
        or image_bytes != len(image)
        or entry != origin
    ):
        raise AssertionError(f"{magic.decode()} worker header drifted")
    return Header(got_magic, version, image_bytes, entry)


def padded_phase(
    measured: bytes,
    sectors: int,
    *,
    fill: int = 0,
) -> bytes:
    capacity = sectors * 512
    if not 0 < len(measured) <= capacity:
        raise AssertionError("phase image exceeds its sector-padded load")
    return measured + bytes([fill]) * (capacity - len(measured))


def stub_phase(
    origin: int,
    sectors: int,
    entries: tuple[int, ...],
) -> bytes:
    image = bytearray(sectors * 512)
    for entry in entries:
        if not origin <= entry < origin + len(image):
            raise AssertionError("stub entry lies outside its sector-padded phase")
        image[entry - origin] = 0xC3
    return bytes(image)


def fixture() -> Fixture:
    issuer = bytearray(hashlib.shake_256(b"Seed lifecycle issuer").digest(114))
    issuer[0] = 1
    psk = hashlib.sha256(b"Seed lifecycle PSK").digest()
    identity = hashlib.shake_256(b"Seed lifecycle identity").digest(192)
    nonce = hashlib.sha256(b"Seed lifecycle nonce").digest()
    ticket_tail = (
        nonce
        + struct.pack("<HH", 0, 3600)
        + b"\x11\x22\x33\x44"
        + struct.pack("<HHB", 32, 192, 1)
    )
    control = bytearray(16)
    struct.pack_into("<H", control, 0, GENERATION)
    struct.pack_into("<H", control, 2, 0x6AC4)
    control[4:8] = b"ROG3"
    control[8:12] = bytes(byte ^ 0xFF for byte in b"ROG3")
    control[12:16] = bytes((3, 0xFC, 0x3C, 0xC3))
    ticket_tail = bytearray(ticket_tail)
    ticket_tail[-1] = 2
    if len(ticket_tail) != 45:
        raise AssertionError("native ticket tail drifted")
    return Fixture(
        bytes(issuer),
        psk,
        identity,
        bytes(ticket_tail),
        bytes(control),
    )


def restored_snapshot(
    item: Fixture,
    marker: int,
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    if marker not in (1, 2):
        raise AssertionError("only normal or early-capable ticket markers restore")
    ticket_tail = bytearray(item.ticket_tail)
    ticket_tail[-1] = marker
    control = bytearray(item.control)
    if marker == 1:
        # The canonical card image remains early-capable (2).  Preserving the
        # spent host marker (1) lowers the checksummed bundle by one, so the
        # stored complemented checksum increases by one.
        checksum = (int.from_bytes(control[2:4], "little") + 1) & 0xFFFF
        control[2:4] = struct.pack("<H", checksum)
    return (
        item.issuer,
        item.psk,
        item.identity,
        bytes(ticket_tail),
        bytes(control),
    )


def expected_receipt(item: Fixture, ticks: int) -> bytes:
    page = bytearray(256)
    page[0:4] = NTR_MAGIC
    page[4:8] = NTR_INVERSE
    struct.pack_into("<HHH", page, 8, ticks & 0xFFFF, ticks >> 16, 0)
    page[NTR_DIGEST : NTR_DIGEST + 32] = hashlib.sha256(
        NTR_MAGIC + page[8:14] + item.native_ticket
    ).digest()
    page[NTR_INV_STATUS] = 0x5A
    page[NTR_STATUS] = 0xA5
    return bytes(page)


def expected_vault(
    item: Fixture,
    *,
    card_marker: int = 2,
) -> tuple[bytes, bytes, bytes]:
    ticket_tail = bytearray(item.ticket_tail)
    ticket_tail[-1] = card_marker
    canonical = (
        item.issuer
        + item.psk
        + item.identity
        + bytes(ticket_tail)
        + item.control
        + b"\0"
    )
    if len(canonical) != 400:
        raise AssertionError("canonical vault object is not 400 bytes")
    head = canonical[:256]
    tail = bytearray(256)
    tail[:RVL_CANONICAL_END] = canonical[256:]
    random = hashlib.sha256(b"Seed RVL1 attempt random").digest()
    session = hashlib.sha256(b"Seed RVL1 session").digest()
    tail[RVL_MAGIC : RVL_MAGIC + 4] = b"RVL1"
    tail[RVL_INVERSE : RVL_INVERSE + 4] = bytes(
        byte ^ 0xFF for byte in b"RVL1"
    )
    struct.pack_into("<H", tail, RVL_GENERATION, GENERATION)
    tail[RVL_RANDOM : RVL_RANDOM + 32] = random
    tail[RVL_SESSION : RVL_SESSION + 32] = session
    digest = hashlib.sha256(
        b"SEED-RVL1"
        + struct.pack("<H", GENERATION)
        + head
        + tail[:RVL_CANONICAL_END]
        + random
        + session
    ).digest()
    tail[RVL_DIGEST : RVL_DIGEST + 32] = digest
    tail[RVL_INV_STATUS] = 0x5A
    tail[RVL_STATUS] = 0xA5
    return head, bytes(tail), digest


class Machine:
    def __init__(
        self,
        worker: bytes,
        *,
        origin: int,
        item: Fixture,
        clocks: tuple[tuple[int, int], ...] = (),
    ) -> None:
        self.worker = worker
        self.origin = origin
        self.item = item
        self.clocks = list(clocks)
        self.card = bytearray(0x10000)
        self.sha: hashlib._Hash | None = None
        self.terminal: int | None = None
        self.loads: list[tuple[int, int]] = []
        self.card_writes: list[tuple[int, bytes, int]] = []
        self.card_reads: list[int] = []
        self.scrub_attempts: list[tuple[int, int]] = []
        self.gate_calls = 0
        self.k14_poison_events = 0
        self.sha_return_sites: list[int] = []
        self.phase_load_writes: list[tuple[int, int, int]] = []
        self.fail_write_calls: set[int] = set()
        self.fail_read_calls: set[int] = set()
        self.tamper_read_calls: set[int] = set()
        self.fail_loads: set[tuple[int, int]] = set()
        self.scrub_fail_pages: set[int] = set()
        self.gate_fail = False

        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, RAM_BYTES)
        self.uc.mem_write(0, bytes([0xA5]) * RAM_BYTES)
        self.uc.mem_write(
            origin,
            padded_phase(worker, 2)
            if origin == LIFECYCLE_ORIGIN
            else worker,
        )
        for address in (
            LOAD_PHASE,
            NE_WRITE,
            NE_READ,
            SHA_INIT,
            SHA_UPDATE,
            SHA_FINISH,
            SCRUB_ENTRY,
            GATE_VALIDATE,
        ):
            self.uc.mem_write(address, b"\xC3")
        self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
        self.uc.mem_write(FO_ENTRY, b"\xF4")
        self.uc.mem_write(PERSIST_FAIL, b"\xF4")
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.write(NE_TX_START, b"\x40")
        self.write(NIC_BASE, struct.pack("<H", 0x0300))
        self.install_bundle()
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt)

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(address, length))

    def write(self, address: int, value: bytes) -> None:
        self.uc.mem_write(address, bytes(value))

    def word(self, address: int) -> int:
        return int.from_bytes(self.read(address, 2), "little")

    def install_bundle(self) -> None:
        self.write(ISSUER, self.item.issuer)
        self.write(PSK, self.item.psk)
        self.write(IDENTITY, self.item.identity)
        self.write(TICKET_TAIL, self.item.ticket_tail)
        self.write(CONTROL, self.item.control)

    def bundle_snapshot(self) -> tuple[bytes, bytes, bytes, bytes, bytes]:
        return (
            self.read(ISSUER, 114),
            self.read(PSK, 32),
            self.read(IDENTITY, 192),
            self.read(TICKET_TAIL, 45),
            self.read(CONTROL, 16),
        )

    def fixture_snapshot(self) -> tuple[bytes, bytes, bytes, bytes, bytes]:
        return restored_snapshot(self.item, 2)

    def spent_fixture_snapshot(
        self,
    ) -> tuple[bytes, bytes, bytes, bytes, bytes]:
        return restored_snapshot(self.item, 1)

    def set_carry(self, carry: bool) -> None:
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        self.uc.reg_write(
            UC_X86_REG_EFLAGS,
            (flags | 1) if carry else (flags & ~1),
        )

    def _code(
        self,
        uc: Uc,
        address: int,
        _size: int,
        _user_data: object,
    ) -> None:
        if self.origin == RECEIPT_ORIGIN and address in {FO_ENTRY, PERSIST_FAIL}:
            self.terminal = address
            uc.emu_stop()
            return
        if address == LOAD_PHASE:
            key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            self.loads.append((key, destination))
            failed = (key, destination) in self.fail_loads
            if not failed and self.origin == LIFECYCLE_ORIGIN:
                if key not in LIFECYCLE_PHASE_IMAGES:
                    raise AssertionError(
                        f"unmodeled lifecycle phase key {key:#06x}"
                    )
                expected_destination, sectors, measured = (
                    LIFECYCLE_PHASE_IMAGES[key]
                )
                if destination != expected_destination:
                    raise AssertionError(
                        f"phase {key:#06x} loaded at mutable destination "
                        f"{destination:#06x}"
                    )
                payload = padded_phase(measured, sectors)
                self.write(destination, payload)
                self.phase_load_writes.append(
                    (destination, len(measured), len(payload))
                )
            self.set_carry(failed)
        elif address == SHA_INIT:
            self._poison_k14_work(uc)
            self.sha = hashlib.sha256()
            self.set_carry(False)
        elif address == SHA_UPDATE:
            if self.sha is None:
                raise AssertionError("SHA update preceded init")
            source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            length = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            self.sha.update(self.read(source, length))
            self._poison_k14_work(uc)
            self.set_carry(False)
        elif address == SHA_FINISH:
            if self.sha is None:
                raise AssertionError("SHA finish preceded init")
            destination = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
            self.write(destination, self.sha.digest())
            self.sha = None
            self._poison_k14_work(uc)
            self.set_carry(False)
        elif address == NE_WRITE:
            call = len(self.card_writes) + 1
            page = self.read(NE_TX_START, 1)[0]
            source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            count = uc.reg_read(UC_X86_REG_BP) & 0xFFFF
            payload = self.read(source, count)
            self.card_writes.append((page, payload, self.read(NE_TX_START, 1)[0]))
            if call not in self.fail_write_calls:
                start = page << 8
                self.card[start : start + count] = payload
            uc.reg_write(UC_X86_REG_AX, 0xDEAD)
            self.set_carry(call in self.fail_write_calls)
        elif address == NE_READ:
            call = len(self.card_reads) + 1
            source = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            length = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            destination = uc.reg_read(UC_X86_REG_DI) & 0xFFFF
            self.card_reads.append(source)
            failed = call in self.fail_read_calls
            if not failed:
                payload = bytearray(self.card[source : source + length])
                if call in self.tamper_read_calls:
                    payload[-1] ^= 1
                self.write(destination, payload)
            uc.reg_write(UC_X86_REG_AX, 0xBEEF)
            self.set_carry(failed)
        elif address == SCRUB_ENTRY:
            if self.read(HEAD_BUFFER, 256) != bytes(256):
                raise AssertionError("full-card scrub source is not all zero")
            old_tx = self.read(NE_TX_START, 1)[0]
            failed = False
            for page in range(0x73, 0x80):
                self.write(NE_TX_START, bytes([page]))
                if page not in self.scrub_fail_pages:
                    self.card[page << 8 : (page + 1) << 8] = bytes(256)
                else:
                    failed = True
                self.write(NE_TX_START, bytes([old_tx]))
                self.scrub_attempts.append((page, self.read(NE_TX_START, 1)[0]))
            self.set_carry(failed)
        elif address == GATE_VALIDATE:
            self.gate_calls += 1
            valid = self.bundle_snapshot() in (
                self.fixture_snapshot(),
                self.spent_fixture_snapshot(),
            )
            uc.reg_write(UC_X86_REG_AX, 1 if valid and not self.gate_fail else 0)
            self.set_carry(self.gate_fail or not valid)

    def _poison_k14_work(self, uc: Uc) -> None:
        sp = uc.reg_read(UC_X86_REG_SP) & 0xFFFF
        return_site = self.word(sp)
        if not HASH_ORIGIN <= return_site < HASH_LIMIT:
            raise AssertionError(
                "K14 SHA was called outside the exact safe hash bridge: "
                f"return={return_site:#06x}"
            )
        self.sha_return_sites.append(return_site)
        poison = (0xD0 + self.k14_poison_events) & 0xFF
        self.write(
            K14_MUTABLE_START,
            bytes([poison]) * (K14_MUTABLE_END - K14_MUTABLE_START),
        )
        self.k14_poison_events += 1

    def _interrupt(self, uc: Uc, number: int, _user_data: object) -> None:
        if number != 0x1A or (uc.reg_read(UC_X86_REG_AX) >> 8) != 0:
            raise AssertionError(f"unexpected BIOS interrupt {number:#x}")
        if not self.clocks:
            raise AssertionError("BIOS clock fixture exhausted")
        ticks, rollover = self.clocks.pop(0)
        uc.reg_write(UC_X86_REG_AX, rollover & 0xFF)
        uc.reg_write(UC_X86_REG_CX, (ticks >> 16) & 0xFFFF)
        uc.reg_write(UC_X86_REG_DX, ticks & 0xFFFF)
        self.set_carry(False)

    def run_receipt(self) -> int:
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP)
        self.uc.reg_write(UC_X86_REG_IP, RECEIPT_ORIGIN)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x402)
        try:
            self.uc.emu_start(RECEIPT_ORIGIN, RAM_BYTES, count=2_000_000)
        except UcError as exc:
            ip = self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF
            raise AssertionError(f"NTRW failed at {ip:04x}: {exc}") from exc
        if self.terminal is None:
            raise AssertionError("NTRW reached no terminal")
        if self.uc.reg_read(UC_X86_REG_SP) & 0xFFFF != STACK_TOP:
            raise AssertionError("NTRW left an unbalanced stack")
        if self.uc.reg_read(UC_X86_REG_EFLAGS) & 0x400:
            raise AssertionError("NTRW returned with DF set")
        if self.read(NE_TX_START, 1) != b"\x40":
            raise AssertionError("NTRW did not restore ordinary TX page")
        return self.terminal

    def call(self, operation: int, *, expect_success: bool) -> tuple[int, int, int]:
        self.terminal = None
        # RSD1 direct mode writes the complete two-sector phase on every
        # operation, including calls made after a prior SHA/self-load failure.
        self.write(LIFECYCLE_ORIGIN, padded_phase(self.worker, 2))
        self.write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        self.uc.reg_write(UC_X86_REG_IP, LIFECYCLE_ORIGIN)
        self.uc.reg_write(UC_X86_REG_AX, operation)
        self.uc.reg_write(UC_X86_REG_ES, 0)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x402)
        try:
            self.uc.emu_start(
                LIFECYCLE_ORIGIN, RETURN_SENTINEL, count=2_000_000
            )
        except UcError as exc:
            ip = self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF
            raise AssertionError(
                f"RVLW op{operation} failed at {ip:04x}: {exc}"
            ) from exc
        if self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF != RETURN_SENTINEL:
            raise AssertionError("RVLW returned to the wrong address")
        if self.uc.reg_read(UC_X86_REG_SP) & 0xFFFF != STACK_TOP:
            raise AssertionError("RVLW left an unbalanced stack")
        if self.uc.reg_read(UC_X86_REG_ES) != 0:
            raise AssertionError("RVLW did not preserve ES")
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        if flags & 0x400:
            raise AssertionError("RVLW returned with DF set")
        carry = bool(flags & 1)
        ax = self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        if expect_success and carry:
            raise AssertionError(f"RVLW op{operation} rejected valid input")
        if not expect_success and (not carry or ax != 0):
            raise AssertionError(f"RVLW op{operation} accepted hostile input")
        return (
            ax,
            self.uc.reg_read(UC_X86_REG_DX) & 0xFFFF,
            self.uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
        )


def install_receipt(machine: Machine, page: bytes) -> None:
    machine.card[CARD_HEAD : CARD_HEAD + 256] = page


def install_vault(machine: Machine, head: bytes, tail: bytes, digest: bytes) -> None:
    machine.card[CARD_HEAD : CARD_HEAD + 256] = head
    machine.card[CARD_TAIL : CARD_TAIL + 256] = tail
    machine.write(LIFECYCLE_DIGEST, digest)
    machine.write(LIFECYCLE_GENERATION, struct.pack("<H", GENERATION))
    machine.write(LIFECYCLE_INVERSE, b"\x5a")
    machine.write(LIFECYCLE_STATUS, b"\xa5")


def clobber_bundle(machine: Machine, *, host_marker: int = 0) -> None:
    machine.write(ISSUER, bytes([0x11]) * 114)
    machine.write(PSK, bytes([0x22]) * 32)
    machine.write(IDENTITY, bytes([0x33]) * 192)
    machine.write(TICKET_TAIL, bytes([0x44]) * 45)
    machine.write(CONTROL, bytes([0x55]) * 16)
    machine.write(TICKET_TAIL + 44, bytes([host_marker]))


def assert_scrub(machine: Machine) -> None:
    if [page for page, _tx in machine.scrub_attempts] != list(range(0x73, 0x80)):
        raise AssertionError("scrub did not attempt every page 0x73..0x7f")
    if any(tx != 0x40 for _page, tx in machine.scrub_attempts):
        raise AssertionError("scrub did not restore TX after every page")


def assert_hash_bridge(
    machine: Machine,
    *,
    bridge_key: int,
    bridge: bytes,
    lifecycle: bytes,
) -> None:
    expected_prefix = [
        (bridge_key, HASH_STAGE),
        (SYM_KEY, 0x1800),
        (LIFECYCLE_KEY, LIFECYCLE_ORIGIN),
    ]
    if machine.loads[:3] != expected_prefix:
        raise AssertionError("hash bridge fixed phase-load prefix drifted")
    if machine.phase_load_writes[:3] != [
        (HASH_STAGE, len(bridge), 512),
        (0x1800, 8 * 512, 8 * 512),
        (LIFECYCLE_ORIGIN, len(lifecycle), 2 * 512),
    ]:
        raise AssertionError("hash bridge no longer models sector-padded loads")
    if machine.read(HASH_ORIGIN, len(bridge)) != bridge:
        raise AssertionError("hash bridge exact-copy payload differs")
    if machine.read(
        HASH_ORIGIN + len(bridge),
        HASH_LIMIT - HASH_ORIGIN - len(bridge),
    ) != bytes([0xA5]) * (HASH_LIMIT - HASH_ORIGIN - len(bridge)):
        raise AssertionError("hash bridge copied file-sector padding into K14 state")
    if (
        machine.k14_poison_events != 7
        or not machine.sha_return_sites
        or machine.read(LIFECYCLE_ORIGIN, 2 * 512)
        != padded_phase(lifecycle, 2)
    ):
        raise AssertionError(
            "hash bridge did not survive actual K14 0x3000..0x33f8 clobber"
        )


def post_controller_gate(
    build: Path,
    receipt: bytes,
) -> dict[str, int | bool]:
    common = {
        "LIVE_K15_POST_CONTROLLER": 1,
        "LIVE_K15_SECURE_FO": 1,
        "LIVE_K15_IDENTITY_CAPTURE": 1,
        "LIVE_K15_PERSIST_FAIL": PERSIST_FAIL,
        "LIVE_K15_PERSIST_EMIT": 0x3588,
        "LIVE_K15_PERSIST_ZERO_WINDOW": 0x3564,
        "LIVE_K15_PERSIST_TRANSITION": 0x355D,
        "LIVE_K15_FO_CONTROLLER_KEY": FO_KEY,
    }
    legacy_listing = build / "post_controller_legacy.lst"
    legacy = assemble(
        CONTROLLERS_SOURCE,
        build / "post_controller_legacy.bin",
        legacy_listing,
        common,
    )
    hooked_listing = build / "post_controller_receipt.lst"
    hooked = assemble(
        CONTROLLERS_SOURCE,
        build / "post_controller_receipt.bin",
        hooked_listing,
        common
        | {
            "LIVE_K15_RESUME_RECEIPT": 1,
            "LIVE_K15_RESUME_RECEIPT_KEY": RECEIPT_KEY,
            "LIVE_K15_RESUME_RECEIPT_BYTES": len(receipt),
        },
    )
    existing = ROOT / "build/crypto-bench/tls13-live-k15/live_post_controller.bin"
    if existing.exists() and legacy != existing.read_bytes():
        raise AssertionError("receipt-disabled post controller is not byte-stable")
    if len(legacy) != 1012 or len(hooked) != 1024:
        raise AssertionError("post-controller slot geometry drifted")

    commit = 0x0900 + LIVE.listing_label_offset(
        hooked_listing, "post_check_commit"
    )
    edge = 0x0900 + LIVE.listing_label_offset(
        hooked_listing, ".resume_receipt_edge"
    )
    if not commit < edge < 0x0D00:
        raise AssertionError("NTR1 edge is not inside exact commit control flow")

    class Edge:
        def __init__(self) -> None:
            self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
            self.uc.mem_map(0, RAM_BYTES)
            self.uc.mem_write(0, bytes(RAM_BYTES))
            self.uc.mem_write(0x0900, hooked)
            self.uc.mem_write(LOAD_PHASE, b"\xC3")
            self.uc.mem_write(0x3564, b"\xC3")
            self.uc.mem_write(PERSIST_FAIL, b"\xF4")
            self.uc.mem_write(RECEIPT_ORIGIN, b"\xF4")
            self.loads: list[tuple[int, int]] = []
            self.terminal: int | None = None
            self.zero_fail = False
            self.load_fail = False
            for register in (
                UC_X86_REG_CS,
                UC_X86_REG_DS,
                UC_X86_REG_ES,
                UC_X86_REG_SS,
            ):
                self.uc.reg_write(register, 0)
            self.uc.hook_add(UC_HOOK_CODE, self.code)

        def carry(self, value: bool) -> None:
            flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
            self.uc.reg_write(
                UC_X86_REG_EFLAGS,
                (flags | 1) if value else (flags & ~1),
            )

        def code(
            self,
            uc: Uc,
            address: int,
            _size: int,
            _data: object,
        ) -> None:
            if address in {PERSIST_FAIL, RECEIPT_ORIGIN}:
                self.terminal = address
                uc.emu_stop()
            elif address == 0x3564:
                self.carry(self.zero_fail)
            elif address == LOAD_PHASE:
                key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
                destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
                self.loads.append((key, destination))
                if not self.load_fail:
                    self.uc.mem_write(destination, receipt.ljust(512, b"\0"))
                self.carry(self.load_fail)

        def call(
            self,
            *,
            header_pos: int,
            head: int,
            ticket: int,
        ) -> int | None:
            self.terminal = None
            self.loads.clear()
            self.uc.mem_write(0x3C35, bytes([header_pos, 0]))
            self.uc.mem_write(0x3C41, bytes([head, ticket]))
            digest = hashlib.sha256(b"post auth CV digest").digest()
            self.uc.mem_write(0x0EE0, digest)
            self.uc.mem_write(STACK_TOP - 2, struct.pack("<H", RETURN_SENTINEL))
            self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
            self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
            self.uc.reg_write(UC_X86_REG_IP, commit)
            self.uc.reg_write(UC_X86_REG_EFLAGS, 2)
            self.uc.emu_start(commit, RETURN_SENTINEL, count=200_000)
            if self.terminal is None:
                if self.uc.reg_read(UC_X86_REG_IP) != RETURN_SENTINEL:
                    raise AssertionError("incomplete commit did not return")
            return self.terminal

    for values in (
        (header_pos, head, ticket)
        for header_pos in (0, 1)
        for head in (0, 1)
        for ticket in (0, 1)
        if (header_pos, head, ticket) != (0, 1, 1)
    ):
        edge_machine = Edge()
        if edge_machine.call(
            header_pos=values[0], head=values[1], ticket=values[2]
        ) is not None:
            raise AssertionError("incomplete record/head/ticket reached NTR1")
        if edge_machine.loads:
            raise AssertionError("incomplete commit loaded NTR1")

    edge_machine = Edge()
    terminal = edge_machine.call(header_pos=0, head=1, ticket=1)
    if terminal != RECEIPT_ORIGIN:
        raise AssertionError("exact authenticated boundary did not enter NTR1")
    if edge_machine.loads != [(RECEIPT_KEY, HEAD_BUFFER)]:
        raise AssertionError("NTR1 edge exposed a mutable key/destination")
    if bytes(edge_machine.uc.mem_read(RECEIPT_ORIGIN, len(receipt))) != receipt:
        raise AssertionError("NTR1 edge did not exact-copy measured worker")
    if bytes(edge_machine.uc.mem_read(0x3510, 0x4D)) != bytes(0x4D):
        raise AssertionError("NTR1 edge reached K14 mutable/persistent state")

    for zero_fail, load_fail in ((True, False), (False, True)):
        edge_machine = Edge()
        edge_machine.zero_fail = zero_fail
        edge_machine.load_fail = load_fail
        terminal = edge_machine.call(header_pos=0, head=1, ticket=1)
        if terminal != PERSIST_FAIL:
            raise AssertionError("NTR1 edge failure did not fail closed")

    return {
        "legacy_bytes": len(legacy),
        "hooked_bytes": len(hooked),
        "legacy_byte_stable": True,
        "commit_entry": commit,
        "receipt_edge": edge,
    }


def main() -> None:
    item = fixture()
    ticks = 0x00123456
    with tempfile.TemporaryDirectory(prefix="seed-rvl1-") as temp_name:
        build = Path(temp_name)
        assert_k14_source_geometry(build)
        receipt = assemble(
            RECEIPT_SOURCE,
            build / "receipt.bin",
            build / "receipt.lst",
            {
                "RESUME_RECEIPT_SHA256_INIT": SHA_INIT,
                "RESUME_RECEIPT_SHA256_UPDATE": SHA_UPDATE,
                "RESUME_RECEIPT_SHA256_FINISH": SHA_FINISH,
                "RESUME_RECEIPT_NE_BUF_LOAD": NE_WRITE,
                "RESUME_RECEIPT_NE_BUF_READ": NE_READ,
                "RESUME_RECEIPT_FO_KEY": FO_KEY,
                "RESUME_RECEIPT_PERSIST_FAIL": PERSIST_FAIL,
            },
        )
        bridge_common = {
            "RESUME_LIFECYCLE_SYM_KEY": SYM_KEY,
            "RESUME_LIFECYCLE_SHA256_INIT": SHA_INIT,
            "RESUME_LIFECYCLE_SHA256_UPDATE": SHA_UPDATE,
            "RESUME_LIFECYCLE_SHA256_FINISH": SHA_FINISH,
            "RESUME_LIFECYCLE_SELF_KEY": LIFECYCLE_KEY,
        }
        receipt_hash = assemble(
            LIFECYCLE_SOURCE,
            build / "lifecycle_receipt_hash.bin",
            build / "lifecycle_receipt_hash.lst",
            bridge_common | {"RESUME_LIFECYCLE_RECEIPT_HASH": 1},
        )
        vault_hash = assemble(
            LIFECYCLE_SOURCE,
            build / "lifecycle_vault_hash.bin",
            build / "lifecycle_vault_hash.lst",
            bridge_common | {"RESUME_LIFECYCLE_VAULT_HASH": 1},
        )
        lifecycle = assemble(
            LIFECYCLE_SOURCE,
            build / "lifecycle.bin",
            build / "lifecycle.lst",
            {
                "RESUME_LIFECYCLE_NE_BUF_READ": NE_READ,
                "RESUME_LIFECYCLE_SCRUB_KEY": SCRUB_KEY,
                "RESUME_LIFECYCLE_SCRUB_ENTRY": SCRUB_ENTRY,
                "RESUME_LIFECYCLE_GATE_KEY": GATE_KEY,
                "RESUME_LIFECYCLE_GATE_VALIDATE": GATE_VALIDATE,
                "RESUME_LIFECYCLE_RECEIPT_HASH_KEY": RECEIPT_HASH_KEY,
                "RESUME_LIFECYCLE_RECEIPT_HASH_BYTES": len(receipt_hash),
                "RESUME_LIFECYCLE_VAULT_HASH_KEY": VAULT_HASH_KEY,
                "RESUME_LIFECYCLE_VAULT_HASH_BYTES": len(vault_hash),
            },
        )
        receipt_header = parse_header(receipt, b"NTRW", RECEIPT_ORIGIN)
        lifecycle_header = parse_header(lifecycle, b"RVLW", LIFECYCLE_ORIGIN)
        receipt_hash_header = parse_header(
            receipt_hash, b"RVNH", HASH_ORIGIN
        )
        vault_hash_header = parse_header(vault_hash, b"RVVH", HASH_ORIGIN)
        if (
            len(receipt) > 0x110
            or len(lifecycle) > 0x400
            or len(receipt_hash) > HASH_LIMIT - HASH_ORIGIN
            or len(vault_hash) > HASH_LIMIT - HASH_ORIGIN
        ):
            raise AssertionError("worker exceeds immutable dispatch slot")

        global LIFECYCLE_PHASE_IMAGES
        LIFECYCLE_PHASE_IMAGES = {
            LIFECYCLE_KEY: (LIFECYCLE_ORIGIN, 2, lifecycle),
            RECEIPT_HASH_KEY: (HASH_STAGE, 1, receipt_hash),
            VAULT_HASH_KEY: (HASH_STAGE, 1, vault_hash),
            SYM_KEY: (
                0x1800,
                8,
                stub_phase(
                    0x1800,
                    8,
                    (SHA_INIT, SHA_UPDATE, SHA_FINISH),
                ),
            ),
            SCRUB_KEY: (
                FO_ENTRY,
                1,
                stub_phase(FO_ENTRY, 1, (SCRUB_ENTRY,)),
            ),
            GATE_KEY: (
                0x1800,
                2,
                stub_phase(0x1800, 2, (GATE_VALIDATE,)),
            ),
        }

        post_gate = post_controller_gate(build, receipt)

        receipt_page = expected_receipt(item, ticks)
        machine = Machine(
            receipt,
            origin=RECEIPT_ORIGIN,
            item=item,
            clocks=((ticks, 1),),
        )
        machine.write(
            LIFECYCLE_DIGEST,
            bytes([LIFECYCLE_PREFILL])
            * (LIFECYCLE_END - LIFECYCLE_DIGEST),
        )
        fo_tail_state = machine.read(TICKET_TAIL + 45, 1)
        terminal = machine.run_receipt()
        if terminal != FO_ENTRY:
            raise AssertionError("valid NTR1 capture did not enter original FO")
        if machine.loads != [(FO_KEY, FO_ENTRY)]:
            raise AssertionError("NTR1 worker loaded mutable FO authority")
        if machine.card[CARD_HEAD : CARD_HEAD + 256] != receipt_page:
            raise AssertionError("NTR1 final card image differs")
        if len(machine.card_writes) != 2 or len(machine.card_reads) != 2:
            raise AssertionError("NTR1 did not perform two write/readback rounds")
        first = machine.card_writes[0][1]
        second = machine.card_writes[1][1]
        if (
            first[NTR_INV_STATUS:] != b"\0\0"
            or second != receipt_page
            or machine.read(LIFECYCLE_DIGEST, LIFECYCLE_END - LIFECYCLE_DIGEST)
            != bytes([LIFECYCLE_PREFILL])
            * (LIFECYCLE_END - LIFECYCLE_DIGEST)
        ):
            raise AssertionError(
                "NTR1 status-last write or pre-auth lifecycle preservation drifted"
            )
        if (
            machine.read(RECEIPT_BUILD, 238)
            != item.identity + item.ticket_tail + fo_tail_state
        ):
            raise AssertionError("NTR1 did not reconstruct original FO ticket hold")

        receipt_faults = 0
        for kind in ("write", "read", "tamper"):
            for call in (1, 2):
                failed = Machine(
                    receipt,
                    origin=RECEIPT_ORIGIN,
                    item=item,
                    clocks=((ticks, 0),),
                )
                getattr(failed, f"fail_{kind}_calls", None)
                if kind == "write":
                    failed.fail_write_calls.add(call)
                elif kind == "read":
                    failed.fail_read_calls.add(call)
                else:
                    failed.tamper_read_calls.add(call)
                if failed.run_receipt() != PERSIST_FAIL:
                    raise AssertionError(f"NTR1 {kind}{call} did not fail closed")
                receipt_faults += 1

        nst = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
        install_receipt(nst, receipt_page)
        before = bytes(nst.card)
        ax, dx, bx = nst.call(10, expect_success=True)
        if (dx << 16) | ax != ticks or bx != 0:
            raise AssertionError("op10 did not import original NTR1 clock")
        if bytes(nst.card) != before or nst.card_writes:
            raise AssertionError("op10 mutated NTR1")
        assert_hash_bridge(
            nst,
            bridge_key=RECEIPT_HASH_KEY,
            bridge=receipt_hash,
            lifecycle=lifecycle,
        )

        bridge_fault_cases = 0
        for failed_load in (
            (RECEIPT_HASH_KEY, HASH_STAGE),
            (SYM_KEY, 0x1800),
            (LIFECYCLE_KEY, LIFECYCLE_ORIGIN),
        ):
            faulted_nst = Machine(
                lifecycle, origin=LIFECYCLE_ORIGIN, item=item
            )
            install_receipt(faulted_nst, receipt_page)
            faulted_nst.fail_loads.add(failed_load)
            faulted_nst.call(10, expect_success=False)
            if faulted_nst.card_writes:
                raise AssertionError("failed op10 bridge mutated card state")
            bridge_fault_cases += 1

        ntr_tamper_cases = 0
        for offset in range(256):
            hostile = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
            page = bytearray(receipt_page)
            page[offset] ^= 1
            install_receipt(hostile, page)
            hostile.call(10, expect_success=False)
            if hostile.card_writes:
                raise AssertionError("hostile op10 wrote card state")
            ntr_tamper_cases += 1
        native = item.native_ticket
        for offset in range(len(native)):
            hostile = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
            install_receipt(hostile, receipt_page)
            if offset < 32:
                address = PSK + offset
            elif offset < 224:
                address = IDENTITY + offset - 32
            else:
                address = TICKET_TAIL + offset - 224
            hostile.write(address, bytes([hostile.read(address, 1)[0] ^ 1]))
            hostile.call(10, expect_success=False)
            ntr_tamper_cases += 1

        clock_cases = 0
        for rollover in (0, 1):
            clock = Machine(
                lifecycle,
                origin=LIFECYCLE_ORIGIN,
                item=item,
                clocks=((ticks, rollover),),
            )
            ax, dx, bx = clock.call(1, expect_success=True)
            if (dx << 16) | ax != ticks or bx != rollover:
                raise AssertionError("op1 clock/day result drifted")
            clock_cases += 1
        for bad_ticks, bad_rollover in ((0x001800B0, 0), (ticks, 2)):
            clock = Machine(
                lifecycle,
                origin=LIFECYCLE_ORIGIN,
                item=item,
                clocks=((bad_ticks, bad_rollover),),
            )
            clock.call(1, expect_success=False)
            clock_cases += 1

        initial_route = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
        initial_route.write(
            LIFECYCLE_DIGEST,
            bytes(LIFECYCLE_END - LIFECYCLE_DIGEST),
        )
        initial_route.call(9, expect_success=True)
        if (
            initial_route.loads != [(GATE_KEY, 0x1800)]
            or initial_route.gate_calls != 1
            or initial_route.scrub_attempts
        ):
            raise AssertionError("first op9 consumed NTR1 or bypassed fixed ROG4")

        head, tail, vault_digest = expected_vault(item)
        restored = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
        install_vault(restored, head, tail, vault_digest)
        clobber_bundle(restored)
        restored.call(9, expect_success=True)
        if restored.bundle_snapshot() != restored.fixture_snapshot():
            raise AssertionError(
                "marker-0 op9 did not restore card-present 2 unchanged"
            )
        assert_hash_bridge(
            restored,
            bridge_key=VAULT_HASH_KEY,
            bridge=vault_hash,
            lifecycle=lifecycle,
        )
        if restored.loads[3:] != [
            (SCRUB_KEY, FO_ENTRY),
            (GATE_KEY, 0x1800),
        ]:
            raise AssertionError("op9 restore/scrub/ROG4 phase order drifted")
        if restored.read(LIFECYCLE_INVERSE, 2) != b"\x3c\xc3":
            raise AssertionError("op9 did not mark RESTORED before scrub")
        assert_scrub(restored)
        if restored.gate_calls != 1 or any(
            restored.card[page << 8 : (page + 1) << 8] != bytes(256)
            for page in range(0x73, 0x80)
        ):
            raise AssertionError("op9 scrub/ROG4 order drifted")

        spent = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
        install_vault(spent, head, tail, vault_digest)
        clobber_bundle(spent, host_marker=1)
        spent.call(9, expect_success=True)
        if spent.bundle_snapshot() != spent.spent_fixture_snapshot():
            raise AssertionError(
                "marker-1 op9 did not preserve the one-shot host marker"
            )
        canonical_checksum = int.from_bytes(item.control[2:4], "little")
        restored_checksum = spent.word(CONTROL + 2)
        if restored_checksum != (canonical_checksum + 1) & 0xFFFF:
            raise AssertionError(
                "marker 2->1 bundle decrement did not adjust its "
                "complemented gate checksum"
            )
        assert_hash_bridge(
            spent,
            bridge_key=VAULT_HASH_KEY,
            bridge=vault_hash,
            lifecycle=lifecycle,
        )
        assert_scrub(spent)
        if spent.gate_calls != 1:
            raise AssertionError("spent marker restore did not reach fixed ROG4")

        invalid_marker_cases = 0
        for host_marker in (2, 3, 0xFF):
            invalid_host = Machine(
                lifecycle,
                origin=LIFECYCLE_ORIGIN,
                item=item,
            )
            install_vault(invalid_host, head, tail, vault_digest)
            clobber_bundle(invalid_host, host_marker=host_marker)
            invalid_host.call(11, expect_success=False)
            assert_scrub(invalid_host)
            if invalid_host.gate_calls:
                raise AssertionError("invalid host marker reached fixed ROG4")
            invalid_marker_cases += 1
        for card_marker in (0, 1, 3, 0xFF):
            bad_head, bad_tail, bad_digest = expected_vault(
                item,
                card_marker=card_marker,
            )
            invalid_card = Machine(
                lifecycle,
                origin=LIFECYCLE_ORIGIN,
                item=item,
            )
            install_vault(
                invalid_card,
                bad_head,
                bad_tail,
                bad_digest,
            )
            clobber_bundle(invalid_card)
            invalid_card.call(11, expect_success=False)
            assert_scrub(invalid_card)
            if invalid_card.gate_calls:
                raise AssertionError("invalid card marker reached fixed ROG4")
            invalid_marker_cases += 1

        for failed_load in (
            (VAULT_HASH_KEY, HASH_STAGE),
            (SYM_KEY, 0x1800),
            (LIFECYCLE_KEY, LIFECYCLE_ORIGIN),
        ):
            faulted_restore = Machine(
                lifecycle, origin=LIFECYCLE_ORIGIN, item=item
            )
            install_vault(faulted_restore, head, tail, vault_digest)
            clobber_bundle(faulted_restore)
            faulted_restore.fail_loads.add(failed_load)
            faulted_restore.call(9, expect_success=False)
            if faulted_restore.gate_calls:
                raise AssertionError("failed op9 bridge reached ROG4")
            faulted_restore.fail_loads.clear()
            faulted_restore.scrub_attempts.clear()
            faulted_restore.call(11, expect_success=True)
            assert_scrub(faulted_restore)
            if (
                faulted_restore.bundle_snapshot()
                != faulted_restore.fixture_snapshot()
            ):
                raise AssertionError(
                    "op11 did not recover after a bridge/self-load failure"
                )
            bridge_fault_cases += 1

        vault_tamper_cases = 0
        for page_address, clean in ((CARD_HEAD, head), (CARD_TAIL, tail)):
            for offset in range(256):
                hostile = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
                install_vault(hostile, head, tail, vault_digest)
                hostile.card[page_address + offset] ^= 1
                clobber_bundle(hostile)
                hostile.call(9, expect_success=False)
                if hostile.gate_calls:
                    raise AssertionError("tampered vault reached ROG4")
                hostile.call(11, expect_success=False)
                assert_scrub(hostile)
                vault_tamper_cases += 1

        scrub_fault_cases = 0
        for failed_pages in (
            *((page,) for page in range(0x73, 0x80)),
            (0x73, 0x79, 0x7F),
        ):
            faulted = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
            install_vault(faulted, head, tail, vault_digest)
            clobber_bundle(faulted)
            faulted.scrub_fail_pages.update(failed_pages)
            faulted.call(9, expect_success=False)
            assert_scrub(faulted)
            if faulted.gate_calls or faulted.read(LIFECYCLE_INVERSE, 2) != b"\x3c\xc3":
                raise AssertionError("scrub fault reached route or allowed re-import")
            snapshot = faulted.bundle_snapshot()
            faulted.scrub_fail_pages.clear()
            faulted.scrub_attempts.clear()
            faulted.call(11, expect_success=True)
            assert_scrub(faulted)
            if faulted.bundle_snapshot() != snapshot:
                raise AssertionError("RESTORED op11 re-imported the vault")
            scrub_fault_cases += 1

        none_cleanup = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
        none_cleanup.write(
            LIFECYCLE_DIGEST,
            bytes(LIFECYCLE_END - LIFECYCLE_DIGEST),
        )
        none_cleanup.call(11, expect_success=True)
        assert_scrub(none_cleanup)

        partial_cleanup = Machine(lifecycle, origin=LIFECYCLE_ORIGIN, item=item)
        partial_cleanup.write(LIFECYCLE_STATUS, b"\xa5")
        partial_cleanup.write(LIFECYCLE_INVERSE, b"\0")
        partial_cleanup.call(11, expect_success=False)
        assert_scrub(partial_cleanup)

        invalid_selector = Machine(
            lifecycle, origin=LIFECYCLE_ORIGIN, item=item
        )
        invalid_selector.call(8, expect_success=False)

        report = {
            "receipt_worker": {
                "bytes": receipt_header.image_bytes,
                "limit": 0x110,
                "writes": 2,
                "readbacks": 2,
                "fault_cases": receipt_faults,
                "status_last": True,
                "tx_restored": True,
                "pre_auth_lifecycle_span": "0x3c76..0x3c9a",
                "pre_auth_lifecycle_span_preserved": True,
                "lifecycle_initialization_owner": (
                    "post-auth entry after exact-pin P-256 and LP1 publication"
                ),
            },
            "lifecycle_worker": {
                "bytes": lifecycle_header.image_bytes,
                "limit": 0x400,
                "direct_operations": [1, 9, 10, 11],
                "receipt_hash_bridge_bytes": receipt_hash_header.image_bytes,
                "vault_hash_bridge_bytes": vault_hash_header.image_bytes,
                "hash_bridge_limit": HASH_LIMIT - HASH_ORIGIN,
                "hash_bridge_stage": HASH_STAGE,
                "hash_bridge_origin": HASH_ORIGIN,
                "k14_mutable_poison_range": [
                    K14_MUTABLE_START,
                    K14_MUTABLE_END,
                ],
                "k14_record_aead_subspan": [
                    K14_RECORD_AEAD_START,
                    K14_RECORD_AEAD_END,
                ],
                "k14_bounds_source_derived": True,
                "sector_padded_loads_modeled": True,
                "bridge_load_fault_cases": bridge_fault_cases,
                "ntr_page_tamper_cases": ntr_tamper_cases,
                "native_ticket_tamper_cases": len(item.native_ticket),
                "vault_byte_tamper_cases": vault_tamper_cases,
                "clock_cases": clock_cases,
                "scrub_fault_cases": scrub_fault_cases,
                "scrub_pages_each_attempt": 13,
                "restored_before_scrub": True,
                "no_reimport_after_restored": True,
            },
            "post_controller": post_gate,
        }
        result_path = HERE / "post_auth_resume_lifecycle_worker_results.json"
        result_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            "post-auth resume lifecycle: PASS "
            f"(NTRW {len(receipt)}/272 bytes, RVLW {len(lifecycle)}/1024 bytes, "
            f"RVNH/RVVH {len(receipt_hash)}/{len(vault_hash)}/272 bytes, "
            f"K14 poison 0x{K14_MUTABLE_START:04x}..0x{K14_MUTABLE_END:04x} "
            f"(record AEAD 0x{K14_RECORD_AEAD_START:04x}.."
            f"0x{K14_RECORD_AEAD_END:04x}), "
            f"{ntr_tamper_cases} NTR tamper cases, "
            f"{vault_tamper_cases} vault-byte tamper cases, "
            f"{scrub_fault_cases} scrub fault cases, "
            f"{invalid_marker_cases + 2} one-shot marker cases)"
        )


if __name__ == "__main__":
    main()
