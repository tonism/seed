#!/usr/bin/env python3
"""Executable hostile gate for the TLS 1.3 286 entropy controller.

This checker deliberately gives emulator timing zero entropy credit.  It proves
only the controller mechanics around the physical-source boundary:

* 1,024 silent PC/AT RTC-periodic/PIT timing samples and exact six-byte event
  capture, with bounded oscillator failure and RTC register restoration;
* injectable SP 800-90B RCT/APT state-machine boundaries;
* the real cached-pack ML-KEM module's SHA3-256 conditioner operation;
* the SP 800-90A SHA-256 HMAC_DRBG algorithm and its official CAVP KAT;
* two sequential, status-last 160-byte attempt publications; and
* replay/reentry rejection plus success, failure, and pre-NIC abort
  zeroization through the authenticated bootstrap stack bridge.

The HMAC_DRBG known-answer material is the first SHA-256, no-reseed,
prediction-resistance-disabled case in NIST's official ``drbgtestvectors.zip``:

    drbgvectors_no_reseed.zip / HMAC_DRBG.rsp, COUNT = 0

The response file publishes the second Generate(1024) output.  This checker
also derives the first output and all intermediate state from an independent
host implementation of SP 800-90A.

Passing this file is not physical SP 800-90B characterization and is not a
FIPS validation claim.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from typing import Iterable

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
    UC_X86_REG_DS,
    UC_X86_REG_DX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


ROOT = Path(__file__).resolve().parents[3]
BOOT = ROOT / "targets/ibm_pc_5150/boot"
SOURCE = BOOT / "tls13/tls13_286_entropy.asm"
ROOT_BUILDER = (
    ROOT / "tools/crypto-bench/tls13-product/build_286_root_stage.py"
)
ROOT_STAGE = ROOT / "build/ibm_pc_5150/tls13-286-root-stage.bin"
PRODUCT_ABI = ROOT / "build/ibm_pc_5150/tls13-286-product-abi.inc"
PACK = (
    ROOT / "build/ibm_pc_5150/crypto-bench/tls13-286-modules.bin"
)

CONTROLLER_BASE = 0x1800
CONTROLLER_LIMIT = 0x3400
CONTROLLER_CAPACITY = CONTROLLER_LIMIT - CONTROLLER_BASE
CONTROLLER_MAGIC = b"S286ENT2"
ABI_VERSION = 2
CONTROLLER_ENTRY_COUNT = 5
CONTROLLER_HEADER_BYTES = 14 + CONTROLLER_ENTRY_COUNT * 2

LOADER_BASE = 0x3400
LOADER_ENTRY_TABLE = LOADER_BASE + 14
LOADER_VALIDATE_INDEX = 0
LOADER_DECODE_INDEX = 1
LOADER_CALL_INDEX = 2
MODULE_BASE = 0x4230
MODULE_LIMIT = 0x7A00
MODULE_KIND_MLKEM_KEYGEN = 1
MODULE_OP_SHA3_CONDITION = 7

ROOT_STATE = 0x4020
ROOT_STATE_MODE = ROOT_STATE
ROOT_STATE_CRYPTO_SEG = ROOT_STATE + 2
LOADER_STATE = ROOT_STATE + 4
LOADER_STATE_CACHE_SEG = LOADER_STATE
LOADER_STATE_CACHE_CAPACITY = LOADER_STATE + 2
LOADER_STATE_PACK_BYTES = LOADER_STATE + 4
LOADER_STATE_BYTES = 18
ROOT_PARENT_SP = LOADER_STATE + LOADER_STATE_BYTES
ROOT_PARENT_SP_INVERSE = ROOT_PARENT_SP + 2
ROOT_PARENT_STATUS_INV = ROOT_PARENT_SP + 4
ROOT_SERVICE_TABLE = 0x3910
ROOT_SERVICE_CHAIN_POINTER = ROOT_SERVICE_TABLE + 10
TAIL_KIND_ACQUIRE = 5

CRYPTO_SEG = 0x7000
CRYPTO_BASE = CRYPTO_SEG << 4
HIGH_RESERVE_BYTES = 64 * 1024
PACK_BYTES = 41 * 512
RAW_OFF = 0x5800
RAW_BYTES = 1024 * 6
RAW = CRYPTO_BASE + RAW_OFF
CMOS_INDEX = 0x70
CMOS_DATA = 0x71
CMOS_STATUS_A = 0x0A
CMOS_STATUS_B = 0x0B
CMOS_STATUS_C = 0x0C
CMOS_32KHZ_1024HZ = 0x26
CMOS_32KHZ_4096HZ = 0x24
CMOS_PERIODIC = 0x40
CONDITIONED_OFF = 0xB0E0
CONDITIONED_BYTES = 64
CONDITIONED = CRYPTO_BASE + CONDITIONED_OFF
PREVIOUS_HASH_OFF = 0xB802
PREVIOUS_HASH_BYTES = 32
PREVIOUS_HASH = CRYPTO_BASE + PREVIOUS_HASH_OFF
HEALTH_OFF = 0xB822
HEALTH_BYTES = 64
HEALTH = CRYPTO_BASE + HEALTH_OFF
FOOTER_OFF = 0xB602
FOOTER = CRYPTO_BASE + FOOTER_OFF
ESCROW_CRYPTO_SEG_OFF = 0xB870
ESCROW_STATUS_INV_OFF = 0xB880

ATTEMPT_BYTES = 160
ATTEMPT_ACQUIRE_OFF = 0xB982
ATTEMPT_FRESH_OFF = ATTEMPT_ACQUIRE_OFF + ATTEMPT_BYTES
ATTEMPT_ACQUIRE = CRYPTO_BASE + ATTEMPT_ACQUIRE_OFF
ATTEMPT_FRESH = CRYPTO_BASE + ATTEMPT_FRESH_OFF
DRBG_K_OFF = ATTEMPT_FRESH_OFF + ATTEMPT_BYTES
DRBG_V_OFF = DRBG_K_OFF + 32
DRBG_WORK_OFF = DRBG_V_OFF + 32
GENERATION_HASH_OFF = DRBG_WORK_OFF + 64
DRBG_K = CRYPTO_BASE + DRBG_K_OFF
DRBG_V = CRYPTO_BASE + DRBG_V_OFF
DRBG_WORK = CRYPTO_BASE + DRBG_WORK_OFF
GENERATION_HASH = CRYPTO_BASE + GENERATION_HASH_OFF
GENERATION_HASH_BYTES = 32
ROOT_STATUS_INV = GENERATION_HASH + GENERATION_HASH_BYTES
ROOT_STATUS = ROOT_STATUS_INV + 1
ACQUIRE_STATUS_INV = ROOT_STATUS + 1
ACQUIRE_STATUS = ACQUIRE_STATUS_INV + 1
FRESH_STATUS_INV = ACQUIRE_STATUS + 1
FRESH_STATUS = FRESH_STATUS_INV + 1
PUBLICATION_END = FRESH_STATUS + 1
STATUS_READY_INV = 0x5A
STATUS_READY = 0xA5

RETURN_SENTINEL = 0x0200
BOOTSTRAP_ABORT_STUB = 0x0202
CHAIN_RETURN_STUB = 0x0204
BOOTSTRAP_ABORT_POINTER = 0x0706
HANDOFF_RAM_TOP = 0x062C
PARENT_STACK_TOP = 0xFFF0
PARENT_ENTRY_SP = PARENT_STACK_TOP - 2
ROUTE_MODE = 0x11AD
STACK_BOTTOM = 0x7A00
STACK_TOP = 0x7FFE
PROTECTED_START = 0x3C00
PROTECTED_BYTES = 0x400
HANDOFF_START = 0x4000
HANDOFF_BYTES = 0x200

SAMPLES_REQUIRED = 1024
EVENT_BYTES = 6
RCT_CUTOFF = 64
APT_WINDOW = 512
APT_CUTOFF = 400

CONDITION_DOMAIN = b"Seed 286 raw timing conditioner v1\0"

# NIST CAVP DRBGVS, SHA-256, no reseed, prediction resistance false,
# EntropyInputLen=256, NonceLen=128, PersonalizationStringLen=0,
# AdditionalInputLen=0, ReturnedBitsLen=1024, COUNT=0.
KAT_ENTROPY = bytes.fromhex(
    "ca851911349384bffe89de1cbdc46e68"
    "31e44d34a4fb935ee285dd14b71a7488"
)
KAT_NONCE = bytes.fromhex("659ba96c601dc69fc902940805ec0ca8")
KAT_INSTANTIATE_K = bytes.fromhex(
    "302a4aba78412ab36940f4be7b940a0c"
    "728542b8b81d95b801a57b3797f9dd6e"
)
KAT_INSTANTIATE_V = bytes.fromhex(
    "e75855f93b971ac468d200992e211960"
    "202d53cf08852ef86772d6490bfb53f9"
)
KAT_FIRST = bytes.fromhex(
    "591adfe6e6ee9ba3e7d11ed51db04b3b"
    "f9600c1733c0b0c4486eb8230bc56344"
    "b563ba9bd6858c0e4a04888c0b13cd4e"
    "024d2866f8f5b2bf4db1d83e27bd1eae"
    "13864768ccae5d6b903d3fcc6a517bc6"
    "817779cec7ec7eb34fec5ae0481e46f0"
    "2d91b8ff9a3be9376c17d8a58033e69b"
    "3de00e2bafa1fb5f396daf2cf2345290"
)
KAT_AFTER_FIRST_K = bytes.fromhex(
    "911bf7cbda4387a172a1a3daf6c9fa8e"
    "17c4bfef69cc7eff1341e7eef88d2811"
)
KAT_AFTER_FIRST_V = bytes.fromhex(
    "bfbdcf455d5c82acafc59f339ce57126"
    "ff70b67aef910fa25db7617818faeafe"
)
KAT_SECOND = bytes.fromhex(
    "e528e9abf2dece54d47c7e75e5fe3021"
    "49f817ea9fb4bee6f4199697d04d5b89"
    "d54fbb978a15b5c443c9ec21036d2460"
    "b6f73ebad0dc2aba6e624abf07745bc1"
    "07694bb7547bb0995f70de25d6b29e2d"
    "3011bb19d27676c07162c8b5ccde0668"
    "961df86803482cb37ed6d5c0bb8d50cf"
    "1f50d476aa0458bdaba806f48be9dcb8"
)
KAT_AFTER_SECOND_K = bytes.fromhex(
    "6dd2cd5b1edba4b620d195ce26ad6845"
    "b063211d11e591432de37a3ad793f66c"
)
KAT_AFTER_SECOND_V = bytes.fromhex(
    "6b94e773e3469353a1ca8face76b238c"
    "5919d62a150a7dfc589ffa11c30b5b94"
)


def u16(blob: bytes, offset: int) -> int:
    return int.from_bytes(blob[offset : offset + 2], "little")


def put_u16(blob: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", blob, offset, value)


def interval_contains(
    outer: tuple[int, int], address: int, size: int
) -> bool:
    return outer[0] <= address and address + size <= outer[1]


class HmacDrbg:
    """Small independent SP 800-90A HMAC_DRBG(SHA-256) oracle."""

    def __init__(
        self,
        entropy: bytes,
        nonce: bytes,
        personalization: bytes = b"",
    ) -> None:
        self.k = bytes(32)
        self.v = bytes((1,)) * 32
        self.update(entropy + nonce + personalization)

    @staticmethod
    def _hmac(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def update(self, provided_data: bytes = b"") -> None:
        self.k = self._hmac(self.k, self.v + b"\x00" + provided_data)
        self.v = self._hmac(self.k, self.v)
        if provided_data:
            self.k = self._hmac(
                self.k, self.v + b"\x01" + provided_data
            )
            self.v = self._hmac(self.k, self.v)

    def generate(self, count: int) -> bytes:
        output = bytearray()
        while len(output) < count:
            self.v = self._hmac(self.k, self.v)
            output += self.v
        self.update()
        return bytes(output[:count])


def assert_host_kat() -> None:
    drbg = HmacDrbg(KAT_ENTROPY, KAT_NONCE)
    if drbg.k != KAT_INSTANTIATE_K or drbg.v != KAT_INSTANTIATE_V:
        raise AssertionError("host HMAC_DRBG instantiate differs from CAVP")
    if drbg.generate(128) != KAT_FIRST:
        raise AssertionError("host HMAC_DRBG first KAT output drifted")
    if drbg.k != KAT_AFTER_FIRST_K or drbg.v != KAT_AFTER_FIRST_V:
        raise AssertionError("host HMAC_DRBG first post-state drifted")
    if drbg.generate(128) != KAT_SECOND:
        raise AssertionError("host HMAC_DRBG differs from CAVP ReturnedBits")
    if drbg.k != KAT_AFTER_SECOND_K or drbg.v != KAT_AFTER_SECOND_V:
        raise AssertionError("host HMAC_DRBG second post-state drifted")


def condition_raw(raw: bytes) -> bytes:
    if len(raw) != RAW_BYTES:
        raise AssertionError("conditioner oracle requires exactly 6,144 bytes")
    prefix = CONDITION_DOMAIN[:-1]
    return b"".join(
        hashlib.sha3_256(prefix + bytes((counter,)) + raw).digest()
        for counter in range(2)
    )


def expected_attempts(
    raw: bytes,
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    conditioned = condition_raw(raw)
    drbg = HmacDrbg(
        conditioned[:32],
        conditioned[32:48],
        conditioned[48:64],
    )
    acquire = drbg.generate(ATTEMPT_BYTES)
    fresh = drbg.generate(ATTEMPT_BYTES)
    conditioned_hash = hashlib.sha256(conditioned).digest()
    generation_hash = hashlib.sha256(
        conditioned + acquire + fresh
    ).digest()
    return conditioned, acquire, fresh, conditioned_hash, generation_hash


@dataclass(frozen=True)
class TimedEvent:
    before: int
    after: int
    fail: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.before <= 0xFFFF:
            raise ValueError("PIT before count is not a word")
        if not 0 <= self.after <= 0xFFFF:
            raise ValueError("PIT after count is not a word")
    @property
    def symbol(self) -> int:
        delta = (self.before - self.after) & 0xFFFF
        return ((delta & 0xFF) ^ (delta >> 8)) & 0xFF


def samples_for_symbols(
    symbols: Iterable[int],
    *,
    timing_bias: int = 0,
) -> list[TimedEvent]:
    samples: list[TimedEvent] = []
    for index, symbol in enumerate(symbols):
        if not 0 <= symbol <= 0xFF:
            raise ValueError("health symbol is not a byte")
        # A duration 0x01XX folds to XX XOR 1.
        duration = 0x0100 | (symbol ^ 1)
        before = (
            0xF137 - index * 0x0137 - timing_bias * 0x0029
        ) & 0xFFFF
        after = (before - duration) & 0xFFFF
        sample = TimedEvent(before, after)
        if sample.symbol != symbol:
            raise AssertionError("synthetic timing did not realize symbol")
        samples.append(sample)
    return samples


def healthy_samples(
    *,
    timing_bias: int = 0,
) -> list[TimedEvent]:
    symbols = [
        (index * 73 + index // 7 + timing_bias * 19) & 0xFF
        for index in range(SAMPLES_REQUIRED)
    ]
    return samples_for_symbols(
        symbols,
        timing_bias=timing_bias,
    )


def raw_events(samples: list[TimedEvent]) -> bytes:
    if len(samples) != SAMPLES_REQUIRED:
        raise AssertionError("raw oracle requires exactly 1,024 samples")
    return b"".join(
        struct.pack("<HHH", sample.before, sample.after, index)
        for index, sample in enumerate(samples)
    )


@dataclass(frozen=True)
class Built:
    controller: bytes
    entries: tuple[int, ...]
    stage: bytes
    pack: bytes
    loader_entries: tuple[int, ...]
    bootstrap_parent_sp: int


def build_images(temp: Path) -> Built:
    if not SOURCE.exists():
        raise AssertionError(
            "entropy controller source is not present yet: "
            f"{SOURCE.relative_to(ROOT)}"
        )
    subprocess.run(
        [sys.executable, str(ROOT_BUILDER)],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    stage = ROOT_STAGE.read_bytes()
    pack = PACK.read_bytes()
    parent_sp_fields = [
        line.split()[2]
        for line in PRODUCT_ABI.read_text(encoding="ascii").splitlines()
        if line.startswith("%define TLS13_286_PRODUCT_BOOTSTRAP_PARENT_SP ")
    ]
    if len(parent_sp_fields) != 1:
        raise AssertionError("cannot resolve generated bootstrap parent-SP ABI")
    bootstrap_parent_sp = int(parent_sp_fields[0], 0)
    if len(stage) != 2048:
        raise AssertionError("root stage is not exactly four sectors")
    if len(pack) != PACK_BYTES:
        raise AssertionError("module pack is not exactly 41 sectors")
    if stage[:8] != b"S286CTL2":
        raise AssertionError("pack-loader magic drifted")
    if u16(stage, 8) != ABI_VERSION or u16(stage, 12) != 4:
        raise AssertionError("pack-loader ABI/entry count drifted")
    loader_entries = tuple(u16(stage, 14 + index * 2) for index in range(4))
    if not all(LOADER_BASE <= entry < 0x3910 for entry in loader_entries):
        raise AssertionError("pack-loader entry escaped its fixed image")

    image = temp / "tls13-286-entropy.bin"
    listing = temp / "tls13-286-entropy.lst"
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{BOOT}/",
            "-l",
            str(listing),
            "-o",
            str(image),
            str(SOURCE),
        ],
        cwd=ROOT,
        check=True,
    )
    controller = image.read_bytes()
    if not CONTROLLER_HEADER_BYTES <= len(controller) <= CONTROLLER_CAPACITY:
        raise AssertionError(
            f"entropy controller is {len(controller)} bytes, capacity is "
            f"{CONTROLLER_CAPACITY}"
        )
    if controller[:8] != CONTROLLER_MAGIC:
        raise AssertionError("entropy-controller magic drifted")
    abi, image_bytes, count = struct.unpack_from("<HHH", controller, 8)
    if (
        abi != ABI_VERSION
        or image_bytes != len(controller)
        or count != CONTROLLER_ENTRY_COUNT
    ):
        raise AssertionError("entropy-controller header geometry drifted")
    entries = tuple(
        u16(controller, 14 + index * 2)
        for index in range(CONTROLLER_ENTRY_COUNT)
    )
    if len(set(entries)) != CONTROLLER_ENTRY_COUNT or not all(
        CONTROLLER_BASE <= entry < CONTROLLER_BASE + len(controller)
        for entry in entries
    ):
        raise AssertionError("entropy-controller entry table is not canonical")

    # The runtime KAT must carry the official input and comparison value, not
    # a host-generated substitute hidden in the checker.
    for name, fixture in (
        ("entropy", KAT_ENTROPY),
        ("nonce", KAT_NONCE),
        ("official second ReturnedBits", KAT_SECOND),
    ):
        if controller.count(fixture) != 1:
            raise AssertionError(
                f"entropy controller must embed exactly one CAVP {name}"
            )
    return Built(
        controller,
        entries,
        stage,
        pack,
        loader_entries,
        bootstrap_parent_sp,
    )


@dataclass(frozen=True)
class ReadyEvent:
    name: str
    write_index: int
    acquire: bytes
    fresh: bytes
    generation_hash: bytes
    status_bytes: bytes


class Machine:
    def __init__(
        self,
        built: Built,
        samples: list[TimedEvent],
        *,
        controller: bytes | None = None,
        rtc_status_a: int = CMOS_32KHZ_1024HZ,
        rtc_status_b: int = 0x02,
    ) -> None:
        self.built = built
        self.controller = built.controller if controller is None else controller
        self.samples = list(samples)
        self.event_index = 0
        self.latches: list[int] = []
        self.latched_bytes: bytes | None = None
        self.latched_index = 0
        self.interrupts: list[int] = []
        self.rtc_index = 0
        self.rtc_status_a = rtc_status_a
        self.rtc_status_b = rtc_status_b
        self.rtc_status_a_writes: list[int] = []
        self.rtc_index_writes: list[int] = []
        self.rtc_c_reads = 0
        self.rtc_drained = False
        self.periodic_poll_count = 0
        self.writes: list[tuple[int, int]] = []
        self.ready_events: list[ReadyEvent] = []
        self.decode_calls = 0
        self.module_calls = 0
        self.raw_at_conditioner: bytes | None = None
        self.health_at_conditioner: bytes | None = None
        self.root_aborted = False
        self.controller_retired_before_abort: bool | None = None
        self.parent_stack_restored = False
        self.chain_calls = 0
        self.chain_kinds: list[int] = []

        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 1024 * 1024)
        self.uc.mem_write(CONTROLLER_BASE, self.controller)
        self.uc.mem_write(LOADER_BASE, built.stage)
        self.uc.mem_write(CRYPTO_BASE, built.pack)
        self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
        self.uc.mem_write(BOOTSTRAP_ABORT_STUB, b"\xF4")
        self.uc.mem_write(CHAIN_RETURN_STUB, b"\x31\xC0\xF8\xC3")
        self.uc.mem_write(ROUTE_MODE, b"\xC3")
        self.uc.mem_write(
            BOOTSTRAP_ABORT_POINTER,
            struct.pack("<H", BOOTSTRAP_ABORT_STUB),
        )
        self.uc.mem_write(
            built.bootstrap_parent_sp, struct.pack("<H", PARENT_ENTRY_SP)
        )
        self.uc.mem_write(
            HANDOFF_RAM_TOP, struct.pack("<H", PARENT_STACK_TOP)
        )
        if self.controller.find(b"S286AB02") >= 0:
            raise AssertionError("entropy redundantly embeds the post-NIC capsule")
        self.root_chain_entry = u16(
            built.stage, ROOT_SERVICE_CHAIN_POINTER - LOADER_BASE
        )
        if not ROOT_SERVICE_TABLE <= self.root_chain_entry < 0x3C00:
            raise AssertionError(
                "root component-chain service pointer escaped root image"
            )
        protected = bytes(
            (index * 37 + 11) & 0xFF for index in range(PROTECTED_BYTES)
        )
        self.uc.mem_write(PROTECTED_START, protected)
        self.original_protected = protected
        self.uc.mem_write(ROOT_STATE_MODE, b"\x01")
        self.uc.mem_write(
            ROOT_STATE_CRYPTO_SEG, struct.pack("<H", CRYPTO_SEG)
        )
        self.uc.mem_write(
            LOADER_STATE_CACHE_SEG, struct.pack("<H", CRYPTO_SEG)
        )
        self.uc.mem_write(
            LOADER_STATE_CACHE_CAPACITY, struct.pack("<H", PACK_BYTES)
        )
        self.uc.mem_write(
            CRYPTO_BASE + ESCROW_CRYPTO_SEG_OFF,
            struct.pack("<H", CRYPTO_SEG),
        )
        self.uc.mem_write(
            CRYPTO_BASE + ESCROW_STATUS_INV_OFF, b"\x5A\xA5"
        )
        self.uc.mem_write(
            FOOTER, b"S286TL02" + bytes(512 - len(b"S286TL02"))
        )

        self.shadow = bytearray(self.uc.mem_read(0, 1024 * 1024))
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt)
        self.uc.hook_add(
            UC_HOOK_INSN, self._in_hook, None, 1, 0, UC_X86_INS_IN
        )
        self.uc.hook_add(
            UC_HOOK_INSN, self._out_hook, None, 1, 0, UC_X86_INS_OUT
        )
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write_hook)
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self._validate_pack()
        self.writes.clear()
        self.ready_events.clear()
        self.shadow[:] = self.uc.mem_read(0, 1024 * 1024)

    def _validate_pack(self) -> None:
        self._call_address(
            self.built.loader_entries[LOADER_VALIDATE_INDEX],
            bx=LOADER_STATE,
            expect_success=True,
            instruction_limit=30_000_000,
        )
        if u16(
            bytes(self.uc.mem_read(LOADER_STATE_PACK_BYTES, 2)), 0
        ) != PACK_BYTES:
            raise AssertionError("pack loader did not publish exact cached size")
        if bytes(self.uc.mem_read(CRYPTO_BASE, PACK_BYTES)) != self.built.pack:
            raise AssertionError("pack validation changed cached pack bytes")
        if any(self.uc.mem_read(MODULE_BASE, MODULE_LIMIT - MODULE_BASE)):
            raise AssertionError("pack validation left module overlay live")

    def _code_hook(
        self, uc: Uc, address: int, size: int, user_data: object
    ) -> None:
        del size, user_data
        if address == BOOTSTRAP_ABORT_STUB:
            self.root_aborted = True
            self.parent_stack_restored = (
                uc.reg_read(UC_X86_REG_SP) & 0xFFFF
            ) == PARENT_ENTRY_SP
            self.controller_retired_before_abort = not any(
                uc.mem_read(
                    CONTROLLER_BASE, CONTROLLER_LIMIT - CONTROLLER_BASE
                )
            )
            low_limit = 0x8000 if self.parent_stack_restored else MODULE_LIMIT
            if any(uc.mem_read(MODULE_BASE, low_limit - MODULE_BASE)):
                raise AssertionError(
                    "root abort reached bootstrap with low private state live"
                )
            uc.mem_write(LOADER_BASE, bytes(0x3C00 - LOADER_BASE))
            uc.mem_write(HANDOFF_START, bytes(MODULE_BASE - HANDOFF_START))
            uc.mem_write(CRYPTO_BASE, bytes(HIGH_RESERVE_BYTES))
            # The real bootstrap abort always restores the frozen resident
            # caller SP after escrow/high-state cleanup.  Private entropy
            # failures arrive here on that stack already; pre-private aborts
            # may still arrive on the temporary tail stack.
            uc.reg_write(UC_X86_REG_SP, PARENT_ENTRY_SP)
            self._near_return(carry=True)
        elif address == ROUTE_MODE:
            if self.root_aborted:
                self.controller_retired_before_abort = not any(
                    uc.mem_read(
                        CONTROLLER_BASE, CONTROLLER_LIMIT - CONTROLLER_BASE
                    )
                )
        elif address == self.built.loader_entries[LOADER_DECODE_INDEX]:
            if (uc.reg_read(UC_X86_REG_AX) & 0xFFFF) != (
                MODULE_KIND_MLKEM_KEYGEN
            ):
                raise AssertionError("controller decoded the wrong module kind")
            self.decode_calls += 1
            self.health_at_conditioner = bytes(
                uc.mem_read(HEALTH, HEALTH_BYTES)
            )
        elif address == self.built.loader_entries[LOADER_CALL_INDEX]:
            if (uc.reg_read(UC_X86_REG_AX) & 0xFFFF) != (
                MODULE_OP_SHA3_CONDITION
            ):
                raise AssertionError("controller invoked the wrong module op")
            self.module_calls += 1
            self.raw_at_conditioner = bytes(
                uc.mem_read(RAW, RAW_BYTES)
            )
        elif address == self.root_chain_entry:
            kind = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            if kind != TAIL_KIND_ACQUIRE:
                raise AssertionError(
                    f"entropy controller chained tail kind {kind}, "
                    f"expected {TAIL_KIND_ACQUIRE}"
                )
            self.chain_calls += 1
            self.chain_kinds.append(kind)
            uc.reg_write(UC_X86_REG_IP, CHAIN_RETURN_STUB)

    def _near_return(self, *, carry: bool) -> None:
        sp = self.uc.reg_read(UC_X86_REG_SP) & 0xFFFF
        ip = int.from_bytes(self.uc.mem_read(sp, 2), "little")
        self.uc.reg_write(UC_X86_REG_SP, (sp + 2) & 0xFFFF)
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        flags = (flags | 1) if carry else (flags & ~1)
        flags &= ~0x0400
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags)
        self.uc.reg_write(UC_X86_REG_DS, 0)
        self.uc.reg_write(UC_X86_REG_ES, 0)
        self.uc.reg_write(UC_X86_REG_IP, ip)

    def _write_hook(
        self,
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        self.writes.append((address, size))
        if size > 8:
            raise AssertionError(f"unexpected {size}-byte x86 memory write")
        mask = (1 << (size * 8)) - 1
        self.shadow[address : address + size] = (
            int(value) & mask
        ).to_bytes(size, "little")
        status_map = (
            ("acquire", ACQUIRE_STATUS_INV, ACQUIRE_STATUS),
            ("fresh", FRESH_STATUS_INV, FRESH_STATUS),
            ("root", ROOT_STATUS_INV, ROOT_STATUS),
        )
        for name, inverse, status in status_map:
            if address >= status + 1 or address + size <= inverse:
                continue
            if (
                self.shadow[inverse] == STATUS_READY_INV
                and self.shadow[status] == STATUS_READY
            ):
                self.ready_events.append(
                    ReadyEvent(
                        name,
                        len(self.writes) - 1,
                        bytes(
                            self.shadow[
                                ATTEMPT_ACQUIRE : ATTEMPT_ACQUIRE
                                + ATTEMPT_BYTES
                            ]
                        ),
                        bytes(
                            self.shadow[
                                ATTEMPT_FRESH : ATTEMPT_FRESH + ATTEMPT_BYTES
                            ]
                        ),
                        bytes(
                            self.shadow[
                                GENERATION_HASH : GENERATION_HASH
                                + GENERATION_HASH_BYTES
                            ]
                        ),
                        bytes(
                            self.shadow[ROOT_STATUS_INV:PUBLICATION_END]
                        ),
                    )
                )

    def _out_hook(
        self,
        _uc: Uc,
        port: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        if size != 1:
            raise AssertionError(
                f"unexpected OUT port={port:04x} size={size} value={value:02x}"
            )
        if port == CMOS_INDEX:
            if value & 0x80:
                raise AssertionError("entropy collection disabled NMI")
            self.rtc_index = value & 0x7F
            self.rtc_index_writes.append(self.rtc_index)
            return
        if port == CMOS_DATA:
            if self.rtc_index != CMOS_STATUS_A:
                raise AssertionError(
                    f"entropy wrote unexpected CMOS register {self.rtc_index:02x}"
                )
            self.rtc_status_a = value & 0x7F
            self.rtc_status_a_writes.append(self.rtc_status_a)
            return
        if port != 0x43 or value != 0:
            raise AssertionError(
                f"unexpected OUT port={port:04x} size={size} value={value:02x}"
            )
        if (
            self.latched_bytes is not None
            and self.latched_index != len(self.latched_bytes)
        ):
            raise AssertionError("PIT relatched before both bytes were consumed")
        sample_index = len(self.latches) // 2
        if sample_index >= len(self.samples):
            raise AssertionError("controller requested timing beyond fixture")
        sample = self.samples[sample_index]
        value16 = sample.before if len(self.latches) % 2 == 0 else sample.after
        self.latches.append(value16)
        self.latched_bytes = struct.pack("<H", value16)
        self.latched_index = 0

    def _in_hook(
        self, _uc: Uc, port: int, size: int, _user: object
    ) -> int:
        if size != 1:
            raise AssertionError(f"unexpected IN port={port:04x} size={size}")
        if port == CMOS_DATA:
            if self.rtc_index == CMOS_STATUS_A:
                return self.rtc_status_a
            if self.rtc_index == CMOS_STATUS_B:
                return self.rtc_status_b
            if self.rtc_index != CMOS_STATUS_C:
                raise AssertionError(
                    f"entropy read unexpected CMOS register {self.rtc_index:02x}"
                )
            self.rtc_c_reads += 1
            if not self.rtc_drained:
                self.rtc_drained = True
                return 0
            if self.event_index >= len(self.samples):
                raise AssertionError("controller requested timing beyond fixture")
            sample = self.samples[self.event_index]
            self.periodic_poll_count += 1
            if sample.fail:
                return 0
            polls_required = 1 + ((self.event_index * 3) % 5)
            if self.periodic_poll_count < polls_required:
                return 0
            self.periodic_poll_count = 0
            self.event_index += 1
            return CMOS_PERIODIC
        if port != 0x40:
            raise AssertionError(f"unexpected IN port={port:04x} size={size}")
        if self.latched_bytes is None or self.latched_index >= 2:
            raise AssertionError("PIT byte read without a fresh latch")
        value = self.latched_bytes[self.latched_index]
        self.latched_index += 1
        return value

    def _interrupt(self, uc: Uc, number: int, _user: object) -> None:
        del uc
        self.interrupts.append(number)
        raise AssertionError(
            f"silent entropy collection invoked BIOS interrupt {number:02x}"
        )

    def _call_address(
        self,
        address: int,
        *,
        ax: int = 0,
        bx: int = CRYPTO_SEG,
        si: int = FOOTER_OFF,
        expect_success: bool,
        instruction_limit: int = 600_000_000,
    ) -> int:
        self.uc.mem_write(
            STACK_TOP - 2, RETURN_SENTINEL.to_bytes(2, "little")
        )
        self.uc.mem_write(
            PARENT_ENTRY_SP, RETURN_SENTINEL.to_bytes(2, "little")
        )
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        self.uc.reg_write(UC_X86_REG_IP, address)
        self.uc.reg_write(UC_X86_REG_AX, ax)
        self.uc.reg_write(UC_X86_REG_BX, bx)
        self.uc.reg_write(UC_X86_REG_SI, si)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0402)
        try:
            self.uc.emu_start(
                address,
                RETURN_SENTINEL,
                count=instruction_limit,
            )
        except UcError as error:
            ip = self.uc.reg_read(UC_X86_REG_IP)
            raise AssertionError(
                f"entropy controller failed at {ip:04x}: {error}"
            ) from error
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        carry = bool(flags & 1)
        result = self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        if carry == expect_success:
            expected = "success" if expect_success else "failure"
            raise AssertionError(
                f"entropy entry {address:04x} did not return {expected}: "
                f"CF={int(carry)} AX={result:04x}"
            )
        if expect_success and result != 0:
            raise AssertionError(
                f"successful entropy entry returned AX={result:04x}"
            )
        if not expect_success and result == 0 and not self.root_aborted:
            raise AssertionError("failed entropy entry returned zero error")
        if flags & 0x0400:
            raise AssertionError("entropy entry returned with DF set")
        if self.uc.reg_read(UC_X86_REG_DS) or self.uc.reg_read(UC_X86_REG_ES):
            raise AssertionError("entropy entry did not restore DS=ES=0")
        return result

    def call(
        self,
        entry_index: int,
        *,
        ax: int = 0,
        expect_success: bool,
        instruction_limit: int = 600_000_000,
    ) -> int:
        return self._call_address(
            self.built.entries[entry_index],
            ax=ax,
            expect_success=expect_success,
            instruction_limit=instruction_limit,
        )

    def assert_controller_restored(self) -> None:
        actual = bytes(
            self.uc.mem_read(CONTROLLER_BASE, len(self.controller))
        )
        if actual != self.controller:
            raise AssertionError(
                "controller did not scrub mutable state back to image zeros"
            )

    def assert_pack_and_guards(self) -> None:
        if bytes(self.uc.mem_read(CRYPTO_BASE, PACK_BYTES)) != self.built.pack:
            raise AssertionError("entropy path changed authenticated pack cache")
        if any(self.uc.mem_read(MODULE_BASE, MODULE_LIMIT - MODULE_BASE)):
            raise AssertionError("entropy path left executable module bytes live")
        if any(self.uc.mem_read(RAW, RAW_BYTES)):
            raise AssertionError("entropy path left raw timing events live")
        if any(self.uc.mem_read(CONDITIONED, CONDITIONED_BYTES)):
            raise AssertionError("entropy path left conditioned seed live")
        if any(self.uc.mem_read(HEALTH, HEALTH_BYTES)):
            raise AssertionError("entropy path left health work state live")
        if any(self.uc.mem_read(DRBG_K, 32)):
            raise AssertionError("entropy path left HMAC_DRBG K live")
        if any(self.uc.mem_read(DRBG_V, 32)):
            raise AssertionError("entropy path left HMAC_DRBG V live")
        if any(self.uc.mem_read(DRBG_WORK, 64)):
            raise AssertionError("entropy path left HMAC_DRBG work live")

    def assert_root_aborted(self, *, require_parent_stack: bool = False) -> None:
        if not self.root_aborted:
            raise AssertionError("fatal entropy path bypassed root abort")
        if require_parent_stack and not self.parent_stack_restored:
            raise AssertionError(
                "private entropy abort bypassed validated parent stack bridge"
            )
        if self.controller_retired_before_abort is not True:
            raise AssertionError(
                "root abort left decoded entropy controller executable"
            )
        if any(
            self.uc.mem_read(
                CONTROLLER_BASE, CONTROLLER_LIMIT - CONTROLLER_BASE
            )
        ):
            raise AssertionError("root abort left controller window live")
        if any(self.uc.mem_read(LOADER_BASE, 0x3C00 - LOADER_BASE)):
            raise AssertionError("bootstrap abort left root stage live")
        if any(self.uc.mem_read(HANDOFF_START, MODULE_BASE - HANDOFF_START)):
            raise AssertionError("abort left controller handoff live")
        if any(self.uc.mem_read(CRYPTO_BASE, HIGH_RESERVE_BYTES)):
            raise AssertionError("bootstrap abort left high crypto state live")
        if any(self.uc.mem_read(MODULE_BASE, MODULE_LIMIT - MODULE_BASE)):
            raise AssertionError("root abort left module overlay live")
        if (
            bytes(self.uc.mem_read(PROTECTED_START, PROTECTED_BYTES))
            != self.original_protected
        ):
            raise AssertionError("root abort changed protected resident state")
        if self.uc.reg_read(UC_X86_REG_DS) or self.uc.reg_read(UC_X86_REG_ES):
            raise AssertionError("root abort did not restore DS=ES=0")

    def assert_failed_state(self) -> None:
        self.assert_controller_restored()
        self.assert_pack_and_guards()
        if any(self.uc.mem_read(PREVIOUS_HASH, PREVIOUS_HASH_BYTES)):
            raise AssertionError("failed entropy path left replay hash live")
        if any(
            self.uc.mem_read(
                ATTEMPT_ACQUIRE, PUBLICATION_END - ATTEMPT_ACQUIRE
            )
        ):
            raise AssertionError("failed entropy path exposed attempt state")

    def assert_write_bounds(self) -> None:
        allowed = (
            (CONTROLLER_BASE, CONTROLLER_LIMIT),
            (LOADER_BASE, 0x3C00),
            (ROOT_STATE, ROOT_STATE + 32),
            (MODULE_BASE, 0x8000),
            (PARENT_ENTRY_SP - 2, PARENT_STACK_TOP),
            (RAW, RAW + RAW_BYTES),
            (CONDITIONED, CONDITIONED + CONDITIONED_BYTES),
            (PREVIOUS_HASH, PREVIOUS_HASH + PREVIOUS_HASH_BYTES),
            (HEALTH, HEALTH + HEALTH_BYTES),
            (ATTEMPT_ACQUIRE, PUBLICATION_END),
        )
        bad = [
            (address, size)
            for index, (address, size) in enumerate(self.writes)
            if not any(
                interval_contains(region, address, size)
                for region in allowed
            )
        ]
        if bad:
            address, size = bad[0]
            raise AssertionError(
                f"entropy controller escaped write contract at "
                f"{address:05x}+{size}"
            )


def assert_ready_publication(
    machine: Machine,
    *,
    acquire: bytes,
    fresh: bytes,
    generation_hash: bytes,
) -> None:
    if [event.name for event in machine.ready_events] != [
        "acquire",
        "fresh",
        "root",
    ]:
        raise AssertionError(
            "status-last publication order drifted: "
            f"{[event.name for event in machine.ready_events]!r}"
        )
    acquire_event, fresh_event, root_event = machine.ready_events
    if acquire_event.acquire != acquire:
        raise AssertionError("acquire status became ready before full bundle")
    if fresh_event.acquire != acquire or fresh_event.fresh != fresh:
        raise AssertionError("fresh status became ready before both bundles")
    if (
        root_event.acquire != acquire
        or root_event.fresh != fresh
        or root_event.generation_hash != generation_hash
    ):
        raise AssertionError("root status became ready before full publication")
    expected_statuses = bytes(
        (
            STATUS_READY_INV,
            STATUS_READY,
            STATUS_READY_INV,
            STATUS_READY,
            STATUS_READY_INV,
            STATUS_READY,
        )
    )
    if root_event.status_bytes != expected_statuses:
        raise AssertionError("root-ready status/inverse publication drifted")


def assert_health_publication(
    machine: Machine, samples: list[TimedEvent]
) -> None:
    health = machine.health_at_conditioner
    if health is None:
        raise AssertionError("controller did not publish health before conditioning")
    symbols = [sample.symbol for sample in samples]
    final_run = 1
    for index in range(len(symbols) - 1, 0, -1):
        if symbols[index - 1] != symbols[-1]:
            break
        final_run += 1
    expected = bytearray(HEALTH_BYTES)
    expected[:8] = b"E286H001"
    struct.pack_into(
        "<HHHHHHHHB",
        expected,
        8,
        SAMPLES_REQUIRED,
        RCT_CUTOFF,
        APT_WINDOW,
        APT_CUTOFF,
        symbols[-1],
        final_run,
        0,
        0,
        0,
    )
    if health != expected:
        raise AssertionError(
            "published health mechanics/status differs from host oracle"
        )


def healthy_apt_window(reference: int, reference_count: int) -> list[int]:
    if not 1 <= reference_count < APT_CUTOFF:
        raise ValueError("passing APT reference count is out of range")
    symbols = [reference]
    remaining_reference = reference_count - 1
    for index in range(1, APT_WINDOW):
        slots_left = APT_WINDOW - index
        if remaining_reference and (
            index % 4 != 0 or remaining_reference >= slots_left
        ):
            symbols.append(reference)
            remaining_reference -= 1
        else:
            symbols.append((reference + index + 1) & 0xFF)
    if symbols.count(reference) != reference_count:
        raise AssertionError("APT passing fixture construction drifted")
    return symbols


def failing_apt_window(reference: int) -> list[int]:
    # Exactly 112 non-reference symbols at indices 4,8,...,448 leave 400
    # references.  The 400th arrives at sample 512, while the final reference
    # run is 63 and therefore remains below the RCT cutoff.
    symbols = [reference] * APT_WINDOW
    for index in range(4, 449, 4):
        symbols[index] = (reference + index + 1) & 0xFF
    if (
        symbols.count(reference) != APT_CUTOFF
        or max(
            len(run)
            for run in "".join(
                "R" if value == reference else "X" for value in symbols
            ).split("X")
        )
        >= RCT_CUTOFF
    ):
        raise AssertionError("APT failing fixture construction drifted")
    return symbols


def run_health_checks(built: Built) -> None:
    machine = Machine(built, [])
    machine.call(1, expect_success=True)
    passing = healthy_apt_window(0x5A, APT_CUTOFF - 1)
    for symbol in passing:
        machine.call(2, ax=symbol, expect_success=True)
    # APT windows are non-overlapping.  The next sample is a new reference.
    machine.call(2, ax=0xA6, expect_success=True)
    machine.call(4, expect_success=False)
    machine.assert_root_aborted()

    rct = Machine(built, [])
    rct.call(1, expect_success=True)
    for _ in range(RCT_CUTOFF - 1):
        rct.call(2, ax=0x33, expect_success=True)
    rct.call(2, ax=0x33, expect_success=False)
    rct.call(2, ax=0x44, expect_success=False)
    rct.call(4, expect_success=False)
    rct.assert_root_aborted()

    apt = Machine(built, [])
    apt.call(1, expect_success=True)
    failing = failing_apt_window(0x71)
    for symbol in failing[:-1]:
        apt.call(2, ax=symbol, expect_success=True)
    apt.call(2, ax=failing[-1], expect_success=False)
    apt.call(2, ax=0x22, expect_success=False)
    apt.call(4, expect_success=False)
    apt.assert_root_aborted()


def run_kat_checks(built: Built) -> None:
    machine = Machine(built, [])
    before = bytes(
        machine.uc.mem_read(CRYPTO_BASE + PACK_BYTES, HIGH_RESERVE_BYTES - PACK_BYTES)
    )
    machine.call(3, expect_success=True)
    after = bytes(
        machine.uc.mem_read(CRYPTO_BASE + PACK_BYTES, HIGH_RESERVE_BYTES - PACK_BYTES)
    )
    if after != before:
        raise AssertionError("standalone DRBG KAT changed product high state")
    if machine.interrupts or machine.decode_calls or machine.module_calls:
        raise AssertionError("standalone DRBG KAT touched BIOS/module boundary")
    machine.assert_controller_restored()
    machine.assert_pack_and_guards()

    # Flip the unique official comparison value.  Both the explicit KAT and
    # main entry must fail before touching the physical-source boundary.
    offset = built.controller.find(KAT_SECOND)
    if offset < 0 or built.controller.find(KAT_SECOND, offset + 1) >= 0:
        raise AssertionError("cannot identify unique embedded KAT comparison")
    bad_controller = bytearray(built.controller)
    bad_controller[offset] ^= 1
    bad = Machine(built, [], controller=bytes(bad_controller))
    bad.call(3, expect_success=False)
    bad.assert_failed_state()
    bad_main = Machine(built, [], controller=bytes(bad_controller))
    bad_main.call(0, ax=1, expect_success=False)
    if bad_main.event_index or bad_main.rtc_c_reads or bad_main.interrupts:
        raise AssertionError("main path touched the timing source after KAT failure")
    bad_main.assert_root_aborted(require_parent_stack=True)


def run_main_checks(built: Built) -> None:
    samples = healthy_samples()
    raw = raw_events(samples)
    (
        conditioned,
        acquire,
        fresh,
        conditioned_hash,
        generation_hash,
    ) = expected_attempts(raw)
    machine = Machine(built, samples)
    machine.call(0, ax=1, expect_success=True)
    if machine.chain_calls != 1 or machine.chain_kinds != [TAIL_KIND_ACQUIRE]:
        raise AssertionError(
            "successful entropy path did not chain exactly once to acquisition"
        )
    if machine.event_index != SAMPLES_REQUIRED:
        raise AssertionError("main path did not collect exactly 1,024 RTC events")
    if len(machine.latches) != SAMPLES_REQUIRED * 2:
        raise AssertionError("main path did not make two PIT latches per RTC edge")
    if machine.interrupts:
        raise AssertionError("silent entropy path invoked a BIOS service")
    if machine.rtc_status_a_writes != [
        CMOS_32KHZ_4096HZ,
        CMOS_32KHZ_1024HZ,
    ]:
        raise AssertionError(
            "main path did not select and restore the RTC periodic rate"
        )
    if any(
        index not in {CMOS_STATUS_A, CMOS_STATUS_B, CMOS_STATUS_C}
        for index in machine.rtc_index_writes
    ):
        raise AssertionError("main path escaped RTC status registers A/B/C")
    if machine.raw_at_conditioner != raw:
        raise AssertionError("target event capture differs from host raw oracle")
    if machine.decode_calls != 1 or machine.module_calls != 1:
        raise AssertionError("main path did not use conditioner module exactly once")
    if bytes(machine.uc.mem_read(ATTEMPT_ACQUIRE, ATTEMPT_BYTES)) != acquire:
        raise AssertionError("acquisition attempt differs from HMAC_DRBG oracle")
    if bytes(machine.uc.mem_read(ATTEMPT_FRESH, ATTEMPT_BYTES)) != fresh:
        raise AssertionError("fresh attempt differs from HMAC_DRBG oracle")
    if acquire == fresh:
        raise AssertionError("sequential attempt bundles repeated")
    for field in range(0, ATTEMPT_BYTES, 32):
        if acquire[field : field + 32] == fresh[field : field + 32]:
            raise AssertionError("attempt subfield repeated across connections")
    if bytes(
        machine.uc.mem_read(GENERATION_HASH, GENERATION_HASH_BYTES)
    ) != generation_hash:
        raise AssertionError("generation hash differs from host SHA-256 oracle")
    if bytes(
        machine.uc.mem_read(PREVIOUS_HASH, PREVIOUS_HASH_BYTES)
    ) != conditioned_hash:
        raise AssertionError("same-boot replay hash was not published")
    if conditioned == bytes(CONDITIONED_BYTES):
        raise AssertionError("conditioner host oracle unexpectedly returned zero")
    assert_ready_publication(
        machine,
        acquire=acquire,
        fresh=fresh,
        generation_hash=generation_hash,
    )
    machine.assert_controller_restored()
    machine.assert_pack_and_guards()
    assert_health_publication(machine, samples)
    machine.assert_write_bounds()

    # Reentry must reject without another oscillator sample and retire the formerly
    # published attempt state, rather than leaving stale bytes consumable.
    events = machine.event_index
    machine.call(0, ax=1, expect_success=False)
    if machine.event_index != events:
        raise AssertionError("root-ready reentry touched the timing source")
    machine.assert_root_aborted()

    # A distinct transcript must produce distinct conditioned and attempt
    # bytes while preserving the same mechanics.
    diverse_samples = healthy_samples(timing_bias=23)
    diverse_raw = raw_events(diverse_samples)
    diverse_expected = expected_attempts(diverse_raw)
    diverse = Machine(built, diverse_samples)
    diverse.call(0, ax=0, expect_success=True)
    if diverse.chain_calls != 1:
        raise AssertionError("diverse entropy path did not chain to acquisition")
    if (
        bytes(diverse.uc.mem_read(ATTEMPT_ACQUIRE, ATTEMPT_BYTES))
        != diverse_expected[1]
        or bytes(diverse.uc.mem_read(ATTEMPT_FRESH, ATTEMPT_BYTES))
        != diverse_expected[2]
    ):
        raise AssertionError("diverse attempt publication differs from oracle")
    if diverse_expected[1:3] == (acquire, fresh):
        raise AssertionError("different timing transcript repeated attempts")
    if diverse.rtc_status_a != CMOS_32KHZ_1024HZ:
        raise AssertionError("diverse path did not restore RTC Status A")
    diverse.assert_controller_restored()
    diverse.assert_pack_and_guards()
    diverse.assert_write_bounds()

def run_failure_checks(built: Built) -> None:
    samples = healthy_samples()

    wrong_divider = Machine(built, [], rtc_status_a=0x16)
    wrong_divider.call(0, ax=1, expect_success=False)
    if (
        wrong_divider.event_index
        or wrong_divider.latches
        or wrong_divider.rtc_status_a_writes
    ):
        raise AssertionError("wrong RTC divider reached the sampling boundary")
    wrong_divider.assert_root_aborted(require_parent_stack=True)
    wrong_divider.assert_write_bounds()

    irq_enabled = Machine(built, [], rtc_status_b=0x42)
    irq_enabled.call(0, ax=1, expect_success=False)
    if irq_enabled.event_index or irq_enabled.latches:
        raise AssertionError("PIE-enabled RTC reached the polling boundary")
    irq_enabled.assert_root_aborted(require_parent_stack=True)
    irq_enabled.assert_write_bounds()

    failed_events = list(samples)
    failed_events[19] = replace(failed_events[19], fail=True)
    failed = Machine(built, failed_events)
    failed.call(0, ax=1, expect_success=False)
    if failed.chain_calls:
        raise AssertionError("failed entropy source reached acquisition")
    if failed.event_index != 19 or len(failed.latches) != 39:
        raise AssertionError("RTC timeout did not stop before the after-edge latch")
    if failed.rtc_status_a != CMOS_32KHZ_1024HZ:
        raise AssertionError("RTC timeout did not restore Status A")
    if failed.rtc_status_a_writes != [
        CMOS_32KHZ_4096HZ,
        CMOS_32KHZ_1024HZ,
    ]:
        raise AssertionError("RTC timeout rate-select/restore sequence drifted")
    failed.assert_root_aborted(require_parent_stack=True)
    failed.assert_write_bounds()

    stuck = Machine(
        built,
        samples_for_symbols([0x5A] * SAMPLES_REQUIRED),
    )
    stuck.call(0, ax=1, expect_success=False)
    if stuck.chain_calls:
        raise AssertionError("RCT failure reached acquisition")
    if stuck.event_index != RCT_CUTOFF:
        raise AssertionError("main-path RCT cutoff drifted")
    stuck.assert_root_aborted(require_parent_stack=True)
    stuck.assert_write_bounds()

    apt_symbols = failing_apt_window(0x71) + [
        (index * 17 + 3) & 0xFF
        for index in range(SAMPLES_REQUIRED - APT_WINDOW)
    ]
    apt = Machine(built, samples_for_symbols(apt_symbols))
    apt.call(0, ax=1, expect_success=False)
    if apt.chain_calls:
        raise AssertionError("APT failure reached acquisition")
    if apt.event_index != APT_WINDOW:
        raise AssertionError("main-path APT cutoff drifted")
    apt.assert_root_aborted(require_parent_stack=True)
    apt.assert_write_bounds()

    # A CRC-protected module payload changed after whole-pack validation must
    # fail in the actual loader/module transition and expose no derived bytes.
    corrupted = Machine(built, samples)
    first_payload_off = int.from_bytes(built.pack[36:40], "little")
    original_payload_byte = built.pack[first_payload_off]
    corrupted.uc.mem_write(
        CRYPTO_BASE + first_payload_off,
        bytes((original_payload_byte ^ 1,)),
    )
    corrupted.shadow[:] = corrupted.uc.mem_read(0, 1024 * 1024)
    corrupted.call(0, ax=1, expect_success=False)
    if corrupted.module_calls:
        raise AssertionError("corrupt conditioner module was invoked")
    corrupted.assert_root_aborted(require_parent_stack=True)
    corrupted.assert_write_bounds()

    # Any preexisting READY root/attempt marker is a duplicate-root/reuse
    # condition.  It must be rejected before collection and wiped.
    for name, inverse, status in (
        ("root", ROOT_STATUS_INV, ROOT_STATUS),
        ("acquire", ACQUIRE_STATUS_INV, ACQUIRE_STATUS),
        ("fresh", FRESH_STATUS_INV, FRESH_STATUS),
    ):
        reused = Machine(built, [])
        reused.uc.mem_write(inverse, bytes((STATUS_READY_INV, STATUS_READY)))
        reused.uc.mem_write(ATTEMPT_ACQUIRE, b"\xA7" * ATTEMPT_BYTES)
        reused.shadow[:] = reused.uc.mem_read(0, 1024 * 1024)
        reused.call(0, ax=1, expect_success=False)
        if reused.event_index or reused.rtc_c_reads:
            raise AssertionError(f"{name} reuse rejection touched the timing source")
        reused.assert_root_aborted(require_parent_stack=True)

    # An otherwise-clear root with the same generation hash must collect and
    # derive, but reject before any status publication.
    raw = raw_events(samples)
    conditioned_hash = expected_attempts(raw)[3]
    replay = Machine(built, samples)
    replay.uc.mem_write(PREVIOUS_HASH, conditioned_hash)
    replay.shadow[:] = replay.uc.mem_read(0, 1024 * 1024)
    replay.call(0, ax=1, expect_success=False)
    if replay.event_index != SAMPLES_REQUIRED:
        raise AssertionError("same-transcript replay rejected before comparison")
    if replay.ready_events:
        raise AssertionError("same-transcript replay published a READY marker")
    replay.assert_root_aborted(require_parent_stack=True)
    replay.assert_write_bounds()

    abort = Machine(built, [])
    poison_start = PREVIOUS_HASH
    poison_bytes = PUBLICATION_END - poison_start
    abort.uc.mem_write(poison_start, b"\xD7" * poison_bytes)
    abort.uc.mem_write(RAW, b"\xD8" * RAW_BYTES)
    abort.uc.mem_write(CONDITIONED, b"\xDA" * CONDITIONED_BYTES)
    abort.uc.mem_write(HEALTH, b"\xDB" * HEALTH_BYTES)
    abort.shadow[:] = abort.uc.mem_read(0, 1024 * 1024)
    abort.call(4, expect_success=False)
    abort.assert_root_aborted()
    abort.assert_write_bounds()


def main() -> None:
    assert_host_kat()
    with tempfile.TemporaryDirectory(prefix="seed-286-entropy-") as raw:
        built = build_images(Path(raw))
        run_health_checks(built)
        run_kat_checks(built)
        run_main_checks(built)
        run_failure_checks(built)
    print("TLS13 286 ENTROPY CONTROLLER PASS")
    print(
        "  1024 silent RTC-periodic/PIT events + bounded source + exact raw oracle PASS"
    )
    print("  injectable provisional RCT64 + non-overlap APT512/C400 PASS")
    print("  actual cached MLKEMKG SHA3 conditioner + host oracle PASS")
    print("  official NIST CAVP SHA-256 HMAC_DRBG KAT PASS")
    print("  two sequential 160-byte status-last publications PASS")
    print("  replay/reentry/failure/abort wipe and bounds matrix PASS")
    print("  emulator entropy credit=0; physical characterization pending")


if __name__ == "__main__":
    main()
