#!/usr/bin/env python3
"""Executable restore/retirement gate for the TLS 1.3 286 abort capsule."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
import subprocess
import sys

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
BUILD = ROOT / "build/ibm_pc_5150"
BUILDER = HERE / "build_286_hello_controller.py"
CAPSULE = BUILD / "tls13-286-abort-capsule.bin"
CORE = BUILD / "tls13-286-tail-base/SEED.SYS"
RUNTIME_ABI = BUILD / "tls13-286-runtime-abi.inc"

CAPSULE_LOAD = 0x4040
CAPSULE_LIMIT = 0x4230
CAPSULE_CRYPTO_SEG = CAPSULE_LIMIT - 4
CAPSULE_CRYPTO_SEG_INVERSE = CAPSULE_LIMIT - 2
CONTROLLER_START = 0x1800
ROOT_END = 0x3C00
HANDOFF_START = 0x4000
MODULE_START = 0x4230
MODULE_END = 0x7A00
ROOT_STATE_MODE = 0x4020
ROOT_STATE_CRYPTO_SEG = 0x4022
ROOT_PARENT_SP = 0x4036
ROOT_PARENT_SP_INVERSE = 0x4038
ROOT_PARENT_STATUS_INV = 0x403A
BDA_MEMORY_KB = 0x0413
HANDOFF_STATUS = 0x0619
DPI_REACHED = 0x3CA2

CRYPTO_SEG = 0x7000
CRYPTO_BASE = CRYPTO_SEG << 4
HIGH_BYTES = 64 * 1024
SHADOW_BYTES = 16 + 29 * 512
SHADOW_BASE = CRYPTO_BASE - SHADOW_BYTES
SHADOW_DATA_OFF = 16
SHADOW_DATA_BYTES = 29 * 512
LOOP_CACHE_START = 0x4000
LOOP_CACHE_END = 0x7A00
LOOP_CACHE_ENTRIES = 5
CONFIG_OFF = 0xA31C
CONFIG_SOURCE = 0x3B9C
CONFIG_BYTES = 0x0464
LOW_OFF = 0xB552
LOW_SOURCE = 0x0F33
LOW_BYTES = 0x00AF
PROMPT_OFF = 0xB882
PROMPT_SOURCE = 0x36C2
PROMPT_BYTES = 255
PROMPT_LEN_OFF = 0xB981
PROMPT_LEN_SOURCE = 0x37C1
META_OFF = 0xB862
MAGIC_OFF = META_OFF
MAGIC_INV_OFF = META_OFF + 4
CONFIG_CRC_OFF = META_OFF + 8
LOW_CRC_OFF = META_OFF + 10
MODE_OFF = META_OFF + 12
CRYPTO_SEG_OFF = META_OFF + 14
PROMPT_CRC_OFF = META_OFF + 16
PROMPT_LEN_META_OFF = META_OFF + 18
PROMPT_LEN_INV_OFF = META_OFF + 19
PRESERVE_CRC_OFF = META_OFF + 20
STATUS_INV_OFF = META_OFF + 30
STATUS_OFF = META_OFF + 31
APP_STATE_START = 0x3600
APP_STATE_END = 0x3668
APP_READY = 0x06C4

RETURN_SENTINEL = 0x0200
STACK_TOP = 0x7FFE
PARENT_STACK_TOP = 0xFFF0
PARENT_ENTRY_SP = PARENT_STACK_TOP - 2


def defines(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "%define":
            result[fields[1]] = int(fields[2], 0)
    return result


RUNTIME = defines(RUNTIME_ABI)


def crc16(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = (
                ((value << 1) ^ 0x1021) & 0xFFFF
                if value & 0x8000
                else (value << 1) & 0xFFFF
            )
    return value


@dataclass(frozen=True)
class Fixture:
    image: bytes
    abort_entry: int
    success_entry: int
    memory: bytes
    original_config: bytes
    original_low: bytes
    original_prompt: bytes
    original_protected: bytes
    original_app: bytes
    original_cache: bytes
    original_shadow: bytes


def make_pattern(length: int, multiplier: int, bias: int) -> bytes:
    return bytes((index * multiplier + bias) & 0xFF for index in range(length))


def build_fixture() -> Fixture:
    subprocess.run([sys.executable, str(BUILDER)], cwd=ROOT, check=True)
    image = CAPSULE.read_bytes()
    if len(image) < 16 or image[:8] != b"S286AB02":
        raise AssertionError("abort capsule magic drifted")
    abi, image_bytes, abort_entry, success_entry = struct.unpack_from(
        "<HHHH", image, 8
    )
    if (
        abi != 2
        or image_bytes != len(image)
        or len(image) != CAPSULE_LIMIT - CAPSULE_LOAD
        or not CAPSULE_LOAD <= abort_entry < CAPSULE_LOAD + len(image)
        or not CAPSULE_LOAD <= success_entry < CAPSULE_LOAD + len(image)
        or abort_entry == success_entry
        or len(image) > CAPSULE_LIMIT - CAPSULE_LOAD
    ):
        raise AssertionError("abort capsule header/geometry drifted")

    memory = bytearray(1024 * 1024)
    memory[0x1000:0x1800] = CORE.read_bytes()[:0x800]
    memory[CAPSULE_LOAD : CAPSULE_LOAD + len(image)] = image
    memory[RETURN_SENTINEL] = 0xF4
    struct.pack_into("<H", memory, BDA_MEMORY_KB, 512)
    memory[HANDOFF_STATUS] = 3
    memory[DPI_REACHED] = 0
    memory[ROOT_STATE_MODE] = 1
    struct.pack_into("<H", memory, ROOT_STATE_CRYPTO_SEG, CRYPTO_SEG)
    struct.pack_into("<H", memory, ROOT_PARENT_SP, PARENT_ENTRY_SP)
    struct.pack_into(
        "<H", memory, ROOT_PARENT_SP_INVERSE, PARENT_ENTRY_SP ^ 0xFFFF
    )
    memory[ROOT_PARENT_STATUS_INV : ROOT_PARENT_STATUS_INV + 2] = b"\x5A\xA5"

    original_config = bytearray(make_pattern(CONFIG_BYTES, 37, 11))
    original_config[DPI_REACHED - CONFIG_SOURCE] = 0
    original_config = bytes(original_config)
    original_low = make_pattern(LOW_BYTES, 43, 17)
    original_prompt = make_pattern(PROMPT_BYTES, 47, 23)
    prompt_len = 91
    original_protected = bytearray(make_pattern(0x400, 53, 29))
    # The protected region contains the portions of config/prompt that already
    # live at 3c00..3de6; make one coherent original low-state image.
    memory[0x3C00:0x4000] = original_protected
    memory[CONFIG_SOURCE : CONFIG_SOURCE + CONFIG_BYTES] = original_config
    memory[LOW_SOURCE : LOW_SOURCE + LOW_BYTES] = original_low
    memory[PROMPT_SOURCE : PROMPT_SOURCE + PROMPT_BYTES] = original_prompt
    memory[PROMPT_LEN_SOURCE] = prompt_len
    original_protected = bytes(memory[0x3C00:0x4000])

    high = CRYPTO_BASE
    memory[high + CONFIG_OFF : high + CONFIG_OFF + CONFIG_BYTES] = original_config
    memory[high + LOW_OFF : high + LOW_OFF + LOW_BYTES] = original_low
    memory[high + PROMPT_OFF : high + PROMPT_OFF + PROMPT_BYTES] = original_prompt
    memory[high + PROMPT_LEN_OFF] = prompt_len
    struct.pack_into("<I", memory, high + MAGIC_OFF, 0x53453632)
    struct.pack_into("<I", memory, high + MAGIC_INV_OFF, 0xACBAC9CD)
    struct.pack_into("<H", memory, high + CONFIG_CRC_OFF, crc16(original_config))
    struct.pack_into("<H", memory, high + LOW_CRC_OFF, crc16(original_low))
    memory[high + MODE_OFF] = 1
    struct.pack_into("<H", memory, high + CRYPTO_SEG_OFF, CRYPTO_SEG)
    struct.pack_into("<H", memory, high + PROMPT_CRC_OFF, crc16(original_prompt))
    memory[high + PROMPT_LEN_META_OFF] = prompt_len
    memory[high + PROMPT_LEN_INV_OFF] = prompt_len ^ 0xFF
    struct.pack_into(
        "<H", memory, high + PRESERVE_CRC_OFF, crc16(original_protected)
    )
    memory[high + STATUS_INV_OFF] = 0x5A
    memory[high + STATUS_OFF] = 0xA5

    # Parent time preloads the complete prompt-time working set once, copies
    # it into the arena-excluded shadow, authenticates it, and marks the low
    # copy quarantined before any crypto overlay is entered.
    original_cache = make_pattern(SHADOW_DATA_BYTES, 73, 41)
    memory[LOOP_CACHE_START:LOOP_CACHE_END] = original_cache
    memory[SHADOW_BASE:CRYPTO_BASE] = bytes(SHADOW_BYTES)
    memory[
        SHADOW_BASE + SHADOW_DATA_OFF :
        SHADOW_BASE + SHADOW_DATA_OFF + SHADOW_DATA_BYTES
    ] = original_cache
    struct.pack_into("<H", memory, SHADOW_BASE, crc16(original_cache))
    struct.pack_into(
        "<H", memory, RUNTIME["TLS13_286_LINK_LOOP_CACHE_COUNT"], 0xFFFF
    )
    original_shadow = bytes(memory[SHADOW_BASE:CRYPTO_BASE])

    # Model the state immediately before a controller abort.  HELLO uses this
    # exact low band as controller/SHA work and clears all but its final eight
    # bytes; restoration must therefore come from authenticated high escrow.
    memory[CONTROLLER_START:ROOT_END] = bytes(
        (index * 59 + 31) & 0xFF
        for index in range(ROOT_END - CONTROLLER_START)
    )
    memory[0x3C00:0x3FF8] = bytes(0x3F8)
    memory[HANDOFF_START:CAPSULE_LOAD] = bytes(
        (index * 61 + 7) & 0xFF
        for index in range(CAPSULE_LOAD - HANDOFF_START)
    )
    memory[MODULE_START:MODULE_END] = bytes(
        (index * 67 + 13) & 0xFF
        for index in range(MODULE_END - MODULE_START)
    )
    original_app = make_pattern(APP_STATE_END - APP_STATE_START, 71, 19)
    memory[APP_STATE_START:APP_STATE_END] = original_app
    memory[APP_READY] = 0

    # The capsule/root state is installed after the modeled overwrite.
    memory[CAPSULE_LOAD : CAPSULE_LOAD + len(image)] = image
    # hello_install_abort_capsule publishes this pair after copying the
    # authenticated immutable image and before private-state consumption.
    struct.pack_into("<H", memory, CAPSULE_CRYPTO_SEG, CRYPTO_SEG)
    struct.pack_into(
        "<H", memory, CAPSULE_CRYPTO_SEG_INVERSE, CRYPTO_SEG ^ 0xFFFF
    )
    memory[ROOT_STATE_MODE] = 1
    struct.pack_into("<H", memory, ROOT_STATE_CRYPTO_SEG, CRYPTO_SEG)
    struct.pack_into("<H", memory, ROOT_PARENT_SP, PARENT_ENTRY_SP)
    struct.pack_into(
        "<H", memory, ROOT_PARENT_SP_INVERSE, PARENT_ENTRY_SP ^ 0xFFFF
    )
    memory[ROOT_PARENT_STATUS_INV : ROOT_PARENT_STATUS_INV + 2] = b"\x5A\xA5"
    return Fixture(
        image,
        abort_entry,
        success_entry,
        bytes(memory),
        original_config,
        original_low,
        original_prompt,
        original_protected,
        original_app,
        original_cache,
        original_shadow,
    )


def run(
    image: bytes,
    entry: int,
    *,
    expect_success: bool,
    expect_restore: bool = True,
) -> tuple[bytes, int, int]:
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 1024 * 1024)
    uc.mem_write(0, image)
    uc.mem_write(STACK_TOP - 2, RETURN_SENTINEL.to_bytes(2, "little"))
    uc.mem_write(PARENT_ENTRY_SP, RETURN_SENTINEL.to_bytes(2, "little"))
    route_hits = 0
    restore_hits = 0
    cleanup_events: list[str] = []
    last_address: int | None = None

    def hook(_uc: Uc, address: int, _size: int, _user: object) -> None:
        nonlocal last_address, restore_hits, route_hits
        if address == RUNTIME["TLS13_286_LINK_ROUTE_MODE"]:
            route_hits += 1
            cleanup_events.append("route-mode")
        # Unicorn reports the REP MOVSW entry once per iteration. Count only
        # a control-flow entry into the resident restore thunk.
        if (
            address == RUNTIME["TLS13_286_LINK_RESTORE_LOOP_CACHE_SHADOW"]
            and last_address != address
        ):
            restore_hits += 1
            cleanup_events.append("restore")
        last_address = address

    uc.hook_add(UC_HOOK_CODE, hook)
    for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
        uc.reg_write(register, 0)
    uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
    uc.reg_write(UC_X86_REG_IP, entry)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x0402)
    try:
        uc.emu_start(entry, RETURN_SENTINEL, count=20_000_000)
    except UcError as error:
        ip = uc.reg_read(UC_X86_REG_IP) & 0xFFFF
        raise AssertionError(f"abort capsule failed at {ip:04x}: {error}") from error
    flags = uc.reg_read(UC_X86_REG_EFLAGS)
    result = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
    if route_hits != 1:
        raise AssertionError(
            f"cleanup capsule executed route mode {route_hits} times"
        )
    expected_restores = 1 if expect_restore else 0
    if restore_hits != expected_restores:
        raise AssertionError(
            "cleanup capsule cache-shadow restore count drifted: "
            f"got {restore_hits}, expected {expected_restores}"
        )
    expected_events = ["route-mode"] + (["restore"] if expect_restore else [])
    if cleanup_events != expected_events:
        raise AssertionError(
            f"cleanup capsule return ordering drifted: {cleanup_events!r}"
        )
    if expect_success and (flags & 1 or result != 1):
        raise AssertionError(
            f"success capsule did not return CF=0/ready: {flags:04x}/{result:04x}"
        )
    if not expect_success and (not flags & 1 or result != 5):
        raise AssertionError(
            f"abort capsule did not return CF=1/profile: {flags:04x}/{result:04x}"
        )
    if flags & 0x0400:
        raise AssertionError("abort capsule returned with DF set")
    if uc.reg_read(UC_X86_REG_DS) or uc.reg_read(UC_X86_REG_ES):
        raise AssertionError("abort capsule did not restore DS=ES=0")
    return bytes(uc.mem_read(0, 1024 * 1024)), flags, result


def returned_config(fixture: Fixture) -> bytes:
    expected = bytearray(fixture.original_config)
    expected[DPI_REACHED - CONFIG_SOURCE] = 1
    return bytes(expected)


def returned_protected(fixture: Fixture) -> bytes:
    expected = bytearray(fixture.original_protected)
    expected[DPI_REACHED - 0x3C00] = 1
    return bytes(expected)


def assert_common_retirement(after: bytes, fixture: Fixture, label: str) -> None:
    if after[LOW_SOURCE : LOW_SOURCE + LOW_BYTES] != fixture.original_low:
        raise AssertionError(f"{label} did not restore low control state")
    if after[PROMPT_SOURCE : PROMPT_SOURCE + PROMPT_BYTES] != fixture.original_prompt:
        raise AssertionError(f"{label} did not restore prompt")
    if after[0x3C00:0x4000] != returned_protected(fixture):
        raise AssertionError(f"{label} changed protected low state outside DPI")
    if after[LOOP_CACHE_START:LOOP_CACHE_END] != fixture.original_cache:
        raise AssertionError(f"{label} did not restore the complete loop cache")
    if (
        struct.unpack_from(
            "<H", after, RUNTIME["TLS13_286_LINK_LOOP_CACHE_COUNT"]
        )[0]
        != LOOP_CACHE_ENTRIES
    ):
        raise AssertionError(f"{label} did not publish the loop-cache lookup count")
    if any(after[CRYPTO_BASE : CRYPTO_BASE + HIGH_BYTES]):
        raise AssertionError(f"{label} left high private state live")
    if after[SHADOW_BASE:CRYPTO_BASE] != fixture.original_shadow:
        raise AssertionError(f"{label} changed the immutable RAM shadow")


def assert_valid_abort(fixture: Fixture) -> None:
    after, _flags, _result = run(
        fixture.memory, fixture.abort_entry, expect_success=False
    )
    if after[CONFIG_SOURCE : CONFIG_SOURCE + CONFIG_BYTES] != returned_config(
        fixture
    ):
        raise AssertionError("valid capsule did not restore config")
    if any(after[CONTROLLER_START:PROMPT_SOURCE]):
        raise AssertionError("valid capsule left controller prefix live")
    if any(after[PROMPT_LEN_SOURCE + 1 : CONFIG_SOURCE]):
        raise AssertionError("valid capsule left root bytes outside restored state")
    if any(after[APP_STATE_START:APP_STATE_END]):
        raise AssertionError("valid abort capsule preserved application state")
    if after[APP_READY] != 0:
        raise AssertionError("valid abort capsule published application readiness")
    assert_common_retirement(after, fixture, "valid abort capsule")


def assert_valid_success(fixture: Fixture) -> None:
    published = bytearray(fixture.memory)
    published[APP_READY] = 1
    after, _flags, _result = run(
        bytes(published), fixture.success_entry, expect_success=True
    )
    if after[CONFIG_SOURCE : CONFIG_SOURCE + CONFIG_BYTES] != returned_config(
        fixture
    ):
        raise AssertionError("success capsule did not restore config")
    if any(after[CONTROLLER_START:APP_STATE_START]):
        raise AssertionError("success capsule left controller prefix live")
    if after[APP_STATE_START:APP_STATE_END] != fixture.original_app:
        raise AssertionError("success capsule did not preserve application state")
    if any(after[APP_STATE_END:PROMPT_SOURCE]):
        raise AssertionError("success capsule left post-application bytes live")
    if any(after[PROMPT_LEN_SOURCE + 1 : CONFIG_SOURCE]):
        raise AssertionError("success capsule left root bytes outside restored state")
    assert_common_retirement(after, fixture, "success capsule")


def assert_unready_success_rejected(fixture: Fixture) -> None:
    after, _flags, _result = run(
        fixture.memory, fixture.success_entry, expect_success=False
    )
    if any(after[APP_STATE_START:APP_STATE_END]):
        raise AssertionError("unready success entry preserved application state")
    if after[APP_READY] != 0:
        raise AssertionError("unready success entry published readiness")


def assert_tamper_matrix(fixture: Fixture) -> None:
    cases = {
        "magic": CRYPTO_BASE + MAGIC_OFF,
        "config": CRYPTO_BASE + CONFIG_OFF + 17,
        "low": CRYPTO_BASE + LOW_OFF + 9,
        "prompt": CRYPTO_BASE + PROMPT_OFF + 31,
        "prompt-len-inverse": CRYPTO_BASE + PROMPT_LEN_INV_OFF,
        "crypto-segment": CRYPTO_BASE + CRYPTO_SEG_OFF,
        "root-mode": ROOT_STATE_MODE,
        "root-crypto-segment": ROOT_STATE_CRYPTO_SEG,
    }
    for name, offset in cases.items():
        changed = bytearray(fixture.memory)
        changed[offset] ^= 1
        for entry_label, entry in (
            ("abort", fixture.abort_entry),
            ("success", fixture.success_entry),
        ):
            restore = name != "root-crypto-segment"
            after, _flags, _result = run(
                bytes(changed),
                entry,
                expect_success=False,
                expect_restore=restore,
            )
            if (
                after[CONFIG_SOURCE : CONFIG_SOURCE + CONFIG_BYTES]
                == returned_config(fixture)
            ):
                raise AssertionError(
                    f"{name} tamper via {entry_label} published escrow bytes"
                )
            if any(after[CRYPTO_BASE : CRYPTO_BASE + HIGH_BYTES]):
                raise AssertionError(
                    f"{name} tamper via {entry_label} left high state live"
                )
            if any(after[CONTROLLER_START:ROOT_END]):
                raise AssertionError(
                    f"{name} tamper via {entry_label} left low executable live"
                )
            if restore:
                if after[LOOP_CACHE_START:LOOP_CACHE_END] != fixture.original_cache:
                    raise AssertionError(
                        f"{name} tamper via {entry_label} did not restore cache"
                    )
            elif any(after[MODULE_START:MODULE_END]):
                raise AssertionError(
                    f"{name} tamper via {entry_label} left module overlay live"
                )


def assert_shadow_tamper_rejected(fixture: Fixture) -> None:
    cases = {
        "shadow-crc": SHADOW_BASE,
        "shadow-data": SHADOW_BASE + SHADOW_DATA_OFF + 113,
    }
    for name, offset in cases.items():
        changed = bytearray(fixture.memory)
        changed[offset] ^= 1
        after, _flags, _result = run(
            bytes(changed),
            fixture.success_entry,
            expect_success=False,
            expect_restore=False,
        )
        if any(after[CRYPTO_BASE : CRYPTO_BASE + HIGH_BYTES]):
            raise AssertionError(f"{name} left high private state live")
        if any(after[HANDOFF_START:CAPSULE_LOAD]):
            raise AssertionError(f"{name} left root handoff state live")
        if any(after[MODULE_START:MODULE_END]):
            raise AssertionError(f"{name} left asymmetric module live")
        if (
            struct.unpack_from(
                "<H", after, RUNTIME["TLS13_286_LINK_LOOP_CACHE_COUNT"]
            )[0]
            != 0xFFFF
        ):
            raise AssertionError(f"{name} published a rejected loop cache")


def assert_frozen_geometry(fixture: Fixture) -> None:
    # BDA[0413] is an admission-time input, not live cleanup authority.  Once
    # HELLO has frozen the validated segment, arbitrary later BDA values must
    # neither redirect retirement nor prevent the real high wipe.
    for memory_kb in (0, 511, 513, 640, 641, 0xFFFF):
        changed = bytearray(fixture.memory)
        struct.pack_into("<H", changed, BDA_MEMORY_KB, memory_kb)
        after, _flags, _result = run(
            bytes(changed), fixture.abort_entry, expect_success=False
        )
        if any(after[CRYPTO_BASE : CRYPTO_BASE + HIGH_BYTES]):
            raise AssertionError(
                f"BDA {memory_kb} redirected the frozen high retirement"
            )

    # The root word, installed segment, and installed inverse are three
    # independent representations.  With hostile BDA, any one damaged copy
    # must still retire the real reservation; a bad root must also prevent
    # escrow restoration.
    cases = {
        "root": ROOT_STATE_CRYPTO_SEG,
        "installed-segment": CAPSULE_CRYPTO_SEG,
        "installed-inverse": CAPSULE_CRYPTO_SEG_INVERSE,
    }
    for name, offset in cases.items():
        changed = bytearray(fixture.memory)
        struct.pack_into("<H", changed, BDA_MEMORY_KB, 0xFFFF)
        changed[offset] ^= 1
        restore = name != "root"
        after, _flags, _result = run(
            bytes(changed),
            fixture.abort_entry,
            expect_success=False,
            expect_restore=restore,
        )
        if any(after[CRYPTO_BASE : CRYPTO_BASE + HIGH_BYTES]):
            raise AssertionError(
                f"{name} tamper with hostile BDA left high state live"
            )
        if name == "root" and (
            after[CONFIG_SOURCE : CONFIG_SOURCE + CONFIG_BYTES]
            == returned_config(fixture)
        ):
            raise AssertionError("bad root geometry restored escrow")
        if restore:
            if after[LOOP_CACHE_START:LOOP_CACHE_END] != fixture.original_cache:
                raise AssertionError(f"{name} repair did not restore loop cache")
        elif any(after[MODULE_START:MODULE_END]):
            raise AssertionError(f"{name} tamper left module overlay live")


def main() -> None:
    fixture = build_fixture()
    assert_valid_abort(fixture)
    assert_valid_success(fixture)
    assert_unready_success_rejected(fixture)
    assert_tamper_matrix(fixture)
    assert_shadow_tamper_rejected(fixture)
    assert_frozen_geometry(fixture)
    print(
        "TLS13 286 ABORT CAPSULE PASS "
        f"bytes={len(fixture.image)} entries=2 unready=reject "
        "escrow_tamper=16 shadow_tamper=2 bda=non_authoritative "
        "cache=ram-shadow"
    )


if __name__ == "__main__":
    main()
