#!/usr/bin/env python3
"""Offline execution gate for the bounded TLS 1.3 K14 product state guard.

The guard is intentionally not wired into core.asm yet.  This checker assembles
the fixed-origin image directly, proves its mirrored ABI still matches the
canonical layout, and executes every entry mode under Unicorn's 8086-compatible
16-bit engine.  The execution matrix covers the prompt scatter's protected
hole, status-last publication, MDA replay, CGA preservation, the K14 scrub /
escrow / POST ordering contract, EMS cursor recovery, and hostile state.
"""
from __future__ import annotations

import importlib.util
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path

try:
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
        UC_X86_REG_CS,
        UC_X86_REG_DS,
        UC_X86_REG_EFLAGS,
        UC_X86_REG_ES,
        UC_X86_REG_IP,
        UC_X86_REG_SP,
        UC_X86_REG_SS,
    )
except ImportError as exc:  # pragma: no cover - exercised by a missing dependency
    raise SystemExit(f"unicorn is required for the K14 state-guard gate: {exc}")


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "targets/ibm_pc_5150/boot/core"
TLS13 = ROOT / "targets/ibm_pc_5150/boot/tls13"
SOURCE = TLS13 / "k14_product_state_guard.asm"
ABI = TLS13 / "k14_product_state_guard_abi.inc"
LAYOUT = CORE / "layout.inc"
DATA = CORE / "data.inc"

ORIGIN = 0x0700
IMAGE_BYTES = 1024
RETURN_IP = 0x05F0
STACK_TOP = 0x3F00
MEM_BYTES = 0xC0000
MDA_BASE = 0xB0000
CGA_BASE = 0xB8000
VISIBLE_BYTES = 80 * 25 * 2

# Mirrored product addresses.  Keeping the test's accessors named makes the
# individual execution cases readable; drift is rejected against both the ABI
# include and core's canonical equates before any emulation begins.
H = {
    "handoff": 0x0600,
    "handoff_flags": 0x0608,
    "handoff_video_cols": 0x060C,
    "handoff_seed_col": 0x060D,
    "bda_video_cols": 0x044A,
    "bda_crt_port": 0x0463,
    "marker_row": 0x0F33,
    "form_left": 0x0F38,
    "form_field": 0x0F39,
    "cursor_row": 0x0F55,
    "cursor_col": 0x0F56,
    "screen_cols": 0x0F57,
    "video_seg": 0x0F58,
    "seed_col": 0x0F5A,
    "attrs": 0x0F5B,
    "load_marker_char": 0x0F64,
    "load_marker_attr": 0x0F65,
    "loop_pending": 0x0F66,
    "loop_count": 0x0F67,
    "low_constants": 0x0F69,
    "low_constants_end": 0x0FE2,
    "prompt_len": 0x3C9C,
    "scroll_br": 0x3CA9,
    "prompt_valid": 0x3CBF,
    "saved_loop": 0x3CC0,
    "ems_count": 0x3CE0,
    "far_ctx": 0x3CE2,
    "prompt_head": 0x3CE6,
    "ems_page": 0x3CE6,
    "ems_off": 0x3CE8,
    "render_type": 0x3CEA,
    "prompt_hole": 0x3CEB,
    "tool_state": 0x3CEB,
    "prompt_tail": 0x3CEC,
    "reconnect_end": 0x3DE6,
}

HEAD_LEN = 5
PROMPT_MAX = 255
MDA_ATTRS = bytes((0x0F, 0x07, 0x07, 0x07, 0x0F, 0x0F, 0x0F, 0x0F, 0x07))
CGA_ATTRS = bytes((0x0F, 0x08, 0x08, 0x07, 0x0F, 0x0F, 0x0C, 0x0F, 0x08))


def low_constants_image() -> bytes:
    labels = (
        b"master secret"
        b"client finished"
        b"server finished"
        b"key expansion"
    )
    chacha = struct.pack(
        "<8H", 0x7865, 0x6170, 0x646E, 0x3320,
        0x2D32, 0x7962, 0x6574, 0x6B20,
    )
    poly = b"\xfb" + (b"\xff" * 15) + b"\x03"
    sha = struct.pack(
        "<16H",
        0xE667, 0x6A09, 0xAE85, 0xBB67,
        0xF372, 0x3C6E, 0xF53A, 0xA54F,
        0x527F, 0x510E, 0x688C, 0x9B05,
        0xD9AB, 0x1F83, 0xCD19, 0x5BE0,
    )
    image = labels + chacha + poly + sha
    assert len(image) == H["low_constants_end"] - H["low_constants"]
    return image


LOW_CONSTANTS = low_constants_image()


class CheckFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def load_equate_parser():
    path = ROOT / "tools/check-layout.py"
    spec = importlib.util.spec_from_file_location("seed_check_layout", path)
    require(spec is not None and spec.loader is not None, "cannot load check-layout.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.parse_equates


def assemble() -> tuple[bytes, int]:
    with tempfile.TemporaryDirectory(prefix="seed-k14-guard-") as tmp:
        tmpdir = Path(tmp)
        binary = tmpdir / "guard.bin"
        listing = tmpdir / "guard.lst"
        subprocess.run(
            [
                "nasm",
                "-f", "bin",
                "-I", f"{TLS13}/",
                "-l", str(listing),
                "-o", str(binary),
                str(SOURCE),
            ],
            check=True,
            cwd=ROOT,
        )
        image = binary.read_bytes()
        actual_end = None
        for line in listing.read_text().splitlines():
            if "times k14_guard_max_bytes" not in line:
                continue
            match = re.search(r"\b([0-9A-Fa-f]{8})\b", line)
            if match:
                actual_end = int(match.group(1), 16)
                break
        require(actual_end is not None, "cannot resolve unpadded guard extent")
        return image, actual_end


def check_abi(image: bytes, actual_end: int) -> None:
    parse_equates = load_equate_parser()
    core = parse_equates([LAYOUT, DATA])
    abi = parse_equates([ABI])

    require(len(image) == IMAGE_BYTES, f"guard image is {len(image)} B, expected {IMAGE_BYTES}")
    require(actual_end <= IMAGE_BYTES, f"guard executable/data extent is {actual_end} B")
    require(abi.get("k14_guard_origin") == ORIGIN, "guard origin drift")
    require(abi.get("k14_guard_max_bytes") == IMAGE_BYTES, "guard sector budget drift")

    expected = {
        "k14_guard_origin": core["low_scratch_start"],
        "k14_guard_handoff": core["handoff_addr"],
        "k14_guard_handoff_flags": core["handoff_addr"] + core["handoff_flags"],
        "k14_guard_handoff_video_mode": core["handoff_addr"] + core["handoff_video_mode"],
        "k14_guard_handoff_video_cols": core["handoff_addr"] + core["handoff_video_cols"],
        "k14_guard_handoff_seed_col": core["handoff_addr"] + core["handoff_seed_col"],
        "k14_guard_handoff_flag_mda": core["handoff_flag_mda"],
        "k14_guard_dpi_prompt_marker_row": core["dpi_prompt_marker_row"],
        "k14_guard_form_left_col": core["form_left_col"],
        "k14_guard_form_field_col": core["form_field_col"],
        "k14_guard_cursor_row": core["cursor_row"],
        "k14_guard_cursor_col": core["cursor_col"],
        "k14_guard_screen_cols": core["screen_cols"],
        "k14_guard_video_seg": core["video_seg"],
        "k14_guard_seed_col": core["seed_col"],
        "k14_guard_seed_attr": core["seed_attr"],
        "k14_guard_build_attr": core["build_attr"],
        "k14_guard_load_attr": core["load_attr"],
        "k14_guard_crypto_attr": core["crypto_attr"],
        "k14_guard_ready_attr": core["ready_attr"],
        "k14_guard_question_attr": core["question_attr"],
        "k14_guard_error_attr": core["error_attr"],
        "k14_guard_menu_selected_attr": core["menu_selected_attr"],
        "k14_guard_menu_idle_attr": core["menu_idle_attr"],
        "k14_guard_load_marker_char": core["load_marker_char"],
        "k14_guard_load_marker_attr": core["load_marker_attr"],
        "k14_guard_agent_loop_pending": core["agent_loop_pending"],
        "k14_guard_agent_loop_count": core["agent_loop_count"],
        "k14_guard_low_constants_start": core["low_static_constants_start"],
        "k14_guard_low_constants_end": core["low_static_constants_end"],
        "k14_guard_prompt_len": core["chat_resend_prompt_len"],
        "k14_guard_scroll_br": core["scroll_br"],
        "k14_guard_prompt_valid": core["recert_flag"],
        "k14_guard_saved_loop_word": core["recert_mod_ptr"],
        "k14_guard_ems_page_count": core["ems_page_count"],
        "k14_guard_far_ctx_base": core["far_ctx_base"],
        "k14_guard_prompt_head": core["ems_ctx_page"],
        "k14_guard_ems_ctx_page": core["ems_ctx_page"],
        "k14_guard_ems_ctx_off": core["ems_ctx_off"],
        "k14_guard_render_last_type": core["render_last_type"],
        "k14_guard_prompt_hole": core["tool_fc_state"],
        "k14_guard_tool_fc_state": core["tool_fc_state"],
        "k14_guard_prompt_tail": core["fc_match_state"],
        "k14_guard_reconnect_state_end": core["reconnect_state_end"],
        "k14_guard_render_type_user": core["render_type_user"],
        "k14_guard_ems_flat_base_hi": core["ems_flat_base_hi"],
        "k14_guard_dpi_prompt_row": core["dpi_prompt_row"],
        "k14_guard_dpi_prompt_col": core["dpi_prompt_col"],
        "k14_guard_prompt_max": core["dpi_input_max_len"],
        "k14_guard_seed_attr_cga": core["seed_attr_cga"],
        "k14_guard_build_attr_cga": core["build_attr_cga"],
        "k14_guard_load_attr_cga": core["load_attr_cga"],
        "k14_guard_crypto_attr_cga": core["crypto_attr_cga"],
        "k14_guard_ready_attr_cga": core["ready_attr_cga"],
        "k14_guard_question_attr_cga": core["question_attr_cga"],
        "k14_guard_error_attr_cga": core["error_attr_cga"],
        "k14_guard_menu_selected_attr_cga": core["menu_selected_attr_cga"],
        "k14_guard_menu_idle_attr_cga": core["menu_idle_attr_cga"],
        "k14_guard_seed_attr_mda": core["seed_attr_mda"],
        "k14_guard_build_attr_mda": core["build_attr_mda"],
        "k14_guard_load_attr_mda": core["load_attr_mda"],
        "k14_guard_crypto_attr_mda": core["crypto_attr_mda"],
        "k14_guard_ready_attr_mda": core["ready_attr_mda"],
        "k14_guard_question_attr_mda": core["question_attr_mda"],
        "k14_guard_error_attr_mda": core["error_attr_mda"],
        "k14_guard_menu_selected_attr_mda": core["menu_selected_attr_mda"],
        "k14_guard_menu_idle_attr_mda": core["menu_idle_attr_mda"],
    }
    for name, value in expected.items():
        require(name in abi, f"ABI parser could not resolve {name}")
        require(
            abi[name] == value,
            f"{name} drifted: guard={abi[name]:#06x}, core={value:#06x}",
        )

    for name, value in H.items():
        abi_name = {
            "marker_row": "k14_guard_dpi_prompt_marker_row",
            "form_left": "k14_guard_form_left_col",
            "form_field": "k14_guard_form_field_col",
            "attrs": "k14_guard_seed_attr",
            "loop_pending": "k14_guard_agent_loop_pending",
            "loop_count": "k14_guard_agent_loop_count",
            "low_constants": "k14_guard_low_constants_start",
            "low_constants_end": "k14_guard_low_constants_end",
            "prompt_len": "k14_guard_prompt_len",
            "prompt_valid": "k14_guard_prompt_valid",
            "saved_loop": "k14_guard_saved_loop_word",
            "ems_count": "k14_guard_ems_page_count",
            "far_ctx": "k14_guard_far_ctx_base",
            "prompt_head": "k14_guard_prompt_head",
            "ems_page": "k14_guard_ems_ctx_page",
            "ems_off": "k14_guard_ems_ctx_off",
            "render_type": "k14_guard_render_last_type",
            "prompt_hole": "k14_guard_prompt_hole",
            "tool_state": "k14_guard_tool_fc_state",
            "prompt_tail": "k14_guard_prompt_tail",
            "reconnect_end": "k14_guard_reconnect_state_end",
        }.get(name, f"k14_guard_{name}")
        # BDA locations are IBM BIOS ABI constants, not Seed layout equates.
        if name.startswith("bda_"):
            continue
        require(abi.get(abi_name) == value, f"checker address drift for {name}")


class Machine:
    def __init__(self, image: bytes):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, MEM_BYTES)
        self.uc.mem_write(ORIGIN, image)
        self.writes: list[tuple[int, int, int]] = []
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write_hook)
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)

    def _write_hook(self, _uc, _access, address, size, value, _user) -> None:
        self.writes.append((address, size, value))

    def _code_hook(self, uc, address, _size, _user) -> None:
        if address == RETURN_IP:
            uc.emu_stop()

    def write(self, address: int, data: bytes) -> None:
        self.uc.mem_write(address, data)

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(address, length))

    def w8(self, address: int, value: int) -> None:
        self.write(address, bytes((value & 0xFF,)))

    def w16(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<H", value & 0xFFFF))

    def w32(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def u8(self, address: int) -> int:
        return self.read(address, 1)[0]

    def u16(self, address: int) -> int:
        return struct.unpack("<H", self.read(address, 2))[0]

    def run(self, mode: int) -> bool:
        self.writes.clear()
        self.uc.reg_write(UC_X86_REG_CS, 0)
        self.uc.reg_write(UC_X86_REG_IP, ORIGIN)
        self.uc.reg_write(UC_X86_REG_DS, 0)
        self.uc.reg_write(UC_X86_REG_ES, 0x1234)
        self.uc.reg_write(UC_X86_REG_SS, 0)
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        self.w16(STACK_TOP - 2, RETURN_IP)
        self.uc.reg_write(UC_X86_REG_AX, 0xA500 | (mode & 0xFF))
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0002)
        try:
            self.uc.emu_start(ORIGIN, RETURN_IP + 1, count=1_000_000)
        except UcError as exc:
            raise CheckFailure(f"emulation failed in mode {mode}: {exc}") from exc
        require(self.uc.reg_read(UC_X86_REG_IP) == RETURN_IP, f"mode {mode} did not return")
        require(self.uc.reg_read(UC_X86_REG_DS) == 0, f"mode {mode} clobbered DS")
        require(self.uc.reg_read(UC_X86_REG_SS) == 0, f"mode {mode} clobbered SS")
        require(self.uc.reg_read(UC_X86_REG_SP) == STACK_TOP, f"mode {mode} unbalanced SP")
        return bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)


def configure_video(m: Machine, *, mda: bool, cols: int = 80) -> None:
    m.w16(H["handoff_flags"], 1 if mda else 0)
    m.w8(H["handoff_video_cols"], cols)
    m.w16(H["bda_video_cols"], cols)
    m.w16(H["bda_crt_port"], 0x03B4 if mda else 0x03D4)
    m.w8(H["screen_cols"], cols)
    m.w16(H["video_seg"], 0xB000 if mda else 0xB800)
    m.w8(H["marker_row"], 20)
    m.w8(H["cursor_row"], 21)
    m.w8(H["cursor_col"], 7)


def prompt_positions(row: int, cols: int, length: int):
    col = 2
    for _ in range(length):
        yield row, col
        col += 1
        if col >= cols:
            row += 1
            col = 2


def put_prompt(m: Machine, prompt: bytes, *, row: int, cols: int, attr: int = 0x0F) -> None:
    require(len(prompt) <= PROMPT_MAX, "test prompt too long")
    m.w8(H["prompt_len"], len(prompt))
    m.w8(H["marker_row"], row)
    for byte, (screen_row, col) in zip(prompt, prompt_positions(row, cols, len(prompt))):
        address = MDA_BASE + 2 * (screen_row * cols + col)
        m.write(address, bytes((byte, attr)))


def read_scatter(m: Machine, length: int) -> bytes:
    head_len = min(length, HEAD_LEN)
    return (
        m.read(H["prompt_head"], head_len)
        + m.read(H["prompt_tail"], length - head_len)
    )


def write_scatter(m: Machine, prompt: bytes) -> None:
    m.write(H["prompt_head"], prompt[:HEAD_LEN])
    m.write(H["prompt_tail"], prompt[HEAD_LEN:])


def read_screen_prompt(m: Machine, length: int, *, row: int, cols: int) -> bytes:
    result = bytearray()
    for screen_row, col in prompt_positions(row, cols, length):
        result.append(m.u8(MDA_BASE + 2 * (screen_row * cols + col)))
    return bytes(result)


def status_values(m: Machine) -> list[int]:
    return [
        value & 0xFF
        for address, size, value in m.writes
        if address == H["prompt_valid"] and size == 1
    ]


def nonstack_writes(m: Machine) -> list[tuple[int, int, int]]:
    return [
        write for write in m.writes
        if not (STACK_TOP - 0x100 <= write[0] < STACK_TOP)
    ]


def test_pre_cold(image: bytes) -> None:
    m = Machine(image)
    configure_video(m, mda=True)
    m.w8(H["prompt_valid"], 0xA5)
    m.w8(H["loop_pending"], 1)
    m.w8(H["loop_count"], 7)
    m.write(H["prompt_head"], b"HEAD!")
    m.w8(H["prompt_hole"], 0x6D)
    m.write(H["prompt_tail"], b"tail")
    carry = m.run(0)
    require(not carry, "PRE_COLD returned carry")
    require(m.u8(H["prompt_valid"]) == 0, "PRE_COLD did not invalidate")
    require(m.u16(H["saved_loop"]) == 0x0701, "PRE_COLD loop word mismatch")
    require(m.read(H["prompt_head"], 5) == b"HEAD!", "PRE_COLD touched prompt head")
    require(m.u8(H["prompt_hole"]) == 0x6D, "PRE_COLD touched protected hole")
    require(m.read(H["prompt_tail"], 4) == b"tail", "PRE_COLD touched prompt tail")
    require(status_values(m) == [0], "PRE_COLD publication ordering mismatch")


def test_pre_cga(image: bytes) -> None:
    m = Machine(image)
    configure_video(m, mda=False)
    m.w8(H["prompt_valid"], 1)
    m.w8(H["loop_pending"], 0)
    m.w8(H["loop_count"], 4)
    m.w8(H["tool_state"], 0)
    m.w8(H["prompt_len"], 31)
    m.write(H["prompt_head"], b"ABCDE")
    m.write(H["prompt_tail"], b"FGHIJ")
    m.write(CGA_BASE, bytes((i * 13 + 5) & 0xFF for i in range(VISIBLE_BYTES)))
    before = m.read(CGA_BASE, VISIBLE_BYTES)
    carry = m.run(1)
    require(not carry, "PRE_HUMAN CGA returned carry")
    require(m.u8(H["prompt_valid"]) == 0, "PRE_HUMAN CGA published a snapshot")
    require(m.u16(H["saved_loop"]) == 0x0400, "PRE_HUMAN CGA loop word mismatch")
    require(m.read(H["prompt_head"], 5) == b"ABCDE", "PRE_HUMAN CGA touched prompt head")
    require(m.read(H["prompt_tail"], 5) == b"FGHIJ", "PRE_HUMAN CGA touched prompt tail")
    require(m.read(CGA_BASE, VISIBLE_BYTES) == before, "PRE_HUMAN CGA touched video")


def test_pre_mda(image: bytes, *, length: int, row: int, cols: int) -> None:
    m = Machine(image)
    configure_video(m, mda=True, cols=cols)
    prompt = bytes(0x21 + (i * 37 % 0x5E) for i in range(length))
    put_prompt(m, prompt, row=row, cols=cols)
    m.w8(H["loop_pending"], 0)
    m.w8(H["loop_count"], 0)
    m.w8(H["tool_state"], 0)
    m.w8(H["prompt_valid"], 0xA5)
    carry = m.run(1)
    require(not carry, "PRE_HUMAN MDA returned carry")
    require(read_scatter(m, length) == prompt, f"MDA scatter mismatch at length {length}")
    require(m.u8(H["prompt_hole"]) == 0, "MDA capture overwrote protected hole")
    require(status_values(m) == [0, 1], "MDA status was not invalid-then-valid")
    require(
        nonstack_writes(m)[-1][:2] == (H["prompt_valid"], 1),
        "MDA snapshot publication was not the last product write",
    )
    prompt_writes = [
        (address, size) for address, size, _value in m.writes
        if H["prompt_head"] <= address < H["reconnect_end"]
    ]
    require(
        all(address != H["prompt_hole"] for address, _size in prompt_writes),
        "MDA capture wrote the protected hole",
    )


def test_ineligible_pre(image: bytes) -> None:
    cases = (
        ("pending", 1, 0, 8, 80, 20, True),
        ("tool", 0, 1, 8, 80, 20, True),
        ("empty", 0, 0, 0, 80, 20, False),
        ("narrow", 0, 0, 8, 19, 20, True),
        ("wide", 0, 0, 8, 81, 20, True),
        ("row", 0, 0, 8, 80, 25, True),
    )
    for name, pending, tool, length, cols, row, rejected in cases:
        m = Machine(image)
        configure_video(m, mda=True, cols=cols)
        m.w8(H["loop_pending"], pending)
        m.w8(H["loop_count"], 3)
        m.w8(H["tool_state"], tool)
        m.w8(H["prompt_len"], length)
        m.w8(H["marker_row"], row)
        m.write(H["prompt_head"], b"ABCDE")
        m.write(H["prompt_tail"], b"FGHIJ")
        carry = m.run(1)
        require(
            carry is rejected,
            f"{name} PRE carry mismatch: got {carry}, expected {rejected}",
        )
        require(m.u8(H["prompt_valid"]) == 0, f"{name} PRE published")
        require(m.read(H["prompt_head"], 5) == b"ABCDE", f"{name} PRE touched head")
        require(m.read(H["prompt_tail"], 5) == b"FGHIJ", f"{name} PRE touched tail")
        require(status_values(m) == [0], f"{name} PRE status mismatch")

    # The vault selects its MDA backend from the BDA and clears that visible
    # page.  Every partial MDA triple must therefore fail closed: accepting
    # either one or two MDA-looking facts could erase an unsnapshotted prompt.
    metadata_controls = (
        (False, False, True),
        (False, True, False),
        (False, True, True),
        (True, False, False),
        (True, False, True),
        (True, True, False),
    )
    for handoff_mda, crt_mda, segment_mda in metadata_controls:
        m = Machine(image)
        configure_video(m, mda=False)
        m.w8(H["prompt_len"], 8)
        m.w8(H["loop_pending"], 0)
        m.w8(H["tool_state"], 0)
        m.w16(H["handoff_flags"], 1 if handoff_mda else 0)
        m.w16(H["bda_crt_port"], 0x03B4 if crt_mda else 0x03D4)
        m.w16(H["video_seg"], 0xB000 if segment_mda else 0xB800)
        name = (
            f"handoff={int(handoff_mda)} "
            f"crt={int(crt_mda)} segment={int(segment_mda)}"
        )
        carry = m.run(1)
        require(carry, f"{name} inconsistent metadata did not fail closed")
        require(m.u8(H["prompt_valid"]) == 0, f"{name} metadata control published")
        require(status_values(m) == [0], f"{name} metadata status mismatch")

    invalid_metadata = (
        ("CGA invalid CRT", False, 0x0000, 0xB800),
        ("CGA invalid segment", False, 0x03D4, 0xA000),
        ("CGA invalid pair", False, 0xFFFF, 0x0000),
        ("MDA invalid CRT", True, 0x0000, 0xB000),
        ("MDA invalid segment", True, 0x03B4, 0xA000),
        ("MDA invalid pair", True, 0xFFFF, 0x0000),
    )
    for name, handoff_mda, crt_port, video_segment in invalid_metadata:
        m = Machine(image)
        configure_video(m, mda=False)
        m.w8(H["prompt_len"], 8)
        m.w8(H["loop_pending"], 0)
        m.w8(H["tool_state"], 0)
        m.w16(H["handoff_flags"], 1 if handoff_mda else 0)
        m.w16(H["bda_crt_port"], crt_port)
        m.w16(H["video_seg"], video_segment)
        carry = m.run(1)
        require(carry, f"{name} metadata did not fail closed")
        require(m.u8(H["prompt_valid"]) == 0, f"{name} metadata published")
        require(status_values(m) == [0], f"{name} metadata status mismatch")

    # A prompt which would leave the visible page may be partially copied, but
    # it must never publish, and PRE must fail rather than allow the vault to
    # erase the only complete copy.
    overflow = Machine(image)
    configure_video(overflow, mda=True, cols=80)
    put_prompt(overflow, b"z" * 79, row=24, cols=80)
    overflow.w8(H["loop_pending"], 0)
    overflow.w8(H["tool_state"], 0)
    require(overflow.run(1), "overflowing PRE did not return carry")
    require(overflow.u8(H["prompt_valid"]) == 0, "overflowing PRE published a partial snapshot")
    require(status_values(overflow) == [0], "overflowing PRE changed publication status")


def scrub_and_restore_escrow(m: Machine, escrow: bytes) -> None:
    # K14 retires this conventional band before the vault escrow restores the
    # five exact product bytes.  The product POST runs only after both steps.
    m.write(0x0D00, b"\x00" * (H["low_constants_end"] - 0x0D00))
    m.w8(H["cursor_row"], escrow[0])
    m.w8(H["cursor_col"], escrow[1])
    m.w8(H["marker_row"], escrow[2])
    m.w8(H["loop_pending"], escrow[3])
    m.w8(H["loop_count"], escrow[4])


def test_post_mda(image: bytes) -> None:
    m = Machine(image)
    configure_video(m, mda=True, cols=80)
    prompt = bytes(0x20 + (i * 19 % 0x5F) for i in range(173))
    put_prompt(m, prompt, row=20, cols=80)
    m.w8(H["loop_pending"], 0)
    m.w8(H["loop_count"], 6)
    m.w8(H["tool_state"], 0)
    m.run(1)
    require(m.u8(H["prompt_valid"]) == 1, "POST setup capture failed")
    escrow = bytes((22, 41, 20, 0, 6))

    scrub_and_restore_escrow(m, escrow)
    m.write(H["low_constants"], b"\xCC" * len(LOW_CONSTANTS))
    m.write(H["attrs"], b"\xCC" * 9)
    m.w8(H["load_marker_char"], 0xCC)
    m.w8(H["load_marker_attr"], 0xCC)
    m.w16(H["ems_count"], 16)
    far_ctx = 0x0012BEEF
    m.w32(H["far_ctx"], far_ctx)
    m.write(MDA_BASE, b"\x00" * VISIBLE_BYTES)

    carry = m.run(2)
    require(not carry, "POST_ROUTE MDA returned carry")
    require(m.read(H["low_constants"], len(LOW_CONSTANTS)) == LOW_CONSTANTS, "constant recovery failed")
    require(m.read(H["attrs"], 9) == MDA_ATTRS, "MDA attributes not reconstructed")
    require(m.u16(H["scroll_br"]) == 0x184F, "MDA scroll geometry mismatch")
    require(m.u8(H["seed_col"]) == 38 and m.u8(H["handoff_seed_col"]) == 38, "seed column mismatch")
    require(m.u8(H["form_left"]) == 32 and m.u8(H["form_field"]) == 42, "form geometry mismatch")
    require(m.u8(H["load_marker_char"]) == ord("."), "load marker char not reconstructed")
    require(m.u8(H["load_marker_attr"]) == MDA_ATTRS[2], "load marker attr mismatch")
    require(m.read(H["cursor_row"], 2) == escrow[:2], "POST changed escrow cursor")
    require(m.u8(H["marker_row"]) == escrow[2], "POST changed escrow marker row")
    require(m.read(H["loop_pending"], 2) == escrow[3:], "POST changed escrow loop word")
    require(m.u16(H["ems_page"]) == ((far_ctx - 0x00100000) >> 14), "EMS page recompute mismatch")
    require(m.u16(H["ems_off"]) == (far_ctx & 0x3FFF), "EMS offset recompute mismatch")
    require(m.u8(H["render_type"]) == 1, "render type was not restored to user")
    require(m.u8(H["prompt_valid"]) == 0, "POST did not consume prompt snapshot")
    require(status_values(m) == [0], "POST status write mismatch")
    require(nonstack_writes(m)[-1][:2] == (H["prompt_valid"], 1), "POST invalidation was not last")
    marker_cell = MDA_BASE + 2 * (20 * 80)
    require(
        m.read(marker_cell, 4) == b">" + bytes((0x0F,)) + b" " + bytes((0x0F,)),
        "MDA marker redraw failed",
    )
    require(read_screen_prompt(m, len(prompt), row=20, cols=80) == prompt, "MDA prompt replay failed")
    require(m.u8(H["prompt_hole"]) == 0, "POST touched protected hole")


def test_post_cga(image: bytes) -> None:
    m = Machine(image)
    configure_video(m, mda=False, cols=80)
    escrow = bytes((7, 31, 19, 1, 5))
    m.w8(H["prompt_valid"], 1)
    write_scatter(m, b"x" * 80)
    scrub_and_restore_escrow(m, escrow)
    m.w8(H["prompt_valid"], 1)
    pattern = bytes((i * 29 + 7) & 0xFF for i in range(VISIBLE_BYTES))
    m.write(CGA_BASE, pattern)
    m.run(2)
    require(m.read(CGA_BASE, VISIBLE_BYTES) == pattern, "POST CGA touched visible video")
    require(m.read(H["attrs"], 9) == CGA_ATTRS, "CGA attributes not reconstructed")
    require(m.u16(H["scroll_br"]) == 0x184F, "CGA scroll geometry mismatch")
    require(m.u16(H["video_seg"]) == 0xB800, "CGA video segment mismatch")
    require(m.read(H["cursor_row"], 2) == escrow[:2], "POST CGA changed cursor")
    require(m.u8(H["marker_row"]) == escrow[2], "POST CGA changed marker")
    require(m.read(H["loop_pending"], 2) == escrow[3:], "POST CGA changed loop word")
    require(m.u8(H["prompt_valid"]) == 0, "POST CGA did not invalidate")
    require(nonstack_writes(m)[-1][:2] == (H["prompt_valid"], 1), "POST CGA status was not last")


def test_hostile_post(image: bytes) -> None:
    m = Machine(image)
    configure_video(m, mda=True)
    m.w8(H["handoff_video_cols"], 0)
    m.w8(H["bda_video_cols"], 0xFF)
    m.w8(H["screen_cols"], 0)
    escrow = bytes((0xE1, 0xE2, 0xFF, 0xE3, 0xE4))
    m.write(H["cursor_row"], escrow[:2])
    m.w8(H["marker_row"], escrow[2])
    m.write(H["loop_pending"], escrow[3:])
    m.w8(H["prompt_valid"], 1)
    m.w8(H["prompt_len"], 255)
    write_scatter(m, bytes(range(255)))
    m.w16(H["ems_count"], 1)
    m.w32(H["far_ctx"], 0x000FFFFF)
    m.w16(H["ems_page"], 0xFFFF)
    m.w16(H["ems_off"], 0xFFFF)
    m.write(MDA_BASE, b"\xAA" * VISIBLE_BYTES)
    m.run(2)
    require(m.u8(H["screen_cols"]) == 80, "hostile columns did not fall back to 80")
    require(m.u8(H["handoff_video_cols"]) == 80, "handoff columns not repaired")
    require(m.u16(H["ems_page"]) == 0 and m.u16(H["ems_off"]) == 0, "hostile EMS cursor accepted")
    require(m.read(H["cursor_row"], 2) == escrow[:2], "hostile POST changed cursor")
    require(m.u8(H["marker_row"]) == escrow[2], "hostile POST changed marker")
    require(m.read(H["loop_pending"], 2) == escrow[3:], "hostile POST changed loop")
    require(m.u8(H["prompt_valid"]) == 0, "hostile POST did not invalidate")
    require(m.read(MDA_BASE, 4) == b" \x07 \x07", "hostile prompt was replayed")
    video_writes = [
        (address, size) for address, size, _value in m.writes
        if address >= 0xA0000
    ]
    require(video_writes, "hostile POST did not establish an MDA baseline")
    require(
        all(MDA_BASE <= address and address + size <= MDA_BASE + VISIBLE_BYTES
            for address, size in video_writes),
        "hostile POST wrote outside the visible MDA baseline",
    )


def test_abort_and_unknown(image: bytes) -> None:
    abort = Machine(image)
    abort.w8(H["prompt_valid"], 1)
    abort.w8(H["prompt_hole"], 0x6D)
    require(not abort.run(3), "ABORT returned carry")
    require(abort.u8(H["prompt_valid"]) == 0, "ABORT did not invalidate")
    require(abort.u8(H["prompt_hole"]) == 0x6D, "ABORT touched prompt hole")
    require(status_values(abort) == [0], "ABORT write contract mismatch")

    unknown = Machine(image)
    unknown.w8(H["prompt_valid"], 0xA5)
    unknown.w8(H["prompt_hole"], 0x6D)
    require(unknown.run(4), "unknown mode did not return carry")
    require(unknown.u8(H["prompt_valid"]) == 0xA5, "unknown mode touched state")
    require(unknown.u8(H["prompt_hole"]) == 0x6D, "unknown mode touched hole")
    require(nonstack_writes(unknown) == [], "unknown mode performed a product write")


def main() -> int:
    image, actual_end = assemble()
    checks = [
        ("abi_and_size", lambda: check_abi(image, actual_end)),
        ("pre_cold", lambda: test_pre_cold(image)),
        ("pre_cga", lambda: test_pre_cga(image)),
        ("pre_mda_wrap", lambda: test_pre_mda(image, length=173, row=20, cols=80)),
        ("pre_mda_max255", lambda: test_pre_mda(image, length=255, row=18, cols=40)),
        ("pre_ineligible", lambda: test_ineligible_pre(image)),
        ("post_mda_scrub_recovery", lambda: test_post_mda(image)),
        ("post_cga_preservation", lambda: test_post_cga(image)),
        ("post_hostile_state", lambda: test_hostile_post(image)),
        ("abort_and_unknown", lambda: test_abort_and_unknown(image)),
    ]
    passed = []
    for name, check in checks:
        check()
        passed.append(name)
    print(json.dumps({
        "status": "ok",
        "phase": "k14_product_state_guard",
        "origin": f"0x{ORIGIN:04x}",
        "image_bytes": len(image),
        "code_data_bytes": actual_end,
        "checks": passed,
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CheckFailure, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"K14 state-guard gate FAILED: {exc}") from exc
