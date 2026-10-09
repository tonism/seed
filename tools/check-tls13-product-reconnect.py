#!/usr/bin/env python3
"""Check product request admission and bounded reconnect/replay composition.

The prefix gates execute config caching, source bounds, the cached/cold TCP
route decision, and output-event selection. With --image, the separate H2
composition gate executes actual R/X/AEAD/H2/T and the resident retry scheduler,
using an independent synthetic peer and explicit BIOS/NIC/route fixture leaves.
No emulator or physical-provider behavior is inferred from these offline gates.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
import sys
from pathlib import Path

from unicorn import Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_DX,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SI,
    UC_X86_REG_SP,
)


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/ibm_pc_5150"
DISPATCH_GATE = ROOT / "tools/check-tls13-core-dispatch.py"
LAYOUT_GATE = ROOT / "tools/check-layout.py"
LAYOUT = ROOT / "targets/ibm_pc_5150/boot/core/layout.inc"
DATA = ROOT / "targets/ibm_pc_5150/boot/core/data.inc"

BUILD_RETURN_STUB = 0xFC00
SCREEN_COLS = 0x0F57
DPI_PROMPT_MARKER_ROW = 0x0F33
DPI_INPUT_BUF = 0x37C1 - 255
HANDOFF_STATUS = 0x0619
HANDOFF_STATUS_READY = 3
PROMPT_COLUMN = 2
PROMPT = (
    b"Explain why one durable human prompt survives a dead TLS channel, "
    b"including this wrapped tail: {same-request:true}."
)
LIVE_PROMPT = (
    b"What is six times seven? Reply with the answer in uppercase English "
    b"letters, with no spaces or punctuation."
)
DEFAULT_REASONING_EFFORT = b"xhigh"


def wire_model_tail(model: bytes, effort: bytes = DEFAULT_REASONING_EFFORT) -> bytes:
    """Return agent_cache's reconnect-safe model/reasoning JSON tail."""

    return model + b'","reasoning":{"effort":"' + effort + b'"}'


def install_wire_model_cache(
    machine: object,
    model: bytes,
    effort: bytes = DEFAULT_REASONING_EFFORT,
) -> None:
    tail = wire_model_tail(model, effort) + b"\0"
    require(
        len(tail) < STREAM["seed_model_len"],
        "wire model/reasoning tail reaches the live prompt-length byte",
    )
    machine.uc.mem_write(  # type: ignore[attr-defined]
        STREAM["chat_model_cache"], tail.ljust(STREAM["seed_model_len"], b"\0")
    )


def load_dispatch_gate():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_core_dispatch", DISPATCH_GATE
    )
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load TLS 1.3 core-dispatch harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = load_dispatch_gate()


def load_layout_gate():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_stream_bounds_layout", LAYOUT_GATE
    )
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load layout parser for stream bounds")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


L = load_layout_gate()
STREAM = L.parse_equates([LAYOUT, DATA])


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def fat12_entry(fat: bytes, cluster: int) -> int:
    offset = cluster + cluster // 2
    require(offset + 1 < len(fat), f"FAT cluster {cluster} escapes its table")
    word = fat[offset] | (fat[offset + 1] << 8)
    return (word >> 4) & 0x0FFF if cluster & 1 else word & 0x0FFF


def parse_product_image(
    image_path: Path, core: bytes
) -> tuple[bytes, int, dict[str, tuple[int, int, bytes]]]:
    """Return the exact packaged prompt assets and prove they bind to core."""

    image = image_path.read_bytes()
    require(len(image) >= 12 * 512, "product floppy image is truncated")
    sector_bytes = u16(image, 11)
    sectors_per_cluster = image[13]
    reserved = u16(image, 14)
    fat_count = image[16]
    root_entries = u16(image, 17)
    sectors_per_fat = u16(image, 22)
    require(
        sector_bytes == 512 and sectors_per_cluster == 1,
        "ready-turn gate requires the one-sector-cluster Seed FAT12 layout",
    )
    root_sectors = (root_entries * 32 + sector_bytes - 1) // sector_bytes
    root_start = reserved + fat_count * sectors_per_fat
    data_start = root_start + root_sectors
    fat_start = reserved * sector_bytes
    fat = image[fat_start : fat_start + sectors_per_fat * sector_bytes]

    def entries(block: bytes, count: int) -> dict[bytes, tuple[int, int, int]]:
        result: dict[bytes, tuple[int, int, int]] = {}
        for index in range(count):
            entry = block[index * 32 : (index + 1) * 32]
            if not entry or entry[0] == 0:
                break
            if entry[0] == 0xE5 or entry[11] & 0x08:
                continue
            result[bytes(entry[:11])] = (entry[11], u16(entry, 26), u32(entry, 28))
        return result

    def cluster_sector(cluster: int) -> int:
        require(cluster >= 2, f"invalid FAT data cluster {cluster}")
        return data_start + cluster - 2

    def file_bytes(cluster: int, size: int, label: str) -> bytes:
        remaining = size
        current = cluster
        seen: set[int] = set()
        result = bytearray()
        while remaining:
            require(current not in seen, f"{label} has a cyclic FAT chain")
            seen.add(current)
            sector = cluster_sector(current)
            start = sector * sector_bytes
            require(start + sector_bytes <= len(image), f"{label} escapes the image")
            take = min(remaining, sector_bytes)
            result.extend(image[start : start + take])
            remaining -= take
            following = fat12_entry(fat, current)
            if remaining:
                require(
                    2 <= following < 0xFF8,
                    f"{label} has a truncated FAT chain",
                )
                current = following
            else:
                require(
                    0xFF8 <= following <= 0xFFF,
                    f"{label} FAT chain continues past its declared size",
                )
        return bytes(result)

    root_offset = root_start * sector_bytes
    root = image[root_offset : root_offset + root_sectors * sector_bytes]
    root_files = entries(root, root_entries)
    require(b"SEED    SYS" in root_files, "product image has no SEED.SYS")
    require(b"SEED       " in root_files, "product image has no SEED directory")
    seed_attr, seed_cluster, seed_size = root_files[b"SEED    SYS"]
    directory_attr, directory_cluster, _directory_size = root_files[b"SEED       "]
    require(not (seed_attr & 0x10) and directory_attr & 0x10, "FAT root types drifted")
    require(
        file_bytes(seed_cluster, seed_size, "SEED.SYS") == core,
        "packaged SEED.SYS is not the checked final core",
    )
    directory_sector = cluster_sector(directory_cluster)
    directory_start = directory_sector * sector_bytes
    directory = image[directory_start : directory_start + sector_bytes]
    seed_files = entries(directory, sector_bytes // 32)
    result: dict[str, tuple[int, int, bytes]] = {}
    for label, fat_name in (
        ("identity", b"IDENTITY   "),
        ("compact", b"COMPACT    "),
        ("tools", b"TOOLS      "),
    ):
        require(fat_name in seed_files, f"product image has no SEED/{label.upper()}")
        attr, cluster, size = seed_files[fat_name]
        require(not (attr & 0x10) and 0 < size <= 512, f"SEED/{label.upper()} geometry drifted")
        result[label] = (cluster, size, file_bytes(cluster, size, f"SEED/{label.upper()}"))
    return image, data_start, result


def listing_offset_after(listing: str, marker: str) -> int:
    lines = listing.splitlines()
    emitted = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+")
    needle = f"{marker}:"
    for index, line in enumerate(lines):
        if needle not in line:
            continue
        for candidate in lines[index + 1 : index + 40]:
            match = emitted.match(candidate)
            if match is not None:
                return int(match.group(1), 16)
        break
    raise AssertionError(f"{marker} has no emitted address in listing")


def assert_source_contract() -> None:
    scheduler_source = (
        ROOT / "targets/ibm_pc_5150/boot/core/net_phase.inc"
    ).read_text(encoding="utf-8")
    scheduler = scheduler_source[
        : scheduler_source.index("tls13_product_net_block_end:")
    ]
    request = (
        ROOT / "targets/ibm_pc_5150/boot/phases/agent_request.inc"
    ).read_text(encoding="utf-8")
    exchange = (
        ROOT / "targets/ibm_pc_5150/boot/phases/http2/h2_exchange.asm"
    ).read_text(encoding="utf-8")
    stream = (
        ROOT / "targets/ibm_pc_5150/boot/phases/agent_api_stream.inc"
    ).read_text(encoding="utf-8")
    tcp_connect = (
        ROOT / "targets/ibm_pc_5150/boot/phases/tcp_connect.inc"
    ).read_text(encoding="utf-8")
    main = (
        ROOT / "targets/ibm_pc_5150/boot/core/main.inc"
    ).read_text(encoding="utf-8")
    agents_cfg = (
        ROOT / "targets/ibm_pc_5150/boot/phases/agents_cfg.inc"
    ).read_text(encoding="utf-8")
    require(
        "mov ah, 1" in scheduler
        and "mov [chat_resend_prompt_len], ax" in scheduler,
        "human-turn replay budget is not initialized atomically to one",
    )
    require(
        "dec byte [reconnect_retries]" in scheduler
        and "jz .pass" in scheduler,
        "bounded failure-to-reconnect transition is absent",
    )
    require(
        "cmp byte [tool_fc_state], 2" in scheduler
        and "je .nonreplayable" in scheduler
        and "cmp byte [agent_loop_pending], 0" in scheduler
        and "je .establish" in scheduler
        and ".establish:" in scheduler
        and "call tls13_product_establish_route" in scheduler
        and "jc .burn" in scheduler,
        "tool/agent-loop route denial is absent",
    )
    require(
        ".failed:" in scheduler
        and ".failed:\n    stc\n    ret" in scheduler,
        "route failure no longer unwinds into the caller's reconnect loop",
    )
    require(
        "agent_api_stream_append_prompt_screen_to_buffer:" in stream
        and "mov al, [chat_resend_prompt_len]" in stream
        and "mov ax, [video_seg]" in stream,
        "X phase no longer reconstructs the prompt from its durable screen copy",
    )
    require(
        "mov byte [reconnect_retries], 0" in exchange
        and "jmp request_aux_fail" in exchange,
        "text-seen fallback no longer retires without scheduler replay",
    )
    require(
        "cmp byte [h2+18], 2" in exchange
        and "cmp byte [api_stream_completed], 1" in exchange
        and "mov byte [api_stream_completed], 3" in exchange,
        "success no longer requires both authenticated END_STREAM and response.completed",
    )
    require(
        request.index("call .validate_stream_inputs")
        < request.index(".dlg_store:"),
        "R no longer validates 16K inputs before request construction",
    )
    require(
        stream.index("agent_request_phase.validate_stream_bounds")
        < stream.index("phase_call_res 10254"),
        "X no longer validates final stream metadata before its first TLS send",
    )
    require(
        STREAM["tools_schema_max_len"] == 384
        and STREAM["chat_context_len"] == 96
        and STREAM["basic_sidecar_stack_top_16k"] == 0x4000,
        "canonical 16K stream bounds drifted",
    )
    prompt_preload = main[
        main.index(".commit:") : main.index("agent_resolve_prompt_source:")
    ]
    require(
        "mov si, prompt_id_cluster" in prompt_preload
        and "mov si, prompt_tools_cluster" in prompt_preload
        and "call read_abs_sector" in prompt_preload
        and "call load_core_sectors_at" not in prompt_preload,
        "32K prompt caches are not loaded from full 16-bit FAT LBAs after route setup",
    )
    prompt_discovery = agents_cfg[
        agents_cfg.index("agents_cfg_phase_find_prompts:") :
        agents_cfg.index("agents_cfg_phase_identity_name")
    ]
    require(
        "tools_cache" not in prompt_discovery
        and "load_core_sectors_at" not in prompt_discovery,
        "agents_cfg still populates a high cache before the secure root retires",
    )
    ready_guard = (
        "cmp byte [handoff_addr + handoff_status], handoff_status_ready"
    )
    connected_guard = (
        "cmp byte [handoff_addr + handoff_net_status], "
        "net_status_tcp_connected"
    )
    require(
        ready_guard in tcp_connect
        and connected_guard in tcp_connect
        and tcp_connect.index(ready_guard)
        < tcp_connect.index(connected_guard)
        < tcp_connect.index("je tcp_reopen_cached_target"),
        "cached TCP reopen is not bound to same-boot connected transport state",
    )


def phase_runtime_label(
    core: bytes, listing: str, phase_id: bytes, marker: str
) -> int:
    sector, _sectors, destination = D.phase_geometry(core, phase_id)
    if phase_id == b"R":
        # The resident run_core_phase launcher loads R at low_scratch_start.
        # Its phase-table destination remains the shared X window for external
        # metadata compatibility, but is not the scheduler's execution address.
        destination = STREAM["low_scratch_start"]
    return destination + listing_offset_after(listing, marker) - sector * 512


def stream_bounds_machine(
    core: bytes,
    listing: str,
    *,
    load_x: bool = False,
    ready: bool = True,
) -> D.ResidentMachine:
    machine = D.ResidentMachine(core, listing)
    r_sector, r_sectors, _r_metadata_destination = D.phase_geometry(core, b"R")
    r_destination = STREAM["low_scratch_start"]
    machine.uc.mem_write(
        r_destination,
        core[r_sector * 512 : (r_sector + r_sectors) * 512],
    )
    if load_x:
        x_sector, x_sectors, x_destination = D.phase_geometry(core, b"X")
        machine.uc.mem_write(
            x_destination,
            core[x_sector * 512 : (x_sector + x_sectors) * 512],
        )

    machine.w8(HANDOFF_STATUS, HANDOFF_STATUS_READY if ready else 0)
    machine.w16(
        STREAM["handoff_addr"] + STREAM["handoff_ram_top"],
        STREAM["basic_sidecar_stack_top_16k"],
    )
    machine.w16(STREAM["prompt_tools_size"], STREAM["tools_schema_max_len"])
    machine.w16(STREAM["prompt_id_size"], 512)
    machine.w16(STREAM["prompt_compact_size"], 512)
    machine.w16(STREAM["chat_context_len_var"], STREAM["chat_context_len"])
    machine.w16(STREAM["chat_context_used"], 40)
    machine.w16(STREAM["note_len"], 10)
    machine.w16(STREAM["far_log_seg_var"], 0)
    machine.w16(STREAM["far_flushed_len"], 0)
    machine.w16(STREAM["far_flushed_len"] + 2, 0)
    machine.w16(STREAM["far_flushed_esc"], 0)
    machine.w16(STREAM["far_flushed_esc"] + 2, 0)
    machine.w16(STREAM["far_ctx_base"], 0)
    machine.w16(STREAM["far_ctx_base"] + 2, 1)
    machine.w16(STREAM["dialogue_off"], STREAM["chat_context_start"] + 10)
    machine.w16(STREAM["dialogue_cnt"], 30)
    machine.w16(STREAM["dialogue_cnt"] + 2, 0)
    machine.w16(
        D.resolve_symbol(listing, "tls_app_plain_ptr"),
        STREAM["api_request_plain"] + STREAM["tls_record_header_len"],
    )
    machine.w16(STREAM["tls_app_len"], 64)
    return machine


def test_product_agent_cache(core: bytes, listing: str) -> None:
    """Bind parsed reasoning config to the reconnect-safe request tail."""

    sector, sectors, destination = D.phase_geometry(core, b"V")
    require(
        (sectors, destination) == (1, STREAM["low_scratch_start"]),
        "agent-cache phase escaped its one-sector low window",
    )
    phase = core[sector * 512 : (sector + sectors) * 512]
    entry = phase_runtime_label(core, listing, b"V", "agent_cache_phase")
    model = b"gpt-5.6-sol"
    key = b"sk-seed-cache-overlap-gate"

    def configured_machine(effort: bytes | None, configured_model: bytes = model):
        machine = D.ResidentMachine(core, listing)
        machine.uc.mem_write(destination, phase)
        machine.uc.mem_write(
            STREAM["seed_agent_id"],
            b"openai\0".ljust(STREAM["agent_id_len"], b"\0"),
        )
        machine.uc.mem_write(
            STREAM["seed_model"],
            (configured_model + b"\0").ljust(STREAM["seed_model_len"], b"\0"),
        )
        key_image = (key + b"\0").ljust(STREAM["seed_key_len"], b"\0")
        machine.uc.mem_write(STREAM["seed_key"], key_image)
        reasoning_image = ((effort or b"") + b"\0").ljust(
            STREAM["seed_reasoning_len"], b"\0"
        )
        machine.uc.mem_write(STREAM["seed_reasoning"], reasoning_image)
        machine.w8(
            STREAM["seed_config_flags"],
            STREAM["seed_flag_reasoning"] if effort is not None else 0,
        )
        machine.w8(STREAM["chat_turn_failed"], 0xFF)
        return machine, key_image

    cases = (
        (None, DEFAULT_REASONING_EFFORT),
        (b"none", b"none"),
        (b"low", b"low"),
        (b"medium", b"medium"),
        (b"high", b"high"),
        (b"xhigh", b"xhigh"),
        (b"max", b"max"),
    )
    for configured, expected in cases:
        machine, key_image = configured_machine(configured)
        require(
            not machine.execute(entry),
            f"agent cache rejected reasoning effort {configured!r}",
        )
        require(
            machine.u8(STREAM["chat_turn_failed"]) == 0,
            "ENV-restore entry retained a stale turn-failure notification",
        )
        expected_tail = (wire_model_tail(model, expected) + b"\0").ljust(
            STREAM["seed_model_len"], b"\0"
        )
        require(
            bytes(
                machine.uc.mem_read(
                    STREAM["chat_model_cache"], STREAM["seed_model_len"]
                )
            )
            == expected_tail,
            f"agent cache serialized the wrong wire tail for {configured!r}",
        )
        require(
            bytes(
                machine.uc.mem_read(
                    STREAM["chat_key_cache"], STREAM["seed_key_len"]
                )
            )
            == key_image,
            f"agent cache corrupted the overlapping credential for {configured!r}",
        )

    invalid, _key_image = configured_machine(b'bad"')
    require(
        invalid.execute(entry),
        "agent cache accepted an unescaped/unsupported reasoning effort",
    )
    too_long, _key_image = configured_machine(
        None, b"m" * (STREAM["chat_model_value_max_len"] + 1)
    )
    require(
        too_long.execute(entry),
        "agent cache accepted a model that reaches the prompt-length byte",
    )


def test_response_output_event_filter(core: bytes, listing: str) -> None:
    """Render output-text deltas, never reasoning-stream deltas."""

    resident_bytes = u16(core, 15) * 512
    machine = D.ResidentMachine(core[:resident_bytes], listing)
    sector, sectors, destination = D.phase_geometry(core, b"T")
    require(sectors == 2, "response event filter escaped its two-sector window")
    machine.uc.mem_write(
        destination,
        core[sector * 512 : (sector + sectors) * 512],
    )
    entry = phase_runtime_label(core, listing, b"T", "agent_response_phase")
    input_buffer = STREAM["tls_rx_copy"]
    app_data_pointer = D.resolve_symbol(listing, "tls_app_data_ptr")
    rendered = bytearray()

    def print_char(uc: Uc) -> None:
        rendered.append(uc.reg_read(UC_X86_REG_AX) & 0xFF)
        machine.w8(
            STREAM["cursor_col"],
            (machine.u8(STREAM["cursor_col"]) + 1) & 0xFF,
        )
        D.near_return(uc, False)

    machine.on(D.resolve_symbol(listing, "print_char"), "output-char", print_char)
    machine.w8(HANDOFF_STATUS, HANDOFF_STATUS_READY)
    machine.w8(SCREEN_COLS, 80)
    machine.w8(STREAM["cursor_row"], 0)
    machine.w8(STREAM["cursor_col"], 0)
    machine.w8(STREAM["render_last_type"], 0)
    machine.w8(D.API_STREAM_COMPLETED, 0)
    machine.w8(D.API_STREAM_TEXT_SEEN, 0)
    machine.w8(STREAM["api_stream_state"], 0)
    machine.w8(STREAM["api_stream_delta_match"], 0)
    machine.w8(D.TOOL_FC_STATE, 0)
    machine.w8(STREAM["api_stream_done_match"], 0)
    machine.w8(STREAM["api_http_state"], 0)

    payload = (
        b'data: {"type":"response.reasoning_summary_text.delta",'
        b'"delta":"Ready."}\n\n'
        b'data: {"type":"response.output_text.delta",'
        b'"delta":"42"}\n\n'
        b'data: {"type":"response.completed"}\n\n'
    )
    split_points = (17, 61, 109, len(payload))
    start = 0
    for stop in split_points:
        fragment = payload[start:stop]
        machine.uc.mem_write(input_buffer, fragment)
        machine.w16(app_data_pointer, input_buffer)
        machine.w16(STREAM["tls_app_len"], len(fragment))
        machine.execute(entry)
        start = stop

    require(
        bytes(rendered) == b"42",
        f"response event filter rendered {bytes(rendered)!r}, expected b'42'",
    )
    require(
        machine.u8(D.API_STREAM_TEXT_SEEN) == 1,
        "output-text delta did not publish text-seen",
    )
    require(
        machine.u8(D.API_STREAM_COMPLETED) == 1,
        "filtered DATA did not publish response.completed (END_STREAM is owned by H2)",
    )




def test_first_ready_stale_dialogue(core: bytes, listing: str) -> None:
    machine = stream_bounds_machine(core, listing)
    input_entry = phase_runtime_label(
        core, listing, b"R", ".validate_stream_inputs"
    )
    dialogue_store = phase_runtime_label(core, listing, b"R", ".dlg_store")
    dialogue_ready = phase_runtime_label(
        core, listing, b"R", ".dialogue_bounds_ready"
    )

    # ROM BASIC does not promise zero-filled reconnect state.  The early R
    # check must ignore stale dialogue metadata because .dlg_store replaces it
    # before the full check.
    machine.w16(STREAM["dialogue_off"], 0xE731)
    machine.w16(STREAM["dialogue_cnt"], 0xFFFF)
    machine.w16(STREAM["dialogue_cnt"] + 2, 0xFFFF)
    require(
        not machine.execute(input_entry),
        "first-ready input validation consumed stale dialogue metadata",
    )

    expected_off = STREAM["chat_context_start"] + 7
    expected_count = 33
    machine.uc.reg_write(UC_X86_REG_SI, expected_off)
    machine.uc.reg_write(UC_X86_REG_AX, expected_count)
    machine.uc.reg_write(UC_X86_REG_DX, 0)

    def finish_dialogue(uc: Uc) -> None:
        D.near_return(uc, False)

    machine.on(dialogue_ready, "dialogue-ready", finish_dialogue)
    require(
        not machine.execute(dialogue_store),
        "fresh first-ready dialogue publication failed",
    )
    require(
        machine.calls.get("dialogue-ready", 0) == 1
        and int.from_bytes(
            machine.uc.mem_read(STREAM["dialogue_off"], 2), "little"
        )
        == expected_off
        and int.from_bytes(
            machine.uc.mem_read(STREAM["dialogue_cnt"], 2), "little"
        )
        == expected_count
        and int.from_bytes(
            machine.uc.mem_read(STREAM["dialogue_cnt"] + 2, 2), "little"
        )
        == 0,
        "R did not overwrite poisoned first-ready dialogue metadata",
    )
    full_entry = phase_runtime_label(
        core, listing, b"R", ".validate_stream_bounds"
    )
    require(
        not machine.execute(full_entry),
        "X-edge validator rejected R's freshly computed first-ready dialogue",
    )


def test_r_input_bounds(core: bytes, listing: str) -> None:
    cases = (
        (
            "tools-size",
            lambda machine: machine.w16(
                STREAM["prompt_tools_size"], STREAM["tools_schema_max_len"] + 1
            ),
        ),
        (
            "identity-size",
            lambda machine: machine.w16(STREAM["prompt_id_size"], 513),
        ),
        (
            "compact-size",
            lambda machine: machine.w16(STREAM["prompt_compact_size"], 513),
        ),
        (
            "context-cap",
            lambda machine: machine.w16(
                STREAM["chat_context_len_var"], STREAM["chat_context_len"] + 1
            ),
        ),
        (
            "context-used",
            lambda machine: machine.w16(
                STREAM["chat_context_used"], STREAM["chat_context_len"] + 1
            ),
        ),
        (
            "note-used",
            lambda machine: machine.w16(STREAM["note_len"], 41),
        ),
        (
            "far-segment",
            lambda machine: machine.w16(STREAM["far_log_seg_var"], 0x1000),
        ),
        (
            "far-count-low",
            lambda machine: machine.w16(STREAM["far_flushed_len"], 1),
        ),
        (
            "far-count-high",
            lambda machine: machine.w16(STREAM["far_flushed_len"] + 2, 1),
        ),
        (
            "far-escaped-low",
            lambda machine: machine.w16(STREAM["far_flushed_esc"], 1),
        ),
        (
            "far-escaped-high",
            lambda machine: machine.w16(STREAM["far_flushed_esc"] + 2, 1),
        ),
    )
    input_entry = phase_runtime_label(
        core, listing, b"R", ".validate_stream_inputs"
    )
    for label, corrupt in cases:
        machine = stream_bounds_machine(core, listing)
        machine.w16(STREAM["dialogue_off"], 0xE731)
        machine.w16(STREAM["dialogue_cnt"], 0xFFFF)
        machine.w16(STREAM["dialogue_cnt"] + 2, 0xFFFF)
        corrupt(machine)
        require(
            machine.execute(input_entry),
            f"{label} reached R request work despite invalid 16K source state",
        )










def test_tcp_route_state_matrix(core: bytes, listing: str) -> None:
    """Execute C's cold-vs-cached decision from the generated phase image."""

    sector, sectors, destination = D.phase_geometry(core, b"C")
    require(
        (sectors, destination) == (3, 0x0900),
        "TCP-connect phase left its fixed three-sector window",
    )
    phase = core[sector * 512 : (sector + sectors) * 512]
    require(
        len(phase) == sectors * 512,
        "TCP-connect phase is truncated",
    )

    entry = D.phase_runtime_symbol(
        core, listing, b"C", "tcp_connect_phase"
    )
    flush = D.phase_runtime_symbol(
        core, listing, b"C", "ne_flush_receive_frames"
    )
    cold = D.phase_runtime_symbol(
        core, listing, b"C", "tcp_connect_target"
    )
    reopen = D.phase_runtime_symbol(
        core, listing, b"C", "tcp_reopen_cached_target"
    )
    require(entry == destination, "TCP-connect entry drifted from C base")

    handoff = STREAM["handoff_addr"]
    nic_family = handoff + STREAM["handoff_nic_family"]
    status_address = handoff + STREAM["handoff_status"]
    net_status_address = handoff + STREAM["handoff_net_status"]
    cases = (
        (
            "booting-connected",
            STREAM["handoff_status_booting"],
            STREAM["net_status_tcp_connected"],
            "cold",
        ),
        (
            "ready-restored-env",
            STREAM["handoff_status_ready"],
            STREAM["net_status_dhcp_ack_received"],
            "cold",
        ),
        (
            "ready-same-boot-connected",
            STREAM["handoff_status_ready"],
            STREAM["net_status_tcp_connected"],
            "reopen",
        ),
        (
            "ready-error",
            STREAM["handoff_status_ready"],
            0xFE,
            "cold",
        ),
    )

    for label, status, net_status, expected in cases:
        machine = D.ResidentMachine(core[: 4 * 512], listing)
        machine.uc.mem_write(destination, phase)
        # 3c501 takes the common no-register-cleanup edge, keeping this route
        # policy gate independent of host I/O emulation.
        machine.w8(nic_family, STREAM["family_3c501"])
        machine.w8(status_address, status)
        machine.w8(net_status_address, net_status)
        machine.w16(D.PRODUCT_TCP_DEST_PORT, 0)
        events: list[str] = []

        def return_leaf(uc: Uc, event: str) -> None:
            events.append(event)
            D.near_return(uc, False)

        machine.on(
            flush,
            "flush",
            lambda uc: return_leaf(uc, "flush"),
        )
        machine.on(
            cold,
            "cold",
            lambda uc: return_leaf(uc, "cold"),
        )
        machine.on(
            reopen,
            "reopen",
            lambda uc: return_leaf(uc, "reopen"),
        )
        require(
            not machine.execute(entry),
            f"{label} C-route decision returned failure",
        )
        actual = (
            "reopen"
            if "reopen" in events
            else "cold"
            if "cold" in events
            else "none"
        )
        require(
            actual == expected,
            f"{label} selected {actual}, expected {expected}: {events!r}",
        )
        require(
            events == (["reopen"] if expected == "reopen" else ["flush", "cold"]),
            f"{label} C-route edge ordering drifted: {events!r}",
        )
        require(
            int.from_bytes(
                machine.uc.mem_read(D.PRODUCT_TCP_DEST_PORT, 2), "little"
            )
            == D.PRODUCT_TCP_HTTPS_WORD,
            f"{label} did not seed the immutable HTTPS destination port",
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--core",
        type=Path,
        default=BUILD / "tls13-pack-base/SEED.SYS",
    )
    parser.add_argument(
        "--listing",
        type=Path,
        default=BUILD / "tls13-pack-base/SEED.SYS.lst",
    )
    parser.add_argument(
        "--image",
        type=Path,
        help="also execute the real 512 KiB ready turn from this packaged FAT12 image",
    )
    args = parser.parse_args()
    core = args.core.read_bytes()
    listing = args.listing.read_text(encoding="utf-8")

    assert_source_contract()
    test_product_agent_cache(core, listing)
    test_first_ready_stale_dialogue(core, listing)
    test_r_input_bounds(core, listing)
    test_tcp_route_state_matrix(core, listing)
    test_response_output_event_filter(core, listing)
    print("TLS 1.3 request admission: PASS "
          "(config-wire=9, first-ready-stale=1, r-input-bounds=11, "
          "c-route-matrix=4, output-event-filter=1)", flush=True)
    if args.image is not None:
        # R/X, authenticated responses, native continuations and bounded
        # reconnect execute against the final image in the H2 gate.
        import subprocess
        subprocess.run([
            sys.executable, str(ROOT / "tools/crypto-bench/tls13-product/run_http2_gates.py"),
            "--core", str(args.core), "--listing", str(args.listing),
            "--image", str(args.image),
        ], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
