#!/usr/bin/env python3
"""Gate the product TLS 1.3 bounded reconnect/replay contract.

The resident scheduler owns a deliberately small policy:

* a live application channel is reused without establishing a route;
* the first no-text failure retires that channel, establishes one fresh route,
  rebuilds the durable human request, and sends it once more;
* a second failure retires the fresh channel and returns failure;
* tool/agent-loop continuations are never rebuilt on a fresh route; and
* a transport failure after rendered text retires the channel without replay.

This gate executes the real resident scheduler under Unicorn.  Route
establishment, request transmission, and exchange outcomes are deterministic
leaves, while each request build executes the real R-phase
``restore_prompt_from_screen`` helper.  The text-seen case also executes the
real ``agent_api_exchange`` fallback and resident retirement leaf.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
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
        ROOT / "targets/ibm_pc_5150/boot/core/agent_api.inc"
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
        "or al, [agent_loop_pending]" in scheduler
        and "jz .establish" in scheduler
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
        ".restore_prompt_from_screen:" in request
        and "mov al, [chat_resend_prompt_len]" in request
        and "mov ax, [video_seg]" in request,
        "R phase no longer reconstructs the prompt from its durable screen copy",
    )
    require(
        "http_content_length_text db 'Content-Type:application/json', "
        "13, 10, 'Content-Length:', 0" in request,
        "OpenAI JSON media type is absent from the request header block",
    )
    require(
        "mov byte [reconnect_retries], 0" in exchange
        and "call tls13_product_retire_app_state" in exchange,
        "text-seen fallback no longer retires without scheduler replay",
    )
    require(
        "cmp byte [api_stream_completed], 3\n"
        "    jne .receive" in exchange
        and "cmp byte [api_stream_completed], 2\n"
        "    ja .success" in exchange,
        "provisional HTTP terminal no longer preserves rendered text or bounded failure",
    )
    require(
        request.index("call .validate_stream_inputs")
        < request.index(".dlg_store:"),
        "R no longer validates 16K inputs before request construction",
    )
    require(
        stream.index("agent_request_phase.validate_stream_bounds")
        < stream.index("tls_prepare_3c501_receive", stream.index(".ready_tail:")),
        "X no longer validates final stream metadata before its first TLS send",
    )
    require(
        stream.index("agent_request_phase.validate_product_prefix")
        < stream.index("tls_prepare_3c501_receive"),
        "X no longer validates the cold request pointer/length before TLS send",
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


class ProductHarness:
    """Real scheduler plus deterministic route/request/exchange leaves."""

    def __init__(
        self,
        core: bytes,
        listing: str,
        *,
        ready: bool,
        agent_loop: int = 0,
        tool_state: int = 0,
    ) -> None:
        self.core = core
        self.listing = listing
        self.machine = D.ResidentMachine(core, listing)
        self.events: list[str] = []
        self.loads: list[tuple[int, int]] = []
        self.build_prompts: list[bytes] = []
        self.sent_prompts: list[bytes] = []
        self.sent_digests: list[bytes] = []
        self.route_observations: list[tuple[int, bytes, int]] = []
        self.current_digest: bytes | None = None

        r_sector, r_sectors, r_destination = D.phase_geometry(core, b"R")
        require(
            (r_sectors, r_destination) == (3, D.X_PHASE_ENTRY),
            "R phase geometry drifted from the three-sector request window",
        )
        self.r_phase = core[
            r_sector * 512 : (r_sector + r_sectors) * 512
        ]
        helper_file = listing_offset_after(
            listing, ".restore_prompt_from_screen"
        )
        self.r_restore = r_destination + helper_file - r_sector * 512
        require(
            r_destination <= self.r_restore < r_destination + len(self.r_phase),
            "R prompt-restoration helper is outside the R phase",
        )

        y_sector, y_sectors, y_destination = D.phase_geometry(core, b"Y")
        self.response_key = (y_sectors << 8) | y_sector
        self.response_destination = y_destination

        machine = self.machine
        machine.w8(HANDOFF_STATUS, HANDOFF_STATUS_READY)
        machine.w8(D.TLS_READY, 1 if ready else 0)
        machine.w8(D.AGENT_LOOP_PENDING, agent_loop)
        machine.w8(D.TOOL_FC_STATE, tool_state)
        machine.w8(D.COMPACTING, 0)
        machine.w16(D.FAR_LOG_SEG, 0)
        machine.w8(D.DPI_INPUT_LEN, len(PROMPT))
        machine.w8(D.CHAT_PROMPT_LEN, len(PROMPT))
        machine.w16(D.VIDEO_SEG, 0xB800)
        machine.w8(SCREEN_COLS, 80)
        machine.w8(DPI_PROMPT_MARKER_ROW, 0x80 | 5)
        machine.uc.mem_write(DPI_INPUT_BUF, PROMPT)
        machine.uc.mem_write(
            D.TLS_APP_STATE_START,
            (
                b"\xA5"
                if ready
                else b"\0"
            )
            * (D.TLS_APP_STATE_END - D.TLS_APP_STATE_START),
        )
        self._write_prompt_to_screen(PROMPT)
        self._install_nic()
        self._install_request_build()
        self._install_loader_and_send()

    def _write_prompt_to_screen(self, prompt: bytes) -> None:
        segment = 0xB800
        columns = 80
        row = 5
        column = PROMPT_COLUMN
        for character in prompt:
            address = (segment << 4) + (row * columns + column) * 2
            self.machine.uc.mem_write(address, bytes((character, 0x07)))
            column += 1
            if column == columns:
                row += 1
                column = PROMPT_COLUMN

    def _install_nic(self) -> None:
        machine = self.machine
        machine.w16(
            D.EXPECTED_CALLBACKS["nic_vt_enter"], D.NIC_ENTER_STUB
        )
        machine.w16(
            D.EXPECTED_CALLBACKS["nic_vt_restore"], D.NIC_RESTORE_STUB
        )

        def enter(uc: Uc) -> None:
            self.events.append("nic-enter")
            D.poison_gp(uc)
            D.near_return(uc, False)

        def restore(uc: Uc) -> None:
            self.events.append("nic-restore")
            D.poison_gp(uc)
            # The scheduler must restore the saved exchange flags, not inherit
            # this deliberately hostile carry.
            D.near_return(uc, True)

        machine.on(D.NIC_ENTER_STUB, "enter", enter)
        machine.on(D.NIC_RESTORE_STUB, "restore", restore)

    def _install_request_build(self) -> None:
        machine = self.machine

        def start_real_restore(uc: Uc) -> None:
            self.events.append("build")
            uc.mem_write(D.X_PHASE_ENTRY, self.r_phase)
            stack = (uc.reg_read(UC_X86_REG_SP) - 2) & 0xFFFF
            uc.mem_write(stack, struct.pack("<H", BUILD_RETURN_STUB))
            uc.reg_write(UC_X86_REG_SP, stack)
            uc.reg_write(UC_X86_REG_IP, self.r_restore)

        def finish_build(uc: Uc) -> None:
            length = self.machine.u8(D.DPI_INPUT_LEN)
            prompt = bytes(uc.mem_read(DPI_INPUT_BUF, length))
            require(
                length == len(PROMPT) and prompt == PROMPT,
                "real R helper did not recover the durable human prompt",
            )
            self.build_prompts.append(prompt)
            self.current_digest = hashlib.sha256(
                b"Seed product request\0" + prompt
            ).digest()
            D.near_return(uc, False)

        machine.on(
            machine.symbols["run_core_phase"], "build", start_real_restore
        )
        machine.handlers[BUILD_RETURN_STUB] = finish_build

    def _install_loader_and_send(self) -> None:
        machine = self.machine

        def load(uc: Uc) -> None:
            key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            self.loads.append((key, destination))
            self.events.append(f"load-{destination:04x}")
            D.near_return(uc, False)

        def send(uc: Uc) -> None:
            require(
                self.current_digest is not None and self.build_prompts,
                "X send ran without a rebuilt request",
            )
            self.events.append("send")
            self.sent_prompts.append(self.build_prompts[-1])
            self.sent_digests.append(self.current_digest)
            # X normally returns the Y phase key/address for
            # agent_api_exchange's first load.
            uc.reg_write(UC_X86_REG_AX, self.response_key)
            uc.reg_write(UC_X86_REG_BX, self.response_destination)
            D.near_return(uc, False)

        machine.on(
            machine.symbols["load_core_sectors_at"], "load", load
        )
        machine.on(D.X_PHASE_ENTRY, "send", send)

    def clobber_receive_alias(self, value: int) -> None:
        self.machine.uc.mem_write(
            DPI_INPUT_BUF, bytes((value & 0xFF,)) * len(PROMPT)
        )
        self.machine.w8(D.DPI_INPUT_LEN, value)

    def install_route_stub(self) -> None:
        machine = self.machine

        def route(uc: Uc) -> None:
            app_state = bytes(
                uc.mem_read(
                    D.TLS_APP_STATE_START,
                    D.TLS_APP_STATE_END - D.TLS_APP_STATE_START,
                )
            )
            self.route_observations.append(
                (
                    self.machine.u8(D.TLS_READY),
                    app_state,
                    self.machine.u8(D.CHAT_PROMPT_LEN),
                )
            )
            self.events.append("route")
            self.clobber_receive_alias(0xE1)
            uc.mem_write(
                D.TLS_APP_STATE_START,
                b"\x5A" * len(app_state),
            )
            self.machine.w8(D.TLS_READY, 1)
            D.poison_gp(uc)
            D.near_return(uc, False)

        machine.on(
            machine.symbols["tls13_product_establish_route"],
            "route",
            route,
        )

    def observe_real_route(self) -> None:
        def observe(_uc: Uc) -> None:
            self.events.append("route-attempt")
            # Returning from a code hook without changing IP lets Unicorn
            # execute the real route establishment instructions.

        self.machine.on(
            self.machine.symbols["tls13_product_establish_route"],
            "route-attempt",
            observe,
        )

    def install_route_load_failure(self) -> None:
        def fail(uc: Uc) -> None:
            self.events.append("route-load-failed")
            D.near_return(uc, True)

        self.machine.on(
            self.machine.symbols["load_core_sectors_at"],
            "route-load-failed",
            fail,
        )

    def install_exchange_outcomes(self, failures: list[bool]) -> None:
        pending = failures.copy()

        def exchange(uc: Uc) -> None:
            require(pending, "scheduler performed an unbudgeted exchange")
            failed = pending.pop(0)
            self.events.append(
                "exchange-failed" if failed else "exchange-succeeded"
            )
            if failed:
                self.clobber_receive_alias(0xD3)
            D.poison_gp(uc)
            D.near_return(uc, failed)

        self.machine.on(
            self.machine.symbols["agent_api_exchange"],
            "exchange",
            exchange,
        )
        self.pending_exchange_outcomes = pending

    def install_text_seen_transport_failure(self, completed: int = 0) -> None:
        machine = self.machine
        machine.w8(D.API_STREAM_TEXT_SEEN, 1)
        machine.w8(D.API_STREAM_COMPLETED, completed)
        machine.w8(D.resolve_symbol(self.listing, "ka_sent_count"), 0)
        machine.leaf(
            D.resolve_symbol(
                self.listing, "tls_receive_application_data"
            ),
            "receive",
            carry=True,
        )
        machine.leaf(
            D.resolve_symbol(self.listing, "ne_transmit_tcp_flags"),
            "close",
            carry=False,
        )

    def run(self) -> bool:
        carry = self.machine.execute(
            self.machine.symbols["prepare_agent_endpoint_path"]
        )
        pending = getattr(self, "pending_exchange_outcomes", [])
        require(not pending, f"unused exchange outcomes remain: {pending!r}")
        return carry

    def app_state(self) -> bytes:
        return bytes(
            self.machine.uc.mem_read(
                D.TLS_APP_STATE_START,
                D.TLS_APP_STATE_END - D.TLS_APP_STATE_START,
            )
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


def test_response_http_terminal_drain(core: bytes, listing: str) -> None:
    """Do not publish completion until the authenticated HTTP terminal.

    OpenAI's response.completed event can precede the final chunk boundary by
    one or more TLS records.  Returning at the event and clearing a coalesced
    tail silently skips a server record sequence, so the next ready turn fails
    authentication before the provider can answer.
    """

    resident_bytes = u16(core, 15) * 512
    machine = D.ResidentMachine(core[:resident_bytes], listing)
    sector, sectors, destination = D.phase_geometry(core, b"T")
    phase = core[sector * 512 : (sector + sectors) * 512]
    machine.uc.mem_write(destination, phase)
    entry = phase_runtime_label(core, listing, b"T", "agent_response_phase")
    input_buffer = STREAM["tls_rx_copy"]
    app_data_pointer = D.resolve_symbol(listing, "tls_app_data_ptr")
    machine.leaf(
        D.resolve_symbol(listing, "agent_api_keepalive"),
        "terminal-keepalive",
        carry=False,
    )
    machine.w8(D.API_STREAM_COMPLETED, 0)
    machine.w8(D.API_STREAM_TEXT_SEEN, 0)
    machine.w8(D.TOOL_FC_STATE, 0)
    machine.w8(STREAM["api_stream_done_match"], 0)
    machine.w8(STREAM["api_http_state"], 0)

    def feed(payload: bytes) -> None:
        require(
            len(payload) <= STREAM["tls_payload_buffer_len"],
            "HTTP-terminal fixture exceeds the response input buffer",
        )
        machine.uc.mem_write(input_buffer, payload)
        machine.w16(app_data_pointer, input_buffer)
        machine.w16(STREAM["tls_app_len"], len(payload))
        machine.execute(entry)

    feed(b"0\r\n\r\n")
    require(
        machine.u8(D.API_STREAM_COMPLETED) == 2,
        "HTTP terminal without response.completed was not bounded as failure",
    )
    machine.w8(D.API_STREAM_COMPLETED, 0)
    machine.w8(STREAM["api_http_state"], 0)
    # The live OpenAI header currently ends in `alt-svc: ... ma=86400`.
    # Its final zero plus the header delimiter is byte-identical to the
    # chunked terminal. It must remain provisional rather than ending the
    # response before the SSE body is parsed.
    feed(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
        b"alt-svc: h3=\":443\"; ma=86400\r\n\r\n"
    )
    require(
        machine.u8(D.API_STREAM_COMPLETED) == 2,
        "hostile OpenAI header suffix did not enter provisional drain state",
    )
    feed(
        b'data: {"type":"response.completed","response":'
        b'{"output":[{"type":"function_call"}]}}\n\n'
    )
    require(
        machine.u8(D.API_STREAM_COMPLETED) == 1,
        "response.completed did not clear the provisional header terminal",
    )
    require(
        machine.u8(D.TOOL_FC_STATE) == 0,
        "post-completion response metadata re-entered function-call parsing",
    )
    feed(b"0\r\n")
    require(
        machine.u8(D.API_STREAM_COMPLETED) == 1,
        "split HTTP terminal completed before its final bytes",
    )
    feed(b"\r\n")
    require(
        machine.u8(D.API_STREAM_COMPLETED) == 3,
        "exact split HTTP terminal did not complete the response",
    )
    require(
        machine.calls.get("terminal-keepalive", 0) == 5,
        f"response phase invocation count drifted: {machine.calls!r}",
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
    machine.leaf(
        D.resolve_symbol(listing, "agent_api_keepalive"),
        "output-keepalive",
        carry=False,
    )
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
        b'data: {"type":"response.completed"}\n\n0\r\n\r\n'
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
        machine.u8(D.API_STREAM_COMPLETED) == 3,
        "filtered response did not reach authenticated HTTP completion",
    )


def test_512k_ready_turn_from_floppy(
    core: bytes, listing: str, image_path: Path
) -> dict[str, object]:
    """Execute the real cached R -> X -> resident exchange -> T handoff.

    The network boundary supplies one already-authenticated response record,
    but the product scheduler, phase loader, response dispatch, and cache copy
    remain real.  This binds the phase key returned by X to the exact shipped T
    image without requiring a live provider response in an offline gate.
    """

    image, data_start, assets = parse_product_image(image_path, core)
    identity_cluster, identity_size, identity = assets["identity"]
    compact_cluster, compact_size, _compact = assets["compact"]
    tools_cluster, tools_size, tools = assets["tools"]
    identity_lba = data_start + identity_cluster - 2
    tools_lba = data_start + tools_cluster - 2
    require(
        identity_lba > 0xFF and tools_lba > 0xFF,
        "packaged prompts no longer exercise the full-width FAT-LBA boundary",
    )

    resident_bytes = u16(core, 15) * 512
    require(resident_bytes == 2048, "ready-turn gate requires the four-sector nucleus")
    machine = D.ResidentMachine(core[:resident_bytes], listing)
    loop_cache_count = D.resolve_symbol(listing, "loop_cache_count")
    tls_app_plain_ptr = D.resolve_symbol(listing, "tls_app_plain_ptr")
    read_sector = D.resolve_symbol(listing, "read_abs_sector")
    preload = D.resolve_symbol(listing, "preload_loop_cache")
    sends: list[bytes] = []
    reads: list[tuple[int, int]] = []
    events: list[str] = []
    response_sector, response_sectors, response_destination = D.phase_geometry(
        core, b"T"
    )
    response_image = core[
        response_sector * 512 : (response_sector + response_sectors) * 512
    ]

    def write32(address: int, value: int) -> None:
        machine.uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def disk_read(uc: Uc) -> None:
        lba = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = (
            ((uc.reg_read(UC_X86_REG_ES) & 0xFFFF) << 4)
            + (uc.reg_read(UC_X86_REG_BX) & 0xFFFF)
        )
        start = lba * 512
        require(start + 512 <= len(image), f"guest requested out-of-image LBA {lba}")
        uc.mem_write(destination, image[start : start + 512])
        # Host-side BIOS emulation writes may replace a phase at an address
        # Unicorn has already translated.  Real x86 fetches the new bytes;
        # invalidate the corresponding TB so this harness does too.
        uc.ctl_remove_cache(destination, destination + 511)
        reads.append((lba, destination))
        events.append(f"read-{lba}")
        D.near_return(uc, False)

    machine.on(read_sector, "disk-read", disk_read)
    machine.w16(
        STREAM["handoff_addr"] + STREAM["handoff_ram_top"], 0x8000
    )
    machine.w16(loop_cache_count, 0)
    machine.w16(STREAM["prompt_id_cluster"], identity_cluster)
    machine.w16(STREAM["prompt_id_size"], identity_size)
    machine.w16(STREAM["prompt_compact_cluster"], compact_cluster)
    machine.w16(STREAM["prompt_compact_size"], compact_size)
    machine.w16(STREAM["prompt_tools_cluster"], tools_cluster)
    machine.w16(STREAM["prompt_tools_size"], tools_size)
    machine.uc.mem_write(
        STREAM["tools_cache"], b"\xA5" * STREAM["tools_cache_len"]
    )
    machine.uc.mem_write(
        STREAM["loop_cache_start"],
        b"\x5A" * (STREAM["loop_cache_end"] - STREAM["loop_cache_start"]),
    )
    require(not machine.execute(preload), "post-bootstrap loop-cache preload failed")
    require(machine.u8(loop_cache_count) == 5, "loop-cache entry count drifted")
    require(
        bytes(machine.uc.mem_read(STREAM["prompt_id_cache"], 512))
        == identity.ljust(512, b"\0"),
        "IDENTITY cache does not match its packaged high-cluster file",
    )
    require(
        bytes(machine.uc.mem_read(STREAM["tools_cache"], 512))
        == tools.ljust(512, b"\0"),
        "TOOLS cache does not match its packaged high-cluster file",
    )
    require(
        reads.count((identity_lba, STREAM["prompt_id_cache"])) == 1
        and reads.count((tools_lba, STREAM["tools_cache"])) == 1,
        f"prompt cache reads did not preserve their full LBAs: {reads!r}",
    )

    # Exact 6 MHz/512 KiB post-cold memory geometry: the secure controller has
    # retired its 64 KiB reservation, while the resident 32 KiB cache remains.
    machine.w8(HANDOFF_STATUS, HANDOFF_STATUS_READY)
    machine.w16(
        STREAM["handoff_addr"] + STREAM["handoff_flags"],
        STREAM["handoff_flag_cpu_286plus"],
    )
    machine.w16(
        STREAM["handoff_addr"] + STREAM["handoff_net_status"],
        STREAM["net_status_tcp_connected"],
    )
    machine.w8(D.TLS_READY, 1)
    machine.w8(D.AGENT_LOOP_PENDING, 0)
    machine.w8(D.TOOL_FC_STATE, 0)
    machine.w8(D.COMPACTING, 0)
    machine.w8(STREAM["compact_next"], 0)
    machine.w16(STREAM["chat_context_len_var"], 0x00E0)
    machine.w16(STREAM["chat_compact_threshold"], 0x00A8)
    machine.w16(STREAM["chat_effective_cap"], 0x00E0)
    machine.w16(STREAM["chat_context_used"], 0)
    machine.w16(STREAM["note_len"], 0)
    machine.w16(STREAM["far_log_seg_var"], 0x4000)
    write32(STREAM["far_flushed_len"], 0)
    write32(STREAM["far_flushed_esc"], 0)
    write32(STREAM["far_window_cap"], 0x00030000)
    write32(STREAM["far_arena_base"], 0x00010000)
    write32(STREAM["far_arena_top"], 0x00040000)
    write32(STREAM["far_ctx_base"], 0x00040000)
    machine.w16(STREAM["ems_page_count"], 0)
    machine.w16(STREAM["dialogue_off"], 0xE731)
    write32(STREAM["dialogue_cnt"], 0xFFFFFFFF)

    model = b"gpt-5"
    key = b"sk-seed-ready-turn-gate"
    install_wire_model_cache(machine, model)
    machine.uc.mem_write(STREAM["chat_key_cache"], key + b"\0")
    machine.w8(D.DPI_INPUT_LEN, len(PROMPT))
    machine.w8(D.CHAT_PROMPT_LEN, len(PROMPT))
    machine.w16(D.VIDEO_SEG, 0xB800)
    machine.w8(SCREEN_COLS, 80)
    machine.w8(DPI_PROMPT_MARKER_ROW, 0x80 | 5)
    machine.uc.mem_write(DPI_INPUT_BUF, b"\xCC" * len(PROMPT))
    column = PROMPT_COLUMN
    row = 5
    for character in PROMPT:
        address = (0xB800 << 4) + (row * 80 + column) * 2
        machine.uc.mem_write(address, bytes((character, 0x07)))
        column += 1
        if column == 80:
            row += 1
            column = PROMPT_COLUMN

    machine.w16(D.EXPECTED_CALLBACKS["nic_vt_enter"], D.NIC_ENTER_STUB)
    machine.w16(D.EXPECTED_CALLBACKS["nic_vt_restore"], D.NIC_RESTORE_STUB)

    def enter(uc: Uc) -> None:
        events.append("nic-enter")
        D.poison_gp(uc)
        D.near_return(uc, False)

    def restore(uc: Uc) -> None:
        events.append("nic-restore")
        D.poison_gp(uc)
        D.near_return(uc, True)

    def prepare_receive(uc: Uc) -> None:
        events.append("prepare-send")
        D.near_return(uc, False)

    def send(uc: Uc) -> None:
        pointer = u16(bytes(uc.mem_read(tls_app_plain_ptr, 2)), 0)
        length = u16(bytes(uc.mem_read(STREAM["tls_app_len"], 2)), 0)
        require(
            pointer == STREAM["api_request_plain"] + STREAM["tls_record_header_len"]
            and 0 < length <= STREAM["api_request_plain_len"],
            f"ready-turn TLS record has invalid plaintext geometry {pointer:#x}/{length}",
        )
        sends.append(bytes(uc.mem_read(pointer, length)))
        events.append(f"send-{length}")
        D.near_return(uc, False)

    def render_response(uc: Uc) -> None:
        events.append("response-phase")
        D.near_return(uc, False)

    def receive(uc: Uc) -> None:
        require(
            bytes(uc.mem_read(response_destination, len(response_image)))
            == response_image,
            "X returned a response key that did not load the exact shipped T phase",
        )
        # Install this only after X has been replaced by T: both phases execute
        # at net_setup_phase_start, so an eager hook would intercept X itself.
        machine.on(response_destination, "response-phase", render_response)
        machine.w8(D.API_STREAM_TEXT_SEEN, 1)
        machine.w8(D.API_STREAM_COMPLETED, 3)
        events.append("authenticated-response")
        D.near_return(uc, False)

    machine.on(D.NIC_ENTER_STUB, "ready-enter", enter)
    machine.on(D.NIC_RESTORE_STUB, "ready-restore", restore)
    machine.leaf(
        D.resolve_symbol(listing, "tls_prepare_3c501_receive"),
        "prepare-send",
        carry=False,
    )
    machine.on(
        D.resolve_symbol(listing, "tls_send_application_data_current_seq"),
        "tls-send",
        send,
    )
    machine.on(
        D.resolve_symbol(listing, "tls_receive_application_data"),
        "authenticated-response",
        receive,
    )
    machine.leaf(
        D.resolve_symbol(listing, "ne_transmit_tcp_ack"),
        "response-ack",
        carry=False,
    )
    turn_read_start = len(reads)
    require(
        not machine.execute(machine.symbols["prepare_agent_endpoint_path"]),
        "real cached 512 KiB ready turn returned failure",
    )
    turn_reads = reads[turn_read_start:]
    require(
        len(turn_reads) == 1
        and turn_reads[0][1] == STREAM["low_scratch_start"],
        f"ready turn performed unexpected floppy reads: {turn_reads!r}",
    )
    require(
        "nic-enter" in events
        and all(not event.startswith("read-") for event in events[events.index("nic-enter") + 1 :]),
        "ready turn read the floppy inside its NIC/TLS lease",
    )
    require(
        machine.calls.get("ready-enter", 0)
        == machine.calls.get("ready-restore", 0)
        == 1,
        f"ready-turn dispatch/NIC lease drifted: {machine.calls!r}",
    )
    require(
        machine.calls.get("authenticated-response", 0)
        == machine.calls.get("response-ack", 0)
        == machine.calls.get("response-phase", 0)
        == 1,
        f"ready-turn X-to-T response handoff drifted: {machine.calls!r}",
    )
    require(len(sends) >= 4, f"ready request was not streamed: {[len(x) for x in sends]!r}")
    wire = b"".join(sends)
    require(
        wire.startswith(b"POST /v1/responses HTTP/1.1\r\n")
        and b"\r\n\r\n" in wire,
        "ready-turn stream has no complete HTTP request prefix",
    )
    header, body = wire.split(b"\r\n\r\n", 1)
    match = re.search(rb"(?:^|\r\n)Content-Length:([0-9]+)(?:\r\n|$)", header)
    require(match is not None, "ready-turn request has no Content-Length")
    require(int(match.group(1)) == len(body), "ready-turn Content-Length does not match streamed body")
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"ready-turn request is invalid JSON: {exc}") from exc
    require(
        document.get("model") == model.decode("ascii")
        and document.get("reasoning") == {"effort": "xhigh"},
        "ready-turn request lost its model/reasoning contract",
    )
    flattened_tools = bytes(value if value >= 32 else 32 for value in tools)
    flattened_identity = bytes(value if value >= 32 else 32 for value in identity)
    require(
        wire.count(flattened_tools) == 1
        and wire.count(flattened_identity) == 1
        and wire.count(PROMPT) == 1,
        "ready-turn stream did not contain exact TOOLS, IDENTITY, and prompt bytes once",
    )
    require(
        flattened_tools not in sends[0]
        and flattened_identity not in sends[0]
        and wire.index(flattened_tools) < wire.index(flattened_identity) < wire.index(PROMPT),
        "ready-turn streamed fields in the wrong order",
    )
    return {
        "identity_cluster": identity_cluster,
        "tools_cluster": tools_cluster,
        "turn_reads": len(turn_reads),
        "records": len(sends),
        "record_lengths": [len(value) for value in sends],
        "response_sector": response_sector,
        "response_sectors": response_sectors,
    }


def test_16k_reconnect_request_from_floppy(
    core: bytes, listing: str, image_path: Path
) -> dict[str, object]:
    """Execute both exact 16 KiB R -> X request builds around a dead session.

    Unlike ``ProductHarness``, this uses the packaged R/X images and their real
    floppy prompt streamers.  The first authenticated application channel is
    failed before any response text, the route leaf destroys receive scratch,
    and the resident scheduler must rebuild the same complete HTTP/JSON request
    from the on-screen human prompt on its one fresh channel.
    """

    image, data_start, assets = parse_product_image(image_path, core)
    identity_cluster, identity_size, identity = assets["identity"]
    compact_cluster, compact_size, _compact = assets["compact"]
    tools_cluster, tools_size, tools = assets["tools"]
    identity_lba = data_start + identity_cluster - 2
    tools_lba = data_start + tools_cluster - 2

    resident_bytes = u16(core, 15) * 512
    require(resident_bytes == 2048, "16K reconnect gate requires the four-sector nucleus")
    machine = D.ResidentMachine(core[:resident_bytes], listing)
    read_sector = D.resolve_symbol(listing, "read_abs_sector")
    tls_app_plain_ptr = D.resolve_symbol(listing, "tls_app_plain_ptr")
    reads: list[tuple[int, int]] = []
    records: list[bytes] = []
    requests: list[bytes] = []
    events: list[str] = []

    def write32(address: int, value: int) -> None:
        machine.uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def disk_read(uc: Uc) -> None:
        lba = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        destination = (
            ((uc.reg_read(UC_X86_REG_ES) & 0xFFFF) << 4)
            + (uc.reg_read(UC_X86_REG_BX) & 0xFFFF)
        )
        start = lba * 512
        require(start + 512 <= len(image), f"guest requested out-of-image LBA {lba}")
        uc.mem_write(destination, image[start : start + 512])
        uc.ctl_remove_cache(destination, destination + 511)
        reads.append((lba, destination))
        events.append(f"read-{lba}")
        D.near_return(uc, False)

    machine.on(read_sector, "disk-read-16k", disk_read)
    machine.w16(
        STREAM["handoff_addr"] + STREAM["handoff_ram_top"],
        STREAM["basic_sidecar_stack_top_16k"],
    )
    machine.w16(STREAM["handoff_addr"] + STREAM["handoff_flags"], 0)
    machine.w16(
        STREAM["handoff_addr"] + STREAM["handoff_net_status"],
        STREAM["net_status_tcp_connected"],
    )
    machine.w8(HANDOFF_STATUS, HANDOFF_STATUS_READY)
    machine.w16(D.resolve_symbol(listing, "loop_cache_count"), 0)
    machine.w16(STREAM["prompt_id_cluster"], identity_cluster)
    machine.w16(STREAM["prompt_id_size"], identity_size)
    machine.w16(STREAM["prompt_compact_cluster"], compact_cluster)
    machine.w16(STREAM["prompt_compact_size"], compact_size)
    machine.w16(STREAM["prompt_tools_cluster"], tools_cluster)
    machine.w16(STREAM["prompt_tools_size"], tools_size)

    machine.w8(D.TLS_READY, 1)
    machine.w8(D.AGENT_LOOP_PENDING, 0)
    machine.w8(D.TOOL_FC_STATE, 0)
    machine.w8(D.COMPACTING, 0)
    machine.w8(STREAM["compact_next"], 0)
    machine.w16(STREAM["chat_context_len_var"], STREAM["chat_context_len"])
    machine.w16(
        STREAM["chat_compact_threshold"],
        (STREAM["chat_context_len"] * 3) // 4,
    )
    machine.w16(STREAM["chat_effective_cap"], STREAM["chat_context_len"])
    machine.w16(STREAM["chat_context_used"], 0)
    machine.w16(STREAM["note_len"], 0)
    machine.w16(STREAM["far_log_seg_var"], 0)
    write32(STREAM["far_flushed_len"], 0)
    write32(STREAM["far_flushed_esc"], 0)
    write32(STREAM["far_window_cap"], 0)
    write32(STREAM["far_arena_base"], 0x10000)
    write32(STREAM["far_arena_top"], 0x10000)
    write32(STREAM["far_ctx_base"], 0x10000)
    machine.w16(STREAM["ems_page_count"], 0)
    machine.uc.mem_write(
        D.TLS_APP_STATE_START,
        b"\xA5" * (D.TLS_APP_STATE_END - D.TLS_APP_STATE_START),
    )

    model = b"gpt-5.6-sol"
    key = b"sk-seed-16k-reconnect-gate"
    install_wire_model_cache(machine, model)
    machine.uc.mem_write(STREAM["chat_key_cache"], key + b"\0")
    machine.w8(D.DPI_INPUT_LEN, len(LIVE_PROMPT))
    machine.w8(D.CHAT_PROMPT_LEN, len(LIVE_PROMPT))
    machine.w16(D.VIDEO_SEG, 0xB800)
    machine.w8(SCREEN_COLS, 80)
    machine.w8(DPI_PROMPT_MARKER_ROW, 0x80 | 5)
    machine.uc.mem_write(DPI_INPUT_BUF, b"\xCC" * len(LIVE_PROMPT))
    column = PROMPT_COLUMN
    row = 5
    for character in LIVE_PROMPT:
        address = (0xB800 << 4) + (row * 80 + column) * 2
        machine.uc.mem_write(address, bytes((character, 0x07)))
        column += 1
        if column == 80:
            row += 1
            column = PROMPT_COLUMN

    machine.w16(D.EXPECTED_CALLBACKS["nic_vt_enter"], D.NIC_ENTER_STUB)
    machine.w16(D.EXPECTED_CALLBACKS["nic_vt_restore"], D.NIC_RESTORE_STUB)

    def enter(uc: Uc) -> None:
        events.append("nic-enter")
        D.poison_gp(uc)
        D.near_return(uc, False)

    def restore(uc: Uc) -> None:
        events.append("nic-restore")
        D.poison_gp(uc)
        D.near_return(uc, True)

    def prepare_receive(uc: Uc) -> None:
        events.append("prepare-send")
        D.near_return(uc, False)

    def send(uc: Uc) -> None:
        pointer = u16(bytes(uc.mem_read(tls_app_plain_ptr, 2)), 0)
        length = u16(bytes(uc.mem_read(STREAM["tls_app_len"], 2)), 0)
        require(
            pointer == STREAM["api_request_plain"] + STREAM["tls_record_header_len"]
            and 0 < length <= STREAM["api_request_plain_len"],
            "16K reconnect record has invalid plaintext geometry "
            f"{pointer:#x}/{length}; tail={events[-12:]!r}",
        )
        records.append(bytes(uc.mem_read(pointer, length)))
        events.append(f"send-{length}")
        D.near_return(uc, False)

    outcomes = [True, False]

    def exchange(uc: Uc) -> None:
        require(outcomes, "16K reconnect gate performed an unbudgeted exchange")
        require(records, "16K reconnect exchange had no request records")
        requests.append(b"".join(records))
        records.clear()
        failed = outcomes.pop(0)
        events.append("exchange-failed" if failed else "exchange-succeeded")
        if failed:
            uc.mem_write(DPI_INPUT_BUF, b"\xD3" * len(LIVE_PROMPT))
        else:
            machine.w8(D.API_STREAM_TEXT_SEEN, 1)
            machine.w8(D.API_STREAM_COMPLETED, 3)
        D.near_return(uc, failed)

    def establish(uc: Uc) -> None:
        require(machine.u8(D.TLS_READY) == 0, "fresh route began before old state was retired")
        require(
            machine.u8(D.CHAT_PROMPT_LEN) == len(LIVE_PROMPT),
            "fresh route lost the durable prompt length",
        )
        uc.mem_write(DPI_INPUT_BUF, b"\xE1" * len(LIVE_PROMPT))
        uc.mem_write(
            D.TLS_APP_STATE_START,
            b"\x5A" * (D.TLS_APP_STATE_END - D.TLS_APP_STATE_START),
        )
        machine.w8(D.TLS_READY, 1)
        events.append("fresh-route")
        D.near_return(uc, False)

    machine.on(D.NIC_ENTER_STUB, "16k-enter", enter)
    machine.on(D.NIC_RESTORE_STUB, "16k-restore", restore)
    machine.leaf(
        D.resolve_symbol(listing, "tls_prepare_3c501_receive"),
        "16k-prepare-send",
        carry=False,
    )
    machine.on(
        D.resolve_symbol(listing, "tls_send_application_data_current_seq"),
        "16k-send",
        send,
    )
    machine.on(machine.symbols["agent_api_exchange"], "16k-exchange", exchange)
    machine.on(
        machine.symbols["tls13_product_establish_route"],
        "16k-establish",
        establish,
    )

    require(
        not machine.execute(machine.symbols["prepare_agent_endpoint_path"]),
        "exact 16K request reconnect returned failure",
    )
    require(not outcomes and not records, "16K reconnect did not consume both exact requests")
    require(
        machine.calls.get("16k-exchange", 0) == 2
        and machine.calls.get("16k-establish", 0) == 1
        and machine.calls.get("16k-enter", 0) == 2
        and machine.calls.get("16k-restore", 0) == 2,
        f"16K reconnect topology drifted: {machine.calls!r}",
    )

    parsed: list[dict[str, object]] = []
    for index, wire in enumerate(requests, 1):
        require(
            wire.startswith(b"POST /v1/responses HTTP/1.1\r\n")
            and b"\r\n\r\n" in wire,
            f"16K request {index} has no complete HTTP prefix",
        )
        header, body = wire.split(b"\r\n\r\n", 1)
        match = re.search(rb"(?:^|\r\n)Content-Length:([0-9]+)(?:\r\n|$)", header)
        require(match is not None, f"16K request {index} has no Content-Length")
        require(
            int(match.group(1)) == len(body),
            f"16K request {index} Content-Length does not match its body",
        )
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AssertionError(f"16K request {index} is invalid JSON: {exc}") from exc
        require(isinstance(document, dict), f"16K request {index} JSON is not an object")
        parsed.append(document)

    require(requests[0] == requests[1], "fresh 16K route did not replay the identical request")
    expected_tools = json.loads(tools)
    flattened_identity = bytes(value if value >= 32 else 32 for value in identity).decode("ascii")
    for index, document in enumerate(parsed, 1):
        input_items = document.get("input")
        require(
            document.get("model") == model.decode("ascii")
            and document.get("reasoning") == {"effort": "xhigh"}
            and document.get("tools") == expected_tools
            and isinstance(document.get("instructions"), str)
            and document["instructions"].startswith(flattened_identity),
            f"16K request {index} lost model/reasoning/tools/identity",
        )
        require(
            input_items
            == [
                {
                    "role": "user",
                    "content": "U:" + LIVE_PROMPT.decode("ascii"),
                }
            ],
            f"16K request {index} carried the wrong human input: {input_items!r}",
        )
        require(
            requests[index - 1].count(LIVE_PROMPT) == 1,
            f"16K request {index} did not carry the exact prompt once",
        )

    require(
        reads.count((identity_lba, STREAM["tls_rx_copy"])) == 2
        and reads.count((tools_lba, STREAM["tls_rx_copy"])) == 2,
        "16K request pair did not stream IDENTITY/TOOLS once per build",
    )
    return {
        "requests": len(requests),
        "records": [len(wire) for wire in requests],
        "disk_reads": len(reads),
        "identity_reads": reads.count((identity_lba, STREAM["tls_rx_copy"])),
        "tools_reads": reads.count((tools_lba, STREAM["tls_rx_copy"])),
    }


def test_cold_request_wire(core: bytes, listing: str) -> None:
    """Execute R's real cold builder and compare the complete HTTP request."""

    machine = stream_bounds_machine(core, listing, ready=False)
    # Match the shipped user configuration's geometry without embedding its
    # credential: the live 16 KiB cold turn currently carries an 11-byte
    # model name and a 167-byte bearer token.  A short synthetic token here
    # would miss a first-turn request-prefix overflow before any TLS I/O.
    model = b"m" * 11
    key = b"k" * 167
    require(
        len(model) < STREAM["seed_model_len"]
        and len(key) < STREAM["seed_key_len"],
        "cold-wire fixture exceeds the product config cache",
    )
    install_wire_model_cache(machine, model)
    machine.uc.mem_write(STREAM["chat_key_cache"], key + b"\0")

    entry = phase_runtime_label(core, listing, b"R", "agent_request_phase")
    require(not machine.execute(entry), "real cold request builder failed")
    length = int.from_bytes(
        machine.uc.mem_read(STREAM["tls_app_len"], 2), "little"
    )
    request = bytes(
        machine.uc.mem_read(
            STREAM["api_request_plain"] + STREAM["tls_record_header_len"],
            length,
        )
    )
    body = (
        b'{"model":"'
        + model
        + b'","reasoning":{"effort":"xhigh"},'
        + b'"input":"Greet.","store":false,"stream":true}'
    )
    expected = (
        b"POST /v1/responses HTTP/1.1\r\n"
        b"Host:api.openai.com\r\n"
        b"Authorization:Bearer "
        + key
        + b"\r\n"
        b"Content-Type:application/json\r\n"
        b"Content-Length:"
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )
    require(
        request == expected,
        "real cold request bytes drifted from the OpenAI JSON wire contract",
    )
    require(
        length <= STREAM["api_request_plain_len"],
        "cold OpenAI request exceeds the authenticated record arena",
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


def test_post_r_stream_bounds(core: bytes, listing: str) -> None:
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
        (
            "dialogue-count-high",
            lambda machine: machine.w16(STREAM["dialogue_cnt"] + 2, 1),
        ),
        (
            "dialogue-before-window",
            lambda machine: machine.w16(
                STREAM["dialogue_off"], STREAM["chat_context_start"] - 1
            ),
        ),
        (
            "dialogue-past-window",
            lambda machine: machine.w16(
                STREAM["dialogue_cnt"], STREAM["chat_context_len"] + 1
            ),
        ),
        (
            "dialogue-wrap",
            lambda machine: (
                machine.w16(STREAM["dialogue_off"], 0xFFFF),
                machine.w16(STREAM["dialogue_cnt"], 2),
            ),
        ),
        (
            "request-pointer",
            lambda machine: machine.w16(
                D.resolve_symbol(listing, "tls_app_plain_ptr"),
                STREAM["api_request_plain"],
            ),
        ),
        (
            "request-length-zero",
            lambda machine: machine.w16(STREAM["tls_app_len"], 0),
        ),
        (
            "request-length-oversize",
            lambda machine: machine.w16(
                STREAM["tls_app_len"], STREAM["api_request_plain_len"] + 1
            ),
        ),
    )
    x_entry = D.phase_geometry(core, b"X")[2]
    prepare = D.resolve_symbol(listing, "tls_prepare_3c501_receive")
    send = D.resolve_symbol(listing, "tls_send_application_data_current_seq")

    for label, corrupt in cases:
        machine = stream_bounds_machine(core, listing, load_x=True)
        corrupt(machine)

        def forbidden(_uc: Uc, name: str = label) -> None:
            raise AssertionError(f"{name} reached TLS send preparation")

        machine.on(prepare, "tls-prepare", forbidden)
        machine.on(send, "tls-send", forbidden)
        require(
            machine.execute(x_entry),
            f"{label} did not fail closed at X's final stream edge",
        )
        require(
            machine.calls.get("tls-prepare", 0) == 0
            and machine.calls.get("tls-send", 0) == 0,
            f"{label} reached TLS I/O",
        )

    cold_prefix_cases = (
        (
            "cold-request-pointer",
            lambda machine: machine.w16(
                D.resolve_symbol(listing, "tls_app_plain_ptr"),
                STREAM["api_request_plain"],
            ),
        ),
        (
            "cold-request-length-zero",
            lambda machine: machine.w16(STREAM["tls_app_len"], 0),
        ),
        (
            "cold-request-length-oversize",
            lambda machine: machine.w16(
                STREAM["tls_app_len"], STREAM["api_request_plain_len"] + 1
            ),
        ),
    )
    for label, corrupt in cold_prefix_cases:
        machine = stream_bounds_machine(
            core, listing, load_x=True, ready=False
        )
        corrupt(machine)

        def forbidden(_uc: Uc, name: str = label) -> None:
            raise AssertionError(f"{name} reached TLS send preparation")

        machine.on(prepare, "tls-prepare", forbidden)
        machine.on(send, "tls-send", forbidden)
        require(
            machine.execute(x_entry),
            f"{label} did not fail closed at X's cold stream edge",
        )
        require(
            machine.calls.get("tls-prepare", 0) == 0
            and machine.calls.get("tls-send", 0) == 0,
            f"{label} reached TLS I/O",
        )

    # The guard is deliberately an exact-floor boundary.  Existing larger/far
    # request geometry remains governed by its 32-bit stream implementation.
    machine = stream_bounds_machine(core, listing)
    machine.w16(
        STREAM["handoff_addr"] + STREAM["handoff_ram_top"], 0x8000
    )
    machine.w16(STREAM["prompt_tools_size"], 0xFFFF)
    machine.w16(STREAM["far_log_seg_var"], 0x2000)
    machine.w16(STREAM["far_flushed_len"] + 2, 1)
    machine.w16(STREAM["far_flushed_esc"] + 2, 1)
    machine.w16(STREAM["dialogue_cnt"] + 2, 0xFFFF)
    full_entry = phase_runtime_label(
        core, listing, b"R", ".validate_stream_bounds"
    )
    require(
        not machine.execute(full_entry),
        "16K stream cap leaked into a larger/far tier",
    )


def assert_prompt_replayed_once(harness: ProductHarness) -> None:
    require(
        harness.build_prompts == [PROMPT, PROMPT],
        "reconnect did not rebuild the same durable human prompt exactly once",
    )
    require(
        harness.sent_prompts == [PROMPT, PROMPT]
        and len(set(harness.sent_digests)) == 1,
        "reconnect did not resend the same rebuilt request exactly once",
    )


def test_live_reuse(core: bytes, listing: str) -> None:
    harness = ProductHarness(core, listing, ready=True)
    harness.install_route_stub()
    harness.install_exchange_outcomes([False])
    require(not harness.run(), "live-session reuse returned failure")
    require(
        harness.machine.calls.get("route", 0) == 0,
        "live-session reuse established a fresh route",
    )
    require(
        harness.build_prompts == [PROMPT]
        and harness.sent_prompts == [PROMPT],
        "live-session reuse did not build/send exactly once",
    )
    require(
        harness.machine.calls.get("enter", 0)
        == harness.machine.calls.get("restore", 0)
        == 1,
        f"live-session NIC lease drifted: {harness.machine.calls!r}",
    )
    require(
        harness.machine.u8(D.TLS_READY) == 1
        and harness.app_state()
        == b"\xA5" * len(harness.app_state()),
        "successful live-session reuse retired its TLS capability",
    )


def test_one_reconnect(core: bytes, listing: str) -> None:
    harness = ProductHarness(core, listing, ready=True)
    harness.install_route_stub()
    harness.install_exchange_outcomes([True, False])
    require(not harness.run(), "one-reconnect recovery returned failure")
    assert_prompt_replayed_once(harness)
    require(
        harness.machine.calls.get("route", 0) == 1,
        f"one failure did not establish exactly one route: {harness.events!r}",
    )
    require(
        harness.route_observations
        == [
            (
                0,
                b"\0" * (D.TLS_APP_STATE_END - D.TLS_APP_STATE_START),
                len(PROMPT),
            )
        ],
        "fresh route began before old application state was fully retired",
    )
    require(
        harness.events.index("nic-restore")
        < harness.events.index("route")
        < harness.events.index("build", 1),
        f"reconnect/rebuild ordering drifted: {harness.events!r}",
    )
    require(
        harness.machine.calls.get("enter", 0)
        == harness.machine.calls.get("restore", 0)
        == 2,
        f"reconnect NIC leases drifted: {harness.machine.calls!r}",
    )
    require(
        harness.machine.u8(D.TLS_READY) == 1
        and harness.app_state()
        == b"\x5A" * len(harness.app_state())
        and harness.machine.u8(D.CHAT_PROMPT_LEN + 1) == 0,
        "successful reconnect did not publish only the fresh capability",
    )


def test_second_failure_exhausts(core: bytes, listing: str) -> None:
    harness = ProductHarness(core, listing, ready=True)
    harness.install_route_stub()
    harness.install_exchange_outcomes([True, True])
    require(harness.run(), "second no-text failure did not exhaust")
    assert_prompt_replayed_once(harness)
    require(
        harness.machine.calls.get("route", 0) == 1,
        "exhaustion established more than one fresh route",
    )
    require(
        harness.machine.u8(D.TLS_READY) == 0
        and harness.app_state() == b"\0" * len(harness.app_state())
        and harness.machine.u8(D.CHAT_PROMPT_LEN + 1) == 0xFF,
        "exhaustion did not retire the fresh capability and close the budget",
    )


def test_nonreplayable_continuations(
    core: bytes, listing: str
) -> None:
    cases = (
        ("agent-live", True, 1, 0),
        ("tool-live", True, 0, 2),
        ("agent-dead", False, 1, 0),
        ("tool-dead", False, 0, 2),
    )
    for name, ready, agent_loop, tool_state in cases:
        harness = ProductHarness(
            core,
            listing,
            ready=ready,
            agent_loop=agent_loop,
            tool_state=tool_state,
        )
        harness.observe_real_route()
        if ready:
            harness.install_exchange_outcomes([True])
        require(
            harness.run(),
            f"{name} continuation unexpectedly recovered on a fresh route",
        )
        expected_sends = 1 if ready else 0
        require(
            len(harness.build_prompts) == expected_sends
            and len(harness.sent_prompts) == expected_sends,
            f"{name} continuation was rebuilt/replayed: {harness.events!r}",
        )
        require(
            harness.machine.calls.get("route-attempt", 0) == 0,
            f"{name} entered route establishment despite the denial gate",
        )
        require(
            harness.machine.calls.get("enter", 0)
            == harness.machine.calls.get("restore", 0)
            == expected_sends,
            f"{name} continuation NIC lease drifted",
        )


def test_route_failure_unwinds(core: bytes, listing: str) -> None:
    harness = ProductHarness(core, listing, ready=False)
    harness.observe_real_route()
    harness.install_route_load_failure()
    require(harness.run(), "two failed route loads did not exhaust")
    require(
        harness.machine.calls.get("route-attempt", 0) == 2
        and harness.machine.calls.get("route-load-failed", 0) == 2,
        f"route-load retry budget drifted: {harness.events!r}",
    )
    require(
        not harness.build_prompts
        and not harness.sent_prompts
        and harness.machine.calls.get("enter", 0) == 0
        and harness.machine.calls.get("restore", 0) == 0,
        f"failed route crossed into request/NIC work: {harness.events!r}",
    )
    require(
        harness.machine.u8(D.TLS_READY) == 0
        and harness.app_state() == b"\0" * len(harness.app_state())
        and harness.machine.u8(D.CHAT_PROMPT_LEN + 1) == 0xFF,
        "failed-route exhaustion did not leave a retired capability/budget",
    )


def test_text_seen_retirement(core: bytes, listing: str) -> None:
    for completed in (0, 2):
        harness = ProductHarness(core, listing, ready=True)
        harness.observe_real_route()
        harness.install_text_seen_transport_failure(completed)
        require(
            not harness.run(),
            f"state {completed} text-seen fallback discarded rendered-answer success",
        )
        require(
            harness.build_prompts == [PROMPT]
            and harness.sent_prompts == [PROMPT],
            f"state {completed} text-seen fallback rebuilt or replayed the request",
        )
        require(
            harness.machine.calls.get("route-attempt", 0) == 0,
            f"state {completed} text-seen fallback established a fresh route",
        )
        require(
            harness.machine.calls.get("receive", 0) == 1
            and harness.machine.calls.get("close", 0) == 1,
            f"state {completed} text-seen fallback path drifted: "
            f"{harness.machine.calls!r}",
        )
        require(
            harness.machine.u8(D.TLS_READY) == 0
            and harness.app_state() == b"\0" * len(harness.app_state())
            and harness.machine.u8(D.CHAT_PROMPT_LEN + 1) == 0xFF,
            f"state {completed} text-seen fallback did not retire the full "
            "application capability",
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
    test_cold_request_wire(core, listing)
    test_first_ready_stale_dialogue(core, listing)
    test_r_input_bounds(core, listing)
    test_post_r_stream_bounds(core, listing)
    test_live_reuse(core, listing)
    test_one_reconnect(core, listing)
    test_second_failure_exhausts(core, listing)
    test_nonreplayable_continuations(core, listing)
    test_route_failure_unwinds(core, listing)
    test_text_seen_retirement(core, listing)
    test_tcp_route_state_matrix(core, listing)
    test_response_http_terminal_drain(core, listing)
    test_response_output_event_filter(core, listing)
    ready = None
    reconnect_16k = None
    if args.image is not None:
        ready = test_512k_ready_turn_from_floppy(core, listing, args.image)
        reconnect_16k = test_16k_reconnect_request_from_floppy(
            core, listing, args.image
        )
    ready_text = ""
    if ready is not None:
        ready_text = (
            ", fat-ready=1"
            f", clusters={ready['identity_cluster']}/{ready['tools_cluster']}"
            f", records={ready['record_lengths']}"
            f", x-to-t={ready['response_sector']}+{ready['response_sectors']}"
        )
    if reconnect_16k is not None:
        ready_text += (
            ", exact-16k-replay=1"
            f", request-bytes={reconnect_16k['records']}"
            f", reads={reconnect_16k['disk_reads']}"
        )
    print(
        "TLS 1.3 product reconnect/replay: PASS "
        "(config-wire=9, cold-wire=1, r-input-bounds=11, x-stream-bounds=18, cold-prefix-bounds=3, "
        "first-ready-stale=1, "
        "reuse=1, replay=1, "
        "exhausted=1, continuations=4, route-failure=1, text-seen=1, "
        f"c-route-matrix=4, http-terminal=1, output-event-filter=1{ready_text})"
    )


if __name__ == "__main__":
    main()
