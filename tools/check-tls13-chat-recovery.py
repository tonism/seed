#!/usr/bin/env python3
"""Gate authenticated-DATA parsing, compaction, and visible failure cleanup.

Execute the emitted T, M and far-context mirror with fixture DATA. The exact
AEAD/H2/R/X/scheduler and native continuation composition is checked separately
by tls13-product/run_http2_gates.py against the final packaged image.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from unicorn import UC_HOOK_INTR, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_DS,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_ES,
    UC_X86_REG_IP,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/ibm_pc_5150"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


G = load_module("seed_chat_recovery", ROOT / "tools/check-tls13-product-reconnect.py")
A = load_module("seed_chat_record_oracle", ROOT / "tools/check-tls13-app.py")
S = G.STREAM


class Gate:
    def __init__(self, core: bytes, listing: str):
        self.core = core
        self.listing = listing
        self.rows: list[dict] = []

    def phase(self, machine, key: bytes) -> int:
        sector, count, destination = G.D.phase_geometry(self.core, key)
        if key == b"M":
            destination = S["low_scratch_start"]
        machine.uc.mem_write(
            destination, self.core[sector * 512 : (sector + count) * 512]
        )
        machine.uc.ctl_remove_cache(destination, destination + count * 512 - 1)
        return destination

    def parser_machine(self):
        from types import SimpleNamespace
        machine = G.D.ResidentMachine(self.core, self.listing)
        harness = SimpleNamespace(machine=machine)
        machine.w8(G.HANDOFF_STATUS, G.HANDOFF_STATUS_READY)
        machine.w8(G.SCREEN_COLS, 80)
        machine.w16(G.D.VIDEO_SEG, 0xb800)
        machine.w8(G.D.COMPACTING, 0)
        machine.w16(G.D.FAR_LOG_SEG, 0)
        for field in (
            "chat_turn_failed", "fc_match_state", "api_stream_state",
            "api_stream_completed", "api_stream_text_seen", "api_stream_done_match",
            "api_http_state", "api_stream_delta_match", "api_stream_fc_start_match",
        ):
            machine.w8(S[field], 0)
        machine.uc.mem_write(
            S["tool_fc_state"], bytes(S["reconnect_state_end"] - S["tool_fc_state"])
        )
        machine.uc.mem_write(S["fc_capture_buf"], bytes(S["fc_capture_max"]))
        machine.w16(S["esc_stop"], 0)
        machine.w8(S["cursor_row"], 4)
        machine.w8(S["cursor_col"], 0)
        machine.w8(S["menu_idle_attr"], 7)
        machine.leaf(G.D.resolve_symbol(self.listing, "wait_ticks"), "fast-type-tick")
        drawn = bytearray()

        def bios(emulator, interrupt, _data):
            assert interrupt == 0x10, (interrupt, emulator.reg_read(UC_X86_REG_AX))
            ax = emulator.reg_read(UC_X86_REG_AX)
            if ax >> 8 == 9:
                drawn.append(ax & 255)

        machine.uc.hook_add(UC_HOOK_INTR, bios)
        return harness, drawn

    def tool_boundaries(self) -> None:
        def event(kind, **fields):
            body = b"event: " + kind.encode() + b"\ndata: " + json.dumps(
                dict(type=kind, **fields), separators=(",", ":")
            ).encode() + b"\n\n"
            return body

        call = dict(type="function_call", call_id="call_probe", name="read_mem",
                    arguments='{"addr":"0x3e40","len":1}')
        parts = [
            event("response.output_item.added", item=dict(call, arguments="")),
            event("response.output_item.done", item=call),
            event("response.completed", response=dict(output=[call])),
        ]
        for cut in range(2, len(parts) + 1):
            harness, drawn = self.parser_machine()
            machine = harness.machine
            entry = self.phase(machine, b"T")
            states = []
            for index, data in enumerate(parts[:cut]):
                machine.uc.mem_write(S["tls_rx_copy"], data)
                machine.w16(G.D.resolve_symbol(self.listing, "tls_app_data_ptr"), S["tls_rx_copy"])
                machine.w16(S["tls_app_len"], len(data))
                machine.execute(entry)
                states.append([machine.u8(S[field]) for field in (
                    "tool_fc_state", "api_stream_completed", "api_stream_text_seen",
                )])
                assert machine.u8(S["api_stream_text_seen"]) == 0
                if index < len(parts) - 1:
                    assert machine.u8(S["api_stream_completed"]) != 3
            # Only the transport owner may promote response.completed to
            # final success after authenticated HTTP/2 END_STREAM.
            if cut == len(parts):
                assert machine.u8(S["api_stream_completed"]) == 1
                machine.w8(S["api_stream_completed"], 3)
            else:
                machine.w8(S["chat_turn_failed"], 255)
            machine.execute(self.phase(machine, b"M"))
            if cut == len(parts):
                assert machine.u8(S["tool_helper_pending"]) == ord("r")
                assert machine.u8(S["agent_loop_pending"]) == 1
                assert machine.u8(S["tool_fc_state"]) == 2 and not drawn
            else:
                self.assert_failed_turn(machine, drawn)
            self.rows.append(dict(case=f"tool-cut-{cut}", states=states,
                                  dispatch=cut == len(parts), message=drawn.decode()))

    def compaction_capture(self) -> None:
        # Receiving metadata is not a replacement summary. Only the first
        # output-text byte may replace the old dialogue and arm promotion.
        harness, drawn = self.parser_machine()
        machine = harness.machine
        entry = self.phase(machine, b"T")
        machine.w16(S["handoff_addr"] + S["handoff_ram_top"], S["basic_sidecar_stack_top_16k"])
        machine.w16(S["far_log_seg_var"], 0)
        original = b"N" * 48 + b"D" * 48
        machine.uc.mem_write(S["chat_context_start"], original)
        machine.w16(S["chat_context_used"], len(original))
        machine.w16(S["note_len"], 48)
        machine.w16(S["chat_context_len_var"], 96)
        machine.w16(S["chat_effective_cap"], 48)
        machine.w8(S["compacting_msg"], 1)
        machine.w8(S["chat_prompt_len_cache"], 0)
        machine.w8(S["api_stream_prompt_len"], 12)

        def feed(data):
            machine.uc.mem_write(S["tls_rx_copy"], data)
            machine.w16(G.D.resolve_symbol(self.listing, "tls_app_data_ptr"), S["tls_rx_copy"])
            machine.w16(S["tls_app_len"], len(data))
            machine.execute(entry)

        def event(kind, **fields):
            body = b"event: " + kind.encode() + b"\ndata: " + json.dumps(
                dict(type=kind, **fields), separators=(",", ":")
            ).encode() + b"\n\n"
            return body

        feed(event("response.reasoning_summary_text.delta", delta="thinking"))
        assert machine.u8(S["compacting_msg"]) == 1
        assert bytes(machine.uc.mem_read(S["chat_context_start"], 96)) == original
        assert machine.u8(S["api_stream_text_seen"]) == 0
        for text in ("forty", "two"):
            feed(event("response.output_text.delta", delta=text))
            assert machine.u8(S["compacting_msg"]) == 2
        assert bytes(machine.uc.mem_read(S["chat_context_start"], 8)) == b"fortytwo"
        assert G.u16(bytes(machine.uc.mem_read(S["chat_context_used"], 2)), 0) == 8
        assert G.u16(bytes(machine.uc.mem_read(S["note_len"], 2)), 0) == 48  # promoted by R
        assert machine.u8(S["api_stream_text_seen"]) == 1
        feed(event("response.completed", response=dict(output=[])))
        assert machine.u8(S["api_stream_completed"]) == 1
        assert not drawn, drawn
        self.rows.append(dict(case="compaction-text-capture", replacement_bytes=8,
                              old_note_bytes=48, rendered=False, response_completed=1))

    def far_compaction_mirror(self) -> None:
        # At the 286 floor, the scheduler mirrors the low staging window
        # before R. A no-text retry must retain the already-flushed dialogue.
        for state in (0, 1, 2):
            machine = G.D.ResidentMachine(self.core, self.listing)
            destination = self.phase(machine, b"G")
            machine.w16(S["handoff_addr"] + S["handoff_ram_top"], 0x8000)
            machine.w16(S["chat_context_len_var"], 224)
            machine.w16(S["far_log_seg_var"], 0x4000)
            machine.w16(S["ems_page_count"], 0)
            for field, value in (("far_ctx_base", 0x40000), ("far_window_cap", 0x10000),
                                 ("far_flushed_len", 64), ("far_flushed_esc", 66)):
                machine.uc.mem_write(S[field], value.to_bytes(4, "little"))
            machine.w8(S["compacting_msg"], state)
            data = b"fortytwo" if state == 2 else b" U:latest answer? A:fortytwo"
            machine.w16(S["chat_context_used"], len(data))
            machine.uc.mem_write(S["tools_cache"] - 224, data)
            prefix = b"P" * 64
            machine.uc.mem_write(0x40000, prefix + b"\xA7" * 64)
            assert not machine.execute(destination)
            offset = 0 if state == 2 else 64
            assert bytes(machine.uc.mem_read(0x40000 + offset, len(data))) == data
            if state != 2:
                assert bytes(machine.uc.mem_read(0x40000, 64)) == prefix
            for field, expected in (("far_flushed_len", offset),
                                    ("far_flushed_esc", 0 if state == 2 else 66)):
                assert int.from_bytes(machine.uc.mem_read(S[field], 4), "little") == expected
            self.rows.append(dict(case=f"far-compaction-mirror-{state}", preserved_prefix=offset))

    @staticmethod
    def assert_failed_turn(machine, drawn) -> None:
        assert bytes(drawn) == b"> response failed; try again", drawn
        assert machine.calls["fast-type-tick"] == len(drawn)
        assert all(machine.u8(S[field]) == 0 for field in (
            "chat_turn_failed", "tool_helper_pending", "agent_loop_pending",
        ))
        assert not any(machine.uc.mem_read(
            S["tool_fc_state"], S["reconnect_state_end"] - S["tool_fc_state"]
        ))
        assert not any(machine.uc.mem_read(S["fc_capture_buf"], S["fc_capture_max"]))

    def new_human_after_failure(self) -> None:
        for state in range(6):
            harness, drawn = self.parser_machine()
            machine = harness.machine
            machine.w8(S["tool_fc_state"], state)
            machine.w8(S["chat_turn_failed"], 255)
            machine.w8(G.D.TLS_READY, 0)
            machine.uc.mem_write(
                G.D.TLS_APP_STATE_START,
                bytes(G.D.TLS_APP_STATE_END - G.D.TLS_APP_STATE_START),
            )
            machine.execute(self.phase(machine, b"M"))
            self.assert_failed_turn(machine, drawn)
            self.rows.append(dict(case=f"failed-state-{state}", status_cleared=True))

    def graceful_stop(self) -> None:
        harness, drawn = self.parser_machine()
        machine = harness.machine
        machine.w8(S["tool_fc_state"], 5)
        machine.w8(S["chat_turn_failed"], 255)
        machine.w8(S["esc_stop"], 1)
        machine.execute(self.phase(machine, b"M"))
        assert bytes(drawn) == b"> stopped", drawn
        assert all(machine.u8(S[field]) == 0 for field in (
            "tool_fc_state", "chat_turn_failed", "tool_helper_pending", "agent_loop_pending",
        ))
        self.rows.append(dict(case="incomplete-tool-explicit-stop", message=drawn.decode()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, default=BUILD / "SEED.SYS")
    parser.add_argument("--listing", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    core = args.core.read_bytes()
    listing = (args.listing or args.core.with_suffix(".SYS.lst")).read_text()
    gate = Gate(core, listing)
    gate.tool_boundaries()
    gate.compaction_capture()
    gate.far_compaction_mirror()
    gate.new_human_after_failure()
    gate.graceful_stop()
    result = dict(core_sha256=hashlib.sha256(core).hexdigest(), cases=gate.rows,
                  passed=True, limits=__doc__)
    if args.json_out:
        args.json_out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"TLS 1.3 chat recovery: PASS ({len(gate.rows)} cases)")


if __name__ == "__main__":
    main()
