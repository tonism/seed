#!/usr/bin/env python3
"""Gate the fixed resident ABI and TLS 1.3 NIC-lease dispatcher.

The 8088 cold pack calls the resident nucleus by absolute near address.  This
gate therefore treats the first four sectors as a wire ABI: the pack-generation
prefix and final flat SEED.SYS must be byte-identical there except for the
header's total-sector word, and every published callback must retain its
established address.

The execution cases use the real resident scheduler with only phase/NIC leaves
stubbed.  The NIC enter shim deliberately poisons every general-purpose
register, including BX, so an accidental return to the old ``call bx`` pattern
cannot pass.  Success and failure cases must balance every acquired NIC lease.
"""

from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
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


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/ibm_pc_5150"
ORIGIN = 0x1000
RETURN_SENTINEL = 0xFF00
STACK_TOP = 0xFEF0
MEMORY_BYTES = 0x100000
HEADER_RESIDENT_SECTORS = 15
HEADER_TOTAL_SECTORS = 17

NIC_ENTER_STUB = 0x0500
NIC_RESTORE_STUB = 0x0520
X_PHASE_ENTRY = 0x0900
K14_ROOT_ENTRY = 0x3400
K14_ROOT_KEY = 0x0193
TIER286_ROOT_ENTRY = 0x0700
TIER286_ROOT_KEY = 0x0329
TIER286_ROOT_DESTINATION = 0x0700
TIER286_PARENT_TIME_KEY = 0x0224
TIER286_PARENT_TIME_PUBLICATION = 0x062E
PRODUCT_DNS_TX_STUB = 0x0540
PRODUCT_DNS_FRAME = 0x0700
PRODUCT_DNS_FRAME_BYTES = 74
PRODUCT_DNS_QNAME_OFFSET = 54
PRODUCT_DNS_QNAME = b"\x03api\x06openai\x03com\0"
PRODUCT_TCP_DEST_PORT = 0x06EB
PRODUCT_TCP_HTTPS_WORD = 0xBB01
PRODUCT_TCP_DEST_PORT_OFFSET = 36
TIER286_ROOT_LOAD = 0x3400
TIER286_ROOT_LIMIT = 0x3C00

# Fixed low-state ABI consumed by the resident scheduler and its product packs.
HANDOFF_FLAGS = 0x0608
HANDOFF_STATUS = 0x0619
BDA_MEMORY_KB = 0x0413
TLS_READY = 0x06C4
API_STREAM_TEXT_SEEN = 0x06FE
API_STREAM_COMPLETED = 0x0F37
VIDEO_SEG = 0x0F58
AGENT_LOOP_PENDING = 0x0F66
DPI_INPUT_LEN = 0x37C1
CHAT_PROMPT_LEN = 0x3C9C
COMPACTING = 0x3C9F
DPI_REACHED = 0x3CA2
FAR_LOG_SEG = 0x3CCC
TOOL_FC_STATE = 0x3CEB
TLS_APP_STATE_START = 0x3600
TLS_APP_STATE_END = 0x3668

EXPECTED_CALLBACKS = {
    "load_core_sectors_at": 0x10C4,
    "wait_ticks": 0x11E5,
    "prepare_internet_path": 0x11F6,
    "read_abs_sector": 0x1343,
    "ne_transmit_tcp_ack": 0x13A6,
    "tcp_send_payload": 0x13BF,
    "build_tcp_segment_frame": 0x13E2,
    "tcp_add_cx_to_seq": 0x14DA,
    "tcp_receive_payload": 0x14ED,
    "parse_tcp_payload": 0x1522,
    "nic_vt_enter": 0x15DB,
    "nic_vt_restore": 0x15DD,
    "nic_vt_transmit": 0x15DF,
    "nic_vt_receive": 0x15E1,
    "nic_vt_rx_fallback": 0x15E3,
}
PHASE_ENTRY_BYTES = 10

GP_REGISTERS = (
    UC_X86_REG_AX,
    UC_X86_REG_BX,
    UC_X86_REG_CX,
    UC_X86_REG_DX,
    UC_X86_REG_SI,
    UC_X86_REG_DI,
    UC_X86_REG_BP,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def resolve_symbol(listing: str, symbol: str) -> int:
    lines = listing.splitlines()
    marker = re.compile(
        rf"\b{re.escape(symbol)}(?::|\s+(?:d[wbqd]|res[wbqd])\b)"
    )
    emitted = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+")
    for index, line in enumerate(lines):
        if marker.search(line) is None:
            continue
        # Data labels emit on their declaration line; code labels resolve to
        # the first following instruction.  Stop well before an inactive
        # conditional's duplicate label can be mistaken for the active one.
        for candidate in lines[index : index + 40]:
            match = emitted.match(candidate)
            if match is not None:
                return ORIGIN + int(match.group(1), 16)
        raise AssertionError(f"{symbol} has no emitted address in listing")
    raise AssertionError(f"{symbol} is absent from listing")


def assert_callback_map(label: str, listing: str) -> None:
    actual = {
        symbol: resolve_symbol(listing, symbol)
        for symbol in EXPECTED_CALLBACKS
    }
    require(
        actual == EXPECTED_CALLBACKS,
        f"{label} resident callback drift: {actual!r}",
    )


def assert_resident_equivalence(base: bytes, final: bytes) -> int:
    require(base[3:11] == b"SEEDCORE", "pack-base header magic is invalid")
    require(final[3:11] == b"SEEDCORE", "final header magic is invalid")
    base_resident = struct.unpack_from("<H", base, HEADER_RESIDENT_SECTORS)[0]
    final_resident = struct.unpack_from("<H", final, HEADER_RESIDENT_SECTORS)[0]
    require(
        base_resident == final_resident == 4,
        "TLS 1.3 resident prefix is no longer exactly four sectors",
    )
    resident_bytes = base_resident * 512
    require(
        len(base) >= resident_bytes and len(final) >= resident_bytes,
        "core image is shorter than its resident prefix",
    )
    base_prefix = bytearray(base[:resident_bytes])
    final_prefix = bytearray(final[:resident_bytes])
    differences = [
        index
        for index, (left, right) in enumerate(zip(base_prefix, final_prefix))
        if left != right
    ]
    require(
        set(differences) <= {HEADER_TOTAL_SECTORS, HEADER_TOTAL_SECTORS + 1},
        f"pack-base/final resident bytes drift at {differences!r}",
    )
    base_prefix[HEADER_TOTAL_SECTORS : HEADER_TOTAL_SECTORS + 2] = b"\0\0"
    final_prefix[HEADER_TOTAL_SECTORS : HEADER_TOTAL_SECTORS + 2] = b"\0\0"
    require(
        base_prefix == final_prefix,
        "pack-base/final resident normalization is not byte-identical",
    )
    return resident_bytes


def phase_geometry(
    core: bytes, phase_id: bytes
) -> tuple[int, int, int]:
    table = struct.unpack_from("<H", core, 19)[0]
    count = struct.unpack_from("<H", core, 21)[0]
    for index in range(count):
        offset = table + index * PHASE_ENTRY_BYTES
        entry = core[offset : offset + PHASE_ENTRY_BYTES]
        if entry[:1] == phase_id:
            return struct.unpack_from("<3H", entry, 2)
    raise AssertionError(f"phase {phase_id!r} is absent")


def phase_runtime_symbol(
    core: bytes,
    listing: str,
    phase_id: bytes,
    symbol: str,
) -> int:
    sector, _sectors, destination = phase_geometry(core, phase_id)
    file_offset = resolve_symbol(listing, symbol) - ORIGIN
    return destination + file_offset - sector * 512


def set_carry(machine: Uc, carry: bool) -> None:
    flags = machine.reg_read(UC_X86_REG_EFLAGS)
    machine.reg_write(
        UC_X86_REG_EFLAGS,
        (flags | 1) if carry else (flags & ~1),
    )


def poison_gp(machine: Uc) -> None:
    for index, register in enumerate(GP_REGISTERS):
        machine.reg_write(register, 0xA100 + index * 0x111)


def near_return(machine: Uc, carry: bool) -> None:
    stack = machine.reg_read(UC_X86_REG_SP)
    return_ip = struct.unpack(
        "<H", machine.mem_read(stack, 2)
    )[0]
    machine.reg_write(UC_X86_REG_SP, (stack + 2) & 0xFFFF)
    set_carry(machine, carry)
    machine.reg_write(UC_X86_REG_IP, return_ip)


class ResidentMachine:
    def __init__(self, resident: bytes, listing: str) -> None:
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, MEMORY_BYTES)
        self.uc.mem_write(ORIGIN, resident)
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.symbols = {
            name: resolve_symbol(listing, name)
            for name in (
                "run_net_setup_phase",
                "run_core_phase",
                "load_core_sectors_at",
                "prepare_internet_path",
                "prepare_agent_endpoint_path",
                "tls13_product_establish_route",
                "agent_api_exchange",
            )
        }
        self.calls: dict[str, int] = {}
        self.handlers: dict[int, object] = {}
        self.uc.hook_add(UC_HOOK_CODE, self._dispatch)

    def _dispatch(
        self, machine: Uc, address: int, _size: int, _data: object
    ) -> None:
        handler = self.handlers.get(address)
        if handler is not None:
            handler(machine)

    def on(self, address: int, name: str, handler) -> None:
        def counted(machine: Uc) -> None:
            self.calls[name] = self.calls.get(name, 0) + 1
            handler(machine)

        self.handlers[address] = counted

    def leaf(
        self,
        address: int,
        name: str,
        *,
        carry: bool = False,
        poison: bool = False,
    ) -> None:
        def run(machine: Uc) -> None:
            if poison:
                poison_gp(machine)
            near_return(machine, carry)

        self.on(address, name, run)

    def w8(self, address: int, value: int) -> None:
        self.uc.mem_write(address, bytes((value & 0xFF,)))

    def w16(self, address: int, value: int) -> None:
        self.uc.mem_write(address, struct.pack("<H", value & 0xFFFF))

    def u8(self, address: int) -> int:
        return self.uc.mem_read(address, 1)[0]

    def execute(self, entry: int) -> bool:
        self.uc.reg_write(UC_X86_REG_SP, STACK_TOP - 2)
        self.w16(STACK_TOP - 2, RETURN_SENTINEL)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0002)
        returned = False

        def stop(machine: Uc) -> None:
            nonlocal returned
            returned = True
            machine.emu_stop()

        self.handlers[RETURN_SENTINEL] = stop
        self.uc.reg_write(UC_X86_REG_IP, entry)
        self.uc.emu_start(entry, RETURN_SENTINEL + 1, count=100_000)
        require(returned, f"resident entry {entry:#06x} did not return")
        require(
            self.uc.reg_read(UC_X86_REG_SP) == STACK_TOP,
            f"resident entry {entry:#06x} unbalanced SP",
        )
        require(
            self.uc.reg_read(UC_X86_REG_DS) == 0
            and self.uc.reg_read(UC_X86_REG_SS) == 0,
            f"resident entry {entry:#06x} clobbered DS/SS",
        )
        require(
            not (self.uc.reg_read(UC_X86_REG_EFLAGS) & 0x0400),
            f"resident entry {entry:#06x} returned with DF set",
        )
        return bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)


def install_nic(
    machine: ResidentMachine, *, restore_carry: bool = True
) -> None:
    machine.w16(EXPECTED_CALLBACKS["nic_vt_enter"], NIC_ENTER_STUB)
    machine.w16(EXPECTED_CALLBACKS["nic_vt_restore"], NIC_RESTORE_STUB)
    machine.leaf(
        NIC_ENTER_STUB, "enter", carry=False, poison=True
    )
    machine.leaf(
        NIC_RESTORE_STUB,
        "restore",
        carry=restore_carry,
        poison=True,
    )


def test_internet_lease(
    resident: bytes, listing: str, *, dhcp_fails: bool
) -> None:
    machine = ResidentMachine(resident, listing)
    install_nic(machine)
    machine.leaf(
        machine.symbols["run_net_setup_phase"],
        "dhcp",
        carry=dhcp_fails,
        poison=True,
    )
    carry = machine.execute(machine.symbols["prepare_internet_path"])
    require(carry is dhcp_fails, "DHCP carry did not survive NIC restore")
    require(
        (machine.calls.get("enter", 0), machine.calls.get("restore", 0))
        == (1, 1),
        f"DHCP NIC lease imbalance: {machine.calls!r}",
    )


def test_product_dns_boundary(core: bytes, listing: str) -> None:
    sector, sectors, destination = phase_geometry(core, b"C")
    require(
        (sectors, destination) == (3, 0x0900),
        "TCP-connect phase left its fixed three-sector window",
    )
    phase = core[sector * 512 : (sector + sectors) * 512]
    require(
        len(phase) == sectors * 512,
        "TCP-connect phase is truncated",
    )
    entry = phase_runtime_symbol(
        core,
        listing,
        b"C",
        "ne_transmit_dns_query",
    )
    qname = phase_runtime_symbol(
        core,
        listing,
        b"C",
        "tcp_product_dns_qname",
    )
    tcp_entry = phase_runtime_symbol(
        core,
        listing,
        b"C",
        "tcp_connect_phase",
    )
    syn_entry = phase_runtime_symbol(
        core,
        listing,
        b"C",
        "ne_send_tcp_syn_frame",
    )

    machine = ResidentMachine(core[:2048], listing)
    machine.uc.mem_write(destination, phase)
    machine.uc.mem_write(
        TIER286_ROOT_LOAD,
        b"\xA5" * (TIER286_ROOT_LIMIT - TIER286_ROOT_LOAD),
    )
    machine.w16(
        EXPECTED_CALLBACKS["nic_vt_transmit"],
        PRODUCT_DNS_TX_STUB,
    )
    machine.w16(PRODUCT_TCP_DEST_PORT, 0)
    machine.uc.reg_write(UC_X86_REG_IP, tcp_entry)
    machine.uc.emu_start(tcp_entry, tcp_entry + 8, count=1)
    require(
        int.from_bytes(
            machine.uc.mem_read(PRODUCT_TCP_DEST_PORT, 2),
            "little",
        )
        == PRODUCT_TCP_HTTPS_WORD,
        "product TCP-connect entry did not restore the HTTPS destination port",
    )
    transmitted: list[tuple[int, int]] = []

    def transmit(uc: Uc) -> None:
        transmitted.append(
            (
                uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
                uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
            )
        )
        near_return(uc, False)

    machine.on(PRODUCT_DNS_TX_STUB, "dns-transmit", transmit)
    require(
        not machine.execute(entry),
        "fixed product DNS query returned carry",
    )
    require(
        transmitted == [(PRODUCT_DNS_FRAME, PRODUCT_DNS_FRAME_BYTES)],
        f"product DNS transmit pointer/length drifted: {transmitted!r}",
    )
    frame = bytes(
        machine.uc.mem_read(PRODUCT_DNS_FRAME, PRODUCT_DNS_FRAME_BYTES)
    )
    require(
        frame[PRODUCT_DNS_QNAME_OFFSET : PRODUCT_DNS_QNAME_OFFSET + 16]
        == PRODUCT_DNS_QNAME,
        "product DNS query read the root-overwritten legacy QNAME",
    )
    require(
        frame[16:18] == b"\0\x3c"
        and frame[38:40] == b"\0\x28",
        "product DNS IPv4/UDP lengths are not bound to the fixed QNAME",
    )
    require(
        bytes(machine.uc.mem_read(qname, 16)) == PRODUCT_DNS_QNAME,
        "phase-local OpenAI QNAME drifted",
    )
    require(
        not machine.execute(syn_entry),
        "fixed product TCP SYN returned carry",
    )
    syn = bytes(
        machine.uc.mem_read(
            PRODUCT_DNS_FRAME,
            PRODUCT_TCP_DEST_PORT_OFFSET + 2,
        )
    )
    require(
        syn[
            PRODUCT_TCP_DEST_PORT_OFFSET :
            PRODUCT_TCP_DEST_PORT_OFFSET + 2
        ]
        == b"\x01\xbb",
        "product TCP SYN did not carry destination port 443",
    )


def test_application_lease(
    resident: bytes, listing: str, *, exchange_fails: bool
) -> None:
    machine = ResidentMachine(resident, listing)
    install_nic(machine)
    machine.w8(TLS_READY, 1)
    machine.w8(AGENT_LOOP_PENDING, 0)
    machine.w8(COMPACTING, 0)
    machine.w16(FAR_LOG_SEG, 0)
    machine.w8(DPI_INPUT_LEN, 7)
    machine.uc.reg_write(UC_X86_REG_ES, 0x4321)
    machine.uc.mem_write(
        TLS_APP_STATE_START,
        b"\xA5" * (TLS_APP_STATE_END - TLS_APP_STATE_START),
    )
    machine.leaf(
        machine.symbols["run_core_phase"], "phase", carry=False
    )
    machine.leaf(
        machine.symbols["load_core_sectors_at"],
        "load",
        carry=False,
        poison=True,
    )
    machine.leaf(X_PHASE_ENTRY, "x", carry=False)
    machine.leaf(
        machine.symbols["agent_api_exchange"],
        "exchange",
        carry=exchange_fails,
        poison=True,
    )
    carry = machine.execute(
        machine.symbols["prepare_agent_endpoint_path"]
    )
    require(
        carry is exchange_fails,
        "application exchange carry did not survive NIC restore",
    )
    require(
        (machine.calls.get("enter", 0), machine.calls.get("restore", 0))
        == (1, 1),
        f"application NIC lease imbalance: {machine.calls!r}",
    )
    require(
        machine.calls.get("x", 0) == 1
        and machine.calls.get("exchange", 0) == 1,
        f"poisoned-BX direct X/application dispatch failed: {machine.calls!r}",
    )
    require(
        machine.u8(TLS_READY) == (0 if exchange_fails else 1),
        "application failure did not burn TLS-ready state",
    )
    require(
        machine.uc.reg_read(UC_X86_REG_ES) == 0x4321,
        "application state retirement clobbered caller ES",
    )
    app_state = bytes(
        machine.uc.mem_read(
            TLS_APP_STATE_START,
            TLS_APP_STATE_END - TLS_APP_STATE_START,
        )
    )
    require(
        app_state
        == (
            b"\0" * len(app_state)
            if exchange_fails
            else b"\xA5" * len(app_state)
        ),
        "application failure did not retire the full key/IV/sequence band",
    )


def test_text_seen_retirement(core: bytes, listing: str) -> None:
    for completed in (0, 2):
        machine = ResidentMachine(core, listing)
        machine.w8(TLS_READY, 1)
        machine.w8(API_STREAM_TEXT_SEEN, 1)
        machine.w8(API_STREAM_COMPLETED, completed)
        machine.w8(resolve_symbol(listing, "ka_sent_count"), 0)
        machine.uc.reg_write(UC_X86_REG_ES, 0x4321)
        machine.uc.mem_write(
            TLS_APP_STATE_START,
            b"\xA5" * (TLS_APP_STATE_END - TLS_APP_STATE_START),
        )
        machine.leaf(
            machine.symbols["load_core_sectors_at"],
            "load",
            carry=False,
        )
        machine.leaf(
            resolve_symbol(listing, "tls_receive_application_data"),
            "receive",
            carry=True,
        )
        machine.leaf(
            resolve_symbol(listing, "ne_transmit_tcp_flags"),
            "close",
            carry=False,
        )

        carry = machine.execute(machine.symbols["agent_api_exchange"])
        require(
            not carry,
            f"state {completed} text-seen fallback discarded rendered-answer success",
        )
        require(
            machine.calls.get("load", 0) == 1
            and machine.calls.get("receive", 0) == 1
            and machine.calls.get("close", 0) == 1,
            f"state {completed} text-seen fallback dispatch drifted: "
            f"{machine.calls!r}",
        )
        require(
            machine.u8(TLS_READY) == 0,
            f"state {completed} text-seen fallback left TLS ready",
        )
        require(
            bytes(
                machine.uc.mem_read(
                    TLS_APP_STATE_START,
                    TLS_APP_STATE_END - TLS_APP_STATE_START,
                )
            )
            == b"\0" * (TLS_APP_STATE_END - TLS_APP_STATE_START),
            f"state {completed} text-seen fallback did not retire the full "
            "key/IV/sequence band",
        )
        require(
            machine.uc.reg_read(UC_X86_REG_ES) == 0x4321,
            f"state {completed} text-seen retirement clobbered caller ES",
        )


def test_k14_route(
    resident: bytes,
    listing: str,
    *,
    root_load_fails: bool = False,
    root_fails: bool = False,
) -> None:
    machine = ResidentMachine(resident, listing)
    install_nic(machine)
    machine.w16(HANDOFF_FLAGS, 0)
    machine.w8(HANDOFF_STATUS, 1)
    machine.w8(TOOL_FC_STATE, 0)
    machine.w8(AGENT_LOOP_PENDING, 0)
    machine.w16(VIDEO_SEG, 0xB800)
    machine.w8(CHAT_PROMPT_LEN, 0)
    machine.uc.mem_write(
        TLS_APP_STATE_START,
        b"\xA5" * (TLS_APP_STATE_END - TLS_APP_STATE_START),
    )
    root_modes: list[int] = []

    def load_phase(uc: Uc) -> None:
        key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        poison_gp(uc)
        near_return(uc, root_load_fails and key == K14_ROOT_KEY)

    def root(uc: Uc) -> None:
        root_modes.append(uc.reg_read(UC_X86_REG_AX) & 0xFF)
        # The RAM-only root owns the NIC-enter half of the lease.  Its final
        # success/abort capsule returns carry only; the resident caller hides
        # READY until after the matching NIC restore has completed.
        machine.calls["enter"] = machine.calls.get("enter", 0) + 1
        poison_gp(uc)
        near_return(uc, root_fails)

    machine.on(
        machine.symbols["load_core_sectors_at"], "load", load_phase
    )
    machine.on(K14_ROOT_ENTRY, "root", root)
    expected_failure = root_load_fails or root_fails
    # A successful route is independently callable.  Every failure is
    # exercised through the real endpoint scheduler so its one bounded retry,
    # application-state retirement, and call-frame unwind are part of the
    # gate—not accidentally attributed to the route helper itself.
    carry = machine.execute(
        machine.symbols[
            "prepare_agent_endpoint_path"
            if expected_failure
            else "tls13_product_establish_route"
        ]
    )
    require(carry is expected_failure, "K14 route carry mismatch")
    attempts = 2 if expected_failure else 1
    expected_lease = 0 if root_load_fails else attempts
    require(
        (
            machine.calls.get("root", 0),
            machine.calls.get("enter", 0),
            machine.calls.get("restore", 0),
        )
        == (expected_lease, expected_lease, expected_lease),
        f"K14 NIC lease imbalance: {machine.calls!r}",
    )
    require(
        machine.u8(TLS_READY) == (0 if expected_failure else 1),
        "K14 route published the wrong ready state",
    )
    app_state = bytes(
        machine.uc.mem_read(
            TLS_APP_STATE_START,
            TLS_APP_STATE_END - TLS_APP_STATE_START,
        )
    )
    require(
        app_state
        == (
            b"\0" * len(app_state)
            if expected_failure
            else b"\xA5" * len(app_state)
        ),
        "K14 failure did not retire the full key/IV/sequence band",
    )
    require(
        root_modes == [0] * expected_lease,
        f"K14 root received the wrong fresh-route mode: {root_modes!r}",
    )
    require(
        machine.u8(DPI_REACHED) == 0,
        "cold K14 route restored an invalid DPI gate",
    )


def test_286_route(
    resident: bytes,
    listing: str,
    *,
    memory_kb: int = 512,
    load_fails: bool = False,
    controller_fails: bool = False,
    reconnect: bool = False,
) -> None:
    machine = ResidentMachine(resident, listing)
    machine.w16(HANDOFF_FLAGS, 0x0010)
    machine.w8(HANDOFF_STATUS, 3 if reconnect else 1)
    machine.w16(BDA_MEMORY_KB, memory_kb)
    machine.w8(TOOL_FC_STATE, 0)
    machine.w8(AGENT_LOOP_PENDING, 0)
    machine.w8(TLS_READY, 0)
    machine.uc.mem_write(
        TLS_APP_STATE_START,
        b"\xA5" * (TLS_APP_STATE_END - TLS_APP_STATE_START),
    )
    loads: list[tuple[int, int]] = []
    time_calls: list[int] = []
    modes: list[int] = []
    leases = {"enter": 0, "restore": 0}

    def parent_time(uc: Uc) -> None:
        key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        time_calls.append(key)
        failed = memory_kb < 512
        if not failed:
            uc.mem_write(
                TIER286_PARENT_TIME_PUBLICATION,
                b"\x20\x26\x07\x30\x14\x25\x36\x5A\xA5",
            )
            uc.reg_write(
                UC_X86_REG_DI, TIER286_PARENT_TIME_PUBLICATION
            )
        near_return(uc, failed)

    def load_phase(uc: Uc) -> None:
        loads.append(
            (
                uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
                uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
            )
        )
        # The real resident loader preserves DI on both its floppy and cache
        # paths.  Poison every other GP register so BX-independence remains
        # covered while preserving the new trusted-time pointer contract.
        publication = uc.reg_read(UC_X86_REG_DI)
        poison_gp(uc)
        uc.reg_write(UC_X86_REG_DI, publication)
        near_return(uc, load_fails)

    def controller(uc: Uc) -> None:
        mode = uc.reg_read(UC_X86_REG_AX) & 0xFF
        modes.append(mode)
        rtc_pointer = uc.reg_read(UC_X86_REG_DI)
        require(
            rtc_pointer == TIER286_PARENT_TIME_PUBLICATION,
            "286 bootstrap did not receive the parent RTC pointer: "
            f"got {rtc_pointer:04x}",
        )
        leases["enter"] += 1
        leases["restore"] += 1
        if controller_fails:
            uc.mem_write(
                TLS_APP_STATE_START,
                b"\0" * (TLS_APP_STATE_END - TLS_APP_STATE_START),
            )
            uc.mem_write(TLS_READY, b"\0")
        else:
            uc.mem_write(
                TLS_APP_STATE_START,
                b"\x5A" * (TLS_APP_STATE_END - TLS_APP_STATE_START),
            )
            uc.mem_write(TLS_READY, b"\1")
        uc.mem_write(DPI_REACHED, bytes((mode,)))
        poison_gp(uc)
        near_return(uc, controller_fails)

    machine.on(
        machine.symbols["run_net_setup_phase"], "parent_time", parent_time
    )
    machine.on(
        machine.symbols["load_core_sectors_at"], "load", load_phase
    )
    machine.on(TIER286_ROOT_ENTRY, "controller", controller)
    gated = memory_kb < 512
    expected_failure = gated or load_fails or controller_fails
    carry = machine.execute(
        machine.symbols[
            "prepare_agent_endpoint_path"
            if expected_failure
            else "tls13_product_establish_route"
        ]
    )
    attempts = 2 if expected_failure else 1
    require(carry is expected_failure, "286 route carry mismatch")
    require(
        time_calls == [TIER286_PARENT_TIME_KEY] * attempts,
        f"286 parent-time dispatch drifted: {time_calls!r}",
    )
    require(
        loads
        == (
            []
            if gated
            else [(TIER286_ROOT_KEY, TIER286_ROOT_DESTINATION)] * attempts
        ),
        f"286 fixed bootstrap load/no-downgrade gate drifted: {loads!r}",
    )
    controller_called = not gated and not load_fails
    require(
        modes
        == (
            [1 if reconnect else 0] * attempts
            if controller_called
            else []
        ),
        f"286 endpoint-mode tail handoff drifted: {modes!r}",
    )
    expected_leases = attempts if controller_called else 0
    require(
        leases == {"enter": expected_leases, "restore": expected_leases},
        f"286 controller NIC lease imbalance: {leases!r}",
    )
    require(
        machine.u8(TLS_READY) == (0 if expected_failure else 1),
        "286 route published the wrong ready state",
    )
    app_state = bytes(
        machine.uc.mem_read(
            TLS_APP_STATE_START,
            TLS_APP_STATE_END - TLS_APP_STATE_START,
        )
    )
    require(
        app_state
        == (
            b"\0" * len(app_state)
            if expected_failure
            else b"\x5A" * len(app_state)
        ),
        "286 failure did not retire the full key/IV/sequence band",
    )
    require(
        machine.u8(DPI_REACHED) == (1 if reconnect else 0),
        "286 route did not restore the endpoint DPI gate",
    )


def test_286_far_ceiling(core: bytes, listing: str) -> None:
    sector, sectors, destination = phase_geometry(core, b"H")
    require(destination == 0x0700, "hardware phase load address drifted")
    phase = core[sector * 512 : (sector + sectors) * 512]
    helper_file = (
        resolve_symbol(listing, "hardware_setup_tls13_far_ceiling")
        - ORIGIN
    )
    helper = destination + helper_file - sector * 512
    cases = (
        ("8088-16K", False, 16, 0x04000),
        ("8088-32K", False, 32, 0x08000),
        ("8088-640K", False, 640, 0xA0000),
        ("286-below-floor", True, 511, 0x7FC00),
        ("286-512K", True, 512, 0x6C5F0),
        ("286-640K", True, 640, 0x8C5F0),
    )
    for name, cpu286, memory_kb, expected in cases:
        machine = ResidentMachine(core[:2048], listing)
        machine.uc.mem_write(destination, phase)
        machine.w16(HANDOFF_FLAGS, 0x0010 if cpu286 else 0)
        machine.w16(BDA_MEMORY_KB, memory_kb)
        true_top = memory_kb * 1024
        machine.uc.reg_write(UC_X86_REG_AX, true_top & 0xFFFF)
        machine.uc.reg_write(UC_X86_REG_DX, true_top >> 16)
        require(
            not machine.execute(helper),
            f"{name} ceiling helper unexpectedly returned carry",
        )
        actual = (
            (machine.uc.reg_read(UC_X86_REG_DX) & 0xFFFF) << 16
        ) | (machine.uc.reg_read(UC_X86_REG_AX) & 0xFFFF)
        require(
            actual == expected,
            f"{name} usable ceiling drifted: {actual:#x} != {expected:#x}",
        )
        if name in ("286-512K", "286-640K"):
            half = (expected - 0x10000) // 2
            context_base = expected - half
            expected_half = 0x2E2F8 if memory_kb == 512 else 0x3E2F8
            require(
                half == expected_half
                and context_base
                == (0x3E2F8 if memory_kb == 512 else 0x4E2F8),
                f"{name} 50/50 arena/context split drifted",
            )


def assert_source_contract() -> None:
    source = (
        ROOT / "targets/ibm_pc_5150/boot/core/net_phase.inc"
    ).read_text(encoding="utf-8")
    core_source = (
        ROOT / "targets/ibm_pc_5150/boot/core.asm"
    ).read_text(encoding="utf-8")
    time_source = (
        ROOT
        / "targets/ibm_pc_5150/boot/phases/tls13_286_parent_time.inc"
    ).read_text(encoding="utf-8")
    tcp_source = (
        ROOT / "targets/ibm_pc_5150/boot/phases/tcp_connect.inc"
    ).read_text(encoding="utf-8")
    product = source[: source.index("tls13_product_net_block_end:")]
    require(
        "call net_setup_phase_start" in product
        and "call bx" not in product,
        "application X dispatch is not fixed-address/BX-independent",
    )
    require(
        "call TLS13_K14_PRODUCT_ROOT_ENTRY" in product
        and "call [nic_vt_restore]" in product
        and "TLS13_K14_PRODUCT_STATE_GUARD" not in product,
        "K14 RAM-only root/lease dispatch drifted",
    )
    require(
        "TLS13_286_PRODUCT_ROOT_ENTRY" in product,
        "286 product controller hook is absent",
    )
    require(
        "run_net_phase core_ntp_setup_phase_start" in product
        and "jmp TLS13_286_PRODUCT_ROOT_ENTRY" in product
        and "%ifdef TLS13_286_PRODUCT_ROOT_PHASE_KEY" not in product,
        "286 parent-time-gated unconditional tail dispatch drifted",
    )
    require(
        "mov di, tls13_286_parent_rtc_publication" in time_source
        and "int 0x1a" in time_source
        and "call .preserve_loop_cache" in time_source
        and "handoff_flag_rtc_utc_confirmed" not in time_source
        and "call fast_type" not in time_source
        and "int 0x16" not in time_source,
        "286 silent platform-RTC/RAM-shadow publication contract is absent",
    )
    require(
        '%include "phases/tls13_286_parent_time.inc"' in core_source,
        "product N slot does not replace unauthenticated NTP",
    )
    require(
        '%include "tls13-286-product-abi.inc"' in core_source
        and 'incbin "tls13-286-bootstrap.bin"' in core_source,
        "286 fixed bootstrap/ABI is not linked into the product L slot",
    )
    dns_boundary = tcp_source.split("ne_transmit_dns_query:", 1)[1].split(
        "parse_tcp_synack:", 1
    )[0]
    require(
        "tcp_product_dns_qname" in dns_boundary
        and "[dns_tx_len]" not in dns_boundary
        and "[dns_qname_len]" not in dns_boundary
        and "mov si, dns_qname" not in dns_boundary,
        "product DNS still depends on 286 root-overwritten scratch",
    )
    tcp_entry = tcp_source.split("tcp_connect_phase:", 1)[1].split(
        ".nic_clean:", 1
    )[0]
    require(
        "mov word [tcp_dest_port_word], tcp_port_https_word" in tcp_entry,
        "product TCP-connect phase does not restore its HTTPS destination port",
    )
    p256_tail = core_source.index("core_p256_module_start:")
    product_guard = core_source.rfind(
        "%ifndef TLS13_PRODUCT_TLS13", 0, p256_tail
    )
    require(
        product_guard >= 0,
        "product core can still include the retired TLS 1.2 P-256 tail",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-core",
        type=Path,
        default=BUILD / "tls13-pack-base/SEED.SYS",
    )
    parser.add_argument(
        "--base-listing",
        type=Path,
        default=BUILD / "tls13-pack-base/SEED.SYS.lst",
    )
    parser.add_argument(
        "--final-core",
        type=Path,
        default=BUILD / "SEED.SYS",
    )
    parser.add_argument(
        "--final-listing",
        type=Path,
        default=BUILD / "SEED.SYS.lst",
    )
    parser.add_argument(
        "--base-only",
        action="store_true",
        help="run ABI/dispatch execution gates before a final pack is built",
    )
    args = parser.parse_args()

    base = args.base_core.read_bytes()
    base_listing = args.base_listing.read_text(encoding="utf-8")
    assert_callback_map("pack-base", base_listing)
    resident_bytes = struct.unpack_from(
        "<H", base, HEADER_RESIDENT_SECTORS
    )[0] * 512
    require(resident_bytes == 2048, "pack-base resident extent drifted")
    resident = base[:resident_bytes]
    require(
        phase_geometry(base, b"L") == (41, 3, 0x0700),
        "286 bootstrap no longer occupies fixed sectors 41..43 at 0x0700",
    )
    require(
        phase_geometry(base, b"N") == (36, 2, 0x0900),
        "286 trusted-time phase moved from the retired two-sector N slot",
    )

    if not args.base_only:
        final = args.final_core.read_bytes()
        final_listing = args.final_listing.read_text(encoding="utf-8")
        assert_callback_map("final", final_listing)
        assert_resident_equivalence(base, final)

    assert_source_contract()
    test_internet_lease(resident, base_listing, dhcp_fails=False)
    test_internet_lease(resident, base_listing, dhcp_fails=True)
    test_product_dns_boundary(base, base_listing)
    test_application_lease(resident, base_listing, exchange_fails=False)
    # Failure is no longer a one-shot lease: the product scheduler owns one
    # bounded fresh-route replay.  Its complete state machine is gated by
    # check-tls13-product-reconnect.py.
    test_text_seen_retirement(base, base_listing)
    test_k14_route(resident, base_listing)
    test_k14_route(resident, base_listing, root_load_fails=True)
    test_k14_route(resident, base_listing, root_fails=True)
    test_286_route(resident, base_listing)
    test_286_route(resident, base_listing, reconnect=True)
    test_286_route(resident, base_listing, memory_kb=511)
    test_286_route(resident, base_listing, load_fails=True)
    test_286_route(resident, base_listing, controller_fails=True)
    test_286_far_ceiling(base, base_listing)
    print(
        "TLS 1.3 resident dispatch: PASS "
        f"(resident={resident_bytes}, callbacks={len(EXPECTED_CALLBACKS)}, "
        f"base_final={'skipped' if args.base_only else 'identical'}, "
        "286-routes=checked, dns=root-independent)"
    )


if __name__ == "__main__":
    main()
