#!/usr/bin/env python3
"""Build and hostile-test the 16 KiB TLS 1.3 post-auth application PoC.

The checker executes the actual cpu-8086 request/response controllers and K14
ChaCha20-Poly1305 primitives under Unicorn.  The credential callback is a fixed
resident test double for the hardened authenticated-commit publisher: no test
credential is compiled into an image or emitted in the result report.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from capstone.x86_const import X86_OP_IMM
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_MEM_WRITE,
    UC_MODE_16,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_REG_AX,
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
SPIKE_SOURCE = HERE.parent / "tls13-spike" / "tls13_spike.py"
SYM_SOURCE = HERE / "tls13_sym_overlay.asm"
REQUEST_SOURCE = HERE / "post_auth_request_controller.asm"
REQUEST_ADAPTER_SOURCE = HERE / "post_auth_sym_adapter.asm"
RESPONSE_SOURCE = HERE / "post_auth_response_controller.asm"
RESPONSE_LITERALS_SOURCE = HERE / "post_auth_response_literals.asm"

RAM_BYTES = 0x10000
RETURN_SENTINEL = 0x04F0
SYM_RESTORE_CALLBACK = 0x0510
UNLOCK_CALLBACK = 0x0520
SEND_CALLBACK = 0x0500
RX_BUFFER = 0x0700
CONTROLLER_BASE = 0x0900
CONTROLLER_LIMIT = 0x0D00
SYM_BASE = 0x1800
SYM_LIMIT = 0x3400
ADAPTER_BASE = 0x3400
ADAPTER_LIMIT = 0x3510
RESIDENT_LOAD_PHASE = 0x10C4
RESIDENT_TCP_ACK = 0x13A6
PLACEHOLDER_SUPERVISOR_RECEIVE = 0x3000
PERSISTENT_SECURE_FAIL = 0x35D9
SYM_RECORD_ACTIVE = 0x3520
CLIENT_APP_KEY = 0x3838
CLIENT_APP_IV = 0x3858
SERVER_APP_KEY = 0x3864
SERVER_APP_IV = 0x3884
CLIENT_APP_SEQ = 0x38E0
SERVER_APP_SEQ = 0x38E8
IO_BASE = 0x39A0
ARENA_FLOOR = 0x3E40
STACK_BOTTOM = 0x3F00
STACK_TOP = 0x3FF0

PUBLICATION_START = 0x0D00
PUBLICATION_STATUS = PUBLICATION_START
PUBLICATION_GENERATION = PUBLICATION_START + 10
PUBLICATION_ROUTE = PUBLICATION_START + 12
PUBLICATION_ROUTE_INVERSE = PUBLICATION_START + 13
PUBLICATION_KEY_LEN = PUBLICATION_START + 14
PUBLICATION_KEY = PUBLICATION_START + 16
PUBLICATION_KEY_MAX = 192
PUBLICATION_KEY_END = PUBLICATION_KEY + PUBLICATION_KEY_MAX + 1
PUBLICATION_MODEL_LEN = PUBLICATION_KEY_END
PUBLICATION_MODEL = PUBLICATION_MODEL_LEN + 2
PUBLICATION_MODEL_MAX = 64
PUBLICATION_MODEL_END = PUBLICATION_MODEL + PUBLICATION_MODEL_MAX + 1
PUBLICATION_CHECKSUM_A = PUBLICATION_MODEL_END
PUBLICATION_CHECKSUM_B = PUBLICATION_CHECKSUM_A + 2
PUBLICATION_END = PUBLICATION_CHECKSUM_B + 2
PUBLICATION_CHECK_START = PUBLICATION_GENERATION
PUBLICATION_CHECK_LEN = PUBLICATION_CHECKSUM_A - PUBLICATION_CHECK_START
FRAGMENT_BUFFER = 0x0E20
FRAGMENT_END = 0x0F00

REQUEST_STATUS = 0x3C49
RESPONSE_INITIALIZED = 0x3C4A
RESPONSE_TERMINAL = 0x3C4C
RESPONSE_STATUS = 0x3C4D
RESPONSE_HTTP_STATE = 0x3C5A
RESPONSE_STATE_END = 0x3C5F

QUARANTINE_RANGES = (
    (0x0D00, 0x0F00),
    (0x3600, 0x3838),
    (0x3910, 0x3B40),
)

REQUEST_PREFIX = (
    b"POST /v1/responses HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"Authorization: Bearer "
)
REQUEST_AFTER_KEY = (
    b"\r\nContent-Type: application/json\r\n"
    b"Content-Length: "
)
REQUEST_HEADER_END = b"\r\n\r\n"
REQUEST_BODY_PREFIX = b'{"model":"'
REQUEST_BODY_SUFFIX = b'","input":"Reply exactly ok.","stream":true}'
HTTP_PREFIX = b"HTTP/1.1 "
OUTPUT_MARKER = b'"type":"response.output_text.delta"'
DELTA_MARKER = b'"delta":"'
COMPLETE_MARKER = b'"type":"response.completed"'
HTTP_TERMINAL_MARKER = b"0\r\n\r\n"

TEST_CLIENT_KEY = hashlib.sha256(b"seed post-auth client key").digest()
TEST_CLIENT_IV = hashlib.sha256(b"seed post-auth client iv").digest()[:12]
TEST_SERVER_KEY = hashlib.sha256(b"seed post-auth server key").digest()
TEST_SERVER_IV = hashlib.sha256(b"seed post-auth server iv").digest()[:12]
TEST_CREDENTIAL = (
    b"sk-" + hashlib.sha256(b"seed post-auth synthetic credential").hexdigest().encode()
)
TEST_GENERATION = 0x5A31
TEST_MODEL = b"gpt-5-nano"


def load_spike():
    spec = importlib.util.spec_from_file_location(
        "seed_post_auth_tls13_spike", SPIKE_SOURCE
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SPIKE_SOURCE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TLS = load_spike()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rol16(value: int) -> int:
    return ((value << 1) | (value >> 15)) & 0xFFFF


def publication_checksum(payload: bytes) -> tuple[int, int]:
    checksum_a = 0x6D5A
    checksum_b = 0xB481
    for byte in payload:
        checksum_a = rol16((checksum_a + byte) & 0xFFFF)
        checksum_b ^= checksum_a
        checksum_b = rol16((checksum_b + 0x9E37) & 0xFFFF)
    return checksum_a, checksum_b


def run_nasm(
    source: Path,
    output: Path,
    listing: Path,
    *,
    defines: dict[str, int] | None = None,
    include_boot: bool = False,
) -> bytes:
    command = ["nasm", "-f", "bin"]
    for name, value in (defines or {}).items():
        command.append(f"-D{name}=0x{value:x}")
    if include_boot:
        command.extend(
            ["-I", str(ROOT / "targets/ibm_pc_5150/boot") + "/"]
        )
    command.extend(
        ["-l", str(listing), "-o", str(output), str(source)]
    )
    subprocess.run(command, cwd=ROOT, check=True)
    return output.read_bytes()


def listing_symbol_address(
    listing: Path, label: str, *, origin: int
) -> int:
    lines = listing.read_text().splitlines()
    marker = re.compile(rf"\b{re.escape(label)}:")
    offset_pattern = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+")
    for index, line in enumerate(lines):
        if not marker.search(line):
            continue
        for candidate in lines[index : index + 8]:
            match = offset_pattern.match(candidate)
            if match:
                return origin + int(match.group(1), 16)
    raise AssertionError(f"cannot resolve {label} in {listing}")


def blob_address(image: bytes, blob: bytes, *, origin: int) -> int:
    offset = image.find(blob)
    if offset < 0 or image.find(blob, offset + 1) >= 0:
        raise AssertionError(f"literal is absent or ambiguous: {blob!r}")
    return origin + offset


def parse_sym_entries(image: bytes) -> tuple[int, ...]:
    if image[:8] != b"T13SYM02":
        raise AssertionError("K14 symmetric image magic mismatch")
    fields = struct.unpack_from("<12H", image, 8)
    image_bytes = fields[1]
    entry_count = fields[-1]
    if image_bytes != len(image):
        raise AssertionError("K14 symmetric header size mismatch")
    return struct.unpack_from(f"<{entry_count}H", image, 32)


def parse_phase_entries(
    image: bytes, magic: bytes, count: int
) -> tuple[int, ...]:
    if image[:4] != magic:
        raise AssertionError(f"{magic.decode()} phase magic mismatch")
    version, image_bytes = struct.unpack_from("<2H", image, 4)
    if version != 1 or image_bytes != len(image):
        raise AssertionError(f"{magic.decode()} phase header mismatch")
    return struct.unpack_from(f"<{count}H", image, 8)


@dataclass(frozen=True)
class Artifacts:
    sym: bytes
    sym_entries: tuple[int, ...]
    request: bytes
    request_entries: tuple[int, ...]
    request_adapter: bytes
    response: bytes
    response_entries: tuple[int, ...]
    response_literals: bytes
    paths: dict[str, Path]


def response_literal_defines(
    *,
    supervisor_receive: int = PLACEHOLDER_SUPERVISOR_RECEIVE,
    persistent_fail: int = PERSISTENT_SECURE_FAIL,
) -> dict[str, int]:
    return {
        "POST_AUTH_RESPONSE_TCP_ACK": RESIDENT_TCP_ACK,
        "POST_AUTH_RESPONSE_SUPERVISOR_RECEIVE": supervisor_receive,
        "POST_AUTH_RESPONSE_PERSIST_FAIL": persistent_fail,
    }


def build_artifacts(
    build_dir: Path,
    *,
    preloaded_publication: bool = False,
) -> Artifacts:
    build_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "sym": build_dir / "sym_k14.bin",
        "sym_listing": build_dir / "sym_k14.lst",
        "request_adapter": build_dir / "post_auth_sym_adapter.bin",
        "request_adapter_listing": build_dir / "post_auth_sym_adapter.lst",
        "request": build_dir / "post_auth_request_controller.bin",
        "request_listing": build_dir / "post_auth_request_controller.lst",
        "response_literals": build_dir / "post_auth_response_literals.bin",
        "response_literals_listing": build_dir / "post_auth_response_literals.lst",
        "response": build_dir / "post_auth_response_controller.bin",
        "response_listing": build_dir / "post_auth_response_controller.lst",
    }

    sym = run_nasm(
        SYM_SOURCE,
        paths["sym"],
        paths["sym_listing"],
        defines={"TLS13_POC_K14": 1, "TLS13_SHARED_SECRET_LEN": 64},
        include_boot=True,
    )
    if SYM_BASE + len(sym) > SYM_LIMIT:
        raise AssertionError("K14 symmetric image exceeds 0x1800..0x3400")
    sym_entries = parse_sym_entries(sym)
    seal_entry = listing_symbol_address(
        paths["sym_listing"], "sym_seal_record", origin=SYM_BASE
    )

    request_adapter = run_nasm(
        REQUEST_ADAPTER_SOURCE,
        paths["request_adapter"],
        paths["request_adapter_listing"],
        defines={
            "POST_AUTH_SYM_SEAL_RECORD": seal_entry,
            "POST_AUTH_RESPONSE_LOAD_PHASE": RESIDENT_LOAD_PHASE,
        },
    )
    request_defines = {
        "POST_AUTH_SYM_SEAL_ENTRY": ADAPTER_BASE + 10,
        "POST_AUTH_REQUEST_PREFIX": blob_address(
            request_adapter, REQUEST_PREFIX, origin=ADAPTER_BASE
        ),
        "POST_AUTH_REQUEST_PREFIX_LEN": len(REQUEST_PREFIX),
        "POST_AUTH_REQUEST_AFTER_KEY": blob_address(
            request_adapter, REQUEST_AFTER_KEY, origin=ADAPTER_BASE
        ),
        "POST_AUTH_REQUEST_AFTER_KEY_LEN": len(REQUEST_AFTER_KEY),
        "POST_AUTH_REQUEST_HEADER_END": blob_address(
            request_adapter, REQUEST_HEADER_END, origin=ADAPTER_BASE
        ),
        "POST_AUTH_REQUEST_HEADER_END_LEN": len(REQUEST_HEADER_END),
        "POST_AUTH_REQUEST_BODY_PREFIX": blob_address(
            request_adapter, REQUEST_BODY_PREFIX, origin=ADAPTER_BASE
        ),
        "POST_AUTH_REQUEST_BODY_PREFIX_LEN": len(REQUEST_BODY_PREFIX),
        "POST_AUTH_REQUEST_BODY_SUFFIX": blob_address(
            request_adapter, REQUEST_BODY_SUFFIX, origin=ADAPTER_BASE
        ),
        "POST_AUTH_REQUEST_BODY_SUFFIX_LEN": len(REQUEST_BODY_SUFFIX),
    }
    if preloaded_publication:
        request_defines["POST_AUTH_PRELOADED_PUBLICATION"] = 1
    request = run_nasm(
        REQUEST_SOURCE,
        paths["request"],
        paths["request_listing"],
        defines=request_defines,
    )

    response_literals = run_nasm(
        RESPONSE_LITERALS_SOURCE,
        paths["response_literals"],
        paths["response_literals_listing"],
        defines=response_literal_defines(),
    )
    response_helper_entries = parse_phase_entries(
        response_literals, b"PAS2", 3
    )
    response_defines = {
        "POST_AUTH_SYM_OPEN_BEGIN": sym_entries[5],
        "POST_AUTH_SYM_OPEN_CHUNK": sym_entries[6],
        "POST_AUTH_SYM_OPEN_FINISH": sym_entries[7],
        "POST_AUTH_RESPONSE_HTTP_PREFIX": blob_address(
            response_literals, HTTP_PREFIX, origin=ADAPTER_BASE
        ),
        "POST_AUTH_RESPONSE_HTTP_PREFIX_LEN": len(HTTP_PREFIX),
        "POST_AUTH_RESPONSE_OUTPUT_MARKER": blob_address(
            response_literals, OUTPUT_MARKER, origin=ADAPTER_BASE
        ),
        "POST_AUTH_RESPONSE_OUTPUT_MARKER_LEN": len(OUTPUT_MARKER),
        "POST_AUTH_RESPONSE_DELTA_MARKER": blob_address(
            response_literals, DELTA_MARKER, origin=ADAPTER_BASE
        ),
        "POST_AUTH_RESPONSE_DELTA_MARKER_LEN": len(DELTA_MARKER),
        "POST_AUTH_RESPONSE_COMPLETE_MARKER": blob_address(
            response_literals, COMPLETE_MARKER, origin=ADAPTER_BASE
        ),
        "POST_AUTH_RESPONSE_COMPLETE_MARKER_LEN": len(COMPLETE_MARKER),
        "POST_AUTH_RESPONSE_HTTP_TERMINAL": blob_address(
            response_literals, HTTP_TERMINAL_MARKER, origin=ADAPTER_BASE
        ),
        "POST_AUTH_RESPONSE_HTTP_TERMINAL_LEN": len(HTTP_TERMINAL_MARKER),
        "POST_AUTH_RESPONSE_MARKER_ADVANCE": response_helper_entries[0],
        "POST_AUTH_RESPONSE_CLEAR_QUARANTINE": response_helper_entries[1],
        "POST_AUTH_RESPONSE_CLEAR_STATE": response_helper_entries[2],
    }
    response = run_nasm(
        RESPONSE_SOURCE,
        paths["response"],
        paths["response_listing"],
        defines=response_defines,
    )

    if CONTROLLER_BASE + len(request) > CONTROLLER_LIMIT:
        raise AssertionError("request controller exceeds low controller slot")
    if CONTROLLER_BASE + len(response) > CONTROLLER_LIMIT:
        raise AssertionError("response controller exceeds low controller slot")
    if ADAPTER_BASE + len(request_adapter) > ADAPTER_LIMIT:
        raise AssertionError("request adapter reaches K14 runtime state")
    if ADAPTER_BASE + len(response_literals) > ADAPTER_LIMIT:
        raise AssertionError("response literals reach K14 runtime state")

    return Artifacts(
        sym=sym,
        sym_entries=sym_entries,
        request=request,
        request_entries=parse_phase_entries(request, b"PAR1", 2),
        request_adapter=request_adapter,
        response=response,
        response_entries=parse_phase_entries(response, b"PAR2", 6),
        response_literals=response_literals,
        paths=paths,
    )


def build_publication(
    key: bytes,
    *,
    declared_len: int | None = None,
    terminate: bool = True,
    model: bytes = TEST_MODEL,
    declared_model_len: int | None = None,
    terminate_model: bool = True,
    route: int = 1,
    checksum_valid: bool = True,
) -> bytes:
    value = bytearray(PUBLICATION_END - PUBLICATION_START)
    value[1] = 0
    value[2:6] = b"PAK1"
    value[6:10] = bytes(byte ^ 0xFF for byte in b"PAK1")
    value[10:12] = TEST_GENERATION.to_bytes(2, "little")
    value[12] = route & 0xFF
    value[13] = (~route) & 0xFF
    length = len(key) if declared_len is None else declared_len
    value[14:16] = length.to_bytes(2, "little")
    copied = min(len(key), PUBLICATION_KEY_MAX + 1)
    value[16 : 16 + copied] = key[:copied]
    if terminate and length <= PUBLICATION_KEY_MAX:
        value[16 + length] = 0
    elif length <= PUBLICATION_KEY_MAX:
        value[16 + length] = 0x58
    model_length = (
        len(model) if declared_model_len is None else declared_model_len
    )
    model_len_offset = PUBLICATION_MODEL_LEN - PUBLICATION_START
    model_offset = PUBLICATION_MODEL - PUBLICATION_START
    value[model_len_offset : model_len_offset + 2] = model_length.to_bytes(
        2, "little"
    )
    copied_model = min(len(model), PUBLICATION_MODEL_MAX + 1)
    value[model_offset : model_offset + copied_model] = model[:copied_model]
    if terminate_model and model_length <= PUBLICATION_MODEL_MAX:
        value[model_offset + model_length] = 0
    elif model_length <= PUBLICATION_MODEL_MAX:
        value[model_offset + model_length] = 0x58
    checksum_a, checksum_b = publication_checksum(
        value[
            PUBLICATION_CHECK_START
            - PUBLICATION_START : PUBLICATION_CHECKSUM_A
            - PUBLICATION_START
        ]
    )
    if not checksum_valid:
        checksum_a ^= 1
    value[
        PUBLICATION_CHECKSUM_A
        - PUBLICATION_START : PUBLICATION_CHECKSUM_A
        - PUBLICATION_START
        + 2
    ] = checksum_a.to_bytes(2, "little")
    value[
        PUBLICATION_CHECKSUM_B
        - PUBLICATION_START : PUBLICATION_CHECKSUM_B
        - PUBLICATION_START
        + 2
    ] = checksum_b.to_bytes(2, "little")
    value[0] = 1
    return bytes(value)


class Machine:
    def __init__(
        self,
        artifacts: Artifacts,
        *,
        publication_mode: str = "success",
        send_failure: bool = False,
        restore_failure: bool = False,
    ) -> None:
        self.artifacts = artifacts
        self.publication_mode = publication_mode
        self.send_failure = send_failure
        self.restore_failure = restore_failure
        self.sent_records: list[bytes] = []
        self.unlock_calls: list[dict[str, int]] = []
        self.restore_calls: list[dict[str, int]] = []
        self.publication_clear_at_unlock: list[bool] = []
        self.publication_trace: list[str] = []
        self.interrupts: list[int] = []
        self.write_events: list[tuple[str, int, int]] = []
        self.active_label = ""
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, RAM_BYTES)
        self.uc.mem_write(0, bytes(RAM_BYTES))
        self.uc.mem_write(SYM_BASE, artifacts.sym)
        self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
        self.uc.mem_write(UNLOCK_CALLBACK, b"\xC3")
        self.uc.mem_write(SYM_RESTORE_CALLBACK, b"\xC3")
        self.uc.mem_write(SEND_CALLBACK, b"\xC3")
        for register in (
            UC_X86_REG_CS,
            UC_X86_REG_DS,
            UC_X86_REG_ES,
            UC_X86_REG_SS,
        ):
            self.uc.reg_write(register, 0)
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt_hook)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write_hook)
        self.write(CLIENT_APP_KEY, TEST_CLIENT_KEY)
        self.write(CLIENT_APP_IV, TEST_CLIENT_IV)
        self.write(SERVER_APP_KEY, TEST_SERVER_KEY)
        self.write(SERVER_APP_IV, TEST_SERVER_IV)
        self.write(CLIENT_APP_SEQ, bytes(8))
        self.write(SERVER_APP_SEQ, bytes(8))

    def _set_carry(self, carry: bool) -> None:
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        if carry:
            flags |= 1
        else:
            flags &= ~1
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags)

    def _code_hook(
        self, uc: Uc, address: int, _size: int, _user: object
    ) -> None:
        if address == UNLOCK_CALLBACK:
            self.publication_clear_at_unlock.append(
                not any(
                    self.read(
                        PUBLICATION_START,
                        PUBLICATION_END - PUBLICATION_START,
                    )
                )
            )
            self.unlock_calls.append(
                {
                    "ax": uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
                    "bx": uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
                    "cx": uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
                    "dx": uc.reg_read(UC_X86_REG_DX) & 0xFFFF,
                    "si": uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
                    "di": uc.reg_read(UC_X86_REG_DI) & 0xFFFF,
                }
            )
            if self.publication_mode != "external":
                self._set_carry(self._publish())
        elif address == SYM_RESTORE_CALLBACK:
            self.restore_calls.append(
                {
                    "ax": uc.reg_read(UC_X86_REG_AX) & 0xFFFF,
                    "bx": uc.reg_read(UC_X86_REG_BX) & 0xFFFF,
                    "cx": uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
                    "dx": uc.reg_read(UC_X86_REG_DX) & 0xFFFF,
                    "si": uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
                    "di": uc.reg_read(UC_X86_REG_DI) & 0xFFFF,
                }
            )
            self._set_carry(self.restore_failure)
        elif address == SEND_CALLBACK:
            source = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            length = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            if source != IO_BASE or not 22 <= length <= 405:
                raise AssertionError("send callback received an invalid record")
            self.sent_records.append(self.read(source, length))
            self._set_carry(self.send_failure)

    def _interrupt_hook(self, _uc: Uc, number: int, _user: object) -> None:
        self.interrupts.append(number)
        raise AssertionError(f"unexpected BIOS/DOS interrupt {number:#x}")

    def _write_hook(
        self,
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        if self.active_label:
            self.write_events.append((self.active_label, address, size))
            if ARENA_FLOOR <= address < STACK_BOTTOM:
                raise AssertionError(
                    f"{self.active_label} wrote into the arena at {address:#06x}"
                )

    def _publish(self) -> bool:
        mode = self.publication_mode
        if mode == "callback_failure":
            self.write(PUBLICATION_KEY, b"partial")
            self.publication_trace.append("partial")
            return True
        if mode == "precommit":
            self.publication_trace.append("empty")
            return False
        if mode == "partial_success":
            self.write(PUBLICATION_START + 2, b"PA")
            self.write(PUBLICATION_STATUS, b"\x01")
            self.publication_trace.extend(("partial", "status"))
            return False

        options: dict[str, object] = {}
        key = TEST_CREDENTIAL
        if mode == "overlength":
            key = b"K" * (PUBLICATION_KEY_MAX + 1)
            options["declared_len"] = PUBLICATION_KEY_MAX + 1
            options["terminate"] = False
        elif mode == "unterminated":
            options["terminate"] = False
        elif mode == "bad_checksum":
            options["checksum_valid"] = False
        elif mode == "wrong_route":
            options["route"] = 2
        elif mode == "model_overlength":
            options["model"] = b"m" * (PUBLICATION_MODEL_MAX + 1)
            options["declared_model_len"] = PUBLICATION_MODEL_MAX + 1
            options["terminate_model"] = False
        elif mode == "model_unterminated":
            options["model"] = b"n" * PUBLICATION_MODEL_MAX
            options["terminate_model"] = False
        elif mode == "model_injection":
            options["model"] = b'gpt-5"bad'
        elif mode != "success":
            raise AssertionError(f"unknown publication mode {mode}")

        publication = build_publication(key, **options)
        self.write(PUBLICATION_START + 1, publication[1:])
        self.publication_trace.append("payload")
        self.write(PUBLICATION_STATUS, publication[:1])
        self.publication_trace.append("status")
        return False

    def _invalidate(self, start: int, end: int) -> None:
        try:
            self.uc.ctl_remove_cache(start, end)
        except AttributeError:
            pass

    def install_request_phase(self) -> None:
        self.write(
            CONTROLLER_BASE, bytes(CONTROLLER_LIMIT - CONTROLLER_BASE)
        )
        self.write(CONTROLLER_BASE, self.artifacts.request)
        self.write(ADAPTER_BASE, bytes(ADAPTER_LIMIT - ADAPTER_BASE))
        self.write(ADAPTER_BASE, self.artifacts.request_adapter)
        self._invalidate(CONTROLLER_BASE, CONTROLLER_LIMIT)
        self._invalidate(ADAPTER_BASE, ADAPTER_LIMIT)

    def install_response_phase(self) -> None:
        self.write(
            CONTROLLER_BASE, bytes(CONTROLLER_LIMIT - CONTROLLER_BASE)
        )
        self.write(CONTROLLER_BASE, self.artifacts.response)
        self.write(ADAPTER_BASE, bytes(ADAPTER_LIMIT - ADAPTER_BASE))
        self.write(ADAPTER_BASE, self.artifacts.response_literals)
        self._invalidate(CONTROLLER_BASE, CONTROLLER_LIMIT)
        self._invalidate(ADAPTER_BASE, ADAPTER_LIMIT)

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.uc.mem_read(address, length))

    def write(self, address: int, value: bytes) -> None:
        self.uc.mem_write(address, bytes(value))

    def call(
        self,
        address: int,
        *,
        label: str,
        ax: int = 0xA5A5,
        bx: int = 0xB6B6,
        cx: int = 0xC7C7,
        dx: int = 0xD8D8,
        si: int = 0xE9E9,
        di: int = 0xFAFA,
        expect_success: bool,
        expect_ax: int,
    ) -> tuple[int, bool]:
        self.write(STACK_TOP - 2, RETURN_SENTINEL.to_bytes(2, "little"))
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
        self.uc.reg_write(UC_X86_REG_CX, cx)
        self.uc.reg_write(UC_X86_REG_DX, dx)
        self.uc.reg_write(UC_X86_REG_SI, si)
        self.uc.reg_write(UC_X86_REG_DI, di)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x2)
        self.active_label = label
        try:
            self.uc.emu_start(address, RETURN_SENTINEL, count=120_000_000)
        except UcError as exc:
            ip = self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF
            raise AssertionError(
                f"Unicorn failed in {label} at {ip:#06x}: {exc}"
            ) from exc
        finally:
            self.active_label = ""
        final_ip = self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF
        final_sp = self.uc.reg_read(UC_X86_REG_SP) & 0xFFFF
        if final_ip != RETURN_SENTINEL or final_sp != STACK_TOP:
            raise AssertionError(
                f"{label} violated return contract "
                f"(IP={final_ip:#06x}, SP={final_sp:#06x})"
            )
        carry = bool(self.uc.reg_read(UC_X86_REG_EFLAGS) & 1)
        result_ax = self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        if carry == expect_success:
            raise AssertionError(f"{label} returned unexpected carry")
        if result_ax != expect_ax:
            raise AssertionError(
                f"{label} returned AX={result_ax}, expected {expect_ax}"
            )
        if self.interrupts:
            raise AssertionError(f"{label} reached an interrupt")
        return result_ax, carry

    def scanner_snapshot(self) -> bytes:
        return (
            self.read(RESPONSE_STATUS, 1)
            + self.read(RESPONSE_HTTP_STATE, RESPONSE_STATE_END - RESPONSE_HTTP_STATE)
        )

    def assert_quarantine_clear(self) -> None:
        for start, end in QUARANTINE_RANGES:
            if any(self.read(start, end - start)):
                raise AssertionError(
                    f"quarantine {start:#06x}..{end:#06x} was not scrubbed"
                )

    def assert_request_scratch_clear(self) -> None:
        if any(self.read(PUBLICATION_START, FRAGMENT_END - PUBLICATION_START)):
            raise AssertionError("request plaintext scratch was not scrubbed")
        if any(self.read(0x3C40, REQUEST_STATUS - 0x3C40)):
            raise AssertionError("request control scratch was not scrubbed")


def decrypt_request(records: list[bytes]) -> tuple[bytes, list[int]]:
    plaintext = bytearray()
    lengths: list[int] = []
    for sequence, record in enumerate(records):
        inner_type, content = TLS.decrypt_record(
            TEST_CLIENT_KEY, TEST_CLIENT_IV, sequence, record
        )
        if inner_type != TLS.CONTENT_APPLICATION_DATA:
            raise AssertionError("request record has wrong inner type")
        if len(content) > 224 or len(content) > 383:
            raise AssertionError("request record exceeds bounded content")
        lengths.append(len(content))
        plaintext.extend(content)
    return bytes(plaintext), lengths


def run_request_success(artifacts: Artifacts) -> tuple[Machine, dict[str, object]]:
    machine = Machine(artifacts)
    machine.install_request_phase()
    machine.call(
        artifacts.request_entries[0],
        label="request_success",
        expect_success=True,
        expect_ax=1,
    )
    if len(machine.unlock_calls) != 1:
        raise AssertionError("request did not call the fixed unlock once")
    if any(machine.unlock_calls[0].values()):
        raise AssertionError("unlock callback received caller-controlled arguments")
    if machine.publication_clear_at_unlock != [True]:
        raise AssertionError("publication was not empty before authenticated load")
    if machine.publication_trace != ["payload", "status"]:
        raise AssertionError("credential publication was not status-last")
    if len(machine.restore_calls) != 1 or any(machine.restore_calls[0].values()):
        raise AssertionError("symmetric restore received caller authority")
    request, fragment_lengths = decrypt_request(machine.sent_records)
    body = REQUEST_BODY_PREFIX + TEST_MODEL + REQUEST_BODY_SUFFIX
    expected = (
        REQUEST_PREFIX
        + TEST_CREDENTIAL
        + REQUEST_AFTER_KEY
        + str(len(body)).encode()
        + REQUEST_HEADER_END
        + body
    )
    if request != expected:
        raise AssertionError("decrypted request is not byte-exact")
    if machine.read(REQUEST_STATUS, 1) != b"\x01":
        raise AssertionError("request success was not retained")
    expected_sequence = len(machine.sent_records).to_bytes(8, "big")
    if machine.read(CLIENT_APP_SEQ, 8) != expected_sequence:
        raise AssertionError("client application sequence did not advance")
    machine.assert_request_scratch_clear()
    if TEST_CREDENTIAL in machine.read(0, RAM_BYTES):
        raise AssertionError("credential remained in RAM after request send")
    return machine, {
        "records": len(machine.sent_records),
        "fragment_lengths": fragment_lengths,
        "plaintext_bytes": len(request),
        "max_tls_inner_content": max(fragment_lengths),
        "fixed_unlock_arguments_zero": True,
        "status_last_publication": True,
        "publication_empty_before_callback": True,
        "fixed_restore_arguments_zero": True,
        "scratch_scrubbed": True,
    }


def run_request_hostile(artifacts: Artifacts) -> list[str]:
    passed: list[str] = []
    for mode in (
        "precommit",
        "callback_failure",
        "partial_success",
        "overlength",
        "unterminated",
        "bad_checksum",
        "wrong_route",
        "model_overlength",
        "model_unterminated",
        "model_injection",
    ):
        machine = Machine(artifacts, publication_mode=mode)
        machine.install_request_phase()
        if mode == "precommit":
            machine.write(PUBLICATION_KEY, b"precommit-key-poison")
            machine.write(PUBLICATION_MODEL, b"precommit-model-poison")
        machine.call(
            artifacts.request_entries[0],
            label=f"request_{mode}",
            expect_success=False,
            expect_ax=0,
        )
        if machine.sent_records:
            raise AssertionError(f"{mode} emitted an unauthorised request")
        if len(machine.unlock_calls) != 1:
            raise AssertionError(f"{mode} did not traverse the fixed unlock")
        if machine.publication_clear_at_unlock != [True]:
            raise AssertionError(f"{mode} saw pre-auth publication bytes")
        if machine.read(REQUEST_STATUS, 1) != b"\0":
            raise AssertionError(f"{mode} retained request success")
        machine.assert_request_scratch_clear()
        passed.append(mode)

    machine = Machine(artifacts, send_failure=True)
    machine.install_request_phase()
    machine.call(
        artifacts.request_entries[0],
        label="request_send_failure",
        expect_success=False,
        expect_ax=0,
    )
    if not machine.sent_records:
        raise AssertionError("send failure did not exercise the send callback")
    machine.assert_request_scratch_clear()
    passed.append("send_failure")

    machine = Machine(artifacts, restore_failure=True)
    machine.install_request_phase()
    machine.call(
        artifacts.request_entries[0],
        label="request_restore_failure",
        expect_success=False,
        expect_ax=0,
    )
    if machine.sent_records:
        raise AssertionError("restore failure emitted a request")
    if len(machine.restore_calls) != 1:
        raise AssertionError("restore failure missed the fixed callback")
    machine.assert_request_scratch_clear()
    passed.append("restore_failure")
    return passed


def make_response_machine(artifacts: Artifacts) -> Machine:
    machine = Machine(artifacts)
    machine.write(REQUEST_STATUS, b"\x01")
    machine.install_response_phase()
    machine.call(
        artifacts.response_entries[0],
        label="response_start",
        expect_success=True,
        expect_ax=0,
    )
    return machine


def feed_server_record(
    machine: Machine,
    record: bytes,
    *,
    label: str,
    expect_success: bool,
    expect_ax: int,
    bad_tag: bool = False,
    cuts: tuple[int, ...] = (1, 383, 17, 224, 3, 311),
) -> None:
    entries = machine.artifacts.response_entries
    machine.write(IO_BASE, record[:5])
    machine.call(
        entries[1],
        label=f"{label}_begin",
        expect_success=True,
        expect_ax=0,
    )
    scanner_before = machine.scanner_snapshot()
    ciphertext = record[5:-16]
    offset = 0
    cut_index = 0
    while offset < len(ciphertext):
        size = min(cuts[cut_index % len(cuts)], 383, len(ciphertext) - offset)
        chunk = ciphertext[offset : offset + size]
        machine.write(RX_BUFFER, chunk)
        machine.call(
            entries[2],
            label=f"{label}_chunk",
            si=RX_BUFFER,
            cx=len(chunk),
            expect_success=True,
            expect_ax=0,
        )
        if machine.scanner_snapshot() != scanner_before:
            raise AssertionError("unauthenticated chunk changed scanner state")
        offset += len(chunk)
        cut_index += 1
    tag = bytearray(record[-16:])
    if bad_tag:
        tag[-1] ^= 1
    machine.write(RX_BUFFER, tag)
    machine.call(
        entries[3],
        label=f"{label}_finish",
        si=RX_BUFFER,
        expect_success=expect_success,
        expect_ax=expect_ax,
    )
    machine.assert_quarantine_clear()


def successful_sse_stream() -> tuple[bytes, list[bytes]]:
    headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/event-stream\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Cache-Control: no-cache\r\n"
        b"\r\n"
    )
    filler = (
        b"event: response.created\n"
        b'data: {"type" : "response.created", "padding" : "'
        + (b"x" * 1280)
        + b'"}\n\n'
    )
    output_o = (
        b"event: response.output_text.delta\n"
        b"data: {\n"
        b'  "type" : "response.output_text.delta",\n'
        b'  "delta" : "o",\n'
        b'  "sequence_number" : 1\n'
        b"}\n\n"
    )
    output_k = (
        b"event: response.output_text.delta\n"
        b"data: {\n"
        b'  "type" : "response.output_text.delta",\n'
        b'  "delta" : "k",\n'
        b'  "sequence_number" : 2\n'
        b"}\n\n"
    )
    completed = (
        b"event: response.output_text.done\n"
        b'data: {"type" : "response.output_text.done"}\n\n'
        b"event: response.completed\n"
        b"data: {\n"
        b'  "type" : "response.completed",\n'
        b'  "response" : {"status" : "completed"}\n'
        b"}\n\n"
    )
    def chunk(value: bytes) -> bytes:
        return f"{len(value):x}\r\n".encode() + value + b"\r\n"

    stream = (
        headers
        + chunk(filler)
        + chunk(output_o)
        + chunk(output_k)
        + chunk(completed)
        + b"0\r\n\r\n"
    )
    output_value = stream.index(b'"response.output_text.delta"')
    delta_o = stream.index(b'"o"', output_value)
    output_value_2 = stream.index(
        b'"response.output_text.delta"', delta_o
    )
    delta_k = stream.index(b'"k"', output_value_2)
    completed_value = stream.index(b'"response.completed"', delta_k)
    terminal_start = len(stream) - len(HTTP_TERMINAL_MARKER)
    if stream[terminal_start:] != HTTP_TERMINAL_MARKER:
        raise AssertionError("successful fixture lacks exact HTTP terminal chunk")
    boundaries = (
        output_value + 13,
        delta_o + 1,
        output_value_2 + 17,
        delta_k + 2,
        completed_value + 12,
        terminal_start,
    )
    records: list[bytes] = []
    start = 0
    for end in boundaries + (len(stream),):
        records.append(stream[start:end])
        start = end
    if not 1080 < len(records[0]) <= 1623:
        raise AssertionError("fixture does not cross all quarantine spans")
    return stream, records


def run_response_success(
    machine: Machine, artifacts: Artifacts
) -> dict[str, object]:
    machine.install_response_phase()
    machine.call(
        artifacts.response_entries[0],
        label="integrated_response_start",
        expect_success=True,
        expect_ax=0,
    )
    _stream, contents = successful_sse_stream()
    for sequence, content in enumerate(contents):
        record = TLS.encrypted_record(
            TEST_SERVER_KEY,
            TEST_SERVER_IV,
            sequence,
            TLS.CONTENT_APPLICATION_DATA,
            content,
            padding_len=7 if sequence == 0 else 0,
        )
        feed_server_record(
            machine,
            record,
            label=f"response_record_{sequence}",
            expect_success=True,
            expect_ax=1 if sequence == len(contents) - 1 else 0,
        )
    machine.call(
        artifacts.response_entries[4],
        label="response_eof",
        expect_success=True,
        expect_ax=1,
    )
    if machine.read(RESPONSE_STATUS, 1) != b"\x01":
        raise AssertionError("completed response status was not retained")
    if machine.read(SERVER_APP_SEQ, 8) != len(contents).to_bytes(8, "big"):
        raise AssertionError("server application sequence did not advance")
    return {
        "records": len(contents),
        "largest_authenticated_content": max(map(len, contents)),
        "crossed_quarantine_spans": 3,
        "record_seam_splits": [
            "first_output_type",
            "first_delta_value",
            "second_output_type",
            "second_delta_value",
            "completed_type",
        ],
        "scanner_unchanged_before_each_tag": True,
        "aggregated_exact_ok_then_completed": True,
        "http_transfer_framing": "chunked",
        "http_terminal_separate_authenticated_record": True,
        "sse_event_lines_harmless": True,
    }


def encrypted_server_record(
    content: bytes, *, sequence: int = 0, padding_len: int = 0
) -> bytes:
    return TLS.encrypted_record(
        TEST_SERVER_KEY,
        TEST_SERVER_IV,
        sequence,
        TLS.CONTENT_APPLICATION_DATA,
        content,
        padding_len=padding_len,
    )


def run_response_hostile(artifacts: Artifacts) -> list[str]:
    passed: list[str] = []

    machine = make_response_machine(artifacts)
    partial = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
        b'data: {"type":"response.output_te'
    )
    feed_server_record(
        machine,
        encrypted_server_record(partial),
        label="tag_fail_prefix",
        expect_success=True,
        expect_ax=0,
    )
    if machine.read(RESPONSE_HTTP_STATE, RESPONSE_STATE_END - RESPONSE_HTTP_STATE) == bytes(
        RESPONSE_STATE_END - RESPONSE_HTTP_STATE
    ):
        raise AssertionError("tag-fail setup did not retain an authenticated seam")
    continuation = (
        b'xt.delta","delta":"ok"}\n'
        b'data: {"type":"response.completed"}\n'
    )
    feed_server_record(
        machine,
        encrypted_server_record(continuation, sequence=1),
        label="tag_fail",
        expect_success=False,
        expect_ax=0,
        bad_tag=True,
    )
    if machine.read(REQUEST_STATUS, 1) != b"\0":
        raise AssertionError("tag failure did not revoke request status")
    if machine.scanner_snapshot() != bytes(len(machine.scanner_snapshot())):
        raise AssertionError("tag failure did not scrub scanner state")
    passed.append("tag_failure_after_authenticated_partial_marker")

    machine = make_response_machine(artifacts)
    non_2xx = (
        b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n"
        b'{"error":"unauthorized"}'
    )
    feed_server_record(
        machine,
        encrypted_server_record(non_2xx),
        label="non_2xx",
        expect_success=False,
        expect_ax=0,
    )
    passed.append("authenticated_non_2xx")

    incomplete_cases = {
        "missing_completion": (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b'data: {"type":"response.output_text.delta","delta":"ok"}\n\n'
        ),
        "orphan_delta": (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b'data: {"delta":"ok"}\n\n'
            b'data: {"type":"response.completed"}\n\n'
        ),
        "delta_in_later_object": (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b'data: {"type":"response.output_text.delta"}\n\n'
            b'data: {"delta":"ok"}\n\n'
            b'data: {"type":"response.completed"}\n\n'
        ),
        "completion_without_http_terminal": (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b'data: {"type":"response.output_text.delta","delta":"ok"}\n\n'
            b'data: {"type":"response.completed"}\n\n'
        ),
    }
    for name, content in incomplete_cases.items():
        machine = make_response_machine(artifacts)
        feed_server_record(
            machine,
            encrypted_server_record(content),
            label=name,
            expect_success=True,
            expect_ax=0,
        )
        machine.call(
            artifacts.response_entries[4],
            label=f"{name}_eof",
            expect_success=False,
            expect_ax=0,
        )
        passed.append(name)

    immediate_rejections = {
        "wrong_delta": (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b'data: {"type":"response.output_text.delta","delta":"okay"}\n\n'
            b'data: {"type":"response.completed"}\n\n'
        ),
        "whitespace_inside_ok": (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b'data: {"type":"response.output_text.delta","delta":"o k"}\n\n'
            b'data: {"type":"response.completed"}\n\n'
        ),
        "wrong_first_byte": (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b'data: {"type":"response.output_text.delta","delta":"x"}\n\n'
            b'data: {"type":"response.completed"}\n\n'
        ),
        "bytes_after_http_terminal": (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b'data: {"type":"response.output_text.delta","delta":"ok"}\n\n'
            b'data: {"type":"response.completed"}\n\n'
            + HTTP_TERMINAL_MARKER
            + b"x"
        ),
    }
    for name, content in immediate_rejections.items():
        machine = make_response_machine(artifacts)
        feed_server_record(
            machine,
            encrypted_server_record(content),
            label=name,
            expect_success=False,
            expect_ax=0,
        )
        passed.append(name)

    machine = make_response_machine(artifacts)
    compact_single_delta = (
        b"HTTP/1.1 200 OK\r\n\r\n"
        b'data: {"type":"response.output_text.delta","delta":"ok"}\n\n'
        b'data: {"type":"response.output_text.done"}\n\n'
        b'data: {"type":"response.completed"}\n\n'
        + HTTP_TERMINAL_MARKER
    )
    feed_server_record(
        machine,
        encrypted_server_record(compact_single_delta),
        label="compact_single_delta",
        expect_success=True,
        expect_ax=1,
    )
    machine.call(
        artifacts.response_entries[4],
        label="compact_single_delta_eof",
        expect_success=True,
        expect_ax=1,
    )
    passed.append("compact_single_delta_ok_accepted")

    machine = make_response_machine(artifacts)
    third_output = (
        b"HTTP/1.1 200 OK\r\n\r\n"
        b'data: {"type":"response.output_text.delta","delta":"ok"}\n\n'
        b'data: {"type":"response.output_text.delta","delta":"x"}\n\n'
        b'data: {"type":"response.completed"}\n\n'
    )
    feed_server_record(
        machine,
        encrypted_server_record(third_output),
        label="third_output",
        expect_success=False,
        expect_ax=0,
    )
    passed.append("third_output_event")

    machine = make_response_machine(artifacts)
    oversized_plaintext = 1625
    payload_len = oversized_plaintext + 16
    machine.write(
        IO_BASE,
        b"\x17\x03\x03" + payload_len.to_bytes(2, "big"),
    )
    machine.call(
        artifacts.response_entries[1],
        label="oversized_record",
        expect_success=False,
        expect_ax=0,
    )
    passed.append("oversized_record")
    return passed


def static_controller_gate(artifacts: Artifacts) -> dict[str, object]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    reports: dict[str, object] = {}
    for name, image, entries in (
        ("request", artifacts.request, artifacts.request_entries),
        ("response", artifacts.response, artifacts.response_entries),
    ):
        start = min(entries)
        offset = start - CONTROLLER_BASE
        instructions = list(
            decoder.disasm(image[offset:], start)
        )
        calls: list[int] = []
        for instruction in instructions:
            if instruction.mnemonic in {
                "int",
                "int1",
                "int3",
                "into",
                "in",
                "insb",
                "insw",
                "out",
                "outsb",
                "outsw",
            }:
                raise AssertionError(f"{name} contains direct I/O")
            if instruction.mnemonic == "call":
                if (
                    len(instruction.operands) != 1
                    or instruction.operands[0].type != X86_OP_IMM
                ):
                    raise AssertionError(f"{name} contains an indirect call")
                calls.append(instruction.operands[0].imm & 0xFFFF)
        reports[name] = {
            "decoded_instructions": len(instructions),
            "direct_call_targets": [f"{target:#06x}" for target in sorted(set(calls))],
        }
        if name == "request" and calls.count(UNLOCK_CALLBACK) != 1:
            raise AssertionError("request does not have exactly one fixed unlock call")
        if name == "request" and calls.count(SEND_CALLBACK) != 1:
            raise AssertionError("request does not have exactly one fixed send call")
        if name == "request" and calls.count(SYM_RESTORE_CALLBACK) != 1:
            raise AssertionError("request does not have exactly one fixed restore call")
    return reports


def run(build_dir: Path) -> dict[str, object]:
    artifacts = build_artifacts(build_dir)
    static_report = static_controller_gate(artifacts)
    request_machine, request_report = run_request_success(artifacts)
    request_hostile = run_request_hostile(artifacts)
    response_report = run_response_success(request_machine, artifacts)
    response_hostile = run_response_hostile(artifacts)

    source_and_images = b"".join(
        path.read_bytes()
        for path in (
            REQUEST_SOURCE,
            REQUEST_ADAPTER_SOURCE,
            RESPONSE_SOURCE,
            RESPONSE_LITERALS_SOURCE,
            artifacts.paths["request"],
            artifacts.paths["request_adapter"],
            artifacts.paths["response"],
            artifacts.paths["response_literals"],
        )
    )
    if TEST_CREDENTIAL in source_and_images:
        raise AssertionError("synthetic credential leaked into source/image")

    return {
        "status": "PASS",
        "profile": "cpu-8086 K14 post-auth application controller",
        "layout": {
            "request_controller_bytes": len(artifacts.request),
            "request_adapter_bytes": len(artifacts.request_adapter),
            "response_controller_bytes": len(artifacts.response),
            "response_literals_bytes": len(artifacts.response_literals),
            "low_controller_slot": "0x0900..0x0d00",
            "quarantine_spans": [
                "0x0d00..0x0f00",
                "0x3600..0x3838",
                "0x3920..0x3b40",
            ],
            "retained_scanner_state": "0x3c4a..0x3c62",
        },
        "request": request_report,
        "response": response_report,
        "hostile_request_cases": request_hostile,
        "hostile_response_cases": response_hostile,
        "static_gate": static_report,
        "credential_policy": {
            "compiled_or_reported": False,
            "publication_address_fixed": f"{PUBLICATION_START:#06x}",
            "unlock_callback_fixed": f"{UNLOCK_CALLBACK:#06x}",
            "sym_restore_callback_fixed": f"{SYM_RESTORE_CALLBACK:#06x}",
            "send_callback_fixed": f"{SEND_CALLBACK:#06x}",
        },
        "sha256": {
            name: sha256_file(path)
            for name, path in artifacts.paths.items()
            if not name.endswith("_listing")
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=ROOT / "build/crypto-bench/tls13-post-auth-request",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=HERE / "post_auth_application_results.json",
    )
    args = parser.parse_args()
    result = run(args.build_dir)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
