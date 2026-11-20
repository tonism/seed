#!/usr/bin/env python3
"""Executable hostile gate for the acquisition/resumption TLS 1.3 286 HELLO.

The gate runs the real cached-pack loader, ML-KEM-768 key generator, X25519
module, ClientHello iterator, and streaming ServerHello parser under Unicorn.
Independent host oracles bind the generated asymmetric outputs, complete wire
image, transcript digest, profile exclusions, pending-fragment semantics, and
both accepted ServerHello extension orders.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_MEM_READ,
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
BUILD = ROOT / "build/ibm_pc_5150"
CRYPTO_BUILD = BUILD / "crypto-bench"
HELLO_BUILDER = HERE / "build_286_hello_controller.py"
ROOT_BUILDER = HERE / "build_286_root_stage.py"
RUNTIME_ABI_BUILDER = HERE / "build_286_runtime_abi.py"
FLIGHT_SYM_BUILDER = HERE / "build_286_flight_sym.py"
FLIGHT_BUILDER = HERE / "build_286_flight.py"
HELLO = BUILD / "tls13-286-hello.bin"
ABORT_CAPSULE = BUILD / "tls13-286-abort-capsule.bin"
STAGE = BUILD / "tls13-286-root-stage.bin"
CORE = BUILD / "tls13-286-tail-base/SEED.SYS"
PACK = CRYPTO_BUILD / "tls13-286-modules.bin"
RUNTIME_ABI_REPORT = BUILD / "tls13-286-runtime-abi.json"
FLIGHT = BUILD / "tls13-286-flight.bin"
FLIGHT_COMPONENT = BUILD / "tls13-286-flight-component.bin"
FLIGHT_REPORT = BUILD / "tls13-286-flight.json"
K14_SYM = BUILD / "tls13-286-flight-sym-k14.bin"
MLKEM_SEED = CRYPTO_BUILD / "tls13-286-mlkem-seed.bin"
MLKEM_DK = CRYPTO_BUILD / "tls13-286-mlkem-expected-dk.bin"
MLKEM_CIPHERTEXT = CRYPTO_BUILD / "tls13-286-mlkem-ciphertext.bin"
MLKEM_SECRET = CRYPTO_BUILD / "tls13-286-mlkem-expected-secret.bin"
MLKEM_MATRIX_CACHE = (
    CRYPTO_BUILD / "tls13-286-mlkem-expected-matrix-cache.bin"
)
MLKEM_KEYGEN_ORACLE = (
    HERE.parent / "tls13-spike/mlkem768_integrated_keygen_check.py"
)
FLIGHT_CHECKER = HERE / "check_286_flight.py"

HELLO_BASE = 0x1800
HELLO_LIMIT = 0x3400
HELLO_MAGIC = b"S286HL02"
HELLO_ENTRIES = 2
STAGE_BASE = 0x3400
STAGE_LIMIT = 0x3C00
LOADER_ENTRY_TABLE = STAGE_BASE + 14
LOADER_VALIDATE_INDEX = 0
LOADER_DECODE_INDEX = 1
LOADER_CALL_INDEX = 2
ROOT_SERVICE_TABLE = 0x3910
ROOT_SERVICE_CHAIN_POINTER = ROOT_SERVICE_TABLE + 10
MODULE_BASE = 0x4230
MODULE_LIMIT = 0x7A00
ABORT_CAPSULE_LOAD = 0x4040
ABORT_CAPSULE_LIMIT = MODULE_BASE
ABORT_CAPSULE_MAGIC = b"S286AB02"
ABORT_CAPSULE_HEADER_BYTES = 16
ABORT_CAPSULE_CRYPTO_SEG = ABORT_CAPSULE_LIMIT - 4
ABORT_CAPSULE_CRYPTO_SEG_INVERSE = ABORT_CAPSULE_LIMIT - 2

ROOT_STATE = 0x4020
ROOT_CRYPTO_SEG = ROOT_STATE + 2
LOADER_STATE = ROOT_STATE + 4
LOADER_CACHE_SEG = LOADER_STATE
LOADER_CACHE_CAPACITY = LOADER_STATE + 2
LOADER_PACK_BYTES = LOADER_STATE + 4
ROOT_PARENT_SP = LOADER_STATE + 18
ROOT_PARENT_SP_INVERSE = ROOT_PARENT_SP + 2
ROOT_PARENT_STATUS_INV = ROOT_PARENT_SP + 4

CRYPTO_SEG = 0x7000
CRYPTO_BASE = CRYPTO_SEG << 4
HIGH_BYTES = 64 * 1024
PACK_BYTES = 41 * 512
CORE_START_LBA = 11
DK_OFF = 0xA780
DK_BYTES = 2400
SCALAR_OFF = 0xB120
SCALAR_BYTES = 32
HYBRID_SECRET_OFF = 0xB140
TICKET_PSK_OFF = 0xB1A0
TICKET_PSK_BYTES = 32
TICKET_IDENTITY_OFF = 0xB1C0
TICKET_IDENTITY_MAX = 192
TICKET_NONCE_OFF = 0xB280
TICKET_NONCE_MAX = 32
FOOTER_OFF = 0xB602
ATTEMPT_OFF = 0xB982
ATTEMPT_BYTES = 160
FRESH_ATTEMPT_OFF = ATTEMPT_OFF + ATTEMPT_BYTES
ROOT_STATUS_INV_OFF = 0xBB62
ROOT_STATUS_OFF = ROOT_STATUS_INV_OFF + 1
ACQUIRE_STATUS_INV_OFF = ROOT_STATUS_OFF + 1
ACQUIRE_STATUS_OFF = ACQUIRE_STATUS_INV_OFF + 1
FRESH_STATUS_INV_OFF = ACQUIRE_STATUS_OFF + 1
FRESH_STATUS_OFF = FRESH_STATUS_INV_OFF + 1
READY_INV = 0x5A
READY = 0xA5
USED_INV = 0xC3
USED = 0x3C

RX_OFF = 0x0700
EK_OFF = 0x08C0
EK_BYTES = 1184
CIPHERTEXT_OFF = 0x08C0
CIPHERTEXT_BYTES = 1088
SERVER_X_OFF = 0x0D00
DIGEST_OFF = 0x0D20
CTX_MAGIC_OFF = 0x0D40
CTX_BLOCK_LEN_OFF = 0x0D45
CTX_LEN_LOW_OFF = 0x0D46
CTX_LEN_HIGH_OFF = 0x0D48
CTX_BLOCK_OFF = 0x0D6A
STATUS_OFF = 0x0DAA
CLIENT_X_HANDOFF = 0x4000
PENDING_WIRE_OFF = 0xBB68
PENDING_WIRE_LEN_OFF = PENDING_WIRE_OFF + 384
PENDING_WIRE_STATUS_INV_OFF = PENDING_WIRE_LEN_OFF + 2
PENDING_WIRE_STATUS_OFF = PENDING_WIRE_STATUS_INV_OFF + 1
CANDIDATE_CIPHERTEXT_OFF = 0x5800
CANDIDATE_SECRET_OFF = CANDIDATE_CIPHERTEXT_OFF + CIPHERTEXT_BYTES
CANDIDATE_STATUS_INV_OFF = CANDIDATE_SECRET_OFF + 32
CANDIDATE_STATUS_OFF = CANDIDATE_STATUS_INV_OFF + 1
CANDIDATE_VALID_INV = 0x5A
CANDIDATE_VALID = 0xA5

AUTH_STATUS_INV_OFF = 0xBCF6
AUTH_STATUS_OFF = AUTH_STATUS_INV_OFF + 1
TICKET_LIFETIME_HI_OFF = 0xBD10
TICKET_LIFETIME_LO_OFF = TICKET_LIFETIME_HI_OFF + 2
TICKET_AGE_ADD_OFF = TICKET_LIFETIME_LO_OFF + 2
TICKET_NONCE_LEN_OFF = TICKET_AGE_ADD_OFF + 4
TICKET_IDENTITY_LEN_OFF = TICKET_NONCE_LEN_OFF + 2
TICKET_RECEIPT_TICK_LO_OFF = TICKET_IDENTITY_LEN_OFF + 2
TICKET_RECEIPT_TICK_HI_OFF = TICKET_RECEIPT_TICK_LO_OFF + 2
TICKET_STATUS_INV_OFF = TICKET_RECEIPT_TICK_HI_OFF + 2
TICKET_STATUS_OFF = TICKET_STATUS_INV_OFF + 1
TICKET_TRUNCATED_HASH_OFF = TICKET_STATUS_OFF + 1
TICKET_BINDER_OFF = TICKET_TRUNCATED_HASH_OFF + 32
SYM_STAGE_STATUS_INV_OFF = TICKET_BINDER_OFF + 32
SYM_STAGE_STATUS_OFF = SYM_STAGE_STATUS_INV_OFF + 1
RESUMPTION_EARLY_OFF = SYM_STAGE_STATUS_OFF + 1
RESUMPTION_EARLY_BYTES = 32
RESUMPTION_EARLY_INVERSE_OFF = (
    RESUMPTION_EARLY_OFF + RESUMPTION_EARLY_BYTES
)
RESUMPTION_EARLY_STATUS_INV_OFF = (
    RESUMPTION_EARLY_INVERSE_OFF + RESUMPTION_EARLY_BYTES
)
RESUMPTION_EARLY_STATUS_OFF = RESUMPTION_EARLY_STATUS_INV_OFF + 1
MLKEM_MATRIX_STATUS_INV_OFF = RESUMPTION_EARLY_STATUS_OFF + 1
MLKEM_MATRIX_STATUS_OFF = MLKEM_MATRIX_STATUS_INV_OFF + 1
RECORD_PLAIN_BYTES = (1 << 14) + 256 - 16
SYM_STAGE_OFF = HIGH_BYTES - RECORD_PLAIN_BYTES
MLKEM_MATRIX_STAGE_OFF = SYM_STAGE_OFF + 12 * 512
MLKEM_MATRIX_STAGE_BYTES = 9 * 256 * 2
FLIGHT_STAGE_STATUS_INV_OFF = MLKEM_MATRIX_STATUS_OFF + 1
FLIGHT_STAGE_STATUS_OFF = FLIGHT_STAGE_STATUS_INV_OFF + 1
FLIGHT_STAGE_OFF = MLKEM_MATRIX_STAGE_OFF + MLKEM_MATRIX_STAGE_BYTES
FLIGHT_STAGE_BYTES = 6 * 512
TICKET_TENTATIVE_INV = 0x5A
TICKET_TENTATIVE = 0xA5
TICKET_PROMOTED_INV = 0xC3
TICKET_PROMOTED = 0x3C
TICKET_USED_INV = 0x96
TICKET_USED = 0x69

RETURN_SENTINEL = 0x0200
ABORT_STUB = 0x0202
BOOTSTRAP_ABORT_POINTER = 0x0706
STACK_TOP = 0x7FFE
PARENT_STACK_TOP = 0xFFF0
PARENT_ENTRY_SP = PARENT_STACK_TOP - 2
FEED_BUFFER = 0x5000
NIC_ENTER_STUB = 0x0300
NIC_RESTORE_STUB = 0x0302

MODULE_KIND_KEYGEN = 1
MODULE_KIND_DECAP = 2
MODULE_KIND_X25519 = 3
MODULE_OP_KEYGEN = 1
MODULE_OP_MLKEM_DECAP = 2
MODULE_OP_X25519_KEYGEN = 3
MODULE_OP_X25519_SHARED = 4
MODULE_OP_MLKEM_CANDIDATE = 8
MODULE_OP_MLKEM_MATRIX_PRECOMPUTE = 9
MODULE_OP_MLKEM_DECAP_CACHED = 10
TAIL_KIND_FLIGHT = 9

DESC_OP = 0
DESC_FLAGS = 2
DESC_INPUT0 = 4
SPAN_BYTES = 8
DESC_INPUT1 = DESC_INPUT0 + SPAN_BYTES
DESC_INPUT2 = DESC_INPUT1 + SPAN_BYTES
DESC_INPUT3 = DESC_INPUT2 + SPAN_BYTES
DESC_OUTPUT0 = DESC_INPUT3 + SPAN_BYTES
DESC_OUTPUT1 = DESC_OUTPUT0 + SPAN_BYTES
DESC_BYTES = DESC_OUTPUT1 + SPAN_BYTES

CLIENT_RANDOM = bytes((index * 13 + 7) & 0xFF for index in range(32))
SESSION_ID = bytes((index * 29 + 3) & 0xFF for index in range(32))
X_SCALAR = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645"
    "df4c2f87ebc0992ab177fba51db92c2a"
)
FRESH_BUNDLE = bytes((index * 41 + 19) & 0xFF for index in range(160))
SERVER_RANDOM = bytes((index * 17 + 0x31) & 0xFF for index in range(32))
SERVER_CIPHERTEXT = bytes((index * 73 + 0x29) & 0xFF for index in range(1088))
SERVER_X = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece43537"
    "3f8343c85b78674dadfc7e146f882b4f"
)
TICKET_PSK = bytes((index * 31 + 0x42) & 0xFF for index in range(32))
TICKET_IDENTITY = bytes(
    (index * 47 + 0x19) & 0xFF for index in range(96)
)
TICKET_NONCE = bytes((index * 11 + 0x73) & 0xFF for index in range(16))
TICKET_AGE_ADD = bytes.fromhex("10203040")
TICKET_LIFETIME = 7200
TICKET_RECEIPT_TICKS = 10_000
TICKET_CURRENT_TICKS = 10_010


def load_keygen_oracle():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_286_hello_keygen_oracle",
        MLKEM_KEYGEN_ORACLE,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load independent ML-KEM keygen oracle")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


KEYGEN_ORACLE = load_keygen_oracle()


def load_flight_checker():
    spec = importlib.util.spec_from_file_location(
        "seed_tls13_286_hello_flight_checker",
        FLIGHT_CHECKER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load 286 protected-flight checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def u16(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def x25519(scalar: bytes, peer: bytes) -> bytes:
    if len(scalar) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    if len(peer) != 32:
        raise ValueError("X25519 peer must be 32 bytes")
    value = bytearray(scalar)
    value[0] &= 248
    value[31] &= 127
    value[31] |= 64
    k = int.from_bytes(value, "little")
    p = 2**255 - 19
    x1 = int.from_bytes(peer, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for position in range(254, -1, -1):
        bit = (k >> position) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % p
        aa = a * a % p
        b = (x2 - z2) % p
        bb = b * b % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = d * a % p
        cb = c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * (da - cb) ** 2 % p
        x2 = aa * bb % p
        z2 = e * (aa + 121665 * e) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = x2 * pow(z2, p - 2, p) % p
    return result.to_bytes(32, "little")


def x25519_base(scalar: bytes) -> bytes:
    return x25519(scalar, (9).to_bytes(32, "little"))


def mlkem_encapsulate(ek: bytes, seed: bytes) -> tuple[bytes, bytes]:
    if len(ek) != EK_BYTES or len(seed) != 32:
        raise ValueError("ML-KEM encapsulation fixture geometry drifted")
    message = hashlib.sha3_256(seed).digest()
    kr = hashlib.sha3_512(
        message + hashlib.sha3_256(ek).digest()
    ).digest()
    ciphertext = KEYGEN_ORACLE.ORACLE.k_pke_encrypt(
        ek, message, kr[32:]
    )
    return ciphertext, kr[:32]


def matrix_cache_oracle(dk: bytes) -> bytes:
    if len(dk) != DK_BYTES:
        raise ValueError("matrix-cache oracle requires one expanded dk")
    rho = dk[2304:2336]
    matrix = b"".join(
        struct.pack(
            "<256H",
            *KEYGEN_ORACLE.ORACLE.sample_ntt(
                rho + bytes((row, column))
            ),
        )
        for row in range(3)
        for column in range(3)
    )
    if len(matrix) != MLKEM_MATRIX_STAGE_BYTES:
        raise AssertionError("matrix-cache oracle geometry drifted")
    return matrix


@dataclass(frozen=True)
class Built:
    hello: bytes
    entries: tuple[int, ...]
    abort_capsule: bytes
    abort_entry: int
    success_entry: int
    stage: bytes
    core: bytes
    loader_entries: tuple[int, ...]
    pack: bytes
    seed: bytes
    expected_dk: bytes
    expected_secret: bytes
    expected_matrix_cache: bytes
    runtime: dict[str, int]
    flight: bytes
    flight_component: bytes
    flight_entry: int
    flight_start_sector: int
    flight_stored_bytes: int
    flight_crc16: int
    footer: bytes


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


def build_footer(
    *,
    flight_start: int,
    flight_sectors: int,
    stored_bytes: int,
    flight_entry: int,
    flight_crc: int,
) -> bytes:
    total_sectors = flight_start + flight_sectors + 1
    footer = bytearray(512)
    struct.pack_into(
        "<8sHHHHHHH",
        footer,
        0,
        b"S286TL02",
        2,
        32,
        total_sectors,
        flight_start,
        flight_sectors + 1,
        1,
        16,
    )
    struct.pack_into(
        "<HHHHHHHH",
        footer,
        32,
        TAIL_KIND_FLIGHT,
        3,
        flight_start,
        flight_sectors,
        stored_bytes,
        0x6300,
        flight_entry,
        flight_crc,
    )
    struct.pack_into("<H", footer, 510, crc16(footer[:510]))
    return bytes(footer)


def build() -> Built:
    global SERVER_CIPHERTEXT
    subprocess.run([sys.executable, str(ROOT_BUILDER)], cwd=ROOT, check=True)
    subprocess.run(
        [sys.executable, str(RUNTIME_ABI_BUILDER)],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [sys.executable, str(FLIGHT_SYM_BUILDER)], cwd=ROOT, check=True
    )
    subprocess.run(
        [sys.executable, str(FLIGHT_BUILDER)], cwd=ROOT, check=True
    )
    subprocess.run([sys.executable, str(HELLO_BUILDER)], cwd=ROOT, check=True)
    hello = HELLO.read_bytes()
    abort_capsule = ABORT_CAPSULE.read_bytes()
    stage = STAGE.read_bytes()
    core = CORE.read_bytes()
    pack = PACK.read_bytes()
    seed = MLKEM_SEED.read_bytes()
    expected_dk = MLKEM_DK.read_bytes()
    SERVER_CIPHERTEXT = MLKEM_CIPHERTEXT.read_bytes()
    expected_secret = MLKEM_SECRET.read_bytes()
    expected_matrix_cache = MLKEM_MATRIX_CACHE.read_bytes()
    flight = FLIGHT.read_bytes()
    flight_component = FLIGHT_COMPONENT.read_bytes()
    flight_report = json.loads(FLIGHT_REPORT.read_text())
    report = json.loads(RUNTIME_ABI_REPORT.read_text())
    runtime = {
        name: int(value, 16)
        for name, value in report["definitions"].items()
    }
    if hello[:8] != HELLO_MAGIC:
        raise AssertionError("HELLO magic drifted")
    abi, image_bytes, count = struct.unpack_from("<HHH", hello, 8)
    if (abi, image_bytes, count) != (2, len(hello), HELLO_ENTRIES):
        raise AssertionError("HELLO header drifted")
    if (
        len(abort_capsule) < ABORT_CAPSULE_HEADER_BYTES
        or abort_capsule[:8] != ABORT_CAPSULE_MAGIC
    ):
        raise AssertionError("abort capsule magic drifted")
    abort_abi, abort_bytes, abort_entry, success_entry = struct.unpack_from(
        "<HHHH", abort_capsule, 8
    )
    if (
        abort_abi != 2
        or abort_bytes != len(abort_capsule)
        or not 0 < len(abort_capsule) <= ABORT_CAPSULE_LIMIT - ABORT_CAPSULE_LOAD
        or not (
            ABORT_CAPSULE_LOAD
            <= abort_entry
            < ABORT_CAPSULE_LOAD + len(abort_capsule)
        )
        or not (
            ABORT_CAPSULE_LOAD
            <= success_entry
            < ABORT_CAPSULE_LOAD + len(abort_capsule)
        )
        or abort_entry == success_entry
    ):
        raise AssertionError("abort capsule header/geometry drifted")
    if hello.count(abort_capsule) != 1:
        raise AssertionError(
            "HELLO does not package exactly one byte-identical abort capsule"
        )
    entries = struct.unpack_from(f"<{count}H", hello, 14)
    loader_entries = struct.unpack_from("<4H", stage, 14)
    flight_entry = u16(flight, 14)
    flight_sectors = len(flight_component) // 512
    flight_start_sector = len(core) // 512
    flight_stored_bytes = int(flight_report["stored_bytes"])
    flight_crc = int(flight_report["raw_crc16_ccitt"], 16)
    footer = build_footer(
        flight_start=flight_start_sector,
        flight_sectors=flight_sectors,
        stored_bytes=flight_stored_bytes,
        flight_entry=flight_entry,
        flight_crc=flight_crc,
    )
    if len(stage) != STAGE_LIMIT - STAGE_BASE or len(pack) != PACK_BYTES:
        raise AssertionError("root stage/module pack geometry drifted")
    if (
        len(seed) != 64
        or len(expected_dk) != DK_BYTES
        or len(SERVER_CIPHERTEXT) != CIPHERTEXT_BYTES
        or len(expected_secret) != 32
        or len(expected_matrix_cache) != MLKEM_MATRIX_STAGE_BYTES
    ):
        raise AssertionError("ML-KEM oracle fixture geometry drifted")
    return Built(
        hello,
        entries,
        abort_capsule,
        abort_entry,
        success_entry,
        stage,
        core,
        loader_entries,
        pack,
        seed,
        expected_dk,
        expected_secret,
        expected_matrix_cache,
        runtime,
        flight,
        flight_component,
        flight_entry,
        flight_start_sector,
        flight_stored_bytes,
        flight_crc,
        footer,
    )


class Machine:
    def __init__(
        self,
        built: Built,
        snapshot: bytes | None = None,
        network_payloads: list[bytes] | None = None,
        *,
        bios_ticks: int = TICKET_CURRENT_TICKS,
        bios_rollover: int = 0,
        fail_sym_read_index: int | None = None,
        fail_flight_read_index: int | None = None,
        matrix_status_before_transport: bytes | None = None,
        matrix_payload_flip_index: int | None = None,
    ) -> None:
        if (
            matrix_status_before_transport is not None
            and len(matrix_status_before_transport) != 2
        ):
            raise ValueError("matrix status override must be exactly two bytes")
        if matrix_payload_flip_index is not None and not (
            0 <= matrix_payload_flip_index < MLKEM_MATRIX_STAGE_BYTES
        ):
            raise ValueError("matrix payload flip escaped the exact cache")
        if (
            matrix_status_before_transport is not None
            and matrix_payload_flip_index is not None
        ):
            raise ValueError(
                "matrix status and payload hostility are separate cases"
            )
        self.built = built
        self.root_aborted = False
        self.bundle_reads: list[tuple[int, int, bytes]] = []
        self.status_writes: list[tuple[int, int, bytes]] = []
        self.fresh_status_writes: list[tuple[int, int, bytes]] = []
        self.pending_status_writes: list[tuple[int, int, bytes]] = []
        self.ticket_status_writes: list[tuple[int, int, bytes]] = []
        self.sym_stage_status_writes: list[tuple[int, int, bytes]] = []
        self.flight_stage_status_writes: list[tuple[int, int, bytes]] = []
        self.early_status_writes: list[tuple[int, int, bytes]] = []
        self.early_data_write_statuses: list[bytes] = []
        self.matrix_status_writes: list[tuple[int, int, bytes]] = []
        self.matrix_data_write_statuses: list[bytes] = []
        self.matrix_data_read_statuses: list[bytes] = []
        self.matrix_write_coverage: set[int] = set()
        self.matrix_read_coverage: set[int] = set()
        self.sym_stage_reads: list[tuple[int, int, int, bytes]] = []
        self.flight_stage_reads: list[tuple[int, int, int, bytes]] = []
        self.sym_stage_ready_event: (
            tuple[bytes, int, int, int, int, bytes, bytes] | None
        ) = None
        self.flight_stage_ready_event: (
            tuple[bytes, int, int, int, int] | None
        ) = None
        self.flight_decode_event: tuple[bytes, bytes] | None = None
        self.early_ready_event: (
            tuple[bytes, bytes, bytes, int, int, int] | None
        ) = None
        self.matrix_ready_event: (
            tuple[bytes, int, int, int, int] | None
        ) = None
        self.matrix_cached_decap_event: (
            tuple[bytes, int, int, int] | None
        ) = None
        self.cache_publication_events: list[str] = []
        self.ticket_private_reads: list[tuple[int, int, bytes]] = []
        self.module_decodes: list[int] = []
        self.module_calls: list[int] = []
        self.module_descriptors: list[tuple[int, bytes]] = []
        self.transport_events: list[str] = []
        self.status_ready_event: bytes | None = None
        self.network_payloads = list(network_payloads or ())
        self.bios_ticks = bios_ticks
        self.bios_rollover = bios_rollover
        self.fail_sym_read_index = fail_sym_read_index
        self.fail_flight_read_index = fail_flight_read_index
        self.matrix_status_before_transport = matrix_status_before_transport
        self.matrix_payload_flip_index = matrix_payload_flip_index
        self.matrix_status_injected = False
        self.matrix_payload_injection_event: (
            tuple[int, int, int, bytes, int, int, int] | None
        ) = None
        self.bios_tick_reads = 0
        self.sent_payloads: list[bytes] = []
        self.phase_loads: list[tuple[int, int]] = []
        self.phase_load_snapshots: list[tuple[bytes, bytes]] = []
        self.tcp_connects = 0
        self.tcp_acks = 0
        self.nic_enters = 0
        self.nic_restores = 0
        self.chain_kinds: list[int] = []
        self.chain_handoff_event: bytes | None = None
        self.chain_hybrid_event: bytes | None = None
        self.root_chain_entry = u16(
            built.stage, ROOT_SERVICE_CHAIN_POINTER - STAGE_BASE
        )
        if not ROOT_SERVICE_TABLE <= self.root_chain_entry < STAGE_LIMIT:
            raise AssertionError(
                "root component-chain service pointer escaped root image"
            )
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 1024 * 1024)
        if snapshot is None:
            self.uc.mem_write(HELLO_BASE, built.hello)
            self.uc.mem_write(STAGE_BASE, built.stage)
            self.uc.mem_write(CRYPTO_BASE, built.pack)
            self.uc.mem_write(CRYPTO_BASE + FOOTER_OFF, built.footer)
            self.uc.mem_write(RETURN_SENTINEL, b"\xF4")
            self.uc.mem_write(ABORT_STUB, b"\xF4")
            self.uc.mem_write(
                BOOTSTRAP_ABORT_POINTER, struct.pack("<H", ABORT_STUB)
            )
            self.uc.mem_write(NIC_ENTER_STUB, b"\xF4")
            self.uc.mem_write(NIC_RESTORE_STUB, b"\xF4")
            self.uc.mem_write(
                built.runtime["TLS13_286_LINK_NIC_ENTER_SLOT"],
                struct.pack("<H", NIC_ENTER_STUB),
            )
            self.uc.mem_write(
                built.runtime["TLS13_286_LINK_NIC_RESTORE_SLOT"],
                struct.pack("<H", NIC_RESTORE_STUB),
            )
            self.uc.mem_write(0x0413, struct.pack("<H", 512))
            self.uc.mem_write(ROOT_CRYPTO_SEG, struct.pack("<H", CRYPTO_SEG))
            self.uc.mem_write(
                ROOT_PARENT_SP, struct.pack("<H", PARENT_ENTRY_SP)
            )
            self.uc.mem_write(
                ROOT_PARENT_SP_INVERSE,
                struct.pack("<H", PARENT_ENTRY_SP ^ 0xFFFF),
            )
            self.uc.mem_write(ROOT_PARENT_STATUS_INV, b"\x5A\xA5")
            self.uc.mem_write(LOADER_CACHE_SEG, struct.pack("<H", CRYPTO_SEG))
            self.uc.mem_write(
                LOADER_CACHE_CAPACITY, struct.pack("<H", PACK_BYTES)
            )
        else:
            if len(snapshot) != 1024 * 1024:
                raise ValueError("machine snapshot is not exact")
            self.uc.mem_write(0, snapshot)
        self.shadow = bytearray(self.uc.mem_read(0, 1024 * 1024))
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_INTR, self._interrupt)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write)
        if snapshot is None:
            self.call_address(
                built.loader_entries[LOADER_VALIDATE_INDEX],
                bx=LOADER_STATE,
                expect_success=True,
                instruction_limit=30_000_000,
            )
            if u16(bytes(self.uc.mem_read(LOADER_PACK_BYTES, 2))) != PACK_BYTES:
                raise AssertionError("pack validation did not publish exact size")
            self._install_attempts()
            self.bundle_reads.clear()
            self.status_writes.clear()
            self.fresh_status_writes.clear()
            self.sym_stage_status_writes.clear()
            self.flight_stage_status_writes.clear()
            self.early_status_writes.clear()
            self.early_data_write_statuses.clear()
            self.matrix_status_writes.clear()
            self.matrix_data_write_statuses.clear()
            self.matrix_data_read_statuses.clear()
            self.matrix_write_coverage.clear()
            self.matrix_read_coverage.clear()

    def install_promoted_ticket(
        self,
        *,
        identity: bytes = TICKET_IDENTITY,
        psk: bytes = TICKET_PSK,
        nonce: bytes = TICKET_NONCE,
        lifetime: int = TICKET_LIFETIME,
        age_add: bytes = TICKET_AGE_ADD,
        receipt_ticks: int = TICKET_RECEIPT_TICKS,
    ) -> None:
        if (
            len(psk) != TICKET_PSK_BYTES
            or not 0 < len(identity) <= TICKET_IDENTITY_MAX
            or not 0 < len(nonce) <= TICKET_NONCE_MAX
            or len(age_add) != 4
            or not 0 < lifetime <= 604_800
            or not 0 <= receipt_ticks < 0x1800B0
        ):
            raise ValueError("invalid promoted-ticket fixture")
        base = CRYPTO_BASE
        self.uc.mem_write(
            base + AUTH_STATUS_INV_OFF,
            bytes((CANDIDATE_VALID_INV, CANDIDATE_VALID)),
        )
        self.uc.mem_write(base + TICKET_PSK_OFF, psk)
        self.uc.mem_write(base + TICKET_IDENTITY_OFF, identity)
        self.uc.mem_write(base + TICKET_NONCE_OFF, nonce)
        self.uc.mem_write(
            base + TICKET_LIFETIME_HI_OFF,
            struct.pack("<HH", lifetime >> 16, lifetime & 0xFFFF),
        )
        self.uc.mem_write(base + TICKET_AGE_ADD_OFF, age_add)
        self.uc.mem_write(
            base + TICKET_NONCE_LEN_OFF,
            struct.pack(
                "<HHHH",
                len(nonce),
                len(identity),
                receipt_ticks & 0xFFFF,
                receipt_ticks >> 16,
            ),
        )
        self.uc.mem_write(
            base + TICKET_STATUS_INV_OFF,
            bytes((TICKET_PROMOTED_INV, TICKET_PROMOTED)),
        )
        self.uc.mem_write(base + TICKET_TRUNCATED_HASH_OFF, bytes(64))
        self.shadow[:] = self.uc.mem_read(0, 1024 * 1024)
        self.ticket_status_writes.clear()
        self.ticket_private_reads.clear()
        self.early_status_writes.clear()
        self.early_data_write_statuses.clear()
        self.early_ready_event = None
        self.matrix_status_writes.clear()
        self.matrix_data_write_statuses.clear()
        self.matrix_data_read_statuses.clear()
        self.matrix_write_coverage.clear()
        self.matrix_read_coverage.clear()
        self.matrix_ready_event = None
        self.matrix_cached_decap_event = None
        self.cache_publication_events.clear()

    def install_stale_ready_caches(self) -> None:
        early = bytes(
            (index * 37 + 0x29) & 0xFF
            for index in range(RESUMPTION_EARLY_BYTES)
        )
        matrix = bytes(
            (index * 43 + 0x17) & 0xFF
            for index in range(MLKEM_MATRIX_STAGE_BYTES)
        )
        self.uc.mem_write(
            CRYPTO_BASE + RESUMPTION_EARLY_OFF,
            early + bytes(byte ^ 0xFF for byte in early),
        )
        self.uc.mem_write(
            CRYPTO_BASE + RESUMPTION_EARLY_STATUS_INV_OFF,
            bytes((READY_INV, READY)),
        )
        self.uc.mem_write(
            CRYPTO_BASE + MLKEM_MATRIX_STAGE_OFF, matrix
        )
        self.uc.mem_write(
            CRYPTO_BASE + MLKEM_MATRIX_STATUS_INV_OFF,
            bytes((READY_INV, READY)),
        )
        self.shadow[:] = self.uc.mem_read(0, 1024 * 1024)
        self.early_status_writes.clear()
        self.early_data_write_statuses.clear()
        self.early_ready_event = None
        self.matrix_status_writes.clear()
        self.matrix_data_write_statuses.clear()
        self.matrix_data_read_statuses.clear()
        self.matrix_write_coverage.clear()
        self.matrix_read_coverage.clear()
        self.matrix_ready_event = None
        self.matrix_cached_decap_event = None
        self.cache_publication_events.clear()

    def _interrupt(self, uc: Uc, intno: int, _user: object) -> None:
        if intno != 0x1A or ((uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF) != 0:
            raise AssertionError(f"unexpected BIOS interrupt {intno:02x}")
        if not 0 <= self.bios_ticks < 0x1800B0:
            raise AssertionError("host BIOS tick fixture escaped one day")
        self.bios_tick_reads += 1
        self.cache_publication_events.append("ticket-age-tick")
        uc.reg_write(
            UC_X86_REG_AX,
            (uc.reg_read(UC_X86_REG_AX) & 0xFF00)
            | (self.bios_rollover & 0xFF),
        )
        uc.reg_write(UC_X86_REG_CX, self.bios_ticks >> 16)
        uc.reg_write(UC_X86_REG_DX, self.bios_ticks & 0xFFFF)

    def _install_attempts(self) -> None:
        acquire = (
            self.built.seed
            + X_SCALAR
            + CLIENT_RANDOM
            + SESSION_ID
        )
        if len(acquire) != ATTEMPT_BYTES:
            raise AssertionError("acquisition fixture length drifted")
        self.uc.mem_write(CRYPTO_BASE + ATTEMPT_OFF, acquire)
        self.uc.mem_write(CRYPTO_BASE + FRESH_ATTEMPT_OFF, FRESH_BUNDLE)
        status = bytes((READY_INV, READY, READY_INV, READY, READY_INV, READY))
        self.uc.mem_write(CRYPTO_BASE + ROOT_STATUS_INV_OFF, status)
        self.shadow[:] = self.uc.mem_read(0, 1024 * 1024)

    def _code(self, uc: Uc, address: int, _size: int, _user: object) -> None:
        runtime = self.built.runtime
        if address == runtime["TLS13_286_LINK_LOAD_CORE_SECTORS_AT"]:
            phase_key = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            self.phase_loads.append(
                (
                    phase_key,
                    destination,
                )
            )
            sector = phase_key & 0xFF
            sectors = phase_key >> 8
            start = sector * 512
            end = start + sectors * 512
            if not sectors or end > len(self.built.core):
                raise AssertionError(
                    f"invalid core phase geometry {phase_key:04x}"
                )
            uc.mem_write(destination, self.built.core[start:end])
            self.phase_load_snapshots.append(
                (
                    bytes(uc.mem_read(EK_OFF, EK_BYTES)),
                    bytes(
                        uc.mem_read(
                            CRYPTO_BASE + DK_OFF + 1152,
                            EK_BYTES,
                        )
                    ),
                )
            )
            self._near_return(carry=False)
        elif address == runtime["TLS13_286_LINK_READ_ABS_SECTOR"]:
            # Cleanup restores and traverses resident parent code after the
            # packaged abort entry.  At that point this numeric address is no
            # longer a callable staging event.
            if self.root_aborted:
                return
            lba = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            es = uc.reg_read(UC_X86_REG_ES) & 0xFFFF
            destination = uc.reg_read(UC_X86_REG_BX) & 0xFFFF
            if uc.reg_read(UC_X86_REG_DS) != 0 or es != CRYPTO_SEG:
                raise AssertionError(
                    "HELLO staged a sector with noncanonical segments: "
                    f"ds={uc.reg_read(UC_X86_REG_DS):04x} es={es:04x}"
                )
            if self.module_calls or self.nic_enters or self.tcp_connects:
                raise AssertionError(
                    "HELLO staged a sector after crypto or NIC/TCP work"
                )
            phase_key = runtime["TLS13_286_LINK_SYM_PHASE_KEY"]
            source_sector = phase_key & 0xFF
            sector_count = runtime["TLS13_286_LINK_SYM_SECTORS"]
            if destination < FLIGHT_STAGE_OFF:
                index = len(self.sym_stage_reads)
                expected_lba = CORE_START_LBA + source_sector + index
                expected_destination = SYM_STAGE_OFF + index * 512
                if (
                    phase_key >> 8 != sector_count
                    or index >= sector_count
                    or lba != expected_lba
                    or destination != expected_destination
                ):
                    raise AssertionError(
                        "HELLO symmetric sector geometry drifted: "
                        f"index={index} lba={lba} es={es:04x} "
                        f"destination={destination:04x}"
                    )
                status = bytes(
                    self.shadow[
                        CRYPTO_BASE + SYM_STAGE_STATUS_INV_OFF :
                        CRYPTO_BASE + SYM_STAGE_STATUS_OFF + 1
                    ]
                )
                self.sym_stage_reads.append((lba, es, destination, status))
                if self.fail_sym_read_index == index:
                    self._near_return(carry=True, clear_segments=False)
                    return
                start = (source_sector + index) * 512
                payload = self.built.core[start : start + 512]
                if len(payload) != 512:
                    raise AssertionError(
                        "symmetric source sector escaped SEED.SYS"
                    )
            else:
                index = len(self.flight_stage_reads)
                sector_count = len(self.built.flight_component) // 512
                expected_lba = (
                    CORE_START_LBA
                    + self.built.flight_start_sector
                    + index
                )
                expected_destination = FLIGHT_STAGE_OFF + index * 512
                if (
                    index >= sector_count
                    or lba != expected_lba
                    or destination != expected_destination
                ):
                    raise AssertionError(
                        "HELLO FLIGHT sector geometry drifted: "
                        f"index={index} lba={lba} es={es:04x} "
                        f"destination={destination:04x}"
                    )
                status = bytes(
                    self.shadow[
                        CRYPTO_BASE + FLIGHT_STAGE_STATUS_INV_OFF :
                        CRYPTO_BASE + FLIGHT_STAGE_STATUS_OFF + 1
                    ]
                )
                self.flight_stage_reads.append((lba, es, destination, status))
                if self.fail_flight_read_index == index:
                    self._near_return(carry=True, clear_segments=False)
                    return
                start = index * 512
                payload = self.built.flight_component[start : start + 512]
                if len(payload) != 512:
                    raise AssertionError(
                        "FLIGHT source sector escaped its exact component"
                    )
            physical_destination = (es << 4) + destination
            uc.mem_write(physical_destination, payload)
            self.shadow[
                physical_destination : physical_destination + len(payload)
            ] = payload
            self._near_return(carry=False, clear_segments=False)
        elif address == runtime["TLS13_286_LINK_TCP_CONNECT_ENTRY"]:
            self.tcp_connects += 1
            self.transport_events.append("tcp-connect")
            self._near_return(carry=False)
        elif address == runtime["TLS13_286_LINK_TCP_SEND"]:
            # Once the authenticated abort capsule has been entered, the
            # transport call surface is dead.  Its numeric address may later
            # be traversed as ordinary restored parent code; do not mistake
            # that post-abort instruction address for another wire send.
            if self.root_aborted:
                return
            pointer = uc.reg_read(UC_X86_REG_SI) & 0xFFFF
            length = uc.reg_read(UC_X86_REG_CX) & 0xFFFF
            payload = bytes(uc.mem_read(pointer, length))
            self.sent_payloads.append(payload)
            self.transport_events.append("tcp-send")
            self._near_return(carry=False)
        elif address == runtime["TLS13_286_LINK_TCP_RECEIVE"]:
            if not self.network_payloads:
                self._near_return(carry=True)
            else:
                payload = self.network_payloads.pop(0)
                if not 0 < len(payload) <= 384:
                    raise AssertionError(
                        f"host queued invalid TCP payload length {len(payload)}"
                    )
                uc.mem_write(RX_OFF, payload)
                uc.mem_write(
                    runtime["TLS13_286_LINK_TCP_RX_PAYLOAD_PTR"],
                    struct.pack("<H", RX_OFF),
                )
                uc.mem_write(
                    runtime["TLS13_286_LINK_TCP_RX_PAYLOAD_LEN"],
                    struct.pack("<H", len(payload)),
                )
                self._near_return(carry=False)
        elif address == runtime["TLS13_286_LINK_TCP_ACK"]:
            self.tcp_acks += 1
            self._near_return(carry=False)
        elif address == NIC_ENTER_STUB:
            if self.matrix_status_before_transport is not None:
                status_address = (
                    CRYPTO_BASE + MLKEM_MATRIX_STATUS_INV_OFF
                )
                uc.mem_write(
                    status_address, self.matrix_status_before_transport
                )
                self.shadow[
                    status_address : status_address + 2
                ] = self.matrix_status_before_transport
                self.matrix_status_injected = True
            elif self.matrix_payload_flip_index is not None:
                matrix_address = (
                    CRYPTO_BASE
                    + MLKEM_MATRIX_STAGE_OFF
                    + self.matrix_payload_flip_index
                )
                status = bytes(
                    self.shadow[
                        CRYPTO_BASE + MLKEM_MATRIX_STATUS_INV_OFF :
                        CRYPTO_BASE + MLKEM_MATRIX_STATUS_OFF + 1
                    ]
                )
                if (
                    self.matrix_ready_event is None
                    or status != bytes((READY_INV, READY))
                ):
                    raise AssertionError(
                        "matrix payload hostility preceded READY publication"
                    )
                before = self.shadow[matrix_address]
                after = before ^ 1
                uc.mem_write(matrix_address, bytes((after,)))
                self.shadow[matrix_address] = after
                self.matrix_payload_injection_event = (
                    self.matrix_payload_flip_index,
                    before,
                    after,
                    status,
                    len(self.module_calls),
                    self.nic_enters,
                    self.tcp_connects,
                )
            self.nic_enters += 1
            self.transport_events.append("nic-enter")
            self._near_return(carry=False)
        elif address == NIC_RESTORE_STUB:
            self.nic_restores += 1
            self._near_return(carry=False)
        elif address == self.built.flight_entry:
            decoded = bytes(
                uc.mem_read(0x6300, len(self.built.flight))
            )
            # X25519/ML-KEM overlays span this numeric offset while they are
            # live.  Only the exact decoded S286FL02 header identifies the
            # later one-way coordinator handoff.
            if decoded[:8] != b"S286FL02":
                return
            staged = bytes(
                uc.mem_read(
                    CRYPTO_BASE + FLIGHT_STAGE_OFF,
                    FLIGHT_STAGE_BYTES,
                )
            )
            if decoded != self.built.flight:
                mismatch = next(
                    index
                    for index, (actual, expected) in enumerate(
                        zip(decoded, self.built.flight, strict=True)
                    )
                    if actual != expected
                )
                raise AssertionError(
                    "HELLO did not decode the exact protected-flight image: "
                    f"offset={mismatch:#x} "
                    f"actual={decoded[mismatch:mismatch + 16].hex()} "
                    f"expected={self.built.flight[mismatch:mismatch + 16].hex()}"
                )
            if staged[: len(self.built.flight_component)] != \
                self.built.flight_component or any(
                    staged[len(self.built.flight_component) :]
                ):
                raise AssertionError(
                    "HELLO entered FLIGHT without the exact staged component"
                )
            if bytes(
                uc.mem_read(
                    CRYPTO_BASE + FLIGHT_STAGE_STATUS_INV_OFF, 2
                )
            ) != b"\x00\x00":
                raise AssertionError(
                    "HELLO entered FLIGHT before consuming stage status"
                )
            self.flight_decode_event = (decoded, staged)
            self.chain_kinds.append(TAIL_KIND_FLIGHT)
            self.chain_handoff_event = bytes(
                uc.mem_read(
                    SERVER_X_OFF,
                    STATUS_OFF + 1 - SERVER_X_OFF,
                )
            )
            self.chain_hybrid_event = bytes(
                uc.mem_read(CRYPTO_BASE + HYBRID_SECRET_OFF, 64)
            )
            retired = bytes(len(self.built.flight))
            uc.mem_write(0x6300, retired)
            self.shadow[0x6300 : 0x6300 + len(retired)] = retired
            staged_retired = bytes(FLIGHT_STAGE_BYTES)
            uc.mem_write(CRYPTO_BASE + FLIGHT_STAGE_OFF, staged_retired)
            self.shadow[
                CRYPTO_BASE + FLIGHT_STAGE_OFF :
                CRYPTO_BASE + FLIGHT_STAGE_OFF + FLIGHT_STAGE_BYTES
            ] = staged_retired
            uc.reg_write(UC_X86_REG_AX, TAIL_KIND_FLIGHT)
            self._near_return(carry=False)
        elif address == self.root_chain_entry:
            self.chain_kinds.append(
                uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            )
            self.chain_handoff_event = bytes(
                uc.mem_read(
                    SERVER_X_OFF,
                    STATUS_OFF + 1 - SERVER_X_OFF,
                )
            )
            self.chain_hybrid_event = bytes(
                uc.mem_read(
                    CRYPTO_BASE + HYBRID_SECRET_OFF,
                    64,
                )
            )
            self._near_return(carry=False)
        elif address == self.built.abort_entry:
            self.root_aborted = True
        elif (
            address == self.built.runtime["TLS13_286_LINK_ROUTE_MODE"]
            and self.root_aborted
        ):
            self._near_return(carry=False)
        elif address == self.built.loader_entries[LOADER_DECODE_INDEX]:
            self.module_decodes.append(uc.reg_read(UC_X86_REG_AX) & 0xFFFF)
        elif address == self.built.loader_entries[LOADER_CALL_INDEX]:
            operation = uc.reg_read(UC_X86_REG_AX) & 0xFFFF
            self.module_calls.append(operation)
            descriptor = bytes(
                uc.mem_read(
                    uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
                    DESC_BYTES,
                )
            )
            self.module_descriptors.append((operation, descriptor))
            if operation == MODULE_OP_MLKEM_DECAP_CACHED:
                self.matrix_cached_decap_event = (
                    bytes(
                        self.shadow[
                            CRYPTO_BASE + MLKEM_MATRIX_STATUS_INV_OFF :
                            CRYPTO_BASE + MLKEM_MATRIX_STATUS_OFF + 1
                        ]
                    ),
                    self.nic_enters,
                    self.tcp_connects,
                    len(self.matrix_data_read_statuses),
                )
            self.transport_events.append(f"module-{operation}")

    def _read(
        self,
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        _value: int,
        _user: object,
    ) -> None:
        start = CRYPTO_BASE + ATTEMPT_OFF
        end = start + ATTEMPT_BYTES
        if address < end and address + size > start:
            statuses = bytes(
                self.shadow[
                    CRYPTO_BASE + ACQUIRE_STATUS_INV_OFF :
                    CRYPTO_BASE + ACQUIRE_STATUS_OFF + 1
                ]
            )
            self.bundle_reads.append((address, size, statuses))
        private_ranges = (
            (
                CRYPTO_BASE + TICKET_PSK_OFF,
                CRYPTO_BASE + TICKET_PSK_OFF + TICKET_PSK_BYTES,
            ),
            (
                CRYPTO_BASE + TICKET_IDENTITY_OFF,
                CRYPTO_BASE + TICKET_IDENTITY_OFF + TICKET_IDENTITY_MAX,
            ),
        )
        if any(
            address < end and address + size > start
            for start, end in private_ranges
        ):
            status = bytes(
                self.shadow[
                    CRYPTO_BASE + TICKET_STATUS_INV_OFF :
                    CRYPTO_BASE + TICKET_STATUS_OFF + 1
                ]
            )
            self.ticket_private_reads.append((address, size, status))
        matrix_start = CRYPTO_BASE + MLKEM_MATRIX_STAGE_OFF
        matrix_end = matrix_start + MLKEM_MATRIX_STAGE_BYTES
        if address < matrix_end and address + size > matrix_start:
            self.matrix_data_read_statuses.append(
                bytes(
                    self.shadow[
                        CRYPTO_BASE + MLKEM_MATRIX_STATUS_INV_OFF :
                        CRYPTO_BASE + MLKEM_MATRIX_STATUS_OFF + 1
                    ]
                )
            )
            overlap_start = max(address, matrix_start)
            overlap_end = min(address + size, matrix_end)
            self.matrix_read_coverage.update(
                range(
                    overlap_start - matrix_start,
                    overlap_end - matrix_start,
                )
            )

    def _write(
        self,
        _uc: Uc,
        _access: int,
        address: int,
        size: int,
        value: int,
        _user: object,
    ) -> None:
        mask = (1 << (size * 8)) - 1
        self.shadow[address : address + size] = (
            int(value) & mask
        ).to_bytes(size, "little")
        inv = CRYPTO_BASE + ACQUIRE_STATUS_INV_OFF
        end = CRYPTO_BASE + ACQUIRE_STATUS_OFF + 1
        if address < end and address + size > inv:
            pair = bytes(self.shadow[inv:end])
            self.status_writes.append((address, size, pair))
        fresh_inv = CRYPTO_BASE + FRESH_STATUS_INV_OFF
        fresh_end = CRYPTO_BASE + FRESH_STATUS_OFF + 1
        if address < fresh_end and address + size > fresh_inv:
            pair = bytes(self.shadow[fresh_inv:fresh_end])
            self.fresh_status_writes.append((address, size, pair))
        if address <= STATUS_OFF < address + size:
            if self.shadow[STATUS_OFF] == 1:
                self.status_ready_event = bytes(
                    self.shadow[SERVER_X_OFF : STATUS_OFF + 1]
                )
        pending_inv = CRYPTO_BASE + PENDING_WIRE_STATUS_INV_OFF
        pending_end = CRYPTO_BASE + PENDING_WIRE_STATUS_OFF + 1
        if address < pending_end and address + size > pending_inv:
            self.pending_status_writes.append(
                (
                    address,
                    size,
                    bytes(self.shadow[pending_inv:pending_end]),
                )
            )
        ticket_inv = CRYPTO_BASE + TICKET_STATUS_INV_OFF
        ticket_end = CRYPTO_BASE + TICKET_STATUS_OFF + 1
        if address < ticket_end and address + size > ticket_inv:
            self.ticket_status_writes.append(
                (
                    address,
                    size,
                    bytes(self.shadow[ticket_inv:ticket_end]),
                )
            )
        stage_inv = CRYPTO_BASE + SYM_STAGE_STATUS_INV_OFF
        stage_end = CRYPTO_BASE + SYM_STAGE_STATUS_OFF + 1
        if address < stage_end and address + size > stage_inv:
            pair = bytes(self.shadow[stage_inv:stage_end])
            self.sym_stage_status_writes.append((address, size, pair))
            if pair == bytes((READY_INV, READY)):
                self.sym_stage_ready_event = (
                    bytes(
                        self.shadow[
                            CRYPTO_BASE + SYM_STAGE_OFF :
                            CRYPTO_BASE
                            + SYM_STAGE_OFF
                            + self.built.runtime["TLS13_286_LINK_SYM_SECTORS"]
                            * 512
                        ]
                    ),
                    len(self.sym_stage_reads),
                    len(self.module_calls),
                    self.nic_enters,
                    self.tcp_connects,
                    bytes(
                        self.uc.mem_read(
                            CRYPTO_BASE
                            + SYM_STAGE_OFF
                            + self.built.runtime[
                                "TLS13_286_LINK_SYM_PRODUCT_INITIAL_POINTER_OFF"
                            ],
                            2,
                        )
                    ),
                    bytes(
                        self.uc.mem_read(
                            CRYPTO_BASE + SYM_STAGE_OFF + 0x16E0,
                            0x0120,
                        )
                    ),
                )
        flight_stage_inv = CRYPTO_BASE + FLIGHT_STAGE_STATUS_INV_OFF
        flight_stage_end = CRYPTO_BASE + FLIGHT_STAGE_STATUS_OFF + 1
        if address < flight_stage_end and address + size > flight_stage_inv:
            pair = bytes(self.shadow[flight_stage_inv:flight_stage_end])
            self.flight_stage_status_writes.append((address, size, pair))
            if pair == bytes((READY_INV, READY)):
                sectors = len(self.built.flight_component) // 512
                self.flight_stage_ready_event = (
                    bytes(
                        self.shadow[
                            CRYPTO_BASE + FLIGHT_STAGE_OFF :
                            CRYPTO_BASE + FLIGHT_STAGE_OFF + sectors * 512
                        ]
                    ),
                    len(self.flight_stage_reads),
                    len(self.module_calls),
                    self.nic_enters,
                    self.tcp_connects,
                )
        early_start = CRYPTO_BASE + RESUMPTION_EARLY_OFF
        early_end = (
            CRYPTO_BASE
            + RESUMPTION_EARLY_INVERSE_OFF
            + RESUMPTION_EARLY_BYTES
        )
        early_status_inv = (
            CRYPTO_BASE + RESUMPTION_EARLY_STATUS_INV_OFF
        )
        early_status_end = CRYPTO_BASE + RESUMPTION_EARLY_STATUS_OFF + 1
        if address < early_end and address + size > early_start:
            self.early_data_write_statuses.append(
                bytes(self.shadow[early_status_inv:early_status_end])
            )
        if address < early_status_end and address + size > early_status_inv:
            pair = bytes(self.shadow[early_status_inv:early_status_end])
            self.early_status_writes.append((address, size, pair))
            if pair == bytes((READY_INV, READY)):
                self.cache_publication_events.append("early-ready")
                self.early_ready_event = (
                    bytes(
                        self.shadow[
                            early_start :
                            early_start + RESUMPTION_EARLY_BYTES
                        ]
                    ),
                    bytes(
                        self.shadow[
                            CRYPTO_BASE + RESUMPTION_EARLY_INVERSE_OFF :
                            CRYPTO_BASE
                            + RESUMPTION_EARLY_INVERSE_OFF
                            + RESUMPTION_EARLY_BYTES
                        ]
                    ),
                    bytes(
                        self.shadow[
                            CRYPTO_BASE + TICKET_STATUS_INV_OFF :
                            CRYPTO_BASE + TICKET_STATUS_OFF + 1
                        ]
                    ),
                    len(self.module_calls),
                    self.nic_enters,
                    self.tcp_connects,
                )
        matrix_start = CRYPTO_BASE + MLKEM_MATRIX_STAGE_OFF
        matrix_end = matrix_start + MLKEM_MATRIX_STAGE_BYTES
        matrix_status_inv = (
            CRYPTO_BASE + MLKEM_MATRIX_STATUS_INV_OFF
        )
        matrix_status_end = CRYPTO_BASE + MLKEM_MATRIX_STATUS_OFF + 1
        if address < matrix_end and address + size > matrix_start:
            self.matrix_data_write_statuses.append(
                bytes(self.shadow[matrix_status_inv:matrix_status_end])
            )
            overlap_start = max(address, matrix_start)
            overlap_end = min(address + size, matrix_end)
            self.matrix_write_coverage.update(
                range(
                    overlap_start - matrix_start,
                    overlap_end - matrix_start,
                )
            )
        if (
            address < matrix_status_end
            and address + size > matrix_status_inv
        ):
            pair = bytes(
                self.shadow[matrix_status_inv:matrix_status_end]
            )
            self.matrix_status_writes.append((address, size, pair))
            if pair == bytes((READY_INV, READY)):
                self.cache_publication_events.append("matrix-ready")
                self.matrix_ready_event = (
                    bytes(self.shadow[matrix_start:matrix_end]),
                    len(self.matrix_write_coverage),
                    len(self.module_calls),
                    self.nic_enters,
                    self.tcp_connects,
                )

    def _near_return(
        self, *, carry: bool, clear_segments: bool = True
    ) -> None:
        sp = self.uc.reg_read(UC_X86_REG_SP) & 0xFFFF
        ip = u16(bytes(self.uc.mem_read(sp, 2)))
        self.uc.reg_write(UC_X86_REG_SP, (sp + 2) & 0xFFFF)
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        flags = (flags | 1) if carry else (flags & ~1)
        flags &= ~0x0400
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags)
        if clear_segments:
            self.uc.reg_write(UC_X86_REG_DS, 0)
            self.uc.reg_write(UC_X86_REG_ES, 0)
        self.uc.reg_write(UC_X86_REG_IP, ip)

    def call_address(
        self,
        address: int,
        *,
        ax: int = 0,
        bx: int = 0,
        cx: int = 0,
        si: int = 0,
        expect_success: bool,
        instruction_limit: int = 600_000_000,
    ) -> tuple[int, int, int]:
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
        self.uc.reg_write(UC_X86_REG_CX, cx)
        self.uc.reg_write(UC_X86_REG_SI, si)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x0402)
        try:
            self.uc.emu_start(address, RETURN_SENTINEL, count=instruction_limit)
        except UcError as error:
            ip = self.uc.reg_read(UC_X86_REG_IP) & 0xFFFF
            raise AssertionError(
                f"286 HELLO failed at {ip:04x}: {error}"
            ) from error
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        carry = bool(flags & 1)
        result = self.uc.reg_read(UC_X86_REG_AX) & 0xFFFF
        if carry == expect_success:
            raise AssertionError(
                f"entry {address:04x} returned CF={int(carry)} AX={result:04x}"
            )
        if flags & 0x0400:
            raise AssertionError("286 HELLO returned with DF set")
        if self.uc.reg_read(UC_X86_REG_DS) or self.uc.reg_read(UC_X86_REG_ES):
            raise AssertionError("286 HELLO did not restore DS=ES=0")
        return (
            result,
            self.uc.reg_read(UC_X86_REG_SI) & 0xFFFF,
            self.uc.reg_read(UC_X86_REG_CX) & 0xFFFF,
        )

    def call(
        self,
        index: int,
        *,
        ax: int = 0,
        bx: int = 0,
        cx: int = 0,
        si: int = 0,
        expect_success: bool = True,
        instruction_limit: int = 600_000_000,
    ) -> tuple[int, int, int]:
        return self.call_address(
            self.built.entries[index],
            ax=ax,
            bx=bx,
            cx=cx,
            si=si,
            expect_success=expect_success,
            instruction_limit=instruction_limit,
        )

    def snapshot(self) -> bytes:
        return bytes(self.uc.mem_read(0, 1024 * 1024))


def client_oracle(
    ek: bytes,
    client_x: bytes,
    client_random: bytes = CLIENT_RANDOM,
    session_id: bytes = SESSION_ID,
) -> bytes:
    fixed = b"\x00\x02\x13\x03\x01\x00"
    extensions = (
        bytes.fromhex("00000013001100000e")
        + b"api.openai.com"
        + bytes.fromhex("002b0003020304")
        + bytes.fromhex("000a0004000211ec")
        + bytes.fromhex("000d000400020403")
        + bytes.fromhex("003304c604c411ec04c0")
        + ek
        + client_x
        + bytes.fromhex("001000050003026832")
        + bytes.fromhex("00320006000404030503")
        + bytes.fromhex("002d00020101")
    )
    if len(extensions) != 0x511:
        raise AssertionError("host ClientHello extension accounting drifted")
    body = (
        b"\x03\x03"
        + client_random
        + b"\x20"
        + session_id
        + fixed
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes) -> bytes:
    info = (
        (32).to_bytes(2, "big")
        + bytes((len(b"tls13 " + label),))
        + b"tls13 "
        + label
        + bytes((len(context),))
        + context
        + b"\x01"
    )
    return hmac_sha256(secret, info)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    import hmac

    return hmac.new(key, data, hashlib.sha256).digest()


def binder_oracle(psk: bytes, truncated_hash: bytes) -> bytes:
    early = hmac_sha256(bytes(32), psk)
    binder_key = hkdf_expand_label(
        early, b"res binder", hashlib.sha256(b"").digest()
    )
    finished_key = hkdf_expand_label(binder_key, b"finished", b"")
    return hmac_sha256(finished_key, truncated_hash)


def early_derived_oracle(psk: bytes) -> bytes:
    early = hmac_sha256(bytes(32), psk)
    return hkdf_expand_label(
        early, b"derived", hashlib.sha256(b"").digest()
    )


def ticks_to_ms(ticks: int) -> int:
    return ticks * 55 - ((ticks * 611) >> 13)


def resume_client_oracle(
    ek: bytes,
    client_x: bytes,
    identity: bytes,
    psk: bytes,
    age_add: bytes,
    elapsed_ticks: int,
    client_random: bytes,
    session_id: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    if len(age_add) != 4:
        raise ValueError("ticket age_add must be uint32 wire bytes")
    age = (
        int.from_bytes(age_add, "big") + ticks_to_ms(elapsed_ticks)
    ) & 0xFFFFFFFF
    base = client_oracle(
        ek,
        client_x,
        client_random,
        session_id,
    )
    base_handshake = base[5:]
    base_body = base_handshake[4:]
    fixed_prefix = base_body[: -(0x511 + 2)]
    base_extensions = base_body[-0x511:]
    psk_body = (
        (len(identity) + 6).to_bytes(2, "big")
        + len(identity).to_bytes(2, "big")
        + identity
        + age.to_bytes(4, "big")
    )
    psk_extension_without_binders = (
        b"\x00\x29"
        + (len(identity) + 43).to_bytes(2, "big")
        + psk_body
    )
    extensions_len = len(base_extensions) + len(identity) + 47
    body_len = len(fixed_prefix) + 2 + extensions_len
    truncated_handshake = (
        b"\x01"
        + body_len.to_bytes(3, "big")
        + fixed_prefix
        + extensions_len.to_bytes(2, "big")
        + base_extensions
        + psk_extension_without_binders
    )
    truncated_hash = hashlib.sha256(truncated_handshake).digest()
    binder = binder_oracle(psk, truncated_hash)
    handshake = (
        truncated_handshake
        + b"\x00\x21"
        + b"\x20"
        + binder
    )
    record = (
        b"\x16\x03\x01"
        + len(handshake).to_bytes(2, "big")
        + handshake
    )
    return record, truncated_hash, binder, age.to_bytes(4, "big")


def parse_client_extension_items(record: bytes) -> list[tuple[int, bytes]]:
    if record[:3] != b"\x16\x03\x01":
        raise AssertionError("ClientHello record header drifted")
    handshake = record[5:]
    if handshake[0] != 1 or int.from_bytes(handshake[1:4], "big") != len(handshake) - 4:
        raise AssertionError("ClientHello handshake length drifted")
    body = handshake[4:]
    position = 2 + 32
    session_len = body[position]
    position += 1 + session_len
    suites_len = int.from_bytes(body[position : position + 2], "big")
    position += 2 + suites_len
    compression_len = body[position]
    position += 1 + compression_len
    extensions_len = int.from_bytes(body[position : position + 2], "big")
    position += 2
    end = position + extensions_len
    result: list[tuple[int, bytes]] = []
    while position < end:
        kind = int.from_bytes(body[position : position + 2], "big")
        length = int.from_bytes(body[position + 2 : position + 4], "big")
        result.append(
            (kind, body[position + 4 : position + 4 + length])
        )
        position += 4 + length
    if position != end or end != len(body):
        raise AssertionError("ClientHello extension parser did not end exactly")
    return result


def parse_client_extensions(record: bytes) -> list[int]:
    return [kind for kind, _value in parse_client_extension_items(record)]


def server_oracle(
    order: str,
    *,
    resumed: bool = False,
    selected_identity: int = 0,
    ciphertext: bytes | None = None,
    server_x: bytes = SERVER_X,
    session_id: bytes = SESSION_ID,
) -> bytes:
    if ciphertext is None:
        ciphertext = SERVER_CIPHERTEXT
    versions = bytes.fromhex("002b00020304")
    key_share = (
        bytes.fromhex("0033046411ec0460") + ciphertext + server_x
    )
    psk = bytes.fromhex("00290002") + selected_identity.to_bytes(2, "big")
    if not resumed and order == "versions-first":
        extensions = versions + key_share
    elif not resumed and order == "keyshare-first":
        extensions = key_share + versions
    elif resumed and order == "versions-first":
        extensions = versions + key_share + psk
    elif resumed and order == "psk-first":
        extensions = psk + key_share + versions
    else:
        raise ValueError("unknown ServerHello extension order")
    body = (
        b"\x03\x03"
        + SERVER_RANDOM
        + b"\x20"
        + session_id
        + b"\x13\x03\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    if len(message) != (1216 if resumed else 1210):
        raise AssertionError("host ServerHello length drifted")
    return message


def collect_client(machine: Machine) -> tuple[bytes, list[int]]:
    fragments: list[bytes] = []
    lengths: list[int] = []
    while True:
        result, pointer, length = machine.call(1)
        if result == 0:
            if length:
                raise AssertionError("end-of-ClientHello returned a length")
            break
        if result != 1 or not length:
            raise AssertionError("ClientHello iterator returned invalid state")
        first = bytes(machine.uc.mem_read(pointer, length))
        repeated = machine.call(1)
        if repeated != (result, pointer, length):
            raise AssertionError("pending ClientHello fragment changed")
        if bytes(machine.uc.mem_read(pointer, length)) != first:
            raise AssertionError("pending ClientHello bytes changed")
        fragments.append(first)
        lengths.append(length)
        machine.call(2)
    return b"".join(fragments), lengths


def feed_server(machine: Machine, server: bytes) -> None:
    machine.call(4)
    position = 0
    sizes = (1, 383, 7, 251, 384, 109, 75)
    index = 0
    while position < len(server):
        take = min(sizes[index % len(sizes)], len(server) - position)
        chunk = server[position : position + take]
        machine.uc.mem_write(FEED_BUFFER, chunk)
        machine.call(5, si=FEED_BUFFER, cx=take)
        position += take
        index += 1
    machine.call(6)


def assert_begin(built: Built) -> bytes:
    machine = Machine(built)
    machine.call(0, bx=CRYPTO_SEG, si=FOOTER_OFF)
    expected_capsule = bytearray(built.abort_capsule)
    struct.pack_into(
        "<HH",
        expected_capsule,
        ABORT_CAPSULE_CRYPTO_SEG - ABORT_CAPSULE_LOAD,
        CRYPTO_SEG,
        CRYPTO_SEG ^ 0xFFFF,
    )
    if bytes(
        machine.uc.mem_read(ABORT_CAPSULE_LOAD, len(built.abort_capsule))
    ) != bytes(expected_capsule):
        raise AssertionError(
            "HELLO did not install the exact abort capsule/frozen geometry"
        )
    if machine.module_decodes != [MODULE_KIND_KEYGEN, MODULE_KIND_X25519]:
        raise AssertionError(
            f"module decode order drifted: {machine.module_decodes!r}"
        )
    if machine.module_calls != [MODULE_OP_KEYGEN, MODULE_OP_X25519_KEYGEN]:
        raise AssertionError(
            f"module call order drifted: {machine.module_calls!r}"
        )
    if any(
        pair != bytes((USED_INV, USED))
        for _address, _size, pair in machine.bundle_reads
    ):
        raise AssertionError("private acquisition bytes were read before USED")
    if [pair for _address, _size, pair in machine.status_writes[:3]] != [
        bytes((READY_INV, 0)),
        bytes((USED_INV, 0)),
        bytes((USED_INV, USED)),
    ]:
        raise AssertionError(
            f"status-last consume order drifted: {machine.status_writes!r}"
        )
    if any(machine.uc.mem_read(CRYPTO_BASE + ATTEMPT_OFF, ATTEMPT_BYTES)):
        raise AssertionError("consumed acquisition bundle was not wiped")
    if (
        bytes(machine.uc.mem_read(CRYPTO_BASE + FRESH_ATTEMPT_OFF, ATTEMPT_BYTES))
        != FRESH_BUNDLE
    ):
        raise AssertionError("acquisition changed independent fresh bundle")
    statuses = bytes(
        machine.uc.mem_read(CRYPTO_BASE + ROOT_STATUS_INV_OFF, 6)
    )
    if statuses != bytes(
        (READY_INV, READY, USED_INV, USED, READY_INV, READY)
    ):
        raise AssertionError("acquisition status ledger drifted")
    if bytes(machine.uc.mem_read(CRYPTO_BASE + DK_OFF, DK_BYTES)) != built.expected_dk:
        raise AssertionError("product ML-KEM keygen differs from independent KAT")
    expected_ek = built.expected_dk[1152 : 1152 + EK_BYTES]
    if bytes(machine.uc.mem_read(EK_OFF, EK_BYTES)) != expected_ek:
        raise AssertionError("product ML-KEM public key differs from KAT")
    expected_x = x25519_base(X_SCALAR)
    if any(machine.uc.mem_read(CLIENT_X_HANDOFF, 32)):
        raise AssertionError("raw X25519 handoff was not scrubbed")
    if any(machine.uc.mem_read(MODULE_BASE, MODULE_LIMIT - MODULE_BASE)):
        raise AssertionError("asymmetric module overlay remained executable")

    snapshot = machine.snapshot()
    branch = Machine(built, snapshot=snapshot)
    branch.uc.mem_write(EK_OFF, b"\xA6" * EK_BYTES)
    record, lengths = collect_client(branch)
    expected_record = client_oracle(expected_ek, expected_x)
    if record != expected_record:
        raise AssertionError("target ClientHello differs from host oracle")
    if lengths != [140, 384, 384, 384, 32, 57]:
        raise AssertionError(f"ClientHello fragmentation drifted: {lengths!r}")
    extension_types = parse_client_extensions(record)
    if extension_types != [0, 43, 10, 13, 51, 16, 50, 45]:
        raise AssertionError(
            f"ClientHello extension surface drifted: {extension_types!r}"
        )
    forbidden = {27, 41, 42}
    if forbidden.intersection(extension_types):
        raise AssertionError("286 acquisition exposed compression/PSK/0-RTT")

    branch.call(3)
    replay, replay_lengths = collect_client(branch)
    if replay != record or replay_lengths != lengths:
        raise AssertionError("whole-ClientHello replay changed bytes")
    server = server_oracle("versions-first")
    feed_server(branch, server)
    digest = hashlib.sha256(record[5:] + server).digest()
    if bytes(branch.uc.mem_read(DIGEST_OFF, 32)) != digest:
        raise AssertionError("HELLO transcript digest differs from host SHA-256")
    actual_ciphertext = bytes(
        branch.uc.mem_read(CIPHERTEXT_OFF, CIPHERTEXT_BYTES)
    )
    if actual_ciphertext != SERVER_CIPHERTEXT:
        mismatch = next(
            (
                index
                for index, (actual, expected) in enumerate(
                    zip(
                        actual_ciphertext,
                        SERVER_CIPHERTEXT,
                        strict=True,
                    )
                )
                if actual != expected
            ),
            -1,
        )
        raise AssertionError(
            f"ServerHello ciphertext handoff drifted at {mismatch}: "
            f"{actual_ciphertext[:16].hex()} != "
            f"{SERVER_CIPHERTEXT[:16].hex()}"
        )
    if bytes(branch.uc.mem_read(SERVER_X_OFF, 32)) != SERVER_X:
        raise AssertionError("ServerHello X25519 handoff drifted")
    if bytes(branch.uc.mem_read(CTX_MAGIC_OFF, 4)) != b"T13C":
        raise AssertionError("live transcript-context magic drifted")
    transcript_len = len(record) - 5 + len(server)
    if (
        branch.uc.mem_read(CTX_BLOCK_LEN_OFF, 1)[0] != transcript_len % 64
        or u16(bytes(branch.uc.mem_read(CTX_LEN_LOW_OFF, 2))) != transcript_len
        or u16(bytes(branch.uc.mem_read(CTX_LEN_HIGH_OFF, 2))) != 0
    ):
        raise AssertionError("live transcript-context length drifted")
    if branch.status_ready_event is None:
        raise AssertionError("HELLO status did not publish last")
    if branch.status_ready_event[-1] != 1:
        raise AssertionError("HELLO status-last snapshot is invalid")

    branch.call(9)
    if branch.module_decodes != [2, MODULE_KIND_X25519]:
        raise AssertionError(
            f"hybrid module decode order drifted: {branch.module_decodes!r}"
        )
    if branch.module_calls != [2, 4]:
        raise AssertionError(
            f"hybrid module call order drifted: {branch.module_calls!r}"
        )
    expected_hybrid = built.expected_secret + x25519(X_SCALAR, SERVER_X)
    actual_hybrid = bytes(
        branch.uc.mem_read(CRYPTO_BASE + HYBRID_SECRET_OFF, 64)
    )
    if actual_hybrid != expected_hybrid:
        raise AssertionError(
            "product hybrid secret differs from independent oracles"
        )
    if any(branch.uc.mem_read(CIPHERTEXT_OFF, CIPHERTEXT_BYTES + 32)):
        raise AssertionError(
            "HELLO retained peer key-share bytes after derivation"
        )
    if any(branch.uc.mem_read(MODULE_BASE, MODULE_LIMIT - MODULE_BASE)):
        raise AssertionError("hybrid derivation left module code executable")

    alternate = Machine(built, snapshot=snapshot)
    alternate_record, _ = collect_client(alternate)
    if alternate_record != record:
        raise AssertionError("snapshot ClientHello changed")
    alternate_server = server_oracle("keyshare-first")
    feed_server(alternate, alternate_server)
    alternate_digest = hashlib.sha256(
        record[5:] + alternate_server
    ).digest()
    if bytes(alternate.uc.mem_read(DIGEST_OFF, 32)) != alternate_digest:
        raise AssertionError("alternate ServerHello order digest drifted")

    malformed = Machine(built, snapshot=snapshot)
    collect_client(malformed)
    bad_server = bytearray(server)
    bad_server[77] = 0x1B
    malformed.call(4)
    malformed.uc.mem_write(FEED_BUFFER, bytes(bad_server))
    malformed.call(
        5,
        si=FEED_BUFFER,
        cx=min(384, len(bad_server)),
        expect_success=False,
    )
    if malformed.root_aborted:
        raise AssertionError("parser helper destroyed its live caller frame")
    malformed.call(8, expect_success=False)
    if not malformed.root_aborted:
        raise AssertionError("malformed ServerHello bypassed product abort")
    if any(malformed.uc.mem_read(CRYPTO_BASE, HIGH_BYTES)):
        raise AssertionError("fatal ServerHello left high private state live")
    return record


def assert_status_failure(built: Built) -> None:
    machine = Machine(built)
    machine.uc.mem_write(
        CRYPTO_BASE + ACQUIRE_STATUS_INV_OFF, bytes((READY_INV, 0))
    )
    machine.shadow[:] = machine.uc.mem_read(0, 1024 * 1024)
    machine.call(
        0,
        bx=CRYPTO_SEG,
        si=FOOTER_OFF,
        expect_success=False,
        instruction_limit=10_000_000,
    )
    if not machine.root_aborted:
        raise AssertionError("invalid acquisition status bypassed root abort")
    if machine.module_decodes or machine.module_calls:
        raise AssertionError("invalid acquisition status reached crypto module")
    if any(machine.uc.mem_read(CRYPTO_BASE, HIGH_BYTES)):
        raise AssertionError("invalid acquisition status left high state live")


def expected_symmetric_stage(built: Built) -> tuple[int, bytes]:
    phase_key = built.runtime["TLS13_286_LINK_SYM_PHASE_KEY"]
    source_sector = phase_key & 0xFF
    sector_count = built.runtime["TLS13_286_LINK_SYM_SECTORS"]
    if phase_key >> 8 != sector_count or sector_count != 12:
        raise AssertionError("symmetric source is no longer exactly twelve sectors")
    start = source_sector * 512
    payload = built.core[start : start + sector_count * 512]
    if (
        len(payload) != sector_count * 512
        or len(payload) != built.runtime["TLS13_286_LINK_SYM_IMAGE_BYTES"]
        or payload[:8] != b"T13SYM02"
    ):
        raise AssertionError("symmetric staging source geometry drifted")
    return source_sector, payload


def assert_symmetric_stage(machine: Machine, built: Built, label: str) -> None:
    source_sector, payload = expected_symmetric_stage(built)
    sector_count = built.runtime["TLS13_286_LINK_SYM_SECTORS"]
    canonical = K14_SYM.read_bytes()
    if len(canonical) != 12 * 512:
        raise AssertionError("canonical K14 symmetric image geometry drifted")
    normalized = bytearray(payload)
    normalized[0x16E0:] = canonical[0x16E0:]
    pointer_offset = built.runtime[
        "TLS13_286_LINK_SYM_PRODUCT_INITIAL_POINTER_OFF"
    ]
    struct.pack_into("<H", normalized, pointer_offset, 0x2EE0)
    if bytes(normalized) != canonical:
        raise AssertionError(
            f"{label} shipping symmetric image is not exactly normalizable"
        )
    expected_reads = [
        (
            CORE_START_LBA + source_sector + index,
            CRYPTO_SEG,
            SYM_STAGE_OFF + index * 512,
            b"\x00\x00",
        )
        for index in range(sector_count)
    ]
    if machine.sym_stage_reads != expected_reads:
        raise AssertionError(
            f"{label} symmetric pre-stage reads drifted: "
            f"{machine.sym_stage_reads!r}"
        )
    expected_ready = (
        canonical,
        sector_count,
        0,
        0,
        0,
        b"\xe0\x2e",
        canonical[0x16E0:0x1800],
    )
    if machine.sym_stage_ready_event != expected_ready:
        actual = machine.sym_stage_ready_event
        actual_summary = (
            None
            if actual is None
            else ("tuple-length", len(actual))
            if len(actual) != 7
            else (
                hashlib.sha256(actual[0]).hexdigest(),
                *actual[1:5],
                actual[5].hex(),
                hashlib.sha256(actual[6]).hexdigest(),
            )
        )
        expected_summary = (
            hashlib.sha256(expected_ready[0]).hexdigest(),
            *expected_ready[1:5],
            expected_ready[5].hex(),
            hashlib.sha256(expected_ready[6]).hexdigest(),
        )
        raise AssertionError(
            f"{label} symmetric stage and canonical SHA tail were not "
            "published after all reads and before crypto/NIC/TCP: "
            f"actual={actual_summary!r} expected={expected_summary!r}"
        )
    pairs = [
        pair for _address, _size, pair in machine.sym_stage_status_writes
    ]
    if pairs != [
        b"\x00\x00",
        b"\x5a\x00",
        b"\x5a\xa5",
    ]:
        raise AssertionError(
            f"{label} symmetric status-last order drifted: "
            f"{machine.sym_stage_status_writes!r}"
        )
    if bytes(
        machine.uc.mem_read(CRYPTO_BASE + SYM_STAGE_OFF, len(payload))
    ) != canonical:
        raise AssertionError(
            f"{label} symmetric stage differs from the proven canonical "
            "pre-TCP normalization"
        )
    if bytes(
        machine.uc.mem_read(CRYPTO_BASE + SYM_STAGE_STATUS_INV_OFF, 2)
    ) != b"\x5a\xa5":
        raise AssertionError(f"{label} symmetric stage is not READY")


def assert_symmetric_stage_read_failure(built: Built) -> None:
    machine = Machine(built, fail_sym_read_index=11)
    machine.call(
        0,
        bx=CRYPTO_SEG,
        si=FOOTER_OFF,
        expect_success=False,
        instruction_limit=1_200_000_000,
    )
    if not machine.root_aborted:
        raise AssertionError("failed final symmetric sector bypassed product abort")
    if machine.nic_enters or machine.tcp_connects or machine.sent_payloads:
        raise AssertionError(
            "failed symmetric pre-stage opened the NIC/TCP transport"
        )
    if len(machine.sym_stage_reads) != 12:
        raise AssertionError("failed final symmetric sector read count drifted")
    if machine.sym_stage_ready_event is not None:
        raise AssertionError("failed symmetric pre-stage published READY")
    if any(machine.uc.mem_read(CRYPTO_BASE, HIGH_BYTES)):
        raise AssertionError("failed symmetric pre-stage left high state live")


def assert_flight_stage(machine: Machine, built: Built, label: str) -> None:
    sectors = len(built.flight_component) // 512
    if len(machine.flight_stage_reads) != sectors:
        raise AssertionError(f"{label} FLIGHT pre-stage read count drifted")
    if machine.flight_stage_ready_event != (
        built.flight_component,
        sectors,
        0,
        0,
        0,
    ):
        raise AssertionError(
            f"{label} FLIGHT was not fully staged before crypto/NIC/TCP"
        )
    pairs = [
        pair for _address, _size, pair in machine.flight_stage_status_writes
    ]
    if pairs[:3] != [b"\x00\x00", b"\x5a\x00", b"\x5a\xa5"]:
        raise AssertionError(
            f"{label} FLIGHT status-last publication drifted: {pairs!r}"
        )
    if pairs[-1:] != [b"\x00\x00"]:
        raise AssertionError(
            f"{label} FLIGHT stage status was not consumed first"
        )
    if machine.flight_decode_event != (
        built.flight,
        built.flight_component
        + bytes(FLIGHT_STAGE_BYTES - len(built.flight_component)),
    ):
        raise AssertionError(
            f"{label} did not decode exact FLIGHT from its staged copy"
        )


def assert_flight_stage_read_failure(built: Built) -> None:
    sectors = len(built.flight_component) // 512
    machine = Machine(built, fail_flight_read_index=sectors - 1)
    machine.call(
        0,
        bx=CRYPTO_SEG,
        si=FOOTER_OFF,
        expect_success=False,
        instruction_limit=1_200_000_000,
    )
    if not machine.root_aborted:
        raise AssertionError("failed final FLIGHT sector bypassed product abort")
    if machine.nic_enters or machine.tcp_connects or machine.sent_payloads:
        raise AssertionError("failed FLIGHT pre-stage opened NIC/TCP transport")
    if len(machine.flight_stage_reads) != sectors:
        raise AssertionError("failed FLIGHT pre-stage read count drifted")
    if machine.flight_stage_ready_event is not None:
        raise AssertionError("failed FLIGHT pre-stage published READY")
    if any(machine.uc.mem_read(CRYPTO_BASE, HIGH_BYTES)):
        raise AssertionError("failed FLIGHT pre-stage left high state live")


def assert_no_resumption_early_cache(
    machine: Machine, label: str
) -> None:
    status_pairs = [
        pair for _address, _size, pair in machine.early_status_writes
    ]
    if (
        machine.early_ready_event is not None
        or any(
            status != b"\x00\x00"
            for status in machine.early_data_write_statuses
        )
        or status_pairs != [b"\x00\x00"]
        or bytes(
            machine.uc.mem_read(
                CRYPTO_BASE + RESUMPTION_EARLY_STATUS_INV_OFF, 2
            )
        )
        != b"\x00\x00"
    ):
        raise AssertionError(
            f"{label} left stale early-derived READY live"
        )


def assert_resumption_early_cache(
    machine: Machine, label: str
) -> None:
    expected = early_derived_oracle(TICKET_PSK)
    expected_inverse = bytes(byte ^ 0xFF for byte in expected)
    expected_event = (
        expected,
        expected_inverse,
        bytes((TICKET_USED_INV, TICKET_USED)),
        3,
        0,
        0,
    )
    if machine.early_ready_event != expected_event:
        raise AssertionError(
            f"{label} early-derived cache was not published after "
            "independent keygen and before NIC/TCP"
        )
    if (
        not machine.early_data_write_statuses
        or any(
            status != b"\x00\x00"
            for status in machine.early_data_write_statuses
        )
    ):
        raise AssertionError(
            f"{label} wrote early-derived bytes while cache was replayable"
        )
    pairs = [
        pair for _address, _size, pair in machine.early_status_writes
    ]
    if pairs != [
        b"\x00\x00",
        b"\x00\x00",
        b"\x5a\x00",
        b"\x5a\xa5",
    ]:
        raise AssertionError(
            f"{label} early-derived status-last order drifted: "
            f"{machine.early_status_writes!r}"
        )
    start = CRYPTO_BASE + RESUMPTION_EARLY_OFF
    inverse = CRYPTO_BASE + RESUMPTION_EARLY_INVERSE_OFF
    status = CRYPTO_BASE + RESUMPTION_EARLY_STATUS_INV_OFF
    if (
        bytes(machine.uc.mem_read(start, RESUMPTION_EARLY_BYTES))
        != expected
        or bytes(
            machine.uc.mem_read(inverse, RESUMPTION_EARLY_BYTES)
        )
        != expected_inverse
        or bytes(machine.uc.mem_read(status, 2)) != b"\x5a\xa5"
    ):
        raise AssertionError(
            f"{label} retained early-derived cache differs from oracle"
        )


def canonical_span(physical: int, length: int) -> bytes:
    if (
        physical < 0
        or physical + length > 1024 * 1024
        or length < 0
    ):
        raise ValueError("descriptor span escaped conventional memory")
    return struct.pack(
        "<HHI",
        physical & 15,
        physical >> 4,
        length,
    )


def expected_module_descriptor(
    operation: int, spans: dict[int, bytes]
) -> bytes:
    descriptor = bytearray(DESC_BYTES)
    struct.pack_into("<H", descriptor, DESC_OP, operation)
    for offset, span in spans.items():
        if offset not in (
            DESC_INPUT0,
            DESC_INPUT1,
            DESC_INPUT2,
            DESC_INPUT3,
            DESC_OUTPUT0,
            DESC_OUTPUT1,
        ):
            raise ValueError("invalid descriptor span offset")
        if len(span) != SPAN_BYTES:
            raise ValueError("descriptor span has wrong encoded length")
        descriptor[offset : offset + SPAN_BYTES] = span
    return bytes(descriptor)


def assert_exact_module_descriptor(
    machine: Machine,
    operation: int,
    expected: bytes,
    label: str,
) -> None:
    matches = [
        descriptor
        for actual_operation, descriptor in machine.module_descriptors
        if actual_operation == operation
    ]
    if matches != [expected]:
        raise AssertionError(
            f"{label} descriptor geometry drifted: {matches!r}"
        )


def assert_no_matrix_cache(machine: Machine, label: str) -> None:
    status_pairs = [
        pair for _address, _size, pair in machine.matrix_status_writes
    ]
    if (
        machine.matrix_ready_event is not None
        or machine.matrix_data_write_statuses
        or machine.matrix_data_read_statuses
        or machine.matrix_write_coverage
        or machine.matrix_read_coverage
        or MODULE_OP_MLKEM_MATRIX_PRECOMPUTE in machine.module_calls
        or MODULE_OP_MLKEM_DECAP_CACHED in machine.module_calls
        or status_pairs != [b"\x00\x00"]
        or bytes(
            machine.uc.mem_read(
                CRYPTO_BASE + MLKEM_MATRIX_STATUS_INV_OFF, 2
            )
        )
        != b"\x00\x00"
    ):
        raise AssertionError(
            f"{label} published or consumed a resumption-only matrix cache"
        )


def assert_matrix_cache_lifecycle(
    machine: Machine, built: Built, label: str
) -> None:
    expected = matrix_cache_oracle(
        KEYGEN_ORACLE.fips_keygen_internal(FRESH_BUNDLE[:64])
    )
    expected_ready = (
        expected,
        MLKEM_MATRIX_STAGE_BYTES,
        3,
        0,
        0,
    )
    if machine.matrix_ready_event != expected_ready:
        raise AssertionError(
            f"{label} matrix was not published completely before NIC/TCP"
        )
    if machine.cache_publication_events != [
        "matrix-ready",
        "ticket-age-tick",
        "early-ready",
    ]:
        raise AssertionError(
            f"{label} matrix/ticket-age/early publication order drifted: "
            f"{machine.cache_publication_events!r}"
        )
    if (
        not machine.matrix_data_write_statuses
        or any(
            status != b"\x00\x00"
            for status in machine.matrix_data_write_statuses
        )
        or machine.matrix_write_coverage
        != set(range(MLKEM_MATRIX_STAGE_BYTES))
    ):
        raise AssertionError(
            f"{label} matrix writes escaped the invalid-status window"
        )
    status_pairs = [
        pair for _address, _size, pair in machine.matrix_status_writes
    ]
    if status_pairs != [
        b"\x00\x00",
        b"\x00\x00",
        b"\x5a\x00",
        b"\x5a\xa5",
        b"\x00\x00",
    ]:
        raise AssertionError(
            f"{label} matrix status-last/consume order drifted: "
            f"{machine.matrix_status_writes!r}"
        )
    if machine.matrix_cached_decap_event != (b"\x00\x00", 1, 1, 0):
        raise AssertionError(
            f"{label} cached decap did not follow one-shot status consume"
        )
    if (
        not machine.matrix_data_read_statuses
        or any(
            status != b"\x00\x00"
            for status in machine.matrix_data_read_statuses
        )
        or machine.matrix_read_coverage
        != set(range(MLKEM_MATRIX_STAGE_BYTES))
    ):
        raise AssertionError(
            f"{label} did not consume every cache byte after status clear"
        )
    if bytes(
        machine.uc.mem_read(
            CRYPTO_BASE + MLKEM_MATRIX_STAGE_OFF,
            MLKEM_MATRIX_STAGE_BYTES,
        )
    ) != expected:
        raise AssertionError(f"{label} matrix cache differs from oracle")
    if bytes(
        machine.uc.mem_read(
            CRYPTO_BASE + MLKEM_MATRIX_STATUS_INV_OFF, 2
        )
    ) != b"\x00\x00":
        raise AssertionError(f"{label} left a replayable matrix status")

    assert_exact_module_descriptor(
        machine,
        MODULE_OP_MLKEM_MATRIX_PRECOMPUTE,
        expected_module_descriptor(
            MODULE_OP_MLKEM_MATRIX_PRECOMPUTE,
            {
                DESC_INPUT0: (
                    canonical_span(
                        CRYPTO_BASE + DK_OFF,
                        DK_BYTES,
                    )
                ),
                DESC_OUTPUT0: (
                    canonical_span(
                        CRYPTO_BASE + MLKEM_MATRIX_STAGE_OFF,
                        MLKEM_MATRIX_STAGE_BYTES,
                    )
                ),
            },
        ),
        f"{label} op9",
    )
    assert_exact_module_descriptor(
        machine,
        MODULE_OP_MLKEM_DECAP_CACHED,
        expected_module_descriptor(
            MODULE_OP_MLKEM_DECAP_CACHED,
            {
                DESC_INPUT0: (
                    canonical_span(
                        CRYPTO_BASE + DK_OFF,
                        DK_BYTES,
                    )
                ),
                DESC_INPUT1: (
                    canonical_span(
                        CIPHERTEXT_OFF,
                        CIPHERTEXT_BYTES,
                    )
                ),
                DESC_INPUT2: (
                    canonical_span(
                        CRYPTO_BASE + MLKEM_MATRIX_STAGE_OFF,
                        MLKEM_MATRIX_STAGE_BYTES,
                    )
                ),
                DESC_OUTPUT0: (
                    canonical_span(
                        CRYPTO_BASE + HYBRID_SECRET_OFF,
                        32,
                    )
                ),
            },
        ),
        f"{label} op10",
    )


def assert_live_transport(built: Built) -> bytes:
    server = server_oracle("versions-first")
    protected_suffix = bytes.fromhex(
        "1703030029"
        "5d6a04226ae7f31e36b8820a96620d4e"
        "93f0d4daaa8b6daf17d189a97f5d3e12"
        "67a9c504"
    )
    wire = (
        b"\x16\x03\x03"
        + len(server).to_bytes(2, "big")
        + server
        + protected_suffix
    )
    sizes = (1, 2, 380, 384, 384, len(wire) - 1151)
    if sum(sizes) != len(wire) or sizes[-1] <= len(protected_suffix):
        raise AssertionError("live hostile TCP segmentation drifted")
    payloads: list[bytes] = []
    position = 0
    for size in sizes:
        payloads.append(wire[position : position + size])
        position += size

    machine = Machine(built, network_payloads=payloads)
    machine.install_stale_ready_caches()
    result, _si, _cx = machine.call(
        0,
        bx=CRYPTO_SEG,
        si=FOOTER_OFF,
        instruction_limit=1_200_000_000,
    )
    if result != TAIL_KIND_FLIGHT or machine.chain_kinds != [
        TAIL_KIND_FLIGHT
    ]:
        raise AssertionError(
            "live HELLO did not chain exactly once to protected flight"
        )
    runtime = built.runtime
    expected_load = (
        runtime["TLS13_286_LINK_TCP_CONNECT_PHASE_KEY"],
        runtime["TLS13_286_LINK_TCP_CONNECT_DESTINATION"],
    )
    if machine.phase_loads != [expected_load] or machine.tcp_connects != 1:
        raise AssertionError(
            "live HELLO did not use the generated connect geometry exactly"
        )
    if machine.nic_enters != 1 or machine.nic_restores:
        raise AssertionError("live HELLO NIC lease handoff drifted")
    if machine.transport_events[:4] != [
        f"module-{MODULE_OP_KEYGEN}",
        f"module-{MODULE_OP_X25519_KEYGEN}",
        "nic-enter",
        "tcp-connect",
    ]:
        raise AssertionError(
            "live HELLO opened the timed transport before key generation: "
            f"{machine.transport_events[:4]!r}"
        )
    if machine.tcp_acks != len(payloads) or machine.network_payloads:
        raise AssertionError("live HELLO TCP receive/ACK accounting drifted")
    expected_ek = built.expected_dk[1152 : 1152 + EK_BYTES]
    expected_record = client_oracle(expected_ek, x25519_base(X_SCALAR))
    if len(machine.phase_load_snapshots) != 1:
        raise AssertionError("live HELLO did not materialize one connect phase")
    phase_key, destination = expected_load
    phase_sector = phase_key & 0xFF
    phase_sectors = phase_key >> 8
    phase_image = built.core[
        phase_sector * 512 : (phase_sector + phase_sectors) * 512
    ]
    overwrite_at = destination - EK_OFF
    if not 0 < overwrite_at < EK_BYTES:
        raise AssertionError("connect phase no longer overlaps low public key")
    expected_low_ek = (
        expected_ek[:overwrite_at]
        + phase_image[: EK_BYTES - overwrite_at]
    )
    low_after_load, high_after_load = machine.phase_load_snapshots[0]
    if low_after_load != expected_low_ek:
        raise AssertionError("connect phase overwrite fixture drifted")
    if high_after_load != expected_ek:
        raise AssertionError("connect phase damaged embedded high ML-KEM key")
    if b"".join(machine.sent_payloads) != expected_record:
        raise AssertionError("live TCP sends differ from exact ClientHello")
    if [len(item) for item in machine.sent_payloads] != [
        140,
        384,
        384,
        384,
        32,
        57,
    ]:
        raise AssertionError("live TCP ClientHello fragmentation drifted")

    expected_hybrid = built.expected_secret + x25519(X_SCALAR, SERVER_X)
    actual_hybrid = bytes(
        machine.uc.mem_read(CRYPTO_BASE + HYBRID_SECRET_OFF, 64)
    )
    if actual_hybrid != expected_hybrid:
        raise AssertionError("live HELLO hybrid secret drifted")
    if machine.module_calls != [
        MODULE_OP_KEYGEN,
        MODULE_OP_X25519_KEYGEN,
        MODULE_OP_MLKEM_CANDIDATE,
        MODULE_OP_X25519_SHARED,
    ]:
        raise AssertionError(
            f"acquisition did not use candidate-first split: "
            f"{machine.module_calls!r}"
        )
    candidate = bytes(
        machine.uc.mem_read(
            CRYPTO_BASE + CANDIDATE_CIPHERTEXT_OFF,
            CIPHERTEXT_BYTES + 32,
        )
    )
    if candidate != SERVER_CIPHERTEXT + built.expected_secret:
        raise AssertionError("candidate c/K' escrow differs from exact oracle")
    if bytes(
        machine.uc.mem_read(
            CRYPTO_BASE + CANDIDATE_STATUS_INV_OFF, 2
        )
    ) != bytes((CANDIDATE_VALID_INV, CANDIDATE_VALID)):
        raise AssertionError("candidate escrow was not published status-last")
    if u16(
        bytes(
            machine.uc.mem_read(
                CRYPTO_BASE + PENDING_WIRE_LEN_OFF, 2
            )
        )
    ) != len(protected_suffix):
        raise AssertionError("coalesced protected suffix length drifted")
    if (
        bytes(
            machine.uc.mem_read(
                CRYPTO_BASE + PENDING_WIRE_OFF, len(protected_suffix)
            )
        )
        != protected_suffix
    ):
        raise AssertionError("coalesced protected suffix bytes drifted")
    if bytes(
        machine.uc.mem_read(
            CRYPTO_BASE + PENDING_WIRE_STATUS_INV_OFF, 2
        )
    ) != bytes((0x5A, 0xA5)):
        raise AssertionError("coalesced protected suffix was not published")
    if not machine.pending_status_writes or machine.pending_status_writes[-1][2] != bytes(
        (0x5A, 0xA5)
    ):
        raise AssertionError("coalesced protected suffix status was not last")

    assert_symmetric_stage(machine, built, "acquisition")
    assert_flight_stage(machine, built, "acquisition")
    assert_no_resumption_early_cache(machine, "acquisition")
    assert_no_matrix_cache(machine, "acquisition")
    assert_live_resumption(
        built,
        machine,
        overwrite_at=overwrite_at,
        phase_image=phase_image,
    )
    return expected_record


def segmented_server_wire(server: bytes) -> list[bytes]:
    protected_suffix = bytes.fromhex(
        "1703030029"
        "5d6a04226ae7f31e36b8820a96620d4e"
        "93f0d4daaa8b6daf17d189a97f5d3e12"
        "67a9c504"
    )
    wire = (
        b"\x16\x03\x03"
        + len(server).to_bytes(2, "big")
        + server
        + protected_suffix
    )
    sizes = (1, 2, 380, 384, 384)
    payloads: list[bytes] = []
    position = 0
    for size in sizes:
        payloads.append(wire[position : position + size])
        position += size
    while position < len(wire):
        take = min(384, len(wire) - position)
        payloads.append(wire[position : position + take])
        position += take
    if b"".join(payloads) != wire:
        raise AssertionError("resume hostile TCP segmentation drifted")
    return payloads


def assert_psk_extension(
    record: bytes,
    *,
    identity: bytes,
    age: bytes,
    binder: bytes,
) -> None:
    items = parse_client_extension_items(record)
    kinds = [kind for kind, _value in items]
    if kinds != [0, 43, 10, 13, 51, 16, 50, 45, 41]:
        raise AssertionError(
            f"resumed ClientHello extension surface drifted: {kinds!r}"
        )
    if items[-2][1] != b"\x01\x01":
        raise AssertionError("resumed ClientHello did not select psk_dhe_ke")
    if 42 in kinds or kinds[-1] != 41:
        raise AssertionError("resumed ClientHello offered 0-RTT/non-final PSK")
    value = items[-1][1]
    identities_len = int.from_bytes(value[:2], "big")
    identity_len = int.from_bytes(value[2:4], "big")
    identity_end = 4 + identity_len
    if (
        identities_len != identity_len + 6
        or value[4:identity_end] != identity
        or value[identity_end : identity_end + 4] != age
    ):
        raise AssertionError("resumed PSK identity/age vector drifted")
    position = identity_end + 4
    if (
        value[position : position + 2] != b"\x00\x21"
        or value[position + 2 : position + 3] != b"\x20"
        or value[position + 3 :] != binder
    ):
        raise AssertionError("resumed PSK binder vector drifted")


def assert_resumed_client_hello(
    machine: Machine,
    expected_record: bytes,
) -> None:
    client_lengths = [
        140,
        384,
        384,
        384,
        32,
        104 + len(TICKET_IDENTITY),
    ]
    actual_record = b"".join(machine.sent_payloads)
    if actual_record != expected_record:
        mismatch = next(
            (
                index
                for index, (actual, expected) in enumerate(
                    zip(actual_record, expected_record, strict=False)
                )
                if actual != expected
            ),
            min(len(actual_record), len(expected_record)),
        )
        raise AssertionError(
            f"resumed ClientHello differs from host oracle at {mismatch}: "
            f"{actual_record[mismatch:mismatch + 40].hex()} != "
            f"{expected_record[mismatch:mismatch + 40].hex()}"
        )
    if [len(item) for item in machine.sent_payloads] != client_lengths:
        raise AssertionError("resumed ClientHello fragmentation drifted")


def run_live_resume(
    built: Built,
    snapshot: bytes,
    *,
    order: str,
    selected_identity: int = 0,
    matrix_status_before_transport: bytes | None = None,
    matrix_payload_flip_index: int | None = None,
    expect_success: bool,
) -> tuple[Machine, bytes, bytes, bytes, bytes, bytes]:
    fresh_dk = KEYGEN_ORACLE.fips_keygen_internal(FRESH_BUNDLE[:64])
    fresh_ek = fresh_dk[1152 : 1152 + EK_BYTES]
    resume_ciphertext, resume_secret = mlkem_encapsulate(
        fresh_ek, bytes(range(32))
    )
    server = server_oracle(
        order,
        resumed=True,
        selected_identity=selected_identity,
        ciphertext=resume_ciphertext,
        session_id=FRESH_BUNDLE[128:160],
    )
    machine = Machine(
        built,
        snapshot=snapshot,
        network_payloads=segmented_server_wire(server),
        bios_ticks=TICKET_CURRENT_TICKS,
        matrix_status_before_transport=matrix_status_before_transport,
        matrix_payload_flip_index=matrix_payload_flip_index,
    )
    machine.install_promoted_ticket()
    machine.install_stale_ready_caches()
    try:
        machine.call(
            1,
            bx=CRYPTO_SEG,
            si=FOOTER_OFF,
            expect_success=expect_success,
            instruction_limit=1_600_000_000,
        )
    except AssertionError as error:
        raise AssertionError(
            f"{error}; modules={machine.module_calls!r} "
            f"events={machine.transport_events!r} "
            f"sent_lengths={[len(item) for item in machine.sent_payloads]!r} "
            f"acks={machine.tcp_acks} payloads_left={len(machine.network_payloads)} "
            f"ticket_writes={machine.ticket_status_writes!r} "
            f"tick_reads={machine.bios_tick_reads} "
            f"aborted={machine.root_aborted}"
        ) from error
    expected_record, truncated_hash, binder, age = resume_client_oracle(
        fresh_ek,
        x25519_base(FRESH_BUNDLE[64:96]),
        TICKET_IDENTITY,
        TICKET_PSK,
        TICKET_AGE_ADD,
        TICKET_CURRENT_TICKS - TICKET_RECEIPT_TICKS,
        FRESH_BUNDLE[96:128],
        FRESH_BUNDLE[128:160],
    )
    return (
        machine,
        expected_record,
        truncated_hash,
        binder,
        age,
        resume_secret,
    )


def assert_corrupt_matrix_fo_finished_boundary(
    built: Built,
    snapshot: bytes,
) -> None:
    """Bind a published-cache fault through FO and the protected flight."""

    flip_index = 0
    (
        machine,
        expected_record,
        truncated_hash,
        binder,
        _age,
        resume_secret,
    ) = run_live_resume(
        built,
        snapshot,
        order="versions-first",
        matrix_payload_flip_index=flip_index,
        expect_success=True,
    )
    fresh_dk = KEYGEN_ORACLE.fips_keygen_internal(FRESH_BUNDLE[:64])
    fresh_ek = fresh_dk[1152 : 1152 + EK_BYTES]
    resume_ciphertext, repeated_secret = mlkem_encapsulate(
        fresh_ek, bytes(range(32))
    )
    if repeated_secret != resume_secret:
        raise AssertionError("matrix hostility changed the host ML-KEM oracle")
    expected_matrix = matrix_cache_oracle(fresh_dk)
    expected_injection = (
        flip_index,
        expected_matrix[flip_index],
        expected_matrix[flip_index] ^ 1,
        bytes((READY_INV, READY)),
        3,
        0,
        0,
    )
    if machine.matrix_payload_injection_event != expected_injection:
        raise AssertionError(
            "matrix payload corruption did not follow exact READY publication: "
            f"{machine.matrix_payload_injection_event!r}"
        )
    if machine.matrix_ready_event != (
        expected_matrix,
        MLKEM_MATRIX_STAGE_BYTES,
        3,
        0,
        0,
    ):
        raise AssertionError(
            "matrix payload corruption preceded complete cache publication"
        )
    if (
        machine.root_aborted
        or machine.module_calls
        != [
            MODULE_OP_KEYGEN,
            MODULE_OP_X25519_KEYGEN,
            MODULE_OP_MLKEM_MATRIX_PRECOMPUTE,
            MODULE_OP_MLKEM_DECAP_CACHED,
            MODULE_OP_X25519_SHARED,
        ]
        or machine.matrix_cached_decap_event
        != (b"\x00\x00", 1, 1, 0)
        or machine.matrix_read_coverage
        != set(range(MLKEM_MATRIX_STAGE_BYTES))
        or not machine.matrix_data_read_statuses
        or any(
            status != b"\x00\x00"
            for status in machine.matrix_data_read_statuses
        )
        or machine.chain_kinds != [TAIL_KIND_FLIGHT]
    ):
        raise AssertionError(
            "matrix payload corruption escaped cached full-FO lifecycle"
        )
    corrupted_matrix = bytearray(expected_matrix)
    corrupted_matrix[flip_index] ^= 1
    if bytes(
        machine.uc.mem_read(
            CRYPTO_BASE + MLKEM_MATRIX_STAGE_OFF,
            MLKEM_MATRIX_STAGE_BYTES,
        )
    ) != bytes(corrupted_matrix):
        raise AssertionError("cached FO did not consume the exact corrupted matrix")
    rejection_secret = hashlib.shake_256(
        fresh_dk[2368:2400] + resume_ciphertext
    ).digest(32)
    if rejection_secret == resume_secret:
        raise AssertionError("FO rejection oracle equals the accepted secret")
    x_shared = x25519(FRESH_BUNDLE[64:96], SERVER_X)
    accepted_hybrid = resume_secret + x_shared
    rejected_hybrid = rejection_secret + x_shared
    if (
        machine.chain_hybrid_event != rejected_hybrid
        or bytes(
            machine.uc.mem_read(
                CRYPTO_BASE + HYBRID_SECRET_OFF,
                len(rejected_hybrid),
            )
        )
        != rejected_hybrid
    ):
        raise AssertionError(
            "corrupted cached decapsulation did not select exact FO rejection J"
        )

    server = server_oracle(
        "versions-first",
        resumed=True,
        ciphertext=resume_ciphertext,
        session_id=FRESH_BUNDLE[128:160],
    )
    resume_hello = expected_record[5:] + server
    flight_checker = load_flight_checker()
    expected_handoff = bytearray(
        flight_checker.CHECK.build_hello_handoff(
            resume_hello,
            SERVER_X,
        )
    )
    # HELLO retires the already-consumed peer share before chaining.  Flight
    # imports the transcript context beginning at the following digest field.
    expected_handoff[:32] = bytes(32)
    expected_handoff = bytes(expected_handoff)
    actual_handoff = machine.chain_handoff_event or b""
    normalized_handoff = bytearray(actual_handoff)
    block_len_index = CTX_BLOCK_LEN_OFF - SERVER_X_OFF
    block_index = CTX_BLOCK_OFF - SERVER_X_OFF
    status_index = STATUS_OFF - SERVER_X_OFF
    if len(normalized_handoff) != len(expected_handoff):
        raise AssertionError("matrix-hostile HELLO handoff geometry drifted")
    block_len = normalized_handoff[block_len_index]
    if block_len > 64:
        raise AssertionError("matrix-hostile HELLO exported an invalid SHA block")
    # The fixed handoff copies all 64 SHA work bytes, but only block_len bytes
    # are live transcript context.  Its unused public tail may retain bytes
    # from the preceding compressed block and is deliberately ignored by the
    # Flight importer.
    normalized_handoff[
        block_index + block_len : status_index
    ] = bytes(64 - block_len)
    if bytes(normalized_handoff) != expected_handoff:
        mismatch = next(
            (
                index
                for index, (actual, expected) in enumerate(
                    zip(normalized_handoff, expected_handoff, strict=False)
                )
                if actual != expected
            ),
            min(len(normalized_handoff), len(expected_handoff)),
        )
        raise AssertionError(
            "matrix-hostile HELLO did not hand the exact transcript to flight "
            f"at {mismatch}: "
            f"{normalized_handoff[mismatch:mismatch + 32].hex()} != "
            f"{expected_handoff[mismatch:mismatch + 32].hex()}"
        )

    early_derived = early_derived_oracle(TICKET_PSK)
    accepted_schedule = flight_checker.BASE.hkdf_extract(
        early_derived,
        accepted_hybrid,
    )
    rejected_schedule = flight_checker.BASE.hkdf_extract(
        early_derived,
        rejected_hybrid,
    )
    accepted_traffic = flight_checker.CHECK.derive_traffic(
        accepted_schedule,
        resume_hello,
    )
    rejected_traffic = flight_checker.CHECK.derive_traffic(
        rejected_schedule,
        resume_hello,
    )
    encrypted_extensions = flight_checker.hs(8, flight_checker.H2_EE)
    finished_hash = hashlib.sha256(
        resume_hello + encrypted_extensions
    ).digest()
    accepted_verify = hmac.new(
        accepted_traffic["server_finished"],
        finished_hash,
        hashlib.sha256,
    ).digest()
    rejected_verify = hmac.new(
        rejected_traffic["server_finished"],
        finished_hash,
        hashlib.sha256,
    ).digest()
    if accepted_verify == rejected_verify:
        raise AssertionError(
            "accepted and rejected Finished oracles unexpectedly coincide"
        )
    finished_plaintext = encrypted_extensions + flight_checker.hs(
        20,
        accepted_verify,
    )
    # Encrypt under the client's exact rejection schedule so record AEAD
    # succeeds.  The target must then reach and reject the genuine server's
    # accepted-secret Finished value, rather than failing earlier at the tag.
    finished_record = flight_checker.BASE.encrypted_record(
        rejected_traffic["server_key"],
        rejected_traffic["server_iv"],
        0,
        flight_checker.ORACLE.CONTENT_HANDSHAKE,
        finished_plaintext,
        padding_len=5,
    )
    flight_fixture = {
        "resume_handoff": actual_handoff,
        "hybrid": rejected_hybrid,
        "ticket_psk": TICKET_PSK,
        "ticket_identity": TICKET_IDENTITY,
        "ticket_nonce": TICKET_NONCE,
        "ticket_age_add": int.from_bytes(TICKET_AGE_ADD, "big"),
        "binder_hash": truncated_hash,
        "binder": binder,
        "early_derived": early_derived,
        "resume_records": [finished_record],
    }
    flight = flight_checker.FlightMachine(
        flight_fixture,
        resumed=True,
        wire_records=[finished_record],
    )
    boundary_hits = {"finished": 0, "application": 0}

    def observe_auth_boundary(
        _machine: Uc,
        address: int,
        _size: int,
        _user: object,
    ) -> None:
        if (
            address
            == flight_checker.SYMS[
                "TLS13_286_FLIGHT_SYM_VERIFY_SERVER_FINISHED"
            ]
        ):
            boundary_hits["finished"] += 1
        elif (
            address
            == flight_checker.SYMS[
                "TLS13_286_FLIGHT_SYM_DERIVE_APPLICATION"
            ]
        ):
            boundary_hits["application"] += 1

    flight.machine.hook_add(UC_HOOK_CODE, observe_auth_boundary)
    flight.run()
    if boundary_hits != {"finished": 1, "application": 0}:
        raise AssertionError(
            "matrix-hostile flight did not fail exactly at server Finished: "
            f"{boundary_hits!r}"
        )
    if flight.sent:
        raise AssertionError(
            "matrix-hostile flight sent client Finished/application data"
        )
    flight_checker.assert_staged_symmetric_consumed(
        flight,
        "matrix-hostile resumed flight",
    )
    flight_checker.assert_early_cache_consumed(
        flight,
        early_derived,
        "matrix-hostile resumed flight",
    )
    flight_checker.assert_abort_boundary(
        flight,
        "matrix-hostile server Finished",
    )


def assert_live_resumption(
    built: Built,
    acquisition: Machine,
    *,
    overwrite_at: int,
    phase_image: bytes,
) -> None:
    snapshot = acquisition.snapshot()
    pack_before = snapshot[CRYPTO_BASE : CRYPTO_BASE + PACK_BYTES]
    (
        machine,
        expected_record,
        truncated_hash,
        binder,
        age,
        resume_secret,
    ) = run_live_resume(
        built,
        snapshot,
        order="versions-first",
        expect_success=True,
    )
    if machine.root_aborted:
        raise AssertionError("valid promoted ticket reached product abort")
    assert_symmetric_stage(machine, built, "resumption")
    assert_flight_stage(machine, built, "resumption")
    assert_resumption_early_cache(machine, "resumption")
    assert_matrix_cache_lifecycle(machine, built, "resumption")
    if machine.bios_tick_reads != 1:
        raise AssertionError("resumption did not take one coherent tick sample")
    if machine.chain_kinds != [TAIL_KIND_FLIGHT]:
        raise AssertionError("resumption did not chain once to resumed flight")
    if [
        pair for _address, _size, pair in machine.ticket_status_writes[:3]
    ] != [
        bytes((TICKET_PROMOTED_INV, 0)),
        bytes((TICKET_USED_INV, 0)),
        bytes((TICKET_USED_INV, TICKET_USED)),
    ]:
        raise AssertionError(
            "ticket status-last consume order drifted: "
            f"{machine.ticket_status_writes!r}"
        )
    if not machine.ticket_private_reads or any(
        status != bytes((TICKET_USED_INV, TICKET_USED))
        for _address, _size, status in machine.ticket_private_reads
    ):
        raise AssertionError("ticket private bytes were read before USED")
    if bytes(
        machine.uc.mem_read(
            CRYPTO_BASE + TICKET_STATUS_INV_OFF, 2
        )
    ) != bytes((TICKET_USED_INV, TICKET_USED)):
        raise AssertionError("resumption ticket ledger did not remain USED")
    if machine.module_calls != [
        MODULE_OP_KEYGEN,
        MODULE_OP_X25519_KEYGEN,
        MODULE_OP_MLKEM_MATRIX_PRECOMPUTE,
        MODULE_OP_MLKEM_DECAP_CACHED,
        MODULE_OP_X25519_SHARED,
    ]:
        raise AssertionError(
            f"resumption module operation order drifted: "
            f"{machine.module_calls!r}"
        )
    if machine.module_decodes != [
        MODULE_KIND_KEYGEN,
        MODULE_KIND_X25519,
        MODULE_KIND_DECAP,
        MODULE_KIND_DECAP,
        MODULE_KIND_X25519,
    ]:
        raise AssertionError(
            f"resumption module decode order drifted: "
            f"{machine.module_decodes!r}"
        )
    if machine.transport_events[:5] != [
        f"module-{MODULE_OP_KEYGEN}",
        f"module-{MODULE_OP_X25519_KEYGEN}",
        f"module-{MODULE_OP_MLKEM_MATRIX_PRECOMPUTE}",
        "nic-enter",
        "tcp-connect",
    ]:
        raise AssertionError(
            "resumption opened TCP before keygen/matrix precompute"
        )
    assert_resumed_client_hello(machine, expected_record)
    assert_psk_extension(
        expected_record,
        identity=TICKET_IDENTITY,
        age=age,
        binder=binder,
    )
    if bytes(
        machine.uc.mem_read(
            CRYPTO_BASE + TICKET_TRUNCATED_HASH_OFF, 32
        )
    ) != truncated_hash:
        raise AssertionError("stored ClientHelloTruncated hash drifted")
    if bytes(
        machine.uc.mem_read(CRYPTO_BASE + TICKET_BINDER_OFF, 32)
    ) != binder:
        raise AssertionError("stored resumption binder drifted")
    expected_hybrid = resume_secret + x25519(
        FRESH_BUNDLE[64:96], SERVER_X
    )
    if bytes(
        machine.uc.mem_read(CRYPTO_BASE + HYBRID_SECRET_OFF, 64)
    ) != expected_hybrid:
        raise AssertionError("resumed full ML-KEM/X25519 secret drifted")
    if any(machine.uc.mem_read(CIPHERTEXT_OFF, CIPHERTEXT_BYTES + 32)):
        raise AssertionError("resumption retained peer key-share bytes")
    if any(machine.uc.mem_read(MODULE_BASE, MODULE_LIMIT - MODULE_BASE)):
        raise AssertionError("resumption left module/binder scratch live")
    if bytes(
        machine.uc.mem_read(CRYPTO_BASE, PACK_BYTES)
    ) != pack_before:
        raise AssertionError("resumption modified authenticated module pack")

    fresh_dk = KEYGEN_ORACLE.fips_keygen_internal(FRESH_BUNDLE[:64])
    fresh_ek = fresh_dk[1152 : 1152 + EK_BYTES]
    if len(machine.phase_load_snapshots) != 1:
        raise AssertionError("resumption did not load one TCP phase")
    low_after_load, high_after_load = machine.phase_load_snapshots[0]
    expected_low = (
        fresh_ek[:overwrite_at]
        + phase_image[: EK_BYTES - overwrite_at]
    )
    if low_after_load != expected_low or high_after_load != fresh_ek:
        raise AssertionError("resumption damaged independent ek provenance")

    assert_corrupt_matrix_fo_finished_boundary(built, snapshot)

    alternate, alternate_record, *_rest = run_live_resume(
        built,
        snapshot,
        order="psk-first",
        expect_success=True,
    )
    if alternate.root_aborted:
        raise AssertionError("valid alternate resumed extension order failed")
    assert_resumed_client_hello(alternate, alternate_record)
    assert_resumption_early_cache(alternate, "alternate resumption")
    assert_matrix_cache_lifecycle(
        alternate, built, "alternate resumption"
    )

    rejected, *_rest = run_live_resume(
        built,
        snapshot,
        order="versions-first",
        selected_identity=1,
        expect_success=False,
    )
    if not rejected.root_aborted:
        raise AssertionError("selected_identity != 0 bypassed product abort")
    if (
        MODULE_OP_MLKEM_DECAP in rejected.module_calls
        or MODULE_OP_MLKEM_DECAP_CACHED in rejected.module_calls
    ):
        raise AssertionError("invalid resumed ServerHello reached full decapsulation")
    if any(rejected.uc.mem_read(CRYPTO_BASE, HIGH_BYTES)):
        raise AssertionError("selected_identity rejection left high state live")

    for label, status in (
        ("missing matrix status", b"\x00\x00"),
        ("torn matrix inverse", b"\x5a\x00"),
        ("torn matrix valid", b"\x00\xa5"),
        ("reversed matrix status", b"\xa5\x5a"),
        ("stale USED matrix status", bytes((USED_INV, USED))),
    ):
        invalid, *_rest = run_live_resume(
            built,
            snapshot,
            order="versions-first",
            matrix_status_before_transport=status,
            expect_success=False,
        )
        if (
            not invalid.matrix_status_injected
            or not invalid.root_aborted
            or invalid.chain_kinds
            or invalid.module_calls
            != [
                MODULE_OP_KEYGEN,
                MODULE_OP_X25519_KEYGEN,
                MODULE_OP_MLKEM_MATRIX_PRECOMPUTE,
            ]
            or invalid.matrix_cached_decap_event is not None
            or invalid.matrix_data_read_statuses
            or invalid.matrix_read_coverage
        ):
            raise AssertionError(
                f"{label} reached cached decapsulation/publication"
            )
        if invalid.matrix_ready_event != (
            matrix_cache_oracle(
                KEYGEN_ORACLE.fips_keygen_internal(FRESH_BUNDLE[:64])
            ),
            MLKEM_MATRIX_STAGE_BYTES,
            3,
            0,
            0,
        ):
            raise AssertionError(
                f"{label} was not injected after exact pre-TCP publication"
            )
        if any(invalid.uc.mem_read(CRYPTO_BASE, HIGH_BYTES)):
            raise AssertionError(f"{label} left high private state live")

    torn = Machine(built, snapshot=snapshot)
    torn.install_promoted_ticket()
    torn.uc.mem_write(
        CRYPTO_BASE + TICKET_STATUS_OFF, b"\x00"
    )
    torn.shadow[:] = torn.uc.mem_read(0, 1024 * 1024)
    torn.call(
        1,
        bx=CRYPTO_SEG,
        si=FOOTER_OFF,
        expect_success=False,
        instruction_limit=20_000_000,
    )
    if not torn.root_aborted or torn.module_calls:
        raise AssertionError("torn promoted ticket reached crypto/transport")

    unauthenticated = Machine(built, snapshot=snapshot)
    unauthenticated.install_promoted_ticket()
    unauthenticated.uc.mem_write(
        CRYPTO_BASE + AUTH_STATUS_OFF, b"\x00"
    )
    unauthenticated.shadow[:] = unauthenticated.uc.mem_read(0, 1024 * 1024)
    unauthenticated.call(
        1,
        bx=CRYPTO_SEG,
        si=FOOTER_OFF,
        expect_success=False,
        instruction_limit=20_000_000,
    )
    if not unauthenticated.root_aborted or unauthenticated.module_calls:
        raise AssertionError("unauthenticated ticket reached crypto/transport")


def main() -> None:
    built = build()
    assert_status_failure(built)
    assert_symmetric_stage_read_failure(built)
    assert_flight_stage_read_failure(built)
    record = assert_live_transport(built)
    print(
        "TLS13 286 HELLO PRODUCT PASS "
        f"raw={len(built.hello)} record={len(record)} "
        f"sha256={hashlib.sha256(built.hello).hexdigest()}"
    )


if __name__ == "__main__":
    main()
