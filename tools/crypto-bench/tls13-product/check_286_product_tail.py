#!/usr/bin/env python3
"""Exact hostile gate for the appended TLS 1.3 286 product tail.

This gate deliberately does not trust the tail builder's report.  It parses
the resident prefix, footer, directory, module pack, and compressed entropy
controller independently, then binds those bytes back to the generated report
and NASM ABI.  The valid image is also walked through the real product
bootstrap and root stage under Unicorn.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass, replace
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
from types import ModuleType
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150"

DEFAULT_PREFIX = BUILD / "tls13-286-tail-base/SEED.SYS"
DEFAULT_TAIL = BUILD / "tls13-286-product-tail.bin"
DEFAULT_REPORT = BUILD / "tls13-286-product-tail.json"
DEFAULT_ABI = BUILD / "tls13-286-tail-abi.inc"
DEFAULT_ROOT_STAGE = BUILD / "tls13-286-root-stage.bin"
DEFAULT_MODULE_PACK = BUILD / "crypto-bench/tls13-286-modules.bin"
DEFAULT_ENTROPY_COMPONENT = BUILD / "tls13-286-entropy-component.bin"
DEFAULT_ENTROPY_RAW = BUILD / "tls13-286-entropy.bin"
DEFAULT_HELLO_COMPONENT = BUILD / "tls13-286-hello-component.bin"
DEFAULT_HELLO_RAW = BUILD / "tls13-286-hello.bin"
DEFAULT_FLIGHT_COMPONENT = BUILD / "tls13-286-flight-component.bin"
DEFAULT_FLIGHT_RAW = BUILD / "tls13-286-flight.bin"
DEFAULT_FLIGHT_SYM_K14_RAW = BUILD / "tls13-286-flight-sym-k14.bin"
DEFAULT_FLIGHT_SYM_RAW = BUILD / "tls13-286-flight-sym.bin"
DEFAULT_AUTH_COMPONENT = BUILD / "tls13-286-auth-component.bin"
DEFAULT_AUTH_RAW = BUILD / "tls13-286-auth.bin"
DEFAULT_BOOTSTRAP = BUILD / "tls13-286-bootstrap.bin"

BOOTSTRAP_GATE = HERE / "check_286_product_bootstrap.py"
ROOT_GATE = HERE / "check_286_root_stage.py"

SECTOR_BYTES = 512
CORE_MAGIC = b"SEEDCORE"
CORE_MAGIC_OFF = 3
CORE_VERSION_OFF = 11
CORE_TOTAL_SECTORS_OFF = 0x11
BOOTSTRAP_MAX_TOTAL_SECTORS = 320
FAT_DATA_SECTORS = 309
PACKAGED_AUXILIARY_SECTORS = 15
UNIVERSAL_MAX_SEED_SECTORS = (
    FAT_DATA_SECTORS - PACKAGED_AUXILIARY_SECTORS - 1
)

TAIL_MAGIC = b"S286TL02"
TAIL_ABI = 2
TAIL_HEADER_BYTES = 32
TAIL_ENTRY_BYTES = 16
TAIL_DIRECTORY_OFF = 32
TAIL_FOOTER_CRC_OFF = 510
TAIL_ENTRY_STRUCT = struct.Struct("<HHHHHHHH")

TAIL_FLAG_PRODUCT = 0x0001
TAIL_FLAG_RAW_LZ4 = 0x0002
TAIL_KIND_ROOT = 1
TAIL_KIND_PACK = 2
TAIL_KIND_HELLO_RESUME = 4
TAIL_KIND_ACQUIRE = 5
TAIL_KIND_AUTHENTICATE = 6
TAIL_KIND_PRECOMPUTE = 8
TAIL_KIND_FLIGHT = 9

ROOT_SECTORS = 4
ROOT_BYTES = ROOT_SECTORS * SECTOR_BYTES
ROOT_LOAD = 0x3400
ROOT_SERVICE_TABLE = 0x3910
ROOT_SERVICE_CHAIN_POINTER = ROOT_SERVICE_TABLE + 10
ROOT_SERVICE_POINTERS = 3
ROOT_ENTRY = ROOT_SERVICE_TABLE + 8 + ROOT_SERVICE_POINTERS * 2
ROOT_LIMIT = 0x3C00

PACK_MAGIC = b"S286PK02"
PACK_BYTES = 44 * SECTOR_BYTES
PACK_SECTORS = 44
PACK_HEADER_BYTES = 512
PACK_DIRECTORY_OFF = 20
PACK_ENTRY_BYTES = 24
PACK_ENTRY_STRUCT = struct.Struct("<8sHHHHIHH")
PACK_FLAG_RAW_LZ4 = 1
MODULE_MAGIC = b"S286MOD2"
MODULE_HEADER_BYTES = 32
MODULE_REQUIRED_STATE_BYTES = 18
MODULE_FLAG_ONE_SHOT = 1
MODULE_LOAD = 0x4230
MODULE_LIMIT = 0x7A00
MODULE_MAX_BYTES = MODULE_LIMIT - MODULE_LOAD

ENTROPY_MAGIC = b"S286ENT2"
CONTROLLER_LOAD = 0x1800
CONTROLLER_LIMIT = 0x3400
FLIGHT_LOAD = 0x6300
FLIGHT_LIMIT = 0x7380
# Retain the original local names for the bootstrap/root executable harness.
ENTROPY_LOAD = CONTROLLER_LOAD
ENTROPY_LIMIT = CONTROLLER_LIMIT
ENTROPY_ENTRY_COUNT = 5
HELLO_MAGIC = b"S286HL02"
HELLO_ENTRY_COUNT = 2
FLIGHT_MAGIC = b"S286FL02"
FLIGHT_ENTRY_COUNT = 1
AUTH_MAGIC = b"S286AU02"
AUTH_ENTRY_COUNT = 1
LZ4_HEADER = struct.Struct("<4sHHHH")
PRODUCT_SYM_BYTES = 12 * SECTOR_BYTES
PRODUCT_CRITICAL_TAIL_OFFSET = 0x16E0
PRODUCT_CRITICAL_TAIL_BYTES = 0x0120
PRODUCT_SHA256_INITIAL_STATE = 0x2EE0
CANONICAL_SHA256_INITIAL_STATE = 0x2EE0
PRODUCT_INITIAL_POINTER_OFF = 0x0E10

ABI_NAMES = {
    "TLS13_286_PRODUCT_TAIL_START_SECTOR",
    "TLS13_286_PRODUCT_TAIL_SECTORS",
    "TLS13_286_PRODUCT_FINAL_SECTORS",
    "TLS13_286_PRODUCT_ROOT_START_SECTOR",
    "TLS13_286_PRODUCT_MODULE_PACK_START_SECTOR",
    "TLS13_286_PRODUCT_ENTROPY_START_SECTOR",
    "TLS13_286_PRODUCT_ENTROPY_SECTORS",
    "TLS13_286_PRODUCT_HELLO_START_SECTOR",
    "TLS13_286_PRODUCT_HELLO_SECTORS",
    "TLS13_286_PRODUCT_FLIGHT_START_SECTOR",
    "TLS13_286_PRODUCT_FLIGHT_SECTORS",
    "TLS13_286_PRODUCT_AUTH_START_SECTOR",
    "TLS13_286_PRODUCT_AUTH_SECTORS",
    "TLS13_286_PRODUCT_FOOTER_SECTOR",
}

EXPECTED_MODULE_NAMES = {
    1: b"MLKEMKG",
    2: b"MLKEM768",
    3: b"X25519",
    4: b"P256W7",
    5: b"ECDSAW7",
}


def fail(message: str) -> None:
    raise AssertionError(message)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def crc16(value: bytes) -> int:
    result = 0xFFFF
    for byte in value:
        result ^= byte << 8
        for _ in range(8):
            result = (
                ((result << 1) ^ 0x1021) & 0xFFFF
                if result & 0x8000
                else (result << 1) & 0xFFFF
            )
    return result


def word(value: bytes, offset: int) -> int:
    return struct.unpack_from("<H", value, offset)[0]


def put_word(value: bytearray, offset: int, item: int) -> None:
    struct.pack_into("<H", value, offset, item)


def normalize_product_symmetric_image(
    product: bytes, canonical: bytes
) -> tuple[bytes, tuple[int, ...]]:
    """Independently prove the exact pre-TCP product-to-canonical rewrite."""

    if (
        len(product) != PRODUCT_SYM_BYTES
        or len(canonical) != PRODUCT_SYM_BYTES
        or PRODUCT_CRITICAL_TAIL_OFFSET + PRODUCT_CRITICAL_TAIL_BYTES
        != PRODUCT_SYM_BYTES
    ):
        fail("K14 symmetric normalization geometry drifted")
    if product[:8] != b"T13SYM02" or canonical[:8] != b"T13SYM02":
        fail("K14 symmetric normalization magic drifted")
    if (
        product[PRODUCT_CRITICAL_TAIL_OFFSET:]
        == canonical[PRODUCT_CRITICAL_TAIL_OFFSET:]
    ):
        fail("8088 K14 product tail unexpectedly equals canonical SHA tail")

    normalized = bytearray(product)
    normalized[PRODUCT_CRITICAL_TAIL_OFFSET:] = canonical[
        PRODUCT_CRITICAL_TAIL_OFFSET:
    ]
    pointer_offsets: list[int] = []
    for offset in range(PRODUCT_CRITICAL_TAIL_OFFSET - 1):
        if (
            word(product, offset) == CANONICAL_SHA256_INITIAL_STATE
            and word(canonical, offset) == CANONICAL_SHA256_INITIAL_STATE
        ):
            pointer_offsets.append(offset)
    if tuple(pointer_offsets) != (PRODUCT_INITIAL_POINTER_OFF,):
        fail(f"K14 symmetric normalization pointer set drifted: {pointer_offsets!r}")
    if bytes(normalized) != canonical:
        fail("pre-TCP K14 symmetric normalization is not byte exact")
    return bytes(normalized), tuple(pointer_offsets)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read product-tail report {path}: {error}")
    if not isinstance(value, dict):
        fail("product-tail report is not a JSON object")
    return value


def require_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    actual = set(value)
    if actual != expected:
        fail(
            f"{label} keys drifted: missing={sorted(expected - actual)!r}, "
            f"extra={sorted(actual - expected)!r}"
        )
    return value


def require_int(value: object, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        fail(f"{label} is {value!r}, expected {expected}")


def require_hex(value: object, expected: int, label: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        fail(f"{label} is not a hexadecimal value")
    if int(value, 16) != expected:
        fail(f"{label} is {value}, expected 0x{expected:04x}")


def require_crc(value: object, expected: int, label: str) -> None:
    if value != f"{expected:04X}":
        fail(f"{label} is {value!r}, expected {expected:04X}")


def require_hash(value: object, expected: bytes, label: str) -> None:
    if value != digest(expected):
        fail(f"{label} does not bind the exact bytes")


def resolve_report_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        fail(f"{label} is not a path")
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def parse_abi(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        fail(f"cannot read product-tail ABI {path}: {error}")
    for raw in lines:
        words = raw.split()
        if not words or words[0].startswith(";"):
            continue
        if len(words) != 3 or words[0] != "%define":
            fail(f"product-tail ABI has an unexpected active line: {raw!r}")
        name = words[1]
        if name in result:
            fail(f"product-tail ABI repeats {name}")
        try:
            result[name] = int(words[2], 0)
        except ValueError:
            fail(f"product-tail ABI {name} is not an integer")
    if set(result) != ABI_NAMES:
        fail(
            "product-tail ABI symbol set drifted: "
            f"missing={sorted(ABI_NAMES - set(result))!r}, "
            f"extra={sorted(set(result) - ABI_NAMES)!r}"
        )
    return result


def decode_lz4_block(block: bytes, expected_bytes: int, label: str) -> bytes:
    """Decode one raw LZ4 block with exact source and destination bounds."""

    source = 0
    output = bytearray()
    while source < len(block):
        token = block[source]
        source += 1

        literal_bytes = token >> 4
        if literal_bytes == 15:
            while True:
                if source >= len(block):
                    fail(f"{label} ends in a literal-length extension")
                extension = block[source]
                source += 1
                literal_bytes += extension
                if extension != 255:
                    break
        literal_end = source + literal_bytes
        if literal_end > len(block):
            fail(f"{label} literal run exceeds the compressed block")
        if len(output) + literal_bytes > expected_bytes:
            fail(f"{label} literal run exceeds the declared raw image")
        output += block[source:literal_end]
        source = literal_end

        if source == len(block):
            break
        if source + 2 > len(block):
            fail(f"{label} ends in a truncated match offset")
        offset = block[source] | block[source + 1] << 8
        source += 2
        if offset == 0 or offset > len(output):
            fail(f"{label} has an invalid match offset")

        match_bytes = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while True:
                if source >= len(block):
                    fail(f"{label} ends in a match-length extension")
                extension = block[source]
                source += 1
                match_bytes += extension
                if extension != 255:
                    break
        if len(output) + match_bytes > expected_bytes:
            fail(f"{label} match exceeds the declared raw image")
        for _ in range(match_bytes):
            output.append(output[-offset])

    if source != len(block):
        fail(f"{label} did not consume the exact compressed block")
    if len(output) != expected_bytes:
        fail(
            f"{label} decoded {len(output)} bytes, expected {expected_bytes}"
        )
    return bytes(output)


@dataclass(frozen=True)
class TailEntry:
    kind: int
    flags: int
    start: int
    sectors: int
    image_bytes: int
    load: int
    entry: int
    crc: int

    @property
    def end(self) -> int:
        return self.start + self.sectors


@dataclass(frozen=True)
class Inputs:
    prefix: bytes
    tail: bytes
    report: dict[str, Any]
    abi: dict[str, int]
    root_stage: bytes
    module_pack: bytes
    entropy_component: bytes
    entropy_raw: bytes
    hello_component: bytes
    hello_raw: bytes
    flight_component: bytes
    flight_raw: bytes
    flight_sym_k14_raw: bytes
    flight_sym_raw: bytes
    auth_component: bytes
    auth_raw: bytes
    prefix_path: Path
    tail_path: Path


@dataclass(frozen=True)
class Validated:
    prefix_sectors: int
    total_sectors: int
    footer_sector: int
    tail_sectors: int
    entries: tuple[TailEntry, ...]
    root: TailEntry
    pack: TailEntry
    entropy: TailEntry
    hello: TailEntry
    hello_resume: TailEntry
    flight: TailEntry
    auth: TailEntry
    entropy_stored_bytes: int
    entropy_entry: int
    hello_stored_bytes: int
    hello_entry: int
    hello_resume_entry: int
    component_stored_bytes: dict[int, int]


def validate_prefix(prefix: bytes) -> int:
    if not prefix or len(prefix) % SECTOR_BYTES:
        fail("286 tail prefix is not a nonempty sector-aligned image")
    if len(prefix) < CORE_TOTAL_SECTORS_OFF + 2:
        fail("286 tail prefix is shorter than its resident header")
    if prefix[CORE_MAGIC_OFF : CORE_MAGIC_OFF + len(CORE_MAGIC)] != CORE_MAGIC:
        fail("286 tail prefix has no SEEDCORE magic")
    if prefix[CORE_VERSION_OFF] != 1:
        fail("286 tail prefix has an unsupported core-header version")
    sectors = len(prefix) // SECTOR_BYTES
    declared = word(prefix, CORE_TOTAL_SECTORS_OFF)
    if declared != sectors:
        fail(
            f"286 tail prefix header declares {declared} sectors, file has "
            f"{sectors}"
        )
    if prefix[-SECTOR_BYTES :][: len(TAIL_MAGIC)] == TAIL_MAGIC:
        fail("286 tail prefix already contains a product-tail footer")
    return sectors


def parse_footer(
    tail: bytes, prefix_sectors: int
) -> tuple[int, int, tuple[TailEntry, ...]]:
    if not tail or len(tail) % SECTOR_BYTES:
        fail("286 product tail is not a nonempty sector-aligned image")
    footer = tail[-SECTOR_BYTES:]
    if footer[:8] != TAIL_MAGIC:
        fail("286 product-tail footer magic drifted")
    if word(footer, 8) != TAIL_ABI:
        fail("286 product-tail footer ABI drifted")
    if word(footer, 10) != TAIL_HEADER_BYTES:
        fail("286 product-tail footer header size drifted")
    if word(footer, 20) != TAIL_ENTRY_BYTES:
        fail("286 product-tail directory entry size drifted")
    if any(footer[22:TAIL_DIRECTORY_OFF]):
        fail("286 product-tail reserved header bytes are not zero")
    if crc16(footer[:TAIL_FOOTER_CRC_OFF]) != word(
        footer, TAIL_FOOTER_CRC_OFF
    ):
        fail("286 product-tail footer CRC does not verify")

    tail_sectors = len(tail) // SECTOR_BYTES
    total_sectors = word(footer, 12)
    tail_start = word(footer, 14)
    declared_tail_sectors = word(footer, 16)
    entry_count = word(footer, 18)
    if tail_start != prefix_sectors:
        fail("286 product-tail start is not the exact end of its prefix")
    if declared_tail_sectors != tail_sectors:
        fail("286 product-tail footer sector count is not exact")
    if total_sectors != prefix_sectors + tail_sectors:
        fail("286 product-tail footer total does not match prefix + tail")
    if total_sectors > BOOTSTRAP_MAX_TOTAL_SECTORS:
        fail("286 product tail exceeds the bootstrap's 16-bit disk bound")
    if total_sectors > UNIVERSAL_MAX_SEED_SECTORS:
        fail("286 product tail exceeds the universal 160 KiB SEED.SYS budget")
    if total_sectors + PACKAGED_AUXILIARY_SECTORS > FAT_DATA_SECTORS:
        fail("286 product plus auxiliary files exceed the 160 KiB FAT data area")
    if entry_count != 7:
        fail("286 product-tail directory is not the exact seven-entry profile")
    directory_end = TAIL_DIRECTORY_OFF + entry_count * TAIL_ENTRY_BYTES
    if directory_end > TAIL_FOOTER_CRC_OFF:
        fail("286 product-tail directory exceeds the footer")
    if any(footer[directory_end:TAIL_FOOTER_CRC_OFF]):
        fail("286 product-tail unused directory bytes are not canonical zero")

    entries = tuple(
        TailEntry(*TAIL_ENTRY_STRUCT.unpack_from(
            footer, TAIL_DIRECTORY_OFF + index * TAIL_ENTRY_BYTES
        ))
        for index in range(entry_count)
    )
    footer_sector = total_sectors - 1
    for entry in entries:
        if entry.sectors == 0 or entry.image_bytes == 0:
            fail("286 product-tail entry has an empty extent")
        if entry.start < tail_start or entry.end > footer_sector:
            fail("286 product-tail entry escapes the component extent")
        if entry.image_bytes > entry.sectors * SECTOR_BYTES:
            fail("286 product-tail entry image exceeds its sector extent")
    acquire = entries[3]
    resume = entries[4]
    if (
        acquire.kind != TAIL_KIND_ACQUIRE
        or resume.kind != TAIL_KIND_HELLO_RESUME
        or (
            acquire.flags,
            acquire.start,
            acquire.sectors,
            acquire.image_bytes,
            acquire.load,
            acquire.crc,
        )
        != (
            resume.flags,
            resume.start,
            resume.sectors,
            resume.image_bytes,
            resume.load,
            resume.crc,
        )
        or acquire.entry == resume.entry
    ):
        fail("286 HELLO acquisition/resumption entries are not one exact safe alias")

    physical: dict[tuple[int, int], TailEntry] = {}
    for entry in entries:
        extent = (entry.start, entry.end)
        previous = physical.get(extent)
        if previous is not None:
            if {previous.kind, entry.kind} != {
                TAIL_KIND_ACQUIRE,
                TAIL_KIND_HELLO_RESUME,
            }:
                fail("286 product-tail has an unapproved aliased extent")
            continue
        physical[extent] = entry
    ordered = sorted(physical.values(), key=lambda entry: (entry.start, entry.end))
    for left, right in zip(ordered, ordered[1:]):
        if left.end > right.start:
            fail("286 product-tail entries overlap")
    cursor = tail_start
    for entry in ordered:
        if entry.start != cursor:
            fail("286 product-tail component extents are not contiguous")
        cursor = entry.end
    if cursor != footer_sector:
        fail("286 product-tail components do not end at the footer")

    kinds = [entry.kind for entry in entries]
    if len(set(kinds)) != len(kinds):
        fail("286 product-tail directory contains a duplicate kind")
    if kinds != [
        TAIL_KIND_ROOT,
        TAIL_KIND_PACK,
        TAIL_KIND_PRECOMPUTE,
        TAIL_KIND_ACQUIRE,
        TAIL_KIND_HELLO_RESUME,
        TAIL_KIND_FLIGHT,
        TAIL_KIND_AUTHENTICATE,
    ]:
        fail("286 product-tail directory kind/order profile drifted")
    return total_sectors, footer_sector, entries


def validate_root(root: bytes, entry: TailEntry) -> None:
    expected = TailEntry(
        TAIL_KIND_ROOT,
        TAIL_FLAG_PRODUCT,
        entry.start,
        ROOT_SECTORS,
        ROOT_BYTES,
        ROOT_LOAD,
        ROOT_ENTRY,
        crc16(root),
    )
    if entry != expected:
        fail("286 product-tail root-stage entry drifted")
    if len(root) != ROOT_BYTES:
        fail("286 root stage is not exactly four sectors")
    table = ROOT_SERVICE_TABLE - ROOT_LOAD
    if root[table : table + 8] != b"S286RT02":
        fail("286 root-stage service table magic drifted")
    pointers = struct.unpack_from("<HHH", root, table + 8)
    if pointers[0] != ROOT_ENTRY:
        fail("286 root-stage main entry drifted")
    if any(not ROOT_ENTRY <= pointer < ROOT_LIMIT for pointer in pointers):
        fail("286 root-stage service pointer escaped the four-sector stage")


def validate_module_pack(pack: bytes, entry: TailEntry) -> None:
    expected = TailEntry(
        TAIL_KIND_PACK,
        TAIL_FLAG_PRODUCT,
        entry.start,
        PACK_SECTORS,
        PACK_BYTES,
        0,
        0,
        crc16(pack),
    )
    if entry != expected:
        fail("286 product-tail module-pack entry drifted")
    if len(pack) != PACK_BYTES:
        fail("286 module pack is not exactly 44 sectors")
    if pack[:8] != PACK_MAGIC:
        fail("286 module pack has no S286PK02 magic")
    abi, count, header_bytes, entry_bytes = struct.unpack_from("<HHHH", pack, 8)
    total_bytes = struct.unpack_from("<I", pack, 16)[0]
    if (abi, count, header_bytes, entry_bytes, total_bytes) != (
        TAIL_ABI,
        5,
        PACK_HEADER_BYTES,
        PACK_ENTRY_BYTES,
        len(pack),
    ):
        fail("286 S286PK02 header/count/geometry drifted")
    directory_end = PACK_DIRECTORY_OFF + count * PACK_ENTRY_BYTES
    if directory_end > PACK_HEADER_BYTES:
        fail("286 S286PK02 directory exceeds its header sector")
    if any(pack[directory_end:PACK_HEADER_BYTES]):
        fail("286 S286PK02 unused header bytes are not canonical zero")

    expected_payload = PACK_HEADER_BYTES
    seen_kinds: set[int] = set()
    for index in range(count):
        offset = PACK_DIRECTORY_OFF + index * PACK_ENTRY_BYTES
        (
            name_field,
            kind,
            flags,
            raw_bytes,
            compressed_bytes,
            payload,
            raw_crc,
            reserved,
        ) = PACK_ENTRY_STRUCT.unpack_from(pack, offset)
        if kind not in EXPECTED_MODULE_NAMES or kind in seen_kinds:
            fail("286 S286PK02 module kinds are missing, unknown, or duplicated")
        seen_kinds.add(kind)
        expected_name = EXPECTED_MODULE_NAMES[kind]
        if name_field != expected_name.ljust(8, b"\0"):
            fail("286 S286PK02 module name/kind binding drifted")
        if flags != PACK_FLAG_RAW_LZ4 or reserved:
            fail("286 S286PK02 module flags/reserved field drifted")
        if not 0 < raw_bytes <= MODULE_MAX_BYTES or compressed_bytes == 0:
            fail("286 S286PK02 module length escaped the product overlay")
        if payload != expected_payload:
            fail("286 S286PK02 compressed payloads have a gap or overlap")
        payload_end = payload + compressed_bytes
        if payload_end > len(pack):
            fail("286 S286PK02 compressed payload exceeds the pack")
        raw = decode_lz4_block(
            pack[payload:payload_end],
            raw_bytes,
            f"S286PK02 kind {kind}",
        )
        if crc16(raw) != raw_crc:
            fail("286 S286PK02 decoded module CRC does not verify")
        if raw[:8] != MODULE_MAGIC:
            fail("286 S286PK02 decoded payload has no S286MOD2 magic")
        module_abi, module_kind, image_bytes, entry_off = struct.unpack_from(
            "<HHHH", raw, 8
        )
        required_state = word(raw, 16)
        required_stack = word(raw, 18)
        module_flags = word(raw, 20)
        if (
            module_abi != TAIL_ABI
            or module_kind != kind
            or image_bytes != len(raw)
            or not MODULE_HEADER_BYTES <= entry_off < len(raw)
            or required_state != MODULE_REQUIRED_STATE_BYTES
            or required_stack > 2048
            or module_flags != MODULE_FLAG_ONE_SHOT
        ):
            fail("286 S286MOD2 callable header/profile drifted")
        if any(raw[22:MODULE_HEADER_BYTES]):
            fail("286 S286MOD2 reserved header bytes are not canonical zero")
        expected_payload = payload_end
    if seen_kinds != set(EXPECTED_MODULE_NAMES):
        fail("286 S286PK02 does not contain the complete module kind set")
    if any(pack[expected_payload:]):
        fail("286 S286PK02 trailing sector padding is not canonical zero")


def validate_controller(
    component: bytes,
    expected_raw: bytes,
    entry: TailEntry,
    *,
    controller_magic: bytes,
    abi_expected: int,
    entry_count_expected: int,
    entry_count_off: int | None,
    entry_table_off: int,
    load: int,
    limit: int,
    selected_entry_index: int,
    label: str,
) -> tuple[int, tuple[int, ...]]:
    if not component or len(component) % SECTOR_BYTES:
        fail(f"286 {label} component is not sector aligned")
    if len(component) != entry.sectors * SECTOR_BYTES:
        fail(f"286 {label} component sector count is not exact")
    if len(component) < LZ4_HEADER.size:
        fail(f"286 {label} component is shorter than its LZ4B header")
    lz4_magic, raw_bytes, block_bytes, raw_crc, reserved = LZ4_HEADER.unpack_from(
        component
    )
    stored_bytes = LZ4_HEADER.size + block_bytes
    if lz4_magic != b"LZ4B" or reserved:
        fail(f"286 {label} component LZ4B header drifted")
    if stored_bytes != entry.image_bytes or stored_bytes > len(component):
        fail(f"286 {label} component stored-byte length is not exact")
    if len(component) != (
        (stored_bytes + SECTOR_BYTES - 1) // SECTOR_BYTES
    ) * SECTOR_BYTES:
        fail(f"286 {label} component has redundant zero sectors")
    if any(component[stored_bytes:]):
        fail(f"286 {label} component padding is not canonical zero")
    raw = decode_lz4_block(
        component[LZ4_HEADER.size:stored_bytes],
        raw_bytes,
        f"{label} LZ4B",
    )
    if crc16(raw) != raw_crc or entry.crc != raw_crc:
        fail(f"286 {label} component raw CRC does not verify")
    if raw != expected_raw:
        fail(f"286 {label} component does not decode to the product raw image")
    if raw[:8] != controller_magic:
        fail(f"286 {label} controller magic drifted")
    abi, image_bytes = struct.unpack_from("<HH", raw, 8)
    entry_count = (
        word(raw, entry_count_off)
        if entry_count_off is not None
        else entry_count_expected
    )
    if (abi, image_bytes, entry_count) != (
        abi_expected,
        len(raw),
        entry_count_expected,
    ):
        fail(f"286 {label} header/image/entry count drifted")
    if len(raw) > limit - load:
        fail(f"286 {label} image exceeds the safe controller overlay")
    entry_points = struct.unpack_from(
        "<" + "H" * entry_count, raw, entry_table_off
    )
    if len(set(entry_points)) != entry_count or any(
        not load <= point < load + len(raw)
        for point in entry_points
    ):
        fail(f"286 {label} entry table is duplicated or out of bounds")
    if entry.flags != TAIL_FLAG_PRODUCT | TAIL_FLAG_RAW_LZ4:
        fail(f"286 {label} directory flags drifted")
    if (
        not 0 <= selected_entry_index < entry_count
        or entry.load != load
        or entry.entry != entry_points[selected_entry_index]
    ):
        fail(f"286 {label} load/selected-entry binding drifted")
    return stored_bytes, entry_points


def validate_report_and_abi(
    inputs: Inputs,
    *,
    prefix_sectors: int,
    tail_sectors: int,
    total_sectors: int,
    footer_sector: int,
    entries: tuple[TailEntry, ...],
    entropy_stored_bytes: int,
    hello_stored_bytes: int,
) -> None:
    report = require_keys(
        inputs.report,
        {
            "schema",
            "prefix",
            "tail",
            "final_total_sectors",
            "bootstrap_max_total_sectors",
            "bootstrap_sector_headroom",
            "footer",
            "entries",
            "runtime_module_loading",
            "legacy_phase_keys_used_for_tail",
        },
        "product-tail report",
    )
    if report["schema"] != "seed-tls13-286-product-tail-v1":
        fail("product-tail report schema drifted")

    prefix_report = require_keys(
        report["prefix"], {"image", "bytes", "sectors", "sha256"}, "prefix report"
    )
    if resolve_report_path(prefix_report["image"], "prefix report image") != (
        inputs.prefix_path.resolve()
    ):
        fail("product-tail report names a different prefix image")
    require_int(prefix_report["bytes"], len(inputs.prefix), "prefix report bytes")
    require_int(prefix_report["sectors"], prefix_sectors, "prefix report sectors")
    require_hash(prefix_report["sha256"], inputs.prefix, "prefix report SHA-256")

    tail_report = require_keys(
        report["tail"],
        {"image", "bytes", "start_sector", "sectors", "sha256"},
        "tail report",
    )
    if resolve_report_path(tail_report["image"], "tail report image") != (
        inputs.tail_path.resolve()
    ):
        fail("product-tail report names a different tail image")
    require_int(tail_report["bytes"], len(inputs.tail), "tail report bytes")
    require_int(
        tail_report["start_sector"], prefix_sectors, "tail report start sector"
    )
    require_int(tail_report["sectors"], tail_sectors, "tail report sectors")
    require_hash(tail_report["sha256"], inputs.tail, "tail report SHA-256")

    require_int(
        report["final_total_sectors"],
        total_sectors,
        "report final total sectors",
    )
    require_int(
        report["bootstrap_max_total_sectors"],
        BOOTSTRAP_MAX_TOTAL_SECTORS,
        "report bootstrap sector cap",
    )
    require_int(
        report["bootstrap_sector_headroom"],
        BOOTSTRAP_MAX_TOTAL_SECTORS - total_sectors,
        "report bootstrap sector headroom",
    )
    if report["runtime_module_loading"] is not False:
        fail("product-tail report claims a runtime module-loading ABI")
    if report["legacy_phase_keys_used_for_tail"] is not False:
        fail("product-tail report claims legacy phase keys address the tail")

    footer = inputs.tail[-SECTOR_BYTES:]
    footer_report = require_keys(
        report["footer"],
        {"sector", "magic", "abi", "crc16_ccitt"},
        "footer report",
    )
    require_int(footer_report["sector"], footer_sector, "footer report sector")
    if footer_report["magic"] != TAIL_MAGIC.decode("ascii"):
        fail("footer report magic drifted")
    require_int(footer_report["abi"], TAIL_ABI, "footer report ABI")
    require_crc(
        footer_report["crc16_ccitt"],
        crc16(footer[:TAIL_FOOTER_CRC_OFF]),
        "footer report CRC",
    )

    report_entries = report["entries"]
    if not isinstance(report_entries, list) or len(report_entries) != 4:
        fail("product-tail report does not contain exactly four entries")
    root_report = require_keys(
        report_entries[0],
        {
            "kind",
            "name",
            "flags",
            "start_sector",
            "sectors",
            "image_bytes",
            "load",
            "entry",
            "crc16_ccitt",
            "sha256",
        },
        "root-stage report",
    )
    pack_report = require_keys(
        report_entries[1],
        {
            "kind",
            "name",
            "flags",
            "start_sector",
            "sectors",
            "image_bytes",
            "load",
            "entry",
            "crc16_ccitt",
            "sha256",
        },
        "module-pack report",
    )
    entropy_report = require_keys(
        report_entries[2],
        {
            "kind",
            "name",
            "flags",
            "start_sector",
            "sectors",
            "image_bytes",
            "load",
            "entry",
            "crc16_ccitt",
            "raw_bytes",
            "raw_sha256",
            "component_sha256",
        },
        "entropy-precompute report",
    )
    hello_report = require_keys(
        report_entries[3],
        {
            "kind",
            "name",
            "flags",
            "start_sector",
            "sectors",
            "image_bytes",
            "load",
            "entry",
            "crc16_ccitt",
            "raw_bytes",
            "raw_sha256",
            "component_sha256",
        },
        "hello-acquisition report",
    )
    for item, entry, name in (
        (root_report, entries[0], "root-stage"),
        (pack_report, entries[1], "module-pack"),
        (entropy_report, entries[2], "entropy-precompute"),
        (hello_report, entries[3], "hello-acquisition"),
    ):
        require_int(item["kind"], entry.kind, f"{name} report kind")
        if item["name"] != name:
            fail(f"{name} report name drifted")
        require_int(item["flags"], entry.flags, f"{name} report flags")
        require_int(
            item["start_sector"], entry.start, f"{name} report start sector"
        )
        require_int(item["sectors"], entry.sectors, f"{name} report sectors")
        require_int(
            item["image_bytes"], entry.image_bytes, f"{name} report image bytes"
        )
        require_hex(item["load"], entry.load, f"{name} report load")
        require_hex(item["entry"], entry.entry, f"{name} report entry")
        require_crc(item["crc16_ccitt"], entry.crc, f"{name} report CRC")
    require_hash(
        root_report["sha256"], inputs.root_stage, "root-stage report SHA-256"
    )
    require_hash(
        pack_report["sha256"], inputs.module_pack, "module-pack report SHA-256"
    )
    require_int(
        entropy_report["image_bytes"],
        entropy_stored_bytes,
        "entropy report stored bytes",
    )
    require_int(
        entropy_report["raw_bytes"],
        len(inputs.entropy_raw),
        "entropy report raw bytes",
    )
    require_hash(
        entropy_report["raw_sha256"],
        inputs.entropy_raw,
        "entropy report raw SHA-256",
    )
    require_hash(
        entropy_report["component_sha256"],
        inputs.entropy_component,
        "entropy report component SHA-256",
    )
    require_int(
        hello_report["image_bytes"],
        hello_stored_bytes,
        "HELLO report stored bytes",
    )
    require_int(
        hello_report["raw_bytes"],
        len(inputs.hello_raw),
        "HELLO report raw bytes",
    )
    require_hash(
        hello_report["raw_sha256"],
        inputs.hello_raw,
        "HELLO report raw SHA-256",
    )
    require_hash(
        hello_report["component_sha256"],
        inputs.hello_component,
        "HELLO report component SHA-256",
    )

    expected_abi = {
        "TLS13_286_PRODUCT_TAIL_START_SECTOR": prefix_sectors,
        "TLS13_286_PRODUCT_TAIL_SECTORS": tail_sectors,
        "TLS13_286_PRODUCT_FINAL_SECTORS": total_sectors,
        "TLS13_286_PRODUCT_ROOT_START_SECTOR": entries[0].start,
        "TLS13_286_PRODUCT_MODULE_PACK_START_SECTOR": entries[1].start,
        "TLS13_286_PRODUCT_ENTROPY_START_SECTOR": entries[2].start,
        "TLS13_286_PRODUCT_ENTROPY_SECTORS": entries[2].sectors,
        "TLS13_286_PRODUCT_HELLO_START_SECTOR": entries[3].start,
        "TLS13_286_PRODUCT_HELLO_SECTORS": entries[3].sectors,
        "TLS13_286_PRODUCT_FOOTER_SECTOR": footer_sector,
    }
    if inputs.abi != expected_abi:
        fail("generated product-tail ABI does not exactly match parsed geometry")


def validate_report_and_abi_v2(inputs: Inputs, layout: Validated) -> None:
    """Bind the complete universal product graph to its report and NASM ABI."""

    report = require_keys(
        inputs.report,
        {
            "schema",
            "prefix",
            "tail",
            "final_total_sectors",
            "universal_max_seed_sectors",
            "packaged_auxiliary_sectors",
            "fat_data_sectors",
            "final_packaged_sectors",
            "universal_packaged_headroom",
            "universal_runtime_growth_headroom",
            "sector_savings",
            "bootstrap_max_total_sectors",
            "bootstrap_sector_headroom",
            "footer",
            "entries",
            "symmetric_reuse",
            "trusted_time",
            "runtime_module_loading",
            "legacy_phase_keys_used_for_tail",
        },
        "product-tail report",
    )
    if report["schema"] != "seed-tls13-286-product-tail-v1":
        fail("product-tail report schema drifted")

    prefix_report = require_keys(
        report["prefix"], {"image", "bytes", "sectors", "sha256"}, "prefix report"
    )
    if resolve_report_path(prefix_report["image"], "prefix report image") != (
        inputs.prefix_path.resolve()
    ):
        fail("product-tail report names a different prefix image")
    require_int(prefix_report["bytes"], len(inputs.prefix), "prefix report bytes")
    require_int(
        prefix_report["sectors"], layout.prefix_sectors, "prefix report sectors"
    )
    require_hash(prefix_report["sha256"], inputs.prefix, "prefix report SHA-256")

    tail_report = require_keys(
        report["tail"],
        {"image", "bytes", "start_sector", "sectors", "sha256"},
        "tail report",
    )
    if resolve_report_path(tail_report["image"], "tail report image") != (
        inputs.tail_path.resolve()
    ):
        fail("product-tail report names a different tail image")
    require_int(tail_report["bytes"], len(inputs.tail), "tail report bytes")
    require_int(
        tail_report["start_sector"],
        layout.prefix_sectors,
        "tail report start sector",
    )
    require_int(tail_report["sectors"], layout.tail_sectors, "tail report sectors")
    require_hash(tail_report["sha256"], inputs.tail, "tail report SHA-256")
    require_int(
        report["final_total_sectors"],
        layout.total_sectors,
        "report final total sectors",
    )
    require_int(
        report["universal_max_seed_sectors"],
        UNIVERSAL_MAX_SEED_SECTORS,
        "report universal SEED.SYS cap",
    )
    require_int(
        report["packaged_auxiliary_sectors"],
        PACKAGED_AUXILIARY_SECTORS,
        "report packaged auxiliary sectors",
    )
    require_int(
        report["fat_data_sectors"],
        FAT_DATA_SECTORS,
        "report FAT data sectors",
    )
    require_int(
        report["final_packaged_sectors"],
        layout.total_sectors + PACKAGED_AUXILIARY_SECTORS,
        "report final packaged sectors",
    )
    require_int(
        report["universal_packaged_headroom"],
        FAT_DATA_SECTORS
        - layout.total_sectors
        - PACKAGED_AUXILIARY_SECTORS,
        "report universal packaged headroom",
    )
    require_int(
        report["universal_runtime_growth_headroom"],
        UNIVERSAL_MAX_SEED_SECTORS - layout.total_sectors,
        "report universal runtime growth headroom",
    )
    savings = require_keys(
        report["sector_savings"],
        {
            "reference_final_seed_sectors",
            "relocated_k14_symmetric_reuse",
            "parent_published_utc",
            "flight_relocator_growth",
            "net",
        },
        "sector-savings report",
    )
    require_int(
        savings["reference_final_seed_sectors"],
        303,
        "reference final SEED.SYS sectors",
    )
    require_int(
        savings["relocated_k14_symmetric_reuse"],
        10,
        "symmetric-reuse saving",
    )
    require_int(savings["parent_published_utc"], 1, "trusted-time saving")
    require_int(
        savings["flight_relocator_growth"],
        layout.flight.sectors - 5,
        "flight relocator growth",
    )
    require_int(savings["net"], 303 - layout.total_sectors, "net sector saving")
    require_int(
        report["bootstrap_max_total_sectors"],
        BOOTSTRAP_MAX_TOTAL_SECTORS,
        "report bootstrap sector cap",
    )
    require_int(
        report["bootstrap_sector_headroom"],
        BOOTSTRAP_MAX_TOTAL_SECTORS - layout.total_sectors,
        "report bootstrap sector headroom",
    )
    if report["runtime_module_loading"] is not False:
        fail("product-tail report claims a general runtime module ABI")
    if report["legacy_phase_keys_used_for_tail"] is not False:
        fail("product-tail report claims legacy phase keys address the tail")

    footer = inputs.tail[-SECTOR_BYTES:]
    footer_report = require_keys(
        report["footer"],
        {"sector", "magic", "abi", "crc16_ccitt"},
        "footer report",
    )
    require_int(
        footer_report["sector"], layout.footer_sector, "footer report sector"
    )
    if footer_report["magic"] != TAIL_MAGIC.decode("ascii"):
        fail("footer report magic drifted")
    require_int(footer_report["abi"], TAIL_ABI, "footer report ABI")
    require_crc(
        footer_report["crc16_ccitt"],
        crc16(footer[:TAIL_FOOTER_CRC_OFF]),
        "footer report CRC",
    )

    report_entries = report["entries"]
    if not isinstance(report_entries, list) or len(report_entries) != len(
        layout.entries
    ):
        fail("product-tail report does not contain exactly seven entries")
    component_inputs = {
        TAIL_KIND_PRECOMPUTE: (
            "entropy-precompute",
            inputs.entropy_raw,
            inputs.entropy_component,
        ),
        TAIL_KIND_ACQUIRE: (
            "hello-acquisition",
            inputs.hello_raw,
            inputs.hello_component,
        ),
        TAIL_KIND_HELLO_RESUME: (
            "hello-resume",
            inputs.hello_raw,
            inputs.hello_component,
        ),
        TAIL_KIND_FLIGHT: (
            "protected-flight",
            inputs.flight_raw,
            inputs.flight_component,
        ),
        TAIL_KIND_AUTHENTICATE: (
            "offline-authentication",
            inputs.auth_raw,
            inputs.auth_component,
        ),
    }
    for index, (item, entry) in enumerate(
        zip(report_entries, layout.entries, strict=True)
    ):
        if index < 2:
            expected_keys = {
                "kind",
                "name",
                "flags",
                "start_sector",
                "sectors",
                "image_bytes",
                "load",
                "entry",
                "crc16_ccitt",
                "sha256",
            }
            name = "root-stage" if index == 0 else "module-pack"
            checked = require_keys(item, expected_keys, f"{name} report")
            source = inputs.root_stage if index == 0 else inputs.module_pack
            require_hash(checked["sha256"], source, f"{name} report SHA-256")
        else:
            name, raw, component = component_inputs[entry.kind]
            expected_keys = {
                "kind",
                "name",
                "flags",
                "start_sector",
                "sectors",
                "image_bytes",
                "load",
                "entry",
                "crc16_ccitt",
                "raw_bytes",
                "raw_sha256",
                "component_sha256",
            }
            if entry.kind == TAIL_KIND_HELLO_RESUME:
                expected_keys.add("alias_of")
            checked = require_keys(item, expected_keys, f"{name} report")
            if entry.kind == TAIL_KIND_HELLO_RESUME and checked["alias_of"] != (
                "hello-acquisition"
            ):
                fail("resumed HELLO report alias binding drifted")
            require_int(
                checked["raw_bytes"], len(raw), f"{name} report raw bytes"
            )
            require_hash(checked["raw_sha256"], raw, f"{name} report raw SHA-256")
            require_hash(
                checked["component_sha256"],
                component,
                f"{name} report component SHA-256",
            )
            require_int(
                checked["image_bytes"],
                layout.component_stored_bytes[entry.kind],
                f"{name} report stored bytes",
            )

        require_int(checked["kind"], entry.kind, f"{name} report kind")
        if checked["name"] != name:
            fail(f"{name} report name drifted")
        require_int(checked["flags"], entry.flags, f"{name} report flags")
        require_int(
            checked["start_sector"], entry.start, f"{name} report start sector"
        )
        require_int(checked["sectors"], entry.sectors, f"{name} report sectors")
        require_int(
            checked["image_bytes"], entry.image_bytes, f"{name} report image bytes"
        )
        require_hex(checked["load"], entry.load, f"{name} report load")
        require_hex(checked["entry"], entry.entry, f"{name} report entry")
        require_crc(checked["crc16_ccitt"], entry.crc, f"{name} report CRC")

    expected_abi = {
        "TLS13_286_PRODUCT_TAIL_START_SECTOR": layout.prefix_sectors,
        "TLS13_286_PRODUCT_TAIL_SECTORS": layout.tail_sectors,
        "TLS13_286_PRODUCT_FINAL_SECTORS": layout.total_sectors,
        "TLS13_286_PRODUCT_ROOT_START_SECTOR": layout.root.start,
        "TLS13_286_PRODUCT_MODULE_PACK_START_SECTOR": layout.pack.start,
        "TLS13_286_PRODUCT_ENTROPY_START_SECTOR": layout.entropy.start,
        "TLS13_286_PRODUCT_ENTROPY_SECTORS": layout.entropy.sectors,
        "TLS13_286_PRODUCT_HELLO_START_SECTOR": layout.hello.start,
        "TLS13_286_PRODUCT_HELLO_SECTORS": layout.hello.sectors,
        "TLS13_286_PRODUCT_FLIGHT_START_SECTOR": layout.flight.start,
        "TLS13_286_PRODUCT_FLIGHT_SECTORS": layout.flight.sectors,
        "TLS13_286_PRODUCT_AUTH_START_SECTOR": layout.auth.start,
        "TLS13_286_PRODUCT_AUTH_SECTORS": layout.auth.sectors,
        "TLS13_286_PRODUCT_FOOTER_SECTOR": layout.footer_sector,
    }
    if inputs.abi != expected_abi:
        fail("generated product-tail ABI does not exactly match parsed geometry")

    sym_offsets = [
        offset
        for offset in range(len(inputs.prefix) - 7)
        if inputs.prefix.startswith(b"T13SYM02", offset)
    ]
    if len(sym_offsets) != 1:
        fail("universal prefix does not contain one K14 symmetric image")
    sym_offset = sym_offsets[0]
    product_sym = inputs.prefix[
        sym_offset : sym_offset + len(inputs.flight_sym_k14_raw)
    ]
    normalized_sym, pointer_offsets = normalize_product_symmetric_image(
        product_sym, inputs.flight_sym_k14_raw
    )
    if normalized_sym != inputs.flight_sym_k14_raw:
        fail("normalized K14 symmetric source differs from canonical flight input")
    reuse = require_keys(
        report["symmetric_reuse"],
        {
            "prefix_offset",
            "prefix_sector",
            "product_source_bytes",
            "product_source_sha256",
            "canonical_source_bytes",
            "canonical_source_sha256",
            "relocated_bytes",
            "relocated_sha256",
            "pre_tcp_normalization",
        },
        "symmetric-reuse report",
    )
    require_int(reuse["prefix_offset"], sym_offset, "symmetric source offset")
    require_int(
        reuse["prefix_sector"],
        sym_offset // SECTOR_BYTES,
        "symmetric source sector",
    )
    require_int(
        reuse["product_source_bytes"],
        len(product_sym),
        "product symmetric source bytes",
    )
    require_hash(
        reuse["product_source_sha256"],
        product_sym,
        "product symmetric source SHA-256",
    )
    require_int(
        reuse["canonical_source_bytes"],
        len(inputs.flight_sym_k14_raw),
        "canonical symmetric source bytes",
    )
    require_hash(
        reuse["canonical_source_sha256"],
        inputs.flight_sym_k14_raw,
        "canonical symmetric source SHA-256",
    )
    require_int(
        reuse["relocated_bytes"],
        len(inputs.flight_sym_raw),
        "relocated symmetric bytes",
    )
    require_hash(
        reuse["relocated_sha256"],
        inputs.flight_sym_raw,
        "relocated symmetric SHA-256",
    )
    normalization = require_keys(
        reuse["pre_tcp_normalization"],
        {
            "initial_pointer_from",
            "initial_pointer_to",
            "initial_pointer_offsets",
            "critical_tail_offset",
            "critical_tail_bytes",
            "canonical_byte_equivalent",
        },
        "symmetric normalization report",
    )
    require_hex(
        normalization["initial_pointer_from"],
        PRODUCT_SHA256_INITIAL_STATE,
        "product SHA initial-state pointer",
    )
    require_hex(
        normalization["initial_pointer_to"],
        CANONICAL_SHA256_INITIAL_STATE,
        "canonical SHA initial-state pointer",
    )
    if normalization["initial_pointer_offsets"] != list(pointer_offsets):
        fail("symmetric normalization report pointer offsets drifted")
    require_int(
        normalization["critical_tail_offset"],
        PRODUCT_CRITICAL_TAIL_OFFSET,
        "symmetric normalization tail offset",
    )
    require_int(
        normalization["critical_tail_bytes"],
        PRODUCT_CRITICAL_TAIL_BYTES,
        "symmetric normalization tail bytes",
    )
    if normalization["canonical_byte_equivalent"] is not True:
        fail("symmetric normalization report does not claim canonical identity")
    trusted_time = require_keys(
        report["trusted_time"],
        {
            "source",
            "publication_bytes",
            "status_last",
            "tail_component_present",
        },
        "trusted-time report",
    )
    if trusted_time["source"] != "silent coherent platform-UTC publication":
        fail("trusted-time source policy drifted")
    require_int(
        trusted_time["publication_bytes"], 9, "trusted-time publication bytes"
    )
    if (
        trusted_time["status_last"] is not True
        or trusted_time["tail_component_present"] is not False
    ):
        fail("trusted-time tail/status policy drifted")


def validate(inputs: Inputs, *, metadata: bool = True) -> Validated:
    prefix_sectors = validate_prefix(inputs.prefix)
    total_sectors, footer_sector, entries = parse_footer(
        inputs.tail, prefix_sectors
    )
    (
        root,
        pack,
        entropy,
        hello,
        hello_resume,
        flight,
        auth,
    ) = entries

    def image(entry: TailEntry) -> bytes:
        offset = (entry.start - prefix_sectors) * SECTOR_BYTES
        return inputs.tail[offset : offset + entry.sectors * SECTOR_BYTES]

    tail_footer_offset = len(inputs.tail) - SECTOR_BYTES
    root_image = image(root)
    pack_image = image(pack)
    entropy_image = image(entropy)
    hello_image = image(hello)
    flight_image = image(flight)
    auth_image = image(auth)

    validate_root(root_image, root)
    validate_module_pack(pack_image, pack)
    entropy_stored_bytes, entropy_points = validate_controller(
        entropy_image,
        inputs.entropy_raw,
        entropy,
        controller_magic=ENTROPY_MAGIC,
        abi_expected=TAIL_ABI,
        entry_count_expected=ENTROPY_ENTRY_COUNT,
        entry_count_off=12,
        entry_table_off=14,
        load=CONTROLLER_LOAD,
        limit=CONTROLLER_LIMIT,
        selected_entry_index=0,
        label="entropy-precompute",
    )
    hello_stored_bytes, hello_points = validate_controller(
        hello_image,
        inputs.hello_raw,
        hello,
        controller_magic=HELLO_MAGIC,
        abi_expected=TAIL_ABI,
        entry_count_expected=HELLO_ENTRY_COUNT,
        entry_count_off=12,
        entry_table_off=14,
        load=CONTROLLER_LOAD,
        limit=CONTROLLER_LIMIT,
        selected_entry_index=0,
        label="HELLO acquisition",
    )
    resume_stored_bytes, resume_points = validate_controller(
        hello_image,
        inputs.hello_raw,
        hello_resume,
        controller_magic=HELLO_MAGIC,
        abi_expected=TAIL_ABI,
        entry_count_expected=HELLO_ENTRY_COUNT,
        entry_count_off=12,
        entry_table_off=14,
        load=CONTROLLER_LOAD,
        limit=CONTROLLER_LIMIT,
        selected_entry_index=1,
        label="HELLO resumption",
    )
    flight_stored_bytes, _ = validate_controller(
        flight_image,
        inputs.flight_raw,
        flight,
        controller_magic=FLIGHT_MAGIC,
        abi_expected=TAIL_ABI,
        entry_count_expected=FLIGHT_ENTRY_COUNT,
        entry_count_off=12,
        entry_table_off=14,
        load=FLIGHT_LOAD,
        limit=FLIGHT_LIMIT,
        selected_entry_index=0,
        label="protected-flight coordinator",
    )
    auth_stored_bytes, _ = validate_controller(
        auth_image,
        inputs.auth_raw,
        auth,
        controller_magic=AUTH_MAGIC,
        abi_expected=TAIL_ABI,
        entry_count_expected=AUTH_ENTRY_COUNT,
        entry_count_off=12,
        entry_table_off=14,
        load=CONTROLLER_LOAD,
        limit=CONTROLLER_LIMIT,
        selected_entry_index=0,
        label="offline authentication",
    )
    if resume_stored_bytes != hello_stored_bytes or resume_points != hello_points:
        fail("HELLO aliases did not validate against one immutable entry table")

    if root_image != inputs.root_stage:
        fail("product tail does not contain the exact built root stage")
    if pack_image != inputs.module_pack:
        fail("product tail does not contain the exact built module pack")
    if entropy_image != inputs.entropy_component:
        fail("product tail does not contain the exact built entropy component")
    if hello_image != inputs.hello_component:
        fail("product tail does not contain the exact built HELLO component")
    if flight_image != inputs.flight_component:
        fail("product tail does not contain the exact built flight component")
    if auth_image != inputs.auth_component:
        fail("product tail does not contain the exact built auth component")
    expected_tail = (
        inputs.root_stage
        + inputs.module_pack
        + inputs.entropy_component
        + inputs.hello_component
        + inputs.flight_component
        + inputs.auth_component
        + inputs.tail[tail_footer_offset:]
    )
    if inputs.tail != expected_tail:
        fail("product-tail bytes are not the canonical component concatenation")

    tail_sectors = len(inputs.tail) // SECTOR_BYTES
    stored = {
        TAIL_KIND_PRECOMPUTE: entropy_stored_bytes,
        TAIL_KIND_ACQUIRE: hello_stored_bytes,
        TAIL_KIND_HELLO_RESUME: hello_stored_bytes,
        TAIL_KIND_FLIGHT: flight_stored_bytes,
        TAIL_KIND_AUTHENTICATE: auth_stored_bytes,
    }
    layout = Validated(
        prefix_sectors=prefix_sectors,
        total_sectors=total_sectors,
        footer_sector=footer_sector,
        tail_sectors=tail_sectors,
        entries=entries,
        root=root,
        pack=pack,
        entropy=entropy,
        hello=hello,
        hello_resume=hello_resume,
        flight=flight,
        auth=auth,
        entropy_stored_bytes=entropy_stored_bytes,
        entropy_entry=entropy_points[0],
        hello_stored_bytes=hello_stored_bytes,
        hello_entry=hello_points[0],
        hello_resume_entry=hello_points[1],
        component_stored_bytes=stored,
    )
    if metadata:
        validate_report_and_abi_v2(inputs, layout)
    return layout


def import_gate(path: Path, name: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        fail(f"cannot import executable gate {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def run_executable_path(
    inputs: Inputs,
    layout: Validated,
    bootstrap_path: Path,
) -> None:
    """Walk the exact footer/root/component chain through product machine code."""

    if not bootstrap_path.is_file():
        fail(f"missing product bootstrap for executable tail gate: {bootstrap_path}")
    bootstrap = bootstrap_path.read_bytes()
    if len(bootstrap) != 3 * SECTOR_BYTES:
        fail("product bootstrap is not exactly three sectors")
    full_disk = inputs.prefix + inputs.tail
    sectors = [
        full_disk[offset : offset + SECTOR_BYTES]
        for offset in range(0, len(full_disk), SECTOR_BYTES)
    ]

    bootstrap_gate = import_gate(
        BOOTSTRAP_GATE, "_seed_tls13_286_bootstrap_gate"
    )
    bootstrap_tail = bootstrap_gate.Tail(
        sectors=sectors,
        total_sectors=layout.total_sectors,
        stage_sector=layout.root.start,
        stage_sectors=layout.root.sectors,
        stage_bytes=layout.root.image_bytes,
        stage_image=inputs.root_stage,
    )
    bootstrap_machine = bootstrap_gate.Machine(bootstrap, bootstrap_tail)

    def stop_at_root(
        machine: Any, address: int, _size: int, _user_data: object
    ) -> None:
        if address == layout.root.entry:
            bootstrap_machine.stop_reason = "stage"
            machine.emu_stop()

    bootstrap_machine.uc.hook_add(
        bootstrap_gate.UC_HOOK_CODE, stop_at_root
    )
    bootstrap_machine.call(expect="stage")
    expected_bootstrap_reads = [layout.footer_sector] + list(
        range(layout.root.start, layout.root.end)
    )
    if bootstrap_machine.carry:
        fail("real bootstrap reached the root stage with carry")
    if bootstrap_machine.reads != expected_bootstrap_reads:
        fail(
            "real bootstrap tail read sequence drifted: "
            f"{bootstrap_machine.reads!r}"
        )
    if bytes(
        bootstrap_machine.uc.mem_read(ROOT_LOAD, len(inputs.root_stage))
    ) != inputs.root_stage:
        fail("real bootstrap did not load the exact root-stage bytes")

    root_gate = import_gate(ROOT_GATE, "_seed_tls13_286_root_gate")
    root_tail = root_gate.Tail(
        sectors=sectors,
        footer=inputs.tail[-SECTOR_BYTES:],
        pack_start=layout.pack.start,
        component_start=layout.entropy.start,
        controller=inputs.entropy_raw,
    )
    root_machine = root_gate.Machine(inputs.root_stage, root_tail)

    def stop_at_entropy(
        machine: Any, address: int, _size: int, _user_data: object
    ) -> None:
        if address == layout.entropy_entry:
            root_machine.stop_reason = "controller"
            machine.emu_stop()

    root_machine.uc.hook_add(root_gate.UC_HOOK_CODE, stop_at_entropy)
    root_machine.run(expect="controller")
    expected_root_reads = list(range(layout.pack.start, layout.pack.end)) + list(
        range(layout.entropy.start, layout.entropy.end)
    )
    if root_machine.aborted:
        fail("real root stage aborted the valid product tail")
    if root_machine.reads != expected_root_reads:
        fail(f"real root-stage tail read sequence drifted: {root_machine.reads!r}")
    if bytes(
        root_machine.uc.mem_read(ENTROPY_LOAD, len(inputs.entropy_raw))
    ) != inputs.entropy_raw:
        fail("real root stage did not decode the exact entropy controller")

    # Re-enter through the exported one-way chain service, as the entropy
    # controller does after status-last publication.  A normal CALL/RET loader
    # transition would return into bytes just overwritten by HELLO; this gate
    # requires the root-resident service to land directly at HELLO's validated
    # entry instead.
    chain_entry = word(
        inputs.root_stage, ROOT_SERVICE_CHAIN_POINTER - ROOT_LOAD
    )
    if not ROOT_ENTRY <= chain_entry < ROOT_LIMIT:
        fail("root component-chain pointer escaped the root stage")

    def stop_at_hello(
        machine: Any, address: int, _size: int, _user_data: object
    ) -> None:
        if address == layout.hello_entry:
            root_machine.stop_reason = "hello"
            machine.emu_stop()

    root_machine.uc.hook_add(root_gate.UC_HOOK_CODE, stop_at_hello)
    root_machine.stop_reason = ""
    for register in (
        root_gate.UC_X86_REG_CS,
        root_gate.UC_X86_REG_DS,
        root_gate.UC_X86_REG_ES,
        root_gate.UC_X86_REG_SS,
    ):
        root_machine.uc.reg_write(register, 0)
    root_machine.uc.reg_write(root_gate.UC_X86_REG_SP, 0x7FFE)
    root_machine.uc.mem_write(
        0x7FFE, struct.pack("<H", root_gate.RETURN_SENTINEL)
    )
    root_machine.uc.reg_write(root_gate.UC_X86_REG_AX, TAIL_KIND_ACQUIRE)
    root_machine.uc.reg_write(root_gate.UC_X86_REG_EFLAGS, 0x0002)
    root_machine.uc.emu_start(chain_entry, 0x10000, count=20_000_000)
    if root_machine.stop_reason != "hello":
        fail(
            "root component chain did not transfer directly to HELLO: "
            f"IP={root_machine.uc.reg_read(root_gate.UC_X86_REG_IP):04x} "
            f"reason={root_machine.stop_reason!r}"
        )
    if root_machine.aborted:
        fail("real root component chain aborted the valid HELLO")
    expected_chain_reads = expected_root_reads + list(
        range(layout.hello.start, layout.hello.end)
    )
    if root_machine.reads != expected_chain_reads:
        fail(
            "real entropy-to-HELLO tail read sequence drifted: "
            f"{root_machine.reads!r}"
        )
    if bytes(
        root_machine.uc.mem_read(ENTROPY_LOAD, len(inputs.hello_raw))
    ) != inputs.hello_raw:
        fail("real root chain did not decode the exact HELLO controller")
    if root_machine.uc.reg_read(root_gate.UC_X86_REG_AX) & 0xFF != 1:
        fail("real root chain lost cold/human mode at HELLO handoff")
    if root_machine.uc.reg_read(root_gate.UC_X86_REG_BX) != root_gate.CRYPTO_SEG:
        fail("real root chain passed the wrong crypto segment to HELLO")
    if root_machine.uc.reg_read(root_gate.UC_X86_REG_SI) != 0xB602:
        fail("real root chain passed the wrong footer offset to HELLO")

    # Exercise every remaining one-way root transition without executing the
    # controller body.  This proves the two HELLO kinds are true directory
    # aliases, the 0x6300 flight destination is admitted, and low auth/HELLO
    # controller loads preserve the prior flight through handoff.  The auth
    # body may subsequently retire that disposable code with a module decode.
    next_stop = {"address": -1, "reason": ""}

    def stop_at_selected(
        machine: Any, address: int, _size: int, _user_data: object
    ) -> None:
        if address == next_stop["address"]:
            root_machine.stop_reason = next_stop["reason"]
            machine.emu_stop()

    root_machine.uc.hook_add(root_gate.UC_HOOK_CODE, stop_at_selected)
    expected_reads = list(root_machine.reads)

    def chain_component(
        *,
        kind: int,
        entry: TailEntry,
        raw: bytes,
        load: int,
        reason: str,
    ) -> None:
        next_stop["address"] = entry.entry
        next_stop["reason"] = reason
        root_machine.stop_reason = ""
        for register in (
            root_gate.UC_X86_REG_CS,
            root_gate.UC_X86_REG_ES,
            root_gate.UC_X86_REG_SS,
        ):
            root_machine.uc.reg_write(register, 0)
        # A disposable controller may return from transport/crypto callbacks
        # with DS clobbered.  The fixed root service must recover its own
        # segment rather than inheriting this untrusted transition state.
        root_machine.uc.reg_write(root_gate.UC_X86_REG_DS, 0x1234)
        root_machine.uc.reg_write(root_gate.UC_X86_REG_SP, 0x7FFE)
        root_machine.uc.mem_write(
            0x7FFE, struct.pack("<H", root_gate.RETURN_SENTINEL)
        )
        root_machine.uc.reg_write(root_gate.UC_X86_REG_AX, kind)
        root_machine.uc.reg_write(root_gate.UC_X86_REG_EFLAGS, 0x0002)
        root_machine.uc.emu_start(chain_entry, 0x10000, count=20_000_000)
        if root_machine.stop_reason != reason or root_machine.aborted:
            fail(
                f"root component chain did not transfer to {reason}: "
                f"IP={root_machine.uc.reg_read(root_gate.UC_X86_REG_IP):04x}"
            )
        expected_reads.extend(range(entry.start, entry.end))
        if root_machine.reads != expected_reads:
            fail(f"root {reason} read sequence drifted: {root_machine.reads!r}")
        if bytes(root_machine.uc.mem_read(load, len(raw))) != raw:
            fail(f"root did not decode the exact {reason} image")

    chain_component(
        kind=TAIL_KIND_FLIGHT,
        entry=layout.flight,
        raw=inputs.flight_raw,
        load=FLIGHT_LOAD,
        reason="flight-capture",
    )
    chain_component(
        kind=TAIL_KIND_AUTHENTICATE,
        entry=layout.auth,
        raw=inputs.auth_raw,
        load=CONTROLLER_LOAD,
        reason="offline-auth",
    )
    if bytes(root_machine.uc.mem_read(FLIGHT_LOAD, len(inputs.flight_raw))) != (
        inputs.flight_raw
    ):
        fail("offline-auth load damaged the resident flight coordinator")
    chain_component(
        kind=TAIL_KIND_HELLO_RESUME,
        entry=layout.hello_resume,
        raw=inputs.hello_raw,
        load=CONTROLLER_LOAD,
        reason="hello-resume",
    )
    chain_component(
        kind=TAIL_KIND_FLIGHT,
        entry=layout.flight,
        raw=inputs.flight_raw,
        load=FLIGHT_LOAD,
        reason="flight-resumed",
    )


def recalculate_footer(tail: bytearray) -> None:
    footer = len(tail) - SECTOR_BYTES
    put_word(
        tail,
        footer + TAIL_FOOTER_CRC_OFF,
        crc16(bytes(tail[footer : footer + TAIL_FOOTER_CRC_OFF])),
    )


def expect_reject(
    label: str,
    inputs: Inputs,
    mutation: Callable[[Inputs], Inputs],
    *,
    metadata: bool = False,
) -> None:
    hostile = mutation(inputs)
    try:
        validate(hostile, metadata=metadata)
    except AssertionError:
        return
    fail(f"hostile tail case was accepted: {label}")


def run_tamper_matrix(inputs: Inputs, layout: Validated) -> int:
    footer = len(inputs.tail) - SECTOR_BYTES
    directory = footer + TAIL_DIRECTORY_OFF
    entropy_offset = (
        layout.entropy.start - layout.prefix_sectors
    ) * SECTOR_BYTES

    def mutate_tail(change: Callable[[bytearray], None]) -> Callable[[Inputs], Inputs]:
        def mutation(value: Inputs) -> Inputs:
            tail = bytearray(value.tail)
            change(tail)
            return replace(value, tail=bytes(tail))

        return mutation

    cases: list[tuple[str, Callable[[Inputs], Inputs], bool]] = []
    cases.append(
        (
            "footer CRC",
            mutate_tail(
                lambda tail: tail.__setitem__(
                    footer + TAIL_FOOTER_CRC_OFF,
                    tail[footer + TAIL_FOOTER_CRC_OFF] ^ 1,
                )
            ),
            False,
        )
    )
    cases.append(
        (
            "footer magic",
            mutate_tail(lambda tail: tail.__setitem__(footer, tail[footer] ^ 1)),
            False,
        )
    )

    def bad_directory_flags(tail: bytearray) -> None:
        put_word(tail, directory + 2, TAIL_FLAG_PRODUCT | TAIL_FLAG_RAW_LZ4)
        recalculate_footer(tail)

    cases.append(
        ("directory semantics", mutate_tail(bad_directory_flags), False)
    )
    cases.append(
        (
            "component CRC",
            mutate_tail(lambda tail: tail.__setitem__(0, tail[0] ^ 1)),
            False,
        )
    )

    def bad_component_block(tail: bytearray) -> None:
        block = entropy_offset + LZ4_HEADER.size
        tail[block + 31] ^= 1

    cases.append(
        ("compressed component", mutate_tail(bad_component_block), False)
    )
    cases.append(
        (
            "component padding",
            mutate_tail(
                lambda tail: tail.__setitem__(
                    entropy_offset + layout.entropy_stored_bytes, 0xA5
                )
            ),
            False,
        )
    )

    def bad_footer_padding(tail: bytearray) -> None:
        used_directory = directory + len(layout.entries) * TAIL_ENTRY_BYTES
        tail[used_directory] = 0xA5
        recalculate_footer(tail)

    cases.append(("footer padding", mutate_tail(bad_footer_padding), False))

    def duplicate_kind(tail: bytearray) -> None:
        precompute = directory + 2 * TAIL_ENTRY_BYTES
        put_word(tail, precompute, TAIL_KIND_ROOT)
        recalculate_footer(tail)

    cases.append(("duplicate directory kind", mutate_tail(duplicate_kind), False))

    def overlap_extent(tail: bytearray) -> None:
        precompute = directory + 2 * TAIL_ENTRY_BYTES
        put_word(tail, precompute + 4, layout.pack.start + 1)
        recalculate_footer(tail)

    cases.append(("overlapping extents", mutate_tail(overlap_extent), False))

    def bad_prefix_total(value: Inputs) -> Inputs:
        prefix = bytearray(value.prefix)
        put_word(prefix, CORE_TOTAL_SECTORS_OFF, layout.prefix_sectors + 1)
        return replace(value, prefix=bytes(prefix))

    cases.append(("prefix total", bad_prefix_total, False))

    def bad_report_total(value: Inputs) -> Inputs:
        report = copy.deepcopy(value.report)
        report["final_total_sectors"] = layout.total_sectors + 1
        return replace(value, report=report)

    cases.append(("report total", bad_report_total, True))

    def bad_abi_total(value: Inputs) -> Inputs:
        abi = dict(value.abi)
        abi["TLS13_286_PRODUCT_FINAL_SECTORS"] = layout.total_sectors + 1
        return replace(value, abi=abi)

    cases.append(("ABI total", bad_abi_total, True))

    for label, mutation, metadata in cases:
        expect_reject(label, inputs, mutation, metadata=metadata)
    return len(cases)


def validate_final_image(
    path: Path,
    inputs: Inputs,
    layout: Validated,
) -> None:
    final = path.read_bytes()
    expected_bytes = layout.total_sectors * SECTOR_BYTES
    if len(final) != expected_bytes:
        fail(
            f"final SEED.SYS is {len(final)} bytes, expected {expected_bytes}"
        )
    prefix_bytes = len(inputs.prefix)
    if final[:CORE_TOTAL_SECTORS_OFF] != inputs.prefix[:CORE_TOTAL_SECTORS_OFF]:
        fail("final SEED.SYS changed bytes before the total-sector header word")
    if word(final, CORE_TOTAL_SECTORS_OFF) != layout.total_sectors:
        fail("final SEED.SYS header does not publish the generated final total")
    after_total = CORE_TOTAL_SECTORS_OFF + 2
    if final[after_total:prefix_bytes] != inputs.prefix[after_total:]:
        fail("final SEED.SYS prefix differs outside its total-sector word")
    if final[prefix_bytes:] != inputs.tail:
        fail("final SEED.SYS does not append the exact generated product tail")


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise SystemExit(f"missing {label}: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, default=DEFAULT_PREFIX)
    parser.add_argument("--tail", type=Path, default=DEFAULT_TAIL)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--abi", type=Path, default=DEFAULT_ABI)
    parser.add_argument("--root-stage", type=Path, default=DEFAULT_ROOT_STAGE)
    parser.add_argument("--module-pack", type=Path, default=DEFAULT_MODULE_PACK)
    parser.add_argument(
        "--entropy-component", type=Path, default=DEFAULT_ENTROPY_COMPONENT
    )
    parser.add_argument("--entropy-raw", type=Path, default=DEFAULT_ENTROPY_RAW)
    parser.add_argument(
        "--hello-component", type=Path, default=DEFAULT_HELLO_COMPONENT
    )
    parser.add_argument("--hello-raw", type=Path, default=DEFAULT_HELLO_RAW)
    parser.add_argument(
        "--flight-component", type=Path, default=DEFAULT_FLIGHT_COMPONENT
    )
    parser.add_argument("--flight-raw", type=Path, default=DEFAULT_FLIGHT_RAW)
    parser.add_argument(
        "--flight-sym-k14-raw",
        type=Path,
        default=DEFAULT_FLIGHT_SYM_K14_RAW,
    )
    parser.add_argument(
        "--flight-sym-raw", type=Path, default=DEFAULT_FLIGHT_SYM_RAW
    )
    parser.add_argument(
        "--auth-component", type=Path, default=DEFAULT_AUTH_COMPONENT
    )
    parser.add_argument("--auth-raw", type=Path, default=DEFAULT_AUTH_RAW)
    parser.add_argument("--bootstrap", type=Path, default=DEFAULT_BOOTSTRAP)
    parser.add_argument(
        "--skip-executable-path",
        action="store_true",
        help="run only the independent host parser and hostile matrix",
    )
    parser.add_argument(
        "--final-core",
        type=Path,
        help="also bind a final linked SEED.SYS (header total + exact tail)",
    )
    args = parser.parse_args()

    for path, label in (
        (args.prefix, "286 K14-complete prefix"),
        (args.tail, "286 product tail"),
        (args.report, "286 product-tail report"),
        (args.abi, "286 product-tail ABI"),
        (args.root_stage, "286 root stage"),
        (args.module_pack, "286 module pack"),
        (args.entropy_component, "286 entropy component"),
        (args.entropy_raw, "286 raw entropy controller"),
        (args.hello_component, "286 HELLO component"),
        (args.hello_raw, "286 raw HELLO controller"),
        (args.flight_component, "286 protected-flight component"),
        (args.flight_raw, "286 raw protected-flight controller"),
        (args.flight_sym_k14_raw, "K14 symmetric reuse source"),
        (args.flight_sym_raw, "286 raw protected-flight symmetric image"),
        (args.auth_component, "286 authentication component"),
        (args.auth_raw, "286 raw authentication controller"),
    ):
        require_file(path, label)
    if not args.skip_executable_path:
        require_file(args.bootstrap, "286 product bootstrap")
    if args.final_core is not None:
        require_file(args.final_core, "final linked SEED.SYS")

    inputs = Inputs(
        prefix=args.prefix.read_bytes(),
        tail=args.tail.read_bytes(),
        report=read_json(args.report),
        abi=parse_abi(args.abi),
        root_stage=args.root_stage.read_bytes(),
        module_pack=args.module_pack.read_bytes(),
        entropy_component=args.entropy_component.read_bytes(),
        entropy_raw=args.entropy_raw.read_bytes(),
        hello_component=args.hello_component.read_bytes(),
        hello_raw=args.hello_raw.read_bytes(),
        flight_component=args.flight_component.read_bytes(),
        flight_raw=args.flight_raw.read_bytes(),
        flight_sym_k14_raw=args.flight_sym_k14_raw.read_bytes(),
        flight_sym_raw=args.flight_sym_raw.read_bytes(),
        auth_component=args.auth_component.read_bytes(),
        auth_raw=args.auth_raw.read_bytes(),
        prefix_path=args.prefix,
        tail_path=args.tail,
    )
    layout = validate(inputs)
    hostile_cases = run_tamper_matrix(inputs, layout)
    if not args.skip_executable_path:
        run_executable_path(inputs, layout, args.bootstrap)
    if args.final_core is not None:
        validate_final_image(args.final_core, inputs, layout)

    print("TLS13 286 PRODUCT TAIL PASS")
    print(
        f"  prefix {layout.prefix_sectors} + tail {layout.tail_sectors} = "
        f"{layout.total_sectors} sectors; footer {layout.footer_sector} PASS"
    )
    print(
        "  exact root4 + pack44 + entropy + aliased HELLO + flight/auth "
        "component graph PASS"
    )
    print("  footer/directory/CRC/bounds/canonical-padding matrix PASS")
    print("  generated report + final-total ABI binding PASS")
    if not args.skip_executable_path:
        print(
            "  real bootstrap/root one-way entropy/acquire/flight/auth/resume "
            "transitions PASS"
        )
    if args.final_core is not None:
        print("  final SEED.SYS header total + exact appended tail PASS")
    print(f"  hostile tamper matrix {hostile_cases}/{hostile_cases} PASS")


if __name__ == "__main__":
    main()
