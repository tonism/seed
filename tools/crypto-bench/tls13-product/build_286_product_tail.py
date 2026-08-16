#!/usr/bin/env python3
"""Build the exact appended TLS 1.3 286 product tail.

The input is a sector-aligned, K14-complete SEED.SYS prefix whose header still
describes only that prefix.  This builder appends, in fixed order:

* the four-sector low root stage;
* the 44-sector cached asymmetric-module pack;
* compressed entropy, HELLO, protected-flight, and authentication images;
* one final discovery/footer sector.

Before TCP, HELLO converts the already-shipped 8088 K14 symmetric image
to its exact canonical form by verifying the already-canonical SHA initial-state
operand and restoring the 288-byte SHA tail.  The protected-flight coordinator
then byte-exactly relocates that canonical stage.  Trusted UTC is
parent-published before bootstrap/root entry, so neither duplicate is stored in
this tail.

The output is only the appended byte range.  The final NASM link includes it at
``core_image_end`` so the resident header's total-sector word is resolved by
the assembler, while the footer independently carries the same final total.
No component becomes a FAT file and no legacy eight-bit phase key addresses
any byte in this tail.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150"

ROOT_BUILDER = HERE / "build_286_root_stage.py"
ENTROPY_BUILDER = HERE / "build_286_entropy_controller.py"
HELLO_BUILDER = HERE / "build_286_hello_controller.py"
FLIGHT_SYM_BUILDER = HERE / "build_286_flight_sym.py"
FLIGHT_BUILDER = HERE / "build_286_flight.py"
AUTH_BUILDER = HERE / "build_286_auth.py"
ROOT_STAGE = BUILD / "tls13-286-root-stage.bin"
MODULE_PACK = BUILD / "crypto-bench/tls13-286-modules.bin"
ENTROPY_RAW = BUILD / "tls13-286-entropy.bin"
ENTROPY_COMPONENT = BUILD / "tls13-286-entropy-component.bin"
HELLO_RAW = BUILD / "tls13-286-hello.bin"
HELLO_COMPONENT = BUILD / "tls13-286-hello-component.bin"
FLIGHT_RAW = BUILD / "tls13-286-flight.bin"
FLIGHT_COMPONENT = BUILD / "tls13-286-flight-component.bin"
FLIGHT_SYM_RAW = BUILD / "tls13-286-flight-sym.bin"
FLIGHT_SYM_K14_RAW = BUILD / "tls13-286-flight-sym-k14.bin"
AUTH_RAW = BUILD / "tls13-286-auth.bin"
AUTH_COMPONENT = BUILD / "tls13-286-auth-component.bin"

DEFAULT_PREFIX = BUILD / "tls13-286-tail-base/SEED.SYS"
DEFAULT_TAIL = BUILD / "tls13-286-product-tail.bin"
DEFAULT_ABI = BUILD / "tls13-286-tail-abi.inc"
DEFAULT_REPORT = BUILD / "tls13-286-product-tail.json"

SECTOR_BYTES = 512
CORE_MAGIC = b"SEEDCORE"
CORE_MAGIC_OFF = 3
CORE_TOTAL_SECTORS_OFF = 0x11
BOOTSTRAP_MAX_TOTAL_SECTORS = 320
FAT_DATA_SECTORS = 309
PACKAGED_AUXILIARY_SECTORS = 15
UNIVERSAL_MAX_SEED_SECTORS = (
    FAT_DATA_SECTORS - PACKAGED_AUXILIARY_SECTORS - 1
)

TAIL_MAGIC = b"S286TL02"
ABI_VERSION = 2
TAIL_HEADER_BYTES = 32
TAIL_ENTRY_BYTES = 16
TAIL_FOOTER_CRC_OFF = 510
TAIL_ENTRY = struct.Struct("<HHHHHHHH")

TAIL_FLAG_PRODUCT = 0x0001
TAIL_FLAG_RAW_LZ4 = 0x0002
TAIL_KIND_ROOT_STAGE = 1
TAIL_KIND_MODULE_PACK = 2
TAIL_KIND_HELLO_RESUME = 4
TAIL_KIND_ACQUIRE = 5
TAIL_KIND_AUTHENTICATE = 6
TAIL_KIND_PRECOMPUTE = 8
TAIL_KIND_FLIGHT = 9

ROOT_LOAD = 0x3400
ROOT_ENTRY = 0x391E
ROOT_SECTORS = 4
ROOT_BYTES = ROOT_SECTORS * SECTOR_BYTES
MODULE_PACK_SECTORS = 44
MODULE_PACK_BYTES = MODULE_PACK_SECTORS * SECTOR_BYTES
CONTROLLER_LOAD = 0x1800
CONTROLLER_LIMIT = 0x3400
FLIGHT_LOAD = 0x6300
FLIGHT_LIMIT = 0x7380

LZ4_HEADER = struct.Struct("<4sHHHH")


def load_runtime_builder():
    path = HERE / "build_286_runtime_abi.py"
    spec = importlib.util.spec_from_file_location("seed_286_runtime_abi", path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load runtime ABI helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


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


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def run_builder(path: Path) -> None:
    subprocess.run([sys.executable, str(path)], cwd=ROOT, check=True)


def read_prefix(path: Path) -> tuple[bytes, int]:
    prefix = path.read_bytes()
    if not prefix or len(prefix) % SECTOR_BYTES:
        raise AssertionError("286 tail prefix is not a nonempty sector-aligned image")
    if prefix[CORE_MAGIC_OFF : CORE_MAGIC_OFF + len(CORE_MAGIC)] != CORE_MAGIC:
        raise AssertionError("286 tail prefix has no SEEDCORE header")
    prefix_sectors = len(prefix) // SECTOR_BYTES
    declared = int.from_bytes(
        prefix[CORE_TOTAL_SECTORS_OFF : CORE_TOTAL_SECTORS_OFF + 2], "little"
    )
    if declared != prefix_sectors:
        raise AssertionError(
            f"286 tail prefix header declares {declared} sectors, "
            f"file has {prefix_sectors}"
        )
    if prefix[-SECTOR_BYTES : -SECTOR_BYTES + len(TAIL_MAGIC)] == TAIL_MAGIC:
        raise AssertionError("286 tail prefix already ends in a product-tail footer")
    return prefix, prefix_sectors


def validate_root_stage(image: bytes) -> None:
    if len(image) != ROOT_BYTES:
        raise AssertionError(
            f"286 root stage is {len(image)} bytes, expected {ROOT_BYTES}"
        )
    table_off = 0x3910 - ROOT_LOAD
    if image[table_off : table_off + 8] != b"S286RT02":
        raise AssertionError("286 root-stage service table magic drifted")
    entry = int.from_bytes(image[table_off + 8 : table_off + 10], "little")
    if entry != ROOT_ENTRY:
        raise AssertionError(
            f"286 root-stage entry is {entry:#06x}, expected {ROOT_ENTRY:#06x}"
        )


def validate_module_pack(image: bytes) -> None:
    if len(image) != MODULE_PACK_BYTES:
        raise AssertionError(
            f"286 module pack is {len(image)} bytes, expected {MODULE_PACK_BYTES}"
        )
    if image[:8] != b"S286PK02":
        raise AssertionError("286 module-pack magic drifted")
    abi, count, header_bytes, entry_bytes = struct.unpack_from("<HHHH", image, 8)
    total_bytes = struct.unpack_from("<I", image, 16)[0]
    if abi != ABI_VERSION or count != 5:
        raise AssertionError("286 module-pack ABI/count drifted")
    if header_bytes != SECTOR_BYTES or entry_bytes != 24:
        raise AssertionError("286 module-pack directory geometry drifted")
    if total_bytes != len(image):
        raise AssertionError("286 module-pack header length is not exact")


def validate_controller(
    raw: bytes,
    component: bytes,
    *,
    magic: bytes,
    abi: int,
    entry_count: int,
    entry_count_off: int | None,
    entry_table_off: int,
    load: int,
    limit: int,
    label: str,
) -> tuple[tuple[int, ...], int, int]:
    if raw[:8] != magic:
        raise AssertionError(f"286 {label} magic drifted")
    actual_abi, raw_bytes = struct.unpack_from("<HH", raw, 8)
    actual_entry_count = (
        struct.unpack_from("<H", raw, entry_count_off)[0]
        if entry_count_off is not None
        else entry_count
    )
    if (actual_abi, raw_bytes, actual_entry_count) != (
        abi,
        len(raw),
        entry_count,
    ):
        raise AssertionError(f"286 {label} header drifted")
    entries = struct.unpack_from(f"<{entry_count}H", raw, entry_table_off)
    if len(set(entries)) != entry_count or any(
        not load <= entry < load + len(raw) for entry in entries
    ):
        raise AssertionError(f"286 {label} entry table escaped its raw image")
    if len(raw) > limit - load:
        raise AssertionError(f"286 {label} exceeds its fixed destination window")

    if len(component) % SECTOR_BYTES:
        raise AssertionError(f"286 {label} component is not sector padded")
    magic, encoded_raw, block_bytes, encoded_crc, reserved = (
        LZ4_HEADER.unpack_from(component)
    )
    stored_bytes = LZ4_HEADER.size + block_bytes
    if magic != b"LZ4B" or reserved:
        raise AssertionError(f"286 {label} component header drifted")
    if encoded_raw != len(raw) or encoded_crc != crc16(raw):
        raise AssertionError(
            f"286 {label} component does not authenticate its raw image"
        )
    if stored_bytes > len(component):
        raise AssertionError(f"286 {label} component block exceeds its sectors")
    if any(component[stored_bytes:]):
        raise AssertionError(
            f"286 {label} component sector padding is not canonical zero"
        )
    return entries, stored_bytes, encoded_crc


def component_report(
    *,
    kind: int,
    name: str,
    start: int,
    sectors: int,
    stored_bytes: int,
    load: int,
    entry: int,
    checksum: int,
    raw: bytes,
    component: bytes,
    alias_of: str | None = None,
) -> dict[str, object]:
    report: dict[str, object] = {
        "kind": kind,
        "name": name,
        "flags": TAIL_FLAG_PRODUCT | TAIL_FLAG_RAW_LZ4,
        "start_sector": start,
        "sectors": sectors,
        "image_bytes": stored_bytes,
        "load": f"0x{load:04x}",
        "entry": f"0x{entry:04x}",
        "crc16_ccitt": f"{checksum:04X}",
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "component_sha256": hashlib.sha256(component).hexdigest(),
    }
    if alias_of is not None:
        report["alias_of"] = alias_of
    return report


def make_footer(
    *,
    total_sectors: int,
    tail_start: int,
    tail_sectors: int,
    entries: tuple[bytes, ...],
) -> bytes:
    if not entries:
        raise AssertionError("286 product tail has no directory entries")
    directory_end = TAIL_HEADER_BYTES + len(entries) * TAIL_ENTRY_BYTES
    if directory_end > TAIL_FOOTER_CRC_OFF:
        raise AssertionError("286 product-tail directory exceeds its footer")
    footer = bytearray(SECTOR_BYTES)
    struct.pack_into(
        "<8sHHHHHHH",
        footer,
        0,
        TAIL_MAGIC,
        ABI_VERSION,
        TAIL_HEADER_BYTES,
        total_sectors,
        tail_start,
        tail_sectors,
        len(entries),
        TAIL_ENTRY_BYTES,
    )
    for index, entry in enumerate(entries):
        start = TAIL_HEADER_BYTES + index * TAIL_ENTRY_BYTES
        footer[start : start + TAIL_ENTRY_BYTES] = entry
    struct.pack_into("<H", footer, TAIL_FOOTER_CRC_OFF, crc16(footer[:510]))
    return bytes(footer)


def build(
    *,
    prefix_path: Path,
    tail_out: Path,
    abi_out: Path,
    report_out: Path,
    build_dependencies: bool,
) -> None:
    if build_dependencies:
        run_builder(ROOT_BUILDER)
        run_builder(FLIGHT_SYM_BUILDER)
        run_builder(FLIGHT_BUILDER)
        run_builder(HELLO_BUILDER)
        run_builder(ENTROPY_BUILDER)
        run_builder(AUTH_BUILDER)

    prefix, prefix_sectors = read_prefix(prefix_path)
    root = ROOT_STAGE.read_bytes()
    module_pack = MODULE_PACK.read_bytes()
    entropy_raw = ENTROPY_RAW.read_bytes()
    entropy_component = ENTROPY_COMPONENT.read_bytes()
    hello_raw = HELLO_RAW.read_bytes()
    hello_component = HELLO_COMPONENT.read_bytes()
    flight_raw = FLIGHT_RAW.read_bytes()
    flight_component = FLIGHT_COMPONENT.read_bytes()
    flight_sym_raw = FLIGHT_SYM_RAW.read_bytes()
    flight_sym_k14_raw = FLIGHT_SYM_K14_RAW.read_bytes()
    auth_raw = AUTH_RAW.read_bytes()
    auth_component = AUTH_COMPONENT.read_bytes()
    validate_root_stage(root)
    validate_module_pack(module_pack)
    entropy_entries, entropy_stored_bytes, entropy_crc = validate_controller(
        entropy_raw,
        entropy_component,
        magic=b"S286ENT2",
        abi=ABI_VERSION,
        entry_count=5,
        entry_count_off=12,
        entry_table_off=14,
        load=CONTROLLER_LOAD,
        limit=CONTROLLER_LIMIT,
        label="entropy controller",
    )
    hello_entries, hello_stored_bytes, hello_crc = validate_controller(
        hello_raw,
        hello_component,
        magic=b"S286HL02",
        abi=ABI_VERSION,
        entry_count=2,
        entry_count_off=12,
        entry_table_off=14,
        load=CONTROLLER_LOAD,
        limit=CONTROLLER_LIMIT,
        label="HELLO controller",
    )
    flight_entries, flight_stored_bytes, flight_crc = validate_controller(
        flight_raw,
        flight_component,
        magic=b"S286FL02",
        abi=ABI_VERSION,
        entry_count=1,
        entry_count_off=12,
        entry_table_off=14,
        load=FLIGHT_LOAD,
        limit=FLIGHT_LIMIT,
        label="protected-flight coordinator",
    )
    if (
        len(flight_sym_raw) != len(flight_sym_k14_raw)
        or flight_sym_raw[:8] != b"T13SYM02"
        or flight_sym_k14_raw[:8] != b"T13SYM02"
    ):
        raise AssertionError("relocated/K14 symmetric reference geometry drifted")
    sym_offsets = [
        offset
        for offset in range(len(prefix) - 7)
        if prefix.startswith(b"T13SYM02", offset)
    ]
    if len(sym_offsets) != 1:
        raise AssertionError(
            f"universal prefix contains {len(sym_offsets)} K14 symmetric images"
        )
    sym_offset = sym_offsets[0]
    if sym_offset % SECTOR_BYTES:
        raise AssertionError("universal prefix K14 symmetric image is unaligned")
    product_sym = prefix[sym_offset : sym_offset + len(flight_sym_k14_raw)]
    if len(product_sym) != len(flight_sym_k14_raw):
        raise AssertionError("universal prefix truncates its K14 symmetric image")
    runtime_helper = load_runtime_builder()
    normalized_sym, initial_pointer_offsets = (
        runtime_helper.normalize_product_symmetric_image(
            product_sym, flight_sym_k14_raw
        )
    )
    if normalized_sym != flight_sym_k14_raw:
        raise AssertionError("pre-TCP symmetric normalization is not byte exact")
    auth_entries, auth_stored_bytes, auth_crc = validate_controller(
        auth_raw,
        auth_component,
        magic=b"S286AU02",
        abi=ABI_VERSION,
        entry_count=1,
        entry_count_off=12,
        entry_table_off=14,
        load=CONTROLLER_LOAD,
        limit=CONTROLLER_LIMIT,
        label="offline authentication controller",
    )
    root_start = prefix_sectors
    module_start = root_start + ROOT_SECTORS
    entropy_start = module_start + MODULE_PACK_SECTORS
    entropy_sectors = len(entropy_component) // SECTOR_BYTES
    hello_start = entropy_start + entropy_sectors
    hello_sectors = len(hello_component) // SECTOR_BYTES
    flight_start = hello_start + hello_sectors
    flight_sectors = len(flight_component) // SECTOR_BYTES
    auth_start = flight_start + flight_sectors
    auth_sectors = len(auth_component) // SECTOR_BYTES
    footer_sector = auth_start + auth_sectors
    total_sectors = footer_sector + 1
    tail_sectors = total_sectors - prefix_sectors
    if total_sectors > BOOTSTRAP_MAX_TOTAL_SECTORS:
        raise AssertionError(
            f"286 product image needs {total_sectors} sectors, bootstrap cap is "
            f"{BOOTSTRAP_MAX_TOTAL_SECTORS}"
        )
    if total_sectors > UNIVERSAL_MAX_SEED_SECTORS:
        raise AssertionError(
            f"universal SEED.SYS needs {total_sectors} sectors, budget is "
            f"{UNIVERSAL_MAX_SEED_SECTORS}"
        )
    if total_sectors + PACKAGED_AUXILIARY_SECTORS > FAT_DATA_SECTORS:
        raise AssertionError("universal 160 KiB packaged-sector budget drifted")

    entries = (
        TAIL_ENTRY.pack(
            TAIL_KIND_ROOT_STAGE,
            TAIL_FLAG_PRODUCT,
            root_start,
            ROOT_SECTORS,
            len(root),
            ROOT_LOAD,
            ROOT_ENTRY,
            crc16(root),
        ),
        TAIL_ENTRY.pack(
            TAIL_KIND_MODULE_PACK,
            TAIL_FLAG_PRODUCT,
            module_start,
            MODULE_PACK_SECTORS,
            len(module_pack),
            0,
            0,
            crc16(module_pack),
        ),
        TAIL_ENTRY.pack(
            TAIL_KIND_PRECOMPUTE,
            TAIL_FLAG_PRODUCT | TAIL_FLAG_RAW_LZ4,
            entropy_start,
            entropy_sectors,
            entropy_stored_bytes,
            CONTROLLER_LOAD,
            entropy_entries[0],
            entropy_crc,
        ),
        TAIL_ENTRY.pack(
            TAIL_KIND_ACQUIRE,
            TAIL_FLAG_PRODUCT | TAIL_FLAG_RAW_LZ4,
            hello_start,
            hello_sectors,
            hello_stored_bytes,
            CONTROLLER_LOAD,
            hello_entries[0],
            hello_crc,
        ),
        # The final no-0RTT resumption reuses the exact same immutable HELLO
        # sectors but selects its independently bounded live entry.
        TAIL_ENTRY.pack(
            TAIL_KIND_HELLO_RESUME,
            TAIL_FLAG_PRODUCT | TAIL_FLAG_RAW_LZ4,
            hello_start,
            hello_sectors,
            hello_stored_bytes,
            CONTROLLER_LOAD,
            hello_entries[1],
            hello_crc,
        ),
        TAIL_ENTRY.pack(
            TAIL_KIND_FLIGHT,
            TAIL_FLAG_PRODUCT | TAIL_FLAG_RAW_LZ4,
            flight_start,
            flight_sectors,
            flight_stored_bytes,
            FLIGHT_LOAD,
            flight_entries[0],
            flight_crc,
        ),
        TAIL_ENTRY.pack(
            TAIL_KIND_AUTHENTICATE,
            TAIL_FLAG_PRODUCT | TAIL_FLAG_RAW_LZ4,
            auth_start,
            auth_sectors,
            auth_stored_bytes,
            CONTROLLER_LOAD,
            auth_entries[0],
            auth_crc,
        ),
    )
    footer = make_footer(
        total_sectors=total_sectors,
        tail_start=prefix_sectors,
        tail_sectors=tail_sectors,
        entries=entries,
    )
    tail = (
        root
        + module_pack
        + entropy_component
        + hello_component
        + flight_component
        + auth_component
        + footer
    )
    if len(tail) != tail_sectors * SECTOR_BYTES:
        raise AssertionError("286 product-tail sector accounting drifted")

    digest = hashlib.sha256(tail).hexdigest()
    abi = f"""; Generated by {Path(__file__).resolve().relative_to(ROOT)}.
; The final link must append this exact byte range to the K14-complete prefix.
%define TLS13_286_PRODUCT_TAIL_START_SECTOR {prefix_sectors}
%define TLS13_286_PRODUCT_TAIL_SECTORS {tail_sectors}
%define TLS13_286_PRODUCT_FINAL_SECTORS {total_sectors}
%define TLS13_286_PRODUCT_ROOT_START_SECTOR {root_start}
%define TLS13_286_PRODUCT_MODULE_PACK_START_SECTOR {module_start}
%define TLS13_286_PRODUCT_ENTROPY_START_SECTOR {entropy_start}
%define TLS13_286_PRODUCT_ENTROPY_SECTORS {entropy_sectors}
%define TLS13_286_PRODUCT_HELLO_START_SECTOR {hello_start}
%define TLS13_286_PRODUCT_HELLO_SECTORS {hello_sectors}
%define TLS13_286_PRODUCT_FLIGHT_START_SECTOR {flight_start}
%define TLS13_286_PRODUCT_FLIGHT_SECTORS {flight_sectors}
%define TLS13_286_PRODUCT_AUTH_START_SECTOR {auth_start}
%define TLS13_286_PRODUCT_AUTH_SECTORS {auth_sectors}
%define TLS13_286_PRODUCT_FOOTER_SECTOR {footer_sector}
"""
    report = {
        "schema": "seed-tls13-286-product-tail-v1",
        "prefix": {
            "image": display_path(prefix_path),
            "bytes": len(prefix),
            "sectors": prefix_sectors,
            "sha256": hashlib.sha256(prefix).hexdigest(),
        },
        "tail": {
            "image": display_path(tail_out),
            "bytes": len(tail),
            "start_sector": prefix_sectors,
            "sectors": tail_sectors,
            "sha256": digest,
        },
        "final_total_sectors": total_sectors,
        "universal_max_seed_sectors": UNIVERSAL_MAX_SEED_SECTORS,
        "packaged_auxiliary_sectors": PACKAGED_AUXILIARY_SECTORS,
        "fat_data_sectors": FAT_DATA_SECTORS,
        "final_packaged_sectors": (
            total_sectors + PACKAGED_AUXILIARY_SECTORS
        ),
        "universal_packaged_headroom": (
            FAT_DATA_SECTORS
            - total_sectors
            - PACKAGED_AUXILIARY_SECTORS
        ),
        "universal_runtime_growth_headroom": (
            UNIVERSAL_MAX_SEED_SECTORS - total_sectors
        ),
        "sector_savings": {
            "reference_final_seed_sectors": 303,
            "relocated_k14_symmetric_reuse": 10,
            "parent_published_utc": 1,
            "flight_relocator_growth": flight_sectors - 5,
            "net": 303 - total_sectors,
        },
        "bootstrap_max_total_sectors": BOOTSTRAP_MAX_TOTAL_SECTORS,
        "bootstrap_sector_headroom": BOOTSTRAP_MAX_TOTAL_SECTORS - total_sectors,
        "footer": {
            "sector": footer_sector,
            "magic": TAIL_MAGIC.decode("ascii"),
            "abi": ABI_VERSION,
            "crc16_ccitt": f"{crc16(footer[:510]):04X}",
        },
        "entries": [
            {
                "kind": TAIL_KIND_ROOT_STAGE,
                "name": "root-stage",
                "flags": TAIL_FLAG_PRODUCT,
                "start_sector": root_start,
                "sectors": ROOT_SECTORS,
                "image_bytes": len(root),
                "load": f"0x{ROOT_LOAD:04x}",
                "entry": f"0x{ROOT_ENTRY:04x}",
                "crc16_ccitt": f"{crc16(root):04X}",
                "sha256": hashlib.sha256(root).hexdigest(),
            },
            {
                "kind": TAIL_KIND_MODULE_PACK,
                "name": "module-pack",
                "flags": TAIL_FLAG_PRODUCT,
                "start_sector": module_start,
                "sectors": MODULE_PACK_SECTORS,
                "image_bytes": len(module_pack),
                "load": "0x0000",
                "entry": "0x0000",
                "crc16_ccitt": f"{crc16(module_pack):04X}",
                "sha256": hashlib.sha256(module_pack).hexdigest(),
            },
            component_report(
                kind=TAIL_KIND_PRECOMPUTE,
                name="entropy-precompute",
                start=entropy_start,
                sectors=entropy_sectors,
                stored_bytes=entropy_stored_bytes,
                load=CONTROLLER_LOAD,
                entry=entropy_entries[0],
                checksum=entropy_crc,
                raw=entropy_raw,
                component=entropy_component,
            ),
            component_report(
                kind=TAIL_KIND_ACQUIRE,
                name="hello-acquisition",
                start=hello_start,
                sectors=hello_sectors,
                stored_bytes=hello_stored_bytes,
                load=CONTROLLER_LOAD,
                entry=hello_entries[0],
                checksum=hello_crc,
                raw=hello_raw,
                component=hello_component,
            ),
            component_report(
                kind=TAIL_KIND_HELLO_RESUME,
                name="hello-resume",
                start=hello_start,
                sectors=hello_sectors,
                stored_bytes=hello_stored_bytes,
                load=CONTROLLER_LOAD,
                entry=hello_entries[1],
                checksum=hello_crc,
                raw=hello_raw,
                component=hello_component,
                alias_of="hello-acquisition",
            ),
            component_report(
                kind=TAIL_KIND_FLIGHT,
                name="protected-flight",
                start=flight_start,
                sectors=flight_sectors,
                stored_bytes=flight_stored_bytes,
                load=FLIGHT_LOAD,
                entry=flight_entries[0],
                checksum=flight_crc,
                raw=flight_raw,
                component=flight_component,
            ),
            component_report(
                kind=TAIL_KIND_AUTHENTICATE,
                name="offline-authentication",
                start=auth_start,
                sectors=auth_sectors,
                stored_bytes=auth_stored_bytes,
                load=CONTROLLER_LOAD,
                entry=auth_entries[0],
                checksum=auth_crc,
                raw=auth_raw,
                component=auth_component,
            ),
        ],
        "symmetric_reuse": {
            "prefix_offset": sym_offset,
            "prefix_sector": sym_offset // SECTOR_BYTES,
            "product_source_bytes": len(product_sym),
            "product_source_sha256": hashlib.sha256(product_sym).hexdigest(),
            "canonical_source_bytes": len(flight_sym_k14_raw),
            "canonical_source_sha256": hashlib.sha256(
                flight_sym_k14_raw
            ).hexdigest(),
            "relocated_bytes": len(flight_sym_raw),
            "relocated_sha256": hashlib.sha256(flight_sym_raw).hexdigest(),
            "pre_tcp_normalization": {
                "initial_pointer_from": (
                    f"0x{runtime_helper.PRODUCT_SHA256_INITIAL_STATE:04x}"
                ),
                "initial_pointer_to": (
                    f"0x{runtime_helper.SYM_ORIGIN + runtime_helper.PRODUCT_CRITICAL_TAIL_OFFSET:04x}"
                ),
                "initial_pointer_offsets": list(initial_pointer_offsets),
                "critical_tail_offset": (
                    runtime_helper.PRODUCT_CRITICAL_TAIL_OFFSET
                ),
                "critical_tail_bytes": (
                    runtime_helper.PRODUCT_CRITICAL_TAIL_BYTES
                ),
                "canonical_byte_equivalent": True,
            },
        },
        "trusted_time": {
            "source": "silent coherent platform-UTC publication",
            "publication_bytes": 9,
            "status_last": True,
            "tail_component_present": False,
        },
        "runtime_module_loading": False,
        "legacy_phase_keys_used_for_tail": False,
    }

    # The tail is the Make transaction marker: publish its dependent metadata
    # first, and publish the exact incbin payload only after both succeeded.
    atomic_write(abi_out, abi.encode("ascii"))
    atomic_write(
        report_out,
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    atomic_write(tail_out, tail)
    print(json.dumps(report, indent=2, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, default=DEFAULT_PREFIX)
    parser.add_argument("--tail-out", type=Path, default=DEFAULT_TAIL)
    parser.add_argument("--abi-out", type=Path, default=DEFAULT_ABI)
    parser.add_argument("--report-out", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--skip-dependency-build",
        action="store_true",
        help="consume already-built root/module/entropy artifacts",
    )
    args = parser.parse_args()
    build(
        prefix_path=args.prefix,
        tail_out=args.tail_out,
        abi_out=args.abi_out,
        report_out=args.report_out,
        build_dependencies=not args.skip_dependency_build,
    )


if __name__ == "__main__":
    main()
