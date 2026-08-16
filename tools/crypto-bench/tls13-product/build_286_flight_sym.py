#!/usr/bin/env python3
"""Build the 286 protected-flight symmetric image and exact symbol ABI.

The immutable 0x1800 implementation is derived from the shipping T13SYM02
image.  The product pack's final 288 bytes are 8088-route helpers; the
286 flight replaces exactly that tail with the canonical SHA constants before
applying the generated mutable-state relocations to 0x7380..0x79ad, above the
P-256 authentication modules and below Seed's 0x7a00 stack guard.
The 0x6300 flight controller intentionally lifetime-aliases the upper part of
those modules: acquisition retires its symmetric image and one-way chains to
offline authentication before any P256W7/ECDSAW7 decode, while resumption
finishes the HELLO modules before loading a fresh flight controller.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150"
PROBE = HERE / "tls13_286_sym_abi_probe.asm"
MODULE_PACK = BUILD / "crypto-bench/tls13-286-modules.bin"
RAW = BUILD / "tls13-286-flight-sym.bin"
K14_RAW = BUILD / "tls13-286-flight-sym-k14.bin"
COMPONENT = BUILD / "tls13-286-flight-sym-component.bin"
ABI_OUT = BUILD / "tls13-286-flight-sym-abi.inc"
REPORT = BUILD / "tls13-286-flight-sym.json"

ORIGIN = 0x1800
IMAGE_MAGIC = b"T13SYM02"
PROBE_MAGIC = b"S286SAB2"
ABI = 2
ENTRY_COUNT = 19
STATE_BASE = 0x7380
STATE_LIMIT = 0x7A00
COORDINATOR_LOAD = 0x6300
SOURCE_STAGE = 0x4230
LZ4_HEADER = struct.Struct("<4sHHHH")
K14_STATE_BASE = 0x3600
K14_STATE_END = 0x3C2E
RELOCATED_STATE_BASE = STATE_BASE
RELOCATION_DELTA = RELOCATED_STATE_BASE - K14_STATE_BASE
HEADER_ARENA_FLOOR_OFF = 24
HEADER_STACK_GUARD_OFF = 26
RELOCATED_ARENA_FLOOR = 0x79B0
RELOCATED_STACK_GUARD = 0x7A00


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
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
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


def compress_raw_lz4(raw: bytes) -> bytes:
    if shutil.which("lz4") is None:
        raise SystemExit("lz4 command is required to build the 286 sym image")
    with tempfile.TemporaryDirectory(prefix="seed-286-flight-sym-", dir=BUILD) as temp:
        directory = Path(temp)
        source = directory / "sym.raw"
        framed = directory / "sym.legacy.lz4"
        decoded = directory / "sym.roundtrip"
        source.write_bytes(raw)
        subprocess.run(
            ["lz4", "-q", "-l", "-9", "-f", str(source), str(framed)],
            cwd=ROOT,
            check=True,
        )
        wrapped = framed.read_bytes()
        if len(wrapped) < 8 or wrapped[:4] != b"\x02\x21\x4c\x18":
            raise AssertionError("lz4 did not emit one legacy raw block")
        size = int.from_bytes(wrapped[4:8], "little")
        block = wrapped[8:]
        if size != len(block):
            raise AssertionError("286 sym image did not fit one raw LZ4 block")
        subprocess.run(
            ["lz4", "-q", "-d", "-f", str(framed), str(decoded)],
            cwd=ROOT,
            check=True,
        )
        if decoded.read_bytes() != raw:
            raise AssertionError("286 sym LZ4 round trip changed bytes")
        return block


def validate_auth_module_ceiling() -> dict[str, int]:
    pack = MODULE_PACK.read_bytes()
    if pack[:8] != b"S286PK02":
        raise AssertionError("286 module pack is absent or malformed")
    ceilings: dict[str, int] = {}
    for index in range(5):
        offset = 20 + index * 24
        name = pack[offset : offset + 8].rstrip(b"\0").decode("ascii")
        kind, _, raw_bytes = struct.unpack_from("<HHH", pack, offset + 8)
        if kind in (4, 5):
            ceiling = SOURCE_STAGE + raw_bytes
            if ceiling > STATE_BASE:
                raise AssertionError(
                    f"{name} reaches {ceiling:#06x}, overlapping protected "
                    "symmetric state"
                )
            ceilings[name] = ceiling
    if set(ceilings) != {"P256W7", "ECDSAW7"}:
        raise AssertionError("286 authentication module set drifted")
    return ceilings


def packed_k14_symmetric_image(helper) -> bytes:
    pack = helper.DEFAULT_PACK.read_bytes()
    offsets = [
        offset
        for offset in range(len(pack) - len(IMAGE_MAGIC) + 1)
        if pack.startswith(IMAGE_MAGIC, offset)
    ]
    if len(offsets) != 1:
        raise AssertionError(
            f"K14 product pack contains {len(offsets)} symmetric images"
        )
    offset = offsets[0]
    if offset % 512:
        raise AssertionError("K14 symmetric image is not sector aligned")
    image_bytes = struct.unpack_from("<H", pack, offset + 10)[0]
    raw = pack[offset : offset + image_bytes]
    if len(raw) != image_bytes:
        raise AssertionError("K14 symmetric image is truncated")
    return raw


def probe_image(probe: bytes) -> bytes:
    if probe[:8] != IMAGE_MAGIC or struct.unpack_from("<H", probe, 8)[0] != ABI:
        raise AssertionError("symmetric image header drifted")
    image_bytes = struct.unpack_from("<H", probe, 10)[0]
    if not 32 + ENTRY_COUNT * 2 <= image_bytes <= len(probe):
        raise AssertionError("symmetric probe image length drifted")
    return probe[:image_bytes]


def build_relocations(source: bytes, target: bytes) -> tuple[int, ...]:
    if len(source) != len(target):
        raise AssertionError("K14 and 286 symmetric images differ in length")
    offsets: list[int] = []
    for offset in range(len(source) - 1):
        before = struct.unpack_from("<H", source, offset)[0]
        after = struct.unpack_from("<H", target, offset)[0]
        if (
            K14_STATE_BASE <= before <= K14_STATE_END
            and after == (before + RELOCATION_DELTA) & 0xFFFF
            and before != after
        ):
            offsets.append(offset)
    if any(right <= left + 1 for left, right in zip(offsets, offsets[1:])):
        raise AssertionError("symmetric relocation words overlap")

    relocated = bytearray(source)
    for offset in offsets:
        before = struct.unpack_from("<H", relocated, offset)[0]
        struct.pack_into(
            "<H", relocated, offset, (before + RELOCATION_DELTA) & 0xFFFF
        )
    struct.pack_into(
        "<H", relocated, HEADER_ARENA_FLOOR_OFF, RELOCATED_ARENA_FLOOR
    )
    struct.pack_into(
        "<H", relocated, HEADER_STACK_GUARD_OFF, RELOCATED_STACK_GUARD
    )
    if bytes(relocated) != target:
        differing = [
            index
            for index, (left, right) in enumerate(zip(relocated, target))
            if left != right
        ]
        raise AssertionError(
            "generated K14 symmetric relocation is not byte exact: "
            f"{differing[:16]}"
        )
    return tuple(offsets)


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    helper = load_runtime_builder()
    with tempfile.TemporaryDirectory(prefix="seed-286-flight-sym-", dir=BUILD) as temp:
        directory = Path(temp)
        probes: dict[str, bytes] = {}
        for label, extra in (
            ("k14", []),
            ("286", ["-DTLS13_286_PRODUCT_SYM=1"]),
        ):
            output = directory / f"{label}-sym-probe.bin"
            subprocess.run(
                [
                    "nasm",
                    "-f",
                    "bin",
                    *extra,
                    f"-I{ROOT}/",
                    f"-I{ROOT / 'tools/crypto-bench/tls13-poc'}/",
                    f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
                    "-o",
                    str(output),
                    str(PROBE),
                ],
                cwd=ROOT,
                check=True,
            )
            probes[label] = output.read_bytes()

    probe = probes["286"]
    raw = probe_image(probe)
    image_bytes = len(raw)
    trailer = probe[image_bytes:]
    if (
        len(trailer) < 12
        or trailer[:8] != PROBE_MAGIC
        or struct.unpack_from("<H", trailer, 8)[0] != ABI
    ):
        raise AssertionError("286 symmetric symbol trailer is absent")
    count = struct.unpack_from("<H", trailer, 10)[0]
    if count != len(helper.PROBE_NAMES) or len(trailer) != 12 + count * 2:
        raise AssertionError("286 symmetric symbol trailer length drifted")
    values = struct.unpack_from(f"<{count}H", trailer, 12)
    symbols = dict(zip(helper.PROBE_NAMES, values, strict=True))
    if (
        symbols["SYM_IMAGE_START"] != ORIGIN
        or symbols["SYM_IMAGE_END"] - ORIGIN != len(raw)
        or symbols["SYM_ENTRY_COUNT"] != ENTRY_COUNT
        or symbols["SYM_INPUT_SHARED_SECRET"] != STATE_BASE
        or not STATE_BASE < symbols["SYM_HIGH_STATE_END"] <= STATE_LIMIT
    ):
        raise AssertionError("286 symmetric fixed geometry drifted")
    entries = struct.unpack_from(f"<{ENTRY_COUNT}H", raw, 32)
    expected_entries = tuple(
        symbols[name] for name in helper.PROBE_NAMES[4 : 4 + ENTRY_COUNT]
    )
    if entries != expected_entries:
        raise AssertionError("286 symmetric entry table and symbol ABI disagree")

    k14_raw = probe_image(probes["k14"])
    relocation_offsets = build_relocations(k14_raw, raw)
    packed_k14_raw = packed_k14_symmetric_image(helper)
    tail_offset = helper.PRODUCT_CRITICAL_TAIL_OFFSET
    tail_bytes = helper.PRODUCT_CRITICAL_TAIL_BYTES
    product_initial = helper.PRODUCT_SHA256_INITIAL_STATE
    canonical_initial = ORIGIN + tail_offset
    rebuilt_k14, initial_pointer_offsets = (
        helper.normalize_product_symmetric_image(packed_k14_raw, k14_raw)
    )
    if rebuilt_k14 != k14_raw:
        raise AssertionError(
            "canonical SHA tail with bound initial-state operand does not "
            "rebuild exact K14 sym"
        )

    block = compress_raw_lz4(raw)
    checksum = crc16(raw)
    stored_bytes = LZ4_HEADER.size + len(block)
    sectors = (stored_bytes + 511) // 512
    if SOURCE_STAGE + sectors * 512 > COORDINATOR_LOAD:
        raise AssertionError("compressed 286 sym overlaps its live coordinator")
    component = (
        LZ4_HEADER.pack(b"LZ4B", len(raw), len(block), checksum, 0) + block
    )
    component += bytes(sectors * 512 - len(component))

    definitions = {
        f"TLS13_286_FLIGHT_{name}": value for name, value in symbols.items()
    }
    definitions.update(
        {
            "TLS13_286_FLIGHT_SYM_COMPONENT_SECTORS": sectors,
            "TLS13_286_FLIGHT_SYM_COMPONENT_BYTES": stored_bytes,
            "TLS13_286_FLIGHT_SYM_COMPONENT_CRC16": checksum,
            "TLS13_286_FLIGHT_SYM_SOURCE_STAGE": SOURCE_STAGE,
            "TLS13_286_FLIGHT_SYM_K14_STATE_BASE": K14_STATE_BASE,
            "TLS13_286_FLIGHT_SYM_K14_STATE_END": K14_STATE_END,
            "TLS13_286_FLIGHT_SYM_RELOCATION_DELTA": RELOCATION_DELTA,
            "TLS13_286_FLIGHT_SYM_RELOCATION_COUNT": len(
                relocation_offsets
            ),
            "TLS13_286_FLIGHT_SYM_HEADER_ARENA_FLOOR_OFF": (
                HEADER_ARENA_FLOOR_OFF
            ),
            "TLS13_286_FLIGHT_SYM_HEADER_STACK_GUARD_OFF": (
                HEADER_STACK_GUARD_OFF
            ),
            "TLS13_286_FLIGHT_SYM_RELOCATED_ARENA_FLOOR": (
                RELOCATED_ARENA_FLOOR
            ),
            "TLS13_286_FLIGHT_SYM_RELOCATED_STACK_GUARD": (
                RELOCATED_STACK_GUARD
            ),
            "TLS13_286_FLIGHT_SYM_RELOCATED_CRC16": checksum,
        }
    )
    include = (
        "; Generated by build_286_flight_sym.py; do not edit.\n"
        + "\n".join(
            f"%define {name} 0x{value:04x}"
            for name, value in definitions.items()
        )
        + "\n"
        + "%macro TLS13_286_FLIGHT_SYM_EMIT_RELOCATIONS 0\n"
        + "\n".join(
            "    dw "
            + ", ".join(f"0x{value:04x}" for value in relocation_offsets[start : start + 8])
            for start in range(0, len(relocation_offsets), 8)
        )
        + "\n%endmacro\n"
    ).encode("ascii")
    ceilings = validate_auth_module_ceiling()
    report = {
        "schema": "seed-tls13-286-flight-sym-v1",
        "raw": str(RAW.relative_to(ROOT)),
        "k14_raw": str(K14_RAW.relative_to(ROOT)),
        "component": str(COMPONENT.relative_to(ROOT)),
        "raw_bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_crc16_ccitt": f"{checksum:04X}",
        "compressed_block_bytes": len(block),
        "stored_bytes": stored_bytes,
        "component_sectors": sectors,
        "component_sha256": hashlib.sha256(component).hexdigest(),
        "state_base": f"0x{STATE_BASE:04x}",
        "state_end": f"0x{symbols['SYM_HIGH_STATE_END']:04x}",
        "stack_guard": f"0x{STATE_LIMIT:04x}",
        "coordinator_load": f"0x{COORDINATOR_LOAD:04x}",
        "authentication_module_ceilings": {
            name: f"0x{ceiling:04x}" for name, ceiling in ceilings.items()
        },
        "flight_module_lifetime": (
            "0x6300 coordinator is retired by a one-way root-chain transition "
            "before P256W7/ECDSAW7 decode; relocated symmetric state remains "
            "above every authentication module"
        ),
        "k14_reuse": {
            "source_bytes": len(k14_raw),
            "source_sha256": hashlib.sha256(k14_raw).hexdigest(),
            "source_crc16_ccitt": f"{crc16(k14_raw):04X}",
            "current_product_pack_normalizable": True,
            "current_product_pack_sha256": hashlib.sha256(
                packed_k14_raw
            ).hexdigest(),
            "product_critical_tail_offset": tail_offset,
            "product_critical_tail_bytes": tail_bytes,
            "product_critical_tail_sha256": hashlib.sha256(
                packed_k14_raw[tail_offset:]
            ).hexdigest(),
            "canonical_tail_sha256": hashlib.sha256(
                k14_raw[tail_offset:]
            ).hexdigest(),
            "canonical_tail_rebuild_byte_equivalent": True,
            "product_initial_pointer": f"0x{product_initial:04x}",
            "canonical_initial_pointer": f"0x{canonical_initial:04x}",
            "initial_pointer_patch_offsets": [
                f"0x{offset:04x}" for offset in initial_pointer_offsets
            ],
            "canonical_source_rebuild_byte_equivalent": True,
            "relocation_delta": f"0x{RELOCATION_DELTA:04x}",
            "relocation_words": len(relocation_offsets),
            "relocated_byte_equivalent": True,
            "tail_component_sectors_retired": sectors,
        },
        "definitions": {
            name: f"0x{value:04x}" for name, value in definitions.items()
        },
    }
    atomic_write(ABI_OUT, include)
    atomic_write(K14_RAW, k14_raw)
    atomic_write(RAW, raw)
    atomic_write(COMPONENT, component)
    atomic_write(
        REPORT,
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
