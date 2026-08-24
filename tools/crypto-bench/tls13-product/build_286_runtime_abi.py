#!/usr/bin/env python3
"""Generate the exact resident/T13SYM02 ABI consumed by the 286 tail.

The generated include is accepted only when:

* every resident callback resolves from the K14-complete prefix listing;
* TCP connect/one-sector-close geometry agrees with the prefix phase table;
* a freshly assembled canonical K14 symmetric image is byte-identical to the
  unique ``T13SYM02`` phase inside the validated product pack; and
* the probe trailer, symmetric header, entry table, and zero slot padding all
  agree on the same fixed-origin image.

No current address is trusted merely because it appeared in an earlier spike.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BOOT = ROOT / "targets/ibm_pc_5150/boot"
BUILD = ROOT / "build/ibm_pc_5150"

DEFAULT_CORE = BUILD / "tls13-286-tail-base/SEED.SYS"
DEFAULT_LISTING = BUILD / "tls13-286-tail-base/SEED.SYS.lst"
DEFAULT_PACK = BUILD / "tls13-k14-product-pack.bin"
DEFAULT_OUTPUT = BUILD / "tls13-286-runtime-abi.inc"
DEFAULT_REPORT = BUILD / "tls13-286-runtime-abi.json"
PROBE_SOURCE = HERE / "tls13_286_sym_abi_probe.asm"

ORIGIN = 0x1000
SECTOR = 512
K14_PACK_START_SECTOR = 45
SYM_MAGIC = b"T13SYM02"
SYM_ORIGIN = 0x1800
SYM_ABI = 2
SYM_ENTRY_COUNT = 19
PROBE_MAGIC = b"S286SAB2"
PROBE_ABI = 2
PRODUCT_SYM_BYTES = 12 * SECTOR
PRODUCT_CRITICAL_TAIL_OFFSET = 0x16E0
PRODUCT_CRITICAL_TAIL_BYTES = 0x0120
PRODUCT_SHA256_INITIAL_STATE = 0x2EE0

CALLBACK_SYMBOLS = (
    "load_core_sectors_at",
    "tls13_286_restore_loop_cache_shadow",
    "loop_cache_count",
    "read_abs_sector",
    "ne_transmit_tcp_ack",
    "tcp_send_payload",
    "tcp_receive_payload",
    "nic_vt_enter",
    "nic_vt_restore",
    "tls13_product_route_mode",
)

RUNTIME_SYMBOLS = (
    "tcp_rx_payload_ptr",
    "tcp_rx_payload_len",
    "tls_buffered_payload_ptr",
    "tls_current_payload_len",
    "tls_client_write_key",
    "tls_server_write_key",
    "tls_client_write_iv",
    "tls_server_write_iv",
    "tls_client_record_seq",
    "tls_server_record_seq",
    "tls_key_schedule_ready",
)

PROBE_NAMES = (
    "SYM_IMAGE_START",
    "SYM_IMAGE_END",
    "SYM_ENTRY_TABLE",
    "SYM_ENTRY_COUNT",
    "SYM_INIT",
    "SYM_TRANSCRIPT_INIT",
    "SYM_TRANSCRIPT_UPDATE",
    "SYM_CRITICAL_SCHEDULE",
    "SYM_SERVER_HS_OPEN_BEGIN",
    "SYM_SERVER_APP_OPEN_BEGIN",
    "SYM_OPEN_CHUNK",
    "SYM_OPEN_FINISH",
    "SYM_VERIFY_SERVER_FINISHED",
    "SYM_BUILD_CLIENT_FINISHED",
    "SYM_DERIVE_APPLICATION",
    "SYM_BUILD_HEAD",
    "SYM_PARSE_NST",
    "SYM_RESUMPTION_BINDER",
    "SYM_RESUMPTION_HANDSHAKE",
    "SYM_TRANSCRIPT_IMPORT",
    "SYM_DERIVE_CLIENT_APPLICATION",
    "SYM_DERIVE_SERVER_APPLICATION",
    "SYM_AUTHENTICATE_RESUMED_FLIGHT",
    "SYM_SHA256_INIT",
    "SYM_SHA256_UPDATE",
    "SYM_SHA256_FINISH",
    "SYM_SHA256_STATE",
    "SYM_SHA256_BLOCK",
    "SYM_SHA256_LEN_LOW",
    "SYM_SHA256_LEN_HIGH",
    "SYM_SHA256_BLOCK_LEN",
    "SYM_HELLO_SERVER_X",
    "SYM_HELLO_DIGEST",
    "SYM_HELLO_CONTEXT",
    "SYM_INPUT_SHARED_SECRET",
    "SYM_INPUT_HELLO_HASH",
    "SYM_RECEIVED_SERVER_FINISHED",
    "SYM_CLIENT_FINISHED_MESSAGE",
    "SYM_IO_BASE",
    "SYM_IO_END",
    "SYM_CLIENT_HS_KEY",
    "SYM_CLIENT_HS_IV",
    "SYM_SERVER_HS_KEY",
    "SYM_SERVER_HS_IV",
    "SYM_CLIENT_HS_SEQ",
    "SYM_SERVER_HS_SEQ",
    "SYM_CLIENT_APP_KEY",
    "SYM_CLIENT_APP_IV",
    "SYM_SERVER_APP_KEY",
    "SYM_SERVER_APP_IV",
    "SYM_CLIENT_APP_SEQ",
    "SYM_SERVER_APP_SEQ",
    "SYM_TICKET_PSK",
    "SYM_TICKET_IDENTITY",
    "SYM_TICKET_NONCE",
    "SYM_TICKET_LIFETIME_HI",
    "SYM_TICKET_LIFETIME_LO",
    "SYM_TICKET_AGE_ADD",
    "SYM_TICKET_NONCE_LEN",
    "SYM_TICKET_IDENTITY_LEN",
    "SYM_TICKET_PRESENT",
    "SYM_INPUT_BINDER_HASH",
    "SYM_RESUMPTION_BINDER_VALUE",
    "SYM_RESUMPTION_MASTER_SECRET",
    "SYM_CLIENT_FINISHED_STATE",
    "SYM_HANDSHAKE_DERIVED",
    "SYM_HIGH_STATE_END",
)


def fail(message: str) -> None:
    raise AssertionError(message)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def u16(value: bytes, offset: int) -> int:
    return struct.unpack_from("<H", value, offset)[0]


def normalize_product_symmetric_image(
    product_image: bytes, canonical_image: bytes
) -> tuple[bytes, tuple[int, ...]]:
    """Validate the shipped image's canonical K14 normalization contract.

    The RAM-only 8088 route ships the canonical image directly.  Retain the
    historical one-word pre-TCP normalization ABI used by the 286 controller;
    writing 0x2ee0 over the already-canonical operand is deliberately
    idempotent and keeps the tail/controller contract stable.
    """

    if (
        len(product_image) != PRODUCT_SYM_BYTES
        or len(canonical_image) != PRODUCT_SYM_BYTES
        or PRODUCT_CRITICAL_TAIL_OFFSET + PRODUCT_CRITICAL_TAIL_BYTES
        != PRODUCT_SYM_BYTES
    ):
        fail("product/canonical symmetric normalization geometry drifted")
    if product_image[:8] != SYM_MAGIC or canonical_image[:8] != SYM_MAGIC:
        fail("product/canonical symmetric normalization magic drifted")
    normalized = bytearray(product_image)
    if product_image != canonical_image:
        normalized[PRODUCT_CRITICAL_TAIL_OFFSET:] = canonical_image[
            PRODUCT_CRITICAL_TAIL_OFFSET:
        ]
    canonical_initial = SYM_ORIGIN + PRODUCT_CRITICAL_TAIL_OFFSET
    initial_pointer_offsets: list[int] = []
    for offset in range(PRODUCT_CRITICAL_TAIL_OFFSET - 1):
        if (
            u16(product_image, offset) == canonical_initial
            and u16(canonical_image, offset) == canonical_initial
        ):
            initial_pointer_offsets.append(offset)
    if len(initial_pointer_offsets) != 1 or bytes(normalized) != canonical_image:
        fail(
            "shipped symmetric image is not exactly canonical or normalizable "
            "by its initial-state operand and 288-byte SHA tail"
        )
    return bytes(normalized), tuple(initial_pointer_offsets)


def atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Offline controller gates regenerate this ABI to prove that the current
    # prefix, listing, and K14 symmetric image still agree.  Preserve the
    # transaction marker's timestamp when that proof produces identical
    # bytes; replacing an unchanged prerequisite after the tail is built
    # otherwise makes every subsequent Make invocation rebuild the complete
    # 286 tail and its expensive hostile gates.
    if path.is_file() and path.read_bytes() == value:
        return
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def resolve_symbol(listing: str, symbol: str) -> int:
    lines = listing.splitlines()
    marker = re.compile(
        rf"\b{re.escape(symbol)}(?::|\s+(?:d[wbqd]|res[wbqd])\b)"
    )
    emitted = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{8})\s+")
    found: list[int] = []
    for index, line in enumerate(lines):
        if marker.search(line) is None:
            continue
        for candidate in lines[index : index + 40]:
            match = emitted.match(candidate)
            if match is not None:
                found.append(ORIGIN + int(match.group(1), 16))
                break
    if len(found) != 1:
        fail(f"listing symbol {symbol!r} resolved {len(found)} times: {found}")
    return found[0]


def parse_core_equates() -> dict[str, int]:
    lines: list[str] = []
    for path in (BOOT / "core/layout.inc", BOOT / "core/data.inc"):
        lines.extend(path.read_text(encoding="utf-8").splitlines())
    constants: dict[str, int] = {}
    while True:
        before = len(constants)
        for raw in lines:
            line = raw.split(";", 1)[0].strip()
            match = re.match(r"^(\w+)\s+equ\s+(.+)$", line)
            if match is None or match.group(1) in constants:
                continue
            expression = match.group(2).replace("/", "//")
            try:
                constants[match.group(1)] = int(
                    eval(expression, {"__builtins__": {}}, constants)
                )
            except Exception:
                continue
        if len(constants) == before:
            break
    missing = [name for name in RUNTIME_SYMBOLS if name not in constants]
    if missing:
        fail(f"cannot resolve core runtime equates: {missing!r}")
    return constants


def phase_geometry(core: bytes, phase_id: bytes) -> tuple[int, int, int]:
    if len(phase_id) != 1:
        raise ValueError("phase id is not one byte")
    table = u16(core, 19)
    count = u16(core, 21)
    matches: list[tuple[int, int, int]] = []
    for index in range(count):
        offset = table + index * 10
        if core[offset : offset + 1] == phase_id:
            matches.append(struct.unpack_from("<HHH", core, offset + 2))
    if len(matches) != 1:
        fail(f"phase {phase_id!r} resolved {len(matches)} times")
    return matches[0]


def build_probe(
    temp: Path, product_critical_tail: bytes | None = None
) -> bytes:
    output = temp / "sym-probe.bin"
    listing = temp / "sym-probe.lst"
    product_defines: list[str] = []
    if product_critical_tail is not None:
        if len(product_critical_tail) != PRODUCT_CRITICAL_TAIL_BYTES:
            fail("product symmetric critical tail geometry drifted")
        critical_tail = temp / "product-symmetric-critical-tail.bin"
        critical_tail.write_bytes(product_critical_tail)
        product_defines = [
            (
                "-DTLS13_PRODUCT_CRITICAL_TAIL_PATH="
                f'"{critical_tail.as_posix()}"'
            ),
            (
                "-DTLS13_PRODUCT_SHA256_INITIAL_STATE="
                f"0x{PRODUCT_SHA256_INITIAL_STATE:04x}"
            ),
        ]
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT}/",
            f"-I{ROOT / 'tools/crypto-bench/tls13-poc'}/",
            f"-I{BOOT}/",
            f"-I{BOOT / 'tls13'}/",
            *product_defines,
            "-l",
            str(listing),
            "-o",
            str(output),
            str(PROBE_SOURCE),
        ],
        cwd=ROOT,
        check=True,
    )
    return output.read_bytes()


def locate_sym_slot(pack: bytes) -> tuple[int, int, int, bytes]:
    offsets = [
        offset
        for offset in range(0, len(pack) - len(SYM_MAGIC) + 1)
        if pack.startswith(SYM_MAGIC, offset)
    ]
    if len(offsets) != 1:
        fail(f"validated K14 pack contains {len(offsets)} T13SYM02 images")
    offset = offsets[0]
    if offset % SECTOR:
        fail("T13SYM02 image is not sector aligned in the product pack")
    if u16(pack, offset + 8) != SYM_ABI:
        fail("T13SYM02 ABI drifted")
    image_bytes = u16(pack, offset + 10)
    if not 32 + SYM_ENTRY_COUNT * 2 <= image_bytes <= 16 * SECTOR:
        fail("T13SYM02 image length escaped the fixed K window")
    if u16(pack, offset + 30) != SYM_ENTRY_COUNT:
        fail("T13SYM02 entry count drifted")
    sectors = (image_bytes + SECTOR - 1) // SECTOR
    slot = pack[offset : offset + sectors * SECTOR]
    if len(slot) != sectors * SECTOR or any(slot[image_bytes:]):
        fail("T13SYM02 slot padding is not canonical zero")
    return offset, image_bytes, sectors, slot


def locate_sym(pack: bytes, probe: bytes) -> tuple[int, int, dict[str, int]]:
    offset, image_bytes, sectors, slot = locate_sym_slot(pack)
    if probe[:image_bytes] != slot[:image_bytes]:
        fail(
            "fresh K14 symmetric prefix plus validated product tail differs "
            "from the shipped pack image"
        )
    trailer = probe[image_bytes:]
    if (
        len(trailer) < 12
        or trailer[:8] != PROBE_MAGIC
        or u16(trailer, 8) != PROBE_ABI
    ):
        fail("symmetric ABI probe trailer is absent or malformed")
    count = u16(trailer, 10)
    if count != len(PROBE_NAMES) or len(trailer) != 12 + count * 2:
        fail("symmetric ABI probe value count/length drifted")
    values = struct.unpack_from(f"<{count}H", trailer, 12)
    fields = dict(zip(PROBE_NAMES, values, strict=True))
    if (
        fields["SYM_IMAGE_START"] != SYM_ORIGIN
        or fields["SYM_IMAGE_END"] - SYM_ORIGIN != image_bytes
        or fields["SYM_ENTRY_TABLE"] != SYM_ORIGIN + 32
        or fields["SYM_ENTRY_COUNT"] != SYM_ENTRY_COUNT
    ):
        fail("symmetric ABI probe/header geometry disagrees")
    header_entries = struct.unpack_from(
        f"<{SYM_ENTRY_COUNT}H", pack, offset + 32
    )
    probe_entries = tuple(
        fields[name]
        for name in PROBE_NAMES[4 : 4 + SYM_ENTRY_COUNT]
    )
    if probe_entries != header_entries or len(set(header_entries)) != len(
        header_entries
    ):
        fail("symmetric ABI probe differs from the shipped entry table")
    if any(not SYM_ORIGIN <= entry < SYM_ORIGIN + image_bytes for entry in header_entries):
        fail("symmetric entry escaped its exact image")
    return offset, sectors, fields


def generate(
    core_path: Path,
    listing_path: Path,
    pack_path: Path,
) -> tuple[bytes, dict[str, object]]:
    core = core_path.read_bytes()
    listing = listing_path.read_text(encoding="utf-8", errors="strict")
    pack = pack_path.read_bytes()
    if core[3:11] != b"SEEDCORE" or len(core) % SECTOR:
        fail("runtime ABI core is not a sector-aligned SEEDCORE image")
    if u16(core, 17) != len(core) // SECTOR:
        fail("runtime ABI core total-sector header is stale")

    resident = {name: resolve_symbol(listing, name) for name in CALLBACK_SYMBOLS}
    core_equates = parse_core_equates()
    runtime = {name: core_equates[name] for name in RUNTIME_SYMBOLS}

    phase_sector, phase_sectors, phase_load = phase_geometry(core, b"C")
    phase_start = resolve_symbol(listing, "core_tcp_connect_phase_start")
    phase_end = resolve_symbol(listing, "core_tcp_connect_phase_end")
    connect = resolve_symbol(listing, "tcp_connect_phase")
    close = resolve_symbol(listing, "tcp_close_cached_target")
    if (
        phase_sector != (phase_start - ORIGIN) // SECTOR
        or phase_sectors != (phase_end - phase_start + SECTOR - 1) // SECTOR
        or connect != phase_start
    ):
        fail("TCP phase table/listing geometry disagrees")
    connect_entry = phase_load + connect - phase_start
    close_entry = phase_load + close - phase_start
    if not phase_load <= close_entry < phase_load + SECTOR:
        fail("bounded TCP close entry escaped the phase's first sector")

    sym_offset, sym_image_bytes, _sym_sectors, sym_slot = locate_sym_slot(pack)
    if sym_image_bytes != PRODUCT_SYM_BYTES:
        fail("product K14 symmetric image is not the exact 12-sector image")
    critical_tail = sym_slot[
        PRODUCT_CRITICAL_TAIL_OFFSET :
        PRODUCT_CRITICAL_TAIL_OFFSET + PRODUCT_CRITICAL_TAIL_BYTES
    ]
    if len(critical_tail) != PRODUCT_CRITICAL_TAIL_BYTES:
        fail("validated product pack truncates the symmetric critical tail")
    with tempfile.TemporaryDirectory(prefix="seed-286-runtime-abi-") as raw:
        canonical_probe = build_probe(Path(raw))
    sym_offset, sym_sectors, sym = locate_sym(pack, canonical_probe)
    canonical_bytes = u16(canonical_probe, 10)
    if (
        canonical_probe[:8] != SYM_MAGIC
        or canonical_bytes != sym_image_bytes
        or len(canonical_probe) < canonical_bytes
    ):
        fail("canonical symmetric normalization probe drifted")
    product_image = pack[sym_offset : sym_offset + sym_image_bytes]
    canonical_image = canonical_probe[:canonical_bytes]
    canonical_initial = SYM_ORIGIN + PRODUCT_CRITICAL_TAIL_OFFSET
    normalized, initial_pointer_offsets = normalize_product_symmetric_image(
        product_image, canonical_image
    )
    sym_sector = K14_PACK_START_SECTOR + sym_offset // SECTOR
    if sym_sector > 0xFF or sym_sectors > 0xFF:
        fail("symmetric phase escaped the legacy phase-key geometry")

    definitions = {
        "TLS13_286_LINK_LOAD_CORE_SECTORS_AT": resident[
            "load_core_sectors_at"
        ],
        "TLS13_286_LINK_RESTORE_LOOP_CACHE_SHADOW": resident[
            "tls13_286_restore_loop_cache_shadow"
        ],
        "TLS13_286_LINK_LOOP_CACHE_COUNT": resident["loop_cache_count"],
        "TLS13_286_LINK_READ_ABS_SECTOR": resident["read_abs_sector"],
        "TLS13_286_LINK_TCP_ACK": resident["ne_transmit_tcp_ack"],
        "TLS13_286_LINK_TCP_SEND": resident["tcp_send_payload"],
        "TLS13_286_LINK_TCP_RECEIVE": resident["tcp_receive_payload"],
        "TLS13_286_LINK_NIC_ENTER_SLOT": resident["nic_vt_enter"],
        "TLS13_286_LINK_NIC_RESTORE_SLOT": resident["nic_vt_restore"],
        "TLS13_286_LINK_ROUTE_MODE": resident["tls13_product_route_mode"],
        "TLS13_286_LINK_TCP_CONNECT_PHASE_KEY": (
            phase_sectors << 8
        ) | phase_sector,
        "TLS13_286_LINK_TCP_CONNECT_DESTINATION": phase_load,
        "TLS13_286_LINK_TCP_CONNECT_ENTRY": connect_entry,
        "TLS13_286_LINK_TCP_CLOSE_PHASE_KEY": 0x100 | phase_sector,
        "TLS13_286_LINK_TCP_CLOSE_DESTINATION": phase_load,
        "TLS13_286_LINK_TCP_CLOSE_ENTRY": close_entry,
        "TLS13_286_LINK_SYM_PHASE_KEY": (sym_sectors << 8) | sym_sector,
        "TLS13_286_LINK_SYM_DESTINATION": SYM_ORIGIN,
        "TLS13_286_LINK_SYM_SECTORS": sym_sectors,
        "TLS13_286_LINK_SYM_IMAGE_BYTES": sym["SYM_IMAGE_END"]
        - sym["SYM_IMAGE_START"],
        "TLS13_286_LINK_SYM_PRODUCT_INITIAL_POINTER_OFF": (
            initial_pointer_offsets[0]
        ),
        "TLS13_286_LINK_TCP_RX_PAYLOAD_PTR": runtime[
            "tcp_rx_payload_ptr"
        ],
        "TLS13_286_LINK_TCP_RX_PAYLOAD_LEN": runtime[
            "tcp_rx_payload_len"
        ],
        "TLS13_286_LINK_TLS_BUFFERED_PAYLOAD_PTR": runtime[
            "tls_buffered_payload_ptr"
        ],
        "TLS13_286_LINK_TLS_CURRENT_PAYLOAD_LEN": runtime[
            "tls_current_payload_len"
        ],
        "TLS13_286_LINK_APP_CLIENT_KEY": runtime["tls_client_write_key"],
        "TLS13_286_LINK_APP_SERVER_KEY": runtime["tls_server_write_key"],
        "TLS13_286_LINK_APP_CLIENT_IV": runtime["tls_client_write_iv"],
        "TLS13_286_LINK_APP_SERVER_IV": runtime["tls_server_write_iv"],
        "TLS13_286_LINK_APP_CLIENT_SEQ": runtime["tls_client_record_seq"],
        "TLS13_286_LINK_APP_SERVER_SEQ": runtime["tls_server_record_seq"],
        "TLS13_286_LINK_APP_READY": runtime["tls_key_schedule_ready"],
    }
    definitions.update(
        {f"TLS13_286_LINK_{name}": value for name, value in sym.items()}
    )
    include = [
        "; Generated by build_286_runtime_abi.py.",
        "; Bound to the exact K14-complete resident prefix and shipped T13SYM02.",
    ]
    include.extend(
        f"%define {name} 0x{value:04x}"
        for name, value in definitions.items()
    )
    include_data = ("\n".join(include) + "\n").encode("ascii")
    report: dict[str, object] = {
        "schema": "seed-tls13-286-runtime-abi-v1",
        "core": {
            "path": str(core_path.relative_to(ROOT)),
            "bytes": len(core),
            "sha256": sha256(core),
        },
        "listing": {
            "path": str(listing_path.relative_to(ROOT)),
            "sha256": sha256(listing_path.read_bytes()),
        },
        "k14_pack": {
            "path": str(pack_path.relative_to(ROOT)),
            "bytes": len(pack),
            "sha256": sha256(pack),
        },
        "tcp_phase": {
            "sector": phase_sector,
            "sectors": phase_sectors,
            "load": phase_load,
            "connect_entry": connect_entry,
            "close_entry": close_entry,
        },
        "symmetric_phase": {
            "sector": sym_sector,
            "sectors": sym_sectors,
            "image_bytes": definitions["TLS13_286_LINK_SYM_IMAGE_BYTES"],
            "image_sha256": sha256(
                pack[sym_offset : sym_offset + int(
                    definitions["TLS13_286_LINK_SYM_IMAGE_BYTES"]
                )]
            ),
            "fresh_prefix_plus_product_tail_byte_equivalent": True,
            "shipped_canonical": product_image == canonical_image,
            "product_critical_tail": {
                "offset": PRODUCT_CRITICAL_TAIL_OFFSET,
                "bytes": PRODUCT_CRITICAL_TAIL_BYTES,
                "sha256": sha256(critical_tail),
                "source": "canonical exact validated K14 pack bytes",
            },
            "pre_tcp_normalization": {
                "canonical_image_sha256": sha256(canonical_image),
                "initial_pointer_from": (
                    f"0x{PRODUCT_SHA256_INITIAL_STATE:04x}"
                ),
                "initial_pointer_to": f"0x{canonical_initial:04x}",
                "initial_pointer_offsets": initial_pointer_offsets,
                "critical_tail_offset": PRODUCT_CRITICAL_TAIL_OFFSET,
                "critical_tail_bytes": PRODUCT_CRITICAL_TAIL_BYTES,
                "canonical_byte_equivalent": True,
            },
            "entry_count": SYM_ENTRY_COUNT,
        },
        "definitions": {
            name: f"0x{value:04x}" for name, value in definitions.items()
        },
        "include_sha256": sha256(include_data),
    }
    return include_data, report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, default=DEFAULT_CORE)
    parser.add_argument("--listing", type=Path, default=DEFAULT_LISTING)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    include, report = generate(
        args.core.resolve(), args.listing.resolve(), args.pack.resolve()
    )
    atomic_write(args.report, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    atomic_write(args.output, include)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
