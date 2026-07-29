#!/usr/bin/env python3
"""Compose the explicit credentialed-live post-auth TLS 1.3 image.

This is intentionally a sibling of build_live_k15.py.  It consumes an already
completed credential-free secure-FO build and never changes that builder or
its output. A real USER.CFG is packaged only when --credentialed-live,
--automatic-floppy-entropy, and --user-cfg are all supplied. The production
path never reads, prints, or hashes configuration contents; only FAT metadata
is inspected after the ordinary image builder has copied the file. A separate
fixed synthetic-fixture mode exists solely for zero-credit plumbing tests.
"""

from __future__ import annotations

import atexit
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import post_auth_application_check as APP


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEFAULT_BASE = ROOT / "build/crypto-bench/tls13-live-k15"
DEFAULT_BUILD = ROOT / "build/crypto-bench/tls13-live-k15-post-auth"
PRODUCT_BUILD = ROOT / "build/ibm_pc_5150"

CONTROLLER_SOURCE = HERE / "post_auth_live_controller.asm"
LIVE_CONTROLLERS_SOURCE = HERE / "live_k15_controllers.asm"
CALLBACK_SOURCE = HERE / "post_auth_live_callbacks.asm"
USER_LOADER_SOURCE = HERE / "post_auth_user_cfg_loader.asm"
GATE_SOURCE = HERE / "read_only_commit_gate.asm"
PUBLICATION_ADAPTER_SOURCE = HERE / "auth_p256_publication_adapter.asm"
RESUME_CONTROLLER_SOURCE = HERE / "ticket_resumption_controller.asm"
RESUME_DISPATCHER_SOURCE = HERE / "post_auth_resumption_dispatcher.asm"
RESUME_RECEIPT_SOURCE = HERE / "post_auth_resume_receipt_worker.asm"
RESUME_LIFECYCLE_SOURCE = HERE / "post_auth_resume_lifecycle_worker.asm"
RESUME_PREPARE_SOURCE = HERE / "post_auth_resume_prepare_worker.asm"
RESUME_EXCHANGE_SOURCE = HERE / "post_auth_resume_exchange_worker.asm"
RESUME_FO_SOURCE = HERE / "post_auth_resume_fo_worker.asm"
RESUME_SYM_IO_SOURCE = HERE / "post_auth_resume_sym_io_worker.asm"
RESUME_LIVENESS_SOURCE = HERE / "post_auth_resume_liveness_worker.asm"
HELLO_SOURCE = HERE / "hello_overlay.asm"
CACHED_CONNECT_SOURCE = HERE / "post_auth_cached_connect.asm"
IMAGE_BUILDER = ROOT / "tools/build-fat12-image.py"
BASIC_LOADER_SOURCE = ROOT / "targets/ibm_pc_5150/basic/bootstrap.asm"
BASIC_TEXT_BUILDER = ROOT / "tools/build-basic-bootstrap.py"

SECTOR = 512
CORE_START_LBA = 11
BIOS_DRIVE = 1
BASIC_TIMER_IRET = 0x15FF
BASIC_TIMER_IRET_CORE_OFFSET = BASIC_TIMER_IRET - 0x1000
SUPERVISOR_START = 0x3000
AUTH_CONTROLLER_START = 0x3200
GATE_START = 0x1800
CALLBACKS_START = 0x0500
REQUEST_START = 0x0900
USER_LOADER_START = 0x0900
USER_LOADER_LIMIT = 0x0D00
AUTH_CALLBACK_STAGE = 0x0D00
REQUEST_CALLBACK_STAGE = 0x1C00
ADAPTER_STAGE = 0x0D00
ADAPTER_RUNTIME = 0x3400
PUBLICATION_ADAPTER_START = 0x3200
RESUME_LOW_START = 0x0900
RESUME_LOW_LIMIT = 0x0D00
RESUME_PREFIX_START = 0x0B50
RESUME_SUFFIX_START = 0x0C5D
RESUME_AFTER_LIVENESS = 0x0F30
RESUME_LIVENESS_START = 0x0900
RESUME_LIVENESS_LIMIT = 0x0F00
CACHED_CONNECT_ORIGIN = 0x2800
SYM_ENTRY_TABLE = 0x1820
SYM_RECORD_ACTIVE = 0x3520
SYM_SERVER_APP_OPEN_SLOT = SYM_ENTRY_TABLE + 5 * 2
SYM_OPEN_CHUNK_SLOT = SYM_ENTRY_TABLE + 6 * 2
SYM_OPEN_FINISH_SLOT = SYM_ENTRY_TABLE + 7 * 2
SYM_PARSE_NST_SLOT = SYM_ENTRY_TABLE + 12 * 2
SYM_RECEIVED_TAG = 0x3910
SYM_IO = 0x39A0
SYM_TICKET_PRESENT = 0x3C2C
PERSISTENT_START = 0x355D
PERSISTENT_END = 0x3600
RESUME_LIFECYCLE_START = 0x3C76
RESUME_LIFECYCLE_END = 0x3C9A

SYNTHETIC_USER_CFG = (
    b"agent openai\n"
    b"model gpt-5-mini\n"
    b"key sk-seed-post-auth-synthetic-fixture-only\n"
)


@dataclass(frozen=True)
class Phase:
    name: str
    start: int
    count: int
    destination: int
    data: bytes

    @property
    def key(self) -> int:
        return phase_key(self.start, self.count)


PHASE_RUNTIME_DESTINATION_OVERRIDES: dict[str, str | list[str]] = {
    "post_auth_resume_controller": "scatter; see resumption.scatter",
    "post_auth_resume_receipt": "0x3400",
    "post_auth_resume_lifecycle_receipt_hash": "0x3400",
    "post_auth_resume_lifecycle_vault_hash": "0x3400",
    "post_auth_resume_prepare_hash": "0x3400",
    "post_auth_resume_prepare_commit": "0x3400",
    "post_auth_resume_prepare_crypto": "0x3400",
    "post_auth_resume_prepare_binder": "0x3400",
    "post_auth_resume_exchange_tx": "0x3400",
    "post_auth_resume_exchange_post": [
        "0x2400 prefix",
        "0x3400 exact-copied suffix",
    ],
    "post_auth_resume_exchange_restore": "0x3400",
    "post_auth_request_adapter": "0x3400",
    "post_auth_response_literals": "0x3400",
}


@dataclass(frozen=True)
class ConfigMetadata:
    absolute_lba: int
    file_size: int
    cluster_count: int
    sectors_per_track: int
    head_count: int
    cylinder: int
    head: int
    sector_number: int
    core_first_cluster: int
    core_file_size: int
    driver_file_size: int


@dataclass(frozen=True)
class ResumeControllerMetadata:
    low_bytes: int
    prefix_bytes: int
    suffix_bytes: int
    state_start: int
    state_end: int
    callback: int
    stamp_entry: int
    attempt_entry: int


@dataclass(frozen=True)
class HelloMetadata:
    image_bytes: int
    k_start: int
    k_end: int
    ticket_start: int
    ticket_max: int
    attempt_end: int
    entries: tuple[int, ...]


@dataclass(frozen=True)
class CachedConnectMetadata:
    image_bytes: int
    entries: tuple[int, int, int]


@dataclass(frozen=True)
class CallbackMetadata:
    image_bytes: int
    mode: int


@dataclass(frozen=True)
class DispatcherMetadata:
    image_bytes: int
    operations: tuple[tuple[int, int, int], ...]


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def phase_key(start: int, count: int) -> int:
    if not 0 <= start <= 0xFF or not 1 <= count <= 0xFF:
        raise AssertionError(f"phase is not encodable: start={start} count={count}")
    return (count << 8) | start


def parse_hex(value: object, label: str) -> int:
    if not isinstance(value, str):
        raise AssertionError(f"base manifest lacks {label}")
    return int(value, 0)


def parse_phase_entries(
    image: bytes,
    magic: bytes,
    count: int,
    *,
    versions: tuple[int, ...],
) -> tuple[int, ...]:
    if image[:4] != magic:
        raise AssertionError(f"{magic.decode()} phase magic mismatch")
    version, image_bytes = struct.unpack_from("<2H", image, 4)
    if version not in versions or image_bytes != len(image):
        raise AssertionError(f"{magic.decode()} phase header mismatch")
    return struct.unpack_from(f"<{count}H", image, 8)


def parse_resume_controller(image: bytes) -> ResumeControllerMetadata:
    if image[:4] != b"RSU1":
        raise AssertionError("RSU1 controller magic mismatch")
    (
        version,
        image_bytes,
        low_bytes,
        prefix_bytes,
        suffix_bytes,
        state_start,
        state_end,
        callback,
        entry_count,
    ) = struct.unpack_from("<9H", image, 4)
    if (
        version != 1
        or image_bytes != len(image)
        or low_bytes + prefix_bytes + suffix_bytes != len(image)
        or entry_count != 2
    ):
        raise AssertionError("RSU1 controller header mismatch")
    stamp_entry, attempt_entry = struct.unpack_from("<2H", image, 22)
    if (
        not 512 < low_bytes <= 1024
        or prefix_bytes > 0x110
        or suffix_bytes > 0x0A3
        or callback != 0x0500
    ):
        raise AssertionError("RSU1 scatter geometry drifted")
    return ResumeControllerMetadata(
        low_bytes,
        prefix_bytes,
        suffix_bytes,
        state_start,
        state_end,
        callback,
        stamp_entry,
        attempt_entry,
    )


def parse_resumed_hello(image: bytes) -> HelloMetadata:
    if image[:8] != b"T13HEL01":
        raise AssertionError("resumed HELLO phase magic mismatch")
    values = struct.unpack_from("<20H", image, 8)
    (
        version,
        image_bytes,
        k_start,
        k_end,
        _rx_start,
        _rx_end,
        _ek_start,
        _ek_end,
        _c_start,
        _c_end,
        ticket_start,
        ticket_max,
        _server_x,
        _digest,
        _state_start,
        _state_end,
        _sha_start,
        _sha_end,
        attempt_end,
        entry_count,
    ) = values
    entries = struct.unpack_from(f"<{entry_count}H", image, 48)
    if (
        version != 1
        or image_bytes != len(image)
        or k_start != 0x1800
        or k_end != 0x3400
        or ticket_start != 0x3000
        or ticket_max != 192
        or attempt_end != 0x3C02
        or entry_count != 15
        or len(set(entries[9:12])) != 1
        or not all(k_start <= entry < k_start + image_bytes for entry in entries)
    ):
        raise AssertionError("resumed HELLO phase header/ABI drifted")
    return HelloMetadata(
        image_bytes,
        k_start,
        k_end,
        ticket_start,
        ticket_max,
        attempt_end,
        entries,
    )


def parse_cached_connect(image: bytes) -> CachedConnectMetadata:
    if image[:4] != b"RHC1":
        raise AssertionError("cached connector phase magic mismatch")
    version, image_bytes, entry_count = struct.unpack_from("<3H", image, 4)
    entries = struct.unpack_from("<3H", image, 10)
    if (
        version != 1
        or image_bytes != len(image)
        or entry_count != 3
        or not all(
            CACHED_CONNECT_ORIGIN
            <= entry
            < CACHED_CONNECT_ORIGIN + len(image)
            for entry in entries
        )
    ):
        raise AssertionError("cached connector phase header/ABI drifted")
    return CachedConnectMetadata(image_bytes, entries)


def parse_callback_page(image: bytes, expected_mode: int) -> CallbackMetadata:
    offset = image.find(b"PAC1")
    if offset < 0:
        raise AssertionError("post-auth callback page magic mismatch")
    version, image_bytes, mode = struct.unpack_from("<3H", image, offset + 4)
    if (
        version != 2
        or image_bytes != len(image)
        or mode != expected_mode
        or len(image) > 0x100
    ):
        raise AssertionError("post-auth callback page header/size drifted")
    return CallbackMetadata(image_bytes, mode)


def parse_resume_dispatcher(image: bytes) -> DispatcherMetadata:
    header = struct.Struct("<4s4H")
    operation = struct.Struct("<BBHH")
    if len(image) < 2 + header.size + 11 * operation.size or image[0] != 0xEB:
        raise AssertionError("fixed resumption dispatcher is truncated")
    magic, version, image_bytes, origin, entry = header.unpack_from(image, 2)
    if (
        magic != b"RSD1"
        or version != 1
        or image_bytes != len(image)
        or origin != CALLBACKS_START
        or entry != CALLBACKS_START
        or len(image) > 0x100
    ):
        raise AssertionError("fixed resumption dispatcher header/size drifted")
    table_start = len(image) - 11 * operation.size
    operations: list[tuple[int, int, int]] = []
    for index in range(11):
        mode, reserved, key, byte_count = operation.unpack_from(
            image, table_start + index * operation.size
        )
        if reserved != 0 or mode not in {0, 1, 2, 3} or byte_count == 0:
            raise AssertionError("fixed resumption dispatcher table drifted")
        if key >> 8 != (byte_count + SECTOR - 1) // SECTOR:
            raise AssertionError(
                "fixed resumption dispatcher key/length binding drifted"
            )
        operations.append((mode, key, byte_count))
    return DispatcherMetadata(len(image), tuple(operations))


def parse_fixed_worker(
    image: bytes,
    magic: bytes,
    *,
    origin: int,
    limit: int,
) -> int:
    if len(image) < 12 or image[0] != 0xEB or image[2:6] != magic:
        raise AssertionError(f"{magic.decode()} worker header mismatch")
    version, image_bytes, entry = struct.unpack_from("<3H", image, 6)
    if (
        version != 1
        or image_bytes != len(image)
        or entry != origin
        or not 0 < len(image) <= limit
    ):
        raise AssertionError(f"{magic.decode()} worker geometry drifted")
    return entry


def parse_fixed_origin_worker(
    image: bytes,
    magic: bytes,
    *,
    origin: int,
    limit: int,
) -> int:
    if len(image) < 14 or image[0] != 0xEB or image[2:6] != magic:
        raise AssertionError(f"{magic.decode()} worker header mismatch")
    version, image_bytes, embedded_origin, entry = struct.unpack_from(
        "<4H", image, 6
    )
    if (
        version != 1
        or image_bytes != len(image)
        or embedded_origin != origin
        or entry != origin
        or not 0 < len(image) <= limit
    ):
        raise AssertionError(f"{magic.decode()} worker geometry drifted")
    return entry


def listing_symbol_address(
    listing: Path,
    label: str,
    *,
    origin: int,
) -> int:
    lines = listing.read_text(encoding="utf-8").splitlines()
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


def listing_equ_value(listing: Path, label: str) -> int:
    pattern = re.compile(
        rf"\b{re.escape(label)}\s+equ\s+(?:0x)?([0-9A-Fa-f]+)\b",
        re.IGNORECASE,
    )
    for line in listing.read_text(encoding="utf-8").splitlines():
        match = pattern.search(line)
        if match:
            return int(match.group(1), 16)
    raise AssertionError(f"cannot resolve {label} in {listing}")


def listing_mov_word_target(listing: Path, label: str) -> int:
    pattern = re.compile(
        rf"^\s*\d+\s+[0-9A-Fa-f]{{8}}\s+"
        rf"C706([0-9A-Fa-f]{{4}}).*\b{re.escape(label)}\b"
    )
    for line in listing.read_text(encoding="utf-8").splitlines():
        match = pattern.search(line)
        if match:
            encoded = bytes.fromhex(match.group(1))
            return int.from_bytes(encoded, "little")
    raise AssertionError(f"cannot resolve word target {label} in {listing}")


def listing_mov_immediate(listing: Path, label: str) -> int:
    line_pattern = re.compile(
        rf"^\s*\d+\s+[0-9A-Fa-f]{{8}}\s+"
        rf"([0-9A-Fa-f]{{6}})\s+.*\b{re.escape(label)}\b"
    )
    for line in listing.read_text(encoding="utf-8").splitlines():
        match = line_pattern.search(line)
        if not match:
            continue
        encoded = bytes.fromhex(match.group(1))
        if 0xB8 <= encoded[0] <= 0xBF:
            return int.from_bytes(encoded[1:3], "little")
    raise AssertionError(f"cannot resolve immediate {label} in {listing}")


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def assemble(
    source: Path,
    output: Path,
    listing: Path,
    defines: dict[str, int | str],
) -> bytes:
    command = [
        "nasm",
        "-f",
        "bin",
        f"-I{ROOT}/",
        f"-I{HERE}/",
        f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
    ]
    for name, value in defines.items():
        rendered = f"0x{value:x}" if isinstance(value, int) else value
        command.append(f"-D{name}={rendered}")
    command.extend(
        ["-l", str(listing), "-o", str(output), str(source)]
    )
    run(command)
    return output.read_bytes()


def padded(value: bytes, sectors: int) -> bytes:
    capacity = sectors * SECTOR
    if len(value) > capacity:
        raise AssertionError(
            f"{len(value)}-byte phase exceeds {sectors}-sector slot"
        )
    return value.ljust(capacity, b"\0")


def manifest_phases(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    phases = manifest.get("live_phases")
    if not isinstance(phases, list):
        raise AssertionError("base manifest lacks its live phase ledger")
    result: dict[str, dict[str, Any]] = {}
    for phase in phases:
        if not isinstance(phase, dict) or not isinstance(phase.get("name"), str):
            raise AssertionError("base phase ledger contains a malformed entry")
        result[phase["name"]] = phase
    return result


def validate_base(
    base: Path,
) -> tuple[dict[str, Any], bytes, dict[str, dict[str, Any]], Path]:
    manifest_path = base / "manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"missing secure base manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    secure = manifest.get("secure_fo_checkpoint")
    identity = manifest.get("identity_checkpoint")
    literal = manifest.get("literal_gate")
    entropy = manifest.get("entropy_ceremony")
    entropy_mode = (
        entropy.get("operational_mode")
        if isinstance(entropy, dict)
        else None
    )
    entropy_output = entropy.get("output") if isinstance(entropy, dict) else None
    resumption_attempt = (
        entropy_output.get("resumption_attempt")
        if isinstance(entropy_output, dict)
        else None
    )
    if (
        not isinstance(secure, dict)
        or secure.get("enabled") is not True
        or secure.get("credential_unlock") is not False
        or not isinstance(identity, dict)
        or identity.get("enabled") is not True
        or not isinstance(literal, dict)
        or literal.get("credential_files_packaged") is not False
        or not isinstance(entropy, dict)
        or entropy.get("enabled") is not True
        or entropy.get("public_fixture_phase_present") is not False
        or not isinstance(entropy_mode, dict)
        or entropy_mode.get("manual_operator_entry_required") is not False
        or entropy_mode.get("unattended_collection") is not True
        or entropy_mode.get("collection_before_first_network_transmission")
        is not True
        or entropy_mode.get("automated_security_credit_bits") != 0
        or entropy_mode.get("physical_security_credit_pending") is not True
        or not isinstance(resumption_attempt, dict)
        or resumption_attempt.get("one_shot") is not True
        or resumption_attempt.get("domain_separated") is not True
    ):
        raise AssertionError(
            "base artifact is not the credential-free automatic-floppy-entropy "
            "secure-FO checkpoint"
        )
    output = manifest.get("output")
    if not isinstance(output, dict):
        raise AssertionError("base manifest lacks output metadata")
    core_path = Path(str(output.get("core", "")))
    if not core_path.is_absolute():
        core_path = ROOT / core_path
    core = core_path.read_bytes()
    expected_bytes = output.get("core_bytes")
    expected_hash = output.get("core_sha256")
    if (
        expected_bytes != len(core)
        or expected_hash != sha256(core)
        or len(core) % SECTOR
    ):
        raise AssertionError("base core does not match its secure manifest")
    phases = manifest_phases(manifest)
    for required in ("auth_controller", "auth", "sym"):
        if required not in phases:
            raise AssertionError(f"base core lacks {required!r} phase")
    auth_controller = phases["auth_controller"]
    if (
        auth_controller.get("sectors") != 1
        or parse_hex(auth_controller.get("destination"), "auth destination")
        != AUTH_CONTROLLER_START
    ):
        raise AssertionError("base auth-controller geometry drifted")
    return manifest, core, phases, manifest_path


def base_phase_bytes(core: bytes, phase: dict[str, Any]) -> bytes:
    start = int(phase["start_sector"])
    count = int(phase["sectors"])
    value = core[start * SECTOR : (start + count) * SECTOR]
    if len(value) != count * SECTOR:
        raise AssertionError("base phase escapes core")
    return value


def base_phase_payload(core: bytes, phase: dict[str, Any]) -> bytes:
    padded_value = base_phase_bytes(core, phase)
    byte_count = phase.get("bytes")
    digest = phase.get("sha256")
    if (
        not isinstance(byte_count, int)
        or not 0 < byte_count <= len(padded_value)
        or not isinstance(digest, str)
    ):
        raise AssertionError("base phase lacks measured payload metadata")
    value = padded_value[:byte_count]
    if sha256(value) != digest:
        raise AssertionError("base phase payload does not match its manifest")
    return value


def read_at(handle: Any, offset: int, size: int) -> bytes:
    handle.seek(offset)
    value = handle.read(size)
    if len(value) != size:
        raise AssertionError("short FAT metadata read")
    return value


def find_entry(directory: bytes, raw_name: bytes) -> tuple[int, int, int]:
    for offset in range(0, len(directory), 32):
        first = directory[offset]
        if first == 0:
            break
        if first == 0xE5 or directory[offset + 11] & 0x08:
            continue
        if directory[offset : offset + 11] == raw_name:
            return (
                directory[offset + 11],
                int.from_bytes(directory[offset + 26 : offset + 28], "little"),
                int.from_bytes(directory[offset + 28 : offset + 32], "little"),
            )
    raise AssertionError(f"FAT metadata entry {raw_name!r} is absent")


def fat12_entry(fat: bytes, cluster: int) -> int:
    offset = cluster + cluster // 2
    pair = int.from_bytes(fat[offset : offset + 2], "little")
    return (pair >> 4) & 0x0FFF if cluster & 1 else pair & 0x0FFF


def inspect_config_metadata(image: Path) -> ConfigMetadata:
    # Read only the BPB, FAT, root directory, and SEED directory. In
    # particular, never seek to or read the USER.CFG data sector.
    with image.open("rb") as handle:
        boot = read_at(handle, 0, SECTOR)
        bytes_per_sector = int.from_bytes(boot[11:13], "little")
        sectors_per_cluster = boot[13]
        reserved = int.from_bytes(boot[14:16], "little")
        fat_count = boot[16]
        root_entries = int.from_bytes(boot[17:19], "little")
        sectors_per_fat = int.from_bytes(boot[22:24], "little")
        sectors_per_track = int.from_bytes(boot[24:26], "little")
        head_count = int.from_bytes(boot[26:28], "little")
        if (
            bytes_per_sector != SECTOR
            or sectors_per_cluster != 1
            or not sectors_per_track
            or not head_count
        ):
            raise AssertionError("unsupported credentialed-live FAT geometry")
        root_sectors = (root_entries * 32 + SECTOR - 1) // SECTOR
        fat_start = reserved
        root_start = fat_start + fat_count * sectors_per_fat
        data_start = root_start + root_sectors
        fat = read_at(
            handle,
            fat_start * SECTOR,
            sectors_per_fat * SECTOR,
        )
        root = read_at(
            handle,
            root_start * SECTOR,
            root_sectors * SECTOR,
        )
        core_attr, core_cluster, core_size = find_entry(root, b"SEED    SYS")
        seed_attr, seed_cluster, _ = find_entry(root, b"SEED       ")
        if core_attr & 0x10 or not seed_attr & 0x10 or core_cluster != 2:
            raise AssertionError("SEED.SYS is not the first FAT data file")
        seed_lba = data_start + seed_cluster - 2
        seed_directory = read_at(handle, seed_lba * SECTOR, SECTOR)
        drivers_attr, drivers_cluster, _ = find_entry(
            seed_directory, b"DRIVERS    "
        )
        config_attr, config_cluster, config_size = find_entry(
            seed_directory, b"USER    CFG"
        )
        if not drivers_attr & 0x10 or config_attr & 0x10:
            raise AssertionError("packaged driver/config entry has wrong type")
        drivers_lba = data_start + drivers_cluster - 2
        drivers_directory = read_at(handle, drivers_lba * SECTOR, SECTOR)
        driver_attr, _driver_cluster, driver_size = find_entry(
            drivers_directory, b"NE      DRV"
        )
        if driver_attr & 0x10:
            raise AssertionError("packaged NE.DRV has directory type")
        clusters: list[int] = []
        cluster = config_cluster
        while True:
            if cluster < 2 or cluster in clusters:
                raise AssertionError("invalid USER.CFG FAT chain")
            clusters.append(cluster)
            following = fat12_entry(fat, cluster)
            if following >= 0xFF8:
                break
            cluster = following

    absolute_lba = data_start + config_cluster - 2
    cylinder = absolute_lba // (sectors_per_track * head_count)
    remainder = absolute_lba % (sectors_per_track * head_count)
    head = remainder // sectors_per_track
    sector_number = remainder % sectors_per_track + 1
    return ConfigMetadata(
        absolute_lba=absolute_lba,
        file_size=config_size,
        cluster_count=len(clusters),
        sectors_per_track=sectors_per_track,
        head_count=head_count,
        cylinder=cylinder,
        head=head,
        sector_number=sector_number,
        core_first_cluster=core_cluster,
        core_file_size=core_size,
        driver_file_size=driver_size,
    )


def build_image(
    output: Path,
    *,
    core: Path,
    driver: Path,
    user_cfg: Path,
    boot: Path,
    loader: Path,
) -> None:
    run(
        [
            sys.executable,
            str(IMAGE_BUILDER),
            "build",
            "--boot",
            str(boot),
            "--loader",
            str(loader),
            "--loader-sectors",
            "4",
            "--output",
            str(output),
            "--file",
            f"{core}:SEED.SYS",
            "--file",
            f"{driver}:SEED/DRIVERS/NE.DRV",
            "--file",
            f"{user_cfg}:SEED/USER.CFG",
        ]
    )


def phase_report(
    phase: Phase,
    *,
    include_hash: bool,
) -> dict[str, object]:
    report: dict[str, object] = {
        "name": phase.name,
        "start_sector": phase.start,
        "sectors": phase.count,
        "key": f"0x{phase.key:04x}",
        "file_load_stage": f"0x{phase.destination:04x}",
        "runtime_destination": PHASE_RUNTIME_DESTINATION_OVERRIDES.get(
            phase.name,
            f"0x{phase.destination:04x}",
        ),
        "bytes": len(phase.data),
    }
    report["sha256"] = sha256(phase.data) if include_hash else None
    report["hash_deliberately_omitted"] = not include_hash
    return report


def build_and_bind_basic_sidecar(
    build: Path,
    base: Path,
) -> tuple[Path, Path, bytes, bytes]:
    loader = build / "live-k15-basic-loader.bin"
    basic = build / "LIVEK15.BAS"

    def assemble_loader(output: Path, *, timer_boundary: bool) -> None:
        command = [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
            "-DBASIC_BOOTSTRAP_ADDR=0x3a00",
            f"-DSEED_CORE_START_LBA={CORE_START_LBA}",
            "-DSEED_CORE_SECTORS=4",
            "-DSEED_RAM_TOP=0x4000",
            "-DSEED_BOOT_DRIVE=1",
        ]
        if timer_boundary:
            command.append(f"-DBASIC_TIMER_IRET=0x{BASIC_TIMER_IRET:04x}")
        command.extend(
            [
            "-o",
            str(output),
            str(BASIC_LOADER_SOURCE),
            ]
        )
        run(command)

    def build_basic_text(input_path: Path, output_path: Path) -> None:
        run(
            [
            sys.executable,
            str(BASIC_TEXT_BUILDER),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--load-addr",
            "0x3a00",
            "--clear-top",
            "14847",
            "--max-addr",
            "0x4000",
            ]
        )

    # Prove the optional boundary hook does not silently change the secure
    # base sidecar.  Only the credentialed sibling enables it.
    with tempfile.TemporaryDirectory(
        prefix="seed-basic-boundary-", dir=build
    ) as temp_name:
        baseline_loader = Path(temp_name) / "loader.bin"
        baseline_basic = Path(temp_name) / "loader.bas"
        assemble_loader(baseline_loader, timer_boundary=False)
        build_basic_text(baseline_loader, baseline_basic)
        base_loader = base / "live-k15-basic-loader.bin"
        base_basic = base / "LIVEK15.BAS"
        if (
            not base_loader.is_file()
            or not base_basic.is_file()
            or base_loader.read_bytes() != baseline_loader.read_bytes()
            or base_basic.read_bytes() != baseline_basic.read_bytes()
        ):
            raise AssertionError(
                "secure base BASIC sidecar is not the deterministic 16 KiB "
                "read-only loader"
            )

    assemble_loader(loader, timer_boundary=True)
    build_basic_text(loader, basic)
    loader_bytes = loader.read_bytes()
    basic_bytes = basic.read_bytes()
    return loader, basic, loader_bytes, basic_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-build", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument(
        "--credentialed-live",
        action="store_true",
        help="explicitly permit packaging USER.CFG in this isolated live image",
    )
    parser.add_argument(
        "--automatic-floppy-entropy",
        action="store_true",
        help=(
            "select the unattended read-only floppy-timing collector; "
            "physical entropy credit remains pending hardware characterization"
        ),
    )
    parser.add_argument(
        "--synthetic-fixture",
        action="store_true",
        help=(
            "build only the fixed public fake-credential plumbing fixture; "
            "this mode receives zero security credit"
        ),
    )
    parser.add_argument(
        "--user-cfg",
        type=Path,
        help="USER.CFG to package; contents and hash are never inspected or logged",
    )
    parser.add_argument(
        "--boot",
        type=Path,
        default=PRODUCT_BUILD / "boot.bin",
    )
    parser.add_argument(
        "--loader",
        type=Path,
        default=PRODUCT_BUILD / "loader.bin",
    )
    parser.add_argument(
        "--ne-driver",
        type=Path,
        default=PRODUCT_BUILD / "drivers/NE.DRV",
    )
    args = parser.parse_args()

    # This must precede every caller-selected config path existence/stat
    # operation. In particular, no real credential file may be packaged under
    # a fixture or automated-entropy mode.
    if args.credentialed_live == args.synthetic_fixture:
        raise SystemExit(
            "select exactly one of --credentialed-live or --synthetic-fixture"
        )
    base = args.base_build.resolve()
    build = args.build_dir.resolve()
    if build == base:
        raise SystemExit("credentialed output must not replace the secure base build")
    build.mkdir(parents=True, exist_ok=True)
    input_directory = Path(
        tempfile.mkdtemp(prefix=".credential-input-", dir=build)
    )
    atexit.register(shutil.rmtree, input_directory, True)
    opaque_user_cfg = input_directory / "USER.CFG"
    if args.credentialed_live:
        if not args.automatic_floppy_entropy:
            raise SystemExit(
                "--credentialed-live requires --automatic-floppy-entropy"
            )
        if args.user_cfg is None:
            raise SystemExit("--credentialed-live also requires --user-cfg")
        selected_user_cfg = args.user_cfg.resolve()
        if not selected_user_cfg.is_file():
            raise SystemExit("the explicitly selected USER.CFG is not a file")
        config_size = selected_user_cfg.stat().st_size
        if not 1 <= config_size <= SECTOR:
            raise SystemExit("credentialed-live USER.CFG must occupy 1..512 bytes")
        try:
            os.link(selected_user_cfg, opaque_user_cfg)
        except OSError:
            raise SystemExit(
                "unable to stage the credential through an opaque same-filesystem "
                "hard link"
            ) from None
        user_cfg = opaque_user_cfg
    else:
        if args.automatic_floppy_entropy or args.user_cfg is not None:
            raise SystemExit(
                "--synthetic-fixture accepts neither --user-cfg nor "
                "--automatic-floppy-entropy"
            )
        user_cfg = opaque_user_cfg
        user_cfg.write_bytes(SYNTHETIC_USER_CFG)
        config_size = len(SYNTHETIC_USER_CFG)
    for required in (args.boot, args.loader, args.ne_driver):
        if not required.is_file():
            raise SystemExit(f"missing prerequisite artifact: {required}")

    base_manifest, base_core, base_phases, base_manifest_path = validate_base(base)
    base_core_hash = sha256(base_core)
    base_manifest_hash = sha256_file(base_manifest_path)
    driver = args.ne_driver.read_bytes()
    if len(driver) != SECTOR or driver[10:14] != b"SDRV":
        raise AssertionError("credentialed-live requires the packaged NE.DRV")

    app = APP.build_artifacts(build, preloaded_publication=True)
    response_stage_adapter = listing_symbol_address(
        app.paths["request_adapter_listing"],
        "post_auth_live_response_stage_adapter",
        origin=ADAPTER_RUNTIME,
    )
    response_ack_more = listing_symbol_address(
        app.paths["response_literals_listing"],
        "post_auth_live_response_ack_more",
        origin=ADAPTER_RUNTIME,
    )
    response_success_text = listing_symbol_address(
        app.paths["response_literals_listing"],
        "post_auth_live_response_success_text",
        origin=ADAPTER_RUNTIME,
    )
    sym_phase = base_phases["sym"]
    sym_start = int(sym_phase["start_sector"])
    if int(sym_phase["sectors"]) < 9:
        raise AssertionError("base K14 phase lacks the RX-overwritten tail sector")
    if phase_key(sym_start, 9) > 0xFFFF:
        raise AssertionError("base K14 restore key is not encodable")
    base_sym = base_phase_bytes(base_core, sym_phase)
    if base_sym[: len(app.sym)] != app.sym:
        raise AssertionError(
            "post-auth symmetric image differs from the live secure base phase"
        )
    sym_key = parse_hex(sym_phase.get("key"), "complete symmetric phase key")
    if sym_key != phase_key(sym_start, int(sym_phase["sectors"])):
        raise AssertionError("complete symmetric phase key/geometry drifted")

    persistent = base_manifest.get("persistent_services")
    if not isinstance(persistent, dict):
        raise AssertionError("secure base lacks persistent services")
    persist_zero_window = parse_hex(
        persistent.get("zero_window"), "persistent zero-window"
    )
    persist_emit = parse_hex(persistent.get("emit"), "persistent emit")
    persist_transition = parse_hex(
        persistent.get("transition"), "persistent transition"
    )
    persist_fail = parse_hex(persistent.get("fail"), "persistent fail")

    secure_checkpoint = base_manifest.get("secure_fo_checkpoint")
    if not isinstance(secure_checkpoint, dict):
        raise AssertionError("secure base lacks its FO checkpoint")
    packaged_driver = secure_checkpoint.get("packaged_driver")
    if not isinstance(packaged_driver, dict):
        raise AssertionError("secure base lacks guarded-driver metadata")
    ne_buf_load = parse_hex(
        packaged_driver.get("remote_dma_write"), "guarded NE2000 write leaf"
    )
    ne_buf_read = parse_hex(
        packaged_driver.get("remote_dma_read"), "guarded NE2000 read leaf"
    )
    expected_driver_hash = packaged_driver.get("sha256")
    if (
        not isinstance(expected_driver_hash, str)
        or sha256(driver) != expected_driver_hash
        or packaged_driver.get("bytes") != len(driver)
        or packaged_driver.get("probe_sha256") != expected_driver_hash
        or packaged_driver.get("byte_identical") is not True
        or ne_buf_load != 0x1724
        or ne_buf_read != 0x175B
    ):
        raise AssertionError(
            "selected NE.DRV differs from the base-probed guarded driver"
        )

    for required_phase in (
        "post_controller",
        "fo_controller",
        "scrub_controller",
        "fo",
        "crypto_controller",
    ):
        if required_phase not in base_phases:
            raise AssertionError(
                f"secure base lacks fixed {required_phase!r} phase"
            )
    base_post_controller = base_phase_payload(
        base_core, base_phases["post_controller"]
    )
    base_fo_controller = base_phase_payload(
        base_core, base_phases["fo_controller"]
    )
    base_scrub_controller = base_phase_payload(
        base_core, base_phases["scrub_controller"]
    )
    base_crypto_controller = base_phase_payload(
        base_core, base_phases["crypto_controller"]
    )
    if len(base_post_controller) != 1012:
        raise AssertionError("legacy post controller geometry drifted")
    fo_controller_key = parse_hex(
        base_phases["fo_controller"].get("key"), "fixed FO controller key"
    )
    scrub_controller_key = parse_hex(
        base_phases["scrub_controller"].get("key"),
        "fixed scrub-controller key",
    )
    fo_kernel_key = parse_hex(
        base_phases["fo"].get("key"), "fixed FO-kernel key"
    )
    auth_controller_key = parse_hex(
        base_phases["auth_controller"].get("key"),
        "fixed auth-controller key",
    )
    crypto_controller_key = parse_hex(
        base_phases["crypto_controller"].get("key"),
        "fixed recovery-controller key",
    )
    for name, expected_sectors, expected_destination in (
        ("post_controller", 2, 0x0900),
        ("fo_controller", 1, 0x2400),
        ("scrub_controller", 1, 0x2400),
    ):
        phase = base_phases[name]
        start = int(phase["start_sector"])
        sectors = int(phase["sectors"])
        if (
            sectors != expected_sectors
            or parse_hex(phase.get("key"), f"{name} key")
            != phase_key(start, sectors)
            or parse_hex(phase.get("destination"), f"{name} destination")
            != expected_destination
        ):
            raise AssertionError(f"secure base {name} geometry drifted")
    for name, expected_destination in (
        ("fo", 0x1800),
        ("auth_controller", 0x3200),
        ("crypto_controller", 0x3400),
    ):
        phase = base_phases[name]
        start = int(phase["start_sector"])
        sectors = int(phase["sectors"])
        if (
            parse_hex(phase.get("key"), f"{name} key")
            != phase_key(start, sectors)
            or parse_hex(phase.get("destination"), f"{name} destination")
            != expected_destination
        ):
            raise AssertionError(f"secure base {name} geometry drifted")
    crypto_listing = base / "live_crypto_controller.lst"
    if not crypto_listing.is_file():
        raise AssertionError("secure base lacks recovery-controller listing")
    base_recovery_fail = listing_symbol_address(
        crypto_listing, "live_secure_persist_fail", origin=0x3400
    )
    if (
        base_recovery_fail != persist_fail
        or len(base_crypto_controller) != SECTOR - 1
    ):
        raise AssertionError("secure base recovery controller drifted")
    scrub_listing = base / "live_scrub_controller.lst"
    if not scrub_listing.is_file():
        raise AssertionError("secure base lacks scrub-controller listing")
    scrub_card_pages = listing_symbol_address(
        scrub_listing, "scrub_card_pages", origin=0x2400
    )
    if (
        len(base_scrub_controller) != 118
        or scrub_card_pages != 0x2432
        or not 0x2400 <= scrub_card_pages < 0x2400 + len(base_scrub_controller)
    ):
        raise AssertionError(
            "secure base does not contain the expanded 0x73..0x7f scrub"
        )
    card_vault = secure_checkpoint.get("card_vault")
    failure_cleanup = (
        card_vault.get("failure_cleanup")
        if isinstance(card_vault, dict)
        else None
    )
    if (
        not isinstance(failure_cleanup, dict)
        or failure_cleanup.get("phase_key")
        != f"0x{scrub_controller_key:04x}"
        or failure_cleanup.get("card_pages_attempted_after_successful_load")
        != "0x73..0x7f"
        or failure_cleanup.get("card_page_count") != 13
        or failure_cleanup.get("all_card_pages_attempted_with_aggregate_failure")
        is not True
    ):
        raise AssertionError("secure base scrub manifest is stale")

    sym_listing = app.paths["sym_listing"]
    sha256_init = listing_symbol_address(
        sym_listing, "sha256_init", origin=0x1800
    )
    sha256_update = listing_symbol_address(
        sym_listing, "sha256_update", origin=0x1800
    )
    sha256_finish = listing_symbol_address(
        sym_listing, "sha256_finish", origin=0x1800
    )
    sym_init = app.sym_entries[0]
    sym_resumption_binder = app.sym_entries[13]
    sym_image_crc16 = 0xFFFF
    for byte in app.sym:
        sym_image_crc16 ^= byte
        for _ in range(8):
            if sym_image_crc16 & 1:
                sym_image_crc16 = (
                    (sym_image_crc16 >> 1) ^ 0xA001
                )
            else:
                sym_image_crc16 >>= 1
    sym_image_crc16 &= 0xFFFF
    sym_binder_hash = listing_equ_value(
        sym_listing, "sym_pre_finished_hash"
    )
    sym_binder_value = listing_equ_value(
        sym_listing, "sym_client_finished_verify"
    )
    sym_shared_secret = listing_equ_value(
        sym_listing, "sym_input_shared_secret"
    )
    sym_early_derived = listing_equ_value(
        sym_listing, "sym_handshake_derived"
    )
    sym_early_secret = listing_equ_value(
        sym_listing, "sym_handshake_secret"
    )
    sym_hello_hash = listing_equ_value(
        sym_listing, "sym_input_hello_hash"
    )
    sym_client_secret = listing_equ_value(
        sym_listing, "sym_client_app_secret"
    )
    sym_early_head_hold = listing_equ_value(
        sym_listing, "sym_received_server_finished"
    )
    sym_prepare_secret = listing_symbol_address(
        sym_listing, "tls13_prepare_secret", origin=0x1800
    )
    sym_expand_label = listing_symbol_address(
        sym_listing, "tls13_expand_label_prepared", origin=0x1800
    )
    sym_expand_group = listing_symbol_address(
        sym_listing, "tls13_expand_group", origin=0x1800
    )
    sym_client_key_group = listing_symbol_address(
        sym_listing, "tls13_group_client_application", origin=0x1800
    )
    sym_seal_record = listing_symbol_address(
        sym_listing, "sym_seal_record", origin=0x1800
    )
    sym_transcript_snapshot = listing_symbol_address(
        sym_listing, "sym_transcript_snapshot", origin=0x1800
    )
    sym_label_ptr = listing_mov_word_target(
        sym_listing, "tls13_expand_label_ptr"
    )
    sym_label_len = sym_label_ptr + 2
    sym_context_ptr = sym_label_len + 2
    sym_context_len = sym_context_ptr + 2
    sym_output_ptr = sym_context_len + 2
    sym_output_len = sym_output_ptr + 2

    gate_path = build / "post_auth_route_gate.bin"
    gate_listing = build / "post_auth_route_gate.lst"
    gate = assemble(
        GATE_SOURCE,
        gate_path,
        gate_listing,
        {
            "GATE_CREDENTIAL_LOADER_CALLBACK": 0x0520,
            "GATE_CREDENTIAL_PHASE_KEY": 1,
            "GATE_CREDENTIAL_DESTINATION": ADAPTER_RUNTIME,
        },
    )
    gate_entries = parse_phase_entries(
        gate,
        b"ROG3",
        5,
        versions=(4,),
    )
    (
        gate_commit,
        _gate_unlock,
        _gate_abort,
        gate_authorize,
        gate_validate_ticket_only,
    ) = gate_entries
    if len(gate) > 2 * SECTOR:
        raise AssertionError("ROG3 exceeds its two-sector phase")

    resume_receipt = assemble(
        RESUME_RECEIPT_SOURCE,
        build / "post_auth_resume_receipt.bin",
        build / "post_auth_resume_receipt.lst",
        {
            "RESUME_RECEIPT_SHA256_INIT": sha256_init,
            "RESUME_RECEIPT_SHA256_UPDATE": sha256_update,
            "RESUME_RECEIPT_SHA256_FINISH": sha256_finish,
            "RESUME_RECEIPT_NE_BUF_LOAD": ne_buf_load,
            "RESUME_RECEIPT_NE_BUF_READ": ne_buf_read,
            "RESUME_RECEIPT_FO_KEY": fo_controller_key,
            "RESUME_RECEIPT_PERSIST_FAIL": persist_fail,
        },
    )
    parse_fixed_worker(
        resume_receipt,
        b"NTRW",
        origin=0x3400,
        limit=0x110,
    )
    if len(resume_receipt) > SECTOR:
        raise AssertionError("NTR1 receipt worker exceeds one file sector")

    publication_adapter_path = build / "post_auth_publication_adapter.bin"
    publication_adapter_listing = build / "post_auth_publication_adapter.lst"
    publication_adapter = assemble(
        PUBLICATION_ADAPTER_SOURCE,
        publication_adapter_path,
        publication_adapter_listing,
        {},
    )
    (publication_adapter_entry,) = parse_phase_entries(
        publication_adapter,
        b"LPA1",
        1,
        versions=(1,),
    )
    if len(publication_adapter) > SECTOR:
        raise AssertionError("LP1 publication adapter exceeds one sector")

    resume_controller_path = build / "post_auth_resume_controller.bin"
    resume_controller_listing = build / "post_auth_resume_controller.lst"
    resume_controller = assemble(
        RESUME_CONTROLLER_SOURCE,
        resume_controller_path,
        resume_controller_listing,
        {
            "RESUME_CONTROLLER_ORIGIN": RESUME_LOW_START,
            "RESUME_CONTROLLER_LIMIT": RESUME_LOW_LIMIT,
            "RESUME_HIGH_PREFIX_ORIGIN": RESUME_PREFIX_START,
            "RESUME_HIGH_SUFFIX_ORIGIN": RESUME_SUFFIX_START,
            "RESUME_OUTER_AFTER_LIVENESS": RESUME_AFTER_LIVENESS,
            "RESUME_DIRECT_SYM_IO_ENTRY": ADAPTER_STAGE,
            "RESUME_DIRECT_TCP_SEND": 0x13BF,
            "RESUME_DIRECT_ZERO_WINDOW": persist_zero_window,
            "RESUME_DEFER_CLIENT_APP_TO_SYM_IO": 1,
        },
    )
    resume_metadata = parse_resume_controller(resume_controller)
    resume_after_prepare = listing_symbol_address(
        resume_controller_listing,
        "resume_after_prepare_callback",
        origin=RESUME_LOW_START,
    )
    if (
        len(resume_controller) > 2 * SECTOR
        or resume_metadata.low_bytes != RESUME_PREFIX_START - RESUME_LOW_START
        or RESUME_PREFIX_START + resume_metadata.prefix_bytes
        > RESUME_SUFFIX_START
        or RESUME_SUFFIX_START + resume_metadata.suffix_bytes > RESUME_LOW_LIMIT
    ):
        raise AssertionError("RSU1 controller exceeds two file sectors")

    resumed_hello_path = build / "post_auth_resumed_hello.bin"
    resumed_hello_listing = build / "post_auth_resumed_hello.lst"
    resumed_hello = assemble(
        HELLO_SOURCE,
        resumed_hello_path,
        resumed_hello_listing,
        {
            "TLS13_POC_K14": 1,
            "HELLO_RESUMED_ONLY": 1,
            "HELLO_RESUMED_EARLY_DATA": 1,
        },
    )
    resumed_hello_metadata = parse_resumed_hello(resumed_hello)
    if len(resumed_hello) > 8 * SECTOR:
        raise AssertionError("resumed HELLO exceeds its eight-sector restore")
    hello_truncated_digest = listing_mov_immediate(
        resumed_hello_listing, "hello_truncated_digest"
    )
    hello_binder_value = listing_mov_immediate(
        resumed_hello_listing, "hello_secret_b"
    )
    hello_client_digest = resumed_hello_metadata.entries[14]
    if not (
        0x0D00 <= hello_truncated_digest < 0x1000
        and hello_truncated_digest + 32 <= hello_binder_value < 0x1000
    ):
        raise AssertionError("resumed HELLO binder ABI drifted")

    cached_connect_path = build / "post_auth_cached_connect.bin"
    cached_connect_listing = build / "post_auth_cached_connect.lst"
    cached_connect = assemble(
        CACHED_CONNECT_SOURCE,
        cached_connect_path,
        cached_connect_listing,
        {
            "POST_AUTH_CACHED_CONNECT_ORIGIN": CACHED_CONNECT_ORIGIN,
        },
    )
    cached_connect_metadata = parse_cached_connect(cached_connect)
    if len(cached_connect) > SECTOR:
        raise AssertionError("cached connector exceeds its one-sector phase")

    base_cursor = len(base_core) // SECTOR
    reservations = (
        (
            "post_auth_publication_adapter",
            1,
            PUBLICATION_ADAPTER_START,
        ),
        ("post_auth_supervisor", 2, SUPERVISOR_START),
        ("post_auth_route_gate", 2, GATE_START),
        ("post_auth_resume_controller", 2, ADAPTER_STAGE),
        ("post_auth_cached_connect", 1, CACHED_CONNECT_ORIGIN),
        ("post_auth_resumed_hello", 8, 0x1800),
        ("post_auth_resume_receipt", 1, AUTH_CALLBACK_STAGE),
        ("post_auth_resume_lifecycle", 2, 0x3000),
        ("post_auth_resume_lifecycle_receipt_hash", 1, 0x2400),
        ("post_auth_resume_lifecycle_vault_hash", 1, 0x2400),
        ("post_auth_resume_prepare", 2, 0x3000),
        ("post_auth_resume_prepare_hash", 1, 0x3000),
        ("post_auth_resume_prepare_commit", 1, 0x3000),
        ("post_auth_resume_prepare_crypto", 1, 0x3000),
        ("post_auth_resume_prepare_age", 1, 0x2800),
        ("post_auth_resume_prepare_binder", 1, 0x3000),
        ("post_auth_resume_prepare_sym_binder", 1, 0x3400),
        ("post_auth_resume_prepare_early", 1, 0x3400),
        ("post_auth_resume_prepare_restore", 1, 0x3000),
        ("post_auth_resume_exchange", 1, 0x3000),
        ("post_auth_resume_exchange_tx", 1, 0x3000),
        ("post_auth_resume_exchange_rx", 2, 0x2800),
        ("post_auth_resume_exchange_crypto", 1, 0x3000),
        ("post_auth_resume_exchange_post", 1, 0x2400),
        ("post_auth_resume_exchange_restore", 1, 0x0700),
        ("post_auth_resume_fo", 1, 0x3000),
        ("post_auth_resume_fo_controller", 3, 0x2400),
        ("post_auth_resume_sym_io", 1, ADAPTER_STAGE),
        ("post_auth_resume_dispatcher", 1, CALLBACKS_START),
        ("post_auth_resume_liveness", 2, RESUME_LIVENESS_START),
        ("post_auth_auth_callbacks", 1, CALLBACKS_START),
        ("post_auth_user_loader", 2, USER_LOADER_START),
        ("post_auth_request_callbacks", 1, CALLBACKS_START),
        ("post_auth_request", 2, REQUEST_START),
        ("post_auth_request_adapter", 1, ADAPTER_STAGE),
        ("post_auth_response", 2, REQUEST_START),
        ("post_auth_response_literals", 1, ADAPTER_STAGE),
    )
    phase_geometry: dict[str, tuple[int, int, int]] = {}
    cursor = base_cursor
    for name, count, destination in reservations:
        phase_geometry[name] = (cursor, count, destination)
        cursor += count
    if cursor >= 256:
        raise AssertionError("credentialed phase tail exceeds 8-bit phase offsets")
    appended_keys = [
        phase_key(start, count)
        for start, count, _destination in phase_geometry.values()
    ]
    if len(appended_keys) != len(set(appended_keys)):
        raise AssertionError("credentialed phase ledger contains a key collision")
    critical_base_keys = {
        sym_key,
        phase_key(sym_start, 8),
        phase_key(sym_start, 9),
        phase_key(sym_start, 10),
        fo_controller_key,
        scrub_controller_key,
        fo_kernel_key,
        auth_controller_key,
        crypto_controller_key,
    }
    if critical_base_keys.intersection(appended_keys):
        raise AssertionError("credentialed phase key aliases a reused base phase")

    def key(name: str) -> int:
        start, count, _destination = phase_geometry[name]
        return phase_key(start, count)

    legacy_post_defines = {
        "LIVE_K15_POST_CONTROLLER": 1,
        "LIVE_K15_PERSIST_FAIL": persist_fail,
        "LIVE_K15_PERSIST_EMIT": persist_emit,
        "LIVE_K15_IDENTITY_CAPTURE": 1,
        "LIVE_K15_PERSIST_ZERO_WINDOW": persist_zero_window,
        "LIVE_K15_PERSIST_TRANSITION": persist_transition,
        "LIVE_K15_SECURE_FO": 1,
        "LIVE_K15_FO_CONTROLLER_KEY": fo_controller_key,
    }
    legacy_post_controller = assemble(
        LIVE_CONTROLLERS_SOURCE,
        build / "post_auth_legacy_post_controller.bin",
        build / "post_auth_legacy_post_controller.lst",
        legacy_post_defines,
    )
    if legacy_post_controller != base_post_controller:
        raise AssertionError(
            "current legacy post controller is not byte-identical to secure base"
        )
    current_fo_controller = assemble(
        LIVE_CONTROLLERS_SOURCE,
        build / "post_auth_base_fo_controller.bin",
        build / "post_auth_base_fo_controller.lst",
        {
            "LIVE_K15_FO_CONTROLLER": 1,
            "LIVE_K15_FO_PHASE_KEY": fo_kernel_key,
            "LIVE_K15_AUTH_CONTROLLER_KEY": auth_controller_key,
            "LIVE_K15_NE_BUF_LOAD": ne_buf_load,
            "LIVE_K15_NE_BUF_READ": ne_buf_read,
            "LIVE_K15_PERSIST_FAIL": persist_fail,
            "LIVE_K15_PERSIST_EMIT": persist_emit,
        },
    )
    current_scrub_listing = build / "post_auth_base_scrub_controller.lst"
    current_scrub_controller = assemble(
        LIVE_CONTROLLERS_SOURCE,
        build / "post_auth_base_scrub_controller.bin",
        current_scrub_listing,
        {
            "LIVE_K15_SCRUB_CONTROLLER": 1,
            "LIVE_K15_NE_BUF_LOAD": ne_buf_load,
            "LIVE_K15_PERSIST_EMIT": persist_emit,
        },
    )
    current_scrub_entry = listing_symbol_address(
        current_scrub_listing, "scrub_card_pages", origin=0x2400
    )
    if (
        current_fo_controller != base_fo_controller
        or current_scrub_controller != base_scrub_controller
        or current_scrub_entry != scrub_card_pages
    ):
        raise AssertionError(
            "current fixed FO/scrub controllers differ from secure base"
        )
    receipt_post_controller = assemble(
        LIVE_CONTROLLERS_SOURCE,
        build / "post_auth_receipt_post_controller.bin",
        build / "post_auth_receipt_post_controller.lst",
        {
            **legacy_post_defines,
            "LIVE_K15_RESUME_RECEIPT": 1,
            "LIVE_K15_RESUME_RECEIPT_KEY": key(
                "post_auth_resume_receipt"
            ),
            "LIVE_K15_RESUME_RECEIPT_BYTES": len(resume_receipt),
        },
    )
    if len(receipt_post_controller) != 2 * SECTOR:
        raise AssertionError(
            "receipt-hooked post controller must exactly fill its base slot"
        )

    lifecycle_bridge_common = {
        "RESUME_LIFECYCLE_SYM_KEY": sym_key,
        "RESUME_LIFECYCLE_SHA256_INIT": sha256_init,
        "RESUME_LIFECYCLE_SHA256_UPDATE": sha256_update,
        "RESUME_LIFECYCLE_SHA256_FINISH": sha256_finish,
        "RESUME_LIFECYCLE_SELF_KEY": key("post_auth_resume_lifecycle"),
    }
    resume_lifecycle_receipt_hash = assemble(
        RESUME_LIFECYCLE_SOURCE,
        build / "post_auth_resume_lifecycle_receipt_hash.bin",
        build / "post_auth_resume_lifecycle_receipt_hash.lst",
        {
            **lifecycle_bridge_common,
            "RESUME_LIFECYCLE_RECEIPT_HASH": 1,
        },
    )
    resume_lifecycle_vault_hash = assemble(
        RESUME_LIFECYCLE_SOURCE,
        build / "post_auth_resume_lifecycle_vault_hash.bin",
        build / "post_auth_resume_lifecycle_vault_hash.lst",
        {
            **lifecycle_bridge_common,
            "RESUME_LIFECYCLE_VAULT_HASH": 1,
        },
    )
    parse_fixed_worker(
        resume_lifecycle_receipt_hash,
        b"RVNH",
        origin=0x3400,
        limit=0x110,
    )
    parse_fixed_worker(
        resume_lifecycle_vault_hash,
        b"RVVH",
        origin=0x3400,
        limit=0x110,
    )
    resume_lifecycle = assemble(
        RESUME_LIFECYCLE_SOURCE,
        build / "post_auth_resume_lifecycle.bin",
        build / "post_auth_resume_lifecycle.lst",
        {
            "RESUME_LIFECYCLE_NE_BUF_READ": ne_buf_read,
            "RESUME_LIFECYCLE_SCRUB_KEY": scrub_controller_key,
            "RESUME_LIFECYCLE_SCRUB_ENTRY": scrub_card_pages,
            "RESUME_LIFECYCLE_GATE_KEY": key("post_auth_route_gate"),
            "RESUME_LIFECYCLE_GATE_VALIDATE": gate_validate_ticket_only,
            "RESUME_LIFECYCLE_RECEIPT_HASH_KEY": key(
                "post_auth_resume_lifecycle_receipt_hash"
            ),
            "RESUME_LIFECYCLE_RECEIPT_HASH_BYTES": len(
                resume_lifecycle_receipt_hash
            ),
            "RESUME_LIFECYCLE_VAULT_HASH_KEY": key(
                "post_auth_resume_lifecycle_vault_hash"
            ),
            "RESUME_LIFECYCLE_VAULT_HASH_BYTES": len(
                resume_lifecycle_vault_hash
            ),
        },
    )
    parse_fixed_worker(
        resume_lifecycle,
        b"RVLW",
        origin=0x3000,
        limit=0x400,
    )
    if len(resume_lifecycle) > 2 * SECTOR:
        raise AssertionError("RVLW lifecycle worker exceeds two file sectors")

    for required_phase in ("keygen", "candidate"):
        if required_phase not in base_phases:
            raise AssertionError(
                f"secure base lacks fixed {required_phase!r} crypto phase"
            )
    keygen_key = parse_hex(
        base_phases["keygen"].get("key"), "fixed KeyGen phase key"
    )
    candidate_key = parse_hex(
        base_phases["candidate"].get("key"), "fixed candidate phase key"
    )
    if (
        keygen_key
        != phase_key(
            int(base_phases["keygen"]["start_sector"]),
            int(base_phases["keygen"]["sectors"]),
        )
        or candidate_key
        != phase_key(
            int(base_phases["candidate"]["start_sector"]),
            int(base_phases["candidate"]["sectors"]),
        )
        or
        parse_hex(
            base_phases["keygen"].get("destination"),
            "KeyGen destination",
        )
        != 0x1800
        or parse_hex(
            base_phases["candidate"].get("destination"),
            "candidate destination",
        )
        != 0x1800
    ):
        raise AssertionError("base ML-KEM phase destination drifted")

    base_delta_loader = base / "live_delta_loader.bin"
    if not base_delta_loader.is_file():
        raise AssertionError("secure base lacks its embedded delta loader")
    current_crypto_listing = build / "post_auth_base_crypto_controller.lst"
    current_crypto_controller = assemble(
        LIVE_CONTROLLERS_SOURCE,
        build / "post_auth_base_crypto_controller.bin",
        current_crypto_listing,
        {
            "LIVE_K15_SECURE_CRYPTO_CONTROLLER": 1,
            "LIVE_K15_CANDIDATE_KEY": candidate_key,
            "LIVE_K15_DELTA_LOADER_PATH": (
                f'"{base_delta_loader.as_posix()}"'
            ),
            "LIVE_K15_CORE_START_LBA": CORE_START_LBA,
            "LIVE_K15_NE_BUF_LOAD": ne_buf_load,
            "LIVE_K15_NE_BUF_READ": ne_buf_read,
            "LIVE_K15_SCRUB_CONTROLLER_KEY": scrub_controller_key,
        },
    )
    current_recovery_fail = listing_symbol_address(
        current_crypto_listing,
        "live_secure_persist_fail",
        origin=0x3400,
    )
    if (
        current_crypto_controller != base_crypto_controller
        or current_recovery_fail != base_recovery_fail
    ):
        raise AssertionError(
            "current recovery crypto controller differs from secure base"
        )

    prepare_common = {
        "RESUME_PREPARE_LOAD_PHASE": 0x10C4,
        "RESUME_PREPARE_NE_BUF_READ": ne_buf_read,
        "RESUME_PREPARE_NE_BUF_LOAD": ne_buf_load,
        "RESUME_PREPARE_NIC_BASE": 0x060E,
        "RESUME_PREPARE_NE_TX_START": 0x06CB,
        "RESUME_PREPARE_LIFECYCLE_START": RESUME_LIFECYCLE_START,
        "RESUME_PREPARE_LIFECYCLE_END": RESUME_LIFECYCLE_END,
        "RESUME_PREPARE_PERSIST_FAIL": current_recovery_fail,
        "RESUME_PREPARE_EXPECTED_RETURN": resume_after_prepare,
    }
    resume_controller_start = phase_geometry[
        "post_auth_resume_controller"
    ][0]
    prepare_binder_common = {
        name: value
        for name, value in prepare_common.items()
        if name
        not in {
            "RESUME_PREPARE_DIAGNOSTIC",
            "RESUME_PREPARE_EXPECTED_RETURN",
        }
    }
    resume_prepare_restore = assemble(
        RESUME_PREPARE_SOURCE,
        build / "post_auth_resume_prepare_restore.bin",
        build / "post_auth_resume_prepare_restore.lst",
        {
            **prepare_common,
            "RESUME_PREPARE_RESTORE": 1,
            "RESUME_PREPARE_CONTROLLER_HEAD_KEY": phase_key(
                resume_controller_start, 1
            ),
            "RESUME_PREPARE_CONTROLLER_TAIL_KEY": phase_key(
                resume_controller_start + 1, 1
            ),
            "RESUME_PREPARE_CONTROLLER_LOW_START": RESUME_LOW_START,
            "RESUME_PREPARE_CONTROLLER_LOW_BYTES": (
                resume_metadata.low_bytes
            ),
            "RESUME_PREPARE_CONTROLLER_PREFIX_START": RESUME_PREFIX_START,
            "RESUME_PREPARE_CONTROLLER_PREFIX_BYTES": (
                resume_metadata.prefix_bytes
            ),
            "RESUME_PREPARE_CONTROLLER_SUFFIX_START": RESUME_SUFFIX_START,
            "RESUME_PREPARE_CONTROLLER_SUFFIX_BYTES": (
                resume_metadata.suffix_bytes
            ),
            "RESUME_PREPARE_SYM_EARLY_DERIVED": sym_early_derived,
            "RESUME_PREPARE_SYM_EARLY_HEAD_HOLD": sym_early_head_hold,
            "RESUME_PREPARE_SYM_EARLY_EOED": SYM_IO,
        },
    )
    resume_prepare_early = assemble(
        RESUME_PREPARE_SOURCE,
        build / "post_auth_resume_prepare_early.bin",
        build / "post_auth_resume_prepare_early.lst",
        {
            **prepare_binder_common,
            "RESUME_PREPARE_EARLY": 1,
            "RESUME_PREPARE_SYM_EARLY_SECRET": sym_early_secret,
            "RESUME_PREPARE_SYM_HELLO_HASH": sym_hello_hash,
            "RESUME_PREPARE_SYM_CLIENT_SECRET": sym_client_secret,
            "RESUME_PREPARE_SYM_PREPARE_SECRET": sym_prepare_secret,
            "RESUME_PREPARE_SYM_EXPAND_LABEL": sym_expand_label,
            "RESUME_PREPARE_SYM_EXPAND_GROUP": sym_expand_group,
            "RESUME_PREPARE_SYM_CLIENT_KEY_GROUP": sym_client_key_group,
            "RESUME_PREPARE_SYM_BUILD_HEAD": app.sym_entries[11],
            "RESUME_PREPARE_SYM_SEAL_RECORD": sym_seal_record,
            "RESUME_PREPARE_SYM_EARLY_IO": SYM_IO,
            "RESUME_PREPARE_SYM_EARLY_HEAD_HOLD": sym_early_head_hold,
            "RESUME_PREPARE_SYM_LABEL_PTR": sym_label_ptr,
            "RESUME_PREPARE_SYM_LABEL_LEN": sym_label_len,
            "RESUME_PREPARE_SYM_CONTEXT_PTR": sym_context_ptr,
            "RESUME_PREPARE_SYM_CONTEXT_LEN": sym_context_len,
            "RESUME_PREPARE_SYM_OUTPUT_PTR": sym_output_ptr,
            "RESUME_PREPARE_SYM_OUTPUT_LEN": sym_output_len,
            "RESUME_PREPARE_RESTORE_KEY": key(
                "post_auth_resume_prepare_restore"
            ),
        },
    )
    resume_prepare_sym_binder = assemble(
        RESUME_PREPARE_SOURCE,
        build / "post_auth_resume_prepare_sym_binder.bin",
        build / "post_auth_resume_prepare_sym_binder.lst",
        {
            **prepare_binder_common,
            "RESUME_PREPARE_SYM_BINDER": 1,
            "RESUME_PREPARE_SYM_KEY": sym_key,
            "RESUME_PREPARE_SYM_INIT": sym_init,
            "RESUME_PREPARE_SYM_BINDER_ENTRY": sym_resumption_binder,
            "RESUME_PREPARE_SYM_BINDER_HASH": sym_binder_hash,
            "RESUME_PREPARE_SYM_BINDER_VALUE": sym_binder_value,
            "RESUME_PREPARE_SYM_IMAGE_BYTES": len(app.sym),
            "RESUME_PREPARE_SYM_IMAGE_SECTORS": (
                (len(app.sym) + SECTOR - 1) // SECTOR
            ),
            "RESUME_PREPARE_SYM_IMAGE_CRC16": sym_image_crc16,
            "RESUME_PREPARE_EARLY_KEY": key(
                "post_auth_resume_prepare_early"
            ),
            "RESUME_PREPARE_EARLY_BYTES": len(resume_prepare_early),
            "RESUME_PREPARE_RESTORE_KEY": key(
                "post_auth_resume_prepare_restore"
            ),
        },
    )
    resume_prepare_binder = assemble(
        RESUME_PREPARE_SOURCE,
        build / "post_auth_resume_prepare_binder.bin",
        build / "post_auth_resume_prepare_binder.lst",
        {
            **prepare_binder_common,
            "RESUME_PREPARE_BINDER": 1,
            "RESUME_PREPARE_HELLO_BEGIN": resumed_hello_metadata.entries[1],
            "RESUME_PREPARE_HELLO_NEXT": resumed_hello_metadata.entries[2],
            "RESUME_PREPARE_HELLO_DONE": resumed_hello_metadata.entries[3],
            "RESUME_PREPARE_HELLO_CLIENT_DIGEST": hello_client_digest,
            "RESUME_PREPARE_HELLO_TRUNCATED": hello_truncated_digest,
            "RESUME_PREPARE_HELLO_BINDER": hello_binder_value,
            "RESUME_PREPARE_SYM_BINDER_KEY": key(
                "post_auth_resume_prepare_sym_binder"
            ),
            "RESUME_PREPARE_SYM_BINDER_BYTES": len(
                resume_prepare_sym_binder
            ),
            "RESUME_PREPARE_RESTORE_KEY": key(
                "post_auth_resume_prepare_restore"
            ),
        },
    )
    resume_prepare_age = assemble(
        RESUME_PREPARE_SOURCE,
        build / "post_auth_resume_prepare_age.bin",
        build / "post_auth_resume_prepare_age.lst",
        {
            **prepare_binder_common,
            "RESUME_PREPARE_AGE": 1,
            "RESUME_PREPARE_CLOCK_CALLBACK": CALLBACKS_START,
            "RESUME_PREPARE_BINDER_KEY": key(
                "post_auth_resume_prepare_binder"
            ),
            "RESUME_PREPARE_BINDER_BYTES": len(resume_prepare_binder),
            "RESUME_PREPARE_RESTORE_KEY": key(
                "post_auth_resume_prepare_restore"
            ),
        },
    )
    resume_prepare_crypto = assemble(
        RESUME_PREPARE_SOURCE,
        build / "post_auth_resume_prepare_crypto.bin",
        build / "post_auth_resume_prepare_crypto.lst",
        {
            **prepare_common,
            "RESUME_PREPARE_CRYPTO": 1,
            "RESUME_PREPARE_KEYGEN_KEY": keygen_key,
            "RESUME_PREPARE_KEYGEN_ENTRY": 0x1800,
            "RESUME_PREPARE_HELLO_KEY": key("post_auth_resumed_hello"),
            "RESUME_PREPARE_AGE_KEY": key(
                "post_auth_resume_prepare_age"
            ),
            "RESUME_PREPARE_RESTORE_KEY": key(
                "post_auth_resume_prepare_restore"
            ),
        },
    )
    resume_prepare_commit = assemble(
        RESUME_PREPARE_SOURCE,
        build / "post_auth_resume_prepare_commit.bin",
        build / "post_auth_resume_prepare_commit.lst",
        {
            **prepare_common,
            "RESUME_PREPARE_COMMIT": 1,
            "RESUME_PREPARE_CRYPTO_KEY": key(
                "post_auth_resume_prepare_crypto"
            ),
            "RESUME_PREPARE_CRYPTO_BYTES": len(resume_prepare_crypto),
        },
    )
    resume_prepare_hash = assemble(
        RESUME_PREPARE_SOURCE,
        build / "post_auth_resume_prepare_hash.bin",
        build / "post_auth_resume_prepare_hash.lst",
        {
            **prepare_common,
            "RESUME_PREPARE_HASH": 1,
            "RESUME_PREPARE_SYM_KEY": sym_key,
            "RESUME_PREPARE_SYM_SHA_INIT": sha256_init,
            "RESUME_PREPARE_SYM_SHA_UPDATE": sha256_update,
            "RESUME_PREPARE_SYM_SHA_FINISH": sha256_finish,
            "RESUME_PREPARE_COMMIT_KEY": key(
                "post_auth_resume_prepare_commit"
            ),
            "RESUME_PREPARE_COMMIT_BYTES": len(resume_prepare_commit),
        },
    )
    resume_prepare = assemble(
        RESUME_PREPARE_SOURCE,
        build / "post_auth_resume_prepare.bin",
        build / "post_auth_resume_prepare.lst",
        {
            **prepare_common,
            "RESUME_PREPARE_BROKER": 1,
            "RESUME_PREPARE_HASH_KEY": key(
                "post_auth_resume_prepare_hash"
            ),
            "RESUME_PREPARE_HASH_BYTES": len(resume_prepare_hash),
        },
    )
    if (
        resume_prepare[2:6] != b"RPB1"
        or struct.unpack_from("<4H", resume_prepare, 6)
        != (1, len(resume_prepare), 0x3000, 0x3000)
        or len(resume_prepare) > 2 * SECTOR
    ):
        raise AssertionError("RPB1 PREPARE broker geometry drifted")
    for label, image in (
        ("hash", resume_prepare_hash),
        ("commit", resume_prepare_commit),
        ("crypto", resume_prepare_crypto),
        ("binder", resume_prepare_binder),
        ("symmetric binder", resume_prepare_sym_binder),
        ("early-data seal", resume_prepare_early),
    ):
        if not 0 < len(image) <= 0x110:
            raise AssertionError(
                f"PREPARE {label} continuation reaches K14 mutable work"
            )
    if not 0 < len(resume_prepare_restore) <= SECTOR:
        raise AssertionError("PREPARE restore exceeds its direct-worker sector")
    if not 0 < len(resume_prepare_age) <= SECTOR:
        raise AssertionError("PREPARE late-age worker exceeds one sector")

    exchange_common = {
        "RESUME_EXCHANGE_LOAD_PHASE": 0x10C4,
        "RESUME_EXCHANGE_NE_BUF_READ": ne_buf_read,
        "RESUME_EXCHANGE_NE_BUF_LOAD": ne_buf_load,
        "RESUME_EXCHANGE_NIC_BASE": 0x060E,
        "RESUME_EXCHANGE_NE_TX_START": 0x06CB,
        "RESUME_EXCHANGE_LIFECYCLE_START": RESUME_LIFECYCLE_START,
        "RESUME_EXCHANGE_LIFECYCLE_END": RESUME_LIFECYCLE_END,
        "RESUME_EXCHANGE_PERSIST_FAIL": current_recovery_fail,
    }
    exchange_rx_common = exchange_common
    resume_exchange_restore = assemble(
        RESUME_EXCHANGE_SOURCE,
        build / "post_auth_resume_exchange_restore.bin",
        build / "post_auth_resume_exchange_restore.lst",
        {
            **exchange_common,
            "RESUME_EXCHANGE_RESTORE": 1,
            "RESUME_EXCHANGE_CONTROLLER_HEAD_KEY": phase_key(
                resume_controller_start, 1
            ),
            "RESUME_EXCHANGE_CONTROLLER_TAIL_KEY": phase_key(
                resume_controller_start + 1, 1
            ),
            "RESUME_EXCHANGE_CONTROLLER_LOW_START": RESUME_LOW_START,
            "RESUME_EXCHANGE_CONTROLLER_LOW_BYTES": (
                resume_metadata.low_bytes
            ),
            "RESUME_EXCHANGE_CONTROLLER_PREFIX_START": RESUME_PREFIX_START,
            "RESUME_EXCHANGE_CONTROLLER_PREFIX_BYTES": (
                resume_metadata.prefix_bytes
            ),
            "RESUME_EXCHANGE_CONTROLLER_SUFFIX_START": RESUME_SUFFIX_START,
            "RESUME_EXCHANGE_CONTROLLER_SUFFIX_BYTES": (
                resume_metadata.suffix_bytes
            ),
        },
    )
    resume_exchange_post = assemble(
        RESUME_EXCHANGE_SOURCE,
        build / "post_auth_resume_exchange_post.bin",
        build / "post_auth_resume_exchange_post.lst",
        {
            **exchange_common,
            "RESUME_EXCHANGE_POST": 1,
            "RESUME_EXCHANGE_SYM_RESTORE_KEY": phase_key(sym_start, 10),
            "RESUME_EXCHANGE_SYM_INIT": sym_init,
            "RESUME_EXCHANGE_SYM_EARLY_DERIVED": sym_early_derived,
            "RESUME_EXCHANGE_SYM_SHARED_SECRET": sym_shared_secret,
            "RESUME_EXCHANGE_SYM_IO": SYM_IO,
            "RESUME_EXCHANGE_RESTORE_KEY": key(
                "post_auth_resume_exchange_restore"
            ),
            "RESUME_EXCHANGE_RESTORE_BYTES": len(resume_exchange_restore),
        },
    )
    resume_exchange_crypto = assemble(
        RESUME_EXCHANGE_SOURCE,
        build / "post_auth_resume_exchange_crypto.bin",
        build / "post_auth_resume_exchange_crypto.lst",
        {
            **exchange_common,
            "RESUME_EXCHANGE_CRYPTO": 1,
            "RESUME_EXCHANGE_CANDIDATE_KEY": candidate_key,
            "RESUME_EXCHANGE_CANDIDATE_ENTRY": 0x1800,
            "RESUME_EXCHANGE_POST_KEY": key(
                "post_auth_resume_exchange_post"
            ),
            "RESUME_EXCHANGE_POST_BYTES": len(resume_exchange_post),
        },
    )
    resume_exchange_rx = assemble(
        RESUME_EXCHANGE_SOURCE,
        build / "post_auth_resume_exchange_rx.bin",
        build / "post_auth_resume_exchange_rx.lst",
        {
            **exchange_rx_common,
            "RESUME_EXCHANGE_RX": 1,
            "RESUME_EXCHANGE_HELLO_SERVER_BEGIN": (
                resumed_hello_metadata.entries[5]
            ),
            "RESUME_EXCHANGE_HELLO_SERVER_FEED": (
                resumed_hello_metadata.entries[6]
            ),
            "RESUME_EXCHANGE_HELLO_SERVER_FINISH": (
                resumed_hello_metadata.entries[7]
            ),
            "RESUME_EXCHANGE_TCP_RECEIVE": 0x14ED,
            "RESUME_EXCHANGE_TCP_ACK": 0x13A6,
            "RESUME_EXCHANGE_ZERO_WINDOW": persist_zero_window,
            "RESUME_EXCHANGE_TCP_RX_PTR": 0x0FE2,
            "RESUME_EXCHANGE_TCP_RX_LEN": 0x0FE4,
            "RESUME_EXCHANGE_TCP_REMOTE_ACK": 0x06F1,
            "RESUME_EXCHANGE_CRYPTO_KEY": key(
                "post_auth_resume_exchange_crypto"
            ),
        },
    )
    resume_exchange_tx = assemble(
        RESUME_EXCHANGE_SOURCE,
        build / "post_auth_resume_exchange_tx.bin",
        build / "post_auth_resume_exchange_tx.lst",
        {
            **exchange_common,
            "RESUME_EXCHANGE_TX": 1,
            "RESUME_EXCHANGE_HELLO_BEGIN": resumed_hello_metadata.entries[1],
            "RESUME_EXCHANGE_HELLO_NEXT": resumed_hello_metadata.entries[2],
            "RESUME_EXCHANGE_HELLO_DONE": resumed_hello_metadata.entries[3],
            "RESUME_EXCHANGE_HELLO_REWIND": resumed_hello_metadata.entries[4],
            "RESUME_EXCHANGE_CONNECT_ENTRY": (
                cached_connect_metadata.entries[0]
            ),
            "RESUME_EXCHANGE_TCP_SEND": 0x13BF,
            "RESUME_EXCHANGE_RX_KEY": key(
                "post_auth_resume_exchange_rx"
            ),
        },
    )
    resume_exchange = assemble(
        RESUME_EXCHANGE_SOURCE,
        build / "post_auth_resume_exchange.bin",
        build / "post_auth_resume_exchange.lst",
        {
            **exchange_common,
            "RESUME_EXCHANGE_BROKER": 1,
            "RESUME_EXCHANGE_CONNECT_KEY": key(
                "post_auth_cached_connect"
            ),
            "RESUME_EXCHANGE_HELLO_KEY": key("post_auth_resumed_hello"),
            "RESUME_EXCHANGE_TX_KEY": key(
                "post_auth_resume_exchange_tx"
            ),
            "RESUME_EXCHANGE_TX_BYTES": len(resume_exchange_tx),
        },
    )
    if (
        resume_exchange[2:6] != b"RXB1"
        or struct.unpack_from("<4H", resume_exchange, 6)
        != (1, len(resume_exchange), 0x3000, 0x3000)
        or len(resume_exchange) > 0x400
        or len(resume_exchange_crypto) > 0x400
    ):
        raise AssertionError("RXB1 EXCHANGE direct-worker geometry drifted")
    for label, image in (
        ("tx", resume_exchange_tx),
    ):
        if not 0 < len(image) <= 0x110:
            raise AssertionError(
                f"EXCHANGE {label} continuation reaches K14 mutable work"
            )
    if not 0 < len(resume_exchange_rx) <= 2 * SECTOR:
        raise AssertionError("EXCHANGE RX exceeds its direct two-sector phase")
    if not 0 < len(resume_exchange_post) <= SECTOR:
        raise AssertionError(
            "EXCHANGE post exceeds its 0x2400 staging sector"
        )
    if not 0 < len(resume_exchange_restore) <= 0x110:
        raise AssertionError(
            "EXCHANGE restore reaches symmetric extension work"
        )

    resume_fo_common = {
        "RESUME_FO_LOAD_PHASE": 0x10C4,
        "RESUME_FO_NE_BUF_READ": ne_buf_read,
        "RESUME_FO_NE_BUF_LOAD": ne_buf_load,
        "RESUME_FO_NIC_BASE": 0x060E,
        "RESUME_FO_NE_TX_START": 0x06CB,
    }
    resume_fo = assemble(
        RESUME_FO_SOURCE,
        build / "post_auth_resume_fo.bin",
        build / "post_auth_resume_fo.lst",
        {
            **resume_fo_common,
            "RESUME_FO_BROKER": 1,
            "RESUME_FO_CONTROLLER_KEY": key(
                "post_auth_resume_fo_controller"
            ),
        },
    )
    parse_fixed_origin_worker(
        resume_fo,
        b"RFB1",
        origin=0x3000,
        limit=SECTOR,
    )

    auth_callbacks = assemble(
        CALLBACK_SOURCE,
        build / "post_auth_live_auth_callbacks.bin",
        build / "post_auth_live_auth_callbacks.lst",
        {
            "POST_AUTH_LIVE_AUTH_CALLBACKS": 1,
            "POST_AUTH_LIVE_USER_LOADER_KEY": key("post_auth_user_loader"),
            "POST_AUTH_LIVE_USER_LOADER_DESTINATION": USER_LOADER_START,
            "POST_AUTH_LIVE_USER_LOADER_ENTRY": USER_LOADER_START,
        },
    )
    auth_callbacks_metadata = parse_callback_page(auth_callbacks, 1)
    request_callbacks = assemble(
        CALLBACK_SOURCE,
        build / "post_auth_live_request_callbacks.bin",
        build / "post_auth_live_request_callbacks.lst",
        {
            "POST_AUTH_LIVE_REQUEST_CALLBACKS": 1,
            "POST_AUTH_LIVE_SYM_RESTORE_KEY": phase_key(sym_start, 8),
            "POST_AUTH_LIVE_GATE_AUTHORIZE": gate_authorize,
        },
    )
    request_callbacks_metadata = parse_callback_page(request_callbacks, 2)

    auth_phase = base_phases["auth"]
    auth_key = parse_hex(auth_phase.get("key"), "auth phase key")
    if (
        auth_key
        != phase_key(
            int(auth_phase["start_sector"]),
            int(auth_phase["sectors"]),
        )
        or parse_hex(auth_phase.get("destination"), "auth destination")
        != 0x1800
    ):
        raise AssertionError("base exact-pin auth phase geometry drifted")

    resume_sym_io = assemble(
        RESUME_SYM_IO_SOURCE,
        build / "post_auth_resume_sym_io.bin",
        build / "post_auth_resume_sym_io.lst",
        {
            "RESUME_SYM_IO_ORIGIN": ADAPTER_STAGE,
            "RESUME_SYM_IO_TCP_SEND": 0x13BF,
            "RESUME_SYM_IO_WAIT_TICKS": 0x11E5,
            "RESUME_SYM_IO_DERIVE_CLIENT_APP": app.sym_entries[16],
            "RESUME_SYM_IO_BUILD_HEAD": app.sym_entries[11],
            "RESUME_SYM_IO_ZERO_WINDOW": persist_zero_window,
            "RESUME_SYM_IO_NE_BUF_READ": ne_buf_read,
            "RESUME_SYM_IO_SHA256_UPDATE": sha256_update,
            "RESUME_SYM_IO_TRANSCRIPT_SNAPSHOT": sym_transcript_snapshot,
            "RESUME_SYM_IO_SERVER_OPEN_BEGIN": app.sym_entries[4],
            "RESUME_SYM_IO_OPEN_CHUNK": app.sym_entries[6],
            "RESUME_SYM_IO_OPEN_FINISH": app.sym_entries[7],
            "RESUME_SYM_IO_EARLY_DATA": 1,
        },
    )
    if (
        len(resume_sym_io) > SECTOR
        or resume_sym_io[2:6] != b"RSI1"
    ):
        raise AssertionError("resumed symmetric I/O worker slot/header drifted")

    resume_liveness = assemble(
        RESUME_LIVENESS_SOURCE,
        build / "post_auth_resume_liveness.bin",
        build / "post_auth_resume_liveness.lst",
        {
            "RESUME_LIVENESS_TCP_RECEIVE": 0x14ED,
            "RESUME_LIVENESS_TCP_ACK": 0x13A6,
            "RESUME_LIVENESS_NIC_RECEIVE_SLOT": 0x15E1,
            "RESUME_LIVENESS_RX_SAMPLE_COUNT": 0x06D5,
            "RESUME_LIVENESS_RX_READ_LIMIT": 0x06D7,
            "RESUME_LIVENESS_TCP_PAYLOAD_PTR": 0x0FE2,
            "RESUME_LIVENESS_TCP_PAYLOAD_LEN": 0x0FE4,
            "RESUME_LIVENESS_SYM_OPEN_BEGIN_ENTRY": (
                SYM_SERVER_APP_OPEN_SLOT
            ),
            "RESUME_LIVENESS_SYM_OPEN_CHUNK_ENTRY": SYM_OPEN_CHUNK_SLOT,
            "RESUME_LIVENESS_SYM_OPEN_FINISH_ENTRY": SYM_OPEN_FINISH_SLOT,
            "RESUME_LIVENESS_SYM_PARSE_NST_ENTRY": SYM_PARSE_NST_SLOT,
            "RESUME_LIVENESS_SYM_RECORD_ACTIVE": SYM_RECORD_ACTIVE,
            "RESUME_LIVENESS_SYM_IO": SYM_IO,
            "RESUME_LIVENESS_SYM_RECEIVED_TAG": SYM_RECEIVED_TAG,
            "RESUME_LIVENESS_TICKET_PRESENT": SYM_TICKET_PRESENT,
        },
    )
    if (
        len(resume_liveness) > RESUME_LIVENESS_LIMIT - RESUME_LIVENESS_START
        or len(resume_liveness) > 2 * SECTOR
        or resume_liveness[2:6] != b"RSL1"
    ):
        raise AssertionError("resumed liveness MODE_LOW slot/header drifted")
    (
        liveness_version,
        liveness_bytes,
        liveness_origin,
        liveness_entry,
    ) = struct.unpack_from("<4H", resume_liveness, 6)
    if (
        liveness_version != 1
        or liveness_bytes != len(resume_liveness)
        or liveness_origin != RESUME_LIVENESS_START
        or liveness_entry != RESUME_LIVENESS_START
    ):
        raise AssertionError("resumed liveness header geometry drifted")

    # Populate this fixed table only as each independently gated worker lands.
    # Missing operations are an intentional hard stop: no generic callback,
    # dummy phase, or caller-selected tuple may weaken RSD1 to make a partial
    # composition boot.
    resume_dispatch_operations: dict[int, tuple[int, int, int]] = {
        1: (
            0,  # RSD1 MODE_DIRECT
            key("post_auth_resume_lifecycle"),
            len(resume_lifecycle),
        ),
        2: (
            0,  # RSD1 MODE_DIRECT
            key("post_auth_resume_prepare"),
            len(resume_prepare),
        ),
        3: (
            0,  # RSD1 MODE_DIRECT
            key("post_auth_resume_exchange"),
            len(resume_exchange),
        ),
        4: (
            3,  # RSD1 MODE_TRANSCRIPT
            key("post_auth_resume_sym_io"),
            len(resume_sym_io),
        ),
        5: (
            3,
            key("post_auth_resume_sym_io"),
            len(resume_sym_io),
        ),
        6: (
            3,
            key("post_auth_resume_sym_io"),
            len(resume_sym_io),
        ),
        7: (
            0,
            key("post_auth_resume_fo"),
            len(resume_fo),
        ),
        8: (
            2,  # RSD1 MODE_LOW
            key("post_auth_resume_liveness"),
            len(resume_liveness),
        ),
        9: (
            0,
            key("post_auth_resume_lifecycle"),
            len(resume_lifecycle),
        ),
        10: (
            0,
            key("post_auth_resume_lifecycle"),
            len(resume_lifecycle),
        ),
        11: (
            0,
            key("post_auth_resume_lifecycle"),
            len(resume_lifecycle),
        ),
    }
    missing_resume_operations = [
        operation
        for operation in range(1, 12)
        if operation not in resume_dispatch_operations
    ]
    if missing_resume_operations:
        missing = ", ".join(map(str, missing_resume_operations))
        raise AssertionError(
            "fixed resumption dispatcher still lacks independently gated "
            f"operations: {missing}; operation 8 is wired"
        )

    resume_dispatch_defines: dict[str, int] = {}
    for operation in range(1, 12):
        mode, operation_key, byte_count = resume_dispatch_operations[operation]
        resume_dispatch_defines.update(
            {
                f"RESUME_DISPATCH_OP{operation}_MODE": mode,
                f"RESUME_DISPATCH_OP{operation}_KEY": operation_key,
                f"RESUME_DISPATCH_OP{operation}_BYTES": byte_count,
            }
        )
    resume_dispatcher = assemble(
        RESUME_DISPATCHER_SOURCE,
        build / "post_auth_resume_dispatcher.bin",
        build / "post_auth_resume_dispatcher.lst",
        resume_dispatch_defines,
    )
    resume_dispatcher_metadata = parse_resume_dispatcher(resume_dispatcher)
    if (
        len(resume_dispatcher) > SECTOR
        or resume_dispatcher_metadata.operations
        != tuple(
            resume_dispatch_operations[operation]
            for operation in range(1, 12)
        )
    ):
        raise AssertionError("fixed resumption dispatcher table drifted")

    supervisor_path = build / "post_auth_live_supervisor.bin"
    supervisor_listing = build / "post_auth_live_supervisor.lst"
    supervisor = assemble(
        CONTROLLER_SOURCE,
        supervisor_path,
        supervisor_listing,
        {
            "POST_AUTH_LIVE_SUPERVISOR": 1,
            "POST_AUTH_LIVE_SUPERVISOR_KEY": key("post_auth_supervisor"),
            "POST_AUTH_LIVE_GATE_KEY": key("post_auth_route_gate"),
            "POST_AUTH_LIVE_GATE_COMMIT": gate_commit,
            "POST_AUTH_LIVE_GATE_AUTHORIZE": gate_authorize,
            "POST_AUTH_LIVE_RESUME_CONTROLLER_HEAD_KEY": phase_key(
                phase_geometry["post_auth_resume_controller"][0], 1
            ),
            "POST_AUTH_LIVE_RESUME_CONTROLLER_TAIL_KEY": phase_key(
                phase_geometry["post_auth_resume_controller"][0] + 1, 1
            ),
            "POST_AUTH_LIVE_RESUME_LOW_BYTES": resume_metadata.low_bytes,
            "POST_AUTH_LIVE_RESUME_LOW_START": RESUME_LOW_START,
            "POST_AUTH_LIVE_RESUME_PREFIX_BYTES": resume_metadata.prefix_bytes,
            "POST_AUTH_LIVE_RESUME_PREFIX_START": RESUME_PREFIX_START,
            "POST_AUTH_LIVE_RESUME_SUFFIX_BYTES": resume_metadata.suffix_bytes,
            "POST_AUTH_LIVE_RESUME_SUFFIX_START": RESUME_SUFFIX_START,
            "POST_AUTH_LIVE_RESUME_STAMP": resume_metadata.stamp_entry,
            "POST_AUTH_LIVE_RESUME_ATTEMPT": resume_metadata.attempt_entry,
            "POST_AUTH_LIVE_AFTER_LIVENESS": RESUME_AFTER_LIVENESS,
            "POST_AUTH_LIVE_RESUME_CALLBACKS_KEY": key(
                "post_auth_resume_dispatcher"
            ),
            "POST_AUTH_LIVE_RESUME_CALLBACKS_BYTES": (
                resume_dispatcher_metadata.image_bytes
            ),
            "POST_AUTH_LIVE_AUTH_CALLBACKS_KEY": key(
                "post_auth_auth_callbacks"
            ),
            "POST_AUTH_LIVE_AUTH_CALLBACKS_BYTES": (
                auth_callbacks_metadata.image_bytes
            ),
            "POST_AUTH_LIVE_USER_LOADER_ENTRY": USER_LOADER_START,
            "POST_AUTH_LIVE_REQUEST_CALLBACKS_KEY": key(
                "post_auth_request_callbacks"
            ),
            "POST_AUTH_LIVE_REQUEST_CALLBACKS_BYTES": (
                request_callbacks_metadata.image_bytes
            ),
            "POST_AUTH_LIVE_REQUEST_KEY": key("post_auth_request"),
            "POST_AUTH_LIVE_REQUEST_ADAPTER_KEY": key(
                "post_auth_request_adapter"
            ),
            "POST_AUTH_LIVE_REQUEST_ADAPTER_BYTES": len(app.request_adapter),
            "POST_AUTH_LIVE_REQUEST_ENTRY": app.request_entries[0],
            "POST_AUTH_LIVE_RESPONSE_KEY": key("post_auth_response"),
            "POST_AUTH_LIVE_RESPONSE_LITERALS_KEY": key(
                "post_auth_response_literals"
            ),
            "POST_AUTH_LIVE_RESPONSE_LITERALS_BYTES": len(
                app.response_literals
            ),
            "POST_AUTH_LIVE_RESPONSE_START": app.response_entries[0],
            "POST_AUTH_LIVE_RESPONSE_BEGIN": app.response_entries[1],
            "POST_AUTH_LIVE_RESPONSE_CHUNK": app.response_entries[2],
            "POST_AUTH_LIVE_RESPONSE_FINISH": app.response_entries[3],
            "POST_AUTH_LIVE_RESPONSE_EOF": app.response_entries[4],
            "POST_AUTH_LIVE_RESPONSE_STAGE_ADAPTER": (
                response_stage_adapter
            ),
            "POST_AUTH_LIVE_RESPONSE_ACK_MORE": response_ack_more,
            "POST_AUTH_LIVE_RESPONSE_SUCCESS_TEXT": response_success_text,
            "POST_AUTH_LIVE_PERSIST_EMIT": persist_emit,
            "POST_AUTH_LIVE_PERSIST_FAIL": persist_fail,
        },
    )
    supervisor_response_receive = listing_symbol_address(
        supervisor_listing,
        "post_auth_live_response_receive",
        origin=SUPERVISOR_START,
    )
    response_literals = assemble(
        APP.RESPONSE_LITERALS_SOURCE,
        app.paths["response_literals"],
        app.paths["response_literals_listing"],
        APP.response_literal_defines(
            supervisor_receive=supervisor_response_receive,
            persistent_fail=persist_fail,
        ),
    )
    if len(response_literals) != len(app.response_literals):
        raise AssertionError("final response-literals geometry drifted")
    if (
        listing_symbol_address(
            app.paths["response_literals_listing"],
            "post_auth_live_response_ack_more",
            origin=ADAPTER_RUNTIME,
        )
        != response_ack_more
        or listing_symbol_address(
            app.paths["response_literals_listing"],
            "post_auth_live_response_success_text",
            origin=ADAPTER_RUNTIME,
        )
        != response_success_text
    ):
        raise AssertionError("final response-literals tail addresses drifted")
    supervisor_transition_source = listing_symbol_address(
        supervisor_listing,
        "post_auth_resume_transition_source",
        origin=SUPERVISOR_START,
    )
    supervisor_transition_end = listing_symbol_address(
        supervisor_listing,
        "post_auth_failed",
        origin=SUPERVISOR_START,
    )
    supervisor_transition_bytes = (
        supervisor_transition_end - supervisor_transition_source
    )
    supervisor_transition_declared = listing_mov_immediate(
        supervisor_listing,
        "post_auth_resume_transition_len",
    )
    if not (
        SUPERVISOR_START
        <= supervisor_transition_source
        < supervisor_transition_end
        <= SUPERVISOR_START + len(supervisor)
        and supervisor_transition_bytes == supervisor_transition_declared
        and supervisor_transition_bytes <= 0x100
    ):
        raise AssertionError("post-auth supervisor transition geometry drifted")
    resume_fo_controller = assemble(
        RESUME_FO_SOURCE,
        build / "post_auth_resume_fo_controller.bin",
        build / "post_auth_resume_fo_controller.lst",
        {
            **resume_fo_common,
            "RESUME_FO_CONTROLLER": 1,
            "RESUME_FO_CONTROLLER_LIMIT": 3 * SECTOR,
            "RESUME_FO_KERNEL_KEY": fo_kernel_key,
            "RESUME_FO_SYM_RESTORE_KEY": phase_key(sym_start, 8),
            "RESUME_FO_RECOVERY_KEY": crypto_controller_key,
            "RESUME_FO_RECOVERY_FAIL": base_recovery_fail,
            "RESUME_FO_RSU_HEAD_KEY": phase_key(
                phase_geometry["post_auth_resume_controller"][0], 1
            ),
            "RESUME_FO_RSU_TAIL_KEY": phase_key(
                phase_geometry["post_auth_resume_controller"][0] + 1, 1
            ),
            "RESUME_FO_RSU_LOW_BYTES": resume_metadata.low_bytes,
            "RESUME_FO_RSU_LOW_START": RESUME_LOW_START,
            "RESUME_FO_RSU_PREFIX_BYTES": resume_metadata.prefix_bytes,
            "RESUME_FO_RSU_PREFIX_START": RESUME_PREFIX_START,
            "RESUME_FO_RSU_SUFFIX_BYTES": resume_metadata.suffix_bytes,
            "RESUME_FO_RSU_SUFFIX_START": RESUME_SUFFIX_START,
            "RESUME_FO_SUPERVISOR_KEY": key("post_auth_supervisor"),
            "RESUME_FO_SUPERVISOR_TRANSITION_SOURCE": (
                supervisor_transition_source
            ),
            "RESUME_FO_SUPERVISOR_TRANSITION_BYTES": (
                supervisor_transition_bytes
            ),
        },
    )
    parse_fixed_origin_worker(
        resume_fo_controller,
        b"RFC1",
        origin=0x2400,
        limit=3 * SECTOR,
    )
    if not 2 * SECTOR < len(resume_fo_controller) <= 3 * SECTOR:
        raise AssertionError(
            "deferred-FO controller must occupy exactly three file sectors"
        )
    entry_path = build / "post_auth_live_entry.bin"
    entry_listing = build / "post_auth_live_entry.lst"
    entry = assemble(
        CONTROLLER_SOURCE,
        entry_path,
        entry_listing,
        {
            "POST_AUTH_LIVE_ENTRY": 1,
            "POST_AUTH_LIVE_AUTH_KEY": auth_key,
            "POST_AUTH_LIVE_PUBLICATION_ADAPTER_KEY": key(
                "post_auth_publication_adapter"
            ),
            "POST_AUTH_LIVE_PUBLICATION_ADAPTER_ENTRY": (
                publication_adapter_entry
            ),
            "POST_AUTH_LIVE_SUPERVISOR_KEY": key("post_auth_supervisor"),
            "POST_AUTH_LIVE_PERSIST_FAIL": persist_fail,
        },
    )
    if len(supervisor) > 2 * SECTOR or len(entry) > SECTOR:
        raise AssertionError("post-auth controller slot overflow")

    def assemble_user_loader(
        metadata: ConfigMetadata | None,
        suffix: str,
    ) -> bytes:
        output = build / f"post_auth_user_cfg_loader_{suffix}.bin"
        listing = build / f"post_auth_user_cfg_loader_{suffix}.lst"
        return assemble(
            USER_LOADER_SOURCE,
            output,
            listing,
            {
                "USER_CFG_FULL_AUTHORIZE_ENTRY": gate_authorize,
                "USER_CFG_LOADER_ORIGIN": USER_LOADER_START,
                "USER_CFG_LOADER_LIMIT": USER_LOADER_LIMIT,
                "USER_CFG_ABSOLUTE_LBA": (
                    0 if metadata is None else metadata.absolute_lba
                ),
                "USER_CFG_FILE_SIZE": (
                    1 if metadata is None else metadata.file_size
                ),
                "USER_CFG_CLUSTER_COUNT": (
                    1 if metadata is None else metadata.cluster_count
                ),
                "USER_CFG_SECTORS_PER_TRACK": (
                    8 if metadata is None else metadata.sectors_per_track
                ),
                "USER_CFG_HEAD_COUNT": (
                    1 if metadata is None else metadata.head_count
                ),
                "USER_CFG_DRIVE": BIOS_DRIVE,
            },
        )

    placeholder_loader = assemble_user_loader(None, "layout")

    def compose_core(user_loader_image: bytes) -> tuple[bytes, list[Phase]]:
        phases = [
            Phase(
                "post_auth_publication_adapter",
                *phase_geometry["post_auth_publication_adapter"],
                publication_adapter,
            ),
            Phase(
                "post_auth_supervisor",
                *phase_geometry["post_auth_supervisor"],
                supervisor,
            ),
            Phase(
                "post_auth_route_gate",
                *phase_geometry["post_auth_route_gate"],
                gate,
            ),
            Phase(
                "post_auth_resume_controller",
                *phase_geometry["post_auth_resume_controller"],
                resume_controller,
            ),
            Phase(
                "post_auth_cached_connect",
                *phase_geometry["post_auth_cached_connect"],
                cached_connect,
            ),
            Phase(
                "post_auth_resumed_hello",
                *phase_geometry["post_auth_resumed_hello"],
                resumed_hello,
            ),
            Phase(
                "post_auth_resume_receipt",
                *phase_geometry["post_auth_resume_receipt"],
                resume_receipt,
            ),
            Phase(
                "post_auth_resume_lifecycle",
                *phase_geometry["post_auth_resume_lifecycle"],
                resume_lifecycle,
            ),
            Phase(
                "post_auth_resume_lifecycle_receipt_hash",
                *phase_geometry["post_auth_resume_lifecycle_receipt_hash"],
                resume_lifecycle_receipt_hash,
            ),
            Phase(
                "post_auth_resume_lifecycle_vault_hash",
                *phase_geometry["post_auth_resume_lifecycle_vault_hash"],
                resume_lifecycle_vault_hash,
            ),
            Phase(
                "post_auth_resume_prepare",
                *phase_geometry["post_auth_resume_prepare"],
                resume_prepare,
            ),
            Phase(
                "post_auth_resume_prepare_hash",
                *phase_geometry["post_auth_resume_prepare_hash"],
                resume_prepare_hash,
            ),
            Phase(
                "post_auth_resume_prepare_commit",
                *phase_geometry["post_auth_resume_prepare_commit"],
                resume_prepare_commit,
            ),
            Phase(
                "post_auth_resume_prepare_crypto",
                *phase_geometry["post_auth_resume_prepare_crypto"],
                resume_prepare_crypto,
            ),
            Phase(
                "post_auth_resume_prepare_age",
                *phase_geometry["post_auth_resume_prepare_age"],
                resume_prepare_age,
            ),
            Phase(
                "post_auth_resume_prepare_binder",
                *phase_geometry["post_auth_resume_prepare_binder"],
                resume_prepare_binder,
            ),
            Phase(
                "post_auth_resume_prepare_sym_binder",
                *phase_geometry["post_auth_resume_prepare_sym_binder"],
                resume_prepare_sym_binder,
            ),
            Phase(
                "post_auth_resume_prepare_early",
                *phase_geometry["post_auth_resume_prepare_early"],
                resume_prepare_early,
            ),
            Phase(
                "post_auth_resume_prepare_restore",
                *phase_geometry["post_auth_resume_prepare_restore"],
                resume_prepare_restore,
            ),
            Phase(
                "post_auth_resume_exchange",
                *phase_geometry["post_auth_resume_exchange"],
                resume_exchange,
            ),
            Phase(
                "post_auth_resume_exchange_tx",
                *phase_geometry["post_auth_resume_exchange_tx"],
                resume_exchange_tx,
            ),
            Phase(
                "post_auth_resume_exchange_rx",
                *phase_geometry["post_auth_resume_exchange_rx"],
                resume_exchange_rx,
            ),
            Phase(
                "post_auth_resume_exchange_crypto",
                *phase_geometry["post_auth_resume_exchange_crypto"],
                resume_exchange_crypto,
            ),
            Phase(
                "post_auth_resume_exchange_post",
                *phase_geometry["post_auth_resume_exchange_post"],
                resume_exchange_post,
            ),
            Phase(
                "post_auth_resume_exchange_restore",
                *phase_geometry["post_auth_resume_exchange_restore"],
                resume_exchange_restore,
            ),
            Phase(
                "post_auth_resume_fo",
                *phase_geometry["post_auth_resume_fo"],
                resume_fo,
            ),
            Phase(
                "post_auth_resume_fo_controller",
                *phase_geometry["post_auth_resume_fo_controller"],
                resume_fo_controller,
            ),
            Phase(
                "post_auth_resume_sym_io",
                *phase_geometry["post_auth_resume_sym_io"],
                resume_sym_io,
            ),
            Phase(
                "post_auth_resume_dispatcher",
                *phase_geometry["post_auth_resume_dispatcher"],
                resume_dispatcher,
            ),
            Phase(
                "post_auth_resume_liveness",
                *phase_geometry["post_auth_resume_liveness"],
                resume_liveness,
            ),
            Phase(
                "post_auth_auth_callbacks",
                *phase_geometry["post_auth_auth_callbacks"],
                auth_callbacks,
            ),
            Phase(
                "post_auth_user_loader",
                *phase_geometry["post_auth_user_loader"],
                user_loader_image,
            ),
            Phase(
                "post_auth_request_callbacks",
                *phase_geometry["post_auth_request_callbacks"],
                request_callbacks,
            ),
            Phase(
                "post_auth_request",
                *phase_geometry["post_auth_request"],
                app.request,
            ),
            Phase(
                "post_auth_request_adapter",
                *phase_geometry["post_auth_request_adapter"],
                app.request_adapter,
            ),
            Phase(
                "post_auth_response",
                *phase_geometry["post_auth_response"],
                app.response,
            ),
            Phase(
                "post_auth_response_literals",
                *phase_geometry["post_auth_response_literals"],
                response_literals,
            ),
        ]
        core = bytearray(base_core)
        if base_core[BASIC_TIMER_IRET_CORE_OFFSET] != 0:
            raise AssertionError(
                "secure base resident timer-IRET pad byte is no longer free"
            )
        core[BASIC_TIMER_IRET_CORE_OFFSET] = 0xCF
        post_controller = base_phases["post_controller"]
        post_offset = int(post_controller["start_sector"]) * SECTOR
        post_count = int(post_controller["sectors"])
        core[
            post_offset : post_offset + post_count * SECTOR
        ] = padded(receipt_post_controller, post_count)
        for unchanged_name in (
            "fo_controller",
            "scrub_controller",
            "crypto_controller",
        ):
            unchanged = base_phases[unchanged_name]
            unchanged_start = int(unchanged["start_sector"]) * SECTOR
            unchanged_end = unchanged_start + int(unchanged["sectors"]) * SECTOR
            if (
                core[unchanged_start:unchanged_end]
                != base_core[unchanged_start:unchanged_end]
            ):
                raise AssertionError(
                    f"composed core changed fixed {unchanged_name} phase"
                )
        auth_controller = base_phases["auth_controller"]
        auth_offset = int(auth_controller["start_sector"]) * SECTOR
        core[auth_offset : auth_offset + SECTOR] = padded(entry, 1)
        expected = base_cursor
        for phase in phases:
            if phase.start != expected:
                raise AssertionError("post-auth phase ledger is not contiguous")
            if phase.count != (len(phase.data) + SECTOR - 1) // SECTOR:
                raise AssertionError(
                    f"{phase.name} phase reservation is not exact"
                )
            core.extend(padded(phase.data, phase.count))
            expected += phase.count
        if expected != cursor or len(core) != cursor * SECTOR:
            raise AssertionError("credentialed core sector ledger mismatch")
        struct.pack_into("<H", core, 0x11, cursor)
        struct.pack_into("<H", core, 0x13, 0)
        struct.pack_into("<H", core, 0x15, 0)
        return bytes(core), phases

    provisional_core, _ = compose_core(placeholder_loader)
    provisional_path = build / "SEED.layout.SYS"
    provisional_path.write_bytes(provisional_core)

    with tempfile.TemporaryDirectory(
        prefix="seed-post-auth-layout-", dir=build
    ) as temp_name:
        probe_image = Path(temp_name) / "layout.img"
        build_image(
            probe_image,
            core=provisional_path,
            driver=args.ne_driver,
            user_cfg=user_cfg,
            boot=args.boot,
            loader=args.loader,
        )
        metadata = inspect_config_metadata(probe_image)

    if (
        metadata.file_size != config_size
        or metadata.cluster_count != 1
        or metadata.core_file_size != len(provisional_core)
        or metadata.driver_file_size != SECTOR
        or metadata.cylinder > 1023
        or not 1 <= metadata.sector_number <= 63
    ):
        raise AssertionError("builder-resolved credential file layout is unsafe")

    user_loader = assemble_user_loader(metadata, "final")
    if len(user_loader) > USER_LOADER_LIMIT - USER_LOADER_START:
        raise AssertionError("USER.CFG loader exceeds its retired low slot")
    if len(user_loader) > 2 * SECTOR:
        raise AssertionError("USER.CFG loader exceeds its two-sector phase")
    if len(user_loader) != len(placeholder_loader):
        raise AssertionError("resolved USER.CFG geometry changed loader size")

    core, phases = compose_core(user_loader)
    core_path = build / "SEED.SYS"
    core_path.write_bytes(core)
    provisional_path.unlink()

    # Public request literals are allowed only in the measured adapter. No
    # credential-shaped value is ever compiled into SEED.SYS.
    literal_expectations = {
        APP.REQUEST_PREFIX: 1,
        APP.REQUEST_AFTER_KEY: 1,
        APP.REQUEST_HEADER_END: 1,
        APP.REQUEST_BODY_PREFIX: 1,
        APP.REQUEST_BODY_SUFFIX: 1,
    }
    for literal, expected in literal_expectations.items():
        if app.request_adapter.count(literal) != expected:
            raise AssertionError(f"request literal gate drifted: {literal!r}")
    if b"sk-" in core.lower():
        raise AssertionError("credential-shaped literal leaked into SEED.SYS")
    if core.count(APP.REQUEST_PREFIX) != 1:
        raise AssertionError("credentialed core request allowlist count drifted")

    with tempfile.TemporaryDirectory(
        prefix="seed-post-auth-final-", dir=build
    ) as temp_name:
        temporary_image = Path(temp_name) / "floppy.img"
        build_image(
            temporary_image,
            core=core_path,
            driver=args.ne_driver,
            user_cfg=user_cfg,
            boot=args.boot,
            loader=args.loader,
        )
        final_metadata = inspect_config_metadata(temporary_image)
        if final_metadata != metadata:
            raise AssertionError("final USER.CFG FAT metadata changed after resolution")
        image_path = build / "floppy-160k-live-k15-post-auth.img"
        os.replace(temporary_image, image_path)
    image_path.chmod(0o444)

    (
        basic_loader_path,
        basic_path,
        basic_loader_bytes,
        basic_bytes,
    ) = build_and_bind_basic_sidecar(build, base)

    if sha256_file(base_manifest_path) != base_manifest_hash:
        raise AssertionError("secure base manifest changed during composition")
    base_core_path = Path(str(base_manifest["output"]["core"]))
    if not base_core_path.is_absolute():
        base_core_path = ROOT / base_core_path
    if sha256_file(base_core_path) != base_core_hash:
        raise AssertionError("secure base core changed during composition")

    manifest = {
        "schema": "seed-live-k14-credentialed-post-auth-v2",
        "scope": (
            (
                "explicit credentialed-live"
                if args.credentialed_live
                else "fixed public synthetic zero-credit"
            )
            + " sibling composition over an unchanged "
            "credential-free secure-FO base; build performed no VM launch or "
            "network I/O"
        ),
        "mode": {
            "credentialed_live": args.credentialed_live,
            "synthetic_fixture": args.synthetic_fixture,
            "ordinary_secure_fo_builder_changed": False,
            "requires_explicit_flag": "--credentialed-live",
            "requires_explicit_config": "--user-cfg",
            "requires_automatic_floppy_entropy": args.credentialed_live,
            "automatic_floppy_entropy": args.automatic_floppy_entropy,
            "entropy_values_accepted_by_cli_or_environment": False,
            "security_credit": (
                "functional mechanism only in emulator; physical entropy "
                "credit pending representative hardware characterization"
                if args.credentialed_live
                else "zero; public fixture plumbing only"
            ),
            "bios_drive": BIOS_DRIVE,
            "read_only_media_compatible": True,
        },
        "base": {
            "manifest": str(base_manifest_path),
            "manifest_sha256": base_manifest_hash,
            "core_sha256": base_core_hash,
            "unchanged": True,
            "secure_fo_enabled": True,
            "credential_files_packaged": False,
        },
        "output": {
            "core": str(core_path),
            "core_bytes": len(core),
            "core_sectors": cursor,
            "core_sha256": (
                None if args.credentialed_live else sha256(core)
            ),
            "core_hash_deliberately_omitted": args.credentialed_live,
            "image": str(image_path),
            "image_bytes": image_path.stat().st_size,
            "image_sha256": None,
            "image_hash_deliberately_omitted": True,
            "basic_loader": str(basic_loader_path),
            "basic_loader_bytes": len(basic_loader_bytes),
            "basic_loader_sha256": sha256(basic_loader_bytes),
            "basic_program": str(basic_path),
            "basic_program_bytes": len(basic_bytes),
            "basic_program_sha256": sha256(basic_bytes),
            "basic_sidecar_rebuilt_and_base_compared": True,
            "basic_timer_iret": f"0x{BASIC_TIMER_IRET:04x}",
            "basic_timer_vector": "0000:0070 -> 0000:15ff",
            "basic_timer_boundary_only": True,
        },
        "replaced_phase": {
            "name": "auth_controller",
            "same_start_sector": int(
                base_phases["auth_controller"]["start_sector"]
            ),
            "same_sectors": 1,
            "same_key": base_phases["auth_controller"]["key"],
            "file_load_stage": "0x3200",
            "runtime_destination": "0x3200",
            "entry_bytes": len(entry),
            "entry_sha256": sha256(entry),
            "unchanged_auth_overlay_key": f"0x{auth_key:04x}",
        },
        "replaced_post_controller": {
            "name": "post_controller",
            "same_start_sector": int(
                base_phases["post_controller"]["start_sector"]
            ),
            "same_sectors": int(base_phases["post_controller"]["sectors"]),
            "same_key": base_phases["post_controller"]["key"],
            "file_load_stage": base_phases["post_controller"]["destination"],
            "runtime_destination": base_phases["post_controller"]["destination"],
            "legacy_bytes": len(base_post_controller),
            "legacy_sha256": sha256(base_post_controller),
            "current_source_without_receipt_byte_identical": True,
            "receipt_hooked_bytes": len(receipt_post_controller),
            "receipt_hooked_sha256": sha256(receipt_post_controller),
            "receipt_phase": {
                "key": f"0x{key('post_auth_resume_receipt'):04x}",
                "file_bytes": len(resume_receipt),
                "file_sha256": sha256(resume_receipt),
                "file_load_stage": f"0x{AUTH_CALLBACK_STAGE:04x}",
                "exact_copy_destination": "0x3400",
                "exact_copy_limit": "0x3510",
            },
            "sole_receipt_edge": (
                "authenticated HEAD complete, first retained native NST, "
                "exact TLS-record boundary, and frozen receive window"
            ),
        },
        "unchanged_security_phases": {
            "fo_controller": {
                "key": f"0x{fo_controller_key:04x}",
                "file_load_stage": "0x2400",
                "runtime_destination": "0x2400",
                "bytes": len(base_fo_controller),
                "sha256": sha256(base_fo_controller),
                "composed_core_slice_byte_identical": True,
            },
            "scrub_controller": {
                "key": f"0x{scrub_controller_key:04x}",
                "file_load_stage": "0x2400",
                "runtime_destination": "0x2400",
                "bytes": len(base_scrub_controller),
                "sha256": sha256(base_scrub_controller),
                "scrub_card_pages_entry": f"0x{scrub_card_pages:04x}",
                "card_pages": "0x73..0x7f",
                "composed_core_slice_byte_identical": True,
            },
            "crypto_controller": {
                "key": f"0x{crypto_controller_key:04x}",
                "file_load_stage": "0x3400",
                "runtime_destination": "0x3400",
                "bytes": len(base_crypto_controller),
                "sha256": sha256(base_crypto_controller),
                "persistent_fail": f"0x{base_recovery_fail:04x}",
                "composed_core_slice_byte_identical": True,
            },
        },
        "post_auth_phases": [
            phase_report(
                phase,
                include_hash=not (
                    args.credentialed_live
                    and phase.name == "post_auth_user_loader"
                ),
            )
            for phase in phases
        ],
        "fixed_callbacks": {
            "send": "0x0500 -> resident tcp_send_payload",
            "symmetric_restore": (
                f"0x0510 -> phase key 0x{phase_key(sym_start, 8):04x}, "
                "8 sectors at 0x1800"
            ),
            "user_cfg": (
                "auth page 0x0520 -> fixed two-sector UCL1 at 0x0900"
            ),
            "request_authorize": (
                f"request page 0x0520 -> ROG4 0x{gate_authorize:04x} "
                "plus exact PAK1/gate generation match"
            ),
            "safe_callback_range": "0x0500..0x0600",
            "static_callback_copy_preserves": "0x0600..0x08b6",
            "operation_2_temporal_reuse": (
                "after the attempt bundle is consumed, PREPARE reuses "
                "0x0700..0x075f for digests, 0x0780 for its private phase "
                "transition, and 0x07fe..0x07ff for retry/outcome"
            ),
            "auth_callback_bytes": len(auth_callbacks),
            "request_callback_bytes": len(request_callbacks),
            "user_loader_bytes": len(user_loader),
            "user_loader_slot": (
                f"0x{USER_LOADER_START:04x}..0x{USER_LOADER_LIMIT:04x}"
            ),
            "preloaded_publication": True,
            "full_authorize_entry": f"0x{gate_authorize:04x}",
        },
        "route_commit": {
            "gate_magic": "ROG3",
            "gate_version": 4,
            "gate_bytes": len(gate),
            "commit_entry": f"0x{gate_commit:04x}",
            "authorize_entry": f"0x{gate_authorize:04x}",
            "validate_ticket_only_entry": (
                f"0x{gate_validate_ticket_only:04x}"
            ),
            "initial_route": "TICKET_ONLY",
            "promoted_route": "LIVE_TICKET",
            "promotion_boundary": (
                "fresh PSK-DHE target resumption, credential-free HEAD before "
                "deferred FO, authenticated HEAD-response drain after FO"
            ),
            "direct_lp1_issuer_publication": "0x3600..0x3672 status-last",
            "legacy_we1_bridge_used": False,
        },
        "resumption": {
            "controller_magic": "RSU1",
            "controller_bytes": len(resume_controller),
            "scatter": {
                "low": (
                    f"0x{RESUME_LOW_START:04x}.."
                    f"0x{RESUME_LOW_START + resume_metadata.low_bytes:04x}"
                ),
                "prefix": (
                    f"0x{RESUME_PREFIX_START:04x}.."
                    f"0x{RESUME_PREFIX_START + resume_metadata.prefix_bytes:04x}"
                ),
                "symmetric_mutable_hole": "0x3510..0x355d preserved",
                "suffix": (
                    f"0x{RESUME_SUFFIX_START:04x}.."
                    f"0x{RESUME_SUFFIX_START + resume_metadata.suffix_bytes:04x}"
                ),
                "persistent_services": (
                    f"0x{PERSISTENT_START:04x}..0x{PERSISTENT_END:04x} "
                    "untouched"
                ),
            },
            "stamp_entry": f"0x{resume_metadata.stamp_entry:04x}",
            "attempt_entry": f"0x{resume_metadata.attempt_entry:04x}",
            "fixed_callback": f"0x{resume_metadata.callback:04x}",
            "dispatcher": {
                "magic": "RSD1",
                "phase_key": (
                    f"0x{key('post_auth_resume_dispatcher'):04x}"
                ),
                "file_load_stage": f"0x{CALLBACKS_START:04x}",
                "runtime_destination": f"0x{CALLBACKS_START:04x}",
                "file_bytes": resume_dispatcher_metadata.image_bytes,
                "sha256": sha256(resume_dispatcher),
                "operations": {
                    str(operation): {
                        "mode": (
                            "DIRECT",
                            "SYM",
                            "LOW",
                            "TRANSCRIPT",
                        )[mode],
                        "phase_key": f"0x{operation_key:04x}",
                        "measured_bytes": byte_count,
                        "runtime_destination": (
                            "0x3000"
                            if mode == 0
                            else "0x3400"
                            if mode == 1
                            else "0x0d00"
                            if mode == 3
                            else "0x0900"
                        ),
                        "file_load_stage": (
                            "0x3000"
                            if mode == 0
                            else "0x0d00"
                            if mode in {1, 3}
                            else "0x0900"
                        ),
                    }
                    for operation, (
                        mode,
                        operation_key,
                        byte_count,
                    ) in sorted(resume_dispatch_operations.items())
                },
                "operation_8": {
                    "mode": "MODE_LOW",
                    "phase_key": (
                        f"0x{key('post_auth_resume_liveness'):04x}"
                    ),
                    "measured_bytes": len(resume_liveness),
                    "file_load_stage": f"0x{RESUME_LIVENESS_START:04x}",
                    "runtime_destination": f"0x{RESUME_LIVENESS_START:04x}",
                    "return": f"0x{RESUME_AFTER_LIVENESS:04x}",
                },
            },
            "receipt_vault_lifecycle": {
                "receipt_magic": "NTRW",
                "receipt_phase_key": (
                    f"0x{key('post_auth_resume_receipt'):04x}"
                ),
                "receipt_bytes": len(resume_receipt),
                "lifecycle_magic": "RVLW",
                "lifecycle_phase_key": (
                    f"0x{key('post_auth_resume_lifecycle'):04x}"
                ),
                "lifecycle_bytes": len(resume_lifecycle),
                "dispatcher_operations": [1, 9, 10, 11],
                "receipt_hash_bridge": {
                    "phase_key": (
                        f"0x{key('post_auth_resume_lifecycle_receipt_hash'):04x}"
                    ),
                    "file_load_stage": "0x2400",
                    "exact_copy_destination": "0x3400",
                    "bytes": len(resume_lifecycle_receipt_hash),
                    "sha256": sha256(resume_lifecycle_receipt_hash),
                },
                "vault_hash_bridge": {
                    "phase_key": (
                        f"0x{key('post_auth_resume_lifecycle_vault_hash'):04x}"
                    ),
                    "file_load_stage": "0x2400",
                    "exact_copy_destination": "0x3400",
                    "bytes": len(resume_lifecycle_vault_hash),
                    "sha256": sha256(resume_lifecycle_vault_hash),
                },
                "sha_work_self_overwrite_avoided": True,
                "self_reload_phase_key": (
                    f"0x{key('post_auth_resume_lifecycle'):04x}"
                ),
                "full_symmetric_phase_key": f"0x{sym_key:04x}",
                "fixed_fo_controller_key": f"0x{fo_controller_key:04x}",
                "fixed_scrub_controller_key": (
                    f"0x{scrub_controller_key:04x}"
                ),
                "status_last": True,
                "card_vault": "0x7300..0x7fff",
            },
            "zero_rtt": {
                "sequence": [
                    (
                        "PREPARE requires marker 2, commits the card vault, "
                        "retires the native marker to 0, independently agrees "
                        "the one on-wire binder, derives the early write key, "
                        "and seals HEAD plus EndOfEarlyData"
                    ),
                    (
                        "PREPARE publishes the duplicated early object to "
                        "card page 0x7e with status written last"
                    ),
                    (
                        "EXCHANGE restores inputs and prehashes the exact "
                        "ClientHello while offline, opens TCP only after "
                        "rewind, replays immediately, burns marker 0 to 1, "
                        "and sends the 72-byte early HEAD before waiting for "
                        "any server byte"
                    ),
                    (
                        "the resumed path authenticates exact "
                        "EncryptedExtensions(early_data)+Finished, sends the "
                        "26-byte EndOfEarlyData, then sends the 58-byte client "
                        "Finished"
                    ),
                    (
                        "after application-key completion and zero-window "
                        "hold, deferred FO succeeds and authenticated liveness "
                        "drains the early HEAD response"
                    ),
                    (
                        "operation 9 restores and validates the vault while "
                        "preserving spent marker 1 before status-last route "
                        "promotion"
                    ),
                ],
                "card_page_7e_lifetimes": [
                    "early-data object",
                    "duplicated candidate",
                    "deferred-FO backup",
                    "scrubbed",
                ],
                "early_object_layout": {
                    "early_derived_a": "0x7e00..0x7e1f",
                    "head_a_72_bytes": "0x7e20..0x7e67",
                    "end_of_early_data_26_bytes": "0x7e68..0x7e81",
                    "early_derived_b": "0x7e82..0x7ea1",
                    "head_b_72_bytes": "0x7ea2..0x7ee9",
                    "reserved": "0x7eea..0x7ef5",
                    "magic": "0x7ef6..0x7ef9",
                    "generation": "0x7efa..0x7efb",
                    "inverse_generation": "0x7efc..0x7efd",
                    "inverse_status": "0x7efe",
                    "status_last": "0x7eff",
                },
                "candidate_replacement": (
                    "EXCHANGE first moves EndOfEarlyData to 0x7d40..0x7d59, "
                    "then candidate A/B replace 0x7e00..0x7eff"
                ),
                "ticket_marker": {
                    "address": f"0x{SYM_TICKET_PRESENT:04x}",
                    "states": {
                        "0": "vaulted and temporarily unpublished",
                        "1": "spent; normal-only",
                        "2": "unspent early-capable ticket",
                    },
                    "secure_floor_flow": [2, 0, 1],
                    "burn_boundary": (
                        "write 1 before the first ambiguous 0-RTT TCP send"
                    ),
                    "restore_rule": (
                        "pre-burn cleanup may reconstruct 2; operation 9 and "
                        "liveness preserve spent state 1"
                    ),
                },
            },
            "prepare": {
                "broker_phase_key": (
                    f"0x{key('post_auth_resume_prepare'):04x}"
                ),
                "broker_bytes": len(resume_prepare),
                "file_load_stage": "0x3000",
                "runtime_destination": "0x3000",
                "private_transition": {
                    "digest_live_range": "0x0700..0x075f",
                    "transition_origin": "0x0780",
                    "transition_slot": "0x0780..0x07fd",
                    "retry_outcome": "0x07fe..0x07ff",
                    "installed_after": (
                        "the original 0x0780..0x07ff attempt bundle has been "
                        "consumed and its readback work is complete"
                    ),
                    "generic_file_load_stage": "0x3000",
                    "generic_exact_copy_destination": "0x3400",
                },
                "continuations": {
                    "hash": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_prepare_hash'):04x}"
                        ),
                        "bytes": len(resume_prepare_hash),
                        "file_load_stage": "0x3000",
                        "runtime_destination": "0x3400",
                    },
                    "commit": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_prepare_commit'):04x}"
                        ),
                        "bytes": len(resume_prepare_commit),
                        "file_load_stage": "0x3000",
                        "runtime_destination": "0x3400",
                    },
                    "crypto": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_prepare_crypto'):04x}"
                        ),
                        "bytes": len(resume_prepare_crypto),
                        "file_load_stage": "0x3000",
                        "runtime_destination": "0x3400",
                    },
                    "late_ticket_age": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_prepare_age'):04x}"
                        ),
                        "bytes": len(resume_prepare_age),
                        "file_load_stage": "0x2800",
                        "runtime_destination": "0x2800",
                        "clock_callback": f"0x{CALLBACKS_START:04x}",
                    },
                    "binder": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_prepare_binder'):04x}"
                        ),
                        "bytes": len(resume_prepare_binder),
                        "file_load_stage": "0x3000",
                        "runtime_destination": "0x3400",
                    },
                    "symmetric_binder": {
                        "phase_key": (
                            "0x"
                            f"{key('post_auth_resume_prepare_sym_binder'):04x}"
                        ),
                        "bytes": len(resume_prepare_sym_binder),
                        "file_load_stage": "0x3000",
                        "exact_copy_destination": "0x3400",
                        "runtime_destination": "0x3400",
                    },
                    "early_data_seal": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_prepare_early'):04x}"
                        ),
                        "bytes": len(resume_prepare_early),
                        "file_load_stage": "0x3000",
                        "exact_copy_destination": "0x3400",
                        "runtime_destination": "0x3400",
                    },
                    "restore": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_prepare_restore'):04x}"
                        ),
                        "bytes": len(resume_prepare_restore),
                        "file_load_stage": "0x3000",
                        "runtime_destination": "0x3000",
                        "controller_head_key": (
                            f"0x{phase_key(resume_controller_start, 1):04x}"
                        ),
                        "controller_tail_key": (
                            f"0x{phase_key(resume_controller_start + 1, 1):04x}"
                        ),
                        "restored_scatter": [
                            (
                                f"0x{RESUME_LOW_START:04x}.."
                                f"0x{RESUME_LOW_START + resume_metadata.low_bytes:04x}"
                            ),
                            (
                                f"0x{RESUME_PREFIX_START:04x}.."
                                f"0x{RESUME_PREFIX_START + resume_metadata.prefix_bytes:04x}"
                            ),
                            (
                                f"0x{RESUME_SUFFIX_START:04x}.."
                                f"0x{RESUME_SUFFIX_START + resume_metadata.suffix_bytes:04x}"
                            ),
                        ],
                    },
                },
            },
            "exchange": {
                "broker_phase_key": (
                    f"0x{key('post_auth_resume_exchange'):04x}"
                ),
                "broker_bytes": len(resume_exchange),
                "file_load_stage": "0x3000",
                "runtime_destination": "0x3000",
                "continuations": {
                    "tx": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_exchange_tx'):04x}"
                        ),
                        "bytes": len(resume_exchange_tx),
                        "file_load_stage": "0x3000",
                        "runtime_destination": "0x3400",
                    },
                    "rx": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_exchange_rx'):04x}"
                        ),
                        "bytes": len(resume_exchange_rx),
                        "file_load_stage": "0x2800",
                        "runtime_destination": "0x2800",
                        "borrowed_symmetric_tail": "0x2800..0x2bff",
                        "hello_sha_preserved": "0x30c0..0x33b8",
                    },
                    "crypto": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_exchange_crypto'):04x}"
                        ),
                        "bytes": len(resume_exchange_crypto),
                        "file_load_stage": "0x3000",
                        "runtime_destination": "0x3000",
                    },
                    "post": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_exchange_post'):04x}"
                        ),
                        "bytes": len(resume_exchange_post),
                        "file_load_stage": "0x2400",
                        "runtime_destination": "0x2400",
                        "relocated_suffix_destination": "0x3400",
                        "symmetric_restore_key": (
                            f"0x{phase_key(sym_start, 10):04x}"
                        ),
                        "symmetric_restore_sectors": 10,
                        "symmetric_restore_span": "0x1800..0x2bff",
                    },
                    "restore": {
                        "phase_key": (
                            f"0x{key('post_auth_resume_exchange_restore'):04x}"
                        ),
                        "bytes": len(resume_exchange_restore),
                        "file_load_stage": "0x0700",
                        "runtime_destination": "0x3400",
                        "private_bridge": "0x0e00",
                        "controller_head_key": (
                            f"0x{phase_key(resume_controller_start, 1):04x}"
                        ),
                        "controller_tail_key": (
                            f"0x{phase_key(resume_controller_start + 1, 1):04x}"
                        ),
                        "restored_spans": [
                            (
                                f"0x{RESUME_LOW_START:04x}.."
                                f"0x{RESUME_LOW_START + resume_metadata.low_bytes:04x}"
                            ),
                            (
                                f"0x{RESUME_PREFIX_START:04x}.."
                                f"0x{RESUME_PREFIX_START + resume_metadata.prefix_bytes:04x}"
                            ),
                            (
                                f"0x{RESUME_SUFFIX_START:04x}.."
                                f"0x{RESUME_SUFFIX_START + resume_metadata.suffix_bytes:04x}"
                            ),
                        ],
                    },
                },
            },
            "deferred_fo": {
                "broker_magic": "RFB1",
                "broker_phase_key": (
                    f"0x{key('post_auth_resume_fo'):04x}"
                ),
                "broker_bytes": len(resume_fo),
                "controller_magic": "RFC1",
                "controller_phase_key": (
                    f"0x{key('post_auth_resume_fo_controller'):04x}"
                ),
                "controller_bytes": len(resume_fo_controller),
                "controller_sectors": 3,
                "unchanged_fo_kernel_key": f"0x{fo_kernel_key:04x}",
                "unchanged_recovery_controller_key": (
                    f"0x{crypto_controller_key:04x}"
                ),
                "unchanged_recovery_fail": (
                    f"0x{base_recovery_fail:04x}"
                ),
                "symmetric_restore_key": (
                    f"0x{phase_key(sym_start, 8):04x}"
                ),
                "supervisor_transition_source": (
                    f"0x{supervisor_transition_source:04x}"
                ),
                "supervisor_transition_bytes": supervisor_transition_bytes,
                "candidate_pages": "0x7e00..0x7eff",
                "candidate_copies_verified_before_fo": True,
                "persistent_backup_status_last": True,
                "retired_candidate_page_scrubbed": True,
                "post_fo_failure_is_terminal": True,
            },
            "authenticated_liveness": {
                "magic": "RSL1",
                "phase_key": (
                    f"0x{key('post_auth_resume_liveness'):04x}"
                ),
                "file_load_stage": f"0x{RESUME_LIVENESS_START:04x}",
                "runtime_destination": f"0x{RESUME_LIVENESS_START:04x}",
                "file_bytes": len(resume_liveness),
                "padded_bytes": 2 * SECTOR,
                "sha256": sha256(resume_liveness),
                "server_app_open_slots": [
                    f"0x{SYM_SERVER_APP_OPEN_SLOT:04x}",
                    f"0x{SYM_OPEN_CHUNK_SLOT:04x}",
                    f"0x{SYM_OPEN_FINISH_SLOT:04x}",
                ],
                "nst_parser_slot": f"0x{SYM_PARSE_NST_SLOT:04x}",
                "tcp_receive": "0x14ed",
                "tcp_ack": "0x13a6",
                "nic_receive_slot": "0x15e1",
                "success": (
                    "authenticated complete HTTP/1.1 HEAD header with "
                    "2xx, non-425 4xx, or 5xx status at an exact TLS record "
                    "boundary; authenticated HTTP 425 is early-data rejection"
                ),
                "retained_ticket_replaced": False,
            },
            "credential_surface_reachable_before_promotion": False,
            "hello": {
                "cached_connector": {
                    "phase_key": (
                        f"0x{key('post_auth_cached_connect'):04x}"
                    ),
                    "file_load_stage": (
                        f"0x{CACHED_CONNECT_ORIGIN:04x}"
                    ),
                    "runtime_destination": (
                        f"0x{CACHED_CONNECT_ORIGIN:04x}"
                    ),
                    "file_bytes": len(cached_connect),
                    "padded_bytes": SECTOR,
                    "sha256": sha256(cached_connect),
                    "entry_table": {
                        "file_offset": 10,
                        "connect": (
                            f"0x{cached_connect_metadata.entries[0]:04x}"
                        ),
                        "zero_window_ack": (
                            f"0x{cached_connect_metadata.entries[1]:04x}"
                        ),
                        "window_update": (
                            f"0x{cached_connect_metadata.entries[2]:04x}"
                        ),
                    },
                    "deadline_order": (
                        "load HELLO, fixed inputs, and this borrowed "
                        "ninth-sector phase while offline; prehash the exact "
                        "ClientHello; then open TCP and replay immediately"
                    ),
                },
                "phase_key": f"0x{key('post_auth_resumed_hello'):04x}",
                "file_load_stage": "0x1800",
                "runtime_destination": "0x1800",
                "file_bytes": len(resumed_hello),
                "padded_bytes": 8 * SECTOR,
                "sectors": 8,
                "sha256": sha256(resumed_hello),
                "defines": [
                    "TLS13_POC_K14",
                    "HELLO_RESUMED_ONLY",
                    "HELLO_RESUMED_EARLY_DATA",
                ],
                "entry_table": {
                    "fresh_fail_closed": (
                        f"0x{resumed_hello_metadata.entries[0]:04x}"
                    ),
                    "resumed_begin": (
                        f"0x{resumed_hello_metadata.entries[1]:04x}"
                    ),
                    "next_fragment": (
                        f"0x{resumed_hello_metadata.entries[2]:04x}"
                    ),
                    "fragment_consumed": (
                        f"0x{resumed_hello_metadata.entries[3]:04x}"
                    ),
                    "full_client_digest": (
                        f"0x{resumed_hello_metadata.entries[14]:04x}"
                    ),
                    "relocate_pending": (
                        f"0x{resumed_hello_metadata.entries[12]:04x}"
                    ),
                    "server_begin": (
                        f"0x{resumed_hello_metadata.entries[5]:04x}"
                    ),
                    "server_feed": (
                        f"0x{resumed_hello_metadata.entries[6]:04x}"
                    ),
                    "server_finish": (
                        f"0x{resumed_hello_metadata.entries[7]:04x}"
                    ),
                },
                "required_dispatch_order": (
                    "one-sector cached connector while symmetric binder is "
                    "resident; load eight-sector resumed HELLO; restore "
                    "random/session/ticket/PSK/age/ek; resumed_begin entry 1"
                ),
                "hello_input_restore_sectors": 8,
                "exchange_borrow_repair_sectors": 10,
                "base_fresh_only_phase_replaced": False,
            },
        },
        "application": {
            "request_controller_bytes": len(app.request),
            "request_adapter_bytes": len(app.request_adapter),
            "response_controller_bytes": len(app.response),
            "response_literals_bytes": len(response_literals),
            "adapter_load": (
                "one sector staged at 0x0d00; only measured bytes copied to "
                "0x3400, preserving 0x3510+ K14/persistent state"
            ),
            "success_contract": (
                "authenticated exact output 'ok', response.completed, and "
                "the exact HTTP chunk terminator"
            ),
        },
        "fat_metadata": {
            "files_packaged": [
                "SEED.SYS",
                "SEED/DRIVERS/NE.DRV",
                "SEED/USER.CFG",
            ],
            "user_cfg_packaged": True,
            "user_cfg_is_fixed_public_synthetic_fixture": (
                args.synthetic_fixture
            ),
            "user_cfg_contents_read_by_composer": False,
            "user_cfg_content_hash_recorded": False,
            "user_cfg_path_recorded": False,
            "user_cfg_size_recorded": False,
            "single_cluster": metadata.cluster_count == 1,
            "builder_resolved_absolute_lba": metadata.absolute_lba,
            "builder_resolved_chs": [
                metadata.cylinder,
                metadata.head,
                metadata.sector_number,
            ],
            "geometry": [
                metadata.sectors_per_track,
                metadata.head_count,
            ],
            "image_hash_recorded": False,
        },
        "literal_gate": {
            "request_literals_allowlisted": True,
            "authorization_prefix_occurrences_in_core": core.count(
                APP.REQUEST_PREFIX
            ),
            "credential_shaped_literal_occurrences_in_core": 0,
            "credential_material_in_core": False,
            "credential_material_is_separate_fat_file": args.credentialed_live,
            "synthetic_literal_is_separate_fat_file": args.synthetic_fixture,
            "ordinary_secure_base_remains_credential_free": True,
        },
        "offline_gates": {
            "base_manifest_and_core_unchanged": True,
            "phase_tail_encodable": cursor < 256,
            "request_adapter_exact_copy_preserves_k14_tail": (
                len(app.request_adapter) <= 0x110
            ),
            "response_literals_exact_copy_preserves_k14_tail": (
                len(response_literals) <= 0x110
            ),
            "user_cfg_single_checked_sector": metadata.cluster_count == 1,
            "floppy_mode": "0444",
            "vm_or_network_launched": False,
            "automated_entropy_security_credit": False,
        },
    }
    manifest_path = build / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        (
            "credentialed-live"
            if args.credentialed_live
            else "synthetic zero-credit"
        )
        + " TLS 1.3 post-auth image: PASS"
    )
    print(
        f"  core={len(core)} bytes ({cursor} sectors)"
        + (
            " sha256=OMITTED (credential-dependent)"
            if args.credentialed_live
            else f" sha256={sha256(core)}"
        )
    )
    print(f"  image={image_path} (hash deliberately omitted)")
    print("  packaged files=SEED.SYS + SEED/DRIVERS/NE.DRV + SEED/USER.CFG")
    if args.credentialed_live:
        print("  USER.CFG contents/path/size/hash=NOT LOGGED")
        print("  target automatic read-only floppy timing=ENABLED")
        print("  emulator entropy security credit=ZERO")
    else:
        print("  USER.CFG=fixed public synthetic fixture; security credit=ZERO")
    print(f"  manifest={manifest_path}")
    print("  VM/network launch=NOT PERFORMED")


if __name__ == "__main__":
    main()
