#!/usr/bin/env python3
"""Verify the real 160 KiB TLS 1.3 package allocation and file surface."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


SECTOR_BYTES = 512
EXPECTED_TOTAL_SECTORS = 320
EXPECTED_RESERVED_SECTORS = 5
EXPECTED_FAT_COUNT = 2
EXPECTED_SECTORS_PER_FAT = 1
EXPECTED_ROOT_ENTRIES = 64
EXPECTED_DATA_SECTORS = 309

REQUIRED_PATHS = {
    "SEED.SYS",
    "SEED/",
    "SEED/IDENTITY",
    "SEED/COMPACT",
    "SEED/TOOLS",
}
ALLOWED_PATHS = REQUIRED_PATHS | {
    "SEED/AGENTS.CFG",
    "SEED/USER.CFG",
    "SEED/DRIVERS/",
    "SEED/DRIVERS/NE.DRV",
    "SEED/DRIVERS/WD80X3.DRV",
    "SEED/DRIVERS/3C503.DRV",
    "SEED/DRIVERS/3C501.DRV",
    "SEED/DRIVERS/PCNET.DRV",
    "SEED/DRIVERS/TULIP.DRV",
    "SEED/DRIVERS/RTL8139.DRV",
    "SEED/DRIVERS/EPIC100.DRV",
}


def fail(message: str) -> None:
    raise AssertionError(message)


def u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def fat12_entry(fat: bytes, cluster: int) -> int:
    offset = cluster + cluster // 2
    if offset + 1 >= len(fat):
        fail(f"FAT12 cluster {cluster} escapes the FAT")
    word = fat[offset] | (fat[offset + 1] << 8)
    return (word >> 4) & 0x0FFF if cluster & 1 else word & 0x0FFF


def fat_name(entry: bytes) -> str:
    stem = entry[:8].decode("ascii").rstrip()
    extension = entry[8:11].decode("ascii").rstrip()
    return f"{stem}.{extension}" if extension else stem


def check(image_path: Path, report_path: Path) -> None:
    image = image_path.read_bytes()
    if len(image) != EXPECTED_TOTAL_SECTORS * SECTOR_BYTES:
        fail("TLS 1.3 budget gate requires the exact 160 KiB image")
    if u16(image, 11) != SECTOR_BYTES or image[13] != 1:
        fail("160 KiB image is not 512-byte/one-sector-cluster FAT12")
    reserved = u16(image, 14)
    fat_count = image[16]
    root_entries = u16(image, 17)
    total_sectors = u16(image, 19)
    sectors_per_fat = u16(image, 22)
    if (
        reserved,
        fat_count,
        root_entries,
        total_sectors,
        sectors_per_fat,
    ) != (
        EXPECTED_RESERVED_SECTORS,
        EXPECTED_FAT_COUNT,
        EXPECTED_ROOT_ENTRIES,
        EXPECTED_TOTAL_SECTORS,
        EXPECTED_SECTORS_PER_FAT,
    ):
        fail("160 KiB FAT12 geometry drifted")

    root_sectors = math.ceil(root_entries * 32 / SECTOR_BYTES)
    root_start = reserved + fat_count * sectors_per_fat
    data_start = root_start + root_sectors
    data_sectors = total_sectors - data_start
    if data_sectors != EXPECTED_DATA_SECTORS:
        fail(f"FAT12 data area is {data_sectors}, expected {EXPECTED_DATA_SECTORS}")
    fat_start = reserved * SECTOR_BYTES
    fat = image[fat_start : fat_start + sectors_per_fat * SECTOR_BYTES]
    second_fat_start = (reserved + sectors_per_fat) * SECTOR_BYTES
    second_fat = image[
        second_fat_start : second_fat_start + sectors_per_fat * SECTOR_BYTES
    ]
    if fat != second_fat:
        fail("FAT12 copies differ")

    highest_cluster = data_sectors + 1
    allocated: dict[int, str] = {}
    paths: dict[str, tuple[int, int, tuple[int, ...]]] = {}

    def chain(first: int, owner: str) -> tuple[int, ...]:
        if not 2 <= first <= highest_cluster:
            fail(f"{owner} starts at invalid cluster {first}")
        result: list[int] = []
        seen: set[int] = set()
        cluster = first
        while True:
            if cluster in seen:
                fail(f"{owner} has a cyclic FAT chain")
            if not 2 <= cluster <= highest_cluster:
                fail(f"{owner} reaches invalid cluster {cluster}")
            if cluster in allocated:
                fail(f"{owner} cross-links cluster {cluster} with {allocated[cluster]}")
            seen.add(cluster)
            allocated[cluster] = owner
            result.append(cluster)
            following = fat12_entry(fat, cluster)
            if 0xFF8 <= following <= 0xFFF:
                return tuple(result)
            if following in (0x000, 0xFF7):
                fail(f"{owner} has a truncated/bad FAT chain")
            cluster = following

    def cluster_bytes(cluster: int) -> bytes:
        sector = data_start + cluster - 2
        start = sector * SECTOR_BYTES
        return image[start : start + SECTOR_BYTES]

    def visit(directory: bytes, entries: int, prefix: str) -> None:
        for index in range(entries):
            entry = directory[index * 32 : (index + 1) * 32]
            if not entry or entry[0] == 0x00:
                break
            if entry[0] == 0xE5 or entry[11] & 0x08:
                continue
            name = fat_name(entry)
            if name in (".", ".."):
                continue
            is_directory = bool(entry[11] & 0x10)
            first = u16(entry, 26)
            size = u32(entry, 28)
            path = f"{prefix}{name}{'/' if is_directory else ''}"
            if path in paths:
                fail(f"duplicate FAT path {path}")
            clusters = chain(first, path)
            expected = 1 if is_directory else max(1, math.ceil(size / SECTOR_BYTES))
            if len(clusters) != expected:
                fail(
                    f"{path} has {len(clusters)} clusters, expected {expected} "
                    f"for {size} bytes"
                )
            if any(right != left + 1 for left, right in zip(clusters, clusters[1:])):
                fail(f"{path} is not contiguous")
            paths[path] = (first, size, clusters)
            if is_directory:
                if len(clusters) != 1:
                    fail(f"{path} escaped the one-cluster directory contract")
                visit(cluster_bytes(first), SECTOR_BYTES // 32, path)

    root_offset = root_start * SECTOR_BYTES
    root = image[root_offset : root_offset + root_sectors * SECTOR_BYTES]
    visit(root, root_entries, "")

    actual_paths = set(paths)
    missing = REQUIRED_PATHS - actual_paths
    unexpected = actual_paths - ALLOWED_PATHS
    if missing or unexpected:
        fail(
            f"FAT package surface drifted: missing={sorted(missing)} "
            f"unexpected={sorted(unexpected)}"
        )
    if "SEED/LEAF.DER" in actual_paths:
        fail("obsolete TLS 1.2 SEED/LEAF.DER remains packaged")

    seed_first, seed_bytes, seed_chain = paths["SEED.SYS"]
    if seed_first != 2:
        fail("SEED.SYS is no longer the first FAT data file")
    if seed_bytes % SECTOR_BYTES:
        fail("SEED.SYS is not sector aligned")

    report = json.loads(report_path.read_text())
    if report.get("schema") != "seed-tls13-286-product-tail-v1":
        fail("286 tail report schema drifted")
    seed_sectors = seed_bytes // SECTOR_BYTES
    if seed_sectors != report.get("final_total_sectors"):
        fail("FAT SEED.SYS size disagrees with the 286 tail report")
    if seed_sectors > report.get("universal_max_seed_sectors", 0):
        fail("FAT SEED.SYS exceeds the universal image budget")
    if report.get("fat_data_sectors") != data_sectors:
        fail("tail-report FAT data-sector budget drifted")

    auxiliary_clusters = len(allocated) - len(seed_chain)
    auxiliary_limit = report.get("packaged_auxiliary_sectors")
    if not isinstance(auxiliary_limit, int) or auxiliary_clusters > auxiliary_limit:
        fail(
            f"auxiliary package uses {auxiliary_clusters} clusters, "
            f"budget is {auxiliary_limit}"
        )
    if report.get("final_packaged_sectors") != seed_sectors + auxiliary_limit:
        fail("tail-report packaged-sector total drifted")
    if report.get("universal_packaged_headroom") != (
        data_sectors - seed_sectors - auxiliary_limit
    ):
        fail("tail-report packaged headroom drifted")

    used_clusters = len(allocated)
    free_clusters = data_sectors - used_clusters
    if used_clusters != seed_sectors + auxiliary_clusters or free_clusters < 1:
        fail("real FAT cluster accounting exhausted the 160 KiB image")
    for cluster in range(2, highest_cluster + 1):
        value = fat12_entry(fat, cluster)
        if (cluster in allocated) != (value != 0):
            fail(f"FAT allocation bitmap disagrees at cluster {cluster}")

    print(
        "TLS13 FAT BUDGET PASS "
        f"seed={seed_sectors} aux={auxiliary_clusters}/{auxiliary_limit} "
        f"used={used_clusters}/{data_sectors} free={free_clusters} "
        "leaf_der=absent first_cluster=2"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--tail-report", type=Path, required=True)
    args = parser.parse_args()
    check(args.image, args.tail_report)


if __name__ == "__main__":
    main()
