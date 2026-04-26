#!/usr/bin/env python3
import argparse
import math
from pathlib import Path


BYTES_PER_SECTOR = 512
TOTAL_SECTORS = 320
SECTORS_PER_CLUSTER = 1
FAT_COUNT = 2
ROOT_ENTRIES = 64
SECTORS_PER_FAT = 1
ROOT_DIR_SECTORS = (ROOT_ENTRIES * 32 + BYTES_PER_SECTOR - 1) // BYTES_PER_SECTOR
MEDIA_DESCRIPTOR = 0xFC
IMAGE_SIZE = TOTAL_SECTORS * BYTES_PER_SECTOR


def parse_file_arg(value):
    if ":" not in value:
        raise argparse.ArgumentTypeError("--file expects SOURCE:DEST")
    source, dest = value.split(":", 1)
    return Path(source), dest


def fat_name(name):
    upper = name.upper()
    if "/" in upper or "\\" in upper:
        raise ValueError(f"FAT root file name must not contain a path: {name}")
    stem, dot, ext = upper.partition(".")
    if not stem or len(stem) > 8 or len(ext) > 3 or (dot and not ext):
        raise ValueError(f"Only 8.3 FAT names are supported: {name}")
    return stem.ljust(8) + ext.ljust(3)


def set_fat12_entry(fat, cluster, value):
    offset = cluster + cluster // 2
    value &= 0x0FFF
    if cluster & 1:
        fat[offset] = (fat[offset] & 0x0F) | ((value << 4) & 0xF0)
        fat[offset + 1] = (value >> 4) & 0xFF
    else:
        fat[offset] = value & 0xFF
        fat[offset + 1] = (fat[offset + 1] & 0xF0) | ((value >> 8) & 0x0F)


def write_root_entry(root, index, name, first_cluster, size):
    offset = index * 32
    root[offset:offset + 11] = fat_name(name).encode("ascii")
    root[offset + 11] = 0x20
    root[offset + 26:offset + 28] = first_cluster.to_bytes(2, "little")
    root[offset + 28:offset + 32] = size.to_bytes(4, "little")


def build_image(args):
    reserved_sectors = 1 + args.stage2_sectors
    fat_start = reserved_sectors
    root_start = fat_start + FAT_COUNT * SECTORS_PER_FAT
    data_start = root_start + ROOT_DIR_SECTORS

    boot = args.boot.read_bytes()
    stage2 = args.stage2.read_bytes()
    if len(boot) != BYTES_PER_SECTOR:
        raise SystemExit(f"boot sector must be 512 bytes, got {len(boot)}")
    if len(stage2) > args.stage2_sectors * BYTES_PER_SECTOR:
        raise SystemExit("stage2 is larger than the reserved stage2 area")
    if boot[-2:] != b"\x55\xaa":
        raise SystemExit("boot sector is missing the 55 aa signature")

    image = bytearray(IMAGE_SIZE)
    image[0:BYTES_PER_SECTOR] = boot
    stage2_start = BYTES_PER_SECTOR
    image[stage2_start:stage2_start + len(stage2)] = stage2

    fat = bytearray(SECTORS_PER_FAT * BYTES_PER_SECTOR)
    fat[0:3] = bytes([MEDIA_DESCRIPTOR, 0xFF, 0xFF])
    root = bytearray(ROOT_DIR_SECTORS * BYTES_PER_SECTOR)

    next_cluster = 2
    for index, (source, dest_name) in enumerate(args.file):
        if index >= ROOT_ENTRIES:
            raise SystemExit("too many root directory files for this image")
        data = source.read_bytes()
        cluster_count = max(1, math.ceil(len(data) / BYTES_PER_SECTOR))
        first_cluster = next_cluster
        for cluster_offset in range(cluster_count):
            cluster = first_cluster + cluster_offset
            next_value = 0xFFF if cluster_offset == cluster_count - 1 else cluster + 1
            set_fat12_entry(fat, cluster, next_value)
            start = cluster_offset * BYTES_PER_SECTOR
            end = start + BYTES_PER_SECTOR
            sector = data_start + (cluster - 2) * SECTORS_PER_CLUSTER
            if sector >= TOTAL_SECTORS:
                raise SystemExit("files do not fit in the 160 KiB image")
            image_offset = sector * BYTES_PER_SECTOR
            image[image_offset:image_offset + BYTES_PER_SECTOR] = data[start:end].ljust(
                BYTES_PER_SECTOR,
                b"\x00",
            )
        write_root_entry(root, index, dest_name, first_cluster, len(data))
        next_cluster += cluster_count

    for copy_index in range(FAT_COUNT):
        offset = (fat_start + copy_index * SECTORS_PER_FAT) * BYTES_PER_SECTOR
        image[offset:offset + len(fat)] = fat

    root_offset = root_start * BYTES_PER_SECTOR
    image[root_offset:root_offset + len(root)] = root
    args.output.write_bytes(image)


def list_image(args):
    image = args.image.read_bytes()
    if len(image) != IMAGE_SIZE:
        raise SystemExit(f"expected a 160 KiB image, got {len(image)} bytes")

    reserved = int.from_bytes(image[14:16], "little")
    fat_count = image[16]
    root_entries = int.from_bytes(image[17:19], "little")
    sectors_per_fat = int.from_bytes(image[22:24], "little")
    root_sectors = (root_entries * 32 + BYTES_PER_SECTOR - 1) // BYTES_PER_SECTOR
    root_start = reserved + fat_count * sectors_per_fat
    root_offset = root_start * BYTES_PER_SECTOR
    root = image[root_offset:root_offset + root_sectors * BYTES_PER_SECTOR]

    print("root directory:")
    for index in range(root_entries):
        offset = index * 32
        first = root[offset]
        if first == 0x00:
            break
        if first == 0xE5:
            continue
        attr = root[offset + 11]
        if attr & 0x08:
            continue
        raw_name = root[offset:offset + 11].decode("ascii")
        stem = raw_name[:8].rstrip()
        ext = raw_name[8:].rstrip()
        name = f"{stem}.{ext}" if ext else stem
        cluster = int.from_bytes(root[offset + 26:offset + 28], "little")
        size = int.from_bytes(root[offset + 28:offset + 32], "little")
        print(f"  {name:<12} cluster={cluster:<3} size={size}")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--boot", required=True, type=Path)
    build.add_argument("--stage2", required=True, type=Path)
    build.add_argument("--stage2-sectors", required=True, type=int)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--file", action="append", type=parse_file_arg, default=[])
    build.set_defaults(func=build_image)

    listing = subparsers.add_parser("list")
    listing.add_argument("image", type=Path)
    listing.set_defaults(func=list_image)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
