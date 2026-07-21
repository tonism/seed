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
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20


def parse_file_arg(value):
    if ":" not in value:
        raise argparse.ArgumentTypeError("--file expects SOURCE:DEST")
    source, dest = value.split(":", 1)
    parts = [part for part in dest.replace("\\", "/").split("/") if part]
    if not parts:
        raise argparse.ArgumentTypeError("--file destination must not be empty")
    return Path(source), parts


def fat_name(name):
    upper = name.upper()
    if "/" in upper or "\\" in upper:
        raise ValueError(f"FAT root file name must not contain a path: {name}")
    stem, dot, ext = upper.partition(".")
    if not stem or len(stem) > 8 or len(ext) > 3 or (dot and not ext):
        raise ValueError(f"Only 8.3 FAT names are supported: {name}")
    return stem.ljust(8) + ext.ljust(3)


def fat_dir_name(name):
    upper = name.upper()
    if not upper or "." in upper or "/" in upper or "\\" in upper or len(upper) > 8:
        raise ValueError(f"Only plain 8-character FAT directory names are supported: {name}")
    return upper.ljust(8) + "   "


def set_fat12_entry(fat, cluster, value):
    offset = cluster + cluster // 2
    value &= 0x0FFF
    if cluster & 1:
        fat[offset] = (fat[offset] & 0x0F) | ((value << 4) & 0xF0)
        fat[offset + 1] = (value >> 4) & 0xFF
    else:
        fat[offset] = value & 0xFF
        fat[offset + 1] = (fat[offset + 1] & 0xF0) | ((value >> 8) & 0x0F)


def write_dir_entry(directory, index, name, attr, first_cluster, size):
    offset = index * 32
    directory[offset:offset + 11] = name.encode("ascii")
    directory[offset + 11] = attr
    directory[offset + 26:offset + 28] = first_cluster.to_bytes(2, "little")
    directory[offset + 28:offset + 32] = size.to_bytes(4, "little")


class Directory:
    def __init__(self, path, name, parent=None):
        self.path = path
        self.name = name
        self.parent = parent
        self.cluster = 0
        self.entries = []

    def add_entry(self, name, attr, first_cluster, size):
        capacity = ROOT_ENTRIES if self.parent is None else BYTES_PER_SECTOR // 32
        if len(self.entries) >= capacity:
            limit = f"{ROOT_ENTRIES} root entries" if self.parent is None else "one 512-byte cluster"
            raise SystemExit(f"directory {'/'.join(self.path) or '/'} exceeds {limit}")
        self.entries.append((name, attr, first_cluster, size))

    def bytes(self):
        data = bytearray(BYTES_PER_SECTOR)
        if self.parent is not None:
            write_dir_entry(data, 0, ".          ", ATTR_DIRECTORY, self.cluster, 0)
            parent_cluster = self.parent.cluster if self.parent.parent is not None else 0
            write_dir_entry(data, 1, "..         ", ATTR_DIRECTORY, parent_cluster, 0)
            start = 2
        else:
            start = 0
        for index, (name, attr, first_cluster, size) in enumerate(self.entries, start=start):
            if index >= 16:
                raise SystemExit(f"directory {'/'.join(self.path) or '/'} exceeds one 512-byte cluster")
            write_dir_entry(data, index, name, attr, first_cluster, size)
        return data


def set_chain(fat, first_cluster, cluster_count):
    for cluster_offset in range(cluster_count):
        cluster = first_cluster + cluster_offset
        next_value = 0xFFF if cluster_offset == cluster_count - 1 else cluster + 1
        set_fat12_entry(fat, cluster, next_value)


def write_cluster_data(image, data_start, first_cluster, data):
    cluster_count = max(1, math.ceil(len(data) / BYTES_PER_SECTOR))
    for cluster_offset in range(cluster_count):
        cluster = first_cluster + cluster_offset
        start = cluster_offset * BYTES_PER_SECTOR
        end = start + BYTES_PER_SECTOR
        sector = data_start + (cluster - 2) * SECTORS_PER_CLUSTER
        image_offset = sector * BYTES_PER_SECTOR
        image[image_offset:image_offset + BYTES_PER_SECTOR] = data[start:end].ljust(
            BYTES_PER_SECTOR,
            b"\x00",
        )


def build_image(args):
    reserved_sectors = 1 + args.loader_sectors
    fat_start = reserved_sectors
    root_start = fat_start + FAT_COUNT * SECTORS_PER_FAT
    data_start = root_start + ROOT_DIR_SECTORS

    boot = args.boot.read_bytes()
    loader = args.loader.read_bytes()
    if len(boot) != BYTES_PER_SECTOR:
        raise SystemExit(f"boot sector must be 512 bytes, got {len(boot)}")
    if len(loader) > args.loader_sectors * BYTES_PER_SECTOR:
        raise SystemExit("loader is larger than the reserved loader area")
    if boot[-2:] != b"\x55\xaa":
        raise SystemExit("boot sector is missing the 55 aa signature")

    image = bytearray(args.total_sectors * BYTES_PER_SECTOR)
    image[0:BYTES_PER_SECTOR] = boot
    loader_start = BYTES_PER_SECTOR
    image[loader_start:loader_start + len(loader)] = loader

    fat = bytearray(SECTORS_PER_FAT * BYTES_PER_SECTOR)
    fat[0:3] = bytes([args.media, 0xFF, 0xFF])
    root = bytearray(ROOT_DIR_SECTORS * BYTES_PER_SECTOR)

    directories = {(): Directory((), "")}
    root_dir = directories[()]

    def alloc_clusters(count):
        nonlocal next_cluster
        first = next_cluster
        next_cluster += count
        if data_start + (next_cluster - 2) * SECTORS_PER_CLUSTER > args.total_sectors:
            raise SystemExit(
                f"files do not fit in the {args.total_sectors * BYTES_PER_SECTOR // 1024} KiB image"
            )
        return first

    def ensure_dir(path):
        directory = root_dir
        current = []
        for part in path:
            current.append(part)
            key = tuple(current)
            if key in directories:
                directory = directories[key]
                continue
            new_dir = Directory(key, part, directory)
            new_dir.cluster = alloc_clusters(1)
            set_chain(fat, new_dir.cluster, 1)
            directory.add_entry(fat_dir_name(part), ATTR_DIRECTORY, new_dir.cluster, 0)
            directories[key] = new_dir
            directory = new_dir
        return directory

    next_cluster = 2
    for source, dest_parts in args.file:
        data = source.read_bytes()
        cluster_count = max(1, math.ceil(len(data) / BYTES_PER_SECTOR))
        parent = ensure_dir(dest_parts[:-1])
        first_cluster = alloc_clusters(cluster_count)
        set_chain(fat, first_cluster, cluster_count)
        write_cluster_data(image, data_start, first_cluster, data)
        parent.add_entry(fat_name(dest_parts[-1]), ATTR_ARCHIVE, first_cluster, len(data))

    if len(root_dir.entries) > ROOT_ENTRIES:
        raise SystemExit("too many root directory files for this image")
    for index, (name, attr, first_cluster, size) in enumerate(root_dir.entries):
        write_dir_entry(root, index, name, attr, first_cluster, size)

    for path, directory in directories.items():
        if not path:
            continue
        write_cluster_data(image, data_start, directory.cluster, directory.bytes())

    for copy_index in range(FAT_COUNT):
        offset = (fat_start + copy_index * SECTORS_PER_FAT) * BYTES_PER_SECTOR
        image[offset:offset + len(fat)] = fat

    root_offset = root_start * BYTES_PER_SECTOR
    image[root_offset:root_offset + len(root)] = root
    args.output.write_bytes(image)


def list_image(args):
    image = args.image.read_bytes()
    if len(image) == 0 or len(image) % BYTES_PER_SECTOR != 0:
        raise SystemExit(f"image size {len(image)} is not a whole number of sectors")

    reserved = int.from_bytes(image[14:16], "little")
    fat_count = image[16]
    root_entries = int.from_bytes(image[17:19], "little")
    sectors_per_fat = int.from_bytes(image[22:24], "little")
    root_sectors = (root_entries * 32 + BYTES_PER_SECTOR - 1) // BYTES_PER_SECTOR
    root_start = reserved + fat_count * sectors_per_fat
    root_offset = root_start * BYTES_PER_SECTOR
    root = image[root_offset:root_offset + root_sectors * BYTES_PER_SECTOR]

    data_start = root_start + root_sectors

    def cluster_sector(cluster):
        return data_start + (cluster - 2) * SECTORS_PER_CLUSTER

    def print_directory(directory, entry_count, label, prefix="  "):
        print(label)
        subdirs = []
        for index in range(entry_count):
            offset = index * 32
            first = directory[offset]
            if first == 0x00:
                break
            if first == 0xE5:
                continue
            attr = directory[offset + 11]
            if attr & 0x08:
                continue
            raw_name = directory[offset:offset + 11].decode("ascii")
            stem = raw_name[:8].rstrip()
            ext = raw_name[8:].rstrip()
            name = f"{stem}.{ext}" if ext else stem
            cluster = int.from_bytes(directory[offset + 26:offset + 28], "little")
            size = int.from_bytes(directory[offset + 28:offset + 32], "little")
            suffix = "/" if attr & ATTR_DIRECTORY else ""
            print(f"{prefix}{name + suffix:<12} cluster={cluster:<3} size={size}")
            if attr & ATTR_DIRECTORY and name not in (".", ".."):
                subdirs.append((name, cluster))
        for name, cluster in subdirs:
            sector = cluster_sector(cluster)
            start = sector * BYTES_PER_SECTOR
            child = image[start:start + BYTES_PER_SECTOR]
            print_directory(child, BYTES_PER_SECTOR // 32, f"{label.rstrip(':')}/{name}:", prefix)

    print_directory(root, root_entries, "root directory:")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--boot", required=True, type=Path)
    build.add_argument("--loader", required=True, type=Path)
    build.add_argument("--loader-sectors", required=True, type=int)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--file", action="append", type=parse_file_arg, default=[])
    build.add_argument("--total-sectors", type=int, default=TOTAL_SECTORS,
                       help="image size in 512-byte sectors (320 = 160K SS, 720 = 360K DS)")
    build.add_argument("--media", type=lambda v: int(v, 0), default=MEDIA_DESCRIPTOR,
                       help="FAT media-descriptor byte (0xFC = 160K SS, 0xFD = 360K DS)")
    build.set_defaults(func=build_image)

    listing = subparsers.add_parser("list")
    listing.add_argument("image", type=Path)
    listing.set_defaults(func=list_image)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
