#!/usr/bin/env python3
"""Build the conventional-RAM-only 8088 TLS 1.3 product phase pack.

The pack remains a build-time component of the one flat ``SEED.SYS`` file.
It contains no runtime module directory and preserves the fixed 130-sector
K14 boundary consumed by the 286 tail.  Every 8088 private object lives below
the 16 KiB ceiling; display RAM, adapter RAM, mutable configuration, and
writable media are not part of the lifecycle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
POC = ROOT / "tools/crypto-bench/tls13-poc"
BOOT = ROOT / "targets/ibm_pc_5150/boot"
PRODUCT_SOURCE = BOOT / "tls13/k14_product_pack.asm"

SECTOR = 512
CORE_ORIGIN = 0x1000
PACK_START_SECTOR = 45
PACK_SECTORS = 130
CORE_START_LBA = 11
FLOOR_SPT = 8
TICKET_AGE_DESTINATION = 0x2C00


@dataclass
class Image:
    name: str
    data: bytes
    listing: Path


@dataclass
class Slot:
    name: str
    start: int
    sectors: int
    destination: int
    image: Image | None = None

    @property
    def key(self) -> int:
        return (self.sectors << 8) | self.start


def fail(message: str) -> None:
    raise AssertionError(message)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sectors_for(value: bytes) -> int:
    return (len(value) + SECTOR - 1) // SECTOR


def atomic_write(path: Path, value: bytes, *, refresh_if_equal: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.read_bytes() == value:
        if refresh_if_equal:
            path.touch()
        return
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
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


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def assemble(
    work: Path,
    name: str,
    source: Path,
    defines: tuple[str, ...] = (),
) -> Image:
    output = work / f"{name}.bin"
    listing = work / f"{name}.lst"
    command = [
        "nasm",
        "-f",
        "bin",
        *(f"-D{define}" for define in defines),
        f"-I{ROOT}/",
        f"-I{POC}/",
        f"-I{BOOT}/",
        "-l",
        str(listing),
        "-o",
        str(output),
        str(source),
    ]
    run(command)
    return Image(name, output.read_bytes(), listing)


def quoted_define(name: str, path: Path) -> str:
    return f'{name}="{path.as_posix()}"'


def label_offset(listing: Path, label: str) -> int:
    lines = listing.read_text(encoding="utf-8", errors="strict").splitlines()
    marker = re.compile(
        rf"(?<![A-Za-z0-9_.$?]){re.escape(label)}(?::|\s+(?:equ|db|dw|dd|dq|res[wbqd]|times)\b)"
    )
    emitted = re.compile(
        r"^\s*\d+\s+(?:<\d+>\s+)?([0-9A-Fa-f]{8})\s+"
    )
    candidates: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        if marker.search(line) is None:
            continue
        for distance, candidate in enumerate(lines[index : index + 96]):
            match = emitted.search(candidate)
            if match is not None:
                candidates.append((distance, int(match.group(1), 16)))
                break
    if not candidates:
        fail(f"cannot resolve {label!r} in {listing}")
    best = min(distance for distance, _offset in candidates)
    offsets = {offset for distance, offset in candidates if distance == best}
    if len(offsets) != 1:
        fail(f"ambiguous {label!r} in {listing}: {sorted(offsets)}")
    return offsets.pop()


def label_address(listing: Path, label: str, origin: int) -> int:
    return origin + label_offset(listing, label)


def core_phase(core: bytes, phase_id: bytes) -> tuple[int, int, int]:
    table = struct.unpack_from("<H", core, 19)[0]
    count = struct.unpack_from("<H", core, 21)[0]
    matches: list[tuple[int, int, int]] = []
    for index in range(count):
        offset = table + index * 10
        if core[offset : offset + 1] == phase_id:
            matches.append(struct.unpack_from("<HHH", core, offset + 2))
    if len(matches) != 1:
        fail(f"core phase {phase_id!r} resolved {len(matches)} times")
    return matches[0]


def key(sector: int, count: int) -> int:
    if not 0 <= sector <= 0xFF or not 1 <= count <= 0xFF:
        fail(f"phase geometry escaped legacy key: sector={sector}, count={count}")
    return (count << 8) | sector


def build_independent(work: Path) -> dict[str, Image]:
    images: dict[str, Image] = {}

    images["abort"] = assemble(
        work,
        "abort",
        POC / "system_ram_product_abort.asm",
    )
    images["success"] = assemble(
        work, "success", POC / "system_ram_product_success.asm"
    )
    images["resume_ready"] = assemble(
        work, "resume_ready", POC / "system_ram_resume_ready_controller.asm"
    )
    images["ticket_age"] = assemble(
        work,
        "ticket_age",
        POC / "system_ram_ticket_age_controller.asm",
        (f"SYSRAM_TICKET_AGE_ORIGIN=0x{TICKET_AGE_DESTINATION:04x}",),
    )
    images["delta"] = assemble(
        work,
        "delta_0703",
        POC / "delta_loader.asm",
        ("DELTA_LOADER_ORIGIN=0x0703",),
    )

    images["keygen"] = assemble(
        work,
        "keygen_system",
        POC / "keygen_overlay.asm",
        (
            "TLS13_POC_K14=1",
            "MLKEM_KEYGEN_INPUT=0x08b8",
            "MLKEM_KEYGEN_Z_INPUT=0x0dc0",
            "MLKEM_KEYGEN_RUNTIME_ROOT=1",
        ),
    )
    keygen = images["keygen"]
    f1600 = label_address(keygen.listing, "keccak_f1600", 0x1800)
    state = label_address(keygen.listing, "keccak_state", 0x1800)
    work_start = label_address(keygen.listing, "keccak_c", 0x1800)
    work_end = 0x1800 + len(keygen.data)
    images["conditioner"] = assemble(
        work,
        "existing_read_conditioner",
        POC / "existing_read_entropy_controller.asm",
        (
            f"ERE_KEYGEN_KECCAK_F1600=0x{f1600:04x}",
            f"ERE_KEYGEN_KECCAK_STATE=0x{state:04x}",
            f"ERE_KEYGEN_KECCAK_WORK_START=0x{work_start:04x}",
            f"ERE_KEYGEN_KECCAK_WORK_END=0x{work_end:04x}",
        ),
    )

    images["fresh_hello"] = assemble(
        work,
        "fresh_hello_system",
        POC / "hello_overlay.asm",
        (
            "TLS13_POC_K14=1",
            "TLS13_PRODUCT_TLS13=1",
            "HELLO_FRESH_ONLY=1",
            "HELLO_CACHED_CONNECT=1",
            "HELLO_FRESH_TICKET_REQUEST=1",
            "HELLO_SYSTEM_RAM_INPUTS=1",
        ),
    )
    images["resumed_hello"] = assemble(
        work,
        "resumed_hello_system",
        POC / "hello_overlay.asm",
        (
            "TLS13_POC_K14=1",
            "TLS13_PRODUCT_TLS13=1",
            "HELLO_RESUMED_ONLY=1",
            "HELLO_RESUMED_CACHED_CONNECT=1",
            "HELLO_SYSTEM_RAM_RESUME_INPUTS=1",
        ),
    )

    # Keep the provider-window candidate on the original contiguous c ABI.
    # The split accessor is deliberately an offline-only cost: using it in
    # both epochs needlessly burns the 8088 deadline and contradicts the
    # candidate kernel's own lifetime contract.
    images["candidate_live"] = assemble(
        work,
        "candidate_system_live",
        POC / "mlkem_candidate_kernel.asm",
        (
            "TLS13_POC_K14=1",
            "MLKEM_MESSAGE_ADDR=0x3a40",
            "MLKEM_CANDIDATE_G_ADDR=0x3a60",
            "MLKEM_CANDIDATE_Z_ADDR=0x3aa0",
            "MLKEM_INTERNAL_HOLDS=1",
        ),
    )
    images["candidate"] = assemble(
        work,
        "candidate_system",
        POC / "mlkem_candidate_kernel.asm",
        (
            "TLS13_POC_K14=1",
            "MLKEM_MESSAGE_ADDR=0x3a40",
            "MLKEM_CANDIDATE_G_ADDR=0x3a60",
            "MLKEM_CANDIDATE_Z_ADDR=0x3aa0",
            "MLKEM_INTERNAL_HOLDS=1",
            "MLKEM_SCATTERED_C=1",
            "MLKEM_C_SEG0_ADDR=0x3400",
            "MLKEM_C_SEG0_LEN=448",
            "MLKEM_C_SEG1_ADDR=0x0500",
            "MLKEM_C_SEG1_LEN=256",
            "MLKEM_C_SEG2_ADDR=0x0d60",
            "MLKEM_C_SEG2_LEN=96",
            "MLKEM_C_SEG3_ADDR=0x0de0",
            "MLKEM_C_SEG3_LEN=288",
            "MLKEM_STAGE_EK_FOR_FO=1",
        ),
    )
    images["fo"] = assemble(
        work,
        "fo_system",
        POC / "fo_tail_kernel.asm",
        (
            "TLS13_POC_K14=1",
            "FO_MESSAGE_ADDR=0x3a40",
            "FO_CANDIDATE_G_ADDR=0x3a60",
            "FO_Z_ADDR=0x3aa0",
        ),
    )
    images["auth"] = assemble(
        work,
        "auth_system",
        POC / "auth_p256_overlay.asm",
        (
            "AUTH_P256_LIVE_COMPACT_INPUT=1",
            "AUTH_P256_LIVE_202607_PIN=1",
            "AUTH_P256_LIVE_COMPACT_BASE=0x3440",
        ),
    )
    images["acq_sym"] = assemble(
        work,
        "acquisition_sym_system",
        POC / "tls13_sym_overlay.asm",
        (
            "TLS13_POC_K14=1",
            "TLS13_SYM_ACQUISITION_ONLY=1",
            "TLS13_SYM_SYSTEM_RAM=1",
            "TLS13_SHARED_SECRET_LEN=64",
        ),
    )
    images["res_sym"] = assemble(
        work,
        "resumption_sym_system",
        POC / "tls13_sym_overlay.asm",
        (
            "TLS13_POC_K14=1",
            "TLS13_SYM_SYSTEM_RAM_RESUMPTION=1",
            "TLS13_SHARED_SECRET_LEN=64",
        ),
    )
    images["canonical_sym"] = assemble(
        work,
        "canonical_sym",
        POC / "tls13_sym_overlay.asm",
        ("TLS13_POC_K14=1", "TLS13_SHARED_SECRET_LEN=64"),
    )
    images["lifecycle"] = assemble(
        work,
        "product_lifecycle",
        POC / "system_ram_product_lifecycle.asm",
        (quoted_define("SYSRAM_LOW_ABORT_PATH", work / "abort.bin"),),
    )

    if images["conditioner"].data[:4] != b"ERE1" or len(images["conditioner"].data) != SECTOR:
        fail("existing-read conditioner lost its exact one-sector ERE1 ABI")
    if images["canonical_sym"].data[:8] != b"T13SYM02":
        fail("canonical 286 symmetric image lost T13SYM02")
    if images["acq_sym"].data[:8] != b"T13SRA2!":
        fail("acquisition symmetric image lost T13SRA2")
    if images["res_sym"].data[:8] != b"T13SRR2!":
        fail("resumption symmetric image lost T13SRR2")
    return images


def make_layout(images: dict[str, Image]) -> tuple[list[Slot], dict[str, Slot]]:
    slots: list[Slot] = []
    named: dict[str, Slot] = {}
    cursor = PACK_START_SECTOR

    def add(
        name: str,
        destination: int,
        image: Image | None = None,
        fixed: int | None = None,
    ) -> Slot:
        nonlocal cursor
        count = fixed if fixed is not None else sectors_for(image.data if image else b"")
        if count <= 0:
            fail(f"phase {name} has no sectors")
        slot = Slot(name, cursor, count, destination, image)
        slots.append(slot)
        named[name] = slot
        cursor += count
        return slot

    def align(label: str) -> None:
        nonlocal cursor
        count = (-(CORE_START_LBA + cursor)) % FLOOR_SPT
        if count:
            slots.append(Slot(label, cursor, count, 0, None))
            cursor += count

    add("canonical_sym", 0x1800, images["canonical_sym"])
    add("keygen", 0x1800, images["keygen"])
    add("conditioner", 0x0900, images["conditioner"])
    add("fresh_hello", 0x1800, images["fresh_hello"])
    add("resumed_hello", 0x1800, images["resumed_hello"])
    align("candidate_track_pad")
    add("candidate_live", 0x1800, images["candidate_live"])
    align("acquisition_sym_track_pad")
    add("acq_sym", 0x1800, images["acq_sym"])
    align("resumption_sym_track_pad")
    add("res_sym", 0x1800, images["res_sym"])
    # Full FO regenerates ek after dialogue and reads retained c from bounded
    # conventional-RAM slices. It is outside both provider deadline windows,
    # so place its slower accessor after the aligned live phases.
    add("candidate", 0x1800, images["candidate"])
    add("fo", 0x1800, images["fo"])
    add("auth", 0x1800, images["auth"])
    add("lifecycle", 0x0900, images["lifecycle"])

    # Dependent controllers have deliberately fixed, source-enforced slots.
    add("root", 0x3400, fixed=1)
    add("fresh_hello_controller", 0x3400, fixed=1)
    add("resumed_hello_controller", 0x2A00, fixed=1)
    add("acquisition_deadline", 0x3400, fixed=1)
    add("resumption_deadline", 0x3400, fixed=1)
    add("fresh_protected", 0x0900, fixed=3)
    add("resumed_protected", 0x0900, fixed=2)
    add("acquisition_offline", 0x0900, fixed=1)
    add("resumption_offline", 0x0900, fixed=1)
    # The disk-loaded controller stages a sub-page runner at 0500, then is
    # deliberately retired when full FO takes ownership of 0700..0fd0.
    add("acquisition_fo", 0x0900, fixed=1)
    add("resumption_fo", 0x0900, fixed=1)
    add("auth_return", 0x3550, fixed=1)
    add("fresh_post", 0x0900, fixed=3)
    # The final connection authenticates and drains OpenAI's post-Finished
    # NST batch before accepting HTTP.  Keep the validation explicit rather
    # than squeezing it into two sectors; this consumes one reserved pack
    # sector without growing the fixed-size pack or SEED.SYS.
    add("final_post", 0x0900, fixed=3)
    # Consume one formerly reserved pack sector without moving any existing
    # phase key.  Keep this late monotonic-age helper immediately after the
    # resumed HELLO controller: 0900 would overwrite regenerated ek, while
    # 2c00..2dff is disjoint from HELLO, its controller, TX staging, and the
    # ticket identity.
    add("ticket_age", TICKET_AGE_DESTINATION, images["ticket_age"])

    end = PACK_START_SECTOR + PACK_SECTORS
    if cursor > end:
        fail(f"RAM-only product phases need {cursor - PACK_START_SECTOR} sectors, cap is {PACK_SECTORS}")
    if cursor < end:
        slots.append(Slot("reserved_zero", cursor, end - cursor, 0, None))
    return slots, named


def build_dependent(
    work: Path,
    images: dict[str, Image],
    named: dict[str, Slot],
    core: bytes,
    core_listing: Path,
) -> None:
    endpoint_sector, endpoint_count, endpoint_destination = core_phase(core, b"E")
    tcp_sector, tcp_count, tcp_destination = core_phase(core, b"C")
    if endpoint_destination != 0x0700 or tcp_destination != 0x0900:
        fail("ordinary endpoint/TCP phase destinations drifted")
    endpoint_key = key(endpoint_sector, endpoint_count)
    tcp_key = key(tcp_sector, tcp_count)
    tcp_close_offset = label_offset(core_listing, "tcp_close_cached_target")
    tcp_phase_offset = tcp_sector * SECTOR
    if not tcp_phase_offset <= tcp_close_offset < tcp_phase_offset + tcp_count * SECTOR:
        fail("TCP close label escaped the shipped C phase")
    tcp_close = tcp_destination + tcp_close_offset - tcp_phase_offset
    if not tcp_destination <= tcp_close < tcp_destination + tcp_count * SECTOR:
        fail("TCP close runtime mapping escaped the shipped C phase")
    nonce_entry = label_address(images["keygen"].listing, "mlkem_keygen_attempt_nonces", 0x1800)

    def p(name: str) -> Path:
        return work / f"{name}.bin"

    continuations = {
        "root_hello_cont": (
            "SYSRAM_ROOT_HELLO_TRANSITION",
            (f"SYSRAM_FRESH_HELLO_CONTROLLER_KEY=0x{named['fresh_hello_controller'].key:04x}",),
        ),
        "acq_stage1": (
            "SYSRAM_ACQUISITION_STAGE1",
            (
                f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
                f"SYSRAM_KEYGEN_KEY=0x{named['keygen'].key:04x}",
                f"SYSRAM_CANDIDATE_KEY=0x{named['candidate'].key:04x}",
                f"SYSRAM_ACQ_FO_CONTROLLER_KEY=0x{named['acquisition_fo'].key:04x}",
                f"SYSRAM_ACQ_FO_CONTROLLER_DEST=0x{named['acquisition_fo'].destination:04x}",
            ),
        ),
        "res_stage1": (
            "SYSRAM_RESUMPTION_STAGE1",
            (
                f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
                f"SYSRAM_KEYGEN_KEY=0x{named['keygen'].key:04x}",
                f"SYSRAM_CANDIDATE_KEY=0x{named['candidate'].key:04x}",
                f"SYSRAM_RESUME_FO_CONTROLLER_KEY=0x{named['resumption_fo'].key:04x}",
                f"SYSRAM_RESUME_FO_CONTROLLER_DEST=0x{named['resumption_fo'].destination:04x}",
            ),
        ),
        "acq_stage2": (
            "SYSRAM_ACQUISITION_STAGE2",
            (
                f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
                f"SYSRAM_AUTH_RETURN_KEY=0x{named['auth_return'].key:04x}",
                f"SYSRAM_AUTH_KEY=0x{named['auth'].key:04x}",
            ),
        ),
        "res_stage2": (
            "SYSRAM_RESUMPTION_STAGE2",
            (
                f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
                f"SYSRAM_RES_SYM_KEY=0x{named['res_sym'].key:04x}",
                f"SYSRAM_FINAL_POST_KEY=0x{named['final_post'].key:04x}",
            ),
        ),
    }
    for name, (mode, defines) in continuations.items():
        images[name] = assemble(
            work,
            name,
            POC / "system_ram_product_continuations.asm",
            (f"{mode}=1", *defines),
        )

    for name, stage2 in (
        ("acq_fo_runner", "acq_stage2"),
        ("res_fo_runner", "res_stage2"),
    ):
        runner_defines = (
            f"SYSRAM_FO_STAGE2_BYTES={len(images[stage2].data)}",
            f"SYSRAM_LOW_ABORT_BYTES={len(images['abort'].data)}",
        )
        images[name] = assemble(
            work,
            name,
            POC / "system_ram_product_fo_runner.asm",
            runner_defines,
        )

    common = (f"SYSRAM_TCP_CLOSE_CACHED=0x{tcp_close:04x}",)
    images["root"] = assemble(
        work,
        "root",
        POC / "system_ram_product_controllers.asm",
        (
            "SYSRAM_PRODUCT_ROOT=1",
            *common,
            quoted_define("SYSRAM_LOW_ABORT_PATH", p("abort")),
            f"SYSRAM_ENDPOINT_KEY=0x{endpoint_key:04x}",
            f"SYSRAM_TCP_KEY=0x{tcp_key:04x}",
            f"SYSRAM_ACQ_SYM_KEY=0x{named['acq_sym'].key:04x}",
            f"SYSRAM_KEYGEN_KEY=0x{named['keygen'].key:04x}",
            f"SYSRAM_CONDITIONER_KEY=0x{named['conditioner'].key:04x}",
            f"SYSRAM_FRESH_HELLO_KEY=0x{named['fresh_hello'].key:04x}",
            f"SYSRAM_FRESH_HELLO_CONTROLLER_KEY=0x{named['fresh_hello_controller'].key:04x}",
            quoted_define("SYSRAM_ROOT_HELLO_CONTINUATION_PATH", p("root_hello_cont")),
            f"SYSRAM_KEYGEN_NONCE_ENTRY=0x{nonce_entry:04x}",
        ),
    )
    images["acquisition_offline"] = assemble(
        work,
        "acquisition_offline",
        POC / "system_ram_product_controllers.asm",
        (
            "SYSRAM_ACQUISITION_OFFLINE=1",
            *common,
            f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
            f"SYSRAM_KEYGEN_KEY=0x{named['keygen'].key:04x}",
            f"SYSRAM_CANDIDATE_KEY=0x{named['candidate'].key:04x}",
            f"SYSRAM_ACQ_FO_CONTROLLER_KEY=0x{named['acquisition_fo'].key:04x}",
            f"SYSRAM_ACQ_FO_CONTROLLER_DEST=0x{named['acquisition_fo'].destination:04x}",
            quoted_define("SYSRAM_ACQ_STAGE1_PATH", p("acq_stage1")),
        ),
    )
    images["resumption_offline"] = assemble(
        work,
        "resumption_offline",
        POC / "system_ram_product_controllers.asm",
        (
            "SYSRAM_RESUMPTION_OFFLINE=1",
            *common,
            f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
            f"SYSRAM_KEYGEN_KEY=0x{named['keygen'].key:04x}",
            f"SYSRAM_CANDIDATE_KEY=0x{named['candidate'].key:04x}",
            f"SYSRAM_RESUME_FO_CONTROLLER_KEY=0x{named['resumption_fo'].key:04x}",
            f"SYSRAM_RESUME_FO_CONTROLLER_DEST=0x{named['resumption_fo'].destination:04x}",
            quoted_define("SYSRAM_RESUME_STAGE1_PATH", p("res_stage1")),
        ),
    )
    images["acquisition_fo"] = assemble(
        work,
        "acquisition_fo",
        POC / "system_ram_product_controllers.asm",
        (
            "SYSRAM_ACQUISITION_FO=1",
            *common,
            f"SYSRAM_FO_KEY=0x{named['fo'].key:04x}",
            f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
            f"SYSRAM_AUTH_RETURN_KEY=0x{named['auth_return'].key:04x}",
            f"SYSRAM_AUTH_KEY=0x{named['auth'].key:04x}",
            quoted_define("SYSRAM_FO_RUNNER_PATH", p("acq_fo_runner")),
            quoted_define("SYSRAM_LOW_ABORT_PATH", p("abort")),
            quoted_define("SYSRAM_ACQ_STAGE2_PATH", p("acq_stage2")),
        ),
    )
    images["resumption_fo"] = assemble(
        work,
        "resumption_fo",
        POC / "system_ram_product_controllers.asm",
        (
            "SYSRAM_RESUMPTION_FO=1",
            *common,
            f"SYSRAM_FO_KEY=0x{named['fo'].key:04x}",
            f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
            f"SYSRAM_RES_SYM_KEY=0x{named['res_sym'].key:04x}",
            f"SYSRAM_FINAL_POST_KEY=0x{named['final_post'].key:04x}",
            quoted_define("SYSRAM_FO_RUNNER_PATH", p("res_fo_runner")),
            quoted_define("SYSRAM_LOW_ABORT_PATH", p("abort")),
            quoted_define("SYSRAM_RESUME_STAGE2_PATH", p("res_stage2")),
        ),
    )
    images["auth_return"] = assemble(
        work,
        "auth_return",
        POC / "system_ram_product_controllers.asm",
        (
            "SYSRAM_AUTH_RETURN=1",
            *common,
            f"SYSRAM_ACQ_SYM_KEY=0x{named['acq_sym'].key:04x}",
            f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
            f"SYSRAM_FRESH_POST_KEY=0x{named['fresh_post'].key:04x}",
            "SYSRAM_AUTH_CAPSULE_RESTORE="
            f"0x{label_address(images['acq_fo_runner'].listing, 'sysram_auth_capsule_restore', 0x0500):04x}",
        ),
    )

    images["fresh_post"] = assemble(
        work,
        "fresh_post",
        POC / "system_ram_post_controller.asm",
        (
            "SYSRAM_POST_FRESH=1",
            f"SYSRAM_LIFECYCLE_KEY=0x{named['lifecycle'].key:04x}",
            f"SYSRAM_RES_SYM_KEY=0x{named['res_sym'].key:04x}",
            f"SYSRAM_KEYGEN_KEY=0x{named['keygen'].key:04x}",
            f"SYSRAM_KEYGEN_NONCE_ENTRY=0x{nonce_entry:04x}",
            f"SYSRAM_TICKET_AGE_KEY=0x{named['ticket_age'].key:04x}",
            f"SYSRAM_TICKET_AGE_DEST=0x{named['ticket_age'].destination:04x}",
            quoted_define("SYSRAM_RESUME_READY_PATH", p("resume_ready")),
            f"SYSRAM_RESUMED_HELLO_KEY=0x{named['resumed_hello'].key:04x}",
            f"SYSRAM_RESUMED_HELLO_CONTROLLER_KEY=0x{named['resumed_hello_controller'].key:04x}",
            f"SYSRAM_RESUMED_HELLO_CONTROLLER_DEST=0x{named['resumed_hello_controller'].destination:04x}",
            "SYSRAM_RECORD_TICK_ENTRY="
            f"0x{label_address(images['resume_ready'].listing, 'system_ram_record_tick', 0x0F00):04x}",
        ),
    )
    images["final_post"] = assemble(
        work,
        "final_post",
        POC / "system_ram_post_controller.asm",
        (
            "SYSRAM_POST_FINAL=1",
            quoted_define("SYSRAM_SUCCESS_PATH", p("success")),
            "SYSRAM_RES_SYM_CRYPTO_CONSTANTS="
            f"0x{label_address(images['res_sym'].listing, 'chacha_constants', 0x1800):04x}",
        ),
    )

    sym = images["acq_sym"]
    sym_labels = {
        name: label_address(sym.listing, name, 0x1800)
        for name in (
            "sym_transcript_snapshot",
            "sha256_init",
            "sha256_update",
            "sha256_finish",
            "sha256_save_context",
            "sha256_restore_context",
        )
    }
    protected_defines = (
        "LIVE_K15_PROTECTED_CONTROLLER=1",
        "LIVE_K15_PRODUCT_MODE=1",
        "LIVE_K15_SECURE_FO=1",
        "LIVE_K15_IDENTITY_CAPTURE=1",
        "LIVE_K15_SYSTEM_RAM=1",
        "LIVE_K15_PERSIST_FAIL=0x0f60",
        "LIVE_K15_PERSIST_EMIT=0x0f60",
        "LIVE_K15_PERSIST_ZERO_WINDOW=0x0f60",
        "LIVE_K15_PERSIST_TRANSITION=0x0f60",
        f"LIVE_K15_POST_CONTROLLER_KEY=0x{named['acquisition_offline'].key:04x}",
        f"LIVE_K15_SYSTEM_OFFLINE_KEY=0x{named['acquisition_offline'].key:04x}",
        f"LIVE_K15_SYM_TRANSCRIPT_SNAPSHOT=0x{sym_labels['sym_transcript_snapshot']:04x}",
        f"LIVE_K15_SHA256_INIT=0x{sym_labels['sha256_init']:04x}",
        f"LIVE_K15_SHA256_UPDATE=0x{sym_labels['sha256_update']:04x}",
        f"LIVE_K15_SHA256_FINISH=0x{sym_labels['sha256_finish']:04x}",
        f"LIVE_K15_SHA256_SAVE_CONTEXT=0x{sym_labels['sha256_save_context']:04x}",
        f"LIVE_K15_SHA256_RESTORE_CONTEXT=0x{sym_labels['sha256_restore_context']:04x}",
    )
    images["fresh_protected"] = assemble(
        work,
        "fresh_protected",
        POC / "live_k15_controllers.asm",
        protected_defines,
    )
    images["resumed_protected"] = assemble(
        work,
        "resumed_protected",
        POC / "system_ram_resumed_protected_controller.asm",
        (f"SYSRAM_RESUME_OFFLINE_KEY=0x{named['resumption_offline'].key:04x}",),
    )

    for mode, phase, protected in (
        ("ACQUISITION", "acquisition_deadline", "fresh_protected"),
        ("RESUMPTION", "resumption_deadline", "resumed_protected"),
    ):
        terminal_name = f"{phase}_terminal"
        images[terminal_name] = assemble(
            work,
            terminal_name,
            POC / "system_ram_deadline_terminal.asm",
            (
                f"SYSRAM_DEADLINE_{mode}=1",
                quoted_define("SYSRAM_DELTA_LOADER_PATH", p("delta_0703")),
                f"SYSRAM_CORE_START_LBA={CORE_START_LBA}",
                f"SYSRAM_CANDIDATE_KEY=0x{named['candidate_live'].key:04x}",
                (
                    "SYSRAM_SYM_RESTORE_KEY="
                    f"0x{key(named['acq_sym'].start, 11):04x}"
                    if mode == "ACQUISITION"
                    else f"SYSRAM_SYM_RESTORE_KEY=0x{key(named['res_sym'].start, 11):04x}"
                ),
                f"SYSRAM_PROTECTED_KEY=0x{named[protected].key:04x}",
                f"SYSRAM_PROTECTED_BYTES={len(images[protected].data)}",
            ),
        )
        images[phase] = assemble(
            work,
            phase,
            POC / "system_ram_deadline_controller.asm",
            (
                quoted_define("SYSRAM_DEADLINE_TERMINAL_PATH", p(terminal_name)),
            ),
        )

    for mode, name, hello_name, deadline_name, origin, body, extra in (
        (
            "fresh",
            "fresh_hello_controller",
            "fresh_hello",
            "acquisition_deadline",
            0x3400,
            1210,
            (),
        ),
        (
            "resumed",
            "resumed_hello_controller",
            "resumed_hello",
            "resumption_deadline",
            0x2A00,
            1216,
            (
                "LIVE_K15_SYSTEM_RAM_RESUMED=1",
                "LIVE_K15_TICKET_AGE_ENTRY="
                f"0x{named['ticket_age'].destination:04x}",
            ),
        ),
    ):
        images[name] = assemble(
            work,
            name,
            POC / "live_k15_controllers.asm",
            (
                "LIVE_K15_HELLO_CONTROLLER=1",
                "LIVE_K15_PRODUCT_MODE=1",
                "LIVE_K15_SYSTEM_RAM=1",
                *extra,
                f"LIVE_K15_CRYPTO_CONTROLLER_KEY=0x{named[deadline_name].key:04x}",
                "LIVE_K15_PRECONNECT_FAIL=0x0f60",
                f"LIVE_K15_HELLO_CONTROLLER_ORIGIN=0x{origin:04x}",
                f"LIVE_K15_HELLO_TX_STAGE=0x{(0x2700 if mode == 'fresh' else 0x2e00):04x}",
                f"LIVE_K15_HELLO_BODY_LEN={body}",
            ),
        )

    for name, image in images.items():
        if name in named:
            slot = named[name]
            if len(image.data) > slot.sectors * SECTOR:
                fail(
                    f"{name} is {len(image.data)} bytes, exceeds its "
                    f"{slot.sectors}-sector slot"
                )
            slot.image = image


def build_pack(work: Path, slots: list[Slot]) -> bytes:
    include = work / "system_ram_product_phases.inc"
    lines = ["; Generated RAM-only product phases. Do not edit."]
    for slot in slots:
        safe = re.sub(r"[^a-z0-9_]", "_", slot.name.lower())
        lines.append(f"tls13_sysram_{safe}_start:")
        if slot.image is not None:
            lines.append(f'incbin "{(work / (slot.image.name + ".bin")).as_posix()}"')
            padding = slot.sectors * SECTOR - len(slot.image.data)
        else:
            padding = slot.sectors * SECTOR
        if padding:
            lines.append(f"times {padding} db 0")
        lines.append(f"tls13_sysram_{safe}_end:")
    atomic_write(include, ("\n".join(lines) + "\n").encode("ascii"))
    product = assemble(
        work,
        "system_ram_product_pack",
        PRODUCT_SOURCE,
        (quoted_define("TLS13_PRODUCT_GENERATED_INCLUDE", include),),
    ).data
    if len(product) != PACK_SECTORS * SECTOR:
        fail(f"product pack is {len(product)} bytes, expected {PACK_SECTORS * SECTOR}")

    expected = bytearray()
    for slot in slots:
        payload = slot.image.data if slot.image is not None else b""
        expected.extend(payload)
        expected.extend(bytes(slot.sectors * SECTOR - len(payload)))
    if product != bytes(expected):
        fail("product-owned NASM pack differs from the checked phase ledger")
    return product


def generate(
    core_path: Path,
    listing_path: Path,
) -> tuple[bytes, bytes, bytes]:
    core = core_path.read_bytes()
    base_sectors = len(core) // SECTOR
    if (
        core[3:11] != b"SEEDCORE"
        or len(core) % SECTOR
        or base_sectors <= PACK_START_SECTOR
        or struct.unpack_from("<H", core, 17)[0] != base_sectors
    ):
        fail("product pack base is not a complete sector-aligned SEEDCORE image")
    with tempfile.TemporaryDirectory(prefix="seed-system-ram-pack-") as raw:
        work = Path(raw)
        images = build_independent(work)
        slots, named = make_layout(images)
        build_dependent(work, images, named, core, listing_path)
        pack = build_pack(work, slots)

        if pack.count(b"T13SYM02") != 1:
            fail("product pack must contain exactly one canonical T13SYM02 image")
        if any(token in pack for token in (b"K14V", b"K14P", b"K14E")):
            fail("legacy vault/config-escrow phase marker survived the RAM-only pack")

        definitions = {
            "TLS13_K14_PRODUCT_TOTAL_SECTORS": base_sectors + PACK_SECTORS,
            "TLS13_K14_PRODUCT_PACK_SECTORS": PACK_SECTORS,
            "TLS13_K14_PRODUCT_ROOT_PHASE_KEY": named["root"].key,
            "TLS13_K14_PRODUCT_ROOT_DESTINATION": named["root"].destination,
            "TLS13_K14_PRODUCT_ROOT_ENTRY": named["root"].destination,
        }
        abi = [
            "; Generated by build_system_ram_product_pack.py.",
            "; Conventional-RAM-only 8088 TLS 1.3 phase root.",
            *(f"%define {name} 0x{value:04x}" for name, value in definitions.items()),
        ]
        abi_data = ("\n".join(abi) + "\n").encode("ascii")

        phase_report = []
        for slot in slots:
            phase_report.append(
                {
                    "name": slot.name,
                    "start_sector": slot.start,
                    "sectors": slot.sectors,
                    "key": f"0x{slot.key:04x}",
                    "destination": f"0x{slot.destination:04x}",
                    "bytes": len(slot.image.data) if slot.image else 0,
                    "sha256": sha256(slot.image.data) if slot.image else None,
                }
            )
        report = {
            "schema": "seed-tls13-system-ram-product-pack-v1",
            "floor": "4.77 MHz 8088 / 16 KiB",
            "core": {"bytes": len(core), "sha256": sha256(core)},
            "pack": {"bytes": len(pack), "sha256": sha256(pack)},
            "definitions": {name: f"0x{value:04x}" for name, value in definitions.items()},
            "phases": phase_report,
            "security_boundary": {
                "private_state": (
                    "TLS private state below 0x4000; direct-tier 28-byte "
                    "arena shadow in conventional stack guard"
                ),
                "display_ram": False,
                "adapter_ram": False,
                "config_escrow": False,
                "writable_media": False,
                "entropy_only_reads": False,
                "canonical_286_symmetric_images": pack.count(b"T13SYM02"),
            },
        }
        report_data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return pack, abi_data, report_data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product-core", type=Path, required=True)
    parser.add_argument("--product-listing", type=Path, required=True)
    parser.add_argument("--pack-out", type=Path, required=True)
    parser.add_argument("--abi-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path)
    args = parser.parse_args()
    pack, abi, report = generate(
        args.product_core.resolve(), args.product_listing.resolve()
    )
    # ABI first, report second, pack last: the pack remains Make's transaction
    # marker for the complete generated set.
    atomic_write(args.abi_out.resolve(), abi)
    if args.report_out is not None:
        atomic_write(args.report_out.resolve(), report)
    # The pack is Make's transaction marker for the generated ABI/report and
    # the integration gate that follows this builder.  Refresh an identical
    # marker after dependency changes so subsequent builds do not rerun the
    # complete crypto graph indefinitely.
    atomic_write(args.pack_out.resolve(), pack, refresh_if_equal=True)
    print(report.decode("utf-8"), end="")


if __name__ == "__main__":
    main()
