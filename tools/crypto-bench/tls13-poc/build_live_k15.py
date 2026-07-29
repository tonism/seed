#!/usr/bin/env python3
"""Build the isolated, credential-free live TLS 1.3 deadline harness.

This builder never starts 86Box and never opens a network connection.  It
copies the already-built Build-13 resident nucleus and NE.DRV, removes the
TLS 1.2/API-request overlay, and appends only the logical-K14 TLS 1.3 overlays
and live controller phases needed to measure ServerHello -> client Finished,
then send one exact credential-free HEAD and tentatively capture a session
ticket in RAM.  The live_k15 filename is historical; this is not a 15-sector-K
memory proof or a secure-tier commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEFAULT_BUILD = ROOT / "build/crypto-bench/tls13-live-k15"
PRODUCT_BUILD = ROOT / "build/ibm_pc_5150"
CONTROLLERS = HERE / "live_k15_controllers.asm"
SECTOR = 512
CORE_START_LBA = 11
FLOPPY_SECTORS_PER_TRACK = 8
BASE_SECTORS = 45
LINK_START = 0x0800
LINK_END = 0x2600
RX_BUFFER_START = 0x0700
RX_BUFFER_END = 0x08B6
PROTECTED_CONTROLLER_START = 0x0900
PROTECTED_CONTROLLER_END = 0x0D00
IDENTITY_PROTECTED_CONTROLLER_END = 0x0F00
POST_CONTROLLER_START = PROTECTED_CONTROLLER_START
POST_CONTROLLER_END = PROTECTED_CONTROLLER_END
TRANSCRIPT_HANDOFF_START = 0x0D00
TRANSCRIPT_HANDOFF_END = 0x0DAB
POST_QUARANTINE_START = 0x0D00
POST_QUARANTINE_END = 0x0F00
IDENTITY_POST_QUARANTINE_END = 0x0EE0
POST_SCATTER_MID_START = 0x3600
POST_SCATTER_MID_END = 0x3838
POST_RETAINED_APP_STATE_START = POST_SCATTER_MID_END
POST_RETAINED_APP_STATE_END = 0x3920
POST_SCATTER_HIGH_START = POST_RETAINED_APP_STATE_END
POST_SCATTER_HIGH_END = 0x3B40
POST_RETAINED_TICKET_STATE_START = POST_SCATTER_HIGH_END
POST_RECORD_PLAINTEXT_CAP = (
    POST_QUARANTINE_END
    - POST_QUARANTINE_START
    + POST_SCATTER_MID_END
    - POST_SCATTER_MID_START
    + POST_SCATTER_HIGH_END
    - POST_SCATTER_HIGH_START
)
IDENTITY_POST_RECORD_PLAINTEXT_CAP = (
    IDENTITY_POST_QUARANTINE_END
    - POST_QUARANTINE_START
    + POST_SCATTER_MID_END
    - POST_SCATTER_MID_START
    + POST_SCATTER_HIGH_END
    - POST_SCATTER_HIGH_START
)
DELTA_LOADER_START = 0x0F00
TCP_TAIL_STATE_START = 0x0FE2
HELLO_IMAGE_START = 0x1800
HELLO_TX_STAGE_START = 0x2700
HELLO_TX_STAGE_END = 0x2800
K14_EXTENSION_START = 0x3400
K14_SYM_RUNTIME_START = 0x3510
K14_SYM_RUNTIME_END = 0x355D
K14_EXTENSION_END = 0x3600
PROTECTED_HIGH_STATE_END = 0x3CAC
PRODUCT_CHAT_POOL_START = 0x3E40
PRODUCT_CHAT_POOL_END = 0x3F00
PRE_SYM_TRANSITION_START = 0x0F00
PERSISTENT_SERVICES_START = K14_SYM_RUNTIME_END
PERSISTENT_SERVICES_END = K14_EXTENSION_END
FO_CONTROLLER_START = 0x2400
FO_CONTROLLER_END = 0x2600
FO_KERNEL_START = 0x1800
FO_KERNEL_SECTORS = 6
FO_TICKET_HOLD_START = 0x0700
FO_TICKET_HOLD_END = 0x07EE
FO_EXPECTED_K_START = FO_TICKET_HOLD_END
FO_EXPECTED_K_END = 0x080E
SECURE_CARD_CONTROLLER_ADDR = 0x7300
SECURE_CARD_EK_ADDR = 0x7400
SECURE_CARD_EK_LEN = 1184
SECURE_CARD_C_ADDR = 0x7900
SECURE_CARD_C_LEN = 1088
SECURE_CARD_HANDOFF_A_ADDR = 0x7E00
SECURE_CARD_HANDOFF_B_ADDR = 0x7F00
SECURE_CARD_HANDOFF_LEN = 128
SECURE_NE_PSTOP = 0x73
PRODUCT_NE_PSTOP = 0x80
PACKET_IO_PSTOP_PATCH_OFFSET = 0x4081
NIC_DRIVER_SLOT = 0x1600

FORBIDDEN_LITERALS = (
    b"authorization",
    b"bearer ",
    b"content-type:",
    b"openai-beta",
    b"x-api-key",
    b"api-key",
    b"post ",
    b"get /",
    b"/v1/",
    b'"input"',
    b'"model"',
    b"sk-",
)
CANARY_HEAD_REQUEST = (
    b"HEAD /v1/models HTTP/1.1\r\n"
    b"Host: api.openai.com\r\n"
    b"\r\n"
)

ABI_OFFSETS = {
    "load_core_sectors_at": 0x00C4,
    "wait_ticks": 0x01E5,
    "prepare_internet_path": 0x01F6,
    "ne_transmit_tcp_ack": 0x03A6,
    "tcp_send_payload": 0x03BF,
    "build_tcp_segment_frame": 0x03E2,
    "tcp_add_cx_to_seq": 0x04DA,
    "tcp_receive_payload": 0x04ED,
    "parse_tcp_payload": 0x0522,
    "nic_vt_enter": 0x05DB,
    "nic_vt_restore": 0x05DD,
    "nic_vt_transmit": 0x05DF,
    "nic_vt_receive": 0x05E1,
    "nic_vt_rx_fallback": 0x05E3,
}


@dataclass(frozen=True)
class ProductPhase:
    tag: str
    start: int
    count: int
    destination: int
    flags: int

    @property
    def key(self) -> int:
        return phase_key(self.start, self.count)


@dataclass(frozen=True)
class LivePhase:
    name: str
    start: int
    count: int
    destination: int
    data: bytes

    @property
    def key(self) -> int:
        return phase_key(self.start, self.count)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def phase_key(start: int, count: int) -> int:
    if not 0 <= start <= 0xFF or not 1 <= count <= 0xFF:
        raise AssertionError(f"phase key is not encodable: start={start} count={count}")
    return (count << 8) | start


def run(command: list[str], *, capture: bool = False) -> str:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=capture,
    )
    return completed.stdout if capture else ""


def assemble(
    build: Path,
    source: Path,
    stem: str,
    defines: tuple[str, ...],
) -> tuple[bytes, Path]:
    output = build / f"{stem}.bin"
    listing = build / f"{stem}.lst"
    command = [
        "nasm",
        "-f",
        "bin",
        f"-I{ROOT}/",
        f"-I{HERE}/",
        f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
    ]
    for define in defines:
        command.extend(["-D", define])
    command.extend(["-l", str(listing), "-o", str(output), str(source)])
    run(command)
    return output.read_bytes(), listing


def listing_label_offset(listing: Path, label: str) -> int:
    lines = listing.read_text(encoding="utf-8", errors="replace").splitlines()
    label_pattern = re.compile(
        rf"(?<![A-Za-z0-9_.$?]){re.escape(label)}"
        rf"(?::|\s+(?:db|dw|dd|equ)\b)"
    )
    offset_pattern = re.compile(
        r"^\s*\d+\s+(?:<\d+>\s+)?([0-9A-Fa-f]{8})\s"
    )
    for index, line in enumerate(lines):
        if not label_pattern.search(line):
            continue
        for candidate in lines[index : index + 24]:
            match = offset_pattern.search(candidate)
            if match:
                return int(match.group(1), 16)
        break
    raise AssertionError(f"cannot resolve listing label {label!r} in {listing}")


def listing_source_offset(listing: Path, source_text: str) -> int:
    offset_pattern = re.compile(
        r"^\s*\d+\s+(?:<\d+>\s+)?([0-9A-Fa-f]{8})\s"
    )
    for line in listing.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        if source_text not in line:
            continue
        match = offset_pattern.search(line)
        if match:
            return int(match.group(1), 16)
    raise AssertionError(
        f"cannot resolve listing source {source_text!r} in {listing}"
    )


def parse_product_phases(core: bytes) -> dict[str, ProductPhase]:
    if core[3:11] != b"SEEDCORE":
        raise AssertionError("product SEED.SYS magic mismatch")
    header_len, resident, total, table_off, count = struct.unpack_from(
        "<5H", core, 0x0D
    )
    if header_len != 0x17 or resident != 4:
        raise AssertionError(
            f"unexpected product header: len={header_len:#x} resident={resident}"
        )
    if total != len(core) // SECTOR or len(core) % SECTOR:
        raise AssertionError("product total-sector header does not match its file")
    if table_off + count * 10 > len(core):
        raise AssertionError("product phase table escapes SEED.SYS")
    phases: dict[str, ProductPhase] = {}
    for index in range(count):
        offset = table_off + index * 10
        raw_tag, start, sectors, destination, flags = struct.unpack_from(
            "<2s4H", core, offset
        )
        tag = raw_tag.rstrip(b"\0").decode("ascii")
        phases[tag] = ProductPhase(tag, start, sectors, destination, flags)
    expected = {
        "H": (21, 4),
        "2": (28, 2),
        "Z": (31, 1),
        "I": (32, 1),
        "D": (33, 3),
        "C": (38, 3),
        "E": (44, 1),
    }
    for tag, geometry in expected.items():
        phase = phases.get(tag)
        if phase is None or (phase.start, phase.count) != geometry:
            raise AssertionError(
                f"Build-13 phase {tag!r} geometry drifted: {phase}"
            )
    if phases["E"].start + phases["E"].count != BASE_SECTORS:
        raise AssertionError("base truncation no longer ends after endpoint phase")
    return phases


def verify_product_abi(listing: Path) -> None:
    for label, expected in ABI_OFFSETS.items():
        actual = listing_label_offset(listing, label)
        if actual != expected:
            raise AssertionError(
                f"Build-13 resident ABI drifted: {label}={actual:#x}, "
                f"expected {expected:#x}"
            )


def verify_product_memory_contract(listing: Path) -> None:
    text = listing.read_text(encoding="utf-8", errors="replace")
    match = re.search(
        r"\bB8([0-9A-Fa-f]{4})\b.*\bmov ax, chat_pool_start\b",
        text,
    )
    if match is None:
        raise AssertionError("cannot resolve product chat_pool_start immediate")
    pool_start = int.from_bytes(bytes.fromhex(match.group(1)), "little")
    if pool_start != PRODUCT_CHAT_POOL_START:
        raise AssertionError(
            f"product chat pool moved: {pool_start:#x} != "
            f"{PRODUCT_CHAT_POOL_START:#x}"
        )


def padded(data: bytes, count: int) -> bytes:
    size = count * SECTOR
    if len(data) > size:
        raise AssertionError(f"{len(data)} bytes exceed reserved {size}-byte phase")
    return data.ljust(size, b"\0")


def reserve_layout(
    overlays: dict[str, bytes],
    fixture: bytes,
    *,
    identity: bool,
    secure: bool = False,
) -> dict[str, tuple[int, int, int, bytes]]:
    specs: list[tuple[str, int, int, bytes]] = [
        ("boot_controller", 1, 0x3400, b""),
        ("hello_controller", 1, 0x3400, b""),
        ("crypto_controller", 1, 0x3400, b""),
    ]
    if secure:
        specs.append(("secure_sym_controller", 1, 0x3400, b""))
        # This useful one-sector continuation also preserves the former pad's
        # alignment, keeping the following identity/post controllers within
        # individual 160 KiB floppy tracks.
        specs.append(("secure_preconnect_controller", 1, 0x2400, b""))
    specs.extend(
        [
        (
            "protected_controller",
            (
                (IDENTITY_PROTECTED_CONTROLLER_END - PROTECTED_CONTROLLER_START)
                if identity
                else (PROTECTED_CONTROLLER_END - PROTECTED_CONTROLLER_START)
            )
            // SECTOR,
            PROTECTED_CONTROLLER_START,
            b"",
        ),
        (
            "post_controller",
            (POST_CONTROLLER_END - POST_CONTROLLER_START) // SECTOR,
            POST_CONTROLLER_START,
            b"",
        ),
        ]
    )
    if secure:
        specs.append(
            (
                "fo_controller",
                (FO_CONTROLLER_END - FO_CONTROLLER_START) // SECTOR,
                FO_CONTROLLER_START,
                b"",
            )
        )
        specs.append(("scrub_controller", 1, FO_CONTROLLER_START, b""))
        specs.append(
            ("entropy_controller", 1, 0x0900, overlays["entropy"])
        )
    else:
        specs.append(("public_fixture", 1, 0x0700, fixture))
    specs.extend(
        [
        ("keygen", 6, 0x1800, overlays["keygen"]),
        ("hello", 8, 0x1800, overlays["hello"]),
        ]
    )
    cursor = BASE_SECTORS
    result: dict[str, tuple[int, int, int, bytes]] = {}
    for name, count, destination, data in specs:
        result[name] = (cursor, count, destination, data)
        cursor += count

    # The critical loader never crosses a track in one BIOS request.  Spend
    # otherwise-cheap media sectors to make candidate and the eight-sector
    # symmetric restore each a single call under either controller geometry.
    candidate_pad = (
        -(CORE_START_LBA + cursor)
    ) % FLOPPY_SECTORS_PER_TRACK
    result["candidate_track_pad"] = (cursor, candidate_pad, 0x0000, b"")
    cursor += candidate_pad
    result["candidate"] = (cursor, 5, 0x1800, overlays["candidate"])
    cursor += 5
    sym_pad = (
        -(CORE_START_LBA + cursor)
    ) % FLOPPY_SECTORS_PER_TRACK
    result["sym_track_pad"] = (cursor, sym_pad, 0x0000, b"")
    cursor += sym_pad
    result["sym"] = (cursor, 12, 0x1800, overlays["sym"])
    cursor += 12

    if secure:
        fo_pad = (
            -(CORE_START_LBA + cursor)
        ) % FLOPPY_SECTORS_PER_TRACK
        result["fo_track_pad"] = (cursor, fo_pad, 0x0000, b"")
        cursor += fo_pad
        result["fo"] = (
            cursor,
            FO_KERNEL_SECTORS,
            FO_KERNEL_START,
            overlays["fo"],
        )
        cursor += FO_KERNEL_SECTORS
        result["auth_controller"] = (cursor, 1, 0x3200, b"")
        cursor += 1
        auth_pad = (
            -(CORE_START_LBA + cursor)
        ) % FLOPPY_SECTORS_PER_TRACK
        result["auth_track_pad"] = (cursor, auth_pad, 0x0000, b"")
        cursor += auth_pad
        result["auth"] = (cursor, 13, 0x1800, overlays["auth"])
        cursor += 13
    elif identity:
        result["auth_controller"] = (cursor, 1, 0x3200, b"")
        cursor += 1
        auth_pad = (
            -(CORE_START_LBA + cursor)
        ) % FLOPPY_SECTORS_PER_TRACK
        result["auth_track_pad"] = (cursor, auth_pad, 0x0000, b"")
        cursor += auth_pad
        result["auth"] = (cursor, 13, 0x1800, overlays["auth"])
        cursor += 13

    if cursor >= 256:
        raise AssertionError("live phase tail exceeds 8-bit resident loader offset")
    return result


def make_live_phase(
    layout: dict[str, tuple[int, int, int, bytes]],
    name: str,
    data: bytes | None = None,
) -> LivePhase:
    start, count, destination, reserved_data = layout[name]
    return LivePhase(
        name,
        start,
        count,
        destination,
        reserved_data if data is None else data,
    )


def patch_exact(image: bytearray, offset: int, before: bytes, after: bytes) -> None:
    if len(before) != len(after):
        raise AssertionError("patch must preserve resident size")
    actual = bytes(image[offset : offset + len(before)])
    if actual != before:
        raise AssertionError(
            f"product patch preimage drifted at {offset:#x}: "
            f"{actual.hex()} != {before.hex()}"
        )
    image[offset : offset + len(after)] = after


def scan_no_request_or_credentials(
    name: str,
    value: bytes,
    *,
    allow_exact_head: bool = False,
) -> None:
    lowered = value.lower()
    if allow_exact_head:
        exact = CANARY_HEAD_REQUEST.lower()
        if lowered.count(exact) != 1:
            raise AssertionError(
                f"{name} must contain exactly one compiled canary HEAD"
            )
        at = lowered.index(exact)
        lowered = lowered[:at] + bytes(len(exact)) + lowered[at + len(exact) :]
    found = [token for token in FORBIDDEN_LITERALS if token in lowered]
    if found:
        rendered = ", ".join(repr(token) for token in found)
        raise AssertionError(f"{name} contains forbidden request/credential literals: {rendered}")


def build_basic_sidecar(build: Path) -> tuple[Path, Path]:
    loader = build / "live-k15-basic-loader.bin"
    basic = build / "LIVEK15.BAS"
    run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT / 'targets/ibm_pc_5150/boot'}/",
            "-DBASIC_BOOTSTRAP_ADDR=0x3a00",
            f"-DSEED_CORE_START_LBA={CORE_START_LBA}",
            "-DSEED_CORE_SECTORS=4",
            "-DSEED_RAM_TOP=0x4000",
            "-DSEED_BOOT_DRIVE=1",
            "-o",
            str(loader),
            str(ROOT / "targets/ibm_pc_5150/basic/bootstrap.asm"),
        ]
    )
    run(
        [
            "python3",
            str(ROOT / "tools/build-basic-bootstrap.py"),
            "--input",
            str(loader),
            "--output",
            str(basic),
            "--load-addr",
            "0x3a00",
            "--clear-top",
            "14847",
            "--max-addr",
            "0x4000",
        ]
    )
    return loader, basic


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build only the offline logical-K14 artifacts for the 16 KiB live "
            "TLS 1.3 ServerHello-to-Finished timing PoC; never launches 86Box"
        )
    )
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument(
        "--product-core",
        type=Path,
        default=PRODUCT_BUILD / "SEED.SYS",
    )
    parser.add_argument(
        "--product-listing",
        type=Path,
        default=PRODUCT_BUILD / "SEED.SYS.lst",
    )
    parser.add_argument(
        "--ne-driver",
        type=Path,
        default=PRODUCT_BUILD / "drivers/NE.DRV",
    )
    parser.add_argument(
        "--identity",
        action="store_true",
        help=(
            "capture the authenticated live CertificateVerify transcript and "
            "run the dated exact-leaf P-256 checkpoint after HEAD/ticket"
        ),
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        help=(
            "run live card-RAM ML-KEM FO validation before the exact-leaf "
            "identity checkpoint; implies --identity"
        ),
    )
    args = parser.parse_args()
    if args.secure:
        args.identity = True
    build = args.build_dir if args.build_dir.is_absolute() else ROOT / args.build_dir
    build.mkdir(parents=True, exist_ok=True)

    entropy_meta_path = (
        ROOT / "build/crypto-bench/tls13-poc/entropy_meta_fixture.bin"
    )
    hello_inputs_path = (
        ROOT / "build/crypto-bench/tls13-poc/hello_inputs_fixture.bin"
    )
    required = (
        args.product_core,
        args.product_listing,
        args.ne_driver,
        PRODUCT_BUILD / "boot.bin",
        PRODUCT_BUILD / "loader.bin",
    )
    if args.secure:
        required += (
            PRODUCT_BUILD / "drivers/ne-driver-wrapper.asm",
            PRODUCT_BUILD / "drivers/nic-driver-abi.inc",
        )
    else:
        required += (entropy_meta_path, hello_inputs_path)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SystemExit(
            "missing prerequisite artifact(s):\n  "
            + "\n  ".join(missing)
            + "\nRun `make` and "
            "`python3 tools/crypto-bench/tls13-poc/build_poc_harness.py --k14` "
            "first."
        )

    product = args.product_core.read_bytes()
    product_phases = parse_product_phases(product)
    verify_product_abi(args.product_listing)
    verify_product_memory_contract(args.product_listing)
    packet_io_pstop_instruction_offset = None
    if args.secure:
        packet_io_pstop_instruction_offset = listing_source_offset(
            args.product_listing,
            "mov byte [ne_rx_stop], ne_rx_stop_2k",
        )
        if packet_io_pstop_instruction_offset != PACKET_IO_PSTOP_PATCH_OFFSET:
            raise AssertionError(
                "product packet-I/O PSTOP instruction drifted: "
                f"{packet_io_pstop_instruction_offset:#x} != "
                f"{PACKET_IO_PSTOP_PATCH_OFFSET:#x}"
            )
        expected_pstop_instruction = (
            b"\xc6\x06\xcd\x06" + bytes([PRODUCT_NE_PSTOP])
        )
        if (
            product[
                packet_io_pstop_instruction_offset:
                packet_io_pstop_instruction_offset + 5
            ]
            != expected_pstop_instruction
        ):
            raise AssertionError(
                "product packet-I/O PSTOP instruction preimage drifted"
            )
    driver = args.ne_driver.read_bytes()
    if len(driver) != SECTOR or driver[10:14] != b"SDRV":
        raise AssertionError("NE.DRV is not the expected one-sector Build-13 driver")
    ne_buf_load = None
    ne_buf_read = None
    driver_probe = b""
    driver_probe_listing = None
    if args.secure:
        driver_probe, driver_probe_listing = assemble(
            build,
            PRODUCT_BUILD / "drivers/ne-driver-wrapper.asm",
            "secure_ne_driver_probe",
            (),
        )
        if driver_probe != driver:
            raise AssertionError(
                "secure vault driver probe is not byte-identical to packaged NE.DRV"
            )
        ne_buf_load = (
            NIC_DRIVER_SLOT
            + listing_label_offset(driver_probe_listing, "ne_buf_load")
        )
        ne_buf_read = (
            NIC_DRIVER_SLOT
            + listing_label_offset(driver_probe_listing, "ne_buf_read")
        )
        if (ne_buf_load, ne_buf_read) != (0x1724, 0x175B):
            raise AssertionError(
                "packaged NE.DRV remote-DMA leaves drifted: "
                f"write={ne_buf_load:#x} read={ne_buf_read:#x}"
            )

    keygen, keygen_listing = assemble(
        build,
        HERE / "keygen_overlay.asm",
        "keygen_k14",
        ("TLS13_POC_K14",),
    )
    entropy = b""
    entropy_listing = None
    if args.secure:
        keccak_f1600 = HELLO_IMAGE_START + listing_label_offset(
            keygen_listing, "keccak_f1600"
        )
        keccak_state = HELLO_IMAGE_START + listing_label_offset(
            keygen_listing, "keccak_state"
        )
        keccak_work_start = HELLO_IMAGE_START + listing_label_offset(
            keygen_listing, "keccak_c"
        )
        keccak_work_end = HELLO_IMAGE_START + len(keygen)
        entropy, entropy_listing = assemble(
            build,
            HERE / "floppy_entropy_controller.asm",
            "floppy_entropy_controller",
            (
                f"FTE_KEYGEN_KECCAK_F1600=0x{keccak_f1600:04x}",
                f"FTE_KEYGEN_KECCAK_STATE=0x{keccak_state:04x}",
                (
                    "FTE_KEYGEN_KECCAK_WORK_START="
                    f"0x{keccak_work_start:04x}"
                ),
                f"FTE_KEYGEN_KECCAK_WORK_END=0x{keccak_work_end:04x}",
            ),
        )
    hello, _ = assemble(
        build,
        HERE / "hello_overlay.asm",
        "hello_cached_k14",
        (
            "TLS13_POC_K14",
            "HELLO_FRESH_ONLY",
            "HELLO_CACHED_CONNECT",
            "HELLO_FRESH_TICKET_REQUEST",
        ),
    )
    candidate, _ = assemble(
        build,
        HERE / "mlkem_candidate_kernel.asm",
        "candidate_k14",
        ("TLS13_POC_K14",),
    )
    sym, sym_listing = assemble(
        build,
        HERE / "tls13_sym_overlay.asm",
        "sym_k14",
        ("TLS13_POC_K14",),
    )
    auth = b""
    if args.identity:
        auth, _ = assemble(
            build,
            HERE / "auth_p256_overlay.asm",
            "auth_p256_live",
            (
                "TLS13_POC_K14",
                "AUTH_P256_LIVE_COMPACT_INPUT",
                "AUTH_P256_LIVE_202607_PIN",
            ),
        )
    fo = b""
    if args.secure:
        fo, _ = assemble(
            build,
            HERE / "fo_tail_kernel.asm",
            "fo_tail_live",
            ("TLS13_POC_K14",),
        )
    delta_loader, _ = assemble(
        build,
        HERE / "delta_loader.asm",
        "live_delta_loader",
        (),
    )
    if sym.count(CANARY_HEAD_REQUEST) != 1:
        raise AssertionError("symmetric canary HEAD-request literal geometry drifted")
    overlays = {
        "keygen": keygen,
        "hello": hello,
        "candidate": candidate,
        "sym": sym,
    }
    if args.identity:
        overlays["auth"] = auth
    if args.secure:
        overlays["fo"] = fo
        overlays["entropy"] = entropy
    expected_overlay_sizes = {
        "keygen": 2871,
        "hello": 3740,
        "candidate": 2113,
        "sym": 6142,
        "delta_loader": 146,
    }
    if args.secure:
        expected_overlay_sizes["fo"] = 2829
        expected_overlay_sizes["entropy"] = 512
    sized_images = overlays | {"delta_loader": delta_loader}
    for name, expected in expected_overlay_sizes.items():
        if len(sized_images[name]) != expected:
            raise AssertionError(
                f"{name} image drifted: {len(sized_images[name])} != {expected}"
            )

    fixture = b""
    if not args.secure:
        entropy_meta = entropy_meta_path.read_bytes()
        hello_inputs = hello_inputs_path.read_bytes()
        if len(entropy_meta) != SECTOR or len(hello_inputs) != SECTOR:
            raise AssertionError("K14 public input fixture is not sector-sized")
        d_z = entropy_meta[98:162]
        random_session = hello_inputs[:64]
        if len(d_z) != 64 or len(random_session) != 64:
            raise AssertionError("public fixture geometry drifted")
        fixture = (d_z + random_session).ljust(SECTOR, b"\0")
    if args.identity and not (12 * SECTOR < len(auth) <= 13 * SECTOR):
        raise AssertionError(
            f"live compact auth image is not exactly 13 sectors: {len(auth)} bytes"
        )
    layout = reserve_layout(
        overlays,
        fixture,
        identity=args.identity,
        secure=args.secure,
    )
    candidate_absolute_lba = CORE_START_LBA + layout["candidate"][0]
    sym_absolute_lba = CORE_START_LBA + layout["sym"][0]
    protected_absolute_lba = (
        CORE_START_LBA + layout["protected_controller"][0]
    )
    post_absolute_lba = CORE_START_LBA + layout["post_controller"][0]
    fo_absolute_lba = (
        CORE_START_LBA + layout["fo"][0] if args.secure else None
    )
    if (
        candidate_absolute_lba % FLOPPY_SECTORS_PER_TRACK != 0
        or sym_absolute_lba % FLOPPY_SECTORS_PER_TRACK != 0
        or (
            args.secure
            and fo_absolute_lba % FLOPPY_SECTORS_PER_TRACK != 0
        )
        or (
            protected_absolute_lba % FLOPPY_SECTORS_PER_TRACK
            + layout["protected_controller"][1]
            > FLOPPY_SECTORS_PER_TRACK
        )
        or (
            post_absolute_lba % FLOPPY_SECTORS_PER_TRACK
            + layout["post_controller"][1]
            > FLOPPY_SECTORS_PER_TRACK
        )
    ):
        raise AssertionError("critical live phases are not track-batchable")

    def key(name: str, count: int | None = None) -> int:
        start, reserved_count, _destination, _data = layout[name]
        return phase_key(start, reserved_count if count is None else count)

    bootstrap, _ = assemble(
        build,
        CONTROLLERS,
        "live_bootstrap",
        (
            "LIVE_K15_BOOTSTRAP",
            f"LIVE_K15_SCHEDULER_LBA={CORE_START_LBA + layout['boot_controller'][0]}",
        ),
    )
    boot_defines = [
        "LIVE_K15_BOOT_CONTROLLER",
        f"LIVE_K15_SYM_KEY=0x{key('sym'):04x}",
        f"LIVE_K15_ENDPOINT_KEY=0x{product_phases['E'].key:04x}",
        f"LIVE_K15_TCP_KEY=0x{product_phases['C'].key:04x}",
        f"LIVE_K15_KEYGEN_KEY=0x{key('keygen'):04x}",
        f"LIVE_K15_HELLO_KEY=0x{key('hello'):04x}",
        f"LIVE_K15_HELLO_CONTROLLER_KEY=0x{key('hello_controller'):04x}",
    ]
    if args.secure:
        assert ne_buf_load is not None
        boot_defines.extend(
            [
                "LIVE_K15_SECURE_FO",
                (
                    "LIVE_K15_SECURE_SYM_CONTROLLER_KEY="
                    f"0x{key('secure_sym_controller'):04x}"
                ),
                (
                    "LIVE_K15_ENTROPY_CONTROLLER_KEY="
                    f"0x{key('entropy_controller'):04x}"
                ),
                (
                    "LIVE_K15_SECURE_PRECONNECT_KEY="
                    f"0x{key('secure_preconnect_controller'):04x}"
                ),
                f"LIVE_K15_NE_BUF_LOAD=0x{ne_buf_load:04x}",
            ]
        )
    else:
        boot_defines.append(
            f"LIVE_K15_FIXTURE_KEY=0x{key('public_fixture'):04x}"
        )
    boot_controller, boot_listing = assemble(
        build,
        CONTROLLERS,
        "live_boot_controller",
        tuple(boot_defines),
    )
    secure_preconnect_controller = b""
    pre_sym_image = boot_controller
    pre_sym_listing = boot_listing
    pre_sym_source_label = "live_pre_sym_transition_source"
    pre_sym_end_label = "live_pre_sym_transition_end"
    if args.secure:
        assert ne_buf_read is not None

        def boot_address(label: str) -> int:
            return K14_EXTENSION_START + listing_label_offset(
                boot_listing, label
            )

        secure_preconnect_controller, secure_preconnect_listing = assemble(
            build,
            CONTROLLERS,
            "live_secure_preconnect_controller",
            (
                "LIVE_K15_SECURE_PRECONNECT_CONTROLLER",
                f"LIVE_K15_ENDPOINT_KEY=0x{product_phases['E'].key:04x}",
                f"LIVE_K15_TCP_KEY=0x{product_phases['C'].key:04x}",
                f"LIVE_K15_KEYGEN_KEY=0x{key('keygen'):04x}",
                f"LIVE_K15_HELLO_KEY=0x{key('hello'):04x}",
                (
                    "LIVE_K15_HELLO_CONTROLLER_KEY="
                    f"0x{key('hello_controller'):04x}"
                ),
                f"LIVE_K15_BOOT_EMIT=0x{boot_address('live_emit'):04x}",
                f"LIVE_K15_BOOT_FAIL=0x{boot_address('live_fail'):04x}",
                (
                    "LIVE_K15_BOOT_CARD_WRITE="
                    f"0x{boot_address('live_secure_card_write'):04x}"
                ),
                f"LIVE_K15_NE_BUF_READ=0x{ne_buf_read:04x}",
                f"LIVE_K15_NE_BUF_LOAD=0x{ne_buf_load:04x}",
                (
                    "LIVE_K15_PREPARE_INTERNET="
                    f"0x{0x1000 + ABI_OFFSETS['prepare_internet_path']:04x}"
                ),
            ),
        )
        pre_sym_image = secure_preconnect_controller
        pre_sym_listing = secure_preconnect_listing
        pre_sym_source_label = "preconnect_transition_source"
        pre_sym_end_label = "preconnect_transition_end"

    pre_sym_source = listing_label_offset(
        pre_sym_listing, pre_sym_source_label
    )
    pre_sym_end = listing_label_offset(pre_sym_listing, pre_sym_end_label)
    if not pre_sym_source < pre_sym_end <= len(pre_sym_image):
        raise AssertionError("pre-sym transition source escaped its controller")
    pre_sym_transition = pre_sym_image[pre_sym_source:pre_sym_end]
    pre_sym_binary = build / "live_pre_sym_transition.bin"
    pre_sym_binary.write_bytes(pre_sym_transition)
    if PRE_SYM_TRANSITION_START + len(pre_sym_transition) > TCP_TAIL_STATE_START:
        raise AssertionError("pre-sym transition reaches live TCP tail state")

    hello_controller, _ = assemble(
        build,
        CONTROLLERS,
        "live_hello_controller",
        (
            "LIVE_K15_HELLO_CONTROLLER",
            f"LIVE_K15_CRYPTO_CONTROLLER_KEY=0x{key('crypto_controller'):04x}",
        ),
    )
    crypto_defines = [
        (
            "LIVE_K15_SECURE_CRYPTO_CONTROLLER"
            if args.secure
            else "LIVE_K15_CRYPTO_CONTROLLER"
        ),
        f"LIVE_K15_CANDIDATE_KEY=0x{key('candidate'):04x}",
        (
            "LIVE_K15_DELTA_LOADER_PATH="
            f'"{(build / "live_delta_loader.bin").as_posix()}"'
        ),
        f"LIVE_K15_CORE_START_LBA={CORE_START_LBA}",
    ]
    if args.secure:
        assert ne_buf_load is not None and ne_buf_read is not None
        crypto_defines.extend(
            [
                f"LIVE_K15_NE_BUF_LOAD=0x{ne_buf_load:04x}",
                f"LIVE_K15_NE_BUF_READ=0x{ne_buf_read:04x}",
                (
                    "LIVE_K15_SCRUB_CONTROLLER_KEY="
                    f"0x{key('scrub_controller'):04x}"
                ),
            ]
        )
    else:
        crypto_defines.extend(
            [
                f"LIVE_K15_SYM_RESTORE_KEY=0x{key('sym', 8):04x}",
                (
                    "LIVE_K15_PROTECTED_CONTROLLER_KEY="
                    f"0x{key('protected_controller'):04x}"
                ),
            ]
        )
    crypto_controller, crypto_listing = assemble(
        build,
        CONTROLLERS,
        "live_crypto_controller",
        tuple(crypto_defines),
    )
    persistent_prefix = "live_secure_persist" if args.secure else "live_persist"
    persistent_start = listing_label_offset(
        crypto_listing, f"{persistent_prefix}_services_start"
    )
    persistent_end = len(crypto_controller)

    def persistent_address(label: str) -> int:
        return K14_EXTENSION_START + listing_label_offset(crypto_listing, label)

    def sym_address(label: str) -> int:
        return HELLO_IMAGE_START + listing_label_offset(sym_listing, label)

    persistent_transition = persistent_address(f"{persistent_prefix}_transition")
    persistent_zero_window = persistent_address(f"{persistent_prefix}_zero_window")
    persistent_emit = persistent_address(f"{persistent_prefix}_emit")
    persistent_fail = persistent_address(f"{persistent_prefix}_fail")
    persistent_runtime_start = K14_EXTENSION_START + persistent_start
    persistent_runtime_end = K14_EXTENSION_START + persistent_end
    if not (
        persistent_runtime_start == PERSISTENT_SERVICES_START
        and persistent_runtime_start < persistent_runtime_end
        and persistent_runtime_end <= PERSISTENT_SERVICES_END
        and persistent_transition == persistent_runtime_start
    ):
        raise AssertionError("persistent post-Finished service geometry is unsafe")
    persistent_services_data = crypto_controller[persistent_start:persistent_end]
    persistent_services_binary = build / "live_persistent_services.bin"
    persistent_services_binary.write_bytes(persistent_services_data)

    secure_sym_controller = b""
    secure_sym_listing = None
    if args.secure:
        secure_sym_controller, secure_sym_listing = assemble(
            build,
            CONTROLLERS,
            "live_secure_sym_controller",
            (
                "LIVE_K15_SECURE_SYM_CONTROLLER",
                f"LIVE_K15_SYM_RESTORE_KEY=0x{key('sym', 8):04x}",
                (
                    "LIVE_K15_PROTECTED_CONTROLLER_KEY="
                    f"0x{key('protected_controller'):04x}"
                ),
                f"LIVE_K15_CORE_START_LBA={CORE_START_LBA}",
                f"LIVE_K15_PERSIST_FAIL=0x{persistent_fail:04x}",
            ),
        )

    protected_defines = [
        "LIVE_K15_PROTECTED_CONTROLLER",
        f"LIVE_K15_PERSIST_FAIL=0x{persistent_fail:04x}",
        f"LIVE_K15_PERSIST_EMIT=0x{persistent_emit:04x}",
        (
            "LIVE_K15_PERSIST_ZERO_WINDOW="
            f"0x{persistent_zero_window:04x}"
        ),
        (
            "LIVE_K15_PERSIST_TRANSITION="
            f"0x{persistent_transition:04x}"
        ),
        f"LIVE_K15_POST_CONTROLLER_KEY=0x{key('post_controller'):04x}",
    ]
    if args.identity:
        protected_defines.extend(
            [
                "LIVE_K15_IDENTITY_CAPTURE",
                (
                    "LIVE_K15_SYM_TRANSCRIPT_SNAPSHOT="
                    f"0x{sym_address('sym_transcript_snapshot'):04x}"
                ),
                f"LIVE_K15_SHA256_INIT=0x{sym_address('sha256_init'):04x}",
                f"LIVE_K15_SHA256_UPDATE=0x{sym_address('sha256_update'):04x}",
                f"LIVE_K15_SHA256_FINISH=0x{sym_address('sha256_finish'):04x}",
                (
                    "LIVE_K15_SHA256_SAVE_CONTEXT="
                    f"0x{sym_address('sha256_save_context'):04x}"
                ),
                (
                    "LIVE_K15_SHA256_RESTORE_CONTEXT="
                    f"0x{sym_address('sha256_restore_context'):04x}"
                ),
            ]
        )
    protected_controller, _ = assemble(
        build,
        CONTROLLERS,
        "live_protected_controller",
        tuple(protected_defines),
    )
    post_defines = [
        "LIVE_K15_POST_CONTROLLER",
        f"LIVE_K15_PERSIST_FAIL=0x{persistent_fail:04x}",
        f"LIVE_K15_PERSIST_EMIT=0x{persistent_emit:04x}",
    ]
    if args.identity:
        post_defines.extend(
            [
                "LIVE_K15_IDENTITY_CAPTURE",
                (
                    "LIVE_K15_PERSIST_ZERO_WINDOW="
                    f"0x{persistent_zero_window:04x}"
                ),
                (
                    "LIVE_K15_PERSIST_TRANSITION="
                    f"0x{persistent_transition:04x}"
                ),
            ]
        )
        if args.secure:
            post_defines.extend(
                [
                    "LIVE_K15_SECURE_FO",
                    (
                        "LIVE_K15_FO_CONTROLLER_KEY="
                        f"0x{key('fo_controller'):04x}"
                    ),
                ]
            )
        else:
            post_defines.append(
                "LIVE_K15_AUTH_CONTROLLER_KEY="
                f"0x{key('auth_controller'):04x}"
            )
    post_controller, _ = assemble(
        build,
        CONTROLLERS,
        "live_post_controller",
        tuple(post_defines),
    )
    auth_controller = b""
    if args.identity:
        auth_defines = ["LIVE_K15_AUTH_CONTROLLER"]
        if args.secure:
            auth_defines.extend(
                [
                    "LIVE_K15_AUTH_USE_RESIDENT_LOADER",
                    f"LIVE_K15_AUTH_PHASE_KEY=0x{key('auth'):04x}",
                ]
            )
        else:
            auth_defines.extend(
                [
                    (
                        "LIVE_K15_AUTH_ABSOLUTE_LBA="
                        f"{CORE_START_LBA + layout['auth'][0]}"
                    ),
                    f"LIVE_K15_AUTH_SECTORS={layout['auth'][1]}",
                ]
            )
        auth_controller, _ = assemble(
            build,
            CONTROLLERS,
            "live_auth_controller",
            tuple(auth_defines),
        )
    fo_controller = b""
    fo_controller_listing = None
    scrub_controller = b""
    if args.secure:
        assert ne_buf_load is not None and ne_buf_read is not None
        fo_controller, fo_controller_listing = assemble(
            build,
            CONTROLLERS,
            "live_fo_controller",
            (
                "LIVE_K15_FO_CONTROLLER",
                f"LIVE_K15_FO_PHASE_KEY=0x{key('fo'):04x}",
                (
                    "LIVE_K15_AUTH_CONTROLLER_KEY="
                    f"0x{key('auth_controller'):04x}"
                ),
                f"LIVE_K15_NE_BUF_LOAD=0x{ne_buf_load:04x}",
                f"LIVE_K15_NE_BUF_READ=0x{ne_buf_read:04x}",
                f"LIVE_K15_PERSIST_FAIL=0x{persistent_fail:04x}",
                f"LIVE_K15_PERSIST_EMIT=0x{persistent_emit:04x}",
            ),
        )
        scrub_controller, _ = assemble(
            build,
            CONTROLLERS,
            "live_scrub_controller",
            (
                "LIVE_K15_SCRUB_CONTROLLER",
                f"LIVE_K15_NE_BUF_LOAD=0x{ne_buf_load:04x}",
                f"LIVE_K15_PERSIST_EMIT=0x{persistent_emit:04x}",
            ),
        )
    controller_data = {
        "boot_controller": boot_controller,
        "hello_controller": hello_controller,
        "crypto_controller": crypto_controller,
        "protected_controller": protected_controller,
        "post_controller": post_controller,
    }
    if args.identity:
        controller_data["auth_controller"] = auth_controller
    if args.secure:
        controller_data["secure_sym_controller"] = secure_sym_controller
        controller_data[
            "secure_preconnect_controller"
        ] = secure_preconnect_controller
        controller_data["fo_controller"] = fo_controller
        controller_data["scrub_controller"] = scrub_controller
    for name, value in controller_data.items():
        reserved = layout[name][1] * SECTOR
        if len(value) > reserved:
            raise AssertionError(
                f"{name} is {len(value)} bytes, exceeds {reserved}-byte slot"
            )
    if len(bootstrap) > SECTOR:
        raise AssertionError("resident bootstrap exceeds the temporary driver slot")
    crypto_code_label = (
        "live_secure_crypto_controller_code_end"
        if args.secure
        else "live_crypto_controller_code_end"
    )
    delta_source_label = (
        "live_secure_delta_loader_source"
        if args.secure
        else "live_delta_loader_source"
    )
    crypto_code_end = listing_label_offset(crypto_listing, crypto_code_label)
    delta_source = listing_label_offset(crypto_listing, delta_source_label)
    delta_source_end = delta_source + len(delta_loader)
    if crypto_code_end > K14_SYM_RUNTIME_START - K14_EXTENSION_START:
        raise AssertionError(
            "live crypto code reaches K14's extension-resident symmetric runtime"
        )
    if not (
        crypto_code_end == delta_source
        and crypto_controller[delta_source:delta_source_end] == delta_loader
        and len(crypto_controller) <= K14_EXTENSION_END - K14_EXTENSION_START
        and delta_source < K14_SYM_RUNTIME_START - K14_EXTENSION_START
        and delta_source_end <= persistent_start
        and persistent_start == K14_SYM_RUNTIME_END - K14_EXTENSION_START
        and persistent_end == len(crypto_controller)
    ):
        raise AssertionError(
            "embedded delta-loader/persistent-service geometry drifted"
        )
    if not (
        TRANSCRIPT_HANDOFF_END <= DELTA_LOADER_START
        and DELTA_LOADER_START + len(delta_loader) <= TCP_TAIL_STATE_START
    ):
        raise AssertionError(
            "relocated delta loader overlaps transcript or live TCP tail state"
        )
    if args.secure:
        assert secure_sym_listing is not None
        secure_sym_code_end = listing_label_offset(
            secure_sym_listing, "live_secure_sym_controller_code_end"
        )
        if not (
            len(secure_sym_controller) == 256
            and secure_sym_code_end <= len(secure_sym_controller)
            and len(fo_controller) <= FO_CONTROLLER_END - FO_CONTROLLER_START
            and len(fo) <= FO_KERNEL_SECTORS * SECTOR
            and FO_KERNEL_START + FO_KERNEL_SECTORS * SECTOR
            == FO_CONTROLLER_START
            and SECURE_CARD_CONTROLLER_ADDR + 256 <= SECURE_CARD_EK_ADDR
            and SECURE_CARD_EK_ADDR + SECURE_CARD_EK_LEN
            <= SECURE_CARD_C_ADDR
            and SECURE_CARD_C_ADDR + SECURE_CARD_C_LEN
            <= SECURE_CARD_HANDOFF_A_ADDR
            and SECURE_CARD_HANDOFF_A_ADDR + SECURE_CARD_HANDOFF_LEN
            <= SECURE_CARD_HANDOFF_B_ADDR
            and SECURE_CARD_HANDOFF_B_ADDR + SECURE_CARD_HANDOFF_LEN
            <= 0x8000
        ):
            raise AssertionError("secure card-vault/controller geometry is unsafe")
    hello_image_end = HELLO_IMAGE_START + len(hello)
    if not (
        hello_image_end <= HELLO_TX_STAGE_START
        and HELLO_TX_STAGE_START < HELLO_TX_STAGE_END
        and HELLO_TX_STAGE_END == HELLO_IMAGE_START + (8 * SECTOR)
    ):
        raise AssertionError(
            "HELLO transmit stage is not bounded by the image tail and "
            "eight-sector symmetric restore"
        )
    protected_reserved = layout["protected_controller"][1] * SECTOR
    if len(protected_controller) > protected_reserved:
        raise AssertionError("protected controller exceeds its two-sector low slot")
    if (
        args.identity
        and PROTECTED_CONTROLLER_START + len(protected_controller) > 0x0E00
    ):
        raise AssertionError(
            "identity protected executable reaches its 0x0e00 tail quarantine"
        )
    post_reserved = POST_CONTROLLER_END - POST_CONTROLLER_START
    if len(post_controller) > post_reserved:
        raise AssertionError("post controller exceeds its two-sector low slot")
    post_plaintext_cap = (
        IDENTITY_POST_RECORD_PLAINTEXT_CAP
        if args.identity
        else POST_RECORD_PLAINTEXT_CAP
    )
    if not (
        RX_BUFFER_END <= PROTECTED_CONTROLLER_START
        and (
            args.identity
            or PROTECTED_CONTROLLER_END <= TRANSCRIPT_HANDOFF_START
        )
        and POST_CONTROLLER_START == PROTECTED_CONTROLLER_START
        and POST_CONTROLLER_END <= POST_QUARANTINE_START
        and POST_QUARANTINE_END == DELTA_LOADER_START
        and POST_SCATTER_MID_START == K14_EXTENSION_END
        and POST_SCATTER_MID_END == POST_RETAINED_APP_STATE_START
        and POST_RETAINED_APP_STATE_END == POST_SCATTER_HIGH_START
        and POST_SCATTER_HIGH_END == POST_RETAINED_TICKET_STATE_START
        and POST_RECORD_PLAINTEXT_CAP == 1624
        and IDENTITY_POST_RECORD_PLAINTEXT_CAP == 1592
        and post_plaintext_cap == (1592 if args.identity else 1624)
    ):
        raise AssertionError("protected/post controller low-memory lifetime is unsafe")
    if args.identity and not (
        IDENTITY_POST_QUARANTINE_END + 32 == DELTA_LOADER_START
        and HELLO_IMAGE_START + layout["auth"][1] * SECTOR == 0x3200
        and layout["auth_controller"][2] == 0x3200
        and HELLO_IMAGE_START + len(auth) <= 0x3200
    ):
        raise AssertionError("identity digest/auth-controller lifetime is unsafe")
    if not (
        PROTECTED_HIGH_STATE_END <= PRODUCT_CHAT_POOL_START
        and persistent_runtime_start >= K14_SYM_RUNTIME_END
        and persistent_runtime_end <= K14_EXTENSION_END
    ):
        raise AssertionError("persistent services overlap symmetric or product state")

    live_phase_names = [
        "boot_controller",
        "hello_controller",
        "crypto_controller",
    ]
    if args.secure:
        live_phase_names.extend(
            ["secure_sym_controller", "secure_preconnect_controller"]
        )
    live_phase_names.extend(
        [
        "protected_controller",
        "post_controller",
        ]
    )
    if args.secure:
        live_phase_names.extend(["fo_controller", "scrub_controller"])
    if args.secure:
        live_phase_names.append("entropy_controller")
    else:
        live_phase_names.append("public_fixture")
    live_phase_names.extend(
        [
        "keygen",
        "hello",
        "candidate_track_pad",
        "candidate",
        "sym_track_pad",
        "sym",
        ]
    )
    if args.secure:
        live_phase_names.extend(
            [
                "fo_track_pad",
                "fo",
                "auth_controller",
                "auth_track_pad",
                "auth",
            ]
        )
    elif args.identity:
        live_phase_names.extend(
            ["auth_controller", "auth_track_pad", "auth"]
        )
    live_phases = [
        make_live_phase(
            layout,
            name,
            controller_data.get(name),
        )
        for name in live_phase_names
    ]
    cursor = BASE_SECTORS
    for phase in live_phases:
        if phase.start != cursor:
            raise AssertionError("live phase layout is not contiguous")
        cursor += phase.count

    core = bytearray(product[: BASE_SECTORS * SECTOR])
    if any(core[0x0600:0x0800]):
        raise AssertionError("product resident driver slot is no longer zero-filled")
    core[LINK_START:LINK_END] = bytes(LINK_END - LINK_START)
    patch_exact(core, 0x0017, b"\xfa\xbd\x00\x80", b"\xe9\xe6\x05\x90")
    patch_exact(
        core,
        0x004A,
        b"\xb8\x3e\x01\xe8\x69\x00",
        b"\x90" * 6,
    )
    if args.secure:
        # Take over immediately after packet-I/O initialization but before the
        # product's first DHCP call.  The preconnect continuation invokes that
        # exact routine only after conditioned output is card-vaulted.
        patch_exact(
            core,
            0x0069,
            b"\xe8\x8a\x01\x72\x42",
            b"\xe9\x94\x23\x90\x90",
        )
    else:
        # The credential-free timing harness retains the historical
        # post-DHCP takeover.
        patch_exact(
            core,
            0x006E,
            b"\xb8\x24\x02\xe8\x40\x00",
            b"\xe9\x8f\x23" + b"\x90" * 3,
        )
    if args.secure:
        patch_exact(
            core,
            PACKET_IO_PSTOP_PATCH_OFFSET,
            b"\xc6\x06\xcd\x06" + bytes([PRODUCT_NE_PSTOP]),
            b"\xc6\x06\xcd\x06" + bytes([SECURE_NE_PSTOP]),
        )
    core[0x0600:0x0800] = padded(bootstrap, 1)
    for phase in live_phases:
        core.extend(padded(phase.data, phase.count))
    if len(core) != cursor * SECTOR:
        raise AssertionError("constructed core does not match phase-sector ledger")
    struct.pack_into("<H", core, 0x11, cursor)
    struct.pack_into("<H", core, 0x13, 0)
    struct.pack_into("<H", core, 0x15, 0)

    live_core = build / "SEED.SYS"
    live_core.write_bytes(core)
    scan_no_request_or_credentials(
        "live SEED.SYS",
        core,
        allow_exact_head=True,
    )
    if core.lower().count(b"api.openai.com") != 3:
        raise AssertionError(
            "harness must contain endpoint-DNS, ClientHello-SNI, and HEAD host literals"
        )
    if any(core[LINK_START:LINK_END]):
        raise AssertionError("removed product LINK/API overlay is not all zero")

    image = build / "floppy-160k-live-k15.img"
    run(
        [
            "python3",
            str(ROOT / "tools/build-fat12-image.py"),
            "build",
            "--boot",
            str(PRODUCT_BUILD / "boot.bin"),
            "--loader",
            str(PRODUCT_BUILD / "loader.bin"),
            "--loader-sectors",
            "4",
            "--output",
            str(image),
            "--file",
            f"{live_core}:SEED.SYS",
            "--file",
            f"{args.ne_driver}:SEED/DRIVERS/NE.DRV",
        ]
    )
    image_bytes = image.read_bytes()
    if image_bytes[CORE_START_LBA * SECTOR : (CORE_START_LBA + cursor) * SECTOR] != core:
        raise AssertionError("SEED.SYS is not the first contiguous FAT data file")
    scan_no_request_or_credentials(
        "live floppy image",
        image_bytes,
        allow_exact_head=True,
    )
    basic_loader, basic = build_basic_sidecar(build)

    phase_manifest = [
        {
            "name": phase.name,
            "start_sector": phase.start,
            "sectors": phase.count,
            "key": f"0x{phase.key:04x}",
            "destination": f"0x{phase.destination:04x}",
            "bytes": len(phase.data),
            "sha256": sha256(phase.data),
        }
        for phase in live_phases
    ]
    manifest_scope = (
        (
            "offline-built, credential-free live-network deadline plus "
            "post-Finished HEAD/tentative-ticket, live NE2000 card-RAM "
            "ML-KEM FO validation, and dated exact-leaf P-256 checkpoint; "
            "this remains an isolated secure-tier PoC with no credential "
            "unlock and performed no VM launch or network I/O while building"
        )
        if args.secure
        else (
            "offline-built, credential-free live-network deadline plus "
            "post-Finished HEAD/tentative-ticket canary using logical-K14 "
            "overlays and memory geometry; the live_k15 filename is historical "
            "and this is neither a 15-sector-K proof nor a secure-tier commit; "
            "this build performed no VM launch and no network I/O"
        )
    )
    post_quarantine_runtime_end = (
        IDENTITY_POST_QUARANTINE_END
        if args.identity
        else POST_QUARANTINE_END
    )
    limitations = [
        (
            "the secure artifact automatically SHA3-256-conditions 256 "
            "PIT-measured alternating read-only floppy completions before "
            "networking; emulator timing receives zero security credit and "
            "physical-drive characterization remains pending"
            if args.secure
            else (
                "d||z and ClientHello random/session are public deterministic "
                "fixtures; the 8088 still performs KeyGen and every TLS secret "
                "operation"
            )
        ),
        (
            "the secure checkpoint remains credential-free and RAM/card-RAM "
            "only; it does not unlock product credentials, persist a ticket, "
            "or prove a resumed connection"
            if args.secure
            else (
                "CANARY COMMIT means only server Finished, client Finished, "
                "credential-free HEAD response, and RAM-only tentative ticket "
                "were authenticated/drained; it does not unlock credentials, "
                "persist state, or prove resumption"
            )
        ),
        "a VM/pcap run remains required to establish live timing",
    ]
    if not args.secure:
        limitations.insert(
            1, "no certificate authentication or ML-KEM FO proof is included"
        )
    manifest = {
        "scope": manifest_scope,
        "crypto_memory_variant": {
            "logical_variant": "K14",
            "k_window": "0x1800..0x3400 (end exclusive)",
            "persistent_extension": "0x3400..0x3600 (end exclusive)",
            "historical_artifact_name": "live_k15",
            "is_15_sector_k_memory_proof": False,
        },
        "identity_checkpoint": {
            "enabled": args.identity,
            "policy": (
                "dated exact-leaf P-256 possession checkpoint"
                if args.identity
                else None
            ),
            "credential_unlock": False,
            "compact_input": (
                "0x3c30..0x3c9b" if args.identity else None
            ),
            "digest_hold": (
                "0x0ee0..0x0f00 until exact post-record commit"
                if args.identity
                else None
            ),
            "auth_controller": (
                "0x3200; auth overlay padded end is exactly 0x3200"
                if args.identity
                else None
            ),
        },
        "git_head": run(["git", "rev-parse", "HEAD"], capture=True).strip(),
        "product_input": {
            "path": str(args.product_core),
            "bytes": len(product),
            "sha256": sha256(product),
            "resident_abi_offsets": {
                name: f"0x{offset + 0x1000:04x}"
                for name, offset in ABI_OFFSETS.items()
            },
        },
        "output": {
            "core": str(live_core),
            "core_bytes": len(core),
            "core_sectors": cursor,
            "core_sha256": sha256(core),
            "image": str(image),
            "image_bytes": len(image_bytes),
            "image_sha256": sha256(image_bytes),
            "basic_loader": str(basic_loader),
            "basic_program": str(basic),
            "pre_sym_transition": str(pre_sym_binary),
            "persistent_services": str(persistent_services_binary),
        },
        "live_phases": phase_manifest,
        "pre_sym_transition": {
            "runtime_start": f"0x{PRE_SYM_TRANSITION_START:04x}",
            "runtime_end": (
                f"0x{PRE_SYM_TRANSITION_START + len(pre_sym_transition):04x}"
            ),
            "runtime_limit": f"0x{TCP_TAIL_STATE_START:04x}",
            "bytes": len(pre_sym_transition),
            "sha256": sha256(pre_sym_transition),
            "installed_after_endpoint_dns": True,
            "loads": [
                "eight-sector HELLO phase to 0x1800..0x2800",
                "one-sector HELLO controller staged at 0x3000..0x3200",
            ],
            "controller_stage_copied_to": "0x3400..0x3600 only after full read",
            "failed_stage_preserves_boot_fail_service": True,
            "phase_loader_registers_treated_as_clobbered": True,
        },
        "persistent_services": {
            "transition": f"0x{persistent_transition:04x}",
            "zero_window": f"0x{persistent_zero_window:04x}",
            "emit": f"0x{persistent_emit:04x}",
            "fail": f"0x{persistent_fail:04x}",
            "runtime_start": f"0x{persistent_runtime_start:04x}",
            "runtime_end": f"0x{persistent_runtime_end:04x}",
            "runtime_limit": f"0x{PERSISTENT_SERVICES_END:04x}",
            "bytes": len(persistent_services_data),
            "sha256": sha256(persistent_services_data),
            "borrowed_product_region": None,
            "product_arena_context_writes": 0,
            "post_controller_load_destination": "0x0900",
        },
        "critical_delta_loader": {
            "source": str(HERE / "delta_loader.asm"),
            "source_image": str(build / "live_delta_loader.bin"),
            "source_image_bytes": len(delta_loader),
            "source_image_sha256": sha256(delta_loader),
            "embedded_controller_range": (
                f"0x{K14_EXTENSION_START + delta_source:04x}.."
                f"0x{K14_EXTENSION_START + delta_source_end:04x}"
            ),
            "runtime_range": (
                f"0x{DELTA_LOADER_START:04x}.."
                f"0x{DELTA_LOADER_START + len(delta_loader):04x}"
            ),
            "resident_phase_key_input": True,
            "absolute_lba_base": CORE_START_LBA,
            "track_batched": True,
            "single_sector_fallback": True,
            "copied_before_candidate_load": True,
            "embedded_source_dead_before_sym_init": True,
            "critical_disk_layout": {
                "sectors_per_track": FLOPPY_SECTORS_PER_TRACK,
                "alignment_padding_sectors": (
                    layout["candidate_track_pad"][1]
                    + layout["sym_track_pad"][1]
                    + (
                        layout["fo_track_pad"][1]
                        if args.secure
                        else 0
                    )
                    + (
                        layout["auth_track_pad"][1]
                        if args.identity
                        else 0
                    )
                ),
                "candidate_absolute_lba": candidate_absolute_lba,
                "candidate_batch_calls": 1,
                "symmetric_restore_absolute_lba": sym_absolute_lba,
                "symmetric_restore_sectors": 8,
                "symmetric_restore_batch_calls": 1,
                "protected_controller_absolute_lba": protected_absolute_lba,
                "protected_controller_batch_calls": 1,
                "post_controller_absolute_lba": post_absolute_lba,
                "post_controller_batch_calls": 1,
                "fo_absolute_lba": fo_absolute_lba,
                "fo_sectors": FO_KERNEL_SECTORS if args.secure else 0,
                "fo_load_via_resident_loader": args.secure,
            },
        },
        "memory_lifetimes": {
            "range_convention": "all ranges are half-open [start,end)",
            "nic_rx": f"[0x{RX_BUFFER_START:04x},0x{RX_BUFFER_END:04x})",
            "temporary_k_prime_handoff": (
                "0x08c0..0x08e0; populated before sym_init, copied to "
                "0x3600 after init, then zeroized"
            ),
            "protected_controller": (
                f"0x{PROTECTED_CONTROLLER_START:04x}.."
                f"0x{PROTECTED_CONTROLLER_START + protected_reserved:04x}"
            ),
            "post_controller": (
                f"0x{POST_CONTROLLER_START:04x}.."
                f"0x{POST_CONTROLLER_END:04x}"
            ),
            "transcript_then_post_quarantine": (
                "0x0d00..0x0dab HELLO handoff until sym import; "
                "after sym import, authenticated post-Finished plaintext "
                f"scatter spans are 0x0d00..0x{post_quarantine_runtime_end:04x}, "
                "0x3600..0x3838, and "
                "0x3920..0x3b40"
            ),
            "post_finished_plaintext_scatter": {
                "capacity_bytes": post_plaintext_cap,
                "spans": [
                    (
                        f"0x0d00..0x{post_quarantine_runtime_end:04x}"
                    ),
                    "0x3600..0x3838",
                    "0x3920..0x3b40",
                ],
                "retained_client_and_server_application_state": (
                    "0x3838..0x3920"
                ),
                "retained_ticket_state_start": "0x3b40",
                "parse_only_after_tag_verification": True,
                "tls_inner_plaintext_padding_supported": False,
            },
            "identity_digest_hold": (
                {
                    "range": "0x0ee0..0x0f00",
                    "source": "0x3c30..0x3c50",
                    "saved_before_post_controller": True,
                    "restored_at_exact_head_ticket_boundary": True,
                    "outside_identity_post_scatter": True,
                }
                if args.identity
                else None
            ),
            "fo_ticket_hold": (
                {
                    "ticket": "0x0700..0x07ee",
                    "expected_provisional_k": "0x07ee..0x080e",
                    "kernel_preserved_limit": "0x0830",
                    "restored_only_after_valid_fo": True,
                }
                if args.secure
                else None
            ),
            "critical_delta_loader": (
                f"0x{DELTA_LOADER_START:04x}.."
                f"0x{DELTA_LOADER_START + len(delta_loader):04x}; "
                "installed only after HELLO commits, above its transcript "
                "handoff and below the live TCP tail"
            ),
            "hello_tx_stage": (
                f"0x{HELLO_TX_STAGE_START:04x}..0x{HELLO_TX_STAGE_END:04x}; "
                "first byte-identical replay prefix prebuilt before TCP SYN; "
                "restored by the first eight symmetric sectors"
            ),
            "hello_tx_stage_restore": {
                "phase": "sym",
                "destination": f"0x{HELLO_IMAGE_START:04x}",
                "bytes": 8 * SECTOR,
            },
            "persistent_services": (
                f"0x{persistent_runtime_start:04x}.."
                f"0x{persistent_runtime_end:04x}; untouched K14 extension tail"
            ),
            "product_arena_context": "0x3e40..0x3f00; zero harness writes",
            "k14_extension": (
                f"0x{K14_EXTENSION_START:04x}..0x{K14_EXTENSION_END:04x}"
            ),
            "k14_symmetric_runtime": (
                f"0x{K14_SYM_RUNTIME_START:04x}..0x{K14_SYM_RUNTIME_END:04x}"
            ),
            "post_sym_phase_loads": [
                {
                    "phase": "protected_controller",
                    "destination": f"0x{PROTECTED_CONTROLLER_START:04x}",
                    "bytes": protected_reserved,
                },
                {
                    "phase": "post_controller",
                    "destination": f"0x{POST_CONTROLLER_START:04x}",
                    "bytes": post_reserved,
                },
            ],
            "post_sym_extension_writes": (
                "sym_init owns 0x3510..0x355d; persistent service bytes "
                "0x355d..runtime_end are installed before sym_init and never rewritten"
            ),
            "product_arena_context_writes": 0,
        },
        "patches": {
            "start_detour": "file 0x0017 -> resident 0x1600 bootstrap",
            "splash_skip": "file 0x004a..0x004f",
            "pre_dhcp_detour": (
                (
                    "file 0x0069..0x006d -> 0x3400 controller, after local "
                    "packet-I/O init and before first network transmission"
                )
                if args.secure
                else None
            ),
            "post_dhcp_detour": (
                None
                if args.secure
                else "file 0x006e..0x0073 -> 0x3400 controller after DHCP"
            ),
            "removed_link_api_window": "file 0x0800..0x25ff is zero",
            "secure_ne2000_pstop": (
                {
                    "listing_instruction_offset": (
                        f"0x{packet_io_pstop_instruction_offset:04x}"
                    ),
                    "instruction_preimage": "c606cd0680",
                    "instruction_postimage": "c606cd0673",
                    "immediate_offset": "0x4085",
                    "live_artifact_only": True,
                    "product_source_edited": False,
                }
                if args.secure
                else None
            ),
            "compiled_canary_head_request": (
                "exactly one 50-byte HEAD /v1/models request retained in the "
                "symmetric overlay; Host only, no credential or body; "
                "72-byte encrypted TLS record"
            ),
        },
        "literal_gate": {
            "forbidden": [
                token.decode("ascii", errors="replace")
                for token in FORBIDDEN_LITERALS
            ],
            "forbidden_hits": 0,
            "exact_allowed_head_occurrences": 1,
            "allowed_head_sha256": sha256(CANARY_HEAD_REQUEST),
            "api_openai_host_occurrences": 3,
            "files_packaged": ["SEED.SYS", "SEED/DRIVERS/NE.DRV"],
            "credential_files_packaged": False,
            "credential_free_canary_request_compiled": True,
        },
        "timing_contract": {
            "client_hello_schedule": (
                "the exact six-fragment ClientHello is built/hashed/consumed "
                "offline, rewound with hashing disabled, and its first replay "
                "fragment is staged before the cached TCP SYN"
            ),
            "fresh_ticket_request": {
                "build_define": "HELLO_FRESH_TICKET_REQUEST",
                "extension": "002d00020101",
                "meaning": "psk_key_exchange_modes = psk_dhe_ke",
                "occurrences": 1,
                "client_hello_handshake_bytes": 1382,
                "client_hello_record_bytes": 1387,
                "fragment_bytes": [147, 384, 384, 384, 32, 56],
                "pre_shared_key_offered": False,
                "server_ticket_issuance_is_discretionary": True,
            },
            "guest_start": "first TCP payload carrying ServerHello, after resident receive returns",
            "guest_end": "BIOS tick sampled after resident client-Finished tcp_send_payload returns",
            "post_finished_ticks": (
                "client-Finished return, client application write-key ready, "
                "HEAD-send return, and post-controller load"
            ),
            "deadline_ticks": 273,
            "wire_authority": (
                "live_k15_pcap.py measures first ServerHello byte to first "
                "client Finished byte from the host pcap"
            ),
        },
        "strict_server_shape": {
            "server_hello_record": "Handshake TLS 1.2 legacy version, body 1210 bytes",
            "protected_flight": (
                "zero or one one-byte compatibility CCS followed by exactly "
                "one encrypted handshake record, no padding, and no coalesced "
                "or already-queued next record"
            ),
            "post_finished": (
                f"only authenticated application records; plaintext <={post_plaintext_cap} "
                "bytes per record and no TLSInnerPlaintext padding; inner type "
                "is HTTP response data for the one outstanding HEAD, 1..4 "
                "complete bounded NewSessionTickets whose extensions are "
                "empty, early_data only, or early_data plus one zero-length "
                "unknown extension; or a classified alert that always fails "
                "closed"
            ),
        },
        "limitations": limitations,
    }
    if args.secure:
        assert ne_buf_load is not None and ne_buf_read is not None
        manifest["entropy_ceremony"] = {
            "enabled": True,
            "controller": {
                "source": str(HERE / "floppy_entropy_controller.asm"),
                "image": str(build / "floppy_entropy_controller.bin"),
                "bytes": len(entropy),
                "sha256": sha256(entropy),
                "runtime": "0x0900..0x0b00",
                "phase_key": f"0x{key('entropy_controller'):04x}",
            },
            "primitive": {
                "source": str(HERE / "keygen_overlay.asm"),
                "image": str(build / "keygen_k14.bin"),
                "sha256": sha256(keygen),
                "reuse": "checked KeyGen Keccak-f[1600] and mutable work area",
            },
            "source_model": {
                "source": (
                    "completion timing of 256 alternating read-only BIOS "
                    "floppy reads between cylinders 0 and 39"
                ),
                "samples": 256,
                "measurement_clock": "PIT channel 0 latched before and after",
                "credited_entropy_bits": 0,
                "credit_status": (
                    "pending representative physical-drive min-entropy "
                    "characterization; emulator timing receives zero credit"
                ),
                "health_checks": [
                    "all 256 BIOS reads must succeed",
                    "maximum identical folded-interval run length 64",
                    "at least eight folded-interval symbol changes",
                ],
                "health_check_status": (
                    "provisional stuck-source mechanics gate, not an entropy "
                    "estimate or NIST SP 800-90B validation"
                ),
            },
            "output": {
                "bytes": 256,
                "initial_attempt": {
                    "range": "0x0700..0x0780",
                    "content": "ML-KEM d[32] || z[32] || random[32] || session[32]",
                },
                "resumption_attempt": {
                    "range": "0x0780..0x0800",
                    "content": "ML-KEM d[32] || z[32] || random[32] || session[32]",
                    "domain_separated": True,
                    "one_shot": True,
                },
            },
            "operational_mode": {
                "manual_operator_entry_required": False,
                "unattended_collection": True,
                "collection_before_first_network_transmission": True,
                "automated_security_credit_bits": 0,
                "physical_security_credit_pending": True,
            },
            "public_fixture_phase_present": False,
            "disk_writes": 0,
            "read_only_floppy_compatible": True,
        }
        manifest["secure_fo_checkpoint"] = {
            "enabled": True,
            "policy": (
                "actual live ML-KEM-768 FO re-encryption/serialized compare "
                "before exact-leaf authentication"
            ),
            "credential_unlock": False,
            "read_only_floppy_compatible": True,
            "required_nic_family": "NE2000",
            "marker_order": [
                "FO BEGIN",
                "KEM VALID",
                "AUTH BEGIN",
                "IDENTITY PASS",
                "PASS",
                "RESULT",
            ],
            "success_requires_exact_marker_order": True,
            "identity_only_is_success": False,
            "packaged_driver": {
                "path": str(args.ne_driver),
                "bytes": len(driver),
                "sha256": sha256(driver),
                "probe": str(build / "secure_ne_driver_probe.bin"),
                "probe_sha256": sha256(driver_probe),
                "byte_identical": driver_probe == driver,
                "remote_dma_write": f"0x{ne_buf_load:04x}",
                "remote_dma_read": f"0x{ne_buf_read:04x}",
            },
            "card_vault": {
                "pstop": f"0x{SECURE_NE_PSTOP:02x}",
                "ring": "0x4600..0x7300",
                "continuation_controller": {
                    "range": "0x7300..0x7400",
                    "bytes": len(secure_sym_controller),
                    "sha256": sha256(secure_sym_controller),
                    "preloaded_before_socket": True,
                },
                "live_ek": {
                    "range": "0x7400..0x78a0",
                    "bytes": SECURE_CARD_EK_LEN,
                    "captured_after_target_keygen": True,
                },
                "live_ciphertext": {
                    "range": "0x7900..0x7d40",
                    "bytes": SECURE_CARD_C_LEN,
                    "captured_before_candidate": True,
                },
                "handoff_a": "0x7e00..0x7f00",
                "handoff_b": "0x7f00..0x8000",
                "handoff_content": {
                    "initial_half": (
                        "m'[32] || G[64] || z[32], replacing the original "
                        "initial entropy after protected processing"
                    ),
                    "resumption_half": (
                        "domain-separated one-shot d[32] || z[32] || "
                        "random[32] || session[32]"
                    ),
                },
                "duplicates_compared_before_scatter": True,
                "initial_handoff_halves_zeroized_before_auth": True,
                "resumption_halves_preserved_until_consumed_or_failed": True,
                "boot_page_73_overwritten_by_controller_before_vault_read": True,
                "boot_stale_clear_pages": "0x74..0x7f",
                "boot_stale_clear_page_count": 12,
                "boot_all_stale_pages_attempted_before_vault_read": True,
                "boot_zeroization_failure_prevents_secure_progress": True,
                "failure_cleanup": {
                    "phase": "scrub_controller",
                    "phase_key": f"0x{key('scrub_controller'):04x}",
                    "destination": "0x2400",
                    "loads_from_read_only_floppy": True,
                    "load_is_best_effort": True,
                    "load_failure_card_erasure_claim": False,
                    "card_pages_attempted_after_successful_load": "0x73..0x7f",
                    "card_page_count": 13,
                    "all_card_pages_attempted_with_aggregate_failure": True,
                    "ne_tx_page_restored_after_every_attempt": True,
                    "local_erasure_before_card_writes": True,
                },
                "public_ek_ciphertext_retained": True,
                "volatile_only": True,
            },
            "fo_kernel": {
                "source": str(HERE / "fo_tail_kernel.asm"),
                "source_sha256": sha256(
                    (HERE / "fo_tail_kernel.asm").read_bytes()
                ),
                "image": str(build / "fo_tail_live.bin"),
                "image_bytes": len(fo),
                "image_sha256": sha256(fo),
                "runtime": "0x1800..0x2400 padded",
                "source_edited_by_live_integration": False,
                "public_callback_max_bytes": 384,
                "public_callback_bounds": {
                    "ek": SECURE_CARD_EK_LEN,
                    "ciphertext": SECURE_CARD_C_LEN,
                },
                "requires_status": "CF=0, AX=1",
                "requires_selected_k_matches_provisional": True,
            },
            "phase_transitions": {
                "secure_preconnect_controller": (
                    "0x2400..0x2600; survives KeyGen image/poly work and "
                    "relocates before padded HELLO self-overwrite"
                ),
                "card_continuation_destination": "0x3400..0x3500",
                "persistent_services_preserved": (
                    f"0x{PERSISTENT_SERVICES_START:04x}.."
                    f"0x{persistent_runtime_end:04x}"
                ),
                "fo_controller": "0x2400..0x2600",
                "failure_scrub_controller": "0x2400..0x2600",
                "fo_kernel_loader": "resident 0x10c4",
                "auth_controller": "0x3200",
                "auth_loader_after_fo": "resident 0x10c4 via low trampoline",
                "delta_loader_dead_after_fo": True,
            },
            "preconnect_failure_cleanup": {
                "relocated_runtime": (
                    f"0x{PRE_SYM_TRANSITION_START:04x}.."
                    f"0x{PRE_SYM_TRANSITION_START + len(pre_sym_transition):04x}"
                ),
                "local_secret_ranges": [
                    "0x0700..0x0800",
                    "0x1800..0x2337",
                    "0x3000..0x3400",
                    "0x3600..0x3b00",
                    "0x3b9c..0x3bdc",
                ],
                "full_card_handoffs": [
                    "0x7e00..0x7f00",
                    "0x7f00..0x8000",
                ],
                "both_card_writes_attempted": True,
                "ne_tx_page_restored": True,
                "hello_controller_read_staging": "0x3000..0x3200",
                "boot_fail_service_preserved_on_partial_read": True,
            },
            "tentative_ticket": {
                "source": "0x3b40..0x3c2e",
                "hold": "0x0700..0x07ee",
                "saved_after_zero_window": True,
                "restored_only_after_fo_valid_and_k_match": True,
                "psk_sentinel": "0x38b0..0x38d0",
                "psk_outside_parked_range": True,
                "psk_preserved_by_fo_kernel": True,
            },
            "secret_cleanup": {
                "low_handoffs": "0x0d00..0x0e00",
                "expected_k": "0x07ee..0x080e",
                "retired_high_message": "0x3a40..0x3a60",
                "card_initial_handoffs": [
                    "0x7e00..0x7e80",
                    "0x7f00..0x7f80",
                ],
                "card_resumption_handoffs": [
                    "0x7e80..0x7f00",
                    "0x7f80..0x8000",
                ],
                "initial_handoffs_scrubbed_before_auth": True,
                "resumption_handoffs_retained_before_auth": True,
                "failure_path_attempts_full_card_cleanup": True,
                "failure_scrub_phase_load_best_effort": True,
                "failure_scrub_load_failure_does_not_claim_card_erasure": True,
                "warm_restart_boot_overwrites_73_and_clears_74_through_7f_before_any_read": True,
            },
            "product_arena_context_writes": 0,
        }
    manifest_path = build / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print("live TLS 1.3 logical-K14 offline image: PASS")
    print(
        f"  core={len(core)} bytes ({cursor} sectors) "
        f"sha256={sha256(core)}"
    )
    print(f"  image={image} sha256={sha256(image_bytes)}")
    print(
        "  controllers="
        + ", ".join(f"{name}:{len(data)}B" for name, data in controller_data.items())
    )
    print(
        "  exact credential-free HEAD allowlist + credential literal gate=PASS; "
        "packaged files=SEED.SYS + SEED/DRIVERS/NE.DRV"
    )
    print(f"  BASIC sidecar={basic}")
    print(f"  manifest={manifest_path}")
    print("  VM/network launch=NOT PERFORMED")


if __name__ == "__main__":
    main()
