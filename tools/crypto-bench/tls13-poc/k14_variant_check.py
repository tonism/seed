#!/usr/bin/env python3
"""Execute the opt-in TLS13_POC_K14 layout and phase gates.

This is an offline gate.  It never starts 86Box.  K14 changes only each
phase's logical K ceiling and selected phase-local work addresses.  High
security state remains at 0x3600, so 0x3400..0x3600 is phase-owned reclaimed
space.  It is neither user arena nor reconnect-safe persistent storage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BOOT = ROOT / "targets/ibm_pc_5150/boot"
BUILD = ROOT / "build/crypto-bench/tls13-poc"

K_START = 0x1800
K_END = 0x3400
PHASE_RECLAIMED_START = 0x3400
PHASE_RECLAIMED_END = 0x3600
HIGH_START = 0x3600
LOW_END = 0x1000
SECTOR = 512

PHASES: dict[str, tuple[Path, tuple[str, ...]]] = {
    "keygen": (
        HERE / "keygen_overlay.asm",
        (
            "mlkem_keygen_overlay",
            "image_end",
            "poly_s",
            "poly_acc",
            "poc_k_start",
            "poc_k_end",
            "poc_k_extension_start",
            "poc_k_extension_end",
            "poc_high_start",
        ),
    ),
    "hello": (
        HERE / "hello_overlay.asm",
        (
            "hello_overlay_header",
            "hello_image_end",
            "hello_state_base",
            "hello_state_end",
            "poc_ticket_identity",
            "poc_ticket_identity_end",
            "hello_sha_work_start",
            "hello_sha_work_end",
            "poc_rx_frame_start",
            "poc_rx_frame_end",
        ),
    ),
    "candidate": (
        HERE / "mlkem_candidate_kernel.asm",
        (
            "mlkem_overlay_start",
            "mlkem_overlay_end",
            "mlkem_poly_u",
            "mlkem_poly_acc",
            "mlkem_keccak_state",
            "mlkem_keccak_work_end",
        ),
    ),
    "symmetric": (
        HERE / "tls13_sym_overlay.asm",
        (
            "sym_overlay_header",
            "sym_overlay_end",
            "sym_k_work_base",
            "sym_k_work_end",
            "sym_low_runtime_clear_start",
            "sym_low_runtime_clear_end",
            "sym_high_state_base",
            "sym_high_state_end",
        ),
    ),
    "fo_tail": (
        HERE / "fo_tail_kernel.asm",
        (
            "fo_overlay_start",
            "fo_overlay_end",
            "fo_keccak_state",
            "fo_keccak_work_end",
            "fo_poly_acc",
            "fo_low_work_end",
        ),
    ),
    "auth_exact": (
        HERE / "auth_p256_overlay.asm",
        (
            "auth_overlay_table",
            "auth_overlay_image_end",
            "auth_work_start",
            "auth_work_end",
        ),
    ),
    "auth_issuer": (
        HERE / "issuer_auth_overlay.asm",
        (
            "issuer_auth_overlay_table",
            "issuer_auth_overlay_image_end",
            "auth_work_start",
            "auth_work_end",
        ),
    ),
    "entropy": (
        HERE / "entropy_ratchet_overlay.asm",
        (
            "entropy_header",
            "entropy_overlay_end",
            "entropy_slot0",
            "entropy_high_start",
            "entropy_high_end",
        ),
    ),
}

CONTROLLER_PROBES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "hello": (
        (
            "POC_BUILD_HELLO_CONTROLLER",
            "POC_HELLO_FRESH_CHUNKS=6",
            "POC_HELLO_RESUMED_CHUNKS=8",
            "POC_HELLO_SERVER_CHUNKS=4",
        ),
        ("hello_server_stage", "hello_server_stage_sectors"),
    ),
    "candidate": (
        ("POC_BUILD_CANDIDATE_CONTROLLER",),
        ("candidate_handoff_start", "candidate_handoff_end"),
    ),
    "symmetric": (
        (
            "POC_BUILD_SYM_CONTROLLER",
            "POC_SYM_FLIGHT_BYTES=1926",
            "POC_SYM_FLIGHT_PREFIX=1889",
        ),
        (
            "sym_flight_stage",
            "sym_flight_stage_sectors",
            "sym_controller",
            "sym_controller_end",
        ),
    ),
    "fo_tail": (
        ("POC_BUILD_FO_CONTROLLER", "POC_FO_REQUESTS=17"),
        ("fo_stream_stage", "fo_stream_stage_sectors"),
    ),
}

EXACT: dict[str, dict[str, int]] = {
    "keygen": {
        "mlkem_keygen_overlay": 0x1800,
        "image_end": 0x2337,
        "poly_s": 0x3000,
        "poly_acc": 0x3200,
        "poc_k_start": K_START,
        "poc_k_end": K_END,
        "poc_k_extension_start": PHASE_RECLAIMED_START,
        "poc_k_extension_end": PHASE_RECLAIMED_END,
        "poc_high_start": HIGH_START,
    },
    "hello": {
        "hello_overlay_header": 0x1800,
        "hello_image_end": 0x2824,
        "hello_state_base": 0x0DC0,
        "hello_state_end": 0x0EFD,
        "poc_ticket_identity": 0x3000,
        "poc_ticket_identity_end": 0x30C0,
        "hello_sha_work_start": 0x30C0,
        "hello_sha_work_end": 0x33B8,
        "poc_rx_frame_start": 0x0700,
        "poc_rx_frame_end": 0x08B6,
    },
    "candidate": {
        "mlkem_overlay_start": 0x1800,
        "mlkem_overlay_end": 0x2041,
        "mlkem_poly_u": 0x3000,
        "mlkem_poly_acc": 0x3200,
        "mlkem_keccak_state": 0x3600,
        "mlkem_keccak_work_end": 0x37E8,
    },
    "symmetric": {
        "sym_overlay_header": 0x1800,
        "sym_overlay_end": 0x2FFE,
        "sym_k_work_base": 0x3000,
        "sym_k_work_end": 0x33F8,
        "sym_low_runtime_clear_start": 0x3510,
        "sym_low_runtime_clear_end": 0x355D,
        "sym_high_state_base": HIGH_START,
        "sym_high_state_end": 0x3C2E,
    },
    "fo_tail": {
        "fo_overlay_start": 0x1800,
        "fo_overlay_end": 0x230D,
        "fo_keccak_state": 0x3000,
        "fo_keccak_work_end": 0x31E8,
        "fo_poly_acc": 0x3200,
        "fo_low_work_end": 0x0FD0,
    },
    "entropy": {
        "entropy_header": 0x1800,
        "entropy_overlay_end": 0x201C,
        "entropy_slot0": 0x0700,
        "entropy_high_start": HIGH_START,
        "entropy_high_end": 0x394C,
    },
}


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def assemble_probe(
    name: str,
    source: Path,
    symbols: tuple[str, ...],
    directory: Path,
    *,
    k14: bool,
) -> tuple[bytes, dict[str, int]]:
    wrapper = directory / f"{name}_{'k14' if k14 else 'k15'}_probe.asm"
    binary = wrapper.with_suffix(".bin")
    emitted = "\n".join(f"    dw {symbol}" for symbol in symbols)
    wrapper.write_text(
        "bits 16\n"
        "cpu 8086\n"
        + ("%define TLS13_POC_K14 1\n" if k14 else "")
        + f'%include "{source.as_posix()}"\n'
        + "__k14_probe:\n"
        + emitted
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT}/",
            f"-I{HERE}/",
            f"-I{BOOT}/",
            "-o",
            str(binary),
            str(wrapper),
        ],
        cwd=ROOT,
        check=True,
    )
    blob = binary.read_bytes()
    probe_bytes = len(symbols) * 2
    if len(blob) <= probe_bytes:
        raise AssertionError(f"{name}: missing assembled phase image")
    image = blob[:-probe_bytes]
    values = struct.unpack(f"<{len(symbols)}H", blob[-probe_bytes:])
    return image, dict(zip(symbols, values, strict=True))


def assemble_controller_probe(
    name: str,
    defines: tuple[str, ...],
    symbols: tuple[str, ...],
    directory: Path,
) -> dict[str, int]:
    wrapper = directory / f"{name}_controller_probe.asm"
    binary = wrapper.with_suffix(".bin")
    emitted = "\n".join(f"    dw {symbol}" for symbol in symbols)
    rendered_defines = ""
    for define in defines:
        key, separator, value = define.partition("=")
        rendered_defines += (
            f"%define {key} {value}\n"
            if separator
            else f"%define {key} 1\n"
        )
    wrapper.write_text(
        "bits 16\n"
        "cpu 8086\n"
        "%define TLS13_POC_K14 1\n"
        + rendered_defines
        + f'%include "{(HERE / "poc_harness.asm").as_posix()}"\n'
        + "__controller_probe:\n"
        + emitted
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{ROOT}/",
            f"-I{HERE}/",
            f"-I{BOOT}/",
            "-o",
            str(binary),
            str(wrapper),
        ],
        cwd=ROOT,
        check=True,
    )
    blob = binary.read_bytes()
    probe_bytes = len(symbols) * 2
    if len(blob) <= probe_bytes:
        raise AssertionError(f"{name}: missing assembled controller")
    values = struct.unpack(f"<{len(symbols)}H", blob[-probe_bytes:])
    return dict(zip(symbols, values, strict=True))


def check_exact_symbols(name: str, symbols: dict[str, int]) -> None:
    for symbol, expected in EXACT.get(name, {}).items():
        actual = symbols[symbol]
        if actual != expected:
            raise AssertionError(
                f"{name}: {symbol}={actual:#06x}, expected {expected:#06x}"
            )


def check_intervals(snapshots: dict[str, dict[str, Any]]) -> None:
    intervals = {
        "keygen": (
            ("image", 0x1800, 0x2337),
            ("poly", 0x3000, 0x3200),
            ("accumulator", 0x3200, 0x3400),
        ),
        "hello": (
            ("low state", 0x0DC0, 0x0EFD),
            ("image", 0x1800, 0x2824),
            ("ticket", 0x3000, 0x30C0),
            ("SHA/HMAC", 0x30C0, 0x33B8),
        ),
        "candidate": (
            ("image", 0x1800, 0x2041),
            ("poly", 0x3000, 0x3200),
            ("accumulator", 0x3200, 0x3400),
        ),
        "symmetric": (
            ("image", 0x1800, 0x2FFE),
            ("K primitive work", 0x3000, 0x33F8),
            ("extension runtime", 0x3510, 0x355D),
        ),
        "fo_tail": (
            ("image", 0x1800, 0x230D),
            ("Keccak", 0x3000, 0x31E8),
            ("accumulator", 0x3200, 0x3400),
        ),
    }
    for phase, regions in intervals.items():
        ordered = sorted(regions, key=lambda item: item[1])
        for (left_name, _left_start, left_end), (
            right_name,
            right_start,
            _right_end,
        ) in zip(ordered, ordered[1:]):
            if left_end > right_start:
                raise AssertionError(
                    f"{phase}: {left_name} overlaps {right_name}"
                )
        for region, start, end in regions:
            if start >= K_START:
                in_logical_k = K_START <= start < end <= K_END
                in_extension = (
                    phase == "symmetric"
                    and region == "extension runtime"
                    and PHASE_RECLAIMED_START <= start < end <= PHASE_RECLAIMED_END
                )
                if not (in_logical_k or in_extension):
                    raise AssertionError(
                        f"{phase}: {region} escaped logical K14/extension"
                    )
            elif end > LOW_END:
                raise AssertionError(
                    f"{phase}: {region} crossed the resident nucleus"
                )
    for name, snapshot in snapshots.items():
        sectors = snapshot["sectors"]
        if sectors > 14:
            raise AssertionError(f"{name}: {sectors} sectors exceed K14")
    if snapshots["auth_exact"]["sectors"] > 13:
        raise AssertionError("exact authentication no longer fits 13 sectors")
    if snapshots["auth_issuer"]["sectors"] > 14:
        raise AssertionError("issuer authentication no longer fits 14 sectors")
    if snapshots["hello"]["sectors"] != 9:
        raise AssertionError("HELLO no longer has the current 9-sector geometry")
    if snapshots["symmetric"]["sectors"] != 12:
        raise AssertionError("symmetric preload no longer has 12 sectors")


def ranges_overlap(
    left: tuple[int, int],
    right: tuple[int, int],
) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def derive_sector_extent(
    name: str,
    start: int,
    sectors: int,
) -> tuple[int, int]:
    if not 0 <= start < 0x10000:
        raise AssertionError(f"{name}: invalid start {start:#06x}")
    if sectors <= 0:
        raise AssertionError(f"{name}: sector count must be positive")
    end = start + sectors * SECTOR
    if end > 0x10000:
        raise AssertionError(f"{name}: sector write wraps real-mode memory")
    return start, end


def describe_sector_extent(
    extent: tuple[int, int],
    sectors: int,
) -> dict[str, Any]:
    return {
        "start": f"0x{extent[0]:04x}",
        "end": f"0x{extent[1]:04x}",
        "sectors_per_write": sectors,
        "bytes_per_write": extent[1] - extent[0],
    }


def validate_ordered_write_lifetimes(
    events: tuple[dict[str, Any], ...],
    *,
    preloaded_suffix: tuple[int, int],
    candidate_handoff: tuple[int, int],
    phase_owned_space: tuple[int, int],
) -> list[dict[str, Any]]:
    """Reject external writes that cross a simultaneously live K14 lifetime."""

    preloaded_suffix_live = False
    candidate_live = False
    phase_runtime_live = False
    trace: list[dict[str, Any]] = []
    saw_candidate_lifetime = False
    saw_runtime_lifetime = False

    for event in events:
        write = event.get("write")
        write_class = event.get("write_class")
        if write is not None:
            if (
                preloaded_suffix_live
                and write_class == "sector"
                and ranges_overlap(write, preloaded_suffix)
            ):
                raise AssertionError(
                    f"{event['name']}: sector write overlaps the live "
                    "preloaded symmetric suffix"
                )
            if (
                candidate_live
                and write_class in {"rx", "sector"}
                and ranges_overlap(write, candidate_handoff)
            ):
                raise AssertionError(
                    f"{event['name']}: RX/stage write overlaps the live "
                    "candidate handoff"
                )
            if (
                phase_runtime_live
                and write_class == "sector"
                and ranges_overlap(write, phase_owned_space)
            ):
                raise AssertionError(
                    f"{event['name']}: phase-owned-space write occurs after "
                    "sym_init while the symmetric phase runtime is live"
                )

        trace.append(
            {
                "event": event["name"],
                "write": (
                    None
                    if write is None
                    else {
                        "start": f"0x{write[0]:04x}",
                        "end": f"0x{write[1]:04x}",
                        "class": write_class,
                    }
                ),
                "preloaded_suffix_live": preloaded_suffix_live,
                "candidate_handoff_live": candidate_live,
                "phase_runtime_live": phase_runtime_live,
            }
        )

        if "preloaded_suffix_live_after" in event:
            preloaded_suffix_live = event["preloaded_suffix_live_after"]
        if "candidate_live_after" in event:
            candidate_live = event["candidate_live_after"]
            saw_candidate_lifetime = True
        if "phase_runtime_live_after" in event:
            phase_runtime_live = event["phase_runtime_live_after"]
            saw_runtime_lifetime = True

    if preloaded_suffix_live:
        raise AssertionError("preloaded symmetric suffix lifetime never ended")
    if candidate_live:
        raise AssertionError("candidate handoff lifetime never ended")
    if phase_runtime_live:
        raise AssertionError("symmetric phase runtime lifetime never ended")
    if not saw_candidate_lifetime:
        raise AssertionError("candidate handoff lifetime was not modeled")
    if not saw_runtime_lifetime:
        raise AssertionError("symmetric phase runtime lifetime was not modeled")
    return trace


def check_full_sector_io_staging(
    snapshots: dict[str, dict[str, Any]],
    controllers: dict[str, dict[str, int]],
) -> dict[str, Any]:
    """Prove each BIOS-sized cold read is disjoint from simultaneously live state."""

    stage_sector_counts = {
        "hello_server": controllers["hello"]["hello_server_stage_sectors"],
        "symmetric_flight": controllers["symmetric"][
            "sym_flight_stage_sectors"
        ],
        "fo_public_stream": controllers["fo_tail"]["fo_stream_stage_sectors"],
    }
    phase_stages = {
        "hello_server": derive_sector_extent(
            "hello_server",
            controllers["hello"]["hello_server_stage"],
            stage_sector_counts["hello_server"],
        ),
        "symmetric_flight": derive_sector_extent(
            "symmetric_flight",
            controllers["symmetric"]["sym_flight_stage"],
            stage_sector_counts["symmetric_flight"],
        ),
        "fo_public_stream": derive_sector_extent(
            "fo_public_stream",
            controllers["fo_tail"]["fo_stream_stage"],
            stage_sector_counts["fo_public_stream"],
        ),
    }
    candidate_start = controllers["candidate"]["candidate_handoff_start"]
    candidate_end = controllers["candidate"]["candidate_handoff_end"]
    candidate_handoff = (candidate_start, candidate_end)
    hello_symbols = snapshots["hello"]["symbols"]
    rx_frame = (
        int(hello_symbols["poc_rx_frame_start"], 16),
        int(hello_symbols["poc_rx_frame_end"], 16),
    )
    symmetric_symbols = snapshots["symmetric"]["symbols"]
    runtime_start = int(
        symmetric_symbols["sym_low_runtime_clear_start"], 16
    )
    runtime_end = int(symmetric_symbols["sym_low_runtime_clear_end"], 16)
    runtime = (runtime_start, runtime_end)
    hello_dirty_end = K_START + snapshots["hello"]["sectors"] * SECTOR
    symmetric_preload_end = (
        K_START + snapshots["symmetric"]["sectors"] * SECTOR
    )
    preloaded_suffix = (hello_dirty_end, symmetric_preload_end)
    live_ranges = {
        "hello_server": (
            ("raw ciphertext", 0x08C0, 0x0D00),
            ("HELLO state", 0x0DC0, 0x0EFD),
            (
                "preloaded symmetric immutable suffix",
                preloaded_suffix[0],
                preloaded_suffix[1],
            ),
            ("high KeyGen state", 0x3600, 0x3B00),
        ),
        "symmetric_flight": (
            ("candidate handoff", candidate_start, candidate_end),
            ("retained raw ciphertext", 0x08C0, 0x0D00),
            ("symmetric phase runtime", runtime_start, runtime_end),
        ),
        "fo_public_stream": (
            ("FO Keccak", 0x3000, 0x31E8),
            ("FO accumulator", 0x3200, 0x3400),
            ("saved ciphertext", 0x3600, 0x3A40),
        ),
    }
    for phase, (stage_start, stage_end) in phase_stages.items():
        if stage_end - stage_start != stage_sector_counts[phase] * SECTOR:
            raise AssertionError(f"{phase}: derived staging extent is inconsistent")
        for name, live_start, live_end in live_ranges[phase]:
            if ranges_overlap(
                (stage_start, stage_end),
                (live_start, live_end),
            ):
                raise AssertionError(f"{phase}: staging overlaps live {name}")
    expected_stages = {
        "hello_server": (0x3400, 0x3600),
        "symmetric_flight": (0x0E00, 0x1000),
        "fo_public_stream": (0x3400, 0x3600),
    }
    if phase_stages != expected_stages:
        raise AssertionError(
            f"K14 cold-controller staging geometry drifted: {phase_stages}"
        )
    if candidate_end - candidate_start != 128:
        raise AssertionError("candidate handoff is not exact m'||G||z")
    if preloaded_suffix != (0x2A00, 0x3000):
        raise AssertionError(
            "HELLO no longer preserves the exact preloaded SYM suffix"
        )
    if not ranges_overlap(candidate_handoff, rx_frame):
        raise AssertionError(
            "candidate handoff no longer records the known live-RX conflict"
        )
    if (
        controllers["symmetric"]["sym_controller"] != PHASE_RECLAIMED_START
        or controllers["symmetric"]["sym_controller_end"] > runtime_start
    ):
        raise AssertionError(
            "symmetric controller reaches its phase-owned runtime tail"
        )

    sym_controller_bytes = (
        controllers["symmetric"]["sym_controller_end"]
        - controllers["symmetric"]["sym_controller"]
    )
    if sym_controller_bytes <= 0:
        raise AssertionError("symmetric controller content is empty")
    sym_controller_sectors = (sym_controller_bytes + SECTOR - 1) // SECTOR
    sym_controller_install = derive_sector_extent(
        "symmetric_controller_install",
        controllers["symmetric"]["sym_controller"],
        sym_controller_sectors,
    )
    if sym_controller_install != (PHASE_RECLAIMED_START, PHASE_RECLAIMED_END):
        raise AssertionError(
            "symmetric controller padded install is not the reclaimed phase sector"
        )
    if not ranges_overlap(sym_controller_install, runtime):
        raise AssertionError(
            "symmetric controller install no longer makes ordering safety relevant"
        )

    preload = derive_sector_extent(
        "symmetric_preload",
        K_START,
        snapshots["symmetric"]["sectors"],
    )
    keygen_load = derive_sector_extent(
        "keygen_phase_load",
        K_START,
        snapshots["keygen"]["sectors"],
    )
    hello_load = derive_sector_extent(
        "hello_phase_load",
        K_START,
        snapshots["hello"]["sectors"],
    )
    candidate_load = derive_sector_extent(
        "candidate_phase_load",
        K_START,
        snapshots["candidate"]["sectors"],
    )
    sym_restore = derive_sector_extent(
        "symmetric_dirty_prefix_restore",
        K_START,
        snapshots["hello"]["sectors"],
    )
    fo_load = derive_sector_extent(
        "fo_phase_load",
        K_START,
        snapshots["fo_tail"]["sectors"],
    )
    events: tuple[dict[str, Any], ...] = (
        {
            "name": "symmetric_preload",
            "write": preload,
            "write_class": "sector",
            "preloaded_suffix_live_after": True,
        },
        {
            "name": "keygen_phase_load",
            "write": keygen_load,
            "write_class": "sector",
        },
        {
            "name": "hello_phase_load",
            "write": hello_load,
            "write_class": "sector",
        },
        {
            "name": "hello_server_fixture_stage",
            "write": phase_stages["hello_server"],
            "write_class": "sector",
        },
        {
            "name": "candidate_phase_load",
            "write": candidate_load,
            "write_class": "sector",
        },
        {
            "name": "candidate_handoff_publish",
            "write": candidate_handoff,
            "write_class": "handoff",
            "candidate_live_after": True,
        },
        {
            "name": "symmetric_dirty_prefix_restore",
            "write": sym_restore,
            "write_class": "sector",
            "preloaded_suffix_live_after": False,
        },
        {
            "name": "symmetric_controller_install",
            "write": sym_controller_install,
            "write_class": "sector",
        },
        {
            "name": "sym_init",
            "write": None,
            "write_class": None,
            "phase_runtime_live_after": True,
        },
        {
            "name": "symmetric_flight_stage",
            "write": phase_stages["symmetric_flight"],
            "write_class": "sector",
        },
        {
            "name": "client_finished_fixture_stage",
            "write": phase_stages["symmetric_flight"],
            "write_class": "sector",
        },
        {
            "name": "sym_complete",
            "write": None,
            "write_class": None,
            "phase_runtime_live_after": False,
        },
        {
            "name": "candidate_rehome",
            "write": None,
            "write_class": None,
            "candidate_live_after": False,
        },
        {
            "name": "fo_phase_load",
            "write": fo_load,
            "write_class": "sector",
        },
        {
            "name": "fo_public_stream_stage",
            "write": phase_stages["fo_public_stream"],
            "write_class": "sector",
        },
    )
    trace = validate_ordered_write_lifetimes(
        events,
        preloaded_suffix=preloaded_suffix,
        candidate_handoff=candidate_handoff,
        phase_owned_space=(PHASE_RECLAIMED_START, PHASE_RECLAIMED_END),
    )

    sym_init_index = next(
        index for index, event in enumerate(events) if event["name"] == "sym_init"
    )
    bad_phase_space_events = list(events)
    bad_phase_space_events.insert(
        sym_init_index + 1,
        {
            "name": "negative_late_phase_owned_sector_write",
            "write": phase_stages["fo_public_stream"],
            "write_class": "sector",
        },
    )
    try:
        validate_ordered_write_lifetimes(
            tuple(bad_phase_space_events),
            preloaded_suffix=preloaded_suffix,
            candidate_handoff=candidate_handoff,
            phase_owned_space=(PHASE_RECLAIMED_START, PHASE_RECLAIMED_END),
        )
    except AssertionError as error:
        if "after sym_init" not in str(error):
            raise
    else:
        raise AssertionError(
            "negative control: late phase-owned-space write was accepted"
        )

    bad_rx_events = list(events)
    bad_rx_events.insert(
        sym_init_index + 1,
        {
            "name": "negative_live_rx_write",
            "write": rx_frame,
            "write_class": "rx",
        },
    )
    try:
        validate_ordered_write_lifetimes(
            tuple(bad_rx_events),
            preloaded_suffix=preloaded_suffix,
            candidate_handoff=candidate_handoff,
            phase_owned_space=(PHASE_RECLAIMED_START, PHASE_RECLAIMED_END),
        )
    except AssertionError as error:
        if "candidate handoff" not in str(error):
            raise
    else:
        raise AssertionError(
            "negative control: live RX/candidate overlap was accepted"
        )

    return {
        "preloaded_symmetric_suffix": {
            "start": f"0x{preloaded_suffix[0]:04x}",
            "end": f"0x{preloaded_suffix[1]:04x}",
            "bytes": preloaded_suffix[1] - preloaded_suffix[0],
            "live_during_hello": True,
        },
        "candidate_handoff": {
            "start": f"0x{candidate_handoff[0]:04x}",
            "end": f"0x{candidate_handoff[1]:04x}",
            "bytes": candidate_handoff[1] - candidate_handoff[0],
        },
        "live_rx_frame": {
            "start": f"0x{rx_frame[0]:04x}",
            "end": f"0x{rx_frame[1]:04x}",
            "overlaps_candidate_handoff": True,
        },
        "symmetric_phase_runtime": {
            "start": f"0x{runtime[0]:04x}",
            "end": f"0x{runtime[1]:04x}",
            "bytes": runtime[1] - runtime[0],
        },
        "derived_full_sector_writes": {
            name: describe_sector_extent(
                extent,
                stage_sector_counts[name],
            )
            for name, extent in phase_stages.items()
        }
        | {
            "symmetric_controller_install": describe_sector_extent(
                sym_controller_install,
                sym_controller_sectors,
            )
        },
        "ordered_events": trace,
        "negative_controls": {
            "phase_owned_sector_after_sym_init_rejected": True,
            "rx_write_during_candidate_lifetime_rejected": True,
        },
    }


def run_gate(command: list[str], *, k14: bool = False) -> str:
    environment = os.environ.copy()
    if k14:
        environment["TLS13_POC_K14"] = "1"
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
    )
    if completed.returncode:
        raise AssertionError(
            f"gate failed ({' '.join(command)}):\n"
            f"{completed.stdout}{completed.stderr}"
        )
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    snapshots: dict[str, dict[str, Any]] = {}
    controller_symbols: dict[str, dict[str, int]] = {}
    with tempfile.TemporaryDirectory(prefix="seed-tls13-k14-") as temp:
        directory = Path(temp)
        for name, (source, symbols) in PHASES.items():
            image, values = assemble_probe(
                name, source, symbols, directory, k14=True
            )
            default_image, _default_values = assemble_probe(
                name, source, symbols, directory, k14=False
            )
            check_exact_symbols(name, values)
            sectors = (len(image) + SECTOR - 1) // SECTOR
            snapshots[name] = {
                "bytes": len(image),
                "sectors": sectors,
                "rounded_bytes": sectors * SECTOR,
                "image_sha256": sha256(image),
                "symbols": {key: f"0x{value:04x}" for key, value in values.items()},
            }
            if name in {"auth_exact", "auth_issuer", "entropy"}:
                if image != default_image:
                    raise AssertionError(
                        f"{name}: K14 changed an address-independent phase image"
                    )
        for name, (defines, symbols) in CONTROLLER_PROBES.items():
            controller_symbols[name] = assemble_controller_probe(
                name,
                defines,
                symbols,
                directory,
            )

    check_intervals(snapshots)
    memory_lifetimes = check_full_sector_io_staging(
        snapshots,
        controller_symbols,
    )

    python = os.environ.get("PYTHON", "python3")
    functional = {
        "keygen": run_gate(
            [python, str(HERE / "check_keygen_overlay.py")], k14=True
        ),
        "candidate": run_gate(
            [python, str(HERE / "mlkem_candidate_check.py")], k14=True
        ),
        "hello": run_gate(
            [python, str(HERE / "hello_check.py")], k14=True
        ),
        "symmetric": run_gate(
            [python, str(HERE / "check_tls13_sym_overlay.py")], k14=True
        ),
        "fo_tail": run_gate(
            [python, str(HERE / "fo_tail_check.py")], k14=True
        ),
        "auth_exact": run_gate(
            [python, str(HERE / "auth_p256_check.py")]
        ),
        "auth_issuer": run_gate(
            [python, str(HERE / "issuer_auth_check.py")]
        ),
        "entropy": run_gate(
            [python, str(HERE / "entropy_ratchet_check.py")]
        ),
    }

    k14_build = run_gate(
        [python, str(HERE / "build_poc_harness.py"), "--k14"]
    )
    if "variant=K14; resident=2048 bytes" not in k14_build:
        raise AssertionError("K14 phase container lost its four-sector prefix")
    if "sym-delta-restore=9/12 sectors" not in k14_build:
        raise AssertionError("K14 container lost the current 9-sector SYM delta")
    k14_container = BUILD / "poc_harness_k14.bin"
    if not k14_container.is_file() or len(k14_container.read_bytes()[:0x800]) != 0x800:
        raise AssertionError("K14 container artifact is missing its resident prefix")

    # Restore the default build directory after the opt-in build, then prove
    # the retained K14 artifact remains independently available.
    default_build = run_gate(
        [python, str(HERE / "build_poc_harness.py")]
    )
    if "variant=K15; resident=2048 bytes" not in default_build:
        raise AssertionError("default phase container did not rebuild as K15")
    if not k14_container.is_file():
        raise AssertionError("default rebuild removed the retained K14 container")

    result = {
        "schema": "seed-tls13-poc-k14-variant-v1",
        "status": "pass",
        "scope": "offline optional K14 phase implementation; no 86Box run",
        "limitations": {
            "candidate_handoff_overlaps_live_rx_frame": True,
            "fixture_chain_avoids_rx_by_staging_at_0x0e00": True,
            "live_controller_reclaimed_space_reload_after_sym_init_is_unsafe": True,
            "secure_live_network_floor_proven": False,
        },
        "logical_k": {
            "start": "0x1800",
            "end": "0x3400",
            "bytes": 14 * SECTOR,
        },
        "phase_owned_reclaimed_space": {
            "start": "0x3400",
            "end": "0x3600",
            "bytes": 512,
            "user_arena": False,
            "reconnect_safe": False,
            "contiguous_with_product_arena_context": False,
        },
        "unchanged_high_security_start": "0x3600",
        "delta_restore": {
            "symmetric_preload_sectors": 12,
            "hello_dirty_prefix_sectors": 9,
            "restore_sectors": 9,
        },
        "phase_container": {
            "path": str(k14_container.relative_to(ROOT)),
            "bytes": k14_container.stat().st_size,
            "sectors": (k14_container.stat().st_size + 511) // 512,
            "resident_prefix_bytes": 2048,
            "sha256": sha256(k14_container.read_bytes()),
        },
        "phases": snapshots,
        "controller_symbols": {
            name: {
                key: f"0x{value:04x}"
                for key, value in values.items()
            }
            for name, values in controller_symbols.items()
        },
        "memory_lifetimes": memory_lifetimes,
        "gates": {
            "exact_symbol_addresses": True,
            "phase_interval_nonoverlap": True,
            "full_sector_io_staging_nonoverlap": True,
            "derived_full_sector_write_geometry": True,
            "preloaded_symmetric_suffix_live_through_HELLO": True,
            "ordered_phase_owned_sector_writes_avoid_live_sym_runtime": True,
            "ordered_RX_and_stage_writes_avoid_live_candidate_handoff": True,
            "unsafe_lifetime_order_negative_controls_rejected": True,
            "sector_rounded_images_end_at_or_below_0x3400": True,
            "exact_auth_at_most_13_sectors": True,
            "issuer_auth_at_most_14_sectors": True,
            "address_independent_auth_and_entropy_images_match_K15": True,
            "functional_oracles": sorted(functional),
            "return_and_stack_contracts": True,
            "write_set_and_protected_band_sentinels": True,
            "full_four_sector_phase_container": True,
            "default_K15_container_rebuilt_after_K14": True,
            "86box_started": False,
        },
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        destination = args.json_out
        if not destination.is_absolute():
            destination = ROOT / destination
        destination.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
