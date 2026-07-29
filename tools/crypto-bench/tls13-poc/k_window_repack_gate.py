#!/usr/bin/env python3
"""Mechanically gate 14- and 13-sector TLS 1.3 PoC K layouts.

This is a feasibility gate, not a source transformer.  It assembles the
current phase sources through small temporary probe wrappers, obtains exact
image and external-work symbols from NASM, and applies those measured sizes to
the proposed K14 and K13 interval ledgers.  K13's one exact, source-derived
symmetric overflow is recorded as infeasible; any changed/additional range
blocker, overlap, protected-band crossing, or lost low-memory handoff makes the
gate fail.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BOOT = ROOT / "targets" / "ibm_pc_5150" / "boot"
CHECKER = Path(__file__).resolve()
RESULTS = HERE / "k_window_repack_results.json"

K_START = 0x1800
K14_END = 0x3400
K13_END = 0x3200
LOW_START = 0x0700
LOW_END = 0x1000
RESIDENT_START = 0x1000
DRIVER_START = 0x1600
HIGH_START = 0x3600
ATTEMPT_END = 0x3C9C
RECONNECT_START = 0x3C9C
ESC_START = 0x3DE6
PRODUCT_POOL_START = 0x3E40
STACK_GUARD_START = 0x3F00
RAM_END = 0x4000
SECTOR = 512

EXPECTED_SYMMETRIC_IMAGE_BYTES = 6142
EXPECTED_SYMMETRIC_IMAGE_END = 0x2FFE
EXPECTED_SYMMETRIC_K_WORK_BASE = 0x3000
EXPECTED_SYMMETRIC_K_WORK_END = 0x33F8
EXPECTED_K14_SYMMETRIC_MARGIN = 8
EXPECTED_K13_SYMMETRIC_RETAINED_END = 0x3238
EXPECTED_K13_SYMMETRIC_OVERFLOW = 56

SOURCES = {
    "keygen": HERE / "keygen_overlay.asm",
    "hello": HERE / "hello_overlay.asm",
    "candidate": HERE / "mlkem_candidate_kernel.asm",
    "symmetric": HERE / "tls13_sym_overlay.asm",
    "fo_tail": HERE / "fo_tail_kernel.asm",
    "auth": HERE / "auth_p256_overlay.asm",
    "entropy": HERE / "entropy_ratchet_overlay.asm",
}

PROBES = {
    "keygen": (
        "mlkem_keygen_overlay",
        "image_end",
        "poly_s",
        "poly_acc",
        "keygen_ek",
        "keygen_s_hat0",
        "keygen_s_hat2",
        "keygen_input",
        "poc_hello_handoff_end",
        "poc_low_scratch_start",
        "poc_low_scratch_end",
        "poc_resident_start",
        "poc_nic_driver_slot",
        "poc_k_start",
        "poc_k_end",
        "poc_high_start",
        "poc_high_end",
        "poc_attempt_cache_start",
        "poc_attempt_cache_end",
        "poc_reconnect_state_start",
        "poc_esc_handler_start",
        "poc_product_pool_start",
        "poc_arena_start",
        "poc_context_start",
        "poc_stack_guard_start",
        "poc_ram_end",
    ),
    "hello": (
        "hello_overlay_header",
        "hello_image_end",
        "hello_state_base",
        "hello_state_end",
        "poc_ticket_identity",
        "poc_ticket_identity_end",
        "hello_sha_work_start",
        "hello_sha_work_end",
        "poc_hello_handoff_start",
        "poc_hello_handoff_end",
        "hello_attempt_used_end",
    ),
    "candidate": (
        "mlkem_overlay_start",
        "mlkem_overlay_end",
        "mlkem_poly_u",
        "mlkem_poly_acc",
        "mlkem_keccak_state",
        "mlkem_keccak_work_end",
        "mlkem_message",
        "mlkem_candidate_g",
        "mlkem_candidate_z",
    ),
    "symmetric": (
        "sym_overlay_header",
        "sym_overlay_end",
        "sym_k_work_base",
        "sym_k_work_end",
        "hmac_prepared_inner_state",
        "sym_low_runtime_clear_start",
        "sym_low_runtime_clear_end",
        "sym_hello_context_end",
        "sym_high_state_base",
        "sym_high_state_end",
    ),
    "fo_tail": (
        "fo_overlay_start",
        "fo_overlay_end",
        "fo_keccak_state",
        "fo_keccak_work_end",
        "fo_poly_acc",
        "fo_low_work_end",
        "fo_message",
        "fo_candidate_k",
        "fo_z",
    ),
    "auth": (
        "auth_overlay_table",
        "auth_overlay_image_end",
        "auth_work_start",
        "auth_work_end",
        "auth_input_guard_lo",
        "auth_input_end",
        "auth_input_guard_hi",
    ),
    "entropy": (
        "entropy_header",
        "entropy_overlay_end",
        "entropy_slot0",
        "entropy_slot1",
        "entropy_supplement",
        "entropy_timing_sample",
        "entropy_write_record",
        "entropy_readback",
        "entropy_high_start",
        "entropy_high_end",
    ),
}


@dataclass(frozen=True)
class Snapshot:
    name: str
    source: Path
    image: bytes
    listing: str
    symbols: dict[str, int]

    @property
    def image_start(self) -> int:
        return next(iter(self.symbols.values()))

    @property
    def image_end(self) -> int:
        return list(self.symbols.values())[1]


@dataclass(frozen=True)
class Region:
    name: str
    start: int
    end: int
    space: str
    old_start: int | None = None
    old_end: int | None = None

    @property
    def size(self) -> int:
        return self.end - self.start

    def json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "space": self.space,
            "start": hex16(self.start),
            "end": hex16(self.end),
            "bytes": self.size,
        }
        if self.old_start is not None and self.old_end is not None:
            result["move"] = {
                "from": f"{hex16(self.old_start)}..{hex16(self.old_end)}",
                "to": f"{hex16(self.start)}..{hex16(self.end)}",
                "delta": self.start - self.old_start,
            }
        return result


def hex16(value: int) -> str:
    return f"0x{value:04x}"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rounded(value: int, quantum: int) -> int:
    return (value + quantum - 1) // quantum * quantum


def assemble_snapshot(
    name: str, source: Path, symbols: tuple[str, ...], directory: Path
) -> Snapshot:
    wrapper = directory / f"{name}_probe.asm"
    binary = directory / f"{name}_probe.bin"
    listing = directory / f"{name}_probe.lst"
    emitted = "\n".join(f"    dw {symbol}" for symbol in symbols)
    wrapper.write_text(
        "bits 16\n"
        "cpu 8086\n"
        f'%include "{source.as_posix()}"\n'
        "__k_window_probe:\n"
        f"{emitted}\n"
    )
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            f"-I{HERE}/",
            f"-I{ROOT}/",
            f"-I{BOOT}/",
            "-l",
            str(listing),
            "-o",
            str(binary),
            str(wrapper),
        ],
        cwd=ROOT,
        check=True,
    )
    blob = binary.read_bytes()
    probe_bytes = 2 * len(symbols)
    if len(blob) <= probe_bytes:
        raise AssertionError(f"{name}: NASM probe did not contain an image")
    image = blob[:-probe_bytes]
    values = struct.unpack(f"<{len(symbols)}H", blob[-probe_bytes:])
    symbol_values = dict(zip(symbols, values, strict=True))
    listing_text = listing.read_text()
    for symbol in symbols:
        if symbol not in listing_text:
            raise AssertionError(f"{name}: {symbol} absent from NASM listing")
    if symbol_values[symbols[0]] != K_START:
        raise AssertionError(
            f"{name}: image start {symbol_values[symbols[0]]:#06x} != K"
        )
    if symbol_values[symbols[1]] - K_START != len(image):
        raise AssertionError(
            f"{name}: probed image end does not match {len(image)} output bytes"
        )
    return Snapshot(name, source, image, listing_text, symbol_values)


def assert_layout_contract(snapshots: dict[str, Snapshot]) -> None:
    """Reject drift in the product bands which this ledger promises to keep."""

    keygen = snapshots["keygen"].symbols
    hello = snapshots["hello"].symbols
    candidate = snapshots["candidate"].symbols
    symmetric = snapshots["symmetric"].symbols
    fo = snapshots["fo_tail"].symbols
    auth = snapshots["auth"].symbols
    entropy = snapshots["entropy"].symbols

    exact = {
        "keygen public ek": (keygen["keygen_ek"], 0x08C0),
        "keygen high output": (keygen["keygen_s_hat0"], HIGH_START),
        "keygen input": (keygen["keygen_input"], 0x3B9C),
        "hello handoff start": (hello["poc_hello_handoff_start"], 0x0D00),
        "hello handoff end": (hello["poc_hello_handoff_end"], 0x0DAB),
        "hello attempt end": (hello["hello_attempt_used_end"], 0x3C02),
        "candidate high work": (candidate["mlkem_keccak_state"], HIGH_START),
        "symmetric handoff end": (symmetric["sym_hello_context_end"], 0x0DAB),
        "symmetric high start": (symmetric["sym_high_state_base"], HIGH_START),
        "symmetric image end": (
            snapshots["symmetric"].image_end,
            EXPECTED_SYMMETRIC_IMAGE_END,
        ),
        "symmetric K work base": (
            symmetric["sym_k_work_base"],
            EXPECTED_SYMMETRIC_K_WORK_BASE,
        ),
        "symmetric K work end": (
            symmetric["sym_k_work_end"],
            EXPECTED_SYMMETRIC_K_WORK_END,
        ),
        "symmetric K13 retained end": (
            symmetric["hmac_prepared_inner_state"],
            EXPECTED_K13_SYMMETRIC_RETAINED_END,
        ),
        "FO low work end": (fo["fo_low_work_end"], 0x0FD0),
        "auth low start": (auth["auth_work_start"], LOW_START),
        "auth input guard": (auth["auth_input_guard_lo"], 0x3B9C),
        "entropy low slot": (entropy["entropy_slot0"], LOW_START),
        "entropy high start": (entropy["entropy_high_start"], HIGH_START),
        "low scratch start": (keygen["poc_low_scratch_start"], LOW_START),
        "low scratch end": (keygen["poc_low_scratch_end"], LOW_END),
        "resident start": (keygen["poc_resident_start"], RESIDENT_START),
        "NIC driver start": (keygen["poc_nic_driver_slot"], DRIVER_START),
        "current K start": (keygen["poc_k_start"], K_START),
        "current K end": (keygen["poc_k_end"], HIGH_START),
        "high start": (keygen["poc_high_start"], HIGH_START),
        "high end": (keygen["poc_high_end"], 0x3B9C),
        "attempt start": (keygen["poc_attempt_cache_start"], 0x3B9C),
        "attempt end": (keygen["poc_attempt_cache_end"], ATTEMPT_END),
        "reconnect start": (
            keygen["poc_reconnect_state_start"],
            RECONNECT_START,
        ),
        "ESC start": (keygen["poc_esc_handler_start"], ESC_START),
        "product pool": (
            keygen["poc_product_pool_start"],
            PRODUCT_POOL_START,
        ),
        "arena start": (keygen["poc_arena_start"], PRODUCT_POOL_START),
        "context start": (keygen["poc_context_start"], 0x3EA0),
        "stack guard": (
            keygen["poc_stack_guard_start"],
            STACK_GUARD_START,
        ),
        "RAM end": (keygen["poc_ram_end"], RAM_END),
    }
    failures = [
        f"{label}: {actual:#06x} != {expected:#06x}"
        for label, (actual, expected) in exact.items()
        if actual != expected
    ]
    if failures:
        raise AssertionError("protected layout drift:\n  " + "\n  ".join(failures))

    if len(snapshots["symmetric"].image) != EXPECTED_SYMMETRIC_IMAGE_BYTES:
        raise AssertionError(
            "symmetric image size drift: "
            f"{len(snapshots['symmetric'].image)} != "
            f"{EXPECTED_SYMMETRIC_IMAGE_BYTES}"
        )
    if K14_END - symmetric["sym_k_work_end"] != EXPECTED_K14_SYMMETRIC_MARGIN:
        raise AssertionError(
            "K14 symmetric margin drift: "
            f"{K14_END - symmetric['sym_k_work_end']} != "
            f"{EXPECTED_K14_SYMMETRIC_MARGIN}"
        )
    k13_symmetric_overflow = (
        symmetric["hmac_prepared_inner_state"] - K13_END
    )
    if k13_symmetric_overflow != EXPECTED_K13_SYMMETRIC_OVERFLOW:
        raise AssertionError(
            "K13 symmetric blocker drift: "
            f"{k13_symmetric_overflow} != "
            f"{EXPECTED_K13_SYMMETRIC_OVERFLOW}"
        )

    if keygen["poly_acc"] - keygen["poly_s"] != SECTOR:
        raise AssertionError("KeyGen polynomial work is no longer two sectors")
    if candidate["mlkem_poly_acc"] - candidate["mlkem_poly_u"] != SECTOR:
        raise AssertionError("candidate polynomial work is no longer two sectors")
    if hello["poc_ticket_identity_end"] - hello["poc_ticket_identity"] != 192:
        raise AssertionError("HELLO ticket identity is no longer 192 bytes")
    if symmetric["sym_high_state_end"] > ATTEMPT_END:
        raise AssertionError("symmetric high state reaches reconnect state")
    if entropy["entropy_high_end"] > ATTEMPT_END:
        raise AssertionError("entropy high state reaches reconnect state")
    if auth["auth_input_end"] > auth["auth_input_guard_hi"]:
        raise AssertionError("auth input crosses its high guard")


def image_region(snapshot: Snapshot) -> Region:
    return Region("image", K_START, snapshot.image_end, "K")


def moved(
    name: str,
    start: int,
    size: int,
    space: str,
    old_start: int,
) -> Region:
    return Region(name, start, start + size, space, old_start, old_start + size)


def phase_regions(
    sectors: int, snapshots: dict[str, Snapshot]
) -> dict[str, list[Region]]:
    if sectors not in (13, 14):
        raise ValueError("only K13 and K14 are defined")

    keygen = snapshots["keygen"].symbols
    hello = snapshots["hello"].symbols
    candidate = snapshots["candidate"].symbols
    symmetric = snapshots["symmetric"].symbols
    fo = snapshots["fo_tail"].symbols
    auth = snapshots["auth"].symbols
    entropy = snapshots["entropy"].symbols

    if sectors == 14:
        poly_u = 0x3000
        poly_acc = 0x3200
        hello_state = 0x0DC0
        sym_split_symbol = "sym_k_work_end"
        sym_low = 0x0DC0
        fo_keccak = 0x3000
        fo_acc = 0x3200
    else:
        poly_u = 0x2E00
        poly_acc = 0x3000
        hello_state = 0x0DC0
        sym_split_symbol = "hmac_prepared_inner_state"
        sym_low = 0x0DC0
        fo_keccak = 0x2E00
        fo_acc = 0x3000

    hello_state_size = hello["hello_state_end"] - hello["hello_state_base"]
    ticket_size = (
        hello["poc_ticket_identity_end"] - hello["poc_ticket_identity"]
    )
    hello_sha_size = hello["hello_sha_work_end"] - hello["hello_sha_work_start"]
    sym_split = symmetric[sym_split_symbol]
    sym_tail_size = symmetric["sym_low_runtime_clear_end"] - sym_split
    fo_keccak_size = fo["fo_keccak_work_end"] - fo["fo_keccak_state"]
    auth_low_size = auth["auth_work_end"] - auth["auth_work_start"]

    return {
        "keygen": [
            image_region(snapshots["keygen"]),
            moved("poly_s", poly_u, SECTOR, "K", keygen["poly_s"]),
            moved("poly_acc", poly_acc, SECTOR, "K", keygen["poly_acc"]),
            Region("public_ek", keygen["keygen_ek"], 0x0D60, "LOW"),
            Region(
                "split_secret_output",
                keygen["keygen_s_hat0"],
                keygen["keygen_s_hat2"] + 384,
                "HIGH",
            ),
            Region(
                "attempt_seed",
                keygen["keygen_input"],
                keygen["keygen_input"] + 64,
                "HIGH",
            ),
        ],
        "hello": [
            image_region(snapshots["hello"]),
            moved(
                "state",
                hello_state,
                hello_state_size,
                "LOW",
                hello["hello_state_base"],
            ),
            moved(
                "ticket_identity",
                poly_u,
                ticket_size,
                "K",
                hello["poc_ticket_identity"],
            ),
            moved(
                "sha_hmac_work",
                poly_u + ticket_size,
                hello_sha_size,
                "K",
                hello["hello_sha_work_start"],
            ),
            Region(
                "preserved_network_and_public_object",
                LOW_START,
                0x0D00,
                "LOW",
            ),
            Region(
                "preserved_hello_handoff",
                0x0D00,
                hello["poc_hello_handoff_end"],
                "LOW",
            ),
            Region(
                "attempt_inputs",
                0x3B9C,
                hello["hello_attempt_used_end"],
                "HIGH",
            ),
        ],
        "candidate": [
            image_region(snapshots["candidate"]),
            moved(
                "decoded_u",
                poly_u,
                SECTOR,
                "K",
                candidate["mlkem_poly_u"],
            ),
            moved(
                "accumulator",
                poly_acc,
                SECTOR,
                "K",
                candidate["mlkem_poly_acc"],
            ),
            Region(
                "raw_ciphertext",
                0x08C0,
                0x0D00,
                "LOW",
            ),
            Region(
                "candidate_high_lifetime",
                candidate["mlkem_keccak_state"],
                candidate["mlkem_candidate_z"] + 32,
                "HIGH",
            ),
        ],
        "symmetric": [
            image_region(snapshots["symmetric"]),
            Region(
                "k_primitive_work",
                symmetric["sym_k_work_base"],
                sym_split,
                "K",
            ),
            moved(
                (
                    "runtime_tail"
                    if sectors == 14
                    else "prepared_hmac_aead_runtime_tail"
                ),
                sym_low,
                sym_tail_size,
                "LOW",
                sym_split,
            ),
            Region(
                "preserved_rx_frame",
                LOW_START,
                0x08B7,
                "LOW",
            ),
            Region(
                "preserved_raw_ciphertext",
                0x08C0,
                0x0D00,
                "LOW",
            ),
            Region(
                "preserved_hello_handoff",
                0x0D00,
                symmetric["sym_hello_context_end"],
                "LOW",
            ),
            Region(
                "retained_tls_state",
                symmetric["sym_high_state_base"],
                symmetric["sym_high_state_end"],
                "HIGH",
            ),
        ],
        "fo_tail": [
            image_region(snapshots["fo_tail"]),
            moved(
                "keccak_work",
                fo_keccak,
                fo_keccak_size,
                "K",
                fo["fo_keccak_state"],
            ),
            moved(
                "accumulator",
                fo_acc,
                SECTOR,
                "K",
                fo["fo_poly_acc"],
            ),
            Region("offline_low_work", LOW_START, fo["fo_low_work_end"], "LOW"),
            Region("retained_fo_state", HIGH_START, 0x3BFC, "HIGH"),
        ],
        "auth": [
            image_region(snapshots["auth"]),
            Region(
                "external_p256_work",
                LOW_START,
                LOW_START + auth_low_size,
                "LOW",
            ),
            Region(
                "quarantined_input",
                auth["auth_input_guard_lo"],
                auth["auth_input_end"],
                "HIGH",
            ),
        ],
        "entropy": [
            image_region(snapshots["entropy"]),
            Region("slot0", entropy["entropy_slot0"], entropy["entropy_slot1"], "LOW"),
            Region("slot1", entropy["entropy_slot1"], entropy["entropy_supplement"], "LOW"),
            Region("supplement", entropy["entropy_supplement"], 0x0B60, "LOW"),
            Region(
                "timing_sample",
                entropy["entropy_timing_sample"],
                entropy["entropy_timing_sample"] + 12,
                "LOW",
            ),
            Region(
                "write_record",
                entropy["entropy_write_record"],
                entropy["entropy_write_record"] + SECTOR,
                "LOW",
            ),
            Region(
                "readback",
                entropy["entropy_readback"],
                entropy["entropy_readback"] + SECTOR,
                "LOW",
            ),
            Region(
                "ratchet_state",
                entropy["entropy_high_start"],
                entropy["entropy_high_end"],
                "HIGH",
            ),
        ],
    }


def range_blocker(
    phase: str,
    region: Region,
    lower: int,
    upper: int,
) -> dict[str, Any]:
    return {
        "kind": "range_exceeds_space",
        "phase": phase,
        "region": region.name,
        "range": f"{hex16(region.start)}..{hex16(region.end)}",
        "space": region.space,
        "space_range": f"{hex16(lower)}..{hex16(upper)}",
        "underflow_bytes": max(0, lower - region.start),
        "overflow_bytes": max(0, region.end - upper),
    }


def expected_k13_blockers() -> list[dict[str, Any]]:
    return [
        range_blocker(
            "symmetric",
            Region(
                "k_primitive_work",
                EXPECTED_SYMMETRIC_K_WORK_BASE,
                EXPECTED_K13_SYMMETRIC_RETAINED_END,
                "K",
            ),
            K_START,
            K13_END,
        )
    ]


def validate_regions(
    sectors: int,
    phases: dict[str, list[Region]],
    *,
    expected_blockers: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    k_end = K_START + sectors * SECTOR
    limits = {
        "K": (K_START, k_end),
        "LOW": (LOW_START, LOW_END),
        "HIGH": (HIGH_START, ATTEMPT_END),
    }
    ledger: dict[str, dict[str, Any]] = {}
    blockers: list[dict[str, Any]] = []

    for phase, regions in phases.items():
        for region in regions:
            if region.end <= region.start:
                raise AssertionError(f"{phase}/{region.name}: empty or reversed")
            lower, upper = limits[region.space]
            if region.start < lower or region.end > upper:
                blockers.append(range_blocker(phase, region, lower, upper))

        for space in limits:
            same_space = sorted(
                (region for region in regions if region.space == space),
                key=lambda region: (region.start, region.end),
            )
            for left, right in zip(same_space, same_space[1:]):
                if left.end > right.start:
                    raise AssertionError(
                        f"K{sectors} {phase}: {left.name} "
                        f"{hex16(left.start)}..{hex16(left.end)} overlaps "
                        f"{right.name} {hex16(right.start)}..{hex16(right.end)}"
                    )

        k_regions = [region for region in regions if region.space == "K"]
        low_regions = [region for region in regions if region.space == "LOW"]
        used_k = sum(region.size for region in k_regions)
        k_top = k_end - max(region.end for region in k_regions)
        low_top = (
            LOW_END - max(region.end for region in low_regions)
            if low_regions
            else LOW_END - LOW_START
        )
        ledger[phase] = {
            "image_bytes": next(
                region.size for region in k_regions if region.name == "image"
            ),
            "image_sectors": rounded(
                next(region.size for region in k_regions if region.name == "image"),
                SECTOR,
            )
            // SECTOR,
            "k_used_bytes": used_k,
            "k_free_total_bytes": sectors * SECTOR - used_k,
            "k_top_margin_bytes": k_top,
            "low_top_margin_bytes": low_top,
            "regions": [region.json() for region in regions],
        }

    allowed = [] if expected_blockers is None else expected_blockers
    if blockers != allowed:
        raise AssertionError(
            f"K{sectors} range blockers changed: "
            f"expected={allowed!r}, actual={blockers!r}"
        )
    return ledger, blockers


def overlap_negative_canary() -> bool:
    """Prove that the interval checker rejects an overlap."""

    bad = {
        "canary": [
            Region("first", K_START, K_START + 32, "K"),
            Region("second", K_START + 31, K_START + 64, "K"),
        ]
    }
    try:
        validate_regions(14, bad)
    except AssertionError as error:
        return "overlaps" in str(error)
    return False


def unexpected_range_negative_canary() -> bool:
    """Prove that an unlisted out-of-bounds region remains terminal."""

    bad = {
        "canary": [
            Region("image", K_START, K14_END + 1, "K"),
        ]
    }
    try:
        validate_regions(14, bad)
    except AssertionError as error:
        return "range blockers changed" in str(error)
    return False


def current_phase_ends(snapshots: dict[str, Snapshot]) -> dict[str, int]:
    keygen = snapshots["keygen"].symbols
    hello = snapshots["hello"].symbols
    candidate = snapshots["candidate"].symbols
    symmetric = snapshots["symmetric"].symbols
    fo = snapshots["fo_tail"].symbols
    return {
        "keygen": max(snapshots["keygen"].image_end, keygen["poly_acc"] + SECTOR),
        "hello": max(
            snapshots["hello"].image_end,
            hello["hello_state_end"],
            hello["poc_ticket_identity_end"],
            hello["hello_sha_work_end"],
        ),
        "candidate": max(
            snapshots["candidate"].image_end,
            candidate["mlkem_poly_acc"] + SECTOR,
        ),
        "symmetric": max(
            snapshots["symmetric"].image_end,
            symmetric["sym_low_runtime_clear_end"],
        ),
        "fo_tail": max(
            snapshots["fo_tail"].image_end,
            fo["fo_keccak_work_end"],
            fo["fo_poly_acc"] + SECTOR,
        ),
        "auth": snapshots["auth"].image_end,
        "entropy": snapshots["entropy"].image_end,
    }


def snapshot_json(snapshot: Snapshot) -> dict[str, Any]:
    return {
        "source": str(snapshot.source.relative_to(ROOT)),
        "source_sha256": sha256(snapshot.source),
        "image_bytes": len(snapshot.image),
        "image_sha256": hashlib.sha256(snapshot.image).hexdigest(),
        "image_start": hex16(snapshot.image_start),
        "image_end": hex16(snapshot.image_end),
        "sector_count": rounded(len(snapshot.image), SECTOR) // SECTOR,
        "symbols": {
            name: hex16(value) for name, value in snapshot.symbols.items()
        },
    }


def build_result() -> dict[str, Any]:
    if shutil.which("nasm") is None:
        raise SystemExit("nasm is required for the K-window feasibility gate")

    with tempfile.TemporaryDirectory(prefix="seed-k-window-repack-") as name:
        directory = Path(name)
        snapshots = {
            phase: assemble_snapshot(phase, SOURCES[phase], PROBES[phase], directory)
            for phase in SOURCES
        }

    assert_layout_contract(snapshots)
    current_ends = current_phase_ends(snapshots)
    windows: dict[str, Any] = {}
    for sectors in (14, 13):
        k_end = K_START + sectors * SECTOR
        phases = phase_regions(sectors, snapshots)
        expected_blockers = expected_k13_blockers() if sectors == 13 else []
        ledger, blockers = validate_regions(
            sectors,
            phases,
            expected_blockers=expected_blockers,
        )
        windows[f"K{sectors}"] = {
            "feasible": not blockers,
            "range": f"{hex16(K_START)}..{hex16(k_end)}",
            "capacity_bytes": sectors * SECTOR,
            "blockers": blockers,
            "unmodified_overflow_bytes": {
                phase: max(0, end - k_end)
                for phase, end in current_ends.items()
            },
            "phases": ledger,
        }

    if not overlap_negative_canary():
        raise AssertionError("overlap detector negative canary did not fire")
    if not unexpected_range_negative_canary():
        raise AssertionError("unexpected range blocker negative canary did not fire")

    p256 = BOOT / "core" / "p256.inc"
    return {
        "schema": "seed-tls13-poc-k-window-repack-v2",
        "scope": (
            "mechanical address feasibility only; current sources are assembled "
            "but proposed addresses are not linked into the runtime"
        ),
        "result": {
            "K14": "feasible",
            "K13": "infeasible-current-symmetric-split",
            "recommended_first_target": "K14",
        },
        "fixed_product_bands": {
            "low": f"{hex16(LOW_START)}..{hex16(LOW_END)}",
            "resident": f"{hex16(RESIDENT_START)}..{hex16(DRIVER_START)}",
            "driver": f"{hex16(DRIVER_START)}..{hex16(K_START)}",
            "high_security": f"{hex16(HIGH_START)}..{hex16(ATTEMPT_END)}",
            "reconnect": f"{hex16(RECONNECT_START)}..{hex16(ESC_START)}",
            "esc": f"{hex16(ESC_START)}..{hex16(PRODUCT_POOL_START)}",
            "arena_context": (
                f"{hex16(PRODUCT_POOL_START)}..{hex16(STACK_GUARD_START)}"
            ),
            "stack": f"{hex16(STACK_GUARD_START)}..{hex16(RAM_END)}",
        },
        "assembled_snapshots": {
            phase: snapshot_json(snapshot)
            for phase, snapshot in snapshots.items()
        },
        "windows": windows,
        "hard_dependencies": {
            "slim_auth_image_bytes": len(snapshots["auth"].image),
            "slim_auth_sector_count": rounded(
                len(snapshots["auth"].image), SECTOR
            )
            // SECTOR,
            "p256_external_work_source": str(p256.relative_to(ROOT)),
            "p256_external_work_source_sha256": sha256(p256),
            "auth_K13_raw_margin_bytes": (
                K13_END - snapshots["auth"].image_end
            ),
            "K13_symmetric_k_margin_bytes": (
                K13_END
                - snapshots["symmetric"].symbols[
                    "hmac_prepared_inner_state"
                ]
            ),
            "K13_symmetric_low_margin_bytes": (
                LOW_END
                - (
                    0x0DC0
                    + snapshots["symmetric"].symbols[
                        "sym_low_runtime_clear_end"
                    ]
                    - snapshots["symmetric"].symbols[
                        "hmac_prepared_inner_state"
                    ]
                )
            ),
        },
        "gate_canaries": {
            "overlap_rejected": True,
            "unexpected_range_blocker_rejected": True,
            "exact_K13_blocker_recorded": True,
            "protected_bands_unchanged": True,
            "current_images_assembled_with_cpu_8086": True,
        },
        "provenance": {
            "checker": str(CHECKER.relative_to(ROOT)),
            "checker_sha256": sha256(CHECKER),
            "nasm": subprocess.run(
                ["nasm", "-v"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
        },
    }


def concise(result: dict[str, Any]) -> None:
    print("TLS13 PoC K-window repack: PASS")
    for name in ("K14", "K13"):
        window = result["windows"][name]
        print(f"  {name}: {window['range']} {result['result'][name]}")
        for phase in (
            "keygen",
            "hello",
            "candidate",
            "symmetric",
            "fo_tail",
            "auth",
            "entropy",
        ):
            item = window["phases"][phase]
            print(
                f"    {phase:9s} image={item['image_bytes']:4d} "
                f"K-top={item['k_top_margin_bytes']:4d} "
                f"K-free={item['k_free_total_bytes']:4d} "
                f"low-top={item['low_top_margin_bytes']:4d}"
            )
        for blocker in window["blockers"]:
            print(
                f"    blocker: {blocker['phase']}/{blocker['region']} "
                f"{blocker['range']} exceeds {blocker['space_range']} by "
                f"{blocker['overflow_bytes']} bytes"
            )
    hard = result["hard_dependencies"]
    print(
        "  tight K13 gates: "
        f"auth={hard['auth_K13_raw_margin_bytes']} bytes, "
        f"sym-K={hard['K13_symmetric_k_margin_bytes']} bytes, "
        f"sym-low={hard['K13_symmetric_low_margin_bytes']} bytes"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    parser.add_argument(
        "--check-recorded",
        action="store_true",
        help="require generated output to match k_window_repack_results.json",
    )
    args = parser.parse_args()

    result = build_result()
    rendered = json.dumps(result, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(rendered)
    if args.check_recorded:
        if not RESULTS.exists():
            raise SystemExit(f"missing recorded result: {RESULTS}")
        recorded = json.loads(RESULTS.read_text())
        if recorded != result:
            raise SystemExit(
                "K-window recorded result differs; inspect and regenerate with "
                f"--json-out {RESULTS}"
            )
    concise(result)


if __name__ == "__main__":
    main()
