#!/usr/bin/env python3
"""Correctness and cost spike for two-fixed-base P-256 ECDSA verification.

ECDSA verification evaluates::

    u1 * G + u2 * Q

The old Seed scoping treated ``Q`` as a variable base.  That is true across
leaf rotation, but not within one adopted leaf's lifetime: both ``G`` and the
pinned leaf point ``Q`` are exact fixed points.  This spike checks an unsigned
fixed-base comb for both points and turns its exact point-operation counts into
8088 timing bounds.

This is not an ECDSA implementation.  It deliberately excludes DER parsing,
SHA-256, reduction modulo the group order, and the ``s^-1`` calculation.  Its
reported verify time is the two-base curve evaluation plus conversion of the
result X coordinate to affine form.

The timing inputs are correctness-gated ``cycles8088.py`` measurements of
``variants/p256_combined.inc`` on this branch:

    field multiply       53,903 cycles
    point double        478,851 cycles
    mixed point add     693,307 cycles
    field inversion   2,232,732 cycles

The cycle model is calibrated against the original-speed 4.77 MHz 8088.  Run
``p256_eval.py variants/p256_combined.inc --full`` before treating the timing
as evidence; this program independently correctness-checks every comb width.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CHECK_P256 = ROOT / "tools" / "check-p256.py"

_spec = importlib.util.spec_from_file_location("seed_check_p256", CHECK_P256)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"cannot load {CHECK_P256}")
oracle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oracle)

Point = Optional[tuple[int, int]]

CPU_HZ = 4_772_728.0
FIELD_MUL_CYCLES = 53_903
POINT_DOUBLE_CYCLES = 478_851
POINT_ADD_CYCLES = 693_307
FIELD_INV_CYCLES = 2_232_732

# Measured from the assembled variants/p256_combined.inc harness.  The span is
# p256_from_be32..p256_w_tableX; private data is the include's data tail.  The
# common harness scratch is the P256_DATA block.  The wNAF scalar path reached
# an 84-byte maximum stack depth; this is not a two-base ECDSA stack result.
OPT_CORE_CODE_BYTES = 5_058
OPT_CORE_PRIVATE_DATA_BYTES = 896
COMMON_P256_SCRATCH_BYTES = 1_010
MEASURED_MAX_STACK_BYTES = 84

POINT_BYTES = 64
SECTOR_BYTES = 512
SCALAR_BITS = 256


def _point_add(left: Point, right: Point) -> Point:
    return oracle.point_add(left, right)


def _scalar_mult_or_none(scalar: int, point: tuple[int, int]) -> Point:
    scalar %= oracle.N
    if scalar == 0:
        return None
    return oracle.scalar_mult(scalar, point)


@dataclass(frozen=True)
class Comb:
    width: int
    columns: int
    teeth: tuple[tuple[int, int], ...]
    table: tuple[Point, ...]


def build_comb(point: tuple[int, int], width: int) -> Comb:
    """Build T[i] = sum(bit_j(i) * 2**(j*d) * point), d=ceil(256/w)."""
    if not 2 <= width <= 8:
        raise ValueError("spike bounds widths to 2..8")
    columns = math.ceil(SCALAR_BITS / width)
    teeth = [point]
    for _ in range(1, width):
        tooth = teeth[-1]
        for _ in range(columns):
            tooth = _point_add(tooth, tooth)
            if tooth is None:
                raise AssertionError("unexpected infinity while deriving comb tooth")
        teeth.append(tooth)

    table: list[Point] = [None] * (1 << width)
    for index in range(1, 1 << width):
        low_bit = index & -index
        tooth_index = low_bit.bit_length() - 1
        table[index] = _point_add(table[index ^ low_bit], teeth[tooth_index])
        if table[index] is None:
            raise AssertionError("unexpected infinity in comb table")
    return Comb(width, columns, tuple(teeth), tuple(table))


def comb_index(scalar: int, column: int, comb: Comb) -> int:
    index = 0
    for tooth in range(comb.width):
        bit_position = column + tooth * comb.columns
        if bit_position < SCALAR_BITS:
            index |= ((scalar >> bit_position) & 1) << tooth
    return index


def two_fixed_base_mult(
    left_scalar: int,
    left: Comb,
    right_scalar: int,
    right: Comb,
) -> tuple[Point, int, int]:
    """Return u1*P1 + u2*P2 and actual full point double/add counts."""
    if left.width != right.width or left.columns != right.columns:
        raise ValueError("comb geometries differ")
    left_scalar %= oracle.N
    right_scalar %= oracle.N
    accumulator: Point = None
    doubles = 0
    additions = 0
    for column in range(left.columns - 1, -1, -1):
        if accumulator is not None:
            accumulator = _point_add(accumulator, accumulator)
            doubles += 1
        left_index = comb_index(left_scalar, column, left)
        if left_index:
            if accumulator is None:
                accumulator = left.table[left_index]
            else:
                accumulator = _point_add(accumulator, left.table[left_index])
                additions += 1
        right_index = comb_index(right_scalar, column, right)
        if right_index:
            if accumulator is None:
                accumulator = right.table[right_index]
            else:
                accumulator = _point_add(accumulator, right.table[right_index])
                additions += 1
    return accumulator, doubles, additions


def binary_shamir_mult(
    left_scalar: int,
    left_point: tuple[int, int],
    right_scalar: int,
    right_point: tuple[int, int],
) -> tuple[Point, int, int]:
    """Classic two-bit Shamir/Straus interleave with one G+Q precompute."""
    left_scalar %= oracle.N
    right_scalar %= oracle.N
    table: tuple[Point, ...] = (
        None,
        right_point,
        left_point,
        _point_add(left_point, right_point),
    )
    accumulator: Point = None
    doubles = 0
    additions = 0
    for bit in range(SCALAR_BITS - 1, -1, -1):
        if accumulator is not None:
            accumulator = _point_add(accumulator, accumulator)
            doubles += 1
        index = ((left_scalar >> bit) & 1) << 1
        index |= (right_scalar >> bit) & 1
        if index:
            if accumulator is None:
                accumulator = table[index]
            else:
                accumulator = _point_add(accumulator, table[index])
                additions += 1
    return accumulator, doubles, additions


def build_unsigned_window(
    point: tuple[int, int], width: int
) -> tuple[Point, ...]:
    """All positive multiples 0P..(2**w-1)P for unsigned fixed-window."""
    table: list[Point] = [None]
    for _ in range(1, 1 << width):
        table.append(_point_add(table[-1], point))
    return tuple(table)


def unsigned_window_mult(
    left_scalar: int,
    left_table: tuple[Point, ...],
    right_scalar: int,
    right_table: tuple[Point, ...],
    width: int,
) -> tuple[Point, int, int]:
    """Conventional fixed-window two-base interleave (comparison baseline)."""
    left_scalar %= oracle.N
    right_scalar %= oracle.N
    mask = (1 << width) - 1
    chunks = math.ceil(SCALAR_BITS / width)
    accumulator: Point = None
    doubles = 0
    additions = 0
    for chunk in range(chunks - 1, -1, -1):
        if accumulator is not None:
            for _ in range(width):
                accumulator = _point_add(accumulator, accumulator)
                doubles += 1
        left_index = (left_scalar >> (chunk * width)) & mask
        if left_index:
            if accumulator is None:
                accumulator = left_table[left_index]
            else:
                accumulator = _point_add(accumulator, left_table[left_index])
                additions += 1
        right_index = (right_scalar >> (chunk * width)) & mask
        if right_index:
            if accumulator is None:
                accumulator = right_table[right_index]
            else:
                accumulator = _point_add(accumulator, right_table[right_index])
                additions += 1
    return accumulator, doubles, additions


def wnaf(scalar: int, width: int) -> tuple[int, ...]:
    """Least-significant-first width-w non-adjacent form."""
    scalar %= oracle.N
    digits: list[int] = []
    modulus = 1 << width
    midpoint = 1 << (width - 1)
    while scalar:
        digit = 0
        if scalar & 1:
            digit = scalar & (modulus - 1)
            if digit >= midpoint:
                digit -= modulus
            scalar -= digit
        digits.append(digit)
        scalar >>= 1
    return tuple(digits)


def build_odd_window(
    point: tuple[int, int], width: int
) -> tuple[tuple[int, int], ...]:
    """Positive odd multiples P,3P,...,(2**(w-1)-1)P."""
    count = 1 << (width - 2)
    two_point = _point_add(point, point)
    if two_point is None:
        raise AssertionError("unexpected infinity for 2P")
    table = [point]
    for _ in range(1, count):
        next_point = _point_add(table[-1], two_point)
        if next_point is None:
            raise AssertionError("unexpected infinity in odd-multiple table")
        table.append(next_point)
    return tuple(table)


def wnaf_straus_mult(
    left_scalar: int,
    left_table: tuple[tuple[int, int], ...],
    right_scalar: int,
    right_table: tuple[tuple[int, int], ...],
    width: int,
) -> tuple[Point, int, int]:
    """Shared-doubling two-base width-w NAF (small-table comparison)."""
    left_digits = wnaf(left_scalar, width)
    right_digits = wnaf(right_scalar, width)
    columns = max(len(left_digits), len(right_digits))
    accumulator: Point = None
    doubles = 0
    additions = 0

    def selected(
        digits: tuple[int, ...],
        table: tuple[tuple[int, int], ...],
        column: int,
    ) -> Point:
        if column >= len(digits) or digits[column] == 0:
            return None
        digit = digits[column]
        point = table[(abs(digit) - 1) // 2]
        return point if digit > 0 else (point[0], (-point[1]) % oracle.P)

    for column in range(columns - 1, -1, -1):
        if accumulator is not None:
            accumulator = _point_add(accumulator, accumulator)
            doubles += 1
        for point in (
            selected(left_digits, left_table, column),
            selected(right_digits, right_table, column),
        ):
            if point is None:
                continue
            if accumulator is None:
                accumulator = point
            else:
                accumulator = _point_add(accumulator, point)
                additions += 1
    return accumulator, doubles, additions


def serialize_table(comb: Comb) -> bytes:
    output = bytearray()
    for point in comb.table[1:]:
        if point is None:
            raise AssertionError("nonzero table entry is infinity")
        output.extend(point[0].to_bytes(32, "big"))
        output.extend(point[1].to_bytes(32, "big"))
    return bytes(output)


def check_serialized_table(comb: Comb, encoded: bytes) -> None:
    expected_len = ((1 << comb.width) - 1) * POINT_BYTES
    if len(encoded) != expected_len:
        raise AssertionError((len(encoded), expected_len))
    for offset in range(0, len(encoded), POINT_BYTES):
        point = (
            int.from_bytes(encoded[offset : offset + 32], "big"),
            int.from_bytes(encoded[offset + 32 : offset + 64], "big"),
        )
        if not oracle.is_on_curve(point):
            raise AssertionError(f"serialized point {offset // POINT_BYTES} off curve")


def _seconds(cycles: float) -> float:
    return cycles / CPU_HZ


def _batch_groups(width: int, batch_points: int) -> tuple[int, int]:
    """Return (normalized points, inversion batches) for staged table creation.

    Teeth are one dependency stage.  At subset stage j, all ``2**j - 1`` new
    entries depend only on the already-affine lower half and can therefore be
    normalized in bounded chunks.
    """
    normalized = width - 1
    groups = 1 if normalized else 0
    for stage in range(1, width):
        count = (1 << stage) - 1
        normalized += count
        groups += math.ceil(count / batch_points)
    if normalized != (1 << width) - 2:
        raise AssertionError("normalization accounting mismatch")
    return normalized, groups


@dataclass(frozen=True)
class WidthResult:
    width: int
    columns: int
    points_per_base: int
    two_base_table_bytes: int
    two_base_table_sectors: int
    g_anchor_leaf_table_bytes: int
    g_anchor_leaf_table_sectors: int
    expected_adds: float
    worst_adds: int
    expected_curve_and_final_x_seconds: float
    worst_curve_and_final_x_seconds: float
    generation_seconds_per_base_batch32: float
    generation_seconds_three_bases_batch32: float
    cold_self_boot_three_tables_two_verifies_seconds: float
    checked_cases: int
    observed_average_doubles: float
    observed_average_adds: float


@dataclass(frozen=True)
class AlgorithmResult:
    algorithm: str
    table_bytes: int
    table_sectors: int
    checked_cases: int
    observed_average_doubles: float
    observed_average_adds: float
    modeled_seconds_from_observed_ops_and_final_x: float
    self_generation_seconds_for_g_anchor_leaf: float
    cold_self_boot_generation_plus_two_verifies_seconds: float
    notes: str


def evaluate_comparison_algorithms(
    cases: list[tuple[int, int]],
    q: tuple[int, int],
) -> list[AlgorithmResult]:
    final_x_cycles = FIELD_INV_CYCLES + 2 * FIELD_MUL_CYCLES
    want = [
        _point_add(
            _scalar_mult_or_none(u1, oracle.G),
            _scalar_mult_or_none(u2, q),
        )
        for u1, u2 in cases
    ]

    candidates = []
    full_affine_cycles = FIELD_INV_CYCLES + 4 * FIELD_MUL_CYCLES
    candidates.append(
        (
            "binary Shamir",
            lambda u1, u2: binary_shamir_mult(u1, oracle.G, u2, q),
            POINT_BYTES,
            2 * (POINT_ADD_CYCLES + full_affine_cycles),
            "one stored G+Q point; its one-time generation is excluded",
        )
    )

    unsigned_width = 4
    unsigned_g = build_unsigned_window(oracle.G, unsigned_width)
    unsigned_q = build_unsigned_window(q, unsigned_width)
    candidates.append(
        (
            "unsigned fixed-window w=4",
            lambda u1, u2: unsigned_window_mult(
                u1, unsigned_g, u2, unsigned_q, unsigned_width
            ),
            2 * ((1 << unsigned_width) - 1) * POINT_BYTES,
            3
            * (
                POINT_DOUBLE_CYCLES
                + 13 * POINT_ADD_CYCLES
                + 14 * full_affine_cycles
            ),
            "same table bytes as comb w=4, but conventional 4-bit chunks",
        )
    )

    wnaf_width = 4
    wnaf_g = build_odd_window(oracle.G, wnaf_width)
    wnaf_q = build_odd_window(q, wnaf_width)
    candidates.append(
        (
            "two-base Straus wNAF w=4",
            lambda u1, u2: wnaf_straus_mult(
                u1, wnaf_g, u2, wnaf_q, wnaf_width
            ),
            2 * len(wnaf_g) * POINT_BYTES,
            3
            * (
                POINT_DOUBLE_CYCLES
                + 3 * POINT_ADD_CYCLES
                + 4 * full_affine_cycles
            ),
            "P,3P,5P,7P per base; table generation is excluded",
        )
    )

    results: list[AlgorithmResult] = []
    for name, operation, table_bytes, generation_cycles, notes in candidates:
        total_doubles = 0
        total_adds = 0
        for index, (u1, u2) in enumerate(cases):
            got, doubles, additions = operation(u1, u2)
            if got != want[index]:
                raise AssertionError(f"{name}: mismatch in case {index}")
            # The first four cases are deliberately sparse edge vectors.  Keep
            # them in the correctness gate, but do not let them bias the random
            # scalar cost mean.
            if index >= 4:
                total_doubles += doubles
                total_adds += additions
        cost_cases = len(cases) - 4
        average_doubles = total_doubles / cost_cases
        average_adds = total_adds / cost_cases
        cycles = (
            average_doubles * POINT_DOUBLE_CYCLES
            + average_adds * POINT_ADD_CYCLES
            + final_x_cycles
        )
        results.append(
            AlgorithmResult(
                algorithm=name,
                table_bytes=table_bytes,
                table_sectors=math.ceil(table_bytes / SECTOR_BYTES),
                checked_cases=len(cases),
                observed_average_doubles=average_doubles,
                observed_average_adds=average_adds,
                modeled_seconds_from_observed_ops_and_final_x=_seconds(cycles),
                self_generation_seconds_for_g_anchor_leaf=_seconds(
                    generation_cycles
                ),
                cold_self_boot_generation_plus_two_verifies_seconds=(
                    _seconds(generation_cycles) + 2 * _seconds(cycles)
                ),
                notes=notes,
            )
        )
    return results


def evaluate_width(
    width: int,
    cases: list[tuple[int, int]],
    q: tuple[int, int],
    batch_points: int,
) -> WidthResult:
    g_comb = build_comb(oracle.G, width)
    q_comb = build_comb(q, width)
    check_serialized_table(g_comb, serialize_table(g_comb))
    check_serialized_table(q_comb, serialize_table(q_comb))

    observed_doubles = 0
    observed_adds = 0
    for u1, u2 in cases:
        got, doubles, additions = two_fixed_base_mult(
            u1, g_comb, u2, q_comb
        )
        want = _point_add(
            _scalar_mult_or_none(u1, oracle.G),
            _scalar_mult_or_none(u2, q),
        )
        if got != want:
            raise AssertionError(
                f"width {width}: comb mismatch for u1={u1:x}, u2={u2:x}"
            )
        observed_doubles += doubles
        observed_adds += additions

    columns = g_comb.columns
    points_per_base = (1 << width) - 1
    two_base_bytes = 2 * points_per_base * POINT_BYTES
    three_base_bytes = 3 * points_per_base * POINT_BYTES

    # A random w-bit comb digit is nonzero with probability 1-2^-w.  Two
    # independent scalars therefore need this many mixed additions on average.
    # Treat every column's doubling as a full point double for a conservative
    # timing bound, even though the first infinity double is only a cheap test.
    expected_adds = 2 * columns * (1 - 1 / (1 << width))
    worst_adds = 2 * columns
    final_x_cycles = FIELD_INV_CYCLES + 2 * FIELD_MUL_CYCLES
    expected_cycles = (
        columns * POINT_DOUBLE_CYCLES
        + expected_adds * POINT_ADD_CYCLES
        + final_x_cycles
    )
    worst_cycles = (
        columns * POINT_DOUBLE_CYCLES
        + worst_adds * POINT_ADD_CYCLES
        + final_x_cycles
    )

    # On-machine table generation:
    #   * derive w teeth with (w-1)*d doublings;
    #   * create all non-singleton subset sums with 2^w-w-1 mixed adds;
    #   * normalize 2^w-2 Jacobian points in bounded batches.
    #
    # Batch normalization of k points costs one inversion, 3k-3 field
    # multiplies for the shared inverses, and 4k multiplies for affine X/Y.
    normalized, groups = _batch_groups(width, batch_points)
    generation_doubles = (width - 1) * columns
    generation_adds = (1 << width) - width - 1
    normalization_multiplies = 7 * normalized - 3 * groups
    generation_cycles = (
        generation_doubles * POINT_DOUBLE_CYCLES
        + generation_adds * POINT_ADD_CYCLES
        + groups * FIELD_INV_CYCLES
        + normalization_multiplies * FIELD_MUL_CYCLES
    )

    return WidthResult(
        width=width,
        columns=columns,
        points_per_base=points_per_base,
        two_base_table_bytes=two_base_bytes,
        two_base_table_sectors=math.ceil(two_base_bytes / SECTOR_BYTES),
        g_anchor_leaf_table_bytes=three_base_bytes,
        g_anchor_leaf_table_sectors=math.ceil(three_base_bytes / SECTOR_BYTES),
        expected_adds=expected_adds,
        worst_adds=worst_adds,
        expected_curve_and_final_x_seconds=_seconds(expected_cycles),
        worst_curve_and_final_x_seconds=_seconds(worst_cycles),
        generation_seconds_per_base_batch32=_seconds(generation_cycles),
        generation_seconds_three_bases_batch32=3 * _seconds(generation_cycles),
        cold_self_boot_three_tables_two_verifies_seconds=(
            3 * _seconds(generation_cycles) + 2 * _seconds(expected_cycles)
        ),
        checked_cases=len(cases),
        observed_average_doubles=observed_doubles / len(cases),
        observed_average_adds=observed_adds / len(cases),
    )


def make_cases(sample_count: int) -> list[tuple[int, int]]:
    cases = [
        (0, 1),
        (1, 0),
        (1, 1),
        (oracle.N - 1, oracle.N - 1),
    ]
    rng = random.Random(0xECDA_5150)
    for _ in range(sample_count):
        cases.append((rng.randrange(oracle.N), rng.randrange(oracle.N)))
    return cases


def report(
    results: list[WidthResult],
    algorithms: list[AlgorithmResult],
    q: tuple[int, int],
) -> dict:
    return {
        "profile": {
            "cpu_hz": CPU_HZ,
            "q": {"x": f"{q[0]:064x}", "y": f"{q[1]:064x}"},
            "timing_cycles": {
                "field_mul": FIELD_MUL_CYCLES,
                "point_double": POINT_DOUBLE_CYCLES,
                "point_add_mixed": POINT_ADD_CYCLES,
                "field_inverse": FIELD_INV_CYCLES,
            },
            "assembled_combined_variant_harness": {
                "code_bytes": OPT_CORE_CODE_BYTES,
                "private_data_bytes": OPT_CORE_PRIVATE_DATA_BYTES,
                "common_scratch_bytes": COMMON_P256_SCRATCH_BYTES,
                "measured_max_stack_bytes": MEASURED_MAX_STACK_BYTES,
            },
            "scope_exclusions": [
                "ECDSA DER parsing",
                "SHA-256 signed-content hashing",
                "s inverse modulo group order",
                "u1/u2 multiplication and reduction modulo group order",
                "comb driver code and floppy I/O",
            ],
        },
        "comparison_algorithms": [asdict(result) for result in algorithms],
        "widths": [asdict(result) for result in results],
    }


def print_human(data: dict) -> None:
    profile = data["profile"]
    timing = profile["timing_cycles"]
    core = profile["assembled_combined_variant_harness"]
    print("two-fixed-base P-256 comb: correctness PASS")
    print(
        "8088 model inputs: "
        f"D={timing['point_double']:,}cy "
        f"A={timing['point_add_mixed']:,}cy "
        f"M={timing['field_mul']:,}cy "
        f"I={timing['field_inverse']:,}cy"
    )
    print(
        "variants/p256_combined.inc one-scalar harness: "
        f"{core['code_bytes']:,} B code + "
        f"{core['private_data_bytes'] + core['common_scratch_bytes']:,} B data; "
        f"one-scalar stack reference {core['measured_max_stack_bytes']} B"
    )
    print()
    print(
        " w   d  pts/base  tables G+Q   tables G+anchor+leaf  "
        "verify avg/worst   gen/base  cold(3gen+2V)"
    )
    for item in data["widths"]:
        print(
            f"{item['width']:2d} {item['columns']:3d} "
            f"{item['points_per_base']:9d} "
            f"{item['two_base_table_bytes']:6d} B/"
            f"{item['two_base_table_sectors']:2d}s  "
            f"{item['g_anchor_leaf_table_bytes']:6d} B/"
            f"{item['g_anchor_leaf_table_sectors']:3d}s  "
            f"{item['expected_curve_and_final_x_seconds']:6.2f}/"
            f"{item['worst_curve_and_final_x_seconds']:6.2f}s  "
            f"{item['generation_seconds_per_base_batch32']:7.2f}s "
            f"{item['cold_self_boot_three_tables_two_verifies_seconds']:8.2f}s"
        )
    print()
    print("verify timing includes curve evaluation + final affine X only")
    print("table generation uses on-machine 32-point batch normalization")
    print("all widths checked against independent scalar multiplication")
    print()
    print("small-table comparisons (observed deterministic-case operation means):")
    for item in data["comparison_algorithms"]:
        print(
            f"  {item['algorithm']:<29} "
            f"{item['table_bytes']:5d} B/"
            f"{item['table_sectors']:2d}s  "
            f"D={item['observed_average_doubles']:6.1f} "
            f"A={item['observed_average_adds']:6.1f}  "
            f"V={item['modeled_seconds_from_observed_ops_and_final_x']:6.2f}s "
            f"cold2={item['cold_self_boot_generation_plus_two_verifies_seconds']:6.2f}s"
        )
    print("cold2 includes on-machine table generation + two verifies")
    wnaf = next(
        item
        for item in data["comparison_algorithms"]
        if item["algorithm"] == "two-base Straus wNAF w=4"
    )
    per_base_generation = (
        wnaf["self_generation_seconds_for_g_anchor_leaf"] / 3
    )
    conservative_verify = _seconds(
        256 * POINT_DOUBLE_CYCLES
        + 130 * POINT_ADD_CYCLES
        + FIELD_INV_CYCLES
        + 2 * FIELD_MUL_CYCLES
    )
    expected_verify = wnaf["modeled_seconds_from_observed_ops_and_final_x"]
    print(
        "wNAF w4 immutable-leaf fast path expected/conservative: "
        f"{2 * per_base_generation + expected_verify:.2f}/"
        f"{2 * per_base_generation + conservative_verify:.2f}s"
    )
    print(
        "wNAF w4 WE1 recertification expected/conservative: "
        f"{3 * per_base_generation + 2 * expected_verify:.2f}/"
        f"{3 * per_base_generation + 2 * conservative_verify:.2f}s"
    )
    print(
        "all seconds are correctness-gated static-cycle-model estimates; "
        "sample means use deterministic random scalar pairs"
    )
    print("all timing still excludes ECDSA mod-n work, hashing, parsing, and I/O")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--samples",
        type=int,
        default=16,
        help="deterministic random scalar pairs in addition to four edge cases",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the complete machine-readable report"
    )
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be positive")

    # A deterministic nontrivial stand-in for a pinned P-256 leaf point.  Comb
    # correctness is independent of which valid subgroup point is selected.
    q = oracle.scalar_mult(
        0x5EED_5150_8088_2860_1234_5678_9ABC_DEF0_1020_3040_5060_7080,
        oracle.G,
    )
    if not oracle.is_on_curve(q):
        raise AssertionError("test Q is not on P-256")
    cases = make_cases(args.samples)
    results = [
        evaluate_width(width, cases, q, batch_points=32)
        for width in range(2, 9)
    ]
    algorithms = evaluate_comparison_algorithms(cases, q)
    data = report(results, algorithms, q)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print_human(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
