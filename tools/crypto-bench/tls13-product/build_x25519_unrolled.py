#!/usr/bin/env python3
"""Build an exact X25519 gate with statically unrolled 16-bit field products.

The original spike deliberately uses compact looped Comba multiplication and
squaring.  That is a useful portable baseline, but it spends a large fraction
of its 80286 time calculating column bounds, advancing pointers, and executing
LOOP around every 16x16 multiply.  This experiment emits the same arithmetic
as straight-line 8086-compatible code.  It changes neither the field
representation nor the RFC 7748 Montgomery ladder, so the existing target-side
public-key and shared-secret comparisons remain the correctness gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE.parent / "tls13-spike/x25519_bench.asm"
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench"
OUTPUT = BUILD / "x25519_unrolled_bench.asm"
METADATA = BUILD / "x25519-unrolled-build.json"


def mem(base: str, word: int) -> str:
    offset = word * 2
    return f"[{base}]" if offset == 0 else f"[{base} + {offset}]"


def emit_accumulate(left: str, right: str, doubled: bool = False) -> list[str]:
    lines = [
        f"    mov ax, {left}",
        f"    mul word {right}",
    ]
    if doubled:
        lines += [
            "    shl ax, 1",
            "    rcl dx, 1",
            "    adc cx, 0",
        ]
    lines += [
        "    add bx, ax",
        "    adc bp, dx",
        "    adc cx, 0",
    ]
    return lines


def emit_column_start() -> list[str]:
    return []


def emit_column_end(k: int) -> list[str]:
    return [
        f"    mov [fe_product + {2 * k}], bx",
        "    mov bx, bp",
        "    mov bp, cx",
        "    xor cx, cx",
    ]


def generate_mul() -> str:
    lines = [
        "; SI=a, DI=b, BX=out.  Statically unrolled 16x16-word Comba product.",
        "fe_mul:",
        "    mov [fm_left_ptr], si",
        "    mov [fm_right_ptr], di",
        "    mov [fm_out_ptr], bx",
        "    xor bx, bx",
        "    xor bp, bp",
        "    xor cx, cx",
    ]
    for k in range(31):
        lines += ["", f"    ; product column {k}", *emit_column_start()]
        start = max(0, k - 15)
        end = min(15, k)
        for i in range(start, end + 1):
            j = k - i
            lines += emit_accumulate(mem("si", i), mem("di", j))
        lines += emit_column_end(k)
    lines += [
        "",
        "    mov [fe_product + 62], bx",
        "    mov [fe_product + 64], bp",
        "    mov bx, [fm_out_ptr]",
        "    call fe_reduce_product",
        "    ret",
    ]
    return "\n".join(lines)


def generate_sq() -> str:
    lines = [
        "; SI=a, BX=out.  Statically unrolled symmetric 16-word Comba square.",
        "fe_sq:",
        "    mov [fm_left_ptr], si",
        "    mov [fm_out_ptr], bx",
        "    xor bx, bx",
        "    xor bp, bp",
        "    xor cx, cx",
    ]
    for k in range(31):
        lines += ["", f"    ; square column {k}", *emit_column_start()]
        start = max(0, k - 15)
        end = min(15, k)
        for i in range(start, end + 1):
            j = k - i
            if i > j:
                continue
            lines += emit_accumulate(mem("si", i), mem("si", j), i != j)
        lines += emit_column_end(k)
    lines += [
        "",
        "    mov [fe_product + 62], bx",
        "    mov [fe_product + 64], bp",
        "    mov bx, [fm_out_ptr]",
        "    call fe_reduce_product",
        "    ret",
    ]
    return "\n".join(lines)


def generate_reduce() -> str:
    lines = [
        "; Reduce fe_product modulo 2^256-38 into BX.",
        "; The carry and constant stay in registers across all 16 limbs.",
        "fe_reduce_product:",
        "    mov [fr_out_ptr], bx",
        "    xor bp, bp",
        "    mov cx, 38",
    ]
    for i in range(16):
        lines += [
            f"    mov ax, {mem('fe_product', 16 + i)}",
            "    mul cx",
            f"    add ax, {mem('fe_product', i)}",
            "    adc dx, 0",
            "    add ax, bp",
            "    adc dx, 0",
            f"    mov {mem('bx', i)}, ax",
            "    mov bp, dx",
        ]
    lines += [
        "    mov ax, bp",
        "    call fe_fold_256",
        "    call fe_fold_top",
        "    call fe_canonical",
        "    ret",
    ]
    return "\n".join(lines)


def generate_add_sub() -> str:
    lines = [
        "; SI=a, DI=b, BX=out.  Straight-line field addition.",
        "fe_add:",
        "    push cx",
        "    push dx",
        "    clc",
    ]
    for i in range(16):
        lines += [
            f"    mov ax, {mem('si', i)}",
            f"    adc ax, {mem('di', i)}",
            f"    mov {mem('bx', i)}, ax",
        ]
    lines += [
        "    mov ax, 0",
        "    adc ax, 0",
        "    call fe_fold_256",
        "    call fe_fold_top",
        "    call fe_canonical",
        "    pop dx",
        "    pop cx",
        "    ret",
        "",
        "; SI=a, DI=b, BX=out.  Straight-line, branch-free field subtraction.",
        "fe_sub:",
        "    push cx",
        "    push dx",
        "    clc",
    ]
    for i in range(16):
        lines += [
            f"    mov ax, {mem('si', i)}",
            f"    {'sub' if i == 0 else 'sbb'} ax, {mem('di', i)}",
            f"    mov {mem('bx', i)}, ax",
        ]
    lines += [
        "    sbb dx, dx",
        "    mov cx, dx",
        "    and cx, 0x7fff",
        "    mov ax, dx",
        "    and ax, 0xffed",
        "    add [bx], ax",
    ]
    for i in range(1, 15):
        lines += [
            "    mov ax, dx",
            f"    adc {mem('bx', i)}, ax",
        ]
    lines += [
        "    mov ax, cx",
        "    adc [bx + 30], ax",
        "    pop dx",
        "    pop cx",
        "    ret",
    ]
    return "\n".join(lines)


def generate_cswap() -> str:
    lines = [
        "; Constant-time conditional swap of two field elements.",
        "; AX=0/1, SI/DI=field elements.",
        "fe_cswap:",
        "    push ax",
        "    push bx",
        "    push dx",
        "    neg ax",
        "    mov dx, ax",
    ]
    for i in range(16):
        lines += [
            f"    mov ax, {mem('si', i)}",
            f"    mov bx, {mem('di', i)}",
            "    xor ax, bx",
            "    and ax, dx",
            f"    xor {mem('si', i)}, ax",
            f"    xor {mem('di', i)}, ax",
        ]
    lines += [
        "    pop dx",
        "    pop bx",
        "    pop ax",
        "    ret",
    ]
    return "\n".join(lines)


def generate_mul_a24() -> str:
    lines = [
        "; SI=a, BX=out.  121665 = 0x1db41.",
        "; Keep the word-product carry in BP and use the bounded two-word high",
        "; half for a shortened pseudo-Mersenne reduction.",
        "fe_mul_a24:",
        "    mov [fm_out_ptr], bx",
        "    xor bp, bp",
        "    mov cx, 0xdb41",
    ]
    for i in range(16):
        lines += [
            f"    mov ax, {mem('si', i)}",
            "    mul cx",
            "    add ax, bp",
            "    adc dx, 0",
            f"    mov {mem('fe_product', i)}, ax",
            "    mov bp, dx",
        ]
    lines += [
        "    mov [fe_product + 32], bp",
        "    mov word [fe_product + 34], 0",
        "    clc",
    ]
    for i in range(16):
        lines += [
            f"    mov ax, {mem('si', i)}",
            f"    adc {mem('fe_product', i + 1)}, ax",
        ]
    lines += [
        "    adc word [fe_product + 34], 0",
        "",
        "    mov bx, [fm_out_ptr]",
        "    mov cx, 38",
        "    xor bp, bp",
    ]
    for i in range(16):
        if i < 2:
            lines += [
                f"    mov ax, {mem('fe_product', 16 + i)}",
                "    mul cx",
            ]
        else:
            lines += [
                "    xor ax, ax",
                "    xor dx, dx",
            ]
        lines += [
            f"    add ax, {mem('fe_product', i)}",
            "    adc dx, 0",
            "    add ax, bp",
            "    adc dx, 0",
            f"    mov {mem('bx', i)}, ax",
            "    mov bp, dx",
        ]
    lines += [
        "    mov ax, bp",
        "    call fe_fold_256",
        "    call fe_fold_top",
        "    call fe_canonical",
        "    ret",
    ]
    return "\n".join(lines)


def emit_small_product(square: bool, suffix: str, output: str) -> str:
    name = f"fe_{'ksq8' if square else 'kmul8'}_{suffix}"
    description = (
        "symmetric 8-word Comba square"
        if square
        else "8x8-word Comba product"
    )
    lines = [
        f"; SI=a{'' if square else ', DI=b'}, BX=16-word output.",
        f"; Statically unrolled {description}.",
        f"{name}:",
        "    xor bx, bx",
        "    xor bp, bp",
        "    xor cx, cx",
    ]
    for k in range(15):
        lines += ["", f"    ; half-product column {k}", *emit_column_start()]
        start = max(0, k - 7)
        end = min(7, k)
        for i in range(start, end + 1):
            j = k - i
            if square and i > j:
                continue
            right_base = "si" if square else "di"
            lines += emit_accumulate(
                mem("si", i), mem(right_base, j), square and i != j
            )
        lines += [
            f"    mov {mem(output, k)}, bx",
            "    mov bx, bp",
            "    mov bp, cx",
            "    xor cx, cx",
        ]
    lines += [
        "",
        f"    mov {mem(output, 15)}, bx",
        "    ret",
    ]
    return "\n".join(lines)


def emit_absdiff(
    left: str, right: str, output: str, sign_output: str | None
) -> list[str]:
    lines = ["    clc"]
    for i in range(8):
        instruction = "sub" if i == 0 else "sbb"
        lines += [
            f"    mov ax, {mem(left, i)}",
            f"    {instruction} ax, {mem(right, i)}",
            f"    mov {mem(output, i)}, ax",
        ]
    lines += ["    sbb bp, bp"]
    if sign_output is not None:
        lines += [f"    mov [{sign_output}], bp"]
    lines += [
        "    mov dx, bp",
        "    and dx, 1",
    ]
    for i in range(8):
        instruction = "add" if i == 0 else "adc"
        lines += [
            f"    mov ax, {mem(output, i)}",
            "    xor ax, bp",
            f"    {instruction} ax, {'dx' if i == 0 else '0'}",
            f"    mov {mem(output, i)}, ax",
        ]
    return lines


def emit_cross(sign_for_negative: str | None) -> list[str]:
    lines = ["    ; Form the 17-word cross coefficient L + H."]
    for i in range(16):
        lines += [
            f"    mov ax, {mem('fe_kar_l', i)}",
            f"    {'add' if i == 0 else 'adc'} ax, {mem('fe_kar_h', i)}",
            f"    mov {mem('fe_kar_c', i)}, ax",
        ]
    lines += [
        "    mov ax, 0",
        "    adc ax, 0",
        "    mov [fe_kar_c + 32], ax",
        "",
        "    ; Add signed M: -M for equal signs, +M for different signs.",
    ]
    if sign_for_negative is None:
        lines += ["    mov dx, 0xffff"]
    else:
        lines += [
            f"    mov dx, [{sign_for_negative}]",
            "    xor dx, [fm_sign_b]",
            "    not dx",
        ]
    for i in range(16):
        lines += [f"    xor word {mem('fe_kar_m', i)}, dx"]
    lines += [
        "    mov ax, dx",
        "    shr ax, 1",
    ]
    for i in range(16):
        lines += [
            f"    mov ax, {mem('fe_kar_m', i)}",
            f"    adc {mem('fe_kar_c', i)}, ax",
        ]
    lines += [
        "    mov ax, dx",
        "    adc [fe_kar_c + 32], ax",
        "",
        "    ; Assemble L + cross*B^8 + H*B^16.",
        "    mov si, fe_kar_l",
        "    mov di, fe_product",
        "    mov cx, 32",
        "    rep movsw",
        "    mov word [fe_product + 64], 0",
        "    mov word [fe_product + 66], 0",
        "    clc",
    ]
    for i in range(17):
        lines += [
            f"    mov ax, {mem('fe_kar_c', i)}",
            f"    adc {mem('fe_product', 8 + i)}, ax",
        ]
    for i in range(25, 34):
        lines += [f"    adc word {mem('fe_product', i)}, 0"]
    return lines


def generate_karatsuba_mul() -> str:
    lines = [
        "; SI=a, DI=b, BX=out.  One-level subtractive Karatsuba product.",
        "; Absolute differences and sign selection are branch-free.",
        "fe_mul:",
        "    mov [fm_left_ptr], si",
        "    mov [fm_right_ptr], di",
        "    mov [fm_out_ptr], bx",
        "",
        "    call fe_kmul8_l",
        "    mov si, [fm_left_ptr]",
        "    add si, 16",
        "    mov di, [fm_right_ptr]",
        "    add di, 16",
        "    call fe_kmul8_h",
        "",
        "    mov si, [fm_left_ptr]",
    ]
    lines += emit_absdiff("si", "si + 16", "fe_kar_da", "fm_sign_a")
    lines += [
        "",
        "    mov si, [fm_right_ptr]",
    ]
    lines += emit_absdiff("si", "si + 16", "fe_kar_db", "fm_sign_b")
    lines += [
        "",
        "    mov si, fe_kar_da",
        "    mov di, fe_kar_db",
        "    call fe_kmul8_m",
        "",
        "    ; Cross term is L + H - (Alo-Ahi)(Blo-Bhi).",
        *emit_cross("fm_sign_a"),
        "",
        "    mov bx, [fm_out_ptr]",
        "    call fe_reduce_product",
        "    ret",
        "",
        emit_small_product(False, "l", "fe_kar_l"),
        "",
        emit_small_product(False, "h", "fe_kar_h"),
        "",
        emit_small_product(False, "m", "fe_kar_m"),
    ]
    return "\n".join(lines)


def generate_karatsuba_sq() -> str:
    lines = [
        "; SI=a, BX=out.  One-level subtractive Karatsuba square.",
        "; The absolute half difference removes its secret-dependent sign.",
        "fe_sq:",
        "    mov [fm_left_ptr], si",
        "    mov [fm_out_ptr], bx",
        "",
        "    call fe_ksq8_l",
        "    mov si, [fm_left_ptr]",
        "    add si, 16",
        "    call fe_ksq8_h",
        "",
        "    mov si, [fm_left_ptr]",
    ]
    lines += emit_absdiff("si", "si + 16", "fe_kar_da", None)
    lines += [
        "",
        "    mov si, fe_kar_da",
        "    call fe_ksq8_m",
        "",
        "    ; Cross term is L + H - (Alo-Ahi)^2.",
        *emit_cross(None),
        "",
        "    mov bx, [fm_out_ptr]",
        "    call fe_reduce_product",
        "    ret",
        "",
        emit_small_product(True, "l", "fe_kar_l"),
        "",
        emit_small_product(True, "h", "fe_kar_h"),
        "",
        emit_small_product(True, "m", "fe_kar_m"),
    ]
    return "\n".join(lines)


def build_source(karatsuba: bool) -> str:
    source = SOURCE.read_text()
    cswap_start = source.index("; Constant-time conditional swap")
    cswap_end = source.index(
        "; ---------------------------------------------------------------------------\n"
        "; Field arithmetic",
        cswap_start,
    )
    source = (
        source[:cswap_start]
        + generate_cswap()
        + "\n\n"
        + source[cswap_end:]
    )
    add_start = source.index("; SI=a, DI=b, BX=out.\nfe_add:")
    add_end = source.index(
        "; SI=a, BX=out.  Symmetric 16-word Comba square", add_start
    )
    source = (
        source[:add_start]
        + generate_add_sub()
        + "\n\n"
        + source[add_end:]
    )
    start = source.index("; SI=a, BX=out.  Symmetric 16-word Comba square")
    end = source.index("; SI=a, BX=out.  121665", start)
    if karatsuba:
        replacement = (
            generate_karatsuba_sq() + "\n\n" + generate_karatsuba_mul() + "\n\n"
        )
    else:
        replacement = generate_sq() + "\n\n" + generate_mul() + "\n\n"
    source = source[:start] + replacement + source[end:]
    a24_start = source.index("; SI=a, BX=out.  121665")
    a24_end = source.index("; Reduce fe_product into BX.", a24_start)
    source = (
        source[:a24_start]
        + generate_mul_a24()
        + "\n\n"
        + source[a24_end:]
    )
    reduce_start = source.index("; Reduce fe_product into BX.")
    reduce_end = source.index(
        "; BX=field, AX=coefficient beyond word 15.", reduce_start
    )
    source = (
        source[:reduce_start]
        + generate_reduce()
        + "\n\n"
        + source[reduce_end:]
    )
    source = source.replace("mov sp, 0x3ff0", "mov sp, 0xfff0", 1)
    source = source.replace(
        "%if image_end - core_header > 0x2f00",
        "%if image_end - core_header > 0xe000",
        1,
    )
    source = source.replace(
        '%error "X25519 benchmark leaves insufficient room below the 16 KiB stack"',
        '%error "X25519 benchmark exceeds the 286 gate segment budget"',
        1,
    )
    if karatsuba:
        scratch = """
fm_sign_a: dw 0
fm_sign_b: dw 0
fe_kar_l:  times 16 dw 0
fe_kar_h:  times 16 dw 0
fe_kar_m:  times 16 dw 0
fe_kar_c:  times 17 dw 0
fe_kar_da: times 8 dw 0
fe_kar_db: times 8 dw 0
"""
        source = source.replace("image_end:\n", scratch + "\nimage_end:\n", 1)
    return source


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--karatsuba", action="store_true")
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    output = (
        BUILD / "x25519_unrolled_karatsuba_bench.asm"
        if args.karatsuba
        else OUTPUT
    )
    metadata = (
        BUILD / "x25519-unrolled-karatsuba-build.json"
        if args.karatsuba
        else METADATA
    )
    source = build_source(args.karatsuba)
    output.write_text(source)
    report = {
        "source": str(SOURCE.relative_to(ROOT)),
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "output": str(output.relative_to(ROOT)),
        "output_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "field_multiplication": (
            "unrolled one-level subtractive Karatsuba (192 MUL)"
            if args.karatsuba
            else "unrolled 256-MUL Comba"
        ),
        "field_square": (
            "unrolled one-level subtractive Karatsuba (108 MUL)"
            if args.karatsuba
            else "unrolled 136-MUL symmetric Comba"
        ),
        "ladder": "unchanged constant-time RFC 7748 Montgomery ladder",
        "correctness_gate": (
            "target-side RFC 7748 public-key and shared-secret byte comparisons"
        ),
    }
    metadata.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
