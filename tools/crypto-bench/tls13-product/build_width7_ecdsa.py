#!/usr/bin/env python3
"""Build an exact target-executed width-7 P-256 ECDSA benchmark.

The checked-in authentication spike has complete strict-DER, modulo-n, and
P-256 verification code, but its curve equation uses width-4 Straus tables.
This builder keeps that implementation as the source of truth and makes a
benchmark-only transformation:

* move the stack above the enlarged image on the 512 KiB gate machine;
* replace only the two-scalar curve loop with a width-7 two-fixed-base comb;
* embed independently generated G, anchor, and leaf tables as a stand-in for
  the same tables Seed would generate locally before TCP; and
* retain both complete fixture signatures, final affine-x/r comparisons, and
  the benchmark's target-side AUTH PASS gate.

The embedded tables are not a proposed product trust boundary.  They isolate
the post-ServerHello timing of the exact width-7 verifier after same-machine
precomputation.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path
from types import ModuleType


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPIKE = HERE.parent / "tls13-spike"
SOURCE = SPIKE / "auth_integrated_bench.asm"
ORACLE_SOURCE = SPIKE / "auth_integrated_oracle.py"
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench"
OUTPUT_ASM = BUILD / "width7_ecdsa_bench.asm"
TABLE_PATHS = {
    "g": BUILD / "width7-ecdsa-g.bin",
    "anchor": BUILD / "width7-ecdsa-anchor.bin",
    "leaf": BUILD / "width7-ecdsa-leaf.bin",
}
METADATA = BUILD / "width7-ecdsa-build.json"

WIDTH = 7
COLUMNS = math.ceil(256 / WIDTH)
POINT_BYTES = 64
POINTS_PER_BASE = (1 << WIDTH) - 1


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def build_comb(oracle: ModuleType, point: tuple[int, int]) -> list[tuple[int, int]]:
    """Return T[i]=sum(bit_j(i)*2**(j*d)*P), excluding T[0]."""
    teeth = [point]
    for _ in range(1, WIDTH):
        tooth = teeth[-1]
        for _ in range(COLUMNS):
            tooth = oracle.P256.point_add(tooth, tooth)
            if tooth is None:
                raise AssertionError("unexpected infinity while deriving comb tooth")
        teeth.append(tooth)

    table: list[tuple[int, int] | None] = [None] * (1 << WIDTH)
    for index in range(1, 1 << WIDTH):
        low_bit = index & -index
        tooth_index = low_bit.bit_length() - 1
        value = oracle.P256.point_add(table[index ^ low_bit], teeth[tooth_index])
        if value is None or not oracle.P256.is_on_curve(value):
            raise AssertionError(f"invalid comb table point {index}")
        table[index] = value
    return [point for point in table[1:] if point is not None]


def serialize_table(points: list[tuple[int, int]]) -> bytes:
    if len(points) != POINTS_PER_BASE:
        raise AssertionError("width-7 table lost an entry")
    output = bytearray()
    for x, y in points:
        output.extend(x.to_bytes(32, "little"))
        output.extend(y.to_bytes(32, "little"))
    expected = POINTS_PER_BASE * POINT_BYTES
    if len(output) != expected:
        raise AssertionError((len(output), expected))
    return bytes(output)


def replace_once(source: str, old: str, new: str, description: str) -> str:
    count = source.count(old)
    if count != 1:
        raise AssertionError(f"{description}: expected one source match, found {count}")
    return source.replace(old, new, 1)


VERIFY_DISPATCH_OLD = """auth_verify_certificate:
    mov word [auth_signature_ptr], auth_certificate_signature
    mov word [auth_signature_len], auth_certificate_signature_len
    mov word [auth_digest_ptr], auth_certificate_digest_be
    jmp auth_ecdsa_verify

auth_build_leaf_table:
    mov word [p256_affine_x_ptr], auth_leaf_x
    mov word [p256_affine_y_ptr], auth_leaf_y
    call p256_w_build_table
    clc
    ret

auth_verify_certificate_verify:
    mov word [auth_signature_ptr], auth_cv_signature
    mov word [auth_signature_len], auth_cv_signature_len
    mov word [auth_digest_ptr], auth_cv_digest_be
    jmp auth_ecdsa_verify
"""

VERIFY_DISPATCH_NEW = """auth_verify_certificate:
    mov word [auth_comb_q_table_ptr], auth_comb_anchor_table
    mov word [auth_signature_ptr], auth_certificate_signature
    mov word [auth_signature_len], auth_certificate_signature_len
    mov word [auth_digest_ptr], auth_certificate_digest_be
    jmp auth_ecdsa_verify

auth_build_leaf_table:
    ; Preserve the original benchmark phase boundary.  The width-7 leaf table
    ; was generated before the timed server-dependent path.
    clc
    ret

auth_verify_certificate_verify:
    mov word [auth_comb_q_table_ptr], auth_comb_leaf_table
    mov word [auth_signature_ptr], auth_cv_signature
    mov word [auth_signature_len], auth_cv_signature_len
    mov word [auth_digest_ptr], auth_cv_digest_be
    jmp auth_ecdsa_verify
"""

COMB_LOOP = """auth_ecdsa_straus_start:
    call p256_point_set_infinity
    mov word [auth_loop_index], 37
.column:
    dec word [auth_loop_index]
    call p256_point_double_jacobian

    mov si, auth_u1
    call auth_comb_index
    mov bx, auth_comb_g_table
    call auth_comb_add_index

    mov si, auth_u2
    call auth_comb_index
    mov bx, [auth_comb_q_table_ptr]
    call auth_comb_add_index

    cmp word [auth_loop_index], 0
    jne .column

auth_ecdsa_straus_end:
"""

COMB_HELPERS = """
; Return the seven-bit comb digit for scalar SI at the current column.
auth_comb_index:
    push bx
    push cx
    push dx
    push si
    push di
    mov [auth_comb_scalar_ptr], si
    mov ax, [auth_loop_index]
    mov [auth_comb_bit_position], ax
    mov word [auth_comb_index_value], 0
    mov word [auth_comb_index_mask], 1
    mov di, 7
.tooth:
    mov ax, [auth_comb_bit_position]
    cmp ax, 256
    jae .next
    mov dx, ax
    and dx, 15
    mov cl, 4
    shr ax, cl
    shl ax, 1
    mov bx, [auth_comb_scalar_ptr]
    add bx, ax
    mov ax, [bx]
    mov cl, dl
    shr ax, cl
    test al, 1
    jz .next
    mov ax, [auth_comb_index_mask]
    or [auth_comb_index_value], ax
.next:
    shl word [auth_comb_index_mask], 1
    add word [auth_comb_bit_position], 37
    dec di
    jnz .tooth
    mov ax, [auth_comb_index_value]
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    ret

; Add width-7 table entry AX (zero means no point), table base BX.
auth_comb_add_index:
    or ax, ax
    jz .done
    push ax
    push bx
    push cx
    dec ax
    mov cl, 6
    shl ax, cl
    add bx, ax
    mov [p256_affine_x_ptr], bx
    add bx, 32
    mov [p256_affine_y_ptr], bx
    call p256_point_add_mixed
    pop cx
    pop bx
    pop ax
.done:
    ret
"""


def generated_source(table_paths: dict[str, Path]) -> str:
    source = SOURCE.read_text()
    source = replace_once(
        source,
        "auth_stack_guard_start equ 0x3a00",
        "auth_stack_guard_start equ 0xe000",
        "stack guard relocation",
    )
    source = replace_once(
        source,
        "auth_stack_top equ 0x3ff0",
        "auth_stack_top equ 0xeff0",
        "stack relocation",
    )
    source = replace_once(
        source,
        VERIFY_DISPATCH_OLD,
        VERIFY_DISPATCH_NEW,
        "verification table dispatch",
    )
    source = replace_once(
        source,
        "    call serial_init\n    call auth_fill_stack_guard\n",
        (
            "    call serial_init\n"
            "    mov si, tag_width7_start\n"
            "    call emit_str\n"
            "    call emit_crlf\n"
            "    ; Fill while interrupts are disabled and no call frame is live;\n"
            "    ; the original helper overwrites its own return address.\n"
            "    mov al, 0xa5\n"
            "    mov di, auth_stack_guard_start\n"
            "    mov cx, auth_stack_top - auth_stack_guard_start\n"
            "    rep stosb\n"
            "    mov si, tag_width7_guard\n"
            "    call emit_str\n"
            "    call emit_crlf\n"
            "    sti\n"
        ),
        "startup/stack-guard marker",
    )
    source = replace_once(
        source,
        "    mov [auth_tick0], ax\n\n    call auth_prepare\n    jc .fail\n",
        (
            "    mov [auth_tick0], ax\n"
            "    mov si, tag_width7_tick\n"
            "    call emit_str\n"
            "    call emit_crlf\n\n"
            "    call auth_prepare\n"
            "    jc .fail\n"
            "    mov si, tag_width7_prepare\n"
            "    call emit_str\n"
            "    call emit_crlf\n"
        ),
        "prepare marker",
    )
    source = replace_once(
        source,
        "    call auth_verify_certificate\n    jc .fail\n",
        (
            "    call auth_verify_certificate\n"
            "    jc .fail\n"
            "    mov si, tag_width7_certificate\n"
            "    call emit_str\n"
            "    call emit_crlf\n"
        ),
        "certificate marker",
    )
    source = replace_once(
        source,
        "    call auth_verify_certificate_verify\n    jc .fail\n",
        (
            "    call auth_verify_certificate_verify\n"
            "    jc .fail\n"
            "    mov si, tag_width7_cv\n"
            "    call emit_str\n"
            "    call emit_crlf\n"
        ),
        "CertificateVerify marker",
    )

    recode_start = source.index("    ; Recode u1 and retain its digits separately.")
    recode_end = source.index("auth_ecdsa_scalar_prep_end:", recode_start)
    source = (
        source[:recode_start]
        + "    ; Width-7 comb reads u1/u2 directly; no wNAF recode is needed.\n\n"
        + source[recode_end:]
    )

    loop_start = source.index("auth_ecdsa_straus_start:")
    loop_end = source.index("auth_ecdsa_straus_end:", loop_start)
    loop_end += len("auth_ecdsa_straus_end:\n")
    source = source[:loop_start] + COMB_LOOP + source[loop_end:]

    helper_insert = source.index("; Strict short-form DER parser")
    source = source[:helper_insert] + COMB_HELPERS + "\n" + source[helper_insert:]

    table_text = f"""
align 2
auth_comb_q_table_ptr: dw 0
auth_comb_scalar_ptr: dw 0
auth_comb_bit_position: dw 0
auth_comb_index_value: dw 0
auth_comb_index_mask: dw 0
tag_width7_start: db 'WIDTH7 START', 0
tag_width7_guard: db 'WIDTH7 GUARD', 0
tag_width7_tick: db 'WIDTH7 TICK', 0
tag_width7_prepare: db 'WIDTH7 PREPARE', 0
tag_width7_certificate: db 'WIDTH7 CERTIFICATE', 0
tag_width7_cv: db 'WIDTH7 CV', 0

align 2
auth_comb_g_table:
    incbin "{table_paths['g']}"
auth_comb_anchor_table:
    incbin "{table_paths['anchor']}"
auth_comb_leaf_table:
    incbin "{table_paths['leaf']}"

"""
    source = replace_once(
        source,
        "image_end:\n",
        table_text + "image_end:\n",
        "table insertion",
    )
    return source


def main() -> None:
    oracle = load_module(ORACLE_SOURCE, "seed_width7_auth_oracle")
    fixture = oracle.make_fixture()
    points = {
        "g": oracle.G,
        "anchor": fixture.anchor_point,
        "leaf": fixture.leaf_point,
    }
    BUILD.mkdir(parents=True, exist_ok=True)
    table_report: dict[str, object] = {}
    for name, point in points.items():
        encoded = serialize_table(build_comb(oracle, point))
        TABLE_PATHS[name].write_bytes(encoded)
        table_report[name] = {
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "point_x": f"{point[0]:064x}",
            "point_y": f"{point[1]:064x}",
        }

    transformed = generated_source(TABLE_PATHS)
    OUTPUT_ASM.write_text(transformed)
    report = {
        "source": str(SOURCE.relative_to(ROOT)),
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "output": str(OUTPUT_ASM.relative_to(ROOT)),
        "output_sha256": hashlib.sha256(transformed.encode()).hexdigest(),
        "width": WIDTH,
        "columns": COLUMNS,
        "points_per_base": POINTS_PER_BASE,
        "table_bytes_three_bases": 3 * POINTS_PER_BASE * POINT_BYTES,
        "tables": table_report,
        "scope": (
            "exact target ECDSA verifier; immutable tables stand in for "
            "same-machine pre-TCP generation"
        ),
    }
    METADATA.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
