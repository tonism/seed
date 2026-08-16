#!/usr/bin/env python3
"""Build exact X25519 variants with the secret scalar scheduled before TCP.

The baseline RFC 7748 bench performs two full-field conditional swaps for
every Montgomery-ladder bit.  Seed knows and clamps its ephemeral scalar before
opening TCP, so this spike expands the 255 scalar bits into a fixed schedule
outside the timed server-dependent operation.  Each scheduled step executes
the same differential add plus doubling, but writes them directly to the
correct R0/R1 slots instead of swapping 64 words around the arithmetic.

This is an optimization experiment, not yet a product side-channel decision:
the scheduled branch exposes scalar-bit-dependent memory access and therefore
must be replaced or explicitly justified before it can form the secure tier.
The RFC 7748 public/share KATs remain the target-side correctness gate.
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
OUTPUT = BUILD / "x25519_fixed_schedule_bench.asm"
METADATA = BUILD / "x25519-fixed-schedule-build.json"


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise AssertionError(f"{label}: expected one match, found {count}")
    return source.replace(old, new, 1)


SCHEDULE_BUILD = """
    ; Expand the clamped scalar once, before either timed multiplication.
    mov si, scalar_work + 31
    mov di, ladder_schedule
    mov byte [ladder_scalar_mask], 0x40
    mov cx, 255
.schedule_bit:
    xor ax, ax
    mov al, [si]
    and al, [ladder_scalar_mask]
    neg ax
    sbb ax, ax
    and al, 1
    stosb
    shr byte [ladder_scalar_mask], 1
    jnz .schedule_mask_ready
    mov byte [ladder_scalar_mask], 0x80
    dec si
.schedule_mask_ready:
    loop .schedule_bit
"""


LADDER = r"""%macro X25519_SCHEDULED_STEP 8
    ; A/AA/B/BB/E for the point selected for doubling.
    mov si, %1
    mov di, %2
    mov bx, fe_a
    call fe_add
    mov si, fe_a
    mov bx, fe_aa
    call fe_sq
    mov si, %1
    mov di, %2
    mov bx, fe_b
    call fe_sub
    mov si, fe_b
    mov bx, fe_bb
    call fe_sq
    mov si, fe_aa
    mov di, fe_bb
    mov bx, fe_e
    call fe_sub

    ; C/D for the other ladder point; differential add is symmetric.
    mov si, %3
    mov di, %4
    mov bx, fe_c
    call fe_add
    mov si, %3
    mov di, %4
    mov bx, fe_d
    call fe_sub
    mov si, fe_d
    mov di, fe_a
    mov bx, fe_da
    call fe_mul
    mov si, fe_c
    mov di, fe_b
    mov bx, fe_cb
    call fe_mul

    ; Scheduled differential-add destination.
    mov si, fe_da
    mov di, fe_cb
    mov bx, fe_tmp
    call fe_add
    mov si, fe_tmp
    mov bx, %7
    call fe_sq
    mov si, fe_da
    mov di, fe_cb
    mov bx, fe_tmp
    call fe_sub
    mov si, fe_tmp
    mov bx, fe_t0
    call fe_sq
    mov si, fe_x1
    mov di, fe_t0
    mov bx, %8
    call fe_mul

    ; Scheduled doubling destination.
    mov si, fe_aa
    mov di, fe_bb
    mov bx, %5
    call fe_mul
    mov si, fe_e
    mov bx, fe_tmp
    call fe_mul_a24
    mov si, fe_aa
    mov di, fe_tmp
    mov bx, fe_tmp
    call fe_add
    mov si, fe_e
    mov di, fe_tmp
    mov bx, %6
    call fe_mul
%endmacro

x25519_shared:
    mov di, fe_x2
    call fe_one
    mov di, fe_z2
    call fe_zero
    mov si, fe_x1
    mov di, fe_x3
    call fe_copy
    mov di, fe_z3
    call fe_one

    mov word [ladder_schedule_ptr], ladder_schedule
    mov word [ladder_count], 255
.bit_loop:
    mov si, [ladder_schedule_ptr]
    lodsb
    mov [ladder_schedule_ptr], si
    or al, al
    jnz .bit_one
    call x25519_step_zero
    jmp short .step_done
.bit_one:
    call x25519_step_one
.step_done:
    dec word [ladder_count]
    jnz .bit_loop

    mov si, fe_z2
    mov bx, fe_inv
    call fe_invert
    mov si, fe_x2
    mov di, fe_inv
    mov bx, x25519_output
    call fe_mul
    ret

x25519_step_zero:
    X25519_SCHEDULED_STEP fe_x2, fe_z2, fe_x3, fe_z3, fe_x2, fe_z2, fe_x3, fe_z3
    ret

x25519_step_one:
    X25519_SCHEDULED_STEP fe_x3, fe_z3, fe_x2, fe_z2, fe_x3, fe_z3, fe_x2, fe_z2
    ret

"""


BINARY_INVERSE = r"""fe_invert:
    ; Variable-time binary extended-GCD experiment for p=2^255-19.
    mov [inv_z_ptr], si
    mov [inv_out_ptr], bx
    mov si, [inv_z_ptr]
    mov di, fe_bi_u
    call fe_copy
    mov si, fe_prime
    mov di, fe_bi_v
    call fe_copy
    mov di, fe_bi_x1
    call fe_one
    mov di, fe_bi_x2
    call fe_zero

.main:
    mov si, fe_bi_u
    call fe_bi_is_one
    jc .copy_x1
    mov si, fe_bi_v
    call fe_bi_is_one
    jc .copy_x2
.reduce_u:
    test word [fe_bi_u], 1
    jnz .reduce_v
    mov di, fe_bi_u
    call fe_bi_rshift1
    test word [fe_bi_x1], 1
    jnz .x1_odd
    mov di, fe_bi_x1
    call fe_bi_rshift1
    jmp .reduce_u
.x1_odd:
    mov di, fe_bi_x1
    call fe_bi_add_prime_rshift1
    jmp .reduce_u
.reduce_v:
    test word [fe_bi_v], 1
    jnz .subtract
    mov di, fe_bi_v
    call fe_bi_rshift1
    test word [fe_bi_x2], 1
    jnz .x2_odd
    mov di, fe_bi_x2
    call fe_bi_rshift1
    jmp .reduce_v
.x2_odd:
    mov di, fe_bi_x2
    call fe_bi_add_prime_rshift1
    jmp .reduce_v
.subtract:
    mov si, fe_bi_u
    mov di, fe_bi_v
    call fe_bi_cmp
    jc .v_larger
    mov si, fe_bi_u
    mov di, fe_bi_v
    mov bx, fe_bi_u
    call fe_bi_sub_words
    mov si, fe_bi_x1
    mov di, fe_bi_x2
    mov bx, fe_bi_x1
    call fe_sub
    jmp .main
.v_larger:
    mov si, fe_bi_v
    mov di, fe_bi_u
    mov bx, fe_bi_v
    call fe_bi_sub_words
    mov si, fe_bi_x2
    mov di, fe_bi_x1
    mov bx, fe_bi_x2
    call fe_sub
    jmp .main
.copy_x1:
    mov si, fe_bi_x1
    jmp short .copy
.copy_x2:
    mov si, fe_bi_x2
.copy:
    mov di, [inv_out_ptr]
    call fe_copy
    ret

; CF=1 only for the value one.
fe_bi_is_one:
    cmp word [si], 1
    jne .no
    add si, 2
    mov cx, 15
.word:
    cmp word [si], 0
    jne .no
    add si, 2
    loop .word
    stc
    ret
.no:
    clc
    ret

; CF=1 when SI < DI.
fe_bi_cmp:
    add si, 30
    add di, 30
    mov cx, 16
.word:
    mov ax, [si]
    cmp ax, [di]
    jb .less
    ja .greater
    sub si, 2
    sub di, 2
    loop .word
.greater:
    clc
    ret
.less:
    stc
    ret

; BX = SI - DI, with SI/BX aliasing permitted.
fe_bi_sub_words:
    mov cx, 16
    clc
.word:
    mov ax, [si]
    sbb ax, [di]
    mov [bx], ax
    add si, 2
    add di, 2
    add bx, 2
    loop .word
    ret

fe_bi_rshift1:
    add di, 30
    mov cx, 16
    clc
.word:
    rcr word [di], 1
    sub di, 2
    loop .word
    ret

; DI = (DI + p) / 2, retaining the carry above bit 255.
fe_bi_add_prime_rshift1:
    push di
    mov si, fe_prime
    mov cx, 16
    clc
.add:
    mov ax, [si]
    adc [di], ax
    add si, 2
    add di, 2
    loop .add
    pop di
    lea di, [di + 30]
    mov cx, 16
.shift:
    rcr word [di], 1
    sub di, 2
    loop .shift
    ret

"""


def build_source(binary_inverse: bool) -> str:
    source = SOURCE.read_text()
    clamp_tail = """    and byte [scalar_work], 248
    and byte [scalar_work + 31], 127
    or byte [scalar_work + 31], 64
"""
    source = replace_once(
        source,
        clamp_tail,
        clamp_tail + SCHEDULE_BUILD,
        "offline scalar schedule",
    )

    ladder_start = source.index("x25519_shared:")
    ladder_end = source.index("; Constant-time conditional swap", ladder_start)
    source = source[:ladder_start] + LADDER + source[ladder_end:]

    if binary_inverse:
        inverse_start = source.index("fe_invert:")
        inverse_end = source.index(
            "; SI=input, BX=output, CX=count.", inverse_start
        )
        source = source[:inverse_start] + BINARY_INVERSE + "\n" + source[inverse_end:]

    data = """
ladder_schedule_ptr: dw 0
ladder_schedule: times 255 db 0
fe_bi_u: times 16 dw 0
fe_bi_v: times 16 dw 0
fe_bi_x1: times 16 dw 0
fe_bi_x2: times 16 dw 0
"""
    source = replace_once(
        source,
        "image_end:\n",
        data + "\nimage_end:\n",
        "schedule data",
    )
    return source


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary-inverse", action="store_true")
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    output = (
        BUILD / "x25519_fixed_binary_inverse_bench.asm"
        if args.binary_inverse
        else OUTPUT
    )
    metadata = (
        BUILD / "x25519-fixed-binary-inverse-build.json"
        if args.binary_inverse
        else METADATA
    )
    source = build_source(args.binary_inverse)
    output.write_text(source)
    report = {
        "source": str(SOURCE.relative_to(ROOT)),
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "output": str(output.relative_to(ROOT)),
        "output_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "offline_schedule_bytes": 255,
        "binary_inverse": args.binary_inverse,
        "timed_server_operation": (
            "255 differential-add/double steps without full-field cswap"
        ),
        "security_caveat": (
            "scalar-bit-dependent branch/memory schedule is not yet an accepted "
            "secure-tier side-channel boundary"
        ),
    }
    metadata.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
