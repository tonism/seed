#!/usr/bin/env python3
"""Build the measured X25519 core as a callable ``S286MOD2`` image.

The timing spike deliberately boots as a complete standalone program.  This
builder reuses its generated straight-line arithmetic, removes the benchmark
harness and fixed RFC inputs, and supplies the product descriptor boundary
defined by ``tls13_286_abi.inc``.

The result is fixed at physical ``0000:4230``.  It is therefore directly
callable after a raw-LZ4 decode and needs no relocation records.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench"
GENERATOR = HERE / "build_x25519_unrolled.py"
OUTPUT_ASM = BUILD / "tls13-286-x25519-module.asm"
OUTPUT_BIN = BUILD / "tls13-286-x25519-module.bin"
OUTPUT_LISTING = BUILD / "tls13-286-x25519-module.lst"
REPORT = BUILD / "tls13-286-x25519-module.json"
META_INCLUDE = BUILD / "tls13-286-x25519-product-meta.inc"


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MODULE_PREFIX = r"""bits 16
cpu 8086

%include "tls13/tls13_286_abi.inc"
org tls13_286_module_load

fe_words equ 16
fe_bytes equ 32

module_header:
    db 'S286MOD2'
    dw tls13_286_abi_version
    dw tls13_286_mod_kind_x25519
    dw image_end - module_header
    dw module_entry - module_header
    dw tls13_286_state_bytes
    dw 256
    dw tls13_286_mod_flag_one_shot
    times tls13_286_mod_header_bytes - ($ - module_header) db 0

; AX=operation, SI=one tls13_286_desc_* structure, DI=0.
; BX=tls13_286_root_state_loader exactly.  DS=ES=SS=0 and DF=0 are required
; at entry.  Product spans are bound to the unique X25519 slots consumed by
; HELLO; this one-shot image retains no caller-selectable output address.
module_entry:
    push bp
    cld
    mov dx, sp
    test dx, 1
    jnz module_error_stack
    cmp dx, tls13_286_module_limit + 256
    jb module_error_stack
    cmp dx, 0x8000
    jae module_error_stack
    or di, di
    jnz module_error_abi
    cmp si, tls13_286_controller_load
    jb module_error_bounds
    cmp si, tls13_286_controller_limit - tls13_286_desc_bytes
    ja module_error_bounds
    cmp word [si + tls13_286_desc_flags], 0
    jne module_error_abi
    cmp word [si + tls13_286_desc_op], ax
    jne module_error_abi
    cmp ax, tls13_286_mod_op_x25519_keygen
    je .operation_ok
    cmp ax, tls13_286_mod_op_x25519_shared
    jne module_error_abi
.operation_ok:
    cmp bx, tls13_286_root_state_loader
    jne module_error_bounds
    cmp word [bx + tls13_286_state_cache_capacity], \
        tls13_286_pack_cache_bytes
    jne module_error_bounds
    mov dx, [bx + tls13_286_state_cache_seg]
    cmp dx, 0x7000
    jb module_error_bounds
    cmp dx, 0x9000
    ja module_error_bounds
    test dx, 0x003f
    jnz module_error_bounds
    mov [module_crypto_seg], dx
    mov [module_operation], ax
    mov [module_desc], si

    call module_validate_shape
    jc module_error_bounds

    mov bx, si
    add bx, tls13_286_desc_input0
    mov dx, fe_bytes
    mov di, scalar_work
    call module_copy_span_to_near
    and byte [scalar_work], 248
    and byte [scalar_work + 31], 127
    or byte [scalar_work + 31], 64

    cmp word [module_operation], tls13_286_mod_op_x25519_keygen
    je .keygen

    mov bx, [module_desc]
    add bx, tls13_286_desc_input1
    mov dx, fe_bytes
    mov di, fe_x1
    call module_copy_span_to_near
    and word [fe_x1 + 30], 0x7fff
    jmp short .run

.keygen:
    mov di, fe_x1
    call fe_zero
    mov word [fe_x1], 9

.run:
    call x25519_shared

    ; RFC 7748 permits an all-zero result, but TLS key exchange must reject
    ; the small-order/all-zero outcome rather than deriving traffic keys.
    cmp word [module_operation], tls13_286_mod_op_x25519_shared
    jne .copy_result
    xor ax, ax
    mov si, x25519_output
    mov cx, fe_words
.nonzero:
    or ax, [si]
    add si, 2
    loop .nonzero
    or ax, ax
    jz module_error_crypto_wipe

.copy_result:
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov si, x25519_output
    mov dx, fe_bytes
    call module_copy_near_to_span
    call module_wipe
    xor dx, dx
    jmp module_finish_result

module_error_abi:
    call module_wipe
    mov dx, tls13_286_error_abi
    jmp module_finish_result
module_error_bounds:
    call module_wipe
    mov dx, tls13_286_error_bounds
    jmp module_finish_result
module_error_crypto_wipe:
    call module_wipe
    mov dx, tls13_286_error_crypto
    jmp module_finish_result
module_error_stack:
    mov ax, tls13_286_error_bounds
    stc
    pop bp
    ret

; Validate the exact product descriptor before copying the private scalar.
; Key generation consumes only input0/output0; shared-secret derivation adds
; input1.  Every inactive span must be encoded as eight zero bytes.
module_validate_shape:
    mov bx, [module_desc]
    add bx, tls13_286_desc_input0
    mov ax, tls13_286_x25519_scalar_off
    mov dx, fe_bytes
    call module_validate_high_at
    jc .bad

    mov bx, [module_desc]
    add bx, tls13_286_desc_input2
    call module_validate_zero_span
    jc .bad
    add bx, tls13_286_span_bytes
    call module_validate_zero_span
    jc .bad
    mov bx, [module_desc]
    add bx, tls13_286_desc_output1
    call module_validate_zero_span
    jc .bad

    cmp word [module_operation], tls13_286_mod_op_x25519_shared
    je .shared

    mov bx, [module_desc]
    add bx, tls13_286_desc_input1
    call module_validate_zero_span
    jc .bad
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov ax, tls13_286_client_x_public
    mov dx, fe_bytes
    call module_validate_low_at
    ret

.shared:
    mov bx, [module_desc]
    add bx, tls13_286_desc_input1
    mov ax, tls13_286_hello_server_x_off
    mov dx, fe_bytes
    call module_validate_low_at
    jc .bad
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov ax, tls13_286_hybrid_secret_off + 32
    mov dx, fe_bytes
    call module_validate_high_at
    ret
.bad:
    stc
    ret

; BX=span, DX=required exact byte count.  Canonical conventional-RAM spans
; use segment=physical>>4 and offset=physical&15.  Their exclusive physical
; end may equal 0xa0000 but must never cross into VGA/ROM space.
module_validate_span:
    cmp word [bx + tls13_286_span_len], dx
    jne module_span_bad
    cmp word [bx + tls13_286_span_len + 2], 0
    jne module_span_bad
    cmp word [bx + tls13_286_span_off], 15
    ja module_span_bad
    cmp word [bx + tls13_286_span_seg], 0xa000
    jae module_span_bad
    mov ax, [bx + tls13_286_span_off]
    mov cx, [bx + tls13_286_span_seg]
    xor di, di
    xchg ax, cx
    push cx
    mov cx, 4
.shift_segment:
    shl ax, 1
    rcl di, 1
    loop .shift_segment
    pop cx
    add ax, cx
    adc di, 0
    add ax, dx
    adc di, 0
    cmp di, 0x000a
    jb .good
    ja module_span_bad
    or ax, ax
    jnz module_span_bad
.good:
    clc
    ret
module_span_bad:
    stc
    ret

module_validate_zero_span:
    mov ax, [bx + tls13_286_span_off]
    or ax, [bx + tls13_286_span_seg]
    or ax, [bx + tls13_286_span_len]
    or ax, [bx + tls13_286_span_len + 2]
    jnz module_span_bad
    clc
    ret

; BX=span, AX=exact offset inside the validated top reservation, DX=length.
module_validate_high_at:
    push cx
    mov cx, ax
    and ax, 15
    cmp [bx + tls13_286_span_off], ax
    jne .bad
    mov ax, cx
    mov cl, 4
    shr ax, cl
    add ax, [module_crypto_seg]
    cmp [bx + tls13_286_span_seg], ax
    jne .bad
    pop cx
    jmp module_validate_span
.bad:
    pop cx
    stc
    ret

; BX=span, AX=exact low physical address, DX=length.
module_validate_low_at:
    push cx
    mov cx, ax
    and ax, 15
    cmp [bx + tls13_286_span_off], ax
    jne .bad
    mov ax, cx
    mov cl, 4
    shr ax, cl
    cmp [bx + tls13_286_span_seg], ax
    jne .bad
    pop cx
    jmp module_validate_span
.bad:
    pop cx
    stc
    ret

; BX=validated span, DI=near destination, DX=length.
module_copy_span_to_near:
    push ds
    push es
    mov ax, [bx + tls13_286_span_seg]
    mov si, [bx + tls13_286_span_off]
    mov ds, ax
    xor ax, ax
    mov es, ax
    mov cx, dx
    rep movsb
    pop es
    pop ds
    ret

; BX=validated output span, SI=near source, DX=length.
module_copy_near_to_span:
    push es
    mov ax, [bx + tls13_286_span_seg]
    mov es, ax
    mov di, [bx + tls13_286_span_off]
    mov cx, dx
    rep movsb
    pop es
    ret

module_wipe:
    push ax
    push cx
    push di
    push es
    xor ax, ax
    mov es, ax
    mov di, module_secret_start
    mov cx, image_end - module_secret_start
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

; With all arithmetic calls returned, SP points at the saved caller BP.  Wipe
; every now-free stack word below it, then use an IRET frame to restore the
; caller interrupt state and publish CF atomically.  No interrupt can spill
; secret-bearing volatile registers between the scrub and the return.
module_finish_result:
    pushf
    pop bx
    cli
    and bx, 0xfffe
    or dx, dx
    jz .status_ready
    or bx, 1
.status_ready:
    mov cx, sp
    mov di, tls13_286_module_limit
    sub cx, di
    shr cx, 1
    xor ax, ax
    mov es, ax
    rep stosw
    mov ax, dx
    pop bp
    pop si
    push bx
    push cs
    push si
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    iret

; ---------------------------------------------------------------------------
; X25519 Montgomery ladder
; ---------------------------------------------------------------------------
"""


def product_source() -> str:
    generator = load_module(GENERATOR, "seed_x25519_unrolled_generator")
    source = generator.build_source(False)

    ladder_marker = (
        "; ---------------------------------------------------------------------------\n"
        "; X25519 Montgomery ladder\n"
        "; ---------------------------------------------------------------------------\n\n"
    )
    ladder = source[source.index(ladder_marker) + len(ladder_marker) :]

    harness_marker = (
        "; ---------------------------------------------------------------------------\n"
        "; Harness I/O\n"
        "; ---------------------------------------------------------------------------\n"
    )
    ladder = ladder[: ladder.index(harness_marker)]

    # Retain only arithmetic constants/state from the old fixed-vector tail.
    state = source[source.index("fe_prime:\n") :]
    state = state[: state.index("image_end:\n")]
    for dead in (
        "t0_lo dw 0\n",
        "t0_hi dw 0\n",
        "dt_lo dw 0\n",
        "case_expected_ptr dw 0\n",
        "case_check_tag dw 0\n",
    ):
        state = state.replace(dead, "", 1)
    state = state.replace(
        "\n\nladder_scalar_ptr dw 0\n",
        (
            "\n\nmodule_secret_start:\n"
            "module_operation dw 0\n"
            "module_desc dw 0\n"
            "module_crypto_seg dw 0\n"
            "ladder_scalar_ptr dw 0\n"
        ),
        1,
    )
    if "module_secret_start:" not in state:
        raise AssertionError("X25519 writable-state marker drifted")

    return MODULE_PREFIX + ladder + state + "image_end:\n"


def label_offset(listing: Path, label: str) -> int:
    lines = listing.read_text().splitlines()
    pattern = re.compile(rf"\b{re.escape(label)}:")
    offset = re.compile(r"\s([0-9A-F]{8})\s")
    for index, line in enumerate(lines):
        if pattern.search(line) is None:
            continue
        for candidate in lines[index : index + 4]:
            match = offset.search(candidate)
            if match is not None:
                return int(match.group(1), 16)
    raise AssertionError(f"missing {label} in {listing}")


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    source = product_source()
    OUTPUT_ASM.write_text(source)
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            "-Itargets/ibm_pc_5150/boot/",
            "-l",
            str(OUTPUT_LISTING),
            "-o",
            str(OUTPUT_BIN),
            str(OUTPUT_ASM),
        ],
        cwd=ROOT,
        check=True,
    )
    image = OUTPUT_BIN.read_bytes()
    if not image.startswith(b"S286MOD2"):
        raise AssertionError("product module lost S286MOD2 header")
    if len(image) > 0x3800:
        raise AssertionError(f"X25519 product module exceeds overlay: {len(image)}")
    wipe_start = label_offset(OUTPUT_LISTING, "module_secret_start")
    if not 0 < wipe_start < len(image):
        raise AssertionError("X25519 wipe range is outside module image")
    META_INCLUDE.write_text(
        f"x25519_module_bytes equ {len(image)}\n"
        f"x25519_wipe_start_off equ {wipe_start}\n"
        f"x25519_wipe_bytes equ {len(image) - wipe_start}\n"
    )
    report = {
        "format": "S286MOD2",
        "abi": 2,
        "kind": "X25519",
        "origin": "0000:4230",
        "operations": ["X25519 keygen", "X25519 shared"],
        "bytes": len(image),
        "overlay_headroom": 0x3800 - len(image),
        "one_shot_wipe": True,
        "private_state_wipe_offset": wipe_start,
        "private_state_wipe_bytes": len(image) - wipe_start,
        "stack_residue_wipe": "0x7a00..entry-SP, interrupt-safe IRET",
        "descriptor_policy": {
            "controller_state": "exact root_state_loader",
            "canonical_spans": True,
            "exact_product_slots": True,
            "inactive_spans_zero": True,
        },
        "sha256": hashlib.sha256(image).hexdigest(),
        "source": str(OUTPUT_ASM.relative_to(ROOT)),
        "image": str(OUTPUT_BIN.relative_to(ROOT)),
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
