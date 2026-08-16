#!/usr/bin/env python3
"""Build descriptor-driven fixed-origin ML-KEM-768 product modules.

The arithmetic bodies remain the independently checked FIPS 203 assembly
spikes.  This builder removes their boot/serial harnesses and wraps the exact
cores in the ``S286MOD2`` descriptor ABI.  Inputs are copied from caller spans
into the core's writable fixture-shaped buffers, outputs are copied back to
caller spans, and the one-shot image wipes all retained KEM state before
returning.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPIKE = HERE.parent / "tls13-spike"
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench"

KEYGEN_SOURCE = SPIKE / "mlkem768_integrated_keygen.asm"
DECAP_SOURCE = SPIKE / "mlkem768_integrated_candidate.asm"
KEYGEN_CHECK = SPIKE / "mlkem768_integrated_keygen_check.py"
DECAP_CHECK = SPIKE / "mlkem768_integrated_check.py"

KEYGEN_ASM = BUILD / "tls13-286-mlkem-keygen-module.asm"
KEYGEN_BIN = BUILD / "tls13-286-mlkem-keygen-module.bin"
KEYGEN_LISTING = BUILD / "tls13-286-mlkem-keygen-module.lst"
DECAP_ASM = BUILD / "tls13-286-mlkem-decap-module.asm"
DECAP_BIN = BUILD / "tls13-286-mlkem-decap-module.bin"
DECAP_LISTING = BUILD / "tls13-286-mlkem-decap-module.lst"
REPORT = BUILD / "tls13-286-mlkem-product-modules.json"
META_INCLUDE = BUILD / "tls13-286-mlkem-product-meta.inc"

SEED_BIN = BUILD / "tls13-286-mlkem-seed.bin"
EXPECTED_DK_BIN = BUILD / "tls13-286-mlkem-expected-dk.bin"
CIPHERTEXT_BIN = BUILD / "tls13-286-mlkem-ciphertext.bin"
EXPECTED_SECRET_BIN = BUILD / "tls13-286-mlkem-expected-secret.bin"
EXPECTED_INVALID_CANDIDATE_BIN = (
    BUILD / "tls13-286-mlkem-expected-invalid-candidate.bin"
)
EXPECTED_INVALID_SECRET_BIN = (
    BUILD / "tls13-286-mlkem-expected-invalid-secret.bin"
)
EXPECTED_MATRIX_CACHE_BIN = (
    BUILD / "tls13-286-mlkem-expected-matrix-cache.bin"
)
EXPECTED_VALID_REJECTION_SECRET_BIN = (
    BUILD / "tls13-286-mlkem-expected-valid-rejection-secret.bin"
)

MATRIX_POLYNOMIALS = 9
MATRIX_POLY_BYTES = 512
MATRIX_CACHE_BYTES = MATRIX_POLYNOMIALS * MATRIX_POLY_BYTES


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COMMON_HELPERS = r"""
; BX=span, DX=required exact byte count.  Product spans are canonical
; physical addresses, never arbitrary segment:offset aliases.  The exclusive
; physical end may equal 0xa0000 but must never cross into VGA/ROM space.
module_validate_span:
    cmp word [bx + tls13_286_span_len], dx
    jne module_span_bad
    cmp word [bx + tls13_286_span_len + 2], 0
    jne module_span_bad
    cmp word [bx + tls13_286_span_off], 15
    ja module_span_bad
    cmp word [bx + tls13_286_span_seg], 0xa000
    jae module_span_bad
    mov ax, [bx + tls13_286_span_seg]
    xor di, di
    mov cx, 4
.shift_segment:
    shl ax, 1
    rcl di, 1
    loop .shift_segment
    add ax, [bx + tls13_286_span_off]
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

; BX=inactive span.  An exact per-operation descriptor has no alternate
; addresses hidden in fields that the selected operation does not consume.
module_validate_zero_span:
    mov ax, [bx + tls13_286_span_off]
    or ax, [bx + tls13_286_span_seg]
    or ax, [bx + tls13_286_span_len]
    or ax, [bx + tls13_286_span_len + 2]
    jnz module_span_bad
    clc
    ret

; BX=span, AX=exact offset inside the validated top 64 KiB reservation,
; DX=exact bytes.  Binding every ML-KEM object to its named product slot makes
; the non-alias policy explicit: outputs cannot target controller/module/stack
; memory or overwrite a private input, and inputs cannot be redirected to
; exfiltrate unrelated controller/private state.
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

; BX=span, AX=exact low physical address, DX=exact bytes.
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

; The conditioned seed may belong to either independently generated attempt.
module_validate_attempt_seed:
    push ax
    mov ax, tls13_286_attempt_acquire_off + tls13_286_attempt_d_off
    call module_validate_high_at
    jnc .done
    mov ax, tls13_286_attempt_fresh_off + tls13_286_attempt_d_off
    call module_validate_high_at
.done:
    pop ax
    ret

; Live ServerHello ciphertext is in the canonical low public slot; offline FO
; uses the status-last high candidate escrow.  No other source is accepted.
module_validate_ciphertext:
    push ax
    mov ax, tls13_286_hello_ciphertext_off
    call module_validate_low_at
    jnc .done
    mov ax, tls13_286_candidate_ciphertext_off
    call module_validate_high_at
.done:
    pop ax
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

; BX=validated span, SI=near source, DX=length.
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

; Tail-only module return path.  ML-KEM arithmetic uses the resident
; 0x7a00..0x7fff downward-growing stack guard for private intermediates.
; With all internal calls returned, SP points at the saved caller BP; scrub
; every now-free word below it without touching the live BP/return chain.
; DX is the final ABI status (zero for success).  IRET restores the caller's
; interrupt state and publishes CF atomically, so a timer interrupt cannot
; spill secret-bearing volatile registers after the scrub and before return.
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
"""


KEYGEN_PREFIX = r"""bits 16
cpu 8086

%include "tls13/tls13_286_abi.inc"
org tls13_286_module_load

poly_words equ 256
state_bytes equ 200

module_header:
    db 'S286MOD2'
    dw tls13_286_abi_version
    dw tls13_286_mod_kind_mlkem_keygen
    dw image_end - module_header
    dw module_entry - module_header
    dw tls13_286_state_bytes
    dw 256
    dw tls13_286_mod_flag_one_shot
    times tls13_286_mod_header_bytes - ($ - module_header) db 0

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
    mov [module_desc], si
    cmp ax, tls13_286_mod_op_sha3_256_condition
    je module_sha3_entry
    cmp ax, tls13_286_mod_op_mlkem_keygen
    jne module_error_abi

    call module_validate_input_tail_zero
    jc module_error_bounds
    mov bx, si
    add bx, tls13_286_desc_input0
    mov dx, 64
    call module_validate_attempt_seed
    jc module_error_bounds
    mov di, fixture_d_z
    call module_copy_span_to_near

    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov ax, tls13_286_hello_mlkem_ek_off
    mov dx, 1184
    call module_validate_low_at
    jc module_error_bounds_wipe
    mov bx, [module_desc]
    add bx, tls13_286_desc_output1
    mov ax, tls13_286_mlkem_dk_off
    mov dx, 2400
    call module_validate_high_at
    jc module_error_bounds_wipe

    call mlkem_keygen_internal
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov si, generated_dk + 1152
    mov dx, 1184
    call module_copy_near_to_span
    mov bx, [module_desc]
    add bx, tls13_286_desc_output1
    mov si, generated_dk
    mov dx, 2400
    call module_copy_near_to_span
    call module_wipe
    xor dx, dx
    jmp module_finish_result

module_sha3_entry:
    call module_validate_input_tail_zero
    jc module_error_bounds
    mov bx, [module_desc]
    add bx, tls13_286_desc_output1
    call module_validate_zero_span
    jc module_error_bounds
    mov bx, si
    add bx, tls13_286_desc_input0
    mov ax, tls13_286_entropy_raw_off
    mov dx, tls13_286_entropy_raw_bytes
    call module_validate_high_at
    jc module_error_bounds
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov ax, tls13_286_entropy_seed_off
    mov dx, 64
    call module_validate_high_at
    jc module_error_bounds
    mov byte [module_hash_domain_counter], 0
    call module_sha3_condition
    mov si, keccak_state
    mov di, module_conditioned
    mov cx, 32
    rep movsb
    mov byte [module_hash_domain_counter], 1
    call module_sha3_condition
    mov si, keccak_state
    mov di, module_conditioned + 32
    mov cx, 32
    rep movsb
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov si, module_conditioned
    mov dx, 64
    call module_copy_near_to_span
    call module_wipe
    xor dx, dx
    jmp module_finish_result

; Key generation and conditioning both consume only input0.  Reject any
; alternate addresses hidden in input1..input3 before reading private input.
module_validate_input_tail_zero:
    mov bx, [module_desc]
    add bx, tls13_286_desc_input1
    mov cx, 3
.next:
    call module_validate_zero_span
    jc .bad
    add bx, tls13_286_span_bytes
    loop .next
    clc
    ret
.bad:
    stc
    ret

; SHA3-256(domain || 1024 six-byte raw timing events).  The far input is read
; directly while all Keccak state remains in segment zero.
module_sha3_condition:
    call clear_keccak
    push ds
    pop es
    mov si, module_entropy_domain
    mov di, keccak_state
    mov cx, module_entropy_domain_len
    rep movsb
    mov al, [module_hash_domain_counter]
    xor [keccak_state + module_entropy_domain_len - 1], al
    mov word [module_hash_pos], module_entropy_domain_len
    mov word [module_hash_remaining], tls13_286_entropy_raw_bytes
    mov bx, [module_desc]
    add bx, tls13_286_desc_input0
    mov ax, [bx + tls13_286_span_seg]
    mov es, ax
    mov ax, [bx + tls13_286_span_off]
    mov [module_hash_input_off], ax
.byte:
    mov si, [module_hash_input_off]
    mov bx, [module_hash_pos]
    mov al, [es:si]
    xor [keccak_state + bx], al
    inc si
    mov [module_hash_input_off], si
    inc bx
    cmp bx, 136
    jne .position
    mov word [module_hash_pos], 0
    push es
    push ds
    pop es
    call keccak_f1600
    pop es
    jmp short .next
.position:
    mov [module_hash_pos], bx
.next:
    dec word [module_hash_remaining]
    jnz .byte
    mov bx, [module_hash_pos]
    xor byte [keccak_state + bx], 0x06
    xor byte [keccak_state + 135], 0x80
    push ds
    pop es
    call keccak_f1600
    ret

module_error_abi:
    mov dx, tls13_286_error_abi
    jmp module_finish_result
module_error_bounds_wipe:
    call module_wipe
module_error_bounds:
    mov dx, tls13_286_error_bounds
    jmp module_finish_result
module_error_stack:
    mov ax, tls13_286_error_bounds
    stc
    pop bp
    ret

module_desc: dw 0
module_crypto_seg: dw 0
module_entropy_domain db 'Seed 286 raw timing conditioner v1',0
module_entropy_domain_len equ $ - module_entropy_domain
"""


DECAP_PREFIX = r"""bits 16
cpu 8086

%include "tls13/tls13_286_abi.inc"
org tls13_286_module_load

poly_words equ 256
poly_bytes equ 512
state_bytes equ 200
dkpke_bytes equ 1152
ek_bytes equ 1184
h_offset equ dkpke_bytes + ek_bytes

module_header:
    db 'S286MOD2'
    dw tls13_286_abi_version
    dw tls13_286_mod_kind_mlkem_decap
    dw image_end - module_header
    dw module_entry - module_header
    dw tls13_286_state_bytes
    dw 256
    dw tls13_286_mod_flag_one_shot
    times tls13_286_mod_header_bytes - ($ - module_header) db 0

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
    cmp ax, tls13_286_mod_op_mlkem_decap
    je module_operation_ok
    cmp ax, tls13_286_mod_op_mlkem_decap_cached
    je module_operation_ok
    cmp ax, tls13_286_mod_op_mlkem_candidate
    je module_operation_ok
    cmp ax, tls13_286_mod_op_mlkem_matrix_precompute
    jne module_error_abi
module_operation_ok:
    mov [module_desc], si
    mov [module_op], al
    call module_validate_decap_shape
    jc module_error_bounds

    mov bx, si
    add bx, tls13_286_desc_input0
    mov ax, tls13_286_mlkem_dk_off
    mov dx, 2400
    call module_validate_high_at
    jc module_error_bounds
    mov di, fixture_dk
    call module_copy_span_to_near

    mov bx, [module_desc]
    cmp byte [module_op], \
        tls13_286_mod_op_mlkem_matrix_precompute
    je module_matrix_precompute
    add bx, tls13_286_desc_input1
    mov dx, 1088
    call module_validate_ciphertext
    jc module_error_bounds_wipe
    mov di, fixture_ciphertext
    call module_copy_span_to_near

    mov bx, [module_desc]
    cmp byte [module_op], \
        tls13_286_mod_op_mlkem_decap_cached
    jne module_validate_secret_output
    add bx, tls13_286_desc_input2
    call module_bind_cache
    jc module_error_bounds_wipe

module_validate_secret_output:
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov ax, tls13_286_hybrid_secret_off
    mov dx, 32
    call module_validate_high_at
    jc module_error_bounds_wipe

    cmp byte [module_op], \
        tls13_286_mod_op_mlkem_candidate
    je module_candidate
    cmp byte [module_op], \
        tls13_286_mod_op_mlkem_decap_cached
    je module_cached
    call mlkem_decaps
    mov si, selected_secret
    jmp short module_copy_secret
module_cached:
    call mlkem_decaps_cached
    mov si, selected_secret
    jmp short module_copy_secret
module_candidate:
    call mlkem_candidate
    mov si, candidate_g
module_copy_secret:
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov dx, 32
    call module_copy_near_to_span
module_success:
    call module_wipe
    xor dx, dx
    jmp module_finish_result

module_matrix_precompute:
    add bx, tls13_286_desc_output0
    call module_bind_cache
    jc module_error_bounds_wipe
    call mlkem_matrix_precompute
    jmp short module_success

module_bind_cache:
    mov ax, tls13_286_mlkem_matrix_stage_off
    mov dx, 4608
    call module_validate_high_at
    jc .done
    mov ax, [bx + tls13_286_span_off]
    mov [matrix_cache_off], ax
    mov ax, [bx + tls13_286_span_seg]
    mov [matrix_cache_seg], ax
.done:
    ret

; Every operation leaves input3 and output1 inactive.  Ordinary/candidate
; decapsulation also leaves input2 inactive; matrix precompute leaves both
; input1 and input2 inactive.  Cached decapsulation alone consumes input2.
module_validate_decap_shape:
    mov bx, [module_desc]
    add bx, tls13_286_desc_input3
    call module_validate_zero_span
    jc .bad
    mov bx, [module_desc]
    add bx, tls13_286_desc_output1
    call module_validate_zero_span
    jc .bad
    cmp byte [module_op], tls13_286_mod_op_mlkem_decap_cached
    je .good
    mov bx, [module_desc]
    add bx, tls13_286_desc_input2
    call module_validate_zero_span
    jc .bad
    cmp byte [module_op], tls13_286_mod_op_mlkem_matrix_precompute
    jne .good
    mov bx, [module_desc]
    add bx, tls13_286_desc_input1
    call module_validate_zero_span
    jc .bad
.good:
    clc
    ret
.bad:
    stc
    ret

module_error_abi:
    mov dx, tls13_286_error_abi
    jmp module_finish_result
module_error_bounds_wipe:
    call module_wipe
module_error_bounds:
    mov dx, tls13_286_error_bounds
    jmp module_finish_result
module_error_stack:
    mov ax, tls13_286_error_bounds
    stc
    pop bp
    ret

module_desc: dw 0
module_op: db 0
module_crypto_seg: dw 0
"""


def between(source: str, begin: str, end: str) -> str:
    start = source.index(begin)
    finish = source.index(end, start)
    return source[start:finish]


def build_keygen_source() -> str:
    source = KEYGEN_SOURCE.read_text()
    algorithm = between(
        source,
        "; ---------------------------------------------------------------------------\n"
        "; ML-KEM.KeyGen_internal",
        "; ---------------------------------------------------------------------------\n"
        "; Timing and serial output",
    )
    algorithm = algorithm.replace(
        "%ifdef TLS13_POC_OVERLAY\nmlkem_keygen_overlay:\n%endif\n", "", 1
    )
    state = between(source, "cbd2_nibbles db", "\nimage_end:")
    state, fixture_replacements = re.subn(
        r"fixture_d_z:\n.*?fixture_d_z_end:",
        "fixture_d_z:\n    times 64 db 0\nfixture_d_z_end:",
        state,
        count=1,
        flags=re.DOTALL,
    )
    if fixture_replacements != 1:
        raise AssertionError("failed to remove frozen ML-KEM keygen seed")
    state = state.replace(
        "fixture_d_z:\n",
        (
            "module_secret_start:\n"
            "module_hash_pos: dw 0\n"
            "module_hash_remaining: dw 0\n"
            "module_hash_input_off: dw 0\n"
            "module_hash_domain_counter: db 0\n"
            "module_conditioned: times 64 db 0\n"
            "fixture_d_z:\n"
        ),
        1,
    )
    mapping = r"""
keygen_input       equ fixture_d_z
keygen_s_hat0      equ generated_dk
keygen_s_hat1      equ generated_dk + 384
keygen_s_hat2      equ generated_dk + 768
keygen_ek          equ generated_dk + 1152
keygen_h_ek        equ generated_dk + 2336
keygen_z           equ generated_dk + 2368
"""
    return (
        KEYGEN_PREFIX
        + COMMON_HELPERS
        + mapping
        + algorithm
        + state
        + "\nimage_end:\n"
        + "%if image_end - module_header > tls13_286_module_max_bytes\n"
        + '%error "ML-KEM keygen module exceeds overlay"\n'
        + "%endif\n"
    )


def build_decap_source() -> str:
    source = DECAP_SOURCE.read_text()
    algorithm = between(
        source,
        "; ---------------------------------------------------------------------------\n"
        "; Exact K-PKE.Decrypt + G provisional path",
        "; ---------------------------------------------------------------------------\n"
        "; Timing and serial output",
    )
    algorithm = algorithm.replace(
        "mlkem_decaps:\n"
        "    call mlkem_candidate\n",
        (
            "; Build the public A^T cache outside either provider deadline.  The\n"
            "; layout is nine row-major SampleNTT polynomials, each 256 little-\n"
            "; endian words: rho || row || col for row=0..2, col=0..2.\n"
            "mlkem_matrix_precompute:\n"
            "    mov byte [sample_export], 1\n"
            "    xor ax, ax\n"
            "    mov cx, 9\n"
            ".next:\n"
            "    push ax\n"
            "    push cx\n"
            "    call sample_ntt_accumulate\n"
            "    pop cx\n"
            "    pop ax\n"
            "    inc ah\n"
            "    cmp ah, 3\n"
            "    jb .advance\n"
            "    xor ah, ah\n"
            "    inc al\n"
            ".advance:\n"
            "    loop .next\n"
            "    ret\n"
            "\n"
            "mlkem_decaps:\n"
            "    mov word [matrix_accumulate_ptr], sample_ntt_accumulate\n"
            "    jmp short mlkem_decaps_common\n"
            "mlkem_decaps_cached:\n"
            "    mov word [matrix_accumulate_ptr], cached_ntt_accumulate\n"
            "mlkem_decaps_common:\n"
            "    call mlkem_candidate\n"
        ),
        1,
    )
    algorithm = algorithm.replace(
        "    call sample_ntt_accumulate\n"
        "    inc byte [reencrypt_col]\n"
        "    cmp byte [reencrypt_col], 3\n"
        "    jb .u_col\n",
        (
            "    call word [matrix_accumulate_ptr]\n"
            "    inc byte [reencrypt_col]\n"
            "    cmp byte [reencrypt_col], 3\n"
            "    jb .u_col\n"
        ),
        1,
    )
    algorithm = algorithm.replace(
        "sample_accept:\n"
        "    cmp ax, 3329\n"
        "    jae .done\n"
        "    mov bx, [sample_fill]\n"
        "    shl bx, 1\n"
        "    mov [sample_group + bx], ax\n"
        "    inc word [sample_fill]\n"
        "    cmp word [sample_fill], 4\n"
        "    jb .done\n"
        "    call accumulate_sample_group\n"
        "    mov word [sample_fill], 0\n"
        "    inc word [sample_group_index]\n"
        ".done:\n"
        "    ret\n"
        "\n",
        (
            "sample_accept:\n"
            "    cmp ax, 3329\n"
            "    jae .done\n"
            "    cmp byte [sample_export], 0\n"
            "    je .retain\n"
            "    push es\n"
            "    push ax\n"
            "    mov ax, [matrix_cache_seg]\n"
            "    mov es, ax\n"
            "    pop ax\n"
            "    mov bx, [matrix_cache_off]\n"
            "    mov [es:bx], ax\n"
            "    add word [matrix_cache_off], 2\n"
            "    pop es\n"
            "    jmp short .accepted\n"
            ".retain:\n"
            "    mov bx, [sample_fill]\n"
            "    shl bx, 1\n"
            "    mov [sample_group + bx], ax\n"
            ".accepted:\n"
            "    inc word [sample_fill]\n"
            "    cmp word [sample_fill], 4\n"
            "    jb .done\n"
            "    cmp byte [sample_export], 0\n"
            "    jne .reset\n"
            "    call accumulate_sample_group\n"
            ".reset:\n"
            "    mov word [sample_fill], 0\n"
            "    inc word [sample_group_index]\n"
            ".done:\n"
            "    ret\n"
            "\n"
            "; Consume one cached A^T polynomial in the same 64 groups used by\n"
            "; the generated path.  This removes all 27 matrix SHAKE128 Keccak\n"
            "; permutations from the connection deadline while preserving the\n"
            "; exact BaseMultiply/reduction/ciphertext-comparison path.\n"
            "cached_ntt_accumulate:\n"
            "    push es\n"
            "    mov ax, [matrix_cache_seg]\n"
            "    mov es, ax\n"
            "    mov bx, [matrix_cache_off]\n"
            "    mov word [sample_group_index], 0\n"
            ".group:\n"
            "    mov di, sample_group\n"
            "    mov cx, 4\n"
            ".copy:\n"
            "    mov ax, [es:bx]\n"
            "    mov [di], ax\n"
            "    add bx, 2\n"
            "    add di, 2\n"
            "    loop .copy\n"
            "    push bx\n"
            "    call accumulate_sample_group\n"
            "    pop bx\n"
            "    inc word [sample_group_index]\n"
            "    cmp word [sample_group_index], 64\n"
            "    jb .group\n"
            "    mov [matrix_cache_off], bx\n"
            "    pop es\n"
            "    ret\n"
            "\n"
            "; BaseMultiply one four-coefficient A/tHat group by the corresponding yHat\n"
            "; group and add all four output words to poly_acc.\n"
            "accumulate_sample_group:\n"
        ),
        1,
    )
    for needle in (
        "mlkem_matrix_precompute:",
        "mlkem_decaps_cached:",
        "cached_ntt_accumulate:",
    ):
        if needle not in algorithm:
            raise AssertionError(f"failed to inject {needle}")
    state = between(source, "align 2\ny_poly_ptrs", "\nimage_end:")
    state = state.replace(
        '%include "tools/crypto-bench/tls13-spike/mlkem768_integrated_vectors.inc"',
        (
            "module_secret_start:\n"
            "; Product inputs are always copied from validated caller spans.\n"
            "; Never ship the spike's frozen private fixture in the module.\n"
            "fixture_dk: times 2400 db 0\n"
            "fixture_dk_end:\n"
            "fixture_ciphertext: times 1088 db 0\n"
            "fixture_ciphertext_end:\n"
        ),
        1,
    )
    state = state.replace(
        "reencrypt_y_ptr dw 0\n",
        (
            "reencrypt_y_ptr dw 0\n"
            "matrix_cache_off dw 0\n"
            "matrix_cache_seg dw 0\n"
            "matrix_accumulate_ptr dw 0\n"
            "sample_export db 0\n"
        ),
        1,
    )
    return (
        DECAP_PREFIX
        + COMMON_HELPERS
        + algorithm
        + state
        + "\nimage_end:\n"
        + "%if image_end - module_header > tls13_286_module_max_bytes\n"
        + '%error "ML-KEM decap module exceeds overlay"\n'
        + "%endif\n"
    )


def assemble(source: Path, output: Path, listing: Path) -> bytes:
    subprocess.run(
        [
            "nasm",
            "-f",
            "bin",
            "-Itargets/ibm_pc_5150/boot/",
            "-Itools/crypto-bench/",
            "-l",
            str(listing),
            "-o",
            str(output),
            str(source),
        ],
        cwd=ROOT,
        check=True,
    )
    image = output.read_bytes()
    if not image.startswith(b"S286MOD2"):
        raise AssertionError(f"{source.name} lost S286MOD2")
    if len(image) > 0x3800:
        raise AssertionError(f"{source.name} exceeds 0x3800 overlay")
    return image


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


def build_fixtures() -> dict[str, str]:
    keygen = load_module(KEYGEN_CHECK, "seed_mlkem_product_keygen_oracle")
    decap = load_module(DECAP_CHECK, "seed_mlkem_product_decap_oracle")
    seed, dk = keygen.expected_fixture()
    with tempfile.TemporaryDirectory(prefix="seed-mlkem-product-fixture-") as temp:
        image, listing = decap.assemble(Path(temp))
    labels = {
        name: decap.label_address(listing, name)
        for name in (
            "fixture_ciphertext",
            "fixture_ciphertext_end",
        )
    }
    ciphertext = decap.fixture_bytes(
        image, labels, "fixture_ciphertext", "fixture_ciphertext_end"
    )
    expected_dk = keygen.fips_keygen_internal(seed)
    if expected_dk != dk:
        raise AssertionError("independent FIPS keygen differs from frozen dk")
    secret = decap.openssl_decapsulate(seed, dk, ciphertext)
    _, candidate_g = decap.k_pke_decrypt(dk, ciphertext)
    candidate = candidate_g[:32]
    if candidate != secret:
        raise AssertionError("valid candidate differs from decapsulation secret")
    invalid_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    _, invalid_candidate_g = decap.k_pke_decrypt(dk, invalid_ciphertext)
    invalid_candidate = invalid_candidate_g[:32]
    invalid_secret = decap.openssl_decapsulate(seed, dk, invalid_ciphertext)
    if invalid_candidate == invalid_secret:
        raise AssertionError(
            "invalid candidate unexpectedly equals implicit-rejection secret"
        )
    rho = dk[2304:2336]
    if len(rho) != 32:
        raise AssertionError("frozen dk lost embedded public rho")
    matrix_cache = b"".join(
        struct.pack(
            "<256H",
            *decap.sample_ntt(rho + bytes((row, col))),
        )
        for row in range(3)
        for col in range(3)
    )
    if len(matrix_cache) != MATRIX_CACHE_BYTES:
        raise AssertionError("independent A^T cache has wrong size")
    valid_rejection_secret = hashlib.shake_256(
        dk[2368:2400] + ciphertext
    ).digest(32)
    if valid_rejection_secret == secret:
        raise AssertionError(
            "valid fixture's implicit-rejection secret unexpectedly equals K'"
        )
    SEED_BIN.write_bytes(seed)
    EXPECTED_DK_BIN.write_bytes(dk)
    CIPHERTEXT_BIN.write_bytes(ciphertext)
    EXPECTED_SECRET_BIN.write_bytes(secret)
    EXPECTED_INVALID_CANDIDATE_BIN.write_bytes(invalid_candidate)
    EXPECTED_INVALID_SECRET_BIN.write_bytes(invalid_secret)
    EXPECTED_MATRIX_CACHE_BIN.write_bytes(matrix_cache)
    EXPECTED_VALID_REJECTION_SECRET_BIN.write_bytes(valid_rejection_secret)
    return {
        "seed_sha256": hashlib.sha256(seed).hexdigest(),
        "dk_sha256": hashlib.sha256(dk).hexdigest(),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "secret_sha256": hashlib.sha256(secret).hexdigest(),
        "invalid_candidate_sha256": hashlib.sha256(
            invalid_candidate
        ).hexdigest(),
        "invalid_secret_sha256": hashlib.sha256(invalid_secret).hexdigest(),
        "matrix_cache_bytes": len(matrix_cache),
        "matrix_cache_sha256": hashlib.sha256(matrix_cache).hexdigest(),
        "valid_rejection_secret_sha256": hashlib.sha256(
            valid_rejection_secret
        ).hexdigest(),
    }


def main() -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    KEYGEN_ASM.write_text(build_keygen_source())
    DECAP_ASM.write_text(build_decap_source())
    fixture_hashes = build_fixtures()
    keygen_image = assemble(KEYGEN_ASM, KEYGEN_BIN, KEYGEN_LISTING)
    decap_image = assemble(DECAP_ASM, DECAP_BIN, DECAP_LISTING)
    if SEED_BIN.read_bytes() in keygen_image:
        raise AssertionError("product keygen module embeds frozen private seed")
    if (
        EXPECTED_DK_BIN.read_bytes() in decap_image
        or CIPHERTEXT_BIN.read_bytes() in decap_image
    ):
        raise AssertionError("product decap module embeds frozen private fixture")
    decap_wipe_probe_off = label_offset(DECAP_LISTING, "fixture_dk")
    META_INCLUDE.write_text(
        f"keygen_module_bytes equ {len(keygen_image)}\n"
        f"decap_module_bytes equ {len(decap_image)}\n"
        f"decap_wipe_probe_off equ {decap_wipe_probe_off}\n"
        f"matrix_cache_bytes equ {MATRIX_CACHE_BYTES}\n"
    )
    report = {
        "format": "S286MOD2",
        "abi": 2,
        "origin": "0000:4230",
        "one_shot_wipe": True,
        "stack_residue_wipe": "0x7a00..entry-SP, interrupt-safe IRET",
        "frozen_private_fixture_embedded": False,
        "keygen": {
            "bytes": len(keygen_image),
            "headroom": 0x3800 - len(keygen_image),
            "sha256": hashlib.sha256(keygen_image).hexdigest(),
        },
        "decap": {
            "bytes": len(decap_image),
            "headroom": 0x3800 - len(decap_image),
            "sha256": hashlib.sha256(decap_image).hexdigest(),
            "operations": {
                "full_decapsulation": 2,
                "candidate": 8,
                "matrix_precompute": 9,
                "cached_decapsulation": 10,
            },
            "matrix_cache_bytes": MATRIX_CACHE_BYTES,
            "matrix_cache_polynomials": MATRIX_POLYNOMIALS,
            "matrix_cache_order": "row-major A^T: rho || row || col",
            "cached_matrix_shake128_permutations": 0,
            "uncached_matrix_shake128_permutations": 27,
            "dk_wipe_probe_offset": decap_wipe_probe_off,
        },
        "fixtures": fixture_hashes,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
