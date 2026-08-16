#!/usr/bin/env python3
"""Build the width-7 P-256 verifier as a callable ``S286MOD2`` image.

The timing benchmark in ``build_width7_ecdsa.py`` is the arithmetic source of
truth.  This builder retains its strict DER, modulo-n, P-256, and width-7 comb
code while replacing the standalone harness and embedded tables with the
descriptor-driven product boundary in ``tls13_286_abi.inc``.

The product image contains no host-generated runtime table.  Each invocation
reads exact 8,128-byte G and Q tables from caller-supplied far spans.  Those
tables are produced by the target-side P-256 table generator before this
module is called.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/ibm_pc_5150/crypto-bench"
WIDTH7_BUILDER = HERE / "build_width7_ecdsa.py"
OUTPUT_ASM = BUILD / "tls13-286-ecdsa-module.asm"
OUTPUT_BIN = BUILD / "tls13-286-ecdsa-module.bin"
OUTPUT_LISTING = BUILD / "tls13-286-ecdsa-module.lst"
REPORT = BUILD / "tls13-286-ecdsa-module.json"
META_INCLUDE = BUILD / "tls13-286-ecdsa-product-meta.inc"


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


MODULE_PREFIX = r"""bits 16
cpu 8086

%include "core/layout.inc"
%include "tls13/tls13_286_abi.inc"
org tls13_286_module_load

auth_cert_digest_slot equ 0x0c00
auth_cert_signature_slot equ 0x0c20

module_header:
    db 'S286MOD2'
    dw tls13_286_abi_version
    dw tls13_286_mod_kind_ecdsa_verify
    dw image_end - module_header
    dw module_entry - module_header
    dw tls13_286_state_bytes
    dw 512
    dw tls13_286_mod_flag_one_shot
    times tls13_286_mod_header_bytes - ($ - module_header) db 0

; AX=ECDSA operation, BX=tls13_286_root_state_loader, SI=one descriptor
; wholly inside the authenticated offline-auth controller image, DI=0.
; DS=ES=SS=0 and DF=0 at entry.
;
; Descriptor mapping:
;   input0  32-byte SHA-256 digest in one exact certificate/CV slot
;   input1  8..72-byte strict DER signature in the matching exact slot
;   input2  8,128-byte target-generated width-7 G table
;   input3  8,128-byte target-generated width-7 Q table
;   output0 one-byte success decision
;
; The decision span is not touched on any rejection.  The caller initializes
; it to zero; this module publishes one only after the complete equation and
; x mod n comparison succeed.
module_entry:
    mov dx, sp
    test dx, 1
    jnz module_error_stack
    cmp dx, tls13_286_module_limit + 512 + 2
    jb module_error_stack
    cmp dx, 0x8000
    jae module_error_stack
    push bp
    cld
    or di, di
    jnz module_error_abi
    cmp ax, tls13_286_mod_op_ecdsa_verify
    jne module_error_abi
    call module_validate_controller_desc
    jc module_error_bounds
    cmp word [si + tls13_286_desc_op], tls13_286_mod_op_ecdsa_verify
    jne module_error_abi
    cmp word [si + tls13_286_desc_flags], 0
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

    call module_validate_shape
    jc module_error_bounds

    mov bx, si
    add bx, tls13_286_desc_input0
    mov dx, 32
    mov di, auth_digest_buffer
    call module_copy_span_to_near

    mov bx, [module_desc]
    add bx, tls13_286_desc_input1
    mov dx, [bx + tls13_286_span_len]
    mov [auth_signature_len], dx
    mov di, auth_signature_buffer
    call module_copy_span_to_near
    call module_wipe_input_evidence

    mov bx, [module_desc]
    add bx, tls13_286_desc_input2
    mov ax, [bx + tls13_286_span_off]
    mov [auth_g_span], ax
    mov ax, [bx + tls13_286_span_seg]
    mov [auth_g_span + 2], ax

    mov bx, [module_desc]
    add bx, tls13_286_desc_input3
    mov ax, [bx + tls13_286_span_off]
    mov [auth_q_span], ax
    mov ax, [bx + tls13_286_span_seg]
    mov [auth_q_span + 2], ax

    mov word [auth_signature_ptr], auth_signature_buffer
    mov word [auth_digest_ptr], auth_digest_buffer
    call auth_ecdsa_verify
    jc module_error_crypto

    ; Publication is deliberately last.  All module arithmetic and all
    ; descriptor input reads are complete before this one-byte far write.
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov ax, [bx + tls13_286_span_seg]
    mov es, ax
    mov di, [bx + tls13_286_span_off]
    mov byte [es:di], 1
    xor ax, ax
    mov es, ax
    xor dx, dx
    jmp short module_retire

module_error_abi:
    mov dx, tls13_286_error_abi
    jmp short module_retire
module_error_bounds:
    mov dx, tls13_286_error_bounds
    jmp short module_retire
module_error_crypto:
    mov dx, tls13_286_error_crypto
module_retire:
    call module_wipe
    jmp module_finish_result
module_error_stack:
    mov ax, tls13_286_error_bounds
    stc
    ret

; The descriptor itself is not caller-selected scratch: it must be entirely
; inside the actual authenticated auth-controller image named by S286AU02.
module_validate_controller_desc:
    cmp word [tls13_286_controller_load + 0], 0x3253
    jne .bad
    cmp word [tls13_286_controller_load + 2], 0x3638
    jne .bad
    cmp word [tls13_286_controller_load + 4], 0x5541
    jne .bad
    cmp word [tls13_286_controller_load + 6], 0x3230
    jne .bad
    cmp word [tls13_286_controller_load + 8], tls13_286_abi_version
    jne .bad
    mov dx, [tls13_286_controller_load + 10]
    cmp dx, 16
    jb .bad
    cmp dx, tls13_286_controller_max_bytes
    ja .bad
    add dx, tls13_286_controller_load
    jc .bad
    cmp si, tls13_286_controller_load
    jb .bad
    mov ax, si
    add ax, tls13_286_desc_bytes
    jc .bad
    cmp ax, dx
    ja .bad
    clc
    ret
.bad:
    stc
    ret

; Validate the complete product shape before copying any evidence.  The two
; legal input pairs are indivisible: fixed normalized certificate slots in
; low RAM, or the captured CertificateVerify slots in the top reservation.
module_validate_shape:
    mov bx, [module_desc]
    add bx, tls13_286_desc_input0
    mov ax, auth_cert_digest_slot
    mov dx, 32
    call module_validate_low_at
    jnc .certificate
    mov ax, tls13_286_cv_digest_off
    call module_validate_high_at
    jc .bad
    mov bx, [module_desc]
    add bx, tls13_286_desc_input1
    mov ax, tls13_286_cv_signature_off
    call module_validate_signature_high_at
    jc .bad
    jmp short .common
.certificate:
    mov bx, [module_desc]
    add bx, tls13_286_desc_input1
    mov ax, auth_cert_signature_slot
    call module_validate_signature_low_at
    jc .bad
.common:
    mov bx, [module_desc]
    add bx, tls13_286_desc_input2
    mov ax, tls13_286_g_table_off
    mov dx, tls13_286_w7_table_bytes
    call module_validate_high_at
    jc .bad
    mov bx, [module_desc]
    add bx, tls13_286_desc_input3
    mov ax, tls13_286_leaf_table_off
    mov dx, tls13_286_w7_table_bytes
    call module_validate_high_at
    jc .bad
    mov bx, [module_desc]
    add bx, tls13_286_desc_output0
    mov ax, tls13_286_ecdsa_result_off
    mov dx, 1
    call module_validate_high_at
    jc .bad
    mov bx, [module_desc]
    add bx, tls13_286_desc_output1
    call module_validate_zero_span
    ret
.bad:
    stc
    ret

module_validate_signature_low_at:
    call module_validate_signature_length
    jc .bad
    jmp module_validate_low_at
.bad:
    ret

module_validate_signature_high_at:
    call module_validate_signature_length
    jc .bad
    jmp module_validate_high_at
.bad:
    ret

module_validate_signature_length:
    cmp word [bx + tls13_286_span_len + 2], 0
    jne .bad
    mov dx, [bx + tls13_286_span_len]
    cmp dx, 8
    jb .bad
    cmp dx, tls13_286_cv_signature_max
    ja .bad
    clc
    ret
.bad:
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

; BX=span, DX=required exact byte count.
module_validate_span:
    cmp word [bx + tls13_286_span_len], dx
    jne module_span_bad
    cmp word [bx + tls13_286_span_len + 2], 0
    jne module_span_bad
    cmp word [bx + tls13_286_span_off], 15
    ja module_span_bad
    mov ax, [bx + tls13_286_span_seg]
    cmp ax, 0xa000
    jae module_span_bad
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

; BX=span, AX=exact offset within the validated reservation, DX=exact length.
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

; BX=span, AX=exact low physical address, DX=exact length.
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

; Both accepted evidence pairs are transient.  Once copied into private
; module state, retire the caller slots before doing the expensive equation;
; this covers successful and cryptographic-rejection returns alike.
module_wipe_input_evidence:
    mov bx, [module_desc]
    add bx, tls13_286_desc_input0
    call module_wipe_span
    mov bx, [module_desc]
    add bx, tls13_286_desc_input1
module_wipe_span:
    mov ax, [bx + tls13_286_span_seg]
    mov es, ax
    mov di, [bx + tls13_286_span_off]
    mov cx, [bx + tls13_286_span_len]
    xor ax, ax
    rep stosb
    mov es, ax
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

; Retire the complete free stack guard, then restore IF and publish CF in one
; IRET.  The only post-return residue is the explicit public IRET frame.
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
    mov ds, ax
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


FAR_COMB_HELPER = r"""
; Add width-7 table entry AX from the canonical far span named by BX.
; Index zero is the implicit point at infinity; entries 1..127 are 64-byte
; little-endian affine x/y pairs generated and validated on this target.
auth_comb_add_index:
    or ax, ax
    jz .done
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push ds
    push es
    dec ax
    mov cl, 6
    shl ax, cl
    add ax, [bx]
    mov si, ax
    mov ax, [bx + 2]
    mov ds, ax
    xor ax, ax
    mov es, ax
    mov di, auth_point_buffer
    mov cx, 32
    rep movsw
    pop es
    pop ds
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    mov word [p256_affine_x_ptr], auth_point_buffer
    mov word [p256_affine_y_ptr], auth_point_buffer + 32
    call p256_point_add_mixed
.done:
    ret

"""


DATA_TAIL = r"""
; Minimal common data required by core/p256.inc.
align 2
p256_prime: dw 65535,65535,65535,65535,65535,65535,0,0,0,0,0,0,1,0,65535,65535
p256_three: dw 3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
module_secret_start:
module_desc: dw 0
module_crypto_seg: dw 0
p256_jac_x: times 16 dw 0
p256_jac_y: times 16 dw 0
p256_jac_z: times 16 dw 0
p256_s0: times 16 dw 0
p256_s1: times 16 dw 0
p256_s2: times 16 dw 0
p256_s3: times 16 dw 0
p256_s4: times 16 dw 0
p256_s5: times 16 dw 0
p256_s6: times 16 dw 0
p256_s7: times 16 dw 0
p256_s8: times 16 dw 0
p256_product: times 36 dw 0
p256_carry: db 0
p256_left_ptr: dw 0
p256_right_ptr: dw 0
p256_result_ptr: dw 0
p256_inv_output_ptr: dw 0
p256_affine_x_ptr: dw 0
p256_affine_y_ptr: dw 0
p256_scalar_ptr: dw 0

p256_client_private equ p256_s0
tls_server_ec_x_words equ p256_s1
tls_server_ec_y_words equ p256_s2
tls_shared_x_words equ p256_s3

auth_order_n: dw 9553,64611,51906,62393,40580,42775,64173,48358
              dw 65535,65535,65535,65535,0,0,65535,65535

align 2
auth_r: times 16 dw 0
auth_s: times 16 dw 0
auth_z: times 16 dw 0
auth_w: times 16 dw 0
auth_u1: times 16 dw 0
auth_u2: times 16 dw 0
auth_result_x: times 16 dw 0
auth_result_y: times 16 dw 0

auth_signature_ptr: dw 0
auth_signature_len: dw 0
auth_digest_ptr: dw 0
auth_der_end: dw 0
auth_der_output_ptr: dw 0
auth_der_next_ptr: dw 0
auth_n_inverse_output_ptr: dw 0
auth_n_multiply_output_ptr: dw 0
auth_n_multiply_right_ptr: dw 0

auth_comb_scalar_ptr: dw 0
auth_comb_bit_position: dw 0
auth_comb_index_value: dw 0
auth_comb_index_mask: dw 0
auth_loop_index: dw 0
auth_g_span: dw 0, 0
auth_q_span: dw 0, 0

auth_digest_buffer: times 32 db 0
auth_signature_buffer: times 72 db 0
auth_point_buffer: times 64 db 0

image_end:
"""


def product_source() -> str:
    width7 = load_module(WIDTH7_BUILDER, "seed_width7_ecdsa_builder")
    transformed = width7.generated_source(width7.TABLE_PATHS)

    verify = between(
        transformed,
        "auth_ecdsa_verify:\n",
        "; Validate canonical affine coordinate ranges",
    )
    old_helper = between(
        verify,
        "; Add width-7 table entry AX (zero means no point), table base BX.\n",
        "; Strict short-form DER parser",
    )
    verify = verify.replace(old_helper, FAR_COMB_HELPER, 1)
    verify = verify.replace(
        "    mov bx, auth_comb_g_table\n",
        "    mov bx, auth_g_span\n",
        1,
    )
    verify = verify.replace(
        "    mov bx, [auth_comb_q_table_ptr]\n",
        "    mov bx, auth_q_span\n",
        1,
    )

    n_math = between(
        transformed,
        "; Binary extended-GCD inverse modulo the P-256 group order n.",
        "auth_save_generator_table:",
    )
    equality = between(
        transformed,
        "; CF=0 equal, CF=1 different.\n",
        "auth_fill_stack_guard:",
    )

    return (
        MODULE_PREFIX
        + verify
        + n_math
        + equality
        + "\n; Shared P-256 field and point implementation.\n"
        + "tls_premaster_secret equ p256_s4\n"
        + "%include \"core/p256.inc\"\n"
        + DATA_TAIL
    )


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
    width7 = load_module(WIDTH7_BUILDER, "seed_width7_ecdsa_materializer")
    with redirect_stdout(io.StringIO()):
        width7.main()

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
        raise AssertionError("ECDSA product module lost S286MOD2 header")
    if len(image) > 0x3800:
        raise AssertionError(f"ECDSA product module exceeds overlay: {len(image)}")
    if any(table in image for table in (path.read_bytes() for path in width7.TABLE_PATHS.values())):
        raise AssertionError("ECDSA product image embeds a host-generated width-7 table")
    wipe_start = label_offset(OUTPUT_LISTING, "module_secret_start")
    if not 0 < wipe_start < len(image):
        raise AssertionError("ECDSA wipe range is outside module image")
    META_INCLUDE.write_text(
        f"ecdsa_module_bytes equ {len(image)}\n"
        f"ecdsa_wipe_start_off equ {wipe_start}\n"
        f"ecdsa_wipe_bytes equ {len(image) - wipe_start}\n"
    )

    report = {
        "format": "S286MOD2",
        "abi": 2,
        "kind": "ECDSA_VERIFY",
        "origin": "0000:4230",
        "operation": "P-256 ECDSA SHA-256 verify",
        "bytes": len(image),
        "overlay_headroom": 0x3800 - len(image),
        "one_shot_wipe": True,
        "private_state_wipe_offset": wipe_start,
        "private_state_wipe_bytes": len(image) - wipe_start,
        "stack_residue_wipe": "0x7a00..entry-SP, interrupt-safe IRET",
        "descriptor_policy": {
            "controller_state": "exact root_state_loader",
            "controller_descriptor": "inside actual S286AU02 image",
            "crypto_segment": "0x7000..0x9000, 0x40 aligned",
            "canonical_spans": True,
            "exact_product_slots": True,
            "certificate_inputs": "0000:0c00/0c20 normalized pair",
            "certificate_verify_inputs": "reservation b2e8/b2a0 pair",
            "inactive_spans_zero": True,
        },
        "sha256": hashlib.sha256(image).hexdigest(),
        "source": str(OUTPUT_ASM.relative_to(ROOT)),
        "image": str(OUTPUT_BIN.relative_to(ROOT)),
        "runtime_tables": {
            "embedded": False,
            "g_bytes": 8128,
            "q_bytes": 8128,
            "source": "target-generated descriptor spans",
        },
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
