; Exact 6 MHz / 512 KiB descriptor/KAT gate for the two ML-KEM modules.

bits 16
cpu 8086
org 0x1000

%include "tls13/tls13_286_abi.inc"
%include "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-product-meta.inc"

bench_crypto_seg equ 0x7000
bench_stack_top equ 0x8000
; The module returns through a public IRET frame at 0x7ff6..0x7ffb for this
; call depth.  Secret-derived stack state must be zero below that frame.
bench_module_public_frame equ bench_stack_top - 10

%define HIGH_SPAN_OFF(object_off) ((object_off) & 15)
%define HIGH_SPAN_SEG(object_off) \
    (bench_crypto_seg + ((object_off) >> 4))
%define LOW_SPAN_OFF(address) ((address) & 15)
%define LOW_SPAN_SEG(address) ((address) >> 4)

%macro SET_SPAN 4
    mov word [operation_desc + %1 + tls13_286_span_off], %2
    mov word [operation_desc + %1 + tls13_286_span_seg], %3
    mov word [operation_desc + %1 + tls13_286_span_len], %4
%endmacro

core_header:
    jmp short start
    nop
    db 'SEEDCORE'
    db 1
    db 0
    dw core_header_end - core_header
    dw (image_end - core_header + 511) / 512
    dw (image_end - core_header + 511) / 512
    dw 0
    dw 0
core_header_end:

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, bench_stack_top
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init

    mov word [tls13_286_root_state_loader + tls13_286_state_cache_seg], \
        bench_crypto_seg
    mov word [tls13_286_root_state_loader + tls13_286_state_cache_capacity], \
        tls13_286_pack_cache_bytes

    ; Product conditioner: 1024 six-byte raw events in the pre-table high
    ; window must match an independent SHA3-256 oracle.
    mov ax, HIGH_SPAN_SEG(tls13_286_entropy_raw_off)
    mov es, ax
    mov di, HIGH_SPAN_OFF(tls13_286_entropy_raw_off)
    mov al, 0xa5
    mov cx, tls13_286_entropy_raw_bytes
    rep stosb
    xor ax, ax
    mov es, ax
    mov ax, tls13_286_mod_op_sha3_256_condition
    call prepare_desc
    SET_SPAN tls13_286_desc_input0, \
        HIGH_SPAN_OFF(tls13_286_entropy_raw_off), \
        HIGH_SPAN_SEG(tls13_286_entropy_raw_off), \
        tls13_286_entropy_raw_bytes
    SET_SPAN tls13_286_desc_output0, \
        HIGH_SPAN_OFF(tls13_286_entropy_seed_off), \
        HIGH_SPAN_SEG(tls13_286_entropy_seed_off), \
        tls13_286_entropy_seed_bytes
    mov ax, tls13_286_mod_op_sha3_256_condition
    call module_call
    jc fail
    push es
    mov ax, HIGH_SPAN_SEG(tls13_286_entropy_seed_off)
    mov es, ax
    mov si, conditioner_expected
    mov di, HIGH_SPAN_OFF(tls13_286_entropy_seed_off)
    mov cx, 64
    repe cmpsb
    pop es
    jne fail
    call load_keygen_module

    ; The conditioner KAT is independent from the deterministic ML-KEM KAT.
    ; Copy its known D||Z seed into one exact attempt bundle before keygen.
    push es
    mov ax, HIGH_SPAN_SEG(tls13_286_attempt_acquire_off)
    mov es, ax
    mov si, seed
    mov di, HIGH_SPAN_OFF(tls13_286_attempt_acquire_off)
    mov cx, 64
    rep movsb
    pop es

    cmp word [tls13_286_module_load + tls13_286_mod_kind], \
        tls13_286_mod_kind_mlkem_keygen
    jne fail
    mov ax, tls13_286_mod_op_mlkem_keygen
    call prepare_desc
    SET_SPAN tls13_286_desc_input0, \
        HIGH_SPAN_OFF(tls13_286_attempt_acquire_off), \
        HIGH_SPAN_SEG(tls13_286_attempt_acquire_off), 64
    SET_SPAN tls13_286_desc_output0, \
        LOW_SPAN_OFF(tls13_286_hello_mlkem_ek_off), \
        LOW_SPAN_SEG(tls13_286_hello_mlkem_ek_off), \
        tls13_286_hello_mlkem_ek_bytes
    SET_SPAN tls13_286_desc_output1, \
        HIGH_SPAN_OFF(tls13_286_mlkem_dk_off), \
        HIGH_SPAN_SEG(tls13_286_mlkem_dk_off), \
        tls13_286_mlkem_dk_bytes
    call timer_start
    mov ax, tls13_286_mod_op_mlkem_keygen
    call module_call
    jc fail
    call timer_stop
    mov [keygen_ticks], ax
    push es
    mov ax, HIGH_SPAN_SEG(tls13_286_mlkem_dk_off)
    mov es, ax
    mov si, expected_dk
    mov di, HIGH_SPAN_OFF(tls13_286_mlkem_dk_off)
    mov cx, 2400
    repe cmpsb
    pop es
    jne fail
    mov si, tls13_286_hello_mlkem_ek_off
    mov di, expected_dk + 1152
    mov cx, 1184
    repe cmpsb
    jne fail

    ; Precompute all nine public A^T SampleNTT polynomials before TCP.  The
    ; far cache must exactly match the independent row-major oracle and the
    ; one-shot image must retire its copied dk before returning.
    call load_decap_module
    mov ax, tls13_286_mod_op_mlkem_matrix_precompute
    call setup_matrix_desc
    call timer_start
    mov ax, tls13_286_mod_op_mlkem_matrix_precompute
    call module_call
    jc fail
    call timer_stop
    mov [matrix_ticks], ax
    call assert_decap_dk_wiped
    jc fail
    push es
    mov ax, HIGH_SPAN_SEG(tls13_286_mlkem_matrix_stage_off)
    mov es, ax
    mov si, expected_matrix_cache
    mov di, HIGH_SPAN_OFF(tls13_286_mlkem_matrix_stage_off)
    mov cx, matrix_cache_bytes
    repe cmpsb
    pop es
    jne fail

    ; The low public band held the generated EK.  Replace it with the exact
    ; live ServerHello ciphertext before exercising decapsulation.
    push es
    mov ax, LOW_SPAN_SEG(tls13_286_hello_ciphertext_off)
    mov es, ax
    mov si, ciphertext
    mov di, LOW_SPAN_OFF(tls13_286_hello_ciphertext_off)
    mov cx, tls13_286_hello_ciphertext_bytes
    rep movsb
    pop es

    call load_decap_module
    cmp word [tls13_286_module_load + tls13_286_mod_kind], \
        tls13_286_mod_kind_mlkem_decap
    jne fail
    mov ax, tls13_286_mod_op_mlkem_decap
    call setup_decap_desc
    call timer_start
    mov ax, tls13_286_mod_op_mlkem_decap
    call module_call
    jc fail
    call timer_stop
    mov [decap_ticks], ax
    mov si, expected_secret
    call compare_product_secret
    jne fail
    mov di, secret_output
    call save_product_secret
    call assert_decap_dk_wiped
    jc fail

    ; Reload and perform the standards-complete operation with the far public
    ; cache.  It must be bit-identical to both the independent oracle and the
    ; existing uncached op2 result.
    call load_decap_module
    mov ax, tls13_286_mod_op_mlkem_decap_cached
    call setup_decap_desc
    call timer_start
    mov ax, tls13_286_mod_op_mlkem_decap_cached
    call module_call
    jc fail
    call timer_stop
    mov [cached_ticks], ax
    mov si, expected_secret
    call compare_product_secret
    jne fail
    mov si, secret_output
    call compare_product_secret
    jne fail
    mov di, cached_output
    call save_product_secret
    call assert_decap_dk_wiped
    jc fail

    ; Reload the one-shot image and expose exactly the valid provisional K'.
    ; It must equal both the independent oracle and the complete valid decap.
    call load_decap_module
    mov ax, tls13_286_mod_op_mlkem_candidate
    call setup_decap_desc
    call timer_start
    mov ax, tls13_286_mod_op_mlkem_candidate
    call module_call
    jc fail
    call timer_stop
    mov [candidate_ticks], ax
    mov si, expected_secret
    call compare_product_secret
    jne fail
    mov si, secret_output
    call compare_product_secret
    jne fail
    mov di, candidate_output
    call save_product_secret
    call assert_decap_dk_wiped
    jc fail

    ; On a corrupted ciphertext the candidate operation still returns the
    ; independently computed K', while full decapsulation must select J(z||c).
    xor byte [tls13_286_hello_ciphertext_off], 1
    call load_decap_module
    mov ax, tls13_286_mod_op_mlkem_candidate
    call setup_decap_desc
    call timer_start
    mov ax, tls13_286_mod_op_mlkem_candidate
    call module_call
    jc fail
    call timer_stop
    mov [invalid_candidate_ticks], ax
    mov si, expected_invalid_candidate
    call compare_product_secret
    jne fail
    mov di, candidate_output
    call save_product_secret
    call assert_decap_dk_wiped
    jc fail

    call load_decap_module
    mov ax, tls13_286_mod_op_mlkem_decap
    call setup_decap_desc
    call timer_start
    mov ax, tls13_286_mod_op_mlkem_decap
    call module_call
    jc fail
    call timer_stop
    mov [invalid_ticks], ax
    mov si, expected_invalid_secret
    call compare_product_secret
    jne fail
    mov di, secret_output
    call save_product_secret
    mov si, candidate_output
    call compare_product_secret
    je fail
    call assert_decap_dk_wiped
    jc fail

    ; The cached path must make exactly the same invalid-ciphertext implicit
    ; rejection choice as op2.
    call load_decap_module
    mov ax, tls13_286_mod_op_mlkem_decap_cached
    call setup_decap_desc
    call timer_start
    mov ax, tls13_286_mod_op_mlkem_decap_cached
    call module_call
    jc fail
    call timer_stop
    mov [invalid_cached_ticks], ax
    mov si, expected_invalid_secret
    call compare_product_secret
    jne fail
    mov si, secret_output
    call compare_product_secret
    jne fail
    mov di, cached_output
    call save_product_secret
    call assert_decap_dk_wiped
    jc fail

    ; A corrupted public cache is never accepted as K'.  With the original
    ; valid ciphertext the full compare must fail closed to exact J(z || c).
    xor byte [tls13_286_hello_ciphertext_off], 1
    push es
    mov ax, HIGH_SPAN_SEG(tls13_286_mlkem_matrix_stage_off)
    mov es, ax
    xor byte [es:HIGH_SPAN_OFF(tls13_286_mlkem_matrix_stage_off) + 73], 1
    pop es
    call load_decap_module
    mov ax, tls13_286_mod_op_mlkem_decap_cached
    call setup_decap_desc
    mov ax, tls13_286_mod_op_mlkem_decap_cached
    call module_call
    jc fail
    mov si, expected_valid_rejection_secret
    call compare_product_secret
    jne fail
    mov si, expected_secret
    call compare_product_secret
    je fail
    call assert_decap_dk_wiped
    jc fail

    ; Exact spans are part of the operation ABI.  Short cache/output spans and
    ; unknown operations reject without publishing a caller-visible secret.
    call fill_cached_sentinel
    call load_decap_module
    mov ax, tls13_286_mod_op_mlkem_decap_cached
    call setup_decap_desc
    mov word [operation_desc + tls13_286_desc_input2 + tls13_286_span_len], \
        matrix_cache_bytes - 1
    mov ax, tls13_286_mod_op_mlkem_decap_cached
    call module_call
    jnc fail
    cmp ax, tls13_286_error_bounds
    jne fail
    call assert_cached_sentinel
    jc fail
    call assert_decap_dk_wiped
    jc fail

    call fill_cached_sentinel
    call load_decap_module
    mov ax, tls13_286_mod_op_mlkem_matrix_precompute
    call setup_matrix_desc
    mov word [operation_desc + tls13_286_desc_output0 + tls13_286_span_len], \
        matrix_cache_bytes - 1
    mov ax, tls13_286_mod_op_mlkem_matrix_precompute
    call module_call
    jnc fail
    cmp ax, tls13_286_error_bounds
    jne fail
    call assert_cached_sentinel
    jc fail
    call assert_decap_dk_wiped
    jc fail

    call fill_cached_sentinel
    call load_decap_module
    mov ax, 0x7fff
    call prepare_desc
    mov ax, 0x7fff
    call module_call
    jnc fail
    cmp ax, tls13_286_error_abi
    jne fail
    call assert_cached_sentinel
    jc fail

    mov si, tag_keygen
    mov ax, [keygen_ticks]
    call emit_metric
    mov si, tag_matrix
    mov ax, [matrix_ticks]
    call emit_metric
    mov si, tag_decap
    mov ax, [decap_ticks]
    call emit_metric
    mov si, tag_cached
    mov ax, [cached_ticks]
    call emit_metric
    mov si, tag_candidate
    mov ax, [candidate_ticks]
    call emit_metric
    mov si, tag_invalid_candidate
    mov ax, [invalid_candidate_ticks]
    call emit_metric
    mov si, tag_invalid
    mov ax, [invalid_ticks]
    call emit_metric
    mov si, tag_invalid_cached
    mov ax, [invalid_cached_ticks]
    call emit_metric
    mov si, tag_check
    mov ax, 1
    call emit_check
    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

fail:
    mov si, tag_fail
    call emit_str
    call emit_crlf
    jmp start.hang

load_decap_module:
    push ax
    push cx
    push si
    push di
    push es
    xor ax, ax
    mov es, ax
    mov si, decap_module_image
    mov di, tls13_286_module_load
    mov cx, decap_module_bytes
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

load_keygen_module:
    push ax
    push cx
    push si
    push di
    push es
    xor ax, ax
    mov es, ax
    mov si, keygen_module_image
    mov di, tls13_286_module_load
    mov cx, keygen_module_bytes
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

; AX=operation.  Every operation gets an exact fresh descriptor so inactive
; spans cannot inherit aliases from an earlier operation.
prepare_desc:
    push ax
    push cx
    push di
    push es
    xor ax, ax
    mov es, ax
    mov di, operation_desc
    mov cx, tls13_286_desc_bytes / 2
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    mov [operation_desc + tls13_286_desc_op], ax
    ret

; AX=one of op2/op8/op10.
setup_decap_desc:
    call prepare_desc
    SET_SPAN tls13_286_desc_input0, \
        HIGH_SPAN_OFF(tls13_286_mlkem_dk_off), \
        HIGH_SPAN_SEG(tls13_286_mlkem_dk_off), \
        tls13_286_mlkem_dk_bytes
    SET_SPAN tls13_286_desc_input1, \
        LOW_SPAN_OFF(tls13_286_hello_ciphertext_off), \
        LOW_SPAN_SEG(tls13_286_hello_ciphertext_off), \
        tls13_286_hello_ciphertext_bytes
    SET_SPAN tls13_286_desc_output0, \
        HIGH_SPAN_OFF(tls13_286_hybrid_secret_off), \
        HIGH_SPAN_SEG(tls13_286_hybrid_secret_off), 32
    cmp ax, tls13_286_mod_op_mlkem_decap_cached
    jne .done
    SET_SPAN tls13_286_desc_input2, \
        HIGH_SPAN_OFF(tls13_286_mlkem_matrix_stage_off), \
        HIGH_SPAN_SEG(tls13_286_mlkem_matrix_stage_off), \
        tls13_286_mlkem_matrix_stage_bytes
.done:
    ret

setup_matrix_desc:
    call prepare_desc
    SET_SPAN tls13_286_desc_input0, \
        HIGH_SPAN_OFF(tls13_286_mlkem_dk_off), \
        HIGH_SPAN_SEG(tls13_286_mlkem_dk_off), \
        tls13_286_mlkem_dk_bytes
    SET_SPAN tls13_286_desc_output0, \
        HIGH_SPAN_OFF(tls13_286_mlkem_matrix_stage_off), \
        HIGH_SPAN_SEG(tls13_286_mlkem_matrix_stage_off), \
        tls13_286_mlkem_matrix_stage_bytes
    ret

module_call:
    push bp
    mov bx, tls13_286_root_state_loader
    mov si, operation_desc
    xor di, di
    mov bp, [tls13_286_module_load + tls13_286_mod_entry_off]
    add bp, tls13_286_module_load
    call bp
.module_return:
    cli
    mov [module_return_ax], ax
    mov dx, [bench_module_public_frame + 4]
    mov [module_return_flags], dx
    cmp sp, bench_stack_top - 4
    jne fail
    cmp word [bench_module_public_frame], .module_return
    jne fail
    cmp word [bench_module_public_frame + 2], 0
    jne fail
    test dx, 0x0200
    jz fail
    mov ax, [module_return_ax]
    or ax, ax
    jz .expect_carry_clear
    test dx, 1
    jz fail
    jmp short .frame_ok
.expect_carry_clear:
    test dx, 1
    jnz fail
.frame_ok:
    mov si, tls13_286_module_limit
    mov cx, bench_module_public_frame - tls13_286_module_limit
.stack_byte:
    cmp byte [si], 0
    jne fail
    inc si
    loop .stack_byte
    mov ax, [module_return_ax]
    push word [module_return_flags]
    popf
    pop bp
    ret

; SI=local 32-byte oracle/snapshot.  Preserve all registers and return the
; product-slot comparison in ZF.
compare_product_secret:
    push ax
    push cx
    push si
    push di
    push es
    mov ax, HIGH_SPAN_SEG(tls13_286_hybrid_secret_off)
    mov es, ax
    mov di, HIGH_SPAN_OFF(tls13_286_hybrid_secret_off)
    mov cx, 32
    repe cmpsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

; DI=local 32-byte snapshot destination.
save_product_secret:
    push ax
    push cx
    push si
    push di
    push ds
    push es
    mov ax, HIGH_SPAN_SEG(tls13_286_hybrid_secret_off)
    mov ds, ax
    xor ax, ax
    mov es, ax
    mov si, HIGH_SPAN_OFF(tls13_286_hybrid_secret_off)
    mov cx, 32
    rep movsb
    pop es
    pop ds
    pop di
    pop si
    pop cx
    pop ax
    ret

assert_decap_dk_wiped:
    mov si, tls13_286_module_load + decap_wipe_probe_off
    mov cx, 2400
.byte:
    cmp byte [si], 0
    jne .bad
    inc si
    loop .byte
    clc
    ret
.bad:
    stc
    ret

fill_cached_sentinel:
    push es
    mov ax, HIGH_SPAN_SEG(tls13_286_hybrid_secret_off)
    mov es, ax
    mov di, HIGH_SPAN_OFF(tls13_286_hybrid_secret_off)
    mov al, 0xa6
    mov cx, 32
    rep stosb
    pop es
    ret

assert_cached_sentinel:
    push es
    mov ax, HIGH_SPAN_SEG(tls13_286_hybrid_secret_off)
    mov es, ax
    mov di, HIGH_SPAN_OFF(tls13_286_hybrid_secret_off)
    mov al, 0xa6
    mov cx, 32
.byte:
    cmp [es:di], al
    jne .bad
    inc di
    loop .byte
    pop es
    clc
    ret
.bad:
    pop es
    stc
    ret

timer_start:
    call read_tick_low
    mov bx, ax
.edge:
    call read_tick_low
    cmp ax, bx
    je .edge
    call read_tick
    mov [tick_lo], ax
    mov [tick_hi], dx
    ret

timer_stop:
    call read_tick
    sub ax, [tick_lo]
    sbb dx, [tick_hi]
    ret

read_tick:
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret

read_tick_low:
    mov ax, [0x046c]
    ret

emit_metric:
    push ax
    call emit_str
    mov si, str_n
    call emit_str
    mov ax, 1
    call emit_dec16
    mov si, str_dt
    call emit_str
    pop ax
    call emit_dec16
    call emit_crlf
    ret

emit_check:
    push ax
    call emit_str
    mov si, str_check
    call emit_str
    pop ax
    call emit_hex16
    call emit_crlf
    ret

serial_init:
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 0x0c
    out dx, al
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 0x03
    out dx, al
    ret

emit_char:
    push ax
    push bx
    push cx
    push dx
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    mov ah, al
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, 0x3f8
    mov al, ah
    out dx, al
    pop dx
    pop cx
    pop bx
    pop ax
    ret

emit_str:
    push ax
    push si
.next:
    lodsb
    or al, al
    jz .done
    call emit_char
    jmp short .next
.done:
    pop si
    pop ax
    ret

emit_crlf:
    push ax
    mov al, 13
    call emit_char
    mov al, 10
    call emit_char
    pop ax
    ret

emit_hex16:
    push ax
    push cx
    push dx
    mov dx, ax
    mov cx, 4
.digit:
    rol dx, 1
    rol dx, 1
    rol dx, 1
    rol dx, 1
    mov al, dl
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .emit
    add al, 7
.emit:
    call emit_char
    loop .digit
    pop dx
    pop cx
    pop ax
    ret

emit_dec16:
    push ax
    push bx
    push cx
    push dx
    mov bx, 10
    xor cx, cx
.divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .divide
.pop:
    pop ax
    add al, '0'
    call emit_char
    loop .pop
    pop dx
    pop cx
    pop bx
    pop ax
    ret

seed:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-seed.bin"
expected_dk:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-expected-dk.bin"
ciphertext:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-ciphertext.bin"
expected_secret:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-expected-secret.bin"
expected_invalid_candidate:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-expected-invalid-candidate.bin"
expected_invalid_secret:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-expected-invalid-secret.bin"

secret_output: times 32 db 0
candidate_output: times 32 db 0
cached_output: times 32 db 0
conditioner_expected:
    db 0xbf,0x56,0xbb,0xf8,0xc8,0x1f,0x6d,0xa5
    db 0xf3,0xe9,0x7a,0x2a,0x9a,0xbb,0xfa,0x84
    db 0x98,0xf7,0xc8,0x75,0x0f,0x3d,0xf2,0x9f
    db 0xd8,0x35,0xff,0x43,0x67,0x49,0x11,0x42
    db 0x3b,0x4f,0xee,0x5a,0x70,0x56,0x15,0xae
    db 0xed,0x36,0x13,0x6f,0xe1,0x48,0xf1,0xe0
    db 0x11,0x84,0xe7,0x94,0xbd,0x0b,0x48,0x1b
    db 0xa5,0xf8,0x87,0xd3,0x5a,0x38,0x6e,0xcb

tick_lo: dw 0
tick_hi: dw 0
keygen_ticks: dw 0
matrix_ticks: dw 0
decap_ticks: dw 0
cached_ticks: dw 0
candidate_ticks: dw 0
invalid_candidate_ticks: dw 0
invalid_ticks: dw 0
invalid_cached_ticks: dw 0
module_return_ax: dw 0
module_return_flags: dw 0

align 2
operation_desc:
    dw 0, 0
    times 4 * tls13_286_span_bytes db 0
    times 2 * tls13_286_span_bytes db 0

%if operation_desc - $$ + 0x1000 < tls13_286_controller_load
%error "ML-KEM benchmark descriptor precedes controller window"
%endif
%if operation_desc - $$ + 0x1000 + tls13_286_desc_bytes > \
    tls13_286_controller_limit
%error "ML-KEM benchmark descriptor exceeds controller window"
%endif

tag_keygen db 'MLKMODKG', 0
tag_matrix db 'MLKMODMX', 0
tag_decap db 'MLKMODDC', 0
tag_cached db 'MLKMODCD', 0
tag_candidate db 'MLKMODCA', 0
tag_invalid_candidate db 'MLKMODCI', 0
tag_invalid db 'MLKMODIR', 0
tag_invalid_cached db 'MLKMODIC', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_n db ' N=', 0
str_dt db ' dt=', 0
str_check db ' N=1 dt=0 ck=', 0

times (tls13_286_module_load - 0x1000) - ($ - $$) db 0
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-keygen-module.bin"

times (0x8000 - 0x1000) - ($ - $$) db 0
decap_module_image:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-decap-module.bin"
expected_matrix_cache:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-expected-matrix-cache.bin"
expected_valid_rejection_secret:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-expected-valid-rejection-secret.bin"
; Reload source for the second one-shot keygen-module operation.  Keep it above
; the decap/oracle payload, never in the product stack/module band.
keygen_module_image:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-keygen-module.bin"
image_end:

%if decap_module_image - $$ + 0x1000 != bench_stack_top
%error "ML-KEM benchmark decap reload source moved off 0x8000"
%endif
%if keygen_module_image - $$ + 0x1000 < bench_stack_top
%error "ML-KEM benchmark duplicate keygen source entered product stack band"
%endif
%if (image_end - core_header + 511) / 512 > 103
%error "ML-KEM benchmark exceeds 103-sector exact-gate limit"
%endif
