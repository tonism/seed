; Literal-16-KiB post-Finished authentication spike.
;
; This benchmark executes two complete P-256 ECDSA verification equations:
;
;   1. synthetic leaf certificate signature under the pinned test WE1 key;
;   2. TLS 1.3 server CertificateVerify under that leaf key.
;
; Both signatures are strict canonical DER and the 8088 computes r/s, s^-1,
; u1=z/s, u2=r/s, and u1*G + u2*Q itself.  The width-4 Straus loop shares each
; doubling between the two bases.  Tables are generated on target from G,
; WE1, and leaf coordinates; no precomputed scalar result is embedded.
;
; This is still a spike boundary, not a TLS/X.509 implementation.  The paired
; host oracle owns exact X.509/SPKI/profile/scheme/context/time parsing.  The
; target validates the supplied affine coordinates and executes the two
; cryptographic proof equations.  The target has no Brotli decoder.

bits 16
cpu 8086
org 0x1000

%include "core/layout.inc"

auth_stack_guard_start equ 0x3a00
auth_stack_top equ 0x3ff0
auth_resumable_bytes equ 706

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
    mov sp, auth_stack_top
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init
    call auth_fill_stack_guard
    sti

    ; Start on a tick edge so the component differences are independently
    ; useful despite the PC BIOS tick's coarse 54.9 ms resolution.
    call read_tick_low
    mov bx, ax
.tick_edge:
    call read_tick_low
    cmp ax, bx
    je .tick_edge
    mov [auth_tick0], ax

    call auth_prepare
    jc .fail
    call read_tick_low
    mov [auth_tick1], ax

    call auth_verify_certificate
    jc .fail
    call read_tick_low
    mov [auth_tick2], ax

    call auth_build_leaf_table
    jc .fail
    call read_tick_low
    mov [auth_tick3], ax

    call auth_verify_certificate_verify
    jc .fail
    call read_tick_low
    mov [auth_tick4], ax
    mov byte [auth_passed], 1
    jmp .report

.fail:
    mov byte [auth_passed], 0
    call read_tick_low
    mov [auth_tick4], ax

.report:
    cli
    call auth_measure_stack
    mov [auth_stack_bytes], ax
    sti

    mov si, tag_authprep
    mov ax, [auth_tick1]
    sub ax, [auth_tick0]
    call emit_metric
    mov si, tag_authcert
    mov ax, [auth_tick2]
    sub ax, [auth_tick1]
    call emit_metric
    mov si, tag_authleaf
    mov ax, [auth_tick3]
    sub ax, [auth_tick2]
    call emit_metric
    mov si, tag_authcv
    mov ax, [auth_tick4]
    sub ax, [auth_tick3]
    call emit_metric
    mov si, tag_authpost
    mov ax, [auth_tick4]
    sub ax, [auth_tick1]
    call emit_metric
    mov si, tag_authtotal
    mov ax, [auth_tick4]
    sub ax, [auth_tick0]
    call emit_metric

    mov si, tag_authstack
    call emit_str
    mov ax, [auth_stack_bytes]
    call emit_dec16
    call emit_crlf
    mov si, tag_authstate
    call emit_str
    mov ax, auth_resumable_bytes
    call emit_dec16
    call emit_crlf

    cmp byte [auth_passed], 1
    jne .emit_fail
    mov si, tag_auth_pass
    jmp .emit_result
.emit_fail:
    mov si, tag_auth_fail
.emit_result:
    call emit_str
    call emit_crlf
    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

; Return AX=1 only when the complete target-executed two-signature gate passes.
; This direct entry is used by the independent Unicorn checker.
auth_integrated_gate:
    call auth_prepare
    jc .failed
    call auth_verify_certificate
    jc .failed
    call auth_build_leaf_table
    jc .failed
    call auth_verify_certificate_verify
    jc .failed
    mov ax, 1
    ret
.failed:
    xor ax, ax
    ret

; Validate G/WE1/leaf coordinates, build G's table into persistent storage,
; and leave WE1's table active in the core's default table.
auth_prepare:
    mov si, auth_generator_x
    mov di, auth_generator_y
    call auth_validate_point
    jc .failed
    mov si, auth_anchor_x
    mov di, auth_anchor_y
    call auth_validate_point
    jc .failed
    mov si, auth_leaf_x
    mov di, auth_leaf_y
    call auth_validate_point
    jc .failed

    mov word [p256_affine_x_ptr], auth_generator_x
    mov word [p256_affine_y_ptr], auth_generator_y
    call p256_w_build_table
    call auth_save_generator_table

    mov word [p256_affine_x_ptr], auth_anchor_x
    mov word [p256_affine_y_ptr], auth_anchor_y
    call p256_w_build_table
    clc
    ret
.failed:
    stc
    ret

auth_verify_certificate:
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

; Full ECDSA verify after exact-profile parsing has supplied Q's active table.
auth_ecdsa_verify:
auth_ecdsa_scalar_prep_start:
    mov si, [auth_signature_ptr]
    mov cx, [auth_signature_len]
    call auth_parse_signature
    jc auth_ecdsa_failed

    mov si, [auth_digest_ptr]
    mov di, auth_z
    call p256_from_be32

auth_ecdsa_n_inverse_start:
    mov si, auth_s
    mov di, auth_w
    call auth_n_inverse
    jc auth_ecdsa_failed
auth_ecdsa_n_inverse_end:
auth_ecdsa_n_mul_z_start:
    mov si, auth_z
    mov di, auth_w
    mov bx, auth_u1
    call auth_n_multiply
auth_ecdsa_n_mul_z_end:
auth_ecdsa_n_mul_r_start:
    mov si, auth_r
    mov di, auth_w
    mov bx, auth_u2
    call auth_n_multiply
auth_ecdsa_n_mul_r_end:

    ; Recode u1 and retain its digits separately.
    mov si, auth_u1
    mov di, p256_w_scalar
    call p256_copy_words
    call auth_clear_active_digits
    call p256_w_recode
    mov ax, [p256_w_count]
    mov [auth_g_count], ax
    mov si, p256_w_digits
    mov di, auth_g_digits
    mov cx, 132
    push ds
    pop es
    rep movsw

    ; Recode u2 in the core's active digit buffer.
    mov si, auth_u2
    mov di, p256_w_scalar
    call p256_copy_words
    call auth_clear_active_digits
    call p256_w_recode

auth_ecdsa_scalar_prep_end:
auth_ecdsa_straus_start:
    call p256_point_set_infinity
    mov ax, [auth_g_count]
    cmp ax, [p256_w_count]
    jae auth_ecdsa_have_count
    mov ax, [p256_w_count]
auth_ecdsa_have_count:
    mov [auth_loop_index], ax
    or ax, ax
    jz auth_ecdsa_failed

auth_ecdsa_straus_loop:
auth_ecdsa_straus_checkpoint:
    dec word [auth_loop_index]
    call p256_point_double_jacobian
    mov bx, [auth_loop_index]
    mov si, auth_g_digits
    add si, bx
    mov al, [si]
    call auth_add_generator_digit
    mov bx, [auth_loop_index]
    mov si, p256_w_digits
    add si, bx
    mov al, [si]
    call auth_add_active_digit
    cmp word [auth_loop_index], 0
    jne auth_ecdsa_straus_loop

auth_ecdsa_straus_end:
auth_ecdsa_affine_start:
    mov si, p256_jac_z
    call p256_is_zero
    jc auth_ecdsa_failed
    mov di, auth_result_x
    mov bx, auth_result_y
    call p256_w_to_affine

    ; Affine x is below p and p < 2n, so ECDSA's x mod n needs at most
    ; one subtraction.
    mov si, auth_result_x
    mov di, auth_order_n
    call p256_cmp_words
    jc auth_ecdsa_compare_r
    mov si, auth_result_x
    mov di, auth_order_n
    mov bx, auth_result_x
    call p256_sub_words
auth_ecdsa_compare_r:
    mov si, auth_result_x
    mov di, auth_r
    call auth_words_equal
    jc auth_ecdsa_failed
auth_ecdsa_affine_end:
    clc
    ret
auth_ecdsa_failed:
    stc
    ret

; Strict short-form DER parser for the P-256 ECDSA signature profile.
; It rejects long-form lengths, negative/redundantly padded integers, values
; wider than 256 bits, zero, and values >= n.  On success r/s are little-endian
; word arrays in auth_r/auth_s.
auth_parse_signature:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    cmp cx, 8
    jb .failed
    mov dx, si
    add dx, cx
    jc .failed
    mov [auth_der_end], dx
    lodsb
    cmp al, 0x30
    jne .failed
    lodsb
    test al, 0x80
    jnz .failed
    xor ah, ah
    mov bx, ax
    mov ax, cx
    sub ax, 2
    cmp bx, ax
    jne .failed
    mov di, auth_r
    call auth_parse_der_integer
    jc .failed
    mov di, auth_s
    call auth_parse_der_integer
    jc .failed
    cmp si, [auth_der_end]
    jne .failed
    clc
    jmp .done
.failed:
    stc
.done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Input SI advances past one INTEGER; DI names its 32-byte LE output.
auth_parse_der_integer:
    push ax
    push bx
    push cx
    push dx
    push di
    push bp
    cmp si, [auth_der_end]
    jae .failed
    lodsb
    cmp al, 0x02
    jne .failed
    cmp si, [auth_der_end]
    jae .failed
    lodsb
    test al, 0x80
    jnz .failed
    or al, al
    jz .failed
    xor ah, ah
    mov bx, ax
    mov ax, si
    add ax, bx
    jc .failed
    cmp ax, [auth_der_end]
    ja .failed
    mov al, [si]
    test al, 0x80
    jnz .failed
    or al, al
    jnz .unpadded
    cmp bx, 1
    jbe .failed
    test byte [si + 1], 0x80
    jz .failed
    inc si
    dec bx
.unpadded:
    cmp bx, p256_word_len
    ja .failed
    mov [auth_der_output_ptr], di
    call p256_clear_words
    mov bp, bx
    add di, bx
    dec di
.copy_big_endian:
    lodsb
    mov [di], al
    dec di
    dec bp
    jnz .copy_big_endian
    mov [auth_der_next_ptr], si
    mov si, [auth_der_output_ptr]
    call p256_is_zero
    jc .failed
    mov di, auth_order_n
    call p256_cmp_words
    jnc .failed
    mov si, [auth_der_next_ptr]
    clc
    jmp .done
.failed:
    stc
.done:
    pop bp
    pop di
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Validate canonical affine coordinate ranges and y^2=x^3-3x+b mod p.
; Input SI=x, DI=y.  CF=1 is failure.
auth_validate_point:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov [auth_point_x_ptr], si
    mov [auth_point_y_ptr], di
    mov di, p256_prime
    call p256_cmp_words
    jnc .failed
    mov si, [auth_point_y_ptr]
    mov di, p256_prime
    call p256_cmp_words
    jnc .failed

    mov si, [auth_point_y_ptr]
    mov di, si
    mov bx, p256_s0
    call p256_mul_mod                 ; s0 = y^2
    mov si, [auth_point_x_ptr]
    mov di, si
    mov bx, p256_s1
    call p256_mul_mod                 ; s1 = x^2
    mov si, p256_s1
    mov di, [auth_point_x_ptr]
    mov bx, p256_s2
    call p256_mul_mod                 ; s2 = x^3
    mov si, [auth_point_x_ptr]
    mov bx, p256_s3
    call p256_double_mod              ; s3 = 2x
    mov si, p256_s3
    mov di, [auth_point_x_ptr]
    mov bx, p256_s3
    call p256_add_mod                 ; s3 = 3x
    mov si, p256_s2
    mov di, p256_s3
    mov bx, p256_s4
    call p256_sub_mod                 ; s4 = x^3 - 3x
    mov si, p256_s4
    mov di, auth_curve_b
    mov bx, p256_s4
    call p256_add_mod                 ; s4 = x^3 - 3x + b
    mov si, p256_s0
    mov di, p256_s4
    call auth_words_equal
    jc .failed
    clc
    jmp .done
.failed:
    stc
.done:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Binary extended-GCD inverse modulo the P-256 group order n.
; Input SI, output DI; CF=1 for zero/non-invertible.
auth_n_inverse:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov [auth_n_inverse_output_ptr], di
    mov di, p256_s0
    call p256_copy_words
    mov si, auth_order_n
    mov di, p256_s1
    call p256_copy_words
    mov si, p256_s0
    call p256_is_zero
    jc .failed
    mov di, p256_s2
    call p256_set_one
    mov di, p256_s3
    call p256_clear_words
.main_loop:
    mov si, p256_s0
    call p256_is_one
    jc .copy_x1
    mov si, p256_s1
    call p256_is_one
    jc .copy_x2
.reduce_u:
    test word [p256_s0], 1
    jnz .reduce_v
    mov di, p256_s0
    call p256_rshift1_inplace
    test word [p256_s2], 1
    jnz .x1_odd
    mov di, p256_s2
    call p256_rshift1_inplace
    jmp .reduce_u
.x1_odd:
    mov di, p256_s2
    call auth_n_add_order_rshift1
    jmp .reduce_u
.reduce_v:
    test word [p256_s1], 1
    jnz .subtract
    mov di, p256_s1
    call p256_rshift1_inplace
    test word [p256_s3], 1
    jnz .x2_odd
    mov di, p256_s3
    call p256_rshift1_inplace
    jmp .reduce_v
.x2_odd:
    mov di, p256_s3
    call auth_n_add_order_rshift1
    jmp .reduce_v
.subtract:
    mov si, p256_s0
    mov di, p256_s1
    call p256_cmp_words
    jc .v_larger
    mov si, p256_s0
    mov di, p256_s1
    mov bx, p256_s0
    call p256_sub_words
    mov si, p256_s2
    mov di, p256_s3
    mov bx, p256_s2
    call auth_n_sub_mod
    jmp .main_loop
.v_larger:
    mov si, p256_s1
    mov di, p256_s0
    mov bx, p256_s1
    call p256_sub_words
    mov si, p256_s3
    mov di, p256_s2
    mov bx, p256_s3
    call auth_n_sub_mod
    jmp .main_loop
.copy_x1:
    mov si, p256_s2
    jmp .copy_result
.copy_x2:
    mov si, p256_s3
.copy_result:
    mov di, [auth_n_inverse_output_ptr]
    call p256_copy_words
    clc
    jmp .done
.failed:
    stc
.done:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Constant-iteration double-and-add multiplication modulo n.
; Input SI*DI -> BX.  The operands and output must not alias p256_s4..s6.
auth_n_multiply:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov [auth_n_multiply_output_ptr], bx
    mov [auth_n_multiply_right_ptr], di
    mov di, p256_s4
    call p256_copy_words
    mov si, [auth_n_multiply_right_ptr]
    mov di, p256_s6
    call p256_copy_words
    mov di, p256_s5
    call p256_clear_words
    mov cx, 256
.bit_loop:
    test word [p256_s6], 1
    jz .skip_add
    mov si, p256_s5
    mov di, p256_s4
    mov bx, p256_s5
    call auth_n_add_mod
.skip_add:
    mov si, p256_s4
    mov di, p256_s4
    mov bx, p256_s4
    call auth_n_add_mod
    mov di, p256_s6
    call p256_rshift1_inplace
    loop .bit_loop
    mov si, p256_s5
    mov di, [auth_n_multiply_output_ptr]
    call p256_copy_words
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

auth_n_add_mod:
    call p256_add_words
    mov al, 0
    adc al, 0
    jnz .subtract_n
    push si
    push di
    mov si, bx
    mov di, auth_order_n
    call p256_cmp_words
    pop di
    pop si
    jc .done
.subtract_n:
    push di
    mov di, bx
    call auth_n_sub_order_inplace
    pop di
.done:
    ret

auth_n_sub_mod:
    call p256_sub_words
    mov al, 0
    adc al, 0
    jz .done
    push di
    mov di, bx
    call auth_n_add_order_inplace
    pop di
.done:
    ret

auth_n_add_order_inplace:
    push ax
    push cx
    push si
    push di
    mov si, auth_order_n
    mov cx, p256_word_count
    clc
.word:
    mov ax, [di]
    adc ax, [si]
    mov [di], ax
    lea si, [si + 2]
    lea di, [di + 2]
    loop .word
    pop di
    pop si
    pop cx
    pop ax
    ret

auth_n_sub_order_inplace:
    push ax
    push cx
    push si
    push di
    mov si, auth_order_n
    mov cx, p256_word_count
    clc
.word:
    mov ax, [di]
    sbb ax, [si]
    mov [di], ax
    lea si, [si + 2]
    lea di, [di + 2]
    loop .word
    pop di
    pop si
    pop cx
    pop ax
    ret

auth_n_add_order_rshift1:
    push ax
    push cx
    push si
    push di
    mov si, auth_order_n
    mov cx, p256_word_count
    clc
.add_word:
    mov ax, [si]
    adc [di], ax
    lea si, [si + 2]
    lea di, [di + 2]
    loop .add_word
    pushf
    sub di, p256_word_len
    add di, p256_word_len - 2
    mov cx, p256_word_count
    popf
.shift_word:
    rcr word [di], 1
    lea di, [di - 2]
    loop .shift_word
    pop di
    pop si
    pop cx
    pop ax
    ret

auth_save_generator_table:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, p256_w_tableX
    mov di, auth_g_table_x
    mov cx, 64
    rep movsw
    mov si, p256_w_tableY
    mov di, auth_g_table_y
    mov cx, 64
    rep movsw
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

auth_clear_active_digits:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, p256_w_digits
    mov cx, 132
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret

; AL is a signed width-4 wNAF digit for the saved G table.
auth_add_generator_digit:
    or al, al
    jz .done
    push ax
    test al, 0x80
    jnz .negative
    mov ah, al
    dec ah
    shr ah, 1
    call auth_set_generator_positive
    jmp .add
.negative:
    neg al
    mov ah, al
    dec ah
    shr ah, 1
    call auth_set_generator_negative
.add:
    call p256_point_add_mixed
    pop ax
.done:
    ret

; AL is a signed width-4 wNAF digit for the active Q table.
auth_add_active_digit:
    or al, al
    jz .done
    push ax
    test al, 0x80
    jnz .negative
    mov ah, al
    dec ah
    shr ah, 1
    call p256_w_set_affine_pos
    jmp .add
.negative:
    neg al
    mov ah, al
    dec ah
    shr ah, 1
    call p256_w_set_affine_neg
.add:
    call p256_point_add_mixed
    pop ax
.done:
    ret

auth_set_generator_positive:
    push ax
    push bx
    push cx
    mov al, ah
    xor ah, ah
    mov cl, 5
    shl ax, cl
    mov bx, auth_g_table_x
    add bx, ax
    mov [p256_affine_x_ptr], bx
    mov bx, auth_g_table_y
    add bx, ax
    mov [p256_affine_y_ptr], bx
    pop cx
    pop bx
    pop ax
    ret

auth_set_generator_negative:
    push ax
    push bx
    push cx
    push si
    push di
    mov al, ah
    xor ah, ah
    mov cl, 5
    shl ax, cl
    mov bx, auth_g_table_x
    add bx, ax
    mov [p256_affine_x_ptr], bx
    mov si, p256_prime
    mov di, auth_g_table_y
    add di, ax
    mov bx, p256_w_negy
    call p256_sub_words
    mov word [p256_affine_y_ptr], p256_w_negy
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

; CF=0 equal, CF=1 different.
auth_words_equal:
    push ax
    push cx
    push si
    push di
    mov cx, p256_word_count
.word:
    mov ax, [si]
    cmp ax, [di]
    jne .different
    add si, 2
    add di, 2
    loop .word
    clc
    jmp .done
.different:
    stc
.done:
    pop di
    pop si
    pop cx
    pop ax
    ret

auth_fill_stack_guard:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    mov al, 0xa5
    mov di, auth_stack_guard_start
    mov cx, auth_stack_top - auth_stack_guard_start
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

auth_measure_stack:
    push bx
    push cx
    push di
    mov di, auth_stack_guard_start
    mov cx, auth_stack_top - auth_stack_guard_start
    mov al, 0xa5
    repe scasb
    jz .untouched
    dec di
    mov ax, auth_stack_top
    sub ax, di
    jmp .done
.untouched:
    xor ax, ax
.done:
    pop di
    pop cx
    pop bx
    ret

read_tick_low:
    mov ax, [0x046c]
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

emit_metric:
    push ax
    call emit_str
    mov si, str_dt
    call emit_str
    pop ax
    call emit_dec16
    call emit_crlf
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
    jmp .next
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
.pop_digit:
    pop ax
    add al, '0'
    call emit_char
    loop .pop_digit
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; The current checked-in optimized P-256 field/point/wNAF implementation is
; included read-only.  Its private tables/scratch follow its executable text.
tls_premaster_secret equ p256_s4
auth_p256_code_start:
%include "core/p256.inc"
auth_p256_code_end equ p256_w_tableX

; Minimal common data required by core/p256.inc.  The unused ECDHE-facing
; aliases satisfy routines present in the include but never called here.
align 2
p256_prime: dw 65535,65535,65535,65535,65535,65535,0,0,0,0,0,0,1,0,65535,65535
p256_three: dw 3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
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

%include "tls13-spike/auth_integrated_vectors.inc"

align 2
auth_g_table_x: times (4 * p256_word_count) dw 0
auth_g_table_y: times (4 * p256_word_count) dw 0
auth_g_digits: times 264 db 0
auth_g_count: dw 0
auth_loop_index: dw 0

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
auth_point_x_ptr: dw 0
auth_point_y_ptr: dw 0
auth_n_inverse_output_ptr: dw 0
auth_n_multiply_output_ptr: dw 0
auth_n_multiply_right_ptr: dw 0

auth_tick0: dw 0
auth_tick1: dw 0
auth_tick2: dw 0
auth_tick3: dw 0
auth_tick4: dw 0
auth_stack_bytes: dw 0
auth_passed: db 0

tag_authprep db 'AUTHPREP N=1', 0
tag_authcert db 'AUTHCERT N=1', 0
tag_authleaf db 'AUTHLEAF N=1', 0
tag_authcv db 'AUTHCV N=1', 0
tag_authpost db 'AUTHPOST N=1', 0
tag_authtotal db 'AUTHTOTAL N=1', 0
tag_authstack db 'AUTHSTACK N=', 0
tag_authstate db 'AUTHSTATE N=', 0
tag_auth_pass db 'AUTH PASS', 0
tag_auth_fail db 'AUTH FAIL', 0
tag_done db 'DONE', 0
str_dt db ' dt=', 0

image_end:
