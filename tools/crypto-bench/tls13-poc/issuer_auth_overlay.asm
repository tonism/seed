; Product-shaped issuer-authorized TLS 1.3 P-256 authentication overlay.
;
; Runtime contract:
;   * cpu 8086, ORG/load address 0x1800;
;   * one K-window image, at most 0x1e00 / 7680 bytes;
;   * mutable point/ECDSA work overlays the offline low scratch
;     0x0700..0x1000 and never reaches the resident nucleus;
;   * the default isolated ABI uses the 0x3b9c..0x3c9c attempt cache;
;   * TLS13_POC_READ_ONLY_INPUT instead uses the retired lower K14 extension
;     so the complete symmetric ticket remains in place;
;   * arena/context/reconnect/stack state is untouched;
;   * pass 1 authenticates a dynamic leaf point under immutable WE1;
;   * pass 2 can use only the leaf committed by a successful pass 1.
;
; The phase-local input ABI is reused between calls:
;   issuer_input_profile_flags word, exact parser/profile proof bitmap
;   issuer_input_generation    nonzero caller attempt generation
;   issuer_input_digest        32-byte SHA-256 digest (big-endian)
;   issuer_input_signature_len word, 8..72
;   issuer_input_signature     strict DER ECDSA signature
;   issuer_input_leaf_x_be     pass-1 candidate uncompressed-SPKI x
;   issuer_input_leaf_y_be     pass-1 candidate uncompressed-SPKI y
;
; Call the pass-1 pointer at K+0, reload the phase if desired, replace the
; digest/signature/profile input, then call pass 2 at K+2.  CF=0 and AX=1 mean
; success.  Every rejection returns CF=1 and AX=0.  The output byte is 1 only
; on success; callers must not expose internal failure stage differences.

bits 16
cpu 8086
org 0x1800

%include "layout.inc"

p256_word_count equ 16
p256_word_len equ p256_word_count * 2
p256_product_word_count equ p256_word_count * 2
p256_product_word_len equ p256_product_word_count * 2
tls_ec_coordinate_len equ 32

; Quarantined input ABI. Eight-byte sentinels at both ends are checker-owned
; and intentionally never read or written by target code. The read-only
; integration profile begins exactly after the 14-sector phase image and ends
; below symmetric extension work. It is populated only after the controller
; that formerly occupied 0x3400..0x3600 has retired.
%ifdef TLS13_POC_READ_ONLY_INPUT
; The low checker sentinel occupies the final eight bytes of the rounded phase
; image; a real phase reload may replace that sentinel, but never the input
; beginning exactly at 0x3400.
issuer_input_guard_lo equ poc_k_extension_start - 8
%else
issuer_input_guard_lo equ poc_attempt_cache_start
%endif
issuer_input_profile_flags equ issuer_input_guard_lo + 8
issuer_input_generation equ issuer_input_profile_flags + 2
issuer_input_digest equ issuer_input_generation + 2
issuer_input_signature_len equ issuer_input_digest + 32
issuer_input_signature equ issuer_input_signature_len + 2
issuer_input_signature_max equ 72
issuer_input_leaf_x_be equ issuer_input_signature + issuer_input_signature_max
issuer_input_leaf_y_be equ issuer_input_leaf_x_be + 32
issuer_output_status equ issuer_input_leaf_y_be + 32
issuer_input_end equ issuer_output_status + 1
%ifdef TLS13_POC_READ_ONLY_INPUT
issuer_input_guard_hi equ poc_k_extension_sym_work_start - 8
%else
issuer_input_guard_hi equ poc_attempt_cache_end - 8
%endif

issuer_leaf_profile_required equ 0x003f
issuer_cv_profile_required equ 0x0700

%if issuer_input_end > issuer_input_guard_hi
%error "issuer authentication input ABI exceeds its quarantined phase slot"
%endif
%ifdef TLS13_POC_READ_ONLY_INPUT
%if issuer_input_profile_flags != poc_k_end
%error "read-only issuer input must begin after the complete K14 phase image"
%endif
%if issuer_input_guard_hi + 8 > poc_k_extension_sym_work_start
%error "read-only issuer input reaches symmetric extension work"
%endif
%endif

; Post-FO high state.  Status is committed last.  The checksum is an accidental
; corruption/torn-handoff sentinel, not a substitute for the pass-1 ECDSA
; proof or a defense against arbitrary RAM writes.
issuer_commit_status equ poc_high_start
issuer_commit_reserved equ issuer_commit_status + 1
issuer_commit_magic equ issuer_commit_reserved + 1
issuer_commit_magic_inverse equ issuer_commit_magic + 4
issuer_commit_generation equ issuer_commit_magic_inverse + 4
issuer_commit_profile equ issuer_commit_generation + 2
issuer_commit_leaf_x_be equ issuer_commit_profile + 2
issuer_commit_leaf_y_be equ issuer_commit_leaf_x_be + 32
issuer_commit_cert_digest equ issuer_commit_leaf_y_be + 32
issuer_commit_checksum_a equ issuer_commit_cert_digest + 32
issuer_commit_checksum_b equ issuer_commit_checksum_a + 2
issuer_commit_end equ issuer_commit_checksum_b + 2
issuer_commit_check_start equ issuer_commit_generation
issuer_commit_check_len equ issuer_commit_checksum_a - issuer_commit_check_start

%if issuer_commit_end > poc_fo_ciphertext_end
%error "issuer-auth handoff exceeds the retired post-FO ciphertext band"
%endif

; Authentication is post-socket and post-FO, so the low phase/packet/file
; window is dead and may hold all mutable curve state.  These equates replace
; both the benchmark's point state and p256.inc's private wNAF/Karatsuba work.
; Nothing mutable needs to remain inside the K image.
auth_work_start equ poc_low_scratch_start
p256_jac_x equ auth_work_start
p256_jac_y equ p256_jac_x + 32
p256_jac_z equ p256_jac_y + 32
p256_s0 equ p256_jac_z + 32
p256_s1 equ p256_s0 + 32
p256_s2 equ p256_s1 + 32
p256_s3 equ p256_s2 + 32
p256_s4 equ p256_s3 + 32
p256_s5 equ p256_s4 + 32
p256_s6 equ p256_s5 + 32
p256_s7 equ p256_s6 + 32
p256_s8 equ p256_s7 + 32
p256_product equ p256_s8 + 32
p256_carry equ p256_product + 72
p256_ptr_base equ (p256_carry + 2) & ~1
p256_left_ptr equ p256_ptr_base
p256_right_ptr equ p256_left_ptr + 2
p256_result_ptr equ p256_right_ptr + 2
p256_inv_output_ptr equ p256_result_ptr + 2
p256_affine_x_ptr equ p256_inv_output_ptr + 2
p256_affine_y_ptr equ p256_affine_x_ptr + 2
p256_scalar_ptr equ p256_affine_y_ptr + 2

p256_client_private equ p256_s0
tls_server_ec_x_words equ p256_s1
tls_server_ec_y_words equ p256_s2
tls_shared_x_words equ p256_s3
tls_premaster_secret equ p256_s4

auth_g_table_x equ p256_scalar_ptr + 2
auth_g_table_y equ auth_g_table_x + 128
auth_g_digits equ auth_g_table_y + 128
auth_g_count equ auth_g_digits + 264
auth_loop_index equ auth_g_count + 2
auth_leaf_x equ auth_loop_index + 2
auth_leaf_y equ auth_leaf_x + 32
auth_r equ auth_leaf_y + 32
auth_s equ auth_r + 32
auth_z equ auth_s + 32
auth_w equ auth_z + 32
auth_u1 equ auth_w + 32
auth_u2 equ auth_u1 + 32
auth_result_x equ auth_u2 + 32
auth_result_y equ auth_result_x + 32
auth_vars equ auth_result_y + 32
auth_signature_ptr equ auth_vars
auth_signature_len equ auth_signature_ptr + 2
auth_digest_ptr equ auth_signature_len + 2
auth_der_end equ auth_digest_ptr + 2
auth_der_output_ptr equ auth_der_end + 2
auth_der_next_ptr equ auth_der_output_ptr + 2
auth_n_inverse_output_ptr equ auth_der_next_ptr + 2
auth_n_multiply_output_ptr equ auth_n_inverse_output_ptr + 2
auth_n_multiply_right_ptr equ auth_n_multiply_output_ptr + 2
auth_point_x_ptr equ auth_n_multiply_right_ptr + 2
auth_point_y_ptr equ auth_point_x_ptr + 2
auth_private_work_end equ auth_point_y_ptr + 2
p256_external_work_start equ (auth_private_work_end + 1) & ~1
%define P256_EXTERNAL_WORK_BASE p256_external_work_start

; Fixed entry table.
issuer_auth_overlay_table:
    dw issuer_auth_verify_leaf
    dw issuer_auth_verify_certificate_verify
    dw issuer_auth_clear
    dw issuer_we1_spki_sha256
    dw issuer_auth_overlay_image_end - $$
    dw 1                              ; ABI version

; Pass 1: exact-profile parser output + dynamic point under immutable WE1.
issuer_auth_verify_leaf:
    mov byte [issuer_output_status], 0
    call issuer_auth_clear_commit
    cmp word [issuer_input_profile_flags], issuer_leaf_profile_required
    jne .failed
    cmp word [issuer_input_generation], 0
    je .failed

    mov si, issuer_input_leaf_x_be
    mov di, auth_leaf_x
    call p256_from_be32
    mov si, issuer_input_leaf_y_be
    mov di, auth_leaf_y
    call p256_from_be32
    mov si, auth_leaf_x
    mov di, auth_leaf_y
    call auth_validate_point
    jc .failed

    ; Generate G and immutable WE1 tables on target.
    mov si, issuer_we1_x
    mov di, issuer_we1_y
    call issuer_auth_build_tables
    call issuer_auth_verify_input_signature
    jc .failed

    call issuer_auth_commit_leaf
    mov byte [issuer_output_status], 1
    mov ax, 1
    clc
    ret
.failed:
    call issuer_auth_clear_commit
    xor ax, ax
    stc
    ret

; Pass 2: only the leaf in the pass-1 commit is used.  The untrusted input
; point capacity is deliberately ignored on this path.
issuer_auth_verify_certificate_verify:
    mov byte [issuer_output_status], 0
    cmp word [issuer_input_profile_flags], issuer_cv_profile_required
    jne .failed
    call issuer_auth_check_commit
    jc .failed

    mov si, issuer_commit_leaf_x_be
    mov di, auth_leaf_x
    call p256_from_be32
    mov si, issuer_commit_leaf_y_be
    mov di, auth_leaf_y
    call p256_from_be32
    mov si, auth_leaf_x
    mov di, auth_leaf_y
    call auth_validate_point
    jc .failed

    mov si, auth_leaf_x
    mov di, auth_leaf_y
    call issuer_auth_build_tables
    call issuer_auth_verify_input_signature
    jc .failed
    mov byte [issuer_output_status], 1
    mov ax, 1
    clc
    ret
.failed:
    call issuer_auth_clear_commit
    xor ax, ax
    stc
    ret

; Best-effort zeroization of mutable curve/input/commit state.  The immutable
; WE1 anchor and entry table remain.
issuer_auth_clear:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, auth_work_start
    mov cx, (p256_mutable_work_end - auth_work_start + 1) / 2
    rep stosw
    mov di, issuer_input_profile_flags
    mov cx, (issuer_output_status - issuer_input_profile_flags) / 2
    rep stosw
    mov byte [issuer_output_status], 0
    pop es
    pop di
    pop cx
    pop ax
    jmp issuer_auth_clear_commit

issuer_auth_clear_commit:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, issuer_commit_status
    mov cx, (issuer_commit_end - issuer_commit_status + 1) / 2
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret

; Publish an issuer-authenticated leaf handoff.  Status is written last.
issuer_auth_commit_leaf:
    push ax
    push cx
    push dx
    push si
    push di
    push es
    push ds
    pop es
    cld
    mov byte [issuer_commit_status], 0
    mov byte [issuer_commit_reserved], 0
    mov si, issuer_input_generation
    mov di, issuer_commit_generation
    movsw
    mov si, issuer_input_profile_flags
    movsw
    mov si, issuer_input_leaf_x_be
    mov cx, 32
    rep movsw
    mov si, issuer_input_digest
    mov cx, 16
    rep movsw
    mov si, issuer_commit_check_start
    mov cx, issuer_commit_check_len
    call issuer_auth_checksum
    mov [issuer_commit_checksum_a], ax
    mov [issuer_commit_checksum_b], dx
    mov word [issuer_commit_magic], 0x4557       ; "WE"
    mov word [issuer_commit_magic + 2], 0x2131   ; "1!"
    mov word [issuer_commit_magic_inverse], 0xbaa8
    mov word [issuer_commit_magic_inverse + 2], 0xdece
    mov byte [issuer_commit_status], 1
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop ax
    ret

; CF=0 only for a complete, same-attempt pass-1 handoff.
issuer_auth_check_commit:
    push ax
    push cx
    push dx
    push si
    cmp byte [issuer_commit_status], 1
    jne .failed
    cmp byte [issuer_commit_reserved], 0
    jne .failed
    cmp word [issuer_commit_magic], 0x4557
    jne .failed
    cmp word [issuer_commit_magic + 2], 0x2131
    jne .failed
    cmp word [issuer_commit_magic_inverse], 0xbaa8
    jne .failed
    cmp word [issuer_commit_magic_inverse + 2], 0xdece
    jne .failed
    mov ax, [issuer_input_generation]
    or ax, ax
    jz .failed
    cmp ax, [issuer_commit_generation]
    jne .failed
    cmp word [issuer_commit_profile], issuer_leaf_profile_required
    jne .failed
    mov si, issuer_commit_check_start
    mov cx, issuer_commit_check_len
    call issuer_auth_checksum
    cmp ax, [issuer_commit_checksum_a]
    jne .failed
    cmp dx, [issuer_commit_checksum_b]
    jne .failed
    clc
    jmp .done
.failed:
    stc
.done:
    pop si
    pop dx
    pop cx
    pop ax
    ret

; Lightweight torn/corruption check, deliberately not described as a MAC.
; Input SI/CX; output AX/DX.
issuer_auth_checksum:
    push bx
    mov ax, 0x6d5a
    mov dx, 0xb481
.byte:
    xor bx, bx
    mov bl, [si]
    inc si
    add ax, bx
    rol ax, 1
    xor dx, ax
    add dx, 0x9e37
    rol dx, 1
    loop .byte
    pop bx
    ret

; Input SI/DI is the active Q.  Generate G's retained table, then Q's table.
issuer_auth_build_tables:
    push si
    push di
    mov word [p256_affine_x_ptr], auth_generator_x
    mov word [p256_affine_y_ptr], auth_generator_y
    call p256_w_build_table
    call auth_save_generator_table
    pop di
    pop si
    mov [p256_affine_x_ptr], si
    mov [p256_affine_y_ptr], di
    jmp p256_w_build_table

issuer_auth_verify_input_signature:
    mov word [auth_signature_ptr], issuer_input_signature
    mov ax, [issuer_input_signature_len]
    mov [auth_signature_len], ax
    mov word [auth_digest_ptr], issuer_input_digest
    jmp auth_ecdsa_verify

; Full ECDSA verify after the caller selected an authenticated Q table.
auth_ecdsa_verify:
    mov si, [auth_signature_ptr]
    mov cx, [auth_signature_len]
    call auth_parse_signature
    jc auth_ecdsa_failed

    mov si, [auth_digest_ptr]
    mov di, auth_z
    call p256_from_be32

    mov si, auth_s
    mov di, auth_w
    call auth_n_inverse
    jc auth_ecdsa_failed
    mov si, auth_z
    mov di, auth_w
    mov bx, auth_u1
    call auth_n_multiply
    mov si, auth_r
    mov di, auth_w
    mov bx, auth_u2
    call auth_n_multiply

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

    mov si, auth_u2
    mov di, p256_w_scalar
    call p256_copy_words
    call auth_clear_active_digits
    call p256_w_recode

    call p256_point_set_infinity
    mov ax, [auth_g_count]
    cmp ax, [p256_w_count]
    jae .have_count
    mov ax, [p256_w_count]
.have_count:
    mov [auth_loop_index], ax
    or ax, ax
    jz auth_ecdsa_failed
.straus:
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
    jne .straus

    mov si, p256_jac_z
    call p256_is_zero
    jc auth_ecdsa_failed
    mov di, auth_result_x
    mov bx, auth_result_y
    call p256_w_to_affine

    ; p < 2n, so affine x mod n needs at most one subtraction.
    mov si, auth_result_x
    mov di, auth_order_n
    call p256_cmp_words
    jc .compare_r
    mov si, auth_result_x
    mov di, auth_order_n
    mov bx, auth_result_x
    call p256_sub_words
.compare_r:
    mov si, auth_result_x
    mov di, auth_r
    call auth_words_equal
    jc auth_ecdsa_failed
    clc
    ret
auth_ecdsa_failed:
    stc
    ret

; Strict short-form DER parser for P-256 ECDSA.
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
    cmp cx, issuer_input_signature_max
    ja .failed
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
    call p256_mul_mod
    mov si, [auth_point_x_ptr]
    mov di, si
    mov bx, p256_s1
    call p256_mul_mod
    mov si, p256_s1
    mov di, [auth_point_x_ptr]
    mov bx, p256_s2
    call p256_mul_mod
    mov si, [auth_point_x_ptr]
    mov bx, p256_s3
    call p256_double_mod
    mov si, p256_s3
    mov di, [auth_point_x_ptr]
    mov bx, p256_s3
    call p256_add_mod
    mov si, p256_s2
    mov di, p256_s3
    mov bx, p256_s4
    call p256_sub_mod
    mov si, p256_s4
    mov di, auth_curve_b
    mov bx, p256_s4
    call p256_add_mod
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

; Fixed 256-iteration multiplication modulo n.
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

auth_p256_code_start:
%include "core/p256.inc"
auth_p256_code_end:
auth_work_end equ p256_mutable_work_end

%if auth_p256_code_end != p256_code_end
%error "P-256 code-end marker moved away from included executable"
%endif
%if p256_mutable_work_start != p256_external_work_start
%error "P-256 external work does not begin after private authentication state"
%endif
%if p256_mutable_work_len != 896
%error "P-256 external work contract changed; re-audit low scratch"
%endif
%if auth_work_end > poc_low_scratch_end
%error "P-256 authentication work exceeds offline low scratch"
%endif

; Immutable P-256 constants.
align 2
p256_prime:
    dw 65535,65535,65535,65535,65535,65535,0,0
    dw 0,0,0,0,1,0,65535,65535
p256_three:
    dw 3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
auth_order_n:
    dw 9553,64611,51906,62393,40580,42775,64173,48358
    dw 65535,65535,65535,65535,0,0,65535,65535
auth_generator_x:
    dw 49814,55448,14661,62625,13216,11755,32129,30467
    dw 16626,25508,59109,63676,16967,57644,53746,27415
auth_generator_y:
    dw 20981,14271,16488,52150,24270,27441,13143,11214
    dw 40470,31759,60234,36583,32667,65050,17122,20451

auth_curve_b:
    dw 24651,10194,15422,15310,45302,52307,1712,25885
    dw 34492,30360,48469,46059,37863,43578,13784,23238

; Google Trust Services WE1 from the second certificate in the tracked chain.
; Coordinates are the little-endian field representation consumed by p256.inc.
issuer_we1_x:
    dw 60806,54652,14311,50713,6021,49500,3904,22599
    dw 23995,49735,34112,8451,18252,26455,15102,28621
issuer_we1_y:
    dw 64086,3842,9659,58918,39157,11302,22927,65296
    dw 59550,50374,63640,2563,5029,55066,33241,19355
issuer_we1_spki_sha256:
    db 0x90,0x87,0x69,0xe8,0xd3,0x44,0x77,0xcc
    db 0x2c,0xba,0x06,0x32,0xc8,0x86,0x05,0xb2
    db 0x2d,0x72,0x94,0xc0,0x84,0x0f,0x78,0x59
    db 0x6d,0x24,0x7c,0x64,0x5b,0x1a,0xfc,0x0e

issuer_auth_overlay_image_end:

%if (issuer_auth_overlay_image_end - $$) > (14 * 512)
%error "issuer-auth P-256 phase exceeds its 14-sector design target"
%endif
