
; Field elements are 16 little-endian 16-bit words modulo the P-256 prime.
; TLS ServerKeyExchange coordinates arrive as 32-byte big-endian values.

p256_from_be32:
    push ax
    push bx
    push cx
    push si
    push di
    mov bx, si
    add bx, tls_ec_coordinate_len - 1
    mov cx, p256_word_count
.next_word:
    mov al, [bx]
    mov ah, [bx - 1]
    mov [di], ax
    lea di, [di + 2]
    sub bx, 2
    loop .next_word
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

p256_to_be32:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov bx, si
    add bx, p256_word_len - 2
    mov cx, p256_word_count
.next_word:
    mov ax, [bx]
    xchg al, ah
    stosw
    sub bx, 2
    loop .next_word
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

p256_cmp_words:
    ; Returns CF=1 when SI value is below DI value, CF=0 otherwise.
    push ax
    push cx
    push si
    push di
    add si, p256_word_len - 2
    add di, p256_word_len - 2
    mov cx, p256_word_count
.next_word:
    mov ax, [si]
    cmp ax, [di]
    jb .less
    ja .greater_or_equal
    sub si, 2
    sub di, 2
    loop .next_word
.greater_or_equal:
    pop di
    pop si
    pop cx
    pop ax
    clc
    ret
.less:
    pop di
    pop si
    pop cx
    pop ax
    stc
    ret

p256_add_words:
    push ax
    push bx
    push cx
    push si
    push di
    mov cx, p256_word_count
    clc
.next_word:
    mov ax, [si]
    adc ax, [di]
    mov [bx], ax
    lea si, [si + 2]
    lea di, [di + 2]
    lea bx, [bx + 2]
    loop .next_word
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

p256_sub_words:
    push ax
    push bx
    push cx
    push si
    push di
    mov cx, p256_word_count
    clc
.next_word:
    mov ax, [si]
    sbb ax, [di]
    mov [bx], ax
    lea si, [si + 2]
    lea di, [di + 2]
    lea bx, [bx + 2]
    loop .next_word
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

p256_add_prime_inplace:
    push ax
    push cx
    push si
    push di
    mov si, p256_prime
    mov cx, p256_word_count
    clc
.next_word:
    mov ax, [di]
    adc ax, [si]
    mov [di], ax
    lea si, [si + 2]
    lea di, [di + 2]
    loop .next_word
    pop di
    pop si
    pop cx
    pop ax
    ret

p256_sub_prime_inplace:
    push ax
    push cx
    push si
    push di
    mov si, p256_prime
    mov cx, p256_word_count
    clc
.next_word:
    mov ax, [di]
    sbb ax, [si]
    mov [di], ax
    lea si, [si + 2]
    lea di, [di + 2]
    loop .next_word
    pop di
    pop si
    pop cx
    pop ax
    ret

p256_add_mod:
    call p256_add_words
    mov al, 0
    adc al, 0
    mov [p256_carry], al
    cmp byte [p256_carry], 0
    jne .subtract_prime
    push si
    push di
    mov si, bx
    mov di, p256_prime
    call p256_cmp_words
    pop di
    pop si
    jc .done
.subtract_prime:
    push di
    mov di, bx
    call p256_sub_prime_inplace
    pop di
.done:
    ret

p256_sub_mod:
    call p256_sub_words
    mov al, 0
    adc al, 0
    cmp al, 0
    je .done
    push di
    mov di, bx
    call p256_add_prime_inplace
    pop di
.done:
    ret

p256_double_mod:
    push di
    mov di, si
    call p256_add_mod
    pop di
    ret

p256_quad_mod:
    push si
    call p256_double_mod
    mov si, bx
    call p256_double_mod
    pop si
    ret

p256_eight_mod:
    push si
    call p256_quad_mod
    mov si, bx
    call p256_double_mod
    pop si
    ret

p256_copy_words:
    push cx
    push si
    push di
    push es
    mov cx, p256_word_count
    push ds
    pop es
    rep movsw
    pop es
    pop di
    pop si
    pop cx
    ret

p256_clear_words:
    push ax
    push cx
    push di
    push es
    xor ax, ax
    mov cx, p256_word_count
    push ds
    pop es
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret

p256_set_one:
    call p256_clear_words
    mov word [di], 1
    ret

p256_is_zero:
    ; Returns CF=1 when the field element at SI is zero.
    push ax
    push cx
    push si
    mov cx, p256_word_count
.next_word:
    mov ax, [si]
    or ax, ax
    jnz .not_zero
    lea si, [si + 2]
    loop .next_word
    pop si
    pop cx
    pop ax
    stc
    ret
.not_zero:
    pop si
    pop cx
    pop ax
    clc
    ret

p256_is_one:
    ; Returns CF=1 when the field element at SI is exactly one.
    push ax
    push cx
    push si
    lodsw
    cmp ax, 1
    jne .not_one
    mov cx, p256_word_count - 1
.next_word:
    lodsw
    or ax, ax
    jnz .not_one
    loop .next_word
    pop si
    pop cx
    pop ax
    stc
    ret
.not_one:
    pop si
    pop cx
    pop ax
    clc
    ret

p256_rshift1_inplace:
    ; Logical right shift of a 256-bit little-endian word array at DI.
    push cx
    push di
    add di, p256_word_len - 2
    mov cx, p256_word_count
    clc
.next_word:
    rcr word [di], 1
    lea di, [di - 2]
    loop .next_word
    pop di
    pop cx
    ret

p256_add_prime_rshift1_inplace:
    ; DI = (DI + p) / 2. Carries the 257th bit through the shift.
    push ax
    push cx
    push si
    push di
    mov si, p256_prime
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

p256_point_set_infinity:
    mov di, p256_jac_x
    call p256_clear_words
    mov di, p256_jac_y
    call p256_clear_words
    mov di, p256_jac_z
    jmp p256_clear_words

p256_point_set_from_affine:
    mov si, [p256_affine_x_ptr]
    mov di, p256_jac_x
    call p256_copy_words
    mov si, [p256_affine_y_ptr]
    mov di, p256_jac_y
    call p256_copy_words
    mov di, p256_jac_z
    jmp p256_set_one

p256_point_double_jacobian:
    ; In-place Jacobian point doubling for the current p256_jac_* point.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov si, p256_jac_z
    call p256_is_zero
    jc .done
    mov si, p256_jac_y
    call p256_is_zero
    jc .infinity
    mov si, p256_jac_z
    mov di, p256_jac_z
    mov bx, p256_s0
    call p256_mul_mod
    mov si, p256_jac_y
    mov di, p256_jac_y
    mov bx, p256_s1
    call p256_mul_mod
    mov si, p256_jac_x
    mov di, p256_s1
    mov bx, p256_s2
    call p256_mul_mod
    mov si, p256_jac_x
    mov di, p256_s0
    mov bx, p256_s3
    call p256_sub_mod
    mov si, p256_jac_x
    mov di, p256_s0
    mov bx, p256_s4
    call p256_add_mod
    mov si, p256_s3
    mov di, p256_s4
    mov bx, p256_s3
    call p256_mul_mod
    mov si, p256_s3
    mov bx, p256_s4
    call p256_double_mod
    mov si, p256_s4
    mov di, p256_s3
    mov bx, p256_s3
    call p256_add_mod
    mov si, p256_s3
    mov di, p256_s3
    mov bx, p256_s4
    call p256_mul_mod
    mov si, p256_s2
    mov bx, p256_s5
    call p256_eight_mod
    mov si, p256_s4
    mov di, p256_s5
    mov bx, p256_jac_x
    call p256_sub_mod
    mov si, p256_jac_y
    mov di, p256_jac_z
    mov bx, p256_s4
    call p256_add_mod
    mov si, p256_s4
    mov di, p256_s4
    mov bx, p256_s4
    call p256_mul_mod
    mov si, p256_s4
    mov di, p256_s1
    mov bx, p256_s4
    call p256_sub_mod
    mov si, p256_s4
    mov di, p256_s0
    mov bx, p256_jac_z
    call p256_sub_mod
    mov si, p256_s2
    mov bx, p256_s4
    call p256_quad_mod
    mov si, p256_s4
    mov di, p256_jac_x
    mov bx, p256_s4
    call p256_sub_mod
    mov si, p256_s3
    mov di, p256_s4
    mov bx, p256_s4
    call p256_mul_mod
    mov si, p256_s1
    mov di, p256_s1
    mov bx, p256_s5
    call p256_mul_mod
    mov si, p256_s5
    mov bx, p256_s5
    call p256_eight_mod
    mov si, p256_s4
    mov di, p256_s5
    mov bx, p256_jac_y
    call p256_sub_mod
    jmp .done
.infinity:
    call p256_point_set_infinity
.done:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

p256_point_add_mixed:
    ; In-place p256_jac_* += affine point referenced by p256_affine_*_ptr.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov si, p256_jac_z
    call p256_is_zero
    jc .copy_affine
    mov si, p256_jac_z
    mov di, p256_jac_z
    mov bx, p256_s0
    call p256_mul_mod
    mov si, [p256_affine_x_ptr]
    mov di, p256_s0
    mov bx, p256_s1
    call p256_mul_mod
    mov si, p256_jac_z
    mov di, p256_s0
    mov bx, p256_s2
    call p256_mul_mod
    mov si, [p256_affine_y_ptr]
    mov di, p256_s2
    mov bx, p256_s2
    call p256_mul_mod
    mov si, p256_s1
    mov di, p256_jac_x
    mov bx, p256_s3
    call p256_sub_mod
    mov si, p256_s2
    mov di, p256_jac_y
    mov bx, p256_s6
    call p256_sub_mod
    mov si, p256_s3
    call p256_is_zero
    jnc .regular_add
    mov si, p256_s6
    call p256_is_zero
    jc .same_point
    call p256_point_set_infinity
    jmp .done
.same_point:
    call p256_point_double_jacobian
    jmp .done
.regular_add:
    mov si, p256_s3
    mov di, p256_s3
    mov bx, p256_s4
    call p256_mul_mod
    mov si, p256_s4
    mov bx, p256_s4
    call p256_quad_mod
    mov si, p256_s3
    mov di, p256_s4
    mov bx, p256_s5
    call p256_mul_mod
    mov si, p256_s6
    mov bx, p256_s6
    call p256_double_mod
    mov si, p256_jac_x
    mov di, p256_s4
    mov bx, p256_s7
    call p256_mul_mod
    mov si, p256_s6
    mov di, p256_s6
    mov bx, p256_s8
    call p256_mul_mod
    mov si, p256_s8
    mov di, p256_s5
    mov bx, p256_s8
    call p256_sub_mod
    mov si, p256_s7
    mov bx, p256_s4
    call p256_double_mod
    mov si, p256_s8
    mov di, p256_s4
    mov bx, p256_jac_x
    call p256_sub_mod
    mov si, p256_s7
    mov di, p256_jac_x
    mov bx, p256_s4
    call p256_sub_mod
    mov si, p256_s6
    mov di, p256_s4
    mov bx, p256_s4
    call p256_mul_mod
    mov si, p256_jac_y
    mov di, p256_s5
    mov bx, p256_s5
    call p256_mul_mod
    mov si, p256_s5
    mov bx, p256_s5
    call p256_double_mod
    mov si, p256_s4
    mov di, p256_s5
    mov bx, p256_jac_y
    call p256_sub_mod
    mov si, p256_s3
    mov di, p256_s3
    mov bx, p256_s8
    call p256_mul_mod
    mov si, p256_jac_z
    mov di, p256_s3
    mov bx, p256_s4
    call p256_add_mod
    mov si, p256_s4
    mov di, p256_s4
    mov bx, p256_s4
    call p256_mul_mod
    mov si, p256_s4
    mov di, p256_s0
    mov bx, p256_s4
    call p256_sub_mod
    mov si, p256_s4
    mov di, p256_s8
    mov bx, p256_jac_z
    call p256_sub_mod
    jmp .done
.copy_affine:
    call p256_point_set_from_affine
.done:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

p256_scalar_mult_mixed:
    ; Multiplies affine p256_affine_* by the 256-bit scalar at SI.
    ; The resulting Jacobian point is left in p256_jac_*.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov [p256_scalar_ptr], si
    call p256_point_set_infinity
    mov si, [p256_scalar_ptr]
    add si, p256_word_len - 2
    mov byte [p256_scalar_word_count], p256_word_count
.find_first_word:
    mov ax, [si]
    or ax, ax
    jnz .first_word_ready
    sub si, 2
    dec byte [p256_scalar_word_count]
    jnz .find_first_word
    jmp .done
.first_word_ready:
    mov [p256_scalar_word_ptr], si
    mov [p256_scalar_word_value], ax
    mov word [p256_scalar_mask], 0x8000
.find_first_bit:
    test ax, [p256_scalar_mask]
    jnz .bit_loop
    shr word [p256_scalar_mask], 1
    jmp .find_first_bit
.word_loop:
    mov si, [p256_scalar_word_ptr]
    mov ax, [si]
    mov [p256_scalar_word_value], ax
    mov word [p256_scalar_mask], 0x8000
.bit_loop:
    call p256_point_double_jacobian
    mov ax, [p256_scalar_word_value]
    test ax, [p256_scalar_mask]
    jz .skip_add
    call p256_point_add_mixed
.skip_add:
    shr word [p256_scalar_mask], 1
    cmp word [p256_scalar_mask], 0
    jne .bit_loop
    sub word [p256_scalar_word_ptr], 2
    dec byte [p256_scalar_word_count]
    jnz .word_loop
.done:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

p256_compute_server_shared_jacobian:
    ; Uses the current ServerKeyExchange public point and fixed client scalar.
    push si
    mov word [p256_affine_x_ptr], tls_server_ec_x_words
    mov word [p256_affine_y_ptr], tls_server_ec_y_words
    mov si, p256_client_private
    call p256_scalar_mult_mixed
    pop si
    ret

p256_compute_server_premaster_secret:
    call p256_client_private_is_one
    jnc .full_scalar
    mov si, tls_server_ec_x_words
    mov di, tls_premaster_secret
    call p256_to_be32
    clc
    ret
.full_scalar:
    call p256_client_private_is_two
    jnc .generic_scalar
    jmp p256_compute_server_premaster_secret_scalar2
.generic_scalar:
    call p256_compute_server_shared_jacobian
    mov si, p256_jac_z
    call p256_is_zero
    jc .failed
    mov si, p256_jac_z
    mov di, p256_s0
    call p256_inv_mod
    mov si, p256_s0
    mov di, p256_s0
    mov bx, p256_s1
    call p256_mul_mod
    mov si, p256_jac_x
    mov di, p256_s1
    mov bx, tls_shared_x_words
    call p256_mul_mod
    mov si, tls_shared_x_words
    mov di, tls_premaster_secret
    call p256_to_be32
    clc
    ret
.failed:
    stc
    ret

p256_client_private_is_one:
    ; Returns CF=1 for the current insecure Build 6 scalar fast path.
    push ax
    push cx
    push si
    cmp word [p256_client_private], 1
    jne .not_one
    mov si, p256_client_private + 2
    mov cx, p256_word_count - 1
.next:
    lodsw
    or ax, ax
    jnz .not_one
    loop .next
    pop si
    pop cx
    pop ax
    stc
    ret
.not_one:
    pop si
    pop cx
    pop ax
    clc
    ret

p256_client_private_is_two:
    push ax
    push cx
    push si
    cmp word [p256_client_private], 2
    jne .not_two
    mov si, p256_client_private + 2
    mov cx, p256_word_count - 1
.next:
    lodsw
    or ax, ax
    jnz .not_two
    loop .next
    pop si
    pop cx
    pop ax
    stc
    ret
.not_two:
    pop si
    pop cx
    pop ax
    clc
    ret

p256_compute_server_premaster_secret_scalar2:
    ; Affine double of the server point. Shared X = lambda^2 - 2*x.
    ; lambda = (3*x^2 - 3) / (2*y).
    mov si, tls_server_ec_y_words
    call p256_is_zero
    jc .failed
    mov si, tls_server_ec_x_words
    mov di, tls_server_ec_x_words
    mov bx, p256_s0
    call p256_mul_mod
    mov si, p256_s0
    mov bx, p256_s1
    call p256_double_mod
    mov si, p256_s1
    mov di, p256_s0
    mov bx, p256_s1
    call p256_add_mod
    mov si, p256_s1
    mov di, p256_three
    mov bx, p256_s1
    call p256_sub_mod
    mov si, p256_s1
    mov di, p256_s4
    call p256_copy_words
    mov si, tls_server_ec_y_words
    mov bx, p256_s2
    call p256_double_mod
    mov si, p256_s2
    mov di, p256_s2
    mov bx, p256_s2
    call p256_inv_mod
    mov si, p256_s4
    mov di, p256_s2
    mov bx, p256_s1
    call p256_mul_mod
    mov si, p256_s1
    mov di, p256_s1
    mov bx, p256_s2
    call p256_mul_mod
    mov si, tls_server_ec_x_words
    mov bx, p256_s0
    call p256_double_mod
    mov si, p256_s2
    mov di, p256_s0
    mov bx, tls_shared_x_words
    call p256_sub_mod
    mov si, tls_shared_x_words
    mov di, tls_premaster_secret
    call p256_to_be32
    clc
    ret
.failed:
    stc
    ret

p256_inv_mod:
    ; Binary extended-GCD inverse. This is slower than a tuned addition chain
    ; on modern CPUs, but much cheaper than exponentiation on an 8088.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov [p256_inv_output_ptr], di
    mov di, p256_s0
    call p256_copy_words
    mov si, p256_prime
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
    call p256_add_prime_rshift1_inplace
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
    call p256_add_prime_rshift1_inplace
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
    call p256_sub_mod
    jmp .main_loop
.v_larger:
    mov si, p256_s1
    mov di, p256_s0
    mov bx, p256_s1
    call p256_sub_words
    mov si, p256_s3
    mov di, p256_s2
    mov bx, p256_s3
    call p256_sub_mod
    jmp .main_loop
.copy_x1:
    mov si, p256_s2
    mov di, [p256_inv_output_ptr]
    call p256_copy_words
    clc
    jmp .done
.copy_x2:
    mov si, p256_s3
    mov di, [p256_inv_output_ptr]
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

p256_mul_mod:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    mov [p256_left_ptr], si
    mov [p256_right_ptr], di
    mov [p256_result_ptr], bx
    call p256_mul_product
    call p256_reduce_product
    mov si, p256_product
    mov di, [p256_result_ptr]
    mov cx, p256_word_count
    push ds
    pop es
    rep movsw
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; ===========================================================================
; WILDCARD optimisation: single-level subtractive Karatsuba field multiply.
;
;   A,B are 16 words. Split each into 8-word halves: A = A_hi*B^8 + A_lo.
;     z0 = A_lo * B_lo            (8x8 -> 16 words)
;     z2 = A_hi * B_hi            (8x8 -> 16 words)
;     m  = |A_hi-A_lo|*|B_hi-B_lo| (8x8 -> 16 words), sign = sgn(da)^sgn(db)
;   middle = z0 + z2 - da*db = z0 + z2 -/+ m
;   product = z0 + middle*B^8 + z2*B^16
;
; 3 half-multiplies = 3*64 = 192 single-word MULs instead of the schoolbook
; 256 (a 25% cut on the dominant MUL term), plus the 8x8 Comba below keeps
; acc0 in a register (one accumulator memory RMW per MUL, not three). The
; 512-bit product is written to p256_product so the existing reducer is
; unchanged -- correctness vs the oracle is preserved end-to-end.
; ===========================================================================

%define KHALF 8                          ; words per Karatsuba half
%define KHI   (KHALF * 2)                ; byte offset of the high half

p256_mul_product:
    push bp
    ; --- z0 = A_lo * B_lo -------------------------------------------------
    mov si, [p256_left_ptr]
    mov di, [p256_right_ptr]
    mov bx, p256_kz0
    call p256_kmul8
    ; --- z2 = A_hi * B_hi -------------------------------------------------
    mov si, [p256_left_ptr]
    add si, KHI
    mov di, [p256_right_ptr]
    add di, KHI
    mov bx, p256_kz2
    call p256_kmul8
    ; --- da = |A_hi - A_lo|, db = |B_hi - B_lo|, ksign = sgn(da)^sgn(db) --
    mov word [p256_ksign], 0
    mov si, [p256_left_ptr]
    add si, KHI                          ; A_hi
    mov di, [p256_left_ptr]              ; A_lo
    mov bx, p256_kda
    call p256_kabs_diff8                 ; |A_hi-A_lo| -> kda, CF=1 if negated
    jnc .da_pos
    not word [p256_ksign]                ; sign flip
.da_pos:
    mov si, [p256_right_ptr]
    add si, KHI                          ; B_hi
    mov di, [p256_right_ptr]             ; B_lo
    mov bx, p256_kdb
    call p256_kabs_diff8                 ; |B_hi-B_lo| -> kdb
    jnc .db_pos
    not word [p256_ksign]
.db_pos:
    ; --- m = |da| * |db| --------------------------------------------------
    mov si, p256_kda
    mov di, p256_kdb
    mov bx, p256_km
    call p256_kmul8
    ; --- assemble product = z0 + (z0+z2 -/+ m)*B^8 + z2*B^16 --------------
    ; product[0..15] = z0 ; product[16..31] = z2 (direct copies, no add)
    push es
    push ds
    pop es
    mov si, p256_kz0
    mov di, p256_product
    mov cx, p256_word_count
    rep movsw
    mov si, p256_kz2
    mov cx, p256_word_count
    rep movsw
    pop es
    ; kmid[0..15] = z0 + z2 ; kmid[16] = carry  (unrolled)
    mov ax, [p256_kz0+0]
    add ax, [p256_kz2+0]
    mov [p256_kmid+0], ax
    mov ax, [p256_kz0+2]
    adc ax, [p256_kz2+2]
    mov [p256_kmid+2], ax
    mov ax, [p256_kz0+4]
    adc ax, [p256_kz2+4]
    mov [p256_kmid+4], ax
    mov ax, [p256_kz0+6]
    adc ax, [p256_kz2+6]
    mov [p256_kmid+6], ax
    mov ax, [p256_kz0+8]
    adc ax, [p256_kz2+8]
    mov [p256_kmid+8], ax
    mov ax, [p256_kz0+10]
    adc ax, [p256_kz2+10]
    mov [p256_kmid+10], ax
    mov ax, [p256_kz0+12]
    adc ax, [p256_kz2+12]
    mov [p256_kmid+12], ax
    mov ax, [p256_kz0+14]
    adc ax, [p256_kz2+14]
    mov [p256_kmid+14], ax
    mov ax, [p256_kz0+16]
    adc ax, [p256_kz2+16]
    mov [p256_kmid+16], ax
    mov ax, [p256_kz0+18]
    adc ax, [p256_kz2+18]
    mov [p256_kmid+18], ax
    mov ax, [p256_kz0+20]
    adc ax, [p256_kz2+20]
    mov [p256_kmid+20], ax
    mov ax, [p256_kz0+22]
    adc ax, [p256_kz2+22]
    mov [p256_kmid+22], ax
    mov ax, [p256_kz0+24]
    adc ax, [p256_kz2+24]
    mov [p256_kmid+24], ax
    mov ax, [p256_kz0+26]
    adc ax, [p256_kz2+26]
    mov [p256_kmid+26], ax
    mov ax, [p256_kz0+28]
    adc ax, [p256_kz2+28]
    mov [p256_kmid+28], ax
    mov ax, [p256_kz0+30]
    adc ax, [p256_kz2+30]
    mov [p256_kmid+30], ax
    mov ax, 0
    adc ax, 0
    mov [p256_kmid+32], ax
    ; kmid -/+ m  (subtract m when da*db positive, else add)
    cmp word [p256_ksign], 0
    jne .mid_add_m
.mid_sub_m:
    mov ax, [p256_kmid+0]
    sub ax, [p256_km+0]
    mov [p256_kmid+0], ax
    mov ax, [p256_kmid+2]
    sbb ax, [p256_km+2]
    mov [p256_kmid+2], ax
    mov ax, [p256_kmid+4]
    sbb ax, [p256_km+4]
    mov [p256_kmid+4], ax
    mov ax, [p256_kmid+6]
    sbb ax, [p256_km+6]
    mov [p256_kmid+6], ax
    mov ax, [p256_kmid+8]
    sbb ax, [p256_km+8]
    mov [p256_kmid+8], ax
    mov ax, [p256_kmid+10]
    sbb ax, [p256_km+10]
    mov [p256_kmid+10], ax
    mov ax, [p256_kmid+12]
    sbb ax, [p256_km+12]
    mov [p256_kmid+12], ax
    mov ax, [p256_kmid+14]
    sbb ax, [p256_km+14]
    mov [p256_kmid+14], ax
    mov ax, [p256_kmid+16]
    sbb ax, [p256_km+16]
    mov [p256_kmid+16], ax
    mov ax, [p256_kmid+18]
    sbb ax, [p256_km+18]
    mov [p256_kmid+18], ax
    mov ax, [p256_kmid+20]
    sbb ax, [p256_km+20]
    mov [p256_kmid+20], ax
    mov ax, [p256_kmid+22]
    sbb ax, [p256_km+22]
    mov [p256_kmid+22], ax
    mov ax, [p256_kmid+24]
    sbb ax, [p256_km+24]
    mov [p256_kmid+24], ax
    mov ax, [p256_kmid+26]
    sbb ax, [p256_km+26]
    mov [p256_kmid+26], ax
    mov ax, [p256_kmid+28]
    sbb ax, [p256_km+28]
    mov [p256_kmid+28], ax
    mov ax, [p256_kmid+30]
    sbb ax, [p256_km+30]
    mov [p256_kmid+30], ax
    sbb word [p256_kmid+32], 0
    jmp .mid_into_product
.mid_add_m:
    mov ax, [p256_kmid+0]
    add ax, [p256_km+0]
    mov [p256_kmid+0], ax
    mov ax, [p256_kmid+2]
    adc ax, [p256_km+2]
    mov [p256_kmid+2], ax
    mov ax, [p256_kmid+4]
    adc ax, [p256_km+4]
    mov [p256_kmid+4], ax
    mov ax, [p256_kmid+6]
    adc ax, [p256_km+6]
    mov [p256_kmid+6], ax
    mov ax, [p256_kmid+8]
    adc ax, [p256_km+8]
    mov [p256_kmid+8], ax
    mov ax, [p256_kmid+10]
    adc ax, [p256_km+10]
    mov [p256_kmid+10], ax
    mov ax, [p256_kmid+12]
    adc ax, [p256_km+12]
    mov [p256_kmid+12], ax
    mov ax, [p256_kmid+14]
    adc ax, [p256_km+14]
    mov [p256_kmid+14], ax
    mov ax, [p256_kmid+16]
    adc ax, [p256_km+16]
    mov [p256_kmid+16], ax
    mov ax, [p256_kmid+18]
    adc ax, [p256_km+18]
    mov [p256_kmid+18], ax
    mov ax, [p256_kmid+20]
    adc ax, [p256_km+20]
    mov [p256_kmid+20], ax
    mov ax, [p256_kmid+22]
    adc ax, [p256_km+22]
    mov [p256_kmid+22], ax
    mov ax, [p256_kmid+24]
    adc ax, [p256_km+24]
    mov [p256_kmid+24], ax
    mov ax, [p256_kmid+26]
    adc ax, [p256_km+26]
    mov [p256_kmid+26], ax
    mov ax, [p256_kmid+28]
    adc ax, [p256_km+28]
    mov [p256_kmid+28], ax
    mov ax, [p256_kmid+30]
    adc ax, [p256_km+30]
    mov [p256_kmid+30], ax
    adc word [p256_kmid+32], 0
.mid_into_product:
    ; product[8..24] += kmid (17 words, unrolled), ripple to product end
    mov di, p256_product + KHI
    mov ax, [p256_kmid+0]
    add [di+0], ax
    mov ax, [p256_kmid+2]
    adc [di+2], ax
    mov ax, [p256_kmid+4]
    adc [di+4], ax
    mov ax, [p256_kmid+6]
    adc [di+6], ax
    mov ax, [p256_kmid+8]
    adc [di+8], ax
    mov ax, [p256_kmid+10]
    adc [di+10], ax
    mov ax, [p256_kmid+12]
    adc [di+12], ax
    mov ax, [p256_kmid+14]
    adc [di+14], ax
    mov ax, [p256_kmid+16]
    adc [di+16], ax
    mov ax, [p256_kmid+18]
    adc [di+18], ax
    mov ax, [p256_kmid+20]
    adc [di+20], ax
    mov ax, [p256_kmid+22]
    adc [di+22], ax
    mov ax, [p256_kmid+24]
    adc [di+24], ax
    mov ax, [p256_kmid+26]
    adc [di+26], ax
    mov ax, [p256_kmid+28]
    adc [di+28], ax
    mov ax, [p256_kmid+30]
    adc [di+30], ax
    mov ax, [p256_kmid+32]
    adc [di+32], ax
    jnc .assembled
    lea di, [di + 34]
.pmid_ripple:
    cmp di, p256_product + p256_product_word_len
    jae .assembled
    add word [di], 1
    lea di, [di + 2]
    jc .pmid_ripple
.assembled:
    pop bp
    ret

p256_kmul8:
    ; SI=a base (8 words), DI=b base (8 words), BX=dest base (16 words out).
    ; Fully-unrolled Comba; acc0=BP, acc1=BX(after save), acc2=CX. di/si
    ; hold the operand bases for the whole routine; column words are
    ; written to the fixed p256_kprod scratch, copied to dest at the end.
    mov [p256_kdest], bx
    push si
    push di
    push bp
    xor bp, bp                 ; acc0
    xor bx, bx                 ; acc1
    xor cx, cx                 ; acc2
    ; column 0
    mov ax, [si+0]
    mul word [di+0]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+0], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 1
    mov ax, [si+0]
    mul word [di+2]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+2]
    mul word [di+0]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+2], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 2
    mov ax, [si+0]
    mul word [di+4]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+2]
    mul word [di+2]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+4]
    mul word [di+0]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+4], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 3
    mov ax, [si+0]
    mul word [di+6]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+2]
    mul word [di+4]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+4]
    mul word [di+2]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+6]
    mul word [di+0]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+6], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 4
    mov ax, [si+0]
    mul word [di+8]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+2]
    mul word [di+6]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+4]
    mul word [di+4]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+6]
    mul word [di+2]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+8]
    mul word [di+0]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+8], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 5
    mov ax, [si+0]
    mul word [di+10]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+2]
    mul word [di+8]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+4]
    mul word [di+6]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+6]
    mul word [di+4]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+8]
    mul word [di+2]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+10]
    mul word [di+0]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+10], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 6
    mov ax, [si+0]
    mul word [di+12]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+2]
    mul word [di+10]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+4]
    mul word [di+8]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+6]
    mul word [di+6]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+8]
    mul word [di+4]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+10]
    mul word [di+2]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+12]
    mul word [di+0]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+12], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 7
    mov ax, [si+0]
    mul word [di+14]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+2]
    mul word [di+12]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+4]
    mul word [di+10]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+6]
    mul word [di+8]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+8]
    mul word [di+6]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+10]
    mul word [di+4]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+12]
    mul word [di+2]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+14]
    mul word [di+0]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+14], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 8
    mov ax, [si+2]
    mul word [di+14]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+4]
    mul word [di+12]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+6]
    mul word [di+10]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+8]
    mul word [di+8]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+10]
    mul word [di+6]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+12]
    mul word [di+4]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+14]
    mul word [di+2]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+16], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 9
    mov ax, [si+4]
    mul word [di+14]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+6]
    mul word [di+12]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+8]
    mul word [di+10]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+10]
    mul word [di+8]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+12]
    mul word [di+6]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+14]
    mul word [di+4]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+18], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 10
    mov ax, [si+6]
    mul word [di+14]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+8]
    mul word [di+12]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+10]
    mul word [di+10]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+12]
    mul word [di+8]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+14]
    mul word [di+6]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+20], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 11
    mov ax, [si+8]
    mul word [di+14]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+10]
    mul word [di+12]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+12]
    mul word [di+10]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+14]
    mul word [di+8]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+22], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 12
    mov ax, [si+10]
    mul word [di+14]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+12]
    mul word [di+12]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+14]
    mul word [di+10]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+24], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 13
    mov ax, [si+12]
    mul word [di+14]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov ax, [si+14]
    mul word [di+12]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+26], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    ; column 14
    mov ax, [si+14]
    mul word [di+14]
    add bp, ax
    adc bx, dx
    adc cx, 0
    mov [p256_kprod+28], bp
    mov bp, bx                 ; acc0 <- acc1
    mov bx, cx                 ; acc1 <- acc2
    xor cx, cx                 ; acc2 <- 0
    mov [p256_kprod+30], bp
    ; copy 16 result words p256_kprod -> dest
    pop bp
    push ds
    pop es
    mov si, p256_kprod
    mov di, [p256_kdest]
    mov cx, 16
    rep movsw
    pop di
    pop si
    ret

; --- |[SI] - [DI]| -> [BX], 8 words. Returns CF=1 if the result was negated.
p256_kabs_diff8:
    push ax
    push cx
    push si
    push di
    push bx
    ; first try dest = SI - DI
    push si
    push di
    mov cx, KHALF
    clc
.sub1:
    mov ax, [si]
    sbb ax, [di]
    mov [bx], ax
    lea si, [si + 2]
    lea di, [di + 2]
    lea bx, [bx + 2]
    loop .sub1
    pop di
    pop si
    jnc .positive
    ; negative: recompute dest = DI - SI
    pop bx
    push bx
    mov cx, KHALF
    clc
.sub2:
    mov ax, [di]
    sbb ax, [si]
    mov [bx], ax
    lea si, [si + 2]
    lea di, [di + 2]
    lea bx, [bx + 2]
    loop .sub2
    pop bx
    pop di
    pop si
    pop cx
    pop ax
    stc
    ret
.positive:
    pop bx
    pop di
    pop si
    pop cx
    pop ax
    clc
    ret


p256_reduce_product:
    call p256_reduce_init_acc
    call p256_reduce_fold_high_words
.normalize:
    call p256_reduce_normalize_acc
    cmp word [p256_reduce_carry], 0
    je .copy_result
    call p256_reduce_fold_carry
    jmp .normalize
.copy_result:
    call p256_reduce_copy_acc_to_product
.correct:
    mov si, p256_product
    mov di, p256_prime
    call p256_cmp_words
    jc .done
    mov di, p256_product
    call p256_sub_prime_inplace
    jmp .correct
.done:
    ret

p256_reduce_init_acc:
    push ax
    push cx
    push si
    push di
    mov si, p256_product
    mov di, p256_reduce_acc
    mov cx, p256_word_count
.next_word:
    lodsw
    mov [di], ax
    mov word [di + 2], 0
    add di, 4
    loop .next_word
    pop di
    pop si
    pop cx
    pop ax
    ret

p256_reduce_fold_high_words:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov bx, p256_product + p256_word_len
    mov si, p256_reduce_coeffs
    mov byte [p256_i], p256_word_count
.high_loop:
    mov ax, [bx]
    mov [p256_mul_left_word], ax
    or ax, ax
    jz .skip_row
    mov di, p256_reduce_acc
    mov cx, p256_word_count
.coeff_loop:
    lodsb
    or al, al
    jz .next_coeff
    mov [p256_j], al
    mov ax, [p256_mul_left_word]
    xor dx, dx
    cmp byte [p256_j], 0xff
    je .subtract_coeff
    cmp byte [p256_j], 1
    je .add_coeff
    shl ax, 1
    rcl dx, 1
    cmp byte [p256_j], 2
    je .add_coeff
    add ax, [p256_mul_left_word]
    adc dx, 0
.add_coeff:
    add [di], ax
    adc [di + 2], dx
    jmp .next_coeff
.subtract_coeff:
    sub [di], ax
    sbb [di + 2], dx
.next_coeff:
    add di, 4
    loop .coeff_loop
    jmp .next_high
.skip_row:
    add si, p256_word_count
.next_high:
    add bx, 2
    dec byte [p256_i]
    jnz .high_loop
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

p256_reduce_normalize_acc:
    push ax
    push cx
    push dx
    push di
    mov word [p256_reduce_carry], 0
    mov di, p256_reduce_acc
    mov cx, p256_word_count
.next_word:
    mov ax, [p256_reduce_carry]
    cwd
    add [di], ax
    adc [di + 2], dx
    mov ax, [di + 2]
    mov [p256_reduce_carry], ax
    mov word [di + 2], 0
    add di, 4
    loop .next_word
    pop di
    pop dx
    pop cx
    pop ax
    ret

p256_reduce_fold_carry:
    push ax
    push di
    mov ax, [p256_reduce_carry]
    mov di, p256_reduce_acc
    call p256_reduce_add_signed_word
    mov ax, [p256_reduce_carry]
    mov di, p256_reduce_acc + 14 * 4
    call p256_reduce_add_signed_word
    mov ax, [p256_reduce_carry]
    mov di, p256_reduce_acc + 12 * 4
    call p256_reduce_sub_signed_word
    mov ax, [p256_reduce_carry]
    mov di, p256_reduce_acc + 6 * 4
    call p256_reduce_sub_signed_word
    pop di
    pop ax
    ret

p256_reduce_add_signed_word:
    push dx
    cwd
    add [di], ax
    adc [di + 2], dx
    pop dx
    ret

p256_reduce_sub_signed_word:
    push dx
    cwd
    sub [di], ax
    sbb [di + 2], dx
    pop dx
    ret

p256_reduce_copy_acc_to_product:
    push ax
    push cx
    push si
    push di
    mov si, p256_reduce_acc
    mov di, p256_product
    mov cx, p256_word_count
.next_word:
    mov ax, [si]
    mov [di], ax
    add si, 4
    add di, 2
    loop .next_word
    pop di
    pop si
    pop cx
    pop ax
    ret

; ---- Karatsuba scratch (defined by the variant; same data segment) --------
align 2
p256_kprod: times 16 dw 0
p256_kmid:  times 18 dw 0
p256_kz0:   times 16 dw 0
p256_kz2:   times 16 dw 0
p256_km:    times 16 dw 0
p256_kda:   times 8 dw 0
p256_kdb:   times 8 dw 0
p256_ksign:   dw 0
p256_kdest:   dw 0
