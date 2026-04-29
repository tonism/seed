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

p256_point_set_infinity:
    mov di, p256_jac_x
    call p256_clear_words
    mov di, p256_jac_y
    call p256_clear_words
    mov di, p256_jac_z
    call p256_clear_words
    ret

p256_point_set_from_affine:
    mov si, [p256_affine_x_ptr]
    mov di, p256_jac_x
    call p256_copy_words
    mov si, [p256_affine_y_ptr]
    mov di, p256_jac_y
    call p256_copy_words
    mov di, p256_jac_z
    call p256_set_one
    ret

p256_validate_point_on_curve:
    ; Validates the loaded ServerKeyExchange point: y^2 == x^3 - 3x + b.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov si, tls_server_ec_y_words
    mov di, tls_server_ec_y_words
    mov bx, p256_lhs
    call p256_mul_mod
    mov si, tls_server_ec_x_words
    mov di, tls_server_ec_x_words
    mov bx, p256_rhs
    call p256_mul_mod
    mov si, p256_rhs
    mov di, tls_server_ec_x_words
    mov bx, p256_rhs
    call p256_mul_mod
    mov si, tls_server_ec_x_words
    mov di, tls_server_ec_x_words
    mov bx, p256_tmp
    call p256_add_mod
    mov si, p256_tmp
    mov di, tls_server_ec_x_words
    mov bx, p256_tmp
    call p256_add_mod
    mov si, p256_rhs
    mov di, p256_tmp
    mov bx, p256_rhs
    call p256_sub_mod
    mov si, p256_rhs
    mov di, p256_b
    mov bx, p256_rhs
    call p256_add_mod
    mov si, p256_lhs
    mov di, p256_rhs
    call p256_cmp_words
    jc .invalid
    mov si, p256_rhs
    mov di, p256_lhs
    call p256_cmp_words
    jc .invalid
    clc
    jmp .done
.invalid:
    stc
.done:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

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
    mov [p256_scalar_word_ptr], si
    mov byte [p256_scalar_word_count], p256_word_count
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

p256_inv_mod:
    ; Raises SI to p-2 and writes the field inverse to DI.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov [p256_inv_output_ptr], di
    mov di, p256_s1
    call p256_copy_words
    mov di, p256_s0
    call p256_set_one
    mov si, p256_prime_minus_2
    add si, p256_word_len - 2
    mov [p256_scalar_word_ptr], si
    mov byte [p256_scalar_word_count], p256_word_count
.word_loop:
    mov si, [p256_scalar_word_ptr]
    mov ax, [si]
    mov [p256_scalar_word_value], ax
    mov word [p256_scalar_mask], 0x8000
.bit_loop:
    mov si, p256_s0
    mov di, p256_s0
    mov bx, p256_s0
    call p256_mul_mod
    mov ax, [p256_scalar_word_value]
    test ax, [p256_scalar_mask]
    jz .skip_mul
    mov si, p256_s0
    mov di, p256_s1
    mov bx, p256_s0
    call p256_mul_mod
.skip_mul:
    shr word [p256_scalar_mask], 1
    cmp word [p256_scalar_mask], 0
    jne .bit_loop
    sub word [p256_scalar_word_ptr], 2
    dec byte [p256_scalar_word_count]
    jnz .word_loop
    mov si, p256_s0
    mov di, [p256_inv_output_ptr]
    call p256_copy_words
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

p256_mul_product:
    mov word [p256_mul_acc0], 0
    mov word [p256_mul_acc1], 0
    mov word [p256_mul_acc2], 0
    mov byte [p256_i], 0
.outer_loop:
    cmp byte [p256_i], p256_product_word_count
    jae .done
    mov al, [p256_i]
    cmp al, p256_word_count
    jb .start_zero
    sub al, p256_word_count - 1
    jmp .start_ready
.start_zero:
    xor al, al
.start_ready:
    mov [p256_j], al
    mov ah, [p256_i]
    cmp ah, p256_word_count - 1
    jbe .end_ready
    mov ah, p256_word_count - 1
.end_ready:
    cmp ah, [p256_j]
    jb .store_word
    sub ah, [p256_j]
    inc ah
    xor ch, ch
    mov cl, ah
    mov si, [p256_left_ptr]
    mov bl, [p256_j]
    xor bh, bh
    add bx, bx
    add si, bx
    mov di, [p256_right_ptr]
    mov bl, [p256_i]
    sub bl, [p256_j]
    xor bh, bh
    add bx, bx
    add di, bx
.inner_loop:
    mov ax, [si]
    mul word [di]
    add [p256_mul_acc0], ax
    adc [p256_mul_acc1], dx
    adc word [p256_mul_acc2], 0
.next_inner:
    add si, 2
    sub di, 2
    loop .inner_loop
.store_word:
    mov bl, [p256_i]
    xor bh, bh
    add bx, bx
    mov ax, [p256_mul_acc0]
    mov [p256_product + bx], ax
    mov ax, [p256_mul_acc1]
    mov [p256_mul_acc0], ax
    mov ax, [p256_mul_acc2]
    mov [p256_mul_acc1], ax
    mov word [p256_mul_acc2], 0
    inc byte [p256_i]
    jmp .outer_loop
.done:
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
