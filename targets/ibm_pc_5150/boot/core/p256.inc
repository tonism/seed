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
    call p256_clear_product
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

p256_clear_product:
    push ax
    push cx
    push di
    push es
    xor ax, ax
    mov di, p256_product
    mov cx, p256_product_word_count
    push ds
    pop es
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret

p256_mul_product:
    mov byte [p256_i], 0
.outer_loop:
    cmp byte [p256_i], p256_word_count
    jae .done
    mov si, [p256_left_ptr]
    mov bl, [p256_i]
    xor bh, bh
    add bx, bx
    add si, bx
    mov ax, [si]
    mov [p256_mul_left_word], ax
    mov byte [p256_j], 0
.inner_loop:
    cmp byte [p256_j], p256_word_count
    jae .next_outer
    mov si, [p256_right_ptr]
    mov bl, [p256_j]
    xor bh, bh
    add bx, bx
    add si, bx
    mov ax, [p256_mul_left_word]
    mul word [si]
    mov bl, [p256_i]
    add bl, [p256_j]
    xor bh, bh
    add bx, bx
    add bx, p256_product
    call p256_add_mul_word
    inc byte [p256_j]
    jmp .inner_loop
.next_outer:
    inc byte [p256_i]
    jmp .outer_loop
.done:
    ret

p256_add_mul_word:
    ; Adds DX:AX to p256_product at word offset BX.
    mov word [p256_mul_carry], 0
    add [bx], ax
    adc dx, 0
    adc word [p256_mul_carry], 0
    add [bx + 2], dx
    adc word [p256_mul_carry], 0
    add bx, 4
    mov ax, [p256_mul_carry]
    or ax, ax
    jz .done
    add [bx], ax
    jnc .done
    add bx, 2
.propagate:
    inc word [bx]
    jnz .done
    add bx, 2
    jmp .propagate
.done:
    ret

p256_reduce_product:
    mov byte [p256_word_shift], 16
    mov byte [p256_bit_shift], 0
    call p256_reduce_current_shift
    mov byte [p256_word_shift], 15
.word_loop:
    mov byte [p256_bit_shift], 15
.bit_loop:
    call p256_reduce_current_shift
    cmp byte [p256_bit_shift], 0
    je .next_word
    dec byte [p256_bit_shift]
    jmp .bit_loop
.next_word:
    cmp byte [p256_word_shift], 0
    je .done
    dec byte [p256_word_shift]
    jmp .word_loop
.done:
    ret

p256_reduce_current_shift:
    call p256_compare_product_shifted_prime
    jc .done
    call p256_sub_product_shifted_prime
.done:
    ret

p256_compare_product_shifted_prime:
    mov byte [p256_compare_index], p256_product_word_count - 1
.next_word:
    mov al, [p256_compare_index]
    call p256_get_shifted_prime_word
    mov bl, [p256_compare_index]
    xor bh, bh
    add bx, bx
    mov ax, [p256_product + bx]
    cmp ax, dx
    jb .less
    ja .greater_or_equal
    cmp byte [p256_compare_index], 0
    je .greater_or_equal
    dec byte [p256_compare_index]
    jmp .next_word
.greater_or_equal:
    clc
    ret
.less:
    stc
    ret

p256_get_shifted_prime_word:
    ; AL is product word index. Returns the shifted-prime word in DX.
    push ax
    push bx
    push si
    xor dx, dx
    cmp al, [p256_word_shift]
    jb .done
    sub al, [p256_word_shift]
    cmp al, p256_prime_shift_word_count
    jae .done
    mov bl, [p256_bit_shift]
    xor bh, bh
    add bx, bx
    mov si, [p256_prime_shift_ptrs + bx]
    mov bl, al
    xor bh, bh
    add bx, bx
    add si, bx
    mov dx, [si]
.done:
    pop si
    pop bx
    pop ax
    ret

p256_sub_product_shifted_prime:
    mov bl, [p256_bit_shift]
    xor bh, bh
    add bx, bx
    mov si, [p256_prime_shift_ptrs + bx]
    mov bl, [p256_word_shift]
    xor bh, bh
    add bx, bx
    mov di, p256_product
    add di, bx
    mov cx, p256_prime_shift_word_count
    cmp byte [p256_word_shift], 16
    jne .subtract
    dec cx
.subtract:
    clc
.next_word:
    mov ax, [di]
    sbb ax, [si]
    mov [di], ax
    lea si, [si + 2]
    lea di, [di + 2]
    loop .next_word
    ret
