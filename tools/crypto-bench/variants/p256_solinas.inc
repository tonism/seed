
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
    ; Direct NIST P-256 (Solinas) fast reduction of the 512-bit p256_product.
    ; Replaces the generic table-driven reduction. Folds the 8 high 32-bit words
    ; per FIPS 186-4 D.2: r = s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9,
    ; computed column-by-column into an 18-word signed accumulator (sol_acc),
    ; then reduced into [0, p) by a few conditional add/sub of the prime.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    ; acc(BP:BX:CX) = signed 48-bit running accumulator; result -> sol_acc[18 words]
    xor cx, cx
    mov bx, cx
    mov bp, cx
    ; --- column 0 ---
    add cx, [p256_product + 0]
    adc bx, [p256_product + 2]
    adc bp, 0
    add cx, [p256_product + 32]
    adc bx, [p256_product + 34]
    adc bp, 0
    add cx, [p256_product + 36]
    adc bx, [p256_product + 38]
    adc bp, 0
    sub cx, [p256_product + 44]
    sbb bx, [p256_product + 46]
    sbb bp, 0
    sub cx, [p256_product + 48]
    sbb bx, [p256_product + 50]
    sbb bp, 0
    sub cx, [p256_product + 52]
    sbb bx, [p256_product + 54]
    sbb bp, 0
    sub cx, [p256_product + 56]
    sbb bx, [p256_product + 58]
    sbb bp, 0
    mov [sol_acc + 0], cx
    mov [sol_acc + 2], bx
    mov ax, bp
    cwd
    mov cx, ax
    mov bx, dx
    mov bp, dx
    ; --- column 1 ---
    add cx, [p256_product + 4]
    adc bx, [p256_product + 6]
    adc bp, 0
    add cx, [p256_product + 36]
    adc bx, [p256_product + 38]
    adc bp, 0
    add cx, [p256_product + 40]
    adc bx, [p256_product + 42]
    adc bp, 0
    sub cx, [p256_product + 48]
    sbb bx, [p256_product + 50]
    sbb bp, 0
    sub cx, [p256_product + 52]
    sbb bx, [p256_product + 54]
    sbb bp, 0
    sub cx, [p256_product + 56]
    sbb bx, [p256_product + 58]
    sbb bp, 0
    sub cx, [p256_product + 60]
    sbb bx, [p256_product + 62]
    sbb bp, 0
    mov [sol_acc + 4], cx
    mov [sol_acc + 6], bx
    mov ax, bp
    cwd
    mov cx, ax
    mov bx, dx
    mov bp, dx
    ; --- column 2 ---
    add cx, [p256_product + 8]
    adc bx, [p256_product + 10]
    adc bp, 0
    add cx, [p256_product + 40]
    adc bx, [p256_product + 42]
    adc bp, 0
    add cx, [p256_product + 44]
    adc bx, [p256_product + 46]
    adc bp, 0
    sub cx, [p256_product + 52]
    sbb bx, [p256_product + 54]
    sbb bp, 0
    sub cx, [p256_product + 56]
    sbb bx, [p256_product + 58]
    sbb bp, 0
    sub cx, [p256_product + 60]
    sbb bx, [p256_product + 62]
    sbb bp, 0
    mov [sol_acc + 8], cx
    mov [sol_acc + 10], bx
    mov ax, bp
    cwd
    mov cx, ax
    mov bx, dx
    mov bp, dx
    ; --- column 3 ---
    add cx, [p256_product + 12]
    adc bx, [p256_product + 14]
    adc bp, 0
    sub cx, [p256_product + 32]
    sbb bx, [p256_product + 34]
    sbb bp, 0
    sub cx, [p256_product + 36]
    sbb bx, [p256_product + 38]
    sbb bp, 0
    mov ax, [p256_product + 44]
    mov dx, [p256_product + 46]
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    mov ax, [p256_product + 48]
    mov dx, [p256_product + 50]
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, [p256_product + 52]
    adc bx, [p256_product + 54]
    adc bp, 0
    sub cx, [p256_product + 60]
    sbb bx, [p256_product + 62]
    sbb bp, 0
    mov [sol_acc + 12], cx
    mov [sol_acc + 14], bx
    mov ax, bp
    cwd
    mov cx, ax
    mov bx, dx
    mov bp, dx
    ; --- column 4 ---
    add cx, [p256_product + 16]
    adc bx, [p256_product + 18]
    adc bp, 0
    sub cx, [p256_product + 36]
    sbb bx, [p256_product + 38]
    sbb bp, 0
    sub cx, [p256_product + 40]
    sbb bx, [p256_product + 42]
    sbb bp, 0
    mov ax, [p256_product + 48]
    mov dx, [p256_product + 50]
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    mov ax, [p256_product + 52]
    mov dx, [p256_product + 54]
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, [p256_product + 56]
    adc bx, [p256_product + 58]
    adc bp, 0
    mov [sol_acc + 16], cx
    mov [sol_acc + 18], bx
    mov ax, bp
    cwd
    mov cx, ax
    mov bx, dx
    mov bp, dx
    ; --- column 5 ---
    add cx, [p256_product + 20]
    adc bx, [p256_product + 22]
    adc bp, 0
    sub cx, [p256_product + 40]
    sbb bx, [p256_product + 42]
    sbb bp, 0
    sub cx, [p256_product + 44]
    sbb bx, [p256_product + 46]
    sbb bp, 0
    mov ax, [p256_product + 52]
    mov dx, [p256_product + 54]
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    mov ax, [p256_product + 56]
    mov dx, [p256_product + 58]
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, [p256_product + 60]
    adc bx, [p256_product + 62]
    adc bp, 0
    mov [sol_acc + 20], cx
    mov [sol_acc + 22], bx
    mov ax, bp
    cwd
    mov cx, ax
    mov bx, dx
    mov bp, dx
    ; --- column 6 ---
    add cx, [p256_product + 24]
    adc bx, [p256_product + 26]
    adc bp, 0
    sub cx, [p256_product + 32]
    sbb bx, [p256_product + 34]
    sbb bp, 0
    sub cx, [p256_product + 36]
    sbb bx, [p256_product + 38]
    sbb bp, 0
    add cx, [p256_product + 52]
    adc bx, [p256_product + 54]
    adc bp, 0
    mov ax, [p256_product + 56]
    mov dx, [p256_product + 58]
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    mov ax, [p256_product + 60]
    mov dx, [p256_product + 62]
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    mov [sol_acc + 24], cx
    mov [sol_acc + 26], bx
    mov ax, bp
    cwd
    mov cx, ax
    mov bx, dx
    mov bp, dx
    ; --- column 7 ---
    add cx, [p256_product + 28]
    adc bx, [p256_product + 30]
    adc bp, 0
    add cx, [p256_product + 32]
    adc bx, [p256_product + 34]
    adc bp, 0
    sub cx, [p256_product + 40]
    sbb bx, [p256_product + 42]
    sbb bp, 0
    sub cx, [p256_product + 44]
    sbb bx, [p256_product + 46]
    sbb bp, 0
    sub cx, [p256_product + 48]
    sbb bx, [p256_product + 50]
    sbb bp, 0
    sub cx, [p256_product + 52]
    sbb bx, [p256_product + 54]
    sbb bp, 0
    mov ax, [p256_product + 60]
    mov dx, [p256_product + 62]
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    add cx, ax
    adc bx, dx
    adc bp, 0
    mov [sol_acc + 28], cx
    mov [sol_acc + 30], bx
    mov ax, bp
    cwd
    mov cx, ax
    mov bx, dx
    mov bp, dx
    ; residual (value >> 256) -> dword 8 (words 16,17)
    mov [sol_acc + 32], cx
    mov [sol_acc + 34], bx
.make_nonneg:
    ; while value < 0 (sign bit of word 17 set): value += p   (<= ~4 iterations)
    test word [sol_acc + 34], 0x8000
    jz .reduce_ge
    mov si, p256_prime
    mov di, sol_acc
    mov cx, p256_word_count
    clc
.add_p_word:
    lodsw
    adc [di], ax
    lea di, [di + 2]
    loop .add_p_word
    adc word [sol_acc + 32], 0
    adc word [sol_acc + 34], 0
    jmp .make_nonneg
.reduce_ge:
    ; value now >= 0. while value >= p: value -= p   (<= ~5 iterations)
    cmp word [sol_acc + 34], 0
    jne .sub_p
    cmp word [sol_acc + 32], 0
    jne .sub_p
    mov si, sol_acc
    mov di, p256_prime
    call p256_cmp_words
    jc .finished
.sub_p:
    mov si, p256_prime
    mov di, sol_acc
    mov cx, p256_word_count
    clc
.sub_p_word:
    lodsw
    sbb [di], ax
    lea di, [di + 2]
    loop .sub_p_word
    sbb word [sol_acc + 32], 0
    sbb word [sol_acc + 34], 0
    jmp .reduce_ge
.finished:
    ; copy the reduced low 256 bits (16 words) to p256_product
    mov si, sol_acc
    mov di, p256_product
    mov cx, p256_word_count
    push ds
    pop es
    rep movsw
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

align 2
sol_acc: times 18 dw 0
