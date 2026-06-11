
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
    ; Register-resident Comba: the running column accumulators acc0/acc1 live in
    ; BP/BX across the whole multiply (carried column-to-column without touching
    ; memory); only the top word acc2 stays in RAM, taking a single carry per
    ; inner step. The dominant per-step memory traffic (was add[acc0]/adc[acc1]/
    ; adc[acc2] = 3 RMW) drops to one register add, one register adc, one mem adc.
    ; Two triangular phases remove the per-column max/min jstart/jend branches:
    ;   low  cols i=0..15 : j=0..i      -> left starts at base, right at +2*i
    ;   high cols i=16..31: j=i-15..15  -> right at top word, left at +2*(i-15)
    ; acc0/acc1 ride in BP/BX across columns; acc2 (carry-only) is a byte in RAM.
    push bp
    xor bp, bp                      ; acc0
    xor bx, bx                      ; acc1
    mov word [p256_mul_acc2], 0     ; acc2 (top word, memory; high byte stays 0)
    mov byte [p256_i], 0
.lowA:
    ; count = i+1 -> CX
    mov al, [p256_i]
    mov ah, 0
    mov cx, ax
    inc cx
    ; si = left ; di = right + 2*i   (ah=0, so add di,ax is the full 2*i)
    add ax, ax
    mov si, [p256_left_ptr]
    mov di, [p256_right_ptr]
    add di, ax
    jmp .inner_loop
.highB:
    ; count = (2*16 - 1) - i = 31 - i  (col 31 is empty -> count 0, skip inner)
    mov al, p256_product_word_count - 1
    sub al, [p256_i]
    jz .store_word                  ; empty top column: just propagate the carry
    mov ah, 0
    mov cx, ax
    ; si = left + 2*(i-15) ; di = right + 30 (top word)
    mov al, [p256_i]
    sub al, p256_word_count - 1     ; i-15
    mov ah, 0
    add ax, ax
    mov si, [p256_left_ptr]
    add si, ax
    mov di, [p256_right_ptr]
    add di, (p256_word_count - 1) * 2
.inner_loop:
    lodsw                           ; ax = left[..]; si += 2 (folds the add si,2)
    mul word [di]
    add bp, ax
    adc bx, dx
    adc byte [p256_mul_acc2], 0     ; acc2 top word: carry-only, <=16 -> byte RMW
    sub di, 2
    loop .inner_loop
.store_word:
    ; product[i] = acc0(bp); shift acc1->acc0, acc2->acc1, acc2=0.
    ; Store index recomputed into SI (free after the inner loop); BP/BX intact.
    mov al, [p256_i]
    mov ah, 0
    add ax, ax
    mov si, ax
    mov [p256_product + si], bp
    mov bp, bx                      ; new acc0 = old acc1
    mov bx, [p256_mul_acc2]         ; new acc1 = old acc2 (high byte 0)
    mov word [p256_mul_acc2], 0     ; new acc2 = 0
    inc byte [p256_i]
    mov al, [p256_i]
    cmp al, p256_word_count
    jb .lowA
    cmp al, p256_product_word_count
    jb .highB
    pop bp
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
