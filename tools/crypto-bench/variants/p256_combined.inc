
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

; ---------------------------------------------------------------------------
; Windowed (width-4 wNAF) scalar multiply -- testbench optimization.
;
; Plain double-and-add does ~141 point-adds for a random 256-bit scalar (one per
; set bit). A width-4 wNAF recodes the scalar into signed digits {0, +/-1, +/-3,
; +/-5, +/-7} with at most one nonzero digit in every 4 -- ~51 nonzero for a
; 255-bit scalar -- so the add count drops from ~141 to ~51 while the ~255
; doublings are unchanged. Each nonzero digit d picks the precomputed odd
; multiple (|d|)*P; negative d uses the point negation -kP = (x, p-y), which is
; free. Only 1P,3P,5P,7P are precomputed (1 double + 3 mixed-adds + 4 affine
; conversions), so the precompute is cheap relative to the ~90 adds saved.
;
; Buffers (defined in this .inc, see the data block at the end): the table
; persists through the whole loop, so it cannot live in the p256_s* scratch
; (the point ops clobber those). The working scalar / digit recoding happens
; entirely before the main loop, where the p256_s* scratch is still free.
; ---------------------------------------------------------------------------

p256_w_to_affine:
    ; Convert the current Jacobian p256_jac_* to affine; x -> [di], y -> [bx].
    ; Uses p256_s0..p256_s2 (free during precompute). Clobbers nothing in jac_*.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov [p256_w_outx_ptr], di
    mov [p256_w_outy_ptr], bx
    mov si, p256_jac_z
    mov di, p256_s0
    call p256_inv_mod                 ; s0 = z^-1
    mov si, p256_s0
    mov di, p256_s0
    mov bx, p256_s1
    call p256_mul_mod                 ; s1 = z^-2
    mov si, p256_s1
    mov di, p256_s0
    mov bx, p256_s2
    call p256_mul_mod                 ; s2 = z^-3
    mov si, p256_jac_x
    mov di, p256_s1
    mov bx, [p256_w_outx_ptr]
    call p256_mul_mod                 ; outx = X * z^-2
    mov si, p256_jac_y
    mov di, p256_s2
    mov bx, [p256_w_outy_ptr]
    call p256_mul_mod                 ; outy = Y * z^-3
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

p256_w_build_table:
    ; Precompute affine 1P,3P,5P,7P into p256_w_tableX/Y[0..3] from the affine
    ; point referenced by p256_affine_*_ptr (the original input P). Leaves the
    ; original affine pointers restored on exit.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    ; save the caller's affine pointers (the original base point P)
    mov ax, [p256_affine_x_ptr]
    mov [p256_w_basex_ptr], ax
    mov ax, [p256_affine_y_ptr]
    mov [p256_w_basey_ptr], ax
    ; table[0] = 1P (copy the input affine coords straight in)
    mov si, [p256_w_basex_ptr]
    mov di, p256_w_tableX
    call p256_copy_words
    mov si, [p256_w_basey_ptr]
    mov di, p256_w_tableY
    call p256_copy_words
    ; 2P (affine) = double(P); kept in p256_w_p2x / p256_w_p2y
    call p256_point_set_from_affine   ; jac = 1P
    call p256_point_double_jacobian   ; jac = 2P
    mov di, p256_w_p2x
    mov bx, p256_w_p2y
    call p256_w_to_affine             ; 2P -> p2x,p2y (affine)
    ; running Jacobian accumulator starts at 1P again
    call p256_point_set_from_affine   ; jac = 1P
    ; point the mixed-add at 2P for the repeated additions
    mov word [p256_affine_x_ptr], p256_w_p2x
    mov word [p256_affine_y_ptr], p256_w_p2y
    mov byte [p256_w_tmp], 1          ; table slot index to fill next (1 -> 3P)
.next_odd:
    call p256_point_add_mixed         ; jac += 2P  -> 3P, then 5P, then 7P
    ; affine-convert into table slot [p256_w_tmp]
    mov al, [p256_w_tmp]
    xor ah, ah
    mov cl, 5
    shl ax, cl                        ; slot * 32 (field-element stride)
    mov di, p256_w_tableX
    add di, ax
    mov bx, p256_w_tableY
    add bx, ax
    call p256_w_to_affine
    inc byte [p256_w_tmp]
    cmp byte [p256_w_tmp], 4
    jb .next_odd
    ; restore the original base-point affine pointers
    mov ax, [p256_w_basex_ptr]
    mov [p256_affine_x_ptr], ax
    mov ax, [p256_w_basey_ptr]
    mov [p256_affine_y_ptr], ax
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

p256_w_recode:
    ; Width-4 wNAF recode of the 32-byte working scalar at p256_w_scalar into the
    ; byte array p256_w_digits (LSB-first, signed bytes), digit count -> p256_w_count.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov word [p256_w_count], 0
.digit_loop:
    ; is the running scalar zero? (whole 32 bytes)
    mov si, p256_w_scalar
    call p256_is_zero
    jc .recode_done
    mov al, 0                         ; default digit 0 (even position)
    test byte [p256_w_scalar], 1
    jz .store_digit
    ; odd: d = (low 4 bits), mapped to signed -7..7
    mov al, [p256_w_scalar]
    and al, 0x0f                      ; 1,3,5,7,9,11,13,15
    cmp al, 8
    jb .have_digit
    sub al, 16                        ; 9->-7, 11->-5, 13->-3, 15->-1
.have_digit:
    ; subtract the signed digit from the running scalar: W -= d
    push ax
    call p256_w_sub_digit             ; AL = signed digit, updates p256_w_scalar
    pop ax
.store_digit:
    mov bx, [p256_w_count]
    mov si, p256_w_digits
    add si, bx
    mov [si], al
    inc word [p256_w_count]
    ; W >>= 1 (logical right shift of the 256-bit working scalar)
    mov di, p256_w_scalar
    call p256_rshift1_inplace
    jmp .digit_loop
.recode_done:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

p256_w_sub_digit:
    ; p256_w_scalar -= signed-byte digit in AL (|d| <= 7). Propagates the
    ; borrow/carry across the 256-bit working scalar.
    push ax
    push bx
    push cx
    push si
    mov si, p256_w_scalar
    mov cx, p256_word_count
    or al, al
    js .add_neg
    ; positive digit: subtract |d| with borrow
    xor ah, ah
    mov bx, ax                        ; bx = +d (16-bit)
    clc
.sub_word:
    mov ax, [si]
    sbb ax, bx
    mov [si], ax
    mov bx, 0                         ; only the first word carries the value
    lea si, [si + 2]
    loop .sub_word
    jmp .sub_done
.add_neg:
    ; negative digit: add |d| with carry
    neg al
    xor ah, ah
    mov bx, ax                        ; bx = |d|
    clc
.add_word:
    mov ax, [si]
    adc ax, bx
    mov [si], ax
    mov bx, 0
    lea si, [si + 2]
    loop .add_word
.sub_done:
    pop si
    pop cx
    pop bx
    pop ax
    ret

p256_scalar_mult_mixed:
    ; Multiplies affine p256_affine_* by the 256-bit scalar at SI (width-4 wNAF).
    ; The resulting Jacobian point is left in p256_jac_*.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov [p256_scalar_ptr], si
    ; working scalar copy for the wNAF recode
    mov di, p256_w_scalar
    call p256_copy_words
    call p256_w_recode                ; fill p256_w_digits / p256_w_count
    call p256_w_build_table           ; fill p256_w_tableX/Y[0..3]
    call p256_point_set_infinity
    ; main loop: digits MSB-first (index count-1 .. 0)
    mov ax, [p256_w_count]
    or ax, ax
    jz .done                          ; scalar was zero
.bit_loop:
    dec word [p256_w_count]
    call p256_point_double_jacobian
    mov bx, [p256_w_count]
    mov si, p256_w_digits
    add si, bx
    mov al, [si]                      ; signed wNAF digit at this position
    or al, al
    jz .next_bit
    ; idx = (|d| - 1) / 2  -> table slot 0..3 for 1P,3P,5P,7P
    js .neg_digit
    ; positive digit: affine y = table[idx] y
    mov ah, al
    dec ah
    shr ah, 1                         ; (d-1)/2
    call p256_w_set_affine_pos
    jmp .do_add
.neg_digit:
    neg al                            ; |d|
    mov ah, al
    dec ah
    shr ah, 1
    call p256_w_set_affine_neg
.do_add:
    call p256_point_add_mixed
.next_bit:
    cmp word [p256_w_count], 0
    jne .bit_loop
.done:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

p256_w_set_affine_pos:
    ; AH = table slot (0..3). Point the mixed-add at table[slot] (x,y), y positive.
    push ax
    push bx
    push cx
    push si
    push di
    mov al, ah
    xor ah, ah
    mov cl, 5
    shl ax, cl                        ; slot * 32
    mov bx, p256_w_tableX
    add bx, ax
    mov [p256_affine_x_ptr], bx
    mov bx, p256_w_tableY
    add bx, ax
    mov [p256_affine_y_ptr], bx
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

p256_w_set_affine_neg:
    ; AH = table slot (0..3). Point the mixed-add at table[slot] x, and at a freshly
    ; computed negated y (p - y) for the negative wNAF digit.
    push ax
    push bx
    push cx
    push si
    push di
    mov al, ah
    xor ah, ah
    mov cl, 5
    shl ax, cl                        ; slot * 32
    mov bx, p256_w_tableX
    add bx, ax
    mov [p256_affine_x_ptr], bx
    ; neg_y = prime - table[slot].y  (0 < y < p, so no final borrow)
    mov si, p256_prime
    mov di, p256_w_tableY
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

; ---------------------------------------------------------------------------
; Windowed-scalar-mult data block (testbench-only; appended by this variant).
; These buffers persist across the whole scalar multiply, so they must NOT
; overlap the p256_s* scratch the point ops clobber. The harness includes this
; .inc after the (halted) caller and before its own P256_DATA block, so these
; labels assemble into addressable, never-executed RAM.
; ---------------------------------------------------------------------------
align 2
p256_w_tableX: times (4 * p256_word_count) dw 0   ; affine x of 1P,3P,5P,7P
p256_w_tableY: times (4 * p256_word_count) dw 0   ; affine y of 1P,3P,5P,7P
p256_w_p2x:    times p256_word_count dw 0         ; affine 2P (precompute step)
p256_w_p2y:    times p256_word_count dw 0
p256_w_negy:   times p256_word_count dw 0         ; p - y for negative digits
p256_w_scalar: times p256_word_count dw 0         ; working scalar for the recode
p256_w_digits: times 264 db 0                     ; signed wNAF digits (LSB-first)
p256_w_count:      dw 0
p256_w_tmp:        db 0
p256_w_basex_ptr:  dw 0
p256_w_basey_ptr:  dw 0
p256_w_outx_ptr:   dw 0
p256_w_outy_ptr:   dw 0


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


align 2
sol_acc: times 18 dw 0
