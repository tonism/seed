poly1305_mac_finished:
    call poly1305_clear_acc

    call poly1305_clear_block
    push ds
    pop es
    mov si, tls_aead_aad
    mov di, poly_block
    mov cx, tls_aead_aad_len
    rep movsb
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block

    push ds
    pop es
    mov si, tls_finished_cipher
    mov di, poly_block
    mov cx, tls_finished_cipher_len
    rep movsb
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block

    call poly1305_clear_block
    mov byte [poly_block], tls_aead_aad_len
    mov byte [poly_block + 8], tls_finished_cipher_len
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block

    call poly1305_emit_tag
    clc
    ret

poly1305_load_key:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, chacha_block
    mov di, poly_r
    mov cx, poly1305_r_len
    rep movsb
    mov di, poly_s
    mov cx, poly1305_s_len
    rep movsb
    and byte [poly_r + 3], 0x0f
    and byte [poly_r + 7], 0x0f
    and byte [poly_r + 11], 0x0f
    and byte [poly_r + 15], 0x0f
    and byte [poly_r + 4], 0xfc
    and byte [poly_r + 8], 0xfc
    and byte [poly_r + 12], 0xfc
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

poly1305_clear_acc:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    mov di, poly_acc
    mov cx, poly1305_acc_len
    xor al, al
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

poly1305_clear_block:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    mov di, poly_block
    mov cx, 16
    xor al, al
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

poly1305_process_block:
    call poly1305_add_block
    call poly1305_mul_acc_r
    jmp poly1305_reduce_product

poly1305_add_block:
    push ax
    push cx
    push si
    push di
    mov si, [poly_block_ptr]
    mov di, poly_acc
    mov cx, 16
    clc
.next:
    lodsb
    adc [di], al
    inc di
    loop .next
    mov al, 1
    adc [di], al
    pop di
    pop si
    pop cx
    pop ax
    ret

poly1305_mul_acc_r:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    push ds
    pop es
    mov di, poly_product
    mov cx, poly1305_product_len
    xor al, al
    rep stosb

    mov byte [poly_i], 0
.outer:
    cmp byte [poly_i], poly1305_acc_len
    jae .done
    mov byte [poly_j], 0
.inner:
    cmp byte [poly_j], poly1305_r_len
    jae .next_outer
    mov bl, [poly_i]
    xor bh, bh
    mov si, poly_acc
    add si, bx
    mov al, [si]
    mov bl, [poly_j]
    xor bh, bh
    mov si, poly_r
    add si, bx
    mul byte [si]
    mov bl, [poly_i]
    add bl, [poly_j]
    xor bh, bh
    add bx, poly_product
    add [bx], ax
    inc bx
    inc bx
.propagate:
    adc byte [bx], 0
    jnc .mul_done
    inc bx
    jmp .propagate
.mul_done:
    inc byte [poly_j]
    jmp .inner
.next_outer:
    inc byte [poly_i]
    jmp .outer
.done:
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

poly1305_reduce_product:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    push ds
    pop es
    mov si, poly_product
    mov di, poly_value
    mov cx, poly1305_value_len
    xor al, al
    rep stosb
    mov si, poly_product
    mov di, poly_value
    mov cx, poly1305_acc_len
    rep movsb
    and byte [poly_value + 16], 0x03
    call poly1305_fold_product_high
    call poly1305_fold_value_high
    call poly1305_fold_value_high
    call poly1305_fold_value_high
    call poly1305_subtract_prime_until_below
    mov si, poly_value
    mov di, poly_acc
    mov cx, poly1305_acc_len
    rep movsb
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

poly1305_fold_product_high:
    mov byte [poly_i], 0
.next:
    cmp byte [poly_i], 19
    jae .last
    mov bl, [poly_i]
    xor bh, bh
    mov si, poly_product + 16
    add si, bx
    mov al, [si]
    shr al, 1
    shr al, 1
    mov dl, [si + 1]
    mov cl, 6
    shl dl, cl
    or al, dl
    mov di, poly_value
    add di, bx
    call poly1305_add_al_times5
    inc byte [poly_i]
    jmp .next
.last:
    mov al, [poly_product + 35]
    shr al, 1
    shr al, 1
    mov di, poly_value + 19
    jmp poly1305_add_al_times5

poly1305_fold_value_high:
    mov byte [poly_i], 0
.next:
    cmp byte [poly_i], 7
    jae .last
    mov bl, [poly_i]
    xor bh, bh
    mov si, poly_value + 16
    add si, bx
    mov al, [si]
    shr al, 1
    shr al, 1
    mov dl, [si + 1]
    mov cl, 6
    shl dl, cl
    or al, dl
    mov di, poly_value
    add di, bx
    call poly1305_add_al_times5
    inc byte [poly_i]
    jmp .next
.last:
    mov al, [poly_value + 23]
    shr al, 1
    shr al, 1
    mov di, poly_value + 7
    call poly1305_add_al_times5
    and byte [poly_value + 16], 0x03
    mov di, poly_value + 17
    mov cx, poly1305_value_len - 17
    xor al, al
    rep stosb
    ret

poly1305_add_al_times5:
    or al, al
    jz .done
    push ax
    push bx
    push dx
    xor ah, ah
    mov dx, ax
    shl ax, 1
    shl ax, 1
    add ax, dx
    add [di], ax
    mov bx, di
    inc bx
    inc bx
.propagate:
    adc byte [bx], 0
    jnc .pop_done
    inc bx
    jmp .propagate
.pop_done:
    pop dx
    pop bx
    pop ax
.done:
    ret

poly1305_subtract_prime_until_below:
    call poly1305_value_cmp_prime
    jc .done
    call poly1305_value_sub_prime
    jmp poly1305_subtract_prime_until_below
.done:
    ret

poly1305_value_cmp_prime:
    ; Returns CF=1 when poly_value is below p.
    push ax
    push cx
    push si
    push di
    mov si, poly_value + poly1305_acc_len - 1
    mov di, poly1305_prime + poly1305_acc_len - 1
    mov cx, poly1305_acc_len
.next:
    mov al, [si]
    cmp al, [di]
    jb .less
    ja .greater_or_equal
    dec si
    dec di
    loop .next
.greater_or_equal:
    clc
    jmp short .cmp_restore
.less:
    stc
.cmp_restore:
    pop di
    pop si
    pop cx
    pop ax
    ret

poly1305_value_sub_prime:
    push ax
    push cx
    push si
    push di
    mov si, poly1305_prime
    mov di, poly_value
    mov cx, poly1305_acc_len
    clc
.next:
    lodsb
    sbb [di], al
    inc di
    loop .next
    pop di
    pop si
    pop cx
    pop ax
    ret

poly1305_emit_tag:
    push ax
    push cx
    push si
    push di
    push bx
    push es
    push ds
    pop es
    mov bx, poly_acc
    mov si, poly_s
    mov di, tls_finished_tag
    mov cx, 16
    clc
.next:
    mov al, [bx]
    adc al, [si]
    stosb
    inc bx
    inc si
    loop .next
    pop es
    pop bx
    pop di
    pop si
    pop cx
    pop ax
    ret
