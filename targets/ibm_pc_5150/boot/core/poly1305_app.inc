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
    ; Exact 136-bit accumulator x 128-bit r, using 72 word products.
    ; Each row adds a_i*r_j + product[i+j] + carry.  With base B=65536,
    ; (B-1)^2 + 2*(B-1) = B^2-1, so DX:AX retains every carry.
    ; The final accumulator byte is zero-extended without reading past it.
    ; BP holds the row multiplier; the saved caller registers are the only
    ; stack state, and no new persistent scratch is needed.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push es
    mov ax, ds
    mov es, ax
    mov di, poly_product
    mov cx, poly1305_product_len
    xor al, al
    rep stosb

    mov byte [poly_i], 0
.outer:
    xor bx, bx
    mov bl, [poly_i]
    xor ax, ax
    mov al, [poly_acc + bx]
    cmp bl, poly1305_acc_len - 1
    je .multiplier_ready
    mov ah, [poly_acc + bx + 1]
.multiplier_ready:
    mov bp, ax
    add bx, poly_product
    mov di, poly_r
    xor si, si
    mov cx, poly1305_r_len / 2
.inner:
    mov ax, bp
    call poly1305_mul_word_fixed
    add ax, [bx]
    adc dx, 0
    add ax, si
    adc dx, 0
    mov [bx], ax
    mov si, dx
    add bx, 2
    add di, 2
    loop .inner
    ; Prior rows end one word earlier; this high word was still zero.
    mov [bx], si
    add byte [poly_i], 2
    cmp byte [poly_i], poly1305_acc_len
    jb .outer

    pop es
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Private replacement for the application's old variable-work reduction.
; P is the exact 136-by-128-bit product, hence P < 2^264. Write
; P = L + 2^130 H. First compute L+5H (<81*2^130), then fold its high
; bits twice. After the second small fold the result is <2^130, so one
; masked subtraction of p=2^130-5 gives the canonical representative.
; Every loop bound and address depends only on the public word position.

; AX * [DI] -> DX:AX with a fixed sixteen-round shift/add multiplication.
; A hardware MUL is deliberately not used as a timing premise on the 8088.
; Preserve the caller's row pointers and carry. No operand goes on the stack.
; Two rounds per iteration remove half the public loop branches.
poly1305_mul_word_fixed:
    push bx
    push cx
    xor dx, dx
    mov cx, 8
.bit:
    mov bx, ax
    and bx, 1
    neg bx
    and bx, [di]
    add dx, bx
    rcr dx, 1
    rcr ax, 1
    mov bx, ax
    and bx, 1
    neg bx
    and bx, [di]
    add dx, bx
    rcr dx, 1
    rcr ax, 1
    loop .bit
    pop cx
    pop bx
    ret

poly1305_reduce_product:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push es
    push ds
    pop es
    mov si, poly_product
    mov di, poly_value
    xor bp, bp                      ; carry of L+5H, at most five
    mov cx, 8
.word:
    mov ax, [si+16]
    shr ax, 1
    shr ax, 1
    mov dx, [si+18]
    and dx, 3
    ror dx, 1
    ror dx, 1
    or ax, dx                       ; one word of P >> 130
    mov bx, ax
    xor dx, dx
    shl ax, 1
    rcl dx, 1
    shl ax, 1
    rcl dx, 1
    add ax, bx
    adc dx, 0
    add ax, [si]
    adc dx, 0
    add ax, bp
    adc dx, 0
    mov [di], ax
    mov bp, dx
    add si, 2
    add di, 2
    loop .word
    ; Product bytes 33..35 are zero for this exact operand width. The last
    ; high word therefore has at most six bits and its times-five fits AX.
    mov ax, [poly_product+32]
    shr ax, 1
    shr ax, 1
    mov bx, ax
    shl ax, 1
    shl ax, 1
    add ax, bx
    xor bx, bx
    mov bl, [poly_product+16]
    and bl, 3
    add ax, bx
    add ax, bp
    mov [poly_value+16], ax
    mov cx, 2
.fold:
    mov ax, [poly_value+16]
    and word [poly_value+16], 3
    shr ax, 1
    shr ax, 1
    mov dx, ax
    shl ax, 1
    shl ax, 1
    add ax, dx
    add [poly_value], ax
%assign n 2
%rep 8
    adc word [poly_value+n], 0
%assign n n+2
%endrep
    loop .fold
    mov si, poly_value
    mov bx, poly1305_prime
    mov di, poly_acc
    mov cx, poly1305_acc_len
    clc
.subtract:
    lodsb
    sbb al, [bx]
    stosb
    inc bx
    loop .subtract
    sbb dl, dl                      ; ff iff V < p, so retain original V
    mov si, poly_value
    mov di, poly_acc
    mov cx, poly1305_acc_len
.select:
    lodsb
    xor al, [di]
    and al, dl
    xor [di], al
    inc di
    loop .select
    pop es
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
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
