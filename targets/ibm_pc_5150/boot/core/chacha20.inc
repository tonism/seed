%macro CHACHA_ADD 2
    mov ax, [chacha_work + %1]
    add ax, [chacha_work + %2]
    mov [chacha_work + %1], ax
    mov ax, [chacha_work + %1 + 2]
    adc ax, [chacha_work + %2 + 2]
    mov [chacha_work + %1 + 2], ax
%endmacro

%macro CHACHA_XOR 2
    mov ax, [chacha_work + %1]
    xor ax, [chacha_work + %2]
    mov [chacha_work + %1], ax
    mov ax, [chacha_work + %1 + 2]
    xor ax, [chacha_work + %2 + 2]
    mov [chacha_work + %1 + 2], ax
%endmacro

%macro CHACHA_ROTL 2
    mov ax, [chacha_work + %1]
    mov dx, [chacha_work + %1 + 2]
    mov cl, %2
    call chacha_rotl32_axdx
    mov [chacha_work + %1], ax
    mov [chacha_work + %1 + 2], dx
%endmacro

%macro CHACHA_QR 4
    CHACHA_ADD %1, %2
    CHACHA_XOR %4, %1
    CHACHA_ROTL %4, 16
    CHACHA_ADD %3, %4
    CHACHA_XOR %2, %3
    CHACHA_ROTL %2, 12
    CHACHA_ADD %1, %2
    CHACHA_XOR %4, %1
    CHACHA_ROTL %4, 8
    CHACHA_ADD %3, %4
    CHACHA_XOR %2, %3
    CHACHA_ROTL %2, 7
%endmacro

chacha20_block:
    ; chacha_key_ptr, chacha_nonce_ptr, and chacha_counter_* select the block.
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

    mov si, chacha_constants
    mov di, chacha_state
    mov cx, 8
    rep movsw
    mov si, [chacha_key_ptr]
    mov cx, tls_chacha_key_len / 2
    rep movsw
    mov ax, [chacha_counter_low]
    stosw
    mov ax, [chacha_counter_high]
    stosw
    mov si, [chacha_nonce_ptr]
    mov cx, tls_chacha_iv_len / 2
    rep movsw

    mov si, chacha_state
    mov di, chacha_work
    mov cx, chacha_block_len / 2
    rep movsw

    mov bp, 10
.round:
    call chacha_double_round
    dec bp
    jnz .round

    mov si, chacha_work
    mov di, chacha_state
    mov bx, chacha_block
    mov cx, chacha_word_count
.add_state:
    mov ax, [si]
    add ax, [di]
    mov [bx], ax
    mov ax, [si + 2]
    adc ax, [di + 2]
    mov [bx + 2], ax
    add si, 4
    add di, 4
    add bx, 4
    loop .add_state

    pop es
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    clc
    ret

chacha_double_round:
    CHACHA_QR 0, 16, 32, 48
    CHACHA_QR 4, 20, 36, 52
    CHACHA_QR 8, 24, 40, 56
    CHACHA_QR 12, 28, 44, 60
    CHACHA_QR 0, 20, 40, 60
    CHACHA_QR 4, 24, 44, 48
    CHACHA_QR 8, 28, 32, 52
    CHACHA_QR 12, 16, 36, 56
    ret

chacha_rotl32_axdx:
    xor ch, ch
    jcxz .done
.rotate:
    shl ax, 1
    rcl dx, 1
    adc ax, 0
    loop .rotate
.done:
    ret
