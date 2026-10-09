h2 equ 0x062e
tx equ 0x3912
quota equ h2+62

upload_send:
    cld
    cmp byte [h2+61], 1
    jne .failed
    cmp dl, 1
    ja .failed
    cmp ax, 427
    ja .failed
    cmp ax, [quota]
    ja .failed
    or ax, ax
    jnz .check_window
    or dl, dl
    jz .failed
    jmp short .build
.check_window:
    mov bx, [h2+30]
    or bx, bx
    js .failed
    jnz .connection
    cmp ax, [h2+28]
    ja .failed
.connection:
    mov bx, [h2+34]
    or bx, bx
    js .failed
    jnz .spend
    cmp ax, [h2+32]
    ja .failed
.spend:
    sub [h2+28], ax
    sbb word [h2+30], 0
    sub [h2+32], ax
    sbb word [h2+34], 0
.build:
    mov word [quota], 0
    push dx
    push ax
    mov di, tx+5
    xor al, al
    stosb
    pop ax
    push ax
    xchg al, ah
    stosw
    xor al, al
    stosb
    mov al, dl
    stosb
    mov si, h2+20
    movsw
    movsw
    pop ax
    add ax, 9
    call .send
    pop dx
    jc .failed
    or dl, dl
    jz .done
    ; Source ownership ends before the first inbound DATA credit is granted.
    mov byte [h2+61], 0
    call h2_rx_clear_record
    mov di, tx+5
    mov ax, 0
    stosw
    mov ax, 0x0804                   ; length=4, type=WINDOW_UPDATE
    stosw
    xor al, al
    stosb
    mov si, h2+20
    movsw
    movsw
    xor ax, ax
    stosw
    mov ax, 2                        ; network-order 00000200
    stosw
    mov ax, 13
    call .send
    jc .failed
    mov word [0x2e10], 512
.done:
    clc
    ret
.failed:
    stc
    ret
.send:
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], tx+5
    call tls_prepare_3c501_receive
    call tls_send_application_data_current_seq
    pushf
    call tls_h2_clear_crypto_prefix
    popf
    ret
