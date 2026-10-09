tls_validate_post_handshake_nst:
    push bp
.message:
    cmp cx, 19                         ; header + smallest bounded NST body
    jb .bad
    cmp byte [si], 4                   ; NewSessionTicket
    jne .bad
    cmp byte [si + 1], 0               ; bounded 16-bit handshake length
    jne .bad
    mov dx, [si + 2]
    xchg dl, dh
    cmp dx, 15                         ; nonce and ticket are both nonempty
    jb .bad
    add dx, 4
    jc .bad
    cmp dx, cx
    ja .bad
    sub cx, dx
    push cx                            ; bytes after this complete message
    mov bp, si
    add bp, dx                         ; exact message end

    ; ticket_lifetime = 1..604800 seconds (0x0009:0x3a80).
    mov ax, [si + 4]
    xchg al, ah
    mov bx, [si + 6]
    xchg bl, bh
    mov dx, ax
    or dx, bx
    jz .bad_pop
    cmp ax, 9
    ja .bad_pop
    jb .lifetime_ready
    cmp bx, 0x3a80
    ja .bad_pop
.lifetime_ready:
    xor dx, dx
    mov dl, [si + 12]
    or dx, dx
    jz .bad_pop
    cmp dx, 32
    ja .bad_pop
    add si, 13
    mov ax, bp
    sub ax, si
    cmp ax, dx
    jb .bad_pop
    add si, dx

    mov ax, bp
    sub ax, si
    cmp ax, 2
    jb .bad_pop
    mov dx, [si]
    xchg dl, dh
    or dx, dx
    jz .bad_pop
    cmp dx, 192
    ja .bad_pop
    add si, 2
    mov ax, bp
    sub ax, si
    cmp ax, dx
    jb .bad_pop
    add si, dx

    mov ax, bp
    sub ax, si
    cmp ax, 2
    jb .bad_pop
    mov dx, [si]
    xchg dl, dh
    add si, 2
    mov ax, bp
    sub ax, si
    cmp dx, ax
    jne .bad_pop
    mov [0x31fc], si                ; beginning of this extension list
.extension:
    or dx, dx
    jz .message_done
    cmp dx, 4
    jb .bad_pop
    ; Every prior extension is already bounded. Reject repeated types,
    ; including unknown ones, before retaining resumption authority.
    push cx
    push dx
    mov di, [0x31fc]
.prior:
    cmp di, si
    je .unique
    mov ax, [di]
    cmp ax, [si]
    je .duplicate
    mov bx, [di+2]
    xchg bl, bh
    add di, 4
    add di, bx
    jmp short .prior
.duplicate:
    pop dx
    pop cx
    jmp .bad_pop
.unique:
    pop dx
    pop cx
    mov ax, [si]
    mov bx, [si + 2]
    xchg bl, bh
    add si, 4
    sub dx, 4
    cmp bx, dx
    ja .bad_pop
    cmp ax, 0x2a00                    ; early_data
    jne .extension_ready
    cmp bx, 4
    jne .bad_pop
.extension_ready:
    add si, bx
    sub dx, bx
    jmp short .extension
.message_done:
    mov si, bp
    pop cx
    or cx, cx
    jnz .message
    pop bp
    clc
    ret
.bad_pop:
    pop cx
.bad:
    pop bp
    stc
    ret
