; Authenticated bounded EncryptedExtensions for the 8088 compatibility route.
; SI -> first handshake byte; success CX = complete EE length (15 or 19).
; Require h2, optionally accept one empty server_name acknowledgement in
; either order. No duplicate, unsolicited, or malformed extension is accepted.
h2_validate_ee:
    cmp word [si], 8
    jne .bad
    mov cx, 15
    cmp word [si + 2], 0x0b00
    je .length
    mov cl, 19
    cmp word [si + 2], 0x0f00
    jne .bad
.length:
    mov ax, cx
    sub ax, 6
    xchg al, ah
    cmp [si + 4], ax
    jne .bad
    add si, 6
    cmp cl, 19
    jne .alpn
    cmp word [si], 0
    jne .sni_after
    cmp word [si + 2], 0
    jne .bad
    add si, 4
    jmp short .alpn
.sni_after:
    cmp word [si + 9], 0
    jne .bad
    cmp word [si + 11], 0
    jne .bad
.alpn:
    push cx
    mov di, h2_alpn_extension
    mov cx, 9
    repe cmpsb
    pop cx
    jne .bad
    clc
    ret
.bad:
    stc
    ret
h2_alpn_extension db 0,0x10,0,5,0,3,2,'h2'
