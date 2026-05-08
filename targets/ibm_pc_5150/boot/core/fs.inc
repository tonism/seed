read_abs_sector:
    push ax
    push cx
    mov cl, 8
    div cl
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
    mov dl, [handoff_addr + handoff_boot_drive]
    mov ax, 0x0201
    int 0x13
    pop cx
    pop ax
    ret
