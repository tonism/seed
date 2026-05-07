read_abs_sector:
    push ax
    push cx
    push dx
    div byte [disk_sectors_per_track]
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
    mov dl, [handoff_addr + handoff_boot_drive]
    mov ax, 0x0201
    int 0x13
    pop dx
    pop cx
    pop ax
    ret
