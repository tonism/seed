append_z_to_buffer:
    lodsb
    or al, al
    jz .done
    stosb
    jmp append_z_to_buffer
.done:
    ret

append_crlf_to_buffer:
    mov al, 13
    stosb
    mov al, 10
    stosb
    ret

read_cluster_to_buffer:
    cmp ax, fat_first_data_cluster
    jb .failed
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    call read_abs_sector
    ret
.failed:
    stc
    ret

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
