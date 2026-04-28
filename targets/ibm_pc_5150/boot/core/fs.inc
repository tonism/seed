save_user_cfg:
    call find_user_cfg
    jnc .have_root
    cmp byte [fs_free_root_found], 0
    je .done
    call find_free_cluster
    jc .done
    mov ax, [fs_free_cluster]
    mov [seed_cluster], ax
    mov ax, [fs_free_root_lba]
    mov [seed_root_lba], ax
    mov ax, [fs_free_root_offset]
    mov [seed_root_offset], ax
.have_root:
    cmp word [seed_cluster], fat_first_data_cluster
    jb .done
    call write_user_data
    jc .done
    call write_user_fat
    jc .done
    call write_user_root
.done:
    clc
    ret

find_free_cluster:
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    call read_abs_sector
    jc .failed
    mov word [fs_scan_cluster], fat_first_data_cluster
.next:
    mov ax, [fs_scan_cluster]
    cmp ax, fat_max_cluster
    jae .failed
    call get_fat_entry
    and ax, 0x0fff
    jz .found
    inc word [fs_scan_cluster]
    jmp .next
.found:
    mov ax, [fs_scan_cluster]
    mov [fs_free_cluster], ax
    clc
    ret
.failed:
    stc
    ret

get_fat_entry:
    push bx
    push dx
    mov dx, ax
    mov bx, ax
    shr bx, 1
    add bx, dx
    mov al, [fs_sector_buffer + bx]
    mov ah, [fs_sector_buffer + bx + 1]
    test dl, 1
    jz .even
    shr ax, 1
    shr ax, 1
    shr ax, 1
    shr ax, 1
.even:
    and ax, 0x0fff
    pop dx
    pop bx
    ret

write_user_data:
    call build_user_cfg_buffer
    mov ax, [seed_cluster]
    call write_cluster_from_buffer
    ret

write_user_fat:
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    call read_abs_sector
    jc .failed
    mov ax, [seed_cluster]
    call set_fat_entry_eoc
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    call write_abs_sector
    jc .failed
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba + 1
    call write_abs_sector
    ret
.failed:
    stc
    ret

set_fat_entry_eoc:
    push ax
    push bx
    push dx
    mov dx, ax
    mov bx, ax
    shr bx, 1
    add bx, dx
    test dl, 1
    jnz .odd
    mov byte [fs_sector_buffer + bx], 0xff
    mov al, [fs_sector_buffer + bx + 1]
    and al, 0xf0
    or al, 0x0f
    mov [fs_sector_buffer + bx + 1], al
    jmp .done
.odd:
    mov al, [fs_sector_buffer + bx]
    and al, 0x0f
    or al, 0xf0
    mov [fs_sector_buffer + bx], al
    mov byte [fs_sector_buffer + bx + 1], 0xff
.done:
    pop dx
    pop bx
    pop ax
    ret

write_user_root:
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [seed_root_lba]
    call read_abs_sector
    jc .failed
    call write_user_root_entry
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [seed_root_lba]
    call write_abs_sector
    ret
.failed:
    stc
    ret

write_user_root_entry:
    push ds
    pop es
    mov bx, [seed_root_offset]
    mov di, fs_sector_buffer
    add di, bx
    xor ax, ax
    mov cx, fat_dir_entry_size / 2
    rep stosw
    mov di, fs_sector_buffer
    add di, bx
    mov si, user_cfg_name
    mov cx, 11
    rep movsb
    mov bx, [seed_root_offset]
    mov byte [fs_sector_buffer + bx + 11], 0x20
    mov ax, [seed_cluster]
    mov [fs_sector_buffer + bx + 26], ax
    mov ax, [user_cfg_size_current]
    mov [fs_sector_buffer + bx + 28], ax
    mov word [fs_sector_buffer + bx + 30], 0
    ret

build_user_cfg_buffer:
    call clear_fs_sector_buffer
    push ds
    pop es
    mov di, fs_sector_buffer
    mov si, agent_prefix_text
    call append_z_to_buffer
    mov si, seed_agent_id
    call append_z_to_buffer
    call append_crlf_to_buffer
    test byte [seed_config_flags], seed_flag_model
    jz .reasoning
    mov si, model_prefix_text
    call append_z_to_buffer
    mov si, seed_model
    call append_z_to_buffer
    call append_crlf_to_buffer
.reasoning:
    test byte [seed_config_flags], seed_flag_reasoning
    jz .key
    mov si, reasoning_prefix_text
    call append_z_to_buffer
    mov si, seed_reasoning
    call append_z_to_buffer
    call append_crlf_to_buffer
.key:
    test byte [seed_config_flags], seed_flag_key
    jz .endpoint
    mov si, key_prefix_text
    call append_z_to_buffer
    mov si, seed_key
    call append_z_to_buffer
    call append_crlf_to_buffer
.endpoint:
    test byte [seed_config_flags], seed_flag_endpoint
    jz .finish
    mov si, endpoint_prefix_text
    call append_z_to_buffer
    mov si, seed_endpoint
    call append_z_to_buffer
    call append_crlf_to_buffer
.finish:
    mov ax, di
    sub ax, fs_sector_buffer
    mov [user_cfg_size_current], ax
    ret

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

clear_fs_sector_buffer:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, fs_sector_buffer
    mov cx, 256
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
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

write_cluster_from_buffer:
    cmp ax, fat_first_data_cluster
    jb .failed
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    call write_abs_sector
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

write_abs_sector:
    push ax
    push cx
    push dx
    div byte [disk_sectors_per_track]
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
    mov dl, [handoff_addr + handoff_boot_drive]
    mov ax, 0x0301
    int 0x13
    pop dx
    pop cx
    pop ax
    ret
