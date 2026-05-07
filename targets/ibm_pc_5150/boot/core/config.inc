find_root_file:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
.next_sector:
    cmp word [fs_root_left], 0
    je .not_found
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [fs_lba]
    call read_abs_sector
    jc .not_found
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.next_entry:
    mov al, [si]
    or al, al
    jz .end_marker
    cmp al, 0xe5
    je .advance
    test byte [si + 11], 0x18
    jnz .advance
    push si
    push cx
    push di
    mov cx, 11
.compare:
    mov al, [si]
    cmp al, [di]
    jne .mismatch
    inc si
    inc di
    loop .compare
    pop di
    pop cx
    pop si
    mov ax, [si + 26]
    mov [fs_file_cluster], ax
    mov ax, [si + 28]
    mov [fs_file_size_low], ax
    mov ax, [si + 30]
    mov [fs_file_size_high], ax
    clc
    ret
.mismatch:
    pop di
    pop cx
    pop si
    jmp .advance
.advance:
    add si, fat_dir_entry_size
    loop .next_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .next_sector
.end_marker:
.not_found:
    stc
    ret

ensure_seed_values:
    cmp byte [seed_agent_id], 'l'
    jne .key_only
    test byte [seed_config_flags], seed_flag_endpoint
    jz .missing
.key_only:
    test byte [seed_config_flags], seed_flag_key
    jz .missing
    clc
    ret
.missing:
    stc
.done:
    ret
