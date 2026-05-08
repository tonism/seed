%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

save_user_cfg_phase:
    call .find_existing_user_cfg
    jc .done
    call .build_user_cfg_buffer
    mov ax, [seed_cluster]
    call .write_cluster_from_buffer
    jc .done
    call .write_user_root_size
.done:
    clc
    ret

.find_existing_user_cfg:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
.next_sector:
    cmp word [fs_root_left], 0
    je .find_failed
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [fs_lba]
    phase_call_res read_abs_sector
    jc .find_failed
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.next_entry:
    mov al, [si]
    or al, al
    jz .find_failed
    cmp al, 0xe5
    je .advance
    test byte [si + 11], 0x18
    jnz .advance
    push si
    push cx
    mov di, low_scratch_start + (save_user_cfg_name - PHASE_BASE)
    mov cx, 11
.compare:
    mov al, [si]
    cmp al, [di]
    jne .mismatch
    inc si
    inc di
    loop .compare
    pop cx
    pop si
    mov ax, [si + 26]
    mov [seed_cluster], ax
    mov ax, [fs_lba]
    mov [seed_root_lba], ax
    mov ax, si
    sub ax, fs_sector_buffer
    mov [seed_root_offset], ax
    clc
    ret
.mismatch:
    pop cx
    pop si
.advance:
    add si, fat_dir_entry_size
    loop .next_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .next_sector
.find_failed:
    stc
    ret

.build_user_cfg_buffer:
    call .clear_fs_sector_buffer
    push ds
    pop es
    mov di, fs_sector_buffer
    mov si, low_scratch_start + (agent_prefix_text - PHASE_BASE)
    call save_user_cfg_phase_append_z_to_buffer
    mov si, seed_agent_id
    call save_user_cfg_phase_append_z_to_buffer
    call save_user_cfg_phase_append_crlf_to_buffer
    test byte [seed_config_flags], seed_flag_model
    jz .reasoning
    mov si, low_scratch_start + (model_prefix_text - PHASE_BASE)
    call save_user_cfg_phase_append_z_to_buffer
    mov si, seed_model
    call save_user_cfg_phase_append_z_to_buffer
    call save_user_cfg_phase_append_crlf_to_buffer
.reasoning:
    test byte [seed_config_flags], seed_flag_reasoning
    jz .key
    mov si, low_scratch_start + (reasoning_prefix_text - PHASE_BASE)
    call save_user_cfg_phase_append_z_to_buffer
    mov si, seed_reasoning
    call save_user_cfg_phase_append_z_to_buffer
    call save_user_cfg_phase_append_crlf_to_buffer
.key:
    test byte [seed_config_flags], seed_flag_key
    jz .endpoint
    mov si, low_scratch_start + (key_prefix_text - PHASE_BASE)
    call save_user_cfg_phase_append_z_to_buffer
    mov si, seed_key
    call save_user_cfg_phase_append_z_to_buffer
    call save_user_cfg_phase_append_crlf_to_buffer
.endpoint:
    test byte [seed_config_flags], seed_flag_endpoint
    jz .finish
    mov si, low_scratch_start + (endpoint_prefix_text - PHASE_BASE)
    call save_user_cfg_phase_append_z_to_buffer
    mov si, seed_endpoint
    call save_user_cfg_phase_append_z_to_buffer
    call save_user_cfg_phase_append_crlf_to_buffer
.finish:
    mov ax, di
    sub ax, fs_sector_buffer
    mov [user_cfg_size_current], ax
    ret

.write_cluster_from_buffer:
    cmp ax, fat_first_data_cluster
    jb .write_cluster_failed
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    call .write_abs_sector
    ret
.write_cluster_failed:
    stc
    ret

.write_user_root_size:
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [seed_root_lba]
    phase_call_res read_abs_sector
    jc .write_root_failed
    mov bx, [seed_root_offset]
    mov ax, [user_cfg_size_current]
    mov [fs_sector_buffer + bx + 28], ax
    mov word [fs_sector_buffer + bx + 30], 0
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [seed_root_lba]
    call .write_abs_sector
    ret
.write_root_failed:
    stc
    ret

.clear_fs_sector_buffer:
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

.write_abs_sector:
    push ax
    push cx
    mov cl, 8
    div cl
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
    mov dl, [handoff_addr + handoff_boot_drive]
    mov ax, 0x0301
    int 0x13
    pop cx
    pop ax
    ret

save_user_cfg_name db 'USER    CFG'
agent_prefix_text db 'agent ', 0
model_prefix_text db 'model ', 0
reasoning_prefix_text db 'reasoning ', 0
key_prefix_text db 'key ', 0
endpoint_prefix_text db 'endpoint ', 0

save_user_cfg_phase_append_z_to_buffer:
    lodsb
    or al, al
    jz .done
    stosb
    jmp save_user_cfg_phase_append_z_to_buffer
.done:
    ret

save_user_cfg_phase_append_crlf_to_buffer:
    mov al, 13
    stosb
    mov al, 10
    stosb
    ret

%unmacro phase_call_res 1
