%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

user_cfg_phase:
    call user_cfg_phase_clear_seed_values
    call user_cfg_phase_find_seed_dir
    jc .failed
    mov ax, [fs_file_cluster]
    mov [fs_current_cluster], ax
    mov di, low_scratch_start + (user_cfg_phase_name - PHASE_BASE)
    call user_cfg_phase_find_dir_file
    jc .failed
    mov ax, [fs_file_cluster]
    mov [seed_cluster], ax
    mov ax, [fs_file_size_low]
    mov [seed_size_low], ax
    mov ax, [fs_file_size_high]
    mov [seed_size_high], ax
    cmp word [seed_size_high], 0
    jne .failed
    cmp word [seed_size_low], 6
    jb .failed
    mov ax, [seed_cluster]
    call user_cfg_phase_read_cluster_to_buffer
    jc .failed
    call .parse
    jc .failed
    clc
    ret
.failed:
    stc
    ret

.parse:
    mov si, fs_sector_buffer
    mov cx, [seed_size_low]
    cmp cx, 512
    jbe .size_ready
    mov cx, 512
.size_ready:
    mov byte [fs_line_start], 1
.next_byte:
    cmp cx, 0
    je .validate
    cmp byte [fs_line_start], 1
    jne .consume
    call .parse_line
.consume:
    lodsb
    dec cx
    cmp al, 13
    je .line_start
    cmp al, 10
    je .line_start
    mov byte [fs_line_start], 0
    jmp .next_byte
.line_start:
    mov byte [fs_line_start], 1
    jmp .next_byte
.validate:
    test byte [seed_config_flags], seed_flag_agent
    jz .parse_failed
    call .match_agent
    jc .parse_failed
    cmp byte [seed_agent_id], 'l'
    jne .key_ready
    test byte [seed_config_flags], seed_flag_endpoint
    jz .parse_failed
.key_ready:
    test byte [seed_config_flags], seed_flag_key
    jz .parse_failed
    clc
    ret
.parse_failed:
    stc
    ret

.parse_line:
    cmp cx, 6
    jb .check_key
    cmp byte [si], 'a'
    jne .check_model
    cmp byte [si + 1], 'g'
    jne .check_model
    cmp byte [si + 2], 'e'
    jne .check_model
    cmp byte [si + 3], 'n'
    jne .check_model
    cmp byte [si + 4], 't'
    jne .check_model
    cmp byte [si + 5], ' '
    jne .check_model
    push si
    push cx
    add si, 6
    sub cx, 6
    mov di, seed_agent_id
    mov dl, agent_id_len
    call user_cfg_phase_copy_line_value
    pop cx
    pop si
    cmp byte [seed_agent_id], 0
    je .done
    or byte [seed_config_flags], seed_flag_agent
    ret
.check_model:
    cmp cx, 6
    jb .check_key
    cmp byte [si], 'm'
    jne .check_reasoning
    cmp byte [si + 1], 'o'
    jne .check_reasoning
    cmp byte [si + 2], 'd'
    jne .check_reasoning
    cmp byte [si + 3], 'e'
    jne .check_reasoning
    cmp byte [si + 4], 'l'
    jne .check_reasoning
    cmp byte [si + 5], ' '
    jne .check_reasoning
    push si
    push cx
    add si, 6
    sub cx, 6
    mov di, seed_model
    mov dl, seed_model_len
    call user_cfg_phase_copy_line_value
    pop cx
    pop si
    cmp byte [seed_model], 0
    je .done
    or byte [seed_config_flags], seed_flag_model
    ret
.check_reasoning:
    cmp cx, 10
    jb .check_key
    cmp byte [si], 'r'
    jne .check_key
    cmp byte [si + 1], 'e'
    jne .check_key
    cmp byte [si + 2], 'a'
    jne .check_key
    cmp byte [si + 3], 's'
    jne .check_key
    cmp byte [si + 4], 'o'
    jne .check_key
    cmp byte [si + 5], 'n'
    jne .check_key
    cmp byte [si + 6], 'i'
    jne .check_key
    cmp byte [si + 7], 'n'
    jne .check_key
    cmp byte [si + 8], 'g'
    jne .check_key
    cmp byte [si + 9], ' '
    jne .check_key
    push si
    push cx
    add si, 10
    sub cx, 10
    mov di, seed_reasoning
    mov dl, seed_reasoning_len
    call user_cfg_phase_copy_line_value
    pop cx
    pop si
    cmp byte [seed_reasoning], 0
    je .done
    or byte [seed_config_flags], seed_flag_reasoning
    ret
.check_key:
    cmp cx, 4
    jb .check_endpoint
    cmp byte [si], 'k'
    jne .check_endpoint
    cmp byte [si + 1], 'e'
    jne .check_endpoint
    cmp byte [si + 2], 'y'
    jne .check_endpoint
    cmp byte [si + 3], ' '
    jne .check_endpoint
    push si
    push cx
    add si, 4
    sub cx, 4
    mov di, seed_key
    mov dl, seed_key_len
    call user_cfg_phase_copy_line_value
    pop cx
    pop si
    cmp byte [seed_key], 0
    je .done
    or byte [seed_config_flags], seed_flag_key
    ret
.check_endpoint:
    cmp cx, 9
    jb .done
    cmp byte [si], 'e'
    jne .done
    cmp byte [si + 1], 'n'
    jne .done
    cmp byte [si + 2], 'd'
    jne .done
    cmp byte [si + 3], 'p'
    jne .done
    cmp byte [si + 4], 'o'
    jne .done
    cmp byte [si + 5], 'i'
    jne .done
    cmp byte [si + 6], 'n'
    jne .done
    cmp byte [si + 7], 't'
    jne .done
    cmp byte [si + 8], ' '
    jne .done
    push si
    push cx
    add si, 9
    sub cx, 9
    mov di, seed_endpoint
    mov dl, seed_endpoint_len
    call user_cfg_phase_copy_line_value
    pop cx
    pop si
    cmp byte [seed_endpoint], 0
    je .done
    or byte [seed_config_flags], seed_flag_endpoint
.done:
    ret

.match_agent:
    mov byte [agent_scan_index], 0
.next_agent:
    mov al, [agent_scan_index]
    cmp al, [agent_count]
    jae .match_failed
    call .agent_ptr_from_al
    mov di, seed_agent_id
    call .strings_equal
    jnc .found
    inc byte [agent_scan_index]
    jmp .next_agent
.found:
    mov al, [agent_scan_index]
    mov [menu_index], al
    clc
    ret
.match_failed:
    stc
    ret

.agent_ptr_from_al:
    xor ah, ah
    mov si, ax
    shl si, 1
    shl si, 1
    shl si, 1
    shl si, 1
    add si, agent_ids
    ret

.strings_equal:
    mov al, [si]
    cmp al, [di]
    jne .not_equal
    or al, al
    jz .equal
    inc si
    inc di
    jmp .strings_equal
.equal:
    clc
    ret
.not_equal:
    stc
    ret

user_cfg_phase_name db 'USER    CFG'
user_cfg_phase_seed_name db 'SEED       '

user_cfg_phase_find_seed_dir:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
.next_sector:
    cmp word [fs_root_left], 0
    je .not_found
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [fs_lba]
    phase_call_res read_abs_sector
    jc .not_found
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.next_entry:
    mov al, [si]
    or al, al
    jz .end_marker
    cmp al, 0xe5
    je .advance
    test byte [si + 11], 0x10
    jz .advance
    push si
    push cx
    mov di, low_scratch_start + (user_cfg_phase_seed_name - PHASE_BASE)
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
    mov [fs_file_cluster], ax
    mov ax, [si + 28]
    mov [fs_file_size_low], ax
    mov ax, [si + 30]
    mov [fs_file_size_high], ax
    clc
    ret
.mismatch:
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

user_cfg_phase_find_dir_file:
    mov ax, [fs_current_cluster]
    cmp ax, fat_first_data_cluster
    jb .not_found
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    phase_call_res read_abs_sector
    jc .not_found
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.dir_entry:
    mov al, [si]
    or al, al
    jz .not_found
    cmp al, 0xe5
    je .dir_advance
    test byte [si + 11], 0x18
    jnz .dir_advance
    push si
    push cx
    push di
    mov cx, 11
.dir_compare:
    mov al, [si]
    cmp al, [di]
    jne .dir_mismatch
    inc si
    inc di
    loop .dir_compare
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
.dir_mismatch:
    pop di
    pop cx
    pop si
.dir_advance:
    add si, fat_dir_entry_size
    loop .dir_entry
.not_found:
    stc
    ret

user_cfg_phase_clear_seed_values:
    push es
    push ds
    pop es
    xor ax, ax
    mov di, seed_agent_id
    mov cx, seed_value_total_len / 2
    rep stosw
    mov byte [seed_config_flags], 0
    mov byte [user_cfg_dirty], 0
    pop es
    ret

user_cfg_phase_read_cluster_to_buffer:
    cmp ax, fat_first_data_cluster
    jb .failed
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    phase_call_res read_abs_sector
    ret
.failed:
    stc
    ret

user_cfg_phase_copy_line_value:
    push ax
    push cx
    push dx
    push si
    push di
    dec dl
.copy:
    cmp cx, 0
    je .terminate
    cmp dl, 0
    je .terminate
    mov al, [si]
    cmp al, 13
    je .terminate
    cmp al, 10
    je .terminate
    or al, al
    jz .terminate
    mov [di], al
    inc si
    inc di
    dec cx
    dec dl
    jmp .copy
.terminate:
    mov byte [di], 0
    pop di
    pop si
    pop dx
    pop cx
    pop ax
    ret

%unmacro phase_call_res 1
