%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

agents_cfg_phase:
    mov byte [agent_count], 0
    call agents_cfg_phase_find
    jc .fallback
    call agents_cfg_phase_parse
    jc .fallback
    cmp byte [agent_count], 0
    je .fallback
    clc
    ret
.fallback:
    call agents_cfg_phase_load_builtin
    clc
    ret

agents_cfg_phase_load_builtin:
    push ds
    pop es
    mov si, builtin_agent_ids
    mov di, agent_ids
    mov bx, 3
.next_builtin:
    mov cx, agent_id_len
.copy:
    lodsb
    stosb
    loop .copy
    add di, 16 - agent_id_len
    dec bx
    jnz .next_builtin
    mov byte [agent_count], 3
    ret

agents_cfg_phase_find:
    mov di, agents_cfg_name
    phase_call_res find_root_file
    jc .not_found
    mov ax, [fs_file_cluster]
    mov [agents_cluster], ax
    mov ax, [fs_file_size_low]
    mov [agents_size_low], ax
    mov ax, [fs_file_size_high]
    mov [agents_size_high], ax
    clc
    ret
.not_found:
    stc
    ret

agents_cfg_phase_parse:
    cmp word [agents_size_high], 0
    jne .failed
    mov ax, [agents_cluster]
    cmp ax, fat_first_data_cluster
    jb .failed
    mov [fs_current_cluster], ax
    mov ax, [agents_size_low]
    mov [fs_bytes_left], ax
    or ax, ax
    jz .failed
.next_cluster:
    cmp byte [agent_count], agent_slot_count
    jae .done
    cmp word [fs_bytes_left], 0
    je .done
    mov ax, [fs_current_cluster]
    phase_call_res read_cluster_to_buffer
    jc .failed
    mov ax, [fs_bytes_left]
    cmp ax, 512
    jbe .size_ready
    mov ax, 512
.size_ready:
    mov [fs_bytes_this], ax
    call agents_cfg_phase_parse_sector
    mov ax, [fs_bytes_left]
    sub ax, [fs_bytes_this]
    mov [fs_bytes_left], ax
    inc word [fs_current_cluster]
    jmp .next_cluster
.done:
    clc
    ret
.failed:
    stc
    ret

agents_cfg_phase_parse_sector:
    mov si, fs_sector_buffer
    mov cx, [fs_bytes_this]
    mov byte [fs_line_start], 1
.next_byte:
    cmp cx, 0
    je .done
    cmp byte [fs_line_start], 1
    jne .consume
    cmp byte [agent_count], agent_slot_count
    jae .done
    cmp cx, 6
    jb .consume
    cmp byte [si], 'a'
    jne .consume
    cmp byte [si + 1], 'g'
    jne .consume
    cmp byte [si + 2], 'e'
    jne .consume
    cmp byte [si + 3], 'n'
    jne .consume
    cmp byte [si + 4], 't'
    jne .consume
    cmp byte [si + 5], ' '
    jne .consume
    call agents_cfg_phase_copy_id
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
.done:
    ret

agents_cfg_phase_copy_id:
    push si
    push cx
    mov al, [agent_count]
    xor ah, ah
    mov di, ax
    shl di, 1
    shl di, 1
    shl di, 1
    shl di, 1
    add di, agent_ids
    add si, 6
    mov bp, cx
    sub bp, 6
    mov dx, agent_id_len - 1
.copy:
    cmp bp, 0
    je .terminate
    cmp dx, 0
    je .terminate
    lodsb
    dec bp
    cmp al, 13
    je .terminate
    cmp al, 10
    je .terminate
    cmp al, ' '
    je .terminate
    cmp al, 9
    je .terminate
    stosb
    dec dx
    jmp .copy
.terminate:
    mov byte [di], 0
    inc byte [agent_count]
    pop cx
    pop si
    ret

%unmacro phase_call_res 1
