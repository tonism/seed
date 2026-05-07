%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

user_cfg_phase:
    phase_call_res clear_seed_values
    mov di, user_cfg_name
    phase_call_res find_root_file
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
    phase_call_res read_cluster_to_buffer
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
    phase_call_res copy_line_value
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
    phase_call_res copy_line_value
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
    phase_call_res copy_line_value
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
    phase_call_res copy_line_value
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
    phase_call_res copy_line_value
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

%unmacro phase_call_res 1
