load_net_probe_cfg:
    mov di, net_cfg_name
    call find_root_file
    jc .failed
    cmp word [fs_file_size_high], 0
    jne .failed
    cmp word [fs_file_size_low], 7
    jb .failed
    mov ax, [fs_file_cluster]
    call read_cluster_to_buffer
    jc .failed
    mov si, fs_sector_buffer
    mov cx, [fs_file_size_low]
    cmp cx, 512
    jbe .size_ready
    mov cx, 512
.size_ready:
    mov byte [fs_line_start], 1
.next_byte:
    cmp cx, 0
    je .failed
    cmp byte [fs_line_start], 1
    jne .consume
    cmp cx, 6
    jb .consume
    cmp byte [si], 'p'
    jne .consume
    cmp byte [si + 1], 'r'
    jne .consume
    cmp byte [si + 2], 'o'
    jne .consume
    cmp byte [si + 3], 'b'
    jne .consume
    cmp byte [si + 4], 'e'
    jne .consume
    cmp byte [si + 5], ' '
    jne .consume
    add si, 6
    sub cx, 6
    mov di, seed_endpoint
    mov dl, seed_endpoint_len
    call copy_line_value
    cmp byte [seed_endpoint], 0
    je .failed
    mov si, seed_endpoint
    call set_dns_target_from_text
    ret
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
.failed:
    stc
    ret

set_agent_endpoint_target:
    mov word [tcp_dest_port_word], tcp_port_https_word
    call selected_agent_needs_endpoint
    jc .known_provider
    mov si, seed_endpoint
    jmp set_dns_target_from_text
.known_provider:
    cmp byte [seed_agent_id], 'o'
    je .open_provider
    cmp byte [seed_agent_id], 'a'
    je .anthropic
    cmp byte [seed_agent_id], 'g'
    je .google
    stc
    ret
.open_provider:
    cmp byte [seed_agent_id + 4], 'r'
    je .openrouter
    mov si, host_openai_text
    jmp set_dns_target_from_text
.openrouter:
    mov si, host_openrouter_text
    jmp set_dns_target_from_text
.anthropic:
    mov si, host_anthropic_text
    jmp set_dns_target_from_text
.google:
    mov si, host_google_text
    jmp set_dns_target_from_text

set_dns_target_from_text:
    call skip_endpoint_prefix
    cmp byte [si], 0
    je .failed
    mov di, dns_qname
    mov byte [dns_qname_len], 0
.next_label:
    mov [dns_label_ptr], di
    mov byte [di], 0
    inc di
    inc byte [dns_qname_len]
    mov byte [dns_label_len], 0
.next_char:
    lodsb
    or al, al
    jz .finish
    cmp al, 13
    je .finish
    cmp al, 10
    je .finish
    cmp al, ' '
    je .finish
    cmp al, '/'
    je .finish
    cmp al, ':'
    je .finish
    cmp al, '.'
    je .dot
    cmp al, 'A'
    jb .store
    cmp al, 'Z'
    ja .store
    add al, 32
.store:
    cmp byte [dns_label_len], 63
    jae .failed
    cmp byte [dns_qname_len], dns_qname_max_len - 1
    jae .failed
    mov [di], al
    inc di
    inc byte [dns_label_len]
    inc byte [dns_qname_len]
    jmp .next_char
.dot:
    cmp byte [dns_label_len], 0
    je .failed
    call finish_dns_label
    jmp .next_label
.finish:
    cmp byte [dns_label_len], 0
    je .failed
    call finish_dns_label
    cmp byte [dns_qname_len], dns_qname_max_len
    jae .failed
    mov byte [di], 0
    inc byte [dns_qname_len]
    call update_dns_tx_len
    clc
    ret
.failed:
    stc
    ret

skip_endpoint_prefix:
    mov bx, si
    cmp byte [si], 'h'
    jne .done
    cmp byte [si + 1], 't'
    jne .done
    cmp byte [si + 2], 't'
    jne .done
    cmp byte [si + 3], 'p'
    jne .done
    add si, 4
    cmp byte [si], 's'
    jne .colon
    inc si
.colon:
    cmp byte [si], ':'
    jne .restore
    inc si
    cmp byte [si], '/'
    jne .restore
    inc si
    cmp byte [si], '/'
    jne .restore
    inc si
    ret
.restore:
    mov si, bx
.done:
    ret

finish_dns_label:
    mov bx, [dns_label_ptr]
    mov al, [dns_label_len]
    mov [bx], al
    ret

update_dns_tx_len:
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len
    mov [dns_tx_len], ax
    ret

load_agents_cfg:
    mov byte [agent_count], 0
    call find_agents_cfg
    jc .fallback
    call parse_agents_cfg
    jc .fallback
    cmp byte [agent_count], 0
    je .fallback
    clc
    ret
.fallback:
    call load_builtin_agents
    clc
    ret

load_builtin_agents:
    push ds
    pop es
    mov si, builtin_agent_ids
    mov di, agent_ids
    mov cx, (3 * agent_id_len) / 2
    rep movsw
    mov byte [agent_count], 3
    ret

find_agents_cfg:
    mov di, agents_cfg_name
    call find_root_file
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

find_seed_cfg:
    mov di, seed_cfg_name
    call find_root_file
    jc .not_found
    mov ax, [fs_file_cluster]
    mov [seed_cluster], ax
    mov ax, [fs_file_size_low]
    mov [seed_size_low], ax
    mov ax, [fs_file_size_high]
    mov [seed_size_high], ax
    mov ax, [fs_file_root_lba]
    mov [seed_root_lba], ax
    mov ax, [fs_file_root_offset]
    mov [seed_root_offset], ax
    clc
    ret
.not_found:
    stc
    ret

find_root_file:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
    mov byte [fs_free_root_found], 0
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
    je .free_entry
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
    mov ax, [fs_lba]
    mov [fs_file_root_lba], ax
    mov ax, si
    sub ax, fs_sector_buffer
    mov [fs_file_root_offset], ax
    clc
    ret
.mismatch:
    pop di
    pop cx
    pop si
    jmp .advance
.free_entry:
    call record_free_root_entry
.advance:
    add si, fat_dir_entry_size
    loop .next_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .next_sector
.end_marker:
    call record_free_root_entry
.not_found:
    stc
    ret

record_free_root_entry:
    cmp byte [fs_free_root_found], 0
    jne .done
    mov byte [fs_free_root_found], 1
    mov ax, [fs_lba]
    mov [fs_free_root_lba], ax
    mov ax, si
    sub ax, fs_sector_buffer
    mov [fs_free_root_offset], ax
.done:
    ret

parse_agents_cfg:
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
    call read_cluster_to_buffer
    jc .failed
    mov ax, [fs_bytes_left]
    cmp ax, 512
    jbe .size_ready
    mov ax, 512
.size_ready:
    mov [fs_bytes_this], ax
    call parse_agent_sector
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

parse_agent_sector:
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
    call copy_agent_id_from_line
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

copy_agent_id_from_line:
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

load_seed_cfg:
    call clear_seed_values
    call find_seed_cfg
    jc .failed
    cmp word [seed_size_high], 0
    jne .failed
    cmp word [seed_size_low], 6
    jb .failed
    mov ax, [seed_cluster]
    call read_cluster_to_buffer
    jc .failed
    call parse_seed_cfg
    jc .failed
    clc
    ret
.failed:
    stc
    ret

parse_seed_cfg:
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
    call parse_seed_line
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
    jz .failed
    call match_seed_agent
    jc .failed
    clc
    ret
.failed:
    stc
    ret

parse_seed_line:
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
    call copy_line_value
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
    call copy_line_value
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
    call copy_line_value
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
    call copy_line_value
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
    call copy_line_value
    pop cx
    pop si
    cmp byte [seed_endpoint], 0
    je .done
    or byte [seed_config_flags], seed_flag_endpoint
.done:
    ret

copy_line_value:
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

match_seed_agent:
    mov byte [agent_scan_index], 0
.next_agent:
    mov al, [agent_scan_index]
    cmp al, [agent_count]
    jae .failed
    call agent_scan_ptr
    mov di, seed_agent_id
    call strings_equal
    jnc .found
    inc byte [agent_scan_index]
    jmp .next_agent
.found:
    mov al, [agent_scan_index]
    mov [menu_index], al
    clc
    ret
.failed:
    stc
    ret

strings_equal:
    mov al, [si]
    cmp al, [di]
    jne .failed
    or al, al
    jz .equal
    inc si
    inc di
    jmp strings_equal
.equal:
    clc
    ret
.failed:
    stc
    ret

clear_seed_values:
    push es
    push ds
    pop es
    xor ax, ax
    mov di, seed_agent_id
    mov cx, seed_value_total_len / 2
    rep stosw
    mov byte [seed_config_flags], 0
    mov byte [seed_cfg_dirty], 0
    pop es
    ret

ensure_seed_values:
    call selected_agent_needs_endpoint
    jc .key_only
    test byte [seed_config_flags], seed_flag_endpoint
    jz .ask
.key_only:
    test byte [seed_config_flags], seed_flag_key
    jnz .done
    jmp .ask
.ask:
    call ask_agent_values
.done:
    ret

selected_agent_needs_endpoint:
    cmp byte [seed_agent_id], 'l'
    jne .no
    clc
    ret
.no:
    stc
    ret

ask_agent_values:
    mov byte [menu_value_a], 0
    mov byte [blink_state], 0
.render:
    call clear_agent_field_area
    call render_agent_values_form
    call set_active_form_input
    call show_cursor
.input:
    call input_wait_key
    cmp al, 0x0d
    je .accept
    cmp al, 0x08
    je .backspace
    cmp al, 0x1b
    je .cancel
    cmp ah, 0x48
    je .previous
    cmp ah, 0x50
    je .next
    cmp al, 0x20
    jb .input
    cmp al, 0x7e
    ja .input
    mov dl, [input_max]
    dec dl
    cmp [input_len], dl
    jae .input
    call input_store_char
    jmp .input
.backspace:
    call input_backspace
    jmp .input
.previous:
.next:
    call selected_agent_needs_endpoint
    jc .input
    xor byte [menu_value_a], 1
    call draw_agent_form_fields
    call set_active_form_input
    call show_cursor
    jmp .input
.accept:
    call validate_agent_values
    jc .render
    call hide_cursor
    call clear_question_area
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    call show_load_marker
    clc
    ret
.cancel:
    call hide_cursor
    call slide_selected_agent_right
    stc
    ret

validate_agent_values:
    call selected_agent_needs_endpoint
    jc .check_key
    cmp byte [seed_endpoint], 0
    jne .check_key
    mov byte [menu_value_a], 0
    stc
    ret
.check_key:
    cmp byte [seed_key], 0
    jne .valid
    call selected_agent_needs_endpoint
    jc .key_focus
    mov byte [menu_value_a], 1
    jmp .invalid
.key_focus:
    mov byte [menu_value_a], 0
.invalid:
    stc
    ret
.valid:
    or byte [seed_config_flags], seed_flag_key
    call selected_agent_needs_endpoint
    jc .done
    or byte [seed_config_flags], seed_flag_endpoint
.done:
    mov byte [seed_cfg_dirty], 1
    clc
    ret

set_active_form_input:
    call selected_agent_needs_endpoint
    jc .key
    cmp byte [menu_value_a], 0
    jne .key
    mov di, seed_endpoint
    mov al, seed_endpoint_len
    mov dl, question_row
    add dl, [menu_index]
    jmp .set
.key:
    mov di, seed_key
    mov al, seed_key_len
    mov dl, question_row
    add dl, [menu_index]
    call selected_agent_needs_endpoint
    jc .set
    inc dl
.set:
    mov [input_target], di
    mov [input_max], al
    call measure_input_len
    mov [cursor_row], dl
    mov al, [form_field_col]
    add al, 8
    mov [input_start_col], al
    call set_input_window
    ret

measure_input_len:
    mov byte [input_len], 0
    mov di, [input_target]
.next:
    cmp byte [di], 0
    je .done
    inc di
    inc byte [input_len]
    jmp .next
.done:
    ret

input_store_char:
    mov bl, [input_len]
    xor bh, bh
    mov di, [input_target]
    add di, bx
    mov [di], al
    inc byte [input_len]
    inc di
    mov byte [di], 0
    call render_text_input
    ret

input_backspace:
    cmp byte [input_len], 0
    je .done
    dec byte [input_len]
    mov bl, [input_len]
    xor bh, bh
    mov di, [input_target]
    add di, bx
    mov byte [di], 0
    call render_text_input
.done:
    ret

input_wait_key:
    xor ah, ah
    int 0x16
    ret

render_text_input:
    call clear_input_line
    call set_input_window
    mov bl, [question_attr]
.next:
    jcxz .done
    lodsb
    call print_char
    loop .next
.done:
    call set_bios_cursor
    ret

set_input_window:
    mov al, [input_start_col]
    mov [cursor_col], al
    mov dl, [screen_cols]
    sub dl, al
    dec dl
    mov cl, [input_len]
    xor ch, ch
    mov si, [input_target]
    cmp cl, dl
    jbe .done
    mov al, cl
    sub al, dl
    xor ah, ah
    add si, ax
    mov cl, dl
.done:
    ret

ask_agent_setup:
.select:
    call clear_seed_values
    call ask_agent
.values:
    call ensure_seed_values
    jc .reselect
    ret
.reselect:
    call clear_seed_values
    call ask_agent_resume
    jmp .values

ask_agent:
    mov byte [menu_index], 0
    mov byte [blink_state], 0
    call notify_question
    call render_agent_question
ask_agent_resume:
.input:
    call blink_load_marker
    mov ah, 0x01
    int 0x16
    jz .input
    xor ah, ah
    int 0x16
    cmp al, 0x0d
    je .accept
    cmp ah, 0x48
    je .previous
    cmp ah, 0x50
    jne .input
.next:
    mov al, [menu_index]
    inc al
    cmp al, [agent_count]
    jb .store_index
    xor al, al
    jmp .store_index
.previous:
    cmp byte [menu_index], 0
    jne .decrement
    mov al, [agent_count]
    dec al
    jmp .store_index
.decrement:
    mov al, [menu_index]
    dec al
.store_index:
    mov [menu_index], al
    call draw_agent_options
    jmp .input
.accept:
    call copy_selected_agent
    call slide_selected_agent_left
    ret

copy_selected_agent:
    mov al, [menu_index]
    call agent_ptr_from_al
    mov di, seed_agent_id
    mov cx, agent_id_len
.copy:
    lodsb
    stosb
    or al, al
    jz .done
    loop .copy
    mov byte [di - 1], 0
.done:
    or byte [seed_config_flags], seed_flag_agent
    mov byte [seed_cfg_dirty], 1
    ret

slide_selected_agent_left:
    mov al, [seed_col]
    add al, 2
.loop:
    call draw_selected_agent_slide
    mov ah, [form_left_col]
    cmp al, ah
    jbe .done
    sub al, 4
    cmp al, ah
    jae .wait
    mov al, ah
.wait:
    mov cx, 1
    call wait_ticks
    jmp .loop
.done:
    ret

slide_selected_agent_right:
    mov al, [form_left_col]
.loop:
    call draw_selected_agent_slide
    mov ah, [seed_col]
    add ah, 2
    cmp al, ah
    jae .done
    add al, 4
    cmp al, ah
    jbe .wait
    mov al, ah
.wait:
    mov cx, 1
    call wait_ticks
    jmp .loop
.done:
    ret

draw_selected_agent_slide:
    mov [input_start_col], al
    call clear_panel_area
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    call show_load_marker
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, agent_prompt_text
    call print_z
    call draw_agent_options_at_col
    mov al, [input_start_col]
    ret
