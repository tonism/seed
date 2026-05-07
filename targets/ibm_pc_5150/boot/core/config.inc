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

clear_seed_values:
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

ensure_seed_values:
    call selected_agent_needs_endpoint
    jc .key_only
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

selected_agent_needs_endpoint:
    cmp byte [seed_agent_id], 'l'
    jne .no
    clc
    ret
.no:
    stc
    ret
