%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

net_probe_cfg_phase:
    mov di, low_scratch_start + (net_probe_cfg_name - PHASE_BASE)
    phase_call_res find_root_file
    jc .failed
    cmp word [fs_file_size_high], 0
    jne .failed
    cmp word [fs_file_size_low], 7
    jb .failed
    mov ax, [fs_file_cluster]
    call net_probe_cfg_phase_read_cluster_to_buffer
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
    call net_probe_cfg_phase_copy_line_value
    cmp byte [seed_endpoint], 0
    je .failed
    mov si, seed_endpoint
    call .set_dns_target_from_text
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

.set_dns_target_from_text:
    call .skip_endpoint_prefix
    cmp byte [si], 0
    je .dns_failed
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
    jae .dns_failed
    cmp byte [dns_qname_len], dns_qname_max_len - 1
    jae .dns_failed
    mov [di], al
    inc di
    inc byte [dns_label_len]
    inc byte [dns_qname_len]
    jmp .next_char
.dot:
    cmp byte [dns_label_len], 0
    je .dns_failed
    call .finish_dns_label
    jmp .next_label
.finish:
    cmp byte [dns_label_len], 0
    je .dns_failed
    call .finish_dns_label
    cmp byte [dns_qname_len], dns_qname_max_len
    jae .dns_failed
    mov byte [di], 0
    inc byte [dns_qname_len]
    call .update_dns_tx_len
    clc
    ret
.dns_failed:
    stc
    ret

.skip_endpoint_prefix:
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

.finish_dns_label:
    mov bx, [dns_label_ptr]
    mov al, [dns_label_len]
    mov [bx], al
    ret

.update_dns_tx_len:
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len
    mov [dns_tx_len], ax
    ret

net_probe_cfg_name db 'NET     CFG'

net_probe_cfg_phase_read_cluster_to_buffer:
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

net_probe_cfg_phase_copy_line_value:
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
