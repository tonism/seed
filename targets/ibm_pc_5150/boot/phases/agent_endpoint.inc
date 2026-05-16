%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

agent_endpoint_phase:
    mov word [tcp_dest_port_word], tcp_port_https_word
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .open_provider
    call agent_endpoint_phase_selected_agent_needs_endpoint
    jc .known_provider
    mov si, seed_endpoint
    jmp .set_dns_target_from_text
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
    mov si, low_scratch_start + (host_openai_text - PHASE_BASE)
    jmp .set_dns_target_from_text
.openrouter:
    mov si, low_scratch_start + (host_openrouter_text - PHASE_BASE)
    jmp .set_dns_target_from_text
.anthropic:
    mov si, low_scratch_start + (host_anthropic_text - PHASE_BASE)
    jmp .set_dns_target_from_text
.google:
    mov si, low_scratch_start + (host_google_text - PHASE_BASE)

.set_dns_target_from_text:
    call .skip_endpoint_prefix
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
    call .finish_dns_label
    jmp .next_label
.finish:
    cmp byte [dns_label_len], 0
    je .failed
    call .finish_dns_label
    cmp byte [dns_qname_len], dns_qname_max_len
    jae .failed
    mov byte [di], 0
    inc byte [dns_qname_len]
    call .update_dns_tx_len
    clc
    ret
.failed:
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

host_openrouter_text db 'openrouter.ai', 0
host_openai_text db 'api.openai.com', 0
host_anthropic_text db 'api.anthropic.com', 0
host_google_text db 'generativelanguage.googleapis.com', 0

agent_endpoint_phase_selected_agent_needs_endpoint:
    cmp byte [seed_agent_id], 'l'
    jne .no
    clc
    ret
.no:
    stc
    ret

%unmacro phase_call_res 1
