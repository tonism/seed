%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

tls_client_hello_phase:
    call build_tls_client_hello_phase
    ret

build_tls_client_hello_phase:
    call tls_seed_client_random_phase
    mov al, [dns_qname_len]
    cmp al, 3
    jb .failed
    sub al, 2
    xor ah, ah
    mov [tls_host_len], ax
    add ax, tls_client_base_len
    cmp ax, tcp_payload_max_len
    ja .failed
    mov [tls_tx_len], ax

    mov di, tls_client_hello_buffer
    mov al, 0x16
    stosb
    mov ax, 0x0103
    stosw
    mov ax, [tls_host_len]
    add ax, tls_record_base_len
    phase_call_res tls_write_be16

    mov al, 0x01
    stosb
    xor al, al
    stosb
    mov ax, [tls_host_len]
    add ax, tls_body_base_len
    phase_call_res tls_write_be16
    mov ax, 0x0303
    stosw

    mov si, tls_random
    mov cx, tls_random_len
    rep movsb
    mov si, low_scratch_start + (tls_client_hello_after_random - PHASE_BASE)
    mov cx, tls_after_random_len
    rep movsb

    mov ax, [tls_host_len]
    add ax, tls_extensions_base_len
    phase_call_res tls_write_be16

    mov si, low_scratch_start + (tls_client_hello_extensions_prefix - PHASE_BASE)
    mov cx, tls_extensions_prefix_len
    rep movsb

    xor ax, ax
    stosw
    mov ax, [tls_host_len]
    add ax, 5
    phase_call_res tls_write_be16
    mov ax, [tls_host_len]
    add ax, 3
    phase_call_res tls_write_be16
    xor al, al
    stosb
    mov ax, [tls_host_len]
    phase_call_res tls_write_be16

    mov si, dns_qname
.label:
    lodsb
    or al, al
    jz .host_done
    mov cl, al
    xor ch, ch
    rep movsb
    cmp byte [si], 0
    je .label
    mov al, '.'
    stosb
    jmp .label
.host_done:
    mov si, low_scratch_start + (tls_client_hello_extensions_tail - PHASE_BASE)
    mov cx, tls_extensions_tail_len
    rep movsb
    clc
    ret
.failed:
    stc
    ret

tls_seed_client_random_phase:
    push ax
    push bx
    push cx
    push dx
    push di
    push es
    push ds
    pop es
    mov ax, [0x046c]
    xor ax, [0x046e]
    xor al, [handoff_addr + handoff_mac]
    xor ah, [handoff_addr + handoff_mac + 5]
    or ax, ax
    jnz .seed_ready
    mov ax, 0x5eed
.seed_ready:
    mov bx, 25173
    mov di, tls_random
    mov cx, tls_random_len / 2
.next_word:
    mul bx
    add ax, 13849
    adc dx, 0
    xor ax, dx
    add ax, cx
    stosw
    loop .next_word
    pop es
    pop di
    pop dx
    pop cx
    pop bx
    pop ax
    ret

tls_client_hello_after_random db 0
                              db 0, 2
                              db 0xcc, 0xa9
                              db 1, 0
tls_client_hello_extensions_prefix db 0xff, 1, 0, 1, 0
tls_client_hello_extensions_tail db 0, 11, 0, 2, 1, 0
                                 db 0, 10, 0, 4, 0, 2, 0, 23
                                 db 0, 35, 0, 0
                                 db 0, 22, 0, 0
                                 db 0, 13, 0, 42, 0, 40
                                 db 4, 3, 5, 3, 6, 3, 8, 7
                                 db 8, 8, 8, 9, 8, 10, 8, 11
                                 db 8, 4, 8, 5, 8, 6, 4, 1
                                 db 5, 1, 6, 1, 3, 3, 3, 1
                                 db 3, 2, 4, 2, 5, 2, 6, 2

%unmacro phase_call_res 1
