tls_probe_server:
    call build_tls_client_hello
    jc .failed
    call tls_prepare_3c501_receive
    mov si, fs_sector_buffer
    mov cx, [tls_tx_len]
    call tcp_send_payload
    jc .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_clienthello_sent
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .wait_for_record
    mov cx, 4
    call wait_ticks
.wait_for_record:
    call tls_wait_for_server_hello
    jc .failed
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_prepare_3c501_receive:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .done
    ; 3c501 can drop the TLS record when a pure ACK latches receive first.
    ; Let consecutive good frames accumulate for the first TLS response.
    xor al, al
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_rcvptr
    out dx, al
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_rx_cmd
    mov al, el1_rx_cmd_bcast_good - 0x20
    out dx, al
.done:
    ret

tls_wait_for_server_hello:
    call tcp_receive_payload
    jc .failed
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]
    cmp cx, 47
    jb .failed
    cmp byte [si], 0x16
    jne .failed
    cmp byte [si + 1], 0x03
    jne .failed
    cmp byte [si + 2], 0x01
    jb .failed
    cmp byte [si + 2], 0x04
    ja .failed
    mov al, [si + 1]
    mov [tls_record_major], al
    mov al, [si + 2]
    mov [tls_record_minor], al
    mov ah, [si + 3]
    mov al, [si + 4]
    or ax, ax
    jz .failed
    cmp ax, 42
    jb .failed
    mov bx, ax
    mov dx, cx
    sub dx, 5
    cmp bx, dx
    ja .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_record_received
    cmp byte [si + 5], 0x02
    jne .failed
    cmp byte [si + 6], 0
    jne .failed
    mov ah, [si + 7]
    mov al, [si + 8]
    cmp ax, 38
    jb .failed
    mov dx, bx
    sub dx, 4
    cmp ax, dx
    ja .failed
    mov [tls_server_handshake_len], ax
    cmp byte [si + 9], 0x03
    jne .failed
    cmp byte [si + 10], 0x01
    jb .failed
    cmp byte [si + 10], 0x04
    ja .failed
    mov al, [si + 9]
    mov [tls_server_major], al
    mov al, [si + 10]
    mov [tls_server_minor], al
    push si
    push ds
    pop es
    add si, 11
    mov di, tls_server_random
    mov cx, tls_random_len
    rep movsb
    pop si
    mov al, [si + 43]
    mov [tls_server_session_id_len], al
    xor ah, ah
    mov bx, ax
    add ax, 38
    cmp ax, [tls_server_handshake_len]
    ja .failed
    mov di, si
    add di, 44
    add di, bx
    mov ah, [di]
    mov al, [di + 1]
    call tls_validate_cipher_suite
    jc .failed
    mov [tls_server_cipher], ax
    cmp byte [di + 2], 0
    jne .failed
    mov al, [di + 2]
    mov [tls_server_compression], al
    mov ax, bx
    add ax, 38
    cmp ax, [tls_server_handshake_len]
    je .no_extensions
    add ax, 2
    cmp ax, [tls_server_handshake_len]
    ja .failed
    mov ah, [di + 3]
    mov al, [di + 4]
    mov [tls_server_extensions_len], ax
    mov cx, [tls_server_handshake_len]
    mov dx, bx
    add dx, 40
    sub cx, dx
    cmp ax, cx
    jne .failed
    jmp .parsed
.no_extensions:
    mov word [tls_server_extensions_len], 0
.parsed:
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverhello_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_validate_cipher_suite:
    cmp ax, 0xc02f
    je .ok
    cmp ax, 0xc030
    je .ok
    cmp ax, 0xcca8
    je .ok
    cmp ax, 0x009c
    je .ok
    cmp ax, 0x009d
    je .ok
    stc
    ret
.ok:
    clc
    ret

build_tls_client_hello:
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

    mov di, fs_sector_buffer
    mov al, 0x16
    stosb
    mov ax, 0x0103
    stosw
    mov ax, [tls_host_len]
    add ax, tls_record_base_len
    call tls_write_be16

    mov al, 0x01
    stosb
    xor al, al
    stosb
    mov ax, [tls_host_len]
    add ax, tls_body_base_len
    call tls_write_be16
    mov ax, 0x0303
    stosw

    mov si, tls_random
    mov cx, tls_random_len
    rep movsb
    mov si, tls_after_random
    mov cx, tls_after_random_len
    rep movsb

    mov ax, [tls_host_len]
    add ax, tls_extensions_base_len
    call tls_write_be16
    xor ax, ax
    stosw
    mov ax, [tls_host_len]
    add ax, 5
    call tls_write_be16
    mov ax, [tls_host_len]
    add ax, 3
    call tls_write_be16
    xor al, al
    stosb
    mov ax, [tls_host_len]
    call tls_write_be16

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
    mov si, tls_extensions_tail
    mov cx, tls_extensions_tail_len
    rep movsb
    clc
    ret
.failed:
    stc
    ret

tls_write_be16:
    xchg al, ah
    stosw
    ret
