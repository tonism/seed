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
    call tls_wait_for_record
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

tls_wait_for_record:
    call tcp_receive_payload
    jc .failed
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]
    cmp cx, 5
    jb .failed
    lodsb
    cmp al, 0x15
    je .type_ok
    cmp al, 0x16
    jne .failed
.type_ok:
    cmp byte [si], 0x03
    jne .failed
    cmp byte [si + 1], 0x01
    jb .failed
    cmp byte [si + 1], 0x04
    ja .failed
    mov ah, [si + 2]
    mov al, [si + 3]
    or ax, ax
    jz .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_record_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
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
