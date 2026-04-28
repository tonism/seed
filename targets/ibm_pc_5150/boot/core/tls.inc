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
    mov [tls_server_cipher], ax
    call tls_classify_cipher_suite
    jc .failed
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
    mov si, di
    add si, 5
    call tls_parse_server_extensions
    jc .failed
    jmp .parsed
.no_extensions:
    mov word [tls_server_extensions_len], 0
    mov byte [tls_server_extension_flags], 0
.parsed:
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverhello_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_classify_cipher_suite:
    cmp ax, 0xc02f
    je .ecdhe_aes128_sha256
    cmp ax, 0xc030
    je .ecdhe_aes256_sha384
    cmp ax, 0xcca8
    je .ecdhe_chacha_sha256
    cmp ax, 0x009c
    je .rsa_aes128_sha256
    cmp ax, 0x009d
    je .rsa_aes256_sha384
    stc
    ret
.ecdhe_aes128_sha256:
    mov byte [tls_server_key_exchange], tls_kx_ecdhe_rsa
    mov byte [tls_server_bulk_cipher], tls_bulk_aes_128_gcm
    mov byte [tls_server_prf_hash], tls_prf_sha256
    clc
    ret
.ecdhe_aes256_sha384:
    mov byte [tls_server_key_exchange], tls_kx_ecdhe_rsa
    mov byte [tls_server_bulk_cipher], tls_bulk_aes_256_gcm
    mov byte [tls_server_prf_hash], tls_prf_sha384
    clc
    ret
.ecdhe_chacha_sha256:
    mov byte [tls_server_key_exchange], tls_kx_ecdhe_rsa
    mov byte [tls_server_bulk_cipher], tls_bulk_chacha20_poly1305
    mov byte [tls_server_prf_hash], tls_prf_sha256
    clc
    ret
.rsa_aes128_sha256:
    mov byte [tls_server_key_exchange], tls_kx_rsa
    mov byte [tls_server_bulk_cipher], tls_bulk_aes_128_gcm
    mov byte [tls_server_prf_hash], tls_prf_sha256
    clc
    ret
.rsa_aes256_sha384:
    mov byte [tls_server_key_exchange], tls_kx_rsa
    mov byte [tls_server_bulk_cipher], tls_bulk_aes_256_gcm
    mov byte [tls_server_prf_hash], tls_prf_sha384
    clc
    ret

tls_parse_server_extensions:
    mov byte [tls_server_extension_flags], 0
.next:
    or cx, cx
    jz .done
    cmp cx, 4
    jb .failed
    mov ah, [si]
    mov al, [si + 1]
    mov bh, [si + 2]
    mov bl, [si + 3]
    sub cx, 4
    cmp bx, cx
    ja .failed
    add si, 4
    call tls_note_server_extension
    jc .failed
    add si, bx
    sub cx, bx
    jmp .next
.done:
    clc
    ret
.failed:
    stc
    ret

tls_note_server_extension:
    cmp ax, 0x000b
    je .ec_point_formats
    cmp ax, 0x0017
    je .extended_master_secret
    cmp ax, 0xff01
    je .renegotiation_info
    cmp ax, 0x0023
    je .session_ticket
    cmp ax, 0x0010
    je .alpn
    cmp ax, 0x002b
    je .supported_versions
    clc
    ret
.ec_point_formats:
    cmp bx, 2
    jb .failed
    push dx
    mov dl, [si]
    xor dh, dh
    inc dx
    cmp dx, bx
    pop dx
    jne .failed
    or byte [tls_server_extension_flags], tls_ext_ec_point_formats
    clc
    ret
.extended_master_secret:
    or bx, bx
    jnz .failed
    or byte [tls_server_extension_flags], tls_ext_extended_master_secret
    clc
    ret
.renegotiation_info:
    cmp bx, 1
    jne .failed
    cmp byte [si], 0
    jne .failed
    or byte [tls_server_extension_flags], tls_ext_renegotiation_info
    clc
    ret
.session_ticket:
    or byte [tls_server_extension_flags], tls_ext_session_ticket
    clc
    ret
.alpn:
    or byte [tls_server_extension_flags], tls_ext_alpn
    clc
    ret
.supported_versions:
    cmp bx, 2
    jne .failed
    cmp byte [si], 0x03
    jne .failed
    cmp byte [si + 1], 0x03
    jne .failed
    or byte [tls_server_extension_flags], tls_ext_supported_versions
    clc
    ret
.failed:
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
