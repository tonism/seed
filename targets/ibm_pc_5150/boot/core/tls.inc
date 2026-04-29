tls_probe_server:
    call build_tls_client_hello
    jc .failed
    call tls_transcript_start
    mov si, fs_sector_buffer
    add si, 5
    mov cx, [tls_tx_len]
    sub cx, 5
    call tls_transcript_update
    jc .failed
    or byte [tls_transcript_flags], tls_transcript_clienthello
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
    cmp word [tls_buffered_payload_len], 0
    jne .parse_certificate
    call ne_transmit_tcp_ack
    jc .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverhello_received
.parse_certificate:
    call tls_wait_for_server_certificate
    jc .failed
    call tls_wait_for_server_key_exchange_or_done
    jc .failed
    mov bl, [crypto_attr]
    mov al, 'o'
    call show_load_marker
    call tls_prepare_premaster_secret
    jc .failed
    call tls_send_client_key_exchange
    jc .failed
    call tls_send_change_cipher_spec
    jc .failed
    call tls_send_client_finished
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
    mov [tls_server_record_len], ax
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
    mov si, [tcp_rx_payload_ptr]
    add si, 5
    mov cx, [tls_server_handshake_len]
    add cx, 4
    call tls_transcript_update
    jc .failed
    or byte [tls_transcript_flags], tls_transcript_serverhello
    call tls_save_buffered_server_payload
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverhello_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_save_buffered_server_payload:
    mov ax, [tls_server_record_len]
    add ax, 5
    mov dx, [tcp_rx_payload_len]
    cmp dx, ax
    jbe .none
    sub dx, ax
    mov [tls_buffered_payload_len], dx
    mov bx, [tcp_rx_payload_ptr]
    add bx, ax
    mov [tls_buffered_payload_ptr], bx
    ret
.none:
    mov word [tls_buffered_payload_ptr], 0
    mov word [tls_buffered_payload_len], 0
    ret

tls_classify_cipher_suite:
    cmp ax, 0xcca8
    je .ecdhe_chacha_sha256
    stc
    ret
.ecdhe_chacha_sha256:
    mov byte [tls_server_key_exchange], tls_kx_ecdhe_rsa
    mov byte [tls_server_bulk_cipher], tls_bulk_chacha20_poly1305
    mov byte [tls_server_prf_hash], tls_prf_sha256
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

tls_wait_for_server_certificate:
    call tls_load_server_payload
    jc .failed
    call tls_parse_server_certificate
    jc .failed
    call tls_drain_server_certificate
    jc .failed
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_load_server_payload:
    mov cx, [tls_buffered_payload_len]
    or cx, cx
    jz .receive
    mov si, [tls_buffered_payload_ptr]
    jmp .loaded
.receive:
    call tcp_receive_payload
    jc .done
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]
.loaded:
    mov [tls_current_payload_ptr], si
    mov [tls_current_payload_len], cx
    clc
    ret
.done:
    ret

tls_drain_server_certificate:
    call tls_copy_current_payload
    jc .failed
    call ne_transmit_tcp_ack
    jc .failed
    call tls_transcript_update_certificate_current
    jc .failed
    mov ax, [tls_server_certificate_total_len]
    mov cx, [tls_current_payload_len]
    cmp cx, ax
    jb .need_more
    call tls_save_payload_after_current_offset
.done:
    cmp word [tls_transcript_certificate_remaining], 0
    jne .failed
    or byte [tls_transcript_flags], tls_transcript_certificate
    mov byte [handoff_addr + handoff_net_status], net_status_tls_certificate_drained
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

.need_more:
    sub ax, cx
    mov [tls_stream_skip_remaining], ax
    call tls_clear_buffered_payload
.receive_more:
    call tcp_receive_payload
    jc .failed
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]
    mov [tls_current_payload_ptr], si
    mov [tls_current_payload_len], cx
    call tls_copy_current_payload
    jc .failed
    call ne_transmit_tcp_ack
    jc .failed
    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
    call tls_transcript_update_certificate_chunk
    jc .failed
    mov ax, [tls_stream_skip_remaining]
    mov cx, [tls_current_payload_len]
    cmp cx, ax
    jb .consume_all
    mov bx, [tls_current_payload_ptr]
    mov [tls_current_payload_ptr], bx
    mov [tls_current_payload_len], cx
    call tls_save_payload_after_current_offset
    jmp .done
.consume_all:
    sub ax, cx
    mov [tls_stream_skip_remaining], ax
    jmp .receive_more
.failed:
    stc
    ret

tls_copy_current_payload:
    mov cx, [tls_current_payload_len]
    cmp cx, tcp_payload_read_len
    ja .failed
    push ds
    pop es
    mov si, [tls_current_payload_ptr]
    mov di, tls_rx_copy
    rep movsb
    mov word [tls_current_payload_ptr], tls_rx_copy
    clc
    ret
.failed:
    stc
    ret

tls_save_payload_after_current_offset:
    mov bx, [tls_current_payload_len]
    sub bx, ax
    mov [tls_buffered_payload_len], bx
    or bx, bx
    jz .none
    mov bx, [tls_current_payload_ptr]
    add bx, ax
    mov [tls_buffered_payload_ptr], bx
    ret
.none:
    call tls_clear_buffered_payload
    ret

tls_clear_buffered_payload:
    mov word [tls_buffered_payload_ptr], 0
    mov word [tls_buffered_payload_len], 0
    ret

tls_transcript_start:
    mov word [tls_transcript_len_low], 0
    mov word [tls_transcript_len_high], 0
    mov word [tls_transcript_certificate_remaining], 0
    mov byte [tls_transcript_flags], 0
    call tls_clear_client_record_seq
    call sha256_init
    ret

tls_transcript_update:
    add [tls_transcript_len_low], cx
    mov ax, [tls_transcript_len_high]
    adc ax, 0
    mov [tls_transcript_len_high], ax
    call sha256_update
    ret

tls_transcript_update_certificate_current:
    mov si, [tls_current_payload_ptr]
    add si, 5
    mov cx, [tls_current_payload_len]
    sub cx, 5
    call tls_transcript_update_certificate_chunk
    ret

tls_transcript_update_certificate_chunk:
    or cx, cx
    jz .done
    mov ax, [tls_transcript_certificate_remaining]
    or ax, ax
    jz .done
    cmp cx, ax
    jbe .length_ready
    mov cx, ax
.length_ready:
    push cx
    call tls_transcript_update
    pop cx
    sub [tls_transcript_certificate_remaining], cx
.done:
    clc
    ret

tls_transcript_update_next_handshake:
    cmp word [tls_server_next_record_len], 0
    jne .record
    mov si, [tls_current_payload_ptr]
    mov cx, [tls_server_next_total_len]
    call tls_transcript_update
    ret
.record:
    mov si, [tls_current_payload_ptr]
    add si, 5
    mov cx, [tls_server_next_total_len]
    sub cx, 5
    call tls_transcript_update
    ret

tls_parse_server_certificate:
    cmp cx, 12
    jb .failed
    cmp byte [si], 0x16
    jne .failed
    cmp byte [si + 1], 0x03
    jne .failed
    cmp byte [si + 2], 0x01
    jb .failed
    cmp byte [si + 2], 0x04
    ja .failed
    mov ah, [si + 3]
    mov al, [si + 4]
    cmp ax, 7
    jb .failed
    mov [tls_server_certificate_record_len], ax
    cmp byte [si + 5], 0x0b
    jne .failed
    mov ah, [si + 7]
    mov al, [si + 8]
    mov [tls_server_certificate_len_low], ax
    mov al, [si + 6]
    mov [tls_server_certificate_len_high], al
    mov ah, [si + 10]
    mov al, [si + 11]
    mov [tls_server_certificate_list_len_low], ax
    mov al, [si + 9]
    mov [tls_server_certificate_list_len_high], al

    mov dl, [si + 9]
    mov bh, [si + 10]
    mov bl, [si + 11]
    add bx, 3
    adc dl, 0
    cmp dl, [si + 6]
    jne .failed
    cmp bh, [si + 7]
    jne .failed
    cmp bl, [si + 8]
    jne .failed
    cmp byte [tls_server_certificate_len_high], 0
    jne .failed
    mov ax, [tls_server_certificate_len_low]
    add ax, 4
    cmp ax, [tls_server_certificate_record_len]
    ja .failed
    add ax, 5
    mov [tls_server_certificate_total_len], ax
    sub ax, 5
    mov [tls_transcript_certificate_remaining], ax
    mov byte [handoff_addr + handoff_net_status], net_status_tls_certificate_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_wait_for_server_key_exchange_or_done:
    cmp byte [tls_server_key_exchange], tls_kx_ecdhe_rsa
    jne .wait_done
    call tls_load_server_payload
    jc .failed
    call tls_parse_server_key_exchange
    jc .failed
    call tls_finish_server_key_exchange
    jc .failed
.wait_done:
    call tls_wait_for_server_hello_done
    jc .failed
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_wait_for_server_hello_done:
    call tls_load_server_payload
    jc .failed
    call tls_parse_server_hello_done
    jc .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverhellodone_received
    call tls_transcript_update_next_handshake
    jc .failed
    or byte [tls_transcript_flags], tls_transcript_serverhellodone
    call tls_clear_buffered_payload
    call ne_transmit_tcp_ack
    jc .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_transcript_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    stc
    ret

tls_prepare_premaster_secret:
    cmp byte [tls_server_key_exchange], tls_kx_ecdhe_rsa
    jne .done
    call p256_compute_server_premaster_secret
    jc .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_premaster_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    call tls_prepare_key_schedule
    jc .failed
.done:
    clc
    ret
.failed:
    stc
    ret

tls_prepare_key_schedule:
    call tls_build_master_secret_seed
    mov word [tls_prf_secret_ptr], tls_premaster_secret
    mov word [tls_prf_secret_len], tls_ec_coordinate_len
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_master_secret
    mov word [tls_prf_output_len], tls_master_secret_len
    call tls_prf_sha256_expand
    jc .failed

    call tls_build_key_expansion_seed
    mov word [tls_prf_secret_ptr], tls_master_secret
    mov word [tls_prf_secret_len], tls_master_secret_len
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_key_block
    mov word [tls_prf_output_len], tls_key_block_len
    call tls_prf_sha256_expand
    jc .failed
    call tls_split_key_block
    mov byte [handoff_addr + handoff_net_status], net_status_tls_keys_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    stc
    ret

tls_build_master_secret_seed:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, tls_prf_seed
    mov si, tls_label_master_secret
    mov cx, tls_label_master_secret_len
    rep movsb
    mov si, tls_random
    mov cx, tls_random_len
    rep movsb
    mov si, tls_server_random
    mov cx, tls_random_len
    rep movsb
    mov word [tls_prf_seed_len], tls_label_master_secret_len + tls_random_len + tls_random_len
    pop es
    pop di
    pop si
    pop cx
    ret

tls_build_key_expansion_seed:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, tls_prf_seed
    mov si, tls_label_key_expansion
    mov cx, tls_label_key_expansion_len
    rep movsb
    mov si, tls_server_random
    mov cx, tls_random_len
    rep movsb
    mov si, tls_random
    mov cx, tls_random_len
    rep movsb
    mov word [tls_prf_seed_len], tls_label_key_expansion_len + tls_random_len + tls_random_len
    pop es
    pop di
    pop si
    pop cx
    ret

tls_prf_sha256_expand:
    mov ax, [tls_prf_output_len]
    mov [tls_prf_output_remaining], ax
    mov ax, [tls_prf_output_ptr]
    mov [tls_prf_current_output_ptr], ax

    mov ax, [tls_prf_secret_ptr]
    mov [hmac_key_ptr], ax
    mov ax, [tls_prf_secret_len]
    mov [hmac_key_len], ax
    mov ax, [tls_prf_seed_ptr]
    mov [hmac_data1_ptr], ax
    mov ax, [tls_prf_seed_len]
    mov [hmac_data1_len], ax
    mov word [hmac_data2_len], 0
    mov word [hmac_data3_len], 0
    mov word [hmac_output_ptr], tls_prf_a
    call hmac_sha256
    jc .failed
.next_chunk:
    cmp word [tls_prf_output_remaining], 0
    je .done
    mov ax, [tls_prf_secret_ptr]
    mov [hmac_key_ptr], ax
    mov ax, [tls_prf_secret_len]
    mov [hmac_key_len], ax
    mov word [hmac_data1_ptr], tls_prf_a
    mov word [hmac_data1_len], sha256_digest_len
    mov ax, [tls_prf_seed_ptr]
    mov [hmac_data2_ptr], ax
    mov ax, [tls_prf_seed_len]
    mov [hmac_data2_len], ax
    mov word [hmac_data3_len], 0
    mov word [hmac_output_ptr], tls_prf_chunk
    call hmac_sha256
    jc .failed

    mov cx, [tls_prf_output_remaining]
    cmp cx, sha256_digest_len
    jbe .chunk_len_ready
    mov cx, sha256_digest_len
.chunk_len_ready:
    mov [tls_prf_chunk_len], cx
    push ds
    pop es
    mov si, tls_prf_chunk
    mov di, [tls_prf_current_output_ptr]
    rep movsb
    mov ax, [tls_prf_chunk_len]
    add [tls_prf_current_output_ptr], ax
    sub [tls_prf_output_remaining], ax
    cmp word [tls_prf_output_remaining], 0
    je .done

    mov ax, [tls_prf_secret_ptr]
    mov [hmac_key_ptr], ax
    mov ax, [tls_prf_secret_len]
    mov [hmac_key_len], ax
    mov word [hmac_data1_ptr], tls_prf_a
    mov word [hmac_data1_len], sha256_digest_len
    mov word [hmac_data2_len], 0
    mov word [hmac_data3_len], 0
    mov word [hmac_output_ptr], tls_prf_a
    call hmac_sha256
    jc .failed
    jmp .next_chunk
.done:
    clc
    ret
.failed:
    stc
    ret

tls_split_key_block:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tls_key_block
    mov di, tls_client_write_key
    mov cx, tls_chacha_key_len
    rep movsb
    mov di, tls_server_write_key
    mov cx, tls_chacha_key_len
    rep movsb
    mov di, tls_client_write_iv
    mov cx, tls_chacha_iv_len
    rep movsb
    mov di, tls_server_write_iv
    mov cx, tls_chacha_iv_len
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    ret

tls_send_client_key_exchange:
    call build_tls_client_key_exchange
    jc .failed
    mov si, fs_sector_buffer
    add si, 5
    mov cx, [tls_tx_len]
    sub cx, 5
    call tls_transcript_update
    jc .failed
    mov si, fs_sector_buffer
    mov cx, [tls_tx_len]
    call tcp_send_payload
    jc .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_clientkeyexchange_sent
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    stc
    ret

tls_send_change_cipher_spec:
    call build_tls_change_cipher_spec
    jc .failed
    mov si, fs_sector_buffer
    mov cx, [tls_tx_len]
    call tcp_send_payload
    jc .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_changecipherspec_sent
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    stc
    ret

tls_send_client_finished:
    call tls_build_client_finished_plaintext
    jc .failed
    call tls_encrypt_client_finished
    jc .failed
    mov si, fs_sector_buffer
    mov cx, [tls_tx_len]
    call tcp_send_payload
    jc .failed
    mov si, tls_finished_plain
    mov cx, tls_finished_plain_len
    call tls_transcript_update
    jc .failed
    call tls_increment_client_record_seq
    mov byte [handoff_addr + handoff_net_status], net_status_tls_clientfinished_sent
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    stc
    ret

tls_build_client_finished_plaintext:
    call sha256_save_context
    mov di, tls_handshake_hash
    call sha256_finish
    call sha256_restore_context

    call tls_build_client_finished_seed
    mov word [tls_prf_secret_ptr], tls_master_secret
    mov word [tls_prf_secret_len], tls_master_secret_len
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_verify_data
    mov word [tls_prf_output_len], tls_finished_verify_len
    call tls_prf_sha256_expand
    jc .failed

    push ds
    pop es
    mov di, tls_finished_plain
    mov al, 0x14
    stosb
    xor al, al
    stosb
    stosb
    mov al, tls_finished_verify_len
    stosb
    mov si, tls_verify_data
    mov cx, tls_finished_verify_len
    rep movsb
    clc
    ret
.failed:
    stc
    ret

tls_build_client_finished_seed:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, tls_prf_seed
    mov si, tls_label_client_finished
    mov cx, tls_label_client_finished_len
    rep movsb
    mov si, tls_handshake_hash
    mov cx, sha256_digest_len
    rep movsb
    mov word [tls_prf_seed_len], tls_label_client_finished_len + sha256_digest_len
    pop es
    pop di
    pop si
    pop cx
    ret

tls_encrypt_client_finished:
    call tls_build_client_nonce
    call tls_build_finished_aad

    mov word [chacha_key_ptr], tls_client_write_key
    mov word [chacha_nonce_ptr], tls_client_nonce
    mov word [chacha_counter_low], 0
    mov word [chacha_counter_high], 0
    call chacha20_block
    call poly1305_load_key

    mov word [chacha_counter_low], 1
    mov word [chacha_counter_high], 0
    call chacha20_block
    call tls_xor_finished_plaintext
    call poly1305_mac_finished
    call build_tls_client_finished_record
    clc
    ret

tls_build_client_nonce:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tls_client_write_iv
    mov di, tls_client_nonce
    mov cx, tls_chacha_iv_len
    rep movsb
    mov si, tls_client_record_seq
    mov di, tls_client_nonce + 4
    mov cx, tls_client_record_seq_len
.xor_seq:
    lodsb
    xor [di], al
    inc di
    loop .xor_seq
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

tls_build_finished_aad:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tls_client_record_seq
    mov di, tls_aead_aad
    mov cx, tls_client_record_seq_len
    rep movsb
    mov al, 0x16
    stosb
    mov ax, 0x0303
    stosw
    mov ax, tls_finished_plain_len
    call tls_write_be16
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

tls_xor_finished_plaintext:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tls_finished_plain
    mov di, tls_finished_cipher
    mov bx, chacha_block
    mov cx, tls_finished_plain_len
.next:
    lodsb
    xor al, [bx]
    stosb
    inc bx
    loop .next
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

build_tls_client_finished_record:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov word [tls_tx_len], tls_finished_total_len
    mov di, fs_sector_buffer
    mov al, 0x16
    stosb
    mov ax, 0x0303
    stosw
    mov ax, tls_finished_record_len
    call tls_write_be16
    mov si, tls_finished_cipher
    mov cx, tls_finished_cipher_len
    rep movsb
    mov si, tls_finished_tag
    mov cx, 16
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    ret

tls_clear_client_record_seq:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    mov di, tls_client_record_seq
    mov cx, tls_client_record_seq_len
    xor al, al
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

tls_increment_client_record_seq:
    push ax
    push cx
    push si
    mov si, tls_client_record_seq + tls_client_record_seq_len - 1
    mov cx, tls_client_record_seq_len
    stc
.next:
    mov al, [si]
    adc al, 0
    mov [si], al
    jnc .done
    dec si
    loop .next
.done:
    pop si
    pop cx
    pop ax
    ret

tls_parse_next_handshake_header:
    cmp cx, 4
    jb .failed
    cmp byte [si], 0x16
    je .record
    mov al, [si]
    mov [tls_server_next_handshake_type], al
    mov al, [si + 1]
    mov [tls_server_next_handshake_len_high], al
    mov ah, [si + 2]
    mov al, [si + 3]
    mov [tls_server_next_handshake_len_low], ax
    mov word [tls_server_next_record_len], 0
    mov bx, si
    add bx, 4
    mov [tls_next_handshake_body_ptr], bx
    call tls_finish_next_handshake_header
    ret
.record:
    cmp cx, 9
    jb .failed
    cmp byte [si + 1], 0x03
    jne .failed
    cmp byte [si + 2], 0x01
    jb .failed
    cmp byte [si + 2], 0x04
    ja .failed
    mov ah, [si + 3]
    mov al, [si + 4]
    cmp ax, 4
    jb .failed
    mov [tls_server_next_record_len], ax
    mov dx, cx
    sub dx, 5
    cmp ax, dx
    ja .failed
    mov al, [si + 5]
    mov [tls_server_next_handshake_type], al
    mov al, [si + 6]
    mov [tls_server_next_handshake_len_high], al
    mov ah, [si + 7]
    mov al, [si + 8]
    mov [tls_server_next_handshake_len_low], ax
    mov bx, si
    add bx, 9
    mov [tls_next_handshake_body_ptr], bx
    call tls_finish_next_handshake_header
    jc .failed
    mov ax, [tls_server_next_handshake_len_low]
    add ax, 4
    cmp ax, [tls_server_next_record_len]
    ja .failed
    ret
.failed:
    stc
    ret

tls_finish_next_handshake_header:
    cmp byte [tls_server_next_handshake_len_high], 0
    jne .failed
    mov ax, [tls_server_next_handshake_len_low]
    add ax, 4
    cmp word [tls_server_next_record_len], 0
    je .total_ready
    add ax, 5
.total_ready:
    mov [tls_server_next_total_len], ax
    cmp ax, [tls_current_payload_len]
    ja .failed
    clc
    ret
.failed:
    stc
    ret

tls_parse_server_key_exchange:
    call tls_parse_next_handshake_header
    jc .failed
    cmp byte [tls_server_next_handshake_type], 0x0c
    jne .failed
    cmp word [tls_server_next_handshake_len_low], 8
    jb .failed
    mov bx, [tls_next_handshake_body_ptr]
    cmp byte [bx], 3
    jne .failed
    mov ah, [bx + 1]
    mov al, [bx + 2]
    cmp ax, tls_curve_secp256r1
    jne .failed
    mov [tls_server_key_curve], ax
    mov al, [bx + 3]
    or al, al
    jz .failed
    mov [tls_server_key_public_len], al
    cmp al, tls_ec_public_uncompressed_len
    jne .failed
    xor ah, ah
    mov dx, [tls_server_next_handshake_len_low]
    add ax, 8
    cmp ax, dx
    ja .failed
    cmp byte [bx + 4], 0x04
    jne .failed
    push ds
    pop es
    mov si, bx
    add si, 5
    mov di, tls_server_ec_x
    mov cx, tls_ec_coordinate_len
    rep movsb
    mov di, tls_server_ec_y
    mov cx, tls_ec_coordinate_len
    rep movsb
    mov si, tls_server_ec_x
    mov di, tls_server_ec_x_words
    call p256_from_be32
    mov si, tls_server_ec_y
    mov di, tls_server_ec_y_words
    call p256_from_be32
    mov si, tls_server_ec_x_words
    mov di, p256_prime
    call p256_cmp_words
    jnc .failed
    mov si, tls_server_ec_y_words
    mov di, p256_prime
    call p256_cmp_words
    jnc .failed
    call p256_validate_point_on_curve
    jc .failed
    mov al, [tls_server_key_public_len]
    xor ah, ah
    mov bx, [tls_next_handshake_body_ptr]
    add bx, ax
    add bx, 4
    mov al, [bx]
    mov [tls_server_signature_hash], al
    mov al, [bx + 1]
    mov [tls_server_signature_alg], al
    mov ah, [bx + 2]
    mov al, [bx + 3]
    mov [tls_server_signature_len], ax
    mov dx, ax
    mov al, [tls_server_key_public_len]
    xor ah, ah
    add ax, 8
    add ax, dx
    cmp ax, [tls_server_next_handshake_len_low]
    jne .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverkeyexchange_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    stc
    ret

tls_finish_server_key_exchange:
    call tls_transcript_update_next_handshake
    jc .failed
    or byte [tls_transcript_flags], tls_transcript_serverkeyexchange
    mov ax, [tls_server_next_total_len]
    call tls_save_payload_after_current_offset
    cmp word [tls_buffered_payload_len], 0
    jne .done
    call ne_transmit_tcp_ack
    jc .failed
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverkeyexchange_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    stc
    ret

tls_parse_server_hello_done:
    call tls_parse_next_handshake_header
    jc .failed
    cmp byte [tls_server_next_handshake_type], 0x0e
    jne .failed
    cmp word [tls_server_next_handshake_len_low], 0
    jne .failed
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

build_tls_client_key_exchange:
    mov word [tls_tx_len], tls_client_key_exchange_total_len
    mov di, fs_sector_buffer
    mov al, 0x16
    stosb
    mov ax, 0x0303
    stosw
    mov ax, tls_client_key_exchange_record_len
    call tls_write_be16

    mov al, 0x10
    stosb
    xor al, al
    stosb
    mov ax, tls_client_key_exchange_handshake_len
    call tls_write_be16
    mov al, tls_ec_public_uncompressed_len
    stosb
    mov si, tls_client_ec_public
    mov cx, tls_ec_public_uncompressed_len
    rep movsb
    clc
    ret

build_tls_change_cipher_spec:
    mov word [tls_tx_len], tls_change_cipher_spec_total_len
    mov di, fs_sector_buffer
    mov al, 0x14
    stosb
    mov ax, 0x0303
    stosw
    mov ax, 1
    call tls_write_be16
    mov al, 1
    stosb
    clc
    ret

tls_write_be16:
    xchg al, ah
    stosw
    ret
