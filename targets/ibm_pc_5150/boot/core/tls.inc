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
    call tls_prepare_client_key_exchange_transcript
    jc .failed
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .prepare_keys
    call tls_send_client_key_exchange
    jc .failed
.prepare_keys:
    mov bl, [crypto_attr]
    mov al, 'o'
    call show_load_marker
    cmp byte [tls_key_schedule_ready], 1
    je .key_schedule_ready
    call tls_prepare_premaster_secret
    jc .failed
    call tls_prepare_master_secret
    jc .failed
    call tls_prepare_key_block
    jc .failed
.key_schedule_ready:
    call tls_prepare_client_finished
    jc .failed
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    je .send_final_flight
    call tls_send_client_key_exchange
    jc .failed
.send_final_flight:
    call tls_send_client_final_flight
    jc .failed
    call tls_prepare_application_data_current_seq
    jc .failed
    call tls_send_pending_application_data_early
    jc .failed
    call tls_wait_for_server_finished
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
    cmp ax, 0xcca9
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

tls_ensure_current_handshake_record_complete:
    mov si, [tls_current_payload_ptr]
    cmp word [tls_current_payload_len], 0
    je .done
    cmp byte [si], 0x16
    jne .done
    call tls_copy_current_payload
    jc .failed
.receive_header:
    cmp word [tls_current_payload_len], 5
    jae .header_ready
    call .append_next_payload
    jc .failed
    jmp .receive_header
.header_ready:
    mov si, [tls_current_payload_ptr]
    mov ah, [si + 3]
    mov al, [si + 4]
    add ax, 5
    cmp ax, tcp_payload_read_len
    ja .failed
    mov [tls_stream_skip_remaining], ax
    cmp [tls_current_payload_len], ax
    jae .done
.receive_more:
    call .append_next_payload
    jc .failed
    mov ax, [tls_current_payload_len]
    cmp ax, [tls_stream_skip_remaining]
    jb .receive_more
.done:
    clc
    ret
.failed:
    stc
    ret
.append_next_payload:
    call ne_transmit_tcp_ack
    jc .append_failed
    call tcp_receive_payload
    jc .append_failed
    mov ax, [tls_current_payload_len]
    mov di, tls_rx_copy
    add di, ax
    mov cx, [tcp_rx_payload_len]
    add ax, cx
    cmp ax, tcp_payload_read_len
    ja .append_failed
    push ds
    pop es
    mov si, [tcp_rx_payload_ptr]
    rep movsb
    mov [tls_current_payload_len], ax
    mov word [tls_current_payload_ptr], tls_rx_copy
    clc
    ret
.append_failed:
    stc
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
    mov byte [tls_key_schedule_ready], 0
    mov word [tls_prepared_app_len], 0
    mov byte [tls_app_sent], 0
    call tls_clear_client_record_seq
    call tls_clear_server_record_seq
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
    call tls_ensure_current_handshake_record_complete
    jc .failed
    call tls_parse_server_key_exchange
    jc .failed
    call tls_finish_server_key_exchange
    jc .failed
    call tls_prepare_early_key_schedule
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

tls_prepare_early_key_schedule:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .done
    test byte [tls_server_extension_flags], tls_ext_extended_master_secret
    jnz .done
    call tls_prepare_premaster_secret
    jc .failed
    call tls_prepare_master_secret
    jc .failed
    call tls_prepare_key_block
    jc .failed
.done:
    clc
    ret
.failed:
    stc
    ret

tls_wait_for_server_hello_done:
    call tls_load_server_payload
    jc .failed
    call tls_ensure_current_handshake_record_complete
    jc .failed
    call tls_parse_server_hello_done
    jc .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverhellodone_received
    call tls_transcript_update_next_handshake
    jc .failed
    or byte [tls_transcript_flags], tls_transcript_serverhellodone
    call tls_clear_buffered_payload
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    je .ack_done
    call ne_transmit_tcp_ack
    jc .failed
.ack_done:
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
.done:
    clc
    ret
.failed:
    stc
    ret

tls_prepare_master_secret:
    call tls_build_master_secret_seed
    mov word [tls_prf_secret_ptr], tls_premaster_secret
    mov word [tls_prf_secret_len], tls_ec_coordinate_len
    mov word [hmac_key_ptr], tls_premaster_secret
    mov word [hmac_key_len], tls_ec_coordinate_len
    call hmac_prepare_current_key_context
    jc .failed
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_master_secret
    mov word [tls_prf_output_len], tls_master_secret_len
    mov byte [tls_prf_prepared_hmac], 1
    call tls_prf_sha256_expand
    pushf
    mov byte [tls_prf_prepared_hmac], 0
    popf
    jc .failed
    mov word [hmac_key_ptr], tls_master_secret
    mov word [hmac_key_len], tls_master_secret_len
    call hmac_prepare_current_key_context
    jc .failed
    clc
    ret
.failed:
    stc
    ret

tls_prepare_key_block:
    call tls_build_key_expansion_seed
    mov word [tls_prf_secret_ptr], tls_master_secret
    mov word [tls_prf_secret_len], tls_master_secret_len
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_key_block
    mov word [tls_prf_output_len], tls_key_block_len
    mov byte [tls_prf_prepared_hmac], 1
    call tls_prf_sha256_expand
    pushf
    mov byte [tls_prf_prepared_hmac], 0
    popf
    jc .failed
    call tls_split_key_block
    mov byte [tls_key_schedule_ready], 1
    mov byte [handoff_addr + handoff_net_status], net_status_tls_keys_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    stc
    ret

tls_build_master_secret_seed:
    test byte [tls_server_extension_flags], tls_ext_extended_master_secret
    jnz tls_build_extended_master_secret_seed
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

tls_build_extended_master_secret_seed:
    call sha256_save_context
    mov di, tls_handshake_hash
    call sha256_finish
    call sha256_restore_context

    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, tls_prf_seed
    mov si, tls_label_extended_master_secret
    mov cx, tls_label_extended_master_secret_len
    rep movsb
    mov si, tls_handshake_hash
    mov cx, sha256_digest_len
    rep movsb
    mov word [tls_prf_seed_len], tls_label_extended_master_secret_len + sha256_digest_len
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
    call tls_prf_call_hmac
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
    call tls_prf_call_hmac
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
    call tls_prf_call_hmac
    jc .failed
    jmp .next_chunk
.done:
    clc
    ret
.failed:
    stc
    ret

tls_prf_call_hmac:
    cmp byte [tls_prf_prepared_hmac], 0
    jne hmac_sha256_prepared
    call hmac_sha256
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

tls_prepare_client_key_exchange_transcript:
    call build_tls_client_key_exchange
    jc .failed
    mov si, fs_sector_buffer
    add si, 5
    mov cx, [tls_tx_len]
    sub cx, 5
    call tls_transcript_update
    jc .failed
    clc
    ret
.failed:
    stc
    ret

tls_send_client_key_exchange:
    call build_tls_client_key_exchange
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

tls_prepare_client_finished:
    call tls_build_client_finished_plaintext
    jc .failed
    call tls_encrypt_client_finished
    jc .failed
    clc
    ret
.failed:
    stc
    ret

tls_send_client_final_flight:
    call build_tls_client_final_flight
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

tls_wait_for_server_finished:
    call tls_prepare_3c501_receive
    call tls_load_server_payload
    jc .failed
    mov si, [tls_current_payload_ptr]
    call tls_maybe_consume_server_new_session_ticket
    jc .failed
    call tls_parse_server_change_cipher_spec
    jc .failed
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverccs_received
    cmp word [tls_buffered_payload_len], 0
    jne .load_finished
    call ne_transmit_tcp_ack
    jc .failed
.load_finished:
    call tls_load_server_payload
    jc .failed
    mov si, [tls_current_payload_ptr]
    call tls_parse_server_finished_record
    jc .failed
    call tls_verify_server_finished
    jc .failed
    mov si, tls_finished_plain
    mov cx, tls_finished_plain_len
    call tls_transcript_update
    jc .failed
    call tls_increment_server_record_seq
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    je .maybe_defer_finished_ack
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .send_finished_ack
.maybe_defer_finished_ack:
    cmp byte [tls_app_sent], 0
    jne .send_finished_ack
    cmp word [tls_prepared_app_len], 0
    jne .finished_ack_done
.send_finished_ack:
    call ne_transmit_tcp_ack
    jc .failed
.finished_ack_done:
    mov byte [handoff_addr + handoff_net_status], net_status_tls_serverfinished_verified
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_send_application_data:
    mov word [tls_app_record_ptr], tls_app_record_buffer
    cmp word [tls_app_plain_ptr], 0
    jne .plain_ready
    mov word [tls_app_plain_ptr], tls_rx_copy + tls_record_header_len
.plain_ready:
    call tls_build_application_data_record
    jc .failed
    mov si, [tls_app_record_ptr]
    mov cx, [tls_tx_len]
    call tcp_send_payload
    jc .failed
    call tls_increment_client_record_seq
    mov byte [tls_app_sent], 1
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_send_pending_application_data_early:
    cmp byte [tls_app_sent], 0
    jne .done
    cmp word [tls_app_len], 0
    je .done
    call tls_send_application_data_for_nic
    jc .failed
.done:
    clc
    ret
.failed:
    stc
    ret

tls_send_application_data_for_nic:
    cmp word [tls_prepared_app_len], 0
    jne tls_send_prepared_application_data
    call tls_send_application_data
    ret

tls_prepare_application_data_current_seq:
    cmp word [tls_app_len], 0
    jne .request_ready
    call agent_api_prepare_request
    jc .failed
.request_ready:
    cmp word [tls_app_len], 0
    je .none
    mov word [tls_app_record_ptr], tls_app_record_buffer
    call tls_build_application_data_record
    jc .failed
    mov ax, [tls_tx_len]
    mov [tls_prepared_app_len], ax
    clc
    ret
.none:
    mov word [tls_prepared_app_len], 0
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_send_prepared_application_data:
    cmp word [tls_prepared_app_len], 0
    je .done
    mov si, [tls_app_record_ptr]
    mov cx, [tls_prepared_app_len]
    call tcp_send_payload
    jc .failed
    call tls_increment_client_record_seq
    mov byte [tls_app_sent], 1
    mov word [tls_prepared_app_len], 0
.done:
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_build_application_data_record:
    cmp word [tls_app_len], api_request_plain_len
    ja .failed
    cmp word [tls_app_plain_ptr], 0
    je .failed
    cmp word [tls_app_record_ptr], 0
    je .failed
    mov byte [tls_app_content_type], 0x17
    push ds
    pop es
    mov si, [tls_app_plain_ptr]
    mov di, [tls_app_record_ptr]
    add di, tls_record_header_len
    mov cx, [tls_app_len]
    rep movsb
    mov ax, [tls_app_record_ptr]
    add ax, tls_record_header_len
    mov [tls_app_data_ptr], ax
    call tls_build_client_app_nonce
    call tls_build_client_app_aad
    mov word [chacha_key_ptr], tls_client_write_key
    mov word [chacha_nonce_ptr], tls_client_nonce
    mov word [chacha_counter_low], 0
    mov word [chacha_counter_high], 0
    call chacha20_block
    call poly1305_load_key
    mov word [chacha_counter_low], 1
    mov word [chacha_counter_high], 0
    call tls_xor_app_data
    call tls_poly1305_mac_app

    push ds
    pop es
    mov di, [tls_app_record_ptr]
    mov al, [tls_app_content_type]
    stosb
    mov ax, 0x0303
    stosw
    mov ax, [tls_app_len]
    add ax, tls_aead_tag_len
    mov [tls_app_record_len], ax
    call tls_write_be16
    mov di, [tls_app_data_ptr]
    add di, [tls_app_len]
    mov si, tls_finished_tag
    mov cx, tls_aead_tag_len
    rep movsb

    mov ax, [tls_app_len]
    add ax, tls_record_header_len + tls_aead_tag_len
    mov [tls_tx_len], ax
    clc
    ret
.failed:
    stc
    ret

tls_receive_application_data:
    call tls_load_server_payload
    jc .failed
    mov si, [tls_current_payload_ptr]
    call tls_ensure_current_tls_record_complete
    jc .failed
    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
    cmp cx, tls_record_header_len + tls_aead_tag_len
    jb .failed
    mov al, [si]
    mov [tls_app_content_type], al
    cmp byte [tls_app_content_type], 0x17
    je .type_ready
    cmp byte [tls_app_content_type], 0x15
    jne .failed
.type_ready:
    cmp byte [si + 1], 0x03
    jne .failed
    cmp byte [si + 2], 0x03
    jne .failed
    mov ah, [si + 3]
    mov al, [si + 4]
    cmp ax, tls_aead_tag_len + 1
    jb .failed
    mov [tls_app_record_len], ax
    mov dx, ax
    sub dx, tls_aead_tag_len
    cmp dx, tcp_payload_read_len
    ja .failed
    mov [tls_app_len], dx
    add ax, tls_record_header_len
    mov [tls_app_total_len], ax
    cmp ax, cx
    ja .failed
    call tls_save_payload_after_current_offset

    push ds
    pop es
    add si, tls_record_header_len
    mov di, tls_rx_copy
    mov cx, [tls_app_len]
    rep movsb
    mov di, tls_received_tag
    mov cx, tls_aead_tag_len
    rep movsb
    mov word [tls_app_data_ptr], tls_rx_copy

    call tls_build_server_app_nonce
    call tls_build_server_app_aad
    mov word [chacha_key_ptr], tls_server_write_key
    mov word [chacha_nonce_ptr], tls_client_nonce
    mov word [chacha_counter_low], 0
    mov word [chacha_counter_high], 0
    call chacha20_block
    call poly1305_load_key
    call tls_poly1305_mac_app
    mov si, tls_finished_tag
    mov di, tls_received_tag
    mov cx, tls_aead_tag_len
    call tls_compare_buffers
    jc .failed
    mov word [chacha_counter_low], 1
    mov word [chacha_counter_high], 0
    call tls_xor_app_data
    cmp byte [tls_app_content_type], 0x15
    jne .application_record
    jmp .failed
.application_record:
    call tls_increment_server_record_seq
    call ne_transmit_tcp_ack
    jc .failed
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tls
    stc
    ret

tls_ensure_current_tls_record_complete:
    mov si, [tls_current_payload_ptr]
    cmp word [tls_current_payload_len], 0
    je .done
    call tls_copy_current_payload
    jc .failed
.receive_header:
    cmp word [tls_current_payload_len], tls_record_header_len
    jae .header_ready
    call .append_next_payload
    jc .failed
    jmp .receive_header
.header_ready:
    mov si, [tls_current_payload_ptr]
    mov ah, [si + 3]
    mov al, [si + 4]
    add ax, tls_record_header_len
    cmp ax, tls_stream_buffer_len
    ja .failed
    mov [tls_stream_skip_remaining], ax
    cmp [tls_current_payload_len], ax
    jae .done
.receive_more:
    call .append_next_payload
    jc .failed
    mov ax, [tls_current_payload_len]
    cmp ax, [tls_stream_skip_remaining]
    jb .receive_more
.done:
    clc
    ret
.failed:
    stc
    ret
.append_next_payload:
    call ne_transmit_tcp_ack
    jc .append_failed
    call tcp_receive_payload
    jc .append_failed
    mov ax, [tls_current_payload_len]
    mov di, tls_rx_copy
    add di, ax
    mov cx, [tcp_rx_payload_len]
    add ax, cx
    cmp ax, tls_stream_buffer_len
    ja .append_failed
    push ds
    pop es
    mov si, [tcp_rx_payload_ptr]
    rep movsb
    mov [tls_current_payload_len], ax
    mov word [tls_current_payload_ptr], tls_rx_copy
    clc
    ret
.append_failed:
    stc
    ret

tls_xor_app_data:
    push ax
    push bx
    push cx
    push dx
    push si
    mov si, [tls_app_data_ptr]
    mov cx, [tls_app_len]
.next_block:
    or cx, cx
    jz .done
    push cx
    call chacha20_block
    pop cx
    mov dx, cx
    cmp dx, chacha_block_len
    jbe .chunk_ready
    mov dx, chacha_block_len
.chunk_ready:
    mov [tls_app_chunk_len], dx
    sub cx, dx
    push cx
    mov cx, dx
    mov bx, chacha_block
.xor_byte:
    mov al, [si]
    xor al, [bx]
    mov [si], al
    inc si
    inc bx
    loop .xor_byte
    inc word [chacha_counter_low]
    jnz .counter_ready
    inc word [chacha_counter_high]
.counter_ready:
    pop cx
    jmp .next_block
.done:
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

tls_poly1305_mac_app:
    call poly1305_clear_acc

    call poly1305_clear_block
    push ds
    pop es
    mov si, tls_aead_aad
    mov di, poly_block
    mov cx, tls_aead_aad_len
    rep movsb
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block

    mov si, [tls_app_data_ptr]
    mov cx, [tls_app_len]
.cipher_block:
    or cx, cx
    jz .length_block
    call poly1305_clear_block
    mov dx, cx
    cmp dx, 16
    jbe .cipher_chunk_ready
    mov dx, 16
.cipher_chunk_ready:
    mov [tls_app_chunk_len], dx
    sub cx, dx
    push cx
    push ds
    pop es
    mov di, poly_block
    mov cx, dx
    rep movsb
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    pop cx
    jmp .cipher_block

.length_block:
    call poly1305_clear_block
    mov byte [poly_block], tls_aead_aad_len
    mov ax, [tls_app_len]
    mov [poly_block + 8], ax
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    call poly1305_emit_tag
    clc
    ret

tls_build_client_app_nonce:
    call tls_build_client_nonce
    ret

tls_build_server_app_nonce:
    call tls_build_server_nonce
    ret

tls_build_client_app_aad:
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
    mov al, [tls_app_content_type]
    stosb
    mov ax, 0x0303
    stosw
    mov ax, [tls_app_len]
    call tls_write_be16
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

tls_build_server_app_aad:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tls_server_record_seq
    mov di, tls_aead_aad
    mov cx, tls_server_record_seq_len
    rep movsb
    mov al, [tls_app_content_type]
    stosb
    mov ax, 0x0303
    stosw
    mov ax, [tls_app_len]
    call tls_write_be16
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

tls_maybe_consume_server_new_session_ticket:
    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
    cmp cx, 9
    jb .done
    cmp byte [si], 0x16
    jne .done
    cmp byte [si + 5], 0x04
    jne .done
    call tls_parse_next_handshake_header
    jc .failed
    cmp byte [tls_server_next_handshake_type], 0x04
    jne .done
    call tls_transcript_update_next_handshake
    jc .failed
    mov ax, [tls_server_next_total_len]
    call tls_save_payload_after_current_offset
    cmp word [tls_buffered_payload_len], 0
    jne .load_next
    call ne_transmit_tcp_ack
    jc .failed
.load_next:
    call tls_load_server_payload
    jc .failed
.done:
    clc
    ret
.failed:
    stc
    ret

tls_parse_server_change_cipher_spec:
    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
    cmp cx, tls_change_cipher_spec_total_len
    jb .failed
    cmp byte [si], 0x14
    jne .failed
    cmp byte [si + 1], 0x03
    jne .failed
    cmp byte [si + 2], 0x01
    jb .failed
    cmp byte [si + 2], 0x04
    ja .failed
    cmp byte [si + 3], 0
    jne .failed
    cmp byte [si + 4], 1
    jne .failed
    cmp byte [si + 5], 1
    jne .failed
    mov ax, tls_change_cipher_spec_total_len
    call tls_save_payload_after_current_offset
    clc
    ret
.failed:
    stc
    ret

tls_parse_server_finished_record:
    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
    cmp cx, tls_finished_total_len
    jb .failed
    cmp byte [si], 0x16
    jne .failed
    cmp byte [si + 1], 0x03
    jne .failed
    cmp byte [si + 2], 0x03
    jne .failed
    cmp byte [si + 3], 0
    jne .failed
    cmp byte [si + 4], tls_finished_record_len
    jne .failed
    push ds
    pop es
    add si, 5
    mov di, tls_finished_cipher
    mov cx, tls_finished_cipher_len
    rep movsb
    mov di, tls_received_tag
    mov cx, 16
    rep movsb
    mov ax, tls_finished_total_len
    call tls_save_payload_after_current_offset
    clc
    ret
.failed:
    stc
    ret

tls_verify_server_finished:
    call tls_decrypt_server_finished
    jc .failed
    cmp byte [tls_finished_plain], 0x14
    jne .failed
    cmp byte [tls_finished_plain + 1], 0
    jne .failed
    cmp byte [tls_finished_plain + 2], 0
    jne .failed
    cmp byte [tls_finished_plain + 3], tls_finished_verify_len
    jne .failed
    call tls_build_server_finished_verify
    jc .failed
    mov si, tls_finished_plain + 4
    mov di, tls_verify_data
    mov cx, tls_finished_verify_len
    call tls_compare_buffers
    jc .failed
    clc
    ret
.failed:
    stc
    ret

tls_decrypt_server_finished:
    call tls_build_server_nonce
    call tls_build_server_finished_aad

    mov word [chacha_key_ptr], tls_server_write_key
    mov word [chacha_nonce_ptr], tls_client_nonce
    mov word [chacha_counter_low], 0
    mov word [chacha_counter_high], 0
    call chacha20_block
    call poly1305_load_key
    call poly1305_mac_finished
    mov si, tls_finished_tag
    mov di, tls_received_tag
    mov cx, 16
    call tls_compare_buffers
    jc .failed

    mov word [chacha_counter_low], 1
    mov word [chacha_counter_high], 0
    call chacha20_block
    call tls_xor_finished_ciphertext
    clc
    ret
.failed:
    stc
    ret

tls_build_server_finished_verify:
    call sha256_save_context
    mov di, tls_handshake_hash
    call sha256_finish
    call sha256_restore_context

    call tls_build_server_finished_seed
    mov word [tls_prf_secret_ptr], tls_master_secret
    mov word [tls_prf_secret_len], tls_master_secret_len
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_verify_data
    mov word [tls_prf_output_len], tls_finished_verify_len
    mov byte [tls_prf_prepared_hmac], 1
    call tls_prf_sha256_expand
    pushf
    mov byte [tls_prf_prepared_hmac], 0
    popf
    ret

tls_build_server_finished_seed:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, tls_prf_seed
    mov si, tls_label_server_finished
    mov cx, tls_label_server_finished_len
    rep movsb
    mov si, tls_handshake_hash
    mov cx, sha256_digest_len
    rep movsb
    mov word [tls_prf_seed_len], tls_label_server_finished_len + sha256_digest_len
    pop es
    pop di
    pop si
    pop cx
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
    mov byte [tls_prf_prepared_hmac], 1
    call tls_prf_sha256_expand
    pushf
    mov byte [tls_prf_prepared_hmac], 0
    popf
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

tls_build_server_nonce:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tls_server_write_iv
    mov di, tls_client_nonce
    mov cx, tls_chacha_iv_len
    rep movsb
    mov si, tls_server_record_seq
    mov di, tls_client_nonce + 4
    mov cx, tls_server_record_seq_len
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

tls_build_server_finished_aad:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tls_server_record_seq
    mov di, tls_aead_aad
    mov cx, tls_server_record_seq_len
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

tls_xor_finished_ciphertext:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tls_finished_cipher
    mov di, tls_finished_plain
    mov bx, chacha_block
    mov cx, tls_finished_cipher_len
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

build_tls_client_final_flight:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov word [tls_tx_len], tls_change_cipher_spec_total_len + tls_finished_total_len
    mov di, fs_sector_buffer
    mov al, 0x14
    stosb
    mov ax, 0x0303
    stosw
    mov ax, 1
    call tls_write_be16
    mov al, 1
    stosb
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

tls_clear_server_record_seq:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    mov di, tls_server_record_seq
    mov cx, tls_server_record_seq_len
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

tls_increment_server_record_seq:
    push ax
    push cx
    push si
    mov si, tls_server_record_seq + tls_server_record_seq_len - 1
    mov cx, tls_server_record_seq_len
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

tls_compare_buffers:
    push ax
    push cx
    push si
    push di
    xor ah, ah
.next:
    jcxz .done
    lodsb
    xor al, [di]
    or ah, al
    inc di
    loop .next
.done:
    or ah, ah
    jnz .failed
    pop di
    pop si
    pop cx
    pop ax
    clc
    ret
.failed:
    pop di
    pop si
    pop cx
    pop ax
    stc
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
    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
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
    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
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
    call tls_seed_client_random
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

    mov si, tls_extensions_prefix
    mov cx, tls_extensions_prefix_len
    rep movsb

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

tls_seed_client_random:
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
    xor ax, [tcp_local_seq]
    xor ax, [tcp_local_seq + 2]
    xor ax, [tcp_remote_ack]
    xor ax, [tcp_remote_ack + 2]
    xor al, [handoff_addr + handoff_mac]
    xor ah, [handoff_addr + handoff_mac + 5]
    or ax, ax
    jnz .seed_ready
    mov ax, 0x5eed
.seed_ready:
    mov [tls_random_state], ax
    mov bx, 25173
    mov di, tls_random
    mov cx, tls_random_len / 2
.next_word:
    mov ax, [tls_random_state]
    mul bx
    add ax, 13849
    adc dx, 0
    xor ax, dx
    add ax, cx
    mov [tls_random_state], ax
    stosw
    loop .next_word
    pop es
    pop di
    pop dx
    pop cx
    pop bx
    pop ax
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

tls_write_be16:
    xchg al, ah
    stosw
    ret
