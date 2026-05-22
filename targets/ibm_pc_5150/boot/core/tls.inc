tls_fail_error:
    mov al, net_error_tls
    jmp net_fail_al

tls_probe_server:
    call tls_transcript_start
    mov si, tls_client_hello_buffer
    add si, 5
    mov cx, [tls_tx_len]
    sub cx, 5
    call tls_transcript_update
    jc .failed
    call tls_prepare_3c501_receive
    mov si, tls_client_hello_buffer
    mov cx, [tls_tx_len]
    call tcp_send_payload
    jc .failed
.wait_for_record:
    call tls_wait_for_server_hello
    jc .failed
    cmp word [tls_buffered_payload_len], 0
    jne .parse_certificate
    call ne_transmit_tcp_ack
    jc .failed
.parse_certificate:
    call tls_wait_for_server_certificate
    jc .failed
    call tls_wait_for_server_key_exchange_or_done
    jc .failed
.transcript_client_key_exchange:
    call tls_prepare_client_key_exchange_transcript
    jc .failed
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .show_crypto_ready
    call tls_send_client_key_exchange
    jc .failed
.show_crypto_ready:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    je .maybe_prepare_keys
    mov bl, [crypto_attr]
    mov al, 'o'
    call show_load_marker
.maybe_prepare_keys:
    cmp byte [tls_key_schedule_ready], 1
    je .key_schedule_ready
    call tls_prepare_master_secret
    jc .failed
    call tls_prepare_key_block
    jc .failed
.key_schedule_ready:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .prepare_client_finished
    call tls_prepare_3c501_split_application_record
    jc .failed
.prepare_client_finished:
    call tls_prepare_client_finished
    jc .failed
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    je .send_final_flight
    call tls_send_client_key_exchange
    jc .failed
.send_final_flight:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .final_flight_ready
    call tls_prepare_3c501_prebuilt_application_tcp_frame
    jc .failed
.final_flight_ready:
    call tls_send_client_final_flight
    jc .failed
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .send_application_data
    call tls_wait_for_server_finished_then_send_prebuilt_application
    jc .failed
    jmp .done
.send_application_data:
    call tls_send_application_data_current_seq
    jc .failed
.wait_for_server_finished:
    call tls_wait_for_server_finished
    jc .failed
.done:
    clc
    ret
.failed:
    jmp tls_fail_error

tls_prepare_3c501_receive:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .done
    ; 3c501 can drop the TLS record when a pure ACK latches receive first.
    ; Let consecutive good frames accumulate for the first TLS response.
    xor al, al
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + el1_rcvptr]
    out dx, al
    lea dx, [bx + el1_rx_cmd]
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
    push si
    push ds
    pop es
    add si, 11
    mov di, tls_server_random
    mov cx, tls_random_len
    rep movsb
    pop si
    mov al, [si + 43]
    xor ah, ah
    mov bx, ax
    add ax, 38
    cmp ax, [tls_server_handshake_len]
    ja .failed
    mov di, si
    add di, 44
    add di, bx
    cmp word [di], 0xa9cc
    jne .failed
    cmp byte [di + 2], 0
    jne .failed
    mov ax, bx
    add ax, 38
    cmp ax, [tls_server_handshake_len]
    je .no_extensions
    add ax, 2
    cmp ax, [tls_server_handshake_len]
    ja .failed
    mov ah, [di + 3]
    mov al, [di + 4]
    mov cx, [tls_server_handshake_len]
    mov dx, bx
    add dx, 40
    sub cx, dx
    cmp ax, cx
    jne .failed
    jmp .parsed
.no_extensions:
.parsed:
    mov si, [tcp_rx_payload_ptr]
    add si, 5
    mov cx, [tls_server_handshake_len]
    add cx, 4
    call tls_transcript_update
    jc .failed
    call tls_save_buffered_server_payload
    clc
    ret
.failed:
    jmp tls_fail_error

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

tls_wait_for_server_certificate:
    call tls_load_server_payload
    jc .failed
    call tls_parse_server_certificate
    jc .failed
    jmp tls_drain_server_certificate
.failed:
    jmp tls_fail_error

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
    cmp ax, tls_payload_buffer_len
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
    cmp ax, tls_payload_buffer_len
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
    cmp cx, tls_payload_buffer_len
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
    jmp tls_clear_buffered_payload

tls_clear_buffered_payload:
    mov word [tls_buffered_payload_ptr], 0
    mov word [tls_buffered_payload_len], 0
    ret

tls_transcript_start:
    mov word [tls_transcript_certificate_remaining], 0
    mov byte [tls_key_schedule_ready], 0
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    mov di, tls_client_record_seq
    mov cx, tls_client_record_seq_len + tls_server_record_seq_len
    xor al, al
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    jmp sha256_init

tls_transcript_update:
    jmp sha256_update

tls_transcript_update_certificate_current:
    mov si, [tls_current_payload_ptr]
    add si, 5
    mov cx, [tls_current_payload_len]
    sub cx, 5
    jmp tls_transcript_update_certificate_chunk

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
    jmp tls_transcript_update
.record:
    mov si, [tls_current_payload_ptr]
    add si, 5
    mov cx, [tls_server_next_total_len]
    sub cx, 5
    jmp tls_transcript_update

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
    clc
    ret
.failed:
    jmp tls_fail_error

tls_wait_for_server_key_exchange_or_done:
    call tls_load_server_payload
    jc .failed
    call tls_ensure_current_handshake_record_complete
    jc .failed
    call tls_parse_server_key_exchange
    jc .failed
    call tls_finish_server_key_exchange
    jc .failed
    call tls_wait_for_server_hello_done
    jc .failed
    clc
    ret
.failed:
    jmp tls_fail_error

tls_prepare_early_key_schedule:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .done
    call tls_prepare_master_secret
    jc .failed
    jmp tls_prepare_key_block
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
    call tls_transcript_update_next_handshake
    jc .failed
    call tls_clear_buffered_payload
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    je .ack_done
    call ne_transmit_tcp_ack
    jc .failed
.ack_done:
    clc
    ret
.failed:
    stc
    ret

tls_prepare_master_secret:
    call tls_build_master_secret_seed
    mov word [hmac_key_ptr], tls_premaster_secret
    mov word [hmac_key_len], tls_ec_coordinate_len
    call hmac_prepare_current_key_context
    jc .failed
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_master_secret
    mov word [tls_prf_output_len], tls_master_secret_len
    call tls_prf_sha256_expand
    jc .failed
    mov word [hmac_key_ptr], tls_master_secret
    mov word [hmac_key_len], tls_master_secret_len
    jmp hmac_prepare_current_key_context
.failed:
    stc
    ret

tls_prepare_key_block:
    call tls_build_key_expansion_seed
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_key_block
    mov word [tls_prf_output_len], tls_key_block_len
    call tls_prf_sha256_expand
    jc .failed
    call tls_split_key_block
    mov byte [tls_key_schedule_ready], 1
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

    mov ax, [tls_prf_seed_ptr]
    mov [hmac_data1_ptr], ax
    mov ax, [tls_prf_seed_len]
    mov [hmac_data1_len], ax
    mov word [hmac_data2_len], 0
    mov word [hmac_output_ptr], tls_prf_a
    call hmac_sha256_prepared
    jc .failed
.next_chunk:
    cmp word [tls_prf_output_remaining], 0
    je .done
    mov word [hmac_data1_ptr], tls_prf_a
    mov word [hmac_data1_len], sha256_digest_len
    mov ax, [tls_prf_seed_ptr]
    mov [hmac_data2_ptr], ax
    mov ax, [tls_prf_seed_len]
    mov [hmac_data2_len], ax
    mov word [hmac_output_ptr], tls_prf_chunk
    call hmac_sha256_prepared
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

    mov word [hmac_data1_ptr], tls_prf_a
    mov word [hmac_data1_len], sha256_digest_len
    mov word [hmac_data2_len], 0
    mov word [hmac_output_ptr], tls_prf_a
    call hmac_sha256_prepared
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

tls_prepare_client_key_exchange_transcript:
    call build_tls_client_key_exchange
    jc .failed
    mov si, fs_sector_buffer
    add si, 5
    mov cx, [tls_tx_len]
    sub cx, 5
    jmp tls_transcript_update
.failed:
    ret

tls_send_client_key_exchange:
    call build_tls_client_key_exchange
    jc .failed
    mov si, fs_sector_buffer
    mov cx, [tls_tx_len]
    call tcp_send_payload
    jc .failed
    ret
.failed:
    ret

tls_prepare_client_finished:
    call tls_build_client_finished_plaintext
    jc .failed
    jmp tls_encrypt_client_finished
.failed:
    ret

tls_send_client_final_flight:
    call build_tls_client_final_flight
    mov si, tls_finished_plain
    mov cx, tls_finished_plain_len
    call tls_transcript_update
    jc tls_send_client_final_flight_failed
tls_send_prebuilt_client_final_flight:
    mov si, fs_sector_buffer
    mov cx, [tls_tx_len]
    call tcp_send_payload
    jc tls_send_client_final_flight_failed
    call tls_increment_client_record_seq
    ret
tls_send_client_final_flight_failed:
    stc
    ret

tls_prepare_3c501_split_application_record:
    inc byte [tls_client_record_seq + tls_client_record_seq_len - 1]
    call tls_build_application_data_record
    dec byte [tls_client_record_seq + tls_client_record_seq_len - 1]
    ret

tls_wait_for_server_finished_then_send_prebuilt_application:
    call tls_prepare_3c501_receive
    call tls_load_server_payload
    jc .failed
    call tls_send_prebuilt_3c501_application_tcp_frame
    jc .failed
    call tls_parse_server_change_cipher_spec
    jc .failed
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
    clc
    ret
.failed:
    stc
    ret

tls_prepare_3c501_prebuilt_application_tcp_frame:
    mov ax, [tcp_remote_ack]
    push ax
    mov ax, [tcp_remote_ack + 2]
    push ax
    mov ax, [tcp_local_seq]
    push ax
    mov ax, [tcp_local_seq + 2]
    push ax
    mov di, tcp_remote_ack
    mov cx, tls_change_cipher_spec_total_len + tls_finished_total_len
    call tcp_add_cx_to_seq
    mov di, tcp_local_seq
    call tcp_add_cx_to_seq
    mov al, 0x18
    mov si, tls_app_record_buffer
    mov cx, [tls_app_record_len]
    call build_tcp_segment_frame
    mov [tls_app_chunk_len], cx
    push ds
    pop es
    mov si, ne_tx_frame
    mov di, tls_rx_copy
    rep movsb
    pop ax
    mov [tcp_local_seq + 2], ax
    pop ax
    mov [tcp_local_seq], ax
    pop ax
    mov [tcp_remote_ack + 2], ax
    pop ax
    mov [tcp_remote_ack], ax
    clc
    ret

tls_send_prebuilt_3c501_application_tcp_frame:
    mov si, tls_rx_copy
    mov cx, [tls_app_chunk_len]
    call ne_transmit_frame
    jc .failed
    mov di, tcp_local_seq
    mov cx, [tls_app_record_len]
    call tcp_add_cx_to_seq
    call tls_increment_client_record_seq
    clc
    ret
.failed:
    stc
    ret

tls_wait_for_server_finished:
    call tls_prepare_3c501_receive
    call tls_load_server_payload
    jc .failed
    call tls_parse_server_change_cipher_spec
    jc .failed
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
    call ne_transmit_tcp_ack
    jc .failed
    clc
    ret
.failed:
    jmp tls_fail_error

tls_send_application_data_current_seq:
    call tls_build_application_data_record
tls_send_prebuilt_application_data_current_seq:
    mov si, tls_app_record_buffer
    mov cx, [tls_app_record_len]
    call tcp_send_payload
    jc tls_send_app_failed
    call tls_increment_client_record_seq
tls_send_app_done:
    clc
    ret
tls_send_app_failed:
    ret

tls_build_application_data_record:
    mov byte [tls_app_content_type], 0x17
    push ds
    pop es
    mov si, [tls_app_plain_ptr]
    mov di, tls_app_record_buffer
    add di, tls_record_header_len
    mov cx, [tls_app_len]
    rep movsb
    mov ax, tls_app_record_buffer
    add ax, tls_record_header_len
    mov [tls_app_data_ptr], ax
    call tls_build_client_nonce
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
    mov di, tls_app_record_buffer
    mov al, [tls_app_content_type]
    stosb
    mov ax, 0x0303
    stosw
    mov ax, [tls_app_len]
    add ax, tls_aead_tag_len
    call tls_write_be16
    mov di, [tls_app_data_ptr]
    add di, [tls_app_len]
    mov si, tls_finished_tag
    mov cx, tls_aead_tag_len
    rep movsb

    mov ax, [tls_app_len]
    add ax, tls_record_header_len + tls_aead_tag_len
    mov [tls_app_record_len], ax
    mov [tls_tx_len], ax
    ret

tls_receive_application_data:
    call tls_load_server_payload
    jc .failed
    call tls_ensure_tls_header_complete
    jc .failed
    mov si, [tls_current_payload_ptr]
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
    mov dx, ax
    sub dx, tls_aead_tag_len
    mov [tls_app_len], dx
    add ax, tls_record_header_len
    mov [tls_app_total_len], ax
    cmp ax, tls_stream_buffer_len
    ja .large_record
    call tls_ensure_current_tls_record_complete
    jc .failed
    mov ax, [tls_app_total_len]
    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
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

    call tls_build_server_nonce
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
    jnc .tag_ready
    mov byte [handoff_addr + handoff_net_status], 0xe4
    jmp .failed
.tag_ready:
    mov word [chacha_counter_low], 1
    mov word [chacha_counter_high], 0
    call tls_xor_app_data
    cmp byte [tls_app_content_type], 0x15
    jne .application_record
    cmp word [tls_rx_copy], 0x0001
    jne .failed
    mov byte [tls_key_schedule_ready], 0
    mov byte [api_stream_completed], 3
.application_record:
    call tls_preserve_buffered_payload
    call tls_increment_server_record_seq
    ret
.large_record:
    cmp byte [api_stream_text_seen], 0
    je .large_before_text
    xor ax, ax
    mov [tls_app_len], ax
    call tls_clear_buffered_payload
    mov byte [tls_key_schedule_ready], 0
    mov byte [api_stream_completed], 3
    ret
.large_before_text:
    jmp tls_receive_large_application_record
.failed:
    jmp tls_fail_error

tls_ensure_tls_header_complete:
    cmp word [tls_current_payload_len], tls_record_header_len
    jae .done
    call tls_copy_current_payload
    jc .failed
.receive_more:
    call ne_transmit_tcp_ack
    jc .failed
    call tcp_receive_payload
    jc .failed
    mov ax, [tls_current_payload_len]
    mov di, tls_rx_copy
    add di, ax
    mov cx, [tcp_rx_payload_len]
    add ax, cx
    cmp ax, tls_stream_buffer_len
    ja .failed
    push ds
    pop es
    mov si, [tcp_rx_payload_ptr]
    rep movsb
    mov [tls_current_payload_len], ax
    mov word [tls_current_payload_ptr], tls_rx_copy
    cmp ax, tls_record_header_len
    jb .receive_more
.done:
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], 0xe7
    stc
    ret

tls_receive_large_application_record:
    call tls_clear_buffered_payload

    mov ax, [tls_app_total_len]
    sub ax, tls_record_header_len
    mov [tls_stream_skip_remaining], ax

    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
    add si, tls_record_header_len
    sub cx, tls_record_header_len
.consume_current:
    cmp word [tls_stream_skip_remaining], 0
    je .record_done
    or cx, cx
    jnz .have_bytes
    call ne_transmit_tcp_ack
    jc .failed
    call tcp_receive_payload
    jc .failed
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]
.have_bytes:
    mov dx, cx
    mov ax, [tls_stream_skip_remaining]
    cmp dx, ax
    jbe .take_ready
    mov dx, ax
.take_ready:
    add si, dx
    sub cx, dx
    sub word [tls_stream_skip_remaining], dx
    jmp .consume_current
.record_done:
    mov [tls_buffered_payload_len], cx
    mov [tls_buffered_payload_ptr], si
    xor ax, ax
    mov [tls_app_len], ax
    call tls_preserve_buffered_payload
    call tls_increment_server_record_seq
    call ne_transmit_tcp_ack
    jc .failed
    ret
.failed:
    stc
    ret

tls_preserve_buffered_payload:
    mov cx, [tls_buffered_payload_len]
    jcxz .done
    mov ax, tls_rx_copy
    add ax, [tls_app_len]
    push ds
    pop es
    mov si, [tls_buffered_payload_ptr]
    mov di, ax
    rep movsb
    mov [tls_buffered_payload_ptr], ax
.done:
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
    mov byte [handoff_addr + handoff_net_status], 0xe8
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
    call tls_poly1305_process_cipher_bytes
    call poly1305_clear_block
    mov byte [poly_block], tls_aead_aad_len
    mov ax, [tls_app_len]
    mov [poly_block + 8], ax
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    call poly1305_emit_tag
    ret

tls_poly1305_process_cipher_bytes:
.cipher_block:
    or cx, cx
    jz .cipher_done
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
.cipher_done:
    ret

tls_build_client_app_aad:
    mov si, tls_client_record_seq
    jmp tls_build_app_aad_from_seq

tls_build_server_app_aad:
    mov si, tls_server_record_seq

tls_build_app_aad_from_seq:
    push es
    push ds
    pop es
    mov di, tls_aead_aad
    mov cx, tls_record_seq_len
    rep movsb
    mov al, [tls_app_content_type]
    stosb
    mov ax, 0x0303
    stosw
    mov ax, [tls_app_len]
    call tls_write_be16
    pop es
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
    jmp tls_compare_buffers
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
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_verify_data
    mov word [tls_prf_output_len], tls_finished_verify_len
    jmp tls_prf_sha256_expand

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
    clc
    ret

tls_build_client_nonce:
    mov si, tls_client_write_iv
    mov bx, tls_client_record_seq
    jmp tls_build_nonce_from_ptrs

tls_build_server_nonce:
    mov si, tls_server_write_iv
    mov bx, tls_server_record_seq

tls_build_nonce_from_ptrs:
    push es
    push ds
    pop es
    mov di, tls_client_nonce
    mov cx, tls_chacha_iv_len
    rep movsb
    mov si, bx
    mov di, tls_client_nonce + 4
    mov cx, tls_record_seq_len
.xor_seq:
    lodsb
    xor [di], al
    inc di
    loop .xor_seq
    pop es
    ret

tls_build_finished_aad:
    mov si, tls_client_record_seq
    jmp tls_build_finished_aad_from_seq

tls_build_server_finished_aad:
    mov si, tls_server_record_seq

tls_build_finished_aad_from_seq:
    push es
    push ds
    pop es
    mov di, tls_aead_aad
    mov cx, tls_record_seq_len
    rep movsb
    mov al, 0x16
    stosb
    mov ax, 0x0303
    stosw
    mov ax, tls_finished_plain_len
    call tls_write_be16
    pop es
    ret

tls_xor_finished_plaintext:
    mov si, tls_finished_plain
    mov di, tls_finished_cipher
    mov cx, tls_finished_plain_len
    jmp tls_xor_finished_bytes

tls_xor_finished_ciphertext:
    mov si, tls_finished_cipher
    mov di, tls_finished_plain
    mov cx, tls_finished_cipher_len

tls_xor_finished_bytes:
    push es
    push ds
    pop es
    mov bx, chacha_block
.next:
    lodsb
    xor al, [bx]
    stosb
    inc bx
    loop .next
    pop es
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

tls_increment_client_record_seq:
    push si
    mov si, tls_client_record_seq + tls_client_record_seq_len - 1
    jmp tls_increment_record_seq

tls_increment_server_record_seq:
    push si
    mov si, tls_server_record_seq + tls_server_record_seq_len - 1

tls_increment_record_seq:
    push ax
    push cx
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
    pop cx
    pop ax
    pop si
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
    jmp tls_finish_next_handshake_header
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
    cmp byte [bx + 3], tls_ec_public_uncompressed_len
    jne .failed
    mov dx, [tls_server_next_handshake_len_low]
    mov ax, tls_ec_public_uncompressed_len
    add ax, 8
    cmp ax, dx
    ja .failed
    cmp byte [bx + 4], 0x04
    jne .failed
    mov si, bx
    add si, 5
    mov di, tls_premaster_secret
    mov cx, tls_ec_coordinate_len
    rep movsb
    mov bx, [tls_next_handshake_body_ptr]
    add bx, tls_ec_public_uncompressed_len + 4
    mov ah, [bx + 2]
    mov al, [bx + 3]
    mov dx, ax
    mov ax, tls_ec_public_uncompressed_len
    add ax, 8
    add ax, dx
    cmp ax, [tls_server_next_handshake_len_low]
    jne .failed
    clc
    ret
.failed:
    stc
    ret

tls_finish_server_key_exchange:
    call tls_transcript_update_next_handshake
    jc .failed
    mov ax, [tls_server_next_total_len]
    call tls_save_payload_after_current_offset
    cmp word [tls_buffered_payload_len], 0
    jne .done
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    je .done
    call ne_transmit_tcp_ack
    jc .failed
.done:
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
    mov si, tls_client_ec_public_constant
    mov cx, tls_ec_public_uncompressed_len
    rep movsb
    clc
    ret

tls_write_be16:
    xchg al, ah
    stosw
    ret

tls_client_ec_public_constant db 0x04
                              db 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47
                              db 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2
                              db 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0
                              db 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
                              db 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b
                              db 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16
                              db 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce
                              db 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
tls_client_ec_public_constant_len equ $ - tls_client_ec_public_constant
%if tls_client_ec_public_constant_len != tls_ec_public_uncompressed_len
%error "TLS client public key constant length mismatch"
%endif
