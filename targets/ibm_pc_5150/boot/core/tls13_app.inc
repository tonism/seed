; PRIVATE RECEIVER COMPOSITION ONLY: no H2 scheduler/ALPN/loader yet.
; TLS 1.3 application-record layer for the committed Seed channel.
;
; The pre-commit handshake/proof is a cold phase chain.  Once that chain has
; atomically published the application keys, the normal DPI/chat/tool loop
; reloads this compact K image.  Only the fixed high-crypto key/IV/sequence
; band survives request/config phases; no handshake secret or tentative
; plaintext is part of the application ABI.
;
; Narrow product profile:
;   TLS 1.3 / TLS_CHACHA20_POLY1305_SHA256
;   outer type application_data, legacy_record_version 0x0303
;   application_data plus bounded post-handshake NewSessionTicket records
;
; The OpenAI HTTP/SSE path is textual.  Receive ciphertext is MACed into the
; established small streaming scratch and staged in an authenticated-record
; spool.  Only after the tag passes is TLSInnerPlaintext scanned backward over
; authenticated zero padding, its inner content type checked, and the content
; decrypted back through either the product parser or the strict disposable
; NewSessionTicket drain.  Thus a forged record cannot speculatively paint
; text, mutate the conversation, dispatch a tool, or steer post-handshake
; state.
;
; Every adapter uses conventional RAM for the authenticated-record spool.
; The small-RAM route retains its 2-KiB ceiling. On the conforming 286 tier,
; the already arena-excluded, retired handshake reservation holds a complete
; TLSCiphertext inner plaintext. A peer need not negotiate record_size_limit;
; accepting the larger record still requires storage, MAC and type validation.
; Video and adapter RAM are never selected.

tls13_auth_spool_offset equ 0x2e00
tls13_auth_spool_len equ 0x800
tls13_auth_spool_max_inner equ tls13_auth_spool_len
tls13_auth_replay_chunk equ 576
tls13_nst_record_max equ tls13_auth_replay_chunk

%if tls_payload_buffer_len > tls_pre_response_tail_len
%error "TLS 1.3 buffered TCP tail exceeds its retired handshake-scratch escrow"
%endif

tls_fail_error:
    stc
    ret

; Preserve the existing 3c501 first-response receive quirk.  This is transport
; setup, not a TLS-version property, and remains behind the selected driver.
tls_prepare_3c501_receive:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .done
    xor al, al
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + el1_rcvptr]
    out dx, al
    lea dx, [bx + el1_rx_cmd]
    mov al, el1_rx_cmd_bcast_good - 0x20
    out dx, al
.done:
    ret

; ---------------------------------------------------------------------------
; TCP payload cursor
; ---------------------------------------------------------------------------

tls_load_server_payload:
    mov cx, [tls_buffered_payload_len]
    or cx, cx
    jz .receive
    mov si, [tls_buffered_payload_ptr]
    jmp .loaded
.receive:
    call [nic_vt_rx_fallback]
    jnc .loaded_from_tcp
    ; Retire short control records at the TCP layer before waiting again.
    ; Otherwise several records can exhaust our advertised receive window
    ; without triggering the within-record acknowledgement path.
    call ne_transmit_tcp_ack
    jc .done
    call tcp_receive_payload
    jc .done
.loaded_from_tcp:
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]
.loaded:
    mov [tls_current_payload_ptr], si
    mov [tls_current_payload_len], cx
    clc
.done:
    ret

tls_copy_current_payload:
    mov cx, [tls_current_payload_len]
    cmp cx, tls_stream_buffer_len
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

tls_clear_buffered_payload:
    mov word [tls_buffered_payload_ptr], 0
    mov word [tls_buffered_payload_len], 0
    clc
    ret

tls_ensure_tls_header_complete:
    cmp word [tls_current_payload_len], tls_record_header_len
    jae .done
    call tls_copy_current_payload
    jc .failed
.receive_more:
%ifdef TLS13_APP_ORACLE_CHECK
    call [nic_vt_rx_fallback]
    jnc .append_more
%endif
    call ne_transmit_tcp_ack
    jc .failed
    call tcp_receive_payload
    jc .failed
.append_more:
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
    stc
    ret

; ---------------------------------------------------------------------------
; Seal one unpadded TLS 1.3 application_data record
; ---------------------------------------------------------------------------

tls_send_application_data_current_seq:
    call tls_build_application_data_record
    jc tls_send_app_failed
tls_send_prebuilt_application_data_current_seq:
    mov si, tls_app_record_buffer
    mov cx, [tls_app_record_len]
    call tcp_send_payload
    jc tls_send_app_failed
    call tls_increment_client_record_seq
    ret
tls_send_app_failed:
    stc
    ret

tls_build_application_data_record:
    mov ax, [tls_app_len]
    cmp ax, 436
    ja .failed
    add ax, tls13_inner_type_len        ; content || inner_type
    mov [tls_app_chunk_len], ax
    add ax, tls_aead_tag_len
    mov [tls_app_total_len], ax         ; TLSCiphertext.length
    add ax, tls_record_header_len
    mov [tls_app_record_len], ax
    mov [tls_tx_len], ax

    ; The five-byte TLSCiphertext header is also the complete TLS 1.3 AAD.
    push ds
    pop es
    mov di, tls_app_record_buffer
    mov al, 0x17
    stosb
    mov ax, 0x0303
    stosw
    mov ax, [tls_app_total_len]
    call tls_write_be16
    mov si, tls_app_record_buffer
    mov di, tls_aead_aad
    mov cx, tls_record_header_len
    rep movsb

    mov si, [tls_app_plain_ptr]
    mov di, tls_app_record_buffer + tls_record_header_len
    mov cx, [tls_app_len]
    rep movsb
    mov al, 0x17                      ; TLSInnerPlaintext.type
    stosb
    mov word [tls_app_data_ptr], tls_app_record_buffer + tls_record_header_len

    call tls_build_client_nonce
    mov word [chacha_key_ptr], tls_client_write_key
    mov word [chacha_nonce_ptr], tls_client_nonce
    mov word [chacha_counter_low], 0
    mov word [chacha_counter_high], 0
    call chacha20_block
    call poly1305_load_key
    mov word [chacha_counter_low], 1
    mov word [chacha_counter_high], 0
    mov si, [tls_app_data_ptr]
    mov cx, [tls_app_chunk_len]
    call tls_xor_app_data
    call tls_poly1305_mac_app

    push ds
    pop es
    mov di, tls_app_record_buffer + tls_record_header_len
    add di, [tls_app_chunk_len]
    mov si, tls_finished_tag
    mov cx, tls_aead_tag_len
    rep movsb
    clc
    ret
.failed:
    stc
    ret

; ---------------------------------------------------------------------------
; Open one TLS 1.3 application_data record
; ---------------------------------------------------------------------------

tls_receive_application_data:
    call tls_server_record_seq_available
    jc .failed
    call tls_load_server_payload
    jc .failed
    call tls_ensure_tls_header_complete
    jc .failed
    mov si, [tls_current_payload_ptr]
    cmp byte [si], 0x17
    jne .failed
    cmp word [si + 1], 0x0303
    jne .failed
    mov ah, [si + 3]
    mov al, [si + 4]
    cmp ax, tls_aead_tag_len + 1
    jb .failed
    mov dx, ax
    sub dx, tls_aead_tag_len
    ; Full TLS 1.3 ciphertext bound, independent of body/control retention.
    cmp dx, 16624
    ja .failed
.limit_ready:
    mov [tls_app_len], dx              ; encrypted inner plaintext bytes
    add ax, tls_record_header_len
    mov [tls_app_total_len], ax
    jmp tls_receive_large_application_record
.failed:
    jmp tls_h2_receive_failed

tls_receive_large_application_record:
    call tls_clear_buffered_payload
    ; The NIC frame aliases primitive work on some 16-KiB layouts.  Preserve
    ; the first payload before deriving the record one-time key.
    call tls_copy_current_payload
    jc .failed
    mov si, tls_rx_copy
    mov di, tls_aead_aad
    mov cx, tls_record_header_len
    rep movsb
    call tls_build_server_nonce
    mov word [chacha_key_ptr], tls_server_write_key
    mov word [chacha_nonce_ptr], tls_client_nonce
    mov word [chacha_counter_low], 0
    mov word [chacha_counter_high], 0
    call chacha20_block
    call poly1305_load_key
    call tls_poly1305_app_init
    call tls_poly1305_rx_save
    mov ax, [tls_app_len]
    mov [tls_stream_skip_remaining], ax
    mov word [tls_app_record_len], tls_aead_tag_len
    mov word [chacha_counter_low], 1
    mov word [chacha_counter_high], 0
    mov byte [tls_large_chacha_offset], chacha_block_len
    mov byte [tls_app_content_type], 0
    call h2_rx_begin_record

    mov si, [tls_current_payload_ptr]
    mov cx, [tls_current_payload_len]
    add si, tls_record_header_len
    sub cx, tls_record_header_len
    call .copy_current_to_rx
.consume_current:
    or cx, cx
    jnz .have_bytes
    cmp word [tls_stream_skip_remaining], 0
    jne .receive_more
    cmp word [tls_app_record_len], 0
    je .record_done
.receive_more:
    call [nic_vt_rx_fallback]
    jnc .received_payload
    call ne_transmit_tcp_ack
    jc .failed
    call tcp_receive_payload
    jc .failed
.received_payload:
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]
    call .copy_current_to_rx
.have_bytes:
    cmp word [tls_stream_skip_remaining], 0
    jne .consume_cipher
    cmp word [tls_app_record_len], 0
    jne .consume_tag
    jmp .record_done

.consume_cipher:
    mov dx, cx
    mov ax, [tls_stream_skip_remaining]
    cmp dx, ax
    jbe .cipher_take_ready
    mov dx, ax
.cipher_take_ready:
    push cx
    push dx
    mov cx, dx
    call tls_poly1305_rx_restore
    push si
    call tls_poly1305_app_update        ; MAC ciphertext before in-place open
    pop si
    call tls_poly1305_rx_save
    pop dx
    mov cx, dx
    call tls_h2_collect_cipher
    pop cx
    jc .failed

    add si, dx
    sub cx, dx
    sub word [tls_stream_skip_remaining], dx
    jmp .consume_current

.consume_tag:
    mov dx, cx
    mov ax, [tls_app_record_len]
    cmp dx, ax
    jbe .tag_take_ready
    mov dx, ax
.tag_take_ready:
    push si
    push di
    push cx
    push es
    push ds
    pop es
    mov di, tls_received_tag
    mov cx, tls_aead_tag_len
    sub cx, [tls_app_record_len]
    add di, cx
    mov cx, dx
    rep movsb
    pop es
    pop cx
    pop di
    pop si
    add si, dx
    sub cx, dx
    sub word [tls_app_record_len], dx
    jmp .consume_current

.record_done:
    mov [tls_buffered_payload_len], cx
    mov [tls_buffered_payload_ptr], si
    call tls_poly1305_rx_restore
    call tls_poly1305_app_final
    mov si, tls_finished_tag
    mov di, tls_received_tag
    mov cx, tls_aead_tag_len
    call tls_compare_buffers
    jc .failed
    ; No plaintext-dependent verdict or protocol publication precedes this
    ; complete tag comparison. The collector's last-nonzero snapshot excludes
    ; the authenticated inner type and zero padding from HTTP/2 state.
tls_h2_tag_verified equ $
    cmp word [h2_rx_last_position], 16384
    ja .failed
    mov al, [h2_rx_last_value]
    mov [tls_app_content_type], al
    cmp al, 0x17
    jne .tls_control
    mov al, 1
    call h2_rx_finish_record
    jc .failed
    ; Preserve the DATA/control handoff while erasing the raw TLS-control
    ; prefix and receive MAC. Keep a following encrypted record in RX, never
    ; in the TX arena needed for HTTP/2 replies.
    push si
    push cx
    push di
    push bp
    push dx
    call tls_h2_clear_crypto_prefix
    call tls_h2_preserve_tail
    call tls_increment_server_record_seq
    pop dx
    pop bp
    pop di
    pop cx
    pop si
    ret
.tls_control:
    cmp al, 0x16
    je .ticket
    cmp al, 0x15
    jne .failed
    cmp word [h2_rx_last_position], 2
    jne .failed
    mov al, [tls_app_record_buffer]
    cmp al, 1
    je .alert_ready
    cmp al, 2
    jne .failed
.alert_ready:
    mov al, [tls_app_record_buffer+1]
    mov [handoff_addr+handoff_net_status], al
    mov byte [handoff_addr+handoff_net_error], net_error_tls
    jmp .failed
.ticket:
    mov cx, [h2_rx_last_position]
    cmp cx, tls13_nst_record_max
    ja .failed
    mov si, tls_app_record_buffer
    push cx
    call tls_validate_post_handshake_nst
    pop bp
    jc .failed
    ; The entire tag and bounded NST record have passed. Stage its content
    ; in the dead per-record journals for the cold-only ticket derivation.
    ; Ordinary application callers must still drain/retire this handoff.
    call h2_rx_clear_record
    cmp byte [0x062e+65], 1
    je .ticket_retire                ; normal owner must inspect inner type
    mov si, tls_app_record_buffer
    mov di, h2_rx_journal
    mov cx, bp
    rep movsb
.ticket_retire:
    push bp
    call tls_h2_clear_crypto_prefix
    call tls_h2_preserve_tail
    call tls_increment_server_record_seq
    pop cx
    mov si, h2_rx_journal
    ret

.copy_current_to_rx:
    mov dx, cx
    push ds
    pop es
    mov di, tls_rx_copy
    rep movsb
    mov si, tls_rx_copy
    mov cx, dx
    ret
.failed:
    jmp tls_h2_receive_failed

tls_h2_receive_failed:
    call h2_rx_clear_record
    call tls_h2_clear_crypto_prefix
    call tls_clear_buffered_payload
    mov di, tls_rx_copy
    mov cx, tls_payload_buffer_len / 2
    xor ax, ax
    rep stosw
    stc
    ret

; MAC has already consumed this ciphertext fragment. Decrypt only in private
; scratch and run the fixed-work collector; all resulting effects stay private.
; SI/CX/DX remain caller-owned. BP is a pointer into the public-length fragment.
tls_h2_collect_cipher:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    call tls_xor_large_app_chunk
    mov bp, si
.byte:
    jcxz .done
    push cx
    mov al, [ds:bp]
    ; Retain the same bounded prefix for EVERY record. This branch depends
    ; only on the public byte position, never on unauthenticated plaintext.
    mov bx, [h2_rx_position]
    cmp bx, tls13_nst_record_max+1
    jae .prefix_done
    mov [tls_app_record_buffer+bx], al
.prefix_done:
    call h2_rx_feed_byte
    inc bp
    pop cx
    loop .byte
.done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    clc
    ret

tls_h2_clear_crypto_prefix:
    xor ax, ax
    mov di, ne_tx_frame
    mov cx, (agent_response_phase_load_addr-ne_tx_frame)/2
    rep stosw                       ; erase retired key/keystream/MAC work
    mov di, poly_rx_save
    mov cx, 65
    rep stosb
    mov di, tls_app_record_buffer
    mov cx, tls13_nst_record_max+1
    rep stosb
    ret

tls_h2_preserve_tail:
    mov si, [tls_buffered_payload_ptr]
    mov cx, [tls_buffered_payload_len]
    mov di, tls_rx_copy
    rep movsb
    mov word [tls_buffered_payload_ptr], tls_rx_copy
    ; Only the still-encrypted following tail survives the successful receive.
    mov cx, tls_rx_copy+tls_payload_buffer_len
    sub cx, di
    xor ax, ax
    rep stosb
    ret

%include "core/h2_retention.inc"

; Validate and discard one authenticated post-handshake record containing one
; or more complete NewSessionTicket messages.  Seed has already promoted the
; ticket used by this final connection, so accepting replacement resumption
; authority would enlarge the mutable trust surface for no product benefit.
; The bounded drain nevertheless checks the complete RFC 8446 vector shape,
; the product lifetime/nonce/identity limits, and every extension boundary.
; Unknown extensions are structurally drained; early_data, when present, must
; carry its uint32 value.  A fragmented or non-NST handshake fails closed.
tls_validate_post_handshake_nst:
    push bp
    push di
.message:
    cmp cx, 19                         ; header + smallest bounded NST body
    jb .bad
    cmp byte [si], 4                   ; NewSessionTicket
    jne .bad
    cmp byte [si + 1], 0               ; bounded 16-bit handshake length
    jne .bad
    mov dx, [si + 2]
    xchg dl, dh
    cmp dx, 15                         ; nonce and ticket are both nonempty
    jb .bad
    add dx, 4
    jc .bad
    cmp dx, cx
    ja .bad
    sub cx, dx
    push cx                            ; bytes after this complete message
    mov bp, si
    add bp, dx                         ; exact message end

    ; ticket_lifetime = 1..604800 seconds (0x0009:0x3a80).
    mov ax, [si + 4]
    xchg al, ah
    mov bx, [si + 6]
    xchg bl, bh
    mov dx, ax
    or dx, bx
    jz .bad_pop
    cmp ax, 9
    ja .bad_pop
    jb .lifetime_ready
    cmp bx, 0x3a80
    ja .bad_pop
.lifetime_ready:
    xor dx, dx
    mov dl, [si + 12]
    or dx, dx
    jz .bad_pop
    cmp dx, 32
    ja .bad_pop
    add si, 13
    mov ax, bp
    sub ax, si
    cmp ax, dx
    jb .bad_pop
    add si, dx

    mov ax, bp
    sub ax, si
    cmp ax, 2
    jb .bad_pop
    mov dx, [si]
    xchg dl, dh
    or dx, dx
    jz .bad_pop
    cmp dx, 192
    ja .bad_pop
    add si, 2
    mov ax, bp
    sub ax, si
    cmp ax, dx
    jb .bad_pop
    add si, dx

    mov ax, bp
    sub ax, si
    cmp ax, 2
    jb .bad_pop
    mov dx, [si]
    xchg dl, dh
    add si, 2
    mov ax, bp
    sub ax, si
    cmp dx, ax
    jne .bad_pop
    mov di, si                       ; first extension in this message
.extension:
    or dx, dx
    jz .message_done
    cmp dx, 4
    jb .bad_pop
    mov ax, [si]
    push dx
    mov bx, si
    mov si, di
.duplicates:
    cmp si, bx
    je .unique
    cmp ax, [si]
    je .duplicate
    mov dx, [si + 2]
    xchg dl, dh
    add si, 4
    add si, dx                       ; earlier entries are already bounded
    jmp short .duplicates
.duplicate:
    pop dx
    jmp .bad_pop
.unique:
    pop dx
    mov bx, [si + 2]
    xchg bl, bh
    add si, 4
    sub dx, 4
    cmp bx, dx
    ja .bad_pop
    cmp ax, 0x2a00                    ; early_data
    jne .extension_ready
    cmp bx, 4
    jne .bad_pop
.extension_ready:
    add si, bx
    sub dx, bx
    jmp short .extension
.message_done:
    mov si, bp
    pop cx
    or cx, cx
    jnz .message
    pop di
    pop bp
    clc
    ret
.bad_pop:
    pop cx
.bad:
    pop di
    pop bp
    stc
    ret

tls_server_record_seq_available:
    push ax
    push cx
    push si
    mov al, 0xff
    mov si, tls_server_record_seq
    mov cx, tls_server_record_seq_len
.next:
    and al, [si]
    inc si
    loop .next
    add al, 1                       ; carry iff every sequence byte was ff
    pop si
    pop cx
    pop ax
    ret

tls_xor_app_data:
    ; Sending starts a fresh keystream block, then shares the exact bounded
    ; XOR iterator used for streamed input. Preserve the old sender ABI.
    push cx
    push dx
    push si
    mov byte [tls_large_chacha_offset], chacha_block_len
    mov si, [tls_app_data_ptr]
    mov cx, [tls_app_chunk_len]
    call tls_xor_large_app_chunk
    pop si
    pop dx
    pop cx
    ret

tls_xor_large_app_chunk:
    push ax
    push bx
    push cx
    push si
    mov bl, [tls_large_chacha_offset]
    cmp bl, chacha_block_len
    jae .next_byte
    call chacha20_block
.next_byte:
    or cx, cx
    jz .done
    mov bl, [tls_large_chacha_offset]
    cmp bl, chacha_block_len
    jb .block_ready
    call chacha20_block
    xor bl, bl
.block_ready:
    xor bh, bh
    mov al, [si]
    xor al, [chacha_block + bx]
    mov [si], al
    inc si
    inc bl
    mov [tls_large_chacha_offset], bl
    dec cx
    cmp bl, chacha_block_len
    jne .next_byte
    inc word [chacha_counter_low]
    jnz .next_byte
    inc word [chacha_counter_high]
    jmp .next_byte
.done:
    pop si
    pop cx
    pop bx
    pop ax
    ret

tls_poly1305_mac_app:
    call tls_poly1305_app_init
    mov si, [tls_app_data_ptr]
    mov cx, [tls_app_len]
    add cx, tls13_inner_type_len
    call tls_poly1305_app_update
    jmp tls_poly1305_app_final

tls_poly1305_app_init:
    call poly1305_clear_acc
    call poly1305_clear_block
    push ds
    pop es
    mov si, tls_aead_aad
    mov di, poly_block
    mov cx, tls13_aead_aad_len
    rep movsb
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    call poly1305_clear_block
    mov byte [tls_poly_app_fill], 0
    mov word [tls_poly_app_cipher_len], 0
    ret

tls_poly1305_app_update:
    or cx, cx
    jz .done
    add [tls_poly_app_cipher_len], cx
.byte:
    mov bl, [tls_poly_app_fill]
    xor bh, bh
    mov al, [si]
    mov [poly_block + bx], al
    inc si
    inc bx
    cmp bl, 16
    jb .keep
    push cx
    push si
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    call poly1305_clear_block
    pop si
    pop cx
    xor bx, bx
.keep:
    mov [tls_poly_app_fill], bl
    dec cx
    jnz .byte
.done:
    ret

tls_poly1305_app_final:
    cmp byte [tls_poly_app_fill], 0
    je .lengths
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
.lengths:
    call poly1305_clear_block
    mov byte [poly_block], tls13_aead_aad_len
    mov ax, [tls_poly_app_cipher_len]
    mov [poly_block + 8], ax
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    call poly1305_emit_tag
    ret

tls_poly1305_rx_save:
    push si
    push di
    push cx
    push es
    push ds
    pop es
    mov si, poly_acc
    mov di, poly_rx_save
    mov cx, poly1305_acc_len + 16
    rep movsb
    mov si, poly_r
    mov di, poly_rx_otk
    mov cx, poly1305_r_len + poly1305_s_len
    rep movsb
    pop es
    pop cx
    pop di
    pop si
    ret

tls_poly1305_rx_restore:
    push si
    push di
    push cx
    push es
    push ds
    pop es
    mov si, poly_rx_save
    mov di, poly_acc
    mov cx, poly1305_acc_len + 16
    rep movsb
    mov si, poly_rx_otk
    mov di, poly_r
    mov cx, poly1305_r_len + poly1305_s_len
    rep movsb
    pop es
    pop cx
    pop di
    pop si
    ret

; ---------------------------------------------------------------------------
; Fixed record state helpers
; ---------------------------------------------------------------------------

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

tls_increment_client_record_seq:
    mov si, tls_client_record_seq + tls_client_record_seq_len - 1
    jmp tls_increment_record_seq

tls_increment_server_record_seq:
    mov si, tls_server_record_seq + tls_server_record_seq_len - 1

tls_increment_record_seq:
    push ax
    push cx
    mov cx, tls_record_seq_len
    stc
.next:
    mov al, [si]
    adc al, 0
    mov [si], al
    jnc .ok
    dec si
    loop .next
    pop cx
    pop ax
    stc                                 ; TLS 1.3 sequence exhaustion
    ret
.ok:
    pop cx
    pop ax
    clc
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
    neg ah                          ; carry iff any compared byte differed
    pop di
    pop si
    pop cx
    pop ax
    ret

tls_write_be16:
    xchg al, ah
    stosw
    ret

tls13_app_code_end:
%if (core_load_addr + (tls13_app_code_end - $$)) > tls13_auth_spool_offset
%error "TLS 1.3 application code overlaps the authenticated-record spool"
%endif

%ifdef TLS13_APP_ORACLE_CHECK
; Compile-check-only transport/parser probes used by tools/check-tls13-app.py.
; The shipping image has neither this state nor these branches.
tls13_test_stream_ptr dw 0
tls13_test_stream_remaining dw 0
tls13_test_stream_chunk dw 0
tls13_test_publish_ptr dw 0
tls13_test_publish_len dw 0
tls13_test_publish_calls dw 0

tls13_test_rx_fallback:
    mov cx, [tls13_test_stream_remaining]
    jcxz .empty
    mov ax, [tls13_test_stream_chunk]
    cmp cx, ax
    jbe .count_ready
    mov cx, ax
.count_ready:
    mov si, [tls13_test_stream_ptr]
    mov [tcp_rx_payload_ptr], si
    mov [tcp_rx_payload_len], cx
    add [tls13_test_stream_ptr], cx
    sub [tls13_test_stream_remaining], cx
    clc
    ret
.empty:
    stc
    ret

tls13_test_publish:
    push ax
    push cx
    push si
    push di
    push es
    mov si, [tls_app_data_ptr]
    mov cx, [tls_app_len]
    mov di, [tls13_test_publish_ptr]
    add di, [tls13_test_publish_len]
    push ds
    pop es
    rep movsb
    mov ax, [tls_app_len]
    add [tls13_test_publish_len], ax
    inc word [tls13_test_publish_calls]
    pop es
    pop di
    pop si
    pop cx
    pop ax
    clc
    ret
%endif
