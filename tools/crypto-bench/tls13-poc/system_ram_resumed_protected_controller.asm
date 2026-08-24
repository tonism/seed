; Exact no-0RTT resumed protected flight for the 16 KiB RAM-only route.
;
; The ServerHello controller left the peer at a zero receive window.  This
; image reopens it, accepts an optional compatibility CCS followed by exactly
; one 64-byte TLS record, authenticates the fixed empty EncryptedExtensions +
; Finished shape, sends client Finished and the credential-free HEAD, then
; closes the window again before slow FO/offline work.

bits 16
cpu 8086
org 0x0900

%ifndef SYSRAM_RESUME_OFFLINE_KEY
%error "resumed protected controller requires the offline continuation"
%endif

resident_load_phase          equ 0x10c4
res_wait_ticks               equ 0x11e5
res_tcp_ack                  equ 0x13a6
res_tcp_send                 equ 0x13bf
res_build_tcp_frame          equ 0x13e2
res_tcp_receive              equ 0x14ed
res_parse_tcp_payload        equ 0x1522
res_nic_vt_transmit          equ 0x15df
res_nic_vt_receive           equ 0x15e1
res_nic_vt_rx_fallback       equ 0x15e3
low_abort                    equ 0x0f60
ne_rx_sample_count           equ 0x06d5
ne_rx_read_limit             equ 0x06d7
tcp_remote_ack               equ 0x06f1
tcp_rx_payload_ptr           equ 0x0fe2
tcp_rx_payload_len           equ 0x0fe4
ne_tx_frame                  equ 0x0700
tcp_window_word              equ ne_tx_frame + 34 + 14
tcp_checksum_word            equ ne_tx_frame + 34 + 16

sym_entry_table              equ 0x1820
sym_verify_finish_entry      equ sym_entry_table + 8 * 2
sym_build_finish_entry       equ sym_entry_table + 9 * 2
sym_build_head_entry         equ sym_entry_table + 11 * 2
sym_derive_client_app_entry  equ sym_entry_table + 16 * 2
sym_derive_server_app_entry  equ sym_entry_table + 17 * 2
sym_auth_resumed_entry       equ sym_entry_table + 18 * 2
sym_received_finish          equ 0x38f0
sym_io                       equ 0x39a0
resumed_tail_len             equ 0x0f16
resumed_tail_buffer          equ 0x0f18
resumed_tail_capacity        equ 70

resumed_record_wire_len      equ 64
resumed_record_body_len      equ 59
resumed_plain_len            equ 43

sysram_resumed_protected:
    cld
    mov word [ne_rx_read_limit], 438
    mov cx, 256
.flush:
    push cx
    call word [res_nic_vt_receive]
    pop cx
    jc resumed_failed
    cmp word [ne_rx_sample_count], 0
    je .window_update
    loop .flush
    jmp resumed_failed
.window_update:
    call res_tcp_ack
    jc resumed_failed
    mov word [resumed_header_pos], 0
    mov word [resumed_state], 0
    mov word [resumed_record_pos], 0
    mov byte [resumed_seen_ccs], 0

    ; Consume any prefix that arrived in the same TCP segment as ServerHello
    ; before asking the NIC for more.  HELLO already advanced the ACK across
    ; these bytes, so this is a pure conventional-RAM handoff.  A partial
    ; prefix naturally falls through to the ordinary receiver for its suffix.
    mov cx, [resumed_tail_len]
    cmp cx, resumed_tail_capacity
    ja resumed_failed
    or cx, cx
    jz .receive
    mov si, resumed_tail_buffer
    jmp .consume

.receive:
    call word [res_nic_vt_rx_fallback]
    jnc .received
    call res_tcp_receive
    jc resumed_failed
.received:
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]

.consume:
    or cx, cx
    jz .ack_more
    cmp byte [resumed_state], 0
    jne .body
    xor bx, bx
    mov bl, [resumed_header_pos]
    mov al, [si]
    mov [resumed_header + bx], al
    inc si
    dec cx
    inc byte [resumed_header_pos]
    cmp byte [resumed_header_pos], 5
    jne .consume
    ; resumed_start_record copies the authenticated-record header into sym_io
    ; and therefore uses both SI and CX.  Preserve the current ingress cursor
    ; so a coalesced header + body is consumed exactly once.
    push si
    push cx
    call resumed_start_record
    pop cx
    pop si
    jc resumed_failed
    jmp short .consume

.body:
    cmp byte [resumed_state], 1
    jne .encrypted
    cmp byte [si], 1
    jne resumed_failed
    inc si
    dec cx
    dec word [resumed_remaining]
    jnz resumed_failed
    mov word [resumed_header_pos], 0
    mov byte [resumed_state], 0
    jmp .consume

.encrypted:
    mov ax, [resumed_remaining]
    or ax, ax
    jz .record_complete
    mov dx, cx
    cmp cx, ax
    jbe .copy_count
    mov cx, ax
.copy_count:
    push es
    push ds
    pop es
    mov di, sym_io
    add di, [resumed_record_pos]
    mov ax, cx
    rep movsb
    pop es
    add [resumed_record_pos], ax
    sub [resumed_remaining], ax
    sub dx, ax
    mov cx, dx
    cmp word [resumed_remaining], 0
    jne .consume
.record_complete:
    or cx, cx
    jnz resumed_failed
    cmp word [resumed_record_pos], resumed_record_wire_len
    jne resumed_failed
    push es
    push ds
    pop es
    xor ax, ax
    mov di, resumed_tail_len
    mov cx, (0x0f60 - resumed_tail_len) / 2
    rep stosw
    pop es
    call res_tcp_ack
    jc resumed_failed
    jmp resumed_process_record

.ack_more:
    call res_tcp_ack
    jc resumed_failed
    jmp .receive

resumed_start_record:
    cmp word [resumed_header + 1], 0x0303
    jne .failed
    cmp byte [resumed_header], 0x14
    jne .encrypted
    cmp byte [resumed_seen_ccs], 0
    jne .failed
    cmp word [resumed_header + 3], 0x0100
    jne .failed
    mov byte [resumed_seen_ccs], 1
    mov byte [resumed_state], 1
    mov word [resumed_remaining], 1
    clc
    ret
.encrypted:
    cmp byte [resumed_header], 0x17
    jne .failed
    cmp word [resumed_header + 3], 0x3b00
    jne .failed
    push es
    push ds
    pop es
    mov si, resumed_header
    mov di, sym_io
    mov cx, 5
    rep movsb
    pop es
    mov word [resumed_record_pos], 5
    mov word [resumed_remaining], resumed_record_body_len
    mov byte [resumed_state], 2
    clc
    ret
.failed:
    stc
    ret

resumed_process_record:
    call word [sym_auth_resumed_entry]
    jc resumed_failed
    cmp ax, 2
    jne resumed_failed
resumed_record_authenticated:
    push ds
    pop es
    mov si, sym_io + 5
    mov di, resumed_plain_prefix
    mov cx, resumed_plain_prefix_end - resumed_plain_prefix
    repe cmpsb
    jne resumed_failed
    cmp byte [sym_io + 5 + resumed_plain_len - 1], 0x16
    jne resumed_failed
resumed_structure_valid:
    mov si, sym_io + 15
    mov di, sym_received_finish
    mov cx, 16
    rep movsw
    call word [sym_verify_finish_entry]
    jc resumed_failed
resumed_finished_verified:
    call word [sym_build_finish_entry]
resumed_finished_build_returned:
    jc resumed_failed
    cmp ax, 58
    jne resumed_failed
resumed_finished_built:
    call reject_queued_tail
    jc resumed_failed
resumed_queue_clean:
    mov si, sym_io
    mov cx, 58
    call res_tcp_send
    jc resumed_failed
resumed_finished_sent:
    call word [sym_derive_client_app_entry]
    jc resumed_failed
    call word [sym_build_head_entry]
    jc resumed_failed
    cmp ax, 72
    jne resumed_failed
    mov si, sym_io
    mov cx, 72
    call res_tcp_send
    jc resumed_failed
    mov cx, 1
    call res_wait_ticks
    call resumed_zero_window
    jc resumed_failed
    call word [sym_derive_server_app_entry]
    jc resumed_failed

    ; The deadline is closed.  A retry-capable low continuation performs the
    ; cold controller read without executing from its overwritten 0x0900 slot.
    push ds
    pop es
    mov si, resumed_offline_load_source
    mov di, 0x0700
    mov cx, resumed_offline_load_end - resumed_offline_load_source
    rep movsb
    jmp 0x0700

resumed_offline_load_source:
    mov bp, 3
.load:
    mov ax, SYSRAM_RESUME_OFFLINE_KEY
    mov bx, 0x0900
    mov dx, resident_load_phase
    call dx
    jnc .loaded
    dec bp
    jz .failed
    xor ax, ax
    mov dl, [0x060a]
    int 0x13
    jmp short .load
.failed:
    mov dx, low_abort
    jmp dx
.loaded:
    mov dx, 0x0900
    jmp dx
resumed_offline_load_end:

reject_queued_tail:
    mov bp, 256
.poll:
    push bp
    call word [res_nic_vt_receive]
    pop bp
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .clean
    push bp
    call res_parse_tcp_payload
    pop bp
    jnc .failed
    push bp
    call word [res_nic_vt_rx_fallback]
    pop bp
    jnc .failed
    dec bp
    jnz .poll
.failed:
    stc
    ret
.clean:
    clc
    ret

resumed_zero_window:
    mov al, 0x10
    xor cx, cx
    mov si, tcp_remote_ack
    call res_build_tcp_frame
    mov word [tcp_window_word], 0
    mov ax, [tcp_checksum_word]
    add ax, 1
    adc ax, 0
    mov [tcp_checksum_word], ax
    mov si, ne_tx_frame
    call word [res_nic_vt_transmit]
    ret

resumed_failed:
    jmp low_abort

resumed_plain_prefix:
    db 0x08,0x00,0x00,0x02,0x00,0x00
    db 0x14,0x00,0x00,0x20
resumed_plain_prefix_end:
resumed_header       times 5 db 0
resumed_header_pos   db 0
resumed_state        db 0
resumed_seen_ccs     db 0
resumed_remaining    dw 0
resumed_record_pos   dw 0

sysram_resumed_protected_end:

%if (sysram_resumed_protected_end - $$) > (2 * 512)
%error "resumed protected controller exceeds two sectors"
%endif
%if (resumed_offline_load_end - resumed_offline_load_source) > 0x01b8
%error "resumed offline loader exceeds dead RX/ciphertext prefix"
%endif
