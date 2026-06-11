%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%define PHASE_LOAD_ADDR low_scratch_start
%define PHASE_LOAD_ADDR_DEFAULTED
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

%if dns_rx_read_len > net_setup_frame_scratch_len
%error "tcp connect DNS scratch too small"
%endif
%if tcp_rx_read_len > net_setup_frame_scratch_len
%error "tcp connect TCP scratch too small"
%endif
%if dns_tx_frame_max_len > net_setup_frame_scratch_len
%error "tcp connect DNS transmit scratch too small"
%endif
%if arp_tx_frame_len > net_setup_frame_scratch_len
%error "tcp connect ARP scratch too small"
%endif

tcp_connect_phase:
    ; ESC-panic NIC safety (Build 11): a Ctrl+ESC longjmp can fire mid-NIC-access during the receive,
    ; leaving the dp8390 command register on page 1 or a remote-DMA stalled; the reconnect then reuses
    ; that dirty state and the SYN never reaches the wire (pcap-confirmed: zero SYNs leave after a
    ; panic). ne_cmd_start_nodma (0x22 = page 0 + abort remote DMA + running) forces a clean state
    ; before the flush/SYN below. dp8390 only -- the 3c501 has no DMA/page and re-inits its CR per TX.
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    je .nic_clean
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + ne_cr]
    mov al, ne_cmd_start_nodma
    out dx, al
.nic_clean:
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je tcp_reopen_cached_target
    call tcp_connect_target
    ret

tcp_reopen_cached_target:
    call ne_flush_receive_frames
    call ne_tcp_syn_handshake
    jc .failed
    phase_call_res ne_transmit_tcp_ack
    jc .done
    cmp byte [handoff_addr + handoff_net_status], net_status_tcp_connected
    jne .failed
    call ne_flush_receive_frames
    clc
    ret
.failed:
    stc
.done:
    ret

tcp_connect_target:
    call tcp_resolve_target_name
    jc .done
    call tcp_open_resolved_target
.done:
    ret

tcp_resolve_target_name:
    call ne_resolve_dns_arp
    jc .done
    cmp byte [handoff_addr + handoff_net_status], net_status_arp_resolved
    jne .failed
    call ne_flush_receive_frames
    call ne_transmit_dns_query
    jc .done
    call ne_wait_for_dns_response
    cmp byte [handoff_addr + handoff_net_status], net_status_dns_response_received
    je .resolved
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .failed
    call ne_flush_receive_frames
    call ne_transmit_dns_query
    jc .done
    call ne_wait_for_dns_response
    cmp byte [handoff_addr + handoff_net_status], net_status_dns_response_received
    jne .failed
.resolved:
    clc
    ret
.failed:
    stc
.done:
    ret

ne_flush_receive_frames:
    mov word [ne_rx_read_limit], ne_rx_sample_len
    mov cx, 256
.next:
    push cx
    call [nic_vt_receive]
    pop cx
    jc .done
    cmp word [ne_rx_sample_count], 0
    je .done
    loop .next
.done:
    clc
    ret

tcp_open_resolved_target:
    call ne_resolve_tcp_next_hop_arp
    jc .done
    cmp byte [handoff_addr + handoff_net_status], net_status_next_hop_arp_resolved
    jne .failed
    call ne_tcp_syn_handshake
    jc .failed
    phase_call_res ne_transmit_tcp_ack
    jc .done
    cmp byte [handoff_addr + handoff_net_status], net_status_tcp_connected
    jne .failed
    clc
    ret
.failed:
    stc
.done:
    ret

; Build 11 slice 2 (SYN retransmit): reset the connection state ONCE, then (re)send the SYN and
; wait for the SYN-ACK up to tcp_syn_retry_count times. A dropped SYN or SYN-ACK no longer fails
; the whole connect -- the resend reuses the same source port + ISN (tcp_reset_state runs only
; once), so it is a true retransmit the server dedups, not a new connection. CF clear = connected
; (SYN-ACK received); CF set = exhausted. Used by both the cold connect and the mid-chat reopen.
ne_tcp_syn_handshake:
    call tcp_reset_state
    mov cx, tcp_syn_retry_count
.try:
    push cx
    call ne_send_tcp_syn_frame
    jc .next
    call ne_wait_for_tcp_synack
    cmp byte [handoff_addr + handoff_net_status], net_status_tcp_synack_received
    je .ok
.next:
    pop cx
    loop .try
    stc
    ret
.ok:
    pop cx
    clc
    ret

; Build + transmit the SYN with the CURRENT state (no reset), so ne_tcp_syn_handshake can retransmit.
ne_send_tcp_syn_frame:
    mov al, 0x02
    ; The 4-byte MSS option rides as the SYN "payload": build_tcp_segment_frame counts it in the IP
    ; length + TCP checksum. Build 11 reorg: it emits data-offset 0x50 (20-byte header) for EVERY
    ; segment to keep the SYN-only branch out of the resident nucleus; patch it here to 0x60 (24-byte
    ; header = +4 MSS-option bytes). The data-offset byte is the low byte of the header word at +12, so
    ; the +0x10 it adds to the checksum sum is undone by subtracting 0x10 from the stored checksum --
    ; one's-complement: add ~0x10 (0xffef) and fold the end-around carry (adc), keeping the SYN valid.
    mov cx, 4
    mov si, PHASE_LOAD_ADDR + (tcp_syn_mss_option - PHASE_BASE)
    phase_call_res build_tcp_segment_frame
    mov byte [ne_tx_frame + tcp_offset + 12], 0x60
    mov ax, [ne_tx_frame + tcp_offset + 16]
    add ax, 0xffef
    adc ax, 0
    mov [ne_tx_frame + tcp_offset + 16], ax

    mov si, ne_tx_frame
    call [nic_vt_transmit]
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_syn_sent
.done:
    ret

tcp_syn_mss_option:
    db 0x02, 0x04, tcp_syn_mss >> 8, tcp_syn_mss & 0xff

tcp_reset_state:
    mov ax, [tcp_source_port_word]
    or ax, ax
    jnz .bump_source_port
    mov bx, [0x046c]
    mov al, bl
    and al, 0x3f
    add al, 0xc0
    mov ah, bh
    jmp .source_port_ready
.bump_source_port:
    inc ah
    jnz .source_port_ready
    inc al
    cmp al, 0xc0
    jae .source_port_ready
    mov al, 0xc0
.source_port_ready:
    mov [tcp_source_port_word], ax
    mov word [tcp_local_seq], 0x4553
    mov word [tcp_local_seq + 2], 0x4445
    mov di, tcp_remote_ack
    xor ax, ax
    stosw
    stosw
    ret

ne_resolve_dns_arp:
    mov si, handoff_addr + handoff_dns_addr
    mov di, arp_target_ip
    mov cx, 4
    rep movsb
    mov byte [arp_status_sent], net_status_arp_request_sent
    mov byte [arp_status_resolved], net_status_arp_resolved
    mov byte [arp_error_code], net_error_arp
    call ne_resolve_arp_target
    ret

ne_resolve_tcp_next_hop_arp:
    call select_tcp_next_hop
    mov byte [arp_status_sent], net_status_next_hop_arp_request_sent
    mov byte [arp_status_resolved], net_status_next_hop_arp_resolved
    mov byte [arp_error_code], net_error_next_hop_arp
    call ne_resolve_arp_target
    ret

select_tcp_next_hop:
    mov si, handoff_addr + handoff_subnet_addr
    mov cx, 4
    xor al, al
.check_subnet:
    or al, [si]
    inc si
    loop .check_subnet
    or al, al
    jz .router

    mov si, tcp_target_ip
    mov di, handoff_addr + handoff_ip_addr
    mov bx, handoff_addr + handoff_subnet_addr
    mov cx, 4
.compare_net:
    lodsb
    mov ah, [bx]
    and al, ah
    mov dl, [di]
    and dl, ah
    cmp al, dl
    jne .router
    inc bx
    inc di
    loop .compare_net
    mov si, tcp_target_ip
    jmp .copy
.router:
    mov si, handoff_addr + handoff_router_addr
.copy:
    mov di, arp_target_ip
    mov cx, 4
    rep movsb
    ret

ne_resolve_arp_target:
    mov si, arp_target_ip
    mov cx, 4
    xor al, al
.check_target:
    or al, [si]
    inc si
    loop .check_target
    or al, al
    jnz .have_target
    mov al, [arp_error_code]
    mov [handoff_addr + handoff_net_error], al
    clc
    ret
.have_target:
    call ne_transmit_arp_request
    jc .done
    call ne_wait_for_arp_reply
.done:
    ret

ne_wait_for_arp_reply:
    mov word [ne_rx_read_limit], arp_tx_frame_len
    mov word [dhcp_wait_count], arp_wait_count
.poll:
    call [nic_vt_receive]
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_arp_reply
    jnc .done
.wait:
    mov cx, 2
    phase_call_res wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov al, [arp_status_sent]
    mov [handoff_addr + handoff_net_status], al
    mov al, [arp_error_code]
    mov [handoff_addr + handoff_net_error], al
    clc
    ret
.failed:
    mov al, [arp_status_sent]
    mov [handoff_addr + handoff_net_status], al
    clc
    ret
.done:
    mov al, [arp_status_resolved]
    mov [handoff_addr + handoff_net_status], al
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

ne_wait_for_dns_response:
    mov word [ne_rx_read_limit], dns_rx_read_len
    mov word [dhcp_wait_count], dns_wait_count
.poll:
    call [nic_vt_receive]
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_dns_response
    jnc .done
.wait:
    mov cx, 2
    phase_call_res wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_status], net_status_dns_query_sent
    mov byte [handoff_addr + handoff_net_error], net_error_dns
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], net_status_dns_query_sent
    mov byte [handoff_addr + handoff_net_error], net_error_dns
    clc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_dns_response_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

ne_wait_for_tcp_synack:
    mov word [ne_rx_read_limit], tcp_rx_read_len
    mov word [dhcp_wait_count], tcp_wait_count
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .poll
    mov word [dhcp_wait_count], tcp_wait_count_3c501
.poll:
    call [nic_vt_receive]
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_tcp_synack
    jnc .done
.wait:
    mov cx, 2
    phase_call_res wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_syn_sent
    mov byte [handoff_addr + handoff_net_error], net_error_tcp
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_syn_sent
    clc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_synack_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

ne_transmit_arp_request:
    call build_arp_request_frame

    mov si, ne_tx_frame
    mov cx, arp_tx_frame_len
    call [nic_vt_transmit]
    jc .done
    mov al, [arp_status_sent]
    mov [handoff_addr + handoff_net_status], al
.done:
    ret

ne_transmit_dns_query:
    call build_dns_query_frame

    mov si, ne_tx_frame
    mov cx, [dns_tx_len]
    call [nic_vt_transmit]
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_dns_query_sent
.done:
    ret

build_arp_request_frame:
    mov di, ne_tx_frame
    xor al, al
    mov cx, arp_tx_frame_len
    rep stosb

    mov di, ne_tx_frame
    mov al, 0xff
    mov cx, 6
    rep stosb

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov ax, 0x0608
    stosw
    mov ax, 0x0100
    stosw
    mov ax, 0x0008
    stosw
    mov ax, 0x0406
    stosw
    mov ax, 0x0100
    stosw

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov si, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb

    xor al, al
    mov cx, 6
    rep stosb

    mov si, arp_target_ip
    mov cx, 4
    rep movsb
    ret

build_dns_query_frame:
    mov di, ne_tx_frame
    xor al, al
    mov cx, dns_tx_frame_max_len
    rep stosb

    mov di, ne_tx_frame
    mov si, arp_target_mac
    mov cx, 6
    rep movsb

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov ax, 0x0008
    stosw

    mov ax, 0x0045
    stosw
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, ipv4_header_len + udp_header_len + dns_payload_base_len
    xchg al, ah
    stosw
    xor ax, ax
    stosw
    stosw
    mov ax, 0x1140
    stosw
    xor ax, ax
    stosw

    mov si, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb

    mov si, handoff_addr + handoff_dns_addr
    mov cx, 4
    rep movsb

    mov ax, 0x01c0
    stosw
    mov ax, 0x3500
    stosw
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, udp_header_len + dns_payload_base_len
    xchg al, ah
    stosw
    xor ax, ax
    stosw

    mov ax, dns_query_id_word
    stosw
    mov ax, 0x0001
    stosw
    mov ax, 0x0100
    stosw
    xor ax, ax
    stosw
    stosw
    stosw
    mov si, dns_qname
    mov cl, [dns_qname_len]
    xor ch, ch
    rep movsb
    mov ax, 0x0100
    stosw
    mov ax, 0x0100
    stosw

    phase_call_res write_ipv4_checksum
    ret

parse_arp_reply:
    cmp word [ne_rx_sample_count], arp_frame_len
    jb .not_reply
    cmp word [ne_tx_frame + 12], 0x0608
    jne .not_reply
    cmp word [ne_tx_frame + arp_payload_offset], 0x0100
    jne .not_reply
    cmp word [ne_tx_frame + arp_payload_offset + 2], 0x0008
    jne .not_reply
    cmp word [ne_tx_frame + arp_payload_offset + 4], 0x0406
    jne .not_reply
    cmp word [ne_tx_frame + arp_payload_offset + 6], 0x0200
    jne .not_reply

    mov si, ne_tx_frame + arp_tpa_offset
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
.check_target_ip:
    lodsb
    cmp al, [di]
    jne .not_reply
    inc di
    loop .check_target_ip

    mov si, ne_tx_frame + arp_spa_offset
    mov di, arp_target_ip
    mov cx, 4
.check_sender_ip:
    lodsb
    cmp al, [di]
    jne .not_reply
    inc di
    loop .check_sender_ip

    mov si, ne_tx_frame + arp_sha_offset
    mov di, arp_target_mac
    mov cx, 6
    rep movsb
    clc
    ret
.not_reply:
    stc
    ret

parse_dns_response:
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, dns_payload_offset + 12 + 4 + 16
    cmp word [ne_rx_sample_count], ax
    jb .not_response
    cmp word [ne_tx_frame + 12], 0x0008
    jne .not_response
    cmp byte [ne_tx_frame + eth_header_len], 0x45
    jne .not_response
    cmp byte [ne_tx_frame + eth_header_len + 9], 17
    jne .not_response

    mov si, ne_tx_frame + eth_header_len + 12
    mov di, handoff_addr + handoff_dns_addr
    mov cx, 4
.check_source_ip:
    lodsb
    cmp al, [di]
    jne .not_response
    inc di
    loop .check_source_ip

    mov si, ne_tx_frame + eth_header_len + 16
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
.check_dest_ip:
    lodsb
    cmp al, [di]
    jne .not_response
    inc di
    loop .check_dest_ip

    cmp word [ne_tx_frame + dns_udp_offset], 0x3500
    jne .not_response
    cmp word [ne_tx_frame + dns_udp_offset + 2], 0x01c0
    jne .not_response
    cmp word [ne_tx_frame + dns_payload_offset], dns_query_id_word
    jne .not_response
    test byte [ne_tx_frame + dns_payload_offset + 2], 0x80
    jz .not_response
    cmp byte [ne_tx_frame + dns_payload_offset + 7], 0
    je .not_response

    mov si, ne_tx_frame + dns_payload_offset + 12
    mov bl, [dns_qname_len]
    xor bh, bh
    add si, bx
    add si, 4
.answer:
    mov al, [ne_tx_frame + dns_payload_offset + 7]
    mov [dns_answer_remaining], al
.next_answer:
    cmp byte [dns_answer_remaining], 0
    je .not_response
    call dns_skip_name
    jc .not_response
    cmp word [si], 0x0100
    jne .skip_answer
    cmp word [si + 2], 0x0100
    jne .skip_answer
    cmp word [si + 8], 0x0400
    jne .skip_answer
    add si, 10
    mov di, tcp_target_ip
    mov cx, 4
    rep movsb
    clc
    ret
.skip_answer:
    mov ah, [si + 8]
    mov al, [si + 9]
    add si, 10
    add si, ax
    dec byte [dns_answer_remaining]
    jmp .next_answer
.not_response:
    stc
    ret

dns_skip_name:
    mov cx, 64
.part:
    lodsb
    mov ah, al
    and ah, 0xc0
    cmp ah, 0xc0
    je .pointer
    or ah, ah
    jnz .bad
    or al, al
    jz .done
    xor ah, ah
    add si, ax
    loop .part
.bad:
    stc
    ret
.pointer:
    lodsb
.done:
    clc
    ret

parse_tcp_synack:
    cmp word [ne_rx_sample_count], tcp_offset + 20
    jb .not_synack
    cmp word [ne_tx_frame + 12], 0x0008
    jne .not_synack
    cmp byte [ne_tx_frame + eth_header_len], 0x45
    jne .not_synack
    cmp byte [ne_tx_frame + eth_header_len + 9], 6
    jne .not_synack

    mov si, ne_tx_frame + eth_header_len + 12
    mov di, tcp_target_ip
    mov cx, 4
.check_source_ip:
    lodsb
    cmp al, [di]
    jne .not_synack
    inc di
    loop .check_source_ip

    mov si, ne_tx_frame + eth_header_len + 16
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
.check_dest_ip:
    lodsb
    cmp al, [di]
    jne .not_synack
    inc di
    loop .check_dest_ip

    mov ax, [tcp_dest_port_word]
    cmp word [ne_tx_frame + tcp_offset], ax
    jne .not_synack
    mov ax, [tcp_source_port_word]
    cmp word [ne_tx_frame + tcp_offset + 2], ax
    jne .not_synack
    mov al, [ne_tx_frame + tcp_offset + 13]
    and al, 0x12
    cmp al, 0x12
    jne .not_synack
    cmp word [ne_tx_frame + tcp_offset + 8], 0x4553
    jne .not_synack
    cmp word [ne_tx_frame + tcp_offset + 10], 0x4545
    jne .not_synack
    mov si, ne_tx_frame + tcp_offset + 8
    mov di, tcp_local_seq
    movsw
    movsw
    mov si, ne_tx_frame + tcp_offset + 4
    mov di, tcp_remote_ack
    movsw
    movsw
    mov di, tcp_remote_ack
    mov cx, 1
    phase_call_res tcp_add_cx_to_seq
    clc
    ret
.not_synack:
    stc
    ret

%unmacro phase_call_res 1
%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
