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

%if dhcp_rx_frame_len > net_setup_frame_scratch_len
%error "dhcp setup packet scratch too small"
%endif

dhcp_setup_phase:
    call ne_transmit_dhcp_discover
    jc .failed
    call ne_wait_for_dhcp_offer
    cmp byte [handoff_addr + handoff_net_status], net_status_dhcp_offer_received
    jne .failed
    call ne_transmit_dhcp_request
    jc .failed
    call ne_wait_for_dhcp_ack
    cmp byte [handoff_addr + handoff_net_status], net_status_dhcp_ack_received
    jne .failed
    clc
    ret
.failed:
    stc
    ret

ne_wait_for_dhcp_offer:
    mov word [ne_rx_read_limit], dhcp_rx_frame_len
    mov word [dhcp_wait_count], dhcp_offer_wait_count
.poll:
    call [nic_vt_receive]
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_dhcp_offer
    jnc .done
.wait:
    mov cx, 2
    phase_call_res wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_discover_sent
    mov byte [handoff_addr + handoff_net_error], net_error_dhcp_offer
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_discover_sent
    clc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_offer_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

ne_wait_for_dhcp_ack:
    mov word [ne_rx_read_limit], dhcp_rx_frame_len
    mov word [dhcp_wait_count], dhcp_ack_wait_count
.poll:
    call [nic_vt_receive]
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_dhcp_ack
    jnc .done
.wait:
    mov cx, 2
    phase_call_res wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_request_sent
    mov byte [handoff_addr + handoff_net_error], net_error_dhcp_ack
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_request_sent
    clc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_ack_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

ne_transmit_dhcp_discover:
    call build_dhcp_discover_frame

    mov si, ne_tx_frame
    mov cx, dhcp_frame_len
    call [nic_vt_transmit]
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_discover_sent
.done:
    ret

ne_transmit_dhcp_request:
    call build_dhcp_request_frame

    mov si, ne_tx_frame
    mov cx, dhcp_frame_len
    call [nic_vt_transmit]
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_request_sent
.done:
    ret

build_dhcp_discover_frame:
    call build_dhcp_base_frame

    mov al, 53
    stosb
    mov al, 1
    stosb
    stosb

    mov al, 55
    stosb
    mov al, 3
    stosb
    mov al, 1
    stosb
    mov al, 3
    stosb
    mov al, 6
    stosb

    mov al, 61
    stosb
    mov al, 7
    stosb
    mov al, 1
    stosb
    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov al, 57
    stosb
    mov al, 2
    stosb
    stosb
    mov al, 64
    stosb

    mov al, 255
    stosb
    ret

build_dhcp_request_frame:
    call build_dhcp_base_frame

    mov al, 53
    stosb
    mov al, 1
    stosb
    mov al, 3
    stosb

    mov al, 50
    stosb
    mov al, 4
    stosb
    mov si, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb

    mov al, 54
    stosb
    mov al, 4
    stosb
    mov si, dhcp_server_addr
    mov cx, 4
    rep movsb

    mov al, 61
    stosb
    mov al, 7
    stosb
    mov al, 1
    stosb
    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    xor al, al
    stosb
    mov al, 255
    stosb
    ret

build_dhcp_base_frame:
    mov di, ne_tx_frame
    xor al, al
    mov cx, dhcp_frame_len
    rep stosb

    mov di, ne_tx_frame
    mov al, 0xff
    mov cx, 6
    rep stosb

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov al, 0x08
    stosb
    xor al, al
    stosb

    mov al, 0x45
    stosb
    xor al, al
    stosb
    mov al, dhcp_ip_len >> 8
    stosb
    mov al, dhcp_ip_len & 0xff
    stosb
    xor ax, ax
    stosw
    stosw
    mov al, 64
    stosb
    mov al, 17
    stosb
    mov al, dhcp_ip_checksum >> 8
    stosb
    mov al, dhcp_ip_checksum & 0xff
    stosb
    xor al, al
    mov cx, 4
    rep stosb
    mov al, 0xff
    mov cx, 4
    rep stosb

    xor al, al
    stosb
    mov al, 68
    stosb
    xor al, al
    stosb
    mov al, 67
    stosb
    mov al, dhcp_udp_len >> 8
    stosb
    mov al, dhcp_udp_len & 0xff
    stosb
    xor ax, ax
    stosw

    mov al, 1
    stosb
    stosb
    mov al, 6
    stosb
    xor al, al
    stosb
    mov al, 'S'
    stosb
    mov al, 'E'
    stosb
    stosb
    mov al, 'D'
    stosb
    xor ax, ax
    stosw
    mov al, 0x80
    stosb
    xor al, al
    stosb
    add di, 16

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb
    add di, 10 + 64 + 128

    mov al, 99
    stosb
    mov al, 130
    stosb
    mov al, 83
    stosb
    mov al, 99
    stosb
    ret

parse_dhcp_offer:
    cmp word [ne_rx_sample_count], dhcp_options_offset + 3
    jb .not_offer
    call dhcp_reply_prefix_matches
    jc .not_offer

    mov si, ne_tx_frame + dhcp_chaddr_offset
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.check_mac:
    lodsb
    cmp al, [di]
    jne .not_offer
    inc di
    loop .check_mac

    cmp word [ne_tx_frame + dhcp_cookie_offset], 0x8263
    jne .not_offer
    cmp word [ne_tx_frame + dhcp_cookie_offset + 2], 0x6353
    jne .not_offer

    mov di, handoff_addr + handoff_ip_addr
    xor ax, ax
    mov cx, 8
    rep stosw
    mov di, dhcp_server_addr
    xor ax, ax
    stosw
    stosw
    mov byte [dhcp_message_type], 0

    mov ax, [ne_rx_sample_count]
    sub ax, dhcp_options_offset
    mov [dhcp_options_left], ax
    mov si, ne_tx_frame + dhcp_options_offset
.option:
    cmp word [dhcp_options_left], 0
    je .check_type
    lodsb
    dec word [dhcp_options_left]
    cmp al, 0
    je .option
    cmp al, 255
    je .check_type
    mov [dhcp_option_code], al
    cmp word [dhcp_options_left], 0
    je .check_type
    lodsb
    dec word [dhcp_options_left]
    xor ah, ah
    mov [dhcp_option_len], ax
    cmp [dhcp_options_left], ax
    jb .check_type
    cmp byte [dhcp_option_code], 53
    jne .subnet
    cmp ax, 1
    jb .skip
    mov al, [si]
    mov [dhcp_message_type], al
    jmp .skip
.subnet:
    cmp byte [dhcp_option_code], 1
    jne .router
    cmp ax, 4
    jb .skip
    push si
    mov di, handoff_addr + handoff_subnet_addr
    mov cx, 4
    rep movsb
    pop si
    jmp .skip
.router:
    cmp byte [dhcp_option_code], 3
    jne .dns
    cmp ax, 4
    jb .skip
    push si
    mov di, handoff_addr + handoff_router_addr
    mov cx, 4
    rep movsb
    pop si
    jmp .skip
.dns:
    cmp byte [dhcp_option_code], 6
    jne .server
    cmp ax, 4
    jb .skip
    push si
    mov di, handoff_addr + handoff_dns_addr
    mov cx, 4
    rep movsb
    pop si
    jmp .skip
.server:
    cmp byte [dhcp_option_code], 54
    jne .skip
    cmp ax, 4
    jb .skip
    push si
    mov di, dhcp_server_addr
    mov cx, 4
    rep movsb
    pop si
.skip:
    mov cx, [dhcp_option_len]
    add si, cx
    sub [dhcp_options_left], cx
    jmp .option
.check_type:
    cmp byte [dhcp_message_type], 2
    jne .not_offer
    mov si, ne_tx_frame + dhcp_yiaddr_offset
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb
    clc
    ret
.not_offer:
    mov di, handoff_addr + handoff_ip_addr
    xor ax, ax
    mov cx, 8
    rep stosw
    stc
    ret

parse_dhcp_ack:
    cmp word [ne_rx_sample_count], dhcp_options_offset + 3
    jb .not_ack
    call dhcp_reply_prefix_matches
    jc .not_ack

    mov si, ne_tx_frame + dhcp_chaddr_offset
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.check_mac:
    lodsb
    cmp al, [di]
    jne .not_ack
    inc di
    loop .check_mac

    cmp word [ne_tx_frame + dhcp_cookie_offset], 0x8263
    jne .not_ack
    cmp word [ne_tx_frame + dhcp_cookie_offset + 2], 0x6353
    jne .not_ack

    mov si, ne_tx_frame + dhcp_yiaddr_offset
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
.check_ip:
    lodsb
    cmp al, [di]
    jne .not_ack
    inc di
    loop .check_ip

    mov byte [dhcp_message_type], 0
    mov ax, [ne_rx_sample_count]
    sub ax, dhcp_options_offset
    mov [dhcp_options_left], ax
    mov si, ne_tx_frame + dhcp_options_offset
.option:
    cmp word [dhcp_options_left], 0
    je .check_type
    lodsb
    dec word [dhcp_options_left]
    cmp al, 0
    je .option
    cmp al, 255
    je .check_type
    mov [dhcp_option_code], al
    cmp word [dhcp_options_left], 0
    je .check_type
    lodsb
    dec word [dhcp_options_left]
    xor ah, ah
    mov [dhcp_option_len], ax
    cmp [dhcp_options_left], ax
    jb .check_type
    cmp byte [dhcp_option_code], 53
    jne .skip
    cmp ax, 1
    jb .skip
    mov al, [si]
    mov [dhcp_message_type], al
.skip:
    mov cx, [dhcp_option_len]
    add si, cx
    sub [dhcp_options_left], cx
    jmp .option
.check_type:
    cmp byte [dhcp_message_type], 5
    jne .not_ack
    clc
    ret
.not_ack:
    stc
    ret

dhcp_reply_prefix_matches:
    cmp word [ne_tx_frame + 12], 0x0008
    jne .no
    cmp byte [ne_tx_frame + eth_header_len + 9], 17
    jne .no
    cmp word [ne_tx_frame + eth_header_len + ipv4_header_len], 0x4300
    jne .no
    cmp word [ne_tx_frame + eth_header_len + ipv4_header_len + 2], 0x4400
    jne .no
    cmp byte [ne_tx_frame + dhcp_bootp_offset], 2
    jne .no
    cmp byte [ne_tx_frame + dhcp_bootp_offset + 1], 1
    jne .no
    cmp byte [ne_tx_frame + dhcp_bootp_offset + 2], 6
    jne .no
    cmp word [ne_tx_frame + dhcp_bootp_offset + 4], 0x4553
    jne .no
    cmp word [ne_tx_frame + dhcp_bootp_offset + 6], 0x4445
    jne .no
    clc
    ret
.no:
    stc
    ret

%unmacro phase_call_res 1
%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
