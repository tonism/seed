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
    phase_call_res ne_transmit_dhcp_discover
    jc .failed
    call ne_wait_for_dhcp_offer
    cmp byte [handoff_addr + handoff_net_status], net_status_dhcp_offer_received
    jne .failed
    phase_call_res ne_transmit_dhcp_request
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
    phase_call_res ne_try_receive_frame
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
    phase_call_res ne_try_receive_frame
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

parse_dhcp_offer:
    cmp word [ne_rx_sample_count], dhcp_options_offset + 3
    jb .not_offer
    phase_call_res dhcp_reply_prefix_matches
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
    phase_call_res dhcp_reply_prefix_matches
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

%unmacro phase_call_res 1
%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
