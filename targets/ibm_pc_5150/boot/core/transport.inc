tcp_receive_payload:
    ; Keep this distinct from dhcp_rx_frame_len, which enables the DHCP prefix filter.
    mov word [ne_rx_read_limit], tcp_payload_read_len
    mov word [dhcp_wait_count], tcp_payload_wait_count
.poll:
    call ne_try_receive_frame
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_tcp_payload
    jnc .done
    call tcp_parse_3c501_second_frame
    jnc .done
.wait:
    call tcp_payload_poll_delay
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_error], net_error_tcp
    stc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tcp
    stc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_payload_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

tcp_payload_poll_delay:
    push cx
    mov cx, 0x0800
.delay:
    loop .delay
    pop cx
    ret

tcp_parse_3c501_second_frame:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .failed
    call tcp_3c501_drop_first_frame
    jc .failed
    call parse_tcp_payload
    jnc .done
    call tcp_3c501_drop_first_frame
    jc .failed
    call parse_tcp_payload
.done:
    ret
.failed:
    stc
    ret

tcp_3c501_drop_first_frame:
    cmp word [ne_rx_sample_count], eth_header_len + ipv4_header_len
    jb .failed
    cmp word [ne_tx_frame + 12], 0x0008
    jne .failed
    mov ah, [ne_tx_frame + eth_header_len + 2]
    mov al, [ne_tx_frame + eth_header_len + 3]
    add ax, eth_header_len
    cmp ax, 60
    jae .frame_len_ready
    mov ax, 60
.frame_len_ready:
    mov dx, [ne_rx_sample_count]
    cmp ax, dx
    jae .failed
    sub dx, ax
    cmp dx, tcp_offset + 20 + 5
    jb .failed
    mov [ne_rx_sample_count], dx
    mov si, ne_tx_frame
    add si, ax
    mov di, ne_tx_frame
    mov cx, dx
    rep movsb
    clc
    ret
.failed:
    stc
    ret
