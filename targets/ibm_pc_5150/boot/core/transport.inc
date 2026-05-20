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
    mov cx, 0x0800
.delay:
    loop .delay
    dec word [dhcp_wait_count]
    jnz .poll
.failed:
    mov al, net_error_tcp
    jmp net_fail_al
.done:
    ret

tcp_parse_3c501_second_frame:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .failed
    mov cx, 16
.next_frame:
    call tcp_3c501_drop_first_frame
    jc .failed
    call parse_tcp_payload
    jnc .done
    loop .next_frame
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
    mov ax, [ne_tx_frame + eth_header_len + 2]
    xchg al, ah
    add ax, eth_header_len
    cmp ax, 60
    jae .frame_len_ready
    mov ax, 60
.frame_len_ready:
    mov dx, [ne_rx_sample_count]
    cmp ax, dx
    jae .failed
    sub dx, ax
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
