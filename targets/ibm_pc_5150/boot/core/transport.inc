tcp_receive_payload:
    ; Keep this distinct from dhcp_rx_frame_len, which enables the DHCP prefix filter.
    mov word [ne_rx_read_limit], tcp_payload_read_len
    mov word [dhcp_wait_count], tcp_payload_wait_count
.poll:
    call [nic_vt_receive]
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_tcp_payload
    jnc .done
    call [nic_vt_rx_fallback]
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

; Build 12 NIC HAL: the 3c501 single-buffer RX fallback (drop a stale frame, parse a second),
; reached via nic_vt_rx_fallback. nic_rx_fallback_none (CF=1 = "no usable second frame") is the
; default every other family points at; the family `cmp` is gone -- the vtable routed the family in.
el1_rx_second_frame:
    mov cx, 16
.next_frame:
    call tcp_3c501_drop_first_frame
    jc nic_rx_fallback_none
    call parse_tcp_payload
    jnc .done
    loop .next_frame
.done:
    ret
nic_rx_fallback_none:
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
