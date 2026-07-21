; 3c501 driver — 3Com EtherLink / el1. A fully custom single-buffer card: it shares none of the
; DP8390 ring, so this driver is self-contained TX/RX plus the single-buffer RX fallback (drop a
; stale frame, parse a second). Self-contained module loaded into nic_driver_slot at boot.
; enter/restore are no-ops; rx_fallback is this driver's el1_second_frame (the one card that has one).
; Resident shared routines (net_fail_al, parse_tcp_payload) are reached via drv_call_res/drv_jmp_res.
    dw nic_driver_slot + (driver_noop - DRIVER_BASE)
    dw nic_driver_slot + (driver_noop - DRIVER_BASE)
    dw nic_driver_slot + (el1_transmit - DRIVER_BASE)
    dw nic_driver_slot + (el1_receive - DRIVER_BASE)
    dw nic_driver_slot + (el1_second_frame - DRIVER_BASE)
    nic_driver_metadata

; transmit: cx = frame length, si = frame at ne_tx_frame.
el1_transmit:
    mov bp, cx
    mov ax, 0x0800
    sub ax, bp
    mov [el1_tx_ptr], ax
    mov bx, [handoff_addr + handoff_nic_base]
    call el1_set_gp
    lea dx, [bx + el1_aux]
    mov al, el1_aux_system
    out dx, al
    inc dx
    mov cx, bp
.write:
    lodsb
    out dx, al
    loop .write
    mov ax, [el1_tx_ptr]
    call el1_set_gp
    lea dx, [bx + el1_aux]
    mov al, el1_aux_xmit_recv
    out dx, al
    mov cx, 0xffff
.wait:
    lea dx, [bx + el1_tx_cmd]
    in al, dx
    test al, el1_tx_status_ready
    jnz .done
    loop .wait
    mov al, net_error_ne_tx
    drv_jmp_res net_fail_al
.done:
    lea dx, [bx + el1_aux]
    mov al, el1_aux_system
    out dx, al
    mov al, el1_aux_receive
    out dx, al
    clc
    ret

el1_receive:
    mov word [ne_rx_sample_count], 0
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + el1_rcvptr]
    in ax, dx
    mov [ne_rx_count], ax
    or ax, ax
    jnz .check_status
    clc
    ret
.check_status:
    mov dx, bx
    in al, dx
    test al, el1_rx_status_good
    jz .release_empty
    mov ax, [ne_rx_count]
    cmp ax, [ne_rx_read_limit]
    jbe .sample_count_ready
    mov ax, [ne_rx_read_limit]
.sample_count_ready:
    ; Keep accumulated 3c501 samples below the response phase loaded at 0x0900.
    cmp ax, agent_response_phase_load_addr - ne_tx_frame
    jbe .safe_sample_count_ready
    mov ax, agent_response_phase_load_addr - ne_tx_frame
.safe_sample_count_ready:
    mov [ne_rx_sample_count], ax
    mov cx, ax
    xor ax, ax
    call el1_set_gp
    mov di, ne_tx_frame
    lea dx, [bx + el1_data]
    push es
    push ds
    pop es
.read:
    in al, dx
    stosb
    loop .read
    pop es
.release_frame:
    lea dx, [bx + el1_rcvptr]
    xor al, al
    out dx, al
    lea dx, [bx + el1_aux]
    mov al, el1_aux_system
    out dx, al
    mov al, el1_aux_receive
    out dx, al
    clc
    ret
.release_empty:
    mov word [ne_rx_sample_count], 0
    jmp .release_frame

el1_set_gp:
    lea dx, [bx + el1_dataptr]
    out dx, ax
    ret

; single-buffer RX fallback: a pure ACK can latch receive ahead of the wanted frame, so drop the
; stale leading frame(s) and parse the next. Returns CF=0 if a payload was parsed, CF=1 otherwise
; (the .none path is the local no-frame default).
el1_second_frame:
    mov cx, 16
.next_frame:
    call el1_drop_first_frame
    jc .poll_card
    drv_call_res parse_tcp_payload
    jc .next_not_payload
    jmp .done
.next_not_payload:
    loop .next_frame
.poll_card:
    mov bp, 32
.poll_wait:
    call el1_receive
    jc .none
    cmp word [ne_rx_sample_count], 0
    jne .polled_frame
    mov cx, 0x0400
.poll_delay:
    loop .poll_delay
    dec bp
    jnz .poll_wait
    jmp .none
.polled_frame:
    drv_call_res parse_tcp_payload
    jc .polled_not_payload
    jmp .done
.polled_not_payload:
    mov cx, 16
.next_polled_frame:
    call el1_drop_first_frame
    jc .none
    drv_call_res parse_tcp_payload
    jc .next_polled_not_payload
    jmp .done
.next_polled_not_payload:
    loop .next_polled_frame
.none:
    stc
    ret
.done:
    ret

el1_drop_first_frame:
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
    push es
    push ds
    pop es
    rep movsb
    pop es
    clc
    ret
.failed:
    stc
    ret
