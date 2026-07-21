; Build 12 NIC HAL: the family-agnostic TCP payload parser stays resident — every driver fills
; ne_tx_frame / ne_rx_sample_count the same way, so this validates the received frame (addresses,
; ports, ack, header length) and publishes tcp_rx_payload_ptr/len identically for all of them. The
; per-family receive code (the DP8390 ring, el1) moved to the floppy driver modules.
parse_tcp_payload:
    cmp word [ne_rx_sample_count], tcp_offset + 20
    jb .not_payload_early
    cmp word [ne_tx_frame + 12], 0x0008
    jne .not_payload_early
    cmp byte [ne_tx_frame + eth_header_len], 0x45
    jne .not_payload_early
    cmp byte [ne_tx_frame + eth_header_len + 9], 6
    jne .not_payload_early

    push ds
    pop es
    mov si, ne_tx_frame + eth_header_len + 12
    mov di, tcp_target_ip
    mov cx, 2
    repe cmpsw
    jne .not_payload_early

    mov si, ne_tx_frame + eth_header_len + 16
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 2
    repe cmpsw
    jne .not_payload_early

    mov ax, [tcp_dest_port_word]
    cmp word [ne_tx_frame + tcp_offset], ax
    je .ports_ready
.not_payload_early:
    stc
    ret
.ports_ready:
    mov ax, [tcp_source_port_word]
    cmp word [ne_tx_frame + tcp_offset + 2], ax
    jne .not_payload
    test byte [ne_tx_frame + tcp_offset + 13], 0x04
    jnz .not_payload
    mov si, ne_tx_frame + tcp_offset + 4
    mov di, tcp_remote_ack
    mov cx, 2
    repe cmpsw
    jne .not_payload

    xor bx, bx
    mov bl, [ne_tx_frame + tcp_offset + 12]
    and bl, 0xf0
    shr bl, 1
    shr bl, 1
    cmp bl, 20
    jb .not_payload

    mov ax, [ne_tx_frame + eth_header_len + 2]
    xchg al, ah
    cmp ax, ipv4_header_len + 20
    jb .not_payload
    sub ax, ipv4_header_len
    cmp ax, bx
    jbe .not_payload
    sub ax, bx
    mov cx, ax

    add bx, tcp_offset
    mov dx, [ne_rx_sample_count]
    cmp dx, bx
    jbe .not_payload
    sub dx, bx
    cmp ax, dx
    ja .not_payload
    mov [tcp_rx_payload_len], ax
    mov ax, ne_tx_frame
    add ax, bx
    mov [tcp_rx_payload_ptr], ax

    mov si, ne_tx_frame + tcp_offset + 4
    mov di, tcp_remote_ack
    movsw
    movsw
    mov di, tcp_remote_ack
    call tcp_add_cx_to_seq
    clc
    ret
.not_payload:
    stc
    ret
