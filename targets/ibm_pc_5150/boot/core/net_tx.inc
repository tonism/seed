ne_transmit_dhcp_discover:
    call build_dhcp_discover_frame

    mov si, ne_tx_frame
    mov cx, dhcp_frame_len
    call ne_transmit_frame
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_discover_sent
.done:
    ret

ne_transmit_dhcp_request:
    call build_dhcp_request_frame

    mov si, ne_tx_frame
    mov cx, dhcp_frame_len
    call ne_transmit_frame
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_request_sent
.done:
    ret

ne_transmit_arp_request:
    call build_arp_request_frame

    mov si, ne_tx_frame
    mov cx, arp_tx_frame_len
    call ne_transmit_frame
    jc .done
    mov al, [arp_status_sent]
    mov [handoff_addr + handoff_net_status], al
.done:
    ret

ne_transmit_dns_query:
    call build_dns_query_frame

    mov si, ne_tx_frame
    mov cx, [dns_tx_len]
    call ne_transmit_frame
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_dns_query_sent
.done:
    ret

ne_transmit_tcp_syn:
    call tcp_reset_state
    mov al, 0x02
    xor cx, cx
    mov si, tcp_remote_ack
    call build_tcp_segment_frame

    mov si, ne_tx_frame
    mov cx, [tcp_tx_len]
    call ne_transmit_frame
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_syn_sent
.done:
    ret

ne_transmit_tcp_ack:
    mov al, 0x10
    xor cx, cx
    mov si, tcp_remote_ack
    call build_tcp_segment_frame

    mov si, ne_tx_frame
    mov cx, [tcp_tx_len]
    call ne_transmit_frame
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_connected
.done:
    ret

tcp_send_payload:
    cmp cx, tcp_payload_max_len
    ja .failed
    push cx
    mov al, 0x18
    call build_tcp_segment_frame

    mov si, ne_tx_frame
    mov cx, [tcp_tx_len]
    call ne_transmit_frame
    pop cx
    jc .done
    mov di, tcp_local_seq
    call tcp_add_cx_to_seq
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_payload_sent
    clc
.done:
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tcp
    stc
    ret

ne_transmit_frame:
    mov [ne_tx_len], cx
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .dp8390
    call el1_transmit_frame
    ret

.dp8390:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    mov al, ne_isr_rdc | ne_isr_txe | ne_isr_ptx
    out dx, al

    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .check_3c503
    xor bl, bl
    mov bh, [ne_tx_start]
    mov cx, [ne_tx_len]
    call wd_write_sharedmem_bytes
    jmp .frame_loaded

.check_3c503:
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    jne .remote_dma
    xor bl, bl
    mov bh, [ne_tx_start]
    mov cx, [ne_tx_len]
    call c503_write_chipmem_bytes
    jmp .frame_loaded

.remote_dma:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rbcr0
    mov ax, [ne_tx_len]
    out dx, al
    inc dx
    mov al, ah
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rsar0
    xor al, al
    out dx, al
    inc dx
    mov al, [ne_tx_start]
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_remote_write
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_data
    mov cx, [ne_tx_len]
.write_frame:
    lodsb
    out dx, al
    loop .write_frame

    mov cx, 0xffff
.wait_dma:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    test al, ne_isr_rdc
    jnz .dma_done
    loop .wait_dma
    jmp .failed
.dma_done:
    mov al, ne_isr_rdc
    out dx, al

.frame_loaded:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_tpsr
    mov al, [ne_tx_start]
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_tbcr0
    mov ax, [ne_tx_len]
    out dx, al
    inc dx
    mov al, ah
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_transmit
    out dx, al

    mov cx, 0xffff
.wait_tx:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    test al, ne_isr_ptx | ne_isr_txe
    jnz .tx_done
    loop .wait_tx
    jmp .failed
.tx_done:
    mov al, ne_isr_ptx | ne_isr_txe
    out dx, al
    mov byte [handoff_addr + handoff_net_status], net_status_tx_ready
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_tx
    stc
    ret

el1_transmit_frame:
    mov ax, 0x0800
    sub ax, [ne_tx_len]
    mov [el1_tx_ptr], ax
    call el1_set_gp

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_system
    out dx, al
    inc dx
    mov cx, [ne_tx_len]
.write4:
    cmp cx, 4
    jb .write_tail
    lodsb
    out dx, al
    lodsb
    out dx, al
    lodsb
    out dx, al
    lodsb
    out dx, al
    sub cx, 4
    jmp .write4
.write_tail:
    or cx, cx
    jz .write_done
.write1:
    lodsb
    out dx, al
    loop .write1
.write_done:

    mov ax, [el1_tx_ptr]
    call el1_set_gp
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_xmit_recv
    out dx, al

    mov cx, 0xffff
.wait:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_tx_cmd
    in al, dx
    test al, el1_tx_status_ready
    jnz .done
    loop .wait
    mov byte [handoff_addr + handoff_net_error], net_error_ne_tx
    stc
    ret
.done:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_system
    out dx, al
    mov al, el1_aux_receive
    out dx, al
    mov byte [handoff_addr + handoff_net_status], net_status_tx_ready
    clc
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

    call write_ipv4_checksum
    ret

tcp_reset_state:
    mov word [tcp_local_seq], 0x4553
    mov word [tcp_local_seq + 2], 0x4445
    mov di, tcp_remote_ack
    xor ax, ax
    stosw
    stosw
    ret

build_tcp_segment_frame:
    mov [tcp_tx_flags], al
    mov [tcp_tx_payload_ptr], si
    mov [tcp_tx_payload_len], cx

    mov di, ne_tx_frame
    xor al, al
    mov cx, net_frame_buffer_len
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
    mov ax, [tcp_tx_payload_len]
    add ax, tcp_ip_len
    xchg al, ah
    stosw
    xor ax, ax
    stosw
    stosw
    mov ax, 0x0640
    stosw
    xor ax, ax
    stosw

    mov si, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb

    mov si, tcp_target_ip
    mov cx, 4
    rep movsb

    mov ax, tcp_source_port_word
    stosw
    mov ax, [tcp_dest_port_word]
    stosw
    mov si, tcp_local_seq
    movsw
    movsw
    mov si, tcp_remote_ack
    movsw
    movsw
    mov ah, [tcp_tx_flags]
    mov al, 0x50
    stosw
    mov ax, 0x0004
    stosw
    xor ax, ax
    stosw
    stosw

    mov cx, [tcp_tx_payload_len]
    or cx, cx
    jz .payload_done
    mov si, [tcp_tx_payload_ptr]
    rep movsb
.payload_done:

    mov ax, [tcp_tx_payload_len]
    add ax, tcp_payload_offset
    cmp ax, tcp_tx_frame_len
    jae .tx_len_ready
    mov ax, tcp_tx_frame_len
.tx_len_ready:
    mov [tcp_tx_len], ax

    call write_ipv4_checksum
    call write_tcp_checksum
    ret

write_ipv4_checksum:
    mov si, ne_tx_frame + eth_header_len
    xor bx, bx
    xor dx, dx
    mov cx, ipv4_header_len / 2
.sum:
    lodsw
    add bx, ax
    adc dx, 0
    loop .sum
    add bx, dx
    adc bx, 0
    not bx
    mov [ne_tx_frame + eth_header_len + 10], bx
    ret

write_tcp_checksum:
    xor bx, bx
    xor dx, dx
    mov si, handoff_addr + handoff_ip_addr
    mov cx, 2
.src_ip:
    lodsw
    add bx, ax
    adc dx, 0
    loop .src_ip
    mov si, tcp_target_ip
    mov cx, 2
.dst_ip:
    lodsw
    add bx, ax
    adc dx, 0
    loop .dst_ip
    mov ax, 0x0600
    add bx, ax
    adc dx, 0
    mov ax, [tcp_tx_payload_len]
    add ax, 20
    xchg al, ah
    add bx, ax
    adc dx, 0
    mov si, ne_tx_frame + tcp_offset
    mov cx, [tcp_tx_payload_len]
    add cx, 20
    push cx
    shr cx, 1
.tcp_word:
    jcxz .tcp_words_done
    lodsw
    add bx, ax
    adc dx, 0
    loop .tcp_word
.tcp_words_done:
    pop cx
    test cl, 1
    jz .fold
    lodsb
    xor ah, ah
    add bx, ax
    adc dx, 0
.fold:
    add bx, dx
    adc bx, 0
    not bx
    mov [ne_tx_frame + tcp_offset + 16], bx
    ret

tcp_add_cx_to_seq:
    add [di + 3], cl
    adc [di + 2], ch
    adc byte [di + 1], 0
    adc byte [di], 0
    ret
