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
    mov cx, [tcp_tx_payload_len]
    add cx, tcp_payload_offset
    cmp cx, tcp_tx_frame_len
    jae .clear_len_ready
    mov cx, tcp_tx_frame_len
.clear_len_ready:
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
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .default_window
    mov ax, 0x0002
    jmp .write_window
.default_window:
    mov ax, 0x0004
.write_window:
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
