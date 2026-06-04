ne_transmit_tcp_ack:
    mov al, 0x10
    xor cx, cx
    mov si, tcp_remote_ack
    call build_tcp_segment_frame

    mov si, ne_tx_frame
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
    call ne_transmit_frame
    pop cx
    jc .done
    mov di, tcp_local_seq
    call tcp_add_cx_to_seq
    clc
.done:
    ret
.failed:
    mov al, net_error_tcp
    jmp net_fail_al

ne_transmit_frame:
    mov bp, cx
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    je el1_transmit_frame
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + ne_isr]
    mov al, ne_isr_rdc | ne_isr_txe | ne_isr_ptx
    out dx, al

    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .check_3c503
    xor bl, bl
    mov bh, [ne_tx_start]
    mov cx, bp
    call wd_write_sharedmem_bytes
    jmp .frame_loaded

.check_3c503:
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    jne .remote_dma
    xor bl, bl
    mov bh, [ne_tx_start]
    mov cx, bp
    call c503_write_chipmem_bytes
    jmp .frame_loaded

.remote_dma:
    ; bx still holds the NIC base from the top of ne_transmit_frame (only the wd/3c503
    ; branches clobber it, and neither was taken to reach here), so no reload needed.
    lea dx, [bx + ne_rbcr0]
    mov ax, bp
    call out_dx_word

    lea dx, [bx + ne_rsar0]
    xor al, al
    out dx, al
    inc dx
    mov al, [ne_tx_start]
    out dx, al

    lea dx, [bx + ne_cr]
    mov al, ne_cmd_remote_write
    out dx, al

    lea dx, [bx + ne_data]
    mov cx, bp
.write_frame:
    lodsb
    out dx, al
    loop .write_frame

    mov cx, 0xffff
.wait_dma:
    lea dx, [bx + ne_isr]
    in al, dx
    test al, ne_isr_rdc
    jnz .dma_done
    loop .wait_dma
    jmp .failed
.dma_done:
    mov al, ne_isr_rdc
    out dx, al

.frame_loaded:
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + ne_tpsr]
    mov al, [ne_tx_start]
    out dx, al

    lea dx, [bx + ne_tbcr0]
    mov ax, bp
    call out_dx_word

    lea dx, [bx + ne_cr]
    mov al, ne_cmd_transmit
    out dx, al

    mov cx, 0xffff
.wait_tx:
    lea dx, [bx + ne_isr]
    in al, dx
    test al, ne_isr_ptx | ne_isr_txe
    jnz .tx_done
    loop .wait_tx
    jmp .failed
.tx_done:
    mov al, ne_isr_ptx | ne_isr_txe
    out dx, al
    clc
    ret
.failed:
    mov al, net_error_ne_tx
    jmp net_fail_al

el1_transmit_frame:
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
    jmp net_fail_al
.done:
    lea dx, [bx + el1_aux]
    mov al, el1_aux_system
    out dx, al
    mov al, el1_aux_receive
    out dx, al
    clc
    ret

build_tcp_segment_frame:
    mov dl, al
    push si
    mov bp, cx

    mov di, ne_tx_frame
    mov si, arp_target_mac
    movsw
    movsw
    movsw

    mov si, handoff_addr + handoff_mac
    movsw
    movsw
    movsw

    mov ax, 0x0008
    stosw

    mov ax, 0x0045
    stosw
    mov ax, bp
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
    movsw
    movsw

    mov si, tcp_target_ip
    movsw
    movsw

    mov ax, [tcp_source_port_word]
    stosw
    mov ax, [tcp_dest_port_word]
    stosw
    mov si, tcp_local_seq
    movsw
    movsw
    mov si, tcp_remote_ack
    movsw
    movsw
    mov ah, dl
    mov al, 0x50
    stosw
    ; Uniform 256-byte advertised window. Under SLiRP (the emulated test path) the
    ; VM<->proxy link is local, so the window has no real effect on throughput; the
    ; bytes freed by dropping the per-NIC case pay for the reconnect request-rebuild
    ; in net_phase. (3c501 previously advertised 512; revisit only if/when running on
    ; real hardware where the advertised window actually paces the sender.)
    mov ax, 0x0001
    stosw
    xor ax, ax
    stosw
    stosw

    mov cx, bp
    pop si
    or cx, cx
    jz .payload_done
    rep movsb
.payload_done:
    mov cx, tcp_tx_frame_len - tcp_payload_offset
    sub cx, bp
    jbe .padding_done
    xor al, al
    rep stosb
.padding_done:

    mov ax, bp
    add ax, tcp_payload_offset
    cmp ax, tcp_tx_frame_len
    jae .tx_len_ready
    mov ax, tcp_tx_frame_len
.tx_len_ready:
    push ax
    call write_ipv4_checksum
    call write_tcp_checksum
    pop cx
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
    add bx, [handoff_addr + handoff_ip_addr]
    adc dx, 0
    add bx, [handoff_addr + handoff_ip_addr + 2]
    adc dx, 0
    add bx, [tcp_target_ip]
    adc dx, 0
    add bx, [tcp_target_ip + 2]
    adc dx, 0
    add bh, 6
    adc dx, 0
    mov ax, bp
    add ax, 20
    xchg al, ah
    add bx, ax
    adc dx, 0
    mov si, ne_tx_frame + tcp_offset
    mov cx, bp
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

net_fail_al:
    mov [handoff_addr + handoff_net_error], al
    stc
    ret
