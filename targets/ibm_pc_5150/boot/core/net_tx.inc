ne_transmit_tcp_ack:
    mov al, 0x10
ne_transmit_tcp_flags:
    xor cx, cx
    mov si, tcp_remote_ack
    call build_tcp_segment_frame

    mov si, ne_tx_frame
    call [nic_vt_transmit]
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
    call [nic_vt_transmit]
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
    mov al, 0x50                        ; data offset 5 (20-byte header) for every segment; the SYN's
    stosw                               ; 24-byte header (4-byte MSS option) is patched in + checksum-
                                        ; corrected by ne_send_tcp_syn_frame, keeping that cost out of
                                        ; the resident nucleus (Build 11 never-blank reorg).
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

    ; Build 12 (env save/load): the frame length is just di - ne_tx_frame. di already points past the
    ; payload AND the min-frame padding above, so this equals the old explicit max(tcp_payload_offset +
    ; payload, tcp_tx_frame_len) in BOTH the padded (short payload) and long-payload cases. 9 B smaller,
    ; which funds the env-restore hook in prepare_agent_path (the shared resident nucleus is otherwise
    ; exactly full at the 0x1600 driver slot). di is dead after the frame is built. (xchg ax,di is 1 B.)
    xchg ax, di
    sub ax, ne_tx_frame
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
