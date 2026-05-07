ne_try_receive_frame:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .dp8390
    jmp el1_try_receive_frame
.dp8390:
    mov word [ne_rx_sample_count], 0
    call ne_read_ring_pointers
    call ne_select_next_rx_page
    mov al, [ne_next_page]
    cmp al, [ne_current_page]
    jne .packet_waiting
    mov byte [handoff_addr + handoff_net_status], net_status_rx_poll_ready
    clc
    ret

.packet_waiting:
    xor bl, bl
    mov bh, [ne_next_page]
    mov cx, ne_rx_header_len
    mov di, ne_rx_header
    call ne_remote_read_bytes
    jc .dma_failed

    mov al, [ne_rx_header + 1]
    cmp al, [ne_rx_start]
    jb .header_failed
    cmp al, [ne_rx_stop]
    jae .header_failed

    test byte [ne_rx_header], ne_rsr_prx
    jz .release_frame

    mov al, [ne_rx_header + 2]
    mov ah, [ne_rx_header + 3]
    mov [ne_rx_count], ax
    cmp ax, ne_rx_header_len
    jbe .count_failed
    cmp ax, ne_rx_max_count
    ja .count_failed
    sub ax, ne_rx_header_len
    mov [ne_rx_sample_count], ax
    or ax, ax
    jz .release_frame
    cmp ax, [ne_rx_read_limit]
    jbe .sample_count_ready
    mov ax, [ne_rx_read_limit]
.sample_count_ready:
    mov [ne_rx_sample_count], ax

.filter_dhcp:
    cmp word [ne_rx_read_limit], dhcp_rx_frame_len
    jne .read_frame
    cmp ax, dhcp_filter_len
    jb .release_empty
    push ax
    mov bl, ne_rx_header_len
    mov bh, [ne_next_page]
    mov cx, dhcp_filter_len
    mov di, ne_tx_frame
    call ne_remote_read_bytes
    jc .prefix_dma_failed
    call dhcp_reply_prefix_matches
    pop ax
    jc .release_empty

.read_frame:
    mov bl, ne_rx_header_len
    mov bh, [ne_next_page]
    mov cx, ax
    mov di, ne_tx_frame
    call ne_remote_read_bytes
    jc .dma_failed

    mov byte [handoff_addr + handoff_net_status], net_status_rx_frame_read

.release_frame:
    call ne_release_rx_frame
    clc
    ret

.release_empty:
    mov word [ne_rx_sample_count], 0
    jmp .release_frame

.count_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp .release_frame

.prefix_dma_failed:
    pop ax

.dma_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_dma
    stc
    ret

.header_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_header
    stc
    ret

el1_try_receive_frame:
    mov word [ne_rx_sample_count], 0
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_rcvptr
    in ax, dx
    mov [ne_rx_count], ax
    or ax, ax
    jnz .check_status
    mov byte [handoff_addr + handoff_net_status], net_status_rx_poll_ready
    clc
    ret

.check_status:
    mov dx, [handoff_addr + handoff_nic_base]
    in al, dx
    test al, el1_rx_status_good
    jz .release_empty
    mov ax, [ne_rx_count]
    cmp ax, ne_rx_max_count
    ja .count_failed
    cmp ax, [ne_rx_read_limit]
    jbe .sample_count_ready
    mov ax, [ne_rx_read_limit]
.sample_count_ready:
    mov [ne_rx_sample_count], ax
    mov cx, ax
    xor ax, ax
    call el1_set_gp
    mov di, ne_tx_frame
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_data
.read4:
    cmp cx, 4
    jb .read_tail
    in al, dx
    stosb
    in al, dx
    stosb
    in al, dx
    stosb
    in al, dx
    stosb
    sub cx, 4
    jmp .read4
.read_tail:
    or cx, cx
    jz .read_done
.read1:
    in al, dx
    stosb
    loop .read1
.read_done:
    mov byte [handoff_addr + handoff_net_status], net_status_rx_frame_read

.release_frame:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_rcvptr
    xor al, al
    out dx, al
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_system
    out dx, al
    mov al, el1_aux_receive
    out dx, al
    clc
    ret
.release_empty:
    mov word [ne_rx_sample_count], 0
    jmp .release_frame
.count_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp .release_frame

el1_set_gp:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_dataptr
    out dx, ax
    ret

dhcp_reply_prefix_matches:
    cmp word [ne_tx_frame + 12], 0x0008
    jne .no
    cmp byte [ne_tx_frame + eth_header_len + 9], 17
    jne .no
    cmp word [ne_tx_frame + eth_header_len + ipv4_header_len], 0x4300
    jne .no
    cmp word [ne_tx_frame + eth_header_len + ipv4_header_len + 2], 0x4400
    jne .no
    cmp byte [ne_tx_frame + dhcp_bootp_offset], 2
    jne .no
    cmp byte [ne_tx_frame + dhcp_bootp_offset + 1], 1
    jne .no
    cmp byte [ne_tx_frame + dhcp_bootp_offset + 2], 6
    jne .no
    cmp word [ne_tx_frame + dhcp_bootp_offset + 4], 0x4553
    jne .no
    cmp word [ne_tx_frame + dhcp_bootp_offset + 6], 0x4445
    jne .no
    clc
    ret
.no:
    stc
    ret

parse_tcp_payload:
    cmp word [ne_rx_sample_count], tcp_offset + 20
    jb .not_payload
    cmp word [ne_tx_frame + 12], 0x0008
    jne .not_payload
    cmp byte [ne_tx_frame + eth_header_len], 0x45
    jne .not_payload
    cmp byte [ne_tx_frame + eth_header_len + 9], 6
    jne .not_payload

    mov si, ne_tx_frame + eth_header_len + 12
    mov di, tcp_target_ip
    mov cx, 4
.check_source_ip:
    lodsb
    cmp al, [di]
    jne .not_payload
    inc di
    loop .check_source_ip

    mov si, ne_tx_frame + eth_header_len + 16
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
.check_dest_ip:
    lodsb
    cmp al, [di]
    jne .not_payload
    inc di
    loop .check_dest_ip

    mov ax, [tcp_dest_port_word]
    cmp word [ne_tx_frame + tcp_offset], ax
    jne .not_payload
    cmp word [ne_tx_frame + tcp_offset + 2], tcp_source_port_word
    jne .not_payload
    test byte [ne_tx_frame + tcp_offset + 13], 0x04
    jnz .not_payload
    mov si, ne_tx_frame + tcp_offset + 4
    mov di, tcp_remote_ack
    mov cx, 4
.check_sequence:
    lodsb
    cmp al, [di]
    jne .not_payload
    inc di
    loop .check_sequence

    mov al, [ne_tx_frame + tcp_offset + 12]
    and al, 0xf0
    shr al, 1
    shr al, 1
    cmp al, 20
    jb .not_payload
    mov [tcp_rx_header_len], al

    mov ah, [ne_tx_frame + eth_header_len + 2]
    mov al, [ne_tx_frame + eth_header_len + 3]
    cmp ax, ipv4_header_len + 20
    jb .not_payload
    sub ax, ipv4_header_len
    mov bl, [tcp_rx_header_len]
    xor bh, bh
    cmp ax, bx
    jbe .not_payload
    sub ax, bx
    mov [tcp_rx_wire_payload_len], ax

    add bx, tcp_offset
    mov dx, [ne_rx_sample_count]
    cmp dx, bx
    jbe .not_payload
    sub dx, bx
    cmp dx, 5
    jb .not_payload
    cmp ax, dx
    jbe .payload_len_ready
    mov ax, dx
.payload_len_ready:
    mov [tcp_rx_payload_len], ax
    mov ax, ne_tx_frame
    add ax, bx
    mov [tcp_rx_payload_ptr], ax

    mov si, ne_tx_frame + tcp_offset + 4
    mov di, tcp_remote_ack
    movsw
    movsw
    mov di, tcp_remote_ack
    mov cx, [tcp_rx_wire_payload_len]
    call tcp_add_cx_to_seq
    clc
    ret
.not_payload:
    stc
    ret

ne_read_ring_pointers:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_page1
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    mov [ne_current_page], al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_nodma
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_bnry
    in al, dx
    mov [ne_boundary_page], al
    ret

ne_select_next_rx_page:
    mov al, [ne_boundary_page]
    inc al
    cmp al, [ne_rx_stop]
    jb .selected
    mov al, [ne_rx_start]
.selected:
    mov [ne_next_page], al
    ret

ne_release_rx_frame:
    mov al, [ne_rx_header + 1]
    dec al
    cmp al, [ne_rx_start]
    jae .write_boundary
    mov al, [ne_rx_stop]
    dec al
.write_boundary:
    mov [ne_boundary_page], al
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_bnry
    out dx, al
    ret

ne_remote_read_bytes:
    mov [ne_dma_addr], bx
    mov [ne_dma_count], cx

    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .check_3c503
    call wd_read_sharedmem_bytes
    clc
    ret

.check_3c503:
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    jne .remote_dma
    call c503_read_chipmem_bytes
    clc
    ret

.remote_dma:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    mov al, ne_isr_rdc
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rbcr0
    mov ax, [ne_dma_count]
    out dx, al
    inc dx
    mov al, ah
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rsar0
    mov ax, [ne_dma_addr]
    out dx, al
    inc dx
    mov al, ah
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_remote_read
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_data
    mov cx, [ne_dma_count]
.read_byte:
    in al, dx
    stosb
    loop .read_byte

    mov cx, ne_read_dma_wait_count
.wait_dma:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    test al, ne_isr_rdc
    jnz .done
    loop .wait_dma
    call ne_finish_remote_dma
    stc
    ret
.done:
    mov al, ne_isr_rdc
    out dx, al
    call ne_finish_remote_dma
    clc
    ret

ne_finish_remote_dma:
    push ax
    push dx
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_nodma
    out dx, al
    pop dx
    pop ax
    ret

wd_write_sharedmem_bytes:
    push es
    mov ax, wd_ram_segment
    mov es, ax
    mov di, bx
    rep movsb
    pop es
    ret

wd_read_sharedmem_bytes:
    mov bx, [ne_dma_addr]
    mov cx, [ne_dma_count]
    mov dh, [ne_rx_start]
    mov dl, [ne_rx_stop]
    push ds
    mov ax, wd_ram_segment
    mov ds, ax
    mov si, bx
.read:
    lodsb
    stosb
    mov ax, si
    cmp ah, dl
    jne .next
    or al, al
    jnz .next
    mov al, dh
    xor ah, ah
    xchg al, ah
    mov si, ax
.next:
    loop .read
    pop ds
    ret

c503_write_chipmem_bytes:
    mov [ne_dma_addr], bx
    mov [ne_dma_count], cx
    call c503_begin_dma_write
    mov cx, [ne_dma_count]
    inc cx
    shr cx, 1
.write:
    push cx
    mov cx, 0x1000
.wait_ready:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_status
    in al, dx
    test al, el2_status_dprdy
    jnz .ready
    loop .wait_ready
    pop cx
    jmp .done
.ready:
    pop cx
    lodsw
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_data
    out dx, ax
    loop .write
.done:
    call c503_select_dp8390
    ret

c503_begin_dma_write:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    mov al, el2_ctrl_dma | el2_ctrl_download | el2_ctrl_thin
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_da_high
    mov ax, [ne_dma_addr]
    mov al, ah
    out dx, al
    inc dx
    mov ax, [ne_dma_addr]
    out dx, al
    ret

c503_read_chipmem_bytes:
    call c503_begin_dma
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_data
    mov cx, [ne_dma_count]
.read:
    in al, dx
    stosb
    inc word [ne_dma_addr]
    mov ax, [ne_dma_addr]
    cmp ah, [ne_rx_stop]
    jne .next
    or al, al
    jnz .next
    mov al, [ne_rx_start]
    xor ah, ah
    xchg al, ah
    mov [ne_dma_addr], ax
    call c503_begin_dma
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_data
.next:
    loop .read
    call c503_select_dp8390
    ret

c503_begin_dma:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    mov al, el2_ctrl_dma | el2_ctrl_thin
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_da_high
    mov ax, [ne_dma_addr]
    mov al, ah
    out dx, al
    inc dx
    mov ax, [ne_dma_addr]
    out dx, al
    ret
