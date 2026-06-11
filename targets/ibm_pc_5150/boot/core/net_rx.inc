; Build 12 NIC HAL: the NE-family receive (DP8390 ring — ne2000/ne1000/3c503/wd8003), reached via
; nic_vt_receive. 3c501 (el1) is a full receive override the vtable routes to el1_try_receive_frame
; instead, so the old `cmp family_3c501/je el1_try_receive_frame` top dispatch is gone. Both receive
; impls are self-contained (each clears ne_rx_sample_count and reads the NIC itself — no input regs).
; The inner wd/3c503/remote-DMA buffer-read split in ne_remote_read_bytes stays a direct branch (the
; NE driver's own DP8390 access taxonomy, not a separate driver — handover scope note).
ne_try_receive_frame:
    mov word [ne_rx_sample_count], 0
    call ne_read_ring_pointers
    cmp al, ah
    jne .packet_waiting
    clc
    ret

.packet_waiting:
    mov [ne_next_page], al
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

    mov bl, ne_rx_header_len
    mov bh, [ne_next_page]
    mov cx, ax
    mov di, ne_tx_frame
    call ne_remote_read_bytes
    jc .dma_failed

.release_frame:
    call ne_release_rx_frame
    clc
    ret

.count_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp .release_frame

.dma_failed:
    mov al, net_error_ne_rx_dma
    jmp net_fail_al

.header_failed:
    mov al, net_error_ne_rx_header
    jmp net_fail_al

el1_try_receive_frame:
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
    lea dx, [bx + el1_data]
.read:
    in al, dx
    stosb
    loop .read
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
.count_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp .release_frame

el1_set_gp:
    lea dx, [bx + el1_dataptr]
    out dx, ax
    ret

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
    call tcp_add_cx_to_seq
    clc
    ret
.not_payload:
    stc
    ret

ne_read_ring_pointers:
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + ne_cr]
    mov al, ne_cmd_start_page1
    out dx, al

    lea dx, [bx + ne_isr]
    in al, dx
    mov ah, al

    lea dx, [bx + ne_cr]
    mov al, ne_cmd_start_nodma
    out dx, al

    lea dx, [bx + ne_bnry]
    in al, dx
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
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + ne_isr]
    mov al, ne_isr_rdc
    out dx, al

    lea dx, [bx + ne_rbcr0]
    mov ax, [ne_dma_count]
    call out_dx_word

    lea dx, [bx + ne_rsar0]
    mov ax, [ne_dma_addr]
    call out_dx_word

    lea dx, [bx + ne_cr]
    mov al, ne_cmd_remote_read
    out dx, al

    lea dx, [bx + ne_data]
    mov cx, [ne_dma_count]
.read_byte:
    in al, dx
    stosb
    loop .read_byte

    mov cx, ne_read_dma_wait_count
.wait_dma:
    lea dx, [bx + ne_isr]
    in al, dx
    test al, ne_isr_rdc
    jnz .done
    loop .wait_dma
    lea dx, [bx + ne_cr]
    mov al, ne_cmd_start_nodma
    out dx, al
    stc
    ret
.done:
    mov al, ne_isr_rdc
    out dx, al
    lea dx, [bx + ne_cr]
    mov al, ne_cmd_start_nodma
    out dx, al
    clc
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
    xor al, al
    mov ah, dh
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
    lea dx, [bx + el2_status]
    in al, dx
    test al, el2_status_dprdy
    jnz .ready
    loop .wait_ready
    pop cx
    jmp .done
.ready:
    pop cx
    lodsw
    lea dx, [bx + el2_data]
    out dx, ax
    loop .write
.done:
    jmp c503_select_dp8390

c503_begin_dma_write:
    mov al, el2_ctrl_dma | el2_ctrl_download | el2_ctrl_thin
    jmp c503_begin_dma_al

c503_begin_dma:
    mov al, el2_ctrl_dma | el2_ctrl_thin

c503_begin_dma_al:
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + el2_ctrl]
    out dx, al

    lea dx, [bx + el2_da_high]
    mov ax, [ne_dma_addr]
    xchg al, ah
    call out_dx_word
    ret

c503_read_chipmem_bytes:
    call c503_begin_dma
    lea dx, [bx + el2_data]
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
    xor al, al
    mov ah, [ne_rx_start]
    mov [ne_dma_addr], ax
    call c503_begin_dma
    lea dx, [bx + el2_data]
.next:
    loop .read
    jmp c503_select_dp8390
