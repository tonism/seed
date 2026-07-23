; AMD PCnet/LANCE driver — ISA, PCI, and compatible Racal variants.
; Uses the controller's reset-default 16-bit descriptor style with one RX and
; one TX descriptor in a fixed below-64K DMA workspace.
    dw nic_driver_slot + (pcnet_enter - DRIVER_BASE)
    dw nic_driver_slot + (driver_noop - DRIVER_BASE)
    dw nic_driver_slot + (pcnet_transmit - DRIVER_BASE)
    dw nic_driver_slot + (pcnet_receive - DRIVER_BASE)
    dw nic_driver_slot + (driver_no_fallback - DRIVER_BASE)
    nic_driver_metadata

pcnet_enter:
    cmp byte [handoff_addr + handoff_net_status], net_status_packet_ready
    jb .init
    clc
    ret
.init:
    test word [handoff_addr + handoff_flags], handoff_flag_mac_valid
    jnz .mac_ready
.init_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_init
    stc
    ret
.mac_ready:
    cmp word [handoff_addr + handoff_ram_top], pcnet_dma_end
    jb .init_failed
    push es
    push ds
    pop es

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, pcnet_reset
    in ax, dx

    xor ax, ax
    mov di, pcnet_init_block
    stosw
    mov si, handoff_addr + handoff_mac
    movsw
    movsw
    movsw
    mov cx, 4
.clear_ladr:
    stosw
    loop .clear_ladr
    mov ax, pcnet_rx_desc
    stosw
    xor ax, ax
    stosw
    mov ax, pcnet_tx_desc
    stosw
    xor ax, ax
    stosw

    mov word [pcnet_rx_desc + 2], 0
    mov word [pcnet_rx_desc], pcnet_rx_buf
    mov word [pcnet_rx_desc + 4], pcnet_rx_buf_bcnt
    mov word [pcnet_rx_desc + 6], 0
    mov word [pcnet_rx_desc + 2], pcnet_desc_own
    mov word [pcnet_tx_desc + 2], 0
    mov word [pcnet_tx_desc], pcnet_tx_buf
    mov word [pcnet_tx_desc + 4], 0
    mov word [pcnet_tx_desc + 6], 0

    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + pcnet_rap]
    mov ax, 1
    out dx, ax
    lea dx, [bx + pcnet_rdp]
    mov ax, pcnet_init_block
    out dx, ax
    lea dx, [bx + pcnet_rap]
    mov ax, 2
    out dx, ax
    lea dx, [bx + pcnet_rdp]
    xor ax, ax
    out dx, ax
    lea dx, [bx + pcnet_rap]
    xor ax, ax
    out dx, ax
    lea dx, [bx + pcnet_rdp]
    mov ax, pcnet_csr_init
    out dx, ax
    mov cx, 0xffff
.wait_idon:
    in ax, dx
    test ax, pcnet_csr_idon
    jnz .initialized
    loop .wait_idon
    pop es
    jmp .init_failed
.initialized:
    mov ax, pcnet_csr_start | pcnet_csr_idon
    out dx, ax
    mov byte [handoff_addr + handoff_net_status], net_status_packet_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    pop es
    clc
    ret

pcnet_transmit:
    mov bp, cx
    push es
    push ds
    pop es
    mov di, pcnet_tx_buf
    rep movsb
    pop es

    mov word [pcnet_tx_desc + 2], 0
    mov word [pcnet_tx_desc], pcnet_tx_buf
    mov ax, bp
    neg ax
    and ax, 0x0fff
    or ax, 0xf000
    mov [pcnet_tx_desc + 4], ax
    mov word [pcnet_tx_desc + 6], 0
    mov word [pcnet_tx_desc + 2], pcnet_desc_own | pcnet_desc_stp_enp

    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + pcnet_rap]
    xor ax, ax
    out dx, ax
    lea dx, [bx + pcnet_rdp]
    mov ax, pcnet_csr_tx_demand
    out dx, ax

    mov bp, 4
.wait_pass:
    mov cx, 0xffff
.wait_tx:
    test word [pcnet_tx_desc + 2], pcnet_desc_own
    jz .done
    loop .wait_tx
    dec bp
    jnz .wait_pass
    ; Match the DP8390 path's tolerance: once the descriptor was handed to the
    ; device, let TCP recovery judge delivery instead of aborting the session.
.done:
    clc
    ret

pcnet_receive:
    mov word [ne_rx_sample_count], 0
    test word [pcnet_rx_desc + 2], pcnet_desc_own
    jz .have_frame
    clc
    ret
.have_frame:
    mov ax, [pcnet_rx_desc + 2]
    test ax, pcnet_desc_err
    jnz .rearm
    and ax, pcnet_desc_stp_enp
    cmp ax, pcnet_desc_stp_enp
    jne .rearm
    mov ax, [pcnet_rx_desc + 6]
    and ax, 0x0fff
    cmp ax, 4
    jbe .count_ready
    sub ax, 4
.count_ready:
    cmp ax, ne_rx_max_count
    jbe .count_valid
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp .rearm
.count_valid:
    cmp ax, [ne_rx_read_limit]
    jbe .sample_ready
    mov ax, [ne_rx_read_limit]
.sample_ready:
    mov [ne_rx_sample_count], ax
    or ax, ax
    jz .rearm
    mov cx, ax
    mov si, pcnet_rx_buf
    mov di, ne_tx_frame
    push es
    push ds
    pop es
    rep movsb
    pop es
.rearm:
    mov word [pcnet_rx_desc + 2], 0
    mov word [pcnet_rx_desc], pcnet_rx_buf
    mov word [pcnet_rx_desc + 4], pcnet_rx_buf_bcnt
    mov word [pcnet_rx_desc + 6], 0
    mov word [pcnet_rx_desc + 2], pcnet_desc_own
    clc
    ret
