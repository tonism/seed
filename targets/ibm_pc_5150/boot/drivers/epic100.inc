; SMC 83C170 EPIC/100 PCI driver, using direct bus-master descriptors.
    dw nic_driver_slot + (epic100_enter - DRIVER_BASE)
    dw nic_driver_slot + (driver_noop - DRIVER_BASE)
    dw nic_driver_slot + (epic100_transmit - DRIVER_BASE)
    dw nic_driver_slot + (epic100_receive - DRIVER_BASE)
    dw nic_driver_slot + (driver_no_fallback - DRIVER_BASE)
    nic_driver_metadata

epic100_command equ 0x00
epic100_intstat equ 0x04
epic100_intmask equ 0x08
epic100_genctl equ 0x0c
epic100_lan0 equ 0x40
epic100_rxcon equ 0x60
epic100_prcdar equ 0x84
epic100_ptcdar equ 0xc4
epic100_cmd_start_rx equ 0x02
epic100_cmd_txqueued equ 0x04
epic100_cmd_rxqueued equ 0x08
epic100_genctl_soft_reset equ 0x0001
epic100_rxcon_accept_broadcast equ 0x04
epic100_desc_own equ 0x8000
epic100_rx_ok equ 0x0001
epic100_rx_error_mask equ 0x2006

%macro epic100_mov_eax_imm 1
    db 0x66, 0xb8
    dd %1
%endmacro

%macro epic100_zero_eax 0
    db 0x66, 0x31, 0xc0
%endmacro

%macro epic100_out_dx_eax 0
    db 0x66, 0xef
%endmacro

epic100_enter:
    cmp byte [handoff_addr + handoff_net_status], net_status_packet_ready
    jb .init
    clc
    ret
.init:
    call epic100_read_mac
    jc .failed
    cmp word [handoff_addr + handoff_ram_top], epic100_dma_end
    jb .failed
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + epic100_genctl]
    mov ax, epic100_genctl_soft_reset
    out dx, ax
    xor ax, ax
    out dx, ax
    lea dx, [bx + epic100_intmask]
    epic100_zero_eax
    epic100_out_dx_eax
    lea dx, [bx + epic100_intstat]
    epic100_mov_eax_imm 0x0007ffff
    epic100_out_dx_eax
    lea dx, [bx + epic100_rxcon]
    mov ax, epic100_rxcon_accept_broadcast
    out dx, ax
    call epic100_rearm_rx
    push es
    push ds
    pop es
    mov di, epic100_tx_desc
    xor ax, ax
    mov cx, 8
    rep stosw
    pop es
    lea dx, [bx + epic100_prcdar]
    epic100_mov_eax_imm epic100_rx_desc
    epic100_out_dx_eax
    lea dx, [bx + epic100_command]
    mov al, epic100_cmd_start_rx | epic100_cmd_rxqueued
    out dx, al
    mov byte [handoff_addr + handoff_net_status], net_status_packet_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_init
    stc
    ret

epic100_read_mac:
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + epic100_lan0]
    mov di, handoff_addr + handoff_mac
    mov cx, 3
.read:
    in ax, dx
    stosw
    add dx, 4
    loop .read
    test byte [handoff_addr + handoff_mac], 0x01
    jnz .failed
    mov si, handoff_addr + handoff_mac
    xor al, al
    mov cx, 6
.nonzero:
    or al, [si]
    inc si
    loop .nonzero
    or al, al
    jz .failed
    or word [handoff_addr + handoff_flags], handoff_flag_mac_valid
    clc
    ret
.failed:
    stc
    ret

epic100_transmit:
    mov bp, cx
    push es
    push ds
    pop es
    mov di, epic100_tx_buf
    rep movsb
    mov word [epic100_tx_desc], 0
    mov [epic100_tx_desc + 2], bp
    mov word [epic100_tx_desc + 4], epic100_tx_buf
    mov word [epic100_tx_desc + 6], 0
    mov [epic100_tx_desc + 8], bp
    mov word [epic100_tx_desc + 10], 0
    mov word [epic100_tx_desc + 12], 0
    mov word [epic100_tx_desc + 14], 0
    mov word [epic100_tx_desc], epic100_desc_own
    pop es

    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + epic100_ptcdar]
    epic100_mov_eax_imm epic100_tx_desc
    epic100_out_dx_eax
    lea dx, [bx + epic100_command]
    mov al, epic100_cmd_txqueued
    out dx, al

    mov bp, 4
.wait_pass:
    mov cx, 0xffff
.wait_tx:
    test word [epic100_tx_desc], epic100_desc_own
    jz .done
    loop .wait_tx
    dec bp
    jnz .wait_pass
.done:
    lea dx, [bx + epic100_intstat]
    epic100_mov_eax_imm 0x0007ffff
    epic100_out_dx_eax
    clc
    ret

epic100_receive:
    mov word [ne_rx_sample_count], 0
    test word [epic100_rx_desc], epic100_desc_own
    jz .have_frame
    clc
    ret
.have_frame:
    test word [epic100_rx_desc], epic100_rx_ok
    jz .rearm
    test word [epic100_rx_desc], epic100_rx_error_mask
    jnz .rearm
    mov ax, [epic100_rx_desc + 2]
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
    mov si, epic100_rx_buf
    mov di, ne_tx_frame
    push es
    push ds
    pop es
    rep movsb
    pop es
.rearm:
    call epic100_rearm_rx
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + epic100_command]
    mov al, epic100_cmd_rxqueued
    out dx, al
    lea dx, [bx + epic100_intstat]
    epic100_mov_eax_imm 0x0007ffff
    epic100_out_dx_eax
    clc
    ret

epic100_rearm_rx:
    mov word [epic100_rx_desc], 0
    mov word [epic100_rx_desc + 2], 0
    mov word [epic100_rx_desc + 4], epic100_rx_buf
    mov word [epic100_rx_desc + 6], 0
    mov word [epic100_rx_desc + 8], pcnet_rx_buf_len
    mov word [epic100_rx_desc + 10], 0
    mov word [epic100_rx_desc + 12], epic100_rx_desc
    mov word [epic100_rx_desc + 14], 0
    mov word [epic100_rx_desc], epic100_desc_own
    ret
