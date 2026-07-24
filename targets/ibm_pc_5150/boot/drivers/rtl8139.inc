; Realtek RTL8139C+ PCI driver, using the legacy RTL8139 RX ring / TX slots.
    dw nic_driver_slot + (rtl8139_enter - DRIVER_BASE)
    dw nic_driver_slot + (driver_noop - DRIVER_BASE)
    dw nic_driver_slot + (rtl8139_transmit - DRIVER_BASE)
    dw nic_driver_slot + (rtl8139_receive - DRIVER_BASE)
    dw nic_driver_slot + (driver_no_fallback - DRIVER_BASE)
    nic_driver_metadata

rtl8139_mac0 equ 0x00
rtl8139_tx_status0 equ 0x10
rtl8139_tx_addr0 equ 0x20
rtl8139_rx_buf_reg equ 0x30
rtl8139_cmd equ 0x37
rtl8139_capr equ 0x38
rtl8139_intr_mask equ 0x3c
rtl8139_intr_status equ 0x3e
rtl8139_tx_config equ 0x40
rtl8139_rx_config equ 0x44
rtl8139_tx_summary equ 0x60
rtl8139_cmd_reset equ 0x10
rtl8139_cmd_rx_tx equ 0x0c
rtl8139_rx_empty equ 0x01
rtl8139_rx_config_accept equ 0x0a
rtl8139_tx_config_normal equ 0x03000700
rtl8139_tx_ok0 equ 0x1000
rtl8139_tx_desc equ ne_next_page
rtl8139_rx_ptr equ ne_rx_count

%macro rtl8139_mov_eax_imm 1
    db 0x66, 0xb8
    dd %1
%endmacro

%macro rtl8139_zero_eax 0
    db 0x66, 0x31, 0xc0
%endmacro

%macro rtl8139_out_dx_eax 0
    db 0x66, 0xef
%endmacro

rtl8139_enter:
    cmp byte [handoff_addr + handoff_net_status], net_status_packet_ready
    jb .init
    clc
    ret
.init:
    call rtl8139_read_mac
    jc .failed
    cmp word [handoff_addr + handoff_ram_top], rtl8139_dma_end
    jb .failed
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + rtl8139_cmd]
    mov al, rtl8139_cmd_reset
    out dx, al
    mov cx, 0xffff
.wait_reset:
    in al, dx
    test al, rtl8139_cmd_reset
    jz .reset_done
    loop .wait_reset
    jmp .failed
.reset_done:
    mov word [rtl8139_rx_ptr], 0
    mov byte [rtl8139_tx_desc], 0
    lea dx, [bx + rtl8139_rx_buf_reg]
    rtl8139_mov_eax_imm rtl8139_rx_buf
    rtl8139_out_dx_eax
    lea dx, [bx + rtl8139_rx_config]
    rtl8139_mov_eax_imm rtl8139_rx_config_accept
    rtl8139_out_dx_eax
    lea dx, [bx + rtl8139_tx_addr0]
    rtl8139_mov_eax_imm rtl8139_tx_buf
    mov cx, 4
.tx_addr:
    rtl8139_out_dx_eax
    add dx, 4
    loop .tx_addr
    lea dx, [bx + rtl8139_cmd]
    mov al, rtl8139_cmd_rx_tx
    out dx, al
    lea dx, [bx + rtl8139_tx_config]
    rtl8139_mov_eax_imm rtl8139_tx_config_normal
    rtl8139_out_dx_eax
    lea dx, [bx + rtl8139_capr]
    mov ax, 0xfff0
    out dx, ax
    lea dx, [bx + rtl8139_intr_mask]
    xor ax, ax
    out dx, ax
    lea dx, [bx + rtl8139_intr_status]
    dec ax
    out dx, ax
    mov byte [handoff_addr + handoff_net_status], net_status_packet_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_init
    stc
    ret

rtl8139_read_mac:
    mov dx, [handoff_addr + handoff_nic_base]
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.read:
    in al, dx
    stosb
    inc dx
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

rtl8139_transmit:
    mov bp, cx
    push es
    push ds
    pop es
    mov di, rtl8139_tx_buf
    rep movsb
    pop es
    mov di, [handoff_addr + handoff_nic_base]
    mov cl, [rtl8139_tx_desc]
    mov si, rtl8139_tx_ok0
    shl si, cl
    xor ch, ch
    mov bx, cx
    shl bx, 1
    shl bx, 1
    lea dx, [di + rtl8139_tx_status0]
    add dx, bx
    rtl8139_zero_eax
    mov ax, bp
    rtl8139_out_dx_eax
    mov bp, 4
.wait_pass:
    mov cx, 0xffff
.wait_tx:
    lea dx, [di + rtl8139_tx_summary]
    in ax, dx
    test ax, si
    jnz .tx_done
    loop .wait_tx
    dec bp
    jnz .wait_pass
    mov byte [handoff_addr + handoff_net_error], net_error_ne_tx
    stc
    ret
.tx_done:
    inc byte [rtl8139_tx_desc]
    and byte [rtl8139_tx_desc], 3
.done:
    lea dx, [di + rtl8139_intr_status]
    mov ax, 0xffff
    out dx, ax
    clc
    ret

rtl8139_receive:
    mov word [ne_rx_sample_count], 0
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + rtl8139_cmd]
    in al, dx
    test al, rtl8139_rx_empty
    jz .have_frame
    clc
    ret
.have_frame:
    mov bx, [rtl8139_rx_ptr]
    mov cx, ne_rx_header_len
    mov di, ne_rx_header
    call rtl8139_copy_from_ring
    test word [ne_rx_header], 0x0001
    jz .release
    mov ax, [ne_rx_header + 2]
    cmp ax, 4
    jbe .count_failed
    cmp ax, ne_rx_max_count + 4
    jbe .count_valid
.count_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp .release
.count_valid:
    sub ax, 4
    mov [ne_rx_sample_count], ax
    or ax, ax
    jz .release
    cmp ax, [ne_rx_read_limit]
    jbe .sample_ready
    mov ax, [ne_rx_read_limit]
.sample_ready:
    mov [ne_rx_sample_count], ax
    mov cx, ax
    mov bx, [rtl8139_rx_ptr]
    add bx, ne_rx_header_len
    cmp bx, rtl8139_rx_ring_len
    jb .copy_ready
    sub bx, rtl8139_rx_ring_len
.copy_ready:
    mov di, ne_tx_frame
    call rtl8139_copy_from_ring
.release:
    mov ax, [ne_rx_header + 2]
    add ax, 7
    and ax, 0xfffc
    add ax, [rtl8139_rx_ptr]
    cmp ax, rtl8139_rx_ring_len
    jb .ptr_ready
    sub ax, rtl8139_rx_ring_len
.ptr_ready:
    mov [rtl8139_rx_ptr], ax
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + rtl8139_capr]
    sub ax, 0x10
    out dx, ax
    lea dx, [bx + rtl8139_intr_status]
    mov ax, 0xffff
    out dx, ax
    clc
    ret

rtl8139_copy_from_ring:
    push es
    push ds
    pop es
.again:
    or cx, cx
    jz .done
    mov si, rtl8139_rx_buf
    add si, bx
    mov ax, rtl8139_rx_ring_len
    sub ax, bx
    cmp cx, ax
    jbe .last
    push cx
    mov cx, ax
    rep movsb
    pop cx
    sub cx, ax
    xor bx, bx
    jmp .again
.last:
    rep movsb
.done:
    pop es
    ret
