; NE family driver — ne1000 / ne2000 / Novell NE1000 (DP8390, remote-DMA buffer access).
; Self-contained module loaded into nic_driver_slot at boot. DRIVER_BASE is %defined to this
; module's start label by the driver wrapper before %include. Header (10 B) = the 5 nic_vt_* entries;
; the driver-load phase copies them into the resident nic_vtable. Metadata after the header declares which
; detected families this driver supports. enter/restore are no-ops (no windowing);
; rx_fallback is the resident default (no 3c501 second-frame). The DP8390 ring comes from
; core/nic_ring.inc; ne_buf_load / ne_buf_read are the remote-DMA leaves.
    dw nic_driver_slot + (driver_noop - DRIVER_BASE)
    dw nic_driver_slot + (driver_noop - DRIVER_BASE)
    dw nic_driver_slot + (ne_transmit - DRIVER_BASE)
    dw nic_driver_slot + (ne_receive - DRIVER_BASE)
    dw nic_driver_slot + (driver_no_fallback - DRIVER_BASE)
    nic_driver_metadata

ne_transmit:
    nic_dp8390_transmit ne_buf_load
ne_receive:
    nic_dp8390_receive ne_buf_read

; remote-DMA write: si=frame, bp=len, bx=nic_base -> CF (set on DMA timeout).
ne_buf_load:
    lea dx, [bx + ne_rbcr0]
    mov ax, bp
    nic_out_dx_word
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
    stc
    ret
.dma_done:
    mov al, ne_isr_rdc
    out dx, al
    clc
    ret

; remote-DMA read: bx=ring page addr, cx=count, di=dest -> CF (set on DMA timeout).
ne_buf_read:
    mov [ne_dma_addr], bx
    mov [ne_dma_count], cx
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + ne_isr]
    mov al, ne_isr_rdc
    out dx, al
    lea dx, [bx + ne_rbcr0]
    mov ax, [ne_dma_count]
    nic_out_dx_word
    lea dx, [bx + ne_rsar0]
    mov ax, [ne_dma_addr]
    nic_out_dx_word
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
