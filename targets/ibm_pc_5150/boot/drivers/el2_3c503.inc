; 3c503 driver — 3Com EtherLink II / el2 (DP8390 with a gate-array DMA into the card's chip memory).
; Self-contained module loaded into nic_driver_slot at boot. The DP8390 ring (core/nic_ring.inc)
; drives TX/RX; the buffer leaves move bytes through the el2 gate array. c503_select_dp8390 (returning
; the gate array to DP8390 mode after each chip-memory burst) stays RESIDENT — it is a tiny helper
; the cold packet-IO init also calls — so the driver reaches it via drv_call_res. enter/restore are
; no-ops; rx_fallback is the resident default.
    dw nic_noop
    dw nic_noop
    dw nic_driver_slot + (c503_transmit - DRIVER_BASE)
    dw nic_driver_slot + (c503_receive - DRIVER_BASE)
    dw nic_rx_fallback_none

c503_transmit:
    nic_dp8390_transmit c503_buf_load
c503_receive:
    nic_dp8390_receive c503_buf_read

; chip-memory write (gate-array DMA download): si=frame, bp=len -> CF=0.
c503_buf_load:
    xor bl, bl
    mov bh, [ne_tx_start]
    mov cx, bp
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
    drv_call_res c503_select_dp8390
    clc
    ret

; chip-memory read (gate-array DMA upload): bx=ring page addr, cx=count, di=dest -> CF=0. Wraps at
; the RX ring stop page and re-arms the gate array, matching the DP8390 ring.
c503_buf_read:
    mov [ne_dma_addr], bx
    mov [ne_dma_count], cx
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
    drv_call_res c503_select_dp8390
    clc
    ret

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
    drv_call_res out_dx_word
    ret
