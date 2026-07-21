; WD8003 driver — Western Digital / SMC (DP8390 behind a windowed register bank + shared memory).
; Self-contained module loaded into nic_driver_slot at boot. enter/restore window the DP8390 (the
; packet path maps the NIC registers at nic_base + wd_dp8390_offset, then unmaps); the DP8390 ring
; (core/nic_ring.inc) drives TX/RX; metadata after the vtable declares supported detected families.
; The buffer leaves copy frames in/out of the card's shared RAM.
    dw nic_driver_slot + (wd_enter - DRIVER_BASE)
    dw nic_driver_slot + (wd_restore - DRIVER_BASE)
    dw nic_driver_slot + (wd_transmit - DRIVER_BASE)
    dw nic_driver_slot + (wd_receive - DRIVER_BASE)
    dw nic_driver_slot + (driver_no_fallback - DRIVER_BASE)
    nic_driver_metadata

wd_enter:
    add word [handoff_addr + handoff_nic_base], wd_dp8390_offset
    ret
wd_restore:
    sub word [handoff_addr + handoff_nic_base], wd_dp8390_offset
    ret

wd_transmit:
    nic_dp8390_transmit wd_buf_load
wd_receive:
    nic_dp8390_receive wd_buf_read

; shared-memory write: si=frame, bp=len -> CF=0. Copies the frame into the card's TX page.
wd_buf_load:
    xor bl, bl
    mov bh, [ne_tx_start]
    mov cx, bp
    push es
    mov ax, wd_ram_segment
    mov es, ax
    mov di, bx
    rep movsb
    pop es
    clc
    ret

; shared-memory read: bx=ring page addr, cx=count, di=dest -> CF=0. Copies count bytes out of the
; card's shared RAM, wrapping at the RX ring stop page back to the start (matches the DP8390 ring).
wd_buf_read:
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
    clc
    ret
