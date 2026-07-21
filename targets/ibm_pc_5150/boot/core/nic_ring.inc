; Build 12 NIC HAL — driver-module ABI + the shared DP8390 ring.
;
; A NIC driver is a self-contained module on the floppy, loaded at boot into the resident
; active-driver slot (nic_driver_slot) by the driver-load phase, so only the selected driver
; costs resident RAM — every other family's driver stays on the floppy (0 resident RAM). A driver
; runs at the slot like a cold phase: internal calls/jumps are relative (position-independent),
; resident shared routines (net_fail_al / parse_tcp_payload / c503_select_dp8390) are reached via
; the slot-aware drv_call_res / drv_jmp_res below (the established phase_call_res idiom, base =
; nic_driver_slot). The driver's first 10 bytes are a header of the 5 nic_vt_* entries, followed by
; SDRV metadata (ABI version + supported-family mask); the driver-load phase validates metadata and
; copies the vtable into the resident nic_vtable. DRIVER_BASE must name the module's start label.
;
; The DP8390 ring (ne2000/ne1000/3c503/wd8003) is identical across those three cards except for how
; bytes move in/out of the card's packet buffer, so it lives here as two macros parameterised by the
; driver's buffer-access leaf (nic_buf_load for TX, nic_buf_read for RX). Each DP8390 driver emits
; the ring with its own leaf; %% labels keep the per-driver expansions from colliding. 3c501 (el1)
; shares none of this and is a fully custom driver.

%macro drv_call_res 1
    db 0xe8
    dw %1 - (nic_driver_slot + ($ - DRIVER_BASE) + 2)
%endmacro

%macro drv_jmp_res 1
    db 0xe9
    dw %1 - (nic_driver_slot + ($ - DRIVER_BASE) + 2)
%endmacro

%macro nic_out_dx_word 0
    out dx, al
    inc dx
    mov al, ah
    out dx, al
%endmacro

%macro nic_driver_metadata 0
    db 'SDRV'
    db nic_driver_abi_version
    db DRIVER_FAMILY_MASK
%endmacro

; DP8390 transmit. Contract (shared by every transmit impl): cx = frame length, si = frame at
; ne_tx_frame. %1 = the driver's buffer-load leaf (si=frame, bp=len, bx=nic_base -> CF; loads the
; frame into the card's TX buffer). Then the shared DP8390 transmit trigger fires the frame.
%macro nic_dp8390_transmit 1
    mov bp, cx
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + ne_isr]
    mov al, ne_isr_rdc | ne_isr_txe | ne_isr_ptx
    out dx, al
    call %1
    jc %%failed
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + ne_tpsr]
    mov al, [ne_tx_start]
    out dx, al
    lea dx, [bx + ne_tbcr0]
    mov ax, bp
    nic_out_dx_word
    lea dx, [bx + ne_cr]
    mov al, ne_cmd_transmit
    out dx, al
    mov bp, 4
%%wait_tx_pass:
    mov cx, 0xffff
%%wait_tx:
    lea dx, [bx + ne_isr]
    in al, dx
    test al, ne_isr_ptx | ne_isr_txe
    jnz %%tx_done
    loop %%wait_tx
    dec bp
    jnz %%wait_tx_pass
    ; The frame has already been DMA'd and the TX command accepted. Some DP8390
    ; emulations can expose a stale completion bit under dense app-data sends even
    ; though the packet is on the wire; after several full waits, let TCP recovery
    ; prove delivery instead of aborting a half-written HTTP body here.
    clc
    ret
%%tx_done:
    mov al, ne_isr_ptx | ne_isr_txe
    out dx, al
    clc
    ret
%%failed:
    mov al, net_error_ne_tx
    drv_jmp_res net_fail_al
%endmacro

; DP8390 receive. Self-contained (clears ne_rx_sample_count, reads the card itself; no input regs).
; %1 = the driver's buffer-read leaf (bx=page addr, cx=count, di=dest -> CF; copies count bytes out
; of the card's RX ring). The ring-pointer read and the frame release are DP8390-generic (%% locals).
%macro nic_dp8390_receive 1
    mov word [ne_rx_sample_count], 0
    call %%read_ring_pointers
    cmp al, ah
    jne %%packet_waiting
    clc
    ret
%%packet_waiting:
    mov [ne_next_page], al
    xor bl, bl
    mov bh, [ne_next_page]
    mov cx, ne_rx_header_len
    mov di, ne_rx_header
    call %1
    jc %%dma_failed
    mov al, [ne_rx_header + 1]
    cmp al, [ne_rx_start]
    jb %%header_failed
    cmp al, [ne_rx_stop]
    jae %%header_failed
    test byte [ne_rx_header], ne_rsr_prx
    jz %%release_frame
    mov al, [ne_rx_header + 2]
    mov ah, [ne_rx_header + 3]
    mov [ne_rx_count], ax
    cmp ax, ne_rx_header_len
    jbe %%count_failed
    cmp ax, ne_rx_max_count
    ja %%count_failed
    sub ax, ne_rx_header_len
    mov [ne_rx_sample_count], ax
    or ax, ax
    jz %%release_frame
    cmp ax, [ne_rx_read_limit]
    jbe %%sample_count_ready
    mov ax, [ne_rx_read_limit]
%%sample_count_ready:
    mov [ne_rx_sample_count], ax
    mov bl, ne_rx_header_len
    mov bh, [ne_next_page]
    mov cx, ax
    mov di, ne_tx_frame
    call %1
    jc %%dma_failed
%%release_frame:
    call %%release_rx_frame
    clc
    ret
%%count_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp %%release_frame
%%dma_failed:
    mov al, net_error_ne_rx_dma
    drv_jmp_res net_fail_al
%%header_failed:
    mov al, net_error_ne_rx_header
    drv_jmp_res net_fail_al
%%read_ring_pointers:
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
    jb %%selected
    mov al, [ne_rx_start]
%%selected:
    mov [ne_next_page], al
    ret
%%release_rx_frame:
    mov al, [ne_rx_header + 1]
    dec al
    cmp al, [ne_rx_start]
    jae %%write_boundary
    mov al, [ne_rx_stop]
    dec al
%%write_boundary:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_bnry
    out dx, al
    ret
%endmacro
