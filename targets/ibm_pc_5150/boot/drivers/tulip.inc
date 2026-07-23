; DEC Tulip PCI driver — 21040 / 21140 / 21143 / Virtual PC 21140.
; Uses one RX and one TX descriptor in a fixed below-64K bus-master workspace.
    dw nic_driver_slot + (tulip_enter - DRIVER_BASE)
    dw nic_driver_slot + (driver_noop - DRIVER_BASE)
    dw nic_driver_slot + (tulip_transmit - DRIVER_BASE)
    dw nic_driver_slot + (tulip_receive - DRIVER_BASE)
    dw nic_driver_slot + (driver_no_fallback - DRIVER_BASE)
    nic_driver_metadata

tulip_csr0 equ 0x00
tulip_csr1 equ 0x08
tulip_csr3 equ 0x18
tulip_csr4 equ 0x20
tulip_csr5 equ 0x28
tulip_csr6 equ 0x30
tulip_csr7 equ 0x38
tulip_csr9 equ 0x48
tulip_swr equ 0x0001
tulip_rx_run_tx_run_promisc equ 0x20c2
tulip_rx_own_hi equ 0x8000
tulip_rx_buf_len equ pcnet_rx_buf_len
tulip_rx_control_hi equ 0x0200
tulip_tx_control_hi equ 0x6200
tulip_csr9_sr equ 0x0800
tulip_csr9_cs equ 0x01
tulip_csr9_sk equ 0x02
tulip_csr9_di equ 0x04
tulip_csr9_do equ 0x08

tulip_enter:
    cmp byte [handoff_addr + handoff_net_status], net_status_packet_ready
    jb .init
    clc
    ret
.init:
    call tulip_read_rom_mac
    jc .failed
    cmp word [handoff_addr + handoff_ram_top], tulip_dma_end
    jb .failed

    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + tulip_csr0]
    mov ax, tulip_swr
    out dx, ax
    xor ax, ax
    out dx, ax

    call tulip_rearm_rx

    push es
    push ds
    pop es
    mov di, tulip_tx_desc
    xor ax, ax
    mov cx, 8
    rep stosw
    pop es
    mov word [tulip_tx_desc + 8], tulip_tx_buf

    lea dx, [bx + tulip_csr3]
    mov ax, tulip_rx_desc
    out dx, ax
    lea dx, [bx + tulip_csr4]
    mov ax, tulip_tx_desc
    out dx, ax
    lea dx, [bx + tulip_csr7]
    xor ax, ax
    out dx, ax
    lea dx, [bx + tulip_csr6]
    mov ax, tulip_rx_run_tx_run_promisc
    out dx, ax

    mov byte [handoff_addr + handoff_net_status], net_status_packet_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_init
    stc
    ret

tulip_transmit:
    mov bp, cx
    push es
    push ds
    pop es
    mov di, tulip_tx_buf
    rep movsb
    pop es

    mov word [tulip_tx_desc], 0
    mov word [tulip_tx_desc + 2], 0
    mov word [tulip_tx_desc + 4], bp
    mov word [tulip_tx_desc + 6], tulip_tx_control_hi
    mov word [tulip_tx_desc + 2], tulip_rx_own_hi

    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + tulip_csr1]
    mov ax, 1
    out dx, ax

    mov bp, 4
.wait_pass:
    mov cx, 0xffff
.wait_tx:
    test word [tulip_tx_desc + 2], tulip_rx_own_hi
    jz .done
    loop .wait_tx
    dec bp
    jnz .wait_pass
.done:
    clc
    ret

tulip_receive:
    mov word [ne_rx_sample_count], 0
    test word [tulip_rx_desc + 2], tulip_rx_own_hi
    jz .have_frame
    clc
    ret
.have_frame:
    test word [tulip_rx_desc], 0x8000
    jnz .rearm
    mov ax, [tulip_rx_desc]
    and ax, 0x0300
    cmp ax, 0x0300
    jne .rearm
    mov ax, [tulip_rx_desc + 2]
    and ax, 0x3fff
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
    mov si, tulip_rx_buf
    mov di, ne_tx_frame
    push es
    push ds
    pop es
    rep movsb
    pop es
.rearm:
    call tulip_rearm_rx
    clc
    ret

tulip_rearm_rx:
    mov word [tulip_rx_desc], 0
    mov word [tulip_rx_desc + 2], 0
    mov word [tulip_rx_desc + 4], tulip_rx_buf_len
    mov word [tulip_rx_desc + 6], tulip_rx_control_hi
    mov word [tulip_rx_desc + 8], tulip_rx_buf
    mov word [tulip_rx_desc + 10], 0
    mov word [tulip_rx_desc + 12], 0
    mov word [tulip_rx_desc + 14], 0
    mov word [tulip_rx_desc + 2], tulip_rx_own_hi
    ret

tulip_read_rom_mac:
    call tulip_read_direct_mac
    call tulip_validate_mac
    jnc .done
    call tulip_read_srom_mac
    call tulip_validate_mac
.done:
    ret

tulip_read_direct_mac:
    mov bx, [handoff_addr + handoff_nic_base]
    lea dx, [bx + tulip_csr9]
    xor ax, ax
    out dx, ax
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.read:
    in al, dx
    stosb
    loop .read
    ret

tulip_read_srom_mac:
    mov di, handoff_addr + handoff_mac
    mov bp, 10
    mov cx, 3
.read:
    push cx
    mov ax, bp
    call tulip_read_srom_word
    stosw
    inc bp
    pop cx
    loop .read
    ret

tulip_read_srom_word:
    xor bh, bh
    mov bl, al
    or bx, 0x0180
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, tulip_csr9
    mov ax, tulip_csr9_sr
    out dx, ax
    inc ax
    out dx, ax
    mov cx, 9
.command_bit:
    mov ax, tulip_csr9_sr | tulip_csr9_cs
    test bx, 0x0100
    jz .command_ready
    or al, tulip_csr9_di
.command_ready:
    out dx, ax
    or al, tulip_csr9_sk
    out dx, ax
    and al, 0xff ^ tulip_csr9_sk
    out dx, ax
    shl bx, 1
    loop .command_bit
    xor bx, bx
    mov cx, 16
.data_bit:
    mov ax, tulip_csr9_sr | tulip_csr9_cs | tulip_csr9_sk
    out dx, ax
    in ax, dx
    shl bx, 1
    test al, tulip_csr9_do
    jz .data_ready
    inc bx
.data_ready:
    mov ax, tulip_csr9_sr | tulip_csr9_cs
    out dx, ax
    loop .data_bit
    mov ax, tulip_csr9_sr
    out dx, ax
    mov ax, bx
    ret

tulip_validate_mac:
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
