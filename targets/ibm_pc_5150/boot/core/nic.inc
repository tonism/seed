wd_enable_shared_ram:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .done
    mov dx, [handoff_addr + handoff_nic_base]
    in al, dx
    or al, wd_msr_enable_ram
    out dx, al
.done:
    ret

wd_select_dp8390_base:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .done
    add word [handoff_addr + handoff_nic_base], wd_dp8390_offset
.done:
    ret

wd_restore_dp8390_base:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .done
    sub word [handoff_addr + handoff_nic_base], wd_dp8390_offset
.done:
    ret

init_ne_packet_io:
    test word [handoff_addr + handoff_flags], handoff_flag_mac_valid
    jnz .have_mac
    mov byte [handoff_addr + handoff_net_error], net_error_ne_init
    stc
    ret
.have_mac:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .check_3c503
    jmp el1_init_packet_io
.check_3c503:
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    jne .pages
    call c503_select_dp8390
.pages:
    mov byte [ne_tx_start], ne_tx_start_2k
    mov byte [ne_rx_start], ne_rx_start_2k
    mov byte [ne_rx_stop], ne_rx_stop_2k
    cmp byte [handoff_addr + handoff_nic_family], family_ne2000
    je .pages_ready
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .pages_1k
    mov byte [ne_tx_start], wd_tx_start
    mov byte [ne_rx_start], wd_rx_start
    mov byte [ne_rx_stop], wd_rx_stop
    jmp .pages_ready
.pages_1k:
    mov byte [ne_tx_start], ne_tx_start_1k
    mov byte [ne_rx_start], ne_rx_start_1k
    mov byte [ne_rx_stop], ne_rx_stop_1k
.pages_ready:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_stop_nodma
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_dcr
    mov al, ne_dcr_bytewide
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rbcr0
    xor al, al
    out dx, al
    inc dx
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rcr
    mov al, ne_rcr_broadcast
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_tcr
    mov al, ne_tcr_loopback
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    inc dx
    mov al, [ne_rx_start]
    out dx, al
    inc dx
    mov al, [ne_rx_stop]
    out dx, al
    inc dx
    mov al, [ne_rx_start]
    out dx, al
    inc dx
    mov al, [ne_tx_start]
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    mov al, 0xff
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_imr
    xor al, al
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_page1
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    inc dx
    mov si, handoff_addr + handoff_mac
    mov cx, 6
.write_mac:
    lodsb
    out dx, al
    inc dx
    loop .write_mac

    mov al, [ne_rx_start]
    inc al
    out dx, al

    inc dx
    xor al, al
    mov cx, 8
.clear_mar:
    out dx, al
    inc dx
    loop .clear_mar

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_nodma
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_tcr
    xor al, al
    out dx, al

    mov byte [handoff_addr + handoff_net_status], net_status_packet_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

c503_select_dp8390:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    mov al, el2_ctrl_thin
    out dx, al
    ret

el1_init_packet_io:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_reset
    out dx, al
    mov al, el1_aux_system
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    mov si, handoff_addr + handoff_mac
    mov cx, 6
.mac:
    lodsb
    out dx, al
    inc dx
    loop .mac

    mov al, el1_rx_cmd_bcast_good
    out dx, al
    inc dx
    mov al, el1_tx_cmd_success
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_rcvptr
    out dx, al
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_receive
    out dx, al

    mov byte [handoff_addr + handoff_net_status], net_status_packet_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
