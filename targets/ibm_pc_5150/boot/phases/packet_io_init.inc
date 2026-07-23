%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

packet_io_init_phase:
    mov byte [handoff_addr + handoff_net_status], net_status_identity_ready
    push ds
    pop es
    call packet_io_init_phase_enable_wd_ram
    cmp byte [handoff_addr + handoff_nic_family], family_pcnet
    je .driver_init_only
    cmp byte [handoff_addr + handoff_nic_family], family_tulip
    jne .init_resident_family
.driver_init_only:
    call [nic_vt_enter]
    jc .done
    jmp .init_done
.init_resident_family:
    call [nic_vt_enter]
    call init_ne_packet_io_phase
    jc .done
.init_done:
    mov word [ne_rx_read_limit], ne_rx_sample_len
    call [nic_vt_receive]
    jc .done
    clc
.done:
    pushf
    call [nic_vt_restore]
    popf
    ret

packet_io_init_phase_enable_wd_ram:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    je .enable
    cmp byte [handoff_addr + handoff_nic_family], family_wd8013
    jne .done
.enable:
    mov dx, [handoff_addr + handoff_nic_base]
    in al, dx
    or al, wd_msr_enable_ram
    out dx, al
.done:
    ret

init_ne_packet_io_phase:
    test word [handoff_addr + handoff_flags], handoff_flag_mac_valid
    jnz .have_mac
    mov byte [handoff_addr + handoff_net_error], net_error_ne_init
    stc
    ret
.have_mac:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .check_3c503
    jmp el1_init_packet_io_phase
.check_3c503:
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    jne .pages
    phase_call_res c503_select_dp8390
.pages:
    mov byte [ne_tx_start], ne_tx_start_2k
    mov byte [ne_rx_start], ne_rx_start_2k
    mov byte [ne_rx_stop], ne_rx_stop_2k
    cmp byte [handoff_addr + handoff_nic_family], family_ne2000
    je .pages_ready
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    je .pages_wd8003
    cmp byte [handoff_addr + handoff_nic_family], family_wd8013
    jne .pages_1k
    mov byte [ne_tx_start], wd_tx_start
    mov byte [ne_rx_start], wd_rx_start
    mov byte [ne_rx_stop], wd8013_rx_stop
    jmp .pages_ready
.pages_wd8003:
    mov byte [ne_tx_start], wd_tx_start
    mov byte [ne_rx_start], wd_rx_start
    mov byte [ne_rx_stop], wd_rx_stop
    jmp .pages_ready
.pages_1k:
    mov byte [ne_tx_start], ne_tx_start_1k
    mov byte [ne_rx_start], ne_rx_start_1k
    mov byte [ne_rx_stop], ne_rx_stop_1k
.pages_ready:
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    jne .dp8390_init
    call c503_init_gate_array_phase
.dp8390_init:
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

c503_init_gate_array_phase:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_start_page
    mov al, [ne_rx_start]
    out dx, al
    inc dx
    mov al, [ne_rx_stop]
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_drq_count
    mov al, 8
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ga_config
    mov al, el2_ga_config_norm
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_da_high
    mov al, [ne_tx_start]
    out dx, al
    inc dx
    xor al, al
    out dx, al
    ret

el1_init_packet_io_phase:
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
    xor al, al
    out dx, al
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_receive
    out dx, al

    mov byte [handoff_addr + handoff_net_status], net_status_packet_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

%unmacro phase_call_res 1
