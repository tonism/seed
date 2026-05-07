reset_hal_state:
    and word [handoff_addr + handoff_flags], handoff_flag_mda
    mov di, handoff_addr + handoff_nic_base
    xor ax, ax
    mov cx, (handoff_size_bytes - handoff_nic_base) / 2
    rep stosw
    mov byte [handoff_addr + handoff_status], handoff_status_booting
    mov byte [blink_state], 0
    ret

prepare_hal_path:
    mov byte [handoff_addr + handoff_net_status], net_status_identity_ready
    call selected_nic_has_packet_path
    jnc .packet
    clc
    ret
.packet:
    push ds
    pop es
    call wd_enable_shared_ram
    call wd_select_dp8390_base
    call init_ne_packet_io
    jc .done
    mov word [ne_rx_read_limit], ne_rx_sample_len
    call ne_try_receive_frame
    jc .done
    clc
.done:
    pushf
    call wd_restore_dp8390_base
    popf
    ret
