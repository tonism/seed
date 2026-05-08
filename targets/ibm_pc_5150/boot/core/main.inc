start:
    cli
    mov bp, runtime_stack_top
    cmp bx, basic_boot_magic_bx
    jne .stack_ready
    cmp cx, basic_boot_magic_cx
    jne .stack_ready
    mov bp, ax
.stack_ready:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, bp
    sti
    cld

    call clear_high_crypto_scratch
    call clear_critical_scratch
    call init_handoff
    call detect_display
    call clear_screen
    call hide_cursor

hal_start:
    call clear_question_area
    call reset_hal_state
    mov bl, [load_attr]
    mov al, '.'
    call show_load_marker
    call run_hardware_setup_phase
    jc network_error

    call prepare_hal_path
    jc network_setup_error

    mov bl, [load_attr]
    mov al, ','
    call show_load_marker
    call prepare_internet_path
    jc network_setup_error

    mov bl, [load_attr]
    mov al, 'o'
    call show_load_marker
    call prepare_agent_path
    jc agent_setup_error
    mov byte [handoff_addr + handoff_status], handoff_status_ready
    call run_splash_phase

halt:
    hlt
    jmp halt

network_error:
    mov al, handoff_status_no_nic
    jmp show_failure

network_setup_error:
    mov al, handoff_status_network_failed
    jmp show_failure

agent_setup_error:
    mov al, handoff_status_agent_failed

show_failure:
    mov [handoff_addr + handoff_status], al
    mov bl, [error_attr]
    mov al, [load_marker_char]
    call show_load_marker

    call run_failure_phase
    or al, al
    jz hal_start
    mov word [0x0472], 0x1234
    jmp 0xffff:0x0000

set_seed_cursor:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    mov [cursor_col], al
    ret

run_save_user_cfg_phase:
    mov al, (core_save_phase_start - $$) / 512
    mov cl, (core_save_phase_end - core_save_phase_start + 511) / 512
    jmp run_core_phase

run_hardware_setup_phase:
    mov al, (core_hardware_setup_phase_start - $$) / 512
    mov cl, (core_hardware_setup_phase_end - core_hardware_setup_phase_start + 511) / 512
    jmp run_core_phase

run_packet_io_init_phase:
    mov al, (core_packet_io_init_phase_start - $$) / 512
    mov cl, (core_packet_io_init_phase_end - core_packet_io_init_phase_start + 511) / 512
    jmp run_core_phase

run_failure_phase:
    mov al, (core_failure_phase_start - $$) / 512
    mov cl, (core_failure_phase_end - core_failure_phase_start + 511) / 512
    jmp run_core_phase

run_dhcp_setup_phase:
    mov al, (core_dhcp_setup_phase_start - $$) / 512
    mov cl, (core_dhcp_setup_phase_end - core_dhcp_setup_phase_start + 511) / 512
    mov bx, net_setup_phase_start
    jmp run_core_phase_at

run_tcp_connect_phase:
    mov al, (core_tcp_connect_phase_start - $$) / 512
    mov cl, (core_tcp_connect_phase_end - core_tcp_connect_phase_start + 511) / 512
    mov bx, net_setup_phase_start
    jmp run_core_phase_at

run_tls_client_hello_phase:
    mov al, (core_tls_client_hello_phase_start - $$) / 512
    mov cl, (core_tls_client_hello_phase_end - core_tls_client_hello_phase_start + 511) / 512
    jmp run_core_phase

run_net_probe_cfg_phase:
    mov al, (core_probe_cfg_phase_start - $$) / 512
    mov cl, (core_probe_cfg_phase_end - core_probe_cfg_phase_start + 511) / 512
    jmp run_core_phase

run_agents_cfg_phase:
    mov al, (core_agents_cfg_phase_start - $$) / 512
    mov cl, (core_agents_cfg_phase_end - core_agents_cfg_phase_start + 511) / 512
    jmp run_core_phase

run_user_cfg_phase:
    mov al, (core_user_cfg_phase_start - $$) / 512
    mov cl, (core_user_cfg_phase_end - core_user_cfg_phase_start + 511) / 512
    jmp run_core_phase

run_agent_setup_phase:
    mov al, (core_agent_setup_phase_start - $$) / 512
    mov cl, (core_agent_setup_phase_end - core_agent_setup_phase_start + 511) / 512
    jmp run_core_phase

run_agent_request_phase:
    mov al, (core_agent_request_phase_start - $$) / 512
    mov cl, (core_agent_request_phase_end - core_agent_request_phase_start + 511) / 512
    jmp run_core_phase

run_agent_endpoint_phase:
    mov al, (core_agent_endpoint_phase_start - $$) / 512
    mov cl, (core_agent_endpoint_phase_end - core_agent_endpoint_phase_start + 511) / 512
    jmp run_core_phase

run_agent_response_phase:
    mov al, (core_agent_response_phase_start - $$) / 512
    mov cl, (core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512
    jmp run_core_phase

run_splash_phase:
    mov al, (core_splash_phase_start - $$) / 512
    mov cl, (core_splash_phase_end - core_splash_phase_start + 511) / 512
    jmp run_core_phase

run_core_phase:
    mov bx, low_scratch_start

run_core_phase_at:
    push bx
    xor ah, ah
    xor ch, ch
    push ds
    pop es
    add ax, fat_data_start_lba
.next_sector:
    call read_abs_sector
    jc .read_failed
    add bx, 512
    inc ax
    loop .next_sector
    push ds
    pop es
    pop bx
    call bx
.done:
    ret
.read_failed:
    pop bx
    ret

clear_critical_scratch:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, critical_scratch_start
    mov cx, critical_scratch_len / 2
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret

clear_high_crypto_scratch:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, high_crypto_scratch_start
    mov cx, (high_crypto_scratch_end - high_crypto_scratch_start) / 2
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret
