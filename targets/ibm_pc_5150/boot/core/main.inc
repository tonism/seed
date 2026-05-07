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

    call init_handoff
    call init_phase_services
    call detect_display
    call clear_screen
    call hide_cursor
    call load_noop_phase
    jc network_setup_error
    cmp byte [phase_probe], 0x5a
    jne network_setup_error

hal_start:
    call clear_question_area
    call reset_hal_state
    mov bl, [load_attr]
    mov al, '.'
    call show_load_marker
    call probe_network_card
    jc network_error

    call resolve_network_config
    call read_network_address
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
    mov cx, load_ticks
    call wait_ticks

    call set_seed_cursor
    mov si, seed_text
    mov bl, [seed_attr]
    call type_z

    mov al, ' '
    mov bl, [build_attr]
    call type_char

    mov si, build_text
    call type_z

    mov cx, done_ticks
    call wait_ticks

halt:
    hlt
    jmp halt

network_error:
    mov al, handoff_status_no_nic
    mov si, network_error_text
    jmp show_failure

network_setup_error:
    mov al, handoff_status_network_failed
    mov si, network_setup_error_text
    jmp show_failure

agent_setup_error:
    mov al, handoff_status_agent_failed
    mov si, agent_setup_error_text

show_failure:
    mov [handoff_addr + handoff_status], al
    mov bl, [error_attr]
    mov al, [load_marker_char]
    call show_load_marker

    inc byte [cursor_col]
    call notify_failure
    call type_z
    call ask_failure_action
    jmp halt

set_seed_cursor:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    mov [cursor_col], al
    ret

load_noop_phase:
    push ds
    pop es
    mov bx, low_scratch_start
    mov ax, [core_header_resident_sectors]
    add ax, fat_data_start_lba
    call read_abs_sector
    jc .done
    call low_scratch_start
.done:
    ret

run_save_user_cfg_phase:
    push ds
    pop es
    mov bx, low_scratch_start
    mov ax, (core_save_phase_start - $$) / 512
    add ax, fat_data_start_lba
    call read_abs_sector
    jc .done
    call low_scratch_start
.done:
    clc
    ret

init_phase_services:
    mov word [phase_svc_probe_ok], phase_probe_ok
    ret

phase_probe_ok:
    mov byte [phase_probe], 0x5a
    ret
