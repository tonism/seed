start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, runtime_stack_top
    sti
    cld

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
    mov byte [handoff_addr + handoff_status], handoff_status_no_nic
    mov bl, [error_attr]
    mov al, [load_marker_char]
    call show_load_marker

    inc byte [cursor_col]
    call notify_failure
    mov si, network_error_text
    call type_z
    call ask_failure_action
    jmp halt

network_setup_error:
    mov byte [handoff_addr + handoff_status], handoff_status_network_failed
    mov bl, [error_attr]
    mov al, [load_marker_char]
    call show_load_marker

    inc byte [cursor_col]
    call notify_failure
    mov si, network_setup_error_text
    call type_z
    call ask_failure_action
    jmp halt

agent_setup_error:
    mov byte [handoff_addr + handoff_status], handoff_status_agent_failed
    mov bl, [error_attr]
    mov al, [load_marker_char]
    call show_load_marker

    inc byte [cursor_col]
    call notify_failure
    mov si, agent_setup_error_text
    call type_z
    call ask_failure_action
    jmp halt

set_seed_cursor:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    mov [cursor_col], al
    ret
