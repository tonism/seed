start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, runtime_stack_top
    sti
    cld

    mov ax, [0x046c]
    mov [debug_start_tick], ax
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

    call type_debug_elapsed
    call type_debug_milestones

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
    mov si, agent_fail_short_text
    call type_z
    mov al, ' '
    call type_char
    mov al, [handoff_addr + handoff_net_status]
    call type_hex_byte
    mov al, '/'
    call type_char
    mov al, [handoff_addr + handoff_net_error]
    call type_hex_byte
    mov al, ' '
    call type_char
    mov al, [tls_debug_stage]
    call type_hex_byte
    mov al, '/'
    call type_char
    mov al, [tls_debug_detail]
    call type_hex_byte
    mov al, ' '
    call type_char
    mov al, [api_debug_records]
    call type_hex_byte
    mov al, '/'
    call type_char
    mov al, [api_debug_first]
    call type_hex_byte
    call type_debug_elapsed
    call type_debug_milestones
    call ask_failure_action
    jmp halt

set_seed_cursor:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    mov [cursor_col], al
    ret

type_hex_byte:
    push ax
    shr al, 1
    shr al, 1
    shr al, 1
    shr al, 1
    call type_hex_nibble
    pop ax
    and al, 0x0f
    call type_hex_nibble
    ret

type_hex_nibble:
    cmp al, 10
    jb .digit
    add al, 'a' - 10
    jmp .type
.digit:
    add al, '0'
.type:
    call type_char
    ret

type_debug_elapsed:
    mov al, ' '
    call type_char
    mov al, 't'
    call type_char
    call debug_elapsed_ax
    call type_hex_word
    ret

debug_elapsed_ax:
    mov ax, [0x046c]
    sub ax, [debug_start_tick]
    ret

type_debug_milestones:
    mov byte [cursor_row], question_row + 4
    mov byte [cursor_col], 0
    mov bl, [error_attr]
    mov al, 'h'
    call type_char
    mov ax, [debug_tick_hello_done]
    call type_hex_word
    mov al, ' '
    call type_char
    mov al, 'p'
    call type_char
    mov ax, [debug_tick_premaster]
    call type_hex_word
    mov al, ' '
    call type_char
    mov al, 'm'
    call type_char
    mov ax, [debug_tick_master]
    call type_hex_word
    mov al, ' '
    call type_char
    mov al, 'k'
    call type_char
    mov ax, [debug_tick_keyblock]
    call type_hex_word
    mov al, ' '
    call type_char
    mov al, 'f'
    call type_char
    mov ax, [debug_tick_finished]
    call type_hex_word
    mov al, ' '
    call type_char
    mov al, 's'
    call type_char
    mov ax, [debug_tick_server_finished]
    call type_hex_word
    mov al, ' '
    call type_char
    mov al, 'r'
    call type_char
    mov ax, [debug_tick_request_sent]
    call type_hex_word
    ret

type_hex_word:
    push ax
    mov al, ah
    call type_hex_byte
    pop ax
    call type_hex_byte
    ret
