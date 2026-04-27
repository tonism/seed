ask_adapter:
    mov byte [menu_index], 0
    mov byte [blink_state], 0
    call notify_question
    call render_adapter_question
.input:
    call blink_load_marker
    mov ah, 0x01
    int 0x16
    jz .input
    xor ah, ah
    int 0x16
    cmp al, 0x0d
    je .accept
    cmp ah, 0x48
    je .toggle
    cmp ah, 0x50
    jne .input
.toggle:
    xor byte [menu_index], 1
    call draw_menu_options
    jmp .input
.accept:
    mov al, [menu_value_a]
    cmp byte [menu_index], 0
    je .store
    mov al, [menu_value_b]
.store:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_user
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    call clear_question_area
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    call show_load_marker
    ret

ask_failure_action:
    mov word [menu_option_a], retry_text
    mov word [menu_option_b], restart_text
    mov byte [menu_index], 0
    call type_menu_options
.input:
    hlt
    mov ah, 0x01
    int 0x16
    jz .input
    xor ah, ah
    int 0x16
    cmp al, 0x0d
    je .accept
    cmp ah, 0x48
    je .toggle
    cmp ah, 0x50
    jne .input
.toggle:
    xor byte [menu_index], 1
    call draw_menu_options
    jmp .input
.accept:
    cmp byte [menu_index], 0
    jne restart_machine
    jmp hal_start

restart_machine:
    mov word [0x0472], 0x1234
    jmp 0xffff:0x0000
