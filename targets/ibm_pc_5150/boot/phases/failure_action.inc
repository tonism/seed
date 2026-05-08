%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

failure_action_phase:
    mov bl, [error_attr]
    mov al, [load_marker_char]
    phase_call_res show_load_marker
    inc byte [cursor_col]
    call failure_action_phase_notify_failure
    mov bl, [error_attr]
    call .message_ptr
    call failure_action_phase_type_z
    mov byte [menu_index], 0
    call .type_failure_options
    call .flush_keys
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
    call .draw_failure_options
    jmp .input
.accept:
    cmp byte [menu_index], 0
    je .retry
    mov word [0x0472], 0x1234
    jmp 0xffff:0x0000
.retry:
    ret

.flush_keys:
    mov ah, 0x01
    int 0x16
    jz .flush_done
    xor ah, ah
    int 0x16
    jmp .flush_keys
.flush_done:
    ret

.message_ptr:
    mov si, low_scratch_start + (agent_setup_error_text - PHASE_BASE)
    cmp byte [handoff_addr + handoff_status], handoff_status_agent_failed
    je .message_done
    mov si, low_scratch_start + (network_setup_error_text - PHASE_BASE)
    cmp byte [handoff_addr + handoff_status], handoff_status_network_failed
    je .message_done
    mov si, low_scratch_start + (network_error_text - PHASE_BASE)
.message_done:
    ret

.type_failure_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_selected_attr]
    mov si, low_scratch_start + (retry_text - PHASE_BASE)
    call failure_action_phase_type_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov si, low_scratch_start + (restart_text - PHASE_BASE)
    call failure_action_phase_type_z
    ret

.draw_failure_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 0
    jne .draw_retry
    mov bl, [menu_selected_attr]
.draw_retry:
    mov si, low_scratch_start + (retry_text - PHASE_BASE)
    call .print_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 1
    jne .draw_restart
    mov bl, [menu_selected_attr]
.draw_restart:
    mov si, low_scratch_start + (restart_text - PHASE_BASE)
    call .print_z
    ret

.print_z:
    lodsb
    or al, al
    jz .print_done
    phase_call_res print_char
    jmp .print_z
.print_done:
    ret

failure_action_phase_type_z:
    lodsb
    or al, al
    jz .type_done
    call failure_action_phase_type_char
    jmp failure_action_phase_type_z
.type_done:
    ret

failure_action_phase_type_char:
    phase_call_res print_char
    mov cx, type_ticks
    phase_call_res wait_ticks
    ret

network_error_text db 'no network card', 0
network_setup_error_text db 'network setup failed', 0
agent_setup_error_text db 'agent setup failed', 0
retry_text db 'retry', 0
restart_text db 'restart', 0

failure_action_phase_notify_failure:
    mov ax, 5424
    call failure_action_phase_speaker_tone
    mov cx, 2
    phase_call_res wait_ticks
    mov ax, 7231
    call failure_action_phase_speaker_tone
    mov cx, 3
    phase_call_res wait_ticks
    jmp failure_action_phase_speaker_off

failure_action_phase_speaker_tone:
    push ax
    mov al, 0xb6
    out 0x43, al
    pop ax
    out 0x42, al
    mov al, ah
    out 0x42, al
    in al, 0x61
    or al, 0x03
    out 0x61, al
    ret

failure_action_phase_speaker_off:
    in al, 0x61
    and al, 0xfc
    out 0x61, al
    ret

%unmacro phase_call_res 1
