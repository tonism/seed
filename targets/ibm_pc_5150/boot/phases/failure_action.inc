%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

; Build 12 UI unification: terminal-style failure handling. The normal splash phase has already
; drawn the banner, so this phase only appends the setup/connect failure UI below it. The system
; reports the error as a DIM "> "-prefixed line (message + net code), then asks "retry or restart?"
; as a terminal numbered list -- answered exactly like the provider list: type a number OR the full
; name, Enter; anything else -> dim "> incorrect option", re-prompt. Keeps the two-tone failure beep.
failure_action_phase:
    call failure_action_phase_notify_failure
    ; dim "> "-prefixed system error line (message + net code), drawn once
    call .newline
    mov bl, [menu_idle_attr]
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    call .message_ptr
    mov bl, [menu_idle_attr]
    call .print_msg
    call .type_net_code
.retry_prompt:
    call .newline
    call .newline                              ; blank line below the system message / previous prompt
    mov si, low_scratch_start + (retry_question_text - PHASE_BASE)
    mov bl, 0x07
    call .print_msg
    mov al, '1'
    mov si, low_scratch_start + (retry_text - PHASE_BASE)
    call .option_line
    mov al, '2'
    mov si, low_scratch_start + (restart_text - PHASE_BASE)
    call .option_line
    call .newline
    call .newline                              ; blank line before the prompt
    call .read_line
    ; validate: a single digit 1 (retry) / 2 (restart)?
    cmp byte [input_len], 1
    jne .by_name
    mov al, [dpi_input_buf]
    cmp al, '1'
    je .do_retry
    cmp al, '2'
    je .do_restart
.by_name:
    mov si, low_scratch_start + (retry_text - PHASE_BASE)
    mov di, dpi_input_buf
    call .streq
    je .do_retry
    mov si, low_scratch_start + (restart_text - PHASE_BASE)
    mov di, dpi_input_buf
    call .streq
    je .do_restart
    call .newline
    mov bl, [menu_idle_attr]
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    mov si, low_scratch_start + (fail_incorrect_text - PHASE_BASE)
    mov bl, [menu_idle_attr]
    call .print_msg
    jmp .retry_prompt
.do_retry:
    ret
.do_restart:
    mov word [0x0472], 0x1234
    jmp 0xffff:0x0000                           ; warm reboot

.option_line:                                  ; al = digit, si = label -> newline + "N. label" (normal)
    push ax                                     ; .newline clobbers al -- save the digit
    call .newline
    pop ax
    push si
    mov bl, 0x07
    phase_call_res print_char
    mov al, '.'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    pop si
    mov bl, 0x07
    call .print_msg
    ret

.read_line:                                    ; read a line into dpi_input_buf; text echoes white; Enter
    mov word [input_target], dpi_input_buf     ; finishes and erases the "> " marker (DPI-style)
    mov byte [input_max], 8
    mov byte [input_len], 0
    mov byte [dpi_input_buf], 0
    call .show_cursor
    mov al, [cursor_row]
    mov [menu_index], al
    mov bl, [ready_attr]
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
.read_key_loop:
    call .sync_cursor
    xor ah, ah
    int 0x16
    cmp al, 0x0d
    je .read_line_done
    cmp al, 0x08
    je .read_backspace
    cmp al, 0x20
    jb .read_key_loop
    cmp al, 0x7e
    ja .read_key_loop
    mov bl, [input_len]
    xor bh, bh
    mov dl, [input_max]
    dec dl
    cmp bl, dl
    jae .read_key_loop
    mov di, [input_target]
    add di, bx
    mov [di], al
    inc byte [input_len]
    mov byte [di + 1], 0
    mov bl, 0x0f
    phase_call_res print_char
    jmp .read_key_loop
.read_backspace:
    cmp byte [input_len], 0
    je .read_key_loop
    dec byte [input_len]
    mov bl, [input_len]
    xor bh, bh
    mov di, [input_target]
    add di, bx
    mov byte [di], 0
    dec byte [cursor_col]
    mov al, ' '
    mov bl, 0x0f
    phase_call_res print_char
    dec byte [cursor_col]
    jmp .read_key_loop
.read_line_done:
    call .hide_cursor
    mov al, [cursor_row]
    mov ah, [cursor_col]
    push ax
    mov al, [menu_index]
    mov [cursor_row], al
    mov byte [cursor_col], 0
    mov al, ' '
    mov bl, 0x07
    phase_call_res print_char
    pop ax
    mov [cursor_row], al
    mov [cursor_col], ah
    call .newline
    ret

.streq:                                        ; compare [ds:si] vs [ds:di] (NUL-term) -> ZF=1 if equal
    push si
    push di
.streq_loop:
    mov al, [si]
    cmp al, [di]
    jne .streq_done
    or al, al
    jz .streq_done
    inc si
    inc di
    jmp .streq_loop
.streq_done:
    pop di
    pop si
    ret

.message_ptr:                                  ; si = the error text for the current handoff_status
    mov si, low_scratch_start + (agent_setup_error_text - PHASE_BASE)
    cmp byte [handoff_addr + handoff_status], handoff_status_agent_failed
    je .message_done
    mov si, low_scratch_start + (network_setup_error_text - PHASE_BASE)
    cmp byte [handoff_addr + handoff_status], handoff_status_network_failed
    jne .not_network_setup
    cmp byte [handoff_addr + handoff_net_error], net_error_driver
    jne .message_done
    mov si, low_scratch_start + (driver_setup_error_text - PHASE_BASE)
    jmp .message_done
.not_network_setup:
    mov si, low_scratch_start + (network_error_text - PHASE_BASE)
.message_done:
    ret

.type_net_code:                                ; " NN/NN" net error code, dim -- only on a network/agent fail
    cmp byte [handoff_addr + handoff_status], handoff_status_agent_failed
    je .net_code
    cmp byte [handoff_addr + handoff_status], handoff_status_network_failed
    jne .net_code_done
.net_code:
    mov al, ' '
    mov bl, [menu_idle_attr]
    phase_call_res print_char
    mov al, [handoff_addr + handoff_net_error]
    call .type_hex_byte
    mov al, '/'
    mov bl, [menu_idle_attr]
    phase_call_res print_char
    mov al, [handoff_addr + handoff_net_status]
    call .type_hex_byte
.net_code_done:
    ret

.type_hex_byte:                                ; al -> two hex chars, dim
    push ax
    shr al, 1
    shr al, 1
    shr al, 1
    shr al, 1
    call .type_hex_nibble
    pop ax
    and al, 0x0f
.type_hex_nibble:
    add al, '0'
    cmp al, '9'
    jbe .hex_ready
    add al, 7
.hex_ready:
    mov bl, [menu_idle_attr]
    phase_call_res print_char
    ret

.print_msg:                                    ; print NUL-terminated [ds:si] in attr bl (caller sets bl)
    lodsb
    or al, al
    jz .print_msg_done
    phase_call_res print_char
    jmp .print_msg
.print_msg_done:
    ret

.show_cursor:
    mov cx, 0x0607
    jmp .apply_cursor_shape
.hide_cursor:
    mov cx, 0x2000
.apply_cursor_shape:
    mov ah, 0x01
    int 0x10
    ret

.sync_cursor:
    mov ah, 0x02
    xor bh, bh
    mov dh, [cursor_row]
    mov dl, [cursor_col]
    int 0x10
    ret

.newline:
    mov byte [cursor_col], 0
    mov al, [cursor_row]
    cmp al, dpi_prompt_row
    jb .newline_down
    mov ax, 0x0601
    mov cx, 0x0100
    phase_call_res scroll_text_area
    ret
.newline_down:
    inc byte [cursor_row]
    ret

network_error_text db 'no network card', 0
network_setup_error_text db 'network setup failed', 0
driver_setup_error_text db 'driver setup failed', 0
agent_setup_error_text db 'agent setup failed', 0
retry_question_text db 'retry or restart?', 0
retry_text db 'retry', 0
restart_text db 'restart', 0
fail_incorrect_text db 'incorrect option', 0
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
