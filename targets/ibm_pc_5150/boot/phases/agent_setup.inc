%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

; Build 12 UI unification: terminal-style config as a chat exchange. The system asks with a normal-color
; message (like a model turn -- red for an error), a blank line, then a "> " prompt where the user types
; (bright white, like a chat user message); on Enter the "> " marker is erased (as the DPI does) so the
; submitted line reads as the user's message, and a blank line separates it from the next turn. The agent
; field is a numbered list: type a number OR the full name; anything else -> red "incorrect option",
; re-prompt. Flows below the banner (drawn early); no absolute positioning / menu / slide.
agent_setup_phase:
    call agent_setup_phase_clear_seed_values
    call .ask_agent
    or byte [seed_config_flags], seed_flag_agent
    call agent_setup_phase_selected_agent_needs_endpoint
    jc .ask_key
    mov si, low_scratch_start + (server_question_text - PHASE_BASE)
    mov di, seed_endpoint
    mov byte [input_max], seed_endpoint_len
    call .ask_free
    or byte [seed_config_flags], seed_flag_endpoint
.ask_key:
    mov si, low_scratch_start + (key_question_text - PHASE_BASE)
    mov di, seed_key
    mov byte [input_max], seed_key_len
    call .ask_free
    or byte [seed_config_flags], seed_flag_key
    mov byte [user_cfg_dirty], 1
    clc
    ret

; ---- agent: numbered-list selection (a number OR the full name), re-prompt on an invalid answer ----
.ask_agent:
    mov word [input_target], seed_agent_id
    mov byte [input_max], agent_id_len
.ask_agent_retry:
    call .newline                              ; blank line separating this turn from the previous
    mov si, low_scratch_start + (agent_question_text - PHASE_BASE)
    mov bl, 0x07
    call .print_msg
    mov byte [agent_draw_index], 0
.ask_agent_list:
    mov al, [agent_draw_index]
    cmp al, [agent_count]
    jae .ask_agent_list_done
    call .newline
    mov bl, 0x07
    mov al, [agent_draw_index]
    add al, '1'
    phase_call_res print_char
    mov al, '.'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    mov al, [agent_draw_index]
    call .agent_ptr
    mov bl, 0x07
    call .print_msg
    inc byte [agent_draw_index]
    jmp .ask_agent_list
.ask_agent_list_done:
    call .newline
    call .newline                              ; blank line between the message and the prompt
    call .read_line
    ; validate -- a single digit 1..agent_count?
    cmp byte [input_len], 1
    jne .ask_agent_by_name
    mov al, [seed_agent_id]
    sub al, '1'
    jb .ask_agent_by_name
    cmp al, [agent_count]
    jae .ask_agent_by_name
    call .agent_ptr                            ; si = agent_ids[al]
    mov di, seed_agent_id
    call .copy_z
    ret
.ask_agent_by_name:
    mov byte [agent_draw_index], 0
.ask_agent_name_loop:
    mov al, [agent_draw_index]
    cmp al, [agent_count]
    jae .ask_agent_invalid
    call .agent_ptr
    mov di, seed_agent_id
    call .streq
    je .ask_agent_ok                           ; typed name matches an option -> keep it
    inc byte [agent_draw_index]
    jmp .ask_agent_name_loop
.ask_agent_ok:
    ret
.ask_agent_invalid:
    call .newline
    mov bl, 0x08                               ; dim system message (dark style), "> "-prefixed like the chat
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    mov si, low_scratch_start + (incorrect_text - PHASE_BASE)
    mov bl, 0x08
    call .print_msg
    call .newline                              ; blank line between the system message and the agent's re-ask
    jmp .ask_agent_retry

; ---- free-text field (key / server): message, blank line, "> " prompt ----
.ask_free:
    mov [input_target], di
    call .newline                              ; blank line separating this turn from the previous
    mov bl, 0x07
    call .print_msg
    call .newline
    call .newline                              ; blank line between the message and the prompt
    call .read_line
    ret

; ---- read a line into [input_target] (max [input_max]); the user's text echoes bright white; Enter
; finishes and erases the "> " marker (like the DPI), leaving the submitted line as the user's message ----
.read_line:
    mov byte [input_len], 0
    mov di, [input_target]
    mov byte [di], 0
    mov al, [cursor_row]
    mov [menu_index], al                       ; remember the "> " marker row (to erase it on submit)
    mov bl, [ready_attr]
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
.read_key_loop:
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
    mov bl, 0x0f                               ; the user's typed text is bright white
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
    ; erase the "> " marker (DPI-style): save the end cursor, go to the marker row col 0, print a space
    ; over the '>', restore, then break to the next line so the submitted line reads as the user's message.
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

.agent_ptr:                                    ; al = index -> si = agent_ids + index*16
    xor ah, ah
    mov si, ax
    shl si, 1
    shl si, 1
    shl si, 1
    shl si, 1
    add si, agent_ids
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

.print_msg:                                    ; print NUL-terminated [ds:si] in attr bl (caller sets bl)
    lodsb
    or al, al
    jz .print_msg_done
    phase_call_res print_char
    jmp .print_msg
.print_msg_done:
    ret

.copy_z:                                        ; copy NUL-terminated [ds:si] -> [ds:di]
    lodsb
    mov [di], al
    inc di
    or al, al
    jnz .copy_z
    ret

.newline:
    mov byte [cursor_col], 0
    mov al, [cursor_row]
    cmp al, dpi_prompt_row
    jb .newline_down
    mov ax, 0x0601                             ; at the bottom: scroll the terminal up one line
    mov cx, 0x0100
    phase_call_res scroll_text_area
    ret
.newline_down:
    inc byte [cursor_row]
    ret

agent_question_text db 'which provider?', 0
key_question_text db 'api key:', 0
server_question_text db 'server url?', 0
incorrect_text db 'incorrect option', 0

agent_setup_phase_clear_seed_values:
    push es
    push ds
    pop es
    xor ax, ax
    mov di, seed_agent_id
    mov cx, seed_value_total_len / 2
    rep stosw
    mov byte [seed_config_flags], 0
    mov byte [user_cfg_dirty], 0
    pop es
    ret

agent_setup_phase_selected_agent_needs_endpoint:
    cmp byte [seed_agent_id], 'l'
    jne .no
    clc
    ret
.no:
    stc
    ret

%unmacro phase_call_res 1
