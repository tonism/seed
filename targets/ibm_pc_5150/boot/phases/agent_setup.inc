%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

agent_setup_phase:
.select:
    call agent_setup_phase_clear_seed_values
    call .ask_agent
.values:
    call .ask_agent_values
    jnc .setup_done
    call agent_setup_phase_clear_seed_values
    call .ask_agent_resume
    jmp .values
.setup_done:
    ret

.ask_agent_values:
    mov byte [menu_value_a], 0
    mov byte [blink_state], 0
.render:
    call .clear_agent_field_area
    call .render_agent_values_form
    call .set_active_form_input
    phase_call_res show_cursor
.input:
    call .input_wait_key
    cmp al, 0x0d
    je .accept
    cmp al, 0x08
    je .backspace
    cmp al, 0x1b
    je .cancel
    cmp ah, 0x48
    je .previous
    cmp ah, 0x50
    je .next
    cmp al, 0x20
    jb .input
    cmp al, 0x7e
    ja .input
    mov dl, [input_max]
    dec dl
    cmp [input_len], dl
    jae .input
    call .input_store_char
    jmp .input
.backspace:
    call .input_backspace
    jmp .input
.previous:
.next:
    call agent_setup_phase_selected_agent_needs_endpoint
    jc .input
    xor byte [menu_value_a], 1
    call .draw_agent_form_fields
    call .set_active_form_input
    phase_call_res show_cursor
    jmp .input
.accept:
    call .validate_agent_values
    jc .render
    phase_call_res hide_cursor
    phase_call_res clear_question_area
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    phase_call_res show_load_marker
    clc
    ret
.cancel:
    phase_call_res hide_cursor
    call .slide_selected_agent_right
    stc
    ret

.validate_agent_values:
    call agent_setup_phase_selected_agent_needs_endpoint
    jc .check_key
    cmp byte [seed_endpoint], 0
    jne .check_key
    mov byte [menu_value_a], 0
    stc
    ret
.check_key:
    cmp byte [seed_key], 0
    jne .valid
    call agent_setup_phase_selected_agent_needs_endpoint
    jc .key_focus
    mov byte [menu_value_a], 1
    jmp .invalid
.key_focus:
    mov byte [menu_value_a], 0
.invalid:
    stc
    ret
.valid:
    or byte [seed_config_flags], seed_flag_key
    call agent_setup_phase_selected_agent_needs_endpoint
    jc .validated
    or byte [seed_config_flags], seed_flag_endpoint
.validated:
    mov byte [user_cfg_dirty], 1
    clc
    ret

.set_active_form_input:
    call agent_setup_phase_selected_agent_needs_endpoint
    jc .key
    cmp byte [menu_value_a], 0
    jne .key
    mov di, seed_endpoint
    mov al, seed_endpoint_len
    mov dl, question_row
    add dl, [menu_index]
    jmp .set
.key:
    mov di, seed_key
    mov al, seed_key_len
    mov dl, question_row
    add dl, [menu_index]
    call agent_setup_phase_selected_agent_needs_endpoint
    jc .set
    inc dl
.set:
    mov [input_target], di
    mov [input_max], al
    call .measure_input_len
    mov [cursor_row], dl
    mov al, [form_field_col]
    add al, 8
    mov [input_start_col], al
    call .set_input_window
    ret

.input_store_char:
    mov bl, [input_len]
    xor bh, bh
    mov di, [input_target]
    add di, bx
    mov [di], al
    inc byte [input_len]
    inc di
    mov byte [di], 0
    call .render_text_input
    ret

.input_backspace:
    cmp byte [input_len], 0
    je .backspace_done
    dec byte [input_len]
    mov bl, [input_len]
    xor bh, bh
    mov di, [input_target]
    add di, bx
    mov byte [di], 0
    call .render_text_input
.backspace_done:
    ret

.input_wait_key:
    xor ah, ah
    int 0x16
    ret

.ask_agent:
    mov byte [menu_index], 0
    mov byte [blink_state], 0
    phase_call_res notify_question
    call .render_agent_question
.ask_agent_resume:
.agent_input:
    phase_call_res blink_load_marker
    mov ah, 0x01
    int 0x16
    jz .agent_input
    xor ah, ah
    int 0x16
    cmp al, 0x0d
    je .accept_agent
    cmp ah, 0x48
    je .previous_agent
    cmp ah, 0x50
    jne .agent_input
.next_agent:
    mov al, [menu_index]
    inc al
    cmp al, [agent_count]
    jb .store_agent_index
    xor al, al
    jmp .store_agent_index
.previous_agent:
    cmp byte [menu_index], 0
    jne .decrement_agent
    mov al, [agent_count]
    dec al
    jmp .store_agent_index
.decrement_agent:
    mov al, [menu_index]
    dec al
.store_agent_index:
    mov [menu_index], al
    call .draw_agent_options
    jmp .agent_input
.accept_agent:
    call .copy_selected_agent
    call .slide_selected_agent_left
    ret

.copy_selected_agent:
    mov al, [menu_index]
    call .agent_ptr_from_al
    mov di, seed_agent_id
    mov cx, agent_id_len
.copy:
    lodsb
    stosb
    or al, al
    jz .copied
    loop .copy
    mov byte [di - 1], 0
.copied:
    or byte [seed_config_flags], seed_flag_agent
    mov byte [user_cfg_dirty], 1
    ret

.slide_selected_agent_left:
    mov al, [seed_col]
    add al, 2
.slide_left_loop:
    call .draw_selected_agent_slide
    mov ah, [form_left_col]
    cmp al, ah
    jbe .slide_left_done
    sub al, 4
    cmp al, ah
    jae .slide_left_wait
    mov al, ah
.slide_left_wait:
    mov cx, 1
    phase_call_res wait_ticks
    jmp .slide_left_loop
.slide_left_done:
    ret

.slide_selected_agent_right:
    mov al, [form_left_col]
.slide_right_loop:
    call .draw_selected_agent_slide
    mov ah, [seed_col]
    add ah, 2
    cmp al, ah
    jae .slide_right_done
    add al, 4
    cmp al, ah
    jbe .slide_right_wait
    mov al, ah
.slide_right_wait:
    mov cx, 1
    phase_call_res wait_ticks
    jmp .slide_right_loop
.slide_right_done:
    ret

.draw_selected_agent_slide:
    mov [input_start_col], al
    call .clear_panel_area
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    phase_call_res show_load_marker
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, low_scratch_start + (agent_prompt_text - PHASE_BASE)
    phase_call_res print_z
    call .draw_agent_options_at_col
    mov al, [input_start_col]
    ret

.render_agent_question:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, low_scratch_start + (agent_prompt_text - PHASE_BASE)
    phase_call_res type_z

    call .type_agent_options
    ret

.render_agent_values_form:
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    phase_call_res show_load_marker

    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, low_scratch_start + (agent_prompt_text - PHASE_BASE)
    phase_call_res type_z

    mov al, [form_left_col]
    mov [input_start_col], al
    call .draw_agent_options_at_col

.draw_agent_form_fields:
    call agent_setup_phase_selected_agent_needs_endpoint
    jc .form_key_only
    mov al, question_row
    add al, [menu_index]
    mov [cursor_row], al
    mov si, low_scratch_start + (endpoint_prompt_text - PHASE_BASE)
    mov di, seed_endpoint
    mov al, 0
    call .draw_form_field
    mov al, question_row + 1
    add al, [menu_index]
    mov [cursor_row], al
    mov si, low_scratch_start + (key_prompt_text - PHASE_BASE)
    mov di, seed_key
    mov al, 1
    call .draw_form_field
    ret
.form_key_only:
    mov al, question_row
    add al, [menu_index]
    mov [cursor_row], al
    mov si, low_scratch_start + (key_prompt_text - PHASE_BASE)
    mov di, seed_key
    mov al, 0
    call .draw_form_field
    ret

.draw_form_field:
    push ax
    mov [input_target], di
    mov al, [form_field_col]
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    pop ax
    cmp al, [menu_value_a]
    jne .field_label_ready
    mov bl, [question_attr]
.field_label_ready:
    phase_call_res print_z
    mov al, [form_field_col]
    add al, 8
    mov [input_start_col], al
    call .measure_input_len
    call .render_text_input
    ret

.type_agent_options:
    mov byte [agent_draw_index], 0
.type_agent_next:
    mov al, [agent_draw_index]
    cmp al, [agent_count]
    jae .type_agent_done
    mov al, question_row
    add al, [agent_draw_index]
    mov [cursor_row], al
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov al, [agent_draw_index]
    cmp al, [menu_index]
    jne .type_agent_attr_ready
    mov bl, [menu_selected_attr]
.type_agent_attr_ready:
    mov al, [agent_draw_index]
    call .agent_ptr_from_al
    phase_call_res type_z
    inc byte [agent_draw_index]
    jmp .type_agent_next
.type_agent_done:
    ret

.draw_agent_options:
    mov al, [seed_col]
    add al, 2
    mov [input_start_col], al
.draw_agent_options_at_col:
    mov byte [agent_draw_index], 0
.draw_agent_next:
    mov al, [agent_draw_index]
    cmp al, [agent_count]
    jae .draw_agent_done
    mov al, question_row
    add al, [agent_draw_index]
    mov [cursor_row], al
    mov al, [input_start_col]
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov al, [agent_draw_index]
    cmp al, [menu_index]
    jne .draw_agent_attr_ready
    mov bl, [menu_selected_attr]
.draw_agent_attr_ready:
    mov al, [agent_draw_index]
    call .agent_ptr_from_al
    phase_call_res print_z
    inc byte [agent_draw_index]
    jmp .draw_agent_next
.draw_agent_done:
    ret

.agent_ptr_from_al:
    xor ah, ah
    mov si, ax
    shl si, 1
    shl si, 1
    shl si, 1
    shl si, 1
    add si, agent_ids
    ret

.measure_input_len:
    mov byte [input_len], 0
    mov di, [input_target]
.measure_next:
    cmp byte [di], 0
    je .measure_done
    inc di
    inc byte [input_len]
    jmp .measure_next
.measure_done:
    ret

.render_text_input:
    call .clear_input_line
    call .set_input_window
    mov bl, [question_attr]
.render_text_next:
    jcxz .render_text_done
    lodsb
    phase_call_res print_char
    loop .render_text_next
.render_text_done:
    phase_call_res set_bios_cursor
    ret

.set_input_window:
    mov al, [input_start_col]
    mov [cursor_col], al
    mov dl, [screen_cols]
    sub dl, al
    dec dl
    mov cl, [input_len]
    xor ch, ch
    mov si, [input_target]
    cmp cl, dl
    jbe .input_window_done
    mov al, cl
    sub al, dl
    xor ah, ah
    add si, ax
    mov cl, dl
.input_window_done:
    ret

.clear_panel_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, question_row
    xor cl, cl
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

.clear_agent_field_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, question_row
    mov cl, [form_field_col]
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

.clear_input_line:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, [cursor_row]
    mov cl, [input_start_col]
    mov dh, ch
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

agent_prompt_text db 'agent?', 0
key_prompt_text db 'key?', 0
endpoint_prompt_text db 'server?', 0

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
