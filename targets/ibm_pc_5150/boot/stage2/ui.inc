render_adapter_question:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, adapter_prompt_text
    call type_z

    call type_menu_options
    ret

render_agent_question:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, agent_prompt_text
    call type_z

    call type_agent_options
    ret

render_agent_values_form:
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    call show_load_marker

    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, agent_prompt_text
    call type_z

    mov al, [form_left_col]
    mov [input_start_col], al
    call draw_agent_options_at_col

draw_agent_form_fields:
    call selected_agent_needs_endpoint
    jc .key_only
    mov al, question_row
    add al, [menu_index]
    mov [cursor_row], al
    mov si, endpoint_prompt_text
    mov di, seed_endpoint
    mov al, 0
    call draw_form_field
    mov al, question_row + 1
    add al, [menu_index]
    mov [cursor_row], al
    mov si, key_prompt_text
    mov di, seed_key
    mov al, 1
    call draw_form_field
    ret
.key_only:
    mov al, question_row
    add al, [menu_index]
    mov [cursor_row], al
    mov si, key_prompt_text
    mov di, seed_key
    mov al, 0
    call draw_form_field
    ret

draw_form_field:
    push ax
    mov [input_target], di
    mov al, [form_field_col]
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    pop ax
    cmp al, [menu_value_a]
    jne .label_ready
    mov bl, [question_attr]
.label_ready:
    call print_z
    mov al, [form_field_col]
    add al, 8
    mov [input_start_col], al
    call measure_input_len
    call render_text_input
    ret

type_agent_options:
    mov byte [agent_draw_index], 0
.next:
    mov al, [agent_draw_index]
    cmp al, [agent_count]
    jae .done
    mov al, question_row
    add al, [agent_draw_index]
    mov [cursor_row], al
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov al, [agent_draw_index]
    cmp al, [menu_index]
    jne .attr_ready
    mov bl, [menu_selected_attr]
.attr_ready:
    mov al, [agent_draw_index]
    call agent_ptr_from_al
    call type_z
    inc byte [agent_draw_index]
    jmp .next
.done:
    ret

draw_agent_options:
    mov al, [seed_col]
    add al, 2
    mov [input_start_col], al
draw_agent_options_at_col:
    mov byte [agent_draw_index], 0
.next:
    mov al, [agent_draw_index]
    cmp al, [agent_count]
    jae .done
    mov al, question_row
    add al, [agent_draw_index]
    mov [cursor_row], al
    mov al, [input_start_col]
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov al, [agent_draw_index]
    cmp al, [menu_index]
    jne .attr_ready
    mov bl, [menu_selected_attr]
.attr_ready:
    mov al, [agent_draw_index]
    call agent_ptr_from_al
    call print_z
    inc byte [agent_draw_index]
    jmp .next
.done:
    ret

agent_scan_ptr:
    mov al, [agent_scan_index]
    call agent_ptr_from_al
    ret

agent_ptr_from_al:
    xor ah, ah
    mov si, ax
    shl si, 1
    shl si, 1
    shl si, 1
    shl si, 1
    add si, agent_ids
    ret

type_menu_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_selected_attr]
    mov si, [menu_option_a]
    call type_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov si, [menu_option_b]
    call type_z
    ret

draw_menu_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 0
    jne .first
    mov bl, [menu_selected_attr]
.first:
    mov si, [menu_option_a]
    call print_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 1
    jne .second
    mov bl, [menu_selected_attr]
.second:
    mov si, [menu_option_b]
    call print_z
    ret

print_z:
    lodsb
    or al, al
    jz .done
    call print_char
    jmp print_z
.done:
    ret

blink_load_marker:
    call set_seed_cursor
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    xor byte [blink_state], 1
    jnz .show
    mov al, ' '
.show:
    call print_char
    mov cx, 2
    call wait_ticks
    ret

show_load_marker:
    mov [load_marker_char], al
    mov [load_marker_attr], bl
    call set_seed_cursor
    mov al, [load_marker_char]
    call print_char
    ret

clear_question_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, seed_row
    xor cl, cl
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

clear_panel_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, question_row
    xor cl, cl
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

clear_agent_field_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, question_row
    mov cl, [form_field_col]
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

clear_input_line:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, [cursor_row]
    mov cl, [input_start_col]
    mov dh, ch
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

notify_question:
    mov ax, 6087
    call speaker_tone
    mov cx, 2
    call wait_ticks
    call speaker_off
    ret

notify_failure:
    mov ax, 5424
    call speaker_tone
    mov cx, 2
    call wait_ticks
    mov ax, 7231
    call speaker_tone
    mov cx, 3
    call wait_ticks
    call speaker_off
    ret

speaker_tone:
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

speaker_off:
    in al, 0x61
    and al, 0xfc
    out 0x61, al
    ret
