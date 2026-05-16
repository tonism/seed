%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%define PHASE_LOAD_ADDR low_scratch_start
%define PHASE_LOAD_ADDR_DEFAULTED
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

api_response_answer_ptr equ PHASE_LOAD_ADDR + (api_response_answer_ptr_storage - PHASE_BASE)
api_response_answer_len equ PHASE_LOAD_ADDR + (api_response_answer_len_storage - PHASE_BASE)

agent_response_phase:
    cmp word [api_response_pending_len], 0
    jne .answer_ready
    call .api_find_answer
    jc .update_remaining
    call .api_render_answer
    mov word [api_response_pending_len], 1
.answer_ready:
.update_remaining:
    call .api_update_body_remaining
    jc .need_more
    cmp word [api_response_pending_len], 0
    je .failed
    ret
.need_more:
    stc
    ret
.failed:
    stc
    ret

.api_find_answer:
    mov si, PHASE_LOAD_ADDR + (api_answer_output_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, PHASE_LOAD_ADDR + (api_answer_output_spaced_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, PHASE_LOAD_ADDR + (api_answer_text_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, PHASE_LOAD_ADDR + (api_answer_text_spaced_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, PHASE_LOAD_ADDR + (api_error_message_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, PHASE_LOAD_ADDR + (api_error_message_spaced_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    stc
    ret

.api_find_pattern:
    mov [api_response_answer_ptr], si
    mov bx, [tls_app_data_ptr]
    mov dx, [tls_app_len]
.next_position:
    or dx, dx
    jz .find_failed
    push bx
    push dx
    mov si, [api_response_answer_ptr]
    mov di, bx
.compare:
    lodsb
    or al, al
    jz .found
    or dx, dx
    jz .no_match
    cmp al, [di]
    jne .no_match
    inc di
    dec dx
    jmp .compare
.found:
    mov [api_response_answer_ptr], di
    pop dx
    pop bx
    clc
    ret
.no_match:
    pop dx
    pop bx
    inc bx
    dec dx
    jmp .next_position
.find_failed:
    stc
    ret

.api_measure_answer:
    mov si, [api_response_answer_ptr]
    mov ax, si
    sub ax, [tls_app_data_ptr]
    mov dx, [tls_app_len]
    cmp ax, dx
    jae .measure_failed
    sub dx, ax
    xor cx, cx
.measure_next:
    or dx, dx
    jz .measure_done
    mov al, [si]
    cmp al, '"'
    je .measure_done
    cmp al, 13
    je .measure_done
    cmp al, 10
    je .measure_done
    inc si
    inc cx
    dec dx
    jmp .measure_next
.measure_done:
    or cx, cx
    jz .measure_failed
    mov [api_response_answer_len], cx
    clc
    ret
.measure_failed:
    stc
    ret

.api_render_answer:
    cmp word [api_response_pending_len], 0
    jne .position_ready
    mov byte [cursor_row], dpi_prompt_row - 1
    mov byte [cursor_col], dpi_prompt_col
.position_ready:
    mov si, [api_response_answer_ptr]
    mov cx, [api_response_answer_len]
    cmp cx, api_response_text_max_len
    jbe .len_ready
    mov cx, api_response_text_max_len
.len_ready:
    jcxz .render_done
.render_next:
    lodsb
    cmp al, '\'
    je .render_escape
    cmp al, 13
    je .render_newline
    cmp al, 10
    je .render_newline
    call .render_char
    loop .render_next
    ret
.render_escape:
    dec cx
    jcxz .render_done
    lodsb
    cmp al, 'n'
    je .render_newline_after_escape
    call .render_char
    loop .render_next
    ret
.render_newline_after_escape:
    call .scroll_screen
    mov byte [cursor_row], dpi_prompt_row - 1
    mov byte [cursor_col], dpi_prompt_col
    loop .render_next
    ret
.render_newline:
    call .scroll_screen
    mov byte [cursor_row], dpi_prompt_row - 1
    mov byte [cursor_col], dpi_prompt_col
    loop .render_next
    ret
.render_done:
    ret

.render_char:
    push cx
    mov bl, [crypto_attr]
    phase_call_res print_char
    mov al, [cursor_col]
    cmp al, [screen_cols]
    jb .render_char_done
    call .scroll_screen
    mov byte [cursor_row], dpi_prompt_row - 1
    mov byte [cursor_col], dpi_prompt_col
.render_char_done:
    pop cx
    ret

.scroll_screen:
    push cx
    mov ah, 0x06
    mov al, 1
    mov bh, 0x07
    xor cx, cx
    mov dh, dpi_prompt_row
    mov dl, [screen_cols]
    dec dl
    int 0x10
    pop cx
    ret

.api_update_body_remaining:
    cmp word [api_body_len], 0
    jne .consume_whole_record
    mov si, PHASE_LOAD_ADDR + (api_content_length_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .content_length_ready
    mov si, PHASE_LOAD_ADDR + (api_content_length_caps_pattern - PHASE_BASE)
    call .api_find_pattern
    jc .need_more_body
.content_length_ready:
    mov si, [api_response_answer_ptr]
    call .api_parse_content_length
    jc .need_more_body
    mov [api_body_len], bx
    mov si, PHASE_LOAD_ADDR + (api_header_end_pattern - PHASE_BASE)
    call .api_find_pattern
    jc .need_more_body
    mov si, [api_response_answer_ptr]
    jmp .consume_from_si
.consume_whole_record:
    mov si, [tls_app_data_ptr]
.consume_from_si:
    mov ax, [tls_app_data_ptr]
    add ax, [tls_app_len]
    cmp ax, si
    jbe .need_more_body
    sub ax, si
    mov bx, [api_body_len]
    cmp ax, bx
    jb .body_partial
    mov word [api_body_len], 0
    clc
    ret
.body_partial:
    sub bx, ax
    mov [api_body_len], bx
.need_more_body:
    stc
    ret

.api_parse_content_length:
    xor bx, bx
.content_digit:
    lodsb
    cmp al, '0'
    jb .content_done
    cmp al, '9'
    ja .content_done
    sub al, '0'
    push ax
    mov ax, bx
    mov dx, 10
    mul dx
    mov bx, ax
    pop ax
    xor ah, ah
    add bx, ax
    jmp .content_digit
.content_done:
    or bx, bx
    jz .content_failed
    clc
    ret
.content_failed:
    stc
    ret

api_answer_output_pattern db '"output_text":"', 0
api_answer_output_spaced_pattern db '"output_text": "', 0
api_answer_text_pattern db '"text":"', 0
api_answer_text_spaced_pattern db '"text": "', 0
api_error_message_pattern db '"message":"', 0
api_error_message_spaced_pattern db '"message": "', 0
api_content_length_pattern db 'content-length: ', 0
api_content_length_caps_pattern db 'Content-Length: ', 0
api_header_end_pattern db 13, 10, 13, 10, 0
api_response_answer_ptr_storage dw 0
api_response_answer_len_storage dw 0

%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
