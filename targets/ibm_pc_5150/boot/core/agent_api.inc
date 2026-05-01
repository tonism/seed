agent_api_prepare_request:
    call selected_agent_is_openai
    jc .failed
    call build_openai_request
    jc .failed
    clc
    ret
.failed:
    stc
    ret

agent_api_exchange:
    mov byte [tls_debug_stage], 0xa0
    mov byte [tls_debug_detail], 0
    mov byte [api_debug_records], 0
    mov byte [api_debug_first], 0
    cmp byte [tls_app_sent], 0
    jne .receive_response
    cmp word [tls_app_len], 0
    jne .send_request
    mov byte [tls_debug_stage], 0xa1
    call agent_api_prepare_request
    jc .failed
.send_request:
    mov byte [tls_debug_stage], 0xa2
    call tls_send_application_data_for_nic
    jc .failed
    call debug_elapsed_ax
    mov [debug_tick_request_sent], ax

.receive_response:
    mov byte [tls_debug_stage], 0xa3
    mov byte [api_receive_tries], 8
.receive:
    call tls_receive_application_data
    jc .failed
    mov byte [tls_debug_stage], 0xa4
    inc byte [api_debug_records]
    mov al, [tls_rx_copy]
    mov [api_debug_first], al
    call api_find_answer
    jnc .answer
    dec byte [api_receive_tries]
    jnz .receive
    jmp .failed
.answer:
    call api_type_answer
    clc
    ret
.failed:
    stc
    ret

selected_agent_is_openai:
    cmp byte [seed_agent_id], 'o'
    jne .failed
    cmp byte [seed_agent_id + 1], 'p'
    jne .failed
    cmp byte [seed_agent_id + 2], 'e'
    jne .failed
    cmp byte [seed_agent_id + 3], 'n'
    jne .failed
    cmp byte [seed_agent_id + 4], 'a'
    jne .failed
    cmp byte [seed_agent_id + 5], 'i'
    jne .failed
    cmp byte [seed_agent_id + 6], 0
    jne .failed
    clc
    ret
.failed:
    stc
    ret

build_openai_request:
    call build_openai_body
    jc .failed
    push ds
    pop es
    mov di, api_request_plain
    mov si, http_post_text
    call append_z_to_buffer
    mov si, http_openai_path_text
    call append_z_to_buffer
    mov si, http_version_text
    call append_z_to_buffer
    mov si, http_host_text
    call append_z_to_buffer
    mov si, host_openai_text
    call append_z_to_buffer
    call append_crlf_to_buffer
    mov si, http_auth_bearer_text
    call append_z_to_buffer
    mov si, seed_key
    call append_z_to_buffer
    call append_crlf_to_buffer
    mov si, http_content_type_text
    call append_z_to_buffer
    mov si, http_content_length_text
    call append_z_to_buffer
    mov ax, [api_body_len]
    call append_u16_decimal
    call append_crlf_to_buffer
    call append_crlf_to_buffer
    mov si, fs_sector_buffer
    mov cx, [api_body_len]
    rep movsb
    mov ax, di
    sub ax, api_request_plain
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain
    cmp ax, tls_app_max_plain_len
    ja .failed
    clc
    ret
.failed:
    stc
    ret

build_openai_body:
    push ds
    pop es
    mov di, fs_sector_buffer
    mov si, api_json_model_text
    call append_z_to_buffer
    mov si, seed_model
    call append_z_to_buffer
    mov si, api_json_input_text
    call append_z_to_buffer
    mov si, api_json_plain_close_text
    call append_z_to_buffer
    mov ax, di
    sub ax, fs_sector_buffer
    mov [api_body_len], ax
    cmp ax, 512
    ja .failed
    clc
    ret
.failed:
    stc
    ret

append_u16_decimal:
    mov byte [api_decimal_started], 0
    mov bx, 100
    xor dx, dx
    div bx
    or ax, ax
    jz .tens
    add al, '0'
    stosb
    mov byte [api_decimal_started], 1
.tens:
    mov ax, dx
    mov bx, 10
    xor dx, dx
    div bx
    cmp byte [api_decimal_started], 0
    jne .write_tens
    or ax, ax
    jz .ones
.write_tens:
    add al, '0'
    stosb
.ones:
    mov al, dl
    add al, '0'
    stosb
    ret

api_find_answer:
    mov si, api_answer_output_pattern
    call api_find_pattern
    jnc api_measure_answer
    mov si, api_answer_output_spaced_pattern
    call api_find_pattern
    jnc api_measure_answer
    mov si, api_answer_text_pattern
    call api_find_pattern
    jnc api_measure_answer
    mov si, api_answer_text_spaced_pattern
    call api_find_pattern
    jnc api_measure_answer
    mov si, api_error_message_pattern
    call api_find_pattern
    jnc api_measure_answer
    mov si, api_error_message_spaced_pattern
    call api_find_pattern
    jnc api_measure_answer
    stc
    ret

api_find_pattern:
    mov [api_answer_ptr], si
    mov bx, tls_rx_copy
    mov dx, [tls_app_len]
.next_position:
    or dx, dx
    jz .failed
    push bx
    push dx
    mov si, [api_answer_ptr]
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
    mov [api_answer_ptr], di
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
.failed:
    stc
    ret

api_measure_answer:
    mov si, [api_answer_ptr]
    mov ax, si
    sub ax, tls_rx_copy
    mov dx, [tls_app_len]
    cmp ax, dx
    jae .failed
    sub dx, ax
    xor cx, cx
.next:
    or dx, dx
    jz .done
    mov al, [si]
    cmp al, '"'
    je .done
    cmp al, 13
    je .done
    cmp al, 10
    je .done
    inc si
    inc cx
    dec dx
    jmp .next
.done:
    or cx, cx
    jz .failed
    mov [api_answer_len], cx
    clc
    ret
.failed:
    stc
    ret

api_type_answer:
    call clear_question_area
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, [api_answer_ptr]
    mov cx, [api_answer_len]
.next:
    jcxz .done
    lodsb
    push cx
    call type_char
    pop cx
    loop .next
.done:
    ret
