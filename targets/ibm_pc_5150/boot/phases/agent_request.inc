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

agent_request_phase:
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .session_ready
    call .selected_agent_is_openai
    jc .failed
.session_ready:
    call .build_openai_request
    jc .failed
    clc
    ret
.failed:
    stc
    ret

.selected_agent_is_openai:
    cmp byte [seed_agent_id], 'o'
    jne .selected_failed
    cmp byte [seed_agent_id + 1], 'p'
    jne .selected_failed
    cmp byte [seed_agent_id + 2], 'e'
    jne .selected_failed
    cmp byte [seed_agent_id + 3], 'n'
    jne .selected_failed
    cmp byte [seed_agent_id + 4], 'a'
    jne .selected_failed
    cmp byte [seed_agent_id + 5], 'i'
    jne .selected_failed
    cmp byte [seed_agent_id + 6], 0
    jne .selected_failed
    clc
    ret
.selected_failed:
    stc
    ret

.build_openai_request:
    mov word [api_response_pending_len], 0
    mov byte [api_stream_state], 0
    mov byte [api_stream_delta_match], 0
    mov byte [api_stream_seen], 0
    mov byte [api_stream_text_seen], 0
    mov byte [api_stream_prompt_len], 0
    mov byte [api_stream_completed], 0
    mov byte [api_http_state], 0
    mov byte [api_http_header_match], 0
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .build_ready_openai_request
    mov byte [dpi_input_len_byte], 0
    mov byte [dpi_prompt_marker_row], 0
    mov byte [api_stream_event_ready], 0
    call .build_openai_body
    jc .request_failed
    push ds
    pop es
    mov di, api_request_plain + tls_record_header_len
    mov si, PHASE_LOAD_ADDR + (http_post_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_openai_path_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_version_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_host_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (agent_request_host_openai_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_auth_bearer_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .reuse_key
    mov si, seed_key
    call agent_request_phase_append_z_to_buffer
    jmp .key_done
.reuse_key:
    mov si, chat_key_cache
    mov cx, seed_key_len
    call agent_request_phase_append_z_bounded_to_buffer
    jc .request_key_failed
.key_done:
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_content_length_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov ax, [api_body_len]
    call .append_u16_decimal
    call agent_request_phase_append_crlf_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, fs_sector_buffer
    mov cx, [api_body_len]
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    jne .copy_body_prefix
    mov cx, [api_response_pending_len]
.copy_body_prefix:
    rep movsb
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    mov [tls_app_total_len], ax
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    cmp ax, api_request_plain_len
    ja .request_too_large
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .ready_request
    mov word [api_response_pending_len], 1
    jmp .success_ready
.ready_request:
    mov word [handoff_addr + handoff_net_status], 0xb0fe
.success_ready:
    clc
    ret
.build_ready_openai_request:
    call .compute_ready_body_lengths
    jc .request_failed
    mov al, [dpi_input_len_byte]
    mov [api_stream_prompt_len], al
    push ds
    pop es
    mov di, api_request_plain + tls_record_header_len
    mov si, PHASE_LOAD_ADDR + (http_post_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_openai_path_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_version_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_host_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (agent_request_host_openai_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_auth_bearer_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, chat_key_cache
    mov cx, seed_key_len
    call agent_request_phase_append_z_bounded_to_buffer
    jc .request_key_failed
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_content_length_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov ax, [api_body_len]
    call .append_u16_decimal
    call agent_request_phase_append_crlf_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (api_json_model_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, chat_model_cache
    mov cx, seed_model_len
    call agent_request_phase_append_z_bounded_to_buffer
    jc .request_failed
    mov si, PHASE_LOAD_ADDR + (api_json_ready_input_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    mov [tls_app_total_len], ax
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    cmp ax, api_request_plain_len
    ja .request_too_large
    mov word [handoff_addr + handoff_net_status], 0xb0fe
    clc
    ret
.request_key_failed:
    mov word [handoff_addr + handoff_net_status], 0xb404
    jmp .request_failed
.request_too_large:
    mov word [handoff_addr + handoff_net_status], 0xb505
    jmp .request_failed
.request_failed:
    stc
    ret

.build_openai_body:
    push ds
    pop es
    mov di, fs_sector_buffer
    mov si, PHASE_LOAD_ADDR + (api_json_model_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .reuse_model
    mov si, seed_model
    call agent_request_phase_append_z_to_buffer
    jmp .model_done
.reuse_model:
    mov si, chat_model_cache
    mov cx, seed_model_len
    call agent_request_phase_append_z_bounded_to_buffer
    jc .body_failed
.model_done:
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    jne .cold_input_prefix
    mov si, PHASE_LOAD_ADDR + (api_json_ready_input_text - PHASE_BASE)
    jmp .input_prefix_ready
.cold_input_prefix:
    mov si, PHASE_LOAD_ADDR + (api_json_input_text - PHASE_BASE)
.input_prefix_ready:
    call agent_request_phase_append_z_to_buffer
    mov ax, di
    sub ax, fs_sector_buffer
    mov [api_response_pending_len], ax
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    jne .initial_prompt
    mov si, dpi_input_buf
    mov cl, [dpi_input_len_byte]
    xor ch, ch
    call agent_request_phase_append_json_bytes_to_buffer
    jmp .body_close
.initial_prompt:
    mov si, PHASE_LOAD_ADDR + (api_json_boot_prompt_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
.body_close:
    mov si, PHASE_LOAD_ADDR + (api_json_stream_close_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov ax, di
    sub ax, fs_sector_buffer
    mov [api_body_len], ax
    cmp ax, 512
    ja .body_failed
    clc
    ret
.body_failed:
    mov word [handoff_addr + handoff_net_status], 0xb202
    stc
    ret

.compute_ready_body_lengths:
    mov si, chat_model_cache
    mov cx, seed_model_len
    call agent_request_phase_strlen_z_bounded
    jc .body_failed
    mov bx, ax
    mov si, dpi_input_buf
    mov cl, [dpi_input_len_byte]
    xor ch, ch
    call agent_request_phase_json_bytes_len
    mov dx, ax
    add ax, api_ready_stream_close_text_len
    mov [api_response_pending_len], ax
    mov ax, dx
    add ax, bx
    add ax, api_json_model_text_len + api_json_ready_input_text_len + api_ready_stream_close_text_len
    mov [api_body_len], ax
    clc
    ret

.append_u16_decimal:
    xor cx, cx
    mov bx, 100
    xor dx, dx
    div bx
    or ax, ax
    jz .tens
    add al, '0'
    stosb
    inc cx
.tens:
    mov ax, dx
    mov bx, 10
    xor dx, dx
    div bx
    or cx, cx
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

http_post_text db 'POST ', 0
http_openai_path_text db '/v1/responses', 0
http_version_text db ' HTTP/1.1', 13, 10, 0
http_host_text db 'Host:', 0
http_auth_bearer_text db 'Authorization:Bearer ', 0
http_content_length_text db 'Content-Length:', 0
agent_request_host_openai_text db 'api.openai.com', 0
api_json_model_text db '{"model":"', 0
api_json_model_text_len equ $ - api_json_model_text - 1
api_json_input_text db '","input":"', 0
api_json_input_text_len equ $ - api_json_input_text - 1
api_json_ready_input_text db '","reasoning":{"effort":"minimal"},"input":"', 0
api_json_ready_input_text_len equ $ - api_json_ready_input_text - 1
api_json_boot_prompt_text db 'Greet.', 0
api_json_stream_close_text db '","stream":true}', 0
api_json_stream_close_text_len equ $ - api_json_stream_close_text - 1
api_ready_stream_close_text_len equ 63

agent_request_phase_strlen_z_bounded:
    xor dx, dx
.strlen_next:
    jcxz .strlen_failed
    lodsb
    or al, al
    jz .strlen_done
    inc dx
    loop .strlen_next
.strlen_failed:
    stc
    ret
.strlen_done:
    mov ax, dx
    clc
    ret

agent_request_phase_json_bytes_len:
    xor dx, dx
    jcxz .json_len_done
.json_len_next:
    lodsb
    cmp al, '"'
    je .json_len_escape
    cmp al, '\'
    je .json_len_escape
    inc dx
    loop .json_len_next
    jmp .json_len_done
.json_len_escape:
    inc dx
    inc dx
    loop .json_len_next
.json_len_done:
    mov ax, dx
    clc
    ret

agent_request_phase_append_z_to_buffer:
    lodsb
    or al, al
    jz .done
    stosb
    jmp agent_request_phase_append_z_to_buffer
.done:
    ret

agent_request_phase_append_z_bounded_to_buffer:
    jcxz .failed
    lodsb
    or al, al
    jz .done
    stosb
    loop agent_request_phase_append_z_bounded_to_buffer
.failed:
    stc
    ret
.done:
    clc
    ret

agent_request_phase_append_crlf_to_buffer:
    mov al, 13
    stosb
    mov al, 10
    stosb
    ret

agent_request_phase_append_json_bytes_to_buffer:
    jcxz .done
.next:
    lodsb
    cmp al, '"'
    je .escape
    cmp al, '\'
    je .escape
    cmp al, 32
    jb .space
    stosb
    loop .next
    ret
.escape:
    mov ah, al
    mov al, '\'
    stosb
    mov al, ah
    stosb
    loop .next
    ret
.space:
    mov al, ' '
    stosb
    loop .next
.done:
    ret

%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
