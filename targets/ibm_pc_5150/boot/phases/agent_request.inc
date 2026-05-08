%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

agent_request_phase:
    call .selected_agent_is_openai
    jc .failed
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
    call .build_openai_body
    jc .request_failed
    push ds
    pop es
    mov di, api_request_plain + tls_record_header_len
    mov si, low_scratch_start + (http_post_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, low_scratch_start + (http_openai_path_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, low_scratch_start + (http_version_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, low_scratch_start + (http_host_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, low_scratch_start + (agent_request_host_openai_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, low_scratch_start + (http_auth_bearer_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, seed_key
    call agent_request_phase_append_z_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, low_scratch_start + (http_content_type_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, low_scratch_start + (http_content_length_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov ax, [api_body_len]
    call .append_u16_decimal
    call agent_request_phase_append_crlf_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, fs_sector_buffer
    mov cx, [api_body_len]
    rep movsb
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    cmp ax, api_request_plain_len
    ja .request_failed
    clc
    ret
.request_failed:
    stc
    ret

.build_openai_body:
    push ds
    pop es
    mov di, fs_sector_buffer
    mov si, low_scratch_start + (api_json_model_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, seed_model
    call agent_request_phase_append_z_to_buffer
    mov si, low_scratch_start + (api_json_input_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, low_scratch_start + (api_json_plain_close_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov ax, di
    sub ax, fs_sector_buffer
    mov [api_body_len], ax
    cmp ax, 512
    ja .body_failed
    clc
    ret
.body_failed:
    stc
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
http_host_text db 'Host: ', 0
http_auth_bearer_text db 'Authorization: Bearer ', 0
http_content_type_text db 'Content-Type: application/json', 13, 10, 0
http_content_length_text db 'Content-Length: ', 0
agent_request_host_openai_text db 'api.openai.com', 0
api_json_model_text db '{"model":"', 0
api_json_input_text db '","input":"Reply exactly: ok","store":false', 0
api_json_plain_close_text db '}', 0

agent_request_phase_append_z_to_buffer:
    lodsb
    or al, al
    jz .done
    stosb
    jmp agent_request_phase_append_z_to_buffer
.done:
    ret

agent_request_phase_append_crlf_to_buffer:
    mov al, 13
    stosb
    mov al, 10
    stosb
    ret

%unmacro phase_call_res 1
