%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name the runtime load address"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

agent_api_stream_phase:
    push ds
    pop es
    cld
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .ready_tail
    mov ax, (((core_splash_phase_end - core_splash_phase_start + 511) / 512) << 8) | ((core_splash_phase_start - $$) / 512)
    mov bx, low_scratch_start
    phase_call_res run_core_phase_at
    jc .failed
    jmp .done

.ready_tail:
    cmp word [api_response_pending_len], 0
    je .done
    mov di, api_request_plain + tls_record_header_len
    mov si, dpi_input_buf
    mov cl, [dpi_input_len_byte]
    xor ch, ch
    call agent_api_stream_append_json_bytes_to_buffer
    mov si, PHASE_LOAD_ADDR + (api_stream_json_close_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len

.send_tail:
    or ax, ax
    jz .done
    cmp ax, api_request_plain_len
    ja .failed
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    phase_call_res tls_send_application_data_current_seq
    jc .failed
.done:
    mov word [api_response_pending_len], 0
    mov word [api_body_len], 0
    clc
    ret

.failed:
    stc
    ret

api_stream_json_close_text db '","stream":true}', 0

agent_api_stream_append_z_to_buffer:
    lodsb
    or al, al
    jz .append_done
    stosb
    jmp agent_api_stream_append_z_to_buffer
.append_done:
    ret

agent_api_stream_append_json_bytes_to_buffer:
    jcxz .json_done
.json_next:
    lodsb
    cmp al, '"'
    je .json_escape
    cmp al, '\'
    je .json_escape
    cmp al, 32
    jb .json_space
    stosb
    loop .json_next
    ret
.json_escape:
    mov ah, al
    mov al, '\'
    stosb
    mov al, ah
    stosb
    loop .json_next
    ret
.json_space:
    mov al, ' '
    stosb
    loop .json_next
.json_done:
    ret

%unmacro phase_call_res 1
