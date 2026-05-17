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
    mov si, fs_sector_buffer
    add si, [api_response_pending_len]
    mov cx, [api_body_len]
    sub cx, [api_response_pending_len]

.send_tail:
    jcxz .done
    cmp cx, api_request_plain_len
    ja .failed
    mov di, api_request_plain + tls_record_header_len
    mov ax, cx
    rep movsb
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

%unmacro phase_call_res 1
