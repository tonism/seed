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
    mov byte [cursor_row], dpi_prompt_row - 2
    mov byte [cursor_col], dpi_prompt_col
    jmp .done

.ready_tail:
    mov al, [chat_prompt_len_cache]
    push ax
    cmp word [tls_app_len], 0
    je .tail_pending
    phase_call_res tls_prepare_3c501_receive
    phase_call_res tls_send_application_data_current_seq
    jc .prefix_failed
.tail_pending:
    pop ax
    mov [api_stream_prompt_len], al
    or al, al
    je .done
    mov di, api_request_plain + tls_record_header_len
    call agent_api_stream_append_prompt_screen_to_buffer
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
    phase_call_res tls_prepare_3c501_receive
    phase_call_res tls_send_application_data_current_seq
    jc .failed
    phase_call_res tls_prepare_3c501_receive
.done:
    mov ax, (((core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512) << 8) | ((core_agent_response_phase_start - $$) / 512)
    mov bx, agent_response_phase_load_addr
    phase_call_res load_core_sectors_at
    jc .failed
    ; Reset keep-alive timing: this request is the last client activity, so the idle clock
    ; (Cloudflare's ~400s timeout) restarts here, with no pings outstanding for this exchange.
    mov ax, [0x046c]
    mov [ka_last_tick], ax
    mov byte [ka_sent_count], 0
    mov word [api_response_pending_len], 0
    mov word [api_body_len], 0
    mov byte [chat_prompt_len_cache], 0
    mov byte [api_stream_state], 0
    mov byte [api_stream_delta_match], 0
    mov byte [api_stream_seen], 0
    mov byte [api_stream_text_seen], 0
    mov byte [api_stream_completed], 0
    mov byte [api_http_state], 0
    mov byte [api_http_header_match], 0
    clc
    ret

.prefix_failed:
    pop ax
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

agent_api_stream_append_prompt_screen_to_buffer:
    push es
    mov al, [api_stream_prompt_len]
    mov [api_http_state], al
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .segment_ready
    mov ax, 0xb000
.segment_ready:
    mov es, ax
    mov al, [dpi_prompt_marker_row]
    and al, 0x7f
    mov bl, [screen_cols]
    mul bl
    xor bh, bh
    mov bl, dpi_prompt_col + 2
    add ax, bx
    shl ax, 1
    mov si, ax
    mov byte [api_http_header_match], dpi_prompt_col + 2
.screen_next:
    cmp byte [api_http_state], 0
    je .screen_done
    mov al, [es:si]
    cmp al, '"'
    je .screen_escape
    cmp al, '\'
    je .screen_escape
    cmp al, 32
    jb .screen_space
    jmp .screen_store
.screen_escape:
    mov ah, al
    mov al, '\'
    mov [di], al
    inc di
    mov al, ah
    mov [di], al
    inc di
    jmp .screen_advanced
.screen_space:
    mov al, ' '
    mov [di], al
    inc di
    jmp .screen_advanced
.screen_store:
    mov [di], al
    inc di
.screen_advanced:
    inc si
    inc si
    inc byte [api_http_header_match]
    mov al, [screen_cols]
    cmp [api_http_header_match], al
    jb .screen_count
    mov byte [api_http_header_match], dpi_prompt_col + 2
    add si, (dpi_prompt_col + 2) * 2
.screen_count:
    dec byte [api_http_state]
    jmp .screen_next
.screen_done:
    mov byte [api_http_state], 0
    mov byte [api_http_header_match], 0
    mov byte [api_stream_delta_match], 0
    pop es
    ret

%unmacro phase_call_res 1
