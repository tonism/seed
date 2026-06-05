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
    cmp byte [agent_loop_pending], 0
    jne .skip_prompt_restore             ; agentic auto-continue: dpi_input_buf holds the directive
    call .restore_prompt_from_screen
.skip_prompt_restore:
    call .compute_ready_body_lengths
    jc .request_failed
    mov al, [dpi_input_len_byte]
    mov [api_stream_prompt_len], al
    mov [chat_prompt_len_cache], al
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
    ; Build 9 streaming: R builds only chunk 1 = headers + {"model":"<model> . The stream phase
    ; then builds+sends chunk 2 (",reasoning,instructions:"<identity> <ledger>","input":") and
    ; chunk 3 (<prompt>","stream":true}), so no single record must hold the whole prefix.
    ; Content-Length (compute_ready_body_lengths) is the total body across all 3 records.
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
    ; .build_openai_body runs only on the cold (not-ready) path; the boot greeting stays bare
    ; (no instructions/ledger). The ready chat path builds instructions+ledger inline above.
    mov si, PHASE_LOAD_ADDR + (api_json_input_text - PHASE_BASE)
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
    mov si, PHASE_LOAD_ADDR + (api_json_boot_stream_close_text - PHASE_BASE)
    jmp .append_body_close
.body_close:
    mov si, PHASE_LOAD_ADDR + (api_json_stream_close_text - PHASE_BASE)
.append_body_close:
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
    add ax, api_json_model_text_len + api_ready_stream_close_text_len
    add ax, api_json_instructions_text_len + api_ledger_len + api_json_input_open_text_len
    ; Build 9: the window rides in the input JSON-ESCAPED, so Content-Length must count it ESCAPED
    ; (like the prompt above) - else a quote/backslash-bearing window under-counts and truncates the
    ; sent body. Keep the RAW count for the fill threshold. (WORD throughout.)
    mov si, chat_context_start
    mov cx, [chat_context_used]
    push ax                             ; body-so-far
    push cx                             ; raw window count
    call agent_request_phase_json_bytes_len   ; ax = window length JSON-escaped (clc; cx->0; bx kept)
    pop cx                              ; raw window count (the fill measure)
    pop dx                             ; body-so-far
    add ax, dx                          ; body + escaped window
    ; measured before sending - if the window is past the (tunable) threshold, arm model-compaction
    ; for this request (chunk 2 adds the recap directive; its length is added below).
    mov byte [compact_next], 0
    cmp cx, [chat_compact_threshold]
    jb .body_not_full
    mov byte [compact_next], 1
    mov byte [api_stream_text_seen], 1   ; recap is captured (not rendered), so pre-arm the
    add ax, api_json_compact_directive_text_len   ; transport-completion scan (it gates on text_seen)
.body_not_full:
    mov [api_body_len], ax
    clc
    ret

.restore_prompt_from_screen:
    ; Refresh dpi_input_buf (== tls_rx_copy, clobbered by a reconnect's receives) from the
    ; durable on-screen copy of the prompt, using api_stream_prompt_len (captured before any
    ; receive in prepare_agent_endpoint_path). Harmless on the first build (the screen matches
    ; what DPI captured); repairs the clobbered prompt on a reconnect rebuild. Mirrors the proven
    ; split-tail screen read (agent_api_stream_append_prompt_screen_to_buffer) but copies raw
    ; bytes (no JSON escaping) into dpi_input_buf.
    push es
    mov al, [chat_resend_prompt_len]
    mov [dpi_input_len_byte], al
    or al, al
    jz .restore_done
    xor ah, ah
    mov cx, ax
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .restore_seg_ready
    mov ax, 0xb000
.restore_seg_ready:
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
    mov di, dpi_input_buf
    mov dl, dpi_prompt_col + 2
.restore_next:
    mov al, [es:si]
    mov [di], al
    inc di
    inc si
    inc si
    inc dl
    cmp dl, [screen_cols]
    jb .restore_same_row
    mov dl, dpi_prompt_col + 2
    add si, (dpi_prompt_col + 2) * 2
.restore_same_row:
    loop .restore_next
.restore_done:
    pop es
    ret

; The screen-scan capture (capture_summary_from_screen) is gone: the recap-first compaction
; captures the model's recap directly in the renderer (agent_response.inc .emit_char) and never
; draws it, so there is nothing to scan back off the screen.

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
; Build 9: the tiered ready input-prefix templates were removed; identity+ledger + the
; instructions/input-open templates now live in agent_api_stream.inc (built/sent as chunk 2).
api_json_boot_prompt_text db 'Greet.', 0
api_json_boot_stream_close_text db '","stream":true}', 0
api_json_stream_close_text db '","stream":true}', 0
api_json_stream_close_text_len equ $ - api_json_stream_close_text - 1
api_ready_stream_close_text_len equ api_json_stream_close_text_len

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
