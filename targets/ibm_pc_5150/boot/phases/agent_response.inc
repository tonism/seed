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

agent_response_phase:
    call .scan_tls_record
    ; Keep the live session alive through a long render (see agent_api_keepalive). Called
    ; here, after the record is scanned/rendered, so the ping's record build never disturbs
    ; the bytes the scan just consumed. Resident routine; this phase persists at
    ; agent_response_phase_load_addr across the whole receive loop (the only loaded code
    ; that does), so it is the home for both the call site and the request template.
    phase_call_res agent_api_keepalive
    cmp byte [api_stream_completed], 3
    ret

.scan_tls_record:
    mov si, [tls_app_data_ptr]
    mov cx, [tls_app_len]
.raw_next:
    jcxz .raw_done
    lodsb
    push si
    call .accept_raw_byte
    pop si
    dec cx
    jmp .raw_next
.raw_done:
    ret

.accept_raw_byte:
    cmp byte [tool_fc_state], 3
    jne .fc_capture_done
    mov bx, [fc_capture_len]
    cmp bx, fc_capture_max - 1
    jae .fc_capture_done
    mov [fc_capture_buf + bx], al
    inc word [fc_capture_len]
.fc_capture_done:
    mov si, PHASE_LOAD_ADDR + (completed_pattern - PHASE_BASE)
    mov di, api_stream_done_match
    call .match_char
    jc .scan_delta
.done_ready:
.completion_ready:
    mov al, 3
    ; Treat SSE completion as terminal for this streamed response. HTTP/SSE reuse is still not reliable
    ; on this path, so the next turn opens a fresh TLS session quietly instead of drawing reconnect.
    mov [api_stream_completed], al
    mov byte [tls_key_schedule_ready], tls_key_schedule_quiet_reconnect
    ret

.scan_delta:
    ; load the 0/1/2 state once and walk it down (ah is dead here; write_char_direct resets it),
    ; cheaper than three cmp-immediates - keeps room for native function-call capture.
    mov ah, [api_stream_state]
    or ah, ah
    je .scan_idle
    dec ah
    je .scan_string
    dec ah
    je .scan_escaped
    ret

.scan_idle:
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    jne .fc_no_match
    mov si, PHASE_LOAD_ADDR + (arguments_pattern - PHASE_BASE)
    mov di, fc_match_state
    call .match_char
    jc .fc_start_probe
    mov al, 3
    mov [tool_fc_state], al
    mov word [fc_capture_len], 0
    mov byte [api_stream_text_seen], 1
    ret
.fc_start_probe:
    mov si, PHASE_LOAD_ADDR + (fc_start_pattern - PHASE_BASE)
    mov di, api_stream_fc_start_match
    call .match_char
    jc .fc_no_match
    mov al, 1
    mov [tool_fc_state], al
    mov [api_stream_text_seen], al
    ret
.fc_no_match:
    cmp byte [tool_fc_state], 1
    je .parser_ret
    cmp byte [tool_fc_state], 3
    je .parser_ret
    mov si, PHASE_LOAD_ADDR + (delta_key_pattern - PHASE_BASE)
    mov di, api_stream_delta_match
    call .match_char
    jc .parser_ret
    mov byte [api_stream_state], 1
    ret
.scan_string:
    cmp al, '"'
    je .string_done
    cmp al, '\'
    je .string_escape
    jmp .emit_char
.string_escape:
    mov byte [api_stream_state], 2
    ret
.scan_escaped:
    mov byte [api_stream_state], 1
    cmp al, 'n'
    jne .emit_char                       ; any other escape: emit the char verbatim
    mov al, 10                           ; \n -> LF
    jmp .emit_char
.string_done:
    mov byte [api_stream_state], 0
.parser_ret:
    ret

.match_char:
    mov bl, [di]
    xor bh, bh
    cmp al, [si + bx]
    je .match_advanced
    cmp al, [si]
    jne .match_reset
    mov byte [di], 1
    stc
    ret
.match_reset:
    mov byte [di], 0
    stc
    ret
.match_advanced:
    inc bl
    cmp byte [si + bx], 0
    je .match_complete
    mov [di], bl
    stc
    ret
.match_complete:
    mov byte [di], 0
    clc
    ret

.emit_char:
    cmp byte [api_stream_prompt_len], 0
    jne .emit_store
    cmp byte [compacting_msg], 0
    je .emit_to_screen
.emit_store:
    cmp byte [chat_prompt_len_cache], 0
    jne .prompt_appended
    push ax
    call .append_prompt_to_context
    pop ax
.prompt_appended:
    mov bx, [chat_context_used]
    cmp bx, [chat_effective_cap]
    jae .emit_char_stored
    mov [chat_context_start + bx], al
    inc word [chat_context_used]
.emit_char_stored:
    cmp word [compacting_msg], 0
    je .emit_to_screen
    mov byte [api_stream_text_seen], 1
    ret
.emit_to_screen:
    cmp byte [api_stream_seen], 0
    jne .live_ready
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .position_live_response
    test byte [dpi_prompt_marker_row], 0x80
    jz .position_cold_greeting
.position_live_response:
    push ax
    cmp byte [render_last_type], render_type_system
    jne .position_one_line
    call .advance_response_line
.position_one_line:
    call .advance_response_line
    pop ax
.position_cold_greeting:
    ; UI unification: no absolute positioning -- the greeting flows from where the banner left the cursor
    ; (just below the banner, col 0), so it lands right under it instead of pinned near the screen bottom.
.seen_ready:
.stream_seen_ready:
    mov byte [render_last_type], render_type_agent
    mov byte [api_stream_text_seen], 1
    mov byte [api_stream_seen], 1
.live_ready:
    cmp al, 10
    je .emit_newline
    cmp al, ' '
    jne .emit_glyph
    mov ah, [screen_cols]
    sub ah, 8
    cmp [cursor_col], ah
    jae .emit_newline
.emit_glyph:
    push cx
    mov bl, 0x07
    phase_call_res print_char
    pop cx
    mov al, [cursor_col]
    cmp al, [screen_cols]
    jb .emit_done
.emit_newline:
    call .advance_response_line
.emit_done:
    ret

.advance_response_line:
    cmp byte [cursor_row], dpi_prompt_row
    jb .move_down
    push cx                              ; cx is the outer record byte-counter - preserve it
    mov ax, 0x0601                       ; scroll up 1 line
    mov cx, 0x0100                       ; top-left (row 1, col 0)
    phase_call_res scroll_text_area
    pop cx
    mov byte [cursor_row], dpi_prompt_row - 1
.move_down:
    inc byte [cursor_row]
    mov byte [cursor_col], dpi_prompt_col
    ret

.append_prompt_to_context:
    push cx
    mov byte [chat_prompt_len_cache], 1
    cmp byte [compacting_msg], 0
    je .apt_not_compaction
    mov word [chat_context_used], 0
    jmp .apt_done
.apt_not_compaction:
    cmp byte [agent_loop_pending], 0
    je .apt_real_turn
    cmp byte [tool_fc_state], 2
    jne .apt_done
.apt_real_turn:
    mov al, [api_stream_prompt_len]
    or al, al
    je .apt_done
    xor ah, ah
    mov bx, ax
    add bx, api_json_user_label_text_len + api_json_you_label_text_len
    mov ax, [chat_context_used]
    add bx, ax
    cmp bx, [chat_context_len_var]
    jbe .apt_fits
    mov byte [compact_next], 1
    mov [chat_effective_cap], ax
    jmp .apt_done
.apt_fits:
    mov di, chat_context_start
    mov ax, [chat_context_used]
    add di, ax
    mov byte [di], ' '
    inc di
    mov word [di], 'U:'
    inc di
    inc di
    push es
    mov ax, [video_seg]
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
    mov cl, [api_stream_prompt_len]
    xor ch, ch
    mov dl, dpi_prompt_col + 2
.apt_screen_next:
    mov al, [es:si]
    mov [di], al
    inc di
    inc si
    inc si
    inc dl
    cmp dl, [screen_cols]
    jb .apt_screen_count
    mov dl, dpi_prompt_col + 2
    add si, (dpi_prompt_col + 2) * 2
.apt_screen_count:
    loop .apt_screen_next
    pop es
    mov byte [di], ' '
    inc di
    mov word [di], 'A:'
    inc di
    inc di
    mov byte [di], 10
    inc di
    mov ax, di
    sub ax, chat_context_start
    mov [chat_context_used], ax
.apt_done:
    pop cx
    ret

completed_pattern db 'response.completed', 0
done_pattern equ completed_pattern
arguments_pattern db 'arguments":"{', 0
fc_start_pattern db 'function_call', 0
delta_key_pattern db 'delta":"', 0

; Keep-alive GET template. It lives in this phase instead of persistent RAM: agent_response is loaded
; for the whole receive/render loop, which is the only time agent_api_keepalive can send it.
agent_response_ka_template:
    db "GET /v1 HTTP/1.1", 13, 10
    db "Host: api.openai.com", 13, 10
    db 13, 10
agent_response_ka_template_end:
%if (agent_response_ka_template_end - agent_response_ka_template) != ka_request_len
%error "ka_request_len (layout.inc) does not match the response keep-alive template length"
%endif

%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
