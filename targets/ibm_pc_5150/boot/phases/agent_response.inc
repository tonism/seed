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
    cmp byte [tool_fc_state], 1
    jne .fc_capture_done
    mov bx, [fc_capture_len]
    cmp bx, fc_capture_max - 1
    jae .fc_capture_done
    mov [fc_capture_buf + bx], al
    inc word [fc_capture_len]
.fc_capture_done:
    mov si, PHASE_LOAD_ADDR + (done_pattern - PHASE_BASE)
    cmp byte [tls_key_schedule_ready], 0
    je .done_pattern_ready
    mov si, PHASE_LOAD_ADDR + (completed_pattern - PHASE_BASE)
.done_pattern_ready:
    cmp byte [api_stream_done_match], 0
    jne .match_done
    cmp al, [si]
    jne .scan_delta
.match_done:
    mov di, api_stream_done_match
    call .match_char
    jc .scan_delta
.done_ready:
.completion_ready:
    mov byte [tls_key_schedule_ready], 0
    mov al, 3
    ; Treat SSE completion as terminal and force the next turn to reconnect. This avoids carrying an
    ; unread chunk trailer into a native function_call_output follow-up.
    mov [api_stream_completed], al
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
    mov si, PHASE_LOAD_ADDR + (arguments_pattern - PHASE_BASE)
    mov di, fc_match_state
    call .match_char
    jc .fc_no_match
    mov al, 1
    mov [tool_fc_state], al
    mov word [fc_capture_len], 0
    mov [api_stream_text_seen], al
    mov byte [tls_key_schedule_ready], 0
    ret
.fc_no_match:
    cmp byte [tool_fc_state], 1
    je .parser_ret
.delta_probe:
    cmp byte [api_stream_delta_match], 0
    jne .delta_match
    cmp al, 'c'
    jne .parser_ret
.delta_match:
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
    ; Build 11 #4 real compaction: store the rendered char into the window up to chat_effective_cap -
    ; the FULL window on a normal turn, HALVED on a compaction pass (set once per request in
    ; agent_request). The halving caps the summary at 50%, keeping the post-summary window below the
    ; 75% trigger so the endpoint loop cannot re-fire. On a compaction pass the char is captured but
    ; never drawn (.compaction_suppress): the summary is internal carried state, not an answer, so it
    ; must not render - yet it must still mark text_seen so the socket is not read as empty/dead (->
    ; spurious reconnect). Safe: a DEDICATED exchange with no user answer to eat, unlike the Build-10
    ; recap that swallowed real replies. bx = pre-store used count.
    mov bx, [chat_context_used]
    cmp bx, [chat_effective_cap]
    jae .emit_char_stored               ; window/summary cap reached: stop accumulating
    mov [chat_context_start + bx], al
    inc word [chat_context_used]
.emit_char_stored:
    cmp word [compacting_msg], 0
    je .emit_to_screen
.compaction_suppress:
    ; A compaction summary (or an ESC graceful-stop) is captured into the window above but never
    ; drawn; mark text_seen so the transport-completion scan still runs (it gates on text_seen) and a
    ; reply that draws nothing is not misread as an empty/dead socket -> spurious reconnect. compact_next
    ; is NOT touched: agent_request resets it every request and compaction never reads it.
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
    call .sync_response_video_offset
.live_ready:
    cmp al, 10
    je .emit_newline
    call agent_response_write_char_direct
    inc byte [cursor_col]
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
    call .sync_response_video_offset
    ret

.sync_response_video_offset:
    push ax
    xor ax, ax
    mov al, [cursor_row]
    mov bl, [screen_cols]
    mul bl
    xor bh, bh
    mov bl, [cursor_col]
    add ax, bx
    shl ax, 1
    mov [api_body_len], ax
    pop ax
    ret

completed_pattern db 'response.completed', 0
done_pattern equ completed_pattern
arguments_pattern db 'arguments":"', 0
delta_key_pattern db 'content_index":0,"delta":"', 0

; Keep-alive GET template relocated to the persistent pool (ka_template_persistent), staged once
; at boot by hardware_setup. It must sit at a fixed address that survives the whole receive loop;
; it previously lived here (the only persistent loaded phase), but this one-sector phase is now
; full, so the pool hosts it instead. agent_api_keepalive sends it from there during long renders.

agent_response_write_char_direct:
    push es
    mov ah, 0x07                         ; normal text attribute
    mov bx, [video_seg]
    mov es, bx
    mov di, [api_body_len]
    stosw
    mov [api_body_len], di
    pop es
    ret

%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
