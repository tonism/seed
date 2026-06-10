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
    or cx, cx
    jz .raw_done
    lodsb
    push si
    call .accept_raw_byte
    pop si
    dec cx
    jmp .raw_next
.raw_done:
    ret

.accept_raw_byte:
    cmp byte [api_stream_text_seen], 0
    je .scan_done
    cmp byte [api_http_header_match], 0
    jne .zero_match
    cmp al, '0'
    jne .scan_done
.zero_match:
    mov si, PHASE_LOAD_ADDR + (zero_chunk_pattern - PHASE_BASE)
    mov di, api_http_header_match
    call .match_char
    jc .scan_done
    mov byte [api_stream_completed], 3
    ret

.scan_done:
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
    ; Build 11 #4: golfed from a 2-way branch to arithmetic (tls_key_schedule_ready is strictly 0/1)
    ; to reclaim the bytes the compaction capture branch in .emit_char needs. completed = 3 when cold
    ; (transport-final, no keep-alive drain) or 2 when a live session still awaits the transport
    ; drain, i.e. 3 - the flag. al is dead here (the matched done-pattern char is already consumed).
    mov al, 3
    sub al, [tls_key_schedule_ready]
    mov [api_stream_completed], al
    ret

.scan_delta:
    cmp byte [api_stream_state], 0
    je .scan_idle
    cmp byte [api_stream_state], 1
    je .scan_string
    cmp byte [api_stream_state], 2
    je .scan_escaped
    ret

.scan_idle:
    cmp byte [api_stream_delta_match], 0
    jne .delta_match
    cmp al, '"'
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
    je .escaped_lf
    jmp .emit_char
.escaped_lf:
    mov al, 10
    jmp .emit_char
.string_done:
    mov byte [api_stream_state], 0
    ret
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
    ; 75% trigger so the endpoint loop cannot re-fire. On a compaction pass also suppress the draw and
    ; mark text_seen (via the shared .set_seen_ret below): the summary is internal carried state, not
    ; an answer, so it must not render - and it must not read as an empty/dead socket (-> spurious
    ; reconnect). Safe to suppress here: a DEDICATED exchange with no user answer to eat, unlike the
    ; Build-10 recap that swallowed real replies. bx = pre-store used count.
    mov bx, [chat_context_used]
    cmp bx, [chat_effective_cap]
    jae .emit_char_stored               ; window/summary cap reached: stop accumulating
    mov [chat_context_start + bx], al
    inc word [chat_context_used]
.emit_char_stored:
    cmp byte [compacting_msg], 0
    jne .set_seen_ret                    ; compaction: never draw the summary; mark it seen (below)
    cmp byte [compact_next], 0
    jne .suppress_active                 ; compaction recap OR a tool line already in progress
    ; Build 10: a '$' begins a tool directive - suppress that whole line from the screen (it
    ; is already captured in the window above; the tool phase executes it between turns, and
    ; shows its own dim "read from .." line). Reuse the recap suppress-to-newline below;
    ; compact_next is reset every request, so a trailing-newline-less tool line cannot leak
    ; into the next turn's compaction.
    cmp al, '$'
    jne .emit_to_screen                  ; normal char: render (already stored in the window)
    ; Build 10 fix: a tool directive is suppressed from the screen but IS reply content. Mark
    ; text_seen (like the compaction recap pre-arm, agent_request.inc) so the transport-completion
    ; scan runs (it gates on text_seen) and a tool-ONLY reply (no prose - e.g. an obedient
    ; write-then-run) is NOT misread by agent_api_exchange as an empty/dead-socket response ->
    ; spurious reconnect -> clobbered auto-continue directive -> dead agentic loop.
.set_seen_ret:                           ; a compaction summary char OR a '$' tool line: captured into
    mov byte [api_stream_text_seen], 1   ; the window, never drawn; mark seen so completion still scans
    mov byte [compact_next], 1
    ret
.suppress_active:
    ; Compaction turn: the reply opens with a one-line recap (captured into the window, not
    ; drawn) - suppress until its first newline (or the window cap), then render the answer.
    ; Same path now also hides a tool-directive line until its newline.
    cmp al, 10
    je .recap_end
    cmp bx, [chat_context_len_var]
    jae .recap_end
    ret
.recap_end:
    mov byte [compact_next], 0
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
    jmp .seen_ready
.position_cold_greeting:
    mov byte [cursor_row], dpi_prompt_row - 2
    mov byte [cursor_col], dpi_prompt_col
    jmp .stream_seen_ready
.seen_ready:
.stream_seen_ready:
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
    push bx
    xor ax, ax
    mov al, [cursor_row]
    mov bl, [screen_cols]
    mul bl
    xor bh, bh
    mov bl, [cursor_col]
    add ax, bx
    shl ax, 1
    mov [api_body_len], ax
    pop bx
    pop ax
    ret

done_pattern db '.done', 0
completed_pattern db '_text.done', 0
delta_key_pattern db '"delta":"', 0
zero_chunk_pattern db '0', 13, 10, 13, 10, 0

; Keep-alive GET template relocated to the persistent pool (ka_template_persistent), staged once
; at boot by hardware_setup. It must sit at a fixed address that survives the whole receive loop;
; it previously lived here (the only persistent loaded phase), but this one-sector phase is now
; full, so the pool hosts it instead. agent_api_keepalive sends it from there during long renders.

agent_response_write_char_direct:
    push bx
    push di
    push es
    mov ah, 0x07
    mov bx, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .segment_ready
    mov bx, 0xb000
.segment_ready:
    mov es, bx
    mov di, [api_body_len]
    stosw
    mov [api_body_len], di
    pop es
    pop di
    pop bx
    ret

%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
