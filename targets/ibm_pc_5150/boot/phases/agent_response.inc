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
    ; load the 0/1/2 state once and walk it down (ah is dead here; write_char_direct resets it),
    ; cheaper than three cmp-immediates - reclaims bytes for the line-start dim check below.
    mov ah, [api_stream_state]
    or ah, ah
    je .scan_idle
    dec ah
    je .scan_string
    dec ah
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
    jne .compaction_suppress             ; compacting_msg OR the adjacent esc_stop (Build 11 ESC graceful
                                         ; -stop): capture into the window, never draw, drain the loop
    cmp byte [compact_next], 0
    jne .dim_line                        ; a '$' tool line is open - render it dim to its newline
    ; Build 11 renderer polish: a '$' opens a tool directive. Build 10 HARD-CUT the whole '$'..newline
    ; off the screen, which mangled an inline mention - "verify at 0x7dfe (use $r 7dfe 2)" rendered as
    ; a dangling "(use ". Now render the directive DIMMED (dark grey) instead: the sentence stays
    ; intact and the user SEES the model reach for a tool (tool_call.inc then replays it as its own
    ; dim "> read from .." line). The char is already captured in the window above, so the tool phase
    ; still parses the '$' line verbatim.
    cmp al, '$'
    jne .emit_to_screen                  ; normal char: render at the normal attribute
    ; Build 11 colour-matches-execution: dim a '$' ONLY when it STARTS a line (cursor at column 0),
    ; the same line-start test tool_call's gate uses to decide a real call. A mid-sentence '$' is a
    ; mention - render it as normal prose, not dim. (cursor_col is zeroed before each receive in the
    ; agent_api_stream per-request reset, so a reply that OPENS with a directive also reads as column 0
    ; here, before .emit_to_screen positions it.) The clean-trailing half can't be checked while
    ; streaming (no lookahead), so a
    ; line-start directive followed by same-line prose still dims to its newline - a rare divergence.
    cmp byte [cursor_col], dpi_prompt_col
    jne .emit_to_screen
    mov byte [compact_next], 1           ; open the dim tool line (.emit_to_screen marks text_seen)
    jmp .emit_to_screen                  ; draw the '$' dim - write_char_direct reads compact_next
.compaction_suppress:
    ; A compaction summary (or an ESC graceful-stop) is captured into the window above but never
    ; drawn; mark text_seen so the transport-completion scan still runs (it gates on text_seen) and a
    ; reply that draws nothing is not misread as an empty/dead socket -> spurious reconnect. compact_next
    ; is NOT touched: agent_request resets it every request and compaction never reads it.
    mov byte [api_stream_text_seen], 1
    ret
.dim_line:
    ; Inside an open '$' tool line: render each char dim (compact_next gates the attribute in
    ; write_char_direct) until the newline - or the window cap - closes the line, then fall through to
    ; draw this char/newline at the normal attribute. compact_next is reset every request, so a tool
    ; line with no trailing newline cannot leak dim into the next turn.
    cmp al, 10
    je .dim_line_end
    cmp bx, [chat_context_len_var]
    jb .emit_to_screen
.dim_line_end:
    mov byte [compact_next], 0
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
    ; falls through to .stream_seen_ready (the prior jmp here had a zero displacement)
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

completed_pattern db '_text.done', 0
; '.done' is the trailing 5 chars of '_text.done', so alias it into the longer literal rather than
; carry a second copy. Both are SSE completion markers the scanner walks to the NUL; tls_key_schedule
; _ready selects which (done = transport-final cold path, completed = live-session reuse).
done_pattern equ completed_pattern + 5
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
    mov ah, 0x07                         ; normal text attribute
    mov bx, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jnz .mda_segment                     ; MDA has no dark-grey cell - render the directive normal
    cmp byte [compact_next], 0           ; CGA: an open '$' tool line renders dim (dark grey on black)
    je .segment_ready
    mov ah, 0x08
    jmp short .segment_ready
.mda_segment:
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
