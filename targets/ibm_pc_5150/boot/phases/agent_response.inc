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
    cmp byte [api_stream_completed], 2
    jne .scan_done
    cmp byte [api_http_header_match], 0
    jne .zero_match
    cmp al, '0'
    jne .scan_delta
.zero_match:
    mov si, PHASE_LOAD_ADDR + (zero_chunk_pattern - PHASE_BASE)
    mov di, api_http_header_match
    call .match_char
    jc .scan_delta
    mov al, 'Z'
    call agent_response_trace_step
    mov byte [api_stream_completed], 3
    ret

.scan_done:
    cmp byte [api_stream_done_match], 0
    jne .done_match
    cmp al, '.'
    jne .scan_delta
.done_match:
    mov si, PHASE_LOAD_ADDR + (done_pattern - PHASE_BASE)
    mov di, api_stream_done_match
    call .match_char
    jc .scan_delta
    mov al, 'C'
    call agent_response_trace_step
    mov byte [api_stream_completed], 2
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
    mov al, 'd'
    call agent_response_trace_step
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
    cmp byte [api_stream_seen], 0
    jne .live_ready
    test byte [dpi_prompt_marker_row], 0x80
    jz .seen_ready
    push ax
    call .advance_response_line
    pop ax
.seen_ready:
    push ax
    mov al, 'e'
    call agent_response_trace_step
    pop ax
    mov byte [api_stream_seen], 1
.live_ready:
    cmp al, 10
    je .emit_newline
    mov bl, [crypto_attr]
    push cx
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
    call .scroll_response
    mov byte [cursor_row], dpi_prompt_row - 1
.move_down:
    inc byte [cursor_row]
    mov byte [cursor_col], dpi_prompt_col
    ret

.scroll_response:
    push cx
    mov ah, 0x06
    mov al, 1
    mov bh, 0x07
    mov cx, 0x0100
    mov dh, dpi_prompt_row
    mov dl, [screen_cols]
    dec dl
    int 0x10
    pop cx
    ret

done_pattern db '.completed', 0
delta_key_pattern db '"delta":"', 0
zero_chunk_pattern db '0', 13, 10, 13, 10, 0

agent_response_trace_step:
    push es
    mov bx, debug_trace_video_seg
    mov es, bx
    mov bl, [debug_trace_cursor]
    xor bh, bh
    shl bx, 1
    mov ah, debug_trace_attr
    mov [es:bx], ax
    inc byte [debug_trace_cursor]
    pop es
    ret

%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
