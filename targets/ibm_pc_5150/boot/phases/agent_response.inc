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
    cmp byte [api_stream_completed], 0
    je .need_more
    cmp byte [api_stream_seen], 0
    je .failed
    clc
    ret
.need_more:
    stc
    ret
.failed:
    stc
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
    cmp byte [api_http_state], 0
    je .http_header
    cmp byte [api_http_state], 1
    je .chunk_size
    cmp byte [api_http_state], 2
    je .chunk_size_lf
    cmp byte [api_http_state], 3
    je .chunk_data
    cmp byte [api_http_state], 4
    je .chunk_data_cr
    cmp byte [api_http_state], 5
    je .chunk_data_lf
    ret

.http_header:
    push si
    mov si, PHASE_LOAD_ADDR + (header_end_pattern - PHASE_BASE)
    mov di, api_http_header_match
    call .match_char
    pop si
    jc .raw_ret
    mov byte [api_http_state], 1
    mov word [api_body_len], 0
.raw_ret:
    ret

.chunk_size:
    cmp al, 13
    je .chunk_size_cr
    call .hex_nibble
    jc .raw_ret
    mov bl, al
    xor bh, bh
    mov ax, [api_body_len]
    shl ax, 1
    shl ax, 1
    shl ax, 1
    shl ax, 1
    add ax, bx
    mov [api_body_len], ax
    ret
.chunk_size_cr:
    mov byte [api_http_state], 2
    ret
.chunk_size_lf:
    cmp al, 10
    jne .raw_ret
    cmp word [api_body_len], 0
    jne .chunk_body_ready
    mov byte [api_stream_completed], 1
    mov byte [api_http_state], 6
    ret
.chunk_body_ready:
    mov byte [api_http_state], 3
    ret
.chunk_data:
    call .feed_sse_byte
    dec word [api_body_len]
    jnz .raw_ret
    mov byte [api_http_state], 4
    ret
.chunk_data_cr:
    cmp al, 13
    jne .raw_ret
    mov byte [api_http_state], 5
    ret
.chunk_data_lf:
    cmp al, 10
    jne .raw_ret
    mov byte [api_http_state], 1
    mov word [api_body_len], 0
    ret

.feed_sse_byte:
    cmp byte [api_stream_state], 0
    je .scan_idle
    cmp byte [api_stream_state], 1
    je .scan_string
    cmp byte [api_stream_state], 2
    je .scan_escaped
    ret

.scan_idle:
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
    call .emit_char
    ret
.string_escape:
    mov byte [api_stream_state], 2
    ret
.scan_escaped:
    mov byte [api_stream_state], 1
    cmp al, 'n'
    je .escaped_lf
    cmp al, 'r'
    je .escaped_cr
    cmp al, 't'
    je .escaped_space
    call .emit_char
    ret
.escaped_lf:
    mov al, 10
    call .emit_char
    ret
.escaped_cr:
    mov al, 13
    call .emit_char
    ret
.escaped_space:
    mov al, ' '
    call .emit_char
    ret
.string_done:
    mov byte [api_stream_state], 0
.parser_ret:
    ret

.match_char:
    push bx
    mov bl, [di]
    xor bh, bh
    cmp al, [si + bx]
    je .match_advanced
    cmp al, [si]
    jne .match_reset
    mov byte [di], 1
    stc
    pop bx
    ret
.match_reset:
    mov byte [di], 0
    stc
    pop bx
    ret
.match_advanced:
    inc bl
    cmp byte [si + bx], 0
    je .match_complete
    mov [di], bl
    stc
    pop bx
    ret
.match_complete:
    mov byte [di], 0
    clc
    pop bx
    ret

.hex_nibble:
    cmp al, '0'
    jb .hex_failed
    cmp al, '9'
    jbe .hex_digit
    cmp al, 'A'
    jb .hex_lower
    cmp al, 'F'
    jbe .hex_upper
.hex_lower:
    cmp al, 'a'
    jb .hex_failed
    cmp al, 'f'
    ja .hex_failed
    sub al, 'a' - 10
    clc
    ret
.hex_upper:
    sub al, 'A' - 10
    clc
    ret
.hex_digit:
    sub al, '0'
    clc
    ret
.hex_failed:
    stc
    ret

.emit_char:
    cmp byte [api_stream_seen], 0
    jne .live_ready
    mov byte [cursor_row], dpi_prompt_row - 1
    mov byte [cursor_col], dpi_prompt_col
    mov byte [api_stream_seen], 1
.live_ready:
    cmp al, 13
    je .emit_newline
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
    call .scroll_response
    mov byte [cursor_row], dpi_prompt_row - 1
    mov byte [cursor_col], dpi_prompt_col
.emit_done:
    ret

.scroll_response:
    push ax
    push bx
    push cx
    push dx
    mov ah, 0x06
    mov al, 1
    mov bh, 0x07
    xor cx, cx
    mov dh, dpi_prompt_row
    mov dl, [screen_cols]
    dec dl
    int 0x10
    pop dx
    pop cx
    pop bx
    pop ax
    ret

delta_key_pattern db '"delta":"', 0
header_end_pattern db 13, 10, 13, 10, 0

%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
