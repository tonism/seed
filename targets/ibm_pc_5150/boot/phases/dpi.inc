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

%macro phase_jmp_res 1
    db 0xe9
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

dpi_phase:
    cmp byte [api_stream_event_ready], 1
    je .request_phase_ready
    mov ax, (((core_agent_request_phase_end - core_agent_request_phase_start + 511) / 512) << 8) | ((core_agent_request_phase_start - $$) / 512)
    mov bx, net_setup_phase_start
    phase_call_res load_core_sectors_at
    jc .agent_failed
    mov byte [api_stream_event_ready], 1
.request_phase_ready:
    call .show_cursor
    call .drain_kbd
    call .render_prompt

.read_key:
    call .sync_cursor
    mov ah, 0x00
    int 0x16
    cmp al, 13
    je .enter
    cmp al, 8
    je .backspace
    cmp al, 27
    je .escape
    cmp al, 32
    jb .read_key
    cmp al, 127
    jae .read_key
    mov bl, [ready_attr]
    mov dl, [dpi_input_len_byte]
    cmp dl, dpi_input_max_len
    jae .read_key
    xor dh, dh
    mov si, dx
    mov [dpi_input_buf + si], al
    inc byte [dpi_input_len_byte]
    phase_call_res print_char
    jmp .read_key

.enter:
    cmp byte [dpi_input_len_byte], 0
    je .read_key
    call .submit_line
    clc
    ret

.backspace:
    cmp byte [dpi_input_len_byte], 0
    je .read_key
    dec byte [dpi_input_len_byte]
    dec byte [cursor_col]
    mov al, ' '
    mov bl, [ready_attr]
    phase_call_res print_char
    dec byte [cursor_col]
    jmp .read_key

.escape:
    call .clear_input_line
    jmp .read_key

.submit_line:
    call .scroll_screen
    mov byte [cursor_row], dpi_prompt_row
    mov byte [cursor_col], dpi_prompt_col
    ret
.agent_failed:
    mov al, handoff_status_agent_failed
    phase_jmp_res show_failure

.render_prompt:
    mov byte [cursor_row], dpi_prompt_row
    mov byte [cursor_col], dpi_prompt_col
    mov al, '>'
    mov bl, [ready_attr]
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    mov byte [dpi_input_len_byte], 0
    ret

.clear_input_line:
    cmp byte [dpi_input_len_byte], 0
    je .clear_done
    dec byte [dpi_input_len_byte]
    dec byte [cursor_col]
    mov al, ' '
    mov bl, [ready_attr]
    phase_call_res print_char
    dec byte [cursor_col]
    jmp .clear_input_line
.clear_done:
    ret

.scroll_screen:
    push cx
    mov ah, 0x06
    mov al, 1
    mov bh, 0x07
    xor cx, cx
    mov dh, dpi_prompt_row
    mov dl, [screen_cols]
    dec dl
    int 0x10
    pop cx
    ret

.show_cursor:
    mov ah, 0x01
    mov ch, 0x06
    mov cl, 0x07
    int 0x10
    ret

.sync_cursor:
    push ax
    push bx
    push dx
    mov ah, 0x02
    mov bh, 0
    mov dh, [cursor_row]
    mov dl, [cursor_col]
    int 0x10
    pop dx
    pop bx
    pop ax
    ret

.drain_kbd:
    mov ah, 0x01
    int 0x16
    jz .drain_done
    mov ah, 0x00
    int 0x16
    jmp .drain_kbd
.drain_done:
    ret

%unmacro phase_jmp_res 1
%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
