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
    ; Build 11 ESC gate: the DPI is live now -- open the int 9 hook's ESC/Ctrl+ESC gate. Until this runs
    ; (the entire boot network bring-up), the hook ignores ESC so it can't longjmp into a half-built chat
    ; loop. Idempotent -- set every loop; only the first transition matters.
    mov byte [dpi_reached], 1
    ; Build 10: run any tool directives the previous turn's response left in the
    ; conversation window, before drawing this prompt. Best-effort: a load failure
    ; just skips tools (never breaks the chat loop). Loaded at net_setup_phase_start
    ; (0x0900), above dpi's own 0x0700 sector; returns here when done.
    mov ax, (((core_tool_phase_end - core_tool_phase_start + 511) / 512) << 8) | ((core_tool_phase_start - $$) / 512)
    mov bx, net_setup_phase_start
    phase_call_res load_core_sectors_at
    jc .tools_skipped
    mov bx, net_setup_phase_start
    call bx
.tools_skipped:
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

    ; Build 10 (agentic loop): the tool phase set agent_loop_pending and staged the continue
    ; directive in dpi_input_buf when a tool fired (and the budget was not spent). Submit it
    ; immediately instead of waiting for the user; the model acts on the tool results and
    ; either calls more tools (loop continues) or answers (no tool -> pending clears).
    cmp byte [agent_loop_pending], 0
    je .read_key
    mov byte [dpi_input_len_byte], agent_continue_len
    jmp .enter

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
    call .wrap_prompt_if_needed
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
    call .erase_previous_input_char
    dec byte [dpi_input_len_byte]
    jmp .read_key

.escape:
    call .clear_input_line
    jmp .read_key

.submit_line:
    call .hide_cursor
    mov dl, [cursor_row]
    mov al, [dpi_prompt_marker_row]
    and al, 0x7f
    mov [cursor_row], al
    mov byte [cursor_col], dpi_prompt_col
    mov al, ' '
    mov bl, [ready_attr]
    push dx
    phase_call_res print_char
    pop dx
    mov [cursor_row], dl
    cmp dl, dpi_prompt_row
    jne .submit_no_scroll
    dec byte [dpi_prompt_marker_row]
.submit_no_scroll:
    call .advance_line
    mov byte [cursor_col], dpi_prompt_col
    or byte [dpi_prompt_marker_row], 0x80
    call .sync_cursor
    ret
.agent_failed:
    mov al, handoff_status_agent_failed
    phase_jmp_res show_failure

.render_prompt:
    cmp byte [api_stream_seen], 0
    je .no_response_seen
    mov byte [api_stream_seen], 0
    call .advance_line
    call .advance_line
    jmp .draw_prompt
.no_response_seen:
    cmp byte [dpi_prompt_marker_row], 0
    jne .draw_prompt
    mov byte [cursor_row], dpi_prompt_row - 2
    mov byte [cursor_col], dpi_prompt_col
.draw_prompt:
    mov al, [cursor_row]
    mov [cursor_row], al
    mov byte [cursor_col], dpi_prompt_col
    mov [dpi_prompt_marker_row], al
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
    call .erase_previous_input_char
    dec byte [dpi_input_len_byte]
    jmp .clear_input_line
.clear_done:
    ret

.erase_previous_input_char:
    mov al, [cursor_col]
    cmp al, dpi_prompt_col + 2
    ja .same_line
    mov al, [cursor_row]
    cmp al, [dpi_prompt_marker_row]
    jbe .erase_done
    dec byte [cursor_row]
    mov al, [screen_cols]
    dec al
    mov [cursor_col], al
    jmp .erase_at_cursor
.same_line:
    dec byte [cursor_col]
.erase_at_cursor:
    mov al, ' '
    mov bl, [ready_attr]
    phase_call_res print_char
    dec byte [cursor_col]
.erase_done:
    ret

.advance_line:
    mov al, [cursor_row]
    cmp al, dpi_prompt_row
    jb .move_down
    mov ax, 0x0601                       ; scroll up 1 line (shared helper; callers reload regs)
    mov cx, 0x0100
    phase_call_res scroll_text_area
    mov byte [cursor_row], dpi_prompt_row
    ret
.move_down:
    inc byte [cursor_row]
    ret

.wrap_prompt_if_needed:
    mov al, [cursor_col]
    cmp al, [screen_cols]
    jb .wrap_done
    mov al, [cursor_row]
    cmp al, dpi_prompt_row
    jb .reuse_prompt_row
    mov ax, 0x0601                       ; scroll up 1 line (shared helper)
    mov cx, 0x0100
    phase_call_res scroll_text_area
    mov al, [dpi_prompt_marker_row]
    test al, 0x80
    jnz .marker_ready
    or al, al
    jz .marker_ready
    dec byte [dpi_prompt_marker_row]
.marker_ready:
    mov byte [cursor_row], dpi_prompt_row
    jmp .wrapped_row_ready
.reuse_prompt_row:
    inc byte [cursor_row]
.wrapped_row_ready:
    mov byte [cursor_col], dpi_prompt_col + 2
.wrap_done:
    ret

.show_cursor:
    mov ah, 0x01
    mov ch, 0x06
    mov cl, 0x07
    int 0x10
    ret

.hide_cursor:
    mov ah, 0x01
    mov ch, 0x20
    mov cl, 0x00
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
