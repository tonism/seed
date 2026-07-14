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
    mov byte [recert_flag], 0
    ; Build 11 ESC gate: the DPI is live now -- open the int 9 hook's ESC/Ctrl+ESC gate. Until this runs
    ; (the entire boot network bring-up), the hook ignores ESC so it can't longjmp into a half-built chat
    ; loop. Idempotent -- set every loop; only the first transition matters.
    mov byte [dpi_reached], 1
    ; Build 12 env save/load: resident chat_loop already ran tool_call. If that armed save_env, run the
    ; save prep at 0x0900 before loading the request helper there.
    cmp byte [save_pending], 0
    je .save_skipped
    mov ax, (((core_save_prep_phase_end - core_save_prep_phase_start + 511) / 512) << 8) | ((core_save_prep_phase_start - $$) / 512)
    mov bx, net_setup_phase_start
    phase_call_res load_core_sectors_at
    jc .save_skipped
    call bx                          ; load_core_sectors_at preserves bx (still = net_setup_phase_start)
.save_skipped:
    cmp byte [api_stream_event_ready], 1
    je .request_phase_ready
    mov ax, (((core_agent_request_phase_end - core_agent_request_phase_start + 511) / 512) << 8) | ((core_agent_request_phase_start - $$) / 512)
    mov bx, net_setup_phase_start
    phase_call_res load_core_sectors_at
    jc .agent_failed
    mov byte [api_stream_event_ready], 1
.request_phase_ready:
    call .drain_kbd
    ; Native tool loop: the tool phase set agent_loop_pending after executing a structured function_call.
    ; An auto-continue is NOT a user
    ; turn: there is no input to read and NO prompt to draw. Drawing one here made render_prompt paint a
    ; "> " that .submit_line then erased -- leaving stray blank rows and resetting render_last_type to
    ; USER, which broke the system->agent spacing (the uneven gaps after "> write to .."). So on a pending
    ; continue, skip all prompt UI and return CF=0 to send function_call_output. The reply still
    ; positions itself (one blank, system->agent, via agent_response) because agent_request's
    ; .build_openai_request clears api_stream_seen on every send, so the reply's first char runs the
    ; positioning branch. render_last_type stays SYSTEM (no draw_prompt), so the reply gets exactly one
    ; blank. On a real user turn (not pending) fall through to draw the prompt and read keys.
    cmp byte [agent_loop_pending], 0
    je .draw_prompt_and_read
    mov byte [dpi_input_len_byte], 0
    clc
    ret
.draw_prompt_and_read:
    call .show_cursor
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
    call .wrap_prompt_if_needed
    jmp .read_key

.enter:
    mov cl, [dpi_input_len_byte]
    xor ch, ch
    jcxz .read_key
    mov si, dpi_input_buf
.enter_nonblank_scan:
    lodsb
    cmp al, ' '
    jne .enter_submit
    loop .enter_nonblank_scan
    call .clear_input_line
    jmp .read_key
.enter_submit:
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
    ; Submitted user text should no longer carry the prompt marker. Write directly through BIOS so the
    ; logical cursor still points at the end of the typed line for the line-advance logic below.
    mov ah, 0x02
    xor bh, bh
    mov dh, [dpi_prompt_marker_row]
    mov dl, dpi_prompt_col
    int 0x10
    mov ax, 0x0920
    mov bx, 0x0007
    mov cx, 0x0001
    int 0x10
    mov dl, [cursor_row]
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
    cmp byte [cursor_col], 0
    je .draw_prompt
    call .advance_line
.draw_prompt:
    mov byte [render_last_type], render_type_user   ; type-change spacing: a new user turn resets the tracker
                                                    ; so the reply's blank comes from the ENTER, not a stale
                                                    ; SYSTEM left by a turn that ended on a tool/status line
    mov al, [cursor_row]
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
    mov cx, 0x0607                       ; scan lines 6..7 (visible)
    jmp .apply_cursor_shape
.hide_cursor:
    mov cx, 0x2000                       ; bit 5 set = cursor off
.apply_cursor_shape:
    mov ah, 0x01
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
