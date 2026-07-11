%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name the runtime load address"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

; Tool scratch lives above the 0x0d00..0x0f00 function-call capture handoff sector, below the cursor/
; phase-state bytes around 0x0f55. Do not use fs_sector_buffer/capture space here: native result writes
; must not corrupt the raw call bytes before parsing or the late screen helpers/string table.
; One byte of scratch: 0 = emit to screen + result buffer, 1 = result-buffer only (model-facing data
; the user does not need to see), 2 = screen only.
; Build 12 memory scaling (milestone 1): read_mem/write_mem/exec take a 32-bit flat address and reach it via a far
; seg:off translation (`seg = A>>4, off = A&0xF`), so the agent can address conventional memory beyond
; segment 0. These scratch slots ride the same post-phase scratch as tool_sink:
;   tool_addr   dword  the parsed 32-bit flat address
;   tool_seg    word   the segment computed from tool_addr (the far access reloads es from it per byte,
;                      since the screen-output helpers clobber es)
;   tool_farptr dword  [off,seg] far pointer for `call far` in $x
;   tool_readbuf 32 B  read_mem stages capped bytes here (seg 0) before the hex dump, so the far read (es=seg)
;                      and the dump (es=video) don't fight over es
fc_fail_code equ tool_seg                     ; parser-only diagnostic scratch; helper recomputes tool_seg
%if tool_scratch_end > cursor_row
%error "tool scratch overlaps low phase state"
%endif

; ---------------------------------------------------------------------------
; Build 12: native Responses function calling - the agent's "keys to the kingdom".
;
; This cold phase runs once per turn (loaded by dpi_phase, before the prompt is
; drawn). agent_response captures a streamed function_call into compact state;
; this phase parses call_id/name/arguments, executes the native tool, renders a
; dim human-readable result line, and stores JSON-safe output for the next
; request's function_call_output item. The result is not appended to the text
; conversation window; the structured tool output is the model-facing result.
;
; Native tools:
;   read_mem(addr,len)       read up to 4 bytes from addr
;   write_mem(addr,bytes)    write up to 4 hex bytes to addr
;   exec(addr)               far-call addr; report returned AX + CF
;   save_env()               persist ENV.DAT via the save phase
;   load_env()               reboot through int 19h so boot restore can load ENV.DAT
; Result lines show addr only, or addr -> mapped when EMS page-frame translation changes the target.
; Read bytes are kept model-only; the model-facing read prefix stays compact:
;   read from 0x<addr> / model: read 0x<addr>[: <bb> <bb> ...]
;   write to 0x<addr>
;   execute 0x<addr>: ax=<aaaa> cf=<0|1>
;   <read|write|execute> failed: 0x<addr> out of range
;
; Write + execute is full control: the agent writes a routine into the arena and
; exec executes it; that routine can load any segment / hit any port / call BIOS,
; so three primitives escape the 64K segment-0 limit and own the machine. exec to
; code that never returns hangs the machine - reboot recovery, per the authority
; model ("the tool owns the crash"). Tool calls run BETWEEN turns with the TLS
; session idle-but-alive, a safe point.
;
; Conventions: DS=SS=0 throughout. ES is 0 except inside the screen helpers
; (set to the video segment, restored to 0 before returning to scan/execute, so
; an exec callee always sees ES=0). All window addresses are fixed equ constants.
; ---------------------------------------------------------------------------

tool_phase:
    push bp
    ; Build 11 #5 stage 2: a Ctrl+ESC hard escape longjmp'd here (the hook set esc_panic + jmp chat_loop,
    ; abandoning a hung exec). Draw "> panic stopped" and return WITHOUT dispatching -- a dispatch would
    ; re-run the exec that hung. Clear esc_stop + the adjacent esc_panic together (one word) so "> stopped"
    ; never also shows.
    cmp byte [esc_panic], 0
    je .no_panic
    mov si, PHASE_LOAD_ADDR + (.panic_text - PHASE_BASE)
    call .draw_status
    mov word [esc_stop], 0
    jmp .loop_stop                       ; clears agent_loop_pending + count, pop bp, ret (no scan, no continue)
.no_panic:
    mov byte [agent_loop_pending], 0     ; not boot-cleared; clear each run, set on a tool fire
    mov byte [save_pending], 0           ; clear each run; native save_env sets it below
    mov byte [tool_helper_pending], 0    ; memory helper op queued by this parser phase, if any
    mov byte [fc_fail_code], 0
    cld
    cmp byte [tool_fc_state], 1
    je .native_call
    cmp byte [tool_fc_state], 3
    je .native_call
    cmp byte [tool_fc_state], 2
    jne .scan_done
    xor ax, ax
    mov [tool_fc_state], al              ; prior tool result was already sent and answered
    mov [fc_capture_len], ax
    jmp .scan_done
.native_call:
    call .maybe_save_prev_fc
    call .parse_fc_capture
    jc .native_clear
    call .dispatch_fc
    jc .native_clear
    cmp byte [tool_fc_state], 2
    jne .scan_done
    cmp byte [fc_match_state], 0
    je .native_suffix_ready
    mov ax, [fc_suffix_len]              ; .maybe_save_prev_fc temp: low=output len, high=name len
    mov [fc_capture_len], ax             ; after parse, capture length is dead until the next response
.native_suffix_ready:
    call .compute_fc_suffix_len
    jmp .scan_done
.native_clear:
    mov al, [fc_fail_code]
    or al, al
    jnz .native_fail_code_ready
    mov al, '?'
.native_fail_code_ready:
    mov [PHASE_LOAD_ADDR + (.response_failed_code - PHASE_BASE)], al
    mov si, PHASE_LOAD_ADDR + (.response_failed_text - PHASE_BASE)
    call .draw_status
    mov word [fc_capture_len], 0
    mov byte [tool_fc_state], 0
    mov byte [fc_fail_code], 0
.scan_done:
    ; Agentic-loop decision: a tool fired this turn -> if the budget is not spent, keep
    ; pending=1 (dpi auto-continues next) so the request path sends function_call_output;
    ; else stop and reset the count. count self-heals from boot garbage here
    ; (no tool fired on the greeting -> .loop_reset).
    ; Build 11 ESC: a graceful stop this turn -> show "> stopped" and break the agentic loop. Any tool that
    ; fired above already ran (the user's "let the tool finish"); we just don't auto-continue / send the
    ; result back. .loop_stop clears pending + count and returns to the prompt. esc_stop resets next request.
    cmp byte [esc_stop], 0
    je .esc_not_stopped
    call .draw_stopped
    jmp .loop_stop
.esc_not_stopped:
    cmp byte [agent_loop_pending], 0
    je .loop_reset
    cmp byte [agent_loop_count], agent_loop_max
    jae .loop_stop
    inc byte [agent_loop_count]
    pop bp
    ret
.loop_stop:
    mov byte [agent_loop_pending], 0     ; budget spent -> hand back to the user
.loop_reset:
    mov byte [agent_loop_count], 0
    pop bp
    ret

; Build 11 ESC: draw the dim "> stopped" system line (screen-only, NOT in the model window). Mirrors the
; "> read .." dim prefix in .res_open. Sets api_stream_seen so render_prompt leaves a gap and draws
; the next prompt below it. Called from .scan_done on a graceful stop (after any in-flight tool has run).
.draw_stopped:
    mov si, PHASE_LOAD_ADDR + (.stopped_text - PHASE_BASE)
.draw_status:                            ; si -> relocated z-string; draw it as a dim screen-only system line
    cmp byte [render_last_type], render_type_system
    je .ds_gap_done
    mov byte [render_last_type], render_type_system
    call .scr_newline                    ; type-change spacing: blank line before this system status line
.ds_gap_done:
    mov byte [api_stream_seen], 1
    call .scr_newline
    call .scr_set_video
.draw_status_next:
    mov al, [si]
    or al, al
    jz .draw_status_done
    call .scr_putc
    inc si
    jmp .draw_status_next
.draw_status_done:
    call .scr_clr_video
    ret
.stopped_text db '> stopped', 0
.panic_text db '> panic stopped', 0
.saved_text db '> saved', 0
.response_failed_text db '> failed:'
.response_failed_code db '?', 0

; Build 12 native function calling. agent_response captured raw SSE bytes after the
; function_call marker; parse the last seen call_id/name/arguments fields into compact
; buffers, then dispatch by the structured tool name. The old '$' text grammar is gone.
.parse_fc_capture:
    mov byte [fc_call_id_len], 0
    mov byte [fc_name_len], 0
    mov word [fc_args_len], 0
    mov byte [fc_call_id], 0
    mov byte [fc_name], 0
    mov bx, PHASE_LOAD_ADDR + (.key_call_id - PHASE_BASE)
    mov di, fc_call_id
    mov bp, 47
    mov byte [fc_fail_code], 'i'
    call .copy_last_field
    jc .fc_parse_fail
    mov [fc_call_id_len], al
    mov bx, PHASE_LOAD_ADDR + (.key_name - PHASE_BASE)
    mov di, fc_name
    mov bp, 9
    mov byte [fc_fail_code], 'n'
    call .copy_last_field
    jc .fc_parse_fail
    mov [fc_name_len], al
    mov bx, PHASE_LOAD_ADDR + (.key_args - PHASE_BASE)
    mov di, fc_args_buf
    mov bp, fc_args_max - 1
    mov byte [fc_fail_code], 'g'
    call .copy_last_field
    jnc .args_ready
    mov si, fc_capture_buf
    mov cx, [fc_capture_len]
    mov di, fc_args_buf
    mov bp, fc_args_max - 1
    call .copy_json_string
    or ax, ax
    jz .fc_parse_fail
.args_ready:
    mov byte [fc_fail_code], 0
    mov [fc_args_len], ax
    clc
    ret
.fc_parse_fail:
    stc
    ret

.dispatch_fc:
    mov al, [fc_name]
    cmp al, 'r'
    je .native_read
    cmp al, 'w'
    je .native_write
    cmp al, 'e'
    je .native_exec
    cmp al, 's'
    je .native_save
    cmp al, 'l'
    je .native_load
    mov byte [fc_fail_code], 'u'
    stc
    ret
.native_load:
    int 0x19
.native_save:
    call .arm_fc_result
    mov byte [save_pending], 1
    mov byte [fc_output_len], 5
    mov word [fc_output_buf], 'sa'
    mov word [fc_output_buf + 2], 've'
    mov byte [fc_output_buf + 4], 'd'
	mov byte [fc_output_buf + 5], 0
	mov si, PHASE_LOAD_ADDR + (.saved_text - PHASE_BASE)
	call .draw_status
	clc
	ret
.native_read:
    call .parse_addr_arg
    jc .fail_addr
    call .find_len_arg
    jc .fail_len
    call .parse_dec
    jc .fail_dec
    mov cx, ax
    call .arm_fc_result
    cmp cx, 4                            ; global tool cap keeps replay result lines bounded
    jbe .read_queue
    mov cx, 4
.read_queue:
	mov [tool_readlen], cl
	mov byte [tool_helper_pending], 'r'
	clc
	ret
.native_write:
    call .parse_addr_arg
    jc .fail_addr
    call .find_bytes_arg
    jc .fail_bytes
	call .arm_fc_result
	mov [tool_readlen], si               ; byte-string scan pointer for the helper phase
	mov byte [tool_helper_pending], 'w'
	clc
	ret
.native_exec:
    call .parse_addr_arg
    jc .fail_addr
	call .arm_fc_result
	mov byte [tool_helper_pending], 'e'
	clc
	ret
.fail_addr:
    cmp byte [fc_fail_code], 0
    jne .dispatch_fail
    mov byte [fc_fail_code], 'a'
    jmp .dispatch_fail
.fail_len:
    mov byte [fc_fail_code], 'l'
    jmp .dispatch_fail
.fail_dec:
    mov byte [fc_fail_code], 'd'
    jmp .dispatch_fail
.fail_bytes:
    mov byte [fc_fail_code], 'b'
    jmp .dispatch_fail
.dispatch_fail:
    mov word [fc_capture_len], 0
    mov byte [tool_fc_state], 0
    stc
    ret
.arm_fc_result:
    mov byte [tool_fc_state], 2
    mov byte [agent_loop_pending], 1
    mov byte [fc_output_len], 0
    mov byte [fc_output_buf], 0
    ret
.compute_fc_suffix_len:
    mov ax, api_fc_call_open_text_len + api_fc_name_mid_text_len + api_fc_args_mid_text_len
    add ax, api_fc_output_open_text_len + api_fc_output_mid_text_len + api_stream_json_close_text_len
    xor bh, bh
    mov bl, [fc_call_id_len]
    add ax, bx
    add ax, bx
    mov bl, [fc_name_len]
    add ax, bx
    add ax, [fc_args_len]
    mov bl, [fc_output_len]
    add ax, bx
    call .add_prev_fc_suffix_len
    mov [fc_suffix_len], ax
    ret
.add_prev_fc_suffix_len:
    cmp byte [fc_match_state], 0
    je .ap_done
    add ax, api_fc_call_open_text_len + api_fc_name_mid_text_len + api_fc_args_mid_text_len + 1
    add ax, api_fc_output_open_text_len + api_fc_output_mid_text_len
    mov bl, [fc_match_state]
    add ax, bx
    add ax, bx
    mov bl, [fc_capture_len + 1]
    add ax, bx
    mov bl, [fc_capture_len]
    add ax, bx
.ap_done:
    ret

.maybe_save_prev_fc:
    cmp byte [agent_loop_count], 0
    jne .msp_save
    mov byte [fc_match_state], 0
    ret
.msp_save:
    cmp byte [fc_output_len], 0
    je .msp_done
    push ds
    pop es
    mov al, [fc_call_id_len]
    cmp al, fc_prev_call_id_max
    ja .msp_no_room
    mov [fc_match_state], al
    mov si, fc_call_id
    mov di, fc_prev_call_id
    mov cl, al
    xor ch, ch
    rep movsb
    mov al, [fc_name]
    mov [fc_prev_name_code], al
    mov al, [fc_name_len]
    mov [fc_suffix_len + 1], al
    mov al, [fc_output_len]
    cmp al, fc_prev_output_max
    jbe .msp_len_ready
    mov al, fc_prev_output_max
.msp_len_ready:
    mov [fc_suffix_len], al
    mov si, fc_output_buf
    mov di, fc_prev_output
    mov cl, al
    xor ch, ch
    rep movsb
.msp_done:
    ret
.msp_no_room:
    mov byte [fc_match_state], 0
    ret

.parse_addr_arg:
    mov bx, PHASE_LOAD_ADDR + (.arg_addr - PHASE_BASE)
    call .find_arg_key
    jnc .pa_hex
    mov bx, PHASE_LOAD_ADDR + (.arg_addr_num - PHASE_BASE)
    call .find_arg_key
    jc .pa_fail
    call .parse_dec
    jc .pa_dec_fail
    jmp .pa_store
.pa_hex:
    call .parse_hex
    jc .pa_hex_fail
.pa_store:
    mov [tool_addr], ax
    mov [tool_addr + 2], dx
    clc
    ret
.pa_fail:
    mov byte [fc_fail_code], 'k'
    stc
    ret
.pa_hex_fail:
    mov byte [fc_fail_code], 'h'
    stc
    ret
.pa_dec_fail:
    mov byte [fc_fail_code], 'd'
    stc
    ret
.find_len_arg:
    mov bx, PHASE_LOAD_ADDR + (.arg_len - PHASE_BASE)
    jmp .find_arg_key
.find_bytes_arg:
    mov bx, PHASE_LOAD_ADDR + (.arg_bytes - PHASE_BASE)
    jmp .find_arg_key
.find_arg_key:
    mov si, fc_args_buf
    mov cx, [fc_args_len]
    jmp .find_key

.copy_last_field:
    mov [tool_farptr], di
    mov [tool_farptr + 2], bp
    mov word [tool_readlen], 0
    mov byte [tool_sink], 0              ; found flag, scratch until result emit starts
    mov si, fc_capture_buf
    mov cx, [fc_capture_len]
.clf_next:
    call .find_key
    jc .clf_done
    push bx
    mov di, [tool_farptr]
    mov bp, [tool_farptr + 2]
    call .copy_json_string
    pop bx
    mov [tool_readlen], ax
    mov byte [tool_sink], 1
    jmp .clf_next
.clf_done:
    cmp byte [tool_sink], 0
    jz .clf_fail
    mov ax, [tool_readlen]
    clc
    ret
.clf_fail:
    stc
    ret

.find_key:                               ; bx=key, si/cx=range -> si/cx after key
    xor di, di
.fk_next:
    jcxz .fk_fail
    lodsb
    dec cx
    cmp al, [bx + di]
    je .fk_adv
    cmp al, [bx]
    jne .fk_reset
    mov di, 1
    jmp .fk_next
.fk_reset:
    xor di, di
    jmp .fk_next
.fk_adv:
    inc di
    cmp byte [bx + di], 0
    jne .fk_next
    clc
    ret
.fk_fail:
    stc
    ret

.copy_json_string:                       ; si/cx after key, di=dest, bp=max chars -> ax=len
    xor dx, dx
.cjs_next:
    jcxz .cjs_done
    lodsb
    dec cx
    cmp al, '\'
    je .cjs_escape
    cmp al, '"'
    je .cjs_done
.cjs_store:
    cmp dx, bp
    jae .cjs_next
    stosb
    inc dx
    jmp .cjs_next
.cjs_escape:
    cmp dx, bp
    jae .cjs_skip_escaped
    stosb
    inc dx
.cjs_skip_escaped:
    jcxz .cjs_done
    lodsb
    dec cx
    jmp .cjs_store
.cjs_done:
    mov byte [di], 0
    mov ax, dx
    ret

.parse_dec:
    push bx
    push bp
    xor ax, ax
    xor dx, dx
    mov byte [tool_sink], 0
.pd_skip_space:
    cmp byte [si], ' '
    jne .pd_quote
    inc si
    jmp .pd_skip_space
.pd_quote:
    cmp word [si], 0x225c
    jne .pd_next
    inc si
    inc si
.pd_next:
    mov cl, [si]
    cmp cl, '0'
    jb .pd_done
    cmp cl, '9'
    ja .pd_done
    sub cl, '0'
    mov bx, ax
    mov bp, dx
    shl ax, 1
    rcl dx, 1
    shl bx, 1
    rcl bp, 1
    shl bx, 1
    rcl bp, 1
    shl bx, 1
    rcl bp, 1
    add ax, bx
    adc dx, bp
    xor ch, ch
    add ax, cx
    adc dx, 0
    inc byte [tool_sink]
    inc si
    jmp .pd_next
.pd_done:
    cmp byte [tool_sink], 0
    jz .pd_fail
    pop bp
    pop bx
    clc
    ret
.pd_fail:
    pop bp
    pop bx
    stc
    ret

; ---- parse one hex token at [si] into a 32-bit value ----
; Reads hex digits (upper/lower tolerated) into dx:ax (high:low), then skips one trailing space.
; cf=1 if no digit found. Clobbers ax/cx/dx; advances si; preserves bx/bp. Callers that want a 16-bit
; value (a $r length, a $w byte) just use ax and ignore dx. (Build 12: widened from 16-bit so $r/$w/$x
; can take a flat address beyond segment 0.)
.parse_hex:
    push bx
    xor ax, ax
    xor dx, dx
    xor bx, bx                       ; digit count
.ph_skip_space:
    cmp byte [si], ' '
    jne .ph_quote
    inc si
    jmp .ph_skip_space
.ph_quote:
    cmp word [si], 0x225c
    jne .ph_prefix
    inc si
    inc si
.ph_prefix:
    cmp byte [si], '0'
    jne .ph_next
    mov cl, [si + 1]
    or cl, 0x20
    cmp cl, 'x'
    jne .ph_next
    add si, 2
.ph_next:
    mov cl, [si]
    cmp cl, '0'
    jb .ph_end
    cmp cl, '9'
    jbe .ph_digit
    or cl, 0x20                      ; tolerate 'A'-'F'
    cmp cl, 'a'
    jb .ph_end
    cmp cl, 'f'
    ja .ph_end
    sub cl, 'a' - 10
    jmp .ph_accum
.ph_digit:
    sub cl, '0'
.ph_accum:
    shl ax, 1                        ; dx:ax <<= 4 (one nibble; carry walks ax's top bit into dx)
    rcl dx, 1
    shl ax, 1
    rcl dx, 1
    shl ax, 1
    rcl dx, 1
    shl ax, 1
    rcl dx, 1
    or al, cl                        ; low nibble is 0 after the shift -> OR in the digit (0..15)
    inc bx
    inc si
    jmp .ph_next
.ph_end:
    or bx, bx
    jz .ph_fail
    cmp byte [si], ' '
    jne .ph_ok
    inc si
.ph_ok:
    pop bx
    clc
    ret
.ph_fail:
    pop bx
    stc
    ret

; .scr_putc : al -> screen at the tracked cursor with the dim attribute, advancing cursor_col.
; No per-char pacing: an agent writing a large program emits many tool lines, and a typewriter
; pause per char would drag badly on faster/bigger machines. Dim, but instant.
.scr_putc:
    push bx
    mov bl, 0x08
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .sp_store
    mov bl, 0x07
.sp_store:
    phase_call_res print_char
    pop bx
    mov al, [cursor_col]
    cmp al, [screen_cols]
    jb .sp_done
    call .scr_newline
.sp_done:
    ret

; ---- screen helpers (dim, fast-typed, scroll-aware; modeled on the compaction status) ----
.scr_set_video:
    mov ax, [video_seg]
    mov es, ax
    ret
.scr_clr_video:
    push ds
    pop es
    ret
; advance to a fresh screen line (scroll the text area at the bottom), set di to
; its byte offset, and track cursor_row so dpi draws the next prompt below it.
.scr_newline:
    cmp byte [cursor_row], dpi_prompt_row
    jb .nl_inc
    push bx                          ; int 0x10 scroll can clobber bx/bp - preserve both
    push bp
    mov ah, 0x06
    mov al, 1
    mov bh, 0x07
    mov cx, 0x0100
    mov dh, dpi_prompt_row
    mov dl, [screen_cols]
    dec dl
    int 0x10
    pop bp
    pop bx
    mov byte [cursor_row], dpi_prompt_row - 1
.nl_inc:
    inc byte [cursor_row]
    mov al, [screen_cols]
    mul byte [cursor_row]
    shl ax, 1
    mov di, ax
    mov byte [cursor_col], 0
    ret

.key_call_id db '"call_id":"', 0
.key_name db '"name":"', 0
.key_args db '"arguments":"{', 0
.arg_addr db '\', '"', 'addr', '\', '"', ':', '\', '"', 0
.arg_addr_num db '\', '"', 'addr', '\', '"', ':', 0
.arg_len db '\', '"', 'len', '\', '"', ':', 0
.arg_bytes db '\', '"', 'bytes', '\', '"', ':', 0

%unmacro phase_call_res 1
