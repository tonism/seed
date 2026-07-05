%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name the runtime load address (net_setup_phase_start)"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

; Tool scratch lives just above this 3-sector phase image (0x0900..0x0f00), below the cursor/phase-state
; bytes around 0x0f55. Do not use fs_sector_buffer here: this phase overlaps it once the tool code grew to
; 3 sectors, and native result writes would corrupt the late screen helpers/string table.
tool_scratch_base equ net_setup_phase_start + 3 * 512
; One byte of scratch: 0 = emit to screen + result buffer, 1 = result-buffer only (model-facing data
; the user does not need to see).
tool_sink equ tool_scratch_base
; Build 12 memory scaling (milestone 1): read_mem/write_mem/exec take a 32-bit flat address and reach it via a far
; seg:off translation (`seg = A>>4, off = A&0xF`), so the agent can address conventional memory beyond
; segment 0. These scratch slots ride the same post-phase scratch as tool_sink:
;   tool_addr   dword  the parsed 32-bit flat address
;   tool_seg    word   the segment computed from tool_addr (the far access reloads es from it per byte,
;                      since the screen-output helpers clobber es)
;   tool_farptr dword  [off,seg] far pointer for `call far` in $x
;   tool_readbuf 32 B  read_mem stages the far bytes here (seg 0) before the hex dump, so the far read (es=seg)
;                      and the dump (es=video) don't fight over es
tool_addr    equ tool_scratch_base + 2
tool_seg     equ tool_scratch_base + 6
tool_farptr  equ tool_scratch_base + 8
tool_readlen equ tool_scratch_base + 12
tool_readbuf equ tool_scratch_base + 14
tool_scratch_end equ tool_readbuf + 32

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
;   read_mem(addr,len)       read up to 32 bytes from addr
;   write_mem(addr,bytes)    write hex bytes to addr
;   exec(addr)               far-call addr; report returned AX + CF
;   save_env()               persist ENV.DAT via the save phase
;   load_env()               reboot through int 19h so boot restore can load ENV.DAT
; Result lines (screen; output buffer for the model):
;   read <addr>: <bb> <bb> ...
;   wrote <addr>: <bb> <bb> ...
;   ran <addr>: ax=<aaaa> cf=<0|1>
;
; Write + execute is full control: the agent writes a routine into the arena and
; exec jumps to it; that routine can load any segment / hit any port / call BIOS,
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
    cld
    cmp byte [tool_fc_state], 1
    je .native_call
    cmp byte [tool_fc_state], 2
    jne .maybe_captured_call
    xor ax, ax
    mov [tool_fc_state], al              ; prior tool result was already sent and answered
    mov [fc_capture_len], ax
    jmp .scan_done
.maybe_captured_call:
    cmp word [fc_capture_len], 0         ; if the explicit state byte was lost, the capture length is
    jne .native_call                     ; still a durable per-turn handoff from the response scanner
    jmp .scan_done
.native_call:
    call .parse_fc_capture
    jc .native_clear
    call .dispatch_fc
    jc .scan_done
    cmp byte [tool_fc_state], 2
    jne .scan_done
    call .compute_fc_suffix_len
    jmp .scan_done
.native_clear:
    mov si, PHASE_LOAD_ADDR + (.response_failed_text - PHASE_BASE)
    call .draw_status
    mov word [fc_capture_len], 0
    mov byte [tool_fc_state], 0
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
; "> read from .." dim prefix in .res_open. Sets api_stream_seen so render_prompt leaves a gap and draws
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
.response_failed_text db '> failed', 0

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
    call .copy_last_field
    jc .fc_parse_fail
    mov [fc_call_id_len], al
    mov bx, PHASE_LOAD_ADDR + (.key_name - PHASE_BASE)
    mov di, fc_name
    mov bp, 15
    call .copy_last_field
    jc .fc_parse_fail
    mov [fc_name_len], al
    mov bx, PHASE_LOAD_ADDR + (.key_args - PHASE_BASE)
    mov di, fc_args_buf
    mov bp, fc_args_max - 1
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
    ret
.native_read:
    call .parse_addr_arg
    jc .dispatch_fail
    call .find_len_arg
    jc .dispatch_fail
    call .parse_dec
    jc .dispatch_fail
    mov cx, ax
    call .arm_fc_result
    jmp .read_have_len
.native_write:
    call .parse_addr_arg
    jc .dispatch_fail
    call .find_bytes_arg
    jc .dispatch_fail
    call .arm_fc_result
    jmp .do_write
.native_exec:
    call .parse_addr_arg
    jc .dispatch_fail
    call .arm_fc_result
    mov si, chat_context_start
    add si, [chat_context_used]
    jmp .do_exec
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
    mov ax, api_fc_call_open_text_len - 3 + api_fc_name_mid_text_len + api_fc_args_mid_text_len
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
    mov [fc_suffix_len], ax
    ret

.parse_addr_arg:
    mov bx, PHASE_LOAD_ADDR + (.arg_addr - PHASE_BASE)
    call .find_arg_key
    jnc .pa_hex
    mov bx, PHASE_LOAD_ADDR + (.arg_addr_num - PHASE_BASE)
    call .find_arg_key
    jc .pa_fail
    call .parse_dec
    jc .pa_fail
    xor dx, dx
    jmp .pa_store
.pa_hex:
    call .parse_hex
    jc .pa_fail
.pa_store:
    mov [tool_addr], ax
    mov [tool_addr + 2], dx
    clc
    ret
.pa_fail:
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
    xor ax, ax
    xor bx, bx
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
    mov dx, ax
    shl ax, 1
    shl dx, 1
    shl dx, 1
    shl dx, 1
    add ax, dx
    xor ch, ch
    add ax, cx
    inc bx
    inc si
    jmp .pd_next
.pd_done:
    or bx, bx
    jz .pd_fail
    pop bx
    clc
    ret
.pd_fail:
    pop bx
    stc
    ret

.do_exec:
    call .addr_to_farptr             ; build [tool_farptr] = off:seg from the 32-bit tool_addr; es back to ds
    mov ax, .word_ran                ; print "> ran <addr>" BEFORE the call: a $x into bad code never returns,
    call .res_line                   ; so the action line must land first or the screen looks stuck on the
    call .res_close                  ; previous directive. es back to 0 for the far call.
    push ds                          ; [C]
    push es                          ; [D]
    cld
    call far [tool_farptr]           ; far call to seg:off; agent code returns with retf (uniform far, so the
    cld                              ; same byte $r/$w reach is executable). callee may have left DF set
    pop es                           ; [D]
    pop ds                           ; [C]
    mov bx, ax                       ; bx = returned AX (survives the out_* helpers)
    pushf
    pop dx                           ; dx = returned flags (CF in bit 0)
    mov al, '0'                      ; resolve CF now: out_* clobber dx via wait_ticks
    test dl, 1
    jz .exec_cf_char
    mov al, '1'
.exec_cf_char:
    push ax                          ; [E] CF char, emitted last
    mov byte [tool_sink], 1          ; the ax/cf suffix continues the same window line, model-only
    mov si, PHASE_LOAD_ADDR + (.text_ax - PHASE_BASE)
    call .out_str                    ; " ax="
    mov ax, bx                       ; returned AX
    call .out_hex16
    mov si, PHASE_LOAD_ADDR + (.text_cf - PHASE_BASE)
    call .out_str                    ; " cf="
    pop ax                           ; [E] CF char
    call .out_putc
    ret

; $r ADDR LEN : read LEN (<=32) bytes from the flat address. The far read (es=segment) and the hex dump
; (es=video) fight over es, so stage the bytes into tool_readbuf (seg 0) first, then dump that near.
.read_have_len:
    cmp cx, 32                       ; cap so the result line stays bounded
    jbe .read_capped
    mov cx, 32
.read_capped:
    mov [tool_readlen], cl           ; len (<=32) - reload it for each loop (res_line/addr_to_esbx clobber cx)
    mov ax, .word_read               ; print "> read from <addr>" BEFORE the far read, so a bad address that
    call .res_line                   ; hangs the read still shows the action (matches $w/$x ordering)
    mov byte [tool_sink], 1          ; the ":" + bytes are for the model only (window)
    mov al, ':'
    call .out_putc
    mov cl, [tool_readlen]
    xor ch, ch
    jcxz .read_eol
    call .addr_to_esbx               ; es=segment, bx=offset of tool_addr (clobbers ax,cx,dx)
    mov cl, [tool_readlen]
    xor ch, ch
    mov di, tool_readbuf
.read_stage:
    mov al, [es:bx]                  ; far read
    mov [di], al                     ; -> near staging buffer (ds=0)
    inc bx
    inc di
    loop .read_stage
    push ds
    pop es                           ; es back to ds for the screen helpers
    mov cl, [tool_readlen]
    xor ch, ch
    mov si, tool_readbuf             ; dump the staged bytes (si survives the out_* helpers)
.read_byte:
    mov al, ' '
    call .out_putc
    mov al, [si]
    call .out_hex8
    inc si
    loop .read_byte
.read_eol:
    call .res_close
    ret

; $w ADDR B B ... : write the byte stream to the flat address. parse_hex preserves bx and es, so the
; far es:bx write pointer rides across each byte parse; off<=0xF + a hex-typed stream never crosses 64K.
.do_write:
    push si                          ; [A] scan ptr - .res_line clobbers si; restore it for the byte parse
    mov ax, .word_wrote              ; print "> wrote <addr>" BEFORE the write (consistent action-first order;
    call .res_line                   ; the model already knows the bytes, so no result suffix)
    call .res_close
    pop si                           ; [A] back to the byte args
    call .addr_to_esbx               ; es=segment, bx=offset (the running far write pointer)
.write_byte:
    call .parse_hex                  ; ax = next byte (cf when no more hex); leaves bx and es intact
    jc .write_eol
    mov [es:bx], al                  ; far write
    inc bx
    jmp .write_byte
.write_eol:
    push ds
    pop es                           ; es back to ds
    ret

; ---- flat 32-bit address -> far access (Build 12 milestone 1) ----
; tool_addr (dword) holds the parsed flat address. On an 8088/V30 every conventional byte (<=1 MB) is
; reachable as seg:off with seg = A>>4, off = A&0xF. The screen helpers clobber es, so the segment is
; also stashed in tool_seg for callers that reload es per byte.
.addr_to_esbx:                       ; -> es = tool_seg = segment, bx = offset. clobbers ax,cx,dx
    mov dx, [tool_addr + 2]          ; high word of the flat address
    cmp dx, ems_flat_base_hi         ; >= 0x0010 (>= 1 MB) -> the EMS windowed region
    jae .addr_to_ems
    ; --- direct conventional far (milestone 1): seg = (low>>4)|(high<<12), off = low&0xF ---
    mov ax, [tool_addr]              ; low word
    mov bx, ax
    and bx, 0x000f                   ; off = A & 0xF
    mov cl, 4
    shr ax, cl                       ; ax = low >> 4
    mov cl, 12
    shl dx, cl                       ; high << 12
    or ax, dx                        ; seg = (low>>4) | (high<<12)
    mov [tool_seg], ax
    mov es, ax
    ret
; --- EMS windowed (milestone 2): rel = addr - 0x100000; page = rel>>14; off = rel & 0x3FFF. Map the page
; into frame slot 0 and return es=ems_frame_seg, bx=off. A single $r/$w must stay within one 16 KB EMS
; page (off+len <= 0x4000); a mid-op page remap on boundary crossings is a later refinement. ---
.addr_to_ems:
    mov ax, [tool_addr]              ; low word
    sub dx, ems_flat_base_hi         ; dx:ax = flat addr - 0x100000 = rel into EMS
    mov bx, ax
    and bx, 0x3fff                   ; bx = page offset within the 16 KB slot
    mov cl, 14
    shr ax, cl                       ; ax = rel's bits 14-15 (low 2 bits of the page number)
    mov cl, 2
    shl dx, cl                       ; dx = rel's bits 16+ shifted up 2
    or ax, dx                        ; ax = logical page number (rel >> 14)
    mov dx, ems_base_port
    out dx, al                       ; frame slot 0 <- logical page (al = page, <= 255 for <= 4 MB)
    mov ax, ems_frame_seg
    mov [tool_seg], ax
    mov es, ax
    ret
.addr_to_farptr:                     ; build [tool_farptr] = offset (word), segment (word) for `call far`
    call .addr_to_esbx
    mov [tool_farptr], bx            ; offset
    mov ax, [tool_seg]
    mov [tool_farptr + 2], ax        ; segment
    push ds
    pop es                           ; es back to ds (the far call reads [tool_farptr] ds-relative)
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

; ---- result emit: one readable line, window (model-facing) + dim screen echo ----
; .res_line : ax -> a phase-local z-string verb word ("read "/"wrote "/"ran "). Starts
;             a fresh indented dim screen line + window newline, emits "  " + the verb
;             word + the address in bp. Leaves ES=video for the rest of the line.
;             Preserves bp (the addr lives there); the scan si must be saved by exec.
.res_line:
    push ax                          ; verb-word ptr
    ; A tool result is visible content on screen, just like a model response. Flag it so dpi's
    ; render_prompt leaves a gap and draws the next prompt BELOW the tool output (and the
    ; auto-continue turn's reply renders cleanly under it) instead of orphaning the cursor.
    mov byte [api_stream_seen], 1
    mov byte [tool_sink], 0          ; the action prefix shows on screen + window
    mov byte [fc_output_len], 0
    mov byte [fc_output_buf], 0
    ; Build 12 type-change spacing: ONE blank line when this SYSTEM block follows a different message type
    ; (the model reply / a user prompt), NONE between successive results within the block. render_last_type
    ; is the shared tracker (reconnect-safe block); every renderer routes its transition through it.
    cmp byte [render_last_type], render_type_system
    je .res_line_nl
    cmp byte [render_last_type], render_type_user
    je .res_line_set_type
    call .scr_newline
.res_line_set_type:
    mov byte [render_last_type], render_type_system
.res_line_nl:
    call .scr_newline                ; screen fresh line (scroll-aware; may touch es)
    call .scr_set_video              ; then point es at video
    mov al, '>'
    call .scr_putc                   ; Build 10: screen-only "> " system-line prefix (matches the DPI
    mov al, ' '
    call .scr_putc                   ; prompt + "> compacting context"); window stays clean for the model
    pop si                           ; verb-word ptr -> si
    add si, PHASE_LOAD_ADDR - PHASE_BASE
    call .out_str                    ; "read "/"wrote "/"ran "
    call .out_hex32                  ; the 32-bit flat address (tool_addr)
    ret
.res_close:
    call .scr_clr_video              ; ES back to 0 for the next directive / $x
    ret

; .out_str : si -> z-string (already relocated to the load address). Emit to window+screen.
.out_str:
    push ax
.ostr_next:
    mov al, [si]
    or al, al
    jz .ostr_done
    call .out_putc
    inc si
    jmp .ostr_next
.ostr_done:
    pop ax
    ret

; .out_putc : al -> function_call_output buffer, and screen too UNLESS tool_sink is set
;             (model-only mode for the result suffix). ES=video on screen.
.out_putc:
    call .fc_out_putc
    cmp byte [tool_sink], 0
    jne .out_putc_done               ; window-only: data the user does not need to see
    call .scr_putc
.out_putc_done:
    ret
.fc_out_putc:
    push bx
    xor bh, bh
    mov bl, [fc_output_len]
    cmp bx, fc_output_max - 1
    jae .fop_done
    mov [fc_output_buf + bx], al
    inc byte [fc_output_len]
    mov byte [fc_output_buf + bx + 1], 0
.fop_done:
    pop bx
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

.out_hex32:                          ; tool_addr (dword) -> 8 hex chars (high word then low)
    mov ax, [tool_addr + 2]
    call .out_hex16
    mov ax, [tool_addr]
    ; fall through to out_hex16 for the low word
.out_hex16:                          ; ax -> 4 hex chars (window + screen)
    push ax
    mov al, ah
    call .out_hex8
    pop ax
    ; fall through for the low byte
.out_hex8:                           ; al -> 2 hex chars
    push ax
    shr al, 1
    shr al, 1
    shr al, 1
    shr al, 1
    call .out_hex_nib
    pop ax
    ; fall through for the low nibble
.out_hex_nib:
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .out_nib_emit
    add al, 'a' - '0' - 10
.out_nib_emit:
    jmp .out_putc

; .win_putc : legacy text-tool window append. Native tool results skip it because
;             function_call_output is the model-facing result. Clobbers flags only.
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

.word_read  db 'read from ', 0
.word_wrote db 'write to ', 0
.word_ran   db 'jump to ', 0
.text_ax    db ' ax=', 0
.text_cf    db ' cf=', 0
.key_call_id db '"call_id":"', 0
.key_name db '"name":"', 0
.key_args db '"arguments":"', 0
.arg_addr db '\', '"', 'addr', '\', '"', ':', '\', '"', 0
.arg_addr_num db '\', '"', 'addr', '\', '"', ':', 0
.arg_len db '\', '"', 'len', '\', '"', ':', 0
.arg_bytes db '\', '"', 'bytes', '\', '"', ':', '\', '"', 0

%unmacro phase_call_res 1
