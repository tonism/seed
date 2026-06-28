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

; One byte of scratch: 0 = emit to screen + window, 1 = window-only (model-facing data
; the user does not need to see). fs_sector_buffer is the request-body scratch, dead
; while this phase runs between turns (agent_request rebuilds it on the next send).
tool_sink equ fs_sector_buffer

; ---------------------------------------------------------------------------
; Build 10: minimal tool calling - the agent's "keys to the kingdom".
;
; This cold phase runs once per turn (loaded by dpi_phase, before the prompt is
; drawn). It scans the model-compacted conversation window for tool directives
; the model emitted on their own line, executes them, and appends a single
; human-readable result line per call back INTO the window - so the result rides
; the Build 9 context path into the next request AND shows on screen as a dim,
; "> "-prefixed sub-result (the dark look of "> compacting context"). The raw "$..."
; command itself is NOT echoed here; the renderer
; suppresses it from the model's streamed text, so it appears exactly once, as
; this readable line.
;
; Grammar (ASCII, JSON-safe, one call per line, hex args, segment-0 offsets):
;   $r <addr> <len>          read <len> bytes from <addr>
;   $w <addr> <b0> <b1> ...  write the bytes to <addr>
;   $x <addr>                call <addr> (near, seg 0); report returned AX + CF
; Result lines (window + dim screen), readable and re-scan-safe (no leading '$'):
;   read <addr>: <bb> <bb> ...
;   wrote <addr>: <bb> <bb> ...
;   ran <addr>: ax=<aaaa> cf=<0|1>
;
; Write + execute is full control: the agent writes a routine into the arena and
; $x jumps to it; that routine can load any segment / hit any port / call BIOS,
; so three primitives escape the 64K segment-0 limit and own the machine. $x to
; code that never returns hangs the machine - reboot recovery, per the authority
; model ("the tool owns the crash"). Tool calls run BETWEEN turns with the TLS
; session idle-but-alive, a safe point.
;
; Conventions: DS=SS=0 throughout. ES is 0 except inside the screen helpers
; (set to the video segment, restored to 0 before returning to scan/execute, so
; an $x callee always sees ES=0). All window addresses are fixed equ constants.
; ---------------------------------------------------------------------------

tool_phase:
    push bp
    ; Build 11 #5 stage 2: a Ctrl+ESC hard escape longjmp'd here (the hook set esc_panic + jmp chat_loop,
    ; abandoning the hung $x). Draw "> panic stopped" and return WITHOUT scanning -- a scan would re-run the
    ; $x that hung. Clear esc_stop + the adjacent esc_panic together (one word) so "> stopped" never also shows.
    cmp byte [esc_panic], 0
    je .no_panic
    mov si, PHASE_LOAD_ADDR + (.panic_text - PHASE_BASE)
    call .draw_status
    mov word [esc_stop], 0
    jmp .loop_stop                       ; clears agent_loop_pending + count, pop bp, ret (no scan, no continue)
.no_panic:
    mov byte [agent_loop_pending], 0     ; not boot-cleared; clear each run, set on a tool fire
    mov byte [save_pending], 0           ; Build 12 env save/load: clear each run, set on a "$s"
    cld
    mov si, chat_context_start
    mov bx, si
    add bx, [chat_context_used]      ; bx = window end (exclusive)
.scan:
    cmp si, bx
    jae .scan_done
    cmp byte [si], '$'
    jne .scan_adv
    ; Build 11 whole-line gate (1 of 2): a directive must START its line - be the window's first byte,
    ; or sit right after a newline. The reply is now stored after " You:\n" (a real newline), so a
    ; reply-leading "$r .." is a true line start while an in-sentence "$x .." is not. (.exec_directive's
    ; .line_is_call is half 2: only hex+spaces may follow the args.) This is the focused retry of the
    ; earlier line-start gate, which failed only because the reply abutted " You: " with no newline.
    cmp si, chat_context_start
    je .exec_here
    cmp byte [si - 1], 10
    jne .scan_adv                    ; '$' mid-line -> a mention; leave it intact, scan on
.exec_here:
    call .exec_directive
    mov bx, chat_context_start
    add bx, [chat_context_used]      ; window may have grown (result appended)
    jmp .scan
.scan_adv:
    inc si
    jmp .scan
.scan_done:
    ; Agentic-loop decision: a tool fired this turn -> if the budget is not spent, keep
    ; pending=1 (dpi auto-continues next) and stage the fixed continue directive into
    ; dpi_input_buf; else stop and reset the count. count self-heals from boot garbage here
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
    mov si, PHASE_LOAD_ADDR + (.continue_text - PHASE_BASE)
    mov di, dpi_input_buf
    mov cx, agent_continue_len
    rep movsb
    pop bp
    ret
.loop_stop:
    mov byte [agent_loop_pending], 0     ; budget spent -> hand back to the user
.loop_reset:
    mov byte [agent_loop_count], 0
    pop bp
    ret
.continue_text db 'Continue; answer using the tool output above.'   ; clean ASCII (no escaping)
%if ($ - .continue_text) != agent_continue_len
%error "tool_call .continue_text length must equal agent_continue_len (layout.inc)"
%endif

; Build 11 ESC: draw the dim "> stopped" system line (screen-only, NOT in the model window). Mirrors the
; "> read from .." dim prefix in .res_open. Sets api_stream_seen so render_prompt leaves a gap and draws
; the next prompt below it. Called from .scan_done on a graceful stop (after any in-flight tool has run).
.draw_stopped:
    mov si, PHASE_LOAD_ADDR + (.stopped_text - PHASE_BASE)
.draw_status:                            ; si -> relocated z-string; draw it as a dim screen-only system line
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

; si -> '$'. Validate "$<verb> " with verb in r/w/x. If invalid, step past the
; '$' and return (left intact, never executes). If valid: neutralize the '$',
; parse the address, and dispatch. Each executor builds its result and tail-jumps
; .skip_to_eol, which returns to .scan.
.exec_directive:
    mov al, [si + 1]
    cmp al, 'r'
    je .verb_ok
    cmp al, 'w'
    je .verb_ok
    cmp al, 'x'
    je .verb_ok
    cmp al, 's'
    je .verb_save
    inc si
    ret
; Build 12 env save/load: "$s" is a no-arg save request. It stands alone on its line (the next char
; must be a space/newline/end, not a letter -- so "$send..." prose is left intact). Set save_pending
; (dpi runs the cold save phase after this tool phase returns -- M can't load it over itself) and
; neutralize the '$' so it neither re-fires nor shows. No result line here; the save phase draws one.
.verb_save:
    mov al, [si + 2]
    cmp al, ' '
    ja .save_mention                 ; a letter etc. follows -> not a bare "$s"
    mov byte [save_pending], 1
    mov byte [si], ' '
    inc si
    ret
.save_mention:
    inc si
    ret
.verb_ok:
    cmp byte [si + 2], ' '
    je .verb_armed
    inc si
    ret
.verb_armed:
    mov ah, al                       ; ah = verb ([si+1])
    mov bx, si                       ; bx = '$' position (for neutralize / revert)
    add si, 3                        ; -> first arg
    ; Build 11 whole-line gate (2 of 2): .scan already required a line START; here require the line to
    ; END right after the args - only hex + spaces may follow. Together the line is exactly
    ; "$<verb> <hexargs>"; a trailing-prose mention ("$r 7c00 8, then check") is rejected before it runs.
    call .line_is_call
    jc .verb_revert                  ; trailing prose -> a mention; leave '$' intact, step past it
    push ax                          ; save verb
    push bx                          ; save '$' position
    call .parse_hex                  ; ax = addr; advances si; cf if no digits
    pop bx                           ; '$' position
    pop dx                           ; dh = verb
    jc .verb_revert                  ; no valid address -> not a tool; leave '$' intact
    mov bp, ax                       ; bp = target address
    mov byte [bx], ' '               ; neutralize sentinel ONLY on a real call (no prose damage)
    mov byte [agent_loop_pending], 1 ; a tool fired -> candidate for an auto-continue turn
    mov al, dh                       ; verb
    cmp al, 'r'
    je .do_read
    cmp al, 'w'
    je .do_write
    jmp .do_exec
.verb_revert:
    mov si, bx                       ; back to the '$' (left intact), step past it
    inc si
    ret

.do_exec:
    push si                          ; [A] scan ptr (restore before .skip_to_eol)
    push bp                          ; [B] addr, for the result line
    mov ax, bp
    push ds                          ; [C]
    push es                          ; [D]
    cld
    call ax                          ; near indirect call to seg-0:addr
    cld                              ; callee may have left DF set
    pop es                           ; [D]
    pop ds                           ; [C]
    mov bx, ax                       ; bx = returned AX (survives the out_* helpers)
    pushf
    pop dx                           ; dx = returned flags (CF in bit 0)
    pop bp                           ; [B] addr restored
    mov al, '0'                      ; resolve CF now: out_* clobber dx via wait_ticks
    test dl, 1
    jz .exec_cf_char
    mov al, '1'
.exec_cf_char:
    push ax                          ; [E] CF char, emitted last
    mov ax, .word_ran                ; screen: "jump to <addr>" (action only)
    call .res_line
    mov byte [tool_sink], 1          ; the ax/cf result is for the model only (window)
    mov si, PHASE_LOAD_ADDR + (.text_ax - PHASE_BASE)
    call .out_str                    ; " ax="
    mov ax, bx                       ; returned AX
    call .out_hex16
    mov si, PHASE_LOAD_ADDR + (.text_cf - PHASE_BASE)
    call .out_str                    ; " cf="
    pop ax                           ; [E] CF char
    call .out_putc
    call .res_close
    pop si                           ; [A] scan ptr
    jmp .skip_to_eol

.do_read:
    call .parse_hex                  ; ax = len; si now points past the args
    push si                          ; save scan ptr - .res_line clobbers si (see its comment); .do_exec
    jc .read_zero                    ; saves it the same way. Without this .skip_to_eol wild-scans low RAM.
    mov cx, ax
    jmp .read_have_len
.read_zero:
    xor cx, cx
.read_have_len:
    cmp cx, 32                       ; cap so the result line stays bounded
    jbe .read_capped
    mov cx, 32
.read_capped:
    push cx                          ; len
    mov ax, .word_read               ; screen: "read from <addr>" (action only)
    call .res_line
    mov byte [tool_sink], 1          ; the bytes are for the model only (window)
    mov al, ':'
    call .out_putc
    pop cx                           ; len
    jcxz .read_eol
.read_byte:
    mov al, ' '
    call .out_putc
    mov al, [bp]                     ; SS=0 -> seg-0:addr (read target RAM)
    call .out_hex8
    inc bp
    loop .read_byte
.read_eol:
    call .res_close
    pop si                           ; restore scan ptr saved above
    jmp .skip_to_eol

.do_write:
    push bp                          ; [start] save start addr
.write_byte:
    call .parse_hex                  ; ax = next byte (cf when no more hex)
    jc .write_eol
    mov [bp], al                     ; SS=0 -> seg-0:addr (write target RAM)
    inc bp
    jmp .write_byte
.write_eol:
    pop bp                           ; [start] addr
    push si                          ; save scan ptr - .res_line clobbers si (see its comment)
    mov ax, .word_wrote              ; "write to <addr>" - write cannot fail and the
    call .res_line                   ; model already knows the bytes, so no result suffix
    call .res_close
    pop si                           ; restore scan ptr saved above
    jmp .skip_to_eol

; Advance si to the next newline (or window end). Returns to .scan, which then
; recomputes the window end and resumes (the newline re-arms the line-start flag).
.skip_to_eol:
    mov bx, chat_context_start
    add bx, [chat_context_used]
.eol_next:
    cmp si, bx
    jae .eol_done
    cmp byte [si], 10
    je .eol_done
    inc si
    jmp .eol_next
.eol_done:
    ret

; Build 11 standalone-call gate: si -> a directive's first arg. CF=0 if the rest of the line (to the
; next newline or the window end) is ONLY hex digits and spaces - a real call whose args stand alone;
; CF=1 if any other char appears first - an in-sentence mention, which must NOT execute. Preserves si
; and ax (the scanner's live state); scans a private copy in si. di = window end.
.line_is_call:
    push si
    push ax
    mov di, chat_context_start
    add di, [chat_context_used]
.lic_next:
    cmp si, di
    jae .lic_call                    ; window end reached with only hex/space -> a call
    mov al, [si]
    cmp al, 10
    je .lic_call                     ; newline closes a clean directive line -> a call
    cmp al, ' '
    je .lic_adv
    cmp al, '0'
    jb .lic_mention
    cmp al, '9'
    jbe .lic_adv
    or al, 0x20                      ; tolerate 'A'-'F'
    cmp al, 'a'
    jb .lic_mention
    cmp al, 'f'
    ja .lic_mention
.lic_adv:
    inc si
    jmp .lic_next
.lic_call:
    pop ax
    pop si
    clc
    ret
.lic_mention:
    pop ax
    pop si
    stc
    ret

; ---- parse one hex token at [si] ----
; Reads hex digits (upper/lower tolerated) into ax, then skips one trailing space.
; cf=1 if no digit found. Clobbers ax/cx/dx; advances si; preserves bx/bp.
.parse_hex:
    push bx
    xor ax, ax
    xor bx, bx                       ; digit count
.ph_next:
    mov dl, [si]
    cmp dl, '0'
    jb .ph_end
    cmp dl, '9'
    jbe .ph_digit
    or dl, 0x20                      ; tolerate 'A'-'F'
    cmp dl, 'a'
    jb .ph_end
    cmp dl, 'f'
    ja .ph_end
    sub dl, 'a' - 10
    jmp .ph_accum
.ph_digit:
    sub dl, '0'
.ph_accum:
    mov cl, 4
    shl ax, cl
    xor dh, dh
    add ax, dx
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
    mov al, 10
    call .win_putc                   ; window newline
    call .scr_newline                ; screen fresh line (scroll-aware; may touch es)
    call .scr_set_video              ; then point es at video
    mov al, '>'
    call .scr_putc                   ; Build 10: screen-only "> " system-line prefix (matches the DPI
    mov al, ' '
    call .scr_putc                   ; prompt + "> compacting context"); window stays clean for the model
    pop si                           ; verb-word ptr -> si
    add si, PHASE_LOAD_ADDR - PHASE_BASE
    call .out_str                    ; "read "/"wrote "/"ran "
    mov ax, bp
    call .out_hex16                  ; address
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

; .out_putc : al -> window (cap-respected), and screen too UNLESS tool_sink is set
;             (window-only mode, for the model-facing data suffix). ES=video on screen.
.out_putc:
    call .win_putc
    cmp byte [tool_sink], 0
    jne .out_putc_done               ; window-only: data the user does not need to see
    call .scr_putc
.out_putc_done:
    ret
; .scr_putc : al -> [es:di] with the dim attribute, di+=2. No per-char pacing: an agent
; writing a large program emits many tool lines, and a typewriter pause per char would
; drag badly on faster/bigger machines. Dim, but instant.
.scr_putc:
    mov ah, 0x08
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .sp_store
    mov ah, 0x07
.sp_store:
    stosw
    ret

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

; .win_putc : append al to the conversation window if it fits (else drop; compaction
;             fires next request). Clobbers nothing but flags (saves bx/di).
.win_putc:
    push di
    push bx
    mov di, [chat_context_used]
    cmp di, [chat_context_len_var]
    jae .wp_full
    mov bx, di
    mov [chat_context_start + bx], al
    inc word [chat_context_used]
.wp_full:
    pop bx
    pop di
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

.word_read  db 'read from ', 0
.word_wrote db 'write to ', 0
.word_ran   db 'jump to ', 0
.text_ax    db ' ax=', 0
.text_cf    db ' cf=', 0

%unmacro phase_call_res 1
