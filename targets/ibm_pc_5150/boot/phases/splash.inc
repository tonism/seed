%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

; Build 12 UI unification: the cold-phased banner. Clear the screen and draw the banner as pure NEWLINE
; FLOW at the top (no absolute rows), printed INSTANTLY (fast-type animation retired): blank line, the
; "seed build NN" splash (centered at seed_col), an 8088-only "insecure" line, then a blank line. The
; cursor is left BELOW the banner so the greeting + the whole chat terminal flow from there. On a 286+
; the "insecure" line (and its newline) is skipped, so everything shifts up a row on its own.
splash_phase:
    mov ax, 0x0600                             ; clear the whole screen (rows 0..24)
    mov bh, 0x07
    xor cx, cx
    mov dh, 24
    mov dl, [screen_cols]
    dec dl
    int 0x10
    xor ax, ax
    mov [cursor_row], ax                       ; cursor_row = cursor_col = 0 (top-left)
    call .newline                              ; row 0 blank
    mov al, [seed_col]
    mov [cursor_col], al
    mov bl, [seed_attr]
    mov si, low_scratch_start + (seed_text - PHASE_BASE)
    call .print_z
    mov al, ' '
    mov bl, [build_attr]
    phase_call_res print_char
    mov si, low_scratch_start + (build_text - PHASE_BASE)
    call .print_z
    call .newline                              ; end the splash line
    ; Build 12 286 secure tier (Decision 3): on a pre-286 (8088-class) machine the channel is NOT secure
    ; -- no real key agreement, no cert authentication ("encrypted, not secure"). Warn with a red
    ; "insecure" line, right-aligned so its tail lines up with the "seed build NN" tail above. HIDDEN on a
    ; 286+ (real ECDHE + RSA-cert channel): the line is skipped entirely, so the terminal starts a row
    ; higher. The honest contrast only makes sense now that the secure tier exists.
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jnz .secure_no_warning
    mov al, [seed_col]
    add al, insecure_warning_col_offset
    mov [cursor_col], al
    mov bl, [error_attr]                       ; red (bright red on CGA) -- a warning, not just dim
    mov si, low_scratch_start + (insecure_text - PHASE_BASE)
    call .print_z
    call .newline                              ; end the insecure line
.secure_no_warning:
    call .newline                              ; blank line below the banner; cursor begins the terminal
    clc
    ret

.print_z:                                      ; print NUL-terminated [ds:si] at the cursor, attr in bl
    lodsb
    or al, al
    jz .print_done
    phase_call_res print_char
    jmp .print_z
.print_done:
    ret

.newline:
    mov byte [cursor_col], 0
    inc byte [cursor_row]
    ret

seed_text db 'seed', 0
; Two-digit build number (Build 10+). Single '0'+N broke at 10 ('0'+10 = ':').
build_text db 'build ', '0' + (build_number / 10), '0' + (build_number % 10)
build_text_end db 0
; The pre-286 "insecure" warning (Decision 3). Right-aligned under "seed build NN": the top line is
; seed(4) + ' '(1) + "build NN"; offset = that length minus "insecure"'s, so the tails line up. The
; equate auto-tracks the build-number width.
insecure_text db 'insecure'
insecure_text_end db 0
insecure_warning_col_offset equ (seed_len + 1 + (build_text_end - build_text)) - (insecure_text_end - insecure_text)

%unmacro phase_call_res 1
