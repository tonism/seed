%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

; Build 12 UI unification: the cold-phased banner. Clear the screen and draw the banner as pure NEWLINE
; FLOW at the top (no absolute rows), printed INSTANTLY (fast-type animation retired): blank line, the
; "seed build NN" splash (centered at seed_col), an 8088-only security note, then a blank line. The
; cursor is left BELOW the banner so the greeting + the whole chat terminal flow from there. On a 286+
; the note line (and its newline) is skipped, so everything shifts up a row on its own.
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
    ; The TLS 1.3 product keeps an honest visible distinction between its
    ; documented 8088 Seed boundary ("security note") and the fully
    ; standards-conforming 286 profile.  This is an informational label in the
    ; build-number gray, not the retired key-leakage warning.  Legacy builds
    ; retain their original "insecure" wording.  The note is right-aligned
    ; under "seed build NN".
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jnz .no_security_note
    mov al, [seed_col]
    add al, security_note_col_offset
    mov [cursor_col], al
    mov bl, [build_attr]                       ; same neutral gray as the build number
    mov si, low_scratch_start + (security_note_text - PHASE_BASE)
    call .print_z
    call .newline                              ; end the security-note line
.no_security_note:
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
; Right-align the pre-286 security note under "seed build NN".  The equate
; auto-tracks both the build-number width and the selected text.
security_note_text:
%ifdef TLS13_PRODUCT_TLS13
    db 'security note'
%else
    db 'insecure'
%endif
security_note_text_end db 0
security_note_col_offset equ (seed_len + 1 + (build_text_end - build_text)) - (security_note_text_end - security_note_text)

%unmacro phase_call_res 1
