%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

splash_phase:
    mov bl, [ready_attr]
    mov al, 'o'
    phase_call_res show_load_marker
    mov cx, load_ticks
    phase_call_res wait_ticks

    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    mov [cursor_col], al
    mov si, low_scratch_start + (seed_text - PHASE_BASE)
    mov bl, [seed_attr]
    call splash_phase_type_z

    mov al, ' '
    mov bl, [build_attr]
    call splash_phase_type_char

    mov si, low_scratch_start + (build_text - PHASE_BASE)
    call splash_phase_type_z

    ; Build 12 286 secure tier (Decision 3): on a pre-286 (8088-class) machine the channel is NOT
    ; secure -- no real key agreement, no cert authentication ("encrypted, not secure"). Warn with a
    ; dim "insecure" on the 2nd line, right-aligned so its tail lines up with the "seed build NN" tail
    ; above. HIDDEN on a 286+, which runs the real ECDHE + RSA-cert-authenticated channel. The honest
    ; contrast only makes sense now that the secure tier exists.
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jnz .secure_no_warning
    mov byte [cursor_row], seed_row + 1
    mov al, [seed_col]
    add al, insecure_warning_col_offset
    mov [cursor_col], al
    mov si, low_scratch_start + (insecure_text - PHASE_BASE)
    mov bl, [build_attr]                      ; dim/dark -- matches the "build NN" rendering
    call splash_phase_type_z
.secure_no_warning:
    mov cx, done_ticks
    phase_call_res wait_ticks
    clc
    ret

splash_phase_type_z:
    lodsb
    or al, al
    jz .type_done
    call splash_phase_type_char
    jmp splash_phase_type_z
.type_done:
    ret

splash_phase_type_char:
    phase_call_res print_char
    mov cx, type_ticks
    phase_call_res wait_ticks
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
