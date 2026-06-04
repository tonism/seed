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
build_text db 'build ', '0' + (build_number / 10), '0' + (build_number % 10), 0

%unmacro phase_call_res 1
