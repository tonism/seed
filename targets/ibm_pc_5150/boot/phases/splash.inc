%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

splash_phase:
    mov cx, load_ticks
    phase_call_res wait_ticks

    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    mov [cursor_col], al
    mov si, low_scratch_start + (seed_text - PHASE_BASE)
    mov bl, [seed_attr]
    phase_call_res type_z

    mov al, ' '
    mov bl, [build_attr]
    phase_call_res type_char

    mov si, low_scratch_start + (build_text - PHASE_BASE)
    phase_call_res type_z

    mov cx, done_ticks
    phase_call_res wait_ticks
    clc
    ret

seed_text db 'seed', 0
build_text db 'build ', '0' + build_number, 0

%unmacro phase_call_res 1
