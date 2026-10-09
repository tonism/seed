%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name the runtime load address"
%endif

%macro phase_call_aux 1
    db 0xe8
    dw %1-(PHASE_LOAD_ADDR+($-PHASE_BASE)+2)
%endmacro

; Append prior completed results inside the still-open user content string.
; This bounded journal replaces fabricated previous calls with empty arguments.
; The current call and its exact arguments/output remain structured API items.
tool_replay_prev_phase:
    push ds
    pop es
    cld
    xor cx, cx
    mov cl, [fc_history_len]
    cmp cl, fc_history_max
    ja .failed
    push cx
    mov si, PHASE_LOAD_ADDR + (.label - PHASE_BASE)
    mov cx, .label_end - .label
    phase_call_aux 10307
    pop cx
    mov si, fc_history_buf
    phase_call_aux 10307
    clc
    ret
.failed:
    stc
    ret
.label db ' Completed tools: '
.label_end:

%unmacro phase_call_aux 1
