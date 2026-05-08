%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

api_response_answer_ptr equ low_scratch_start + (api_response_answer_ptr_storage - PHASE_BASE)
api_response_answer_len equ low_scratch_start + (api_response_answer_len_storage - PHASE_BASE)

agent_response_phase:
    call .api_find_answer
    jc .failed
    call .api_type_answer
    clc
    ret
.failed:
    stc
    ret

.api_find_answer:
    mov si, low_scratch_start + (api_answer_output_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, low_scratch_start + (api_answer_output_spaced_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, low_scratch_start + (api_answer_text_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, low_scratch_start + (api_answer_text_spaced_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, low_scratch_start + (api_error_message_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    mov si, low_scratch_start + (api_error_message_spaced_pattern - PHASE_BASE)
    call .api_find_pattern
    jnc .api_measure_answer
    stc
    ret

.api_find_pattern:
    mov [api_response_answer_ptr], si
    mov bx, tls_rx_copy
    mov dx, [tls_app_len]
.next_position:
    or dx, dx
    jz .find_failed
    push bx
    push dx
    mov si, [api_response_answer_ptr]
    mov di, bx
.compare:
    lodsb
    or al, al
    jz .found
    or dx, dx
    jz .no_match
    cmp al, [di]
    jne .no_match
    inc di
    dec dx
    jmp .compare
.found:
    mov [api_response_answer_ptr], di
    pop dx
    pop bx
    clc
    ret
.no_match:
    pop dx
    pop bx
    inc bx
    dec dx
    jmp .next_position
.find_failed:
    stc
    ret

.api_measure_answer:
    mov si, [api_response_answer_ptr]
    mov ax, si
    sub ax, tls_rx_copy
    mov dx, [tls_app_len]
    cmp ax, dx
    jae .measure_failed
    sub dx, ax
    xor cx, cx
.measure_next:
    or dx, dx
    jz .measure_done
    mov al, [si]
    cmp al, '"'
    je .measure_done
    cmp al, 13
    je .measure_done
    cmp al, 10
    je .measure_done
    inc si
    inc cx
    dec dx
    jmp .measure_next
.measure_done:
    or cx, cx
    jz .measure_failed
    mov [api_response_answer_len], cx
    clc
    ret
.measure_failed:
    stc
    ret

.api_type_answer:
    call agent_response_phase_clear_question_area
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, [api_response_answer_ptr]
    mov cx, [api_response_answer_len]
.type_next:
    jcxz .type_done
    lodsb
    push cx
    call agent_response_phase_type_char
    pop cx
    loop .type_next
.type_done:
    ret

agent_response_phase_clear_question_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, seed_row
    xor cl, cl
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

agent_response_phase_type_char:
    phase_call_res print_char
    mov cx, type_ticks
    phase_call_res wait_ticks
    ret

api_answer_output_pattern db '"output_text":"', 0
api_answer_output_spaced_pattern db '"output_text": "', 0
api_answer_text_pattern db '"text":"', 0
api_answer_text_spaced_pattern db '"text": "', 0
api_error_message_pattern db '"message":"', 0
api_error_message_spaced_pattern db '"message": "', 0
api_response_answer_ptr_storage dw 0
api_response_answer_len_storage dw 0

%unmacro phase_call_res 1
