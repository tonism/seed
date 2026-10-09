; Private application-owner credit pump. No request body may be in TX when
; entering this routine. A granted quota must be sent/retired before reentry.
; The source sector lives in DATA while our inbound stream window is zero.
; Every caller supplies the resident NIC-owner abort frame at 0682.
h2_tx_state equ 0x062e
h2_tx_outbound equ h2_tx_state+61
h2_tx_quota equ h2_tx_state+62
h2_tx_app_owner equ h2_tx_state+65
h2_tx_payload_max equ 427             ; 436 TLS plaintext minus H2 header

h2_tx_reserve:
    cmp byte [h2_tx_outbound], 1
    jne h2_tx_failed
    cmp word [h2_tx_quota], 0
    jne h2_tx_failed
.again:
    ; A final response or GOAWAY before upload completion retires this
    ; request through the caller's explicit failure path, never a silent wait.
    cmp byte [h2_tx_state+18], 0
    jne h2_tx_failed
    cmp byte [h2_tx_state+19], 0
    jne h2_tx_failed
    cmp byte [h2_tx_state+49], 0
    jne h2_tx_failed
    mov ax, h2_tx_payload_max
    mov dx, [h2_tx_state+30]
    or dx, dx
    js .receive
    jnz .connection
    cmp ax, [h2_tx_state+28]
    jbe .connection
    mov ax, [h2_tx_state+28]
.connection:
    mov dx, [h2_tx_state+34]
    or dx, dx
    js .receive
    jnz .bounded
    cmp ax, [h2_tx_state+32]
    jbe .bounded
    mov ax, [h2_tx_state+32]
.bounded:
    or ax, ax
    jz .receive
    mov [h2_tx_quota], ax
    clc
    ret
h2_tx_failed equ $
    stc
    ret
.receive:
    call tls_receive_application_data
    jc h2_tx_failed
    cmp byte [tls_app_content_type], 0x16
    je .again                        ; normal NST was validated and drained
    mov ax, 4
    call tls_h2_invoke
    jc h2_tx_failed
    or ax, ax                        ; no inbound DATA credit during upload
    jnz h2_tx_failed
    push cx
    mov cx, bx
    mov si, h2_tx_state+68
    call h2_tx_control
    pop cx
    jc h2_tx_failed
    mov si, 0x3070
    call h2_tx_control
    jc h2_tx_failed
    call h2_rx_clear_record
    jmp .again

; Send authenticated reply bytes without receiving while TX contains them.
; SI/CX are restored around the real TLS/TCP sender; source stays in its queue.
h2_tx_control:
    jcxz .done
    mov ax, 436
    cmp cx, ax
    jae .bounded
    mov ax, cx
.bounded:
    mov [tls_app_plain_ptr], si
    mov [tls_app_len], ax
    push si
    push cx
    push ax
    call tls_prepare_3c501_receive
    call tls_send_application_data_current_seq
    pushf
    call tls_h2_clear_crypto_prefix
    popf
    pop ax
    pop cx
    pop si
    jc h2_tx_failed
    add si, ax
    sub cx, ax
    jmp h2_tx_control
.done:
    clc
    ret
