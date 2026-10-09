; H2 response owner at 2a00. T remains at 0900..0d00. Request helper
; 2800..2a00 owns the final resident unwind and state retirement.
bits 16
cpu 8086
org 0x2a00
%include "exchange-abi.inc"
dw exchange
h2 equ 0x062e
tx equ 0x3912

exchange:
    call load_core_sectors_at          ; AX/BX supplied by completed X
    jc failed
.receive:
    cmp byte [esc_stop], 0
    jne failed
    call tls_receive_application_data
    jc failed
    cmp byte [tls_app_content_type], 0x16
    je .receive                       ; normal owner validated/drained NST
    mov ax, 4
    call exchange_h2
    jc failed
    cmp word [h2+45], 0               ; final HTTP status not known yet
    je .accepted_status
    cmp word [h2+45], 200
    jne failed                       ; error bodies never reach model parser
.accepted_status:
    push ax                           ; authenticated stripped DATA length
    push cx
    mov cx, bx
    mov si, h2+68
    call h2_tx_control
    pop cx
    jc .reply_failed
    mov si, 0x3070
    call h2_tx_control
    jc .reply_failed
    pop ax
    mov [tls_app_len], ax
    mov word [tls_app_data_ptr], 0x2e70
    call 0x0900                       ; only authenticated DATA reaches T
    cmp byte [esc_stop], 0
    jne failed
    call credit_consumed
    jc failed
    call h2_rx_clear_record
    cmp byte [h2+18], 2
    jne .receive
    ; Complete a carried frame/ticket before DPI can reuse the RX arena.
    cmp word [tls_buffered_payload_len], 0
    jne .receive
    cmp byte [h2+9], 0
    jne .receive
    cmp word [h2+10], 0
    jne .receive
    cmp word [h2+45], 200
    jne failed
    cmp byte [api_stream_completed], 1
    jne failed
    cmp byte [api_stream_text_seen], 0
    jne .complete
    cmp byte [tool_fc_state], 1
    jne failed
.complete:
    mov byte [api_stream_completed], 3
    clc
    ret
.reply_failed:
    pop ax
    jmp failed

; A failed replacement must reach this intact owner so rendered text cannot
; be replayed. The general low bridge may not bypass that failure policy.
exchange_h2:
    mov dx, disk_failed
    push dx
    mov [0x0682], sp
    call tls_h2_invoke
    pop dx
    pushf
    mov dx, sp
    add dx, 4                         ; saved flags plus wrapper return
    mov [0x0682], dx
    popf
    ret
disk_failed:
    add sp, 2                         ; discard the wrapper's stale return
    mov [0x0682], sp
failed:
    cmp byte [api_stream_text_seen], 0
    jne .no_replay
    cmp byte [esc_stop], 0
    je .retire
.no_replay:
    mov byte [reconnect_retries], 0
.retire:
    mov al, 0x11
    call ne_transmit_tcp_flags         ; best effort before key retirement
    jmp request_aux_fail

credit_consumed:
    call h2_rx_consume_credit
    jc .done
    or ax, ax
    jz .done
    mov bx, ax
    mov di, tx+5
    xor dx, dx                        ; connection WINDOW_UPDATE first
    xor si, si
    call window_frame
    cmp byte [h2+18], 2
    je .send
    mov dx, [h2+20]
    mov si, [h2+22]
    call window_frame
.send:
    mov cx, di
    sub cx, tx+5
    mov si, tx+5
    call h2_tx_control
.done:
    ret
window_frame:
    xor ax, ax
    stosw
    mov ax, 0x0804
    stosw
    xor al, al
    stosb
    mov ax, dx
    stosw
    mov ax, si
    stosw
    xor ax, ax
    stosw
    mov ax, bx
    xchg al, ah
    stosw
    ret
