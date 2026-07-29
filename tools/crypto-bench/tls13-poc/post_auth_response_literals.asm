; Cold bounded helpers and immutable literals for the post-auth response phase.
;
; This phase replaces the request adapter at 0000:3400 after all outbound
; application data has been sealed.  It occupies only the executable-safe
; prefix below K14 runtime state at 0x3510.

bits 16
cpu 8086
org 0x3400

%ifndef POST_AUTH_RESPONSE_TCP_ACK
%error "post-auth response literals require the resident TCP ACK entry"
%endif
%ifndef POST_AUTH_RESPONSE_SUPERVISOR_RECEIVE
%error "post-auth response literals require the safe supervisor receive entry"
%endif
%ifndef POST_AUTH_RESPONSE_PERSIST_FAIL
%error "post-auth response literals require the persistent secure failure entry"
%endif

literal_header:
    db 'PAS2'
    dw 1
    dw literal_end - literal_header
    dw response_marker_advance
    dw response_clear_quarantine
    dw response_clear_state

; AL=authenticated byte, BP=position byte, DI=token, DL=len, DH=colon index.
; Return CF=1 only when the complete token has matched.
response_marker_advance:
    mov bl, [ss:bp]
    xor bh, bh
    cmp dh, 0xff
    je .compare
    cmp al, ' '
    je .whitespace
    cmp al, 9
    je .whitespace
    cmp al, 13
    je .whitespace
    cmp al, 10
    je .whitespace
.compare:
    cmp al, [di + bx]
    je .matched
    cmp al, [di]
    jne .reset
    mov byte [ss:bp], 1
    clc
    ret
.reset:
    mov byte [ss:bp], 0
    clc
    ret
.whitespace:
    or bl, bl
    jz .accepted
    cmp bl, dh
    je .accepted
    inc dh
    cmp bl, dh
    je .accepted
    jmp short .reset
.accepted:
    clc
    ret
.matched:
    inc bl
    mov [ss:bp], bl
    cmp bl, dl
    jne .accepted
    mov byte [ss:bp], 0
    stc
    ret

response_clear_quarantine:
    push ds
    pop es
    xor ax, ax
    mov di, 0x0d00
    mov cx, 0x0200
    rep stosb
    mov di, 0x3600
    mov cx, 0x0238
    rep stosb
    mov di, 0x3910
    mov cx, 0x0230
    rep stosb
    ret

response_clear_state:
    push ds
    pop es
    xor ax, ax
    mov di, 0x3c4a
    mov cx, 0x0018
    rep stosb
    ret

response_http_prefix db 'HTTP/1.1 '
response_http_prefix_len equ $ - response_http_prefix
response_output_type_marker db '"type":"response.output_text.delta"'
response_output_type_marker_len equ $ - response_output_type_marker
response_delta_prefix_marker db '"delta":"'
response_delta_prefix_marker_len equ $ - response_delta_prefix_marker
response_completed_type_marker db '"type":"response.completed"'
response_completed_type_marker_len equ $ - response_completed_type_marker
response_http_terminal_marker db '0',13,10,13,10
response_http_terminal_marker_len equ $ - response_http_terminal_marker

; Post-request continuations live here because K14 record AEAD owns
; 0x32af..sym_k_work_end. This exact-copied prefix remains executable below
; K14's persistent state at 0x3510.
post_auth_live_response_ack_more:
    call POST_AUTH_RESPONSE_TCP_ACK
    jc .failed
    jmp POST_AUTH_RESPONSE_SUPERVISOR_RECEIVE
.failed:
    jmp POST_AUTH_RESPONSE_PERSIST_FAIL

post_auth_live_response_success_text:
    db 13,10,'ok',13,10,'PASS',13,10,'RESULT',13,10,0

literal_end:

%if (literal_end - literal_header) > (0x3510 - 0x3400)
%error "post-auth response literals reach K14 runtime state"
%endif
