; Cold authenticated OpenAI Responses SSE scanner.
;
; Load this controller at 0000:0900 only after the request controller has
; finished and scrubbed its low plaintext.  Ciphertext is opened in place into
; the three proven K14 quarantine spans.  No byte reaches the HTTP/SSE scanner
; until the complete TLS record tag has verified.  Scanner state is finite and
; retained across authenticated record boundaries, so HTTP fields and JSON
; markers may cross any record seam.
;
; Entry ABI (near calls, DS=ES=SS=0, DF clear):
;   0 response_start
;   1 response_record_begin   TLS header already at 0x39a0
;   2 response_record_chunk   SI=ciphertext, CX=1..383
;   3 response_record_finish  SI=16-byte tag
;   4 response_eof
;   5 response_abort
;
; A valid record finish returns CF=0, AX=0 while more authenticated response
; data is required and CF=0, AX=1 only after output_text delta values aggregate
; to exactly the two bytes "ok" (one or multiple events), followed by a later
; response.completed event and the exact authenticated HTTP terminal chunk.
; Every rejection returns CF=1, AX=0 and makes the stream terminal.

bits 16
cpu 8086
org 0x0900

%ifndef POST_AUTH_SYM_OPEN_BEGIN
%error "POST_AUTH_SYM_OPEN_BEGIN must name sym_server_app_open_begin"
%endif
%ifndef POST_AUTH_SYM_OPEN_CHUNK
%error "POST_AUTH_SYM_OPEN_CHUNK must name sym_open_chunk"
%endif
%ifndef POST_AUTH_SYM_OPEN_FINISH
%error "POST_AUTH_SYM_OPEN_FINISH must name sym_open_finish"
%endif
%ifndef POST_AUTH_RESPONSE_HTTP_PREFIX
%error "response literal addresses are required"
%endif
%ifndef POST_AUTH_RESPONSE_OUTPUT_MARKER
%error "response literal addresses are required"
%endif
%ifndef POST_AUTH_RESPONSE_DELTA_MARKER
%error "response literal addresses are required"
%endif
%ifndef POST_AUTH_RESPONSE_COMPLETE_MARKER
%error "response literal addresses are required"
%endif
%ifndef POST_AUTH_RESPONSE_HTTP_TERMINAL
%error "response terminal-chunk literal address is required"
%endif
%ifndef POST_AUTH_RESPONSE_MARKER_ADVANCE
%error "response helper addresses are required"
%endif
%ifndef POST_AUTH_RESPONSE_CLEAR_QUARANTINE
%error "response helper addresses are required"
%endif
%ifndef POST_AUTH_RESPONSE_CLEAR_STATE
%error "response state-clear helper address is required"
%endif

controller_header:
    db 'PAR2'
    dw 1
    dw controller_end - controller_header
controller_entry_table:
    dw response_start
    dw response_record_begin
    dw response_record_chunk
    dw response_record_finish
    dw response_eof
    dw response_fatal

sym_record_active          equ 0x3520
sym_io_base                equ 0x39a0

response_span0             equ 0x0d00
response_span0_len         equ 0x0200
response_span1             equ 0x3600
response_span1_len         equ 0x0238
response_tag_buffer        equ 0x3910
response_span2             equ 0x3920
response_span2_len         equ 0x0220
response_quarantine_max    equ \
    response_span0_len + response_span1_len + response_span2_len

request_status             equ 0x3c49
response_initialized       equ 0x3c4a
response_active            equ 0x3c4b
response_terminal          equ 0x3c4c
response_status            equ 0x3c4d
response_expected          equ 0x3c4e
response_received          equ 0x3c50
response_source            equ 0x3c52
response_source_remaining  equ 0x3c54
response_piece_len         equ 0x3c56
response_content_len       equ 0x3c58
response_http_state        equ 0x3c5a
response_header_state      equ 0x3c5b
response_body_started      equ 0x3c5c
response_marker_stage      equ 0x3c5d
response_marker_pos        equ 0x3c5e
response_output_count      equ 0x3c5f
response_delta_nonempty    equ 0x3c60
response_extra_pos         equ 0x3c61
response_state_end         equ 0x3c62

http_prefix                equ POST_AUTH_RESPONSE_HTTP_PREFIX
http_prefix_len            equ POST_AUTH_RESPONSE_HTTP_PREFIX_LEN
output_type_marker         equ POST_AUTH_RESPONSE_OUTPUT_MARKER
output_type_marker_len     equ POST_AUTH_RESPONSE_OUTPUT_MARKER_LEN
delta_prefix_marker        equ POST_AUTH_RESPONSE_DELTA_MARKER
delta_prefix_marker_len    equ POST_AUTH_RESPONSE_DELTA_MARKER_LEN
completed_type_marker      equ POST_AUTH_RESPONSE_COMPLETE_MARKER
completed_type_marker_len  equ POST_AUTH_RESPONSE_COMPLETE_MARKER_LEN
http_terminal_marker       equ POST_AUTH_RESPONSE_HTTP_TERMINAL
http_terminal_marker_len   equ POST_AUTH_RESPONSE_HTTP_TERMINAL_LEN
marker_advance             equ POST_AUTH_RESPONSE_MARKER_ADVANCE
clear_quarantine           equ POST_AUTH_RESPONSE_CLEAR_QUARANTINE
clear_response_state       equ POST_AUTH_RESPONSE_CLEAR_STATE

response_start:
    cld
    call clear_quarantine
    call clear_response_state
    cmp byte [request_status], 1
    jne response_fatal
    mov byte [response_initialized], 1
    xor ax, ax
    clc
    ret

response_record_begin:
    cld
    cmp byte [request_status], 1
    jne response_fatal
    cmp word [response_initialized], 0x0001
    jne response_fatal
    cmp word [response_terminal], 0
    jne response_fatal
    mov ax, [sym_io_base + 3]
    xchg al, ah
    cmp ax, 17
    jb response_fatal
    sub ax, 16
    cmp ax, response_quarantine_max
    ja response_fatal
    mov [response_expected], ax
    call POST_AUTH_SYM_OPEN_BEGIN
    jc response_fatal
    call clear_quarantine
    mov word [response_received], 0
    mov byte [response_active], 1
    xor ax, ax
    clc
    ret

response_record_chunk:
    cmp byte [response_active], 1
    jne response_fatal
    or cx, cx
    jz response_fatal
    cmp cx, 383
    ja response_fatal
    mov ax, [response_received]
    add ax, cx
    jc response_fatal
    cmp ax, [response_expected]
    ja response_fatal
    mov [response_source], si
    mov [response_source_remaining], cx

.piece:
    mov bx, [response_received]
    cmp bx, response_span0_len
    jae .span1
    mov di, response_span0
    add di, bx
    mov ax, response_span0_len
    sub ax, bx
    jmp short .span_ready
.span1:
    sub bx, response_span0_len
    cmp bx, response_span1_len
    jae .span2
    mov di, response_span1
    add di, bx
    mov ax, response_span1_len
    sub ax, bx
    jmp short .span_ready
.span2:
    sub bx, response_span1_len
    cmp bx, response_span2_len
    jae response_fatal
    mov di, response_span2
    add di, bx
    mov ax, response_span2_len
    sub ax, bx
.span_ready:
    mov cx, [response_source_remaining]
    cmp cx, ax
    jbe .piece_len_ready
    mov cx, ax
.piece_len_ready:
    mov [response_piece_len], cx
    mov si, [response_source]
    push ds
    pop es
    rep movsb
    mov [response_source], si
    mov ax, [response_piece_len]
    sub [response_source_remaining], ax
    add [response_received], ax
    mov si, di
    sub si, ax
    mov cx, ax
    call POST_AUTH_SYM_OPEN_CHUNK
    jc response_fatal
    cmp word [response_source_remaining], 0
    jne .piece
    xor ax, ax
    clc
    ret

response_record_finish:
    cmp byte [response_active], 1
    jne response_fatal
    mov ax, [response_received]
    cmp ax, [response_expected]
    jne response_fatal
    push ds
    pop es
    mov di, response_tag_buffer
    mov cx, 16
    rep movsb
    mov si, response_tag_buffer
    call POST_AUTH_SYM_OPEN_FINISH
    jc response_fatal
    mov byte [response_active], 0

    mov bx, [response_expected]
.find_inner_type:
    or bx, bx
    jz response_fatal
    dec bx
    call response_load_byte
    or al, al
    jz .find_inner_type
    cmp al, 0x17
    jne response_fatal
    mov [response_content_len], bx
    call scan_authenticated_content
    jc response_fatal
    call clear_quarantine
    xor ax, ax
    cmp byte [response_status], 1
    jne .more
    inc ax
.more:
    clc
    ret

response_eof:
    cmp byte [request_status], 1
    jne response_fatal
    cmp word [response_initialized], 0x0001
    jne response_fatal
    cmp byte [response_body_started], 1
    jne response_fatal
    cmp word [response_terminal], 0x0100
    jne response_fatal
    mov ax, 1
    clc
    ret

; BX is a logical quarantine offset. Return AL without exposing a pointer.
response_load_byte:
    cmp bx, response_span0_len
    jae .span1
    mov al, [response_span0 + bx]
    ret
.span1:
    sub bx, response_span0_len
    cmp bx, response_span1_len
    jae .span2
    mov al, [response_span1 + bx]
    add bx, response_span0_len
    ret
.span2:
    sub bx, response_span1_len
    mov al, [response_span2 + bx]
    add bx, response_span0_len + response_span1_len
    ret

scan_authenticated_content:
    mov dx, [response_content_len]
    cmp dx, response_span0_len
    jbe .only_span0
    mov si, response_span0
    mov cx, response_span0_len
    call scan_span
    jc .failed
    sub dx, response_span0_len
    cmp dx, response_span1_len
    jbe .only_span1
    mov si, response_span1
    mov cx, response_span1_len
    call scan_span
    jc .failed
    sub dx, response_span1_len
    mov si, response_span2
    mov cx, dx
    jmp short scan_span
.only_span1:
    mov si, response_span1
    mov cx, dx
    jmp short scan_span
.only_span0:
    mov si, response_span0
    mov cx, dx
    jmp short scan_span
.failed:
    stc
    ret

scan_span:
    push dx
    or cx, cx
    jz .done
.byte:
    lodsb
    call scan_response_byte
    jc .failed
    loop .byte
.done:
    pop dx
    clc
    ret
.failed:
    pop dx
    stc
    ret

scan_response_byte:
    cmp byte [response_body_started], 1
    je scan_response_marker
    mov bl, [response_http_state]
    xor bh, bh
    cmp bl, http_prefix_len
    jb .http_prefix
    je .status_class
    cmp bl, http_prefix_len + 3
    jb .status_digit
    jmp short .header
.http_prefix:
    mov di, http_prefix
    cmp al, [di + bx]
    jne .failed
    inc byte [response_http_state]
    clc
    ret
.status_class:
    cmp al, '2'
    jne .failed
    inc byte [response_http_state]
    clc
    ret
.status_digit:
    cmp al, '0'
    jb .failed
    cmp al, '9'
    ja .failed
    inc byte [response_http_state]
    clc
    ret
.header:
    mov bl, [response_header_state]
    cmp al, 13
    je .header_cr
    cmp al, 10
    je .header_lf
    mov byte [response_header_state], 0
    clc
    ret
.header_cr:
    cmp bl, 2
    je .header_state3
    mov byte [response_header_state], 1
    clc
    ret
.header_state3:
    mov byte [response_header_state], 3
    clc
    ret
.header_lf:
    cmp bl, 1
    je .header_state2
    cmp bl, 3
    je .body
    mov byte [response_header_state], 0
    clc
    ret
.header_state2:
    mov byte [response_header_state], 2
    clc
    ret
.body:
    mov byte [response_body_started], 1
    mov byte [response_header_state], 0
    clc
    ret
.failed:
    stc
    ret

scan_response_marker:
    mov bl, [response_marker_stage]
    or bl, bl
    jz .seek_output
    cmp bl, 1
    je .seek_delta
    cmp bl, 2
    je .delta_value
    cmp bl, 3
    je .seek_terminal
    cmp bl, 4
    je .monitor_extra
    stc
    ret

.seek_output:
    mov bp, response_marker_pos
    mov di, output_type_marker
    mov dl, output_type_marker_len
    mov dh, 6
    call marker_advance
    jnc .accepted
    mov byte [response_marker_stage], 1
    clc
    ret

.seek_delta:
    cmp al, '}'
    jne .match_delta
    mov byte [response_marker_stage], 0
    mov byte [response_marker_pos], 0
    clc
    ret
.match_delta:
    mov bp, response_marker_pos
    mov di, delta_prefix_marker
    mov dl, delta_prefix_marker_len
    mov dh, 7
    call marker_advance
    jnc .accepted
    mov byte [response_marker_stage], 2
    mov byte [response_delta_nonempty], 0
    clc
    ret

.delta_value:
    cmp al, '"'
    je .delta_end
    mov bl, [response_output_count]
    or bl, bl
    jz .expect_o
    cmp bl, 1
    jne .failed
    cmp al, 'k'
    jne .failed
    jmp short .accepted_output
.expect_o:
    cmp al, 'o'
    jne .failed
.accepted_output:
    inc byte [response_output_count]
    mov byte [response_delta_nonempty], 1
    clc
    ret
.delta_end:
    cmp byte [response_delta_nonempty], 1
    jne .failed
    mov byte [response_delta_nonempty], 0
    cmp byte [response_output_count], 2
    je .have_exact_ok
    mov byte [response_marker_stage], 0
    clc
    ret
.have_exact_ok:
    mov byte [response_marker_stage], 3
    mov byte [response_marker_pos], 0
    mov byte [response_extra_pos], 0
    clc
    ret

.seek_terminal:
    mov bp, response_marker_pos
    mov di, completed_type_marker
    mov dl, completed_type_marker_len
    mov dh, 6
    call marker_advance
    jc .completed
.monitor_extra:
    mov bp, response_extra_pos
    mov di, output_type_marker
    mov dl, output_type_marker_len
    mov dh, 6
    call marker_advance
    jc .failed
    cmp byte [response_marker_stage], 4
    jne .accepted
    mov bp, response_marker_pos
    mov di, http_terminal_marker
    mov dl, http_terminal_marker_len
    mov dh, 0xff
    call marker_advance
    jnc .accepted
    inc byte [response_status]
    inc byte [response_marker_stage]
.accepted:
    clc
    ret
.completed:
    mov byte [response_marker_stage], 4
    clc
    ret
.failed:
    stc
    ret

response_fatal:
    cld
    call clear_quarantine
    call clear_response_state
    mov byte [sym_record_active], 0
    mov byte [request_status], 0
    mov byte [response_terminal], 1
    xor ax, ax
    stc
    ret

controller_end:

%if (controller_end - controller_header) > (response_span0 - 0x0900)
%error "post-auth response controller exceeds 0x0900..0x0d00 slot"
%endif
%if response_span0 + response_span0_len > response_span1
%error "post-auth response quarantine spans overlap"
%endif
%if response_span1 + response_span1_len > response_tag_buffer
%error "post-auth response quarantine reaches tag buffer"
%endif
%if response_tag_buffer + 16 > response_span2
%error "post-auth response tag reaches third quarantine span"
%endif
%if response_span2 + response_span2_len > request_status
%error "post-auth response quarantine reaches retained scanner state"
%endif
%if response_state_end > 0x3c9c
%error "post-auth response state reaches reconnect scratch"
%endif
