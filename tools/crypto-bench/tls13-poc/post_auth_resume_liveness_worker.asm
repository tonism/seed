; Same-boot resumed-connection authenticated liveness worker.
;
; RSD1 MODE_LOW loads this phase at 0x0900 after deferred FO has restored the
; K14 server-application read key/IV/sequence and RSU1 has pushed the fixed
; outer continuation.  AX is the fixed operation number (8); there are no
; caller-selected pointers, lengths, keys, destinations, or service entries.
;
; The peer observed a zero receive window after the credential-free HEAD was
; sent.  This worker drains queued retransmits, advertises the resident receive
; window, incrementally reassembles arbitrarily TCP-fragmented TLS records,
; authenticates every record with K14, and exposes plaintext only to its
; protocol parsers after the tag succeeds.  Authenticated NewSessionTickets
; are syntax-checked through K14's fixed parser while its already-retained
; ticket remains selected.  Success requires an authenticated HTTP/1.1 HEAD
; response header with a 2xx, non-425 4xx, or 5xx status and an exact
; CRLFCRLF end.  HTTP 425 is an authenticated rejection of this early request,
; never liveness success.
;
; Entry/return contract:
;   DS=SS=0, AX=8, DF arbitrary, stack top=fixed outer continuation
;   success: AX=1, CF=0, ES restored, DF clear, RET to that continuation
;   failure: AX=0, CF=1, quarantine/parser state scrubbed, ES restored,
;            DF clear, RET to that continuation

bits 16
cpu 8086
org 0x0900

%ifndef RESUME_LIVENESS_TCP_RECEIVE
%error "liveness worker requires resident TCP receive"
%endif
%ifndef RESUME_LIVENESS_TCP_ACK
%error "liveness worker requires resident TCP ACK"
%endif
%ifndef RESUME_LIVENESS_RX_SAMPLE_COUNT
%error "liveness worker requires resident NIC sample-count state"
%endif
%ifndef RESUME_LIVENESS_TCP_PAYLOAD_PTR
%error "liveness worker requires resident TCP payload-pointer state"
%endif
%ifndef RESUME_LIVENESS_TCP_PAYLOAD_LEN
%error "liveness worker requires resident TCP payload-length state"
%endif
%ifndef RESUME_LIVENESS_SYM_OPEN_BEGIN_ENTRY
%error "liveness worker requires fixed K14 server-app open-begin entry"
%endif
%ifndef RESUME_LIVENESS_SYM_OPEN_CHUNK_ENTRY
%error "liveness worker requires fixed K14 open-chunk entry"
%endif
%ifndef RESUME_LIVENESS_SYM_OPEN_FINISH_ENTRY
%error "liveness worker requires fixed K14 open-finish entry"
%endif
%ifndef RESUME_LIVENESS_SYM_PARSE_NST_ENTRY
%error "liveness worker requires fixed K14 NewSessionTicket parser entry"
%endif
%ifndef RESUME_LIVENESS_SYM_RECORD_ACTIVE
%error "liveness worker requires fixed K14 record-active state"
%endif
%ifndef RESUME_LIVENESS_SYM_IO
%error "liveness worker requires fixed K14 record-I/O address"
%endif
%ifndef RESUME_LIVENESS_SYM_RECEIVED_TAG
%error "liveness worker requires fixed K14 received-tag address"
%endif
%ifndef RESUME_LIVENESS_TICKET_PRESENT
%error "liveness worker requires fixed retained-ticket status"
%endif

resume_liveness_entry:
    jmp short resume_liveness_code

resume_liveness_header:
    db 'RSL1'
    dw 1
    dw resume_liveness_end - $$
    dw 0x0900
    dw resume_liveness_entry

; The low executable ends before 0x0d00.  Authenticated plaintext is scattered
; only into retired regions which do not overlap the restored server key/IV,
; sequence, retained ticket, supervisor, or vault lifecycle.
liveness_span0             equ 0x0d00
liveness_span0_len         equ 0x01e0
liveness_span1             equ 0x3600
liveness_span1_len         equ 0x0238
liveness_tag               equ RESUME_LIVENESS_SYM_RECEIVED_TAG
liveness_span2             equ 0x3920
liveness_span2_len         equ 0x0220
liveness_plain_max         equ \
    liveness_span0_len + liveness_span1_len + liveness_span2_len
liveness_span2_offset      equ liveness_span0_len + liveness_span1_len

; 0x3c30..0x3c45 remains the committed ROG3/publication control.  RSU1's
; receipt/candidate/FO scratch at 0x3c46..0x3c75 is retired after op7 and is
; the only persistent state this worker may reuse.  The op2 lifecycle starts
; at 0x3c76 and remains untouched.
liveness_state_start       equ 0x3c46
liveness_record_header     equ liveness_state_start
liveness_header_pos        equ liveness_record_header + 5
liveness_record_active     equ liveness_header_pos + 1
liveness_cipher_remaining  equ liveness_record_active + 1
liveness_plain_len         equ liveness_cipher_remaining + 2
liveness_tag_pos           equ liveness_plain_len + 2
liveness_chunk_ptr         equ liveness_tag_pos + 1
liveness_chunk_len         equ liveness_chunk_ptr + 2
liveness_http_total        equ liveness_chunk_len + 2
liveness_http_line_state   equ liveness_http_total + 2
liveness_http_done         equ liveness_http_line_state + 1
liveness_http_status_state equ liveness_http_done + 1
liveness_state_end         equ 0x3c76

liveness_http_limit        equ 2048

resume_liveness_code:
    ; Resident tcp_receive_payload waits with HLT. Make its interrupt
    ; requirement explicit at the low-worker boundary rather than inheriting
    ; an incidental IF state from deferred FO and the phase loader.
    sti
    cld
    push es
    push ds
    pop es
    cmp ax, 8
    jne resume_liveness_failed
    cmp byte [RESUME_LIVENESS_TICKET_PRESENT], 1
    jne resume_liveness_failed
    call liveness_clear_all

    ; Open the ordinary receive window without destructively draining the NIC
    ; ring first. tcp_receive_payload's exact-sequence parser retires stale
    ; zero-window probes/duplicates and accepts an already-queued response.
    ; Discarding that exact response here would depend on a host TCP proxy
    ; retransmitting bytes it may already have acknowledged upstream.
    call RESUME_LIVENESS_TCP_ACK
    cld
    jc resume_liveness_failed

.receive:
    call RESUME_LIVENESS_TCP_RECEIVE
    cld
    jc resume_liveness_failed
    mov si, [RESUME_LIVENESS_TCP_PAYLOAD_PTR]
    mov cx, [RESUME_LIVENESS_TCP_PAYLOAD_LEN]
    or cx, cx
    jnz .consume
    jmp resume_liveness_failed

.consume:
    or cx, cx
    jz .ack
    cmp byte [liveness_record_active], 0
    jne .record_body

    xor bx, bx
    mov bl, [liveness_header_pos]
    mov al, [si]
    mov [liveness_record_header + bx], al
    inc si
    dec cx
    inc byte [liveness_header_pos]
    cmp byte [liveness_header_pos], 5
    jne .consume
    push si
    push cx
    call liveness_start_record
    pop cx
    pop si
    jc resume_liveness_failed
    jmp short .consume

.record_body:
    mov ax, [liveness_cipher_remaining]
    or ax, ax
    jz .record_tag
    mov dx, cx
    cmp cx, ax
    jbe .cipher_bound
    mov cx, ax
.cipher_bound:
    cmp cx, 383
    jbe .cipher_chunk
    mov cx, 383
.cipher_chunk:
    mov [liveness_chunk_ptr], si
    mov [liveness_chunk_len], cx
    push dx
    call word [RESUME_LIVENESS_SYM_OPEN_CHUNK_ENTRY]
    pop dx
    cld
    jc resume_liveness_failed
    call liveness_store_chunk
    mov ax, [liveness_chunk_len]
    sub [liveness_cipher_remaining], ax
    sub dx, ax
    mov cx, dx
    jmp .consume

.record_tag:
    mov dx, cx
    xor bx, bx
    mov bl, [liveness_tag_pos]
    mov ax, 16
    sub ax, bx
    cmp cx, ax
    jbe .tag_count
    mov cx, ax
.tag_count:
    mov [liveness_chunk_len], cx
    mov di, liveness_tag
    add di, bx
    rep movsb
    mov ax, [liveness_chunk_len]
    add [liveness_tag_pos], al
    sub dx, ax
    mov cx, dx
    cmp byte [liveness_tag_pos], 16
    jne .consume

    push si
    push cx
    mov si, liveness_tag
    call word [RESUME_LIVENESS_SYM_OPEN_FINISH_ENTRY]
    cld
    jc .finish_failed
    call liveness_process_plaintext
    jc .finish_failed
    pop cx
    pop si
    mov word [liveness_header_pos], 0
    push si
    push cx
    call liveness_clear_quarantine
    pop cx
    pop si
    jmp .consume
.finish_failed:
    pop cx
    pop si
    jmp resume_liveness_failed

.ack:
    ; ACK every completely consumed TCP payload, including a fragment ending
    ; inside a record.  Promotion is checked only at an authenticated record
    ; boundary after that ACK is on the wire.
    call RESUME_LIVENESS_TCP_ACK
    cld
    jc resume_liveness_failed
    cmp word [liveness_header_pos], 0
    jne .receive
    cmp byte [liveness_http_done], 1
    jne .receive
    cmp byte [RESUME_LIVENESS_TICKET_PRESENT], 1
    jne resume_liveness_failed
    call liveness_clear_all
    cld
    mov ax, 1
    clc
    pop es
    ret

liveness_start_record:
    cmp byte [liveness_record_header], 0x17
    jne .failed
    cmp word [liveness_record_header + 1], 0x0303
    jne .failed
    xor ax, ax
    mov ah, [liveness_record_header + 3]
    mov al, [liveness_record_header + 4]
    cmp ax, 17
    jb .failed
    sub ax, 16
    cmp ax, liveness_plain_max
    ja .failed
    mov [liveness_cipher_remaining], ax
    mov word [liveness_plain_len], 0
    mov byte [liveness_tag_pos], 0
    mov si, liveness_record_header
    mov di, RESUME_LIVENESS_SYM_IO
    mov cx, 5
    rep movsb
    call word [RESUME_LIVENESS_SYM_OPEN_BEGIN_ENTRY]
    cld
    jc .failed
    mov byte [liveness_record_active], 1
    clc
    ret
.failed:
    stc
    ret

; K14 authenticates/decrypts the current source chunk in place first.  Only
; then is it copied into the non-authoritative scatter quarantine.  No parser
; reads that quarantine until open-finish validates the record tag.
liveness_store_chunk:
    mov si, [liveness_chunk_ptr]
    mov cx, [liveness_chunk_len]
    mov bx, [liveness_plain_len]
.byte:
    call liveness_scatter_di
    movsb
    inc bx
    loop .byte
    mov [liveness_plain_len], bx
    ret

; BX=logical plaintext offset, returns DI=physical scatter address.
liveness_scatter_di:
    mov di, bx
    cmp bx, liveness_span0_len
    jb .low
    cmp bx, liveness_span2_offset
    jb .middle
    add di, liveness_span2 - liveness_span2_offset
    ret
.middle:
    add di, liveness_span1 - liveness_span0_len
    ret
.low:
    add di, liveness_span0
    ret

liveness_process_plaintext:
    mov cx, [liveness_plain_len]
    or cx, cx
    jz .failed
    mov bx, cx
.find_type:
    dec bx
    call liveness_scatter_di
    mov dl, [di]
    or dl, dl
    jnz .have_type
    or bx, bx
    jnz .find_type
    jmp short .failed
.have_type:
    mov cx, bx                         ; authenticated content length
    jcxz .failed
    cmp dl, 0x16
    je .tickets
    cmp dl, 0x17
    jne .failed
    call liveness_process_http
    ret
.tickets:
    cmp cx, liveness_span0_len
    ja .failed
    mov si, liveness_span0
.ticket:
    cmp cx, 4
    jb .failed
    cmp byte [si], 4
    jne .failed
    cmp byte [si + 1], 0
    jne .failed
    mov ax, [si + 2]
    xchg al, ah
    add ax, 4
    jc .failed
    cmp ax, 384
    ja .failed
    cmp ax, cx
    ja .failed
    push si
    push cx
    push ax
    mov cx, ax
    call word [RESUME_LIVENESS_SYM_PARSE_NST_ENTRY]
    cld
    pop ax
    pop cx
    pop si
    jc .failed
    cmp byte [RESUME_LIVENESS_TICKET_PRESENT], 1
    jne .failed
    add si, ax
    sub cx, ax
    jnz .ticket
    clc
    ret
.failed:
    stc
    ret

liveness_process_http:
    cmp byte [liveness_http_done], 0
    jne .failed
    mov dx, cx
    mov si, liveness_span0
    cmp dx, liveness_span0_len
    jbe .last
    mov cx, liveness_span0_len
    call liveness_feed_http
    jc .failed
    sub dx, liveness_span0_len
    mov si, liveness_span1
    cmp dx, liveness_span1_len
    jbe .last
    mov cx, liveness_span1_len
    call liveness_feed_http
    jc .failed
    sub dx, liveness_span1_len
    mov si, liveness_span2
.last:
    mov cx, dx
    call liveness_feed_http
    ret
.failed:
    stc
    ret

; Strict authenticated HTTP/1.1 response-header DFA.  Bare CR/LF is rejected;
; only complete CRLF line ends and the exact CRLFCRLF terminator are accepted.
liveness_feed_http:
.byte:
    cmp byte [liveness_http_done], 0
    jne .failed                       ; no HEAD body is accepted
    mov bx, [liveness_http_total]
    cmp bx, liveness_http_limit
    jae .failed
    inc word [liveness_http_total]
    lodsb
    cmp bx, 9
    jb .prefix
    cmp bx, 12
    jb .status_digit
    je .status_space

    mov bl, [liveness_http_line_state]
    or bl, bl
    jz .line
    cmp bl, 1
    je .after_cr
    cmp bl, 2
    je .after_crlf
    cmp bl, 3
    jne .failed
    cmp al, 10
    jne .failed
    mov byte [liveness_http_done], 1
    jmp .next
.line:
    cmp al, 13
    je .set_cr
    cmp al, 10
    je .failed
    cmp al, 9
    je .next
    cmp al, 0x20
    jb .failed
    cmp al, 0x7e
    ja .failed
    jmp .next
.set_cr:
    mov byte [liveness_http_line_state], 1
    jmp .next
.after_cr:
    cmp al, 10
    jne .failed
    mov byte [liveness_http_line_state], 2
    jmp short .next
.after_crlf:
    cmp al, 13
    je .set_final_cr
    cmp al, 10
    je .failed
    cmp al, 9
    je .new_line
    cmp al, 0x20
    jb .failed
    cmp al, 0x7e
    ja .failed
.new_line:
    mov byte [liveness_http_line_state], 0
    jmp short .next
.set_final_cr:
    mov byte [liveness_http_line_state], 3
    jmp short .next
.prefix:
    cmp al, [cs:liveness_http_prefix + bx]
    jne .failed
    jmp short .next
.status_digit:
    cmp al, '0'
    jb .failed
    cmp al, '9'
    ja .failed
    cmp bx, 9
    je .status_first
    cmp bx, 10
    je .status_second
    cmp byte [liveness_http_status_state], 2
    jne .next
    cmp al, '5'
    je .failed
    jmp short .next
.status_second:
    cmp byte [liveness_http_status_state], 1
    jne .next
    cmp al, '2'
    jne .next
    inc byte [liveness_http_status_state]
    jmp short .next
.status_first:
    cmp al, '4'
    je .arm_status_probe
    cmp al, '2'
    je .next
    cmp al, '5'
    jne .failed
    jmp short .next
.arm_status_probe:
    inc byte [liveness_http_status_state]
    jmp short .next
.status_space:
    cmp al, ' '
    jne .failed
.next:
    dec cx
    jz .done
    jmp .byte
.done:
    clc
    ret
.failed:
    stc
    ret

resume_liveness_failed:
    cld
    mov byte [RESUME_LIVENESS_SYM_RECORD_ACTIVE], 0
    mov word [RESUME_LIVENESS_RX_SAMPLE_COUNT], 0
    call liveness_clear_all
    xor ax, ax
    stc
    pop es
    ret

liveness_clear_all:
    call liveness_clear_quarantine
    xor ax, ax
    mov di, liveness_state_start
    mov cx, (liveness_state_end - liveness_state_start) / 2
    rep stosw
    ret

liveness_clear_quarantine:
    xor ax, ax
    mov di, liveness_span0
    mov cx, liveness_span0_len / 2
    rep stosw
    mov di, liveness_span1
    mov cx, liveness_span1_len / 2
    rep stosw
    mov di, liveness_tag
    mov cx, 16 / 2
    rep stosw
    mov di, liveness_span2
    mov cx, liveness_span2_len / 2
    rep stosw
    ret

liveness_http_prefix db 'HTTP/1.1 '

resume_liveness_code_end:
resume_liveness_end:

%if (resume_liveness_header - resume_liveness_entry) != 2
%error "liveness worker header moved from file offset 2"
%endif
%if (resume_liveness_code_end - $$) > 0x0400
%error "liveness executable reaches its low plaintext quarantine"
%endif
%if ($ - $$) > 0x0600
%error "liveness worker exceeds the RSD1 MODE_LOW phase window"
%endif
%if liveness_state_start != 0x3c46
%error "liveness state no longer starts at retired RSU scratch"
%endif
%if liveness_state_end != 0x3c76
%error "liveness state reaches op2 lifecycle"
%endif
%if liveness_span0 + liveness_span0_len > 0x0ee0
%error "liveness low quarantine reaches the outer supervisor hold"
%endif
%if liveness_span1 + liveness_span1_len > 0x3838
%error "liveness middle quarantine reaches the client application key"
%endif
%if liveness_tag + 16 > liveness_span2
%error "liveness tag buffer reaches the high quarantine"
%endif
%if liveness_span2 + liveness_span2_len > 0x3b40
%error "liveness high quarantine reaches retained ticket identity"
%endif
