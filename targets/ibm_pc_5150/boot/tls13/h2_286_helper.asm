bits 16
cpu 8086
org 0x5500
%include "h2-helper-refs.inc"
%include "tls13/tls13_286_abi.inc"
dw flight_h2_load, flight_post_h2_bytes, flight_h2_ready, flight_h2_publish, flight_hash_tbs
; Shared H2 parser in retired 286 module RAM. Its unchanged org-1800 image
; executes with CS=DS=ES=02a3; SS stays on the existing guarded low stack.
%include "h2-286-post-abi.inc"
flight_h2_state equ FLIGHT_H2_DELTA + 0x062e
flight_h2_saved_state equ 0x5230
flight_h2_reply_used equ FLIGHT_H2_DELTA + 0x2e26
flight_h2_ctl_ptr equ FLIGHT_H2_DELTA + 0x2e1c
flight_h2_reply_prefix equ flight_h2_saved_state + 68
flight_h2_reply_tail equ FLIGHT_H2_DELTA + 0x3070

flight_h2_load:
    mov ax, 0x070c
    mov bx, 0x4230
    call TLS13_286_LINK_LOAD_CORE_SECTORS_AT
    jc .bad
    mov ax, 0x01d2
    mov bx, 0x5230
    call TLS13_286_LINK_LOAD_CORE_SECTORS_AT
    jc .bad
    mov si, 0x5230 + 35
    mov di, 0x5030
    mov cx, FLIGHT_H2_BYTES - 3584
    rep movsb
    mov si, 0x4230
    mov dx, FLIGHT_H2_BYTES
    call flight_crc16
    cmp ax, FLIGHT_H2_CRC
    jne .bad
    xor ax, ax
    mov di, 0x5830
    mov cx, (0x5fec - 0x5830) / 2
    rep stosw
    mov bx, FLIGHT_H2_INIT
    call flight_h2_call
    jc .bad
    call flight_h2_save
    clc
    ret
.bad:
    stc
    ret

; BX is an unchanged near entry in the shared image; AL may carry input.
flight_h2_call:
    push ds
    push es
    mov dx, FLIGHT_H2_SEG
    mov ds, dx
    mov es, dx
    jmp far [cs:flight_h2_far_pointer]
flight_h2_far_return:
    pop es
    pop ds
    ret
flight_h2_far_thunk:
    call bx
    jmp 0:flight_h2_far_return
flight_h2_far_pointer:
    dw flight_h2_far_thunk - FLIGHT_H2_DELTA, FLIGHT_H2_SEG

; The parser's 84-byte state maps onto dead SHA work at 305e. Save it in
; retired tail-loader staging before any symmetric call reuses that work.
flight_h2_save:
    mov si, flight_h2_state
    mov di, flight_h2_saved_state
    jmp short flight_h2_copy
flight_h2_restore:
    mov si, flight_h2_saved_state
    mov di, flight_h2_state
flight_h2_copy:
    mov cx, 84/2
    rep movsw
    ret

; Full-record AEAD already committed. Feed cold control bytes directly into
; the same frame parser, with no stream or DATA credit before publication.
flight_post_h2_bytes:
    push si
    push cx
    call flight_h2_restore
    pop cx
    pop si
    mov word [flight_h2_reply_used], 0
    mov word [flight_h2_ctl_ptr], 0x3570 ; no unread bytes in reply storage
.byte:
    lodsb
    push si
    push cx
    call flight_h2_byte
    pop cx
    pop si
    jc .bad
    loop .byte
    cmp byte [flight_h2_state + 49], 0
    jne .bad
    call flight_h2_save
    mov cx, [flight_h2_reply_used]
    mov ax, cx
    cmp cx, 16
    jbe .prefix
    mov cx, 16
.prefix:
    sub ax, cx
    push ax
    mov si, flight_h2_reply_prefix
    call flight_h2_send
    pop cx
    jc .bad
    mov si, flight_h2_reply_tail
    jmp flight_h2_send
.bad:
    stc
    ret

flight_h2_byte:
    cmp word [flight_h2_state + 10], 0
    jne .payload
    xor bx, bx
    mov bl, [flight_h2_state + 9]
    mov [flight_h2_state + bx], al
    inc bl
    mov [flight_h2_state + 9], bl
    cmp bl, 9
    jb .done
    mov byte [flight_h2_state + 9], 0
    mov bx, FLIGHT_H2_NEW_FRAME
    jmp flight_h2_call
.payload:
    cmp byte [flight_h2_state + 3], 9
    ja .skip
    mov bx, FLIGHT_H2_PAYLOAD_BYTE
    call flight_h2_call
    jc .return
.skip:
    inc word [flight_h2_state + 12]
    dec word [flight_h2_state + 10]
    jnz .done
    mov bx, FLIGHT_H2_FRAME_DONE
    jmp flight_h2_call
.done:
    clc
.return:
    ret

flight_h2_ready:
    cmp byte [flight_h2_saved_state + 47], 1
    jne .wait
    cmp byte [flight_h2_saved_state + 48], 0
    jne .wait
    cmp byte [flight_h2_saved_state + 60], 0
    jne .wait
    cmp byte [flight_h2_saved_state + 9], 0
    jne .wait
    cmp word [flight_h2_saved_state + 10], 0
    jne .wait
    ; pending_len is the last refill's temporary length, not unread data.
    mov ax, [cs:flight_wire_left]
    or ax, ax
    jnz .wait
    clc
    ret
.wait:
    stc
    ret

flight_h2_publish:
    mov si, flight_h2_saved_state
    mov di, 0x062e
    mov cx, 84/2
    rep movsw
    ret

; Called only after the acquisition's authenticated HEAD/ticket completes.
; AX=crypto segment, ES=0. Copy the bounded leaf and capture its full TBS span;
; AUTH independently requires that span to match its strict X.509 parser.
; DER canonicality and policy remain AUTH's responsibility.
flight_hash_tbs:
    mov ds, ax
    cmp byte [tls13_286_certificate_off + 8], 0
    jne .bad
    mov cx, [tls13_286_certificate_off + 9]
    xchg cl, ch
    cmp cx, 1024
    ja .bad
    mov ax, cx
    add ax, 13
    cmp ax, [tls13_286_certificate_len_off]
    ja .bad
    mov si, tls13_286_certificate_off + 11
    mov di, 0x0800
    push cx
    rep movsb
    xor ax, ax
    mov ds, ax
    mov si, 0x0800
    pop cx
    mov dx, si
    add dx, cx
    call .sequence
    jc .bad
    mov dx, si
    add dx, cx
    mov [0x0c20], si
    call .sequence
    jc .bad
    add cx, si
    sub cx, [0x0c20]
    mov [0x0c22], cx
    mov si, [0x0c20]
    mov dx, cx
    call flight_crc16
    mov [0x0c24], ax
    call FLIGHT_SHA256_INIT
    mov si, [0x0c20]
    mov cx, [0x0c22]
    call FLIGHT_SHA256_UPDATE
    mov di, 0x0c00
    jmp FLIGHT_SHA256_FINISH
.bad:
    stc
    ret
.sequence:
    cmp si, dx
    jae .bad
    lodsb
    cmp al, 0x30
    jne .bad
    cmp si, dx
    jae .bad
    lodsb
    xor cx, cx
    mov cl, al
    test al, 0x80
    jz .length
    sub al, 0x81
    cmp al, 1
    ja .bad
    mov ah, al
    cmp si, dx
    jae .bad
    lodsb
    mov cl, al
    or ah, ah
    jz .length
    cmp si, dx
    jae .bad
    lodsb
    mov ch, cl
    mov cl, al
.length:
    mov ax, si
    add ax, cx
    jc .bad
    cmp dx, ax
    jb .bad
    ret
