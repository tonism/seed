; Cold post-auth OpenAI Responses request controller.
;
; This controller never accepts a caller-provided credential pointer, phase key,
; destination, or route.  It calls one fixed no-argument unlock callback.  That
; trusted callback validates the complete authenticated commit and publishes a
; checksummed credential+model object at a fixed address, with status written
; last.  The controller composes a minimal request only from that authenticated
; object, seals it through the K14 symmetric adapter, sends bounded records
; through one fixed callback, and scrubs all plaintext request material.
;
; Entry ABI (near calls, DS=ES=SS=0, DF clear):
;   0 request_send
;   1 request_abort
;
; Success returns CF=0, AX=1. Failure returns CF=1, AX=0.

bits 16
cpu 8086
org 0x0900

%ifndef POST_AUTH_UNLOCK_CALLBACK
%define POST_AUTH_UNLOCK_CALLBACK 0x0520
%endif
%ifndef POST_AUTH_SEND_CALLBACK
%define POST_AUTH_SEND_CALLBACK 0x0500
%endif
%ifndef POST_AUTH_SYM_RESTORE_CALLBACK
%define POST_AUTH_SYM_RESTORE_CALLBACK 0x0510
%endif
%ifndef POST_AUTH_SYM_SEAL_ENTRY
%define POST_AUTH_SYM_SEAL_ENTRY 0x340a
%endif
%ifndef POST_AUTH_REQUEST_PREFIX
%error "adapter request literal addresses are required"
%endif
%ifndef POST_AUTH_REQUEST_AFTER_KEY
%error "adapter request literal addresses are required"
%endif
%ifndef POST_AUTH_REQUEST_HEADER_END
%error "adapter request literal addresses are required"
%endif
%ifndef POST_AUTH_REQUEST_BODY_PREFIX
%error "adapter request literal addresses are required"
%endif
%ifndef POST_AUTH_REQUEST_BODY_SUFFIX
%error "adapter request literal addresses are required"
%endif

controller_header:
    db 'PAR1'
    dw 1
    dw controller_end - controller_header
controller_entry_table:
    dw request_send
    dw request_abort

sym_io_base                equ 0x39a0

unlock_publication_start   equ 0x0d00
unlock_status              equ unlock_publication_start
unlock_reserved            equ unlock_status + 1
unlock_magic               equ unlock_reserved + 1
unlock_magic_inverse       equ unlock_magic + 4
unlock_generation          equ unlock_magic_inverse + 4
unlock_route               equ unlock_generation + 2
unlock_route_inverse       equ unlock_route + 1
request_key_len            equ unlock_route_inverse + 1
request_key_buffer         equ request_key_len + 2
request_key_max            equ 192
request_key_end            equ request_key_buffer + request_key_max + 1
request_model_len_field    equ request_key_end
request_model_buffer       equ request_model_len_field + 2
request_model_max          equ 64
request_model_end          equ request_model_buffer + request_model_max + 1
unlock_checksum_a          equ request_model_end
unlock_checksum_b          equ unlock_checksum_a + 2
unlock_publication_end     equ unlock_checksum_b + 2
unlock_check_start         equ unlock_generation
unlock_check_len           equ unlock_checksum_a - unlock_check_start
request_fragment_buffer    equ 0x0e20
request_fragment_end       equ 0x0f00
request_fragment_max       equ request_fragment_end - request_fragment_buffer

request_prefix             equ POST_AUTH_REQUEST_PREFIX
request_prefix_len         equ POST_AUTH_REQUEST_PREFIX_LEN
request_after_key          equ POST_AUTH_REQUEST_AFTER_KEY
request_after_key_len      equ POST_AUTH_REQUEST_AFTER_KEY_LEN
request_header_end         equ POST_AUTH_REQUEST_HEADER_END
request_header_end_len     equ POST_AUTH_REQUEST_HEADER_END_LEN
request_body_prefix        equ POST_AUTH_REQUEST_BODY_PREFIX
request_body_prefix_len    equ POST_AUTH_REQUEST_BODY_PREFIX_LEN
request_body_suffix        equ POST_AUTH_REQUEST_BODY_SUFFIX
request_body_suffix_len    equ POST_AUTH_REQUEST_BODY_SUFFIX_LEN

; Retired post-auth control scratch, after the atomic gate control and before
; reconnect state.
request_model_len     equ 0x3c40
request_fragment_len  equ 0x3c42
request_decimal       equ 0x3c44
request_status        equ 0x3c49
controller_state_end  equ 0x3c4a

request_send:
    cld
    mov byte [request_status], 0
%ifdef POST_AUTH_PRELOADED_PUBLICATION
    ; The live supervisor has just executed UCL1 under the full route gate.
    ; Preserve that status-last PAK1 while clearing only request work. The
    ; fixed 0x0520 callback revalidates the route and PAK1 generation before
    ; this controller validates every descriptor field and checksum.
    call clear_request_work
%else
    call clear_plaintext_scratch
%endif

    xor ax, ax
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    call POST_AUTH_UNLOCK_CALLBACK
    jc request_failed
    call validate_publication
    jc request_failed
    call validate_key
    jc request_failed
    call validate_model
    jc request_failed
    mov [request_model_len], cx

    ; The full authorization gate phase-reuses the 0x1800 symmetric image.
    ; Restore the fixed K14 code only after PAK1 has validated and before any
    ; credential-bearing plaintext is composed. No caller authority crosses
    ; this callback.
    xor ax, ax
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    call POST_AUTH_SYM_RESTORE_CALLBACK
    jc request_failed

    mov word [request_fragment_len], 0

    mov si, request_prefix
    mov cx, request_prefix_len
    call request_append
    jc request_failed
    mov si, request_key_buffer
    mov cx, [request_key_len]
    call request_append
    jc request_failed
    mov si, request_after_key
    mov cx, request_after_key_len
    call request_append
    jc request_failed

    mov ax, request_body_prefix_len + request_body_suffix_len
    add ax, [request_model_len]
    call request_append_decimal
    jc request_failed
    mov si, request_header_end
    mov cx, request_header_end_len
    call request_append
    jc request_failed
    mov si, request_body_prefix
    mov cx, request_body_prefix_len
    call request_append
    jc request_failed
    mov si, request_model_buffer
    mov cx, [request_model_len]
    call request_append
    jc request_failed
    mov si, request_body_suffix
    mov cx, request_body_suffix_len
    call request_append
    jc request_failed
    call request_flush
    jc request_failed

    call clear_plaintext_scratch
    mov byte [request_status], 1
    mov ax, 1
    clc
    ret

request_failed:
    call clear_plaintext_scratch
    mov byte [request_status], 0
    xor ax, ax
    stc
    ret

; Validate the fixed, status-last publication from the hardened unlock callback.
validate_publication:
    cmp byte [unlock_status], 1
    jne .failed
    cmp byte [unlock_reserved], 0
    jne .failed
    cmp word [unlock_magic], 0x4150          ; "PA"
    jne .failed
    cmp word [unlock_magic + 2], 0x314b     ; "K1"
    jne .failed
    cmp word [unlock_magic_inverse], 0xbeaf
    jne .failed
    cmp word [unlock_magic_inverse + 2], 0xceb4
    jne .failed
    cmp word [unlock_generation], 0
    je .failed
    mov al, [unlock_route]
    cmp al, 1
    jne .failed
    not al
    cmp al, [unlock_route_inverse]
    jne .failed
    mov si, unlock_check_start
    mov cx, unlock_check_len
    call publication_checksum
    cmp ax, [unlock_checksum_a]
    jne .failed
    cmp dx, [unlock_checksum_b]
    jne .failed
    clc
    ret
.failed:
    stc
    ret

publication_checksum:
    push bx
    mov ax, 0x6d5a
    mov dx, 0xb481
.byte:
    xor bx, bx
    mov bl, [si]
    inc si
    add ax, bx
    rol ax, 1
    xor dx, ax
    add dx, 0x9e37
    rol dx, 1
    loop .byte
    pop bx
    ret

; Return CX=authenticated model length. Only JSON-safe token characters pass.
validate_model:
    mov cx, [request_model_len_field]
    or cx, cx
    jz .failed
    cmp cx, request_model_max
    ja .failed
    mov bx, request_model_buffer
    add bx, cx
    cmp byte [bx], 0
    jne .failed
    mov si, request_model_buffer
.next:
    lodsb
    call model_char
    jc .failed
    loop .next
    mov cx, [request_model_len_field]
    clc
    ret
.failed:
    stc
    ret

model_char:
    cmp al, '0'
    jb .punct
    cmp al, '9'
    jbe .good
    cmp al, 'A'
    jb .punct
    cmp al, 'Z'
    jbe .good
    cmp al, 'a'
    jb .punct
    cmp al, 'z'
    jbe .good
.punct:
    cmp al, '-'
    je .good
    cmp al, '.'
    je .good
    cmp al, ':'
    je .good
    cmp al, '_'
    jne .bad
.good:
    clc
    ret
.bad:
    stc
    ret

; Validate the fixed key field inside the authenticated publication.
validate_key:
    mov cx, [request_key_len]
    or cx, cx
    jz .failed
    cmp cx, request_key_max
    ja .failed
    mov bx, request_key_buffer
    add bx, cx
    cmp byte [bx], 0
    jne .failed
    mov si, request_key_buffer
.byte:
    lodsb
    cmp al, 0x21
    jb .failed
    cmp al, 0x7e
    ja .failed
    loop .byte
    clc
    ret
.failed:
    stc
    ret

request_append:
    or cx, cx
    jz .done
.next:
    lodsb
    mov bx, [request_fragment_len]
    mov [request_fragment_buffer + bx], al
    inc bx
    mov [request_fragment_len], bx
    cmp bx, request_fragment_max
    jb .continued
    push si
    push cx
    call request_flush
    pop cx
    pop si
    jc .failed
.continued:
    dec cx
    jnz .next
.done:
    clc
    ret
.failed:
    stc
    ret

request_append_decimal:
    mov di, request_decimal
    xor cx, cx
    mov bx, 10
.divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .divide
    mov bx, cx
.pop:
    pop ax
    add al, '0'
    stosb
    loop .pop
    mov si, request_decimal
    mov cx, bx
    jmp request_append

request_flush:
    mov cx, [request_fragment_len]
    or cx, cx
    jz .done
    mov si, request_fragment_buffer
    call POST_AUTH_SYM_SEAL_ENTRY
    jc .failed
    mov cx, ax
    mov si, sym_io_base
    call POST_AUTH_SEND_CALLBACK
    jc .failed
    mov word [request_fragment_len], 0
.done:
    clc
    ret
.failed:
    stc
    ret

request_abort:
    cld
    call clear_plaintext_scratch
    mov byte [request_status], 0
    xor ax, ax
    stc
    ret

clear_plaintext_scratch:
    push ds
    pop es
    xor ax, ax
    mov di, unlock_publication_start
    mov cx, request_fragment_end - unlock_publication_start
    rep stosb
    mov di, request_model_len
    mov cx, request_status - request_model_len
    rep stosb
    ret

clear_request_work:
    push ds
    pop es
    xor ax, ax
    mov di, request_fragment_buffer
    mov cx, request_fragment_end - request_fragment_buffer
    rep stosb
    mov di, request_model_len
    mov cx, controller_state_end - request_model_len
    rep stosb
    ret

controller_end:

%if (controller_end - controller_header) > \
    (unlock_publication_start - 0x0900)
%error "post-auth request controller exceeds 0x0900..0x0d00 slot"
%endif
%if unlock_publication_end > request_fragment_buffer
%error "post-auth credential/model publication overlaps request fragment buffer"
%endif
%if request_fragment_max > 383
%error "post-auth request fragment exceeds TLSInnerPlaintext content bound"
%endif
%if controller_state_end > 0x3c9c
%error "post-auth controller state reaches reconnect scratch"
%endif
