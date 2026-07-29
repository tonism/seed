; Explicit validity-time elevation gate for the TLS 1.3 parser PoC.
;
; The parser itself earns only profile 001fh.  This separate phase compares
; its normalized validity interval against a caller-supplied, already-trusted
; UTC value and only then elevates the profile to issuer_auth's 003fh.
;
; IMPORTANT: this code validates and compares time; it does not establish a
; trusted clock.  Calling it with BIOS/NTP/network-controlled time would not
; satisfy the trust boundary.

bits 16
cpu 8086
org 0x1800

parser_leaf_status          equ 0x3600
parser_leaf_profile         equ parser_leaf_status + 1
parser_output_not_before    equ 0x36b3
parser_output_not_after     equ parser_output_not_before + 14
parser_hash_status          equ 0x378e
parser_time_status          equ parser_hash_status + 1

; Reuse the symmetric overlay's existing mutable record payload window.
parser_time_input_start     equ 0x39a5
parser_time_input_end       equ 0x3b25

parser_leaf_structural      equ 0x001f
parser_leaf_trusted_time    equ 0x003f
parser_leaf_hashed_status   equ 2
parser_normalized_time_len  equ 14

cert_time_table:
    dw cert_time_apply
    dw cert_time_clear
    dw cert_time_image_end - $$
    dw 1

; in: DS:SI -> trusted YYYYMMDDHHMMSS, CX=14.
; out: CF=0, AX=1 and profile=003fh; or CF=1, AX=0 and profile remains 001fh.
cert_time_apply:
    cld
    mov byte [parser_time_status], 0
    cmp word [parser_leaf_profile], parser_leaf_structural
    je .profile_ok
    mov word [parser_leaf_profile], 0
    jmp .failed
.profile_ok:
    ; Hash consumes and clears the leaf, then emits a distinct status 2.
    ; (leaf_status=2, hash_status=1) is the one-shot post-hash seal.
    cmp byte [parser_leaf_status], parser_leaf_hashed_status
    jne .failed
    cmp byte [parser_hash_status], 1
    jne .failed
    cmp cx, parser_normalized_time_len
    jne .failed
    cmp si, parser_time_input_start
    jb .failed
    mov ax, si
    add ax, parser_normalized_time_len
    jc .failed
    cmp ax, parser_time_input_end
    ja .failed

    push bp
    mov bp, si
    call cert_time_validate
    jc .failed_bp
    mov si, parser_output_not_before
    call cert_time_validate
    jc .failed_bp
    mov si, parser_output_not_after
    call cert_time_validate
    jc .failed_bp

    push ds
    pop es
    mov si, parser_output_not_before
    mov di, bp
    call cert_time_lte
    jc .failed_bp
    mov si, bp
    mov di, parser_output_not_after
    call cert_time_lte
    jc .failed_bp

    pop bp
    mov word [parser_leaf_profile], parser_leaf_trusted_time
    mov byte [parser_time_status], 1
    mov ax, 1
    clc
    ret

.failed_bp:
    pop bp
.failed:
    xor ax, ax
    stc
    ret

cert_time_clear:
    mov byte [parser_time_status], 0
    cmp word [parser_leaf_profile], parser_leaf_trusted_time
    jne .done
    mov word [parser_leaf_profile], parser_leaf_structural
.done:
    ret

; Validate one normalized time.  The deliberately narrow current profile is
; 2000..2099, allowing a small exact leap-year rule (year mod 4) while covering
; the pinned-anchor lifetime.  Full month/day/hour/minute/second validity is
; enforced; no clock comparison happens here.
; in SI -> 14 bytes. out CF.
cert_time_validate:
    push ax
    push bx
    push cx
    push dx
    push si

    cmp word [si], 0x3032             ; "20"
    jne .bad
    mov bx, si
    mov cx, parser_normalized_time_len
.digit:
    mov al, [bx]
    cmp al, '0'
    jb .bad
    cmp al, '9'
    ja .bad
    inc bx
    loop .digit

    lea bx, [si + 4]
    call cert_time_decimal_pair       ; month
    cmp al, 1
    jb .bad
    cmp al, 12
    ja .bad
    mov dl, al

    add bx, 2
    call cert_time_decimal_pair       ; day
    cmp al, 1
    jb .bad
    mov dh, al
    xor ah, ah
    mov al, dl
    dec ax
    mov bx, cert_time_month_days
    add bx, ax
    mov al, [bx]
    cmp dl, 2
    jne .have_max_day
    lea bx, [si + 2]
    call cert_time_decimal_pair       ; 2000..2099 leap iff YY mod 4 == 0
    and al, 3
    jnz .have_max_day
    mov al, 29
.have_max_day:
    cmp dh, al
    ja .bad

    lea bx, [si + 8]
    call cert_time_decimal_pair       ; hour
    cmp al, 23
    ja .bad
    add bx, 2
    call cert_time_decimal_pair       ; minute
    cmp al, 59
    ja .bad
    add bx, 2
    call cert_time_decimal_pair       ; second
    cmp al, 59
    ja .bad
    clc
    jmp .done
.bad:
    stc
.done:
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Compare two fixed-width normalized UTC values.
; in DS:SI=left, ES:DI=right. out CF=0 iff left <= right.
cert_time_lte:
    push ax
    push cx
    push si
    push di
    mov cx, parser_normalized_time_len
    repe cmpsb
    je .yes
    jb .yes
    stc
    jmp .done
.yes:
    clc
.done:
    pop di
    pop si
    pop cx
    pop ax
    ret

cert_time_decimal_pair:
    push dx
    mov al, [bx]
    sub al, '0'
    xor ah, ah
    mov dl, 10
    mul dl
    add al, [bx + 1]
    sub al, '0'
    pop dx
    ret

cert_time_month_days:
    db 31,28,31,30,31,30,31,31,30,31,30,31

cert_time_image_end:

%if (cert_time_image_end - $$) > 512
%error "certificate time policy exceeds one sector"
%endif
%if parser_time_status >= parser_time_input_start
%error "certificate time status overlaps trusted-time input window"
%endif
