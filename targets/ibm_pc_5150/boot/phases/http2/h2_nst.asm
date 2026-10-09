; Private fresh-connection NST retention after full record authentication.
; This cold-only phase replaces K; no input or secret escapes conventional RAM.
; SI=2e70, CX=complete bounded NST record content, DS=ES=SS=0, DF clear.
; Validate every message before retaining the first ticket, publish status last.
bits 16
cpu 8086
org 0x1800
dw nst_accept, nst_retire
%include "nst-sha-abi.inc"
nst_master equ 0x0d22
nst_psk equ 0x0d42
nst_identity equ 0x0d62
nst_lifetime_hi equ 0x0e22
nst_lifetime_lo equ 0x0e24
nst_age_add equ 0x0e26
nst_identity_len equ 0x0e2a
nst_status equ 0x0e30
nst_input equ 0x2e70
nst_input_bytes equ 576
nst_work equ 0x3100
nst_work_end equ 0x3570
nst_expand equ 0x3480

nst_accept:
    cld
    cmp si, nst_input
    jne .bad
    cmp cx, nst_input_bytes
    ja .bad
    call tls_validate_post_handshake_nst
    jc .bad
    cmp byte [nst_status], 0
    je .retain
    cmp byte [nst_status], 1
    jne .bad
    jmp .done
.retain:
    call sha256_init
    mov word [hmac_key_ptr], nst_master
    mov word [hmac_key_len], 32
    call hmac_prepare_current_key_context
    jc .bad
    ; HKDF-Expand-Label(master, "resumption", nonce, 32), one SHA256 block.
    mov si, nst_expand_prefix
    mov di, nst_expand
    mov cx, nst_expand_prefix_len
    rep movsb
    mov al, [nst_input+12]
    stosb
    xor cx, cx
    mov cl, al
    mov si, nst_input+13
    rep movsb
    mov al, 1
    stosb
    sub di, nst_expand
    mov [hmac_data1_len], di
    mov word [hmac_data1_ptr], nst_expand
    mov word [hmac_data2_len], 0
    mov word [hmac_output_ptr], nst_psk
    call hmac_sha256_prepared
    jc .bad
    xor ax, ax
    mov di, nst_identity
    mov cx, 192/2
    rep stosw
    mov al, [nst_input+12]
    mov si, nst_input+13
    add si, ax
    lodsw
    xchg al, ah
    mov [nst_identity_len], ax
    mov cx, ax
    mov di, nst_identity
    rep movsb
    mov ax, [nst_input+4]
    xchg al, ah
    mov [nst_lifetime_hi], ax
    mov ax, [nst_input+6]
    xchg al, ah
    mov [nst_lifetime_lo], ax
    mov si, nst_input+8
    mov di, nst_age_add
    movsw
    movsw
    ; Subsequent authenticated tickets are drained, so the master is dead.
    xor ax, ax
    mov di, nst_master
    mov cx, 16
    rep stosw
    mov byte [nst_status], 1
.done:
    call nst_retire
    clc
    ret
.bad:
    call nst_retire
    stc
    ret

nst_retire:
    xor ax, ax
    mov di, nst_input
    mov cx, nst_input_bytes/2
    rep stosw
    mov di, nst_work
    mov cx, (nst_work_end-nst_work)/2
    rep stosw
    ; Retire only this machine's stack guard. Direct boot retains its arena
    ; and return trampoline below 7a40; the 16 KiB root frame ends at 3f1c.
    ; Applying the 16 KiB floor to an 8000 stack erases both live regions.
    mov di, 0x3f1c
    cmp sp, 0x4000
    jbe .stack_floor_ready
    mov di, 0x7a40
.stack_floor_ready:
    mov cx, sp
    sub cx, di
    rep stosb
    xor bx, bx
    xor dx, dx
    xor si, si
    xor di, di
    xor bp, bp
    ret

nst_expand_prefix db 0,32,16,'tls13 resumption'
nst_expand_prefix_len equ $ - nst_expand_prefix
%include "nst-validator.inc"
%include "core/sha256.inc"
%include "nst-sha-constants.inc"
nst_end:
%if ($-$$)>6*512
%error "NST phase exceeds remaining cold-pack sectors"
%endif
