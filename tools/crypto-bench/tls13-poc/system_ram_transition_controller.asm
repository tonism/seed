; Conventional-RAM-only acquisition transitions for the 16 KiB TLS 1.3 path.
;
; These are deliberately I/O-free movers.  The product scheduler may perform
; arbitrarily slow phase loads before invoking them, but neither entry reads a
; disk, touches display/adapter RAM, nor borrows product config.

bits 16
cpu 8086

%ifndef SYSRAM_TRANSITION_ORIGIN
%define SYSRAM_TRANSITION_ORIGIN 0x0f00
%endif
%ifndef SYSRAM_SYM_HOLD
%error "SYSRAM_SYM_HOLD is required"
%endif

org SYSRAM_TRANSITION_ORIGIN

sysram_capsule_low          equ 0x0700
sysram_capsule_high         equ 0x3400
sysram_capsule_len          equ 440
sysram_hold_root_len        equ 171
sysram_hold_auth_status     equ SYSRAM_SYM_HOLD + 170
sysram_hold_ticket_status   equ SYSRAM_SYM_HOLD + 171
sysram_hold_control_end     equ SYSRAM_SYM_HOLD + 173

sysram_ticket_psk           equ 0x38b0
sysram_ticket_identity      equ 0x39a0
sysram_ticket_nonce         equ 0x3a60
sysram_ticket_metadata      equ 0x3a80
sysram_ticket_nonce_len     equ 0x3a88
sysram_ticket_identity_len  equ 0x3a8a

sysram_capsule_ticket_psk   equ sysram_capsule_low + 171
sysram_capsule_identity     equ sysram_capsule_ticket_psk + 32
sysram_capsule_nonce        equ sysram_capsule_identity + 192
sysram_capsule_metadata     equ sysram_capsule_nonce + 32
sysram_capsule_status       equ sysram_capsule_metadata + 12

sysram_c_live_0             equ 0x3400
sysram_c_live_gap           equ 0x3600
sysram_c_live_1             equ 0x355d
sysram_c_live_2             equ 0x0500
sysram_c_live_3             equ 0x33e8
sysram_c_live_4             equ 0x08b8
sysram_c_live_5             equ 0x0de0
sysram_abort_capsule        equ 0x35c0

sysram_c_keygen_0           equ 0x3400
sysram_c_keygen_1           equ 0x0500
sysram_c_keygen_2           equ 0x0d60
sysram_c_keygen_3           equ 0x0de0

sysram_ek_low               equ 0x08c0
sysram_ek_fo                equ 0x2400
sysram_c_fo                 equ 0x3600

sysram_transition_entry:
%ifdef SYSRAM_TRANSITION_TO_KEYGEN
sysram_transition_to_keygen:
%elifdef SYSRAM_TRANSITION_TO_FO
sysram_transition_to_fo:
%else
%error "select one system-RAM transition"
%endif

%ifdef SYSRAM_TRANSITION_TO_KEYGEN
    cld
    cmp byte [sysram_hold_auth_status], 1
    jne .failed
    cmp byte [sysram_hold_ticket_status], 0
    je .failed
    mov ax, [SYSRAM_SYM_HOLD + 96]
    or ax, ax
    jz .failed
    cmp ax, 72
    ja .failed
    mov ax, [sysram_ticket_identity_len]
    or ax, ax
    jz .failed
    cmp ax, 192
    ja .failed
    mov dx, [sysram_ticket_nonce_len]
    or dx, dx
    jz .failed
    cmp dx, 32
    ja .failed

    ; Start from zero so short ticket fields cannot retain authenticated input
    ; bytes outside their published lengths.
    push ds
    pop es
    xor bx, bx
    mov di, sysram_capsule_low
    mov cx, sysram_capsule_len / 2
    mov ax, bx
    rep stosw
    mov si, SYSRAM_SYM_HOLD
    mov di, sysram_capsule_low
    mov cx, sysram_hold_root_len
    rep movsb
    mov si, sysram_ticket_psk
    mov di, sysram_capsule_ticket_psk
    mov cx, 32
    rep movsb
    mov si, sysram_ticket_identity
    mov di, sysram_capsule_identity
    mov cx, [sysram_ticket_identity_len]
    rep movsb
    mov si, sysram_ticket_nonce
    mov di, sysram_capsule_nonce
    mov cx, [sysram_ticket_nonce_len]
    rep movsb
    mov si, sysram_ticket_metadata
    mov di, sysram_capsule_metadata
    mov cx, 12
    rep movsb
    mov al, [sysram_hold_ticket_status]
    mov [sysram_capsule_status], al

    ; Retire the symmetric runtime gap and assemble the four read-only c
    ; slices that survive regenerated KeyGen.
    mov si, sysram_c_live_gap
    mov di, 0x3510
    mov cx, 77
    rep movsb
    mov si, sysram_c_live_3
    mov di, sysram_c_keygen_2
    mov cx, 24
    rep movsb
    mov si, sysram_c_live_4
    mov cx, 72
    rep movsb

    ; All old symmetric secrets are now represented in the compact capsule;
    ; clear the source state before the slow KeyGen phase begins.
    xor ax, ax
    mov di, 0x3600
    mov cx, (0x3b35 - 0x3600) / 2
    rep stosw
    stosb
    mov di, SYSRAM_SYM_HOLD
    mov cx, (sysram_hold_control_end - SYSRAM_SYM_HOLD) / 2
    rep stosw
    stosb
    mov di, sysram_c_live_4
    mov cx, 72 / 2
    rep stosw
    clc
    ret
.failed:
    stc
    ret
%endif

%ifdef SYSRAM_TRANSITION_TO_FO
    cld
    push ds
    pop es

    ; Consolidate c immediately below the candidate output, preserving its
    ; exact logical byte order.
    mov si, sysram_c_keygen_0
    mov di, sysram_c_fo
    mov cx, 448
    rep movsb
    mov si, sysram_c_keygen_1
    mov cx, 256
    rep movsb
    mov si, sysram_c_keygen_2
    mov cx, 96
    rep movsb
    mov si, sysram_c_keygen_3
    mov cx, 288
    rep movsb

    mov si, sysram_ek_low
    mov di, sysram_ek_fo
    mov cx, 1184 / 2
    rep movsw
    mov si, sysram_capsule_low
    mov di, sysram_capsule_high
    mov cx, sysram_capsule_len / 2
    rep movsw

    xor ax, ax
    mov di, sysram_c_keygen_1
    mov cx, 256 / 2
    rep stosw
    mov di, sysram_capsule_low
    mov cx, sysram_capsule_len / 2
    rep stosw
    mov di, sysram_ek_low
    mov cx, 1184 / 2
    rep stosw
    mov di, sysram_c_keygen_2
    mov cx, 96 / 2
    rep stosw
    mov di, sysram_c_keygen_3
    mov cx, 288 / 2
    rep stosw
    mov di, sysram_capsule_high + sysram_capsule_len
    mov cx, (sysram_abort_capsule - \
             (sysram_capsule_high + sysram_capsule_len)) / 2
    rep stosw
    mov di, 0x3ac0
    mov cx, (0x3b35 - 0x3ac0) / 2
    rep stosw
    stosb
    clc
    ret
%endif

sysram_transition_end:

%if (sysram_transition_end - $$) > 0x00e2
%error "system-RAM transition reaches the resident TCP tail"
%endif
%if sysram_capsule_status + 1 != sysram_capsule_low + sysram_capsule_len
%error "system-RAM capsule no longer packs to exactly 440 bytes"
%endif
