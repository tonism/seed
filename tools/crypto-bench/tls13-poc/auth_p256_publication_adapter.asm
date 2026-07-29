; Fixed live-P256 CertificateVerify -> ROG3 issuer publication adapter.
;
; This one-sector cold phase is loaded immediately after the 13-sector live
; auth overlay. It accepts no pointers or caller-supplied policy. The adapter
; clears the complete issuer object, reruns the actual exact-leaf P-256 verify
; through the fixed table word at 0x1800, and only then publishes LP1 status
; last. A forged compact auth status byte therefore carries no authority.
;
; Public ABI (near call, DS=ES=SS=0, DF clear):
;   auth_publication_entry: no register inputs
;   success: CF=0, AX=1; failure: CF=1, AX=0 and 0x3600..0x3671 clear

bits 16
cpu 8086
org 0x3200

auth_verify_entry_slot        equ 0x1800
auth_input_generation         equ 0x3c2e
auth_input_digest             equ 0x3c30
auth_input_signature_len      equ 0x3c50
auth_input_signature          equ 0x3c52
auth_output_status            equ 0x3c9a

issuer_commit_start           equ 0x3600
issuer_commit_status          equ issuer_commit_start
issuer_commit_reserved        equ issuer_commit_status + 1
issuer_commit_magic           equ issuer_commit_reserved + 1
issuer_commit_magic_inverse   equ issuer_commit_magic + 4
issuer_commit_generation      equ issuer_commit_magic_inverse + 4
issuer_commit_profile         equ issuer_commit_generation + 2
issuer_commit_leaf_x          equ issuer_commit_profile + 2
issuer_commit_leaf_y          equ issuer_commit_leaf_x + 32
issuer_commit_digest          equ issuer_commit_leaf_y + 32
issuer_commit_checksum_a      equ issuer_commit_digest + 32
issuer_commit_checksum_b      equ issuer_commit_checksum_a + 2
issuer_commit_end             equ issuer_commit_checksum_b + 2
issuer_commit_check_start     equ issuer_commit_generation
issuer_commit_check_len       equ \
    issuer_commit_checksum_a - issuer_commit_check_start
issuer_leaf_profile           equ 0x003f

auth_publication_header:
    db 'LPA1'
    dw 1
    dw auth_publication_image_end - auth_publication_header
    dw auth_publication_entry
    dw auth_verify_entry_slot
    dw auth_input_generation
    dw auth_input_digest
    dw auth_input_signature_len
    dw auth_input_signature
    dw auth_output_status
    dw issuer_commit_start
    dw issuer_commit_end

auth_publication_entry:
    cld
    call auth_publication_clear
    cmp word [auth_input_generation], 0
    je auth_publication_failed

    ; The fixed table slot points at auth_overlay_verify. That routine clears
    ; auth_output_status first and performs strict DER + full P-256 ECDSA.
    call word [auth_verify_entry_slot]
    jc auth_publication_failed
    cmp ax, 1
    jne auth_publication_failed
    cmp byte [auth_output_status], 1
    jne auth_publication_failed

    mov word [issuer_commit_magic], 0x504c       ; "LP"
    mov word [issuer_commit_magic + 2], 0x2131   ; "1!"
    mov word [issuer_commit_magic_inverse], 0xafb3
    mov word [issuer_commit_magic_inverse + 2], 0xdece
    mov ax, [auth_input_generation]
    mov [issuer_commit_generation], ax
    mov word [issuer_commit_profile], issuer_leaf_profile

    push ds
    pop es
    mov si, auth_pinned_leaf_x_be
    mov di, issuer_commit_leaf_x
    mov cx, 16
    rep movsw
    mov si, auth_pinned_leaf_y_be
    mov di, issuer_commit_leaf_y
    mov cx, 16
    rep movsw
    mov si, auth_input_digest
    mov di, issuer_commit_digest
    mov cx, 16
    rep movsw

    mov si, issuer_commit_check_start
    mov cx, issuer_commit_check_len
    call auth_publication_checksum
    mov [issuer_commit_checksum_a], ax
    mov [issuer_commit_checksum_b], dx
    mov byte [issuer_commit_status], 1
    mov ax, 1
    clc
    ret

auth_publication_failed:
    xor ax, ax
    stc
    ret

auth_publication_clear:
    push ds
    pop es
    xor ax, ax
    mov di, issuer_commit_start
    mov cx, issuer_commit_end - issuer_commit_start
    rep stosb
    ret

; Same two-word torn-publication checksum as the durable WE1 publisher and
; ROG3 gate. Security comes from rerunning fixed P-256 above, not this checksum.
auth_publication_checksum:
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

%define AUTH_P256_LIVE_202607_PIN 1
%include "auth_p256_pins.inc"

auth_publication_image_end:

%if (auth_publication_image_end - auth_publication_header) > 512
%error "live P-256 publication adapter exceeds one sector"
%endif
%if issuer_commit_end != 0x3672
%error "live P-256 publication geometry drifted"
%endif
