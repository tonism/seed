; Exact fresh-boundary native-ticket receipt for same-boot TLS 1.3 resumption.
;
; The post-Finished controller stages this measured image outside K14 and
; exact-copies it to 0x3400 only after an authenticated HEAD response and the
; first retained NST have both completed at a TLS-record boundary.  K14's
; SHA-256 code and exact 0x3000..0x33f8 primitive-work interval are therefore
; still resident; its ChaCha/Poly1305 record subspan is 0x32af..0x33f8.  The
; worker publishes NTR1 to card page 0x73 with a zero-status write/readback
; followed by a status-last write/readback, restores the ordinary TX page
; after every DMA write, prepares the existing FO ticket hold, and cold-enters
; FO.
;
; It deliberately occupies at most 0x110 bytes so 0x3510+ K14 mutable work and
; 0x355d+ persistent failure services remain untouched.

bits 16
cpu 8086
org 0x3400

%ifnidn __OUTPUT_FORMAT__, bin
%error "native-ticket receipt worker requires flat-binary output"
%endif

%ifndef RESUME_RECEIPT_SHA256_INIT
%error "native-ticket receipt worker requires resident K14 SHA init"
%endif
%ifndef RESUME_RECEIPT_SHA256_UPDATE
%error "native-ticket receipt worker requires resident K14 SHA update"
%endif
%ifndef RESUME_RECEIPT_SHA256_FINISH
%error "native-ticket receipt worker requires resident K14 SHA finish"
%endif
%ifndef RESUME_RECEIPT_NE_BUF_LOAD
%error "native-ticket receipt worker requires guarded NE2000 DMA write"
%endif
%ifndef RESUME_RECEIPT_NE_BUF_READ
%error "native-ticket receipt worker requires guarded NE2000 DMA read"
%endif
%ifndef RESUME_RECEIPT_FO_KEY
%error "native-ticket receipt worker requires the fixed FO controller phase"
%endif
%ifndef RESUME_RECEIPT_PERSIST_FAIL
%error "native-ticket receipt worker requires the persistent failure service"
%endif

%include "post_auth_resume_vault.inc"

resident_load_phase       equ 0x10c4
handoff_nic_base          equ 0x060e
ne_tx_start               equ 0x06cb
receipt_build             equ 0x0700
receipt_readback          equ 0x0d00
ticket_psk                equ 0x38b0
ticket_identity           equ 0x3b40
ticket_nonce              equ 0x3c00
ticket_present            equ 0x3c2c
ticket_tail_len           equ 45
fo_ticket_hold_len        equ 238
bios_ticks_day_hi         equ 0x0018
bios_ticks_day_lo         equ 0x00b0

receipt_worker_entry:
    jmp short receipt_worker_code

receipt_worker_header:
    db 'NTRW'
    dw 1
    dw receipt_worker_end - $$
    dw receipt_worker_entry

receipt_worker_code:
    cld
    ; The only entry edge is post_ticket_milestone, which is earned by
    ; sym_parse_nst's complete lifetime/nonce/identity/profile validation.
    ; Recheck its status-last retained-object bit before binding all fixed
    ; ticket bytes; op10 independently revalidates the native lengths.
    cmp byte [ticket_present], 0
    je receipt_worker_failed

    push ds
    pop es
    xor ax, ax
    mov di, receipt_build
    mov cx, 128
    rep stosw
    mov word [receipt_build + resume_receipt_magic], \
        resume_receipt_magic_word0
    mov word [receipt_build + resume_receipt_magic + 2], \
        resume_receipt_magic_word1
    mov word [receipt_build + resume_receipt_inverse], \
        resume_receipt_inverse_word0
    mov word [receipt_build + resume_receipt_inverse + 2], \
        resume_receipt_inverse_word1

    ; Do not initialize the later PREPARE lifecycle block here.  Its
    ; 0x3c76..0x3c99 span still contains the tail of the live
    ; CertificateVerify signature required by post-FO P-256 authentication.
    ; The post-auth entry clears that block only after LP1 has been published.

    ; INT 1Ah samples the tick dword coherently and consumes the BIOS midnight
    ; flag.  This is the same-boot epoch: the receipt day is exactly zero and
    ; the later CLOCK operation reports the one possible <=18-hour rollover.
    xor ah, ah
    int 0x1a
    cmp cx, bios_ticks_day_hi
    jae receipt_worker_tick_edge
receipt_worker_tick_ok:
    mov [receipt_build + resume_receipt_tick_lo], dx
    mov [receipt_build + resume_receipt_tick_hi], cx

    call RESUME_RECEIPT_SHA256_INIT
    mov si, receipt_build + resume_receipt_magic
    mov cx, resume_receipt_magic_len
    call RESUME_RECEIPT_SHA256_UPDATE
    mov si, receipt_build + resume_receipt_tick_lo
    mov cx, 6
    call RESUME_RECEIPT_SHA256_UPDATE
    mov si, ticket_psk
    mov cx, resume_vault_psk_len
    call RESUME_RECEIPT_SHA256_UPDATE
    mov si, ticket_identity
    mov cx, resume_vault_identity_len
    call RESUME_RECEIPT_SHA256_UPDATE
    mov si, ticket_nonce
    mov cx, ticket_tail_len
    call RESUME_RECEIPT_SHA256_UPDATE
    mov di, receipt_build + resume_receipt_digest
    call RESUME_RECEIPT_SHA256_FINISH

    ; First prove the complete invalid image, then publish validity physically
    ; last through the second ascending full-page DMA and prove that image.
    call receipt_write_verify
    jc receipt_worker_failed
    mov byte [receipt_build + resume_receipt_inverse_status], \
        resume_receipt_status_valid_inverse
    mov byte [receipt_build + resume_receipt_status], \
        resume_receipt_status_valid
    call receipt_write_verify
    jc receipt_worker_failed

    ; Preserve the exact existing FO input contract after receipt scratch has
    ; retired, then replace FO's controller slot and enter it.
    mov si, ticket_identity
    mov di, receipt_build
    mov cx, fo_ticket_hold_len / 2
    rep movsw
    mov ax, RESUME_RECEIPT_FO_KEY
    mov bx, 0x2400
    call resident_load_phase
    jc receipt_worker_failed
    mov dx, 0x2400
    jmp dx

receipt_worker_tick_edge:
    jne receipt_worker_failed
    cmp dx, bios_ticks_day_lo
    jb receipt_worker_tick_ok
    jmp short receipt_worker_failed

receipt_write_verify:
    mov al, 0x73
    mov ah, [ne_tx_start]
    push ax
    mov [ne_tx_start], al
    mov si, receipt_build
    mov bp, 256
    mov bx, [handoff_nic_base]
    call RESUME_RECEIPT_NE_BUF_LOAD
    pop ax
    mov [ne_tx_start], ah
    jc .done
    mov bx, resume_card_vault_head
    mov cx, 256
    mov di, receipt_readback
    call RESUME_RECEIPT_NE_BUF_READ
    jc .done
    mov si, receipt_build
    mov di, receipt_readback
    mov cx, 128
    repe cmpsw
    je .done
    stc
.done:
    ret

receipt_worker_failed:
    mov dx, RESUME_RECEIPT_PERSIST_FAIL
    jmp dx

receipt_worker_end:

%if ($ - $$) > 0x0110
%error "native-ticket receipt worker reaches K14 mutable work"
%endif
