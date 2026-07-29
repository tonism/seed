; Fixed same-boot resumption receipt/vault lifecycle operations.
;
; RSD1 cold-loads this direct worker at 0x3000 for operations 1, 9, 10, and
; 11.  AX is only an operation selector; every phase key, card address, RAM
; destination, digest span, gate entry, and scrub entry is compiled in.
;
;   1  CLOCK       coherent INT 1Ah ticks plus the <=18-hour midnight flag
;   9  ROUTE_VALID pre-PREPARE ROG4 validation, or post-liveness exact vault
;                  validation/restore/RESTORED mark/scrub/ROG4 validation
;  10  NST_VALID   side-effect-free NTR1 read and native-ticket digest check
;  11  RESTORE     failure-only best-effort restore followed by full scrub
;
; DS=ES=SS=0 and DF clear are required.  ES is preserved, every normal return
; has DF clear, and success/failure are AX=1/CF=0 and AX=0/CF=1 except CLOCK
; and NST_VALID, whose documented result registers are returned on success.

bits 16
cpu 8086

%ifnidn __OUTPUT_FORMAT__, bin
%error "resumption lifecycle worker requires flat-binary output"
%endif

%include "post_auth_resume_vault.inc"

resident_load_phase       equ 0x10c4
vault_head_buffer         equ 0x0d00
vault_tail_buffer         equ 0x0e00
hash_bridge_stage         equ 0x2400
hash_bridge_origin        equ 0x3400
hash_bridge_limit         equ 0x3510
digest_temp               equ 0x3920
issuer_commit             equ 0x3600
ticket_psk                equ 0x38b0
ticket_identity           equ 0x3b40
ticket_nonce              equ 0x3c00
ticket_lifetime_hi        equ 0x3c20
ticket_lifetime_lo        equ 0x3c22
ticket_nonce_len          equ 0x3c28
ticket_identity_len       equ 0x3c2a
ticket_present            equ 0x3c2c
gate_control              equ 0x3c30
gate_checksum             equ 0x3c32
gate_state_inverse        equ 0x3c3e
gate_state                equ 0x3c3f
bios_ticks_day_hi         equ 0x0018
bios_ticks_day_lo         equ 0x00b0

%ifdef RESUME_LIFECYCLE_RECEIPT_HASH

%ifndef RESUME_LIFECYCLE_SYM_KEY
%error "receipt-hash bridge requires the complete K14 phase"
%endif
%ifndef RESUME_LIFECYCLE_SHA256_INIT
%error "receipt-hash bridge requires K14 SHA init"
%endif
%ifndef RESUME_LIFECYCLE_SHA256_UPDATE
%error "receipt-hash bridge requires K14 SHA update"
%endif
%ifndef RESUME_LIFECYCLE_SHA256_FINISH
%error "receipt-hash bridge requires K14 SHA finish"
%endif
%ifndef RESUME_LIFECYCLE_SELF_KEY
%error "receipt-hash bridge requires the fixed RVLW self key"
%endif

org hash_bridge_origin

lifecycle_receipt_hash_entry:
    jmp short lifecycle_receipt_hash_code
lifecycle_receipt_hash_header:
    db 'RVNH'
    dw 1
    dw lifecycle_receipt_hash_end - $$
    dw lifecycle_receipt_hash_entry

lifecycle_receipt_hash_code:
    cld
    push ds
    pop es
    mov ax, RESUME_LIFECYCLE_SYM_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc lifecycle_hash_bridge_failed
    call RESUME_LIFECYCLE_SHA256_INIT
    mov si, vault_head_buffer + resume_receipt_magic
    mov cx, resume_receipt_magic_len
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov si, vault_head_buffer + resume_receipt_tick_lo
    mov cx, 6
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov si, ticket_psk
    mov cx, resume_vault_psk_len
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov si, ticket_identity
    mov cx, resume_vault_identity_len
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov si, ticket_nonce
    mov cx, resume_vault_ticket_tail_len
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov di, digest_temp
    call RESUME_LIFECYCLE_SHA256_FINISH
    jmp short lifecycle_hash_bridge_reload

lifecycle_hash_bridge_reload:
    mov ax, RESUME_LIFECYCLE_SELF_KEY
    mov bx, 0x3000
    call resident_load_phase
    jc lifecycle_hash_bridge_failed
    ret

lifecycle_hash_bridge_failed:
    ; Discard the fixed in-RVLW continuation before restoring the caller's ES.
    pop dx
    xor ax, ax
    stc
    pop es
    cld
    ret

lifecycle_receipt_hash_end:

%if ($ - $$) > (hash_bridge_limit - hash_bridge_origin)
%error "receipt-hash bridge reaches K14 mutable extension"
%endif

%elifdef RESUME_LIFECYCLE_VAULT_HASH

%ifndef RESUME_LIFECYCLE_SYM_KEY
%error "vault-hash bridge requires the complete K14 phase"
%endif
%ifndef RESUME_LIFECYCLE_SHA256_INIT
%error "vault-hash bridge requires K14 SHA init"
%endif
%ifndef RESUME_LIFECYCLE_SHA256_UPDATE
%error "vault-hash bridge requires K14 SHA update"
%endif
%ifndef RESUME_LIFECYCLE_SHA256_FINISH
%error "vault-hash bridge requires K14 SHA finish"
%endif
%ifndef RESUME_LIFECYCLE_SELF_KEY
%error "vault-hash bridge requires the fixed RVLW self key"
%endif

org hash_bridge_origin

lifecycle_vault_hash_entry:
    jmp short lifecycle_vault_hash_code
lifecycle_vault_hash_header:
    db 'RVVH'
    dw 1
    dw lifecycle_vault_hash_end - $$
    dw lifecycle_vault_hash_entry

lifecycle_vault_hash_code:
    cld
    push ds
    pop es
    mov ax, RESUME_LIFECYCLE_SYM_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc lifecycle_hash_bridge_failed
    call RESUME_LIFECYCLE_SHA256_INIT
    mov si, lifecycle_vault_digest_domain
    mov cx, resume_vault_digest_domain_len
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov si, resume_vault_lifecycle_generation
    mov cx, 2
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov si, vault_head_buffer
    mov cx, 256
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov si, vault_tail_buffer
    mov cx, resume_vault_canonical_end
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov si, vault_tail_buffer + resume_vault_meta_random
    mov cx, 64
    call RESUME_LIFECYCLE_SHA256_UPDATE
    mov di, digest_temp
    call RESUME_LIFECYCLE_SHA256_FINISH
    jmp short lifecycle_hash_bridge_reload

lifecycle_hash_bridge_reload:
    mov ax, RESUME_LIFECYCLE_SELF_KEY
    mov bx, 0x3000
    call resident_load_phase
    jc lifecycle_hash_bridge_failed
    ret

lifecycle_hash_bridge_failed:
    ; Discard the fixed in-RVLW continuation before restoring the caller's ES.
    pop dx
    xor ax, ax
    stc
    pop es
    cld
    ret

lifecycle_vault_digest_domain db 'SEED-RVL1'
lifecycle_vault_hash_end:

%if ($ - $$) > (hash_bridge_limit - hash_bridge_origin)
%error "vault-hash bridge reaches K14 mutable extension"
%endif

%else

%ifndef RESUME_LIFECYCLE_NE_BUF_READ
%error "resumption lifecycle worker requires guarded NE2000 DMA read"
%endif
%ifndef RESUME_LIFECYCLE_SCRUB_KEY
%error "resumption lifecycle worker requires the fixed scrub-controller phase"
%endif
%ifndef RESUME_LIFECYCLE_SCRUB_ENTRY
%error "resumption lifecycle worker requires the fixed full-card scrub entry"
%endif
%ifndef RESUME_LIFECYCLE_GATE_KEY
%error "resumption lifecycle worker requires the fixed ROG3 phase"
%endif
%ifndef RESUME_LIFECYCLE_GATE_VALIDATE
%error "resumption lifecycle worker requires fixed ROG4 ticket validation"
%endif
%ifndef RESUME_LIFECYCLE_RECEIPT_HASH_KEY
%error "resumption lifecycle worker requires the fixed receipt-hash bridge"
%endif
%ifndef RESUME_LIFECYCLE_RECEIPT_HASH_BYTES
%error "resumption lifecycle worker requires measured receipt-hash bytes"
%endif
%ifndef RESUME_LIFECYCLE_VAULT_HASH_KEY
%error "resumption lifecycle worker requires the fixed vault-hash bridge"
%endif
%ifndef RESUME_LIFECYCLE_VAULT_HASH_BYTES
%error "resumption lifecycle worker requires measured vault-hash bytes"
%endif
%if RESUME_LIFECYCLE_RECEIPT_HASH_BYTES > \
    (hash_bridge_limit - hash_bridge_origin)
%error "measured receipt-hash bridge reaches K14 mutable extension"
%endif
%if RESUME_LIFECYCLE_VAULT_HASH_BYTES > \
    (hash_bridge_limit - hash_bridge_origin)
%error "measured vault-hash bridge reaches K14 mutable extension"
%endif

org 0x3000

lifecycle_worker_entry:
    jmp short lifecycle_worker_code

lifecycle_worker_header:
    db 'RVLW'
    dw 1
    dw lifecycle_worker_end - $$
    dw lifecycle_worker_entry

lifecycle_worker_code:
    cld
    push es
    cmp ax, 1
    je lifecycle_clock
    cmp ax, 9
    je lifecycle_route
    cmp ax, 10
    je lifecycle_nst
    cmp ax, 11
    je lifecycle_restore
    jmp lifecycle_failed

lifecycle_clock:
    ; NTR1 capture consumed the pre-epoch BIOS rollover flag.  The controller
    ; accepts at most 18 hours, so AL may now describe only day zero or the one
    ; possible midnight crossing.
    xor ah, ah
    int 0x1a
    cld
    xor bx, bx
    mov bl, al
    cmp bx, 1
    ja lifecycle_failed
    call lifecycle_validate_bios_ticks
    jc lifecycle_failed
    mov ax, dx
    mov dx, cx
    pop es
    clc
    ret

lifecycle_nst:
    ; A read of page 0x73 is the only card operation here.  Do not overwrite,
    ; consume, restamp, or otherwise mutate NTR1 before PREPARE.
    mov bx, resume_card_vault_head
    mov cx, 256
    mov di, vault_head_buffer
    call RESUME_LIFECYCLE_NE_BUF_READ
    jc lifecycle_failed
    call lifecycle_validate_receipt_shape
    jc lifecycle_failed
    call lifecycle_validate_native_ticket
    jc lifecycle_failed
    mov dx, lifecycle_nst_after_digest
    push dx
    mov ax, RESUME_LIFECYCLE_RECEIPT_HASH_KEY
    mov cx, RESUME_LIFECYCLE_RECEIPT_HASH_BYTES
    jmp lifecycle_launch_hash_bridge

lifecycle_nst_after_digest:
    push ds
    pop es
    mov si, digest_temp
    mov di, vault_head_buffer + resume_receipt_digest
    mov cx, resume_receipt_digest_len / 2
    repe cmpsw
    jne lifecycle_failed
    mov ax, [vault_head_buffer + resume_receipt_tick_lo]
    mov dx, [vault_head_buffer + resume_receipt_tick_hi]
    mov bx, [vault_head_buffer + resume_receipt_day]
    pop es
    clc
    ret

lifecycle_route:
    cmp byte [resume_vault_lifecycle_status], 0
    jne .maybe_valid
    cmp byte [resume_vault_lifecycle_inverse], 0
    jne lifecycle_failed
    ; First use, before PREPARE: NTR1 must remain on page 0x73.
    cmp byte [ticket_present], 2
    jne lifecycle_failed
    jmp short lifecycle_validate_route
.maybe_valid:
    cmp byte [resume_vault_lifecycle_status], \
        resume_vault_lifecycle_valid
    jne lifecycle_failed
    cmp byte [resume_vault_lifecycle_inverse], \
        resume_vault_lifecycle_valid_inverse
    jne lifecycle_failed
    mov dx, lifecycle_route_after_digest
    push dx
    jmp lifecycle_begin_restore_vault

lifecycle_route_after_digest:
    jc lifecycle_failed
    call lifecycle_finish_restore_vault
    jc lifecycle_failed
    call lifecycle_mark_restored
    call lifecycle_scrub
    jc lifecycle_failed
lifecycle_validate_route:
    mov ax, RESUME_LIFECYCLE_GATE_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc lifecycle_failed
    xor ax, ax
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    call RESUME_LIFECYCLE_GATE_VALIDATE
    jc lifecycle_failed
    cmp ax, 1
    jne lifecycle_failed
    jmp lifecycle_succeeded

lifecycle_restore:
    cmp byte [resume_vault_lifecycle_status], \
        resume_vault_lifecycle_valid
    jne lifecycle_restore_not_valid
    cmp byte [resume_vault_lifecycle_inverse], \
        resume_vault_lifecycle_valid_inverse
    jne lifecycle_restore_scrub_failed
    mov dx, lifecycle_restore_after_digest
    push dx
    jmp lifecycle_begin_restore_vault

lifecycle_restore_after_digest:
    jc lifecycle_restore_scrub_failed
    call lifecycle_finish_restore_vault
    jc lifecycle_restore_scrub_failed
    call lifecycle_mark_restored
    call lifecycle_scrub
    jc lifecycle_failed
    jmp lifecycle_succeeded
lifecycle_restore_not_valid:
    cmp byte [resume_vault_lifecycle_status], \
        resume_vault_lifecycle_restored
    jne lifecycle_restore_none
    cmp byte [resume_vault_lifecycle_inverse], \
        resume_vault_lifecycle_restored_inverse
    jne lifecycle_restore_scrub_failed
    call lifecycle_scrub
    jc lifecycle_failed
    jmp lifecycle_succeeded
lifecycle_restore_none:
    cmp byte [resume_vault_lifecycle_status], 0
    jne lifecycle_restore_scrub_failed
    cmp byte [resume_vault_lifecycle_inverse], 0
    jne lifecycle_restore_scrub_failed
    call lifecycle_scrub
    jc lifecycle_failed
    jmp lifecycle_succeeded
lifecycle_restore_scrub_failed:
    ; Invalid/partial/failed restore is never authority.  Still attempt the
    ; complete cold scrub, but preserve a failure result even if it succeeds.
    call lifecycle_scrub
    jmp lifecycle_failed

; AX=fixed one-sector hash-bridge key, CX=its exact measured length.  Stage the
; padded file sector at 0x2400 while this direct worker is live, copy only the
; measured bytes to 0x3400, and tail-enter it.  The bridge then loads K14 and
; may freely clobber its exact 0x3000..0x33f8 primitive-work interval before
; self-reloading this worker and RETing to the fixed continuation already on
; the stack.  ChaCha/Poly1305 uses the narrower 0x32af..0x33f8 subspan.
lifecycle_launch_hash_bridge:
    push cx
    mov bx, hash_bridge_stage
    call resident_load_phase
    pop cx
    jc .failed
    push ds
    pop es
    mov si, hash_bridge_stage
    mov di, hash_bridge_origin
    rep movsb
    mov dx, hash_bridge_origin
    jmp dx
.failed:
    pop dx                              ; discard fixed after-digest continuation
    jmp lifecycle_failed

lifecycle_validate_receipt_shape:
    cmp word [vault_head_buffer + resume_receipt_magic], \
        resume_receipt_magic_word0
    jne .bad
    cmp word [vault_head_buffer + resume_receipt_magic + 2], \
        resume_receipt_magic_word1
    jne .bad
    cmp word [vault_head_buffer + resume_receipt_inverse], \
        resume_receipt_inverse_word0
    jne .bad
    cmp word [vault_head_buffer + resume_receipt_inverse + 2], \
        resume_receipt_inverse_word1
    jne .bad
    cmp byte [vault_head_buffer + resume_receipt_status], \
        resume_receipt_status_valid
    jne .bad
    cmp byte [vault_head_buffer + resume_receipt_inverse_status], \
        resume_receipt_status_valid_inverse
    jne .bad
    cmp word [vault_head_buffer + resume_receipt_day], 0
    jne .bad
    mov dx, [vault_head_buffer + resume_receipt_tick_lo]
    mov cx, [vault_head_buffer + resume_receipt_tick_hi]
    call lifecycle_validate_bios_ticks
    jc .bad
    mov si, vault_head_buffer + resume_receipt_zero_start
    mov cx, resume_receipt_inverse_status - resume_receipt_zero_start
.zero:
    cmp byte [si], 0
    jne .bad
    inc si
    loop .zero
    clc
    ret
.bad:
    stc
    ret

lifecycle_validate_native_ticket:
    cmp byte [ticket_present], 2
    jne .bad
    mov ax, [ticket_identity_len]
    or ax, ax
    jz .bad
    cmp ax, resume_vault_identity_len
    ja .bad
    mov ax, [ticket_nonce_len]
    or ax, ax
    jz .bad
    cmp ax, 32
    ja .bad
    mov ax, [ticket_lifetime_hi]
    mov dx, [ticket_lifetime_lo]
    or ax, dx
    jz .bad
    mov ax, [ticket_lifetime_hi]
    cmp ax, 9
    ja .bad
    jb .ok
    cmp dx, 0x3a80
    ja .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

lifecycle_validate_bios_ticks:
    cmp cx, bios_ticks_day_hi
    ja .bad
    jb .ok
    cmp dx, bios_ticks_day_lo
    jae .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

lifecycle_begin_restore_vault:
    mov bx, resume_card_vault_head
    mov cx, 256
    mov di, vault_head_buffer
    call RESUME_LIFECYCLE_NE_BUF_READ
    jc .bad
    mov bx, resume_card_vault_tail
    mov cx, 256
    mov di, vault_tail_buffer
    call RESUME_LIFECYCLE_NE_BUF_READ
    jc .bad

    cmp word [vault_tail_buffer + resume_vault_meta_magic], \
        resume_vault_magic_word0
    jne .bad
    cmp word [vault_tail_buffer + resume_vault_meta_magic + 2], \
        resume_vault_magic_word1
    jne .bad
    cmp word [vault_tail_buffer + resume_vault_meta_inverse], \
        resume_vault_inverse_word0
    jne .bad
    cmp word [vault_tail_buffer + resume_vault_meta_inverse + 2], \
        resume_vault_inverse_word1
    jne .bad
    cmp byte [vault_tail_buffer + resume_vault_meta_status], \
        resume_vault_status_valid
    jne .bad
    cmp byte [vault_tail_buffer + resume_vault_meta_inverse_status], \
        resume_vault_status_valid_inverse
    jne .bad
    cmp byte [vault_tail_buffer + resume_vault_tail_zero], 0
    jne .bad
    cmp word [vault_tail_buffer + resume_vault_meta_pad], 0
    jne .bad
    cmp word [vault_tail_buffer + resume_vault_meta_pad + 2], 0
    jne .bad
    mov ax, [resume_vault_lifecycle_generation]
    or ax, ax
    jz .bad
    cmp ax, [vault_tail_buffer + resume_vault_meta_generation]
    jne .bad

    mov ax, RESUME_LIFECYCLE_VAULT_HASH_KEY
    mov cx, RESUME_LIFECYCLE_VAULT_HASH_BYTES
    jmp lifecycle_launch_hash_bridge
.bad:
    stc
    ret

lifecycle_finish_restore_vault:
    push ds
    pop es
    mov si, digest_temp
    mov di, vault_tail_buffer + resume_vault_meta_digest
    mov cx, 16
    repe cmpsw
    jne .bad
    mov si, digest_temp
    mov di, resume_vault_lifecycle_digest
    mov cx, 16
    repe cmpsw
    jne .bad
    cmp byte [vault_tail_buffer + resume_vault_tail_ticket + \
        resume_vault_ticket_tail_len - 1], 2
    jne .bad
    mov al, [ticket_present]
    cmp al, 1
    je .marker_ok
    or al, al
    jnz .bad
.marker_ok:
    mov [vault_tail_buffer + resume_vault_tail_zero], al

    ; Reconstruct every object invalid-first.  The issuer, ticket, and route
    ; status bytes are published only after all ordinary bytes are restored;
    ; gate state remains the final authority store.
    mov byte [issuer_commit], 0
    cmp byte [vault_tail_buffer + resume_vault_tail_zero], 1
    je .ticket_marker_invalidated
    mov byte [ticket_present], 0
.ticket_marker_invalidated:
    mov byte [gate_state_inverse], 0
    mov byte [gate_state], 0
    mov si, vault_head_buffer + 1
    mov di, issuer_commit + 1
    mov cx, resume_vault_issuer_len - 1
    rep movsb
    mov si, vault_head_buffer + resume_vault_head_psk
    mov di, ticket_psk
    mov cx, resume_vault_psk_len
    rep movsb
    mov si, vault_head_buffer + resume_vault_head_identity
    mov di, ticket_identity
    mov cx, resume_vault_head_identity_len
    rep movsb
    mov si, vault_tail_buffer + resume_vault_tail_identity
    mov di, ticket_identity + resume_vault_head_identity_len
    mov cx, resume_vault_tail_identity_len
    rep movsb
    mov si, vault_tail_buffer + resume_vault_tail_ticket
    mov di, ticket_nonce
    mov cx, resume_vault_ticket_tail_len - 1
    rep movsb
    mov si, vault_tail_buffer + resume_vault_tail_control
    mov di, gate_control
    mov cx, resume_vault_control_len - 2
    rep movsb
    cmp byte [vault_tail_buffer + resume_vault_tail_zero], 1
    jne .checksum_ready
    ; Replacing canonical early-capable 2 with spent normal-only 1 lowers the
    ; gate bundle sum by one, so its complemented checksum increases by one.
    inc word [gate_checksum]
.checksum_ready:
    mov al, [vault_head_buffer]
    mov [issuer_commit], al
    cmp byte [vault_tail_buffer + resume_vault_tail_zero], 1
    je .ticket_published
    mov al, [vault_tail_buffer + resume_vault_tail_ticket + \
        resume_vault_ticket_tail_len - 1]
    mov [ticket_present], al
.ticket_published:
    mov al, [vault_tail_buffer + resume_vault_tail_control + \
        resume_vault_control_len - 2]
    mov [gate_state_inverse], al
    mov al, [vault_tail_buffer + resume_vault_tail_control + \
        resume_vault_control_len - 1]
    mov [gate_state], al
    clc
    ret
.bad:
    stc
    ret

lifecycle_mark_restored:
    mov byte [resume_vault_lifecycle_status], 0
    mov byte [resume_vault_lifecycle_inverse], 0
    mov byte [resume_vault_lifecycle_inverse], \
        resume_vault_lifecycle_restored_inverse
    mov byte [resume_vault_lifecycle_status], \
        resume_vault_lifecycle_restored
    ret

lifecycle_scrub:
    mov ax, RESUME_LIFECYCLE_SCRUB_KEY
    mov bx, 0x2400
    call resident_load_phase
    jc .done
    push ds
    pop es
    xor ax, ax
    mov di, vault_head_buffer
    mov cx, 128
    rep stosw
    call RESUME_LIFECYCLE_SCRUB_ENTRY
.done:
    ret

lifecycle_succeeded:
    mov ax, 1
    clc
    pop es
    cld
    ret

lifecycle_failed:
    xor ax, ax
    stc
    pop es
    cld
    ret

lifecycle_worker_end:

%if ($ - $$) > 0x0400
%error "resumption lifecycle worker exceeds the direct dispatcher slot"
%endif

%endif
