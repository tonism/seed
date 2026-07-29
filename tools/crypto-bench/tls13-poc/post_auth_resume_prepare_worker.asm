; Seed TLS 1.3 same-boot resumption PREPARE worker.
;
; The source is assembled as nine fixed images: one operation-2 broker plus
; eight continuations selected exclusively by builder-supplied constants.
; HASH, COMMIT, CRYPTO, and BINDER load at 0x3000 and are exact-copied through
; the private 0x0780 transition to execute at 0x3400.  AGE executes directly at
; 0x2800.  SYM_BINDER and EARLY also stage at 0x3000 and are exact-copied to
; 0x3400 so their padded sectors cannot erase the persistent-service suffix.
; RESTORE executes directly at 0x3000.
;
;   RESUME_PREPARE_BROKER       direct worker at 0x3000
;     consumes the second independently duplicated entropy bundle from
;     read/write NE2000 RAM, writes the canonical issuer/ticket/control vault
;     with an invalid status, and installs a private 0x0780 phase transition.
;
;   RESUME_PREPARE_HASH         continuation at 0x3400
;     binds the exact vault plus attempt random/session with the symmetric
;     overlay's checked SHA-256.
;
;   RESUME_PREPARE_COMMIT       continuation at 0x3400
;     commits card status last, publishes the private lifecycle block status
;     last, and only then retires native state.
;
;   RESUME_PREPARE_CRYPTO       continuation at 0x3400
;     performs fresh target-side KeyGen, vaults ek/private state, independently
;     restores the fixed resumed-HELLO input ABI.
;
;   RESUME_PREPARE_AGE          direct continuation at 0x2800
;     samples the clock after slow KeyGen, rechecks lifetime, and publishes the
;     exact late obfuscated ticket age consumed by ClientHello.
;
;   RESUME_PREPARE_BINDER       continuation at 0x3400
;     independently builds the resumed ClientHello binder with HELLO and
;     finalizes the exact full-ClientHello digest for 0-RTT.
;
;   RESUME_PREPARE_SYM_BINDER   continuation at 0x3400
;     reloads and verifies the symmetric overlay, independently recomputes
;     the binder, and leaves the early resumption schedule live.
;
;   RESUME_PREPARE_EARLY        continuation at 0x3400
;     derives the client early-traffic key from the full ClientHello and
;     seals the one fixed replay-safe credential-free HEAD before reconnect.
;
;   RESUME_PREPARE_RESTORE      final direct worker at 0x3000
;     zeroizes consumed host/card staging, restores the RSU1 low scatter that
;     fresh ek placement necessarily overwrote, and only then returns through
;     the original operation-2 frame.
;
; No floppy write is performed.  The only writable persistence is volatile
; NIC RAM 0x7300..0x7fff.  All phase keys, internal entry points, guarded
; driver leaves, and lifecycle bounds are supplied by the composing builder.

bits 16
cpu 8086

%include "post_auth_resume_vault.inc"

%ifndef RESUME_PREPARE_LOAD_PHASE
%error "resumption PREPARE requires the resident phase loader"
%endif
%ifndef RESUME_PREPARE_NE_BUF_READ
%error "resumption PREPARE requires the guarded NE2000 read leaf"
%endif
%ifndef RESUME_PREPARE_NE_BUF_LOAD
%error "resumption PREPARE requires the guarded NE2000 write leaf"
%endif
%ifndef RESUME_PREPARE_NIC_BASE
%error "resumption PREPARE requires the resident NIC-base word"
%endif
%ifndef RESUME_PREPARE_NE_TX_START
%error "resumption PREPARE requires the resident NE transmit-page byte"
%endif
%ifndef RESUME_PREPARE_LIFECYCLE_START
%error "resumption PREPARE requires the private lifecycle start"
%endif
%ifndef RESUME_PREPARE_LIFECYCLE_END
%error "resumption PREPARE requires the private lifecycle end"
%endif
%ifndef RESUME_PREPARE_PERSIST_FAIL
%error "resumption PREPARE requires the persistent failure service"
%endif
%ifndef RESUME_PREPARE_CONT_LIMIT
%define RESUME_PREPARE_CONT_LIMIT 0x0110
%endif
%ifdef RESUME_PREPARE_DIAGNOSTIC
%ifndef RESUME_PREPARE_EXPECTED_RETURN
%error "diagnostic PREPARE requires its fixed controller return address"
%endif
%endif

prepare_native_issuer          equ 0x3600
prepare_native_ticket_psk      equ 0x38b0
prepare_native_identity        equ 0x3b40
prepare_native_ticket_tail     equ 0x3c00
prepare_native_ticket_end      equ 0x3c2d
prepare_native_generation      equ 0x3c30
prepare_native_control         equ 0x3c30
prepare_native_control_end     equ 0x3c40
prepare_rsu_receipt_tick_lo    equ 0x3c46
prepare_rsu_receipt_tick_hi    equ 0x3c48
prepare_rsu_receipt_day        equ 0x3c4a
prepare_attempt_tick_lo        equ 0x3c58
prepare_attempt_tick_hi        equ 0x3c5a
prepare_attempt_day            equ 0x3c5c
prepare_attempt_age_wire       equ 0x3c5e
prepare_attempt_ms             equ 0x3c62

prepare_entropy_a              equ 0x0d00
prepare_entropy_b              equ 0x0d80
prepare_page                   equ 0x0e00
prepare_readback               equ 0x0700
; 0x0700..0x075f retains the truncated hash, binder, and full ClientHello hash
; across the BINDER -> SYM_BINDER -> EARLY chain.  Keep the executable
; trampoline in the retired upper half of the same page.
prepare_transition             equ 0x0780
prepare_sym_retry_count        equ 0x07fe
prepare_restore_outcome        equ 0x07ff
prepare_transition_terminal    equ 0xa5
prepare_attempt_cache          equ 0x3b9c

prepare_lifecycle_digest       equ RESUME_PREPARE_LIFECYCLE_START
prepare_lifecycle_generation   equ prepare_lifecycle_digest + 32
prepare_lifecycle_inverse      equ prepare_lifecycle_generation + 2
prepare_lifecycle_status       equ prepare_lifecycle_inverse + 1
prepare_lifecycle_used_end     equ prepare_lifecycle_status + 1

%macro prepare_diagnostic 1
%ifdef RESUME_PREPARE_DIAGNOSTIC
    push ax
    push cx
    push dx
    mov ah, %1
    mov dx, 0x03fd
    xor cx, cx
%%wait:
    in al, dx
    test al, 0x20
    loopz %%wait
    mov dl, 0xf8
    mov al, ah
    out dx, al
    pop dx
    pop cx
    pop ax
%endif
%endmacro

%macro prepare_diagnostic_nowait 1
%ifdef RESUME_PREPARE_DIAGNOSTIC
    push ax
    push dx
    mov al, %1
    mov dx, 0x03f8
    out dx, al
    pop dx
    pop ax
%endif
%endmacro

%macro prepare_binder_mark 1
%ifdef RESUME_PREPARE_BINDER_DIAGNOSTIC
    push ax
    mov al, %1
    call prepare_binder_diagnostic_emit
    pop ax
%endif
%endmacro

%if prepare_native_ticket_end - prepare_native_ticket_tail != \
    resume_vault_ticket_tail_len
%error "native ticket-tail geometry drifted"
%endif
%if prepare_native_control_end - prepare_native_control != \
    resume_vault_control_len
%error "native control geometry drifted"
%endif
%if prepare_lifecycle_used_end > RESUME_PREPARE_LIFECYCLE_END
%error "PREPARE lifecycle publication exceeds builder-owned bounds"
%endif
%if RESUME_PREPARE_LIFECYCLE_START != resume_vault_lifecycle_digest
%error "PREPARE lifecycle start differs from shared RVL1 contract"
%endif
%if RESUME_PREPARE_LIFECYCLE_END != resume_vault_lifecycle_end
%error "PREPARE lifecycle end differs from shared RVL1 contract"
%endif
%if RESUME_PREPARE_LIFECYCLE_END > 0x3c9a
%error "PREPARE lifecycle publication reaches reconnect state"
%endif
%if resume_vault_digest_domain_len != 9
%error "PREPARE RVL1 domain length drifted"
%endif

%ifdef RESUME_PREPARE_BROKER

%ifdef RESUME_PREPARE_HASH
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_CRYPTO
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_COMMIT
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_BINDER
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_AGE
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_SYM_BINDER
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_EARLY
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_RESTORE
%error "select one PREPARE phase"
%endif
%ifndef RESUME_PREPARE_HASH_KEY
%error "PREPARE broker requires its fixed hash-continuation key"
%endif
%ifndef RESUME_PREPARE_HASH_BYTES
%error "PREPARE broker requires its measured hash-continuation bytes"
%endif

org 0x3000

resume_prepare_broker_entry:
    jmp short resume_prepare_broker
resume_prepare_broker_header:
    db 'RPB1'
    dw 1
    dw resume_prepare_broker_end - $$
    dw 0x3000
    dw resume_prepare_broker_entry

resume_prepare_broker:
    cld
    push es
    push ds
    pop es
    prepare_diagnostic '1'
    cmp ax, 2
    jne resume_prepare_broker_failed

    ; Invalidate the private host publication before touching either source.
    xor ax, ax
    mov di, RESUME_PREPARE_LIFECYCLE_START
    mov cx, RESUME_PREPARE_LIFECYCLE_END - \
        RESUME_PREPARE_LIFECYCLE_START
    rep stosb

    ; The initial secure path scrubbed the consumed first half of both pages.
    ; The independently duplicated second half is the authoritative resumption
    ; d||z||random||session bundle.  Compare every byte and reject all-zero.
    mov bx, 0x7e80
    mov cx, 128
    mov di, prepare_entropy_a
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_broker_failed
    mov bx, 0x7f80
    mov cx, 128
    mov di, prepare_entropy_b
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_broker_failed
    mov si, prepare_entropy_a
    mov di, prepare_entropy_b
    mov cx, 64
    repe cmpsw
    jne resume_prepare_broker_failed
    mov si, prepare_entropy_a
    mov cx, 64
    xor dx, dx
.entropy_nonzero:
    lodsw
    or dx, ax
    loop .entropy_nonzero
    or dx, dx
    jz resume_prepare_broker_failed
    prepare_diagnostic '2'

    mov ax, [prepare_native_generation]
    or ax, ax
    jz resume_prepare_broker_failed
    ; Secure-floor resumption requires a ticket whose validated early_data
    ; allowance can carry the complete fixed public HEAD.
    cmp byte [0x3c2c], 2
    jne resume_prepare_broker_failed
    mov ax, [0x3c2a]
    or ax, ax
    jz resume_prepare_broker_failed
    cmp ax, resume_vault_identity_len
    ja resume_prepare_broker_failed
    mov si, prepare_native_identity
    add si, ax
    mov cx, resume_vault_identity_len
    sub cx, ax
    jcxz .identity_padding_valid
    xor dx, dx
.identity_padding_zero:
    lodsb
    or dl, al
    loop .identity_padding_zero
    or dl, dl
    jnz resume_prepare_broker_failed
.identity_padding_valid:

    ; Operation 10 has just authenticated NTR1 against the native ticket.
    ; Re-read its authority immediately before consuming page 0x73, require
    ; its clock tuple to equal RSU1's validated publication, and reject any
    ; nonzero reserved byte.  The digest itself was verified by operation 10;
    ; PREPARE's next SHA pass is reserved for the replacement RVL1 object.
    mov bx, resume_card_vault_head
    mov cx, 256
    mov di, prepare_readback
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_broker_failed
    cmp word [prepare_readback + resume_receipt_magic], \
        resume_receipt_magic_word0
    jne resume_prepare_broker_failed
    cmp word [prepare_readback + resume_receipt_magic + 2], \
        resume_receipt_magic_word1
    jne resume_prepare_broker_failed
    cmp word [prepare_readback + resume_receipt_inverse], \
        resume_receipt_inverse_word0
    jne resume_prepare_broker_failed
    cmp word [prepare_readback + resume_receipt_inverse + 2], \
        resume_receipt_inverse_word1
    jne resume_prepare_broker_failed
    cmp byte [prepare_readback + resume_receipt_inverse_status], \
        resume_receipt_status_valid_inverse
    jne resume_prepare_broker_failed
    cmp byte [prepare_readback + resume_receipt_status], \
        resume_receipt_status_valid
    jne resume_prepare_broker_failed
    mov ax, [prepare_readback + resume_receipt_tick_lo]
    cmp ax, [prepare_rsu_receipt_tick_lo]
    jne resume_prepare_broker_failed
    mov ax, [prepare_readback + resume_receipt_tick_hi]
    cmp ax, [prepare_rsu_receipt_tick_hi]
    jne resume_prepare_broker_failed
    mov ax, [prepare_readback + resume_receipt_day]
    cmp ax, [prepare_rsu_receipt_day]
    jne resume_prepare_broker_failed
    mov si, prepare_readback + resume_receipt_zero_start
    mov cx, (resume_receipt_inverse_status - \
        resume_receipt_zero_start) / 2
    xor dx, dx
.receipt_zero:
    lodsw
    or dx, ax
    loop .receipt_zero
    or dx, dx
    jnz resume_prepare_broker_failed
    prepare_diagnostic '3'

    ; Canonical page 0x73: issuer114 || PSK32 || identity[0:110].
    xor ax, ax
    mov di, prepare_page
    mov cx, 128
    rep stosw
    mov si, prepare_native_issuer
    mov di, prepare_page + resume_vault_head_issuer
    mov cx, resume_vault_issuer_len
    rep movsb
    mov si, prepare_native_ticket_psk
    mov di, prepare_page + resume_vault_head_psk
    mov cx, resume_vault_psk_len
    rep movsb
    mov si, prepare_native_identity
    mov di, prepare_page + resume_vault_head_identity
    mov cx, resume_vault_head_identity_len
    rep movsb
    mov al, 0x73
    mov si, prepare_page
    mov bp, 256
    call resume_prepare_broker_card_write
    jc resume_prepare_broker_failed
    mov bx, resume_card_vault_head
    call resume_prepare_broker_verify_page
    jc resume_prepare_broker_failed
    prepare_diagnostic '4'

    ; Canonical page 0x7f: identity tail, native ticket tail, ROG3 control,
    ; required zero, invalid metadata, and the target-generated random/session.
    xor ax, ax
    mov di, prepare_page
    mov cx, 128
    rep stosw
    mov si, prepare_native_identity + resume_vault_head_identity_len
    mov di, prepare_page + resume_vault_tail_identity
    mov cx, resume_vault_tail_identity_len
    rep movsb
    mov si, prepare_native_ticket_tail
    mov di, prepare_page + resume_vault_tail_ticket
    mov cx, resume_vault_ticket_tail_len
    rep movsb
    mov si, prepare_native_control
    mov di, prepare_page + resume_vault_tail_control
    mov cx, resume_vault_control_len
    rep movsb
    mov word [prepare_page + resume_vault_meta_magic], \
        resume_vault_magic_word0
    mov word [prepare_page + resume_vault_meta_magic + 2], \
        resume_vault_magic_word1
    mov word [prepare_page + resume_vault_meta_inverse], \
        resume_vault_inverse_word0
    mov word [prepare_page + resume_vault_meta_inverse + 2], \
        resume_vault_inverse_word1
    mov ax, [prepare_native_generation]
    mov [prepare_page + resume_vault_meta_generation], ax
    mov si, prepare_entropy_a + 64
    mov di, prepare_page + resume_vault_meta_random
    mov cx, 32
    rep movsw
    mov al, 0x7f
    mov si, prepare_page
    mov bp, 256
    call resume_prepare_broker_card_write
    jc resume_prepare_broker_failed
    mov bx, resume_card_vault_tail
    call resume_prepare_broker_verify_page
    jc resume_prepare_broker_failed
    prepare_diagnostic '5'

    ; The transition is private to operation 2 and occupies the receive frame
    ; only after its entropy/readback work is complete.  HELLO may overwrite it
    ; after the final continuation has already been installed.
    mov si, resume_prepare_transition_source
    mov di, prepare_transition
    mov cx, resume_prepare_transition_end - \
        resume_prepare_transition_source
    rep movsb
    mov byte [prepare_restore_outcome], 0
    mov ax, RESUME_PREPARE_HASH_KEY
    mov cx, RESUME_PREPARE_HASH_BYTES
    jmp prepare_transition

resume_prepare_broker_verify_page:
    mov cx, 256
    mov di, prepare_readback
    call RESUME_PREPARE_NE_BUF_READ
    jc .done
    mov si, prepare_readback
    mov di, prepare_page
    mov cx, 128
    repe cmpsw
    jne .different
    clc
.done:
    ret
.different:
    stc
    ret

; AL=card page, SI=source, BP=count.  Restore the product TX page while
; retaining the guarded driver's carry result.
resume_prepare_broker_card_write:
    xor bx, bx
    mov bl, [RESUME_PREPARE_NE_TX_START]
    push bx
    mov [RESUME_PREPARE_NE_TX_START], al
    mov bx, [RESUME_PREPARE_NIC_BASE]
    call RESUME_PREPARE_NE_BUF_LOAD
    pop bx
    mov [RESUME_PREPARE_NE_TX_START], bl
    ret

resume_prepare_transition_source:
    push cx
    mov bx, 0x3000
    mov dx, RESUME_PREPARE_LOAD_PHASE
    call dx
    pop cx
    jc resume_prepare_transition_failed_source
    push ds
    pop es
    mov si, 0x3000
    mov di, 0x3400
    rep movsb
    mov dx, 0x3400
    jmp dx
resume_prepare_transition_failed_source:
    cmp byte [prepare_restore_outcome], prepare_transition_terminal
    je resume_prepare_transition_terminal_source
    xor ax, ax
    stc
    pop es
    ret
resume_prepare_transition_terminal_source:
    mov dx, RESUME_PREPARE_PERSIST_FAIL
    jmp dx
resume_prepare_transition_end:

resume_prepare_broker_failed:
    push ds
    pop es
    xor ax, ax
    mov di, prepare_entropy_a
    mov cx, 256
    rep stosb
    stc
    pop es
    ret

resume_prepare_broker_end:

%if ($ - $$) > 0x0400
%error "PREPARE broker exceeds the direct-worker slot"
%endif
%if (resume_prepare_transition_end - resume_prepare_transition_source) > 0x40
%error "PREPARE private transition unexpectedly grew"
%endif

%elifdef RESUME_PREPARE_HASH

%ifdef RESUME_PREPARE_CRYPTO
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_COMMIT
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_BINDER
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_RESTORE
%error "select one PREPARE phase"
%endif
%ifndef RESUME_PREPARE_SYM_KEY
%error "PREPARE hash continuation requires the symmetric phase"
%endif
%ifndef RESUME_PREPARE_SYM_SHA_INIT
%error "PREPARE hash continuation requires resolved SHA init"
%endif
%ifndef RESUME_PREPARE_SYM_SHA_UPDATE
%error "PREPARE hash continuation requires resolved SHA update"
%endif
%ifndef RESUME_PREPARE_SYM_SHA_FINISH
%error "PREPARE hash continuation requires resolved SHA finish"
%endif
%ifndef RESUME_PREPARE_COMMIT_KEY
%error "PREPARE hash continuation requires its fixed commit-continuation key"
%endif
%ifndef RESUME_PREPARE_COMMIT_BYTES
%error "PREPARE hash continuation requires measured commit bytes"
%endif

org 0x3400

resume_prepare_hash_entry:
    cld
    prepare_diagnostic '6'
    mov ax, RESUME_PREPARE_SYM_KEY
    mov bx, 0x1800
    call RESUME_PREPARE_LOAD_PHASE
    jc resume_prepare_hash_failed

    call RESUME_PREPARE_SYM_SHA_INIT
    mov si, resume_prepare_hash_domain
    mov cx, resume_prepare_hash_domain_end - resume_prepare_hash_domain
    call RESUME_PREPARE_SYM_SHA_UPDATE
    mov si, prepare_native_generation
    mov cx, 2
    call RESUME_PREPARE_SYM_SHA_UPDATE
    mov bx, resume_card_vault_head
    mov cx, 256
    mov di, prepare_entropy_a
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_hash_failed
    mov si, prepare_entropy_a
    mov cx, 256
    call RESUME_PREPARE_SYM_SHA_UPDATE
    mov bx, resume_card_vault_tail
    mov cx, 256
    mov di, prepare_page
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_hash_failed
    cmp byte [prepare_page + resume_vault_meta_status], 0
    jne resume_prepare_hash_failed
    mov si, prepare_page
    mov cx, resume_vault_canonical_end
    call RESUME_PREPARE_SYM_SHA_UPDATE
    mov si, prepare_page + resume_vault_meta_random
    mov cx, 64
    call RESUME_PREPARE_SYM_SHA_UPDATE
    mov di, prepare_lifecycle_digest
    call RESUME_PREPARE_SYM_SHA_FINISH

    mov si, prepare_lifecycle_digest
    mov di, prepare_page + resume_vault_meta_digest
    mov cx, 16
    rep movsw
    prepare_diagnostic '7'
    mov ax, RESUME_PREPARE_COMMIT_KEY
    mov cx, RESUME_PREPARE_COMMIT_BYTES
    jmp prepare_transition

resume_prepare_hash_failed:
    xor ax, ax
    stc
    pop es
    ret

resume_prepare_hash_domain:
    db 'SEED-RVL1'
resume_prepare_hash_domain_end:
resume_prepare_hash_end:

%if ($ - $$) > RESUME_PREPARE_CONT_LIMIT
%error "PREPARE hash continuation reaches symmetric extension work"
%endif

%elifdef RESUME_PREPARE_COMMIT

%ifdef RESUME_PREPARE_CRYPTO
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_BINDER
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_RESTORE
%error "select one PREPARE phase"
%endif
%ifndef RESUME_PREPARE_CRYPTO_KEY
%error "PREPARE commit continuation requires its fixed crypto key"
%endif
%ifndef RESUME_PREPARE_CRYPTO_BYTES
%error "PREPARE commit continuation requires measured crypto bytes"
%endif

org 0x3400

resume_prepare_commit_entry:
    cld
    prepare_diagnostic '8'
    ; First publish the digest with invalid status and verify the full page.
    mov byte [prepare_page + resume_vault_meta_inverse_status], 0
    mov byte [prepare_page + resume_vault_meta_status], 0
    call resume_prepare_commit_write_tail
    jc resume_prepare_commit_failed
    call resume_prepare_commit_verify_tail
    jc resume_prepare_commit_failed

    ; Ascending remote DMA physically writes byte 0x7fff last.
    mov byte [prepare_page + resume_vault_meta_inverse_status], \
        resume_vault_status_valid_inverse
    mov byte [prepare_page + resume_vault_meta_status], \
        resume_vault_status_valid
    call resume_prepare_commit_write_tail
    jc resume_prepare_commit_failed
    call resume_prepare_commit_verify_tail
    jc resume_prepare_commit_failed

    ; Card authority is complete.  Publish the private host lifecycle status
    ; last, then retire every native byte represented by the canonical vault.
    mov ax, [prepare_native_generation]
    mov [prepare_lifecycle_generation], ax
    mov byte [prepare_lifecycle_inverse], \
        resume_vault_lifecycle_valid_inverse
    mov byte [prepare_lifecycle_status], \
        resume_vault_lifecycle_valid
    push ds
    pop es
    xor ax, ax
    mov di, prepare_native_issuer
    mov cx, resume_vault_issuer_len
    rep stosb
    mov di, prepare_native_ticket_psk
    mov cx, resume_vault_psk_len
    rep stosb
    mov di, prepare_native_identity
    mov cx, resume_vault_identity_len
    rep stosb
    mov di, prepare_native_ticket_tail
    mov cx, resume_vault_ticket_tail_len
    rep stosb
    mov di, prepare_native_control
    mov cx, resume_vault_control_len
    rep stosb

    prepare_diagnostic '9'
    mov ax, RESUME_PREPARE_CRYPTO_KEY
    mov cx, RESUME_PREPARE_CRYPTO_BYTES
    jmp prepare_transition

resume_prepare_commit_write_tail:
    mov al, 0x7f
    mov si, prepare_page
    mov bp, 256
    jmp short resume_prepare_commit_card_write

resume_prepare_commit_verify_tail:
    mov bx, resume_card_vault_tail
    mov cx, 256
    mov di, prepare_entropy_a
    call RESUME_PREPARE_NE_BUF_READ
    jc .done
    mov si, prepare_entropy_a
    mov di, prepare_page
    mov cx, 128
    repe cmpsw
    jne .different
    clc
.done:
    ret
.different:
    stc
    ret

resume_prepare_commit_card_write:
    xor bx, bx
    mov bl, [RESUME_PREPARE_NE_TX_START]
    push bx
    mov [RESUME_PREPARE_NE_TX_START], al
    mov bx, [RESUME_PREPARE_NIC_BASE]
    call RESUME_PREPARE_NE_BUF_LOAD
    pop bx
    mov [RESUME_PREPARE_NE_TX_START], bl
    ret

resume_prepare_commit_failed:
    xor ax, ax
    stc
    pop es
    ret

resume_prepare_commit_end:

%if ($ - $$) > RESUME_PREPARE_CONT_LIMIT
%error "PREPARE commit continuation reaches symmetric extension work"
%endif

%elifdef RESUME_PREPARE_CRYPTO

%ifdef RESUME_PREPARE_BINDER
%error "select one PREPARE phase"
%endif
%ifdef RESUME_PREPARE_RESTORE
%error "select one PREPARE phase"
%endif
%ifndef RESUME_PREPARE_KEYGEN_KEY
%error "PREPARE crypto continuation requires fresh KeyGen"
%endif
%ifndef RESUME_PREPARE_KEYGEN_ENTRY
%error "PREPARE crypto continuation requires resolved KeyGen entry"
%endif
%ifndef RESUME_PREPARE_HELLO_KEY
%error "PREPARE crypto continuation requires resumed HELLO"
%endif
%ifndef RESUME_PREPARE_AGE_KEY
%error "PREPARE crypto continuation requires its fixed late-age phase"
%endif
%ifndef RESUME_PREPARE_RESTORE_KEY
%error "PREPARE crypto continuation requires its fixed restore key"
%endif
%ifndef RESUME_PREPARE_PERSIST_FAIL
%error "PREPARE crypto continuation requires the persistent failure service"
%endif

org 0x3400

resume_prepare_crypto_entry:
    cld
    prepare_diagnostic_nowait 'a'
    ; Re-read d||z only after the canonical vault has retired the overlapping
    ; native identity slot.  0x3b9c is both KeyGen's input and part of the
    ; pre-vault 192-byte ticket identity, so an earlier copy would corrupt the
    ; very authority being committed.
    mov bx, resume_card_candidate_b
    mov cx, 64
    mov di, prepare_attempt_cache
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_crypto_failed
    mov ax, RESUME_PREPARE_KEYGEN_KEY
    mov bx, 0x1800
    call RESUME_PREPARE_LOAD_PHASE
    jc resume_prepare_crypto_failed
    call RESUME_PREPARE_KEYGEN_ENTRY
    jc resume_prepare_crypto_failed
    prepare_diagnostic_nowait 'b'

    mov al, 0x74
    mov si, 0x08c0
    mov bp, resume_card_ek_len
    call resume_prepare_crypto_card_write
    jc resume_prepare_crypto_failed
    mov al, 0x79
    mov si, 0x3600
    mov bp, resume_card_private_len
    call resume_prepare_crypto_card_write
    jc resume_prepare_crypto_failed

    mov ax, RESUME_PREPARE_HELLO_KEY
    mov bx, 0x1800
    call RESUME_PREPARE_LOAD_PHASE
    jc resume_prepare_crypto_failed
    mov bx, resume_card_ek
    mov cx, resume_card_ek_len
    mov di, 0x08c0
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_crypto_failed
    mov bx, resume_card_vault_tail + resume_vault_meta_random
    mov cx, 64
    mov di, prepare_attempt_cache
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_crypto_failed
    mov bx, resume_card_vault_head + resume_vault_head_psk
    mov cx, resume_vault_psk_len
    mov di, prepare_attempt_cache + 64
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_crypto_failed
    mov bx, resume_card_vault_tail + resume_vault_tail_ticket + 0x2a
    mov cx, 2
    mov di, prepare_attempt_cache + 100
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_crypto_failed
    prepare_diagnostic_nowait 'c'

    ; Fresh ek occupies 0x08c0..0x0d5f and therefore destroys every live RSU1
    ; low scatter.  From this point onward, the private transition must fail
    ; through the persistent scrub service rather than return through the old
    ; controller.  The transition itself executes at 0x0780 so loading AGE at
    ; 0x2800 cannot overwrite this continuation or the HELLO image ending at
    ; 0x27ff.
    mov byte [prepare_restore_outcome], prepare_transition_terminal
    mov ax, RESUME_PREPARE_AGE_KEY
    mov bx, 0x2800
    call RESUME_PREPARE_LOAD_PHASE
    jc resume_prepare_crypto_terminal
    mov dx, 0x2800
    jmp dx

resume_prepare_crypto_card_write:
    xor bx, bx
    mov bl, [RESUME_PREPARE_NE_TX_START]
    push bx
    mov [RESUME_PREPARE_NE_TX_START], al
    mov bx, [RESUME_PREPARE_NIC_BASE]
    call RESUME_PREPARE_NE_BUF_LOAD
    pop bx
    mov [RESUME_PREPARE_NE_TX_START], bl
    ret

resume_prepare_crypto_failed:
    mov byte [prepare_restore_outcome], 0
    mov ax, RESUME_PREPARE_RESTORE_KEY
    mov bx, 0x3000
    call RESUME_PREPARE_LOAD_PHASE
    jc resume_prepare_crypto_terminal
    mov dx, 0x3000
    jmp dx

resume_prepare_crypto_terminal:
    mov dx, RESUME_PREPARE_PERSIST_FAIL
    jmp dx

resume_prepare_crypto_end:

%if ($ - $$) > RESUME_PREPARE_CONT_LIMIT
%error "PREPARE crypto continuation reaches symmetric extension work"
%endif

%elifdef RESUME_PREPARE_AGE

%ifndef RESUME_PREPARE_CLOCK_CALLBACK
%error "PREPARE age continuation requires the fixed clock callback"
%endif
%ifndef RESUME_PREPARE_BINDER_KEY
%error "PREPARE age continuation requires its fixed binder phase"
%endif
%ifndef RESUME_PREPARE_BINDER_BYTES
%error "PREPARE age continuation requires measured binder bytes"
%endif
%ifndef RESUME_PREPARE_RESTORE_KEY
%error "PREPARE age continuation requires its fixed restore key"
%endif
%ifndef RESUME_PREPARE_PERSIST_FAIL
%error "PREPARE age continuation requires persistent failure"
%endif

prepare_bios_ticks_day_hi equ 0x0018
prepare_bios_ticks_day_lo equ 0x00b0
prepare_ticks_max_hi      equ 0x0012
prepare_ticks_max_lo      equ 0x0084

org 0x2800

resume_prepare_age_entry:
    cld
    cmp byte [prepare_lifecycle_status], resume_vault_lifecycle_valid
    jne resume_prepare_age_failed
    cmp byte [prepare_lifecycle_inverse], \
        resume_vault_lifecycle_valid_inverse
    jne resume_prepare_age_failed
    cmp word [prepare_rsu_receipt_day], 0
    jne resume_prepare_age_failed

    ; Recover numeric lifetime_hi/lifetime_lo followed by the raw
    ; network-order ticket_age_add.  The canonical card object was already
    ; digest-bound and read back before native state was retired.
    mov bx, resume_card_vault_tail + resume_vault_tail_ticket + 0x20
    mov cx, 8
    mov di, prepare_page
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_age_failed

    ; RSD1 operation 1 is the sole coherent BIOS-clock authority.  Its BX is
    ; the rollover delta since the initial attempt sample, not an absolute day.
    mov ax, 1
    call RESUME_PREPARE_CLOCK_CALLBACK
    jc resume_prepare_age_failed
    cmp bx, 1
    ja resume_prepare_age_failed
    mov cx, [prepare_attempt_day]
    cmp cx, 1
    ja resume_prepare_age_failed
    add bx, cx
    cmp bx, 1
    ja resume_prepare_age_failed
    mov [prepare_attempt_day], bx
    mov [prepare_page + 8], ax
    mov [prepare_page + 10], dx

    ; Recompute receipt-to-late-sample elapsed ticks.  The initial converter
    ; deliberately left its elapsed tick tuple in attempt_tick; requiring the
    ; new total to be no smaller catches a backwards same-day clock.
    or bx, bx
    jnz .wrapped
    sub ax, [prepare_rsu_receipt_tick_lo]
    sbb dx, [prepare_rsu_receipt_tick_hi]
    jc resume_prepare_age_failed
    jmp short .elapsed
.wrapped:
    mov ax, prepare_bios_ticks_day_lo
    mov dx, prepare_bios_ticks_day_hi
    sub ax, [prepare_rsu_receipt_tick_lo]
    sbb dx, [prepare_rsu_receipt_tick_hi]
    add ax, [prepare_page + 8]
    adc dx, [prepare_page + 10]
.elapsed:
    cmp dx, [prepare_attempt_tick_hi]
    jb resume_prepare_age_failed
    ja .monotonic
    cmp ax, [prepare_attempt_tick_lo]
    jb resume_prepare_age_failed
.monotonic:
    cmp dx, prepare_ticks_max_hi
    ja resume_prepare_age_failed
    jb .bounded
    cmp ax, prepare_ticks_max_lo
    ja resume_prepare_age_failed
.bounded:
    mov [prepare_attempt_tick_lo], ax
    mov [prepare_attempt_tick_hi], dx
    call resume_prepare_age_ticks_to_ms
    mov [prepare_attempt_ms], ax
    mov [prepare_attempt_ms + 2], dx

    ; KeyGen can cross the ticket's expiry boundary.  Recheck strict lifetime
    ; at this late sample before any binder or early ciphertext is built.
    mov bx, 1000
    div bx
    cmp word [prepare_page], 0
    jne .lifetime_ok
    cmp ax, [prepare_page + 2]
    jae resume_prepare_age_failed
.lifetime_ok:
    mov ax, [prepare_page + 4]
    xchg al, ah
    mov bx, [prepare_page + 6]
    xchg bl, bh
    add bx, [prepare_attempt_ms]
    adc ax, [prepare_attempt_ms + 2]
    xchg al, ah
    mov [prepare_attempt_age_wire], ax
    mov [prepare_attempt_cache + 96], ax
    xchg bl, bh
    mov [prepare_attempt_age_wire + 2], bx
    mov [prepare_attempt_cache + 98], bx

    mov ax, RESUME_PREPARE_BINDER_KEY
    mov cx, RESUME_PREPARE_BINDER_BYTES
    jmp prepare_transition

; DX:AX ticks -> DX:AX milliseconds, exact existing fixed-point conversion:
; ticks*55 - ((ticks*611)>>13).
resume_prepare_age_ticks_to_ms:
    mov cx, dx
    mov bx, 55
    mul bx
    mov [prepare_attempt_ms], ax
    mov si, dx
    mov ax, cx
    mul bx
    add si, ax
    mov [prepare_attempt_ms + 2], si
    mov ax, [prepare_attempt_tick_lo]
    mov bx, 611
    mul bx
    mov si, ax
    mov di, dx
    mov ax, [prepare_attempt_tick_hi]
    mul bx
    add di, ax
    mov cx, 13
.shift:
    shr di, 1
    rcr si, 1
    loop .shift
    mov ax, [prepare_attempt_ms]
    mov dx, [prepare_attempt_ms + 2]
    sub ax, si
    sbb dx, di
    ret

resume_prepare_age_failed:
    mov byte [prepare_restore_outcome], 0
    mov ax, RESUME_PREPARE_RESTORE_KEY
    mov bx, 0x3000
    call RESUME_PREPARE_LOAD_PHASE
    jc resume_prepare_age_terminal
    mov dx, 0x3000
    jmp dx
resume_prepare_age_terminal:
    mov dx, RESUME_PREPARE_PERSIST_FAIL
    jmp dx

resume_prepare_age_end:

%if ($ - $$) > 0x0200
%error "PREPARE age continuation exceeds its direct one-sector phase"
%endif

%elifdef RESUME_PREPARE_BINDER

%ifndef RESUME_PREPARE_HELLO_BEGIN
%error "PREPARE binder continuation requires resolved resumed-begin entry"
%endif
%ifndef RESUME_PREPARE_HELLO_NEXT
%error "PREPARE binder continuation requires the HELLO iterator"
%endif
%ifndef RESUME_PREPARE_HELLO_DONE
%error "PREPARE binder continuation requires HELLO fragment commit"
%endif
%ifndef RESUME_PREPARE_HELLO_CLIENT_DIGEST
%error "PREPARE binder continuation requires full-ClientHello digest entry"
%endif
%ifndef RESUME_PREPARE_HELLO_TRUNCATED
%error "PREPARE binder continuation requires resolved HELLO truncated digest"
%endif
%ifndef RESUME_PREPARE_HELLO_BINDER
%error "PREPARE binder continuation requires resolved HELLO binder"
%endif
%ifndef RESUME_PREPARE_SYM_BINDER_KEY
%error "PREPARE binder continuation requires its symmetric-binder phase"
%endif
%ifndef RESUME_PREPARE_SYM_BINDER_BYTES
%error "PREPARE binder continuation requires measured symmetric-binder bytes"
%endif
%if RESUME_PREPARE_SYM_BINDER_BYTES <= 0 || \
    RESUME_PREPARE_SYM_BINDER_BYTES > RESUME_PREPARE_CONT_LIMIT
%error "PREPARE symmetric-binder copy length is outside its high slot"
%endif
%ifndef RESUME_PREPARE_RESTORE_KEY
%error "PREPARE binder continuation requires its fixed restore key"
%endif
%ifndef RESUME_PREPARE_PERSIST_FAIL
%error "PREPARE binder continuation requires the persistent failure service"
%endif

org 0x3400

resume_prepare_binder_entry:
    cld
    prepare_diagnostic_nowait 'd'
    ; The private transition stages this phase at 0x3000, which is also the
    ; HELLO ticket-identity ABI.  Restore the identity only after the exact
    ; copy to 0x3400 has completed.
    mov bx, resume_card_vault_head + resume_vault_head_identity
    mov cx, resume_vault_head_identity_len
    mov di, 0x3000
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_binder_failed
    mov bx, resume_card_vault_tail + resume_vault_tail_identity
    mov cx, resume_vault_tail_identity_len
    mov di, 0x3000 + resume_vault_head_identity_len
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_binder_failed
    call RESUME_PREPARE_HELLO_BEGIN
    jc resume_prepare_binder_failed
    cld
    push ds
    pop es

    ; Preserve the binder inputs before the normal iterator advances over the
    ; complete encoded ClientHello.  Once the pass reaches TX_DONE, entry 14
    ; finalizes the full transcript digest into the former truncated slot.
    mov si, RESUME_PREPARE_HELLO_TRUNCATED
    mov di, 0x0700
    mov cx, 16
    rep movsw
.prehash:
    call RESUME_PREPARE_HELLO_NEXT
    jc resume_prepare_binder_failed
    or ax, ax
    jz .digest
    call RESUME_PREPARE_HELLO_DONE
    jc resume_prepare_binder_failed
    jmp short .prehash
.digest:
    call RESUME_PREPARE_HELLO_CLIENT_DIGEST
    jc resume_prepare_binder_failed
    cld
    push ds
    pop es
    mov si, RESUME_PREPARE_HELLO_TRUNCATED
    mov di, 0x0740
    mov cx, 16
    rep movsw
    ; The HELLO fragment builder uses 0x0736 as its output buffer.  Preserve
    ; the expected binder only after that final pass has retired the overlap.
    mov si, RESUME_PREPARE_HELLO_BINDER
    mov di, 0x0720
    mov cx, 16
    rep movsw
    mov ax, RESUME_PREPARE_SYM_BINDER_KEY
    jmp short resume_prepare_binder_transition

resume_prepare_binder_failed:
    mov byte [prepare_restore_outcome], 0
    mov ax, RESUME_PREPARE_RESTORE_KEY
resume_prepare_binder_transition:
    push ax
    cld
    push ds
    pop es
    mov si, resume_prepare_binder_transition_source
    mov di, prepare_transition
    mov cx, resume_prepare_binder_transition_end - \
        resume_prepare_binder_transition_source
    rep movsb
    pop ax
    mov dx, prepare_transition
    jmp dx

resume_prepare_binder_transition_source:
    mov bx, 0x3000
    push ax
    mov dx, RESUME_PREPARE_LOAD_PHASE
    call dx
    pop ax
    jc resume_prepare_binder_transition_failed_source
    cmp ax, RESUME_PREPARE_RESTORE_KEY
    je .restore_ready
    ; Loading a padded phase directly at 0x3400 erases the immutable
    ; 0x355d..0x35ff persistent-service suffix.  Stage the sector below it
    ; and copy only the measured executable continuation.
    push ds
    pop es
    mov si, 0x3000
    mov di, 0x3400
    mov cx, RESUME_PREPARE_SYM_BINDER_BYTES
    rep movsb
    mov dx, 0x3400
    jmp dx
.restore_ready:
    mov dx, 0x3000
    jmp dx
resume_prepare_binder_transition_failed_source:
    mov dx, RESUME_PREPARE_PERSIST_FAIL
    jmp dx
resume_prepare_binder_transition_end:

resume_prepare_binder_end:

%if ($ - $$) > RESUME_PREPARE_CONT_LIMIT
%error "PREPARE binder continuation reaches symmetric extension work"
%endif

%elifdef RESUME_PREPARE_SYM_BINDER

%ifndef RESUME_PREPARE_SYM_KEY
%error "PREPARE symmetric-binder continuation requires the symmetric phase"
%endif
%ifndef RESUME_PREPARE_SYM_INIT
%error "PREPARE symmetric-binder continuation requires resolved symmetric init"
%endif
%ifndef RESUME_PREPARE_SYM_BINDER_ENTRY
%error "PREPARE symmetric-binder continuation requires resolved binder"
%endif
%ifndef RESUME_PREPARE_SYM_BINDER_HASH
%error "PREPARE symmetric-binder continuation requires binder-hash ABI"
%endif
%ifndef RESUME_PREPARE_SYM_BINDER_VALUE
%error "PREPARE symmetric-binder continuation requires binder output"
%endif
%ifndef RESUME_PREPARE_SYM_IMAGE_BYTES
%error "PREPARE symmetric-binder continuation requires image length"
%endif
%ifndef RESUME_PREPARE_SYM_IMAGE_SECTORS
%error "PREPARE symmetric-binder continuation requires image sector count"
%endif
%ifndef RESUME_PREPARE_SYM_IMAGE_CRC16
%error "PREPARE symmetric-binder continuation requires image CRC-16"
%endif
%ifndef RESUME_PREPARE_EARLY_KEY
%error "PREPARE symmetric-binder continuation requires early-data phase"
%endif
%ifndef RESUME_PREPARE_EARLY_BYTES
%error "PREPARE symmetric-binder continuation requires measured early-data bytes"
%endif
%if RESUME_PREPARE_EARLY_BYTES <= 0 || \
    RESUME_PREPARE_EARLY_BYTES > RESUME_PREPARE_CONT_LIMIT
%error "PREPARE early-data copy length is outside its high slot"
%endif
%ifndef RESUME_PREPARE_RESTORE_KEY
%error "PREPARE symmetric-binder continuation requires its fixed restore key"
%endif
%ifndef RESUME_PREPARE_PERSIST_FAIL
%error "PREPARE symmetric-binder continuation requires persistent failure"
%endif
%if (RESUME_PREPARE_SYM_KEY >> 8) != RESUME_PREPARE_SYM_IMAGE_SECTORS
%error "PREPARE symmetric key count differs from exact image sectors"
%endif

org 0x3400

resume_prepare_sym_binder_entry:
    cld
    ; The original-speed 5150/BIOS path deterministically altered two bytes
    ; when sectors were DMA-read directly into this reused executable window.
    ; Quarantine every read in the retired 0x0d00 transcript page, CPU-copy it
    ; into place, then cover the complete immutable image with CRC-16/IBM.
    mov byte [prepare_sym_retry_count], 3
.load_sym:
    mov dx, RESUME_PREPARE_SYM_KEY
    xor dh, dh
    mov bp, RESUME_PREPARE_SYM_IMAGE_SECTORS
    mov di, 0x1800
.load_sym_sector:
    mov ax, dx
    mov ah, 1
    mov bx, 0x0d00
    push dx
    push di
    push bp
    call RESUME_PREPARE_LOAD_PHASE
    pop bp
    pop di
    pop dx
    jc resume_prepare_sym_binder_retry
    cld
    cmp bp, RESUME_PREPARE_SYM_IMAGE_SECTORS
    jne .copy
.copy:
    push ds
    pop es
    mov si, 0x0d00
    mov cx, 256
    rep movsw
    inc dl
    dec bp
    jnz .load_sym_sector

    mov dx, 0xffff
    mov si, 0x1800
    mov cx, RESUME_PREPARE_SYM_IMAGE_BYTES
.crc_byte:
    lodsb
    xor dl, al
    mov bl, 8
.crc_bit:
    shr dx, 1
    jnc .crc_next
    xor dx, 0xa001
.crc_next:
    dec bl
    jnz .crc_bit
    loop .crc_byte
    cmp dx, RESUME_PREPARE_SYM_IMAGE_CRC16
    je resume_prepare_sym_binder_verified
resume_prepare_sym_binder_retry:
    prepare_diagnostic_nowait 'r'
    dec byte [prepare_sym_retry_count]
    jnz resume_prepare_sym_binder_entry.load_sym
    jmp resume_prepare_sym_binder_failed
resume_prepare_sym_binder_verified:
    mov byte [prepare_sym_retry_count], 0
    prepare_binder_mark 'C'
    prepare_diagnostic_nowait 'v'

    call RESUME_PREPARE_SYM_INIT
    jc resume_prepare_sym_binder_failed
    mov bx, resume_card_vault_head + resume_vault_head_psk
    mov cx, resume_vault_psk_len
    mov di, prepare_native_ticket_psk
    call RESUME_PREPARE_NE_BUF_READ
    jc resume_prepare_sym_binder_failed
    prepare_binder_mark 'P'

    mov si, 0x0700
    mov di, RESUME_PREPARE_SYM_BINDER_HASH
    mov cx, 16
    rep movsw
    call RESUME_PREPARE_SYM_BINDER_ENTRY
    jc resume_prepare_sym_binder_failed
    prepare_binder_mark 'B'
    prepare_diagnostic_nowait 'm'
    mov si, RESUME_PREPARE_SYM_BINDER_VALUE
    mov di, 0x0720
    mov cx, 16
    repe cmpsw
    jne resume_prepare_sym_binder_failed
    prepare_binder_mark 'S'
    mov ax, RESUME_PREPARE_EARLY_KEY
    jmp short resume_prepare_sym_binder_transition

resume_prepare_sym_binder_failed:
    prepare_binder_mark 'F'
    mov byte [prepare_restore_outcome], 0
    mov ax, RESUME_PREPARE_RESTORE_KEY
resume_prepare_sym_binder_transition:
    push ax
    cld
    push ds
    pop es
    mov si, resume_prepare_sym_binder_transition_source
    mov di, prepare_transition
    mov cx, resume_prepare_sym_binder_transition_end - \
        resume_prepare_sym_binder_transition_source
    rep movsb
    pop ax
    mov dx, prepare_transition
    jmp dx

resume_prepare_sym_binder_transition_source:
    mov bx, 0x3000
    push ax
    mov dx, RESUME_PREPARE_LOAD_PHASE
    call dx
    pop ax
    jc resume_prepare_sym_binder_transition_failed_source
    cmp ax, RESUME_PREPARE_RESTORE_KEY
    je .restore_ready
    ; Preserve the same immutable suffix while replacing SYM_BINDER by EARLY.
    push ds
    pop es
    mov si, 0x3000
    mov di, 0x3400
    mov cx, RESUME_PREPARE_EARLY_BYTES
    rep movsb
    mov dx, 0x3400
    jmp dx
.restore_ready:
    mov dx, 0x3000
    jmp dx
resume_prepare_sym_binder_transition_failed_source:
    mov dx, RESUME_PREPARE_PERSIST_FAIL
    jmp dx
resume_prepare_sym_binder_transition_end:

%ifdef RESUME_PREPARE_BINDER_DIAGNOSTIC
prepare_binder_diagnostic_emit:
    push cx
    push dx
    mov ah, al
    mov dx, 0x03fd
    xor cx, cx
.wait:
    in al, dx
    test al, 0x20
    loopz .wait
    mov dl, 0xf8
    mov al, ah
    out dx, al
    pop dx
    pop cx
    ret
%endif

resume_prepare_sym_binder_end:

%if ($ - $$) > RESUME_PREPARE_CONT_LIMIT
%error "PREPARE symmetric-binder continuation reaches extension work"
%endif

%elifdef RESUME_PREPARE_EARLY

%ifndef RESUME_PREPARE_SYM_EARLY_SECRET
%error "PREPARE early continuation requires the retained early secret"
%endif
%ifndef RESUME_PREPARE_SYM_HELLO_HASH
%error "PREPARE early continuation requires the ClientHello hash ABI"
%endif
%ifndef RESUME_PREPARE_SYM_CLIENT_SECRET
%error "PREPARE early continuation requires client-secret output"
%endif
%ifndef RESUME_PREPARE_SYM_PREPARE_SECRET
%error "PREPARE early continuation requires symmetric HMAC preparation"
%endif
%ifndef RESUME_PREPARE_SYM_EXPAND_LABEL
%error "PREPARE early continuation requires HKDF-Expand-Label"
%endif
%ifndef RESUME_PREPARE_SYM_EXPAND_GROUP
%error "PREPARE early continuation requires grouped expansion"
%endif
%ifndef RESUME_PREPARE_SYM_CLIENT_KEY_GROUP
%error "PREPARE early continuation requires client key/IV descriptors"
%endif
%ifndef RESUME_PREPARE_SYM_BUILD_HEAD
%error "PREPARE early continuation requires the fixed HEAD builder"
%endif
%ifndef RESUME_PREPARE_SYM_SEAL_RECORD
%error "PREPARE early continuation requires the fixed record sealer"
%endif
%ifndef RESUME_PREPARE_SYM_EARLY_IO
%error "PREPARE early continuation requires the symmetric I/O buffer"
%endif
%ifndef RESUME_PREPARE_SYM_EARLY_HEAD_HOLD
%error "PREPARE early continuation requires the sealed HEAD holding slot"
%endif
%ifndef RESUME_PREPARE_SYM_LABEL_PTR
%error "PREPARE early continuation requires expand-label pointer ABI"
%endif
%ifndef RESUME_PREPARE_SYM_LABEL_LEN
%error "PREPARE early continuation requires expand-label length ABI"
%endif
%ifndef RESUME_PREPARE_SYM_CONTEXT_PTR
%error "PREPARE early continuation requires expand-context pointer ABI"
%endif
%ifndef RESUME_PREPARE_SYM_CONTEXT_LEN
%error "PREPARE early continuation requires expand-context length ABI"
%endif
%ifndef RESUME_PREPARE_SYM_OUTPUT_PTR
%error "PREPARE early continuation requires expand-output pointer ABI"
%endif
%ifndef RESUME_PREPARE_SYM_OUTPUT_LEN
%error "PREPARE early continuation requires expand-output length ABI"
%endif
%ifndef RESUME_PREPARE_RESTORE_KEY
%error "PREPARE early continuation requires its fixed restore key"
%endif
%ifndef RESUME_PREPARE_PERSIST_FAIL
%error "PREPARE early continuation requires persistent failure"
%endif

org 0x3400

resume_prepare_early_entry:
    cld
    push ds
    pop es
    mov si, 0x0740
    mov di, RESUME_PREPARE_SYM_HELLO_HASH
    mov cx, 16
    rep movsw

    ; client_early_traffic_secret =
    ; Derive-Secret(Early Secret, "c e traffic", Hash(ClientHello)).
    mov si, RESUME_PREPARE_SYM_EARLY_SECRET
    call RESUME_PREPARE_SYM_PREPARE_SECRET
    jc resume_prepare_early_failed
    mov word [RESUME_PREPARE_SYM_LABEL_PTR], \
        resume_prepare_early_label
    mov word [RESUME_PREPARE_SYM_LABEL_LEN], \
        resume_prepare_early_label_len
    mov word [RESUME_PREPARE_SYM_CONTEXT_PTR], \
        RESUME_PREPARE_SYM_HELLO_HASH
    mov word [RESUME_PREPARE_SYM_CONTEXT_LEN], 32
    mov word [RESUME_PREPARE_SYM_OUTPUT_PTR], \
        RESUME_PREPARE_SYM_CLIENT_SECRET
    mov word [RESUME_PREPARE_SYM_OUTPUT_LEN], 32
    call RESUME_PREPARE_SYM_EXPAND_LABEL
    jc resume_prepare_early_failed

    ; Reuse the symmetric overlay's client key/IV descriptor pair and fixed
    ; public HEAD sealer.  This state is volatile; RESTORE persists only two
    ; authenticated copies of the resulting 72-byte record.
    mov si, RESUME_PREPARE_SYM_CLIENT_SECRET
    call RESUME_PREPARE_SYM_PREPARE_SECRET
    jc resume_prepare_early_failed
    mov si, RESUME_PREPARE_SYM_CLIENT_KEY_GROUP
    mov cx, 2
    call RESUME_PREPARE_SYM_EXPAND_GROUP
    jc resume_prepare_early_failed
    call RESUME_PREPARE_SYM_BUILD_HEAD
    jc resume_prepare_early_failed
    cmp ax, resume_early_head_len
    jne resume_prepare_early_failed
    cld
    push ds
    pop es
    mov si, RESUME_PREPARE_SYM_EARLY_IO
    mov di, RESUME_PREPARE_SYM_EARLY_HEAD_HOLD
    mov cx, resume_early_head_len / 2
    rep movsw

    ; EndOfEarlyData is the next record under client_early_traffic_secret
    ; (sequence 1 after HEAD).  Pre-seal it outside the live deadline; RSI1
    ; later appends the four plaintext handshake bytes to the transcript and
    ; sends this exact 26-byte record before client Finished.
    mov si, resume_prepare_early_eoed_message
    mov cx, 4
    mov al, 0x16
    call RESUME_PREPARE_SYM_SEAL_RECORD
    jc resume_prepare_early_failed
    cmp ax, resume_early_eoed_len
    jne resume_prepare_early_failed
    prepare_binder_mark 's'
    mov byte [prepare_restore_outcome], 1
    mov ax, RESUME_PREPARE_RESTORE_KEY
    jmp short resume_prepare_early_transition

resume_prepare_early_failed:
    prepare_binder_mark 'f'
    mov byte [prepare_restore_outcome], 0
    mov ax, RESUME_PREPARE_RESTORE_KEY
resume_prepare_early_transition:
    push ax
    cld
    push ds
    pop es
    mov si, resume_prepare_early_transition_source
    mov di, prepare_transition
    mov cx, resume_prepare_early_transition_end - \
        resume_prepare_early_transition_source
    rep movsb
    pop ax
    mov dx, prepare_transition
    jmp dx

resume_prepare_early_transition_source:
    mov bx, 0x3000
    mov dx, RESUME_PREPARE_LOAD_PHASE
    call dx
    jc resume_prepare_early_transition_failed_source
    mov dx, 0x3000
    jmp dx
resume_prepare_early_transition_failed_source:
    mov dx, RESUME_PREPARE_PERSIST_FAIL
    jmp dx
resume_prepare_early_transition_end:

%ifdef RESUME_PREPARE_BINDER_DIAGNOSTIC
prepare_binder_diagnostic_emit:
    push cx
    push dx
    mov ah, al
    mov dx, 0x03fd
    xor cx, cx
.wait:
    in al, dx
    test al, 0x20
    loopz .wait
    mov dl, 0xf8
    mov al, ah
    out dx, al
    pop dx
    pop cx
    ret
%endif

resume_prepare_early_label db 'c e traffic'
resume_prepare_early_label_len equ $ - resume_prepare_early_label
resume_prepare_early_eoed_message db 0x05,0x00,0x00,0x00
resume_prepare_early_end:

%if ($ - $$) > RESUME_PREPARE_CONT_LIMIT
%error "PREPARE early continuation reaches symmetric extension work"
%endif

%elifdef RESUME_PREPARE_RESTORE

%ifndef RESUME_PREPARE_CONTROLLER_HEAD_KEY
%error "PREPARE restore requires the fixed RSU1 head-sector key"
%endif
%ifndef RESUME_PREPARE_CONTROLLER_TAIL_KEY
%error "PREPARE restore requires the fixed RSU1 tail-sector key"
%endif
%ifndef RESUME_PREPARE_CONTROLLER_LOW_START
%error "PREPARE restore requires the RSU1 low start"
%endif
%ifndef RESUME_PREPARE_CONTROLLER_LOW_BYTES
%error "PREPARE restore requires the RSU1 low byte count"
%endif
%ifndef RESUME_PREPARE_CONTROLLER_PREFIX_START
%error "PREPARE restore requires the RSU1 prefix start"
%endif
%ifndef RESUME_PREPARE_CONTROLLER_PREFIX_BYTES
%error "PREPARE restore requires the RSU1 prefix byte count"
%endif
%ifndef RESUME_PREPARE_CONTROLLER_SUFFIX_START
%error "PREPARE restore requires the RSU1 suffix start"
%endif
%ifndef RESUME_PREPARE_CONTROLLER_SUFFIX_BYTES
%error "PREPARE restore requires the RSU1 suffix byte count"
%endif
%ifndef RESUME_PREPARE_PERSIST_FAIL
%error "PREPARE restore requires the persistent failure service"
%endif
%ifndef RESUME_PREPARE_SYM_EARLY_DERIVED
%error "PREPARE restore requires the symmetric early-derived ABI"
%endif
%ifndef RESUME_PREPARE_SYM_EARLY_HEAD_HOLD
%error "PREPARE restore requires the sealed early HEAD holding ABI"
%endif
%ifndef RESUME_PREPARE_SYM_EARLY_EOED
%error "PREPARE restore requires the sealed EndOfEarlyData ABI"
%endif

prepare_restore_stage          equ 0x0d00
prepare_restore_head_bytes     equ 0x0200
prepare_restore_low_tail_bytes equ \
    RESUME_PREPARE_CONTROLLER_LOW_BYTES - prepare_restore_head_bytes

%if RESUME_PREPARE_CONTROLLER_LOW_BYTES < prepare_restore_head_bytes
%error "PREPARE restore RSU1 low span is shorter than its head sector"
%endif
%if RESUME_PREPARE_CONTROLLER_LOW_START + \
    RESUME_PREPARE_CONTROLLER_LOW_BYTES > prepare_restore_stage
%error "PREPARE restore RSU1 low span reaches its staging page"
%endif
%if RESUME_PREPARE_CONTROLLER_PREFIX_START + \
    RESUME_PREPARE_CONTROLLER_PREFIX_BYTES > prepare_restore_stage
%error "PREPARE restore RSU1 prefix reaches its staging page"
%endif
%if RESUME_PREPARE_CONTROLLER_SUFFIX_START + \
    RESUME_PREPARE_CONTROLLER_SUFFIX_BYTES > prepare_restore_stage
%error "PREPARE restore RSU1 suffix reaches its staging page"
%endif
%if prepare_restore_low_tail_bytes + \
    RESUME_PREPARE_CONTROLLER_PREFIX_BYTES + \
    RESUME_PREPARE_CONTROLLER_SUFFIX_BYTES > 0x0200
%error "PREPARE restore RSU1 tail scatter exceeds one file sector"
%endif

org 0x3000

resume_prepare_restore_entry:
    cld
    xor ax, ax
    cmp byte [prepare_restore_outcome], 1
    jne .outcome_saved
    inc ax
.outcome_saved:
    push ax
    push ds
    pop es

    ; Always retire the temporarily restored PSK and low digest/transition
    ; page.  On success, replace the consumed entropy page with the one
    ; verified early-derived secret needed after the cached reconnect.  The
    ; connector legitimately destroys the live symmetric high state, so this
    ; volatile card publication is the only copy that crosses it.  On
    ; rejection, also retire fresh ek and all host private/symmetric state
    ; before any controller byte becomes executable again.
    xor ax, ax
    mov di, prepare_native_ticket_psk
    mov cx, resume_vault_psk_len
    rep stosb
    mov di, 0x0700
    mov cx, 128
    rep stosw
    pop dx
    push dx
    or dx, dx
    jnz .publish_early_derived
.wipe_failed_attempt:
    xor ax, ax
    mov di, 0x0700
    mov cx, 256
    rep stosw
    mov di, 0x08c0
    mov cx, resume_card_ek_len
    rep stosb
    mov di, 0x3600
    mov cx, resume_card_private_len
    rep stosb
    jmp .restore_controller

.publish_early_derived:
    mov si, RESUME_PREPARE_SYM_EARLY_DERIVED
    mov di, 0x0700 + resume_early_copy_a
    mov cx, 16
    rep movsw
    mov si, RESUME_PREPARE_SYM_EARLY_DERIVED
    mov di, 0x0700 + resume_early_copy_b
    mov cx, 16
    rep movsw
    mov si, RESUME_PREPARE_SYM_EARLY_HEAD_HOLD
    mov di, 0x0700 + resume_early_head_a
    mov cx, resume_early_head_len / 2
    rep movsw
    mov si, RESUME_PREPARE_SYM_EARLY_HEAD_HOLD
    mov di, 0x0700 + resume_early_head_b
    mov cx, resume_early_head_len / 2
    rep movsw
    mov si, RESUME_PREPARE_SYM_EARLY_EOED
    mov di, 0x0700 + resume_early_eoed
    mov cx, resume_early_eoed_len / 2
    rep movsw
    mov word [0x0700 + resume_early_magic], \
        resume_early_magic_word0
    mov word [0x0700 + resume_early_magic + 2], \
        resume_early_magic_word1
    mov ax, [resume_vault_lifecycle_generation]
    mov [0x0700 + resume_early_generation], ax
    not ax
    mov [0x0700 + resume_early_inverse_generation], ax

    ; Verify an invalid-status image first.  Then publish the valid pair and
    ; verify the complete status-last page a second time.  No partial/stale
    ; DMA can become an importable early-secret object.
    mov al, 0x7e
    mov si, 0x0700
    mov bp, 256
    call resume_prepare_restore_card_write
    jc .early_publication_failed
    call resume_prepare_restore_verify_early
    jc .early_publication_failed
    mov byte [0x0700 + resume_early_inverse_status], \
        resume_early_status_valid_inverse
    mov byte [0x0700 + resume_early_status], \
        resume_early_status_valid
    mov al, 0x7e
    mov si, 0x0700
    mov bp, 256
    call resume_prepare_restore_card_write
    jc .early_publication_failed
    call resume_prepare_restore_verify_early
    jc .early_publication_failed

    ; The sealed records are now the only live outputs.  Retire the complete
    ; symmetric/native-ticket workspace, including the binder, early traffic
    ; secret, derived key/IV, record sequence, and ticket-present byte.
    xor ax, ax
    mov di, prepare_native_issuer
    mov cx, (0x3c2e - prepare_native_issuer) / 2
    rep stosw
    mov di, 0x0700
    mov cx, 256
    rep stosw
    jmp short .restore_controller
.early_publication_failed:
    pop dx
    xor dx, dx
    push dx
    jmp .wipe_failed_attempt

.restore_controller:
    ; The second RSU1 file sector is low-tail||prefix||suffix.  Scatter it
    ; exactly as the supervisor did, then load the first sector directly.
    mov ax, RESUME_PREPARE_CONTROLLER_TAIL_KEY
    mov bx, prepare_restore_stage
    call RESUME_PREPARE_LOAD_PHASE
    jc resume_prepare_restore_terminal
    mov si, prepare_restore_stage
    mov di, RESUME_PREPARE_CONTROLLER_LOW_START + \
        prepare_restore_head_bytes
    mov cx, prepare_restore_low_tail_bytes
    rep movsb
    mov si, prepare_restore_stage + prepare_restore_low_tail_bytes
    mov di, RESUME_PREPARE_CONTROLLER_PREFIX_START
    mov cx, RESUME_PREPARE_CONTROLLER_PREFIX_BYTES
    rep movsb
    mov si, prepare_restore_stage + prepare_restore_low_tail_bytes + \
        RESUME_PREPARE_CONTROLLER_PREFIX_BYTES
    mov di, RESUME_PREPARE_CONTROLLER_SUFFIX_START
    mov cx, RESUME_PREPARE_CONTROLLER_SUFFIX_BYTES
    rep movsb
    mov ax, RESUME_PREPARE_CONTROLLER_HEAD_KEY
    mov bx, RESUME_PREPARE_CONTROLLER_LOW_START
    call RESUME_PREPARE_LOAD_PHASE
    jc resume_prepare_restore_terminal

    ; The tail sector was immutable code, but the staging copy is not part of
    ; the live controller and remains zero on both return outcomes.
    xor ax, ax
    mov di, prepare_restore_stage
    mov cx, 256
    rep stosw
    pop dx
    pop es
    or dx, dx
    jz .failed
    prepare_diagnostic 'S'
    mov ax, 1
    clc
    ret
.failed:
    prepare_diagnostic 'F'
    xor ax, ax
    stc
    ret

resume_prepare_restore_card_write:
    xor bx, bx
    mov bl, [RESUME_PREPARE_NE_TX_START]
    push bx
    mov [RESUME_PREPARE_NE_TX_START], al
    mov bx, [RESUME_PREPARE_NIC_BASE]
    call RESUME_PREPARE_NE_BUF_LOAD
    pop bx
    mov [RESUME_PREPARE_NE_TX_START], bl
    ret

resume_prepare_restore_verify_early:
    mov bx, resume_card_candidate_a
    mov cx, 256
    mov di, 0x0800
    call RESUME_PREPARE_NE_BUF_READ
    jc .done
    mov si, 0x0700
    mov di, 0x0800
    mov cx, 128
    repe cmpsw
    jne .different
    clc
.done:
    ret
.different:
    stc
    ret

resume_prepare_restore_terminal:
    mov dx, RESUME_PREPARE_PERSIST_FAIL
    jmp dx

resume_prepare_restore_end:

%if ($ - $$) > 0x0400
%error "PREPARE restore exceeds the direct-worker slot"
%endif

%else
%error "select one RESUME_PREPARE phase"
%endif
