; TLS 1.3 286 acquisition and final PSK-DHE resumption HELLO controller.
;
; This is an independent product image.  It intentionally does not derive
; from the K14 research HELLO overlay.  The 286 tier has a bounded same-boot
; PSK-DHE resumption surface, but no 0-RTT or compressed-certificate surface.
;
; Root handoff for entry 0:
;   BX=paragraph-aligned 64 KiB crypto reservation
;   SI=frozen product-tail footer offset
;   DS=ES=SS=0, DF=0
;
; Entry 0 transitions the acquisition bundle READY -> USED status-last before
; reading any private byte, invokes the authenticated ML-KEM-768 keygen and
; X25519 modules, wipes the consumed bundle, and initializes one exact
; X25519MLKEM768 ClientHello.  The fragment iterator owns retransmission:
; returning a fragment does not imply it reached TCP, and the same bytes remain
; pending until entry 2 acknowledges them.
;
; Entry 11 is the final credential-bearing connection.  It accepts only an
; authenticated, promoted same-boot ticket, consumes that ticket status-last
; before reading its PSK or identity, consumes the independent attempt bundle,
; computes a no-0RTT PSK-DHE binder, and finishes genuine ML-KEM/X25519 key
; generation before opening TCP.

bits 16
cpu 8086
org 0x1800

%include "tls13/tls13_286_abi.inc"
%include "tls13-286-runtime-abi.inc"
%include "tls13-286-flight-component-abi.inc"

sha256_digest_len             equ 32
sha256_block_size             equ 64
sha256_k_len                  equ 256

hello_mss_max                 equ 384
hello_message_len             equ 1384
hello_body_len                equ hello_message_len - 4
hello_extensions_len          equ 0x0519
hello_resumption_delta        equ 47
hello_prefix_fragment_len     equ 140
hello_fragment_count          equ 6
hello_server_len              equ 1210
hello_resumed_server_len      equ 1216
hello_mode_acquire            equ 0
hello_mode_resume             equ 1
hello_ticket_age_ticks_max    equ 0x2ab0 ; bounded to about ten minutes
hello_bios_ticks_day_hi       equ 0x0018
hello_bios_ticks_day_lo       equ 0x00b0
; tcp_send_payload constructs the Ethernet frame at 0x0700, so a generated
; prefix/tail must never also originate there.  By send time the asymmetric
; module has been wiped; its 0x4230 overlay is safe transient TX staging.
hello_tx_work                 equ tls13_286_module_load

hello_phase_idle              equ 0
hello_phase_tx                equ 1
hello_phase_tx_done           equ 2
hello_phase_rx                equ 3
hello_phase_complete          equ 4
hello_phase_failed            equ 5

hello_header:
    db 'S286HL02'
    dw tls13_286_abi_version
    dw hello_image_end - hello_header
    dw tls13_286_hello_entries
hello_entry_table:
    dw hello_live_acquire
    dw hello_live_fresh

; ---------------------------------------------------------------------------
; Entropy-bundle consumption and product asymmetric modules
; ---------------------------------------------------------------------------

hello_prelude:
    cmp si, tls13_286_tail_footer_off
    jne .bad
    cmp bx, [cs:tls13_286_root_state_crypto_seg]
    jne .bad

    call hello_install_abort_capsule
    call hello_clear_work
    mov [cs:hello_crypto_seg], bx
    mov es, bx
    mov word [es:tls13_286_pending_wire_status_inv_off], 0
    mov word [es:tls13_286_pending_wire_len_off], 0
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    stc
    ret

hello_prepare_crypto:
    mov word [cs:hello_attempt_off], tls13_286_attempt_acquire_off
    mov byte [cs:hello_mode], hello_mode_acquire
    mov word [cs:hello_wire_message_len], hello_message_len
    mov word [cs:hello_wire_extensions_len], hello_extensions_len
    mov word [cs:hello_wire_tail_len], hello_tail_len
    call hello_clear_candidate_escrow
    call hello_consume_acquire
    jmp short hello_prepare_selected

hello_prepare_resume_crypto:
    mov word [cs:hello_attempt_off], tls13_286_attempt_fresh_off
    mov byte [cs:hello_mode], hello_mode_resume
    call hello_consume_resume_ticket
    jc hello_prepare_failed
    call hello_consume_fresh
hello_prepare_selected:
    jc hello_prepare_failed
    call hello_copy_attempt_inputs
    jc hello_prepare_failed
    call hello_mlkem_keygen
    jc hello_prepare_failed
    call hello_x25519_keygen
    jc hello_prepare_failed
    call hello_capture_client_x
    jc hello_prepare_failed
    call hello_wipe_acquire_bundle
    cmp byte [cs:hello_mode], hello_mode_resume
    jne .transcript
    ; Matrix generation is public, connection-independent work.  Complete it
    ; before sampling ticket age so the encoded age remains a near-send value
    ; rather than excluding several seconds of target-side computation.
    call hello_mlkem_matrix_precompute
    jc hello_prepare_failed
    call hello_prepare_ticket_age
    jc hello_prepare_failed
    call hello_make_binder
    jc hello_prepare_failed

.transcript:
    call sha256_init
    mov byte [hello_phase], hello_phase_tx
    mov byte [hello_hash_enabled], 1
    mov byte [tls13_286_hello_status_off], 0
    xor ax, ax
    clc
    ret
hello_prepare_failed:
    stc
    ret

; Require completed offline authentication and consume a promoted ticket
; before any private PSK/identity byte can be read.  Status is cleared first,
; inverse is written next, and USED is the final publication.
hello_consume_resume_ticket:
    mov es, [cs:hello_crypto_seg]
    cmp word [es:tls13_286_auth_status_inv_off], \
        (tls13_286_flight_status_valid << 8) | \
        tls13_286_flight_status_inverse
    jne .bad
    cmp word [es:tls13_286_ticket_status_inv_off], \
        (tls13_286_ticket_status_promoted << 8) | \
        tls13_286_ticket_status_promoted_inv
    jne .bad
    mov byte [es:tls13_286_ticket_status_off], 0
    mov byte [es:tls13_286_ticket_status_inv_off], \
        tls13_286_ticket_status_used_inv
    mov byte [es:tls13_286_ticket_status_off], \
        tls13_286_ticket_status_used
    cmp word [es:tls13_286_ticket_status_inv_off], \
        (tls13_286_ticket_status_used << 8) | \
        tls13_286_ticket_status_used_inv
    jne .bad
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

; The source component is authenticated by the root loader.  Copy its
; dedicated fixed-origin failure continuation before any check can branch to
; hello_abort; later frame/public-object traffic may freely overwrite 0700.
hello_install_abort_capsule:
    push cs
    pop es
    mov si, hello_abort_capsule_blob
    mov di, tls13_286_abort_capsule_load
    mov cx, hello_abort_capsule_blob_bytes
    rep movsb
    ; Freeze the bootstrap-validated conventional reservation inside the
    ; independently authenticated capsule.  Segment is written first and the
    ; inverse last; cleanup also has the separate root-state copy, so any one
    ; torn/corrupt geometry word remains recoverable without rereading BDA.
    mov [es:tls13_286_abort_capsule_crypto_seg], bx
    mov ax, bx
    not ax
    mov [es:tls13_286_abort_capsule_crypto_seg_inverse], ax
    ret

; Status-last consume.  Clearing the status first makes interruption at every
; intermediate write fail closed; private bytes are not touched until the
; final USED status has been stored and rechecked.
hello_consume_acquire:
    mov es, [cs:hello_crypto_seg]
    cmp word [es:tls13_286_entropy_root_status_inv_off], \
        (tls13_286_entropy_status_ready << 8) | \
        tls13_286_entropy_status_ready_inv
    jne .bad
    cmp word [es:tls13_286_attempt_acquire_status_inv_off], \
        (tls13_286_entropy_status_ready << 8) | \
        tls13_286_entropy_status_ready_inv
    jne .bad
    cmp word [es:tls13_286_attempt_fresh_status_inv_off], \
        (tls13_286_entropy_status_ready << 8) | \
        tls13_286_entropy_status_ready_inv
    jne .bad
    mov byte [es:tls13_286_attempt_acquire_status_off], 0
    mov byte [es:tls13_286_attempt_acquire_status_inv_off], \
        tls13_286_entropy_status_used_inv
    mov byte [es:tls13_286_attempt_acquire_status_off], \
        tls13_286_entropy_status_used
    cmp word [es:tls13_286_attempt_acquire_status_inv_off], \
        (tls13_286_entropy_status_used << 8) | \
        tls13_286_entropy_status_used_inv
    jne .bad
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

; The second connection consumes a separately generated attempt.  The first
; bundle bytes have already been wiped, while its durable USED ledger remains;
; accepting READY there would permit a replay of the acquisition key material.
hello_consume_fresh:
    mov es, [cs:hello_crypto_seg]
    cmp word [es:tls13_286_entropy_root_status_inv_off], \
        (tls13_286_entropy_status_ready << 8) | \
        tls13_286_entropy_status_ready_inv
    jne .bad
    cmp word [es:tls13_286_attempt_acquire_status_inv_off], \
        (tls13_286_entropy_status_used << 8) | \
        tls13_286_entropy_status_used_inv
    jne .bad
    cmp word [es:tls13_286_attempt_fresh_status_inv_off], \
        (tls13_286_entropy_status_ready << 8) | \
        tls13_286_entropy_status_ready_inv
    jne .bad
    mov byte [es:tls13_286_attempt_fresh_status_off], 0
    mov byte [es:tls13_286_attempt_fresh_status_inv_off], \
        tls13_286_entropy_status_used_inv
    mov byte [es:tls13_286_attempt_fresh_status_off], \
        tls13_286_entropy_status_used
    cmp word [es:tls13_286_attempt_fresh_status_inv_off], \
        (tls13_286_entropy_status_used << 8) | \
        tls13_286_entropy_status_used_inv
    jne .bad
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

; Convert the authenticated same-boot ticket receipt into the uint32
; obfuscated_ticket_age.  The BIOS tick counter may cross midnight once; the
; final route is deliberately bounded to roughly ten minutes, so a larger or
; ambiguous interval fails closed.
hello_prepare_ticket_age:
    mov es, [cs:hello_crypto_seg]
    cmp word [es:tls13_286_ticket_status_inv_off], \
        (tls13_286_ticket_status_used << 8) | \
        tls13_286_ticket_status_used_inv
    jne .bad
    mov ax, [es:tls13_286_ticket_identity_len_off]
    or ax, ax
    jz .bad
    cmp ax, tls13_286_ticket_identity_max
    ja .bad
    mov [cs:hello_ticket_len_snapshot], ax
    mov ax, [es:tls13_286_ticket_nonce_len_off]
    or ax, ax
    jz .bad
    cmp ax, tls13_286_ticket_nonce_max
    ja .bad
    mov ax, [es:tls13_286_ticket_lifetime_hi_off]
    mov dx, [es:tls13_286_ticket_lifetime_lo_off]
    mov bx, ax
    or bx, dx
    jz .bad
    cmp ax, 9
    ja .bad
    jb .ticket_shape_ok
    cmp dx, 0x3a80
    ja .bad
.ticket_shape_ok:
    xor ax, ax
    mov es, ax

    mov ah, 0
    int 0x1a
    mov [cs:hello_tick_current_lo], dx
    mov [cs:hello_tick_current_hi], cx
    mov [cs:hello_tick_rollover], al

    mov es, [cs:hello_crypto_seg]
    mov ax, [cs:hello_tick_current_lo]
    mov dx, [cs:hello_tick_current_hi]
    cmp dx, [es:tls13_286_ticket_receipt_tick_hi_off]
    jb .wrapped
    ja .same_day
    cmp ax, [es:tls13_286_ticket_receipt_tick_lo_off]
    jb .wrapped
.same_day:
    cmp byte [cs:hello_tick_rollover], 0
    jne .bad
    sub ax, [es:tls13_286_ticket_receipt_tick_lo_off]
    sbb dx, [es:tls13_286_ticket_receipt_tick_hi_off]
    jmp short .elapsed
.wrapped:
    cmp byte [cs:hello_tick_rollover], 1
    jne .bad
    mov ax, hello_bios_ticks_day_lo
    mov dx, hello_bios_ticks_day_hi
    sub ax, [es:tls13_286_ticket_receipt_tick_lo_off]
    sbb dx, [es:tls13_286_ticket_receipt_tick_hi_off]
    add ax, [cs:hello_tick_current_lo]
    adc dx, [cs:hello_tick_current_hi]
.elapsed:
    or dx, dx
    jnz .bad
    cmp ax, hello_ticket_age_ticks_max
    ja .bad
    mov [cs:hello_elapsed_ticks], ax
    call hello_ticks_to_ms
    mov [cs:hello_elapsed_ms], ax
    mov [cs:hello_elapsed_ms + 2], dx

    ; Require elapsed whole seconds to remain strictly below ticket_lifetime.
    cmp word [es:tls13_286_ticket_lifetime_hi_off], 0
    jne .lifetime_ok
    mov bx, 1000
    div bx
    cmp ax, [es:tls13_286_ticket_lifetime_lo_off]
    jae .bad
.lifetime_ok:
    ; age_add is retained in its original network byte order.
    mov ax, [es:tls13_286_ticket_age_add_off]
    xchg al, ah
    mov bx, [es:tls13_286_ticket_age_add_off + 2]
    xchg bl, bh
    add bx, [cs:hello_elapsed_ms]
    adc ax, [cs:hello_elapsed_ms + 2]
    xchg al, ah
    mov [cs:hello_ticket_age], ax
    xchg bl, bh
    mov [cs:hello_ticket_age + 2], bx

    ; Full encoded lengths include the final binders vector.  The binder hash
    ; itself stops immediately before that vector.
    mov ax, [cs:hello_ticket_len_snapshot]
    add ax, hello_message_len + hello_resumption_delta
    mov [cs:hello_wire_message_len], ax
    mov ax, [cs:hello_ticket_len_snapshot]
    add ax, hello_extensions_len + hello_resumption_delta
    mov [cs:hello_wire_extensions_len], ax
    mov ax, [cs:hello_ticket_len_snapshot]
    add ax, hello_tail_len + hello_resumption_delta
    mov [cs:hello_wire_tail_len], ax
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

; AX=elapsed ticks (bounded above), return DX:AX milliseconds:
; ticks*55 - ((ticks*611)>>13).
hello_ticks_to_ms:
    mov bx, 55
    mul bx
    mov si, ax
    mov di, dx
    mov ax, [cs:hello_elapsed_ticks]
    mov bx, 611
    mul bx
    mov cx, 13
.shift:
    shr dx, 1
    rcr ax, 1
    loop .shift
    mov bx, ax
    mov ax, si
    mov dx, di
    sub ax, bx
    sbb dx, 0
    ret

hello_copy_attempt_inputs:
    push ds
    push es
    mov ax, [cs:hello_crypto_seg]
    mov ds, ax
    xor ax, ax
    mov es, ax
    mov si, [cs:hello_attempt_off]
    add si, tls13_286_attempt_random_off
    mov di, hello_random
    mov cx, 32
    rep movsb
    mov si, [cs:hello_attempt_off]
    add si, tls13_286_attempt_session_id_off
    mov di, hello_session
    mov cx, 32
    rep movsb
    mov ax, ds
    mov es, ax
    mov si, [cs:hello_attempt_off]
    add si, tls13_286_attempt_x_scalar_off
    mov di, tls13_286_x25519_scalar_off
    mov cx, tls13_286_x25519_scalar_bytes
    rep movsb
    pop es
    pop ds
    cld
    clc
    ret

hello_mlkem_keygen:
    call hello_clear_desc
    mov word [hello_desc + tls13_286_desc_op], \
        tls13_286_mod_op_mlkem_keygen
    mov di, hello_desc + tls13_286_desc_input0
    mov ax, [cs:hello_attempt_off]
    add ax, tls13_286_attempt_d_off
    mov dx, 64
    call hello_set_high_span
    mov di, hello_desc + tls13_286_desc_output0
    mov ax, tls13_286_hello_mlkem_ek_off
    mov dx, tls13_286_hello_mlkem_ek_bytes
    call hello_set_low_span
    mov di, hello_desc + tls13_286_desc_output1
    mov ax, tls13_286_mlkem_dk_off
    mov dx, tls13_286_mlkem_dk_bytes
    call hello_set_high_span

    mov ax, tls13_286_mod_kind_mlkem_keygen
    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc .done
    mov ax, tls13_286_mod_op_mlkem_keygen
    mov bx, tls13_286_root_state_loader
    mov si, hello_desc
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
.done:
    ret

hello_x25519_keygen:
    call hello_clear_desc
    mov word [hello_desc + tls13_286_desc_op], \
        tls13_286_mod_op_x25519_keygen
    mov di, hello_desc + tls13_286_desc_input0
    mov ax, tls13_286_x25519_scalar_off
    mov dx, tls13_286_x25519_scalar_bytes
    call hello_set_high_span
    mov di, hello_desc + tls13_286_desc_output0
    mov ax, tls13_286_client_x_public
    mov dx, tls13_286_client_x_public_bytes
    call hello_set_low_span

    mov ax, tls13_286_mod_kind_x25519
    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc .done
    mov ax, tls13_286_mod_op_x25519_keygen
    mov bx, tls13_286_root_state_loader
    mov si, hello_desc
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
.done:
    ret

; Generate the final attempt's public A^T matrix from the freshly generated
; ML-KEM dk/ek before TCP.  The module writes every one of the nine exact NTT
; polynomials before READY is published; the post-ServerHello cached decap
; consumes READY before it may read any cache byte.
hello_mlkem_matrix_precompute:
    mov es, [cs:hello_crypto_seg]
    mov word [es:tls13_286_mlkem_matrix_status_inv_off], 0
    xor ax, ax
    mov es, ax
    call hello_clear_desc
    mov word [hello_desc + tls13_286_desc_op], \
        tls13_286_mod_op_mlkem_matrix_precompute
    mov di, hello_desc + tls13_286_desc_input0
    mov ax, tls13_286_mlkem_dk_off
    mov dx, tls13_286_mlkem_dk_bytes
    call hello_set_high_span
    mov di, hello_desc + tls13_286_desc_output0
    mov ax, tls13_286_mlkem_matrix_stage_off
    mov dx, tls13_286_mlkem_matrix_stage_bytes
    call hello_set_high_span

    mov ax, tls13_286_mod_kind_mlkem_decap
    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc .done
    mov ax, tls13_286_mod_op_mlkem_matrix_precompute
    mov bx, tls13_286_root_state_loader
    mov si, hello_desc
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
    jc .done
    mov es, [cs:hello_crypto_seg]
    mov byte [es:tls13_286_mlkem_matrix_status_inv_off], \
        tls13_286_mlkem_matrix_status_inverse
    mov byte [es:tls13_286_mlkem_matrix_status_off], \
        tls13_286_mlkem_matrix_status_valid
    xor ax, ax
    mov es, ax
.done:
    ret

; Derive the real IANA X25519MLKEM768 shared secret after the complete
; ServerHello has been accepted.  The first half is ML-KEM-768 decapsulation;
; the second half is X25519.  Both outputs land only in the private high
; reservation and the product modules fail closed on malformed descriptors or
; an all-zero X25519 result.
hello_hybrid_cached:
    mov word [cs:hello_mlkem_operation], \
        tls13_286_mod_op_mlkem_decap_cached
    jmp short hello_hybrid_selected

; The acquisition socket has a provider deadline, so compute the real
; decrypt-derived K' but defer FO re-encryption/selection until the socket is
; no longer live.  The exact c, dk, and K' remain quarantined for that offline
; equivalence check; no credential-bearing application data is permitted on
; this provisional result.
hello_hybrid_candidate:
    mov word [cs:hello_mlkem_operation], tls13_286_mod_op_mlkem_candidate

hello_hybrid_selected:
    cld
    cmp byte [hello_phase], hello_phase_complete
    jne hello_reject
    cmp byte [tls13_286_hello_status_off], 1
    jne hello_reject

    call hello_clear_desc
    mov ax, [cs:hello_mlkem_operation]
    mov word [hello_desc + tls13_286_desc_op], ax
    mov di, hello_desc + tls13_286_desc_input0
    mov ax, tls13_286_mlkem_dk_off
    mov dx, tls13_286_mlkem_dk_bytes
    call hello_set_high_span
    mov di, hello_desc + tls13_286_desc_input1
    mov ax, tls13_286_hello_ciphertext_off
    mov dx, tls13_286_hello_ciphertext_bytes
    call hello_set_low_span
    mov di, hello_desc + tls13_286_desc_output0
    mov ax, tls13_286_hybrid_secret_off
    mov dx, 32
    call hello_set_high_span
    cmp word [cs:hello_mlkem_operation], \
        tls13_286_mod_op_mlkem_decap_cached
    jne .module
    call hello_consume_mlkem_matrix
    jc hello_reject
    mov di, hello_desc + tls13_286_desc_input2
    mov ax, tls13_286_mlkem_matrix_stage_off
    mov dx, tls13_286_mlkem_matrix_stage_bytes
    call hello_set_high_span

.module:
    mov ax, tls13_286_mod_kind_mlkem_decap
    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc hello_reject
    mov ax, [cs:hello_mlkem_operation]
    mov bx, tls13_286_root_state_loader
    mov si, hello_desc
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
    jc hello_reject

    call hello_clear_desc
    mov word [hello_desc + tls13_286_desc_op], \
        tls13_286_mod_op_x25519_shared
    mov di, hello_desc + tls13_286_desc_input0
    mov ax, tls13_286_x25519_scalar_off
    mov dx, tls13_286_x25519_scalar_bytes
    call hello_set_high_span
    mov di, hello_desc + tls13_286_desc_input1
    mov ax, tls13_286_hello_server_x_off
    mov dx, 32
    call hello_set_low_span
    mov di, hello_desc + tls13_286_desc_output0
    mov ax, tls13_286_hybrid_secret_off + 32
    mov dx, 32
    call hello_set_high_span

    mov ax, tls13_286_mod_kind_x25519
    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc hello_reject
    mov ax, tls13_286_mod_op_x25519_shared
    mov bx, tls13_286_root_state_loader
    mov si, hello_desc
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
    jc hello_reject

    cmp word [cs:hello_mlkem_operation], \
        tls13_286_mod_op_mlkem_candidate
    jne .retire_public
    call hello_publish_candidate_escrow
    jc hello_reject

.retire_public:
    ; The low peer share and ciphertext are public, but retire them now so no
    ; later controller can accidentally treat a stale ServerHello as current.
    push es
    xor ax, ax
    mov es, ax
    mov di, tls13_286_hello_ciphertext_off
    mov cx, tls13_286_hello_ciphertext_bytes / 2
    rep stosw
    mov di, tls13_286_hello_server_x_off
    mov cx, 16
    rep stosw
    pop es
    xor ax, ax
    clc
    ret

hello_consume_mlkem_matrix:
    mov es, [cs:hello_crypto_seg]
    cmp word [es:tls13_286_mlkem_matrix_status_inv_off], \
        (tls13_286_mlkem_matrix_status_valid << 8) | \
        tls13_286_mlkem_matrix_status_inverse
    jne .bad
    mov word [es:tls13_286_mlkem_matrix_status_inv_off], 0
    xor ax, ax
    mov es, ax
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

; Executable acquisition boundary used by the product integration gate.
; Keeping it separate from entry 0 prevents a caller from mistaking a parsed
; ServerHello for a complete TLS session.
;
; in: BX=crypto segment, SI=frozen footer (same as entry 0)
; out success: AX=ACQUIRE_CERTIFICATE, NIC lease retained for the protected
;              flight controller; the exact hybrid is private in high RAM and
;              a coalesced protected suffix is published status-last.
hello_live_acquire:
    cld
    call hello_prelude
    jc hello_abort
    call hello_stage_symmetric
    jc hello_abort
    ; Key generation is connection-independent.  Complete it before acquiring
    ; the NIC/TCP lease so the provider's fresh-socket deadline begins only
    ; when the exact ClientHello is ready to stream.
    call hello_prepare_crypto
    jc hello_abort
    jmp short hello_live_connect

; The authenticated offline stage reloads this same immutable HELLO image and
; enters here for a wholly independent, no-0RTT PSK-DHE X25519MLKEM768
; exchange.  No certificate fallback is accepted on this connection.
hello_live_fresh:
    cld
    call hello_prelude
    jc hello_abort
    call hello_stage_symmetric
    jc hello_abort
    ; The independent attempt has its own one-shot bundle, but the same rule
    ; applies: finish ML-KEM/X25519 key generation and binder construction
    ; before opening TCP.
    call hello_prepare_resume_crypto
    jc hello_abort

hello_live_connect:
    call word [cs:TLS13_286_LINK_NIC_ENTER_SLOT]
    mov byte [cs:hello_nic_owned], 1
    mov ax, TLS13_286_LINK_TCP_CONNECT_PHASE_KEY
    mov bx, TLS13_286_LINK_TCP_CONNECT_DESTINATION
    call TLS13_286_LINK_LOAD_CORE_SECTORS_AT
    jc hello_abort
    call TLS13_286_LINK_TCP_CONNECT_ENTRY
    jc hello_abort

    call hello_live_send_client
    jc hello_abort
    call hello_live_receive_server
    jc hello_abort
    cmp byte [cs:hello_mode], hello_mode_resume
    jne .candidate
    call hello_hybrid_cached
    jc hello_abort
    jmp short .chain
.candidate:
    call hello_hybrid_candidate
    jc hello_abort
.chain:
    jmp hello_enter_staged_flight

hello_stage_symmetric:
    ; The symmetric implementation is immutable and connection-independent.
    ; Stage it before key generation/binder construction and before acquiring
    ; the NIC/TCP lease.  Besides moving twelve floppy reads out of OpenAI's
    ; fresh-socket deadline, this keeps resumed ticket age construction after
    ; all potentially rotational I/O.
    mov es, [cs:hello_crypto_seg]
    mov word [es:tls13_286_symmetric_stage_status_inv_off], 0
    xor ax, ax
    mov di, tls13_286_resumption_early_status_inv_off
    mov cx, 3
    rep stosw
    mov ax, TLS13_286_LINK_SYM_PHASE_KEY & 0x00ff
    add ax, 11                         ; FAT data start LBA
    mov cx, TLS13_286_LINK_SYM_SECTORS
    mov bx, tls13_286_symmetric_stage_off
.sector:
    call TLS13_286_LINK_READ_ABS_SECTOR
    jc .bad
    add bx, 512
    inc ax
    loop .sector
    ; The product K14 image spends its final 288 bytes on the 8088
    ; route's raw-vault writer/continuation.  Its SHA initial-state operand
    ; already names the canonical runtime tail.  Restore that exact tail and
    ; reaffirm the bound operand before publishing READY and before the TCP
    ; lease begins.  FLIGHT later needs only copy+relocation.
    push ds
    push cs
    pop ds
    mov si, sha256_initial_state
    mov di, tls13_286_symmetric_stage_off + 0x16e0
    mov cx, sha256_digest_len / 2
    rep movsw
    mov si, sha256_k
    mov di, tls13_286_symmetric_stage_off + 0x1700
    mov cx, sha256_k_len / 2
    rep movsw
    mov word [es:tls13_286_symmetric_stage_off + \
        TLS13_286_LINK_SYM_PRODUCT_INITIAL_POINTER_OFF], 0x2ee0
    pop ds
    mov ax, (tls13_286_symmetric_stage_status_valid << 8) | \
        tls13_286_symmetric_stage_status_inverse
    mov [es:tls13_286_symmetric_stage_status_inv_off], al
    mov [es:tls13_286_symmetric_stage_status_off], ah
    jmp hello_stage_flight
.bad:
    push cs
    pop es
    stc
    ret

; The protected-flight coordinator is immutable public program data.  Read
; and validate its exact compressed component before TCP so rotational floppy
; latency cannot consume OpenAI's post-ClientHello response window.
hello_stage_flight:
    mov ax, tls13_286_tail_kind_flight
    call tls13_286_root_find_entry
    jc .bad
    mov ax, [si + tls13_286_tail_entry_start_sector]
    add ax, 11
    push cs
    pop ds
    mov bx, tls13_286_flight_stage_off
    mov cx, TLS13_286_FLIGHT_COMPONENT_SECTORS
.sector:
    call TLS13_286_LINK_READ_ABS_SECTOR
    jc .bad
    add bx, 512
    inc ax
    loop .sector
    mov ax, (tls13_286_flight_stage_status_valid << 8) | \
        tls13_286_flight_stage_status_inverse
    mov [es:tls13_286_flight_stage_status_inv_off], al
    mov [es:tls13_286_flight_stage_status_off], ah
    push cs
    pop es
    ; The last bounded add in the sector loop leaves CF clear.  The assertion
    ; below forbids a stage ending at the segment wrap.
    ret
.bad:
    jmp hello_stage_symmetric.bad

; Consume the pre-TCP component status before reading executable bytes, then
; decode and CRC-check high RAM directly into the retired 0x6300 module
; window.  FLIGHT's first record-open wipe retires the remaining public
; compressed copy; every earlier failure enters the full abort scrub.
hello_enter_staged_flight:
    mov es, [cs:hello_crypto_seg]
    cmp word [es:tls13_286_flight_stage_status_inv_off], \
        (tls13_286_flight_stage_status_valid << 8) | \
        tls13_286_flight_stage_status_inverse
    jne .bad
    mov word [es:tls13_286_flight_stage_status_inv_off], 0
    push es
    pop ds
    mov si, tls13_286_flight_stage_off + tls13_286_tail_lz4_header_bytes
    mov cx, TLS13_286_FLIGHT_COMPONENT_BLOCK_BYTES
    mov dx, TLS13_286_FLIGHT_COMPONENT_RAW_BYTES
    mov bp, TLS13_286_FLIGHT_COMPONENT_RAW_CRC16
    push cs
    pop es
    mov di, TLS13_286_FLIGHT_COMPONENT_LOAD
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    jc .bad
    mov al, [tls13_286_root_state_mode]
    mov bx, [tls13_286_root_state_crypto_seg]
    mov si, tls13_286_tail_footer_off
    jmp TLS13_286_FLIGHT_COMPONENT_ENTRY
.bad:
    jmp hello_abort

hello_live_send_client:
.next:
    call hello_next_fragment
    jc .bad
    or ax, ax
    jz .done
    call TLS13_286_LINK_TCP_SEND
    jc .bad
    call hello_fragment_consumed
    jc .bad
    jmp short .next
.done:
    clc
    ret
.bad:
    stc
    ret

; Receive one exact plaintext ServerHello record.  The TCP parser publishes a
; near payload pointer/length; this wrapper consumes a record header even when
; split across frames, feeds only the selected 1,210/1,216-byte handshake to
; HELLO, ACKs every accepted segment, and quarantines any coalesced protected
; suffix.
hello_live_receive_server:
    call hello_server_begin
    jc .bad
    mov byte [hello_tls_header_pos], 0
    mov word [hello_tls_remaining], 0
.receive:
    call TLS13_286_LINK_TCP_RECEIVE
    jc .bad
    mov si, [TLS13_286_LINK_TCP_RX_PAYLOAD_PTR]
    mov cx, [TLS13_286_LINK_TCP_RX_PAYLOAD_LEN]
    or cx, cx
    jz .bad
    cmp cx, hello_mss_max
    ja .bad
    mov [hello_live_ptr], si
    mov [hello_live_remaining], cx

.consume:
    cmp byte [hello_tls_header_pos], 5
    je .body
    cmp word [hello_live_remaining], 0
    je .ack_more
    mov si, [hello_live_ptr]
    lodsb
    mov [hello_live_ptr], si
    dec word [hello_live_remaining]
    xor bx, bx
    mov bl, [hello_tls_header_pos]
    mov [hello_tls_header + bx], al
    inc byte [hello_tls_header_pos]
    cmp byte [hello_tls_header_pos], 5
    jne .consume
    call hello_live_validate_record_header
    jc .bad
    jmp short .consume

.body:
    cmp word [hello_tls_remaining], 0
    je .complete
    mov dx, [hello_live_remaining]
    or dx, dx
    jz .ack_more
    cmp dx, [hello_tls_remaining]
    jbe .chunk_ready
    mov dx, [hello_tls_remaining]
.chunk_ready:
    mov [hello_live_chunk], dx
    mov si, [hello_live_ptr]
    mov cx, dx
    call hello_server_feed
    jc .bad
    mov dx, [hello_live_chunk]
    add [hello_live_ptr], dx
    sub [hello_live_remaining], dx
    sub [hello_tls_remaining], dx
    jmp short .consume

.ack_more:
    call TLS13_286_LINK_TCP_ACK
    jc .bad
    jmp .receive

.complete:
    call hello_server_finish
    jc .bad
    call hello_live_publish_pending
    jc .bad
    call TLS13_286_LINK_TCP_ACK
    jc .bad
    clc
    ret
.bad:
    stc
    ret

hello_live_validate_record_header:
    cmp byte [hello_tls_header], 0x16
    jne .bad
    cmp word [hello_tls_header + 1], 0x0303
    jne .bad
    mov ax, hello_server_len
    cmp byte [hello_mode], hello_mode_resume
    jne .length_ready
    mov ax, hello_resumed_server_len
.length_ready:
    cmp byte [hello_tls_header + 3], ah
    jne .bad
    cmp byte [hello_tls_header + 4], al
    jne .bad
    mov [hello_tls_remaining], ax
    clc
    ret
.bad:
    stc
    ret

hello_live_publish_pending:
    mov cx, [hello_live_remaining]
    cmp cx, tls13_286_pending_wire_max
    ja .bad
    push ds
    mov es, [cs:hello_crypto_seg]
    mov byte [es:tls13_286_pending_wire_status_off], 0
    mov byte [es:tls13_286_pending_wire_status_inv_off], 0
    mov [es:tls13_286_pending_wire_len_off], cx
    mov si, [cs:hello_live_ptr]
    mov di, tls13_286_pending_wire_off
    rep movsb
    mov byte [es:tls13_286_pending_wire_status_inv_off], \
        tls13_286_pending_wire_status_inverse
    mov byte [es:tls13_286_pending_wire_status_off], \
        tls13_286_pending_wire_status_valid
    pop ds
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    stc
    ret

; AX=offset in crypto reservation, DX=exact length, DI=span.
hello_set_high_span:
    mov bx, ax
    and ax, 15
    mov [di + tls13_286_span_off], ax
    mov ax, bx
    mov cl, 4
    shr ax, cl
    add ax, [cs:hello_crypto_seg]
    mov [di + tls13_286_span_seg], ax
    mov [di + tls13_286_span_len], dx
    mov word [di + tls13_286_span_len + 2], 0
    ret

; AX=physical low-memory offset, DX=exact length, DI=span.
hello_set_low_span:
    mov bx, ax
    and ax, 15
    mov [di + tls13_286_span_off], ax
    mov ax, bx
    mov cl, 4
    shr ax, cl
    mov [di + tls13_286_span_seg], ax
    mov [di + tls13_286_span_len], dx
    mov word [di + tls13_286_span_len + 2], 0
    ret

hello_capture_client_x:
    xor dx, dx
    mov si, tls13_286_client_x_public
    mov di, hello_client_x
    mov cx, tls13_286_client_x_public_bytes / 2
.copy:
    lodsw
    or dx, ax
    stosw
    mov word [si - 2], 0
    loop .copy
    or dx, dx
    jz .bad
    clc
    ret
.bad:
    stc
    ret

hello_wipe_acquire_bundle:
    mov es, [cs:hello_crypto_seg]
    mov di, [cs:hello_attempt_off]
    xor ax, ax
    mov cx, tls13_286_attempt_bundle_bytes / 2
    rep stosw
    mov es, ax
    ret

; Clear the publication bytes before acquisition can write any candidate
; evidence.  Status is invalid throughout the wipe.
hello_clear_candidate_escrow:
    mov es, [cs:hello_crypto_seg]
    xor ax, ax
    mov di, tls13_286_candidate_ciphertext_off
    mov cx, (tls13_286_candidate_status_off - \
        tls13_286_candidate_ciphertext_off + 1) / 2
    rep stosw
    ret

; Publish exact c || K' status-last in the retired entropy/G-table window.
; Both inputs already live in Seed-owned memory and remain inaccessible to the
; far arena/context allocator.
hello_publish_candidate_escrow:
    push ds
    push es
    mov es, [cs:hello_crypto_seg]
    mov byte [es:tls13_286_candidate_status_off], 0
    mov byte [es:tls13_286_candidate_status_inv_off], 0
    xor ax, ax
    mov ds, ax
    mov si, tls13_286_hello_ciphertext_off
    mov di, tls13_286_candidate_ciphertext_off
    mov cx, tls13_286_candidate_ciphertext_bytes / 2
    rep movsw
    mov ax, [cs:hello_crypto_seg]
    mov ds, ax
    mov si, tls13_286_hybrid_secret_off
    mov di, tls13_286_candidate_secret_off
    mov cx, tls13_286_candidate_secret_bytes / 2
    rep movsw
    mov byte [es:tls13_286_candidate_status_inv_off], \
        tls13_286_candidate_status_inverse
    mov byte [es:tls13_286_candidate_status_off], \
        tls13_286_candidate_status_valid
    pop es
    pop ds
    clc
    ret

hello_clear_desc:
    xor ax, ax
    mov es, ax
    mov di, hello_desc
    mov cx, tls13_286_desc_bytes / 2
    rep stosw
    ret

; ---------------------------------------------------------------------------
; Exact acquisition/resumption ClientHello fragment iterator
; ---------------------------------------------------------------------------

hello_next_fragment:
    cld
    cmp byte [hello_phase], hello_phase_tx
    je .active
    cmp byte [hello_phase], hello_phase_tx_done
    jne hello_reject
    xor ax, ax
    xor cx, cx
    clc
    ret
.active:
    cmp byte [hello_pending], 0
    jne .repeat
    xor ax, ax
    mov al, [hello_segment]
    cmp ax, hello_fragment_count
    jae .end
    or ax, ax
    jz .prefix
    cmp ax, 5
    jb .ek
    call hello_build_tail
    mov si, hello_tx_work
    mov cx, [hello_wire_tail_len]
    jmp short .publish
.prefix:
    call hello_build_prefix
    mov si, hello_tx_work
    mov cx, hello_prefix_fragment_len
    jmp short .publish
.ek:
    dec ax
    mov bx, hello_mss_max
    mul bx
    mov cx, hello_mss_max
    cmp byte [hello_segment], 4
    jne .stage_ek
    mov cx, tls13_286_hello_mlkem_ek_bytes - 3 * hello_mss_max
.stage_ek:
    call hello_stage_ek_fragment
    jmp short .publish
.publish:
    mov [hello_pending_ptr], si
    mov [hello_pending_len], cx
    mov byte [hello_pending], 1
    cmp byte [hello_hash_enabled], 0
    je .return
    push si
    push cx
    cmp byte [hello_segment], 0
    jne .hash
    add si, 5
    sub cx, 5
.hash:
    call sha256_update
    pop cx
    pop si
.return:
    mov ax, 1
    clc
    ret
.repeat:
    mov si, [hello_pending_ptr]
    mov cx, [hello_pending_len]
    mov ax, 1
    clc
    ret
.end:
    xor ax, ax
    xor cx, cx
    clc
    ret

; AX=byte offset within the ML-KEM encapsulation key, CX=fragment length.
; The embedded ek in the private high dk survives the subsequently loaded
; 0x0900 TCP phase.  Stage only the current public fragment in the retired
; module overlay immediately before hashing/sending it.
hello_stage_ek_fragment:
    push ax
    push bx
    push dx
    push di
    push ds
    push es
    push cx
    add ax, tls13_286_mlkem_dk_ek_off
    mov si, ax
    and si, 15
    mov cl, 4
    shr ax, cl
    add ax, [cs:hello_crypto_seg]
    mov ds, ax
    xor ax, ax
    mov es, ax
    mov di, hello_tx_work
    pop cx
    push cx
    rep movsb
    pop cx
    pop es
    pop ds
    pop di
    pop dx
    pop bx
    pop ax
    mov si, hello_tx_work
    ret

hello_fragment_consumed:
    cld
    cmp byte [hello_phase], hello_phase_tx
    jne hello_reject
    cmp byte [hello_pending], 1
    jne hello_reject
    mov byte [hello_pending], 0
    inc byte [hello_segment]
    cmp byte [hello_segment], hello_fragment_count
    jb .done
    mov byte [hello_phase], hello_phase_tx_done
    mov byte [hello_hash_enabled], 0
.done:
    xor ax, ax
    clc
    ret

hello_build_prefix:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, hello_tx_work
    mov al, 0x16
    stosb
    mov ax, 0x0103                    ; legacy record version 03 01
    stosw
    mov ax, [hello_wire_message_len]
    xchg al, ah
    stosw
    mov al, 1
    stosb
    xor al, al
    stosb
    mov ax, [hello_wire_message_len]
    sub ax, 4
    xchg al, ah
    stosw
    mov ax, 0x0303
    xchg al, ah
    stosw
    mov si, hello_random
    mov cx, 32
    rep movsb
    mov al, 32
    stosb
    mov si, hello_session
    mov cx, 32
    rep movsb
    mov si, hello_client_fixed
    mov cx, hello_client_fixed_len
    rep movsb
    mov ax, [hello_wire_extensions_len]
    xchg al, ah
    stosw
    mov si, hello_prefix_extensions
    mov cx, hello_prefix_extensions_len
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

hello_build_tail:
    cmp byte [hello_mode], hello_mode_resume
    je hello_build_resumed_tail
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, hello_tx_work
    mov si, hello_client_x
    mov cx, 32
    rep movsb
    mov si, hello_tail_suffix
    mov cx, hello_tail_suffix_len
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

hello_build_resumed_tail:
    push ax
    push bx
    push cx
    push si
    push di
    push ds
    push es
    push ds
    pop es
    mov di, hello_tx_work
    mov si, hello_client_x
    mov cx, 32
    rep movsb
    mov si, hello_tail_suffix
    mov cx, hello_tail_suffix_len
    rep movsb
    mov ax, 0x2900                    ; pre_shared_key, mandatory final
    stosw
    mov ax, [cs:hello_ticket_len_snapshot]
    add ax, 43
    xchg al, ah
    stosw
    mov ax, [cs:hello_ticket_len_snapshot]
    add ax, 6
    xchg al, ah
    stosw
    mov ax, [cs:hello_ticket_len_snapshot]
    xchg al, ah
    stosw

    mov ax, [cs:hello_crypto_seg]
    mov ds, ax
    mov si, tls13_286_ticket_identity_off
    mov cx, [cs:hello_ticket_len_snapshot]
    rep movsb
    xor ax, ax
    mov ds, ax
    mov si, hello_ticket_age
    mov cx, 4
    rep movsb
    mov ax, 0x2100                    ; one 32-byte binder
    stosw
    mov al, 32
    stosb
    mov ax, [cs:hello_crypto_seg]
    mov ds, ax
    mov si, tls13_286_ticket_binder_off
    mov cx, tls13_286_ticket_binder_bytes
    rep movsb
    pop es
    pop ds
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

; Compute the RFC 8446 resumption binder over ClientHelloTruncated.  All
; encoded lengths already include the final binders vector, while the hash
; stops immediately before that vector.  The binder and the ticket-only early
; "derived" secret are completed before TCP; FLIGHT consumes the latter once
; ServerHello has selected identity zero, avoiding a duplicate live-window
; binder schedule without changing the authenticated Finished boundary.
hello_make_binder:
    push ds
    push es
    mov es, [cs:hello_crypto_seg]
    xor ax, ax
    mov di, tls13_286_ticket_truncated_hash_off
    mov cx, (tls13_286_ticket_binder_bytes + \
        tls13_286_ticket_truncated_hash_bytes) / 2
    rep stosw
    xor ax, ax
    mov es, ax

    call hello_build_prefix
    call sha256_init
    mov si, hello_tx_work + 5
    mov cx, hello_prefix_fragment_len - 5
    call sha256_update
    xor ax, ax
    mov cx, hello_mss_max
    call hello_stage_ek_fragment
    call sha256_update
    mov ax, hello_mss_max
    mov cx, hello_mss_max
    call hello_stage_ek_fragment
    call sha256_update
    mov ax, 2 * hello_mss_max
    mov cx, hello_mss_max
    call hello_stage_ek_fragment
    call sha256_update
    mov ax, 3 * hello_mss_max
    mov cx, tls13_286_hello_mlkem_ek_bytes - 3 * hello_mss_max
    call hello_stage_ek_fragment
    call sha256_update
    call hello_build_resumed_tail
    mov si, hello_tx_work
    mov cx, [hello_wire_tail_len]
    sub cx, 35                       ; omit the complete binders vector
    call sha256_update
    mov di, hello_truncated_digest
    call sha256_finish

    mov es, [cs:hello_crypto_seg]
    mov si, hello_truncated_digest
    mov di, tls13_286_ticket_truncated_hash_off
    mov cx, tls13_286_ticket_truncated_hash_bytes
    rep movsb
    xor ax, ax
    mov es, ax

    ; TX staging aliases secret_a, so copy the consumed PSK only after the
    ; final truncated fragment has been hashed.
    mov ds, [cs:hello_crypto_seg]
    mov si, tls13_286_ticket_psk_off
    mov di, hello_secret_a
    mov cx, tls13_286_ticket_psk_bytes
    rep movsb
    xor ax, ax
    mov ds, ax

    ; early_secret = HKDF-Extract(zeros, PSK)
    mov si, hello_zeros
    mov bx, hello_secret_a
    mov cx, 32
    mov di, hello_secret_b
    call hello_hmac_once
    jc .bad
    ; early_derived = Derive-Secret(early_secret, "derived", Hash(""))
    mov es, [cs:hello_crypto_seg]
    mov word [es:tls13_286_resumption_early_status_inv_off], 0
    xor ax, ax
    mov es, ax
    mov si, hello_secret_b
    mov bx, hello_label_derived
    mov cx, hello_label_derived_len
    mov dx, hello_empty_hash
    mov ax, 32
    mov di, hello_secret_a
    call hello_expand_label
    jc .bad
    ; Stage value || bitwise-complement while its status remains invalid.
    mov es, [cs:hello_crypto_seg]
    mov si, hello_secret_a
    mov di, tls13_286_resumption_early_off
    mov bx, tls13_286_resumption_early_inverse_off
    mov cx, tls13_286_resumption_early_bytes
.stage_early:
    lodsb
    mov [es:di], al
    not al
    mov [es:bx], al
    inc di
    inc bx
    loop .stage_early
    xor ax, ax
    mov es, ax
    ; binder_key = Derive-Secret(early_secret, "res binder", Hash(""))
    mov si, hello_secret_b
    mov bx, hello_label_res_binder
    mov cx, hello_label_res_binder_len
    mov dx, hello_empty_hash
    mov ax, 32
    mov di, hello_secret_a
    call hello_expand_label
    jc .bad
    ; finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
    mov si, hello_secret_a
    mov bx, hello_label_finished
    mov cx, hello_label_finished_len
    mov dx, hello_empty_context
    xor ax, ax
    mov di, hello_secret_b
    call hello_expand_label
    jc .bad
    ; binder = HMAC(finished_key, ClientHelloTruncated hash)
    mov si, hello_secret_b
    mov bx, hello_truncated_digest
    mov cx, 32
    mov di, hello_secret_a
    call hello_hmac_once
    jc .bad

    mov es, [cs:hello_crypto_seg]
    mov si, hello_secret_a
    mov di, tls13_286_ticket_binder_off
    mov cx, tls13_286_ticket_binder_bytes
    rep movsb
    mov byte [es:tls13_286_resumption_early_status_inv_off], \
        tls13_286_resumption_early_status_inverse
    mov byte [es:tls13_286_resumption_early_status_off], \
        tls13_286_resumption_early_status_valid
    xor ax, ax
    mov es, ax
    mov di, hello_secret_a
    mov cx, (hello_hkdf_block + 32 - hello_secret_a) / 2
    rep stosw
    mov di, hmac_ipad
    mov cx, (hello_sha_work_end - hmac_ipad) / 2
    rep stosw
    pop es
    pop ds
    clc
    ret
.bad:
    xor ax, ax
    mov es, ax
    mov di, hello_secret_a
    mov cx, (hello_hkdf_block + 32 - hello_secret_a) / 2
    rep stosw
    mov di, hmac_ipad
    mov cx, (hello_sha_work_end - hmac_ipad) / 2
    rep stosw
    pop es
    pop ds
    stc
    ret

; SI=secret32, BX=label, CX=label length, DX=context, AX=context length,
; DI=32-byte output.
hello_expand_label:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    mov [hello_expand_output], di
    mov [hello_expand_context], dx
    mov [hello_expand_context_len], ax
    mov [hmac_key_ptr], si
    mov word [hmac_key_len], 32
    call hmac_prepare_current_key_context
    jc .done
    push ds
    pop es
    mov di, hello_hkdf_info
    mov ax, 0x2000
    stosw
    mov al, hello_label_prefix_len
    add al, cl
    stosb
    mov si, hello_label_prefix
    push cx
    mov cx, hello_label_prefix_len
    rep movsb
    pop cx
    mov si, bx
    rep movsb
    mov ax, [hello_expand_context_len]
    stosb
    mov si, [hello_expand_context]
    mov cx, ax
    rep movsb
    mov al, 1
    stosb
    mov ax, di
    sub ax, hello_hkdf_info
    mov word [hmac_data1_ptr], hello_hkdf_info
    mov [hmac_data1_len], ax
    mov word [hmac_data2_len], 0
    mov word [hmac_output_ptr], hello_hkdf_block
    call hmac_sha256_prepared
    jc .done
    mov si, hello_hkdf_block
    mov di, [hello_expand_output]
    mov cx, 32
    rep movsb
    clc
.done:
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; SI=key32, BX=data, CX=data length, DI=output32.
hello_hmac_once:
    mov [hmac_key_ptr], si
    mov word [hmac_key_len], 32
    mov [hmac_data1_ptr], bx
    mov [hmac_data1_len], cx
    mov word [hmac_data2_len], 0
    mov [hmac_output_ptr], di
    call hmac_prepare_current_key_context
    jc .done
    jmp hmac_sha256_prepared
.done:
    ret

; ---------------------------------------------------------------------------
; Strict fixed-profile ServerHello parser
; ---------------------------------------------------------------------------

hello_server_begin:
    cld
    cmp byte [hello_phase], hello_phase_tx_done
    jne hello_reject
    mov byte [hello_phase], hello_phase_rx
    mov byte [hello_segment], 0       ; extension-order selector
    mov byte [tls13_286_hello_status_off], 0
    mov word [hello_server_pos], 0
    mov byte [hello_hrr_difference], 0
    mov byte [hello_x_nonzero], 0
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, hello_server_x_work
    mov cx, 32
    rep stosb
    mov di, tls13_286_hello_server_x_off
    mov cx, tls13_286_hello_handoff_end - tls13_286_hello_server_x_off
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    xor ax, ax
    clc
    ret

hello_server_feed:
    cld
    cmp byte [hello_phase], hello_phase_rx
    jne hello_reject
    or cx, cx
    jz hello_reject
    cmp cx, hello_mss_max
    ja hello_reject
    mov ax, [hello_server_pos]
    add ax, cx
    mov dx, hello_server_len
    cmp byte [hello_mode], hello_mode_resume
    jne .bound_ready
    mov dx, hello_resumed_server_len
.bound_ready:
    cmp ax, dx
    ja hello_reject
    push si
    push cx
.next:
    lodsb
    mov bx, [hello_server_pos]
    cmp bx, 6
    jb .header
    cmp bx, 38
    jb .random
    cmp bx, 39
    jb .session_len
    cmp bx, 71
    jb .session

    ; Acquisition accepts the two RFC-valid layouts observed from the fixed
    ; edge: supported_versions || key_share or key_share ||
    ; supported_versions.  Resumption accepts the two observed layouts around
    ; the same key_share: versions || key_share || selected_identity, or
    ; selected_identity || key_share || versions.
    cmp byte [hello_mode], hello_mode_resume
    jne .fresh_order
    cmp bx, 77
    jne .resume_order_known
    cmp al, 0x29
    jne .resume_order_known
    mov byte [hello_segment], 3
.resume_order_known:
    cmp byte [hello_segment], 3
    jne .shape_ready
    cmp bx, 82
    jb .resume_prefix
    cmp bx, 1210
    jb .shape_ready
    sub bx, 1134
    jmp short .shape_ready
.resume_prefix:
    cmp bx, 76
    jb .shape_ready
    add bx, 1134
    jmp short .shape_ready

.fresh_order:
    cmp bx, 77
    jne .order_known
    cmp al, 0x2b
    je .versions_first
    cmp al, 0x33
    jne .bad
    mov byte [hello_segment], 2
    jmp short .order_known
.versions_first:
    mov byte [hello_segment], 1
.order_known:
    cmp byte [hello_segment], 2
    jne .shape_ready
    cmp bx, 1204
    jae .versions_tail
    add bx, 6
    jmp short .shape_ready
.versions_tail:
    sub bx, 1128
.shape_ready:
    cmp bx, 90
    jb .middle
    cmp bx, 1178
    jb .ciphertext
    cmp bx, 1210
    jb .server_x
    cmp byte [hello_mode], hello_mode_resume
    jne .bad
    cmp bx, hello_resumed_server_len
    jae .bad
    mov di, bx
    sub di, 1210
    cmp al, [hello_server_psk_suffix + di]
    jne .bad
    jmp short .accepted
.header:
    cmp byte [hello_mode], hello_mode_resume
    jne .fresh_header
    cmp al, [hello_server_resumed_header + bx]
    jne .bad
    jmp short .accepted
.fresh_header:
    cmp al, [hello_server_header + bx]
    jne .bad
    jmp short .accepted
.random:
    mov di, bx
    sub di, 6
    mov ah, [hello_hrr_random + di]
    xor ah, al
    or [hello_hrr_difference], ah
    jmp short .accepted
.session_len:
    cmp al, 32
    jne .bad
    jmp short .accepted
.session:
    mov di, bx
    sub di, 39
    cmp al, [hello_session + di]
    jne .bad
    jmp short .accepted
.middle:
    mov di, bx
    sub di, 71
    cmp byte [hello_mode], hello_mode_resume
    jne .fresh_middle
    cmp al, [hello_server_resumed_middle + di]
    jne .bad
    jmp short .accepted
.fresh_middle:
    cmp al, [hello_server_middle + di]
    jne .bad
    jmp short .accepted
.ciphertext:
    mov di, bx
    sub di, 90
    mov [tls13_286_hello_ciphertext_off + di], al
    jmp short .accepted
.server_x:
    mov di, bx
    sub di, 1178
    mov [hello_server_x_work + di], al
    or [hello_x_nonzero], al
.accepted:
    inc word [hello_server_pos]
    dec cx
    jnz .next
    pop cx
    pop si
    call sha256_update
    xor ax, ax
    clc
    ret
.bad:
    pop cx
    pop si
    jmp hello_reject

hello_server_finish:
    cld
    cmp byte [hello_phase], hello_phase_rx
    jne hello_reject
    mov ax, hello_server_len
    cmp byte [hello_mode], hello_mode_resume
    jne .length_ready
    mov ax, hello_resumed_server_len
.length_ready:
    cmp [hello_server_pos], ax
    jne hello_reject
    cmp byte [hello_hrr_difference], 0
    je hello_reject
    cmp byte [hello_x_nonzero], 0
    je hello_reject
    call hello_export_transcript_context
    mov di, tls13_286_hello_digest_off
    call sha256_finish
    push si
    push di
    push cx
    push es
    push ds
    pop es
    mov si, hello_server_x_work
    mov di, tls13_286_hello_server_x_off
    mov cx, 32
    rep movsb
    pop es
    pop cx
    pop di
    pop si
    mov byte [hello_phase], hello_phase_complete
    mov byte [tls13_286_hello_status_off], 1
    xor ax, ax
    clc
    ret

hello_export_transcript_context:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, tls13_286_hello_ctx_magic_off
    mov ax, 0x3154                    ; "T1"
    stosw
    mov ax, 0x4333                    ; "3C"
    stosw
    mov al, 1
    stosb
    mov al, [sha256_block_len]
    stosb
    mov ax, [sha256_len_low]
    stosw
    mov ax, [sha256_len_high]
    stosw
    mov si, sha256_state
    mov di, tls13_286_hello_ctx_state_off
    mov cx, 16
    rep movsw
    mov si, sha256_block
    mov di, tls13_286_hello_ctx_block_off
    mov cx, sha256_block_size
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

; ---------------------------------------------------------------------------
; Retirement and fatal path
; ---------------------------------------------------------------------------

hello_clear_low:
    xor ax, ax
    mov es, ax
    mov di, tls13_286_hello_rx_frame_off
    mov cx, tls13_286_hello_rx_frame_bytes / 2
    rep stosw
    mov di, tls13_286_hello_public_off
    mov cx, (0x1000 - tls13_286_hello_public_off) / 2
    rep stosw
    mov di, tls13_286_client_x_public
    mov cx, tls13_286_client_x_public_bytes / 2
    rep stosw
    ret

hello_clear_work:
    xor ax, ax
    mov es, ax
    mov di, hello_state_clear_start
    mov cx, (hello_sha_work_end - hello_state_clear_start) / 2
    rep stosw
    ret

hello_reject:
    mov ax, tls13_286_error_profile
    stc
    ret

hello_abort:
    cld
    cmp byte [cs:hello_nic_owned], 0
    je .nic_done
    mov byte [cs:hello_nic_owned], 0
    call word [cs:TLS13_286_LINK_NIC_RESTORE_SLOT]
.nic_done:
    call hello_clear_low
    jmp word [cs:tls13_286_abort_capsule_load + \
        tls13_286_abort_capsule_entry_ptr]

; ---------------------------------------------------------------------------
; Shared shipping SHA-256 and immutable wire profile
; ---------------------------------------------------------------------------

%include "core/sha256.inc"

hello_client_fixed:
    db 0x00,0x02,0x13,0x03           ; TLS_CHACHA20_POLY1305_SHA256
    db 0x01,0x00                     ; one null compression method
hello_client_fixed_len equ $ - hello_client_fixed

hello_prefix_extensions:
    ; server_name = api.openai.com
    db 0x00,0x00,0x00,0x13,0x00,0x11,0x00,0x00,0x0e
    db 'api.openai.com'
    ; supported_versions = TLS 1.3
    db 0x00,0x2b,0x00,0x03,0x02,0x03,0x04
    ; supported_groups = X25519MLKEM768 (draft group 0x11ec)
    db 0x00,0x0a,0x00,0x04,0x00,0x02,0x11,0xec
    ; signature_algorithms = ecdsa_secp256r1_sha256
    db 0x00,0x0d,0x00,0x04,0x00,0x02,0x04,0x03
    ; Deliberately no compress_certificate extension.
    ; One hybrid key_share entry: 1184-byte ek || dynamic X25519 public.
    db 0x00,0x33,0x04,0xc6,0x04,0xc4,0x11,0xec,0x04,0xc0
hello_prefix_extensions_len equ $ - hello_prefix_extensions

hello_tail_suffix:
    ; ALPN selects only h2; DATA flow control is independent of TLS records.
    db 0x00,0x10,0x00,0x05,0x00,0x03,0x02,'h2'
    ; RFC 7685 padding; this is the final extension.
    db 0x00,0x15,0x00,0x0e
    times 14 db 0
    ; Request same-boot PSK-DHE tickets without offering a PSK or 0-RTT.
    db 0x00,0x2d,0x00,0x02,0x01,0x01
hello_tail_suffix_len equ $ - hello_tail_suffix
hello_tail_len equ 32 + hello_tail_suffix_len

hello_server_header:
    db 0x02,0x00,0x04,0xb6,0x03,0x03

hello_server_resumed_header:
    db 0x02,0x00,0x04,0xbc,0x03,0x03

hello_server_middle:
    db 0x13,0x03,0x00,0x04,0x6e
    db 0x00,0x2b,0x00,0x02,0x03,0x04
    db 0x00,0x33,0x04,0x64,0x11,0xec,0x04,0x60

hello_server_resumed_middle:
    db 0x13,0x03,0x00,0x04,0x74
    db 0x00,0x2b,0x00,0x02,0x03,0x04
    db 0x00,0x33,0x04,0x64,0x11,0xec,0x04,0x60
hello_server_psk_suffix:
    db 0x00,0x29,0x00,0x02,0x00,0x00 ; selected_identity = 0

hello_hrr_random:
    db 0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11
    db 0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91
    db 0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e
    db 0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c

hello_label_prefix db 'tls13 '
hello_label_prefix_len equ $ - hello_label_prefix
hello_label_res_binder db 'res binder'
hello_label_res_binder_len equ $ - hello_label_res_binder
hello_label_derived db 'derived'
hello_label_derived_len equ $ - hello_label_derived
hello_label_finished db 'finished'
hello_label_finished_len equ $ - hello_label_finished
hello_empty_context:
hello_empty_hash:
    db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14
    db 0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24
    db 0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c
    db 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
hello_zeros times 32 db 0

sha256_initial_state:
    dw 0xe667,0x6a09,0xae85,0xbb67
    dw 0xf372,0x3c6e,0xf53a,0xa54f
    dw 0x527f,0x510e,0x688c,0x9b05
    dw 0xd9ab,0x1f83,0xcd19,0x5be0
sha256_k:
    dw 0x2f98,0x428a,0x4491,0x7137
    dw 0xfbcf,0xb5c0,0xdba5,0xe9b5
    dw 0xc25b,0x3956,0x11f1,0x59f1
    dw 0x82a4,0x923f,0x5ed5,0xab1c
    dw 0xaa98,0xd807,0x5b01,0x1283
    dw 0x85be,0x2431,0x7dc3,0x550c
    dw 0x5d74,0x72be,0xb1fe,0x80de
    dw 0x06a7,0x9bdc,0xf174,0xc19b
    dw 0x69c1,0xe49b,0x4786,0xefbe
    dw 0x9dc6,0x0fc1,0xa1cc,0x240c
    dw 0x2c6f,0x2de9,0x84aa,0x4a74
    dw 0xa9dc,0x5cb0,0x88da,0x76f9
    dw 0x5152,0x983e,0xc66d,0xa831
    dw 0x27c8,0xb003,0x7fc7,0xbf59
    dw 0x0bf3,0xc6e0,0x9147,0xd5a7
    dw 0x6351,0x06ca,0x2967,0x1429
    dw 0x0a85,0x27b7,0x2138,0x2e1b
    dw 0x6dfc,0x4d2c,0x0d13,0x5338
    dw 0x7354,0x650a,0x0abb,0x766a
    dw 0xc92e,0x81c2,0x2c85,0x9272
    dw 0xe8a1,0xa2bf,0x664b,0xa81a
    dw 0x8b70,0xc24b,0x51a3,0xc76c
    dw 0xe819,0xd192,0x0624,0xd699
    dw 0x3585,0xf40e,0xa070,0x106a
    dw 0xc116,0x19a4,0x6c08,0x1e37
    dw 0x774c,0x2748,0xbcb5,0x34b0
    dw 0x0cb3,0x391c,0xaa4a,0x4ed8
    dw 0xca4f,0x5b9c,0x6ff3,0x682e
    dw 0x82ee,0x748f,0x636f,0x78a5
    dw 0x7814,0x84c8,0x0208,0x8cc7
    dw 0xfffa,0x90be,0x6ceb,0xa450
    dw 0xa3f7,0xbef9,0x78f2,0xc671

hello_abort_capsule_blob:
    incbin "build/ibm_pc_5150/tls13-286-abort-capsule.bin"
hello_abort_capsule_blob_bytes equ $ - hello_abort_capsule_blob

align 2, db 0
hello_image_end:

; The operation descriptor is writable, so it is not part of the authenticated
; emitted image.  Keep it in the controller window's reserved trailing slack;
; hello_clear_desc initializes every byte immediately before each module call.
%if (hello_image_end - hello_header) & 1
%error "TLS 1.3 286 HELLO image leaves descriptor unaligned"
%endif
hello_desc equ hello_image_end
%if (hello_image_end - hello_header) + tls13_286_desc_bytes > \
    tls13_286_controller_max_bytes
%error "TLS 1.3 286 HELLO descriptor exceeds controller window"
%endif

; ---------------------------------------------------------------------------
; Mutable low-controller work.  The authenticated component loader zeroes the
; decoded image; entry 0 additionally wipes this whole disjoint work range.
; ---------------------------------------------------------------------------

; The root stage ends at 3c00 and the public X25519 handoff begins at 4000.
; HELLO owns that otherwise dead interval only while this component is live.
; Flight replaces HELLO before using its own 3c00 symmetric state.
hello_state_clear_start       equ 0x3c00
hello_phase                   equ hello_state_clear_start
hello_segment                 equ hello_phase + 1
hello_pending                 equ hello_segment + 1
hello_hash_enabled            equ hello_pending + 1
hello_hrr_difference          equ hello_hash_enabled + 1
hello_x_nonzero               equ hello_hrr_difference + 1
hello_server_pos              equ hello_x_nonzero + 1
hello_pending_ptr             equ hello_server_pos + 2
hello_pending_len             equ hello_pending_ptr + 2
hello_crypto_seg              equ hello_pending_len + 2
hello_attempt_off             equ hello_crypto_seg + 2
hello_mlkem_operation         equ hello_attempt_off + 2
hello_mode                    equ hello_mlkem_operation + 2
hello_nic_owned               equ hello_mode + 1
hello_tls_header_pos          equ hello_nic_owned + 1
hello_tls_header              equ hello_tls_header_pos + 1
hello_tls_remaining           equ hello_tls_header + 5
hello_live_ptr                equ hello_tls_remaining + 2
hello_live_remaining          equ hello_live_ptr + 2
hello_live_chunk              equ hello_live_remaining + 2
hello_wire_message_len        equ hello_live_chunk + 2
hello_wire_extensions_len     equ hello_wire_message_len + 2
hello_wire_tail_len           equ hello_wire_extensions_len + 2
hello_ticket_len_snapshot     equ hello_wire_tail_len + 2
hello_tick_current_lo         equ hello_ticket_len_snapshot + 2
hello_tick_current_hi         equ hello_tick_current_lo + 2
hello_tick_rollover           equ hello_tick_current_hi + 2
hello_elapsed_ticks           equ hello_tick_rollover + 1
hello_elapsed_ms              equ hello_elapsed_ticks + 2
hello_ticket_age              equ hello_elapsed_ms + 4
hello_expand_output           equ hello_ticket_age + 4
hello_expand_context          equ hello_expand_output + 2
hello_expand_context_len      equ hello_expand_context + 2
hello_random                  equ hello_expand_context_len + 2
hello_session                 equ hello_random + 32
hello_client_x                equ hello_session + 32
hello_server_x_work           equ hello_client_x + 32
hello_state_clear_end         equ hello_server_x_work + 32
; Binder-only aliases.  Server-share work is empty before TCP; the
; authenticated one-shot module has already erased 4230..79ff.
hello_truncated_digest        equ hello_server_x_work
hello_secret_a                equ tls13_286_module_load
hello_secret_b                equ hello_secret_a + 32
hello_hkdf_info               equ hello_secret_b + 32
hello_hkdf_info_len           equ 64
hello_hkdf_block              equ hello_hkdf_info + hello_hkdf_info_len

hello_sha_work_start          equ 0x3d00
sha256_state                  equ hello_sha_work_start
sha256_a                      equ sha256_state + 32
sha256_b                      equ sha256_a + 4
sha256_c                      equ sha256_b + 4
sha256_d                      equ sha256_c + 4
sha256_e                      equ sha256_d + 4
sha256_f                      equ sha256_e + 4
sha256_g                      equ sha256_f + 4
sha256_h                      equ sha256_g + 4
sha256_t1                     equ sha256_h + 4
sha256_t2                     equ sha256_t1 + 4
sha256_new_e                  equ sha256_t2 + 4
sha256_tmp                    equ sha256_new_e + 4
sha256_w_ptr                  equ sha256_tmp + 4
sha256_k_ptr                  equ sha256_w_ptr + 2
sha256_len_low                equ sha256_k_ptr + 2
sha256_len_high               equ sha256_len_low + 2
sha256_saved_len_low          equ sha256_len_high + 2
sha256_saved_len_high         equ sha256_saved_len_low + 2
sha256_bit_len0               equ sha256_saved_len_high + 2
sha256_bit_len1               equ sha256_bit_len0 + 2
sha256_bit_len2               equ sha256_bit_len1 + 2
sha256_bit_len3               equ sha256_bit_len2 + 2
sha256_digest_ptr             equ sha256_bit_len3 + 2
hmac_key_ptr                  equ sha256_digest_ptr + 2
hmac_key_len                  equ hmac_key_ptr + 2
hmac_data1_ptr                equ hmac_key_len + 2
hmac_data1_len                equ hmac_data1_ptr + 2
hmac_data2_ptr                equ hmac_data1_len + 2
hmac_data2_len                equ hmac_data2_ptr + 2
hmac_output_ptr               equ hmac_data2_len + 2
sha256_block_len              equ hmac_output_ptr + 2
sha256_saved_block_len        equ sha256_block_len + 1
sha256_schedule_count         equ sha256_saved_block_len + 1
sha256_round_count            equ sha256_schedule_count + 1
sha256_block                  equ sha256_round_count + 1
sha256_w                      equ sha256_block + sha256_block_size
sha256_saved_state            equ sha256_w + sha256_k_len
sha256_saved_block            equ sha256_saved_state + 32
hmac_ipad                     equ sha256_saved_block + sha256_block_size
hmac_opad                     equ hmac_ipad + sha256_block_size
hmac_inner_digest             equ hmac_opad + sha256_block_size
hmac_prepared_inner_state     equ hmac_inner_digest + 32
hmac_prepared_outer_state     equ hmac_prepared_inner_state + 32
hello_sha_work_end            equ hmac_prepared_outer_state + 32

%if (hello_image_end - hello_header) > tls13_286_controller_max_bytes
%error "TLS 1.3 286 HELLO immutable image exceeds controller window"
%endif
%if hello_state_clear_end > hello_sha_work_start
%error "TLS 1.3 286 HELLO state overlaps SHA work"
%endif
%if hello_sha_work_end > tls13_286_client_x_public
%error "TLS 1.3 286 HELLO work exceeds root/controller scratch gap"
%endif
%if hello_prefix_fragment_len > hello_mss_max
%error "TLS 1.3 286 HELLO prefix exceeds MSS"
%endif
%if hello_tail_len > hello_mss_max
%error "TLS 1.3 286 HELLO tail exceeds MSS"
%endif
%if hello_prefix_extensions_len + tls13_286_hello_mlkem_ek_bytes + \
    hello_tail_len != hello_extensions_len
%error "TLS 1.3 286 HELLO extension accounting drifted"
%endif
%if hello_abort_capsule_blob_bytes > \
    (tls13_286_abort_capsule_limit - tls13_286_abort_capsule_load)
%error "TLS 1.3 286 embedded abort capsule exceeds its fixed band"
%endif
%if hello_abort_capsule_blob_bytes != \
    (tls13_286_abort_capsule_limit - tls13_286_abort_capsule_load)
%error "TLS 1.3 286 abort capsule no longer owns its frozen-geometry tail"
%endif
%if tls13_286_flight_stage_off + tls13_286_flight_stage_bytes >= 0x10000
%error "TLS 1.3 286 FLIGHT stage no longer guarantees a clear final carry"
%endif
