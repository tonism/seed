; Seed TLS 1.3 same-machine ticket-resumption controller PoC.
;
; This cold controller occupies the retired HELLO/delta-loader tail immediately
; after the committed 0x0d00..0x0daa transcript handoff.  It is retired before
; the later PAK1/model publication reuses 0x0d00..0x0eff.  No product
; arena/context byte is used.
;
; Public ABI (near calls, DS=ES=SS=0, DF clear):
;   0 resume_stamp_nst
;       Called after an authenticated NST is committed.  Imports the original
;       validated card-tail receipt clock and publishes a RAM ticket binding.
;   1 resume_attempt
;       Requires a committed ROG3 TICKET_ONLY bundle.  Computes the real
;       obfuscated_ticket_age, drives HELLO + symmetric resumption through one
;       fixed callback, checks an exact certificate-free EE+Finished flight,
;       derives only the client application write key, sends the one immutable
;       credential-free HEAD, derives server-read/resumption state behind the
;       zero window before deferred ML-KEM FO, drains an authenticated response
;       after FO, and only then promotes route 3 -> 2.
;
; Fixed callback ABI:
;   AX=1 CLOCK       -> DX:AX BIOS ticks since midnight, BX monotonic day
;   AX=2 PREPARE     -> atomically consume/zero 0x0780..0x07ff
;                       d||z||random||session, run fresh KeyGen/card vault, and
;                       publish a verified binder plus retained early schedule
;   AX=3 EXCHANGE    -> binder-consuming strict HELLO handoff + provisional K'
;   AX=4 RECEIVE     -> exact encrypted resumed flight at 0x39a0
;   AX=5 DIALOGUE    -> consume/send the fixed 58-byte client Finished at
;                       0x39a0 and return behind zero window; the fixed public
;                       HEAD was already sent as accepted 0-RTT
;   AX=6 HEAD_ONLY   -> retained RSI1 compatibility entry; not used here
;   AX=7 EOED        -> recover/send pre-sealed EndOfEarlyData and append its
;                       four plaintext handshake bytes before Finished
;   AX=7 DEFERRED_FO -> full re-encryption proof bound to fresh ek+c, status last
;   AX=8 LIVENESS    -> authenticate and drain the HEAD response after FO
;   AX=9 ROUTE_VALID -> validate the complete ROG3 TICKET_ONLY bundle
;   AX=10 NST_VALID  -> validate the native ticket plus its card-tail receipt;
;                       return original receipt DX:AX ticks and BX day/wrap
;   AX=11 RESTORE    -> restore the PREPARE-vaulted issuer/ticket/control bundle
; All operations return CF clear on success.  No caller pointer, destination,
; credential, route, or media handle crosses this ABI.

bits 16
cpu 8086

%include "post_auth_resume_vault.inc"

%ifndef RESUME_CONTROLLER_ORIGIN
%define RESUME_CONTROLLER_ORIGIN 0x0dab
%endif
%ifndef RESUME_FIXED_CALLBACK
%define RESUME_FIXED_CALLBACK 0x0500
%endif
%ifndef RESUME_CONTROLLER_LIMIT
%define RESUME_CONTROLLER_LIMIT 0x1000
%endif
%ifndef RESUME_HIGH_PREFIX_ORIGIN
%define RESUME_HIGH_PREFIX_ORIGIN 0x3400
%endif
%ifndef RESUME_HIGH_SUFFIX_ORIGIN
%define RESUME_HIGH_SUFFIX_ORIGIN 0x355d
%endif
%ifdef RESUME_DEFER_CLIENT_APP_TO_SYM_IO
%ifndef RESUME_DIRECT_TCP_SEND
%error "deferred live resumption requires the fixed resident TCP sender"
%endif
%ifndef RESUME_DIRECT_ZERO_WINDOW
%error "deferred live resumption requires the fixed zero-window ACK"
%endif
%endif

section .resume_low start=0 vstart=RESUME_CONTROLLER_ORIGIN align=1

resume_header:
    db 'RSU1'
    dw 1
    dw (resume_low_end - resume_header) + \
       (resume_high_prefix_end - resume_high_prefix_start) + \
       (resume_high_suffix_end - resume_high_suffix_start)
    dw resume_low_end - resume_header
    dw resume_high_prefix_end - resume_high_prefix_start
    dw resume_high_suffix_end - resume_high_suffix_start
    dw resume_state_start
    dw resume_state_end
    dw RESUME_FIXED_CALLBACK
    dw resume_entry_count
resume_entry_table:
    dw resume_stamp_nst
    dw resume_attempt
resume_entry_count equ ($ - resume_entry_table) / 2

; Native symmetric ticket and ROG3 bundle.
ticket_psk                  equ 0x38b0
ticket_identity             equ 0x3b40
ticket_nonce                equ 0x3c00
ticket_lifetime_hi          equ 0x3c20
ticket_lifetime_lo          equ 0x3c22
ticket_age_add              equ 0x3c24
ticket_nonce_len            equ 0x3c28
ticket_identity_len         equ 0x3c2a
ticket_present              equ 0x3c2c
ticket_end                  equ 0x3c2d

gate_generation             equ 0x3c30
gate_checksum               equ 0x3c32
gate_magic                  equ 0x3c34
gate_magic_inverse          equ 0x3c38
gate_route                  equ 0x3c3c
gate_route_inverse          equ 0x3c3d
gate_state_inverse          equ 0x3c3e
gate_state                  equ 0x3c3f
gate_route_ticket_only      equ 3
gate_route_live_ticket      equ 2
gate_state_committed        equ 0xc3

; Receipt timestamp, attempt scratch, and status-last FO publications remain
; below reconnect state.  Credential publication occupies 0x3c40..0x3c45.
resume_state_start          equ 0x3c46
receipt_tick_lo             equ resume_state_start
receipt_tick_hi             equ receipt_tick_lo + 2
receipt_day                 equ receipt_tick_hi + 2
receipt_checksum            equ receipt_day + 2
receipt_magic               equ receipt_checksum + 2
receipt_magic_inverse       equ receipt_magic + 4
receipt_status_inverse      equ receipt_magic_inverse + 4
receipt_status              equ receipt_status_inverse + 1
attempt_tick_lo             equ receipt_status + 1
attempt_tick_hi             equ attempt_tick_lo + 2
attempt_day                 equ attempt_tick_hi + 2
attempt_age_wire            equ attempt_day + 2
attempt_ms                  equ attempt_age_wire + 4
candidate_generation        equ attempt_ms + 4
candidate_c_checksum        equ candidate_generation + 2
candidate_ek_checksum       equ candidate_c_checksum + 2
candidate_status_inverse    equ candidate_ek_checksum + 2
candidate_status            equ candidate_status_inverse + 1
fo_generation               equ candidate_status + 1
fo_c_checksum               equ fo_generation + 2
fo_ek_checksum              equ fo_c_checksum + 2
fo_status_inverse           equ fo_ek_checksum + 2
fo_status                   equ fo_status_inverse + 1
resume_state_end            equ fo_status + 1

sym_binder_hash             equ 0x3660
sym_input_hello_hash        equ 0x3640
sym_server_finished_hash    equ 0x3680
sym_received_finished       equ 0x38f0
sym_io                      equ 0x39a0
sym_entry_resumed_hs        equ 0x183c
sym_entry_import            equ 0x183e
sym_entry_derive_client_app equ 0x1840
sym_entry_derive_server_app equ 0x1842
sym_entry_auth_resume       equ 0x1844
sym_entry_build_head        equ 0x1836
rejected_finished_sent      equ 0x82

bios_ticks_day_hi           equ 0x0018
bios_ticks_day_lo           equ 0x00b0
resume_ticks_max_hi         equ 0x0012
resume_ticks_max_lo         equ 0x0084

resume_stamp_nst:
    cld
    mov byte [receipt_status], 0
    mov byte [receipt_status_inverse], 0
    mov ax, 10
    call RESUME_FIXED_CALLBACK
    jc resume_failed
    call resume_validate_clock
    jc resume_failed
    mov [receipt_tick_lo], ax
    mov [receipt_tick_hi], dx
    mov [receipt_day], bx
    call resume_ticket_sum
    add dx, [receipt_tick_lo]
    add dx, [receipt_tick_hi]
    add dx, [receipt_day]
    not dx
    mov [receipt_checksum], dx
    mov word [receipt_magic], 0x5352          ; "RS"
    mov word [receipt_magic + 2], 0x3154      ; "T1"
    mov word [receipt_magic_inverse], 0xacad
    mov word [receipt_magic_inverse + 2], 0xceab
    mov byte [receipt_status_inverse], 0x5a
    mov byte [receipt_status], 0xa5
    jmp resume_succeeded

resume_attempt:
    cld
    mov ax, 9
    call RESUME_FIXED_CALLBACK
    jc resume_failed
    call resume_validate_receipt
    jc resume_failed
    mov ax, 1
    call RESUME_FIXED_CALLBACK
    jc resume_failed
    call resume_validate_clock
    jc resume_failed
    mov [attempt_tick_lo], ax
    mov [attempt_tick_hi], dx
    mov [attempt_day], bx

    ; Same day requires a nondecreasing clock.  Exactly one day transition is
    ; accepted using the resident monotonic day counter; larger jumps fail.
    cmp bx, [receipt_day]
    jne .wrapped
    sub ax, [receipt_tick_lo]
    sbb dx, [receipt_tick_hi]
    jc resume_failed
    jmp .elapsed
.wrapped:
    mov cx, [receipt_day]
    inc cx
    cmp bx, cx
    jne resume_failed
    mov ax, bios_ticks_day_lo
    mov dx, bios_ticks_day_hi
    sub ax, [receipt_tick_lo]
    sbb dx, [receipt_tick_hi]
    add ax, [attempt_tick_lo]
    adc dx, [attempt_tick_hi]
.elapsed:
    cmp dx, resume_ticks_max_hi
    ja resume_failed
    jb .age
    cmp ax, resume_ticks_max_lo
    ja resume_failed
.age:
    call resume_ticks_to_ms
    mov [attempt_ms], ax
    mov [attempt_ms + 2], dx

    ; A sub-18-hour attempt fits a 16-bit seconds quotient.
    mov bx, 1000
    div bx
    cmp word [ticket_lifetime_hi], 0
    jne .lifetime_ok
    cmp ax, [ticket_lifetime_lo]
    jae resume_failed
.lifetime_ok:
    mov ax, [ticket_age_add]
    xchg al, ah
    mov bx, [ticket_age_add + 2]
    xchg bl, bh
    add bx, [attempt_ms]
    adc ax, [attempt_ms + 2]
    xchg al, ah
    mov [attempt_age_wire], ax
    xchg bl, bh
    mov [attempt_age_wire + 2], bx

    call resume_clear_proofs
    mov ax, 2
    call RESUME_FIXED_CALLBACK
resume_after_prepare_callback:
    jc resume_failed
    mov ax, 3
    call RESUME_FIXED_CALLBACK
    jc resume_failed
    call resume_validate_candidate
    jc resume_failed
    call word [sym_entry_import]
    jc resume_failed
    call word [sym_entry_resumed_hs]
    jc resume_failed
    call word [sym_entry_auth_resume]
    jc resume_failed

    ; The symmetric overlay authenticates the AEAD record before returning its
    ; bounded shape.  Exact plaintext and Finished verification below are the
    ; semantic authority for 1=accepted or 2=rejected early data.
    cmp ax, 1
    je .accepted_shape
    cmp ax, 2
    jne resume_failed
    mov si, resume_rejected_plaintext
    mov cx, 10
    mov bx, sym_io + 15
    jmp short .shape_ready
.accepted_shape:
    mov si, resume_accepted_plaintext
    mov cx, 14
    mov bx, sym_io + 19
.shape_ready:
    mov [attempt_day], al
    mov di, sym_io + 5
    repe cmpsb
    jne resume_failed
    cmp byte [bx + 32], 0x16
    jne resume_failed
    mov si, bx
    mov di, sym_received_finished
    mov cx, 16
    rep movsw
    call word [0x1830]                    ; sym_verify_server_finished
    jc resume_failed

    ; RSI1 operation 5 derives c ap traffic from this server-Finished-only
    ; snapshot on both branches.  Accepted EOED may temporarily advance the
    ; ordinary Finished slot, while rejected early data must omit EOED.
    mov si, sym_server_finished_hash
    mov di, sym_input_hello_hash
    mov cx, 16
    rep movsw
    cmp byte [attempt_day], 1
    jne .build_client_finished
    ; Operation 4 is now a fixed accepted-disposition preload: it installs
    ; RSI1 only after the symmetric overlay has authenticated the record and
    ; this controller has verified the exact plaintext and server Finished.
    mov ax, 4
    call RESUME_FIXED_CALLBACK
    jc resume_failed
    mov ax, 7
    call RESUME_DIRECT_SYM_IO_ENTRY
    jc resume_failed
.build_client_finished:
    call word [0x1832]                    ; sym_build_client_finished
    jc resume_failed
    cmp ax, 58
    jne resume_failed
    ; Standalone builds retain the original pre-Finished client-key schedule.
    ; The exact live profile defers it into resident RSI1, after the handshake
    ; record is transmitted but before HEAD is built.  This lets the peer see
    ; valid Finished dialogue before its short close edge without changing
    ; the application-key transcript or its first consumer.
%ifndef RESUME_DEFER_CLIENT_APP_TO_SYM_IO
    call word [sym_entry_derive_client_app]
    jc resume_failed
%else
    ; On authenticated rejection, put Finished on the wire first, then derive
    ; the client application key and replay HEAD directly through the resident
    ; symmetric/TCP entries.  Loading RSI1 before Finished consumes the
    ; absolute peer deadline without adding security authority; deferred FO
    ; still gates route and credentials.
    cmp byte [attempt_day], 2
    jne .dispatch_finished
    mov si, sym_io
    mov cx, 58
    call RESUME_DIRECT_TCP_SEND
    jc resume_failed
    ; Rejection makes post-handshake traffic immediately sendable.  Hold it
    ; while the deferred client-application schedule runs so the tiny receive
    ; path is not overrun.  This is only guest-side flow control: it does not
    ; refresh the peer's absolute SYN-to-request deadline.  Failure is observed
    ; by the later send/drain authority gates and publishes no secure state.
    call RESUME_DIRECT_ZERO_WINDOW
    call word [sym_entry_derive_client_app]
    jc resume_failed
    call word [sym_entry_build_head]
    jc resume_failed
%ifdef RESUME_DIRECT_REPLAY_DIAGNOSTIC
    ; sym_build_head returns AX=72, whose low byte is an unambiguous "H".
    ; Preserve AX for the exact-length check while saving two diagnostic bytes.
    call resume_diag_mark
%endif
    cmp ax, 72
    jne resume_failed
    mov si, sym_io
    mov cx, 72
    call RESUME_DIRECT_TCP_SEND
    jc resume_failed
    jmp resume_valid_dialogue
.dispatch_finished:
%endif
%ifdef RESUME_DIRECT_SYM_IO_ENTRY
%ifdef RESUME_DEFER_CLIENT_APP_TO_SYM_IO
    mov ax, 5
    call RESUME_DIRECT_SYM_IO_ENTRY
%else
    mov ax, 5
    call RESUME_DIRECT_SYM_IO_ENTRY
%endif
%else
    mov ax, 5
    call RESUME_FIXED_CALLBACK
%endif
    jc resume_failed
.valid_dialogue:
    jmp resume_valid_dialogue

%ifndef RESUME_DIRECT_REPLAY_DIAGNOSTIC
resume_rejected_plaintext:
    db 0x08,0x00,0x00,0x02,0x00,0x00
    db 0x14,0x00,0x00,0x20
%endif

; The direct rejected-Finished seam uses the last available low-sector tail.
; Low tail (0x50) + prefix (0x10d) + suffix (0xa3) is exactly one packed
; restore sector; the first 0x200 bytes remain the controller head sector.
times 0x0250 - ($ - resume_header) nop
resume_low_end:

section .resume_high_prefix follows=.resume_low \
    vstart=RESUME_HIGH_PREFIX_ORIGIN align=1

resume_high_prefix_start:
resume_accepted_plaintext:
    db 0x08,0x00,0x00,0x06,0x00,0x04,0x00,0x2a,0x00,0x00
    db 0x14,0x00,0x00,0x20
%ifdef RESUME_DIRECT_REPLAY_DIAGNOSTIC
resume_rejected_plaintext:
    db 0x08,0x00,0x00,0x02,0x00,0x00
    db 0x14,0x00,0x00,0x20
%endif

resume_validate_clock:
    cmp dx, bios_ticks_day_hi
    ja .bad
    jb .ok
    cmp ax, bios_ticks_day_lo
    jae .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

resume_validate_receipt:
    cmp byte [receipt_status], 0xa5
    jne .bad
    cmp byte [receipt_status_inverse], 0x5a
    jne .bad
    cmp word [receipt_magic], 0x5352
    jne .bad
    cmp word [receipt_magic + 2], 0x3154
    jne .bad
    cmp word [receipt_magic_inverse], 0xacad
    jne .bad
    cmp word [receipt_magic_inverse + 2], 0xceab
    jne .bad
    call resume_ticket_sum
    add dx, [receipt_tick_lo]
    add dx, [receipt_tick_hi]
    add dx, [receipt_day]
    not dx
    cmp dx, [receipt_checksum]
    jne .bad
    clc
    ret
.bad:
    stc
    ret

resume_ticket_sum:
    push ax
    push cx
    push si
    xor dx, dx
    mov si, ticket_psk
    mov cx, 32
    call .sum
    mov si, ticket_identity
    mov cx, 192
    call .sum
    mov si, ticket_nonce
    mov cx, ticket_end - ticket_nonce
    call .sum
    pop si
    pop cx
    pop ax
    ret
.sum:
    lodsb
    xor ah, ah
    add dx, ax
    loop .sum
    ret

resume_ticks_to_ms:
    mov [attempt_tick_lo], ax
    mov [attempt_tick_hi], dx
    mov cx, dx
    mov bx, 55
    mul bx
    mov [attempt_ms], ax
    mov si, dx
    mov ax, cx
    mul bx
    add si, ax
    mov [attempt_ms + 2], si
    mov ax, [attempt_tick_lo]
    mov bx, 611
    mul bx
    mov si, ax
    mov di, dx
    mov ax, [attempt_tick_hi]
    mul bx
    add di, ax
    mov cx, 13
.shift:
    shr di, 1
    rcr si, 1
    loop .shift
    mov ax, [attempt_ms]
    mov dx, [attempt_ms + 2]
    sub ax, si
    sbb dx, di
    ret

resume_valid_dialogue:
    ; Operation 6 has sent the complete HEAD and advertised a zero receive
    ; window.  Derive server-read and resumption state while the peer is held,
    ; before the deliberately expensive deferred FO proof.
    call word [sym_entry_derive_server_app]
    jc resume_failed
%ifdef RESUME_CONTROLLER_DIAGNOSTIC
%ifdef RESUME_OUTER_AFTER_LIVENESS
    mov al, 'F'
    call resume_diag_mark
%endif
%endif
    mov ax, 7
    call RESUME_FIXED_CALLBACK
    jc resume_failed
%ifdef RESUME_CONTROLLER_DIAGNOSTIC
%ifdef RESUME_OUTER_AFTER_LIVENESS
    mov al, 'G'
    call resume_diag_mark
%endif
%endif
    call resume_validate_fo
    jc resume_failed
%ifdef RESUME_OUTER_AFTER_LIVENESS
    ; The liveness worker cold-loads at 0x0900 and therefore destroys this
    ; RSU1 caller before it returns. Tail-dispatch it to the fixed outer
    ; continuation instead. MOV/PUSH is used because PUSH imm16 is not 8086.
    mov ax, RESUME_OUTER_AFTER_LIVENESS
    push ax
    mov ax, 8
    jmp RESUME_FIXED_CALLBACK
%else
    mov ax, 8
    call RESUME_FIXED_CALLBACK
    jc resume_failed
    mov ax, 9
    call RESUME_FIXED_CALLBACK
    jc resume_failed
    jmp resume_promote
%endif

%ifdef RESUME_DIRECT_REPLAY_DIAGNOSTIC
resume_diag_mark:
    mov dx, 0x03f8
    out dx, al
    ret
%elifdef RESUME_CONTROLLER_DIAGNOSTIC
resume_diag_mark:
    mov dx, 0x03f8
    out dx, al
    ret
%endif

resume_high_prefix_end:

section .resume_high_suffix follows=.resume_high_prefix \
    vstart=RESUME_HIGH_SUFFIX_ORIGIN align=1

resume_high_suffix_start:

resume_clear_proofs:
    push ds
    pop es
    xor ax, ax
    mov di, candidate_generation
    mov cx, resume_state_end - candidate_generation
    rep stosb
    ret

resume_validate_candidate:
    cmp byte [ticket_present], 1
    jne resume_validation_failed
    cmp byte [candidate_status], 0xa5
    jne resume_validation_failed
    cmp byte [candidate_status_inverse], 0x5a
    jne resume_validation_failed
    ; PREPARE retires the native gate bundle after committing its authenticated
    ; card vault.  Until operation 9 restores that bundle, RVL1 owns the
    ; generation authority for both candidate and deferred-FO publication.
    mov ax, [resume_vault_lifecycle_generation]
    cmp ax, [candidate_generation]
    jne resume_validation_failed
    cmp word [candidate_c_checksum], 0
    je resume_validation_failed
    cmp word [candidate_ek_checksum], 0
    je resume_validation_failed
    clc
    ret

resume_validate_fo:
    cmp byte [fo_status], 0xa5
    jne resume_validation_failed
    cmp byte [fo_status_inverse], 0x5a
    jne resume_validation_failed
    mov ax, [resume_vault_lifecycle_generation]
    cmp ax, [fo_generation]
    jne resume_validation_failed
    mov ax, [candidate_c_checksum]
    or ax, ax
    jz resume_validation_failed
    cmp ax, [fo_c_checksum]
    jne resume_validation_failed
    mov ax, [candidate_ek_checksum]
    or ax, ax
    jz resume_validation_failed
    cmp ax, [fo_ek_checksum]
    jne resume_validation_failed
    clc
    ret

resume_promote:
    ; Promotion is status-last.  The bundle sum loses one when route 3 -> 2,
    ; therefore its complemented checksum gains one.
    mov byte [gate_state], 0
    mov byte [gate_state_inverse], 0
    mov byte [gate_route], gate_route_live_ticket
    mov byte [gate_route_inverse], 0xfd
    inc word [gate_checksum]
    mov byte [gate_state_inverse], 0x3c
    mov byte [gate_state], gate_state_committed
    jmp resume_succeeded

resume_validation_failed:
    stc
    ret

resume_failed:
    mov ax, 11
    call RESUME_FIXED_CALLBACK
    xor ax, ax
    stc
    ret

resume_succeeded:
    mov ax, 1
    clc
    ret

resume_high_suffix_end:

%if resume_state_end > 0x3c9c
%error "resumption state reaches reconnect state"
%endif
%if (resume_low_end - resume_header) > \
    (RESUME_CONTROLLER_LIMIT - RESUME_CONTROLLER_ORIGIN)
%error "resumption controller exceeds retired HELLO low tail"
%endif
%if (resume_high_prefix_end - resume_high_prefix_start) > 0x110
%error "resumption controller prefix reaches symmetric K14 work"
%endif
%if (resume_high_suffix_end - resume_high_suffix_start) > 0x0a3
%error "resumption controller suffix exceeds K14 extension"
%endif
%if RESUME_HIGH_PREFIX_ORIGIN < RESUME_CONTROLLER_LIMIT
%if RESUME_HIGH_PREFIX_ORIGIN < \
    RESUME_CONTROLLER_ORIGIN + (resume_low_end - resume_header)
%error "low resumption prefix overlaps the controller low span"
%endif
%if RESUME_HIGH_PREFIX_ORIGIN + \
    (resume_high_prefix_end - resume_high_prefix_start) > \
    RESUME_CONTROLLER_LIMIT
%error "low resumption prefix exceeds the controller low slot"
%endif
%else
%if RESUME_HIGH_PREFIX_ORIGIN < 0x3400
%error "high resumption prefix starts below the K14 extension"
%endif
%if RESUME_HIGH_PREFIX_ORIGIN + \
    (resume_high_prefix_end - resume_high_prefix_start) > 0x3510
%error "high resumption prefix reaches symmetric mutable state"
%endif
%endif
%if RESUME_HIGH_SUFFIX_ORIGIN < RESUME_CONTROLLER_LIMIT
%if RESUME_HIGH_SUFFIX_ORIGIN < \
    RESUME_CONTROLLER_ORIGIN + (resume_low_end - resume_header)
%error "low resumption suffix overlaps the controller low span"
%endif
%if RESUME_HIGH_PREFIX_ORIGIN < RESUME_CONTROLLER_LIMIT
%if RESUME_HIGH_SUFFIX_ORIGIN < \
    RESUME_HIGH_PREFIX_ORIGIN + \
    (resume_high_prefix_end - resume_high_prefix_start)
%error "low resumption suffix overlaps the relocated prefix"
%endif
%endif
%if RESUME_HIGH_SUFFIX_ORIGIN + \
    (resume_high_suffix_end - resume_high_suffix_start) > \
    RESUME_CONTROLLER_LIMIT
%error "low resumption suffix exceeds the controller low slot"
%endif
%else
%if RESUME_HIGH_SUFFIX_ORIGIN < 0x355d
%error "high resumption suffix overlaps K14 mutable state"
%endif
%if RESUME_HIGH_SUFFIX_ORIGIN + \
    (resume_high_suffix_end - resume_high_suffix_start) > 0x3600
%error "high resumption suffix exceeds the K14 extension"
%endif
%endif
