; RAM-only TLS 1.3 post-authentication route commit and credential unlock gate.
;
; The symmetric ticket stays in its native high-memory slots. The preceding
; issuer-authentication phase is assembled with TLS13_POC_READ_ONLY_INPUT, so
; its 175-byte input/output ABI lives below 0x3510 rather than colliding with
; that ticket. This final cold phase validates the authenticated issuer object
; plus the route-specific ticket contract, clears the retired issuer input,
; and publishes one commit byte last.
;
; Public ABI (near calls, DS=ES=SS=0, DF clear):
;   gate_commit: AX=nonzero attempt generation, BX=gate_route_*
;   gate_unlock: no inputs; caller registers carry no authority
;   gate_abort:  zeroize ticket, issuer, control, and canary state
;   gate_validate_ticket_only: read-only full-bundle validation, route 3 only
;
; gate_unlock invokes one build-time callback with AX=fixed phase key and
; BX=fixed destination. The resident callback must call gate_authorize_loader
; before reading, then publish a bounded credential descriptor status-last.
; Callback or publication failure clears only credential scratch and preserves
; the committed state for retry. Validation/commit failure zeroizes tentative
; security state. All failures return CF=1, AX=0; success returns CF=0, AX=1.
; This image contains no BIOS interrupt or write call.

bits 16
cpu 8086
org 0x1800

%ifndef GATE_CREDENTIAL_LOADER_CALLBACK
%define GATE_CREDENTIAL_LOADER_CALLBACK 0x1580
%endif
%ifndef GATE_CREDENTIAL_PHASE_KEY
%define GATE_CREDENTIAL_PHASE_KEY 0x6b14
%endif
%ifndef GATE_CREDENTIAL_DESTINATION
%define GATE_CREDENTIAL_DESTINATION 0x3400
%endif

gate_header:
    db 'ROG3'
    dw 4
    dw gate_image_end - gate_header
gate_entry_table:
    dw gate_commit
    dw gate_unlock
    dw gate_abort
    dw gate_authorize_loader
    dw gate_validate_ticket_only

issuer_commit_start         equ 0x3600
issuer_commit_status        equ issuer_commit_start
issuer_commit_reserved      equ issuer_commit_status + 1
issuer_commit_magic         equ issuer_commit_reserved + 1
issuer_commit_magic_inverse equ issuer_commit_magic + 4
issuer_commit_generation    equ issuer_commit_magic_inverse + 4
issuer_commit_profile       equ issuer_commit_generation + 2
issuer_commit_leaf_x        equ issuer_commit_profile + 2
issuer_commit_leaf_y        equ issuer_commit_leaf_x + 32
issuer_commit_cert_digest   equ issuer_commit_leaf_y + 32
issuer_commit_checksum_a    equ issuer_commit_cert_digest + 32
issuer_commit_checksum_b    equ issuer_commit_checksum_a + 2
issuer_commit_end           equ issuer_commit_checksum_b + 2
issuer_commit_check_start   equ issuer_commit_generation
issuer_commit_check_len     equ issuer_commit_checksum_a - issuer_commit_check_start
issuer_leaf_profile         equ 0x003f

; TLS13_POC_READ_ONLY_INPUT issuer ABI.
issuer_input_start          equ 0x3400
issuer_input_profile        equ issuer_input_start
issuer_input_generation     equ issuer_input_profile + 2
issuer_input_digest         equ issuer_input_generation + 2
issuer_input_signature_len  equ issuer_input_digest + 32
issuer_input_signature      equ issuer_input_signature_len + 2
issuer_input_leaf_x         equ issuer_input_signature + 72
issuer_input_leaf_y         equ issuer_input_leaf_x + 32
issuer_output_status        equ issuer_input_leaf_y + 32
issuer_input_end            equ issuer_output_status + 1
issuer_cv_profile           equ 0x0700

; Native symmetric ticket bundle.
sym_ticket_psk              equ 0x38b0
sym_ticket_psk_bytes        equ 32
sym_ticket_identity         equ 0x3b40
sym_ticket_identity_bytes   equ 192
sym_ticket_nonce            equ 0x3c00
sym_ticket_nonce_bytes      equ 32
sym_ticket_lifetime_hi      equ 0x3c20
sym_ticket_lifetime_lo      equ sym_ticket_lifetime_hi + 2
sym_ticket_age_add          equ sym_ticket_lifetime_lo + 2
sym_ticket_nonce_len        equ sym_ticket_age_add + 4
sym_ticket_identity_len     equ sym_ticket_nonce_len + 2
sym_ticket_present          equ sym_ticket_identity_len + 2
sym_ticket_end              equ sym_ticket_present + 1

; Retired record-header scratch becomes the tiny commit control block. It sits
; above the ticket and below the attempt-cache/reconnect boundary.
gate_control_start          equ 0x3c30
gate_control_generation     equ gate_control_start
gate_control_checksum       equ gate_control_generation + 2
gate_control_magic          equ gate_control_checksum + 2
gate_control_magic_inverse  equ gate_control_magic + 4
gate_control_route          equ gate_control_magic_inverse + 4
gate_control_route_inverse  equ gate_control_route + 1
gate_control_state_inverse  equ gate_control_route_inverse + 1
gate_control_state          equ gate_control_state_inverse + 1
gate_control_end            equ gate_control_state + 1
gate_route_live_no_ticket   equ 1
gate_route_live_ticket      equ 2
gate_route_ticket_only      equ 3
gate_state_committed        equ 0xc3
gate_state_unlocked         equ 0xe4

credential_destination      equ GATE_CREDENTIAL_DESTINATION
credential_key_max          equ 192
credential_capacity         equ credential_key_max + 1
credential_publication      equ gate_control_end
credential_checksum         equ credential_publication
credential_length           equ credential_checksum + 2
credential_status_inverse   equ credential_length + 2
credential_status           equ credential_status_inverse + 1
credential_publication_end  equ credential_status + 1
credential_status_ready     equ 0xa5

gate_commit:
    cld
    mov byte [gate_control_state], 0
    mov byte [gate_control_state_inverse], 0
    or ax, ax
    jz gate_failed
    cmp bx, gate_route_live_no_ticket
    je .route_valid
    cmp bx, gate_route_live_ticket
    je .route_valid
    cmp bx, gate_route_ticket_only
    jne gate_failed
.route_valid:
    mov [gate_control_generation], ax
    mov [gate_control_route], bl
    mov al, bl
    not al
    mov [gate_control_route_inverse], al
    call gate_validate_issuer
    jc gate_failed
    ; WE1 is the durable parser/issuer proof and must remain bound to its
    ; relocated pass-2 input. LP1 is emitted only by the fixed live-P256
    ; publication adapter after it reruns exact-leaf CertificateVerify.
    cmp word [issuer_commit_magic], 0x504c       ; "LP"
    je .issuer_ready
    cmp word [issuer_input_profile], issuer_cv_profile
    jne gate_failed
    mov ax, [gate_control_generation]
    cmp ax, [issuer_input_generation]
    jne gate_failed
    cmp byte [issuer_output_status], 1
    jne gate_failed
.issuer_ready:
    call gate_validate_route_ticket
    jc gate_failed

    call gate_bundle_checksum
    mov [gate_control_checksum], dx
    mov word [gate_control_magic], 0x4f52       ; "RO"
    mov word [gate_control_magic + 2], 0x3347   ; "G3"
    mov word [gate_control_magic_inverse], 0xb0ad
    mov word [gate_control_magic_inverse + 2], 0xccb8

    ; The pass-2 input is dead. Retire it before the atomic promotion store.
    push ds
    pop es
    push ax
    xor ax, ax
    mov di, issuer_input_start
    mov cx, issuer_input_end - issuer_input_start
    rep stosb
    pop ax
    mov byte [gate_control_state_inverse], 0x3c
    mov byte [gate_control_state], gate_state_committed
    jmp gate_succeeded

gate_unlock:
    cld
    call gate_validate_committed
    jc gate_failed
    cmp byte [gate_control_route], gate_route_live_no_ticket
    je .live
    cmp byte [gate_control_route], gate_route_live_ticket
    jne gate_unlock_retryable
.live:
    ; No prior or partial callback publication may satisfy this attempt.
    call gate_clear_credential
    mov ax, GATE_CREDENTIAL_PHASE_KEY
    mov bx, credential_destination
    call GATE_CREDENTIAL_LOADER_CALLBACK
    jc gate_unlock_retryable
    call gate_validate_credential
    jc gate_unlock_retryable
    mov byte [gate_control_state_inverse], 0x1b
    mov byte [gate_control_state], gate_state_unlocked
    jmp gate_succeeded

gate_unlock_retryable:
    call gate_clear_credential
    xor ax, ax
    stc
    ret

gate_validate_committed:
    cmp byte [gate_control_state], gate_state_committed
    jne gate_validation_failed
    cmp byte [gate_control_state_inverse], 0x3c
    jne gate_validation_failed
    cmp word [gate_control_magic], 0x4f52
    jne gate_validation_failed
    cmp word [gate_control_magic + 2], 0x3347
    jne gate_validation_failed
    cmp word [gate_control_magic_inverse], 0xb0ad
    jne gate_validation_failed
    cmp word [gate_control_magic_inverse + 2], 0xccb8
    jne gate_validation_failed
    cmp word [gate_control_generation], 0
    je gate_validation_failed
    call gate_validate_issuer
    jc gate_validation_failed
    call gate_validate_route_ticket
    jc gate_validation_failed
    call gate_bundle_checksum
    cmp dx, [gate_control_checksum]
    jne gate_validation_failed
    clc
    ret

; Fixed resident callback capability check. Revalidate the complete committed
; issuer/route/ticket bundle rather than trusting the public phase key or the
; four state/route marker bytes. The callback reaches this through the fourth
; fixed header entry, so it need not embed an internal code address.
gate_authorize_loader:
    cld
    call gate_validate_committed
    jc .failed
    cmp byte [gate_control_route], gate_route_live_no_ticket
    je gate_succeeded
    cmp byte [gate_control_route], gate_route_live_ticket
    je gate_succeeded
.failed:
    xor ax, ax
    stc
    ret

; Fixed resumption capability. Unlike gate_authorize_loader this accepts only
; TICKET_ONLY and exposes no credential callback. It gives the resumption
; dispatcher one stable way to validate the complete committed input bundle
; both before tentative key use and immediately before route promotion.
gate_validate_ticket_only:
    cld
    call gate_validate_committed
    jc .failed
    cmp byte [gate_control_route], gate_route_ticket_only
    jne .failed
    jmp gate_succeeded
.failed:
    xor ax, ax
    stc
    ret

gate_validate_issuer:
    cmp byte [issuer_commit_status], 1
    jne gate_validation_failed
    cmp byte [issuer_commit_reserved], 0
    jne gate_validation_failed
    cmp word [issuer_commit_magic + 2], 0x2131
    jne gate_validation_failed
    cmp word [issuer_commit_magic_inverse + 2], 0xdece
    jne gate_validation_failed
    cmp word [issuer_commit_magic], 0x4557       ; "WE"
    je .durable_issuer
    cmp word [issuer_commit_magic], 0x504c       ; "LP"
    jne gate_validation_failed
    cmp word [issuer_commit_magic_inverse], 0xafb3
    jne gate_validation_failed
    jmp .magic_valid
.durable_issuer:
    cmp word [issuer_commit_magic_inverse], 0xbaa8
    jne gate_validation_failed
.magic_valid:
    mov ax, [gate_control_generation]
    or ax, ax
    jnz .have_generation
    mov ax, [issuer_input_generation]
.have_generation:
    cmp ax, [issuer_commit_generation]
    jne gate_validation_failed
    cmp word [issuer_commit_profile], issuer_leaf_profile
    jne gate_validation_failed
    mov si, issuer_commit_check_start
    mov cx, issuer_commit_check_len
    call gate_issuer_checksum
    cmp ax, [issuer_commit_checksum_a]
    jne gate_validation_failed
    cmp dx, [issuer_commit_checksum_b]
    jne gate_validation_failed
    clc
    ret

gate_validate_route_ticket:
    mov al, [gate_control_route]
    mov ah, al
    not ah
    cmp ah, [gate_control_route_inverse]
    jne gate_validation_failed
    cmp al, gate_route_live_no_ticket
    je .without_ticket
    cmp al, gate_route_live_ticket
    je .with_ticket
    cmp al, gate_route_ticket_only
    jne gate_validation_failed
.with_ticket:
    call gate_validate_ticket
    ret
.without_ticket:
    cmp byte [sym_ticket_present], 0
    jne gate_validation_failed
    mov si, sym_ticket_psk
    mov cx, sym_ticket_psk_bytes
    call gate_validate_zero
    jc gate_validation_failed
    mov si, sym_ticket_identity
    mov cx, sym_ticket_end - sym_ticket_identity
    call gate_validate_zero
    ret

gate_validate_ticket:
    cmp byte [sym_ticket_present], 0
    je gate_validation_failed
    mov ax, [sym_ticket_identity_len]
    or ax, ax
    jz gate_validation_failed
    cmp ax, sym_ticket_identity_bytes
    ja gate_validation_failed
    mov ax, [sym_ticket_nonce_len]
    or ax, ax
    jz gate_validation_failed
    cmp ax, sym_ticket_nonce_bytes
    ja gate_validation_failed
    mov ax, [sym_ticket_lifetime_hi]
    mov dx, [sym_ticket_lifetime_lo]
    or ax, dx
    jz gate_validation_failed
    mov ax, [sym_ticket_lifetime_hi]
    cmp ax, 9
    ja gate_validation_failed
    jb .valid
    cmp dx, 0x3a80
    ja gate_validation_failed
.valid:
    clc
    ret

gate_validate_zero:
.byte:
    cmp byte [si], 0
    jne gate_validation_failed
    inc si
    loop .byte
    clc
    ret

; Same torn-handoff checksum used by issuer_auth_overlay.asm.
gate_issuer_checksum:
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

; Bind the route, generation, and fixed ticket slots to promoted control.
gate_bundle_checksum:
    push ax
    push cx
    push si
    xor dx, dx
    add dx, [gate_control_generation]
    xor ax, ax
    mov al, [gate_control_route]
    add dx, ax
    mov si, sym_ticket_psk
    mov cx, sym_ticket_psk_bytes
    call .sum
    mov si, sym_ticket_identity
    mov cx, sym_ticket_identity_bytes
    call .sum
    mov si, sym_ticket_nonce
    mov cx, sym_ticket_nonce_bytes
    call .sum
    mov si, sym_ticket_lifetime_hi
    mov cx, sym_ticket_end - sym_ticket_lifetime_hi
    call .sum
    not dx
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

; The callback owns this descriptor and must write status last. The gate
; clears it before every attempt, then requires a 1..192-byte publication,
; a trailing NUL, and a checksum matching the fixed destination.
gate_validate_credential:
    cmp byte [credential_status], credential_status_ready
    jne gate_validation_failed
    cmp byte [credential_status_inverse], 0x5a
    jne gate_validation_failed
    mov cx, [credential_length]
    or cx, cx
    jz gate_validation_failed
    cmp cx, credential_key_max
    ja gate_validation_failed
    push ax
    push cx
    push si
    xor dx, dx
    mov si, credential_destination
.byte:
    lodsb
    xor ah, ah
    add dx, ax
    loop .byte
    cmp byte [si], 0
    pop si
    pop cx
    pop ax
    jne gate_validation_failed
    or dx, dx
    jz gate_validation_failed
    cmp dx, [credential_checksum]
    jne gate_validation_failed
    clc
    ret

gate_clear_credential:
    cld
    push ds
    pop es
    xor ax, ax
    mov di, credential_publication
    mov cx, credential_publication_end - credential_publication
    rep stosb
    mov di, credential_destination
    mov cx, credential_capacity
    rep stosb
    ret

gate_abort:
    cld
    push ds
    pop es
    xor ax, ax
    mov di, issuer_input_start
    mov cx, issuer_input_end - issuer_input_start
    rep stosb
    mov di, issuer_commit_start
    mov cx, issuer_commit_end - issuer_commit_start
    rep stosb
    mov di, sym_ticket_psk
    mov cx, sym_ticket_psk_bytes
    rep stosb
    mov di, sym_ticket_identity
    mov cx, sym_ticket_end - sym_ticket_identity
    rep stosb
    mov di, gate_control_start
    mov cx, gate_control_end - gate_control_start
    rep stosb
    call gate_clear_credential
    xor ax, ax
    stc
    ret

gate_validation_failed:
    stc
    ret

gate_failed:
    call gate_abort
    ret

gate_succeeded:
    mov ax, 1
    clc
    ret

gate_image_end:

%if issuer_input_end > 0x3510
%error "relocated issuer input reaches symmetric extension work"
%endif
%if sym_ticket_end > gate_control_start
%error "native ticket reaches read-only commit control"
%endif
%if credential_publication_end > 0x3c9c
%error "read-only commit/publication control reaches reconnect state"
%endif
%if (gate_image_end - gate_header) > 1024
%error "read-only commit gate exceeds two sectors"
%endif
