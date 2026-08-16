; Final status-last publication for the 16 KiB TLS 1.3 K14 route.
;
; This phase runs only after exact leaf authentication, same-boot resumption,
; resumed FO validation, authenticated liveness, and route promotion.  It
; copies the resumed application state into the product ABI, reloads the full
; config escrow and validates it, zeroizes the volatile vault, erases retired
; bootstrap state, and publishes tls_key_schedule_ready last.

bits 16
cpu 8086

%include "tls13/k14_product_emergency_vault.inc"

%ifndef PRODUCT_PUBLISH_ORIGIN
%define PRODUCT_PUBLISH_ORIGIN 0x0900
%endif
%ifndef PRODUCT_VAULT_LIFECYCLE_KEY
%error "product publication requires the vault lifecycle phase key"
%endif
%ifndef PRODUCT_VAULT_LIFECYCLE_STAGE
%error "product publication requires the vault lifecycle stage"
%endif
%ifndef PRODUCT_VAULT_ZEROIZE
%error "product publication requires the vault zeroize callback"
%endif
%ifndef PRODUCT_CONFIG_ESCROW_KEY
%error "product publication requires the config-escrow phase key"
%endif
%ifndef PRODUCT_CONFIG_ESCROW_STAGE
%error "product publication requires the config-escrow stage"
%endif
%ifndef PRODUCT_CONFIG_ESCROW_RESTORE
%error "product publication requires the config-escrow restore callback"
%endif
%ifndef PRODUCT_CLIENT_KEY_DEST
%error "product publication requires the client-key destination"
%endif
%ifndef PRODUCT_SERVER_KEY_DEST
%error "product publication requires the server-key destination"
%endif
%ifndef PRODUCT_CLIENT_IV_DEST
%error "product publication requires the client-IV destination"
%endif
%ifndef PRODUCT_SERVER_IV_DEST
%error "product publication requires the server-IV destination"
%endif
%ifndef PRODUCT_CLIENT_SEQ_DEST
%error "product publication requires the client-sequence destination"
%endif
%ifndef PRODUCT_SERVER_SEQ_DEST
%error "product publication requires the server-sequence destination"
%endif
%ifndef PRODUCT_TLS_READY
%error "product publication requires tls_key_schedule_ready"
%endif
%ifndef PRODUCT_APP_CURSOR_START
%error "product publication requires the resident application-cursor start"
%endif
%ifndef PRODUCT_APP_CURSOR_END
%error "product publication requires the resident application-cursor end"
%endif
%ifndef PRODUCT_ROOT_FRAME_SP
%error "product publication requires the status-last root-frame SP"
%endif
%ifndef PRODUCT_ROOT_FRAME_SP_INVERSE
%error "product publication requires the root-frame SP inverse"
%endif
%ifndef PRODUCT_ROOT_FRAME_STATUS_WORD
%error "product publication requires the root-frame status word"
%endif
%ifndef PRODUCT_HANDOFF_RAM_TOP
%error "product publication requires the resident RAM-top handoff"
%endif
%ifndef PRODUCT_ROOT_RETURN
%error "product publication requires the generated resident root return"
%endif
%ifndef PRODUCT_EMERGENCY_RESET
%error "product publication requires the stackless emergency reset"
%endif

%if (PRODUCT_APP_CURSOR_START & 1) || (PRODUCT_APP_CURSOR_END & 1)
%error "product application-cursor scrub requires word alignment"
%endif
%if PRODUCT_APP_CURSOR_START >= PRODUCT_APP_CURSOR_END
%error "product application-cursor scrub range is empty"
%endif

org PRODUCT_PUBLISH_ORIGIN

resident_load_phase            equ 0x10c4
source_client_key              equ 0x3838
source_client_iv               equ 0x3858
source_server_key              equ 0x3864
source_server_iv               equ 0x3884
source_client_sequence         equ 0x38e0
source_server_sequence         equ 0x38e8

k14_product_publication:
    ; The composed route deliberately moves through several cold overlays
    ; after the root published its sole recoverable call frame.  Do not trust
    ; the active success stack merely because every intended path balances:
    ; validate the status-last snapshot without touching the current stack,
    ; then adopt it before the first PUSH/CALL.  Any torn frame goes directly
    ; to the already-gated stackless scrub/reset capsule.
    cli
    cld
    xor ax, ax
    mov ds, ax
    mov ss, ax
    mov byte [PRODUCT_TLS_READY], 0
    cmp word [PRODUCT_ROOT_FRAME_STATUS_WORD], 0xa55a
    jne .root_frame_failed
    mov bx, [PRODUCT_ROOT_FRAME_SP]
    mov ax, [PRODUCT_ROOT_FRAME_SP_INVERSE]
    not ax
    cmp ax, bx
    jne .root_frame_failed
    mov ax, [PRODUCT_HANDOFF_RAM_TOP]
    sub ax, 6
    cmp ax, bx
    jne .root_frame_failed
    cmp word [bx], PRODUCT_ROOT_RETURN
    jne .root_frame_failed
    mov sp, bx
    sti

    push ds
    pop es

    mov si, source_client_key
    mov di, PRODUCT_CLIENT_KEY_DEST
    mov cx, 16
    rep movsw
    mov si, source_server_key
    mov di, PRODUCT_SERVER_KEY_DEST
    mov cx, 16
    rep movsw
    mov si, source_client_iv
    mov di, PRODUCT_CLIENT_IV_DEST
    mov cx, 6
    rep movsw
    mov si, source_server_iv
    mov di, PRODUCT_SERVER_IV_DEST
    mov cx, 6
    rep movsw
    mov si, source_client_sequence
    mov di, PRODUCT_CLIENT_SEQ_DEST
    mov cx, 4
    rep movsw
    mov si, source_server_sequence
    mov di, PRODUCT_SERVER_SEQ_DEST
    mov cx, 4
    rep movsw

    ; Retire protocol material first, while deliberately leaving the
    ; 0x3b9c..0x3c9b config destination untouched.  The validated escrow then
    ; restores that band and the five UI/control bytes erased at 0x0d00.
    call k14_product_scrub_retired
    mov ax, PRODUCT_CONFIG_ESCROW_KEY
    mov bx, PRODUCT_CONFIG_ESCROW_STAGE
    call resident_load_phase
    jc .emergency_failed
    call PRODUCT_CONFIG_ESCROW_RESTORE
    jc .emergency_failed

    ; Reload the complete lifecycle at a safe phase boundary only after the
    ; escrow has been restored and erased. The three-sector image ends below
    ; the config-escrow code at 0x2c00.
    mov ax, PRODUCT_VAULT_LIFECYCLE_KEY
    mov bx, PRODUCT_VAULT_LIFECYCLE_STAGE
    call resident_load_phase
    jc .emergency_failed
    call PRODUCT_VAULT_ZEROIZE
    jc .emergency_failed

    ; The K14 handshake uses its own record parser and never initializes the
    ; resident application's ephemeral TCP/TLS tail.  The established
    ; connection state lives at 0x0600..0x06ff, so clear the whole 0x0fe2
    ; tail before READY becomes observable.  Otherwise a nonzero pre-route
    ; scratch value can be mistaken for queued ciphertext and fail the first
    ; business receive before the peer replies.
    push ds
    pop es
    xor ax, ax
    mov di, PRODUCT_APP_CURSOR_START
    mov cx, (PRODUCT_APP_CURSOR_END - PRODUCT_APP_CURSOR_START) / 2
    rep stosw

    mov byte [PRODUCT_TLS_READY], 1
    mov ax, 1
    clc
    ret

.emergency_failed:
    call k14_product_emergency_vault_zeroize
    call k14_product_scrub_published
    call k14_product_scrub_retired
    mov byte [PRODUCT_TLS_READY], 0
    xor ax, ax
    stc
    ret

.root_frame_failed:
    jmp PRODUCT_EMERGENCY_RESET

; Erase only the newly copied product state.  This is used when vault
; zeroization fails, before the common retired-state scrub.
k14_product_scrub_published:
    push ds
    pop es
    xor ax, ax
    mov di, PRODUCT_CLIENT_KEY_DEST
    mov cx, 16
    rep stosw
    mov di, PRODUCT_SERVER_KEY_DEST
    mov cx, 16
    rep stosw
    mov di, PRODUCT_CLIENT_IV_DEST
    mov cx, 6
    rep stosw
    mov di, PRODUCT_SERVER_IV_DEST
    mov cx, 6
    rep stosw
    mov di, PRODUCT_CLIENT_SEQ_DEST
    mov cx, 4
    rep stosw
    mov di, PRODUCT_SERVER_SEQ_DEST
    mov cx, 4
    rep stosw
    ret

; Preserve resident connection state at 0600..06ff, the ephemeral tail at
; 0fe2..0fff until the caller publishes a canonical zeroed handoff, the
; product application state at 3600..3667, and the caller stack. Everything
; else here is retired K14 bootstrap, candidate, ticket, issuer, or route
; material.
k14_product_scrub_retired:
    push ds
    pop es
    xor ax, ax
    mov di, 0x0700
    mov cx, (0x0900 - 0x0700) / 2
    rep stosw
    mov di, 0x0d00
    mov cx, (0x0fe2 - 0x0d00) / 2
    rep stosw
    mov di, 0x1800
    mov cx, (0x3600 - 0x1800) / 2
    rep stosw
    mov di, 0x3668
    mov cx, (0x3b9c - 0x3668) / 2
    rep stosw
    ret

K14_PRODUCT_EMERGENCY_VAULT_ROUTINE k14_product_emergency_vault_zeroize

k14_product_publication_end:

%if (k14_product_publication_end - k14_product_publication) > 512
%error "K14 product publication exceeds its one-sector phase"
%endif
