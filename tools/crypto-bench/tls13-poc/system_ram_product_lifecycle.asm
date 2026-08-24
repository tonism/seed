; Conventional-RAM lifecycle for the integrated 16 KiB TLS 1.3 route.
;
; All entries are offline: the peer is closed or held at a zero receive
; window.  They compact only the state needed across regenerated KeyGen/FO,
; never touch display/card RAM, and never borrow the cached configuration or
; the user arena/context band.

bits 16
cpu 8086
org 0x0900

%ifndef SYSRAM_LOW_ABORT_PATH
%error "define SYSRAM_LOW_ABORT_PATH to the checked low abort image"
%endif

capsule_low                 equ 0x0700
capsule_high                equ 0x3400
capsule_len                 equ 336
cap_root                    equ 0
cap_provisional             equ 32
cap_auth_digest             equ 64
cap_auth_signature_len      equ 96
cap_auth_signature          equ 98
cap_auth_status             equ 170
cap_client_key              equ 171
cap_client_iv               equ 203
cap_client_seq              equ 215
cap_server_key              equ 223
cap_server_iv               equ 255
cap_server_seq              equ 267
cap_resumption_master       equ 275
cap_fo_status               equ 307
cap_lifecycle_status        equ 308

acq_hold                    equ 0x2f40
acq_hold_root               equ acq_hold
acq_hold_provisional        equ acq_hold + 32
acq_hold_auth_digest        equ acq_hold + 64
acq_hold_auth_status        equ acq_hold + 170
acq_ticket_status           equ acq_hold + 171

sym_root                    equ 0x3600
sym_provisional             equ 0x3620
sym_client_key              equ 0x3838
sym_client_iv               equ 0x3858
sym_server_key              equ 0x3864
sym_server_iv               equ 0x3884
sym_resumption_master       equ 0x3890
sym_client_seq              equ 0x38e0
sym_server_seq              equ 0x38e8

sym_ticket_psk              equ 0x38b0
sym_ticket_identity         equ 0x39a0
sym_ticket_nonce            equ 0x3a60
sym_ticket_metadata         equ 0x3a80
sym_ticket_lifetime_hi      equ sym_ticket_metadata
sym_ticket_lifetime_lo      equ sym_ticket_metadata + 2
sym_ticket_age_add          equ sym_ticket_metadata + 4
sym_ticket_identity_len     equ sym_ticket_metadata + 10

compact_root                equ 0x35c0
compact_root_status         equ 0x35e0
compact_root_inverse        equ 0x35e1
post_ticket_tick            equ 0x35fc

; After compact_root moves into the resumed input capsule, its retired slot
; carries the exact same-boot age inputs across regenerated KeyGen.  The
; resume-ready tail converts and erases them immediately before HELLO.
resume_age_tick_lo          equ compact_root
resume_age_tick_hi          equ resume_age_tick_lo + 2
resume_age_lifetime_hi      equ resume_age_tick_hi + 2
resume_age_lifetime_lo      equ resume_age_lifetime_hi + 2
resume_age_work_lo          equ resume_age_lifetime_lo + 2
resume_age_work_hi          equ resume_age_work_lo + 2
resume_age_state_end        equ resume_age_work_hi + 2

resume_random               equ 0x3420
resume_session              equ 0x3440
resume_psk                  equ 0x3460
resume_age                  equ 0x3480
resume_identity_len         equ 0x3484
resume_identity             equ 0x3486
resume_identity_max         equ 192

fo_selected_secret          equ 0x3a60

sysram_lifecycle_header:
    db 'SRP1'
    dw 1
    dw sysram_lifecycle_end - sysram_lifecycle_header
    dw sysram_lifecycle_entry_count
sysram_lifecycle_entry_table:
    dw lifecycle_acquisition_pack
    dw lifecycle_transition_to_fo
    dw lifecycle_acquisition_validate_fo
    dw lifecycle_acquisition_restore
    dw lifecycle_acquisition_prepare_resumption
    dw lifecycle_resumption_pack
    dw lifecycle_resumption_validate_fo
    dw lifecycle_resumption_restore
sysram_lifecycle_entry_count equ ($ - sysram_lifecycle_entry_table) / 2

; Capture root/provisional/CV plus the complete fresh application state before
; regenerated epoch-0 KeyGen replaces the acquisition symmetric image.
lifecycle_acquisition_pack:
    cld
    cmp byte [acq_hold_auth_status], 0x5a
    jne lifecycle_failed
    push ds
    pop es
    xor ax, ax
    mov di, capsule_low
    mov cx, capsule_len / 2
    rep stosw
    mov si, acq_hold
    mov di, capsule_low
    mov cx, 171
    rep movsb
    mov si, sym_client_key
    mov di, capsule_low + cap_client_key
    mov cx, 32
    rep movsb
    mov si, sym_client_iv
    mov cx, 12
    rep movsb
    mov si, sym_client_seq
    mov cx, 8
    rep movsb
    mov si, sym_server_key
    mov cx, 32
    rep movsb
    mov si, sym_server_iv
    mov cx, 12
    rep movsb
    mov si, sym_server_seq
    mov cx, 8
    rep movsb
    mov si, sym_resumption_master
    mov cx, 32
    rep movsb
    mov byte [capsule_low + cap_lifecycle_status], 0x5a
    call reshape_acquisition_ciphertext
    call clear_retired_symmetric
    clc
    ret

; Shared post-KeyGen/candidate transition: consolidate c and ek for the exact
; FO image, then move the compact retained capsule above both objects.
lifecycle_transition_to_fo:
    cld
    push ds
    pop es
    mov si, 0x3400
    mov di, 0x3600
    mov cx, 448
    rep movsb
    mov si, 0x0500
    mov cx, 256
    rep movsb
    mov si, 0x0d60
    mov cx, 96
    rep movsb
    mov si, 0x0de0
    mov cx, 288
    rep movsb
    ; Candidate already staged ek[64..1088) at its final 2440..2840 home
    ; before this 0900..0cff lifecycle phase replaced the public source.
    mov si, 0x08c0
    mov di, 0x2400
    mov cx, 64 / 2
    rep movsw
    mov si, 0x0d00
    mov di, 0x2840
    mov cx, 96 / 2
    rep movsw
    mov si, capsule_low
    mov di, capsule_high
    mov cx, capsule_len / 2
    rep movsw
    xor ax, ax
    mov di, capsule_low
    mov cx, capsule_len / 2
    rep stosw
    ; Clear only the public-ek fragments outside this executing phase.  The
    ; middle source is already gone because loading lifecycle replaced it.
    mov di, 0x08c0
    mov cx, 64 / 2
    rep stosw
    mov di, 0x0d00
    mov cx, 96 / 2
    rep stosw
    mov di, 0x0d60
    mov cx, 96 / 2
    rep stosw
    mov di, 0x0de0
    mov cx, 288 / 2
    rep stosw
    clc
    ret

lifecycle_acquisition_validate_fo:
    cld
    cmp byte [capsule_high + cap_lifecycle_status], 0x5a
    jne lifecycle_failed
    call compare_selected_secret
    jc lifecycle_failed
    mov byte [capsule_high + cap_fo_status], 0xa5
    clc
    ret

; Called after exact-leaf P-256 auth and a fresh acquisition sym_init.  Restore
; only application traffic/resumption state, compact the root out of the
; response quarantine, and reinstall the low disk-independent abort that the
; P-256 work overlay necessarily erased.
lifecycle_acquisition_restore:
    cld
    cmp byte [capsule_high + cap_fo_status], 0xa5
    jne lifecycle_failed
    cmp byte [capsule_high + cap_auth_status], 1
    jne lifecycle_failed
    call restore_application_state
    mov si, capsule_high + cap_resumption_master
    mov di, sym_resumption_master
    mov cx, 32
    rep movsb
    mov si, capsule_high + cap_root
    mov di, compact_root
    mov cx, 32
    rep movsb
    mov byte [compact_root_status], 0xa5
    mov byte [compact_root_inverse], 0x5a
    xor ax, ax
    mov di, capsule_high
    mov cx, capsule_len / 2
    rep stosw
    call install_low_abort
    clc
    ret

; Consume the authenticated fresh ticket and compact root into the exact
; resumed HELLO input ABI.  Keep ticket_age_add plus the monotonic receipt
; tick/lifetime until regenerated KeyGen completes; the resume-ready tail
; adds measured elapsed milliseconds immediately before HELLO.  This uses no
; RTC or wall-clock trust.
lifecycle_acquisition_prepare_resumption:
    cld
    cmp word [compact_root_status], 0x5aa5
    jne lifecycle_failed
    cmp byte [acq_ticket_status], 0
    je lifecycle_failed
    mov cx, [sym_ticket_identity_len]
    or cx, cx
    jz lifecycle_failed
    cmp cx, resume_identity_max
    ja lifecycle_failed
    push ds
    pop es
    mov si, compact_root
    mov di, capsule_high
    mov cx, 32 / 2
    rep movsw
    xor ax, ax
    mov di, resume_random
    mov cx, 64 / 2
    rep stosw
    mov si, sym_ticket_psk
    mov di, resume_psk
    mov cx, 32 / 2
    rep movsw
    mov si, sym_ticket_age_add
    mov di, resume_age
    mov cx, 4
    rep movsb
    mov ax, [sym_ticket_identity_len]
    mov [resume_identity_len], ax
    mov si, sym_ticket_identity
    mov di, resume_identity
    mov cx, ax
    rep movsb
    mov cx, compact_root
    sub cx, di
    xor ax, ax
    rep stosb
    mov si, post_ticket_tick
    mov di, resume_age_tick_lo
    mov cx, 2
    rep movsw
    mov si, sym_ticket_lifetime_hi
    mov cx, 2
    rep movsw
    xor ax, ax
    mov di, resume_age_work_lo
    mov cx, (34 - (resume_age_work_lo - compact_root)) / 2
    rep stosw
    mov di, post_ticket_tick
    mov cx, 2
    rep stosw
    clc
    ret

; Preserve final application traffic state and reshape the resumption c before
; regenerated epoch-1 KeyGen/FO.
lifecycle_resumption_pack:
    cld
    push ds
    pop es
    xor ax, ax
    mov di, capsule_low
    mov cx, capsule_len / 2
    rep stosw
    mov si, sym_root
    mov di, capsule_low + cap_root
    mov cx, 32
    rep movsb
    mov si, sym_provisional
    mov cx, 32
    rep movsb
    mov di, capsule_low + cap_client_key
    mov si, sym_client_key
    mov cx, 32
    rep movsb
    mov si, sym_client_iv
    mov cx, 12
    rep movsb
    mov si, sym_client_seq
    mov cx, 8
    rep movsb
    mov si, sym_server_key
    mov cx, 32
    rep movsb
    mov si, sym_server_iv
    mov cx, 12
    rep movsb
    mov si, sym_server_seq
    mov cx, 8
    rep movsb
    mov byte [capsule_low + cap_lifecycle_status], 0x3c
    call reshape_resumption_ciphertext
    call clear_retired_symmetric
    clc
    ret

lifecycle_resumption_validate_fo:
    cld
    cmp byte [capsule_high + cap_lifecycle_status], 0x3c
    jne lifecycle_failed
    call compare_selected_secret
    jc lifecycle_failed
    mov byte [capsule_high + cap_fo_status], 0xc3
    clc
    ret

lifecycle_resumption_restore:
    cld
    cmp byte [capsule_high + cap_fo_status], 0xc3
    jne lifecycle_failed
    call restore_application_state
    xor ax, ax
    mov di, capsule_high
    mov cx, capsule_len / 2
    rep stosw
    mov di, 0x0dc0
    mov cx, 32 / 2
    rep stosw
    clc
    ret

restore_application_state:
    push ds
    pop es
    mov si, capsule_high + cap_client_key
    mov di, sym_client_key
    mov cx, 32 + 12
    rep movsb
    mov si, capsule_high + cap_client_seq
    mov di, sym_client_seq
    mov cx, 8
    rep movsb
    mov si, capsule_high + cap_server_key
    mov di, sym_server_key
    mov cx, 32 + 12
    rep movsb
    mov si, capsule_high + cap_server_seq
    mov di, sym_server_seq
    mov cx, 8
    rep movsb
    ret

compare_selected_secret:
    mov si, capsule_high + cap_provisional
    mov di, fo_selected_secret
    mov cx, 32
    xor bx, bx
.byte:
    lodsb
    xor al, [di]
    inc di
    or bl, al
    loop .byte
    or bl, bl
    jnz lifecycle_failed
    clc
    ret

reshape_acquisition_ciphertext:
    push ds
    pop es
    mov si, 0x3600
    mov di, 0x3510
    mov cx, 77
    rep movsb
    mov si, 0x33e8
    mov di, 0x0d60
    mov cx, 24
    rep movsb
    mov si, 0x3b40
    mov cx, 72
    rep movsb
    ret

reshape_resumption_ciphertext:
    push ds
    pop es
    mov si, 0x05f0
    mov di, 0x0d60
    mov cx, 16
    rep movsb
    mov si, 0x33f8
    mov cx, 8
    rep movsb
    mov si, 0x08b8
    mov cx, 72
    rep movsb
    mov si, 0x05ef
    mov di, 0x05ff
    mov cx, 240
    std
    rep movsb
    cld
    mov si, 0x35b0
    mov di, 0x0500
    mov cx, 16
    rep movsb
    mov si, 0x35af
    mov di, 0x35bf
    mov cx, 83
    std
    rep movsb
    cld
    mov si, 0x3640
    mov di, 0x3510
    mov cx, 13
    rep movsb
    mov si, 0x3b40
    mov cx, 80
    rep movsb
    ret

clear_retired_symmetric:
    push es
    push ds
    pop es
    xor ax, ax
    mov di, 0x3600
    mov cx, (0x3b37 - 0x3600) / 2
    rep stosw
    mov byte [0x3b36], 0
    mov di, acq_hold
    mov cx, (acq_ticket_status - acq_hold + 1) / 2
    rep stosw
    mov di, 0x08b8
    mov cx, 72 / 2
    rep stosw
    mov di, 0x3b40
    mov cx, 78 / 2
    rep stosw
    pop es
    ret

install_low_abort:
    push ds
    pop es
    mov si, low_abort_image
    mov di, 0x0f60
    mov cx, low_abort_image_end - low_abort_image
    rep movsb
    ret

lifecycle_failed:
    stc
    ret

low_abort_image:
    incbin SYSRAM_LOW_ABORT_PATH
low_abort_image_end:

sysram_lifecycle_end:

%if (sysram_lifecycle_end - sysram_lifecycle_header) > (3 * 512)
%error "system-RAM product lifecycle exceeds three sectors"
%endif
%if capsule_high + capsule_len > compact_root
%error "system-RAM capsule reaches compact-root slot"
%endif
%if resume_identity + resume_identity_max > compact_root
%error "resumed identity reaches compact-root slot"
%endif
