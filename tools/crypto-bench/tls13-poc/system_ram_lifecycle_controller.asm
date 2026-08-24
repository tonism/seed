; Offline conventional-RAM lifecycle operations for the 16 KiB TLS 1.3 path.
;
; This phase is loaded only after the provider socket is closed or held behind
; a zero window.  Slow disk loading is therefore outside both deadline races.
; It never touches display, adapter, config, or writable media state.

bits 16
cpu 8086
org 0x0900

capsule_high               equ 0x3400
capsule_root               equ capsule_high
capsule_provisional        equ capsule_root + 32
capsule_auth_digest        equ capsule_provisional + 32
capsule_auth_status        equ capsule_high + 170
capsule_ticket_psk         equ capsule_high + 171
capsule_ticket_identity    equ capsule_high + 203
capsule_ticket_metadata    equ capsule_high + 427
capsule_ticket_identity_len equ capsule_ticket_metadata + 10
capsule_ticket_status      equ capsule_high + 439

resume_random              equ 0x3420
resume_session             equ 0x3440
resume_psk                 equ 0x3460
resume_age                 equ 0x3480
resume_identity_len        equ 0x3484
resume_identity_stage      equ 0x3486
resume_identity_max        equ 192
abort_capsule              equ 0x35c0

fo_selected_secret         equ 0x3a60

resume_capsule_low         equ 0x0700
resume_capsule_len         equ 440
resume_capsule_root        equ resume_capsule_low
resume_capsule_provisional equ resume_capsule_root + 32
resume_capsule_client_key  equ resume_capsule_provisional + 32
resume_capsule_client_iv   equ resume_capsule_client_key + 32
resume_capsule_client_seq  equ resume_capsule_client_iv + 12
resume_capsule_server_key  equ resume_capsule_client_seq + 8
resume_capsule_server_iv   equ resume_capsule_server_key + 32
resume_capsule_server_seq  equ resume_capsule_server_iv + 12
resume_capsule_inverse     equ resume_capsule_server_seq + 8
resume_capsule_status      equ resume_capsule_inverse + 1

sym_root                   equ 0x3600
sym_provisional            equ 0x3620
sym_client_app_key         equ 0x3838
sym_client_app_iv          equ 0x3858
sym_server_app_key         equ 0x3864
sym_server_app_iv          equ 0x3884
sym_client_app_seq         equ 0x38e0
sym_server_app_seq         equ 0x38e8

lifecycle_header:
    db 'SRL1'
    dw 1
    dw lifecycle_end - lifecycle_header
    dw lifecycle_entry_count
lifecycle_entry_table:
    dw lifecycle_acquisition_to_resumption
    dw lifecycle_resumption_to_keygen
    dw lifecycle_resumption_fo_validate
    dw lifecycle_resumption_restore_application
lifecycle_entry_count equ ($ - lifecycle_entry_table) / 2

; Input DX:AX is the already-computed four wire bytes of
; obfuscated_ticket_age.  Full FO, exact-leaf CV, and ticket publication must
; all have succeeded before this operation is reachable.
lifecycle_acquisition_to_resumption:
    cld
    push dx
    push ax
    cmp byte [capsule_auth_status], 1
    jne .failed_stacked
    cmp byte [capsule_ticket_status], 0
    je .failed_stacked
    mov cx, [capsule_ticket_identity_len]
    or cx, cx
    jz .failed_stacked
    cmp cx, resume_identity_max
    ja .failed_stacked
    mov si, capsule_provisional
    mov di, fo_selected_secret
    mov cx, 32
    xor bx, bx
.compare_k:
    lodsb
    xor al, [di]
    inc di
    or bl, al
    loop .compare_k
    or bl, bl
    jnz .failed_stacked

    push ds
    pop es
    mov si, capsule_ticket_psk
    mov di, resume_psk
    mov cx, 16
    rep movsw
    mov cx, [capsule_ticket_identity_len]
    mov si, capsule_ticket_identity
    mov di, resume_identity_stage
    rep movsb
    mov ax, [capsule_ticket_identity_len]
    mov [resume_identity_len], ax
    xor ax, ax
    mov di, resume_random
    mov cx, 64 / 2
    rep stosw
    pop ax
    pop dx
    mov [resume_age], ax
    mov [resume_age + 2], dx
    mov di, resume_identity_stage
    add di, [resume_identity_len]
    mov cx, abort_capsule
    sub cx, di
    xor ax, ax
    rep stosb
    mov di, 0x3a40
    mov cx, 128 / 2
    rep stosw
    clc
    ret
.failed_stacked:
    pop ax
    pop dx
    stc
    ret

; Preserve the root, provisional K, and exact application traffic state while
; c and the private key are regenerated for standards-complete resumption FO.
lifecycle_resumption_to_keygen:
    cld
    push ds
    pop es
    xor ax, ax
    mov di, resume_capsule_low
    mov cx, resume_capsule_len / 2
    rep stosw
    mov si, sym_root
    mov di, resume_capsule_root
    mov cx, 32 / 2
    rep movsw
    mov si, sym_provisional
    mov di, resume_capsule_provisional
    mov cx, 32 / 2
    rep movsw
    mov si, sym_client_app_key
    mov di, resume_capsule_client_key
    mov cx, 32 / 2
    rep movsw
    mov si, sym_client_app_iv
    mov di, resume_capsule_client_iv
    mov cx, 12 / 2
    rep movsw
    mov si, sym_client_app_seq
    mov di, resume_capsule_client_seq
    mov cx, 8 / 2
    rep movsw
    mov si, sym_server_app_key
    mov di, resume_capsule_server_key
    mov cx, 32 / 2
    rep movsw
    mov si, sym_server_app_iv
    mov di, resume_capsule_server_iv
    mov cx, 12 / 2
    rep movsw
    mov si, sym_server_app_seq
    mov di, resume_capsule_server_seq
    mov cx, 8 / 2
    rep movsw
    mov byte [resume_capsule_inverse], 0x5a
    mov byte [resume_capsule_status], 0xa5

    ; Assemble c[704..799] before shifting c[464..703] upward by 16.
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

    ; Assemble c[272..447] immediately after the retained c[0..271].  Move
    ; the overlapping final 83 bytes first so the preceding destination does
    ; not overwrite their source.
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

    xor ax, ax
    mov di, 0x08b8
    mov cx, 72 / 2
    rep stosw
    mov di, sym_root
    mov cx, (0x3b9c - sym_root) / 2
    rep stosw
    clc
    ret

; Called after resumption FO and before the symmetric phase is reloaded.
lifecycle_resumption_fo_validate:
    cld
    cmp byte [capsule_high + (resume_capsule_inverse - resume_capsule_low)], 0x5a
    jne .failed
    cmp byte [capsule_high + (resume_capsule_status - resume_capsule_low)], 0xa5
    jne .failed
    mov si, capsule_high + 32
    mov di, fo_selected_secret
    mov cx, 32
    xor bx, bx
.compare:
    lodsb
    xor al, [di]
    inc di
    or bl, al
    loop .compare
    or bl, bl
    jnz .failed
    mov byte [capsule_high + (resume_capsule_inverse - resume_capsule_low)], 0x3c
    mov byte [capsule_high + (resume_capsule_status - resume_capsule_low)], 0xc3
    clc
    ret
.failed:
    stc
    ret

; Called after sym_init has erased c/FO state.  Restore only the traffic keys,
; IVs, and sequence numbers needed to authenticate the delayed HEAD response.
lifecycle_resumption_restore_application:
    cld
    cmp byte [capsule_high + (resume_capsule_inverse - resume_capsule_low)], 0x3c
    jne .failed
    cmp byte [capsule_high + (resume_capsule_status - resume_capsule_low)], 0xc3
    jne .failed
    push ds
    pop es
    mov si, capsule_high + (resume_capsule_client_key - resume_capsule_low)
    mov di, sym_client_app_key
    mov cx, 32 / 2
    rep movsw
    mov si, capsule_high + (resume_capsule_client_iv - resume_capsule_low)
    mov di, sym_client_app_iv
    mov cx, 12 / 2
    rep movsw
    mov si, capsule_high + (resume_capsule_client_seq - resume_capsule_low)
    mov di, sym_client_app_seq
    mov cx, 8 / 2
    rep movsw
    mov si, capsule_high + (resume_capsule_server_key - resume_capsule_low)
    mov di, sym_server_app_key
    mov cx, 32 / 2
    rep movsw
    mov si, capsule_high + (resume_capsule_server_iv - resume_capsule_low)
    mov di, sym_server_app_iv
    mov cx, 12 / 2
    rep movsw
    mov si, capsule_high + (resume_capsule_server_seq - resume_capsule_low)
    mov di, sym_server_app_seq
    mov cx, 8 / 2
    rep movsw
    xor ax, ax
    mov di, capsule_high
    mov cx, (abort_capsule - capsule_high) / 2
    rep stosw
    mov di, 0x0dc0
    mov cx, 32 / 2
    rep stosw
    clc
    ret
.failed:
    stc
    ret

lifecycle_end:
%if (lifecycle_end - $$) > (0x0d00 - 0x0900)
%error "system-RAM lifecycle exceeds retired low object space"
%endif
