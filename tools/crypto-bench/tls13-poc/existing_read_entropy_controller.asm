; Condition PIT phase samples captured by Seed's already-required floppy reads.
;
; This controller performs no BIOS or filesystem operation.  The resident
; read_abs_sector tail appends one PIT channel-0 byte after each successful
; product read into 0500..0577.  Entry freezes that one-shot recorder, applies
; conservative stuck/run health checks, and derives the acquisition material:
;
;   0500..0520  same-boot root
;   0520..0540  ML-KEM d
;   0540..0560  ML-KEM z
;   0560..0580  ClientHello random
;   0580..05a0  ClientHello legacy session ID
;
; Emulator timing receives zero entropy credit.  Physical min-entropy remains
; a separate product-floor characterization gate; this phase only removes the
; former entropy-only reads and binds the existing observations cleanly.

bits 16
cpu 8086
org 0x0900

%ifndef ERE_KEYGEN_KECCAK_F1600
%error "ERE_KEYGEN_KECCAK_F1600 is required"
%endif
%ifndef ERE_KEYGEN_KECCAK_STATE
%error "ERE_KEYGEN_KECCAK_STATE is required"
%endif
%ifndef ERE_KEYGEN_KECCAK_WORK_START
%error "ERE_KEYGEN_KECCAK_WORK_START is required"
%endif
%ifndef ERE_KEYGEN_KECCAK_WORK_END
%error "ERE_KEYGEN_KECCAK_WORK_END is required"
%endif

ere_samples              equ 0x0500
ere_sample_capacity      equ 120
ere_sample_count         equ 0x05fe
ere_sample_frozen        equ 0x05ff
ere_output               equ 0x0500
ere_output_bytes         equ 160
ere_root_temp            equ 0x0800
ere_root_bytes           equ 32
ere_min_samples          equ 32
ere_max_symbol_run       equ 32
ere_min_symbol_changes   equ 4
ere_sha3_rate            equ 136
ere_frozen_marker        equ 0xa5

ere_header:
    db 'ERE1'
    dw 1
    dw ere_controller_end - ere_header
    dw ere_output
    dw ere_output_bytes
    dw ere_min_samples
    dw ere_entry_count
ere_entry_table:
    dw ere_collect
    dw ere_abort
ere_entry_count equ ($ - ere_entry_table) / 2

ere_collect:
    cld
    mov byte [ere_sample_frozen], ere_frozen_marker
    xor ax, ax
    mov al, [ere_sample_count]
    cmp ax, ere_min_samples
    jb ere_failed
    cmp ax, ere_sample_capacity
    ja ere_failed

    ; Reject an obviously stuck source or one dominated by a single run.  This
    ; detects gross failure only; it neither estimates nor manufactures entropy.
    mov si, ere_samples
    lodsb
    mov [ere_previous_symbol], al
    mov byte [ere_current_run], 1
    mov byte [ere_symbol_changes], 0
    mov cl, [ere_sample_count]
    xor ch, ch
    dec cx
.health_byte:
    jcxz .health_done
    lodsb
    cmp al, [ere_previous_symbol]
    jne .changed
    inc byte [ere_current_run]
    cmp byte [ere_current_run], ere_max_symbol_run
    ja ere_failed
    jmp short .health_next
.changed:
    mov [ere_previous_symbol], al
    mov byte [ere_current_run], 1
    inc byte [ere_symbol_changes]
.health_next:
    loop .health_byte
.health_done:
    cmp byte [ere_symbol_changes], ere_min_symbol_changes
    jb ere_failed

    call ere_hash_reset
    mov si, ere_root_domain
    mov cx, ere_root_domain_len
    call ere_hash_update
    xor ax, ax
    mov al, [ere_sample_count]
    call ere_hash_byte
    mov si, ere_samples
    xor cx, cx
    mov cl, [ere_sample_count]
    call ere_hash_update
    mov di, ere_root_temp
    call ere_hash_finish

    xor dx, dx
.derive:
    call ere_hash_reset
    mov si, ere_derive_domain
    mov cx, ere_derive_domain_len
    call ere_hash_update
    xor ax, ax
    call ere_hash_byte             ; acquisition epoch 0
    mov ax, dx
    call ere_hash_byte             ; material index
    mov si, ere_root_temp
    mov cx, ere_root_bytes
    call ere_hash_update
    mov ax, dx
    mov cl, 5
    shl ax, cl
    add ax, ere_output + ere_root_bytes
    mov di, ax
    push dx
    call ere_hash_finish
    pop dx
    inc dx
    cmp dx, 4
    jb .derive

    ; Publish the root last.  Before this copy, a torn/faulted derivation leaves
    ; no root at the stable ABI and therefore cannot seed a later attempt.
    push ds
    pop es
    mov si, ere_root_temp
    mov di, ere_output
    mov cx, ere_root_bytes / 2
    rep movsw
    call ere_clear_private_work
    clc
    ret

ere_failed:
    call ere_abort
    stc
    ret

ere_abort:
    cld
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, ere_output
    mov cx, ere_sample_frozen - ere_output
    rep stosb
    mov byte [ere_sample_frozen], ere_frozen_marker
    mov di, ere_root_temp
    mov cx, ere_root_bytes
    rep stosb
    mov di, ere_private_start
    mov cx, ere_private_end - ere_private_start
    rep stosb
    mov di, ERE_KEYGEN_KECCAK_WORK_START
    mov cx, ERE_KEYGEN_KECCAK_WORK_END - ERE_KEYGEN_KECCAK_WORK_START
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    clc
    ret

ere_hash_reset:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, ERE_KEYGEN_KECCAK_WORK_START
    mov cx, ERE_KEYGEN_KECCAK_WORK_END - ERE_KEYGEN_KECCAK_WORK_START
    rep stosb
    mov [ere_hash_pos], ax
    pop es
    pop di
    pop cx
    pop ax
    ret

ere_hash_byte:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    mov bx, [ere_hash_pos]
    xor [ERE_KEYGEN_KECCAK_STATE + bx], al
    inc bx
    mov [ere_hash_pos], bx
    cmp bx, ere_sha3_rate
    jne .done
    call ERE_KEYGEN_KECCAK_F1600
    mov word [ere_hash_pos], 0
.done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

ere_hash_update:
    or cx, cx
    jz .done
.byte:
    lodsb
    call ere_hash_byte
    loop .byte
.done:
    ret

ere_hash_finish:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    mov [ere_output_ptr], di
    mov bx, [ere_hash_pos]
    xor byte [ERE_KEYGEN_KECCAK_STATE + bx], 0x06
    xor byte [ERE_KEYGEN_KECCAK_STATE + ere_sha3_rate - 1], 0x80
    call ERE_KEYGEN_KECCAK_F1600
    push ds
    pop es
    mov si, ERE_KEYGEN_KECCAK_STATE
    mov di, [ere_output_ptr]
    mov cx, 32
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

ere_clear_private_work:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, ere_root_temp
    mov cx, ere_root_bytes
    rep stosb
    mov di, ere_private_start
    mov cx, ere_private_end - ere_private_start
    rep stosb
    mov di, ERE_KEYGEN_KECCAK_WORK_START
    mov cx, ERE_KEYGEN_KECCAK_WORK_END - ERE_KEYGEN_KECCAK_WORK_START
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

ere_root_domain db 'S13 existing read root v1',0
ere_root_domain_len equ $ - ere_root_domain
ere_derive_domain db 'S13 8088 attempt v2',0
ere_derive_domain_len equ $ - ere_derive_domain

ere_private_start:
ere_hash_pos dw 0
ere_output_ptr dw 0
ere_previous_symbol db 0
ere_current_run db 0
ere_symbol_changes db 0
ere_private_end:

times 512 - ($ - $$) db 0
ere_controller_end:

%if ere_controller_end - ere_header > 512
%error "existing-read entropy controller exceeds one sector"
%endif
%if ere_output + ere_output_bytes > 0x0600
%error "existing-read entropy output reaches the handoff block"
%endif
