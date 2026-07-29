; Automatic, read-only target-side entropy collection for the 16 KiB TLS 1.3
; PoC.
;
; The controller alternates successful one-sector BIOS reads between opposite
; ends of the physical floppy and measures each completion against PIT channel
; 0.  On a mechanical drive, spindle phase, seek
; settling, controller, and media timing are asynchronous physical inputs.  The
; PIT is only the measuring clock: elapsed time by itself is not credited as
; entropy.
;
; The conditioned output ABI is shared with the former manual ceremony:
;
;   0x0700..0x0720  ML-KEM d
;   0x0720..0x0740  ML-KEM z
;   0x0740..0x0760  ClientHello random
;   0x0760..0x0780  ClientHello legacy session ID
;   0x0780..0x07a0  resumption ML-KEM d
;   0x07a0..0x07c0  resumption ML-KEM z
;   0x07c0..0x07e0  resumption ClientHello random
;   0x07e0..0x0800  resumption legacy session ID
;
; The two attempt bundles are domain-separated.  The caller card-vaults the
; second bundle before the first connection and never reuses it.
;
; This phase performs no disk write.  Track 0 / sector 1 and track 39 /
; sector 8 are valid on both supported 160 KiB single-sided and 360 KiB
; double-sided 5.25-inch layouts.  The destination is transient scratch below
; the resident nucleus and contains only public disk bytes.
;
; The source is intentionally not assigned a min-entropy estimate here.
; Emulator timing earns zero security credit, and the provisional raw-symbol
; health checks must be calibrated from representative physical hardware
; before this collector can establish the secure product floor.

bits 16
cpu 8086
org 0x0900

%ifndef FTE_KEYGEN_KECCAK_F1600
%error "FTE_KEYGEN_KECCAK_F1600 is required"
%endif
%ifndef FTE_KEYGEN_KECCAK_STATE
%error "FTE_KEYGEN_KECCAK_STATE is required"
%endif
%ifndef FTE_KEYGEN_KECCAK_WORK_START
%error "FTE_KEYGEN_KECCAK_WORK_START is required"
%endif
%ifndef FTE_KEYGEN_KECCAK_WORK_END
%error "FTE_KEYGEN_KECCAK_WORK_END is required"
%endif

fte_output             equ 0x0700
fte_output_bytes       equ 256
fte_root               equ 0x0800
fte_root_bytes         equ 32
fte_disk_scratch       equ 0x0d00
fte_samples_required   equ 256
fte_sha3_rate          equ 136
fte_max_symbol_run     equ 64
fte_min_symbol_changes equ 8
fte_boot_drive         equ 0x060a

fte_header:
    db 'FTE1'
    dw 1
    dw fte_controller_end - fte_header
    dw fte_output
    dw fte_output_bytes
    dw fte_samples_required
    dw fte_entry_count
fte_entry_table:
    dw fte_collect
    dw fte_abort
fte_entry_count equ ($ - fte_entry_table) / 2

fte_collect:
    cld
    call fte_abort
    call fte_hash_reset
    mov si, fte_root_domain
    mov cx, fte_root_domain_len
    call fte_hash_update

.next_read:
    mov di, fte_event
    call fte_latch_before

    xor ax, ax
    mov es, ax
    mov bx, fte_disk_scratch
    test byte [fte_sample_count], 1
    jnz .outer_track
    mov cx, 0x0001                 ; cylinder 0, sector 1
    jmp short .chs_ready
.outer_track:
    mov cx, 0x2708                 ; cylinder 39, sector 8
.chs_ready:
    xor dh, dh
    mov dl, [fte_boot_drive]
    mov al, [fte_sample_count]
    mov [fte_event + 4], al
    mov ax, 0x0201                 ; read one sector
    int 0x13

    ; Restore the controller's flat segment assumption even on a hostile BIOS,
    ; while retaining the BIOS carry result.
    pushf
    xor ax, ax
    mov ds, ax
    popf
    jc fte_failed

    mov di, fte_event + 2
    call fte_latch_before
    call fte_check_symbol
    jc fte_failed

    mov si, fte_event
    mov cx, fte_event_len
    call fte_hash_update
    inc byte [fte_sample_count]
    jnz .next_read

    cmp byte [fte_symbol_changes], fte_min_symbol_changes
    jb fte_failed

    mov di, fte_root
    call fte_hash_finish

    xor dx, dx
.derive:
    call fte_hash_reset
    mov si, fte_derive_domain
    mov cx, fte_derive_domain_len
    call fte_hash_update
    mov ax, dx
    call fte_hash_byte
    mov si, fte_root
    mov cx, fte_root_bytes
    call fte_hash_update
    mov ax, dx
    mov cl, 5
    shl ax, cl
    add ax, fte_output
    mov di, ax
    push dx
    call fte_hash_finish
    pop dx
    inc dx
    cmp dx, 8
    jb .derive

    call fte_clear_private_work
    clc
    ret

fte_failed:
    call fte_abort
    stc
    ret

; DI selects the two-byte event slot for a latched PIT channel-0 count.
fte_latch_before:
    xor al, al
    out 0x43, al
    in al, 0x40
    mov [di], al
    inc di
    in al, 0x40
    mov [di], al
    ret

; Fold the raw interval observation to one health symbol.  These checks catch
; an obviously stuck source; they do not establish or increase entropy.
fte_check_symbol:
    mov ax, [fte_event]
    sub ax, [fte_event + 2]
    xor al, ah

    cmp byte [fte_sample_count], 0
    je .new_run
    cmp al, [fte_previous_symbol]
    jne .changed
    inc byte [fte_current_run]
    cmp byte [fte_current_run], fte_max_symbol_run
    ja .failed
    clc
    ret
.changed:
    inc byte [fte_symbol_changes]
.new_run:
    mov [fte_previous_symbol], al
    mov byte [fte_current_run], 1
    clc
    ret
.failed:
    stc
    ret

fte_abort:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, fte_output
    mov cx, fte_output_bytes + fte_root_bytes
    rep stosb
    mov di, fte_private_start
    mov cx, fte_private_end - fte_private_start
    rep stosb
    mov di, FTE_KEYGEN_KECCAK_WORK_START
    mov cx, FTE_KEYGEN_KECCAK_WORK_END - FTE_KEYGEN_KECCAK_WORK_START
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    clc
    ret

fte_hash_reset:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, FTE_KEYGEN_KECCAK_WORK_START
    mov cx, FTE_KEYGEN_KECCAK_WORK_END - FTE_KEYGEN_KECCAK_WORK_START
    rep stosb
    mov [fte_hash_pos], ax
    pop es
    pop di
    pop cx
    pop ax
    ret

; Preserve every caller register: the shared Keccak permutation is a leaf
; primitive, not an ABI-preserving routine.
fte_hash_byte:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    mov bx, [fte_hash_pos]
    xor [FTE_KEYGEN_KECCAK_STATE + bx], al
    inc bx
    mov [fte_hash_pos], bx
    cmp bx, fte_sha3_rate
    jne .done
    call FTE_KEYGEN_KECCAK_F1600
    mov word [fte_hash_pos], 0
.done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

fte_hash_update:
    or cx, cx
    jz .done
.byte:
    lodsb
    call fte_hash_byte
    loop .byte
.done:
    ret

; DI=32-byte digest output.
fte_hash_finish:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    mov [fte_output_ptr], di
    mov bx, [fte_hash_pos]
    xor byte [FTE_KEYGEN_KECCAK_STATE + bx], 0x06
    xor byte [FTE_KEYGEN_KECCAK_STATE + fte_sha3_rate - 1], 0x80
    call FTE_KEYGEN_KECCAK_F1600
    push ds
    pop es
    mov si, FTE_KEYGEN_KECCAK_STATE
    mov di, [fte_output_ptr]
    mov cx, 32
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

fte_clear_private_work:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, fte_root
    mov cx, fte_root_bytes
    rep stosb
    mov di, fte_private_start
    mov cx, fte_private_end - fte_private_start
    rep stosb
    mov di, FTE_KEYGEN_KECCAK_WORK_START
    mov cx, FTE_KEYGEN_KECCAK_WORK_END - FTE_KEYGEN_KECCAK_WORK_START
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

fte_root_domain db 'S13floppy root v1',0
fte_root_domain_len equ $ - fte_root_domain
fte_derive_domain db 'S13output v2',0
fte_derive_domain_len equ $ - fte_derive_domain

fte_private_start:
fte_hash_pos dw 0
fte_output_ptr dw 0
fte_sample_count db 0
fte_previous_symbol db 0
fte_current_run db 0
fte_symbol_changes db 0
; before PIT[2], after PIT[2], sample index[1].
fte_event times 5 db 0
fte_event_len equ $ - fte_event
fte_private_end:

times 512 - ($ - $$) db 0
fte_controller_end:

%if fte_controller_end - fte_header > 512
%error "floppy timing entropy controller exceeds one sector"
%endif
