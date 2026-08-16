; Fixed three-sector TLS 1.3 286 bootstrap.
;
; This image replaces only the product build's retired TLS 1.2 ClientHello
; phase (SEED.SYS sectors 41..43) and runs at 0000:0700.  It is unreachable
; from the 8088 route.  Before any later controller may reuse 0x3400+, it:
;
;   * repeats the 286/512 KiB gate and derives the top-relative 64 KiB crypto
;     reserve plus its adjacent 14,864-byte prompt-cache shadow;
;   * validates the prompt/UI/tool-control boundary and escrows it status-last;
;   * discovers the 16-bit product tail through its last-sector footer;
;   * validates and loads the unique root-stage image at 0000:3400; and
;   * tail-jumps without disturbing the original endpoint return address.
;
; Entry:
;   AL=0 cold or AL=1 human reconnect, DS=ES=SS=0, DF=0.
;   Parent has silently published the nine-byte platform UTC value status-last at the
;   fixed low source and at its fixed top-relative reservation offset;
;   bootstrap independently derives the high address and requires exact
;   low/high agreement before preserving only that slot during its wipe.
; Exit:
;   success tail-jumps to the root stage with AL=mode, BX=crypto-base segment,
;   SI=high footer offset; failure returns CF=1 with DS=ES=0 and DF=0.
;
; The pointer table remains callable until a later phase deliberately replaces
; 0x0700.  A final/abort controller running outside 0x3400..41ff may call the
; restore entry before wiping the high reservation.  Restore clears only the
; validated root-stage extent plus 0x4000..41ff; 0x3c00..3fff is sentinel-
; checked again immediately before any low-state publication.

bits 16
cpu 8086
org 0x0700

%include "tls13/tls13_286_abi.inc"

bootstrap_entry:
    jmp short bootstrap_start
bootstrap_restore_ptr:
    dw bootstrap_restore_escrow
bootstrap_wipe_ptr:
    dw bootstrap_wipe_high
bootstrap_abort_ptr:
    dw bootstrap_abort
bootstrap_magic:
    db 'S286BT02'

bootstrap_handoff_flags          equ 0x0608
bootstrap_handoff_flag_286       equ 0x0010
bootstrap_handoff_flag_mda       equ 0x0001
bootstrap_bda_memory_kb          equ 0x0413
bootstrap_bda_video_cols         equ 0x044a
bootstrap_bda_crt_port           equ 0x0463
bootstrap_mda_crt_port           equ 0x03b4
bootstrap_cga_crt_port           equ 0x03d4
bootstrap_core_total_sectors     equ 0x1011
bootstrap_read_abs_sector        equ 0x1343
bootstrap_fat_data_start_lba     equ 11

bootstrap_screen_cols            equ 0x0f57
bootstrap_video_seg              equ 0x0f58
bootstrap_cursor_row             equ 0x0f55
bootstrap_cursor_col             equ 0x0f56
bootstrap_prompt_marker_row      equ 0x0f33
bootstrap_agent_loop_pending     equ 0x0f66
bootstrap_agent_loop_count       equ 0x0f67
bootstrap_resend_prompt_len      equ 0x3c9c
bootstrap_tool_fc_state          equ 0x3ceb

bootstrap_stage_load             equ 0x3400
bootstrap_stage_limit            equ 0x3c00
bootstrap_stage_max_sectors      equ \
    (bootstrap_stage_limit - bootstrap_stage_load) / 512
bootstrap_footer_buffer          equ tls13_286_controller_handoff
bootstrap_footer_limit           equ tls13_286_controller_handoff_end
bootstrap_rtc_source             equ 0x062e

bootstrap_start:
    cld
    mov [cs:bootstrap_mode], al
    xor ax, ax
    mov ds, ax
    mov es, ax

    cmp byte [cs:bootstrap_mode], 1
    ja bootstrap_fail
    cmp byte [cs:bootstrap_escrow_live], 0
    jne bootstrap_fail
    test word [bootstrap_handoff_flags], bootstrap_handoff_flag_286
    jz bootstrap_fail
    mov ax, [bootstrap_bda_memory_kb]
    cmp ax, tls13_286_min_conventional_kb
    jb bootstrap_fail
    cmp ax, 640
    ja bootstrap_fail
    mov cl, 6
    shl ax, cl
    sub ax, tls13_286_high_reserve_bytes / 16
    jc bootstrap_fail
    mov [cs:bootstrap_crypto_seg], ax

    mov es, ax
    cmp word [es:tls13_286_rtc_status_inv_off], 0xa55a
    jne bootstrap_fail_rtc
    mov si, bootstrap_rtc_source
    mov di, tls13_286_rtc_publication_off
    mov cx, tls13_286_rtc_publication_bytes
    repe cmpsb
    jne bootstrap_fail_rtc
    xor ax, ax
    mov es, ax

    call bootstrap_validate_live_state
    jc bootstrap_fail
    mov si, bootstrap_stage_limit
    mov cx, 0x4000 - bootstrap_stage_limit
    call bootstrap_crc16
    mov [cs:bootstrap_preserve_crc], ax
    call bootstrap_save_escrow
    jc bootstrap_fail_wipe
    mov byte [bootstrap_escrow_live], 1

    ; The verified escrow already carries its config CRC, so this mutable word
    ; is dead.  Reuse it to freeze the exact resident caller SP, then run the
    ; complete authenticated tail on the fixed low guard.  Entropy validates
    ; and republishes the saved value redundantly before private work begins.
    mov [bootstrap_config_crc], sp
    cli
    mov sp, tls13_286_tail_stack_top
    sti

    call bootstrap_read_footer
    jc bootstrap_abort
    call bootstrap_load_root_stage
    jc bootstrap_abort

    ; The frozen footer is now high-only.  This also guarantees HELLO's later
    ; dynamic X25519 input begins from a clean 0000:4000..401f.
    xor ax, ax
    mov es, ax
    mov di, bootstrap_footer_buffer
    mov cx, (bootstrap_footer_limit - bootstrap_footer_buffer) / 2
    rep stosw
    mov al, [cs:bootstrap_mode]
    mov bx, [cs:bootstrap_crypto_seg]
    mov si, tls13_286_tail_footer_off
    jmp word [cs:bootstrap_stage_entry]

bootstrap_fail_wipe:
    call bootstrap_wipe_high
bootstrap_fail:
    stc
    ret
bootstrap_fail_rtc:
    xor ax, ax
    mov di, tls13_286_rtc_publication_off
    mov cx, tls13_286_rtc_publication_bytes
    rep stosb
    mov es, ax
    mov di, bootstrap_rtc_source
    mov cx, tls13_286_rtc_publication_bytes
    rep stosb
    jmp short bootstrap_fail

bootstrap_validate_live_state:
    cmp byte [bootstrap_agent_loop_pending], 0
    jne .bad
    cmp byte [bootstrap_tool_fc_state], 0
    jne .bad

    xor ax, ax
    mov al, [tls13_286_prompt_len_source]
    cmp ax, 255
    ja .bad
    cmp al, [bootstrap_resend_prompt_len]
    jne .bad
    cmp byte [cs:bootstrap_mode], 0
    jne .human
    or al, al
    jnz .bad
    jmp short .prompt_ok
.human:
    or al, al
    jz .bad
.prompt_ok:
    mov al, [bootstrap_screen_cols]
    cmp al, 20
    jb .bad
    cmp al, 80
    ja .bad
    cmp byte [bootstrap_bda_video_cols + 1], 0
    jne .bad
    cmp al, [bootstrap_bda_video_cols]
    jne .bad
    cmp byte [bootstrap_cursor_row], 25
    jae .bad
    cmp byte [bootstrap_cursor_col], al
    jae .bad
    cmp byte [tls13_286_prompt_len_source], 0
    je .marker_ok
    mov ah, [bootstrap_prompt_marker_row]
    and ah, 0x7f
    cmp ah, 25
    jae .bad
.marker_ok:

    test word [bootstrap_handoff_flags], bootstrap_handoff_flag_mda
    jnz .mda
    cmp word [bootstrap_video_seg], 0xb800
    jne .bad
    cmp word [bootstrap_bda_crt_port], bootstrap_cga_crt_port
    jne .bad
    clc
    ret
.mda:
    cmp word [bootstrap_video_seg], 0xb000
    jne .bad
    cmp word [bootstrap_bda_crt_port], bootstrap_mda_crt_port
    jne .bad
    clc
    ret
.bad:
    stc
    ret

bootstrap_save_escrow:
    mov ax, [cs:bootstrap_crypto_seg]
    mov es, ax
    xor di, di
    xor ax, ax
    mov cx, tls13_286_rtc_publication_off / 2
    rep stosw
    add di, tls13_286_rtc_publication_bytes
    mov cx, tls13_286_high_reserve_bytes - \
        tls13_286_rtc_publication_off - tls13_286_rtc_publication_bytes
    rep stosb

    mov si, tls13_286_escrow_config_source
    mov cx, tls13_286_escrow_config_bytes
    call bootstrap_crc16
    mov [cs:bootstrap_config_crc], ax
    mov si, tls13_286_escrow_config_source
    mov di, tls13_286_escrow_config_off
    mov cx, tls13_286_escrow_config_bytes
    rep movsb

    mov si, tls13_286_escrow_low_source
    mov cx, tls13_286_escrow_low_bytes
    call bootstrap_crc16
    mov [cs:bootstrap_low_crc], ax
    mov si, tls13_286_escrow_low_source
    mov di, tls13_286_escrow_low_off
    mov cx, tls13_286_escrow_low_bytes
    rep movsb

    mov si, tls13_286_prompt_source
    mov cx, tls13_286_prompt_max
    call bootstrap_crc16
    mov [cs:bootstrap_prompt_crc], ax
    mov si, tls13_286_prompt_source
    mov di, tls13_286_prompt_off
    mov cx, tls13_286_prompt_max
    rep movsb
    mov al, [tls13_286_prompt_len_source]
    mov [es:tls13_286_prompt_len_off], al

    push ds
    mov ds, [cs:bootstrap_crypto_seg]
    mov si, tls13_286_escrow_config_off
    mov cx, tls13_286_escrow_config_bytes
    call bootstrap_crc16
    cmp ax, [cs:bootstrap_config_crc]
    jne .copy_bad
    mov si, tls13_286_escrow_low_off
    mov cx, tls13_286_escrow_low_bytes
    call bootstrap_crc16
    cmp ax, [cs:bootstrap_low_crc]
    jne .copy_bad
    mov si, tls13_286_prompt_off
    mov cx, tls13_286_prompt_max
    call bootstrap_crc16
    cmp ax, [cs:bootstrap_prompt_crc]
    jne .copy_bad
    pop ds

    mov word [es:tls13_286_escrow_magic_off], \
        tls13_286_escrow_magic_lo
    mov word [es:tls13_286_escrow_magic_off + 2], \
        tls13_286_escrow_magic_hi
    mov word [es:tls13_286_escrow_magic_inv_off], \
        tls13_286_escrow_magic_inv_lo
    mov word [es:tls13_286_escrow_magic_inv_off + 2], \
        tls13_286_escrow_magic_inv_hi
    mov ax, [cs:bootstrap_config_crc]
    mov [es:tls13_286_escrow_config_crc_off], ax
    mov ax, [cs:bootstrap_low_crc]
    mov [es:tls13_286_escrow_low_crc_off], ax
    mov ax, [cs:bootstrap_prompt_crc]
    mov [es:tls13_286_escrow_prompt_crc_off], ax
    mov al, [tls13_286_prompt_len_source]
    mov [es:tls13_286_escrow_prompt_len_off], al
    not al
    mov [es:tls13_286_escrow_prompt_len_inv_off], al
    mov al, [cs:bootstrap_mode]
    mov [es:tls13_286_escrow_mode_off], al
    mov ax, [cs:bootstrap_crypto_seg]
    mov [es:tls13_286_escrow_crypto_seg_off], ax
    mov ax, [cs:bootstrap_preserve_crc]
    mov [es:tls13_286_escrow_preserve_crc_off], ax
    mov byte [es:tls13_286_escrow_status_inv_off], \
        tls13_286_escrow_status_inverse
    mov byte [es:tls13_286_escrow_status_off], \
        tls13_286_escrow_status_valid
    xor ax, ax
    mov es, ax
    clc
    ret
.copy_bad:
    pop ds
    xor ax, ax
    mov es, ax
    stc
    ret

bootstrap_read_footer:
    mov ax, [bootstrap_core_total_sectors]
    cmp ax, 2
    jb .bad
    cmp ax, 320
    ja .bad
    mov [cs:bootstrap_total_sectors], ax
    dec ax
    add ax, bootstrap_fat_data_start_lba
    mov bx, bootstrap_footer_buffer
    call bootstrap_read_abs_sector
    jc .bad

    mov si, bootstrap_footer_buffer
    mov di, bootstrap_tail_magic
    mov cx, 8
.magic:
    mov al, [si]
    cmp al, [cs:di]
    jne .bad
    inc si
    inc di
    loop .magic
    cmp word [bootstrap_footer_buffer + tls13_286_tail_abi], \
        tls13_286_abi_version
    jne .bad
    cmp word [bootstrap_footer_buffer + tls13_286_tail_header_bytes_off], \
        tls13_286_tail_header_bytes
    jne .bad
    mov ax, [cs:bootstrap_total_sectors]
    cmp [bootstrap_footer_buffer + tls13_286_tail_total_sectors], ax
    jne .bad
    cmp word [bootstrap_footer_buffer + tls13_286_tail_entry_bytes_off], \
        tls13_286_tail_entry_bytes
    jne .bad
    mov cx, [bootstrap_footer_buffer + tls13_286_tail_entry_count]
    or cx, cx
    jz .bad
    cmp cx, tls13_286_tail_max_entries
    ja .bad
    mov si, bootstrap_footer_buffer + tls13_286_tail_reserved
    mov dx, 10
.reserved:
    cmp byte [si], 0
    jne .bad
    inc si
    dec dx
    jnz .reserved

    mov si, bootstrap_footer_buffer
    mov cx, tls13_286_tail_footer_crc
    call bootstrap_crc16
    cmp ax, [bootstrap_footer_buffer + tls13_286_tail_footer_crc]
    jne .bad
    mov ax, [bootstrap_footer_buffer + tls13_286_tail_start_sector]
    or ax, ax
    jz .bad
    mov dx, ax
    add dx, [bootstrap_footer_buffer + tls13_286_tail_sectors]
    jc .bad
    cmp dx, [cs:bootstrap_total_sectors]
    jne .bad

    xor bp, bp
    mov si, bootstrap_footer_buffer + tls13_286_tail_directory_off
    mov cx, [bootstrap_footer_buffer + tls13_286_tail_entry_count]
.entry:
    cmp word [si + tls13_286_tail_entry_kind], \
        tls13_286_tail_kind_root_stage
    jne .next
    or bp, bp
    jne .bad
    inc bp
    cmp word [si + tls13_286_tail_entry_flags], \
        tls13_286_tail_flag_product
    jne .bad
    mov ax, [si + tls13_286_tail_entry_start_sector]
    cmp ax, [bootstrap_footer_buffer + tls13_286_tail_start_sector]
    jb .bad
    mov [cs:bootstrap_stage_sector], ax
    mov dx, [si + tls13_286_tail_entry_sectors]
    or dx, dx
    jz .bad
    cmp dx, bootstrap_stage_max_sectors
    ja .bad
    mov [cs:bootstrap_stage_sectors], dx
    add ax, dx
    jc .bad
    cmp ax, [cs:bootstrap_total_sectors]
    jae .bad
    mov ax, [si + tls13_286_tail_entry_image_bytes]
    or ax, ax
    jz .bad
    mov [cs:bootstrap_stage_bytes], ax
    mov bx, dx
    mov bh, bl
    xor bl, bl
    shl bx, 1
    cmp ax, bx
    ja .bad
    cmp word [si + tls13_286_tail_entry_load], bootstrap_stage_load
    jne .bad
    mov dx, [si + tls13_286_tail_entry_entry]
    cmp dx, bootstrap_stage_load
    jb .bad
    mov bx, bootstrap_stage_load
    add bx, ax
    jc .bad
    cmp dx, bx
    jae .bad
    mov [cs:bootstrap_stage_entry], dx
    mov ax, [si + tls13_286_tail_entry_crc16]
    mov [cs:bootstrap_stage_crc], ax
.next:
    add si, tls13_286_tail_entry_bytes
    dec cx
    jnz .entry
    cmp bp, 1
    jne .bad

    mov ax, [cs:bootstrap_crypto_seg]
    mov es, ax
    mov si, bootstrap_footer_buffer
    mov di, tls13_286_tail_footer_off
    mov cx, tls13_286_tail_footer_bytes / 2
    rep movsw
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    stc
    ret

bootstrap_load_root_stage:
    xor ax, ax
    mov es, ax
    mov bx, bootstrap_stage_load
    mov ax, [cs:bootstrap_stage_sector]
    add ax, bootstrap_fat_data_start_lba
    mov cx, [cs:bootstrap_stage_sectors]
.read:
    call bootstrap_read_abs_sector
    jc .bad
    add bx, 512
    inc ax
    loop .read
    mov si, bootstrap_stage_load
    mov cx, [cs:bootstrap_stage_bytes]
    call bootstrap_crc16
    cmp ax, [cs:bootstrap_stage_crc]
    jne .bad
    mov si, bootstrap_stage_limit
    mov cx, 0x4000 - bootstrap_stage_limit
    call bootstrap_crc16
    cmp ax, [cs:bootstrap_preserve_crc]
    jne .bad

    mov ax, [cs:bootstrap_stage_sectors]
    mov cl, 9
    shl ax, cl
    sub ax, [cs:bootstrap_stage_bytes]
    jz .good
    mov cx, ax
    mov si, bootstrap_stage_load
    add si, [cs:bootstrap_stage_bytes]
.padding:
    cmp byte [si], 0
    jne .bad
    inc si
    loop .padding
.good:
    clc
    ret
.bad:
    stc
    ret

; Callable through [0000:0702].  The caller must execute outside the validated
; root-stage extent and 0x4000..41ff: restore clears exactly those two spans
; before publishing any restored byte and never touches 0x3c00..3fff.
bootstrap_restore_escrow:
    cld
    xor ax, ax
    mov es, ax
    mov ax, [cs:bootstrap_crypto_seg]
    or ax, ax
    jz .bad
    mov ds, ax
    cmp word [tls13_286_escrow_magic_off], \
        tls13_286_escrow_magic_lo
    jne .bad_ds
    cmp word [tls13_286_escrow_magic_off + 2], \
        tls13_286_escrow_magic_hi
    jne .bad_ds
    cmp word [tls13_286_escrow_magic_inv_off], \
        tls13_286_escrow_magic_inv_lo
    jne .bad_ds
    cmp word [tls13_286_escrow_magic_inv_off + 2], \
        tls13_286_escrow_magic_inv_hi
    jne .bad_ds
    cmp byte [tls13_286_escrow_status_inv_off], \
        tls13_286_escrow_status_inverse
    jne .bad_ds
    cmp byte [tls13_286_escrow_status_off], \
        tls13_286_escrow_status_valid
    jne .bad_ds
    mov ax, [cs:bootstrap_crypto_seg]
    cmp [tls13_286_escrow_crypto_seg_off], ax
    jne .bad_ds
    mov al, [cs:bootstrap_mode]
    cmp [tls13_286_escrow_mode_off], al
    jne .bad_ds
    mov si, tls13_286_escrow_config_off
    mov cx, tls13_286_escrow_config_bytes
    call bootstrap_crc16
    cmp ax, [tls13_286_escrow_config_crc_off]
    jne .bad_ds
    mov si, tls13_286_escrow_low_off
    mov cx, tls13_286_escrow_low_bytes
    call bootstrap_crc16
    cmp ax, [tls13_286_escrow_low_crc_off]
    jne .bad_ds
    mov si, tls13_286_prompt_off
    mov cx, tls13_286_prompt_max
    call bootstrap_crc16
    cmp ax, [tls13_286_escrow_prompt_crc_off]
    jne .bad_ds
    mov al, [tls13_286_prompt_len_off]
    cmp al, [tls13_286_escrow_prompt_len_off]
    jne .bad_ds
    mov ah, [tls13_286_escrow_prompt_len_inv_off]
    not ah
    cmp al, ah
    jne .bad_ds
    xor ax, ax
    mov di, bootstrap_stage_load
    mov cx, [cs:bootstrap_stage_sectors]
    mov ch, cl
    xor cl, cl
    rep stosw
    mov di, bootstrap_footer_buffer
    mov cx, (bootstrap_footer_limit - bootstrap_footer_buffer) / 2
    rep stosw
    mov si, tls13_286_escrow_config_off
    mov di, tls13_286_escrow_config_source
    mov cx, tls13_286_escrow_config_bytes
    rep movsb
    mov si, tls13_286_escrow_low_off
    mov di, tls13_286_escrow_low_source
    mov cx, tls13_286_escrow_low_bytes
    rep movsb
    mov si, tls13_286_prompt_off
    mov di, tls13_286_prompt_source
    mov cx, tls13_286_prompt_max
    rep movsb
    mov al, [tls13_286_prompt_len_off]
    mov [es:tls13_286_prompt_len_source], al
    mov byte [tls13_286_escrow_status_off], 0
    mov byte [tls13_286_escrow_status_inv_off], 0
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov byte [cs:bootstrap_escrow_live], 0
    clc
    ret
.bad_ds:
    xor ax, ax
    mov ds, ax
.bad:
    mov es, ax
    stc
    ret

; Callable through [0000:0704].  This retires the complete crypto reservation,
; including cached executable bytes and all private key material.
bootstrap_wipe_high:
    cld
    mov ax, [cs:bootstrap_crypto_seg]
    or ax, ax
    jz .done
    mov es, ax
    xor di, di
    xor ax, ax
    mov cx, tls13_286_high_reserve_bytes / 2
    rep stosw
.done:
    xor ax, ax
    mov ds, ax
    mov es, ax
    ret

bootstrap_abort:
    cmp byte [cs:bootstrap_escrow_live], 0
    je .return
    call bootstrap_restore_escrow
    call bootstrap_wipe_high
.return:
    cli
    mov sp, [bootstrap_config_crc]
    sti
    stc
    ret

; CRC-16/CCITT-FALSE over DS:SI, CX bytes.
bootstrap_crc16:
    mov ax, 0xffff
    mov dx, cx
.byte:
    or dx, dx
    jz .done
    xor ah, [si]
    inc si
    mov cx, 8
.bit:
    shl ax, 1
    jnc .plain
    xor ax, 0x1021
.plain:
    loop .bit
    dec dx
    jmp .byte
.done:
    ret

bootstrap_tail_magic db 'S286TL02'
bootstrap_mode db 0
bootstrap_escrow_live db 0
bootstrap_crypto_seg dw 0
bootstrap_config_crc dw 0
bootstrap_low_crc dw 0
bootstrap_prompt_crc dw 0
bootstrap_total_sectors dw 0
bootstrap_stage_sector dw 0
bootstrap_stage_sectors dw 0
bootstrap_stage_bytes dw 0
bootstrap_stage_entry dw 0
bootstrap_stage_crc dw 0
bootstrap_preserve_crc dw 0

bootstrap_image_end:

%if (bootstrap_entry - $$) != 0
%error "TLS 1.3 286 bootstrap entry moved"
%endif
%if (bootstrap_image_end - $$) > 1536
%error "TLS 1.3 286 bootstrap exceeds reclaimed three-sector phase"
%endif
times 1536 - (bootstrap_image_end - $$) db 0
