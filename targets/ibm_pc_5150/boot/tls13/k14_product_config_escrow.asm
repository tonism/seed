; Status-last reconnect-state escrow for the 16 KiB TLS 1.3 product route.
;
; The TLS 1.3 K14 overlays retire the conventional 0x3b9c..0x3c9b
; model/key caches and five small UI/control bytes that must survive both a
; cold post-config setup and a human reconnect.  The generic public vault
; already owns the preceding video window, so this phase uses the remaining
; 416 bytes:
;
;   CGA  B800:1e00..1f9f
;   MDA  B000:0e00..0f9f
;
; The full object is created immediately after pv_begin.  Restore validates
; redundant scalar metadata plus IEEE CRC32 and CRC32C before copying any
; byte back to conventional RAM.  Both successful and failed restores erase
; the complete escrow.  Intermediate vault retirement preserves this object
; and keeps MDA output disabled.  The terminal vault zeroizer runs only after
; restore has erased the tail; it then clears the complete MDA page and
; restores video output.
;
; Entry table:
;   +0 save:    DX=nonzero lifecycle generation, CF status
;   +2 restore: no input, CF status
;
; All entries preserve the caller's general/segment registers and return
; with DF clear.

bits 16
cpu 8086

%ifndef K14_CONFIG_ESCROW_ORIGIN
%define K14_CONFIG_ESCROW_ORIGIN 0x2c00
%endif
%ifndef K14_CONFIG_CACHE
%error "K14 config escrow requires the 256-byte cache address"
%endif
%ifndef K14_CONFIG_SENSITIVE_START
%error "K14 config escrow requires the conventional config start"
%endif
%ifndef K14_CONFIG_SENSITIVE_END
%error "K14 config escrow requires the conventional config end"
%endif
%ifndef K14_CURSOR_ROW
%error "K14 config escrow requires cursor_row"
%endif
%ifndef K14_CURSOR_COL
%error "K14 config escrow requires cursor_col"
%endif
%ifndef K14_PROMPT_MARKER_ROW
%error "K14 config escrow requires dpi_prompt_marker_row"
%endif
%ifndef K14_AGENT_LOOP_PENDING
%error "K14 config escrow requires agent_loop_pending"
%endif
%ifndef K14_AGENT_LOOP_COUNT
%error "K14 config escrow requires agent_loop_count"
%endif

org K14_CONFIG_ESCROW_ORIGIN

k14_config_escrow_table:
    dw k14_config_escrow_save
    dw k14_config_escrow_restore

escrow_cga_segment              equ 0xb800
escrow_cga_offset               equ 0x1e00
escrow_mda_segment              equ 0xb000
escrow_mda_offset               equ 0x0e00
escrow_bda_crt_port             equ 0x0463
escrow_mda_crt_port             equ 0x03b4
escrow_cga_crt_port             equ 0x03d4

escrow_cache_len                equ 256
escrow_ui_offset                equ 0x0100
escrow_preimage_end             equ 0x0114
escrow_magic_offset             equ 0x0108
escrow_magic_inverse_offset     equ 0x010c
escrow_generation_offset        equ 0x0110
escrow_generation_inverse       equ 0x0112
escrow_crc32_offset             equ 0x0114
escrow_crc32c_offset            equ 0x0118
escrow_inverse_status_offset    equ 0x019e
escrow_status_offset            equ 0x019f
escrow_bytes                    equ 0x01a0

escrow_magic_0                  equ 0x434b       ; "KC"
escrow_magic_1                  equ 0x3145       ; "E1"
escrow_magic_inverse_0          equ 0xbcb4
escrow_magic_inverse_1          equ 0xcebA
escrow_status_valid             equ 0xa5
escrow_status_valid_inverse     equ 0x5a

%if K14_CONFIG_SENSITIVE_START > K14_CONFIG_CACHE
%error "K14 config scrub begins above its cache"
%endif
%if K14_CONFIG_SENSITIVE_END != K14_CONFIG_CACHE + escrow_cache_len
%error "K14 config scrub does not end at the cache boundary"
%endif

k14_config_escrow_save:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push es
    cld
    or dx, dx
    jz .bad
    call k14_config_escrow_map
    jc .bad

    ; Invalidate and erase the complete prior object before publishing a new
    ; one.  DI remains the mapped object base.
    call k14_config_escrow_clear
    push di
    mov si, K14_CONFIG_CACHE
    mov cx, escrow_cache_len
    rep movsb
    pop di
    mov al, [K14_CURSOR_ROW]
    mov [es:di + escrow_ui_offset + 0], al
    mov al, [K14_CURSOR_COL]
    mov [es:di + escrow_ui_offset + 1], al
    mov al, [K14_PROMPT_MARKER_ROW]
    mov [es:di + escrow_ui_offset + 2], al
    mov al, [K14_AGENT_LOOP_PENDING]
    mov [es:di + escrow_ui_offset + 3], al
    mov al, [K14_AGENT_LOOP_COUNT]
    mov [es:di + escrow_ui_offset + 4], al

    mov word [es:di + escrow_magic_offset], escrow_magic_0
    mov word [es:di + escrow_magic_offset + 2], escrow_magic_1
    mov word [es:di + escrow_magic_inverse_offset], \
        escrow_magic_inverse_0
    mov word [es:di + escrow_magic_inverse_offset + 2], \
        escrow_magic_inverse_1
    mov [es:di + escrow_generation_offset], dx
    not dx
    mov [es:di + escrow_generation_inverse], dx

    mov si, di
    mov cx, escrow_preimage_end
    mov bx, 0x8320
    mov bp, 0xedb8
    call k14_config_escrow_crc
    mov [es:di + escrow_crc32_offset], ax
    mov [es:di + escrow_crc32_offset + 2], dx
    mov si, di
    mov cx, escrow_preimage_end
    mov bx, 0x3b78
    mov bp, 0x82f6
    call k14_config_escrow_crc
    mov [es:di + escrow_crc32c_offset], ax
    mov [es:di + escrow_crc32c_offset + 2], dx

    ; The escrow object now contains the only credential copy allowed before
    ; route authorization.  Retire both the original parsed config and the
    ; reconnect cache before making that object valid.  Restore republishes
    ; only the cache after every authentication gate has passed.
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, K14_CONFIG_SENSITIVE_START
    mov cx, K14_CONFIG_SENSITIVE_END - K14_CONFIG_SENSITIVE_START
    rep stosb
    pop es
    pop di

    ; Publish inverse first and status physically last.
    mov byte [es:di + escrow_inverse_status_offset], \
        escrow_status_valid_inverse
    mov byte [es:di + escrow_status_offset], escrow_status_valid
    clc
    jmp short .done
.bad:
    stc
.done:
    cld
    pop es
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

k14_config_escrow_restore:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push es
    cld
    call k14_config_escrow_map
    jc .bad_unmapped
    cmp byte [es:di + escrow_status_offset], escrow_status_valid
    jne .bad_mapped
    cmp byte [es:di + escrow_inverse_status_offset], \
        escrow_status_valid_inverse
    jne .bad_mapped
    cmp word [es:di + escrow_magic_offset], escrow_magic_0
    jne .bad_mapped
    cmp word [es:di + escrow_magic_offset + 2], escrow_magic_1
    jne .bad_mapped
    cmp word [es:di + escrow_magic_inverse_offset], \
        escrow_magic_inverse_0
    jne .bad_mapped
    cmp word [es:di + escrow_magic_inverse_offset + 2], \
        escrow_magic_inverse_1
    jne .bad_mapped
    mov ax, [es:di + escrow_generation_offset]
    or ax, ax
    jz .bad_mapped
    mov dx, [es:di + escrow_generation_inverse]
    not dx
    cmp ax, dx
    jne .bad_mapped

    mov si, di
    mov cx, escrow_preimage_end
    mov bx, 0x8320
    mov bp, 0xedb8
    call k14_config_escrow_crc
    cmp ax, [es:di + escrow_crc32_offset]
    jne .bad_mapped
    cmp dx, [es:di + escrow_crc32_offset + 2]
    jne .bad_mapped
    mov si, di
    mov cx, escrow_preimage_end
    mov bx, 0x3b78
    mov bp, 0x82f6
    call k14_config_escrow_crc
    cmp ax, [es:di + escrow_crc32c_offset]
    jne .bad_mapped
    cmp dx, [es:di + escrow_crc32c_offset + 2]
    jne .bad_mapped

    ; Validation is complete.  Only now publish conventional state.
    push di
    mov si, di
    mov di, K14_CONFIG_CACHE
    mov cx, escrow_cache_len
    push ds
    push es
    pop ds
    pop es
    rep movsb
    push es
    push ds
    pop es
    pop ds
    pop di
    mov al, [es:di + escrow_ui_offset + 0]
    mov [K14_CURSOR_ROW], al
    mov al, [es:di + escrow_ui_offset + 1]
    mov [K14_CURSOR_COL], al
    mov al, [es:di + escrow_ui_offset + 2]
    mov [K14_PROMPT_MARKER_ROW], al
    mov al, [es:di + escrow_ui_offset + 3]
    mov [K14_AGENT_LOOP_PENDING], al
    mov al, [es:di + escrow_ui_offset + 4]
    mov [K14_AGENT_LOOP_COUNT], al
    call k14_config_escrow_clear
    clc
    jmp short .done

.bad_mapped:
    call k14_config_escrow_clear
.bad_unmapped:
    stc
.done:
    cld
    pop es
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Output ES:DI = exact 416-byte escrow window.
k14_config_escrow_map:
    mov ax, [escrow_bda_crt_port]
    cmp ax, escrow_mda_crt_port
    je .mda
    cmp ax, escrow_cga_crt_port
    jne .bad
    mov ax, escrow_cga_segment
    mov es, ax
    mov di, escrow_cga_offset
    clc
    ret
.mda:
    mov ax, escrow_mda_segment
    mov es, ax
    mov di, escrow_mda_offset
    clc
    ret
.bad:
    stc
    ret

; ES:DI mapped object.  Preserve DI for the caller.
k14_config_escrow_clear:
    push di
    xor ax, ax
    mov cx, escrow_bytes / 2
    rep stosw
    pop di
    ret

; ES:SI bytes, CX count, BP:BX reflected polynomial -> DX:AX CRC32.
k14_config_escrow_crc:
    mov ax, 0xffff
    mov dx, 0xffff
.byte:
    xor al, [es:si]
    inc si
    push cx
    mov cx, 8
.bit:
    shr dx, 1
    rcr ax, 1
    jnc .next_bit
    xor ax, bx
    xor dx, bp
.next_bit:
    loop .bit
    pop cx
    loop .byte
    not ax
    not dx
    ret

k14_config_escrow_end:

%if escrow_bytes != 416
%error "K14 config escrow physical object geometry drifted"
%endif
%if (k14_config_escrow_end - k14_config_escrow_table) > 1024
%error "K14 config escrow exceeds its two-sector phase"
%endif
