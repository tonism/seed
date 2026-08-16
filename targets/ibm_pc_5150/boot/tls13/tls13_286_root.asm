; Compact root continuation for the 286 product tail.
;
; The pack loader is already resident at 0000:3400.  This continuation is
; fixed at 0000:3910, leaving the complete 0x3c00..3fff live-state band
; untouched.  Entry caches and validates the 44-sector asymmetric pack before
; any NIC lease, then loads the compressed precompute controller.  Later
; controllers call the same bounded component loader through the fixed table.

bits 16
cpu 8086

; Keep ORG literal here so NASM applies it before the equate-only ABI include.
; The assertion below still makes the shared ABI authoritative.
org 0x3910

%include "tls13/tls13_286_abi.inc"

root_service_table:
root_magic db 'S286RT02'
    dw root_entry
    dw root_chain_component
    dw root_abort

root_read_abs_sector equ 0x1343
root_fat_data_start  equ 11
; Compressed controllers are staged only in the retired low module window.
; Keeping this scratch below the current flight coordinator preserves it
; through the one-way controller handoff; offline auth may then deliberately
; retire its code by decoding P256W7/ECDSAW7.  Neither path reuses the
; authenticated high Certificate quarantine.
root_component_temp  equ tls13_286_module_load
root_component_cap   equ tls13_286_flight_load - tls13_286_module_load

root_entry:
    cld
    cmp al, 1
    ja root_abort
    cmp si, tls13_286_tail_footer_off
    jne root_abort
    mov [tls13_286_root_state_mode], al
    mov [tls13_286_root_state_crypto_seg], bx
    mov ax, [0x0413]
    mov cl, 6
    shl ax, cl
    sub ax, tls13_286_high_reserve_bytes / 16
    cmp ax, bx
    jne root_abort
    call root_validate_footer
    jc root_abort

    mov ax, tls13_286_tail_kind_module_pack
    call root_find_entry
    jc root_abort
    cmp word [si + tls13_286_tail_entry_flags], \
        tls13_286_tail_flag_product
    jne root_abort
    cmp word [si + tls13_286_tail_entry_sectors], 44
    jne root_abort
    cmp word [si + tls13_286_tail_entry_image_bytes], \
        tls13_286_pack_cache_bytes
    jne root_abort
    cmp word [si + tls13_286_tail_entry_load], 0
    jne root_abort
    mov ax, [si + tls13_286_tail_entry_start_sector]
    mov [cs:root_component_sector], ax
    mov ax, [si + tls13_286_tail_entry_crc16]
    mov [cs:root_component_crc], ax
    push cs
    pop ds
    mov ax, [cs:root_component_sector]
    mov cx, 44
    xor bx, bx
    mov es, [cs:tls13_286_root_state_crypto_seg]
    call root_read_sectors
    jc root_abort

    mov ds, [cs:tls13_286_root_state_crypto_seg]
    xor si, si
    mov cx, tls13_286_pack_cache_bytes
    call root_crc16
    cmp ax, [cs:root_component_crc]
    jne root_abort
    push cs
    pop ds
    push cs
    pop es
    mov bx, tls13_286_root_state_loader
    mov ax, [cs:tls13_286_root_state_crypto_seg]
    mov [bx + tls13_286_state_cache_seg], ax
    mov word [bx + tls13_286_state_cache_capacity], \
        tls13_286_pack_cache_bytes
    call word [tls13_286_loader_load + tls13_286_loader_entry_validate]
    jc root_abort

    mov ax, tls13_286_tail_kind_precompute

; AX=tail kind.  This is the only safe transition between low controllers:
; it never returns through bytes that the decoder has just overwritten.
root_chain_component:
    ; Low controllers may leave DS naming transport or crypto scratch.  This
    ; near service is fixed in segment zero, so re-establish the root data
    ; segment before validating any root-state or footer byte.
    push cs
    pop ds
    call root_load_component
    jc root_abort
    mov al, [tls13_286_root_state_mode]
    mov bx, [tls13_286_root_state_crypto_seg]
    mov si, tls13_286_tail_footer_off
    jmp dx

; AX=tail kind -> decoded controller, DX=validated entry, CF status.
; This is intentionally not exported in the service table: a low-controller
; caller cannot safely return after the operation overwrites its own code.
root_load_component:
    push ax
    call root_validate_footer
    pop ax
    jc .bad
    call root_find_entry
    jc .bad
    cmp word [si + tls13_286_tail_entry_flags], \
        tls13_286_tail_flag_product | tls13_286_tail_flag_raw_lz4
    jne .bad
    mov cx, [si + tls13_286_tail_entry_sectors]
    or cx, cx
    jz .bad
    cmp cx, root_component_cap / 512
    ja .bad
    mov ax, [si + tls13_286_tail_entry_image_bytes]
    cmp ax, tls13_286_tail_lz4_header_bytes
    jbe .bad
    mov dx, cx
    mov dh, dl
    xor dl, dl
    shl dx, 1
    cmp ax, dx
    ja .bad
    mov [cs:root_stored_bytes], ax
    mov ax, [si + tls13_286_tail_entry_start_sector]
    mov [cs:root_component_sector], ax
    mov ax, [si + tls13_286_tail_entry_load]
    mov [cs:root_component_load], ax
    mov ax, [si + tls13_286_tail_entry_entry]
    mov [cs:root_component_entry], ax
    mov ax, [si + tls13_286_tail_entry_crc16]
    mov [cs:root_component_crc], ax

    mov ax, [cs:root_component_sector]
    mov bx, root_component_temp
    xor dx, dx
    mov es, dx
    mov ds, dx
    call root_read_sectors
    jc .bad_low
    cmp word [root_component_temp + tls13_286_tail_lz4_magic], 'LZ'
    jne .bad_low
    cmp word [root_component_temp + tls13_286_tail_lz4_magic + 2], '4B'
    jne .bad_low
    cmp word [root_component_temp + tls13_286_tail_lz4_reserved], 0
    jne .bad_low
    mov cx, [root_component_temp + tls13_286_tail_lz4_block_bytes]
    mov ax, cx
    add ax, tls13_286_tail_lz4_header_bytes
    cmp ax, [cs:root_stored_bytes]
    jne .bad_low
    mov dx, [root_component_temp + tls13_286_tail_lz4_raw_bytes]
    mov bp, [root_component_temp + tls13_286_tail_lz4_crc16]
    cmp bp, [cs:root_component_crc]
    jne .bad_low
    mov di, [cs:root_component_load]
    mov ax, [cs:root_component_entry]
    cmp ax, di
    jb .bad_low
    mov bx, di
    add bx, dx
    jc .bad_low
    cmp ax, bx
    jae .bad_low
    mov [cs:root_component_entry], ax
    mov si, root_component_temp + tls13_286_tail_lz4_header_bytes
    xor ax, ax
    mov es, ax
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    pushf
    call root_wipe_temp
    popf
    jc .bad
    mov dx, [cs:root_component_entry]
    clc
    ret
.bad_low:
    call root_wipe_temp
    stc
    ret
.bad:
    push cs
    pop ds
    push cs
    pop es
    stc
    ret

root_validate_footer:
    mov ax, [tls13_286_root_state_crypto_seg]
    mov ds, ax
    cmp word [tls13_286_escrow_status_inv_off], 0xa55a
    jne .bad
    cmp word [tls13_286_escrow_crypto_seg_off], ax
    jne .bad
    cmp word [tls13_286_rtc_status_inv_off], 0xa55a
    jne .bad
    mov si, tls13_286_tail_footer_off
    mov di, root_tail_magic
    mov cx, 8
.magic:
    mov al, [si]
    cmp al, [cs:di]
    jne .bad
    inc si
    inc di
    loop .magic
    cmp word [tls13_286_tail_footer_off + tls13_286_tail_abi], \
        tls13_286_abi_version
    jne .bad
    cmp word [tls13_286_tail_footer_off + \
        tls13_286_tail_header_bytes_off], tls13_286_tail_header_bytes
    jne .bad
    cmp word [tls13_286_tail_footer_off + \
        tls13_286_tail_entry_bytes_off], tls13_286_tail_entry_bytes
    jne .bad
    mov cx, [tls13_286_tail_footer_off + tls13_286_tail_entry_count]
    or cx, cx
    jz .bad
    cmp cx, tls13_286_tail_max_entries
    ja .bad
    mov si, tls13_286_tail_footer_off
    mov cx, tls13_286_tail_footer_crc
    call root_crc16
    cmp ax, [tls13_286_tail_footer_off + tls13_286_tail_footer_crc]
    jne .bad
    xor ax, ax
    mov ds, ax
    clc
    ret
.bad:
    xor ax, ax
    mov ds, ax
    stc
    ret

; AX=kind -> DS=crypto segment, SI=unique directory entry.
root_find_entry:
    mov dx, ax
    mov ds, [cs:tls13_286_root_state_crypto_seg]
    mov cx, [tls13_286_tail_footer_off + tls13_286_tail_entry_count]
    mov si, tls13_286_tail_footer_off + tls13_286_tail_directory_off
    mov word [cs:root_component_sector], 0
.next:
    cmp dx, [si + tls13_286_tail_entry_kind]
    jne .advance
    cmp word [cs:root_component_sector], 0
    jne .bad
    mov [cs:root_component_sector], si
.advance:
    add si, tls13_286_tail_entry_bytes
    loop .next
    mov si, [cs:root_component_sector]
    or si, si
    jz .bad
    mov ax, [si + tls13_286_tail_entry_start_sector]
    cmp ax, [tls13_286_tail_footer_off + tls13_286_tail_start_sector]
    jb .bad
    add ax, [si + tls13_286_tail_entry_sectors]
    jc .bad
    cmp ax, [tls13_286_tail_footer_off + tls13_286_tail_total_sectors]
    jae .bad
    clc
    ret
.bad:
    xor ax, ax
    mov ds, ax
    stc
    ret

; AX=SEED.SYS-relative sector, CX=count, ES:BX=destination.
root_read_sectors:
    add ax, root_fat_data_start
.next:
    call root_read_abs_sector
    jc .done
    add bx, 512
    inc ax
    loop .next
    clc
.done:
    ret

root_wipe_temp:
    xor ax, ax
    mov es, ax
    mov di, root_component_temp
    mov cx, root_component_cap / 2
    rep stosw
    mov ds, ax
    mov es, ax
    ret

root_abort:
    cld
    push cs
    pop ds
    push cs
    pop es
    xor ax, ax
    mov di, tls13_286_controller_load
    mov cx, tls13_286_controller_max_bytes / 2
    rep stosw
    jmp word [cs:0x0706]

root_crc16:
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

root_component_sector dw 0
root_stored_bytes dw 0
root_component_load dw 0
root_component_entry dw 0
root_component_crc dw 0
root_tail_magic db 'S286TL02'

root_image_end:

%if (root_service_table - $$) != 0
%error "TLS 1.3 286 root service table moved"
%endif
%if (root_entry - root_service_table) != tls13_286_root_service_bytes
%error "TLS 1.3 286 root entry moved"
%endif
%if (root_image_end - $$) > (0x3c00 - tls13_286_root_service_table)
%error "TLS 1.3 286 root continuation exceeds four-sector root stage"
%endif
%if (root_validate_footer - root_service_table) != \
    (tls13_286_root_validate_footer - tls13_286_root_service_table)
%error "TLS 1.3 286 preconnection footer validator moved"
%endif
%if (root_find_entry - root_service_table) != \
    (tls13_286_root_find_entry - tls13_286_root_service_table)
%error "TLS 1.3 286 preconnection directory lookup moved"
%endif
