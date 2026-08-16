; Stateless volatile 3328-byte precommit vault for the 16 KiB TLS 1.3 path.
;
; This product backend replaces the resumption proof's NE2000 card range
; 7300..7fff without floppy writes or NIC RAM.  Payload and every mutable
; lifecycle byte live in video RAM:
;
;   CGA  B800:1000..1cff payload, B800:1d00..1dff metadata
;   MDA  B000:0000..0cff payload, B000:0d00..0dff metadata
;
; MDA output is disabled through port 03b8 before the visible page is touched.
; The 6845 scanout is also narrowed and redirected to a zeroed quarantine cell:
; some adapters/emulators retain the mode byte without honoring its output bit.
; The write-only mode register is recovered from the BIOS shadow only after
; payload+metadata erasure.  That post-scrub display value is not part of the
; confidentiality boundary.  BIOS/direct video writes and mode/page changes
; are forbidden while the vault is active.
;
; Product resumption has a distinct intermediate retirement boundary.  It
; erases every vault-owned byte while the adjacent config escrow is still the
; only credential copy.  On MDA it leaves the hardware quarantine in place;
; terminal zeroize runs only after the config escrow has been restored and
; erased.
;
; Direct drop-in NE call contracts:
;
;   write: AL=virtual page 73h..7fh, SI=source, BP=count (>0).
;          Destination page offset is zero and the count may span pages.
;   read:  BX=virtual address 7300h..7fff, CX=count (>0), DI=destination.
;
; Both return CF clear on success and set on failure.  Both preserve all input
; registers, DS, ES, SS and BP, balance the 3f00..4000 stack, and return DF
; clear.  This is stronger than the real NE leaf's clobber contract.
;
; Each 256-byte virtual page has an IEEE CRC32 and its bitwise inverse binding
; generation_le16 || page_index || page.  A write verifies the old value of
; every partially overwritten page, invalidates global status first, copies
; the complete requested span, recomputes touched tags, advances the redundant
; epoch, then publishes status physically last.  Complete-page replacement
; does not spend 8088 cycles authenticating bytes that no longer influence the
; new object.  A read still verifies every touched page before returning any
; byte.  Torn/stale writes therefore fail closed.  These tags protect against
; accidental corruption and lifecycle confusion; arbitrary malicious local
; memory writes remain outside the Seed machine boundary.
;
; With PV_ACCESS_ONLY=1 the build emits only a two-pointer table followed by
; the stateless read/write leaf.  The leaf has no mutable conventional state
; and no absolute references to its own image, so it can be assembled into
; every consuming phase.  Arbitrary phase overwrites between calls are safe.

bits 16
cpu 8086

%ifndef PV_LOAD_ADDR
    %define PV_LOAD_ADDR 0x2400
%endif

org PV_LOAD_ADDR

pv_backend_cga                 equ 0
pv_backend_mda                 equ 1
pv_virtual_start               equ 0x7300
pv_virtual_end                 equ 0x8000
pv_page_count                  equ 13
pv_page_len                    equ 256
pv_payload_len                 equ pv_page_count * pv_page_len

pv_cga_segment                 equ 0xb800
pv_cga_offset                  equ 0x1000
pv_mda_segment                 equ 0xb000
pv_mda_offset                  equ 0x0000
pv_mda_visible_bytes           equ 4000
pv_bda_crt_port                equ 0x0463
pv_bda_mode_control            equ 0x0465
pv_mda_crt_port                equ 0x03b4
pv_cga_crt_port                equ 0x03d4
pv_mda_mode_port               equ 0x03b8
pv_video_enable_inverse        equ 0xf7
pv_mda_crtc_data_port          equ pv_mda_crt_port + 1
pv_mda_hdisplay_reg            equ 0x01
pv_mda_start_high_reg          equ 0x0c
pv_mda_start_low_reg           equ 0x0d
pv_mda_normal_columns          equ 80
pv_mda_quarantine_offset       equ 0x0fa0
pv_mda_quarantine_address      equ pv_mda_quarantine_offset / 2
pv_mda_quarantine_cells        equ 25

pv_meta_rel                    equ pv_payload_len
pv_meta_len                    equ 256
pv_owned_len                   equ pv_payload_len + pv_meta_len
pv_meta_magic                  equ pv_meta_rel + 0x00
pv_meta_inverse                equ pv_meta_rel + 0x04
pv_meta_generation             equ pv_meta_rel + 0x08
pv_meta_generation_inverse     equ pv_meta_rel + 0x0a
pv_meta_epoch                  equ pv_meta_rel + 0x0c
pv_meta_epoch_inverse          equ pv_meta_rel + 0x0e
pv_meta_backend                equ pv_meta_rel + 0x10
pv_meta_backend_inverse        equ pv_meta_rel + 0x11
pv_meta_video_a                equ pv_meta_rel + 0x12
pv_meta_video_b                equ pv_meta_rel + 0x13
pv_meta_video_inverse          equ pv_meta_rel + 0x14
pv_meta_access_mode            equ pv_meta_rel + 0x15
pv_meta_access_mode_inverse    equ pv_meta_rel + 0x16
pv_meta_tags                   equ pv_meta_rel + 0x20
pv_meta_inverse_status         equ pv_meta_rel + 0xfe
pv_meta_status                 equ pv_meta_rel + 0xff

pv_magic_word0                 equ 0x5653       ; "SV"
pv_magic_word1                 equ 0x314c       ; "L1"
pv_inverse_word0               equ 0xa9ac
pv_inverse_word1               equ 0xceb3
pv_status_valid                equ 0xa5
pv_status_valid_inverse        equ 0x5a
pv_access_mode_checked         equ 0x3c
pv_access_mode_checked_inverse equ 0xc3
pv_access_mode_raw             equ 0xa5
pv_access_mode_raw_inverse     equ 0x5a

%ifdef PV_ACCESS_ONLY
pv_access_table:
    dw pv_write
    dw pv_read
%else
pv_entry_table:
    dw pv_begin
    dw pv_write
    dw pv_read
    dw pv_seal
    dw pv_verify
    dw pv_zeroize
    dw pv_retire
    dw pv_enter_raw
    dw pv_rebind_raw

; DX=nonzero lifecycle generation.  Backend is detected from the BIOS CRT
; controller port word, so callers do not acquire a new architecture ABI.
pv_begin:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push ds
    push es
    cld
    mov bp, dx
    or bp, bp
    jz .bad_input
    call pv_map
    jc .bad_input

    cmp dl, pv_backend_mda
    jne .display_held
    call pv_mda_hold
.display_held:
    call pv_clear_mapped
    call pv_map
    jc .bad

    mov word [es:bx + pv_meta_magic], pv_magic_word0
    mov word [es:bx + pv_meta_magic + 2], pv_magic_word1
    mov word [es:bx + pv_meta_inverse], pv_inverse_word0
    mov word [es:bx + pv_meta_inverse + 2], pv_inverse_word1
    mov [es:bx + pv_meta_generation], bp
    mov cx, bp
    not cx
    mov [es:bx + pv_meta_generation_inverse], cx
    mov word [es:bx + pv_meta_epoch], 0
    mov word [es:bx + pv_meta_epoch_inverse], 0xffff
    mov [es:bx + pv_meta_backend], dl
    mov dh, dl
    not dh
    mov [es:bx + pv_meta_backend_inverse], dh
    mov byte [es:bx + pv_meta_access_mode], pv_access_mode_checked
    mov byte [es:bx + pv_meta_access_mode_inverse], \
        pv_access_mode_checked_inverse
    mov byte [es:bx + pv_meta_inverse_status], 0
    mov byte [es:bx + pv_meta_status], 0
    xor ax, ax
    mov cx, pv_payload_len
    call pv_store_pages
    jc .bad
    mov byte [es:bx + pv_meta_inverse_status], pv_status_valid_inverse
    mov byte [es:bx + pv_meta_status], pv_status_valid
    clc
    jmp short .done
.bad:
    call pv_fail_closed
.bad_input:
    stc
.done:
    cld
    pop es
    pop ds
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Re-hash the complete current span without changing write authority.
pv_seal:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push ds
    push es
    cld
    call pv_map
    jc .bad_input
    call pv_validate_meta
    jc .bad
    xor ax, ax
    mov cx, pv_payload_len
    call pv_verify_pages
    jc .bad
    call pv_validate_meta
    jc .bad
    clc
    jmp short .done
.bad:
    call pv_fail_closed
.bad_input:
    stc
.done:
    cld
    pop es
    pop ds
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; DX=expected lifecycle generation.
pv_verify:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push ds
    push es
    cld
    mov bp, dx
    or bp, bp
    jz .bad_input
    call pv_map
    jc .bad_input
    call pv_validate_meta
    jc .bad
    cmp bp, [es:bx + pv_meta_generation]
    jne .bad
    xor ax, ax
    mov cx, pv_payload_len
    call pv_verify_pages
    jc .bad
    call pv_validate_meta
    jc .bad
    clc
    jmp short .done
.bad:
    call pv_fail_closed
.bad_input:
    stc
.done:
    cld
    pop es
    pop ds
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Deadline handoff.  Verify the complete checked vault once, then publish a
; status-last raw epoch.  The K14 8088 route may update only
; cryptographically bound/duplicated objects in this mode; ordinary access
; leaves reject it until pv_rebind_raw has rebuilt every page tag.
pv_enter_raw:
    cld
    call pv_seal
    jc .bad_input
    call pv_map
    jc .bad_input
    call pv_validate_meta
    jc .bad
    mov byte [es:bx + pv_meta_status], 0
    mov byte [es:bx + pv_meta_inverse_status], 0
    mov byte [es:bx + pv_meta_access_mode], pv_access_mode_raw
    mov byte [es:bx + pv_meta_access_mode_inverse], \
        pv_access_mode_raw_inverse
    call pv_commit_status
    clc
    jmp short .done
.bad:
    call pv_fail_closed
.bad_input:
    stc
.done:
    cld
    ret

; Off-deadline conversion back to the ordinary checked vault.  A completed
; raw epoch is not an authority grant: the caller still owes the handshake,
; full-FO, and identity proofs.  This leaf merely binds the current bytes to
; fresh CRC tags so later ordinary access can fail closed on new corruption.
pv_rebind_raw:
    cld
    call pv_map
    jc .bad_input
    call pv_validate_meta_raw
    jc .bad
    mov byte [es:bx + pv_meta_status], 0
    mov byte [es:bx + pv_meta_inverse_status], 0
    xor ax, ax
    mov cx, pv_payload_len
    call pv_store_pages
    jc .bad
    mov byte [es:bx + pv_meta_access_mode], pv_access_mode_checked
    mov byte [es:bx + pv_meta_access_mode_inverse], \
        pv_access_mode_checked_inverse
    call pv_commit_status
    clc
    jmp short .done
.bad:
    call pv_fail_closed
.bad_input:
    stc
.done:
    cld
    ret

pv_zeroize:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push ds
    push es
    cld
    call pv_fail_closed
    clc
    cld
    pop es
    pop ds
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Intermediate product retirement.  Erase all payload, integrity, generation,
; and lifecycle state without touching the adjacent config escrow.  It
; deliberately performs no port I/O: the MDA quarantine remains live and the
; credential-bearing config escrow stays hidden until its validated restore
; has erased that tail.
pv_retire:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push ds
    push es
    cld
    call pv_map
    jc .bad

    ; Invalidate before the first payload byte.  A torn retirement can never
    ; remain a readable vault object.
    mov byte [es:bx + pv_meta_status], 0
    mov byte [es:bx + pv_meta_inverse_status], 0
    call pv_clear_owned
.ok:
    clc
    jmp short .done
.bad:
    stc
.done:
    cld
    pop es
    pop ds
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; ES video, BX base.  Clear only the public vault's payload+metadata ownership
; interval.  In particular this never reaches the adjacent 416-byte product
; config escrow.
pv_clear_owned:
    push ax
    push cx
    push di
    mov di, bx
    xor ax, ax
    mov cx, pv_owned_len / 2
    rep stosw
    pop di
    pop cx
    pop ax
    ret

; ES=B000.  The real adapter's mode register is write-only, so 0040:0065 is
; the available post-scrub display shadow.  A one-column
; scanout rooted in the 96 bytes beyond the visible 4,000-byte page makes the
; hold effective on implementations that ignore mode-control bit 3.  Only the
; first 25 cells can be fetched while the ordinary 25-row timing remains live.
pv_mda_hold:
    xor ax, ax
    mov di, pv_mda_quarantine_offset
    mov cx, pv_mda_quarantine_cells
    rep stosw
    mov al, [pv_bda_mode_control]
    and al, pv_video_enable_inverse
    mov dx, pv_mda_mode_port
    out dx, al
    mov dx, pv_mda_crt_port
    mov al, pv_mda_hdisplay_reg
    out dx, al
    inc dx
    mov al, 1
    out dx, al
    dec dx
    mov al, pv_mda_start_high_reg
    out dx, al
    inc dx
    mov al, pv_mda_quarantine_address >> 8
    out dx, al
    dec dx
    mov al, pv_mda_start_low_reg
    out dx, al
    inc dx
    mov al, pv_mda_quarantine_address & 0xff
    out dx, al
    ret
%endif

; Everything from here through pv_access_leaf_end is duplicated into each
; card-consuming phase.  It owns no conventional mutable byte.
pv_access_leaf_start:

; AL=virtual page, SI=source, BP=count.
pv_write:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push ds
    push es
    cld
    cmp al, 0x73
    jb .bad
    cmp al, 0x7f
    ja .bad
    or bp, bp
    jz .bad
    mov dx, si
    add dx, bp
    jc .bad
    sub al, 0x73
    mov ah, al
    xor al, al
    mov di, ax
    add ax, bp
    jc .bad
    cmp ax, pv_payload_len
    ja .bad
    call pv_map
    jc .bad_return
    call pv_validate_meta
    jc .bad
    ; The write ABI starts at a page boundary.  Fully replaced pages have no
    ; old byte that can influence the resulting object, so only a partial tail
    ; needs its old tag checked before the write preserves that tail.
    mov ax, bp
    or al, al
    jz .old_value_ready
    mov ax, di
    add ax, bp
    dec ax
    and ax, 0xff00
    mov cx, 1
    call pv_verify_pages
    jc .bad
.old_value_ready:

    ; Invalidate before the first payload byte.  Any interrupted update is
    ; unreadable until a complete later begin.
    mov byte [es:bx + pv_meta_status], 0
    mov byte [es:bx + pv_meta_inverse_status], 0
    push di
    add di, bx
    mov cx, bp
    rep movsb
    pop di
    mov ax, di
    mov cx, bp
    call pv_store_pages
    jc .bad
    call pv_commit_status
    clc
    jmp short .done
.bad:
    call pv_fail_closed
.bad_return:
    stc
.done:
    cld
    pop es
    pop ds
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; BX=virtual address, CX=count, DI=destination.
pv_read:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push ds
    push es
    cld
    or cx, cx
    jz .bad
    cmp bx, pv_virtual_start
    jb .bad
    mov ax, bx
    add ax, cx
    jc .bad
    cmp ax, pv_virtual_end
    ja .bad
    mov ax, di
    add ax, cx
    jc .bad
    mov bp, bx
    sub bp, pv_virtual_start
    call pv_map
    jc .bad_return
    call pv_validate_meta
    jc .bad
    mov ax, bp
    call pv_verify_pages
    jc .bad
    call pv_validate_meta
    jc .bad

    mov si, bx
    add si, bp
    push es
    xor ax, ax
    mov es, ax
    pop ds
    rep movsb
    clc
    jmp short .done
.bad:
    call pv_fail_closed
.bad_return:
    stc
.done:
    cld
    pop es
    pop ds
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Detect the active text adapter from the BIOS CRT controller base.
; Output: ES video segment, BX vault base offset, DL backend.
pv_map:
    push ax
    mov ax, [pv_bda_crt_port]
    cmp ax, pv_mda_crt_port
    je .mda
    cmp ax, pv_cga_crt_port
    jne .bad
    mov ax, pv_cga_segment
    mov es, ax
    mov bx, pv_cga_offset
    mov dl, pv_backend_cga
    clc
    pop ax
    ret
.mda:
    mov ax, pv_mda_segment
    mov es, ax
    mov bx, pv_mda_offset
    mov dl, pv_backend_mda
    clc
    pop ax
    ret
.bad:
    stc
    pop ax
    ret

; Validate status-last metadata and all redundant scalar pairs.  Ordinary
; callers accept only the CRC-checked access mode.
pv_validate_meta:
    mov ax, (pv_access_mode_checked_inverse << 8) | \
        pv_access_mode_checked
    jmp short pv_validate_meta_mode

; Rebinding is the sole full-image consumer allowed to enter from raw mode.
pv_validate_meta_raw:
    mov ax, (pv_access_mode_raw_inverse << 8) | pv_access_mode_raw

pv_validate_meta_mode:
    cmp [es:bx + pv_meta_access_mode], ax
    jne .bad_mode
    jmp short pv_validate_meta_common
.bad_mode:
    stc
    ret

pv_validate_meta_common:
    push ax
    push cx
    push dx
    cmp word [es:bx + pv_meta_magic], pv_magic_word0
    jne .bad
    cmp word [es:bx + pv_meta_magic + 2], pv_magic_word1
    jne .bad
    cmp word [es:bx + pv_meta_inverse], pv_inverse_word0
    jne .bad
    cmp word [es:bx + pv_meta_inverse + 2], pv_inverse_word1
    jne .bad
    mov ax, [es:bx + pv_meta_generation]
    or ax, ax
    jz .bad
    mov cx, ax
    not cx
    cmp cx, [es:bx + pv_meta_generation_inverse]
    jne .bad
    mov ax, [es:bx + pv_meta_epoch]
    not ax
    cmp ax, [es:bx + pv_meta_epoch_inverse]
    jne .bad
    cmp dl, [es:bx + pv_meta_backend]
    jne .bad
    mov dh, dl
    not dh
    cmp dh, [es:bx + pv_meta_backend_inverse]
    jne .bad
.status:
    cmp byte [es:bx + pv_meta_inverse_status], pv_status_valid_inverse
    jne .bad
    cmp byte [es:bx + pv_meta_status], pv_status_valid
    jne .bad
    clc
    jmp short .done
.bad:
    stc
.done:
    pop dx
    pop cx
    pop ax
    ret

; ES video, BX vault base.  Advance the redundant epoch and publish validity
; physically last after the caller has completed payload/tag/mode writes.
pv_commit_status:
    push ax
    mov ax, [es:bx + pv_meta_epoch]
    inc ax
    mov [es:bx + pv_meta_epoch], ax
    not ax
    mov [es:bx + pv_meta_epoch_inverse], ax
    mov byte [es:bx + pv_meta_inverse_status], pv_status_valid_inverse
    mov byte [es:bx + pv_meta_status], pv_status_valid
    pop ax
    ret

; Input AX payload-relative start, CX count.  Verify every touched page before
; any caller copies or overwrites a byte.
pv_verify_pages:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    mov bp, ax
    mov dl, ah
    add ax, cx
    dec ax
    mov dh, ah
.next:
    mov al, dl
    call pv_page_compare
    jc .bad
    cmp dl, dh
    je .ok
    inc dl
    jmp short .next
.ok:
    clc
    jmp short .done
.bad:
    stc
.done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Input AX payload-relative start, CX count.  Recompute every touched tag.
pv_store_pages:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    mov bp, ax
    mov dl, ah
    add ax, cx
    dec ax
    mov dh, ah
.next:
    mov al, dl
    call pv_page_store
    jc .bad
    cmp dl, dh
    je .ok
    inc dl
    jmp short .next
.ok:
    clc
    jmp short .done
.bad:
    stc
.done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; AL page index, ES video, BX vault base.
pv_page_compare:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    xor ah, ah
    mov bp, ax
    mov si, bx
    mov ah, al
    xor al, al
    add si, ax
    mov di, bx
    add di, pv_meta_rel
    call pv_crc32_ieee_page
    mov di, bp
    shl di, 1
    shl di, 1
    shl di, 1
    add di, bx
    add di, pv_meta_tags
    cmp ax, [es:di]
    jne .bad
    cmp dx, [es:di + 2]
    jne .bad
    not ax
    not dx
    cmp ax, [es:di + 4]
    jne .bad
    cmp dx, [es:di + 6]
    jne .bad
    clc
    jmp short .done
.bad:
    stc
.done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; AL page index, ES video, BX vault base.
pv_page_store:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    xor ah, ah
    mov bp, ax
    mov si, bx
    mov ah, al
    xor al, al
    add si, ax
    mov di, bx
    add di, pv_meta_rel
    call pv_crc32_ieee_page
    mov di, bp
    shl di, 1
    shl di, 1
    shl di, 1
    add di, bx
    add di, pv_meta_tags
    mov [es:di], ax
    mov [es:di + 2], dx
    not ax
    not dx
    mov [es:di + 4], ax
    mov [es:di + 6], dx
    clc
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; ES:SI page, ES:DI metadata, BP page index -> DX:AX IEEE CRC32.
pv_crc32_ieee_page:
    push bx
    push cx
    push si
    push di
    push bp
    mov cx, bp
    mov ax, 0xffff
    mov dx, 0xffff
    mov bl, [es:di + 8]
    call .byte
    mov bl, [es:di + 9]
    call .byte
    mov bx, cx
    call .byte
    mov cx, pv_page_len
.next:
    mov bl, [es:si]
    inc si
    call .byte
    loop .next
    not ax
    not dx
    pop bp
    pop di
    pop si
    pop cx
    pop bx
    ret
.byte:
    xor al, bl
    mov bp, 8
.bit:
    test ax, 1
    jz .shift
    shr dx, 1
    rcr ax, 1
    xor ax, 0x8320
    xor dx, 0xedb8
    jmp short .again
.shift:
    shr dx, 1
    rcr ax, 1
.again:
    dec bp
    jnz .bit
    ret

; Erase the active backend and only then restore MDA scanout/output.  The BIOS
; shadow is sufficient for post-scrub display recovery; it is not part of the
; confidentiality boundary and no mutable saved-mode copy is retained here.
pv_fail_closed:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push ds
    push es
    cld
    call pv_map
    jc .done
    xor ah, ah
    cmp dl, pv_backend_mda
    jne .clear
    mov ah, 1
.clear:
    push ax
    call pv_clear_mapped
    pop ax
    or ah, ah
    jz .done
    call pv_mda_restore
.done:
    cld
    pop es
    pop ds
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; The visible page has already been scrubbed.  Restore the only IBM MDA text
; geometry (80 columns, page zero) before making the write-only mode control
; live again; the product caller redraws afterward.
pv_mda_restore:
    mov dx, pv_mda_crt_port
    mov al, pv_mda_start_high_reg
    out dx, al
    inc dx
    xor al, al
    out dx, al
    dec dx
    mov al, pv_mda_start_low_reg
    out dx, al
    inc dx
    xor al, al
    out dx, al
    dec dx
    mov al, pv_mda_hdisplay_reg
    out dx, al
    inc dx
    mov al, pv_mda_normal_columns
    out dx, al
    mov dx, pv_mda_mode_port
    mov al, [pv_bda_mode_control]
    or al, 0x08
    out dx, al
    ret

; ES video, BX base.  MDA owns/scrubs the complete visible 4000-byte page;
; CGA owns only its off-screen payload+metadata window.
pv_clear_mapped:
    push ax
    push cx
    push di
    push es
    mov ax, es
    cmp ax, pv_mda_segment
    jne .cga
    mov cx, pv_mda_visible_bytes / 2
    jmp short .clear
.cga:
    mov cx, pv_owned_len / 2
.clear:
    mov di, bx
    xor ax, ax
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret

pv_access_leaf_end:
pv_access_leaf_bytes equ pv_access_leaf_end - pv_access_leaf_start
pv_image_end:
pv_image_bytes equ pv_image_end - $$

%if pv_payload_len != 3328
    %error "linear vault payload is not exactly 3328 bytes"
%endif
%if (pv_meta_tags + pv_page_count * 8) > (pv_meta_rel + 0xfe)
    %error "linear vault page tags reach status-last bytes"
%endif
%if pv_owned_len > pv_mda_visible_bytes
    %error "linear vault exceeds visible MDA VRAM"
%endif
%if (pv_cga_offset + pv_owned_len) > 0x4000
    %error "linear vault exceeds CGA VRAM"
%endif
%if (pv_access_leaf_bytes) > 1024
    %error "linear vault duplicated access leaf exceeds two sectors"
%endif
%ifndef PV_ACCESS_ONLY
%if (PV_LOAD_ADDR + pv_image_bytes) > 0x3000
    %error "linear vault full image reaches 3000"
%endif
%endif
