; Build 12 (2-image): the floppy geometry is adopted from the boot-sector BPB at startup
; (detect_floppy_geometry) so ONE SEED.SYS works on a 160K single-sided OR a 360K
; double-sided image. read_abs_sector turns the LBA in AX into CHS with that geometry:
; LBA / spt -> track (rem = sector), track / heads -> cylinder (rem = head). For the 160K
; default (spt=8, heads=1) this is byte-for-byte the same CHS as the old hardcoded path.
read_abs_sector:
    push ax
    push cx
    div byte [fs_sectors_per_track]   ; al = track, ah = sector-in-track
    mov cl, ah
    inc cl                            ; INT 13h sector is 1-based
    mov ah, 0
    div byte [fs_heads]               ; al = cylinder, ah = head
    mov ch, al
    mov dh, ah
    mov dl, [handoff_addr + handoff_boot_drive]
    mov ax, 0x0201
    int 0x13
    pop cx
    pop ax
    ret

; Read the boot sector (LBA 0 = CHS 0/0/1, which is geometry-independent) and adopt its
; BPB sectors-per-track (0x18) + heads (0x1a). Runs once at boot, before the first phase
; load. Leaves the 160K default (8 spt / 1 head) if the read fails or the BPB is blank.
detect_floppy_geometry:
    push es
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov dl, [handoff_addr + handoff_boot_drive]
    mov cx, 0x0001                    ; cylinder 0, sector 1
    xor dh, dh                        ; head 0
    mov ax, 0x0201
    int 0x13
    jc .done
    mov al, [fs_sector_buffer + 0x18]
    or al, al
    jz .done
    mov [fs_sectors_per_track], al
    mov al, [fs_sector_buffer + 0x1a]
    or al, al
    jz .done
    mov [fs_heads], al
.done:
    pop es
    ret

fs_sectors_per_track db 8
fs_heads db 1
