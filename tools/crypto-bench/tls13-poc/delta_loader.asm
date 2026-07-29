; Low trampoline for restoring a contiguous K-overlay prefix without
; executing from the destination being overwritten.
;
; Load at 0000:0f00 after the HELLO transcript handoff (ends at 0x0dab).
; Entry ABI: AX=absolute floppy LBA, BX=destination, CX=sector count,
; DS=SS=0.  Registers are preserved; CF reports the BIOS result.
;
; Reads are batched only to the end of the current track.  On the first
; multi-sector BIOS rejection the trampoline resets the drive and falls back
; to one-sector calls for the rest of the request.

bits 16
cpu 8086
org 0x0f00

delta_fs_spt       equ 0x138f
delta_fs_heads     equ 0x1390
delta_boot_drive   equ 0x060a

delta_load:
    cld
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push es
    push ds
    pop es
    or cx, cx
    jz .failed
    cmp byte [delta_fs_spt], 0
    je .failed
    cmp byte [delta_fs_heads], 0
    je .failed
    mov si, ax
    mov bp, cx
    mov byte [delta_single_sector], 0

.next:
    mov ax, si
    div byte [delta_fs_spt]          ; AL=track, AH=zero-based sector
    mov cl, ah
    inc cl                           ; one-based BIOS sector
    mov dl, [delta_fs_spt]
    sub dl, ah                       ; sectors remaining on this track
    xor dh, dh
    mov di, dx
    cmp bp, di
    jae .remaining_ready
    mov di, bp
.remaining_ready:
    cmp byte [delta_single_sector], 0
    je .run_ready
    mov di, 1
.run_ready:
    xor ah, ah
    div byte [delta_fs_heads]        ; AL=cylinder, AH=head
    mov ch, al
    mov dh, ah
    mov ax, di                       ; AL=bounded sector count
    mov ah, 0x02
    mov dl, [delta_boot_drive]
    int 0x13
    jnc .read_ok
    cmp byte [delta_single_sector], 0
    jne .failed
    mov byte [delta_single_sector], 1
    xor ah, ah                       ; reset before conservative fallback
    int 0x13
    jc .failed
    jmp short .next

.read_ok:
    mov ax, di
    add si, ax
    sub bp, ax
    mov cl, 9
    shl ax, cl
    add bx, ax
    or bp, bp
    jnz .next
    clc
    jmp short .restore
.failed:
    stc
.restore:
    pop es
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

delta_single_sector db 0
delta_loader_end:

%if (delta_loader_end - $$) > 0x100
%error "delta loader exceeds the low 0x0f00 trampoline sector"
%endif
