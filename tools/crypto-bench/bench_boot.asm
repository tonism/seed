; Boot sector for the crypto bench on a STANDARD 360 KB floppy (9 spt / 2 heads),
; with a real BPB so AT-class BIOSes boot it. Loads up to 28 sectors of the bench
; SEED.SYS from sector 2 onward to 0000:1000 via a per-sector LBA->CHS loop (so it
; spans tracks/heads -- the P-256 ECDHE bench is >8 sectors). Then jumps to 1000.

bits 16
cpu 8086
org 0x7c00

    jmp short start
    nop
    db 'SEED    '
    dw 512
    db 2
    dw 1
    db 2
    dw 112
    dw 720
    db 0xFD
    dw 2
    dw 9
    dw 2
    dd 0
    dd 0
    db 0
    db 0
    db 0x29
    dd 0x43425948
    db 'CRYPTOBENCH'
    db 'FAT12   '

SECTORS equ 28

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7000
    sti
    cld
    mov [drive], dl

    mov word [lba], 1
    mov word [dest], 0x1000
    mov cx, SECTORS
.next:
    push cx
    mov di, 5                  ; per-sector retries
.retry:
    mov ax, [lba]
    xor dx, dx
    mov bx, 9
    div bx                     ; ax=LBA/9 (track), dx=LBA%9
    mov cl, dl
    inc cl                     ; sector = LBA%9 + 1
    xor dx, dx
    mov bx, 2
    div bx                     ; ax=track/2=cyl, dx=track%2=head
    mov ch, al                 ; cylinder (<40, fits 8 bits)
    mov dh, dl                 ; head
    mov dl, [drive]
    mov bx, [dest]
    mov ax, 0x0201             ; read 1 sector
    int 0x13
    jnc .ok
    xor ah, ah
    mov dl, [drive]
    int 0x13                   ; reset, retry
    dec di
    jnz .retry
    mov al, 'E'
    call putc
    jmp .hang
.ok:
    add word [dest], 512
    inc word [lba]
    pop cx
    loop .next
    jmp 0x0000:0x1000

.hang:
    hlt
    jmp .hang
putc:
    mov ah, 0x0e
    mov bx, 7
    int 0x10
    ret

drive db 0
lba dw 0
dest dw 0

times 510 - ($ - $$) db 0
dw 0xaa55
