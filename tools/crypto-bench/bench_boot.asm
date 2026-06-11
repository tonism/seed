; Minimal boot sector for the crypto bench on a STANDARD 360 KB floppy, with a
; real BPB (media descriptor 0xFD) so AT-class BIOSes recognize + boot it. Prints
; an instant 'B' (boot ran), then loads the bench from sector 2 to 0000:1000 and
; jumps; 'K' = read OK, 'E' = read failed -- so a screenshot shows how far it got.

bits 16
cpu 8086
org 0x7c00

    jmp short start
    nop
    db 'SEED    '          ; OEM
    dw 512                 ; bytes/sector
    db 2                   ; sectors/cluster
    dw 1                   ; reserved sectors
    db 2                   ; FATs
    dw 112                 ; root entries
    dw 720                 ; total sectors (360K)
    db 0xFD                ; media descriptor: 5.25" 360K
    dw 2                   ; sectors/FAT
    dw 9                   ; sectors/track
    dw 2                   ; heads
    dd 0                   ; hidden
    dd 0                   ; large total
    db 0                   ; drive
    db 0
    db 0x29                ; ext boot sig
    dd 0x43425948          ; volume serial
    db 'CRYPTOBENCH'       ; label (11)
    db 'FAT12   '          ; fs type (8)

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

    mov al, 'B'            ; instant: boot sector is running
    call putc

    mov di, 5
.retry:
    xor ax, ax
    mov es, ax
    mov bx, 0x1000
    mov ah, 0x02
    mov al, 8
    mov ch, 0
    mov cl, 2
    mov dh, 0
    mov dl, [drive]
    int 0x13
    jnc .ok
    xor ah, ah
    mov dl, [drive]
    int 0x13
    dec di
    jnz .retry
    mov al, 'E'
    call putc
    jmp .hang
.ok:
    mov al, 'K'
    call putc
    mov dl, [drive]
    jmp 0x0000:0x1000
.hang:
    hlt
    jmp .hang

putc:
    push ax
    mov ah, 0x0e
    mov bx, 7
    int 0x10
    pop ax
    ret

drive db 0

times 510 - ($ - $$) db 0
dw 0xaa55
