bits 16
cpu 8086
org 0x7c00

%ifndef LOADER_SECTORS
%define LOADER_SECTORS 4
%endif

; Floppy geometry. Defaults = the 160 KiB single-sided format (the 1981 IBM PC 5150
; headline). The 360 KiB build (the 286 tier — the AT's drive rejects single-sided
; 160K) overrides these via -D in the Makefile. The defaults keep the 160K boot
; sector byte-identical.
%ifndef FLOPPY_TOTAL_SECTORS
%define FLOPPY_TOTAL_SECTORS 320
%endif
%ifndef FLOPPY_SPT
%define FLOPPY_SPT 8
%endif
%ifndef FLOPPY_HEADS
%define FLOPPY_HEADS 1
%endif
%ifndef FLOPPY_MEDIA
%define FLOPPY_MEDIA 0xfc
%endif

jmp short start
nop

db 'SEEDBOOT'
dw 512
db 1
dw 1 + LOADER_SECTORS
db 2
dw 64
dw FLOPPY_TOTAL_SECTORS
db FLOPPY_MEDIA
dw 1
dw FLOPPY_SPT
dw FLOPPY_HEADS
dd 0
dd 0
db 0
db 0
db 0x29
dd 0x20260426
db 'BOOT       '
db 'FAT12   '

loader_offset equ 0x0600
floppy_sectors_per_track equ FLOPPY_SPT

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    sti
    cld

    mov [boot_drive], dl
    mov si, 3

read_loader:
    xor ax, ax
    mov es, ax
    mov dl, [boot_drive]
    int 0x13

    xor ax, ax
    mov es, ax
    mov bx, loader_offset
    xor ch, ch
    mov cl, 0x02
    xor dh, dh
    mov bp, LOADER_SECTORS

.read_sector:
    mov ah, 0x02
    mov al, 0x01
    mov dl, [boot_drive]
    int 0x13
    jc .read_failed

    add bx, 512
    inc cl
    cmp cl, floppy_sectors_per_track + 1
    jb .same_track
    mov cl, 0x01
    inc ch
.same_track:
    dec bp
    jnz .read_sector

    mov dl, [boot_drive]
    jmp 0x0000:loader_offset

.read_failed:
    dec si
    jnz read_loader

    mov si, load_error_text
    call print_teletype

halt:
    hlt
    jmp halt

print_teletype:
    lodsb
    or al, al
    jz halt
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    jmp print_teletype

boot_drive db 0
load_error_text db 'boot load error', 0

times 510 - ($ - $$) db 0
dw 0xaa55
