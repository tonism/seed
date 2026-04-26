bits 16
org 0x7c00

%ifndef STAGE2_SECTORS
%define STAGE2_SECTORS 7
%endif

stage2_offset equ 0x8000

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

read_stage2:
    xor ax, ax
    mov es, ax
    mov dl, [boot_drive]
    int 0x13

    xor ax, ax
    mov es, ax
    mov bx, stage2_offset
    mov ah, 0x02
    mov al, STAGE2_SECTORS
    xor ch, ch
    mov cl, 0x02
    xor dh, dh
    mov dl, [boot_drive]
    int 0x13
    jc .read_failed
    mov dl, [boot_drive]
    jmp 0x0000:stage2_offset

.read_failed:
    dec si
    jnz read_stage2

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
load_error_text db 'seed load error', 0

times 510 - ($ - $$) db 0
dw 0xaa55
