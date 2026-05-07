bits 16
cpu 8086

%ifndef BASIC_BOOTSTRAP_ADDR
%define BASIC_BOOTSTRAP_ADDR 0x3000
%endif

%ifndef SEED_CORE_START_LBA
%define SEED_CORE_START_LBA 11
%endif

%ifndef SEED_CORE_SECTORS
%define SEED_CORE_SECTORS 4
%endif

%ifndef SEED_BOOT_DRIVE
%define SEED_BOOT_DRIVE 0
%endif

%ifndef SEED_RAM_TOP
%define SEED_RAM_TOP 0x4000
%endif

org BASIC_BOOTSTRAP_ADDR

core_offset equ 0x1000
seed_len equ 4
seed_row equ 12
basic_boot_magic_bx equ 0x5345
basic_boot_magic_cx equ 0x4544
loader_stack_top equ SEED_RAM_TOP
loader_stack_guard equ 0x0100
sector_size equ 512
floppy_sectors_per_track equ 8
core_end equ core_offset + (SEED_CORE_SECTORS * sector_size)

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, loader_stack_top
    sti
    cld

    mov ax, core_end
    cmp ax, BASIC_BOOTSTRAP_ADDR
    ja .failed

    mov bx, core_offset
    mov si, SEED_CORE_START_LBA
    mov bp, SEED_CORE_SECTORS
.read_next:
    mov ax, si
    mov dl, floppy_sectors_per_track
    div dl
    mov ch, al
    mov cl, ah
    inc cx
    xor dh, dh
    mov dl, SEED_BOOT_DRIVE
    mov ax, 0x0201
    int 0x13
    jc .failed
    inc si
    add bx, sector_size
    dec bp
    jnz .read_next

    mov ax, SEED_RAM_TOP
    mov bx, basic_boot_magic_bx
    mov cx, basic_boot_magic_cx
    mov dl, SEED_BOOT_DRIVE
    jmp 0x0000:core_offset

.halt:
    hlt
    jmp .halt

.failed:
    mov dl, [0x044a]
    or dl, dl
    jnz .have_columns
    mov dl, 80
.have_columns:
    push dx
    mov ax, 0x0600
    mov bh, 0x07
    xor cx, cx
    mov dh, 24
    dec dl
    int 0x10
    pop dx
    sub dl, seed_len
    shr dl, 1
    mov ah, 0x02
    mov dh, seed_row
    xor bh, bh
    int 0x10
    mov ax, 0x0958
    mov bl, 0x0c
    mov cx, 1
    int 0x10
    jmp .halt

bootstrap_end:
