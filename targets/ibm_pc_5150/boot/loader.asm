bits 16
cpu 8086
org 0x0600

%ifndef LOADER_SECTORS
%define LOADER_SECTORS 4
%endif

core_offset equ 0x1000
loader_stack_top equ 0xc000
sector_size equ 512
floppy_sectors_per_track equ 8
fat_count equ 2
root_sectors equ 4
root_entries_per_sector equ 16
dir_entry_size equ 32
first_data_cluster equ 2
fat_max_cluster equ 300
fat_start_lba equ 1 + LOADER_SECTORS
root_start_lba equ fat_start_lba + fat_count
data_start_lba equ root_start_lba + root_sectors
root_buffer equ 0x7000
fat_buffer equ 0x0e00

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, loader_stack_top
    sti
    cld

    mov [boot_drive], dl
    call find_core
    jc missing_core
    call load_core
    jc load_failed

    mov dl, [boot_drive]
    jmp 0x0000:core_offset

missing_core:
    mov si, missing_core_text
    jmp fail

load_failed:
    mov si, load_failed_text
    jmp fail

find_core:
    mov word [root_lba], root_start_lba
    mov byte [root_left], root_sectors
.next_sector:
    cmp byte [root_left], 0
    je .not_found
    push ds
    pop es
    mov bx, root_buffer
    mov ax, [root_lba]
    call read_abs_sector
    jc .not_found

    mov si, root_buffer
    mov bp, root_entries_per_sector
.next_entry:
    mov al, [si]
    or al, al
    jz .not_found
    cmp al, 0xe5
    je .advance
    test byte [si + 11], 0x18
    jnz .advance
    call entry_matches_core
    jc .advance
    mov ax, [si + 26]
    mov [core_cluster], ax
    mov ax, [si + 28]
    mov [core_bytes_left], ax
    cmp word [si + 30], 0
    jne .not_found
    cmp word [core_bytes_left], 0
    je .not_found
    clc
    ret
.advance:
    add si, dir_entry_size
    dec bp
    jnz .next_entry
    inc word [root_lba]
    dec byte [root_left]
    jmp .next_sector
.not_found:
    stc
    ret

entry_matches_core:
    push si
    push di
    push cx
    mov di, core_name
    mov cx, 11
.compare:
    mov al, [si]
    cmp al, [di]
    jne .mismatch
    inc si
    inc di
    loop .compare
    pop cx
    pop di
    pop si
    clc
    ret
.mismatch:
    pop cx
    pop di
    pop si
    stc
    ret

load_core:
    push ds
    pop es
    mov bx, fat_buffer
    mov ax, fat_start_lba
    call read_abs_sector
    jc .failed
    mov word [core_dest], core_offset
.next_cluster:
    mov ax, [core_cluster]
    cmp ax, first_data_cluster
    jb .failed
    cmp ax, fat_max_cluster
    jae .failed
    sub ax, first_data_cluster
    add ax, data_start_lba
    push ds
    pop es
    mov bx, [core_dest]
    call read_abs_sector
    jc .failed
    cmp word [core_bytes_left], sector_size
    jbe .done
    sub word [core_bytes_left], sector_size
    add word [core_dest], sector_size
    mov ax, [core_cluster]
    call get_fat_entry
    cmp ax, 0x0ff8
    jae .failed
    mov [core_cluster], ax
    jmp .next_cluster
.done:
    clc
    ret
.failed:
    stc
    ret

get_fat_entry:
    push bx
    push dx
    mov dx, ax
    mov bx, ax
    shr bx, 1
    add bx, dx
    mov al, [fat_buffer + bx]
    mov ah, [fat_buffer + bx + 1]
    test dl, 1
    jz .even
    shr ax, 1
    shr ax, 1
    shr ax, 1
    shr ax, 1
.even:
    and ax, 0x0fff
    pop dx
    pop bx
    ret

read_abs_sector:
    push ax
    push cx
    push dx
    div byte [sectors_per_track]
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
    mov dl, [boot_drive]
    mov ax, 0x0201
    int 0x13
    pop dx
    pop cx
    pop ax
    ret

fail:
    call print_teletype
.halt:
    hlt
    jmp .halt

print_teletype:
    lodsb
    or al, al
    jz .done
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    jmp print_teletype
.done:
    ret

boot_drive db 0
root_lba dw 0
root_left db 0
core_cluster dw 0
core_bytes_left dw 0
core_dest dw 0
sectors_per_track db floppy_sectors_per_track
core_name db 'CORE    SYS'
missing_core_text db 'core missing', 0
load_failed_text db 'core load error', 0

times (LOADER_SECTORS * 512) - ($ - $$) db 0
