bits 16
cpu 8086
org 0x0600

%ifndef LOADER_SECTORS
%define LOADER_SECTORS 4
%endif

; Floppy geometry. Defaults = 160 KiB single-sided. The 360 KiB build (the 286 tier)
; overrides FLOPPY_SPT/FLOPPY_HEADS via -D. Both images share the same FAT12 internal
; layout (data at LBA 11) — only read_abs_sector's CHS gains a head axis when
; heads > 1, and the defaults keep the 160K loader byte-identical.
%ifndef FLOPPY_SPT
%define FLOPPY_SPT 8
%endif
%ifndef FLOPPY_HEADS
%define FLOPPY_HEADS 1
%endif

core_offset equ 0x1000
loader_stack_top equ 0x8000
sector_size equ 512
floppy_sectors_per_track equ FLOPPY_SPT
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
core_header_magic_off equ 3
core_header_version_off equ 11
core_header_resident_sectors_off equ 15
core_header_magic_len equ 8
; Build 10: hand CORE.SYS a real RAM top via the same AX + BX/CX-magic contract the
; ROM BASIC sidecar uses (layout.inc basic_boot_magic_bx/cx), so the conversation
; window + user/agent arena scale to the machine instead of the old fixed 0x8000.
basic_magic_bx equ 0x5345
basic_magic_cx equ 0x4544
seg0_stack_cap equ 0xfff0

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

    ; Detect conventional memory (int 0x12 -> KB) and convert to a segment-0 byte
    ; ceiling for CORE.SYS's stack/pool. KB<64 -> KB*1024 (<=0xFC00, no overflow);
    ; KB>=64 -> cap at top of segment 0 (KB*1024 would overflow 16 bits). Direct boot
    ; only happens at >=32 KiB, so 32 KiB still yields 0x8000 exactly (no regression).
    int 0x12                    ; ax = KB conventional memory
    cmp ax, 64
    jb .ram_shift
    mov ax, seg0_stack_cap
    jmp .ram_ready
.ram_shift:
    mov cl, 10
    shl ax, cl                  ; KB * 1024
.ram_ready:
    mov bx, basic_magic_bx      ; signal "RAM top in AX" to CORE.SYS start (== BASIC path)
    mov cx, basic_magic_cx
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
    mov byte [core_need_header], 1
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
    cmp byte [core_need_header], 0
    je .sector_loaded
    mov byte [core_need_header], 0
    call read_core_header
    jc .failed
.sector_loaded:
    dec word [core_sectors_left]
    jz .done
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

read_core_header:
    push si
    push di
    push cx
    mov si, core_offset + core_header_magic_off
    mov di, core_header_magic
    mov cx, core_header_magic_len
.compare_magic:
    mov al, [si]
    cmp al, [di]
    jne .failed
    inc si
    inc di
    loop .compare_magic

    cmp byte [core_offset + core_header_version_off], 1
    jne .failed
    mov ax, [core_offset + core_header_resident_sectors_off]
    or ax, ax
    jz .failed
    mov [core_sectors_left], ax

    mov ax, [core_bytes_left]
    add ax, sector_size - 1
    mov cl, 9
    shr ax, cl
    cmp [core_sectors_left], ax
    ja .failed

    pop cx
    pop di
    pop si
    clc
    ret
.failed:
    pop cx
    pop di
    pop si
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
    div byte [sectors_per_track]    ; al = track (LBA/spt), ah = sector-in-track
%if FLOPPY_HEADS > 1
    mov cl, ah                      ; sector-in-track (0-based)
    inc cl                          ; INT 13h sector is 1-based
    mov ah, 0
    div byte [floppy_heads]         ; al = cylinder (track/heads), ah = head (track%heads)
    mov ch, al
    mov dh, ah
%else
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
%endif
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
core_sectors_left dw 0
core_need_header db 0
sectors_per_track db floppy_sectors_per_track
%if FLOPPY_HEADS > 1
floppy_heads db FLOPPY_HEADS
%endif
core_name db 'CORE    SYS'
core_header_magic db 'SEEDCORE'
missing_core_text db 'core missing', 0
load_failed_text db 'core load error', 0

times (LOADER_SECTORS * 512) - ($ - $$) db 0
