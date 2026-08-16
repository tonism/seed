; Large-payload boot sector for the 286 TLS 1.3 product gate.
;
; This is the established 360 KiB benchmark loader with a build-time sector
; count.  The normal 28-sector loader remains untouched.  A 512 KiB 286 can
; use the rest of the first real-mode segment for immutable benchmark tables,
; so this spike permits payloads through 0000:dfff and keeps its stack at
; 0000:e000 or above.

bits 16
cpu 8086
org 0x7c00

%ifndef BENCH_SECTORS
    %error "BENCH_SECTORS must be defined"
%endif
%if BENCH_SECTORS < 1 || BENCH_SECTORS > 103
    %error "BENCH_SECTORS must keep the 0x1000 payload below 0xe000"
%endif

RELOC equ 0x0600

    jmp short start
    nop
    db 'SEED    '
    dw 512
    db 2
    dw 1
    db 2
    dw 112
    dw 720
    db 0xfd
    dw 2
    dw 9
    dw 2
    dd 0
    dd 0
    db 0
    db 0
    db 0x29
    dd 0x37313236
    db 'TLS13GATE  '
    db 'FAT12   '

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov si, 0x7c00
    mov di, RELOC
    mov cx, 256
    cld
    rep movsw
    jmp 0x0000:(RELOC + relocated - $$)

relocated:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0xf000
    sti
    cld
    mov [RELOC + drive - $$], dl

    mov word [RELOC + lba - $$], 1
    mov word [RELOC + dest - $$], 0x1000
    mov cx, BENCH_SECTORS
.next:
    push cx
    mov di, 5
.retry:
    mov ax, [RELOC + lba - $$]
    xor dx, dx
    mov bx, 9
    div bx
    mov cl, dl
    inc cl
    xor dx, dx
    mov bx, 2
    div bx
    mov ch, al
    mov dh, dl
    mov dl, [RELOC + drive - $$]
    mov bx, [RELOC + dest - $$]
    mov ax, 0x0201
    int 0x13
    jnc .ok
    xor ah, ah
    mov dl, [RELOC + drive - $$]
    int 0x13
    dec di
    jnz .retry
    mov al, 'E'
    call putc
    jmp .hang
.ok:
    add word [RELOC + dest - $$], 512
    inc word [RELOC + lba - $$]
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
