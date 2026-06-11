; 80186-instruction benefit, MEASURED on V20/V30. The SHA-256 hot op is a 32-bit
; rotate; after the byte-granular step the residual is 1..7 bits. This measures
; that residual rotate two ways at three sizes (2/5/7), same result, different
; instructions:
;   R<n>_86  - 8086: n x single-bit shr/rcr (+wrap)
;   R<n>_187 - 186: shift-by-IMMEDIATE cross-register combine
; The dt delta per size is exactly what the 186 ISA buys on the SHA rotate, and
; shows where it wins (large residual) vs loses (small residual, fixed overhead).
; Run on a V20/V30 (only 086-class CPUs with the 186 instruction set).

bits 16
cpu 8086
org 0x1000

%include "core/layout.inc"

core_header:
    jmp short start
    nop
    db 'SEEDCORE'
    db 1
    db 0
    dw core_header_end - core_header
    dw (image_end - core_header + 511) / 512
    dw (image_end - core_header + 511) / 512
    dw 0
    dw 0
core_header_end:

; one single-bit 32-bit rotate-right step (dx:ax), %% labels need a macro
%macro ROR32_1 0
    shr dx, 1
    rcr ax, 1
    jnc %%nw
    or dx, 0x8000
%%nw:
%endmacro

; residual rotr by N, single-bit (8086)
%macro ROR_8086 1
    mov ax, [rot_val]
    mov dx, [rot_val+2]
%rep %1
    ROR32_1
%endrep
    mov [rot_val], ax
    mov [rot_val+2], dx
    ret
%endmacro

; residual rotr by N, 186 shift-by-immediate cross-register combine
%macro ROR_186 1
    mov ax, [rot_val]
    mov dx, [rot_val+2]
    cpu 186
    mov bx, dx
    mov si, ax
    shr ax, %1
    shr dx, %1
    and bx, (1 << %1) - 1
    shl bx, 16 - %1
    or ax, bx
    and si, (1 << %1) - 1
    shl si, 16 - %1
    or dx, si
    cpu 8086
    mov [rot_val], ax
    mov [rot_val+2], dx
    ret
%endmacro

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7000
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init

    mov bp, r2_86
    mov si, t_r2_86
    call bench
    mov bp, r2_187
    mov si, t_r2_187
    call bench
    mov bp, r5_86
    mov si, t_r5_86
    call bench
    mov bp, r5_187
    mov si, t_r5_187
    call bench
    mov bp, r7_86
    mov si, t_r7_86
    call bench
    mov bp, r7_187
    mov si, t_r7_187
    call bench

    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

r2_86:  ROR_8086 2
r2_187: ROR_186 2
r5_86:  ROR_8086 5
r5_187: ROR_186 5
r7_86:  ROR_8086 7
r7_187: ROR_186 7

; bench: si=tag, bp=op. resets rot_val, times 30000, prints "<tag> N dt ck"
bench:
    push si
    mov word [rot_val], 0x5678
    mov word [rot_val+2], 0x1234
    mov [op_ptr], bp
    pop si
    call emit_str
    mov al, ' '
    call emit_char
    call read_tick_low
    mov bx, ax
.edge:
    call read_tick_low
    cmp ax, bx
    je .edge
    call read_tick
    mov [t0_lo], ax
    mov cx, 30000
.loop:
    push cx
    call [op_ptr]
    pop cx
    loop .loop
    call read_tick
    sub ax, [t0_lo]
    mov si, str_dt
    call emit_str
    call emit_dec16
    mov si, str_ck
    call emit_str
    mov ax, [rot_val]
    add ax, [rot_val+2]
    call emit_hex16
    call emit_crlf
    ret

read_tick:
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret
read_tick_low:
    mov ax, [0x046c]
    ret

serial_init:
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 0x0c
    out dx, al
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 0x03
    out dx, al
    ret

emit_char:
    push ax
    push bx
    push cx
    push dx
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    mov ah, al
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, 0x3f8
    mov al, ah
    out dx, al
    pop dx
    pop cx
    pop bx
    pop ax
    ret

emit_str:
    push ax
    push si
.next:
    lodsb
    or al, al
    jz .done
    call emit_char
    jmp .next
.done:
    pop si
    pop ax
    ret

emit_crlf:
    push ax
    mov al, 13
    call emit_char
    mov al, 10
    call emit_char
    pop ax
    ret

emit_hex16:
    push ax
    push cx
    push dx
    mov dx, ax
    mov cx, 4
.dig:
    rol dx, 1
    rol dx, 1
    rol dx, 1
    rol dx, 1
    mov al, dl
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .ok
    add al, 7
.ok:
    call emit_char
    loop .dig
    pop dx
    pop cx
    pop ax
    ret

emit_dec16:
    push ax
    push bx
    push cx
    push dx
    mov bx, 10
    xor cx, cx
.div:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .div
.pop:
    pop ax
    add al, '0'
    call emit_char
    loop .pop
    pop dx
    pop cx
    pop bx
    pop ax
    ret

t_r2_86  db 'R2_86', 0
t_r2_187 db 'R2_187', 0
t_r5_86  db 'R5_86', 0
t_r5_187 db 'R5_187', 0
t_r7_86  db 'R7_86', 0
t_r7_187 db 'R7_187', 0
tag_done db 'DONE', 0
str_dt   db ' dt=', 0
str_ck   db ' ck=', 0

op_ptr dw 0
t0_lo dw 0
rot_val dd 0

image_end:
