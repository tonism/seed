; RSA-2048 signature-verify timing bench (boots as SEED.SYS on the 360K image).
; Times ONE full verify -- rsa_sig^65537 mod rsa_n (16 squarings + 1 multiply, CIOS
; Montgomery) -> rsa_result -- via the BIOS tick, emits "RSA N=1 dt=<ticks> ck=<hex4>"
; over COM1 + screen. ck must be 54F2 (wordsum of all 128 result limbs) = correct
; s^65537 mod N. The verify itself is rsa_verify.inc; inputs are baked in
; rsa_data_bench.inc. 8086 only (runs faster on the 286 -- that's the measurement).

bits 16
cpu 8086
org 0x1000

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

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x6000          ; clear of the RSA code+data loaded at 0x1000+
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init

    mov si, tag_rsa
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
    mov [t0_hi], dx

    call rsa_verify         ; one full RSA-2048 verify -> rsa_result

    call read_tick
    sub ax, [t0_lo]
    sbb dx, [t0_hi]
    mov [dt_lo], ax
    mov si, str_dt
    call emit_str
    mov ax, [dt_lo]
    call emit_dec16
    ; checksum all 128 result limbs
    xor ax, ax
    mov si, rsa_result
    mov cx, 128
.sum:
    add ax, [si]
    inc si
    inc si
    loop .sum
    push ax
    mov si, str_ck
    call emit_str
    pop ax
    call emit_hex16
    call emit_crlf
    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

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

tag_rsa  db 'RSA N=1', 0
tag_done db 'DONE', 0
str_dt   db ' dt=', 0
str_ck   db ' ck=', 0
t0_lo dw 0
t0_hi dw 0
dt_lo dw 0

%include "rsa_verify.inc"
%include "rsa_data_bench.inc"

image_end:
