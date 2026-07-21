; FPU feasibility micro-benchmark: does an 8087 accelerate the 256-bit modular
; multiply that bottlenecks P-256? Head-to-head of the multiply PRIMITIVE
; (32x32->64) on the 8088 (four 16x16 MULs + carry) vs the 8087 (FILD/FMUL/FISTP).
;
; The 32x32 product is exact in the 8087's 64-bit mantissa, so FILD/FMUL/FISTP
; gives the exact 64-bit integer product. The ratio here is the UPPER BOUND on
; any P-256 multiply speedup (the modular reduction + carry accumulation get no
; FPU benefit, and SHA-256 none at all).
;
; Boots as SEED.SYS; times N iterations of each op via the BIOS tick, emits
; "<tag> N=.. dt=.. ck=.." over COM1 + screen. ck = wordsum of the 64-bit product
; (must be 39FB for A=12345678 * B=9ABCDEF0, cross-checked on the host).
; 8086 + 8087 only.

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
    finit                       ; init 8087 (default control word: round nearest)

    mov word [num_a], 0x5678
    mov word [num_a+2], 0x1234
    mov word [num_b], 0xdef0
    mov word [num_b+2], 0x7abc

    ; ---- 8088: 32x32->64 via four 16x16 MULs ----
    mov si, tag_mul88
    mov cx, 30000
    mov bp, op_mul32_8088
    call run_op
    mov si, prod
    mov cx, 4
    call emit_tail

    ; ---- 8087: 32x32->64 via FILD/FMUL/FISTP ----
    mov si, tag_fmul87
    mov cx, 30000
    mov bp, op_fmul32_8087
    call run_op
    mov si, prod
    mov cx, 4
    call emit_tail

    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

; ---- 8088 32x32 -> 64 (unsigned), result in prod[0..3] ----
op_mul32_8088:
    mov ax, [num_a]
    mul word [num_b]            ; a_lo*b_lo
    mov [prod], ax
    mov [prod+2], dx
    mov ax, [num_a+2]
    mul word [num_b+2]          ; a_hi*b_hi
    mov [prod+4], ax
    mov [prod+6], dx
    mov ax, [num_a]
    mul word [num_b+2]          ; a_lo*b_hi
    add [prod+2], ax
    adc [prod+4], dx
    adc word [prod+6], 0
    mov ax, [num_a+2]
    mul word [num_b]            ; a_hi*b_lo
    add [prod+2], ax
    adc [prod+4], dx
    adc word [prod+6], 0
    ret

; ---- 8087 32x32 -> 64 exact (product fits the 64-bit mantissa) ----
op_fmul32_8087:
    fild dword [num_a]
    fild dword [num_b]
    fmulp st1, st0
    fistp qword [prod]
    fwait
    ret

; ---------------------------------------------------------------------------
; timing + output infra (same as bench.asm)
; ---------------------------------------------------------------------------
run_op:
    mov [op_ptr], bp
    mov [bench_iters], cx
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
    mov cx, [bench_iters]
.loop:
    push cx
    call [op_ptr]
    pop cx
    loop .loop
    call read_tick
    sub ax, [t0_lo]
    sbb dx, [t0_hi]
    mov [dt_lo], ax
    mov si, str_N
    call emit_str
    mov ax, [bench_iters]
    call emit_dec16
    mov si, str_dt
    call emit_str
    mov ax, [dt_lo]
    call emit_dec16
    ret

emit_tail:
    xor ax, ax
    mov di, cx
.sum:
    or di, di
    jz .done
    add ax, [si]
    inc si
    inc si
    dec di
    jmp .sum
.done:
    push ax
    mov si, str_ck
    call emit_str
    pop ax
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

tag_mul88  db 'MUL88', 0
tag_fmul87 db 'FMUL87', 0
tag_done   db 'DONE', 0
str_N      db 'N=', 0
str_dt     db ' dt=', 0
str_ck     db ' ck=', 0

bench_iters dw 0
op_ptr dw 0
t0_lo dw 0
t0_hi dw 0
dt_lo dw 0
num_a dd 0
num_b dd 0
prod  dq 0

image_end:
