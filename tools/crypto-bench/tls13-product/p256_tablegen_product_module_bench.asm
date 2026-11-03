; Exact 6 MHz / 512 KiB gate for the one-shot product P-256 table generator.

bits 16
cpu 8086
org 0x1000

%include "tls13/tls13_286_abi.inc"

%ifndef BENCH_CRYPTO_SEG
%define BENCH_CRYPTO_SEG 0x7000
%endif

bench_crypto_seg equ BENCH_CRYPTO_SEG
bench_stack_top equ 0x8000
auth_generator_point equ 0x3220
auth_desc equ 0x3279
auth_leaf_point equ 0x32ad
tablegen_scratch_bytes equ 16256

%define HIGH_SEG(object_off) (bench_crypto_seg + ((object_off) >> 4))

%macro EXPECT_REJECT 1
    call load_p256_module
    mov ax, tls13_286_mod_op_p256_tablegen
    call invoke_module
    jnc fail
    cmp ax, %1
    jne fail
%endmacro

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
    mov sp, bench_stack_top
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init

    mov word [tls13_286_root_state_loader + tls13_286_state_cache_seg], \
        bench_crypto_seg
    mov word [tls13_286_root_state_loader + \
        tls13_286_state_cache_capacity], tls13_286_pack_cache_bytes
    call prepare_desc
    call load_p256_module

    cmp word [tls13_286_module_load + tls13_286_mod_abi], \
        tls13_286_abi_version
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_kind], \
        tls13_286_mod_kind_p256_tablegen
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_required_state], \
        tls13_286_state_bytes
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_required_stack], 512
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_flags], \
        tls13_286_mod_flag_one_shot
    jne fail

    call timer_start
    mov ax, tls13_286_mod_op_p256_tablegen
    call invoke_module
    pushf
    pop cx
    mov [call_result], ax
    call timer_stop
    mov [table_ticks], ax
    test cx, 1
    jnz fail
    cmp word [call_result], tls13_286_status_ok
    jne fail
    call compare_generator_table
    jc fail

    ; Each rejection reloads the advertised one-shot image first.  These
    ; mutations are deliberately early and must never reach table generation.
    call prepare_desc
    mov word [auth_desc + tls13_286_desc_flags], 1
    EXPECT_REJECT tls13_286_error_abi

    call prepare_desc
    dec word [auth_desc + tls13_286_desc_input1 + tls13_286_span_seg]
    EXPECT_REJECT tls13_286_error_bounds

    call prepare_desc
    mov word [auth_desc + tls13_286_desc_input2 + tls13_286_span_off], 1
    EXPECT_REJECT tls13_286_error_bounds

    call prepare_desc
    mov word [auth_desc + tls13_286_desc_output0 + tls13_286_span_seg], \
        HIGH_SEG(tls13_286_leaf_table_off)
    EXPECT_REJECT tls13_286_error_bounds

    call prepare_desc
    dec word [tls13_286_root_state_loader + \
        tls13_286_state_cache_capacity]
    EXPECT_REJECT tls13_286_error_bounds
    mov word [tls13_286_root_state_loader + \
        tls13_286_state_cache_capacity], tls13_286_pack_cache_bytes

    ; The mapped generator slot remains untrusted data: an off-curve point is
    ; a crypto rejection even though every descriptor field is exact.
    call prepare_desc
    xor word [auth_generator_point], 1
    EXPECT_REJECT tls13_286_error_crypto
    xor word [auth_generator_point], 1

    mov si, tag_tablegen
    mov ax, [table_ticks]
    call emit_metric
    mov si, tag_check
    mov ax, 1
    call emit_check
    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

fail:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov si, tag_fail
    call emit_str
    call emit_crlf
    jmp start.hang

prepare_desc:
    push ax
    push cx
    push si
    push di
    mov si, good_desc
    mov di, auth_desc
    mov cx, tls13_286_desc_bytes
    rep movsb
    pop di
    pop si
    pop cx
    pop ax
    ret

load_p256_module:
    push ax
    push cx
    push si
    push di
    push es
    xor ax, ax
    mov es, ax
    mov si, p256_module_image
    mov di, tls13_286_module_load
    mov cx, p256_module_bytes
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

invoke_module:
    mov bx, tls13_286_root_state_loader
    mov si, auth_desc
    xor di, di
    push bp
    mov bp, [tls13_286_module_load + tls13_286_mod_entry_off]
    add bp, tls13_286_module_load
    call bp
    pop bp
    ret

compare_generator_table:
    push ax
    push cx
    push si
    push di
    push ds
    push es
    mov ax, HIGH_SEG(tls13_286_g_table_off)
    mov ds, ax
    xor si, si
    xor ax, ax
    mov es, ax
    mov di, expected_table
    mov cx, tls13_286_w7_table_bytes
    repe cmpsb
    jne .bad
    clc
    jmp short .done
.bad:
    stc
.done:
    pop es
    pop ds
    pop di
    pop si
    pop cx
    pop ax
    ret

timer_start:
    call read_tick_low
    mov bx, ax
.edge:
    call read_tick_low
    cmp ax, bx
    je .edge
    call read_tick
    mov [tick_lo], ax
    mov [tick_hi], dx
    ret

timer_stop:
    call read_tick
    sub ax, [tick_lo]
    sbb dx, [tick_hi]
    ret

read_tick:
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret

read_tick_low:
    mov ax, [0x046c]
    ret

emit_metric:
    push ax
    call emit_str
    mov si, str_n
    call emit_str
    mov ax, 1
    call emit_dec16
    mov si, str_dt
    call emit_str
    pop ax
    call emit_dec16
    call emit_crlf
    ret

emit_check:
    push ax
    call emit_str
    mov si, str_check
    call emit_str
    pop ax
    call emit_hex16
    call emit_crlf
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
    jmp short .next
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
.digit:
    rol dx, 1
    rol dx, 1
    rol dx, 1
    rol dx, 1
    mov al, dl
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .emit
    add al, 7
.emit:
    call emit_char
    loop .digit
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
.divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .divide
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

align 2
good_desc:
    dw tls13_286_mod_op_p256_tablegen, 0
    dw auth_generator_point & 15, auth_generator_point >> 4
    dd 64
    dw 0, HIGH_SEG(tls13_286_record_plain_off)
    dd tablegen_scratch_bytes
    times tls13_286_span_bytes db 0
    times tls13_286_span_bytes db 0
    dw 0, HIGH_SEG(tls13_286_g_table_off)
    dd tls13_286_w7_table_bytes
    times tls13_286_span_bytes db 0

tick_lo: dw 0
tick_hi: dw 0
table_ticks: dw 0
call_result: dw 0
tag_tablegen db 'TABLEGEN', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_n db ' N=', 0
str_dt db ' dt=', 0
str_check db ' N=1 dt=0 ck=', 0

times (auth_generator_point - 0x1000) - ($ - $$) db 0
generator_x:
    dw 49814,55448,14661,62625,13216,11755,32129,30467
    dw 16626,25508,59109,63676,16967,57644,53746,27415
generator_y:
    dw 20981,14271,16488,52150,24270,27441,13143,11214
    dw 40470,31759,60234,36583,32667,65050,17122,20451

times (auth_desc - 0x1000) - ($ - $$) db 0
operation_desc:
    times tls13_286_desc_bytes db 0

; Product parser output slot.  The hostile host gate supplies an on-curve
; value here when it exercises the leaf-to-Q mapping.
times 64 db 0

times (tls13_286_root_state_loader - 0x1000) - ($ - $$) db 0
root_state_loader:
    times tls13_286_state_bytes db 0

times (0x8000 - 0x1000) - ($ - $$) db 0
p256_module_image:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-p256-tablegen.raw"
p256_module_end:
p256_module_bytes equ p256_module_end - p256_module_image
expected_table:
    incbin "build/ibm_pc_5150/crypto-bench/width7-ecdsa-g.bin"
image_end:

%if generator_x - $$ + 0x1000 != auth_generator_point
%error "benchmark generator point moved"
%endif
%if operation_desc - $$ + 0x1000 != auth_desc
%error "benchmark descriptor moved"
%endif
%if root_state_loader - $$ + 0x1000 != tls13_286_root_state_loader
%error "benchmark loader state moved"
%endif
