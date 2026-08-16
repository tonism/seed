; Exact 6 MHz / 512 KiB gate for the callable S286MOD2 X25519 image.

bits 16
cpu 8086
org 0x1000

%include "tls13/tls13_286_abi.inc"
%include "build/ibm_pc_5150/crypto-bench/tls13-286-x25519-product-meta.inc"

bench_crypto_seg equ 0x7000
bench_stack_top equ 0x8000
bench_module_entry_sp equ bench_stack_top - 8
timer_irq_stack_top equ 0x3ff0
; With this wrapper depth, the audited module return publishes a six-byte
; IRET frame at 0x7ff6..0x7ffb.  Only bytes below that public frame must be
; zero; the wrapper validates and then restores its saved flags explicitly.
bench_module_public_frame equ bench_stack_top - 10

%define HIGH_SPAN_OFF(object_off) ((object_off) & 15)
%define HIGH_SPAN_SEG(object_off) \
    (bench_crypto_seg + ((object_off) >> 4))
%define LOW_SPAN_OFF(address) ((address) & 15)
%define LOW_SPAN_SEG(address) ((address) >> 4)

%macro SET_SPAN 4
    mov word [operation_desc + %1 + tls13_286_span_off], %2
    mov word [operation_desc + %1 + tls13_286_span_seg], %3
    mov word [operation_desc + %1 + tls13_286_span_len], %4
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
    call install_timer_irq

    mov word [tls13_286_root_state_loader + tls13_286_state_cache_seg], \
        bench_crypto_seg
    mov word [tls13_286_root_state_loader + tls13_286_state_cache_capacity], \
        tls13_286_pack_cache_bytes
    call copy_scalar_to_product_slot
    call copy_peer_to_product_slot
    call load_x25519_module

    cmp word [tls13_286_module_load + tls13_286_mod_abi], \
        tls13_286_abi_version
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_kind], \
        tls13_286_mod_kind_x25519
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_required_state], \
        tls13_286_state_bytes
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_required_stack], 256
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_flags], \
        tls13_286_mod_flag_one_shot
    jne fail

    mov ax, tls13_286_mod_op_x25519_keygen
    call prepare_keygen_desc
    call fill_low_public_sentinel
    call load_x25519_module
    call fill_stack_guard
    call timer_start
    mov ax, tls13_286_mod_op_x25519_keygen
    mov bx, tls13_286_root_state_loader
    mov si, operation_desc
    xor di, di
    call module_call
    jc fail
    or ax, ax
    jnz fail
    call timer_stop
    mov [keygen_ticks], ax
    call assert_module_wiped
    jc fail
    mov si, tls13_286_client_x_public
    mov di, rfc_public
    mov cx, 32
    repe cmpsb
    jne fail

    mov ax, tls13_286_mod_op_x25519_shared
    call prepare_shared_desc
    call fill_high_shared_sentinel
    call load_x25519_module
    call fill_stack_guard
    call timer_start
    mov ax, tls13_286_mod_op_x25519_shared
    mov bx, tls13_286_root_state_loader
    mov si, operation_desc
    xor di, di
    call module_call
    jc fail
    or ax, ax
    jnz fail
    call timer_stop
    mov [shared_ticks], ax
    call assert_module_wiped
    jc fail
    mov ax, HIGH_SPAN_SEG(tls13_286_hybrid_secret_off + 32)
    mov es, ax
    mov di, HIGH_SPAN_OFF(tls13_286_hybrid_secret_off + 32)
    mov si, rfc_expected
    mov cx, 32
    repe cmpsb
    pushf
    xor ax, ax
    mov es, ax
    popf
    jne fail

    ; A valid all-zero peer reaches the late crypto rejection.  It must not
    ; publish output and must retire both private module state and stack.
    call copy_zero_peer_to_product_slot
    mov ax, tls13_286_mod_op_x25519_shared
    call prepare_shared_desc
    call fill_high_shared_sentinel
    call load_x25519_module
    call fill_stack_guard
    mov ax, tls13_286_mod_op_x25519_shared
    mov bx, tls13_286_root_state_loader
    mov si, operation_desc
    xor di, di
    call module_call
    jnc fail
    cmp ax, tls13_286_error_crypto
    jne fail
    call assert_module_wiped
    jc fail
    call assert_high_shared_sentinel
    jc fail
    call copy_peer_to_product_slot

    ; Flags and non-canonical aliases fail before any private input is read.
    mov ax, tls13_286_mod_op_x25519_keygen
    call prepare_keygen_desc
    mov word [operation_desc + tls13_286_desc_flags], 1
    call fill_low_public_sentinel
    call load_x25519_module
    call fill_stack_guard
    mov ax, tls13_286_mod_op_x25519_keygen
    mov bx, tls13_286_root_state_loader
    mov si, operation_desc
    xor di, di
    call module_call
    jnc fail
    cmp ax, tls13_286_error_abi
    jne fail
    call assert_module_wiped
    jc fail
    call assert_low_public_sentinel
    jc fail

    mov ax, tls13_286_mod_op_x25519_keygen
    call prepare_keygen_desc
    ; 0x7b11:0010 aliases canonical 0x7b12:0000 but is forbidden.
    mov word [operation_desc + tls13_286_desc_input0 + \
        tls13_286_span_off], 16
    dec word [operation_desc + tls13_286_desc_input0 + \
        tls13_286_span_seg]
    call fill_low_public_sentinel
    call load_x25519_module
    call fill_stack_guard
    mov ax, tls13_286_mod_op_x25519_keygen
    mov bx, tls13_286_root_state_loader
    mov si, operation_desc
    xor di, di
    call module_call
    jnc fail
    cmp ax, tls13_286_error_bounds
    jne fail
    call assert_low_public_sentinel
    jc fail

    ; An inactive span and an alternate controller-state pointer are rejected.
    mov ax, tls13_286_mod_op_x25519_keygen
    call prepare_keygen_desc
    SET_SPAN tls13_286_desc_input1, \
        LOW_SPAN_OFF(tls13_286_hello_server_x_off), \
        LOW_SPAN_SEG(tls13_286_hello_server_x_off), 32
    call fill_low_public_sentinel
    call load_x25519_module
    call fill_stack_guard
    mov ax, tls13_286_mod_op_x25519_keygen
    mov bx, tls13_286_root_state_loader
    mov si, operation_desc
    xor di, di
    call module_call
    jnc fail
    cmp ax, tls13_286_error_bounds
    jne fail
    call assert_low_public_sentinel
    jc fail

    mov ax, tls13_286_mod_op_x25519_keygen
    call prepare_keygen_desc
    call fill_low_public_sentinel
    call load_x25519_module
    call fill_stack_guard
    mov ax, tls13_286_mod_op_x25519_keygen
    mov bx, tls13_286_root_state_loader + 2
    mov si, operation_desc
    xor di, di
    call module_call
    jnc fail
    cmp ax, tls13_286_error_bounds
    jne fail
    call assert_low_public_sentinel
    jc fail

    ; Same-length output at a different low address cannot be selected.
    mov ax, tls13_286_mod_op_x25519_keygen
    call prepare_keygen_desc
    add word [operation_desc + tls13_286_desc_output0 + \
        tls13_286_span_seg], 2
    call fill_low_public_sentinel
    call load_x25519_module
    call fill_stack_guard
    mov ax, tls13_286_mod_op_x25519_keygen
    mov bx, tls13_286_root_state_loader
    mov si, operation_desc
    xor di, di
    call module_call
    jnc fail
    cmp ax, tls13_286_error_bounds
    jne fail
    call assert_low_public_sentinel
    jc fail

    ; Restore the valid result once more to prove every call really reloads
    ; the one-shot image rather than relying on retained arithmetic state.
    mov ax, tls13_286_mod_op_x25519_shared
    call prepare_shared_desc
    call fill_high_shared_sentinel
    call load_x25519_module
    call fill_stack_guard
    mov ax, tls13_286_mod_op_x25519_shared
    mov bx, tls13_286_root_state_loader
    mov si, operation_desc
    xor di, di
    call module_call
    jc fail
    or ax, ax
    jnz fail
    call assert_module_wiped
    jc fail
    mov ax, HIGH_SPAN_SEG(tls13_286_hybrid_secret_off + 32)
    mov es, ax
    mov di, HIGH_SPAN_OFF(tls13_286_hybrid_secret_off + 32)
    mov si, rfc_expected
    mov cx, 32
    repe cmpsb
    pushf
    xor ax, ax
    mov es, ax
    popf
    jne fail

    mov si, tag_keygen
    mov ax, [keygen_ticks]
    call emit_metric
    mov si, tag_shared
    mov ax, [shared_ticks]
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
    mov si, tag_fail
    call emit_str
    call emit_crlf
    jmp start.hang

prepare_keygen_desc:
    call prepare_desc
    SET_SPAN tls13_286_desc_input0, \
        HIGH_SPAN_OFF(tls13_286_x25519_scalar_off), \
        HIGH_SPAN_SEG(tls13_286_x25519_scalar_off), 32
    SET_SPAN tls13_286_desc_output0, \
        LOW_SPAN_OFF(tls13_286_client_x_public), \
        LOW_SPAN_SEG(tls13_286_client_x_public), 32
    ret

prepare_shared_desc:
    call prepare_desc
    SET_SPAN tls13_286_desc_input0, \
        HIGH_SPAN_OFF(tls13_286_x25519_scalar_off), \
        HIGH_SPAN_SEG(tls13_286_x25519_scalar_off), 32
    SET_SPAN tls13_286_desc_input1, \
        LOW_SPAN_OFF(tls13_286_hello_server_x_off), \
        LOW_SPAN_SEG(tls13_286_hello_server_x_off), 32
    SET_SPAN tls13_286_desc_output0, \
        HIGH_SPAN_OFF(tls13_286_hybrid_secret_off + 32), \
        HIGH_SPAN_SEG(tls13_286_hybrid_secret_off + 32), 32
    ret

prepare_desc:
    push ax
    mov di, operation_desc
    mov cx, tls13_286_desc_bytes
    xor ax, ax
    rep stosb
    pop ax
    mov [operation_desc + tls13_286_desc_op], ax
    ret

copy_scalar_to_product_slot:
    mov ax, HIGH_SPAN_SEG(tls13_286_x25519_scalar_off)
    mov es, ax
    mov di, HIGH_SPAN_OFF(tls13_286_x25519_scalar_off)
    mov si, rfc_scalar
    mov cx, 32
    rep movsb
    xor ax, ax
    mov es, ax
    ret

copy_peer_to_product_slot:
    mov ax, LOW_SPAN_SEG(tls13_286_hello_server_x_off)
    mov es, ax
    mov di, LOW_SPAN_OFF(tls13_286_hello_server_x_off)
    mov si, rfc_peer_u
    mov cx, 32
    rep movsb
    xor ax, ax
    mov es, ax
    ret

copy_zero_peer_to_product_slot:
    mov ax, LOW_SPAN_SEG(tls13_286_hello_server_x_off)
    mov es, ax
    mov di, LOW_SPAN_OFF(tls13_286_hello_server_x_off)
    xor ax, ax
    mov cx, 16
    rep stosw
    mov es, ax
    ret

fill_low_public_sentinel:
    mov ax, LOW_SPAN_SEG(tls13_286_client_x_public)
    mov es, ax
    mov di, LOW_SPAN_OFF(tls13_286_client_x_public)
    mov ax, 0xa6a6
    mov cx, 16
    rep stosw
    xor ax, ax
    mov es, ax
    ret

fill_high_shared_sentinel:
    mov ax, HIGH_SPAN_SEG(tls13_286_hybrid_secret_off + 32)
    mov es, ax
    mov di, HIGH_SPAN_OFF(tls13_286_hybrid_secret_off + 32)
    mov ax, 0xa6a6
    mov cx, 16
    rep stosw
    xor ax, ax
    mov es, ax
    ret

assert_low_public_sentinel:
    mov ax, LOW_SPAN_SEG(tls13_286_client_x_public)
    mov es, ax
    mov di, LOW_SPAN_OFF(tls13_286_client_x_public)
    mov al, 0xa6
    mov cx, 32
.byte:
    cmp [es:di], al
    jne .bad
    inc di
    loop .byte
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

assert_high_shared_sentinel:
    mov ax, HIGH_SPAN_SEG(tls13_286_hybrid_secret_off + 32)
    mov es, ax
    mov di, HIGH_SPAN_OFF(tls13_286_hybrid_secret_off + 32)
    mov al, 0xa6
    mov cx, 32
.byte:
    cmp [es:di], al
    jne .bad
    inc di
    loop .byte
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

; This helper intentionally uses no pushes: its own return address is above
; the exact range that the module must scrub.
fill_stack_guard:
    xor ax, ax
    mov es, ax
    mov di, tls13_286_module_limit
    mov ax, 0xa6a6
    mov cx, (bench_module_entry_sp - tls13_286_module_limit) / 2
    rep stosw
    ret

assert_module_wiped:
    mov si, tls13_286_module_load + x25519_wipe_start_off
    mov cx, x25519_wipe_bytes
.byte:
    cmp byte [si], 0
    jne .bad
    inc si
    loop .byte
    clc
    ret
.bad:
    stc
    ret

load_x25519_module:
    push ax
    push cx
    push si
    push di
    push es
    xor ax, ax
    mov es, ax
    mov si, x25519_module_image
    mov di, tls13_286_module_load
    mov cx, x25519_module_bytes
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

module_call:
    push bp
    mov bp, [tls13_286_module_load + tls13_286_mod_entry_off]
    add bp, tls13_286_module_load
    call bp
.module_return:
    cli
    mov [module_return_ax], ax
    mov dx, [bench_module_public_frame + 4]
    mov [module_return_flags], dx
    cmp sp, bench_stack_top - 4
    jne fail
    cmp word [bench_module_public_frame], .module_return
    jne fail
    cmp word [bench_module_public_frame + 2], 0
    jne fail
    test dx, 0x0200
    jz fail
    mov ax, [module_return_ax]
    or ax, ax
    jz .expect_carry_clear
    test dx, 1
    jz fail
    jmp short .frame_ok
.expect_carry_clear:
    test dx, 1
    jnz fail
.frame_ok:
    mov si, tls13_286_module_limit
    mov cx, bench_module_public_frame - tls13_286_module_limit
.stack_byte:
    cmp byte [si], 0
    jne fail
    inc si
    loop .stack_byte
    mov ax, [module_return_ax]
    push word [module_return_flags]
    popf
    pop bp
    ret

; Keep the real BIOS IRQ0 work and PIT cadence while preventing the BIOS
; handler's public register pushes from contaminating the module's own stack-
; residue audit.  The wrapper preserves its entry state without using the
; interrupted stack, chains the original BIOS handler on a dedicated low
; stack, then returns through the original hardware frame.  Other IRQs are
; masked for this standalone timing image.  The wrapper overhead makes the
; measured wall time slightly conservative rather than removing BIOS cost.
install_timer_irq:
    cli
    mov ax, [0x0020]
    mov [cs:timer_irq_original], ax
    mov ax, [0x0022]
    mov [cs:timer_irq_original + 2], ax
    mov word [0x0020], timer_irq
    mov word [0x0022], 0
    mov al, 0xfe
    out 0x21, al
    sti
    ret

timer_irq:
    mov [cs:timer_irq_saved_ax], ax
    mov ax, ss
    mov [cs:timer_irq_saved_ss], ax
    mov ax, sp
    mov [cs:timer_irq_saved_sp], ax
    xor ax, ax
    mov ss, ax
    mov sp, timer_irq_stack_top
    pushf
    push cs
    mov ax, .bios_return
    push ax
    jmp far [cs:timer_irq_original]
.bios_return:
    cli
    mov ax, [cs:timer_irq_saved_ss]
    mov ss, ax
    mov sp, [cs:timer_irq_saved_sp]
    mov ax, [cs:timer_irq_saved_ax]
    iret

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

times (0x3000 - 0x1000) - ($ - $$) db 0
operation_desc:
    times tls13_286_desc_bytes db 0

rfc_scalar:
    db 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
    db 0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
    db 0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
    db 0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
rfc_public:
    db 0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
    db 0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
    db 0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
    db 0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
rfc_peer_u:
    db 0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
    db 0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
    db 0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
    db 0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
rfc_expected:
    db 0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1
    db 0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
    db 0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33
    db 0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42

tick_lo: dw 0
tick_hi: dw 0
keygen_ticks: dw 0
shared_ticks: dw 0
module_return_ax: dw 0
module_return_flags: dw 0
timer_irq_original: dw 0, 0
timer_irq_saved_ax: dw 0
timer_irq_saved_ss: dw 0
timer_irq_saved_sp: dw 0
tag_keygen db 'XMODKG', 0
tag_shared db 'XMODSS', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_n db ' N=', 0
str_dt db ' dt=', 0
str_check db ' N=1 dt=0 ck=', 0

times (0x8000 - 0x1000) - ($ - $$) db 0
x25519_module_image:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-x25519-module.bin"
image_end:
