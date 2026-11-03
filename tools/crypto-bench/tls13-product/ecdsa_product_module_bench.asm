; Exact 6 MHz / 512 KiB gate for the one-shot S286MOD2 P-256 verifier.
;
; Both target-generated tables and both legal ECDSA input pairs use the exact
; product geometry.  Each one-shot module is restored from a pristine source
; above the 0x7a00..0x7fff stack guard before its next invocation.

bits 16
cpu 8086
org 0x1000

%include "tls13/tls13_286_abi.inc"

crypto_seg equ 0x7000
crypto_base equ crypto_seg << 4
g_table_phys equ crypto_base + tls13_286_g_table_off
q_table_phys equ crypto_base + tls13_286_leaf_table_off
table_scratch_phys equ crypto_base + tls13_286_record_plain_off
cv_signature_phys equ crypto_base + tls13_286_cv_signature_off
cv_digest_phys equ crypto_base + tls13_286_cv_digest_off
result_phys equ crypto_base + tls13_286_ecdsa_result_off
cert_digest_phys equ 0x0c00
cert_signature_phys equ 0x0c20
generator_phys equ 0x3220
leaf_phys equ 0x32ad
q_selected_entry_offset equ (13 - 1) * 64

%macro span_phys 2
    dw ((%1) & 15), ((%1) >> 4)
    dd %2
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
    mov sp, 0x8000
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init

    mov word [tls13_286_root_state_loader + tls13_286_state_cache_seg], \
        crypto_seg
    mov word [tls13_286_root_state_loader + \
        tls13_286_state_cache_capacity], tls13_286_pack_cache_bytes

    cmp word [tls13_286_module_load + tls13_286_mod_abi], \
        tls13_286_abi_version
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_kind], \
        tls13_286_mod_kind_p256_tablegen
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_required_state], \
        tls13_286_state_bytes
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_flags], \
        tls13_286_mod_flag_one_shot
    jne fail

    call tick_start
    mov ax, tls13_286_mod_op_p256_tablegen
    mov bx, tls13_286_root_state_loader
    mov si, g_tablegen_desc
    xor di, di
    call module_call
    jc fail
    call reload_tablegen
    mov ax, tls13_286_mod_op_p256_tablegen
    mov bx, tls13_286_root_state_loader
    mov si, q_tablegen_desc
    xor di, di
    call module_call
    jc fail
    call tick_stop
    mov [table_ticks], ax

    call stage_cv_high
    call reload_ecdsa
    cmp word [tls13_286_module_load + tls13_286_mod_kind], \
        tls13_286_mod_kind_ecdsa_verify
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_required_state], \
        tls13_286_state_bytes
    jne fail
    cmp word [tls13_286_module_load + tls13_286_mod_flags], \
        tls13_286_mod_flag_one_shot
    jne fail

    call clear_decision
    call tick_start
    mov ax, tls13_286_mod_op_ecdsa_verify
    mov bx, tls13_286_root_state_loader
    mov si, ecdsa_cv_desc
    xor di, di
    call module_call
    jc fail
    or ax, ax
    jnz fail
    call tick_stop
    mov [ecdsa_ticks], ax
    call decision_is_one
    jc fail

    ; The normalized certificate pair is independently accepted with the same
    ; valid equation; no parser-selected address reaches the module.
    call stage_certificate_low
    call clear_decision
    call reload_ecdsa
    mov ax, tls13_286_mod_op_ecdsa_verify
    mov bx, tls13_286_root_state_loader
    mov si, ecdsa_cert_desc
    xor di, di
    call module_call
    jc fail
    call decision_is_one
    jc fail
    call wipe_certificate_low

    ; Unknown selector cannot publish.
    call poison_decision
    call reload_ecdsa
    mov ax, tls13_286_mod_op_p256_tablegen
    mov bx, tls13_286_root_state_loader
    mov si, ecdsa_cv_desc
    xor di, di
    call module_call
    jnc fail
    cmp ax, tls13_286_error_abi
    jne fail
    call decision_is_poison
    jc fail

    ; Exact digest length.
    call poison_decision
    mov word [ecdsa_cv_desc + tls13_286_desc_input0 + \
        tls13_286_span_len], 31
    call expect_bounds_reject
    jc fail
    mov word [ecdsa_cv_desc + tls13_286_desc_input0 + \
        tls13_286_span_len], 32

    ; Strict DER rejection in the only accepted CV signature slot.
    call poison_decision
    mov ax, crypto_seg
    mov es, ax
    mov si, bad_der
    mov di, tls13_286_cv_signature_off
    mov cx, bad_der_len
    rep movsb
    xor ax, ax
    mov es, ax
    mov word [ecdsa_cv_desc + tls13_286_desc_input1 + \
        tls13_286_span_len], bad_der_len
    call expect_crypto_reject
    jc fail
    call stage_cv_high
    mov word [ecdsa_cv_desc + tls13_286_desc_input1 + \
        tls13_286_span_len], cv_signature_len

    ; Canonical signature and transcript digest tampering.
    call poison_decision
    mov ax, crypto_seg
    mov es, ax
    xor byte [es:tls13_286_cv_signature_off + cv_signature_len - 1], 1
    xor ax, ax
    mov es, ax
    call expect_crypto_reject
    jc fail
    call stage_cv_high

    call poison_decision
    mov ax, crypto_seg
    mov es, ax
    xor byte [es:tls13_286_cv_digest_off], 1
    xor ax, ax
    mov es, ax
    call expect_crypto_reject
    jc fail
    call stage_cv_high

    ; Corrupt one Q-table entry selected by this fixture's u2 comb digits.
    call poison_decision
    mov ax, crypto_seg
    mov es, ax
    xor byte [es:tls13_286_leaf_table_off + q_selected_entry_offset], 1
    xor ax, ax
    mov es, ax
    call expect_crypto_reject
    pushf
    mov ax, crypto_seg
    mov es, ax
    xor byte [es:tls13_286_leaf_table_off + q_selected_entry_offset], 1
    xor ax, ax
    mov es, ax
    popf
    jc fail

    mov si, tag_tablegen
    mov ax, [table_ticks]
    call emit_metric
    mov si, tag_ecdsa
    mov ax, [ecdsa_ticks]
    call emit_metric
    mov si, tag_check
    xor ax, ax
    call emit_metric
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

expect_bounds_reject:
    call reload_ecdsa
    mov ax, tls13_286_mod_op_ecdsa_verify
    mov bx, tls13_286_root_state_loader
    mov si, ecdsa_cv_desc
    xor di, di
    call module_call
    jnc .bad
    cmp ax, tls13_286_error_bounds
    jne .bad
    call decision_is_poison
    ret
.bad:
    stc
    ret

expect_crypto_reject:
    call reload_ecdsa
    mov ax, tls13_286_mod_op_ecdsa_verify
    mov bx, tls13_286_root_state_loader
    mov si, ecdsa_cv_desc
    xor di, di
    call module_call
    jnc .bad
    cmp ax, tls13_286_error_crypto
    jne .bad
    call decision_is_poison
    ret
.bad:
    stc
    ret

module_call:
    push bp
    mov bp, [tls13_286_module_load + tls13_286_mod_entry_off]
    add bp, tls13_286_module_load
    call bp
    pop bp
    ret

reload_tablegen:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tablegen_module_blob
    mov di, tls13_286_module_load
    mov cx, tablegen_module_blob_end - tablegen_module_blob
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

reload_ecdsa:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, ecdsa_module_blob
    mov di, tls13_286_module_load
    mov cx, ecdsa_module_blob_end - ecdsa_module_blob
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

stage_cv_high:
    push ax
    push cx
    push si
    push di
    push es
    mov ax, crypto_seg
    mov es, ax
    mov si, cv_digest
    mov di, tls13_286_cv_digest_off
    mov cx, 32
    rep movsb
    mov si, cv_signature
    mov di, tls13_286_cv_signature_off
    mov cx, cv_signature_len
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

stage_certificate_low:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, cv_digest
    mov di, cert_digest_phys
    mov cx, 32
    rep movsb
    mov si, cv_signature
    mov di, cert_signature_phys
    mov cx, cv_signature_len
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

wipe_certificate_low:
    push ax
    push cx
    push di
    push es
    xor ax, ax
    mov es, ax
    mov di, cert_digest_phys
    mov cx, cert_signature_phys + tls13_286_cv_signature_max - cert_digest_phys
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

clear_decision:
    push ax
    push es
    mov ax, crypto_seg
    mov es, ax
    mov byte [es:tls13_286_ecdsa_result_off], 0
    pop es
    pop ax
    ret

poison_decision:
    push ax
    push es
    mov ax, crypto_seg
    mov es, ax
    mov byte [es:tls13_286_ecdsa_result_off], 0xa5
    pop es
    pop ax
    ret

decision_is_one:
    push ax
    push es
    mov ax, crypto_seg
    mov es, ax
    cmp byte [es:tls13_286_ecdsa_result_off], 1
    jne .bad
    clc
    jmp short .done
.bad:
    stc
.done:
    pop es
    pop ax
    ret

decision_is_poison:
    push ax
    push es
    mov ax, crypto_seg
    mov es, ax
    cmp byte [es:tls13_286_ecdsa_result_off], 0xa5
    jne .bad
    clc
    jmp short .done
.bad:
    stc
.done:
    pop es
    pop ax
    ret

tick_start:
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

tick_stop:
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
    mov si, str_ck
    call emit_str
    mov ax, 1
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
cv_digest:
    db 5,160,52,73,61,91,69,28,190,177,40,248,139,204,152,15
    db 63,99,80,127,188,97,47,18,224,122,134,0,239,189,234,42
cv_signature:
    db 48,69,2,32,93,85,215,213,161,207,189,229,199,182,186,185
    db 143,177,168,185,148,47,229,87,138,17,99,254,249,229,74,188
    db 172,119,152,38,2,33,0,222,138,188,7,79,76,7,86,199
    db 233,39,96,2,8,165,144,74,228,93,103,254,62,96,95,45
    db 205,107,38,52,230,210,118
cv_signature_len equ $ - cv_signature
bad_der:
    db 0x30,0x81,0x06,0x02,0x01,0x01,0x02,0x01,0x01
bad_der_len equ $ - bad_der

tick_lo: dw 0
tick_hi: dw 0
table_ticks: dw 0
ecdsa_ticks: dw 0
tag_tablegen db 'TABLEGEN', 0
tag_ecdsa db 'ECDSAPROD', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_n db ' N=', 0
str_dt db ' dt=', 0
str_ck db ' ck=', 0

times 0x1800 - ($ - $$ + 0x1000) db 0
auth_bench_header:
    db 'S286AU02'
    dw tls13_286_abi_version
    dw auth_bench_image_end - auth_bench_header
    dw 1
    dw start

g_tablegen_desc:
    dw tls13_286_mod_op_p256_tablegen, 0
    span_phys generator_phys, 64
    span_phys table_scratch_phys, 16256
    span_phys 0, 0
    span_phys 0, 0
    span_phys g_table_phys, tls13_286_w7_table_bytes
    span_phys 0, 0

q_tablegen_desc:
    dw tls13_286_mod_op_p256_tablegen, 0
    span_phys leaf_phys, 64
    span_phys table_scratch_phys, 16256
    span_phys 0, 0
    span_phys 0, 0
    span_phys q_table_phys, tls13_286_w7_table_bytes
    span_phys 0, 0

ecdsa_cv_desc:
    dw tls13_286_mod_op_ecdsa_verify, 0
    span_phys cv_digest_phys, 32
    span_phys cv_signature_phys, cv_signature_len
    span_phys g_table_phys, tls13_286_w7_table_bytes
    span_phys q_table_phys, tls13_286_w7_table_bytes
    span_phys result_phys, 1
    span_phys 0, 0

ecdsa_cert_desc:
    dw tls13_286_mod_op_ecdsa_verify, 0
    span_phys cert_digest_phys, 32
    span_phys cert_signature_phys, cv_signature_len
    span_phys g_table_phys, tls13_286_w7_table_bytes
    span_phys q_table_phys, tls13_286_w7_table_bytes
    span_phys result_phys, 1
    span_phys 0, 0

times generator_phys - ($ - $$ + 0x1000) db 0
generator_x:
    dw 49814,55448,14661,62625,13216,11755,32129,30467
    dw 16626,25508,59109,63676,16967,57644,53746,27415
generator_y:
    dw 20981,14271,16488,52150,24270,27441,13143,11214
    dw 40470,31759,60234,36583,32667,65050,17122,20451

times leaf_phys - ($ - $$ + 0x1000) db 0
leaf_x:
    dw 55915,3498,56094,48973,9044,8703,11167,41356
    dw 31549,43999,29596,40542,5757,9490,20289,63970
leaf_y:
    dw 37709,60675,25887,26394,23328,8974,32096,17921
    dw 634,36466,21947,58108,12261,47582,45790,29758
auth_bench_image_end:

times tls13_286_module_load - ($ - $$ + 0x1000) db 0
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-p256-tablegen.bin"

times 0x8000 - ($ - $$ + 0x1000) db 0
tablegen_module_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-p256-tablegen.bin"
tablegen_module_blob_end:
ecdsa_module_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-ecdsa-module.bin"
ecdsa_module_blob_end:
image_end:

%if generator_x - $$ + 0x1000 != generator_phys
%error "ECDSA bench generator point moved"
%endif
%if leaf_x - $$ + 0x1000 != leaf_phys
%error "ECDSA bench leaf point moved"
%endif
