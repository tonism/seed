; Standalone TLS 1.3 SHA-256 key-schedule benchmark for an 8088-class target.
;
; Compatible with tools/crypto-bench/run86box.py:
;
;   python3 tools/crypto-bench/run86box.py \
;     --asm tools/crypto-bench/tls13-spike/hkdf_bench.asm
;
; It emits:
;
;   HKFULL N=1 dt=<ticks> ck=2D5F
;   VFULL  N=1 dt=0       ck=0001
;   HKHOT  N=1 dt=<ticks> ck=2D5F
;   VHOT   N=1 dt=0       ck=0001
;   DONE
;
; V*=1 means SHA256(the 528-byte output bundle) matches the host oracle.

bits 16
cpu 8086
org 0x1000

sha256_digest_len equ 32
sha256_block_size equ 64
sha256_k_len equ 256
tls13_key_len equ 32
tls13_iv_len equ 12

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
    mov sp, 0x3ff0
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init

    mov si, tag_critical
    mov cx, 1
    mov bp, tls13_schedule_critical
    call run_op
    mov si, tls13_critical_outputs_start
    mov cx, tls13_critical_outputs_len / 2
    call emit_tail
    call validate_critical_outputs
    mov si, tag_vcritical
    call emit_validation

    mov si, tag_full
    mov cx, 1
    mov bp, tls13_schedule_full
    call run_op
    mov si, tls13_outputs_start
    mov cx, tls13_outputs_len / 2
    call emit_tail
    call validate_outputs
    mov si, tag_vfull
    call emit_validation

    mov si, tag_hot
    mov cx, 1
    mov bp, tls13_schedule_hot
    call run_op
    mov si, tls13_outputs_start
    mov cx, tls13_outputs_len / 2
    call emit_tail
    call validate_outputs
    mov si, tag_vhot
    call emit_validation

    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

; Time CX iterations of [BP].  SI is a NUL-terminated tag.
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

; Sum CX little-endian words at SI and emit the run86box-compatible checksum.
emit_tail:
    xor ax, ax
    mov di, cx
.sum:
    or di, di
    jz .done
    add ax, [si]
    add si, 2
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

; Hash the complete output bundle and compare its digest with the stdlib
; oracle.  Returns AX=1 on a byte-exact match, AX=0 otherwise.
validate_outputs:
    call sha256_init
    mov si, tls13_outputs_start
    mov cx, tls13_outputs_len
    call sha256_update
    mov di, tls13_validation_digest
    call sha256_finish
    mov si, tls13_validation_digest
    mov di, tls13_expected_output_hash
    mov cx, sha256_digest_len
    repe cmpsb
    mov ax, 0
    jne .done
    inc ax
.done:
    ret

; Check the exact subset produced before the quarantined client Finished.
validate_critical_outputs:
    call sha256_init
    mov si, tls13_critical_outputs_start
    mov cx, tls13_critical_outputs_len
    call sha256_update
    mov di, tls13_validation_digest
    call sha256_finish
    mov si, tls13_validation_digest
    mov di, tls13_expected_critical_output_hash
    mov cx, sha256_digest_len
    repe cmpsb
    mov ax, 0
    jne .done
    inc ax
.done:
    ret

; SI=tag, AX=0/1.  Emit "<tag> N=1 dt=0 ck=<AX>".
emit_validation:
    push ax
    call emit_str
    mov si, str_validation
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

tag_critical db 'HKCRIT', 0
tag_full db 'HKFULL', 0
tag_hot db 'HKHOT', 0
tag_vcritical db 'VCRIT', 0
tag_vfull db 'VFULL', 0
tag_vhot db 'VHOT', 0
tag_done db 'DONE', 0
str_N db 'N=', 0
str_dt db ' dt=', 0
str_ck db ' ck=', 0
str_validation db ' N=1 dt=0 ck=', 0

bench_iters dw 0
op_ptr dw 0
t0_lo dw 0
t0_hi dw 0
dt_lo dw 0

tls13_hkdf_code_start:
%include "tls13-spike/hkdf_schedule.inc"
tls13_hkdf_code_end:

sha256_code_start:
%include "core/sha256.inc"
sha256_code_end:

; Deterministic benchmark inputs.  These are inputs *to* the key schedule, not
; a claim about how transcripts are buffered in the runtime.
tls13_input_shared_secret:
    db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
    db 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    db 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
tls13_input_hello_hash:
    db 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27
    db 0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    db 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
    db 0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
tls13_input_server_finished_hash:
    db 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
    db 0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
    db 0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57
    db 0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
tls13_input_client_finished_hash:
    db 0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67
    db 0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f
    db 0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77
    db 0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f

tls13_zeros times sha256_digest_len db 0

; SHA256 over tls13_outputs_start..end, independently generated by
; hkdf_bench.py using hashlib/hmac.
tls13_expected_hash_marker db 'HKDFHASH'
tls13_expected_output_hash:
    db 0xfd,0x6d,0x59,0xc0,0x03,0x2b,0x16,0xcd
    db 0xd2,0x95,0x39,0x7a,0xe3,0xe8,0xfd,0xf8
    db 0xf1,0xf2,0x38,0xee,0x2f,0x43,0xa2,0xb5
    db 0xdb,0x09,0x23,0xea,0x9d,0x18,0x69,0x60
tls13_expected_critical_hash_marker db 'HKDFCRIT'
tls13_expected_critical_output_hash:
    db 0x02,0xfe,0xcd,0xaf,0x1e,0x7b,0x1a,0x4d
    db 0x5c,0xb0,0xc8,0x94,0x4c,0x58,0x80,0xdc
    db 0x3f,0xdb,0xe6,0x4f,0xd0,0xc5,0x92,0xd3
    db 0x81,0x85,0x16,0xe4,0x5d,0x38,0xd3,0xc5

sha256_initial_state:
    dw 0xe667,0x6a09,0xae85,0xbb67
    dw 0xf372,0x3c6e,0xf53a,0xa54f
    dw 0x527f,0x510e,0x688c,0x9b05
    dw 0xd9ab,0x1f83,0xcd19,0x5be0
sha256_k:
    dw 0x2f98,0x428a,0x4491,0x7137
    dw 0xfbcf,0xb5c0,0xdba5,0xe9b5
    dw 0xc25b,0x3956,0x11f1,0x59f1
    dw 0x82a4,0x923f,0x5ed5,0xab1c
    dw 0xaa98,0xd807,0x5b01,0x1283
    dw 0x85be,0x2431,0x7dc3,0x550c
    dw 0x5d74,0x72be,0xb1fe,0x80de
    dw 0x06a7,0x9bdc,0xf174,0xc19b
    dw 0x69c1,0xe49b,0x4786,0xefbe
    dw 0x9dc6,0x0fc1,0xa1cc,0x240c
    dw 0x2c6f,0x2de9,0x84aa,0x4a74
    dw 0xa9dc,0x5cb0,0x88da,0x76f9
    dw 0x5152,0x983e,0xc66d,0xa831
    dw 0x27c8,0xb003,0x7fc7,0xbf59
    dw 0x0bf3,0xc6e0,0x9147,0xd5a7
    dw 0x6351,0x06ca,0x2967,0x1429
    dw 0x0a85,0x27b7,0x2138,0x2e1b
    dw 0x6dfc,0x4d2c,0x0d13,0x5338
    dw 0x7354,0x650a,0x0abb,0x766a
    dw 0xc92e,0x81c2,0x2c85,0x9272
    dw 0xe8a1,0xa2bf,0x664b,0xa81a
    dw 0x8b70,0xc24b,0x51a3,0xc76c
    dw 0xe819,0xd192,0x0624,0xd699
    dw 0x3585,0xf40e,0xa070,0x106a
    dw 0xc116,0x19a4,0x6c08,0x1e37
    dw 0x774c,0x2748,0xbcb5,0x34b0
    dw 0x0cb3,0x391c,0xaa4a,0x4ed8
    dw 0xca4f,0x5b9c,0x6ff3,0x682e
    dw 0x82ee,0x748f,0x636f,0x78a5
    dw 0x7814,0x84c8,0x0208,0x8cc7
    dw 0xfffa,0x90be,0x6ceb,0xa450
    dw 0xa3f7,0xbef9,0x78f2,0xc671

; Fixed low-memory SHA/HMAC/HKDF work area.  It fits entirely below the
; SEED.SYS load address and mirrors the product's scratch-oriented shape.
tls13_scratch_base equ 0x0700
sha256_state equ tls13_scratch_base
sha256_a equ sha256_state + 32
sha256_b equ sha256_a + 4
sha256_c equ sha256_b + 4
sha256_d equ sha256_c + 4
sha256_e equ sha256_d + 4
sha256_f equ sha256_e + 4
sha256_g equ sha256_f + 4
sha256_h equ sha256_g + 4
sha256_t1 equ sha256_h + 4
sha256_t2 equ sha256_t1 + 4
sha256_new_e equ sha256_t2 + 4
sha256_tmp equ sha256_new_e + 4
sha256_w_ptr equ sha256_tmp + 4
sha256_k_ptr equ sha256_w_ptr + 2
sha256_len_low equ sha256_k_ptr + 2
sha256_len_high equ sha256_len_low + 2
sha256_saved_len_low equ sha256_len_high + 2
sha256_saved_len_high equ sha256_saved_len_low + 2
sha256_bit_len0 equ sha256_saved_len_high + 2
sha256_bit_len1 equ sha256_bit_len0 + 2
sha256_bit_len2 equ sha256_bit_len1 + 2
sha256_bit_len3 equ sha256_bit_len2 + 2
sha256_digest_ptr equ sha256_bit_len3 + 2
hmac_key_ptr equ sha256_digest_ptr + 2
hmac_key_len equ hmac_key_ptr + 2
hmac_data1_ptr equ hmac_key_len + 2
hmac_data1_len equ hmac_data1_ptr + 2
hmac_data2_ptr equ hmac_data1_len + 2
hmac_data2_len equ hmac_data2_ptr + 2
hmac_output_ptr equ hmac_data2_len + 2
sha256_block_len equ hmac_output_ptr + 2
sha256_saved_block_len equ sha256_block_len + 1
sha256_schedule_count equ sha256_saved_block_len + 1
sha256_round_count equ sha256_schedule_count + 1
sha256_block equ sha256_round_count + 1
sha256_w equ sha256_block + sha256_block_size
sha256_saved_state equ sha256_w + sha256_k_len
sha256_saved_block equ sha256_saved_state + 32
hmac_ipad equ sha256_saved_block + sha256_block_size
hmac_opad equ hmac_ipad + sha256_block_size
hmac_inner_digest equ hmac_opad + sha256_block_size
hmac_prepared_inner_state equ hmac_inner_digest + sha256_digest_len
hmac_prepared_outer_state equ hmac_prepared_inner_state + 32
tls13_hkdf_info equ hmac_prepared_outer_state + 32
tls13_hkdf_info_len equ 55
tls13_hkdf_block equ tls13_hkdf_info + tls13_hkdf_info_len
tls13_expand_label_ptr equ tls13_hkdf_block + sha256_digest_len
tls13_expand_label_len equ tls13_expand_label_ptr + 2
tls13_expand_context_ptr equ tls13_expand_label_len + 2
tls13_expand_context_len equ tls13_expand_context_ptr + 2
tls13_expand_output_ptr equ tls13_expand_context_len + 2
tls13_expand_output_len equ tls13_expand_output_ptr + 2
tls13_validation_digest equ tls13_expand_output_len + 2
tls13_scratch_end equ tls13_validation_digest + sha256_digest_len
%if tls13_scratch_end > 0x1000
%error "TLS 1.3 HKDF scratch exceeds the low-memory window"
%endif

; The benchmark retains every semantic output for an oracle hash.  Production
; can overlay transient secrets after liveness analysis.
tls13_output_base equ 0x3000
tls13_early_secret equ tls13_output_base
tls13_early_derived equ tls13_early_secret + 32
tls13_outputs_start equ tls13_early_derived + 32
tls13_handshake_secret equ tls13_outputs_start
tls13_client_hs_secret equ tls13_handshake_secret + 32
tls13_server_hs_secret equ tls13_client_hs_secret + 32
tls13_client_hs_key equ tls13_server_hs_secret + 32
tls13_client_hs_iv equ tls13_client_hs_key + 32
tls13_client_finished_key equ tls13_client_hs_iv + 12
tls13_client_finished_verify equ tls13_client_finished_key + 32
tls13_server_hs_key equ tls13_client_finished_verify + 32
tls13_server_hs_iv equ tls13_server_hs_key + 32
tls13_server_finished_key equ tls13_server_hs_iv + 12
tls13_server_finished_verify equ tls13_server_finished_key + 32
tls13_handshake_derived equ tls13_server_finished_verify + 32
tls13_critical_outputs_start equ tls13_handshake_secret
tls13_critical_outputs_end equ tls13_handshake_derived
tls13_critical_outputs_len equ tls13_critical_outputs_end - tls13_critical_outputs_start
%if tls13_critical_outputs_len != 312
%error "TLS 1.3 critical output bundle layout changed"
%endif
tls13_master_secret equ tls13_handshake_derived + 32
tls13_client_app_secret equ tls13_master_secret + 32
tls13_server_app_secret equ tls13_client_app_secret + 32
tls13_client_app_key equ tls13_server_app_secret + 32
tls13_client_app_iv equ tls13_client_app_key + 32
tls13_server_app_key equ tls13_client_app_iv + 12
tls13_server_app_iv equ tls13_server_app_key + 32
tls13_outputs_end equ tls13_server_app_iv + 12
tls13_outputs_len equ tls13_outputs_end - tls13_outputs_start
%if tls13_outputs_len != 528
%error "TLS 1.3 HKDF output bundle layout changed"
%endif
%if tls13_outputs_end > 0x3400
%error "TLS 1.3 HKDF retained outputs collide with benchmark stack"
%endif

; Machine-readable build metadata consumed by hkdf_bench.py.
tls13_size_footer:
    db 'HKDFSZ01'
    dw tls13_hkdf_code_end - tls13_hkdf_code_start
    dw sha256_code_end - sha256_code_start
    dw tls13_scratch_end - tls13_scratch_base
    dw tls13_outputs_len
image_end:
