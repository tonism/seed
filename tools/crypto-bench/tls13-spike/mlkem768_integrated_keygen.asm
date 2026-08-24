; Exact deterministic ML-KEM-768 KeyGen_internal spike for an 8088.
;
; The 64-byte fixture is only d || z, the two inputs that a real machine must
; obtain from its own entropy source.  Everything else in the 2400-byte
; expanded decapsulation key is generated on-device:
;
;   (rho, sigma) = SHA3-512(d || 0x03)
;   (ekPKE, dkPKE) = K-PKE.KeyGen(d)
;   dk = dkPKE || ekPKE || H(ekPKE) || z
;
; Matrix polynomials are SHAKE128-sampled four coefficients at a time and fed
; straight into base multiplication.  The serialized dkPKE is decoded one
; polynomial at a time while constructing each public-key row, so neither a
; 4608-byte matrix nor a retained three-polynomial secret vector is required.

bits 16
cpu 8086
%ifdef TLS13_POC_OVERLAY
org poc_k_start
%else
org 0x1000
%endif

poly_words equ 256
state_bytes equ 200

%ifndef TLS13_POC_OVERLAY
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

    call mlkem_keygen_internal
    call checksum_generated_dk
    cmp ax, 0xda4e
    jne fail
    mov si, tag_check
    mov ax, 1
    call emit_check

    mov si, tag_keygen
    mov cx, 1
    mov bp, mlkem_keygen_internal
    call run_op
    call checksum_generated_dk
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

fail:
    mov si, tag_fail
    call emit_str
    call emit_crlf
    jmp start.hang
%endif

%ifdef TLS13_POC_OVERLAY
%ifdef MLKEM_KEYGEN_INPUT
keygen_input       equ MLKEM_KEYGEN_INPUT
%else
keygen_input       equ poc_attempt_cache_start
%endif
%ifdef MLKEM_KEYGEN_Z_INPUT
keygen_z_input     equ MLKEM_KEYGEN_Z_INPUT
%else
keygen_z_input     equ keygen_input + 32
%endif
%ifdef MLKEM_KEYGEN_ROOT_INPUT
%define MLKEM_KEYGEN_ROOT_DERIVATION 1
%endif
%ifdef MLKEM_KEYGEN_RUNTIME_ROOT
%define MLKEM_KEYGEN_ROOT_DERIVATION 1
%endif
keygen_s_hat0      equ poc_s_hat0
keygen_s_hat1      equ poc_s_hat1
keygen_s_hat2      equ poc_s_hat2
keygen_ek          equ poc_mlkem_ek
keygen_h_ek        equ poc_h_ek
keygen_z           equ poc_z
poly_s             equ poc_poly_u
poly_acc           equ poc_poly_acc
%else
keygen_input       equ fixture_d_z
keygen_z_input     equ keygen_input + 32
keygen_s_hat0      equ generated_dk
keygen_s_hat1      equ generated_dk + 384
keygen_s_hat2      equ generated_dk + 768
keygen_ek          equ generated_dk + 1152
keygen_h_ek        equ generated_dk + 2336
keygen_z           equ generated_dk + 2368
%endif

; ---------------------------------------------------------------------------
; ML-KEM.KeyGen_internal(d, z)
; ---------------------------------------------------------------------------

%ifdef TLS13_POC_OVERLAY
mlkem_keygen_overlay:
%ifdef MLKEM_KEYGEN_RUNTIME_ROOT
    cmp al, 1
    ja .invalid_epoch
    mov [keygen_root_epoch], al
    mov [keygen_root_ptr], si
    call derive_regenerated_d_z
    call mlkem_keygen_internal
    clc
    ret
.invalid_epoch:
    stc
    ret
%elifdef MLKEM_KEYGEN_ROOT_INPUT
    call derive_regenerated_d_z
%endif
%endif
mlkem_keygen_internal:
    call derive_rho_sigma

    ; Generate and serialize the three sHat polynomials as dkPKE.
    mov byte [keygen_col], 0
.secret:
    mov al, [keygen_col]
    mov di, poly_s
    call sigma_noise_to_poly
    mov si, poly_s
    call ntt_poly
    xor bx, bx
    mov bl, [keygen_col]
    shl bx, 1
    mov di, [sk_output_ptrs + bx]
    mov si, poly_s
    call encode_poly12
    inc byte [keygen_col]
    cmp byte [keygen_col], 3
    jb .secret

    ; tHat[row] = A[row] o sHat + eHat[row].  Decode each serialized sHat
    ; component only for the row that currently occupies the accumulator.
    mov byte [keygen_row], 0
.public_row:
    call zero_acc
    mov byte [keygen_col], 0
.public_col:
    xor bx, bx
    mov bl, [keygen_col]
    shl bx, 1
    mov si, [sk_output_ptrs + bx]
    call decode_poly12
    mov word [matrix_y_ptr], poly_s
    ; A[row,col] = SampleNTT(rho || col || row).
    mov al, [keygen_col]
    mov ah, [keygen_row]
    call sample_ntt_accumulate
    inc byte [keygen_col]
    cmp byte [keygen_col], 3
    jb .public_col
    call reduce_acc
    call tomont_acc

    mov al, [keygen_row]
    add al, 3
    mov di, poly_s
    call sigma_noise_to_poly
    mov si, poly_s
    call ntt_poly
    call add_error_reduce

    xor bx, bx
    mov bl, [keygen_row]
    shl bx, 1
    mov di, [pk_output_ptrs + bx]
    mov si, poly_acc
    call encode_poly12
    inc byte [keygen_row]
    cmp byte [keygen_row], 3
    jb .public_row

    ; Finish ekPKE with rho, then expanded dk with H(ekPKE) and z.
    mov si, rho_sigma
    mov di, keygen_ek + 1152
    mov cx, 32
    rep movsb
    call hash_public_key
    mov si, keygen_z_input
    mov di, keygen_z
    mov cx, 32
    rep movsb
    ret

derive_rho_sigma:
    call clear_keccak
    mov si, keygen_input
    mov di, keccak_state
    mov cx, 32
    rep movsb
    mov al, 3
    stosb
    mov byte [keccak_state + 33], 0x06
    mov byte [keccak_state + 71], 0x80
    call keccak_f1600
    mov si, keccak_state
    mov di, rho_sigma
    mov cx, 64
    rep movsb
    ret

%ifdef MLKEM_KEYGEN_ROOT_DERIVATION
; Derive a fresh deterministic ML-KEM attempt from the same-boot entropy root.
; This is deliberately part of the slow regenerated KeyGen phase: no extra
; entropy collection or retained 64-byte d||z object is needed after the
; credential-free dialogue.  Acquisition and resumption are independent:
; SHA3-256(domain || epoch || index || root), epoch 0/1 and index 0/1.
derive_regenerated_d_z:
    xor dx, dx
.next:
    mov [keygen_root_index], dl
    call clear_keccak
    mov si, keygen_regenerate_domain
    mov di, keccak_state
    mov cx, keygen_regenerate_domain_len
    rep movsb
%ifdef MLKEM_KEYGEN_RUNTIME_ROOT
    mov al, [keygen_root_epoch]
%else
%ifndef MLKEM_KEYGEN_ROOT_EPOCH
%define MLKEM_KEYGEN_ROOT_EPOCH 0
%endif
    mov al, MLKEM_KEYGEN_ROOT_EPOCH
%endif
    stosb
    mov al, [keygen_root_index]
    stosb
%ifdef MLKEM_KEYGEN_RUNTIME_ROOT
    mov si, [keygen_root_ptr]
%else
    mov si, MLKEM_KEYGEN_ROOT_INPUT
%endif
    mov cx, 32
    rep movsb
    mov bx, di
    sub bx, keccak_state
    mov byte [keccak_state + bx], 0x06
    mov byte [keccak_state + 135], 0x80
    push dx
    call keccak_f1600
    pop dx
    mov si, keccak_state
    mov di, keygen_input
    or dx, dx
    jz .copy
    mov di, keygen_z_input
.copy:
    mov cx, 32
    rep movsb
    inc dx
    cmp dx, 2
    jb .next
    ret

%ifdef MLKEM_KEYGEN_RUNTIME_ROOT
; Derive the two public ClientHello nonce fields from the same attempt epoch.
; Entry ABI: AL=epoch 0/1, SI=root[32], DI=random[32] || session_id[32].
mlkem_keygen_attempt_nonces:
    cmp al, 1
    ja .invalid_epoch
    mov [keygen_root_epoch], al
    mov [keygen_root_ptr], si
    mov [keygen_root_output], di
    mov byte [keygen_root_index], 2
.next_nonce:
    call clear_keccak
    mov si, keygen_regenerate_domain
    mov di, keccak_state
    mov cx, keygen_regenerate_domain_len
    rep movsb
    mov al, [keygen_root_epoch]
    stosb
    mov al, [keygen_root_index]
    stosb
    mov si, [keygen_root_ptr]
    mov cx, 32
    rep movsb
    mov bx, di
    sub bx, keccak_state
    mov byte [keccak_state + bx], 0x06
    mov byte [keccak_state + 135], 0x80
    call keccak_f1600
    mov si, keccak_state
    mov di, [keygen_root_output]
    mov cx, 32
    rep movsb
    mov [keygen_root_output], di
    inc byte [keygen_root_index]
    cmp byte [keygen_root_index], 4
    jb .next_nonce
    clc
    ret
.invalid_epoch:
    stc
    ret
%endif
%endif

; H(ekPKE) = SHA3-256 over 1184 bytes: eight full 136-byte blocks and a
; final 96-byte block.
hash_public_key:
    call clear_keccak
    mov word [hash_input_ptr], keygen_ek
    mov bp, 8
.full:
    mov si, [hash_input_ptr]
    mov di, keccak_state
    mov cx, 68
.xor_word:
    lodsw
    xor [di], ax
    add di, 2
    loop .xor_word
    mov [hash_input_ptr], si
    push bp
    call keccak_f1600
    pop bp
    dec bp
    jnz .full
    mov si, [hash_input_ptr]
    mov di, keccak_state
    mov cx, 48
.tail:
    lodsw
    xor [di], ax
    add di, 2
    loop .tail
    xor byte [keccak_state + 96], 0x06
    xor byte [keccak_state + 135], 0x80
    call keccak_f1600
    mov si, keccak_state
    mov di, keygen_h_ek
    mov cx, 32
    rep movsb
    ret

; SHAKE256(sigma || nonce, 128), followed by CBD_eta2.
sigma_noise_to_poly:
    mov [noise_nonce], al
    push di
    call clear_keccak
    mov si, rho_sigma + 32
    mov di, keccak_state
    mov cx, 32
    rep movsb
    mov al, [noise_nonce]
    stosb
    mov byte [keccak_state + 33], 0x1f
    mov byte [keccak_state + 135], 0x80
    call keccak_f1600
    pop di
    mov si, keccak_state
    mov bx, cbd2_nibbles
    mov bp, 128
.byte:
    lodsb
    mov dl, al
    and al, 0x0f
    xlat
    cbw
    stosw
    xor ax, ax
    mov al, dl
    mov cl, 4
    shr al, cl
    xlat
    cbw
    stosw
    dec bp
    jnz .byte
    ret

zero_acc:
    mov di, poly_acc
    xor ax, ax
    mov cx, poly_words
    rep stosw
    ret

reduce_acc:
    mov si, poly_acc
    mov di, poly_acc
    mov cx, poly_words
.word:
    lodsw
    push cx
    call barrett_reduce
    pop cx
    stosw
    loop .word
    ret

; K-PKE.KeyGen's conversion after BaseMultiply: multiply by 2^16 in the
; NTT/Montgomery representation using the Kyber/ML-KEM factor 1353.
tomont_acc:
    mov di, poly_acc
    mov cx, poly_words
.word:
    mov ax, [di]
    mov bx, 1353
    call fqmul
    mov [di], ax
    add di, 2
    loop .word
    ret

add_error_reduce:
    mov si, poly_s
    mov di, poly_acc
    mov cx, poly_words
.word:
    lodsw
    add ax, [di]
    push cx
    call barrett_reduce
    cwd
    and dx, 3329
    add ax, dx
    pop cx
    mov [di], ax
    add di, 2
    loop .word
    ret

; ---------------------------------------------------------------------------
; Streaming SampleNTT and BaseMultiply
; ---------------------------------------------------------------------------

sample_ntt_accumulate:
    mov [sample_first], al
    mov [sample_second], ah
    call clear_keccak
    mov si, rho_sigma
    mov di, keccak_state
    mov cx, 32
    rep movsb
    mov al, [sample_first]
    stosb
    mov al, [sample_second]
    stosb
    mov byte [keccak_state + 34], 0x1f
    mov byte [keccak_state + 167], 0x80
    call keccak_f1600
    mov word [sample_pos], 0
    mov word [sample_group_index], 0
    mov word [sample_fill], 0
.next_triple:
    cmp word [sample_pos], 165
    jbe .have_three
    call keccak_f1600
    mov word [sample_pos], 0
.have_three:
    mov bx, keccak_state
    add bx, [sample_pos]
    xor ax, ax
    mov al, [bx + 1]
    and ax, 0x000f
    mov cl, 8
    shl ax, cl
    xor dx, dx
    mov dl, [bx]
    or ax, dx
    mov [sample_d1], ax
    xor ax, ax
    mov al, [bx + 1]
    mov cl, 4
    shr ax, cl
    xor dx, dx
    mov dl, [bx + 2]
    shl dx, cl
    or ax, dx
    mov [sample_d2], ax
    add word [sample_pos], 3
    mov ax, [sample_d1]
    call sample_accept
    cmp word [sample_group_index], 64
    je .done
    mov ax, [sample_d2]
    call sample_accept
    cmp word [sample_group_index], 64
    jb .next_triple
.done:
    ret

sample_accept:
    cmp ax, 3329
    jae .done
    mov bx, [sample_fill]
    shl bx, 1
    mov [sample_group + bx], ax
    inc word [sample_fill]
    cmp word [sample_fill], 4
    jb .done
    call accumulate_sample_group
    mov word [sample_fill], 0
    inc word [sample_group_index]
.done:
    ret

accumulate_sample_group:
    mov ax, [sample_group_index]
    mov bx, ax
    mov cl, 3
    shl ax, cl
    mov [sample_offset], ax
    mov si, sample_group
    mov di, [matrix_y_ptr]
    add di, ax
    mov bp, sample_product
    mov ax, bx
    add ax, 64
    shl ax, 1
    mov bx, zetas
    add bx, ax
    mov ax, [bx]
    mov [bm_zeta], ax
    call basemul_pair
    mov si, sample_group + 4
    mov di, [matrix_y_ptr]
    add di, [sample_offset]
    add di, 4
    mov bp, sample_product + 4
    neg word [bm_zeta]
    call basemul_pair
    mov si, sample_product
    mov di, poly_acc
    add di, [sample_offset]
    mov cx, 4
.add:
    lodsw
    add [di], ax
    add di, 2
    loop .add
    ret

; ---------------------------------------------------------------------------
; ByteEncode/ByteDecode_12
; ---------------------------------------------------------------------------

canonicalize:
    call barrett_reduce
    cwd
    and dx, 3329
    add ax, dx
    ret

encode_poly12:
    mov word [codec_pairs], 128
.pair:
    lodsw
    call canonicalize
    mov [codec_a], ax
    lodsw
    call canonicalize
    mov [codec_b], ax
    mov ax, [codec_a]
    stosb
    mov cl, 8
    shr ax, cl
    mov dx, [codec_b]
    mov cl, 4
    shl dx, cl
    or ax, dx
    stosb
    mov ax, [codec_b]
    mov cl, 4
    shr ax, cl
    stosb
    dec word [codec_pairs]
    jnz .pair
    ret

decode_poly12:
    mov di, poly_s
    mov word [codec_pairs], 128
.pair:
    lodsb
    mov dl, al
    lodsb
    mov dh, al
    lodsb
    mov bl, al
    xor ax, ax
    mov al, dh
    and ax, 0x000f
    mov bp, ax
    mov cl, 8
    shl bp, cl
    xor ax, ax
    mov al, dl
    or ax, bp
    stosw
    xor ax, ax
    mov al, dh
    mov cl, 4
    shr ax, cl
    xor dx, dx
    mov dl, bl
    shl dx, cl
    or ax, dx
    stosw
    dec word [codec_pairs]
    jnz .pair
    ret

clear_keccak:
    mov di, keccak_state
    xor ax, ax
    mov cx, state_bytes / 2
    rep stosw
    ret

%ifdef TLS13_POC_OVERLAY
%define MLKEM_KEYGEN_ONLY 1
%endif
%include "tools/crypto-bench/tls13-spike/mlkem768_integrated_core.inc"
%ifdef TLS13_POC_OVERLAY
%undef MLKEM_KEYGEN_ONLY
%endif

; ---------------------------------------------------------------------------
; Timing and serial output
; ---------------------------------------------------------------------------

%ifndef TLS13_POC_OVERLAY
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

checksum_generated_dk:
    mov si, generated_dk
    mov cx, 1200
    xor ax, ax
.word:
    add ax, [si]
    add si, 2
    loop .word
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

emit_check:
    push ax
    call emit_str
    mov si, str_check
    call emit_str
    pop ax
    call emit_hex16
    call emit_crlf
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
%endif

; ---------------------------------------------------------------------------
; Immutable d||z fixture and writable state
; ---------------------------------------------------------------------------

%ifndef TLS13_POC_OVERLAY
tag_keygen db 'MLKKEY', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_N db 'N=', 0
str_dt db ' dt=', 0
str_ck db ' ck=', 0
str_check db ' N=1 dt=0 ck=', 0
%endif
cbd2_nibbles db 0,1,1,2,-1,0,0,1,-1,0,0,1,-2,-1,-1,0
%ifdef MLKEM_KEYGEN_ROOT_DERIVATION
keygen_regenerate_domain db 'S13 8088 attempt v2',0
keygen_regenerate_domain_len equ $ - keygen_regenerate_domain
%endif

align 2
%ifndef TLS13_POC_OVERLAY
fixture_d_z:
    db 0xa0,0x10,0x8d,0x8d,0x49,0x51,0x5e,0x7e,0x24,0x86,0x42,0x16,0xb5,0x0d,0xa8,0x61
    db 0x34,0xf4,0x24,0x8c,0x74,0xe4,0xdc,0xd1,0xde,0xc4,0x1d,0xd1,0x96,0x98,0x51,0x89
    db 0x33,0xe6,0x76,0x73,0xf1,0x58,0xec,0xbe,0x40,0x1e,0x56,0x3c,0x96,0x73,0x43,0xa3
    db 0xc4,0x88,0xb0,0xd2,0x1f,0x7c,0x04,0x8e,0x10,0xaf,0x2c,0x74,0x61,0xc4,0xc8,0x4e
fixture_d_z_end:
%endif

align 2
sk_output_ptrs:
    dw keygen_s_hat0, keygen_s_hat1, keygen_s_hat2
pk_output_ptrs:
    dw keygen_ek, keygen_ek + 384, keygen_ek + 768

round_index dw 0
%ifdef MLKEM_KEYGEN_RUNTIME_ROOT
keygen_root_ptr dw 0
keygen_root_output dw 0
keygen_root_epoch db 0
keygen_root_index db 0
%elifdef MLKEM_KEYGEN_ROOT_INPUT
keygen_root_index db 0
%endif
rot_outputs dw 0
rot_bits db 0
rot_inv_bits db 0
%ifndef TLS13_POC_OVERLAY
op_ptr dw 0
bench_iters dw 0
t0_lo dw 0
t0_hi dw 0
dt_lo dw 0
%endif
fq_product_lo dw 0
fq_product_hi dw 0
barrett_input dw 0
poly_ptr dw 0
ntt_k dw 0
ntt_len dw 0
ntt_start dw 0
ntt_zeta dw 0
ntt_distance dw 0
ntt_end_ptr dw 0
bm_group dw 0
bm_zeta dw 0
bm_a_ptr dw 0
bm_b_ptr dw 0
bm_r_ptr dw 0
bm_temp dw 0

keygen_row db 0
keygen_col db 0
noise_nonce db 0
hash_input_ptr dw 0
matrix_y_ptr dw 0
sample_first db 0
sample_second db 0
sample_pos dw 0
sample_group_index dw 0
sample_fill dw 0
sample_d1 dw 0
sample_d2 dw 0
sample_offset dw 0
codec_pairs dw 0
codec_a dw 0
codec_b dw 0
sample_group: times 4 dw 0
sample_product: times 4 dw 0
rho_sigma: times 64 db 0

keccak_c: times 40 db 0
keccak_d: times 40 db 0
lane_tmp: times 8 db 0
keccak_state: times state_bytes db 0
keccak_b: times state_bytes db 0

%ifndef TLS13_POC_OVERLAY
poly_s: times poly_words dw 0
poly_acc: times poly_words dw 0
%endif
poly_u equ poly_s
poly_product equ poly_acc
%ifndef TLS13_POC_OVERLAY
generated_dk: times 2400 db 0
%endif

image_end:

%ifdef TLS13_POC_OVERLAY
%if (image_end - $$) > (poc_timed_code_end_max - poc_k_start)
    %error "product-shaped ML-KEM KeyGen exceeds the timed-overlay code budget"
%endif
%else
%if image_end - core_header > 0x2e00
    %error "integrated ML-KEM KeyGen leaves less than 512 bytes below 16 KiB"
%endif
%endif
