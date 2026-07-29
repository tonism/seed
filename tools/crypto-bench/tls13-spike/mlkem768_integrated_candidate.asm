; Exact byte-level ML-KEM-768 decapsulation spike for an 8088.
;
; This is not product code and it is not complete ML-KEM decapsulation.  It
; consumes one deterministic, valid FIPS 203/OpenSSL ML-KEM-768 decapsulation
; key and ciphertext and performs the real byte-level operations through:
;
;   m'       = K-PKE.Decrypt(dkPKE, c)
;   (K', r') = G(m' || H(ek))
;
; It retains the provisional boundary as a separately callable correctness
; gate, then performs exact K-PKE.Encrypt re-encryption, a fixed-length
; serialized ciphertext comparison, J(z || c), and branchless implicit
; rejection selection.

bits 16
cpu 8086
org 0x1000

poly_words equ 256
poly_bytes equ 512
state_bytes equ 200
dkpke_bytes equ 1152
ek_bytes equ 1184
h_offset equ dkpke_bytes + ek_bytes

%ifndef BENCH_ITERS
    %define BENCH_ITERS 1
%endif

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

%ifdef BENCH_INVALID
    xor byte [fixture_ciphertext], 1
%endif

%ifdef BENCH_CANDIDATE_ONLY
    call mlkem_candidate
    call candidate_matches_oracle
%else
    call mlkem_decaps
    call selected_matches_oracle
%endif
    or ax, ax
    jz fail

    mov si, tag_check
    mov ax, 1
    call emit_check

%ifdef BENCH_CANDIDATE_ONLY
    mov si, tag_candidate
    mov bp, mlkem_candidate
%else
    mov si, tag_decaps
    mov bp, mlkem_decaps
%endif
    mov cx, BENCH_ITERS
    call run_op
%ifdef BENCH_CANDIDATE_ONLY
    mov si, candidate_g
%else
    mov si, selected_secret
%endif
    mov cx, 16
    call emit_tail

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

; Return AX=1 only when all 64 G-output bytes match the frozen oracle.
candidate_matches_oracle:
    mov si, candidate_g
    mov di, fixture_expected_g
    mov cx, 64
.compare:
    mov al, [si]
    xor al, [di]
    jnz .bad
    inc si
    inc di
    loop .compare
    mov ax, 1
    ret
.bad:
    xor ax, ax
    ret

; Return AX=1 only when the selected valid-ciphertext secret matches K'.
selected_matches_oracle:
    mov si, selected_secret
%ifdef BENCH_INVALID
    mov di, fixture_expected_invalid_secret
%else
    mov di, fixture_expected_g
%endif
    mov cx, 32
.compare:
    mov al, [si]
    xor al, [di]
    jnz .bad
    inc si
    inc di
    loop .compare
    mov ax, 1
    ret
.bad:
    xor ax, ax
    ret

; ---------------------------------------------------------------------------
; Exact K-PKE.Decrypt + G provisional path
; ---------------------------------------------------------------------------

mlkem_candidate:
    ; The accumulator is the NTT-domain inner product sHat^T * NTT(u).
    mov di, poly_acc
    xor ax, ax
    mov cx, poly_words
    rep stosw

    mov si, fixture_dk
    call decode_poly12
    mov si, fixture_ciphertext
    call decode_poly10_decompress
    call candidate_component

    mov si, fixture_dk + 384
    call decode_poly12
    mov si, fixture_ciphertext + 320
    call decode_poly10_decompress
    call candidate_component

    mov si, fixture_dk + 768
    call decode_poly12
    mov si, fixture_ciphertext + 640
    call decode_poly10_decompress
    call candidate_component

    ; Match polyvec_basemul_acc_montgomery's final reduction, then return
    ; from the NTT domain.
    call reduce_and_inv_acc

    ; Decode/decompress v, form v - sHat^T*u, Compress_1, and ByteEncode_1.
    mov si, fixture_ciphertext + 960
    call decode_poly4_decompress
    call decrypt_poly_to_message

    ; SHA3-512(m' || H(ek)); candidate_g[0:32] is K', [32:64] is r'.
    call sha3_512_message_h
    ret

candidate_component:
    mov si, poly_u
    call ntt_poly
    call basemul_poly
    mov si, poly_product
    mov di, poly_acc
    mov cx, poly_words
.accumulate:
    lodsw
    add [di], ax
    add di, 2
    loop .accumulate
    ret

; Decode one 384-byte ByteEncode_12 polynomial at SI to poly_s.
decode_poly12:
    mov di, poly_s
    mov word [decode_pairs_left], 128
.pair:
    call decode_poly12_pair
    dec word [decode_pairs_left]
    jnz .pair
    ret

; Decode one three-byte pair at SI to two 12-bit words at DI.
decode_poly12_pair:
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
    ret

; Decode one 320-byte ByteEncode_10 polynomial and Decompress_10 to poly_u.
decode_poly10_decompress:
    mov di, poly_u
    mov word [decode_groups_left], 64
.group:
    lodsb
    mov [decode_b0], al
    lodsb
    mov [decode_b1], al
    lodsb
    mov [decode_b2], al
    lodsb
    mov [decode_b3], al
    lodsb
    mov [decode_b4], al

    xor ax, ax
    mov al, [decode_b1]
    and ax, 3
    mov cl, 8
    shl ax, cl
    xor bx, bx
    mov bl, [decode_b0]
    or ax, bx
    call decompress10
    stosw

    xor ax, ax
    mov al, [decode_b1]
    mov cl, 2
    shr ax, cl
    xor bx, bx
    mov bl, [decode_b2]
    and bx, 15
    mov cl, 6
    shl bx, cl
    or ax, bx
    call decompress10
    stosw

    xor ax, ax
    mov al, [decode_b2]
    mov cl, 4
    shr ax, cl
    xor bx, bx
    mov bl, [decode_b3]
    and bx, 63
    shl bx, cl
    or ax, bx
    call decompress10
    stosw

    xor ax, ax
    mov al, [decode_b3]
    mov cl, 6
    shr ax, cl
    xor bx, bx
    mov bl, [decode_b4]
    mov cl, 2
    shl bx, cl
    or ax, bx
    call decompress10
    stosw

    dec word [decode_groups_left]
    jnz .group
    ret

; Decode one 128-byte ByteEncode_4 polynomial and Decompress_4 to poly_product.
decode_poly4_decompress:
    mov di, poly_product
    mov word [decode_pairs_left], 128
.pair:
    lodsb
    mov dl, al
    and ax, 0x000f
    call decompress4
    stosw
    xor ax, ax
    mov al, dl
    mov cl, 4
    shr ax, cl
    call decompress4
    stosw
    dec word [decode_pairs_left]
    jnz .pair
    ret

; AX in [0,1023] -> round(q*AX/2^10), exact FIPS Decompress_10.
decompress10:
    push bx
    push cx
    push dx
    mov bx, 3329
    mul bx
    add ax, 512
    adc dx, 0
    mov cx, 10
.shift:
    shr dx, 1
    rcr ax, 1
    loop .shift
    pop dx
    pop cx
    pop bx
    ret

; AX in [0,15] -> round(q*AX/2^4), exact FIPS Decompress_4.
decompress4:
    push bx
    push dx
    mov bx, 3329
    mul bx
    add ax, 8
    adc dx, 0
    mov bx, 4
.shift:
    shr dx, 1
    rcr ax, 1
    dec bx
    jnz .shift
    pop dx
    pop bx
    ret

; Compress_1(v - inner product), ByteEncode_1, little-endian bit order.
decrypt_poly_to_message:
    mov si, poly_product
    mov di, poly_acc
    mov bp, message_m
    mov word [message_bytes_left], 32
.byte:
    mov byte [message_byte], 0
    mov byte [message_mask], 1
    mov word [message_bits_left], 8
.bit:
    lodsw
    sub ax, [di]
    add di, 2
    call barrett_reduce
    test ax, ax
    jns .canonical
    add ax, 3329
.canonical:
    shl ax, 1
    add ax, 1664
    xor dx, dx
    mov bx, 3329
    div bx
    and al, 1
    jz .zero
    mov al, [message_mask]
    or [message_byte], al
.zero:
    shl byte [message_mask], 1
    dec word [message_bits_left]
    jnz .bit
    mov al, [message_byte]
    mov [bp], al
    inc bp
    dec word [message_bytes_left]
    jnz .byte
    ret

sha3_512_message_h:
    mov di, keccak_state
    xor ax, ax
    mov cx, state_bytes / 2
    rep stosw
    mov si, message_m
    mov di, keccak_state
    mov cx, 32
    rep movsb
    mov si, fixture_dk + h_offset
    mov cx, 32
    rep movsb
    mov byte [keccak_state + 64], 0x06
    mov byte [keccak_state + 71], 0x80
    call keccak_f1600
    mov si, keccak_state
    mov di, candidate_g
    mov cx, 64
    rep movsb
    ret

; ---------------------------------------------------------------------------
; Standards-complete ML-KEM.Decaps tail
; ---------------------------------------------------------------------------

mlkem_decaps:
    call mlkem_candidate
    mov byte [cipher_diff], 0

    ; y = NTT(CBD(PRF(r', nonce))) for nonces 0, 1, and 2.
    xor ax, ax
    mov di, poly_s
    call noise_to_poly
    mov si, poly_s
    call ntt_poly
    mov al, 1
    mov di, poly_u
    call noise_to_poly
    mov si, poly_u
    call ntt_poly
    mov al, 2
    mov di, poly_product
    call noise_to_poly
    mov si, poly_product
    call ntt_poly

    ; u = A^T*y + e1.  Generate each public A^T polynomial directly into
    ; four-coefficient base-multiplication groups, so no matrix cache exists.
    mov byte [reencrypt_row], 0
.u_row:
    call zero_acc
    mov byte [reencrypt_col], 0
.u_col:
    xor bx, bx
    mov bl, [reencrypt_col]
    shl bx, 1
    mov ax, [y_poly_ptrs + bx]
    mov [reencrypt_y_ptr], ax
    mov al, [reencrypt_row]
    mov ah, [reencrypt_col]
    call sample_ntt_accumulate
    inc byte [reencrypt_col]
    cmp byte [reencrypt_col], 3
    jb .u_col
    call reduce_and_inv_acc
    mov al, [reencrypt_row]
    add al, 3
    call noise_add_to_acc
    xor bx, bx
    mov bl, [reencrypt_row]
    shl bx, 1
    mov si, [u_cipher_ptrs + bx]
    call compress10_compare
    inc byte [reencrypt_row]
    cmp byte [reencrypt_row], 3
    jb .u_row

    ; v = tHat^T*y + e2 + Decompress_1(m).  Decode tHat in four-word
    ; base-multiplication groups and retain no expanded public-key polynomial.
    call zero_acc
    mov byte [reencrypt_col], 0
.v_col:
    xor bx, bx
    mov bl, [reencrypt_col]
    shl bx, 1
    mov ax, [y_poly_ptrs + bx]
    mov [reencrypt_y_ptr], ax
    mov si, [t_poly_ptrs + bx]
    call decode12_accumulate
    inc byte [reencrypt_col]
    cmp byte [reencrypt_col], 3
    jb .v_col
    call reduce_and_inv_acc
    mov al, 6
    call noise_add_to_acc
    call add_message_to_acc
    mov si, fixture_ciphertext + 960
    call compress4_compare

    ; Both paths always compute J.  Only the fixed-length serialized compare
    ; and branchless byte selection decide which 32-byte secret is returned.
    call shake256_j
    call select_decaps_secret
    ret

zero_acc:
    mov di, poly_acc
    xor ax, ax
    mov cx, poly_words
    rep stosw
    ret

reduce_and_inv_acc:
    mov si, poly_acc
    mov di, poly_acc
    mov cx, poly_words
.reduce:
    lodsw
    push cx
    call barrett_reduce
    pop cx
    stosw
    loop .reduce
    mov si, poly_acc
    call invntt_poly
    ret

clear_keccak:
    mov di, keccak_state
    xor ax, ax
    mov cx, state_bytes / 2
    rep stosw
    ret

; SHAKE128(rho || row || col), rejection-sampled as SampleNTT, immediately
; base-multiplied by the polynomial at reencrypt_y_ptr and added to poly_acc.
sample_ntt_accumulate:
    mov [sample_row], al
    mov [sample_col], ah
    call clear_keccak
    mov si, fixture_dk + dkpke_bytes + 1152
    mov di, keccak_state
    mov cx, 32
    rep movsb
    mov al, [sample_row]
    stosb
    mov al, [sample_col]
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

; BaseMultiply one four-coefficient A/tHat group by the corresponding yHat
; group and add all four output words to poly_acc.
accumulate_sample_group:
    mov ax, [sample_group_index]
    mov bx, ax
    mov cl, 3
    shl ax, cl
    mov [sample_offset], ax
    mov si, sample_group
    mov di, [reencrypt_y_ptr]
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
    mov di, [reencrypt_y_ptr]
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

; Decode one public-key ByteEncode_12 polynomial and feed each four-word group
; to the same streaming base-multiply accumulator.
decode12_accumulate:
    mov word [sample_group_index], 0
.group:
    mov di, sample_group
    call decode_poly12_pair
    call decode_poly12_pair
    push si
    call accumulate_sample_group
    pop si
    inc word [sample_group_index]
    cmp word [sample_group_index], 64
    jb .group
    ret

; SHAKE256(r' || nonce, 128) and CBD_eta2 into one full polynomial at DI.
noise_to_poly:
    push di
    call prf_noise
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

; SHAKE256(r' || nonce, 128), CBD_eta2, and add directly to poly_acc.
noise_add_to_acc:
    call prf_noise
    mov si, keccak_state
    mov di, poly_acc
    mov bx, cbd2_nibbles
    mov bp, 128
.byte:
    lodsb
    mov dl, al
    and al, 0x0f
    xlat
    cbw
    add [di], ax
    add di, 2
    xor ax, ax
    mov al, dl
    mov cl, 4
    shr al, cl
    xlat
    cbw
    add [di], ax
    add di, 2
    dec bp
    jnz .byte
    ret

prf_noise:
    mov [noise_nonce], al
    call clear_keccak
    mov si, candidate_g + 32
    mov di, keccak_state
    mov cx, 32
    rep movsb
    mov al, [noise_nonce]
    stosb
    mov byte [keccak_state + 33], 0x1f
    mov byte [keccak_state + 135], 0x80
    call keccak_f1600
    ret

canonicalize:
    call barrett_reduce
    cwd
    and dx, 3329
    add ax, dx
    ret

compress10_value:
    call canonicalize
    mov bx, 1024
    mul bx
    add ax, 1664
    adc dx, 0
    mov bx, 3329
    div bx
    and ax, 1023
    ret

compress4_value:
    call canonicalize
    mov bx, 16
    mul bx
    add ax, 1664
    adc dx, 0
    mov bx, 3329
    div bx
    and ax, 15
    ret

; Fixed-length ByteEncode_10 comparison: all 960 serialized u bytes are
; visited and OR-reduced into cipher_diff.
compress10_compare:
    mov di, poly_acc
    mov bp, 64
.group:
    mov ax, [di]
    add di, 2
    call compress10_value
    mov [compress_values], ax
    mov ax, [di]
    add di, 2
    call compress10_value
    mov [compress_values + 2], ax
    mov ax, [di]
    add di, 2
    call compress10_value
    mov [compress_values + 4], ax
    mov ax, [di]
    add di, 2
    call compress10_value
    mov [compress_values + 6], ax

    mov al, [compress_values]
    call compare_byte
    mov ax, [compress_values]
    mov cl, 8
    shr ax, cl
    mov dx, [compress_values + 2]
    shl dx, 1
    shl dx, 1
    or ax, dx
    call compare_byte
    mov ax, [compress_values + 2]
    mov cl, 6
    shr ax, cl
    mov dx, [compress_values + 4]
    mov cl, 4
    shl dx, cl
    or ax, dx
    call compare_byte
    mov ax, [compress_values + 4]
    mov cl, 4
    shr ax, cl
    mov dx, [compress_values + 6]
    mov cl, 6
    shl dx, cl
    or ax, dx
    call compare_byte
    mov ax, [compress_values + 6]
    mov cl, 2
    shr ax, cl
    call compare_byte
    dec bp
    jnz .group
    ret

; Add Decompress_1(m) without a data-dependent branch.
add_message_to_acc:
    mov si, message_m
    mov di, poly_acc
    mov word [message_bytes_left], 32
.byte:
    lodsb
    mov dl, al
    mov bp, 8
.bit:
    xor ax, ax
    mov al, dl
    and ax, 1
    neg ax
    and ax, 1665
    add [di], ax
    add di, 2
    shr dl, 1
    dec bp
    jnz .bit
    dec word [message_bytes_left]
    jnz .byte
    ret

; Fixed-length ByteEncode_4 comparison of all 128 serialized v bytes.
compress4_compare:
    mov di, poly_acc
    mov bp, 128
.pair:
    mov ax, [di]
    add di, 2
    call compress4_value
    mov [compress_low], al
    mov ax, [di]
    add di, 2
    call compress4_value
    mov cl, 4
    shl al, cl
    or al, [compress_low]
    call compare_byte
    dec bp
    jnz .pair
    ret

compare_byte:
    xor al, [si]
    or [cipher_diff], al
    inc si
    ret

; J(z || c) = SHAKE256(z || c, 32), absorbing 8 full 136-byte blocks and
; one final 32-byte block.
shake256_j:
    call clear_keccak
    mov si, fixture_dk + 2368
    mov di, keccak_state
    mov cx, 32
    rep movsb
    mov si, fixture_ciphertext
    mov cx, 104
    rep movsb
    call keccak_f1600
    mov word [j_cipher_ptr], fixture_ciphertext + 104
    mov bp, 7
.full_block:
    mov si, [j_cipher_ptr]
    mov di, keccak_state
    mov cx, 68
.xor_word:
    lodsw
    xor [di], ax
    add di, 2
    loop .xor_word
    mov [j_cipher_ptr], si
    push bp
    call keccak_f1600
    pop bp
    dec bp
    jnz .full_block
    mov si, [j_cipher_ptr]
    mov di, keccak_state
    mov cx, 16
.xor_tail:
    lodsw
    xor [di], ax
    add di, 2
    loop .xor_tail
    xor byte [keccak_state + 32], 0x1f
    xor byte [keccak_state + 135], 0x80
    call keccak_f1600
    ret

; mask = 00 for c'=c and FF for any serialized difference.  Every output
; byte executes the same candidate/J selection sequence.
select_decaps_secret:
    mov al, [cipher_diff]
    neg al
    sbb al, al
    mov [reject_mask], al
    mov si, candidate_g
    mov bx, keccak_state
    mov di, selected_secret
    mov cx, 32
.byte:
    lodsb
    mov dl, al
    xor al, [bx]
    and al, [reject_mask]
    xor al, dl
    stosb
    inc bx
    loop .byte
    ret

%include "tools/crypto-bench/tls13-spike/mlkem768_integrated_core.inc"

; ---------------------------------------------------------------------------
; Timing and serial output
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
    call checksum_words
    push ax
    mov si, str_ck
    call emit_str
    pop ax
    call emit_hex16
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

checksum_words:
    xor ax, ax
.sum:
    add ax, [si]
    add si, 2
    loop .sum
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

; ---------------------------------------------------------------------------
; Immutable reference fixture and writable state
; ---------------------------------------------------------------------------

tag_candidate db 'MLKCAND', 0
tag_decaps db 'MLKDECAP', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_N db 'N=', 0
str_dt db ' dt=', 0
str_ck db ' ck=', 0
str_check db ' N=1 dt=0 ck=', 0

align 2
y_poly_ptrs dw poly_s, poly_u, poly_product
t_poly_ptrs:
    dw fixture_dk + dkpke_bytes
    dw fixture_dk + dkpke_bytes + 384
    dw fixture_dk + dkpke_bytes + 768
u_cipher_ptrs:
    dw fixture_ciphertext
    dw fixture_ciphertext + 320
    dw fixture_ciphertext + 640
cbd2_nibbles db 0,1,1,2,-1,0,0,1,-1,0,0,1,-2,-1,-1,0
%ifdef BENCH_INVALID
fixture_expected_invalid_secret:
    db 0x56,0xc5,0x84,0x36,0xfb,0x2a,0xc9,0x37
    db 0x44,0xab,0x65,0x64,0xad,0x26,0x49,0x1c
    db 0x5f,0x49,0x37,0xa2,0xd7,0x39,0xa9,0x52
    db 0x9a,0x33,0x3c,0x92,0x77,0xa8,0xce,0x3c
%endif

%include "tools/crypto-bench/tls13-spike/mlkem768_integrated_vectors.inc"

align 2
round_index dw 0
rot_outputs dw 0
rot_bits db 0
rot_inv_bits db 0
op_ptr dw 0
bench_iters dw 0
t0_lo dw 0
t0_hi dw 0
dt_lo dw 0
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

decode_pairs_left dw 128
decode_groups_left dw 0
decode_b0 db 0
decode_b1 db 0
decode_b2 db 0
decode_b3 db 0
decode_b4 db 0
message_bytes_left dw 0
message_bits_left dw 0
message_byte db 0
message_mask db 0
reencrypt_row db 0
reencrypt_col db 0
reencrypt_y_ptr dw 0
sample_row db 0
sample_col db 0
sample_pos dw 0
sample_group_index dw 0
sample_fill dw 0
sample_d1 dw 0
sample_d2 dw 0
sample_offset dw 0
noise_nonce db 0
cipher_diff db 0
compress_low db 0
reject_mask db 0
j_cipher_ptr dw 0
sample_group: times 4 dw 0
sample_product: times 4 dw 0
compress_values: times 4 dw 0

keccak_c: times 40 db 0
keccak_d: times 40 db 0
lane_tmp: times 8 db 0
keccak_state: times state_bytes db 0
keccak_b: times state_bytes db 0

poly_s: times poly_words dw 0
poly_u: times poly_words dw 0
poly_product: times poly_words dw 0
poly_acc: times poly_words dw 0
message_m: times 32 db 0
candidate_g: times 64 db 0
selected_secret: times 32 db 0

image_end:

%if image_end - core_header > 0x2e00
    %error "integrated ML-KEM candidate leaves less than 512 bytes below the 16 KiB stack"
%endif
