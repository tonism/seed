; Product-shaped ML-KEM-768 Fujisaki-Okamoto tail for an offline 8088 phase.
;
; This overlay starts after the provisional candidate and socket close.  It
; does not repeat K-PKE.Decrypt.  It consumes persistent m', K' || r', and z,
; streams the public ek/c objects through a caller callback, performs exact
; K-PKE.Encrypt re-encryption and a fixed-length serialized comparison, then
; computes J(z || c) and branchlessly selects K' or the rejection secret.
;
; Entry:
;   DS=ES=SS=0
;   BX = near callback address
;
; Callback:
;   AL = object (0=ek[1184], 1=c[1088])
;   DX = byte offset, CX = byte count, DI = destination below 0x4000
;   CF clear on success, set on failure
;   preserves BX, BP, DS, ES, SS; returns with DF clear
;   maximum request is 384 bytes
;
; Exit:
;   CF clear, AX=1: c'=c and 3b9c..3bbc contains confirmed K'
;   CF clear, AX=0: reject and 3b9c..3bbc contains J(z || c)
;   CF set,   AX=ffff: public-object read failed; output was zeroed
;
; Fixed persistent inputs:
;   3a40..3a60  m'[32]
;   3b9c..3bbc  provisional K'[32]
;   3bbc..3bdc  r'[32]
;   3bdc..3bfc  z[32]

bits 16
cpu 8086

%ifndef FO_LOAD_ADDR
    %define FO_LOAD_ADDR 0x1800
%endif

org FO_LOAD_ADDR

%include "layout.inc"

fo_q                         equ 3329
fo_poly_words                equ 256
fo_poly_bytes                equ 512
fo_state_bytes               equ 200
fo_object_ek                 equ 0
fo_object_c                  equ 1

; Preserve this entire band for a live ticket identity/metadata hold.
%ifdef FO_TICKET_HOLD_ADDR
fo_ticket_hold               equ FO_TICKET_HOLD_ADDR
%else
fo_ticket_hold               equ poc_low_scratch_start
%endif
fo_ticket_hold_len           equ 0x0130
fo_ticket_hold_end           equ fo_ticket_hold + fo_ticket_hold_len

; Offline low work: three retained yHat polynomials, rho, and one bounded
; public-object stream buffer.  The final 48 low bytes remain a guard.
fo_y0                        equ fo_ticket_hold_end
fo_y1                        equ fo_y0 + fo_poly_bytes
fo_y2                        equ fo_y1 + fo_poly_bytes
fo_rho                       equ fo_y2 + fo_poly_bytes
fo_public_buffer             equ fo_rho + 32
fo_public_buffer_len         equ 384
fo_low_work_end              equ fo_public_buffer + fo_public_buffer_len

; K-resident external work.  Keeping this below 0x3600 leaves the high saved-c
; mirror untouched and makes the image directly timing-ready at K=0x1800.
fo_keccak_state              equ 0x3000
fo_keccak_b                  equ fo_keccak_state + 200
fo_keccak_c                  equ fo_keccak_b + 200
fo_keccak_d                  equ fo_keccak_c + 40
fo_lane_tmp                  equ fo_keccak_d + 40
fo_keccak_work_end           equ fo_lane_tmp + 8
fo_poly_acc                  equ poc_poly_acc

%ifdef FO_MESSAGE_ADDR
fo_message                   equ FO_MESSAGE_ADDR
%else
fo_message                   equ poc_tls_vault_start
%endif
%ifdef FO_CANDIDATE_G_ADDR
fo_selected_secret           equ FO_CANDIDATE_G_ADDR
fo_candidate_k               equ FO_CANDIDATE_G_ADDR
fo_reencrypt_coins           equ FO_CANDIDATE_G_ADDR + 32
%else
fo_selected_secret           equ poc_candidate_g
fo_candidate_k               equ poc_candidate_g
fo_reencrypt_coins           equ poc_candidate_g + 32
%endif
%ifdef FO_Z_ADDR
fo_z                         equ FO_Z_ADDR
%else
fo_z                         equ poc_candidate_z
%endif

fo_overlay_start:

; Timing entry for the whole offline FO tail.
fo_tail_entry:
    cld
    mov [fo_read_ptr], bx
    mov byte [fo_cipher_diff], 0

    ; rho is the only public-key field reused across all nine A samples.
    mov al, fo_object_ek
    mov dx, 1152
    mov cx, 32
    mov di, fo_rho
    call fo_read_public
    jc fo_io_fail

    ; yHat = NTT(CBD(PRF(r', nonce))) for nonces 0, 1, 2.
    xor ax, ax
    mov di, fo_y0
    call fo_noise_to_poly
    mov si, fo_y0
    call fo_ntt_poly

    mov al, 1
    mov di, fo_y1
    call fo_noise_to_poly
    mov si, fo_y1
    call fo_ntt_poly

    mov al, 2
    mov di, fo_y2
    call fo_noise_to_poly
    mov si, fo_y2
    call fo_ntt_poly

fo_reencrypt_start:
    ; u = A^T*y + e1.  Each sampled A polynomial is consumed four
    ; coefficients at a time and accumulated directly; no poly_product exists.
    mov byte [fo_reencrypt_row], 0
.u_row:
    call fo_zero_acc
    mov byte [fo_reencrypt_col], 0
.u_col:
    xor bx, bx
    mov bl, [fo_reencrypt_col]
    shl bx, 1
    mov ax, [fo_y_poly_ptrs + bx]
    mov [fo_reencrypt_y_ptr], ax
    mov al, [fo_reencrypt_row]
    mov ah, [fo_reencrypt_col]
    call fo_sample_ntt_accumulate
    inc byte [fo_reencrypt_col]
    cmp byte [fo_reencrypt_col], 3
    jb .u_col
    call fo_reduce_and_inv_acc
    mov al, [fo_reencrypt_row]
    add al, 3
    call fo_noise_add_to_acc

    xor bx, bx
    mov bl, [fo_reencrypt_row]
    shl bx, 1
    mov dx, [fo_u_cipher_offsets + bx]
    mov al, fo_object_c
    mov cx, 320
    mov di, fo_public_buffer
    call fo_read_public
    jc fo_io_fail
    mov si, fo_public_buffer
    call fo_compress10_compare

    inc byte [fo_reencrypt_row]
    cmp byte [fo_reencrypt_row], 3
    jb .u_row

    ; v = tHat^T*y + e2 + Decompress_1(m').  A compressed tHat component
    ; is streamed into the 384-byte public buffer and decoded directly into
    ; four-word base-multiplication groups.
    call fo_zero_acc
    mov byte [fo_reencrypt_col], 0
.v_col:
    xor bx, bx
    mov bl, [fo_reencrypt_col]
    shl bx, 1
    mov ax, [fo_y_poly_ptrs + bx]
    mov [fo_reencrypt_y_ptr], ax
    mov dx, [fo_t_hat_offsets + bx]
    mov al, fo_object_ek
    mov cx, 384
    mov di, fo_public_buffer
    call fo_read_public
    jc fo_io_fail
    mov si, fo_public_buffer
    call fo_decode12_accumulate
    inc byte [fo_reencrypt_col]
    cmp byte [fo_reencrypt_col], 3
    jb .v_col
    call fo_reduce_and_inv_acc
    mov al, 6
    call fo_noise_add_to_acc
    call fo_add_message_to_acc

    mov al, fo_object_c
    mov dx, 960
    mov cx, 128
    mov di, fo_public_buffer
    call fo_read_public
    jc fo_io_fail
    mov si, fo_public_buffer
    call fo_compress4_compare

fo_reencrypt_end:
fo_j_start:
    ; yHat is dead.  J uses the separate K Keccak workspace and streams c in
    ; rate-sized pieces, so neither public object ever needs a RAM-sized copy.
    call fo_shake256_j
    jc fo_io_fail
    call fo_select_decaps_secret

    xor ax, ax
    cmp byte [fo_cipher_diff], 0
    jne .reject
    inc ax
.reject:
    clc
    ret

fo_io_fail:
    mov di, fo_selected_secret
    xor ax, ax
    mov cx, 16
    rep stosw
    mov ax, 0xffff
    stc
    ret

; Invoke the supplied stream callback and re-establish the string invariant
; without disturbing its success/failure carry result.
fo_read_public:
    call word [fo_read_ptr]
    cld
    ret

fo_zero_acc:
    mov di, fo_poly_acc
    xor ax, ax
    mov cx, fo_poly_words
    rep stosw
    ret

fo_reduce_and_inv_acc:
    mov si, fo_poly_acc
    mov di, fo_poly_acc
    mov cx, fo_poly_words
.reduce:
    lodsw
    push cx
    call fo_barrett_reduce
    pop cx
    stosw
    loop .reduce
    mov si, fo_poly_acc
    call fo_invntt_poly
    ret

fo_clear_keccak:
    mov di, fo_keccak_state
    xor ax, ax
    mov cx, fo_state_bytes / 2
    rep stosw
    ret

; SHAKE256(r' || nonce, 128), CBD_eta2, and retain a full polynomial at DI.
fo_noise_to_poly:
    push di
    call fo_prf_noise
    pop di
    mov si, fo_keccak_state
    mov bx, fo_cbd2_nibbles
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

; SHAKE256(r' || nonce, 128), CBD_eta2, and add directly to the accumulator.
fo_noise_add_to_acc:
    call fo_prf_noise
    mov si, fo_keccak_state
    mov di, fo_poly_acc
    mov bx, fo_cbd2_nibbles
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

fo_prf_noise:
    mov [fo_noise_nonce], al
    call fo_clear_keccak
    mov si, fo_reencrypt_coins
    mov di, fo_keccak_state
    mov cx, 32
    rep movsb
    mov al, [fo_noise_nonce]
    stosb
    mov byte [fo_keccak_state + 33], 0x1f
    mov byte [fo_keccak_state + 135], 0x80
    call fo_keccak_f1600
    ret

; SHAKE128(rho || row || col), rejection-sampled as SampleNTT, immediately
; base-multiplied by the selected yHat polynomial and added to the accumulator.
fo_sample_ntt_accumulate:
    mov [fo_sample_row], al
    mov [fo_sample_col], ah
    call fo_clear_keccak
    mov si, fo_rho
    mov di, fo_keccak_state
    mov cx, 32
    rep movsb
    mov al, [fo_sample_row]
    stosb
    mov al, [fo_sample_col]
    stosb
    mov byte [fo_keccak_state + 34], 0x1f
    mov byte [fo_keccak_state + 167], 0x80
    call fo_keccak_f1600
    mov word [fo_sample_pos], 0
    mov word [fo_sample_group_index], 0
    mov word [fo_sample_fill], 0
.next_triple:
    cmp word [fo_sample_pos], 165
    jbe .have_three
    call fo_keccak_f1600
    mov word [fo_sample_pos], 0
.have_three:
    mov bx, fo_keccak_state
    add bx, [fo_sample_pos]
    xor ax, ax
    mov al, [bx + 1]
    and ax, 0x000f
    mov cl, 8
    shl ax, cl
    xor dx, dx
    mov dl, [bx]
    or ax, dx
    mov [fo_sample_d1], ax
    xor ax, ax
    mov al, [bx + 1]
    mov cl, 4
    shr ax, cl
    xor dx, dx
    mov dl, [bx + 2]
    shl dx, cl
    or ax, dx
    mov [fo_sample_d2], ax
    add word [fo_sample_pos], 3
    mov ax, [fo_sample_d1]
    call fo_sample_accept
    cmp word [fo_sample_group_index], 64
    je .done
    mov ax, [fo_sample_d2]
    call fo_sample_accept
    cmp word [fo_sample_group_index], 64
    jb .next_triple
.done:
    ret

fo_sample_accept:
    cmp ax, fo_q
    jae .done
    mov bx, [fo_sample_fill]
    shl bx, 1
    mov [fo_sample_group + bx], ax
    inc word [fo_sample_fill]
    cmp word [fo_sample_fill], 4
    jb .done
    call fo_accumulate_sample_group
    mov word [fo_sample_fill], 0
    inc word [fo_sample_group_index]
.done:
    ret

; BaseMultiply one four-coefficient A/tHat group by the matching yHat group
; and add directly to the final accumulator words.
fo_accumulate_sample_group:
    mov ax, [fo_sample_group_index]
    mov bx, ax
    mov cl, 3
    shl ax, cl
    mov [fo_sample_offset], ax
    mov si, fo_sample_group
    mov di, [fo_reencrypt_y_ptr]
    add di, ax
    mov bp, fo_poly_acc
    add bp, ax
    mov ax, bx
    add ax, 64
    shl ax, 1
    mov bx, fo_zetas
    add bx, ax
    mov ax, [bx]
    mov [fo_bm_zeta], ax
    call fo_basemul_pair_acc
    add si, 4
    add di, 4
    add bp, 4
    neg word [fo_bm_zeta]
    call fo_basemul_pair_acc
    ret

; Decode one compressed tHat polynomial and feed four-word groups directly to
; the same accumulator; no expanded public-key polynomial is retained.
fo_decode12_accumulate:
    mov word [fo_sample_group_index], 0
.group:
    mov di, fo_sample_group
    call fo_decode_poly12_pair
    call fo_decode_poly12_pair
    push si
    call fo_accumulate_sample_group
    pop si
    inc word [fo_sample_group_index]
    cmp word [fo_sample_group_index], 64
    jb .group
    ret

fo_decode_poly12_pair:
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

; Add two base-multiplication outputs directly to [BP].
fo_basemul_pair_acc:
    mov ax, [si + 2]
    mov bx, [di + 2]
    call fo_fqmul
    mov bx, [fo_bm_zeta]
    call fo_fqmul
    mov [fo_bm_temp], ax
    mov ax, [si]
    mov bx, [di]
    call fo_fqmul
    add ax, [fo_bm_temp]
    add [bp], ax

    mov ax, [si]
    mov bx, [di + 2]
    call fo_fqmul
    mov [fo_bm_temp], ax
    mov ax, [si + 2]
    mov bx, [di]
    call fo_fqmul
    add ax, [fo_bm_temp]
    add [bp + 2], ax
    ret

fo_canonicalize:
    call fo_barrett_reduce
    cwd
    and dx, fo_q
    add ax, dx
    ret

fo_compress10_value:
    call fo_canonicalize
    mov bx, 1024
    mul bx
    add ax, 1664
    adc dx, 0
    mov bx, fo_q
    div bx
    and ax, 1023
    ret

fo_compress4_value:
    call fo_canonicalize
    mov bx, 16
    mul bx
    add ax, 1664
    adc dx, 0
    mov bx, fo_q
    div bx
    and ax, 15
    ret

; Fixed-length ByteEncode_10 comparison.  Every one of the 960 serialized u
; bytes is visited and OR-reduced into fo_cipher_diff.
fo_compress10_compare:
    mov di, fo_poly_acc
    mov bp, 64
.group:
    mov ax, [di]
    add di, 2
    call fo_compress10_value
    mov [fo_compress_values], ax
    mov ax, [di]
    add di, 2
    call fo_compress10_value
    mov [fo_compress_values + 2], ax
    mov ax, [di]
    add di, 2
    call fo_compress10_value
    mov [fo_compress_values + 4], ax
    mov ax, [di]
    add di, 2
    call fo_compress10_value
    mov [fo_compress_values + 6], ax

    mov al, [fo_compress_values]
    call fo_compare_byte
    mov ax, [fo_compress_values]
    mov cl, 8
    shr ax, cl
    mov dx, [fo_compress_values + 2]
    shl dx, 1
    shl dx, 1
    or ax, dx
    call fo_compare_byte
    mov ax, [fo_compress_values + 2]
    mov cl, 6
    shr ax, cl
    mov dx, [fo_compress_values + 4]
    mov cl, 4
    shl dx, cl
    or ax, dx
    call fo_compare_byte
    mov ax, [fo_compress_values + 4]
    mov cl, 4
    shr ax, cl
    mov dx, [fo_compress_values + 6]
    mov cl, 6
    shl dx, cl
    or ax, dx
    call fo_compare_byte
    mov ax, [fo_compress_values + 6]
    mov cl, 2
    shr ax, cl
    call fo_compare_byte
    dec bp
    jnz .group
    ret

fo_add_message_to_acc:
    mov si, fo_message
    mov di, fo_poly_acc
    mov word [fo_message_bytes_left], 32
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
    dec word [fo_message_bytes_left]
    jnz .byte
    ret

; Fixed-length ByteEncode_4 comparison of all 128 serialized v bytes.
fo_compress4_compare:
    mov di, fo_poly_acc
    mov bp, 128
.pair:
    mov ax, [di]
    add di, 2
    call fo_compress4_value
    mov [fo_compress_low], al
    mov ax, [di]
    add di, 2
    call fo_compress4_value
    mov cl, 4
    shl al, cl
    or al, [fo_compress_low]
    call fo_compare_byte
    dec bp
    jnz .pair
    ret

fo_compare_byte:
    xor al, [si]
    or [fo_cipher_diff], al
    inc si
    ret

; J(z || c) = SHAKE256(z || c, 32).  The callback sequence is one 104-byte
; prefix, seven complete 136-byte rate blocks, and one 32-byte tail.
fo_shake256_j:
    call fo_clear_keccak
    mov si, fo_z
    mov di, fo_keccak_state
    mov cx, 32
    rep movsb

    mov al, fo_object_c
    xor dx, dx
    mov cx, 104
    mov di, fo_keccak_state + 32
    call fo_read_public
    jc .fail
    call fo_keccak_f1600

    mov word [fo_j_cipher_offset], 104
    mov byte [fo_j_blocks_left], 7
.full_block:
    mov al, fo_object_c
    mov dx, [fo_j_cipher_offset]
    mov cx, 136
    mov di, fo_public_buffer
    call fo_read_public
    jc .fail
    mov si, fo_public_buffer
    mov di, fo_keccak_state
    mov cx, 68
.xor_word:
    lodsw
    xor [di], ax
    add di, 2
    loop .xor_word
    add word [fo_j_cipher_offset], 136
    call fo_keccak_f1600
    dec byte [fo_j_blocks_left]
    jnz .full_block

    mov al, fo_object_c
    mov dx, [fo_j_cipher_offset]
    mov cx, 32
    mov di, fo_public_buffer
    call fo_read_public
    jc .fail
    mov si, fo_public_buffer
    mov di, fo_keccak_state
    mov cx, 16
.xor_tail:
    lodsw
    xor [di], ax
    add di, 2
    loop .xor_tail
    xor byte [fo_keccak_state + 32], 0x1f
    xor byte [fo_keccak_state + 135], 0x80
    call fo_keccak_f1600
    clc
    ret
.fail:
    stc
    ret

; mask=00 for c'=c and FF for any serialized difference.  Every output byte
; executes the same candidate/J selection sequence.
fo_select_decaps_secret:
    mov al, [fo_cipher_diff]
    neg al
    sbb al, al
    mov [fo_reject_mask], al
    mov si, fo_candidate_k
    mov bx, fo_keccak_state
    mov di, fo_selected_secret
    mov cx, 32
.byte:
    lodsb
    mov dl, al
    xor al, [bx]
    and al, [fo_reject_mask]
    xor al, dl
    stosb
    inc bx
    loop .byte
    ret

; ---------------------------------------------------------------------------
; Keccak-f[1600]
; ---------------------------------------------------------------------------

fo_keccak_f1600:
    mov word [fo_round_index], 0
.round:
    mov si, fo_keccak_state
    mov di, fo_keccak_c
    mov cx, 5
.theta_column:
    push cx
    mov cx, 4
.theta_word:
    mov ax, [si]
    xor ax, [si + 40]
    xor ax, [si + 80]
    xor ax, [si + 120]
    xor ax, [si + 160]
    stosw
    add si, 2
    loop .theta_word
    pop cx
    loop .theta_column

    xor bx, bx
.theta_d:
    mov al, [fo_theta_next + bx]
    xor ah, ah
    add ax, fo_keccak_c
    mov si, ax
    mov di, fo_lane_tmp
    mov cl, 1
    call fo_rotl64_to
    mov al, [fo_theta_prev + bx]
    xor ah, ah
    add ax, fo_keccak_c
    mov si, ax
    mov di, fo_keccak_d
    mov ax, bx
    mov cl, 3
    shl ax, cl
    add di, ax
    mov cx, 4
.theta_xor:
    mov ax, [si]
    xor ax, [fo_lane_tmp]
    push si
    mov si, fo_lane_tmp
    mov dx, 4
    sub dx, cx
    shl dx, 1
    add si, dx
    xor ax, [si]
    pop si
    xor ax, [fo_lane_tmp]
    stosw
    add si, 2
    loop .theta_xor
    inc bx
    cmp bx, 5
    jb .theta_d

    xor bx, bx
.theta_apply_column:
    mov ax, bx
    mov cl, 3
    shl ax, cl
    mov si, fo_keccak_d
    add si, ax
    mov di, fo_keccak_state
    add di, ax
    mov dx, 5
.theta_apply_row:
    mov cx, 4
.theta_apply_word:
    lodsw
    xor [di], ax
    add di, 2
    loop .theta_apply_word
    sub si, 8
    add di, 32
    dec dx
    jnz .theta_apply_row
    inc bx
    cmp bx, 5
    jb .theta_apply_column

    xor bx, bx
.rho_pi:
    mov ax, bx
    mov cl, 3
    shl ax, cl
    mov si, fo_keccak_state
    add si, ax
    mov al, [fo_pi_offsets + bx]
    xor ah, ah
    mov di, fo_keccak_b
    add di, ax
    mov cl, [fo_rho_offsets + bx]
    call fo_rotl64_to
    inc bx
    cmp bx, 25
    jb .rho_pi

    mov bx, fo_keccak_b
    mov bp, fo_keccak_state
    mov dx, 5
.chi_row:
    xor si, si
.chi_word:
    mov ax, [bx + si + 8]
    not ax
    and ax, [bx + si + 16]
    xor ax, [bx + si]
    mov [bp + si], ax

    mov ax, [bx + si + 16]
    not ax
    and ax, [bx + si + 24]
    xor ax, [bx + si + 8]
    mov [bp + si + 8], ax

    mov ax, [bx + si + 24]
    not ax
    and ax, [bx + si + 32]
    xor ax, [bx + si + 16]
    mov [bp + si + 16], ax

    mov ax, [bx + si + 32]
    not ax
    and ax, [bx + si]
    xor ax, [bx + si + 24]
    mov [bp + si + 24], ax

    mov ax, [bx + si]
    not ax
    and ax, [bx + si + 8]
    xor ax, [bx + si + 32]
    mov [bp + si + 32], ax

    add si, 2
    cmp si, 8
    jb .chi_word
    add bx, 40
    add bp, 40
    dec dx
    jnz .chi_row

    mov bx, [fo_round_index]
    mov ax, bx
    mov cl, 3
    shl ax, cl
    mov si, fo_round_constants
    add si, ax
    mov ax, [si]
    xor [fo_keccak_state], ax
    mov ax, [si + 2]
    xor [fo_keccak_state + 2], ax
    mov ax, [si + 4]
    xor [fo_keccak_state + 4], ax
    mov ax, [si + 6]
    xor [fo_keccak_state + 6], ax
    inc word [fo_round_index]
    cmp word [fo_round_index], 24
    jb .round
    ret

; CL is a public Keccak rotation count; caller lanes are disjoint.
; Preserve caller registers without spilling the newly loaded lane words.
fo_rotl64_to:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    cmp cl, 1
    jne .general
    mov ax, [si]
    mov bx, [si + 2]
    mov dx, [si + 4]
    mov bp, [si + 6]
    ; Seed carry from w3, then insert the final w2 carry into shifted w3.
    shl bp, 1
    rcl ax, 1
    rcl bx, 1
    rcl dx, 1
    adc bp, 0
    stosw
    mov ax, bx
    stosw
    mov ax, dx
    stosw
    mov ax, bp
    stosw
    jmp .done
.general:
    ; Rotate residual bits with fixed source offsets, then place each
    ; output at its public whole-word rotation index. No lane value indexes RAM.
    mov bl, cl
    xor bh, bh
    shr bx, 1
    shr bx, 1
    shr bx, 1
    and bx, 6
    and cl, 15
    jz .whole_words
    mov ch, 16
    sub ch, cl
    mov ax, [si + 0]
    shl ax, cl
    mov dx, [si + 6]
    xchg cl, ch
    shr dx, cl
    xchg cl, ch
    or ax, dx
    mov [bx + di], ax
    add bx, 2
    and bx, 6
    mov ax, [si + 2]
    shl ax, cl
    mov dx, [si + 0]
    xchg cl, ch
    shr dx, cl
    xchg cl, ch
    or ax, dx
    mov [bx + di], ax
    add bx, 2
    and bx, 6
    mov ax, [si + 4]
    shl ax, cl
    mov dx, [si + 2]
    xchg cl, ch
    shr dx, cl
    xchg cl, ch
    or ax, dx
    mov [bx + di], ax
    add bx, 2
    and bx, 6
    mov ax, [si + 6]
    shl ax, cl
    mov dx, [si + 4]
    xchg cl, ch
    shr dx, cl
    xchg cl, ch
    or ax, dx
    mov [bx + di], ax
    jmp short .done
.whole_words:
    mov ax, [si + 0]
    mov [bx + di], ax
    add bx, 2
    and bx, 6
    mov ax, [si + 2]
    mov [bx + di], ax
    add bx, 2
    and bx, 6
    mov ax, [si + 4]
    mov [bx + di], ax
    add bx, 2
    and bx, 6
    mov ax, [si + 6]
    mov [bx + di], ax
.done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; ---------------------------------------------------------------------------
; ML-KEM q=3329 NTT and Montgomery arithmetic
; ---------------------------------------------------------------------------

fo_fqmul:
    imul bx
    mov [fo_fq_product_lo], ax
    mov [fo_fq_product_hi], dx
    mov bx, -3327
    imul bx
    mov bx, ax
    mov ax, fo_q
    imul bx
    sub [fo_fq_product_lo], ax
    sbb [fo_fq_product_hi], dx
    mov ax, [fo_fq_product_hi]
    ret

fo_barrett_reduce:
    push ax
    mov bx, 20159
    imul bx
    add dx, 0x0200
    mov ax, dx
    sar ax, 1
    sar ax, 1
    sar ax, 1
    sar ax, 1
    sar ax, 1
    sar ax, 1
    sar ax, 1
    sar ax, 1
    sar ax, 1
    sar ax, 1
    mov bx, fo_q
    imul bx
    mov bx, ax
    pop ax
    sub ax, bx
    ret

fo_ntt_poly:
    mov [fo_poly_ptr], si
    mov word [fo_ntt_k], 1
    mov word [fo_ntt_len], 128
.layer:
    mov word [fo_ntt_start], 0
.block:
    mov ax, [fo_ntt_k]
    inc word [fo_ntt_k]
    shl ax, 1
    mov bx, fo_zetas
    add bx, ax
    mov ax, [bx]
    mov [fo_ntt_zeta], ax
    mov ax, [fo_ntt_start]
    shl ax, 1
    add ax, [fo_poly_ptr]
    mov di, ax
    mov ax, [fo_ntt_len]
    shl ax, 1
    mov [fo_ntt_distance], ax
    add ax, di
    mov [fo_ntt_end_ptr], ax
.butterfly:
    mov bp, di
    add bp, [fo_ntt_distance]
    mov ax, [bp]
    mov bx, [fo_ntt_zeta]
    call fo_fqmul
    mov dx, [di]
    mov bx, dx
    sub bx, ax
    mov [bp], bx
    add dx, ax
    mov [di], dx
    add di, 2
    cmp di, [fo_ntt_end_ptr]
    jb .butterfly
    mov ax, [fo_ntt_start]
    mov dx, [fo_ntt_len]
    shl dx, 1
    add ax, dx
    mov [fo_ntt_start], ax
    cmp ax, 256
    jb .block
    shr word [fo_ntt_len], 1
    cmp word [fo_ntt_len], 2
    jae .layer
    ret

fo_invntt_poly:
    mov [fo_poly_ptr], si
    mov word [fo_ntt_k], 127
    mov word [fo_ntt_len], 2
.layer:
    mov word [fo_ntt_start], 0
.block:
    mov ax, [fo_ntt_k]
    dec word [fo_ntt_k]
    shl ax, 1
    mov bx, fo_zetas
    add bx, ax
    mov ax, [bx]
    mov [fo_ntt_zeta], ax
    mov ax, [fo_ntt_start]
    shl ax, 1
    add ax, [fo_poly_ptr]
    mov di, ax
    mov ax, [fo_ntt_len]
    shl ax, 1
    mov [fo_ntt_distance], ax
    add ax, di
    mov [fo_ntt_end_ptr], ax
.butterfly:
    mov bp, di
    add bp, [fo_ntt_distance]
    mov dx, [di]
    mov ax, dx
    add ax, [bp]
    push dx
    call fo_barrett_reduce
    pop dx
    mov [di], ax
    mov ax, [bp]
    sub ax, dx
    mov bx, [fo_ntt_zeta]
    call fo_fqmul
    mov [bp], ax
    add di, 2
    cmp di, [fo_ntt_end_ptr]
    jb .butterfly
    mov ax, [fo_ntt_start]
    mov dx, [fo_ntt_len]
    shl dx, 1
    add ax, dx
    mov [fo_ntt_start], ax
    cmp ax, 256
    jb .block
    shl word [fo_ntt_len], 1
    cmp word [fo_ntt_len], 128
    jbe .layer
    mov di, [fo_poly_ptr]
    mov cx, fo_poly_words
.scale:
    mov ax, [di]
    mov bx, 1441
    call fo_fqmul
    stosw
    loop .scale
    ret

fo_code_end:

; ---------------------------------------------------------------------------
; Immutable tables
; ---------------------------------------------------------------------------

fo_static_start:
fo_y_poly_ptrs dw fo_y0, fo_y1, fo_y2
fo_t_hat_offsets dw 0, 384, 768
fo_u_cipher_offsets dw 0, 320, 640
fo_cbd2_nibbles db 0,1,1,2,-1,0,0,1,-1,0,0,1,-2,-1,-1,0

fo_rot_word_pairs:
    db 0,6, 2,0, 4,2, 6,4
    db 6,4, 0,6, 2,0, 4,2
    db 4,2, 6,4, 0,6, 2,0
    db 2,0, 4,2, 6,4, 0,6

fo_theta_prev db 32,0,8,16,24
fo_theta_next db 8,16,24,32,0
fo_pi_offsets db 0,80,160,40,120,128,8,88,168,48,56,136,16,96,176,184,64,144,24,104,112,192,72,152,32
fo_rho_offsets db 0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14

align 2
fo_round_constants:
    dq 0x0000000000000001, 0x0000000000008082
    dq 0x800000000000808a, 0x8000000080008000
    dq 0x000000000000808b, 0x0000000080000001
    dq 0x8000000080008081, 0x8000000000008009
    dq 0x000000000000008a, 0x0000000000000088
    dq 0x0000000080008009, 0x000000008000000a
    dq 0x000000008000808b, 0x800000000000008b
    dq 0x8000000000008089, 0x8000000000008003
    dq 0x8000000000008002, 0x8000000000000080
    dq 0x000000000000800a, 0x800000008000000a
    dq 0x8000000080008081, 0x8000000000008080
    dq 0x0000000080000001, 0x8000000080008008

fo_zetas:
    dw -1044,-758,-359,-1517,1493,1422,287,202
    dw -171,622,1577,182,962,-1202,-1474,1468
    dw 573,-1325,264,383,-829,1458,-1602,-130
    dw -681,1017,732,608,-1542,411,-205,-1571
    dw 1223,652,-552,1015,-1293,1491,-282,-1544
    dw 516,-8,-320,-666,-1618,-1162,126,1469
    dw -853,-90,-271,830,107,-1421,-247,-951
    dw -398,961,-1508,-725,448,-1065,677,-1275
    dw -1103,430,555,843,-1251,871,1550,105
    dw 422,587,177,-235,-291,-460,1574,1653
    dw -246,778,1159,-147,-777,1483,-602,1119
    dw -1590,644,-872,349,418,329,-156,-75
    dw 817,1097,603,610,1322,-1285,-1465,384
    dw -1215,-136,1218,-1335,-874,220,-1187,-1659
    dw -1185,-1530,-1278,794,-1510,-854,-870,478
    dw -108,-308,996,991,958,-1460,1522,1628
fo_static_end:

align 2
fo_mutable_start:
fo_read_ptr                   dw 0
fo_fq_product_lo              dw 0
fo_fq_product_hi              dw 0
fo_poly_ptr                   dw 0
fo_ntt_k                      dw 0
fo_ntt_len                    dw 0
fo_ntt_start                  dw 0
fo_ntt_zeta                   dw 0
fo_ntt_distance               dw 0
fo_ntt_end_ptr                dw 0
fo_bm_zeta                    dw 0
fo_bm_temp                    dw 0
fo_reencrypt_y_ptr            dw 0
fo_sample_pos                 dw 0
fo_sample_group_index         dw 0
fo_sample_fill                dw 0
fo_sample_d1                  dw 0
fo_sample_d2                  dw 0
fo_sample_offset              dw 0
fo_j_cipher_offset            dw 0
fo_message_bytes_left         dw 0
fo_round_index                dw 0
fo_rot_outputs                dw 0
fo_compress_values            times 4 dw 0
fo_sample_group               times 4 dw 0
fo_reencrypt_row              db 0
fo_reencrypt_col              db 0
fo_sample_row                 db 0
fo_sample_col                 db 0
fo_noise_nonce                db 0
fo_cipher_diff                db 0
fo_compress_low               db 0
fo_reject_mask                db 0
fo_j_blocks_left              db 0
fo_rot_bits                   db 0
fo_rot_inv_bits               db 0
fo_mutable_end:
fo_overlay_end:

%if FO_LOAD_ADDR != poc_k_start
    ; The checker links a second origin to prove internal relocations.
%elif fo_overlay_end > fo_keccak_state
    %error "FO overlay image reaches its K-resident Keccak work"
%endif
%if fo_ticket_hold_len < 300
    %error "FO offline layout preserves less than 300 ticket bytes"
%endif
%if fo_low_work_end > poc_low_scratch_end
    %error "FO low work reaches the resident nucleus"
%endif
%if fo_public_buffer_len < 384
    %error "FO public stream buffer cannot hold one tHat component"
%endif
%if fo_keccak_work_end > fo_poly_acc
    %error "FO Keccak work reaches the accumulator"
%endif
%if fo_poly_acc + fo_poly_bytes > poc_k_end
    %error "FO accumulator crosses K"
%endif
%if fo_message != poc_fo_ciphertext_end
    %error "FO m' input must follow the saved high ciphertext mirror"
%endif
%if fo_z + 32 > poc_attempt_cache_end
    %error "FO persistent candidate inputs reach reconnect state"
%endif
