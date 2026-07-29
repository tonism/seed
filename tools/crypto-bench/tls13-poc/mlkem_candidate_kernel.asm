; Product-shaped provisional ML-KEM-768 candidate overlay for an 8088.
;
; Contract (all segments zero, DF clear on return):
;
;   input, read-only
;     08c0..0d00  raw c[1088]
;     3600..3780  compressed sHat[0]
;     3780..37a0  H(ek)
;     37a0..37c0  z
;     3800..3980  compressed sHat[1]
;     3980..3b00  compressed sHat[2]
;
;   output
;     3a40..3a60  m'[32]
;     3b9c..3bdc  G(m' || H(ek))[64] = K' || r'
;     3bdc..3bfc  preserved z[32]
;
;   work
;     final two logical K sectors: decoded/decompressed u, then v; followed
;     by the running base-multiplication accumulator
;     3600..37e8  disposable Keccak work, but only after all sHat inputs die
;
; The source can be linked at another paragraph-aligned address by defining
; MLKEM_LOAD_ADDR.  Product builds use K=0x1800.  All phase inputs, outputs,
; and large work buffers stay at the fixed addresses in layout.inc.

bits 16
cpu 8086

%ifndef MLKEM_LOAD_ADDR
    %define MLKEM_LOAD_ADDR 0x1800
%endif

org MLKEM_LOAD_ADDR

%include "layout.inc"

mlkem_poly_words             equ 256
mlkem_poly_bytes             equ 512
mlkem_state_bytes            equ 200

mlkem_raw_c                  equ poc_mlkem_ciphertext
mlkem_poly_u                 equ poc_poly_u
mlkem_poly_acc               equ poc_poly_acc
mlkem_message                equ poc_tls_vault_start
mlkem_candidate_g            equ poc_candidate_g
mlkem_candidate_z            equ poc_candidate_z

; These buffers reuse dead KeyGen secret storage only after the third component
; has been multiplied into mlkem_poly_acc.  They are disposable when the
; scheduler copies raw c to poc_fo_ciphertext after this routine returns.
mlkem_keccak_state           equ poc_high_start
mlkem_keccak_b               equ mlkem_keccak_state + 200
mlkem_keccak_c               equ mlkem_keccak_b + 200
mlkem_keccak_d               equ mlkem_keccak_c + 40
mlkem_lane_tmp               equ mlkem_keccak_d + 40
mlkem_keccak_work_end        equ mlkem_lane_tmp + 8

mlkem_overlay_start:

; K-PKE.Decrypt(dkPKE, c), followed by G(m' || H(ek)).
;
; Entry: DS=ES=SS=0, interrupts/stack supplied by the caller.
; Exit:  AX=mlkem_candidate_g.  AX/BX/CX/DX/SI/DI/BP and flags are clobbered.
;        The routine executes CLD and returns with DF clear.
mlkem_candidate_entry:
    cld

    ; sHat[0] expansion later destroys H(ek) and z.  Preserve both first.
    mov si, poc_h_ek
    mov di, mlkem_candidate_g
    mov cx, poc_h_ek_len / 2
    rep movsw
    mov si, poc_z
    mov di, mlkem_candidate_z
    mov cx, poc_z_len / 2
    rep movsw

    mov di, mlkem_poly_acc
    xor ax, ax
    mov cx, mlkem_poly_words
    rep stosw

    ; Expand backwards so each 384-byte sHat component can become a 512-byte
    ; polynomial in place.  Consume components from high to low so an expanded
    ; component can overlap only inputs that are already dead.
    mov si, poc_s_hat2
    call mlkem_decode_poly12_reverse
    mov si, mlkem_raw_c + 640
    call mlkem_decode_poly10
    mov si, poc_s_hat2
    call mlkem_candidate_component

    mov si, poc_s_hat1
    call mlkem_decode_poly12_reverse
    mov si, mlkem_raw_c + 320
    call mlkem_decode_poly10
    mov si, poc_s_hat1
    call mlkem_candidate_component

    mov si, poc_s_hat0
    call mlkem_decode_poly12_reverse
    mov si, mlkem_raw_c
    call mlkem_decode_poly10
    mov si, poc_s_hat0
    call mlkem_candidate_component

    call mlkem_reduce_and_inv_acc

    ; u is dead.  Reuse its sector for Decompress_4(v), then retain m' in the
    ; post-candidate TLS vault so the full FO tail need not decrypt again.
    mov si, mlkem_raw_c + 960
    call mlkem_decode_poly4
    call mlkem_decrypt_message
    call mlkem_sha3_512_message_h
    mov ax, mlkem_candidate_g
    ret

; Decode one 384-byte ByteEncode_12 polynomial in place.
;
; For group i, the unread source is at base..base+3i+2 while the destination
; starts at base+4i.  Walking i=127..0 therefore cannot overwrite unread input.
mlkem_decode_poly12_reverse:
    add si, 381
    mov di, si
    add di, 127
    mov cx, 128
.pair:
    ; Load both encoded words before either store.  In the final low groups,
    ; the expanded destination overlaps bytes in the group being decoded.
    mov dx, [si]
    and dx, 0x0fff
    mov ax, [si + 1]
    shr ax, 1
    shr ax, 1
    shr ax, 1
    shr ax, 1
    mov [di], dx
    mov [di + 2], ax
    sub si, 3
    sub di, 4
    loop .pair
    ret

; Decode one 320-byte ByteEncode_10 polynomial and Decompress_10 to poly_u.
mlkem_decode_poly10:
    mov di, mlkem_poly_u
    mov word [mlkem_decode_groups], 64
.group:
    lodsb
    mov [mlkem_decode_b0], al
    lodsb
    mov [mlkem_decode_b1], al
    lodsb
    mov [mlkem_decode_b2], al
    lodsb
    mov [mlkem_decode_b3], al
    lodsb
    mov [mlkem_decode_b4], al

    xor ax, ax
    mov al, [mlkem_decode_b1]
    and ax, 3
    mov cl, 8
    shl ax, cl
    xor bx, bx
    mov bl, [mlkem_decode_b0]
    or ax, bx
    call mlkem_decompress10
    stosw

    xor ax, ax
    mov al, [mlkem_decode_b1]
    mov cl, 2
    shr ax, cl
    xor bx, bx
    mov bl, [mlkem_decode_b2]
    and bx, 15
    mov cl, 6
    shl bx, cl
    or ax, bx
    call mlkem_decompress10
    stosw

    xor ax, ax
    mov al, [mlkem_decode_b2]
    mov cl, 4
    shr ax, cl
    xor bx, bx
    mov bl, [mlkem_decode_b3]
    and bx, 63
    shl bx, cl
    or ax, bx
    call mlkem_decompress10
    stosw

    xor ax, ax
    mov al, [mlkem_decode_b3]
    mov cl, 6
    shr ax, cl
    xor bx, bx
    mov bl, [mlkem_decode_b4]
    mov cl, 2
    shl bx, cl
    or ax, bx
    call mlkem_decompress10
    stosw

    dec word [mlkem_decode_groups]
    jnz .group
    ret

; Decode one 128-byte ByteEncode_4 polynomial and Decompress_4 to poly_u.
mlkem_decode_poly4:
    mov di, mlkem_poly_u
    mov cx, 128
.pair:
    lodsb
    mov dl, al
    and ax, 0x000f
    call mlkem_decompress4
    stosw
    xor ax, ax
    mov al, dl
    shr ax, 1
    shr ax, 1
    shr ax, 1
    shr ax, 1
    call mlkem_decompress4
    stosw
    loop .pair
    ret

; AX in [0,1023] -> round(q*AX/2^10), exact FIPS Decompress_10.
mlkem_decompress10:
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
mlkem_decompress4:
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

; NTT(u), then add sHat (*) u directly into the running accumulator.
; No poly_product object exists.
mlkem_candidate_component:
    push si
    mov si, mlkem_poly_u
    call mlkem_ntt_poly
    pop si
    mov di, mlkem_poly_u
    mov bp, mlkem_poly_acc
    mov word [mlkem_bm_zeta_ptr], mlkem_zetas + (64 * 2)
    mov cx, 64
.group:
    mov bx, [mlkem_bm_zeta_ptr]
    mov ax, [bx]
    mov [mlkem_bm_zeta], ax
    add word [mlkem_bm_zeta_ptr], 2
    call mlkem_basemul_pair_acc
    add si, 4
    add di, 4
    add bp, 4
    neg word [mlkem_bm_zeta]
    call mlkem_basemul_pair_acc
    add si, 4
    add di, 4
    add bp, 4
    loop .group
    ret

; BaseMultiply one coefficient pair and add both words directly to [BP].
mlkem_basemul_pair_acc:
    mov ax, [si + 2]
    mov bx, [di + 2]
    call mlkem_fqmul
    mov bx, [mlkem_bm_zeta]
    call mlkem_fqmul
    mov [mlkem_bm_temp], ax
    mov ax, [si]
    mov bx, [di]
    call mlkem_fqmul
    add ax, [mlkem_bm_temp]
    add [bp], ax

    mov ax, [si]
    mov bx, [di + 2]
    call mlkem_fqmul
    mov [mlkem_bm_temp], ax
    mov ax, [si + 2]
    mov bx, [di]
    call mlkem_fqmul
    add ax, [mlkem_bm_temp]
    add [bp + 2], ax
    ret

mlkem_reduce_and_inv_acc:
    mov si, mlkem_poly_acc
    mov di, mlkem_poly_acc
    mov cx, mlkem_poly_words
.reduce:
    lodsw
    push cx
    call mlkem_barrett_reduce
    pop cx
    stosw
    loop .reduce
    mov si, mlkem_poly_acc
    call mlkem_invntt_poly
    ret

; Compress_1(v - inner product), ByteEncode_1, little-endian bit order.
mlkem_decrypt_message:
    mov si, mlkem_poly_u
    mov di, mlkem_poly_acc
    mov bp, mlkem_message
    mov word [mlkem_message_bytes_left], 32
.byte:
    mov byte [mlkem_message_byte], 0
    mov byte [mlkem_message_mask], 1
    mov word [mlkem_message_bits_left], 8
.bit:
    lodsw
    sub ax, [di]
    add di, 2
    call mlkem_barrett_reduce
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
    mov al, [mlkem_message_mask]
    or [mlkem_message_byte], al
.zero:
    shl byte [mlkem_message_mask], 1
    dec word [mlkem_message_bits_left]
    jnz .bit
    mov al, [mlkem_message_byte]
    mov [bp], al
    inc bp
    dec word [mlkem_message_bytes_left]
    jnz .byte
    ret

mlkem_sha3_512_message_h:
    mov di, mlkem_keccak_state
    xor ax, ax
    mov cx, mlkem_state_bytes / 2
    rep stosw
    mov si, mlkem_message
    mov di, mlkem_keccak_state
    mov cx, 32
    rep movsb
    mov si, mlkem_candidate_g
    mov cx, 32
    rep movsb
    mov byte [mlkem_keccak_state + 64], 0x06
    mov byte [mlkem_keccak_state + 71], 0x80
    call mlkem_keccak_f1600
    mov si, mlkem_keccak_state
    mov di, mlkem_candidate_g
    mov cx, 64
    rep movsb
    ret

; ---------------------------------------------------------------------------
; Keccak-f[1600]
; ---------------------------------------------------------------------------

mlkem_keccak_f1600:
    mov word [mlkem_round_index], 0
.round:
    mov si, mlkem_keccak_state
    mov di, mlkem_keccak_c
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
    mov al, [mlkem_theta_next + bx]
    xor ah, ah
    add ax, mlkem_keccak_c
    mov si, ax
    mov di, mlkem_lane_tmp
    mov cl, 1
    call mlkem_rotl64_to
    mov al, [mlkem_theta_prev + bx]
    xor ah, ah
    add ax, mlkem_keccak_c
    mov si, ax
    mov di, mlkem_keccak_d
    mov ax, bx
    mov cl, 3
    shl ax, cl
    add di, ax
    mov cx, 4
.theta_xor:
    mov ax, [si]
    xor ax, [mlkem_lane_tmp]
    push si
    mov si, mlkem_lane_tmp
    mov dx, 4
    sub dx, cx
    shl dx, 1
    add si, dx
    xor ax, [si]
    pop si
    xor ax, [mlkem_lane_tmp]
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
    mov si, mlkem_keccak_d
    add si, ax
    mov di, mlkem_keccak_state
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
    mov si, mlkem_keccak_state
    add si, ax
    mov al, [mlkem_pi_offsets + bx]
    xor ah, ah
    mov di, mlkem_keccak_b
    add di, ax
    mov cl, [mlkem_rho_offsets + bx]
    call mlkem_rotl64_to
    inc bx
    cmp bx, 25
    jb .rho_pi

    mov bx, mlkem_keccak_b
    mov bp, mlkem_keccak_state
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

    mov bx, [mlkem_round_index]
    mov ax, bx
    mov cl, 3
    shl ax, cl
    mov si, mlkem_round_constants
    add si, ax
    mov ax, [si]
    xor [mlkem_keccak_state], ax
    mov ax, [si + 2]
    xor [mlkem_keccak_state + 2], ax
    mov ax, [si + 4]
    xor [mlkem_keccak_state + 4], ax
    mov ax, [si + 6]
    xor [mlkem_keccak_state + 6], ax
    inc word [mlkem_round_index]
    cmp word [mlkem_round_index], 24
    jb .round
    ret

mlkem_rotl64_to:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    mov bp, si
    mov al, cl
    mov ah, al
    and al, 15
    mov [mlkem_rot_bits], al
    mov dl, 16
    sub dl, al
    mov [mlkem_rot_inv_bits], dl
    mov al, ah
    shr al, 1
    and ax, 0x0018
    mov bx, mlkem_rot_word_pairs
    add bx, ax
    cmp byte [mlkem_rot_bits], 0
    je .whole_words
    mov word [mlkem_rot_outputs], 4
.mixed:
    mov dl, [bx]
    xor dh, dh
    mov si, dx
    mov ax, [bp + si]
    mov cl, [mlkem_rot_bits]
    shl ax, cl
    mov dl, [bx + 1]
    xor dh, dh
    mov si, dx
    mov dx, [bp + si]
    mov cl, [mlkem_rot_inv_bits]
    shr dx, cl
    or ax, dx
    stosw
    add bx, 2
    dec word [mlkem_rot_outputs]
    jnz .mixed
    jmp short .done
.whole_words:
    mov cx, 4
.whole:
    mov dl, [bx]
    xor dh, dh
    mov si, dx
    mov ax, [bp + si]
    stosw
    add bx, 2
    loop .whole
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
; ML-KEM q=3329 NTT and Montgomery base multiplication
; ---------------------------------------------------------------------------

mlkem_fqmul:
    imul bx
    mov [mlkem_fq_product_lo], ax
    mov [mlkem_fq_product_hi], dx
    mov bx, -3327
    imul bx
    mov bx, ax
    mov ax, 3329
    imul bx
    sub [mlkem_fq_product_lo], ax
    sbb [mlkem_fq_product_hi], dx
    mov ax, [mlkem_fq_product_hi]
    ret

mlkem_barrett_reduce:
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
    mov bx, 3329
    imul bx
    mov bx, ax
    pop ax
    sub ax, bx
    ret

mlkem_ntt_poly:
    mov [mlkem_poly_ptr], si
    mov word [mlkem_ntt_k], 1
    mov word [mlkem_ntt_len], 128
.layer:
    mov word [mlkem_ntt_start], 0
.block:
    mov ax, [mlkem_ntt_k]
    inc word [mlkem_ntt_k]
    shl ax, 1
    mov bx, mlkem_zetas
    add bx, ax
    mov ax, [bx]
    mov [mlkem_ntt_zeta], ax
    mov ax, [mlkem_ntt_start]
    shl ax, 1
    add ax, [mlkem_poly_ptr]
    mov di, ax
    mov ax, [mlkem_ntt_len]
    shl ax, 1
    mov [mlkem_ntt_distance], ax
    add ax, di
    mov [mlkem_ntt_end_ptr], ax
.butterfly:
    mov bp, di
    add bp, [mlkem_ntt_distance]
    mov ax, [bp]
    mov bx, [mlkem_ntt_zeta]
    call mlkem_fqmul
    mov dx, [di]
    mov bx, dx
    sub bx, ax
    mov [bp], bx
    add dx, ax
    mov [di], dx
    add di, 2
    cmp di, [mlkem_ntt_end_ptr]
    jb .butterfly
    mov ax, [mlkem_ntt_start]
    mov dx, [mlkem_ntt_len]
    shl dx, 1
    add ax, dx
    mov [mlkem_ntt_start], ax
    cmp ax, 256
    jb .block
    shr word [mlkem_ntt_len], 1
    cmp word [mlkem_ntt_len], 2
    jae .layer
    ret

mlkem_invntt_poly:
    mov [mlkem_poly_ptr], si
    mov word [mlkem_ntt_k], 127
    mov word [mlkem_ntt_len], 2
.layer:
    mov word [mlkem_ntt_start], 0
.block:
    mov ax, [mlkem_ntt_k]
    dec word [mlkem_ntt_k]
    shl ax, 1
    mov bx, mlkem_zetas
    add bx, ax
    mov ax, [bx]
    mov [mlkem_ntt_zeta], ax
    mov ax, [mlkem_ntt_start]
    shl ax, 1
    add ax, [mlkem_poly_ptr]
    mov di, ax
    mov ax, [mlkem_ntt_len]
    shl ax, 1
    mov [mlkem_ntt_distance], ax
    add ax, di
    mov [mlkem_ntt_end_ptr], ax
.butterfly:
    mov bp, di
    add bp, [mlkem_ntt_distance]
    mov dx, [di]
    mov ax, dx
    add ax, [bp]
    push dx
    call mlkem_barrett_reduce
    pop dx
    mov [di], ax
    mov ax, [bp]
    sub ax, dx
    mov bx, [mlkem_ntt_zeta]
    call mlkem_fqmul
    mov [bp], ax
    add di, 2
    cmp di, [mlkem_ntt_end_ptr]
    jb .butterfly
    mov ax, [mlkem_ntt_start]
    mov dx, [mlkem_ntt_len]
    shl dx, 1
    add ax, dx
    mov [mlkem_ntt_start], ax
    cmp ax, 256
    jb .block
    shl word [mlkem_ntt_len], 1
    cmp word [mlkem_ntt_len], 128
    jbe .layer
    mov di, [mlkem_poly_ptr]
    mov cx, mlkem_poly_words
.scale:
    mov ax, [di]
    mov bx, 1441
    call mlkem_fqmul
    stosw
    loop .scale
    ret

mlkem_code_end:

; ---------------------------------------------------------------------------
; Immutable permutation/NTT tables
; ---------------------------------------------------------------------------

mlkem_static_start:
mlkem_rot_word_pairs:
    db 0,6, 2,0, 4,2, 6,4
    db 6,4, 0,6, 2,0, 4,2
    db 4,2, 6,4, 0,6, 2,0
    db 2,0, 4,2, 6,4, 0,6

mlkem_theta_prev db 32,0,8,16,24
mlkem_theta_next db 8,16,24,32,0
mlkem_pi_offsets db 0,80,160,40,120,128,8,88,168,48,56,136,16,96,176,184,64,144,24,104,112,192,72,152,32
mlkem_rho_offsets db 0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14

align 2
mlkem_round_constants:
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

mlkem_zetas:
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
mlkem_static_end:

; Small scalar state is deliberately part of the overlay image.  The two
; 512-byte polynomial buffers and all Keccak storage remain externally fixed.
align 2
mlkem_mutable_start:
mlkem_fq_product_lo          dw 0
mlkem_fq_product_hi          dw 0
mlkem_poly_ptr               dw 0
mlkem_ntt_k                  dw 0
mlkem_ntt_len                dw 0
mlkem_ntt_start              dw 0
mlkem_ntt_zeta               dw 0
mlkem_ntt_distance           dw 0
mlkem_ntt_end_ptr            dw 0
mlkem_bm_zeta                dw 0
mlkem_bm_zeta_ptr            dw 0
mlkem_bm_temp                dw 0
mlkem_decode_groups          dw 0
mlkem_decode_b0              db 0
mlkem_decode_b1              db 0
mlkem_decode_b2              db 0
mlkem_decode_b3              db 0
mlkem_decode_b4              db 0
mlkem_message_bytes_left     dw 0
mlkem_message_bits_left      dw 0
mlkem_message_byte           db 0
mlkem_message_mask           db 0
mlkem_round_index            dw 0
mlkem_rot_outputs            dw 0
mlkem_rot_bits               db 0
mlkem_rot_inv_bits           db 0
mlkem_mutable_end:
mlkem_overlay_end:

%if MLKEM_LOAD_ADDR != poc_k_start
    ; Alternate origins are allowed by the checker to prove link relocation.
%elif mlkem_overlay_end > poc_timed_code_end_max
    %error "ML-KEM candidate overlay reaches the final 1024-byte K work area"
%endif
%if mlkem_poly_u + mlkem_poly_bytes != mlkem_poly_acc
    %error "ML-KEM u and accumulator work sectors are not adjacent"
%endif
%if mlkem_poly_acc + mlkem_poly_bytes != poc_k_end
    %error "ML-KEM accumulator does not end at the K boundary"
%endif
%if poc_s_hat2 + mlkem_poly_bytes > poc_high_end
    %error "reverse in-place sHat2 expansion reaches deferred state"
%endif
%if mlkem_keccak_work_end > poc_s_hat1
    %error "candidate Keccak work exceeds the dead low secret bands"
%endif
%if mlkem_message != poc_fo_ciphertext_end
    %error "m' must begin exactly after the post-candidate ciphertext copy"
%endif
%if mlkem_message + 32 > poc_high_end
    %error "m' output reaches deferred state"
%endif
%if mlkem_candidate_z + 32 > poc_attempt_cache_end
    %error "candidate G/z output reaches reconnect state"
%endif
