; Shared only by the isolated integrated ML-KEM spike.  These cpu-8086
; Keccak/NTT/base-multiplication routines are independently checked by the
; companion Python oracle.

; ---------------------------------------------------------------------------
; Keccak-f[1600]
; ---------------------------------------------------------------------------

keccak_f1600:
    mov word [round_index], 0
.round:
    mov si, keccak_state
    mov di, keccak_c
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
    mov al, [theta_next + bx]
    xor ah, ah
    add ax, keccak_c
    mov si, ax
    mov di, lane_tmp
    mov cl, 1
    call rotl64_to
    mov al, [theta_prev + bx]
    xor ah, ah
    add ax, keccak_c
    mov si, ax
    mov di, keccak_d
    mov ax, bx
    mov cl, 3
    shl ax, cl
    add di, ax
    mov cx, 4
.theta_xor:
    mov ax, [si]
    xor ax, [lane_tmp]
    push si
    mov si, lane_tmp
    mov dx, 4
    sub dx, cx
    shl dx, 1
    add si, dx
    xor ax, [si]
    pop si
    xor ax, [lane_tmp]
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
    mov si, keccak_d
    add si, ax
    mov di, keccak_state
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
    mov si, keccak_state
    add si, ax
    mov al, [pi_offsets + bx]
    xor ah, ah
    mov di, keccak_b
    add di, ax
    mov cl, [rho_offsets + bx]
    call rotl64_to
    inc bx
    cmp bx, 25
    jb .rho_pi

    mov bx, keccak_b
    mov bp, keccak_state
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

    mov bx, [round_index]
    mov ax, bx
    mov cl, 3
    shl ax, cl
    mov si, round_constants
    add si, ax
    mov ax, [si]
    xor [keccak_state], ax
    mov ax, [si + 2]
    xor [keccak_state + 2], ax
    mov ax, [si + 4]
    xor [keccak_state + 4], ax
    mov ax, [si + 6]
    xor [keccak_state + 6], ax
    inc word [round_index]
    cmp word [round_index], 24
    jb .round
    ret

; The runtime-root 8088 overlay uses the separately verified FO rotation.
; Other ML-KEM consumers retain their exact existing implementation.
%ifdef MLKEM_KEYGEN_RUNTIME_ROOT
rotl64_to:
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

%else
rotl64_to:
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
    mov [rot_bits], al
    mov dl, 16
    sub dl, al
    mov [rot_inv_bits], dl
    mov al, ah
    shr al, 1
    and ax, 0x0018
    mov bx, rot_word_pairs
    add bx, ax
    cmp byte [rot_bits], 0
    je .whole_words
    mov word [rot_outputs], 4
.mixed:
    mov dl, [bx]
    xor dh, dh
    mov si, dx
    mov ax, [bp + si]
    mov cl, [rot_bits]
    shl ax, cl
    mov dl, [bx + 1]
    xor dh, dh
    mov si, dx
    mov dx, [bp + si]
    mov cl, [rot_inv_bits]
    shr dx, cl
    or ax, dx
    stosw
    add bx, 2
    dec word [rot_outputs]
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

%endif

; ---------------------------------------------------------------------------
; ML-KEM q=3329 NTT and polynomial base multiplication
; ---------------------------------------------------------------------------

fqmul:
    imul bx
    mov [fq_product_lo], ax
    mov [fq_product_hi], dx
    mov bx, -3327
    imul bx
    mov bx, ax
    mov ax, 3329
    imul bx
    sub [fq_product_lo], ax
    sbb [fq_product_hi], dx
    mov ax, [fq_product_hi]
    ret

barrett_reduce:
    mov [barrett_input], ax
    mov bx, 20159
    imul bx
    add dx, 0x0200
    mov ax, dx
    mov cl, 10
    sar ax, cl
    mov bx, 3329
    imul bx
    mov bx, ax
    mov ax, [barrett_input]
    sub ax, bx
    ret

ntt_poly:
    mov [poly_ptr], si
    mov word [ntt_k], 1
    mov word [ntt_len], 128
.layer:
    mov word [ntt_start], 0
.block:
    mov ax, [ntt_k]
    inc word [ntt_k]
    shl ax, 1
    mov bx, zetas
    add bx, ax
    mov ax, [bx]
    mov [ntt_zeta], ax
    mov ax, [ntt_start]
    shl ax, 1
    add ax, [poly_ptr]
    mov di, ax
    mov ax, [ntt_len]
    shl ax, 1
    mov [ntt_distance], ax
    add ax, di
    mov [ntt_end_ptr], ax
.butterfly:
    mov bp, di
    add bp, [ntt_distance]
    mov ax, [bp]
    mov bx, [ntt_zeta]
    call fqmul
    mov cx, ax
    mov dx, [di]
    mov ax, dx
    sub ax, cx
    mov [bp], ax
    add dx, cx
    mov [di], dx
    add di, 2
    cmp di, [ntt_end_ptr]
    jb .butterfly
    mov ax, [ntt_start]
    mov dx, [ntt_len]
    shl dx, 1
    add ax, dx
    mov [ntt_start], ax
    cmp ax, 256
    jb .block
    shr word [ntt_len], 1
    cmp word [ntt_len], 2
    jae .layer
    ret

%ifndef MLKEM_KEYGEN_ONLY
invntt_poly:
    mov [poly_ptr], si
    mov word [ntt_k], 127
    mov word [ntt_len], 2
.layer:
    mov word [ntt_start], 0
.block:
    mov ax, [ntt_k]
    dec word [ntt_k]
    shl ax, 1
    mov bx, zetas
    add bx, ax
    mov ax, [bx]
    mov [ntt_zeta], ax
    mov ax, [ntt_start]
    shl ax, 1
    add ax, [poly_ptr]
    mov di, ax
    mov ax, [ntt_len]
    shl ax, 1
    mov [ntt_distance], ax
    add ax, di
    mov [ntt_end_ptr], ax
.butterfly:
    mov bp, di
    add bp, [ntt_distance]
    mov dx, [di]
    mov ax, dx
    add ax, [bp]
    push dx
    call barrett_reduce
    pop dx
    mov [di], ax
    mov ax, [bp]
    sub ax, dx
    mov bx, [ntt_zeta]
    call fqmul
    mov [bp], ax
    add di, 2
    cmp di, [ntt_end_ptr]
    jb .butterfly
    mov ax, [ntt_start]
    mov dx, [ntt_len]
    shl dx, 1
    add ax, dx
    mov [ntt_start], ax
    cmp ax, 256
    jb .block
    shl word [ntt_len], 1
    cmp word [ntt_len], 128
    jbe .layer
    mov di, [poly_ptr]
    mov cx, poly_words
.scale:
    mov ax, [di]
    mov bx, 1441
    call fqmul
    stosw
    loop .scale
    ret
%endif

; Fixed buffers: poly_s * poly_u -> poly_product.
%ifndef MLKEM_KEYGEN_ONLY
basemul_poly:
    mov word [bm_group], 0
.group:
    mov ax, [bm_group]
    mov bx, ax
    mov cl, 3
    shl ax, cl
    mov si, poly_s
    add si, ax
    mov di, poly_u
    add di, ax
    mov bp, poly_product
    add bp, ax
    mov ax, bx
    add ax, 64
    shl ax, 1
    mov bx, zetas
    add bx, ax
    mov ax, [bx]
    mov [bm_zeta], ax
    call basemul_pair
    add si, 4
    add di, 4
    add bp, 4
    neg word [bm_zeta]
    call basemul_pair
    inc word [bm_group]
    cmp word [bm_group], 64
    jb .group
    ret
%endif

basemul_pair:
    mov [bm_a_ptr], si
    mov [bm_b_ptr], di
    mov [bm_r_ptr], bp
    mov ax, [si + 2]
    mov bx, [di + 2]
    call fqmul
    mov bx, [bm_zeta]
    call fqmul
    mov [bm_temp], ax
    mov si, [bm_a_ptr]
    mov di, [bm_b_ptr]
    mov ax, [si]
    mov bx, [di]
    call fqmul
    add ax, [bm_temp]
    mov bp, [bm_r_ptr]
    mov [bp], ax
    mov si, [bm_a_ptr]
    mov di, [bm_b_ptr]
    mov ax, [si]
    mov bx, [di + 2]
    call fqmul
    mov [bm_temp], ax
    mov ax, [si + 2]
    mov bx, [di]
    call fqmul
    add ax, [bm_temp]
    mov bp, [bm_r_ptr]
    mov [bp + 2], ax
    ret

; ---------------------------------------------------------------------------
; Immutable permutation/NTT constants
; ---------------------------------------------------------------------------

rot_word_pairs:
    db 0,6, 2,0, 4,2, 6,4
    db 6,4, 0,6, 2,0, 4,2
    db 4,2, 6,4, 0,6, 2,0
    db 2,0, 4,2, 6,4, 0,6

theta_prev db 32,0,8,16,24
theta_next db 8,16,24,32,0
pi_offsets db 0,80,160,40,120,128,8,88,168,48,56,136,16,96,176,184,64,144,24,104,112,192,72,152,32
rho_offsets db 0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14

align 2
round_constants:
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

zetas:
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
