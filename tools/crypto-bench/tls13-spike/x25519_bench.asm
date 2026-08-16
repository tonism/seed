; Standalone X25519 server-share benchmark for Seed's 8088 TLS 1.3 spike.
;
; This is deliberately isolated from the product runtime.  It separately
; measures the pre-TCP base-point operation and the server-dependent operation
; that begins after ServerHello:
;
;     XKEYGEN = X25519(clamped_client_scalar, 9)
;     X25519  = X25519(clamped_client_scalar, server_u)
;
; Scalar generation/clamping and peer-u decoding are outside their operation
; timers.  Each timed body includes the 255-step Montgomery ladder, inversion,
; and final multiply.
;
; The inputs and expected outputs are the RFC 7748 Alice key-pair and Alice/Bob
; shared-secret vectors.  DONE is emitted only after both 32-byte results
; compare equal, making run_8088.py's normal done-token check a correctness
; gate.

bits 16
cpu 8086
org 0x1000

fe_words equ 16
fe_bytes equ 32

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

    ; Prepare the private scalar once.  Its base-point multiplication produces
    ; the ClientHello key share and can run entirely before TCP.
    mov si, rfc_scalar
    mov di, scalar_work
    mov cx, fe_words
    rep movsw
    and byte [scalar_work], 248
    and byte [scalar_work + 31], 127
    or byte [scalar_work + 31], 64

    mov di, fe_x1
    call fe_zero
    mov word [fe_x1], 9
    mov si, tag_keygen
    mov di, rfc_public
    mov bp, tag_checkkg
    call run_x25519_case
    jc .failed

    ; Server-dependent phase: decode the peer u-coordinate and perform the
    ; second scalar multiplication after ServerHello.
    mov si, rfc_peer_u
    mov di, fe_x1
    mov cx, fe_words
    rep movsw
    and word [fe_x1 + 30], 0x7fff

    mov si, tag_x25519
    mov di, rfc_expected
    mov bp, tag_checkss
    call run_x25519_case
    jc .failed

    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

.failed:
    mov si, tag_fail
    call emit_str
    call emit_crlf
    jmp .hang

; SI=operation tag, DI=expected 32 bytes, BP=check tag.  Carry is set on a
; mismatch.  Start on a BIOS tick edge to make a one-operation result stable.
run_x25519_case:
    mov [case_expected_ptr], di
    mov [case_check_tag], bp
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

    call x25519_shared

    call read_tick
    sub ax, [t0_lo]
    sbb dx, [t0_hi]
    mov [dt_lo], ax

    mov si, str_N
    call emit_str
    mov ax, 1
    call emit_dec16
    mov si, str_dt
    call emit_str
    mov ax, [dt_lo]
    call emit_dec16

    xor ax, ax
    mov si, x25519_output
    mov cx, fe_words
.checksum:
    add ax, [si]
    add si, 2
    loop .checksum
    push ax
    mov si, str_ck
    call emit_str
    pop ax
    call emit_hex16
    call emit_crlf

    mov si, x25519_output
    mov di, [case_expected_ptr]
    mov cx, fe_bytes
    repe cmpsb
    mov ax, 0
    jne .checked
    inc ax
.checked:
    push ax
    mov si, [case_check_tag]
    call emit_str
    mov si, str_validation
    call emit_str
    pop ax
    push ax
    call emit_hex16
    call emit_crlf
    pop ax
    or ax, ax
    jz .bad
    clc
    ret
.bad:
    stc
    ret

; ---------------------------------------------------------------------------
; X25519 Montgomery ladder
; ---------------------------------------------------------------------------

x25519_shared:
    mov di, fe_x2
    call fe_one
    mov di, fe_z2
    call fe_zero
    mov si, fe_x1
    mov di, fe_x3
    call fe_copy
    mov di, fe_z3
    call fe_one

    mov word [ladder_scalar_ptr], scalar_work + 31
    mov byte [ladder_scalar_mask], 0x40
    mov word [ladder_count], 255
    mov word [ladder_swap], 0

.bit_loop:
    mov si, [ladder_scalar_ptr]
    xor ax, ax
    mov al, [si]
    and al, [ladder_scalar_mask]
    neg ax
    sbb ax, ax
    and ax, 1
    mov [ladder_bit], ax

    xor ax, [ladder_swap]
    mov si, fe_x2
    mov di, fe_x3
    call fe_cswap
    mov ax, [ladder_bit]
    xor ax, [ladder_swap]
    mov si, fe_z2
    mov di, fe_z3
    call fe_cswap
    mov ax, [ladder_bit]
    mov [ladder_swap], ax

    ; A = x2 + z2; AA = A^2
    mov si, fe_x2
    mov di, fe_z2
    mov bx, fe_a
    call fe_add
    mov si, fe_a
    mov bx, fe_aa
    call fe_sq

    ; B = x2 - z2; BB = B^2; E = AA - BB
    mov si, fe_x2
    mov di, fe_z2
    mov bx, fe_b
    call fe_sub
    mov si, fe_b
    mov bx, fe_bb
    call fe_sq
    mov si, fe_aa
    mov di, fe_bb
    mov bx, fe_e
    call fe_sub

    ; C = x3 + z3; D = x3 - z3
    mov si, fe_x3
    mov di, fe_z3
    mov bx, fe_c
    call fe_add
    mov si, fe_x3
    mov di, fe_z3
    mov bx, fe_d
    call fe_sub

    ; DA = D*A; CB = C*B
    mov si, fe_d
    mov di, fe_a
    mov bx, fe_da
    call fe_mul
    mov si, fe_c
    mov di, fe_b
    mov bx, fe_cb
    call fe_mul

    ; x3 = (DA + CB)^2
    mov si, fe_da
    mov di, fe_cb
    mov bx, fe_tmp
    call fe_add
    mov si, fe_tmp
    mov bx, fe_x3
    call fe_sq

    ; z3 = x1 * (DA - CB)^2
    mov si, fe_da
    mov di, fe_cb
    mov bx, fe_tmp
    call fe_sub
    mov si, fe_tmp
    mov bx, fe_t0
    call fe_sq
    mov si, fe_x1
    mov di, fe_t0
    mov bx, fe_z3
    call fe_mul

    ; x2 = AA*BB
    mov si, fe_aa
    mov di, fe_bb
    mov bx, fe_x2
    call fe_mul

    ; z2 = E * (AA + 121665*E)
    mov si, fe_e
    mov bx, fe_tmp
    call fe_mul_a24
    mov si, fe_aa
    mov di, fe_tmp
    mov bx, fe_tmp
    call fe_add
    mov si, fe_e
    mov di, fe_tmp
    mov bx, fe_z2
    call fe_mul

    shr byte [ladder_scalar_mask], 1
    jnz .mask_ready
    mov byte [ladder_scalar_mask], 0x80
    dec word [ladder_scalar_ptr]
.mask_ready:
    dec word [ladder_count]
    jnz .bit_loop

    mov ax, [ladder_swap]
    mov si, fe_x2
    mov di, fe_x3
    call fe_cswap
    mov ax, [ladder_swap]
    mov si, fe_z2
    mov di, fe_z3
    call fe_cswap

    mov si, fe_z2
    mov bx, fe_inv
    call fe_invert
    mov si, fe_x2
    mov di, fe_inv
    mov bx, x25519_output
    call fe_mul
    ret

; Constant-time conditional swap of two field elements.
; AX=0/1, SI/DI=field elements.
fe_cswap:
    push ax
    push bx
    push cx
    push dx
    neg ax
    mov dx, ax
    mov cx, fe_words
.loop:
    mov ax, [si]
    mov bx, [di]
    xor ax, bx
    and ax, dx
    xor [si], ax
    xor [di], ax
    add si, 2
    add di, 2
    loop .loop
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; ---------------------------------------------------------------------------
; Field arithmetic modulo 2^255 - 19, in 16 little-endian 16-bit words.
; Every public operation returns a canonical representative.
; ---------------------------------------------------------------------------

fe_zero:
    push ax
    push cx
    xor ax, ax
    mov cx, fe_words
    rep stosw
    pop cx
    pop ax
    ret

fe_one:
    call fe_zero
    mov word [di - fe_bytes], 1
    ret

fe_copy:
    push cx
    mov cx, fe_words
    rep movsw
    pop cx
    ret

; SI=a, DI=b, BX=out.
fe_add:
    push bx
    push cx
    push dx
    mov dx, bx
    mov cx, fe_words
    clc
.loop:
    mov ax, [si]
    adc ax, [di]
    mov [bx], ax
    lea si, [si + 2]
    lea di, [di + 2]
    lea bx, [bx + 2]
    loop .loop
    mov ax, 0
    adc ax, 0
    mov bx, dx
    call fe_fold_256
    call fe_fold_top
    call fe_canonical
    pop dx
    pop cx
    pop bx
    ret

; SI=a, DI=b, BX=out.
fe_sub:
    push bx
    push cx
    push dx
    mov dx, bx
    mov cx, fe_words
    clc
.loop:
    mov ax, [si]
    sbb ax, [di]
    mov [bx], ax
    lea si, [si + 2]
    lea di, [di + 2]
    lea bx, [bx + 2]
    loop .loop
    jnc .done
    mov bx, dx
    mov si, fe_prime
    mov cx, fe_words
    clc
.add_prime:
    mov ax, [si]
    adc [bx], ax
    lea si, [si + 2]
    lea bx, [bx + 2]
    loop .add_prime
.done:
    pop dx
    pop cx
    pop bx
    ret

; SI=a, BX=out.  Symmetric 16-word Comba square: diagonal products are added
; once and off-diagonal products twice.  This performs 136 MULs instead of the
; general multiplier's 256 while retaining the same reduction.
fe_sq:
    mov [fm_left_ptr], si
    mov [fm_out_ptr], bx

    mov di, fe_product
    xor ax, ax
    mov cx, 34
    rep stosw

    mov word [fm_carry0], 0
    mov word [fm_carry1], 0
    mov word [fm_k], 0
    mov word [fm_product_ptr], fe_product

.column:
    ; start=max(0,k-15), end=floor(k/2), j=k-start.
    mov ax, [fm_k]
    mov bx, ax
    mov cl, 1
    shr bx, cl
    xor dx, dx
    cmp ax, 15
    jbe .range_ready
    mov dx, ax
    sub dx, 15
.range_ready:
    mov cx, bx
    sub cx, dx
    inc cx

    mov si, [fm_left_ptr]
    mov bx, dx
    shl bx, 1
    add si, bx

    sub ax, dx
    shl ax, 1
    mov di, [fm_left_ptr]
    add di, ax

    mov bx, [fm_carry0]
    mov bp, [fm_carry1]
    mov word [fm_acc2], 0

.term:
    mov ax, [si]
    mul word [di]
    cmp si, di
    je .accumulate
    shl ax, 1
    rcl dx, 1
    adc word [fm_acc2], 0
.accumulate:
    add bx, ax
    adc bp, dx
    adc word [fm_acc2], 0
    add si, 2
    sub di, 2
    loop .term

    mov di, [fm_product_ptr]
    mov [di], bx
    add word [fm_product_ptr], 2
    mov [fm_carry0], bp
    mov ax, [fm_acc2]
    mov [fm_carry1], ax

    inc word [fm_k]
    cmp word [fm_k], 31
    jb .column

    mov di, [fm_product_ptr]
    mov ax, [fm_carry0]
    mov [di], ax
    mov ax, [fm_carry1]
    mov [di + 2], ax

    mov bx, [fm_out_ptr]
    call fe_reduce_product
    ret

; SI=a, DI=b, BX=out.  Exact 16x16-word Comba product followed by the special
; reduction 2^256 == 38 (mod 2^255-19).
fe_mul:
    mov [fm_left_ptr], si
    mov [fm_right_ptr], di
    mov [fm_out_ptr], bx

    mov di, fe_product
    xor ax, ax
    mov cx, 34
    rep stosw

    mov word [fm_carry0], 0
    mov word [fm_carry1], 0
    mov word [fm_k], 0
    mov word [fm_product_ptr], fe_product

.column:
    mov ax, [fm_k]
    cmp ax, 15
    ja .high_column

    mov si, [fm_left_ptr]
    mov di, [fm_right_ptr]
    mov bx, ax
    shl bx, 1
    add di, bx
    inc ax
    mov cx, ax
    jmp short .column_ready

.high_column:
    mov bx, ax
    sub bx, 15
    shl bx, 1
    mov si, [fm_left_ptr]
    add si, bx
    mov di, [fm_right_ptr]
    add di, 30
    mov cx, 31
    sub cx, ax

.column_ready:
    mov bx, [fm_carry0]
    mov bp, [fm_carry1]
    mov word [fm_acc2], 0

.term:
    mov ax, [si]
    mul word [di]
    add bx, ax
    adc bp, dx
    adc word [fm_acc2], 0
    add si, 2
    sub di, 2
    loop .term

    mov di, [fm_product_ptr]
    mov [di], bx
    add word [fm_product_ptr], 2
    mov [fm_carry0], bp
    mov ax, [fm_acc2]
    mov [fm_carry1], ax

    inc word [fm_k]
    cmp word [fm_k], 31
    jb .column

    mov di, [fm_product_ptr]
    mov ax, [fm_carry0]
    mov [di], ax
    mov ax, [fm_carry1]
    mov [di + 2], ax

    mov bx, [fm_out_ptr]
    call fe_reduce_product
    ret

; SI=a, BX=out.  121665 = 0x1db41, so compute a*0xdb41 plus a<<16.
; Only 16 MULs are needed instead of a full field multiplication.
fe_mul_a24:
    mov [fm_out_ptr], bx
    mov [fm_left_ptr], si
    mov di, fe_product
    xor ax, ax
    mov cx, 34
    rep stosw

    mov si, [fm_left_ptr]
    mov di, fe_product
    xor bp, bp
    mov cx, fe_words
.low_product:
    mov ax, [si]
    mov bx, 0xdb41
    mul bx
    add ax, bp
    adc dx, 0
    mov [di], ax
    mov bp, dx
    add si, 2
    add di, 2
    loop .low_product
    mov [di], bp

    mov si, [fm_left_ptr]
    mov di, fe_product + 2
    mov cx, fe_words
    clc
.add_shift:
    mov ax, [si]
    adc [di], ax
    lea si, [si + 2]
    lea di, [di + 2]
    loop .add_shift
    adc word [di], 0

    mov bx, [fm_out_ptr]
    call fe_reduce_product
    ret

; Reduce fe_product into BX.
fe_reduce_product:
    mov [fr_out_ptr], bx
    mov si, fe_product
    mov di, fe_product + 32
    mov bx, [fr_out_ptr]
    mov word [fr_carry], 0
    mov cx, fe_words
.fold_words:
    mov ax, [di]
    mov dx, 38
    mul dx
    add ax, [si]
    adc dx, 0
    add ax, [fr_carry]
    adc dx, 0
    mov [bx], ax
    mov [fr_carry], dx
    add si, 2
    add di, 2
    add bx, 2
    loop .fold_words

    mov bx, [fr_out_ptr]
    mov ax, [fr_carry]
    call fe_fold_256
    call fe_fold_top
    call fe_canonical
    ret

; BX=field, AX=coefficient beyond word 15.  Fold AX*2^256 as AX*38.
fe_fold_256:
.again:
    or ax, ax
    jz .done
    mov dx, 38
    mul dx
    call fe_add_small
    jmp short .again
.done:
    ret

; BX=field, DX:AX=small unsigned addend.  Return AX=carry beyond 2^256.
fe_add_small:
    push cx
    push si
    mov si, bx
    add [si], ax
    adc dx, 0
    add si, 2
    mov ax, dx
    mov cx, fe_words - 1
.propagate:
    or ax, ax
    jz .no_carry
    add [si], ax
    mov ax, 0
    adc ax, 0
    add si, 2
    loop .propagate
    jmp short .done
.no_carry:
    xor ax, ax
.done:
    pop si
    pop cx
    ret

; Fold bit 255 using 2^255 == 19.  Repeats only if the small add sets it again.
fe_fold_top:
.again:
    mov ax, [bx + 30]
    mov dx, ax
    and word [bx + 30], 0x7fff
    mov cl, 15
    shr ax, cl
    or ax, ax
    jz .done
    mov dx, 19
    mul dx
    call fe_add_small
    call fe_fold_256
    jmp short .again
.done:
    ret

; Canonical subtraction of p when BX >= p.
fe_canonical:
    push ax
    push cx
    push si
    push di
    mov si, bx
    add si, 30
    mov di, fe_prime + 30
    mov cx, fe_words
.compare:
    mov ax, [si]
    cmp ax, [di]
    ja .subtract
    jb .done
    sub si, 2
    sub di, 2
    loop .compare
.subtract:
    mov si, fe_prime
    mov di, bx
    mov cx, fe_words
    clc
.sub_loop:
    mov ax, [si]
    sbb [di], ax
    lea si, [si + 2]
    lea di, [di + 2]
    loop .sub_loop
.done:
    pop di
    pop si
    pop cx
    pop ax
    ret

; z^(p-2), using the standard 254-square / 11-multiply addition chain.
; SI=z, BX=out.
fe_invert:
    mov [inv_z_ptr], si
    mov [inv_out_ptr], bx

    mov bx, fe_t0
    call fe_sq                         ; t0 = z^2
    mov si, fe_t0
    mov bx, fe_t1
    mov cx, 2
    call fe_sq_n                       ; t1 = z^8
    mov si, fe_t1
    mov di, [inv_z_ptr]
    mov bx, fe_t1
    call fe_mul                        ; t1 = z^9
    mov si, fe_t0
    mov di, fe_t1
    mov bx, fe_t0
    call fe_mul                        ; t0 = z^11
    mov si, fe_t0
    mov bx, fe_t2
    call fe_sq                         ; t2 = z^22
    mov si, fe_t1
    mov di, fe_t2
    mov bx, fe_t1
    call fe_mul                        ; t1 = 2^5 - 1

    mov si, fe_t1
    mov bx, fe_t2
    mov cx, 5
    call fe_sq_n
    mov si, fe_t2
    mov di, fe_t1
    mov bx, fe_t1
    call fe_mul                        ; t1 = 2^10 - 1

    mov si, fe_t1
    mov bx, fe_t2
    mov cx, 10
    call fe_sq_n
    mov si, fe_t2
    mov di, fe_t1
    mov bx, fe_t2
    call fe_mul                        ; t2 = 2^20 - 1

    mov si, fe_t2
    mov bx, fe_t3
    mov cx, 20
    call fe_sq_n
    mov si, fe_t3
    mov di, fe_t2
    mov bx, fe_t2
    call fe_mul                        ; t2 = 2^40 - 1

    mov si, fe_t2
    mov bx, fe_t2
    mov cx, 10
    call fe_sq_n
    mov si, fe_t2
    mov di, fe_t1
    mov bx, fe_t1
    call fe_mul                        ; t1 = 2^50 - 1

    mov si, fe_t1
    mov bx, fe_t2
    mov cx, 50
    call fe_sq_n
    mov si, fe_t2
    mov di, fe_t1
    mov bx, fe_t2
    call fe_mul                        ; t2 = 2^100 - 1

    mov si, fe_t2
    mov bx, fe_t3
    mov cx, 100
    call fe_sq_n
    mov si, fe_t3
    mov di, fe_t2
    mov bx, fe_t2
    call fe_mul                        ; t2 = 2^200 - 1

    mov si, fe_t2
    mov bx, fe_t2
    mov cx, 50
    call fe_sq_n
    mov si, fe_t2
    mov di, fe_t1
    mov bx, fe_t1
    call fe_mul                        ; t1 = 2^250 - 1

    mov si, fe_t1
    mov bx, fe_t1
    mov cx, 5
    call fe_sq_n
    mov si, fe_t1
    mov di, fe_t0
    mov bx, [inv_out_ptr]
    call fe_mul                        ; 2^255 - 21
    ret

; SI=input, BX=output, CX=count.  Input/output may alias after the first square.
fe_sq_n:
    mov [sqn_count], cx
.loop:
    call fe_sq
    dec word [sqn_count]
    jz .done
    mov si, bx
    jmp short .loop
.done:
    ret

; ---------------------------------------------------------------------------
; Harness I/O
; ---------------------------------------------------------------------------

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
; Fixed vectors, state, and scratch
; ---------------------------------------------------------------------------

tag_keygen db 'XKEYGEN', 0
tag_x25519 db 'X25519', 0
tag_checkkg db 'CHECKKG', 0
tag_checkss db 'CHECKSS', 0
tag_done   db 'DONE', 0
tag_fail   db 'FAIL', 0
str_N      db 'N=', 0
str_dt     db ' dt=', 0
str_ck     db ' ck=', 0
str_validation db ' N=1 dt=0 ck=', 0

; RFC 7748 §6.1: Alice private key, Bob public key, shared secret.
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

fe_prime:
    dw 0xffed
    times 14 dw 0xffff
    dw 0x7fff

t0_lo dw 0
t0_hi dw 0
dt_lo dw 0
case_expected_ptr dw 0
case_check_tag dw 0

ladder_scalar_ptr dw 0
ladder_count dw 0
ladder_swap dw 0
ladder_bit dw 0
ladder_scalar_mask db 0
align 2

fm_left_ptr dw 0
fm_right_ptr dw 0
fm_out_ptr dw 0
fm_product_ptr dw 0
fm_carry0 dw 0
fm_carry1 dw 0
fm_acc2 dw 0
fm_k dw 0
fr_out_ptr dw 0
fr_carry dw 0
inv_z_ptr dw 0
inv_out_ptr dw 0
sqn_count dw 0

scalar_work:   times fe_bytes db 0
x25519_output: times fe_bytes db 0

fe_x1:  times fe_words dw 0
fe_x2:  times fe_words dw 0
fe_z2:  times fe_words dw 0
fe_x3:  times fe_words dw 0
fe_z3:  times fe_words dw 0
fe_a:   times fe_words dw 0
fe_aa:  times fe_words dw 0
fe_b:   times fe_words dw 0
fe_bb:  times fe_words dw 0
fe_e:   times fe_words dw 0
fe_c:   times fe_words dw 0
fe_d:   times fe_words dw 0
fe_da:  times fe_words dw 0
fe_cb:  times fe_words dw 0
fe_tmp: times fe_words dw 0
fe_inv: times fe_words dw 0
fe_t0:  times fe_words dw 0
fe_t1:  times fe_words dw 0
fe_t2:  times fe_words dw 0
fe_t3:  times fe_words dw 0

fe_product: times 34 dw 0

image_end:

%if image_end - core_header > 0x2f00
    %error "X25519 benchmark leaves insufficient room below the 16 KiB stack"
%endif
