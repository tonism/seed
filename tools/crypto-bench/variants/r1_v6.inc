sha256_init:
    push ds
    pop es
    mov si, sha256_initial_state
    mov di, sha256_state
    mov cx, 16
    rep movsw
    mov byte [sha256_block_len], 0
    mov word [sha256_len_low], 0
    mov word [sha256_len_high], 0
    clc
    ret

sha256_update:
    or cx, cx
    jz .done
    add [sha256_len_low], cx
    adc word [sha256_len_high], 0
.next:
    lodsb
    mov bx, sha256_block
    mov dl, [sha256_block_len]
    xor dh, dh
    add bx, dx
    mov [bx], al
    inc byte [sha256_block_len]
    cmp byte [sha256_block_len], 64
    jne .advance
    push si
    push cx
    call sha256_process_block
    pop cx
    pop si
    mov byte [sha256_block_len], 0
.advance:
    loop .next
.done:
    clc
    ret

sha256_finish:
    ; Finalizes the current SHA-256 context and writes 32 digest bytes to DI.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    mov [sha256_digest_ptr], di
    mov ax, [sha256_len_low]
    mov dx, [sha256_len_high]
    xor bx, bx
    mov cx, 3
.bit_shift:
    shl ax, 1
    rcl dx, 1
    rcl bx, 1
    loop .bit_shift
    mov [sha256_bit_len0], ax
    mov [sha256_bit_len1], dx
    mov [sha256_bit_len2], bx
    mov word [sha256_bit_len3], 0

    mov al, 0x80
    call sha256_append_padding_byte
    cmp byte [sha256_block_len], 56
    jbe .pad_to_56
.pad_to_64:
    cmp byte [sha256_block_len], sha256_block_size
    je .process_pad_block
    xor al, al
    call sha256_append_padding_byte
    jmp .pad_to_64
.process_pad_block:
    call sha256_process_block
    mov byte [sha256_block_len], 0
.pad_to_56:
    cmp byte [sha256_block_len], 56
    je .write_length
    xor al, al
    call sha256_append_padding_byte
    jmp .pad_to_56
.write_length:
    mov bx, sha256_block
    add bx, 56
    mov ax, [sha256_bit_len3]
    call sha256_store_be16_at_bx
    mov ax, [sha256_bit_len2]
    call sha256_store_be16_at_bx
    mov ax, [sha256_bit_len1]
    call sha256_store_be16_at_bx
    mov ax, [sha256_bit_len0]
    call sha256_store_be16_at_bx
    call sha256_process_block
    mov byte [sha256_block_len], 0

    push ds
    pop es
    mov si, sha256_state
    mov di, [sha256_digest_ptr]
    mov cx, 8
.write_digest:
    mov ax, [si + 2]
    xchg al, ah
    stosw
    mov ax, [si]
    xchg al, ah
    stosw
    add si, 4
    loop .write_digest
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    clc
    ret

sha256_append_padding_byte:
    push bx
    mov bx, sha256_block
    mov dl, [sha256_block_len]
    xor dh, dh
    add bx, dx
    mov [bx], al
    inc byte [sha256_block_len]
    pop bx
    ret

sha256_store_be16_at_bx:
    mov [bx], ah
    mov [bx + 1], al
    add bx, 2
    ret

sha256_save_context:
    push ax
    push cx
    push si
    push di
    push es
    mov ax, [sha256_len_low]
    mov [sha256_saved_len_low], ax
    mov ax, [sha256_len_high]
    mov [sha256_saved_len_high], ax
    mov al, [sha256_block_len]
    mov [sha256_saved_block_len], al
    push ds
    pop es
    mov si, sha256_state
    mov di, sha256_saved_state
    mov cx, 16
    rep movsw
    mov si, sha256_block
    mov di, sha256_saved_block
    mov cx, sha256_block_size
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

sha256_restore_context:
    push ax
    push cx
    push si
    push di
    push es
    mov ax, [sha256_saved_len_low]
    mov [sha256_len_low], ax
    mov ax, [sha256_saved_len_high]
    mov [sha256_len_high], ax
    mov al, [sha256_saved_block_len]
    mov [sha256_block_len], al
    push ds
    pop es
    mov si, sha256_saved_state
    mov di, sha256_state
    mov cx, 16
    rep movsw
    mov si, sha256_saved_block
    mov di, sha256_block
    mov cx, sha256_block_size
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

%if 0
hmac_sha256:
    ; Uses hmac_* globals. Key length must be <= 64 bytes.
    push ax
    push bx
    push cx
    push si
    push di
    push es
    call sha256_save_context
    cmp word [hmac_key_len], sha256_block_size
    ja .failed
    push ds
    pop es
    mov di, hmac_ipad
    mov cx, sha256_block_size
    mov al, 0x36
    rep stosb
    mov di, hmac_opad
    mov cx, sha256_block_size
    mov al, 0x5c
    rep stosb
    mov si, [hmac_key_ptr]
    mov cx, [hmac_key_len]
    mov bx, hmac_ipad
.xor_ipad:
    or cx, cx
    jz .xor_opad_start
    lodsb
    xor [bx], al
    inc bx
    loop .xor_ipad
.xor_opad_start:
    mov si, [hmac_key_ptr]
    mov cx, [hmac_key_len]
    mov bx, hmac_opad
.xor_opad:
    or cx, cx
    jz .inner_hash
    lodsb
    xor [bx], al
    inc bx
    loop .xor_opad
.inner_hash:
    call sha256_init
    mov si, hmac_ipad
    mov cx, sha256_block_size
    call sha256_update
    mov si, [hmac_data1_ptr]
    mov cx, [hmac_data1_len]
    call sha256_update
    mov si, [hmac_data2_ptr]
    mov cx, [hmac_data2_len]
    call sha256_update
    mov di, hmac_inner_digest
    call sha256_finish

    call sha256_init
    mov si, hmac_opad
    mov cx, sha256_block_size
    call sha256_update
    mov si, hmac_inner_digest
    mov cx, sha256_digest_len
    call sha256_update
    mov di, [hmac_output_ptr]
    call sha256_finish
    clc
    jmp .done_hmac
.failed:
    stc
.done_hmac:
    pushf
    call sha256_restore_context
    popf
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

%endif

hmac_prepare_current_key_context:
    ; Pre-hashes HMAC ipad/opad blocks for repeated calls with hmac_key_*.
    push ax
    push bx
    push cx
    push si
    push di
    push es
    call sha256_save_context
    cmp word [hmac_key_len], sha256_block_size
    ja .failed
    push ds
    pop es
    mov di, hmac_ipad
    mov cx, sha256_block_size
    mov al, 0x36
    rep stosb
    mov di, hmac_opad
    mov cx, sha256_block_size
    mov al, 0x5c
    rep stosb
    mov si, [hmac_key_ptr]
    mov cx, [hmac_key_len]
    mov bx, hmac_ipad
.xor_ipad:
    or cx, cx
    jz .xor_opad_start
    lodsb
    xor [bx], al
    inc bx
    loop .xor_ipad
.xor_opad_start:
    mov si, [hmac_key_ptr]
    mov cx, [hmac_key_len]
    mov bx, hmac_opad
.xor_opad:
    or cx, cx
    jz .hash_ipad
    lodsb
    xor [bx], al
    inc bx
    loop .xor_opad
.hash_ipad:
    call sha256_init
    mov si, hmac_ipad
    mov cx, sha256_block_size
    call sha256_update
    mov si, sha256_state
    mov di, hmac_prepared_inner_state
    mov cx, 16
    rep movsw
    call sha256_init
    mov si, hmac_opad
    mov cx, sha256_block_size
    call sha256_update
    mov si, sha256_state
    mov di, hmac_prepared_outer_state
    mov cx, 16
    rep movsw
    clc
    jmp .done_prepare
.failed:
    stc
.done_prepare:
    pushf
    call sha256_restore_context
    popf
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

hmac_sha256_prepared:
    ; Uses hmac_data* globals and hmac_prepared_* states.
    push ax
    push cx
    push si
    push di
    push es
    call sha256_save_context
    call hmac_load_prepared_inner
    mov si, [hmac_data1_ptr]
    mov cx, [hmac_data1_len]
    call sha256_update
    mov si, [hmac_data2_ptr]
    mov cx, [hmac_data2_len]
    call sha256_update
    mov di, hmac_inner_digest
    call sha256_finish

    call hmac_load_prepared_outer
    mov si, hmac_inner_digest
    mov cx, sha256_digest_len
    call sha256_update
    mov di, [hmac_output_ptr]
    call sha256_finish
    clc
    pushf
    call sha256_restore_context
    popf
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

hmac_load_prepared_inner:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, hmac_prepared_inner_state
    mov di, sha256_state
    mov cx, 16
    rep movsw
    mov word [sha256_len_low], sha256_block_size
    mov word [sha256_len_high], 0
    mov byte [sha256_block_len], 0
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

hmac_load_prepared_outer:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, hmac_prepared_outer_state
    mov di, sha256_state
    mov cx, 16
    rep movsw
    mov word [sha256_len_low], sha256_block_size
    mov word [sha256_len_high], 0
    mov byte [sha256_block_len], 0
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

sha256_process_block:
    push ds
    pop es
    mov si, sha256_block
    mov di, sha256_w
    mov cx, 16
.load_word:
    lodsb
    mov ah, al
    lodsb
    mov [di + 2], ax
    lodsb
    mov ah, al
    lodsb
    mov [di], ax
    add di, 4
    loop .load_word

    mov byte [sha256_schedule_count], 48
.schedule:
    mov si, di
    sub si, 8
    call sha256_small_sigma1_mem
    mov [sha256_t1], ax
    mov [sha256_t1 + 2], dx

    mov si, di
    sub si, 28
    call sha256_add_mem_to_t1

    mov si, di
    sub si, 60
    call sha256_small_sigma0_mem
    call sha256_add_pair_to_t1

    mov si, di
    sub si, 64
    call sha256_add_mem_to_t1

    mov ax, [sha256_t1]
    mov [di], ax
    mov ax, [sha256_t1 + 2]
    mov [di + 2], ax
    add di, 4
    dec byte [sha256_schedule_count]
    jnz .schedule

    mov si, sha256_state
    mov di, sha256_a
    mov cx, 16
    rep movsw

    mov word [sha256_w_ptr], sha256_w
    mov word [sha256_k_ptr], sha256_k
    mov byte [sha256_round_count], 64
.round:
    mov ax, [sha256_h]
    mov dx, [sha256_h + 2]
    mov [sha256_t1], ax
    mov [sha256_t1 + 2], dx

    mov si, sha256_e
    call sha256_big_sigma1_mem
    call sha256_add_pair_to_t1

    call sha256_ch
    call sha256_add_pair_to_t1

    mov si, [sha256_k_ptr]
    call sha256_add_mem_to_t1

    mov si, [sha256_w_ptr]
    call sha256_add_mem_to_t1

    mov si, sha256_a
    call sha256_big_sigma0_mem
    mov [sha256_t2], ax
    mov [sha256_t2 + 2], dx

    call sha256_maj
    call sha256_add_pair_to_t2

    mov ax, [sha256_d]
    mov dx, [sha256_d + 2]
    add ax, [sha256_t1]
    adc dx, [sha256_t1 + 2]
    mov [sha256_new_e], ax
    mov [sha256_new_e + 2], dx

    mov ax, [sha256_g]
    mov [sha256_h], ax
    mov ax, [sha256_g + 2]
    mov [sha256_h + 2], ax

    mov ax, [sha256_f]
    mov [sha256_g], ax
    mov ax, [sha256_f + 2]
    mov [sha256_g + 2], ax

    mov ax, [sha256_e]
    mov [sha256_f], ax
    mov ax, [sha256_e + 2]
    mov [sha256_f + 2], ax

    mov ax, [sha256_new_e]
    mov [sha256_e], ax
    mov ax, [sha256_new_e + 2]
    mov [sha256_e + 2], ax

    mov ax, [sha256_c]
    mov [sha256_d], ax
    mov ax, [sha256_c + 2]
    mov [sha256_d + 2], ax

    mov ax, [sha256_b]
    mov [sha256_c], ax
    mov ax, [sha256_b + 2]
    mov [sha256_c + 2], ax

    mov ax, [sha256_a]
    mov [sha256_b], ax
    mov ax, [sha256_a + 2]
    mov [sha256_b + 2], ax

    mov ax, [sha256_t1]
    mov dx, [sha256_t1 + 2]
    add ax, [sha256_t2]
    adc dx, [sha256_t2 + 2]
    mov [sha256_a], ax
    mov [sha256_a + 2], dx

    add word [sha256_w_ptr], 4
    add word [sha256_k_ptr], 4
    dec byte [sha256_round_count]
    jnz .round

    mov si, sha256_a
    mov di, sha256_state
    mov cx, 8
.add_state:
    mov ax, [si]
    add [di], ax
    mov ax, [si + 2]
    adc [di + 2], ax
    add si, 4
    add di, 4
    loop .add_state
    clc
    ret

sha256_add_mem_to_t1:
    mov ax, [si]
    add [sha256_t1], ax
    mov ax, [si + 2]
    adc [sha256_t1 + 2], ax
    ret

sha256_add_pair_to_t1:
    add [sha256_t1], ax
    adc [sha256_t1 + 2], dx
    ret

sha256_add_pair_to_t2:
    add [sha256_t2], ax
    adc [sha256_t2 + 2], dx
    ret

sha256_ch:
    mov ax, [sha256_e]
    mov bx, ax
    and bx, [sha256_f]
    not ax
    and ax, [sha256_g]
    xor ax, bx
    mov [sha256_tmp], ax

    mov dx, [sha256_e + 2]
    mov bx, dx
    and bx, [sha256_f + 2]
    not dx
    and dx, [sha256_g + 2]
    xor dx, bx
    mov ax, [sha256_tmp]
    ret

sha256_maj:
    mov ax, [sha256_a]
    mov bx, ax
    and bx, [sha256_b]
    mov dx, ax
    and dx, [sha256_c]
    xor bx, dx
    mov dx, [sha256_b]
    and dx, [sha256_c]
    xor bx, dx
    mov [sha256_tmp], bx

    mov ax, [sha256_a + 2]
    mov bx, ax
    and bx, [sha256_b + 2]
    mov dx, ax
    and dx, [sha256_c + 2]
    xor bx, dx
    mov dx, [sha256_b + 2]
    and dx, [sha256_c + 2]
    xor dx, bx
    mov ax, [sha256_tmp]
    ret; ---------------------------------------------------------------------------
; r1_v6: rotl-vs-rotr residual minimization + combined byte+bit rotate, with a
; register-resident XOR accumulator and temp-free byte rotates.
;
; Each sigma reads its 32-bit input word ONCE into bp:bx (bp=high16, bx=low16).
; Every fixed rotate is inlined (no generic rotr32 call, no cmp/branch dispatch)
; and decomposed as a byte-aligned rotation + <=4 single-bit steps, choosing
; rotr-by-n or rotl-by-(32-n) -- whichever leaves the FEWER single-bit steps
; (the assigned technique). Single-bit residuals:
;   ROL1: shl ax,1 / rcl dx,1 / adc ax,0   (wrap LSB<-MSB, branchless, no scratch)
;   ROR1: shr dx,1 / rcr ax,1 / jnc/or     (wrap MSB<-LSB, branch, no scratch)
; ROL1 is the cheaper primitive, so it wins ties.
;
; Byte rotations are temp-free 3x-xchg permutations of dx:ax (no scratch reg, and
; cheaper than a 5-mov shuffle). That frees cx, so the running XOR accumulates in
; cx:si (si=high, cx=low) -- pure reg-reg XOR, zero memory traffic -- and di is
; never touched (no push/pop needed; the schedule loop's di pointer is safe).
; Registers: source bp:bx, live rotate dx:ax, accumulator si:cx.
;
; Chosen direction / residual per amount (n = right-rotate):
;   2  ->R 2   13 ->L 3   22 ->L 2     (Sigma0)
;   6  ->L 2   11 ->R 3   25 ->R 1     (Sigma1)
;   7  ->L 1   18 ->R 2   >>3          (sigma0)
;   17 ->R 1   19 ->R 3   >>10         (sigma1)
; ---------------------------------------------------------------------------

; --- byte-granular rotations on dx:ax (bytes MSB..LSB = dh dl ah al), no scratch ---
%macro BYTE_ROL8 0          ; rotate dx:ax left by 8 (dh wraps to al)
    xchg dh, dl
    xchg dl, ah
    xchg ah, al
%endmacro
%macro BYTE_ROR8 0          ; rotate dx:ax right by 8 (al wraps to dh)
    xchg ah, al
    xchg dl, ah
    xchg dh, dl
%endmacro
%macro BYTE_SHR8 0          ; logical shift dx:ax right by 8 (dh<-0), no scratch
    mov al, ah
    mov ah, dl
    mov dl, dh
    xor dh, dh
%endmacro

; --- single-bit rotates on dx:ax (no scratch register) ---
%macro ROL1 0               ; rotate dx:ax left by 1
    shl ax, 1
    rcl dx, 1
    adc ax, 0
%endmacro
%macro ROR1 0               ; rotate dx:ax right by 1
    shr dx, 1
    rcr ax, 1
    jnc %%nw
    or dx, 0x8000
%%nw:
%endmacro

%macro LOADX 0              ; load the source word at [si] once into bp:bx
    mov bx, [si]
    mov bp, [si + 2]
%endmacro
%macro COPYX 0             ; dx:ax <- source bp:bx
    mov ax, bx
    mov dx, bp
%endmacro
%macro ACC_SET 0           ; accumulator si:cx <- dx:ax  (first rotate term)
    mov cx, ax
    mov si, dx
%endmacro
%macro ACC_XOR 0           ; accumulator si:cx ^= dx:ax  (middle term)
    xor cx, ax
    xor si, dx
%endmacro
%macro ACC_MERGE 0         ; dx:ax ^= accumulator si:cx  (final term -> result)
    xor ax, cx
    xor dx, si
%endmacro

sha256_big_sigma0_mem:          ; rotr2 ^ rotr13 ^ rotr22
    LOADX
    ; rotr2  : R, 2x ROR1
    COPYX
    ROR1
    ROR1
    ACC_SET
    ; rotr13 = rotl19 : xchg (rotl16) + 3x ROL1
    COPYX
    xchg ax, dx
    ROL1
    ROL1
    ROL1
    ACC_XOR
    ; rotr22 = rotl10 : BYTE_ROL8 + 2x ROL1
    COPYX
    BYTE_ROL8
    ROL1
    ROL1
    ACC_MERGE
    ret

sha256_big_sigma1_mem:          ; rotr6 ^ rotr11 ^ rotr25
    LOADX
    ; rotr6 = rotl26 : BYTE_ROR8 (rotl24) + 2x ROL1
    COPYX
    BYTE_ROR8
    ROL1
    ROL1
    ACC_SET
    ; rotr11 : BYTE_ROR8 (rotr8) + 3x ROR1
    COPYX
    BYTE_ROR8
    ROR1
    ROR1
    ROR1
    ACC_XOR
    ; rotr25 = rotr24 + rotr1 : BYTE_ROL8 (rotr24) + 1x ROR1
    COPYX
    BYTE_ROL8
    ROR1
    ACC_MERGE
    ret

sha256_small_sigma0_mem:        ; rotr7 ^ rotr18 ^ (x >> 3)
    LOADX
    ; rotr7 = rotl25 : BYTE_ROR8 (rotl24) + 1x ROL1
    COPYX
    BYTE_ROR8
    ROL1
    ACC_SET
    ; rotr18 = rotr16 + rotr2 : xchg + 2x ROR1
    COPYX
    xchg ax, dx
    ROR1
    ROR1
    ACC_XOR
    ; x >> 3 : 3x logical shift right (no wrap)
    COPYX
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    ACC_MERGE
    ret

sha256_small_sigma1_mem:        ; rotr17 ^ rotr19 ^ (x >> 10)
    LOADX
    ; rotr17 = rotr16 + rotr1 : xchg + 1x ROR1
    COPYX
    xchg ax, dx
    ROR1
    ACC_SET
    ; rotr19 = rotr17 + 2x ROR1 : chain from the rotr17 value still in dx:ax
    ; (saves one COPYX + xchg vs recomputing rotr16 -- ACC_SET preserved dx:ax)
    ROR1
    ROR1
    ACC_XOR
    ; x >> 10 : BYTE_SHR8 (>>8) + 2x logical shift right
    COPYX
    BYTE_SHR8
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    ACC_MERGE
    ret

