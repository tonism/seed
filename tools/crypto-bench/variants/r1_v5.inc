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

    ; ---- pointer-rotation of state a..h (sliding window, no per-round copies) ----
    ; The working vars live in an 8-slot window inside sha256_ring (slot = 4 bytes).
    ; Window base = DI. Layout within the window (offsets from DI):
    ;   +0 h, +4 g, +8 f, +12 e, +16 d, +20 c, +24 b, +28 a
    ; Each round the window slides UP by one slot (DI += 4). After the slide the
    ; old g..a are already in the h'..b' positions for free; only the two genuinely
    ; new words are written: e' = old d + T1  (in place at DI+16) and a' = T1 + T2
    ; (the brand-new slot at DI+32). 64 rounds travel 64 slots, so the ring is
    ; 8 + 64 = 72 slots. Seed the window reversed: h at slot0 .. a at slot7.
    mov si, sha256_state            ; state[0..7] = a,b,c,d,e,f,g,h (4 bytes each)
    mov di, sha256_ring + 28        ; slot7 = a
    mov cx, 8
.seed_ring:
    movsw                           ; copy low word, then high word; SI advances
    movsw
    sub di, 8                       ; step DI back to the previous (lower) slot
    loop .seed_ring

    mov word [sha256_w_ptr], sha256_w
    mov bp, sha256_k                ; K pointer kept in BP (survives all sigma/ch/maj calls)
    mov byte [sha256_round_count], 64
    mov di, sha256_ring             ; window base (h at [di], a at [di+28])
.round:
    mov ax, [di]                    ; T1 = h
    mov dx, [di + 2]
    mov [sha256_t1], ax
    mov [sha256_t1 + 2], dx

    ; --- Sigma1(e) inlined (single call site): rotr(e,6)^rotr(e,11)^rotr(e,25) ---
    lea si, [di + 12]               ; &e (also used by Ch below)
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 6
    call sha256_rotr32
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 11
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 25
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    add [sha256_t1], ax             ; T1 += Sigma1(e)
    adc [sha256_t1 + 2], dx

    ; --- Ch(e,f,g) = (e&f)^(~e&g) inlined. Compute BOTH halves first (DX=hi, AX=lo),
    ;     then add/adc back-to-back so the low-half carry survives into the high add. ---
    mov dx, [si + 2]                ; e_hi
    mov bx, dx
    and bx, [si - 2]                ; e & f  (hi)
    not dx
    and dx, [si - 6]                ; ~e & g (hi)
    xor dx, bx                      ; DX = Ch_hi
    mov ax, [si]                    ; e_lo
    mov bx, ax
    and bx, [si - 4]                ; e & f  (lo)
    not ax
    and ax, [si - 8]                ; ~e & g (lo)
    xor ax, bx                      ; AX = Ch_lo
    add [sha256_t1], ax             ; T1 += Ch (carry propagates lo->hi)
    adc [sha256_t1 + 2], dx

    mov ax, [bp]                    ; K[t]  (BP-resident pointer)
    add [sha256_t1], ax
    mov ax, [bp + 2]
    adc [sha256_t1 + 2], ax

    mov si, [sha256_w_ptr]          ; W[t]
    mov ax, [si]
    add [sha256_t1], ax
    mov ax, [si + 2]
    adc [sha256_t1 + 2], ax         ; T1 complete

    ; --- Sigma0(a) inlined: rotr(a,2)^rotr(a,13)^rotr(a,22) ---
    lea si, [di + 28]               ; &a (also used by Maj below)
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 2
    call sha256_rotr32
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 13
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 22
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    mov [sha256_t2], ax             ; T2 = Sigma0(a)
    mov [sha256_t2 + 2], dx

    ; --- Maj(a,b,c) = (a&b)^(a&c)^(b&c) inlined. Stash lo half in CX, compute hi in
    ;     BX, then add/adc back-to-back so the carry propagates correctly. ---
    mov ax, [si]                    ; a_lo
    mov bx, ax
    and bx, [si - 4]                ; a & b
    mov dx, ax
    and dx, [si - 8]                ; a & c
    xor bx, dx
    mov dx, [si - 4]
    and dx, [si - 8]                ; b & c
    xor bx, dx                      ; BX = Maj_lo
    mov cx, bx                      ; stash lo half (CX free here)
    mov ax, [si + 2]                ; a_hi
    mov bx, ax
    and bx, [si - 2]                ; a & b (hi)
    mov dx, ax
    and dx, [si - 6]                ; a & c (hi)
    xor bx, dx
    mov dx, [si - 2]
    and dx, [si - 6]                ; b & c (hi)
    xor bx, dx                      ; BX = Maj_hi
    add [sha256_t2], cx             ; T2 += Maj (carry propagates lo->hi)
    adc [sha256_t2 + 2], bx         ; T2 complete

    ; e' = d + T1, written in place at [di+16] (becomes new-window slot3 after slide)
    mov ax, [di + 16]
    mov dx, [di + 18]
    add ax, [sha256_t1]
    adc dx, [sha256_t1 + 2]
    mov [di + 16], ax
    mov [di + 18], dx

    ; a' = T1 + T2, written to the fresh slot at [di+32] (new-window slot7 after slide)
    mov ax, [sha256_t1]
    mov dx, [sha256_t1 + 2]
    add ax, [sha256_t2]
    adc dx, [sha256_t2 + 2]
    mov [di + 32], ax
    mov [di + 34], dx

    add di, 4                       ; slide window up one slot (h'..b' = old g..a, free)
    add bp, 4                        ; next K constant
    add word [sha256_w_ptr], 4
    dec byte [sha256_round_count]
    jnz .round

    ; Final a..h are now at [di+28]=a .. [di+0]=h (DI = sha256_ring + 256).
    ; Add them back into the canonical state[0..7] = a,b,c,d,e,f,g,h.
    mov si, sha256_state
    add di, 28                      ; &a in the final window
    mov cx, 8
.add_state:
    mov ax, [di]
    add [si], ax
    mov ax, [di + 2]
    adc [si + 2], ax
    add si, 4
    sub di, 4
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

; (Ch, Maj, big_sigma0, big_sigma1 are now inlined into the round above -- their
; standalone definitions were removed since the round was their only call site.)

sha256_small_sigma0_mem:
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 7
    call sha256_rotr32
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 18
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 3
    call sha256_shr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    ret

sha256_small_sigma1_mem:
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 17
    call sha256_rotr32
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 19
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 10
    call sha256_shr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    ret

; v001: byte-granular rotate. rotr32 by cl = (>=16 ? xchg halves) + (>=8 ? byte
; rotate) + (<=7 residual single-bit). Caps the bit loop at 7 iters vs the
; original's up-to-25, and the byte/word steps are a handful of reg moves.
sha256_rotr32:                  ; rotate dx:ax right by cl (0..31)
    cmp cl, 16
    jb .lt16
    xchg ax, dx                 ; rotr by 16 = swap halves
    sub cl, 16
.lt16:
    cmp cl, 8
    jb .lt8
    push bx                     ; rotr by 8 = byte rotate of dh:dl:ah:al
    mov bh, al
    mov al, ah
    mov ah, dl
    mov dl, dh
    mov dh, bh
    pop bx
    sub cl, 8
.lt8:
    or cl, cl
    jz .done
.rotate:
    shr dx, 1
    rcr ax, 1
    jnc .no_wrap
    or dx, 0x8000
.no_wrap:
    dec cl
    jnz .rotate
.done:
    ret

sha256_shr32:                   ; logical shift dx:ax right by cl (0..31)
    cmp cl, 16
    jb .lt16
    mov ax, dx                  ; shr by 16 = low gets high, high = 0
    xor dx, dx
    sub cl, 16
.lt16:
    cmp cl, 8
    jb .lt8
    mov al, ah                  ; shr by 8: al=ah, ah=dl, dl=dh, dh=0
    mov ah, dl
    mov dl, dh
    xor dh, dh
    sub cl, 8
.lt8:
    or cl, cl
    jz .done
.shift:
    shr dx, 1
    rcr ax, 1
    dec cl
    jnz .shift
.done:
    ret

; Sliding-window scratch for the pointer-rotated a..h. 8-word window + 64 rounds
; of upward slide = 72 slots x 4 bytes = 288 bytes. (For a real-nucleus drop-in
; this would be an EQU into a 288-byte dead-scratch region rather than emitted
; image bytes; the benchmark has ample low RAM so a local buffer is used here.)
sha256_ring:
    times 288 db 0
