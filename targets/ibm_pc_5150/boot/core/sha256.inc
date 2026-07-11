; Build 12: fast SHA-256 / PRF (r2_v25 from the crypto spike, tools/crypto-bench).
; 4.33x PRF / 4.62x block vs the original, bit-exact (evaluate.py + check-tls-prf gates).
; Byte-granular rotates + single-load sigmas + register-resident round. Position-independent
; (relative calls, fixed-absolute data refs). Drop-in: same entry points + data.inc state.
; Chosen over r4_v42 (4.64x) because it fits the 16K K window in 15 sectors with NO golf;
; r4_v42 needed a fragile 74 B crypto golf for the last ~0.3x. See notes/old/build12-layout-redesign-attempts.md.

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

; =====================================================================
; r1_v7 (WILDCARD): fixed-shift inline rotates + single-load sigmas.
;
; Structurally different from the byte-rotate leader: rather than a
; generic rotr32/shr32 helper that branches on a runtime CL, each of the
; six sigma functions reads its source word ONCE into dx:ax and computes
; all three rotation terms with a hardcoded, optimal fixed-amount
; sequence (16-bit swap, 8-bit byte-rotate, then the minimal residual
; single-bit shifts), XOR-accumulating in registers. No [si] reloads, no
; sha256_tmp ping-pong inside a sigma, no per-rotate call overhead.
;
; Working-set note: the round still spills a..h to memory (8x32 bits do
; not fit in the 8086 GP file), but the hot inputs e/f/g and a/b/c are
; pulled into registers per-use and the sigma intermediates stay in
; registers, which is where the original burned most of its memory bus.
;
; Fixed rotate macros operate on dx:ax (dx=high16, ax=low16).
; =====================================================================

; rotate dx:ax LEFT by 1, branchless (3 instr)
%macro ROL32_1 0
    shl ax, 1
    rcl dx, 1
    adc al, 0
%endmacro

; rotate dx:ax RIGHT by 1 (carry wraps bit0 -> bit31)
%macro ROR32_1 0
    shr dx, 1
    rcr ax, 1
    jnc %%nw
    or dx, 0x8000
%%nw:
%endmacro

; rotate dx:ax RIGHT by 16 (swap halves) -- 1 instr
%macro ROR32_16 0
    xchg ax, dx
%endmacro

; rotate dx:ax RIGHT by 8 : byte chain dh:dl:ah:al -> shift right one byte
; result byte order (high->low): al, dh, dl, ah  (i.e. old low byte wraps to top)
; new dh = al ; new dl = dh ; new ah = dl ; new al = ah
%macro ROR32_8 0
    mov cl, al      ; save old al (cl is scratch inside sigmas; base lives in bp:bx)
    mov al, ah      ; al <- ah
    mov ah, dl      ; ah <- dl
    mov dl, dh      ; dl <- dh
    mov dh, cl      ; dh <- old al
%endmacro

; rotate dx:ax LEFT by 8 : new al=ah? -- left by 8 = right by 24.
; left8: dh:dl:ah:al -> dl:ah:al:dh  (old top byte dh wraps to bottom)
; new dh = dl ; new dl = ah ; new ah = al ; new al = dh
%macro ROL32_8 0
    mov cl, dh
    mov dh, dl
    mov dl, ah
    mov ah, al
    mov al, cl
%endmacro

; SHA_RND a,b,c,d,e,f,g,h, newa_slot, newe_slot, kw_offset
; One SHA-256 round operating on fixed memory slots (no shuffle). Computes
;   T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i]
;   T2 = S0(a) + Maj(a,b,c)
; then writes new_e = d + T1 to %10 and new_a = T1 + T2 to %9. %9 aliases the
; old 'd' slot and %10 the old 'h' slot, both already consumed, so the writes
; are safe. %11 is the byte displacement (0/4/8/12) into the K/W arrays for this
; sub-round; the si/di bases advance by 16 once per group of four (in .round).
%macro SHA_RND 11
    ; Per-round add-chain memory writes are cut to the bare minimum (6 word
    ; writes: T2 spill + new_a + new_e). The trick is to call each sigma FIRST so
    ; its result lands in dx:ax, then fold the non-linear function (Ch/Maj) into
    ; dx:ax with register-only adds. Ch and Maj contain no further calls, so they
    ; need no across-call spill: the OLD code spilled both Ch and the running T1
    ; partial to memory; this version spills NEITHER. T1 is computed LAST so it
    ; survives in dx:ax and feeds new_e and new_a directly (no [t1] store/reload).
    ;
    ; ---- T2 = S0(a) + Maj(a,b,c), built entirely in registers -> [t2] ----
    mov ax, [%1]                  ; S0(a) first; result returns in dx:ax
    mov dx, [%1 + 2]
    call sha256_big_sigma0_dxax
    ; Maj(a,b,c) = (a & (b^c)) ^ (b&c). Compute the high half into bx (cx temp),
    ; the low half into cx (bp temp), then add the full 32 bits into dx:ax. No
    ; carry hazard: the two Maj halves are finished before either add.
    mov bx, [%2 + 2]
    mov cx, bx
    xor bx, [%3 + 2]
    and bx, [%1 + 2]
    and cx, [%3 + 2]
    xor bx, cx                    ; bx = Maj_hi
    mov cx, [%2]
    mov bp, cx
    xor cx, [%3]
    and cx, [%1]
    and bp, [%3]
    xor cx, bp                    ; cx = Maj_lo
    add ax, cx                    ; T2 = S0 + Maj  (in dx:ax)
    adc dx, bx
    mov [sha256_t2], ax           ; T2 parked in [t2] across the T1 chain/sigma1
    mov [sha256_t2 + 2], dx
    ; ---- T1 = S1(e) + Ch(e,f,g) + h + K[i] + W[i], built in registers ----
    mov ax, [%5]                  ; S1(e) first; result returns in dx:ax
    mov dx, [%5 + 2]
    call sha256_big_sigma1_dxax
    ; Ch(e,f,g) = g ^ (e & (f^g)) fits in bx:cx with no temp (single-reg chain).
    mov cx, [%6]                  ; Ch_lo
    xor cx, [%7]
    and cx, [%5]
    xor cx, [%7]
    mov bx, [%6 + 2]              ; Ch_hi
    xor bx, [%7 + 2]
    and bx, [%5 + 2]
    xor bx, [%7 + 2]
    add ax, cx                    ; + Ch
    adc dx, bx
    add ax, [%8]                  ; + h
    adc dx, [%8 + 2]
    add ax, [si + %11]            ; + K[i]  (si = K base; %11 = 4*subround offset)
    adc dx, [si + %11 + 2]
    add ax, [di + %11]            ; + W[i]  (di = W base)  -> T1 in dx:ax
    adc dx, [di + %11 + 2]
    ; ---- write the two new state words straight from registers ----
    ; T1 is live in dx:ax. Read d (=%4, aliases new_a slot %9) FIRST, form new_e
    ; in bp:bx, then form new_a in dx:ax (T1 + T2-from-[t2]) and store both.
    mov bx, [%4]                  ; d
    mov bp, [%4 + 2]
    add bx, ax                    ; new_e = d + T1  (in bp:bx)
    adc bp, dx
    add ax, [sha256_t2]           ; new_a = T1 + T2  (in dx:ax, T1 consumed here)
    adc dx, [sha256_t2 + 2]
    mov [%9], ax                  ; write new_a (d already read above; %9 aliases d)
    mov [%9 + 2], dx
    mov [%10], bx                 ; write new_e
    mov [%10 + 2], bp
    ; K/W pointers are advanced once per group of 4 sub-rounds (see .round loop),
    ; using the %11 displacement here instead of an add per sub-round.
%endmacro

; All sigma helpers take the source word in dx:ax and return the result in
; dx:ax. The three rotation terms are computed as a CHAIN: each rotation builds
; on the previous (rotr_b = rotr_a then rotr_(b-a)), so no source reload or
; memory spill is needed for the rotation part (the running XOR accumulator
; lives in bp:bx). The small sigmas' shift term still needs the original word,
; so they spill it once to sha256_tmp. si/di are preserved (they carry the K/W
; pointers across calls); cx is transient byte-rotate scratch. Chain deltas and
; their minimal fixed-rotate sequences were chosen by a shortest-path search.

; --- Big Sigma 0: rotr2 ^ rotr13 ^ rotr22  (chain 0->2->13->22, no memory) ---
sha256_big_sigma0_dxax:
    ROR32_1                     ; -> rotr2
    ROR32_1
    mov bp, dx
    mov bx, ax                  ; acc = rotr2
    ROL32_1                     ; +11 -> rotr13
    ROL32_1
    ROL32_1
    ROL32_1
    ROL32_1
    ROR32_16
    xor bx, ax
    xor bp, dx
    ROR32_1                     ; +9 -> rotr22
    ROR32_8
    xor ax, bx
    xor dx, bp
    ret

; --- Big Sigma 1: rotr6 ^ rotr11 ^ rotr25  (chain 0->6->11->25, no memory) ---
sha256_big_sigma1_dxax:
    ROL32_1                     ; +6 -> rotr6
    ROL32_1
    ROR32_8
    mov bp, dx
    mov bx, ax                  ; acc = rotr6
    ROL32_1                     ; +5 -> rotr11
    ROL32_1
    ROL32_1
    ROR32_8
    xor bx, ax
    xor bp, dx
    ROL32_1                     ; +14 -> rotr25
    ROL32_1
    ROR32_16
    xor ax, bx
    xor dx, bp
    ret

; --- small sigma 0: rotr7 ^ rotr18 ^ shr3 ---
sha256_small_sigma0_dxax:
    mov [sha256_tmp], ax        ; spill source (for the shr3 term)
    mov [sha256_tmp + 2], dx
    ROL32_1                     ; +7 -> rotr7
    ROR32_8
    mov bp, dx
    mov bx, ax                  ; acc = rotr7
    ROL32_1                     ; +11 -> rotr18
    ROL32_1
    ROL32_1
    ROL32_1
    ROL32_1
    ROR32_16
    xor bx, ax
    xor bp, dx
    ; shr3 (logical right 3) on the original source
    mov ax, [sha256_tmp]
    mov dx, [sha256_tmp + 2]
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    xor ax, bx
    xor dx, bp
    ret

; --- small sigma 1: rotr17 ^ rotr19 ^ shr10 ---
sha256_small_sigma1_dxax:
    mov [sha256_tmp], ax        ; spill source (for the shr10 term)
    mov [sha256_tmp + 2], dx
    ROR32_1                     ; +17 -> rotr17
    ROR32_16
    mov bp, dx
    mov bx, ax                  ; acc = rotr17
    ROR32_1                     ; +2 -> rotr19
    ROR32_1
    xor bx, ax
    xor bp, dx
    ; shr10 = shr8 + shr2 on the original source
    mov ax, [sha256_tmp]
    mov dx, [sha256_tmp + 2]
    mov al, ah                  ; shr8 logical: al<-ah, ah<-dl, dl<-dh, dh<-0
    mov ah, dl
    mov dl, dh
    xor dh, dh
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    xor ax, bx
    xor dx, bp
    ret

sha256_process_block:
    push ds
    pop es
    ; ---- message schedule words 0..15 (big-endian load) ----
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

    ; ---- extend schedule words 16..63 ----
    ; di points at sha256_w + 64 (word 16). For each new word:
    ;   w = s1(w[-2]) + w[-7] + s0(w[-15]) + w[-16]
    ; si is unused for addressing in this loop (di carries the only pointer) and
    ; the small sigmas preserve si, so use it as the loop counter in a register
    ; -- a register dec/jnz is ~4 cyc vs ~24 for dec byte [mem] x48 iterations.
    mov si, 48
.schedule:
    ; s1(w[-2]) : w[-2] is at di-8
    mov ax, [di - 8]
    mov dx, [di - 6]
    call sha256_small_sigma1_dxax
    ; add w[-7] (at di-28)
    add ax, [di - 28]
    adc dx, [di - 26]
    ; stash partial in t1
    mov [sha256_t1], ax
    mov [sha256_t1 + 2], dx
    ; s0(w[-15]) : at di-60
    mov ax, [di - 60]
    mov dx, [di - 58]
    call sha256_small_sigma0_dxax
    add ax, [sha256_t1]
    adc dx, [sha256_t1 + 2]
    ; add w[-16] (at di-64)
    add ax, [di - 64]
    adc dx, [di - 62]
    mov [di], ax
    mov [di + 2], dx
    add di, 4
    dec si
    jnz .schedule

    ; ---- working vars a..h <- state ----
    mov si, sha256_state
    mov di, sha256_a
    mov cx, 16
    rep movsw

    ; si = running K pointer, di = running W pointer (both survive sigma calls).
    ; The loop ends when di walks past the 64-word schedule (16 groups of 4); a
    ; register pointer-compare is cheaper than a dec byte [mem] counter.
    mov si, sha256_k
    mov di, sha256_w
.round:
    ; Four sub-rounds with the a..h ring renamed in fixed memory slots, so no
    ; per-round state shuffle / copies happen at all. The ring of {a,b,c,d} and
    ; {e,f,g,h} each have period 4, so after 4 sub-rounds the names realign and
    ; the loop body can repeat. new_a is written to the slot the dropped 'd'
    ; vacates; new_e to the slot the dropped 'h' vacates.
    SHA_RND sha256_a, sha256_b, sha256_c, sha256_d, sha256_e, sha256_f, sha256_g, sha256_h, sha256_d, sha256_h, 0
    SHA_RND sha256_d, sha256_a, sha256_b, sha256_c, sha256_h, sha256_e, sha256_f, sha256_g, sha256_c, sha256_g, 4
    SHA_RND sha256_c, sha256_d, sha256_a, sha256_b, sha256_g, sha256_h, sha256_e, sha256_f, sha256_b, sha256_f, 8
    SHA_RND sha256_b, sha256_c, sha256_d, sha256_a, sha256_f, sha256_g, sha256_h, sha256_e, sha256_a, sha256_e, 12
    add si, 16                            ; advance K/W base past the 4 consumed words
    add di, 16
    cmp di, sha256_w + 256                 ; 64 words processed?
    jne .round

    ; ---- state += a..h ----
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
