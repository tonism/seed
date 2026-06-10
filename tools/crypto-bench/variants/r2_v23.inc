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
; r2_v23  (parent: r1_v7) -- streamlined message schedule.
;
; Inherits r1_v7's fixed-shift inline-rotate sigmas (each reads its word
; once into dx:ax and chains hardcoded rotates, XOR-accumulating in regs).
; THIS variant rewrites the word-16..63 schedule extension:
;   * both small sigmas are INLINED into the loop -> no call/ret per word
;     (was 2 call/ret pairs x 48 words) and no sha256_tmp spill: each shift
;     term re-reads its source straight from the still-live W slot;
;   * the s0+w[-7]+w[-16] partial is held in bp:bx ACROSS the s1 computation
;     (s1's inline form uses cx:si as its private accumulator and never
;     touches bp/cx via byte-rotate), so the partial never spills -- the old
;     sha256_t1 round-trip is gone. Net: the schedule's only memory ops are
;     the W source reads and the single final result write per word.
;
; The big-sigma helpers + per-round SHA_RND macro are unchanged from r1_v7.
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

; SHA_RND a,b,c,d,e,f,g,h, newa_slot, newe_slot
; One SHA-256 round operating on fixed memory slots (no shuffle). Computes
;   T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i]
;   T2 = S0(a) + Maj(a,b,c)
; then writes new_e = d + T1 to %10 and new_a = T1 + T2 to %9. %9 aliases the
; old 'd' slot and %10 the old 'h' slot, both already consumed, so the writes
; are safe. Advances the W and K running pointers by 4.
%macro SHA_RND 10
    ; Ch(e,f,g) = g ^ (e & (f ^ g)) -> stash in t1
    mov ax, [%6]
    xor ax, [%7]
    and ax, [%5]
    xor ax, [%7]
    mov [sha256_t1], ax
    mov ax, [%6 + 2]
    xor ax, [%7 + 2]
    and ax, [%5 + 2]
    xor ax, [%7 + 2]
    mov [sha256_t1 + 2], ax
    ; S1(e) into dx:ax, then accumulate Ch + h + K + W in registers
    mov ax, [%5]
    mov dx, [%5 + 2]
    call sha256_big_sigma1_dxax
    add ax, [sha256_t1]
    adc dx, [sha256_t1 + 2]
    add ax, [%8]
    adc dx, [%8 + 2]
    add ax, [si]                  ; + K[i]  (si = running K pointer)
    adc dx, [si + 2]
    add ax, [di]                  ; + W[i]  (di = running W pointer)
    adc dx, [di + 2]
    mov [sha256_t1], ax           ; T1 stored once
    mov [sha256_t1 + 2], dx
    ; Maj(a,b,c) = (a & (b^c)) ^ (b&c) -> stash in t2
    mov ax, [%2]
    mov bx, ax
    xor ax, [%3]
    and ax, [%1]
    and bx, [%3]
    xor ax, bx
    mov [sha256_t2], ax
    mov ax, [%2 + 2]
    mov bx, ax
    xor ax, [%3 + 2]
    and ax, [%1 + 2]
    and bx, [%3 + 2]
    xor ax, bx
    mov [sha256_t2 + 2], ax
    ; S0(a) into dx:ax, + Maj -> T2 ; keep T2 in bp:bx (regs free after sigma)
    mov ax, [%1]
    mov dx, [%1 + 2]
    call sha256_big_sigma0_dxax
    add ax, [sha256_t2]
    adc dx, [sha256_t2 + 2]
    mov bp, dx                     ; bp:bx = T2 (avoids storing/reloading T2)
    mov bx, ax
    ; new_e = d + T1 -> %10 (must read d=%4 before %9 write clobbers it)
    mov ax, [%4]
    mov dx, [%4 + 2]
    add ax, [sha256_t1]
    adc dx, [sha256_t1 + 2]
    mov [%10], ax
    mov [%10 + 2], dx
    ; new_a = T1 + T2 -> %9  (T2 from bp:bx)
    mov ax, bx
    mov dx, bp
    add ax, [sha256_t1]
    adc dx, [sha256_t1 + 2]
    mov [%9], ax
    mov [%9 + 2], dx
    ; advance running K and W pointers (si=K, di=W) by one 32-bit word
    add si, 4
    add di, 4
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

; (small sigma0/sigma1 helpers removed: the message schedule now inlines them
;  directly, so no callable helper is needed. The big-sigma helpers below are
;  still called per-round by SHA_RND.)

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

    ; ---- extend schedule words 16..63 (INLINED sigmas, no calls/tmp spill) ----
    ; di points at sha256_w + 64 (word 16). For each new word:
    ;   w = s1(w[-2]) + w[-7] + s0(w[-15]) + w[-16]
    ; Both small-sigma helpers are inlined here so the running W pointer (di)
    ; stays put across the whole body: no call/ret per word, and the shift-term
    ; source is RE-READ straight from its W slot ([di-6]/[di-58]) instead of
    ; spilling/reloading sha256_tmp (those slots are not overwritten until the
    ; [di] store, which is a different address). bp:bx = rotate XOR accumulator,
    ; cx = byte-rotate scratch (same convention as the helper macros).
    ; Register plan across the body (di = running W ptr, held throughout):
    ;   dx:ax = current working word ; bp:bx = the PARTIAL accumulator that must
    ;   survive both sigmas ; cx:si = s1's private XOR accumulator. s0 is computed
    ;   FIRST into bp:bx-as-partial; s1 then uses cx:si (it touches neither bp:bx
    ;   nor cx in its inlined form, so the partial is safe). This removes the
    ;   sha256_t1 / [di] partial round-trip entirely -- the partial never leaves
    ;   registers, so the only schedule memory ops are the W source reads and the
    ;   single final [di] result write.
    mov byte [sha256_schedule_count], 48
.schedule:
    ; ---- s0(w[-15]) = rotr7 ^ rotr18 ^ shr3  -> dx:ax ----
    mov ax, [di - 60]
    mov dx, [di - 58]
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
    ; shr3 on original source (re-read from its W slot)
    mov ax, [di - 60]
    mov dx, [di - 58]
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    xor ax, bx
    xor dx, bp                  ; dx:ax = s0(w[-15])
    ; fold the cheap memory terms in NOW, then park the partial in bp:bx
    add ax, [di - 28]           ; + w[-7]
    adc dx, [di - 26]
    add ax, [di - 64]           ; + w[-16]
    adc dx, [di - 62]
    mov bp, dx                  ; bp:bx = s0(w[-15]) + w[-7] + w[-16]  (the partial)
    mov bx, ax
    ; ---- s1(w[-2]) = rotr17 ^ rotr19 ^ shr10  -> dx:ax (acc in cx:si) ----
    mov ax, [di - 8]
    mov dx, [di - 6]
    ROR32_1                     ; +17 -> rotr17
    ROR32_16
    mov cx, dx
    mov si, ax                  ; cx:si = rotr17  (private acc, leaves bp:bx alone)
    ROR32_1                     ; +2 -> rotr19
    ROR32_1
    xor si, ax
    xor cx, dx
    ; shr10 = shr8 + shr2 on the original source (re-read from its W slot)
    mov ax, [di - 8]
    mov dx, [di - 6]
    mov al, ah                  ; shr8 logical: al<-ah, ah<-dl, dl<-dh, dh<-0
    mov ah, dl
    mov dl, dh
    xor dh, dh
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    xor ax, si
    xor dx, cx                  ; dx:ax = s1(w[-2])
    ; + the partial held in bp:bx -> final word
    add ax, bx
    adc dx, bp
    mov [di], ax
    mov [di + 2], dx
    add di, 4
    dec byte [sha256_schedule_count]
    jnz .schedule

    ; ---- working vars a..h <- state ----
    mov si, sha256_state
    mov di, sha256_a
    mov cx, 16
    rep movsw

    ; si = running K pointer, di = running W pointer (both survive sigma calls)
    mov si, sha256_k
    mov di, sha256_w
    mov byte [sha256_round_count], 16     ; 16 iterations x 4 unrolled sub-rounds
.round:
    ; Four sub-rounds with the a..h ring renamed in fixed memory slots, so no
    ; per-round state shuffle / copies happen at all. The ring of {a,b,c,d} and
    ; {e,f,g,h} each have period 4, so after 4 sub-rounds the names realign and
    ; the loop body can repeat. new_a is written to the slot the dropped 'd'
    ; vacates; new_e to the slot the dropped 'h' vacates.
    SHA_RND sha256_a, sha256_b, sha256_c, sha256_d, sha256_e, sha256_f, sha256_g, sha256_h, sha256_d, sha256_h
    SHA_RND sha256_d, sha256_a, sha256_b, sha256_c, sha256_h, sha256_e, sha256_f, sha256_g, sha256_c, sha256_g
    SHA_RND sha256_c, sha256_d, sha256_a, sha256_b, sha256_g, sha256_h, sha256_e, sha256_f, sha256_b, sha256_f
    SHA_RND sha256_b, sha256_c, sha256_d, sha256_a, sha256_f, sha256_g, sha256_h, sha256_e, sha256_a, sha256_e
    dec byte [sha256_round_count]
    jnz .round

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
