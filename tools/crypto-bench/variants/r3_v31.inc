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

; --- Inlined Big Sigma 1: rotr6 ^ rotr11 ^ rotr25 of dx:ax -> dx:ax.
; Uses bx,bp (XOR accumulator) and cx (byte-rotate scratch); si/di untouched.
; Same chain as the former sha256_big_sigma1_dxax subroutine, inlined so no
; call/ret overhead and so the round can keep Ch/h/K/W accumulation in regs.
%macro SIGMA1_INLINE 0
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
%endmacro

; --- Inlined Big Sigma 0: rotr2 ^ rotr13 ^ rotr22 of dx:ax -> dx:ax. ---
%macro SIGMA0_INLINE 0
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
%endmacro

; SHA_RND a,b,c,d,e,f,g,h, newa_slot, newe_slot, kw_off
; One SHA-256 round operating on fixed memory slots (no shuffle). Computes
;   T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i]
;   T2 = S0(a) + Maj(a,b,c)
; then writes new_e = d + T1 to %10 and new_a = T1 + T2 to %9. %9 aliases the
; old 'd' slot and %10 the old 'h' slot, both already consumed, so the writes
; are safe. K[i]/W[i] are addressed as [si+%11]/[di+%11] where %11 is the
; sub-round's constant byte offset (0,4,8,12); the running si/di pointers are
; advanced once per OUTER loop (by 16) instead of per sub-round, saving the
; per-sub-round add/inc pair.
;
; r2_v22 (push register residency): the two big sigmas are now inlined (no
; call/ret). Because no call clobbers registers mid-round, Ch and Maj are folded
; straight into the dx:ax accumulator instead of round-tripping through the
; sha256_t1/sha256_t2 memory temporaries (a memory ALU op is ~24 cyc vs ~8 for a
; register one). The ONLY value still spilled per sub-round is T1 (a stack
; push/pop pair), because the inlined S0 needs dx:ax and the 8086 GP file cannot
; hold a third 32-bit live value alongside the rotate accumulator (bx:bp). g (in
; Ch) is also cached in cx so it is read from memory once per half, not twice.
%macro SHA_RND 11
    ; --- S1(e) into dx:ax (inlined sigma) ---
    mov ax, [%5]
    mov dx, [%5 + 2]
    SIGMA1_INLINE                 ; dx:ax = S1(e); bx,bp,cx now free
    ; --- fold Ch(e,f,g) = g ^ (e & (f^g)) directly into dx:ax (no t1 spill) ---
    ; Both halves computed into regs FIRST, so the 32-bit add..adc is contiguous
    ; (intervening mov/xor/and would clobber the carry between the halves). g is
    ; cached in cx so it is read from memory once per half, not twice.
    mov cx, [%7]                  ; cx = g.lo
    mov bx, [%6]
    xor bx, cx
    and bx, [%5]
    xor bx, cx                    ; bx = Ch.lo
    mov cx, [%7 + 2]              ; cx = g.hi
    mov bp, [%6 + 2]
    xor bp, cx
    and bp, [%5 + 2]
    xor bp, cx                    ; bp = Ch.hi
    add ax, bx
    adc dx, bp                    ; dx:ax = S1 + Ch
    ; --- + h + K[i] + W[i] -> T1 ---
    add ax, [%8]
    adc dx, [%8 + 2]
    add ax, [si + %11]            ; + K[i]  (si = K base; %11 = sub-round offset)
    adc dx, [si + %11 + 2]
    add ax, [di + %11]            ; + W[i]  (di = W base; %11 = sub-round offset)
    adc dx, [di + %11 + 2]        ; dx:ax = T1
    ; --- spill T1 once on the STACK (S0 below needs dx:ax); a push/pop pair is
    ; ~12 cyc each vs a ~20/24 cyc direct-memory store/reload. new_e = d + T1 is
    ; done first while T1 is still live in dx:ax (no reload for new_e). ---
    push dx                       ; [sp] = T1.hi
    push ax                       ; [sp] = T1.lo  (top)
    add ax, [%4]                  ; + d  (read d before its slot %9 is overwritten)
    adc dx, [%4 + 2]
    mov [%10], ax                 ; new_e -> %10 (old h slot; h already consumed)
    mov [%10 + 2], dx
    ; --- T2 = S0(a) + Maj(a,b,c) ---
    mov ax, [%1]
    mov dx, [%1 + 2]
    SIGMA0_INLINE                 ; dx:ax = S0(a); bx,bp,cx free
    ; fold Maj = (a & (b^c)) ^ (b&c) directly into dx:ax (no t2 spill).
    ; Both halves into regs first (bp=lo, bx=hi) so add..adc stays contiguous.
    mov bx, [%2]
    mov cx, bx
    xor bx, [%3]
    and bx, [%1]
    and cx, [%3]
    xor bx, cx                    ; bx = Maj.lo
    mov bp, bx                    ; bp = Maj.lo
    mov bx, [%2 + 2]
    mov cx, bx
    xor bx, [%3 + 2]
    and bx, [%1 + 2]
    and cx, [%3 + 2]
    xor bx, cx                    ; bx = Maj.hi
    add ax, bp
    adc dx, bx                    ; dx:ax = T2
    ; --- new_a = T1 + T2 -> %9 (old d slot); pop T1 back off the stack ---
    pop bx                        ; bx = T1.lo
    pop bp                        ; bp = T1.hi
    add ax, bx
    adc dx, bp
    mov [%9], ax
    mov [%9 + 2], dx
    ; (si/di are advanced by 16 once per outer loop, not here)
%endmacro

; All sigma helpers take the source word in dx:ax and return the result in
; dx:ax. The three rotation terms are computed as a CHAIN: each rotation builds
; on the previous (rotr_b = rotr_a then rotr_(b-a)), so no source reload or
; memory spill is needed for the rotation part (the running XOR accumulator
; lives in bp:bx). The small sigmas' shift term still needs the original word,
; so they spill it once to sha256_tmp. si/di are preserved (they carry the K/W
; pointers across calls); cx is transient byte-rotate scratch. Chain deltas and
; their minimal fixed-rotate sequences were chosen by a shortest-path search.

; (All FOUR sigmas are now inlined as macros -- the two big ones into SHA_RND,
; the two small ones into the schedule loop -- so no per-word call/ret overhead.)

; --- small sigma 0: rotr7 ^ rotr18 ^ shr3 (dx:ax -> dx:ax) ---
; r3_v31: the original word (needed for the shr term) is parked on the STACK
; across the rotate chain instead of in [sha256_tmp]. push/pop (~54 cyc) beats the
; four fixed-address memory ops the [sha256_tmp] store+reload cost (~76 cyc). The
; macro is stack-balanced and contains no call, so it nests inside the schedule
; loop's own push/pop of its running partial.
%macro SSIG0_INLINE 0
    push dx                      ; save source (for the shr3 term)
    push ax
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
    pop ax
    pop dx
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1
    xor ax, bx
    xor dx, bp
%endmacro

; --- small sigma 1: rotr17 ^ rotr19 ^ shr10 (dx:ax -> dx:ax) ---
%macro SSIG1_INLINE 0
    push dx                      ; save source (for the shr10 term)
    push ax
    ROR32_1                     ; +17 -> rotr17
    ROR32_16
    mov bp, dx
    mov bx, ax                  ; acc = rotr17
    ROR32_1                     ; +2 -> rotr19
    ROR32_1
    xor bx, ax
    xor bp, dx
    ; shr10 = shr8 + shr2 on the original source
    pop ax
    pop dx
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
%endmacro

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
    ; r3_v31 (recombine r2_v25 loop control onto r2_v22's inlined-sigma body):
    ; di is the ONLY address pointer in this loop and the inlined small sigmas
    ; preserve si, so si is free to hold the counter. A register dec/jnz is ~4 cyc
    ; vs ~24 for dec byte [mem] x48 iterations.
    mov si, 48
.schedule:
    ; s1(w[-2]) : w[-2] is at di-8 (read directly via di; si is the W-base spare)
    mov ax, [di - 8]
    mov dx, [di - 6]
    SSIG1_INLINE                  ; inlined small sigma 1 (no call/ret)
    ; add w[-7] (at di-28)
    add ax, [di - 28]
    adc dx, [di - 26]
    ; r3_v31: park the partial (s1(w[-2]) + w[-7]) on the STACK across the SSIG0
    ; macro instead of in [sha256_t1]. SSIG0 clobbers every GP reg, so the partial
    ; must cross it somewhere; a push/pop pair (~30 cyc) beats the 4 fixed-address
    ; memory ops the [sha256_t1] store+reload cost (~76 cyc). No call sits between
    ; the push and the pop, so the stack stays balanced.
    push dx
    push ax
    ; s0(w[-15]) : at di-60
    mov ax, [di - 60]
    mov dx, [di - 58]
    SSIG0_INLINE                  ; inlined small sigma 0 (no call/ret)
    pop bx                        ; bx = partial.lo
    pop bp                        ; bp = partial.hi
    add ax, bx
    adc dx, bp
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

    ; si = running K pointer, di = running W pointer (both survive the inlined
    ; sigmas). The loop ends when di walks past the 64-word schedule (16 groups of
    ; 4); a register pointer-compare is cheaper than a dec byte [mem] counter
    ; (recombined from r2_v25's loop control).
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
    add si, 16                            ; advance K base past the 4 consumed words
    add di, 16                            ; advance W base past the 4 consumed words
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
