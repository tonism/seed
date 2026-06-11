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

; r3_v32 (state base pointer; shave [disp16] address recomputation):
; The a..h working variables occupy 8 consecutive 32-bit slots
; (sha256_a .. sha256_a+28), so EVERY one is reachable as [si + (slot -
; sha256_a)] with a disp8. On the 8088 a word ALU op with a disp8 base is a
; 3-byte instruction (bus = 4*(3+2) = 20 cyc) vs a 4-byte [disp16] direct
; (24 cyc): a flat 4 cyc saved on each of the ~22 state operands per sub-round.
; So `si` is repurposed from the K pointer to a FIXED state base (= sha256_a,
; never advanced). `di` stays the advancing W pointer, and K[i] -- at the SAME
; index as W[i] but in a different array -- is reached as [di + (sha256_k -
; sha256_w) + off]; that one is a disp16 (24 cyc, the only operand that gets
; *slower*, +4 cyc x 2 reads/sub-round), but it is far outweighed by the 22
; state operands that drop to 20. Net ~ -80 cyc / sub-round x 64.
%define SS(slot)  (si + (slot) - sha256_a)      ; state word via the si base
%define KK(off)   (di + (sha256_k - sha256_w) + (off))  ; K[i] via the di (W) base
%define WW(off)   (di + (off))                          ; W[i] via the di base

; SHA_RND a,b,c,d,e,f,g,h, newa_slot, newe_slot, kw_off
; One SHA-256 round operating on fixed memory slots (no shuffle). Computes
;   T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i]
;   T2 = S0(a) + Maj(a,b,c)
; then writes new_e = d + T1 to %10 and new_a = T1 + T2 to %9. %9 aliases the
; old 'd' slot and %10 the old 'h' slot, both already consumed, so the writes
; are safe. K[i]/W[i] are at the sub-round byte offset %11 (0,4,8,12); W via the
; running di pointer (advanced by 16 once per OUTER loop), K via di + the fixed
; K-W array delta. State slots are addressed off the fixed si = sha256_a base.
;
; The two big sigmas are inlined (no call/ret); Ch and Maj are folded straight
; into the dx:ax accumulator (no t1/t2 memory temp). The ONLY value still
; spilled per sub-round is T1 (a stack push/pop pair), because the inlined S0
; needs dx:ax and the 8086 GP file cannot hold a third 32-bit live value
; alongside the rotate accumulator (bx:bp). g (in Ch) is cached in cx so it is
; read from memory once per half, not twice.
%macro SHA_RND 11
    ; --- S1(e) into dx:ax (inlined sigma) ---
    mov ax, [SS(%5)]
    mov dx, [SS(%5) + 2]
    SIGMA1_INLINE                 ; dx:ax = S1(e); bx,bp,cx now free
    ; --- fold Ch(e,f,g) = g ^ (e & (f^g)) directly into dx:ax (no t1 spill) ---
    ; Both halves computed into regs FIRST, so the 32-bit add..adc is contiguous
    ; (intervening mov/xor/and would clobber the carry between the halves). g is
    ; cached in cx so it is read from memory once per half, not twice.
    mov cx, [SS(%7)]              ; cx = g.lo
    mov bx, [SS(%6)]
    xor bx, cx
    and bx, [SS(%5)]
    xor bx, cx                    ; bx = Ch.lo
    mov cx, [SS(%7) + 2]          ; cx = g.hi
    mov bp, [SS(%6) + 2]
    xor bp, cx
    and bp, [SS(%5) + 2]
    xor bp, cx                    ; bp = Ch.hi
    add ax, bx
    adc dx, bp                    ; dx:ax = S1 + Ch
    ; --- + h + K[i] + W[i] -> T1 ---
    add ax, [SS(%8)]
    adc dx, [SS(%8) + 2]
    add ax, [KK(%11)]             ; + K[i]  (di = W base; K = di + array delta)
    adc dx, [KK(%11) + 2]
    add ax, [WW(%11)]             ; + W[i]  (di = W base; %11 = sub-round offset)
    adc dx, [WW(%11) + 2]         ; dx:ax = T1
    ; --- spill T1 once on the STACK (S0 below needs dx:ax); a push/pop pair is
    ; ~12 cyc each vs a ~20/24 cyc direct-memory store/reload. new_e = d + T1 is
    ; done first while T1 is still live in dx:ax (no reload for new_e). ---
    push dx                       ; [sp] = T1.hi
    push ax                       ; [sp] = T1.lo  (top)
    add ax, [SS(%4)]              ; + d  (read d before its slot %9 is overwritten)
    adc dx, [SS(%4) + 2]
    mov [SS(%10)], ax             ; new_e -> %10 (old h slot; h already consumed)
    mov [SS(%10) + 2], dx
    ; --- T2 = S0(a) + Maj(a,b,c) ---
    mov ax, [SS(%1)]
    mov dx, [SS(%1) + 2]
    SIGMA0_INLINE                 ; dx:ax = S0(a); bx,bp,cx free
    ; fold Maj = (a & (b^c)) ^ (b&c) directly into dx:ax (no t2 spill).
    ; Both halves into regs first (bp=lo, bx=hi) so add..adc stays contiguous.
    mov bx, [SS(%2)]
    mov cx, bx
    xor bx, [SS(%3)]
    and bx, [SS(%1)]
    and cx, [SS(%3)]
    xor bx, cx                    ; bx = Maj.lo
    mov bp, bx                    ; bp = Maj.lo
    mov bx, [SS(%2) + 2]
    mov cx, bx
    xor bx, [SS(%3) + 2]
    and bx, [SS(%1) + 2]
    and cx, [SS(%3) + 2]
    xor bx, cx                    ; bx = Maj.hi
    add ax, bp
    adc dx, bx                    ; dx:ax = T2
    ; --- new_a = T1 + T2 -> %9 (old d slot); pop T1 back off the stack ---
    pop bx                        ; bx = T1.lo
    pop bp                        ; bp = T1.hi
    add ax, bx
    adc dx, bp
    mov [SS(%9)], ax
    mov [SS(%9) + 2], dx
    ; (di advanced by 16 once per outer loop, not here; si is the fixed state base)
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
; %1 = the source word's low-half memory operand (e.g. di - 60). The original
; source is RE-READ from there for the shr3 term instead of round-tripping
; sha256_tmp: in the schedule loop the source still lives at a fixed di-relative
; slot (disp8, 20 cyc) so no spill/reload to a far [disp16] temp is needed.
%macro SSIG0_INLINE 1
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
    ; shr3 (logical right 3) on the original source (re-read from %1)
    mov ax, [%1]
    mov dx, [%1 + 2]
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
; %1 = source word's low-half memory operand (e.g. di - 8); re-read for shr10.
%macro SSIG1_INLINE 1
    ROR32_1                     ; +17 -> rotr17
    ROR32_16
    mov bp, dx
    mov bx, ax                  ; acc = rotr17
    ROR32_1                     ; +2 -> rotr19
    ROR32_1
    xor bx, ax
    xor bp, dx
    ; shr10 = shr8 + shr2 on the original source (re-read from %1)
    mov ax, [%1]
    mov dx, [%1 + 2]
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
    ; big-endian load: read each 16-bit half with one lodsw (2 bus accesses)
    ; then xchg the bytes, instead of four single-byte lodsb (12 cyc apiece).
    lodsw                         ; al=B0, ah=B1
    xchg al, ah                   ; ax = (B0<<8)|B1  (big-endian high half)
    mov [di + 2], ax
    lodsw                         ; al=B2, ah=B3
    xchg al, ah                   ; ax = (B2<<8)|B3  (big-endian low half)
    mov [di], ax
    add di, 4
    loop .load_word

    ; ---- extend schedule words 16..63 ----
    ; di points at sha256_w + 64 (word 16). For each new word:
    ;   w = s1(w[-2]) + w[-7] + s0(w[-15]) + w[-16]
    mov byte [sha256_schedule_count], 48
.schedule:
    ; s1(w[-2]) : w[-2] is at di-8 (read directly via di; si is the W-base spare)
    mov ax, [di - 8]
    mov dx, [di - 6]
    SSIG1_INLINE di - 8           ; inlined small sigma 1 (source re-read from di-8)
    ; add w[-7] (at di-28)
    add ax, [di - 28]
    adc dx, [di - 26]
    ; stash partial on the STACK instead of round-tripping sha256_t1 in memory
    ; (two pushes ~24 cyc + two pops ~24 vs a 92-cyc store+reload to [t1]).
    ; Popped AFTER SSIG0 (which clobbers bx/bp/cx) into now-free bx/cx.
    push dx
    push ax
    ; s0(w[-15]) : at di-60
    mov ax, [di - 60]
    mov dx, [di - 58]
    SSIG0_INLINE di - 60          ; inlined small sigma 0 (source re-read from di-60)
    pop cx                        ; cx = partial.lo (pushed last = top)
    pop bx                        ; bx = partial.hi
    add ax, cx
    adc dx, bx
    ; add w[-16] (at di-64)
    add ax, [di - 64]
    adc dx, [di - 62]
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

    ; si = FIXED state base (sha256_a); di = running W pointer. K[i] is reached
    ; as di + (sha256_k - sha256_w) + off, so only ONE pointer advances per round.
    mov si, sha256_a
    mov di, sha256_w
    mov byte [sha256_round_count], 16     ; 16 iterations x 4 unrolled sub-rounds
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
    add di, 16                            ; advance W base past the 4 consumed words (si is fixed)
    dec byte [sha256_round_count]
    jnz .round

    ; ---- state += a..h ----
    ; Unrolled with fixed disp8 offsets off two bases (no per-iter loop/add-ptr
    ; overhead). a..h are 8 consecutive words at sha256_a; state at sha256_state.
    mov si, sha256_a
    mov di, sha256_state
%assign off 0
%rep 8
    mov ax, [si + off]
    add [di + off], ax
    mov ax, [si + off + 2]
    adc [di + off + 2], ax
%assign off off + 4
%endrep
    clc
    ret
