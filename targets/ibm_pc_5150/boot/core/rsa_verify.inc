; RSA-2048 signature verify: rsa_result = rsa_sig^65537 mod rsa_n
; CIOS Montgomery multiplication, n = 128 limbs, base b = 2^16, e = 65537.
; Variant: the 16 squarings use a dedicated SOS Montgomery SQUARING (montsqr)
; that exploits a^2 symmetry (off-diagonal products computed once then doubled),
; ~halving the multiply-phase MULs vs the generic montmul. The 3 genuine
; products still use the CIOS montmul. Testbench only (correctness-gated).
cpu 8086

%define RSA_N_LIMBS 128

; --------------------------------------------------------------------------
; rsa_verify  --  no args. Reads rsa_sig/rsa_n/rsa_r2/rsa_one/rsa_n0inv,
; writes rsa_result = rsa_sig^65537 mod rsa_n.
;
;   sm  = montmul(sig, r2)        ; enter Montgomery domain: s*R mod N (stored in rsa_result)
;   x   = sm
;   16x: x = montsqr(x)           ; x = sm^(2^16)
;   x   = montmul(x, sm)          ; x = sm^65537
;   result = montmul(x, one)      ; leave domain
; --------------------------------------------------------------------------
rsa_verify:
    ; sm = montmul(sig, r2)
    mov     si, rsa_sig
    mov     bx, rsa_r2
    mov     di, rsa_result
    call    montmul

    ; x = sm  (copy 128 limbs)
    mov     si, rsa_result
    mov     di, rsa_x
    mov     cx, RSA_N_LIMBS
    cld
    rep     movsw

    ; repeat 16 times: x = montsqr(x)
    mov     cx, 16
.sq_loop:
    push    cx
    mov     si, rsa_x               ; in/out operand
    mov     di, rsa_x
    call    montsqr
    pop     cx
    loop    .sq_loop

    ; x = montmul(x, sm)
    mov     si, rsa_x
    mov     bx, rsa_result
    mov     di, rsa_x
    call    montmul

    ; result = montmul(x, one)
    mov     si, rsa_x
    mov     bx, rsa_one
    mov     di, rsa_result
    call    montmul

    ret


; ==========================================================================
; montmul  --  u = a * b * R^-1 mod N   (CIOS), n = 128 limbs.
;   in:  SI = ptr a, BX = ptr b, DI = ptr u  (each 128 LE 16-bit limbs)
;   uses rsa_t (accumulator t[0..n+1]), rsa_n0inv, rsa_n.
;   clobbers all GP regs; caller reloads pointers.
;
; The 32-bit core step  full = word + w1*w2 + C  on 8086:
;     mov ax,w1 ; mul w2  (-> DX:AX) ; add ax,word ; adc dx,0 ; add ax,C ; adc dx,0
; store AX as the low word, keep DX as the new carry C.
;
; Stack frame (BP-relative locals):
;   [bp-2]  ptr a
;   [bp-4]  ptr b (base; indexed by i)
;   [bp-6]  ptr u (output)
;   [bp-8]  bi   = b[i] (current multiplier limb)
;   [bp-10] mm   = m    (reduction multiplier)
;   [bp-12] icnt = outer loop counter (down from 128)
;
; Register use inside the inner loops:
;   SI = walking pointer into a[] / n[]
;   DI = walking pointer into t[]
;   BX = carry C
;   CX = inner loop counter
;   DX:AX = mul scratch
; ==========================================================================
montmul:
    push    bp
    mov     bp, sp
    sub     sp, 12
    mov     [bp-2], si              ; ptr a
    mov     [bp-4], bx              ; ptr b
    mov     [bp-6], di              ; ptr u

    ; ---- t[0..n+1] = 0   (n+2 words) ----
    mov     di, rsa_t
    xor     ax, ax
    mov     cx, RSA_N_LIMBS + 2
    cld
    rep     stosw

    ; ---- outer loop: for i in 0..n-1 ----
    mov     word [bp-12], RSA_N_LIMBS

.outer:
    ; bi = b[i]
    mov     si, [bp-4]
    mov     ax, [si]
    mov     [bp-8], ax
    add     word [bp-4], 2          ; advance b ptr for next i

    ; -------- multiply phase: t += a * b[i] --------
    ; C = 0
    xor     bx, bx                  ; C
    mov     si, [bp-2]              ; si -> a[0]
    mov     di, rsa_t               ; di -> t[0]
    mov     cx, RSA_N_LIMBS
.mul_loop:
    ; full = t[j] + a[j]*bi + C
    mov     ax, [si]                ; a[j]
    mul     word [bp-8]             ; DX:AX = a[j]*bi
    add     ax, [di]                ; + t[j]
    adc     dx, 0
    add     ax, bx                  ; + C
    adc     dx, 0
    mov     [di], ax                ; t[j] = low
    mov     bx, dx                  ; C = high
    add     si, 2
    add     di, 2
    loop    .mul_loop
    ; full = t[n] + C ; t[n] = low ; t[n+1] = high
    ; di now points at t[n]
    mov     ax, [di]                ; t[n]
    add     ax, bx
    mov     [di], ax                ; t[n] = low
    mov     ax, 0
    adc     ax, 0                   ; high (carry-out of the add)
    mov     [di+2], ax              ; t[n+1] = high

    ; -------- reduction phase --------
    ; m = (t[0] * n0inv) & 0xFFFF
    mov     ax, [rsa_t]             ; t[0]
    mul     word [rsa_n0inv]        ; DX:AX = t[0]*n0inv ; keep low (AX)
    mov     [bp-10], ax             ; m

    ; full = t[0] + m*n[0] ; low word becomes 0 ; C = high
    mov     ax, [rsa_n]             ; n[0]
    mul     word [bp-10]            ; DX:AX = m*n[0]
    add     ax, [rsa_t]             ; + t[0]
    adc     dx, 0
    ; ax (low) is discarded (it is the now-zeroed word); C = dx
    mov     bx, dx                  ; C

    ; for j in 1..n-1: full = t[j] + m*n[j] + C ; t[j-1] = low ; C = high
    mov     si, rsa_n + 2           ; si -> n[1]
    mov     di, rsa_t + 2           ; di -> t[1]
    mov     cx, RSA_N_LIMBS - 1
.red_loop:
    mov     ax, [si]                ; n[j]
    mul     word [bp-10]            ; DX:AX = m*n[j]
    add     ax, [di]                ; + t[j]
    adc     dx, 0
    add     ax, bx                  ; + C
    adc     dx, 0
    mov     [di-2], ax              ; t[j-1] = low
    mov     bx, dx                  ; C = high
    add     si, 2
    add     di, 2
    loop    .red_loop
    ; di -> t[n] now.  full = t[n] + C ; t[n-1] = low ; t[n] = t[n+1] + high
    mov     ax, [di]                ; t[n]
    add     ax, bx
    mov     [di-2], ax              ; t[n-1] = low
    mov     ax, 0
    adc     ax, 0                   ; high (carry-out)
    add     ax, [di+2]              ; + t[n+1]
    mov     [di], ax                ; t[n] = t[n+1] + high

    ; ---- end outer iteration ----
    dec     word [bp-12]
    jnz     .outer

    ; ======================================================================
    ; conditional subtract of N + copy result -> u  (shared cond_sub_copy):
    ;   result low limb is t[0]; the top carry word is t[n].
    ; ======================================================================
    mov     bx, rsa_t               ; t_base -> t[0]
    mov     dx, [bp-6]              ; out ptr u
    call    cond_sub_copy

    mov     sp, bp
    pop     bp
    ret


; ==========================================================================
; montsqr  --  u = a * a * R^-1 mod N   (SOS), n = 128 limbs.
;   in:  SI = ptr a, DI = ptr u  (each 128 LE 16-bit limbs)
;   uses rsa_t (260-word product/accumulator), rsa_n0inv, rsa_n.
;   clobbers all GP regs; caller reloads pointers.
;
; Two phases:
;   (1) full integer square  P = a^2  into rsa_t[0..2n-1]  (256 words):
;         A) off-diagonal sum  S = sum_{i<j} a[i]*a[j] * b^(i+j),  each product
;            computed ONCE, accumulated into t.
;         B) double it:  t <<= 1   (one left shift of the whole 256+ word value).
;         C) add the diagonal squares  a[i]^2 at position 2i  (each once).
;       Now t[0..2n-1] = (2*S) + (sum a[i]^2 * b^2i) = a^2.
;   (2) SOS Montgomery reduction of the 256-word product mod N, then the
;       conditional subtract of N.  Result -> u.
;
; The 32-bit core step  full = word + w1*w2 + C  is the same as montmul.
;
; Stack frame (BP-relative locals):
;   [bp-2]  ptr a
;   [bp-4]  ptr u (output)
;   [bp-6]  ai   = a[i] (current multiplier limb)
;   [bp-8]  mm   = m    (reduction multiplier)
;   [bp-10] icnt = outer loop counter / current i
;   [bp-12] ibase= byte offset of t[i] for the current reduction row
; ==========================================================================
montsqr:
    push    bp
    mov     bp, sp
    sub     sp, 12
    mov     [bp-2], si              ; ptr a
    mov     [bp-4], di              ; ptr u

    ; ---- t[0..2n+3] = 0   (2n+4 words; clears product + guard words) ----
    mov     di, rsa_t
    xor     ax, ax
    mov     cx, RSA_N_LIMBS*2 + 4
    cld
    rep     stosw

    ; ======================================================================
    ; (1A) off-diagonal sum:  for i in 0..n-2:  t[2i+1 ..] += a[i]*a[i+1..n-1]
    ;   row i lands its first product at t[i+(i+1)] = t[2i+1].
    ; ======================================================================
    mov     word [bp-10], 0         ; i = 0
.od_outer:
    ; ai = a[i]
    mov     si, [bp-2]
    mov     bx, [bp-10]             ; i
    add     si, bx
    add     si, bx                  ; si -> a[i]  (a + 2i)
    mov     ax, [si]
    mov     [bp-6], ax              ; ai
    add     si, 2                   ; si -> a[i+1]  (first off-diagonal partner)

    ; di -> t[2i+1]  = rsa_t + 2*(2i+1) = rsa_t + 4i + 2
    mov     di, [bp-10]
    add     di, di                  ; 2i
    add     di, di                  ; 4i
    add     di, rsa_t
    add     di, 2                   ; rsa_t + 4i + 2  -> t[2i+1]

    ; inner count = (n-1) - i   (partners j = i+1 .. n-1)
    mov     cx, RSA_N_LIMBS - 1
    sub     cx, [bp-10]             ; cx = (n-1) - i

    xor     bx, bx                  ; C = 0
.od_inner:
    ; full = t[k] + a[j]*ai + C
    mov     ax, [si]                ; a[j]
    mul     word [bp-6]             ; DX:AX = a[j]*ai
    add     ax, [di]                ; + t[k]
    adc     dx, 0
    add     ax, bx                  ; + C
    adc     dx, 0
    mov     [di], ax                ; t[k] = low
    mov     bx, dx                  ; C = high
    add     si, 2
    add     di, 2
    loop    .od_inner

    ; propagate the final carry C up from the current word t[k] (di) while != 0
    call    carry_up                ; in: di -> word, bx = carry

.od_next:
    inc     word [bp-10]            ; i++
    mov     ax, [bp-10]
    cmp     ax, RSA_N_LIMBS - 1     ; loop while i <= n-2  (i.e. i < n-1)
    jb      .od_outer

    ; ======================================================================
    ; (1B) double the off-diagonal sum:  t[0..2n] <<= 1
    ;   (2*S < a^2 < b^2n, so it fits; we shift through t[2n] guard for safety)
    ; ======================================================================
    mov     di, rsa_t
    mov     cx, RSA_N_LIMBS*2 + 1   ; shift t[0 .. 2n]
    clc
.dbl_loop:
    rcl     word [di], 1            ; shift in the previous carry, carry out -> CF
    inc     di
    inc     di
    loop    .dbl_loop

    ; ======================================================================
    ; (1C) add the diagonal squares:  for i in 0..n-1:  t[2i] += a[i]^2
    ;   a[i]^2 is a 32-bit value placed at words t[2i] (low) and t[2i+1] (high).
    ; ======================================================================
    mov     word [bp-10], 0         ; i = 0
.dg_outer:
    mov     si, [bp-2]
    mov     bx, [bp-10]
    add     si, bx
    add     si, bx                  ; si -> a[i]
    mov     ax, [si]
    mul     ax                      ; DX:AX = a[i]^2

    ; di -> t[2i] = rsa_t + 4i
    mov     di, [bp-10]
    add     di, di
    add     di, di                  ; 4i
    add     di, rsa_t               ; -> t[2i]

    ; t[2i] += AX (low) ; t[2i+1] += DX + carry ; propagate carry up
    add     [di], ax                ; t[2i] += low
    adc     dx, 0                   ; fold the carry from the low add into DX
    add     di, 2                   ; -> t[2i+1]
    add     [di], dx                ; t[2i+1] += (high + carry)
    mov     bx, 0
    adc     bx, 0                   ; carry out -> bx
    add     di, 2                   ; -> t[2i+2]
    call    carry_up                ; propagate carry bx up from [di]

.dg_next:
    inc     word [bp-10]
    mov     ax, [bp-10]
    cmp     ax, RSA_N_LIMBS         ; loop while i < n
    jb      .dg_outer

    ; ======================================================================
    ; t[0..2n-1] now holds the full 256-word integer square a^2.
    ; (2) SOS Montgomery reduction:
    ;   for i in 0..n-1:
    ;       m = (t[i] * n0inv) & 0xFFFF
    ;       C = 0
    ;       for j in 0..n-1:  full = t[i+j] + m*n[j] + C ; t[i+j]=low ; C=high
    ;       add C into t[i+n] and propagate up while carry != 0
    ;   result = t[n .. 2n-1] (>> n words), conditional subtract N.
    ; ======================================================================
    mov     word [bp-10], RSA_N_LIMBS   ; outer counter (down from n)
    mov     word [bp-12], rsa_t         ; ibase = &t[i] (byte offset), starts at t[0]
.sos_outer:
    ; m = (t[i] * n0inv) & 0xFFFF
    mov     si, [bp-12]             ; -> t[i]
    mov     ax, [si]                ; t[i]
    mul     word [rsa_n0inv]
    mov     [bp-8], ax              ; m

    ; for j in 0..n-1: full = t[i+j] + m*n[j] + C ; t[i+j]=low ; C=high
    xor     bx, bx                  ; C = 0
    mov     si, rsa_n               ; -> n[0]
    mov     di, [bp-12]             ; -> t[i+0]
    mov     cx, RSA_N_LIMBS
.sos_red:
    mov     ax, [si]                ; n[j]
    mul     word [bp-8]             ; DX:AX = m*n[j]
    add     ax, [di]                ; + t[i+j]
    adc     dx, 0
    add     ax, bx                  ; + C
    adc     dx, 0
    mov     [di], ax                ; t[i+j] = low
    mov     bx, dx                  ; C = high
    add     si, 2
    add     di, 2
    loop    .sos_red

    ; add the final carry C into t[i+n] (di now points there) and propagate up
    call    carry_up                ; in: di -> t[i+n], bx = carry

.sos_advance:
    add     word [bp-12], 2         ; ibase -> t[i+1]
    dec     word [bp-10]
    jnz     .sos_outer

    ; ======================================================================
    ; result = t[n .. 2n-1]  (the high half).  Conditional subtract + copy via
    ; the shared cond_sub_copy: result low limb is t[n]; its top carry word is
    ; t[n + n] = t[2n].  (With a^2 < N*R the top word stays 0, but check anyway.)
    ; ======================================================================
    mov     bx, rsa_t + RSA_N_LIMBS*2   ; t_base -> t[n]  (high half)
    mov     dx, [bp-4]                  ; out ptr u
    call    cond_sub_copy

    mov     sp, bp
    pop     bp
    ret


; ==========================================================================
; cond_sub_copy  --  shared conditional-subtract-N + copy-to-output tail used
; by BOTH montmul and montsqr (their tails were bit-identical bar the t offset).
;   in:  BX = t_base   = byte addr of the result's LOW limb in rsa_t
;        DX = out ptr   = destination for the n result limbs
;   The result occupies t_base[0..n-1]; its top carry word is at t_base+n*2.
;   if topcarry != 0 OR result >= N:  result -= N   (n-limb borrow subtract)
;   then copy result[0..n-1] -> [out].
;   clobbers all GP regs (called as the very last act before the epilogue).
; ==========================================================================
cond_sub_copy:
    mov     si, bx
    mov     ax, [si + RSA_N_LIMBS*2]    ; top carry word (t_base + n*2)
    or      ax, ax
    jnz     .do_sub                     ; nonzero -> definitely >= N

    ; compare result[0..n-1] vs N, most-significant limb down
    mov     si, bx
    add     si, (RSA_N_LIMBS-1)*2       ; -> result[n-1]
    mov     di, rsa_n + (RSA_N_LIMBS-1)*2   ; -> n[n-1]
    mov     cx, RSA_N_LIMBS
.cmp_loop:
    mov     ax, [si]
    cmp     ax, [di]
    ja      .do_sub                     ; result > N at this limb -> >= N
    jb      .no_sub                     ; result < N
    sub     si, 2
    sub     di, 2
    loop    .cmp_loop
    ; all equal -> result == N -> subtract

.do_sub:
    ; result[0..n-1] -= N  (n-limb subtract with borrow)
    mov     si, rsa_n                   ; -> n[0]
    mov     di, bx                      ; -> result[0]
    mov     cx, RSA_N_LIMBS
    clc
.sub_loop:
    mov     ax, [di]
    sbb     ax, [si]
    mov     [di], ax
    inc     si
    inc     si
    inc     di
    inc     di
    loop    .sub_loop

.no_sub:
    ; ---- copy result[0..n-1] -> [out] ----
    mov     si, bx
    mov     di, dx
    mov     cx, RSA_N_LIMBS
    cld
    rep     movsw
    ret


; ==========================================================================
; carry_up  --  propagate a carry upward through the accumulator while nonzero.
; Shared by montsqr's three carry-propagation sites (.od / .dg / .sos rows).
;   in:  DI -> the word to add the carry into, BX = carry
;   out: BX = 0, DI advanced past the last word touched
;   clobbers DI, BX, flags only (leaves SI/CX/AX/DX intact).
; ==========================================================================
carry_up:
    or      bx, bx
    jz      .done
    add     [di], bx
    mov     bx, 0
    adc     bx, 0                   ; carry out of this add
    add     di, 2
    jmp     carry_up
.done:
    ret
