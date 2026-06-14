; RSA-2048 signature verify: rsa_result = rsa_sig^65537 mod rsa_n
; CIOS Montgomery multiplication, n = 128 limbs, base b = 2^16, e = 65537.
; Testbench only (correctness-gated); plain CIOS, no golf.
cpu 8086

%define RSA_N_LIMBS 128

; --------------------------------------------------------------------------
; rsa_verify  --  no args. Reads rsa_sig/rsa_n/rsa_r2/rsa_one/rsa_n0inv,
; writes rsa_result = rsa_sig^65537 mod rsa_n.
;
;   sm  = montmul(sig, r2)        ; enter Montgomery domain: s*R mod N
;   x   = sm
;   16x: x = montmul(x, x)        ; x = sm^(2^16)
;   x   = montmul(x, sm)          ; x = sm^65537
;   result = montmul(x, one)      ; leave domain
; --------------------------------------------------------------------------
rsa_verify:
    ; sm = montmul(sig, r2)
    mov     si, rsa_sig
    mov     bx, rsa_r2
    mov     di, rsa_sm
    call    montmul

    ; x = sm  (copy 128 limbs)
    mov     si, rsa_sm
    mov     di, rsa_x
    mov     cx, RSA_N_LIMBS
    cld
    rep     movsw

    ; repeat 16 times: x = montmul(x, x)
    mov     cx, 16
.sq_loop:
    push    cx
    mov     si, rsa_x
    mov     bx, rsa_x
    mov     di, rsa_x
    call    montmul
    pop     cx
    loop    .sq_loop

    ; x = montmul(x, sm)
    mov     si, rsa_x
    mov     bx, rsa_sm
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
    ; conditional subtract: if t[n] != 0 OR t[0..n-1] >= N: t[0..n-1] -= N
    ; ======================================================================
    ; check t[n] first
    mov     ax, [rsa_t + RSA_N_LIMBS*2]     ; t[n]
    or      ax, ax
    jnz     .do_sub                         ; t[n] != 0 -> definitely >= N (and >= 2^2048)

    ; compare t[0..n-1] vs N, most-significant limb down
    mov     si, rsa_t + (RSA_N_LIMBS-1)*2   ; -> t[n-1]
    mov     di, rsa_n + (RSA_N_LIMBS-1)*2   ; -> n[n-1]
    mov     cx, RSA_N_LIMBS
.cmp_loop:
    mov     ax, [si]
    cmp     ax, [di]
    ja      .do_sub                         ; t > N at this limb -> t >= N
    jb      .no_sub                         ; t < N
    sub     si, 2
    sub     di, 2
    loop    .cmp_loop
    ; all equal -> t == N -> t >= N, subtract

.do_sub:
    ; t[0..n-1] -= N  (128-limb subtract with borrow)
    mov     si, rsa_n               ; -> n[0]
    mov     di, rsa_t               ; -> t[0]
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
    ; ---- copy t[0..n-1] -> u ----
    mov     si, rsa_t
    mov     di, [bp-6]
    mov     cx, RSA_N_LIMBS
    cld
    rep     movsw

    mov     sp, bp
    pop     bp
    ret
