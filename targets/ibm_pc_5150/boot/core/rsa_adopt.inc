; Build 12 auto-recertify: adopt a freshly chain-verified leaf as the fast-path RSA pin.
;
; After x509_parse_leaf + a successful chain-verify vs the pinned WR1, install the new leaf's public
; key into the rsa_verify working constants (rsa_n / rsa_n0inv / rsa_r2) so the RETRY handshake's
; in-race ServerKeyExchange-sig verify uses the new leaf -- 1 RSA verify, the @6 fast path again. The
; read-only floppy can't persist it, so after a rotation it re-derives from WR1 on each boot (the
; baked pin verifies stale -> recertify -> re-adopt). Oracle-gated: tools/crypto-bench/adopt_eval.py
; proves the derived params make rsa_verify reproduce pow(sig,65537,n).
;
; in: SI = ptr to the 256-byte big-endian leaf modulus (x509_mod_ptr). clobbers everything.
; CARRY DISCIPLINE: the 128-limb shift/subtract loops advance pointers with INC (preserves CF), never
; ADD (clobbers CF) -- the carry/borrow must chain across limbs. cpu 8086.

rsa_adopt:
    ; ---- 1. rsa_n <- the modulus as 128 little-endian 16-bit limbs (byte-swap from big-endian) ----
    mov     bx, si
    add     bx, 255                 ; -> least-significant byte
    mov     di, rsa_n
    mov     cx, 128
.swap:
    mov     al, [bx]                ; low byte of this limb
    mov     ah, [bx-1]              ; high byte
    mov     [di], ax
    add     di, 2
    sub     bx, 2
    loop    .swap

    ; ---- 2. rsa_n0inv <- (-n^-1) mod 2^16  (Newton: inv=1; 4x inv = inv*(2 - n0*inv)) ----
    ; n is odd, so inv=1 is correct mod 2^1; each step doubles the correct bits -> mod 2^16 after 4.
    mov     bx, [rsa_n]             ; n0 = low 16 bits of n
    mov     di, 1                   ; inv
    mov     cx, 4
.ninv:
    mov     ax, bx
    mul     di                      ; AX = low(n0 * inv)
    mov     dx, 2
    sub     dx, ax                  ; DX = (2 - n0*inv) mod 2^16
    mov     ax, di
    mul     dx                      ; AX = low(inv * (2 - n0*inv))
    mov     di, ax
    loop    .ninv
    neg     di                      ; -inv mod 2^16
    mov     [rsa_n0inv], di

    ; ---- 3. rsa_r2 <- 2^4096 mod n   (r = 1; double 4096 times: r = (2r) mod n) ----
    mov     di, rsa_r2
    xor     ax, ax
    mov     cx, 128
    rep     stosw                   ; r := 0
    mov     word [rsa_r2], 1        ; r := 1
    mov     word [rsa_adopt_count], 4096
.dbl:
    ; r <<= 1 over 128 limbs; CF afterwards = the bit shifted out of bit 2048
    mov     si, rsa_r2
    mov     cx, 128
    clc
.shl:
    rcl     word [si], 1
    inc     si
    inc     si                      ; INC preserves CF (the shift carry must chain)
    loop    .shl
    jc      .subtract               ; overflowed 2^2048 -> definitely >= n (n < 2^2048)
    ; compare r vs n, most-significant limb first
    mov     si, rsa_r2 + 254
    mov     di, rsa_n + 254
    mov     cx, 128
.cmp:
    mov     ax, [si]
    cmp     ax, [di]
    ja      .subtract
    jb      .nosub
    sub     si, 2
    sub     di, 2
    loop    .cmp
    ; all limbs equal -> r == n -> subtract
.subtract:
    mov     si, rsa_n
    mov     di, rsa_r2
    mov     cx, 128
    clc
.sub:
    mov     ax, [di]
    sbb     ax, [si]
    mov     [di], ax
    inc     si
    inc     si                      ; INC preserves CF (the borrow must chain)
    inc     di
    inc     di
    loop    .sub
.nosub:
    dec     word [rsa_adopt_count]
    jnz     .dbl
    ret

align 2
rsa_adopt_count: dw 0
