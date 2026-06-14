; Build 12: RSA-PKCS#1-v1.5-SHA256 signature verify (reconstruct-and-compare) -- the reusable core
; shared by the in-race ServerKeyExchange-sig verify and the off-race X.509 chain-verify.
;
; Verify that rsa_sig (the signature, big-endian on the wire) is a valid PKCS#1-v1.5 signature over a
; given 32-byte SHA-256 hash, under the modulus currently in rsa_n/rsa_r2/rsa_one/rsa_n0inv. The
; recovered block is compared against a fully RECONSTRUCTED EMSA-PKCS1-v1.5 block (00 01 FF..FF 00
; DigestInfo h) with a whole-256-byte memcmp -- no lax structural parse, so padding-forgery vectors
; (Bleichenbacher/BERserk-style) cannot slip through. This is the exact logic shipped inline in
; p256_module.asm's SKE verify, factored out so the chain-verify reuses it. cpu 8086.

; rsa_pkcs1_verify -- in: SI = 256-byte big-endian signature, DI = 32-byte SHA-256 hash.
;                    out: CF=0 valid, CF=1 invalid. Uses rsa_n/r2/one/n0inv + the rsa_* scratch.
rsa_pkcs1_verify:
    push    di                                   ; save the hash ptr
    mov     di, rsa_sig
    call    rsa_from_be256                       ; rsa_sig <- signature (BE -> LE words)
    pop     si                                   ; si = hash
    call    rsa_build_expected_block             ; rsa_expected <- EMSA-PKCS1-v1.5(hash)
    call    rsa_verify                           ; rsa_result = rsa_sig^65537 mod rsa_n (LE words)
    mov     si, rsa_result
    mov     di, rsa_recovered
    call    rsa_to_be256                         ; rsa_recovered <- recovered block (LE words -> BE)
    push    ds
    pop     es
    cld
    mov     si, rsa_recovered
    mov     di, rsa_expected
    mov     cx, 256
    repe    cmpsb
    jne     .invalid
    clc
    ret
.invalid:
    stc
    ret

; si = 256 big-endian bytes, di = 128 LE-word dest. Preserves SI/DI (so the caller's hash ptr survives).
rsa_from_be256:
    push    ax
    push    bx
    push    cx
    push    si
    push    di
    mov     bx, si
    add     bx, 255                              ; -> the least-significant byte
    mov     cx, 128
.next:
    mov     al, [bx]
    mov     ah, [bx - 1]
    mov     [di], ax
    add     di, 2
    sub     bx, 2
    loop    .next
    pop     di
    pop     si
    pop     cx
    pop     bx
    pop     ax
    ret

; si = 128 LE words, di = 256 big-endian bytes dest.
rsa_to_be256:
    push    ax
    push    bx
    push    cx
    push    si
    push    di
    mov     bx, si
    add     bx, 254                              ; -> the most-significant word
    mov     cx, 128
.next:
    mov     ax, [bx]
    mov     [di], ah                             ; high byte first (big-endian)
    mov     [di + 1], al
    add     di, 2
    sub     bx, 2
    loop    .next
    pop     di
    pop     si
    pop     cx
    pop     bx
    pop     ax
    ret

; si = the 32-byte hash. Reconstructs the EMSA-PKCS1-v1.5(SHA-256) block (big-endian) into
; rsa_expected: 00 01 [FF x 202] 00 [19-byte SHA-256 DigestInfo prefix] [h x 32] (= 256 bytes).
rsa_build_expected_block:
    push    ds
    pop     es
    cld
    mov     dx, si                               ; stash the hash ptr
    mov     di, rsa_expected
    mov     al, 0x00
    stosb
    mov     al, 0x01
    stosb
    mov     al, 0xff
    mov     cx, 202
    rep     stosb
    mov     al, 0x00
    stosb
    mov     si, rsa_sha256_digestinfo
    mov     cx, 19
    rep     movsb
    mov     si, dx
    mov     cx, 32
    rep     movsb
    ret

; The DER DigestInfo prefix for SHA-256 (RFC 8017): SEQ{ SEQ{ OID sha256, NULL }, OCTET STRING(32) }.
rsa_sha256_digestinfo:
    db 0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
rsa_expected:  times 256 db 0
rsa_recovered: times 256 db 0
