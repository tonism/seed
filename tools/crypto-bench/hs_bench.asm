; Full TLS-1.2-ECDHE handshake crypto, timed end-to-end on a 286 (boots on the
; 360K image). One timed sequence:
;   1. real ECDHE (optimized P-256): scalar mult + inv + affine -> shared X (premaster)
;   2. TLS-PRF: master secret (premaster + randoms) + key block
;   3. transcript: SHA-256 over ~3000 bytes (ClientHello..Cert..ServerHelloDone)
; (Cert-auth/RSA-2048 is a separate build; the ChaCha20-Poly1305 Finished is ~tens of ms,
; negligible vs these.) Emits "HS N=1 dt=<ticks> ck=<hex4>". 8086 only; P-256 via -DP256_SRC.

bits 16
cpu 8086
org 0x1000

%include "core/layout.inc"

core_header:
    jmp short start
    nop
    db 'SEEDCORE'
    db 1
    db 0
    dw core_header_end - core_header
    dw (image_end - core_header + 511) / 512
    dw (image_end - core_header + 511) / 512
    dw 0
    dw 0
core_header_end:

%include "core/data.inc"

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x6000
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init
    call deploy_sha_constants      ; SHA K + initial state (the real L phase does this)

    mov si, tag_hs
    call emit_str
    mov al, ' '
    call emit_char
    call read_tick_low
    mov bx, ax
.edge:
    call read_tick_low
    cmp ax, bx
    je .edge
    call read_tick
    mov [t0_lo], ax
    mov [t0_hi], dx

    call hs_full                   ; the timed handshake crypto

    call read_tick
    sub ax, [t0_lo]
    sbb dx, [t0_hi]
    mov [dt_lo], ax
    mov si, str_dt
    call emit_str
    mov ax, [dt_lo]
    call emit_dec16
    ; checksum the key block (sanity tag)
    xor ax, ax
    mov si, tls_key_block
    mov cx, tls_key_block_len / 2
.sum:
    add ax, [si]
    inc si
    inc si
    loop .sum
    push ax
    mov si, str_ck
    call emit_str
    pop ax
    call emit_hex16
    call emit_crlf
    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

; Symmetric handshake crypto only (PRF + transcript). ECDHE is measured separately
; (p256_bench, 6.6 s on 286@6) and summed -- the handshake runs them sequentially with
; no overlap, and an all-in-one image would overrun the PRF's 0x3400 scratch.
hs_full:
    ; --- premaster = 32 dummy bytes (PRF time is content-independent) ---
    mov di, tls_premaster_secret
    mov cx, 32
    xor al, al
.pm:
    mov [di], al
    inc di
    inc al
    loop .pm
    ; --- randoms (content irrelevant to timing) ---
    mov di, tls_random
    mov cx, 32
    xor al, al
.r1:
    mov [di], al
    inc di
    inc al
    loop .r1
    mov di, tls_server_random
    mov cx, 32
    mov al, 0x40
.r2:
    mov [di], al
    inc di
    inc al
    loop .r2
    ; --- 2. PRF: master secret + key block ---
    call tls_prepare_master_secret
    call tls_prepare_key_block
    ; --- 3. transcript: SHA-256 over ~3000 bytes (the handshake messages incl. cert) ---
    call sha256_init
    mov si, 0x1000
    mov cx, 3000
    call sha256_update
    mov di, tls_handshake_hash
    call sha256_finish
    ret

deploy_sha_constants:
    mov si, sha256_k_constant
    mov di, sha256_k
    mov cx, sha256_k_len
    rep movsb
    mov si, tls_low_constants_constant
    mov di, low_static_constants_start
    mov cx, low_static_constants_len
    rep movsb
    ret

read_tick:
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret
read_tick_low:
    mov ax, [0x046c]
    ret

serial_init:
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 0x0c
    out dx, al
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 0x03
    out dx, al
    ret

emit_char:
    push ax
    push bx
    push cx
    push dx
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    mov ah, al
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, 0x3f8
    mov al, ah
    out dx, al
    pop dx
    pop cx
    pop bx
    pop ax
    ret

emit_str:
    push ax
    push si
.next:
    lodsb
    or al, al
    jz .done
    call emit_char
    jmp .next
.done:
    pop si
    pop ax
    ret

emit_crlf:
    push ax
    mov al, 13
    call emit_char
    mov al, 10
    call emit_char
    pop ax
    ret

emit_hex16:
    push ax
    push cx
    push dx
    mov dx, ax
    mov cx, 4
.dig:
    rol dx, 1
    rol dx, 1
    rol dx, 1
    rol dx, 1
    mov al, dl
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .ok
    add al, 7
.ok:
    call emit_char
    loop .dig
    pop dx
    pop cx
    pop ax
    ret

emit_dec16:
    push ax
    push bx
    push cx
    push dx
    mov bx, 10
    xor cx, cx
.div:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .div
.pop:
    pop ax
    add al, '0'
    call emit_char
    loop .pop
    pop dx
    pop cx
    pop bx
    pop ax
    ret

tag_hs   db 'HS N=1', 0
tag_done db 'DONE', 0
str_dt   db ' dt=', 0
str_ck   db ' ck=', 0
t0_lo dw 0
t0_hi dw 0
dt_lo dw 0

%include "core/sha256.inc"
%include "prf_driver.inc"

; SHA constant tables (deployed at boot, from phases/tls_client_hello.inc)
tls_low_constants_constant:
tls_label_master_secret_constant db 'master secret'
tls_label_client_finished_constant db 'client finished'
tls_label_server_finished_constant db 'server finished'
tls_label_key_expansion_constant db 'key expansion'
chacha_constants_constant dw 0x7865, 0x6170, 0x646e, 0x3320
                           dw 0x2d32, 0x7962, 0x6574, 0x6b20
poly1305_prime_constant db 0xfb
                           times 15 db 0xff
                           db 0x03
sha256_initial_state_constant dw 0xe667, 0x6a09, 0xae85, 0xbb67
                           dw 0xf372, 0x3c6e, 0xf53a, 0xa54f
                           dw 0x527f, 0x510e, 0x688c, 0x9b05
                           dw 0xd9ab, 0x1f83, 0xcd19, 0x5be0
%if ($ - tls_low_constants_constant) != low_static_constants_len
%error "low static constants length mismatch"
%endif
sha256_k_constant dw 0x2f98, 0x428a, 0x4491, 0x7137
                  dw 0xfbcf, 0xb5c0, 0xdba5, 0xe9b5
                  dw 0xc25b, 0x3956, 0x11f1, 0x59f1
                  dw 0x82a4, 0x923f, 0x5ed5, 0xab1c
                  dw 0xaa98, 0xd807, 0x5b01, 0x1283
                  dw 0x85be, 0x2431, 0x7dc3, 0x550c
                  dw 0x5d74, 0x72be, 0xb1fe, 0x80de
                  dw 0x06a7, 0x9bdc, 0xf174, 0xc19b
                  dw 0x69c1, 0xe49b, 0x4786, 0xefbe
                  dw 0x9dc6, 0x0fc1, 0xa1cc, 0x240c
                  dw 0x2c6f, 0x2de9, 0x84aa, 0x4a74
                  dw 0xa9dc, 0x5cb0, 0x88da, 0x76f9
                  dw 0x5152, 0x983e, 0xc66d, 0xa831
                  dw 0x27c8, 0xb003, 0x7fc7, 0xbf59
                  dw 0x0bf3, 0xc6e0, 0x9147, 0xd5a7
                  dw 0x6351, 0x06ca, 0x2967, 0x1429
                  dw 0x0a85, 0x27b7, 0x2138, 0x2e1b
                  dw 0x6dfc, 0x4d2c, 0x0d13, 0x5338
                  dw 0x7354, 0x650a, 0x0abb, 0x766a
                  dw 0xc92e, 0x81c2, 0x2c85, 0x9272
                  dw 0xe8a1, 0xa2bf, 0x664b, 0xa81a
                  dw 0x8b70, 0xc24b, 0x51a3, 0xc76c
                  dw 0xe819, 0xd192, 0x0624, 0xd699
                  dw 0x3585, 0xf40e, 0xa070, 0x106a
                  dw 0xc116, 0x19a4, 0x6c08, 0x1e37
                  dw 0x774c, 0x2748, 0xbcb5, 0x34b0
                  dw 0x0cb3, 0x391c, 0xaa4a, 0x4ed8
                  dw 0xca4f, 0x5b9c, 0x6ff3, 0x682e
                  dw 0x82ee, 0x748f, 0x636f, 0x78a5
                  dw 0x7814, 0x84c8, 0x0208, 0x8cc7
                  dw 0xfffa, 0x90be, 0x6ceb, 0xa450
                  dw 0xa3f7, 0xbef9, 0x78f2, 0xc671
%if ($ - sha256_k_constant) != sha256_k_len
%error "sha256 k length mismatch"
%endif

image_end:
