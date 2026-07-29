; SHA-256 handoff phase for the streaming TLS 1.3 certificate parser PoC.
;
; This is deliberately a sibling overlay rather than resident parser code:
; parser output survives at 3600h+, while the code phase at 1800h and low
; workspace are replaceable.  The phase computes the exact TBSCertificate
; digest and TLS 1.3 CertificateVerify signed-input digest, then erases the
; captured certificate and SHA workspace before issuer_auth is loaded.

bits 16
cpu 8086
org 0x1800

; The captured leaf reuses the retired ML-KEM ciphertext band and leaves the
; live NIC receive frame at 0700h..08b6h untouched.
parser_leaf_buffer         equ 0x08c0
parser_leaf_capacity       equ 1024
parser_leaf_buffer_end     equ parser_leaf_buffer + parser_leaf_capacity

parser_leaf_status         equ 0x3600
parser_leaf_profile        equ parser_leaf_status + 1
parser_output_leaf_len     equ parser_leaf_profile + 2
parser_output_tbs_ptr      equ parser_output_leaf_len + 2
parser_output_tbs_len      equ parser_output_tbs_ptr + 2
parser_output_tbs_digest   equ parser_output_tbs_len + 2
parser_output_cert_sig_len equ parser_output_tbs_digest + 32
parser_output_cert_sig     equ parser_output_cert_sig_len + 2

parser_cv_status           equ 0x3700
parser_cv_profile          equ parser_cv_status + 1
parser_transcript_status   equ parser_cv_profile + 2
parser_transcript_hash     equ parser_transcript_status + 1
parser_output_cv_digest    equ parser_transcript_hash + 32
parser_output_cv_sig_len   equ parser_output_cv_digest + 32
parser_output_cv_sig       equ parser_output_cv_sig_len + 2
parser_hash_status         equ parser_output_cv_sig + 72

; The parser cannot manufacture trusted time.  It earns 001fh; a later
; trusted-time gate must add 0020h before issuer_auth may accept 003fh.
parser_leaf_profile_value  equ 0x001f
parser_cv_profile_value    equ 0x0700
parser_leaf_hashed_status  equ 2

sha256_digest_len          equ 32
sha256_block_size          equ 64
sha256_k_len               equ 256

; Phase-local low workspace.  Hashing runs after the protected-flight
; symmetric phase, so it may reuse the retired HELLO/runtime band.  It still
; ends below the 0f00h delta-loader trampoline.
sha256_work_start          equ 0x0d40
sha256_state               equ sha256_work_start
sha256_a                   equ sha256_state + 32
sha256_b                   equ sha256_a + 4
sha256_c                   equ sha256_b + 4
sha256_d                   equ sha256_c + 4
sha256_e                   equ sha256_d + 4
sha256_f                   equ sha256_e + 4
sha256_g                   equ sha256_f + 4
sha256_h                   equ sha256_g + 4
sha256_t1                  equ sha256_h + 4
sha256_t2                  equ sha256_t1 + 4
sha256_tmp                 equ sha256_t2 + 4
sha256_bit_len0            equ sha256_tmp + 4
sha256_bit_len1            equ sha256_bit_len0 + 2
sha256_bit_len2            equ sha256_bit_len1 + 2
sha256_bit_len3            equ sha256_bit_len2 + 2
sha256_digest_ptr          equ sha256_bit_len3 + 2
sha256_len_low             equ sha256_digest_ptr + 2
sha256_len_high            equ sha256_len_low + 2
sha256_block_len           equ sha256_len_high + 2
sha256_block               equ (sha256_block_len + 2) & ~1
sha256_w                   equ sha256_block + sha256_block_size
sha256_work_end            equ sha256_w + 256

cert_hash_table:
    dw cert_hash_run
    dw cert_hash_clear_work
    dw cert_hash_image_end - $$
    dw 1

; Validate the parser handoff, compute both hashes, and erase low scratch.
cert_hash_run:
    mov byte [parser_hash_status], 0
    cmp byte [parser_leaf_status], 1
    jne .failed
    cmp word [parser_leaf_profile], parser_leaf_profile_value
    jne .failed
    cmp byte [parser_cv_status], 1
    jne .failed
    cmp word [parser_cv_profile], parser_cv_profile_value
    jne .failed
    cmp byte [parser_transcript_status], 1
    jne .failed

    mov ax, [parser_output_leaf_len]
    or ax, ax
    jz .failed
    cmp ax, parser_leaf_capacity
    ja .failed
    add ax, parser_leaf_buffer
    jc .failed
    mov dx, ax                         ; exclusive end of captured leaf

    mov si, [parser_output_tbs_ptr]
    cmp si, parser_leaf_buffer
    jb .failed
    mov cx, [parser_output_tbs_len]
    or cx, cx
    jz .failed
    mov ax, si
    add ax, cx
    jc .failed
    cmp ax, dx
    ja .failed

    mov ax, [parser_output_cert_sig_len]
    cmp ax, 8
    jb .failed
    cmp ax, 72
    ja .failed
    mov ax, [parser_output_cv_sig_len]
    cmp ax, 8
    jb .failed
    cmp ax, 72
    ja .failed

    cld
    call sha256_init
    mov si, [parser_output_tbs_ptr]
    mov cx, [parser_output_tbs_len]
    call sha256_update
    mov di, parser_output_tbs_digest
    call sha256_finish

    call sha256_init
    mov si, cert_hash_spaces
    mov cx, 64
    call sha256_update
    mov si, cert_hash_cv_context
    mov cx, cert_hash_cv_context_end - cert_hash_cv_context
    call sha256_update
    mov si, cert_hash_zero
    mov cx, 1
    call sha256_update
    mov si, parser_transcript_hash
    mov cx, 32
    call sha256_update
    mov di, parser_output_cv_digest
    call sha256_finish

    call cert_hash_clear_work
    mov byte [parser_leaf_status], parser_leaf_hashed_status
    inc byte [parser_hash_status]
    mov ax, 1
    clc
    ret

.failed:
    call cert_hash_clear_work
    stc
    ret

cert_hash_clear_work:
    push cx
    push di
    push es
    push ds
    pop es
    cld
    xor ax, ax
    mov di, parser_leaf_buffer
    mov cx, sha256_work_end - parser_leaf_buffer
    rep stosb
    mov [parser_leaf_status], al
    pop es
    pop di
    pop cx
    ret

cert_hash_spaces:
    times 64 db 0x20
cert_hash_cv_context:
    db "TLS 1.3, server CertificateVerify"
cert_hash_cv_context_end:
cert_hash_zero:
    db 0

align 4
sha256_initial_state:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

sha256_k:
    dd 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
    dd 0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
    dd 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
    dd 0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
    dd 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
    dd 0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
    dd 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
    dd 0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
    dd 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
    dd 0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
    dd 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
    dd 0xd192e819,0xd6990624,0xf40e3585,0x106aa070
    dd 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
    dd 0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
    dd 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
    dd 0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2

%include "cert_parser_sha256.inc"

cert_hash_image_end:

%if sha256_work_end > 0x0f00
%error "certificate hash workspace reaches low delta-loader trampoline"
%endif
%if (cert_hash_image_end - $$) > (0x3400 - 0x1800)
%error "certificate hash phase exceeds 14-sector K window"
%endif
%if parser_hash_status >= 0x3b9c
%error "certificate hash output reaches attempt cache"
%endif
