; Test-only EMSA-PSS decoder for the TLS 1.3 architecture spike.
;
; Fixed profile:
;   RSA modulus: 2048 bits
;   emBits:      2047
;   hash/MGF:    SHA-256
;   saltLen:     32
;
; Input:
;   DS:SI -> 256-byte recovered encoded message (signature^65537 mod N)
;   DS:DI -> 32-byte SHA-256 digest of the CertificateVerify signed content
; Output:
;   CF clear on accept, set on reject
; Clobbers:
;   AX, BX, CX, DX, SI, DI, BP, ES and the SHA-256 working context
;
; The caller supplies 74 bytes of transient memory by defining
; pss_scratch_base before including this file.  The implementation streams
; MGF1 one 32-byte digest at a time: it deliberately does not allocate the
; 223-byte dbMask.

%ifndef pss_scratch_base
%error "define pss_scratch_base before including pss_decode.inc"
%endif

pss_salt             equ pss_scratch_base       ; 32 bytes
pss_digest           equ pss_salt + 32           ; 32 bytes; MGF digest, then H'
pss_counter_buf      equ pss_digest + 32         ; 4-byte big-endian MGF counter
pss_em_ptr           equ pss_counter_buf + 4     ; word
pss_message_hash_ptr equ pss_em_ptr + 2          ; word
pss_db_position      equ pss_message_hash_ptr + 2 ; byte
pss_mgf_counter      equ pss_db_position + 1     ; byte
pss_scratch_end      equ pss_mgf_counter + 1
pss_scratch_len      equ pss_scratch_end - pss_scratch_base

pss_verify_sha256_2048_salt32:
pss_verify_sha256_2048_salt32_start equ $
    mov [pss_em_ptr], si
    mov [pss_message_hash_ptr], di

    ; emBits=2047 leaves one unused high bit.  RFC 8017 requires that bit to
    ; be zero in maskedDB and fixes the trailer byte to 0xbc.
    test byte [si], 0x80
    jnz pss_verify_sha256_2048_salt32_failed
    cmp byte [si + 255], 0xbc
    jne pss_verify_sha256_2048_salt32_failed

    mov byte [pss_db_position], 0
    mov byte [pss_mgf_counter], 0

.mgf_block:
    ; dbMask block = SHA256(H || I2OSP(counter, 4)).
    call sha256_init
    mov si, [pss_em_ptr]
    add si, 223
    mov cx, 32
    call sha256_update

    mov word [pss_counter_buf], 0
    mov byte [pss_counter_buf + 2], 0
    mov al, [pss_mgf_counter]
    mov [pss_counter_buf + 3], al
    mov si, pss_counter_buf
    mov cx, 4
    call sha256_update
    mov di, pss_digest
    call sha256_finish

    ; Six complete digest blocks cover DB positions 0..191.  The seventh
    ; contributes only 31 bytes, ending exactly at position 222.
    mov bx, [pss_em_ptr]
    xor ax, ax
    mov al, [pss_db_position]
    add bx, ax
    mov si, pss_digest
    mov cx, 32
    cmp byte [pss_mgf_counter], 6
    jne .chunk_len_ready
    dec cx
.chunk_len_ready:
    mov dl, [pss_db_position]
    xor dh, dh
    mov bp, pss_salt
    cmp dl, 191
    jb .check_byte
    mov al, dl
    sub al, 191
    xor ah, ah
    add bp, ax

.check_byte:
    mov al, [bx]
    xor al, [si]
    or dl, dl
    jnz .unused_bit_done
    and al, 0x7f
.unused_bit_done:
    cmp dl, 190
    jb .expect_zero
    je .expect_one
    mov [bp], al
    inc bp
    jmp short .byte_ok
.expect_zero:
    or al, al
    jnz pss_verify_sha256_2048_salt32_failed
    jmp short .byte_ok
.expect_one:
    cmp al, 1
    jne pss_verify_sha256_2048_salt32_failed
.byte_ok:
    inc bx
    inc si
    inc dl
    loop .check_byte

    mov [pss_db_position], dl
    inc byte [pss_mgf_counter]
    cmp byte [pss_mgf_counter], 7
    jb .mgf_block

    ; H' = SHA256(8 zero octets || messageHash || salt).
    push ds
    pop es
    mov di, pss_digest
    xor ax, ax
    mov cx, 4
    rep stosw
    call sha256_init
    mov si, pss_digest
    mov cx, 8
    call sha256_update
    mov si, [pss_message_hash_ptr]
    mov cx, 32
    call sha256_update
    mov si, pss_salt
    mov cx, 32
    call sha256_update
    mov di, pss_digest
    call sha256_finish

    ; Compare all 32 bytes without an early exit.
    mov bx, [pss_em_ptr]
    add bx, 223
    mov si, pss_digest
    mov cx, 32
    xor dx, dx
.compare_h:
    mov al, [si]
    xor al, [bx]
    or dl, al
    inc si
    inc bx
    loop .compare_h
    or dl, dl
    jnz pss_verify_sha256_2048_salt32_failed
    clc
    ret

pss_verify_sha256_2048_salt32_failed:
    stc
    ret
pss_verify_sha256_2048_salt32_end equ $
