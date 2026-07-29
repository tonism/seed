; TLS 1.3 observed-server-flight micro-benchmark for the 4.77 MHz 8088.
;
; Models the exact outer-record geometry observed from api.openai.com:
;
;   outer TLSCiphertext payload       4327 bytes
;   ciphertext / TLSInnerPlaintext    4311 bytes
;   handshake transcript contribution 4310 bytes
;   inner content type                   1 byte (0x16)
;   ChaCha20 blocks                      69 (counter 0 OTK + 68 data)
;   Poly1305 blocks                     272 (AAD + ciphertext + lengths)
;   SHA-256 compression blocks           68 (including final padding)
;
; The ciphertext is deterministic and content-independent for timing.  Eleven
; 384-byte receive chunks plus one 87-byte tail preserve Seed's advertised MSS
; and exercise the same save/MAC/decrypt/hash order as the draining-FIFO path.
; The final ciphertext byte is chosen so the decrypted inner content type is
; handshake (0x16).
;
; This is a standalone SEED.SYS and does not alter the product runtime.  It
; includes the shipping 8086 ChaCha20, Poly1305, and SHA-256 implementations
; verbatim.  Output:
;
;   FLIGHT N=1 dt=<ticks> ck=<hex4>
;   TAG <32 hex digits>
;   SHA <64 hex digits>
;   OPS chacha=69 poly=272 sha=68 inner=16
;   CHECK PASS
;   DONE

bits 16
cpu 8086
org 0x1000

%include "core/layout.inc"

%ifdef FLIGHT_PROFILE_CERTCOMP
; Live-observed compact ECDSA profile with RFC 8879 Brotli certificate
; compression: EncryptedExtensions=10, CompressedCertificate=1799,
; CertificateVerify=80, Finished=36.  The four handshake messages contribute
; 1925 transcript bytes.
flight_outer_payload_len       equ 1942
flight_expected_cipher_len     equ 1926
flight_expected_chacha_blocks  equ 32
flight_expected_poly_blocks    equ 123
flight_expected_sha_blocks     equ 31
flight_inner_cipher_byte       equ 0xe4
component_expected_chaxor_ck   equ 0x2527
%else
%ifdef FLIGHT_PROFILE_ECDSA
; Observed pre-286 OpenAI profile: P-256 ECDHE key share with the compact
; ECDSA certificate/CV flight (leaf DER 903 B).
flight_outer_payload_len       equ 2638
flight_expected_cipher_len     equ 2622
flight_expected_chacha_blocks  equ 42
flight_expected_poly_blocks    equ 166
flight_expected_sha_blocks     equ 42
flight_inner_cipher_byte       equ 0xd9
component_expected_chaxor_ck   equ 0xbb1b
%else
; Observed 286+ OpenAI profile: RSA leaf/CV flight (leaf DER 1300 B).
flight_outer_payload_len       equ 4327
flight_expected_cipher_len     equ 4311
flight_expected_chacha_blocks  equ 69
flight_expected_poly_blocks    equ 272
flight_expected_sha_blocks     equ 68
flight_inner_cipher_byte       equ 0xa1
component_expected_chaxor_ck   equ 0x4e87
%endif
%endif

flight_cipher_len        equ flight_outer_payload_len - tls_aead_tag_len
flight_transcript_len    equ flight_cipher_len - 1
flight_rx_chunk_len      equ 384
flight_chacha_blocks     equ 1 + ((flight_cipher_len + chacha_block_len - 1) / chacha_block_len)
flight_poly_blocks       equ 1 + ((flight_cipher_len + 15) / 16) + 1
flight_sha_blocks        equ (flight_transcript_len + 9 + sha256_block_size - 1) / sha256_block_size
flight_aad_len           equ 5
flight_final_chunk_len   equ flight_cipher_len % flight_rx_chunk_len
flight_inner_chunk_off   equ flight_final_chunk_len - 1

%if flight_cipher_len != flight_expected_cipher_len
%error "observed TLS 1.3 ciphertext geometry changed"
%endif
%if flight_chacha_blocks != flight_expected_chacha_blocks
%error "observed TLS 1.3 ChaCha block count changed"
%endif
%if flight_poly_blocks != flight_expected_poly_blocks
%error "observed TLS 1.3 Poly1305 block count changed"
%endif
%if flight_sha_blocks != flight_expected_sha_blocks
%error "observed TLS 1.3 SHA block count changed"
%endif
%if flight_final_chunk_len = 0
%error "benchmark profiles require a non-empty final receive chunk"
%endif

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

; Reuse the product's fixed low/high crypto address map.  This emits only the
; two resident pointer words; all other declarations are EQU aliases.
%include "core/data.inc"

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, basic_sidecar_stack_top_16k
    sti
    cld

    mov ax, 0x0003
    int 0x10
    call serial_init
    call deploy_crypto_constants

%ifdef FLIGHT_COMPONENTS
    call components_main
    jmp .hang
%endif

    mov si, tag_flight
    call emit_str
    mov al, ' '
    call emit_char

    ; Align the one-shot measurement to a BIOS tick edge.
    call read_tick_low
    mov bx, ax
.tick_edge:
    call read_tick_low
    cmp ax, bx
    je .tick_edge
    call read_tick
    mov [flight_t0_lo], ax
    mov [flight_t0_hi], dx

    call flight_process

    call read_tick
    sub ax, [flight_t0_lo]
    sbb dx, [flight_t0_hi]
    mov [flight_dt_lo], ax

    mov si, str_n
    call emit_str
    mov ax, 1
    call emit_dec16
    mov si, str_dt
    call emit_str
    mov ax, [flight_dt_lo]
    call emit_dec16
    mov si, str_ck
    call emit_str
    call flight_checksum
    call emit_hex16
    call emit_crlf

    mov si, str_tag
    call emit_str
    mov si, tls_finished_tag
    mov cx, tls_aead_tag_len
    call emit_hexbuf

    mov si, str_sha
    call emit_str
    mov si, flight_digest
    mov cx, sha256_digest_len
    call emit_hexbuf

    mov si, str_ops
    call emit_str
    mov ax, [flight_chacha_count]
    call emit_dec16
    mov si, str_poly
    call emit_str
    mov ax, [flight_poly_count]
    call emit_dec16
    mov si, str_sha_blocks
    call emit_str
    mov ax, flight_sha_blocks
    call emit_dec16
    mov si, str_inner
    call emit_str
    mov al, [flight_last_plain]
    call emit_hex8
    call emit_crlf

    call flight_check
    mov si, str_check_pass
    jnc .emit_check
    mov si, str_check_fail
.emit_check:
    call emit_str
    call emit_crlf
    mov si, tag_done
    call emit_str
    call emit_crlf

.hang:
    hlt
    jmp .hang

%ifdef FLIGHT_COMPONENTS
; ---------------------------------------------------------------------------
; Optional component-breakdown entry (selected by flight_components_bench.asm)
; ---------------------------------------------------------------------------

components_main:
    mov byte [component_failed], 0

    mov si, tag_chaxor
    mov bp, component_chaxor
    mov di, component_check_chaxor
    call component_run

    ; OTK derivation belongs to the ChaCha component.  Seed's shipping
    ; poly1305_load_key transformation is performed outside the POLY timer so
    ; that tag measures only the profile's Poly blocks plus stream
    ; copy/save/restore.
    call component_poly_prepare
    mov si, tag_poly
    mov bp, component_poly
    mov di, component_check_poly
    call component_run

    mov si, tag_shaflt
    mov bp, component_sha
    mov di, component_check_sha
    call component_run

    mov si, tag_flight
    mov bp, flight_process
    mov di, component_check_full
    call component_run

    cmp byte [component_failed], 0
    jne .failed
    mov si, str_check_pass
    jmp short .emit_check
.failed:
    mov si, str_check_fail
.emit_check:
    call emit_str
    call emit_crlf
    mov si, tag_done
    call emit_str
    call emit_crlf
    ret

; SI=tag, BP=operation, DI=post-timing checker/checksum.  The crypto routines
; may clobber BP, so both near pointers live in memory across the call.
component_run:
    mov [component_op_ptr], bp
    mov [component_check_ptr], di
    call emit_str
    mov al, ' '
    call emit_char
    call read_tick_low
    mov bx, ax
.tick_edge:
    call read_tick_low
    cmp ax, bx
    je .tick_edge
    call read_tick
    mov [flight_t0_lo], ax
    mov [flight_t0_hi], dx
    call word [component_op_ptr]
    call read_tick
    sub ax, [flight_t0_lo]
    sbb dx, [flight_t0_hi]
    mov [flight_dt_lo], ax

    call word [component_check_ptr]
    mov [component_ck], ax
    jnc .checked
    mov byte [component_failed], 1
.checked:
    mov si, str_n
    call emit_str
    mov ax, 1
    call emit_dec16
    mov si, str_dt
    call emit_str
    mov ax, [flight_dt_lo]
    call emit_dec16
    mov si, str_ck
    call emit_str
    mov ax, [component_ck]
    call emit_hex16
    call emit_crlf
    ret

; The profile's ChaCha blocks (counter-zero OTK plus all data counters), with
; the same receive copies and in-place XORs as the full workload. No Poly/SHA.
component_chaxor:
    mov word [chacha_key_ptr], flight_key
    mov word [chacha_nonce_ptr], flight_nonce
    mov word [chacha_counter_low], 0
    mov word [chacha_counter_high], 0
    mov word [flight_chacha_count], 0
    mov word [flight_remaining], flight_cipher_len
    call chacha20_block
    inc word [flight_chacha_count]
    mov word [chacha_counter_low], 1
.next_chunk:
    mov cx, [flight_remaining]
    jcxz .done
    cmp cx, flight_rx_chunk_len
    jbe .chunk_ready
    mov cx, flight_rx_chunk_len
.chunk_ready:
    mov [flight_current_chunk], cx
    push ds
    pop es
    mov si, flight_cipher_template
    mov di, flight_chunk
    rep movsb
    mov si, flight_chunk
    mov cx, [flight_current_chunk]
    call flight_decrypt_chunk
    mov ax, [flight_current_chunk]
    sub [flight_remaining], ax
    jmp .next_chunk
.done:
    mov al, [flight_chunk + flight_inner_chunk_off]
    mov [flight_last_plain], al
    ret

component_poly_prepare:
    push ds
    pop es
    mov si, component_otk
    mov di, chacha_block
    mov cx, poly1305_r_len + poly1305_s_len
    rep movsb
    call poly1305_load_key
    ret

; The profile's Poly1305 blocks: padded five-byte AAD, all ciphertext blocks,
; and the length block. Includes receive copy and the accumulator/OTK
; save/restore shuttle at every 384-byte stream boundary. No ChaCha or SHA.
component_poly:
    mov word [flight_poly_count], 0
    mov word [flight_remaining], flight_cipher_len
    call flight_poly_init
    call flight_poly_save
.next_chunk:
    mov cx, [flight_remaining]
    jcxz .done
    cmp cx, flight_rx_chunk_len
    jbe .chunk_ready
    mov cx, flight_rx_chunk_len
.chunk_ready:
    mov [flight_current_chunk], cx
    push ds
    pop es
    mov si, flight_cipher_template
    mov di, flight_chunk
    rep movsb
    call flight_poly_restore
    mov si, flight_chunk
    mov cx, [flight_current_chunk]
    call flight_poly_update
    call flight_poly_save
    mov ax, [flight_current_chunk]
    sub [flight_remaining], ax
    jmp .next_chunk
.done:
    call flight_poly_restore
    call flight_poly_final
    ret

; SHA-256 over the profile's exact transcript length, including the same
; 384-byte receive-copy geometry. No ChaCha or Poly.
component_sha:
    mov word [flight_transcript_remaining], flight_transcript_len
    call sha256_init
.next_chunk:
    mov cx, [flight_transcript_remaining]
    jcxz .done
    cmp cx, flight_rx_chunk_len
    jbe .chunk_ready
    mov cx, flight_rx_chunk_len
.chunk_ready:
    mov [flight_current_chunk], cx
    push ds
    pop es
    mov si, flight_cipher_template
    mov di, flight_chunk
    rep movsb
    mov si, flight_chunk
    mov cx, [flight_current_chunk]
    push cx
    call sha256_update
    pop cx
    sub [flight_transcript_remaining], cx
    jmp .next_chunk
.done:
    mov di, flight_digest
    call sha256_finish
    ret

component_check_chaxor:
    mov si, chacha_block
    mov di, component_expected_last_block
    mov cx, chacha_block_len
    call compare_buffers
    jc .result
    cmp word [flight_chacha_count], flight_chacha_blocks
    jne .failed
    cmp word [chacha_counter_low], flight_chacha_blocks
    jne .failed
    cmp word [chacha_counter_high], 0
    jne .failed
    cmp word [flight_remaining], 0
    jne .failed
    cmp byte [flight_last_plain], 0x16
    jne .failed
    clc
    jmp short .result
.failed:
    stc
.result:
    pushf
    mov si, chacha_block
    mov cx, chacha_block_len
    call component_byte_checksum
    mov bx, ax
    mov si, flight_chunk
    mov cx, flight_final_chunk_len
    call component_byte_checksum
    add ax, bx
    cmp ax, component_expected_chaxor_ck
    je .checksum_ready
    popf
    stc
    ret
.checksum_ready:
    popf
    ret

component_check_poly:
    mov si, tls_finished_tag
    mov di, flight_expected_tag
    mov cx, tls_aead_tag_len
    call compare_buffers
    jc .result
    cmp word [flight_poly_count], flight_poly_blocks
    jne .failed
    cmp word [flight_poly_cipher_len], flight_cipher_len
    jne .failed
    cmp word [flight_remaining], 0
    jne .failed
    clc
    jmp short .result
.failed:
    stc
.result:
    pushf
    mov si, tls_finished_tag
    mov cx, tls_aead_tag_len / 2
    call component_word_checksum
    popf
    ret

component_check_sha:
    mov si, flight_digest
    mov di, component_expected_sha
    mov cx, sha256_digest_len
    call compare_buffers
    jc .result
    cmp word [flight_transcript_remaining], 0
    jne .failed
    clc
    jmp short .result
.failed:
    stc
.result:
    pushf
    mov si, flight_digest
    mov cx, sha256_digest_len / 2
    call component_word_checksum
    popf
    ret

component_check_full:
    call flight_check
    pushf
    call flight_checksum
    popf
    ret

component_byte_checksum:
    push bx
    xor bx, bx
.next:
    or cx, cx
    jz .done
    lodsb
    xor ah, ah
    add bx, ax
    dec cx
    jmp .next
.done:
    mov ax, bx
    pop bx
    ret

component_word_checksum:
    xor ax, ax
.next:
    or cx, cx
    jz .done
    add ax, [si]
    add si, 2
    dec cx
    jmp .next
.done:
    ret
%endif

; ---------------------------------------------------------------------------
; One observed TLS 1.3 encrypted server flight
; ---------------------------------------------------------------------------

flight_process:
    mov word [chacha_key_ptr], flight_key
    mov word [chacha_nonce_ptr], flight_nonce
    mov word [chacha_counter_low], 0
    mov word [chacha_counter_high], 0
    mov word [flight_chacha_count], 0
    mov word [flight_poly_count], 0
    mov word [flight_remaining], flight_cipher_len
    mov word [flight_transcript_remaining], flight_transcript_len

    call sha256_init

    ; RFC 8439 counter-zero block supplies the Poly1305 one-time key.
    call chacha20_block
    inc word [flight_chacha_count]
    call poly1305_load_key
    call flight_poly_init
    call flight_poly_save

    mov word [chacha_counter_low], 1
    mov word [chacha_counter_high], 0

.next_rx_chunk:
    mov cx, [flight_remaining]
    jcxz .record_done
    cmp cx, flight_rx_chunk_len
    jbe .chunk_len_ready
    mov cx, flight_rx_chunk_len
.chunk_len_ready:
    mov [flight_current_chunk], cx

    ; This copy represents the existing receive path's copy out of NIC-owned
    ; storage.  Keeping it inside the timed region avoids claiming a crypto-only
    ; number that the real draining-FIFO path cannot attain.
    push ds
    pop es
    mov si, flight_cipher_template
    mov di, flight_chunk
    rep movsb

    ; Authenticate ciphertext before overwriting it with plaintext.
    call flight_poly_restore
    mov si, flight_chunk
    mov cx, [flight_current_chunk]
    call flight_poly_update
    call flight_poly_save

    mov si, flight_chunk
    mov cx, [flight_current_chunk]
    call flight_decrypt_chunk

    ; TLSInnerPlaintext's final content-type byte is not a Handshake byte.
    mov cx, [flight_current_chunk]
    mov ax, [flight_transcript_remaining]
    cmp cx, ax
    jbe .hash_len_ready
    mov cx, ax
.hash_len_ready:
    mov si, flight_chunk
    push cx
    call sha256_update
    pop cx
    sub [flight_transcript_remaining], cx

    mov ax, [flight_current_chunk]
    sub [flight_remaining], ax
    jmp .next_rx_chunk

.record_done:
    mov al, [flight_chunk + flight_inner_chunk_off]
    mov [flight_last_plain], al
    call flight_poly_restore
    call flight_poly_final
    mov di, flight_digest
    call sha256_finish
    ret

; SI = mutable ciphertext, CX = bytes. Chunk boundaries are block-aligned at
; the 384-byte MSS; the profile-specific final tail consumes the last blocks.
flight_decrypt_chunk:
    or cx, cx
    jz .done
.next_block:
    call chacha20_block
    inc word [flight_chacha_count]
    mov dx, cx
    cmp dx, chacha_block_len
    jbe .xor_len_ready
    mov dx, chacha_block_len
.xor_len_ready:
    push cx
    mov cx, dx
    mov bx, chacha_block
.xor_byte:
    mov al, [si]
    xor al, [bx]
    mov [si], al
    inc si
    inc bx
    loop .xor_byte
    pop cx
    sub cx, dx
    inc word [chacha_counter_low]
    jnz .counter_ready
    inc word [chacha_counter_high]
.counter_ready:
    or cx, cx
    jnz .next_block
.done:
    ret

; ---------------------------------------------------------------------------
; Incremental TLS 1.3 Poly1305 (AAD is the five-byte outer record header)
; ---------------------------------------------------------------------------

flight_poly_init:
    call poly1305_clear_acc
    call poly1305_clear_block
    push ds
    pop es
    mov si, flight_aad
    mov di, poly_block
    mov cx, flight_aad_len
    rep movsb
    call flight_poly_process_block
    call poly1305_clear_block
    mov byte [flight_poly_fill], 0
    mov word [flight_poly_cipher_len], 0
    ret

; SI = ciphertext, CX = byte count.
flight_poly_update:
    or cx, cx
    jz .done
    add [flight_poly_cipher_len], cx
.next_byte:
    mov bl, [flight_poly_fill]
    xor bh, bh
    mov al, [si]
    mov [poly_block + bx], al
    inc si
    inc bl
    cmp bl, 16
    jb .keep
    push cx
    push si
    call flight_poly_process_block
    call poly1305_clear_block
    pop si
    pop cx
    xor bl, bl
.keep:
    mov [flight_poly_fill], bl
    dec cx
    jnz .next_byte
.done:
    ret

flight_poly_final:
    cmp byte [flight_poly_fill], 0
    je .lengths
    call flight_poly_process_block
.lengths:
    call poly1305_clear_block
    mov byte [poly_block], flight_aad_len
    mov ax, [flight_poly_cipher_len]
    mov [poly_block + 8], ax
    call flight_poly_process_block
    call poly1305_emit_tag
    ret

flight_poly_process_block:
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    inc word [flight_poly_count]
    ret

; chacha20_block aliases poly_acc/poly_block, exactly as in the product.  Carry
; the 33-byte accumulator/partial block plus the 32-byte OTK across each chunk.
flight_poly_save:
    push si
    push di
    push cx
    push es
    push ds
    pop es
    mov si, poly_acc
    mov di, flight_poly_saved_state
    mov cx, poly1305_acc_len + 16
    rep movsb
    mov si, poly_r
    mov di, flight_poly_saved_otk
    mov cx, poly1305_r_len + poly1305_s_len
    rep movsb
    pop es
    pop cx
    pop di
    pop si
    ret

flight_poly_restore:
    push si
    push di
    push cx
    push es
    push ds
    pop es
    mov si, flight_poly_saved_state
    mov di, poly_acc
    mov cx, poly1305_acc_len + 16
    rep movsb
    mov si, flight_poly_saved_otk
    mov di, poly_r
    mov cx, poly1305_r_len + poly1305_s_len
    rep movsb
    pop es
    pop cx
    pop di
    pop si
    ret

; ---------------------------------------------------------------------------
; Correctness / reporting helpers
; ---------------------------------------------------------------------------

flight_check:
    mov si, tls_finished_tag
    mov di, flight_expected_tag
    mov cx, tls_aead_tag_len
    call compare_buffers
    jc .failed
    mov si, flight_digest
    mov di, flight_expected_digest
    mov cx, sha256_digest_len
    call compare_buffers
    jc .failed
    cmp byte [flight_last_plain], 0x16
    jne .failed
    cmp word [flight_chacha_count], flight_chacha_blocks
    jne .failed
    cmp word [flight_poly_count], flight_poly_blocks
    jne .failed
    cmp word [flight_poly_cipher_len], flight_cipher_len
    jne .failed
    cmp word [flight_remaining], 0
    jne .failed
    cmp word [flight_transcript_remaining], 0
    jne .failed
    clc
    ret
.failed:
    stc
    ret

compare_buffers:
    or cx, cx
    jz .equal
.next:
    mov al, [si]
    cmp al, [di]
    jne .different
    inc si
    inc di
    loop .next
.equal:
    clc
    ret
.different:
    stc
    ret

flight_checksum:
    push bx
    push cx
    push dx
    push si
    xor dx, dx
    mov si, tls_finished_tag
    mov cx, tls_aead_tag_len / 2
.tag_word:
    add dx, [si]
    add si, 2
    loop .tag_word
    mov si, flight_digest
    mov cx, sha256_digest_len / 2
.digest_word:
    add dx, [si]
    add si, 2
    loop .digest_word
    mov ax, dx
    pop si
    pop dx
    pop cx
    pop bx
    ret

deploy_crypto_constants:
    push ds
    pop es
    mov si, chacha_constants_constant
    mov di, chacha_constants
    mov cx, chacha_constants_len
    rep movsb
    mov si, poly1305_prime_constant
    mov di, poly1305_prime
    mov cx, poly1305_prime_len
    rep movsb
    mov si, sha256_initial_state_constant
    mov di, sha256_initial_state
    mov cx, sha256_initial_state_len
    rep movsb
    mov si, sha256_k_constant
    mov di, sha256_k
    mov cx, sha256_k_len
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

emit_hexbuf:
    push ax
    push bx
    push cx
    push si
.next:
    or cx, cx
    jz .done
    mov al, [si]
    call emit_hex8
    inc si
    dec cx
    jmp .next
.done:
    call emit_crlf
    pop si
    pop cx
    pop bx
    pop ax
    ret

emit_hex8:
    push ax
    push bx
    push cx
    mov bl, al
    mov cl, 4
    shr al, cl
    call emit_nybble
    mov al, bl
    and al, 0x0f
    call emit_nybble
    pop cx
    pop bx
    pop ax
    ret

emit_nybble:
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .emit
    add al, 7
.emit:
    jmp emit_char

emit_hex16:
    push ax
    xchg al, ah
    call emit_hex8
    pop ax
    call emit_hex8
    ret

emit_dec16:
    push ax
    push bx
    push cx
    push dx
    mov bx, 10
    xor cx, cx
.divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .divide
.digit:
    pop ax
    add al, '0'
    call emit_char
    loop .digit
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; ---------------------------------------------------------------------------
; Shipping crypto implementations under test
; ---------------------------------------------------------------------------

%include "core/chacha20.inc"
%include "core/poly1305.inc"
%include "core/sha256.inc"

; ---------------------------------------------------------------------------
; Constants, deterministic vector, and writable benchmark state
; ---------------------------------------------------------------------------

tag_flight     db 'FLIGHT', 0
tag_done       db 'DONE', 0
str_n          db 'N=', 0
str_dt         db ' dt=', 0
str_ck         db ' ck=', 0
str_tag        db 'TAG ', 0
str_sha        db 'SHA ', 0
str_ops        db 'OPS chacha=', 0
str_poly       db ' poly=', 0
str_sha_blocks db ' sha=', 0
str_inner      db ' inner=', 0
str_check_pass db 'CHECK PASS', 0
str_check_fail db 'CHECK FAIL', 0

%ifdef FLIGHT_COMPONENTS
tag_chaxor db 'CHAXOR', 0
tag_poly   db 'POLY', 0
tag_shaflt db 'SHAFLT', 0
%endif

flight_key:
    db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
flight_nonce:
    db 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5
    db 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab
flight_aad:
    db 0x17, 0x03, 0x03
    db (flight_outer_payload_len >> 8) & 0xff
    db flight_outer_payload_len & 0xff

; c[i] = ((i*73 + 41) XOR (i >> 1)) mod 256, except the profile's
; final-chunk offset.  That byte makes the last plaintext byte inner type 0x16.
flight_cipher_template:
%assign flight_i 0
%rep flight_rx_chunk_len
%if flight_i = flight_inner_chunk_off
    db flight_inner_cipher_byte
%else
    db ((flight_i * 73 + 41) ^ (flight_i >> 1)) & 0xff
%endif
%assign flight_i flight_i + 1
%endrep

flight_expected_tag:
%ifdef FLIGHT_PROFILE_CERTCOMP
    db 0x26, 0xbb, 0x2d, 0xb2, 0x3d, 0x60, 0xf2, 0x86
    db 0xaf, 0x03, 0x0f, 0x46, 0x2c, 0x8d, 0x3c, 0x95
flight_expected_digest:
    db 0xd2, 0xa7, 0xf9, 0x87, 0x11, 0xa7, 0x2b, 0xd7
    db 0xf2, 0x14, 0xc1, 0x96, 0xf0, 0xe5, 0xe7, 0x20
    db 0xf3, 0x85, 0x01, 0xa7, 0xb2, 0x24, 0x2e, 0xc5
    db 0x8b, 0x56, 0xca, 0x37, 0x57, 0x1a, 0x9f, 0x85
%else
%ifdef FLIGHT_PROFILE_ECDSA
    db 0x57, 0x92, 0x22, 0x1a, 0x60, 0xd9, 0xe0, 0xd1
    db 0xe0, 0x1f, 0x51, 0x56, 0xaa, 0x9d, 0x64, 0xb0
flight_expected_digest:
    db 0xc1, 0x07, 0xbf, 0x30, 0x77, 0xb5, 0x09, 0x16
    db 0xa6, 0xce, 0x96, 0xfe, 0x13, 0x27, 0x0e, 0x32
    db 0x4f, 0x5b, 0x7e, 0x52, 0x36, 0xcf, 0xba, 0xab
    db 0xbb, 0x0c, 0x71, 0x61, 0x82, 0x75, 0x36, 0x2c
%else
    db 0x5b, 0x0b, 0x72, 0x86, 0x41, 0x0a, 0xc9, 0x72
    db 0x7d, 0x00, 0x59, 0x42, 0x75, 0xd1, 0xab, 0xf4
flight_expected_digest:
    db 0x30, 0xd3, 0xe8, 0xa2, 0x0f, 0xca, 0xd7, 0xb5
    db 0x40, 0x79, 0xe9, 0xb9, 0x5b, 0x83, 0x2b, 0xe5
    db 0x13, 0x39, 0x56, 0xd9, 0x69, 0x81, 0xbb, 0x20
    db 0xee, 0xc7, 0x23, 0x2e, 0xa0, 0x2d, 0xf2, 0xf1
%endif
%endif

%ifdef FLIGHT_COMPONENTS
; Counter-zero ChaCha block prefix, transformed by shipping
; poly1305_load_key outside the isolated POLY timer.
component_otk:
    db 0xf7, 0xba, 0xf7, 0xe4, 0xcc, 0x1b, 0xfe, 0xae
    db 0xa3, 0xe5, 0x88, 0x5e, 0x99, 0xca, 0x20, 0x9f
    db 0x52, 0x0a, 0xde, 0xa7, 0x39, 0x99, 0x7a, 0x35
    db 0x7f, 0x85, 0xab, 0x6e, 0x14, 0x00, 0x71, 0x97
component_expected_last_block:
%ifdef FLIGHT_PROFILE_CERTCOMP
    db 0xd8, 0x17, 0xb5, 0x70, 0x19, 0xf2, 0x94, 0xa9
    db 0xc9, 0x6d, 0x8a, 0x4f, 0xad, 0xeb, 0xc0, 0x45
    db 0x96, 0x7b, 0x91, 0x84, 0xf4, 0x48, 0xb2, 0x17
    db 0xed, 0x47, 0x18, 0x89, 0x35, 0xf1, 0xff, 0xa7
    db 0xf3, 0xad, 0x9c, 0xb5, 0x93, 0xd4, 0x78, 0x7e
    db 0x18, 0x52, 0x6d, 0x62, 0x08, 0xe3, 0xd0, 0x7b
    db 0xfd, 0xac, 0x6c, 0xe1, 0x44, 0x84, 0x17, 0xc4
    db 0x08, 0x97, 0x26, 0x9a, 0x55, 0xf4, 0xc1, 0x4e
component_expected_sha:
    db 0x25, 0x36, 0x43, 0xa6, 0x91, 0x7f, 0xa1, 0x9f
    db 0xca, 0xdf, 0x69, 0xea, 0xf3, 0xd0, 0x38, 0xa5
    db 0x7b, 0x44, 0x84, 0x4e, 0x1a, 0x8f, 0x32, 0xc1
    db 0x1b, 0xc7, 0x40, 0x76, 0x71, 0x5c, 0x9d, 0x56
%else
%ifdef FLIGHT_PROFILE_ECDSA
    db 0x41, 0x06, 0x1a, 0x51, 0xf0, 0xf1, 0xfb, 0xd8
    db 0x49, 0x62, 0xff, 0xc7, 0x5a, 0xad, 0x68, 0xba
    db 0x3c, 0x8f, 0x31, 0xa3, 0x34, 0x5a, 0x83, 0xa9
    db 0xf1, 0xce, 0x13, 0xb7, 0x27, 0x4a, 0xa6, 0xb2
    db 0x1b, 0xc2, 0x0e, 0xc2, 0x5a, 0x9c, 0x48, 0xb0
    db 0x73, 0xbe, 0xc3, 0x3f, 0x95, 0x54, 0x37, 0x9c
    db 0xfa, 0x25, 0x5c, 0xf7, 0x65, 0x4e, 0x79, 0x9e
    db 0x5c, 0xd2, 0x51, 0xf8, 0xc7, 0xcf, 0xb2, 0xf1
component_expected_sha:
    db 0x82, 0x68, 0x0e, 0x1b, 0x19, 0xba, 0xb2, 0xf1
    db 0x02, 0x4d, 0xaa, 0xb8, 0x5a, 0xd1, 0x7e, 0x7e
    db 0x5c, 0x8f, 0x7b, 0xd9, 0x55, 0xf3, 0x7d, 0x95
    db 0x38, 0xf8, 0x0b, 0x91, 0xac, 0x7c, 0xd8, 0xad
%else
    db 0x8e, 0x64, 0xd6, 0x55, 0xab, 0x4e, 0x7e, 0x96
    db 0xd5, 0x73, 0xcd, 0x82, 0x93, 0xd8, 0x7c, 0x60
    db 0x8a, 0x80, 0x15, 0xd3, 0x0f, 0x37, 0xb7, 0x08
    db 0x52, 0x1e, 0xa5, 0x19, 0x46, 0x33, 0xee, 0x7f
    db 0xe9, 0xfc, 0x9c, 0x61, 0x1b, 0xf9, 0x7d, 0xf6
    db 0xb9, 0x89, 0xb8, 0x58, 0xe0, 0x00, 0x49, 0x7e
    db 0x14, 0x71, 0xe9, 0xde, 0x7f, 0x21, 0x47, 0x7d
    db 0x05, 0x1c, 0xec, 0xfb, 0x32, 0xdd, 0x59, 0xb2
component_expected_sha:
    db 0x1f, 0x06, 0xf6, 0xb9, 0x5b, 0x79, 0xad, 0x32
    db 0x28, 0x97, 0x91, 0x4f, 0xeb, 0x4f, 0x94, 0x00
    db 0x51, 0xf1, 0x39, 0xce, 0x82, 0x0f, 0x37, 0xa3
    db 0xed, 0x5b, 0xc9, 0xcc, 0xc8, 0x10, 0x68, 0xc1
%endif
%endif
%endif

chacha_constants_constant:
    dw 0x7865, 0x6170, 0x646e, 0x3320
    dw 0x2d32, 0x7962, 0x6574, 0x6b20
poly1305_prime_constant:
    db 0xfb
    times 15 db 0xff
    db 0x03
sha256_initial_state_constant:
    dw 0xe667, 0x6a09, 0xae85, 0xbb67
    dw 0xf372, 0x3c6e, 0xf53a, 0xa54f
    dw 0x527f, 0x510e, 0x688c, 0x9b05
    dw 0xd9ab, 0x1f83, 0xcd19, 0x5be0
sha256_k_constant:
    dw 0x2f98, 0x428a, 0x4491, 0x7137
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

flight_t0_lo                dw 0
flight_t0_hi                dw 0
flight_dt_lo                dw 0
flight_remaining            dw 0
flight_transcript_remaining dw 0
flight_current_chunk        dw 0
flight_chacha_count         dw 0
flight_poly_count           dw 0
flight_poly_cipher_len      dw 0
flight_poly_fill            db 0
flight_last_plain           db 0
flight_poly_saved_state     times (poly1305_acc_len + 16) db 0
flight_poly_saved_otk       times (poly1305_r_len + poly1305_s_len) db 0
flight_digest               times sha256_digest_len db 0
flight_chunk                times flight_rx_chunk_len db 0

%ifdef FLIGHT_COMPONENTS
component_op_ptr    dw 0
component_check_ptr dw 0
component_ck        dw 0
component_failed    db 0
%endif

image_end:

; The entire resident image lives below the product's high crypto arena.  The
; fixed high arena and the 0x3f00..0x4000 BASIC stack guard therefore remain
; available under the 16 KiB contract.
%if (image_end - core_header) > (high_crypto_scratch_start - core_load_addr)
%error "TLS 1.3 flight benchmark image overlaps high crypto scratch"
%endif
%if high_crypto_scratch_end > (basic_sidecar_stack_top_16k - basic_sidecar_stack_guard_len_16k)
%error "TLS 1.3 flight benchmark high scratch overlaps 16 KiB stack guard"
%endif
