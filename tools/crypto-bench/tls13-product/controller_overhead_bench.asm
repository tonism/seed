; Exact 6 MHz 286 smoke/timing gate for the TLS 1.3 controller boundary.
;
; This image executes the already oracle-gated symmetric overlay and adds the
; operations that isolated crypto timings otherwise omit:
;
;   HELLOHASH  strict fixed-profile ServerHello parse, transcript import,
;              post-receive ServerHello SHA-256, and hello digest check.
;   CTRLRACE   hot handshake schedule, streamed protected-flight AEAD,
;              a live pre-CV transcript snapshot, RFC 8446 CV-input hashing,
;              strict four-message/profile parsing, exact authenticated
;              CompressedCertificate pin match, live Finished extraction and
;              comparison, client Finished seal, width-7 far-table shuttles,
;              and the 58-byte network handoff/copy/checksum.
;
; The exact certificate pin represents a same-machine acquisition result: the
; compressed Certificate message may become trusted only after target-local
; Brotli/X.509/anchor/SAN/time/CV validation on a closed first connection.
; Comparing it here binds the live retry to that validated leaf and chain.
;
; The final network handoff is deliberately a memory/checksum smoke, not a NIC
; transmit.  A product VM/pcap gate still has to prove the real packet leaves
; before the provider deadline.

bits 16
cpu 8086
org 0x1000

%include "build/ibm_pc_5150/crypto-bench/tls13-286-controller/fixture_meta.inc"

sha256_digest_len equ 32
sha256_block_size equ 64
sha256_k_len equ 256

sym_overlay_base equ 0x1800
sym_entry_table equ sym_overlay_base + 32
sym_init_entry equ sym_entry_table + 0 * 2
sym_transcript_update_entry equ sym_entry_table + 2 * 2
sym_critical_entry equ sym_entry_table + 3 * 2
sym_hs_open_begin_entry equ sym_entry_table + 4 * 2
sym_open_chunk_entry equ sym_entry_table + 6 * 2
sym_open_finish_entry equ sym_entry_table + 7 * 2
sym_verify_finished_entry equ sym_entry_table + 8 * 2
sym_build_finished_entry equ sym_entry_table + 9 * 2
sym_transcript_import_entry equ sym_entry_table + 15 * 2

sym_hello_handoff equ 0x0d00
sym_shared_secret equ 0x3600
sym_received_finished equ 0x38f0
sym_io equ 0x39a0

; The current 6,144-byte overlay publishes 0x3000 in header word +12.  The
; runtime assertion below fails closed if that generated ABI ever moves.
sha256_state equ 0x3000
sha256_a equ sha256_state + 32
sha256_b equ sha256_a + 4
sha256_c equ sha256_b + 4
sha256_d equ sha256_c + 4
sha256_e equ sha256_d + 4
sha256_f equ sha256_e + 4
sha256_g equ sha256_f + 4
sha256_h equ sha256_g + 4
sha256_t1 equ sha256_h + 4
sha256_t2 equ sha256_t1 + 4
sha256_new_e equ sha256_t2 + 4
sha256_tmp equ sha256_new_e + 4
sha256_w_ptr equ sha256_tmp + 4
sha256_k_ptr equ sha256_w_ptr + 2
sha256_len_low equ sha256_k_ptr + 2
sha256_len_high equ sha256_len_low + 2
sha256_saved_len_low equ sha256_len_high + 2
sha256_saved_len_high equ sha256_saved_len_low + 2
sha256_bit_len0 equ sha256_saved_len_high + 2
sha256_bit_len1 equ sha256_bit_len0 + 2
sha256_bit_len2 equ sha256_bit_len1 + 2
sha256_bit_len3 equ sha256_bit_len2 + 2
sha256_digest_ptr equ sha256_bit_len3 + 2
hmac_key_ptr equ sha256_digest_ptr + 2
hmac_key_len equ hmac_key_ptr + 2
hmac_data1_ptr equ hmac_key_len + 2
hmac_data1_len equ hmac_data1_ptr + 2
hmac_data2_ptr equ hmac_data1_len + 2
hmac_data2_len equ hmac_data2_ptr + 2
hmac_output_ptr equ hmac_data2_len + 2
sha256_block_len equ hmac_output_ptr + 2
sha256_saved_block_len equ sha256_block_len + 1
sha256_schedule_count equ sha256_saved_block_len + 1
sha256_round_count equ sha256_schedule_count + 1
sha256_block equ sha256_round_count + 1
sha256_w equ sha256_block + sha256_block_size
sha256_saved_state equ sha256_w + sha256_k_len
sha256_saved_block equ sha256_saved_state + 32
hmac_ipad equ 0x6000
hmac_opad equ hmac_ipad + 64
hmac_inner_digest equ hmac_opad + 64
hmac_prepared_inner_state equ hmac_inner_digest + 32
hmac_prepared_outer_state equ hmac_prepared_inner_state + 32

far_table_segment equ 0x7b40
far_leaf_table_offset equ 0x1fc0
far_point_scratch equ 0x6800
mock_tx_buffer equ 0x6c00

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

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0xfff0
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init

    mov byte [fail_code], 1
    cmp word [sym_overlay_base + 12], sha256_state
    jne fail
    cmp word [sym_overlay_base + 28], 64
    jne fail

    ; sym_init is pre-TCP state clearing and is deliberately outside the
    ; provider window.  HELLOHASH starts with the target-published SHA state
    ; after ClientHello and measures only work forced by ServerHello arrival.
    mov byte [fail_code], 2
    call word [sym_init_entry]
    jc fail
    mov si, client_hello_handoff_blob
    mov di, sym_hello_handoff
    mov cx, controller_hello_handoff_bytes
    rep movsb

    mov byte [fail_code], 3
    call tick_start
    mov byte [fail_code], 31
    call parse_server_hello
    jc fail
    mov byte [fail_code], 32
    call word [sym_transcript_import_entry]
    jc fail
    mov byte [fail_code], 33
    mov si, server_hello_blob
    mov cx, controller_server_hello_bytes
    call hash_range
    jc fail
    mov byte [fail_code], 34
    mov di, hello_digest_work
    call sha256_finish
    call tick_stop
    mov [hello_ticks], ax
    mov byte [fail_code], 4
    mov si, hello_digest_work
    mov di, hello_digest_expected
    mov cx, sha256_digest_len
    repe cmpsb
    jne fail

    ; Restore the complete hello publication and the target-local ML-KEM
    ; result.  X25519's server share is part of the publication and is copied
    ; by sym_transcript_import into shared_secret[32..63].
    mov byte [fail_code], 5
    call word [sym_init_entry]
    jc fail
    mov si, full_hello_handoff_blob
    mov di, sym_hello_handoff
    mov cx, controller_hello_handoff_bytes
    rep movsb
    mov si, mlkem_secret_blob
    mov di, sym_shared_secret
    mov cx, 32
    rep movsb

    mov byte [fail_code], 6
    call tick_start
    call word [sym_transcript_import_entry]
    jc fail
    call word [sym_critical_entry]
    jc fail

    ; Header and tag are retained outside the mutable ciphertext buffer.
    mov si, record_meta_blob
    mov di, sym_io
    mov cx, 5
    rep movsb
    mov ax, controller_pre_finished_plaintext_bytes
    call word [sym_hs_open_begin_entry]
    jc fail

    ; Cut exactly at the CertificateVerify transcript boundary.  Plaintext is
    ; still quarantined here; its derived digest is not consumed unless the
    ; complete record tag later verifies.
    mov byte [fail_code], 7
    mov si, flight_cipher_blob
    mov cx, controller_pre_cv_plaintext_bytes
    call open_range
    jc fail
    call build_live_cv_digest
    jc fail

    mov byte [fail_code], 8
    mov si, flight_cipher_blob + controller_pre_cv_plaintext_bytes
    mov cx, controller_flight_cipher_bytes - controller_pre_cv_plaintext_bytes
    call open_range
    jc fail
    mov si, record_meta_blob + 5
    call word [sym_open_finish_entry]
    jc fail

    ; Only authenticated plaintext reaches the parser/pin boundary.
    mov byte [fail_code], 9
    call parse_and_pin_flight
    jc fail
    mov si, live_cv_digest
    mov di, cv_digest_expected
    mov cx, sha256_digest_len
    repe cmpsb
    jne fail

    mov byte [fail_code], 10
    call word [sym_verify_finished_entry]
    jc fail
    call word [sym_build_finished_entry]
    jc fail
    cmp ax, controller_client_finished_record_bytes
    jne fail
    mov si, sym_io
    mov cx, controller_client_finished_record_bytes
    call checksum_bytes
    mov [last_checksum], dx
    cmp dx, controller_client_finished_checksum
    jne fail

    ; The measured width-7 verifier uses near tables.  Product placement keeps
    ; G and live-leaf Q in high conventional memory, so account for the exact
    ; 37 columns * two selected 64-byte affine points copied to low scratch.
    mov byte [fail_code], 11
    call shuttle_width7_points

    ; Model the already-existing TCP/NIC handoff boundary: copy the exact
    ; 58-byte record and fold every word as the packet/checksum path does.
    ; Physical transmit/pcap timing remains a product-level regression gate.
    mov byte [fail_code], 12
    call handoff_client_finished
    jc fail

    call tick_stop
    mov [controller_ticks], ax

    mov si, tag_hello
    mov ax, [hello_ticks]
    call emit_pass_metric
    mov si, tag_controller
    mov ax, [controller_ticks]
    call emit_pass_metric
    mov si, tag_check
    call emit_str
    mov si, str_validation
    call emit_str
    mov ax, 1
    call emit_hex16
    call emit_crlf
    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

fail:
    mov si, tag_fail
    call emit_str
    call emit_crlf
    mov si, tag_fail_code
    call emit_str
    mov si, str_validation
    call emit_str
    xor ax, ax
    mov al, [fail_code]
    call emit_hex16
    call emit_crlf
    mov si, tag_fail_sum
    call emit_str
    mov si, str_validation
    call emit_str
    mov ax, [last_checksum]
    call emit_hex16
    call emit_crlf
    mov si, tag_done
    call emit_str
    call emit_crlf
    jmp start.hang

; Validate the exact fixed OpenAI 286 profile without pinning random/session
; bytes.  The extension set is exactly supported_versions + hybrid key_share.
parse_server_hello:
    mov si, server_hello_blob
    cmp byte [si], 2
    jne .bad
    cmp byte [si + 1], 0
    jne .bad
    cmp word [si + 2], 0xb604
    jne .bad
    cmp word [si + 4], 0x0303
    jne .bad
    cmp byte [si + 38], 32
    jne .bad
    cmp word [si + 71], 0x0313
    jne .bad
    cmp byte [si + 73], 0
    jne .bad
    cmp word [si + 74], 0x6e04
    jne .bad
    cmp word [si + 76], 0x2b00
    jne .bad
    cmp word [si + 78], 0x0200
    jne .bad
    cmp word [si + 80], 0x0403
    jne .bad
    cmp word [si + 82], 0x3300
    jne .bad
    cmp word [si + 84], 0x6404
    jne .bad
    cmp word [si + 86], 0xec11
    jne .bad
    cmp word [si + 88], 0x6004
    jne .bad
    clc
    ret
.bad:
    stc
    ret

; SI=mutable ciphertext, CX=bytes.  Feed <=384-byte chunks and preserve the
; exact caller range even though the overlay entry preserves SI/CX itself.
open_range:
    mov [range_ptr], si
    mov [range_remaining], cx
.next:
    mov cx, [range_remaining]
    or cx, cx
    jz .done
    cmp cx, 384
    jbe .have
    mov cx, 384
.have:
    mov [range_chunk], cx
    mov si, [range_ptr]
    call word [sym_open_chunk_entry]
    jc .bad
    mov cx, [range_chunk]
    add [range_ptr], cx
    sub [range_remaining], cx
    jmp .next
.done:
    clc
    ret
.bad:
    stc
    ret

; SI=bytes, CX=len.  Preserve the overlay's product MSS-sized update ABI.
hash_range:
    mov [range_ptr], si
    mov [range_remaining], cx
.next:
    mov cx, [range_remaining]
    or cx, cx
    jz .done
    cmp cx, 384
    jbe .have
    mov cx, 384
.have:
    mov [range_chunk], cx
    mov si, [range_ptr]
    call word [sym_transcript_update_entry]
    jc .bad
    mov cx, [range_chunk]
    add [range_ptr], cx
    sub [range_remaining], cx
    jmp .next
.done:
    clc
    ret
.bad:
    stc
    ret

; Snapshot the live transcript before CertificateVerify, calculate the exact
; RFC 8446 signed-input digest, then restore the transcript so CV bytes can be
; appended for server Finished verification.
build_live_cv_digest:
    call save_sha_context
    mov di, pre_cv_transcript_hash
    call sha256_finish

    mov di, cv_input_work
    mov al, 0x20
    mov cx, 64
    rep stosb
    mov si, cv_context
    mov cx, cv_context_len
    rep movsb
    xor al, al
    stosb
    mov si, pre_cv_transcript_hash
    mov cx, sha256_digest_len
    rep movsb

    call sha256_init
    mov si, cv_input_work
    mov cx, controller_cv_signed_input_bytes
    call sha256_update
    mov di, live_cv_digest
    call sha256_finish
    call restore_sha_context
    clc
    ret

save_sha_context:
    push es
    push ds
    pop es
    mov si, sha256_state
    mov di, saved_sha_state
    mov cx, 32
    rep movsb
    mov si, sha256_block
    mov di, saved_sha_block
    mov cx, 64
    rep movsb
    mov ax, [sha256_len_low]
    mov [saved_sha_len_low], ax
    mov ax, [sha256_len_high]
    mov [saved_sha_len_high], ax
    mov al, [sha256_block_len]
    mov [saved_sha_block_len], al
    pop es
    ret

restore_sha_context:
    push es
    push ds
    pop es
    mov si, saved_sha_state
    mov di, sha256_state
    mov cx, 32
    rep movsb
    mov si, saved_sha_block
    mov di, sha256_block
    mov cx, 64
    rep movsb
    mov ax, [saved_sha_len_low]
    mov [sha256_len_low], ax
    mov ax, [saved_sha_len_high]
    mov [sha256_len_high], ax
    mov al, [saved_sha_block_len]
    mov [sha256_block_len], al
    pop es
    ret

; Strict fixed-profile message framing plus the authenticated byte pin.  The
; ECDSA module separately performs strict canonical DER/range verification.
parse_and_pin_flight:
    mov si, flight_cipher_blob
    cmp byte [si], 8
    jne .bad
    cmp byte [si + 1], 0
    jne .bad
    cmp word [si + 2], 0x0600
    jne .bad

    add si, controller_encrypted_extensions_bytes
    cmp byte [si], 25
    jne .bad
    cmp byte [si + 1], 0
    jne .bad
    cmp word [si + 2], 0x0307
    jne .bad
    cmp word [si + 4], 0x0200
    jne .bad
    cmp byte [si + 6], 0
    jne .bad
    cmp word [si + 7], 0xbb09
    jne .bad
    cmp byte [si + 9], 0
    jne .bad
    cmp word [si + 10], 0xfb06
    jne .bad
    mov di, compressed_certificate_pin
    mov cx, controller_compressed_certificate_bytes
    repe cmpsb
    jne .bad

    mov si, flight_cipher_blob + controller_pre_cv_plaintext_bytes
    cmp byte [si], 15
    jne .bad
    cmp byte [si + 1], 0
    jne .bad
    cmp word [si + 2], 0x4c00
    jne .bad
    cmp word [si + 4], 0x0304
    jne .bad
    cmp word [si + 6], 0x4800
    jne .bad

    add si, controller_certificate_verify_bytes
    cmp byte [si], 20
    jne .bad
    cmp byte [si + 1], 0
    jne .bad
    cmp word [si + 2], 0x2000
    jne .bad
    cmp byte [si + controller_finished_bytes], 0x16
    jne .bad
    add si, 4
    mov di, sym_received_finished
    mov cx, 32
    rep movsb
    clc
    ret
.bad:
    stc
    ret

shuttle_width7_points:
    push ax
    push bp
    push cx
    push si
    push di
    push ds
    push es
    xor ax, ax
    mov es, ax
    mov ax, far_table_segment
    mov ds, ax
    xor si, si
    mov bp, 37
.g:
    mov di, far_point_scratch
    mov cx, 32
    rep movsw
    dec bp
    jnz .g
    mov si, far_leaf_table_offset
    mov bp, 37
.q:
    mov di, far_point_scratch
    mov cx, 32
    rep movsw
    dec bp
    jnz .q
    pop es
    pop ds
    pop di
    pop si
    pop cx
    pop bp
    pop ax
    ret

handoff_client_finished:
    push es
    push ds
    pop es
    mov si, sym_io
    mov di, mock_tx_buffer
    mov cx, controller_client_finished_record_bytes
    rep movsb
    mov si, mock_tx_buffer
    mov cx, controller_client_finished_record_bytes
    call checksum_bytes
    cmp dx, controller_client_finished_checksum
    jne .bad
    pop es
    clc
    ret
.bad:
    pop es
    stc
    ret

checksum_bytes:
    xor dx, dx
.next:
    or cx, cx
    jz .done
    lodsb
    xor ah, ah
    add dx, ax
    dec cx
    jmp .next
.done:
    ret

tick_start:
    call read_tick_low
    mov bx, ax
.edge:
    call read_tick_low
    cmp ax, bx
    je .edge
    call read_tick
    mov [t0_lo], ax
    mov [t0_hi], dx
    ret

tick_stop:
    call read_tick
    sub ax, [t0_lo]
    sbb dx, [t0_hi]
    ret

read_tick:
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret

read_tick_low:
    mov ax, [0x046c]
    ret

emit_pass_metric:
    push ax
    call emit_str
    mov si, str_n
    call emit_str
    mov ax, 1
    call emit_dec16
    mov si, str_dt
    call emit_str
    pop ax
    call emit_dec16
    mov si, str_ck
    call emit_str
    mov ax, 1
    call emit_hex16
    call emit_crlf
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
    jmp short .next
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
.digit:
    rol dx, 1
    rol dx, 1
    rol dx, 1
    rol dx, 1
    mov al, dl
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .emit
    add al, 7
.emit:
    call emit_char
    loop .digit
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
.divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .divide
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

tag_hello db 'HELLOHASH', 0
tag_controller db 'CTRLRACE', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'BAD', 0
tag_fail_code db 'ERRCODE', 0
tag_fail_sum db 'ERRSUM', 0
str_n db ' N=', 0
str_dt db ' dt=', 0
str_ck db ' ck=', 0
str_validation db ' N=1 dt=0 ck=', 0

t0_lo dw 0
t0_hi dw 0
hello_ticks dw 0
controller_ticks dw 0
range_ptr dw 0
range_remaining dw 0
range_chunk dw 0
fail_code db 0
last_checksum dw 0

cv_context db 'TLS 1.3, server CertificateVerify'
cv_context_len equ $ - cv_context

; The resident controller must fit below the existing symmetric overlay.
times 0x1800 - ($ - $$ + 0x1000) db 0

sym_overlay_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/tls13_sym_overlay.bin"
sym_overlay_blob_end:

%if (sym_overlay_blob_end - sym_overlay_blob) != 6144
%error "symmetric overlay geometry changed; regenerate and re-audit scratch ABI"
%endif

times 0x4200 - ($ - $$ + 0x1000) db 0

client_hello_handoff_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/client-hello-handoff.bin"
full_hello_handoff_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/full-hello-handoff.bin"
server_hello_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/server-hello.bin"
hello_digest_expected:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/hello-digest.bin"
mlkem_secret_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/mlkem-secret.bin"
record_meta_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/record-meta.bin"
flight_cipher_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/flight-cipher.bin"
compressed_certificate_pin:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/compressed-certificate-pin.bin"
cv_digest_expected:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-controller/cv-digest.bin"

align 2
hello_digest_work times 32 db 0
pre_cv_transcript_hash times 32 db 0
live_cv_digest times 32 db 0
cv_input_work times controller_cv_signed_input_bytes db 0
saved_sha_state times 32 db 0
saved_sha_block times 64 db 0
saved_sha_len_low dw 0
saved_sha_len_high dw 0
saved_sha_block_len db 0

; A second copy of the shipping SHA implementation provides an addressable
; snapshot/finalize helper around the incbin symmetric overlay.
%include "core/sha256.inc"

sha256_initial_state:
    dw 0xe667,0x6a09,0xae85,0xbb67
    dw 0xf372,0x3c6e,0xf53a,0xa54f
    dw 0x527f,0x510e,0x688c,0x9b05
    dw 0xd9ab,0x1f83,0xcd19,0x5be0
sha256_k:
    dw 0x2f98,0x428a,0x4491,0x7137
    dw 0xfbcf,0xb5c0,0xdba5,0xe9b5
    dw 0xc25b,0x3956,0x11f1,0x59f1
    dw 0x82a4,0x923f,0x5ed5,0xab1c
    dw 0xaa98,0xd807,0x5b01,0x1283
    dw 0x85be,0x2431,0x7dc3,0x550c
    dw 0x5d74,0x72be,0xb1fe,0x80de
    dw 0x06a7,0x9bdc,0xf174,0xc19b
    dw 0x69c1,0xe49b,0x4786,0xefbe
    dw 0x9dc6,0x0fc1,0xa1cc,0x240c
    dw 0x2c6f,0x2de9,0x84aa,0x4a74
    dw 0xa9dc,0x5cb0,0x88da,0x76f9
    dw 0x5152,0x983e,0xc66d,0xa831
    dw 0x27c8,0xb003,0x7fc7,0xbf59
    dw 0x0bf3,0xc6e0,0x9147,0xd5a7
    dw 0x6351,0x06ca,0x2967,0x1429
    dw 0x0a85,0x27b7,0x2138,0x2e1b
    dw 0x6dfc,0x4d2c,0x0d13,0x5338
    dw 0x7354,0x650a,0x0abb,0x766a
    dw 0xc92e,0x81c2,0x2c85,0x9272
    dw 0xe8a1,0xa2bf,0x664b,0xa81a
    dw 0x8b70,0xc24b,0x51a3,0xc76c
    dw 0xe819,0xd192,0x0624,0xd699
    dw 0x3585,0xf40e,0xa070,0x106a
    dw 0xc116,0x19a4,0x6c08,0x1e37
    dw 0x774c,0x2748,0xbcb5,0x34b0
    dw 0x0cb3,0x391c,0xaa4a,0x4ed8
    dw 0xca4f,0x5b9c,0x6ff3,0x682e
    dw 0x82ee,0x748f,0x636f,0x78a5
    dw 0x7814,0x84c8,0x0208,0x8cc7
    dw 0xfffa,0x90be,0x6ceb,0xa450
    dw 0xa3f7,0xbef9,0x78f2,0xc671

image_end:
