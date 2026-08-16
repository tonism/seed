; Offline TLS 1.3 authentication controller for the 286 product route.
;
; The acquisition flight has already authenticated every protected-record tag
; and server Finished before this image is entered.  This phase runs with no
; provider timer active and establishes the durable same-boot trust boundary:
;
;   * parse the exact ordinary TLS 1.3 Certificate handshake;
;   * apply the strict api.openai.com P-256 leaf profile;
;   * require a caller-published trusted UTC value and check validity;
;   * generate G and immutable Google Trust Services WE1 width-7 tables on
;     this target, then verify the leaf signature under WE1;
;   * replace the WE1 table with the authenticated leaf table and verify the
;     captured TLS CertificateVerify digest/signature; and
;   * publish AUTH only after every preceding operation succeeds.
;
; No build host supplies a leaf key or runtime comb table.  The only baked
; trust object is the WE1 P-256 affine point.  Read-only media is sufficient:
; all certificate evidence, tables, and decisions live in the 64 KiB high
; reservation and are discarded on restart.

bits 16
cpu 8086
org 0x1800

%include "tls13/tls13_286_abi.inc"

auth_component_magic         equ 'S2'
auth_leaf_buffer             equ 0x0800
auth_leaf_capacity           equ 1024
auth_parser_state            equ 0x0d00
auth_table_scratch_bytes     equ 16256
auth_chain_max               equ 4
auth_chain_cert_max          equ 2048
auth_normalized_time_bytes   equ 14
auth_ecdsa_digest_slot       equ 0x0c00
auth_ecdsa_signature_slot    equ 0x0c20
auth_ecdsa_slots_end         equ \
    auth_ecdsa_signature_slot + tls13_286_cv_signature_max
auth_header:
    db 'S286AU02'
    dw tls13_286_abi_version
    dw auth_image_end - auth_header
    dw 1
auth_entry_table:
    dw auth_entry

; BX=crypto reservation segment, SI=validated footer offset, DS=ES=SS=0.
auth_entry:
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    cmp si, tls13_286_tail_footer_off
    jne auth_abort
    mov [cs:auth_crypto_seg], bx
    mov ax, [tls13_286_bda_conventional_kb]
    mov cl, 6
    shl ax, cl
    sub ax, tls13_286_high_reserve_bytes / 16
    cmp ax, bx
    jne auth_abort

    mov es, bx
    mov word [es:tls13_286_auth_status_inv_off], 0
    cmp word [es:tls13_286_capture_status_inv_off], \
        (tls13_286_flight_status_valid << 8) | \
        tls13_286_flight_status_inverse
    jne auth_abort_es
    cmp word [es:tls13_286_rtc_status_inv_off], \
        (tls13_286_rtc_status_valid << 8) | tls13_286_rtc_status_inverse
    jne auth_abort_es
    cmp word [es:tls13_286_candidate_status_inv_off], \
        (tls13_286_candidate_status_valid << 8) | \
        tls13_286_candidate_status_inverse
    jne auth_abort_es
    cmp word [es:tls13_286_ticket_status_inv_off], \
        (tls13_286_ticket_status_tentative << 8) | \
        tls13_286_ticket_status_tentative_inv
    jne auth_abort_es
    ; Consume tentative authority before any private ticket byte can survive
    ; into a later stage.  Only the complete offline authentication path below
    ; may republish this ticket as PROMOTED.
    mov word [es:tls13_286_ticket_status_inv_off], 0
    xor ax, ax
    mov es, ax
    call auth_verify_candidate_fo
    jc auth_abort
    call auth_parse_certificate_message
    jc auth_abort
    mov si, auth_leaf_buffer
    mov cx, [cs:auth_leaf_len]
    push ds
    pop es
    call x509_parse_leaf
    jc auth_abort
    call auth_extract_leaf
    jc auth_abort
    call auth_validate_time
    jc auth_abort
    call auth_hash_tbs
    jc auth_abort

    ; Reuse the retired protected-record quarantine for temporary table
    ; generation.  It never overlaps the advertised far pool or module cache.
    call auth_build_generator_table
    jc auth_abort
    mov si, auth_we1_point
    mov ax, tls13_286_leaf_table_off
    call auth_build_table
    jc auth_abort
    mov si, auth_ecdsa_digest_slot
    mov cx, [x509_sig_len]
    mov di, [x509_sig_ptr]
    call auth_verify_near_signature
    jc auth_abort

    mov si, auth_leaf_point
    mov ax, tls13_286_leaf_table_off
    call auth_build_table
    jc auth_abort
    call auth_verify_captured_cv
    jc auth_abort

    mov es, [cs:auth_crypto_seg]
    mov byte [es:tls13_286_auth_status_inv_off], \
        tls13_286_flight_status_inverse
    mov byte [es:tls13_286_auth_status_off], \
        tls13_286_flight_status_valid
    ; Ticket publication is the last authority write.  A reset between these
    ; stores leaves a torn pair which the resumption entry rejects.
    mov byte [es:tls13_286_ticket_status_inv_off], \
        tls13_286_ticket_status_promoted_inv
    mov byte [es:tls13_286_ticket_status_off], \
        tls13_286_ticket_status_promoted
    xor ax, ax
    mov es, ax
    mov ax, tls13_286_tail_kind_hello_resume
    jmp word [cs:tls13_286_root_service_chain]

auth_abort_es:
    xor ax, ax
    mov es, ax
auth_abort:
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    jmp word [cs:tls13_286_abort_capsule_load + \
        tls13_286_abort_capsule_entry_ptr]

; Complete the FIPS 203 implicit-rejection path off-socket.  Acquisition used
; only decrypt-derived K' to meet the provider deadline; this operation
; re-encrypts, selects the standards-defined secret, and requires byte-exact
; equality with that provisional K' before any certificate decision can be
; published.  Status is consumed first and dk/c/K'/output are wiped on every
; return path.
auth_verify_candidate_fo:
    mov es, [cs:auth_crypto_seg]
    mov word [es:tls13_286_candidate_status_inv_off], 0
    xor ax, ax
    mov es, ax

    call auth_clear_desc
    mov word [cs:auth_desc + tls13_286_desc_op], \
        tls13_286_mod_op_mlkem_decap
    mov di, auth_desc + tls13_286_desc_input0
    mov ax, tls13_286_mlkem_dk_off
    mov dx, tls13_286_mlkem_dk_bytes
    call auth_set_high_span
    mov di, auth_desc + tls13_286_desc_input1
    mov ax, tls13_286_candidate_ciphertext_off
    mov dx, tls13_286_candidate_ciphertext_bytes
    call auth_set_high_span
    mov di, auth_desc + tls13_286_desc_output0
    mov ax, tls13_286_hybrid_secret_off
    mov dx, tls13_286_candidate_secret_bytes
    call auth_set_high_span

    mov ax, tls13_286_mod_kind_mlkem_decap
    call auth_decode_module
    jc .failed
    mov ax, tls13_286_mod_op_mlkem_decap
    call auth_call_module
    jc .failed

    mov es, [cs:auth_crypto_seg]
    mov si, tls13_286_hybrid_secret_off
    mov di, tls13_286_candidate_secret_off
    mov cx, tls13_286_candidate_secret_bytes
    xor dx, dx
.compare:
    mov al, [es:si]
    xor al, [es:di]
    or dl, al
    inc si
    inc di
    loop .compare
    or dl, dl
    jnz .failed
    call auth_wipe_candidate_fo
    clc
    ret
.failed:
    call auth_wipe_candidate_fo
    stc
    ret

auth_wipe_candidate_fo:
    push ax
    push cx
    push di
    push es
    mov es, [cs:auth_crypto_seg]
    xor ax, ax
    mov di, tls13_286_mlkem_dk_off
    mov cx, tls13_286_mlkem_dk_bytes / 2
    rep stosw
    mov di, tls13_286_hybrid_secret_off
    mov cx, tls13_286_hybrid_secret_bytes / 2
    rep stosw
    mov di, tls13_286_candidate_ciphertext_off
    mov cx, (tls13_286_candidate_status_off - \
        tls13_286_candidate_ciphertext_off + 1) / 2
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret

; Validate the complete ordinary Certificate handshake and copy only the first
; certificate to bounded low scratch.  Remaining entries are structurally
; consumed; their presence never substitutes for proof under the baked WE1
; key.  This profile did not offer per-Certificate extensions, so each entry
; must carry an empty extension vector.
auth_parse_certificate_message:
    mov es, [cs:auth_crypto_seg]
    mov cx, [es:tls13_286_certificate_len_off]
    cmp cx, 13
    jb .bad
    cmp cx, tls13_286_certificate_max
    ja .bad
    cmp byte [es:tls13_286_certificate_off], 11
    jne .bad
    cmp byte [es:tls13_286_certificate_off + 1], 0
    jne .bad
    mov ax, [es:tls13_286_certificate_off + 2]
    xchg al, ah
    add ax, 4
    jc .bad
    cmp ax, cx
    jne .bad
    cmp byte [es:tls13_286_certificate_off + 4], 0
    jne .bad
    cmp byte [es:tls13_286_certificate_off + 5], 0
    jne .bad
    mov ax, [es:tls13_286_certificate_off + 6]
    xchg al, ah
    mov dx, cx
    sub dx, 8
    cmp ax, dx
    jne .bad
    mov [cs:auth_list_remaining], dx
    mov word [cs:auth_list_pos], 8
    mov byte [cs:auth_chain_count], 0

.entry:
    cmp word [cs:auth_list_remaining], 5
    jb .bad
    mov si, [cs:auth_list_pos]
    cmp byte [es:tls13_286_certificate_off + si], 0
    jne .bad
    mov ax, [es:tls13_286_certificate_off + si + 1]
    xchg al, ah
    or ax, ax
    jz .bad
    cmp ax, auth_chain_cert_max
    ja .bad
    mov bx, ax
    add ax, 5
    jc .bad
    cmp ax, [cs:auth_list_remaining]
    ja .bad

    cmp byte [cs:auth_chain_count], 0
    jne .skip_leaf
    cmp bx, auth_leaf_capacity
    ja .bad
    mov [cs:auth_leaf_len], bx
    add si, tls13_286_certificate_off + 3
    mov di, auth_leaf_buffer
    mov cx, bx
.copy_leaf:
    mov al, [es:si]
    mov [di], al
    inc si
    inc di
    loop .copy_leaf
.skip_leaf:
    mov ax, bx
    add ax, 3
    add [cs:auth_list_pos], ax
    sub [cs:auth_list_remaining], ax
    cmp word [cs:auth_list_remaining], 2
    jb .bad
    mov si, [cs:auth_list_pos]
    mov ax, [es:tls13_286_certificate_off + si]
    xchg al, ah
    or ax, ax
    jnz .bad
    add word [cs:auth_list_pos], 2
    sub word [cs:auth_list_remaining], 2
    inc byte [cs:auth_chain_count]
    cmp byte [cs:auth_chain_count], auth_chain_max
    ja .bad
    cmp word [cs:auth_list_remaining], 0
    jne .entry
    cmp byte [cs:auth_chain_count], 0
    je .bad
    xor ax, ax
    mov es, ax
    clc
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

; Copy the parser outputs to controller-owned stable inputs.  DER points are
; big endian; the target table generator consumes 16-word little endian.
auth_extract_leaf:
    mov al, [x509_nb_tag]
    mov si, [x509_nb_ptr]
    mov di, auth_not_before
    call auth_normalize_time
    jc .bad
    mov al, [x509_na_tag]
    mov si, [x509_na_ptr]
    mov di, auth_not_after
    call auth_normalize_time
    jc .bad
    mov si, [x509_point_x_ptr]
    mov di, auth_leaf_point + 31
    mov cx, 32
    call auth_reverse_32
    mov si, [x509_point_y_ptr]
    mov di, auth_leaf_point + 63
    mov cx, 32
    call auth_reverse_32
    clc
    ret
.bad:
    stc
    ret

auth_reverse_32:
.byte:
    lodsb
    mov [di], al
    dec di
    loop .byte
    ret

; Convert strict DER UTCTime/GeneralizedTime to fixed YYYYMMDDHHMMSS.
auth_normalize_time:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    push ds
    pop es
    cmp al, 0x17
    jne .generalized
    mov bx, si
    call x509_decimal_pair
    cmp al, 50
    jb .year_20
    mov ax, 0x3931                  ; "19"
    jmp short .year
.year_20:
    mov ax, 0x3032                  ; "20"
.year:
    stosw
    mov cx, 12
    rep movsb
    jmp short .ok
.generalized:
    cmp al, 0x18
    jne .bad
    mov cx, 14
    rep movsb
.ok:
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    clc
    ret
.bad:
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    stc
    ret

; The parent publishes seven packed-BCD bytes from the coherent platform UTC
; clock. Revalidate the publication and compare it lexicographically with the
; exact normalized certificate interval.
auth_validate_time:
    mov es, [cs:auth_crypto_seg]
    mov si, tls13_286_rtc_publication_off
    mov di, auth_now
    mov cx, 7
.bcd:
    mov al, [es:si]
    mov ah, al
    and al, 0x0f
    cmp al, 9
    ja .bad
    and ah, 0xf0
    mov dl, 4
    mov cl, dl
    shr ah, cl
    cmp ah, 9
    ja .bad
    add ah, '0'
    mov [di], ah
    add al, '0'
    mov [di + 1], al
    inc si
    add di, 2
    mov cx, 7
    sub cx, si
    add cx, tls13_286_rtc_publication_off
    jnz .bcd
    xor ax, ax
    mov es, ax
    mov si, auth_now
    call auth_time_validate
    jc .bad_low
    mov si, auth_not_before
    call auth_time_validate
    jc .bad_low
    mov si, auth_not_after
    call auth_time_validate
    jc .bad_low
    push ds
    pop es
    mov si, auth_not_before
    mov di, auth_now
    call auth_time_lte
    jc .bad_low
    mov si, auth_now
    mov di, auth_not_after
    call auth_time_lte
    jc .bad_low
    clc
    ret
.bad:
    xor ax, ax
    mov es, ax
.bad_low:
    stc
    ret

; Exact Gregorian validation for 2000..2099, covering WE1's lifetime.
auth_time_validate:
    push ax
    push bx
    push cx
    push dx
    push si
    cmp word [si], 0x3032
    jne .bad
    mov bx, si
    mov cx, auth_normalized_time_bytes
.digit:
    mov al, [bx]
    cmp al, '0'
    jb .bad
    cmp al, '9'
    ja .bad
    inc bx
    loop .digit
    lea bx, [si + 4]
    call auth_decimal_pair
    cmp al, 1
    jb .bad
    cmp al, 12
    ja .bad
    mov dl, al
    add bx, 2
    call auth_decimal_pair
    cmp al, 1
    jb .bad
    mov dh, al
    xor ah, ah
    mov al, dl
    dec ax
    mov bx, auth_month_days
    add bx, ax
    mov al, [bx]
    cmp dl, 2
    jne .have_day
    lea bx, [si + 2]
    call auth_decimal_pair
    and al, 3
    jnz .have_day
    mov al, 29
.have_day:
    cmp dh, al
    ja .bad
    lea bx, [si + 8]
    call auth_decimal_pair
    cmp al, 23
    ja .bad
    add bx, 2
    call auth_decimal_pair
    cmp al, 59
    ja .bad
    add bx, 2
    call auth_decimal_pair
    cmp al, 59
    ja .bad
    clc
    jmp short .done
.bad:
    stc
.done:
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

auth_time_lte:
    push ax
    push cx
    push si
    push di
    mov cx, auth_normalized_time_bytes
    repe cmpsb
    je .yes
    jb .yes
    stc
    jmp short .done
.yes:
    clc
.done:
    pop di
    pop si
    pop cx
    pop ax
    ret

auth_decimal_pair:
    push dx
    mov al, [bx]
    sub al, '0'
    xor ah, ah
    mov dl, 10
    mul dl
    add al, [bx + 1]
    sub al, '0'
    pop dx
    ret

auth_hash_tbs:
    call sha256_init
    mov si, [x509_tbs_ptr]
    mov cx, [x509_tbs_len]
    call sha256_update
    mov di, auth_ecdsa_digest_slot
    call sha256_finish
    clc
    ret

auth_build_generator_table:
    mov si, auth_generator_point
    mov ax, tls13_286_g_table_off

; SI=near little-endian point, AX=high reservation output offset.
auth_build_table:
    mov [cs:auth_table_point], si
    mov [cs:auth_table_output], ax
    call auth_clear_desc
    mov word [cs:auth_desc + tls13_286_desc_op], \
        tls13_286_mod_op_p256_tablegen
    mov di, auth_desc + tls13_286_desc_input0
    mov ax, [cs:auth_table_point]
    mov dx, 64
    call auth_set_near_span
    mov di, auth_desc + tls13_286_desc_input1
    xor ax, ax
    mov dx, auth_table_scratch_bytes
    call auth_set_scratch_span
    mov di, auth_desc + tls13_286_desc_output0
    mov ax, [cs:auth_table_output]
    mov dx, tls13_286_w7_table_bytes
    call auth_set_high_span
    mov ax, tls13_286_mod_kind_p256_tablegen
    call auth_decode_module
    jc .bad
    mov ax, tls13_286_mod_op_p256_tablegen
    call auth_call_module
    ret
.bad:
    stc
    ret

; Verify a near digest/signature using G and the current high leaf-table slot.
; SI=digest, DI=signature, CX=signature length.
auth_verify_near_signature:
    jmp near auth_verify_near_signature_hardened
    ; Preserve the established point/tablegen addresses.  The hardened body
    ; lives after all three fixed P-256 point objects.
    times 55 - ($ - auth_verify_near_signature) db 0

auth_verify_captured_cv:
    call auth_clear_desc
    mov word [cs:auth_desc + tls13_286_desc_op], \
        tls13_286_mod_op_ecdsa_verify
    mov di, auth_desc + tls13_286_desc_input0
    mov ax, tls13_286_cv_digest_off
    mov dx, tls13_286_cv_digest_bytes
    call auth_set_high_span
    mov es, [cs:auth_crypto_seg]
    mov dx, [es:tls13_286_cv_signature_len_off]
    xor ax, ax
    mov es, ax
    cmp dx, 8
    jb .bad
    cmp dx, tls13_286_cv_signature_max
    ja .bad
    mov di, auth_desc + tls13_286_desc_input1
    mov ax, tls13_286_cv_signature_off
    call auth_set_high_span
    jmp short auth_verify_common
.bad:
    stc
    ret

auth_verify_common:
    mov di, auth_desc + tls13_286_desc_input2
    mov ax, tls13_286_g_table_off
    mov dx, tls13_286_w7_table_bytes
    call auth_set_high_span
    mov di, auth_desc + tls13_286_desc_input3
    mov ax, tls13_286_leaf_table_off
    mov dx, tls13_286_w7_table_bytes
    call auth_set_high_span
    mov di, auth_desc + tls13_286_desc_output0
    mov ax, tls13_286_ecdsa_result_off
    mov dx, 1
    call auth_set_high_span
    mov es, [cs:auth_crypto_seg]
    mov byte [es:tls13_286_ecdsa_result_off], 0
    xor ax, ax
    mov es, ax
    mov ax, tls13_286_mod_kind_ecdsa_verify
    call auth_decode_module
    jc .bad
    mov ax, tls13_286_mod_op_ecdsa_verify
    call auth_call_module
    jc .bad
    mov es, [cs:auth_crypto_seg]
    cmp byte [es:tls13_286_ecdsa_result_off], 1
    jne .bad_es
    mov byte [es:tls13_286_ecdsa_result_off], 0
    xor ax, ax
    mov es, ax
    clc
    ret
.bad_es:
    xor ax, ax
    mov es, ax
.bad:
    stc
    ret

auth_decode_module:
    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    ret

auth_call_module:
    mov bx, tls13_286_root_state_loader
    mov si, auth_desc
    xor di, di
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
    xor dx, dx
    mov ds, dx
    mov es, dx
    ret

auth_clear_desc:
    push ax
    push cx
    push di
    push es
    xor ax, ax
    mov es, ax
    mov di, auth_desc
    mov cx, tls13_286_desc_bytes / 2
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret

; AX=near offset, DX=len, DI=span.
auth_set_near_span:
    push ax
    push bx
    push cx
    mov bx, ax
    and ax, 15
    mov [di + tls13_286_span_off], ax
    mov ax, bx
    mov cl, 4
    shr ax, cl
    mov [di + tls13_286_span_seg], ax
    mov [di + tls13_286_span_len], dx
    mov word [di + tls13_286_span_len + 2], 0
    pop cx
    pop bx
    pop ax
    ret

; Table generation happens only after the acquisition record has been
; authenticated and retired.  Reuse the complete-record quarantine inside the
; reserved top segment rather than borrowing from the advertised far pool.
auth_set_scratch_span:
    mov word [di + tls13_286_span_off], 0
    mov ax, [cs:auth_crypto_seg]
    add ax, tls13_286_record_plain_off / 16
    mov [di + tls13_286_span_seg], ax
    mov [di + tls13_286_span_len], dx
    mov word [di + tls13_286_span_len + 2], 0
    ret

; AX=reservation offset, DX=len, DI=span.
auth_set_high_span:
    push ax
    push bx
    push cx
    mov bx, ax
    and ax, 15
    mov [di + tls13_286_span_off], ax
    mov ax, bx
    mov cl, 4
    shr ax, cl
    add ax, [cs:auth_crypto_seg]
    mov [di + tls13_286_span_seg], ax
    mov [di + tls13_286_span_len], dx
    mov word [di + tls13_286_span_len + 2], 0
    pop cx
    pop bx
    pop ax
    ret

; Strict fixed-profile P-256 X.509 parser shared with the independently gated
; 16 KiB research route.  Only its state-placement equate is product-local.
parser_x509_state_start equ auth_parser_state
%include "cert_parser_p256.inc"

; Shipping SHA-256 implementation used for the exact TBSCertificate span.
sha256_block_size equ 64
sha256_k_len      equ 256
sha256_digest_len equ 32
%include "core/sha256.inc"

sha256_initial_state:
    dw 0xe667,0x6a09,0xae85,0xbb67
    dw 0xf372,0x3c6e,0xf53a,0xa54f
    dw 0x527f,0x510e,0x688c,0x9b05
    dw 0xd9ab,0x1f83,0xcd19,0x5be0
sha256_k:
    dw 0x2f98,0x428a,0x4491,0x7137,0xfbcf,0xb5c0,0xdba5,0xe9b5
    dw 0xc25b,0x3956,0x11f1,0x59f1,0x82a4,0x923f,0x5ed5,0xab1c
    dw 0xaa98,0xd807,0x5b01,0x1283,0x85be,0x2431,0x7dc3,0x550c
    dw 0x5d74,0x72be,0xb1fe,0x80de,0x06a7,0x9bdc,0xf174,0xc19b
    dw 0x69c1,0xe49b,0x4786,0xefbe,0x9dc6,0x0fc1,0xa1cc,0x240c
    dw 0x2c6f,0x2de9,0x84aa,0x4a74,0xa9dc,0x5cb0,0x88da,0x76f9
    dw 0x5152,0x983e,0xc66d,0xa831,0x27c8,0xb003,0x7fc7,0xbf59
    dw 0x0bf3,0xc6e0,0x9147,0xd5a7,0x6351,0x06ca,0x2967,0x1429
    dw 0x0a85,0x27b7,0x2138,0x2e1b,0x6dfc,0x4d2c,0x0d13,0x5338
    dw 0x7354,0x650a,0x0abb,0x766a,0xc92e,0x81c2,0x2c85,0x9272
    dw 0xe8a1,0xa2bf,0x664b,0xa81a,0x8b70,0xc24b,0x51a3,0xc76c
    dw 0xe819,0xd192,0x0624,0xd699,0x3585,0xf40e,0xa070,0x106a
    dw 0xc116,0x19a4,0x6c08,0x1e37,0x774c,0x2748,0xbcb5,0x34b0
    dw 0x0cb3,0x391c,0xaa4a,0x4ed8,0xca4f,0x5b9c,0x6ff3,0x682e
    dw 0x82ee,0x748f,0x636f,0x78a5,0x7814,0x84c8,0x0208,0x8cc7
    dw 0xfffa,0x90be,0x6ceb,0xa450,0xa3f7,0xbef9,0x78f2,0xc671

times 16 db 0                   ; keep all tablegen point slots fixed
align 2
auth_generator_point:
    dw 49814,55448,14661,62625,13216,11755,32129,30467
    dw 16626,25508,59109,63676,16967,57644,53746,27415
    dw 20981,14271,16488,52150,24270,27441,13143,11214
    dw 40470,31759,60234,36583,32667,65050,17122,20451

; Immutable Google Trust Services WE1 P-256 anchor from the second certificate
; in tools/x509/certs/ecdsa_live_chain.pem, little endian x then y.
auth_we1_point:
    dw 60806,54652,14311,50713,6021,49500,3904,22599
    dw 23995,49735,34112,8451,18252,26455,15102,28621
    dw 64086,3842,9659,58918,39157,11302,22927,65296
    dw 59550,50374,63640,2563,5029,55066,33241,19355

auth_month_days db 31,28,31,30,31,30,31,31,30,31,30,31

align 2
auth_crypto_seg dw 0
auth_leaf_len dw 0
auth_list_pos dw 0
auth_list_remaining dw 0
auth_chain_count db 0
auth_table_point dw 0
auth_table_output dw 0
times 10 db 0                   ; keep auth_desc/parsed-leaf product slots fixed
auth_desc times tls13_286_desc_bytes db 0
auth_leaf_point times 64 db 0

auth_verify_near_signature_hardened:
    cmp cx, 8
    jb .bad
    cmp cx, tls13_286_cv_signature_max
    ja .bad
    push cx

    ; auth_hash_tbs already published the digest in its exact low slot.  Copy
    ; only the parser-selected DER signature into the matching fixed slot.
    mov si, di
    mov di, auth_ecdsa_signature_slot
    rep movsb

    mov word [auth_desc + tls13_286_desc_op], \
        tls13_286_mod_op_ecdsa_verify
    mov di, auth_desc + tls13_286_desc_input0
    mov ax, auth_ecdsa_digest_slot
    mov dx, 32
    call auth_set_near_span
    mov di, auth_desc + tls13_286_desc_input1
    mov ax, auth_ecdsa_signature_slot
    pop dx
    call auth_set_near_span
    call auth_verify_common
    ret
.bad:
    stc
    ret

auth_not_before times auth_normalized_time_bytes db 0
auth_not_after times auth_normalized_time_bytes db 0
auth_now times auth_normalized_time_bytes db 0

; SHA-256/HMAC data contract.  HMAC symbols are present because the shared
; source assembles both entry families even though this controller calls only
; SHA-256.
sha256_state times 32 db 0
sha256_a times 4 db 0
sha256_b times 4 db 0
sha256_c times 4 db 0
sha256_d times 4 db 0
sha256_e times 4 db 0
sha256_f times 4 db 0
sha256_g times 4 db 0
sha256_h times 4 db 0
sha256_t1 times 4 db 0
sha256_t2 times 4 db 0
sha256_new_e times 4 db 0
sha256_tmp times 4 db 0
sha256_w_ptr dw 0
sha256_k_ptr dw 0
sha256_len_low dw 0
sha256_len_high dw 0
sha256_saved_len_low dw 0
sha256_saved_len_high dw 0
sha256_bit_len0 dw 0
sha256_bit_len1 dw 0
sha256_bit_len2 dw 0
sha256_bit_len3 dw 0
sha256_digest_ptr dw 0
hmac_key_ptr dw 0
hmac_key_len dw 0
hmac_data1_ptr dw 0
hmac_data1_len dw 0
hmac_data2_ptr dw 0
hmac_data2_len dw 0
hmac_output_ptr dw 0
sha256_block_len db 0
sha256_saved_block_len db 0
sha256_schedule_count db 0
sha256_round_count db 0
sha256_block times sha256_block_size db 0
sha256_w times sha256_k_len db 0
sha256_saved_state times 32 db 0
sha256_saved_block times sha256_block_size db 0
hmac_ipad times 64 db 0
hmac_opad times 64 db 0
hmac_inner_digest times 32 db 0
hmac_prepared_inner_state times 32 db 0
hmac_prepared_outer_state times 32 db 0

auth_image_end:

%if auth_table_scratch_bytes & 15
%error "TLS 1.3 286 P-256 scratch must be paragraph aligned"
%endif
%if auth_table_scratch_bytes > tls13_286_record_plain_bytes
%error "TLS 1.3 286 P-256 scratch exceeds full-record quarantine"
%endif
%if parser_x509_state_end > 0x0d40
%error "TLS 1.3 286 X.509 state exceeds low parser-state budget"
%endif
%if (auth_image_end - $$) > tls13_286_controller_max_bytes
%error "TLS 1.3 286 auth controller exceeds safe controller window"
%endif
%if auth_leaf_buffer + auth_leaf_capacity > auth_parser_state
%error "TLS 1.3 286 auth leaf buffer overlaps parser state"
%endif
%if auth_leaf_buffer + auth_leaf_capacity > auth_ecdsa_digest_slot
%error "TLS 1.3 286 auth leaf buffer overlaps normalized ECDSA evidence"
%endif
%if auth_ecdsa_slots_end > auth_parser_state
%error "TLS 1.3 286 normalized ECDSA evidence overlaps parser state"
%endif
%if auth_generator_point - $$ + 0x1800 != 0x2c5e
%error "TLS 1.3 286 generator point moved from the tablegen product slot"
%endif
%if auth_we1_point - $$ + 0x1800 != 0x2c9e
%error "TLS 1.3 286 WE1 point moved from the tablegen product slot"
%endif
%if auth_leaf_point - $$ + 0x1800 != 0x2d35
%error "TLS 1.3 286 parsed leaf point moved from the tablegen product slot"
%endif
