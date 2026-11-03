; Offline TLS 1.3 authentication controller for the 286 product route.
;
; The acquisition flight has already authenticated every protected-record tag
; and server Finished before this image is entered.  This phase runs with no
; provider timer active and establishes the durable same-boot trust boundary:
;
;   * parse the exact ordinary TLS 1.3 Certificate handshake;
;   * apply the strict api.openai.com P-256 leaf profile;
;   * require a caller-published trusted UTC value and check validity;
;   * verify the SHA-384 leaf signature under the immutable YE2 P-384 key;
;   * generate G and the authenticated P-256 leaf width-7 tables on this
;     target, then verify the captured TLS CertificateVerify; and
;   * publish AUTH only after every preceding operation succeeds.
;
; No build host supplies a leaf key or runtime comb table.  The only baked
; trust object is the YE2 P-384 affine point.  Read-only media is sufficient:
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
    call auth_verify_issuer
    jc auth_abort
    call auth_build_generator_table
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
; consumed; their presence never substitutes for proof under the baked YE2
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

; Exact Gregorian validation for 2000..2099, within the supported platform-UTC range.
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

; Strict DER, positive canonical scalars and 0<r,s<n, shared with P-384.
x509_check_ecdsa_signature:
    mov [pv_sig],si
    add si,cx
    mov [pv_sig_end],si
    jmp pv_parse

; Reuse only the retired ML-KEM low overlay. No module executes here until
; this complete public scratch span is erased and its replacement decoded.
auth_verify_issuer:
    mov si,[x509_tbs_ptr]
    mov cx,[x509_tbs_len]
    call sha384_hash
    jc .wipe
    mov si,s_digest
    mov di,[x509_sig_ptr]
    mov cx,[x509_sig_len]
    mov bp,pc_issuer
    call p384_verify
.wipe:
    pushf
    xor ax,ax
    mov di,0x4230
    mov cx,(s_scratch_end-0x4230)/2
    rep stosw
    popf
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

; P-256 leaf/SPKI/CV with an exact P-384/SHA-384 issuer profile. The same
; strict scalar parser serves framing and the subsequent issuer equation.
%define X509_ISSUER_P384 1
parser_x509_state_start equ auth_parser_state
%include "cert_parser_p256.inc"

%include "tls13/p384_verify_286.inc"
%include "tls13/p384_ye2_constants.inc"
%include "tls13/sha384_286.inc"
%include "tls13/sha384_constants.inc"

align 2
auth_generator_point:
    dw 49814,55448,14661,62625,13216,11755,32129,30467
    dw 16626,25508,59109,63676,16967,57644,53746,27415
    dw 20981,14271,16488,52150,24270,27441,13143,11214
    dw 40470,31759,60234,36583,32667,65050,17122,20451

auth_month_days db 31,28,31,30,31,30,31,31,30,31,30,31

align 2
auth_crypto_seg dw 0
auth_leaf_len dw 0
auth_list_pos dw 0
auth_list_remaining dw 0
auth_chain_count db 0
auth_table_point dw 0
auth_table_output dw 0
auth_desc times tls13_286_desc_bytes db 0
auth_leaf_point times 64 db 0

auth_not_before times auth_normalized_time_bytes db 0
auth_not_after times auth_normalized_time_bytes db 0
auth_now times auth_normalized_time_bytes db 0

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
%if auth_generator_point - $$ + 0x1800 != 0x3220
%error "TLS 1.3 286 generator point moved from its bounded tablegen slot"
%endif
%if auth_leaf_point - $$ + 0x1800 != 0x32ad
%error "TLS 1.3 286 leaf point moved from its bounded tablegen slot"
%endif
