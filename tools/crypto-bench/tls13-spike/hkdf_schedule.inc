; TLS 1.3 SHA-256 key-schedule spike for the narrow Seed profile.
;
; This is isolated benchmark code, not runtime code.  It deliberately uses the
; production sha256.inc HMAC entry points and models:
;
;   no PSK
;   TLS_CHACHA20_POLY1305_SHA256
;   handshake traffic keys/IVs and Finished keys/verify_data
;   application traffic keys/IVs
;
; The caller supplies fixed 32-byte shared-secret and transcript-hash inputs
; through the tls13_input_* labels.  All output labels and scratch globals are
; supplied by hkdf_bench.asm.
;
; hmac_prepare_current_key_context costs two SHA-256 compression blocks.  The
; driver prepares each secret once, then expands every label that uses it:
; handshake_secret -> {c hs traffic, s hs traffic, derived}; each traffic
; secret -> {key, iv, finished}; master_secret -> {c ap traffic, s ap traffic};
; each application traffic secret -> {key, iv}.

; Prepare a 32-byte SHA-256 HMAC secret.
; in: SI = key
tls13_prepare_secret:
    mov [hmac_key_ptr], si
    mov word [hmac_key_len], sha256_digest_len
    jmp hmac_prepare_current_key_context

; One HKDF-Extract/HMAC with 32-byte salt and arbitrary input.
; in: SI = salt, BX = input, CX = input length, DI = 32-byte output
tls13_hmac_once:
    mov [hmac_key_ptr], si
    mov word [hmac_key_len], sha256_digest_len
    mov [hmac_data1_ptr], bx
    mov [hmac_data1_len], cx
    mov word [hmac_data2_len], 0
    mov [hmac_output_ptr], di
    call hmac_prepare_current_key_context
    jc .failed
    jmp hmac_sha256_prepared
.failed:
    ret

; HKDF-Expand-Label for outputs <= SHA-256's 32-byte digest.  The prepared
; secret is reused; one HKDF block is therefore sufficient.  Inputs are globals
; because the production HMAC/SHA code intentionally uses BX/DX/BP as scratch:
;   tls13_expand_label_ptr/len
;   tls13_expand_context_ptr/len
;   tls13_expand_output_ptr/len
tls13_expand_label_prepared:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    push ds
    pop es

    mov di, tls13_hkdf_info
    mov ax, [tls13_expand_output_len]
    mov byte [di], 0
    mov [di + 1], al
    mov ax, [tls13_expand_label_len]
    add al, tls13_label_prefix_len
    mov [di + 2], al
    add di, 3

    mov si, tls13_label_prefix
    mov cx, tls13_label_prefix_len
    rep movsb
    mov si, [tls13_expand_label_ptr]
    mov cx, [tls13_expand_label_len]
    rep movsb

    mov ax, [tls13_expand_context_len]
    stosb
    mov si, [tls13_expand_context_ptr]
    mov cx, [tls13_expand_context_len]
    rep movsb
    mov al, 1
    stosb

    mov ax, di
    sub ax, tls13_hkdf_info
    mov word [hmac_data1_ptr], tls13_hkdf_info
    mov [hmac_data1_len], ax
    mov word [hmac_data2_len], 0
    mov word [hmac_output_ptr], tls13_hkdf_block
    call hmac_sha256_prepared
    jc .done

    mov si, tls13_hkdf_block
    mov di, [tls13_expand_output_ptr]
    mov cx, [tls13_expand_output_len]
    rep movsb
    clc
.done:
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Expand CX descriptors using one prepared secret.  A 9-byte descriptor is:
;
;   dw label_ptr; db label_len
;   dw context_ptr; db context_len
;   dw output_ptr; db output_len
;
; Tables replace sixteen 40+-byte immediate-call sites.  The few extra loads
; are negligible beside HMAC on an 8088 and materially reduce executable area.
; in: SI = descriptor table, CX = descriptor count
tls13_expand_group:
.next:
    lodsw
    mov [tls13_expand_label_ptr], ax
    lodsb
    xor ah, ah
    mov [tls13_expand_label_len], ax
    lodsw
    mov [tls13_expand_context_ptr], ax
    lodsb
    xor ah, ah
    mov [tls13_expand_context_len], ax
    lodsw
    mov [tls13_expand_output_ptr], ax
    lodsb
    xor ah, ah
    mov [tls13_expand_output_len], ax
    call tls13_expand_label_prepared
    jc .done
    loop .next
    clc
.done:
    ret

%macro TLS13_DESCRIPTOR 6
    dw %1
    db %2
    dw %3
    db %4
    dw %5
    db %6
%endmacro

; Literal RFC 8446 no-PSK schedule, starting with Extract(zeros, zeros).
tls13_schedule_full:
    mov si, tls13_zeros
    mov bx, tls13_zeros
    mov cx, sha256_digest_len
    mov di, tls13_early_secret
    call tls13_hmac_once
    jc tls13_schedule_failed

    mov si, tls13_early_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_early
    mov cx, tls13_group_early_count
    call tls13_expand_group
    jc tls13_schedule_failed

    mov si, tls13_early_derived
    jmp tls13_schedule_after_no_psk

; Mathematically identical optimized path.  In a no-PSK build the first
; Derive-Secret is a protocol constant, so baking it saves 8 SHA-256 blocks:
; two HMAC key preparations and two HMAC evaluations.
tls13_schedule_hot:
    mov si, tls13_no_psk_derived

tls13_schedule_after_no_psk:
    ; handshake_secret = HKDF-Extract(Derive-Secret(early,"derived",""),
    ;                                 ECDHE)
    mov bx, tls13_input_shared_secret
    mov cx, sha256_digest_len
    mov di, tls13_handshake_secret
    call tls13_hmac_once
    jc tls13_schedule_failed

    ; One preparation feeds both handshake traffic secrets and the later
    ; master-secret "derived" value.
    mov si, tls13_handshake_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_handshake
    mov cx, tls13_group_handshake_count
    call tls13_expand_group
    jc tls13_schedule_failed

    ; Client handshake write material + Finished.
    mov si, tls13_client_hs_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_client_handshake
    mov cx, tls13_group_client_handshake_count
    call tls13_expand_group
    jc tls13_schedule_failed

    mov si, tls13_client_finished_key
    mov bx, tls13_input_client_finished_hash
    mov cx, sha256_digest_len
    mov di, tls13_client_finished_verify
    call tls13_hmac_once
    jc tls13_schedule_failed

    ; Server handshake write material + Finished verification.
    mov si, tls13_server_hs_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_server_handshake
    mov cx, tls13_group_server_handshake_count
    call tls13_expand_group
    jc tls13_schedule_failed

    mov si, tls13_server_finished_key
    mov bx, tls13_input_server_finished_hash
    mov cx, sha256_digest_len
    mov di, tls13_server_finished_verify
    call tls13_hmac_once
    jc tls13_schedule_failed

    ; master_secret = HKDF-Extract(Derive-Secret(handshake,"derived",""),
    ;                              zeros)
    mov si, tls13_handshake_derived
    mov bx, tls13_zeros
    mov cx, sha256_digest_len
    mov di, tls13_master_secret
    call tls13_hmac_once
    jc tls13_schedule_failed

    ; Both application traffic secrets share one prepared master secret.
    mov si, tls13_master_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_master
    mov cx, tls13_group_master_count
    call tls13_expand_group
    jc tls13_schedule_failed

    mov si, tls13_client_app_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_client_application
    mov cx, tls13_group_client_application_count
    call tls13_expand_group
    jc tls13_schedule_failed

    mov si, tls13_server_app_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_server_application
    mov cx, tls13_group_server_application_count
    call tls13_expand_group
    jc tls13_schedule_failed

    clc
    ret

tls13_schedule_failed:
    stc
    ret

; Critical-window-only schedule for the quarantined first-handshake spike.
; It deliberately stops after generating/verifying both handshake Finished
; values.  The handshake "derived" value, master secret, application traffic
; material, and resumption master secret can be generated only after the
; client Finished has been sent.  The two first handshake descriptors are
; c_hs_traffic and s_hs_traffic; the third ("derived") is intentionally
; omitted here.
;
; This routine duplicates the small orchestration sequence so its timing does
; not include a benchmark-only mode branch in the critical path.
tls13_schedule_critical:
    mov si, tls13_no_psk_derived
    mov bx, tls13_input_shared_secret
    mov cx, sha256_digest_len
    mov di, tls13_handshake_secret
    call tls13_hmac_once
    jc tls13_schedule_failed

    mov si, tls13_handshake_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_handshake
    mov cx, 2
    call tls13_expand_group
    jc tls13_schedule_failed

    mov si, tls13_client_hs_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_client_handshake
    mov cx, tls13_group_client_handshake_count
    call tls13_expand_group
    jc tls13_schedule_failed

    mov si, tls13_client_finished_key
    mov bx, tls13_input_client_finished_hash
    mov cx, sha256_digest_len
    mov di, tls13_client_finished_verify
    call tls13_hmac_once
    jc tls13_schedule_failed

    mov si, tls13_server_hs_secret
    call tls13_prepare_secret
    jc tls13_schedule_failed
    mov si, tls13_group_server_handshake
    mov cx, tls13_group_server_handshake_count
    call tls13_expand_group
    jc tls13_schedule_failed

    mov si, tls13_server_finished_key
    mov bx, tls13_input_server_finished_hash
    mov cx, sha256_digest_len
    mov di, tls13_server_finished_verify
    call tls13_hmac_once
    ret

; Product constants for the fixed profile.
tls13_label_prefix db 'tls13 '
tls13_label_prefix_len equ $ - tls13_label_prefix
tls13_label_derived db 'derived'
tls13_label_derived_len equ $ - tls13_label_derived
tls13_label_c_hs_traffic db 'c hs traffic'
tls13_label_c_hs_traffic_len equ $ - tls13_label_c_hs_traffic
tls13_label_s_hs_traffic db 's hs traffic'
tls13_label_s_hs_traffic_len equ $ - tls13_label_s_hs_traffic
tls13_label_c_ap_traffic db 'c ap traffic'
tls13_label_c_ap_traffic_len equ $ - tls13_label_c_ap_traffic
tls13_label_s_ap_traffic db 's ap traffic'
tls13_label_s_ap_traffic_len equ $ - tls13_label_s_ap_traffic
tls13_label_key db 'key'
tls13_label_key_len equ $ - tls13_label_key
tls13_label_iv db 'iv'
tls13_label_iv_len equ $ - tls13_label_iv
tls13_label_finished db 'finished'
tls13_label_finished_len equ $ - tls13_label_finished
tls13_empty_context:

; SHA256("") and Derive-Secret(Extract(zeros,zeros),"derived",SHA256("")).
tls13_empty_hash:
    db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14
    db 0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24
    db 0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c
    db 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
tls13_no_psk_derived:
    db 0x6f,0x26,0x15,0xa1,0x08,0xc7,0x02,0xc5
    db 0x67,0x8f,0x54,0xfc,0x9d,0xba,0xb6,0x97
    db 0x16,0xc0,0x76,0x18,0x9c,0x48,0x25,0x0c
    db 0xeb,0xea,0xc3,0x57,0x6c,0x36,0x11,0xba

; Expansion descriptors, grouped so each group shares one prepared HMAC key.
tls13_group_early:
    TLS13_DESCRIPTOR tls13_label_derived, tls13_label_derived_len, \
                     tls13_empty_hash, sha256_digest_len, \
                     tls13_early_derived, sha256_digest_len
tls13_group_early_count equ ($ - tls13_group_early) / 9

tls13_group_handshake:
    TLS13_DESCRIPTOR tls13_label_c_hs_traffic, tls13_label_c_hs_traffic_len, \
                     tls13_input_hello_hash, sha256_digest_len, \
                     tls13_client_hs_secret, sha256_digest_len
    TLS13_DESCRIPTOR tls13_label_s_hs_traffic, tls13_label_s_hs_traffic_len, \
                     tls13_input_hello_hash, sha256_digest_len, \
                     tls13_server_hs_secret, sha256_digest_len
    TLS13_DESCRIPTOR tls13_label_derived, tls13_label_derived_len, \
                     tls13_empty_hash, sha256_digest_len, \
                     tls13_handshake_derived, sha256_digest_len
tls13_group_handshake_count equ ($ - tls13_group_handshake) / 9

tls13_group_client_handshake:
    TLS13_DESCRIPTOR tls13_label_key, tls13_label_key_len, \
                     tls13_empty_context, 0, tls13_client_hs_key, tls13_key_len
    TLS13_DESCRIPTOR tls13_label_iv, tls13_label_iv_len, \
                     tls13_empty_context, 0, tls13_client_hs_iv, tls13_iv_len
    TLS13_DESCRIPTOR tls13_label_finished, tls13_label_finished_len, \
                     tls13_empty_context, 0, tls13_client_finished_key, \
                     sha256_digest_len
tls13_group_client_handshake_count equ ($ - tls13_group_client_handshake) / 9

tls13_group_server_handshake:
    TLS13_DESCRIPTOR tls13_label_key, tls13_label_key_len, \
                     tls13_empty_context, 0, tls13_server_hs_key, tls13_key_len
    TLS13_DESCRIPTOR tls13_label_iv, tls13_label_iv_len, \
                     tls13_empty_context, 0, tls13_server_hs_iv, tls13_iv_len
    TLS13_DESCRIPTOR tls13_label_finished, tls13_label_finished_len, \
                     tls13_empty_context, 0, tls13_server_finished_key, \
                     sha256_digest_len
tls13_group_server_handshake_count equ ($ - tls13_group_server_handshake) / 9

tls13_group_master:
    TLS13_DESCRIPTOR tls13_label_c_ap_traffic, tls13_label_c_ap_traffic_len, \
                     tls13_input_server_finished_hash, sha256_digest_len, \
                     tls13_client_app_secret, sha256_digest_len
    TLS13_DESCRIPTOR tls13_label_s_ap_traffic, tls13_label_s_ap_traffic_len, \
                     tls13_input_server_finished_hash, sha256_digest_len, \
                     tls13_server_app_secret, sha256_digest_len
tls13_group_master_count equ ($ - tls13_group_master) / 9

tls13_group_client_application:
    TLS13_DESCRIPTOR tls13_label_key, tls13_label_key_len, \
                     tls13_empty_context, 0, tls13_client_app_key, tls13_key_len
    TLS13_DESCRIPTOR tls13_label_iv, tls13_label_iv_len, \
                     tls13_empty_context, 0, tls13_client_app_iv, tls13_iv_len
tls13_group_client_application_count equ ($ - tls13_group_client_application) / 9

tls13_group_server_application:
    TLS13_DESCRIPTOR tls13_label_key, tls13_label_key_len, \
                     tls13_empty_context, 0, tls13_server_app_key, tls13_key_len
    TLS13_DESCRIPTOR tls13_label_iv, tls13_label_iv_len, \
                     tls13_empty_context, 0, tls13_server_app_iv, tls13_iv_len
tls13_group_server_application_count equ ($ - tls13_group_server_application) / 9
