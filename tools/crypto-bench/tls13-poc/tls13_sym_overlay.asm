; Seed TLS 1.3 symmetric PoC overlay.
;
; This is deliberately not wired into the runtime yet.  It is a product-shaped,
; flat 8086 overlay linked for the existing K window at 0000:1800.  Code and
; immutable constants lead the window; mutable primitive work consumes only
; their unused K tail.  Retained objects use fixed handshake-only high scratch.
;
; Entry ABI (near call, DS=ES=SS=0, DF clear):
;   0  sym_init
;   1  sym_transcript_init
;   2  sym_transcript_update       SI=bytes, CX=len
;   3  sym_critical_schedule       fixed 64-byte hybrid + hello hash
;   4  sym_server_hs_open_begin    AX=plaintext transcript-prefix bytes
;   5  sym_server_app_open_begin   no transcript hashing
;   6  sym_open_chunk              SI=mutable ciphertext, CX=1..384
;   7  sym_open_finish             SI=received 16-byte tag
;   8  sym_verify_server_finished  fixed received verify_data
;   9  sym_build_client_finished   record at sym_io_base, AX=58
;  10  sym_derive_application      app keys + resumption master secret
;  11  sym_build_head              record at sym_io_base, AX=record bytes
;  12  sym_parse_nst               SI=plaintext NST, CX=len
;  13  sym_resumption_binder       ticket PSK + truncated-CH digest
;  14  sym_resumption_handshake    fresh 64-byte hybrid + resumed hello hash
;  15  sym_transcript_import       committed HELLO low-memory handoff
;  16  sym_derive_client_application
;                                  client write traffic/key/IV only
;  17  sym_derive_server_application
;                                  server read traffic/key/IV + res master
;  18  sym_authenticate_resumed_flight
;                                  exact accepted/rejected protected record
;
; Every operation returns CF=0 on success and CF=1 on rejection.  The streaming
; open API authenticates ciphertext before overwriting each chunk, but plaintext
; remains QUARANTINED until sym_open_finish succeeds.  A failed finish invalidates
; the transcript and the caller must close and discard the provisional session.

bits 16
cpu 8086
org 0x1800

sha256_digest_len equ 32
sha256_block_size equ 64
sha256_k_len equ 256
tls_chacha_key_len equ 32
tls_chacha_iv_len equ 12
chacha_word_count equ 16
chacha_block_len equ 64
poly1305_r_len equ 16
poly1305_s_len equ 16
poly1305_acc_len equ 17
poly1305_product_len equ 36
poly1305_value_len equ 24
tls_aead_tag_len equ 16

sym_overlay_base equ 0x1800
%ifdef TLS13_POC_K14
sym_overlay_limit equ 0x3400
sym_k_extension_start equ 0x3400
sym_k_extension_end equ 0x3600
sym_k_extension_work_start equ 0x3510
sym_k_extension_work_end equ 0x355d
%else
sym_overlay_limit equ 0x3600
%endif
sym_rx_frame_start equ 0x0700
sym_rx_frame_end equ 0x08b7
sym_mlkem_ciphertext_start equ 0x08c0
sym_mlkem_ciphertext_end equ 0x0d00
sym_optional_low_work_start equ 0x0d00
sym_optional_low_work_end equ 0x1000
sym_hello_server_x equ 0x0d00
sym_hello_digest equ 0x0d20
sym_hello_context equ 0x0d40
sym_hello_context_version equ sym_hello_context + 4
sym_hello_context_block_len equ sym_hello_context + 5
sym_hello_context_len_low equ sym_hello_context + 6
sym_hello_context_len_high equ sym_hello_context + 8
sym_hello_context_state equ sym_hello_context + 10
sym_hello_context_block equ sym_hello_context_state + 32
sym_hello_context_status equ sym_hello_context_block + 64
sym_hello_context_end equ sym_hello_context_status + 1
%ifdef TLS13_POC_286
; The 286 product root/decoder remains live at 0x3400..0x3bff across both
; protected flights.  Move only the mutable symmetric state into the unused
; gap above every P-256 module and below the resident 0x7a00 stack guard.
; Code and immutable data remain fixed at 0x1800, so this variant has the same
; entry-table ABI without allowing record work to overwrite its supervisor.
sym_high_state_base equ 0x7380
sym_high_security_state_limit equ 0x7a00
sym_arena_floor equ 0x79b0
sym_stack_guard_base equ 0x7a00
%else
sym_high_state_base equ 0x3600
sym_high_security_state_limit equ 0x3c9c
sym_arena_floor equ 0x3e40
sym_stack_guard_base equ 0x3f00
%endif
sym_mss_max equ 384
; The shared primitive accepts the complete TLS 1.3 ChaCha20-Poly1305
; TLSInnerPlaintext bound.  Restricted callers retain their smaller independent
; record caps before entering this reusable symmetric engine.
sym_record_cipher_max equ (1 << 14) + 256 - tls_aead_tag_len
sym_ticket_identity_max equ 192
sym_ticket_nonce_max equ 32

%ifndef TLS13_SHARED_SECRET_LEN
%define TLS13_SHARED_SECRET_LEN 64
%endif
%if TLS13_SHARED_SECRET_LEN != 32 && TLS13_SHARED_SECRET_LEN != 64
%error "TLS13_SHARED_SECRET_LEN must be 32 or 64"
%endif
sym_shared_secret_len equ TLS13_SHARED_SECRET_LEN

sym_overlay_header:
    db 'T13SYM02'
    dw 2
    dw sym_overlay_end - sym_overlay_header
    dw sym_low_scratch_base
%ifdef TLS13_POC_K14
    dw sym_k_work_end
%else
    dw sym_low_scratch_end
%endif
    dw sym_high_state_base
    dw sym_high_state_end
    dw sym_io_base
    dw sym_io_end
    dw sym_arena_floor
    dw sym_stack_guard_base
    dw sym_shared_secret_len
    dw sym_entry_count
sym_entry_table:
    dw sym_init
    dw sym_transcript_init
    dw sym_transcript_update
    dw sym_critical_schedule
    dw sym_server_hs_open_begin
    dw sym_server_app_open_begin
    dw sym_open_chunk
    dw sym_open_finish
    dw sym_verify_server_finished
    dw sym_build_client_finished
    dw sym_derive_application
    dw sym_build_head
    dw sym_parse_nst
    dw sym_resumption_binder
    dw sym_resumption_handshake
    dw sym_transcript_import
    dw sym_derive_client_application
    dw sym_derive_server_application
    dw sym_authenticate_resumed_flight
sym_entry_count equ ($ - sym_entry_table) / 2

; ---------------------------------------------------------------------------
; Public orchestration entries
; ---------------------------------------------------------------------------

sym_init:
    cld
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, sym_pre_finished_hash
    mov cx, sym_high_state_end - sym_pre_finished_hash
    rep stosb
    mov di, sym_low_runtime_clear_start
    mov cx, sym_low_runtime_clear_end - sym_low_runtime_clear_start
    rep stosb
    call sha256_init
    pop es
    pop di
    pop cx
    pop ax
    clc
    ret

sym_transcript_init:
    jmp sha256_init

sym_transcript_update:
    cmp cx, sym_mss_max
    ja .failed
    jmp sha256_update
.failed:
    stc
    ret

; Import the byte-exact SHA-256 transcript context exported by HELLO after
; ClientHello || ServerHello.  HELLO writes status last; the candidate must
; preserve this low 0d00..0daa handoff while it reuses high attempt-cache state.
; K' is supplied separately in the first 32 bytes of sym_input_shared_secret.
sym_transcript_import:
    cmp word [sym_hello_context], 0x3154       ; ASCII "T1"
    jne .failed
    cmp word [sym_hello_context + 2], 0x4333   ; ASCII "3C"
    jne .failed
    cmp byte [sym_hello_context_version], 1
    jne .failed
    cmp byte [sym_hello_context_status], 1
    jne .failed
    mov al, [sym_hello_context_block_len]
    cmp al, sha256_block_size - 1
    ja .failed
    mov ah, [sym_hello_context_len_low]
    and ah, sha256_block_size - 1
    cmp al, ah
    jne .failed

    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
%if sym_shared_secret_len == 64
    mov si, sym_hello_server_x
    mov di, sym_input_shared_secret + 32
    mov cx, 16
    rep movsw
%endif
    mov si, sym_hello_digest
    mov di, sym_input_hello_hash
    mov cx, 16
    rep movsw
    mov si, sym_hello_context_state
    mov di, sha256_state
    mov cx, 16
    rep movsw
    mov si, sym_hello_context_block
    mov di, sha256_block
    mov cx, sha256_block_size / 2
    rep movsw
    mov ax, [sym_hello_context_len_low]
    mov [sha256_len_low], ax
    mov ax, [sym_hello_context_len_high]
    mov [sha256_len_high], ax
    mov al, [sym_hello_context_block_len]
    mov [sha256_block_len], al
    ; Consume the publication only after every validation and copy succeeds.
    ; A rejected handoff remains byte-for-byte available for diagnosis/retry.
    mov byte [sym_hello_context_status], 0
    pop es
    pop di
    pop si
    pop cx
    pop ax
    clc
    ret
.failed:
    stc
    ret

; RFC 8446 no-PSK critical schedule.  The provisional secret and transcript
; digest are supplied at fixed ABI addresses and are not baked fixtures.
sym_critical_schedule:
    mov si, tls13_no_psk_derived
    mov bx, sym_input_shared_secret
    mov cx, sym_shared_secret_len
    mov di, sym_handshake_secret
    call tls13_hmac_once
    jc sym_derive_handshake_traffic.done

sym_derive_handshake_traffic:
    mov si, sym_handshake_secret
    call tls13_prepare_secret
    jc .done
    ; Preserve the already-prepared handshake-secret HMAC states in the two
    ; not-yet-live application-secret slots.  Entry 16 restores this cache,
    ; expands "derived" after Finished, then overwrites both slots with their
    ; real application traffic secrets.
    mov si, hmac_prepared_inner_state
    mov di, sym_client_app_secret
    mov cx, 32
    rep movsw
    mov si, tls13_group_handshake
    mov cx, tls13_group_handshake_count
    call tls13_expand_group
    jc .done

    mov si, sym_client_hs_secret
    call tls13_prepare_secret
    jc .done
    mov si, tls13_group_client_handshake
    mov cx, tls13_group_client_handshake_count
    call tls13_expand_group
    jc .done

    mov si, sym_server_hs_secret
    call tls13_prepare_secret
    jc .done
    mov si, tls13_group_server_handshake
    mov cx, tls13_group_server_handshake_count
    call tls13_expand_group
    jc .done
    mov byte [sym_client_finished_state], 0
    clc
.done:
    ret

sym_server_hs_open_begin:
    mov word [sym_record_key_ptr], sym_server_hs_key
    mov word [sym_record_iv_ptr], sym_server_hs_iv
    mov word [sym_record_seq_ptr], sym_server_hs_seq
    mov [sym_record_hash_remaining], ax
    jmp sym_open_begin

sym_server_app_open_begin:
    mov word [sym_record_key_ptr], sym_server_app_key
    mov word [sym_record_iv_ptr], sym_server_app_iv
    mov word [sym_record_seq_ptr], sym_server_app_seq
    mov word [sym_record_hash_remaining], 0
    jmp sym_open_begin

; Authenticate one exact unpadded resumed server flight without loading a
; separate transcript-page worker.  AX=1 means authenticated early-data
; acceptance; AX=2 means authenticated early-data rejection.  The caller
; remains responsible for exact plaintext shape and Finished verification.
sym_authenticate_resumed_flight:
    mov al, [sym_io_base + 4]
    cmp al, 0x3f
    je .accepted
    cmp al, 0x3b
    jne .failed
    mov ax, 6
    mov cx, 43
    mov dx, sym_io_base + 48
    jmp short .open
.accepted:
    mov ax, 10
    mov cx, 47
    mov dx, sym_io_base + 52
.open:
    push dx
    push cx
    call sym_server_hs_open_begin
    pop cx
    jc .failed_pop
    mov si, sym_io_base + 5
    call sym_open_chunk
    jc .failed_pop
    pop si
    call sym_open_finish
    jc .failed
    mov ax, 1
    cmp byte [sym_io_base + 4], 0x3f
    je .done
    inc ax
.done:
    clc
    ret
.failed_pop:
    pop dx
.failed:
    xor ax, ax
    stc
    ret

; The transcript currently ends immediately before the 36-byte server Finished.
; Verify its body, then append the complete Finished message and snapshot the
; two transcript digests needed by the client flight and application schedule.
sym_verify_server_finished:
    mov di, sym_pre_finished_hash
    call sym_transcript_snapshot

    mov si, sym_server_finished_key
    mov bx, sym_pre_finished_hash
    mov cx, sha256_digest_len
    mov di, sym_verify_work
    call tls13_hmac_once
    jc .failed
    mov si, sym_verify_work
    mov di, sym_received_server_finished
    mov cx, sha256_digest_len
    call sym_compare_ct
    jc .failed

    mov si, tls13_finished_header
    mov cx, 4
    call sha256_update
    mov si, sym_received_server_finished
    mov cx, sha256_digest_len
    call sha256_update
    mov di, sym_server_finished_hash
    call sym_transcript_snapshot
    clc
    ret
.failed:
    stc
    ret

sym_build_client_finished:
    cmp byte [sym_client_finished_state], 0
    jne .failed
    mov si, sym_client_finished_key
    mov bx, sym_server_finished_hash
    mov cx, sha256_digest_len
    mov di, sym_client_finished_verify
    call tls13_hmac_once
    jc .failed

    push ds
    pop es
    mov si, tls13_finished_header
    mov di, sym_client_finished_message
    mov cx, 4
    rep movsb
    mov si, sym_client_finished_verify
    mov cx, sha256_digest_len
    rep movsb

    mov word [sym_record_key_ptr], sym_client_hs_key
    mov word [sym_record_iv_ptr], sym_client_hs_iv
    mov word [sym_record_seq_ptr], sym_client_hs_seq
    mov si, sym_client_finished_message
    mov cx, 36
    mov al, 0x16
    call sym_seal_record
    jc .failed
    mov byte [sym_client_finished_state], 1
    clc
    ret
.failed:
    stc
    ret

sym_derive_application:
    call sym_derive_client_application
    jc .done
    jmp sym_derive_server_application
.done:
    ret

; Minimal pre-HEAD schedule.  Derive only the master secret, client
; application traffic secret, and client write key/IV.  Server-read and
; resumption work stay deferred while the complete liveness request is sent.
sym_derive_client_application:
    mov si, sym_client_app_secret
    mov di, hmac_prepared_inner_state
    mov cx, 32
    rep movsw
    mov si, tls13_group_handshake_derived
    mov cx, 1
    call tls13_expand_group
    jc .done

    mov si, sym_handshake_derived
    mov bx, tls13_zeros
    mov cx, sha256_digest_len
    mov di, sym_master_secret
    call tls13_hmac_once
    jc .done

    mov si, sym_master_secret
    call tls13_prepare_secret
    jc .done
    mov si, tls13_group_master
    mov cx, 1
    call tls13_expand_group
    jc .done

    mov si, sym_client_app_secret
    call tls13_prepare_secret
    jc .done
    mov si, tls13_group_client_application
    mov cx, tls13_group_client_application_count
    call tls13_expand_group
.done:
    ret

; Deferred post-HEAD schedule.  The live controller keeps the receive window
; closed while deriving the read key/IV and resumption master.  Entry 10 calls
; both halves, preserving the original full-derive ABI.
sym_derive_server_application:
    cmp byte [sym_client_finished_state], 1
    jne .failed
    ; Claim the deferred transcript operation before any mutable work.  A
    ; failure is terminal and cannot be retried into a double append.
    mov byte [sym_client_finished_state], 2
    mov si, sym_master_secret
    call tls13_prepare_secret
    jc .done
    mov si, tls13_group_master + 9
    mov cx, 1
    call tls13_expand_group
    jc .done
    mov si, sym_server_app_secret
    call tls13_prepare_secret
    jc .done
    mov si, tls13_group_server_application
    mov cx, tls13_group_server_application_count
    call tls13_expand_group
    jc .done

    ; The complete HEAD needs only the server-Finished transcript hash.  Keep
    ; client-Finished transcript work out of that liveness path, then append
    ; and snapshot it here immediately before the resumption-master expansion.
    mov si, sym_client_finished_message
    mov cx, 36
    call sha256_update
    mov di, sym_client_finished_hash
    call sym_transcript_snapshot

    mov si, sym_master_secret
    call tls13_prepare_secret
    jc .done
    mov si, tls13_group_resumption_master
    mov cx, 1
    call tls13_expand_group
.done:
    ret
.failed:
    stc
    ret

sym_build_head:
    mov word [sym_record_key_ptr], sym_client_app_key
    mov word [sym_record_iv_ptr], sym_client_app_iv
    mov word [sym_record_seq_ptr], sym_client_app_seq
    mov si, tls13_head_request
    mov cx, tls13_head_request_len
    mov al, 0x17
    jmp sym_seal_record

; SI=one complete plaintext NewSessionTicket handshake message, CX=length.
; Accept exactly one bounded identity, nonce 1..32, and either no extension,
; the observed well-formed early_data extension, or that extension followed by
; one well-formed zero-length unknown extension.  Derive and retain its PSK.
sym_parse_nst:
    cmp cx, 17
    jb .failed
    cmp cx, sym_mss_max
    ja .failed
    mov [sym_parse_message_ptr], si
    mov bx, si
    add bx, cx
    jc .failed
    mov [sym_parse_message_end], bx
    cmp byte [si], 4
    jne .failed
    cmp byte [si + 1], 0
    jne .failed
    mov ax, [si + 2]
    xchg al, ah
    mov dx, cx
    sub dx, 4
    cmp ax, dx
    jne .failed

    ; lifetime: 1..604800 (0x0009:0x3a80), network byte order.
    mov ax, [si + 4]
    xchg al, ah
    mov dx, [si + 6]
    xchg dl, dh
    mov [sym_parse_lifetime_hi], ax
    mov [sym_parse_lifetime_lo], dx
    or ax, dx
    jz .failed
    mov ax, [sym_parse_lifetime_hi]
    cmp ax, 9
    ja .failed
    jb .lifetime_ok
    cmp word [sym_parse_lifetime_lo], 0x3a80
    ja .failed
.lifetime_ok:
    mov ax, [si + 8]
    mov [sym_parse_age_add], ax
    mov ax, [si + 10]
    mov [sym_parse_age_add + 2], ax

    mov dl, [si + 12]
    xor dh, dh
    or dx, dx
    jz .failed
    cmp dx, sym_ticket_nonce_max
    ja .failed
    mov [sym_parse_nonce_len], dx
    mov bx, si
    add bx, 13
    mov [sym_parse_nonce_ptr], bx
    add bx, dx
    jc .failed
    mov ax, bx
    add ax, 2
    jc .failed
    cmp ax, [sym_parse_message_end]
    ja .failed
    mov si, bx
    mov ax, [si]
    xchg al, ah
    mov [sym_parse_identity_len], ax
    or ax, ax
    jz .failed
    cmp ax, sym_ticket_identity_max
    ja .failed
    add si, 2
    mov [sym_parse_identity_ptr], si
    mov bx, si
    add bx, ax
    jc .failed
    mov dx, bx
    add dx, 2
    jc .failed
    cmp dx, [sym_parse_message_end]
    ja .failed

    mov si, bx
    mov ax, [si]
    xchg al, ah
    mov [sym_parse_extensions_len], ax
    add si, 2
    mov [sym_parse_extensions_ptr], si
    mov bx, si
    add bx, ax
    jc .failed
    cmp bx, [sym_parse_message_end]
    jne .failed
    mov ax, [sym_parse_extensions_len]
    or ax, ax
    jz .extensions_ok
    cmp ax, 8
    je .extensions_first
    cmp ax, 12
    jne .extensions_failed
.extensions_first:
    mov bx, [sym_parse_extensions_ptr]
    cmp word [bx], 0x2a00              ; network bytes 00 2a
    jne .extensions_failed
    cmp word [bx + 2], 0x0400          ; network bytes 00 04
    jne .extensions_failed
    ; Retain early-data authority only when the ticket's uint32 allowance can
    ; carry the complete fixed public HEAD.  A nonzero high word is already
    ; sufficient; otherwise compare the normalized low word exactly.
    mov dx, [bx + 4]
    xchg dl, dh
    or dx, dx
    jnz .early_size_ok
    mov dx, [bx + 6]
    xchg dl, dh
    cmp dx, tls13_head_request_len
    jb .extensions_failed
.early_size_ok:
    cmp ax, 8
    je .extensions_ok
    cmp word [bx + 8], 0x2a00          ; second type must not repeat early_data
    je .extensions_failed
    cmp word [bx + 10], 0              ; unknown type, zero-length value
    je .extensions_ok
.extensions_failed:
    stc
    ret
.extensions_ok:
    ; TLS permits multiple NSTs.  Keep the first, but fully validate and drain
    ; later messages without changing the retained ticket's metadata or PSK.
    cmp byte [sym_ticket_present], 0
    jne .drained
    mov ax, [sym_parse_lifetime_hi]
    mov [sym_ticket_lifetime_hi], ax
    mov ax, [sym_parse_lifetime_lo]
    mov [sym_ticket_lifetime_lo], ax
    mov ax, [sym_parse_age_add]
    mov [sym_ticket_age_add], ax
    mov ax, [sym_parse_age_add + 2]
    mov [sym_ticket_age_add + 2], ax
    mov ax, [sym_parse_nonce_len]
    mov [sym_ticket_nonce_len], ax
    mov ax, [sym_parse_identity_len]
    mov [sym_ticket_identity_len], ax

    push ds
    pop es
    mov si, [sym_parse_nonce_ptr]
    mov di, sym_ticket_nonce
    mov cx, [sym_ticket_nonce_len]
    rep movsb
    mov si, [sym_parse_identity_ptr]
    mov di, sym_ticket_identity
    mov cx, [sym_ticket_identity_len]
    rep movsb

    mov si, sym_resumption_master_secret
    call tls13_prepare_secret
    jc .failed
    mov word [tls13_expand_label_ptr], tls13_label_resumption
    mov word [tls13_expand_label_len], tls13_label_resumption_len
    mov word [tls13_expand_context_ptr], sym_ticket_nonce
    mov ax, [sym_ticket_nonce_len]
    mov [tls13_expand_context_len], ax
    mov word [tls13_expand_output_ptr], sym_ticket_psk
    mov word [tls13_expand_output_len], sha256_digest_len
    call tls13_expand_label_prepared
    jc .failed
    mov al, 1
    cmp word [sym_parse_extensions_len], 0
    je .store_present
    inc al                              ; 2 = early-data capable
.store_present:
    mov [sym_ticket_present], al
.drained:
    clc
    ret
.failed:
    stc
    ret

; PSK-DHE resumption is a two-step surface because the binder must be emitted
; before ServerHello provides the fresh X25519MLKEM768 ciphertext/share.
;
; Input:  retained sym_ticket_psk and SHA256(ClientHelloTruncated) at
;         sym_input_binder_hash (aliases the later pre-Finished digest slot).
; Output: 32-byte binder at sym_resumption_binder_value; the early "derived"
;         secret remains at sym_handshake_derived for step two.
sym_resumption_binder:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, sym_client_hs_seq
    mov cx, 32
    rep stosb
    pop es
    pop di
    pop cx
    pop ax

    ; early_secret = HKDF-Extract(zeros, ticket_psk)
    mov si, tls13_zeros
    mov bx, sym_ticket_psk
    mov cx, sha256_digest_len
    mov di, sym_handshake_secret
    call tls13_hmac_once
    jc .done

    ; binder_key = Derive-Secret(early, "res binder", "")
    ; early_derived = Derive-Secret(early, "derived", "")
    mov si, sym_handshake_secret
    call tls13_prepare_secret
    jc .done
    mov si, tls13_group_resumption_early
    mov cx, tls13_group_resumption_early_count
    call tls13_expand_group
    jc .done

    ; finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
    mov si, sym_client_hs_secret
    call tls13_prepare_secret
    jc .done
    mov si, tls13_group_resumption_binder_finished
    mov cx, 1
    call tls13_expand_group
    jc .done

    ; binder = HMAC(finished_key, Transcript-Hash(ClientHelloTruncated))
    mov si, sym_client_finished_key
    mov bx, sym_input_binder_hash
    mov cx, sha256_digest_len
    mov di, sym_resumption_binder_value
    call tls13_hmac_once
.done:
    ret

; Input: fresh fixed-u=9 hybrid secret ML-KEM K' || server X25519 public
;        (64 bytes in the live profile) and resumed ClientHello..ServerHello
;        digest at sym_input_hello_hash.
sym_resumption_handshake:
    mov si, sym_handshake_derived
    mov bx, sym_input_shared_secret
    mov cx, sym_shared_secret_len
    mov di, sym_handshake_secret
    call tls13_hmac_once
    jc sym_derive_handshake_traffic.done
    jmp sym_derive_handshake_traffic

; ---------------------------------------------------------------------------
; Streaming TLS 1.3 ChaCha20-Poly1305 record open
; ---------------------------------------------------------------------------

sym_open_begin:
    cmp byte [sym_record_active], 0
    jne .failed
    cmp byte [sym_io_base], 0x17
    jne .failed
    cmp word [sym_io_base + 1], 0x0303
    jne .failed
    mov ax, [sym_io_base + 3]
    xchg al, ah
    cmp ax, tls_aead_tag_len + 1
    jb .failed
    sub ax, tls_aead_tag_len
    cmp ax, sym_record_cipher_max
    ja .failed
    mov [sym_record_cipher_total], ax
    mov [sym_record_cipher_remaining], ax
    cmp [sym_record_hash_remaining], ax
    ja .failed

    push ds
    pop es
    mov si, sym_io_base
    mov di, sym_record_header
    mov cx, 5
    rep movsb
    call sym_prepare_record_crypto
    jc .failed
    mov byte [sym_record_active], 1
    clc
    ret
.failed:
    stc
    ret

sym_open_chunk:
    cmp byte [sym_record_active], 1
    jne .failed
    or cx, cx
    jz .failed
    cmp cx, sym_mss_max
    ja .failed
    cmp cx, [sym_record_cipher_remaining]
    ja .failed
    push si
    push cx
    call sym_poly_update
    pop cx
    pop si
    call sym_chacha_xor
    jc .failed

    mov dx, cx
    cmp dx, [sym_record_hash_remaining]
    jbe .hash_len_ready
    mov dx, [sym_record_hash_remaining]
.hash_len_ready:
    or dx, dx
    jz .hashed
    sub [sym_record_hash_remaining], dx
    push cx
    mov cx, dx
    call sha256_update
    pop cx
.hashed:
    sub [sym_record_cipher_remaining], cx
    clc
    ret
.failed:
    stc
    ret

sym_open_finish:
    cmp byte [sym_record_active], 1
    jne .failed
    cmp word [sym_record_cipher_remaining], 0
    jne .failed
    cmp word [sym_record_hash_remaining], 0
    jne .failed
    push si
    call sym_poly_finish
    pop si
    mov di, sym_calc_tag
    xchg si, di
    mov cx, tls_aead_tag_len
    call sym_compare_ct
    jc .failed_clear
    mov si, [sym_record_seq_ptr]
    call sym_increment_seq
    jc .failed_clear
    mov byte [sym_record_active], 0
    clc
    ret
.failed_clear:
    mov byte [sym_record_active], 0
.failed:
    stc
    ret

; ---------------------------------------------------------------------------
; AEAD seal and common crypto helpers
; ---------------------------------------------------------------------------

; SI=content, CX=content length, AL=TLSInnerPlaintext content type.
sym_seal_record:
    cmp cx, sym_mss_max - 1
    ja .failed
    mov [sym_seal_content_len], cx
    mov [sym_seal_inner_type], al
    push ds
    pop es
    mov di, sym_io_base + 5
    rep movsb
    mov al, [sym_seal_inner_type]
    stosb

    mov ax, [sym_seal_content_len]
    inc ax
    mov [sym_record_cipher_total], ax
    add ax, tls_aead_tag_len
    mov byte [sym_io_base], 0x17
    mov word [sym_io_base + 1], 0x0303
    xchg al, ah
    mov [sym_io_base + 3], ax
    push ds
    pop es
    mov si, sym_io_base
    mov di, sym_record_header
    mov cx, 5
    rep movsb

    call sym_prepare_record_crypto
    jc .failed
    mov si, sym_io_base + 5
    mov cx, [sym_record_cipher_total]
    call sym_chacha_xor
    jc .failed
    mov si, sym_io_base + 5
    mov cx, [sym_record_cipher_total]
    call sym_poly_update
    call sym_poly_finish
    push ds
    pop es
    mov si, sym_calc_tag
    mov di, sym_io_base + 5
    add di, [sym_record_cipher_total]
    mov cx, tls_aead_tag_len
    rep movsb
    mov si, [sym_record_seq_ptr]
    call sym_increment_seq
    jc .failed
    mov ax, [sym_record_cipher_total]
    add ax, 5 + tls_aead_tag_len
    clc
    ret
.failed:
    stc
    ret

sym_prepare_record_crypto:
    push ds
    pop es
    mov si, [sym_record_iv_ptr]
    mov di, sym_record_nonce
    mov cx, tls_chacha_iv_len
    rep movsb
    mov si, [sym_record_seq_ptr]
    mov di, sym_record_nonce + 4
    mov cx, 8
.xor_seq:
    lodsb
    xor [di], al
    inc di
    loop .xor_seq

    mov ax, [sym_record_key_ptr]
    mov [chacha_key_ptr], ax
    mov word [chacha_nonce_ptr], sym_record_nonce
    mov word [chacha_counter_low], 0
    mov word [chacha_counter_high], 0
    call chacha20_block
    call poly1305_load_key
    call poly1305_clear_acc
    call poly1305_clear_block
    push ds
    pop es
    mov si, sym_record_header
    mov di, poly_block
    mov cx, 5
    rep movsb
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    call poly1305_clear_block
    mov byte [sym_poly_fill], 0
    mov word [sym_poly_cipher_len], 0
    mov word [chacha_counter_low], 1
    mov word [chacha_counter_high], 0
    mov byte [sym_chacha_pos], chacha_block_len
    clc
    ret

; SI=mutable buffer, CX=len.  Works across arbitrary <=384-byte chunk cuts.
sym_chacha_xor:
    push ax
    push bx
    push cx
    push si
.next:
    or cx, cx
    jz .done
    cmp byte [sym_chacha_pos], chacha_block_len
    jb .have_block
    call chacha20_block
    inc word [chacha_counter_low]
    jnz .counter_ok
    inc word [chacha_counter_high]
.counter_ok:
    mov byte [sym_chacha_pos], 0
.have_block:
    mov bl, [sym_chacha_pos]
    xor bh, bh
    mov al, [chacha_block + bx]
    xor [si], al
    inc si
    inc byte [sym_chacha_pos]
    dec cx
    jmp .next
.done:
    pop si
    pop cx
    pop bx
    pop ax
    clc
    ret

; SI=ciphertext, CX=len.
sym_poly_update:
    or cx, cx
    jz .done
    add [sym_poly_cipher_len], cx
.next:
    mov bl, [sym_poly_fill]
    xor bh, bh
    mov al, [si]
    mov [poly_block + bx], al
    inc si
    inc bl
    cmp bl, 16
    jb .keep
    push cx
    push si
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    call poly1305_clear_block
    pop si
    pop cx
    xor bl, bl
.keep:
    mov [sym_poly_fill], bl
    dec cx
    jnz .next
.done:
    ret

sym_poly_finish:
    cmp byte [sym_poly_fill], 0
    je .lengths
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
.lengths:
    call poly1305_clear_block
    mov byte [poly_block], 5
    mov ax, [sym_poly_cipher_len]
    mov [poly_block + 8], ax
    mov word [poly_block_ptr], poly_block
    call poly1305_process_block
    call poly1305_emit_tag
    ret

sym_increment_seq:
    push cx
    push di
    mov di, si
    mov cx, 8
.check_exhausted:
    cmp byte [di], 0xff
    jne .increment
    inc di
    loop .check_exhausted
    stc
    jmp short .done
.increment:
    mov di, si
    add di, 7
    mov cx, 8
.next:
    inc byte [di]
    jnz .incremented
    dec di
    loop .next
.incremented:
    clc
.done:
    pop di
    pop cx
    ret

sym_compare_ct:
    ; SI/DI buffers, CX=len.  CF=0 only when every byte is equal.
    push ax
    push bx
    xor bx, bx
.next:
    or cx, cx
    jz .done
    mov al, [si]
    xor al, [di]
    or bl, al
    inc si
    inc di
    dec cx
    jmp .next
.done:
    or bl, bl
    jnz .different
    clc
    jmp short .restore
.different:
    stc
.restore:
    pop bx
    pop ax
    ret

sym_transcript_snapshot:
    ; DI=32-byte output; leave the live transcript context unchanged.
    pushf
    call sha256_save_context
    call sha256_finish
    call sha256_restore_context
    popf
    clc
    ret

; ---------------------------------------------------------------------------
; HKDF-Expand-Label and grouped fixed-profile schedule
; ---------------------------------------------------------------------------

tls13_prepare_secret:
    mov [hmac_key_ptr], si
    mov word [hmac_key_len], sha256_digest_len
    jmp hmac_prepare_current_key_context

; SI=salt32, BX=input, CX=input len, DI=output32.
tls13_hmac_once:
    mov [hmac_key_ptr], si
    mov word [hmac_key_len], sha256_digest_len
    mov [hmac_data1_ptr], bx
    mov [hmac_data1_len], cx
    mov word [hmac_data2_len], 0
    mov [hmac_output_ptr], di
    call hmac_prepare_current_key_context
    jc .done
    jmp hmac_sha256_prepared
.done:
    ret

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

; ---------------------------------------------------------------------------
; Shipping primitive implementations
; ---------------------------------------------------------------------------

; The overlay's deadline path uses the compact exact byte-rotate form.  The
; shipping core keeps its established implementation unless it opts in.
%define CHACHA_COMPACT_FAST_ROTATES 1
%include "core/chacha20.inc"
%undef CHACHA_COMPACT_FAST_ROTATES
%include "core/poly1305.inc"
%include "core/sha256.inc"

; ---------------------------------------------------------------------------
; Immutable protocol constants and descriptor tables
; ---------------------------------------------------------------------------

tls13_label_prefix db 'tls13 '
tls13_label_prefix_len equ $ - tls13_label_prefix
tls13_label_c_hs_traffic db 'c hs traffic'
tls13_label_c_hs_traffic_len equ $ - tls13_label_c_hs_traffic
tls13_label_s_hs_traffic db 's hs traffic'
tls13_label_s_hs_traffic_len equ $ - tls13_label_s_hs_traffic
tls13_label_derived db 'derived'
tls13_label_derived_len equ $ - tls13_label_derived
tls13_label_key db 'key'
tls13_label_key_len equ $ - tls13_label_key
tls13_label_iv db 'iv'
tls13_label_iv_len equ $ - tls13_label_iv
tls13_label_finished db 'finished'
tls13_label_finished_len equ $ - tls13_label_finished
tls13_label_c_ap_traffic db 'c ap traffic'
tls13_label_c_ap_traffic_len equ $ - tls13_label_c_ap_traffic
tls13_label_s_ap_traffic db 's ap traffic'
tls13_label_s_ap_traffic_len equ $ - tls13_label_s_ap_traffic
tls13_label_res_master db 'res master'
tls13_label_res_master_len equ $ - tls13_label_res_master
tls13_label_res_binder db 'res binder'
tls13_label_res_binder_len equ $ - tls13_label_res_binder
tls13_label_resumption db 'resumption'
tls13_label_resumption_len equ $ - tls13_label_resumption
tls13_empty_context:

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
tls13_zeros times sha256_digest_len db 0
tls13_finished_header db 0x14,0x00,0x00,0x20
tls13_head_request:
    db 'HEAD /v1/models HTTP/1.1',13,10
    db 'Host: api.openai.com',13,10
    db 13,10
tls13_head_request_len equ $ - tls13_head_request

tls13_group_handshake:
    TLS13_DESCRIPTOR tls13_label_c_hs_traffic, tls13_label_c_hs_traffic_len, \
                     sym_input_hello_hash, sha256_digest_len, \
                     sym_client_hs_secret, sha256_digest_len
    TLS13_DESCRIPTOR tls13_label_s_hs_traffic, tls13_label_s_hs_traffic_len, \
                     sym_input_hello_hash, sha256_digest_len, \
                     sym_server_hs_secret, sha256_digest_len
tls13_group_handshake_count equ ($ - tls13_group_handshake) / 9

tls13_group_client_handshake:
    TLS13_DESCRIPTOR tls13_label_key, tls13_label_key_len, \
                     tls13_empty_context, 0, sym_client_hs_key, 32
    TLS13_DESCRIPTOR tls13_label_iv, tls13_label_iv_len, \
                     tls13_empty_context, 0, sym_client_hs_iv, 12
    TLS13_DESCRIPTOR tls13_label_finished, tls13_label_finished_len, \
                     tls13_empty_context, 0, sym_client_finished_key, 32
tls13_group_client_handshake_count equ ($ - tls13_group_client_handshake) / 9

tls13_group_server_handshake:
    TLS13_DESCRIPTOR tls13_label_key, tls13_label_key_len, \
                     tls13_empty_context, 0, sym_server_hs_key, 32
    TLS13_DESCRIPTOR tls13_label_iv, tls13_label_iv_len, \
                     tls13_empty_context, 0, sym_server_hs_iv, 12
    TLS13_DESCRIPTOR tls13_label_finished, tls13_label_finished_len, \
                     tls13_empty_context, 0, sym_server_finished_key, 32
tls13_group_server_handshake_count equ ($ - tls13_group_server_handshake) / 9

tls13_group_handshake_derived:
    TLS13_DESCRIPTOR tls13_label_derived, tls13_label_derived_len, \
                     tls13_empty_hash, sha256_digest_len, \
                     sym_handshake_derived, sha256_digest_len

tls13_group_master:
    TLS13_DESCRIPTOR tls13_label_c_ap_traffic, tls13_label_c_ap_traffic_len, \
                     sym_server_finished_hash, sha256_digest_len, \
                     sym_client_app_secret, sha256_digest_len
    TLS13_DESCRIPTOR tls13_label_s_ap_traffic, tls13_label_s_ap_traffic_len, \
                     sym_server_finished_hash, sha256_digest_len, \
                     sym_server_app_secret, sha256_digest_len
tls13_group_master_count equ ($ - tls13_group_master) / 9

tls13_group_client_application:
    TLS13_DESCRIPTOR tls13_label_key, tls13_label_key_len, \
                     tls13_empty_context, 0, sym_client_app_key, 32
    TLS13_DESCRIPTOR tls13_label_iv, tls13_label_iv_len, \
                     tls13_empty_context, 0, sym_client_app_iv, 12
tls13_group_client_application_count equ ($ - tls13_group_client_application) / 9

tls13_group_server_application:
    TLS13_DESCRIPTOR tls13_label_key, tls13_label_key_len, \
                     tls13_empty_context, 0, sym_server_app_key, 32
    TLS13_DESCRIPTOR tls13_label_iv, tls13_label_iv_len, \
                     tls13_empty_context, 0, sym_server_app_iv, 12
tls13_group_server_application_count equ ($ - tls13_group_server_application) / 9

tls13_group_resumption_master:
    TLS13_DESCRIPTOR tls13_label_res_master, tls13_label_res_master_len, \
                     sym_client_finished_hash, sha256_digest_len, \
                     sym_resumption_master_secret, sha256_digest_len

tls13_group_resumption_early:
    TLS13_DESCRIPTOR tls13_label_res_binder, tls13_label_res_binder_len, \
                     tls13_empty_hash, sha256_digest_len, \
                     sym_client_hs_secret, sha256_digest_len
    TLS13_DESCRIPTOR tls13_label_derived, tls13_label_derived_len, \
                     tls13_empty_hash, sha256_digest_len, \
                     sym_handshake_derived, sha256_digest_len
tls13_group_resumption_early_count equ ($ - tls13_group_resumption_early) / 9

tls13_group_resumption_binder_finished:
    TLS13_DESCRIPTOR tls13_label_finished, tls13_label_finished_len, \
                     tls13_empty_context, 0, sym_client_finished_key, \
                     sha256_digest_len

chacha_constants:
    dw 0x7865,0x6170,0x646e,0x3320
    dw 0x2d32,0x7962,0x6574,0x6b20
poly1305_prime:
    db 0xfb
    times 15 db 0xff
    db 0x03
%ifdef TLS13_PRODUCT_CRITICAL_TAIL_PATH
%ifndef TLS13_PRODUCT_SHA256_INITIAL_STATE
%error "product critical tail requires the canonical SHA-256 initial-state address"
%endif
; The product K14 operand remains bound to the canonical state at 2ee0.  After
; ServerHello commits, HELLO stages a copy of that state below the resident TCP
; tail and stages K[0..63] in Seed's existing 0500..05ff low table.  The 288
; bytes thereby released at the end of the immutable symmetric image carry the
; deadline-only vault writer and copy-before-use symmetric continuation.  That
; continuation reconstructs the canonical state at 2ee0 and K at 2f00 before
; the first SHA operation; later off-window loads apply the canonical final-
; sector restore phase.
sha256_initial_state equ TLS13_PRODUCT_SHA256_INITIAL_STATE
sha256_k             equ 0x2f00
%if ($ - sym_overlay_header) != 0x16e0
%error "product symmetric critical tail no longer begins at 2ee0"
%endif
sym_product_critical_tail:
    incbin TLS13_PRODUCT_CRITICAL_TAIL_PATH
sym_product_critical_tail_end:
%if (sym_product_critical_tail_end - sym_product_critical_tail) != 0x0120
%error "product symmetric critical tail is not exactly 288 bytes"
%endif
%else
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
%endif

sym_overlay_end:

; ---------------------------------------------------------------------------
; Fixed external writable ABI
; ---------------------------------------------------------------------------

; SHA/HMAC/AEAD work is packed into the unused tail of the loaded K overlay.
; It deliberately leaves both live low-memory bands untouched:
;   0700..08b6  receive frame
;   08c0..0cff  raw ML-KEM ciphertext retained through post-Finished proof
sym_k_work_base equ sym_overlay_base + \
    (((sym_overlay_end - sym_overlay_header) + 15) & 0xfff0)
sym_low_scratch_base equ sym_k_work_base
sha256_state equ sym_low_scratch_base
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
hmac_ipad equ sha256_saved_block + sha256_block_size
hmac_opad equ hmac_ipad + sha256_block_size
; Raw ipad/opad bytes are dead as soon as their chaining states are prepared.
; Reuse their 128-byte span for the inner digest, the contiguous prepared
; inner/outer pair, and the HKDF info tail.  hmac_sha256_prepared consumes
; these in that lifetime order and never needs the raw pads again.
hmac_inner_digest equ hmac_ipad
hmac_prepared_inner_state equ hmac_ipad + 32
hmac_prepared_outer_state equ hmac_opad
tls13_hkdf_info equ hmac_opad + 32
tls13_hkdf_info_len equ 55
tls13_hkdf_block equ tls13_hkdf_info + tls13_hkdf_info_len
tls13_expand_label_ptr equ tls13_hkdf_block + 32
tls13_expand_label_len equ tls13_expand_label_ptr + 2
tls13_expand_context_ptr equ tls13_expand_label_len + 2
tls13_expand_context_len equ tls13_expand_context_ptr + 2
tls13_expand_output_ptr equ tls13_expand_context_len + 2
tls13_expand_output_len equ tls13_expand_output_ptr + 2

; HKDF output/descriptor scratch is dead whenever record ChaCha is active.
; Alias the 64-byte ChaCha state at tls13_hkdf_block, reclaiming the 44-byte
; block-plus-descriptor tail without overlapping the still-live HKDF info.
chacha_state equ tls13_hkdf_block
chacha_work equ chacha_state + 64
chacha_block equ chacha_work + 64
chacha_key_ptr equ chacha_block + 64
chacha_nonce_ptr equ chacha_key_ptr + 2
chacha_counter_low equ chacha_nonce_ptr + 2
chacha_counter_high equ chacha_counter_low + 2
poly_r equ chacha_counter_high + 2
poly_s equ poly_r + 16
poly_acc equ poly_s + 16
poly_product equ poly_acc + 17
poly_value equ poly_product + 36
poly_block equ poly_value + 24
poly_block_ptr equ poly_block + 16
poly_i equ poly_block_ptr + 2
poly_j equ poly_i + 1
sym_k_work_end equ poly_j + 1

%ifdef TLS13_POC_K14
; Primitive SHA/HMAC/AEAD work stays in K through
; sym_k_work_end (currently 0x33f8). The 77-byte runtime tail follows the cold symmetric
; controller in K14's persistent extension.  This leaves the complete
; 0e00..0fff sector available for protected-flight disk staging without
; destroying either the retained candidate handoff at 0700 or live state.
sym_low_runtime_clear_start equ sym_k_extension_work_start
%else
sym_low_runtime_clear_start equ poly_j + 1
%endif
sym_record_key_ptr equ sym_low_runtime_clear_start
sym_record_iv_ptr equ sym_record_key_ptr + 2
sym_record_seq_ptr equ sym_record_iv_ptr + 2
sym_record_cipher_total equ sym_record_seq_ptr + 2
sym_record_cipher_remaining equ sym_record_cipher_total + 2
sym_record_hash_remaining equ sym_record_cipher_remaining + 2
sym_poly_cipher_len equ sym_record_hash_remaining + 2
sym_poly_fill equ sym_poly_cipher_len + 2
sym_chacha_pos equ sym_poly_fill + 1
sym_record_active equ sym_chacha_pos + 1
sym_seal_inner_type equ sym_record_active + 1
sym_seal_content_len equ sym_seal_inner_type + 1
sym_record_header equ sym_seal_content_len + 2
sym_record_nonce equ sym_record_header + 5
sym_calc_tag equ sym_record_nonce + 12
sym_parse_message_ptr equ sym_calc_tag + 16
sym_parse_message_end equ sym_parse_message_ptr + 2
sym_parse_lifetime_hi equ sym_parse_message_end + 2
sym_parse_lifetime_lo equ sym_parse_lifetime_hi + 2
sym_parse_age_add equ sym_parse_lifetime_lo + 2
sym_parse_nonce_ptr equ sym_parse_age_add + 4
sym_parse_nonce_len equ sym_parse_nonce_ptr + 2
sym_parse_identity_ptr equ sym_parse_nonce_len + 2
sym_parse_identity_len equ sym_parse_identity_ptr + 2
sym_parse_extensions_ptr equ sym_parse_identity_len + 2
sym_parse_extensions_len equ sym_parse_extensions_ptr + 2
sym_low_runtime_clear_end equ sym_parse_extensions_len + 2
sym_low_scratch_end equ sym_low_runtime_clear_end
%ifdef TLS13_POC_K14
%if sym_low_runtime_clear_end != sym_k_extension_work_end
%error "K14 symmetric runtime tail no longer matches shared extension contract"
%endif
%endif

; Names required by the shipping Poly1305 compilation unit.  The TLS 1.2-only
; convenience routine is never called by this overlay.
tls_aead_aad equ sym_record_header
tls_aead_aad_len equ 5
tls_finished_cipher equ sym_io_base + 5
tls_finished_cipher_len equ 16
tls_finished_tag equ sym_calc_tag

; High retained state.  The live fixed-u=9 profile passes the 64-byte
; ML-KEM K' || server-X25519-public string directly to HKDF-Extract.
sym_input_shared_secret equ sym_high_state_base + 0x000
sym_input_hello_hash equ sym_high_state_base + 0x040
sym_pre_finished_hash equ sym_high_state_base + 0x060
sym_input_binder_hash equ sym_pre_finished_hash
sym_server_finished_hash equ sym_high_state_base + 0x080
sym_client_finished_hash equ sym_high_state_base + 0x0a0
sym_handshake_secret equ sym_high_state_base + 0x0c0
sym_client_hs_secret equ sym_high_state_base + 0x0e0
sym_server_hs_secret equ sym_high_state_base + 0x100
sym_client_hs_key equ sym_high_state_base + 0x120
sym_client_hs_iv equ sym_high_state_base + 0x140
sym_client_finished_key equ sym_high_state_base + 0x14c
sym_server_hs_key equ sym_high_state_base + 0x16c
sym_server_hs_iv equ sym_high_state_base + 0x18c
sym_server_finished_key equ sym_high_state_base + 0x198
sym_handshake_derived equ sym_high_state_base + 0x1b8
sym_master_secret equ sym_high_state_base + 0x1d8
sym_client_app_secret equ sym_high_state_base + 0x1f8
sym_server_app_secret equ sym_high_state_base + 0x218
sym_client_app_key equ sym_high_state_base + 0x238
sym_client_app_iv equ sym_high_state_base + 0x258
sym_server_app_key equ sym_high_state_base + 0x264
sym_server_app_iv equ sym_high_state_base + 0x284
sym_resumption_master_secret equ sym_high_state_base + 0x290
sym_ticket_psk equ sym_high_state_base + 0x2b0
sym_client_hs_seq equ sym_high_state_base + 0x2d0
sym_server_hs_seq equ sym_high_state_base + 0x2d8
sym_client_app_seq equ sym_high_state_base + 0x2e0
sym_server_app_seq equ sym_high_state_base + 0x2e8
sym_received_server_finished equ sym_high_state_base + 0x2f0
sym_received_tag equ sym_high_state_base + 0x310
sym_verify_work equ sym_high_state_base + 0x320
sym_client_finished_verify equ sym_high_state_base + 0x340
sym_resumption_binder_value equ sym_client_finished_verify
sym_client_finished_message equ sym_high_state_base + 0x360
sym_io_base equ sym_high_state_base + 0x3a0
sym_io_end equ sym_io_base + 5 + sym_mss_max + tls_aead_tag_len
sym_ticket_identity equ sym_high_state_base + 0x540
sym_ticket_nonce equ sym_high_state_base + 0x600
sym_ticket_lifetime_hi equ sym_high_state_base + 0x620
sym_ticket_lifetime_lo equ sym_ticket_lifetime_hi + 2
sym_ticket_age_add equ sym_ticket_lifetime_lo + 2
sym_ticket_nonce_len equ sym_ticket_age_add + 4
sym_ticket_identity_len equ sym_ticket_nonce_len + 2
sym_ticket_present equ sym_ticket_identity_len + 2
sym_client_finished_state equ sym_ticket_present + 1
sym_high_state_end equ sym_client_finished_state + 1

%if sym_high_state_end > sym_high_security_state_limit
%error "symmetric retained state exceeds its security-state window"
%endif

%if (sym_overlay_end - sym_overlay_header) > (sym_overlay_limit - sym_overlay_base)
%error "TLS 1.3 symmetric overlay exceeds the 15-sector K window"
%endif
%if sym_k_work_end > sym_overlay_limit
%error "TLS 1.3 symmetric primitive work exceeds the K tail"
%endif
%if sym_low_scratch_base < \
    (sym_overlay_base + (sym_overlay_end - sym_overlay_header))
%error "TLS 1.3 symmetric mutable work overlaps code/static data"
%endif
%if (sym_low_scratch_base < sym_optional_low_work_end) && \
    (sym_low_scratch_end > sym_rx_frame_start)
%error "TLS 1.3 symmetric work overlaps live low receive/KEM bands"
%endif
%ifdef TLS13_POC_K14
%if sym_low_runtime_clear_start < sym_k_extension_start
%error "K14 symmetric runtime tail begins below the executable extension"
%endif
%if sym_low_runtime_clear_end > sym_k_extension_end
%error "K14 symmetric runtime tail exceeds the executable extension"
%endif
%else
%if sym_low_scratch_end != sym_k_work_end + \
    (sym_low_runtime_clear_end - sym_low_runtime_clear_start)
%error "default symmetric work lost its contiguous K layout"
%endif
%endif
%if sym_hello_context_end > sym_optional_low_work_end
%error "HELLO transcript handoff exceeds optional low scratch"
%endif
%if sym_io_end > sym_ticket_identity
%error "TLS 1.3 symmetric IO overlaps ticket identity"
%endif
%if (sym_ticket_identity + sym_ticket_identity_max) > sym_ticket_nonce
%error "TLS 1.3 ticket identity exceeds its fixed slot"
%endif
%if (sym_ticket_nonce + sym_ticket_nonce_max) > sym_ticket_lifetime_hi
%error "TLS 1.3 ticket nonce exceeds its fixed slot"
%endif
%if sym_high_state_end > sym_high_security_state_limit
%error "TLS 1.3 symmetric retained state exceeds the security-state band"
%endif
%if sym_arena_floor >= sym_stack_guard_base
%error "bad product arena/stack guard ordering"
%endif
