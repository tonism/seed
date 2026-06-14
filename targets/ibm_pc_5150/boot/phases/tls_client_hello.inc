%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

tls_client_hello_phase:
    ; Build 12 286 secure increment B: patch the ClientHello for the RSA cert-auth path BEFORE building
    ; it -- offer ECDHE_RSA (0xcca8) + advertise rsa_pkcs1_sha256 (0x0401), so the server presents an
    ; RSA cert + an RSA-PKCS1-SHA256 ServerKeyExchange signature we verify against the pinned leaf key.
    ; 286-only; the 8088 keeps ECDHE_ECDSA (0xcca9) -- unauthenticated, and its smaller ECDSA cert
    ; keeps the tight 8088 handshake window. The patch rides the L-phase image (re-applied per load).
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .build
    mov byte [low_scratch_start + (tls_ch_cipher_lo - PHASE_BASE)], 0xa8
    mov byte [low_scratch_start + (tls_ch_sigalg_lo - PHASE_BASE)], 1
.build:
    call build_tls_client_hello_phase
    jc .done
    ; Build 12 286 secure tier: generate the client ephemeral ECDHE keypair (real entropy -> client
    ; scalar -> client_public = scalar x G) HERE in the L phase -- before the TCP connect (C) and the
    ; ClientHello send -- so the ~6.6s scalar mult falls OUTSIDE the server's ServerHelloDone->Finished
    ; patience window. 286-only (gated on the boot-detected CPU class); the 8088 sends the fixed G.
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .done
    call tls_client_hello_secure_prep            ; CF on module-load or keypair-gen failure -> retry
.done:
    ret

build_tls_client_hello_phase:
    call tls_seed_client_random_phase
    mov si, low_scratch_start + (sha256_k_constant - PHASE_BASE)
    mov di, sha256_k
    mov cx, sha256_k_len
    rep movsb
    mov si, low_scratch_start + (tls_low_constants_constant - PHASE_BASE)
    mov di, low_static_constants_start
    mov cx, low_static_constants_len
    rep movsb
    mov al, [dns_qname_len]
    cmp al, 3
    jb .failed
    sub al, 2
    xor ah, ah
    mov [tls_host_len], ax
    add ax, tls_client_base_len
    cmp ax, tcp_payload_max_len
    ja .failed
    mov [tls_tx_len], ax

    mov di, tls_client_hello_buffer
    mov al, 0x16
    stosb
    mov ax, 0x0103
    stosw
    mov ax, [tls_host_len]
    add ax, tls_record_base_len
    phase_call_res tls_write_be16

    mov al, 0x01
    stosb
    xor al, al
    stosb
    mov ax, [tls_host_len]
    add ax, tls_body_base_len
    phase_call_res tls_write_be16
    mov ax, 0x0303
    stosw

    mov si, tls_random
    mov cx, tls_random_len
    rep movsb
    mov si, low_scratch_start + (tls_client_hello_after_random - PHASE_BASE)
    mov cx, tls_after_random_len
    rep movsb

    mov ax, [tls_host_len]
    add ax, tls_extensions_base_len
    phase_call_res tls_write_be16

    mov si, low_scratch_start + (tls_client_hello_extensions_prefix - PHASE_BASE)
    mov cx, tls_extensions_prefix_len
    rep movsb

    xor ax, ax
    stosw
    mov ax, [tls_host_len]
    add ax, 5
    phase_call_res tls_write_be16
    mov ax, [tls_host_len]
    add ax, 3
    phase_call_res tls_write_be16
    xor al, al
    stosb
    mov ax, [tls_host_len]
    phase_call_res tls_write_be16

    mov si, dns_qname
.label:
    lodsb
    or al, al
    jz .host_done
    mov cl, al
    xor ch, ch
    rep movsb
    cmp byte [si], 0
    je .label
    mov al, '.'
    stosb
    jmp .label
.host_done:
    mov si, low_scratch_start + (tls_client_hello_extensions_tail - PHASE_BASE)
    mov cx, tls_extensions_tail_len
    rep movsb
    clc
    ret
.failed:
    stc
    ret

tls_seed_client_random_phase:
    push ax
    push bx
    push cx
    push dx
    push di
    push es
    push ds
    pop es
    mov ax, [0x046c]
    xor ax, [0x046e]
    xor al, [handoff_addr + handoff_mac]
    xor ah, [handoff_addr + handoff_mac + 5]
    or ax, ax
    jnz .seed_ready
    mov ax, 0x5eed
.seed_ready:
    mov bx, 25173
    mov di, tls_random
    mov cx, tls_random_len / 2
.next_word:
    mul bx
    add ax, 13849
    adc dx, 0
    xor ax, dx
    add ax, cx
    stosw
    loop .next_word
    pop es
    pop di
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Build 12 286 secure tier: generate the client ephemeral ECDHE keypair. Loads the P-256 module (a
; floppy read -- fine here: pre-connect, before the ~15s handshake race), mixes a real entropy pool
; into a SHA-256 client scalar, then computes client_public = scalar x G into the module. CF=1 on a
; module-load or degenerate-keypair failure (the caller retries). The 86Box emulator is cycle-exact,
; so the pool is reproducible under test; on real hardware the BIOS tick + PIT phase carry entropy
; (keystrokes are unavailable at boot). The pool is REAL; its emulated determinism is documented, and
; it matters only bundled with the real ECDHE secret below -- not a cosmetic standalone fix.
tls_client_hello_secure_prep:
    ; 1. load the 286-only P-256 module (whole sectors) into its overlay band at p256_module_load.
    mov ax, (((core_p256_module_end - core_p256_module_start + 511) / 512) << 8) | ((core_p256_module_start - $$) / 512)
    mov bx, p256_module_load
    phase_call_res load_core_sectors_at
    jc .sp_fail
    ; 2. entropy pool -> SHA-256 -> 32-byte client secret. The K crypto window (sha256_*) is resident
    ;    here (loaded in prepare_agent_endpoint_path before this phase). The digest temporarily uses
    ;    tls_premaster_secret (0x3600), which the real premaster overwrites later in tls_probe.
    phase_call_res sha256_init
    mov si, tls_random                          ; LCG client random (already tick/MAC-seeded), 32 B
    mov cx, tls_random_len
    phase_call_res sha256_update
    mov si, handoff_addr + handoff_mac          ; NIC MAC (per machine), 6 B
    mov cx, 6
    phase_call_res sha256_update
    mov si, 0x046c                              ; BIOS tick count @ 0040:006C (boot timing), 4 B
    mov cx, 4
    phase_call_res sha256_update
    mov al, 0                                   ; latch PIT channel 0 (the system timer sub-tick)
    out 0x43, al
    in al, 0x40
    mov [low_scratch_start + (entropy_pit_buf - PHASE_BASE)], al
    in al, 0x40
    mov [low_scratch_start + (entropy_pit_buf - PHASE_BASE) + 1], al
    mov si, low_scratch_start + (entropy_pit_buf - PHASE_BASE)
    mov cx, 2
    phase_call_res sha256_update
    mov di, tls_premaster_secret
    phase_call_res sha256_finish
    ; 3. seed the client scalar (LANDMINE #3: a SHA-256 digest is never exactly 1 or 2, so the module's
    ;    insecure _is_one/_is_two fast paths never trigger) and compute the client public point.
    mov si, tls_premaster_secret
    call word [p256_ep_set_client_private]
    call word [p256_ep_gen_client_public]       ; CF=1 if priv x G is degenerate
    ret
.sp_fail:
    stc
    ret
entropy_pit_buf: times 2 db 0

tls_client_hello_after_random db 0
                              db 0, 2, 0xcc
tls_ch_cipher_lo:             db 0xa9          ; cipher 0xcca9 (ECDHE_ECDSA); 286 patches -> 0xa8 (ECDHE_RSA 0xcca8)
                              db 1, 0
tls_client_hello_extensions_prefix db 0xff, 1, 0, 1, 0
tls_client_hello_extensions_tail db 0, 11, 0, 2, 1, 0
                                 db 0, 10, 0, 4, 0, 2, 0, 23
                                 db 0, 13, 0, 4, 0, 2, 4
tls_ch_sigalg_lo:                db 3           ; sigalg {sha256(4), ecdsa(3)}; 286 patches -> 1 (rsa) = rsa_pkcs1_sha256
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
tls_low_constants_constant_len equ $ - tls_low_constants_constant
%if tls_low_constants_constant_len != low_static_constants_len
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
sha256_k_constant_len equ $ - sha256_k_constant
%if sha256_k_constant_len != sha256_k_len
%error "sha256 k length mismatch"
%endif

%unmacro phase_call_res 1
