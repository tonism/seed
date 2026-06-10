; Self-contained TLS 1.2 PRF driver for the crypto micro-benchmark.
; Verbatim copy of the PRF/key-schedule functions from core/tls.inc
; (tls_prepare_master_secret @594 .. tls_split_key_block @733). Depends only on
; hmac_*/sha256_* (core/sha256.inc) + memory moves. Inputs: tls_premaster_secret,
; tls_random, tls_server_random. Outputs: tls_master_secret, tls_key_block, and
; the split client/server write keys/ivs. Kept here so the benchmark can exercise
; the exact ~7.5 s CKE->Finished cost without pulling in tls.inc's net deps.

tls_prepare_master_secret:
    call tls_build_master_secret_seed
    mov word [hmac_key_ptr], tls_premaster_secret
    mov word [hmac_key_len], tls_ec_coordinate_len
    call hmac_prepare_current_key_context
    jc .failed
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_master_secret
    mov word [tls_prf_output_len], tls_master_secret_len
    call tls_prf_sha256_expand
    jc .failed
    mov word [hmac_key_ptr], tls_master_secret
    mov word [hmac_key_len], tls_master_secret_len
    jmp hmac_prepare_current_key_context
.failed:
    stc
    ret

tls_prepare_key_block:
    call tls_build_key_expansion_seed
    mov word [tls_prf_seed_ptr], tls_prf_seed
    mov word [tls_prf_output_ptr], tls_key_block
    mov word [tls_prf_output_len], tls_key_block_len
    call tls_prf_sha256_expand
    jc .failed
    call tls_split_key_block
    mov byte [tls_key_schedule_ready], 1
    clc
    ret
.failed:
    stc
    ret

tls_build_master_secret_seed:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, tls_prf_seed
    mov si, tls_label_master_secret
    mov cx, tls_label_master_secret_len
    rep movsb
    mov si, tls_random
    mov cx, tls_random_len
    rep movsb
    mov si, tls_server_random
    mov cx, tls_random_len
    rep movsb
    mov word [tls_prf_seed_len], tls_label_master_secret_len + tls_random_len + tls_random_len
    pop es
    pop di
    pop si
    pop cx
    ret

tls_build_key_expansion_seed:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, tls_prf_seed
    mov si, tls_label_key_expansion
    mov cx, tls_label_key_expansion_len
    rep movsb
    mov si, tls_server_random
    mov cx, tls_random_len
    rep movsb
    mov si, tls_random
    mov cx, tls_random_len
    rep movsb
    mov word [tls_prf_seed_len], tls_label_key_expansion_len + tls_random_len + tls_random_len
    pop es
    pop di
    pop si
    pop cx
    ret

tls_prf_sha256_expand:
    mov ax, [tls_prf_output_len]
    mov [tls_prf_output_remaining], ax
    mov ax, [tls_prf_output_ptr]
    mov [tls_prf_current_output_ptr], ax

    mov ax, [tls_prf_seed_ptr]
    mov [hmac_data1_ptr], ax
    mov ax, [tls_prf_seed_len]
    mov [hmac_data1_len], ax
    mov word [hmac_data2_len], 0
    mov word [hmac_output_ptr], tls_prf_a
    call hmac_sha256_prepared
    jc .failed
.next_chunk:
    cmp word [tls_prf_output_remaining], 0
    je .done
    mov word [hmac_data1_ptr], tls_prf_a
    mov word [hmac_data1_len], sha256_digest_len
    mov ax, [tls_prf_seed_ptr]
    mov [hmac_data2_ptr], ax
    mov ax, [tls_prf_seed_len]
    mov [hmac_data2_len], ax
    mov word [hmac_output_ptr], tls_prf_chunk
    call hmac_sha256_prepared
    jc .failed

    mov cx, [tls_prf_output_remaining]
    cmp cx, sha256_digest_len
    jbe .chunk_len_ready
    mov cx, sha256_digest_len
.chunk_len_ready:
    mov [tls_prf_chunk_len], cx
    push ds
    pop es
    mov si, tls_prf_chunk
    mov di, [tls_prf_current_output_ptr]
    rep movsb
    mov ax, [tls_prf_chunk_len]
    add [tls_prf_current_output_ptr], ax
    sub [tls_prf_output_remaining], ax
    cmp word [tls_prf_output_remaining], 0
    je .done

    mov word [hmac_data1_ptr], tls_prf_a
    mov word [hmac_data1_len], sha256_digest_len
    mov word [hmac_data2_len], 0
    mov word [hmac_output_ptr], tls_prf_a
    call hmac_sha256_prepared
    jc .failed
    jmp .next_chunk
.done:
    clc
    ret
.failed:
    stc
    ret

tls_split_key_block:
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, tls_key_block
    mov di, tls_client_write_key
    mov cx, tls_chacha_key_len
    rep movsb
    mov di, tls_server_write_key
    mov cx, tls_chacha_key_len
    rep movsb
    mov di, tls_client_write_iv
    mov cx, tls_chacha_iv_len
    rep movsb
    mov di, tls_server_write_iv
    mov cx, tls_chacha_iv_len
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    ret
