%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%define PHASE_LOAD_ADDR low_scratch_start
%define PHASE_LOAD_ADDR_DEFAULTED
%endif

agent_cache_phase:
%ifdef TLS13_PRODUCT_TLS13
    ; TLS 1.3 establishes the secure route only after agent configuration is
    ; complete.  Cache the validated fixed-size config buffers before that
    ; route reuses the old seed/TLS scratch.  Every later request reads only
    ; these reconnect-safe copies; this also fixes the ENV-restore path, whose
    ; first request may occur after the original seed buffers were overlaid.
    ; The product route is OpenAI-only.  Check that boundary here, while the
    ; selected-agent ID is still live, rather than trusting a later request
    ; phase whose seed/TLS aliases have already been retired.
    cld
    cmp word [seed_agent_id + 0], 'op'
    jne .product_failed
    cmp word [seed_agent_id + 2], 'en'
    jne .product_failed
    cmp word [seed_agent_id + 4], 'ai'
    jne .product_failed
    cmp byte [seed_agent_id + 6], 0
    jne .product_failed
    push ds
    pop es
    ; seed_key overlaps the destination cache band.  Copy it high-to-low
    ; before publishing the model; a forward copy would consume bytes it had
    ; just overwritten and silently corrupt credentials.
    std
    mov si, seed_key + seed_key_len - 1
    mov di, chat_key_cache + seed_key_len - 1
    mov cx, seed_key_len
    rep movsb
    cld
    mov si, seed_model
    mov di, chat_model_cache
    mov cx, seed_model_len
    rep movsb
    mov byte [chat_prompt_len_cache], 0
    clc
    ret
.product_failed:
    mov word [handoff_addr + handoff_net_status], 0xb613
    stc
    ret
%else
    ; On a reconnect (chat loop, handoff ready) the key/model are already cached
    ; from the cold connect, and api_request_plain now holds the ready-request
    ; layout (different key/model offsets), so re-parsing it fails (B6/06). The
    ; cache is still valid, so skip re-caching and keep the live prompt length.
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .done
    cmp byte [reconnect_retries], 3      ; reconnect: the cache is already valid from the cold connect's
    jb .done                              ; first attempt (seed_* is now handshake-clobbered) -- don't re-parse
    call .cache_key
    jc .failed
    call .cache_model
    jc .failed
    mov byte [chat_prompt_len_cache], 0
.done:
    clc
    ret
.failed:
    mov word [handoff_addr + handoff_net_status], 0xb606
    stc
    ret

.cache_key:
    mov si, api_request_plain + tls_record_header_len + api_request_key_value_offset
    mov di, chat_key_cache
    mov cx, seed_key_len - 1
.key_next:
    lodsb
    cmp al, 13
    je .key_done
    cmp al, 10
    je .key_done
    or al, al
    jz .cache_failed
    stosb
    loop .key_next
.key_done:
    xor al, al
    stosb
    clc
    ret

.cache_model:
    mov si, api_request_plain + tls_record_header_len
    mov cx, [tls_app_total_len]
.find_body:
    cmp cx, 4
    jb .cache_failed
    lodsb
    dec cx
    cmp al, 13
    jne .find_body
    cmp byte [si], 10
    jne .find_body
    cmp byte [si + 1], 13
    jne .find_body
    cmp byte [si + 2], 10
    jne .find_body
    add si, 3
    sub cx, 3
    cmp cx, api_request_model_value_offset
    jb .cache_failed
    add si, api_request_model_value_offset
    sub cx, api_request_model_value_offset
    mov di, chat_model_cache
    mov bx, seed_model_len - 2
.model_next:
    or cx, cx
    jz .cache_failed
    lodsb
    dec cx
    cmp al, '"'
    je .model_done
    cmp al, 13
    je .cache_failed
    cmp al, 10
    je .cache_failed
    or al, al
    jz .cache_failed
    stosb
    dec bx
    jnz .model_next
.model_done:
    xor al, al
    stosb
    clc
    ret
.cache_failed:
    stc
    ret
%endif

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
