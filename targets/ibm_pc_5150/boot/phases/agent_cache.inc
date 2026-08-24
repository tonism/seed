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
    ; Resolve the optional effort while seed_reasoning is still live. Missing
    ; means the current product default, xhigh. A configured value must exactly
    ; match one supported Responses effort; fixed 8-byte rows keep the check
    ; bounded and prevent config text from becoming unescaped JSON.
    mov bx, PHASE_LOAD_ADDR + (agent_cache_reasoning_xhigh - PHASE_BASE)
    test byte [seed_config_flags], seed_flag_reasoning
    jz .reasoning_ready
    mov bx, PHASE_LOAD_ADDR + (agent_cache_reasoning_values - PHASE_BASE)
    mov dx, agent_cache_reasoning_value_count
.reasoning_next:
    push bx
    mov si, seed_reasoning
    mov di, bx
    mov cx, seed_reasoning_len
    repe cmpsb
    pop bx
    je .reasoning_ready
    add bx, seed_reasoning_len
    dec dx
    jnz .reasoning_next
    jmp .product_failed
.reasoning_ready:
    ; seed_key overlaps the destination cache band.  Copy it high-to-low
    ; before publishing the model; a forward copy would consume bytes it had
    ; just overwritten and silently corrupt credentials.
    std
    mov si, seed_key + seed_key_len - 1
    mov di, chat_key_cache + seed_key_len - 1
    mov cx, seed_key_len
    rep movsb
    cld
    ; Publish the complete model/reasoning JSON tail here. R and X have only 8
    ; and 3 bytes of phase headroom; this one-sector phase has ample room and
    ; runs before TLS reuses the original config arena.
    mov si, seed_model
    mov di, chat_model_cache
    mov cx, chat_model_value_max_len + 1
.model_next:
    lodsb
    or al, al
    jz .model_done
    stosb
    loop .model_next
    jmp .product_failed
.model_done:
    mov si, PHASE_LOAD_ADDR + (agent_cache_reasoning_prefix - PHASE_BASE)
    call .append_fragment
    mov si, bx
    call .append_fragment
    mov ax, 0x7d22                   ; '"}' closes effort string + object
    stosw
    xor al, al
    stosb
    mov byte [chat_prompt_len_cache], 0
    clc
    ret
.append_fragment:
    lodsb
    or al, al
    jz .fragment_done
    stosb
    jmp .append_fragment
.fragment_done:
    ret
.product_failed:
    mov word [handoff_addr + handoff_net_status], 0xb613
    stc
    ret

agent_cache_reasoning_prefix db '","reasoning":{"effort":"', 0
agent_cache_reasoning_values:
agent_cache_reasoning_none   db 'none',   0, 0, 0, 0
agent_cache_reasoning_low    db 'low',    0, 0, 0, 0, 0
agent_cache_reasoning_medium db 'medium', 0, 0
agent_cache_reasoning_high   db 'high',   0, 0, 0, 0
agent_cache_reasoning_xhigh  db 'xhigh',  0, 0, 0
agent_cache_reasoning_max    db 'max',    0, 0, 0, 0, 0
agent_cache_reasoning_value_count equ 6
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
