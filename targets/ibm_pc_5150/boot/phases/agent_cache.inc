%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%define PHASE_LOAD_ADDR low_scratch_start
%define PHASE_LOAD_ADDR_DEFAULTED
%endif

agent_cache_phase:
    call .cache_key
    jc .failed
    call .cache_model
    jc .failed
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
    mov bx, seed_model_len - 1
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

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
