agent_api_exchange:
    mov byte [api_receive_tries], 80
    mov ax, (((core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512) << 8) | ((core_agent_response_phase_start - $$) / 512)
    mov bx, ne_prom
    call load_core_sectors_at
    jc .failed
.receive:
    call tls_receive_application_data
    jc .retry
    call ne_prom
    jnc .answer
.retry:
    dec byte [api_receive_tries]
    jnz .receive
.failed:
    stc
.answer:
    ret
