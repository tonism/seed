agent_api_exchange:
    mov byte [api_receive_tries], 16
.receive:
    call tls_receive_application_data
    jc .retry
    call_core_phase_at core_agent_response_phase_start, core_agent_response_phase_end, low_scratch_start
    jnc .answer
.retry:
    dec byte [api_receive_tries]
    jnz .receive
.failed:
    stc
.answer:
    ret
