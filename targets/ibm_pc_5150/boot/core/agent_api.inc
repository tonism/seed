agent_api_exchange:
    mov byte [api_receive_tries], 8
.receive:
    call tls_receive_application_data
    jc .failed
    call_core_phase_at core_agent_response_phase_start, core_agent_response_phase_end, fs_sector_buffer
    jnc .answer
    dec byte [api_receive_tries]
    jnz .receive
.failed:
    stc
    ret
.answer:
    clc
    ret
