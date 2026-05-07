agent_api_exchange:
    mov byte [api_receive_tries], 8
.receive:
    call tls_receive_application_data
    jc .failed
    call run_agent_response_phase
    jnc .answer
    dec byte [api_receive_tries]
    jnz .receive
    jmp .failed
.answer:
    clc
    ret
.failed:
    stc
    ret
