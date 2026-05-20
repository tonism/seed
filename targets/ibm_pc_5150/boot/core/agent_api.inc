agent_api_exchange:
.receive:
    call tls_receive_application_data
    jc .failed
    call agent_response_phase_load_addr
    cmp byte [api_stream_completed], 3
    jnz .receive
.success:
    call tls_clear_buffered_payload
    clc
    ret
.failed:
    cmp byte [api_stream_completed], 2
    je .success
    stc
    ret
