agent_api_exchange:
.receive:
    call tls_receive_application_data
    jc .failed
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_ne2000
    je .maybe_render_before_ack
    cmp al, family_ne1000
    je .maybe_render_before_ack
.ack_before_render:
    call ne_transmit_tcp_ack
    jc .failed
    call agent_response_phase_load_addr
    jmp .check_complete
.maybe_render_before_ack:
    cmp byte [api_stream_text_seen], 0
    je .ack_before_render
    call agent_response_phase_load_addr
    call ne_transmit_tcp_ack
    jc .failed
.check_complete:
    cmp byte [api_stream_completed], 3
    jnz .receive
.success:
    call tls_clear_buffered_payload
    clc
    ret
.failed:
    cmp byte [api_stream_completed], 2
    jae .success
    stc
    ret
