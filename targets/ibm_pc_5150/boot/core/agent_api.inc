agent_api_exchange:
.receive:
    call tls_receive_application_data
    jc .failed
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_3c501
    jbe .maybe_render_before_ack
.ack_before_render:
    call ne_transmit_tcp_ack
    jc .failed
    call agent_response_phase_load_addr
    jmp .check_complete
.maybe_render_before_ack:
    cmp byte [api_stream_text_seen], 0
    je .ack_before_render
.render_before_ack:
    call agent_response_phase_load_addr
    call ne_transmit_tcp_ack
    jc .failed
.check_complete:
    ; 3c503 reuses the live keep-alive TLS session like the NE family and waits
    ; for true transport completion (zero chunk / close_notify). The deeper
    ; 3c503 long blocker is intermittent completion-detection in multi-large
    ; -record trailers - see notes/nic_timing_lanes.md.
    cmp byte [api_stream_completed], 3
    jne .receive
.success:
    jmp tls_clear_buffered_payload
.failed:
    mov byte [handoff_addr + handoff_net_status], 0xf0
    cmp byte [api_stream_completed], 2
    jae .success
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_3c501
    je .text_seen_fallback
    jmp .hard_failed
.text_seen_fallback:
    cmp byte [api_stream_text_seen], 0
    je .hard_failed
    mov byte [tls_key_schedule_ready], 0
    jmp .success
.hard_failed:
    stc
    ret
