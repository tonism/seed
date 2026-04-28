tcp_connect_target:
    call tcp_resolve_target_name
    jc .done
    call tcp_open_resolved_target
.done:
    ret

tcp_resolve_target_name:
    call ne_resolve_dns_arp
    jc .done
    cmp byte [handoff_addr + handoff_net_status], net_status_arp_resolved
    jne .failed
    call ne_transmit_dns_query
    jc .done
    call ne_wait_for_dns_response
    cmp byte [handoff_addr + handoff_net_status], net_status_dns_response_received
    jne .failed
    clc
    ret
.failed:
    stc
.done:
    ret

tcp_open_resolved_target:
    call ne_resolve_tcp_next_hop_arp
    jc .done
    cmp byte [handoff_addr + handoff_net_status], net_status_next_hop_arp_resolved
    jne .failed
    call ne_transmit_tcp_syn
    jc .done
    call ne_wait_for_tcp_synack
    cmp byte [handoff_addr + handoff_net_status], net_status_tcp_synack_received
    jne .failed
    call ne_transmit_tcp_ack
    jc .done
    cmp byte [handoff_addr + handoff_net_status], net_status_tcp_connected
    jne .failed
    clc
    ret
.failed:
    stc
.done:
    ret

tcp_receive_payload:
    mov word [ne_rx_read_limit], dhcp_rx_frame_len
    mov word [dhcp_wait_count], tcp_wait_count
.poll:
    call ne_try_receive_frame
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_tcp_payload
    jnc .done
.wait:
    mov cx, 2
    call wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_error], net_error_tcp
    stc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_tcp
    stc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_payload_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
