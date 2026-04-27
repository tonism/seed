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
    clc
    ret
.failed:
    stc
.done:
    ret
