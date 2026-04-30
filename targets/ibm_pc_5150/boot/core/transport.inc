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
    call ne_flush_receive_frames
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

ne_flush_receive_frames:
    mov word [ne_rx_read_limit], ne_rx_sample_len
    mov cx, 8
.next:
    push cx
    call ne_try_receive_frame
    pop cx
    jc .done
    cmp word [ne_rx_sample_count], 0
    je .done
    loop .next
.done:
    clc
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
    ; Keep this distinct from dhcp_rx_frame_len, which enables the DHCP prefix filter.
    mov word [ne_rx_read_limit], tcp_payload_read_len
    mov word [dhcp_wait_count], tcp_payload_wait_count
.poll:
    call ne_try_receive_frame
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_tcp_payload
    jnc .done
    call tcp_parse_3c501_second_frame
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

tcp_parse_3c501_second_frame:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .failed
    ; In coalesced 3c501 reads, the TLS data can follow a padded 60-byte ACK.
    cmp word [ne_rx_sample_count], 60 + tcp_offset + 20 + 5
    jb .failed
    mov cx, [ne_rx_sample_count]
    sub cx, 60
    mov [ne_rx_sample_count], cx
    mov si, ne_tx_frame + 60
    mov di, ne_tx_frame
    rep movsb
    call parse_tcp_payload
    ret
.failed:
    stc
    ret
