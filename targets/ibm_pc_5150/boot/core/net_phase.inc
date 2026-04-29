prepare_internet_path:
    call selected_nic_has_packet_path
    jnc .packet
    clc
    ret
.packet:
    push ds
    pop es
    call wd_enable_shared_ram
    call wd_select_dp8390_base
    call ne_transmit_dhcp_discover
    jc .done
    call ne_wait_for_dhcp_offer
    cmp byte [handoff_addr + handoff_net_status], net_status_dhcp_offer_received
    jne .failed
    call ne_transmit_dhcp_request
    jc .done
    call ne_wait_for_dhcp_ack
    cmp byte [handoff_addr + handoff_net_status], net_status_dhcp_ack_received
    jne .failed
    call set_default_internet_target
    call tcp_connect_target
    jc .failed
    clc
.done:
    pushf
    call wd_restore_dp8390_base
    popf
    ret
.failed:
    stc
    jmp .done

prepare_agent_path:
    call load_agents_cfg
    call load_user_cfg
    jnc .have_agent
    call ask_agent_setup
    jmp .values_ready
.have_agent:
    call ensure_seed_values
    jnc .values_ready
    call ask_agent_setup
.values_ready:
    call prepare_agent_endpoint_path
    jc .failed
    mov bl, [ready_attr]
    mov al, 'o'
    call show_load_marker
    cmp byte [user_cfg_dirty], 0
    je .ready
    call save_user_cfg
.ready:
    clc
    ret
.failed:
    stc
    ret

prepare_agent_endpoint_path:
    call set_agent_endpoint_target
    jc .failed
    call selected_nic_has_packet_path
    jnc .packet
.failed:
    stc
    ret
.packet:
    push ds
    pop es
    call wd_enable_shared_ram
    call wd_select_dp8390_base
    call tcp_connect_target
    jc .restore
    call tls_probe_server
.restore:
    pushf
    call wd_restore_dp8390_base
    popf
    ret

selected_nic_has_packet_path:
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_3c501
    je .yes
    cmp al, family_3c503
    je .yes
    cmp al, family_ne1000
    je .yes
    cmp al, family_ne2000
    je .yes
    cmp al, family_wd8003
    je .yes
    stc
    ret
.yes:
    clc
    ret

set_default_internet_target:
    call set_example_dns_target
    call load_net_probe_cfg
    jnc .done
    call set_example_dns_target
.done:
    mov word [tcp_dest_port_word], tcp_port_http_word
    clc
    ret

set_example_dns_target:
    mov si, dns_default_qname
    mov di, dns_qname
    mov cx, dns_qname_default_len
    rep movsb
    mov byte [dns_qname_len], dns_qname_default_len
    call update_dns_tx_len
    ret
