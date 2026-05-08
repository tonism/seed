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
    call run_dhcp_setup_phase
    jc .failed
    call run_net_probe_cfg_phase
    jc .failed
    mov word [tcp_dest_port_word], tcp_port_http_word
    call run_tcp_connect_phase
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
    call run_agents_cfg_phase
    call run_user_cfg_phase
    jnc .values_ready
    call run_agent_setup_phase
.values_ready:
    call prepare_agent_endpoint_path
    jc .failed
    mov bl, [ready_attr]
    mov al, 'o'
    call show_load_marker
    cmp byte [user_cfg_dirty], 0
    je .ready
    call run_save_user_cfg_phase
.ready:
    clc
    ret
.failed:
    stc
    ret

prepare_agent_endpoint_path:
    call run_agent_endpoint_phase
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
    call run_agent_request_phase
    jc .restore
    call run_tls_client_hello_phase
    jc .restore
    call run_tcp_connect_phase
    jc .restore
    call tls_probe_server
    jc .restore
    call agent_api_exchange
.restore:
    pushf
    call wd_restore_dp8390_base
    popf
    ret

selected_nic_has_packet_path:
    mov al, [handoff_addr + handoff_nic_family]
    dec al
    cmp al, family_wd8003 - 1
    jbe .yes
    stc
    ret
.yes:
    clc
    ret
