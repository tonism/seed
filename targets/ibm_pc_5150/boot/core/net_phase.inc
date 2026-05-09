prepare_internet_path:
    call selected_nic_has_packet_path
    jnc .packet
    clc
    ret
.packet:
    push ds
    pop es
    call wd_enter_packet_path
    call_core_phase_at core_dhcp_setup_phase_start, core_dhcp_setup_phase_end, net_setup_phase_start
    jc .failed
    call_core_phase core_probe_cfg_phase_start, core_probe_cfg_phase_end
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
    call_core_phase core_agents_cfg_phase_start, core_agents_cfg_phase_end
    call_core_phase core_user_cfg_phase_start, core_user_cfg_phase_end
    jnc .values_ready
    call_core_phase core_agent_setup_phase_start, core_agent_setup_phase_end
.values_ready:
    call prepare_agent_endpoint_path
    jc .failed
    mov bl, [ready_attr]
    mov al, 'o'
    call show_load_marker
    cmp byte [user_cfg_dirty], 0
    je .ready
    call_core_phase core_save_phase_start, core_save_phase_end
.ready:
    clc
    ret
.failed:
    stc
    ret

prepare_agent_endpoint_path:
    call_core_phase core_agent_endpoint_phase_start, core_agent_endpoint_phase_end
    jc .failed
    call selected_nic_has_packet_path
    jnc .packet
.failed:
    stc
    ret
.packet:
    push ds
    pop es
    call wd_enter_packet_path
    call_core_phase core_agent_request_phase_start, core_agent_request_phase_end
    jc .restore
    load_core_window core_link_window_start, core_link_window_end
    jc .restore
    call_core_phase core_tls_client_hello_phase_start, core_tls_client_hello_phase_end
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
