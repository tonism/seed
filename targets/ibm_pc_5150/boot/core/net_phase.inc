prepare_internet_path:
    call wd_enter_packet_path
    call_core_phase_at core_dhcp_setup_phase_start, core_dhcp_setup_phase_end, net_setup_phase_start
    jc .done
    call_core_phase core_probe_cfg_phase_start, core_probe_cfg_phase_end
    jc .done
    mov word [tcp_dest_port_word], tcp_port_http_word
    call run_tcp_connect_phase
.done:
    pushf
    call wd_restore_dp8390_base
    popf
    ret

prepare_agent_path:
    call_core_phase core_agents_cfg_phase_start, core_agents_cfg_phase_end
    call_core_phase core_user_cfg_phase_start, core_user_cfg_phase_end
    jnc .values_ready
    call_core_phase core_agent_setup_phase_start, core_agent_setup_phase_end
.values_ready:
    cmp byte [user_cfg_dirty], 0
    je .config_saved
    call_core_phase core_save_phase_start, core_save_phase_end
.config_saved:
    call prepare_agent_endpoint_path
    jc .failed
.ready:
    clc
    ret
.failed:
    stc
    ret

prepare_agent_endpoint_path:
    call wd_enter_packet_path
    call_core_phase_at core_agent_request_phase_start, core_agent_request_phase_end, net_setup_phase_start
    jc .restore
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .link_loaded
    call_core_phase core_agent_endpoint_phase_start, core_agent_endpoint_phase_end
    jc .restore
.link_loaded:
    load_core_window core_link_window_start, core_link_window_end
    jc .restore
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    jne .connect_new_session
    call tls_send_application_data_current_seq
    jc .restore
    jmp .stream_body
.connect_new_session:
    call_core_phase core_tls_client_hello_phase_start, core_tls_client_hello_phase_end
    jc .restore
    call run_tcp_connect_phase
    jc .restore
    call_core_phase core_agent_cache_phase_start, core_agent_cache_phase_end
    jc .restore
    call tls_probe_server
    jc .restore
.stream_body:
    call_core_phase_at core_agent_api_stream_phase_start, core_agent_api_stream_phase_end, net_setup_phase_start
    jc .restore
.exchange:
    call agent_api_exchange
.restore:
    pushf
    call wd_restore_dp8390_base
    popf
    ret
