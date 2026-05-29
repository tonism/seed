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
prepare_agent_endpoint_path:
    call wd_enter_packet_path
    call_core_phase core_agent_request_phase_start, core_agent_request_phase_end
    jc .restore
    load_core_window core_link_window_start, core_link_window_end
    jc .restore
    ; tls_key_schedule_ready==1 means a live TLS session (only set after a handshake,
    ; boot-cleared) so it already excludes the first request. Try to REUSE the live
    ; session first so short back-and-forth stays fast. If the exchange fails, the
    ; server most likely closed the idle keep-alive socket while the slow 8088 was
    ; busy rendering a long answer, so fall through, reopen, and retry once.
    cmp byte [tls_key_schedule_ready], 1
    jne .connect_new_session
    call .stream_and_exchange
    jnc .restore
    ; Reuse failed: the long answer's TLS receive reuses tls_app_len/total for the
    ; received records, so the request send-state is gone (api_request_plain itself
    ; is intact). Rebuild the request from the prompt before reopening + resending.
    call_core_phase core_agent_request_phase_start, core_agent_request_phase_end
    jc .restore
.connect_new_session:
    call_core_phase core_agent_endpoint_phase_start, core_agent_endpoint_phase_end
    jc .restore
    call_core_phase core_tls_client_hello_phase_start, core_tls_client_hello_phase_end
    jc .restore
    call_core_phase core_agent_cache_phase_start, core_agent_cache_phase_end
    jc .restore
    call run_tcp_connect_phase
    jc .restore
    call tls_probe_server
    jc .restore
    mov word [tls_app_len], 0
    call .stream_and_exchange
.restore:
    pushf
    call wd_restore_dp8390_base
    popf
    ret
.stream_and_exchange:
    call_core_phase_at core_agent_api_stream_phase_start, core_agent_api_stream_phase_end, net_setup_phase_start
    jc .se_done
    call agent_api_exchange
.se_done:
    ret
