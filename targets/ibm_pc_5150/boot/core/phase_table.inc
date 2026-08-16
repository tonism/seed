; Product phase metadata.  This table lives in otherwise-unused padding at the
; tail of the one-sector PCI-detect phase, keeping the header's 16-bit table
; offset valid when the large TLS 1.3 cold phase pack is inserted at sector 45.
; Runtime calls use assembler-derived keys directly; this remains inspection
; metadata and is harmless when the containing PCI phase is loaded.

    db 'K', 0
    dw (core_link_window_start - $$) / 512
    dw (core_link_window_end - core_link_window_start + 511) / 512
    dw core_link_window_start
    dw 0
    db 'F', 0
    dw (core_failure_phase_start - $$) / 512
    dw (core_failure_phase_end - core_failure_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'H', 0
    dw (core_hardware_setup_phase_start - $$) / 512
    dw (core_hardware_setup_phase_end - core_hardware_setup_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db '2', 0
    dw (core_driver_load_phase_start - $$) / 512
    dw (core_driver_load_phase_end - core_driver_load_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db '0', 0
    dw (core_ext_layout_phase_start - $$) / 512
    dw (core_ext_layout_phase_end - core_ext_layout_phase_start + 511) / 512
    dw high_crypto_scratch_start
    dw 0
    db 'Z', 0
    dw (core_unreal_setup_phase_start - $$) / 512
    dw (core_unreal_setup_phase_end - core_unreal_setup_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'I', 0
    dw (core_packet_io_init_phase_start - $$) / 512
    dw (core_packet_io_init_phase_end - core_packet_io_init_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'D', 0
    dw (core_dhcp_setup_phase_start - $$) / 512
    dw (core_dhcp_setup_phase_end - core_dhcp_setup_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'N', 0
    dw (core_ntp_setup_phase_start - $$) / 512
    dw (core_ntp_setup_phase_end - core_ntp_setup_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'C', 0
    dw (core_tcp_connect_phase_start - $$) / 512
    dw (core_tcp_connect_phase_end - core_tcp_connect_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'L', 0
    dw (core_tls_client_hello_phase_start - $$) / 512
    dw (core_tls_client_hello_phase_end - core_tls_client_hello_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'E', 0
    dw (core_agent_endpoint_phase_start - $$) / 512
    dw (core_agent_endpoint_phase_end - core_agent_endpoint_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'A', 0
    dw (core_agents_cfg_phase_start - $$) / 512
    dw (core_agents_cfg_phase_end - core_agents_cfg_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'U', 0
    dw (core_user_cfg_phase_start - $$) / 512
    dw (core_user_cfg_phase_end - core_user_cfg_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'Q', 0
    dw (core_agent_setup_phase_start - $$) / 512
    dw (core_agent_setup_phase_end - core_agent_setup_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'G', 0
    dw (core_context_mirror_phase_start - $$) / 512
    dw (core_context_mirror_phase_end - core_context_mirror_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'J', 0
    dw (core_ext_read_chunk_phase_start - $$) / 512
    dw (core_ext_read_chunk_phase_end - core_ext_read_chunk_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'R', 0
    dw (core_agent_request_phase_start - $$) / 512
    dw (core_agent_request_phase_end - core_agent_request_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'V', 0
    dw (core_agent_cache_phase_start - $$) / 512
    dw (core_agent_cache_phase_end - core_agent_cache_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'X', 0
    dw (core_agent_api_stream_phase_start - $$) / 512
    dw (core_agent_api_stream_phase_end - core_agent_api_stream_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'T', 0
    dw (core_agent_response_phase_start - $$) / 512
    dw (core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512
    dw agent_response_phase_load_addr
    dw 0
    db 'B', 0
    dw (core_splash_phase_start - $$) / 512
    dw (core_splash_phase_end - core_splash_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'Y', 0
    dw (core_dpi_phase_start - $$) / 512
    dw (core_dpi_phase_end - core_dpi_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'M', 0
    dw (core_tool_phase_start - $$) / 512
    dw (core_tool_phase_end - core_tool_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db '1', 0
    dw (core_tool_replay_prev_phase_start - $$) / 512
    dw (core_tool_replay_prev_phase_end - core_tool_replay_prev_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'O', 0
    dw (core_tool_memory_phase_start - $$) / 512
    dw (core_tool_memory_phase_end - core_tool_memory_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'S', 0
    dw (core_save_phase_start - $$) / 512
    dw (core_save_phase_end - core_save_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'P', 0
    dw (core_restore_env_phase_start - $$) / 512
    dw (core_restore_env_phase_end - core_restore_env_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'W', 0
    dw (core_save_prep_phase_start - $$) / 512
    dw (core_save_prep_phase_end - core_save_prep_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
