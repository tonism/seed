prepare_internet_path:
    call wd_enter_packet_path
    call_core_phase_at core_dhcp_setup_phase_start, core_dhcp_setup_phase_end, net_setup_phase_start
    ; DHCP is the whole internet bring-up now. The old port-80 connectivity probe + its NET.CFG
    ; parse (probe_cfg) were removed (Build 11): they were a single-shot, un-retried connect to
    ; example.com that (a) was the dominant spotty-network boot failure, (b) could FALSE-FAIL when
    ; the agent host was reachable but the probe host was not, and (c) duplicated the real test --
    ; the agent connect (port 443) already proves connectivity and is wrapped in the shared 3x
    ; reconnect retry. DHCP's CF propagates through .restore to network_setup_error.
    jmp prepare_agent_endpoint_path.restore

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
    ; Capture the prompt length durably BEFORE any receive. dpi_input_len_byte (and dpi_input_buf)
    ; alias tls_rx_copy, the TLS receive buffer, so a reconnect's dead-socket/cert receives
    ; clobber them. chat_resend_prompt_len lives in the resident nucleus (data.inc) so neither a
    ; receive nor load_core_window's link reload touches it; agent_request restores the prompt
    ; from the screen using it on a reconnect rebuild.
    ; Build 11 never-blank: init the 3x reconnect-retry counter in the SAME word write. reconnect_retries
    ; sits at chat_resend_prompt_len+1 in the reconnect_state_* block, so al (prompt len) and ah (3
    ; retries) land together -- the standalone "mov byte [reconnect_retries],3" the full nucleus had no
    ; room for. Counts attempts for the cold connect AND every reconnect; the endpoint phase reads it.
    mov al, [dpi_input_len_byte]
    mov ah, 3
    mov [chat_resend_prompt_len], ax
    call_core_phase core_agent_request_phase_start, core_agent_request_phase_end
    jc .restore
    load_core_window core_link_window_start, core_link_window_end
    jc .restore
    ; tls_key_schedule_ready==1 means a live TLS session (only set after a handshake,
    ; boot-cleared) so it already excludes the first request. Try to REUSE the live session
    ; first: the keep-alive holds it open through long renders, so an engaged session (incl.
    ; post-long) reuses snappily. If the exchange fails (an hours-long idle closed the socket),
    ; rebuild the request and reopen. The rebuild's agent_request restores the prompt durably
    ; from the screen (via the resident chat_resend_prompt_len), so the resend is correct.
    ; (Handoff-validated reuse->reconnect->resend; the probe-first speedup overflows the byte
    ; wall by ~2B and is deferred - reuse-on-a-dead-socket still reconnects, just less snappily.)
    cmp byte [tls_key_schedule_ready], 1
    jne .connect_new_session
    call .stream_and_exchange
    jnc .restore
.rebuild_and_connect:
    call_core_phase core_agent_request_phase_start, core_agent_request_phase_end
    jc .restore
.connect_new_session:
    call_core_phase core_agent_endpoint_phase_start, core_agent_endpoint_phase_end
    jc .retry
    call_core_phase core_tls_client_hello_phase_start, core_tls_client_hello_phase_end
    jc .retry
    call_core_phase core_agent_cache_phase_start, core_agent_cache_phase_end
    jc .retry
    call run_tcp_connect_phase
    jc .retry
    call tls_probe_server
    jc .retry
    ; Do NOT reset tls_app_len here: agent_request (above) already rebuilt the send-state,
    ; and the handshake never touches tls_app_len/total (only the app-data receive does,
    ; tls.inc:916-918). Zeroing it made an inline follow-up (chat_prompt_len_cache=0) send
    ; nothing on reconnect -> the prompt returned with no answer. The cold first request
    ; does not use tls_app_len here, so leaving it set is harmless for cold.
    call .stream_and_exchange
    jnc .restore
.retry:
    ; Build 11 never-blank: this connect attempt failed (handshake phase OR the exchange). Silently
    ; retry the whole rebuild+connect up to 3x. The endpoint phase draws the single dim "> reconnect"
    ; line on the FIRST reconnect attempt (gated on reconnect_retries==3 + a live prior session) and
    ; appends " failed" once the counter reaches 0. On exhaustion, re-run the endpoint phase ONCE so
    ; it renders that "failed" tail, then fall through to .restore (back to DPI). The user's next
    ; prompt re-inits reconnect_retries=3 (the word write above) and runs the same loop again.
    dec byte [reconnect_retries]
    jnz .rebuild_and_connect
    call_core_phase core_agent_endpoint_phase_start, core_agent_endpoint_phase_end
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
