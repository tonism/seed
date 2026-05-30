; DRAFT - full bounded reconnect retry for prepare_agent_endpoint_path.
; OVERFLOWS the link window by ~15-20B as-is (net_phase shares the 0x3400 crypto
; ceiling). Apply ONLY after reclaiming ~15-20B in the crypto/tls region. Cold-safe
; (first attempt == cold connect); max_reconnect_retries=8. Logic validated; blocked
; only on byte budget. See notes/default-prompt-interface-attempts.md (2026-05-30).

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
max_reconnect_retries equ 8

prepare_agent_endpoint_path:
    call wd_enter_packet_path
    ; Universal reconnect loop. Each attempt (re)builds the request, ensures a working
    ; connection (reuse a live session, else reopen) and exchanges. An attempt that errors
    ; OR comes back with no rendered text (server dropped the idle keep-alive while the slow
    ; 8088 was busy, or the reconnect handshake raced Cloudflare's ~7.5s timeout) fails and
    ; we retry, bounded by max_reconnect_retries, then surface the last error cleanly. This
    ; covers render-idle, hours-long idle, and the cold boot handshake (the first attempt is
    ; the cold connect) with one mechanism. cx holds the attempt budget across phase calls
    ; via the stack.
    mov cx, max_reconnect_retries
.attempt:
    push cx
    call .ensure_and_exchange
    pop cx
    jnc .restore
    loop .attempt
    ; budget exhausted: net_status holds the last failure -> the caller shows the error.
.restore:
    pushf
    call wd_restore_dp8390_base
    popf
    ret

.ensure_and_exchange:
    ; (Re)build the request each attempt (a prior attempt's receive clobbers tls_app_len/
    ; total; api_request_plain itself survives). Build BEFORE loading the link window: the
    ; builder phase overlaps the crypto window, and the handshake never touches the rebuilt
    ; send-state afterward. One build site serves both reuse and reconnect.
    call_core_phase core_agent_request_phase_start, core_agent_request_phase_end
    jc .ee_fail
    load_core_window core_link_window_start, core_link_window_end
    jc .ee_fail
    ; Reuse a live TLS session (tls_key_schedule_ready==1, set only after a handshake)
    ; directly so short back-and-forth stays fast; otherwise reopen the connection first.
    cmp byte [tls_key_schedule_ready], 1
    je .ee_send
    call_core_phase core_agent_endpoint_phase_start, core_agent_endpoint_phase_end
    jc .ee_fail
    call_core_phase core_tls_client_hello_phase_start, core_tls_client_hello_phase_end
    jc .ee_fail
    call_core_phase core_agent_cache_phase_start, core_agent_cache_phase_end
    jc .ee_fail
    call run_tcp_connect_phase
    jc .ee_fail
    call tls_probe_server
    jc .ee_fail
.ee_send:
    ; One shared send for both reuse and reconnect. A follow-up that errors OR renders no
    ; text means the socket was stale / the handshake raced the timeout: mark the session
    ; dead and fail the attempt so the bounded retry reopens and resends. Carry alone marks
    ; the failure for the caller, so no separate net_status write is needed here.
    call .stream_and_exchange
    jc .ee_dead
    cmp byte [api_stream_text_seen], 0
    je .ee_dead
    clc
    ret
.ee_dead:
    mov byte [tls_key_schedule_ready], 0
.ee_fail:
    stc
    ret
.stream_and_exchange:
    call_core_phase_at core_agent_api_stream_phase_start, core_agent_api_stream_phase_end, net_setup_phase_start
    jc .se_done
    call agent_api_exchange
.se_done:
    ret
