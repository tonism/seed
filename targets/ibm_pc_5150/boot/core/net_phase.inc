prepare_internet_path:
    call [nic_vt_enter]
    run_net_phase core_dhcp_setup_phase_start, core_dhcp_setup_phase_end
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
    call [nic_vt_enter]
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
.pass:
    ; Build 11 #4 real compaction: 2-pass loop target. Pass 1 is the compaction summarize exchange
    ; (only if agent_request finds the window >= 75% and sets compacting_msg); pass 2 is the real
    ; turn. agent_request re-decides per pass off chat_context_used, so after the summary shrinks the
    ; window below 75% the loop naturally falls through to the real turn and exits. The clean
    ; prompt-len capture above runs ONCE (the compaction receive clobbers dpi_input_len_byte, which
    ; aliases the RX buffer), and reconnect_retries is intentionally shared across both passes.
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
    jnc .pass_done
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
    run_net_phase core_tcp_connect_phase_start, core_tcp_connect_phase_end
    jc .retry
    ; auto-recertify: reset the leaf-capture cursor before the handshake (286-only; the secure module
    ; is loaded by tls_client_hello above, so the drain's capture hooks have a clean cursor + the dest
    ; buffer). On 8088 the module is absent -> skip (the drain's trampoline also no-ops there).
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .cap_reset_done
    ; re-install a recertified leaf: tls_client_hello above reloaded the module, reverting the pin to
    ; the baked one; restore the chain-verified leaf so this handshake's SKE verify passes.
    cmp byte [recert_flag], 0
    je .no_readopt
    mov si, [recert_mod_ptr]
    call word [p256_ep_adopt_leaf]
.no_readopt:
    mov di, leaf_capture_buf
    call word [p256_ep_capture_reset]
.cap_reset_done:
    call tls_probe_server
    jc .retry
    ; Do NOT reset tls_app_len here: agent_request (above) already rebuilt the send-state,
    ; and the handshake never touches tls_app_len/total (only the app-data receive does,
    ; tls.inc:916-918). Zeroing it made an inline follow-up (chat_prompt_len_cache=0) send
    ; nothing on reconnect -> the prompt returned with no answer. The cold first request
    ; does not use tls_app_len here, so leaving it set is harmless for cold.
    call .stream_and_exchange
    jnc .pass_done
.retry:
    ; Build 11 never-blank: this connect attempt failed (handshake phase OR the exchange). Silently
    ; retry the whole rebuild+connect up to 3x. The endpoint phase draws the single dim "> reconnect"
    ; line on the FIRST reconnect attempt (gated on reconnect_retries==3 + a live prior session) and
    ; appends " failed" once the counter reaches 0. On exhaustion, re-run the endpoint phase ONCE so
    ; it renders that "failed" tail, then fall through to .restore (back to DPI). The user's next
    ; prompt re-inits reconnect_retries=3 (the word write above) and runs the same loop again.
    ; --- auto-recertify (286 secure path) -------------------------------------------------------
    ; A rotated leaf makes the in-race pin verify fail. Off the race (we're between handshakes, no
    ; socket held), verify the leaf captured during this attempt's cert-drain chains to the PINNED
    ; WR1, and if so adopt it as the new pin -- the retry below then re-handshakes against it and
    ; passes. recertify_prep returns CF=1 when no leaf was captured (a pre-cert failure) -> normal
    ; retry. FAIL CLOSED: a leaf that does not chain to WR1 is NOT adopted (-> normal retry -> the
    ; eventual reconnect-failed). The TBS SHA-256 runs in the resident K window (loaded, since a
    ; captured leaf means the cert-drain ran); the hash parks in high_crypto_work (dead here).
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .retry_dec
    call word [p256_ep_recertify_prep]              ; parse the captured leaf -> result block; CF=1 = none/bad
    jc .retry_dec
    call sha256_init
    mov si, [p256_x509_result_tbs_ptr]
    mov cx, [p256_x509_result_tbs_len]
    call sha256_update
    mov di, high_crypto_work
    call sha256_finish
    mov si, [p256_x509_result_sig_ptr]
    mov di, high_crypto_work
    call word [p256_ep_chain_verify_sig]            ; leaf sig chains to WR1?  CF=1 = no -> fail closed
    jc .retry_dec
    ; The leaf is genuine. Don't adopt now -- the retry below reloads the module (reverting the pin).
    ; Save the verified modulus pointer + flag; the pre-tls_probe re-adopt installs it after the reload.
    mov ax, [p256_x509_result_mod_ptr]
    mov [recert_mod_ptr], ax
    mov byte [recert_flag], 1
.retry_dec:
    dec byte [reconnect_retries]
    jnz .rebuild_and_connect
    call_core_phase core_agent_endpoint_phase_start, core_agent_endpoint_phase_end
    jmp .restore                      ; retries exhausted: "failed" rendered; exit, skipping the loop-back
.pass_done:                           ; reached ONLY after a successful exchange (both jnc above, CF=0)
    ; Use TEST not CMP: TEST clears CF, so the normal-turn fall-through to .restore keeps the
    ; exchange's CF=0 (a success return). CMP byte,1 BORROWS on compacting_msg==0 -> CF=1 -> .restore
    ; (pushf/popf) returns failure though the exchange succeeded (greeting renders, yet "agent setup
    ; failed"). ZF=0 (compacting_msg nonzero) means a compaction summarize just finished -> loop.
    test byte [compacting_msg], 0xff
    jnz .pass                         ; compaction summarize done -> loop for the real turn
.restore:
    pushf
    call [nic_vt_restore]
    popf
    ret
.stream_and_exchange:
    run_net_phase core_agent_api_stream_phase_start, core_agent_api_stream_phase_end
    jc .se_done
    call agent_api_exchange
.se_done:
    ret

; secure_capture_chunk -- resident 286-gated trampoline so the K-window cert-drain can fold one
; fragment into the captured leaf with a bare near call. The leaf capture lives in the 286-only
; secure module (not loaded on the 8088 path), so calling its entry directly from the SHARED drain
; would crash on the 8088; this gate makes it a no-op there. in: SI=fragment, CX=len. Preserves all
; registers (the module's capture_leaf_chunk does), so the drain's SI/CX/AX survive the call.
secure_capture_chunk:
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .scc_ret
    call word [p256_ep_capture_chunk]
.scc_ret:
    ret
