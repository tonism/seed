%ifdef TLS13_PRODUCT_TLS13
; Product TLS 1.3 resident scheduler.  This entire conditional occupies the
; exact 333-byte extent of the retired TLS 1.2 scheduler (0x11f6..0x1342).
; K14's phase chain calls fixed resident callbacks, so the filesystem and NIC
; code below this include must remain at their established absolute addresses.
tls13_product_net_block_start:

prepare_internet_path:
    call [nic_vt_enter]
    run_net_phase core_dhcp_setup_phase_start, core_dhcp_setup_phase_end
    pushf
    call [nic_vt_restore]
    popf
    ret

prepare_agent_path:
    call_post_pack_core_phase core_agents_cfg_phase_start, core_agents_cfg_phase_end
    call_post_pack_core_phase core_user_cfg_phase_start, core_user_cfg_phase_end
    jnc .values_ready
    call_post_pack_core_phase core_agent_setup_phase_start, core_agent_setup_phase_end
.values_ready:
    cmp byte [user_cfg_dirty], 0
    je .config_saved
    call_post_pack_core_phase core_save_phase_start, core_save_phase_end
.config_saved:
    ; Cache validated OpenAI model/key state exactly once, before either route
    ; is allowed to reuse the old config/TLS scratch.
    call_post_pack_core_phase core_agent_cache_phase_start, core_agent_cache_phase_end
    jc .done
    call_post_pack_core_phase core_restore_env_phase_start, core_restore_env_phase_end
    jc prepare_agent_endpoint_path
.done:
    ret

prepare_agent_endpoint_path:
    ; The prompt buffer aliases receive scratch.  Preserve its length before a
    ; route or application receive can overwrite it.  A tool continuation uses
    ; the already-durable originating prompt and is never reconstructed/routed.
    mov al, [dpi_input_len_byte]
    cmp byte [agent_loop_pending], 0
    je .prompt_len_ready
    mov al, [chat_resend_prompt_len]
.prompt_len_ready:
    ; One bounded replay is permitted for this human turn.  A tool
    ; continuation still cannot reconnect: establish_route rejects it before
    ; any request rebuild or fresh send.
    mov ah, 1
    mov [chat_resend_prompt_len], ax

.pass:
    cmp byte [tls_key_schedule_ready], 1
    je .build
    ; A tool output is a non-replayable local side effect: if its live
    ; session died, return softly to DPI before entering the reconnect path.
    mov al, [tool_fc_state]
    or al, [agent_loop_pending]
    jz .establish
    stc
    ret
.establish:
    call tls13_product_establish_route
    jc .burn
.build:
    call .build_request
    jc .return
    load_core_window core_link_window_start, core_link_window_end
    jc .burn

    ; Load X without calling it.  K and X are both complete before the single
    ; application-data NIC lease begins.  X returns the response phase key in
    ; AX/BX for agent_api_exchange's first phase load.
    mov ax, post_pack_phase_key(core_agent_api_stream_phase_start, core_agent_api_stream_phase_end)
    mov bx, net_setup_phase_start
    call load_core_sectors_at
    jc .burn
    call [nic_vt_enter]
    ; Driver enter may clobber every GP register; X is at its fixed load
    ; address, so do not trust the pre-enter BX value here.
    call net_setup_phase_start
    jc .exchange_done
    call agent_api_exchange
.exchange_done:
    pushf
    call [nic_vt_restore]
    popf
    jc .burn
    test byte [compacting_msg], 0xff
    jnz .pass
    ret
.burn:
    ; The ready byte is the capability gate, but retire the complete published
    ; TLS 1.3 application state as well: failed records and failed route
    ; finalization must not leave a later path able to reuse old keys/IVs/seqs.
    push es
    push ds
    pop es
    cld
    xor ax, ax
    mov di, tls_client_write_key
    mov cx, (tls_server_record_seq + tls_server_record_seq_len - tls_client_write_key) / 2
    rep stosw
    pop es
    mov [tls_key_schedule_ready], al
    stc
    ; The first no-text failure burns the old capability then rebuilds the
    ; same durable human request on one fresh route.  DEC preserves the carry
    ; set above, so exhaustion returns CF=1.  K's text-seen fallback forces
    ; this counter to zero before entering the retirement leaf.
    dec byte [reconnect_retries]
    jz .pass
.return:
    ret

; K's streamed-answer fallback calls the same resident retirement leaf, then
; deliberately converts its carry back to success after preserving the text.
tls13_product_retire_app_state equ prepare_agent_endpoint_path.burn

.build_request:
    cmp word [far_log_seg_var], 0
    je .request
    call_post_pack_core_phase core_context_mirror_phase_start, core_context_mirror_phase_end
.request:
    call_post_pack_core_phase core_agent_request_phase_start, core_agent_request_phase_end
    ret

; Establish exactly one tier route.  The caller has already rejected
; non-replayable tool/agent-loop continuations, so every failure here can
; return normally into the bounded human-turn reconnect loop.
tls13_product_establish_route:
    call tls13_product_route_mode
    push ax
    sub [dpi_reached], al
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jnz tls13_product_establish_286

    ; The 8088 root now owns only conventional RAM.  There is no hidden video
    ; state to snapshot or restore around it, so enter the root directly.
    mov ax, TLS13_K14_PRODUCT_ROOT_PHASE_KEY
    mov bx, TLS13_K14_PRODUCT_ROOT_DESTINATION
    call load_core_sectors_at
    jc .root_load_failed
    pop ax
    call TLS13_K14_PRODUCT_ROOT_ENTRY
    pushf
    call [nic_vt_restore]
    ; Root success publishes READY=1, while its disk-independent abort returns
    ; with READY=0.  Keep the capability hidden until the root return itself
    ; has committed.
    mov byte [tls_key_schedule_ready], 0
    popf
    jc .restore_dpi_failed
    inc byte [tls_key_schedule_ready]
    jmp tls13_product_route_mode

.root_load_failed:
    pop ax                              ; discard saved route mode
.restore_dpi_failed:
    call tls13_product_route_mode
.failed:
    stc
    ret

tls13_product_establish_286:
    ; The 286 bootstrap reuses 0500..05ff for its low immutable constants.
    ; Freeze the existing-read sampler before that publication so later
    ; required phase reads cannot append into the replaced corpus.
    mov byte [tls13_entropy_read_sample_frozen], 0xa5
    ; N revalidates the 286/512 KiB gates and silently publishes a fresh,
    ; coherent platform-UTC BIOS RTC value. Failure is indistinguishable from
    ; any other unavailable secure route; there is no interactive clock gate.
    run_net_phase core_ntp_setup_phase_start, core_ntp_setup_phase_end
    jc tls13_product_establish_route.root_load_failed
    mov ax, TLS13_286_PRODUCT_ROOT_PHASE_KEY
    mov bx, TLS13_286_PRODUCT_ROOT_DESTINATION
    call load_core_sectors_at
    ; Discard the saved endpoint mode only after the BDA gate and phase load.
    ; POP preserves the loader's carry.  On success the 286 controller is a
    ; true tail call: it owns the one NIC enter/restore lease, DPI restoration,
    ; app-state retirement, and final CF return to our original caller.
    pop ax
    jc tls13_product_establish_route.restore_dpi_failed
    ; N also returns DI at the publication base for its phase contract, but
    ; the bootstrap reads that fixed low address directly and does not trust
    ; a register across the intervening disk load.
    jmp TLS13_286_PRODUCT_ROOT_ENTRY

; Append one raw PIT-channel-0 phase byte after each successful BIOS sector
; read.  The low byte at 05fe is the sample count; the high byte is a freeze
; marker.  A count of 120 or a nonzero marker makes the unsigned word >=120,
; so one comparison enforces both the capacity and the one-shot lifetime.
;
; Entry is a tail jump from read_abs_sector with its saved CX/AX still on the
; stack and BIOS CF live.  Return is byte-for-byte equivalent to the old tail.
tls13_entropy_note_disk_read:
    jc .done
    push bx
    mov bx, [tls13_entropy_read_sample_count]
    cmp bx, tls13_entropy_read_sample_capacity
    jae .restore_bx
    mov al, 0
    out 0x43, al
    in al, 0x40
    mov [bx + tls13_entropy_read_samples], al
    inc byte [tls13_entropy_read_sample_count]
    clc                                 ; preserve the successful BIOS result
.restore_bx:
    pop bx
.done:
    pop cx
    pop ax
    ret

tls13_product_net_block_end:
%if (tls13_product_net_block_end - tls13_product_net_block_start) > 333
%error "TLS 1.3 product scheduler exceeds the fixed 333-byte resident net block"
%endif
times 333 - (tls13_product_net_block_end - tls13_product_net_block_start) db 0

%else
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
    ; Build 12 env save/load (step 3): before the cold greeting, try to restore a saved environment
    ; from the boot drive. CF=0 => the conversation window is populated; skip the greeting entirely
    ; (ret to main, which sets status ready + enters chat_loop; the user's first prompt does the cold
    ; handshake carrying the restored window). CF=1 (no/invalid ENV.DAT, or a load failure) => fall
    ; through to the normal greeting. Restore is a READ, so it is not gated on writeability. Runs
    ; ONLY on this cold-boot fall-through, never on the per-turn chat_loop call below. (Funded by the
    ; build_tcp_segment_frame golf in net_tx.inc -- the nucleus was exactly full.)
    call_core_phase core_restore_env_phase_start, core_restore_env_phase_end
    jc prepare_agent_endpoint_path
    ret
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
    cmp byte [agent_loop_pending], 0
    je .prompt_len_ready
    mov al, [chat_resend_prompt_len]
.prompt_len_ready:
    mov ah, 3
    mov [chat_resend_prompt_len], ax
.pass:
    ; Build 11 #4 real compaction: 2-pass loop target. Pass 1 is the compaction summarize exchange
    ; (only if agent_request finds the window >= 75% and sets compacting_msg); pass 2 is the real
    ; turn. agent_request re-decides per pass off chat_context_used, so after the summary shrinks the
    ; window below 75% the loop naturally falls through to the real turn and exits. The clean
    ; prompt-len capture above runs ONCE (the compaction receive clobbers dpi_input_len_byte, which
    ; aliases the RX buffer), and reconnect_retries is intentionally shared across both passes.
    call .build_request
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
    call .build_request
    jc .restore
.connect_new_session:
    call_core_phase core_agent_endpoint_phase_start, core_agent_endpoint_phase_end
    jc .retry
    call_core_phase core_tls_client_hello_phase_start, core_tls_client_hello_phase_end
    jc .retry
    call_core_phase core_agent_cache_phase_start, core_agent_cache_phase_end
    jc .retry
    ; auto-recertify (286-only): re-adopt the recertified leaf + reset the leaf-capture cursor BEFORE
    ; tcp_connect, so the ~3.3s rsa_adopt_derive (R^2 mod N for the new modulus) runs OFF the server's
    ; handshake window -- before the SYN -- NOT between the SYN-ACK and the ClientHello. Wire-confirmed
    ; @6: with the re-adopt in-window the ClientHello left at +3.3s and the client Finished at +16.6s,
    ; ~1.6s past Cloudflare's ~15s window (server FIN at +15.0s -> recertify failed); off-window the
    ; ClientHello is prompt and the Finished lands inside the window -> the server completes -> greet.
    ; (tls_client_hello above reloaded the module, reverting the pin to the baked one; restore the
    ; chain-verified leaf here so the handshake's SKE verify passes. On 8088 the module is absent -> skip;
    ; the cap_reset gives the drain's capture hooks a clean cursor + dest buffer before tls_probe.)
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .cap_reset_done
    cmp byte [recert_flag], 0
    je .no_readopt
    mov si, [recert_mod_ptr]
    call word [p256_ep_adopt_leaf]
.no_readopt:
    mov di, leaf_capture_buf
    call word [p256_ep_capture_reset]
.cap_reset_done:
    run_net_phase core_tcp_connect_phase_start, core_tcp_connect_phase_end
    jc .retry
    call tls_probe_server
    jc .retry
    ; Do NOT reset tls_app_len here: agent_request (above) already rebuilt the send-state,
    ; and the handshake never touches tls_app_len/total (only the app-data receive does,
    ; tls.inc:916-918). Zeroing it made an inline follow-up (chat_prompt_len_cache=0) send
    ; nothing on reconnect -> the prompt returned with no answer. The cold first request
    ; does not use tls_app_len here, so leaving it set is harmless for cold.
    call .stream_and_exchange
    jnc .pass_done
    jmp .retry_dec
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
    mov byte [recert_flag], 2
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
    jmp agent_api_exchange
.se_done:
    ret
.build_request:
    cmp word [far_log_seg_var], 0
    je .br_request
    call_core_phase core_context_mirror_phase_start, core_context_mirror_phase_end
.br_request:
    call_core_phase core_agent_request_phase_start, core_agent_request_phase_end
.br_done:
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
%endif
