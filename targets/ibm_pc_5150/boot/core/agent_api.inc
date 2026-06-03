agent_api_exchange:
.receive:
    call tls_receive_application_data
    jc .failed
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_3c501
    jbe .maybe_render_before_ack
.ack_before_render:
    call ne_transmit_tcp_ack
    jc .failed
    call agent_response_phase_load_addr
    jmp .check_complete
.maybe_render_before_ack:
    cmp byte [api_stream_text_seen], 0
    je .ack_before_render
.render_before_ack:
    call agent_response_phase_load_addr
    call ne_transmit_tcp_ack
    jc .failed
.check_complete:
    ; 3c503 reuses the live keep-alive TLS session like the NE family and waits
    ; for true transport completion (zero chunk / close_notify). The deeper
    ; 3c503 long blocker is intermittent completion-detection in multi-large
    ; -record trailers - see docs/networking.md.
    cmp byte [api_stream_completed], 3
    jne .receive
.success:
    ; A completed exchange that rendered no text (server dropped the keep-alive on a reuse,
    ; or a reconnect handshake raced the timeout and the request hit a dead socket) returns
    ; carry, so the caller's existing reuse-fail -> reopen -> resend path recovers it instead
    ; of handing the user an empty answer. Real responses (text_seen!=0) still return nc; the
    ; buffer is cleared either way. cmp against 0 never sets CF, so the non-empty ret is nc.
    ; Drain keep-alive responses pipelined behind the answer during a long render (each GET
    ; ping yields a ~1-record 401/421). They MUST be consumed here so the TLS server-record
    ; sequence stays aligned: otherwise the next prompt's probe/receive reads a stale 421
    ; frame and desyncs the cipher. Bounded by pings actually sent; each receive waits for
    ; its already-queued response (no extra idle timeout). ne_transmit_tcp_ack lets the
    ; server flush them. Under-drain self-heals via the reuse->reconnect path.
    mov cl, [ka_sent_count]
    xor ch, ch
    mov byte [ka_sent_count], 0
    jcxz .drained
.drain_one:
    push cx
    call ne_transmit_tcp_ack
    jc .drain_stop
    call tls_receive_application_data
.drain_stop:
    pop cx
    jc .drained
    loop .drain_one
.drained:
    call tls_clear_buffered_payload
    cmp byte [api_stream_text_seen], 0
    je .hard_failed
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], 0xf0
    cmp byte [api_stream_completed], 2
    jae .success
    ; All NICs: a receive/ack failure after text rendered means the answer streamed but the
    ; transport-completion marker was missed (or it cut mid-answer). Accept what rendered and
    ; invalidate the session (clean fresh connect next prompt) instead of reconnecting
    ; mid-exchange into the ~15s handshake race -- the reconnect was the flaky path, and a
    ; truncated-but-clean answer + the user's reliable re-prompt beats a failure screen. A wire
    ; capture confirmed long-render fails are completion-marker misses with the FULL answer
    ; already delivered+rendered. (Was family_3c501-only -- which is why 3c501 went 4/4 on long
    ; while the other NICs flaked into the reconnect race.)
.text_seen_fallback:
    cmp byte [api_stream_text_seen], 0
    je .hard_failed
    mov byte [tls_key_schedule_ready], 0
    jmp .success
.hard_failed:
    stc
    ret

; ---- keep-alive (called once per render iteration from agent_response_phase) ----
; Roughly every ka_interval_ticks, ping the server with a lightweight HTTP request so its
; ~400s HTTP-idle never closes the connection during a long (~11min) render -> the next
; prompt REUSES the live session instead of racing a reconnect handshake. Gated on
; tls_buffered_payload_len==0 so the ping's record build (into tls_app_record_buffer, which
; overlaps the tail of the receive stream buffer) only ever overwrites already-consumed
; plaintext, never a preserved next-record tail; the interval also skips short answers and
; the cold greeting (both finish under the interval). ka_sent_count counts pings so the
; .success drain can consume their responses. Best-effort: a send error is ignored (the
; exchange path recovers). Clobbers ax/cx/si/di; this runs after the record was scanned and
; the render loop reloads its receive state on the next pass.
agent_api_keepalive:
    ; Fire only when the ping's record build (tls_app_record_buffer == tls_rx_copy +
    ; tls_payload_buffer_len) cannot touch live receive data: the current record's plaintext
    ; plus any preserved next-record tail must end below that offset. buffered==0 alone is too
    ; rare in a dense stream (needs a frame ending exactly on a record boundary) and delayed
    ; the ping past the server's ~400s idle-close; this is true at the last record of every
    ; frame, so the ping fires reliably and early enough to hold the connection.
    mov ax, [tls_app_len]
    add ax, [tls_buffered_payload_len]
    cmp ax, tls_payload_buffer_len
    jae .ka_done
    mov ax, [0x046c]
    sub ax, [ka_last_tick]
    cmp ax, ka_interval_ticks
    jb .ka_done
    mov ax, [0x046c]
    mov [ka_last_tick], ax
    mov word [tls_app_len], ka_request_len
    mov word [tls_app_plain_ptr], ka_template_persistent
    call tls_send_application_data_current_seq
    jc .ka_done
    ; Count the ping only once it is actually on the wire, so the .success drain expects
    ; exactly as many responses as were sent (an over-count would block on a missing reply).
    inc byte [ka_sent_count]
.ka_done:
    ret

; Per-exchange keep-alive state (reset in the agent_api_stream phase when the request is
; sent). ka_last_tick = BIOS tick (0x046c low word) at the last request/ping; ka_sent_count
; = pings sent this exchange, drained in .success. Resident so it survives the receive loop.
ka_last_tick dw 0
ka_sent_count db 0
