%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name the runtime load address"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

agent_api_stream_phase:
    push ds
    pop es
    cld
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .ready_tail
    ; Cold greeting: the banner is already drawn (early, at hal_start), so nothing to draw here -- the
    ; greeting just flows from the current cursor (below the banner / config). No absolute positioning.
    jmp .done

.ready_tail:
    mov al, [chat_prompt_len_cache]
    push ax
    cmp word [tls_app_len], 0
    je .stream_chunk2
    phase_call_res tls_prepare_3c501_receive
    phase_call_res tls_send_application_data_current_seq
    jc .prefix_failed
.stream_chunk2:
    ; Build 9 chunk 2: ",reasoning,instructions:"<identity> <ledger>","input":". Build 10 fix:
    ; instructions ride their OWN record, then ledger+directive+input-open ride a second, so
    ; neither overflows the 440 B api_request_plain body. A compaction turn's COMBINED chunk 2
    ; (~586 B) overflowed it into TLS/config scratch and hung the send (16K freeze). Splitting
    ; keeps each record well under the cap; the body now spans 4 TLS records.
    mov di, api_request_plain + tls_record_header_len
    mov si, PHASE_LOAD_ADDR + (api_json_reasoning_prefix - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    ; Build 11 #4: chunk 2 instructions value. CRITICAL: every TLS record's TX frame (record + ~75 B
    ; TLS/TCP/IP/Eth overhead) must fit the 512 B scratch (ne_tx_frame at low_scratch_start .. the phase
    ; load addr net_setup_phase_start) - an oversized frame overwrites THIS phase's own code mid-send.
    ; So no record may exceed api_request_plain_len (440), exactly like the normal-turn records.
    cmp byte [compacting_msg], 0
    je .chunk2_identity
    ; Compaction: stream the contract as <=440 B records (it is larger than one record), staged in the
    ; RX buffer (free on a compaction pass: the prompt is not sent, and the real turn re-reads it from
    ; the screen). The targets + input-open then ride a fresh, bounded record.
    mov ax, [prompt_compact_cluster]
    mov cx, [prompt_compact_size]
    call agent_api_stream_stream_contract
    jc .prefix_failed
    mov di, api_request_plain + tls_record_header_len
    call agent_api_stream_append_compaction_targets   ; " Target about <N> .. at most <M>."
    jmp .chunk2_input_open
.chunk2_identity:
    ; Build 11: stream the identity as <=440 B records (the SAME path as the contract) so it can exceed
    ; one record - the >392 B reframe. The prefix is already in the body; the streamer flushes records as
    ; it fills and leaves di at the body. (Was a single in-place record, Makefile-capped at 392 B.)
    mov ax, [prompt_id_cluster]
    mov cx, [prompt_id_size]
    call agent_api_stream_stream_contract
    jc .prefix_failed
    mov di, api_request_plain + tls_record_header_len
    call agent_api_stream_append_ledger
    ; Build 11 #4 note-as-memory: a normal turn carries the running note (the compacted memory) in
    ; "instructions" behind a label, JSON-escaped (the model summary may contain " or \). This is what
    ; makes the post-compaction turn ANSWER the user's prompt: the note reads as system memory, not as
    ; the latest conversation turn. Skipped until the first compaction (note_len 0).
    cmp word [note_len], 0
    je .chunk2_input_open
    mov si, PHASE_LOAD_ADDR + (api_note_label_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    ; The note exists ONLY on a <=64 KB machine (it rode the model-summarize compaction; note_len is 0 on a
    ; >64 KB machine, so the note_len==0 gate above skips this block there). So the note always reads from
    ; the seg-0 window -- ds = far_log_seg_var = 0 on that machine. (No far/seg branch needed.)
    mov si, chat_context_start
    mov cx, [note_len]
    xor dx, dx                                 ; C1b: 32-bit count high word (the note is small)
    call agent_api_stream_append_context      ; the note [chat_context_start ..+note_len), escaped
    jc .prefix_failed
.chunk2_input_open:
    mov si, PHASE_LOAD_ADDR + (api_json_input_open_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    call .send_app_record                     ; record B: ledger [+ note] + input-open (or targets)
    jc .prefix_failed
.tail_pending:
    pop ax
    mov [api_stream_prompt_len], al           ; gate length stays the user prompt's (non-zero); on a
    or al, al                                 ; compaction pass the input is the WINDOW ONLY (the
    je .done                                  ; directive rode in instructions above)
    mov di, api_request_plain + tls_record_header_len
    ; Build 12 Stage C (C1b): "input" = the dialogue range agent_request precomputed (dialogue_off +
    ; the 32-bit dialogue_cnt); the source segment is far_log_seg_var (the far log, or seg 0 on a <=64 KB
    ; machine). append_context renormalizes ds across 64 KB as the far log streams past segment 0x1000.
    mov si, [dialogue_off]
    mov cx, [dialogue_cnt]
    mov dx, [dialogue_cnt + 2]
    call agent_api_stream_append_context
    jc .failed
    cmp byte [compacting_msg], 0
    jne .tail_close                           ; compaction: input = the window alone, no user prompt
    call agent_api_stream_append_prompt_screen_to_buffer
    jc .failed
.tail_close:
    mov si, PHASE_LOAD_ADDR + (api_stream_json_close_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len

.send_tail:
    or ax, ax
    jz .done
    cmp ax, api_request_plain_len
    ja .failed
    call .send_app_record
    jc .failed
    phase_call_res tls_prepare_3c501_receive
    ; Build 11 cleanup: the compaction-turn window-clear was dead (compact_next is always 0 here);
    ; always accumulate the just-sent prompt into the window for the next turn.
    call agent_api_stream_append_prompt_to_context
.done:
    cmp byte [compacting_msg], 0          ; Build 10: the sliding-window trim shows the status line
    je .done_load_response
    call agent_api_stream_show_compacting
.done_load_response:
    mov ax, (((core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512) << 8) | ((core_agent_response_phase_start - $$) / 512)
    mov bx, agent_response_phase_load_addr
    phase_call_res load_core_sectors_at
    jc .failed
    ; Reset keep-alive timing: this request is the last client activity, so the idle clock
    ; (Cloudflare's ~400s timeout) restarts here, with no pings outstanding for this exchange.
    mov ax, [0x046c]
    mov [ka_last_tick], ax
    mov byte [ka_sent_count], 0
    ; Per-turn state reset, golfed to one zero source + word writes (saves ~24 B so the loop
    ; additions keep this phase inside its 3-sector load window). The pairs are adjacent in
    ; low_phase_state/low_runtime_state, so each word write clears two bytes at once:
    ;   api_stream_state+api_stream_delta_match / api_stream_seen+api_stream_completed /
    ;   api_http_state+api_http_header_match. Functionally identical to the byte-wise resets.
    xor ax, ax
    mov word [api_response_pending_len], ax
    mov word [api_body_len], ax
    mov [chat_prompt_len_cache], al
    mov word [api_stream_state], ax
    mov word [api_stream_seen], ax
    mov word [api_http_state], ax
    mov [api_stream_text_seen], al
    ; Build 11 colour-matches-execution: start the response at column 0 so the renderer's line-start
    ; dim test (agent_response .emit_char) sees a reply-leading '$' as a real call. .emit_to_screen
    ; sets the real cursor when it positions the first char; this only seeds the pre-position read.
    mov [cursor_col], al
    clc
    ret

.prefix_failed:
    pop ax
.failed:
    stc
    ret

; Shared by the chunk-2 and tail sends (ax = record body length): set the record length + the
; plaintext pointer (always the request buffer), prepare the 3c501 receive, send. CF = send failure.
.send_app_record:
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    phase_call_res tls_prepare_3c501_receive
    phase_call_res tls_send_application_data_current_seq
    ret

api_stream_json_close_text db '","stream":true}', 0
api_stream_json_close_text_len equ $ - api_stream_json_close_text - 1

; Build 11 #4: stream the floppy-resident IDENTITY into the open record IN PLACE (one record). ax =
; first cluster, cx = byte size (cached at boot). di = the body write pointer (past the prefix). The
; identity is ONE sector and the whole record (prefix + identity) is <= api_request_plain_len - so the
; TX frame fits the 512 B pre-phase scratch (an oversized frame would overwrite this phase's own code;
; the Makefile guards the identity size). The caller sends the record. Control bytes flatten to space
; (1:1, JSON-safe; the build guard bans " and \), so the streamed length == the cached size, which is
; exactly what compute_ready_body_lengths counts. CF=1 on a sector-read failure. Returns di past the
; identity, cx=0.
agent_api_stream_append_floppy_prompt:
    jcxz .fp_done                        ; size 0 (file absent) -> emit nothing
    push cx                              ; size = bytes to flatten in place
    add ax, fat_data_start_lba - fat_first_data_cluster   ; cluster -> absolute LBA
    mov bx, di                           ; read the sector IN PLACE at the record write pointer
    phase_call_res read_abs_sector       ; es:bx <- sector; clobbers dx + flags, preserves bx/cx
    pop cx
    jc .fp_done_err
.fp_flatten:
    cmp byte [di], 32
    jae .fp_keep
    mov byte [di], ' '                   ; control byte (newline etc.) -> JSON-safe space, 1:1
.fp_keep:
    inc di
    loop .fp_flatten
.fp_done:
    clc
    ret
.fp_done_err:
    stc
    ret

; Build 11 #4: stream the compaction CONTRACT (larger than one record) as <=440 B records, so no TX
; frame ever exceeds the 512 B scratch below the phase. di = the body write pointer (past the prefix).
; The contract is staged in the RX buffer tls_rx_copy - FREE on a compaction pass: the user prompt
; there is not sent (the input is the window alone) and the real turn re-reads it from the screen
; (agent_request restore_prompt_from_screen). Reads the contract (one sector; Makefile-guarded <= 512)
; into tls_rx_copy, then copies it into the body, flushing EVERY full record AND the final partial one
; (so di = body, empty, on return - the caller then puts the targets + input-open in a fresh record).
; Control bytes flatten to space. CF=1 on a sector-read or record-send failure.
agent_api_stream_stream_contract:
    ; Build 11: generalized to stream ANY floppy prompt as <=440 B TLS records (ax = cluster, cx = byte
    ; size, caller-set) - the compaction contract AND the identity, both larger than one record. cx
    ; survives read_abs_sector (preserves bx/cx), so the size carries across the sector stage.
    ; Build 12 incr 3 (32K floppy-free loop): resolve the prompt source via a resident helper (this is
    ; a tight net-window phase, so keep the logic out of it). It returns si = the fixed cache slot when
    ; a 32K boot preloaded this prompt, else reads the sector into tls_rx_copy; CF on a read failure.
    phase_call_res agent_resolve_prompt_source
    jc .sc_fail
.sc_copy:
    jcxz .sc_flush_last
    cmp di, api_request_plain + tls_record_header_len + api_request_plain_len
    jb .sc_room
    call .sc_flush_record                ; record full (440 B): send it, di = body
    jc .sc_fail
.sc_room:
    lodsb
    cmp al, 32
    jae .sc_store
    mov al, ' '
.sc_store:
    stosb
    dec cx
    jmp .sc_copy
.sc_flush_last:
    cmp di, api_request_plain + tls_record_header_len
    je .sc_done                          ; nothing buffered (di == body): done
    call .sc_flush_record                ; flush the final partial contract record
    jc .sc_fail
.sc_done:
    clc
    ret
.sc_fail:
    stc
    ret
.sc_flush_record:
    ; send body[0 .. di-body] as a TLS record; reset di = body. Preserves si + cx (the contract
    ; staging pointer + remaining), which the TLS send would otherwise clobber. CF=1 on send failure.
    push si
    push cx
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    phase_call_res tls_prepare_3c501_receive
    phase_call_res tls_send_application_data_current_seq
    jc .sc_flush_fail
    phase_call_res tls_prepare_3c501_receive
    pop cx
    pop si
    mov di, api_request_plain + tls_record_header_len
    clc
    ret
.sc_flush_fail:
    pop cx
    pop si
    stc
    ret

; Build 11 #4c: append the dynamic char targets after the (floppy) compaction contract, so the model
; sizes its note to the window without doing byte math itself. N = window/4 (the ~25% aim), M =
; window/2 (the hard ceiling - emit_char caps the captured summary at exactly this, keeping the post-
; summary window under the 75% trigger). Rendered as decimals; the fixed text length + the two digit
; counts are mirrored into Content-Length by compute_ready_body_lengths (api_compaction_targets_fixed_len
; + .u16_decimal_len). [es:di] advances; clobbers ax/bx/cx/dx/si.
agent_api_stream_append_compaction_targets:
    mov si, PHASE_LOAD_ADDR + (api_targets_pre_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, [chat_context_len_var]
    shr ax, 1
    shr ax, 1                            ; N = window/4
    call agent_api_stream_append_u16_decimal
    mov si, PHASE_LOAD_ADDR + (api_targets_mid_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, [chat_context_len_var]
    shr ax, 1                            ; M = window/2 (== chat_effective_cap on a compaction pass)
    call agent_api_stream_append_u16_decimal
    mov si, PHASE_LOAD_ADDR + (api_targets_post_text - PHASE_BASE)
    jmp agent_api_stream_append_z_to_buffer

agent_api_stream_append_u16_decimal:
    ; ax = u16 -> variable-width decimal at [es:di]. Renders the dynamic compaction char targets (N/M)
    ; (must agree with agent_request's .u16_decimal_len count). Preserves bx/cx; clobbers ax + dx.
    push cx
    push bx
    xor cx, cx
    mov bx, 10
.u16d_div:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .u16d_div
.u16d_emit:
    pop ax
    add al, '0'
    stosb
    loop .u16d_emit
    pop bx
    pop cx
    ret

api_targets_pre_text db ' Target about ', 0
api_targets_pre_len equ $ - api_targets_pre_text - 1
api_targets_mid_text db ' characters, at most ', 0
api_targets_mid_len equ $ - api_targets_mid_text - 1
api_targets_post_text db '.', 0
api_targets_post_len equ $ - api_targets_post_text - 1
api_compaction_targets_fixed_len equ api_targets_pre_len + api_targets_mid_len + api_targets_post_len

; Build 11 #4 note-as-memory: the label that prefixes the running note in "instructions" (the system
; slot). Frames the note as background memory and explicitly tells the model not to restate it, so the
; post-compaction turn answers the user's new prompt (in "input") instead of continuing the note. Plain
; ASCII (no " or \), so its length is fixed; compute_ready_body_lengths adds api_note_label_text_len.
api_note_label_text db ' Conversation so far (context, do not restate): ', 0
api_note_label_text_len equ $ - api_note_label_text - 1

agent_api_stream_append_z_to_buffer:
    lodsb
    or al, al
    jz .append_done
    stosb
    jmp agent_api_stream_append_z_to_buffer
.append_done:
    ret

; The window's JSON-escaping copy is folded into the flush-aware agent_api_stream_append_context
; below (its only caller): a big-RAM window can exceed one TLS record, so it must flush as it goes.

agent_api_stream_append_prompt_screen_to_buffer:
    cmp byte [agent_loop_pending], 0
    je .from_screen
    ; Build 10 (agentic loop): auto-continue turn - append the fixed continue directive (clean
    ; ASCII, no escaping needed) straight from dpi_input_buf instead of the blank screen prompt.
    ; The directive is always exactly agent_continue_len bytes (dpi set dpi_input_len_byte to it).
    mov si, dpi_input_buf
    mov cx, agent_continue_len
    rep movsb
    clc
    ret
.from_screen:
    push es
    mov al, [api_stream_prompt_len]
    mov [api_http_state], al
    mov ax, [video_seg]
    mov es, ax
    mov al, [dpi_prompt_marker_row]
    and al, 0x7f
    mov bl, [screen_cols]
    mul bl
    xor bh, bh
    mov bl, dpi_prompt_col + 2
    add ax, bx
    shl ax, 1
    mov si, ax
    mov byte [api_http_header_match], dpi_prompt_col + 2
.screen_next:
    cmp byte [api_http_state], 0
    je .screen_done
    ; Build 9 chunk-3 splitting: when the record buffer is about to overflow (leave room for one
    ; escaped pair + the closing JSON), FLUSH it as a TLS record and keep reading into a fresh
    ; buffer - so a long prompt sends as multiple records instead of truncating. Gated here, so a
    ; short prompt (di never reaches the limit) takes the unchanged single-record path.
    cmp di, api_request_plain + tls_record_header_len + api_request_plain_len - api_stream_json_close_text_len - 2
    jae .screen_flush
    mov al, [es:si]
    cmp al, '"'
    je .screen_escape
    cmp al, '\'
    je .screen_escape
    cmp al, 32
    jb .screen_space
    jmp .screen_store
.screen_escape:
    mov ah, al
    mov al, '\'
    mov [di], al
    inc di
    mov al, ah
    mov [di], al
    inc di
    jmp .screen_advanced
.screen_space:
    mov al, ' '
    mov [di], al
    inc di
    jmp .screen_advanced
.screen_store:
    mov [di], al
    inc di
.screen_advanced:
    inc si
    inc si
    inc byte [api_http_header_match]
    mov al, [screen_cols]
    cmp [api_http_header_match], al
    jb .screen_count
    mov byte [api_http_header_match], dpi_prompt_col + 2
    add si, (dpi_prompt_col + 2) * 2
.screen_count:
    dec byte [api_http_state]
    jmp .screen_next
.screen_done:
    mov byte [api_http_state], 0
    mov byte [api_http_header_match], 0
    mov byte [api_stream_delta_match], 0
    pop es
    clc
    ret
.screen_flush:
    ; Record buffer full mid-prompt: send what's built (context + prompt-so-far on the first flush,
    ; pure prompt-parts after) as a TLS record, then keep reading into a fresh buffer. The send
    ; reuses the current-seq path (auto-increments the record seq) and reads plaintext from ds, but
    ; CLOBBERS es (push ds/pop es internally) - so save si (a register) and re-point es at video
    ; after; api_http_state / api_http_header_match are memory and survive the send. di is reset.
    push si
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    phase_call_res tls_prepare_3c501_receive
    phase_call_res tls_send_application_data_current_seq
    jc .screen_flush_failed
    phase_call_res tls_prepare_3c501_receive
    pop si
    mov ax, [video_seg]
    mov es, ax
    mov di, api_request_plain + tls_record_header_len
    jmp .screen_next
.screen_flush_failed:
    pop si
    pop es
    stc
    ret

; Build 9 chunk-2 templates: identity+ledger ride in "instructions"; input opens the prompt.
; Build 10: the RAM tool grammar is advertised here so the model can call tools on its
; own (not only when the user spells the syntax). Build 10 fix: instructions and the
; (ledger+directive+input-open) tail are sent as TWO separate records (.stream_chunk2), so
; each must stay under the 440 B api_request_plain body - NOT their sum. The old single-record
; build summed them (~586 B on a compaction turn), overflowed the buffer, and hung the send.
; Build 11 #4: split into the JSON prefix (always sent) + the identity body (NORMAL turns only). A
; compaction pass sends prefix + the summarize directive instead - so the model NEVER sees the tool
; grammar/identity that made it "summarize" its RAM tools instead of the chat.
api_json_reasoning_prefix db '","reasoning":{"effort":"high"},"instructions":"', 0
api_json_reasoning_prefix_len equ $ - api_json_reasoning_prefix - 1
; Build 11 #4 real compaction: the identity body (normal turns) and the compaction contract
; (compaction passes) are no longer inline strings - they are STREAMED off the floppy
; (agent_api_stream_append_floppy_prompt). This frees the phase bytes they used and lifts the
; in-phase prompt-length cap (the contract can now be detailed). The prefix above still rides record A
; from the phase image; the floppy content follows it.
api_json_input_open_text db '","input":"', 0
api_json_input_open_text_len equ $ - api_json_input_open_text - 1
; Build 11 recall fix: vendor-agnostic role labels for the carried conversation window (the
; compactable layer; identity+ledger stay in "instructions"). Plain JSON-safe text - no escaping,
; no newlines (append_context flattens controls to spaces anyway) - so they pass through unchanged
; and work across providers. Each stored turn becomes " User: <prompt> You: <response>". "You:" is
; deliberately identity-neutral (not "Assistant") - the agent's role/identity lives in the identity
; layer, chosen by identity/the user, not dictated by the transcript format.
api_json_user_label_text db ' User: ', 0
api_json_user_label_text_len equ $ - api_json_user_label_text - 1
; Build 11 whole-line tool gate: this label ends with a real newline (not a trailing space) so the
; model's reply begins on its own line in the raw window - tool_call can then treat a reply-leading
; directive as a true line start. It flattens back to a space when the window is re-sent (append_context
; turns control bytes into spaces), so the model still sees " You: <reply>". Same length as before.
api_json_you_label_text db ' You:', 10, 0
api_json_you_label_text_len equ $ - api_json_you_label_text - 1
; Build 11 cleanup: the Build 9 invisible-compaction recap directive was removed along with the
; dead compact_next request-build branches (recap compaction is gone since Build 10; the sliding
; window in agent_request replaced it).

; Build 9 ledger field labels (terse machine facts serialized from the handoff block)
api_ledger_ram_text db 'ram=', 0
api_ledger_ip_text db ' ip=', 0
; Build 12 memory scaling: gw/dns/mask were dropped from the ledger -- seed does all the routing, the
; model never acts on the gateway/DNS/netmask, so they were dead weight. The freed bytes fund " far@".
api_ledger_fam_text db ' fam=', 0
api_ledger_nic_text db ' nic@', 0
api_ledger_irq_text db ' irq=', 0
api_ledger_arena_text db ' a@', 0
api_ledger_cap_text db ' cap@', 0
api_ledger_save_text db ' save=', 0
; Build 12 memory scaling (C2/C3): the far ARENA (agent workspace) as flat range " far@<base>-<top>".
; Both bounds are computed at emit time (hex32) -- base = 0x10000 + far_window_cap (above the far log),
; top = conv_top. Always emitted, fixed-width -> the ledger stays == api_ledger_len (CL counts it exactly).
api_ledger_far_text db ' far@', 0
; Serialized length (every field is fixed-width / zero-padded, so this is exact, not just an upper bound).
; Labels (minus 9 NULs) + ram hex16(4) + ip dotted(15) + fam dec8(3) + nic hex16(4) + irq dec8(3)
; + arena hex16(4) + cap hex16(4) + save(2) + far [base hex32(8) + '-'(1) + top hex32(8) = 17].
api_ledger_labels_len equ $ - api_ledger_ram_text - 9
api_ledger_len equ api_ledger_labels_len + (4 + 15 + 3 + 4 + 3 + 4 + 4 + 2 + 17)

; Build 10: chunk 2 is sent as two records (instructions; then ledger+directive+input-open),
; so enforce that EACH record fits the api_request_plain body. The old single-record build
; summed them (~586 B on a compaction turn) and overflowed the 440 B buffer, corrupting TLS
; scratch and hanging the send -> the 16K compaction-turn freeze.
; Build 11 #4: TWO floppy-read bounds. (1) The IDENTITY is read a full 512 B sector IN PLACE into the
; record body after the prefix - the read end (prefix + 512) overflows the nominal api_request_plain
; body into the post-record handshake/config scratch tail (dead during chat-loop sends) and MUST stay
; inside the critical scratch arena. (The identity RECORD itself is <= api_request_plain_len, Makefile-
; guarded, so its TX frame fits the pre-phase scratch.) (2) The CONTRACT is staged a sector at a time
; in tls_rx_copy, which MUST hold a full 512 B sector below api_request_plain (tls_payload_buffer_len
; reserves 592 B there). No record exceeds api_request_plain_len, so no TX frame overruns the scratch.
%if (api_request_plain + tls_record_header_len + api_json_reasoning_prefix_len + 512) > critical_scratch_end
%error "floppy identity in-place sector read overflows the critical scratch arena"
%endif
%if 512 > tls_payload_buffer_len
%error "contract staging sector does not fit tls_rx_copy below api_request_plain"
%endif
%if (api_ledger_len + api_json_input_open_text_len) > api_request_plain_len
%error "chunk 2 record B (ledger+input-open) exceeds the api_request_plain body"
%endif

; ---- Build 9 ledger: terse machine-facts serialization of the handoff block ----
; Appends "ram=<hex> ip=<dotted> fam=<dec> nic@<hex> irq=<dec> mac=<hex> a@.. cap@.. far@.. save=.." to
; [es:di] from the resident handoff. es must equal ds. Clobbers ax/cx/dx/si; advances di.
agent_api_stream_append_ledger:
    mov si, PHASE_LOAD_ADDR + (api_ledger_ram_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    ; advertise the ARENA CEILING as ram= (on a 32K direct boot the preload cache sits between the arena
    ; and the stack, so the free arena tops out at loop_cache_start, not ram_top).
    mov ax, [handoff_addr + handoff_ram_top]
    cmp ax, ram_tier_32k_min
    jb .ledger_ram_ready
    mov ax, loop_cache_start
.ledger_ram_ready:
    call agent_api_stream_ledger_hex16
    mov si, PHASE_LOAD_ADDR + (api_ledger_ip_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, handoff_addr + handoff_ip_addr
    call agent_api_stream_ledger_dotted
    mov si, PHASE_LOAD_ADDR + (api_ledger_fam_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov al, [handoff_addr + handoff_nic_family]
    call agent_api_stream_ledger_dec8
    mov si, PHASE_LOAD_ADDR + (api_ledger_nic_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, [handoff_addr + handoff_nic_base]
    call agent_api_stream_ledger_hex16
    mov si, PHASE_LOAD_ADDR + (api_ledger_irq_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov al, [handoff_addr + handoff_nic_irq]
    call agent_api_stream_ledger_dec8
    mov si, PHASE_LOAD_ADDR + (api_ledger_arena_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, chat_context_start
    add ax, [chat_context_len_var]
    call agent_api_stream_ledger_hex16
    mov si, PHASE_LOAD_ADDR + (api_ledger_cap_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, chat_context_len_var
    call agent_api_stream_ledger_hex16
    ; Build 12 Stage C (C2/C3): far@<arena_base>-<arena_top> -- the far ARENA (agent $w/$x workspace), which
    ; now sits ABOVE the far context log (base = 0x10000 + far_window_cap), not overlapping it. Both bounds
    ; are boot-computed DWORDs, emitted fixed-width (hex32) so the ledger stays == api_ledger_len. On a
    ; <=64 KB machine base == top == 0x10000 (empty far range).
    mov si, PHASE_LOAD_ADDR + (api_ledger_far_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, [far_arena_base]
    mov dx, [far_arena_base + 2]
    call agent_api_stream_ledger_hex32
    mov al, '-'
    stosb
    mov ax, [far_arena_top]
    mov dx, [far_arena_top + 2]
    call agent_api_stream_ledger_hex32
    mov si, PHASE_LOAD_ADDR + (api_ledger_save_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ah, 'o'
    test byte [handoff_addr + handoff_flags], handoff_flag_writable_media
    jz .save_ro
    mov ah, 'w'
.save_ro:
    mov al, 'r'
    stosw
    ret
agent_api_stream_ledger_hex32:     ; dx:ax -> 8 hex chars at [es:di] (high word first)
    push ax
    mov ax, dx
    call agent_api_stream_ledger_hex16
    pop ax
    ; fall through to hex16 for the low word
agent_api_stream_ledger_hex16:     ; ax -> 4 hex chars at [es:di]
    push ax
    mov al, ah
    call agent_api_stream_ledger_hex8
    pop ax
agent_api_stream_ledger_hex8:      ; al -> 2 hex chars at [es:di]
    push ax
    push ax
    mov cl, 4
    shr al, cl
    call agent_api_stream_ledger_nibble
    pop ax
    call agent_api_stream_ledger_nibble
    pop ax
    ret
agent_api_stream_ledger_nibble:    ; low nibble of al -> 1 hex char at [es:di]
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .nibble_emit
    add al, 'a' - '0' - 10
.nibble_emit:
    stosb
    ret
agent_api_stream_ledger_dotted:    ; 4 bytes at ds:si -> "a.b.c.d" at [es:di]
    mov cx, 4
.dotted_next:
    lodsb
    call agent_api_stream_ledger_dec8
    dec cx
    jz .dotted_done
    mov al, '.'
    stosb
    jmp .dotted_next
.dotted_done:
    ret
agent_api_stream_ledger_dec8:      ; al (0-255) -> exactly 3 decimal digits at [es:di]
    push cx
    push dx
    xor ah, ah
    mov cl, 100
    div cl
    mov dl, ah
    add al, '0'
    stosb
    mov al, dl
    xor ah, ah
    mov cl, 10
    div cl
    mov dl, ah
    add al, '0'
    stosb
    mov al, dl
    add al, '0'
    stosb
    pop dx
    pop cx
    ret

; ---- Build 9 conversation context: copy a chat_context range into [es:di], JSON-escaped, FLUSHING ----
; Build 11 #4 note-as-memory: range-based - si = start ptr, cx = byte count. Callers pass the NOTE
; range [chat_context_start .. +note_len) (into "instructions") and the DIALOGUE range
; [chat_context_start+note_len .. +used) (into "input") separately; the compaction pass passes the whole
; window. es=ds; tls_send leaves es=ds. A big range flushes across TLS records as the buffer fills.
; Build 12 Stage C: ds:si is the source -- on a >64 KB machine ds=far_log_seg_var (0x1000) and si is a
; FAR-LOG OFFSET; on a <=64 KB machine ds=0 (far_log_seg_var) and si is a seg-0 pointer (chat_context_start
; based). The count is now 32-bit in dx:cx (C1b: the canonical far log grows past 64 KB). ds is loaded from
; far_log_seg_var and RENORMALIZED +0x1000 whenever si wraps a 64 KB boundary (only the far log ever wraps;
; a seg-0 window never reaches 0xFFFF), so the read walks the whole flat log; ds is restored to 0 for the
; flush (tls_app_len + the resident phase calls are ds=0-relative) and on every exit. es stays = the record
; body segment (0). The start offset si is always < 64 KB, so only the in-loop renorm is needed.
agent_api_stream_append_context:        ; si = source offset/ptr, dx:cx = byte count
    push ds
    mov ds, [far_log_seg_var]            ; ds = far context log (0x1000) or seg 0 (<=64 KB fallback)
.ctx_next:
    mov ax, cx
    or ax, dx
    jz .ctx_done                         ; 32-bit count exhausted (also the zero-length entry case)
    cmp di, api_request_plain + tls_record_header_len + api_request_plain_len - 2
    jae .ctx_flush                       ; leave room for one escaped pair before the payload cap
    lodsb                                ; al = [far_log:si]; si++
    test si, si
    jnz .ctx_no_renorm
    mov bx, ds
    add bx, 0x1000                       ; si wrapped 64 KB -> advance to the next paragraph window
    mov ds, bx
.ctx_no_renorm:
    cmp al, '"'
    je .ctx_escape
    cmp al, '\'
    je .ctx_escape
    cmp al, 32
    jb .ctx_space
    stosb
    jmp .ctx_dec
.ctx_escape:
    mov ah, al
    mov al, '\'
    stosb
    mov al, ah
    stosb
    jmp .ctx_dec
.ctx_space:
    mov al, ' '
    stosb
.ctx_dec:
    sub cx, 1
    sbb dx, 0                            ; 32-bit decrement of the remaining count
    jmp .ctx_next
.ctx_done:
    pop ds                               ; restore ds = 0
.ctx_ok:
    clc
    ret
.ctx_flush:                              ; buffer full mid-window: send it as a record, reset di, resume
    push cx
    push dx
    push si
    push ds
    xor ax, ax
    mov ds, ax                           ; flush is ds=0-relative (tls_app_len + the phase calls)
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    call agent_api_stream_phase.send_app_record   ; sets tls_app_len/plain_ptr, prepares + sends; CF=fail
    jc .ctx_flush_failed
    phase_call_res tls_prepare_3c501_receive
    pop ds                               ; back to the far log segment for the resumed read
    pop si
    pop dx
    pop cx
    mov di, api_request_plain + tls_record_header_len
    jmp .ctx_next
.ctx_flush_failed:
    add sp, 8                            ; discard the 4 flush-pushed words (far ds, si, dx, cx)
    pop ds                               ; restore the ENTRY-pushed ds (=0) -- balances the stack + the
                                         ; ds=0-on-exit contract (an unbalanced ret here jumped to 0x0000)
    stc
    ret
agent_api_stream_append_prompt_to_context:   ; accumulate the just-sent prompt (RAW) for later turns
    cmp byte [compacting_msg], 0
    je .ctx_not_compaction
    ; Build 11 #4 note-as-memory: the FULL window was just sent (as "input") to be summarized; reset it
    ; so the streamed summary reply (agent_response/.emit_char) becomes the new window from offset 0.
    ; The next (real) pass records note_len = chat_context_used (agent_request) and sends this note in
    ; the "instructions"/memory slot, NOT as a conversation turn - so the model answers the user's
    ; prompt instead of continuing the note.
    mov word [chat_context_used], 0
    ret
.ctx_not_compaction:
    cmp byte [agent_loop_pending], 0
    jne .ctx_store_done                       ; auto-continue: don't bloat the window with "continue"
    mov al, [api_stream_prompt_len]
    or al, al
    je .ctx_store_done
    ; Build 11 recall fix: store the turn as " User: <prompt> You: " so the carried window is
    ; role-labeled (the response is captured right after the " You: " cue by the renderer).
    ; Vendor-agnostic, JSON-safe; stored RAW (escaped only at send). The separator is now the two
    ; labels instead of one space, so account for both lengths in the fit check.
    xor ah, ah
    mov bx, ax
    add bx, api_json_user_label_text_len + api_json_you_label_text_len
    mov ax, [chat_context_used]
    add bx, ax
    cmp bx, [chat_context_len_var]
    jbe .ctx_fits
    ; Window full: drop the history and start over with this labeled turn (overflow fallback;
    ; model-compaction fires earlier at the threshold). Build 11 #4 note-as-memory: also clear note_len
    ; - dropping the window discards the note too, so note_len must not stay > the (reset) used, or the
    ; dialogue range used-note_len would underflow.
    mov word [chat_context_used], 0
    mov word [note_len], 0
    mov al, [api_stream_prompt_len]
    xor ah, ah
    mov bx, ax
    add bx, api_json_user_label_text_len + api_json_you_label_text_len
    cmp bx, [chat_context_len_var]
    ja .ctx_store_done                  ; single labeled turn too big for the window -> skip
.ctx_fits:
    mov di, chat_context_start
    mov ax, [chat_context_used]
    add di, ax                          ; append at the used offset (accumulate, don't replace)
    mov si, PHASE_LOAD_ADDR + (api_json_user_label_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, dpi_input_buf               ; raw prompt (intact: accumulation runs before the receive)
    mov cl, [api_stream_prompt_len]
    xor ch, ch
    rep movsb
    mov si, PHASE_LOAD_ADDR + (api_json_you_label_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, di
    sub ax, chat_context_start
    mov [chat_context_used], ax
.ctx_store_done:
    ret

; Build 9 (Phase 3b): dim status shown while a compaction reply is in flight - explains the slow
; turn to the user. Dark-gray on CGA (0x08); MDA falls back to normal (0x08 can be invisible there).
agent_api_stream_show_compacting:
    push es
    ; Advance to a fresh line (scrolling the text area up at the bottom, exactly like the renderer)
    ; so the status gets its own line below the prompt; the reply then renders below the status.
    call .compacting_advance
    mov bx, [video_seg]
    mov dl, 0x08
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .compacting_seg
    mov dl, 0x07
.compacting_seg:
    mov es, bx
    mov al, [screen_cols]
    mul byte [cursor_row]
    shl ax, 1
    mov di, ax
    mov ah, dl
    mov si, PHASE_LOAD_ADDR + (api_compacting_text - PHASE_BASE)
.compacting_next:
    lodsb
    or al, al
    jz .compacting_done
    stosw
    ; Fast-type the status like the splash: wait_ticks is the same resident primitive the splash
    ; typewriter uses, so this adds no new code besides the per-char pause. Runs after the send
    ; while the model generates, so the ~1s overlaps response latency. wait_ticks clobbers ax/cx/dx
    ; - only ah (the attribute) needs saving; si/di are untouched and cx is re-set each char.
    push ax
    mov cx, type_ticks
    phase_call_res wait_ticks
    pop ax
    jmp .compacting_next
.compacting_done:
    ; Trailing blank line that SURVIVES the renderer's scroll-at-bottom: advance the same
    ; scroll-aware way the renderer does (a plain inc is eaten when the reply's first line
    ; scrolls in), so a blank row stays between the status and the reply.
    call .compacting_advance
    pop es
    ret
.compacting_advance:
    cmp byte [cursor_row], dpi_prompt_row
    jb .compacting_adv_inc
    mov ah, 0x06
    mov al, 1
    mov bh, 0x07
    mov cx, 0x0100
    mov dh, dpi_prompt_row
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ; Build 11 #4 RECAP FIX (2026-06-10, wire-proven): this scroll moves the captured user prompt up one
    ; row. pass-2 (the post-compaction real turn) rebuilds its prompt by reading the screen at
    ; dpi_prompt_marker_row (restore_prompt_from_screen + append_prompt_screen_to_buffer). If the marker is
    ; NOT moved with the scroll it points at the "> compacting context" line drawn just below, so pass-2
    ; sent "compacting context" as the user input and the model restated the note instead of ANSWERING the
    ; question. Track the prompt: decrement the marker per scroll (the 0x80 "set" flag survives - row < 128
    ; so dec never borrows into bit 7). Guarded so an unset (0) marker can never underflow.
    cmp byte [dpi_prompt_marker_row], 0
    je .compacting_adv_set_row
    dec byte [dpi_prompt_marker_row]
.compacting_adv_set_row:
    mov byte [cursor_row], dpi_prompt_row - 1
.compacting_adv_inc:
    inc byte [cursor_row]
    ret
api_compacting_text db '> compacting context', 0

%unmacro phase_call_res 1
