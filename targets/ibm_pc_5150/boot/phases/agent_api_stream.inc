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

api_ctx_native_chunk equ 0x2e70

agent_api_stream_phase:
    push ds
    pop es
    cld
    mov [0x0682], sp                 ; real resident NIC-owner return frame
    ; R's first sector survives the X load. Validate its source metadata at
    ; the last boundary before opening a stream or sending credentials.
    phase_call_res low_scratch_start + (agent_request_phase.validate_stream_bounds - core_agent_request_phase_start)
    jc .prefix_failed
    phase_call_res 10254
    mov si, PHASE_LOAD_ADDR+(h2_json_model-PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, chat_model_cache
    call agent_api_stream_append_z_to_buffer
    cmp byte [handoff_addr+handoff_status], handoff_status_ready
    je .stream_chunk2
    mov si, PHASE_LOAD_ADDR+(h2_json_greeting-PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    jmp .send_tail
.stream_chunk2:
    ; Build 12 native tool calling: on a NORMAL (non-compaction) ready turn, splice the tools array
    ; right after the model/reasoning tail. 32K+ streams resident tools_cache; 16K reads the one-sector
    ; TOOLS asset into tls_rx_copy and streams it through the same record-flushing copy path.
    mov si, PHASE_LOAD_ADDR + (api_json_reasoning_prefix - PHASE_BASE)
    cmp byte [compacting_msg], 0
    jne .chunk2_do_reasoning
    cmp byte [agent_loop_count], agent_loop_max
    jae .chunk2_do_reasoning            ; return the final tool result for a text answer
    mov si, PHASE_LOAD_ADDR + (api_json_tools_open_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov cx, [prompt_tools_size]
    cmp word [loop_cache_count], 0
    je .chunk2_tools_floppy
    mov si, tools_cache
    call agent_api_stream_stream_contract.sc_copy   ; stream schema as <=436 B records; di=body on return
    jc .prefix_failed
    jmp .chunk2_model_closed
.chunk2_tools_floppy:
    mov ax, [prompt_tools_cluster]
    call agent_api_stream_stream_contract
    jc .prefix_failed
.chunk2_model_closed:
%ifdef TLS13_PRODUCT_TLS13
    mov si, PHASE_LOAD_ADDR + (api_json_reasoning_prefix - PHASE_BASE)
%else
    mov si, PHASE_LOAD_ADDR + (api_json_reasoning_prefix - PHASE_BASE) + 1
%endif
.chunk2_do_reasoning:
    call agent_api_stream_append_z_to_buffer
    ; Build 11 #4: chunk 2 instructions value. CRITICAL: every TLS record's TX frame (record + 76 B
    ; TLS/TCP/IP/Eth overhead) must fit the 512 B scratch (ne_tx_frame at low_scratch_start .. the phase
    ; load addr net_setup_phase_start) - an oversized frame overwrites THIS phase's own code mid-send.
    ; So no record may exceed api_request_send_len (436), exactly like the normal-turn records.
    cmp byte [compacting_msg], 0
    je .chunk2_identity
    ; Compaction: stream the contract as <=436 B records (it is larger than one record), staged in the
    ; RX buffer (free on a compaction pass: the prompt is not sent, and the real turn re-reads it from
    ; the screen). The targets + input-open then ride a fresh, bounded record.
    mov ax, [prompt_compact_cluster]
    mov cx, [prompt_compact_size]
    call agent_api_stream_stream_contract
    jc .prefix_failed
    mov di, api_request_plain + 14
    call agent_api_stream_append_compaction_targets   ; " Target about <N> .. at most <M>."
    jmp .chunk2_input_open
.chunk2_identity:
    ; Build 11: stream the identity as <=436 B records (the SAME path as the contract) so it can exceed
    ; one record - the >392 B reframe. The prefix is already in the body; the streamer flushes records as
    ; it fills and leaves di at the body. (Was a single in-place record, Makefile-capped at 392 B.)
    mov ax, [prompt_id_cluster]
    mov cx, [prompt_id_size]
    call agent_api_stream_stream_contract
    jc .prefix_failed
    call agent_api_stream_append_ledger
    ; Build 11 #4 note-as-memory: a normal turn carries the running note (the compacted memory) in
    ; "instructions", JSON-escaped (the model summary may contain " or \). Skipped until the first
    ; compaction (note_len 0).
    cmp word [note_len], 0
    je .chunk2_input_open
    ; The note exists ONLY on a <=64 KB machine (it rode the model-summarize compaction; note_len is 0 on a
    ; >64 KB machine, so the note_len==0 gate above skips this block there). So the note always reads from
    ; the seg-0 window -- ds = far_log_seg_var = 0 on that machine. (No far/seg branch needed.)
    mov si, [dialogue_off]
    sub si, [note_len]
    mov cx, [note_len]
    xor dx, dx                                 ; C1b: 32-bit count high word (the note is small)
    call agent_api_stream_append_context      ; the note [context_base .. +note_len), escaped
    jc .prefix_failed
.chunk2_input_open:
    mov si, PHASE_LOAD_ADDR + (api_json_input_open_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    call .send_app_record                     ; record B: ledger [+ note] + input-open (or targets)
    jc .prefix_failed
.tail_build:
    push cs
    pop ds
    push cs
    pop es
    ; Reconnect handshakes can clobber api_stream_prompt_len; the durable
    ; prompt length lives beside the retry counter in reconnect-safe state.
    mov al, [chat_resend_prompt_len]
    mov [api_stream_prompt_len], al
    mov di, api_request_plain + 14
    mov si, PHASE_LOAD_ADDR + (api_json_user_item_open_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, [dialogue_off]
    mov cx, [dialogue_cnt]
    mov dx, [dialogue_cnt + 2]
    call agent_api_stream_append_context
    jc .failed
    cmp byte [compacting_msg], 0
    jne .tail_close_json                      ; compaction: input = the window alone, no user prompt
    mov si, PHASE_LOAD_ADDR + (api_json_user_label_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    call agent_api_stream_append_prompt_screen_to_buffer
    jc .failed
    cmp byte [tool_fc_state], 2
    jne .tail_close_json
.tail_fc_output:
    call agent_api_stream_append_fc_output_item
    jc .failed
.tail_close_json:
    mov si, PHASE_LOAD_ADDR + (api_stream_json_close_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
.send_tail:
    phase_call_res 10375
.done:
    ; Reset keep-alive timing: this request is the last client activity, so the idle clock
    ; (Cloudflare's ~400s timeout) restarts here, with no pings outstanding for this exchange.
    mov ax, [0x046c]
    mov [ka_last_tick], ax
    ; Per-turn state reset, golfed to one zero source + word writes (saves ~24 B so the loop
    ; additions keep this phase inside its 3-sector load window). The pairs are adjacent in
    ; low_phase_state/low_runtime_state, so each word write clears two bytes at once:
    ;   api_stream_state+api_stream_delta_match / api_stream_seen+api_stream_completed /
    ;   api_http_state+api_http_header_match. Functionally identical to the byte-wise resets.
    xor ax, ax
    mov [ka_sent_count], al
    mov word [api_response_pending_len], ax
    mov word [api_body_len], ax
    mov [chat_prompt_len_cache], al
    mov word [api_stream_state], ax
    mov word [api_stream_seen], ax
    mov word [api_http_state], ax
    mov [api_stream_text_seen], al
    mov word [fc_match_state], ax
    ; Seed the pre-position cursor column; .emit_to_screen sets the real cursor on first output.
    mov [cursor_col], al
    mov ax, (((core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512) << 8) | ((core_agent_response_phase_start - $$) / 512)
    mov bx, agent_response_phase_load_addr
    push ax
    push bx
    mov ax, 0x01a7                  ; unused third final-controller sector
    mov bx, 0x2a00
    phase_call_res load_core_sectors_at
    jc .owner_failed
    pop bx
    pop ax
    ret
.owner_failed:
    phase_call_res 10388

.prefix_failed:
.failed:
    phase_call_res 10388          ; retire the partially emitted request


; Shared by the chunk-2 and tail sends (ax = record body length): set the record length + the
; plaintext pointer (always the request buffer), prepare the 3c501 receive, send. CF = send failure.
.send_app_record:
    phase_call_res 10316
    ret

h2_json_model db '{"model":"',0
h2_json_greeting db ',"input":"Say Hello! ASCII only.","store":false,"stream":true}',0

; Build 12 native tool calling: ready turns use a local Responses input array. Tool continuation
; replays the captured function_call item plus function_call_output, with store:false so no remote
; response state is retained. The cold boot greeting remains string-input.
api_stream_json_close_text db '"}],"store":false,"stream":true}', 0
api_stream_json_close_text_len equ $ - api_stream_json_close_text - 1
api_json_user_item_open_text db '{"role":"user","content":"', 0
api_json_user_item_open_text_len equ $ - api_json_user_item_open_text - 1
api_fc_call_open_text db '"},{"type":"function_call","call_id":"', 0
api_fc_call_open_text_len equ $ - api_fc_call_open_text - 1
api_fc_name_mid_text db '","name":"', 0
api_fc_name_mid_text_len equ $ - api_fc_name_mid_text - 1
; fc_args_buf starts after agent_response's `arguments":"{` match, so replay must restore the
; leading object brace before the captured escaped key/value bytes.
api_fc_args_mid_text db '","arguments":"{', 0
api_fc_args_mid_text_len equ $ - api_fc_args_mid_text - 1
api_fc_output_open_text db '"},{"type":"function_call_output","call_id":"', 0
api_fc_output_open_text_len equ $ - api_fc_output_open_text - 1
api_fc_output_mid_text db '","output":"', 0
api_fc_output_mid_text_len equ $ - api_fc_output_mid_text - 1

; (Removed in M2e: agent_api_stream_append_floppy_prompt -- the in-place one-record floppy streamer was
; superseded by agent_api_stream_stream_contract, which streams the identity AND the contract as <=436 B
; records. Reclaimed for the EMS context-read path.)

; Build 11 #4: stream the compaction CONTRACT (larger than one record) as <=436 B records, so no TX
; frame ever exceeds the 512 B scratch below the phase. di = the body write pointer (past the prefix).
; The contract is staged in the RX buffer tls_rx_copy - FREE on a compaction pass: the user prompt
; there is not sent (the input is the window alone) and the real turn re-reads it from the screen
; (agent_request restore_prompt_from_screen). Reads the contract (one sector; Makefile-guarded <= 512)
; into tls_rx_copy, then copies it into the body, flushing EVERY full record AND the final partial one
; (so di = body, empty, on return - the caller then puts the targets + input-open in a fresh record).
; Control bytes flatten to space. CF=1 on a sector-read or record-send failure.
agent_api_stream_stream_contract:
    ; Build 11: generalized to stream ANY floppy prompt as <=436 B TLS records (ax = cluster, cx = byte
    ; size, caller-set) - the compaction contract AND the identity, both larger than one record. cx
    ; survives read_abs_sector (preserves bx/cx), so the size carries across the sector stage.
    ; Build 12 incr 3 (32K floppy-free loop): resolve the prompt source via a resident helper (this is
    ; a tight net-window phase, so keep the logic out of it). It returns si = the fixed cache slot when
    ; a 32K boot preloaded this prompt, else reads the sector into tls_rx_copy; CF on a read failure.
    phase_call_res agent_resolve_prompt_source
    jc .sc_fail
.sc_copy:
    jcxz .sc_flush_last
    lodsb
    cmp al, 32
    jae .sc_store
    mov al, ' '
.sc_store:
    phase_call_res 10279
    dec cx
    jmp .sc_copy
.sc_flush_last:
    cmp di, api_request_plain + 14
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
    phase_call_res 10316
    ret

; Build 11 #4c: append the dynamic char targets after the (floppy) compaction contract, so the model
; sizes its note to the window without doing byte math itself. N = window/4 (the aim), M =
; window/2 (the hard ceiling - emit_char caps the captured summary at exactly this, leaving room for
; the prompt that triggered pre-request compaction). Rendered as decimals; the fixed text length + the two digit
; counts are mirrored into Content-Length by compute_ready_body_lengths (api_compaction_targets_fixed_len
; + .u16_decimal_len). [es:di] advances; clobbers ax/bx/cx/dx/si.
agent_api_stream_append_compaction_targets:
    mov al, '~'
    phase_call_res 10279
    mov ax, [chat_context_len_var]
    shr ax, 1
    shr ax, 1                            ; N = window/4
    call agent_api_stream_append_u16_decimal
    mov al, '/'
    phase_call_res 10279
    mov ax, [chat_context_len_var]
    shr ax, 1                            ; M = window/2 (== chat_effective_cap on a compaction pass)
    jmp agent_api_stream_append_u16_decimal

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
    phase_call_res 10279
    loop .u16d_emit
    pop bx
    pop cx
    ret

; Build 12: shortened (was ' Target about '/' characters, at most ') to reclaim phase bytes.
api_compaction_targets_fixed_len equ 2

agent_api_stream_append_z_to_buffer:
    lodsb
    or al, al
    jz .append_done
    phase_call_res 10279
    jmp agent_api_stream_append_z_to_buffer
.append_done:
    ret

agent_api_stream_append_fc_output_item:
    cmp byte [fc_history_len], 0
    je .current_fc_output
    call agent_api_stream_stream_contract.sc_flush_record
    jc .append_done
    mov ax, (((core_tool_replay_prev_phase_end - core_tool_replay_prev_phase_start + 511) / 512) << 8) | ((core_tool_replay_prev_phase_start - $$) / 512)
    mov bx, 0x2c00
    phase_call_res run_core_phase_at
    jc .append_done
.current_fc_output:
    mov si, PHASE_LOAD_ADDR + (api_fc_call_open_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    call .append_call_id
    mov si, PHASE_LOAD_ADDR + (api_fc_name_mid_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, fc_name
    mov cl, [fc_name_len]
    phase_call_res 10307
    mov si, PHASE_LOAD_ADDR + (api_fc_args_mid_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, fc_args_buf
    mov cx, [fc_args_len]
    phase_call_res 10307
    ; A prompt + function_call + function_call_output can exceed one 436-byte TLS body. Split after
    ; the arguments bytes; api_fc_output_open_text's leading `"}' closes this item in the next record.
    call agent_api_stream_stream_contract.sc_flush_record
    jc .append_done
    mov si, PHASE_LOAD_ADDR + (api_fc_output_open_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    call .append_call_id
    mov si, PHASE_LOAD_ADDR + (api_fc_output_mid_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, fc_output_buf
    mov cl, [fc_output_len]
    phase_call_res 10307
.append_done:
    ret
.append_call_id:
    mov si, fc_call_id
    mov cl, [fc_call_id_len]
.append_counted:
    xor ch, ch
    phase_call_res 10307
    ret

; The window's JSON-escaping copy is folded into the flush-aware agent_api_stream_append_context
; below (its only caller): a big-RAM window can exceed one TLS record, so it must flush as it goes.

agent_api_stream_append_prompt_screen_to_buffer:
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
    phase_call_res 10279
    mov al, ah
    phase_call_res 10279
    jmp .screen_advanced
.screen_space:
    mov al, ' '
    phase_call_res 10279
    jmp .screen_advanced
.screen_store:
    phase_call_res 10279
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
    pop es
    ret
; Build 9 chunk-2 templates: identity+ledger ride in "instructions"; input opens the prompt.
; Build 10: the RAM tool grammar is advertised here so the model can call tools on its
; own (not only when the user spells the syntax). Build 10 fix: instructions and the
; (ledger+directive+input-open) tail are sent as TWO separate records (.stream_chunk2), so
; each must stay under the 436 B api_request_plain body - NOT their sum. The old single-record
; build summed them (~586 B on a compaction turn), overflowed the buffer, and hung the send.
; Build 11 #4: split into the JSON prefix (always sent) + the identity body (NORMAL turns only). A
; compaction pass sends prefix + the summarize directive instead - so the model NEVER sees the tool
; grammar/identity that made it "summarize" its RAM tools instead of the chat.
%ifdef TLS13_PRODUCT_TLS13
; chat_model_cache already closes the model and carries reasoning.effort.
api_json_reasoning_prefix db ',"instructions":"', 0
%else
api_json_reasoning_prefix db '","instructions":"', 0
%endif
api_json_reasoning_prefix_len equ $ - api_json_reasoning_prefix - 1
; Build 11 #4 real compaction: the identity body (normal turns) and the compaction contract
; (compaction passes) are no longer inline strings - they are STREAMED off the floppy
; (agent_api_stream_append_floppy_prompt). This frees the phase bytes they used and lifts the
; in-phase prompt-length cap (the contract can now be detailed). The prefix above still rides record A
; from the phase image; the floppy content follows it.
api_json_input_open_text db '","input":[', 0
api_json_input_open_text_len equ $ - api_json_input_open_text - 1
; Build 12: spliced after the model on a normal ready turn. The schema bytes stream next
; (resident tools_cache on 32K+, floppy on 16K), then the instructions prefix.
%ifdef TLS13_PRODUCT_TLS13
api_json_tools_open_text db ',"parallel_tool_calls":false,"tools":', 0
%else
api_json_tools_open_text db '","tools":', 0
%endif
api_json_tools_open_text_len equ $ - api_json_tools_open_text - 1
; Build 11 recall fix: vendor-agnostic role labels for the carried conversation window (the
; compactable layer; identity+ledger stay in "instructions"). Plain JSON-safe text - no escaping,
; no newlines (append_context flattens controls to spaces anyway) - so they pass through unchanged
; and work across providers. Each stored turn becomes " User: <prompt> You: <response>". "You:" is
; deliberately identity-neutral (not "Assistant") - the agent's role/identity lives in the identity
; layer, chosen by identity/the user, not dictated by the transcript format.
api_json_user_label_text db 'U:', 0
api_json_user_label_text_len equ $ - api_json_user_label_text - 1
; End the assistant label with a real newline in the raw window. append_context flattens it back to a
; space when the window is re-sent, so the model sees a compact transcript.
api_json_you_label_text db 'A:', 10, 0
api_json_you_label_text_len equ $ - api_json_you_label_text - 1
; Build 11 cleanup: the Build 9 invisible-compaction recap directive was removed along with the
; dead compact_next request-build branches (recap compaction is gone since Build 10; the sliding
; window in agent_request replaced it).

; Build 9/12 ledger field labels: only model-actionable tool facts. Network diagnostics stay in the
; handoff block; the model does not need them on every turn.
api_ledger_ram_text db 'r=', 0
api_ledger_arena_text db ' a@', 0
api_ledger_cap_text db ' c@', 0
api_ledger_save_text db ' s=', 0
; Build 12 memory scaling (C2/C3): the far ARENA (agent workspace) as flat range " far@<base>-<top>".
; Both bounds are computed at emit time (hex32). The arena is before context, so conventional M1 emits
; [0x10000 .. ctx_base); later tiers add EMS/native ranges separately. Always emitted, fixed-width.
api_ledger_far_text db ' F@', 0
api_ledger_hma_text db ' H@', 0
; Build 12 milestone 2: the EMS windowed arena as flat range " ems@<base>-<top>" (base 0x00100000,
; top = base + ems_page_count*16 KB). Always emitted fixed-width (empty base==top when no board), like far@.
api_ledger_ems_text db ' e@', 0
; Serialized length (every field is fixed-width / zero-padded, so this is exact, not just an upper bound).
; Labels (minus 7 NULs) + ram hex16(4) + arena hex16(4) + cap hex16(4) + save(2) + trailing space
; + far/HMA/extended-or-EMS ranges [base(8)+'-'+top(8)=17 each].
api_ledger_labels_len equ $ - api_ledger_ram_text - 7
api_ledger_len equ api_ledger_labels_len + (4 + 4 + 4 + 2 + 1 + 17 + 17 + 17)

; Build 10: chunk 2 is sent as two records (instructions; then ledger+directive+input-open),
; so enforce that EACH record fits the api_request_plain body. The old single-record build
; summed them (~586 B on a compaction turn) and overflowed the 436 B buffer, corrupting TLS
; scratch and hanging the send -> the 16K compaction-turn freeze.
; Build 11 #4: TWO floppy-read bounds. (1) The IDENTITY is read a full 512 B sector IN PLACE into the
; record body after the prefix - the read end (prefix + 512) overflows the nominal api_request_plain
; body into the post-record handshake/config scratch tail (dead during chat-loop sends) and MUST stay
; inside the critical scratch arena. (The identity RECORD itself is <= api_request_send_len, Makefile-
; guarded, so its TX frame fits the pre-phase scratch.) (2) The CONTRACT is staged a sector at a time
; in tls_rx_copy, which MUST hold a full 512 B sector below api_request_plain (tls_payload_buffer_len
; reserves 592 B there). No record exceeds api_request_send_len, so no TX frame overruns the scratch.
%if (api_request_plain + 14 + api_json_reasoning_prefix_len + 512) > critical_scratch_end
%error "floppy identity in-place sector read overflows the critical scratch arena"
%endif
%if 512 > tls_payload_buffer_len
%error "contract staging sector does not fit tls_rx_copy below api_request_plain"
%endif
%if (api_ledger_len + api_json_input_open_text_len) > api_request_send_len
%error "chunk 2 record B (ledger+input-open) exceeds the api_request_plain body"
%endif

; ---- Build 9/12 ledger: terse tool-facing serialization of actionable runtime facts ----
; Appends "r=<hex> a@<hex> c@<hex> F@<base>-<top> e@<base>-<top> s=<rw|ro> " to [es:di].
; es must equal ds. Clobbers ax/dx/si; advances di.
agent_api_stream_append_ledger:
    mov si, PHASE_LOAD_ADDR + (api_ledger_ram_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    ; advertise the low ARENA CEILING as r=. With arena-first ordering the conversation window sits
    ; at the far end of the low pool, so r = pool_ceiling - context_cap.
    mov ax, [handoff_addr + handoff_ram_top]
    sub ax, 0x100
    cmp ax, ram_tier_32k_min - 0x100
    jb .ledger_pool_ready
    mov ax, tools_cache
.ledger_pool_ready:
    sub ax, [chat_context_len_var]
    call agent_api_stream_ledger_hex16
    mov si, PHASE_LOAD_ADDR + (api_ledger_arena_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, chat_pool_start
    call agent_api_stream_ledger_hex16
    mov si, PHASE_LOAD_ADDR + (api_ledger_cap_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, [chat_context_len_var]
    call agent_api_stream_ledger_hex16
    ; Build 12 Stage C (C2/C3): F@<arena_base>-<arena_top> -- the far ARENA (agent $w/$x workspace),
    ; which sits before the far context log. Both bounds are boot-computed DWORDs, emitted fixed-width
    ; (hex32) so the ledger stays == api_ledger_len. On a <=64 KB machine base == top == 0x10000.
    mov si, PHASE_LOAD_ADDR + (api_ledger_far_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, [far_arena_base]
    mov dx, [far_arena_base + 2]
    call agent_api_stream_ledger_hex32
    mov al, '-'
    phase_call_res 10279
    mov ax, [far_arena_top]
    mov dx, [far_arena_top + 2]
    call agent_api_stream_ledger_hex32
    ; HMA is a separate direct range: it is above the ROM/device hole, so it cannot be honestly folded
    ; into F@'s conventional range.
    mov si, PHASE_LOAD_ADDR + (api_ledger_hma_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    xor ax, ax
    mov dx, hma_flat_base_hi
    call agent_api_stream_ledger_hex32
    mov al, '-'
    phase_call_res 10279
    xor ax, ax
    mov dx, hma_flat_base_hi
    test byte [handoff_addr + handoff_flags + 1], handoff_flag_hma >> 8
    jz .hma_top_ready
    mov ax, hma_flat_top_lo
    mov dx, hma_flat_top_hi
.hma_top_ready:
    call agent_api_stream_ledger_hex32
    ; Build 12 extended/EMS arena. EMS keeps the synthetic 0x00100000 base; native extended memory starts
    ; after HMA at 0x00110000 so H@ remains the only advertised direct HMA range.
    mov si, PHASE_LOAD_ADDR + (api_ledger_ems_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    xor ax, ax
    mov dx, ems_flat_base_hi
    test byte [handoff_addr + handoff_flags + 1], handoff_flag_hma >> 8
    jz .ext_base_ready
    inc dx
.ext_base_ready:
    push dx
    call agent_api_stream_ledger_hex32
    mov al, '-'
    phase_call_res 10279
    ; M2b: the EMS arena ends where the context begins -- top = far_ctx_base on an EMS machine (the context
    ; occupies the top min(pool/2,1MB) of EMS); with no board far_ctx_base is 0x10000, so fall back to the
    ; base (0x100000) for the empty EMS range.
    mov ax, [far_ctx_base]
    mov dx, [far_ctx_base + 2]
    pop bx
    cmp dx, bx
    jae .ems_top_ready
    xor ax, ax
    mov dx, bx
.ems_top_ready:
    call agent_api_stream_ledger_hex32
    mov si, PHASE_LOAD_ADDR + (api_ledger_save_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ah, '?'
    mov al, 'r'
    phase_call_res 10296
    mov al, ' '
    phase_call_res 10279
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
    phase_call_res 10279
    ret

; ---- Build 9 conversation context: copy a chat_context range into [es:di], JSON-escaped, FLUSHING ----
; Build 11 #4 note-as-memory: range-based - si = start ptr, cx = byte count. Callers pass the NOTE
; range [context_base .. +note_len) (into "instructions") and the DIALOGUE range
; [context_base+note_len .. +used) (into "input") separately; the compaction pass passes the whole
; window. es=ds; tls_send leaves es=ds. A big range flushes across TLS records as the buffer fills.
; Build 12 Stage C: ds:si is the source -- on a >64 KB machine ds=far_log_seg_var (0x1000) and si is a
; FAR-LOG OFFSET; on a <=64 KB machine ds=0 (far_log_seg_var) and si is a seg-0 pointer (context-base
; based). The count is now 32-bit in dx:cx (C1b: the canonical far log grows past 64 KB). ds is loaded from
; far_log_seg_var and RENORMALIZED +0x1000 whenever si wraps a 64 KB boundary (only the far log ever wraps;
; a seg-0 window never reaches 0xFFFF), so the read walks the whole flat log; ds is restored to 0 for the
; flush (tls_app_len + the resident phase calls are ds=0-relative) and on every exit. es stays = the record
; body segment (0). The start offset si is always < 64 KB, so only the in-loop renorm is needed.
agent_api_stream_append_context:        ; si = source offset/ptr, dx:cx = byte count
    xor ax, ax
    mov ds, ax
    mov es, ax
    push ax                              ; every exit restores ds=0, even if the caller arrived dirty
    mov bp, dx                           ; M2e: keep the byte-count HIGH word in bp -- the EMS entry/renorm
                                         ; reuse dx as the page-map port, which would otherwise clobber it.
    ; Build 12 M2b/M2e: when the context lives in EMS (far_ctx_base >= 0x100000) the source is the page
    ; frame, not a conventional segment. Convert the far-log offset si -> (page, frame offset), map the
    ; first page into slot 0, keep the page in bl and read via ds=frame_seg with a 16 KB renorm. Only the
    ; dialogue read reaches here on an EMS (>64 KB) machine; the note read is <=64 KB-only. ds=0 at entry.
    cmp byte [far_ctx_base + 2], 0x10
    jb .ctx_conv_entry
    cmp word [ems_page_count], 0
    je .ctx_ext_entry
    mov al, [ems_ctx_page]               ; boot-precomputed page + frame offset of far_ctx_base; the read
    mov bl, al                           ; starts there (dialogue_off is 0 on a >64 KB machine). bl = page
    mov si, [ems_ctx_off]
    mov dx, ems_base_port
    out dx, al                           ; map the first page into slot 0 (al = page); dx is free (count in bp)
    mov ax, ems_frame_seg
    mov ds, ax                           ; ds = frame segment (the EMS source); bl = live page
    jmp .ctx_next
.ctx_ext_entry:
    mov ax, [far_ctx_base]
    mov dx, [far_ctx_base + 2]
    add ax, si
    adc dx, 0
    mov [tool_addr], ax
    mov [tool_addr + 2], dx
    xor ax, ax
    mov [api_http_state], ax
    mov ds, ax
    jmp .ctx_next
.ctx_conv_entry:
    mov ds, [far_log_seg_var]            ; ds = far context log (0x1000) or seg 0 (<=64 KB fallback)
.ctx_next:
    mov ax, cx
    or ax, bp
    jz .ctx_done                         ; 32-bit count (bp:cx) exhausted (also the zero-length entry case)
    cmp byte [es:far_ctx_base + 2], 0x10
    jb .ctx_source_ready
    cmp word [es:ems_page_count], 0
    jne .ctx_source_ready
    cmp word [es:api_http_state], 0
    jne .ctx_source_ready
    mov ax, cx
    or bp, bp
    jz .ctx_ext_count_low
    mov ax, 512
    jmp .ctx_ext_count_ready
.ctx_ext_count_low:
    cmp ax, 512
    jbe .ctx_ext_count_ready
    mov ax, 512
.ctx_ext_count_ready:
    mov [es:tool_readlen], ax
    push cx
    push bp
    push di
    mov ax, (((core_ext_read_chunk_phase_end - core_ext_read_chunk_phase_start + 511) / 512) << 8) | ((core_ext_read_chunk_phase_start - $$) / 512)
    mov bx, low_scratch_start
    phase_call_res run_core_phase_at
    pop di
    pop bp
    pop cx
    jc .ctx_ext_failed
    mov si, api_ctx_native_chunk
    mov ax, [es:tool_readlen]
    mov [es:api_http_state], ax
.ctx_source_ready:
    lodsb                                ; al = [ds:si] (far log or frame); si++
    cmp byte [es:far_ctx_base + 2], 0x10  ; es=0 here -> reads the seg-0 var regardless of ds
    jae .ctx_high_renorm
    test si, si
    jnz .ctx_no_renorm
    mov bx, ds
    add bx, 0x1000                       ; si wrapped 64 KB -> advance to the next paragraph window
    mov ds, bx
    jmp .ctx_no_renorm
.ctx_high_renorm:
    cmp word [es:ems_page_count], 0
    jne .ctx_ems_renorm
    dec word [es:api_http_state]
    jmp .ctx_no_renorm
.ctx_ems_renorm:
    cmp si, 0x4000                       ; frame offset wrapped the 16 KB page -> map the next page
    jb .ctx_no_renorm
    xor si, si
    inc bl                               ; next EMS page (kept in bl; preserved across the flush)
    push ax                              ; preserve the just-read byte across the port write (count is in bp)
    mov dx, ems_base_port
    mov al, bl
    out dx, al
    pop ax
.ctx_no_renorm:
    cmp al, '"'
    je .ctx_escape
    cmp al, '\'
    je .ctx_escape
    cmp al, 32
    jb .ctx_space
    phase_call_res 10279
    jmp .ctx_dec
.ctx_escape:
    mov ah, al
    mov al, '\'
    phase_call_res 10279
    mov al, ah
    phase_call_res 10279
    jmp .ctx_dec
.ctx_space:
    mov al, ' '
    phase_call_res 10279
.ctx_dec:
    sub cx, 1
    sbb bp, 0                            ; 32-bit decrement of the remaining count (bp:cx)
    jmp .ctx_next
.ctx_done:
    pop ds                               ; restore ds = 0
.ctx_ok:
    clc
    ret
.ctx_ext_failed:
    pop ds
    stc
    ret
; Build 9 (Phase 3b): dim status shown while a compaction reply is in flight - explains the slow
; turn to the user. Dark-gray on CGA (0x08); MDA falls back to normal (0x08 can be invisible there).
%unmacro phase_call_res 1
