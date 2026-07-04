%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%define PHASE_LOAD_ADDR low_scratch_start
%define PHASE_LOAD_ADDR_DEFAULTED
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

agent_request_phase:
    ; Build 12 Stage C (C1b): mirror the seg-0 window into the far context log just ABOVE the frozen
    ; history (at flat offset far_flushed_len), so agent_api_stream streams the whole far log -- frozen
    ; turns ++ the live window -- from far memory. The append point is normalized to a far pointer:
    ; seg = far_log_seg + (far_flushed_len >> 4), off = far_flushed_len & 0xF (the window is < 64 KB, so
    ; off + window never crosses a 64 KB boundary -- no mid-copy renorm). On cold boot far_flushed_len
    ; and used are both 0 (a 0-byte copy to far_log_seg:0). The window is stable across this phase + a
    ; reconnect re-mirror is idempotent (a flush zeroes used, so the resend copies 0 bytes). ds=0 here.
    ; Skipped when the far log is inactive (<=64 KB machine): the seg-0 window stays canonical there.
    cmp word [far_log_seg_var], 0
    je .far_mirror_done
    ; Build 12 Stage C (C2/C3): bound the far log at its window cap so it can't grow into the far arena.
    ; If frozen history + the live window would reach far_window_cap, DROP the old history (reset the log to
    ; the current window) before mirroring -- a hard reset at the (large: >=tens of KB) cap. Runs before the
    ; mirror so the reset lands the current window at offset 0. (drop-oldest/summarize is a future refinement.)
    mov ax, [far_flushed_len]
    mov dx, [far_flushed_len + 2]
    add ax, [chat_context_used]
    adc dx, 0                            ; dx:ax = far_flushed_len + used (the log size after this mirror)
    cmp dx, [far_window_cap + 2]
    ja .far_log_full
    jb .far_cap_ok
    cmp ax, [far_window_cap]
    jb .far_cap_ok
.far_log_full:
    xor ax, ax
    mov [far_flushed_len], ax
    mov [far_flushed_len + 2], ax
    mov [far_flushed_esc], ax
    mov [far_flushed_esc + 2], ax
.far_cap_ok:
    push es
    ; Build 12 M2b/M2e: on an EMS machine the context lives in EMS (far_ctx_base >= 0x100000, high word
    ; >= 0x0010) -- mirror via the page frame; else the M1 conventional far-log write (byte-for-byte).
    cmp word [far_ctx_base + 2], 0x0010
    jae .far_mirror_ems
    mov ax, [far_flushed_len]
    mov dx, [far_flushed_len + 2]
    mov di, ax
    and di, 0x000f                       ; di = append offset within the paragraph
    mov cx, 4
.mirror_norm:
    shr dx, 1
    rcr ax, 1
    loop .mirror_norm                    ; ax = far_flushed_len >> 4 (paragraphs; < 64K on this tier)
    add ax, far_log_seg
    mov es, ax                           ; es:di = normalized far-log append point
    mov si, chat_context_start
    mov cx, [chat_context_used]
    cld
    rep movsb                            ; seg-0 window -> far log at far_flushed_len
    pop es
    jmp .far_mirror_done
.far_mirror_ems:
    ; EMS windowed write: seg-0 window [chat_context_start, +used) -> flat (far_ctx_base + far_flushed_len).
    ; rel = flat - 0x100000; map page rel>>14 into frame slot 0, walk di in [0..0x4000), remap on wrap.
    ; ds=0 (source window), es=frame seg. Registers ax/bx/cx/dx/si/di are rebuilt after .far_mirror_done.
    mov ax, [far_ctx_base]
    mov dx, [far_ctx_base + 2]
    add ax, [far_flushed_len]
    adc dx, [far_flushed_len + 2]
    sub ax, 0
    sbb dx, 0x0010                       ; dx:ax = rel = flat - 0x100000
    mov di, ax
    and di, 0x3fff                       ; di = offset within the 16 KB frame page
    mov cl, 14
.ems_wr_pshift:
    shr dx, 1
    rcr ax, 1
    dec cl
    jnz .ems_wr_pshift                   ; ax = page number = rel >> 14 (page < 256, dx now 0)
    mov bx, ax                           ; bx = current EMS page
    mov dx, ems_base_port
    mov al, bl
    out dx, al                           ; map page into slot 0
    mov ax, ems_frame_seg
    mov es, ax
    mov si, chat_context_start
    mov cx, [chat_context_used]
    cld
    jcxz .ems_wr_done
.ems_wr_loop:
    lodsb                                ; al = [ds:si] (seg-0 window); si++
    stosb                                ; [es:di] = al (frame); di++
    cmp di, 0x4000
    jb .ems_wr_cont
    xor di, di                           ; page boundary: reset frame offset, map next page
    inc bx
    mov dx, ems_base_port
    mov al, bl
    out dx, al
.ems_wr_cont:
    loop .ems_wr_loop
.ems_wr_done:
    pop es
.far_mirror_done:
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .session_ready
    ; A RECONNECT (reconnect_retries<3) reuses the cold connect's cached config: seed_* was read on the
    ; first attempt and is now handshake-clobbered (it overlays the TLS PRF scratch -- tls_server_random
    ; equ seed_agent_id), so the agent was already validated on attempt 1; skip the (now-garbage) recheck.
    cmp byte [reconnect_retries], 3
    jb .session_ready
    call .selected_agent_is_openai
    jc .failed
.session_ready:
    call .build_openai_request
    jc .failed
    clc
    ret
.failed:
    stc
    ret

.selected_agent_is_openai:
    cmp byte [seed_agent_id], 'o'
    jne .selected_failed
    cmp byte [seed_agent_id + 1], 'p'
    jne .selected_failed
    cmp byte [seed_agent_id + 2], 'e'
    jne .selected_failed
    cmp byte [seed_agent_id + 3], 'n'
    jne .selected_failed
    cmp byte [seed_agent_id + 4], 'a'
    jne .selected_failed
    cmp byte [seed_agent_id + 5], 'i'
    jne .selected_failed
    cmp byte [seed_agent_id + 6], 0
    jne .selected_failed
    clc
    ret
.selected_failed:
    stc
    ret

.build_openai_request:
    mov word [api_response_pending_len], 0
    mov byte [api_stream_state], 0
    mov byte [api_stream_delta_match], 0
    mov byte [api_stream_seen], 0
    mov byte [api_stream_text_seen], 0
    mov byte [api_stream_prompt_len], 0
    mov byte [api_stream_completed], 0
    mov byte [esc_stop], 0               ; Build 11 ESC: per-turn reset of the graceful-stop flag (the int 9
                                         ; hook sets it during a render; cleared here before the next render)
    mov byte [api_http_state], 0
    mov byte [api_http_header_match], 0
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .build_ready_openai_request
    mov byte [dpi_input_len_byte], 0
    mov byte [dpi_prompt_marker_row], 0
    mov byte [api_stream_event_ready], 0
    call .build_openai_body
    jc .request_failed
    push ds
    pop es
    mov di, api_request_plain + tls_record_header_len
    mov si, PHASE_LOAD_ADDR + (http_post_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_openai_path_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_version_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_host_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (agent_request_host_openai_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_auth_bearer_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .reuse_key
    cmp byte [reconnect_retries], 3          ; reconnect: seed_key is handshake-clobbered -> use the cache
    jb .reuse_key
    mov si, seed_key
    call agent_request_phase_append_z_to_buffer
    jmp .key_done
.reuse_key:
    mov si, chat_key_cache
    mov cx, seed_key_len
    call agent_request_phase_append_z_bounded_to_buffer
    jc .request_key_failed
.key_done:
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_content_length_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov ax, [api_body_len]
    xor dx, dx                           ; cold body <= 512 B: high word 0
    call .append_u32_decimal
    call agent_request_phase_append_crlf_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, fs_sector_buffer
    mov cx, [api_body_len]
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    jne .copy_body_prefix
    mov cx, [api_response_pending_len]
.copy_body_prefix:
    rep movsb
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    mov [tls_app_total_len], ax
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    cmp ax, api_request_plain_len
    ja .request_too_large
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .ready_request
    mov word [api_response_pending_len], 1
    jmp .success_ready
.ready_request:
    mov word [handoff_addr + handoff_net_status], 0xb0fe
.success_ready:
    clc
    ret
.build_ready_openai_request:
    ; Build 11 #4 note-as-memory: if the PRIOR pass was a compaction (compacting_msg still 1 from it,
    ; not yet reset below), the summary just captured into chat_context IS the new memory note - record
    ; its length so THIS (real) pass sends [0..note_len) in "instructions" and the live dialogue
    ; [note_len..used) in "input". Detected here because compacting_msg only stays 1 across the 2-pass
    ; loop's re-entry; a normal turn enters with it 0, so note_len persists untouched (the dialogue
    ; just accumulates after the note).
    cmp byte [compacting_msg], 0
    je .note_len_kept
    mov ax, [chat_context_used]
    mov [note_len], ax
.note_len_kept:
    ; Build 12 Stage C (C1b) far-log flush (>64 KB machine): replaces the Build-11 model-summarize
    ; compaction when the far log is active. When the seg-0 window reaches the 75% trigger
    ; (chat_compact_threshold), FREEZE it into the far log -- it was just mirrored at far_flushed_len by
    ; the phase entry, so the flush only advances far_flushed_len past it (+ folds its JSON-escaped length
    ; into far_flushed_esc for the Content-Length) and resets the seg-0 window to empty. The full
    ; conversation lives on in far memory and streams in full every turn; nothing is summarized or dropped.
    ; compacting_msg stays 0 -> the two-pass summarize loop never fires (net_phase) and the dormant
    ; compaction branches all take the normal path. Reconnect-safe: the flush zeroes used, so a rebuild
    ; re-mirrors 0 bytes and re-flushes nothing. On a <=64 KB machine the far log is inactive, so this
    ; falls through to the Build-11 model-summarize compaction (compacting_msg=1) -- exact Build-11 behavior.
    mov byte [compacting_msg], 0
    mov ax, [chat_context_used]
    cmp ax, [chat_compact_threshold]
    jb .not_compaction_pass
    cmp word [far_log_seg_var], 0
    je .model_summarize_compaction       ; <=64 KB machine: keep Build-11 model-summarize compaction
    push ax
    mov si, chat_context_start
    mov cx, ax
    call agent_request_phase_json_bytes_len   ; ax = escaped length of the window being frozen
    add [far_flushed_esc], ax
    adc word [far_flushed_esc + 2], 0
    pop ax
    add [far_flushed_len], ax
    adc word [far_flushed_len + 2], 0
    mov word [chat_context_used], 0
    jmp .not_compaction_pass
.model_summarize_compaction:
    mov byte [compacting_msg], 1
.not_compaction_pass:
    ; Build 12 Stage C (C1b): precompute the "input" DIALOGUE range here (agent_request knows
    ; far_flushed_len / note_len / compacting_msg / far_log_seg_var) so the maxed agent_api_stream phase
    ; just loads + streams it (segment = far_log_seg_var). >64 KB machine: the whole far log, far-log offset
    ; note_len .. far_log_used (= far_flushed_len + used). <=64 KB machine: the seg-0 window
    ; [chat_context_start+note_len .. +used); a model-summarize compaction pass: the WHOLE seg-0 window.
    mov ax, [chat_context_used]
    add ax, [far_flushed_len]
    mov dx, [far_flushed_len + 2]
    adc dx, 0                            ; dx:ax = far_log_used (== used on a seg-0 machine, far_flushed_len 0)
    mov si, [note_len]                   ; default source offset = note_len (far-log relative)
    cmp word [far_log_seg_var], 0
    jne .dlg_off_ready
    add si, chat_context_start           ; seg-0 fallback: the offset is chat_context_start-relative
.dlg_off_ready:
    cmp byte [compacting_msg], 0
    je .dlg_sub_note
    mov si, chat_context_start           ; compaction: stream the WHOLE seg-0 window (note ++ dialogue)
    mov ax, [chat_context_used]
    xor dx, dx
    jmp .dlg_store
.dlg_sub_note:
    sub ax, [note_len]                   ; dialogue excludes the note (it rides "instructions")
    sbb dx, 0
.dlg_store:
    mov [dialogue_off], si
    mov [dialogue_cnt], ax
    mov [dialogue_cnt + 2], dx
    ; Per-request window store cap (read by agent_response/.emit_char): full window normally, halved
    ; on a compaction pass so the captured summary can never exceed 50% -> the post-summary window
    ; stays under the 75% trigger and the endpoint loop runs at most twice.
    mov ax, [chat_context_len_var]
    cmp byte [compacting_msg], 0
    je .cap_full
    shr ax, 1
.cap_full:
    mov [chat_effective_cap], ax
    cmp byte [agent_loop_pending], 0
    jne .skip_prompt_restore             ; agentic auto-continue: dpi_input_buf holds the directive
    call .restore_prompt_from_screen
.skip_prompt_restore:
    call .compute_ready_body_lengths
    jc .request_failed
    mov al, [dpi_input_len_byte]
    mov [api_stream_prompt_len], al
    mov [chat_prompt_len_cache], al
    push ds
    pop es
    mov di, api_request_plain + tls_record_header_len
    mov si, PHASE_LOAD_ADDR + (http_post_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_openai_path_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_version_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_host_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (agent_request_host_openai_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_auth_bearer_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, chat_key_cache
    mov cx, seed_key_len
    call agent_request_phase_append_z_bounded_to_buffer
    jc .request_key_failed
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (http_content_length_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov ax, [api_body_len]
    mov dx, [api_body_len_hi]            ; C1b: the far-log dialogue can push the body past 64 KB
    call .append_u32_decimal
    call agent_request_phase_append_crlf_to_buffer
    call agent_request_phase_append_crlf_to_buffer
    mov si, PHASE_LOAD_ADDR + (api_json_model_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, chat_model_cache
    mov cx, seed_model_len
    call agent_request_phase_append_z_bounded_to_buffer
    jc .request_failed
    ; Build 9 streaming: R builds only chunk 1 = headers + {"model":"<model> . The stream phase
    ; then builds+sends chunk 2 (",reasoning,instructions:"<identity> <ledger>","input":") and
    ; chunk 3 (<prompt>","stream":true}), so no single record must hold the whole prefix.
    ; Content-Length (compute_ready_body_lengths) is the total body across all 3 records.
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    mov [tls_app_total_len], ax
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    cmp ax, api_request_plain_len
    ja .request_too_large
    mov word [handoff_addr + handoff_net_status], 0xb0fe
    clc
    ret
.request_key_failed:
    mov word [handoff_addr + handoff_net_status], 0xb404
    jmp .request_failed
.request_too_large:
    mov word [handoff_addr + handoff_net_status], 0xb505
    jmp .request_failed
.request_failed:
    stc
    ret

.build_openai_body:
    push ds
    pop es
    mov di, fs_sector_buffer
    mov si, PHASE_LOAD_ADDR + (api_json_model_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .reuse_model
    cmp byte [reconnect_retries], 3          ; reconnect: seed_model is handshake-clobbered -> use the cache
    jb .reuse_model
    mov si, seed_model
    call agent_request_phase_append_z_to_buffer
    jmp .model_done
.reuse_model:
    mov si, chat_model_cache
    mov cx, seed_model_len
    call agent_request_phase_append_z_bounded_to_buffer
    jc .body_failed
.model_done:
    ; .build_openai_body runs only on the cold (not-ready) path; the boot greeting stays bare
    ; (no instructions/ledger). The ready chat path builds instructions+ledger inline above.
    mov si, PHASE_LOAD_ADDR + (api_json_input_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov ax, di
    sub ax, fs_sector_buffer
    mov [api_response_pending_len], ax
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    jne .initial_prompt
    mov si, dpi_input_buf
    mov cl, [dpi_input_len_byte]
    xor ch, ch
    call agent_request_phase_append_json_bytes_to_buffer
    jmp .body_close
.initial_prompt:
    mov si, PHASE_LOAD_ADDR + (api_json_boot_prompt_text - PHASE_BASE)
    call agent_request_phase_append_z_to_buffer
    mov si, PHASE_LOAD_ADDR + (api_json_boot_stream_close_text - PHASE_BASE)
    jmp .append_body_close
.body_close:
    mov si, PHASE_LOAD_ADDR + (api_json_stream_close_text - PHASE_BASE)
.append_body_close:
    call agent_request_phase_append_z_to_buffer
    mov ax, di
    sub ax, fs_sector_buffer
    mov [api_body_len], ax
    cmp ax, 512
    ja .body_failed
    clc
    ret
.body_failed:
    mov word [handoff_addr + handoff_net_status], 0xb202
    stc
    ret

.compute_ready_body_lengths:
    ; Build 11 #4 real compaction: measure the ready-request Content-Length. The Build-10 sliding-
    ; window byte-trim is GONE - the window is compacted by a model summarize exchange instead (the
    ; resident endpoint loop fires it when compacting_msg=1; the decision + flag are set in
    ; .build_ready_openai_request above). So this no longer mutates the window; it only sizes the
    ; body. On a compaction pass the input is the WINDOW alone (the floppy-streamed contract rides in
    ; "instructions"); on a normal pass the input adds the user prompt, JSON-escaped. The FULL window
    ; always rides forward.
    push ds
    pop es
    cld
    mov si, chat_model_cache
    mov cx, seed_model_len
    call agent_request_phase_strlen_z_bounded
    jc .body_failed
    mov bx, ax
    cmp byte [compacting_msg], 0
    je .prompt_user
    xor ax, ax                                  ; compaction: the input is the WINDOW alone (the
    jmp .prompt_len_ready                        ; summarize directive rides in "instructions", below)
.prompt_user:
    mov si, dpi_input_buf
    mov cl, [dpi_input_len_byte]
    xor ch, ch
    call agent_request_phase_json_bytes_len
.prompt_len_ready:
    mov dx, ax
    add ax, api_ready_stream_close_text_len
    mov [api_response_pending_len], ax
    mov ax, dx
    add ax, bx
    add ax, api_json_model_text_len + api_ready_stream_close_text_len
    add ax, api_json_reasoning_prefix_len + api_json_input_open_text_len
    ; instructions value = the compaction contract (compaction) OR identity + ledger (normal turn).
    ; Build 11 #4: the contract/identity are streamed off the floppy, so their length is the cached
    ; file size (prompt_compact_size / prompt_id_size), not a compile-time string length. The bytes
    ; stream RAW (control->space, 1:1; no " or \ -> no escape growth), so sent length == file size.
    cmp byte [compacting_msg], 0
    je .instr_normal
    ; Compaction: instructions = the floppy contract + the seed-appended dynamic char targets
    ; " Target about <N> characters, at most <M>." (N = window/4, M = window/2). The fixed text is a
    ; constant; the two decimals vary, so size them with .u16_decimal_len (bx holds the running body
    ; while the digit counts are computed). Must match exactly what the stream phase renders.
    add ax, [prompt_compact_size]
    add ax, api_compaction_targets_fixed_len
    mov bx, ax
    mov ax, [chat_context_len_var]
    shr ax, 1
    shr ax, 1                            ; N = window/4
    call .u16_decimal_len
    add bx, ax
    mov ax, [chat_context_len_var]
    shr ax, 1                            ; M = window/2
    call .u16_decimal_len
    add bx, ax
    mov ax, bx
    jmp .instr_done
.instr_normal:
    add ax, [prompt_id_size]
    add ax, api_ledger_len
    ; Build 11 #4 note-as-memory: a normal turn also carries the running note in "instructions" behind
    ; a fixed label (when a note exists). The note's bytes are part of the window-escaped count below
    ; (the window = note ++ dialogue), so only the LABEL is extra here.
    cmp word [note_len], 0
    je .instr_done
    add ax, api_note_label_text_len
.instr_done:
    ; Build 9: the window rides JSON-ESCAPED, so Content-Length must count it ESCAPED (else a quote/
    ; backslash-bearing window under-counts and truncates the sent body). Build 11 #4: the window now
    ; splits into the note (-> "instructions") and the dialogue (-> "input"), but escaping is per-char
    ; so escape(note)+escape(dialogue) == escape(window); counting the whole window here is still exact
    ; for both fields combined. Keep the RAW count for the fill threshold. (WORD throughout.)
    ; Build 12 Stage C (C1b): the dialogue streamed is the WHOLE far log -- the frozen history plus the
    ; live seg-0 window -- so its escaped length is far_flushed_esc (the frozen part, a running DWORD)
    ; plus the escaped current window. That can exceed 64 KB, so carry into the 32-bit body total
    ; (api_body_len_hi:api_body_len). far_flushed_esc is 0 until the first flush -> identical to C1a.
    mov si, chat_context_start
    mov cx, [chat_context_used]
    push ax                             ; body-so-far (fixed prefix/identity/ledger, < 64 KB)
    call agent_request_phase_json_bytes_len   ; ax = current window length JSON-escaped (clc; bx kept)
    pop dx                             ; body-so-far
    xor bx, bx                          ; high word of the body total
    add ax, dx                          ; + escaped window (could just cross 64 KB on a huge window)
    adc bx, 0
    add ax, [far_flushed_esc]           ; + the frozen far-log dialogue (escaped, DWORD)
    adc bx, [far_flushed_esc + 2]
    mov [api_body_len_hi], bx
    ; Build 10: model-recap compaction REMOVED. On a compaction turn the renderer used to suppress
    ; the reply's first line (an invisible "recap") until the first newline; but a longer open-ended
    ; reply lacks that recap+newline shape, so the WHOLE answer got suppressed -> a real ~1.5 KB
    ; answer arrived on the wire yet the screen stayed blank -> silent return to DPI (reproduced
    ; 2026-06-06 on "tell me more about that" turns). The directive also provoked history-repeating.
    ; Now the window simply grows to its cap and resets on overflow (agent_api_stream_append_prompt_
    ; to_context); the reply always renders. compact_next stays 0 here; only a tool '$' line raises
    ; it (agent_response.inc), never compaction. cx (raw window count) is now unused here.
    mov byte [compact_next], 0
    mov [api_body_len], ax
    clc
    ret

.restore_prompt_from_screen:
    ; Refresh dpi_input_buf (== tls_rx_copy, clobbered by a reconnect's receives) from the
    ; durable on-screen copy of the prompt, using api_stream_prompt_len (captured before any
    ; receive in prepare_agent_endpoint_path). Harmless on the first build (the screen matches
    ; what DPI captured); repairs the clobbered prompt on a reconnect rebuild. Mirrors the proven
    ; split-tail screen read (agent_api_stream_append_prompt_screen_to_buffer) but copies raw
    ; bytes (no JSON escaping) into dpi_input_buf.
    push es
    mov al, [chat_resend_prompt_len]
    mov [dpi_input_len_byte], al
    or al, al
    jz .restore_done
    xor ah, ah
    mov cx, ax
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
    mov di, dpi_input_buf
    mov dl, dpi_prompt_col + 2
.restore_next:
    mov al, [es:si]
    mov [di], al
    inc di
    inc si
    inc si
    inc dl
    cmp dl, [screen_cols]
    jb .restore_same_row
    mov dl, dpi_prompt_col + 2
    add si, (dpi_prompt_col + 2) * 2
.restore_same_row:
    loop .restore_next
.restore_done:
    pop es
    ret

; The screen-scan capture (capture_summary_from_screen) is gone: the recap-first compaction
; captures the model's recap directly in the renderer (agent_response.inc .emit_char) and never
; draws it, so there is nothing to scan back off the screen.

.append_u32_decimal:
    ; dx:ax = u32 -> variable-width decimal at [es:di]. Build 12 Stage C (C1b): Content-Length must span
    ; the full far-log dialogue, which grows past 64 KB -> a 32-bit value. Divide dx:ax by 10 repeatedly
    ; (the textbook 32-by-16 long division: high/10, then (high%10):low / 10), pushing each remainder
    ; digit; a sentinel (10, never a remainder) marks the stack bottom so the emit loop knows when to
    ; stop without a separate counter. Preserves bx/cx; clobbers ax (the value) + dx.
    push cx
    push bx
    mov cx, 10
    push cx                             ; sentinel (10) under the digits
.u32_div:
    mov bx, ax                          ; low word
    mov ax, dx                          ; high word
    xor dx, dx
    div cx                              ; ax = high/10, dx = high%10
    xchg ax, bx                         ; bx = high quotient, ax = low word, dx = high%10
    div cx                              ; ax = low quotient, dx = remainder (the next digit)
    push dx
    mov dx, bx                          ; quotient = dx:ax
    test ax, ax
    jnz .u32_div
    test dx, dx
    jnz .u32_div
.u32_emit:
    pop ax
    cmp ax, 10                          ; hit the sentinel?
    je .u32_emit_done
    add al, '0'
    stosb
    jmp .u32_emit
.u32_emit_done:
    pop bx
    pop cx
    ret
.u16_decimal_len:
    ; ax = u16 -> ax = its decimal digit count (1-5). Build 11 #4: lets compute_ready_body_lengths
    ; size the dynamic char targets (N, M) into Content-Length exactly, without rendering them.
    ; Preserves bx; clobbers cx, dx.
    push bx
    xor bx, bx                          ; digit count
    mov cx, 10
.dl_loop:
    inc bx
    xor dx, dx
    div cx                              ; ax /= 10
    or ax, ax
    jnz .dl_loop
    mov ax, bx
    pop bx
    ret

http_post_text db 'POST ', 0
http_openai_path_text db '/v1/responses', 0
http_version_text db ' HTTP/1.1', 13, 10, 0
http_host_text db 'Host:', 0
http_auth_bearer_text db 'Authorization:Bearer ', 0
http_content_length_text db 'Content-Length:', 0
agent_request_host_openai_text db 'api.openai.com', 0
api_json_model_text db '{"model":"', 0
api_json_model_text_len equ $ - api_json_model_text - 1
api_json_input_text db '","input":"', 0
api_json_input_text_len equ $ - api_json_input_text - 1
; Build 9: the tiered ready input-prefix templates were removed; identity+ledger + the
; instructions/input-open templates now live in agent_api_stream.inc (built/sent as chunk 2).
api_json_boot_prompt_text db 'Greet.', 0
api_json_boot_stream_close_text db '","stream":true}', 0
api_json_stream_close_text db '","stream":true}', 0
api_json_stream_close_text_len equ $ - api_json_stream_close_text - 1
api_ready_stream_close_text_len equ api_json_stream_close_text_len

agent_request_phase_strlen_z_bounded:
    xor dx, dx
.strlen_next:
    jcxz .strlen_failed
    lodsb
    or al, al
    jz .strlen_done
    inc dx
    loop .strlen_next
.strlen_failed:
    stc
    ret
.strlen_done:
    mov ax, dx
    clc
    ret

agent_request_phase_json_bytes_len:
    xor dx, dx
    jcxz .json_len_done
.json_len_next:
    lodsb
    cmp al, '"'
    je .json_len_escape
    cmp al, '\'
    je .json_len_escape
    inc dx
    loop .json_len_next
    jmp .json_len_done
.json_len_escape:
    inc dx
    inc dx
    loop .json_len_next
.json_len_done:
    mov ax, dx
    clc
    ret

agent_request_phase_append_z_to_buffer:
    lodsb
    or al, al
    jz .done
    stosb
    jmp agent_request_phase_append_z_to_buffer
.done:
    ret

agent_request_phase_append_z_bounded_to_buffer:
    jcxz .failed
    lodsb
    or al, al
    jz .done
    stosb
    loop agent_request_phase_append_z_bounded_to_buffer
.failed:
    stc
    ret
.done:
    clc
    ret

agent_request_phase_append_crlf_to_buffer:
    mov al, 13
    stosb
    mov al, 10
    stosb
    ret

agent_request_phase_append_json_bytes_to_buffer:
    jcxz .done
.next:
    lodsb
    cmp al, '"'
    je .escape
    cmp al, '\'
    je .escape
    cmp al, 32
    jb .space
    stosb
    loop .next
    ret
.escape:
    mov ah, al
    mov al, '\'
    stosb
    mov al, ah
    stosb
    loop .next
    ret
.space:
    mov al, ' '
    stosb
    loop .next
.done:
    ret

%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif
