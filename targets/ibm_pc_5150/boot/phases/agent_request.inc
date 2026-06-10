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
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .session_ready
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
    call .append_u16_decimal
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
    ; Build 11 #4 real compaction: decide PER PASS whether this request is a compaction summarize
    ; exchange. When the carried window has reached the 75% trigger (chat_compact_threshold), set
    ; compacting_msg=1 -> this request streams the FULL window + the summarize directive (in place
    ; of the user prompt), the reply is captured AS the new window (agent_response/.emit_char, hard-
    ; capped at 50%), and the resident endpoint loop re-enters for the real turn. Below 75% it is a
    ; normal turn (compacting_msg=0). The 50% capture cap keeps the post-summary window < 75%, so the
    ; loop runs at most twice. Replaces the Build-10 sliding-window byte-trim (deleted below).
    mov byte [compacting_msg], 0
    mov ax, [chat_context_used]
    cmp ax, [chat_compact_threshold]
    jb .not_compaction_pass
    mov byte [compacting_msg], 1
.not_compaction_pass:
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
    call .append_u16_decimal
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
    mov si, chat_context_start
    mov cx, [chat_context_used]
    push ax                             ; body-so-far
    push cx                             ; raw window count
    call agent_request_phase_json_bytes_len   ; ax = window length JSON-escaped (clc; cx->0; bx kept)
    pop cx                              ; raw window count (the fill measure)
    pop dx                             ; body-so-far
    add ax, dx                          ; body + escaped window
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
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .restore_seg_ready
    mov ax, 0xb000
.restore_seg_ready:
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

.append_u16_decimal:
    ; ax = u16 -> variable-width decimal at [es:di]. Build 11 #4: was a 3-digit-only renderer (div by
    ; 100 then 10, max 999) - fine while the old window-trim + tiny directive kept every body < 1000,
    ; but the floppy compaction contract pushes a compaction-pass body past 1000 (prefix + ~509 B
    ; contract + targets + the carried window), so Content-Length needs the full u16 range. Pushes the
    ; digits low-to-high, emits them high-to-low. Preserves bx/cx; clobbers ax (the value) + dx.
    push cx
    push bx
    xor cx, cx                          ; digits pushed
    mov bx, 10
.u16_div:
    xor dx, dx
    div bx                              ; dx:ax / 10 -> ax = quotient, dx = next digit
    push dx
    inc cx
    or ax, ax
    jnz .u16_div
.u16_emit:
    pop ax
    add al, '0'
    stosb
    loop .u16_emit
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
