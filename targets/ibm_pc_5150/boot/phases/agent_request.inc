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
%ifdef TLS13_PRODUCT_TLS13
    ; Product TLS 1.3 is OpenAI-only and the secure route deliberately
    ; overwrites the original seed-config scratch.  prepare_agent_path has
    ; already validated the selected interface and copied model/key into the
    ; reconnect-safe cache, so every cold, restored-ENV, and reconnect request
    ; follows the same source path.
%else
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .session_ready
    ; A RECONNECT (reconnect_retries<3) reuses the cold connect's cached config: seed_* was read on the
    ; first attempt and is now handshake-clobbered (it overlays the TLS PRF scratch -- tls_server_random
    ; equ seed_agent_id), so the agent was already validated on attempt 1; skip the (now-garbage) recheck.
    cmp byte [reconnect_retries], 3
    jb .session_ready
    call .selected_agent_is_openai
    jc .failed
%endif
.session_ready:
    jmp .build_openai_request
%ifndef TLS13_PRODUCT_TLS13
.failed:
    stc
    ret
%endif

%ifdef TLS13_PRODUCT_TLS13
; The 16 KiB path streams request sources after the R phase has been replaced
; above 0x0900 by X.  Keep these entries in R's surviving first sector.  The
; inputs entry deliberately ignores stale boot-time dialogue metadata. R
; recomputes it, then X performs the full check immediately before its first
; TLS record. Larger/far tiers retain their existing 32-bit stream geometry.
.validate_stream_bounds:
    call .validate_stream_inputs
    jc .bounds_done
    jnz .validate_product_prefix       ; non-16K tier: ZF=0 from the RAM-top compare
    mov ax, [dialogue_cnt + 2]
    or ax, ax
    jnz .bounds_failed
    mov ax, [dialogue_cnt]
    or ax, ax
    jz .bounds_ok
    mov dx, [dialogue_off]
    cmp dx, chat_context_start
    jb .bounds_failed
    add dx, ax
    jc .bounds_failed
    cmp dx, chat_context_end
    ja .bounds_failed
.bounds_ok:
; Every X-phase first record is the HTTP prefix R just built in the fixed
; request body.  tls_build_application_data_record caps the length, but its
; source pointer is otherwise trusted; reject a stale pointer (or an empty
; prefix) before it can disclose an arbitrary resident-memory slice.
.validate_product_prefix:
    clc
.bounds_done:
    ret
.bounds_failed:
    stc
    ret

.validate_stream_inputs:
    cmp word [handoff_addr + handoff_ram_top], basic_sidecar_stack_top_16k
    jne .bounds_done                   ; non-16K compare preserves CF/ZF
    cmp word [prompt_tools_size], tools_schema_max_len
    ja .bounds_failed
    cmp word [prompt_id_size], 512
    ja .bounds_failed
    cmp word [prompt_compact_size], 512
    ja .bounds_failed
    cmp word [chat_context_len_var], chat_context_len
    jne .bounds_failed
    mov ax, [chat_context_used]
    cmp ax, chat_context_len
    ja .bounds_failed
    cmp [note_len], ax
    ja .bounds_failed
    mov ax, [far_log_seg_var]
    or ax, [far_flushed_len]
    or ax, [far_flushed_len + 2]
    or ax, [far_flushed_esc]
    or ax, [far_flushed_esc + 2]
    jnz .bounds_failed
    ret                                 ; zero OR leaves CF=0/ZF=1 to the full entry

%if ($ - PHASE_BASE) > (net_setup_phase_start - low_scratch_start)
%error "16K request stream validator is outside R's X-surviving sector"
%endif
%endif

%ifndef TLS13_PRODUCT_TLS13
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
%endif

.build_openai_request:
    ; These response fields are deliberately paired in the arena. Clear the
    ; five adjacent pairs as words: R has a hard three-sector ceiling, and the
    ; saved bytes fund the required application/json request header without
    ; taking memory from the 16 KiB arena/context contract.
    xor ax, ax
%ifdef TLS13_PRODUCT_TLS13
    ; Only executed output survives a new request. Partial/frozen unexecuted
    ; captures belong to the failed response, never to its bounded retry.
    cmp byte [tool_fc_state], 2
    je .response_state_ready
    mov [tool_fc_state], al
.response_state_ready:
%endif
    mov [api_response_pending_len], ax
    mov [api_stream_text_seen], ax       ; also api_stream_prompt_len
    mov [api_stream_state], ax           ; also api_stream_delta_match
    mov [api_stream_seen], ax            ; also api_stream_completed
    mov [api_http_state], ax             ; also api_http_header_match
    mov [esc_stop], al                   ; per-turn graceful-stop reset
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .build_ready_openai_request
    ; The greeting has no dialogue source. Do not carry boot scratch into
    ; X's final source-bounds check before its first authenticated request.
    mov [dialogue_off], ax
    mov [dialogue_cnt], ax
    mov [dialogue_cnt + 2], ax
    mov [dpi_prompt_marker_row], al
    mov [api_stream_event_ready], al
    mov [chat_prompt_len_cache], al
    jmp .build_h2_headers
.build_ready_openai_request:
    ; Promote a captured summary before checking its new range: it may be
    ; shorter than the previous note. A pending, no-output compaction still
    ; owns the original dialogue and must retry that same request unchanged.
%ifdef TLS13_PRODUCT_TLS13
    cmp byte [compacting_msg], 2
    jne .note_len_kept
%else
    cmp byte [compacting_msg], 0
    je .note_len_kept
%endif
    mov ax, [chat_context_used]
    mov [note_len], ax
.note_len_kept:
%ifdef TLS13_PRODUCT_TLS13
    call .validate_stream_inputs
    jc .request_failed
    cmp byte [compacting_msg], 1
    je .start_compaction_pass
%endif
    ; Uniform compaction policy: every tier compacts when its active context reaches the 75% trigger.
    ; <=64 KB uses the seg-0 window directly. >64 KB still uses the small seg-0 window as a staging tail
    ; and freezes that tail into the far log when the staging window fills, but model compaction is
    ; triggered from the full far-log fullness, not from the machine class.
    mov byte [compacting_msg], 0
    cmp byte [tool_fc_state], 2
    je .not_compaction_pass              ; tool convention: function_call_output must be immediate
    mov al, [compact_next]
    mov byte [compact_next], 0
    or al, al
    jnz .start_compaction_if_used
    cmp word [far_log_seg_var], 0
    je .check_low_window
    call .far_context_over_threshold
    jnc .start_compaction_pass
.check_low_window:
    mov ax, [chat_context_used]
    or ax, ax
    jz .check_threshold
    xor bh, bh
    mov bl, [chat_resend_prompt_len]
    or bx, bx
    jz .check_threshold
    add bx, api_json_user_label_text_len + api_json_you_label_text_len
    add ax, bx
    cmp ax, [chat_context_len_var]
    jbe .check_threshold
    ; After a successful compaction, a tiny 16K window may still not have room
    ; for note + pending prompt. Let the real turn run and rely on the response
    ; store's note-preserving slide; otherwise the same note compacts forever.
    cmp word [note_len], 0
    jne .check_threshold
    jmp .low_window_full
.check_threshold:
    mov ax, [chat_context_used]
    cmp ax, [chat_compact_threshold]
    jb .not_compaction_pass
.low_window_full:
    cmp word [far_log_seg_var], 0
    jne .flush_low_window
.start_compaction_if_used:
    mov ax, [chat_context_used]
    or ax, ax
    jz .not_compaction_pass
.start_compaction_pass:
    mov byte [compacting_msg], 1
    jmp .not_compaction_pass
.flush_low_window:
    mov ax, [chat_context_used]
    push ax
    call .context_base_si
    mov cx, ax
    call agent_request_phase_json_bytes_len   ; ax = escaped length of the window being frozen
    add [far_flushed_esc], ax
    adc word [far_flushed_esc + 2], 0
    pop ax
    add [far_flushed_len], ax
    adc word [far_flushed_len + 2], 0
    mov word [chat_context_used], 0
    jmp .not_compaction_pass
.not_compaction_pass:
    ; Build 12 Stage C (C1b): precompute the "input" DIALOGUE range here (agent_request knows
    ; far_flushed_len / note_len / compacting_msg / far_log_seg_var) so the maxed agent_api_stream phase
    ; just loads + streams it (segment = far_log_seg_var). >64 KB machine: the whole far log, far-log offset
    ; note_len .. far_log_used (= far_flushed_len + used). <=64 KB machine: the seg-0 context window
    ; [context_base+note_len .. +used).
    mov ax, [chat_context_used]
    add ax, [far_flushed_len]
    mov dx, [far_flushed_len + 2]
    adc dx, 0                            ; dx:ax = far_log_used (== used on a seg-0 machine, far_flushed_len 0)
    mov si, [note_len]                   ; default source offset = note_len (far-log relative)
    cmp word [far_log_seg_var], 0
    jne .dlg_off_ready
    call .context_base_bx
    add si, bx                           ; seg-0 fallback: absolute low context pointer
.dlg_off_ready:
    cmp byte [compacting_msg], 0
    je .dlg_sub_note
    cmp word [far_log_seg_var], 0
    jne .dlg_compact_far
    call .context_base_si                ; compaction: stream the WHOLE seg-0 window (note ++ dialogue)
    mov ax, [chat_context_used]
    xor dx, dx
    jmp .dlg_store
.dlg_compact_far:
    xor si, si                           ; compaction: stream the WHOLE far log (frozen ++ live mirror)
    mov ax, [far_flushed_len]
    mov dx, [far_flushed_len + 2]
    add ax, [chat_context_used]
    adc dx, 0
    jmp .dlg_store
.dlg_sub_note:
    sub ax, [note_len]                   ; dialogue excludes the note (it rides "instructions")
    sbb dx, 0
.dlg_store:
    mov [dialogue_off], si
    mov [dialogue_cnt], ax
    mov [dialogue_cnt + 2], dx
%ifdef TLS13_PRODUCT_TLS13
.dialogue_bounds_ready:
%endif
    ; Per-request window store cap (read by agent_response/.emit_char): full window normally, halved
    ; on a compaction pass so the captured summary can never exceed 50% -> the post-summary window
    ; stays under the 75% trigger and the endpoint loop runs at most twice.
    mov ax, [chat_context_len_var]
    cmp byte [compacting_msg], 0
    je .cap_full
    shr ax, 1
.cap_full:
    mov [chat_effective_cap], ax
    mov al, [chat_resend_prompt_len]
    mov [api_stream_prompt_len], al
    mov [chat_prompt_len_cache], al
    cmp byte [compacting_msg], 0
    je .prompt_cache_ready
    ; A compaction response has no real user prompt to append, but the renderer
    ; uses chat_prompt_len_cache as the one-shot "store prefix/reset done" flag.
    ; Force it clear so the first summary byte resets chat_context_used.
    mov byte [chat_prompt_len_cache], 0
.prompt_cache_ready:
    call .validate_stream_bounds
    jc .request_failed
    jmp .build_h2_headers
.request_key_failed:
    mov word [handoff_addr + handoff_net_status], 0xb404
    jmp .request_failed
.request_too_large:
    mov word [handoff_addr + handoff_net_status], 0xb505
    jmp .request_failed
.request_failed:
    stc
    ret


.build_h2_headers:
    push ds
    pop es
    cld
    ; R still occupies three file sectors. Copy its immutable third sector
    ; into unloaded K headroom before X replaces the low R image.
    mov si, PHASE_LOAD_ADDR+1024
    mov di, 0x2800
    mov cx, 256
    rep movsw
    mov di, api_request_plain+14
    mov si, PHASE_LOAD_ADDR+(.hpack_fields-PHASE_BASE)
    mov cx, .hpack_fields_end-.hpack_fields
    rep movsb
    mov si, chat_key_cache
    mov cx, seed_key_len
    call agent_request_phase_strlen_z_bounded
    jc .request_key_failed
    or ax, ax
    jz .request_key_failed
    mov bx, ax
    add ax, 7                         ; 'Bearer ' plus bounded key
    cmp ax, 127
    jb .length
    mov dl, al
    mov al, 127
    stosb
    mov al, dl
    sub al, 127
.length:
    stosb
    mov si, PHASE_LOAD_ADDR+(.bearer-PHASE_BASE)
    mov cx, 7
    rep movsb
    mov si, chat_key_cache
    mov cx, bx
    rep movsb
    mov ax, di
    sub ax, api_request_plain+5
    cmp ax, 436
    ja .request_too_large
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain+5
    sub ax, 9
    mov di, api_request_plain+5
    mov byte [di], 0
    inc di
    xchg al, ah
    stosw
    mov ax, 0x0401                    ; HEADERS, END_HEADERS, no END_STREAM
    stosw
    mov ax, [0x062e+22]
    mov dx, [0x062e+20]
    xchg al, ah
    xchg dl, dh
    mov cx, ax
    or cx, dx
    jnz .next_stream
    mov ax, 1
    jmp short .stream
.next_stream:
    add ax, 2
    adc dx, 0
    test dh, 0x80
    jnz .request_failed
.stream:
    xchg al, ah
    xchg dl, dh
    mov [di], dx
    mov [di+2], ax
    clc
    ret
.hpack_fields:
    db 0x83,0x87                       ; POST, https
    db 0x01,14,'api.openai.com'
    db 0x04,13,'/v1/responses'
    db 0x0f,0x10,16,'application/json'
    db 0x1f,0x08                       ; authorization, never indexed
.hpack_fields_end:
.bearer db 'Bearer '

.far_context_over_threshold:
    ; CF clear means compact: far_used >= 3/4 far_window_cap. CF set means keep accumulating.
    mov ax, [far_flushed_len]
    mov dx, [far_flushed_len + 2]
    add ax, [chat_context_used]
    adc dx, 0
    or ax, ax
    jnz .fc_used
    or dx, dx
    jz .fc_below
.fc_used:
    push ax
    push dx
%ifdef SEED_TEST_FAR_COMPACT_THRESHOLD
    mov bx, (SEED_TEST_FAR_COMPACT_THRESHOLD & 0xffff)
    mov cx, (SEED_TEST_FAR_COMPACT_THRESHOLD >> 16)
%else
    mov ax, [far_window_cap]
    mov dx, [far_window_cap + 2]
    shr dx, 1
    rcr ax, 1                            ; window/2
    mov bx, ax
    mov cx, dx
    mov ax, [far_window_cap]
    mov dx, [far_window_cap + 2]
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1                            ; window/4
    add ax, bx
    adc dx, cx                           ; dx:ax = 3/4 window
    mov bx, ax
    mov cx, dx
%endif
    pop dx
    pop ax                               ; dx:ax = far_used
    cmp dx, cx
    ja .fc_compact
    jb .fc_below
    cmp ax, bx
    jae .fc_compact
.fc_below:
    stc
    ret
.fc_compact:
    clc
    ret

.context_base_si:
    call .context_base_bx
    mov si, bx
    ret
.context_base_bx:
    mov bx, [handoff_addr + handoff_ram_top]
    sub bx, 0x100
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .ctx_base_ready
    mov bx, tools_cache
.ctx_base_ready:
    sub bx, [chat_context_len_var]
    ret

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

%unmacro phase_call_res 1

%ifdef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR_DEFAULTED
%undef PHASE_LOAD_ADDR
%endif

%if ($-PHASE_BASE)>1024
%error "H2 R state/header producer exceeds two sectors before request helper"
%endif
times 1024-($-PHASE_BASE) db 0
incbin "request-aux-sector.bin"
