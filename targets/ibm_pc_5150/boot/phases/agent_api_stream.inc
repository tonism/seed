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
    mov ax, (((core_splash_phase_end - core_splash_phase_start + 511) / 512) << 8) | ((core_splash_phase_start - $$) / 512)
    mov bx, low_scratch_start
    phase_call_res run_core_phase_at
    jc .failed
    mov byte [cursor_row], dpi_prompt_row - 2
    mov byte [cursor_col], dpi_prompt_col
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
    ; Build 9 chunk 2: ",reasoning,instructions:"<identity> <ledger>","input":" - built here (not
    ; in the request phase) so the ledger rides a record of its own; the body spans 3 TLS records.
    mov di, api_request_plain + tls_record_header_len
    mov si, PHASE_LOAD_ADDR + (api_json_instructions_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    call agent_api_stream_append_ledger
    cmp byte [compact_next], 0
    je .no_compact_directive
    mov si, PHASE_LOAD_ADDR + (api_json_compact_directive_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
.no_compact_directive:
    mov si, PHASE_LOAD_ADDR + (api_json_input_open_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    phase_call_res tls_prepare_3c501_receive
    phase_call_res tls_send_application_data_current_seq
    jc .prefix_failed
.tail_pending:
    pop ax
    mov [api_stream_prompt_len], al
    or al, al
    je .done
    mov di, api_request_plain + tls_record_header_len
    call agent_api_stream_append_context
    jc .failed
    call agent_api_stream_append_prompt_screen_to_buffer
    jc .failed
    mov si, PHASE_LOAD_ADDR + (api_stream_json_close_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len

.send_tail:
    or ax, ax
    jz .done
    cmp ax, api_request_plain_len
    ja .failed
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    phase_call_res tls_prepare_3c501_receive
    phase_call_res tls_send_application_data_current_seq
    jc .failed
    phase_call_res tls_prepare_3c501_receive
    cmp byte [compact_next], 0
    je .accumulate_prompt
    mov word [chat_context_used], 0    ; compaction turn: clear the window; the recap (captured by
    jmp .done                          ; the renderer until the first newline) replaces the history
.accumulate_prompt:
    call agent_api_stream_append_prompt_to_context
.done:
    cmp byte [compact_next], 0
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
    mov word [api_response_pending_len], 0
    mov word [api_body_len], 0
    mov byte [chat_prompt_len_cache], 0
    mov byte [api_stream_state], 0
    mov byte [api_stream_delta_match], 0
    mov byte [api_stream_seen], 0
    mov byte [api_stream_text_seen], 0
    mov byte [api_stream_completed], 0
    mov byte [api_http_state], 0
    mov byte [api_http_header_match], 0
    clc
    ret

.prefix_failed:
    pop ax
.failed:
    stc
    ret

api_stream_json_close_text db '","stream":true}', 0
api_stream_json_close_text_len equ $ - api_stream_json_close_text - 1

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
    push es
    mov al, [api_stream_prompt_len]
    mov [api_http_state], al
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .segment_ready
    mov ax, 0xb000
.segment_ready:
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
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .screen_flush_seg
    mov ax, 0xb000
.screen_flush_seg:
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
; own (not only when the user spells the syntax). Terse on purpose - chunk 2 (this +
; ledger + the compaction directive + input-open) must stay under ~616 B so it does not
; overflow the record buffer into critical scratch on a compaction turn (measured: ~603 B
; worst case, ~13 B margin). Each call on its own line keeps the streamed command tidy.
api_json_instructions_text db '","reasoning":{"effort":"high"},"instructions":"Concise: a few sentences unless asked for detail. Factual, professional. ASCII only - map non-ASCII to nearest ASCII (hyphens for dashes, straight quotes); no JSON. RAM tools, hex: $r ADDR LEN read, $w ADDR BYTES write, $x ADDR run. ', 0
api_json_instructions_text_len equ $ - api_json_instructions_text - 1
api_json_input_open_text db '","input":"', 0
api_json_input_open_text_len equ $ - api_json_input_open_text - 1
; Build 9 (invisible compaction): appended to instructions only when compact_next is armed. Asks
; the model to put a one-line recap FIRST (then a newline, then the answer); the renderer captures
; that recap straight into the window until the first newline and never draws it. JSON-safe.
api_json_compact_directive_text db 'First output ONE line (max 80 chars): ALL facts the user shared so far - NOT system details already in your instructions (memory, RAM, IP, NIC) - then a newline, then answer. ', 0
api_json_compact_directive_text_len equ $ - api_json_compact_directive_text - 1

; Build 9 ledger field labels (terse machine facts serialized from the handoff block)
api_ledger_ram_text db 'ram=', 0
api_ledger_ip_text db ' ip=', 0
api_ledger_gw_text db ' gw=', 0
api_ledger_dns_text db ' dns=', 0
api_ledger_mask_text db ' mask=', 0
api_ledger_fam_text db ' fam=', 0
api_ledger_nic_text db ' nic@', 0
api_ledger_irq_text db ' irq=', 0
api_ledger_mac_text db ' mac=', 0
; Build 9 (Phase 3b): the context-management knobs (window/arena/threshold) are documented in
; HANDOFF.md but NOT advertised in the ledger yet - doing so before a memory-write tool exists
; (Build 10) makes the model hallucinate memory-write tool calls. Deferred to Build 10.
; Fixed-width ledger -> constant serialized length (for Content-Length). Labels (minus 9 NULs)
; + ram hex16(4) + ip/gw/dns/mask dotted(4*15) + fam dec8(3) + nic hex16(4) + irq dec8(3) + mac(12).
api_ledger_labels_len equ $ - api_ledger_ram_text - 9
api_ledger_len equ api_ledger_labels_len + (4 + 4 * 15 + 3 + 4 + 3 + 12)

; ---- Build 9 ledger: terse machine-facts serialization of the handoff block ----
; Appends "ram=<hex> ip/gw/dns/mask=<dotted> fam=<dec> nic@<hex> irq=<dec> mac=<hex>" to [es:di]
; from the resident handoff (0x0600). es must equal ds. Clobbers ax/cx/dx/si; advances di.
agent_api_stream_append_ledger:
    mov si, PHASE_LOAD_ADDR + (api_ledger_ram_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov ax, [handoff_addr + handoff_ram_top]
    call agent_api_stream_ledger_hex16
    mov si, PHASE_LOAD_ADDR + (api_ledger_ip_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, handoff_addr + handoff_ip_addr
    call agent_api_stream_ledger_dotted
    mov si, PHASE_LOAD_ADDR + (api_ledger_gw_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, handoff_addr + handoff_router_addr
    call agent_api_stream_ledger_dotted
    mov si, PHASE_LOAD_ADDR + (api_ledger_dns_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, handoff_addr + handoff_dns_addr
    call agent_api_stream_ledger_dotted
    mov si, PHASE_LOAD_ADDR + (api_ledger_mask_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, handoff_addr + handoff_subnet_addr
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
    mov si, PHASE_LOAD_ADDR + (api_ledger_mac_text - PHASE_BASE)
    call agent_api_stream_append_z_to_buffer
    mov si, handoff_addr + handoff_mac
    mov cx, 6
.ledger_mac_loop:
    push cx
    lodsb
    call agent_api_stream_ledger_hex8
    pop cx
    loop .ledger_mac_loop
    ret

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

; ---- Build 9 conversation context (Phase 3): carry the recent prompt into the next input ----
agent_api_stream_append_context:        ; copy the window (RAW) into [es:di], JSON-escaped, FLUSHING
    mov cx, [chat_context_used]          ; full TLS records as the buffer fills - a big-RAM window can
    jcxz .ctx_ok                         ; exceed one record. es=ds (buffer in ds); the source is ds:si
    mov si, chat_context_start           ; (not video like the prompt flush), and tls_send leaves es=ds.
.ctx_next:
    cmp di, api_request_plain + tls_record_header_len + api_request_plain_len - 2
    jae .ctx_flush                       ; leave room for one escaped pair before the payload cap
    lodsb
    cmp al, '"'
    je .ctx_escape
    cmp al, '\'
    je .ctx_escape
    cmp al, 32
    jb .ctx_space
    stosb
    loop .ctx_next
    jmp .ctx_ok
.ctx_escape:
    mov ah, al
    mov al, '\'
    stosb
    mov al, ah
    stosb
    loop .ctx_next
    jmp .ctx_ok
.ctx_space:
    mov al, ' '
    stosb
    loop .ctx_next
.ctx_ok:
    clc
    ret
.ctx_flush:                              ; buffer full mid-window: send it as a record, reset di, resume
    push cx
    push si
    mov ax, di
    sub ax, api_request_plain + tls_record_header_len
    mov [tls_app_len], ax
    mov word [tls_app_plain_ptr], api_request_plain + tls_record_header_len
    phase_call_res tls_prepare_3c501_receive
    phase_call_res tls_send_application_data_current_seq
    jc .ctx_flush_failed
    phase_call_res tls_prepare_3c501_receive
    pop si
    pop cx
    mov di, api_request_plain + tls_record_header_len
    jmp .ctx_next
.ctx_flush_failed:
    pop si
    pop cx
    stc
    ret
agent_api_stream_append_prompt_to_context:   ; accumulate the just-sent prompt (RAW) for later turns
    mov al, [api_stream_prompt_len]
    or al, al
    je .ctx_store_done
    ; Stored raw (escaped only at send), so the real length is the prompt length + separator.
    xor ah, ah
    mov bx, ax
    inc bx
    mov ax, [chat_context_used]
    add bx, ax
    cmp bx, [chat_context_len_var]
    jbe .ctx_fits
    ; Window full: drop the history and start over with this prompt (overflow fallback; model-
    ; compaction fires earlier at the threshold). Re-check the lone prompt fits.
    mov word [chat_context_used], 0
    mov al, [api_stream_prompt_len]
    xor ah, ah
    mov bx, ax
    inc bx
    cmp bx, [chat_context_len_var]
    ja .ctx_store_done                  ; single prompt too big for the window -> skip
.ctx_fits:
    mov di, chat_context_start
    mov ax, [chat_context_used]
    add di, ax                          ; append at the used offset (accumulate, don't replace)
    mov si, dpi_input_buf               ; raw prompt (intact: accumulation runs before the receive)
    mov cl, [api_stream_prompt_len]
    xor ch, ch
    rep movsb
    mov al, ' '
    stosb
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
    mov bx, color_video_seg
    mov dl, 0x08
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .compacting_seg
    mov bx, 0xb000
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
    mov byte [cursor_row], dpi_prompt_row - 1
.compacting_adv_inc:
    inc byte [cursor_row]
    ret
api_compacting_text db 'compacting context', 0

%unmacro phase_call_res 1
