%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

agent_endpoint_phase:
    ; Build 11 never-blank reconnect status (dim, on its own line). net_phase sets reconnect_retries=3
    ; at the top of each turn and decrements it per failed connect; the endpoint phase is the FIRST
    ; phase of the reconnect handshake, so the status lands here BEFORE the ~14.5s crypto, not after.
    ;   retries==0            : the 3x loop is exhausted -> append " failed" to the parked
    ;                           "> reconnect" line, advance a line, and RETURN (this is net_phase's one
    ;                           sacrificial endpoint call; the DNS body is skipped -- we fail out to DPI).
    ;   retries==3 + mid-chat : a reconnect's FIRST attempt -> draw "> reconnect" ONCE and park the
    ;                           cursor after it so the answer (or " failed") appends in place. Retries
    ;                           2/1 re-enter here silently (the ==3 gate), so the line shows once.
    ;   otherwise             : cold connect or a silent retry -> no status; fall through to the body.
    ; "Mid-chat" is gated on chat_context_used > 0, NOT handoff_status (which is ready BEFORE the cold
    ; first connect too -- it could never distinguish loading from a live session, so the loading-time
    ; "> reconnect"/"> recertify" leaked onto the splash). chat_context_used is 0 throughout cold boot:
    ; agent_api_stream sets it only AFTER the first exchange, which runs AFTER this phase -- so the cold
    ; connect and its recertify stay silent during loading, and only a post-greet session shows the line.
    ; (agent_api_stream's session-reuse path still gates on handoff_status==ready, separately.)
    mov al, [reconnect_retries]
    or al, al
    jz .render_reconnect_failed
    cmp byte [recert_flag], 0
    jne .render_recertify
    cmp al, 3
    jne .endpoint_body
    cmp word [chat_context_used], 0
    je .endpoint_body
    cmp byte [render_last_type], render_type_system
    je .rc_drawn
    mov byte [render_last_type], render_type_system
    call .reconnect_advance_line     ; type-change spacing: one blank line before this system status line
.rc_drawn:
    mov byte [cursor_col], dpi_prompt_col
    mov si, low_scratch_start + (reconnect_msg_text - PHASE_BASE)
    mov cx, reconnect_word_len
    call .render_dim_run
    jmp .endpoint_body
.render_recertify:
    ; Build 12 auto-recertify: net_phase set recert_flag because a leaf rotation was detected and the
    ; captured leaf chained to the pinned WR1 (off-race). Show "> recertify" ONLY mid-chat -- a live
    ; session (chat_context_used > 0) where the user is watching. During the cold-boot loading sequence
    ; the recertify is silent (no status line), exactly like "> reconnect"; the dots/splash cover it.
    ; "> recertify" is 11 chars (== "> reconnect"), so a mid-chat recert cleanly overwrites the earlier
    ; "> reconnect" on the same row (reads as one line transitioning reconnect -> recertify).
    cmp word [chat_context_used], 0
    je .endpoint_body
    cmp byte [render_last_type], render_type_system
    je .rec_drawn                    ; already system (e.g. overwriting "> reconnect" in place) -> no blank
    mov byte [render_last_type], render_type_system
    call .reconnect_advance_line     ; type-change spacing: one blank line before this system status line
.rec_drawn:
    mov byte [cursor_col], dpi_prompt_col
    mov si, low_scratch_start + (recertify_msg_text - PHASE_BASE)
    mov cx, recertify_word_len
    call .render_dim_run
    jmp .endpoint_body
.render_reconnect_failed:
    ; The " failed" append belongs to the mid-chat "> reconnect" line -- but on a COLD setup that line was
    ; suppressed (chat_context_used == 0, splash showing), so drawing a bare " failed" here is orphaned
    ; (and redundant with failure_action's "> agent setup failed"). Draw it only mid-chat; cold stays
    ; silent. Either way return CF=1 (the exhaustion signal the cold-setup fatal-screen path relies on).
    cmp word [chat_context_used], 0
    je .reconnect_failed_done
    mov si, low_scratch_start + (reconnect_failed_text - PHASE_BASE)
    mov cx, reconnect_failed_len
    call .render_dim_run
    call .reconnect_advance_line
.reconnect_failed_done:
    stc
    ret
.endpoint_body:
    ; Build 12: OpenAI-only. The other providers (litellm/openrouter/anthropic/google) were never
    ; wired end-to-end (agent_request builds only the openai-responses path) and are removed until
    ; tested, so the DNS/SNI host is always api.openai.com -- the cold connect AND a chat reconnect.
    mov word [tcp_dest_port_word], tcp_port_https_word
    mov si, low_scratch_start + (host_openai_text - PHASE_BASE)
.set_dns_target_from_text:
    call .skip_endpoint_prefix
    cmp byte [si], 0
    je .failed
    mov di, dns_qname
    mov byte [dns_qname_len], 0
.next_label:
    mov [dns_label_ptr], di
    mov byte [di], 0
    inc di
    inc byte [dns_qname_len]
    mov byte [dns_label_len], 0
.next_char:
    lodsb
    or al, al
    jz .finish
    cmp al, 13
    je .finish
    cmp al, 10
    je .finish
    cmp al, ' '
    je .finish
    cmp al, '/'
    je .finish
    cmp al, ':'
    je .finish
    cmp al, '.'
    je .dot
    cmp al, 'A'
    jb .store
    cmp al, 'Z'
    ja .store
    add al, 32
.store:
    cmp byte [dns_label_len], 63
    jae .failed
    cmp byte [dns_qname_len], dns_qname_max_len - 1
    jae .failed
    mov [di], al
    inc di
    inc byte [dns_label_len]
    inc byte [dns_qname_len]
    jmp .next_char
.dot:
    cmp byte [dns_label_len], 0
    je .failed
    call .finish_dns_label
    jmp .next_label
.finish:
    cmp byte [dns_label_len], 0
    je .failed
    call .finish_dns_label
    cmp byte [dns_qname_len], dns_qname_max_len
    jae .failed
    mov byte [di], 0
    inc byte [dns_qname_len]
    call .update_dns_tx_len
    clc
    ret
.failed:
    stc
    ret

.skip_endpoint_prefix:
    mov bx, si
    cmp byte [si], 'h'
    jne .done
    cmp byte [si + 1], 't'
    jne .done
    cmp byte [si + 2], 't'
    jne .done
    cmp byte [si + 3], 'p'
    jne .done
    add si, 4
    cmp byte [si], 's'
    jne .colon
    inc si
.colon:
    cmp byte [si], ':'
    jne .restore
    inc si
    cmp byte [si], '/'
    jne .restore
    inc si
    cmp byte [si], '/'
    jne .restore
    inc si
    ret
.restore:
    mov si, bx
.done:
    ret

.finish_dns_label:
    mov bx, [dns_label_ptr]
    mov al, [dns_label_len]
    mov [bx], al
    ret

.update_dns_tx_len:
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len
    mov [dns_tx_len], ax
    ret

; Render cx chars from [si] at the current cursor, dim (0x08 dark-gray on CGA; 0x07 normal on MDA
; where 0x08 can be invisible) via the resident cursor-aware print_char -- which advances cursor_col,
; so the cursor is left PARKED right after the run for the next in-place append. print_char preserves
; ax/bx but sets cx=1, so only cx is saved across it; bl (the attribute) survives in bx.
.render_dim_run:
    mov bl, 0x08
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .rdr_next
    mov bl, 0x07
.rdr_next:
    lodsb
    push cx
    phase_call_res print_char
    pop cx
    loop .rdr_next
    ret

; Advance one line after "> reconnect failed" so the returning DPI draws its prompt below it (mirrors
; dpi .advance_line: scroll the text area up when already at the bottom row, else just move down).
.reconnect_advance_line:
    cmp byte [cursor_row], dpi_prompt_row
    jb .ral_down
    mov ax, 0x0601
    mov cx, 0x0100
    phase_call_res scroll_text_area
    mov byte [cursor_row], dpi_prompt_row
    jmp .ral_col
.ral_down:
    inc byte [cursor_row]
.ral_col:
    mov byte [cursor_col], dpi_prompt_col
    ret

; Shared dim status text. "> reconnect" (chars 0..10) is drawn on the first reconnect attempt; on
; total failure the trailing " failed" (chars 11..17) is appended at the parked cursor in place.
reconnect_msg_text db '> reconnect failed'
reconnect_word_len equ 11
reconnect_failed_text equ reconnect_msg_text + reconnect_word_len
reconnect_failed_len equ 7
; Build 12 auto-recertify status. 11 chars (== "> reconnect") so it overwrites it in place on a
; mid-chat recert; the shared " failed" tail above appends to whichever line the cursor is parked on.
recertify_msg_text db '> recertify'
recertify_word_len equ 11

host_openai_text db 'api.openai.com', 0

%unmacro phase_call_res 1
