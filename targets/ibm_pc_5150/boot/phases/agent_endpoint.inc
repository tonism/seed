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
    ;   retries==3 + mid-chat : a reconnect's FIRST attempt (handoff_status==ready means we are in the
    ;                           chat loop, so a prior session existed -> a reconnect, NOT the cold first
    ;                           connect) -> draw "> reconnect" ONCE and park the cursor after it so the
    ;                           answer (or " failed") appends in place. Retries 2/1 re-enter here
    ;                           silently (the ==3 gate), so the line shows exactly once. Gate on
    ;                           handoff_status, NOT tls_key_schedule_ready: a real idle-close sends a
    ;                           close_notify that clears key_ready during the failed reuse BEFORE this
    ;                           runs, so a key_ready gate MISSES the real reconnect (the bug the
    ;                           authentic idle demo caught); handoff_status stays ready across the chat.
    ;   otherwise             : cold connect or a silent retry -> no status; fall through to the body.
    mov al, [reconnect_retries]
    or al, al
    jz .render_reconnect_failed
    cmp al, 3
    jne .endpoint_body
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    jne .endpoint_body
    mov byte [cursor_col], dpi_prompt_col
    mov si, low_scratch_start + (reconnect_msg_text - PHASE_BASE)
    mov cx, reconnect_word_len
    call .render_dim_run
    jmp .endpoint_body
.render_reconnect_failed:
    mov si, low_scratch_start + (reconnect_failed_text - PHASE_BASE)
    mov cx, reconnect_failed_len
    call .render_dim_run
    call .reconnect_advance_line
    ; Return CF=1 so this sacrificial "failed" call reports failure: net_phase's exhaustion path
    ; falls straight into .restore, and prepare_agent_path's cold-setup caller (main.inc) relies on
    ; CF to show the fatal screen on a cold-boot agent-connect failure (a mid-chat turn ignores CF).
    stc
    ret
.endpoint_body:
    mov word [tcp_dest_port_word], tcp_port_https_word
    cmp byte [handoff_addr + handoff_status], handoff_status_ready
    je .open_provider
    call agent_endpoint_phase_selected_agent_needs_endpoint
    jc .known_provider
    mov si, seed_endpoint
    jmp .set_dns_target_from_text
.known_provider:
    cmp byte [seed_agent_id], 'o'
    je .open_provider
    cmp byte [seed_agent_id], 'a'
    je .anthropic
    cmp byte [seed_agent_id], 'g'
    je .google
    stc
    ret
.open_provider:
    cmp byte [seed_agent_id + 4], 'r'
    je .openrouter
    mov si, low_scratch_start + (host_openai_text - PHASE_BASE)
    jmp .set_dns_target_from_text
.openrouter:
    mov si, low_scratch_start + (host_openrouter_text - PHASE_BASE)
    jmp .set_dns_target_from_text
.anthropic:
    mov si, low_scratch_start + (host_anthropic_text - PHASE_BASE)
    jmp .set_dns_target_from_text
.google:
    mov si, low_scratch_start + (host_google_text - PHASE_BASE)

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

host_openrouter_text db 'openrouter.ai', 0
host_openai_text db 'api.openai.com', 0
host_anthropic_text db 'api.anthropic.com', 0
host_google_text db 'generativelanguage.googleapis.com', 0

agent_endpoint_phase_selected_agent_needs_endpoint:
    cmp byte [seed_agent_id], 'l'
    jne .no
    clc
    ret
.no:
    stc
    ret

%unmacro phase_call_res 1
