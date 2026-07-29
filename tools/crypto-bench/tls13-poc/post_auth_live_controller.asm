; Final credentialed-live post-auth controller composition.
;
; ENTRY replaces the existing one-sector 0x3200 auth controller at the same
; phase key. It runs the unchanged exact-pin auth overlay, then relocates a
; tiny loader trampoline above the live-auth low workspace and installs
; SUPERVISOR at 0x3000..0x33ff.
;
; SUPERVISOR commits the direct status-last issuer object through ROG3,
; installs the fixed callback block, request controller, and exact-length
; request adapter, then invokes the request. The request's 0x0510 callback
; restores K14 after the ROG3 authorization callback has published PAK1.
; Finally it installs the response controller/literals and feeds ciphertext
; from resident TCP into the authenticated response API.

bits 16
cpu 8086

resident_load_phase          equ 0x10c4
resident_tcp_ack             equ 0x13a6
resident_tcp_receive         equ 0x14ed
resident_nic_receive_slot    equ 0x15e1
ne_rx_sample_count           equ 0x06d5
ne_rx_read_limit             equ 0x06d7
tcp_rx_payload_ptr           equ 0x0fe2
tcp_rx_payload_len           equ 0x0fe4

%ifdef POST_AUTH_LIVE_ENTRY

%ifndef POST_AUTH_LIVE_PUBLICATION_ADAPTER_KEY
%error "post-auth entry requires the fixed LP1 publication-adapter phase"
%endif
%ifndef POST_AUTH_LIVE_AUTH_KEY
%error "post-auth entry requires the unchanged exact-pin auth phase key"
%endif
%ifndef POST_AUTH_LIVE_PUBLICATION_ADAPTER_ENTRY
%error "post-auth entry requires the fixed LP1 publication entry"
%endif
%ifndef POST_AUTH_LIVE_SUPERVISOR_KEY
%error "post-auth entry requires the fixed supervisor phase key"
%endif
%ifndef POST_AUTH_LIVE_PERSIST_FAIL
%error "post-auth entry requires the persistent secure failure service"
%endif
org 0x3200

post_auth_lifecycle_start equ 0x3c76
post_auth_lifecycle_end   equ 0x3c9a

post_auth_live_entry:
    cld
    mov ax, [0x046c]
    or ax, ax
    jnz .generation_ready
    inc ax
.generation_ready:
    mov [0x3c2e], ax

    push ds
    pop es
    mov si, post_auth_transition_source
    mov di, 0x3400
    mov cx, post_auth_transition_len
    rep movsb
    jmp 0x3400

post_auth_entry_failed:
%ifdef POST_AUTH_OFFLINE_TEST
    xor ax, ax
    stc
    ret
%else
    mov dx, POST_AUTH_LIVE_PERSIST_FAIL
    jmp dx
%endif

post_auth_transition_source:
    mov ax, POST_AUTH_LIVE_AUTH_KEY
    mov bx, 0x1800
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov ax, POST_AUTH_LIVE_PUBLICATION_ADAPTER_KEY
    mov bx, 0x3200
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov dx, POST_AUTH_LIVE_PUBLICATION_ADAPTER_ENTRY
    call dx
    jc .failed
    cmp ax, 1
    jne .failed

%ifdef POST_AUTH_LIVE_DIAGNOSTIC
    ; Temporary live-stage marker: exact P-256 and LP1 publication passed.
    mov dx, 0x03f8
    mov al, 'P'
    out dx, al
%endif

    ; LP1 now carries the authenticated digest and immutable exact-leaf
    ; identity.  Only at this point may the overlapping tail of the retired
    ; CertificateVerify signature become the private resumption lifecycle
    ; block.  Operation 9 requires its status/inverse bytes to begin at zero.
    push ds
    pop es
    xor ax, ax
    mov di, post_auth_lifecycle_start
    mov cx, (post_auth_lifecycle_end - post_auth_lifecycle_start) / 2
    rep stosw

    mov ax, POST_AUTH_LIVE_SUPERVISOR_KEY
    mov bx, 0x3000
    mov dx, resident_load_phase
    call dx
    jc .failed
%ifdef POST_AUTH_LIVE_DIAGNOSTIC
    ; Temporary live-stage marker: supervisor phase is installed.
    mov dx, 0x03f8
    mov al, 'S'
    out dx, al
%endif
    jmp bx
.failed:
%ifdef POST_AUTH_OFFLINE_TEST
    xor ax, ax
    stc
    ret
%else
    mov dx, POST_AUTH_LIVE_PERSIST_FAIL
    jmp dx
%endif
post_auth_transition_end:
post_auth_transition_len equ \
    post_auth_transition_end - post_auth_transition_source

%if ($ - $$) > 0x0200
%error "post-auth entry controller exceeds its one-sector phase"
%endif

%elifdef POST_AUTH_LIVE_SUPERVISOR

%ifndef POST_AUTH_LIVE_GATE_KEY
%error "post-auth supervisor requires the fixed ROG3 phase key"
%endif
%ifndef POST_AUTH_LIVE_GATE_COMMIT
%error "post-auth supervisor requires the fixed ROG3 commit entry"
%endif
%ifndef POST_AUTH_LIVE_GATE_AUTHORIZE
%error "post-auth supervisor requires the fixed ROG3 authorize entry"
%endif
%ifndef POST_AUTH_LIVE_SUPERVISOR_KEY
%error "post-auth supervisor requires its own reload phase key"
%endif
%ifndef POST_AUTH_LIVE_RESUME_CALLBACKS_KEY
%error "post-auth supervisor requires the resumption callback dispatcher"
%endif
%ifndef POST_AUTH_LIVE_RESUME_CALLBACKS_BYTES
%error "post-auth supervisor requires the exact resumption callback length"
%endif
%ifndef POST_AUTH_LIVE_RESUME_CONTROLLER_HEAD_KEY
%error "post-auth supervisor requires the RSU1 head-sector key"
%endif
%ifndef POST_AUTH_LIVE_RESUME_CONTROLLER_TAIL_KEY
%error "post-auth supervisor requires the RSU1 tail-sector key"
%endif
%ifndef POST_AUTH_LIVE_RESUME_LOW_BYTES
%error "post-auth supervisor requires the exact RSU1 low length"
%endif
%ifndef POST_AUTH_LIVE_RESUME_LOW_START
%error "post-auth supervisor requires the fixed RSU1 low destination"
%endif
%ifndef POST_AUTH_LIVE_RESUME_PREFIX_BYTES
%error "post-auth supervisor requires the exact RSU1 prefix length"
%endif
%ifndef POST_AUTH_LIVE_RESUME_PREFIX_START
%error "post-auth supervisor requires the fixed RSU1 prefix destination"
%endif
%ifndef POST_AUTH_LIVE_RESUME_SUFFIX_BYTES
%error "post-auth supervisor requires the exact RSU1 suffix length"
%endif
%ifndef POST_AUTH_LIVE_RESUME_SUFFIX_START
%error "post-auth supervisor requires the fixed RSU1 suffix destination"
%endif
%ifndef POST_AUTH_LIVE_RESUME_STAMP
%error "post-auth supervisor requires the fixed RSU1 stamp entry"
%endif
%ifndef POST_AUTH_LIVE_RESUME_ATTEMPT
%error "post-auth supervisor requires the fixed RSU1 attempt entry"
%endif
%ifndef POST_AUTH_LIVE_AFTER_LIVENESS
%error "post-auth supervisor requires the low-worker return continuation"
%endif
%ifndef POST_AUTH_LIVE_AUTH_CALLBACKS_KEY
%error "post-auth supervisor requires the fixed auth callback-page phase"
%endif
%ifndef POST_AUTH_LIVE_AUTH_CALLBACKS_BYTES
%error "post-auth supervisor requires the exact auth callback-page length"
%endif
%ifndef POST_AUTH_LIVE_REQUEST_CALLBACKS_KEY
%error "post-auth supervisor requires the fixed request callback-page phase"
%endif
%ifndef POST_AUTH_LIVE_REQUEST_CALLBACKS_BYTES
%error "post-auth supervisor requires the exact request callback-page length"
%endif
%ifndef POST_AUTH_LIVE_REQUEST_KEY
%error "post-auth supervisor requires the request-controller phase"
%endif
%ifndef POST_AUTH_LIVE_REQUEST_ADAPTER_KEY
%error "post-auth supervisor requires the request-adapter phase"
%endif
%ifndef POST_AUTH_LIVE_REQUEST_ADAPTER_BYTES
%error "post-auth supervisor requires the exact request-adapter length"
%endif
%ifndef POST_AUTH_LIVE_REQUEST_ENTRY
%error "post-auth supervisor requires the fixed request entry"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_KEY
%error "post-auth supervisor requires the response-controller phase"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_LITERALS_KEY
%error "post-auth supervisor requires the response-literals phase"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_LITERALS_BYTES
%error "post-auth supervisor requires the exact response-literals length"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_START
%error "post-auth supervisor requires the fixed response start entry"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_BEGIN
%error "post-auth supervisor requires the fixed response begin entry"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_CHUNK
%error "post-auth supervisor requires the fixed response chunk entry"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_FINISH
%error "post-auth supervisor requires the fixed response finish entry"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_EOF
%error "post-auth supervisor requires the fixed response EOF entry"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_STAGE_ADAPTER
%error "post-auth supervisor requires the post-request-safe phase-load tail"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_ACK_MORE
%error "post-auth supervisor requires the post-request-safe TCP ACK continuation"
%endif
%ifndef POST_AUTH_LIVE_RESPONSE_SUCCESS_TEXT
%error "post-auth supervisor requires the post-request-safe success literal"
%endif
%ifndef POST_AUTH_LIVE_PERSIST_EMIT
%error "post-auth supervisor requires the persistent emit service"
%endif
%ifndef POST_AUTH_LIVE_PERSIST_FAIL
%error "post-auth supervisor requires the persistent secure failure service"
%endif

org 0x3000

issuer_commit_generation     equ 0x360a
gate_route_ticket_only       equ 3
gate_route_live_ticket       equ 2
gate_state_committed         equ 0xc3

stage_buffer                 equ 0x0d00
request_callback_stage       equ 0x1c00
request_adapter_stage        equ 0x2400
callback_page                equ 0x0500
callback_page_end            equ 0x0600
user_loader_callback         equ 0x0520
resume_low_start             equ POST_AUTH_LIVE_RESUME_LOW_START
resume_low_head_bytes        equ 0x0200
resume_low_tail_start        equ resume_low_start + resume_low_head_bytes
resume_prefix_start          equ POST_AUTH_LIVE_RESUME_PREFIX_START
resume_suffix_start          equ POST_AUTH_LIVE_RESUME_SUFFIX_START
gate_route                   equ 0x3c3c
gate_route_inverse           equ 0x3c3d
gate_state_inverse           equ 0x3c3e
gate_state                   equ 0x3c3f
sym_io                       equ 0x39a0
response_tag                 equ 0x3910
wire_header_pos              equ 0x3c62
wire_cipher_remaining        equ 0x3c64
wire_tag_pos                 equ 0x3c66
wire_source                  equ 0x3c68
wire_source_remaining        equ 0x3c6a
wire_piece_len               equ 0x3c6c
wire_state_end               equ 0x3c6e
resume_state_start           equ 0x3c46
resume_state_end             equ 0x3c76
resume_transition            equ 0x0f00
resume_transition_limit      equ 0x0fe2
resume_fixed_callback        equ 0x0500

post_auth_live_supervisor:
    cld
    push ds
    pop es

    ; LP1 is the gate's direct live-P256 issuer input. Its generation was
    ; chosen before the fixed publication adapter reran the exact-pin verify.
    mov ax, [issuer_commit_generation]
    or ax, ax
    jz post_auth_failed

    mov ax, POST_AUTH_LIVE_GATE_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc post_auth_failed
    mov ax, [issuer_commit_generation]
    mov bx, gate_route_ticket_only
    call POST_AUTH_LIVE_GATE_COMMIT
    jc post_auth_failed
    cmp ax, 1
    jne post_auth_failed

    ; A ticket is not credential authority. Install the fixed resumption
    ; dispatcher plus the exact RSU1 scatter controller, stamp the original
    ; authenticated NST receipt, and force one fresh-key resumption. RSU1
    ; promotes route 3 -> 2 only after HEAD-before-FO and authenticated drain.
    mov ax, POST_AUTH_LIVE_RESUME_CALLBACKS_KEY
    mov bx, stage_buffer
    call resident_load_phase
    jc post_auth_failed
    mov si, stage_buffer
    mov cx, POST_AUTH_LIVE_RESUME_CALLBACKS_BYTES
    call post_auth_install_callbacks
    call post_auth_install_resume
    jc post_auth_failed

    ; Every RSU1 fixed operation cold-loads a worker at 0x3000. Retire this
    ; supervisor before the first receipt operation so no return address or
    ; executing byte remains inside the worker slot. The relocated sequence
    ; stays above the authenticated liveness scatter (ending at 0x0ee0) and
    ; strictly below the resident TCP payload fields at 0x0fe2.
    push ds
    pop es
    mov si, post_auth_resume_transition_source
    mov di, resume_transition
    mov cx, post_auth_resume_transition_len
    rep movsb
    jmp resume_transition

post_auth_live_after_resume:
    cmp byte [gate_route], gate_route_live_ticket
    jne post_auth_failed
    cmp byte [gate_route_inverse], 0xfd
    jne post_auth_failed
    cmp byte [gate_state], gate_state_committed
    jne post_auth_failed

    ; The promoted route is fully represented by the issuer, ticket, and
    ; 0x3c30 control block. Retire receipt/candidate/FO attempt state before
    ; the credential callback reuses part of this range.
    push ds
    pop es
    xor ax, ax
    mov di, resume_state_start
    mov cx, resume_state_end - resume_state_start
    rep stosb

    ; Resumption workers displaced ROG3 at 0x1800. Reload it and revalidate
    ; the complete promoted route through the fixed authorize entry before
    ; cold-replacing the dispatcher with any credential callback.
    mov ax, POST_AUTH_LIVE_GATE_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc post_auth_failed
    xor ax, ax
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    call POST_AUTH_LIVE_GATE_AUTHORIZE
    jc post_auth_failed
    cmp ax, 1
    jne post_auth_failed

    ; Install only the exact tiny auth callback page. A direct one-sector
    ; phase load at 0x0500 is forbidden because it would overwrite the live
    ; handoff and NIC/TCP state beginning at 0x0600.
    mov ax, POST_AUTH_LIVE_AUTH_CALLBACKS_KEY
    mov bx, stage_buffer
    call resident_load_phase
    jc post_auth_failed
    mov si, stage_buffer
    mov cx, POST_AUTH_LIVE_AUTH_CALLBACKS_BYTES
    call post_auth_install_callbacks

    ; UCL1 cold-loads at 0x0900 only after RSU1 has retired, performs every
    ; disk read under the full ROG4 authority check, and publishes PAK1
    ; status-last. It returns before the request controller replaces it.
    xor ax, ax
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    call user_loader_callback
    jc post_auth_failed
    cmp ax, 1
    jne post_auth_failed

    ; Preserve PAK1 at 0x0d00 by staging the request callback page in the
    ; retired HELLO tail, then replace the auth page by exact length.
    mov ax, POST_AUTH_LIVE_REQUEST_CALLBACKS_KEY
    mov bx, request_callback_stage
    call resident_load_phase
    jc post_auth_failed
    mov si, request_callback_stage
    mov cx, POST_AUTH_LIVE_REQUEST_CALLBACKS_BYTES
    call post_auth_install_callbacks

    mov ax, POST_AUTH_LIVE_REQUEST_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc post_auth_failed
    mov ax, POST_AUTH_LIVE_REQUEST_ADAPTER_KEY
    call post_auth_stage_request_adapter
    jc post_auth_failed
    mov si, request_adapter_stage
    mov cx, POST_AUTH_LIVE_REQUEST_ADAPTER_BYTES
    call post_auth_install_adapter

post_auth_live_request_call:
    call POST_AUTH_LIVE_REQUEST_ENTRY
post_auth_live_after_request:
    ; K14 request sealing has now claimed 0x32af..sym_k_work_end. Every
    ; continuation reachable below is either in the still-safe supervisor
    ; prefix, the exact-copied response tail below 0x3510, or a persistent
    ; service above 0x355d. Never return to the cold local helpers/fail tail.
    jc POST_AUTH_LIVE_PERSIST_FAIL
    cmp ax, 1
    jne POST_AUTH_LIVE_PERSIST_FAIL
%ifdef POST_AUTH_OFFLINE_STOP_AFTER_REQUEST
    mov ax, 1
    clc
    ret
%endif

    mov ax, POST_AUTH_LIVE_RESPONSE_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc POST_AUTH_LIVE_PERSIST_FAIL
    mov ax, POST_AUTH_LIVE_RESPONSE_LITERALS_KEY
    call POST_AUTH_LIVE_RESPONSE_STAGE_ADAPTER
    jc POST_AUTH_LIVE_PERSIST_FAIL
    mov si, stage_buffer
    mov cx, POST_AUTH_LIVE_RESPONSE_LITERALS_BYTES
    mov di, 0x3400
    rep movsb
    call POST_AUTH_LIVE_RESPONSE_START
    jc POST_AUTH_LIVE_PERSIST_FAIL

    xor ax, ax
    mov di, wire_header_pos
    mov cx, wire_state_end - wire_header_pos
    rep stosb

    ; The authenticated canary path froze the receive window before FO/auth.
    ; Discard queued retransmission copies, then advertise the resident window
    ; at the same TCP sequence before accepting the business response.
    mov word [ne_rx_read_limit], 438
    mov bp, 256
.flush:
    push bp
    call word [resident_nic_receive_slot]
    pop bp
    jc POST_AUTH_LIVE_PERSIST_FAIL
    cmp word [ne_rx_sample_count], 0
    je .open_window
    dec bp
    jnz .flush
    jmp POST_AUTH_LIVE_PERSIST_FAIL
.open_window:
    call resident_tcp_ack
    jc POST_AUTH_LIVE_PERSIST_FAIL

post_auth_live_response_receive:
    call resident_tcp_receive
    jc POST_AUTH_LIVE_PERSIST_FAIL
    mov ax, [tcp_rx_payload_ptr]
    mov [wire_source], ax
    mov ax, [tcp_rx_payload_len]
    mov [wire_source_remaining], ax

.consume:
    cmp word [wire_source_remaining], 0
    je POST_AUTH_LIVE_RESPONSE_ACK_MORE
    cmp byte [wire_header_pos], 5
    je .record_body

    xor bx, bx
    mov bl, [wire_header_pos]
    mov si, [wire_source]
    mov al, [si]
    mov [sym_io + bx], al
    inc si
    mov [wire_source], si
    dec word [wire_source_remaining]
    inc byte [wire_header_pos]
    cmp byte [wire_header_pos], 5
    jne .consume

    mov ax, [sym_io + 3]
    xchg al, ah
    cmp ax, 17
    jb POST_AUTH_LIVE_PERSIST_FAIL
    sub ax, 16
    mov [wire_cipher_remaining], ax
    mov byte [wire_tag_pos], 0
    call POST_AUTH_LIVE_RESPONSE_BEGIN
    jc POST_AUTH_LIVE_PERSIST_FAIL
    jmp .consume

.record_body:
    mov ax, [wire_cipher_remaining]
    or ax, ax
    jz .record_tag
    mov cx, [wire_source_remaining]
    cmp cx, ax
    jbe .cipher_bound
    mov cx, ax
.cipher_bound:
    cmp cx, 383
    jbe .cipher_ready
    mov cx, 383
.cipher_ready:
    mov [wire_piece_len], cx
    mov si, [wire_source]
    call POST_AUTH_LIVE_RESPONSE_CHUNK
    jc POST_AUTH_LIVE_PERSIST_FAIL
    mov ax, [wire_piece_len]
    add [wire_source], ax
    sub [wire_source_remaining], ax
    sub [wire_cipher_remaining], ax
    jmp .consume

.record_tag:
    xor bx, bx
    mov bl, [wire_tag_pos]
    mov ax, 16
    sub ax, bx
    mov cx, [wire_source_remaining]
    cmp cx, ax
    jbe .tag_ready
    mov cx, ax
.tag_ready:
    mov [wire_piece_len], cx
    mov si, [wire_source]
    mov di, response_tag
    add di, bx
    rep movsb
    mov [wire_source], si
    mov ax, [wire_piece_len]
    sub [wire_source_remaining], ax
    add [wire_tag_pos], al
    cmp byte [wire_tag_pos], 16
    jne .consume

    mov si, response_tag
    call POST_AUTH_LIVE_RESPONSE_FINISH
    jc POST_AUTH_LIVE_PERSIST_FAIL
    mov byte [wire_header_pos], 0
    or ax, ax
    jz .consume
    cmp word [wire_source_remaining], 0
    jne POST_AUTH_LIVE_PERSIST_FAIL
    call POST_AUTH_LIVE_RESPONSE_EOF
    jc POST_AUTH_LIVE_PERSIST_FAIL
    cmp ax, 1
    jne POST_AUTH_LIVE_PERSIST_FAIL
    mov si, POST_AUTH_LIVE_RESPONSE_SUCCESS_TEXT
    call POST_AUTH_LIVE_PERSIST_EMIT
%ifdef POST_AUTH_OFFLINE_TEST
    mov ax, 1
    clc
    ret
%else
.halt:
    sti
    hlt
    jmp short .halt
%endif

; Before request_send, 0x0d00 holds the status-last PAK1 publication. Stage
; the request adapter in retired HELLO space so phase loading cannot alter it.
; request_send restores K14 afterward, deliberately overwriting this stage.
post_auth_stage_request_adapter:
    mov bx, request_adapter_stage
    jmp resident_load_phase

post_auth_install_adapter:
    mov di, 0x3400
    rep movsb
    ret

; SI=staged callback bytes, CX=exact measured length (always <=0x100).
; Clear and replace only the immutable callback page; 0x0600..0x08b6 is live.
post_auth_install_callbacks:
    push si
    push cx
    push ds
    pop es
    xor ax, ax
    mov di, callback_page
    mov cx, callback_page_end - callback_page
    rep stosb
    pop cx
    pop si
    mov di, callback_page
    rep movsb
    ret

; RSU1's file image is low||prefix||suffix, but its executable spans
; are discontiguous. Load sector two first, install its low tail and exact high
; prefix plus the post-auth low suffix, then load sector one directly. The
; final live layout keeps all low code below 0x0d00 and leaves the secure
; persistent 0x355d..0x35ff services untouched.
post_auth_install_resume:
    mov ax, POST_AUTH_LIVE_RESUME_CONTROLLER_TAIL_KEY
    mov bx, stage_buffer
    call resident_load_phase
    jc .failed
    push ds
    pop es
    mov si, stage_buffer
    mov di, resume_low_tail_start
    mov cx, POST_AUTH_LIVE_RESUME_LOW_BYTES - resume_low_head_bytes
    rep movsb
    mov si, stage_buffer + \
        (POST_AUTH_LIVE_RESUME_LOW_BYTES - resume_low_head_bytes)
    mov di, resume_prefix_start
    mov cx, POST_AUTH_LIVE_RESUME_PREFIX_BYTES
    rep movsb
    mov si, stage_buffer + \
        (POST_AUTH_LIVE_RESUME_LOW_BYTES - resume_low_head_bytes) + \
        POST_AUTH_LIVE_RESUME_PREFIX_BYTES
    mov di, resume_suffix_start
    mov cx, POST_AUTH_LIVE_RESUME_SUFFIX_BYTES
    rep movsb
    mov ax, POST_AUTH_LIVE_RESUME_CONTROLLER_HEAD_KEY
    mov bx, resume_low_start
    call resident_load_phase
    ret
.failed:
    stc
    ret

; Relocated, position-independent-by-construction resume sequence. All calls
; and jumps use absolute register targets because near immediates would retain
; their source-relative displacement after the copy to 0x0f00.
post_auth_resume_transition_source:
    mov dx, POST_AUTH_LIVE_RESUME_STAMP
    call dx
    jc post_auth_resume_failed
    cmp ax, 1
    jne post_auth_resume_failed
    mov dx, POST_AUTH_LIVE_RESUME_ATTEMPT
    call dx
    jc post_auth_resume_failed
    cmp ax, 1
    jne post_auth_resume_failed
post_auth_resume_reload_supervisor:
    mov ax, POST_AUTH_LIVE_SUPERVISOR_KEY
    mov bx, 0x3000
    mov dx, resident_load_phase
    call dx
    jc post_auth_resume_failed
    mov dx, post_auth_live_after_resume
    jmp dx
post_auth_resume_failed:
    mov dx, POST_AUTH_LIVE_PERSIST_FAIL
    jmp dx

%if (POST_AUTH_LIVE_AFTER_LIVENESS - resume_transition) < \
    ($ - post_auth_resume_transition_source)
%error "post-auth low-worker continuation overlaps the initial transition"
%endif
times (POST_AUTH_LIVE_AFTER_LIVENESS - resume_transition) - \
    ($ - post_auth_resume_transition_source) db 0
post_auth_resume_after_liveness_source:
    ; MODE_LOW overwrote RSU1 at 0x0900. Its RET consumed the explicit
    ; after-liveness address, leaving the stale outer CALL return underneath.
    ; Discard that word before any further call or supervisor reload.
    jc .liveness_failed
    cmp ax, 1
    jne .liveness_failed
    pop dx

    ; Validate the complete still-TICKET_ONLY bundle after authenticated
    ; liveness. The fixed operation restores and scrubs a valid vault before
    ; it invokes ROG4; no caller-selected pointer or route crosses the ABI.
    mov ax, 9
    mov dx, resume_fixed_callback
    call dx
    jc .after_failed
    cmp ax, 1
    jne .after_failed
    cmp byte [gate_route], gate_route_ticket_only
    jne .after_failed
    cmp byte [gate_route_inverse], 0xfc
    jne .after_failed
    cmp byte [gate_state], gate_state_committed
    jne .after_failed

    ; Promotion is status-last. Route 3 -> 2 reduces the committed bundle sum
    ; by one, so its complemented checksum increases by one.
    mov byte [gate_state], 0
    mov byte [gate_state_inverse], 0
    mov byte [gate_route], gate_route_live_ticket
    mov byte [gate_route_inverse], 0xfd
    inc word [0x3c32]
    mov byte [gate_state_inverse], 0x3c
    mov byte [gate_state], gate_state_committed
    jmp post_auth_resume_reload_supervisor

.liveness_failed:
    pop dx
.after_failed:
    mov ax, 11
    mov dx, resume_fixed_callback
    call dx
    jmp post_auth_resume_failed
post_auth_resume_transition_end:
post_auth_resume_transition_len equ \
    post_auth_resume_transition_end - post_auth_resume_transition_source

%if post_auth_resume_transition_len > \
    (resume_transition_limit - resume_transition)
%error "post-auth resume transition reaches resident TCP state"
%endif

post_auth_failed:
    push ds
    pop es
    xor ax, ax
    mov di, callback_page
    mov cx, callback_page_end - callback_page
    rep stosb
    mov di, 0x0d00
    mov cx, 0x0300
    rep stosb
    mov di, 0x3510
    mov cx, 0x355d - 0x3510
    rep stosb
    mov di, 0x3600
    mov cx, 0x0238
    rep stosb
    mov di, 0x3838
    mov cx, 0x0308
    rep stosb
    mov di, 0x3b40
    mov cx, 0x0100
    rep stosb
    mov di, 0x3c40
    mov cx, resume_state_end - 0x3c40
    rep stosb
%ifdef POST_AUTH_OFFLINE_TEST
    xor ax, ax
    stc
    ret
%else
    mov dx, POST_AUTH_LIVE_PERSIST_FAIL
    jmp dx
%endif

%if ($ - $$) > 0x0400
%error "post-auth supervisor exceeds its two-sector 0x3000..0x3400 slot"
%endif

%else
%error "select POST_AUTH_LIVE_ENTRY or POST_AUTH_LIVE_SUPERVISOR"
%endif
