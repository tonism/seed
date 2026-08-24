; Authenticated post-HEAD receiver for the 16 KiB conventional-RAM route.
;
; Fresh mode requires both an authenticated HTTP HEAD completion and one
; bounded NST before preparing the independent resumed connection.  Final
; mode requires only authenticated resumed HEAD completion and then publishes
; the application keys to the resident chat ABI.  Provisional plaintext is
; scattered only through conventional RAM that is dead after full FO.

bits 16
cpu 8086
org 0x0900

%ifndef SYSRAM_POST_FRESH
%ifndef SYSRAM_POST_FINAL
%error "select one system-RAM post controller"
%endif
%endif
%ifdef SYSRAM_POST_FRESH
%ifdef SYSRAM_POST_FINAL
%error "select only one system-RAM post controller"
%endif
%endif

resident_load_phase          equ 0x10c4
res_tcp_ack                  equ 0x13a6
res_build_tcp_frame          equ 0x13e2
res_tcp_receive              equ 0x14ed
res_nic_vt_transmit          equ 0x15df
tcp_remote_ack               equ 0x06f1
tcp_source_port_word         equ 0x06f9
tcp_rx_payload_ptr           equ 0x0fe2
tcp_rx_payload_len           equ 0x0fe4
ne_tx_frame                  equ 0x0700
tcp_window_word              equ ne_tx_frame + 34 + 14
tcp_checksum_word            equ ne_tx_frame + 34 + 16
low_abort                    equ 0x0f60
resident_crypto_constants  equ 0x0fa1
resident_crypto_constants_len equ 65
root_frame_runtime_state   equ 0x3f06
root_frame_prompt_marker  equ 0x3f1a
runtime_state_start        equ 0x0f55
runtime_state_end          equ 0x0f69
dpi_prompt_marker_row      equ 0x0f33
resident_tail_start        equ 0x0fe2
resident_tail_end          equ 0x1000

sym_entry_table              equ 0x1820
sym_server_app_open_entry    equ sym_entry_table + 5 * 2
sym_open_chunk_entry         equ sym_entry_table + 6 * 2
sym_open_finish_entry        equ sym_entry_table + 7 * 2
sym_parse_nst_entry          equ sym_entry_table + 12 * 2
sym_received_tag             equ 0x3910
sym_io                       equ 0x39a0
; Both conventional-RAM symmetric variants assert this private-header ABI.
; Collecting there avoids overwriting the retained ticket aliased at sym_io.
post_record_header           equ 0x3524
sym_ticket_present           equ 0x2feb
lifecycle_entry_table        equ 0x090a

post_buffer_0                equ 0x0d00
post_buffer_0_len            equ 512
post_buffer_1                equ 0x0500
post_buffer_1_len            equ 256
post_buffer_2                equ 0x08b8
post_buffer_2_len            equ 72
%ifdef SYSRAM_POST_FRESH
post_buffer_3                equ 0x33e8
%else
; The resumption symmetric image keeps its streaming Poly1305 tail through
; 0x33f7.  Its compact root is dead after the final FO restore, so quarantine
; these 24 authenticated plaintext bytes there instead.
post_buffer_3                equ 0x35c0
%endif
post_buffer_3_len            equ 24
post_buffer_4                equ 0x3400
post_buffer_4_len            equ 448
post_buffer_5                equ 0x35e2
post_buffer_5_len            equ 26
post_ticket_tick             equ post_buffer_5 + post_buffer_5_len
post_buffer_6                equ 0x3b3d
post_buffer_6_len            equ 95
post_plain_max               equ 1433

sysram_post_controller:
    cld
    push ds
    pop es
%ifdef SYSRAM_POST_FRESH
    ; The third phase sector is deliberately disposable plaintext space.
    ; Evacuate every future transition before opening the receive window.
    mov si, resume_ready_image
    mov di, 0x0f00
    mov cx, resume_ready_image_end - resume_ready_image
    rep movsb
    mov si, resumed_deadline_transition_source
    mov di, 0x0f40
    mov cx, resumed_deadline_transition_end - resumed_deadline_transition_source
    rep movsb
    mov si, fresh_transition_source
    mov di, 0x2f40
    mov cx, fresh_transition_end - fresh_transition_source
    rep movsb
%else
    mov si, success_image
    mov di, 0x0f00
    mov cx, success_image_end - success_image
    rep movsb
%endif
    mov word [post_header_pos], 0
    mov word [post_plain_len], 0
    mov word [post_head_complete], 0
    mov word [post_http_total], 0
    mov word [post_http_match], 0
    call res_tcp_ack
    jc post_failed

.receive:
    call res_tcp_receive
    jc post_failed
%ifdef SYSRAM_POST_FRESH
    ; OpenAI can coalesce the HTTP response and NST on the wire.  The 8088 may
    ; spend minutes opening the first record before it reaches the ticket's
    ; header, so record-parser time is not network ingress time.  Snapshot the
    ; first encrypted response fragment once; it remains provisional until an
    ; AEAD-valid NST publishes post_ticket_complete.
    cmp byte [post_ingress_seen], 1
    je .ingress_ready
    call SYSRAM_RECORD_TICK_ENTRY
    mov byte [post_ingress_seen], 1
.ingress_ready:
%endif
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]
.consume:
    or cx, cx
    jz .ack_more
    cmp byte [post_record_active], 0
    jne .record_body
    xor bx, bx
    mov bl, [post_header_pos]
    mov al, [si]
    mov [post_record_header + bx], al
    inc si
    dec cx
    inc byte [post_header_pos]
    cmp byte [post_header_pos], 5
    jne .consume
    push si
    push cx
    call post_start_record
    pop cx
    pop si
    jc post_failed
    jmp short .consume

.record_body:
    mov ax, [post_cipher_remaining]
    or ax, ax
    jz .tag
    mov dx, cx
    cmp cx, ax
    jbe .bound_mss
    mov cx, ax
.bound_mss:
    cmp cx, 384
    jbe .cipher_chunk
    mov cx, 384
.cipher_chunk:
    mov [post_chunk_ptr], si
    mov [post_chunk_len], cx
    push dx
    call word [sym_open_chunk_entry]
    pop dx
    jc post_failed
    call post_store_chunk
    mov ax, [post_chunk_len]
    sub [post_cipher_remaining], ax
    sub dx, ax
    mov cx, dx
    jmp .consume

.tag:
    mov dx, cx
    xor bx, bx
    mov bl, [post_tag_pos]
    mov ax, 16
    sub ax, bx
    cmp cx, ax
    jbe .tag_count
    mov cx, ax
.tag_count:
    mov [post_chunk_len], cx
    push es
    push ds
    pop es
    mov di, sym_received_tag
    add di, bx
    rep movsb
    pop es
    mov ax, [post_chunk_len]
    add [post_tag_pos], al
    sub dx, ax
    mov cx, dx
    cmp byte [post_tag_pos], 16
    jne .consume
    push si
    push cx
    mov si, sym_received_tag
    call word [sym_open_finish_entry]
    jc post_failed
    call post_process_plaintext
    jc post_failed
    pop cx
    pop si
    mov byte [post_record_active], 0
    mov word [post_header_pos], 0
    jmp .consume

.ack_more:
    call res_tcp_ack
    jc post_failed
    call post_check_commit
    jmp .receive

post_start_record:
    cmp byte [post_record_header], 0x17
    jne .failed
    cmp word [post_record_header + 1], 0x0303
    jne .failed
    xor ax, ax
    mov ah, [post_record_header + 3]
    mov al, [post_record_header + 4]
    cmp ax, 17
    jb .failed
    sub ax, 16
    cmp ax, post_plain_max
    ja .failed
    mov [post_cipher_remaining], ax
    mov word [post_plain_len], 0
    mov byte [post_tag_pos], 0
    ; The RAM-only app-open ABI consumes post_record_header in place.  Do not
    ; copy it through sym_io: the authenticated ticket identity lives there.
    call word [sym_server_app_open_entry]
    jc .failed
    mov byte [post_record_active], 1
    clc
    ret
.failed:
    stc
    ret

post_store_chunk:
    mov si, [post_chunk_ptr]
    mov cx, [post_chunk_len]
    mov bx, [post_plain_len]
    push es
    push ds
    pop es
.byte:
    call post_scatter_di
    movsb
    inc bx
    loop .byte
    pop es
    mov [post_plain_len], bx
    ret

; BX=logical plaintext offset, returns its physical conventional-RAM address.
post_scatter_di:
    mov di, bx
    cmp bx, 512
    jb .s0
    cmp bx, 768
    jb .s1
    cmp bx, 840
    jb .s2
    cmp bx, 864
    jb .s3
    cmp bx, 1312
    jb .s4
    cmp bx, 1338
    jb .s5
    add di, 0x3603
    ret
.s5:
    add di, 0x30c2
    ret
.s4:
    add di, 0x30a0
    ret
.s3:
    add di, post_buffer_3 - 840
    ret
.s2:
    add di, 0x05b8
    ret
.s1:
    add di, 0x0300
    ret
.s0:
    add di, 0x0d00
    ret

post_process_plaintext:
    mov cx, [post_plain_len]
    or cx, cx
    jz .failed
    mov bx, cx
    dec bx
    call post_scatter_di
    mov dl, [di]
    dec cx
    or cx, cx
    jz .failed
    cmp dl, 0x17
    je .http
    cmp dl, 0x16
    je .ticket
    jmp short .failed
.http:
    call post_process_http
    ret
.ticket:
    cmp cx, post_buffer_0_len
    ja .failed
    call post_process_tickets
    ret
.failed:
    stc
    ret

post_process_http:
    cmp byte [post_head_complete], 0
    jne .failed
    mov dx, cx
    xor bp, bp
.byte:
    cmp bp, dx
    jae .done
    mov bx, bp
    call post_scatter_di
    mov al, [di]
    mov bx, [post_http_total]
    cmp bx, 2048
    jae .failed
    inc word [post_http_total]
    cmp bx, 9
    jb .prefix
    cmp bx, 12
    jb .status_digit
    je .status_space
    cmp byte [post_http_done], 0
    jne .failed
    cmp al, 9
    je .match
    cmp al, 10
    je .match
    cmp al, 13
    je .match
    cmp al, 0x20
    jb .failed
    cmp al, 0x7e
    ja .failed
.match:
    xor bx, bx
    mov bl, [post_http_match]
    cmp al, [post_http_end + bx]
    je .matched
    xor bl, bl
    cmp al, 13
    jne .store_match
    inc bl
.store_match:
    mov [post_http_match], bl
    jmp short .next
.matched:
    inc bl
    mov [post_http_match], bl
    cmp bl, 4
    jne .next
    mov byte [post_http_done], 1
    jmp short .next
.prefix:
    cmp al, [post_http_prefix + bx]
    jne .failed
    jmp short .next
.status_digit:
    cmp al, '0'
    jb .failed
    cmp al, '9'
    ja .failed
    cmp bx, 9
    jne .next
    cmp al, '2'
    je .next
    cmp al, '4'
    je .next
    cmp al, '5'
    jne .failed
    jmp short .next
.status_space:
    cmp al, ' '
    jne .failed
.next:
    inc bp
    jmp .byte
.done:
    cmp byte [post_http_done], 1
    jne .success
    mov byte [post_head_complete], 1
.success:
    clc
    ret
.failed:
    stc
    ret

post_process_tickets:
    mov si, post_buffer_0
    mov dx, cx
    xor bp, bp
.next:
    or dx, dx
    jz .done
    cmp dx, 4
    jb .failed
    cmp byte [si], 4
    jne .failed
    cmp byte [si + 1], 0
    jne .failed
    mov ax, [si + 2]
    xchg al, ah
    add ax, 4
    jc .failed
    cmp ax, 384
    ja .failed
    cmp ax, dx
    ja .failed
    mov [post_message_len], ax
%ifdef SYSRAM_POST_FRESH
    push si
    push dx
    push bp
    mov cx, ax
    call word [sym_parse_nst_entry]
    pop bp
    pop dx
    pop si
    jc .failed
%endif
    inc bp
    cmp bp, 4
    ja .failed
    mov ax, [post_message_len]
    add si, ax
    sub dx, ax
    jmp short .next
.done:
    or bp, bp
    jz .failed
%ifdef SYSRAM_POST_FRESH
    cmp byte [sym_ticket_present], 0
    je .failed
    ; The AEAD tag and every NST in this record have now validated.  Publish
    ; completion last; that freezes the provisional response-ingress sample.
    mov byte [post_ticket_complete], 1
%endif
    clc
    ret
.failed:
    stc
    ret

post_check_commit:
    cmp byte [post_record_active], 0
    jne .pending
    cmp word [post_header_pos], 0
    jne .pending
    cmp byte [post_head_complete], 1
    jne .pending
%ifdef SYSRAM_POST_FRESH
    cmp byte [post_ticket_complete], 1
    jne .pending
    call post_zero_window
    jc post_failed
    call post_close_cached
    jmp post_commit_fresh
%else
    ; This is the authenticated connection whose application keys are about
    ; to become the resident chat capability.  The ACK immediately above
    ; already advertised the normal receive window; retain the TCP session so
    ; the first model request exercises real TLS/TCP reuse.
    jmp post_commit_final
%endif
.pending:
    ret

post_zero_window:
    mov al, 0x10
    xor cx, cx
    mov si, tcp_remote_ack
    call res_build_tcp_frame
    mov word [tcp_window_word], 0
    mov ax, [tcp_checksum_word]
    add ax, 1
    adc ax, 0
    mov [tcp_checksum_word], ax
    mov si, ne_tx_frame
    call word [res_nic_vt_transmit]
    ret

; The ordinary C phase was replaced when this controller loaded at 0900.
; Keep its bounded close leaf here instead of calling into stale phase bytes.
post_close_cached:
    mov ax, [tcp_source_port_word]
    or ax, ax
    jz .done
    mov al, 0x11
    mov dx, [tcp_remote_ack]
    or dx, [tcp_remote_ack + 2]
    jnz .send
    mov al, 0x04
.send:
    xor cx, cx
    mov si, tcp_remote_ack
    call res_build_tcp_frame
    mov si, ne_tx_frame
    call word [res_nic_vt_transmit]
.done:
    clc
    ret

%ifdef SYSRAM_POST_FRESH
%ifndef SYSRAM_LIFECYCLE_KEY
%error "fresh post requires lifecycle phase"
%endif
%ifndef SYSRAM_RES_SYM_KEY
%error "fresh post requires resumption symmetric phase"
%endif
%ifndef SYSRAM_KEYGEN_KEY
%error "fresh post requires KeyGen phase"
%endif
%ifndef SYSRAM_KEYGEN_NONCE_ENTRY
%error "fresh post requires KeyGen nonce entry"
%endif
%ifndef SYSRAM_TICKET_AGE_KEY
%error "fresh post requires ticket-age phase"
%endif
%ifndef SYSRAM_TICKET_AGE_DEST
%error "fresh post requires ticket-age destination"
%endif
%ifndef SYSRAM_RESUME_READY_PATH
%error "fresh post requires resume-ready image"
%endif
%ifndef SYSRAM_RESUMED_HELLO_KEY
%error "fresh post requires resumed HELLO phase"
%endif
%ifndef SYSRAM_RESUMED_HELLO_CONTROLLER_KEY
%error "fresh post requires resumed HELLO controller"
%endif
%ifndef SYSRAM_RESUMED_HELLO_CONTROLLER_DEST
%error "fresh post requires resumed HELLO controller destination"
%endif

post_commit_fresh:
    push ds
    pop es
    mov si, 0x2f40
    mov di, 0x0700
    mov cx, fresh_transition_end - fresh_transition_source
    rep movsb
    jmp 0x0700
%else
%ifndef SYSRAM_SUCCESS_PATH
%error "final post requires success publication image"
%endif
%ifndef SYSRAM_RES_SYM_CRYPTO_CONSTANTS
%error "final post requires the resumption symmetric constant source"
%endif

post_commit_final:
    push ds
    pop es
    mov si, 0x3838
    mov di, 0x3600
    mov cx, 16
    rep movsw
    mov si, 0x3864
    mov cx, 16
    rep movsw
    mov si, 0x3858
    mov cx, 6
    rep movsw
    mov si, 0x3884
    mov cx, 6
    rep movsw
    mov si, 0x38e0
    mov cx, 4
    rep movsw
    mov si, 0x38e8
    mov cx, 4
    rep movsw

    ; The 0f00 continuation window aliases Seed's software cursor, display
    ; geometry/attributes, and loop flags.  Restore that conventional-RAM
    ; snapshot before returning the application capability; video RAM itself
    ; was never borrowed or rewritten by the TLS route.
    mov si, root_frame_runtime_state
    mov di, runtime_state_start
    mov cx, (runtime_state_end - runtime_state_start) / 2
    rep movsw
    ; 0f33 lies inside the success capsule itself. Carry the saved marker in
    ; DL; the capsule republishes it only after executing past that byte.
    mov dl, [root_frame_prompt_marker]

    ; Handshake controllers borrow the resident TCP/TLS cursor tail but do
    ; not publish application framing state.  Retire every stale pointer and
    ; length here, while this controller still has room; the compact success
    ; capsule must end before the just-restored runtime-state band at 0f55.
    xor ax, ax
    mov di, resident_tail_start
    mov cx, (resident_tail_end - resident_tail_start) / 2
    rep stosw

    ; The disk-independent abort necessarily occupies 0f60.. and therefore
    ; aliases the resident constant band while the cold route is live.  The
    ; TLS 1.3 product K never references the preceding TLS 1.2 PRF labels; its
    ; application-record engine does consume this contiguous
    ; ChaCha/Poly1305/SHA tail.  Keep the abort through both authenticated
    ; response records, then restore the live constants from the immutable
    ; resumption symmetric image immediately before normal application data.
    mov si, SYSRAM_RES_SYM_CRYPTO_CONSTANTS
    mov di, resident_crypto_constants
    mov cx, resident_crypto_constants_len
    rep movsb
    jmp 0x0f00
%endif

post_failed:
    jmp low_abort

post_http_prefix       db 'HTTP/1.1 '
post_http_end          db 13,10,13,10
post_header_pos        db 0
post_record_active     db 0
post_cipher_remaining  dw 0
post_plain_len         dw 0
post_tag_pos           db 0
post_chunk_ptr         dw 0
post_chunk_len         dw 0
post_head_complete     db 0
post_ticket_complete   db 0
post_http_total        dw 0
post_http_match        db 0
post_http_done         db 0
post_message_len       dw 0
%ifdef SYSRAM_POST_FRESH
post_ingress_seen      db 0
%endif

sysram_post_runtime_end:

%ifdef SYSRAM_POST_FRESH
fresh_transition_source:
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    mov dx, resident_load_phase
    call dx
    jc .failed
    call word [lifecycle_entry_table + 4 * 2]
    jc .failed
    mov ax, SYSRAM_RES_SYM_KEY
    mov bx, 0x1800
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov ax, SYSRAM_KEYGEN_KEY
    mov bx, 0x1800
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov ax, 1
    mov si, 0x3400
    mov dx, 0x0700 + .after_keygen - fresh_transition_source
    push dx
    mov dx, 0x1800
    jmp dx
.after_keygen:
    jc .failed
    mov ax, 1
    mov si, 0x3400
    mov di, 0x3420
    mov dx, SYSRAM_KEYGEN_NONCE_ENTRY
    call dx
    jc .failed
    mov ax, SYSRAM_TICKET_AGE_KEY
    mov bx, SYSRAM_TICKET_AGE_DEST
    mov dx, resident_load_phase
    call dx
    jc .failed
    ; Keep the helper resident, but defer its clock sample until the resumed
    ; HELLO controller is loaded and ready to build the binder.  Its dedicated
    ; 2c00 sector is disjoint from regenerated ek, the 1800..29ff HELLO, the
    ; 2a00 controller, and the 2e00 TX staging page.
    mov dx, 0x0f00
    call dx
    jc .failed
    push ds
    pop es
    mov si, 0x0f40
    mov di, 0x0f00
    mov cx, resumed_deadline_transition_end - resumed_deadline_transition_source
    rep movsb
    mov ax, SYSRAM_RESUMED_HELLO_KEY
    mov bx, 0x1800
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov ax, SYSRAM_RESUMED_HELLO_CONTROLLER_KEY
    mov bx, SYSRAM_RESUMED_HELLO_CONTROLLER_DEST
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov dx, SYSRAM_RESUMED_HELLO_CONTROLLER_DEST
    jmp dx
.failed:
    mov dx, low_abort
    jmp dx
fresh_transition_end:

; Position-independent: staged at 0f40, copied to 0f00 after resume-ready.
resumed_deadline_transition_source:
    mov bx, 0x3400
    mov dx, resident_load_phase
    call dx
    jnc .loaded
    mov dx, low_abort
    jmp dx
.loaded:
    mov dx, 0x3400
    jmp dx
resumed_deadline_transition_end:

resume_ready_image:
    incbin SYSRAM_RESUME_READY_PATH
resume_ready_image_end:
%else
success_image:
    incbin SYSRAM_SUCCESS_PATH
success_image_end:
%endif

sysram_post_controller_end:

%if (sysram_post_runtime_end - $$) > (0x0d00 - 0x0900)
%error "system-RAM post controller reaches its plaintext buffer"
%endif
%if (sysram_post_controller_end - $$) > (0x0f00 - 0x0900)
%error "system-RAM post phase exceeds three sectors"
%endif
%ifdef SYSRAM_POST_FRESH
%if (fresh_transition_end - fresh_transition_source) > (0x08b8 - 0x0700)
%error "fresh post transition exceeds dead RX/ciphertext prefix"
%endif
%if (fresh_transition_end - fresh_transition_source) > (sym_ticket_present - 0x2f40)
%error "fresh post transition staging reaches the authenticated ticket status"
%endif
%if (resume_ready_image_end - resume_ready_image) > 0x0040
%error "resume-ready image reaches its staged transition template"
%endif
; 0f16..0f5f is reserved for the length + exact 70-byte maximum prefix that
; resumed HELLO may quarantine when the provider coalesces its protected
; flight.  Keep the executable transition entirely below that handoff.
%if (resumed_deadline_transition_end - resumed_deadline_transition_source) > 0x0016
%error "resumed deadline transition reaches the protected-tail handoff"
%endif
%endif
