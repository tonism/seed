; Private cold liveness owner. The preface was already sent before offline
; FO/authentication. SETTINGS plus the ACK of our SETTINGS proves the peer
; processed that preface after our Finished on this authenticated connection.
; No credential or stream is sent here. Fresh mode also requires a valid NST.
bits 16
cpu 8086
org 0x0900
%include "cold-abi.inc"

h2 equ 0x062e
root_copy equ 0x0d00
master_copy equ 0x0d22
ticket_psk equ 0x0d42
ticket_identity equ 0x0d62
ticket_lifetime equ 0x0e22
ticket_age_add equ 0x0e26
ticket_identity_len equ 0x0e2a
ticket_tick equ 0x0e2c
ticket_status equ 0x0e30
ticket_bridge_sp equ 0x0e32
abort_sp equ 0x0682

cold_post:
    cld
    push ds
    pop es
    xor ax, ax
    mov di, root_copy
    mov cx, (0x0e34-root_copy)/2
    rep stosw
%ifdef SYSRAM_POST_FRESH
    mov si, 0x35c0
    mov di, root_copy
    mov cx, 34/2
    rep movsw
    mov si, 0x3890
    mov di, master_copy
    mov cx, 32/2
    rep movsw
%endif
    ; Evacuate live SYM state before K and its journals replace that phase.
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
    mov si, SYM_CRYPTO_CONSTANTS
    mov di, 0x0fa1
    mov cx, 65
    rep movsb
    xor ax, ax
    mov di, 0x2e00
    mov cx, (0x3600-0x2e00)/2
    rep stosw
    mov di, 0x3668
    mov cx, (0x3b9c-0x3668)/2
    rep stosw
    mov di, 0x0fe2
    mov cx, (0x1000-0x0fe2)/2
    rep stosw
    mov ax, 0x0804
    mov bx, 0x1800
    call resident_load_phase
    jc cold_failed
    xor ax, ax
    call cold_h2
    jc cold_failed
    call res_tcp_ack
    jc cold_failed
    ; Prime the first TLS input ourselves so its provisional receipt tick
    ; is sampled immediately after network ingress, before expensive AEAD.
    call [nic_vt_rx_fallback]
    jnc .first_payload
    call res_tcp_receive
    jc cold_failed
.first_payload:
    pushf
    cli
    mov ax, [0x046c]
    mov [ticket_tick], ax
    mov ax, [0x046e]
    mov [ticket_tick+2], ax
    popf
    mov ax, [tcp_rx_payload_ptr]
    mov [tls_buffered_payload_ptr], ax
    mov ax, [tcp_rx_payload_len]
    mov [tls_buffered_payload_len], ax
.receive:
    call tls_receive_application_data
    jc cold_failed
    cmp byte [tls_app_content_type], 0x16
    je .ticket
    mov ax, 4
    call cold_h2
    jc cold_failed
    or ax, ax                       ; no stream has been opened yet
    jnz cold_failed
    push cx
    mov cx, bx
    mov si, h2+68
    call cold_send
    pop cx
    jc cold_failed
    mov si, 0x3070
    call cold_send
    jc cold_failed
    jmp short .check
.ticket:
%ifdef SYSRAM_POST_FRESH
    call cold_ticket
    jc cold_failed
%else
    call h2_rx_clear_record
%endif
.check:
    cmp byte [h2+19], 0              ; protocol error
    jne cold_failed
    cmp byte [h2+49], 0              ; GOAWAY/retired connection
    jne cold_failed
    cmp byte [h2+47], 1              ; authenticated peer SETTINGS
    jne .receive
    cmp byte [h2+48], 0              ; ACK of our initial SETTINGS
    jne .receive
    cmp byte [h2+60], 0              ; peer must permit a request stream
    jne .receive
    cmp byte [h2+9], 0              ; complete frame boundary
    jne .receive
    cmp word [h2+10], 0
    jne .receive
    cmp word [tls_buffered_payload_len], 0
    jne .receive                    ; retain no unread coalesced record
%ifdef SYSRAM_POST_FRESH
    cmp byte [ticket_status], 1
    jne .receive
    jmp cold_commit_fresh
%else
    jmp cold_commit_final
%endif

; Each invocation has its own still-resident failure return. A failed phase
; replacement never returns to K bytes that may be partially overwritten.
cold_h2:
    mov dx, cold_failed
    push dx
    mov [abort_sp], sp
    call tls_h2_invoke
    pop dx
    ret

; SI/CX is already-authenticated H2 reply content. This never reads the NIC
; while an unsent fragment occupies the TX arena. Following encrypted input
; remains in the independent RX tail throughout the real record seal/send.
cold_send:
    jcxz .done
    ; 512-byte NIC scratch minus Ethernet/IP/TCP (54), TLS header/tag/type
    ; (22). The old 440-byte API allowance would overwrite four owner bytes.
    mov ax, 436
    cmp cx, ax
    jae .bounded
    mov ax, cx
.bounded:
    mov [tls_app_plain_ptr], si
    mov [tls_app_len], ax
    push si
    push cx
    push ax
    call tls_send_application_data_current_seq
    pushf
    call tls_h2_clear_crypto_prefix
    popf
    pop ax
    pop cx
    pop si
    jc .failed
    add si, ax
    sub cx, ax
    jmp short cold_send
.done:
    clc
.failed:
    ret

%ifdef SYSRAM_POST_FRESH
cold_ticket:
    mov [ticket_bridge_sp], sp
    push si
    push cx
    mov ax, 0x06a9
    mov bx, 0x1800
    call resident_load_phase
    jc .failed
    pop cx
    pop si
    call [0x1800]
    pushf
    mov ax, 0x0804
    mov bx, 0x1800
    call resident_load_phase
    jc .failed
    popf
    ret
.failed:
    mov sp, [ticket_bridge_sp]
    jmp cold_failed

cold_commit_fresh:
    ; Reconstruct the already-validated lifecycle ABI after TLS/H2 is dead.
    ; The existing offline transition then handles age, KeyGen and HELLO.
    call post_zero_window
    jc cold_failed
    call post_close_cached
    mov si, root_copy
    mov di, 0x35c0
    mov cx, 17
    rep movsw
    mov si, ticket_psk
    mov di, 0x38b0
    mov cx, 16
    rep movsw
    mov si, ticket_identity
    mov di, 0x39a0
    mov cx, 96
    rep movsw
    mov si, ticket_lifetime
    mov di, 0x3a80
    mov cx, 4
    rep movsw
    mov ax, [ticket_identity_len]
    mov [0x3a8a], ax
    mov si, ticket_tick
    mov di, 0x35fc
    movsw
    movsw
    mov byte [0x2feb], 1
    xor ax, ax
    mov di, root_copy
    mov cx, (0x0e34-root_copy)/2
    rep stosw
    mov di, h2
    mov cx, (0x0684-h2)/2
    rep stosw
    call cold_install_abort
    mov si, resume_ready_image
    mov di, 0x0f00
    mov cx, resume_ready_image_end-resume_ready_image
    rep movsb
    mov si, resumed_deadline_transition_source
    mov di, 0x0f40
    mov cx, resumed_deadline_transition_end-resumed_deadline_transition_source
    rep movsb
    mov si, fresh_transition_source
    mov di, 0x0700
    mov cx, fresh_transition_end-fresh_transition_source
    rep movsb
    jmp 0x0700
%include "cold-fresh-close.inc"
%else
cold_commit_final:
    mov si, success_image
    mov di, 0x0f00
    mov cx, success_image_end-success_image
    rep movsb
    mov si, 0x3f06
    mov di, 0x0f55
    mov cx, 10
    rep movsw
    mov dl, [0x3f1a]
    xor ax, ax
    mov di, 0x0fe2
    mov cx, 15
    rep stosw
    jmp 0x0f00
%endif

cold_failed:
    ; Low SHA aliases now contain H2 state; the legacy abort does not own
    ; these bytes, so this owner retires them before its disk-free unwind.
    xor ax, ax
    mov di, h2
    mov cx, (0x0684-h2)/2
    rep stosw
    call cold_install_abort
    jmp 0x0f60
cold_install_abort:
    mov si, abort_image
    mov di, 0x0f60
    mov cx, abort_image_end-abort_image
    rep movsb
    ret
abort_image:
    incbin "abort.bin"
abort_image_end:

; Keep immutable templates in the first two sectors alongside their owner;
; the existing third sector becomes the disjoint writable ticket capsule.
%ifdef SYSRAM_POST_FRESH
%include "cold-fresh-transition.inc"
%else
success_image:
    incbin "success.bin"
success_image_end:
%endif
cold_runtime_end:
%if ($-$$)>0x400
%error "cold H2 controller reaches its ticket capsule"
%endif
cold_image_end:
%if ($-$$)>3*512
%error "cold H2 controller exceeds its three-sector phase"
%endif
