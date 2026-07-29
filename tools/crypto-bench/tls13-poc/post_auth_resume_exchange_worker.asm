; Seed TLS 1.3 same-boot resumption EXCHANGE worker.
;
; RSD1 exposes only the direct operation-3 broker.  Five fixed continuations
; split the live network and post-ServerHello crypto work around the K14
; mutable windows:
;
;   BROKER 0x3000  cached connect, resumed HELLO load/input restoration
;   TX     0x3400  offline CH hash, ninth-sector connect, and exact replay
;   RX     0x2800  replace connector; strict server-flight capture and commit
;   CRYPTO 0x3000  private import -> c publication -> candidate tail-call
;   POST   0x2400  duplicate candidate, early-state import, provisional K'
;   RESTORE 0x3400 reload all RSU1 spans before returning to its caller
;
; The 0x7900 lifetime overlay is intentional and ordered: the complete
; 0x7900..0x7dff KeyGen private mirror is imported before any byte of c is
; written to 0x7900..0x7d3f.  Candidate then consumes host private+c and
; publishes two verified m'||G||z copies.  Private state is dead after that;
; deferred FO requires only ek, c, and the duplicated candidate.

bits 16
cpu 8086

%include "post_auth_resume_vault.inc"

%ifndef RESUME_EXCHANGE_LOAD_PHASE
%error "resumption EXCHANGE requires the resident phase loader"
%endif
%ifndef RESUME_EXCHANGE_NE_BUF_READ
%error "resumption EXCHANGE requires the guarded NE2000 read leaf"
%endif
%ifndef RESUME_EXCHANGE_NE_BUF_LOAD
%error "resumption EXCHANGE requires the guarded NE2000 write leaf"
%endif
%ifndef RESUME_EXCHANGE_NIC_BASE
%error "resumption EXCHANGE requires the resident NIC-base word"
%endif
%ifndef RESUME_EXCHANGE_NE_TX_START
%error "resumption EXCHANGE requires the resident NE transmit-page byte"
%endif
%ifndef RESUME_EXCHANGE_LIFECYCLE_START
%error "resumption EXCHANGE requires the RVL1 lifecycle start"
%endif
%ifndef RESUME_EXCHANGE_LIFECYCLE_END
%error "resumption EXCHANGE requires the RVL1 lifecycle end"
%endif
%ifndef RESUME_EXCHANGE_CONT_LIMIT
%define RESUME_EXCHANGE_CONT_LIMIT 0x0110
%endif
%ifndef RESUME_EXCHANGE_RX_ORIGIN
%define RESUME_EXCHANGE_RX_ORIGIN 0x2800
%endif

exchange_attempt_cache          equ 0x3b9c
exchange_ticket_identity        equ 0x3000
exchange_ticket_psk             equ 0x38b0
exchange_ticket_tail            equ 0x3c00
exchange_ticket_present         equ 0x3c2c
exchange_lifecycle_digest       equ RESUME_EXCHANGE_LIFECYCLE_START
exchange_lifecycle_generation   equ exchange_lifecycle_digest + 32
exchange_lifecycle_inverse      equ exchange_lifecycle_generation + 2
exchange_lifecycle_status       equ exchange_lifecycle_inverse + 1
exchange_candidate_generation  equ 0x3c66
exchange_candidate_c_sum       equ 0x3c68
exchange_candidate_ek_sum      equ 0x3c6a
exchange_candidate_inverse     equ 0x3c6c
exchange_candidate_status      equ 0x3c6d
exchange_transition            equ 0x0700
exchange_saved_wire            equ 0x0840
exchange_saved_wire_tail       equ exchange_saved_wire + 68
exchange_saved_wire_inverse    equ exchange_saved_wire + 74
exchange_saved_wire_status     equ exchange_saved_wire_inverse + 1
exchange_saved_early           equ 0x0890
exchange_candidate_buffer      equ 0x0700
; Offset the recovered page so early HEAD A begins exactly at the resident
; Ethernet+IPv4+TCP payload address 0x0736.  tcp_send can then build headers
; in place without overwriting unread ciphertext.
exchange_early_page            equ 0x0716
exchange_early_head_payload    equ \
    exchange_early_page + resume_early_head_a
exchange_hello_handoff         equ 0x0d00
exchange_k_prime_hold          equ 0x08c0
exchange_spent_hold            equ exchange_k_prime_hold + 32
exchange_post_stage            equ 0x2400
exchange_restore_transition    equ 0x0e00
exchange_rx_feed_max           equ 384
exchange_resumed_record_bytes  equ 68
exchange_resumed_reject_bytes  equ 64
exchange_resumed_wire_max      equ 74
exchange_wire_valid            equ 0xa5
exchange_wire_valid_inverse    equ 0x5a

%macro exchange_diagnostic 1
%ifdef RESUME_EXCHANGE_DIAGNOSTIC
    push ax
    push dx
    mov dx, 0x03f8
    mov al, %1
    out dx, al
    pop dx
    pop ax
%endif
%endmacro

%if RESUME_EXCHANGE_LIFECYCLE_START != resume_vault_lifecycle_digest
%error "EXCHANGE lifecycle start differs from shared RVL1 contract"
%endif
%if RESUME_EXCHANGE_LIFECYCLE_END != resume_vault_lifecycle_end
%error "EXCHANGE lifecycle end differs from shared RVL1 contract"
%endif

%ifdef RESUME_EXCHANGE_BROKER

%ifndef RESUME_EXCHANGE_HELLO_KEY
%error "EXCHANGE broker requires the resumed HELLO key"
%endif
%ifndef RESUME_EXCHANGE_CONNECT_KEY
%error "EXCHANGE broker requires the fixed cached-connector key"
%endif
%ifndef RESUME_EXCHANGE_TX_KEY
%error "EXCHANGE broker requires the fixed TX-controller key"
%endif
%ifndef RESUME_EXCHANGE_TX_BYTES
%error "EXCHANGE broker requires measured TX-controller bytes"
%endif
%ifndef RESUME_EXCHANGE_PERSIST_FAIL
%error "EXCHANGE broker requires the persistent failure service"
%endif

org 0x3000

resume_exchange_broker_entry:
    jmp short resume_exchange_broker
resume_exchange_broker_header:
    db 'RXB1'
    dw 1
    dw resume_exchange_broker_end - $$
    dw 0x3000
    dw resume_exchange_broker_entry

resume_exchange_broker:
    cld
    push es
    push ds
    pop es
    cmp ax, 3
    jne resume_exchange_broker_failed
    cmp byte [exchange_lifecycle_status], resume_vault_lifecycle_valid
    jne resume_exchange_broker_failed
    cmp byte [exchange_lifecycle_inverse], \
        resume_vault_lifecycle_valid_inverse
    jne resume_exchange_broker_failed
    exchange_diagnostic 'g'

    ; Restore every fixed HELLO input while no TCP deadline exists.  TX drives
    ; the complete transcript-hashing pass before it opens the socket.
    mov ax, RESUME_EXCHANGE_HELLO_KEY
    mov bx, 0x1800
    call RESUME_EXCHANGE_LOAD_PHASE
    jc resume_exchange_broker_failed
    mov bx, resume_card_ek
    mov cx, resume_card_ek_len
    mov di, 0x08c0
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_broker_terminal
    mov bx, resume_card_vault_tail + resume_vault_meta_random
    mov cx, 64
    mov di, exchange_attempt_cache
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_broker_terminal
    mov bx, resume_card_vault_head + resume_vault_head_psk
    mov cx, resume_vault_psk_len
    mov di, exchange_attempt_cache + 64
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_broker_terminal
    mov bx, resume_card_vault_tail + resume_vault_tail_ticket + 0x24
    mov cx, 4
    mov di, exchange_attempt_cache + 96
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_broker_terminal
    mov bx, resume_card_vault_tail + resume_vault_tail_ticket + 0x2a
    mov cx, 2
    mov di, exchange_attempt_cache + 100
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_broker_terminal
    exchange_diagnostic 'i'

    ; Preload the cached connector into the ninth K sector while TCP is still
    ; closed.  It survives the TX staging copy and all HELLO work, then RX
    ; deliberately replaces it after the replay and early HEAD.
    mov ax, RESUME_EXCHANGE_CONNECT_KEY
    mov bx, RESUME_EXCHANGE_RX_ORIGIN
    call RESUME_EXCHANGE_LOAD_PHASE
    jc resume_exchange_broker_terminal

    push ds
    pop es
    mov si, resume_exchange_transition_source
    mov di, exchange_transition
    mov cx, resume_exchange_transition_end - \
        resume_exchange_transition_source
    rep movsb
    mov ax, RESUME_EXCHANGE_TX_KEY
    mov cx, RESUME_EXCHANGE_TX_BYTES
    jmp exchange_transition

resume_exchange_transition_source:
    push cx
    mov bx, 0x3000
    mov dx, RESUME_EXCHANGE_LOAD_PHASE
    call dx
    pop cx
    jc resume_exchange_transition_failed_source
    push ds
    pop es
    mov si, 0x3000
    mov di, 0x3400
    rep movsb
    mov dx, 0x3400
    jmp dx
resume_exchange_transition_failed_source:
    mov dx, RESUME_EXCHANGE_PERSIST_FAIL
    jmp dx
resume_exchange_transition_end:

resume_exchange_broker_failed:
    xor ax, ax
    stc
    pop es
    ret

resume_exchange_broker_terminal:
    ; The ek import starts at 0x08c0 and can replace RSU1 from 0x0900 even
    ; when the card read itself fails.  Every later failure is terminal.
    mov dx, RESUME_EXCHANGE_PERSIST_FAIL
    jmp dx

resume_exchange_broker_end:

%if ($ - $$) > 0x0400
%error "EXCHANGE broker exceeds direct-worker slot"
%endif

%elifdef RESUME_EXCHANGE_TX

%ifndef RESUME_EXCHANGE_HELLO_BEGIN
%error "EXCHANGE TX requires resolved resumed-begin entry"
%endif
%ifndef RESUME_EXCHANGE_HELLO_NEXT
%error "EXCHANGE TX requires resolved HELLO iterator"
%endif
%ifndef RESUME_EXCHANGE_HELLO_DONE
%error "EXCHANGE TX requires resolved HELLO fragment commit"
%endif
%ifndef RESUME_EXCHANGE_HELLO_REWIND
%error "EXCHANGE TX requires resolved HELLO rewind"
%endif
%ifndef RESUME_EXCHANGE_CONNECT_ENTRY
%error "EXCHANGE TX requires the resolved cached-connect entry"
%endif
%ifndef RESUME_EXCHANGE_TCP_SEND
%error "EXCHANGE TX requires resident TCP send"
%endif
%ifndef RESUME_EXCHANGE_RX_KEY
%error "EXCHANGE TX requires the fixed RX-controller key"
%endif
%ifndef RESUME_EXCHANGE_PERSIST_FAIL
%error "EXCHANGE TX requires the persistent failure service"
%endif

org 0x3400

resume_exchange_tx_entry:
    cld
    exchange_diagnostic 'j'
    ; The transition staged this phase over 0x3000, so restore the bounded,
    ; zero-padded identity only after the exact copy has completed.
    mov bx, resume_card_vault_head + resume_vault_head_identity
    mov cx, resume_vault_head_identity_len
    mov di, exchange_ticket_identity
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_tx_failed
    mov bx, resume_card_vault_tail + resume_vault_tail_identity
    mov cx, resume_vault_tail_identity_len
    mov di, exchange_ticket_identity + resume_vault_head_identity_len
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_tx_failed
    call RESUME_EXCHANGE_HELLO_BEGIN
    jc resume_exchange_tx_failed

    ; Complete the transcript SHA pass offline.  Fragment-consumed and the
    ; dedicated prehashed advance share the checked state transition; rewind
    ; disables hashing for the byte-identical TCP replay.
.prehash:
    call RESUME_EXCHANGE_HELLO_NEXT
    jc resume_exchange_tx_failed
    or ax, ax
    jz .rewind
    call RESUME_EXCHANGE_HELLO_DONE
    jc resume_exchange_tx_failed
    jmp short .prehash
.rewind:
    call RESUME_EXCHANGE_HELLO_REWIND
    jc resume_exchange_tx_failed

    ; BROKER preloaded the connector beyond the eight-sector HELLO image.  It
    ; cannot touch HELLO's low state or 0x30c0+ SHA work.  Open TCP only now,
    ; with the complete ClientHello transcript context ready for exact replay.
    call RESUME_EXCHANGE_CONNECT_ENTRY
    jc resume_exchange_tx_failed
    exchange_diagnostic 'h'
.send:
    call RESUME_EXCHANGE_HELLO_NEXT
    jc resume_exchange_tx_failed
    or ax, ax
    jz .sent

    ; Resumed HELLO constructs its generated fragments directly at the
    ; resident frame's payload offset.  Header construction stops immediately
    ; before SI and the payload copy is source==destination.  EK and ticket
    ; fragments already live outside the frame, so every published pointer is
    ; stable without borrowing HELLO state or the 0x0f00 outer transition.
    call RESUME_EXCHANGE_TCP_SEND
    jc resume_exchange_tx_failed
    call RESUME_EXCHANGE_HELLO_DONE
    jc resume_exchange_tx_failed
    jmp short .send
.sent:
    exchange_diagnostic 'k'
    ; PREPARE sealed the only replay-permitted request before reconnect and
    ; published two exact copies in the status-last page 0x7e.  Recover the
    ; complete page in one guarded read, authenticate its generation/status,
    ; compare both 72-byte records, and send HEAD as TLS 1.3 early data before
    ; waiting for any server byte.
    mov bx, resume_card_candidate_a
    mov cx, 256
    mov di, exchange_early_page
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_tx_failed
    cmp word [exchange_early_page + resume_early_magic], \
        resume_early_magic_word0
    jne resume_exchange_tx_failed
    cmp word [exchange_early_page + resume_early_magic + 2], \
        resume_early_magic_word1
    jne resume_exchange_tx_failed
    mov ax, [exchange_early_page + resume_early_generation]
    cmp ax, [exchange_lifecycle_generation]
    jne resume_exchange_tx_failed
    not ax
    cmp ax, [exchange_early_page + resume_early_inverse_generation]
    jne resume_exchange_tx_failed
    cmp byte [exchange_early_page + resume_early_inverse_status], \
        resume_early_status_valid_inverse
    jne resume_exchange_tx_failed
    cmp byte [exchange_early_page + resume_early_status], \
        resume_early_status_valid
    jne resume_exchange_tx_failed
    mov si, exchange_early_page + resume_early_head_a
    mov di, exchange_early_page + resume_early_head_b
    mov cx, resume_early_head_len / 2
    repe cmpsw
    jne resume_exchange_tx_failed
    cmp byte [exchange_early_head_payload], 0x17
    jne resume_exchange_tx_failed
    cmp word [exchange_early_head_payload + 1], 0x0303
    jne resume_exchange_tx_failed
    cmp word [exchange_early_head_payload + 3], 0x4300
    jne resume_exchange_tx_failed
    ; PREPARE retired the native early-capable marker 2 -> 0 only after the
    ; authenticated vault was committed.  Burn 0-RTT eligibility before the
    ; first ambiguous network action.  A failed send is conservatively spent.
    cmp byte [exchange_ticket_present], 0
    jne resume_exchange_tx_failed
    mov byte [exchange_ticket_present], 1
    mov si, exchange_early_head_payload
    mov cx, resume_early_head_len
    call RESUME_EXCHANGE_TCP_SEND
    jc resume_exchange_tx_failed

    ; The eight-sector HELLO image ends at 0x2800, while its live transcript
    ; SHA work begins at 0x30c0.  Borrow two preloaded symmetric sectors at
    ; 0x2800..0x2bff for RX: loading at 0x3000 would destroy the transcript
    ; before ServerHello is fed, and POST's checked ten-sector SYM reload
    ; repairs the complete borrowed span before sym_init.  RX installs its
    ; retired-frame transition only after the complete server flight is
    ; captured.
    mov ax, RESUME_EXCHANGE_RX_KEY
    mov bx, RESUME_EXCHANGE_RX_ORIGIN
    mov dx, RESUME_EXCHANGE_LOAD_PHASE
    call dx
    jc resume_exchange_tx_failed
    mov dx, RESUME_EXCHANGE_RX_ORIGIN
    jmp dx

resume_exchange_tx_failed:
    ; The broker's ek import has already replaced RSU1.  TX cannot return
    ; through the operation caller on any failure.
    mov dx, RESUME_EXCHANGE_PERSIST_FAIL
    jmp dx

resume_exchange_tx_end:

%if ($ - $$) > RESUME_EXCHANGE_CONT_LIMIT
%error "EXCHANGE TX reaches symmetric extension work"
%endif

%elifdef RESUME_EXCHANGE_RX

%ifndef RESUME_EXCHANGE_HELLO_SERVER_BEGIN
%error "EXCHANGE RX requires resolved ServerHello begin"
%endif
%ifndef RESUME_EXCHANGE_HELLO_SERVER_FEED
%error "EXCHANGE RX requires resolved ServerHello feed"
%endif
%ifndef RESUME_EXCHANGE_HELLO_SERVER_FINISH
%error "EXCHANGE RX requires resolved ServerHello finish"
%endif
%ifndef RESUME_EXCHANGE_TCP_RECEIVE
%error "EXCHANGE RX requires resident TCP receive"
%endif
%ifndef RESUME_EXCHANGE_TCP_ACK
%error "EXCHANGE RX requires resident TCP ACK"
%endif
%ifndef RESUME_EXCHANGE_ZERO_WINDOW
%error "EXCHANGE RX requires persistent zero-window service"
%endif
%ifndef RESUME_EXCHANGE_TCP_RX_PTR
%error "EXCHANGE RX requires the resident RX payload pointer"
%endif
%ifndef RESUME_EXCHANGE_TCP_RX_LEN
%error "EXCHANGE RX requires the resident RX payload length"
%endif
%ifndef RESUME_EXCHANGE_TCP_REMOTE_ACK
%error "EXCHANGE RX requires the resident remote ACK field"
%endif
%ifndef RESUME_EXCHANGE_CRYPTO_KEY
%error "EXCHANGE RX requires the fixed crypto-broker key"
%endif
%ifndef RESUME_EXCHANGE_PERSIST_FAIL
%error "EXCHANGE RX requires the persistent failure service"
%endif

org RESUME_EXCHANGE_RX_ORIGIN

resume_exchange_rx_entry:
    cld
    push ds
    pop es
    exchange_diagnostic 'l'
    xor ax, ax
    mov di, exchange_saved_wire
    mov cx, (exchange_saved_wire_status + 1 - exchange_saved_wire) / 2
    rep stosw
    mov word [resume_exchange_rx_wire_len], 0
    mov word [resume_exchange_rx_wire_expected], 0
    mov word [resume_exchange_rx_rewind], 0
    call RESUME_EXCHANGE_HELLO_SERVER_BEGIN
    jc resume_exchange_rx_failed
    mov byte [resume_exchange_rx_header_pos], 0
    mov word [resume_exchange_rx_remaining], 0
.receive:
    call RESUME_EXCHANGE_TCP_RECEIVE
    jc resume_exchange_rx_failed
    mov si, [RESUME_EXCHANGE_TCP_RX_PTR]
    mov cx, [RESUME_EXCHANGE_TCP_RX_LEN]
.consume:
    or cx, cx
    jz .ack_more
    cmp byte [resume_exchange_rx_header_pos], 5
    je .body
    xor bx, bx
    mov bl, [resume_exchange_rx_header_pos]
    mov al, [si]
    mov [resume_exchange_rx_header + bx], al
    inc si
    dec cx
    inc byte [resume_exchange_rx_header_pos]
    cmp byte [resume_exchange_rx_header_pos], 5
    jne .consume
    cmp byte [resume_exchange_rx_header], 0x16
    jne resume_exchange_rx_failed
    cmp word [resume_exchange_rx_header + 1], 0x0303
    jne resume_exchange_rx_failed
    cmp word [resume_exchange_rx_header + 3], 0xc004
    jne resume_exchange_rx_failed
    mov word [resume_exchange_rx_remaining], 1216
    jmp short .consume
.body:
    mov ax, [resume_exchange_rx_remaining]
    or ax, ax
    jz .boundary
    mov dx, cx
    cmp cx, ax
    jbe .feed_bound
    mov cx, ax
.feed_bound:
    cmp cx, exchange_rx_feed_max
    jbe .feed
    mov cx, exchange_rx_feed_max
.feed:
    mov [resume_exchange_rx_feed_len], cx
    push dx
    call RESUME_EXCHANGE_HELLO_SERVER_FEED
    pop dx
    jc resume_exchange_rx_failed
    exchange_diagnostic 'f'
    mov ax, [resume_exchange_rx_feed_len]
    ; hello_server_feed hashes the accepted chunk before returning.  Its
    ; sha256_update call consumes CX bytes with LODSB, so SI already points at
    ; the first unconsumed byte.  Advancing it again skips a coalesced
    ; protected tail on the final TCP segment.
    sub dx, ax
    mov cx, dx
    sub [resume_exchange_rx_remaining], ax
    cmp word [resume_exchange_rx_remaining], 0
    je .boundary
    or cx, cx
    jnz .consume
    jmp .ack_more
.boundary:
    exchange_diagnostic 'u'
    ; tcp_receive has already advanced the ACK across every byte in this
    ; segment.  Retain the protected tail now instead of rewinding it and
    ; depending on a retransmission that a host-side TCP proxy may already
    ; have acknowledged.  The exact fixed profile accepts one 68-byte record
    ; with an optional six-byte compatibility CCS, fragmented at arbitrary
    ; TCP boundaries.  Accepted 0-RTT may also coalesce application bytes;
    ; rewind that excess before the zero-window ACK so it is retransmitted
    ; after the server application key is ready.
.capture:
    cmp word [resume_exchange_rx_wire_expected], 0
    jne .copy_wire
    or cx, cx
    jz .capture_more
    cmp byte [si], 0x17
    je .expect_record
    cmp byte [si], 0x14
    jne resume_exchange_rx_failed
    mov ax, exchange_resumed_wire_max
    jmp short .expected
.expect_record:
    mov ax, exchange_resumed_record_bytes
.expected:
    mov [resume_exchange_rx_wire_expected], ax
.copy_wire:
    mov ax, [resume_exchange_rx_wire_expected]
    sub ax, [resume_exchange_rx_wire_len]
    cmp cx, ax
    jbe .copy_count_ready
    sub cx, ax
    mov [resume_exchange_rx_rewind], cx
    mov cx, ax
.copy_count_ready:
    mov dx, cx
    mov di, exchange_saved_wire
    add di, [resume_exchange_rx_wire_len]
    ; The resident receive ABI may place a short final segment close enough
    ; to the saved-wire band for source and destination to overlap.  Select
    ; memmove direction explicitly; an ordinary forward REP can otherwise
    ; overwrite unread ciphertext.
    cmp di, si
    jbe .copy_forward
    add si, cx
    add di, cx
    dec si
    dec di
    std
    rep movsb
    cld
    jmp short .copied_wire
.copy_forward:
    rep movsb
.copied_wire:
    add [resume_exchange_rx_wire_len], dx
    mov ax, [resume_exchange_rx_wire_len]
    ; The accepted flight is four bytes longer because EncryptedExtensions
    ; carries the zero-length early_data extension.  Start with the maximum
    ; bound, then refine it as soon as the protected header is complete.
    xor bx, bx
    cmp byte [exchange_saved_wire], 0x14
    jne .wire_header_offset
    mov bl, 6
.wire_header_offset:
    mov dx, bx
    add dx, 5
    cmp ax, dx
    jb .capture_more
    cmp byte [exchange_saved_wire + bx], 0x17
    jne resume_exchange_rx_failed
    cmp word [exchange_saved_wire + bx + 1], 0x0303
    jne resume_exchange_rx_failed
    mov dx, [exchange_saved_wire + bx + 3]
    cmp dx, 0x3f00
    je .accepted_wire
    cmp dx, 0x3b00
    jne resume_exchange_rx_failed
    mov dx, exchange_resumed_reject_bytes
    jmp short .refined_wire
.accepted_wire:
    mov dx, exchange_resumed_record_bytes
.refined_wire:
    add dx, bx
    mov [resume_exchange_rx_wire_expected], dx
    cmp ax, dx
    jbe .refined_count
    sub ax, dx
    add [resume_exchange_rx_rewind], ax
    mov ax, dx
    mov [resume_exchange_rx_wire_len], ax
.refined_count:
    cmp ax, dx
    je .wire_ready
.capture_more:
    call RESUME_EXCHANGE_TCP_ACK
    jc resume_exchange_rx_failed
    call RESUME_EXCHANGE_TCP_RECEIVE
    jc resume_exchange_rx_failed
    mov si, [RESUME_EXCHANGE_TCP_RX_PTR]
    mov cx, [RESUME_EXCHANGE_TCP_RX_LEN]
    or cx, cx
    jz resume_exchange_rx_failed
    jmp .capture

.wire_ready:
    exchange_diagnostic 'w'
    cmp byte [exchange_saved_wire], 0x14
    jne .record_ready
    cmp word [exchange_saved_wire], 0x0314
    jne resume_exchange_rx_failed
    cmp word [exchange_saved_wire + 2], 0x0003
    jne resume_exchange_rx_failed
    cmp word [exchange_saved_wire + 4], 0x0101
    jne resume_exchange_rx_failed
    mov si, exchange_saved_wire + 6
    mov di, exchange_saved_wire
    mov cx, exchange_resumed_record_bytes / 2
    rep movsw
    xor ax, ax
    mov cx, 3
    rep stosw
.record_ready:
    cmp byte [exchange_saved_wire], 0x17
    jne resume_exchange_rx_failed
    cmp word [exchange_saved_wire + 1], 0x0303
    jne resume_exchange_rx_failed
    cmp word [exchange_saved_wire + 3], 0x3f00
    je .record_length_ready
    cmp word [exchange_saved_wire + 3], 0x3b00
    jne resume_exchange_rx_failed
    ; The fixed symmetric handoff remains 68 bytes for both dispositions.
    ; A rejected 64-byte record may have arrived after a compatibility CCS,
    ; so do not trust the four copied bytes beyond its authenticated boundary:
    ; RX/HELLO scratch can legitimately have occupied that saved-wire tail.
    xor ax, ax
    mov word [exchange_saved_wire + 64], ax
    mov word [exchange_saved_wire + 66], ax
.record_length_ready:
    mov byte [exchange_saved_wire_inverse], \
        exchange_wire_valid_inverse
    mov byte [exchange_saved_wire_status], exchange_wire_valid

    mov cx, [resume_exchange_rx_rewind]
    or cx, cx
    jz .ack_exact_boundary
    mov di, RESUME_EXCHANGE_TCP_REMOTE_ACK + 3
    sub [di], cl
    sbb [di - 1], ch
    sbb byte [di - 2], 0
    sbb byte [di - 3], 0
.ack_exact_boundary:
    exchange_diagnostic 'x'
    ; Accepted early data can already have an application response in flight,
    ; so hold it before the 8088 begins candidate/authentication work and make
    ; a failed hold terminal.  Rejected early data cannot produce a legitimate
    ; response until client Finished plus the replayed request; skip the
    ; otherwise wasted transmit on that deadline path.
    cmp word [exchange_saved_wire + 3], 0x3b00
    je .window_ready
    call RESUME_EXCHANGE_ZERO_WINDOW
    jc resume_exchange_rx_failed
.window_ready:
    exchange_diagnostic 'y'
    call RESUME_EXCHANGE_HELLO_SERVER_FINISH
    jc resume_exchange_rx_failed
    exchange_diagnostic 'm'

    ; The receive phase executes in the 0x2800 direct slot.  Once no more
    ; frames can arrive, reinstall a tiny position-independent loader in the
    ; retired 0x0700 frame and use it to replace RX atomically with CRYPTO.
    push ds
    pop es
    mov si, resume_exchange_rx_transition_source
    mov di, exchange_transition
    mov cx, resume_exchange_rx_transition_end - \
        resume_exchange_rx_transition_source
    rep movsb
    mov ax, RESUME_EXCHANGE_CRYPTO_KEY
    mov dx, exchange_transition
    jmp dx
.ack_more:
    call RESUME_EXCHANGE_TCP_ACK
    jc resume_exchange_rx_failed
    jmp .receive

resume_exchange_rx_failed:
    ; ServerHello feed may already have staged c over RSU1.  Never return
    ; through a controller whose executable spans can be only partly intact.
    mov dx, RESUME_EXCHANGE_PERSIST_FAIL
    jmp dx

resume_exchange_rx_transition_source:
    mov bx, 0x3000
    mov dx, RESUME_EXCHANGE_LOAD_PHASE
    call dx
    jc resume_exchange_rx_transition_failed_source
    mov dx, 0x3000
    jmp dx
resume_exchange_rx_transition_failed_source:
    mov dx, RESUME_EXCHANGE_PERSIST_FAIL
    jmp dx
resume_exchange_rx_transition_end:

resume_exchange_rx_header      times 5 db 0
resume_exchange_rx_header_pos  db 0
resume_exchange_rx_remaining   dw 0
resume_exchange_rx_feed_len    dw 0
resume_exchange_rx_wire_len    dw 0
resume_exchange_rx_wire_expected dw 0
resume_exchange_rx_rewind      dw 0
resume_exchange_rx_end:

%if ($ - $$) > 0x0400
%error "EXCHANGE RX exceeds its direct two-sector phase"
%endif

%elifdef RESUME_EXCHANGE_CRYPTO

%ifndef RESUME_EXCHANGE_CANDIDATE_KEY
%error "EXCHANGE crypto requires the candidate phase"
%endif
%ifndef RESUME_EXCHANGE_CANDIDATE_ENTRY
%error "EXCHANGE crypto requires the resolved candidate entry"
%endif
%ifndef RESUME_EXCHANGE_POST_KEY
%error "EXCHANGE crypto requires the fixed post-candidate key"
%endif
%ifndef RESUME_EXCHANGE_POST_BYTES
%error "EXCHANGE crypto requires measured post-candidate bytes"
%endif
%ifndef RESUME_EXCHANGE_PERSIST_FAIL
%error "EXCHANGE crypto requires the persistent failure service"
%endif

org 0x3000

resume_exchange_crypto_entry:
    cld
    push ds
    pop es
    exchange_diagnostic 'n'
    cmp byte [exchange_ticket_present], 1
    jne resume_exchange_crypto_failed
    mov byte [exchange_candidate_status], 0
    mov byte [exchange_candidate_inverse], 0

    ; Complete private import is the authority boundary for reusing its card
    ; band.  Any read failure returns before the first c write.
    mov bx, resume_card_private
    mov cx, resume_card_private_len
    mov di, 0x3600
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_crypto_failed

    ; Only now replace the private mirror with the exact live c.  Deferred FO
    ; later rereads every card byte, recomputes the bound checksum, and blocks
    ; route promotion on any mismatch.  An immediate duplicate readback here
    ; would add a second floppy sector to this deadline-critical phase without
    ; increasing the final authorization authority.
    mov al, 0x79
    mov si, 0x08c0
    mov bp, resume_card_c_len
    call resume_exchange_crypto_card_write
    jc resume_exchange_crypto_failed
    ; c ends 64 bytes into page 0x7d.  Rewrite that complete final page with
    ; c's tail followed by 192 zeros so no private-mirror suffix survives.
    push ds
    pop es
    xor ax, ax
    mov di, 0x0700
    mov cx, 128
    rep stosw
    mov si, 0x08c0 + 1024
    mov di, 0x0700
    mov cx, 32
    rep movsw
    ; Page 0x7e still owns the pre-sealed EOED at this point.  Move it into
    ; the quarantined suffix immediately after live c (0x7d40) before the
    ; candidate atomically replaces page 0x7e with m'||G||z.
    mov bx, resume_card_candidate_a + resume_early_eoed
    mov cx, resume_early_eoed_len
    mov di, 0x0740
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_crypto_failed
    cmp byte [0x0740], 0x17
    jne resume_exchange_crypto_failed
    cmp word [0x0741], 0x0303
    jne resume_exchange_crypto_failed
    cmp word [0x0743], 0x1500
    jne resume_exchange_crypto_failed
    mov al, 0x7d
    mov si, 0x0700
    mov bp, 256
    call resume_exchange_crypto_card_write
    jc resume_exchange_crypto_failed

    mov si, 0x08c0
    mov cx, resume_card_c_len / 2
    xor dx, dx
.sum_c:
    lodsw
    add dx, ax
    loop .sum_c
    or dx, dx
    jz resume_exchange_crypto_failed
    mov [exchange_candidate_c_sum], dx

    mov bx, resume_card_ek
    mov bp, resume_card_ek_len
    call resume_exchange_crypto_sum_card
    jc resume_exchange_crypto_failed
    or dx, dx
    jz resume_exchange_crypto_failed
    mov [exchange_candidate_ek_sum], dx
    mov ax, [exchange_lifecycle_generation]
    or ax, ax
    jz resume_exchange_crypto_failed
    mov [exchange_candidate_generation], ax

    ; Recover PREPARE's already-verified early-derived state before candidate
    ; replaces page 0x7e.  Recomputing the binder after ServerHello is both
    ; redundant and several seconds of avoidable critical-path work on an
    ; original-speed 8088.
    mov bx, resume_card_candidate_a + resume_early_copy_a
    mov cx, 32
    mov di, exchange_saved_early
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_crypto_failed
    mov bx, resume_card_candidate_a + resume_early_copy_b
    mov cx, 32
    mov di, 0x0700
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_crypto_failed
    mov si, exchange_saved_early
    mov di, 0x0700
    mov cx, 16
    repe cmpsw
    jne resume_exchange_crypto_failed
    mov bx, resume_card_candidate_a + resume_early_magic
    mov cx, 10
    mov di, 0x0720
    call RESUME_EXCHANGE_NE_BUF_READ
    jc resume_exchange_crypto_failed
    cmp word [0x0720], resume_early_magic_word0
    jne resume_exchange_crypto_failed
    cmp word [0x0722], resume_early_magic_word1
    jne resume_exchange_crypto_failed
    mov ax, [0x0724]
    cmp ax, [exchange_lifecycle_generation]
    jne resume_exchange_crypto_failed
    not ax
    cmp ax, [0x0726]
    jne resume_exchange_crypto_failed
    cmp byte [0x0728], resume_early_status_valid_inverse
    jne resume_exchange_crypto_failed
    cmp byte [0x0729], resume_early_status_valid
    jne resume_exchange_crypto_failed
    mov si, exchange_saved_early
    mov cx, 16
    xor dx, dx
.early_nonzero:
    lodsw
    or dx, ax
    loop .early_nonzero
    or dx, dx
    jz resume_exchange_crypto_failed

    ; Stage POST outside the candidate and retained K14 bands.  Candidate
    ; returns to its prefix at 0x2400; that prefix copies only the measured
    ; symmetric continuation to 0x3400 before the ten-sector SYM load
    ; destroys 0x2400..0x2bff.  Loading a padded sector directly at 0x3400
    ; would overwrite 0x3510..0x35ff, while staging at 0x0d00 would destroy
    ; the resumed transcript handoff needed by sym_import.
    mov ax, RESUME_EXCHANGE_POST_KEY
    mov bx, exchange_post_stage
    call RESUME_EXCHANGE_LOAD_PHASE
    jc resume_exchange_crypto_failed
    mov ax, RESUME_EXCHANGE_CANDIDATE_KEY
    mov bx, 0x1800
    call RESUME_EXCHANGE_LOAD_PHASE
    jc resume_exchange_crypto_failed
    mov ax, exchange_post_stage
    push ax
    exchange_diagnostic 'o'
    jmp RESUME_EXCHANGE_CANDIDATE_ENTRY

; BX=card, BP=count.  Return additive word checksum in DX.
resume_exchange_crypto_sum_card:
    xor dx, dx
.next:
    mov cx, bp
    cmp cx, 256
    jbe .count
    mov cx, 256
.count:
    push bx
    push cx
    push dx
    mov di, 0x0700
    call RESUME_EXCHANGE_NE_BUF_READ
    pop dx
    pop cx
    pop bx
    jc .done
    push cx
    mov si, 0x0700
    shr cx, 1
.sum:
    lodsw
    add dx, ax
    loop .sum
    pop cx
    add bx, cx
    sub bp, cx
    jnz .next
    clc
.done:
    ret

resume_exchange_crypto_card_write:
    xor bx, bx
    mov bl, [RESUME_EXCHANGE_NE_TX_START]
    push bx
    mov [RESUME_EXCHANGE_NE_TX_START], al
    mov bx, [RESUME_EXCHANGE_NIC_BASE]
    call RESUME_EXCHANGE_NE_BUF_LOAD
    pop bx
    mov [RESUME_EXCHANGE_NE_TX_START], bl
    ret

resume_exchange_crypto_failed:
    ; A partial c publication can already have replaced RSU1's return path.
    ; Failure is therefore terminal rather than a return into mutable bytes.
    mov dx, RESUME_EXCHANGE_PERSIST_FAIL
    jmp dx

resume_exchange_crypto_end:

%if ($ - $$) > 0x0400
%error "EXCHANGE crypto broker exceeds direct-worker slot"
%endif

%elifdef RESUME_EXCHANGE_POST

%ifndef RESUME_EXCHANGE_SYM_RESTORE_KEY
%error "EXCHANGE post requires the checked symmetric-prefix restore"
%endif
%ifndef RESUME_EXCHANGE_SYM_INIT
%error "EXCHANGE post requires resolved symmetric init"
%endif
%ifndef RESUME_EXCHANGE_SYM_EARLY_DERIVED
%error "EXCHANGE post requires the symmetric early-derived ABI"
%endif
%ifndef RESUME_EXCHANGE_SYM_SHARED_SECRET
%error "EXCHANGE post requires the symmetric shared-secret ABI"
%endif
%ifndef RESUME_EXCHANGE_SYM_IO
%error "EXCHANGE post requires the symmetric record I/O ABI"
%endif
%ifndef RESUME_EXCHANGE_RESTORE_KEY
%error "EXCHANGE post requires its fixed RSU1 restore worker"
%endif
%ifndef RESUME_EXCHANGE_RESTORE_BYTES
%error "EXCHANGE post requires measured RSU1 restore bytes"
%endif
%ifndef RESUME_EXCHANGE_PERSIST_FAIL
%error "EXCHANGE post requires the persistent failure service"
%endif

; POST always starts at 0x2400 so its staged architecture survives the
; symmetric-prefix load.  Its position-independent suffix is copied to
; 0x3400 first; calls outside that suffix therefore use absolute targets.
%macro exchange_post_external_call 1
    mov dx, %1
    call dx
%endmacro

%macro exchange_post_candidate_helpers 0
; The guarded leaf starts at page offset zero.  Build one full-page image with
; duplicated A/B halves.  A reported DMA failure remains terminal.  Deferred
; FO rereads and certifies both stored copies before they can authorize route
; or credential promotion, so the deadline path need not duplicate that card
; readback.
resume_exchange_post_card_write_offset:
    push ds
    pop es
    mov si, exchange_candidate_buffer
    mov di, exchange_candidate_buffer + 128
    mov cx, 64
    rep movsw
    mov al, 0x7e
    mov si, exchange_candidate_buffer
    mov bp, 256
    jmp short resume_exchange_post_card_write

resume_exchange_post_card_write:
    xor bx, bx
    mov bl, [RESUME_EXCHANGE_NE_TX_START]
    push bx
    mov [RESUME_EXCHANGE_NE_TX_START], al
    mov bx, [RESUME_EXCHANGE_NIC_BASE]
    call RESUME_EXCHANGE_NE_BUF_LOAD
    pop bx
    mov [RESUME_EXCHANGE_NE_TX_START], bl
    ret
%endmacro

org exchange_post_stage

resume_exchange_post_entry:
    cld
    push ds
    pop es
    exchange_diagnostic 'p'
    ; Candidate returned only after complete private+c consumption.  Freeze
    ; m'||G||z twice; deferred FO owns authoritative card readback.
    mov si, 0x3a40
    mov di, exchange_candidate_buffer
    mov cx, 16
    rep movsw
    mov si, 0x3b9c
    mov cx, 48
    rep movsw
    call resume_exchange_post_card_write_offset
    jc resume_exchange_post_failed
    exchange_diagnostic 's'

    ; The normal SYM restore occupies 0x1800..0x27ff, but RX temporarily owns
    ; the preloaded tail beginning at 0x2800.  EXCHANGE therefore restores
    ; every symmetric sector borrowed by RX.  No byte executing at 0x2400 may
    ; survive that load, so copy the complete position-independent suffix plus
    ; its local terminal failure path to the ordinary 0x3400 slot first.
    push ds
    pop es
    mov si, resume_exchange_post_relocated_source
    mov di, 0x3400
    mov cx, resume_exchange_post_relocated_end - \
        resume_exchange_post_relocated_source
    rep movsb

    ; c occupies 0x08c0..0x0cff and has replaced all three live RSU1 spans.
    ; Install a position-independent bridge in the retired 0x0e00 replay
    ; page.  It stages the fixed restore worker only after POST has finished.
    mov si, resume_exchange_restore_transition_source
    mov di, exchange_restore_transition
    mov cx, resume_exchange_restore_transition_end - \
        resume_exchange_restore_transition_source
    rep movsb
    mov dx, 0x3400
    jmp dx

    ; Prefix-only card helpers remain in the 0x2400 source phase and are dead
    ; before the symmetric load begins.
    exchange_post_candidate_helpers

resume_exchange_restore_transition_source:
    exchange_diagnostic 'A'
    push cx
    mov bx, 0x0700
    mov dx, RESUME_EXCHANGE_LOAD_PHASE
    call dx
    pop cx
    jc resume_exchange_restore_transition_failed_source
    exchange_diagnostic 'B'
    push ds
    pop es
    mov si, 0x0700
    mov di, 0x3400
    rep movsb
    mov dx, 0x3400
    jmp dx
resume_exchange_restore_transition_failed_source:
    mov dx, RESUME_EXCHANGE_PERSIST_FAIL
    jmp dx
resume_exchange_restore_transition_end:

%if exchange_restore_transition + \
    (resume_exchange_restore_transition_end - \
        resume_exchange_restore_transition_source) > 0x0f00
%error "EXCHANGE restore transition reaches the outer resume transition"
%endif

resume_exchange_post_relocated_source:

    ; Preserve K' across sym_init in retired low c space.
    cmp byte [exchange_ticket_present], 1
    jne resume_exchange_post_failed
    mov byte [exchange_spent_hold], 0xa5
    mov si, 0x3b9c
    mov di, exchange_k_prime_hold
    mov cx, 16
    rep movsw
    mov ax, RESUME_EXCHANGE_SYM_RESTORE_KEY
    mov bx, 0x1800
    exchange_post_external_call RESUME_EXCHANGE_LOAD_PHASE
    jc resume_exchange_post_failed
    exchange_diagnostic 't'
    exchange_post_external_call RESUME_EXCHANGE_SYM_INIT
    jc resume_exchange_post_failed
    cmp byte [exchange_spent_hold], 0xa5
    jne resume_exchange_post_failed
    mov byte [exchange_ticket_present], 1
    mov byte [exchange_spent_hold], 0
    exchange_diagnostic 'v'

    ; Candidate cannot touch the retired receive-frame prefix below 0x08c0.
    ; Import both volatile artifacts before the RSU1 restore reclaims and
    ; scrubs that entire page: the PREPARE-verified early-derived secret and
    ; the normalized protected record captured from the accepted TCP flight.
    cmp byte [exchange_saved_wire_status], exchange_wire_valid
    jne resume_exchange_post_failed
    cmp byte [exchange_saved_wire_inverse], \
        exchange_wire_valid_inverse
    jne resume_exchange_post_failed
    cmp byte [exchange_saved_wire], 0x17
    jne resume_exchange_post_failed
    cmp word [exchange_saved_wire + 1], 0x0303
    jne resume_exchange_post_failed
    cmp word [exchange_saved_wire + 3], 0x3f00
    je .saved_wire_length_ready
    cmp word [exchange_saved_wire + 3], 0x3b00
    jne resume_exchange_post_failed
.saved_wire_length_ready:
    mov si, exchange_saved_early
    mov di, RESUME_EXCHANGE_SYM_EARLY_DERIVED
    mov cx, 16
    rep movsw
    mov si, exchange_saved_wire
    mov di, RESUME_EXCHANGE_SYM_IO
    mov cx, exchange_resumed_record_bytes / 2
    rep movsw

    mov si, exchange_k_prime_hold
    mov di, RESUME_EXCHANGE_SYM_SHARED_SECRET
    mov cx, 16
    rep movsw
    exchange_diagnostic 'z'
    xor ax, ax
    mov di, exchange_saved_wire
    mov cx, (exchange_saved_early + 32 - exchange_saved_wire) / 2
    rep stosw
    exchange_diagnostic '{'

    mov byte [exchange_candidate_inverse], 0x5a
    mov byte [exchange_candidate_status], 0xa5
    exchange_diagnostic '|'
    exchange_diagnostic '}'
    mov ax, RESUME_EXCHANGE_RESTORE_KEY
    mov cx, RESUME_EXCHANGE_RESTORE_BYTES
    mov dx, exchange_restore_transition
    jmp dx

resume_exchange_post_failed:
    ; RSU1 is no longer executable after c staging.  Recovery owns the
    ; complete card/high-state scrub and cannot return through this attempt.
    mov dx, RESUME_EXCHANGE_PERSIST_FAIL
    jmp dx

resume_exchange_post_relocated_end:
%if (resume_exchange_post_relocated_end - \
    resume_exchange_post_relocated_source) > RESUME_EXCHANGE_CONT_LIMIT
%error "EXCHANGE relocated suffix reaches symmetric extension work"
%endif

resume_exchange_post_end:

%if ($ - $$) > 0x0200
%error "EXCHANGE post exceeds its staged one-sector phase"
%endif

%elifdef RESUME_EXCHANGE_RESTORE

%ifndef RESUME_EXCHANGE_CONTROLLER_HEAD_KEY
%error "EXCHANGE restore requires the fixed RSU1 head-sector key"
%endif
%ifndef RESUME_EXCHANGE_CONTROLLER_TAIL_KEY
%error "EXCHANGE restore requires the fixed RSU1 tail-sector key"
%endif
%ifndef RESUME_EXCHANGE_CONTROLLER_LOW_START
%error "EXCHANGE restore requires the RSU1 low start"
%endif
%ifndef RESUME_EXCHANGE_CONTROLLER_LOW_BYTES
%error "EXCHANGE restore requires the RSU1 low byte count"
%endif
%ifndef RESUME_EXCHANGE_CONTROLLER_PREFIX_START
%error "EXCHANGE restore requires the RSU1 prefix start"
%endif
%ifndef RESUME_EXCHANGE_CONTROLLER_PREFIX_BYTES
%error "EXCHANGE restore requires the RSU1 prefix byte count"
%endif
%ifndef RESUME_EXCHANGE_CONTROLLER_SUFFIX_START
%error "EXCHANGE restore requires the RSU1 suffix start"
%endif
%ifndef RESUME_EXCHANGE_CONTROLLER_SUFFIX_BYTES
%error "EXCHANGE restore requires the RSU1 suffix byte count"
%endif
%ifndef RESUME_EXCHANGE_PERSIST_FAIL
%error "EXCHANGE restore requires the persistent failure service"
%endif

exchange_restore_stage          equ 0x0700
exchange_restore_head_bytes     equ 0x0200
exchange_restore_low_tail_bytes equ \
    RESUME_EXCHANGE_CONTROLLER_LOW_BYTES - exchange_restore_head_bytes

%if RESUME_EXCHANGE_CONTROLLER_LOW_BYTES < exchange_restore_head_bytes
%error "EXCHANGE restore RSU1 low span is shorter than its head sector"
%endif
%if exchange_restore_low_tail_bytes + \
    RESUME_EXCHANGE_CONTROLLER_PREFIX_BYTES + \
    RESUME_EXCHANGE_CONTROLLER_SUFFIX_BYTES > 0x0200
%error "EXCHANGE restore RSU1 packed tail exceeds its second file sector"
%endif
%if RESUME_EXCHANGE_CONTROLLER_LOW_START + \
    RESUME_EXCHANGE_CONTROLLER_LOW_BYTES > exchange_hello_handoff
%error "EXCHANGE restore RSU1 low span reaches the transcript handoff"
%endif
%if RESUME_EXCHANGE_CONTROLLER_PREFIX_START + \
    RESUME_EXCHANGE_CONTROLLER_PREFIX_BYTES > exchange_hello_handoff
%error "EXCHANGE restore RSU1 prefix reaches the transcript handoff"
%endif
%if RESUME_EXCHANGE_CONTROLLER_SUFFIX_START + \
    RESUME_EXCHANGE_CONTROLLER_SUFFIX_BYTES > exchange_hello_handoff
%error "EXCHANGE restore RSU1 suffix reaches the transcript handoff"
%endif

org 0x3400

resume_exchange_restore_entry:
    cld
    exchange_diagnostic 'C'
    push ds
    pop es

    ; The restored symmetric overlay still owns 0x3000..0x33ff.  Use only the
    ; retired network/ciphertext page at 0x0700: load the packed tail sector,
    ; scatter low-tail||prefix||suffix, then load and copy the head sector.
    ; This leaves the deliberate 0x0c20..0x0c2f hole and the 0x0d00 transcript
    ; handoff untouched.
    mov ax, RESUME_EXCHANGE_CONTROLLER_TAIL_KEY
    mov bx, exchange_restore_stage
    call RESUME_EXCHANGE_LOAD_PHASE
    jc resume_exchange_restore_terminal
    exchange_diagnostic 'D'
    mov si, exchange_restore_stage
    mov di, RESUME_EXCHANGE_CONTROLLER_LOW_START + \
        exchange_restore_head_bytes
    mov cx, exchange_restore_low_tail_bytes
    rep movsb
    mov si, exchange_restore_stage + exchange_restore_low_tail_bytes
    mov di, RESUME_EXCHANGE_CONTROLLER_PREFIX_START
    mov cx, RESUME_EXCHANGE_CONTROLLER_PREFIX_BYTES
    rep movsb
    mov si, exchange_restore_stage + exchange_restore_low_tail_bytes + \
        RESUME_EXCHANGE_CONTROLLER_PREFIX_BYTES
    mov di, RESUME_EXCHANGE_CONTROLLER_SUFFIX_START
    mov cx, RESUME_EXCHANGE_CONTROLLER_SUFFIX_BYTES
    rep movsb

    mov ax, RESUME_EXCHANGE_CONTROLLER_HEAD_KEY
    mov bx, exchange_restore_stage
    call RESUME_EXCHANGE_LOAD_PHASE
    jc resume_exchange_restore_terminal
    exchange_diagnostic 'E'
    mov si, exchange_restore_stage
    mov di, RESUME_EXCHANGE_CONTROLLER_LOW_START
    mov cx, exchange_restore_head_bytes
    rep movsb

    xor ax, ax
    mov di, exchange_restore_stage
    mov cx, 0x0100
    rep stosw

%ifdef RESUME_EXCHANGE_DIAGNOSTIC
    ; Drain POST's final marker and leave DX on COM1 data for RSU1's compact
    ; post-import checkpoint.
    mov dx, 0x03fd
    xor cx, cx
.diagnostic_wait_thr_empty:
    in al, dx
    test al, 0x20
    loopz .diagnostic_wait_thr_empty
    mov dl, 0xf8
    mov al, 'F'
    out dx, al
%endif
    mov ax, 1
    clc
    pop es
    ret

resume_exchange_restore_terminal:
    mov dx, RESUME_EXCHANGE_PERSIST_FAIL
    jmp dx

resume_exchange_restore_end:

%if ($ - $$) > RESUME_EXCHANGE_CONT_LIMIT
%error "EXCHANGE restore reaches symmetric extension work"
%endif

%else
%error "select one RESUME_EXCHANGE phase"
%endif
