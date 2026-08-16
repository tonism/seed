; TLS 1.3 286 protected-flight coordinator.
;
; The acquisition invocation authenticates the server Finished, sends client
; Finished and one immutable credential-free HEAD request, authenticates the
; response plus a bounded NewSessionTicket, then closes and chains to offline
; FO/X.509 authentication.  No credential is exposed on this provisional
; connection.  The resumed invocation requires a complete bounded
; NewSessionTicket plus an authenticated application record with an allowed
; HTTP status before publishing the final application keys.  It need not wait
; indefinitely for a credential-free response-header tail; later
; business-request traffic advances the same authenticated record sequence.
;
; The symmetric image keeps mutable state at 0x7380..0x79ad.  This controller
; is disposable after its one-way auth chain: later P256W7/ECDSAW7 decodes may
; overwrite its lower 0x6300 code, but remain below the retired symmetric
; state and the 0x7a00 stack guard.

bits 16
cpu 8086
org 0x6300

%include "tls13/tls13_286_abi.inc"
%include "tls13-286-runtime-abi.inc"
%include "tls13-286-flight-sym-abi.inc"

flight_record_scratch_off     equ 0
flight_record_plain_max       equ tls13_286_record_plain_bytes
flight_wire_chunk             equ 0x0d00
flight_wire_chunk_max         equ 384
flight_parse_chunk            equ 0x0e80
flight_parse_chunk_max        equ 384
flight_message_work           equ 0x0b00
flight_message_work_max       equ 384
flight_sym_tag                equ TLS13_286_FLIGHT_SYM_RECEIVED_SERVER_FINISHED + 32
flight_capture_mode           equ 0
flight_resumed_mode           equ 1
flight_epoch_handshake        equ 0
flight_epoch_application      equ 1
flight_expected_ee            equ 0
flight_expected_certificate   equ 1
flight_expected_cv            equ 2
flight_expected_finished      equ 3
flight_expected_done          equ 4
flight_http_max               equ 2048

flight_header:
    db 'S286FL02'
    dw tls13_286_abi_version
    dw flight_image_end - flight_header
    dw 1
flight_entry_table:
    dw flight_main

flight_main:
    cld
    cmp si, tls13_286_tail_footer_off
    jne .abort
    cmp bx, [cs:tls13_286_root_state_crypto_seg]
    jne .abort
    mov [cs:flight_crypto_seg], bx
    mov ax, bx
    add ax, tls13_286_record_plain_off / 16
    mov [cs:flight_record_seg], ax
    call flight_select_mode
    jc .abort
    call flight_load_symmetric
    jc .abort
    call flight_start_schedule
    jc .abort
    call flight_parser_reset
    jmp short .record
.abort:
    jmp flight_abort

.record:
    call flight_open_record
    jc .abort
    cmp byte [cs:flight_expected], flight_expected_done
    jne .record

    cmp byte [cs:flight_mode], flight_capture_mode
    jne flight_finish_resumed
    call flight_begin_acquisition_dialogue
    jc .abort
.application_record:
    call flight_open_record
    jc .abort
    cmp word [cs:flight_http_done], 0x0101
    jne .application_record
    cmp word [cs:flight_nst_pos], 0
    jne .application_record
    call flight_export_tentative_ticket
    jc .abort
    call flight_publish_capture
    call flight_close_socket
    jc .abort
    call flight_retire_symmetric
    call word [cs:TLS13_286_LINK_NIC_RESTORE_SLOT]
    mov ax, tls13_286_tail_kind_authenticate
    jmp word [cs:tls13_286_root_service_chain]

flight_finish_resumed:
    call flight_begin_acquisition_dialogue
    jc flight_main.abort
 .application_record:
    call flight_open_record
    jc flight_main.abort
    cmp byte [cs:flight_http_status_valid], 1
    jne .application_record
    cmp byte [cs:flight_ticket_seen], 1
    jne .application_record
    cmp word [cs:flight_nst_pos], 0
    jne .application_record
    call flight_publish_application
    call word [cs:TLS13_286_LINK_NIC_RESTORE_SLOT]
    jmp word [cs:tls13_286_abort_capsule_load + \
        tls13_286_abort_capsule_success_ptr]

; Complete either handshake and transmit the fixed credential-free liveness
; request before doing any deferred server-side application work.
; The resident TCP path advertises only a 256-byte window, which bounds bytes
; queued while the target derives the server application key.
flight_begin_acquisition_dialogue:
    call TLS13_286_FLIGHT_SYM_BUILD_CLIENT_FINISHED
    jc .bad
    cmp ax, 58
    jne .bad
    call flight_send_sym_io
    jc .bad
    call TLS13_286_FLIGHT_SYM_DERIVE_CLIENT_APPLICATION
    jc .bad
    call TLS13_286_FLIGHT_SYM_BUILD_HEAD
    jc .bad
    cmp ax, 72
    jne .bad
    call flight_send_sym_io
    jc .bad
    call TLS13_286_FLIGHT_SYM_DERIVE_SERVER_APPLICATION
    jc .bad
    mov byte [cs:flight_epoch], flight_epoch_application
    push ds
    pop es
    xor ax, ax
    mov di, flight_http_total
    mov cx, 4
    rep stosw
    mov byte [cs:flight_http_status_valid], 0
    ret
.bad:
    stc
    ret

flight_send_sym_io:
    mov si, TLS13_286_FLIGHT_SYM_IO_BASE
    mov cx, ax
    jmp TLS13_286_LINK_TCP_SEND

flight_select_mode:
    mov es, [cs:flight_crypto_seg]
    cmp word [es:tls13_286_attempt_fresh_status_inv_off], \
        (tls13_286_entropy_status_ready << 8) | \
        tls13_286_entropy_status_ready_inv
    jne .resumed
    mov byte [cs:flight_mode], flight_capture_mode
    xor ax, ax
    mov di, tls13_286_certificate_len_off
    mov cx, 4
    rep stosw
    mov word [es:tls13_286_ticket_status_inv_off], 0
    jmp short .good
.resumed:
    cmp word [es:tls13_286_attempt_fresh_status_inv_off], \
        (tls13_286_entropy_status_used << 8) | \
        tls13_286_entropy_status_used_inv
    jne .bad
    cmp word [es:tls13_286_capture_status_inv_off], \
        (tls13_286_flight_status_valid << 8) | \
        tls13_286_flight_status_inverse
    jne .bad
    cmp word [es:tls13_286_auth_status_inv_off], \
        (tls13_286_flight_status_valid << 8) | \
        tls13_286_flight_status_inverse
    jne .bad
    cmp word [es:tls13_286_ticket_status_inv_off], \
        (tls13_286_ticket_status_used << 8) | \
        tls13_286_ticket_status_used_inv
    jne .bad
    mov byte [cs:flight_mode], flight_resumed_mode
.good:
    xor ax, ax
    mov es, ax
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

; Reuse the immutable symmetric implementation already shipped for K14.
; Only its absolute mutable-state operands differ on the 286: the generated
; relocation set is proven byte-for-byte against a freshly assembled 286
; image.  This retires the duplicate ten-sector tail component while retaining
; an exact target CRC check before any symmetric entry is called.
flight_load_symmetric:
    mov ds, [cs:flight_crypto_seg]
    cmp word [tls13_286_symmetric_stage_status_inv_off], \
        (tls13_286_symmetric_stage_status_valid << 8) | \
        tls13_286_symmetric_stage_status_inverse
    jne .bad_high
    xor ax, ax
    ; Consume status before copying so no later entry can replay a partially
    ; transferred stage.  The bytes are public immutable code; their complete
    ; relocated-image CRC below remains the authoritative integrity check.
    mov word [tls13_286_symmetric_stage_status_inv_off], ax
    mov es, ax
    mov si, tls13_286_symmetric_stage_off
    mov di, TLS13_286_LINK_SYM_DESTINATION
    mov cx, tls13_286_symmetric_stage_bytes / 2
    rep movsw
    ; The normal record-open wipe retires the public staged bytes themselves
    ; before authenticated plaintext is written there.
    mov ds, ax
    call flight_relocate_symmetric
    mov si, TLS13_286_FLIGHT_SYM_IMAGE_START
    push si
    mov di, flight_sym_magic
    mov cx, 4
    repe cmpsw
    pop si
    jne .bad
    cmp word [si + 8], tls13_286_abi_version
    jne .bad
    cmp word [si + 10], \
        TLS13_286_FLIGHT_SYM_IMAGE_END - TLS13_286_FLIGHT_SYM_IMAGE_START
    jne .bad
    cmp word [si + 30], TLS13_286_FLIGHT_SYM_ENTRY_COUNT
    jne .bad
    mov dx, TLS13_286_FLIGHT_SYM_IMAGE_END - \
        TLS13_286_FLIGHT_SYM_IMAGE_START
    call flight_crc16
    cmp ax, TLS13_286_FLIGHT_SYM_RELOCATED_CRC16
    jne .bad
    ret
.bad:
    stc
    ret
.bad_high:
    xor ax, ax
    mov ds, ax
    mov es, ax
    stc
    ret

flight_relocate_symmetric:
    mov si, flight_sym_relocations
    mov cx, TLS13_286_FLIGHT_SYM_RELOCATION_COUNT
.word:
    lodsw
    xchg ax, bx
    add bh, TLS13_286_FLIGHT_SYM_IMAGE_START / 256
    ; The authenticated relocation table fixes the write address.  A corrupt
    ; source word can only change that word's value and is rejected by the
    ; complete relocated-image CRC below, so per-word value bounds were
    ; redundant.
    add word [bx], TLS13_286_FLIGHT_SYM_RELOCATION_DELTA
    loop .word
    mov word [TLS13_286_FLIGHT_SYM_IMAGE_START + \
        TLS13_286_FLIGHT_SYM_HEADER_ARENA_FLOOR_OFF], \
        TLS13_286_FLIGHT_SYM_RELOCATED_ARENA_FLOOR
    mov word [TLS13_286_FLIGHT_SYM_IMAGE_START + \
        TLS13_286_FLIGHT_SYM_HEADER_STACK_GUARD_OFF], \
        TLS13_286_FLIGHT_SYM_RELOCATED_STACK_GUARD
    ret

; CRC-16/CCITT-FALSE over DS:SI, nonzero DX bytes.
flight_crc16:
    mov ax, 0xffff
.byte:
    xor ah, [si]
    inc si
    mov cx, 8
.bit:
    shl ax, 1
    jnc .plain
    xor ax, 0x1021
.plain:
    loop .bit
    dec dx
    jnz .byte
    ret

flight_sym_magic:
    db 'T13SYM02'
flight_sym_relocations:
    TLS13_286_FLIGHT_SYM_EMIT_RELOCATIONS

flight_start_schedule:
    call TLS13_286_FLIGHT_SYM_INIT
    cmp byte [cs:flight_mode], flight_resumed_mode
    je .resume
    call TLS13_286_FLIGHT_SYM_TRANSCRIPT_IMPORT
    jc .bad
    call flight_copy_hybrid
    call TLS13_286_FLIGHT_SYM_CRITICAL_SCHEDULE
    jc .bad
    jmp short .scheduled
.resume:
    call flight_import_resumption_early
    jc .bad
    call TLS13_286_FLIGHT_SYM_TRANSCRIPT_IMPORT
    jc .bad
    call flight_copy_hybrid
    call TLS13_286_FLIGHT_SYM_RESUMPTION_HANDSHAKE
    jc .bad
.scheduled:
    ; The symmetric schedule now owns all live-socket derivatives.  Acquisition
    ; deliberately retains only its ML-KEM dk for the offline full-FO
    ; equivalence check; resumption retires every private asymmetric and ticket
    ; bearer byte immediately.
    mov es, [cs:flight_crypto_seg]
    xor ax, ax
    cmp byte [cs:flight_mode], flight_capture_mode
    jne .wipe_all
    mov di, tls13_286_entropy_seed_off
    mov cx, (tls13_286_hybrid_secret_off + \
        tls13_286_hybrid_secret_bytes - tls13_286_entropy_seed_off) / 2
    jmp short .wipe
.wipe_all:
    mov di, tls13_286_private_off
    mov cx, (tls13_286_hybrid_secret_off + \
        tls13_286_hybrid_secret_bytes - tls13_286_private_off) / 2
.wipe:
    rep stosw
    cmp byte [cs:flight_mode], flight_capture_mode
    je .wiped
    mov di, tls13_286_resumption_master_off
    mov cx, (tls13_286_ticket_nonce_off + tls13_286_ticket_nonce_max - \
        tls13_286_resumption_master_off) / 2
    rep stosw
    mov di, tls13_286_ticket_truncated_hash_off
    mov cx, (tls13_286_ticket_meta_end - \
        tls13_286_ticket_truncated_hash_off) / 2
    rep stosw
.wiped:
    mov es, ax
    ret
.bad:
    stc
    ret

flight_copy_hybrid:
    push ds
    mov ds, [cs:flight_crypto_seg]
    xor ax, ax
    mov es, ax
    mov si, tls13_286_hybrid_secret_off
    mov di, TLS13_286_FLIGHT_SYM_INPUT_SHARED_SECRET
    mov cx, tls13_286_hybrid_secret_bytes / 2
    rep movsw
    pop ds
    ret

; Import the ticket-only early "derived" secret that authenticated HELLO
; computed before TCP.  Consume READY before reading, require its complete
; bytewise complement, and wipe both copies on every return.  The strict
; ServerHello parser requires selected_identity=0; the later server Finished
; remains the cryptographic proof of the same PSK and fresh hybrid secret.
flight_import_resumption_early:
    mov ds, [cs:flight_crypto_seg]
    cmp word [tls13_286_resumption_early_status_inv_off], \
        (tls13_286_resumption_early_status_valid << 8) | \
        tls13_286_resumption_early_status_inverse
    jne .bad_high
    xor ax, ax
    mov word [tls13_286_resumption_early_status_inv_off], ax
    mov es, ax
    mov si, tls13_286_resumption_early_off
    mov bx, tls13_286_resumption_early_inverse_off
    mov di, TLS13_286_FLIGHT_SYM_HANDSHAKE_DERIVED
    mov cx, tls13_286_resumption_early_bytes
    xor dx, dx
.copy:
    lodsb
    stosb
    xor al, [bx]
    inc bx
    inc al
    or dl, al
    loop .copy
    push dx
    mov es, [cs:flight_crypto_seg]
    xor ax, ax
    mov di, tls13_286_resumption_early_off
    mov cx, (tls13_286_resumption_early_status_off - \
        tls13_286_resumption_early_off + 1) / 2
    rep stosw
    mov es, ax
    mov ds, ax
    pop dx
    or dl, dl
    jnz .bad
    ret
.bad_high:
    xor ax, ax
    mov ds, ax
    mov es, ax
.bad:
    stc
    ret

; ---------------------------------------------------------------------------
; Protected record stream
; ---------------------------------------------------------------------------

flight_open_record:
.next_header:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov di, TLS13_286_FLIGHT_SYM_IO_BASE
    push di
    call flight_wire_byte
    pop di
    jc .bad
    cmp al, 0x14
    je .compat_ccs
    stosb
    mov cx, 4
.header:
    push cx
    push di
    call flight_wire_byte
    pop di
    pop cx
    jc .bad
    stosb
    loop .header
    cmp byte [TLS13_286_FLIGHT_SYM_IO_BASE], 0x17
    jne .bad
    cmp word [TLS13_286_FLIGHT_SYM_IO_BASE + 1], 0x0303
    jne .bad
    mov ax, [TLS13_286_FLIGHT_SYM_IO_BASE + 3]
    xchg al, ah
    cmp ax, 17
    jb .bad
    sub ax, 16
    cmp ax, flight_record_plain_max
    ja .bad
    mov [cs:flight_record_plain], ax
    xor ax, ax
    cmp byte [cs:flight_epoch], flight_epoch_application
    je .app_open
    call TLS13_286_FLIGHT_SYM_SERVER_HS_OPEN_BEGIN
    jmp short .opened
.app_open:
    call TLS13_286_FLIGHT_SYM_SERVER_APP_OPEN_BEGIN
.opened:
    jc .bad

    mov word [cs:flight_record_pos], 0
.cipher:
    mov ax, [cs:flight_record_pos]
    cmp ax, [cs:flight_record_plain]
    jae .tag
    call flight_wire_available
    jc .bad
    mov dx, [cs:flight_record_plain]
    sub dx, [cs:flight_record_pos]
    cmp cx, dx
    jbe .chunk
    mov cx, dx
.chunk:
    mov [cs:flight_chunk_len], cx
    mov [cs:flight_chunk_ptr], si
    call TLS13_286_FLIGHT_SYM_OPEN_CHUNK
    jc .bad
    push ds
    mov si, [cs:flight_chunk_ptr]
    mov cx, [cs:flight_chunk_len]
    xor ax, ax
    mov ds, ax
    mov es, [cs:flight_record_seg]
    mov di, flight_record_scratch_off
    add di, [cs:flight_record_pos]
    rep movsb
    pop ds
    xor ax, ax
    mov es, ax
    mov cx, [cs:flight_chunk_len]
    add [cs:flight_wire_ptr], cx
    sub [cs:flight_wire_left], cx
    add [cs:flight_record_pos], cx
    jmp short .cipher

.tag:
    mov di, flight_sym_tag
    mov cx, 16
.tag_byte:
    push cx
    push di
    call flight_wire_byte
    pop di
    pop cx
    jc .bad
    stosb
    loop .tag_byte
    mov si, flight_sym_tag
    call TLS13_286_FLIGHT_SYM_OPEN_FINISH
    jc .bad
    call flight_accept_inner_plaintext
    jc .bad
    ret
.compat_ccs:
    ; RFC 8446 middlebox compatibility permits any number of unencrypted,
    ; exact ChangeCipherSpec records after ClientHello and before peer
    ; Finished.  Consume them through the same bounded stream abstraction so
    ; coalesced and TCP-split records behave identically; reject malformed CCS.
    cmp byte [cs:flight_epoch], flight_epoch_handshake
    jne .bad
    mov si, flight_compat_ccs_tail
    mov cx, 5
.compat_ccs_byte:
    push cx
    push si
    call flight_wire_byte
    pop si
    pop cx
    jc .bad
    cmp al, [cs:si]
    jne .bad
    inc si
    loop .compat_ccs_byte
    jmp .next_header
.bad:
    call flight_wipe_record
    stc
    ret

; Authenticate first, then remove only zero padding and the required handshake
; content-type byte.  No plaintext reaches the parser before open_finish.
flight_accept_inner_plaintext:
    mov cx, [cs:flight_record_plain]
    or cx, cx
    jz .bad
    mov ds, [cs:flight_record_seg]
    mov si, flight_record_scratch_off
    add si, cx
.padding:
    dec si
    mov al, [si]
    or al, al
    jnz .type
    loop .padding
    jmp .bad_ds
.type:
    dec cx
    cmp byte [cs:flight_epoch], flight_epoch_application
    je .application
    cmp al, 0x16
    jne .bad_ds
    mov byte [cs:flight_inner_type], 0x16
    jmp short .content
.application:
    cmp al, 0x16
    je .app_type
    cmp al, 0x17
    jne .bad_ds
.app_type:
    mov [cs:flight_inner_type], al
.content:
    or cx, cx
    jz .bad_ds
    mov [cs:flight_record_content], cx
    xor ax, ax
    mov ds, ax
    mov word [cs:flight_record_pos], 0
.parse:
    mov ax, [cs:flight_record_pos]
    cmp ax, [cs:flight_record_content]
    jae .done
    mov cx, [cs:flight_record_content]
    sub cx, ax
    cmp cx, flight_parse_chunk_max
    jbe .copy
    mov cx, flight_parse_chunk_max
.copy:
    mov [cs:flight_chunk_len], cx
    push ds
    mov ds, [cs:flight_record_seg]
    mov si, flight_record_scratch_off
    add si, [cs:flight_record_pos]
    xor ax, ax
    mov es, ax
    mov di, flight_parse_chunk
    rep movsb
    pop ds
    mov es, ax
    mov si, flight_parse_chunk
    mov cx, [cs:flight_chunk_len]
    ; The parsers reuse flight_chunk_len while hashing/copying their bounded
    ; messages.  Preserve this outer plaintext cursor across the call.
    push cx
    cmp byte [cs:flight_epoch], flight_epoch_application
    je .post
    call flight_parse_bytes
    jmp short .parsed
.post:
    call flight_post_parse_bytes
.parsed:
    pop ax
    jc .bad
    add [cs:flight_record_pos], ax
    jmp short .parse
.done:
    call flight_wipe_record
    ret
.bad_ds:
    xor ax, ax
    mov ds, ax
.bad:
    call flight_wipe_record
    stc
    ret

; Feed authenticated application-epoch plaintext only after its complete tag
; has verified.  HTTP application bytes may span records.  NewSessionTicket
; handshake messages may also span records, but a partial handshake message
; cannot be interleaved with application data.
flight_post_parse_bytes:
    cmp byte [cs:flight_inner_type], 0x16
    je flight_post_nst_bytes
    cmp word [cs:flight_nst_pos], 0
    jne .bad
    jmp flight_post_http_bytes
.bad:
    stc
    ret

flight_post_nst_bytes:
.byte:
    lodsb
    mov bx, [cs:flight_nst_pos]
    cmp bx, flight_message_work_max
    jae .bad
    mov [flight_message_work + bx], al
    inc bx
    mov [cs:flight_nst_pos], bx
    cmp bx, 4
    jb .next
    jne .body
    cmp byte [flight_message_work], 4
    jne .bad
    cmp byte [flight_message_work + 1], 0
    jne .bad
    mov ax, [flight_message_work + 2]
    xchg al, ah
    add ax, 4
    jc .bad
    cmp ax, flight_message_work_max
    ja .bad
    mov [cs:flight_nst_total], ax
.body:
    cmp bx, [cs:flight_nst_total]
    jb .next
    jne .bad
    push cx
    push si
    mov si, flight_message_work
    mov cx, bx
    call TLS13_286_FLIGHT_SYM_PARSE_NST
    pop si
    pop cx
    jc .bad
    mov byte [cs:flight_ticket_seen], 1
    mov word [cs:flight_nst_pos], 0
.next:
    loop .byte
    clc
    ret
.bad:
    stc
    ret

; Strict bounded HTTP/1.1 HEAD-response header DFA.  Accept 2xx, 4xx other
; than 425, or 5xx; forbid control bytes except HTAB/CR/LF and require the
; response to end exactly at CRLFCRLF.
flight_post_http_bytes:
.byte:
    cmp byte [cs:flight_http_done], 0
    jne .bad
    mov bx, [cs:flight_http_total]
    cmp bx, flight_http_max
    jae .bad
    inc word [cs:flight_http_total]
    lodsb
    cmp bx, 9
    jb .prefix
    je .status_hundreds
    cmp bx, 11
    jbe .status_tail
    cmp bx, 12
    je .status_space
    cmp al, 9
    je .header
    cmp al, 10
    je .header
    cmp al, 13
    je .header
    cmp al, 0x20
    jb .bad
    cmp al, 0x7e
    ja .bad
.header:
    xor bx, bx
    mov bl, [cs:flight_http_match]
    or bl, bl
    jz .match_cr
    cmp bl, 1
    je .match_lf
    cmp bl, 2
    je .match_second_cr
    cmp al, 10
    jne .bad
    mov byte [cs:flight_http_done], 1
    jmp .next
.match_cr:
    cmp al, 13
    je .first_cr
    cmp al, 10
    je .bad
    jmp .next
.first_cr:
    mov byte [cs:flight_http_match], 1
    jmp .next
.match_lf:
    cmp al, 10
    jne .bad
    mov byte [cs:flight_http_match], 2
    jmp short .next
.match_second_cr:
    cmp al, 13
    je .second_cr
    cmp al, 10
    je .bad
    mov byte [cs:flight_http_match], 0
    jmp short .next
.second_cr:
    mov byte [cs:flight_http_match], 3
    jmp short .next
.prefix:
    cmp al, [cs:flight_http_prefix + bx]
    jne .bad
    jmp short .next
.status_hundreds:
    mov byte [cs:flight_http_425], 0
    cmp al, '4'
    je .possible_425
    cmp al, '2'
    je .next
    cmp al, '5'
    jne .bad
    jmp short .next
.possible_425:
    mov byte [cs:flight_http_425], 1
    jmp short .next
.status_tail:
    cmp al, '0'
    jb .bad
    cmp al, '9'
    ja .bad
    cmp byte [cs:flight_http_425], 0
    je .next
    cmp bx, 10
    jne .third_digit
    cmp al, '2'
    je .next
    mov byte [cs:flight_http_425], 0
    jmp short .next
.third_digit:
    cmp al, '5'
    je .bad
    mov byte [cs:flight_http_425], 0
    jmp short .next
.status_space:
    cmp al, ' '
    jne .bad
    mov byte [cs:flight_http_status_valid], 1
.next:
    dec cx
    jnz .byte
    clc
    ret
.bad:
    stc
    ret

flight_wire_byte:
    call flight_wire_available
    jc .bad
    lodsb
    mov [cs:flight_wire_ptr], si
    dec word [cs:flight_wire_left]
    ret
.bad:
    stc
    ret

flight_wire_available:
    cmp word [cs:flight_wire_left], 0
    jne .ready
    call flight_refill_wire
    jc .bad
.ready:
    mov si, [cs:flight_wire_ptr]
    mov cx, [cs:flight_wire_left]
    ret
.bad:
    stc
    ret

flight_refill_wire:
    mov es, [cs:flight_crypto_seg]
    cmp byte [es:tls13_286_pending_wire_status_inv_off], \
        tls13_286_pending_wire_status_inverse
    jne .network
    cmp byte [es:tls13_286_pending_wire_status_off], \
        tls13_286_pending_wire_status_valid
    jne .bad
    mov cx, [es:tls13_286_pending_wire_len_off]
    cmp cx, flight_wire_chunk_max
    ja .bad
    mov [cs:flight_pending_len], cx
    mov byte [es:tls13_286_pending_wire_status_off], 0
    push ds
    mov ds, [cs:flight_crypto_seg]
    mov si, tls13_286_pending_wire_off
    xor ax, ax
    mov es, ax
    mov di, flight_wire_chunk
    rep movsb
    pop ds
    mov es, ax
    mov cx, [cs:flight_crypto_seg]
    mov es, cx
    xor ax, ax
    mov di, tls13_286_pending_wire_off
    mov cx, tls13_286_pending_wire_max / 2
    rep stosw
    mov word [es:tls13_286_pending_wire_len_off], 0
    mov byte [es:tls13_286_pending_wire_status_inv_off], 0
    mov es, ax
    mov cx, [cs:flight_pending_len]
    or cx, cx
    jz .network
    jmp short .publish
.network:
    xor ax, ax
    mov es, ax
    call TLS13_286_LINK_TCP_RECEIVE
    jc .bad
    mov si, [TLS13_286_LINK_TCP_RX_PAYLOAD_PTR]
    mov cx, [TLS13_286_LINK_TCP_RX_PAYLOAD_LEN]
    or cx, cx
    jz .bad
    cmp cx, flight_wire_chunk_max
    ja .bad
    mov [cs:flight_pending_len], cx
    push ds
    pop es
    mov di, flight_wire_chunk
    rep movsb
    call TLS13_286_LINK_TCP_ACK
    jc .bad
    mov cx, [cs:flight_pending_len]
.publish:
    mov word [cs:flight_wire_ptr], flight_wire_chunk
    mov [cs:flight_wire_left], cx
    ret
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

flight_wipe_record:
    push ax
    push cx
    push di
    push es
    mov es, [cs:flight_record_seg]
    xor ax, ax
    mov di, flight_record_scratch_off
    mov cx, flight_record_plain_max / 2
    rep stosw
    mov es, ax
    pop es
    pop di
    pop cx
    pop ax
    ret

; ---------------------------------------------------------------------------
; Authenticated handshake parser and transcript control
; ---------------------------------------------------------------------------

flight_parser_reset:
    mov word [cs:flight_expected], \
        (flight_epoch_handshake << 8) | flight_expected_ee
    mov byte [cs:flight_header_pos], 0
    mov word [cs:flight_wire_left], 0
    ; The coordinator state survives component reloads in the same boot.
    ; Acquisition advances this byte to the application epoch, so a later
    ; resumption must explicitly return to the handshake epoch before it can
    ; accept the peer's RFC 8446 compatibility CCS and first protected flight.
    mov byte [cs:flight_epoch], flight_epoch_handshake
    ret

flight_parse_bytes:
    or cx, cx
    jz .bad
.next:
    lodsb
    push cx
    push si
    call flight_parse_byte
    pop si
    pop cx
    jc .bad
    loop .next
    clc
    ret
.bad:
    stc
    ret

flight_parse_byte:
    cmp byte [cs:flight_expected], flight_expected_done
    jae .bad
    cmp byte [cs:flight_header_pos], 4
    je .body
    xor bx, bx
    mov bl, [cs:flight_header_pos]
    mov [cs:flight_msg_header + bx], al
    inc byte [cs:flight_header_pos]
    cmp byte [cs:flight_header_pos], 4
    jne .good
    call flight_begin_message
    jc .bad
    cmp word [cs:flight_msg_len], 0
    jne .good
    call flight_complete_message
    ret
.body:
    call flight_store_body_byte
    jc .bad
    inc word [cs:flight_msg_pos]
    mov ax, [cs:flight_msg_pos]
    cmp ax, [cs:flight_msg_len]
    jb .good
    jne .bad
    call flight_complete_message
    ret
.good:
    clc
    ret
.bad:
    stc
    ret

flight_begin_message:
    xor bx, bx
    mov bl, [cs:flight_expected]
    mov al, [cs:flight_expected_types + bx]
    cmp al, [cs:flight_msg_header]
    jne .bad
    cmp byte [cs:flight_msg_header + 1], 0
    jne .bad
    mov ax, [cs:flight_msg_header + 2]
    xchg al, ah
    mov [cs:flight_msg_len], ax
    mov word [cs:flight_msg_pos], 0
    cmp bl, flight_expected_ee
    je .small
    cmp bl, flight_expected_cv
    je .cv
    cmp bl, flight_expected_finished
    je .finished
    ; Certificate includes its four-byte handshake header in the exact pin.
    mov dx, ax
    add dx, 4
    jc .bad
    cmp dx, tls13_286_certificate_max
    ja .bad
    mov word [cs:flight_certificate_pos], 0
    mov si, flight_msg_header
    mov cx, 4
.certificate_header:
    lodsb
    push cx
    call flight_store_certificate_byte
    pop cx
    jc .bad
    loop .certificate_header
    clc
    ret
.small:
    cmp ax, flight_message_work_max - 4
    ja .bad
    jmp short .copy_header
.cv:
    cmp ax, 4 + tls13_286_cv_signature_max
    ja .bad
.copy_header:
    push ds
    pop es
    mov si, flight_msg_header
    mov di, flight_message_work
    mov cx, 4
    rep movsb
    clc
    ret
.finished:
    cmp ax, 32
    jne .bad
    ret
.bad:
    stc
    ret

flight_store_body_byte:
    cmp byte [cs:flight_expected], flight_expected_certificate
    je flight_store_certificate_byte
    cmp byte [cs:flight_expected], flight_expected_finished
    je .finished
    mov bx, [cs:flight_msg_pos]
    mov [flight_message_work + 4 + bx], al
    clc
    ret
.finished:
    mov bx, [cs:flight_msg_pos]
    mov [TLS13_286_FLIGHT_SYM_RECEIVED_SERVER_FINISHED + bx], al
    clc
    ret

flight_store_certificate_byte:
    push ax
    mov bx, [cs:flight_certificate_pos]
    cmp bx, tls13_286_certificate_max
    jae .bad_pop
    mov es, [cs:flight_crypto_seg]
    pop ax
    mov [es:tls13_286_certificate_off + bx], al
.stored:
    inc word [cs:flight_certificate_pos]
    xor ax, ax
    mov es, ax
    ret
.bad_pop:
    pop ax
.bad:
    xor ax, ax
    mov es, ax
    stc
    ret

flight_complete_message:
    mov byte [cs:flight_header_pos], 0
    cmp byte [cs:flight_expected], flight_expected_ee
    je .ee
    cmp byte [cs:flight_expected], flight_expected_certificate
    je .certificate
    cmp byte [cs:flight_expected], flight_expected_cv
    je .cv
    call TLS13_286_FLIGHT_SYM_VERIFY_SERVER_FINISHED
    jc .bad
    mov byte [cs:flight_expected], flight_expected_done
    ret
.ee:
    call flight_validate_ee
    jc .bad
    mov si, flight_message_work
    mov cx, [cs:flight_msg_len]
    add cx, 4
    call TLS13_286_FLIGHT_SYM_TRANSCRIPT_UPDATE
    jc .bad
    cmp byte [cs:flight_mode], flight_resumed_mode
    je .resume_finished
    inc byte [cs:flight_expected]
    clc
    ret
.resume_finished:
    mov byte [cs:flight_expected], flight_expected_finished
    ret
.certificate:
    call flight_validate_certificate
    jc .bad
    mov cx, [cs:flight_msg_len]
    add cx, 4
    cmp cx, [cs:flight_certificate_pos]
    jne .bad
    mov es, [cs:flight_crypto_seg]
    mov [es:tls13_286_certificate_len_off], cx
    xor ax, ax
    mov es, ax
    call flight_hash_certificate
    jc .bad
    inc byte [cs:flight_expected]
    ret
.cv:
    call flight_validate_cv
    jc .bad
    call flight_build_cv_digest
    jc .bad
    call flight_capture_cv_signature
    jc .bad
    mov si, flight_message_work
    mov cx, [cs:flight_msg_len]
    add cx, 4
    call TLS13_286_FLIGHT_SYM_TRANSCRIPT_UPDATE
    jc .bad
    inc byte [cs:flight_expected]
    ret
.bad:
    stc
    ret

flight_validate_ee:
    mov cx, [cs:flight_msg_len]
    cmp cx, 2
    jb .bad
    mov ax, [flight_message_work + 4]
    xchg al, ah
    mov dx, cx
    sub dx, 2
    cmp ax, dx
    jne .bad
    mov si, flight_message_work + 6
.extension:
    or dx, dx
    jz .good
    cmp dx, 4
    jb .bad
    mov ax, [si]
    cmp ax, 0x2a00                    ; early_data
    je .bad
    cmp ax, 0x2900                    ; pre_shared_key
    je .bad
    mov bx, [si + 2]
    xchg bl, bh
    add si, 4
    sub dx, 4
    cmp bx, dx
    ja .bad
    add si, bx
    sub dx, bx
    jmp short .extension
.good:
    ret
.bad:
    stc
    ret

flight_validate_certificate:
    cmp word [cs:flight_msg_len], 7
    jb .bad
    mov es, [cs:flight_crypto_seg]
    cmp byte [es:tls13_286_certificate_off + 4], 0
    jne .bad_es
    cmp byte [es:tls13_286_certificate_off + 5], 0
    jne .bad_es
    mov dx, [es:tls13_286_certificate_off + 6]
    ; CertificateList is a 24-bit vector and this profile is bounded to 4 KiB.
    xchg dl, dh
    mov ax, [cs:flight_msg_len]
    sub ax, 4
    cmp dx, ax
    jne .bad_es
    xor ax, ax
    mov es, ax
    ret
.bad_es:
    xor ax, ax
    mov es, ax
.bad:
    stc
    ret

flight_validate_cv:
    mov ax, [cs:flight_msg_len]
    cmp ax, 12
    jb .bad
    cmp word [flight_message_work + 4], 0x0304
    jne .bad
    mov dx, [flight_message_work + 6]
    xchg dl, dh
    cmp dx, 8
    jb .bad
    cmp dx, tls13_286_cv_signature_max
    ja .bad
    add dx, 4
    cmp dx, ax
    jne .bad
    ret
.bad:
    stc
    ret

flight_hash_certificate:
    mov word [cs:flight_certificate_hash_pos], 0
.next:
    mov ax, [cs:flight_certificate_hash_pos]
    cmp ax, [cs:flight_certificate_pos]
    jae .done
    mov cx, [cs:flight_certificate_pos]
    sub cx, ax
    cmp cx, flight_parse_chunk_max
    jbe .copy
    mov cx, flight_parse_chunk_max
.copy:
    mov [cs:flight_chunk_len], cx
    push ds
    mov ds, [cs:flight_crypto_seg]
    mov si, tls13_286_certificate_off
    add si, [cs:flight_certificate_hash_pos]
    xor ax, ax
    mov es, ax
    mov di, flight_message_work
    rep movsb
    pop ds
    mov es, ax
    mov si, flight_message_work
    mov cx, [cs:flight_chunk_len]
    call TLS13_286_FLIGHT_SYM_TRANSCRIPT_UPDATE
    jc .bad
    mov ax, [cs:flight_chunk_len]
    add [cs:flight_certificate_hash_pos], ax
    jmp short .next
.done:
    ret
.bad:
    stc
    ret

flight_build_cv_digest:
    call flight_save_sha
    mov di, flight_pre_cv_hash
    call TLS13_286_FLIGHT_SYM_SHA256_FINISH
    mov di, flight_cv_input
    mov al, 0x20
    mov cx, 64
    rep stosb
    mov si, flight_cv_context
    mov cx, flight_cv_context_len
    rep movsb
    xor al, al
    stosb
    mov si, flight_pre_cv_hash
    mov cx, 32
    rep movsb
    call TLS13_286_FLIGHT_SYM_SHA256_INIT
    mov si, flight_cv_input
    mov cx, 64 + flight_cv_context_len + 1 + 32
    call TLS13_286_FLIGHT_SYM_SHA256_UPDATE
    mov di, flight_cv_hash
    call TLS13_286_FLIGHT_SYM_SHA256_FINISH
    call flight_restore_sha
    push ds
    pop es
    mov es, [cs:flight_crypto_seg]
    mov si, flight_cv_hash
    mov di, tls13_286_cv_digest_off
    mov cx, 16
    rep movsw
    xor ax, ax
    mov es, ax
    ret

flight_save_sha:
    push ds
    pop es
    mov si, TLS13_286_FLIGHT_SYM_SHA256_STATE
    mov di, flight_saved_sha
    mov cx, 16
    rep movsw
    mov si, TLS13_286_FLIGHT_SYM_SHA256_BLOCK
    mov cx, 32
    rep movsw
    mov ax, [TLS13_286_FLIGHT_SYM_SHA256_LEN_LOW]
    stosw
    mov ax, [TLS13_286_FLIGHT_SYM_SHA256_LEN_HIGH]
    stosw
    mov al, [TLS13_286_FLIGHT_SYM_SHA256_BLOCK_LEN]
    stosb
    ret

flight_restore_sha:
    push ds
    pop es
    mov si, flight_saved_sha
    mov di, TLS13_286_FLIGHT_SYM_SHA256_STATE
    mov cx, 16
    rep movsw
    mov di, TLS13_286_FLIGHT_SYM_SHA256_BLOCK
    mov cx, 32
    rep movsw
    lodsw
    mov [TLS13_286_FLIGHT_SYM_SHA256_LEN_LOW], ax
    lodsw
    mov [TLS13_286_FLIGHT_SYM_SHA256_LEN_HIGH], ax
    lodsb
    mov [TLS13_286_FLIGHT_SYM_SHA256_BLOCK_LEN], al
    ret

flight_capture_cv_signature:
    mov cx, [cs:flight_msg_len]
    sub cx, 4
    mov ax, cx
    mov es, [cs:flight_crypto_seg]
    mov byte [es:tls13_286_capture_status_off], 0
    mov si, flight_message_work + 8
    mov di, tls13_286_cv_signature_off
    rep movsb
    mov [es:tls13_286_cv_signature_len_off], ax
    xor ax, ax
    mov es, ax
    ret

; Freeze the first fully parsed authenticated ticket into the persistent high
; reservation.  Every byte is copied before the inverse/status pair is
; published; the offline authenticator accepts only this tentative state.
flight_export_tentative_ticket:
    mov cx, [TLS13_286_FLIGHT_SYM_TICKET_IDENTITY_LEN]
    dec cx
    cmp cx, tls13_286_ticket_identity_max - 1
    ja .invalid
    mov dx, [TLS13_286_FLIGHT_SYM_TICKET_NONCE_LEN]
    dec dx
    cmp dx, tls13_286_ticket_nonce_max - 1
    jbe .copy
.invalid:
    stc
    ret

.copy:
    mov es, [cs:flight_crypto_seg]
    xor ax, ax
    mov di, tls13_286_resumption_master_off
    mov cx, (tls13_286_ticket_nonce_off + tls13_286_ticket_nonce_max - \
        tls13_286_resumption_master_off) / 2
    rep stosw
    mov di, tls13_286_ticket_meta_off
    mov cx, (tls13_286_ticket_meta_end - tls13_286_ticket_meta_off) / 2
    rep stosw

    mov si, TLS13_286_FLIGHT_SYM_TICKET_PSK
    mov di, tls13_286_ticket_psk_off
    mov cx, tls13_286_ticket_psk_bytes / 2
    rep movsw
    mov si, TLS13_286_FLIGHT_SYM_TICKET_IDENTITY
    mov di, tls13_286_ticket_identity_off
    mov cx, [TLS13_286_FLIGHT_SYM_TICKET_IDENTITY_LEN]
    rep movsb
    mov si, TLS13_286_FLIGHT_SYM_TICKET_NONCE
    mov di, tls13_286_ticket_nonce_off
    mov cx, [TLS13_286_FLIGHT_SYM_TICKET_NONCE_LEN]
    rep movsb
    mov si, TLS13_286_FLIGHT_SYM_TICKET_LIFETIME_HI
    mov di, tls13_286_ticket_lifetime_hi_off
    mov cx, 6
    rep movsw

    ; BIOS time-of-day ticks are same-boot age input only, not trusted wall
    ; time.  Store low/high words in their named order.
    xor ax, ax
    int 0x1a
    mov es, [cs:flight_crypto_seg]
    mov [es:tls13_286_ticket_receipt_tick_lo_off], dx
    mov [es:tls13_286_ticket_receipt_tick_hi_off], cx
    mov byte [es:tls13_286_ticket_status_inv_off], \
        tls13_286_ticket_status_tentative_inv
    mov byte [es:tls13_286_ticket_status_off], \
        tls13_286_ticket_status_tentative
    xor ax, ax
    mov es, ax
    ret

flight_publish_capture:
    mov es, [cs:flight_crypto_seg]
    ; Reaching this edge already requires the exact Certificate/CV/Finished
    ; state-machine sequence and a fully exported authenticated ticket.
    mov byte [es:tls13_286_capture_status_inv_off], \
        tls13_286_flight_status_inverse
    mov byte [es:tls13_286_capture_status_off], \
        tls13_286_flight_status_valid
    xor ax, ax
    mov es, ax
    ret

flight_publish_application:
    mov byte [TLS13_286_LINK_APP_READY], 0
    push ds
    pop es
    mov si, TLS13_286_FLIGHT_SYM_CLIENT_APP_KEY
    mov di, TLS13_286_LINK_APP_CLIENT_KEY
    mov cx, 16
    rep movsw
    mov si, TLS13_286_FLIGHT_SYM_SERVER_APP_KEY
    mov di, TLS13_286_LINK_APP_SERVER_KEY
    mov cx, 16
    rep movsw
    mov si, TLS13_286_FLIGHT_SYM_CLIENT_APP_IV
    mov di, TLS13_286_LINK_APP_CLIENT_IV
    mov cx, 6
    rep movsw
    mov si, TLS13_286_FLIGHT_SYM_SERVER_APP_IV
    mov di, TLS13_286_LINK_APP_SERVER_IV
    mov cx, 6
    rep movsw
    mov si, TLS13_286_FLIGHT_SYM_CLIENT_APP_SEQ
    mov di, TLS13_286_LINK_APP_CLIENT_SEQ
    mov cx, 8
    rep movsw
    ; Acquisition parses protected Certificate/application records through
    ; the resident low-tail TLS cursor block.  That block is deliberately
    ; outside the authenticated low-state escrow and therefore survives into
    ; the independent resumption connection.  Retire its prior-connection
    ; values before publishing the new application epoch; otherwise the
    ; resident opener can mistake stale acquisition bytes for buffered input
    ; and skip the first real TCP receive.
    mov di, TLS13_286_LINK_TLS_BUFFERED_PAYLOAD_PTR
    xor ax, ax
    mov cx, (TLS13_286_LINK_TLS_CURRENT_PAYLOAD_LEN + 2 - \
        TLS13_286_LINK_TLS_BUFFERED_PAYLOAD_PTR) / 2
    rep stosw
    mov byte [TLS13_286_LINK_APP_READY], 1
    ret

flight_close_socket:
    mov ax, TLS13_286_LINK_TCP_CLOSE_PHASE_KEY
    mov bx, TLS13_286_LINK_TCP_CLOSE_DESTINATION
    call TLS13_286_LINK_LOAD_CORE_SECTORS_AT
    jc .done
    jmp TLS13_286_LINK_TCP_CLOSE_ENTRY
.done:
    ret

flight_retire_symmetric:
    xor ax, ax
    mov es, ax
    mov di, TLS13_286_FLIGHT_SYM_IMAGE_START
    mov cx, (TLS13_286_FLIGHT_SYM_IMAGE_END - \
        TLS13_286_FLIGHT_SYM_IMAGE_START) / 2
    rep stosw
    mov di, TLS13_286_FLIGHT_SYM_INPUT_SHARED_SECRET
    mov cx, (TLS13_286_FLIGHT_SYM_HIGH_STATE_END - \
        TLS13_286_FLIGHT_SYM_INPUT_SHARED_SECRET + 1) / 2
    rep stosw
    ret

flight_abort:
    cld
    call word [cs:TLS13_286_LINK_NIC_RESTORE_SLOT]
    jmp word [cs:tls13_286_abort_capsule_load + \
        tls13_286_abort_capsule_entry_ptr]

flight_expected_types:
    db 8, 11, 15, 20
flight_compat_ccs_tail:
    db 0x03, 0x03, 0x00, 0x01, 0x01
flight_cv_context:
    db 'TLS 1.3, server CertificateVerify'
flight_cv_context_len equ $ - flight_cv_context
flight_http_prefix:
    db 'HTTP/1.1 '

flight_image_end:

; Mutable coordinator state.  The decoded image is bounded below this fixed
; range; neither authentication module reaches 0x6300.
flight_state_start             equ 0x7200
flight_crypto_seg              equ flight_state_start
flight_record_seg              equ flight_crypto_seg + 2
flight_mode                    equ flight_record_seg + 2
flight_expected                equ flight_mode + 1
flight_header_pos              equ flight_expected + 1
flight_msg_header              equ flight_header_pos + 1
flight_msg_len                 equ flight_msg_header + 4
flight_msg_pos                 equ flight_msg_len + 2
flight_certificate_pos         equ flight_msg_pos + 2
flight_certificate_hash_pos    equ flight_msg_pos
flight_wire_ptr                equ flight_certificate_pos + 2
flight_wire_left               equ flight_wire_ptr + 2
flight_pending_len             equ flight_wire_left + 2
flight_record_plain            equ flight_pending_len + 2
flight_record_content          equ flight_record_plain + 2
flight_record_pos              equ flight_record_content + 2
flight_chunk_ptr               equ flight_record_pos + 2
flight_chunk_len               equ flight_chunk_ptr + 2
flight_epoch                   equ flight_chunk_len + 2
flight_inner_type              equ flight_epoch + 1
flight_http_total              equ flight_inner_type + 1
flight_http_match              equ flight_http_total + 2
flight_http_425                equ flight_http_match + 1
flight_http_done               equ flight_http_425 + 1
flight_ticket_seen             equ flight_http_done + 1
flight_nst_pos                 equ flight_ticket_seen + 1
flight_nst_total               equ flight_nst_pos + 2
flight_http_status_valid       equ flight_nst_total + 2
flight_saved_sha               equ flight_http_status_valid + 1
flight_saved_sha_bytes         equ 32 + 64 + 2 + 2 + 1
flight_pre_cv_hash             equ flight_saved_sha + flight_saved_sha_bytes
flight_cv_hash                 equ flight_pre_cv_hash + 32
flight_cv_input                equ flight_cv_hash + 32
flight_cv_input_bytes          equ 64 + flight_cv_context_len + 1 + 32
flight_state_end               equ flight_cv_input + flight_cv_input_bytes

%if (flight_image_end - $$ + tls13_286_flight_load) > flight_state_start
%error "TLS 1.3 286 flight image overlaps mutable coordinator state"
%endif
%if flight_state_end > tls13_286_flight_limit
%error "TLS 1.3 286 flight coordinator exceeds its safe window"
%endif
%if TLS13_286_FLIGHT_SYM_HIGH_STATE_END > 0x7a00
%error "TLS 1.3 286 symmetric state crosses the stack guard"
%endif
%if flight_record_plain_max != tls13_286_record_plain_bytes
%error "TLS 1.3 286 record quarantine lost its full protocol bound"
%endif
%if (flight_record_plain_max & 1) != 0
%error "TLS 1.3 286 record scratch wipe requires an even byte count"
%endif
%if (TLS13_286_FLIGHT_SYM_IMAGE_START & 0xff) != 0
%error "TLS 1.3 286 compact relocation requires a page-aligned sym image"
%endif
