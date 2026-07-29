; Seed TLS 1.3 resumed symmetric I/O worker.
;
; This one immutable phase is loaded and tail-entered at 0x0d00 only after
; sym_import has consumed the resumed transcript handoff:
;
;   AX=4  accepted branch only: validate the authenticated disposition and
;         preload this worker before EndOfEarlyData
;   AX=5  send exactly the 58-byte client Finished record at sym_io, then
;         either finish the accepted-0-RTT write schedule or immediately
;         build/send the compatibility 1-RTT HEAD
;   AX=6  build/send only that fixed HEAD (retained compatibility entry)
;   AX=7  accepted 0-RTT only: recover/send the offline-sealed 26-byte
;         EndOfEarlyData record and include its plaintext in client Finished
;
; No pointer, length, credential, media handle, or destination crosses the
; dispatcher ABI.  Success is AX=1/CF=0; failure is AX=0/CF=1.  DS=SS=0 is
; required.  ES is normalized to DS for fixed services, preserved for the
; caller, and DF is clear on every return.

bits 16
cpu 8086

%ifndef RESUME_SYM_IO_ORIGIN
%define RESUME_SYM_IO_ORIGIN 0x0d00
%endif
%ifndef RESUME_SYM_IO_TCP_SEND
%error "resumed symmetric I/O worker requires resident TCP send"
%endif
%ifndef RESUME_SYM_IO_WAIT_TICKS
%error "resumed symmetric I/O worker requires resident wait_ticks"
%endif
%ifndef RESUME_SYM_IO_BUILD_HEAD
%error "resumed symmetric I/O worker requires fixed symmetric HEAD builder"
%endif
%ifndef RESUME_SYM_IO_ZERO_WINDOW
%error "resumed symmetric I/O worker requires persistent zero-window service"
%endif
%ifdef RESUME_SYM_IO_EARLY_DATA
%ifndef RESUME_SYM_IO_NE_BUF_READ
%error "early-data RSI1 requires the guarded NE2000 read leaf"
%endif
%ifndef RESUME_SYM_IO_SHA256_UPDATE
%error "early-data RSI1 requires the resident SHA-256 update leaf"
%endif
%ifndef RESUME_SYM_IO_TRANSCRIPT_SNAPSHOT
%error "early-data RSI1 requires the symmetric transcript snapshot leaf"
%endif
%endif

%macro RESUME_SYM_IO_MARK 1
%ifdef RESUME_SYM_IO_DIAGNOSTIC
    mov al, %1
    mov dx, 0x03f8
    out dx, al
%endif
%endmacro

org RESUME_SYM_IO_ORIGIN

resume_sym_io_entry:
    jmp short resume_sym_io_code

resume_sym_io_header:
    db 'RSI1'
    dw 1
    dw resume_sym_io_end - $$
    dw RESUME_SYM_IO_ORIGIN
    dw resume_sym_io_entry

sym_io                     equ 0x39a0
sym_input_hello_hash       equ 0x3640
sym_server_finished_hash   equ 0x3680
sym_client_finished_state  equ 0x3c2d
early_disposition          equ 0x3c5c
rejected_finished_sent     equ 0x82
early_eoed_card            equ 0x7d40
early_eoed_bytes           equ 26
%ifdef RESUME_SYM_IO_EARLY_DATA
resumed_protected_bytes    equ 68
%else
resumed_protected_bytes    equ 64
%endif
client_finished_bytes      equ 58
head_record_bytes          equ 72

resume_sym_io_code:
    cld
    push es
    push ds
    pop es
    cmp ax, 4
    je resume_sym_io_receive
    cmp ax, 5
    je resume_sym_io_send_finished
    cmp ax, 6
    je resume_sym_io_send_head
%ifdef RESUME_SYM_IO_EARLY_DATA
    cmp ax, 7
    je resume_sym_io_send_eoed
%endif
    jmp resume_sym_io_failed

resume_sym_io_receive:
%ifdef RESUME_SYM_IO_EARLY_DATA
    ; The symmetric overlay has already authenticated the record, and RSU1
    ; has already checked exact accepted plaintext plus server Finished.
    ; Operation 4 exists only to cold-load RSI1 before direct operation 7.
    cmp byte [early_disposition], 1
    jne resume_sym_io_failed
    cmp byte [sym_client_finished_state], 0
    jne resume_sym_io_failed
    jmp resume_sym_io_succeeded
%else
    ; EXCHANGE ACKs and normalizes the complete flight before starting ML-KEM
    ; candidate work, then copies the protected record into symmetric state
    ; before restoring RSU1.  No later network retransmission is required.
    cmp byte [sym_io], 0x17
    jne resume_sym_io_failed
    cmp word [sym_io + 1], 0x0303
    jne resume_sym_io_failed
    cmp word [sym_io + 3], 0x3b00
    jne resume_sym_io_failed
    jmp resume_sym_io_succeeded
%endif

%ifdef RESUME_SYM_IO_EARLY_DATA
resume_sym_io_send_eoed:
    cmp byte [sym_client_finished_state], 0
    jne resume_sym_io_failed
    mov bx, early_eoed_card
    mov cx, early_eoed_bytes
    mov di, sym_io
    call RESUME_SYM_IO_NE_BUF_READ
    jc resume_sym_io_failed
    cmp byte [sym_io], 0x17
    jne resume_sym_io_failed
    cmp word [sym_io + 1], 0x0303
    jne resume_sym_io_failed
    cmp word [sym_io + 3], 0x1500
    jne resume_sym_io_failed

    ; Application traffic secrets use the server-Finished-only transcript,
    ; while client Finished authenticates EndOfEarlyData as well.  Preserve
    ; the former in the now-retired ClientHello-hash slot, then snapshot the
    ; live transcript through plaintext EOED into the ordinary Finished slot.
    cld
    push ds
    pop es
    mov si, sym_server_finished_hash
    mov di, sym_input_hello_hash
    mov cx, 16
    rep movsw
    mov si, resume_sym_io_eoed_plaintext
    mov cx, 4
    call RESUME_SYM_IO_SHA256_UPDATE
    mov di, sym_server_finished_hash
    call RESUME_SYM_IO_TRANSCRIPT_SNAPSHOT

    mov si, sym_io
    mov cx, early_eoed_bytes
    call RESUME_SYM_IO_TCP_SEND
    jc resume_sym_io_failed
    RESUME_SYM_IO_MARK 'O'
    jmp resume_sym_io_succeeded
%endif

resume_sym_io_send_finished:
%ifdef RESUME_SYM_IO_EARLY_DATA
    cmp byte [early_disposition], rejected_finished_sent
    je .finished_sent
    cmp byte [early_disposition], 1
    jne resume_sym_io_failed
%endif
    mov si, sym_io
    mov cx, client_finished_bytes
    call RESUME_SYM_IO_TCP_SEND
    jc resume_sym_io_failed
    RESUME_SYM_IO_MARK 'A'
.finished_sent:
    ; The secure 16 KiB profile is NE2000-only, and its synchronous DP8390
    ; transmit path has already completed before returning.  Normalize the
    ; string ABI and build HEAD immediately; a full BIOS tick here consumed
    ; deadline without adding a delivery guarantee.
    cld
    push ds
    pop es
%ifdef RESUME_SYM_IO_DERIVE_CLIENT_APP
%ifdef RESUME_SYM_IO_EARLY_DATA
    ; The controller parks the server-Finished-only digest here on both the
    ; accepted and rejected early-data branches.
    mov si, sym_input_hello_hash
    mov di, sym_server_finished_hash
    mov cx, 16
    rep movsw
%endif
    call RESUME_SYM_IO_DERIVE_CLIENT_APP
    jc resume_sym_io_failed
    cld
    push ds
    pop es
%endif
%ifdef RESUME_SYM_IO_EARLY_DATA
    ; RX already closed the receive window before expensive crypto.  Refresh
    ; that advertisement only after client application keys are ready; the
    ; fixed HEAD was sent under the early epoch before ServerHello.
    call RESUME_SYM_IO_ZERO_WINDOW
    jc resume_sym_io_failed
    cmp byte [early_disposition], rejected_finished_sent
    jne .disposition_ready
    mov byte [early_disposition], 2
.disposition_ready:
    RESUME_SYM_IO_MARK 'D'
    jmp short resume_sym_io_succeeded
%endif
    ; Fall through without returning to the dispatcher.  The controller has
    ; either already derived the application write key (compatibility build)
    ; or requested the live post-Finished derivation above.  sym_io remains
    ; intact across the fixed TCP send in both cases.

resume_sym_io_send_head:
    call RESUME_SYM_IO_BUILD_HEAD
    jc resume_sym_io_failed
    cmp ax, head_record_bytes
    jne resume_sym_io_failed
    RESUME_SYM_IO_MARK 'B'
    mov si, sym_io
    mov cx, head_record_bytes
    call RESUME_SYM_IO_TCP_SEND
    jc resume_sym_io_failed
    RESUME_SYM_IO_MARK 'C'
    mov cx, 1
    call RESUME_SYM_IO_WAIT_TICKS
    ; Product wait_ticks has no flags contract.  Its incidental carry is
    ; deliberately ignored; the following fixed zero-window service is
    ; fallible and supplies the only post-wait authority boundary.
    call RESUME_SYM_IO_ZERO_WINDOW
    jc resume_sym_io_failed
    RESUME_SYM_IO_MARK 'D'

resume_sym_io_succeeded:
    cld
    mov ax, 1
    clc
    pop es
    ret

resume_sym_io_failed:
    cld
    xor ax, ax
    stc
    pop es
    ret

%ifdef RESUME_SYM_IO_EARLY_DATA
resume_sym_io_eoed_plaintext:
    db 0x05,0x00,0x00,0x00
%endif

resume_sym_io_end:

%if (resume_sym_io_header - resume_sym_io_entry) != 2
%error "resumed symmetric I/O worker header moved from file offset 2"
%endif
%if ($ - $$) > 0x0200
%error "resumed symmetric I/O worker exceeds retired transcript page"
%endif
