; Exact 6 MHz / 512 KiB timing gate for the shipped 286 in-window HELLO CPU.
;
; HELLOACQ and HELLORES start immediately after the resident TCP connect entry
; has returned.  They execute the current S286HL02 ClientHello fragment builder,
; public-key staging, transcript hashing, six send callbacks, hostile split
; five-byte record-header receive wrapper, server begin/feed/finish parser, ACK
; path, and status-last protected-suffix publication.  Callbacks remove only
; NIC wait/transmit/receive latency; the send callback conservatively compares
; every emitted byte with the exact current ClientHello fixture.

bits 16
cpu 8086
org 0x1000

%include "tls13/tls13_286_abi.inc"
%include "build/ibm_pc_5150/tls13-286-runtime-abi.inc"
%include "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/fixture_meta.inc"

crypto_segment equ 0x7000
stack_top equ 0x7a00
run_acquisition equ 0
run_resumed equ 1

core_header:
    jmp bench_main
    nop
    db 'SEEDCORE'
    db 1
    db 0
    dw core_header_end - core_header
    dw (image_end - core_header + 511) / 512
    dw (image_end - core_header + 511) / 512
    dw 0
    dw 0
core_header_end:

times (tls13_286_controller_load - 0x1000) - ($ - $$) db 0
incbin "build/ibm_pc_5150/tls13-286-hello.bin"

; S286HL02 and its SHA work end below 0x4000.  The timed send path uses 0x4230
; for exact public fragment staging, so keep the harness above that workspace.
times (0x5000 - 0x1000) - ($ - $$) db 0

bench_main:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, stack_top
    sti
    cld
    mov ax, 0x0003
%ifndef HELLO_TIMING_SEMANTIC
    int 0x10
%endif
    call serial_init
    call install_callbacks

    mov byte [run_mode], run_acquisition
    call run_hello
    jc bench_fail
    mov [acquisition_ticks], ax

    mov byte [run_mode], run_resumed
    call run_hello
    jc bench_fail
    mov [resumed_ticks], ax

    mov si, tag_acquisition
    mov ax, [acquisition_ticks]
    call emit_metric
    mov si, tag_resumed
    mov ax, [resumed_ticks]
    call emit_metric
    mov si, tag_check
    mov ax, 1
    call emit_check
    mov si, tag_done
    call emit_str
    call emit_crlf
    mov byte [semantic_result], 1
.hang:
    hlt
    jmp .hang

run_hello:
    call initialize_case
    jc .bad
    call tick_start
    call flight_timing_hello_live_send_client
    jc .bad
    call flight_timing_hello_live_receive_server
    jc .bad
    call tick_stop
    push ax
    call validate_case
    pop ax
    ret
.bad:
    stc
    ret

install_callbacks:
    mov di, TLS13_286_LINK_TCP_SEND
    mov ax, callback_send
    call patch_jump
    mov di, TLS13_286_LINK_TCP_RECEIVE
    mov ax, callback_receive
    call patch_jump
    mov di, TLS13_286_LINK_TCP_ACK
    mov ax, callback_ack
    call patch_jump
    ret

; DI=patched resident address, AX=near callback.
patch_jump:
    mov byte [di], 0xe9
    sub ax, di
    sub ax, 3
    mov [di + 1], ax
    ret

initialize_case:
    call flight_timing_hello_clear_work
    xor ax, ax
    mov es, ax
    mov word [send_calls], 0
    mov word [send_bytes], 0
    mov word [receive_calls], 0
    mov word [receive_bytes], 0
    mov word [receive_offset], 0
    mov word [ack_calls], 0
    mov byte [callback_failed], 0

    mov ax, crypto_segment
    mov es, ax
    xor ax, ax
    mov di, tls13_286_pending_wire_off
    mov cx, (tls13_286_pending_wire_status_off + 1 - \
        tls13_286_pending_wire_off) / 2
    rep stosw
    xor ax, ax
    mov es, ax

    cmp byte [run_mode], run_resumed
    je .resumed
.acquisition:
    mov byte [flight_timing_hello_mode], \
        flight_timing_hello_mode_acquire
    mov word [flight_timing_hello_wire_message_len], \
        flight_timing_hello_message_len
    mov word [flight_timing_hello_wire_extensions_len], \
        flight_timing_hello_extensions_len
    mov word [flight_timing_hello_wire_tail_len], \
        flight_timing_hello_tail_len
    mov word [flight_timing_hello_ticket_len_snapshot], 0
    mov si, acquisition_ek
    mov di, tls13_286_mlkem_dk_ek_off
    mov cx, flight_timing_hello_ek_bytes
    call copy_high
    mov si, acquisition_random
    mov di, flight_timing_hello_random
    mov cx, flight_timing_hello_random_bytes
    rep movsb
    mov si, acquisition_session
    mov di, flight_timing_hello_session
    mov cx, flight_timing_hello_session_bytes
    rep movsb
    mov si, acquisition_x
    mov di, flight_timing_hello_client_x
    mov cx, flight_timing_hello_client_x_bytes
    rep movsb
    mov word [send_expected], acquisition_client_record
    mov word [send_remaining], \
        flight_timing_hello_acquisition_client_record_bytes
    mov word [send_expected_bytes], \
        flight_timing_hello_acquisition_client_record_bytes
    mov word [receive_source], acquisition_server_wire
    mov word [receive_expected_bytes], \
        flight_timing_hello_acquisition_server_wire_bytes
    mov word [receive_tail_bytes], \
        flight_timing_hello_acquisition_server_tail_bytes
    mov word [expected_digest], acquisition_digest
    jmp .common
.resumed:
    mov byte [flight_timing_hello_mode], flight_timing_hello_mode_resume
    mov ax, flight_timing_hello_message_len + \
        flight_timing_ticket_identity_bytes + \
        flight_timing_hello_resumption_delta
    mov [flight_timing_hello_wire_message_len], ax
    mov ax, flight_timing_hello_extensions_len + \
        flight_timing_ticket_identity_bytes + \
        flight_timing_hello_resumption_delta
    mov [flight_timing_hello_wire_extensions_len], ax
    mov ax, flight_timing_hello_tail_len + \
        flight_timing_ticket_identity_bytes + \
        flight_timing_hello_resumption_delta
    mov [flight_timing_hello_wire_tail_len], ax
    mov word [flight_timing_hello_ticket_len_snapshot], \
        flight_timing_ticket_identity_bytes
    mov si, resumed_ek
    mov di, tls13_286_mlkem_dk_ek_off
    mov cx, flight_timing_hello_ek_bytes
    call copy_high
    mov si, ticket_identity_fixture
    mov di, tls13_286_ticket_identity_off
    mov cx, flight_timing_ticket_identity_bytes
    call copy_high
    mov si, resumed_binder
    mov di, tls13_286_ticket_binder_off
    mov cx, tls13_286_ticket_binder_bytes
    call copy_high
    mov si, resumed_age
    mov di, flight_timing_hello_ticket_age
    mov cx, 4
    rep movsb
    mov si, resumed_random
    mov di, flight_timing_hello_random
    mov cx, flight_timing_hello_random_bytes
    rep movsb
    mov si, resumed_session
    mov di, flight_timing_hello_session
    mov cx, flight_timing_hello_session_bytes
    rep movsb
    mov si, resumed_x
    mov di, flight_timing_hello_client_x
    mov cx, flight_timing_hello_client_x_bytes
    rep movsb
    mov word [send_expected], resumed_client_record
    mov word [send_remaining], \
        flight_timing_hello_resumed_client_record_bytes
    mov word [send_expected_bytes], \
        flight_timing_hello_resumed_client_record_bytes
    mov word [receive_source], resumed_server_wire
    mov word [receive_expected_bytes], \
        flight_timing_hello_resumed_server_wire_bytes
    mov word [receive_tail_bytes], \
        flight_timing_hello_resumed_server_tail_bytes
    mov word [expected_digest], resumed_digest
.common:
    mov word [flight_timing_hello_crypto_seg], crypto_segment
    call flight_timing_hello_sha256_init
    mov byte [flight_timing_hello_phase], flight_timing_hello_phase_tx
    mov byte [flight_timing_hello_segment], 0
    mov byte [flight_timing_hello_pending], 0
    mov byte [flight_timing_hello_hash_enabled], 1
    mov byte [tls13_286_hello_status_off], 0
    clc
    ret

copy_high:
    push es
    mov ax, crypto_segment
    mov es, ax
    rep movsb
    pop es
    ret

; Validate the exact generated bytes, six-callback geometry, final transcript,
; extracted server X share, and status-last quarantined protected suffix.
validate_case:
    cmp byte [callback_failed], 0
    jne .bad
    cmp word [send_calls], 6
    jne .bad
    cmp word [send_remaining], 0
    jne .bad
    mov ax, [send_expected_bytes]
    cmp [send_bytes], ax
    jne .bad
    cmp word [receive_calls], flight_timing_hello_server_segment_count
    jne .bad
    cmp word [ack_calls], flight_timing_hello_server_segment_count
    jne .bad
    mov ax, [receive_expected_bytes]
    cmp [receive_offset], ax
    jne .bad
    cmp [receive_bytes], ax
    jne .bad
    cmp byte [tls13_286_hello_status_off], 1
    jne .bad
    mov si, tls13_286_hello_digest_off
    mov di, [expected_digest]
    mov cx, 32
    repe cmpsb
    jne .bad
    mov si, tls13_286_hello_server_x_off
    mov di, server_x
    mov cx, 32
    repe cmpsb
    jne .bad
    mov ax, crypto_segment
    mov es, ax
    cmp word [es:tls13_286_pending_wire_len_off], \
        flight_timing_hello_pending_suffix_bytes
    jne .bad_es
    cmp word [es:tls13_286_pending_wire_status_inv_off], 0xa55a
    jne .bad_es
    mov si, pending_suffix
    mov di, tls13_286_pending_wire_off
    mov cx, flight_timing_hello_pending_suffix_bytes
    repe cmpsb
    jne .bad_es
    xor ax, ax
    mov es, ax
    clc
    ret
.bad_es:
    xor ax, ax
    mov es, ax
.bad:
    stc
    ret

; Exact send stub: remove physical transmit latency while conservatively
; comparing every current product fragment inside the timed wrapper.
callback_send:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    inc word [send_calls]
    mov dx, cx
    add [send_bytes], cx
    cmp cx, [send_remaining]
    ja .bad
    push ds
    pop es
    mov di, [send_expected]
    repe cmpsb
    jne .bad
    add [send_expected], dx
    sub [send_remaining], dx
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    clc
    ret
.bad:
    mov byte [callback_failed], 1
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    stc
    ret

; Exact receive stub: publish the same six hostile segments as the current
; semantic product gate.  The shipped wrapper performs every header/body/
; pending-suffix operation after this latency-free publication.
callback_receive:
    push ax
    push bx
    push cx
    push dx
    push si
    mov bx, [receive_calls]
    cmp bx, flight_timing_hello_server_segment_count
    jae .bad
    shl bx, 1
    mov cx, [server_segment_lengths + bx]
    cmp bx, 10
    jne .length_ready
    mov cx, [receive_tail_bytes]
.length_ready:
    mov si, [receive_source]
    add si, [receive_offset]
    mov [TLS13_286_LINK_TCP_RX_PAYLOAD_PTR], si
    mov [TLS13_286_LINK_TCP_RX_PAYLOAD_LEN], cx
    add [receive_offset], cx
    add [receive_bytes], cx
    inc word [receive_calls]
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    clc
    ret
.bad:
    mov byte [callback_failed], 1
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    stc
    ret

callback_ack:
    inc word [ack_calls]
    clc
    ret

bench_fail:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, stack_top
    sti
    cld
    mov si, tag_fail
    call emit_str
    call emit_crlf
    mov si, tag_done
    call emit_str
    call emit_crlf
    jmp bench_main.hang

tick_start:
%ifdef HELLO_TIMING_SEMANTIC
    ret
%else
    call read_tick_low
    mov bx, ax
.edge:
    call read_tick_low
    cmp ax, bx
    je .edge
    call read_tick
    mov [tick_lo], ax
    mov [tick_hi], dx
    ret
%endif

tick_stop:
%ifdef HELLO_TIMING_SEMANTIC
    xor ax, ax
    ret
%else
    call read_tick
    sub ax, [tick_lo]
    sbb dx, [tick_hi]
    ret
%endif

read_tick:
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret

read_tick_low:
    mov ax, [0x046c]
    ret

serial_init:
%ifdef HELLO_TIMING_SEMANTIC
    ret
%else
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 0x0c
    out dx, al
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 0x03
    out dx, al
    ret
%endif

emit_char:
%ifdef HELLO_TIMING_SEMANTIC
    ret
%else
    push ax
    push bx
    push cx
    push dx
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    mov ah, al
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, 0x3f8
    mov al, ah
    out dx, al
    pop dx
    pop cx
    pop bx
    pop ax
    ret
%endif

emit_str:
    push ax
    push si
.next:
    lodsb
    or al, al
    jz .done
    call emit_char
    jmp short .next
.done:
    pop si
    pop ax
    ret

emit_crlf:
    push ax
    mov al, 13
    call emit_char
    mov al, 10
    call emit_char
    pop ax
    ret

emit_metric:
    push ax
    call emit_str
    mov si, str_n
    call emit_str
    mov ax, 1
    call emit_dec16
    mov si, str_dt
    call emit_str
    pop ax
    call emit_dec16
    mov si, str_ck
    call emit_str
    mov ax, 1
    call emit_hex16
    call emit_crlf
    ret

emit_check:
    push ax
    call emit_str
    mov si, str_check
    call emit_str
    pop ax
    call emit_hex16
    call emit_crlf
    ret

emit_dec16:
    push ax
    push bx
    push cx
    push dx
    xor cx, cx
    mov bx, 10
.divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .divide
.digit:
    pop ax
    add al, '0'
    call emit_char
    loop .digit
    pop dx
    pop cx
    pop bx
    pop ax
    ret

emit_hex16:
    push ax
    push cx
    push dx
    mov dx, ax
    mov cx, 4
.digit:
    rol dx, 1
    rol dx, 1
    rol dx, 1
    rol dx, 1
    mov al, dl
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .emit
    add al, 7
.emit:
    call emit_char
    loop .digit
    pop dx
    pop cx
    pop ax
    ret

tick_lo dw 0
tick_hi dw 0
acquisition_ticks dw 0
resumed_ticks dw 0
send_expected dw 0
send_remaining dw 0
send_expected_bytes dw 0
send_calls dw 0
send_bytes dw 0
receive_source dw 0
receive_expected_bytes dw 0
receive_tail_bytes dw 0
receive_offset dw 0
receive_calls dw 0
receive_bytes dw 0
ack_calls dw 0
expected_digest dw 0
run_mode db 0
callback_failed db 0
semantic_magic db 'H286SEM1'
semantic_result db 0
server_segment_lengths dw 1, 2, 380, 384, 384, 0
tag_acquisition db 'HELLOACQ', 0
tag_resumed db 'HELLORES', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_n db ' N=', 0
str_dt db ' dt=', 0
str_ck db ' ck=', 0
str_check db ' N=1 dt=0 ck=', 0

%if ($ - $$ + 0x1000) > 0x7000
%error "HELLO timing harness escaped retired module gap"
%endif

times (0x8000 - 0x1000) - ($ - $$) db 0
acquisition_client_record:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-acquisition-client-record.bin"
acquisition_server_wire:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-acquisition-server-wire.bin"
acquisition_digest:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-acquisition-digest.bin"
acquisition_ek:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-acquisition-ek.bin"
acquisition_random:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-acquisition-random.bin"
acquisition_session:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-acquisition-session.bin"
acquisition_x:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-acquisition-x.bin"
resumed_client_record:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-resumed-client-record.bin"
resumed_server_wire:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-resumed-server-wire.bin"
resumed_digest:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-resumed-digest.bin"
resumed_ek:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-resumed-ek.bin"
resumed_random:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-resumed-random.bin"
resumed_session:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-resumed-session.bin"
resumed_x:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-resumed-x.bin"
resumed_binder:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-resumed-binder.bin"
resumed_age:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-resumed-age.bin"
ticket_identity_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/ticket-identity.bin"
pending_suffix:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-pending-suffix.bin"
server_x:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hello-server-x.bin"
image_end:

%if image_end - $$ + 0x1000 > 0xf000
%error "HELLO timing fixtures collide with temporary high stack"
%endif
