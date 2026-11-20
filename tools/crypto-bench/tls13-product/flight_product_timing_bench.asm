; Exact 6 MHz / 512 KiB timing gate for the current product flight controller.
;
; Both measurements execute the shipped S286FL02 coordinator and its staged,
; target-relocated T13SYM02 image.  ACQFLIGHT covers the ordinary-Certificate
; acquisition flight, Client Finished, immutable credential-free H2 preface,
; SETTINGS/PING acknowledgement, NST export, close, and retirement. RESFLIGHT
; covers the independent no-0RTT PSK-DHE resumed flight, H2 liveness, complete
; authenticated NST, and sequence-preserving application-key publication.
; Resident TCP callbacks are deterministic memory transports;
; live NIC transmission remains a separate pcap gate.

bits 16
cpu 8086
org 0x1000

%include "tls13/tls13_286_abi.inc"
%include "build/ibm_pc_5150/tls13-286-runtime-abi.inc"
%include "build/ibm_pc_5150/tls13-286-flight-sym-abi.inc"
%include "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/fixture_meta.inc"

crypto_segment equ 0x7000
stack_top equ 0x8000
flight_state_start equ 0x7200
fixture_pending_bytes equ 7
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

times (tls13_286_flight_load - 0x1000) - ($ - $$) db 0
incbin "build/ibm_pc_5150/tls13-286-flight.bin"

times (stack_top - 0x1000) - ($ - $$) db 0
sym_source:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/sym-source.bin"
hybrid_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/hybrid.bin"
acquisition_handoff:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/acquisition-handoff.bin"
acquisition_wire:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/acquisition-wire.bin"
acquisition_finished:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/acquisition-client-finished.bin"
acquisition_head:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/acquisition-head.bin"
resumed_handoff:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/resumed-handoff.bin"
resumed_wire:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/resumed-wire.bin"
resumed_finished:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/resumed-client-finished.bin"
resumed_head:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/resumed-head.bin"
ticket_psk_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/ticket-psk.bin"
ticket_identity_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/ticket-identity.bin"
ticket_nonce_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/ticket-nonce.bin"
ticket_age_add_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/ticket-age-add.bin"
ticket_binder_hash_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/ticket-binder-hash.bin"
ticket_binder_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/ticket-binder.bin"
early_derived_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/early-derived.bin"
app_client_key_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/app-client-key.bin"
app_server_key_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/app-server-key.bin"
app_client_iv_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/app-client-iv.bin"
app_server_iv_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/app-server-iv.bin"
app_client_seq_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/app-client-seq.bin"
app_server_seq_fixture:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/app-server-seq.bin"

acquisition_controls:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/acquisition-controls.bin"
resumed_controls:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-flight-timing/resumed-controls.bin"
h2_helper_source:
incbin "build/ibm_pc_5150/tls13-286-h2-helper.bin"
h2_post_source:
incbin "build/ibm_pc_5150/http2/post-head.bin"
h2_tail_source:
times 35 db 0
incbin "build/ibm_pc_5150/http2/post-tail.bin"
times 512 - ($ - h2_tail_source) db 0

%if ($ - $$ + 0x1000) > 0xc200
%error "flight timing fixtures overlap benchmark code"
%endif
; H2 uses 4230..5fec during the flight; no benchmark code may occupy it.
; The current four-certificate fixture needs the additional 512-byte page.
times (0xc200 - 0x1000) - ($ - $$) db 0
bench_main:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0xfff0
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init
    call install_callbacks
    call init_acquisition
    mov byte [run_mode], run_acquisition
    call enter_flight

enter_flight:
    cli
    mov sp, stack_top
    sti
    call tick_start
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov bx, crypto_segment
    mov si, tls13_286_tail_footer_off
    jmp word [tls13_286_flight_load + 14]

install_callbacks:
    mov di, TLS13_286_LINK_LOAD_CORE_SECTORS_AT
    mov ax, callback_load
    call patch_jump
    mov di, TLS13_286_LINK_READ_ABS_SECTOR
    mov ax, bench_fail
    call patch_jump
    mov di, TLS13_286_LINK_TCP_ACK
    mov ax, callback_ok
    call patch_jump
    mov di, TLS13_286_LINK_TCP_SEND
    mov ax, callback_send
    call patch_jump
    mov di, TLS13_286_LINK_TCP_RECEIVE
    mov ax, callback_receive
    call patch_jump
    mov byte [TLS13_286_LINK_TCP_CLOSE_ENTRY], 0xc3
    mov word [TLS13_286_LINK_NIC_RESTORE_SLOT], callback_ok
    mov word [tls13_286_root_service_chain], acquisition_done
    mov word [tls13_286_abort_capsule_load + \
        tls13_286_abort_capsule_entry_ptr], bench_fail
    mov word [tls13_286_abort_capsule_load + \
        tls13_286_abort_capsule_success_ptr], resumed_done
    ret

; DI=patched address, AX=near handler.  Install E9 rel16 without relying on
; the resident core bytes that a standalone benchmark intentionally omits.
patch_jump:
    mov byte [di], 0xe9
    sub ax, di
    sub ax, 3
    mov [di + 1], ax
    ret

init_base:
    mov ax, crypto_segment
    mov es, ax
    xor ax, ax
    xor di, di
    mov cx, 0x8000
    rep stosw
    mov es, ax
    mov di, flight_state_start
    mov cx, (tls13_286_flight_limit - flight_state_start) / 2
    rep stosw
    mov word [tls13_286_root_state_crypto_seg], crypto_segment

    mov ax, crypto_segment
    mov es, ax
    mov si, sym_source
    mov di, tls13_286_symmetric_stage_off
    mov cx, flight_timing_sym_source_bytes / 2
    rep movsw
    mov word [es:tls13_286_symmetric_stage_status_inv_off], 0xa55a
    mov si, hybrid_fixture
    mov di, tls13_286_hybrid_secret_off
    mov cx, flight_timing_hybrid_bytes / 2
    rep movsw
    xor ax, ax
    mov es, ax
    mov byte [send_count], 0
    ret

; Deterministic BIOS-media leaf: copy the exact embedded helper/parser sectors.
; Their normal CRC checks and the full parser execute inside the timed route.
callback_load:
    push ax
    push cx
    push si
    push di
    push es
    cmp ax, TLS13_286_LINK_TCP_CLOSE_PHASE_KEY
    jne .media
    cmp bx, TLS13_286_LINK_TCP_CLOSE_DESTINATION
    jne bench_fail
    ; TBS capture retires the initial close stub in the low leaf window.
    ; Model the product reload before restoring the memory transport leaf.
    mov si, tcp_close_source
    mov cx, (TLS13_286_LINK_TCP_CLOSE_PHASE_KEY >> 8) * 512
    jmp .copy
.media:
    cmp ax, 0x01a4
    jne .post
    cmp bx, 0x5500
    jne bench_fail
    mov si, h2_helper_source
    mov cx, 512
    jmp .copy
.post:
    cmp ax, 0x070c
    jne .tail
    cmp bx, 0x4230
    jne bench_fail
    mov si, h2_post_source
    mov cx, 3584
    jmp .copy
.tail:
    cmp ax, 0x01d2
    jne bench_fail
    cmp bx, 0x5230
    jne bench_fail
    mov si, h2_tail_source
    mov cx, 512
.copy:
    xor ax, ax
    mov es, ax
    mov di, bx
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    cmp ax, TLS13_286_LINK_TCP_CLOSE_PHASE_KEY
    jne .done
    mov byte [TLS13_286_LINK_TCP_CLOSE_ENTRY], 0xc3
.done:
    clc
    ret

init_acquisition:
    call init_base
    mov word [control_cursor], acquisition_controls
    mov si, acquisition_handoff
    call install_handoff
    mov si, acquisition_wire
    mov cx, flight_timing_acquisition_wire_bytes
    call install_wire
    mov ax, crypto_segment
    mov es, ax
    mov word [es:tls13_286_attempt_fresh_status_inv_off], 0xa55a
    xor ax, ax
    mov es, ax
    ret

init_resumed:
    call init_base
    mov word [control_cursor], resumed_controls
    mov si, resumed_handoff
    call install_handoff
    mov si, resumed_wire
    mov cx, flight_timing_resumed_wire_bytes
    call install_wire
    mov ax, crypto_segment
    mov es, ax
    mov word [es:tls13_286_attempt_fresh_status_inv_off], 0x3cc3
    mov word [es:tls13_286_capture_status_inv_off], 0xa55a
    mov word [es:tls13_286_auth_status_inv_off], 0xa55a
    mov word [es:tls13_286_ticket_status_inv_off], 0x6996

    mov si, ticket_psk_fixture
    mov di, tls13_286_ticket_psk_off
    mov cx, tls13_286_ticket_psk_bytes / 2
    rep movsw
    mov si, ticket_identity_fixture
    mov di, tls13_286_ticket_identity_off
    mov cx, flight_timing_ticket_identity_bytes / 2
    rep movsw
    mov si, ticket_nonce_fixture
    mov di, tls13_286_ticket_nonce_off
    mov cx, flight_timing_ticket_nonce_bytes / 2
    rep movsw
    mov word [es:tls13_286_ticket_lifetime_hi_off], 0
    mov word [es:tls13_286_ticket_lifetime_lo_off], 64800
    mov si, ticket_age_add_fixture
    mov di, tls13_286_ticket_age_add_off
    mov cx, 2
    rep movsw
    mov word [es:tls13_286_ticket_nonce_len_off], \
        flight_timing_ticket_nonce_bytes
    mov word [es:tls13_286_ticket_identity_len_off], \
        flight_timing_ticket_identity_bytes
    mov si, ticket_binder_hash_fixture
    mov di, tls13_286_ticket_truncated_hash_off
    mov cx, tls13_286_ticket_binder_bytes / 2
    rep movsw
    mov si, ticket_binder_fixture
    mov di, tls13_286_ticket_binder_off
    mov cx, tls13_286_ticket_binder_bytes / 2
    rep movsw
    mov si, early_derived_fixture
    mov di, tls13_286_resumption_early_off
    mov bx, tls13_286_resumption_early_inverse_off
    mov cx, tls13_286_resumption_early_bytes
.early:
    lodsb
    stosb
    xor al, 0xff
    mov [es:bx], al
    inc bx
    loop .early
    mov word [es:tls13_286_resumption_early_status_inv_off], 0xa55a
    xor ax, ax
    mov es, ax
    ret

install_handoff:
    push es
    push ds
    pop es
    mov di, TLS13_286_FLIGHT_SYM_HELLO_SERVER_X
    mov cx, flight_timing_handoff_bytes
    rep movsb
    pop es
    ret

; SI=complete wire, CX=bytes.  Match the product handoff: seven coalesced
; bytes are consumed from the high pending quarantine, then callbacks expose
; bounded 384-byte pieces of the remaining target-resident fixture.
install_wire:
    mov ax, si
    add ax, fixture_pending_bytes
    mov [wire_cursor], ax
    sub cx, fixture_pending_bytes
    mov [wire_remaining], cx
    mov ax, crypto_segment
    mov es, ax
    mov di, tls13_286_pending_wire_off
    mov cx, fixture_pending_bytes
    rep movsb
    mov word [es:tls13_286_pending_wire_len_off], fixture_pending_bytes
    mov word [es:tls13_286_pending_wire_status_inv_off], 0xa55a
    xor ax, ax
    mov es, ax
    ret

callback_receive:
    mov cx, [wire_remaining]
    or cx, cx
    jz .bad
    cmp cx, 384
    jbe .bounded
    mov cx, 384
.bounded:
    mov si, [wire_cursor]
    mov [TLS13_286_LINK_TCP_RX_PAYLOAD_PTR], si
    mov [TLS13_286_LINK_TCP_RX_PAYLOAD_LEN], cx
    add [wire_cursor], cx
    sub [wire_remaining], cx
    clc
    ret
.bad:
    stc
    ret

callback_send:
    xor ax, ax
    mov es, ax
    cmp byte [send_count], 2
    jae .control
    cmp byte [run_mode], run_resumed
    je .resumed
    cmp byte [send_count], 0
    jne .acquisition_head
    mov di, acquisition_finished
    cmp cx, flight_timing_acquisition_finished_bytes
    jne .bad
    jmp short .compare
.acquisition_head:
    cmp byte [send_count], 1
    jne .bad
    mov di, acquisition_head
    cmp cx, flight_timing_acquisition_head_bytes
    jne .bad
    jmp short .compare
.resumed:
    cmp byte [send_count], 0
    jne .resumed_head
    mov di, resumed_finished
    cmp cx, flight_timing_resumed_finished_bytes
    jne .bad
    jmp short .compare
.resumed_head:
    cmp byte [send_count], 1
    jne .bad
    mov di, resumed_head
    cmp cx, flight_timing_resumed_head_bytes
    jne .bad
    jmp short .compare
.control:
    cmp byte [send_count], 5
    jae .bad
    mov di, [control_cursor]
    mov ax, [di + 3]
    xchg al, ah
    add ax, 5
    cmp cx, ax
    jne .bad
.compare:
    repe cmpsb
    jne .bad
    cmp byte [send_count], 2
    jb .count
    mov [control_cursor], di
.count:
    inc byte [send_count]
    cmp byte [run_mode], run_acquisition
    jne .sent
    cmp byte [send_count], 2
    jne .sent
    ; Split the policy deadline at the successful credential-free preface send.
    ; Response/NST/close remains measured as post-dialogue lifecycle work.
    call read_tick
    sub ax, [tick_lo]
    sbb dx, [tick_hi]
    mov [acquisition_head_ticks], ax
.sent:
    clc
    ret
.bad:
    stc
    ret

callback_ok:
    clc
    ret

acquisition_done:
    push ax
    call tick_stop
    mov [acquisition_ticks], ax
    sub ax, [acquisition_head_ticks]
    mov [acquisition_post_ticks], ax
    pop ax
    cmp ax, tls13_286_tail_kind_authenticate
    jne bench_fail
    cmp byte [send_count], 5
    jne bench_fail
    mov ax, crypto_segment
    mov es, ax
    cmp word [es:tls13_286_capture_status_inv_off], 0xa55a
    jne bench_fail
    cmp word [es:tls13_286_ticket_status_inv_off], 0xa55a
    jne bench_fail
    cmp word [es:tls13_286_ticket_identity_len_off], \
        flight_timing_ticket_identity_bytes
    jne bench_fail
    cmp word [es:tls13_286_ticket_nonce_len_off], \
        flight_timing_ticket_nonce_bytes
    jne bench_fail
    mov si, ticket_psk_fixture
    mov di, tls13_286_ticket_psk_off
    mov cx, tls13_286_ticket_psk_bytes
    repe cmpsb
    jne bench_fail
    mov si, ticket_identity_fixture
    mov di, tls13_286_ticket_identity_off
    mov cx, flight_timing_ticket_identity_bytes
    repe cmpsb
    jne bench_fail
    mov si, ticket_nonce_fixture
    mov di, tls13_286_ticket_nonce_off
    mov cx, flight_timing_ticket_nonce_bytes
    repe cmpsb
    jne bench_fail
    xor ax, ax
    mov es, ax
    call init_resumed
    mov byte [run_mode], run_resumed
    jmp enter_flight

resumed_done:
    call tick_stop
    mov [resumed_ticks], ax
    cmp byte [send_count], 5
    jne bench_fail
    cmp byte [TLS13_286_LINK_APP_READY], 1
    jne bench_fail
    mov si, TLS13_286_LINK_APP_CLIENT_KEY
    mov di, app_client_key_fixture
    mov cx, 32
    repe cmpsb
    jne bench_fail
    mov si, TLS13_286_LINK_APP_SERVER_KEY
    mov di, app_server_key_fixture
    mov cx, 32
    repe cmpsb
    jne bench_fail
    mov si, TLS13_286_LINK_APP_CLIENT_IV
    mov di, app_client_iv_fixture
    mov cx, 12
    repe cmpsb
    jne bench_fail
    mov si, TLS13_286_LINK_APP_SERVER_IV
    mov di, app_server_iv_fixture
    mov cx, 12
    repe cmpsb
    jne bench_fail
    mov si, TLS13_286_LINK_APP_CLIENT_SEQ
    mov di, app_client_seq_fixture
    mov cx, 16
.sequence:
    cmpsb
    jne bench_fail
    loop .sequence

    mov si, tag_acquisition_head
    mov ax, [acquisition_head_ticks]
    call emit_metric
    mov si, tag_acquisition_post
    mov ax, [acquisition_post_ticks]
    call emit_metric
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
.hang:
    hlt
    jmp .hang

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
    jmp resumed_done.hang

%if ($ - $$ + 0x1000) > 0xc900
%error "flight timing harness overlaps timing support"
%endif

; Keep timer/serial code above the low H2 parser and immutable fixtures.
times (0xc970 - 0x1000) - ($ - $$) db 0

tick_start:
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

tick_stop:
    call read_tick
    sub ax, [tick_lo]
    sbb dx, [tick_hi]
    ret

read_tick:
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret

read_tick_low:
    mov ax, [0x046c]
    ret

serial_init:
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

emit_char:
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

wire_cursor dw 0
control_cursor dw 0
wire_remaining dw 0
tick_lo dw 0
tick_hi dw 0
acquisition_ticks dw 0
acquisition_head_ticks dw 0
acquisition_post_ticks dw 0
resumed_ticks dw 0
run_mode db 0
send_count db 0
tag_acquisition_head db 'ACQHEAD', 0
tag_acquisition_post db 'ACQPOST', 0
tag_acquisition db 'ACQFLIGHT', 0
tag_resumed db 'RESFLIGHT', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_n db ' N=', 0
str_dt db ' dt=', 0
str_check db ' N=1 dt=0 ck=', 0

tcp_close_source:
incbin "build/ibm_pc_5150/SEED.SYS", \
    (TLS13_286_LINK_TCP_CLOSE_PHASE_KEY & 0xff) * 512, \
    (TLS13_286_LINK_TCP_CLOSE_PHASE_KEY >> 8) * 512

%if ($ - $$ + 0x1000) > 0xe000
%error "flight timing support escaped its reserved benchmark region"
%endif


image_end:

%if (image_end - $$ + 0x1000) > 0xf000
%error "flight timing fixture collides with temporary high stack"
%endif
