; Literal 16 KiB / 4.77 MHz timing harness for the complete TLS 1.3
; symmetric-overlay initial and same-boot PSK-DHE resumed paths.
;
; The ROM BASIC sidecar loads only this four-sector resident prefix.  The
; 12-sector overlay and deterministic oracle fixtures remain cold in the same
; contiguous floppy file and are read on demand.  Fixture-sector time is
; accumulated separately from the end-to-end target time.

bits 16
cpu 8086
org 0x1000

%include "build/crypto-bench/tls13-sym-literal16k/fixture_meta.inc"

sector_size              equ 512
core_start_lba           equ 11
floppy_sectors_per_track equ 8
resident_sectors         equ 4

resident_start           equ 0x1000
driver_slot_start        equ 0x1600
overlay_base             equ 0x1800
overlay_limit            equ 0x3600
stage_buffer              equ 0x0d00
stage_buffer_bytes        equ 512
stack_top                 equ 0x3ff0

sym_entry_table           equ overlay_base + 32
sym_init_entry            equ sym_entry_table + 0 * 2
sym_critical_entry        equ sym_entry_table + 3 * 2
sym_hs_open_begin_entry   equ sym_entry_table + 4 * 2
sym_app_open_begin_entry  equ sym_entry_table + 5 * 2
sym_open_chunk_entry      equ sym_entry_table + 6 * 2
sym_open_finish_entry     equ sym_entry_table + 7 * 2
sym_verify_finished_entry equ sym_entry_table + 8 * 2
sym_build_finished_entry  equ sym_entry_table + 9 * 2
sym_derive_app_entry      equ sym_entry_table + 10 * 2
sym_build_head_entry      equ sym_entry_table + 11 * 2
sym_parse_nst_entry       equ sym_entry_table + 12 * 2
sym_binder_entry          equ sym_entry_table + 13 * 2
sym_resumed_entry         equ sym_entry_table + 14 * 2
sym_transcript_import_entry equ sym_entry_table + 15 * 2

sym_shared_secret         equ 0x3600
sym_hello_hash            equ 0x3640
sym_handshake_secret      equ 0x36c0
sym_client_app_key        equ 0x3838
sym_server_app_key        equ 0x3864
sym_ticket_psk            equ 0x38b0
sym_received_finished     equ 0x38f0
sym_binder_value          equ 0x3940
sym_io                    equ 0x39a0
sym_ticket_nonce_len      equ 0x3c28
sym_ticket_identity_len   equ 0x3c2a
sym_ticket_present        equ 0x3c2c

; This cache occupies only the otherwise-unused gap after symmetric retained
; state and before the reconnect-state floor.
record_meta_cache         equ 0x3c40
init_header               equ record_meta_cache + 0
init_tag                  equ record_meta_cache + 5
nst_header                equ record_meta_cache + 21
nst_tag                   equ record_meta_cache + 26
resumed_header            equ record_meta_cache + 42
resumed_tag               equ record_meta_cache + 47
initial_finished_total_ticks equ 0x3c80
initial_finished_io_ticks equ 0x3c82

core_header:
    jmp short start
    nop
    db 'SEEDCORE'
    db 1
    db 0
    dw core_header_end - core_header
    dw resident_sectors
    dw (image_end - $$ + 511) / 512
    dw 0
    dw 0
core_header_end:

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, stack_top
    sti
    cld
    mov [boot_drive], dl
    call serial_init

    ; Product-memory sentinels: packet/ciphertext low bands, active driver
    ; slot, and reconnect/arena state must survive both complete paths.
    mov ax, 0xa5a5
    mov di, 0x0700
    mov cx, (stage_buffer - 0x0700) / 2
    rep stosw
    mov di, driver_slot_start
    mov cx, (overlay_base - driver_slot_start) / 2
    rep stosw
    mov di, 0x3c9c
    mov cx, (0x3f00 - 0x3c9c) / 2
    rep stosw

    ; Demand-load the exact overlay and measure its floppy cost separately.
    mov word [io_ticks], 0
    call wait_tick_edge
    mov ax, [0x046c]
    mov [group_start], ax
    mov ax, overlay_phase_sector
    mov bx, overlay_base
    mov cx, overlay_phase_sectors
.load_overlay:
    call timed_read_container_sector
    jc test_fail
    inc ax
    add bx, sector_size
    loop .load_overlay
    mov ax, [0x046c]
    sub ax, [group_start]
    mov [overlay_load_ticks], ax

    ; Cache tiny record headers/tags outside the timed protocol paths.
    mov ax, record_meta_sector
    mov bx, stage_buffer
    call read_container_sector
    jc test_fail
    mov si, stage_buffer
    mov di, record_meta_cache
    mov cx, record_meta_bytes
    rep movsb

    ; Initial path: init, full CH..SH transcript, 64-byte schedule, streamed
    ; protected server flight, both Finished messages, application schedule,
    ; literal credential-free HEAD, protected NST open and bounded capture.
    mov ax, initial_handoff_sector
    mov bx, stage_buffer
    call read_container_sector
    jc test_fail
    mov word [io_ticks], 0
    call wait_tick_edge
    mov ax, [0x046c]
    mov [group_start], ax
    call word [sym_init_entry]
    jc test_fail
    mov si, stage_buffer + initial_candidate_k_offset
    mov di, sym_shared_secret
    mov cx, 32 / 2
    rep movsw
    mov si, stage_buffer + initial_finished_offset
    mov di, sym_received_finished
    mov cx, 32 / 2
    rep movsw
    call word [sym_transcript_import_entry]
    jc test_fail
    call word [sym_critical_entry]
    jc test_fail

    mov si, init_header
    mov di, init_tag
    mov ax, initial_flight_cipher_sector
    mov cx, initial_flight_cipher_bytes
    mov dx, initial_flight_hash_prefix
    call open_hs_stream
    jc test_fail
    call word [sym_verify_finished_entry]
    jc test_fail
    call word [sym_build_finished_entry]
    jc test_fail
    cmp ax, initial_client_finished_record_bytes
    jne test_fail
    mov si, sym_io
    mov cx, initial_client_finished_record_bytes
    call checksum_bytes
    cmp dx, initial_client_finished_checksum
    jne test_fail
    mov ax, [0x046c]
    sub ax, [group_start]
    mov [initial_finished_total_ticks], ax
    mov ax, [io_ticks]
    mov [initial_finished_io_ticks], ax
    call word [sym_derive_app_entry]
    jc test_fail
    call word [sym_build_head_entry]
    jc test_fail
    cmp ax, initial_head_record_bytes
    jne test_fail
    mov si, sym_io
    mov cx, initial_head_record_bytes
    call checksum_bytes
    cmp dx, initial_head_checksum_expected
    jne test_fail

    call open_nst
    jc test_fail
    mov si, sym_io
    mov cx, nst_message_bytes
    call checksum_bytes
    cmp dx, nst_message_checksum
    jne test_fail
    mov si, sym_io
    mov cx, nst_message_bytes
    call word [sym_parse_nst_entry]
    jc test_fail
    call finish_group
    mov ax, [total_ticks]
    mov [initial_total_ticks], ax
    mov ax, [io_ticks]
    mov [initial_io_ticks], ax

    call validate_initial
    jc test_fail
    call verify_sentinels
    jc test_fail

    ; Same-boot resumption: retained PSK, real binder, fresh 64-byte hybrid
    ; Extract, full resumed CH..SH transcript, certificate-free protected
    ; EE/Finished, client Finished, application schedule and HEAD.
    mov ax, resumed_handoff_sector
    mov bx, stage_buffer
    call read_container_sector
    jc test_fail
    mov word [io_ticks], 0
    call wait_tick_edge
    mov ax, [0x046c]
    mov [group_start], ax
    mov si, stage_buffer + resumed_binder_hash_offset
    mov di, 0x3660
    mov cx, 32 / 2
    rep movsw
    call word [sym_binder_entry]
    jc test_fail
    mov si, sym_binder_value
    mov cx, 32
    call checksum_bytes
    cmp dx, resumption_binder_checksum
    jne test_fail
    mov si, stage_buffer + resumed_candidate_k_offset
    mov di, sym_shared_secret
    mov cx, 32 / 2
    rep movsw
    mov si, stage_buffer + resumed_finished_offset
    mov di, sym_received_finished
    mov cx, 32 / 2
    rep movsw
    call word [sym_transcript_import_entry]
    jc test_fail
    call word [sym_resumed_entry]
    jc test_fail
    mov si, resumed_header
    mov di, resumed_tag
    mov ax, resumed_flight_cipher_sector
    mov cx, resumed_flight_cipher_bytes
    mov dx, resumed_flight_hash_prefix
    call open_hs_stream
    jc test_fail
    call word [sym_verify_finished_entry]
    jc test_fail
    call word [sym_build_finished_entry]
    jc test_fail
    cmp ax, resumed_client_finished_record_bytes
    jne test_fail
    mov si, sym_io
    mov cx, resumed_client_finished_record_bytes
    call checksum_bytes
    cmp dx, resumed_client_finished_checksum
    jne test_fail
    call word [sym_derive_app_entry]
    jc test_fail
    call word [sym_build_head_entry]
    jc test_fail
    cmp ax, resumed_head_record_bytes
    jne test_fail
    mov si, sym_io
    mov cx, resumed_head_record_bytes
    call checksum_bytes
    cmp dx, resumed_head_checksum_expected
    jne test_fail
    call finish_group
    mov ax, [total_ticks]
    mov [resumed_total_ticks], ax
    mov ax, [io_ticks]
    mov [resumed_io_ticks], ax

    call validate_resumed
    jc test_fail
    call verify_sentinels
    jc test_fail

    mov si, load_pass
    call emit_str
    mov ax, [overlay_load_ticks]
    call emit_dec16
    mov si, sector_text
    call emit_str
    mov ax, overlay_phase_sectors
    call emit_dec16
    call emit_crlf

    mov si, initial_finished_pass
    mov bx, [initial_finished_total_ticks]
    mov dx, [initial_finished_io_ticks]
    call emit_timing
    mov si, initial_pass
    mov bx, [initial_total_ticks]
    mov dx, [initial_io_ticks]
    call emit_timing
    mov si, resumed_pass
    mov bx, [resumed_total_ticks]
    mov dx, [resumed_io_ticks]
    call emit_timing
    mov si, done_text
    call emit_str
    call emit_crlf
.halt:
    hlt
    jmp .halt

test_fail:
    mov si, fail_text
    call emit_str
    call emit_crlf
    mov si, done_text
    call emit_str
    call emit_crlf
    jmp start.halt

; SI=5-byte header, DI=16-byte tag, AX=cipher object sector,
; CX=cipher bytes, DX=plaintext transcript prefix.
open_hs_stream:
    mov [stream_sector], ax
    mov [stream_remaining], cx
    mov [record_tag_ptr], di
    push ds
    pop es
    mov di, sym_io
    mov cx, 5
    rep movsb
    mov ax, dx
    call word [sym_hs_open_begin_entry]
    jc .failed
    mov ax, [sym_open_chunk_entry]
    mov [stream_call_ptr], ax
    call stream_chunks
    jc .failed
    mov si, [record_tag_ptr]
    call word [sym_open_finish_entry]
    ret
.failed:
    stc
    ret

stream_chunks:
.next_sector:
    call load_stream_sector
    jc .failed
    mov cx, [stream_chunk]
    cmp cx, 384
    jbe .one
    mov si, stage_buffer
    mov cx, 384
    call word [stream_call_ptr]
    jc .failed
    mov si, stage_buffer + 384
    mov cx, [stream_chunk]
    sub cx, 384
    call word [stream_call_ptr]
    jc .failed
    jmp short .consumed
.one:
    mov si, stage_buffer
    call word [stream_call_ptr]
    jc .failed
.consumed:
    call consume_stream_sector
    cmp word [stream_remaining], 0
    jne .next_sector
    clc
    ret
.failed:
    stc
    ret

open_nst:
    push ds
    pop es
    mov si, nst_header
    mov di, sym_io
    mov cx, 5
    rep movsb
    call word [sym_app_open_begin_entry]
    jc .failed
    mov word [stream_sector], nst_cipher_sector
    mov word [stream_remaining], nst_cipher_bytes
    call load_stream_sector
    jc .failed
    mov si, stage_buffer
    mov di, sym_io
    mov cx, nst_cipher_bytes
    rep movsb
    mov si, sym_io
    mov cx, nst_cipher_bytes
    call word [sym_open_chunk_entry]
    jc .failed
    mov si, nst_tag
    call word [sym_open_finish_entry]
    ret
.failed:
    stc
    ret

; Read one padded object sector into the low staging buffer and charge only
; the BIOS disk interval to io_ticks.
load_stream_sector:
    mov ax, [stream_sector]
    mov bx, stage_buffer
    call timed_read_container_sector
    jc .failed
    mov ax, [stream_remaining]
    cmp ax, sector_size
    jbe .length_ready
    mov ax, sector_size
.length_ready:
    mov [stream_chunk], ax
    clc
    ret
.failed:
    stc
    ret

consume_stream_sector:
    mov ax, [stream_chunk]
    sub [stream_remaining], ax
    inc word [stream_sector]
    ret

timed_read_container_sector:
    mov dx, [0x046c]
    mov [io_start], dx
    call read_container_sector
    pushf
    mov dx, [0x046c]
    sub dx, [io_start]
    add [io_ticks], dx
    popf
    ret

; AX=zero-based sector within this phase container, ES:BX=destination.
read_container_sector:
    push ax
    add ax, core_start_lba
    call read_abs_sector
    pop ax
    ret

; AX=absolute LBA.  160 KiB single-sided 8-sector geometry.
read_abs_sector:
    push ax
    push bx
    push cx
    push dx
    push si
    mov si, ax
    mov byte [read_attempts], 3
.retry:
    mov ax, si
    mov dl, floppy_sectors_per_track
    div dl
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
    mov dl, [boot_drive]
    mov ax, 0x0201
    int 0x13
    jnc .ok
    xor ax, ax
    mov dl, [boot_drive]
    int 0x13
    dec byte [read_attempts]
    jnz .retry
    stc
    jmp short .restore
.ok:
    clc
.restore:
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

finish_group:
    mov ax, [0x046c]
    sub ax, [group_start]
    mov [total_ticks], ax
    ret

validate_initial:
    mov si, sym_handshake_secret
    mov cx, 528
    call checksum_bytes
    cmp dx, initial_security_state_checksum
    jne .failed
    cmp byte [sym_ticket_present], 0
    je .failed
    cmp word [sym_ticket_nonce_len], 8
    jne .failed
    cmp word [sym_ticket_identity_len], 192
    jne .failed
    clc
    ret
.failed:
    stc
    ret

validate_resumed:
    mov si, sym_handshake_secret
    mov cx, 528
    call checksum_bytes
    cmp dx, resumed_security_state_checksum
    jne .failed
    clc
    ret
.failed:
    stc
    ret

checksum_bytes:
    push ax
    xor dx, dx
.next:
    lodsb
    xor ah, ah
    add dx, ax
    loop .next
    pop ax
    ret

verify_sentinels:
    mov ax, 0xa5a5
    mov si, 0x0700
    mov cx, (stage_buffer - 0x0700) / 2
.low:
    cmp [si], ax
    jne .failed
    add si, 2
    loop .low
    mov si, driver_slot_start
    mov cx, (overlay_base - driver_slot_start) / 2
.driver:
    cmp [si], ax
    jne .failed
    add si, 2
    loop .driver
    mov si, 0x3c9c
    mov cx, (0x3f00 - 0x3c9c) / 2
.high:
    cmp [si], ax
    jne .failed
    add si, 2
    loop .high
    clc
    ret
.failed:
    stc
    ret

wait_tick_edge:
    mov bx, [0x046c]
.wait:
    mov ax, [0x046c]
    cmp ax, bx
    je .wait
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
    push dx
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

emit_dec16:
    push ax
    push bx
    push cx
    push dx
    mov bx, 10
    xor cx, cx
.divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .divide
.pop:
    pop ax
    add al, '0'
    call emit_char
    loop .pop
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; SI=prefix, BX=total ticks, DX=fixture-I/O ticks.
emit_timing:
    call emit_str
    mov ax, bx
    call emit_dec16
    mov si, io_text
    call emit_str
    mov ax, dx
    call emit_dec16
    mov si, compute_text
    call emit_str
    mov ax, bx
    sub ax, dx
    call emit_dec16
    jmp emit_crlf

load_pass          db 'LOAD PASS t=', 0
initial_finished_pass db 'IFIN PASS t=', 0
initial_pass       db 'INIT PASS t=', 0
resumed_pass       db 'RESUME PASS t=', 0
sector_text        db ' s=', 0
io_text            db ' i=', 0
compute_text       db ' c=', 0
fail_text          db 'FAIL', 0
done_text          db 'DONE', 0

boot_drive db 0
read_attempts db 0
group_start dw 0
io_start dw 0
io_ticks dw 0
total_ticks dw 0
stream_sector dw 0
stream_remaining dw 0
stream_chunk dw 0
stream_call_ptr dw 0
record_tag_ptr dw 0
overlay_load_ticks dw 0
initial_total_ticks dw 0
initial_io_ticks dw 0
resumed_total_ticks dw 0
resumed_io_ticks dw 0

%if ($ - $$) > (driver_slot_start - resident_start)
%error "full symmetric timing scheduler exceeds the three-sector nucleus"
%endif
times (driver_slot_start - resident_start) - ($ - $$) db 0
times (overlay_base - driver_slot_start) db 0
resident_end:

%if (resident_end - $$) != resident_sectors * sector_size
%error "full symmetric timing resident prefix must remain four sectors"
%endif

align 512, db 0
overlay_phase_start:
incbin "build/crypto-bench/tls13-sym-literal16k/tls13_sym_overlay.bin"
overlay_phase_content_end:
align 512, db 0
overlay_phase_end:
overlay_phase_sector equ (overlay_phase_start - $$) / sector_size
overlay_phase_sectors equ (overlay_phase_end - overlay_phase_start) / sector_size

initial_handoff_start:
incbin "build/crypto-bench/tls13-sym-literal16k/initial_handoff.bin"
initial_handoff_end:
align 512, db 0
initial_handoff_sector equ (initial_handoff_start - $$) / sector_size

resumed_handoff_start:
incbin "build/crypto-bench/tls13-sym-literal16k/resumed_handoff.bin"
resumed_handoff_end:
align 512, db 0
resumed_handoff_sector equ (resumed_handoff_start - $$) / sector_size

record_meta_start:
incbin "build/crypto-bench/tls13-sym-literal16k/record_meta.bin"
record_meta_end:
align 512, db 0
record_meta_sector equ (record_meta_start - $$) / sector_size
record_meta_bytes equ record_meta_content_bytes

initial_flight_cipher_start:
incbin "build/crypto-bench/tls13-sym-literal16k/initial_flight_cipher.bin"
initial_flight_cipher_end:
align 512, db 0
initial_flight_cipher_sector equ \
    (initial_flight_cipher_start - $$) / sector_size

nst_cipher_start:
incbin "build/crypto-bench/tls13-sym-literal16k/nst_cipher.bin"
nst_cipher_end:
align 512, db 0
nst_cipher_sector equ (nst_cipher_start - $$) / sector_size

resumed_flight_cipher_start:
incbin "build/crypto-bench/tls13-sym-literal16k/resumed_flight_cipher.bin"
resumed_flight_cipher_end:
align 512, db 0
resumed_flight_cipher_sector equ \
    (resumed_flight_cipher_start - $$) / sector_size

image_end:
