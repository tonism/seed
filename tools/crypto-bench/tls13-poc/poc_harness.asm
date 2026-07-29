; Literal-16-KiB phase container for the Build 13 TLS 1.3 PoC.
;
; Only the four-sector resident prefix is loaded by the ROM BASIC sidecar.
; Crypto images stay in the same flat SEED.SYS-style file and are demand-read
; into K (0x1800..0x3600) from the contiguous first FAT data file.

; Fixed resident ABI used only by the cold harness controllers.  Keeping the
; table immediately after the 23-byte SEEDCORE header lets the four-sector
; scheduler stay small while the executable oracle machinery remains cold.
controller_services         equ 0x1017
controller_descriptors      equ controller_services + 12
service_load_phase          equ controller_services + 0
service_write_abs           equ controller_services + 2
service_disk_reset          equ controller_services + 4
service_verify_sentinels    equ controller_services + 6
service_wait_tick           equ controller_services + 8
service_read_tick           equ controller_services + 10

desc_entropy_slots          equ controller_descriptors + 0
desc_entropy_meta           equ controller_descriptors + 2
desc_entropy_record         equ controller_descriptors + 4
desc_hello_inputs           equ controller_descriptors + 6
desc_hello_resumed          equ controller_descriptors + 8
desc_hello_fresh            equ controller_descriptors + 10
desc_hello_server           equ controller_descriptors + 12
desc_candidate_expected     equ controller_descriptors + 14
desc_fo_stream              equ controller_descriptors + 16
desc_fo_expected            equ controller_descriptors + 18
desc_sym_flight_meta        equ controller_descriptors + 20
desc_sym_flight_cipher      equ controller_descriptors + 22

%ifdef POC_BUILD_ENTROPY_CONTROLLER
bits 16
cpu 8086
org 0x2400

entropy_entry_table equ 0x1800 + 32
core_start_lba equ 11

entropy_controller:
    mov ax, [desc_entropy_slots]
    mov cl, 2
    mov bx, 0x0700
    call word [service_load_phase]
    jc .failed
    mov ax, [desc_entropy_meta]
    mov cl, 1
    mov bx, 0x0b80
    call word [service_load_phase]
    jc .failed

    call word [service_wait_tick]
    call word [service_read_tick]
    mov [entropy_total_start], ax
    call word [entropy_entry_table]
    jc .failed
    call word [entropy_entry_table + 2]
    jc .failed
    call word [entropy_entry_table + 4]
    jc .failed
%ifndef POC_DETERMINISTIC_COHERENT_CHAIN
    ; Production-shaped mode mixes a target timing snapshot.  The coherent
    ; chain oracle deliberately omits it because its downstream fixtures are
    ; byte-exact; this is not a claim of physical min-entropy.
    call word [entropy_entry_table + 8]
    jc .failed
%endif
    mov si, 0x0b82
    mov cx, POC_ENTROPY_SUPPLEMENT_LEN
    call word [entropy_entry_table + 6]
    jc .failed
    call word [entropy_entry_table + 10]
    jc .failed
    cmp ax, POC_ENTROPY_TARGET_SLOT
    jne .failed
    mov [entropy_target], al

    call word [service_wait_tick]
    call word [service_read_tick]
    mov [entropy_write_start], ax
    xor bx, bx
    mov bl, [entropy_target]
    mov ax, [desc_entropy_slots]
    add ax, bx
    add ax, core_start_lba
    mov cl, 1
    mov bx, 0x0c00
    call word [service_write_abs]
    jc .failed
    call word [service_disk_reset]
    jc .failed
    call word [service_read_tick]
    sub ax, [entropy_write_start]
    mov [entropy_write_ticks], ax

    call word [service_wait_tick]
    call word [service_read_tick]
    mov [entropy_read_start], ax
    xor bx, bx
    mov bl, [entropy_target]
    mov ax, [desc_entropy_slots]
    add ax, bx
    mov cl, 1
    mov bx, 0x0e00
    call word [service_load_phase]
    jc .failed
    call word [service_read_tick]
    sub ax, [entropy_read_start]
    mov [entropy_read_ticks], ax

    call word [entropy_entry_table + 12]
    jc .failed
    call word [entropy_entry_table + 14]
    jc .failed
    cmp si, 0x3660
    jne .failed
    cmp cx, 64
    jne .failed
    mov di, 0x3b9c
    mov cx, 32
    rep movsw
    call word [service_read_tick]
    sub ax, [entropy_total_start]
    mov [entropy_total_ticks], ax

    mov ax, [desc_entropy_record]
    mov cl, 1
    mov bx, 0x0700
    call word [service_load_phase]
    jc .failed
    mov si, 0x0c00
    mov di, 0x0700
    mov cx, 512
    repe cmpsb
    jne .failed
    mov ax, [desc_entropy_meta]
    mov cl, 1
    mov bx, 0x0700
    call word [service_load_phase]
    jc .failed
    mov si, 0x3b9c
    mov di, 0x0762
    mov cx, 64
    repe cmpsb
    jne .failed
    call word [service_verify_sentinels]
    or ax, ax
    jz .failed
    mov ax, [entropy_total_ticks]
    mov bx, [entropy_write_ticks]
    mov dx, [entropy_read_ticks]
    clc
    ret
.failed:
    stc
    ret

entropy_total_start dw 0
entropy_total_ticks dw 0
entropy_write_start dw 0
entropy_write_ticks dw 0
entropy_read_start dw 0
entropy_read_ticks dw 0
entropy_target db 0

%elifdef POC_BUILD_KEYGEN_CONTROLLER
bits 16
cpu 8086
org 0x2400

keygen_controller:
    call word [service_wait_tick]
    call word [service_read_tick]
    mov [keygen_tick_start], ax
    call 0x1800
    call word [service_read_tick]
    sub ax, [keygen_tick_start]
    mov [keygen_tick_delta], ax
    xor dx, dx
    mov si, 0x3600
    mov cx, 384 / 2
    call keygen_checksum_words
    mov si, 0x3800
    mov cx, 384 / 2
    call keygen_checksum_words
    mov si, 0x3980
    mov cx, 384 / 2
    call keygen_checksum_words
    mov si, 0x08c0
    mov cx, 1184 / 2
    call keygen_checksum_words
    mov si, 0x3780
    mov cx, 64 / 2
    call keygen_checksum_words
    cmp dx, POC_KEYGEN_CHECKSUM
    jne .failed
    call word [service_verify_sentinels]
    or ax, ax
    jz .failed
    mov ax, [keygen_tick_delta]
    clc
    ret
.failed:
    stc
    ret

keygen_checksum_words:
.next:
    add dx, [si]
    add si, 2
    loop .next
    ret

keygen_tick_start dw 0
keygen_tick_delta dw 0

%elifdef POC_BUILD_HELLO_CONTROLLER
bits 16
cpu 8086
org 0x0f00

hello_entry_table equ 0x1800 + 48
; KeyGen retains H(ek)||z through 0x37bf and sHat1 begins at 0x3800.
; The intervening 64-byte gap is dead until the candidate phase, making it a
; safe save slot for the expected HELLO publication in both K15 and K14.  K14
; relocates HELLO mutable state through 0x0efd, so 0x0e00 is not available.
hello_expected_stage equ 0x37c0
%ifdef TLS13_POC_K14
; BIOS reads fill the complete 512-byte destination even though each fixture
; carries at most 384 ServerHello bytes.  The 0700 receive frame's sector tail
; reaches 0900 and would overwrite c[0..63] at 08c0.  K14's executable
; extension is dead until the later symmetric controller is installed.
hello_server_stage equ 0x3400
%else
hello_server_stage equ 0x0d00
%endif
hello_server_stage_sectors equ 1

hello_controller:
    ; Preserve the resident-staged expected final publication while both
    ; ClientHello forms reuse the 0700 receive frame.
    mov si, 0x0700
    mov di, hello_expected_stage
    mov cx, 64
    rep movsb
    call word [hello_entry_table + 2]
    jc .failed
    mov dl, POC_HELLO_RESUMED_CHUNKS
    call hello_drain_client
    jc .failed
    call word [hello_entry_table]
    jc .failed
    mov dl, POC_HELLO_FRESH_CHUNKS
    call hello_drain_client
    jc .failed
    call word [hello_entry_table + 10]
    jc .failed
    mov ax, [desc_hello_server]
    mov dl, POC_HELLO_SERVER_CHUNKS
    call hello_feed_server
    jc .failed
    call word [hello_entry_table + 14]
    jc .failed
    ; This is the literal pre-Finished deadline start: immediately after the
    ; final ServerHello parser/context publication succeeds.
    call word [service_read_tick]
    mov [0x08b8], ax
    cmp byte [0x0daa], 1
    jne .failed
    mov si, hello_expected_stage
    mov di, 0x0700
    mov cx, 64
    rep movsb
    mov si, 0x0d00
    mov di, 0x0700
    mov cx, 64
    repe cmpsb
    jne .failed
    call word [service_verify_sentinels]
    or ax, ax
    jz .failed
    clc
    ret
.failed:
    stc
    ret

hello_drain_client:
    mov [hello_chunks_left], dl
.next:
    call word [hello_entry_table + 4]
    jc .failed
    or ax, ax
    jz .finished
    cmp ax, 1
    jne .failed
    cmp byte [hello_chunks_left], 0
    je .failed
    or cx, cx
    jz .failed
    cmp cx, 384
    ja .failed
    call word [hello_entry_table + 6]
    jc .failed
    dec byte [hello_chunks_left]
    jmp short .next
.finished:
    cmp byte [hello_chunks_left], 0
    jne .failed
    clc
    ret
.failed:
    stc
    ret

hello_feed_server:
    mov [hello_fixture_next], ax
    mov [hello_chunks_left], dl
.next:
    cmp byte [hello_chunks_left], 0
    je .done
    mov ax, [hello_fixture_next]
    mov cl, hello_server_stage_sectors
    mov bx, hello_server_stage
    call word [service_load_phase]
    jc .failed
    mov si, hello_server_stage + 2
    mov cx, [hello_server_stage]
    call word [hello_entry_table + 12]
    jc .failed
    inc word [hello_fixture_next]
    dec byte [hello_chunks_left]
    jmp short .next
.done:
    clc
    ret
.failed:
    stc
    ret

hello_fixture_next dw 0
hello_chunks_left db 0

%elifdef POC_BUILD_SYM_CONTROLLER
bits 16
cpu 8086
%ifdef TLS13_POC_K14
org 0x3400
%else
org 0x0d00
%endif

sym_entry_table          equ 0x1800 + 32
sym_hs_open_begin_entry  equ sym_entry_table + (4 * 2)
sym_open_chunk_entry     equ sym_entry_table + (6 * 2)
sym_open_finish_entry    equ sym_entry_table + (7 * 2)
sym_verify_finish_entry  equ sym_entry_table + (8 * 2)
sym_build_finish_entry   equ sym_entry_table + (9 * 2)
sym_received_finish      equ 0x38f0
sym_received_tag         equ 0x3910
sym_io                   equ 0x39a0
; K14 places the 77-byte symmetric runtime tail after this controller in the
; persistent extension, leaving this complete low sector phase-private.  Keep
; the candidate/FO handoff at 0700 untouched throughout the protected flight.
sym_flight_stage         equ 0x0e00
sym_flight_stage_sectors equ 1

sym_controller:
    call word [sym_entry_table + (3 * 2)]
    jc .failed

    mov ax, [desc_sym_flight_meta]
    mov cl, sym_flight_stage_sectors
    mov bx, sym_flight_stage
    call word [service_load_phase]
    jc .failed
    mov si, sym_flight_stage
    mov di, sym_io
    mov cx, 5
    rep movsb
    mov di, sym_received_tag
    mov cx, 8
    rep movsw
    mov di, sym_received_finish
    mov cx, 16
    rep movsw

    mov ax, POC_SYM_FLIGHT_PREFIX
    call word [sym_hs_open_begin_entry]
    jc .failed
    mov ax, [desc_sym_flight_cipher]
    mov [sym_stream_sector], ax
    mov word [sym_stream_remaining], POC_SYM_FLIGHT_BYTES
.next_sector:
    mov ax, [sym_stream_sector]
    mov cl, sym_flight_stage_sectors
    mov bx, sym_flight_stage
    call word [service_load_phase]
    jc .failed
    mov cx, [sym_stream_remaining]
    cmp cx, 512
    jbe .chunk_ready
    mov cx, 512
.chunk_ready:
    mov [sym_stream_chunk], cx
    cmp cx, 384
    jbe .one_chunk
    mov si, sym_flight_stage
    mov cx, 384
    call word [sym_open_chunk_entry]
    jc .failed
    mov si, sym_flight_stage + 384
    mov cx, [sym_stream_chunk]
    sub cx, 384
    call word [sym_open_chunk_entry]
    jc .failed
    jmp short .consumed
.one_chunk:
    mov si, sym_flight_stage
    call word [sym_open_chunk_entry]
    jc .failed
.consumed:
    mov ax, [sym_stream_chunk]
    sub [sym_stream_remaining], ax
    inc word [sym_stream_sector]
    cmp word [sym_stream_remaining], 0
    jne .next_sector

    mov si, sym_received_tag
    call word [sym_open_finish_entry]
    jc .failed
    call word [sym_verify_finish_entry]
    jc .failed
    call word [sym_build_finish_entry]
    ret
.failed:
    stc
    ret

sym_stream_sector dw 0
sym_stream_remaining dw 0
sym_stream_chunk dw 0
sym_controller_end:

%ifdef TLS13_POC_K14
%if (sym_controller_end - sym_controller) > (0x3510 - 0x3400)
%error "K14 symmetric controller reaches its extension-resident runtime tail"
%endif
%else
%if (sym_controller_end - sym_controller) > (0x0e00 - 0x0d00)
%error "K15 symmetric controller reaches its protected-flight staging sector"
%endif
%endif

%elifdef POC_BUILD_CANDIDATE_CONTROLLER
bits 16
cpu 8086
org 0x2200

candidate_message_len   equ 32
candidate_cache_len     equ 96
candidate_handoff_start equ 0x0700
candidate_handoff_end   equ candidate_handoff_start + \
                            candidate_message_len + candidate_cache_len

candidate_controller:
    call 0x1800
    mov si, 0x3a40
    mov di, candidate_handoff_start
    mov cx, candidate_message_len / 2
    rep movsw
    mov si, 0x3b9c
    mov di, candidate_handoff_start + candidate_message_len
    mov cx, candidate_cache_len / 2
    rep movsw
    clc
    ret

%elifdef POC_BUILD_FO_CONTROLLER
bits 16
cpu 8086
org 0x2400

%ifdef TLS13_POC_K14
; K14 lowers FO's accumulator to 3200..33ff, so the K15 staging sector at
; 31e8 would overwrite live polynomial work.  The symmetric extension is dead
; once Client Finished commits and is exactly one sector.
fo_stream_stage equ 0x3400
%else
fo_stream_stage equ 0x31e8
%endif
fo_stream_stage_sectors equ 1

fo_controller:
    mov byte [fo_read_index], 0
    call word [service_wait_tick]
    call word [service_read_tick]
    mov [fo_tick_start], ax
    mov bx, fo_read_callback
    call 0x1800
    jc .failed
    cmp ax, 1
    jne .failed
    cmp byte [fo_read_index], POC_FO_REQUESTS
    jne .failed
    call word [service_read_tick]
    sub ax, [fo_tick_start]
    mov [fo_tick_delta], ax
    mov ax, [desc_fo_expected]
    mov cl, 1
    mov bx, 0x0700
    call word [service_load_phase]
    jc .failed
    mov si, 0x3b9c
    mov di, 0x0700
    mov cx, 32
    repe cmpsb
    jne .failed
    call word [service_verify_sentinels]
    or ax, ax
    jz .failed
    mov ax, [fo_tick_delta]
    clc
    ret
.failed:
    stc
    ret

fo_read_callback:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push es
    mov [fo_req_object], al
    mov [fo_req_offset], dx
    mov [fo_req_count], cx
    mov [fo_req_destination], di
    xor bx, bx
    mov bl, [fo_read_index]
    cmp bl, POC_FO_REQUESTS
    jae .failed
    mov ax, [desc_fo_stream]
    add ax, bx
    mov cl, fo_stream_stage_sectors
    mov bx, fo_stream_stage
    call word [service_load_phase]
    jc .failed
    mov al, [fo_req_object]
    cmp al, [fo_stream_stage]
    jne .failed
    mov ax, [fo_req_offset]
    cmp ax, [fo_stream_stage + 1]
    jne .failed
    mov cx, [fo_req_count]
    cmp cx, [fo_stream_stage + 3]
    jne .failed
    mov si, fo_stream_stage + 5
    mov di, [fo_req_destination]
    rep movsb
    inc byte [fo_read_index]
    clc
    jmp short .restore
.failed:
    stc
.restore:
    pop es
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

fo_tick_start dw 0
fo_tick_delta dw 0
fo_req_offset dw 0
fo_req_count dw 0
fo_req_destination dw 0
fo_read_index db 0
fo_req_object db 0

%else
bits 16
cpu 8086
org 0x1000

%include "tools/crypto-bench/tls13-poc/layout.inc"

sector_size             equ 512
core_start_lba          equ 11
floppy_sectors_per_track equ 8
resident_sectors        equ 4
return_stack_top        equ 0x3ff0
%ifdef TLS13_POC_K14
fo_stream_stage         equ 0x3400
%else
fo_stream_stage         equ 0x31e8
%endif
fo_stream_stage_sectors equ 1
cf_tick_start_low       equ 0x08b8
entropy_controller_entry equ 0x2400
keygen_controller_entry equ 0x2400
hello_controller_entry  equ 0x0d60
candidate_controller_entry equ 0x2200
%ifdef TLS13_POC_K14
sym_controller_entry    equ poc_k_extension_start
%else
sym_controller_entry    equ 0x0d00
%endif
fo_controller_entry     equ 0x2400

entropy_entry_table     equ poc_k_start + 32
hello_entry_table       equ poc_k_start + 48

%ifndef POC_KEYGEN_CHECKSUM
%define POC_KEYGEN_CHECKSUM 0xda4e
%endif

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

%if (core_header_end - $$) != 0x17
%error "controller ABI requires the fixed 23-byte SEEDCORE header"
%endif
controller_service_table:
    dw load_phase
    dw write_abs_sectors
    dw disk_reset
    dw verify_product_sentinels
    dw wait_tick_edge
    dw read_tick
controller_descriptor_table:
%ifdef POC_INCLUDE_ENTROPY
    dw entropy_slots_fixture_sector
    dw entropy_meta_fixture_sector
    dw entropy_record_fixture_sector
%else
    times 3 dw 0
%endif
%ifdef POC_INCLUDE_HELLO
    dw hello_inputs_fixture_sector
    dw hello_resumed_fixture_sector
    dw hello_fresh_fixture_sector
    dw hello_server_fixture_sector
%else
    times 4 dw 0
%endif
%ifdef POC_INCLUDE_CANDIDATE
    dw candidate_fixture_sector
%else
    dw 0
%endif
%ifdef POC_INCLUDE_FO
    dw fo_stream_fixture_sector
    dw fo_expected_fixture_sector
%else
    times 2 dw 0
%endif
%ifdef POC_INCLUDE_SYM
    dw sym_flight_meta_fixture_sector
    dw sym_flight_cipher_fixture_sector
%else
    times 2 dw 0
%endif
start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, return_stack_top
    sti
    cld
    mov [boot_drive], dl
    call serial_init

    ; Freeze the product regions that must survive every security overlay.
    mov di, poc_reconnect_state_start
    mov cx, (poc_stack_guard_start - poc_reconnect_state_start) / 2
    mov ax, 0xa5a5
    rep stosw
    mov byte [quarantine_state], 0

    mov si, start_text
    call emit_phase

%ifdef POC_DELTA_PRELOAD
    ; Preload the full symmetric overlay before the connection attempt.  HELLO
    ; and the provisional candidate overwrite only a checked prefix; the
    ; critical-window restore below rereads exactly that dirty prefix.
    mov si, preload_begin
    call emit_phase
    mov ax, sym_phase_sector
    mov cl, sym_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc disk_fail
    call end_load_timing
    mov si, preload_pass
    call emit_str
    mov ax, [load_tick_delta]
    call emit_dec16
    call emit_crlf
%endif

%ifdef POC_COMPARE_LOADERS
    mov si, io_begin
    call emit_phase
    mov ax, keygen_phase_sector
    mov cl, keygen_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase_legacy
    jc disk_fail
    call end_load_timing
    mov ax, [load_tick_delta]
    mov [legacy_load_ticks], ax
    mov ax, keygen_phase_sector
    mov cl, keygen_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc disk_fail
    call end_load_timing
    mov si, io_pass
    call emit_str
    mov ax, [legacy_load_ticks]
    call emit_dec16
    mov si, batch_text
    call emit_str
    mov ax, [load_tick_delta]
    call emit_dec16
    call emit_crlf
%endif

%ifdef POC_INCLUDE_ENTROPY
    mov si, entropy_begin
    call emit_phase
    mov ax, entropy_phase_sector
    mov cl, entropy_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc disk_fail
    call end_load_timing
    call entropy_controller_entry
    jc entropy_fail
    mov [tick_delta], ax
    mov [entropy_write_ticks], bx
    mov [entropy_read_ticks], dx
    mov si, entropy_pass
    call emit_str
    mov ax, [tick_delta]
    call emit_dec16
    mov si, write_text
    call emit_str
    mov ax, [entropy_write_ticks]
    call emit_dec16
    mov si, read_text
    call emit_str
    mov ax, [entropy_read_ticks]
    call emit_dec16
    call emit_load_ticks
    call emit_crlf
%else
    ; Legacy deterministic fixture for builds that intentionally omit the
    ; ratchet overlay.  Secure-chain builds never compile this fallback.
    mov si, fixture_d_z
    mov di, poc_attempt_cache_start
    mov cx, 32
    rep movsw
%endif

    mov si, keygen_begin
    call emit_phase
    mov ax, keygen_phase_sector
    mov cl, keygen_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc disk_fail
    call end_load_timing
    call keygen_controller_entry
    jc crypto_fail
    mov [tick_delta], ax

    mov si, keygen_pass
    mov ax, [tick_delta]
    call emit_result

%ifdef POC_INCLUDE_HELLO
    mov si, hello_begin
    call emit_phase
    mov ax, hello_phase_sector
    mov cl, hello_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc disk_fail
    mov ax, hello_inputs_fixture_sector
    mov cl, hello_inputs_fixture_sectors
    mov bx, 0x0e00
    call load_phase
    jc disk_fail
.hello_full_memory_stage_begin:
    mov si, 0x0e00
    mov di, poc_attempt_cache_start
    mov cx, 102
    rep movsb
    mov si, 0x0e66
    mov di, poc_ticket_identity
    mov cx, 192
    rep movsb
    mov si, 0x0e00 + 294
    mov di, poc_low_scratch_start
    mov cx, 32
    rep movsw
.hello_full_memory_stage_end:
    mov ax, hello_controller_sector
    mov cl, hello_controller_sectors
    mov bx, hello_controller_entry
    call load_phase
    jc disk_fail
    call end_load_timing
    call hello_controller_entry
    jc hello_fail
    ; HELLO has atomically published server-X, digest, and the portable live
    ; SHA-256 context at 0d00..0daa.  The candidate preserves that entire band.
%endif

%ifdef POC_INCLUDE_CANDIDATE
    mov ax, candidate_phase_sector
    mov cl, candidate_phase_sectors
    mov bx, poc_k_start
    call load_phase
    jc disk_fail
    call candidate_controller_entry
    jc candidate_fail
%endif

%ifdef POC_INCLUDE_SYM
    ; Restore SYM's HELLO-dirtied immutable prefix, import the committed
    ; transcript once, then execute the complete protected flight through the
    ; exact client-Finished record.  No diagnostic output occurs inside the
    ; literal HELLO-commit-to-client-Finished interval.
    mov ax, sym_phase_sector
%ifdef POC_DELTA_PRELOAD
    mov cl, POC_SYM_RESTORE_SECTORS
%else
    mov cl, sym_phase_sectors
%endif
    mov bx, poc_k_start
    call load_phase
    jc disk_fail
%ifdef TLS13_POC_K14
    ; Install K14's extension controller before symmetric initialization.  Its
    ; padded sector also clears the extension-resident runtime tail.
    mov ax, sym_controller_sector
    mov cl, sym_controller_sectors
    mov bx, sym_controller_entry
    call load_phase
    jc disk_fail
%endif
    call word [poc_k_start + 32]
    jc sym_fail
    ; Candidate K' is preserved below the receive frame.  Entry 15 imports the
    ; HELLO server share, committed digest, and exact live transcript context.
    mov si, poc_low_scratch_start + 32
    mov di, 0x3600
    mov cx, 16
    rep movsw
    call word [poc_k_start + 32 + (15 * 2)]
    jc sym_fail

%ifndef TLS13_POC_K14
    ; K15 retains the controller in the low HELLO handoff.  Install it only
    ; after transcript import has consumed and invalidated that handoff.
    mov ax, sym_controller_sector
    mov cl, sym_controller_sectors
    mov bx, sym_controller_entry
    call load_phase
    jc disk_fail
%endif
    call sym_controller_entry
    jc sym_fail
    push ax
    ; Timestamp before any oracle comparison: entry 9 has just constructed the
    ; 58-byte encrypted client Finished at the fixed symmetric IO address.
    call read_tick
    sub ax, [cf_tick_start_low]
    mov [tick_delta], ax
    pop ax
    cmp ax, POC_SYM_CLIENT_FINISHED_BYTES
    jne sym_fail

    mov ax, sym_client_finished_fixture_sector
    mov cl, sym_client_finished_fixture_sectors
    mov bx, 0x0e00
    call load_phase
    jc disk_fail
    mov si, 0x39a0
    mov di, 0x0e00
    mov cx, POC_SYM_CLIENT_FINISHED_BYTES
    repe cmpsb
    jne sym_fail
    call verify_product_sentinels
    or ax, ax
    jz sentinel_fail
    mov si, cf_pass
    mov ax, [tick_delta]
    call emit_str
    call emit_dec16
    call emit_crlf

%ifdef POC_INCLUDE_CANDIDATE
    ; The protected-flight controller stages at 0e00, so the low live
    ; candidate handoff remains available for the offline FO proof.
    mov si, poc_low_scratch_start
    mov di, poc_tls_vault_start
    mov cx, 16
    rep movsw
    mov si, poc_low_scratch_start + 32
    mov di, poc_candidate_g
    mov cx, 48
    rep movsw
%endif
%endif

%ifdef POC_INCLUDE_FO
    mov si, fo_begin
    call emit_phase
    mov ax, fo_phase_sector
    mov cl, fo_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc disk_fail
    call end_load_timing
    call fo_controller_entry
    jc fo_fail
    mov [tick_delta], ax
    mov byte [quarantine_state], 1
    mov si, fo_pass
    mov ax, [tick_delta]
    call emit_result
%endif

%ifdef POC_INCLUDE_AUTH
    ; The fixture is cold data, not resident state.  Stage it below the packet
    ; buffer, copy it into the authentication ABI, then replace KeyGen in K.
    cmp byte [quarantine_state], 1
    jne auth_fail
    mov si, auth_begin
    call emit_phase
    mov ax, auth_fixture_sector
    mov cl, auth_fixture_sectors
    mov bx, poc_low_scratch_start
    call load_phase
    jc disk_fail
    mov si, poc_low_scratch_start
    mov di, 0x3ba4
    mov cx, 170 / 2
    rep movsw

    mov ax, auth_phase_sector
    mov cl, auth_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc disk_fail
    call end_load_timing
    call wait_tick_edge
    call read_tick
    mov [tick_start], ax
    call word [poc_k_start]
    jc auth_fail
    cmp ax, 1
    jne auth_fail
    call read_tick
    sub ax, [tick_start]
    mov [tick_delta], ax
    call verify_product_sentinels
    or ax, ax
    jz sentinel_fail
    mov byte [quarantine_state], 2
    mov si, auth_pass
    mov ax, [tick_delta]
    call emit_result
%endif

%ifdef POC_INCLUDE_AUTH
    cmp byte [quarantine_state], 2
    jne auth_fail
%endif
    mov si, pass_text
    call emit_str
    call emit_crlf
    mov si, result_text
    call emit_str
    call emit_crlf
.halt:
    hlt
    jmp .halt

disk_fail:
    mov si, disk_fail_text
    jmp fail
crypto_fail:
    mov si, crypto_fail_text
    jmp fail
sentinel_fail:
    mov si, sentinel_fail_text
    jmp short fail
%ifdef POC_INCLUDE_ENTROPY
entropy_fail:
    mov si, entropy_fail_text
    jmp short fail
%endif
%ifdef POC_INCLUDE_HELLO
hello_fail:
    mov si, hello_fail_text
    jmp short fail
%endif
%ifdef POC_INCLUDE_FO
fo_fail:
    mov si, fo_fail_text
    jmp short fail
%endif
%ifdef POC_INCLUDE_AUTH
auth_fail:
    mov si, auth_fail_text
    jmp short fail
%endif
%ifdef POC_INCLUDE_CANDIDATE
candidate_fail:
    mov si, candidate_fail_text
    jmp short fail
%endif
%ifdef POC_INCLUDE_SYM
sym_fail:
    mov si, sym_fail_text
%endif
fail:
    call emit_str
    call emit_crlf
    mov si, fail_text
    call emit_str
    call emit_crlf
    mov si, result_text
    call emit_str
    call emit_crlf
    jmp start.halt

; The following source-shaped runners are retained as readable ABI reference,
; but executable harness builds use the cold composite controllers above.
%if 0
%ifdef POC_INCLUDE_ENTROPY
run_entropy_phase:
    mov si, entropy_begin
    call emit_phase
    mov ax, entropy_phase_sector
    mov cl, entropy_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc .failed
    call end_load_timing

    mov ax, entropy_slots_fixture_sector
    mov cl, entropy_slots_fixture_sectors
    mov bx, 0x0700
    call load_phase
    jc .failed
    mov ax, entropy_meta_fixture_sector
    mov cl, entropy_meta_fixture_sectors
    mov bx, 0x0b80
    call load_phase
    jc .failed

    call wait_tick_edge
    call read_tick
    mov [tick_start], ax
    call word [entropy_entry_table]
    jc .failed
    call word [entropy_entry_table + 2]
    jc .failed

    ; Exercise the target PIT/BDA collector ABI, but assign it no entropy
    ; credit in this exact deterministic oracle run.
    call word [entropy_entry_table + 8]
    jc .failed
    call word [entropy_entry_table + 4]
    jc .failed
    mov si, 0x0b82
    mov cx, POC_ENTROPY_SUPPLEMENT_LEN
    call word [entropy_entry_table + 6]
    jc .failed
    call word [entropy_entry_table + 10]
    jc .failed
    cmp ax, POC_ENTROPY_TARGET_SLOT
    jne .failed
    mov [entropy_target], al

    ; Write the alternate ratchet slot on the disposable PoC floppy, then
    ; physically reread it before the overlay may publish d||z.
    xor bx, bx
    mov bl, [entropy_target]
    mov ax, entropy_slots_fixture_sector
    add ax, bx
    add ax, core_start_lba
    mov cl, 1
    mov bx, 0x0c00
    call write_abs_sectors
    jc .failed
    xor bx, bx
    mov bl, [entropy_target]
    mov ax, entropy_slots_fixture_sector
    add ax, bx
    mov cl, 1
    mov bx, 0x0e00
    call load_phase
    jc .failed
    call word [entropy_entry_table + 12]
    jc .failed
    call word [entropy_entry_table + 14]
    jc .failed
    cmp si, 0x3660
    jne .failed
    cmp cx, 64
    jne .failed
    mov di, poc_attempt_cache_start
    mov cx, 32
    rep movsw
    call read_tick
    sub ax, [tick_start]
    mov [tick_delta], ax

    ; Exact host-oracle record and d||z comparisons happen after the timed
    ; durable path and before KeyGen can consume the attempt.
    mov ax, entropy_record_fixture_sector
    mov cl, entropy_record_fixture_sectors
    mov bx, 0x0700
    call load_phase
    jc .failed
    mov si, 0x0c00
    mov di, 0x0700
    mov cx, 512
    repe cmpsb
    jne .failed
    mov ax, entropy_meta_fixture_sector
    mov cl, entropy_meta_fixture_sectors
    mov bx, 0x0700
    call load_phase
    jc .failed
    mov si, poc_attempt_cache_start
    mov di, 0x0700 + 2 + 96
    mov cx, 64
    repe cmpsb
    jne .failed
    call verify_product_sentinels
    or ax, ax
    jz .failed

    mov si, entropy_pass
    call emit_str
    mov ax, [tick_delta]
    call emit_dec16
    mov si, sectors_text
    call emit_str
    mov ax, entropy_phase_sectors
    call emit_dec16
    call emit_load_ticks
    call emit_crlf
    clc
    ret
.failed:
    stc
    ret
%endif

%ifdef POC_INCLUDE_HELLO
run_hello_phase:
    mov si, hello_begin
    call emit_phase
    mov ax, hello_phase_sector
    mov cl, hello_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc .failed
    call end_load_timing
    mov ax, hello_inputs_fixture_sector
    mov cl, hello_inputs_fixture_sectors
    mov bx, 0x0e00
    call load_phase
    jc .failed

    mov si, 0x0e00
    mov di, poc_attempt_cache_start
    mov cx, 102
    rep movsb
    mov si, 0x0e00 + 102
    mov di, poc_ticket_identity
    mov cx, 192
    rep movsb

    call wait_tick_edge
    call read_tick
    mov [tick_start], ax
    call word [hello_entry_table + 2]
    jc .failed
    mov ax, hello_resumed_fixture_sector
    mov dl, POC_HELLO_RESUMED_CHUNKS
    call hello_verify_client
    jc .failed
    call word [hello_entry_table]
    jc .failed
    mov ax, hello_fresh_fixture_sector
    mov dl, POC_HELLO_FRESH_CHUNKS
    call hello_verify_client
    jc .failed
    call word [hello_entry_table + 10]
    jc .failed
    mov ax, hello_server_fixture_sector
    mov dl, POC_HELLO_SERVER_CHUNKS
    call hello_feed_server
    jc .failed
    call word [hello_entry_table + 14]
    jc .failed
    cmp byte [0x3c42], 1
    jne .failed
    call read_tick
    sub ax, [tick_start]
    mov [tick_delta], ax

    mov ax, hello_inputs_fixture_sector
    mov cl, hello_inputs_fixture_sectors
    mov bx, 0x0e00
    call load_phase
    jc .failed
    mov si, poc_attempt_cache_start
    mov di, 0x0e00 + 294
    mov cx, 64
    repe cmpsb
    jne .failed
    call verify_product_sentinels
    or ax, ax
    jz .failed
    mov si, hello_pass
    call emit_str
    mov ax, [tick_delta]
    call emit_dec16
    mov si, sectors_text
    call emit_str
    mov ax, hello_phase_sectors
    call emit_dec16
    call emit_load_ticks
    call emit_crlf
    clc
    ret
.failed:
    stc
    ret

; AX=first fixture sector, DL=exact fragment count.
hello_verify_client:
    mov [hello_fixture_next], ax
    mov [hello_chunks_left], dl
.next:
    call word [hello_entry_table + 4]
    jc .failed
    or ax, ax
    jz .finished
    cmp ax, 1
    jne .failed
    cmp byte [hello_chunks_left], 0
    je .failed
    mov [hello_fragment_ptr], si
    mov [hello_fragment_len], cx
    mov ax, [hello_fixture_next]
    mov cl, 1
    mov bx, 0x0e00
    call load_phase
    jc .failed
    mov cx, [hello_fragment_len]
    cmp cx, [0x0e00]
    jne .failed
    mov si, [hello_fragment_ptr]
    mov di, 0x0e02
    repe cmpsb
    jne .failed
    call word [hello_entry_table + 6]
    jc .failed
    inc word [hello_fixture_next]
    dec byte [hello_chunks_left]
    jmp short .next
.finished:
    cmp byte [hello_chunks_left], 0
    jne .failed
    clc
    ret
.failed:
    stc
    ret

; AX=first fixture sector, DL=chunk count.  Each sector begins with a native
; length word followed by one ServerHello handshake fragment.
hello_feed_server:
    mov [hello_fixture_next], ax
    mov [hello_chunks_left], dl
.next:
    cmp byte [hello_chunks_left], 0
    je .done
    mov ax, [hello_fixture_next]
    mov cl, 1
    mov bx, 0x0e00
    call load_phase
    jc .failed
    mov si, 0x0e02
    mov cx, [0x0e00]
    call word [hello_entry_table + 12]
    jc .failed
    inc word [hello_fixture_next]
    dec byte [hello_chunks_left]
    jmp short .next
.done:
    clc
    ret
.failed:
    stc
    ret
%endif

%ifdef POC_INCLUDE_FO
run_fo_phase:
    mov si, fo_begin
    call emit_phase
    mov ax, fo_phase_sector
    mov cl, fo_phase_sectors
    mov bx, poc_k_start
    call begin_load_timing
    call load_phase
    jc .failed
    call end_load_timing
    mov byte [fo_read_index], 0
    call wait_tick_edge
    call read_tick
    mov [tick_start], ax
    mov bx, fo_read_callback
    call poc_k_start
    jc .failed
    cmp ax, 1
    jne .failed
    cmp byte [fo_read_index], POC_FO_REQUESTS
    jne .failed
    call read_tick
    sub ax, [tick_start]
    mov [tick_delta], ax
    mov ax, fo_expected_fixture_sector
    mov cl, fo_expected_fixture_sectors
    mov bx, poc_low_scratch_start
    call load_phase
    jc .failed
    mov si, poc_candidate_g
    mov di, poc_low_scratch_start
    mov cx, 32
    repe cmpsb
    jne .failed
    call verify_product_sentinels
    or ax, ax
    jz .failed
    mov byte [quarantine_state], 1
    mov si, fo_pass
    call emit_str
    mov ax, [tick_delta]
    call emit_dec16
    mov si, sectors_text
    call emit_str
    mov ax, fo_phase_sectors
    call emit_dec16
    call emit_load_ticks
    call emit_crlf
    clc
    ret
.failed:
    stc
    ret

; Strict public-object callback for the FO overlay.  Each cold sector carries
; object-id/offset/count plus the exact oracle bytes for one ABI request.
fo_read_callback:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    push es
    mov [fo_req_object], al
    mov [fo_req_offset], dx
    mov [fo_req_count], cx
    mov [fo_req_destination], di
    xor bx, bx
    mov bl, [fo_read_index]
    cmp bl, POC_FO_REQUESTS
    jae .failed
    mov ax, fo_stream_fixture_sector
    add ax, bx
    mov cl, fo_stream_stage_sectors
    mov bx, fo_stream_stage
    call load_phase
    jc .failed
    mov al, [fo_req_object]
    cmp al, [fo_stream_stage]
    jne .failed
    mov ax, [fo_req_offset]
    cmp ax, [fo_stream_stage + 1]
    jne .failed
    mov cx, [fo_req_count]
    cmp cx, [fo_stream_stage + 3]
    jne .failed
    mov si, fo_stream_stage + 5
    mov di, [fo_req_destination]
    rep movsb
    inc byte [fo_read_index]
    clc
    jmp short .restore
.failed:
    stc
.restore:
    pop es
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret
%endif

%endif
; AX = zero-based sector offset within this phase container, CL = count,
; BX = destination.  The harness file is the first contiguous FAT data file,
; which is the same invariant used by Seed's resident phase loader.
load_phase:
    xor ch, ch
    mov bp, cx
    add ax, core_start_lba
.next:
    ; AL/track division gives the number of sectors left before the next
    ; eight-sector 160 KiB track.  Read the largest legal contiguous batch.
    push ax
    mov dl, floppy_sectors_per_track
    div dl
    mov dl, floppy_sectors_per_track
    sub dl, ah
    xor ch, ch
    mov cl, dl
    cmp cx, bp
    jbe .batch_ready
    mov cx, bp
.batch_ready:
    pop ax
    push cx
    call read_abs_sectors
    pop cx
    jc .failed
    add ax, cx
    sub bp, cx
    push cx
    mov dx, cx
    mov cl, 9
    shl dx, cl
    add bx, dx
    pop cx
    or bp, bp
    jnz .next
    clc
    ret
.failed:
    stc
    ret

%ifdef POC_COMPARE_LOADERS
load_phase_legacy:
    xor ch, ch
    mov bp, cx
    add ax, core_start_lba
.next:
    mov cl, 1
    call read_abs_sectors
    jc .failed
    inc ax
    add bx, sector_size
    dec bp
    jnz .next
    clc
    ret
.failed:
    stc
    ret
%endif

; AX = absolute LBA, CL = count within one track, ES:BX = destination.
; The retry repeats the whole batch after a controller reset.
read_abs_sectors:
    push ax
    push bx
    push cx
    push dx
    push si
    mov si, ax
    mov [read_count], cl
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
    mov al, [read_count]
    mov ah, 0x02
    int 0x13
    jnc .ok
    xor ax, ax
    mov dl, [boot_drive]
    int 0x13
    dec byte [read_attempts]
    jnz .retry
    mov byte [read_status], 1
    jmp short .restore
.ok:
    mov byte [read_status], 0
.restore:
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    cmp byte [read_status], 0
    je .success
    stc
    ret
.success:
    clc
    ret

; Same geometry and retry policy for the disposable ratchet-slot write.
write_abs_sectors:
    push ax
    push bx
    push cx
    push dx
    push si
    mov si, ax
    mov [read_count], cl
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
    mov al, [read_count]
    mov ah, 0x03
    int 0x13
    jnc .ok
    xor ax, ax
    mov dl, [boot_drive]
    int 0x13
    dec byte [read_attempts]
    jnz .retry
    mov byte [read_status], 1
    jmp short .restore
.ok:
    mov byte [read_status], 0
.restore:
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    cmp byte [read_status], 0
    je .success
    stc
    ret
.success:
    clc
    ret

disk_reset:
    push ax
    push dx
    xor ax, ax
    mov dl, [boot_drive]
    int 0x13
    pop dx
    pop ax
    ret

%if 0
; Legacy resident KeyGen verifier; secure-chain builds use the cold controller.
verify_keygen:
    xor dx, dx
    mov si, poc_s_hat0
    mov cx, poc_s_hat0_len / 2
    call checksum_words
    mov si, poc_s_hat1
    mov cx, poc_s_hat1_len / 2
    call checksum_words
    mov si, poc_s_hat2
    mov cx, poc_s_hat2_len / 2
    call checksum_words
    mov si, poc_mlkem_ek
    mov cx, poc_mlkem_ek_len / 2
    call checksum_words
    mov si, poc_h_ek
    mov cx, poc_h_ek_len / 2
    call checksum_words
    mov si, poc_z
    mov cx, poc_z_len / 2
    call checksum_words
    xor ax, ax
    cmp dx, POC_KEYGEN_CHECKSUM
    jne .done
    inc ax
.done:
    ret

checksum_words:
.next:
    add dx, [si]
    add si, 2
    loop .next
    ret
%endif

verify_product_sentinels:
    mov si, poc_reconnect_state_start
    mov cx, (poc_stack_guard_start - poc_reconnect_state_start) / 2
.next:
    cmp word [si], 0xa5a5
    jne .bad
    add si, 2
    loop .next
    mov si, poc_nic_driver_slot
    mov cx, (poc_k_start - poc_nic_driver_slot) / 2
.driver:
    cmp word [si], 0
    jne .bad
    add si, 2
    loop .driver
    mov ax, 1
    ret
.bad:
    xor ax, ax
    ret

wait_tick_edge:
    mov bx, [0x046c]
.wait:
    mov ax, [0x046c]
    cmp ax, bx
    je .wait
    ret

read_tick:
    mov ax, [0x046c]
    ret

begin_load_timing:
    push ax
    push bx
    call wait_tick_edge
    call read_tick
    mov [load_tick_start], ax
    pop bx
    pop ax
    ret

end_load_timing:
    push ax
    call read_tick
    sub ax, [load_tick_start]
    mov [load_tick_delta], ax
    pop ax
    ret

emit_load_ticks:
    push ax
    push si
    mov si, load_text
    call emit_str
    mov ax, [load_tick_delta]
    call emit_dec16
    pop si
    pop ax
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
    ; VGA progress is authoritative.  Serial telemetry must never be able to
    ; strand the harness before the first visible phase marker.
    push ax
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    pop cx
    mov ah, cl
    ; CX is now 0x01xx, so an absent/stuck UART costs at most 511 polls.
    mov ch, 1
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jnz .ready
    loop .wait
    jmp short .done
.ready:
    mov dx, 0x3f8
    mov al, ah
    out dx, al
.done:
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

emit_phase:
    call emit_str
    jmp emit_crlf

; SI=result prefix, AX=compute ticks; appends the most recent phase-load ticks.
emit_result:
    call emit_str
    call emit_dec16
    call emit_load_ticks
    jmp emit_crlf

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

%ifndef POC_INCLUDE_ENTROPY
fixture_d_z:
    db 0xa0,0x10,0x8d,0x8d,0x49,0x51,0x5e,0x7e,0x24,0x86,0x42,0x16,0xb5,0x0d,0xa8,0x61
    db 0x34,0xf4,0x24,0x8c,0x74,0xe4,0xdc,0xd1,0xde,0xc4,0x1d,0xd1,0x96,0x98,0x51,0x89
    db 0x33,0xe6,0x76,0x73,0xf1,0x58,0xec,0xbe,0x40,0x1e,0x56,0x3c,0x96,0x73,0x43,0xa3
    db 0xc4,0x88,0xb0,0xd2,0x1f,0x7c,0x04,0x8e,0x10,0xaf,0x2c,0x74,0x61,0xc4,0xc8,0x4e
%endif

start_text        db 'TLS13 POC', 0
keygen_begin      db 'KG...', 0
keygen_pass       db 'KG t=', 0
%ifdef POC_DELTA_PRELOAD
preload_begin     db 'PRE...', 0
preload_pass      db 'PRE l=', 0
%endif
%ifdef POC_COMPARE_LOADERS
io_begin          db 'IO COMPARE...', 0
io_pass           db 'IO PASS old=', 0
batch_text        db ' batch=', 0
%endif
%ifdef POC_INCLUDE_ENTROPY
entropy_begin     db 'ENT[D]...', 0
entropy_pass      db 'ENT t=', 0
entropy_fail_text db 'ENT!', 0
%endif
%ifdef POC_INCLUDE_HELLO
hello_begin       db 'HEL...', 0
hello_fail_text   db 'HEL!', 0
%endif
%ifdef POC_INCLUDE_CANDIDATE
candidate_fail_text db 'KD!', 0
%endif
%ifdef POC_INCLUDE_SYM
cf_pass           db 'CF t=', 0
sym_fail_text     db 'SYM!', 0
%endif
%ifdef POC_INCLUDE_FO
fo_begin          db 'FO...', 0
fo_pass           db 'FO t=', 0
fo_fail_text      db 'FO!', 0
%endif
%ifdef POC_INCLUDE_AUTH
auth_begin        db 'AU...', 0
auth_pass         db 'AU t=', 0
auth_fail_text    db 'AU!', 0
%endif
load_text         db ' load=', 0
write_text        db ' w=', 0
read_text         db ' r=', 0
disk_fail_text    db 'DISK FAIL', 0
crypto_fail_text  db 'KG FAIL', 0
sentinel_fail_text db 'SENTINEL FAIL', 0
pass_text         db 'PASS', 0
fail_text         db 'FAIL', 0
result_text       db 'RESULT', 0

boot_drive db 0
read_attempts db 0
read_count db 0
read_status db 0
tick_start dw 0
tick_delta dw 0
load_tick_start dw 0
load_tick_delta dw 0
quarantine_state db 0
%ifdef POC_COMPARE_LOADERS
legacy_load_ticks dw 0
%endif
%ifdef POC_INCLUDE_ENTROPY
entropy_write_ticks dw 0
entropy_read_ticks dw 0
%endif

%if ($ - $$) > (poc_nic_driver_slot - poc_resident_start)
%error "TLS13 PoC resident scheduler exceeds the shared three-sector nucleus"
%endif
times (poc_nic_driver_slot - poc_resident_start) - ($ - $$) db 0
times (poc_k_start - poc_nic_driver_slot) db 0
resident_end:

%if (resident_end - $$) != resident_sectors * sector_size
%error "TLS13 PoC resident prefix must remain four sectors"
%endif

%macro align_floppy_track 0
align 512, db 0
times ((-(core_start_lba + (($ - $$) / sector_size))) & 7) * sector_size db 0
%endmacro

%ifdef POC_INCLUDE_ENTROPY
entropy_slots_fixture_start:
incbin "build/crypto-bench/tls13-poc/entropy_slots_fixture.bin"
entropy_slots_fixture_content_end:
align 512, db 0
entropy_slots_fixture_end:

entropy_slots_fixture_sector equ (entropy_slots_fixture_start - $$) / sector_size
entropy_slots_fixture_sectors equ (entropy_slots_fixture_end - entropy_slots_fixture_start) / sector_size

entropy_meta_fixture_start:
incbin "build/crypto-bench/tls13-poc/entropy_meta_fixture.bin"
entropy_meta_fixture_content_end:
align 512, db 0
entropy_meta_fixture_end:

entropy_meta_fixture_sector equ (entropy_meta_fixture_start - $$) / sector_size
entropy_meta_fixture_sectors equ (entropy_meta_fixture_end - entropy_meta_fixture_start) / sector_size

entropy_record_fixture_start:
incbin "build/crypto-bench/tls13-poc/entropy_record_fixture.bin"
entropy_record_fixture_content_end:
align 512, db 0
entropy_record_fixture_end:

entropy_record_fixture_sector equ (entropy_record_fixture_start - $$) / sector_size
entropy_record_fixture_sectors equ (entropy_record_fixture_end - entropy_record_fixture_start) / sector_size

align_floppy_track
entropy_phase_start:
incbin "build/crypto-bench/tls13-poc/entropy_ratchet_composite.bin"
entropy_phase_content_end:
align 512, db 0
entropy_phase_end:

entropy_phase_sector equ (entropy_phase_start - $$) / sector_size
entropy_phase_sectors equ (entropy_phase_end - entropy_phase_start) / sector_size
%endif

align 512, db 0
align_floppy_track
keygen_phase_start:
incbin "build/crypto-bench/tls13-poc/keygen_composite.bin"
keygen_phase_content_end:
align 512, db 0
keygen_phase_end:

keygen_phase_sector  equ (keygen_phase_start - $$) / sector_size
keygen_phase_sectors equ (keygen_phase_end - keygen_phase_start) / sector_size

%ifdef POC_INCLUDE_HELLO
hello_inputs_fixture_start:
incbin "build/crypto-bench/tls13-poc/hello_inputs_fixture.bin"
hello_inputs_fixture_content_end:
align 512, db 0
hello_inputs_fixture_end:

hello_inputs_fixture_sector equ (hello_inputs_fixture_start - $$) / sector_size
hello_inputs_fixture_sectors equ (hello_inputs_fixture_end - hello_inputs_fixture_start) / sector_size

hello_controller_start:
incbin "build/crypto-bench/tls13-poc/hello_controller.bin"
hello_controller_content_end:
align 512, db 0
hello_controller_end:

hello_controller_sector equ (hello_controller_start - $$) / sector_size
hello_controller_sectors equ (hello_controller_end - hello_controller_start) / sector_size

align_floppy_track
hello_resumed_fixture_start:
incbin "build/crypto-bench/tls13-poc/hello_resumed_fixture.bin"
hello_resumed_fixture_content_end:
align 512, db 0
hello_resumed_fixture_end:

hello_resumed_fixture_sector equ (hello_resumed_fixture_start - $$) / sector_size
hello_resumed_fixture_sectors equ (hello_resumed_fixture_end - hello_resumed_fixture_start) / sector_size

align_floppy_track
hello_fresh_fixture_start:
incbin "build/crypto-bench/tls13-poc/hello_fresh_fixture.bin"
hello_fresh_fixture_content_end:
align 512, db 0
hello_fresh_fixture_end:

hello_fresh_fixture_sector equ (hello_fresh_fixture_start - $$) / sector_size
hello_fresh_fixture_sectors equ (hello_fresh_fixture_end - hello_fresh_fixture_start) / sector_size

hello_server_fixture_start:
incbin "build/crypto-bench/tls13-poc/hello_server_fixture.bin"
hello_server_fixture_content_end:
align 512, db 0
hello_server_fixture_end:

hello_server_fixture_sector equ (hello_server_fixture_start - $$) / sector_size
hello_server_fixture_sectors equ (hello_server_fixture_end - hello_server_fixture_start) / sector_size

align_floppy_track
hello_phase_start:
incbin "build/crypto-bench/tls13-poc/hello_overlay.bin"
hello_phase_content_end:
align 512, db 0
hello_phase_end:

hello_phase_sector equ (hello_phase_start - $$) / sector_size
hello_phase_sectors equ (hello_phase_end - hello_phase_start) / sector_size
%endif

%ifdef POC_INCLUDE_CANDIDATE
candidate_fixture_start:
incbin "build/crypto-bench/tls13-poc/candidate_fixture.bin"
candidate_fixture_content_end:
align 512, db 0
candidate_fixture_end:

candidate_fixture_sector  equ (candidate_fixture_start - $$) / sector_size
candidate_fixture_sectors equ (candidate_fixture_end - candidate_fixture_start) / sector_size

align_floppy_track
candidate_phase_start:
incbin "build/crypto-bench/tls13-poc/mlkem_candidate_composite.bin"
candidate_phase_content_end:
align 512, db 0
candidate_phase_end:

candidate_phase_sector  equ (candidate_phase_start - $$) / sector_size
candidate_phase_sectors equ (candidate_phase_end - candidate_phase_start) / sector_size
%endif

%ifdef POC_INCLUDE_AUTH
auth_fixture_start:
incbin "build/crypto-bench/tls13-poc/auth_fixture.bin"
auth_fixture_content_end:
align 512, db 0
auth_fixture_end:

auth_fixture_sector  equ (auth_fixture_start - $$) / sector_size
auth_fixture_sectors equ (auth_fixture_end - auth_fixture_start) / sector_size

align_floppy_track
auth_phase_start:
incbin "build/crypto-bench/tls13-poc/auth_p256_overlay.bin"
auth_phase_content_end:
align 512, db 0
auth_phase_end:

auth_phase_sector  equ (auth_phase_start - $$) / sector_size
auth_phase_sectors equ (auth_phase_end - auth_phase_start) / sector_size
%endif

%ifdef POC_INCLUDE_SYM
sym_controller_start:
incbin "build/crypto-bench/tls13-poc/sym_controller.bin"
sym_controller_content_end:
align 512, db 0
sym_controller_end:

sym_controller_sector  equ (sym_controller_start - $$) / sector_size
sym_controller_sectors equ (sym_controller_end - sym_controller_start) / sector_size

sym_flight_meta_fixture_start:
incbin "build/crypto-bench/tls13-poc/sym_flight_meta_fixture.bin"
sym_flight_meta_fixture_content_end:
align 512, db 0
sym_flight_meta_fixture_end:

sym_flight_meta_fixture_sector equ \
    (sym_flight_meta_fixture_start - $$) / sector_size

sym_flight_cipher_fixture_start:
incbin "build/crypto-bench/tls13-poc/sym_flight_cipher_fixture.bin"
sym_flight_cipher_fixture_content_end:
align 512, db 0
sym_flight_cipher_fixture_end:

sym_flight_cipher_fixture_sector equ \
    (sym_flight_cipher_fixture_start - $$) / sector_size

sym_client_finished_fixture_start:
incbin "build/crypto-bench/tls13-poc/sym_client_finished_fixture.bin"
sym_client_finished_fixture_content_end:
align 512, db 0
sym_client_finished_fixture_end:

sym_client_finished_fixture_sector equ \
    (sym_client_finished_fixture_start - $$) / sector_size
sym_client_finished_fixture_sectors equ \
    (sym_client_finished_fixture_end - sym_client_finished_fixture_start) / sector_size

align_floppy_track
sym_phase_start:
incbin "build/crypto-bench/tls13-poc/tls13_sym_overlay.bin"
sym_phase_content_end:
align 512, db 0
sym_phase_end:

sym_phase_sector  equ (sym_phase_start - $$) / sector_size
sym_phase_sectors equ (sym_phase_end - sym_phase_start) / sector_size
%endif

%ifdef POC_INCLUDE_FO
align_floppy_track
fo_stream_fixture_start:
incbin "build/crypto-bench/tls13-poc/fo_stream_fixture.bin"
fo_stream_fixture_content_end:
align 512, db 0
fo_stream_fixture_end:

fo_stream_fixture_sector equ (fo_stream_fixture_start - $$) / sector_size
fo_stream_fixture_sectors equ (fo_stream_fixture_end - fo_stream_fixture_start) / sector_size

fo_expected_fixture_start:
incbin "build/crypto-bench/tls13-poc/fo_expected_fixture.bin"
fo_expected_fixture_content_end:
align 512, db 0
fo_expected_fixture_end:

fo_expected_fixture_sector equ (fo_expected_fixture_start - $$) / sector_size
fo_expected_fixture_sectors equ (fo_expected_fixture_end - fo_expected_fixture_start) / sector_size

align_floppy_track
fo_phase_start:
incbin "build/crypto-bench/tls13-poc/fo_tail_composite.bin"
fo_phase_content_end:
align 512, db 0
fo_phase_end:

fo_phase_sector equ (fo_phase_start - $$) / sector_size
fo_phase_sectors equ (fo_phase_end - fo_phase_start) / sector_size
%endif

image_end:
%endif
