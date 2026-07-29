; Literal 16 KiB / 4.77 MHz read-only issuer-authentication and commit PoC.
;
; ROM BASIC loads only the four-sector prefix. All cryptographic images,
; public fixtures, and the final canary remain cold in the same contiguous
; floppy file. Every media operation is BIOS read (AH=02) or reset (AH=00);
; this source intentionally contains no write service.

bits 16
cpu 8086
org 0x1000

%include "build/crypto-bench/tls13-read-only-auth/fixture_meta.inc"

sector_size              equ 512
core_start_lba           equ 11
floppy_sectors_per_track equ 8
resident_sectors         equ 4

resident_start           equ 0x1000
driver_slot_start        equ 0x1600
overlay_base             equ 0x1800
issuer_input_start       equ 0x3400
issuer_input_end         equ 0x34af
issuer_commit_start      equ 0x3600
issuer_commit_end        equ 0x3672
ticket_psk               equ 0x38b0
ticket_psk_bytes         equ 32
ticket_state             equ 0x3b40
ticket_state_bytes       equ 237
ticket_present           equ 0x3c2c
gate_control_start       equ 0x3c30
credential_checksum     equ 0x3c40
credential_length       equ 0x3c42
credential_status_inverse equ 0x3c44
credential_status       equ 0x3c45
credential_publication_end equ 0x3c46
reconnect_start          equ 0x3c9c
esc_start                equ 0x3de6
product_pool_start       equ 0x3e40
canary_destination       equ 0x3400
canary_bytes             equ 32
credential_key_max       equ 192
credential_capacity      equ credential_key_max + 1
stack_guard              equ 0x3f00
stack_top                equ 0x3ff0

issuer_leaf_entry        equ overlay_base
issuer_cv_entry          equ overlay_base + 2
gate_entry_table         equ overlay_base + 8
gate_commit_entry        equ gate_entry_table
gate_unlock_entry        equ gate_entry_table + 2
gate_abort_entry         equ gate_entry_table + 4
gate_authorize_entry     equ gate_entry_table + 6
gate_route               equ 0x3c3c
gate_route_inverse       equ 0x3c3d
gate_state_inverse       equ 0x3c3e
gate_state               equ 0x3c3f
gate_control_end         equ 0x3c40
gate_route_live_ticket   equ 2
credential_loader_callback equ 0x1580

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

    ; Regions outside the explicitly borrowed security/control slots retain a
    ; fixed sentinel across both long authentication passes and the gate.
    mov ax, 0xa5a5
    mov di, driver_slot_start
    mov cx, (overlay_base - driver_slot_start) / 2
    rep stosw
    mov di, reconnect_start
    mov cx, (product_pool_start - reconnect_start) / 2
    rep stosw
    mov di, canary_destination
    mov cx, credential_capacity
    xor ax, ax
    rep stosb
    mov di, gate_control_start
    mov cx, (credential_publication_end - gate_control_start) / 2
    rep stosw
    mov ax, 0xa5a5
    mov di, product_pool_start
    mov cx, (stack_guard - product_pool_start) / 2
    rep stosw

    mov si, start_text
    call emit_str
    call emit_crlf

    ; Prove at runtime that a disk-write request is rejected by the sole BIOS
    ; wrapper before the only INT 13h opcode can execute.
    mov ah, 0x03
    call bios_disk_interrupt
    jnc disk_policy_fail
    cmp byte [bios_blocked_functions], 1
    jne disk_policy_fail

    ; The complete tentative ticket is staged once in native symmetric slots.
    mov ax, ticket_fixture_sector
    mov bx, 0x0700
    call read_container_sector
    jc disk_fail
    mov si, 0x0700
    mov di, ticket_psk
    mov cx, ticket_psk_bytes / 2
    rep movsw
    mov si, 0x0700 + ticket_psk_bytes
    mov di, ticket_state
    mov cx, ticket_state_bytes
    rep movsb
    call verify_ticket
    jc ticket_fail

    ; Pass 1: load the exact 14-sector image, then populate the extension ABI.
    mov ax, issuer_phase_sector
    mov cl, issuer_phase_sectors
    mov bx, overlay_base
    call load_phase
    jc disk_fail
    mov ax, issuer_leaf_fixture_sector
    mov bx, issuer_input_start
    call read_container_sector
    jc disk_fail
    call wait_tick_edge
    mov ax, [0x046c]
    mov [tick_start], ax
    call word [issuer_leaf_entry]
    jc auth1_fail
    cmp ax, 1
    jne auth1_fail
    mov ax, [0x046c]
    sub ax, [tick_start]
    mov [auth1_ticks], ax
    call verify_ticket
    jc ticket_fail
    call verify_sentinels
    jc sentinel_fail
    mov si, auth1_text
    mov ax, [auth1_ticks]
    call emit_timing

    ; Pass 2 reload ends exactly at 0x3400, preserving both high handoffs.
    mov ax, issuer_phase_sector
    mov cl, issuer_phase_sectors
    mov bx, overlay_base
    call load_phase
    jc disk_fail
    mov ax, issuer_cv_fixture_sector
    mov bx, issuer_input_start
    call read_container_sector
    jc disk_fail
    call wait_tick_edge
    mov ax, [0x046c]
    mov [tick_start], ax
    call word [issuer_cv_entry]
    jc auth2_fail
    cmp ax, 1
    jne auth2_fail
    mov ax, [0x046c]
    sub ax, [tick_start]
    mov [auth2_ticks], ax
    call verify_ticket
    jc ticket_fail
    call verify_sentinels
    jc sentinel_fail
    mov si, auth2_text
    mov ax, [auth2_ticks]
    call emit_timing

    ; Replace authentication code with the two-sector atomic gate. The canary
    ; is still absent and the product arena/context remains zero here.
    mov ax, gate_phase_sector
    mov cl, gate_phase_sectors
    mov bx, overlay_base
    call load_phase
    jc disk_fail

    ; Reproduce the old direct-callback bypass attempt: forge only the public
    ; route/state marker quartet. The resident callback must ask the loaded
    ; gate to revalidate magic, generation, issuer, ticket, and checksum, so
    ; these stale-looking markers are insufficient.
    mov byte [gate_route], gate_route_live_ticket
    mov byte [gate_route_inverse], 0xfd
    mov byte [gate_state_inverse], 0x3c
    mov byte [gate_state], 0xc3
    mov ax, RO_CREDENTIAL_PHASE_KEY
    mov bx, canary_destination
    call credential_loader_callback
    jnc gate_fail
    mov si, credential_checksum
    mov cx, credential_publication_end - credential_checksum
.forged_publication_absent:
    cmp byte [si], 0
    jne gate_fail
    inc si
    loop .forged_publication_absent
    xor ax, ax
    mov di, gate_control_start
    mov cx, (credential_publication_end - gate_control_start) / 2
    rep stosw
    mov si, forged_text
    call emit_str
    call emit_crlf

    mov ax, RO_GENERATION
    mov bx, gate_route_live_ticket
    call word [gate_commit_entry]
    jc gate_fail
    cmp ax, 1
    jne gate_fail
    cmp byte [gate_state], 0xc3
    jne gate_fail
    cmp byte [gate_state_inverse], 0x3c
    jne gate_fail
    cmp byte [gate_route], gate_route_live_ticket
    jne gate_fail
    cmp byte [gate_route_inverse], 0xfd
    jne gate_fail
    mov si, canary_destination
    mov cx, credential_capacity
.credential_retired:
    cmp byte [si], 0
    jne gate_fail
    inc si
    loop .credential_retired
    call verify_ticket
    jc ticket_fail
    mov si, issuer_input_start
    mov cx, issuer_input_end - issuer_input_start
.input_retired:
    cmp byte [si], 0
    jne gate_fail
    inc si
    loop .input_retired
    mov si, commit_text
    call emit_str
    call emit_crlf

    ; Caller registers carry no authority. The first fixed-callback attempt
    ; deliberately publishes partial bytes and fails. The gate must scrub only
    ; that credential destination while preserving the valid live commit.
    mov ax, 0xdead
    mov bx, 0xbeef
    mov dx, 0xaaaa
    call word [gate_unlock_entry]
    jnc unlock_fail
    or ax, ax
    jnz unlock_fail
    cmp byte [gate_state], 0xc3
    jne unlock_fail
    cmp byte [gate_state_inverse], 0x3c
    jne unlock_fail
    cmp byte [gate_route], gate_route_live_ticket
    jne unlock_fail
    mov si, canary_destination
    mov cx, credential_capacity
.retry_scrubbed:
    cmp byte [si], 0
    jne unlock_fail
    inc si
    loop .retry_scrubbed
    mov si, credential_checksum
    mov cx, credential_publication_end - credential_checksum
.retry_publication_scrubbed:
    cmp byte [si], 0
    jne unlock_fail
    inc si
    loop .retry_publication_scrubbed
    call verify_ticket
    jc ticket_fail
    mov si, retry_text
    call emit_str
    call emit_crlf

    ; Retry with different hostile caller registers. The gate still invokes
    ; only the fixed build-time callback, phase key, and destination.
    mov ax, 0x1111
    mov bx, 0x2222
    mov dx, 0x3333
    call word [gate_unlock_entry]
    jc unlock_fail
    cmp ax, 1
    jne unlock_fail
    cmp byte [gate_state], 0xe4
    jne unlock_fail
    mov si, canary_destination
    mov cx, canary_bytes
    call checksum_bytes
    cmp dx, RO_CANARY_CHECKSUM
    jne unlock_fail
    cmp dx, [credential_checksum]
    jne unlock_fail
    cmp word [credential_length], canary_bytes
    jne unlock_fail
    cmp byte [credential_status_inverse], 0x5a
    jne unlock_fail
    cmp byte [credential_status], 0xa5
    jne unlock_fail
    cmp byte [canary_destination + canary_bytes], 0
    jne unlock_fail
    call verify_ticket
    jc ticket_fail
    call verify_sentinels
    jc sentinel_fail

    mov si, unlock_text
    call emit_str
    call emit_crlf
    mov si, readonly_text
    call emit_str
    mov ax, [disk_reads]
    call emit_dec16
    mov si, bios_text
    call emit_str
    mov ax, [bios_interrupt_calls]
    call emit_dec16
    mov si, blocked_text
    call emit_str
    xor ax, ax
    mov al, [bios_blocked_functions]
    call emit_dec16
    call emit_crlf
    call verify_bios_trace
    jc disk_policy_fail
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
disk_policy_fail:
ticket_fail:
auth1_fail:
auth2_fail:
gate_fail:
unlock_fail:
sentinel_fail:
fail:
    mov si, fail_text
    call emit_str
    call emit_crlf
    mov si, result_text
    call emit_str
    call emit_crlf
    jmp start.halt

verify_ticket:
    cmp byte [ticket_present], 0
    je .failed
    mov si, ticket_psk
    mov cx, ticket_psk_bytes
    call checksum_bytes
    mov bx, dx
    mov si, ticket_state
    mov cx, ticket_state_bytes
    call checksum_bytes
    add dx, bx
    cmp dx, RO_TICKET_CHECKSUM
    jne .failed
    clc
    ret
.failed:
    stc
    ret

verify_sentinels:
    mov ax, 0xa5a5
    mov si, driver_slot_start
    mov cx, (overlay_base - driver_slot_start) / 2
.driver:
    cmp [si], ax
    jne .failed
    add si, 2
    loop .driver
    mov si, reconnect_start
    mov cx, (product_pool_start - reconnect_start) / 2
.reconnect:
    cmp [si], ax
    jne .failed
    add si, 2
    loop .reconnect
    mov si, product_pool_start
    mov cx, (stack_guard - product_pool_start) / 2
.pool_tail:
    cmp [si], ax
    jne .failed
    add si, 2
    loop .pool_tail
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

; AX=first zero-based sector in this container, CL=count, ES:BX=destination.
load_phase:
    xor ch, ch
.next:
    call read_container_sector
    jc .failed
    inc ax
    add bx, sector_size
    loop .next
    clc
    ret
.failed:
    stc
    ret

; AX=zero-based sector in this container, ES:BX=destination.
read_container_sector:
    push ax
    add ax, core_start_lba
    call read_abs_sector
    pop ax
    ret

; AX=absolute LBA on the 160 KiB single-sided, eight-sector geometry.
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
    call bios_disk_interrupt
    jnc .ok
    xor ax, ax
    mov dl, [boot_drive]
    call bios_disk_interrupt
    dec byte [read_attempts]
    jnz .retry
    stc
    jmp short .restore
.ok:
    inc word [disk_reads]
    clc
.restore:
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; The only INT 13h opcode in the resident image lives here. Every attempted
; invocation is checked before the interrupt and every executed AH is recorded.
; Unsupported functions, including writes, return CF=1 without entering BIOS.
bios_disk_interrupt:
    cmp ah, 0x00
    je .reset
    cmp ah, 0x02
    je .read
    inc byte [bios_blocked_functions]
    stc
    ret
.reset:
    inc word [bios_reset_calls]
    jmp short .invoke
.read:
    inc word [bios_read_calls]
.invoke:
    inc word [bios_interrupt_calls]
    int 0x13
    ret

verify_bios_trace:
    cmp byte [bios_blocked_functions], 1
    jne .failed
    mov ax, [bios_read_calls]
    or ax, ax
    jz .failed
    mov dx, ax
    add dx, [bios_reset_calls]
    cmp dx, [bios_interrupt_calls]
    jne .failed
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

emit_timing:
    call emit_str
    call emit_dec16
    mov si, tick_text
    call emit_str
    call emit_crlf
    ret

start_text         db 'ROAUTH POC', 0
forged_text        db 'FORGE PASS', 0
auth1_text         db 'AUTH1 PASS t=', 0
auth2_text         db 'AUTH2 PASS t=', 0
tick_text          db ' ticks', 0
commit_text        db 'COMMIT PASS', 0
retry_text         db 'RETRY PASS', 0
unlock_text        db 'UNLOCK PASS', 0
readonly_text      db 'READONLY PASS reads=', 0
bios_text          db ' bios=', 0
blocked_text       db ' blocked=', 0
pass_text          db 'PASS', 0
fail_text          db 'FAIL', 0
result_text        db 'RESULT', 0

boot_drive  db 0
read_attempts db 0
disk_reads  dw 0
tick_start  dw 0
auth1_ticks dw 0
auth2_ticks dw 0
credential_fail_once db 1
bios_interrupt_calls dw 0
bios_read_calls dw 0
bios_reset_calls dw 0
bios_blocked_functions db 0

%if ($ - $$) > (credential_loader_callback - resident_start)
%error "read-only auth scheduler reaches fixed credential callback"
%endif
times (credential_loader_callback - resident_start) - ($ - $$) db 0

; Fixed build-time credential callback ABI:
;   AX=RO_CREDENTIAL_PHASE_KEY, BX=canary_destination, DS=ES=SS=0, DF clear.
; The callback first recognizes the loaded ROG3 image and asks its fixed fourth
; entry to revalidate the complete committed bundle. Stage the BIOS sector in
; retired low scratch, copy the bounded key plus trailing NUL to the retired
; 0x3400 issuer-input band, then publish
; checksum/length/inverse/status with status last. The deliberate first failure
; exercises retryable gate scrub.
read_canary_phase:
    cmp ax, RO_CREDENTIAL_PHASE_KEY
    jne .failed
    cmp bx, canary_destination
    jne .failed
    cmp word [overlay_base], 0x4f52
    jne .failed
    cmp word [overlay_base + 2], 0x3347
    jne .failed
    cmp word [overlay_base + 4], 4
    jne .failed
    call word [gate_authorize_entry]
    jc .failed
    cmp byte [credential_fail_once], 0
    je .read
    dec byte [credential_fail_once]
    mov word [canary_destination], 0xeeee
    mov word [canary_destination + 2], 0xdddd
    stc
    ret
.read:
    mov ax, canary_fixture_sector
    mov bx, 0x0700
    call read_container_sector
    jc .failed
    mov si, 0x0700
    mov di, canary_destination
    mov cx, canary_bytes / 2
    rep movsw
    mov byte [canary_destination + canary_bytes], 0
    mov si, canary_destination
    mov cx, canary_bytes
    call checksum_bytes
    mov [credential_checksum], dx
    mov word [credential_length], canary_bytes
    mov byte [credential_status_inverse], 0x5a
    mov byte [credential_status], 0xa5
    clc
.failed:
    ret

%if ($ - $$) > (driver_slot_start - resident_start)
%error "fixed credential callback reaches driver slot"
%endif
times (driver_slot_start - resident_start) - ($ - $$) db 0
times (overlay_base - driver_slot_start) db 0
resident_end:

%if (resident_end - $$) != resident_sectors * sector_size
%error "read-only auth resident prefix must remain four sectors"
%endif

align 512, db 0
issuer_phase_start:
incbin "build/crypto-bench/tls13-read-only-auth/issuer_auth_read_only.bin"
issuer_phase_content_end:
align 512, db 0
issuer_phase_end:
issuer_phase_sector equ (issuer_phase_start - $$) / sector_size
issuer_phase_sectors equ (issuer_phase_end - issuer_phase_start) / sector_size

issuer_leaf_fixture_start:
incbin "build/crypto-bench/tls13-read-only-auth/issuer_leaf_fixture.bin"
align 512, db 0
issuer_leaf_fixture_sector equ \
    (issuer_leaf_fixture_start - $$) / sector_size

issuer_cv_fixture_start:
incbin "build/crypto-bench/tls13-read-only-auth/issuer_cv_fixture.bin"
align 512, db 0
issuer_cv_fixture_sector equ (issuer_cv_fixture_start - $$) / sector_size

ticket_fixture_start:
incbin "build/crypto-bench/tls13-read-only-auth/ticket_fixture.bin"
align 512, db 0
ticket_fixture_sector equ (ticket_fixture_start - $$) / sector_size

gate_phase_start:
incbin "build/crypto-bench/tls13-read-only-auth/read_only_commit_gate.bin"
gate_phase_content_end:
align 512, db 0
gate_phase_end:
gate_phase_sector equ (gate_phase_start - $$) / sector_size
gate_phase_sectors equ (gate_phase_end - gate_phase_start) / sector_size

canary_fixture_start:
incbin "build/crypto-bench/tls13-read-only-auth/canary_fixture.bin"
align 512, db 0
canary_fixture_sector equ (canary_fixture_start - $$) / sector_size

image_end:

%if issuer_phase_sectors != 14
%error "read-only issuer phase must remain exactly 14 sectors"
%endif
%if gate_phase_sectors != 2
%error "read-only commit gate must remain exactly two sectors"
%endif
