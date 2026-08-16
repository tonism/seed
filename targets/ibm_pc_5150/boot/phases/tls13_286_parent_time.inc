%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (net_setup_phase_start + ($ - PHASE_BASE) + 2)
%endmacro

; Parent-side trusted-time contract for the product TLS 1.3 286 route.
;
; The machine RTC is the platform UTC clock, just as a conventional TLS client
; relies on its platform clock. Every route, including reconnects, obtains a
; fresh bounded, coherent snapshot without interrupting the chat flow and
; publishes exactly:
;
;   +0..6  packed BCD CC YY MM DD hh mm ss
;   +7     0x5a (inverse READY)
;   +8     0xa5 (READY, written last)
;
; The low publication aliases otherwise-idle SHA state at 0000:062e.  The
; phase also derives the top-relative product reservation independently and
; publishes the same bytes at its fixed high offset.  The fixed bootstrap
; reads the fixed low copy, independently derives the same high address,
; requires byte-for-byte agreement, and preserves only the validated high
; nine-byte slot while clearing the rest of the reservation.

tls13_286_parent_time_phase:
    cld
    push ds
    pop es
    xor ax, ax
    mov di, tls13_286_parent_rtc_publication
    mov cx, tls13_286_parent_rtc_publication_bytes
    rep stosb

    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .failed
    cmp word [0x0413], 512
    jb .failed
    call .derive_high_es
    mov di, tls13_286_rtc_publication_off
    xor ax, ax
    mov cx, tls13_286_parent_rtc_publication_bytes
    rep stosb
    push ds
    pop es
    mov bp, tls13_286_parent_rtc_attempt_limit
.attempt:
    mov si, tls13_286_parent_rtc_raw_a_addr
    call .read_snapshot
    jc .attempt_failed
    call .validate_raw
    jc .attempt_failed
    mov si, tls13_286_parent_rtc_raw_b_addr
    call .read_snapshot
    jc .attempt_failed
    call .snapshots_equal
    jc .attempt_failed
    call .publish
    call .preserve_loop_cache
    jc .failed
    mov di, tls13_286_parent_rtc_publication
    clc
    ret
.attempt_failed:
    dec bp
    jnz .attempt
.failed:
    stc
    ret

; SI names an eight-byte phase-local raw destination:
; CC YY MM DD hh mm ss daylight.  A date read surrounds the time read so a
; midnight crossing is rejected rather than assembled into a mixed timestamp.
.read_snapshot:
    mov ah, 0x04
    int 0x1a
    jc .bios_error
    mov [si], ch
    mov [si + 1], cl
    mov [si + 2], dh
    mov [si + 3], dl

    mov ah, 0x02
    int 0x1a
    jc .bios_error
    mov [si + 4], ch
    mov [si + 5], cl
    mov [si + 6], dh
    mov [si + 7], dl

    mov ah, 0x04
    int 0x1a
    jc .bios_error
    cmp ch, [si]
    jne .incoherent
    cmp cl, [si + 1]
    jne .incoherent
    cmp dh, [si + 2]
    jne .incoherent
    cmp dl, [si + 3]
    jne .incoherent
    clc
    ret
.bios_error:
.incoherent:
    stc
    ret

; Strict packed-BCD Gregorian validation.  The supported certificate interval
; uses RFC 5280 UTCTime, hence the 2024..2049 product range.
.validate_raw:
    cmp byte [tls13_286_parent_rtc_raw_a_addr + 7], 0
    jne .bad
    cmp byte [tls13_286_parent_rtc_raw_a_addr], 0x20
    jne .bad

    mov al, [tls13_286_parent_rtc_raw_a_addr + 1]
    call .bcd_valid
    jc .bad
    mov al, [tls13_286_parent_rtc_raw_a_addr + 1]
    cmp al, 0x24
    jb .bad
    cmp al, 0x49
    ja .bad

    mov al, [tls13_286_parent_rtc_raw_a_addr + 2]
    call .bcd_valid
    jc .bad
    mov al, [tls13_286_parent_rtc_raw_a_addr + 2]
    cmp al, 0x01
    jb .bad
    cmp al, 0x12
    ja .bad

    mov al, [tls13_286_parent_rtc_raw_a_addr + 3]
    call .bcd_valid
    jc .bad
    mov al, [tls13_286_parent_rtc_raw_a_addr + 3]
    cmp al, 0x01
    jb .bad
    call .days_in_month
    cmp [tls13_286_parent_rtc_raw_a_addr + 3], bl
    ja .bad

    mov al, [tls13_286_parent_rtc_raw_a_addr + 4]
    call .bcd_valid
    jc .bad
    mov al, [tls13_286_parent_rtc_raw_a_addr + 4]
    cmp al, 0x23
    ja .bad
    mov al, [tls13_286_parent_rtc_raw_a_addr + 5]
    call .bcd_valid
    jc .bad
    mov al, [tls13_286_parent_rtc_raw_a_addr + 5]
    cmp al, 0x59
    ja .bad
    mov al, [tls13_286_parent_rtc_raw_a_addr + 6]
    call .bcd_valid
    jc .bad
    mov al, [tls13_286_parent_rtc_raw_a_addr + 6]
    cmp al, 0x59
    ja .bad
    clc
    ret
.bad:
    stc
    ret

.days_in_month:
    mov bl, 0x31
    mov al, [tls13_286_parent_rtc_raw_a_addr + 2]
    cmp al, 0x02
    je .february
    cmp al, 0x04
    je .thirty
    cmp al, 0x06
    je .thirty
    cmp al, 0x09
    je .thirty
    cmp al, 0x11
    jne .month_done
.thirty:
    mov bl, 0x30
    ret
.february:
    mov bl, 0x28
    mov al, [tls13_286_parent_rtc_raw_a_addr + 1]
    mov ah, al
    and ax, 0x0f0f
    shl ah, 1
    add al, ah
    test al, 3
    jnz .month_done
    inc bl
.month_done:
    ret

.bcd_valid:
    mov ah, al
    and ax, 0xf00f
    cmp al, 9
    ja .bcd_bad
    cmp ah, 0x90
    ja .bcd_bad
    clc
    ret
.bcd_bad:
    stc
    ret

.snapshots_equal:
    xor bx, bx
.equal_byte:
    mov al, [tls13_286_parent_rtc_raw_a_addr + bx]
    cmp al, [tls13_286_parent_rtc_raw_b_addr + bx]
    jne .different
    inc bx
    cmp bx, 8
    jb .equal_byte
    clc
    ret
.different:
    stc
    ret

.publish:
    mov si, tls13_286_parent_rtc_raw_b_addr
    mov di, tls13_286_parent_rtc_publication
    mov cx, 7
    rep movsb
    mov al, 0x5a
    stosb
    call .derive_high_es
    mov si, tls13_286_parent_rtc_publication
    mov di, tls13_286_rtc_publication_off
    mov cx, tls13_286_parent_rtc_publication_bytes - 1
    rep movsb
    mov al, 0xa5
    stosb
    push ds
    pop es
    ; Product TLS 1.3 replaces the legacy ClientHello phase which historically
    ; published this resident image.  The 8088 route reconstructs it in
    ; its post-route guard; publish the same canonical bytes here so the 286
    ; bootstrap authenticates, escrows, and later restores a usable application
    ; ChaCha20/Poly1305 boundary instead of stale loader/FAT scratch.
    mov si, net_setup_phase_start + \
        (tls13_286_parent_low_constants - PHASE_BASE)
    mov di, low_static_constants_start
    mov cx, low_static_constants_len
    rep movsb
    mov [tls13_286_parent_rtc_publication + 8], al
    mov di, tls13_286_parent_rtc_publication
    ret

.derive_high_es:
    mov ax, [0x0413]
    mov cl, 6
    shl ax, cl
    sub ax, tls13_286_high_reserve_bytes / 16
    mov es, ax
    ret

; Populate the immutable low chat cache once, copy its complete 29-sector span
; to the arena-excluded shadow immediately below the crypto reservation, and
; publish 0xffff only after the copy authenticates. load_core_sectors_at treats
; that negative count as unavailable throughout the crypto lifetime. The final
; capsule validates the CRC and restores the low cache from RAM before the
; scheduler can build or send an application request.
.preserve_loop_cache:
    cmp word [loop_cache_count], 0
    jne .cache_live
    phase_call_res preload_loop_cache
.cache_live:
    cmp word [loop_cache_count], loop_cache_max_entries
    jne .cache_bad
    call .derive_high_es
    mov ax, es
    sub ax, tls13_286_loop_shadow_seg_delta
    mov es, ax
    xor ax, ax
    xor di, di
    mov cx, tls13_286_loop_shadow_data_off / 2
    rep stosw
    mov si, tools_cache
    mov di, tls13_286_loop_shadow_data_off
    mov cx, tls13_286_loop_shadow_data_bytes / 2
    rep movsw
    mov si, tools_cache
    mov cx, tls13_286_loop_shadow_data_bytes
    call .crc16
    mov [es:tls13_286_loop_shadow_crc_off], ax
    mov word [loop_cache_count], 0xffff
    push ds
    pop es
    clc
    ret
.cache_bad:
    push ds
    pop es
    stc
    ret

.crc16:
    mov ax, 0xffff
    mov dx, cx
.crc_byte:
    or dx, dx
    jz .crc_done
    xor ah, [si]
    inc si
    mov cx, 8
.crc_bit:
    shl ax, 1
    jnc .crc_plain
    xor ax, 0x1021
.crc_plain:
    loop .crc_bit
    dec dx
    jmp .crc_byte
.crc_done:
    ret

tls13_286_parent_rtc_raw_a:
    times 8 db 0
tls13_286_parent_rtc_raw_b:
    times 8 db 0
tls13_286_parent_low_constants:
%include "tls13/low_static_constants.inc"
tls13_286_parent_low_constants_end:

%if (tls13_286_parent_low_constants_end - \
    tls13_286_parent_low_constants) != low_static_constants_len
%error "TLS 1.3 286 parent low-constant image length drifted"
%endif

tls13_286_parent_rtc_attempt_limit equ 4
tls13_286_parent_rtc_raw_a_addr equ \
    net_setup_phase_start + (tls13_286_parent_rtc_raw_a - PHASE_BASE)
tls13_286_parent_rtc_raw_b_addr equ \
    net_setup_phase_start + (tls13_286_parent_rtc_raw_b - PHASE_BASE)

%unmacro phase_call_res 1
