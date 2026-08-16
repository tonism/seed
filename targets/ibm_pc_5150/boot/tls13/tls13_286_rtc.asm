; Strict BIOS RTC acquisition for the TLS 1.3 286 certificate-validity route.
;
; This is an independently assembled, fixed-origin component.  It does not
; infer that a PC/AT RTC is UTC: INT 1Ah exposes no timezone.  The caller must
; pass rtc_utc_attestation only after a product-owned UTC provisioning step.
; The component additionally requires the BIOS daylight-saving byte to be zero.
; Hardcoding the attestation without that provisioning step is not valid use.
;
; Entry:
;   AL    = rtc_utc_attestation
;   ES:DI = rtc_publication_bytes writable bytes, without segment wrap
;
; Success:
;   CF=0, AX=0, DF=0
;   ES:DI publication:
;     +0..6  packed BCD CC YY MM DD hh mm ss (fixed-width UTC order)
;     +7     inverse status, rtc_status_ready_inv
;     +8     status, rtc_status_ready (written last)
;
; Failure:
;   CF=1, AX=rtc_error_*, DF=0
;   A valid output span is zero and is never published READY.
;
; BP, DS, ES, SS, and SP are preserved; AX is the result and BX/CX/DX/SI/DI
; are volatile, matching the product module boundary.  The implementation is
; bounded to rtc_attempt_limit attempts.  Each attempt reads two independent
; date/time/date snapshots, so at most 24 INT 1Ah calls can occur.

bits 16
cpu 8086
org 0x1800

rtc_component_abi       equ 1
rtc_entry_count         equ 1
rtc_publication_bytes   equ 9
rtc_attempt_limit       equ 4

rtc_utc_attestation     equ 0xa5
rtc_status_ready_inv    equ 0x5a
rtc_status_ready        equ 0xa5

rtc_error_output        equ 1
rtc_error_utc_policy    equ 2
rtc_error_bios          equ 3
rtc_error_incoherent    equ 4
rtc_error_calendar      equ 5

rtc_min_year_bcd        equ 0x24       ; 2024, with century fixed to 0x20
rtc_max_year_bcd        equ 0x49       ; 2049, the RFC 5280 UTCTime ceiling

rtc_header:
    db 'S286RTC1'
    dw rtc_component_abi
    dw rtc_image_end - rtc_header
    dw rtc_entry_count
rtc_entry_table:
    dw rtc_acquire_utc

rtc_acquire_utc:
    push bp
    push ds
    push es
    cld

    mov [cs:rtc_output_off], di
    mov [cs:rtc_output_seg], es
    cmp di, 0xffff - rtc_publication_bytes + 1
    ja .output_error

    ; Invalidate the complete caller publication before consulting the RTC.
    ; A later success writes the READY byte only after all timestamp bytes and
    ; the inverse status are present.
    push ax
    xor ax, ax
    mov cx, rtc_publication_bytes
    rep stosb
    pop ax

    cmp al, rtc_utc_attestation
    jne .utc_error
    mov bp, rtc_attempt_limit

.attempt:
    mov si, rtc_raw_a
    call rtc_read_snapshot
    jc .remember_failure
    call rtc_validate_raw
    jc .remember_failure
    mov si, rtc_raw_b
    call rtc_read_snapshot
    jc .remember_failure
    call rtc_raw_snapshots_equal
    jc .remember_failure
    call rtc_publish
    jmp short rtc_return_success

.remember_failure:
    dec bp
    jnz .attempt
    jmp short rtc_return_failure

.output_error:
    mov ax, rtc_error_output
    jmp short rtc_return_failure
.utc_error:
    mov ax, rtc_error_utc_policy
    jmp short rtc_return_failure

rtc_return_success:
    pop es
    pop ds
    pop bp
    xor ax, ax
    clc
    ret

rtc_return_failure:
    pop es
    pop ds
    pop bp
    stc
    ret

; Read one internally coherent snapshot.  A date read surrounds the time read;
; crossing midnight therefore rejects instead of combining two calendar days.
; SI names an eight-byte component-local raw destination:
; CC YY MM DD hh mm ss daylight.
rtc_read_snapshot:
    mov ah, 0x04
    int 0x1a
    jc .bios_error
    mov [cs:si], ch
    mov [cs:si + 1], cl
    mov [cs:si + 2], dh
    mov [cs:si + 3], dl

    mov ah, 0x02
    int 0x1a
    jc .bios_error
    mov [cs:si + 4], ch
    mov [cs:si + 5], cl
    mov [cs:si + 6], dh
    mov [cs:si + 7], dl

    mov ah, 0x04
    int 0x1a
    jc .bios_error
    cmp ch, [cs:si]
    jne .incoherent
    cmp cl, [cs:si + 1]
    jne .incoherent
    cmp dh, [cs:si + 2]
    jne .incoherent
    cmp dl, [cs:si + 3]
    jne .incoherent
    xor ax, ax
    clc
    ret

.bios_error:
    mov ax, rtc_error_bios
    stc
    ret
.incoherent:
    mov ax, rtc_error_incoherent
    stc
    ret

; Strict packed-BCD, Gregorian, plausibility, and UTC-policy validation.  The
; accepted raw first seven bytes are already the canonical compact timestamp.
rtc_validate_raw:
    cmp byte [cs:rtc_raw_a + 7], 0
    jne .utc_error
    cmp byte [cs:rtc_raw_a], 0x20
    jne .calendar_error

    mov al, [cs:rtc_raw_a + 1]
    call rtc_bcd_valid
    jc .calendar_error
    mov al, [cs:rtc_raw_a + 1]
    cmp al, rtc_min_year_bcd
    jb .calendar_error
    cmp al, rtc_max_year_bcd
    ja .calendar_error

    mov al, [cs:rtc_raw_a + 2]
    call rtc_bcd_valid
    jc .calendar_error
    mov al, [cs:rtc_raw_a + 2]
    cmp al, 0x01
    jb .calendar_error
    cmp al, 0x12
    ja .calendar_error

    mov al, [cs:rtc_raw_a + 3]
    call rtc_bcd_valid
    jc .calendar_error
    mov al, [cs:rtc_raw_a + 3]
    cmp al, 0x01
    jb .calendar_error
    call rtc_days_in_month
    cmp [cs:rtc_raw_a + 3], bl
    ja .calendar_error

    mov al, [cs:rtc_raw_a + 4]
    call rtc_bcd_valid
    jc .calendar_error
    cmp byte [cs:rtc_raw_a + 4], 0x23
    ja .calendar_error

    mov al, [cs:rtc_raw_a + 5]
    call rtc_bcd_valid
    jc .calendar_error
    cmp byte [cs:rtc_raw_a + 5], 0x59
    ja .calendar_error

    mov al, [cs:rtc_raw_a + 6]
    call rtc_bcd_valid
    jc .calendar_error
    cmp byte [cs:rtc_raw_a + 6], 0x59
    ja .calendar_error
    xor ax, ax
    clc
    ret

.utc_error:
    mov ax, rtc_error_utc_policy
    stc
    ret
.calendar_error:
    mov ax, rtc_error_calendar
    stc
    ret

; Return BL = exact Gregorian month length in packed BCD.  The accepted
; 2024..2049 range contains no non-400 century boundary.
rtc_days_in_month:
    mov bl, 0x31
    mov al, [cs:rtc_raw_a + 2]
    cmp al, 0x02
    je .february
    cmp al, 0x04
    je .thirty
    cmp al, 0x06
    je .thirty
    cmp al, 0x09
    je .thirty
    cmp al, 0x11
    jne .done
.thirty:
    mov bl, 0x30
    ret
.february:
    mov bl, 0x28
    mov al, [cs:rtc_raw_a + 1]
    mov ah, al
    and ax, 0x0f0f
    shl ah, 1
    add al, ah
    test al, 3
    jnz .done
    inc bl
.done:
    ret

; Reject either nibble above nine.  AX is volatile.
rtc_bcd_valid:
    mov ah, al
    and ax, 0xf00f
    cmp al, 9
    ja .bad
    cmp ah, 0x90
    ja .bad
    clc
    ret
.bad:
    stc
    ret

rtc_raw_snapshots_equal:
    xor bx, bx
.byte:
    mov al, [cs:rtc_raw_a + bx]
    cmp al, [cs:rtc_raw_b + bx]
    jne .different
    inc bx
    cmp bx, 8
    jb .byte
    xor ax, ax
    clc
    ret
.different:
    mov ax, rtc_error_incoherent
    stc
    ret

rtc_publish:
    push cs
    pop ds
    mov es, [cs:rtc_output_seg]
    mov di, [cs:rtc_output_off]
    mov si, rtc_raw_b
    mov cx, 7
    rep movsb
    mov al, rtc_status_ready_inv
    stosb
    mov al, rtc_status_ready
    stosb
    cld
    ret

rtc_output_off       dw 0
rtc_output_seg       dw 0
rtc_raw_a:            times 8 db 0
rtc_raw_b:            times 8 db 0

rtc_image_end:

%if (rtc_header - $$) != 0
%error "TLS 1.3 286 RTC component origin moved"
%endif
%if (rtc_image_end - $$) > 512
%error "TLS 1.3 286 RTC component exceeds one sector"
%endif
