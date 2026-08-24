; Late same-boot ticket-age finalization for the 16 KiB TLS 1.3 route.
;
; The authenticated ticket receipt tick and lifetime were retained in
; conventional RAM before regenerated KeyGen.  This one-sector offline phase
; samples the monotonic BIOS tick counter immediately before the resumed
; ClientHello and computes RFC 8446 obfuscated_ticket_age.  It neither reads
; nor trusts the RTC calendar, performs port I/O, or touches display/card RAM.

bits 16
cpu 8086

%ifndef SYSRAM_TICKET_AGE_ORIGIN
%define SYSRAM_TICKET_AGE_ORIGIN 0x0900
%endif

org SYSRAM_TICKET_AGE_ORIGIN

resume_age               equ 0x3480
resume_age_tick_lo       equ 0x35c0
resume_age_tick_hi       equ resume_age_tick_lo + 2
resume_age_lifetime_hi   equ resume_age_tick_hi + 2
resume_age_lifetime_lo   equ resume_age_lifetime_hi + 2
resume_age_work_lo       equ resume_age_lifetime_lo + 2
resume_age_work_hi       equ resume_age_work_lo + 2
resume_age_state_end     equ resume_age_work_hi + 2

bios_ticks_day_hi        equ 0x0018
bios_ticks_day_lo        equ 0x00b0
resume_ticks_max_hi      equ 0x0012
resume_ticks_max_lo      equ 0x0084

system_ram_ticket_age:
    cld
    mov ax, [resume_age_tick_lo]
    mov dx, [resume_age_tick_hi]
    call validate_bios_ticks
    jc .failed

    pushf
    cli
    mov ax, [0x046c]
    mov dx, [0x046e]
    popf
    call validate_bios_ticks
    jc .failed

    cmp dx, [resume_age_tick_hi]
    ja .same_day
    jb .wrapped
    cmp ax, [resume_age_tick_lo]
    jae .same_day
.wrapped:
    mov bx, bios_ticks_day_lo
    mov cx, bios_ticks_day_hi
    sub bx, [resume_age_tick_lo]
    sbb cx, [resume_age_tick_hi]
    add ax, bx
    adc dx, cx
    jmp short .elapsed
.same_day:
    sub ax, [resume_age_tick_lo]
    sbb dx, [resume_age_tick_hi]
.elapsed:
    cmp dx, resume_ticks_max_hi
    ja .failed
    jb .bounded
    cmp ax, resume_ticks_max_lo
    ja .failed
.bounded:
    call ticks_to_ms

    ; A bounded attempt has a 16-bit seconds quotient.  If lifetime_hi is
    ; nonzero the ticket necessarily outlives the 18-hour local bound.
    mov bx, 1000
    div bx
    cmp word [resume_age_lifetime_hi], 0
    jne .lifetime_ok
    cmp ax, [resume_age_lifetime_lo]
    jae .failed
.lifetime_ok:
    mov ax, [resume_age]
    xchg al, ah
    mov bx, [resume_age + 2]
    xchg bl, bh
    add bx, [resume_age_work_lo]
    adc ax, [resume_age_work_hi]
    xchg al, ah
    mov [resume_age], ax
    xchg bl, bh
    mov [resume_age + 2], bx
    push ds
    pop es
    xor ax, ax
    mov di, resume_age_tick_lo
    mov cx, (resume_age_state_end - resume_age_tick_lo) / 2
    rep stosw
    clc
    ret
.failed:
    stc
    ret

validate_bios_ticks:
    cmp dx, bios_ticks_day_hi
    ja .bad
    jb .ok
    cmp ax, bios_ticks_day_lo
    jae .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

; DX:AX ticks -> DX:AX milliseconds, using the earlier resumption
; controller's exact fixed-point conversion:
; ticks*55 - ((ticks*611)>>13).
ticks_to_ms:
    mov [resume_age_tick_lo], ax
    mov [resume_age_tick_hi], dx
    mov cx, dx
    mov bx, 55
    mul bx
    mov [resume_age_work_lo], ax
    mov si, dx
    mov ax, cx
    mul bx
    add si, ax
    mov [resume_age_work_hi], si
    mov ax, [resume_age_tick_lo]
    mov bx, 611
    mul bx
    mov si, ax
    mov di, dx
    mov ax, [resume_age_tick_hi]
    mul bx
    add di, ax
    mov cx, 13
.shift:
    shr di, 1
    rcr si, 1
    loop .shift
    mov ax, [resume_age_work_lo]
    mov dx, [resume_age_work_hi]
    sub ax, si
    sbb dx, di
    mov [resume_age_work_lo], ax
    mov [resume_age_work_hi], dx
    ret

system_ram_ticket_age_end:
%if (system_ram_ticket_age_end - $$) > 512
%error "system-RAM ticket-age phase exceeds one sector"
%endif
