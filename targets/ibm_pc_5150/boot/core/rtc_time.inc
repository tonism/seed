; Build 12 task #7 -- NTP seconds-since-1900 -> calendar -> BCD RTC fields.
; Mirrors tools/x509/ntp_rtc.py (ntp_seconds_to_calendar) + http_date_rtc.to_cmos(). Pure 8086 logic,
; no network/BIOS I/O: the caller stores [ntp_seconds] (unsigned 32-bit, big -- 2026 is > 2^31), calls
; ntp_to_rtc_fields, then writes the rtc_* BCD bytes to the CMOS RTC (int 1Ah AH=03h/05h).
; POSITION-INDEPENDENT: the only data refs are the fixed ntp_seconds/rtc_* scratch (layout.inc
; equates), so this runs correctly inside the NTP setup phase (which loads at net_setup_phase_start,
; not where it is assembled). Month lengths are inlined -- no const table to find a fixed home for.
; Offline-validated by tools/crypto-bench/date_eval.py against the oracle's dense sweep.
; cpu 8086.

; one fixed-length month: subtract it from the day-of-year (SI); if it doesn't fit, this is the month.
%macro ntp_month 1
    cmp     si, %1
    jb      .month_done
    sub     si, %1
    inc     di
%endmacro

ntp_to_rtc_fields:
    ; split seconds-since-1900 into time-of-day + day count via /60 /60 /24
    ; (86400 won't fit a single 16-bit DIV divisor, so we chain three long divisions).
    mov     ax, [ntp_seconds]
    mov     dx, [ntp_seconds + 2]
    mov     bx, 60
    call    ntp_div32by16           ; DX:AX = total minutes, BX = seconds (0-59)
    mov     [rtc_sec], bl
    mov     bx, 60
    call    ntp_div32by16           ; DX:AX = total hours, BX = minutes
    mov     [rtc_min], bl
    mov     bx, 24
    call    ntp_div32by16           ; AX = days since 1900 (DX=0 in NTP era 0), BX = hours
    mov     [rtc_hour], bl
    mov     si, ax                  ; SI = day index since 1900-01-01 (0-based)

    ; subtract whole years; CX = year, BP = (this year leap ? 1 : 0)
    mov     cx, 1900
.year_loop:
    call    ntp_year_is_leap        ; BP = leap flag for CX
    mov     ax, 365
    add     ax, bp                  ; 365 or 366 days this year
    cmp     si, ax
    jb      .months
    sub     si, ax
    inc     cx
    jmp     .year_loop

.months:
    ; SI = day-of-year (0-based), BP = leap flag, CX = year. Walk months with inline lengths -> DI.
    mov     di, 1                   ; January
    ntp_month 31                    ; Jan
    ; February = 28 (+1 if leap) -- the only variable-length month
    mov     ax, 28
    add     ax, bp
    cmp     si, ax
    jb      .month_done
    sub     si, ax
    inc     di
    ntp_month 31                    ; Mar
    ntp_month 30                    ; Apr
    ntp_month 31                    ; May
    ntp_month 30                    ; Jun
    ntp_month 31                    ; Jul
    ntp_month 31                    ; Aug
    ntp_month 30                    ; Sep
    ntp_month 31                    ; Oct
    ntp_month 30                    ; Nov
    ; whatever remains is December
.month_done:
    mov     ax, di
    mov     [rtc_month], al
    inc     si                      ; day-of-month = day-of-year-index + 1 (<= 31)
    mov     ax, si
    mov     [rtc_day], al

    ; century / 2-digit year from the full year in CX
    mov     ax, cx
    xor     dx, dx
    mov     bx, 100
    div     bx                      ; AX = century (e.g. 20), DX = year-of-century (e.g. 26)
    mov     [rtc_century], al
    mov     [rtc_year], dl

    ; pack all seven fields to BCD in place (sec,min,hour,day,month,year,century are contiguous)
    mov     si, rtc_fields
    mov     cx, 7
.bcd_loop:
    mov     al, [si]
    call    ntp_to_bcd
    mov     [si], al
    inc     si
    loop    .bcd_loop
    ret

; DX:AX / BX (unsigned) -> quotient DX:AX, remainder BX. Quotient may exceed 16 bits (long division).
ntp_div32by16:
    mov     cx, ax                  ; save low dividend
    mov     ax, dx                  ; high dividend
    xor     dx, dx
    div     bx                      ; AX = high/BX (q_high), DX = partial remainder
    xchg    cx, ax                  ; CX = q_high, AX = low dividend, DX:AX = rem:low
    div     bx                      ; AX = q_low, DX = final remainder
    mov     bx, dx                  ; BX = remainder
    mov     dx, cx                  ; DX = q_high
    ret

; CX = year -> BP = 1 if leap, else 0. Within NTP era 0 (1900..2036) the Gregorian rule reduces to
; (year%4==0) except 1900 (2000 is leap; 2100 is past the era ceiling -> never seen). Matches the
; oracle's full rule across that range (date_eval.py proves it on the dense sweep).
ntp_year_is_leap:
    xor     bp, bp
    test    cx, 3
    jnz     .nl
    cmp     cx, 1900
    je      .nl
    inc     bp
.nl:
    ret

; AL (0..99) -> AL packed BCD. (aam: AH = AL/10 tens, AL = AL%10 units.)
ntp_to_bcd:
    aam
    push    cx
    mov     cl, 4
    shl     ah, cl
    pop     cx
    or      al, ah
    ret
