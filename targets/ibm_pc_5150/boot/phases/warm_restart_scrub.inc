; Common no-return warm-restart boundary for cold phases loaded at 0000:0700.
;
; A warm reset must not leave an authenticated TLS schedule or the 286
; top-relative crypto reservation readable after reboot.
; The caller supplies its phase-local entry label and runtime load address:
;
;     seed_warm_restart_scrub entry_label, load_address
;
; The entry copies its stackless tail below Seed-owned RAM, then executes from
; 0000:0500 while erasing the phase that contained it.  The fixed conventional
; sweep does not trust the handoff or BDA memory-size words: it covers every
; possible Seed conventional byte through the 640 KiB ceiling on every memory
; floor.  Display and adapter RAM are outside Seed's storage boundary and are
; never touched by this scrub.
;
; This is intentionally a macro rather than a resident call.  The resident
; nucleus is itself inside the erased range, and all three users already carry
; a phase-local copy.  Interrupts stay disabled and no stack access occurs.

%ifndef PHASE_BASE
%error "warm restart scrub requires the containing phase base"
%endif

%macro seed_warm_restart_scrub 2
%1:
    cli
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x0600
    mov si, %2 + (%%relocated - PHASE_BASE)
    mov bx, 0x0500
    mov di, bx
    mov cx, %%relocated_end - %%relocated
    rep movsb
    jmp bx

%%relocated:
    ; Clear the remainder of the first 64 KiB after the callback page, then
    ; nine complete 64 KiB spans.  This covers exactly 0x00600..0x9ffff
    ; without trusting mutable RAM-size metadata or entering video RAM.
    xor ax, ax
    mov es, ax
    mov di, 0x0600
    mov cx, 0x7d00
    rep stosw
    mov dx, 0x1000
%%wipe_conventional:
    mov es, dx
    xor di, di
    mov cx, 0x8000
    rep stosw
    add dh, 0x10
    cmp dh, 0xa0
    jb %%wipe_conventional

    mov word [0x0472], 0x1234
    jmp 0xffff:0x0000
%%relocated_end:

%if (%%relocated_end - %%relocated) > 0x0100
%error "warm restart scrub tail exceeds the 0000:0500 callback page"
%endif
%endmacro
