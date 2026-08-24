; Deadline transition for the 16 KiB conventional-RAM TLS 1.3 route.
;
; The 0x3400 controller copies this complete image to 0x0700 before the raw
; ServerHello ciphertext is scattered over the controller itself.  All
; provider-window phase reads use the checked track-batched loader except the
; final protected-controller tail sector: a <=0x60 continuation at 0x0f00
; loads that required sector through the resident loader after this image is
; dead, then copies only real bytes so the retained c suffix at 0x0de0 is not
; overwritten by sector padding.

bits 16
cpu 8086

%ifndef SYSRAM_DELTA_LOADER_PATH
%error "deadline terminal requires the relocatable delta loader image"
%endif
%ifndef SYSRAM_CORE_START_LBA
%error "deadline terminal requires the SEED.SYS core LBA"
%endif
%ifndef SYSRAM_CANDIDATE_KEY
%error "deadline terminal requires the candidate phase"
%endif
%ifndef SYSRAM_SYM_RESTORE_KEY
%error "deadline terminal requires the symmetric-prefix phase"
%endif
%ifndef SYSRAM_PROTECTED_KEY
%error "deadline terminal requires the protected-controller phase"
%endif
%ifndef SYSRAM_PROTECTED_BYTES
%error "deadline terminal requires the exact protected-controller length"
%endif

%ifndef SYSRAM_DEADLINE_ACQUISITION
%ifndef SYSRAM_DEADLINE_RESUMPTION
%error "select one deadline transition"
%endif
%endif
%ifdef SYSRAM_DEADLINE_ACQUISITION
%ifdef SYSRAM_DEADLINE_RESUMPTION
%error "select only one deadline transition"
%endif
%endif

org 0x0700

resident_load_phase       equ 0x10c4
low_abort                 equ 0x0f60
delta_load                equ 0x0703
sym_entry_table           equ 0x1820
sym_init_entry            equ sym_entry_table + 0 * 2
sym_critical_entry        equ sym_entry_table + 3 * 2
sym_resumption_early      equ sym_entry_table + 13 * 2
sym_resumption_schedule   equ sym_entry_table + 14 * 2
sym_import_entry          equ sym_entry_table + 15 * 2

sysram_deadline_terminal:
    jmp terminal_main
delta_loader_image:
    incbin SYSRAM_DELTA_LOADER_PATH
delta_loader_image_end:

terminal_main:
    cld

    ; The raw ServerHello ciphertext at 08c0..0cff and every compressed dkPKE
    ; component at 3600..3aff must remain intact until the provisional
    ; decapsulation finishes.  In particular, the retained-c home at 3600
    ; aliases the first secret polynomial; scattering before this call would
    ; silently corrupt 77 bytes of sHat[0].
    mov ax, SYSRAM_CANDIDATE_KEY
    mov bx, 0x1800
    call batch_phase
    jc terminal_failed
    call 0x1800

    ; Candidate polynomial work is dead, but the symmetric implementation
    ; expects its complete mutable K tail to start clean.  Clear it before the
    ; retained-c scatter repopulates the route-specific bytes at its end.
    xor ax, ax
    mov di, 0x3000
    mov cx, (0x3400 - 0x3000) / 2
    rep stosw

%ifdef SYSRAM_DEADLINE_RESUMPTION
    mov si, 0x08c0
    mov di, 0x3400
    mov cx, 272
    rep movsb
    mov si, 0x09d0
    mov di, 0x3640
    mov cx, 13
    rep movsb
    mov si, 0x09dd
    mov di, 0x3b40
    mov cx, 80
    rep movsb
    mov si, 0x0a2d
    mov di, 0x355d
    mov cx, 99
    rep movsb
    mov si, 0x0a90
    mov di, 0x0500
    mov cx, 256
    rep movsb
    mov si, 0x0b90
    mov di, 0x33f8
    mov cx, 8
    rep movsb
%else
    mov si, 0x08c0
    mov di, 0x3400
    mov cx, 272
    rep movsb
    mov si, 0x09d0
    mov di, 0x3600
    mov cx, 77
    rep movsb
    mov si, 0x0a1d
    mov di, 0x355d
    mov cx, 99
    rep movsb
    mov si, 0x0a80
    mov di, 0x0500
    mov cx, 256
    rep movsb
    mov si, 0x0b80
    mov di, 0x33e8
    mov cx, 24
    rep movsb
%endif

    mov si, 0x0b98
    mov di, 0x08b8
    mov cx, 72
    rep movsb
    mov si, 0x0be0
    mov di, 0x0de0
    mov cx, 288
    rep movsb

    ; The live candidate deliberately retains the direct 08c0 ciphertext ABI.
    ; Its offline replay has a separate split-c phase.  Clear the overlapping
    ; low object only after the deadline candidate has consumed it.
    mov di, 0x0900
    mov ch, 2
    rep stosw

    ; Preserve the ciphertext bytes whose scatter homes alias the symmetric
    ; schedule inputs.  Both temporary homes are conventional RAM, are dead
    ; for the selected route, and are erased immediately after restoration.
%ifdef SYSRAM_DEADLINE_RESUMPTION
    push ds
    pop es
    mov si, 0x3640
    mov di, 0x0dab
    mov cx, 13
    rep movsb
%else
    push ds
    pop es
    mov si, 0x3600
    mov di, 0x3b40
    mov cx, 77
    rep movsb
%endif

    ; Freeze acquisition K' below K before sym_init clears candidate high
    ; state.  The resumed image deliberately preserves 3a60..3a7f instead;
    ; its record quarantine never reaches that span before the lifecycle.
    ; The RAM-only candidate publishes G(m'||H(ek)) at 3a60, not the retired
    ; product-vault address.
%ifndef SYSRAM_DEADLINE_RESUMPTION
    push ds
    pop es
    mov si, 0x3a60
    mov di, 0x2f60
    mov cx, 16
    rep movsw
%endif

    mov ax, SYSRAM_SYM_RESTORE_KEY
    mov bx, 0x1800
    call batch_phase
    jc terminal_failed
    call word [sym_init_entry]
    jc terminal_failed
%ifdef SYSRAM_DEADLINE_RESUMPTION
    call word [sym_resumption_early]
    jc terminal_failed
    push ds
    pop es
    mov si, 0x3a60
    mov di, 0x3600
    mov cx, 16
    rep movsw
%else
    push ds
    pop es
    mov si, 0x2f60
    mov di, 0x3600
    mov cx, 16
    rep movsw
%endif
    call word [sym_import_entry]
    jc terminal_failed
%ifdef SYSRAM_DEADLINE_RESUMPTION
    call word [sym_resumption_schedule]
%else
    call word [sym_critical_entry]
%endif
    jc terminal_failed

%ifdef SYSRAM_DEADLINE_RESUMPTION
    ; The shared-secret input is dead after the resumed schedule.  Retain the
    ; entropy root/provisional K in its place before the protected flight.
    ; Root occupied only the preloaded image's aligned padding; K' remained
    ; in the unused resumed record-quarantine tail.
    push ds
    pop es
    mov si, 0x2fe0
    mov di, 0x3600
    mov cx, 16
    rep movsw
    mov si, 0x3a60
    mov di, 0x3620
    mov cx, 16
    rep movsw
    mov si, 0x0dab
    mov di, 0x3640
    mov cx, 13
    rep movsb
    xor ax, ax
    mov di, 0x0dab
    mov cx, 13
    rep stosb
    mov di, 0x2fe0
    mov cx, 16
    rep stosw
%else
    ; The acquisition schedule has retired shared_secret||hello_hash.  Restore
    ; the exact c slice over that dead input.  Reuse the same high gap for the
    ; 72-byte low slice before the protected tail-sector read replaces 0700..
    ; 08ff; the offline lifecycle consumes and erases the complete high gap.
    push ds
    pop es
    mov si, 0x3b40
    mov di, 0x3600
    mov cx, 77
    rep movsb
    mov si, 0x08b8
    mov di, 0x3b40
    mov cx, 72
    rep movsb
%endif

%if SYSRAM_PROTECTED_BYTES > 1024
    ; Install the self-overwrite-safe final-sector continuation first, then
    ; batch only the first two sectors into their final 0x0900 destination.
    push ds
    pop es
    mov si, split_tail_source
    mov di, 0x0f00
    mov cx, split_tail_end - split_tail_source
    rep movsb
    mov ax, SYSRAM_PROTECTED_KEY
    mov ah, 2
    mov bx, 0x0900
    call batch_phase
    jc terminal_failed
    jmp 0x0f00
%else
    mov ax, SYSRAM_PROTECTED_KEY
    mov bx, 0x0900
    call batch_phase
    jc terminal_failed
    jmp 0x0900
%endif

terminal_failed:
    jmp low_abort

batch_phase:
    mov cl, ah
    xor ch, ch
    xor ah, ah
    add ax, SYSRAM_CORE_START_LBA
    jmp delta_load

%if SYSRAM_PROTECTED_BYTES > 1024
split_tail_source:
    mov ax, SYSRAM_PROTECTED_KEY
    add al, 2
    mov ah, 1
    mov bx, 0x0700
    mov dx, resident_load_phase
    call dx
    jnc .loaded
    mov dx, low_abort
    jmp dx
.loaded:
    push ds
    pop es
    mov si, 0x0700
    mov di, 0x0d00
    mov cx, SYSRAM_PROTECTED_BYTES - 1024
    rep movsb
    mov dx, 0x0900
    jmp dx
split_tail_end:
%endif

sysram_deadline_terminal_end:

%if (delta_loader_image - $$) != 3
%error "relocatable delta loader lost its 0x0703 entry"
%endif
%if (delta_loader_image_end - delta_loader_image) > 0x0100
%error "relocatable delta loader exceeds one sector"
%endif
%if (sysram_deadline_terminal_end - $$) > (0x08b8 - 0x0700)
%error "deadline terminal exceeds the dead RX/ciphertext prefix"
%endif
%if SYSRAM_PROTECTED_BYTES > 1536
%error "protected controller exceeds three sectors"
%endif
%if SYSRAM_PROTECTED_BYTES > 1024
%if (split_tail_end - split_tail_source) > 0x0060
%error "protected tail continuation reaches the low abort"
%endif
%endif
