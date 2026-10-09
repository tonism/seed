fresh_transition_source:
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    mov dx, resident_load_phase
    call dx
    jc .failed
    call word [lifecycle_entry_table + 4 * 2]
    jc .failed
    mov ax, SYSRAM_RES_SYM_KEY
    mov bx, 0x1800
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov ax, SYSRAM_KEYGEN_KEY
    mov bx, 0x1800
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov ax, 1
    mov si, 0x3400
    mov dx, 0x0700 + .after_keygen - fresh_transition_source
    push dx
    mov dx, 0x1800
    jmp dx
.after_keygen:
    jc .failed
    mov ax, 1
    mov si, 0x3400
    mov di, 0x3420
    mov dx, SYSRAM_KEYGEN_NONCE_ENTRY
    call dx
    jc .failed
    mov ax, SYSRAM_TICKET_AGE_KEY
    mov bx, SYSRAM_TICKET_AGE_DEST
    mov dx, resident_load_phase
    call dx
    jc .failed
    ; Keep the helper resident, but defer its clock sample until the resumed
    ; HELLO controller is loaded and ready to build the binder.  Its dedicated
    ; 2c00 sector is disjoint from regenerated ek, the 1800..29ff HELLO, the
    ; 2a00 controller, and the 2e00 TX staging page.
    mov dx, 0x0f00
    call dx
    jc .failed
    push ds
    pop es
    mov si, 0x0f40
    mov di, 0x0f00
    mov cx, resumed_deadline_transition_end - resumed_deadline_transition_source
    rep movsb
    mov ax, SYSRAM_RESUMED_HELLO_KEY
    mov bx, 0x1800
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov ax, SYSRAM_RESUMED_HELLO_CONTROLLER_KEY
    mov bx, SYSRAM_RESUMED_HELLO_CONTROLLER_DEST
    mov dx, resident_load_phase
    call dx
    jc .failed
    mov dx, SYSRAM_RESUMED_HELLO_CONTROLLER_DEST
    jmp dx
.failed:
    mov dx, low_abort
    jmp dx
fresh_transition_end:

; Position-independent: staged at 0f40, copied to 0f00 after resume-ready.
resumed_deadline_transition_source:
    mov bx, 0x3400
    mov dx, resident_load_phase
    call dx
    jnc .loaded
    mov dx, low_abort
    jmp dx
.loaded:
    mov dx, 0x3400
    jmp dx
resumed_deadline_transition_end:

resume_ready_image:
    incbin SYSRAM_RESUME_READY_PATH,0,48
resume_ready_image_end:
