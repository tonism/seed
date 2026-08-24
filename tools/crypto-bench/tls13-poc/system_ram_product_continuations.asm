; Relocated continuations embedded by the conventional-RAM product phases.
;
; These bytes are linked for their actual 0x0f00 execution address, then
; stored inside a controller sector and copied there before that controller is
; overwritten.  Keeping the link address honest is mandatory: 8086 near
; CALL/JMP immediates are relative and cannot be copied from a 0x0900/0x3400
; source without relocation.

bits 16
cpu 8086
org 0x0f00

resident_load_phase       equ 0x10c4
low_abort                 equ 0x0f60
sym_entry_table           equ 0x1820
lifecycle_entry_table     equ 0x090a
resume_capsule_restore    equ 0x05b2
resume_capsule_save       equ 0x05ca

%ifdef SYSRAM_ROOT_HELLO_TRANSITION

%ifndef SYSRAM_FRESH_HELLO_CONTROLLER_KEY
%error "root HELLO transition requires controller phase"
%endif

sysram_product_continuation:
    mov bx, 0x3400
    call resident_load_phase
    jc low_abort
    jmp 0x3400

%elifdef SYSRAM_ACQUISITION_STAGE1

%ifndef SYSRAM_LIFECYCLE_KEY
%error "acquisition stage 1 requires lifecycle phase"
%endif
%ifndef SYSRAM_KEYGEN_KEY
%error "acquisition stage 1 requires KeyGen phase"
%endif
%ifndef SYSRAM_CANDIDATE_KEY
%error "acquisition stage 1 requires candidate phase"
%endif
%ifndef SYSRAM_ACQ_FO_CONTROLLER_KEY
%error "acquisition stage 1 requires FO continuation"
%endif
%ifndef SYSRAM_ACQ_FO_CONTROLLER_DEST
%error "acquisition stage 1 requires FO controller destination"
%endif

sysram_product_continuation:
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc .failed
    call word [lifecycle_entry_table + 0 * 2]
    jc .failed
    mov ax, SYSRAM_KEYGEN_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc .failed
    xor ax, ax
    mov si, 0x0700
    mov dx, .after_keygen
    push dx
    jmp 0x1800
.after_keygen:
    jc .failed
    mov ax, SYSRAM_CANDIDATE_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc .failed
    call 0x1800
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc .failed
    call word [lifecycle_entry_table + 1 * 2]
    jc .failed
    mov ax, SYSRAM_ACQ_FO_CONTROLLER_KEY
    mov bx, SYSRAM_ACQ_FO_CONTROLLER_DEST
    call resident_load_phase
    jc .failed
    jmp SYSRAM_ACQ_FO_CONTROLLER_DEST
.failed:
    jmp low_abort

%elifdef SYSRAM_RESUMPTION_STAGE1

%ifndef SYSRAM_LIFECYCLE_KEY
%error "resumption stage 1 requires lifecycle phase"
%endif
%ifndef SYSRAM_KEYGEN_KEY
%error "resumption stage 1 requires KeyGen phase"
%endif
%ifndef SYSRAM_CANDIDATE_KEY
%error "resumption stage 1 requires candidate phase"
%endif
%ifndef SYSRAM_RESUME_FO_CONTROLLER_KEY
%error "resumption stage 1 requires FO continuation"
%endif
%ifndef SYSRAM_RESUME_FO_CONTROLLER_DEST
%error "resumption stage 1 requires FO controller destination"
%endif

sysram_product_continuation:
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc .failed
    call word [lifecycle_entry_table + 5 * 2]
    jc .failed
    mov ax, SYSRAM_KEYGEN_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc .failed
    mov ax, 1
    mov si, 0x0700
    mov dx, .after_keygen
    push dx
    jmp 0x1800
.after_keygen:
    jc .failed
    mov ax, SYSRAM_CANDIDATE_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc .failed
    call 0x1800
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc .failed
    call word [lifecycle_entry_table + 1 * 2]
    jc .failed
    mov ax, SYSRAM_RESUME_FO_CONTROLLER_KEY
    mov bx, SYSRAM_RESUME_FO_CONTROLLER_DEST
    call resident_load_phase
    jc .failed
    jmp SYSRAM_RESUME_FO_CONTROLLER_DEST
.failed:
    jmp low_abort

%elifdef SYSRAM_ACQUISITION_STAGE2

%ifndef SYSRAM_LIFECYCLE_KEY
%error "acquisition stage 2 requires lifecycle phase"
%endif
%ifndef SYSRAM_AUTH_RETURN_KEY
%error "acquisition stage 2 requires auth return phase"
%endif
%ifndef SYSRAM_AUTH_KEY
%error "acquisition stage 2 requires auth phase"
%endif

sysram_product_continuation:
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc .failed
    call word [lifecycle_entry_table + 2 * 2]
    jc .failed
    ; sym_init clears its K14 runtime tail at 3510..355d.  The live capsule
    ; occupies 3400..3550, so retain its final 64 bytes in the retired prefix
    ; of the stable 0500 FO runner.  A runner-tail helper restores and erases
    ; this copy immediately after sym_init.
    push ds
    pop es
    mov si, 0x3510
    mov di, 0x0500
    mov cx, 0x0040 / 2
    rep movsw
    mov ax, SYSRAM_AUTH_RETURN_KEY
    mov bx, 0x3550
    call resident_load_phase
    jc .failed
    mov ax, SYSRAM_AUTH_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc 0x35a0
    mov ax, 0x3550
    push ax
    jmp word [0x1800]
.failed:
    jmp low_abort

%elifdef SYSRAM_RESUMPTION_STAGE2

%ifndef SYSRAM_LIFECYCLE_KEY
%error "resumption stage 2 requires lifecycle phase"
%endif
%ifndef SYSRAM_RES_SYM_KEY
%error "resumption stage 2 requires symmetric phase"
%endif
%ifndef SYSRAM_FINAL_POST_KEY
%error "resumption stage 2 requires final post phase"
%endif

sysram_product_continuation:
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc .failed
    call word [lifecycle_entry_table + 6 * 2]
    jc .failed
    ; res_sym's sym_init clears 3510..355d.  Preserve the overlapping final
    ; 64 capsule bytes in the retired FO-runner prefix, exactly as the fresh
    ; auth transition does, then restore and erase that copy after init.
    call resume_capsule_save
    mov ax, SYSRAM_RES_SYM_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc .failed
    call word [sym_entry_table]
    jc .failed
    call resume_capsule_restore
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc .failed
    call word [lifecycle_entry_table + 7 * 2]
    jc .failed
    mov ax, SYSRAM_FINAL_POST_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc .failed
    jmp 0x0900
.failed:
    jmp low_abort

%else
%error "select one system-RAM product continuation"
%endif

sysram_product_continuation_end:

%if (sysram_product_continuation_end - $$) > 0x0060
%error "system-RAM product continuation reaches the low abort"
%endif
