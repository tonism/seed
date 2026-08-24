; Stable full-FO runner for the 16 KiB conventional-RAM product route.
;
; The FO arithmetic owns 0700..0fd0, so neither its callback nor the code
; reached after FO may live in the ordinary 0900 controller/0f00 continuation
; windows.  This runner occupies only the already-retired 0500..05ff page.
; Its controller stages the linked 0f00 continuation and checked low-abort
; image in the lifetime-disjoint 3550..35ff gap before entering FO.

bits 16
cpu 8086
org 0x0500

low_abort                  equ 0x0f60
fo_stage2_source           equ 0x3550
fo_abort_source            equ fo_stage2_source + SYSRAM_FO_STAGE2_BYTES

%ifndef SYSRAM_FO_STAGE2_BYTES
%error "FO runner requires the staged continuation size"
%endif
%ifndef SYSRAM_LOW_ABORT_BYTES
%error "FO runner requires the staged low-abort size"
%endif

sysram_fo_runner:
    cld
    mov bx, sysram_fo_public_object_read
    call 0x1800

    ; FO used 0f60 as public-buffer scratch.  Restore the checked abort before
    ; interpreting either its carry flag or its constant-time selection bit.
    pushf
    push ax
    push ds
    pop es
    mov si, fo_abort_source
    mov di, low_abort
    mov cx, SYSRAM_LOW_ABORT_BYTES
    rep movsb
    pop ax
    popf
    jc low_abort
    cmp ax, 1
    jne low_abort

    mov si, fo_stage2_source
    mov di, 0x0f00
    mov cx, SYSRAM_FO_STAGE2_BYTES
    rep movsb
    jmp 0x0f00

; FO callback: AL=0 ek / AL=1 c, DX=offset, CX=count, DI=destination.
sysram_fo_public_object_read:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    or cx, cx
    jz .failed
    cmp cx, 384
    ja .failed
    cmp al, 0
    je .ek
    cmp al, 1
    jne .failed
    mov si, 0x3600
    mov bx, 1088
    jmp short .bounded
.ek:
    mov si, 0x2400
    mov bx, 1184
.bounded:
    add si, dx
    jc .failed
    sub bx, dx
    jc .failed
    cmp cx, bx
    ja .failed
    push ds
    pop es
    rep movsb
    clc
    jmp short .restore
.failed:
    stc
.restore:
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Acquisition only: stage 2 has retired the runner entry/callback prefix and
; saved the capsule tail at 0500..053f.  sym_init necessarily clears the
; overlapping 3510..355d runtime tail; restore the capsule bytes needed by
; lifecycle_acquisition_restore, then erase the temporary copy.
times 0x00b2 - ($ - $$) db 0
sysram_auth_capsule_restore:
    push ds
    pop es
    mov si, 0x0500
    mov di, 0x3510
    mov cx, 0x0040 / 2
    rep movsw
    xor ax, ax
    mov di, 0x0500
    mov cx, 0x0040 / 2
    rep stosw
    ret

%if (sysram_auth_capsule_restore - $$) != 0x00b2
%error "capsule restore helper moved from its continuation ABI"
%endif

; Resumption reaches the same sym_init overlap without the intervening P-256
; verifier.  Save the affected capsule tail only after full FO validation;
; sysram_auth_capsule_restore above restores it and erases this temporary.
sysram_resumption_capsule_save:
    push ds
    pop es
    mov si, 0x3510
    mov di, 0x0500
    mov cx, 0x0040 / 2
    rep movsw
    ret

%if (sysram_resumption_capsule_save - $$) != 0x00ca
%error "capsule save helper moved from its continuation ABI"
%endif

sysram_fo_runner_end:

%if (sysram_fo_runner_end - $$) > 0x0100
%error "FO runner/callback reaches the 0600 handoff"
%endif
%if (fo_abort_source + SYSRAM_LOW_ABORT_BYTES) > 0x3600
%error "staged FO continuation/abort reaches consolidated ciphertext"
%endif
