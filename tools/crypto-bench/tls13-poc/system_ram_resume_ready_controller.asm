; Post-KeyGen ticket-identity publication for the system-RAM resumption HELLO.
; This tiny resident tail survives the regenerated public key at 08c0..0d5f.

bits 16
cpu 8086
org 0x0f00

resume_identity_len   equ 0x3484
resume_identity_stage equ 0x3486
resume_identity       equ 0x3000
resume_identity_max   equ 192

system_ram_resume_ready:
    cld
    mov dx, [resume_identity_len]
    or dx, dx
    jz .failed
    cmp dx, resume_identity_max
    ja .failed
    push ds
    pop es
    xor ax, ax
    mov di, resume_identity
    mov cx, resume_identity_max / 2
    rep stosw
    mov si, resume_identity_stage
    mov di, resume_identity
    mov cx, dx
    rep movsb
    mov di, resume_identity_stage
    mov cl, resume_identity_max / 2
    rep stosw
    clc
    ret
.failed:
    stc
    ret

; Snapshot the first encrypted response/NST batch ingress time provisionally.
; The post controller calls this once when TCP first supplies that batch; an
; authenticated NST must still publish status before the sample is consumed.
system_ram_record_tick:
    pushf
    cli
    mov ax, [0x046c]
    mov [0x35fc], ax
    mov ax, [0x046e]
    mov [0x35fe], ax
    popf
    ret

system_ram_resume_ready_end:
%if (system_ram_resume_ready_end - $$) > (0x0fe2 - 0x0f00)
%error "system-RAM resume-ready tail reaches resident TCP code"
%endif
