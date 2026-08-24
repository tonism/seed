; Disk-independent failure return for the 16 KiB conventional-RAM TLS route.
;
; The product root snapshots its one caller frame and the resident UI/control
; band plus the DPI prompt marker at the bottom of the 16 KiB stack guard
; (3f00..3f1b).  Every later
; controller may tail-jump here even after its own caller has been overlaid.
; The routine erases all TLS-owned conventional RAM while preserving the
; resident nucleus/NIC, cached product configuration, chat state, arena, and
; the code that is currently executing.  On a direct-entry tier, RET lands in
; the root-installed 7a1e trampoline, which restores the temporarily aliased
; arena bytes and preserves this routine's CF=1 result.

bits 16
cpu 8086

%ifndef SYSRAM_ABORT_ORIGIN
%define SYSRAM_ABORT_ORIGIN 0x0f60
%endif

org SYSRAM_ABORT_ORIGIN

sysram_root_frame_sp       equ 0x3f00
sysram_root_frame_inverse  equ 0x3f02
sysram_root_frame_magic    equ 0x3f04
sysram_root_frame_state    equ 0x3f06
sysram_root_frame_prompt   equ 0x3f1a
sysram_root_frame_end      equ 0x3f1c
sysram_runtime_state_start equ 0x0f55
sysram_runtime_state_end   equ 0x0f69
sysram_dpi_prompt_marker   equ 0x0f33
sysram_private_end         equ 0x3b9c

sysram_product_abort:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov bx, [sysram_root_frame_sp]
    mov dx, [sysram_root_frame_inverse]
    not dx
    cmp bx, dx
    jne .restart
    cmp word [sysram_root_frame_magic], 0xa55a
    jne .restart

    mov di, 0x0500
    mov cx, (0x0600 - 0x0500) / 2
    rep stosw
    mov di, 0x0700
    mov cx, (SYSRAM_ABORT_ORIGIN - 0x0700) / 2
    rep stosw
    mov di, 0x1800
    mov cx, (sysram_private_end - 0x1800) / 2
    rep stosw
    ; This writes back across the already-executed prefix of this abort image;
    ; execution is now above that overlap, so the self-retirement is safe.
    mov si, sysram_root_frame_state
    mov di, sysram_runtime_state_start
    mov cx, (sysram_runtime_state_end - sysram_runtime_state_start) / 2
    rep movsw
    mov al, [sysram_root_frame_prompt]
    mov [sysram_dpi_prompt_marker], al
    xor ax, ax
    mov [0x06c4], al

    mov sp, bx
    mov di, sysram_root_frame_sp
    mov cx, (sysram_root_frame_end - sysram_root_frame_sp) / 2
    rep stosw
    sti
    stc
    ret

.restart:
    jmp 0xffff:0x0000

sysram_product_abort_end:

%if (sysram_product_abort_end - sysram_product_abort) > 0x0082
%error "system-RAM low abort exceeds 0f60..0fe2"
%endif
