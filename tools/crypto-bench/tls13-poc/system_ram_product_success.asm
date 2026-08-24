; Final publication/return capsule for the 16 KiB RAM-only TLS route.
;
; The caller has copied the authenticated resumed application state into the
; resident 0x3600 ABI.  This disk-independent tail erases every other
; conventional TLS span, validates/adopts the root frame, and returns CF=0 to
; the resident scheduler.  The final post controller has already restored the
; resident UI/control snapshot from that frame; display/card/config/arena
; memory is untouched.  On a direct-entry tier, RET lands in the root-installed
; 7a1e trampoline, which restores the temporarily aliased arena bytes while
; preserving CF=0.
;
; Entry: DL is the saved DPI prompt marker. The capsule's first low clear
; executes through 0x0f33 before republishing that byte, avoiding live-code
; self-corruption while the final post controller is still resident.

bits 16
cpu 8086
org 0x0f00

; The bottom 28 bytes of the 16 KiB stack guard are outside the user arena and
; below the measured stack low-water mark.  Keeping the return metadata and
; 20-byte resident-state snapshot plus prompt marker here avoids the live ML-KEM sHat2 expansion
; at 0x3980..0x3b7f.
root_frame_sp       equ 0x3f00
root_frame_inverse  equ 0x3f02
root_frame_magic    equ 0x3f04
root_frame_end      equ 0x3f1c
runtime_state_start equ 0x0f55
dpi_prompt_marker   equ 0x0f33
published_end       equ 0x3668
private_end         equ 0x3b9c

sysram_product_success:
    cli
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov bx, [root_frame_sp]
    mov si, [root_frame_inverse]
    not si
    cmp bx, si
    jne .restart
    cmp word [root_frame_magic], 0xa55a
    je .frame_valid
.restart:
    jmp 0xffff:0x0000
.frame_valid:
    mov di, 0x0500
    mov cx, (0x0600 - 0x0500) / 2
    rep stosw
    mov di, 0x0700
    ; REP leaves CX=0, so the next two page-sized clears need only CH.
    mov ch, ((0x0f00 - 0x0700) / 2) >> 8
    rep stosw
    ; DI is now 0x0f00. The three-byte based store fits the capsule's exact
    ; tail budget and writes only the already-executed 0x0f33 code byte.
    mov [di + dpi_prompt_marker - 0x0f00], dl
    mov di, 0x1800
    mov ch, ((0x3600 - 0x1800) / 2) >> 8
    rep stosw
    mov di, published_end
    mov cx, (private_end - published_end) / 2
    rep stosw
    mov [0x06c4], al
    mov sp, bx
    mov di, root_frame_sp
    mov cl, (root_frame_end - root_frame_sp) / 2
    rep stosw
    sti
    clc
    ret

sysram_product_success_end:

%if (sysram_product_success_end - $$) > (runtime_state_start - 0x0f00)
%error "system-RAM success capsule reaches the resident UI/control restore"
%endif
