; One-sector high controller that evacuates the entire deadline transition to
; dead low RX/ciphertext RAM before the ciphertext scatter overwrites 0x3400.
; The immutable final symmetric-sector prefix is already staged at 0x2e00 by
; the route's full pre-TCP symmetric-image load.  KeyGen and HELLO use only
; memory on either side of that prefix, while the retained root starts exactly
; at its route-specific endpoint.  Do not reread that sector in the provider
; window.

bits 16
cpu 8086
org 0x3400

%ifndef SYSRAM_DEADLINE_TERMINAL_PATH
%error "deadline controller requires the checked low terminal image"
%endif
sysram_deadline_controller:
    cld
    push ds
    pop es

    mov si, terminal_image
    mov di, 0x0700
    mov cx, terminal_image_end - terminal_image
    rep movsb
    jmp 0x0700

terminal_image:
    incbin SYSRAM_DEADLINE_TERMINAL_PATH
terminal_image_end:

sysram_deadline_controller_end:

%if (sysram_deadline_controller_end - $$) > 512
%error "deadline controller exceeds one sector"
%endif
