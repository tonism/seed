; Immutable post-auth callback pages for the credentialed live composition.
;
; A callback phase is always staged outside low live state and copied by its
; exact measured length into 0x0500..0x05ff. No disk phase is ever loaded
; directly at 0x0500, because a one-sector load would overwrite the mandatory
; handoff and NIC/TCP state at 0x0600..0x08b6.
;
; AUTH_CALLBACKS is installed first:
;   0x0520  load the fixed UCL1 phase at 0x0900 and call it
;
; REQUEST_CALLBACKS replaces it after UCL1 returns and before the request
; controller replaces UCL1 at 0x0900:
;   0x0500  send an already-sealed TLS record through resident TCP
;   0x0510  restore the fixed first eight K14 sectors at 0x1800
;   0x0520  revalidate route authority and the preloaded PAK1 generation
;
; Both pages accept no caller-selected phase key, destination, route, media,
; function pointer, or credential pointer.

bits 16
cpu 8086
org 0x0500

%ifnidn __OUTPUT_FORMAT__, bin
%error "post-auth callback page requires flat-binary output"
%endif

%ifdef POST_AUTH_LIVE_AUTH_CALLBACKS
%ifdef POST_AUTH_LIVE_REQUEST_CALLBACKS
%error "select only one post-auth callback page"
%endif
%ifndef POST_AUTH_LIVE_USER_LOADER_KEY
%error "auth callback page requires the fixed UCL1 phase key"
%endif
%ifndef POST_AUTH_LIVE_USER_LOADER_DESTINATION
%error "auth callback page requires the fixed UCL1 destination"
%endif
%ifndef POST_AUTH_LIVE_USER_LOADER_ENTRY
%error "auth callback page requires the fixed UCL1 entry"
%endif

resident_load_phase equ 0x10c4

post_auth_live_header:
    db 'PAC1'
    dw 2
    dw post_auth_live_end - $$
    dw 1                              ; auth-loader page

times 0x0020 - ($ - $$) db 0

post_auth_live_user_loader:
    mov ax, POST_AUTH_LIVE_USER_LOADER_KEY
    mov bx, POST_AUTH_LIVE_USER_LOADER_DESTINATION
    call resident_load_phase
    jc .failed
    xor ax, ax
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    call POST_AUTH_LIVE_USER_LOADER_ENTRY
    ret
.failed:
    xor ax, ax
    stc
    ret

%elifdef POST_AUTH_LIVE_REQUEST_CALLBACKS

%ifndef POST_AUTH_LIVE_SYM_RESTORE_KEY
%error "request callback page requires the fixed K14 restore phase key"
%endif
%ifndef POST_AUTH_LIVE_GATE_AUTHORIZE
%error "request callback page requires the fixed ROG4 authorize entry"
%endif
%ifndef POST_AUTH_LIVE_GATE_GENERATION
%define POST_AUTH_LIVE_GATE_GENERATION 0x3c30
%endif
%ifndef POST_AUTH_LIVE_PUBLICATION_GENERATION
%define POST_AUTH_LIVE_PUBLICATION_GENERATION 0x0d0a
%endif

resident_load_phase equ 0x10c4
resident_tcp_send   equ 0x13bf

post_auth_live_send:
    call resident_tcp_send
    ret

post_auth_live_header:
    db 'PAC1'
    dw 2
    dw post_auth_live_end - $$
    dw 2                              ; request page

times 0x0010 - ($ - $$) db 0

post_auth_live_restore:
    mov ax, POST_AUTH_LIVE_SYM_RESTORE_KEY
    mov bx, 0x1800
    call resident_load_phase
    ret

times 0x0020 - ($ - $$) db 0

post_auth_live_authorize:
    xor ax, ax
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    call POST_AUTH_LIVE_GATE_AUTHORIZE
    jc .failed
    cmp ax, 1
    jne .failed
    mov ax, [POST_AUTH_LIVE_PUBLICATION_GENERATION]
    or ax, ax
    jz .failed
    cmp ax, [POST_AUTH_LIVE_GATE_GENERATION]
    jne .failed
    mov ax, 1
    clc
    ret
.failed:
    xor ax, ax
    stc
    ret

%else
%error "select POST_AUTH_LIVE_AUTH_CALLBACKS or POST_AUTH_LIVE_REQUEST_CALLBACKS"
%endif

post_auth_live_end:

%if ($ - $$) > 0x0100
%error "post-auth callback page exceeds safe 0x0500..0x05ff range"
%endif
%ifdef POST_AUTH_LIVE_AUTH_CALLBACKS
%if (post_auth_live_user_loader - $$) != 0x0020
%error "post-auth USER.CFG callback moved"
%endif
%else
%if (post_auth_live_send - $$) != 0x0000
%error "post-auth send callback moved"
%endif
%if (post_auth_live_restore - $$) != 0x0010
%error "post-auth symmetric restore callback moved"
%endif
%if (post_auth_live_authorize - $$) != 0x0020
%error "post-auth authorization callback moved"
%endif
%endif
