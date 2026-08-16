; Disk-independent emergency erasure for the 16 KiB volatile video vault.
;
; The ordinary lifecycle phase restores the exact saved MDA register value.
; This leaf is the last-resort path when that phase cannot be read after the
; vault may already contain secrets or MDA output may already be disabled.
; It clears the complete payload+metadata span plus the adjacent 416-byte
; config escrow directly and re-enables MDA from the BIOS mode-control
; shadow.  It also restores the standard MDA page-zero scanout after a normal
; or emergency quarantine hold. The product caller reconstructs/redraws after
; return.
;
; Clobbers AX/CX/DX/DI, restores ES=DS=0, returns with DF clear.

%macro K14_PRODUCT_EMERGENCY_VAULT_ROUTINE 1
%1:
    cld
    mov ax, 0xb000
    mov es, ax
    xor di, di
    mov dx, 0x03b8
    cmp word [0x0463], 0x03b4
    je %%clear
    mov ax, 0xb800
    mov es, ax
    mov di, 0x1000
    xor dx, dx

%%clear:
    xor ax, ax
    ; 4000 bytes: MDA's complete visible page, or CGA's complete off-screen
    ; vault+escrow range B800:1000..1f9f.
    mov cx, 0x07d0
    rep stosw
    or dx, dx
    jz %%done
    mov dx, 0x03b4
    mov al, 0x0c
    out dx, al
    inc dx
    xor al, al
    out dx, al
    dec dx
    mov al, 0x0d
    out dx, al
    inc dx
    xor al, al
    out dx, al
    dec dx
    mov al, 0x01
    out dx, al
    inc dx
    mov al, 80
    out dx, al
    mov dx, 0x03b8
    mov al, [0x0465]
    or al, 0x08
    out dx, al

%%done:
    ; A failed phase read cannot validate/restore the escrow.  Erase the
    ; corresponding conventional slots as well; cache loss is explicitly
    ; preferable to exposing K14 scratch as product configuration.
    push ds
    pop es
    xor ax, ax
    mov di, 0x3b9c
    mov cx, 128
    rep stosw
    mov [0x0f55], ax                 ; cursor_row || cursor_col
    mov byte [0x0f33], 0             ; dpi_prompt_marker_row
    mov [0x0f66], ax                 ; pending || count
    mov byte [0x06c4], 0             ; no published TLS schedule
    cld
    ret
%endmacro
