; Low transition inside existing SEED.SYS padding, never a new file.
; Six caller inputs are saved by K before the bootstrap sector replaces NIC
; scratch. The post-tag phase replaces K, so every loader failure must either
; restore all of K or unwind directly to the saved resident owner of the NIC
; lease. It must never return into a partly overwritten K/X frame.
bits 16
cpu 8086
%include "bridge-abi.inc"
org H2_BRIDGE_ENTRY
load_core_sectors_at equ 0x10c4
h2_abort_sp equ 0x0682

bridge:
    mov ax, 0x070c                   ; post-tag first seven sectors, file 12
    mov bx, 0x1800
    call load_core_sectors_at
    jc .abort
    ; Last post-tag fragment was staged with this bridge in the otherwise
    ; unused tail of the existing S phase's final sector. No second read.
    mov si, H2_TAIL_STAGED
    mov di, 0x2600
    mov cx, H2_TAIL_BYTES
    rep movsb
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop ax                          ; trusted entry-table byte offset 0/2/4/6
bridge_enter_post equ $
    mov bx, ax
    call [bx+0x1800]
bridge_leave_post equ $
    pushf
    push ax
    push bx
    push cx
    mov ax, 0x0804                   ; restore the complete eight-sector K
    mov bx, 0x1800
    call load_core_sectors_at
    jc .abort
    pop cx
    pop bx
    pop ax
    popf
    ret
.abort:
bridge_abort equ $
    ; Caller sets this to its resident return-frame before starting the
    ; exchange/send. Both the controller and tentative byte path exclude it.
    mov sp, [h2_abort_sp]
    xor ax, ax
    mov di, 0x062e
    mov cx, (0x0684-0x062e)/2
    rep stosw                       ; protocol/HPACK-reply alias and anchor
    mov di, 0x2e00
    mov cx, 0x3b9c-0x2e00
    rep stosb                       ; journals, keys, receive/TX work + metadata
    mov byte [0x06c4], 0             ; no capability after an incomplete reload
    stc
    ret                             ; resident owner restores NIC and retires
bridge_end:
%if (($-$$)+H2_BRIDGE_ENTRY) > 0x0900
%error "low H2 bridge would overwrite the live T phase"
%endif
