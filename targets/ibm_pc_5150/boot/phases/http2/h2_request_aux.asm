; Request helper copied from R's third file sector beside K.
; K ends at 2800; H2 post ends below 2800; collector state begins at 2e00.
; The response owner also uses the bounded DATA preflight at the end.
bits 16
cpu 8086
org 0x2800
%include "request-aux-abi.inc"
dw aux_start, aux_putc, aux_putw, aux_copy, aux_flush, aux_finish, aux_fail
body equ 0x3912+14
limit equ 0x062e+66

aux_start:
    mov ax, 2
    call tls_h2_invoke
    jc aux_fail
    mov cx, [tls_app_len]
    mov si, 0x3912+5
    call h2_tx_control
    jc aux_fail
    mov di, body
    jmp aux_flush

; CS always names segment zero, even while DS is a far context segment or ES
; is the BIOS text framebuffer being read. Only conventional RAM is written.
aux_putc:
    pushf                             ; replacement for STOSB must preserve flags
    cmp di, [cs:limit]
    jb .room
    call aux_flush
.room:
    mov [cs:di], al
    inc di
    popf
    ret
aux_putw:
    push ax
    call aux_putc
    xchg al, ah
    call aux_putc
    pop ax
    ret
aux_copy:
    jcxz .done
.next:
    lodsb
    call aux_putc
    loop .next
.done:
    ret

aux_flush:
    push ax
    push bx
    push cx
    push dx
    push si
    push bp
    push ds
    push es
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ax, di
    sub ax, body
    jz .empty
    xor dx, dx
    call upload_send
    jc aux_fail
.empty:
    cmp word [quota], 0
    jne .ready
    call h2_tx_reserve
    jc aux_fail
    add ax, body
    mov [limit], ax
.ready:
    pop es
    pop ds
    pop bp
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    mov di, body
    clc
    ret
aux_finish:
    mov ax, di
    sub ax, body
    mov dl, 1
    call upload_send
    jc aux_fail
    ret
aux_fail:
    ; The resident frame was captured at X entry before any nested stream,
    ; context or phase call. Never return into an overwritten scratch phase.
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov sp, [0x0682]
    mov di, 0x062e
    mov cx, (0x0684-0x062e)/2
    rep stosw
    mov di, 0x2e00
    mov cx, (0x3b9c-0x2e00)/2
    rep stosw
    mov byte [0x06c4], 0
    stc
    ret

%include "upload-body.inc"

h2 equ 0x062e
; Post-tag response preflight: SI/CX DATA and DI/BP controls. Accept exactly
; one complete unpadded, non-final DATA frame on the active stream. CF refuses
; without state writes or changes to SI/CX/DI/BP, so the full parser can run.
aux_response_data_check:
    cmp bp, 9
    jne .fallback
    cmp word [h2+10], 0
    jne .fallback
    mov al, [h2+9]
    or al, [h2+16]
    or al, [h2+59]
    jnz .fallback
    cmp word [h2+18], 1
    jne .fallback
    cmp byte [h2+47], 1
    jne .fallback
    cmp cx, 512
    ja .fallback
    mov ax, cx
    add ax, 9
    cmp ax, [0x2e6c]
    jne .fallback
    cmp byte [di], 0
    jne .fallback
    cmp word [di+3], 0
    jne .fallback
    mov ax, [di+1]
    xchg al, ah
    cmp ax, cx
    jne .fallback
    mov ax, [di+5]
    cmp ax, [h2+20]
    jne .fallback
    mov ax, [di+7]
    cmp ax, [h2+22]
    jne .fallback
    mov ax, [h2+20]
    or ax, [h2+22]
    jz .fallback
    clc
    ret
.fallback:
    stc
    ret
