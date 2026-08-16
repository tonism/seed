; Exercise the large 286 benchmark loader without crypto.

bits 16
cpu 8086
org 0x1000

%ifndef SMOKE_BYTES
    %define SMOKE_BYTES 34262
%endif

    jmp short start
    nop
    db 'SEEDCORE'
    db 1, 0
    dw 18
    dw (image_end - $$ + 511) / 512
    dw (image_end - $$ + 511) / 512
    dw 0, 0

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0xeff0
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init
    mov si, done_text
    call emit_str
.hang:
    hlt
    jmp .hang

serial_init:
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 0x0c
    out dx, al
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 0x03
    out dx, al
    ret

emit_str:
    lodsb
    or al, al
    jz .done
    push ax
    push dx
    mov ah, al
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, 0x3f8
    mov al, ah
    out dx, al
    pop dx
    pop ax
    mov ah, 0x0e
    mov bx, 7
    int 0x10
    jmp emit_str
.done:
    ret

done_text db 'DONE', 13, 10, 0
times SMOKE_BYTES - ($ - $$) db 0xa5
image_end:
