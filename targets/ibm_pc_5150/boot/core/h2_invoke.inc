; Private phase call. Inputs AX/CX/DX/SI/DI/BP survive bootstrap load.
; The operation is a trusted word-table offset. A pre-swap load failure returns
; CF into the intact K; after a swap starts, the low bridge owns safe unwind.
tls_h2_invoke:
    push ax
    push cx
    push dx
    push si
    push di
    push bp
    mov ax, 466
    mov bx, 0x0700
    call load_core_sectors_at
    jc .failed
    jmp 2216
.failed:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop ax
    stc
    ret
