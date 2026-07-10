%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

ext_xfer_gdt equ tls_rx_copy
ext_xfer_buf equ tls_rx_copy + 0x30

ext_read_chunk_phase:
    mov cx, [tool_readlen]
    jcxz .ok
    push ds
    pop es
    mov di, ext_xfer_gdt
    xor ax, ax
    mov cx, 24
    rep stosw
    mov cx, [tool_readlen]
    inc cx
    shr cx, 1
    mov ax, cx
    shl ax, 1
    dec ax
    mov [ext_xfer_gdt + 0x10], ax
    mov [ext_xfer_gdt + 0x18], ax
    mov ax, [tool_addr]
    mov [ext_xfer_gdt + 0x12], ax
    mov al, [tool_addr + 2]
    mov [ext_xfer_gdt + 0x14], al
    mov byte [ext_xfer_gdt + 0x15], 0x93
    mov word [ext_xfer_gdt + 0x1a], ext_xfer_buf
    mov byte [ext_xfer_gdt + 0x1c], 0
    mov byte [ext_xfer_gdt + 0x1d], 0x93
    mov si, ext_xfer_gdt
    mov ah, 0x87
    int 0x15
    jc .fail
    mov ax, [tool_readlen]
    add [tool_addr], ax
    adc word [tool_addr + 2], 0
.ok:
    clc
    ret
.fail:
    stc
    ret
