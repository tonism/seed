%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

ext_xfer_gdt equ tls_rx_copy
ext_xfer_buf equ tls_rx_copy + 0x30

ext_read_chunk_phase:
    mov cx, [tool_readlen]
    jcxz .empty
    test word [handoff_addr + handoff_flags], handoff_flag_unreal
    jnz .unreal_read
    jmp .bios_read
.unreal_read:
    call .refresh_unreal
    db 0x66, 0x8b, 0x1e
    dw tool_addr                         ; mov ebx, [tool_addr]
    push ds
    pop es
    mov di, ext_xfer_buf
.unreal_read_loop:
    db 0x64, 0x67, 0x8a, 0x03            ; mov al, [fs:ebx]
    stosb
    db 0x66, 0x43                        ; inc ebx
    loop .unreal_read_loop
    mov ax, [tool_readlen]
    add [tool_addr], ax
    adc word [tool_addr + 2], 0
    jmp .ok
.empty:
    clc
    ret
.bios_read:
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

.refresh_unreal:
    push ax
    pushf
    cli
    db 0x0f, 0x01, 0x16
    dw low_scratch_start + (.unreal_gdt_ptr - PHASE_BASE) ; lgdt [unreal_gdt_ptr]
    db 0x0f, 0x20, 0xc0                  ; mov eax, cr0
    db 0x0c, 0x01                        ; or al, 1
    db 0x0f, 0x22, 0xc0                  ; mov cr0, eax
    db 0xea
    dw low_scratch_start + (.refresh_pm - PHASE_BASE)
    dw 0x0008
.refresh_pm:
    mov ax, 0x0010
    db 0x8e, 0xe0                        ; mov fs, ax
    db 0x0f, 0x20, 0xc0                  ; mov eax, cr0
    db 0x24, 0xfe                        ; and al, ~1
    db 0x0f, 0x22, 0xc0                  ; mov cr0, eax
    db 0xea
    dw low_scratch_start + (.refresh_rm - PHASE_BASE)
    dw 0x0000
.refresh_rm:
    popf
    pop ax
    clc
    ret

align 8, db 0
.unreal_gdt:
    dq 0
    dw 0xffff, 0x0000
    db 0x00, 0x9a, 0x00, 0x00
    dw 0xffff, 0x0000
    db 0x00, 0x92, 0xcf, 0x00
.unreal_gdt_end:
.unreal_gdt_ptr:
    dw .unreal_gdt_end - .unreal_gdt - 1
    dd low_scratch_start + (.unreal_gdt - PHASE_BASE)
