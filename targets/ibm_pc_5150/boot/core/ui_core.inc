type_z:
    lodsb
    or al, al
    jz .done
    call type_char
    jmp type_z
.done:
    ret

type_char:
    call print_char
    mov cx, type_ticks
    call wait_ticks
    ret

print_char:
    push ax
    push bx
    mov ah, 0x02
    mov bh, 0x00
    mov dh, [cursor_row]
    mov dl, [cursor_col]
    int 0x10
    pop bx
    pop ax

    push bx
    push cx
    mov ah, 0x09
    mov bh, 0x00
    mov cx, 0x0001
    int 0x10
    pop cx
    pop bx

    inc byte [cursor_col]
    ret

set_bios_cursor:
    mov ah, 0x02
    mov bh, 0x00
    mov dh, [cursor_row]
    mov dl, [cursor_col]
    int 0x10
    ret

wait_ticks:
    push ax
    push bx
    push cx
    mov bx, [0x046c]
.next_tick:
    hlt
    mov ax, [0x046c]
    cmp ax, bx
    je .next_tick
    mov bx, ax
    loop .next_tick
    pop cx
    pop bx
    pop ax
    ret
