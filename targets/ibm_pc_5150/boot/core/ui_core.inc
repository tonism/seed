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
    mov ah, 0x09
    mov bh, 0x00
    mov cx, 0x0001
    int 0x10
    pop bx

    inc byte [cursor_col]
    ret

wait_ticks:
    mov dx, [0x046c]
.next_tick:
    hlt
    mov ax, [0x046c]
    cmp ax, dx
    je .next_tick
    mov dx, ax
    loop .next_tick
    ret
