show_load_marker:
    mov [load_marker_char], al
    mov [load_marker_attr], bl
    push word [cursor_row]
    mov ah, [seed_col]
    mov al, seed_row
    mov [cursor_row], ax
    mov al, [load_marker_char]
    call print_char
    pop word [cursor_row]
    ret
