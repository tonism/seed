show_load_marker:
    mov [load_marker_char], al
    mov [load_marker_attr], bl
    mov byte [cursor_row], seed_row
    mov dl, [seed_col]
    mov [cursor_col], dl
    call print_char
    ret
