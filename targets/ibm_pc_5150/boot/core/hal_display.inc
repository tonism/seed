init_handoff:
    mov di, handoff_addr
    xor ax, ax
    mov cx, handoff_size_bytes / 2
.clear:
    stosw
    loop .clear
    mov byte [handoff_addr + handoff_magic], 'S'
    mov byte [handoff_addr + handoff_magic + 1], 'E'
    mov byte [handoff_addr + handoff_magic + 2], 'E'
    mov byte [handoff_addr + handoff_magic + 3], 'D'
    mov byte [handoff_addr + handoff_version], handoff_struct_version
    mov byte [handoff_addr + handoff_size], handoff_size_bytes
    mov word [handoff_addr + handoff_build], build_number
    mov byte [handoff_addr + handoff_boot_drive], dl
    mov word [handoff_addr + handoff_ram_top], bp
    mov byte [handoff_addr + handoff_status], handoff_status_booting
    ret

detect_display:
    mov ah, 0x0f
    int 0x10
    mov [handoff_addr + handoff_video_mode], al
    mov [handoff_addr + handoff_video_cols], ah
    mov [screen_cols], ah
    sub ah, seed_len
    shr ah, 1
    mov [seed_col], ah
    mov [handoff_addr + handoff_seed_col], ah
    mov byte [form_left_col], 2
    mov byte [form_field_col], 20
    cmp byte [screen_cols], 80
    jb .display_kind
    mov al, [seed_col]
    sub al, 14
    mov [form_left_col], al
    mov al, [seed_col]
    add al, 10
    mov [form_field_col], al
.display_kind:
    cmp byte [handoff_addr + handoff_video_mode], 0x07
    jne .color
    or word [handoff_addr + handoff_flags], handoff_flag_mda
    mov byte [seed_attr], seed_attr_mda
    mov byte [build_attr], build_attr_mda
    mov byte [load_attr], load_attr_mda
    mov byte [crypto_attr], crypto_attr_mda
    mov byte [ready_attr], ready_attr_mda
    mov byte [question_attr], question_attr_mda
    mov byte [error_attr], error_attr_mda
    mov byte [menu_selected_attr], menu_selected_attr_mda
    mov byte [menu_idle_attr], menu_idle_attr_mda
    ret
.color:
    ret

clear_screen:
    mov ax, 0x0600
    mov bh, 0x07
    xor cx, cx
    mov dh, 0x18
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

hide_cursor:
    mov ah, 0x01
    mov ch, 0x20
    mov cl, 0x00
    int 0x10
    ret

show_cursor:
    call set_bios_cursor
    mov ah, 0x01
    mov ch, 0x06
    mov cl, 0x07
    int 0x10
    ret
