print_z:
    lodsb
    or al, al
    jz .done
    call print_char
    jmp print_z
.done:
    ret

blink_load_marker:
    call set_seed_cursor
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    xor byte [blink_state], 1
    jnz .show
    mov al, ' '
.show:
    call print_char
    mov cx, 2
    call wait_ticks
    ret

show_load_marker:
    mov [load_marker_char], al
    mov [load_marker_attr], bl
    call set_seed_cursor
    mov al, [load_marker_char]
    call print_char
    ret

clear_question_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, seed_row
    xor cl, cl
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

notify_question:
    mov ax, 6087
    call speaker_tone
    mov cx, 2
    call wait_ticks
    call speaker_off
    ret

notify_failure:
    mov ax, 5424
    call speaker_tone
    mov cx, 2
    call wait_ticks
    mov ax, 7231
    call speaker_tone
    mov cx, 3
    call wait_ticks
    call speaker_off
    ret

speaker_tone:
    push ax
    mov al, 0xb6
    out 0x43, al
    pop ax
    out 0x42, al
    mov al, ah
    out 0x42, al
    in al, 0x61
    or al, 0x03
    out 0x61, al
    ret

speaker_off:
    in al, 0x61
    and al, 0xfc
    out 0x61, al
    ret
