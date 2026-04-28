sha256_init:
    push ds
    pop es
    mov si, sha256_initial_state
    mov di, sha256_state
    mov cx, 16
    rep movsw
    mov byte [sha256_block_len], 0
    clc
    ret

sha256_update:
    or cx, cx
    jz .done
.next:
    lodsb
    mov bx, sha256_block
    mov dl, [sha256_block_len]
    xor dh, dh
    add bx, dx
    mov [bx], al
    inc byte [sha256_block_len]
    cmp byte [sha256_block_len], 64
    jne .advance
    push si
    push cx
    call sha256_process_block
    pop cx
    pop si
    mov byte [sha256_block_len], 0
.advance:
    loop .next
.done:
    clc
    ret

sha256_process_block:
    push ds
    pop es
    mov si, sha256_block
    mov di, sha256_w
    mov cx, 16
.load_word:
    lodsb
    mov ah, al
    lodsb
    mov [di + 2], ax
    lodsb
    mov ah, al
    lodsb
    mov [di], ax
    add di, 4
    loop .load_word

    mov byte [sha256_schedule_count], 48
.schedule:
    mov si, di
    sub si, 8
    call sha256_small_sigma1_mem
    mov [sha256_t1], ax
    mov [sha256_t1 + 2], dx

    mov si, di
    sub si, 28
    call sha256_add_mem_to_t1

    mov si, di
    sub si, 60
    call sha256_small_sigma0_mem
    call sha256_add_pair_to_t1

    mov si, di
    sub si, 64
    call sha256_add_mem_to_t1

    mov ax, [sha256_t1]
    mov [di], ax
    mov ax, [sha256_t1 + 2]
    mov [di + 2], ax
    add di, 4
    dec byte [sha256_schedule_count]
    jnz .schedule

    mov si, sha256_state
    mov di, sha256_a
    mov cx, 16
    rep movsw

    mov word [sha256_w_ptr], sha256_w
    mov word [sha256_k_ptr], sha256_k
    mov byte [sha256_round_count], 64
.round:
    mov ax, [sha256_h]
    mov dx, [sha256_h + 2]
    mov [sha256_t1], ax
    mov [sha256_t1 + 2], dx

    mov si, sha256_e
    call sha256_big_sigma1_mem
    call sha256_add_pair_to_t1

    call sha256_ch
    call sha256_add_pair_to_t1

    mov si, [sha256_k_ptr]
    call sha256_add_mem_to_t1

    mov si, [sha256_w_ptr]
    call sha256_add_mem_to_t1

    mov si, sha256_a
    call sha256_big_sigma0_mem
    mov [sha256_t2], ax
    mov [sha256_t2 + 2], dx

    call sha256_maj
    call sha256_add_pair_to_t2

    mov ax, [sha256_d]
    mov dx, [sha256_d + 2]
    add ax, [sha256_t1]
    adc dx, [sha256_t1 + 2]
    mov [sha256_new_e], ax
    mov [sha256_new_e + 2], dx

    mov ax, [sha256_g]
    mov [sha256_h], ax
    mov ax, [sha256_g + 2]
    mov [sha256_h + 2], ax

    mov ax, [sha256_f]
    mov [sha256_g], ax
    mov ax, [sha256_f + 2]
    mov [sha256_g + 2], ax

    mov ax, [sha256_e]
    mov [sha256_f], ax
    mov ax, [sha256_e + 2]
    mov [sha256_f + 2], ax

    mov ax, [sha256_new_e]
    mov [sha256_e], ax
    mov ax, [sha256_new_e + 2]
    mov [sha256_e + 2], ax

    mov ax, [sha256_c]
    mov [sha256_d], ax
    mov ax, [sha256_c + 2]
    mov [sha256_d + 2], ax

    mov ax, [sha256_b]
    mov [sha256_c], ax
    mov ax, [sha256_b + 2]
    mov [sha256_c + 2], ax

    mov ax, [sha256_a]
    mov [sha256_b], ax
    mov ax, [sha256_a + 2]
    mov [sha256_b + 2], ax

    mov ax, [sha256_t1]
    mov dx, [sha256_t1 + 2]
    add ax, [sha256_t2]
    adc dx, [sha256_t2 + 2]
    mov [sha256_a], ax
    mov [sha256_a + 2], dx

    add word [sha256_w_ptr], 4
    add word [sha256_k_ptr], 4
    dec byte [sha256_round_count]
    jnz .round

    mov si, sha256_a
    mov di, sha256_state
    mov cx, 8
.add_state:
    mov ax, [si]
    add [di], ax
    mov ax, [si + 2]
    adc [di + 2], ax
    add si, 4
    add di, 4
    loop .add_state
    clc
    ret

sha256_add_mem_to_t1:
    mov ax, [si]
    add [sha256_t1], ax
    mov ax, [si + 2]
    adc [sha256_t1 + 2], ax
    ret

sha256_add_pair_to_t1:
    add [sha256_t1], ax
    adc [sha256_t1 + 2], dx
    ret

sha256_add_pair_to_t2:
    add [sha256_t2], ax
    adc [sha256_t2 + 2], dx
    ret

sha256_ch:
    mov ax, [sha256_e]
    mov bx, ax
    and bx, [sha256_f]
    not ax
    and ax, [sha256_g]
    xor ax, bx
    mov [sha256_tmp], ax

    mov dx, [sha256_e + 2]
    mov bx, dx
    and bx, [sha256_f + 2]
    not dx
    and dx, [sha256_g + 2]
    xor dx, bx
    mov ax, [sha256_tmp]
    ret

sha256_maj:
    mov ax, [sha256_a]
    mov bx, ax
    and bx, [sha256_b]
    mov dx, ax
    and dx, [sha256_c]
    xor bx, dx
    mov dx, [sha256_b]
    and dx, [sha256_c]
    xor bx, dx
    mov [sha256_tmp], bx

    mov ax, [sha256_a + 2]
    mov bx, ax
    and bx, [sha256_b + 2]
    mov dx, ax
    and dx, [sha256_c + 2]
    xor bx, dx
    mov dx, [sha256_b + 2]
    and dx, [sha256_c + 2]
    xor dx, bx
    mov ax, [sha256_tmp]
    ret

sha256_big_sigma0_mem:
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 2
    call sha256_rotr32
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 13
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 22
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    ret

sha256_big_sigma1_mem:
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 6
    call sha256_rotr32
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 11
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 25
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    ret

sha256_small_sigma0_mem:
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 7
    call sha256_rotr32
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 18
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 3
    call sha256_shr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    ret

sha256_small_sigma1_mem:
    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 17
    call sha256_rotr32
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 19
    call sha256_rotr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    mov [sha256_tmp], ax
    mov [sha256_tmp + 2], dx

    mov ax, [si]
    mov dx, [si + 2]
    mov cl, 10
    call sha256_shr32
    xor ax, [sha256_tmp]
    xor dx, [sha256_tmp + 2]
    ret

sha256_rotr32:
    xor ch, ch
    jcxz .done
.rotate:
    shr dx, 1
    rcr ax, 1
    jnc .no_wrap
    or dx, 0x8000
.no_wrap:
    loop .rotate
.done:
    ret

sha256_shr32:
    xor ch, ch
    jcxz .done
.shift:
    shr dx, 1
    rcr ax, 1
    loop .shift
.done:
    ret
