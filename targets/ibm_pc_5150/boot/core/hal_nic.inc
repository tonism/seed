read_network_address:
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_3c501
    je read_3c501_mac
    cmp al, family_3c503
    je read_3c503_mac
    cmp al, family_ne1000
    je read_ne_prom_mac
    cmp al, family_ne2000
    je read_ne_prom_mac
    cmp al, family_wd8003
    je read_wd8003_mac
    ret

read_3c501_mac:
    call read_3c501_mac_raw
    call finish_handoff_mac
    ret

probe_3c501_mac:
    call read_3c501_mac_raw
    call validate_handoff_mac
    jc .failed
    cmp byte [handoff_addr + handoff_mac], 0x02
    jne .failed
    cmp byte [handoff_addr + handoff_mac + 1], 0x60
    jne .failed
    cmp byte [handoff_addr + handoff_mac + 2], 0x8c
    jne .failed
    clc
    ret
.failed:
    stc
    ret

read_3c501_mac_raw:
    xor ax, ax
    mov cx, 6
    mov di, handoff_addr + handoff_mac
.read:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_dataptr
    out dx, ax
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_saprom
    in al, dx
    stosb
    mov ax, di
    sub ax, handoff_addr + handoff_mac
    loop .read
    ret

read_3c503_mac:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    in al, dx
    push ax
    mov al, el2_ctrl_saprom | el2_ctrl_thin
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.read:
    in al, dx
    stosb
    inc dx
    loop .read

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    pop ax
    out dx, al

    call finish_handoff_mac
    ret

read_wd8003_mac:
    call read_wd8003_mac_raw
    call finish_handoff_mac
    ret

probe_wd8003_mac:
    call read_wd8003_mac_raw
    call validate_handoff_mac
    jc .failed
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, wd_saprom
    xor ah, ah
    mov cx, 8
.sum:
    in al, dx
    add ah, al
    inc dx
    loop .sum
    cmp ah, 0xff
    jne .failed
    clc
    ret
.failed:
    stc
    ret

read_wd8003_mac_raw:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, wd_saprom
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.read:
    in al, dx
    stosb
    inc dx
    loop .read
    ret

read_ne_prom_mac:
    call read_ne_prom_raw
    call copy_ne_mac
    call finish_handoff_mac
    ret

probe_ne_family:
    call read_ne_prom_raw
    call copy_ne_mac
    call validate_handoff_mac
    jc .failed
    mov al, family_ne1000
    cmp byte [ne_prom + 16], 0x57
    jne .done
    call ne_prom_is_paired
    jc .done
    mov al, family_ne2000
.done:
    clc
    ret
.failed:
    stc
    ret

read_ne_prom_raw:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_reset
    in al, dx
    out dx, al

    mov cx, 0xffff
.wait_reset:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    test al, ne_isr_reset
    jnz .reset_done
    loop .wait_reset
.reset_done:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_stop_nodma
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    mov al, 0xff
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_dcr
    mov al, ne_dcr_bytewide
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rbcr0
    mov al, ne_prom_len
    out dx, al
    inc dx
    xor al, al
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rsar0
    xor al, al
    out dx, al
    inc dx
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_remote_read
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_data
    mov di, ne_prom
    mov cx, ne_prom_len
.read:
    in al, dx
    stosb
    loop .read

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_nodma
    out dx, al
    ret

ne_prom_is_paired:
    mov si, ne_prom
    mov cx, 6
.pair:
    lodsb
    cmp al, [si]
    jne .no
    inc si
    loop .pair
    clc
    ret
.no:
    stc
    ret

copy_ne_mac:
    mov si, ne_prom
    mov al, [si]
    cmp al, [si + 1]
    jne .linear
    mov al, [si + 2]
    cmp al, [si + 3]
    jne .linear
    mov al, [si + 4]
    cmp al, [si + 5]
    jne .linear
    mov al, [si + 6]
    cmp al, [si + 7]
    jne .linear
    mov al, [si + 8]
    cmp al, [si + 9]
    jne .linear
    mov al, [si + 10]
    cmp al, [si + 11]
    jne .linear
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.paired:
    lodsb
    stosb
    inc si
    loop .paired
    ret
.linear:
    mov di, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb
    ret

clear_handoff_mac:
    mov di, handoff_addr + handoff_mac
    xor al, al
    mov cx, 6
    rep stosb
    ret

finish_handoff_mac:
    call validate_handoff_mac
    jnc .valid
    call clear_handoff_mac
    ret
.valid:
    or word [handoff_addr + handoff_flags], handoff_flag_mac_valid
    ret

validate_handoff_mac:
    test byte [handoff_addr + handoff_mac], 0x01
    jnz .invalid

    mov si, handoff_addr + handoff_mac
    xor al, al
    mov cx, 6
.nonzero:
    or al, [si]
    inc si
    loop .nonzero
    or al, al
    jz .invalid

    mov si, handoff_addr + handoff_mac
    mov al, 0xff
    mov cx, 6
.not_ff:
    and al, [si]
    inc si
    loop .not_ff
    cmp al, 0xff
    je .invalid

    clc
    ret
.invalid:
    stc
    ret

reset_hal_state:
    and word [handoff_addr + handoff_flags], handoff_flag_mda
    mov di, handoff_addr + handoff_nic_base
    xor ax, ax
    mov cx, (handoff_size_bytes - handoff_nic_base) / 2
    rep stosw
    mov byte [handoff_addr + handoff_status], handoff_status_booting
    mov byte [blink_state], 0
    ret

prepare_hal_path:
    mov byte [handoff_addr + handoff_net_status], net_status_identity_ready
    call selected_nic_has_packet_path
    jnc .packet
    clc
    ret
.packet:
    push ds
    pop es
    call wd_enable_shared_ram
    call wd_select_dp8390_base
    call init_ne_packet_io
    jc .done
    mov word [ne_rx_read_limit], ne_rx_sample_len
    call ne_try_receive_frame
    jc .done
    clc
.done:
    pushf
    call wd_restore_dp8390_base
    popf
    ret
