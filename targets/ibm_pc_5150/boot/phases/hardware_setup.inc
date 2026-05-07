%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

hardware_setup_phase:
    call probe_network_card
    jc .failed
    call resolve_network_config
    call read_network_address
    clc
    ret
.failed:
    stc
    ret

probe_network_card:
    mov si, low_scratch_start + (hardware_nic_ports - PHASE_BASE)
.next:
    lodsw
    or ax, ax
    jz .missing
    mov dx, ax
    in al, dx
    cmp al, 0xff
    je .next
    mov [handoff_addr + handoff_nic_base], dx
    or word [handoff_addr + handoff_flags], handoff_flag_nic_present
    clc
    ret
.missing:
    stc
    ret

resolve_network_config:
    mov ax, [handoff_addr + handoff_nic_base]
    cmp ax, 0x250
    je .known_3c503
    cmp ax, 0x280
    je .detect_io_280
    cmp ax, 0x300
    je .detect_ne
    mov cx, load_ticks
    phase_call_res wait_ticks
    ret
.known_3c503:
    mov al, family_3c503
    call store_auto_network_config
    ret
.detect_io_280:
    call autodetect_io_280
    jnc store_auto_network_config
    mov byte [menu_value_a], adapter_select_io_280
    call adapter_select_phase
    ret
.detect_ne:
    call autodetect_ne
    jnc store_auto_network_config
    mov byte [menu_value_a], adapter_select_ne
    call adapter_select_phase
    ret

store_auto_network_config:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    mov cx, load_ticks
    phase_call_res wait_ticks
    ret

autodetect_io_280:
    call probe_wd8003_mac
    jc .probe_3c501
    mov al, family_wd8003
    clc
    ret
.probe_3c501:
    call probe_3c501_mac
    jc .failed
    mov al, family_3c501
    clc
    ret
.failed:
    stc
    ret

autodetect_ne:
    call probe_ne_family
    ret

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

adapter_select_phase:
    mov byte [menu_index], 0
    mov byte [blink_state], 0
    phase_call_res notify_question
    call .render_adapter_question
.input:
    phase_call_res blink_load_marker
    mov ah, 0x01
    int 0x16
    jz .input
    xor ah, ah
    int 0x16
    cmp al, 0x0d
    je .accept
    cmp ah, 0x48
    je .toggle
    cmp ah, 0x50
    jne .input
.toggle:
    xor byte [menu_index], 1
    call .draw_adapter_options
    jmp .input
.accept:
    cmp byte [menu_value_a], adapter_select_ne
    je .accept_ne
    mov al, family_3c501
    cmp byte [menu_index], 0
    je .store
    mov al, family_wd8003
    jmp .store
.accept_ne:
    mov al, family_ne2000
    cmp byte [menu_index], 0
    je .store
    mov al, family_ne1000
.store:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_user
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    phase_call_res clear_question_area
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    phase_call_res show_load_marker
    ret

.render_adapter_question:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, low_scratch_start + (adapter_prompt_text - PHASE_BASE)
    phase_call_res type_z
    call .type_adapter_options
    ret

.type_adapter_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_selected_attr]
    call .option_a_ptr
    phase_call_res type_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    call .option_b_ptr
    phase_call_res type_z
    ret

.draw_adapter_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 0
    jne .draw_first
    mov bl, [menu_selected_attr]
.draw_first:
    call .option_a_ptr
    call .print_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 1
    jne .draw_second
    mov bl, [menu_selected_attr]
.draw_second:
    call .option_b_ptr
    call .print_z
    ret

.option_a_ptr:
    mov si, low_scratch_start + (adapter_3c501_text - PHASE_BASE)
    cmp byte [menu_value_a], adapter_select_ne
    jne .option_done
    mov si, low_scratch_start + (adapter_ne2000_text - PHASE_BASE)
    ret
.option_b_ptr:
    mov si, low_scratch_start + (adapter_wd8003_text - PHASE_BASE)
    cmp byte [menu_value_a], adapter_select_ne
    jne .option_done
    mov si, low_scratch_start + (adapter_ne1000_text - PHASE_BASE)
.option_done:
    ret

.print_z:
    lodsb
    or al, al
    jz .print_done
    phase_call_res print_char
    jmp .print_z
.print_done:
    ret

hardware_nic_ports dw 0x250, 0x280, 0x2a0, 0x2c0, 0x2e0
                   dw 0x300, 0x310, 0x320, 0x330, 0x340
                   dw 0x350, 0x360, 0x380, 0x3a0
                   dw 0
adapter_prompt_text db 'adapter?', 0
adapter_ne2000_text db 'ne2000', 0
adapter_ne1000_text db 'ne1000', 0
adapter_3c501_text db '3c501', 0
adapter_wd8003_text db 'wd8003', 0

%unmacro phase_call_res 1
