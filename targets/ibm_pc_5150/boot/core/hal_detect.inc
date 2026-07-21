probe_network_card:
    mov si, nic_ports
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
    jmp wait_ticks
.known_3c503:
    mov al, family_3c503
    jmp store_auto_network_config
.detect_io_280:
    call autodetect_io_280
    jnc store_auto_network_config
    mov byte [menu_value_a], adapter_select_io_280
    jmp run_adapter_select_phase
.detect_ne:
    call autodetect_ne
    jnc store_auto_network_config
    mov byte [menu_value_a], adapter_select_ne
    jmp run_adapter_select_phase

store_auto_network_config:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    mov cx, load_ticks
    jmp wait_ticks

autodetect_io_280:
    call probe_wd8003_mac
    jc .probe_3c501
    call detect_wd_family
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

detect_wd_family:
    mov al, family_wd8003
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .done
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, wd_saprom + 6
    in al, dx
    and al, 0xff ^ wd_id_extra_ram
    cmp al, wd_type_wd8013ebt
    mov al, family_wd8003
    jne .done
    mov al, family_wd8013
.done:
    ret

autodetect_ne:
    jmp probe_ne_family
