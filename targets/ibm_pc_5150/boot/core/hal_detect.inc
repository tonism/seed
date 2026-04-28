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
    call wait_ticks
    ret
.known_3c503:
    mov al, family_3c503
    call store_auto_network_config
    ret
.detect_io_280:
    call autodetect_io_280
    jnc store_auto_network_config
    mov word [menu_option_a], adapter_3c501_text
    mov word [menu_option_b], adapter_wd8003_text
    mov byte [menu_value_a], family_3c501
    mov byte [menu_value_b], family_wd8003
    call ask_adapter
    ret
.detect_ne:
    call autodetect_ne
    jnc store_auto_network_config
    mov word [menu_option_a], adapter_ne2000_text
    mov word [menu_option_b], adapter_ne1000_text
    mov byte [menu_value_a], family_ne2000
    mov byte [menu_value_b], family_ne1000
    call ask_adapter
    ret

store_auto_network_config:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    mov cx, load_ticks
    call wait_ticks
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
