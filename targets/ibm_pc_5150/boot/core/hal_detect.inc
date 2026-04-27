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
    je .ask_io_280
    cmp ax, 0x300
    je .ask_ne
    mov cx, load_ticks
    call wait_ticks
    ret
.known_3c503:
    mov byte [handoff_addr + handoff_nic_family], family_3c503
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    mov cx, load_ticks
    call wait_ticks
    ret
.ask_io_280:
    mov word [menu_option_a], adapter_3c501_text
    mov word [menu_option_b], adapter_wd8003_text
    mov byte [menu_value_a], family_3c501
    mov byte [menu_value_b], family_wd8003
    call ask_adapter
    ret
.ask_ne:
    mov word [menu_option_a], adapter_ne2000_text
    mov word [menu_option_b], adapter_ne1000_text
    mov byte [menu_value_a], family_ne2000
    mov byte [menu_value_b], family_ne1000
    call ask_adapter
    ret
