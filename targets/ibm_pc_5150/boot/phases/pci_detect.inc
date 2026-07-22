%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name this phase's runtime load address"
%endif

; PCI BIOS discovery for PCI NICs whose datapath can reuse an existing driver.
; Keep this behind the hardware_setup 386+ gate; the source remains cpu 8086.
pci_detect_phase:
    push ds
    push es
    mov ax, pci_bios_install
    int 0x1a
    jc .failed
    or ah, ah
    jnz .failed

    mov ax, pci_bios_find_device
    mov cx, pci_rtl8029_device
    mov dx, pci_realtek_vendor
    xor si, si
    int 0x1a
    jc .failed
    or ah, ah
    jnz .failed

    mov ax, pci_bios_read_config_word
    mov di, pci_config_bar0
    int 0x1a
    jc .failed
    or ah, ah
    jnz .failed

    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ax, cx
    test al, 0x01
    jz .failed
    and al, 0xfc
    or ax, ax
    jz .failed

    mov [handoff_addr + handoff_nic_base], ax
    mov byte [handoff_addr + handoff_nic_family], family_ne2000
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], 0
    or word [handoff_addr + handoff_flags], handoff_flag_nic_present | handoff_flag_config_resolved
    pop es
    pop ds
    clc
    ret
.failed:
    pop es
    pop ds
    stc
    ret
