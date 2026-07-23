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

    mov ax, (0xfc << 8) | family_ne2000
    mov cx, pci_rtl8029_device
    mov dx, pci_realtek_vendor
    call .try_io_bar0_device
    jnc .done

    mov ax, (0xe0 << 8) | family_pcnet
    mov cx, pci_pcnet_device
    mov dx, pci_amd_vendor
    call .try_io_bar0_device
    jc .failed

.done:
    pop es
    pop ds
    clc
    ret
.failed:
    pop es
    pop ds
    stc
    ret

; In: AL = Seed NIC family, AH = BAR0 low-byte mask, CX = device, DX = vendor.
.try_io_bar0_device:
    push ax
    mov ax, pci_bios_find_device
    xor si, si
    int 0x1a
    jc .try_failed_pop
    or ah, ah
    jnz .try_failed_pop

    mov ax, pci_bios_read_config_word
    mov di, pci_config_bar0
    int 0x1a
    jc .try_failed_pop
    or ah, ah
    jnz .try_failed_pop

    pop dx
    mov ax, cx
    test al, 0x01
    jz .try_failed
    and al, dh
    or ax, ax
    jz .try_failed

    xor cx, cx
    mov ds, cx
    mov es, cx
    mov [handoff_addr + handoff_nic_base], ax
    mov byte [handoff_addr + handoff_nic_family], dl
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], 0
    or word [handoff_addr + handoff_flags], handoff_flag_nic_present | handoff_flag_config_resolved
    clc
    ret

.try_failed_pop:
    pop ax
.try_failed:
    stc
    ret
