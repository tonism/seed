%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name this phase's runtime load address"
%endif

mca_setup_port equ 0x0094
mca_adapter_setup_port equ 0x0096
mca_adapter_setup_enable equ 0x08
mca_pos_id_lo equ 0x0100
mca_pos_id_hi equ 0x0101
mca_pos_2 equ 0x0102
mca_pos_3 equ 0x0103
mca_pos_5 equ 0x0105
mca_ps2_setup_io_vga equ 0xa0
mca_id_ethernextmc equ 0x611f
mca_id_wd80x3_6fc0 equ 0x6fc0
mca_id_wd8013epa equ 0x61c8

; MCA POS discovery/configuration for 86Box-supported MCA NICs. Program a
; known-good resource tuple, then hand off to the normal driver metadata path.
mca_detect_phase:
    push ds
    push es
    xor ax, ax
    mov ds, ax
    mov es, ax

    mov dx, mca_setup_port
    in al, dx
    mov bh, al
    or al, mca_ps2_setup_io_vga
    out dx, al

    xor si, si
.slot:
    mov dx, mca_adapter_setup_port
    mov ax, si
    or al, mca_adapter_setup_enable
    out dx, al

    mov dx, mca_pos_id_lo
    in al, dx
    mov ah, al
    inc dx
    in al, dx
    xchg al, ah

    cmp ax, mca_id_ethernextmc
    je .ethernextmc
    cmp ax, mca_id_wd80x3_6fc0
    je .wd80x3_6fc0
    cmp ax, mca_id_wd8013epa
    je .wd8013epa

    inc si
    cmp si, 8
    jb .slot
    call .restore_setup
    stc
    jmp .done

.ethernextmc:
    ; POS2 bits: base index 0 => 0x300, IRQ index 1 => IRQ3, bit0 enables.
    mov dx, mca_pos_2
    mov al, 0x03
    out dx, al
    mov ax, 0x0300
    mov dl, family_ne2000
    jmp .store

.wd80x3_6fc0:
    ; WD8003ET/A and WD8003E/A: 0x280, IRQ3, shared RAM at DC000.
    mov dx, mca_pos_3
    mov al, 0xdc
    out dx, al
    mov dx, mca_pos_5
    xor al, al
    out dx, al
    mov dx, mca_pos_2
    mov al, 0x29
    out dx, al
    mov ax, 0x0280
    mov dl, family_wd8013
    jmp .store_wd_dc00

.wd8013epa:
    ; WD8013EP/A: base 0x800, IRQ3, 16K shared RAM at DC000.
    mov dx, mca_pos_3
    mov al, 0x1e
    out dx, al
    mov dx, mca_pos_5
    xor al, al
    out dx, al
    mov dx, mca_pos_2
    mov al, 0x01
    out dx, al
    mov ax, 0x0800
    mov dl, family_wd8013

.store_wd_dc00:
    or word [handoff_addr + handoff_flags], handoff_flag_wd_ram_dc00
.store:
    mov [handoff_addr + handoff_nic_base], ax
    mov byte [handoff_addr + handoff_nic_family], dl
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_nic_present | handoff_flag_config_resolved
    call .restore_setup
    clc

.done:
    pop es
    pop ds
    ret

.restore_setup:
    mov dx, mca_adapter_setup_port
    xor al, al
    out dx, al
    mov dx, mca_setup_port
    mov al, bh
    out dx, al
    ret
