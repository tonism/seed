%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name this phase's runtime load address"
%endif

isapnp_addr_port equ 0x0279
isapnp_write_data_port equ 0x0a79
isapnp_read_data_config equ 0x83
isapnp_read_data_port equ (isapnp_read_data_config << 2) | 3
isapnp_reg_set_read_data equ 0x00
isapnp_reg_serial_isolation equ 0x01
isapnp_reg_config_control equ 0x02
isapnp_reg_wake_csn equ 0x03
isapnp_reg_csn equ 0x06
isapnp_reg_ldn equ 0x07
isapnp_reg_activate equ 0x30
isapnp_reg_io_range_check equ 0x31
isapnp_reg_io_base_hi equ 0x60
isapnp_reg_io_base_lo equ 0x61
isapnp_reg_irq equ 0x70
isapnp_reg_irq_type equ 0x71
isapnp_reg_dma equ 0x74

; 86Box exposes RTL8019AS / DE-220P NE-compatible adapters and the AMD
; PCnet-ISA+ as ISA PnP NICs. Activate only those IDs, then let normal MAC/PROM
; detection and driver metadata selection choose NE.DRV or PCNET.DRV.
activate_pnp_nic_phase:
    mov si, PHASE_LOAD_ADDR + (isapnp_key_normal - PHASE_BASE)
    call isapnp_try_nic_key
    jnc .done
    call isapnp_return_to_key
    mov si, PHASE_LOAD_ADDR + (isapnp_key_rt - PHASE_BASE)
    call isapnp_try_nic_key
    jnc .done
    call isapnp_return_to_key
    stc
    ret
.done:
    clc
    ret

isapnp_try_nic_key:
    call isapnp_send_key
    mov ax, (isapnp_read_data_config << 8) | isapnp_reg_set_read_data
    call isapnp_write_reg
    mov ax, (0x04 << 8) | isapnp_reg_config_control
    call isapnp_write_reg
    xor ax, ax
    mov al, isapnp_reg_wake_csn
    call isapnp_write_reg
    mov di, handoff_addr + handoff_mac
    mov cx, 4
.read_id:
    call isapnp_read_serial_byte
    stosb
    loop .read_id
    mov cx, 5
.drain_serial:
    call isapnp_read_serial_byte
    loop .drain_serial
    xor bx, bx
    cmp word [handoff_addr + handoff_mac], 0x8c4a
    jne .check_dlink
    cmp word [handoff_addr + handoff_mac + 2], 0x1980
    je .match_ne2000
.check_dlink:
    cmp word [handoff_addr + handoff_mac], 0x8b11
    jne .check_pcnet
    cmp word [handoff_addr + handoff_mac + 2], 0x0122
    je .match_ne2000
.check_pcnet:
    cmp word [handoff_addr + handoff_mac], 0x9604
    jne .no_match
    cmp word [handoff_addr + handoff_mac + 2], 0xaa55
    jne .no_match
    mov bl, 5
    mov bh, family_pcnet
    jmp .configure
.match_ne2000:
    mov bh, family_ne2000
.configure:
    mov ax, (0x01 << 8) | isapnp_reg_csn
    call isapnp_write_reg
    xor ax, ax
    mov al, isapnp_reg_ldn
    call isapnp_write_reg
    mov ax, (0x03 << 8) | isapnp_reg_io_base_hi
    call isapnp_write_reg
    xor ax, ax
    mov al, isapnp_reg_io_base_lo
    call isapnp_write_reg
    mov ax, (profile_irq << 8) | isapnp_reg_irq
    call isapnp_write_reg
    mov ax, (0x02 << 8) | isapnp_reg_irq_type
    call isapnp_write_reg
    or bl, bl
    jz .activate
    mov ah, bl
    mov al, isapnp_reg_dma
    call isapnp_write_reg
.activate:
    xor ax, ax
    mov al, isapnp_reg_io_range_check
    call isapnp_write_reg
    mov ax, (0x01 << 8) | isapnp_reg_activate
    call isapnp_write_reg
    mov [handoff_addr + handoff_nic_family], bh
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    clc
    ret
.no_match:
    stc
    ret

isapnp_return_to_key:
    mov ax, (0x02 << 8) | isapnp_reg_config_control
    jmp isapnp_write_reg

isapnp_send_key:
    mov dx, isapnp_addr_port
    mov cx, 32
.write:
    lodsb
    out dx, al
    loop .write
    ret

isapnp_write_reg:
    mov dx, isapnp_addr_port
    out dx, al
    mov al, ah
    mov dx, isapnp_write_data_port
    out dx, al
    ret

isapnp_read_serial_byte:
    push bx
    push cx
    xor ah, ah
    mov bl, 1
    mov cx, 8
.bit:
    mov dx, isapnp_addr_port
    mov al, isapnp_reg_serial_isolation
    out dx, al
    mov dx, isapnp_read_data_port
    in al, dx
    cmp al, 0x55
    jne .second
    or ah, bl
.second:
    in al, dx
    shl bl, 1
    loop .bit
    mov al, ah
    pop cx
    pop bx
    ret

isapnp_key_normal:
    db 0x6a,0xb5,0xda,0xed,0xf6,0xfb,0x7d,0xbe
    db 0xdf,0x6f,0x37,0x1b,0x0d,0x86,0xc3,0x61
    db 0xb0,0x58,0x2c,0x16,0x8b,0x45,0xa2,0xd1
    db 0xe8,0x74,0x3a,0x9d,0xce,0xe7,0x73,0x39
isapnp_key_rt:
    db 0xda,0x6d,0x36,0x1b,0x8d,0x46,0x23,0x91
    db 0x48,0xa4,0xd2,0x69,0x34,0x9a,0x4d,0x26
    db 0x13,0x89,0x44,0xa2,0x51,0x28,0x94,0xca
    db 0x65,0x32,0x19,0x0c,0x86,0x43,0xa1,0x50
