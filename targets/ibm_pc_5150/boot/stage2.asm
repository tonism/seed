bits 16
org 0x8000

%ifndef STAGE2_SECTORS
%define STAGE2_SECTORS 7
%endif

build_number equ 5
handoff_addr equ 0x0600
handoff_magic equ 0
handoff_version equ 4
handoff_size equ 5
handoff_build equ 6
handoff_flags equ 8
handoff_boot_drive equ 10
handoff_video_mode equ 11
handoff_video_cols equ 12
handoff_seed_col equ 13
handoff_nic_base equ 14
handoff_nic_family equ 16
handoff_config_source equ 17
handoff_nic_irq equ 18
handoff_mac equ 19
handoff_status equ 25
handoff_net_status equ 26
handoff_net_error equ 27
handoff_ip_addr equ 28
handoff_router_addr equ 32
handoff_dns_addr equ 36
handoff_size_bytes equ 40
handoff_struct_version equ 2
handoff_flag_mda equ 0x0001
handoff_flag_nic_present equ 0x0002
handoff_flag_config_resolved equ 0x0004
handoff_flag_mac_valid equ 0x0008
handoff_status_booting equ 1
handoff_status_no_nic equ 2
handoff_status_ready equ 3
handoff_status_network_failed equ 4
net_status_none equ 0
net_status_identity_ready equ 1
net_status_packet_ready equ 2
net_status_tx_ready equ 3
net_status_rx_poll_ready equ 4
net_status_rx_frame_read equ 5
net_status_dhcp_discover_sent equ 6
net_status_dhcp_offer_received equ 7
net_error_none equ 0
net_error_ne_init equ 1
net_error_ne_tx equ 2
net_error_ne_rx equ 3
net_error_dhcp_offer equ 4
net_error_ne_rx_dma equ 5
net_error_ne_rx_header equ 6
net_error_ne_rx_count equ 7
seed_attr_cga equ 0x0f
build_attr_cga equ 0x08
load_attr_cga equ 0x0f
error_attr_cga equ 0x0c
menu_selected_attr_cga equ 0x0f
menu_idle_attr_cga equ 0x08
seed_attr_mda equ 0x0f
build_attr_mda equ 0x07
load_attr_mda equ 0x0f
error_attr_mda equ 0x0f
menu_selected_attr_mda equ 0x0f
menu_idle_attr_mda equ 0x07
seed_len equ 4
seed_row equ 12
question_row equ seed_row + 2
load_ticks equ 6
type_ticks equ 1
done_ticks equ 9
config_auto equ 1
config_user equ 2
profile_irq equ 3
family_3c503 equ 1
family_ne2000 equ 2
family_ne1000 equ 3
family_3c501 equ 4
family_wd8003 equ 5
el1_dataptr equ 0x08
el1_saprom equ 0x0c
el2_ctrl equ 0x406
el2_ctrl_thin equ 0x02
el2_ctrl_saprom equ 0x04
ne_cr equ 0x00
ne_bnry equ 0x03
ne_tsr equ 0x04
ne_tbcr0 equ 0x05
ne_isr equ 0x07
ne_rsar0 equ 0x08
ne_rbcr0 equ 0x0a
ne_tpsr equ 0x04
ne_rcr equ 0x0c
ne_tcr equ 0x0d
ne_dcr equ 0x0e
ne_imr equ 0x0f
ne_data equ 0x10
ne_reset equ 0x1f
ne_cmd_stop_nodma equ 0x21
ne_cmd_start_nodma equ 0x22
ne_cmd_start_page1 equ 0x62
ne_cmd_remote_read equ 0x0a
ne_cmd_remote_write equ 0x12
ne_cmd_transmit equ 0x26
ne_isr_reset equ 0x80
ne_isr_rdc equ 0x40
ne_isr_txe equ 0x08
ne_isr_ptx equ 0x02
ne_dcr_bytewide equ 0x48
ne_read_dma_wait_count equ 0x0800
ne_prom_len equ 32
ne_rx_header_len equ 4
ne_rx_sample_len equ 64
ne_rx_max_count equ 1600
dhcp_rx_frame_len equ 384
ne_rcr_broadcast equ 0x04
ne_rsr_prx equ 0x01
ne_tcr_loopback equ 0x02
ne_tx_start_1k equ 0x20
ne_rx_start_1k equ 0x26
ne_rx_stop_1k equ 0x40
ne_tx_start_2k equ 0x40
ne_rx_start_2k equ 0x46
ne_rx_stop_2k equ 0x80
eth_header_len equ 14
ipv4_header_len equ 20
udp_header_len equ 8
dhcp_fixed_len equ 236
dhcp_options_len equ 26
dhcp_payload_len equ dhcp_fixed_len + dhcp_options_len
dhcp_udp_len equ udp_header_len + dhcp_payload_len
dhcp_ip_len equ ipv4_header_len + dhcp_udp_len
dhcp_frame_len equ eth_header_len + dhcp_ip_len
dhcp_ip_checksum equ 0x79cc
dhcp_bootp_offset equ eth_header_len + ipv4_header_len + udp_header_len
dhcp_yiaddr_offset equ dhcp_bootp_offset + 16
dhcp_chaddr_offset equ dhcp_bootp_offset + 28
dhcp_cookie_offset equ dhcp_bootp_offset + dhcp_fixed_len
dhcp_options_offset equ dhcp_cookie_offset + 4
dhcp_offer_wait_count equ 1
wd_saprom equ 0x08

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    sti
    cld

    call init_handoff
    call detect_display
    call clear_screen
    call hide_cursor

    call set_seed_cursor
    mov bl, [load_attr]
    mov al, ' '
    call print_char
    call probe_network_card
    jc network_error

    call set_seed_cursor
    mov al, '.'
    call print_char
    call resolve_network_config
    call read_network_address
    call prepare_network_path
    jc network_setup_error

    call set_seed_cursor
    mov al, 'o'
    call print_char
    mov byte [handoff_addr + handoff_status], handoff_status_ready
    mov cx, load_ticks
    call wait_ticks

    call set_seed_cursor
    mov si, seed_text
    mov bl, [seed_attr]
    call type_z

    mov al, ' '
    mov bl, [build_attr]
    call type_char

    mov si, build_text
    call type_z

    mov cx, done_ticks
    call wait_ticks

halt:
    hlt
    jmp halt

network_error:
    mov byte [handoff_addr + handoff_status], handoff_status_no_nic
    call set_seed_cursor
    mov bl, [error_attr]
    mov al, '+'
    call print_char

    inc byte [cursor_col]
    call notify_failure
    mov si, network_error_text
    call type_z
    call ask_failure_action
    jmp halt

network_setup_error:
    mov byte [handoff_addr + handoff_status], handoff_status_network_failed
    call set_seed_cursor
    mov bl, [error_attr]
    mov al, '+'
    call print_char

    inc byte [cursor_col]
    call notify_failure
    mov si, network_setup_error_text
    call type_z
    call ask_failure_action
    jmp halt

set_seed_cursor:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    mov [cursor_col], al
    ret

init_handoff:
    mov di, handoff_addr
    xor ax, ax
    mov cx, handoff_size_bytes / 2
.clear:
    stosw
    loop .clear
    mov byte [handoff_addr + handoff_magic], 'S'
    mov byte [handoff_addr + handoff_magic + 1], 'E'
    mov byte [handoff_addr + handoff_magic + 2], 'E'
    mov byte [handoff_addr + handoff_magic + 3], 'D'
    mov byte [handoff_addr + handoff_version], handoff_struct_version
    mov byte [handoff_addr + handoff_size], handoff_size_bytes
    mov word [handoff_addr + handoff_build], build_number
    mov byte [handoff_addr + handoff_boot_drive], dl
    mov byte [handoff_addr + handoff_status], handoff_status_booting
    ret

detect_display:
    mov ah, 0x0f
    int 0x10
    mov [handoff_addr + handoff_video_mode], al
    mov [handoff_addr + handoff_video_cols], ah
    mov [screen_cols], ah
    sub ah, seed_len
    shr ah, 1
    mov [seed_col], ah
    mov [handoff_addr + handoff_seed_col], ah
    cmp al, 0x07
    jne .color
    or word [handoff_addr + handoff_flags], handoff_flag_mda
    mov byte [seed_attr], seed_attr_mda
    mov byte [build_attr], build_attr_mda
    mov byte [load_attr], load_attr_mda
    mov byte [error_attr], error_attr_mda
    mov byte [menu_selected_attr], menu_selected_attr_mda
    mov byte [menu_idle_attr], menu_idle_attr_mda
    ret
.color:
    ret

clear_screen:
    mov ax, 0x0600
    mov bh, 0x07
    xor cx, cx
    mov dh, 0x18
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

hide_cursor:
    mov ah, 0x01
    mov ch, 0x20
    mov cl, 0x00
    int 0x10
    ret

type_z:
    lodsb
    or al, al
    jz .done
    call type_char
    jmp type_z
.done:
    ret

type_char:
    call print_char
    mov cx, type_ticks
    call wait_ticks
    ret

print_char:
    push ax
    push bx
    mov ah, 0x02
    mov bh, 0x00
    mov dh, [cursor_row]
    mov dl, [cursor_col]
    int 0x10
    pop bx
    pop ax

    push bx
    push cx
    mov ah, 0x09
    mov bh, 0x00
    mov cx, 0x0001
    int 0x10
    pop cx
    pop bx

    inc byte [cursor_col]
    ret

wait_ticks:
    push ax
    push bx
    push cx
    mov bx, [0x046c]
.next_tick:
    hlt
    mov ax, [0x046c]
    cmp ax, bx
    je .next_tick
    mov bx, ax
    loop .next_tick
    pop cx
    pop bx
    pop ax
    ret

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

ask_adapter:
    mov byte [menu_index], 0
    mov byte [blink_state], 0
    call notify_question
    call render_adapter_question
.input:
    call blink_load_marker
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
    call draw_menu_options
    jmp .input
.accept:
    mov al, [menu_value_a]
    cmp byte [menu_index], 0
    je .store
    mov al, [menu_value_b]
.store:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_user
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    call clear_question_area
    ret

ask_failure_action:
    mov word [menu_option_a], retry_text
    mov word [menu_option_b], restart_text
    mov byte [menu_index], 0
    call type_menu_options
.input:
    hlt
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
    call draw_menu_options
    jmp .input
.accept:
    cmp byte [menu_index], 0
    jne restart_machine
    jmp start

restart_machine:
    mov word [0x0472], 0x1234
    jmp 0xffff:0x0000

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

    call finish_handoff_mac
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
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, wd_saprom
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.read:
    in al, dx
    stosb
    inc dx
    loop .read

    call finish_handoff_mac
    ret

read_ne_prom_mac:
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

    call copy_ne_mac
    call finish_handoff_mac
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

prepare_network_path:
    mov byte [handoff_addr + handoff_net_status], net_status_identity_ready
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_ne1000
    je .ne
    cmp al, family_ne2000
    je .ne
    clc
    ret
.ne:
    call init_ne_packet_io
    jc .done
    mov word [ne_rx_read_limit], ne_rx_sample_len
    call ne_try_receive_frame
    jc .done
    call ne_transmit_dhcp_discover
    jc .done
    call ne_wait_for_dhcp_offer
.done:
    ret

init_ne_packet_io:
    test word [handoff_addr + handoff_flags], handoff_flag_mac_valid
    jnz .have_mac
    mov byte [handoff_addr + handoff_net_error], net_error_ne_init
    stc
    ret
.have_mac:
    mov byte [ne_tx_start], ne_tx_start_2k
    mov byte [ne_rx_start], ne_rx_start_2k
    mov byte [ne_rx_stop], ne_rx_stop_2k
    cmp byte [handoff_addr + handoff_nic_family], family_ne2000
    je .pages_ready
    mov byte [ne_tx_start], ne_tx_start_1k
    mov byte [ne_rx_start], ne_rx_start_1k
    mov byte [ne_rx_stop], ne_rx_stop_1k
.pages_ready:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_stop_nodma
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_dcr
    mov al, ne_dcr_bytewide
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rbcr0
    xor al, al
    out dx, al
    inc dx
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rcr
    mov al, ne_rcr_broadcast
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_tcr
    mov al, ne_tcr_loopback
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    inc dx
    mov al, [ne_rx_start]
    out dx, al
    inc dx
    mov al, [ne_rx_stop]
    out dx, al
    inc dx
    mov al, [ne_rx_start]
    out dx, al
    inc dx
    mov al, [ne_tx_start]
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    mov al, 0xff
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_imr
    xor al, al
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_page1
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    inc dx
    mov si, handoff_addr + handoff_mac
    mov cx, 6
.write_mac:
    lodsb
    out dx, al
    inc dx
    loop .write_mac

    mov al, [ne_rx_start]
    inc al
    out dx, al

    inc dx
    xor al, al
    mov cx, 8
.clear_mar:
    out dx, al
    inc dx
    loop .clear_mar

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_nodma
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_tcr
    xor al, al
    out dx, al

    mov byte [handoff_addr + handoff_net_status], net_status_packet_ready
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

ne_transmit_dhcp_discover:
    call build_dhcp_discover_frame

    mov si, ne_tx_frame
    mov cx, dhcp_frame_len
    call ne_transmit_frame
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_discover_sent
.done:
    ret

ne_transmit_frame:
    mov [ne_tx_len], cx

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    mov al, ne_isr_rdc | ne_isr_txe | ne_isr_ptx
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rbcr0
    mov ax, [ne_tx_len]
    out dx, al
    inc dx
    mov al, ah
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rsar0
    xor al, al
    out dx, al
    inc dx
    mov al, [ne_tx_start]
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_remote_write
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_data
    mov cx, [ne_tx_len]
.write_frame:
    lodsb
    out dx, al
    loop .write_frame

    mov cx, 0xffff
.wait_dma:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    test al, ne_isr_rdc
    jnz .dma_done
    loop .wait_dma
    jmp .failed
.dma_done:
    mov al, ne_isr_rdc
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_tpsr
    mov al, [ne_tx_start]
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_tbcr0
    mov ax, [ne_tx_len]
    out dx, al
    inc dx
    mov al, ah
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_transmit
    out dx, al

    mov cx, 0xffff
.wait_tx:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    test al, ne_isr_ptx | ne_isr_txe
    jnz .tx_done
    loop .wait_tx
    jmp .failed
.tx_done:
    mov al, ne_isr_ptx | ne_isr_txe
    out dx, al
    mov byte [handoff_addr + handoff_net_status], net_status_tx_ready
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_tx
    stc
    ret

build_dhcp_discover_frame:
    mov di, ne_tx_frame
    xor al, al
    mov cx, dhcp_frame_len
    rep stosb

    mov di, ne_tx_frame
    mov al, 0xff
    mov cx, 6
    rep stosb

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov al, 0x08
    stosb
    xor al, al
    stosb

    mov al, 0x45
    stosb
    xor al, al
    stosb
    mov al, dhcp_ip_len >> 8
    stosb
    mov al, dhcp_ip_len & 0xff
    stosb
    xor ax, ax
    stosw
    stosw
    mov al, 64
    stosb
    mov al, 17
    stosb
    mov al, dhcp_ip_checksum >> 8
    stosb
    mov al, dhcp_ip_checksum & 0xff
    stosb
    xor al, al
    mov cx, 4
    rep stosb
    mov al, 0xff
    mov cx, 4
    rep stosb

    xor al, al
    stosb
    mov al, 68
    stosb
    xor al, al
    stosb
    mov al, 67
    stosb
    mov al, dhcp_udp_len >> 8
    stosb
    mov al, dhcp_udp_len & 0xff
    stosb
    xor ax, ax
    stosw

    mov al, 1
    stosb
    stosb
    mov al, 6
    stosb
    xor al, al
    stosb
    mov al, 'S'
    stosb
    mov al, 'E'
    stosb
    stosb
    mov al, 'D'
    stosb
    xor ax, ax
    stosw
    mov al, 0x80
    stosb
    xor al, al
    stosb
    add di, 16

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb
    add di, 10 + 64 + 128

    mov al, 99
    stosb
    mov al, 130
    stosb
    mov al, 83
    stosb
    mov al, 99
    stosb

    mov al, 53
    stosb
    mov al, 1
    stosb
    stosb

    mov al, 55
    stosb
    mov al, 3
    stosb
    mov al, 1
    stosb
    mov al, 3
    stosb
    mov al, 6
    stosb

    mov al, 61
    stosb
    mov al, 7
    stosb
    mov al, 1
    stosb
    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov al, 57
    stosb
    mov al, 2
    stosb
    stosb
    mov al, 64
    stosb

    mov al, 255
    stosb
    ret

ne_try_receive_frame:
    mov word [ne_rx_sample_count], 0
    call ne_read_ring_pointers
    call ne_select_next_rx_page
    mov al, [ne_next_page]
    cmp al, [ne_current_page]
    jne .packet_waiting
    mov byte [handoff_addr + handoff_net_status], net_status_rx_poll_ready
    clc
    ret

.packet_waiting:
    xor bl, bl
    mov bh, [ne_next_page]
    mov cx, ne_rx_header_len
    mov di, ne_rx_header
    call ne_remote_read_bytes
    jc .dma_failed

    mov al, [ne_rx_header + 1]
    cmp al, [ne_rx_start]
    jb .header_failed
    cmp al, [ne_rx_stop]
    jae .header_failed

    test byte [ne_rx_header], ne_rsr_prx
    jz .release_frame

    mov al, [ne_rx_header + 2]
    mov ah, [ne_rx_header + 3]
    mov [ne_rx_count], ax
    cmp ax, ne_rx_header_len
    jbe .count_failed
    cmp ax, ne_rx_max_count
    ja .count_failed
    sub ax, ne_rx_header_len
    mov [ne_rx_sample_count], ax
    or ax, ax
    jz .release_frame
    cmp ax, [ne_rx_read_limit]
    jbe .sample_count_ready
    mov ax, [ne_rx_read_limit]
.sample_count_ready:
    mov [ne_rx_sample_count], ax

    mov bl, ne_rx_header_len
    mov bh, [ne_next_page]
    mov cx, ax
    mov di, ne_tx_frame
    call ne_remote_read_bytes
    jc .dma_failed

    mov byte [handoff_addr + handoff_net_status], net_status_rx_frame_read

.release_frame:
    call ne_release_rx_frame
    clc
    ret

.count_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp .release_frame

.dma_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_dma
    stc
    ret

.header_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_header
    stc
    ret

ne_wait_for_dhcp_offer:
    mov word [ne_rx_read_limit], dhcp_rx_frame_len
    mov word [dhcp_wait_count], dhcp_offer_wait_count
.poll:
    call ne_try_receive_frame
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_dhcp_offer
    jnc .done
.wait:
    call blink_load_marker
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_discover_sent
    mov byte [handoff_addr + handoff_net_error], net_error_dhcp_offer
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_discover_sent
    clc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_offer_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

parse_dhcp_offer:
    cmp word [ne_rx_sample_count], dhcp_options_offset + 3
    jb .not_offer
    cmp word [ne_tx_frame + 12], 0x0008
    jne .not_offer
    cmp byte [ne_tx_frame + eth_header_len + 9], 17
    jne .not_offer
    cmp word [ne_tx_frame + eth_header_len + ipv4_header_len], 0x4300
    jne .not_offer
    cmp word [ne_tx_frame + eth_header_len + ipv4_header_len + 2], 0x4400
    jne .not_offer
    cmp byte [ne_tx_frame + dhcp_bootp_offset], 2
    jne .not_offer
    cmp byte [ne_tx_frame + dhcp_bootp_offset + 1], 1
    jne .not_offer
    cmp byte [ne_tx_frame + dhcp_bootp_offset + 2], 6
    jne .not_offer
    cmp word [ne_tx_frame + dhcp_bootp_offset + 4], 0x4553
    jne .not_offer
    cmp word [ne_tx_frame + dhcp_bootp_offset + 6], 0x4445
    jne .not_offer

    mov si, ne_tx_frame + dhcp_chaddr_offset
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.check_mac:
    lodsb
    cmp al, [di]
    jne .not_offer
    inc di
    loop .check_mac

    cmp word [ne_tx_frame + dhcp_cookie_offset], 0x8263
    jne .not_offer
    cmp word [ne_tx_frame + dhcp_cookie_offset + 2], 0x6353
    jne .not_offer

    mov di, handoff_addr + handoff_ip_addr
    xor ax, ax
    mov cx, 6
    rep stosw
    mov byte [dhcp_message_type], 0

    mov ax, [ne_rx_sample_count]
    sub ax, dhcp_options_offset
    mov [dhcp_options_left], ax
    mov si, ne_tx_frame + dhcp_options_offset
.option:
    cmp word [dhcp_options_left], 0
    je .check_type
    lodsb
    dec word [dhcp_options_left]
    cmp al, 0
    je .option
    cmp al, 255
    je .check_type
    mov [dhcp_option_code], al
    cmp word [dhcp_options_left], 0
    je .check_type
    lodsb
    dec word [dhcp_options_left]
    xor ah, ah
    mov [dhcp_option_len], ax
    cmp [dhcp_options_left], ax
    jb .check_type
    cmp byte [dhcp_option_code], 53
    jne .router
    cmp ax, 1
    jb .skip
    mov al, [si]
    mov [dhcp_message_type], al
    jmp .skip
.router:
    cmp byte [dhcp_option_code], 3
    jne .dns
    cmp ax, 4
    jb .skip
    push si
    mov di, handoff_addr + handoff_router_addr
    mov cx, 4
    rep movsb
    pop si
    jmp .skip
.dns:
    cmp byte [dhcp_option_code], 6
    jne .skip
    cmp ax, 4
    jb .skip
    push si
    mov di, handoff_addr + handoff_dns_addr
    mov cx, 4
    rep movsb
    pop si
.skip:
    mov cx, [dhcp_option_len]
    add si, cx
    sub [dhcp_options_left], cx
    jmp .option
.check_type:
    cmp byte [dhcp_message_type], 2
    jne .not_offer
    mov si, ne_tx_frame + dhcp_yiaddr_offset
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb
    clc
    ret
.not_offer:
    mov di, handoff_addr + handoff_ip_addr
    xor ax, ax
    mov cx, 6
    rep stosw
    stc
    ret

ne_read_ring_pointers:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_page1
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    mov [ne_current_page], al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_nodma
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_bnry
    in al, dx
    mov [ne_boundary_page], al
    ret

ne_select_next_rx_page:
    mov al, [ne_boundary_page]
    inc al
    cmp al, [ne_rx_stop]
    jb .selected
    mov al, [ne_rx_start]
.selected:
    mov [ne_next_page], al
    ret

ne_release_rx_frame:
    mov al, [ne_rx_header + 1]
    dec al
    cmp al, [ne_rx_start]
    jae .write_boundary
    mov al, [ne_rx_stop]
    dec al
.write_boundary:
    mov [ne_boundary_page], al
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_bnry
    out dx, al
    ret

ne_remote_read_bytes:
    mov [ne_dma_addr], bx
    mov [ne_dma_count], cx

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    mov al, ne_isr_rdc
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rbcr0
    mov ax, [ne_dma_count]
    out dx, al
    inc dx
    mov al, ah
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rsar0
    mov ax, [ne_dma_addr]
    out dx, al
    inc dx
    mov al, ah
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_remote_read
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_data
    mov cx, [ne_dma_count]
.read_byte:
    in al, dx
    stosb
    loop .read_byte

    mov cx, ne_read_dma_wait_count
.wait_dma:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    test al, ne_isr_rdc
    jnz .done
    loop .wait_dma
    call ne_finish_remote_dma
    stc
    ret
.done:
    mov al, ne_isr_rdc
    out dx, al
    call ne_finish_remote_dma
    clc
    ret

ne_finish_remote_dma:
    push ax
    push dx
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_nodma
    out dx, al
    pop dx
    pop ax
    ret

render_adapter_question:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [load_attr]
    mov si, adapter_prompt_text
    call type_z

    call type_menu_options
    ret

type_menu_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_selected_attr]
    mov si, [menu_option_a]
    call type_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov si, [menu_option_b]
    call type_z
    ret

draw_menu_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 0
    jne .first
    mov bl, [menu_selected_attr]
.first:
    mov si, [menu_option_a]
    call print_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 1
    jne .second
    mov bl, [menu_selected_attr]
.second:
    mov si, [menu_option_b]
    call print_z
    ret

print_z:
    lodsb
    or al, al
    jz .done
    call print_char
    jmp print_z
.done:
    ret

blink_load_marker:
    call set_seed_cursor
    mov bl, [load_attr]
    mov al, '.'
    xor byte [blink_state], 1
    jnz .show
    mov al, ' '
.show:
    call print_char
    mov cx, 2
    call wait_ticks
    ret

clear_question_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, seed_row
    xor cl, cl
    mov dh, question_row + 1
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

notify_question:
    mov ax, 6087
    call speaker_tone
    mov cx, 2
    call wait_ticks
    call speaker_off
    ret

notify_failure:
    mov ax, 5424
    call speaker_tone
    mov cx, 2
    call wait_ticks
    mov ax, 7231
    call speaker_tone
    mov cx, 3
    call wait_ticks
    call speaker_off
    ret

speaker_tone:
    push ax
    mov al, 0xb6
    out 0x43, al
    pop ax
    out 0x42, al
    mov al, ah
    out 0x42, al
    in al, 0x61
    or al, 0x03
    out 0x61, al
    ret

speaker_off:
    in al, 0x61
    and al, 0xfc
    out 0x61, al
    ret

cursor_row db 0
cursor_col db 0
screen_cols db 80
seed_col db (80 - seed_len) / 2
seed_attr db seed_attr_cga
build_attr db build_attr_cga
load_attr db load_attr_cga
error_attr db error_attr_cga
menu_selected_attr db menu_selected_attr_cga
menu_idle_attr db menu_idle_attr_cga
menu_option_a dw 0
menu_option_b dw 0
menu_value_a db 0
menu_value_b db 0
menu_index db 0
blink_state db 0
ne_tx_start db 0
ne_rx_start db 0
ne_rx_stop db 0
ne_current_page db 0
ne_boundary_page db 0
ne_next_page db 0
ne_rx_header times ne_rx_header_len db 0
ne_rx_count dw 0
ne_rx_sample_count dw 0
ne_rx_read_limit dw ne_rx_sample_len
ne_tx_len dw 0
ne_dma_addr dw 0
ne_dma_count dw 0
dhcp_wait_count dw 0
dhcp_options_left dw 0
dhcp_option_len dw 0
dhcp_option_code db 0
dhcp_message_type db 0
ne_prom times ne_prom_len db 0
ne_tx_frame times dhcp_rx_frame_len db 0
seed_text db 'seed', 0
build_text db 'build ', '0' + build_number, 0
network_error_text db 'no network card', 0
network_setup_error_text db 'network setup failed', 0
retry_text db 'retry', 0
restart_text db 'restart', 0
adapter_prompt_text db 'adapter', 0
adapter_ne2000_text db 'ne2000', 0
adapter_ne1000_text db 'ne1000', 0
adapter_3c501_text db '3c501', 0
adapter_wd8003_text db 'wd8003', 0
nic_ports dw 0x250, 0x280, 0x2a0, 0x2c0, 0x2e0
          dw 0x300, 0x310, 0x320, 0x330, 0x340
          dw 0x350, 0x360, 0x380, 0x3a0, 0x3c0
          dw 0

times (STAGE2_SECTORS * 512) - ($ - $$) db 0
