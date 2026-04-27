bits 16
cpu 8086
org 0x8000

%ifndef STAGE2_SECTORS
%define STAGE2_SECTORS 24
%endif

build_number equ 6
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
handoff_subnet_addr equ 40
handoff_size_bytes equ 44
handoff_struct_version equ 3
handoff_flag_mda equ 0x0001
handoff_flag_nic_present equ 0x0002
handoff_flag_config_resolved equ 0x0004
handoff_flag_mac_valid equ 0x0008
handoff_status_booting equ 1
handoff_status_no_nic equ 2
handoff_status_ready equ 3
handoff_status_network_failed equ 4
handoff_status_agent_failed equ 5
seed_flag_agent equ 0x01
seed_flag_model equ 0x02
seed_flag_key equ 0x04
seed_flag_endpoint equ 0x08
seed_flag_reasoning equ 0x10
net_status_none equ 0
net_status_identity_ready equ 1
net_status_packet_ready equ 2
net_status_tx_ready equ 3
net_status_rx_poll_ready equ 4
net_status_rx_frame_read equ 5
net_status_dhcp_discover_sent equ 6
net_status_dhcp_offer_received equ 7
net_status_dhcp_request_sent equ 8
net_status_dhcp_ack_received equ 9
net_status_arp_request_sent equ 10
net_status_arp_resolved equ 11
net_status_dns_query_sent equ 12
net_status_dns_response_received equ 13
net_status_next_hop_arp_request_sent equ 14
net_status_next_hop_arp_resolved equ 15
net_status_tcp_syn_sent equ 16
net_status_tcp_synack_received equ 17
net_error_none equ 0
net_error_ne_init equ 1
net_error_ne_tx equ 2
net_error_ne_rx equ 3
net_error_dhcp_offer equ 4
net_error_ne_rx_dma equ 5
net_error_ne_rx_header equ 6
net_error_ne_rx_count equ 7
net_error_dhcp_ack equ 8
net_error_arp equ 9
net_error_dns equ 10
net_error_next_hop_arp equ 11
net_error_tcp equ 12
seed_attr_cga equ 0x0f
build_attr_cga equ 0x08
load_attr_cga equ 0x08
ready_attr_cga equ 0x0f
question_attr_cga equ 0x0f
error_attr_cga equ 0x0c
menu_selected_attr_cga equ 0x0f
menu_idle_attr_cga equ 0x08
seed_attr_mda equ 0x0f
build_attr_mda equ 0x07
load_attr_mda equ 0x07
ready_attr_mda equ 0x0f
question_attr_mda equ 0x0f
error_attr_mda equ 0x0f
menu_selected_attr_mda equ 0x0f
menu_idle_attr_mda equ 0x07
seed_len equ 4
seed_row equ 12
question_row equ seed_row + 2
load_ticks equ 6
type_ticks equ 1
done_ticks equ 9
agent_slot_count equ 5
agent_id_len equ 16
seed_model_len equ 64
seed_key_len equ 240
seed_endpoint_len equ 96
seed_reasoning_len equ 16
seed_value_total_len equ agent_id_len + seed_model_len + seed_key_len + seed_endpoint_len + seed_reasoning_len
config_auto equ 1
config_user equ 2
profile_irq equ 3
family_3c503 equ 1
family_ne2000 equ 2
family_ne1000 equ 3
family_3c501 equ 4
family_wd8003 equ 5
el1_dataptr equ 0x08
el1_rx_cmd equ 0x06
el1_tx_cmd equ 0x07
el1_rcvptr equ 0x0a
el1_saprom equ 0x0c
el1_aux equ 0x0e
el1_data equ 0x0f
el1_rx_status_good equ 0x20
el1_tx_status_ready equ 0x08
el1_rx_cmd_bcast_good equ 0xa0
el1_tx_cmd_success equ 0x08
el1_aux_system equ 0x00
el1_aux_xmit_recv equ 0x04
el1_aux_receive equ 0x08
el1_aux_reset equ 0x80
el2_ctrl equ 0x406
el2_da_high equ 0x409
el2_da_low equ 0x40a
el2_data equ 0x40e
el2_ctrl_thin equ 0x02
el2_ctrl_saprom equ 0x04
el2_ctrl_dma equ 0x80
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
wd_dp8390_offset equ 0x10
wd_msr_enable_ram equ 0x40
wd_ram_segment equ 0xd000
wd_tx_start equ 0x00
wd_rx_start equ 0x06
wd_rx_stop equ 0x20
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
dhcp_filter_len equ dhcp_bootp_offset + 8
dhcp_offer_wait_count equ 2
dhcp_ack_wait_count equ 2
arp_frame_len equ eth_header_len + 28
arp_tx_frame_len equ 60
arp_payload_offset equ eth_header_len
arp_sha_offset equ arp_payload_offset + 8
arp_spa_offset equ arp_payload_offset + 14
arp_tpa_offset equ arp_payload_offset + 24
arp_wait_count equ 2
dns_qname_default_len equ 13
dns_qname_max_len equ 96
dns_payload_base_len equ 12 + 4
dns_tx_frame_default_len equ eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len + dns_qname_default_len
dns_tx_frame_max_len equ eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len + dns_qname_max_len
dns_rx_read_len equ 192
dns_udp_offset equ eth_header_len + ipv4_header_len
dns_payload_offset equ dns_udp_offset + udp_header_len
dns_query_id_word equ 0x4453
dns_wait_count equ 8
tcp_ip_len equ ipv4_header_len + 20
tcp_tx_frame_len equ 60
tcp_rx_read_len equ 96
tcp_offset equ eth_header_len + ipv4_header_len
tcp_source_port_word equ 0x02c0
tcp_port_http_word equ 0x5000
tcp_port_https_word equ 0xbb01
tcp_wait_count equ 4
wd_saprom equ 0x08
fat_root_start_lba equ STAGE2_SECTORS + 3
fat_fat_start_lba equ STAGE2_SECTORS + 1
fat_data_start_lba equ STAGE2_SECTORS + 7
fat_root_sectors equ 4
fat_dir_entries_per_sector equ 16
fat_dir_entry_size equ 32
fat_first_data_cluster equ 2
fat_max_cluster equ 300

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
    call show_load_marker

hal_start:
    call clear_question_area
    call reset_hal_state
    mov bl, [load_attr]
    mov al, '.'
    call show_load_marker
    call probe_network_card
    jc network_error

    call resolve_network_config
    call read_network_address
    call prepare_hal_path
    jc network_setup_error

    mov bl, [load_attr]
    mov al, 'o'
    call show_load_marker
    call prepare_internet_path
    jc network_setup_error

    mov bl, [ready_attr]
    mov al, 'o'
    call show_load_marker
    call prepare_agent_path
    jc agent_setup_error
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
    mov bl, [error_attr]
    mov al, [load_marker_char]
    call show_load_marker

    inc byte [cursor_col]
    call notify_failure
    mov si, network_error_text
    call type_z
    call ask_failure_action
    jmp halt

network_setup_error:
    mov byte [handoff_addr + handoff_status], handoff_status_network_failed
    mov bl, [error_attr]
    mov al, [load_marker_char]
    call show_load_marker

    inc byte [cursor_col]
    call notify_failure
    mov si, network_setup_error_text
    call type_z
    call ask_failure_action
    jmp halt

agent_setup_error:
    mov byte [handoff_addr + handoff_status], handoff_status_agent_failed
    mov bl, [error_attr]
    mov al, [load_marker_char]
    call show_load_marker

    inc byte [cursor_col]
    call notify_failure
    mov si, agent_setup_error_text
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
    mov byte [form_left_col], 2
    mov byte [form_field_col], 20
    cmp byte [screen_cols], 80
    jb .display_kind
    mov al, [seed_col]
    sub al, 14
    mov [form_left_col], al
    mov al, [seed_col]
    add al, 10
    mov [form_field_col], al
.display_kind:
    cmp byte [handoff_addr + handoff_video_mode], 0x07
    jne .color
    or word [handoff_addr + handoff_flags], handoff_flag_mda
    mov byte [seed_attr], seed_attr_mda
    mov byte [build_attr], build_attr_mda
    mov byte [load_attr], load_attr_mda
    mov byte [ready_attr], ready_attr_mda
    mov byte [question_attr], question_attr_mda
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

show_cursor:
    call set_bios_cursor
    mov ah, 0x01
    mov ch, 0x06
    mov cl, 0x07
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

set_bios_cursor:
    mov ah, 0x02
    mov bh, 0x00
    mov dh, [cursor_row]
    mov dl, [cursor_col]
    int 0x10
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
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    call show_load_marker
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
    jmp hal_start

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

prepare_internet_path:
    call selected_nic_has_packet_path
    jnc .packet
    clc
    ret
.packet:
    push ds
    pop es
    call wd_enable_shared_ram
    call wd_select_dp8390_base
    call ne_transmit_dhcp_discover
    jc .done
    call ne_wait_for_dhcp_offer
    cmp byte [handoff_addr + handoff_net_status], net_status_dhcp_offer_received
    jne .failed
    call ne_transmit_dhcp_request
    jc .done
    call ne_wait_for_dhcp_ack
    cmp byte [handoff_addr + handoff_net_status], net_status_dhcp_ack_received
    jne .failed
    call set_default_internet_target
    call ne_tcp_reachability_path
    jc .failed
    clc
.done:
    pushf
    call wd_restore_dp8390_base
    popf
    ret
.failed:
    stc
    jmp .done

prepare_agent_path:
    call load_agents_cfg
    call load_seed_cfg
    jnc .have_agent
    call ask_agent_setup
    jmp .values_ready
.have_agent:
    call ensure_seed_values
    jnc .values_ready
    call ask_agent_setup
.values_ready:
    call prepare_agent_endpoint_path
    jc .failed
    cmp byte [seed_cfg_dirty], 0
    je .ready
    call save_seed_cfg
.ready:
    clc
    ret
.failed:
    stc
    ret

prepare_agent_endpoint_path:
    call set_agent_endpoint_target
    jc .failed
    call selected_nic_has_packet_path
    jnc .packet
.failed:
    stc
    ret
.packet:
    push ds
    pop es
    call wd_enable_shared_ram
    call wd_select_dp8390_base
    call ne_tcp_reachability_path
    pushf
    call wd_restore_dp8390_base
    popf
    ret

selected_nic_has_packet_path:
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_3c501
    je .yes
    cmp al, family_3c503
    je .yes
    cmp al, family_ne1000
    je .yes
    cmp al, family_ne2000
    je .yes
    cmp al, family_wd8003
    je .yes
    stc
    ret
.yes:
    clc
    ret

set_default_internet_target:
    call set_example_dns_target
    call load_net_probe_cfg
    jnc .done
    call set_example_dns_target
.done:
    mov word [tcp_dest_port_word], tcp_port_http_word
    clc
    ret

set_example_dns_target:
    mov si, dns_default_qname
    mov di, dns_qname
    mov cx, dns_qname_default_len
    rep movsb
    mov byte [dns_qname_len], dns_qname_default_len
    call update_dns_tx_len
    ret

load_net_probe_cfg:
    mov di, net_cfg_name
    call find_root_file
    jc .failed
    cmp word [fs_file_size_high], 0
    jne .failed
    cmp word [fs_file_size_low], 7
    jb .failed
    mov ax, [fs_file_cluster]
    call read_cluster_to_buffer
    jc .failed
    mov si, fs_sector_buffer
    mov cx, [fs_file_size_low]
    cmp cx, 512
    jbe .size_ready
    mov cx, 512
.size_ready:
    mov byte [fs_line_start], 1
.next_byte:
    cmp cx, 0
    je .failed
    cmp byte [fs_line_start], 1
    jne .consume
    cmp cx, 6
    jb .consume
    cmp byte [si], 'p'
    jne .consume
    cmp byte [si + 1], 'r'
    jne .consume
    cmp byte [si + 2], 'o'
    jne .consume
    cmp byte [si + 3], 'b'
    jne .consume
    cmp byte [si + 4], 'e'
    jne .consume
    cmp byte [si + 5], ' '
    jne .consume
    add si, 6
    sub cx, 6
    mov di, seed_endpoint
    mov dl, seed_endpoint_len
    call copy_line_value
    cmp byte [seed_endpoint], 0
    je .failed
    mov si, seed_endpoint
    call set_dns_target_from_text
    ret
.consume:
    lodsb
    dec cx
    cmp al, 13
    je .line_start
    cmp al, 10
    je .line_start
    mov byte [fs_line_start], 0
    jmp .next_byte
.line_start:
    mov byte [fs_line_start], 1
    jmp .next_byte
.failed:
    stc
    ret

set_agent_endpoint_target:
    mov word [tcp_dest_port_word], tcp_port_https_word
    call selected_agent_needs_endpoint
    jc .known_provider
    mov si, seed_endpoint
    jmp set_dns_target_from_text
.known_provider:
    cmp byte [seed_agent_id], 'o'
    je .open_provider
    cmp byte [seed_agent_id], 'a'
    je .anthropic
    cmp byte [seed_agent_id], 'g'
    je .google
    stc
    ret
.open_provider:
    cmp byte [seed_agent_id + 4], 'r'
    je .openrouter
    mov si, host_openai_text
    jmp set_dns_target_from_text
.openrouter:
    mov si, host_openrouter_text
    jmp set_dns_target_from_text
.anthropic:
    mov si, host_anthropic_text
    jmp set_dns_target_from_text
.google:
    mov si, host_google_text
    jmp set_dns_target_from_text

set_dns_target_from_text:
    call skip_endpoint_prefix
    cmp byte [si], 0
    je .failed
    mov di, dns_qname
    mov byte [dns_qname_len], 0
.next_label:
    mov [dns_label_ptr], di
    mov byte [di], 0
    inc di
    inc byte [dns_qname_len]
    mov byte [dns_label_len], 0
.next_char:
    lodsb
    or al, al
    jz .finish
    cmp al, 13
    je .finish
    cmp al, 10
    je .finish
    cmp al, ' '
    je .finish
    cmp al, '/'
    je .finish
    cmp al, ':'
    je .finish
    cmp al, '.'
    je .dot
    cmp al, 'A'
    jb .store
    cmp al, 'Z'
    ja .store
    add al, 32
.store:
    cmp byte [dns_label_len], 63
    jae .failed
    cmp byte [dns_qname_len], dns_qname_max_len - 1
    jae .failed
    mov [di], al
    inc di
    inc byte [dns_label_len]
    inc byte [dns_qname_len]
    jmp .next_char
.dot:
    cmp byte [dns_label_len], 0
    je .failed
    call finish_dns_label
    jmp .next_label
.finish:
    cmp byte [dns_label_len], 0
    je .failed
    call finish_dns_label
    cmp byte [dns_qname_len], dns_qname_max_len
    jae .failed
    mov byte [di], 0
    inc byte [dns_qname_len]
    call update_dns_tx_len
    clc
    ret
.failed:
    stc
    ret

skip_endpoint_prefix:
    mov bx, si
    cmp byte [si], 'h'
    jne .done
    cmp byte [si + 1], 't'
    jne .done
    cmp byte [si + 2], 't'
    jne .done
    cmp byte [si + 3], 'p'
    jne .done
    add si, 4
    cmp byte [si], 's'
    jne .colon
    inc si
.colon:
    cmp byte [si], ':'
    jne .restore
    inc si
    cmp byte [si], '/'
    jne .restore
    inc si
    cmp byte [si], '/'
    jne .restore
    inc si
    ret
.restore:
    mov si, bx
.done:
    ret

finish_dns_label:
    mov bx, [dns_label_ptr]
    mov al, [dns_label_len]
    mov [bx], al
    ret

update_dns_tx_len:
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len
    mov [dns_tx_len], ax
    ret

load_agents_cfg:
    mov byte [agent_count], 0
    call find_agents_cfg
    jc .fallback
    call parse_agents_cfg
    jc .fallback
    cmp byte [agent_count], 0
    je .fallback
    clc
    ret
.fallback:
    call load_builtin_agents
    clc
    ret

load_builtin_agents:
    push ds
    pop es
    mov si, builtin_agent_ids
    mov di, agent_ids
    mov cx, (3 * agent_id_len) / 2
    rep movsw
    mov byte [agent_count], 3
    ret

find_agents_cfg:
    mov di, agents_cfg_name
    call find_root_file
    jc .not_found
    mov ax, [fs_file_cluster]
    mov [agents_cluster], ax
    mov ax, [fs_file_size_low]
    mov [agents_size_low], ax
    mov ax, [fs_file_size_high]
    mov [agents_size_high], ax
    clc
    ret
.not_found:
    stc
    ret

find_seed_cfg:
    mov di, seed_cfg_name
    call find_root_file
    jc .not_found
    mov ax, [fs_file_cluster]
    mov [seed_cluster], ax
    mov ax, [fs_file_size_low]
    mov [seed_size_low], ax
    mov ax, [fs_file_size_high]
    mov [seed_size_high], ax
    mov ax, [fs_file_root_lba]
    mov [seed_root_lba], ax
    mov ax, [fs_file_root_offset]
    mov [seed_root_offset], ax
    clc
    ret
.not_found:
    stc
    ret

find_root_file:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
    mov byte [fs_free_root_found], 0
.next_sector:
    cmp word [fs_root_left], 0
    je .not_found
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [fs_lba]
    call read_abs_sector
    jc .not_found
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.next_entry:
    mov al, [si]
    or al, al
    jz .end_marker
    cmp al, 0xe5
    je .free_entry
    test byte [si + 11], 0x18
    jnz .advance
    push si
    push cx
    push di
    mov cx, 11
.compare:
    mov al, [si]
    cmp al, [di]
    jne .mismatch
    inc si
    inc di
    loop .compare
    pop di
    pop cx
    pop si
    mov ax, [si + 26]
    mov [fs_file_cluster], ax
    mov ax, [si + 28]
    mov [fs_file_size_low], ax
    mov ax, [si + 30]
    mov [fs_file_size_high], ax
    mov ax, [fs_lba]
    mov [fs_file_root_lba], ax
    mov ax, si
    sub ax, fs_sector_buffer
    mov [fs_file_root_offset], ax
    clc
    ret
.mismatch:
    pop di
    pop cx
    pop si
    jmp .advance
.free_entry:
    call record_free_root_entry
.advance:
    add si, fat_dir_entry_size
    loop .next_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .next_sector
.end_marker:
    call record_free_root_entry
.not_found:
    stc
    ret

record_free_root_entry:
    cmp byte [fs_free_root_found], 0
    jne .done
    mov byte [fs_free_root_found], 1
    mov ax, [fs_lba]
    mov [fs_free_root_lba], ax
    mov ax, si
    sub ax, fs_sector_buffer
    mov [fs_free_root_offset], ax
.done:
    ret

parse_agents_cfg:
    cmp word [agents_size_high], 0
    jne .failed
    mov ax, [agents_cluster]
    cmp ax, fat_first_data_cluster
    jb .failed
    mov [fs_current_cluster], ax
    mov ax, [agents_size_low]
    mov [fs_bytes_left], ax
    or ax, ax
    jz .failed
.next_cluster:
    cmp byte [agent_count], agent_slot_count
    jae .done
    cmp word [fs_bytes_left], 0
    je .done
    mov ax, [fs_current_cluster]
    call read_cluster_to_buffer
    jc .failed
    mov ax, [fs_bytes_left]
    cmp ax, 512
    jbe .size_ready
    mov ax, 512
.size_ready:
    mov [fs_bytes_this], ax
    call parse_agent_sector
    mov ax, [fs_bytes_left]
    sub ax, [fs_bytes_this]
    mov [fs_bytes_left], ax
    inc word [fs_current_cluster]
    jmp .next_cluster
.done:
    clc
    ret
.failed:
    stc
    ret

parse_agent_sector:
    mov si, fs_sector_buffer
    mov cx, [fs_bytes_this]
    mov byte [fs_line_start], 1
.next_byte:
    cmp cx, 0
    je .done
    cmp byte [fs_line_start], 1
    jne .consume
    cmp byte [agent_count], agent_slot_count
    jae .done
    cmp cx, 6
    jb .consume
    cmp byte [si], 'a'
    jne .consume
    cmp byte [si + 1], 'g'
    jne .consume
    cmp byte [si + 2], 'e'
    jne .consume
    cmp byte [si + 3], 'n'
    jne .consume
    cmp byte [si + 4], 't'
    jne .consume
    cmp byte [si + 5], ' '
    jne .consume
    call copy_agent_id_from_line
.consume:
    lodsb
    dec cx
    cmp al, 13
    je .line_start
    cmp al, 10
    je .line_start
    mov byte [fs_line_start], 0
    jmp .next_byte
.line_start:
    mov byte [fs_line_start], 1
    jmp .next_byte
.done:
    ret

copy_agent_id_from_line:
    push si
    push cx
    mov al, [agent_count]
    xor ah, ah
    mov di, ax
    shl di, 1
    shl di, 1
    shl di, 1
    shl di, 1
    add di, agent_ids
    add si, 6
    mov bp, cx
    sub bp, 6
    mov dx, agent_id_len - 1
.copy:
    cmp bp, 0
    je .terminate
    cmp dx, 0
    je .terminate
    lodsb
    dec bp
    cmp al, 13
    je .terminate
    cmp al, 10
    je .terminate
    cmp al, ' '
    je .terminate
    cmp al, 9
    je .terminate
    stosb
    dec dx
    jmp .copy
.terminate:
    mov byte [di], 0
    inc byte [agent_count]
    pop cx
    pop si
    ret

load_seed_cfg:
    call clear_seed_values
    call find_seed_cfg
    jc .failed
    cmp word [seed_size_high], 0
    jne .failed
    cmp word [seed_size_low], 6
    jb .failed
    mov ax, [seed_cluster]
    call read_cluster_to_buffer
    jc .failed
    call parse_seed_cfg
    jc .failed
    clc
    ret
.failed:
    stc
    ret

parse_seed_cfg:
    mov si, fs_sector_buffer
    mov cx, [seed_size_low]
    cmp cx, 512
    jbe .size_ready
    mov cx, 512
.size_ready:
    mov byte [fs_line_start], 1
.next_byte:
    cmp cx, 0
    je .validate
    cmp byte [fs_line_start], 1
    jne .consume
    call parse_seed_line
.consume:
    lodsb
    dec cx
    cmp al, 13
    je .line_start
    cmp al, 10
    je .line_start
    mov byte [fs_line_start], 0
    jmp .next_byte
.line_start:
    mov byte [fs_line_start], 1
    jmp .next_byte
.validate:
    test byte [seed_config_flags], seed_flag_agent
    jz .failed
    call match_seed_agent
    jc .failed
    clc
    ret
.failed:
    stc
    ret

parse_seed_line:
    cmp cx, 6
    jb .check_key
    cmp byte [si], 'a'
    jne .check_model
    cmp byte [si + 1], 'g'
    jne .check_model
    cmp byte [si + 2], 'e'
    jne .check_model
    cmp byte [si + 3], 'n'
    jne .check_model
    cmp byte [si + 4], 't'
    jne .check_model
    cmp byte [si + 5], ' '
    jne .check_model
    push si
    push cx
    add si, 6
    sub cx, 6
    mov di, seed_agent_id
    mov dl, agent_id_len
    call copy_line_value
    pop cx
    pop si
    cmp byte [seed_agent_id], 0
    je .done
    or byte [seed_config_flags], seed_flag_agent
    ret
.check_model:
    cmp cx, 6
    jb .check_key
    cmp byte [si], 'm'
    jne .check_reasoning
    cmp byte [si + 1], 'o'
    jne .check_reasoning
    cmp byte [si + 2], 'd'
    jne .check_reasoning
    cmp byte [si + 3], 'e'
    jne .check_reasoning
    cmp byte [si + 4], 'l'
    jne .check_reasoning
    cmp byte [si + 5], ' '
    jne .check_reasoning
    push si
    push cx
    add si, 6
    sub cx, 6
    mov di, seed_model
    mov dl, seed_model_len
    call copy_line_value
    pop cx
    pop si
    cmp byte [seed_model], 0
    je .done
    or byte [seed_config_flags], seed_flag_model
    ret
.check_reasoning:
    cmp cx, 10
    jb .check_key
    cmp byte [si], 'r'
    jne .check_key
    cmp byte [si + 1], 'e'
    jne .check_key
    cmp byte [si + 2], 'a'
    jne .check_key
    cmp byte [si + 3], 's'
    jne .check_key
    cmp byte [si + 4], 'o'
    jne .check_key
    cmp byte [si + 5], 'n'
    jne .check_key
    cmp byte [si + 6], 'i'
    jne .check_key
    cmp byte [si + 7], 'n'
    jne .check_key
    cmp byte [si + 8], 'g'
    jne .check_key
    cmp byte [si + 9], ' '
    jne .check_key
    push si
    push cx
    add si, 10
    sub cx, 10
    mov di, seed_reasoning
    mov dl, seed_reasoning_len
    call copy_line_value
    pop cx
    pop si
    cmp byte [seed_reasoning], 0
    je .done
    or byte [seed_config_flags], seed_flag_reasoning
    ret
.check_key:
    cmp cx, 4
    jb .check_endpoint
    cmp byte [si], 'k'
    jne .check_endpoint
    cmp byte [si + 1], 'e'
    jne .check_endpoint
    cmp byte [si + 2], 'y'
    jne .check_endpoint
    cmp byte [si + 3], ' '
    jne .check_endpoint
    push si
    push cx
    add si, 4
    sub cx, 4
    mov di, seed_key
    mov dl, seed_key_len
    call copy_line_value
    pop cx
    pop si
    cmp byte [seed_key], 0
    je .done
    or byte [seed_config_flags], seed_flag_key
    ret
.check_endpoint:
    cmp cx, 9
    jb .done
    cmp byte [si], 'e'
    jne .done
    cmp byte [si + 1], 'n'
    jne .done
    cmp byte [si + 2], 'd'
    jne .done
    cmp byte [si + 3], 'p'
    jne .done
    cmp byte [si + 4], 'o'
    jne .done
    cmp byte [si + 5], 'i'
    jne .done
    cmp byte [si + 6], 'n'
    jne .done
    cmp byte [si + 7], 't'
    jne .done
    cmp byte [si + 8], ' '
    jne .done
    push si
    push cx
    add si, 9
    sub cx, 9
    mov di, seed_endpoint
    mov dl, seed_endpoint_len
    call copy_line_value
    pop cx
    pop si
    cmp byte [seed_endpoint], 0
    je .done
    or byte [seed_config_flags], seed_flag_endpoint
.done:
    ret

copy_line_value:
    push ax
    push cx
    push dx
    push si
    push di
    dec dl
.copy:
    cmp cx, 0
    je .terminate
    cmp dl, 0
    je .terminate
    mov al, [si]
    cmp al, 13
    je .terminate
    cmp al, 10
    je .terminate
    or al, al
    jz .terminate
    mov [di], al
    inc si
    inc di
    dec cx
    dec dl
    jmp .copy
.terminate:
    mov byte [di], 0
    pop di
    pop si
    pop dx
    pop cx
    pop ax
    ret

match_seed_agent:
    mov byte [agent_scan_index], 0
.next_agent:
    mov al, [agent_scan_index]
    cmp al, [agent_count]
    jae .failed
    call agent_scan_ptr
    mov di, seed_agent_id
    call strings_equal
    jnc .found
    inc byte [agent_scan_index]
    jmp .next_agent
.found:
    mov al, [agent_scan_index]
    mov [menu_index], al
    clc
    ret
.failed:
    stc
    ret

strings_equal:
    mov al, [si]
    cmp al, [di]
    jne .failed
    or al, al
    jz .equal
    inc si
    inc di
    jmp strings_equal
.equal:
    clc
    ret
.failed:
    stc
    ret

clear_seed_values:
    push es
    push ds
    pop es
    xor ax, ax
    mov di, seed_agent_id
    mov cx, seed_value_total_len / 2
    rep stosw
    mov byte [seed_config_flags], 0
    mov byte [seed_cfg_dirty], 0
    pop es
    ret

ensure_seed_values:
    call selected_agent_needs_endpoint
    jc .key_only
    test byte [seed_config_flags], seed_flag_endpoint
    jz .ask
.key_only:
    test byte [seed_config_flags], seed_flag_key
    jnz .done
    jmp .ask
.ask:
    call ask_agent_values
.done:
    ret

selected_agent_needs_endpoint:
    cmp byte [seed_agent_id], 'l'
    jne .no
    clc
    ret
.no:
    stc
    ret

ask_agent_values:
    mov byte [menu_value_a], 0
    mov byte [blink_state], 0
.render:
    call clear_agent_field_area
    call render_agent_values_form
    call set_active_form_input
    call show_cursor
.input:
    call input_wait_key
    cmp al, 0x0d
    je .accept
    cmp al, 0x08
    je .backspace
    cmp al, 0x1b
    je .cancel
    cmp ah, 0x48
    je .previous
    cmp ah, 0x50
    je .next
    cmp al, 0x20
    jb .input
    cmp al, 0x7e
    ja .input
    mov dl, [input_max]
    dec dl
    cmp [input_len], dl
    jae .input
    call input_store_char
    jmp .input
.backspace:
    call input_backspace
    jmp .input
.previous:
.next:
    call selected_agent_needs_endpoint
    jc .input
    xor byte [menu_value_a], 1
    call draw_agent_form_fields
    call set_active_form_input
    call show_cursor
    jmp .input
.accept:
    call validate_agent_values
    jc .render
    call hide_cursor
    call clear_question_area
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    call show_load_marker
    clc
    ret
.cancel:
    call hide_cursor
    call slide_selected_agent_right
    stc
    ret

validate_agent_values:
    call selected_agent_needs_endpoint
    jc .check_key
    cmp byte [seed_endpoint], 0
    jne .check_key
    mov byte [menu_value_a], 0
    stc
    ret
.check_key:
    cmp byte [seed_key], 0
    jne .valid
    call selected_agent_needs_endpoint
    jc .key_focus
    mov byte [menu_value_a], 1
    jmp .invalid
.key_focus:
    mov byte [menu_value_a], 0
.invalid:
    stc
    ret
.valid:
    or byte [seed_config_flags], seed_flag_key
    call selected_agent_needs_endpoint
    jc .done
    or byte [seed_config_flags], seed_flag_endpoint
.done:
    mov byte [seed_cfg_dirty], 1
    clc
    ret

set_active_form_input:
    call selected_agent_needs_endpoint
    jc .key
    cmp byte [menu_value_a], 0
    jne .key
    mov di, seed_endpoint
    mov al, seed_endpoint_len
    mov dl, question_row
    add dl, [menu_index]
    jmp .set
.key:
    mov di, seed_key
    mov al, seed_key_len
    mov dl, question_row
    add dl, [menu_index]
    call selected_agent_needs_endpoint
    jc .set
    inc dl
.set:
    mov [input_target], di
    mov [input_max], al
    call measure_input_len
    mov [cursor_row], dl
    mov al, [form_field_col]
    add al, 8
    mov [input_start_col], al
    call set_input_window
    ret

measure_input_len:
    mov byte [input_len], 0
    mov di, [input_target]
.next:
    cmp byte [di], 0
    je .done
    inc di
    inc byte [input_len]
    jmp .next
.done:
    ret

input_store_char:
    mov bl, [input_len]
    xor bh, bh
    mov di, [input_target]
    add di, bx
    mov [di], al
    inc byte [input_len]
    inc di
    mov byte [di], 0
    call render_text_input
    ret

input_backspace:
    cmp byte [input_len], 0
    je .done
    dec byte [input_len]
    mov bl, [input_len]
    xor bh, bh
    mov di, [input_target]
    add di, bx
    mov byte [di], 0
    call render_text_input
.done:
    ret

input_wait_key:
    xor ah, ah
    int 0x16
    ret

render_text_input:
    call clear_input_line
    call set_input_window
    mov bl, [question_attr]
.next:
    jcxz .done
    lodsb
    call print_char
    loop .next
.done:
    call set_bios_cursor
    ret

set_input_window:
    mov al, [input_start_col]
    mov [cursor_col], al
    mov dl, [screen_cols]
    sub dl, al
    dec dl
    mov cl, [input_len]
    xor ch, ch
    mov si, [input_target]
    cmp cl, dl
    jbe .done
    mov al, cl
    sub al, dl
    xor ah, ah
    add si, ax
    mov cl, dl
.done:
    ret

ask_agent_setup:
.select:
    call clear_seed_values
    call ask_agent
.values:
    call ensure_seed_values
    jc .reselect
    ret
.reselect:
    call clear_seed_values
    call ask_agent_resume
    jmp .values

ask_agent:
    mov byte [menu_index], 0
    mov byte [blink_state], 0
    call notify_question
    call render_agent_question
ask_agent_resume:
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
    je .previous
    cmp ah, 0x50
    jne .input
.next:
    mov al, [menu_index]
    inc al
    cmp al, [agent_count]
    jb .store_index
    xor al, al
    jmp .store_index
.previous:
    cmp byte [menu_index], 0
    jne .decrement
    mov al, [agent_count]
    dec al
    jmp .store_index
.decrement:
    mov al, [menu_index]
    dec al
.store_index:
    mov [menu_index], al
    call draw_agent_options
    jmp .input
.accept:
    call copy_selected_agent
    call slide_selected_agent_left
    ret

copy_selected_agent:
    mov al, [menu_index]
    call agent_ptr_from_al
    mov di, seed_agent_id
    mov cx, agent_id_len
.copy:
    lodsb
    stosb
    or al, al
    jz .done
    loop .copy
    mov byte [di - 1], 0
.done:
    or byte [seed_config_flags], seed_flag_agent
    mov byte [seed_cfg_dirty], 1
    ret

slide_selected_agent_left:
    mov al, [seed_col]
    add al, 2
.loop:
    call draw_selected_agent_slide
    mov ah, [form_left_col]
    cmp al, ah
    jbe .done
    sub al, 4
    cmp al, ah
    jae .wait
    mov al, ah
.wait:
    mov cx, 1
    call wait_ticks
    jmp .loop
.done:
    ret

slide_selected_agent_right:
    mov al, [form_left_col]
.loop:
    call draw_selected_agent_slide
    mov ah, [seed_col]
    add ah, 2
    cmp al, ah
    jae .done
    add al, 4
    cmp al, ah
    jbe .wait
    mov al, ah
.wait:
    mov cx, 1
    call wait_ticks
    jmp .loop
.done:
    ret

draw_selected_agent_slide:
    mov [input_start_col], al
    call clear_panel_area
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    call show_load_marker
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, agent_prompt_text
    call print_z
    call draw_agent_options_at_col
    mov al, [input_start_col]
    ret

save_seed_cfg:
    call find_seed_cfg
    jnc .have_root
    cmp byte [fs_free_root_found], 0
    je .done
    call find_free_cluster
    jc .done
    mov ax, [fs_free_cluster]
    mov [seed_cluster], ax
    mov ax, [fs_free_root_lba]
    mov [seed_root_lba], ax
    mov ax, [fs_free_root_offset]
    mov [seed_root_offset], ax
.have_root:
    cmp word [seed_cluster], fat_first_data_cluster
    jb .done
    call write_seed_data
    jc .done
    call write_seed_fat
    jc .done
    call write_seed_root
.done:
    clc
    ret

find_free_cluster:
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    call read_abs_sector
    jc .failed
    mov word [fs_scan_cluster], fat_first_data_cluster
.next:
    mov ax, [fs_scan_cluster]
    cmp ax, fat_max_cluster
    jae .failed
    call get_fat_entry
    and ax, 0x0fff
    jz .found
    inc word [fs_scan_cluster]
    jmp .next
.found:
    mov ax, [fs_scan_cluster]
    mov [fs_free_cluster], ax
    clc
    ret
.failed:
    stc
    ret

get_fat_entry:
    push bx
    push dx
    mov dx, ax
    mov bx, ax
    shr bx, 1
    add bx, dx
    mov al, [fs_sector_buffer + bx]
    mov ah, [fs_sector_buffer + bx + 1]
    test dl, 1
    jz .even
    shr ax, 1
    shr ax, 1
    shr ax, 1
    shr ax, 1
.even:
    and ax, 0x0fff
    pop dx
    pop bx
    ret

write_seed_data:
    call build_seed_cfg_buffer
    mov ax, [seed_cluster]
    call write_cluster_from_buffer
    ret

write_seed_fat:
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    call read_abs_sector
    jc .failed
    mov ax, [seed_cluster]
    call set_fat_entry_eoc
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    call write_abs_sector
    jc .failed
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba + 1
    call write_abs_sector
    ret
.failed:
    stc
    ret

set_fat_entry_eoc:
    push ax
    push bx
    push dx
    mov dx, ax
    mov bx, ax
    shr bx, 1
    add bx, dx
    test dl, 1
    jnz .odd
    mov byte [fs_sector_buffer + bx], 0xff
    mov al, [fs_sector_buffer + bx + 1]
    and al, 0xf0
    or al, 0x0f
    mov [fs_sector_buffer + bx + 1], al
    jmp .done
.odd:
    mov al, [fs_sector_buffer + bx]
    and al, 0x0f
    or al, 0xf0
    mov [fs_sector_buffer + bx], al
    mov byte [fs_sector_buffer + bx + 1], 0xff
.done:
    pop dx
    pop bx
    pop ax
    ret

write_seed_root:
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [seed_root_lba]
    call read_abs_sector
    jc .failed
    call write_seed_root_entry
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [seed_root_lba]
    call write_abs_sector
    ret
.failed:
    stc
    ret

write_seed_root_entry:
    push ds
    pop es
    mov bx, [seed_root_offset]
    mov di, fs_sector_buffer
    add di, bx
    xor ax, ax
    mov cx, fat_dir_entry_size / 2
    rep stosw
    mov di, fs_sector_buffer
    add di, bx
    mov si, seed_cfg_name
    mov cx, 11
    rep movsb
    mov bx, [seed_root_offset]
    mov byte [fs_sector_buffer + bx + 11], 0x20
    mov ax, [seed_cluster]
    mov [fs_sector_buffer + bx + 26], ax
    mov ax, [seed_cfg_size_current]
    mov [fs_sector_buffer + bx + 28], ax
    mov word [fs_sector_buffer + bx + 30], 0
    ret

build_seed_cfg_buffer:
    call clear_fs_sector_buffer
    push ds
    pop es
    mov di, fs_sector_buffer
    mov si, agent_prefix_text
    call append_z_to_buffer
    mov si, seed_agent_id
    call append_z_to_buffer
    call append_crlf_to_buffer
    test byte [seed_config_flags], seed_flag_model
    jz .reasoning
    mov si, model_prefix_text
    call append_z_to_buffer
    mov si, seed_model
    call append_z_to_buffer
    call append_crlf_to_buffer
.reasoning:
    test byte [seed_config_flags], seed_flag_reasoning
    jz .key
    mov si, reasoning_prefix_text
    call append_z_to_buffer
    mov si, seed_reasoning
    call append_z_to_buffer
    call append_crlf_to_buffer
.key:
    test byte [seed_config_flags], seed_flag_key
    jz .endpoint
    mov si, key_prefix_text
    call append_z_to_buffer
    mov si, seed_key
    call append_z_to_buffer
    call append_crlf_to_buffer
.endpoint:
    test byte [seed_config_flags], seed_flag_endpoint
    jz .finish
    mov si, endpoint_prefix_text
    call append_z_to_buffer
    mov si, seed_endpoint
    call append_z_to_buffer
    call append_crlf_to_buffer
.finish:
    mov ax, di
    sub ax, fs_sector_buffer
    mov [seed_cfg_size_current], ax
    ret

append_z_to_buffer:
    lodsb
    or al, al
    jz .done
    stosb
    jmp append_z_to_buffer
.done:
    ret

append_crlf_to_buffer:
    mov al, 13
    stosb
    mov al, 10
    stosb
    ret

clear_fs_sector_buffer:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, fs_sector_buffer
    mov cx, 256
    rep stosw
    pop es
    pop di
    pop cx
    pop ax
    ret

read_cluster_to_buffer:
    cmp ax, fat_first_data_cluster
    jb .failed
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    call read_abs_sector
    ret
.failed:
    stc
    ret

write_cluster_from_buffer:
    cmp ax, fat_first_data_cluster
    jb .failed
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    call write_abs_sector
    ret
.failed:
    stc
    ret

read_abs_sector:
    push ax
    push cx
    push dx
    div byte [disk_sectors_per_track]
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
    mov dl, [handoff_addr + handoff_boot_drive]
    mov ax, 0x0201
    int 0x13
    pop dx
    pop cx
    pop ax
    ret

write_abs_sector:
    push ax
    push cx
    push dx
    div byte [disk_sectors_per_track]
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
    mov dl, [handoff_addr + handoff_boot_drive]
    mov ax, 0x0301
    int 0x13
    pop dx
    pop cx
    pop ax
    ret

wd_enable_shared_ram:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .done
    mov dx, [handoff_addr + handoff_nic_base]
    in al, dx
    or al, wd_msr_enable_ram
    out dx, al
.done:
    ret

wd_select_dp8390_base:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .done
    add word [handoff_addr + handoff_nic_base], wd_dp8390_offset
.done:
    ret

wd_restore_dp8390_base:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .done
    sub word [handoff_addr + handoff_nic_base], wd_dp8390_offset
.done:
    ret

init_ne_packet_io:
    test word [handoff_addr + handoff_flags], handoff_flag_mac_valid
    jnz .have_mac
    mov byte [handoff_addr + handoff_net_error], net_error_ne_init
    stc
    ret
.have_mac:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .check_3c503
    jmp el1_init_packet_io
.check_3c503:
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    jne .pages
    call c503_select_dp8390
.pages:
    mov byte [ne_tx_start], ne_tx_start_2k
    mov byte [ne_rx_start], ne_rx_start_2k
    mov byte [ne_rx_stop], ne_rx_stop_2k
    cmp byte [handoff_addr + handoff_nic_family], family_ne2000
    je .pages_ready
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .pages_1k
    mov byte [ne_tx_start], wd_tx_start
    mov byte [ne_rx_start], wd_rx_start
    mov byte [ne_rx_stop], wd_rx_stop
    jmp .pages_ready
.pages_1k:
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

c503_select_dp8390:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    mov al, el2_ctrl_thin
    out dx, al
    ret

el1_init_packet_io:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_reset
    out dx, al
    mov al, el1_aux_system
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    mov si, handoff_addr + handoff_mac
    mov cx, 6
.mac:
    lodsb
    out dx, al
    inc dx
    loop .mac

    mov al, el1_rx_cmd_bcast_good
    out dx, al
    inc dx
    mov al, el1_tx_cmd_success
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_rcvptr
    out dx, al
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_receive
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

ne_transmit_dhcp_request:
    call build_dhcp_request_frame

    mov si, ne_tx_frame
    mov cx, dhcp_frame_len
    call ne_transmit_frame
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_request_sent
.done:
    ret

ne_transmit_arp_request:
    call build_arp_request_frame

    mov si, ne_tx_frame
    mov cx, arp_tx_frame_len
    call ne_transmit_frame
    jc .done
    mov al, [arp_status_sent]
    mov [handoff_addr + handoff_net_status], al
.done:
    ret

ne_transmit_dns_query:
    call build_dns_query_frame

    mov si, ne_tx_frame
    mov cx, [dns_tx_len]
    call ne_transmit_frame
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_dns_query_sent
.done:
    ret

ne_transmit_tcp_syn:
    call build_tcp_syn_frame

    mov si, ne_tx_frame
    mov cx, tcp_tx_frame_len
    call ne_transmit_frame
    jc .done
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_syn_sent
.done:
    ret

ne_transmit_frame:
    mov [ne_tx_len], cx
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .dp8390
    call el1_transmit_frame
    ret

.dp8390:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    mov al, ne_isr_rdc | ne_isr_txe | ne_isr_ptx
    out dx, al

    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .check_3c503
    xor bl, bl
    mov bh, [ne_tx_start]
    mov cx, [ne_tx_len]
    call wd_write_sharedmem_bytes
    jmp .frame_loaded

.check_3c503:
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    jne .remote_dma
    xor bl, bl
    mov bh, [ne_tx_start]
    mov cx, [ne_tx_len]
    call c503_write_chipmem_bytes
    jmp .frame_loaded

.remote_dma:
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

.frame_loaded:
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

el1_transmit_frame:
    mov ax, 0x0800
    sub ax, [ne_tx_len]
    mov [el1_tx_ptr], ax
    call el1_set_gp

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_system
    out dx, al
    inc dx
    mov cx, [ne_tx_len]
.write:
    lodsb
    out dx, al
    loop .write

    mov ax, [el1_tx_ptr]
    call el1_set_gp
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_xmit_recv
    out dx, al

    mov cx, 0xffff
.wait:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_tx_cmd
    in al, dx
    test al, el1_tx_status_ready
    jnz .done
    loop .wait
    mov byte [handoff_addr + handoff_net_error], net_error_ne_tx
    stc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_tx_ready
    clc
    ret

build_dhcp_discover_frame:
    call build_dhcp_base_frame

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

build_dhcp_request_frame:
    call build_dhcp_base_frame

    mov al, 53
    stosb
    mov al, 1
    stosb
    mov al, 3
    stosb

    mov al, 50
    stosb
    mov al, 4
    stosb
    mov si, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb

    mov al, 54
    stosb
    mov al, 4
    stosb
    mov si, dhcp_server_addr
    mov cx, 4
    rep movsb

    mov al, 61
    stosb
    mov al, 7
    stosb
    mov al, 1
    stosb
    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    xor al, al
    stosb
    mov al, 255
    stosb
    ret

build_dhcp_base_frame:
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
    ret

build_arp_request_frame:
    mov di, ne_tx_frame
    xor al, al
    mov cx, arp_tx_frame_len
    rep stosb

    mov di, ne_tx_frame
    mov al, 0xff
    mov cx, 6
    rep stosb

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov ax, 0x0608
    stosw
    mov ax, 0x0100
    stosw
    mov ax, 0x0008
    stosw
    mov ax, 0x0406
    stosw
    mov ax, 0x0100
    stosw

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov si, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb

    xor al, al
    mov cx, 6
    rep stosb

    mov si, arp_target_ip
    mov cx, 4
    rep movsb
    ret

build_dns_query_frame:
    mov di, ne_tx_frame
    xor al, al
    mov cx, dns_tx_frame_max_len
    rep stosb

    mov di, ne_tx_frame
    mov si, arp_target_mac
    mov cx, 6
    rep movsb

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov ax, 0x0008
    stosw

    mov ax, 0x0045
    stosw
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, ipv4_header_len + udp_header_len + dns_payload_base_len
    xchg al, ah
    stosw
    xor ax, ax
    stosw
    stosw
    mov ax, 0x1140
    stosw
    xor ax, ax
    stosw

    mov si, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb

    mov si, handoff_addr + handoff_dns_addr
    mov cx, 4
    rep movsb

    mov ax, 0x01c0
    stosw
    mov ax, 0x3500
    stosw
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, udp_header_len + dns_payload_base_len
    xchg al, ah
    stosw
    xor ax, ax
    stosw

    mov ax, dns_query_id_word
    stosw
    mov ax, 0x0001
    stosw
    mov ax, 0x0100
    stosw
    xor ax, ax
    stosw
    stosw
    stosw
    mov si, dns_qname
    mov cl, [dns_qname_len]
    xor ch, ch
    rep movsb
    mov ax, 0x0100
    stosw
    mov ax, 0x0100
    stosw

    call write_ipv4_checksum
    ret

build_tcp_syn_frame:
    mov di, ne_tx_frame
    xor al, al
    mov cx, tcp_tx_frame_len
    rep stosb

    mov di, ne_tx_frame
    mov si, arp_target_mac
    mov cx, 6
    rep movsb

    mov si, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb

    mov ax, 0x0008
    stosw

    mov ax, 0x0045
    stosw
    mov ax, tcp_ip_len << 8
    stosw
    xor ax, ax
    stosw
    stosw
    mov ax, 0x0640
    stosw
    xor ax, ax
    stosw

    mov si, handoff_addr + handoff_ip_addr
    mov cx, 4
    rep movsb

    mov si, tcp_target_ip
    mov cx, 4
    rep movsb

    mov ax, tcp_source_port_word
    stosw
    mov ax, [tcp_dest_port_word]
    stosw
    mov ax, 0x4553
    stosw
    mov ax, 0x4445
    stosw
    xor ax, ax
    stosw
    stosw
    mov ax, 0x0250
    stosw
    mov ax, 0x0004
    stosw
    xor ax, ax
    stosw
    stosw

    call write_ipv4_checksum
    call write_tcp_checksum
    ret

write_ipv4_checksum:
    mov si, ne_tx_frame + eth_header_len
    xor bx, bx
    xor dx, dx
    mov cx, ipv4_header_len / 2
.sum:
    lodsw
    add bx, ax
    adc dx, 0
    loop .sum
    add bx, dx
    adc bx, 0
    not bx
    mov [ne_tx_frame + eth_header_len + 10], bx
    ret

write_tcp_checksum:
    xor bx, bx
    xor dx, dx
    mov si, handoff_addr + handoff_ip_addr
    mov cx, 2
.src_ip:
    lodsw
    add bx, ax
    adc dx, 0
    loop .src_ip
    mov si, tcp_target_ip
    mov cx, 2
.dst_ip:
    lodsw
    add bx, ax
    adc dx, 0
    loop .dst_ip
    mov ax, 0x0600
    add bx, ax
    adc dx, 0
    mov ax, 0x1400
    add bx, ax
    adc dx, 0
    mov si, ne_tx_frame + tcp_offset
    mov cx, 10
.tcp_word:
    lodsw
    add bx, ax
    adc dx, 0
    loop .tcp_word
    add bx, dx
    adc bx, 0
    not bx
    mov [ne_tx_frame + tcp_offset + 16], bx
    ret

ne_try_receive_frame:
    cmp byte [handoff_addr + handoff_nic_family], family_3c501
    jne .dp8390
    jmp el1_try_receive_frame
.dp8390:
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

.filter_dhcp:
    cmp word [ne_rx_read_limit], dhcp_rx_frame_len
    jne .read_frame
    cmp ax, dhcp_filter_len
    jb .release_empty
    push ax
    mov bl, ne_rx_header_len
    mov bh, [ne_next_page]
    mov cx, dhcp_filter_len
    mov di, ne_tx_frame
    call ne_remote_read_bytes
    jc .prefix_dma_failed
    call dhcp_reply_prefix_matches
    pop ax
    jc .release_empty

.read_frame:
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

.release_empty:
    mov word [ne_rx_sample_count], 0
    jmp .release_frame

.count_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp .release_frame

.prefix_dma_failed:
    pop ax

.dma_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_dma
    stc
    ret

.header_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_header
    stc
    ret

el1_try_receive_frame:
    mov word [ne_rx_sample_count], 0
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_rcvptr
    in ax, dx
    mov [ne_rx_count], ax
    or ax, ax
    jnz .check_status
    mov byte [handoff_addr + handoff_net_status], net_status_rx_poll_ready
    clc
    ret

.check_status:
    mov dx, [handoff_addr + handoff_nic_base]
    in al, dx
    test al, el1_rx_status_good
    jz .release_empty
    mov ax, [ne_rx_count]
    cmp ax, ne_rx_max_count
    ja .count_failed
    cmp ax, [ne_rx_read_limit]
    jbe .sample_count_ready
    mov ax, [ne_rx_read_limit]
.sample_count_ready:
    mov [ne_rx_sample_count], ax
    mov cx, ax
    xor ax, ax
    call el1_set_gp
    mov di, ne_tx_frame
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_data
.read:
    in al, dx
    stosb
    loop .read
    mov byte [handoff_addr + handoff_net_status], net_status_rx_frame_read

.release_frame:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_rcvptr
    out dx, al
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_aux
    mov al, el1_aux_system
    out dx, al
    mov al, el1_aux_receive
    out dx, al
    clc
    ret
.release_empty:
    mov word [ne_rx_sample_count], 0
    jmp .release_frame
.count_failed:
    mov byte [handoff_addr + handoff_net_error], net_error_ne_rx_count
    jmp .release_frame

el1_set_gp:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_dataptr
    out dx, ax
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
    mov cx, 2
    call wait_ticks
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

ne_wait_for_dhcp_ack:
    mov word [ne_rx_read_limit], dhcp_rx_frame_len
    mov word [dhcp_wait_count], dhcp_ack_wait_count
.poll:
    call ne_try_receive_frame
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_dhcp_ack
    jnc .done
.wait:
    mov cx, 2
    call wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_request_sent
    mov byte [handoff_addr + handoff_net_error], net_error_dhcp_ack
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_request_sent
    clc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_dhcp_ack_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

ne_tcp_reachability_path:
    call ne_resolve_dns_arp
    jc .done
    cmp byte [handoff_addr + handoff_net_status], net_status_arp_resolved
    jne .failed
    call ne_transmit_dns_query
    jc .done
    call ne_wait_for_dns_response
    cmp byte [handoff_addr + handoff_net_status], net_status_dns_response_received
    jne .failed
    call ne_resolve_tcp_next_hop_arp
    jc .done
    cmp byte [handoff_addr + handoff_net_status], net_status_next_hop_arp_resolved
    jne .failed
    call ne_transmit_tcp_syn
    jc .done
    call ne_wait_for_tcp_synack
    cmp byte [handoff_addr + handoff_net_status], net_status_tcp_synack_received
    jne .failed
    clc
    ret
.failed:
    stc
.done:
    ret

ne_resolve_dns_arp:
    mov si, handoff_addr + handoff_dns_addr
    mov di, arp_target_ip
    mov cx, 4
    rep movsb
    mov byte [arp_status_sent], net_status_arp_request_sent
    mov byte [arp_status_resolved], net_status_arp_resolved
    mov byte [arp_error_code], net_error_arp
    call ne_resolve_arp_target
    ret

ne_resolve_tcp_next_hop_arp:
    call select_tcp_next_hop
    mov byte [arp_status_sent], net_status_next_hop_arp_request_sent
    mov byte [arp_status_resolved], net_status_next_hop_arp_resolved
    mov byte [arp_error_code], net_error_next_hop_arp
    call ne_resolve_arp_target
    ret

select_tcp_next_hop:
    mov si, handoff_addr + handoff_subnet_addr
    mov cx, 4
    xor al, al
.check_subnet:
    or al, [si]
    inc si
    loop .check_subnet
    or al, al
    jz .router

    mov si, tcp_target_ip
    mov di, handoff_addr + handoff_ip_addr
    mov bx, handoff_addr + handoff_subnet_addr
    mov cx, 4
.compare_net:
    lodsb
    mov ah, [bx]
    and al, ah
    mov dl, [di]
    and dl, ah
    cmp al, dl
    jne .router
    inc bx
    inc di
    loop .compare_net
    mov si, tcp_target_ip
    jmp .copy
.router:
    mov si, handoff_addr + handoff_router_addr
.copy:
    mov di, arp_target_ip
    mov cx, 4
    rep movsb
    ret

ne_resolve_arp_target:
    mov si, arp_target_ip
    mov cx, 4
    xor al, al
.check_target:
    or al, [si]
    inc si
    loop .check_target
    or al, al
    jnz .have_target
    mov al, [arp_error_code]
    mov [handoff_addr + handoff_net_error], al
    clc
    ret
.have_target:
    call ne_transmit_arp_request
    jc .done
    call ne_wait_for_arp_reply
.done:
    ret

ne_wait_for_arp_reply:
    mov word [ne_rx_read_limit], arp_tx_frame_len
    mov word [dhcp_wait_count], arp_wait_count
.poll:
    call ne_try_receive_frame
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_arp_reply
    jnc .done
.wait:
    mov cx, 2
    call wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov al, [arp_status_sent]
    mov [handoff_addr + handoff_net_status], al
    mov al, [arp_error_code]
    mov [handoff_addr + handoff_net_error], al
    clc
    ret
.failed:
    mov al, [arp_status_sent]
    mov [handoff_addr + handoff_net_status], al
    clc
    ret
.done:
    mov al, [arp_status_resolved]
    mov [handoff_addr + handoff_net_status], al
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

ne_wait_for_dns_response:
    mov word [ne_rx_read_limit], dns_rx_read_len
    mov word [dhcp_wait_count], dns_wait_count
.poll:
    call ne_try_receive_frame
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_dns_response
    jnc .done
.wait:
    mov cx, 2
    call wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_status], net_status_dns_query_sent
    mov byte [handoff_addr + handoff_net_error], net_error_dns
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], net_status_dns_query_sent
    clc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_dns_response_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

ne_wait_for_tcp_synack:
    mov word [ne_rx_read_limit], tcp_rx_read_len
    mov word [dhcp_wait_count], tcp_wait_count
.poll:
    call ne_try_receive_frame
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_tcp_synack
    jnc .done
.wait:
    mov cx, 2
    call wait_ticks
    dec word [dhcp_wait_count]
    jnz .poll
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_syn_sent
    mov byte [handoff_addr + handoff_net_error], net_error_tcp
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_syn_sent
    clc
    ret
.done:
    mov byte [handoff_addr + handoff_net_status], net_status_tcp_synack_received
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret

dhcp_reply_prefix_matches:
    cmp word [ne_tx_frame + 12], 0x0008
    jne .no
    cmp byte [ne_tx_frame + eth_header_len + 9], 17
    jne .no
    cmp word [ne_tx_frame + eth_header_len + ipv4_header_len], 0x4300
    jne .no
    cmp word [ne_tx_frame + eth_header_len + ipv4_header_len + 2], 0x4400
    jne .no
    cmp byte [ne_tx_frame + dhcp_bootp_offset], 2
    jne .no
    cmp byte [ne_tx_frame + dhcp_bootp_offset + 1], 1
    jne .no
    cmp byte [ne_tx_frame + dhcp_bootp_offset + 2], 6
    jne .no
    cmp word [ne_tx_frame + dhcp_bootp_offset + 4], 0x4553
    jne .no
    cmp word [ne_tx_frame + dhcp_bootp_offset + 6], 0x4445
    jne .no
    clc
    ret
.no:
    stc
    ret

parse_dhcp_offer:
    cmp word [ne_rx_sample_count], dhcp_options_offset + 3
    jb .not_offer
    call dhcp_reply_prefix_matches
    jc .not_offer

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
    mov cx, 8
    rep stosw
    mov di, dhcp_server_addr
    xor ax, ax
    stosw
    stosw
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
    jne .subnet
    cmp ax, 1
    jb .skip
    mov al, [si]
    mov [dhcp_message_type], al
    jmp .skip
.subnet:
    cmp byte [dhcp_option_code], 1
    jne .router
    cmp ax, 4
    jb .skip
    push si
    mov di, handoff_addr + handoff_subnet_addr
    mov cx, 4
    rep movsb
    pop si
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
    jne .server
    cmp ax, 4
    jb .skip
    push si
    mov di, handoff_addr + handoff_dns_addr
    mov cx, 4
    rep movsb
    pop si
    jmp .skip
.server:
    cmp byte [dhcp_option_code], 54
    jne .skip
    cmp ax, 4
    jb .skip
    push si
    mov di, dhcp_server_addr
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
    mov cx, 8
    rep stosw
    stc
    ret

parse_dhcp_ack:
    cmp word [ne_rx_sample_count], dhcp_options_offset + 3
    jb .not_ack
    call dhcp_reply_prefix_matches
    jc .not_ack

    mov si, ne_tx_frame + dhcp_chaddr_offset
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.check_mac:
    lodsb
    cmp al, [di]
    jne .not_ack
    inc di
    loop .check_mac

    cmp word [ne_tx_frame + dhcp_cookie_offset], 0x8263
    jne .not_ack
    cmp word [ne_tx_frame + dhcp_cookie_offset + 2], 0x6353
    jne .not_ack

    mov si, ne_tx_frame + dhcp_yiaddr_offset
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
.check_ip:
    lodsb
    cmp al, [di]
    jne .not_ack
    inc di
    loop .check_ip

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
    jne .skip
    cmp ax, 1
    jb .skip
    mov al, [si]
    mov [dhcp_message_type], al
.skip:
    mov cx, [dhcp_option_len]
    add si, cx
    sub [dhcp_options_left], cx
    jmp .option
.check_type:
    cmp byte [dhcp_message_type], 5
    jne .not_ack
    clc
    ret
.not_ack:
    stc
    ret

parse_arp_reply:
    cmp word [ne_rx_sample_count], arp_frame_len
    jb .not_reply
    cmp word [ne_tx_frame + 12], 0x0608
    jne .not_reply
    cmp word [ne_tx_frame + arp_payload_offset], 0x0100
    jne .not_reply
    cmp word [ne_tx_frame + arp_payload_offset + 2], 0x0008
    jne .not_reply
    cmp word [ne_tx_frame + arp_payload_offset + 4], 0x0406
    jne .not_reply
    cmp word [ne_tx_frame + arp_payload_offset + 6], 0x0200
    jne .not_reply

    mov si, ne_tx_frame + arp_tpa_offset
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
.check_target_ip:
    lodsb
    cmp al, [di]
    jne .not_reply
    inc di
    loop .check_target_ip

    mov si, ne_tx_frame + arp_spa_offset
    mov di, arp_target_ip
    mov cx, 4
.check_sender_ip:
    lodsb
    cmp al, [di]
    jne .not_reply
    inc di
    loop .check_sender_ip

    mov si, ne_tx_frame + arp_sha_offset
    mov di, arp_target_mac
    mov cx, 6
    rep movsb
    clc
    ret
.not_reply:
    stc
    ret

parse_dns_response:
    mov al, [dns_qname_len]
    xor ah, ah
    add ax, dns_payload_offset + 12 + 4 + 16
    cmp word [ne_rx_sample_count], ax
    jb .not_response
    cmp word [ne_tx_frame + 12], 0x0008
    jne .not_response
    cmp byte [ne_tx_frame + eth_header_len], 0x45
    jne .not_response
    cmp byte [ne_tx_frame + eth_header_len + 9], 17
    jne .not_response

    mov si, ne_tx_frame + eth_header_len + 12
    mov di, handoff_addr + handoff_dns_addr
    mov cx, 4
.check_source_ip:
    lodsb
    cmp al, [di]
    jne .not_response
    inc di
    loop .check_source_ip

    mov si, ne_tx_frame + eth_header_len + 16
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
.check_dest_ip:
    lodsb
    cmp al, [di]
    jne .not_response
    inc di
    loop .check_dest_ip

    cmp word [ne_tx_frame + dns_udp_offset], 0x3500
    jne .not_response
    cmp word [ne_tx_frame + dns_udp_offset + 2], 0x01c0
    jne .not_response
    cmp word [ne_tx_frame + dns_payload_offset], dns_query_id_word
    jne .not_response
    test byte [ne_tx_frame + dns_payload_offset + 2], 0x80
    jz .not_response
    cmp byte [ne_tx_frame + dns_payload_offset + 7], 0
    je .not_response

    mov si, ne_tx_frame + dns_payload_offset + 12
    mov bl, [dns_qname_len]
    xor bh, bh
    add si, bx
    add si, 4
    call dns_skip_name
    jc .not_response
    cmp word [si], 0x0100
    jne .not_response
    cmp word [si + 2], 0x0100
    jne .not_response
    cmp word [si + 8], 0x0400
    jne .not_response
    add si, 10
    mov di, tcp_target_ip
    mov cx, 4
    rep movsb
    clc
    ret
.not_response:
    stc
    ret

dns_skip_name:
    mov cx, 64
.part:
    lodsb
    mov ah, al
    and ah, 0xc0
    cmp ah, 0xc0
    je .pointer
    or ah, ah
    jnz .bad
    or al, al
    jz .done
    xor ah, ah
    add si, ax
    loop .part
.bad:
    stc
    ret
.pointer:
    lodsb
.done:
    clc
    ret

parse_tcp_synack:
    cmp word [ne_rx_sample_count], tcp_offset + 20
    jb .not_synack
    cmp word [ne_tx_frame + 12], 0x0008
    jne .not_synack
    cmp byte [ne_tx_frame + eth_header_len], 0x45
    jne .not_synack
    cmp byte [ne_tx_frame + eth_header_len + 9], 6
    jne .not_synack

    mov si, ne_tx_frame + eth_header_len + 12
    mov di, tcp_target_ip
    mov cx, 4
.check_source_ip:
    lodsb
    cmp al, [di]
    jne .not_synack
    inc di
    loop .check_source_ip

    mov si, ne_tx_frame + eth_header_len + 16
    mov di, handoff_addr + handoff_ip_addr
    mov cx, 4
.check_dest_ip:
    lodsb
    cmp al, [di]
    jne .not_synack
    inc di
    loop .check_dest_ip

    mov ax, [tcp_dest_port_word]
    cmp word [ne_tx_frame + tcp_offset], ax
    jne .not_synack
    cmp word [ne_tx_frame + tcp_offset + 2], tcp_source_port_word
    jne .not_synack
    mov al, [ne_tx_frame + tcp_offset + 13]
    and al, 0x12
    cmp al, 0x12
    jne .not_synack
    clc
    ret
.not_synack:
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

    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .check_3c503
    call wd_read_sharedmem_bytes
    clc
    ret

.check_3c503:
    cmp byte [handoff_addr + handoff_nic_family], family_3c503
    jne .remote_dma
    call c503_read_chipmem_bytes
    clc
    ret

.remote_dma:
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

wd_write_sharedmem_bytes:
    push es
    mov ax, wd_ram_segment
    mov es, ax
    mov di, bx
    rep movsb
    pop es
    ret

wd_read_sharedmem_bytes:
    mov bx, [ne_dma_addr]
    mov cx, [ne_dma_count]
    mov dh, [ne_rx_start]
    mov dl, [ne_rx_stop]
    push ds
    mov ax, wd_ram_segment
    mov ds, ax
    mov si, bx
.read:
    lodsb
    stosb
    mov ax, si
    cmp ah, dl
    jne .next
    or al, al
    jnz .next
    mov al, dh
    xor ah, ah
    xchg al, ah
    mov si, ax
.next:
    loop .read
    pop ds
    ret

c503_write_chipmem_bytes:
    mov [ne_dma_addr], bx
    mov [ne_dma_count], cx
    call c503_begin_dma
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_data
    mov cx, [ne_dma_count]
.write:
    lodsb
    out dx, al
    loop .write
    call c503_select_dp8390
    ret

c503_read_chipmem_bytes:
    call c503_begin_dma
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_data
    mov cx, [ne_dma_count]
.read:
    in al, dx
    stosb
    inc word [ne_dma_addr]
    mov ax, [ne_dma_addr]
    cmp ah, [ne_rx_stop]
    jne .next
    or al, al
    jnz .next
    mov al, [ne_rx_start]
    xor ah, ah
    xchg al, ah
    mov [ne_dma_addr], ax
    call c503_begin_dma
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_data
.next:
    loop .read
    call c503_select_dp8390
    ret

c503_begin_dma:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    mov al, el2_ctrl_dma | el2_ctrl_thin
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_da_high
    mov ax, [ne_dma_addr]
    mov al, ah
    out dx, al
    inc dx
    mov ax, [ne_dma_addr]
    out dx, al
    ret

render_adapter_question:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, adapter_prompt_text
    call type_z

    call type_menu_options
    ret

render_agent_question:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, agent_prompt_text
    call type_z

    call type_agent_options
    ret

render_agent_values_form:
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    call show_load_marker

    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, agent_prompt_text
    call type_z

    mov al, [form_left_col]
    mov [input_start_col], al
    call draw_agent_options_at_col

draw_agent_form_fields:
    call selected_agent_needs_endpoint
    jc .key_only
    mov al, question_row
    add al, [menu_index]
    mov [cursor_row], al
    mov si, endpoint_prompt_text
    mov di, seed_endpoint
    mov al, 0
    call draw_form_field
    mov al, question_row + 1
    add al, [menu_index]
    mov [cursor_row], al
    mov si, key_prompt_text
    mov di, seed_key
    mov al, 1
    call draw_form_field
    ret
.key_only:
    mov al, question_row
    add al, [menu_index]
    mov [cursor_row], al
    mov si, key_prompt_text
    mov di, seed_key
    mov al, 0
    call draw_form_field
    ret

draw_form_field:
    push ax
    mov [input_target], di
    mov al, [form_field_col]
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    pop ax
    cmp al, [menu_value_a]
    jne .label_ready
    mov bl, [question_attr]
.label_ready:
    call print_z
    mov al, [form_field_col]
    add al, 8
    mov [input_start_col], al
    call measure_input_len
    call render_text_input
    ret

type_agent_options:
    mov byte [agent_draw_index], 0
.next:
    mov al, [agent_draw_index]
    cmp al, [agent_count]
    jae .done
    mov al, question_row
    add al, [agent_draw_index]
    mov [cursor_row], al
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov al, [agent_draw_index]
    cmp al, [menu_index]
    jne .attr_ready
    mov bl, [menu_selected_attr]
.attr_ready:
    mov al, [agent_draw_index]
    call agent_ptr_from_al
    call type_z
    inc byte [agent_draw_index]
    jmp .next
.done:
    ret

draw_agent_options:
    mov al, [seed_col]
    add al, 2
    mov [input_start_col], al
draw_agent_options_at_col:
    mov byte [agent_draw_index], 0
.next:
    mov al, [agent_draw_index]
    cmp al, [agent_count]
    jae .done
    mov al, question_row
    add al, [agent_draw_index]
    mov [cursor_row], al
    mov al, [input_start_col]
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov al, [agent_draw_index]
    cmp al, [menu_index]
    jne .attr_ready
    mov bl, [menu_selected_attr]
.attr_ready:
    mov al, [agent_draw_index]
    call agent_ptr_from_al
    call print_z
    inc byte [agent_draw_index]
    jmp .next
.done:
    ret

agent_scan_ptr:
    mov al, [agent_scan_index]
    call agent_ptr_from_al
    ret

agent_ptr_from_al:
    xor ah, ah
    mov si, ax
    shl si, 1
    shl si, 1
    shl si, 1
    shl si, 1
    add si, agent_ids
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
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    xor byte [blink_state], 1
    jnz .show
    mov al, ' '
.show:
    call print_char
    mov cx, 2
    call wait_ticks
    ret

show_load_marker:
    mov [load_marker_char], al
    mov [load_marker_attr], bl
    call set_seed_cursor
    mov al, [load_marker_char]
    call print_char
    ret

clear_question_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, seed_row
    xor cl, cl
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

clear_panel_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, question_row
    xor cl, cl
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

clear_agent_field_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, question_row
    mov cl, [form_field_col]
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

clear_input_line:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, [cursor_row]
    mov cl, [input_start_col]
    mov dh, ch
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
ready_attr db ready_attr_cga
question_attr db question_attr_cga
error_attr db error_attr_cga
menu_selected_attr db menu_selected_attr_cga
menu_idle_attr db menu_idle_attr_cga
load_marker_char db ' '
load_marker_attr db load_attr_cga
menu_option_a dw 0
menu_option_b dw 0
menu_value_a db 0
menu_value_b db 0
menu_index db 0
input_target dw 0
input_max db 0
input_len db 0
input_start_col db 0
form_left_col db 2
form_field_col db 20
seed_config_flags db 0
seed_cfg_dirty db 0
agent_count db 0
agent_draw_index db 0
agent_scan_index db 0
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
el1_tx_ptr dw 0
ne_dma_addr dw 0
ne_dma_count dw 0
dhcp_wait_count dw 0
dhcp_options_left dw 0
dhcp_option_len dw 0
dhcp_option_code db 0
dhcp_message_type db 0
dhcp_server_addr times 4 db 0
arp_target_ip times 4 db 0
arp_target_mac times 6 db 0
arp_status_sent db net_status_arp_request_sent
arp_status_resolved db net_status_arp_resolved
arp_error_code db net_error_arp
tcp_target_ip times 4 db 0
tcp_dest_port_word dw tcp_port_http_word
dns_qname_len db dns_qname_default_len
dns_label_len db 0
dns_label_ptr dw 0
dns_tx_len dw dns_tx_frame_default_len
fs_lba dw 0
fs_root_left dw 0
fs_file_cluster dw 0
fs_file_size_low dw 0
fs_file_size_high dw 0
fs_file_root_lba dw 0
fs_file_root_offset dw 0
fs_free_root_found db 0
fs_free_root_lba dw 0
fs_free_root_offset dw 0
fs_current_cluster dw 0
fs_bytes_left dw 0
fs_bytes_this dw 0
fs_line_start db 0
fs_scan_cluster dw 0
fs_free_cluster dw 0
agents_cluster dw 0
agents_size_low dw 0
agents_size_high dw 0
seed_cluster dw 0
seed_size_low dw 0
seed_size_high dw 0
seed_root_lba dw 0
seed_root_offset dw 0
seed_cfg_size_current dw 0
ne_prom times ne_prom_len db 0
ne_tx_frame times dhcp_rx_frame_len db 0
fs_sector_buffer times 512 db 0
agent_ids times agent_slot_count * agent_id_len db 0
seed_agent_id times agent_id_len db 0
seed_model times seed_model_len db 0
seed_key times seed_key_len db 0
seed_endpoint times seed_endpoint_len db 0
seed_reasoning times seed_reasoning_len db 0
builtin_agent_ids db 'openai', 0
                  times agent_id_len - 7 db 0
                  db 'anthropic', 0
                  times agent_id_len - 10 db 0
                  db 'google', 0
                  times agent_id_len - 7 db 0
dns_default_qname db 7, 'example', 3, 'com', 0
dns_qname db 7, 'example', 3, 'com', 0
           times dns_qname_max_len - dns_qname_default_len db 0
seed_text db 'seed', 0
build_text db 'build ', '0' + build_number, 0
network_error_text db 'no network card', 0
network_setup_error_text db 'network setup failed', 0
agent_setup_error_text db 'agent setup failed', 0
retry_text db 'retry', 0
restart_text db 'restart', 0
adapter_prompt_text db 'adapter?', 0
adapter_ne2000_text db 'ne2000', 0
adapter_ne1000_text db 'ne1000', 0
adapter_3c501_text db '3c501', 0
adapter_wd8003_text db 'wd8003', 0
agents_cfg_name db 'AGENTS  CFG'
net_cfg_name db 'NET     CFG'
seed_cfg_name db 'SEED    CFG'
agent_prefix_text db 'agent ', 0
model_prefix_text db 'model ', 0
reasoning_prefix_text db 'reasoning ', 0
key_prefix_text db 'key ', 0
endpoint_prefix_text db 'endpoint ', 0
agent_prompt_text db 'agent?', 0
key_prompt_text db 'key?', 0
endpoint_prompt_text db 'server?', 0
host_openrouter_text db 'openrouter.ai', 0
host_openai_text db 'api.openai.com', 0
host_anthropic_text db 'api.anthropic.com', 0
host_google_text db 'generativelanguage.googleapis.com', 0
disk_sectors_per_track db 8
nic_ports dw 0x250, 0x280, 0x2a0, 0x2c0, 0x2e0
          dw 0x300, 0x310, 0x320, 0x330, 0x340
          dw 0x350, 0x360, 0x380, 0x3a0
          dw 0

times (STAGE2_SECTORS * 512) - ($ - $$) db 0
