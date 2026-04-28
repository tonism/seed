%ifndef LOADER_SECTORS
%define LOADER_SECTORS 4
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
net_status_tcp_connected equ 18
net_status_tcp_payload_sent equ 19
net_status_tcp_payload_received equ 20
net_status_tls_clienthello_sent equ 21
net_status_tls_record_received equ 22
net_status_tls_serverhello_received equ 23
net_status_tls_certificate_received equ 24
net_status_tls_certificate_drained equ 25
net_status_tls_serverkeyexchange_received equ 26
net_status_tls_serverhellodone_received equ 27
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
net_error_tls equ 13
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
net_frame_buffer_len equ ne_rx_max_count
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
tcp_payload_offset equ tcp_offset + 20
tcp_payload_max_len equ dhcp_rx_frame_len - tcp_payload_offset
tcp_payload_read_len equ net_frame_buffer_len
tcp_source_port_word equ 0x02c0
tcp_port_http_word equ 0x5000
tcp_port_https_word equ 0xbb01
tcp_wait_count equ 4
tcp_payload_wait_count equ 32
tls_client_base_len equ 106
tls_body_base_len equ 97
tls_record_base_len equ 101
tls_extensions_base_len equ 46
tls_random_len equ 32
tls_after_random_len equ 15
tls_extensions_tail_len equ 37
tls_ext_ec_point_formats equ 0x01
tls_ext_extended_master_secret equ 0x02
tls_ext_renegotiation_info equ 0x04
tls_ext_session_ticket equ 0x08
tls_ext_alpn equ 0x10
tls_ext_supported_versions equ 0x20
tls_kx_ecdhe_rsa equ 1
tls_kx_rsa equ 2
tls_bulk_aes_128_gcm equ 1
tls_bulk_aes_256_gcm equ 2
tls_bulk_chacha20_poly1305 equ 3
tls_prf_sha256 equ 1
tls_prf_sha384 equ 2
tls_curve_secp256r1 equ 0x0017
wd_saprom equ 0x08
fat_root_start_lba equ LOADER_SECTORS + 3
fat_fat_start_lba equ LOADER_SECTORS + 1
fat_data_start_lba equ LOADER_SECTORS + 7
fat_root_sectors equ 4
fat_dir_entries_per_sector equ 16
fat_dir_entry_size equ 32
fat_first_data_cluster equ 2
fat_max_cluster equ 300
