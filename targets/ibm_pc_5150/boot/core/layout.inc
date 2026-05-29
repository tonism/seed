%ifndef LOADER_SECTORS
%define LOADER_SECTORS 4
%endif

build_number equ 8
core_load_addr equ 0x1000
handoff_addr equ 0x0600
low_sha256_k equ 0x0500
runtime_stack_top equ 0x8000
runtime_stack_guard_len equ 1536
low_scratch_start equ 0x0700
low_scratch_end equ 0x1000
net_setup_frame_scratch_len equ 512
net_setup_phase_start equ low_scratch_start + net_setup_frame_scratch_len
agent_response_phase_load_addr equ low_scratch_start + 0x0600
basic_sidecar_stack_top_16k equ 0x4000
basic_sidecar_stack_guard_len_16k equ 0x0200
basic_sidecar_stack_top_24k equ 0x6000
basic_sidecar_stack_guard_len_24k equ 0x0100
handoff_magic equ 0
handoff_version equ 4
handoff_size equ 5
handoff_build equ 7
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
handoff_ram_top equ 44
handoff_size_bytes equ 46
handoff_struct_version equ 3
basic_boot_magic_bx equ 0x5345
basic_boot_magic_cx equ 0x4544
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
net_status_tls_transcript_ready equ 28
net_status_tls_premaster_ready equ 29
net_status_tls_keys_ready equ 30
net_status_tls_clientkeyexchange_sent equ 31
net_status_tls_changecipherspec_sent equ 32
net_status_tls_clientfinished_sent equ 33
net_status_tls_serverccs_received equ 34
net_status_tls_serverfinished_verified equ 35
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
crypto_attr_cga equ 0x07
ready_attr_cga equ 0x0f
question_attr_cga equ 0x0f
error_attr_cga equ 0x0c
menu_selected_attr_cga equ 0x0f
menu_idle_attr_cga equ 0x08
color_video_seg equ 0xb800
seed_attr_mda equ 0x0f
build_attr_mda equ 0x07
load_attr_mda equ 0x07
crypto_attr_mda equ 0x07
ready_attr_mda equ 0x0f
question_attr_mda equ 0x0f
error_attr_mda equ 0x0f
menu_selected_attr_mda equ 0x0f
menu_idle_attr_mda equ 0x07
seed_len equ 4
seed_row equ 12
question_row equ seed_row + 2
dpi_prompt_row equ 24
dpi_prompt_col equ 0
dpi_input_max_len equ 128
api_response_text_max_len equ 192
load_ticks equ 6
type_ticks equ 1
done_ticks equ 9
agent_slot_count equ 5
adapter_select_io_280 equ 0
adapter_select_ne equ 1
agent_id_len equ 12
seed_model_len equ 64
; Seed policy cap for supported OpenAI/Anthropic/Google key formats.
seed_key_len equ 192
seed_endpoint_len equ 80
seed_reasoning_len equ 8
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
el2_start_page equ 0x400
el2_stop_page equ 0x401
el2_drq_count equ 0x402
el2_ga_config equ 0x405
el2_status equ 0x407
el2_da_high equ 0x409
el2_da_low equ 0x40a
el2_data equ 0x40e
el2_ctrl_thin equ 0x02
el2_ctrl_saprom equ 0x04
el2_ctrl_dma equ 0x80
el2_ctrl_download equ 0x40
el2_ga_config_norm equ 0x49
el2_status_dprdy equ 0x80
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
ne_rx_max_count equ 1518
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
dns_qname_max_len equ 80
dns_payload_base_len equ 12 + 4
dns_tx_frame_default_len equ eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len + dns_qname_default_len
dns_tx_frame_max_len equ eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len + dns_qname_max_len
dns_rx_read_len equ 192
dns_udp_offset equ eth_header_len + ipv4_header_len
dns_payload_offset equ dns_udp_offset + udp_header_len
dns_query_id_word equ 0x4453
dns_wait_count equ 32
tcp_ip_len equ ipv4_header_len + 20
tcp_tx_frame_len equ 60
tcp_rx_read_len equ 96
tcp_offset equ eth_header_len + ipv4_header_len
tcp_payload_offset equ tcp_offset + 20
tcp_payload_max_len equ 1460
tcp_payload_read_len equ tcp_payload_offset + tcp_payload_max_len
tls_payload_buffer_len equ tcp_payload_max_len
tls_pre_response_tail_len equ tls_app_record_buffer_len + (16 * 2) + (16 * 2) + tls_random_len + tls_master_secret_len + sha256_digest_len
tls_stream_buffer_len equ tls_payload_buffer_len + tls_pre_response_tail_len
critical_scratch_start equ 0x34c2
critical_scratch_len equ tls_stream_buffer_len
critical_scratch_end equ critical_scratch_start + critical_scratch_len
tcp_port_http_word equ 0x5000
tcp_port_https_word equ 0xbb01
tcp_wait_count equ 4
tcp_wait_count_3c501 equ 128
tcp_payload_wait_count equ 8192
tls_client_base_len equ 88
tls_body_base_len equ 79
tls_record_base_len equ 83
tls_extensions_base_len equ 36
tls_random_len equ 32
tls_after_random_len equ 7
tls_extensions_prefix_len equ 5
tls_extensions_tail_len equ 22
tls_bulk_aes_128_gcm equ 1
tls_bulk_aes_256_gcm equ 2
tls_bulk_chacha20_poly1305 equ 3
tls_prf_sha256 equ 1
tls_prf_sha384 equ 2
tls_curve_secp256r1 equ 0x0017
tls_ec_coordinate_len equ 32
tls_ec_public_uncompressed_len equ 65
sha256_digest_len equ 32
sha256_block_size equ 64
sha256_k_len equ 256
tls_master_secret_len equ 48
tls_key_block_len equ 88
tls_chacha_key_len equ 32
tls_chacha_iv_len equ 12
tls_prf_seed_max_len equ 77
tls_client_key_exchange_handshake_len equ 1 + tls_ec_public_uncompressed_len
tls_client_key_exchange_record_len equ 4 + tls_client_key_exchange_handshake_len
tls_client_key_exchange_total_len equ 5 + tls_client_key_exchange_record_len
tls_change_cipher_spec_total_len equ 6
tls_finished_verify_len equ 12
tls_finished_plain_len equ 4 + tls_finished_verify_len
tls_finished_cipher_len equ tls_finished_plain_len
tls_finished_record_len equ tls_finished_cipher_len + 16
tls_finished_total_len equ 5 + tls_finished_record_len
tls_aead_aad_len equ 13
tls_record_seq_len equ 8
tls_client_record_seq_len equ tls_record_seq_len
tls_server_record_seq_len equ tls_record_seq_len
tls_record_header_len equ 5
tls_aead_tag_len equ 16
tls_app_max_plain_len equ tcp_payload_max_len - tls_record_header_len - tls_aead_tag_len
; Fixed OpenAI proof request with max 192-byte key and max 64-byte model.
api_request_plain_len equ 440
api_ready_tiny_prompt_max equ 10
api_ready_short_prompt_max equ 24
tls_app_record_buffer_len equ api_request_plain_len + tls_record_header_len + tls_aead_tag_len
api_request_key_value_offset equ 71
api_request_model_value_offset equ 10
chacha_word_count equ 16
chacha_block_len equ 64
poly1305_r_len equ 16
poly1305_s_len equ 16
poly1305_acc_len equ 17
poly1305_product_len equ 36
poly1305_value_len equ 24
p256_word_count equ 16
p256_word_len equ p256_word_count * 2
p256_product_word_count equ p256_word_count * 2
p256_product_word_len equ p256_product_word_count * 2
high_crypto_scratch_start equ 0x3400
high_tls_client_write_key equ high_crypto_scratch_start
high_tls_server_write_key equ high_tls_client_write_key + tls_chacha_key_len
high_tls_client_write_iv equ high_tls_server_write_key + tls_chacha_key_len
high_tls_server_write_iv equ high_tls_client_write_iv + tls_chacha_iv_len
high_tls_client_record_seq equ high_tls_server_write_iv + tls_chacha_iv_len
high_tls_server_record_seq equ high_tls_client_record_seq + tls_client_record_seq_len
high_tls_client_nonce equ high_tls_server_record_seq + tls_server_record_seq_len
high_tls_aead_aad equ high_tls_client_nonce + tls_chacha_iv_len
high_tls_finished_plain equ high_tls_aead_aad + tls_aead_aad_len + 1
high_tls_finished_cipher equ high_tls_finished_plain + tls_finished_plain_len
high_tls_finished_tag equ high_tls_finished_cipher + tls_finished_cipher_len
high_tls_received_tag equ high_tls_finished_tag + tls_aead_tag_len
high_tls_persistent_end equ high_tls_received_tag + tls_aead_tag_len
high_crypto_work equ high_crypto_scratch_start
%if (high_crypto_work + tls_key_block_len) > high_tls_persistent_end
%error "high crypto work overlay exceeds persistent TLS key arena"
%endif
%if (high_crypto_work + (agent_slot_count * 16)) > high_tls_persistent_end
%error "agent id overlay exceeds persistent TLS key arena"
%endif
high_crypto_scratch_end equ high_tls_persistent_end
%if critical_scratch_start != high_crypto_scratch_end
%error "critical scratch must immediately follow high crypto scratch"
%endif
wd_saprom equ 0x08
fat_root_start_lba equ LOADER_SECTORS + 3
fat_fat_start_lba equ LOADER_SECTORS + 1
fat_data_start_lba equ LOADER_SECTORS + 7
fat_root_sectors equ 4
fat_dir_entries_per_sector equ 16
fat_dir_entry_size equ 32
fat_first_data_cluster equ 2
fat_max_cluster equ 300
