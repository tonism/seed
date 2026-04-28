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
tcp_local_seq times 4 db 0
tcp_remote_ack times 4 db 0
tcp_tx_flags db 0
tcp_tx_len dw 0
tcp_tx_payload_ptr dw 0
tcp_tx_payload_len dw 0
tcp_rx_payload_ptr dw 0
tcp_rx_payload_len dw 0
tcp_rx_wire_payload_len dw 0
tcp_rx_header_len db 0
tls_tx_len dw 0
tls_host_len dw 0
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
tls_random db 'SEEDBUILD6TLSCLIENTHELLO00000000'
tls_after_random db 0
                 db 0, 10
                 db 0xc0, 0x2f
                 db 0xc0, 0x30
                 db 0xcc, 0xa8
                 db 0x00, 0x9c
                 db 0x00, 0x9d
                 db 1, 0
tls_extensions_tail db 0, 10, 0, 4, 0, 2, 0, 23
                    db 0, 11, 0, 2, 1, 0
                    db 0, 13, 0, 10, 0, 8, 4, 3, 5, 3, 4, 1, 5, 1
                    db 0, 23, 0, 0
                    db 0xff, 1, 0, 1, 0
disk_sectors_per_track db 8
nic_ports dw 0x250, 0x280, 0x2a0, 0x2c0, 0x2e0
          dw 0x300, 0x310, 0x320, 0x330, 0x340
          dw 0x350, 0x360, 0x380, 0x3a0
          dw 0

times (STAGE2_SECTORS * 512) - ($ - $$) db 0
