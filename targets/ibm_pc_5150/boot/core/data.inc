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
user_cfg_dirty db 0
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
tls_buffered_payload_ptr dw 0
tls_buffered_payload_len dw 0
tls_server_record_len dw 0
tls_server_handshake_len dw 0
tls_server_extensions_len dw 0
tls_server_cipher dw 0
tls_server_certificate_record_len dw 0
tls_server_certificate_total_len dw 0
tls_server_next_record_len dw 0
tls_server_next_handshake_len_low dw 0
tls_server_next_total_len dw 0
tls_server_key_curve dw 0
tls_server_signature_len dw 0
tls_current_payload_ptr dw 0
tls_current_payload_len dw 0
tls_stream_skip_remaining dw 0
tls_transcript_len_low dw 0
tls_transcript_len_high dw 0
tls_transcript_certificate_remaining dw 0
sha256_w_ptr dw 0
sha256_k_ptr dw 0
tls_server_certificate_len_low dw 0
tls_server_certificate_list_len_low dw 0
tls_record_major db 0
tls_record_minor db 0
tls_server_major db 0
tls_server_minor db 0
tls_server_session_id_len db 0
tls_server_compression db 0
tls_server_extension_flags db 0
tls_server_key_exchange db 0
tls_server_bulk_cipher db 0
tls_server_prf_hash db 0
tls_server_next_handshake_type db 0
tls_server_next_handshake_len_high db 0
tls_server_key_public_len db 0
tls_server_signature_hash db 0
tls_server_signature_alg db 0
tls_server_certificate_len_high db 0
tls_server_certificate_list_len_high db 0
tls_transcript_flags db 0
sha256_block_len db 0
sha256_schedule_count db 0
sha256_round_count db 0
tls_next_handshake_body_ptr dw 0
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
user_cfg_size_current dw 0
ne_prom times ne_prom_len db 0
ne_tx_frame times net_frame_buffer_len db 0
tls_rx_copy times tcp_payload_read_len db 0
fs_sector_buffer times 512 db 0
sha256_state times 16 dw 0
sha256_a dw 0, 0
sha256_b dw 0, 0
sha256_c dw 0, 0
sha256_d dw 0, 0
sha256_e dw 0, 0
sha256_f dw 0, 0
sha256_g dw 0, 0
sha256_h dw 0, 0
sha256_t1 dw 0, 0
sha256_t2 dw 0, 0
sha256_new_e dw 0, 0
sha256_tmp dw 0, 0
sha256_block times 64 db 0
sha256_w times 128 dw 0
agent_ids times agent_slot_count * agent_id_len db 0
seed_agent_id times agent_id_len db 0
seed_model times seed_model_len db 0
seed_key times seed_key_len db 0
seed_endpoint times seed_endpoint_len db 0
seed_reasoning times seed_reasoning_len db 0
tls_server_random times tls_random_len db 0
tls_server_ec_x times tls_ec_coordinate_len db 0
tls_server_ec_y times tls_ec_coordinate_len db 0
tls_server_ec_x_words times p256_word_len db 0
tls_server_ec_y_words times p256_word_len db 0
p256_lhs times p256_word_len db 0
p256_rhs times p256_word_len db 0
p256_tmp times p256_word_len db 0
p256_jac_x times p256_word_len db 0
p256_jac_y times p256_word_len db 0
p256_jac_z times p256_word_len db 0
p256_s0 times p256_word_len db 0
p256_s1 times p256_word_len db 0
p256_s2 times p256_word_len db 0
p256_s3 times p256_word_len db 0
p256_s4 times p256_word_len db 0
p256_s5 times p256_word_len db 0
p256_s6 times p256_word_len db 0
p256_s7 times p256_word_len db 0
p256_s8 times p256_word_len db 0
p256_product times p256_product_word_len db 0
p256_affine_x_ptr dw 0
p256_affine_y_ptr dw 0
p256_scalar_ptr dw 0
p256_scalar_word_ptr dw 0
p256_scalar_word_value dw 0
p256_scalar_mask dw 0
p256_scalar_word_count db 0
p256_left_ptr dw 0
p256_right_ptr dw 0
p256_result_ptr dw 0
p256_mul_left_word dw 0
p256_mul_carry dw 0
p256_i db 0
p256_j db 0
p256_word_shift db 0
p256_bit_shift db 0
p256_carry db 0
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
user_cfg_name db 'USER    CFG'
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
                 db 0, 2
                 db 0xcc, 0xa8
                 db 1, 0
tls_extensions_tail db 0, 10, 0, 4, 0, 2, 0, 23
                    db 0, 11, 0, 2, 1, 0
                    db 0, 13, 0, 10, 0, 8, 4, 3, 5, 3, 4, 1, 5, 1
                    db 0, 23, 0, 0
                    db 0xff, 1, 0, 1, 0
p256_prime dw 0xffff, 0xffff, 0xffff, 0xffff
           dw 0xffff, 0xffff, 0x0000, 0x0000
           dw 0x0000, 0x0000, 0x0000, 0x0000
           dw 0x0001, 0x0000, 0xffff, 0xffff
p256_b dw 0x604b, 0x27d2, 0x3c3e, 0x3bce
       dw 0xb0f6, 0xcc53, 0x06b0, 0x651d
       dw 0x86bc, 0x7698, 0xbd55, 0xb3eb
       dw 0x93e7, 0xaa3a, 0x35d8, 0x5ac6
p256_client_private dw 0x31a7, 0xf75b, 0xb1a6, 0x1a07
                    dw 0x47a4, 0xd18b, 0xbda7, 0x01d0
                    dw 0x3645, 0x60ad, 0x8e6c, 0xb1d3
                    dw 0x79a4, 0x982d, 0xf9e2, 0xc9a1
p256_prime_shift_ptrs dw p256_prime_shift_0, p256_prime_shift_1
                      dw p256_prime_shift_2, p256_prime_shift_3
                      dw p256_prime_shift_4, p256_prime_shift_5
                      dw p256_prime_shift_6, p256_prime_shift_7
                      dw p256_prime_shift_8, p256_prime_shift_9
                      dw p256_prime_shift_10, p256_prime_shift_11
                      dw p256_prime_shift_12, p256_prime_shift_13
                      dw p256_prime_shift_14, p256_prime_shift_15
p256_prime_shift_0 dw 0xffff, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x0000, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0001, 0x0000, 0xffff, 0xffff
                   dw 0x0000
p256_prime_shift_1 dw 0xfffe, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x0001, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0002, 0x0000, 0xfffe, 0xffff
                   dw 0x0001
p256_prime_shift_2 dw 0xfffc, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x0003, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0004, 0x0000, 0xfffc, 0xffff
                   dw 0x0003
p256_prime_shift_3 dw 0xfff8, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x0007, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0008, 0x0000, 0xfff8, 0xffff
                   dw 0x0007
p256_prime_shift_4 dw 0xfff0, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x000f, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0010, 0x0000, 0xfff0, 0xffff
                   dw 0x000f
p256_prime_shift_5 dw 0xffe0, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x001f, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0020, 0x0000, 0xffe0, 0xffff
                   dw 0x001f
p256_prime_shift_6 dw 0xffc0, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x003f, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0040, 0x0000, 0xffc0, 0xffff
                   dw 0x003f
p256_prime_shift_7 dw 0xff80, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x007f, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0080, 0x0000, 0xff80, 0xffff
                   dw 0x007f
p256_prime_shift_8 dw 0xff00, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x00ff, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0100, 0x0000, 0xff00, 0xffff
                   dw 0x00ff
p256_prime_shift_9 dw 0xfe00, 0xffff, 0xffff, 0xffff
                   dw 0xffff, 0xffff, 0x01ff, 0x0000
                   dw 0x0000, 0x0000, 0x0000, 0x0000
                   dw 0x0200, 0x0000, 0xfe00, 0xffff
                   dw 0x01ff
p256_prime_shift_10 dw 0xfc00, 0xffff, 0xffff, 0xffff
                    dw 0xffff, 0xffff, 0x03ff, 0x0000
                    dw 0x0000, 0x0000, 0x0000, 0x0000
                    dw 0x0400, 0x0000, 0xfc00, 0xffff
                    dw 0x03ff
p256_prime_shift_11 dw 0xf800, 0xffff, 0xffff, 0xffff
                    dw 0xffff, 0xffff, 0x07ff, 0x0000
                    dw 0x0000, 0x0000, 0x0000, 0x0000
                    dw 0x0800, 0x0000, 0xf800, 0xffff
                    dw 0x07ff
p256_prime_shift_12 dw 0xf000, 0xffff, 0xffff, 0xffff
                    dw 0xffff, 0xffff, 0x0fff, 0x0000
                    dw 0x0000, 0x0000, 0x0000, 0x0000
                    dw 0x1000, 0x0000, 0xf000, 0xffff
                    dw 0x0fff
p256_prime_shift_13 dw 0xe000, 0xffff, 0xffff, 0xffff
                    dw 0xffff, 0xffff, 0x1fff, 0x0000
                    dw 0x0000, 0x0000, 0x0000, 0x0000
                    dw 0x2000, 0x0000, 0xe000, 0xffff
                    dw 0x1fff
p256_prime_shift_14 dw 0xc000, 0xffff, 0xffff, 0xffff
                    dw 0xffff, 0xffff, 0x3fff, 0x0000
                    dw 0x0000, 0x0000, 0x0000, 0x0000
                    dw 0x4000, 0x0000, 0xc000, 0xffff
                    dw 0x3fff
p256_prime_shift_15 dw 0x8000, 0xffff, 0xffff, 0xffff
                    dw 0xffff, 0xffff, 0x7fff, 0x0000
                    dw 0x0000, 0x0000, 0x0000, 0x0000
                    dw 0x8000, 0x0000, 0x8000, 0xffff
                    dw 0x7fff
sha256_initial_state dw 0xe667, 0x6a09, 0xae85, 0xbb67
                     dw 0xf372, 0x3c6e, 0xf53a, 0xa54f
                     dw 0x527f, 0x510e, 0x688c, 0x9b05
                     dw 0xd9ab, 0x1f83, 0xcd19, 0x5be0
sha256_k dw 0x2f98, 0x428a, 0x4491, 0x7137
         dw 0xfbcf, 0xb5c0, 0xdba5, 0xe9b5
         dw 0xc25b, 0x3956, 0x11f1, 0x59f1
         dw 0x82a4, 0x923f, 0x5ed5, 0xab1c
         dw 0xaa98, 0xd807, 0x5b01, 0x1283
         dw 0x85be, 0x2431, 0x7dc3, 0x550c
         dw 0x5d74, 0x72be, 0xb1fe, 0x80de
         dw 0x06a7, 0x9bdc, 0xf174, 0xc19b
         dw 0x69c1, 0xe49b, 0x4786, 0xefbe
         dw 0x9dc6, 0x0fc1, 0xa1cc, 0x240c
         dw 0x2c6f, 0x2de9, 0x84aa, 0x4a74
         dw 0xa9dc, 0x5cb0, 0x88da, 0x76f9
         dw 0x5152, 0x983e, 0xc66d, 0xa831
         dw 0x27c8, 0xb003, 0x7fc7, 0xbf59
         dw 0x0bf3, 0xc6e0, 0x9147, 0xd5a7
         dw 0x6351, 0x06ca, 0x2967, 0x1429
         dw 0x0a85, 0x27b7, 0x2138, 0x2e1b
         dw 0x6dfc, 0x4d2c, 0x0d13, 0x5338
         dw 0x7354, 0x650a, 0x0abb, 0x766a
         dw 0xc92e, 0x81c2, 0x2c85, 0x9272
         dw 0xe8a1, 0xa2bf, 0x664b, 0xa81a
         dw 0x8b70, 0xc24b, 0x51a3, 0xc76c
         dw 0xe819, 0xd192, 0x0624, 0xd699
         dw 0x3585, 0xf40e, 0xa070, 0x106a
         dw 0xc116, 0x19a4, 0x6c08, 0x1e37
         dw 0x774c, 0x2748, 0xbcb5, 0x34b0
         dw 0x0cb3, 0x391c, 0xaa4a, 0x4ed8
         dw 0xca4f, 0x5b9c, 0x6ff3, 0x682e
         dw 0x82ee, 0x748f, 0x636f, 0x78a5
         dw 0x7814, 0x84c8, 0x0208, 0x8cc7
         dw 0xfffa, 0x90be, 0x6ceb, 0xa450
         dw 0xa3f7, 0xbef9, 0x78f2, 0xc671
disk_sectors_per_track db 8
nic_ports dw 0x250, 0x280, 0x2a0, 0x2c0, 0x2e0
          dw 0x300, 0x310, 0x320, 0x330, 0x340
          dw 0x350, 0x360, 0x380, 0x3a0
          dw 0
