cursor_row db 0
cursor_col db 0
screen_cols db 80
seed_col db (80 - seed_len) / 2
seed_attr db seed_attr_cga
build_attr db build_attr_cga
load_attr db load_attr_cga
crypto_attr db crypto_attr_cga
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
tls_app_data_ptr dw 0
tls_app_plain_ptr dw 0
tls_app_record_ptr dw 0
tls_app_len dw 0
tls_app_record_len dw 0
tls_app_total_len dw 0
tls_app_chunk_len dw 0
tls_app_sent db 0
tls_prepared_app_len dw 0
api_body_len dw 0
api_answer_ptr dw 0
api_answer_len dw 0
api_receive_tries db 0
api_decimal_started db 0
tls_app_content_type db 0
tls_random_state dw 0
tls_transcript_len_low dw 0
tls_transcript_len_high dw 0
tls_transcript_certificate_remaining dw 0
sha256_w_ptr dw 0
sha256_k_ptr dw 0
sha256_len_low dw 0
sha256_len_high dw 0
sha256_saved_len_low dw 0
sha256_saved_len_high dw 0
sha256_bit_len0 dw 0
sha256_bit_len1 dw 0
sha256_bit_len2 dw 0
sha256_bit_len3 dw 0
sha256_digest_ptr dw 0
hmac_key_ptr dw 0
hmac_key_len dw 0
hmac_data1_ptr dw 0
hmac_data1_len dw 0
hmac_data2_ptr dw 0
hmac_data2_len dw 0
hmac_data3_ptr dw 0
hmac_data3_len dw 0
hmac_output_ptr dw 0
tls_prf_secret_ptr dw 0
tls_prf_secret_len dw 0
tls_prf_seed_ptr dw 0
tls_prf_seed_len dw 0
tls_prf_output_ptr dw 0
tls_prf_output_len dw 0
tls_prf_output_remaining dw 0
tls_prf_chunk_len dw 0
tls_prf_current_output_ptr dw 0
tls_prf_prepared_hmac db 0
chacha_key_ptr dw 0
chacha_nonce_ptr dw 0
chacha_counter_low dw 0
chacha_counter_high dw 0
poly_block_ptr dw 0
poly_i db 0
poly_j db 0
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
tls_key_schedule_ready db 0
sha256_block_len db 0
sha256_saved_block_len db 0
sha256_schedule_count db 0
sha256_round_count db 0
tls_next_handshake_body_ptr dw 0
dns_qname_len db dns_qname_default_len
dns_label_len db 0
dns_answer_remaining db 0
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
ne_tx_frame equ low_scratch_start
ne_prom equ ne_tx_frame + net_frame_buffer_len
low_packet_scratch_end equ ne_prom + ne_prom_len
fs_sector_buffer equ low_packet_scratch_end
low_file_scratch_end equ fs_sector_buffer + 512
%if low_file_scratch_end > low_scratch_end
%error "low packet scratch arena overflow"
%endif
tls_rx_copy times tls_stream_buffer_len db 0
api_request_plain times tls_app_record_buffer_len db 0
tls_app_record_buffer equ api_request_plain
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
sha256_saved_state times 16 dw 0
sha256_saved_block times sha256_block_size db 0
sha256_w times 128 dw 0
hmac_ipad times sha256_block_size db 0
hmac_opad times sha256_block_size db 0
hmac_inner_digest times sha256_digest_len db 0
hmac_prepared_inner_state times 16 dw 0
hmac_prepared_outer_state times 16 dw 0
tls_prf_seed times tls_prf_seed_max_len db 0
tls_prf_a times sha256_digest_len db 0
tls_prf_chunk times sha256_digest_len db 0
seed_agent_id times agent_id_len db 0
seed_model times seed_model_len db 0
seed_key times seed_key_len db 0
seed_endpoint times seed_endpoint_len db 0
seed_reasoning times seed_reasoning_len db 0
tls_server_random times tls_random_len db 0
tls_server_ec_x_words times p256_word_len db 0
tls_server_ec_y_words times p256_word_len db 0
tls_master_secret times tls_master_secret_len db 0
tls_client_write_key times tls_chacha_key_len db 0
tls_server_write_key times tls_chacha_key_len db 0
tls_client_write_iv times tls_chacha_iv_len db 0
tls_server_write_iv times tls_chacha_iv_len db 0
tls_client_record_seq times tls_client_record_seq_len db 0
tls_server_record_seq times tls_server_record_seq_len db 0
tls_client_nonce times tls_chacha_iv_len db 0
tls_aead_aad times tls_aead_aad_len db 0
tls_handshake_hash times sha256_digest_len db 0
tls_verify_data times tls_finished_verify_len db 0
tls_finished_plain times tls_finished_plain_len db 0
tls_finished_cipher times tls_finished_cipher_len db 0
tls_finished_tag times 16 db 0
tls_received_tag times 16 db 0
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
p256_reduce_acc times p256_word_count * 4 db 0
agent_ids equ p256_lhs
tls_premaster_secret equ p256_lhs
tls_key_block equ p256_lhs
tls_shared_x_words equ p256_s8
chacha_state equ p256_lhs
chacha_work equ p256_tmp
chacha_block equ p256_jac_y
poly_r equ p256_s0
poly_s equ p256_s0 + poly1305_r_len
poly_acc equ p256_s1
poly_block equ p256_s2
poly_product equ p256_s3
poly_value equ p256_s5
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
p256_inv_output_ptr dw 0
p256_mul_left_word dw 0
p256_mul_acc0 dw 0
p256_mul_acc1 dw 0
p256_mul_acc2 dw 0
p256_reduce_carry dw 0
p256_i db 0
p256_j db 0
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
http_post_text db 'POST ', 0
http_openai_path_text db '/v1/responses', 0
http_version_text db ' HTTP/1.1', 13, 10, 0
http_host_text db 'Host: ', 0
http_auth_bearer_text db 'Authorization: Bearer ', 0
http_content_type_text db 'Content-Type: application/json', 13, 10, 0
http_content_length_text db 'Content-Length: ', 0
api_json_model_text db '{"model":"', 0
api_json_input_text db '","input":"Reply exactly: ok","store":false', 0
api_json_plain_close_text db '}', 0
api_answer_output_pattern db '"output_text":"', 0
api_answer_output_spaced_pattern db '"output_text": "', 0
api_answer_text_pattern db '"text":"', 0
api_answer_text_spaced_pattern db '"text": "', 0
api_error_message_pattern db '"message":"', 0
api_error_message_spaced_pattern db '"message": "', 0
tls_random db 'SEEDBUILD6TLSCLIENTHELLO00000000'
tls_after_random db 0
                 db 0, 2
                 db 0xcc, 0xa9
                 db 1, 0
tls_extensions_prefix db 0xff, 1, 0, 1, 0
tls_extensions_tail db 0, 11, 0, 2, 1, 0
                    db 0, 10, 0, 4, 0, 2, 0, 23
                    db 0, 35, 0, 0
                    db 0, 22, 0, 0
                    db 0, 13, 0, 42, 0, 40
                    db 4, 3, 5, 3, 6, 3, 8, 7
                    db 8, 8, 8, 9, 8, 10, 8, 11
                    db 8, 4, 8, 5, 8, 6, 4, 1
                    db 5, 1, 6, 1, 3, 3, 3, 1
                    db 3, 2, 4, 2, 5, 2, 6, 2
tls_client_ec_public db 0x04
                     db 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47
                     db 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2
                     db 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0
                     db 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
                     db 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b
                     db 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16
                     db 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce
                     db 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
tls_label_master_secret db 'master secret'
tls_label_master_secret_len equ $ - tls_label_master_secret
tls_label_extended_master_secret db 'extended master secret'
tls_label_extended_master_secret_len equ $ - tls_label_extended_master_secret
tls_label_key_expansion db 'key expansion'
tls_label_key_expansion_len equ $ - tls_label_key_expansion
tls_label_client_finished db 'client finished'
tls_label_client_finished_len equ $ - tls_label_client_finished
tls_label_server_finished db 'server finished'
tls_label_server_finished_len equ $ - tls_label_server_finished
chacha_constants dw 0x7865, 0x6170, 0x646e, 0x3320
                 dw 0x2d32, 0x7962, 0x6574, 0x6b20
poly1305_prime db 0xfb
               times 15 db 0xff
               db 0x03
p256_prime dw 0xffff, 0xffff, 0xffff, 0xffff
           dw 0xffff, 0xffff, 0x0000, 0x0000
           dw 0x0000, 0x0000, 0x0000, 0x0000
           dw 0x0001, 0x0000, 0xffff, 0xffff
; Insecure Build 6 scalar. Keeps the 5150 TLS proof under cloud handshake
; timeouts. Replace with entropy-backed scalar math before sending secrets.
p256_client_private dw 0x0001, 0x0000, 0x0000, 0x0000
                    dw 0x0000, 0x0000, 0x0000, 0x0000
                    dw 0x0000, 0x0000, 0x0000, 0x0000
                    dw 0x0000, 0x0000, 0x0000, 0x0000
                   db 0, 0, 0, -1, 0, -1, 0, -1, 0, 0, 0, 1, 0, 2, 0, 3
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
