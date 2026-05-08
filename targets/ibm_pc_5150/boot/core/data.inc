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
arp_target_mac times 6 db 0
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
api_receive_tries db 0
tls_app_content_type db 0
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
chacha_key_ptr dw 0
chacha_nonce_ptr dw 0
chacha_counter_low dw 0
chacha_counter_high dw 0
poly_block_ptr dw 0
poly_i db 0
poly_j db 0
tls_server_certificate_len_low dw 0
tls_server_certificate_list_len_low dw 0
tls_server_next_handshake_type db 0
tls_server_next_handshake_len_high db 0
tls_server_key_public_len db 0
tls_server_signature_hash db 0
tls_server_signature_alg db 0
tls_server_certificate_len_high db 0
tls_server_certificate_list_len_high db 0
tls_key_schedule_ready db 0
sha256_block_len db 0
sha256_saved_block_len db 0
sha256_schedule_count db 0
sha256_round_count db 0
tls_next_handshake_body_ptr dw 0
dns_qname_len db dns_qname_default_len
dns_tx_len dw dns_tx_frame_default_len
ne_tx_frame equ low_scratch_start
ne_prom equ ne_tx_frame + net_frame_buffer_len
low_packet_scratch_end equ ne_prom + ne_prom_len
fs_sector_buffer equ low_packet_scratch_end
low_file_scratch_end equ fs_sector_buffer + 512
fs_lba equ low_file_scratch_end
fs_root_left equ fs_lba + 2
fs_file_cluster equ fs_root_left + 2
fs_file_size_low equ fs_file_cluster + 2
fs_file_size_high equ fs_file_size_low + 2
fs_current_cluster equ fs_file_size_high + 2
fs_bytes_left equ fs_current_cluster + 2
fs_bytes_this equ fs_bytes_left + 2
fs_line_start equ fs_bytes_this + 2
agents_cluster equ fs_line_start + 1
agents_size_low equ agents_cluster + 2
agents_size_high equ agents_size_low + 2
seed_cluster equ agents_size_high + 2
seed_size_low equ seed_cluster + 2
seed_size_high equ seed_size_low + 2
seed_root_lba equ seed_size_high + 2
seed_root_offset equ seed_root_lba + 2
user_cfg_size_current equ seed_root_offset + 2
menu_value_a equ user_cfg_size_current + 2
menu_index equ menu_value_a + 1
input_target equ menu_index + 1
input_max equ input_target + 2
input_len equ input_max + 1
input_start_col equ input_len + 1
form_left_col equ input_start_col + 1
form_field_col equ form_left_col + 1
seed_config_flags equ form_field_col + 1
user_cfg_dirty equ seed_config_flags + 1
agent_count equ user_cfg_dirty + 1
agent_draw_index equ agent_count + 1
agent_scan_index equ agent_draw_index + 1
blink_state equ agent_scan_index + 1
dhcp_options_left equ blink_state + 1
dhcp_option_len equ dhcp_options_left + 2
dhcp_option_code equ dhcp_option_len + 2
dhcp_message_type equ dhcp_option_code + 1
dhcp_server_addr equ dhcp_message_type + 1
arp_target_ip equ dhcp_server_addr + 4
arp_status_sent equ arp_target_ip + 4
arp_status_resolved equ arp_status_sent + 1
arp_error_code equ arp_status_resolved + 1
dns_label_len equ arp_error_code + 1
dns_answer_remaining equ dns_label_len + 1
dns_label_ptr equ dns_answer_remaining + 1
cursor_row equ dns_label_ptr + 2
cursor_col equ cursor_row + 1
screen_cols equ cursor_col + 1
seed_col equ screen_cols + 1
seed_attr equ seed_col + 1
build_attr equ seed_attr + 1
load_attr equ build_attr + 1
crypto_attr equ load_attr + 1
ready_attr equ crypto_attr + 1
question_attr equ ready_attr + 1
error_attr equ question_attr + 1
menu_selected_attr equ error_attr + 1
menu_idle_attr equ menu_selected_attr + 1
load_marker_char equ menu_idle_attr + 1
load_marker_attr equ load_marker_char + 1
low_phase_state_end equ load_marker_attr + 1
%if low_file_scratch_end > low_scratch_end
%error "low packet scratch arena overflow"
%endif
%if low_phase_state_end > low_scratch_end
%error "low phase state arena overflow"
%endif
tls_rx_copy equ critical_scratch_start
tls_client_hello_buffer equ tls_rx_copy
dns_qname equ tls_rx_copy + 512

; The second receive-buffer payload is only needed after the request has been
; sent. Until then it can hold setup/request scratch without reducing the
; two-payload response receive window.
tls_pre_response_scratch equ tls_rx_copy + tcp_payload_read_len
%if (dns_qname + dns_qname_max_len) > tls_pre_response_scratch
%error "dns_qname scratch overlaps pre-response scratch"
%endif
api_request_plain equ tls_pre_response_scratch
tls_app_record_buffer equ api_request_plain
sha256_saved_state equ api_request_plain + tls_app_record_buffer_len
sha256_saved_block equ sha256_saved_state + (16 * 2)
hmac_ipad equ sha256_saved_block + sha256_block_size
hmac_opad equ hmac_ipad + sha256_block_size
hmac_inner_digest equ hmac_opad + sha256_block_size
hmac_prepared_inner_state equ hmac_inner_digest + sha256_digest_len
hmac_prepared_outer_state equ hmac_prepared_inner_state + (16 * 2)
tls_prf_seed equ hmac_prepared_outer_state + (16 * 2)
tls_prf_a equ tls_prf_seed + tls_prf_seed_max_len
tls_prf_chunk equ tls_prf_a + sha256_digest_len
seed_agent_id equ tls_prf_chunk + sha256_digest_len
seed_model equ seed_agent_id + agent_id_len
seed_key equ seed_model + seed_model_len
seed_endpoint equ seed_key + seed_key_len
seed_reasoning equ seed_endpoint + seed_endpoint_len
tls_server_random equ seed_reasoning + seed_reasoning_len
tls_master_secret equ tls_server_random + tls_random_len
tls_handshake_hash equ tls_master_secret + tls_master_secret_len
tls_verify_data equ tls_handshake_hash + sha256_digest_len
tls_pre_response_scratch_end equ tls_verify_data + tls_finished_verify_len
%if (tls_pre_response_scratch_end - tls_pre_response_scratch) != tls_pre_response_tail_len
%error "pre-response scratch size constant is stale"
%endif
%if tls_pre_response_scratch_end > (tls_rx_copy + tls_stream_buffer_len)
%error "pre-response scratch exceeds TLS receive buffer tail"
%endif
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
sha256_block equ high_sha256_block
sha256_w equ high_sha256_w
tls_client_write_key equ high_tls_client_write_key
tls_server_write_key equ high_tls_server_write_key
tls_client_write_iv equ high_tls_client_write_iv
tls_server_write_iv equ high_tls_server_write_iv
tls_client_record_seq equ high_tls_client_record_seq
tls_server_record_seq equ high_tls_server_record_seq
tls_client_nonce equ high_tls_client_nonce
tls_aead_aad equ high_tls_aead_aad
tls_finished_plain equ high_tls_finished_plain
tls_finished_cipher equ high_tls_finished_cipher
tls_finished_tag equ high_tls_finished_tag
tls_received_tag equ high_tls_received_tag
p256_lhs equ high_p256_lhs
p256_rhs equ high_p256_rhs
p256_tmp equ high_p256_tmp
p256_jac_x equ high_p256_jac_x
p256_jac_y equ high_p256_jac_y
p256_jac_z equ high_p256_jac_z
p256_s0 equ high_p256_s0
p256_s1 equ high_p256_s1
p256_s2 equ high_p256_s2
p256_s3 equ high_p256_s3
p256_s5 equ high_p256_s5
agent_ids equ p256_lhs
tls_premaster_secret equ p256_lhs
tls_key_block equ p256_lhs
chacha_state equ p256_lhs
chacha_work equ p256_tmp
chacha_block equ p256_jac_y
poly_r equ p256_s0
poly_s equ p256_s0 + poly1305_r_len
poly_acc equ p256_s1
poly_block equ p256_s2
poly_product equ p256_s3
poly_value equ p256_s5
tls_random equ high_tls_random
tls_client_ec_public equ high_tls_client_ec_public
tls_label_master_secret db 'master secret'
tls_label_master_secret_len equ $ - tls_label_master_secret
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
