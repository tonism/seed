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
low_runtime_state_start equ handoff_addr + handoff_size_bytes
sha256_state equ low_runtime_state_start
sha256_a equ sha256_state + 32
sha256_b equ sha256_a + 4
sha256_c equ sha256_b + 4
sha256_d equ sha256_c + 4
sha256_e equ sha256_d + 4
sha256_f equ sha256_e + 4
sha256_g equ sha256_f + 4
sha256_h equ sha256_g + 4
sha256_t1 equ sha256_h + 4
sha256_t2 equ sha256_t1 + 4
sha256_new_e equ sha256_t2 + 4
sha256_tmp equ sha256_new_e + 4
sha256_w_ptr equ sha256_tmp + 4
sha256_k_ptr equ sha256_w_ptr + 2
sha256_len_low equ sha256_k_ptr + 2
sha256_len_high equ sha256_len_low + 2
sha256_saved_len_low equ sha256_len_high + 2
sha256_saved_len_high equ sha256_saved_len_low + 2
sha256_bit_len0 equ sha256_saved_len_high + 2
sha256_bit_len1 equ sha256_bit_len0 + 2
sha256_bit_len2 equ sha256_bit_len1 + 2
sha256_bit_len3 equ sha256_bit_len2 + 2
sha256_digest_ptr equ sha256_bit_len3 + 2
hmac_key_ptr equ sha256_digest_ptr + 2
hmac_key_len equ hmac_key_ptr + 2
hmac_data1_ptr equ hmac_key_len + 2
hmac_data1_len equ hmac_data1_ptr + 2
hmac_data2_ptr equ hmac_data1_len + 2
hmac_data2_len equ hmac_data2_ptr + 2
hmac_data3_ptr equ hmac_data2_len + 2
hmac_data3_len equ hmac_data3_ptr + 2
hmac_output_ptr equ hmac_data3_len + 2
tls_prf_secret_ptr equ hmac_output_ptr + 2
tls_prf_secret_len equ tls_prf_secret_ptr + 2
tls_prf_seed_ptr equ tls_prf_secret_len + 2
tls_prf_seed_len equ tls_prf_seed_ptr + 2
tls_prf_output_ptr equ tls_prf_seed_len + 2
tls_prf_output_len equ tls_prf_output_ptr + 2
tls_prf_output_remaining equ tls_prf_output_len + 2
tls_prf_chunk_len equ tls_prf_output_remaining + 2
tls_prf_current_output_ptr equ tls_prf_chunk_len + 2
chacha_key_ptr equ tls_prf_current_output_ptr + 2
chacha_nonce_ptr equ chacha_key_ptr + 2
chacha_counter_low equ chacha_nonce_ptr + 2
chacha_counter_high equ chacha_counter_low + 2
poly_block_ptr equ chacha_counter_high + 2
poly_i equ poly_block_ptr + 2
poly_j equ poly_i + 1
tls_server_certificate_len_low equ poly_j + 1
tls_server_certificate_list_len_low equ tls_server_certificate_len_low + 2
tls_server_next_handshake_type equ tls_server_certificate_list_len_low + 2
tls_server_next_handshake_len_high equ tls_server_next_handshake_type + 1
tls_server_key_public_len equ tls_server_next_handshake_len_high + 1
tls_server_signature_hash equ tls_server_key_public_len + 1
tls_server_signature_alg equ tls_server_signature_hash + 1
tls_server_certificate_len_high equ tls_server_signature_alg + 1
tls_server_certificate_list_len_high equ tls_server_certificate_len_high + 1
tls_key_schedule_ready equ tls_server_certificate_list_len_high + 1
sha256_block_len equ tls_key_schedule_ready + 1
sha256_saved_block_len equ sha256_block_len + 1
sha256_schedule_count equ sha256_saved_block_len + 1
sha256_round_count equ sha256_schedule_count + 1
tls_next_handshake_body_ptr equ sha256_round_count + 1
low_runtime_state_end equ tls_next_handshake_body_ptr + 2
low_static_constants_start equ low_phase_state_end
tls_label_master_secret equ low_static_constants_start
tls_label_master_secret_len equ 13
tls_label_client_finished equ tls_label_master_secret + tls_label_master_secret_len
tls_label_client_finished_len equ 15
tls_label_server_finished equ tls_label_client_finished + tls_label_client_finished_len
tls_label_server_finished_len equ 15
tls_label_key_expansion equ tls_label_server_finished + tls_label_server_finished_len
tls_label_key_expansion_len equ 13
chacha_constants equ tls_label_key_expansion + tls_label_key_expansion_len
chacha_constants_len equ 16
poly1305_prime equ chacha_constants + chacha_constants_len
poly1305_prime_len equ 17
sha256_initial_state equ poly1305_prime + poly1305_prime_len
sha256_initial_state_len equ 32
low_static_constants_end equ sha256_initial_state + sha256_initial_state_len
low_static_constants_len equ low_static_constants_end - low_static_constants_start
%if low_file_scratch_end > low_scratch_end
%error "low packet scratch arena overflow"
%endif
%if low_phase_state_end > low_scratch_end
%error "low phase state arena overflow"
%endif
%if low_static_constants_end > low_scratch_end
%error "low static constants arena overflow"
%endif
%if low_runtime_state_end > low_scratch_start
%error "low runtime state overlaps phase load window"
%endif
%if (low_sha256_k + sha256_k_len) > handoff_addr
%error "low sha256 k table overlaps handoff block"
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
sha256_k equ low_sha256_k
