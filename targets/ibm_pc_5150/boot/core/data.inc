tls_app_data_ptr dw 0
tls_app_plain_ptr dw 0
; Prompt length preserved for the reconnect resend, captured in prepare_agent_endpoint_path
; before any receive (dpi_input_len_byte aliases the clobbered tls_rx_copy). MUST live in the
; resident nucleus, NOT the link window: net_phase reloads the link window (load_core_window)
; after capturing it, which would reset a link-window byte to its file value (0) and resend an
; empty prompt. The nucleus is loaded once at boot and never reloaded.
chat_resend_prompt_len db 0
; Build 9 (Phase 3): bytes used in the chat_context conversation window (resident, reconnect-safe,
; 0 at boot). The window itself is chat_context_start in the reclaimed pool (data below).
chat_context_used db 0
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
hmac_output_ptr equ hmac_data2_len + 2
tls_prf_seed_ptr equ hmac_output_ptr + 2
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
tls_server_certificate_len_high equ tls_server_next_handshake_len_high + 1
tls_server_certificate_list_len_high equ tls_server_certificate_len_high + 1
tls_key_schedule_ready equ tls_server_certificate_list_len_high + 1
sha256_block_len equ tls_key_schedule_ready + 1
sha256_saved_block_len equ sha256_block_len + 1
sha256_schedule_count equ sha256_saved_block_len + 1
sha256_round_count equ sha256_schedule_count + 1
tls_next_handshake_body_ptr equ sha256_round_count + 1
low_persistent_state_start equ tls_next_handshake_body_ptr + 2
ne_tx_start equ low_persistent_state_start
ne_rx_start equ ne_tx_start + 1
ne_rx_stop equ ne_rx_start + 1
ne_next_page equ ne_rx_stop + 1
ne_rx_header equ ne_next_page + 1
ne_rx_count equ ne_rx_header + ne_rx_header_len
ne_rx_sample_count equ ne_rx_count + 2
ne_rx_read_limit equ ne_rx_sample_count + 2
el1_tx_ptr equ ne_rx_read_limit + 2
ne_dma_addr equ el1_tx_ptr + 2
ne_dma_count equ ne_dma_addr + 2
dhcp_wait_count equ ne_dma_count + 2
arp_target_mac equ dhcp_wait_count + 2
tcp_target_ip equ arp_target_mac + 6
tcp_dest_port_word equ tcp_target_ip + 4
tcp_local_seq equ tcp_dest_port_word + 2
tcp_remote_ack equ tcp_local_seq + 4
tls_stream_skip_remaining equ tcp_remote_ack + 4
api_body_len equ tls_stream_skip_remaining + 2
tcp_source_port_word equ api_body_len + 2
dns_qname_len equ tcp_source_port_word + 2
api_response_pending_len equ dns_qname_len + 1
api_stream_done_match equ api_response_pending_len
api_stream_text_seen equ api_response_pending_len + 2
api_stream_prompt_len equ api_stream_text_seen + 1
api_stream_large_seen equ api_stream_prompt_len
low_runtime_state_end equ api_stream_prompt_len + 1

; After agent/user setup, the setup form scratch bytes are no longer live.
; Reuse them for the chat response scanner instead of growing the always-tight
; low runtime block.
api_stream_state equ menu_value_a
api_stream_delta_match equ menu_index
api_stream_event_match equ input_target
dpi_prompt_marker_row equ api_stream_event_match
api_stream_event_ready equ input_max
api_stream_seen equ input_len
api_stream_completed equ input_start_col
api_http_state equ form_left_col
api_http_header_match equ form_field_col
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
low_tail_state_start equ low_static_constants_end
tcp_rx_payload_ptr equ low_tail_state_start
tcp_rx_payload_len equ tcp_rx_payload_ptr + 2
tls_tx_len equ tcp_rx_payload_len + 2
tls_host_len equ tls_tx_len + 2
tls_buffered_payload_ptr equ tls_host_len + 2
tls_buffered_payload_len equ tls_buffered_payload_ptr + 2
tls_server_record_len equ tls_buffered_payload_len + 2
tls_server_handshake_len equ tls_server_record_len + 2
tls_server_certificate_record_len equ tls_server_handshake_len + 2
tls_server_certificate_total_len equ tls_server_certificate_record_len + 2
tls_server_next_record_len equ tls_server_certificate_total_len + 2
tls_server_next_handshake_len_low equ tls_server_next_record_len + 2
tls_server_next_total_len equ tls_server_next_handshake_len_low + 2
tls_current_payload_ptr equ tls_server_next_total_len + 2
tls_current_payload_len equ tls_current_payload_ptr + 2
low_tail_state_end equ tls_current_payload_len + 2
%if low_file_scratch_end > low_scratch_end
%error "low packet scratch arena overflow"
%endif
%if low_phase_state_end > low_scratch_end
%error "low phase state arena overflow"
%endif
%if low_static_constants_end > low_scratch_end
%error "low static constants arena overflow"
%endif
%if low_tail_state_end > low_scratch_end
%error "low tail state arena overflow"
%endif
%if low_runtime_state_end > low_scratch_start
%error "low runtime state overlaps phase load window"
%endif
%if (low_sha256_k + sha256_k_len) > handoff_addr
%error "low sha256 k table overlaps handoff block"
%endif
low_sha256_block equ fs_sector_buffer + 128
low_sha256_w equ low_sha256_block + sha256_block_size
%if (low_sha256_w + sha256_k_len) > (fs_sector_buffer + 512)
%error "low SHA-256 scratch exceeds fs sector buffer tail"
%endif
%if (tls_client_key_exchange_total_len > 128) || ((tls_change_cipher_spec_total_len + tls_finished_total_len) > 128)
%error "TLS transmit records collide with low SHA-256 scratch"
%endif
low_crypto_work equ ne_tx_frame
low_sha256_saved_state equ low_crypto_work
low_sha256_saved_block equ low_sha256_saved_state + (16 * 2)
low_hmac_ipad equ low_sha256_saved_block + sha256_block_size
low_hmac_opad equ low_hmac_ipad + sha256_block_size
low_hmac_inner_digest equ low_hmac_opad + sha256_block_size
low_tls_prf_seed equ low_hmac_inner_digest + sha256_digest_len
low_tls_prf_a equ low_tls_prf_seed + tls_prf_seed_max_len
low_tls_prf_chunk equ low_tls_prf_a + sha256_digest_len
%if (low_tls_prf_chunk + sha256_digest_len) > ne_prom
%error "low crypto work collides with NE PROM scratch"
%endif
tls_rx_copy equ critical_scratch_start
tls_client_hello_buffer equ tls_rx_copy
dns_qname equ tls_rx_copy + 512

; The second receive-buffer payload is only needed after the request has been
; sent. Until then it can hold setup/request scratch without reducing the
; two-payload response receive window.
tls_pre_response_scratch equ tls_rx_copy + tls_payload_buffer_len
%if (dns_qname + dns_qname_max_len) > tls_pre_response_scratch
%error "dns_qname scratch overlaps pre-response scratch"
%endif
api_request_plain equ tls_pre_response_scratch
api_response_text_buf equ fs_sector_buffer
; Build the encrypted application record over the plaintext request arena. This
; survives server-Finished verification, unlike fs_sector_buffer, and the
; current request cap keeps each request in one TLS record.
tls_app_record_buffer equ api_request_plain
hmac_prepared_inner_state equ api_request_plain + tls_app_record_buffer_len
hmac_prepared_outer_state equ hmac_prepared_inner_state + (16 * 2)
seed_agent_id equ hmac_prepared_outer_state + (16 * 2)
seed_model equ seed_agent_id + agent_id_len
seed_key equ seed_model + seed_model_len
seed_endpoint equ seed_key + seed_key_len
seed_reasoning equ seed_endpoint + seed_endpoint_len
; After agent_request_phase has built the HTTP request, saved config values are
; no longer needed on the OpenAI proof path. Reuse that arena for later TLS
; state instead of extending the critical scratch tail.
tls_server_random equ seed_agent_id
tls_master_secret equ tls_server_random + tls_random_len
tls_handshake_hash equ tls_master_secret + tls_master_secret_len
critical_chacha_state equ low_crypto_work
critical_chacha_work equ critical_chacha_state + chacha_block_len
critical_chacha_block equ critical_chacha_work + chacha_block_len
critical_poly_r equ critical_chacha_block + chacha_block_len
critical_poly_s equ critical_poly_r + poly1305_r_len
critical_poly_acc equ critical_chacha_state
critical_poly_block equ critical_poly_acc + poly1305_acc_len
critical_poly_product equ critical_poly_block + 16
critical_poly_value equ critical_poly_product + poly1305_product_len
%if (critical_poly_value + poly1305_value_len) > critical_poly_r
%error "critical Poly1305 overlay collides with persistent Poly1305 key"
%endif
%if (critical_poly_s + poly1305_s_len) > ne_prom
%error "low AEAD work collides with NE PROM scratch"
%endif
tls_pre_response_scratch_end equ tls_handshake_hash + sha256_digest_len
%if (tls_pre_response_scratch_end - tls_pre_response_scratch) != tls_pre_response_tail_len
%error "pre-response scratch size constant is stale"
%endif
%if tls_pre_response_scratch_end > (tls_rx_copy + tls_stream_buffer_len)
%error "pre-response scratch exceeds TLS receive buffer tail"
%endif
sha256_block equ low_sha256_block
sha256_w equ low_sha256_w
sha256_saved_state equ low_sha256_saved_state
sha256_saved_block equ low_sha256_saved_block
hmac_ipad equ low_hmac_ipad
hmac_opad equ low_hmac_opad
hmac_inner_digest equ low_hmac_inner_digest
tls_prf_seed equ low_tls_prf_seed
tls_prf_a equ low_tls_prf_a
tls_prf_chunk equ low_tls_prf_chunk
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
tls_verify_data equ high_tls_finished_cipher
tls_finished_tag equ high_tls_finished_tag
tls_received_tag equ high_tls_received_tag
agent_ids equ high_crypto_work
tls_premaster_secret equ high_crypto_work
tls_key_block equ high_crypto_work
chacha_state equ critical_chacha_state
chacha_work equ critical_chacha_work
chacha_block equ critical_chacha_block
poly_r equ critical_poly_r
poly_s equ critical_poly_s
poly_acc equ critical_poly_acc
poly_block equ critical_poly_block
poly_product equ critical_poly_product
poly_value equ critical_poly_value
tls_random equ tls_handshake_hash
sha256_k equ low_sha256_k

; Build 8 keeps cross-phase agent/TLS request state outside the resident
; nucleus so adding the chat loop does not push the K window upward.
tls_app_len equ critical_scratch_end
tls_app_record_len equ tls_app_len + 2
tls_app_total_len equ tls_app_record_len + 2
tls_app_chunk_len equ tls_app_total_len + 2
tls_app_content_type equ tls_app_chunk_len + 2
tls_transcript_certificate_remaining equ tls_app_content_type + 1
tls_large_chacha_offset equ tls_transcript_certificate_remaining
dns_tx_len equ tls_transcript_certificate_remaining + 2
; The first TLS handshake and ready-loop state reuse the AGENTS/USER config
; arena. Preserve the chat-loop values that every request still needs.
; Keep DNS/TCP setup state intact through run_tcp_connect; the hot chat loop
; reuses the last 16K-safe bytes below the BASIC stack guard for values needed
; after TLS scratch takes over.
chat_model_cache equ dns_tx_len + 2
chat_prompt_len_cache equ chat_model_cache + seed_model_len - 1
chat_key_cache equ chat_model_cache + seed_model_len
chat_cache_end equ chat_key_cache + seed_key_len
%if chat_model_cache < low_scratch_end
%error "chat config cache overlaps phase load window"
%endif
%if chat_model_cache < tls_pre_response_scratch_end
%error "chat config cache overlaps TLS/request scratch"
%endif
%if chat_cache_end > (basic_sidecar_stack_top_16k - basic_sidecar_stack_guard_len_16k)
%error "chat config cache overlaps 16K BASIC stack guard"
%endif

; Build 9 reconnect-safe context pool, reclaimed from the trimmed 16K stack reserve.
; Above the pinned chat config caches, below the (RAM-relative) stack. Holds the rolling
; conversation summary; everything from chat_arena_start up to (ram_top - stack reserve) is
; the user/agent arena - Seed never writes past chat_context_end. Borders are compile-time
; defaults in Build 9; publishing/moving them is Build 10. ram_top is already in the handoff
; (offset 0x2c), so the ledger carries it and the agent derives the arena ceiling itself.
chat_context_start equ chat_cache_end
chat_context_len equ 128
chat_context_end equ chat_context_start + chat_context_len
chat_arena_start equ chat_context_end
chat_arena_floor_min equ 64
%if (chat_arena_start + chat_arena_floor_min) > (basic_sidecar_stack_top_16k - basic_sidecar_stack_guard_len_16k)
%error "context pool leaves no minimum arena floor below the 16K stack reserve"
%endif

dpi_input_buf equ tls_rx_copy
dpi_input_len_byte equ dpi_input_buf + dpi_input_max_len
%if (dpi_input_len_byte + 1) > tls_pre_response_scratch
%error "DPI input buffer exceeds first TLS receive payload"
%endif
