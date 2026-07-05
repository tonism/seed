tls_app_data_ptr dw 0
tls_app_plain_ptr dw 0
; Build 12 NIC HAL vtable (the dispatch-vector for the active NIC driver). Boot-populated once by
; populate_nic_vtable (hardware_setup, after family detection); the resident hot path then calls the
; active family's ops INDIRECTLY through these slots instead of `cmp [nic_family]/je <override>`,
; so a new NIC family is a new driver + a vtable fill, with no new branch woven into the hot path.
; Lives resident (link==run) so the stored values are the resident routines' final addresses, and
; the table survives every phase load AND a mid-session reconnect (the nucleus is never reloaded) --
; the reconnect-survivor property for free. Net nucleus-negative: removing the per-family branches
; frees more than these 5 words cost. Slots: enter/restore (wd8003 DP8390 windowing), transmit +
; receive (3c501/el1 fully overrides, NE-family shares the ring path), rx_fallback (3c501 second-
; frame quirk). See core/nic.inc, net_tx.inc, net_rx.inc, transport.inc and the population routine.
nic_vtable:
nic_vt_enter       dw 0
nic_vt_restore     dw 0
nic_vt_transmit    dw 0
nic_vt_receive     dw 0
nic_vt_rx_fallback dw 0
; Build 12 (32K floppy-free chat loop): the preload-cache lookup table + count. On a 32K direct boot,
; preload_loop_cache copies each chat-loop working-set phase into the high cache (loop_cache_start..)
; and records {load-request key (sectors<<8|sector-offset), cache address} here; load_core_sectors_at
; scans [0..loop_cache_count) and, on a key match, rep-movsw's from RAM instead of reading the floppy.
; count = 0 on 16K (the preload is skipped, the cache region doesn't exist) AND during the preload
; itself (so load_core_sectors_at floppy-fills the cache), then it is set to the entry count. Resident
; (consulted on every phase load). loop_cache_max_entries = the working set (Y/R/K/X/T/M = 6).
loop_cache_max_entries equ 6
loop_cache_count dw 0
loop_cache_table times (loop_cache_max_entries * 2) dw 0
; Build 11 never-blank reorg: the resident nucleus was full (2048/2048). Seven reconnect-safe vars
; that used to live here as nucleus db/dw -- chat_resend_prompt_len, chat_context_used, compact_next,
; compacting_msg, chat_compact_threshold, chat_context_len_var, scroll_br -- were relocated OUT of the
; nucleus into the reconnect_state_* block defined near chat_cache_end (below). Each is written before
; it is read (per turn, or once at boot by hardware_setup), so it needs no nucleus-resident initialiser;
; the block sits above the TLS/critical scratch, so it survives a reconnect handshake exactly like the
; nucleus copies did. This freed the bytes the 3x-retry reconnect loop + reconnect_retries counter need.
; (tls_app_data_ptr/tls_app_plain_ptr stay resident: they are hot crypto-receive/send pointers.)
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
video_seg equ screen_cols + 1     ; CGA 0xb800 / MDA 0xb000 (word); set once in hardware_setup, read by the direct-screen-write phases
seed_col equ video_seg + 2
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
; Build 10 (agentic loop): live in low_phase_state (persists across phase loads, no resident
; nucleus cost). Not boot-cleared, so the tool phase clears agent_loop_pending at its entry
; each run and agent_loop_count self-heals (reset to 0 on the first no-tool turn, e.g. the
; greeting). pending=1 + budget left -> dpi auto-submits the structured tool-output turn.
agent_loop_pending equ load_marker_attr + 1
agent_loop_count equ agent_loop_pending + 1
; Build 12 env save/load: native save_env requested. Lives in low_phase_state (persists across phase
; loads, NO resident nucleus cost). The tool phase clears it at entry and sets it on save_env;
; dpi runs the save phase when set (the tool phase can't load the save over itself). Cleared at the
; tool phase entry each run, so boot garbage can't trigger a spurious save before dpi reads it.
save_pending equ agent_loop_count + 1
low_phase_state_end equ save_pending + 1

; Build 12 env save/load: the save phases' shared scratch (save_prep computes the geometry/header/
; row-length table; save_write consumes them). Phase-INLINE vars assemble at the CORE.SYS image
; address (~0x83xx, above the 32K RAM ceiling) and are accessed absolutely -> writes lost, reads
; 0xFFFF. So this lives at fixed low addresses, overlaying the boot-only file/config/network scratch
; (fs_file_* onward), all dead between turns when $s runs. (The save still uses fs_lba/fs_root_left
; -- which sit BELOW fs_file_cluster -- for its root-dir scan, and screen_cols, which sits ABOVE this
; block; neither overlaps.) ~49 bytes; must end before cursor_row.
save_scratch_base   equ fs_file_cluster
save_region_stored  equ save_scratch_base        ; region bytes in the file (trailing zeros trimmed)
save_screen_stored  equ save_scratch_base + 2     ; encoded screen bytes (rows + 2*sum row_len)
save_region_len     equ save_scratch_base + 4     ; FULL region extent (for the header + restore clear)
save_file_size      equ save_scratch_base + 6     ; env_hdr_len + region_stored + screen_stored
save_payload_ck     equ save_scratch_base + 8     ; payload checksum (computed in save_prep)
save_needed         equ save_scratch_base + 10    ; data sectors = ceil(file_size / 512)
save_run_start      equ save_scratch_base + 12    ; first cluster of the contiguous run
save_buf_idx        equ save_scratch_base + 14    ; fill index within fs_sector_buffer (sequential emit)
save_sector_index   equ save_scratch_base + 16    ; data sectors emitted so far
save_dir_lba        equ save_scratch_base + 18
save_dir_off        equ save_scratch_base + 20
save_old_cluster    equ save_scratch_base + 22
save_rowlen_table   equ save_scratch_base + 24    ; one byte per screen row (<= 25)
save_scratch_end    equ save_rowlen_table + 25
%if save_scratch_end > cursor_row
%error "save scratch overruns into the live cursor/screen vars"
%endif
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
tls_key_schedule_quiet_reconnect equ 2
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
; Build 11 streaming-Poly1305 receive accumulator: the receive MAC's running state (poly_acc +
; partial poly_block, 33 contiguous bytes) lives here between per-chunk MAC steps so it survives the
; interleaved decrypt AND a mid-receive keep-alive SEND - both of which clobber the shared poly_acc.
; Reuses tls_master_secret (48 B), which is handshake-only: derived during the handshake and idle
; during the chat receive; the send/ping uses the derived keys + poly_acc, never the master secret.
poly_rx_save equ tls_master_secret
; The one-time key (poly_r+poly_s, 32 B) ALSO lives in low_crypto_work, which the inter-chunk NIC
; receive reuses - so stash the (constant) otk here too and restore it before each MAC step. Spans
; the tail of tls_master_secret into tls_handshake_hash (also handshake-only); 33+32 = 65 B of the
; 80 B master_secret+handshake_hash window. The decrypt re-derives its keystream each block so it
; never needed the otk to persist - which is why the old streamed path masked this.
poly_rx_otk equ poly_rx_save + poly1305_acc_len + 16
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
; Build 11 streaming Poly1305 (FIFO receive) state. Reuses scratch that is provably dead during the
; streamed application-data receive: tls_app_chunk_len + tls_app_total_len are touched only by the
; old all-at-once decrypt (tls_xor_app_data) / the whole-record MAC and the
; standard whole-record (now alert-only) path - none of which run inside
; tls_receive_large_application_record. They hold the running ciphertext length and the 0..15
; partial-block fill carried across chunk absorptions so the tag can be verified at record-end.
tls_poly_app_cipher_len equ tls_app_chunk_len
tls_poly_app_fill equ tls_app_total_len
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
; conversation summary; hardware_setup splits the pool (chat_context_start up to ram_top - stack
; reserve) 50/50 into the conversation window and the user/agent arena. The arena base is dynamic
; -- chat_context_start + the live window length -- published via the ledger a@ (the static
; chat_arena_start / chat_context_len below are only the compile-time floor for the %error guard).
; ram_top is already in the handoff
; (offset 0x2c), so the ledger carries it and the agent derives the arena ceiling itself.
; Build 9: keep-alive GET template at a fixed slot BEFORE the context pool, so the conversation
; window and the user/agent arena form one contiguous block - trivially scalable with RAM and
; split-adjustable, with no keepalive wedge in the middle. Staged once at boot by hardware_setup
; (the renderer was too full at 511/512 B to host it; the floppy was rejected - the keepalive
; fires mid-render, and a disk read there risks the long-render receive path).
; Build 11 never-blank reorg: reconnect-safe state relocated from the (full) resident nucleus.
; Above the TLS/critical scratch and below the keep-alive template, so it survives a reconnect
; handshake -- the whole reason the nucleus copies existed. chat_resend_prompt_len + reconnect_retries
; are ADJACENT so net_phase inits both in ONE word write (al = prompt len, ah = 3 retries). All are
; written-before-read each turn EXCEPT chat_context_used, which the cold greeting reads before any
; write -> hardware_setup boot-zeroes it (beside agent_loop_pending, same pattern/reason).
; chat_compact_threshold / chat_context_len_var / scroll_br are written once by hardware_setup at boot
; before any read (formerly carried compile-time defaults that hardware_setup always overwrote).
reconnect_state_start equ chat_cache_end
chat_resend_prompt_len equ reconnect_state_start
reconnect_retries equ chat_resend_prompt_len + 1
compact_next equ reconnect_retries + 1    ; legacy name; old '$' text compaction trigger is gone
compacting_msg equ compact_next + 1
; Build 11 ESC-to-interrupt. esc_stop: the int 9 hook sets it on a plain ESC during a render (graceful
; stop) -- homed right after compacting_msg so emit_char suppresses on BOTH via one word cmp (0 extra
; bytes in the maxed render phase). esc_panic: set instead on Ctrl+ESC (stage 2 hard escape) -- the hook
; longjmps to chat_loop and tool_phase draws "> panic stopped" + skips its scan. Both boot-zeroed together
; (one word write in hardware_setup): tool_phase reads them at the greeting, before agent_request resets.
esc_stop equ compacting_msg + 1
esc_panic equ esc_stop + 1
; Build 11 ESC gate: 0 through the whole boot network bring-up; dpi_phase sets it to 1 the moment the
; DPI goes live. The int 9 hook ignores ESC/Ctrl+ESC while it is 0, so a keypress during boot can't
; longjmp into a half-built chat loop (no splash, dead boot). Boot-zeroed (1 byte, after esc_panic).
dpi_reached equ esc_panic + 1
chat_context_used equ dpi_reached + 1
chat_compact_threshold equ chat_context_used + 2
chat_context_len_var equ chat_compact_threshold + 2
scroll_br equ chat_context_len_var + 2
; Build 11 slice 3a: saved tcp_local_seq for the ClientHello retransmit (handshake loss recovery).
; Homed here -- low_runtime_state is full to the phase load window, and this block has headroom. It
; is handshake-scoped (used + rewound within one tls_probe), so it does not need this block's
; survive-the-handshake property; it just needs a 4-byte home idle during the handshake.
tls_retransmit_seq equ scroll_br + 2
; Build 11 #4 real compaction: the live store cap for the conversation window. agent_request sets it
; each ready request to chat_context_len_var (normal turn) or HALF that (a compaction pass), so
; emit_char's single store path enforces the 50% summary ceiling with no per-char branch. Written-
; before-read each turn (set in .build_ready_openai_request before any receive/render).
chat_effective_cap equ tls_retransmit_seq + 4
; Build 11 #4 real compaction: the two static system prompts (identity, compaction contract) are
; STREAMED off the floppy into the request mid-chat instead of living in the stream phase image. The
; root-dir find runs once at boot (agents_cfg) and caches each file's first cluster + byte size here;
; the stream phase reads cluster, cluster+1, ... for ceil(size/512) sectors via the resident
; read_abs_sector (the builder lays files contiguously + NUL-pads the tail). size feeds the HTTP
; Content-Length (the bytes stream RAW + control->space, so sent length == file size). Homed in this
; block (only 3 B were free in low scratch) because it survives the session like the rest: boot-written
; once, read every request, untouched by the handshake (which uses the scratch BELOW this block). A
; missing file caches size 0 -> the streamer emits nothing (degraded, non-fatal).
prompt_id_cluster equ chat_effective_cap + 2
prompt_id_size equ prompt_id_cluster + 2
prompt_compact_cluster equ prompt_id_size + 2
prompt_compact_size equ prompt_compact_cluster + 2
; Build 12 native tool calling: the tools JSON schema asset (prompts/tools.json, <=1 sector), same
; boot-cached cluster+size scheme as identity/compact. Streamed RAW as the "tools" array value into
; ready requests. On 32K+ it is ALSO preloaded into the resident tools_cache (floppy-free loop); on
; 16K it streams from the floppy per ready turn.
prompt_tools_cluster equ prompt_compact_size + 2
prompt_tools_size equ prompt_tools_cluster + 2
; Build 11 #4 note-as-memory: the conversation window (chat_context) is split into a NOTE prefix
; [0..note_len) and the live DIALOGUE [note_len..chat_context_used). The note is the compacted memory
; and rides in the request "instructions" (system) slot; the dialogue + the user prompt ride in
; "input". Set right after a compaction pass (agent_request) to the captured summary's length; 0 until
; the first compaction. This is what makes the post-compaction turn ANSWER the user's question instead
; of continuing the note (the note reads as system memory, not the latest conversation turn).
note_len equ prompt_tools_size + 2
; Build 12 auto-recertify: re-adopt a chain-verified leaf across the module reload. The reload (each
; connect) reverts the module's pin to the baked one, so net_phase re-installs the verified leaf
; before tls_probe. recert_flag=1 = the off-race chain-verify accepted the captured leaf this
; prepare_agent_endpoint_path; recert_mod_ptr = its modulus (inside the capture buffer). Boot/entry
; zeroed (set at the prepare_agent_endpoint_path entry). (TEMPORARY-arena caveat: the modulus must
; still be in the capture buffer at re-adopt time -- true for the cold-boot recertify; the real home
; makes it robust across turns -- tracked follow-up.)
recert_flag equ note_len + 2
recert_mod_ptr equ recert_flag + 1
; Build 12 Stage C (C1b) far-log flush model: the far context log (far_log_seg) is the CANONICAL
; conversation -- it grows past 64 KB and streams in full every turn, while the seg-0 window keeps
; only the recent tail (renderer/scanner). far_flushed_len = bytes already FROZEN into the far log by
; prior flushes (DWORD: the log exceeds 64 KB); far_flushed_esc = their JSON-escaped length (DWORD,
; for the 32-bit Content-Length). The current seg-0 window is mirrored just above the frozen region at
; offset far_flushed_len (agent_request entry); when it reaches the threshold the flush advances
; far_flushed_len/esc past it + resets the window. Both ACCUMULATE across turns (like chat_context_used,
; read-before-write on the first turn -> hardware_setup boot-zeroes them); reconnect-safe so a resend
; re-streams the same far log. api_body_len_hi = the high word of the ready request's Content-Length
; (the low word reuses api_body_len); recomputed per request, so it rides here only for a free home.
far_flushed_len equ recert_mod_ptr + 2
far_flushed_esc equ far_flushed_len + 4
api_body_len_hi equ far_flushed_esc + 4
; Build 12 Stage C (C1b): the far context log needs real RAM at flat 0x10000, which only exists when
; conventional memory exceeds 64 KB. far_log_seg_var = the log's segment when active (far_log_seg), else
; 0 -- and 0 doubles as the "inactive" flag. On a <=64 KB machine (the 16 KB matrix / RAM floor) the far
; paths fall back to the seg-0 window + Build-11 model-summarize compaction (byte-for-byte Build 11);
; only a >64 KB machine streams the canonical far log. Set once by hardware_setup, read every request.
far_log_seg_var equ api_body_len_hi + 2
; Build 12 Stage C (C1b): agent_request precomputes the "input" dialogue range (it knows far_flushed_len /
; note_len / compacting_msg / far_log_seg_var) and stashes it here for the maxed agent_api_stream phase to
; stream verbatim -- the segment is far_log_seg_var, the start offset is dialogue_off, the byte count is the
; 32-bit dialogue_cnt. Written each ready request before the handshake, read after it -> reconnect-safe home.
dialogue_off equ far_log_seg_var + 2
dialogue_cnt equ dialogue_off + 2
; Build 12 Stage C (C2/C3): the far conventional region [0x10000 .. conv_top) is SPLIT into a far-log
; (context) half + a far-arena (agent workspace) half, so the ledger far@ advert no longer overlaps the
; log. Boot-computed (hardware_setup): far_window_cap = min(region/2, 1 MB) is the far log's byte ceiling
; (C2 50/50 + C3 1 MB cap); far_arena_base = 0x10000 + far_window_cap and far_arena_top = conv_top bound the
; arena the ledger advertises (C3 spill-to-arena is automatic: arena = region - window_cap). All DWORDs
; (the region exceeds 64 KB). Inactive (<=64 KB): cap 0, base==top==0x10000 (empty far range).
far_window_cap equ dialogue_cnt + 4
far_arena_base equ far_window_cap + 4
far_arena_top equ far_arena_base + 4
; Build 12 milestone 2 (EMS): ems_page_count = number of 16 KB EMS logical pages the board backend
; probed at boot (0 = no board -> EMS inactive; the gate, so a no-EMS machine is byte-for-byte
; milestone 1). The frame segment + I/O base + flat base are compile-time constants (layout.inc); the
; flat EMS range is [ems_flat_base_hi:0000 .. + ems_page_count*ems_page_size). Boot-set, read-only after.
ems_page_count equ far_arena_top + 4
; Build 12 milestone 2 (M2b/M2e): the FLAT base of the context (far) log. M1 kept it at 0x10000
; (conventional); with the arena-first inversion the arena takes all conventional and the context moves
; to the top of EMS on an EMS machine -- so the base is now a 32-bit flat address (dword), reached via the
; same per-address dispatch as $r/$w (< 0x100000 direct seg:off; >= 0x100000 EMS-windowed). On a no-EMS
; machine it stays 0x00010000 (byte-for-byte the M1 conventional path). far_flushed_len is its offset.
far_ctx_base equ ems_page_count + 2
; Build 12 M2e: boot-precomputed decomposition of far_ctx_base into an EMS page number + frame offset, so
; the maxed agent_api_stream phase doesn't do the >>14 address math per request (it is tight on sectors).
; Only meaningful on an EMS machine; the context read starts at far_ctx_base (dialogue_off is 0 on >64 KB).
ems_ctx_page equ far_ctx_base + 4
ems_ctx_off equ ems_ctx_page + 2
; Build 12 renderer type-change spacing: the message TYPE of the last thing drawn. Each renderer emits ONE
; blank line only when the type changes (user <-> agent <-> system), none within a run of one type. Homed in
; the reconnect-safe block so it SURVIVES the mid-turn reconnect handshake (a "> reconnect" sets it =system
; before the ~14.5s crypto, and the reply reads it =system after -> the system->agent blank is automatic).
; Not boot-cleared: a wrong blank on the very first render is cosmetic and self-heals after turn 1.
render_last_type equ ems_ctx_off + 2
render_type_user equ 1                     ; user prompt echo (dpi)
render_type_agent equ 2                    ; model reply (agent_response)
render_type_system equ 3                   ; tool results + status lines (tool_call / agent_endpoint / api_stream)
; Build 12 native tool calling: transient captured function_call state. State 1 means the SSE scanner
; saw a function_call and copied raw bytes to fc_capture_buf; state 2 means tool_call executed it and
; the next request sends function_call_output against previous_response_id. The string buffers are JSON-ready:
; call_id/name are raw identifiers, arguments is still the escaped Responses API argument string, and
; output contains only Seed-generated JSON-safe ASCII. Args live in the 0x0d00 capture handoff and are
; dead after tool_call parses them; output must live in reconnect-safe RAM because the 0x0900 request/
; stream phases would otherwise overwrite it before function_call_output is serialized.
tool_fc_state equ render_last_type + 1
fc_match_state equ tool_fc_state + 1
fc_capture_len equ fc_match_state + 1
fc_call_id_len equ fc_capture_len + 2
fc_name_len equ fc_call_id_len + 1
fc_args_len equ fc_name_len + 1
fc_output_len equ fc_args_len + 2
fc_suffix_len equ fc_output_len + 1           ; word: function_call + output suffix byte count
fc_call_id equ fc_suffix_len + 2              ; <=47 chars + NUL
fc_name equ fc_call_id + 48                   ; <=15 chars + NUL
fc_args_buf equ fc_capture_buf                ; raw escaped "arguments" string, parsed from capture
fc_args_max equ 384
fc_output_buf equ fc_name + 16
fc_output_max equ 128
reconnect_state_end equ fc_output_buf + fc_output_max
ka_template_persistent equ reconnect_state_end
; Build 11 ESC: the int 9 keyboard hook handler is staged to this pool slot at boot (position-independent
; code; runs from here so it survives the phase-overlay churn). esc_int9_old saves the BIOS int 9 vector
; the handler chains every key to. Both sit between the keep-alive template and the conversation window.
esc_int9_handler equ ka_template_persistent + ka_request_len
esc_int9_old equ esc_int9_handler + esc_int9_handler_len
prev_response_id equ esc_int9_old + 4
prev_response_id_max equ 56
chat_context_start equ prev_response_id + prev_response_id_max
chat_context_len equ 72
chat_context_end equ chat_context_start + chat_context_len
chat_arena_start equ chat_context_end
; Build 12 auto-recertify: the captured rotated leaf (286 secure path only) lands in the handshake-
; transient TAIL of the 32K loop cache -- just above the P-256 module's budget end
; (p256_module_load + p256_module_max_len) up to loop_cache_end. This is the MID-CHAT-SAFE home:
;  - every 286 connect's tls_client_hello sets loop_cache_count=0, so the chat loop demand-loads its
;    phases + prompt streams from floppy afterward; the cache content here (including
;    prompt_id_cache/prompt_compact_cache, which sit in this same tail) is therefore already invalid
;    when the capture overwrites it -- harmless;
;  - the LIVE CONVERSATION arena (chat_arena_start) is far below and is never touched;
;  - the loaded module (<= 24 sectors) ends at/below leaf_capture_buf, so it doesn't overlap either.
; A leaf larger than leaf_capture_max aborts the capture -> recertify fails closed. The resident caller
; passes this buffer to capture_leaf_reset (the module can't see the address). (Was chat_arena_start --
; a TEMPORARY validation home; this tail relocation is the real, mid-chat-safe home.)
leaf_capture_buf equ p256_module_load + p256_module_max_len
%if leaf_capture_buf + leaf_capture_max > loop_cache_end
%error "leaf-capture slot overflows the loop cache / runtime stack guard"
%endif
chat_arena_floor_min equ 64
%if (chat_arena_start + chat_arena_floor_min) > (basic_sidecar_stack_top_16k - basic_sidecar_stack_guard_len_16k)
%error "context pool leaves no minimum arena floor below the 16K stack reserve"
%endif

dpi_input_buf equ tls_rx_copy
dpi_input_len_byte equ dpi_input_buf + dpi_input_max_len
%if (dpi_input_len_byte + 1) > tls_pre_response_scratch
%error "DPI input buffer exceeds first TLS receive payload"
%endif
