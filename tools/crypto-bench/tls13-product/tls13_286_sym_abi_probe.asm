; Build-time symbol probe for the exact K14 symmetric image reused by the
; TLS 1.3 286 route.  The bytes through sym_overlay_end must be byte-identical
; to the validated product-pack phase.  Only the trailer below is probe-only.

%define TLS13_POC_K14
%ifdef TLS13_286_PRODUCT_SYM
%define TLS13_POC_286
%endif
%include "tools/crypto-bench/tls13-poc/tls13_sym_overlay.asm"

tls13_286_sym_probe:
    db 'S286SAB2'
    dw 2
    dw (tls13_286_sym_probe_end - tls13_286_sym_probe_values) / 2
tls13_286_sym_probe_values:
    dw sym_overlay_header
    dw sym_overlay_end
    dw sym_entry_table
    dw sym_entry_count

    dw sym_init
    dw sym_transcript_init
    dw sym_transcript_update
    dw sym_critical_schedule
    dw sym_server_hs_open_begin
    dw sym_server_app_open_begin
    dw sym_open_chunk
    dw sym_open_finish
    dw sym_verify_server_finished
    dw sym_build_client_finished
    dw sym_derive_application
    dw sym_build_head
    dw sym_parse_nst
    dw sym_resumption_binder
    dw sym_resumption_handshake
    dw sym_transcript_import
    dw sym_derive_client_application
    dw sym_derive_server_application
    dw sym_authenticate_resumed_flight

    dw sha256_init
    dw sha256_update
    dw sha256_finish
    dw sha256_state
    dw sha256_block
    dw sha256_len_low
    dw sha256_len_high
    dw sha256_block_len

    dw sym_hello_server_x
    dw sym_hello_digest
    dw sym_hello_context
    dw sym_input_shared_secret
    dw sym_input_hello_hash
    dw sym_received_server_finished
    dw sym_client_finished_message
    dw sym_io_base
    dw sym_io_end

    dw sym_client_hs_key
    dw sym_client_hs_iv
    dw sym_server_hs_key
    dw sym_server_hs_iv
    dw sym_client_hs_seq
    dw sym_server_hs_seq

    dw sym_client_app_key
    dw sym_client_app_iv
    dw sym_server_app_key
    dw sym_server_app_iv
    dw sym_client_app_seq
    dw sym_server_app_seq
    dw sym_ticket_psk
    dw sym_ticket_identity
    dw sym_ticket_nonce
    dw sym_ticket_lifetime_hi
    dw sym_ticket_lifetime_lo
    dw sym_ticket_age_add
    dw sym_ticket_nonce_len
    dw sym_ticket_identity_len
    dw sym_ticket_present
    dw sym_input_binder_hash
    dw sym_resumption_binder_value
    dw sym_resumption_master_secret
    dw sym_client_finished_state
    dw sym_handshake_derived
    dw sym_high_state_end
tls13_286_sym_probe_end:
