; Fixed-origin TLS 1.3 286 controller/module ABI.
;
; This file defines the product boundary only.  It does not enable dispatch or
; load a module by itself.  Every consumer remains 8086-assemblable; the core
; selects this path only after the existing FLAGS probe reports 286+ and the
; BDA conventional-memory word proves at least 512 KiB.

tls13_286_abi_version              equ 2
tls13_286_bda_conventional_kb      equ 0x0413
tls13_286_min_conventional_kb      equ 512

; Never gate this tier on handoff_ram_top.  That field describes the low
; direct-boot/BASIC contract and intentionally remains 0x8000 on larger direct
; boots.  At runtime:
;
;   conv_top       = dword([0000:0413]) * 1024
;   crypto_base    = conv_top - tls13_286_high_reserve_bytes
;   loop_shadow    = crypto_base - tls13_286_loop_shadow_reserve_bytes
;   usable_conv_top= loop_shadow
;
; usable_conv_top, not conv_top, is passed to the existing far arena/context
; layout.  This makes both reservations relative to the real conventional top
; (and below any EBDA already reflected by the BDA) on 512..640 KiB machines.
; A full TLS 1.3 ciphertext may contain 2^14+256 bytes including the AEAD tag.
; Reserve one complete 64 KiB top segment so the protected plaintext remains
; quarantined until tag verification without borrowing from arena/context RAM.
tls13_286_high_reserve_bytes       equ 64 * 1024
; Preserve the complete 0x4000..0x79ff chat cache outside both the low crypto
; overlay and the advertised arena. A reconnect can then restore Y/R/K/X/T,
; IDENTITY, TOOLS, and their lookup table from RAM before any application send
; instead of racing a floppy read against the provider response.
tls13_286_loop_shadow_data_off      equ 16
tls13_286_loop_shadow_data_bytes    equ 29 * 512
tls13_286_loop_cache_low             equ 0x4000
tls13_286_loop_cache_entries         equ 5
tls13_286_loop_shadow_reserve_bytes equ \
    tls13_286_loop_shadow_data_off + tls13_286_loop_shadow_data_bytes
tls13_286_loop_shadow_seg_delta     equ \
    tls13_286_loop_shadow_reserve_bytes / 16
tls13_286_conventional_reserve_bytes equ \
    tls13_286_high_reserve_bytes + tls13_286_loop_shadow_reserve_bytes
tls13_286_loop_shadow_crc_off       equ 0
tls13_286_record_ciphertext_max    equ (1 << 14) + 256
tls13_286_record_plain_bytes       equ \
    tls13_286_record_ciphertext_max - 16
tls13_286_record_plain_off         equ \
    tls13_286_high_reserve_bytes - tls13_286_record_plain_bytes
tls13_286_pack_cache_off           equ 0x0000
tls13_286_pack_cache_bytes         equ 20992
tls13_286_g_table_off              equ 0x5800
tls13_286_w7_table_bytes           equ 8128
; Before table generation this public table window is the raw, unconditioned
; timing-event buffer.  It is overwritten before any authenticated handshake.
tls13_286_entropy_raw_off           equ tls13_286_g_table_off
tls13_286_entropy_samples           equ 1024
tls13_286_entropy_event_bytes       equ 6
tls13_286_entropy_raw_bytes         equ \
    tls13_286_entropy_samples * tls13_286_entropy_event_bytes
; The acquisition route reuses the retired entropy/G-table window as a
; status-last escrow for the exact peer ML-KEM ciphertext and its provisional
; K'.  Offline authentication performs the complete FO decapsulation against
; the retained dk, compares the selected secret in constant time, wipes this
; escrow, and only then overwrites the same window with the P-256 G table.
tls13_286_candidate_ciphertext_off  equ tls13_286_g_table_off
tls13_286_candidate_ciphertext_bytes equ 1088
tls13_286_candidate_secret_off      equ \
    tls13_286_candidate_ciphertext_off + \
    tls13_286_candidate_ciphertext_bytes
tls13_286_candidate_secret_bytes    equ 32
tls13_286_candidate_status_inv_off  equ \
    tls13_286_candidate_secret_off + tls13_286_candidate_secret_bytes
tls13_286_candidate_status_off      equ \
    tls13_286_candidate_status_inv_off + 1
tls13_286_candidate_status_valid    equ 0xa5
tls13_286_candidate_status_inverse  equ 0x5a
tls13_286_leaf_table_off           equ 0x77c0
tls13_286_certificate_off          equ 0x9780
; The current ordinary four-certificate flight is 3,434 bytes. Bound the
; complete handshake to 4 KiB without moving any private-state slot. The
; low config snapshot occupies retired pack padding below the G table.
tls13_286_certificate_max          equ 4096
tls13_286_private_off              equ 0xa780
tls13_286_mlkem_dk_off             equ tls13_286_private_off
tls13_286_mlkem_dk_bytes           equ 2400
tls13_286_mlkem_dk_ek_offset       equ 1152
tls13_286_mlkem_dk_ek_off          equ \
    tls13_286_mlkem_dk_off + tls13_286_mlkem_dk_ek_offset
tls13_286_entropy_seed_off         equ 0xb0e0
tls13_286_entropy_seed_bytes       equ 64
tls13_286_x25519_scalar_off        equ 0xb120
tls13_286_x25519_scalar_bytes      equ 32
tls13_286_hybrid_secret_off        equ 0xb140
tls13_286_hybrid_secret_bytes      equ 64
tls13_286_resumption_master_off    equ 0xb180
tls13_286_resumption_master_bytes  equ 32
tls13_286_ticket_psk_off           equ 0xb1a0
tls13_286_ticket_psk_bytes         equ 32
tls13_286_ticket_identity_off      equ 0xb1c0
tls13_286_ticket_identity_max      equ 192
tls13_286_ticket_nonce_off         equ 0xb280
tls13_286_ticket_nonce_max         equ 32
tls13_286_cv_signature_off         equ 0xb2a0
tls13_286_cv_signature_max         equ 72
tls13_286_cv_digest_off            equ 0xb2e8
tls13_286_cv_digest_bytes          equ 32
tls13_286_metadata_off             equ 0xb308
tls13_286_metadata_bytes           equ \
    tls13_286_high_reserve_bytes - tls13_286_metadata_off

; High-memory status-last escrow.  The 286 bootstrap runs from the reclaimed
; legacy ClientHello phase before any 0x3400 TLS controller is staged.  It
; preserves the complete reconnect-safe config/prompt block and the compact
; UI/control block here, then validates them before either abort restoration
; or final publication.  A complete validated tail footer is retained beside
; the snapshots so later stages never trust low scratch after it is reused.
tls13_286_escrow_config_off         equ 0x5200
tls13_286_escrow_config_source      equ 0x3b9c
tls13_286_escrow_config_bytes       equ \
    0x4000 - tls13_286_escrow_config_source
tls13_286_escrow_low_off            equ 0xb552
tls13_286_escrow_low_source         equ 0x0f33
tls13_286_escrow_low_bytes          equ 0x00af
tls13_286_tail_footer_off           equ 0xb602
tls13_286_tail_footer_bytes         equ 512
tls13_286_previous_entropy_hash_off equ 0xb802
tls13_286_previous_entropy_hash_len equ 32
tls13_286_entropy_health_off        equ 0xb822
tls13_286_entropy_health_bytes      equ 64
tls13_286_escrow_meta_off           equ 0xb862
tls13_286_escrow_meta_bytes         equ 32
tls13_286_prompt_off                equ 0xb882
tls13_286_prompt_source             equ 0x36c2
tls13_286_prompt_max                equ 255
tls13_286_prompt_len_off            equ 0xb981
tls13_286_prompt_len_source         equ 0x37c1
tls13_286_controller_state_off      equ 0xb982
tls13_286_controller_state_bytes    equ \
    tls13_286_high_reserve_bytes - tls13_286_controller_state_off

; Two independently generated full-hybrid attempts: acquisition and the
; normal-order authenticated fresh connection.  Every consumer transitions
; exactly one bundle from READY to USED before copying any private byte.
tls13_286_attempt_bundle_bytes       equ 160
tls13_286_attempt_d_off              equ 0
tls13_286_attempt_z_off              equ 32
tls13_286_attempt_x_scalar_off       equ 64
tls13_286_attempt_random_off         equ 96
tls13_286_attempt_session_id_off     equ 128
tls13_286_attempt_acquire_off        equ tls13_286_controller_state_off
tls13_286_attempt_fresh_off          equ \
    tls13_286_attempt_acquire_off + tls13_286_attempt_bundle_bytes
tls13_286_drbg_k_off                 equ \
    tls13_286_attempt_fresh_off + tls13_286_attempt_bundle_bytes
tls13_286_drbg_v_off                 equ tls13_286_drbg_k_off + 32
tls13_286_drbg_work_off              equ tls13_286_drbg_v_off + 32
tls13_286_generation_hash_off        equ tls13_286_drbg_work_off + 64
tls13_286_entropy_root_status_inv_off equ \
    tls13_286_generation_hash_off + 32
tls13_286_entropy_root_status_off    equ \
    tls13_286_entropy_root_status_inv_off + 1
tls13_286_attempt_acquire_status_inv_off equ \
    tls13_286_entropy_root_status_off + 1
tls13_286_attempt_acquire_status_off equ \
    tls13_286_attempt_acquire_status_inv_off + 1
tls13_286_attempt_fresh_status_inv_off equ \
    tls13_286_attempt_acquire_status_off + 1
tls13_286_attempt_fresh_status_off   equ \
    tls13_286_attempt_fresh_status_inv_off + 1
; One TCP payload may coalesce the final ServerHello bytes with the beginning
; of the first protected record.  Preserve that still-encrypted suffix in the
; private high quarantine before the low receive frame is reused.
tls13_286_pending_wire_off           equ \
    (tls13_286_attempt_fresh_status_off + 8) & 0xfff8
tls13_286_pending_wire_max           equ 384
tls13_286_pending_wire_len_off       equ \
    tls13_286_pending_wire_off + tls13_286_pending_wire_max
tls13_286_pending_wire_status_inv_off equ \
    tls13_286_pending_wire_len_off + 2
tls13_286_pending_wire_status_off    equ \
    tls13_286_pending_wire_status_inv_off + 1
tls13_286_pending_wire_status_valid  equ 0xa5
tls13_286_pending_wire_status_inverse equ 0x5a
; Persistent first-flight authentication evidence and the one-byte decision
; published by the offline certificate stage.  Certificate bytes occupy the
; dedicated 4 KiB quarantine; these fields are written status-last only after
; the protected record tags and server Finished have both verified.
tls13_286_flight_meta_off            equ \
    (tls13_286_pending_wire_status_off + 8) & 0xfff8
tls13_286_certificate_len_off        equ tls13_286_flight_meta_off + 0
tls13_286_cv_signature_len_off       equ tls13_286_flight_meta_off + 2
tls13_286_capture_status_inv_off     equ tls13_286_flight_meta_off + 4
tls13_286_capture_status_off         equ tls13_286_flight_meta_off + 5
tls13_286_auth_status_inv_off        equ tls13_286_flight_meta_off + 6
tls13_286_auth_status_off            equ tls13_286_flight_meta_off + 7
tls13_286_ecdsa_result_off           equ tls13_286_flight_meta_off + 8
; Parent/core prepares identical low and high normalized UTC publications
; before entering the 286 bootstrap.  Bootstrap receives the low near pointer
; in DI with DS=ES=0, independently derives this high slot, requires exact
; low/high equality and the inverse/READY pair, then preserves only these nine
; bytes while clearing the rest of the high reservation.  Product policy first
; treats a valid machine RTC as the platform UTC clock and rejects absent/torn
; time. It never treats unauthenticated NTP as trusted time or interrupts the
; chat flow with a timezone question.
;   +0..6  packed BCD CC YY MM DD hh mm ss
;   +7     inverse status (0x5a)
;   +8     READY status (0xa5, written last)
tls13_286_rtc_publication_off        equ tls13_286_flight_meta_off + 16
tls13_286_rtc_publication_bytes      equ 9
tls13_286_rtc_status_inv_off         equ \
    tls13_286_rtc_publication_off + 7
tls13_286_rtc_status_off             equ \
    tls13_286_rtc_publication_off + 8
tls13_286_rtc_status_inverse         equ 0x5a
tls13_286_rtc_status_valid           equ 0xa5
; Same-boot NewSessionTicket escrow.  Acquisition exports one authenticated
; ticket as TENTATIVE only after the credential-free HEAD response and the
; ticket record have both authenticated.  Offline FO/X.509/CV authentication
; promotes it; the final resumption consumes it before reading PSK/identity.
tls13_286_ticket_meta_off            equ \
    (tls13_286_rtc_publication_off + tls13_286_rtc_publication_bytes + 15) & \
    0xfff0
tls13_286_ticket_lifetime_hi_off     equ tls13_286_ticket_meta_off + 0
tls13_286_ticket_lifetime_lo_off     equ tls13_286_ticket_meta_off + 2
tls13_286_ticket_age_add_off         equ tls13_286_ticket_meta_off + 4
tls13_286_ticket_nonce_len_off       equ tls13_286_ticket_meta_off + 8
tls13_286_ticket_identity_len_off    equ tls13_286_ticket_meta_off + 10
tls13_286_ticket_receipt_tick_lo_off equ tls13_286_ticket_meta_off + 12
tls13_286_ticket_receipt_tick_hi_off equ tls13_286_ticket_meta_off + 14
tls13_286_ticket_status_inv_off      equ tls13_286_ticket_meta_off + 16
tls13_286_ticket_status_off          equ tls13_286_ticket_meta_off + 17
tls13_286_ticket_truncated_hash_off  equ tls13_286_ticket_meta_off + 18
tls13_286_ticket_truncated_hash_bytes equ 32
tls13_286_ticket_binder_off          equ \
    tls13_286_ticket_truncated_hash_off + \
    tls13_286_ticket_truncated_hash_bytes
tls13_286_ticket_binder_bytes        equ 32
tls13_286_ticket_meta_end            equ \
    tls13_286_ticket_binder_off + tls13_286_ticket_binder_bytes
; The immutable K14 symmetric image is read from SEED.SYS into the otherwise
; idle full-record quarantine before either live TCP connection begins.  The
; flight coordinator consumes it exactly once, invalidates this status before
; doing any symmetric work, relocates the low copy, and authenticates that copy
; with the existing relocated-image CRC.  This removes twelve BIOS floppy
; reads from the provider's fresh-socket deadline without requiring writable
; media or retaining another executable image in the product tail.
tls13_286_symmetric_stage_status_inv_off equ tls13_286_ticket_meta_end
tls13_286_symmetric_stage_status_off equ \
    tls13_286_symmetric_stage_status_inv_off + 1
tls13_286_symmetric_stage_status_valid equ 0xa5
tls13_286_symmetric_stage_status_inverse equ 0x5a
; HELLO computes the resumption early "derived" secret before TCP, beside a
; bytewise complement, then publishes it status-last.  FLIGHT consumes and
; wipes this cache before importing it into the symmetric image.  Moving the
; ticket-only HKDF work out of the live window does not weaken the binder:
; HELLO emits the exact binder, ServerHello must select identity zero, and the
; authenticated server Finished remains the final PSK/hybrid proof.
tls13_286_resumption_early_off       equ \
    tls13_286_symmetric_stage_status_off + 1
tls13_286_resumption_early_bytes     equ 32
tls13_286_resumption_early_inverse_off equ \
    tls13_286_resumption_early_off + tls13_286_resumption_early_bytes
tls13_286_resumption_early_status_inv_off equ \
    tls13_286_resumption_early_inverse_off + \
    tls13_286_resumption_early_bytes
tls13_286_resumption_early_status_off equ \
    tls13_286_resumption_early_status_inv_off + 1
tls13_286_resumption_early_status_valid equ 0xa5
tls13_286_resumption_early_status_inverse equ 0x5a
tls13_286_symmetric_stage_off        equ tls13_286_record_plain_off
tls13_286_symmetric_stage_bytes      equ 12 * 512
; The final attempt precomputes its public nine-polynomial A^T matrix from the
; freshly generated ML-KEM ek/rho before TCP.  Full decapsulation consumes
; this cache exactly once after ServerHello, retaining the complete FIPS 203
; ciphertext compare and implicit-rejection selection while removing 27
; SHAKE128 permutations from the provider deadline.
tls13_286_mlkem_matrix_status_inv_off equ \
    tls13_286_resumption_early_status_off + 1
tls13_286_mlkem_matrix_status_off     equ \
    tls13_286_mlkem_matrix_status_inv_off + 1
tls13_286_mlkem_matrix_status_valid   equ 0xa5
tls13_286_mlkem_matrix_status_inverse equ 0x5a
tls13_286_mlkem_matrix_stage_off      equ \
    tls13_286_symmetric_stage_off + tls13_286_symmetric_stage_bytes
tls13_286_mlkem_matrix_stage_bytes    equ 9 * 256 * 2
; The compressed protected-flight coordinator is also read before TCP.  It
; remains public immutable code, is consumed status-first, and is decoded
; directly from high RAM after the asymmetric modules have retired.  Six
; sectors fit above the resumption matrix without reducing the 16 KiB record
; quarantine used once FLIGHT takes ownership.
tls13_286_flight_stage_status_inv_off equ \
    tls13_286_mlkem_matrix_status_off + 1
tls13_286_flight_stage_status_off     equ \
    tls13_286_flight_stage_status_inv_off + 1
tls13_286_flight_stage_status_valid   equ 0xa5
tls13_286_flight_stage_status_inverse equ 0x5a
tls13_286_flight_stage_off            equ \
    tls13_286_mlkem_matrix_stage_off + tls13_286_mlkem_matrix_stage_bytes
tls13_286_flight_stage_bytes          equ 6 * 512
tls13_286_ticket_status_tentative_inv equ 0x5a
tls13_286_ticket_status_tentative     equ 0xa5
tls13_286_ticket_status_promoted_inv  equ 0xc3
tls13_286_ticket_status_promoted      equ 0x3c
tls13_286_ticket_status_used_inv      equ 0x96
tls13_286_ticket_status_used          equ 0x69
tls13_286_flight_status_valid        equ 0xa5
tls13_286_flight_status_inverse      equ 0x5a
tls13_286_entropy_status_ready       equ 0xa5
tls13_286_entropy_status_ready_inv   equ 0x5a
tls13_286_entropy_status_used        equ 0x3c
tls13_286_entropy_status_used_inv    equ 0xc3

%if tls13_286_attempt_fresh_status_off + 1 > tls13_286_high_reserve_bytes
%error "TLS 1.3 286 entropy/attempt state exceeds high reservation"
%endif
%if tls13_286_pending_wire_status_off + 1 > tls13_286_high_reserve_bytes
%error "TLS 1.3 286 pending-wire quarantine exceeds high reservation"
%endif
%if tls13_286_rtc_publication_off + tls13_286_rtc_publication_bytes > \
    tls13_286_high_reserve_bytes
%error "TLS 1.3 286 flight metadata exceeds high reservation"
%endif
%if tls13_286_rtc_publication_off + tls13_286_rtc_publication_bytes > \
    tls13_286_record_plain_off
%error "TLS 1.3 286 metadata overlaps full-record quarantine"
%endif
%if tls13_286_ticket_meta_end > tls13_286_record_plain_off
%error "TLS 1.3 286 ticket metadata overlaps full-record quarantine"
%endif
%if tls13_286_symmetric_stage_status_off + 1 > \
    tls13_286_symmetric_stage_off
%error "TLS 1.3 286 symmetric-stage status overlaps staged image"
%endif
%if tls13_286_resumption_early_status_off + 1 > \
    tls13_286_symmetric_stage_off
%error "TLS 1.3 286 resumption-early cache overlaps staged image"
%endif
%if tls13_286_mlkem_matrix_status_off + 1 > \
    tls13_286_symmetric_stage_off
%error "TLS 1.3 286 ML-KEM matrix status overlaps staged image"
%endif
%if tls13_286_symmetric_stage_off + tls13_286_symmetric_stage_bytes > \
    tls13_286_high_reserve_bytes
%error "TLS 1.3 286 symmetric stage exceeds full-record quarantine"
%endif
%if tls13_286_mlkem_matrix_stage_off + \
    tls13_286_mlkem_matrix_stage_bytes > tls13_286_high_reserve_bytes
%error "TLS 1.3 286 ML-KEM matrix stage exceeds full-record quarantine"
%endif
%if tls13_286_flight_stage_status_off + 1 > \
    tls13_286_symmetric_stage_off
%error "TLS 1.3 286 flight-stage status overlaps staged executable bytes"
%endif
%if tls13_286_flight_stage_off + tls13_286_flight_stage_bytes > \
    tls13_286_high_reserve_bytes
%error "TLS 1.3 286 flight stage exceeds full-record quarantine"
%endif
%if tls13_286_record_plain_off & 15
%error "TLS 1.3 286 full-record quarantine must be paragraph aligned"
%endif
%if tls13_286_record_plain_off + tls13_286_record_plain_bytes != \
    tls13_286_high_reserve_bytes
%error "TLS 1.3 286 full-record quarantine must end at conventional top"
%endif

tls13_286_escrow_magic_off          equ tls13_286_escrow_meta_off + 0
tls13_286_escrow_magic_inv_off      equ tls13_286_escrow_meta_off + 4
tls13_286_escrow_config_crc_off     equ tls13_286_escrow_meta_off + 8
tls13_286_escrow_low_crc_off        equ tls13_286_escrow_meta_off + 10
tls13_286_escrow_mode_off           equ tls13_286_escrow_meta_off + 12
tls13_286_escrow_crypto_seg_off     equ tls13_286_escrow_meta_off + 14
tls13_286_escrow_prompt_crc_off     equ tls13_286_escrow_meta_off + 16
tls13_286_escrow_prompt_len_off     equ tls13_286_escrow_meta_off + 18
tls13_286_escrow_prompt_len_inv_off equ tls13_286_escrow_meta_off + 19
tls13_286_escrow_preserve_crc_off   equ tls13_286_escrow_meta_off + 20
tls13_286_escrow_status_inv_off     equ tls13_286_escrow_meta_off + 30
tls13_286_escrow_status_off         equ tls13_286_escrow_meta_off + 31
tls13_286_escrow_magic_lo           equ 0x3632 ; "26"
tls13_286_escrow_magic_hi           equ 0x5345 ; "ES"
tls13_286_escrow_magic_inv_lo       equ 0xc9cd
tls13_286_escrow_magic_inv_hi       equ 0xacba
tls13_286_escrow_status_valid       equ 0xa5
tls13_286_escrow_status_inverse     equ 0x5a

%if tls13_286_pack_cache_off + tls13_286_pack_cache_bytes > tls13_286_g_table_off
%error "TLS 1.3 286 pack cache overlaps G table"
%endif
%if tls13_286_g_table_off + tls13_286_w7_table_bytes > tls13_286_leaf_table_off
%error "TLS 1.3 286 G table overlaps leaf table"
%endif
%if tls13_286_leaf_table_off + tls13_286_w7_table_bytes > tls13_286_certificate_off
%error "TLS 1.3 286 leaf table overlaps captured Certificate"
%endif
%if tls13_286_certificate_off + tls13_286_certificate_max > tls13_286_private_off
%error "TLS 1.3 286 Certificate quarantine overlaps private state"
%endif
%if tls13_286_pack_cache_off + tls13_286_pack_cache_bytes > tls13_286_escrow_config_off
%error "TLS 1.3 286 pack cache overlaps config escrow"
%endif
%if tls13_286_escrow_config_off + tls13_286_escrow_config_bytes > tls13_286_g_table_off
%error "TLS 1.3 286 config escrow overlaps G table"
%endif
%if tls13_286_mlkem_dk_off + tls13_286_mlkem_dk_bytes > tls13_286_entropy_seed_off
%error "TLS 1.3 286 ML-KEM decapsulation key overlaps entropy seed"
%endif
%if tls13_286_entropy_seed_off + tls13_286_entropy_seed_bytes > tls13_286_x25519_scalar_off
%error "TLS 1.3 286 entropy seed overlaps X25519 scalar"
%endif
%if tls13_286_x25519_scalar_off + tls13_286_x25519_scalar_bytes > tls13_286_hybrid_secret_off
%error "TLS 1.3 286 X25519 scalar overlaps hybrid secret"
%endif
%if tls13_286_hybrid_secret_off + tls13_286_hybrid_secret_bytes > tls13_286_resumption_master_off
%error "TLS 1.3 286 hybrid secret overlaps resumption master"
%endif
%if tls13_286_resumption_master_off + tls13_286_resumption_master_bytes > tls13_286_ticket_psk_off
%error "TLS 1.3 286 resumption master overlaps ticket PSK"
%endif
%if tls13_286_ticket_psk_off + tls13_286_ticket_psk_bytes > tls13_286_ticket_identity_off
%error "TLS 1.3 286 ticket PSK overlaps ticket identity"
%endif
%if tls13_286_ticket_identity_off + tls13_286_ticket_identity_max > tls13_286_ticket_nonce_off
%error "TLS 1.3 286 ticket identity overlaps ticket nonce"
%endif
%if tls13_286_ticket_nonce_off + tls13_286_ticket_nonce_max > tls13_286_cv_signature_off
%error "TLS 1.3 286 ticket nonce overlaps CertificateVerify signature"
%endif
%if tls13_286_cv_signature_off + tls13_286_cv_signature_max > tls13_286_cv_digest_off
%error "TLS 1.3 286 CertificateVerify signature overlaps its digest"
%endif
%if tls13_286_cv_digest_off + tls13_286_cv_digest_bytes > tls13_286_metadata_off
%error "TLS 1.3 286 CertificateVerify digest overlaps metadata"
%endif
%if tls13_286_metadata_off + tls13_286_metadata_bytes > tls13_286_high_reserve_bytes
%error "TLS 1.3 286 metadata exceeds high reservation"
%endif
%if tls13_286_escrow_config_off + tls13_286_escrow_config_bytes > tls13_286_escrow_low_off
%error "TLS 1.3 286 config escrow overlaps low-state escrow"
%endif
%if tls13_286_escrow_low_off + tls13_286_escrow_low_bytes > tls13_286_tail_footer_off
%error "TLS 1.3 286 low-state escrow overlaps tail footer"
%endif
%if tls13_286_tail_footer_off + tls13_286_tail_footer_bytes > tls13_286_previous_entropy_hash_off
%error "TLS 1.3 286 tail footer overlaps prior entropy hash"
%endif
%if tls13_286_previous_entropy_hash_off + tls13_286_previous_entropy_hash_len > tls13_286_entropy_health_off
%error "TLS 1.3 286 prior entropy hash overlaps health state"
%endif
%if tls13_286_entropy_health_off + tls13_286_entropy_health_bytes > tls13_286_escrow_meta_off
%error "TLS 1.3 286 entropy health state overlaps escrow metadata"
%endif
%if tls13_286_escrow_meta_off + tls13_286_escrow_meta_bytes > tls13_286_controller_state_off
%error "TLS 1.3 286 escrow metadata overlaps prompt/controller state"
%endif
%if tls13_286_prompt_off + tls13_286_prompt_max > tls13_286_prompt_len_off
%error "TLS 1.3 286 prompt escrow overlaps prompt length"
%endif
%if tls13_286_prompt_len_off + 1 > tls13_286_controller_state_off
%error "TLS 1.3 286 prompt escrow overlaps controller state"
%endif
%if tls13_286_controller_state_off + tls13_286_controller_state_bytes > tls13_286_high_reserve_bytes
%error "TLS 1.3 286 controller state exceeds high reservation"
%endif

; Low-memory controller handoff.  The dynamically generated raw X25519 public
; share is written here by the 286 root, snapshotted by HELLO, and scrubbed
; immediately.  The rest of the 512-byte band is reserved for bounded
; controller handoff/scratch.  The 0x4200..422f gap extends the authenticated
; abort capsule with the parent-stack bridge; executable modules begin at
; 0x4230.
tls13_286_controller_load          equ 0x1800
tls13_286_controller_limit         equ 0x3400
tls13_286_controller_max_bytes     equ \
    tls13_286_controller_limit - tls13_286_controller_load
tls13_286_controller_handoff       equ 0x4000
tls13_286_client_x_public          equ 0x4000
tls13_286_client_x_public_bytes    equ 32
tls13_286_controller_handoff_end   equ 0x4200
tls13_286_abort_capsule_load       equ 0x4040
tls13_286_abort_capsule_limit      equ 0x4230
tls13_286_abort_capsule_magic      equ 0       ; "S286AB02"
tls13_286_abort_capsule_abi        equ 8
tls13_286_abort_capsule_bytes      equ 10
tls13_286_abort_capsule_entry_ptr  equ 12
tls13_286_abort_capsule_success_ptr equ 14
tls13_286_abort_capsule_header     equ 16
; The product runtime enters this route on its RAM-relative segment-zero
; stack, which is above 0x8000 at the 512 KiB floor.  The authenticated root
; moves the complete tail to the fixed 0x7a00..0x7fff guard and publishes the
; parent SP status-last.  The capsule validates that root copy and temporarily
; reuses its geometry-inverse word to carry the selected SP through cleanup.
tls13_286_abort_capsule_crypto_seg equ \
    tls13_286_abort_capsule_limit - 4
tls13_286_abort_capsule_crypto_seg_inverse equ \
    tls13_286_abort_capsule_limit - 2

; The fresh-hybrid HELLO controller shares the proven low public-object
; geometry with the 16 KiB research path.  ML-KEM keygen writes a throwaway
; 1,184-byte public-key copy here, while the authoritative embedded copy in
; the high private dk survives later low phase loads.  HELLO stages each
; fragment from that high copy into the retired module overlay immediately
; before hashing and sending it.  After the final ClientHello fragment is
; acknowledged, the peer ciphertext replaces this low public band.  The
; exported peer share, digest, and live SHA-256 context fit in the remaining
; low scratch.  None of these low addresses carries private material.
tls13_286_hello_rx_frame_off        equ 0x0700
tls13_286_hello_rx_frame_bytes      equ 14 + 20 + 20 + 384
tls13_286_hello_public_off          equ 0x08c0
tls13_286_hello_mlkem_ek_off        equ tls13_286_hello_public_off
tls13_286_hello_mlkem_ek_bytes      equ 1184
tls13_286_hello_ciphertext_off      equ tls13_286_hello_public_off
tls13_286_hello_ciphertext_bytes    equ 1088
tls13_286_hello_server_x_off        equ \
    tls13_286_hello_ciphertext_off + tls13_286_hello_ciphertext_bytes
tls13_286_hello_digest_off          equ tls13_286_hello_server_x_off + 32
tls13_286_hello_ctx_magic_off       equ tls13_286_hello_digest_off + 32
tls13_286_hello_ctx_version_off     equ tls13_286_hello_ctx_magic_off + 4
tls13_286_hello_ctx_block_len_off   equ tls13_286_hello_ctx_version_off + 1
tls13_286_hello_ctx_len_low_off     equ \
    tls13_286_hello_ctx_block_len_off + 1
tls13_286_hello_ctx_len_high_off    equ tls13_286_hello_ctx_len_low_off + 2
tls13_286_hello_ctx_state_off       equ tls13_286_hello_ctx_len_high_off + 2
tls13_286_hello_ctx_block_off       equ tls13_286_hello_ctx_state_off + 32
tls13_286_hello_status_off          equ tls13_286_hello_ctx_block_off + 64
tls13_286_hello_handoff_end         equ tls13_286_hello_status_off + 1

%if tls13_286_hello_rx_frame_off + tls13_286_hello_rx_frame_bytes > \
    tls13_286_hello_public_off
%error "TLS 1.3 286 HELLO receive frame overlaps public key/ciphertext"
%endif
%if tls13_286_hello_mlkem_ek_off + tls13_286_hello_mlkem_ek_bytes > 0x1000
%error "TLS 1.3 286 ML-KEM public key exceeds low scratch"
%endif
%if tls13_286_mlkem_dk_ek_offset + tls13_286_hello_mlkem_ek_bytes > \
    tls13_286_mlkem_dk_bytes
%error "TLS 1.3 286 embedded ML-KEM public key exceeds private dk"
%endif
%if tls13_286_hello_handoff_end > 0x1000
%error "TLS 1.3 286 HELLO transcript handoff exceeds low scratch"
%endif

; One decoded asymmetric module occupies this low overlay.  It is outside the
; resident NIC DMA/driver band [0x8000,0x10000) and below the current stack
; guard.  All product modules are assembled for this fixed origin, so the pack
; carries no relocation stream.  The 0x6300 flight coordinator intentionally
; aliases the upper part of P256W7/ECDSAW7, but never coexists with them: the
; acquisition flight retires its symmetric image and one-way chains to auth,
; and resumed HELLO completes every module call before loading a fresh flight.
; The loader wipes the exact authenticated raw length on every transition.
tls13_286_module_load              equ 0x4230
tls13_286_module_limit             equ 0x7a00
tls13_286_module_max_bytes         equ \
    tls13_286_module_limit - tls13_286_module_load
tls13_286_tail_stack_top           equ 0x8000
tls13_286_parent_stack_window      equ 1536
tls13_286_parent_sp_status_inverse equ 0x5a
tls13_286_parent_sp_status_valid   equ 0xa5

%if tls13_286_client_x_public + tls13_286_client_x_public_bytes > tls13_286_controller_handoff_end
%error "TLS 1.3 286 client X25519 share exceeds controller handoff"
%endif
%if tls13_286_client_x_public + tls13_286_client_x_public_bytes > \
    tls13_286_abort_capsule_load
%error "TLS 1.3 286 X25519 handoff overlaps abort capsule"
%endif
%if tls13_286_controller_handoff_end > tls13_286_module_load
%error "TLS 1.3 286 controller handoff overlaps module overlay"
%endif

; Target-local entropy/precompute controller header at the safe controller
; origin.  The main entry is selected by the tail directory; the remaining
; entries are explicit health/KAT/abort gates.
tls13_286_entropy_magic             equ 0       ; "S286ENT2"
tls13_286_entropy_abi               equ 8
tls13_286_entropy_image_bytes       equ 10
tls13_286_entropy_entry_count       equ 12
tls13_286_entropy_entry_table       equ 14
tls13_286_entropy_entry_main        equ \
    tls13_286_entropy_entry_table + 0
tls13_286_entropy_entry_health_reset equ \
    tls13_286_entropy_entry_table + 2
tls13_286_entropy_entry_health_inject equ \
    tls13_286_entropy_entry_table + 4
tls13_286_entropy_entry_drbg_kat    equ \
    tls13_286_entropy_entry_table + 6
tls13_286_entropy_entry_abort       equ \
    tls13_286_entropy_entry_table + 8
tls13_286_entropy_entries           equ 5

; Product acquisition/resumption HELLO controller.  The public ABI exports
; only the two complete live routes.  Fragment construction, ServerHello
; streaming, hybrid selection, and fatal cleanup remain authenticated internal
; routines so product callers cannot stop at a parsed-but-unauthenticated
; intermediate state.
tls13_286_hello_magic               equ 0       ; "S286HL02"
tls13_286_hello_abi                 equ 8
tls13_286_hello_image_bytes         equ 10
tls13_286_hello_entry_count         equ 12
tls13_286_hello_entry_table         equ 14
tls13_286_hello_entry_live_acquire  equ \
    tls13_286_hello_entry_table + 0
tls13_286_hello_entry_live_fresh    equ \
    tls13_286_hello_entry_table + 2
tls13_286_hello_entries             equ 2

; Product module header at tls13_286_module_load.
tls13_286_mod_magic                equ 0       ; 8 bytes: "S286MOD2"
tls13_286_mod_abi                  equ 8       ; word, == tls13_286_abi_version
tls13_286_mod_kind                 equ 10      ; word
tls13_286_mod_image_bytes          equ 12      ; word
tls13_286_mod_entry_off            equ 14      ; word from module_load
tls13_286_mod_required_state       equ 16      ; word, required state bytes
tls13_286_mod_required_stack       equ 18      ; word
tls13_286_mod_flags                equ 20      ; word
tls13_286_mod_header_bytes         equ 32
tls13_286_mod_flag_one_shot        equ 0x0001  ; controller must reload after call

tls13_286_mod_kind_mlkem_keygen    equ 1
tls13_286_mod_kind_mlkem_decap     equ 2
tls13_286_mod_kind_x25519          equ 3
tls13_286_mod_kind_p256_tablegen   equ 4
tls13_286_mod_kind_ecdsa_verify    equ 5

tls13_286_mod_op_mlkem_keygen      equ 1
tls13_286_mod_op_mlkem_decap       equ 2
tls13_286_mod_op_x25519_keygen     equ 3
tls13_286_mod_op_x25519_shared     equ 4
tls13_286_mod_op_p256_tablegen     equ 5
tls13_286_mod_op_ecdsa_verify      equ 6
tls13_286_mod_op_sha3_256_condition equ 7
tls13_286_mod_op_mlkem_candidate   equ 8
tls13_286_mod_op_mlkem_matrix_precompute equ 9
tls13_286_mod_op_mlkem_decap_cached equ 10

%if tls13_286_entropy_raw_off + tls13_286_entropy_raw_bytes > tls13_286_leaf_table_off
%error "TLS 1.3 286 raw entropy events exceed pre-table scratch"
%endif
%if tls13_286_candidate_status_off + 1 > tls13_286_g_table_off + \
    tls13_286_w7_table_bytes
%error "TLS 1.3 286 candidate escrow exceeds retired G-table scratch"
%endif

; Entry contract (near call through module_load + mod_entry_off):
;   in:  AX=operation, BX=controller-state near pointer,
;        SI=one operation descriptor near pointer, DI=0 (reserved),
;        DS=ES=SS=0, DF=0, and an even SP in the 0x7a00..0x7fff guard.
;   out: CF=0 and AX=0 on success; CF=1 and AX=error on rejection.
;   preserved: CS, SS, SP, BP.  Other GP registers/flags are volatile.
; A module owns no state after return; every cross-module object is named by a
; descriptor or controller state.  The controller wipes the overlay before
; decoding the next module.  ML-KEM modules additionally require
; BX=tls13_286_root_state_loader exactly, advertise tls13_286_state_bytes in
; required_state, and bind the state cache segment/capacity to the validated
; top reservation.
tls13_286_status_ok                 equ 0
tls13_286_error_abi                 equ 1
tls13_286_error_bounds              equ 2
tls13_286_error_decode              equ 3
tls13_286_error_crypto              equ 4
tls13_286_error_profile             equ 5

; Common far-span descriptor.  Conventional-RAM spans must use the unique
; canonical representation segment=physical>>4, offset=physical&15; aliases
; with the same physical address are rejected.  Every inactive span in the
; selected operation is encoded as eight zero bytes; alternate addresses in
; unused fields are rejected.
tls13_286_span_off                  equ 0
tls13_286_span_seg                  equ 2
tls13_286_span_len                  equ 4       ; dword
tls13_286_span_bytes                equ 8

; Operation descriptor: four input and two output spans plus flags.  Flags
; must be zero.  Exact length requirements are fixed by the operation:
;   MLKEM keygen seed=64, ek=1184, dk=2400
;   MLKEM decap dk=2400, ciphertext=1088, secret=32
;   MLKEM candidate dk=2400, ciphertext=1088, K'=32
;   MLKEM matrix precompute dk=2400, public A^T cache=4608
;   MLKEM cached decap dk=2400, ciphertext=1088, A^T cache=4608, secret=32
;   X25519 scalar/peer/result=32
;   P-256 tablegen affine=64, scratch=16256, table=8128
;   ECDSA digest=32, DER signature=8..72, G/Q tables=8128, result=1
; ML-KEM-module spans also bind to the exact low/high product slots named
; above; arbitrary same-length buffers or aliases into controller, module,
; descriptor, stack, or another private object are rejected.
tls13_286_desc_op                   equ 0
tls13_286_desc_flags                equ 2
tls13_286_desc_input0               equ 4
tls13_286_desc_input1               equ \
    tls13_286_desc_input0 + tls13_286_span_bytes
tls13_286_desc_input2               equ \
    tls13_286_desc_input1 + tls13_286_span_bytes
tls13_286_desc_input3               equ \
    tls13_286_desc_input2 + tls13_286_span_bytes
tls13_286_desc_output0              equ \
    tls13_286_desc_input3 + tls13_286_span_bytes
tls13_286_desc_output1              equ \
    tls13_286_desc_output0 + tls13_286_span_bytes
tls13_286_desc_bytes                equ \
    tls13_286_desc_output1 + tls13_286_span_bytes

; Pack-v2 header/directory.  The complete pack is a build-time-included,
; contiguous cold tail of SEED.SYS, not another FAT file.  The core reads it
; through its existing SEED.SYS sector map, verifies header/bounds/CRC, and
; caches all bytes before TCP.  Entry payloads are raw LZ4 blocks.
tls13_286_pack_magic                equ 0       ; 8 bytes: "S286PK02"
tls13_286_pack_abi                  equ 8       ; word
tls13_286_pack_count                equ 10      ; word
tls13_286_pack_header_bytes_off     equ 12      ; word
tls13_286_pack_entry_bytes_off      equ 14      ; word
tls13_286_pack_total_bytes          equ 16      ; dword
tls13_286_pack_directory_off        equ 20
tls13_286_pack_header_bytes         equ 512

tls13_286_pack_entry_name           equ 0       ; 8-byte ASCII/NUL
tls13_286_pack_entry_kind           equ 8       ; word
tls13_286_pack_entry_flags          equ 10      ; word
tls13_286_pack_entry_raw_bytes      equ 12      ; word
tls13_286_pack_entry_comp_bytes     equ 14      ; word
tls13_286_pack_entry_payload_off    equ 16      ; dword
tls13_286_pack_entry_crc16          equ 20      ; word CCITT-FALSE
tls13_286_pack_entry_reserved       equ 22      ; word, must be zero
tls13_286_pack_entry_bytes          equ 24
tls13_286_pack_flag_raw_lz4         equ 1
; Sizing tools set this bit because their benchmark images are linked for
; org 0x1000.  The product loader accepts only raw_lz4 and therefore rejects it.
tls13_286_pack_flag_research        equ 0x8000

; Last-sector product-tail footer.  The bootstrap derives its location from
; the resident core header's total-sector word, validates the entire footer,
; then finds the unique root-stage directory entry.  Directory sectors are
; 16-bit SEED.SYS-relative values; they are not restricted to the legacy
; eight-bit phase-key range.
tls13_286_tail_magic                equ 0       ; 8 bytes: "S286TL02"
tls13_286_tail_abi                  equ 8       ; word
tls13_286_tail_header_bytes_off     equ 10      ; word
tls13_286_tail_total_sectors        equ 12      ; word
tls13_286_tail_start_sector         equ 14      ; word
tls13_286_tail_sectors              equ 16      ; word, includes footer
tls13_286_tail_entry_count          equ 18      ; word
tls13_286_tail_entry_bytes_off      equ 20      ; word
tls13_286_tail_reserved             equ 22      ; ten zero bytes
tls13_286_tail_directory_off        equ 32
tls13_286_tail_header_bytes         equ 32
tls13_286_tail_footer_crc           equ 510     ; CRC16 over bytes 0..509
tls13_286_tail_entry_bytes          equ 16
tls13_286_tail_max_entries          equ \
    (tls13_286_tail_footer_crc - tls13_286_tail_directory_off) / \
    tls13_286_tail_entry_bytes

tls13_286_tail_entry_kind           equ 0
tls13_286_tail_entry_flags          equ 2
tls13_286_tail_entry_start_sector   equ 4
tls13_286_tail_entry_sectors        equ 6
tls13_286_tail_entry_image_bytes    equ 8
tls13_286_tail_entry_load           equ 10
tls13_286_tail_entry_entry          equ 12
tls13_286_tail_entry_crc16          equ 14
tls13_286_tail_flag_product         equ 0x0001
tls13_286_tail_flag_raw_lz4         equ 0x0002
tls13_286_tail_kind_root_stage      equ 1
tls13_286_tail_kind_module_pack     equ 2
tls13_286_tail_kind_hello_fresh     equ 3
tls13_286_tail_kind_hello_resume    equ 4
tls13_286_tail_kind_acquire         equ 5
tls13_286_tail_kind_authenticate    equ 6
tls13_286_tail_kind_resume          equ 7
tls13_286_tail_kind_precompute      equ 8
tls13_286_tail_kind_flight          equ 9
tls13_286_tail_kind_flight_sym      equ 10
tls13_286_tail_kind_rtc             equ 11

; The protected-flight coordinator lifetime-aliases the upper module window.
; It is loaded only after HELLO retires its modules and is disposable before
; offline auth decodes P256W7/ECDSAW7.  Its 286 symmetric variant retains
; mutable state at 0x7380..0x79ad, above those modules and below the resident
; 0x7a00 stack guard.
tls13_286_flight_load               equ 0x6300
tls13_286_flight_limit              equ 0x7380
tls13_286_flight_max_bytes          equ \
    tls13_286_flight_limit - tls13_286_flight_load

; Resident-core callback vector supplied to the flat controller.
tls13_286_cb_read_sector            equ 0
tls13_286_cb_tcp_send               equ 2
tls13_286_cb_tcp_receive            equ 4
tls13_286_cb_close_socket           equ 6
tls13_286_cb_bytes                  equ 8

; Near state shared by the cold 286 root, pack loader, and live controller.
; The complete validated pack is cached at cache_seg:0000.  cache_seg is the
; paragraph-aligned top reservation computed from BDA[0413]; the cache never
; aliases the low overlay or the driver/DMA band.
tls13_286_state_cache_seg            equ 0
tls13_286_state_cache_capacity       equ 2
tls13_286_state_pack_bytes           equ 4
tls13_286_state_loaded_kind          equ 6
tls13_286_state_loaded_flags         equ 8
tls13_286_state_callbacks            equ 10
tls13_286_state_bytes                equ \
    tls13_286_state_callbacks + tls13_286_cb_bytes

; Root-stage service table.  The validated pack loader occupies 0x3400 upward;
; the compact root continuation is fixed at 0x3910 so later low controllers
; can call its component loader without depending on the loader's exact size.
tls13_286_root_service_table         equ 0x3910
tls13_286_root_service_entry         equ tls13_286_root_service_table + 8
tls13_286_root_service_chain         equ tls13_286_root_service_table + 10
tls13_286_root_service_abort         equ tls13_286_root_service_table + 12
tls13_286_root_service_bytes         equ 14
tls13_286_root_entry                 equ \
    tls13_286_root_service_table + tls13_286_root_service_bytes
; Read-only preconnection staging helpers.  These are fixed-origin internal
; root routines, called only while the current controller remains disjoint
; from every destination they describe.  Assembly-time assertions in the
; root image make any layout drift fail the build.
tls13_286_root_validate_footer       equ 0x3adf
tls13_286_root_find_entry            equ 0x3b4b
tls13_286_root_state                 equ 0x4020
tls13_286_root_state_mode            equ tls13_286_root_state + 0
tls13_286_root_state_crypto_seg      equ tls13_286_root_state + 2
tls13_286_root_state_loader          equ tls13_286_root_state + 4
; Bootstrap-only parent-stack handoff.  This sits after the loader's bounded
; state and before the independently authenticated capsule at 0x4040.  It is
; status-last and remains an independent copy until HELLO freezes it into the
; capsule tail.
tls13_286_root_state_parent_sp       equ \
    tls13_286_root_state_loader + tls13_286_state_bytes
tls13_286_root_state_parent_sp_inverse equ \
    tls13_286_root_state_parent_sp + 2
tls13_286_root_state_parent_sp_status_inv equ \
    tls13_286_root_state_parent_sp + 4
tls13_286_root_state_parent_sp_status equ \
    tls13_286_root_state_parent_sp + 5
tls13_286_root_state_end             equ \
    tls13_286_root_state_parent_sp_status + 1

%if tls13_286_root_state_end > tls13_286_abort_capsule_load
%error "TLS 1.3 286 root parent-stack handoff overlaps abort capsule"
%endif

; Compressed tail components begin with this fixed header.  The footer's
; image_bytes is the exact stored header+block length (sector padding is not
; input); load/entry name the decoded image.  The header supplies the exact
; raw length required by the bounded generic LZ4 loader entry.
tls13_286_tail_lz4_magic             equ 0       ; 4 bytes: "LZ4B"
tls13_286_tail_lz4_raw_bytes         equ 4       ; word
tls13_286_tail_lz4_block_bytes       equ 6       ; word
tls13_286_tail_lz4_crc16             equ 8       ; word
tls13_286_tail_lz4_reserved          equ 10      ; word, zero
tls13_286_tail_lz4_header_bytes      equ 12

tls13_286_ctl_done                  equ 0
tls13_286_ctl_need_rx               equ 1
tls13_286_ctl_need_reconnect        equ 2
tls13_286_ctl_acquire_certificate   equ 3
tls13_286_ctl_fail                  equ 4

; Fixed-origin pack-loader image at 0000:3400.  The controller loads this
; before any connection and may retain it until the symmetric overlay starts
; consuming 0x3600+.  Entry 0 validates a pack already cached in high RAM;
; entry 1 decodes and authenticates AX=module kind into 0000:4230; entry 2
; invokes the decoded module with AX=operation, SI=descriptor, DI=0; entry 3
; decodes a controller block from DS:SI into one of the bounded low phase
; windows (ES=0, DI destination, CX compressed bytes, DX raw bytes,
; BP expected CRC16).
tls13_286_loader_load                equ 0x3400
tls13_286_loader_magic               equ 0
tls13_286_loader_abi                 equ 8
tls13_286_loader_image_bytes         equ 10
tls13_286_loader_entry_count         equ 12
tls13_286_loader_entry_table         equ 14
tls13_286_loader_entry_validate      equ \
    tls13_286_loader_entry_table + 0
tls13_286_loader_entry_decode        equ \
    tls13_286_loader_entry_table + 2
tls13_286_loader_entry_call          equ \
    tls13_286_loader_entry_table + 4
tls13_286_loader_entry_decode_block  equ \
    tls13_286_loader_entry_table + 6
tls13_286_loader_entries             equ 4
