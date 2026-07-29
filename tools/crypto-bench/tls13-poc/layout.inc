; Product-shaped 16 KiB address contract for the Build 13 TLS 1.3 PoC.
;
; This file deliberately mirrors the shipped PC/16 layout instead of granting
; the benchmark a private flat arena.  The resident nucleus, selected Build 13
; NIC driver, reconnect state, ESC hook, 96-byte executable arena, 96-byte
; context window, and stack keep their shipping addresses.

bits 16
cpu 8086

poc_low_scratch_start       equ 0x0700
poc_low_scratch_end         equ 0x1000
poc_resident_start          equ 0x1000
poc_nic_driver_slot         equ 0x1600
poc_k_start                 equ 0x1800
%ifdef TLS13_POC_K14
%define poc_k_end 0x3400
%else
poc_k_end                   equ 0x3600
%endif
poc_k_len                   equ poc_k_end - poc_k_start

; K14 is an opt-in PoC migration.  It deliberately leaves all existing high
; security/reconnect/arena/context addresses unchanged.  The physical
; 0x3400..0x3600 band is therefore a persistent executable-arena extension,
; not contiguous product arena/context space.
poc_k_extension_start       equ 0x3400
poc_k_extension_end         equ 0x3600
poc_k_extension_len         equ poc_k_extension_end - poc_k_extension_start
; Shared K14 extension contract. The symmetric phase uses only this upper
; subrange for mutable work. Once its network/parser controller has retired,
; the lower subrange can carry authentication input without moving the ticket.
poc_k_extension_sym_work_start equ 0x3510
poc_k_extension_sym_work_end   equ 0x355d

poc_high_start              equ 0x3600
poc_high_end                equ 0x3b9c
poc_attempt_cache_start     equ 0x3b9c
poc_attempt_cache_end       equ 0x3c9c
poc_reconnect_state_start   equ 0x3c9c
poc_esc_handler_start       equ 0x3de6
poc_product_pool_start      equ 0x3e40
poc_arena_start             equ 0x3e40
poc_context_start           equ 0x3ea0
poc_stack_guard_start       equ 0x3f00
poc_ram_end                 equ 0x4000

; The timed image must leave the last two logical K sectors free.  The
; provisional candidate uses one decoded polynomial and one running
; accumulator there.  K14 lowers the pair by exactly one sector.
poc_timed_code_start        equ poc_k_start
%ifdef TLS13_POC_K14
%define poc_timed_code_end_max 0x3000
%define poc_poly_u 0x3000
%define poc_poly_acc 0x3200
%else
poc_timed_code_end_max      equ 0x3200
poc_poly_u                  equ 0x3200
poc_poly_acc                equ 0x3400
%endif
poc_poly_bytes              equ 512

; With the advertised 384-byte MSS, a complete Ethernet+IPv4+TCP frame occupies
; 438 bytes at 0x0700..0x08b6.  Public KeyGen output or the raw ServerHello
; ciphertext can therefore start at 0x08c0 without touching the receive frame.
poc_rx_frame_start          equ 0x0700
poc_rx_frame_max_len        equ 14 + 20 + 20 + 384
poc_rx_frame_end            equ poc_rx_frame_start + poc_rx_frame_max_len
poc_low_object_start        equ 0x08c0
poc_mlkem_ek                equ poc_low_object_start
poc_mlkem_ek_len            equ 1184
poc_mlkem_ek_end            equ poc_mlkem_ek + poc_mlkem_ek_len
poc_mlkem_ciphertext        equ poc_low_object_start
poc_mlkem_ciphertext_len    equ 1088
poc_mlkem_ciphertext_end    equ poc_mlkem_ciphertext + poc_mlkem_ciphertext_len
; HELLO finishes exactly where raw c ends.  Before the ML-KEM candidate reuses
; 0x3b9c for G(m'||H(ek)), publish both the fixed-u server share and a live
; resumable SHA-256 transcript into this candidate-preserved low handoff.
; The symmetric overlay imports the context before reusing 0x0d00..0x1000.
poc_hello_handoff_start     equ poc_mlkem_ciphertext_end
poc_hello_server_x          equ poc_hello_handoff_start
poc_hello_digest            equ poc_hello_server_x + 32
poc_hello_ctx_magic         equ poc_hello_digest + 32
poc_hello_ctx_version       equ poc_hello_ctx_magic + 4
poc_hello_sha_block_len     equ poc_hello_ctx_version + 1
poc_hello_sha_len_low       equ poc_hello_sha_block_len + 1
poc_hello_sha_len_high      equ poc_hello_sha_len_low + 2
poc_hello_sha_state         equ poc_hello_sha_len_high + 2
poc_hello_sha_block         equ poc_hello_sha_state + 32
poc_hello_status            equ poc_hello_sha_block + 64
poc_hello_handoff_end       equ poc_hello_status + 1
; On resumption the public ticket identity is loaded into the first K work
; sector after the timed image is resident.  It is consumed by ClientHello
; before that sector becomes the decoded-u polynomial.  Keeping it out of low
; scratch avoids the shipped SHA-256 block/W schedule at 0x0d8e+.
poc_ticket_identity         equ poc_poly_u
poc_ticket_identity_max     equ 192
poc_ticket_identity_end     equ poc_ticket_identity + poc_ticket_identity_max

; KeyGen writes the compressed K-PKE secret vector around H(ek) and z.  The
; candidate consumes components in reverse order and expands each one in place:
; sHat2, then sHat1, then sHat0.  Its 512-byte expansion never crosses 0x3b9c.
poc_s_hat0                  equ 0x3600
poc_s_hat0_len              equ 384
poc_h_ek                    equ poc_s_hat0 + poc_s_hat0_len
poc_h_ek_len                equ 32
poc_z                       equ poc_h_ek + poc_h_ek_len
poc_z_len                   equ 32
poc_s_hat1                  equ 0x3800
poc_s_hat1_len              equ 384
poc_s_hat2                  equ 0x3980
poc_s_hat2_len              equ 384
poc_s_hat2_expanded_end     equ poc_s_hat2 + poc_poly_bytes

; Before sHat0 is expanded over H(ek)/z, copy the two values here.  Once G is
; computed, the same cache becomes G[64] || z[32].  The model/API-key cache is
; intentionally not populated until authentication commits.
poc_candidate_cache         equ poc_attempt_cache_start
poc_candidate_g             equ poc_candidate_cache
poc_candidate_g_len         equ 64
poc_candidate_z             equ poc_candidate_g + poc_candidate_g_len
poc_candidate_cache_end     equ poc_candidate_z + 32

; After the provisional candidate, dkPKE is dead.  Preserve the public server
; ciphertext here while the low receive frame handles the protected flight.
poc_fo_ciphertext           equ poc_high_start
poc_fo_ciphertext_len       equ poc_mlkem_ciphertext_len
poc_fo_ciphertext_end       equ poc_fo_ciphertext + poc_fo_ciphertext_len
poc_tls_vault_start         equ poc_fo_ciphertext_end
poc_tls_vault_end           equ poc_high_end

%ifdef TLS13_POC_K14
%if poc_k_len != 14 * 512
%error "TLS13 PoC K14 contract must be exactly 14 sectors"
%endif
%if poc_k_extension_len != 512
%error "TLS13 PoC K14 persistent executable extension must be 512 bytes"
%endif
%else
%if poc_k_len != 15 * 512
%error "TLS13 PoC default K contract must remain exactly 15 sectors"
%endif
%endif
%if poc_timed_code_end_max + (2 * poc_poly_bytes) != poc_k_end
%error "TLS13 PoC timed code/work split is not a complete K partition"
%endif
%if poc_rx_frame_end > poc_low_object_start
%error "TLS13 PoC receive frame overlaps the low public object"
%endif
%if poc_hello_handoff_end > poc_low_scratch_end
%error "TLS13 PoC hello transcript handoff exceeds low scratch"
%endif
%if poc_ticket_identity_end > (poc_poly_u + poc_poly_bytes)
%error "TLS13 PoC ticket identity exceeds its pre-candidate work sector"
%endif
%if poc_s_hat2_expanded_end > poc_high_end
%error "TLS13 PoC reverse in-place sHat expansion reaches deferred state"
%endif
%if poc_candidate_cache_end > poc_attempt_cache_end
%error "TLS13 PoC candidate cache reaches reconnect state"
%endif
%if poc_product_pool_start != 0x3e40 || poc_stack_guard_start != 0x3f00
%error "TLS13 PoC must not move the 16 KiB arena/context/stack contract"
%endif
%if poc_high_start != poc_k_extension_end
%error "TLS13 PoC high security band must remain above the K14 extension"
%endif
