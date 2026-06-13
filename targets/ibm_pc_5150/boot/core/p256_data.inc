; Build 12 286 secure tier: P-256 ECDHE module data block.
;
; Derived from tools/crypto-bench/p256_data_bench.inc (the bench-verified, ck=D51E data layout for
; the combined Karatsuba/Solinas/wNAF variant in core/p256.inc), with three runtime differences:
;   - p256_client_private is ZEROED (the runtime seeds it from a SHA-256 entropy pool; the bench
;     baked PEER_PRIVATE here).  LANDMINE #3: it must never stay 1 or 2 -- a SHA-256 output never is.
;   - tls_server_ec_x/y_words are ZEROED (the SKE parser fills them with the real server point; the
;     bench baked the generator G here as the test point).
;   - p256_generator_x/y (G in LE words), p256_client_public_uncompressed and the p256_cpub_* affine
;     scratch are ADDED for the client ephemeral keypair (client_private x G), which the bench did
;     not need (it measured one scalar mult of a baked point).
;
; The reduce-coeff table / p256_mul_acc* / p256_i/j / p256_scalar_word_* from the bench data are
; OMITTED: the combined variant is Solinas-unrolled + Comba and references none of them (verified by
; grep against core/p256.inc). This whole block lives INSIDE the 286-only module at p256_module_load
; (0x4400+), so NO P-256 scratch aliases low_crypto_work(0x0700) or the NIC RX buffer (0x36c2)
; -- LANDMINE #4 is satisfied by construction (the module is entirely above the critical scratch).

align 2
p256_prime: dw 65535,65535,65535,65535,65535,65535,0,0,0,0,0,0,1,0,65535,65535
p256_three: dw 3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
p256_jac_x: times 16 dw 0
p256_jac_y: times 16 dw 0
p256_jac_z: times 16 dw 0
p256_s0: times 16 dw 0
p256_s1: times 16 dw 0
p256_s2: times 16 dw 0
p256_s3: times 16 dw 0
p256_s4: times 16 dw 0
p256_s5: times 16 dw 0
p256_s6: times 16 dw 0
p256_s7: times 16 dw 0
p256_s8: times 16 dw 0
; Runtime-seeded per session from the SHA-256 entropy pool (NOT 1 or 2 -- LANDMINE #3).
p256_client_private: times 16 dw 0
; Runtime-filled from the ServerKeyExchange public point.
tls_server_ec_x_words: times 16 dw 0
tls_server_ec_y_words: times 16 dw 0
tls_shared_x_words: times 16 dw 0
p256_product: times 36 dw 0
p256_carry: db 0
p256_left_ptr: dw 0
p256_right_ptr: dw 0
p256_result_ptr: dw 0
p256_inv_output_ptr: dw 0
p256_affine_x_ptr: dw 0
p256_affine_y_ptr: dw 0
p256_scalar_ptr: dw 0

; --- runtime additions (not in the bench data) ---
; The P-256 base point G in little-endian 16-bit words (verified == NIST P-256 G by tools/check-p256.py
; cross-check; these are the exact LE words the bench baked as its test point). The client ephemeral
; public key is client_private x G.
p256_generator_x: dw 49814,55448,14661,62625,13216,11755,32129,30467,16626,25508,59109,63676,16967,57644,53746,27415
p256_generator_y: dw 20981,14271,16488,52150,24270,27441,13143,11214,40470,31759,60234,36583,32667,65050,17122,20451
; The encoded client ephemeral public key (0x04 || X_be32 || Y_be32) sent in the ClientKeyExchange.
p256_client_public_uncompressed: times tls_ec_public_uncompressed_len db 0
; Affine x/y scratch for the client public point (kept distinct from p256_s* so a future caller that
; reuses s* between the keypair gen and the premaster compute cannot clobber the encoded public key).
p256_cpub_x_words: times 16 dw 0
p256_cpub_y_words: times 16 dw 0
