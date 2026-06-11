; generated: P-256 data block + baked ECDHE inputs (scalar=PEER_PRIVATE, point=G)

; ---- P-256 benchmark data segment (layout defined by the harness) ----
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
p256_client_private: dw 55256,47400,11264,11341,55823,30581,40783,24995,30829,21433,15164,3647,39709,7858,50679,32125
tls_server_ec_x_words: dw 49814,55448,14661,62625,13216,11755,32129,30467,16626,25508,59109,63676,16967,57644,53746,27415
tls_server_ec_y_words: dw 20981,14271,16488,52150,24270,27441,13143,11214,40470,31759,60234,36583,32667,65050,17122,20451
tls_shared_x_words: times 16 dw 0
p256_product: times 36 dw 0
p256_reduce_acc: times 18 dd 0
p256_reduce_coeffs:
    db 1,0,0,0,0,0,255,0,0,0,0,0,255,0,1,0
    db 0,1,0,0,0,0,0,255,0,0,0,0,0,255,0,1
    db 1,0,1,0,0,0,255,0,255,0,0,0,255,0,0,0
    db 0,1,0,1,0,0,0,255,0,255,0,0,0,255,0,0
    db 0,0,1,0,1,0,0,0,255,0,255,0,0,0,255,0
    db 0,0,0,1,0,1,0,0,0,255,0,255,0,0,0,255
    db 255,0,0,0,1,0,2,0,0,0,255,0,0,0,255,0
    db 0,255,0,0,0,1,0,2,0,0,0,255,0,0,0,255
    db 255,0,255,0,0,0,2,0,2,0,0,0,0,0,255,0
    db 0,255,0,255,0,0,0,2,0,2,0,0,0,0,0,255
    db 255,0,255,0,255,0,1,0,2,0,2,0,1,0,255,0
    db 0,255,0,255,0,255,0,1,0,2,0,2,0,1,0,255
    db 255,0,255,0,255,0,0,0,1,0,2,0,3,0,0,0
    db 0,255,0,255,0,255,0,0,0,1,0,2,0,3,0,0
    db 0,0,255,0,255,0,255,0,0,0,1,0,2,0,3,0
    db 0,0,0,255,0,255,0,255,0,0,0,1,0,2,0,3
p256_mul_acc0: dw 0
p256_mul_acc1: dw 0
p256_mul_acc2: dw 0
p256_mul_left_word: dw 0
p256_reduce_carry: dw 0
p256_i: db 0
p256_j: db 0
p256_carry: db 0
p256_left_ptr: dw 0
p256_right_ptr: dw 0
p256_result_ptr: dw 0
p256_inv_output_ptr: dw 0
p256_affine_x_ptr: dw 0
p256_affine_y_ptr: dw 0
p256_scalar_ptr: dw 0
p256_scalar_word_ptr: dw 0
p256_scalar_word_value: dw 0
p256_scalar_mask: dw 0
p256_scalar_word_count: db 0
