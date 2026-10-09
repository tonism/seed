sha256_state equ 0x3100
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
sha256_block_len equ hmac_output_ptr+2
sha256_saved_block_len equ sha256_block_len+1
sha256_schedule_count equ sha256_saved_block_len+1
sha256_round_count equ sha256_schedule_count+1
%if sha256_round_count>=0x3200
%error "SHA scalars reach block"
%endif
sha256_block equ 0x3200
sha256_w equ 0x3240
sha256_saved_state equ 0x3340
sha256_saved_block equ 0x3360
hmac_ipad equ 0x33a0
hmac_opad equ 0x33e0
hmac_inner_digest equ 0x3420
hmac_prepared_inner_state equ 0x3440
hmac_prepared_outer_state equ 0x3460
sha256_digest_len equ 32
sha256_block_size equ 64
sha256_k_len equ 256
