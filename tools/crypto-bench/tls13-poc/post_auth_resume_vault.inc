; Canonical card-RAM vault shared by the same-boot TLS 1.3 resumption workers.
;
; Card pages 0x73 and 0x7f hold one exact 400-byte copy of the committed
; issuer/ticket/ROG3 bundle.  Page 0x7f also carries the attempt random,
; session id, a SHA-256 binding, and a status byte written last by ascending
; NE2000 remote DMA.  Public ek, private KeyGen state, c, and the duplicated
; candidate have separate lifetime-overlaid card bands.

resume_card_vault_head         equ 0x7300
resume_card_ek                 equ 0x7400
resume_card_ek_len             equ 1184
resume_card_private            equ 0x7900
resume_card_private_len        equ 0x0500
resume_card_c                  equ 0x7900
resume_card_c_len              equ 1088
resume_card_candidate_a        equ 0x7e00
resume_card_candidate_b        equ 0x7e80
resume_card_candidate_len      equ 128
resume_card_vault_tail         equ 0x7f00

; Between PREPARE's independent binder verification and candidate
; publication, page 0x7e carries the early "derived" secret across the cached
; connector's destructive high-memory scratch.  Two copies plus generation
; and status-last metadata make partial/stale DMA fail closed.  Candidate
; atomically retires this object by replacing both 128-byte halves.
resume_early_copy_a            equ 0x00
resume_early_head_a            equ 0x20
resume_early_head_len          equ 72
resume_early_eoed              equ 0x68
resume_early_eoed_len          equ 26
resume_early_copy_b            equ 0x82
resume_early_head_b            equ 0xa2
resume_early_magic             equ 0xf6
resume_early_generation        equ 0xfa
resume_early_inverse_generation equ 0xfc
resume_early_inverse_status    equ 0xfe
resume_early_status            equ 0xff
resume_early_magic_word0       equ 0x5352  ; "RS"
resume_early_magic_word1       equ 0x3145  ; "E1"
resume_early_status_valid      equ 0xa5
resume_early_status_valid_inverse equ 0x5a

resume_vault_issuer_len        equ 114
resume_vault_psk_len           equ 32
resume_vault_identity_len      equ 192
resume_vault_ticket_tail_len   equ 45
resume_vault_control_len       equ 16

resume_vault_head_issuer       equ 0x00
resume_vault_head_psk          equ \
    resume_vault_head_issuer + resume_vault_issuer_len
resume_vault_head_identity     equ \
    resume_vault_head_psk + resume_vault_psk_len
resume_vault_head_identity_len equ \
    0x100 - resume_vault_head_identity

resume_vault_tail_identity     equ 0x00
resume_vault_tail_identity_len equ \
    resume_vault_identity_len - resume_vault_head_identity_len
resume_vault_tail_ticket       equ \
    resume_vault_tail_identity + resume_vault_tail_identity_len
resume_vault_tail_control      equ \
    resume_vault_tail_ticket + resume_vault_ticket_tail_len
resume_vault_tail_zero         equ \
    resume_vault_tail_control + resume_vault_control_len
resume_vault_canonical_end     equ resume_vault_tail_zero + 1

resume_vault_meta_magic        equ 0x90
resume_vault_meta_inverse      equ 0x94
resume_vault_meta_generation   equ 0x98
resume_vault_meta_digest       equ 0x9a
resume_vault_meta_random       equ 0xba
resume_vault_meta_session      equ 0xda
resume_vault_meta_pad          equ 0xfa
resume_vault_meta_inverse_status equ 0xfe
resume_vault_meta_status       equ 0xff

resume_vault_magic_word0       equ 0x5652  ; "RV"
resume_vault_magic_word1       equ 0x314c  ; "L1"
resume_vault_inverse_word0     equ 0xa9ad
resume_vault_inverse_word1     equ 0xceb3
resume_vault_status_valid      equ 0xa5
resume_vault_status_valid_inverse equ 0x5a

resume_vault_lifecycle_valid   equ 0xa5
resume_vault_lifecycle_valid_inverse equ 0x5a
resume_vault_lifecycle_restored equ 0xc3
resume_vault_lifecycle_restored_inverse equ 0x3c

; Before PREPARE reclaims page 0x73 for the canonical vault head, the exact
; authenticated fresh HEAD+NST record boundary publishes this one-page native
; ticket receipt.  The digest is
;
;   SHA256("NTR1" || tick_lo || tick_hi || day ||
;          PSK[32] || identity[192] || ticket_tail[45])
;
; where all words are the native little-endian RAM representation.  The first
; complete DMA image has zero inverse/status and is read back exactly.  The
; second complete image has 0x5a/0xa5 at 0xfe/0xff, so ascending remote DMA
; writes the valid status physically last, and is also read back exactly.
resume_receipt_magic          equ 0x00
resume_receipt_magic_len      equ 4
resume_receipt_inverse        equ 0x04
resume_receipt_inverse_len    equ 4
resume_receipt_tick_lo        equ 0x08
resume_receipt_tick_hi        equ 0x0a
resume_receipt_day            equ 0x0c
resume_receipt_digest         equ 0x0e
resume_receipt_digest_len     equ 32
resume_receipt_zero_start     equ 0x2e
resume_receipt_inverse_status equ 0xfe
resume_receipt_status         equ 0xff
resume_receipt_magic_word0    equ 0x544e
resume_receipt_magic_word1    equ 0x3152
resume_receipt_inverse_word0  equ 0xabb1
resume_receipt_inverse_word1  equ 0xcead
resume_receipt_status_valid   equ 0xa5
resume_receipt_status_valid_inverse equ 0x5a

; PREPARE's host-only lifecycle binding.  This lies immediately after RSU1's
; receipt/attempt/FO state and below reconnect state.  NONE and WRITING are
; deliberately indistinguishable (00/00): neither is importable.  VALID is
; changed status-last to RESTORED before any card scrub, preventing a failed
; cleanup path from importing a partly erased vault twice.
resume_vault_lifecycle_digest equ 0x3c76
resume_vault_lifecycle_generation equ 0x3c96
resume_vault_lifecycle_inverse equ 0x3c98
resume_vault_lifecycle_status equ 0x3c99
resume_vault_lifecycle_end    equ 0x3c9a

; The exact RVL1 digest preimage is:
;   "SEED-RVL1" || generation_le16 ||
;   page73[0:256] || page7f[0:144] || random[32] || session[32]
resume_vault_digest_domain_len equ 9
resume_vault_digest_preimage_len equ \
    resume_vault_digest_domain_len + 2 + 0x100 + \
    resume_vault_canonical_end + 32 + 32

%if resume_vault_head_identity_len != 110
%error "resume vault head split drifted"
%endif
%if resume_vault_tail_identity_len != 82
%error "resume vault tail identity split drifted"
%endif
%if resume_vault_canonical_end != 0x90
%error "resume vault canonical payload is not exactly 400 bytes"
%endif
%if resume_vault_meta_digest + 32 != resume_vault_meta_random
%error "resume vault digest/random packing drifted"
%endif
%if resume_vault_meta_random + 32 != resume_vault_meta_session
%error "resume vault random/session packing drifted"
%endif
%if resume_vault_meta_session + 32 != resume_vault_meta_pad
%error "resume vault session/pad packing drifted"
%endif
%if resume_receipt_digest + resume_receipt_digest_len != \
    resume_receipt_zero_start
%error "native ticket receipt digest/zero packing drifted"
%endif
%if resume_receipt_inverse_status + 1 != resume_receipt_status
%error "native ticket receipt status is not physically last"
%endif
%if resume_vault_lifecycle_end > 0x3c9c
%error "resume vault lifecycle reaches reconnect state"
%endif
%if resume_vault_digest_preimage_len != 475
%error "resume vault digest preimage is not exactly 475 bytes"
%endif
%if resume_early_copy_a + 32 > resume_early_copy_b
%error "early-derived copy A overlaps copy B"
%endif
%if resume_early_copy_a + 32 > resume_early_head_a
%error "early-derived copy A overlaps early HEAD A"
%endif
%if resume_early_head_a + resume_early_head_len > resume_early_copy_b
%error "early HEAD A overlaps early EOED"
%endif
%if resume_early_head_a + resume_early_head_len > resume_early_eoed
%error "early HEAD A overlaps early EOED"
%endif
%if resume_early_eoed + resume_early_eoed_len > resume_early_copy_b
%error "early EOED overlaps early-derived copy B"
%endif
%if resume_early_copy_b + 32 > resume_early_magic
%error "early-derived copy B overlaps metadata"
%endif
%if resume_early_copy_b + 32 > resume_early_head_b
%error "early-derived copy B overlaps early HEAD B"
%endif
%if resume_early_head_b + resume_early_head_len > resume_early_magic
%error "early HEAD B overlaps metadata"
%endif
%if resume_early_inverse_status + 1 != resume_early_status
%error "early-derived status is not physically last"
%endif
