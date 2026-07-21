; Build 13 external leaf cache: RSA verify working storage.
;
; The host leaf is no longer baked into SEED.SYS. Standard images ship
; SEED/LEAF.DER instead; every 286+ connect verifies that DER against the baked
; WR1 anchor before adopting the leaf key into this workspace. If the file is
; missing or stale, the first handshake fails fast, captures the presented leaf,
; verifies it against WR1 off-race, then retries with the adopted key.
;
; This storage is emitted as zeroed module data so every module load resets the
; whole RSA workspace. It contains no host-specific trust material; it is only
; filled after SEED/LEAF.DER or a live recertified leaf verifies against WR1.

align 2
rsa_key_ready: db 0
align 2

rsa_n:      times 128 dw 0
rsa_r2:     times 128 dw 0
rsa_one:    times 128 dw 0
rsa_n0inv:  dw 0
rsa_sig:    times 128 dw 0
rsa_result: times 128 dw 0
rsa_x:      times 128 dw 0
rsa_t:      times 260 dw 0
