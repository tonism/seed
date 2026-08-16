; TLS 1.3 286 target-local entropy, health-test, and HMAC_DRBG controller.
;
; The production entry is reached through the authenticated root component
; loader at 0000:1800.  It records 1024 raw six-byte timing events by sampling
; the PC/AT RTC's independent 32.768 kHz oscillator against PIT channel 0,
; applies online RCT/APT health tests, invokes the product SHA3-256 conditioner
; module, runs a NIST CAVP HMAC_DRBG KAT, and publishes two independent
; 160-byte attempt bundles status-last.  Register C's periodic flag is polled
; with PIE disabled, so collection is silent and does not disturb the PIC or
; perform any floppy operation.
;
; The RCT/APT cutoffs are deliberately provisional mechanics gates.  They do
; not confer entropy credit until the physical source has been characterized
; under SP 800-90B on representative machines.

bits 16
cpu 8086
org 0x1800

%include "tls13/tls13_286_abi.inc"
%include "build/ibm_pc_5150/tls13-286-product-abi.inc"

sha256_digest_len equ 32
sha256_block_size equ 64
sha256_k_len equ 256

entropy_rct_cutoff        equ 64
entropy_apt_window        equ 512
entropy_apt_cutoff        equ 400
entropy_cmos_index        equ 0x70
entropy_cmos_data         equ 0x71
entropy_cmos_status_a     equ 0x0a
entropy_cmos_status_b     equ 0x0b
entropy_cmos_status_c     equ 0x0c
entropy_cmos_divider_mask equ 0x70
entropy_cmos_32khz        equ 0x20
entropy_cmos_rate_4096hz  equ 0x04
entropy_cmos_periodic     equ 0x40
entropy_cmos_pie          equ 0x40
entropy_cmos_poll_limit   equ 4096

entropy_header:
    db 'S286ENT2'
    dw tls13_286_abi_version
    dw entropy_image_end - entropy_header
    dw tls13_286_entropy_entries
entropy_entry_table:
    dw entropy_main
    dw entropy_health_reset
    dw entropy_health_inject
    dw entropy_drbg_kat
    dw entropy_abort_bootstrap

; Root handoff:
;   AL=entry mode, BX=crypto segment, SI=frozen footer,
;   DS=ES=SS=0, DF=0.
entropy_main:
    cld
    mov [cs:entropy_mode], al
    cmp al, 1
    ja entropy_abort_bootstrap
    cmp si, tls13_286_tail_footer_off
    jne entropy_abort_bootstrap
    cmp bx, [cs:tls13_286_root_state_crypto_seg]
    jne entropy_abort_bootstrap
    mov [cs:entropy_crypto_seg], bx
    cmp word [cs:tls13_286_root_state_loader + \
        tls13_286_state_pack_bytes], tls13_286_pack_header_bytes
    jb entropy_abort_bootstrap
    call entropy_publish_parent_stack
    jc entropy_abort_bootstrap

    ; A root or either attempt may be published only once per bootstrap.
    mov es, bx
    cmp byte [es:tls13_286_entropy_root_status_inv_off], 0
    jne entropy_abort
    cmp byte [es:tls13_286_entropy_root_status_off], 0
    jne entropy_abort
    cmp byte [es:tls13_286_attempt_acquire_status_inv_off], 0
    jne entropy_abort
    cmp byte [es:tls13_286_attempt_acquire_status_off], 0
    jne entropy_abort
    cmp byte [es:tls13_286_attempt_fresh_status_inv_off], 0
    jne entropy_abort
    cmp byte [es:tls13_286_attempt_fresh_status_off], 0
    jne entropy_abort

    call entropy_drbg_kat
    jc entropy_abort
    call entropy_collect
    jc entropy_abort
    call entropy_condition
    jc entropy_abort
    call entropy_copy_conditioned
    call entropy_hash_conditioned
    call entropy_reject_generation_reuse
    jc entropy_abort

    mov si, entropy_conditioned
    mov cx, tls13_286_entropy_seed_bytes
    call entropy_drbg_instantiate
    jc entropy_abort
    mov di, entropy_drbg_output
    mov cx, tls13_286_attempt_bundle_bytes
    call entropy_drbg_generate
    jc entropy_abort
    mov si, entropy_drbg_output
    mov di, tls13_286_attempt_acquire_off
    call entropy_copy_160_high

    mov di, entropy_drbg_output
    mov cx, tls13_286_attempt_bundle_bytes
    call entropy_drbg_generate
    jc entropy_abort
    mov si, entropy_drbg_output
    mov di, tls13_286_attempt_fresh_off
    call entropy_copy_160_high

    call entropy_compare_attempts
    jc entropy_abort
    call entropy_hash_generation
    call entropy_publish_generation

    ; Status-last publication.  Consumers must verify each inverse/status
    ; pair and transition exactly one attempt from READY to USED before copy.
    mov es, [cs:entropy_crypto_seg]
    mov byte [es:tls13_286_attempt_acquire_status_inv_off], \
        tls13_286_entropy_status_ready_inv
    mov byte [es:tls13_286_attempt_acquire_status_off], \
        tls13_286_entropy_status_ready
    mov byte [es:tls13_286_attempt_fresh_status_inv_off], \
        tls13_286_entropy_status_ready_inv
    mov byte [es:tls13_286_attempt_fresh_status_off], \
        tls13_286_entropy_status_ready
    mov byte [es:tls13_286_entropy_root_status_inv_off], \
        tls13_286_entropy_status_ready_inv
    mov byte [es:tls13_286_entropy_root_status_off], \
        tls13_286_entropy_status_ready

    call entropy_scrub_success

    ; The acquisition ClientHello is the next authenticated product-tail
    ; component.  Do not return to a caller that can accidentally omit the
    ; first fresh connection after publishing the one-shot attempt.  The root
    ; loader resolves the exact footer entry, validates/decompresses it, and
    ; transfers directly to its authenticated entry without returning through
    ; controller bytes that have just been overwritten.
    mov ax, tls13_286_tail_kind_acquire
    jmp word [cs:tls13_286_root_service_chain]

; Collect 1024 events:
;   PIT count before RTC periodic edge, PIT count after edge, sample index.
; The IBM AT BIOS initializes the MC146818-compatible divider for its independent
; 32.768 kHz crystal.  Temporarily select its 4096 Hz tap (about 250 ms total),
; poll PF without enabling IRQ8, and restore Status A on every exit.  The PIT
; and RTC clocks are the physical-source boundary; 86Box receives zero credit.
entropy_collect:
    call entropy_health_reset
    mov word [cs:entropy_sample_index], 0
    call entropy_rtc_begin
    jc .source_bad
    mov es, [cs:entropy_crypto_seg]
    mov di, tls13_286_entropy_raw_off
    mov cx, tls13_286_entropy_samples
.sample:
    push cx
    call entropy_read_pit
    mov [cs:entropy_pit_before], ax
    call entropy_wait_periodic
    jc .source_bad_pop
    call entropy_read_pit
    mov [cs:entropy_pit_after], ax
    mov ax, [cs:entropy_pit_before]
    stosw
    mov ax, [cs:entropy_pit_after]
    stosw
    mov ax, [cs:entropy_sample_index]
    stosw
    mov ax, [cs:entropy_pit_before]
    sub ax, [cs:entropy_pit_after]
    xor al, ah
    call entropy_health_inject
    jc .health_bad
    inc word [cs:entropy_sample_index]
    pop cx
    loop .sample
    call entropy_rtc_end
    call entropy_publish_health
    clc
    ret
.health_bad:
.source_bad_pop:
    pop cx
.source_bad:
    call entropy_rtc_end
    stc
    ret

entropy_read_pit:
    xor al, al
    out 0x43, al
    in al, 0x40
    mov ah, al
    in al, 0x40
    xchg al, ah
    ret

; Bind the expected 32.768 kHz divider, save the complete writable Status A
; value, switch only its rate-select nibble, then drain any old PF.  Port 70h
; bit 7 stays clear so NMI remains enabled throughout collection.
entropy_rtc_begin:
    mov byte [cs:entropy_rtc_active], 0
    mov al, entropy_cmos_status_a
    out entropy_cmos_index, al
    in al, entropy_cmos_data
    and al, 0x7f                    ; UIP is read-only
    mov [cs:entropy_rtc_status_a], al
    mov ah, al
    and ah, entropy_cmos_divider_mask
    cmp ah, entropy_cmos_32khz
    jne .bad
    mov ah, al
    mov al, entropy_cmos_status_b
    out entropy_cmos_index, al
    in al, entropy_cmos_data
    test al, entropy_cmos_pie
    jnz .bad
    mov al, ah
    and al, entropy_cmos_divider_mask
    or al, entropy_cmos_rate_4096hz
    mov ah, al
    mov al, entropy_cmos_status_a
    out entropy_cmos_index, al
    mov al, ah
    out entropy_cmos_data, al
    mov byte [cs:entropy_rtc_active], 1
    mov al, entropy_cmos_status_c
    out entropy_cmos_index, al
    in al, entropy_cmos_data        ; clear stale PF/AF/UF
    clc
    ret
.bad:
    stc
    ret

; Polling Register C does not enable RTC interrupts: MC146818 PF advances
; independently of PIE.  A bounded wait turns a missing/stuck oscillator into
; a fail-closed source error instead of an invisible hang.
entropy_wait_periodic:
    mov dx, entropy_cmos_poll_limit
.wait:
    mov al, entropy_cmos_status_c
    out entropy_cmos_index, al
    in al, entropy_cmos_data
    test al, entropy_cmos_periodic
    jnz .ready
    dec dx
    jnz .wait
    stc
    ret
.ready:
    clc
    ret

entropy_rtc_end:
    cmp byte [cs:entropy_rtc_active], 0
    je .done
    mov al, entropy_cmos_status_a
    out entropy_cmos_index, al
    mov al, [cs:entropy_rtc_status_a]
    out entropy_cmos_data, al
    mov byte [cs:entropy_rtc_active], 0
.done:
    ret

; Injectable nonbinary online health state machine.
; Entry: AL=symbol.  Failure occurs when the RCT run reaches 64 or when more
; the reference-symbol count reaches 400 in a non-overlapping 512-symbol APT.
entropy_health_reset:
    cld
    mov byte [cs:entropy_health_seen], 0
    mov byte [cs:entropy_health_failed], 0
    mov byte [cs:entropy_health_last], 0
    mov byte [cs:entropy_health_run], 0
    mov byte [cs:entropy_health_ref], 0
    mov word [cs:entropy_health_apt_pos], 0
    mov word [cs:entropy_health_apt_matches], 0
    mov word [cs:entropy_health_total], 0
    xor ax, ax
    clc
    ret

entropy_health_inject:
    cld
    cmp byte [cs:entropy_health_failed], 0
    jne .bad
    inc word [cs:entropy_health_total]
    cmp byte [cs:entropy_health_seen], 0
    jne .rct
    mov byte [cs:entropy_health_seen], 1
    mov [cs:entropy_health_last], al
    mov byte [cs:entropy_health_run], 1
    jmp short .apt
.rct:
    cmp al, [cs:entropy_health_last]
    jne .rct_new
    inc byte [cs:entropy_health_run]
    cmp byte [cs:entropy_health_run], entropy_rct_cutoff
    jae .fail
    jmp short .apt
.rct_new:
    mov [cs:entropy_health_last], al
    mov byte [cs:entropy_health_run], 1
.apt:
    cmp word [cs:entropy_health_apt_pos], 0
    jne .apt_count
    mov [cs:entropy_health_ref], al
    mov word [cs:entropy_health_apt_matches], 1
    mov word [cs:entropy_health_apt_pos], 1
    jmp short .ok
.apt_count:
    cmp al, [cs:entropy_health_ref]
    jne .apt_advance
    inc word [cs:entropy_health_apt_matches]
.apt_advance:
    inc word [cs:entropy_health_apt_pos]
    cmp word [cs:entropy_health_apt_pos], entropy_apt_window
    jne .ok
    cmp word [cs:entropy_health_apt_matches], entropy_apt_cutoff
    jae .fail
    mov word [cs:entropy_health_apt_pos], 0
    mov word [cs:entropy_health_apt_matches], 0
.ok:
    xor ax, ax
    clc
    ret
.fail:
    mov byte [cs:entropy_health_failed], 1
.bad:
    mov ax, tls13_286_error_crypto
    stc
    ret

entropy_publish_health:
    mov es, [cs:entropy_crypto_seg]
    mov di, tls13_286_entropy_health_off
    mov si, entropy_health_magic
    mov cx, 8
    rep movsb
    mov ax, [cs:entropy_health_total]
    stosw
    mov ax, entropy_rct_cutoff
    stosw
    mov ax, entropy_apt_window
    stosw
    mov ax, entropy_apt_cutoff
    stosw
    xor ax, ax
    mov al, [cs:entropy_health_last]
    stosw
    xor ax, ax
    mov al, [cs:entropy_health_run]
    stosw
    mov ax, [cs:entropy_health_apt_matches]
    stosw
    mov ax, [cs:entropy_health_apt_pos]
    stosw
    mov al, [cs:entropy_health_failed]
    stosb
    xor al, al
    mov cx, tls13_286_entropy_health_bytes - 25
    rep stosb
    ret

; Authenticate and invoke the pack's ML-KEM keygen image as the SHA3
; conditioner.  The loader retires the decoded overlay after the call.
entropy_condition:
    mov word [cs:entropy_condition_desc + tls13_286_desc_op], \
        tls13_286_mod_op_sha3_256_condition
    mov word [cs:entropy_condition_desc + tls13_286_desc_flags], 0
    mov word [cs:entropy_condition_desc + tls13_286_desc_input0 + \
        tls13_286_span_off], tls13_286_entropy_raw_off & 15
    mov ax, [cs:entropy_crypto_seg]
    add ax, tls13_286_entropy_raw_off >> 4
    mov word [cs:entropy_condition_desc + tls13_286_desc_input0 + \
        tls13_286_span_seg], ax
    mov word [cs:entropy_condition_desc + tls13_286_desc_input0 + \
        tls13_286_span_len], tls13_286_entropy_raw_bytes
    mov word [cs:entropy_condition_desc + tls13_286_desc_input0 + \
        tls13_286_span_len + 2], 0
    mov word [cs:entropy_condition_desc + tls13_286_desc_output0 + \
        tls13_286_span_off], tls13_286_entropy_seed_off & 15
    mov ax, [cs:entropy_crypto_seg]
    add ax, tls13_286_entropy_seed_off >> 4
    mov word [cs:entropy_condition_desc + tls13_286_desc_output0 + \
        tls13_286_span_seg], ax
    mov word [cs:entropy_condition_desc + tls13_286_desc_output0 + \
        tls13_286_span_len], tls13_286_entropy_seed_bytes
    mov word [cs:entropy_condition_desc + tls13_286_desc_output0 + \
        tls13_286_span_len + 2], 0

    mov ax, tls13_286_mod_kind_mlkem_keygen
    mov bx, tls13_286_root_state_loader
    ; entropy_publish_health leaves ES naming the private reservation.  The
    ; fixed loader ABI requires DS=ES=0 even when no prior overlay needs wiping.
    xor dx, dx
    mov es, dx
    call word [cs:tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc .bad
    mov ax, tls13_286_mod_op_sha3_256_condition
    mov si, entropy_condition_desc
    xor di, di
    mov bx, tls13_286_root_state_loader
    call word [cs:tls13_286_loader_load + tls13_286_loader_entry_call]
    jc .bad
    ret
.bad:
    stc
    ret

entropy_copy_conditioned:
    push ds
    mov ds, [cs:entropy_crypto_seg]
    push cs
    pop es
    mov si, tls13_286_entropy_seed_off
    mov di, entropy_conditioned
    mov cx, tls13_286_entropy_seed_bytes
    rep movsb
    pop ds
    ret

entropy_hash_conditioned:
    call sha256_init
    mov si, entropy_conditioned
    mov cx, tls13_286_entropy_seed_bytes
    call sha256_update
    mov di, entropy_conditioned_hash
    call sha256_finish
    ret

entropy_reject_generation_reuse:
    mov es, [cs:entropy_crypto_seg]
    mov di, tls13_286_previous_entropy_hash_off
    mov cx, tls13_286_previous_entropy_hash_len
    xor ax, ax
    push di
    push cx
    repe scasb
    pop cx
    pop di
    je .unused
    mov si, entropy_conditioned_hash
    repe cmpsb
    je .bad
.unused:
    clc
    ret
.bad:
    mov ax, tls13_286_error_crypto
    stc
    ret

entropy_copy_160_high:
    push es
    mov es, [cs:entropy_crypto_seg]
    mov cx, tls13_286_attempt_bundle_bytes
    rep movsb
    pop es
    ret

entropy_compare_attempts:
    push ds
    push es
    mov ds, [cs:entropy_crypto_seg]
    mov es, [cs:entropy_crypto_seg]
    mov si, tls13_286_attempt_acquire_off
    mov di, tls13_286_attempt_fresh_off
    mov cx, tls13_286_attempt_bundle_bytes
    repe cmpsb
    pop es
    pop ds
    jne .different
    mov ax, tls13_286_error_crypto
    stc
    ret
.different:
    clc
    ret

; generation_hash = SHA-256(conditioned seed || acquisition || fresh).
entropy_hash_generation:
    call sha256_init
    mov si, entropy_conditioned
    mov cx, tls13_286_entropy_seed_bytes
    call sha256_update
    mov si, tls13_286_attempt_acquire_off
    mov cx, tls13_286_attempt_bundle_bytes * 2
.chunk:
    push cx
    mov ax, cx
    cmp ax, 32
    jbe .have
    mov ax, 32
.have:
    mov [cs:entropy_hash_chunk], ax
    mov es, [cs:entropy_crypto_seg]
    mov di, entropy_hash_buffer
    mov cx, ax
.copy:
    mov al, [es:si]
    mov [di], al
    inc si
    inc di
    loop .copy
    push si
    mov si, entropy_hash_buffer
    mov cx, [cs:entropy_hash_chunk]
    call sha256_update
    pop si
    pop cx
    sub cx, [cs:entropy_hash_chunk]
    jnz .chunk
    mov di, entropy_generation_hash
    call sha256_finish
    ret

entropy_publish_generation:
    mov es, [cs:entropy_crypto_seg]
    mov si, entropy_conditioned_hash
    mov di, tls13_286_previous_entropy_hash_off
    mov cx, tls13_286_previous_entropy_hash_len
    rep movsb
    mov si, entropy_generation_hash
    mov di, tls13_286_generation_hash_off
    mov cx, 32
    rep movsb
    ret

; SP 800-90A HMAC_DRBG(SHA-256), no prediction resistance.
; Instantiate entry: SI=seed material, CX=bytes.
entropy_drbg_instantiate:
    mov [cs:entropy_drbg_provided_ptr], si
    mov [cs:entropy_drbg_provided_len], cx
    push cs
    pop es
    mov di, entropy_drbg_k
    xor ax, ax
    mov cx, 32
    rep stosb
    mov di, entropy_drbg_v
    mov al, 1
    mov cx, 32
    rep stosb
    mov si, [cs:entropy_drbg_provided_ptr]
    mov cx, [cs:entropy_drbg_provided_len]
    call entropy_drbg_update
    ret

; SI=provided_data, CX=len.  With CX=0 this is Update(NULL).
entropy_drbg_update:
    mov [cs:entropy_drbg_provided_ptr], si
    mov [cs:entropy_drbg_provided_len], cx
    mov si, entropy_drbg_v
    mov di, entropy_drbg_input
    mov cx, 32
    rep movsb
    xor al, al
    stosb
    mov si, [cs:entropy_drbg_provided_ptr]
    mov cx, [cs:entropy_drbg_provided_len]
    rep movsb
    mov si, entropy_drbg_input
    mov cx, [cs:entropy_drbg_provided_len]
    add cx, 33
    mov di, entropy_drbg_k
    call entropy_hmac
    jc .bad
    mov si, entropy_drbg_v
    mov cx, 32
    mov di, entropy_drbg_v
    call entropy_hmac
    jc .bad
    cmp word [cs:entropy_drbg_provided_len], 0
    je .done
    mov si, entropy_drbg_v
    mov di, entropy_drbg_input
    mov cx, 32
    rep movsb
    mov al, 1
    stosb
    mov si, [cs:entropy_drbg_provided_ptr]
    mov cx, [cs:entropy_drbg_provided_len]
    rep movsb
    mov si, entropy_drbg_input
    mov cx, [cs:entropy_drbg_provided_len]
    add cx, 33
    mov di, entropy_drbg_k
    call entropy_hmac
    jc .bad
    mov si, entropy_drbg_v
    mov cx, 32
    mov di, entropy_drbg_v
    call entropy_hmac
    jc .bad
.done:
    clc
    ret
.bad:
    stc
    ret

; DI=near output, CX=requested bytes; current users request multiples of 32.
entropy_drbg_generate:
    push cs
    pop es
    test cx, 31
    jnz .bad
    mov [cs:entropy_drbg_output_ptr], di
    mov [cs:entropy_drbg_output_remaining], cx
.block:
    mov si, entropy_drbg_v
    mov cx, 32
    mov di, entropy_drbg_v
    call entropy_hmac
    jc .bad
    mov si, entropy_drbg_v
    mov di, [cs:entropy_drbg_output_ptr]
    mov cx, 32
    rep movsb
    mov [cs:entropy_drbg_output_ptr], di
    sub word [cs:entropy_drbg_output_remaining], 32
    jnz .block
    xor cx, cx
    xor si, si
    call entropy_drbg_update
    ret
.bad:
    mov ax, tls13_286_error_crypto
    stc
    ret

; HMAC(K, DS:SI[CX]) -> DS:DI[32].
entropy_hmac:
    mov [cs:hmac_key_ptr], word entropy_drbg_k
    mov [cs:hmac_key_len], word 32
    mov [cs:hmac_data1_ptr], si
    mov [cs:hmac_data1_len], cx
    mov [cs:hmac_data2_ptr], word 0
    mov [cs:hmac_data2_len], word 0
    mov [cs:hmac_output_ptr], di
    call hmac_prepare_current_key_context
    jc .bad
    call hmac_sha256_prepared
    ret
.bad:
    stc
    ret

; Mandatory target-side KAT.  This is NIST CAVP HMAC_DRBG SHA-256 no-reseed,
; COUNT=0.  The second 1024-bit Generate output is the published ReturnedBits.
entropy_drbg_kat:
    cld
    push word [cs:entropy_crypto_seg]
    call sha256_init
    mov si, entropy_kat_seed
    mov cx, entropy_kat_seed_len
    call entropy_drbg_instantiate
    jc .bad
    mov di, entropy_drbg_output
    mov cx, 128
    call entropy_drbg_generate
    jc .bad
    mov di, entropy_drbg_output
    mov cx, 128
    call entropy_drbg_generate
    jc .bad
    mov si, entropy_drbg_output
    mov di, entropy_kat_returned
    mov cx, 128
    repe cmpsb
    jne .bad
    call entropy_wipe_local
    pop word [cs:entropy_crypto_seg]
    xor ax, ax
    clc
    ret
.bad:
    call entropy_wipe_local
    pop word [cs:entropy_crypto_seg]
    mov ax, tls13_286_error_crypto
    stc
    ret

entropy_scrub_success:
    mov es, [cs:entropy_crypto_seg]
    xor ax, ax
    mov di, tls13_286_entropy_raw_off
    mov cx, tls13_286_entropy_raw_bytes / 2
    rep stosw
    mov di, tls13_286_entropy_seed_off
    mov cx, tls13_286_entropy_seed_bytes / 2
    rep stosw
    mov di, tls13_286_entropy_health_off
    mov cx, tls13_286_entropy_health_bytes / 2
    rep stosw
    mov di, tls13_286_drbg_k_off
    mov cx, (tls13_286_generation_hash_off - tls13_286_drbg_k_off) / 2
    rep stosw
    call entropy_wipe_local
    ret

entropy_scrub_failure:
    mov es, [cs:entropy_crypto_seg]
    xor ax, ax
    mov di, tls13_286_entropy_raw_off
    mov cx, tls13_286_entropy_raw_bytes / 2
    rep stosw
    mov di, tls13_286_entropy_seed_off
    mov cx, tls13_286_entropy_seed_bytes / 2
    rep stosw
    mov di, tls13_286_entropy_health_off
    mov cx, tls13_286_entropy_health_bytes / 2
    rep stosw
    mov di, tls13_286_attempt_acquire_off
    mov cx, (tls13_286_attempt_fresh_status_off + 1 - \
        tls13_286_attempt_acquire_off) / 2
    rep stosw
    mov di, tls13_286_previous_entropy_hash_off
    mov cx, tls13_286_previous_entropy_hash_len / 2
    rep stosw
    call entropy_wipe_local
    ret

entropy_wipe_local:
    cld
    push cs
    pop es
    xor ax, ax
    mov di, entropy_mutable_start
    mov cx, (entropy_mutable_end - entropy_mutable_start + 1) / 2
    rep stosw
    push cs
    pop ds
    push cs
    pop es
    ret

entropy_abort:
    cld
    mov ax, [cs:tls13_286_root_state_crypto_seg]
    mov [cs:entropy_crypto_seg], ax
    cmp ax, (512 * 1024 - tls13_286_high_reserve_bytes) / 16
    jb .root
    cmp ax, (640 * 1024 - tls13_286_high_reserve_bytes) / 16
    ja .root
    call entropy_scrub_failure
.root:
    ; The bootstrap still exists throughout entropy collection: Ethernet RX
    ; does not reuse 0700 until HELLO has installed the authenticated capsule.
    ; Validate the independently published parent SP, leave the fixed tail
    ; stack, and retire its complete module/guard band before asking the root
    ; and bootstrap to restore escrow and wipe the high reservation.
    xor ax, ax
    mov ds, ax
    cmp word [tls13_286_root_state_parent_sp_status_inv], 0xa55a
    jne .reset
    mov dx, [tls13_286_root_state_parent_sp]
    mov ax, [tls13_286_root_state_parent_sp_inverse]
    not ax
    cmp dx, ax
    jne .reset
    cli
    mov sp, dx
    xor ax, ax
    mov es, ax
    mov di, tls13_286_module_load
    mov cx, (tls13_286_tail_stack_top - tls13_286_module_load) / 2
    rep stosw
    sti
    jmp word [cs:tls13_286_root_service_abort]
.reset:
    cli
    jmp 0xffff:0x0000

; Before any target entropy or private attempt state exists, bind the exact SP
; frozen by the bootstrap to the current low-entry ceiling and publish its
; inverse/status pair.  The capsule consumes this independent copy after the
; original 0x0700 phase has been reused by Ethernet receive buffers.
entropy_publish_parent_stack:
    cmp word [tls13_286_root_state_parent_sp_status_inv], 0
    jne .bad
    mov dx, [TLS13_286_PRODUCT_BOOTSTRAP_PARENT_SP]
    test dl, 1
    jnz .bad
    cmp dx, tls13_286_tail_stack_top
    jbe .bad
    mov cx, [0x062c]
    cmp dx, cx
    jae .bad
    sub cx, tls13_286_parent_stack_window
    jc .bad
    cmp dx, cx
    jb .bad
    mov [tls13_286_root_state_parent_sp], dx
    mov ax, dx
    not ax
    mov [tls13_286_root_state_parent_sp_inverse], ax
    mov word [tls13_286_root_state_parent_sp_status_inv], 0xa55a
    clc
    ret
.bad:
    stc
    ret

entropy_abort_bootstrap:
    jmp word [cs:tls13_286_root_service_abort]

; Shipping SHA-256/HMAC implementation.
%include "core/sha256.inc"

sha256_initial_state:
    dw 0xe667,0x6a09,0xae85,0xbb67
    dw 0xf372,0x3c6e,0xf53a,0xa54f
    dw 0x527f,0x510e,0x688c,0x9b05
    dw 0xd9ab,0x1f83,0xcd19,0x5be0
sha256_k:
    dw 0x2f98,0x428a,0x4491,0x7137
    dw 0xfbcf,0xb5c0,0xdba5,0xe9b5
    dw 0xc25b,0x3956,0x11f1,0x59f1
    dw 0x82a4,0x923f,0x5ed5,0xab1c
    dw 0xaa98,0xd807,0x5b01,0x1283
    dw 0x85be,0x2431,0x7dc3,0x550c
    dw 0x5d74,0x72be,0xb1fe,0x80de
    dw 0x06a7,0x9bdc,0xf174,0xc19b
    dw 0x69c1,0xe49b,0x4786,0xefbe
    dw 0x9dc6,0x0fc1,0xa1cc,0x240c
    dw 0x2c6f,0x2de9,0x84aa,0x4a74
    dw 0xa9dc,0x5cb0,0x88da,0x76f9
    dw 0x5152,0x983e,0xc66d,0xa831
    dw 0x27c8,0xb003,0x7fc7,0xbf59
    dw 0x0bf3,0xc6e0,0x9147,0xd5a7
    dw 0x6351,0x06ca,0x2967,0x1429
    dw 0x0a85,0x27b7,0x2138,0x2e1b
    dw 0x6dfc,0x4d2c,0x0d13,0x5338
    dw 0x7354,0x650a,0x0abb,0x766a
    dw 0xc92e,0x81c2,0x2c85,0x9272
    dw 0xe8a1,0xa2bf,0x664b,0xa81a
    dw 0x8b70,0xc24b,0x51a3,0xc76c
    dw 0xe819,0xd192,0x0624,0xd699
    dw 0x3585,0xf40e,0xa070,0x106a
    dw 0xc116,0x19a4,0x6c08,0x1e37
    dw 0x774c,0x2748,0xbcb5,0x34b0
    dw 0x0cb3,0x391c,0xaa4a,0x4ed8
    dw 0xca4f,0x5b9c,0x6ff3,0x682e
    dw 0x82ee,0x748f,0x636f,0x78a5
    dw 0x7814,0x84c8,0x0208,0x8cc7
    dw 0xfffa,0x90be,0x6ceb,0xa450
    dw 0xa3f7,0xbef9,0x78f2,0xc671

entropy_health_magic db 'E286H001'
entropy_kat_seed:
    db 0xca,0x85,0x19,0x11,0x34,0x93,0x84,0xbf
    db 0xfe,0x89,0xde,0x1c,0xbd,0xc4,0x6e,0x68
    db 0x31,0xe4,0x4d,0x34,0xa4,0xfb,0x93,0x5e
    db 0xe2,0x85,0xdd,0x14,0xb7,0x1a,0x74,0x88
    db 0x65,0x9b,0xa9,0x6c,0x60,0x1d,0xc6,0x9f
    db 0xc9,0x02,0x94,0x08,0x05,0xec,0x0c,0xa8
entropy_kat_seed_len equ $ - entropy_kat_seed
entropy_kat_returned:
    db 0xe5,0x28,0xe9,0xab,0xf2,0xde,0xce,0x54
    db 0xd4,0x7c,0x7e,0x75,0xe5,0xfe,0x30,0x21
    db 0x49,0xf8,0x17,0xea,0x9f,0xb4,0xbe,0xe6
    db 0xf4,0x19,0x96,0x97,0xd0,0x4d,0x5b,0x89
    db 0xd5,0x4f,0xbb,0x97,0x8a,0x15,0xb5,0xc4
    db 0x43,0xc9,0xec,0x21,0x03,0x6d,0x24,0x60
    db 0xb6,0xf7,0x3e,0xba,0xd0,0xdc,0x2a,0xba
    db 0x6e,0x62,0x4a,0xbf,0x07,0x74,0x5b,0xc1
    db 0x07,0x69,0x4b,0xb7,0x54,0x7b,0xb0,0x99
    db 0x5f,0x70,0xde,0x25,0xd6,0xb2,0x9e,0x2d
    db 0x30,0x11,0xbb,0x19,0xd2,0x76,0x76,0xc0
    db 0x71,0x62,0xc8,0xb5,0xcc,0xde,0x06,0x68
    db 0x96,0x1d,0xf8,0x68,0x03,0x48,0x2c,0xb3
    db 0x7e,0xd6,0xd5,0xc0,0xbb,0x8d,0x50,0xcf
    db 0x1f,0x50,0xd4,0x76,0xaa,0x04,0x58,0xbd
    db 0xab,0xa8,0x06,0xf4,0x8b,0xe9,0xdc,0xb8

align 2
entropy_mutable_start:
entropy_mode db 0
entropy_crypto_seg dw 0
entropy_sample_index dw 0
entropy_pit_before dw 0
entropy_pit_after dw 0
entropy_rtc_status_a db 0
entropy_rtc_active db 0
entropy_health_seen db 0
entropy_health_failed db 0
entropy_health_last db 0
entropy_health_run db 0
entropy_health_ref db 0
entropy_health_apt_pos dw 0
entropy_health_apt_matches dw 0
entropy_health_total dw 0
entropy_hash_chunk dw 0
entropy_drbg_provided_ptr dw 0
entropy_drbg_provided_len dw 0
entropy_drbg_output_ptr dw 0
entropy_drbg_output_remaining dw 0
entropy_condition_desc times tls13_286_desc_bytes db 0
entropy_conditioned times 64 db 0
entropy_conditioned_hash times 32 db 0
entropy_generation_hash times 32 db 0
entropy_hash_buffer times 32 db 0
entropy_drbg_k times 32 db 0
entropy_drbg_v times 32 db 0
entropy_drbg_input times 97 db 0
entropy_drbg_output times tls13_286_attempt_bundle_bytes db 0

sha256_state times 32 db 0
sha256_a times 4 db 0
sha256_b times 4 db 0
sha256_c times 4 db 0
sha256_d times 4 db 0
sha256_e times 4 db 0
sha256_f times 4 db 0
sha256_g times 4 db 0
sha256_h times 4 db 0
sha256_t1 times 4 db 0
sha256_t2 times 4 db 0
sha256_new_e times 4 db 0
sha256_tmp times 4 db 0
sha256_w_ptr dw 0
sha256_k_ptr dw 0
sha256_len_low dw 0
sha256_len_high dw 0
sha256_saved_len_low dw 0
sha256_saved_len_high dw 0
sha256_bit_len0 dw 0
sha256_bit_len1 dw 0
sha256_bit_len2 dw 0
sha256_bit_len3 dw 0
sha256_digest_ptr dw 0
hmac_key_ptr dw 0
hmac_key_len dw 0
hmac_data1_ptr dw 0
hmac_data1_len dw 0
hmac_data2_ptr dw 0
hmac_data2_len dw 0
hmac_output_ptr dw 0
sha256_block_len db 0
sha256_saved_block_len db 0
sha256_schedule_count db 0
sha256_round_count db 0
sha256_block times sha256_block_size db 0
sha256_w times sha256_k_len db 0
sha256_saved_state times 32 db 0
sha256_saved_block times sha256_block_size db 0
hmac_ipad times 64 db 0
hmac_opad times 64 db 0
hmac_inner_digest times 32 db 0
hmac_prepared_inner_state times 32 db 0
hmac_prepared_outer_state times 32 db 0
entropy_mutable_end:

entropy_image_end:

%if (entropy_header - $$) != 0
%error "TLS 1.3 286 entropy controller header moved"
%endif
%if (entropy_image_end - $$) > tls13_286_controller_max_bytes
%error "TLS 1.3 286 entropy controller exceeds safe controller window"
%endif
