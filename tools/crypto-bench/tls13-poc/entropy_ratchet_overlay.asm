; Self-contained 8086 two-slot attempt-seed ratchet PoC.
;
; This is an isolated phase overlay, not runtime persistence code.  The caller
; owns the BIOS/FAT sector I/O:
;   1. load the two preallocated 512-byte slots at entropy_slot{0,1};
;   2. select, collect/append timing bytes, and prepare;
;   3. write entropy_write_record to the returned alternate slot;
;   4. read that sector back into entropy_readback;
;   5. call verify_commit, then and only then request d||z.
;
; d||z remains all-zero and entropy_get_dz fails until exact readback plus
; SHA3 record verification succeeds.  The record digest detects damage; it is
; not a MAC and therefore does not authenticate actively modified media.

bits 16
cpu 8086
org 0x1800

entropy_overlay_base equ 0x1800
entropy_overlay_limit equ 0x3600
entropy_sector_bytes equ 512
entropy_record_body_bytes equ 480
entropy_digest_bytes equ 32
entropy_state_bytes equ 32
entropy_supplement_max equ 96
sha3_rate equ 136
keccak_state_bytes equ 200

entropy_slot0 equ 0x0700
entropy_slot1 equ 0x0900
entropy_supplement equ 0x0b00
entropy_timing_sample equ 0x0b80
entropy_write_record equ 0x0c00
entropy_readback equ 0x0e00

entropy_header:
    db 'ENTRT001'
    dw 1
    dw entropy_overlay_end - entropy_header
    dw entropy_slot0
    dw entropy_slot1
    dw entropy_supplement
    dw entropy_supplement_max
    dw entropy_write_record
    dw entropy_readback
    dw entropy_high_start
    dw entropy_high_end
    dw entropy_dz
    dw entropy_entry_count
entropy_entry_table:
    dw entropy_reset
    dw entropy_select_slots
    dw entropy_supplement_reset
    dw entropy_supplement_append
    dw entropy_collect_timing
    dw entropy_prepare_write
    dw entropy_verify_commit
    dw entropy_get_dz
    dw entropy_abort
entropy_entry_count equ ($ - entropy_entry_table) / 2

; ---------------------------------------------------------------------------
; Public phase ABI
; ---------------------------------------------------------------------------

entropy_reset:
    cld
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, entropy_high_start
    mov cx, entropy_high_end - entropy_high_start
    rep stosb
    mov di, entropy_supplement
    mov cx, entropy_supplement_max
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    clc
    ret

entropy_supplement_reset:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov [entropy_supplement_len], ax
    mov di, entropy_supplement
    mov cx, entropy_supplement_max
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    clc
    ret

; SI=caller-collected timing bytes, CX=count (aggregate cap 96).
entropy_supplement_append:
    push ax
    push bx
    push di
    push es
    mov ax, [entropy_supplement_len]
    mov bx, ax
    add ax, cx
    jc .failed
    cmp ax, entropy_supplement_max
    ja .failed
    push ds
    pop es
    mov di, entropy_supplement
    add di, bx
    rep movsb
    mov [entropy_supplement_len], ax
    clc
    jmp short .done
.failed:
    stc
.done:
    pop es
    pop di
    pop bx
    pop ax
    ret

; Minimal nonblocking target collector.  It latches PIT channel 0, snapshots
; the BIOS tick and keyboard-ring metadata, and peeks (does not consume) the
; queued key word when the BDA pointers are sane.  The values are supplemental
; only: neither this code nor its emulator test assigns min-entropy credit.
entropy_collect_timing:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    push ds
    pop es
    mov di, entropy_timing_sample
    xor al, al
    out 0x43, al
    in al, 0x40
    stosb
    in al, 0x40
    stosb
    mov si, 0x046c
    mov cx, 2
    rep movsw
    mov ax, [0x041a]
    stosw
    mov dx, [0x041c]
    mov ax, dx
    stosw
    xor ax, ax
    mov bx, [0x041a]
    cmp bx, dx
    je .store_key
    cmp bx, 0x001e
    jb .store_key
    cmp bx, 0x003c
    ja .store_key
    test bl, 1
    jnz .store_key
    add bx, 0x0400
    mov ax, [bx]
.store_key:
    stosw
    mov si, entropy_timing_sample
    mov cx, 12
    call entropy_supplement_append
    pushf
    pop word [entropy_collector_flags]
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    push word [entropy_collector_flags]
    popf
    ret

; Parse both sectors and choose the newest unambiguous valid generation.
; Equal generation + equal state is unambiguous and chooses slot 1, matching
; the host oracle's stable ordering.  Equal generation + different state fails.
; Returns AX=slot index.
entropy_select_slots:
    mov byte [entropy_slot0_valid], 0
    mov byte [entropy_slot1_valid], 0
    mov byte [entropy_selected], 0
    mov byte [entropy_prepared], 0
    mov byte [entropy_dz_available], 0
    call entropy_zero_dz

    mov word [entropy_validate_slot_ptr], entropy_slot0
    mov word [entropy_validate_gen_ptr], entropy_slot0_generation
    mov word [entropy_validate_state_ptr], entropy_slot0_state
    call entropy_validate_slot
    jc .slot1
    mov byte [entropy_slot0_valid], 1
.slot1:
    mov word [entropy_validate_slot_ptr], entropy_slot1
    mov word [entropy_validate_gen_ptr], entropy_slot1_generation
    mov word [entropy_validate_state_ptr], entropy_slot1_state
    call entropy_validate_slot
    jc .decide
    mov byte [entropy_slot1_valid], 1
.decide:
    cmp byte [entropy_slot0_valid], 0
    jne .have0
    cmp byte [entropy_slot1_valid], 0
    je .failed
    jmp entropy_choose_slot1
.have0:
    cmp byte [entropy_slot1_valid], 0
    je entropy_choose_slot0

    mov ax, [entropy_slot0_generation + 6]
    cmp ax, [entropy_slot1_generation + 6]
    ja entropy_choose_slot0
    jb entropy_choose_slot1
    mov ax, [entropy_slot0_generation + 4]
    cmp ax, [entropy_slot1_generation + 4]
    ja entropy_choose_slot0
    jb entropy_choose_slot1
    mov ax, [entropy_slot0_generation + 2]
    cmp ax, [entropy_slot1_generation + 2]
    ja entropy_choose_slot0
    jb entropy_choose_slot1
    mov ax, [entropy_slot0_generation]
    cmp ax, [entropy_slot1_generation]
    ja entropy_choose_slot0
    jb entropy_choose_slot1

    mov si, entropy_slot0_state
    mov di, entropy_slot1_state
    mov cx, entropy_state_bytes
    repe cmpsb
    jne .failed
    jmp entropy_choose_slot1
.failed:
    stc
    ret

entropy_choose_slot0:
    mov si, entropy_slot0_generation
    mov bx, entropy_slot0_state
    xor ax, ax
    jmp short entropy_choose_slot

entropy_choose_slot1:
    mov si, entropy_slot1_generation
    mov bx, entropy_slot1_state
    mov ax, 1

entropy_choose_slot:
    mov [entropy_current_slot], al
    push ax
    push ds
    pop es
    mov di, entropy_current_generation
    mov cx, 4
    rep movsw
    mov si, bx
    mov di, entropy_current_state
    mov cx, entropy_state_bytes
    rep movsb
    mov byte [entropy_selected], 1
    pop ax
    clc
    ret

; Build the alternate-slot sector.  No d||z bytes are emitted here.
; Returns AX=target slot, SI=record pointer, CX=512.
entropy_prepare_write:
    cmp byte [entropy_selected], 1
    jne .failed
    mov byte [entropy_prepared], 0
    mov byte [entropy_dz_available], 0
    call entropy_zero_dz

    push ds
    pop es
    mov si, entropy_current_generation
    mov di, entropy_next_generation
    mov cx, 4
    rep movsw
    add word [entropy_next_generation], 1
    adc word [entropy_next_generation + 2], 0
    adc word [entropy_next_generation + 4], 0
    adc word [entropy_next_generation + 6], 0
    mov ax, [entropy_next_generation]
    or ax, [entropy_next_generation + 2]
    or ax, [entropy_next_generation + 4]
    or ax, [entropy_next_generation + 6]
    jz .failed

    mov si, entropy_domain_next_state
    mov cx, entropy_domain_next_state_len
    mov di, entropy_next_state
    call entropy_hash_attempt_material

    mov si, entropy_domain_attempt_seed
    mov cx, entropy_domain_attempt_seed_len
    mov di, entropy_pending_attempt_seed
    call entropy_hash_attempt_material

    push ds
    pop es
    xor ax, ax
    mov di, entropy_write_record
    mov cx, entropy_sector_bytes
    rep stosb
    mov si, entropy_record_magic
    mov di, entropy_write_record
    mov cx, 8
    rep movsb
    mov byte [entropy_write_record + 8], 1
    mov si, entropy_next_generation
    mov di, entropy_write_record + 12
    mov cx, 4
    rep movsw
    mov si, entropy_next_state
    mov di, entropy_write_record + 20
    mov cx, entropy_state_bytes
    rep movsb
    mov si, entropy_write_record
    mov di, entropy_write_record + entropy_record_body_bytes
    call entropy_record_digest

    mov al, [entropy_current_slot]
    xor al, 1
    mov [entropy_target_slot], al
    mov byte [entropy_prepared], 1
    xor ah, ah
    mov si, entropy_write_record
    mov cx, entropy_sector_bytes
    clc
    ret
.failed:
    stc
    ret

; Validate exact durable readback and only then derive/publish d||z.
entropy_verify_commit:
    cmp byte [entropy_prepared], 1
    jne .failed
    mov byte [entropy_dz_available], 0
    call entropy_zero_dz

    mov si, entropy_write_record
    mov di, entropy_readback
    mov cx, entropy_sector_bytes
    repe cmpsb
    jne .failed

    mov word [entropy_validate_slot_ptr], entropy_readback
    mov word [entropy_validate_gen_ptr], entropy_verify_generation
    mov word [entropy_validate_state_ptr], entropy_verify_state
    call entropy_validate_slot
    jc .failed
    mov si, entropy_verify_generation
    mov di, entropy_next_generation
    mov cx, 8
    repe cmpsb
    jne .failed
    mov si, entropy_verify_state
    mov di, entropy_next_state
    mov cx, entropy_state_bytes
    repe cmpsb
    jne .failed

    mov si, entropy_domain_mlkem_d
    mov cx, entropy_domain_mlkem_d_len
    mov di, entropy_dz
    call entropy_hash_pending_seed
    mov si, entropy_domain_mlkem_z
    mov cx, entropy_domain_mlkem_z_len
    mov di, entropy_dz + 32
    call entropy_hash_pending_seed

    push ds
    pop es
    mov si, entropy_next_generation
    mov di, entropy_current_generation
    mov cx, 4
    rep movsw
    mov si, entropy_next_state
    mov di, entropy_current_state
    mov cx, entropy_state_bytes
    rep movsb
    mov al, [entropy_target_slot]
    mov [entropy_current_slot], al
    mov byte [entropy_prepared], 0
    mov byte [entropy_dz_available], 1
    call entropy_zero_pending_seed
    clc
    ret
.failed:
    stc
    ret

entropy_get_dz:
    cmp byte [entropy_dz_available], 1
    jne .failed
    mov si, entropy_dz
    mov cx, 64
    clc
    ret
.failed:
    xor si, si
    xor cx, cx
    stc
    ret

entropy_abort:
    mov byte [entropy_prepared], 0
    mov byte [entropy_dz_available], 0
    call entropy_zero_dz
    call entropy_zero_pending_seed
    clc
    ret

; ---------------------------------------------------------------------------
; Record and derivation helpers
; ---------------------------------------------------------------------------

entropy_validate_slot:
    mov si, [entropy_validate_slot_ptr]
    mov di, entropy_digest_work
    call entropy_record_digest
    mov si, entropy_digest_work
    mov di, [entropy_validate_slot_ptr]
    add di, entropy_record_body_bytes
    mov cx, entropy_digest_bytes
    repe cmpsb
    jne .failed
    mov si, [entropy_validate_slot_ptr]
    mov di, entropy_record_magic
    mov cx, 8
    repe cmpsb
    jne .failed
    mov si, [entropy_validate_slot_ptr]
    cmp byte [si + 8], 1
    jne .failed
    add si, 12
    mov di, [entropy_validate_gen_ptr]
    mov cx, 4
    rep movsw
    mov si, [entropy_validate_slot_ptr]
    add si, 20
    mov di, [entropy_validate_state_ptr]
    mov cx, entropy_state_bytes
    rep movsb
    clc
    ret
.failed:
    stc
    ret

; SI=480-byte body, DI=32-byte output.
entropy_record_digest:
    push si
    push di
    call sha3_init
    mov si, entropy_domain_record
    mov cx, entropy_domain_record_len
    call sha3_update
    pop di
    pop si
    push di
    mov cx, entropy_record_body_bytes
    call sha3_update
    pop di
    jmp sha3_finish

; SI=domain, CX=len, DI=output.  Hash domain || current state || next gen ||
; supplemental bytes, matching the checked host crash oracle exactly.
entropy_hash_attempt_material:
    push di
    call sha3_init
    call sha3_update
    mov si, entropy_current_state
    mov cx, entropy_state_bytes
    call sha3_update
    mov si, entropy_next_generation
    mov cx, 8
    call sha3_update
    mov si, entropy_supplement
    mov cx, [entropy_supplement_len]
    call sha3_update
    pop di
    jmp sha3_finish

; SI=domain, CX=len, DI=output.  Expand the committed attempt root into one
; independently domain-separated ML-KEM seed.
entropy_hash_pending_seed:
    push di
    call sha3_init
    call sha3_update
    mov si, entropy_pending_attempt_seed
    mov cx, 32
    call sha3_update
    pop di
    jmp sha3_finish

entropy_zero_dz:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, entropy_dz
    mov cx, 64
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

entropy_zero_pending_seed:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, entropy_pending_attempt_seed
    mov cx, 32
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

; ---------------------------------------------------------------------------
; SHA3-256 sponge
; ---------------------------------------------------------------------------

sha3_init:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, keccak_state
    mov cx, keccak_state_bytes
    rep stosb
    mov [sha3_pos], ax
    pop es
    pop di
    pop cx
    pop ax
    clc
    ret

; SI=data, CX=len.
sha3_update:
    or cx, cx
    jz .done
.next:
    lodsb
    mov bx, [sha3_pos]
    xor [keccak_state + bx], al
    inc bx
    mov [sha3_pos], bx
    dec cx
    cmp bx, sha3_rate
    jne .more
    push si
    push cx
    call keccak_f1600
    pop cx
    pop si
    mov word [sha3_pos], 0
.more:
    or cx, cx
    jnz .next
.done:
    clc
    ret

; DI=32-byte digest output.
sha3_finish:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    mov [sha3_output_ptr], di
    mov bx, [sha3_pos]
    xor byte [keccak_state + bx], 0x06
    xor byte [keccak_state + sha3_rate - 1], 0x80
    call keccak_f1600
    push ds
    pop es
    mov si, keccak_state
    mov di, [sha3_output_ptr]
    mov cx, 32
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    clc
    ret

; ---------------------------------------------------------------------------
; Keccak-f[1600], cpu 8086 (from the checked ML-KEM integrated spike)
; ---------------------------------------------------------------------------

keccak_f1600:
    mov word [round_index], 0
.round:
    mov si, keccak_state
    mov di, keccak_c
    mov cx, 5
.theta_column:
    push cx
    mov cx, 4
.theta_word:
    mov ax, [si]
    xor ax, [si + 40]
    xor ax, [si + 80]
    xor ax, [si + 120]
    xor ax, [si + 160]
    stosw
    add si, 2
    loop .theta_word
    pop cx
    loop .theta_column

    xor bx, bx
.theta_d:
    mov al, [theta_next + bx]
    xor ah, ah
    add ax, keccak_c
    mov si, ax
    mov di, lane_tmp
    mov cl, 1
    call rotl64_to
    mov al, [theta_prev + bx]
    xor ah, ah
    add ax, keccak_c
    mov si, ax
    mov di, keccak_d
    mov ax, bx
    mov cl, 3
    shl ax, cl
    add di, ax
    mov cx, 4
.theta_xor:
    mov ax, [si]
    xor ax, [lane_tmp]
    push si
    mov si, lane_tmp
    mov dx, 4
    sub dx, cx
    shl dx, 1
    add si, dx
    xor ax, [si]
    pop si
    xor ax, [lane_tmp]
    stosw
    add si, 2
    loop .theta_xor
    inc bx
    cmp bx, 5
    jb .theta_d

    xor bx, bx
.theta_apply_column:
    mov ax, bx
    mov cl, 3
    shl ax, cl
    mov si, keccak_d
    add si, ax
    mov di, keccak_state
    add di, ax
    mov dx, 5
.theta_apply_row:
    mov cx, 4
.theta_apply_word:
    lodsw
    xor [di], ax
    add di, 2
    loop .theta_apply_word
    sub si, 8
    add di, 32
    dec dx
    jnz .theta_apply_row
    inc bx
    cmp bx, 5
    jb .theta_apply_column

    xor bx, bx
.rho_pi:
    mov ax, bx
    mov cl, 3
    shl ax, cl
    mov si, keccak_state
    add si, ax
    mov al, [pi_offsets + bx]
    xor ah, ah
    mov di, keccak_b
    add di, ax
    mov cl, [rho_offsets + bx]
    call rotl64_to
    inc bx
    cmp bx, 25
    jb .rho_pi

    mov bx, keccak_b
    mov bp, keccak_state
    mov dx, 5
.chi_row:
    xor si, si
.chi_word:
    mov ax, [bx + si + 8]
    not ax
    and ax, [bx + si + 16]
    xor ax, [bx + si]
    mov [bp + si], ax
    mov ax, [bx + si + 16]
    not ax
    and ax, [bx + si + 24]
    xor ax, [bx + si + 8]
    mov [bp + si + 8], ax
    mov ax, [bx + si + 24]
    not ax
    and ax, [bx + si + 32]
    xor ax, [bx + si + 16]
    mov [bp + si + 16], ax
    mov ax, [bx + si + 32]
    not ax
    and ax, [bx + si]
    xor ax, [bx + si + 24]
    mov [bp + si + 24], ax
    mov ax, [bx + si]
    not ax
    and ax, [bx + si + 8]
    xor ax, [bx + si + 32]
    mov [bp + si + 32], ax
    add si, 2
    cmp si, 8
    jb .chi_word
    add bx, 40
    add bp, 40
    dec dx
    jnz .chi_row

    mov bx, [round_index]
    mov ax, bx
    mov cl, 3
    shl ax, cl
    mov si, round_constants
    add si, ax
    mov ax, [si]
    xor [keccak_state], ax
    mov ax, [si + 2]
    xor [keccak_state + 2], ax
    mov ax, [si + 4]
    xor [keccak_state + 4], ax
    mov ax, [si + 6]
    xor [keccak_state + 6], ax
    inc word [round_index]
    cmp word [round_index], 24
    jb .round
    ret

rotl64_to:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push bp
    mov bp, si
    mov al, cl
    mov ah, al
    and al, 15
    mov [rot_bits], al
    mov dl, 16
    sub dl, al
    mov [rot_inv_bits], dl
    mov al, ah
    shr al, 1
    and ax, 0x0018
    mov bx, rot_word_pairs
    add bx, ax
    cmp byte [rot_bits], 0
    je .whole_words
    mov word [rot_outputs], 4
.mixed:
    mov dl, [bx]
    xor dh, dh
    mov si, dx
    mov ax, [bp + si]
    mov cl, [rot_bits]
    shl ax, cl
    mov dl, [bx + 1]
    xor dh, dh
    mov si, dx
    mov dx, [bp + si]
    mov cl, [rot_inv_bits]
    shr dx, cl
    or ax, dx
    stosw
    add bx, 2
    dec word [rot_outputs]
    jnz .mixed
    jmp short .done
.whole_words:
    mov cx, 4
.whole:
    mov dl, [bx]
    xor dh, dh
    mov si, dx
    mov ax, [bp + si]
    stosw
    add bx, 2
    loop .whole
.done:
    pop bp
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; ---------------------------------------------------------------------------
; Immutable format/domain constants
; ---------------------------------------------------------------------------

entropy_record_magic db 'SEEDRT13'
entropy_domain_record db 'Seed ratchet record v1',0
entropy_domain_record_len equ $ - entropy_domain_record
entropy_domain_next_state db 'Seed ratchet next-state v1',0
entropy_domain_next_state_len equ $ - entropy_domain_next_state
entropy_domain_attempt_seed db 'Seed ML-KEM attempt seed v1',0
entropy_domain_attempt_seed_len equ $ - entropy_domain_attempt_seed
entropy_domain_mlkem_d db 'Seed ML-KEM d from attempt v1',0
entropy_domain_mlkem_d_len equ $ - entropy_domain_mlkem_d
entropy_domain_mlkem_z db 'Seed ML-KEM z from attempt v1',0
entropy_domain_mlkem_z_len equ $ - entropy_domain_mlkem_z

rot_word_pairs:
    db 0,6, 2,0, 4,2, 6,4
    db 6,4, 0,6, 2,0, 4,2
    db 4,2, 6,4, 0,6, 2,0
    db 2,0, 4,2, 6,4, 0,6
theta_prev db 32,0,8,16,24
theta_next db 8,16,24,32,0
pi_offsets db 0,80,160,40,120,128,8,88,168,48,56,136,16,96,176,184,64,144,24,104,112,192,72,152,32
rho_offsets db 0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14
align 2
round_constants:
    dq 0x0000000000000001,0x0000000000008082
    dq 0x800000000000808a,0x8000000080008000
    dq 0x000000000000808b,0x0000000080000001
    dq 0x8000000080008081,0x8000000000008009
    dq 0x000000000000008a,0x0000000000000088
    dq 0x0000000080008009,0x000000008000000a
    dq 0x000000008000808b,0x800000000000008b
    dq 0x8000000000008089,0x8000000000008003
    dq 0x8000000000008002,0x8000000000000080
    dq 0x000000000000800a,0x800000008000000a
    dq 0x8000000080008081,0x8000000000008080
    dq 0x0000000080000001,0x8000000080008008

entropy_overlay_end:

; ---------------------------------------------------------------------------
; External high-memory state/work ABI
; ---------------------------------------------------------------------------

entropy_high_start equ 0x3600
entropy_current_state equ 0x3600
entropy_next_state equ 0x3620
entropy_pending_attempt_seed equ 0x3640
entropy_dz equ 0x3660
entropy_current_generation equ 0x36a0
entropy_next_generation equ 0x36a8
entropy_slot0_generation equ 0x36b0
entropy_slot0_state equ 0x36b8
entropy_slot1_generation equ 0x36d8
entropy_slot1_state equ 0x36e0
entropy_verify_generation equ 0x3700
entropy_verify_state equ 0x3708
entropy_digest_work equ 0x3728
entropy_supplement_len equ 0x3748
entropy_validate_slot_ptr equ 0x374a
entropy_validate_gen_ptr equ 0x374c
entropy_validate_state_ptr equ 0x374e
entropy_slot0_valid equ 0x3750
entropy_slot1_valid equ 0x3751
entropy_selected equ 0x3752
entropy_current_slot equ 0x3753
entropy_target_slot equ 0x3754
entropy_prepared equ 0x3755
entropy_dz_available equ 0x3756
entropy_collector_flags equ 0x3758
sha3_pos equ 0x375a
sha3_output_ptr equ 0x375c
round_index equ 0x375e
rot_outputs equ 0x3760
rot_bits equ 0x3762
rot_inv_bits equ 0x3763
keccak_c equ 0x3764
keccak_d equ 0x378c
lane_tmp equ 0x37b4
keccak_state equ 0x37bc
keccak_b equ 0x3884
entropy_high_end equ 0x394c

%if (entropy_overlay_end - entropy_header) > \
    (entropy_overlay_limit - entropy_overlay_base)
%error "entropy ratchet overlay exceeds the 15-sector phase window"
%endif
%if entropy_high_end > 0x3c9c
%error "entropy ratchet state exceeds the high security-state band"
%endif
%if (entropy_supplement + entropy_supplement_max) > entropy_timing_sample
%error "supplement buffer overlaps collector sample"
%endif
%if (entropy_timing_sample + 12) > entropy_write_record
%error "collector sample overlaps write record"
%endif
%if (entropy_write_record + entropy_sector_bytes) > entropy_readback
%error "write record overlaps readback"
%endif
%if (entropy_readback + entropy_sector_bytes) > 0x1000
%error "readback exceeds low phase memory"
%endif
