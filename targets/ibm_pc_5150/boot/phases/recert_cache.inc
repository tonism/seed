; Build 13 external leaf: verify the shipped/cached SEED/LEAF.DER against the pinned WR1 anchor and
; adopt it before opening a new TLS socket. Missing, stale, malformed, or untrusted cache is ignored;
; the normal recertify path captures and verifies the live leaf, then retries. 286+ only because it
; uses the P-256/RSA module loaded by tls_client_hello.
recert_cache_phase:
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .done
    cmp byte [recert_flag], 0
    jne .done
    call .find_leaf
    jc .done
    cmp word [fs_file_size_high], 0
    jne .done
    mov ax, [fs_file_size_low]
    cmp ax, 4
    jb .done
    cmp ax, leaf_capture_max
    ja .done
    mov ax, [fs_file_cluster]
    cmp ax, fat_first_data_cluster
    jb .done
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    mov si, ax
    mov cx, [fs_file_size_low]
    add cx, 511
    mov cl, ch
    xor ch, ch
    shr cx, 1
    mov di, leaf_capture_buf
.read_loop:
    push ds
    pop es
    mov bx, di
    mov ax, si
    phase_call_res read_abs_sector
    jc .done
    add di, 512
    inc si
    loop .read_loop
    mov si, leaf_capture_buf
    mov cx, [fs_file_size_low]
    call word [p256_ep_parse_leaf]
    jc .done
    phase_call_res sha256_init
    mov si, [p256_x509_result_tbs_ptr]
    mov cx, [p256_x509_result_tbs_len]
    phase_call_res sha256_update
    mov di, high_crypto_work
    phase_call_res sha256_finish
    mov si, [p256_x509_result_sig_ptr]
    mov di, high_crypto_work
    call word [p256_ep_chain_verify_sig]
    jc .reload_module
    mov ax, [p256_x509_result_mod_ptr]
    mov [recert_mod_ptr], ax
    mov byte [recert_flag], 1
.done:
    clc
    ret
.reload_module:
    mov ax, (((core_p256_module_end - core_p256_module_start + 511) / 512) << 8) | ((core_p256_module_start - $$) / 512)
    mov bx, p256_module_load
    phase_call_res load_core_sectors_at
    jmp .done

.find_leaf:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
.seed_sector:
    cmp word [fs_root_left], 0
    je .fail
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [fs_lba]
    phase_call_res read_abs_sector
    jc .fail
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.seed_entry:
    mov al, [si]
    or al, al
    jz .fail
    cmp al, 0xe5
    je .seed_advance
    test byte [si + 11], 0x10
    jz .seed_advance
    push si
    push cx
    mov di, low_scratch_start + (recert_seed_name - PHASE_BASE)
    mov cx, 11
.seed_cmp:
    mov al, [si]
    cmp al, [di]
    jne .seed_mismatch
    inc si
    inc di
    loop .seed_cmp
    pop cx
    pop si
    mov ax, [si + 26]
    cmp ax, fat_first_data_cluster
    jb .fail
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    mov [fs_lba], ax
    jmp .scan_seed_dir
.seed_mismatch:
    pop cx
    pop si
.seed_advance:
    add si, fat_dir_entry_size
    loop .seed_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .seed_sector

.scan_seed_dir:
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [fs_lba]
    phase_call_res read_abs_sector
    jc .fail
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.dir_entry:
    mov al, [si]
    or al, al
    jz .fail
    cmp al, 0xe5
    je .dir_advance
    test byte [si + 11], 0x18
    jnz .dir_advance
    push si
    push cx
    mov di, low_scratch_start + (recert_leaf_name - PHASE_BASE)
    mov cx, 11
.leaf_cmp:
    mov al, [si]
    cmp al, [di]
    jne .leaf_mismatch
    inc si
    inc di
    loop .leaf_cmp
    pop cx
    pop si
    mov ax, [si + 26]
    mov [fs_file_cluster], ax
    mov ax, [si + 28]
    mov [fs_file_size_low], ax
    mov ax, [si + 30]
    mov [fs_file_size_high], ax
    clc
    ret
.leaf_mismatch:
    pop cx
    pop si
.dir_advance:
    add si, fat_dir_entry_size
    loop .dir_entry
.fail:
    stc
    ret

recert_seed_name db 'SEED       '
recert_leaf_name db 'LEAF    DER'
