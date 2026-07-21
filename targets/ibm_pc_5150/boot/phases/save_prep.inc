%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name the runtime load address (net_setup_phase_start)"
%endif

%macro phase_jmp_res 1
    db 0xe9
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

; Build 12 env save/load (design: docs/architecture.md, "Persistence"), SAVE part 1 of 2: SCAN + PLAN. The save
; writer (save_write) is at its 2-sector fs_sector_buffer ceiling, so the trim codec setup lives here
; in its own phase: compute region_len (full extent), region_stored (trailing-zero trim), the per-row
; screen row-length table + screen_stored, the file size, and the payload checksum -- all into fixed
; scratch (data.inc save_*). This phase never touches fs_sector_buffer, so it has the full net-window
; budget. It then chains to save_write by JMPing into the resident phase loader (not a call), so when
; save_write returns it lands back in the resident chat loop, not in this phase's overwritten code. The save runs between
; turns, so it reads only RAM/video here -- the actual disk I/O is all in save_write.
save_prep_phase:
    mov byte [save_pending], 0       ; consume the request (chat_loop loads us as the save entry point)
    ; --- region_len = full arena+context extent (ceiling - chat_pool_start), mirrors restore ---
    mov ax, [handoff_addr + handoff_ram_top]
    sub ax, 0x100
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .rl_ready
    mov ax, loop_cache_start
.rl_ready:
    sub ax, chat_pool_start
    mov [save_region_len], ax

    ; --- region_stored = highest non-zero byte + 1 (trailing-zero trim); 0 if the region is empty ---
    mov bx, ax                       ; bx = region_len, scan downward
.rs_scan:
    or bx, bx
    jz .rs_done
    dec bx
    cmp byte [chat_pool_start + bx], 0
    je .rs_scan
    inc bx                           ; highest non-zero + 1
.rs_done:
    mov [save_region_stored], bx

    ; --- per-row screen row-length table + screen_stored = screen_rows + 2*sum(row_len) ---
    call save_prep_rowlens           ; fills save_rowlen_table; ax = sum(row_len over 25 rows)
    shl ax, 1                        ; 2 * sum (char+attr per cell)
    add ax, 25                       ; + the row-length table (one byte per row)
    mov [save_screen_stored], ax

    ; --- file size + payload checksum ---
    mov ax, [save_region_stored]
    add ax, [save_screen_stored]
    add ax, env_hdr_len
    mov [save_file_size], ax

    ; payload checksum = sum(region prefix) + sum(row-length table) + sum(kept screen cells)
    xor bx, bx                       ; bx = running checksum
    mov si, chat_pool_start
    mov cx, [save_region_stored]
    call save_prep_sum               ; bx += sum [ds:si .. +cx)
    mov si, save_rowlen_table
    mov cx, 25
    call save_prep_sum
    call save_prep_sum_cells         ; bx += sum of the kept screen cells (char+attr)
    mov [save_payload_ck], bx
    call save_prep_find_dir_slot     ; sets save_dir_lba/off + save_old_cluster for SEED/ENV.DAT

    ; --- chain to save_write (loads at 0x0900 over us; returns to dpi via the resident loader) ---
    mov ax, (((core_save_write_phase_end - core_save_write_phase_start + 511) / 512) << 8) | \
            ((core_save_write_phase_start - $$) / 512)
    phase_jmp_res run_net_setup_phase

; es = the video segment (CGA 0xb800 / MDA 0xb000)
save_prep_video_es:
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .v_ok
    mov ax, 0xb000
.v_ok:
    mov es, ax
    ret

; 16-bit additive byte sum over [ds:si .. +cx) ADDED into bx. clobbers ax, si, cx.
save_prep_sum:
    jcxz .s_done
    mov al, [si]
    xor ah, ah
    add bx, ax
    inc si
    dec cx
    jmp save_prep_sum
.s_done:
    ret

; Fill save_rowlen_table (25 bytes): row_len[r] = column after the last non-blank (space) char in
; row r, 0 for a blank row. out: ax = sum of all row_len. Reads video. clobbers ax,bx,cx,dx,si,di,bp,es.
save_prep_rowlens:
    call save_prep_video_es
    xor dx, dx                       ; dx = row index
    xor di, di                       ; di = sum accumulator
    mov bp, save_rowlen_table
.rl_row:
    cmp dl, 25
    jae .rl_done
    mov al, dl
    mul byte [screen_cols]
    shl ax, 1
    mov si, ax                       ; si = video byte offset of (row, col 0)
    xor cx, cx                       ; cx = row_len so far
    xor bx, bx                       ; bx = current column
.rl_col:
    cmp bl, [screen_cols]
    jae .rl_col_done
    mov al, [es:si]
    cmp al, ' '
    je .rl_blank
    mov cx, bx
    inc cx                           ; row_len = col + 1
.rl_blank:
    add si, 2
    inc bx
    jmp .rl_col
.rl_col_done:
    mov [bp], cl                     ; store row_len (<= cols <= 80)
    inc bp
    add di, cx
    inc dx
    jmp .rl_row
.rl_done:
    mov ax, di
    push ds
    pop es
    ret

; bx += sum of the kept screen cells: for each row, its first row_len[r] cells (char+attr). Reads
; video + save_rowlen_table. clobbers ax,cx,dx,si,bp,es (preserves bx's accumulation).
save_prep_sum_cells:
    call save_prep_video_es
    xor dx, dx
    mov bp, save_rowlen_table
.sc_row:
    cmp dl, 25
    jae .sc_done
    mov al, dl
    mul byte [screen_cols]
    shl ax, 1
    mov si, ax
    mov cl, [bp]
    inc bp
    xor ch, ch
    shl cx, 1                        ; cx = row_len * 2 bytes
    jcxz .sc_next
.sc_cell:
    mov al, [es:si]
    xor ah, ah
    add bx, ax
    inc si
    loop .sc_cell
.sc_next:
    inc dx
    jmp .sc_row
.sc_done:
    push ds
    pop es
    ret

; Find the SEED/ENV.DAT entry (reuse) or the first free SEED-dir slot. Sets save_dir_lba/off and
; save_old_cluster (its first cluster, or 0 for a new file). save_write consumes these.
save_prep_find_dir_slot:
    mov word [save_old_cluster], 0
    mov word [save_dir_lba], 0
    call save_prep_find_seed_dir
    jc .fd_done
    mov ax, [fs_file_cluster]
    cmp ax, fat_first_data_cluster
    jb .fd_done
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    mov [fs_lba], ax
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [fs_lba]
    phase_call_res read_abs_sector
    jc .fd_done
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.fd_entry:
    mov al, [si]
    or al, al
    je .fd_free
    cmp al, 0xe5
    je .fd_free
    test byte [si + 11], 0x18
    jnz .fd_advance
    push si
    push cx
    mov di, PHASE_LOAD_ADDR + (save_prep_env_name - PHASE_BASE)
    mov cx, 11
.fd_cmp:
    mov al, [si]
    cmp al, [di]
    jne .fd_nomatch
    inc si
    inc di
    loop .fd_cmp
    pop cx
    pop si
    mov ax, [si + 26]
    mov [save_old_cluster], ax
    call save_prep_record_slot
    jmp .fd_done
.fd_nomatch:
    pop cx
    pop si
    jmp .fd_advance
.fd_free:
    cmp word [save_dir_lba], 0
    jne .fd_advance
    call save_prep_record_slot
    cmp byte [si], 0
    je .fd_done
.fd_advance:
    add si, fat_dir_entry_size
    loop .fd_entry
.fd_done:
    ret

save_prep_find_seed_dir:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
.sd_sector:
    cmp word [fs_root_left], 0
    je .sd_fail
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [fs_lba]
    phase_call_res read_abs_sector
    jc .sd_fail
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.sd_entry:
    mov al, [si]
    or al, al
    jz .sd_fail
    cmp al, 0xe5
    je .sd_advance
    test byte [si + 11], 0x10
    jz .sd_advance
    push si
    push cx
    mov di, PHASE_LOAD_ADDR + (save_prep_seed_name - PHASE_BASE)
    mov cx, 11
.sd_cmp:
    mov al, [si]
    cmp al, [di]
    jne .sd_nomatch
    inc si
    inc di
    loop .sd_cmp
    pop cx
    pop si
    mov ax, [si + 26]
    mov [fs_file_cluster], ax
    clc
    ret
.sd_nomatch:
    pop cx
    pop si
.sd_advance:
    add si, fat_dir_entry_size
    loop .sd_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .sd_sector
.sd_fail:
    stc
    ret

save_prep_record_slot:
    mov ax, [fs_lba]
    mov [save_dir_lba], ax
    mov ax, si
    sub ax, fs_sector_buffer
    mov [save_dir_off], ax
    ret

save_prep_seed_name db 'SEED       '
save_prep_env_name db 'ENV     DAT'

%unmacro phase_call_res 1
%unmacro phase_jmp_res 1
