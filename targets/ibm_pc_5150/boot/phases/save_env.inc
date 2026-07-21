%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name the runtime load address (net_setup_phase_start)"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

; Build 12 env save/load (design: docs/architecture.md, "Persistence"), SAVE part 2 of 2: WRITE. save_prep has
; already filled the scratch (region_len/region_stored, screen_stored, file_size, payload checksum,
; the per-row screen row-length table). This phase does the FAT12 write to the boot drive: locate
; SEED/ENV.DAT (reuse) or a free SEED-dir slot, free any old chain, find a contiguous free run, set the chain,
; write both FAT copies, EMIT the trimmed payload sequentially into the data sectors, then the SEED
; directory entry. Loads at net_setup_phase_start (0x0900) and USES fs_sector_buffer (0xD0E) -- hence the 2-sector
; ceiling. Best-effort: read-only / no room / disk error -> a dim status line, never a crash.
;
; The payload is emitted byte-stream style (save_emit_byte buffers into fs_sector_buffer, flushing a
; full sector at 512): the 28-byte header (built inline, header checksum summed over its first 26
; bytes), then the region prefix (region_stored bytes from chat_pool_start), then the encoded
; screen (the 25-byte row-length table, then each row's row_len char+attr cells from video).
fat_second_lba equ fat_fat_start_lba + 1

save_write_phase:
    ; --- writability gate (the boot probe set handoff_flag_writable_media) ---
    test word [handoff_addr + handoff_flags], handoff_flag_writable_media
    jnz .writable
    mov si, save_msg_readonly
    jmp .status
.writable:
    mov ax, [save_file_size]             ; needed sectors = ceil(file_size / 512)
    add ax, 511
    mov cl, 9
    shr ax, cl
    mov [save_needed], ax

    cmp word [save_dir_lba], 0           ; save_prep found SEED/ENV.DAT or a free SEED-dir slot
    je .err

    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    phase_call_res read_abs_sector
    jc .err
    cmp word [save_old_cluster], 0
    je .no_old
    call save_free_chain                 ; free any existing ENV.DAT chain in the FAT buffer
.no_old:
    call save_find_run                   ; CF=1 -> no contiguous run of save_needed free clusters
    jc .noroom
    call save_set_chain

    push ds                              ; write both FAT copies (save_write_abs_sector keeps es:bx)
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    call save_write_abs_sector
    jc .err
    mov ax, fat_second_lba
    call save_write_abs_sector
    jc .err

    call save_emit_data                  ; stream header + region + encoded screen into the data sectors
    jc .err

    call save_write_dir                  ; create/update the SEED/ directory entry
    jc .err

    mov si, save_msg_saved
    jmp .status
.noroom:
    mov si, save_msg_noroom
    jmp .status
.err:
    mov si, save_msg_diskerr
.status:
    ; Draw the dim, screen-only status line (si -> a PHASE-relative z-string). api_stream_seen=1 makes
    ; dpi's render_prompt leave a gap + draw the next prompt below it.
    add si, PHASE_LOAD_ADDR - PHASE_BASE
    mov byte [api_stream_seen], 1
    call save_scr_newline                ; di = fresh-line byte offset; es still = ds
    call save_video_seg_es               ; es = video segment
    mov ah, [menu_idle_attr]
.st_next:
    lodsb
    or al, al
    jz .st_done
    stosw
    jmp .st_next
.st_done:
    push ds
    pop es
    ret

; advance to a fresh screen line (scroll the bottom text area if at the prompt row), di = its byte
; offset, track cursor_row so dpi draws the next prompt below. Mirrors tool_call .scr_newline.
save_scr_newline:
    cmp byte [cursor_row], dpi_prompt_row
    jb .nl_inc
    push bx
    push bp
    mov ah, 0x06
    mov al, 1
    mov bh, 0x07
    mov cx, 0x0100
    mov dh, dpi_prompt_row
    mov dl, [screen_cols]
    dec dl
    int 0x10
    pop bp
    pop bx
    mov byte [cursor_row], dpi_prompt_row - 1
.nl_inc:
    inc byte [cursor_row]
    mov al, [screen_cols]
    mul byte [cursor_row]
    shl ax, 1
    mov di, ax
    mov byte [cursor_col], 0
    ret

save_msg_saved    db '> saved', 0
save_msg_noroom   db '> no room', 0
save_msg_readonly db '> read-only', 0
save_msg_diskerr  db '> failed', 0

; es = the video segment (CGA 0xb800 / MDA 0xb000)
save_video_seg_es:
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .vs_ok
    mov ax, 0xb000
.vs_ok:
    mov es, ax
    ret

; --- free the old ENV.DAT cluster chain in the FAT buffer (walk first..EOF, set each to 0) ---
save_free_chain:
    mov ax, [save_old_cluster]
.fc_next:
    cmp ax, fat_first_data_cluster
    jb .fc_done
    cmp ax, 0x0ff8
    jae .fc_done
    push ax
    call save_get_fat
    pop bx
    push ax
    mov ax, bx
    xor dx, dx
    call save_put_fat
    pop ax
    jmp .fc_next
.fc_done:
    ret

; --- find a contiguous run of save_needed free (0x000) clusters; save_run_start = first; CF=1 none ---
save_find_run:
    mov si, fat_first_data_cluster
    xor di, di
    mov word [save_run_start], 0
.fr_next:
    cmp si, fat_max_cluster
    ja .fr_fail
    mov ax, si
    call save_get_fat
    or ax, ax
    jne .fr_reset
    inc di
    cmp di, 1
    jne .fr_have
    mov [save_run_start], si
.fr_have:
    cmp di, [save_needed]
    jae .fr_ok
    inc si
    jmp .fr_next
.fr_reset:
    xor di, di
    inc si
    jmp .fr_next
.fr_ok:
    clc
    ret
.fr_fail:
    stc
    ret

; --- set the FAT chain for the run: each cluster -> next, last -> 0x0fff ---
save_set_chain:
    mov si, [save_run_start]
    mov di, [save_needed]
.sc_next:
    cmp di, 1
    je .sc_last
    mov ax, si
    mov dx, si
    inc dx
    call save_put_fat
    inc si
    dec di
    jmp .sc_next
.sc_last:
    mov ax, si
    mov dx, 0x0fff
    call save_put_fat
    ret

; FAT12 entry read: in ax=cluster; out ax=12-bit value. FAT in fs_sector_buffer. clobbers bx,cx,dx.
save_get_fat:
    mov bx, ax
    shr bx, 1
    add bx, ax
    mov dx, [fs_sector_buffer + bx]
    test al, 1
    jz .gf_even
    mov cl, 4
    shr dx, cl
.gf_even:
    and dx, 0x0fff
    mov ax, dx
    ret
; FAT12 entry write: in ax=cluster, dx=12-bit value. modifies fs_sector_buffer. clobbers bx,cx.
save_put_fat:
    mov bx, ax
    shr bx, 1
    add bx, ax
    test al, 1
    jz .pf_even
    mov cl, 4
    shl dx, cl
    mov ax, [fs_sector_buffer + bx]
    and ax, 0x000f
    or ax, dx
    mov [fs_sector_buffer + bx], ax
    ret
.pf_even:
    mov ax, [fs_sector_buffer + bx]
    and ax, 0xf000
    or ax, dx
    mov [fs_sector_buffer + bx], ax
    ret

; ---------------- sequential payload emit (header + region prefix + encoded screen) ----------------
; emit one byte (al) into the sector buffer; flush a full sector at 512. CF on a write error.
; Preserves ax/bx/cx/dx/si/bp/es so the emit loops keep their counters across a flush (the flush's
; save_write_abs_sector clobbers ax/cx/dx). ax's HIGH byte survives; al is the input.
save_emit_byte:
    push es
    push bx
    push cx
    push dx
    push ds
    pop es
    mov bx, [save_buf_idx]
    mov [fs_sector_buffer + bx], al
    inc bx
    mov [save_buf_idx], bx
    cmp bx, 512
    jb .eb_ok
    call save_emit_flush_sector          ; CF from the sector write
    jmp .eb_done
.eb_ok:
    clc
.eb_done:
    pop dx
    pop cx
    pop bx
    pop es
    ret

; write the full fs_sector_buffer to the current data LBA; on success reset save_buf_idx + advance the
; sector index. CF on a write error. (es is already ds via the caller.)
save_emit_flush_sector:                  ; save_write_abs_sector preserves si/bx, so no save needed
    mov bx, fs_sector_buffer
    mov ax, [save_run_start]
    add ax, [save_sector_index]
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    call save_write_abs_sector
    jc .ffs_done
    inc word [save_sector_index]
    mov word [save_buf_idx], 0
.ffs_done:
    ret

; emit ax as two bytes, little-endian (used only for the header; never flushes -> ax survives).
save_emit_word:
    call save_emit_byte                  ; al = low byte
    mov al, ah
    call save_emit_byte                  ; high byte
    ret

save_emit_data:
    xor ax, ax
    mov [save_buf_idx], ax
    mov [save_sector_index], ax
    call save_emit_header                ; 28-byte header (< 512, no flush) into the buffer head
    ; --- region prefix (region_stored bytes from chat_pool_start) ---
    mov si, chat_pool_start
    mov cx, [save_region_stored]
.ed_region:
    jcxz .ed_table
    mov al, [si]
    call save_emit_byte
    jc .ed_fail
    inc si
    dec cx
    jmp .ed_region
    ; --- encoded screen: the 25-byte row-length table, then packed cells ---
.ed_table:
    mov si, save_rowlen_table
    mov cx, 25
.ed_tnext:
    jcxz .ed_cells
    mov al, [si]
    call save_emit_byte
    jc .ed_fail
    inc si
    dec cx
    jmp .ed_tnext
.ed_cells:
    call save_video_seg_es               ; es = video (cells read via es:si)
    xor dx, dx                           ; dx = row index
    mov bp, save_rowlen_table
.ec_row:
    cmp dl, 25
    jae .ec_done
    mov al, dl
    mul byte [screen_cols]
    shl ax, 1
    mov si, ax                           ; si = video byte offset of (row, col 0)
    mov cl, [bp]
    inc bp
    xor ch, ch
    shl cx, 1                            ; row_len * 2 bytes
.ec_byte:
    jcxz .ec_next
    mov al, [es:si]
    call save_emit_byte                  ; preserves es (video), si, cx, dx, bp
    jc .ed_fail
    inc si
    dec cx
    jmp .ec_byte
.ec_next:
    inc dx
    jmp .ec_row
.ec_done:
    push ds
    pop es
    call save_emit_flush                 ; flush the final partial sector
    ret
.ed_fail:
    stc
    ret

; build the 28-byte header into the buffer head, then the header checksum over its first 26 bytes.
save_emit_header:
    mov ax, env_magic_w0
    call save_emit_word
    mov ax, env_magic_w1
    call save_emit_word
    mov al, env_format_current
    call save_emit_byte
    xor al, al                           ; flags
    call save_emit_byte
    mov ax, build_number
    call save_emit_word
    mov ax, [handoff_addr + handoff_ram_top]
    call save_emit_word
    mov ax, [chat_context_len_var]
    call save_emit_word
    mov ax, [chat_context_used]
    call save_emit_word
    mov ax, [note_len]
    call save_emit_word
    mov ax, [save_region_len]
    call save_emit_word
    mov ax, [save_region_stored]
    call save_emit_word
    mov al, [screen_cols]
    call save_emit_byte
    mov al, 25                           ; screen_rows
    call save_emit_byte
    mov ax, [save_screen_stored]
    call save_emit_word
    mov ax, [save_payload_ck]
    call save_emit_word
    ; save_buf_idx == env_hdr_checksum (26) now; header checksum = sum of those bytes.
    xor bx, bx
    xor si, si
.hc_sum:
    cmp si, env_hdr_checksum
    jae .hc_done
    mov al, [fs_sector_buffer + si]
    xor ah, ah
    add bx, ax
    inc si
    jmp .hc_sum
.hc_done:
    mov ax, bx
    jmp save_emit_word                   ; emit header_checksum (tail call)

; flush the final partial sector: pad [save_buf_idx .. 512) with 0, write it. CF on error.
save_emit_flush:
    cmp word [save_buf_idx], 0
    je .fl_done
    push ds
    pop es
    mov di, fs_sector_buffer
    add di, [save_buf_idx]
    mov cx, 512
    sub cx, [save_buf_idx]
    xor al, al
    rep stosb
    jmp save_emit_flush_sector           ; write the padded sector (tail call; CF propagates)
.fl_done:
    clc
    ret

; --- create/update the SEED/ directory entry at save_dir_lba:save_dir_off ---
save_write_dir:
    cmp word [save_dir_lba], 0
    je .wdir_fail
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [save_dir_lba]
    phase_call_res read_abs_sector
    jc .wdir_fail
    mov di, fs_sector_buffer
    add di, [save_dir_off]
    push di
    mov si, PHASE_LOAD_ADDR + (save_env_name - PHASE_BASE)
    mov cx, 11
    rep movsb
    mov al, 0x20                         ; attribute: archive
    stosb
    xor ax, ax
    mov cx, 10                           ; zero offsets 12..31 (reserved/time/date AND size-high)
    rep stosw
    pop di
    mov ax, [save_run_start]
    mov [di + 26], ax                    ; first cluster
    mov ax, [save_file_size]
    mov [di + 28], ax                    ; size low (size-high zeroed above)
    mov bx, fs_sector_buffer
    mov ax, [save_dir_lba]
    call save_write_abs_sector
    ret
.wdir_fail:
    stc
    ret

; --- write one sector: es:bx -> LBA ax. CHS via the resident geometry; AH=03h. CF on error. ---
save_write_abs_sector:                   ; clobbers ax,cx,dx; CF on error
    div byte [fs_sectors_per_track]
    mov cl, ah
    inc cl
    mov ah, 0
    div byte [fs_heads]
    mov ch, al
    mov dh, ah
    mov dl, [handoff_addr + handoff_boot_drive]
    mov ax, 0x0301
    int 0x13
    ret

save_env_name db 'ENV     DAT'

%unmacro phase_call_res 1
