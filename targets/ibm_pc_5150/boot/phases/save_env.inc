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

; Build 12 env save/load (notes/env-save-load-design.md), step 4: the $s SAVE path. Capture the
; user/agent environment -- the conversation window+arena (for the model) and a literal screen
; snapshot (the video text buffer, for the user) -- and write ENV.DAT to the boot drive. Cold phase,
; run by dpi after the tool phase flags save_pending; loads at net_setup_phase_start (0x0900). Uses
; fs_sector_buffer (0xD0E) for the FAT / data / root sectors, sequentially -- so this phase's code +
; data must end before fs_sector_buffer.
;
; FAT12 (grounded in build-fat12-image.py): 512 B/sector, 1 sector/cluster, a 1-sector FAT in TWO
; copies at LBA fat_fat_start_lba (5) and +1 (6), root at LBA 7 (4 sectors), data at LBA 11. Files
; are laid contiguously from cluster 2. We write ENV.DAT as a CONTIGUOUS run (the restore reads it
; contiguously): free any old ENV.DAT chain, find a free run of the needed length, room-check, set
; the chain + write both FAT copies, write the data sectors, then create/update the root entry.
; Best-effort: media read-only / no room / disk error -> a dim status line, never a crash.
fat_second_lba equ fat_fat_start_lba + 1

save_env_phase:
    mov byte [save_pending], 0       ; consume the request here (so dpi need not, saving its bytes)
    ; --- writability gate (the boot probe set handoff_flag_writable_media) ---
    test word [handoff_addr + handoff_flags], handoff_flag_writable_media
    jnz .writable
    mov si, save_msg_readonly
    jmp .status

.writable:
    ; --- geometry: region_len, screen_len, file_size, needed sectors ---
    mov ax, [handoff_addr + handoff_ram_top]
    sub ax, 0x100
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .rl_ready
    mov ax, loop_cache_start
.rl_ready:
    sub ax, chat_context_start
    mov [save_region_len], ax
    mov al, [screen_cols]
    mov ah, 25
    mul ah                           ; ax = cols * 25
    shl ax, 1                        ; * 2 (char+attr cells)
    mov [save_screen_len], ax
    add ax, [save_region_len]
    add ax, env_hdr_len
    mov [save_file_size], ax
    add ax, 511
    mov cl, 9
    shr ax, cl                       ; ceil(file_size / 512)
    mov [save_needed], ax

    call save_build_header           ; assemble the 0x18 header (+ both checksums) into save_header_buf

    ; --- locate ENV.DAT (to reuse + free its chain) or the first free root slot ---
    call save_find_dir_slot          ; sets save_dir_lba/off; save_old_cluster (0 = new file)

    ; --- read FAT copy 1, free any old chain, find a free contiguous run ---
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    phase_call_res read_abs_sector
    jc .err
    cmp word [save_old_cluster], 0
    je .no_old
    call save_free_chain             ; walk save_old_cluster, set entries 0 in the FAT buffer
.no_old:
    call save_find_run               ; CF=1 -> no contiguous run of save_needed free clusters
    jc .noroom
    call save_set_chain              ; link the run in the FAT buffer

    ; --- write both FAT copies (save_write_abs_sector preserves es:bx, so set them once) ---
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, fat_fat_start_lba
    call save_write_abs_sector
    jc .err
    mov ax, fat_second_lba
    call save_write_abs_sector
    jc .err

    ; --- write the data sectors (assemble each from header/window/screen, then write) ---
    call save_write_data
    jc .err

    ; --- create/update the root directory entry ---
    call save_write_dir
    jc .err

    mov si, save_msg_saved
    jmp .status
.noroom:
    mov si, save_msg_noroom
    jmp .status
.err:
    mov si, save_msg_diskerr
.status:
    ; Draw the dim, screen-only status line (si -> a PHASE-relative z-string), like the tool phase's
    ; "> read from .." line. api_stream_seen=1 makes dpi's render_prompt leave a gap + draw the next
    ; prompt below it. Loaded fresh each call -> no resident cost.
    add si, PHASE_LOAD_ADDR - PHASE_BASE  ; relocate the inline string to its load address
    mov byte [api_stream_seen], 1
    call save_scr_newline            ; di = fresh-line byte offset; es still = ds
    mov ax, [video_seg]
    mov es, ax
    mov ah, 0x08                     ; dim attr (CGA grey; MDA 0x07), hoisted out of the loop
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .st_next
    mov ah, 0x07
.st_next:
    lodsb                            ; al = char (ah = attr, preserved)
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
    push bx                          ; int 0x10 scroll can clobber bx/bp
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

; --- assemble the header into save_header_buf, including both checksums ---
save_build_header:
    push ds
    pop es
    mov di, PHASE_LOAD_ADDR + (save_header_buf - PHASE_BASE)
    mov ax, env_magic_w0
    stosw
    mov ax, env_magic_w1
    stosw
    mov al, env_format_current
    stosb
    xor al, al                       ; flags
    stosb
    mov ax, build_number
    stosw
    mov ax, [handoff_addr + handoff_ram_top]
    stosw
    mov ax, [chat_context_len_var]
    stosw
    mov ax, [chat_context_used]
    stosw
    mov ax, [note_len]
    stosw
    mov ax, [save_region_len]
    stosw
    mov al, [screen_cols]
    stosb
    mov al, 25
    stosb
    ; payload checksum = sum(window[0:region_len]) + sum(screen[0:screen_len]). save_sum sets bx;
    ; save_sum_es ADDS into bx (save_video_seg_es preserves bx), so bx accumulates both.
    mov si, chat_context_start
    mov cx, [save_region_len]
    call save_sum                    ; bx = window sum
    call save_video_seg_es           ; es = video segment (preserves bx)
    xor si, si
    mov cx, [save_screen_len]
    call save_sum_es                 ; bx += screen sum -> bx = window + screen
    push ds
    pop es                           ; restore es = ds
    mov di, PHASE_LOAD_ADDR + (save_header_buf + env_hdr_payload_checksum - PHASE_BASE)
    mov [di], bx                     ; payload_checksum
    ; header checksum = sum(header[0 .. env_hdr_checksum))
    mov si, PHASE_LOAD_ADDR + (save_header_buf - PHASE_BASE)
    mov cx, env_hdr_checksum
    call save_sum
    mov di, PHASE_LOAD_ADDR + (save_header_buf + env_hdr_checksum - PHASE_BASE)
    mov [di], bx
    ret

; 16-bit additive byte sum over [ds:si .. +cx). out: bx = sum. clobbers ax, si, cx.
save_sum:
    xor bx, bx
.s_next:
    jcxz .s_done
    mov al, [si]
    xor ah, ah
    add bx, ax
    inc si
    dec cx
    jmp .s_next
.s_done:
    ret
; like save_sum but reads [es:si]; ADDS into the incoming bx. clobbers ax, si, cx.
save_sum_es:
    jcxz .se_done
    mov al, [es:si]
    xor ah, ah
    add bx, ax
    inc si
    dec cx
    jmp save_sum_es
.se_done:
    ret

; es = the video segment (CGA 0xb800 / MDA 0xb000)
save_video_seg_es:
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .vs_ok
    mov ax, 0xb000
.vs_ok:
    mov es, ax
    ret

; --- find the ENV.DAT root entry (reuse) or the first free slot. sets save_dir_lba/off + ---
; --- save_old_cluster (its first cluster, or 0 for a new file). CF unused (always finds a slot ---
; --- on a non-full root; a full root falls through to .err at write time). ---
save_find_dir_slot:
    mov word [save_old_cluster], 0
    mov word [save_dir_lba], 0           ; 0 = no slot yet
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
.fd_sector:
    cmp word [fs_root_left], 0
    je .fd_done
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
    je .fd_free                          ; 0x00 = end of dir (and a usable free slot)
    cmp al, 0xe5
    je .fd_free                          ; deleted = usable free slot
    test byte [si + 11], 0x18
    jnz .fd_advance                      ; volume/subdir
    ; compare the name to ENV     DAT
    push si
    push cx
    mov di, PHASE_LOAD_ADDR + (save_env_name - PHASE_BASE)
    mov cx, 11
.fd_cmp:
    mov al, [si]
    cmp al, [di]
    jne .fd_nomatch
    inc si
    inc di
    loop .fd_cmp
    pop cx
    pop si                               ; existing ENV.DAT -> reuse this slot, free its chain
    mov ax, [si + 26]
    mov [save_old_cluster], ax
    call save_record_slot
    jmp .fd_done                         ; an existing match is final
.fd_nomatch:
    pop cx
    pop si
    jmp .fd_advance
.fd_free:
    cmp word [save_dir_lba], 0           ; remember only the FIRST free slot
    jne .fd_advance
    call save_record_slot
    cmp byte [si], 0
    je .fd_done                          ; 0x00 end-of-dir: no entries beyond -> stop scanning
.fd_advance:
    add si, fat_dir_entry_size
    loop .fd_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .fd_sector
.fd_done:
    ret
; record the slot at [fs_lba]:si (si points into fs_sector_buffer) into save_dir_lba/off
save_record_slot:
    mov ax, [fs_lba]
    mov [save_dir_lba], ax
    mov ax, si
    sub ax, fs_sector_buffer
    mov [save_dir_off], ax
    ret

; --- free the old ENV.DAT cluster chain in the FAT buffer (walk first..EOF, set each to 0) ---
save_free_chain:
    mov ax, [save_old_cluster]
.fc_next:
    cmp ax, fat_first_data_cluster
    jb .fc_done
    cmp ax, 0x0ff8
    jae .fc_done
    push ax                              ; [cur]
    call save_get_fat                    ; ax = next cluster
    pop bx                               ; bx = cur (hold it)
    push ax                              ; [next]
    mov ax, bx                           ; ax = cur
    xor dx, dx                           ; value 0 (save_put_fat takes the value in DX)
    call save_put_fat                    ; FAT[cur] = 0
    pop ax                               ; ax = next
    jmp .fc_next
.fc_done:
    ret

; --- find a contiguous run of save_needed free (0x000) clusters; save_run_start = first; CF=1 none ---
save_find_run:
    mov si, fat_first_data_cluster       ; current cluster
    xor di, di                           ; run length so far
    mov word [save_run_start], 0
.fr_next:
    cmp si, fat_max_cluster
    ja .fr_fail
    mov ax, si
    call save_get_fat
    or ax, ax
    jne .fr_reset
    inc di                               ; free -> extend the run
    cmp di, 1
    jne .fr_have
    mov [save_run_start], si             ; first free of this run
.fr_have:
    cmp di, [save_needed]
    jae .fr_ok
    inc si
    jmp .fr_next
.fr_reset:
    xor di, di                           ; occupied -> run broken
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
    inc dx                               ; next = cluster + 1
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
    add bx, ax                           ; bx = cluster + cluster/2
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
    shl dx, cl                           ; value into bits 4..15
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

; --- write the data sectors: for each of save_needed sectors, assemble it (header/window/screen) ---
; --- into fs_sector_buffer, then write to its data LBA. CF on a write error. ---
save_write_data:
    xor bp, bp                           ; bp = file offset of the current sector
    mov word [save_sector_index], 0
.wd_next:
    mov ax, [save_sector_index]
    cmp ax, [save_needed]
    jae .wd_done
    call save_video_seg_es               ; es = video (assembly reads screen via es; window via ds)
    call save_assemble_sector            ; fills fs_sector_buffer from file offset bp
    push ds
    pop es                               ; es = ds for the write
    mov bx, fs_sector_buffer
    ; LBA = fat_data_start_lba + (run_start - 2) + sector_index
    mov ax, [save_run_start]
    add ax, [save_sector_index]
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    call save_write_abs_sector
    jc .wd_fail
    add bp, 512
    inc word [save_sector_index]
    jmp .wd_next
.wd_done:
    clc
    ret
.wd_fail:
    stc
    ret

; assemble the 512-byte sector at file offset bp into fs_sector_buffer. es = video segment (for the
; screen bytes); ds = 0 (header + window). clobbers ax, bx, cx, di, dx (preserves bp, es, si-free).
save_assemble_sector:
    mov di, 0
    mov dx, bp
.as_next:
    call save_file_byte                  ; in dx=file offset, es=video; out al
    mov bx, di
    mov [fs_sector_buffer + bx], al
    inc dx
    inc di
    cmp di, 512
    jb .as_next
    ret
; the file byte at file offset dx -> al. es = video segment. clobbers bx (not dx).
save_file_byte:
    cmp dx, env_hdr_len
    jae .fb_payload
    mov bx, dx
    mov al, [PHASE_LOAD_ADDR + (save_header_buf - PHASE_BASE) + bx]
    ret
.fb_payload:
    mov bx, dx
    sub bx, env_hdr_len
    cmp bx, [save_region_len]
    jae .fb_screen
    mov al, [chat_context_start + bx]
    ret
.fb_screen:
    sub bx, [save_region_len]
    cmp bx, [save_screen_len]
    jae .fb_zero
    mov al, [es:bx]
    ret
.fb_zero:
    xor al, al
    ret

; --- create/update the root entry at save_dir_lba:save_dir_off ---
save_write_dir:
    cmp word [save_dir_lba], 0
    je .wdir_fail                        ; no slot found (full root)
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [save_dir_lba]
    phase_call_res read_abs_sector
    jc .wdir_fail
    mov di, fs_sector_buffer
    add di, [save_dir_off]
    ; name (11), attr (archive), then zero through offset 26
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
    mov [di + 28], ax                    ; size low (size-high already zeroed above)
    mov bx, fs_sector_buffer
    mov ax, [save_dir_lba]
    call save_write_abs_sector
    ret
.wdir_fail:
    stc
    ret

; --- write one sector: es:bx -> LBA ax. CHS via the resident geometry; AH=03h. CF on error. ---
save_write_abs_sector:                   ; clobbers ax,cx,dx (no caller needs them after); CF on error
    div byte [fs_sectors_per_track]      ; al=track, ah=sector-in-track
    mov cl, ah
    inc cl
    mov ah, 0
    div byte [fs_heads]                  ; al=cylinder, ah=head
    mov ch, al
    mov dh, ah
    mov dl, [handoff_addr + handoff_boot_drive]
    mov ax, 0x0301
    int 0x13
    ret

save_env_name db 'ENV     DAT'

; save_region_len/screen_len/file_size/needed/run_start/sector_index/dir_lba/dir_off/old_cluster
; live in fixed low scratch (data.inc) -- NOT inline here, else they assemble above the RAM ceiling
; and are accessed at the wrong (absolute) address. Only save_header_buf + save_env_name stay inline
; (read/written via PHASE_LOAD_ADDR + (x - PHASE_BASE), so they correctly track the load address).
save_header_buf    times env_hdr_len db 0

%unmacro phase_call_res 1
