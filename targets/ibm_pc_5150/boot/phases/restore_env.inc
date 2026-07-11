%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

; Build 12 env save/load (design: docs/architecture.md, "Persistence"), step 3: restore a saved environment from
; the boot drive at boot, BEFORE the cold greeting. Hooked into prepare_agent_path: CF=0 here => the
; window is populated + the screen repainted, and the caller SKIPS the greeting; CF=1 => no/invalid
; save, the caller falls through to the normal greeting. Restore is a READ, so it is NOT gated on
; writable media.
;
; ENV.DAT carries two things for two audiences: the arena+conversation window ("region") for the MODEL
; (restored into chat_pool_start, with context at the far end), and a literal screen snapshot (the video
; text buffer) for the USER (painted back verbatim so they land on the exact screen they left).
; FAIL-SAFE: the whole file is staged at env_restore_stage (0x1800, the not-yet-loaded K
; window) and validated there (magic / format / header checksum / fit / payload checksum) BEFORE any
; byte is copied into the window or video memory. Any failure returns CF=1 with the boot-empty window
; intact. (The fit MENU for bigger-machine/won't-fit is step 3c; here a misfit just returns CF=1.)
restore_env_phase:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
.scan_sector:
    cmp word [fs_root_left], 0
    je .fail
    push ds
    pop es
    mov bx, env_restore_stage
    mov ax, [fs_lba]
    phase_call_res read_abs_sector
    jc .fail
    mov si, env_restore_stage
    mov cx, fat_dir_entries_per_sector
.scan_entry:
    mov al, [si]
    or al, al
    jz .fail                         ; 0x00 = end of directory -> no ENV.DAT
    cmp al, 0xe5
    je .scan_advance                 ; deleted entry
    test byte [si + 11], 0x18        ; skip volume label / subdirectory
    jnz .scan_advance
    push si
    push cx
    mov di, low_scratch_start + (restore_env_name - PHASE_BASE)
    mov cx, 11
.scan_cmp:
    mov al, [si]
    cmp al, [di]
    jne .scan_mismatch
    inc si
    inc di
    loop .scan_cmp
    pop cx
    pop si                           ; si = matched entry base
    mov ax, [si + 26]
    mov [fs_file_cluster], ax
    mov ax, [si + 28]
    mov [fs_file_size_low], ax
    mov ax, [si + 30]
    mov [fs_file_size_high], ax
    jmp .found
.scan_mismatch:
    pop cx
    pop si
.scan_advance:
    add si, fat_dir_entry_size
    loop .scan_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .scan_sector

.found:
    ; size sanity before any staging read: high word zero, low in [hdr_len .. max]
    cmp word [fs_file_size_high], 0
    jne .fail
    mov ax, [fs_file_size_low]
    cmp ax, env_hdr_len
    jb .fail
    cmp ax, env_restore_max_size
    ja .fail
    ; first data LBA = (cluster - 2) + fat_data_start_lba
    mov ax, [fs_file_cluster]
    cmp ax, fat_first_data_cluster
    jb .fail
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    mov si, ax                       ; si = running LBA (read_abs_sector preserves si)
    ; sector count = ceil(size_low / 512) = (size_low + 511) >> 9
    mov cx, [fs_file_size_low]
    add cx, 511
    mov cl, ch
    xor ch, ch                       ; cx = (size+511) >> 8
    shr cx, 1                        ; cx = (size+511) >> 9
    mov di, env_restore_stage
.read_loop:
    push ds
    pop es
    mov bx, di
    mov ax, si
    phase_call_res read_abs_sector
    jc .fail
    add di, 512
    inc si
    loop .read_loop

    ; --- validate entirely in the staging buffer ---
    mov ax, [env_restore_stage + env_hdr_magic]
    cmp ax, env_magic_w0
    jne .fail
    mov ax, [env_restore_stage + env_hdr_magic + 2]
    cmp ax, env_magic_w1
    jne .fail
    mov al, [env_restore_stage + env_hdr_format]
    cmp al, env_format_min
    jb .fail
    cmp al, env_format_current
    ja .fail
    mov si, env_restore_stage
    mov cx, env_hdr_checksum         ; sum header bytes [0 .. env_hdr_checksum)
    call restore_env_sum
    cmp ax, [env_restore_stage + env_hdr_checksum]
    jne .fail
    ; region_len fit: <= this machine's pool (ceiling - chat_pool_start). ceiling mirrors
    ; hardware_setup: loop_cache_start on a 32K direct boot, else ram_top - the 0x100 stack reserve.
    mov ax, [handoff_addr + handoff_ram_top]
    sub ax, 0x100
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .pool_ready
    mov ax, loop_cache_start
.pool_ready:
    sub ax, chat_pool_start          ; ax = this machine's pool (arena+window bytes)
    mov [fs_bytes_left], ax          ; current pool length, used by the commit copy below
    ; Build 12 step 3c, fit gate (non-interactive). region_len vs pool:
    ;   >  pool : won't fit -> dim error line + clean boot (the save needs a bigger machine)
    ;   == pool : silent restore (the common same-machine case, incl. every same-machine $l revert)
    ;   <  pool : bigger machine than when saved -> restore with the saved context cap + a dim warning
    ;             (surplus RAM lands as arena; arena programs keep their old addresses). The warn flag
    ;             rides fs_current_cluster -- free
    ;             during restore (we read by LBA, not by cluster-walk) and untouched by the commit/paint.
    mov byte [fs_current_cluster], 0
    mov dx, [env_restore_stage + env_hdr_region_len]
    cmp dx, ax
    ja .too_big
    je .fit_checked
    mov byte [fs_current_cluster], 1 ; region_len < pool -> warn
.fit_checked:
    mov ax, [env_restore_stage + env_hdr_window_cap]
    cmp ax, [env_restore_stage + env_hdr_region_len]
    ja .fail
    ; Format 2: payload = region_stored + screen_stored bytes (both trimmed). It must match the staged
    ; file size, and its checksum the header field.
    mov ax, [env_restore_stage + env_hdr_region_stored]
    add ax, [env_restore_stage + env_hdr_screen_stored]
    mov bx, ax                       ; bx = payload byte count
    add ax, env_hdr_len
    cmp ax, [fs_file_size_low]
    ja .fail
    mov si, env_restore_stage + env_hdr_len
    mov cx, bx
    call restore_env_sum
    cmp ax, [env_restore_stage + env_hdr_payload_checksum]
    jne .fail

    ; --- valid: commit the region. CLEAR the full current pool first. Then split the saved prefix:
    ; arena bytes restore at chat_pool_start, context bytes restore at the current top-of-pool context
    ; base. On a larger machine, the extra space naturally lands in the arena gap below context. ---
    push ds
    pop es
    mov ax, [env_restore_stage + env_hdr_window_cap]
    mov [chat_context_len_var], ax
    mov dx, [env_restore_stage + env_hdr_region_len]
    sub dx, ax                       ; dx = saved arena prefix length
    mov [fs_bytes_this], dx
    mov di, chat_pool_start
    mov cx, [fs_bytes_left]
    xor al, al
    rep stosb
    mov si, env_restore_stage + env_hdr_len
    mov di, chat_pool_start
    mov cx, [env_restore_stage + env_hdr_region_stored]
    mov dx, [fs_bytes_this]
    cmp cx, dx
    jbe .arena_count_ready
    mov cx, dx
.arena_count_ready:
    rep movsb
    mov cx, [env_restore_stage + env_hdr_region_stored]
    sub cx, [fs_bytes_this]
    jbe .region_done
    call .context_base_di
    rep movsb
.region_done:
    mov ax, [env_restore_stage + env_hdr_used]
    mov [chat_context_used], ax
    mov ax, [env_restore_stage + env_hdr_note_len]
    mov [note_len], ax
    call restore_env_paint_screen    ; repaint the saved screen (for the user)
    cmp byte [fs_current_cluster], 0 ; bigger-machine warning?
    je .restored
    ; Bigger machine than when saved: the restore succeeded silently; surface a dim "> " system line
    ; at the dpi prompt (NOT a boot banner) so the user sees it once they land in DPI -- mirrors the
    ; "> saved" line. paint_screen left the cursor at dpi_prompt_row-2; draw the line there and set
    ; api_stream_seen so dpi's render_prompt leaves a gap and draws the prompt below it.
    mov si, low_scratch_start + (restore_warn_text - PHASE_BASE)
    call restore_env_warn_line
    mov byte [api_stream_seen], 1
.restored:
    clc
    ret

.context_base_di:
    mov di, [handoff_addr + handoff_ram_top]
    sub di, 0x100
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .ctx_base_ready
    mov di, loop_cache_start
.ctx_base_ready:
    sub di, [chat_context_len_var]
    ret

; Build 12 step 3c (error): the saved region needs more pool than this machine has. Per the UI
; unification this is the one INTERACTIVE restore case, rendered in the single terminal style
; (mirrors failure_action): a dim "> environment needs <N> more RAM" system line, then the agent
; asks "start new or restart?" as a numbered list answered like the provider list -- type a number
; OR the full name, Enter; anything else -> dim "> incorrect option" + re-prompt. "start new" ->
; CF=1 (caller falls through to the normal greeting); "restart" warm-reboots (a chance to swap to a
; machine the save fits, or different media). No silent data loss. No centered menu / arrow toggle.
; ax = pool, dx = region_len here (from the fit cmp); stash the SHORTFALL (extra RAM needed) in
; fs_current_cluster (free in this path) for the message.
.too_big:
    sub dx, ax                       ; dx = region_len - pool = extra RAM the save needs
    mov [fs_current_cluster], dx
    call .tb_newline
    mov bl, [menu_idle_attr]
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    mov si, low_scratch_start + (restore_toobig_text - PHASE_BASE)
    mov bl, [menu_idle_attr]
    call .print_z                    ; "environment needs "
    mov ax, [fs_current_cluster]     ; the shortfall (extra RAM needed vs this machine)
    mov bl, [menu_idle_attr]
    call .print_size                 ; "<n> <unit>"
    mov si, low_scratch_start + (restore_more_text - PHASE_BASE)
    mov bl, [menu_idle_attr]
    call .print_z                    ; " more RAM"
.tb_prompt:
    call .tb_newline
    call .tb_newline                 ; blank line before the agent question
    mov si, low_scratch_start + (restore_toobig_q_text - PHASE_BASE)
    mov bl, 0x07
    call .print_z                    ; "start new or restart?"
    mov al, '1'
    mov si, low_scratch_start + (restore_fresh_text - PHASE_BASE)
    call .tb_option                  ; "1. start new"
    mov al, '2'
    mov si, low_scratch_start + (restore_restart_text - PHASE_BASE)
    call .tb_option                  ; "2. restart"
    call .tb_newline
    call .tb_newline                 ; blank line before the prompt
    call .tb_read_line
    cmp byte [input_len], 1          ; a single digit 1 (start new) / 2 (restart)?
    jne .tb_by_name
    mov al, [dpi_input_buf]
    cmp al, '1'
    je .fail
    cmp al, '2'
    je .tb_restart
.tb_by_name:
    mov si, low_scratch_start + (restore_fresh_text - PHASE_BASE)
    mov di, dpi_input_buf
    call .tb_streq
    je .fail
    mov si, low_scratch_start + (restore_restart_text - PHASE_BASE)
    mov di, dpi_input_buf
    call .tb_streq
    je .tb_restart
    call .tb_newline
    mov bl, [menu_idle_attr]
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    mov si, low_scratch_start + (restore_incorrect_text - PHASE_BASE)
    mov bl, [menu_idle_attr]
    call .print_z                    ; "incorrect option"
    jmp .tb_prompt
.tb_restart:
    mov word [0x0472], 0x1234        ; restart -> warm-boot flag + reset vector
    jmp 0xffff:0x0000
.fail:
    stc
    ret

.tb_option:                          ; al = digit, si = label -> newline + "N. label" (normal 0x07)
    push ax                           ; .tb_newline clobbers al -- save the digit
    call .tb_newline
    pop ax
    push si
    mov bl, 0x07
    phase_call_res print_char
    mov al, '.'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    pop si
    mov bl, 0x07
    call .print_z
    ret

.tb_read_line:                       ; read a line into dpi_input_buf; text echoes white; Enter
    mov word [input_target], dpi_input_buf ; finishes and erases the "> " marker (DPI-style)
    mov byte [input_max], 12
    mov byte [input_len], 0
    mov byte [dpi_input_buf], 0
    call .tb_show_cursor
    mov al, [cursor_row]
    mov [menu_index], al
    mov bl, [ready_attr]
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
.tb_rl_loop:
    call .tb_sync_cursor
    xor ah, ah
    int 0x16
    cmp al, 0x0d
    je .tb_rl_done
    cmp al, 0x08
    je .tb_rl_bs
    cmp al, 0x20
    jb .tb_rl_loop
    cmp al, 0x7e
    ja .tb_rl_loop
    mov bl, [input_len]
    xor bh, bh
    mov dl, [input_max]
    dec dl
    cmp bl, dl
    jae .tb_rl_loop
    mov di, [input_target]
    add di, bx
    mov [di], al
    inc byte [input_len]
    mov byte [di + 1], 0
    mov bl, 0x0f
    phase_call_res print_char
    jmp .tb_rl_loop
.tb_rl_bs:
    cmp byte [input_len], 0
    je .tb_rl_loop
    dec byte [input_len]
    mov bl, [input_len]
    xor bh, bh
    mov di, [input_target]
    add di, bx
    mov byte [di], 0
    dec byte [cursor_col]
    mov al, ' '
    mov bl, 0x0f
    phase_call_res print_char
    dec byte [cursor_col]
    jmp .tb_rl_loop
.tb_rl_done:
    call .tb_hide_cursor
    mov al, [cursor_row]
    mov ah, [cursor_col]
    push ax
    mov al, [menu_index]
    mov [cursor_row], al
    mov byte [cursor_col], 0
    mov al, ' '
    mov bl, 0x07
    phase_call_res print_char
    pop ax
    mov [cursor_row], al
    mov [cursor_col], ah
    call .tb_newline
    ret

.tb_streq:                           ; compare [ds:si] vs [ds:di] (NUL-term) -> ZF=1 if equal
    push si
    push di
.tb_streq_loop:
    mov al, [si]
    cmp al, [di]
    jne .tb_streq_done
    or al, al
    jz .tb_streq_done
    inc si
    inc di
    jmp .tb_streq_loop
.tb_streq_done:
    pop di
    pop si
    ret

.tb_show_cursor:
    mov cx, 0x0607
    jmp .tb_apply_cursor_shape
.tb_hide_cursor:
    mov cx, 0x2000
.tb_apply_cursor_shape:
    mov ah, 0x01
    int 0x10
    ret

.tb_sync_cursor:
    mov ah, 0x02
    xor bh, bh
    mov dh, [cursor_row]
    mov dl, [cursor_col]
    int 0x10
    ret

.tb_newline:
    mov byte [cursor_col], 0
    mov al, [cursor_row]
    cmp al, dpi_prompt_row
    jb .tb_nl_down
    mov ax, 0x0601
    mov cx, 0x0100
    phase_call_res scroll_text_area
    ret
.tb_nl_down:
    inc byte [cursor_row]
    ret

; print ax (a byte count) as "<decimal> <unit>" at the cursor (attr bl), via print_char. Collapses
; by 1024s through B/KB/MB/GB (floor). A 16-bit count reaches B/KB today; MB/GB are ready for a
; future wider-RAM port. clobbers ax, cx, dx, si.
.print_size:
    xor dx, dx                       ; dx = unit index (0=B)
.ps_loop:
    cmp ax, 1024
    jb .ps_emit
    push dx
    mov cl, 10
    shr ax, cl                       ; / 1024
    pop dx
    inc dx
    jmp .ps_loop
.ps_emit:
    push dx                          ; .print_dec clobbers dx (print_char does) -> save the unit index
    call .print_dec                  ; ax (< 1024) in decimal
    pop dx
    mov al, ' '
    push dx
    phase_call_res print_char
    pop dx
    mov si, low_scratch_start + (restore_units - PHASE_BASE)
.ps_skip:
    or dx, dx
    jz .print_z                      ; si now at the dx-th unit z-string -> print it (tail)
    lodsb
    or al, al
    jnz .ps_skip
    dec dx
    jmp .ps_skip

; print ax (< 1024 here) in decimal at the cursor (attr bl), no leading zeros. clobbers ax, cx, dx.
.print_dec:
    mov cx, 0                        ; digit count
    mov si, 10
.pd_div:
    xor dx, dx
    div si                           ; ax /= 10, dx = digit
    push dx
    inc cx
    or ax, ax
    jnz .pd_div
.pd_emit:
    pop ax
    add al, '0'
    push cx
    phase_call_res print_char
    pop cx
    loop .pd_emit
    ret
.print_z:
    lodsb
    or al, al
    jz .pz_done
    phase_call_res print_char
    jmp .print_z
.pz_done:
    ret

; the bigger-machine warning as a dim "> " line at the current cursor row (paint left it at the dpi
; prompt area). si -> a PHASE-relative z-string. clobbers ax, di, si, es (es restored to ds).
restore_env_warn_line:
    mov ax, [video_seg]
    mov es, ax
    mov al, [cursor_row]
    mov ah, [screen_cols]
    mul ah
    shl ax, 1                        ; di = cursor_row * cols * 2 (row byte offset)
    mov di, ax
    mov ah, [menu_idle_attr]
.wl_next:
    lodsb
    or al, al
    jz .wl_done
    stosw
    jmp .wl_next
.wl_done:
    push ds
    pop es
    ret
restore_warn_text    db '> restored. extra RAM is arena', 0
restore_toobig_text  db 'environment needs ', 0   ; "environment needs <shortfall> more RAM"
restore_more_text    db ' more RAM', 0
restore_toobig_q_text db 'start new or restart?', 0
restore_incorrect_text db 'incorrect option', 0
restore_fresh_text   db 'start new', 0
restore_restart_text db 'restart', 0
restore_units        db 'B', 0, 'KB', 0, 'MB', 0, 'GB', 0   ; collapse table (16-bit reaches B/KB today)

; 16-bit additive byte sum (matches tools/env-dat.py checksum16). in: si=start, cx=count.
; out: ax=sum. clobbers bx, si, cx.
restore_env_sum:
    xor ax, ax
.sum_next:
    jcxz .sum_done
    mov bl, [si]
    xor bh, bh
    add ax, bx
    inc si
    dec cx
    jmp .sum_next
.sum_done:
    ret

; Build 12 step 3b (format 2): paint the per-row-trimmed screen snapshot so the user lands on the
; EXACT screen they left (dim tool lines, prompts, wrapping -- preserved as char+attr cells). The
; encoded screen is [screen_rows row-length bytes][packed used cells]; clear the screen to space+attr,
; then for each row copy its row_len cells to video[row*cols]. Painted only when a snapshot is present
; (screen_cols != 0) and its width matches this machine's (a 40<->80 mismatch can't be painted).
; Leaves the cursor where dpi expects to draw the prompt. clobbers ax,bx,cx,dx,si,di,es.
restore_env_paint_screen:
    mov al, [env_restore_stage + env_hdr_screen_cols]
    or al, al
    jz .clear                        ; no snapshot in this ENV.DAT
    cmp al, [screen_cols]
    jne .clear                       ; saved width != this machine's -> cannot paint
    call .clear_window               ; clear to space+attr; the decode paints only the kept cells
    mov si, env_restore_stage + env_hdr_len
    add si, [env_restore_stage + env_hdr_region_stored]  ; si -> the row-length table
    mov bx, si                       ; bx = row-length table base
    mov al, [env_restore_stage + env_hdr_screen_rows]
    xor ah, ah
    add si, ax                       ; si -> packed cells (after the screen_rows length bytes)
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .seg_ready
    mov ax, 0xb000
.seg_ready:
    mov es, ax                       ; es = video segment (stosw target)
    xor dx, dx                       ; dx = current row
.row_loop:
    cmp dl, [env_restore_stage + env_hdr_screen_rows]
    jae .done
    mov al, dl                       ; di = row * cols * 2 (row byte offset)
    mul byte [screen_cols]
    shl ax, 1
    mov di, ax
    push bx                          ; cx = row_len[row]
    add bx, dx
    mov cl, [bx]
    pop bx
    xor ch, ch
    jcxz .row_next
.cell_loop:
    lodsw                            ; ax = char+attr from the packed cells (ds:si)
    stosw                            ; -> video (es:di)
    loop .cell_loop
.row_next:
    inc dx
    jmp .row_loop
.done:
    push ds
    pop es
    jmp .cursor
.clear:
    call .clear_window
.cursor:
    mov byte [cursor_row], dpi_prompt_row - 2
    mov byte [cursor_col], 0
    ret
.clear_window:
    mov ax, 0x0600
    mov bh, [ready_attr]
    xor cx, cx
    mov dx, 0x184f
    int 0x10
    ret

restore_env_name db 'ENV     DAT'

%unmacro phase_call_res 1
