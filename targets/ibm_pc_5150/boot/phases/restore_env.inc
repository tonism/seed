%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

; Build 12 env save/load (notes/env-save-load-design.md), step 3: restore a saved environment from
; the boot drive at boot, BEFORE the cold greeting. Hooked into prepare_agent_path: CF=0 here => the
; window is populated + the screen repainted, and the caller SKIPS the greeting; CF=1 => no/invalid
; save, the caller falls through to the normal greeting. Restore is a READ, so it is NOT gated on
; writable media.
;
; ENV.DAT carries two things for two audiences: the conversation window+arena ("region") for the
; MODEL (restored into chat_context_start, rides into the request), and a literal screen snapshot
; (the video text buffer) for the USER (painted back verbatim so they land on the exact screen they
; left). FAIL-SAFE: the whole file is staged at env_restore_stage (0x1800, the not-yet-loaded K
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
    ; region_len fit: <= this machine's pool (ceiling - chat_context_start). ceiling mirrors
    ; hardware_setup: loop_cache_start on a 32K direct boot, else ram_top - the 0x100 stack reserve.
    mov ax, [handoff_addr + handoff_ram_top]
    sub ax, 0x100
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .pool_ready
    mov ax, loop_cache_start
.pool_ready:
    sub ax, chat_context_start
    cmp [env_restore_stage + env_hdr_region_len], ax
    ja .fail                         ; region_len > pool: won't fit (3c adds the menu; here clean boot)
    ; total payload = region_len + screen_len; it must fit the staged file
    call restore_env_payload_len     ; ax = region_len + screen_cols*screen_rows*2
    mov bx, ax
    add ax, env_hdr_len
    cmp ax, [fs_file_size_low]
    ja .fail
    ; payload checksum (header field) over the whole payload
    mov si, env_restore_stage + env_hdr_len
    mov cx, bx
    call restore_env_sum
    cmp ax, [env_restore_stage + env_hdr_payload_checksum]
    jne .fail

    ; --- valid: commit (window -> chat_context_start, for the model) ---
    mov si, env_restore_stage + env_hdr_len
    mov di, chat_context_start
    mov cx, [env_restore_stage + env_hdr_region_len]
    push ds
    pop es
    rep movsb
    mov ax, [env_restore_stage + env_hdr_window_cap]
    mov [chat_context_len_var], ax
    mov ax, [env_restore_stage + env_hdr_used]
    mov [chat_context_used], ax
    mov ax, [env_restore_stage + env_hdr_note_len]
    mov [note_len], ax
    call restore_env_neutralize
    call restore_env_paint_screen    ; repaint the saved screen (for the user)
    clc
    ret
.fail:
    stc
    ret

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

; out: ax = region_len + screen_cols*screen_rows*2 (the whole payload length). clobbers ax only.
restore_env_payload_len:
    mov al, [env_restore_stage + env_hdr_screen_cols]
    mul byte [env_restore_stage + env_hdr_screen_rows]   ; ax = cols*rows
    shl ax, 1                                            ; *2 (char+attr cells)
    add ax, [env_restore_stage + env_hdr_region_len]
    ret

; Neutralize any line-start '$' in the restored window so last session's tool directives do NOT
; re-fire on the first turn. in: chat_context_used. clobbers ax, bx, cx, si.
restore_env_neutralize:
    mov si, chat_context_start
    mov cx, [chat_context_used]
    jcxz .neu_done
    mov bl, 1                        ; bl=1 => si is at a line start
.neu_next:
    mov al, [si]
    cmp bl, 1
    jne .neu_after_dollar
    cmp al, '$'
    jne .neu_after_dollar
    mov byte [si], ' '
.neu_after_dollar:
    cmp al, 10
    jne .neu_not_nl
    mov bl, 1
    jmp .neu_adv
.neu_not_nl:
    xor bl, bl
.neu_adv:
    inc si
    loop .neu_next
.neu_done:
    ret

; Build 12 step 3b: paint the saved screen snapshot back to video memory, so the user lands on the
; EXACT screen they left (dim tool lines, prompts, wrapping -- all preserved as char+attr cells), not
; a semantic reconstruction. Painted only when a snapshot is present (screen_cols != 0) and its width
; matches this machine's [screen_cols] (a 40<->80 mismatch can't be painted). The snapshot is
; row-major char+attr exactly as in CGA/MDA text memory -> a straight rep movsw to the video segment.
; Otherwise just clear the screen (the window is still restored for the model; no visual history).
; Leaves the cursor where dpi expects to draw the prompt. clobbers ax,bx,cx,dx,si,di,es.
restore_env_paint_screen:
    mov al, [env_restore_stage + env_hdr_screen_cols]
    or al, al
    jz .clear                        ; no snapshot in this ENV.DAT
    cmp al, [screen_cols]
    jne .clear                       ; saved width != this machine's -> cannot paint
    mov ax, color_video_seg
    test word [handoff_addr + handoff_flags], handoff_flag_mda
    jz .seg_ready
    mov ax, 0xb000
.seg_ready:
    mov es, ax
    xor di, di
    mov si, env_restore_stage + env_hdr_len
    add si, [env_restore_stage + env_hdr_region_len]     ; -> the screen cells (after the window)
    call restore_env_payload_len
    sub ax, [env_restore_stage + env_hdr_region_len]     ; ax = screen_len (bytes)
    mov cx, ax
    shr cx, 1                        ; cells (words)
    rep movsw
    push ds
    pop es
    jmp .cursor
.clear:
    mov ax, 0x0600
    mov bh, [ready_attr]
    xor cx, cx
    mov dx, 0x184f
    int 0x10
.cursor:
    mov byte [cursor_row], dpi_prompt_row - 2
    mov byte [cursor_col], 0
    ret

restore_env_name db 'ENV     DAT'

%unmacro phase_call_res 1
