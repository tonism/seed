%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

agents_cfg_phase:
    mov byte [agent_count], 0
    ; Build 11 #4 real compaction: cache the floppy-resident system prompts (identity + compaction
    ; contract) here, while a root-dir scan buffer (fs_sector_buffer) is free - the stream phase
    ; later overlaps that buffer with its own code, so the find CANNOT run mid-chat. Caches each
    ; file's first cluster + size (size 0 if absent); the stream phase reads the sectors directly.
    call agents_cfg_phase_find_prompts
    call agents_cfg_phase_find
    jc .fallback
    call agents_cfg_phase_parse
    jc .fallback
    cmp byte [agent_count], 0
    je .fallback
    clc
    ret
.fallback:
    call agents_cfg_phase_load_builtin
    clc
    ret

agents_cfg_phase_load_builtin:
    push ds
    pop es
    mov si, low_scratch_start + (agents_cfg_phase_builtin_ids - PHASE_BASE)
    mov di, agent_ids
    mov bx, 1
.next_builtin:
    mov cx, agent_id_len
.copy:
    lodsb
    stosb
    loop .copy
    add di, 16 - agent_id_len
    dec bx
    jnz .next_builtin
    mov byte [agent_count], 1
    ret

agents_cfg_phase_find:
    mov di, low_scratch_start + (agents_cfg_phase_name - PHASE_BASE)
    call agents_cfg_phase_find_root_file
    jc .not_found
    mov ax, [fs_file_cluster]
    mov [agents_cluster], ax
    mov ax, [fs_file_size_low]
    mov [agents_size_low], ax
    mov ax, [fs_file_size_high]
    mov [agents_size_high], ax
    clc
    ret
.not_found:
    stc
    ret

agents_cfg_phase_parse:
    cmp word [agents_size_high], 0
    jne .failed
    mov ax, [agents_cluster]
    cmp ax, fat_first_data_cluster
    jb .failed
    mov [fs_current_cluster], ax
    mov ax, [agents_size_low]
    mov [fs_bytes_left], ax
    or ax, ax
    jz .failed
.next_cluster:
    cmp byte [agent_count], agent_slot_count
    jae .done
    cmp word [fs_bytes_left], 0
    je .done
    mov ax, [fs_current_cluster]
    call agents_cfg_phase_read_cluster_to_buffer
    jc .failed
    mov ax, [fs_bytes_left]
    cmp ax, 512
    jbe .size_ready
    mov ax, 512
.size_ready:
    mov [fs_bytes_this], ax
    call agents_cfg_phase_parse_sector
    mov ax, [fs_bytes_left]
    sub ax, [fs_bytes_this]
    mov [fs_bytes_left], ax
    inc word [fs_current_cluster]
    jmp .next_cluster
.done:
    clc
    ret
.failed:
    stc
    ret

agents_cfg_phase_parse_sector:
    mov si, fs_sector_buffer
    mov cx, [fs_bytes_this]
    mov byte [fs_line_start], 1
.next_byte:
    cmp cx, 0
    je .done
    cmp byte [fs_line_start], 1
    jne .consume
    cmp byte [agent_count], agent_slot_count
    jae .done
    cmp cx, 6
    jb .consume
    cmp byte [si], 'a'
    jne .consume
    cmp byte [si + 1], 'g'
    jne .consume
    cmp byte [si + 2], 'e'
    jne .consume
    cmp byte [si + 3], 'n'
    jne .consume
    cmp byte [si + 4], 't'
    jne .consume
    cmp byte [si + 5], ' '
    jne .consume
    call agents_cfg_phase_copy_id
.consume:
    lodsb
    dec cx
    cmp al, 13
    je .line_start
    cmp al, 10
    je .line_start
    mov byte [fs_line_start], 0
    jmp .next_byte
.line_start:
    mov byte [fs_line_start], 1
    jmp .next_byte
.done:
    ret

agents_cfg_phase_copy_id:
    push si
    push cx
    mov al, [agent_count]
    xor ah, ah
    mov di, ax
    shl di, 1
    shl di, 1
    shl di, 1
    shl di, 1
    add di, agent_ids
    add si, 6
    mov bp, cx
    sub bp, 6
    mov dx, agent_id_len - 1
.copy:
    cmp bp, 0
    je .terminate
    cmp dx, 0
    je .terminate
    lodsb
    dec bp
    cmp al, 13
    je .terminate
    cmp al, 10
    je .terminate
    cmp al, ' '
    je .terminate
    cmp al, 9
    je .terminate
    stosb
    dec dx
    jmp .copy
.terminate:
    mov byte [di], 0
    inc byte [agent_count]
    pop cx
    pop si
    ret

; Build 11 #4 real compaction: locate the two streamed prompts and cache (cluster, size) for each.
; A missing file -> size 0 (the stream phase then emits nothing for it - degraded but non-fatal).
; Reuses agents_cfg_phase_find_root_file (di = 11-byte 8.3 name); the find leaves fs_file_cluster +
; fs_file_size_low set on success. The caches live in the reconnect_state block (data.inc): boot-
; written here, read every request, survives the session.
agents_cfg_phase_find_prompts:
    mov di, low_scratch_start + (agents_cfg_phase_identity_name - PHASE_BASE)
    call agents_cfg_phase_find_root_file
    jc .no_identity
    mov ax, [fs_file_cluster]
    mov [prompt_id_cluster], ax
    mov ax, [fs_file_size_low]
    mov [prompt_id_size], ax
    jmp .find_compact
.no_identity:
    mov word [prompt_id_size], 0
.find_compact:
    mov di, low_scratch_start + (agents_cfg_phase_compact_name - PHASE_BASE)
    call agents_cfg_phase_find_root_file
    jc .no_compact
    mov ax, [fs_file_cluster]
    mov [prompt_compact_cluster], ax
    mov ax, [fs_file_size_low]
    mov [prompt_compact_size], ax
    jmp .find_tools
.no_compact:
    mov word [prompt_compact_size], 0
.find_tools:
    ; Build 12 native tool calling: cache the tools schema (cluster, size), same scheme as id/compact.
    mov di, low_scratch_start + (agents_cfg_phase_tools_name - PHASE_BASE)
    call agents_cfg_phase_find_root_file
    jc .no_tools
    mov ax, [fs_file_cluster]
    mov [prompt_tools_cluster], ax
    mov ax, [fs_file_size_low]
    mov [prompt_tools_size], ax
    ; On a loop-cache tier (32K+) preload the schema into the resident tools_cache now, so the chat loop
    ; streams it from RAM (floppy-free). Homed here (not the resident nucleus, which is full) -- ram_top
    ; is already set, loop_cache_count is still 0 so load_core_sectors_at floppy-fills, and tools_cache is
    ; a fixed address. It may span 2 sectors (contiguous clusters). 16K skips (T7 floppy-streams tools).
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .tools_done
    mov ax, [prompt_tools_cluster]
    sub ax, fat_first_data_cluster       ; al = data-area sector offset
    mov ah, 1                            ; <=512 B -> one sector
    cmp word [prompt_tools_size], 512
    jbe .tools_load
    mov ah, 2                            ; >512 B -> two contiguous sectors
.tools_load:
    mov bx, tools_cache
    phase_call_res load_core_sectors_at
.tools_done:
    ret
.no_tools:
    mov word [prompt_tools_size], 0
    ret

agents_cfg_phase_identity_name db 'IDENTITY   '
agents_cfg_phase_compact_name db 'COMPACT    '
agents_cfg_phase_tools_name db 'TOOLS      '
agents_cfg_phase_name db 'AGENTS  CFG'
; Build 12: OpenAI-only. The other providers (litellm/openrouter/anthropic/google) were never wired
; end-to-end (agent_request builds only the openai-responses path) so they are removed until tested.
agents_cfg_phase_builtin_ids db 'openai', 0
                            times agent_id_len - 7 db 0

agents_cfg_phase_find_root_file:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
.next_sector:
    cmp word [fs_root_left], 0
    je .not_found
    push ds
    pop es
    mov bx, fs_sector_buffer
    mov ax, [fs_lba]
    phase_call_res read_abs_sector
    jc .not_found
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.next_entry:
    mov al, [si]
    or al, al
    jz .end_marker
    cmp al, 0xe5
    je .advance
    test byte [si + 11], 0x18
    jnz .advance
    push si
    push cx
    push di
    mov cx, 11
.compare:
    mov al, [si]
    cmp al, [di]
    jne .mismatch
    inc si
    inc di
    loop .compare
    pop di
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
.mismatch:
    pop di
    pop cx
    pop si
    jmp .advance
.advance:
    add si, fat_dir_entry_size
    loop .next_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .next_sector
.end_marker:
.not_found:
    stc
    ret

agents_cfg_phase_read_cluster_to_buffer:
    cmp ax, fat_first_data_cluster
    jb .failed
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    phase_call_res read_abs_sector
    ret
.failed:
    stc
    ret

%unmacro phase_call_res 1
