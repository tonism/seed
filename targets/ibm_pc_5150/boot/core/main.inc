%macro call_core_phase 2
    mov ax, (((%2 - %1 + 511) / 512) << 8) | ((%1 - $$) / 512)
    call run_core_phase
%endmacro

%macro call_core_phase_at 3
    mov ax, (((%2 - %1 + 511) / 512) << 8) | ((%1 - $$) / 512)
    mov bx, %3
    call run_core_phase_at
%endmacro

%macro load_core_window 2
    mov ax, (((%2 - %1 + 511) / 512) << 8) | ((%1 - $$) / 512)
    mov bx, %1
    call load_core_sectors_at
%endmacro

start:
    cli
    mov bp, runtime_stack_top
    cmp bx, basic_boot_magic_bx
    jne .stack_ready
    cmp cx, basic_boot_magic_cx
    jne .stack_ready
    mov bp, ax
.stack_ready:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, bp
    sti
    cld

    call clear_runtime_scratch
    mov byte [handoff_addr + handoff_boot_drive], dl
    mov word [handoff_addr + handoff_ram_top], bp
    ; Build 12 (2-image): adopt the floppy geometry from the boot-sector BPB before the first
    ; phase load, so one CORE.SYS works on a 160K single-sided or 360K double-sided image.
    call detect_floppy_geometry

hal_start:
    call_core_phase core_hardware_setup_phase_start, core_hardware_setup_phase_end
    jc network_error

    call_core_phase core_packet_io_init_phase_start, core_packet_io_init_phase_end
    jc network_setup_error

    call prepare_internet_path
    jc network_setup_error

    mov bl, [load_attr]
    mov al, 'o'
    call show_load_marker
    call prepare_agent_path
    jc agent_setup_error
    mov byte [handoff_addr + handoff_status], handoff_status_ready

    ; Build 12 (32K floppy-free loop): preload the chat-loop working set — phases (incl. K) AND the
    ; streamed IDENTITY/COMPACT prompts — into the high cache, now that agents_cfg has set the prompt
    ; clusters. No-op on 16K (tier-gated). After this the chat loop reads no floppy per turn. Runs once
    ; here per cold bring-up (and on a retry loop back through hal_start), before the first request.
    call preload_loop_cache

chat_loop:
    call_core_phase core_dpi_phase_start, core_dpi_phase_end
    call prepare_agent_endpoint_path
    ; Build 10 soft-fail: a chat turn ALWAYS returns to DPI. prepare_agent_endpoint_path tries reuse
    ; then a reconnect; if it still fails the user just re-asks (a fresh attempt) instead of hitting
    ; the fatal retry/restart screen. The fatal path below now serves only the cold setup sequence
    ; (jc agent_setup_error above), never a mid-chat turn.
    jmp chat_loop

agent_setup_error:
    mov al, handoff_status_agent_failed

show_failure:
    mov [handoff_addr + handoff_status], al
    call_core_phase core_failure_phase_start, core_failure_phase_end
    jmp hal_start

network_error:
    mov al, handoff_status_no_nic
    jmp show_failure

network_setup_error:
    mov al, handoff_status_network_failed
    jmp show_failure

run_tcp_connect_phase:
    mov ax, (((core_tcp_connect_phase_end - core_tcp_connect_phase_start + 511) / 512) << 8) | ((core_tcp_connect_phase_start - $$) / 512)
    mov bx, net_setup_phase_start
    jmp run_core_phase_at

run_core_phase:
    mov bx, low_scratch_start

run_core_phase_at:
    call load_core_sectors_at
    jc .done
    call bx
.done:
    ret

load_core_sectors_at:
    ; Build 12 (32K floppy-free chat loop): if this phase was preloaded into the high RAM cache
    ; (loop_cache_count > 0 and the load-request key in ax matches a loop_cache_table entry), copy it
    ; from RAM instead of reading the floppy. On 16K loop_cache_count is 0 (the preload is skipped and
    ; the cache region does not exist), so this is bypassed and every load hits the floppy as before.
    cmp word [loop_cache_count], 0
    je .floppy
    push ax
    push cx
    push si
    push di
    mov cx, [loop_cache_count]
    mov si, loop_cache_table
.cache_scan:
    cmp ax, [si]
    je .cache_hit
    add si, 4
    loop .cache_scan
    pop di
    pop si
    pop cx
    pop ax
    jmp .floppy
.cache_hit:
    mov di, bx
    mov si, [si + 2]
    xor cx, cx
    mov ch, ah                 ; cx = sectors * 256 words = sectors * 512 bytes
    push ds
    pop es
    rep movsw
    pop di
    pop si
    pop cx
    pop ax
    clc
    ret
.floppy:
    push bx
    mov cl, ah
    xor ah, ah
    xor ch, ch
    push ds
    pop es
    add ax, fat_data_start_lba
.next_sector:
    call read_abs_sector
    jc .read_failed
    add bx, 512
    inc ax
    loop .next_sector
    pop bx
    clc
    ret
.read_failed:
    pop bx
    stc
    ret

clear_runtime_scratch:
    xor ax, ax
    mov di, low_runtime_state_start
    mov cx, (low_runtime_state_end - low_runtime_state_start + 1) / 2
    rep stosw
    mov di, high_crypto_scratch_start
    mov cx, (critical_scratch_end - high_crypto_scratch_start) / 2
    rep stosw
    ret

; Build 12 (32K floppy-free chat loop): preload the chat-loop working-set phases into the high cache
; so the loop reads no floppy mid-conversation. 32K direct boot only (gated on ram_top); a no-op on
; 16K (the loop demand-loads, count stays 0). Each phase is read via load_core_sectors_at while
; loop_cache_count is still 0 (so it floppy-fills the cache), its {key, cache addr} recorded; then the
; count is set so subsequent loads of the same phase rep-movsw from RAM. Reuses the canonical load key
; (sectors<<8 | sector-offset) so the loop's own loads match by construction.
preload_loop_cache:
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .done
    push es
    push ds
    pop es
    mov di, loop_cache_table
    mov bx, loop_cache_start
    mov si, loop_preload_list
.next:
    mov ax, [si]
    or ax, ax
    jz .commit
    add si, 2
    mov [di], ax
    mov [di + 2], bx
    add di, 4
    push ax
    push si
    push di
    call load_core_sectors_at
    pop di
    pop si
    pop ax
    xor cx, cx
    mov ch, ah                 ; cx = sectors * 256 words ...
    shl cx, 1                  ; ... * 2 = sectors * 512 bytes
    add bx, cx
    jmp .next
.commit:
    mov ax, di
    sub ax, loop_cache_table
    shr ax, 1
    shr ax, 1                  ; ax = phase entry count
    push ax                    ; commit it AFTER the prompt preloads, so they floppy-fill (count still 0)
    ; Build 12 incr 3: preload the two streamed system prompts into their fixed top-of-cache slots
    ; (agents_cfg, which ran before this preload's new call site, set the clusters + sizes). With
    ; loop_cache_count still 0, load_core_sectors_at floppy-fills. The prompt LBA is read as a 1-sector
    ; load whose data-area offset is cluster - fat_first_data_cluster.
    mov ax, [prompt_id_cluster]
    mov cx, [prompt_id_size]
    mov bx, prompt_id_cache
    call .preload_one_prompt
    mov ax, [prompt_compact_cluster]
    mov cx, [prompt_compact_size]
    mov bx, prompt_compact_cache
    call .preload_one_prompt
    pop ax
    mov [loop_cache_count], ax  ; phase cache live; the prompt cache is gated on loop_cache_count > 0 too
    pop es
.done:
    ret
.preload_one_prompt:
    ; ax = cluster, cx = byte size, bx = cache slot. Read the one prompt sector if the file exists
    ; (size > 0); a missing prompt (size 0) leaves the slot unused — its stream is empty regardless.
    or cx, cx
    jz .pp_done
    sub ax, fat_first_data_cluster
    mov ah, 1                  ; ah = 1 sector; al = data-area offset (prompts sit well within 8 bits)
    call load_core_sectors_at
.pp_done:
    ret

; Build 12 incr 3 (32K floppy-free loop): resolve the streamed-prompt source for the X phase. ax =
; the IDENTITY or COMPACT first cluster. When a 32K boot preloaded the prompts (loop_cache_count > 0),
; return si = the fixed cache slot (no floppy); else read the one prompt sector into tls_rx_copy and
; return si = tls_rx_copy. CF on a read failure. Resident so the tight net-window X phase stays small.
; (ax IS the cluster being checked against, so on 32K a hit is guaranteed.)
agent_resolve_prompt_source:
    cmp word [loop_cache_count], 0
    je .floppy
    cmp ax, [prompt_id_cluster]
    je .id
    cmp ax, [prompt_compact_cluster]
    jne .floppy
    mov si, prompt_compact_cache
    clc
    ret
.id:
    mov si, prompt_id_cache
    clc
    ret
.floppy:
    add ax, fat_data_start_lba - fat_first_data_cluster
    mov bx, tls_rx_copy
    call read_abs_sector
    jc .fail
    mov si, tls_rx_copy
    clc
    ret
.fail:
    stc
    ret

; The chat-loop working set, as canonical load keys (sectors<<8 | sector-offset): dpi/Y,
; agent_request/R, agent_api_stream/X, agent_response/T, tool/M, and the K crypto window (the
; dominant per-turn cost, reloaded every turn to restore 0x1800 after a $x; the cache copy is
; pristine, so the reload becomes a RAM memcpy). Must stay <= loop_cache_max_entries; their total
; sectors <= loop_cache_max_sectors (build-asserted in core.asm). 0 terminates the list.
loop_preload_list:
    dw (((core_dpi_phase_end - core_dpi_phase_start + 511) / 512) << 8) | ((core_dpi_phase_start - $$) / 512)
    dw (((core_agent_request_phase_end - core_agent_request_phase_start + 511) / 512) << 8) | ((core_agent_request_phase_start - $$) / 512)
    dw (((core_agent_api_stream_phase_end - core_agent_api_stream_phase_start + 511) / 512) << 8) | ((core_agent_api_stream_phase_start - $$) / 512)
    dw (((core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512) << 8) | ((core_agent_response_phase_start - $$) / 512)
    dw (((core_tool_phase_end - core_tool_phase_start + 511) / 512) << 8) | ((core_tool_phase_start - $$) / 512)
    dw (((core_link_window_end - core_link_window_start + 511) / 512) << 8) | ((core_link_window_start - $$) / 512)
    dw 0
