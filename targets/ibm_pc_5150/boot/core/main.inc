%macro call_core_phase 2
    mov ax, (((%2 - %1 + 511) / 512) << 8) | ((%1 - $$) / 512)
    call run_core_phase
%endmacro

%macro call_core_phase_at 3
    mov ax, (((%2 - %1 + 511) / 512) << 8) | ((%1 - $$) / 512)
    mov bx, %3
    call run_core_phase_at
%endmacro

; Like call_core_phase_at but for the net-setup window specifically: the load address is implicit in
; the shared run_net_setup_phase launcher, so the call site is 3 bytes smaller than call_core_phase_at.
; Used for every net_setup_phase_start phase (dhcp / tcp_connect / api_stream / ntp).
%macro run_net_phase 2
    mov ax, (((%2 - %1 + 511) / 512) << 8) | ((%1 - $$) / 512)
    call run_net_setup_phase
%endmacro

%macro load_core_window 2
    mov ax, (((%2 - %1 + 511) / 512) << 8) | ((%1 - $$) / 512)
    mov bx, %1
    call load_core_sectors_at
%endmacro

; The private TLS 1.3 pack-generation core physically omits the K14 pack at
; sector 45.  It is never booted, but its resident callback nucleus must be
; byte-identical to the final link.  Encode post-pack phase keys against their
; final positions in that one build while leaving the base's phase metadata
; and physical suffix untouched for the pack builder.
%ifdef TLS13_PRODUCT_TLS13
%ifdef TLS13_PRODUCT_PACK_BASE
%define TLS13_POST_PACK_PHASE_BIAS TLS13_K14_PRODUCT_PACK_SECTORS
%else
%define TLS13_POST_PACK_PHASE_BIAS 0
%endif
%else
%define TLS13_POST_PACK_PHASE_BIAS 0
%endif

%define post_pack_phase_key(phase_start,phase_end) \
    ((((phase_end - phase_start + 511) / 512) << 8) | \
    (((phase_start - $$) / 512) + TLS13_POST_PACK_PHASE_BIAS))

%macro call_post_pack_core_phase 2
    mov ax, post_pack_phase_key(%1, %2)
    call run_core_phase
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
    ; phase load, so one SEED.SYS works on a 160K single-sided or 360K double-sided image.
    call detect_floppy_geometry

hal_start:
    call_core_phase core_hardware_setup_phase_start, core_hardware_setup_phase_end
    pushf
    ; Draw the banner once, after display + CPU-class setup and before driver/network setup.
    ; The pre-286 security note is therefore independent of later success/failure paths.
    call_post_pack_core_phase core_splash_phase_start, core_splash_phase_end
    popf
    jc network_error
    call_core_phase core_driver_load_phase_start, core_driver_load_phase_end
    jc network_setup_error
    call_core_phase core_unreal_setup_phase_start, core_unreal_setup_phase_end

    call_core_phase core_packet_io_init_phase_start, core_packet_io_init_phase_end
    jc network_setup_error

    call prepare_internet_path
    jc network_setup_error

%ifdef TLS13_PRODUCT_TLS13
    ; Product TLS 1.3 routes own all time acquisition needed by their security
    ; boundary.  Preserve the old six-byte call site's extent so the resident
    ; callback ABI and K14's fixed phase keys do not move.
    times 6 nop
%else
    ; Build 12 task#7: 286-only network-time sync -- set the CMOS RTC for the recertify validity gate,
    ; right after the internet is up and BEFORE the first connect, so the clock is established
    ; out-of-band (not from the connection it authenticates). The phase self-gates on 286 and fails
    ; open; CF here is irrelevant (the next op is a mov), so no result handling is needed.
    run_net_phase core_ntp_setup_phase_start, core_ntp_setup_phase_end
%endif

    call prepare_agent_path
    jc agent_setup_error
    mov byte [handoff_addr + handoff_status], handoff_status_ready

    ; Preload the chat-loop working set after route setup. The 286 parent also
    ; snapshots this immutable set before crypto and restores it from RAM on
    ; reconnect; this cold-start call remains the common K14/non-product setup
    ; point. After it, the normal 32K+ chat loop reads no floppy per turn.
    call preload_loop_cache

chat_loop:
    ; Native tools run before DPI from resident code. tool_call loads at 0x0700 so it must not be
    ; loaded by DPI itself (also 0x0700); doing that overwrote DPI and could skip the prompt.
    call_post_pack_core_phase core_tool_phase_start, core_tool_phase_end
    cmp byte [tool_helper_pending], 0
    je .tool_helper_done
    call_post_pack_core_phase core_tool_memory_phase_start, core_tool_memory_phase_end
.tool_helper_done:
    call_post_pack_core_phase core_dpi_phase_start, core_dpi_phase_end
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

run_net_setup_phase:
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
    jle .floppy
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
    mov ax, loop_cache_max_entries
    push ax                    ; commit it AFTER the prompt preloads, so they floppy-fill (count still 0)
    ; Preload the normal-turn IDENTITY prompt and tools schema after route setup. Both secure roots may
    ; use/wipe the 32K high band, so agents_cfg only discovers their full 16-bit FAT clusters; it cannot
    ; safely populate these caches earlier. COMPACT is rare and deliberately streams from floppy.
    mov si, prompt_id_cluster
    mov bx, prompt_id_cache
    call .preload_one_prompt
    mov si, prompt_tools_cluster
    mov bx, tools_cache
    call .preload_one_prompt
    pop ax
    mov [loop_cache_count], ax  ; phase cache live; the prompt cache is gated on loop_cache_count > 0 too
    pop es
.done:
    ret
.preload_one_prompt:
    ; si -> {cluster,size}, bx = cache slot. Prompt clusters are full 16-bit FAT values and may lie
    ; beyond SEED.SYS sector 255, so do not encode them in load_core_sectors_at's AL phase key.
    ; agents_cfg publishes cluster 0 for a missing file; that leaves the unused cache slot untouched.
    mov ax, [si]
    or ax, ax
    jz .pp_done
    add ax, fat_data_start_lba - fat_first_data_cluster
    call read_abs_sector
    ; Keep the resident nucleus and every fixed TLS callback at their established addresses.
    nop
.pp_done:
    ret

; Build 12 incr 3 (32K floppy-free normal loop): resolve the streamed-prompt source for the X phase.
; IDENTITY is cached on 32K; COMPACT deliberately falls through to the floppy path. CF on a read
; failure. Resident so the tight net-window X phase stays small.
agent_resolve_prompt_source:
    cmp word [loop_cache_count], 0
    je .floppy
    cmp ax, [prompt_id_cluster]
    jne .floppy
.id:
    mov si, prompt_id_cache
    clc
    ret
.floppy:
    add ax, fat_data_start_lba - fat_first_data_cluster
    mov bx, tls_rx_copy
    call read_abs_sector
    jc .done
    mov si, tls_rx_copy
    clc
.done:
    ret

%ifdef TLS13_PRODUCT_TLS13
; Return AL=0 for the cold booting status and AL=1 for ready/chat, and publish
; the matching ESC gate.  prepare_agent_endpoint_path immediately suppresses
; the gate while a secure route owns volatile MDA state; later calls restore it.
tls13_product_route_mode:
    mov al, [handoff_addr + handoff_status]
    shr al, 1                           ; booting=1 -> 0, ready=3 -> 1
    mov [dpi_reached], al
    ; Product success tail-jumps here, so consume the region's spare byte to
    ; make that return a guaranteed CF=0.
    clc
    ret
%else
    times 10 db 0
%endif
    ; Preserve the historical size of this resident region.  The fixed K14
    ; callbacks below it must not move.

; The chat-loop working set, as canonical load keys (sectors<<8 | sector-offset): dpi/Y,
; agent_request/R, agent_api_stream/X, agent_response/T, and the K crypto window (the
; dominant per-turn cost, reloaded every turn to restore 0x1800 after a $x; the cache copy is
; pristine, so the reload becomes a RAM memcpy). The tool parser demand-loads so the cache stops before
; the 286 recert leaf-capture tail. Must stay <= loop_cache_max_entries; their total sectors <=
; loop_cache_max_sectors (build-asserted in core.asm). 0 terminates the list.
loop_preload_list:
    dw post_pack_phase_key(core_dpi_phase_start, core_dpi_phase_end)
    dw post_pack_phase_key(core_agent_request_phase_start, core_agent_request_phase_end)
    dw post_pack_phase_key(core_agent_api_stream_phase_start, core_agent_api_stream_phase_end)
    dw post_pack_phase_key(core_agent_response_phase_start, core_agent_response_phase_end)
    dw (((core_link_window_end - core_link_window_start + 511) / 512) << 8) | ((core_link_window_start - $$) / 512)
loop_preload_list_end:
    dw 0
