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

hal_start:
    call_core_phase core_hardware_setup_phase_start, core_hardware_setup_phase_end
    jc network_error

    call_core_phase core_packet_io_init_phase_start, core_packet_io_init_phase_end
    jc network_setup_error

    ; Build 12: on a 32K direct boot, preload the chat-loop working set into the high cache so the
    ; loop runs floppy-free (no-op on 16K). Done here, at boot, before the network bring-up — the
    ; floppy is free, and the cache region above the (not-yet-populated) arena is available.
    call preload_loop_cache

    call prepare_internet_path
    jc network_setup_error

    mov bl, [load_attr]
    mov al, 'o'
    call show_load_marker
    call prepare_agent_path
    jc agent_setup_error
    mov byte [handoff_addr + handoff_status], handoff_status_ready

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
    shr ax, 1                  ; entries = (di - loop_cache_table) / 4
    mov [loop_cache_count], ax
    pop es
.done:
    ret

; The chat-loop working set, as canonical load keys (sectors<<8 | sector-offset). dpi/Y, agent_request/R,
; agent_api_stream/X, agent_response/T, tool/M. The K crypto window is added in a later increment.
; Must stay <= loop_cache_max_entries; their total sectors <= loop_cache_max_sectors (build-asserted
; against the cache size once K joins). 0 terminates the list.
loop_preload_list:
    dw (((core_dpi_phase_end - core_dpi_phase_start + 511) / 512) << 8) | ((core_dpi_phase_start - $$) / 512)
    dw (((core_agent_request_phase_end - core_agent_request_phase_start + 511) / 512) << 8) | ((core_agent_request_phase_start - $$) / 512)
    dw (((core_agent_api_stream_phase_end - core_agent_api_stream_phase_start + 511) / 512) << 8) | ((core_agent_api_stream_phase_start - $$) / 512)
    dw (((core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512) << 8) | ((core_agent_response_phase_start - $$) / 512)
    dw (((core_tool_phase_end - core_tool_phase_start + 511) / 512) << 8) | ((core_tool_phase_start - $$) / 512)
    dw 0
