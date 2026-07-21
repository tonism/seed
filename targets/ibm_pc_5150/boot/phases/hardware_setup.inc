%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

hardware_setup_phase:
    call hardware_setup_phase_init_handoff
    call hardware_setup_detect_cpu
    call hardware_setup_phase_display
    ; Build 9 (compaction redesign): stage the keep-alive template into the persistent pool once at boot,
    ; so the renderer no longer carries it (frees its last bytes for compaction).
    ; Build 11 #4 COLD-BOOT-FREEZE FIX (2026-06-10): this MUST run BEFORE the network I/O below.
    ; hardware_setup loads at low_scratch_start, which == ne_tx_frame; the NIC's MAC-PROM read target
    ; (ne_prom .. low_packet_scratch_end, a 32 B window just under fs_sector_buffer) OVERLAPS this
    ; phase's tail, where stage_ka_template's CODE and ka_template_source DATA live. At some phase sizes
    ; the routine's code lands inside ne_prom's window; read_network_address then writes the MAC PROM
    ; over it, so calling stage_ka_template AFTER read_network_address (the old order) executed code the
    ; MAC read had just clobbered -> hard cold-boot freeze, no splash. Size-fragile: Build 11 #4's
    ; chat_effective_cap write (6 B) shifted the tail into range. Staging FIRST runs the routine + reads
    ; ka_template_source while both are intact; the later MAC read can clobber that dead region harmlessly.
    call hardware_setup_stage_ka_template
    call probe_network_card
    jnc .card_ready
    call activate_ne_pnp_card
    jc .failed
    call probe_network_card
    jc .failed
.card_ready:
    call resolve_network_config
    ; read_network_address writes the MAC PROM into ne_prom, which physically overlaps this phase's own
    ; image. Keep it as the last hardware-setup step; the following driver load happens in a fresh phase.
    call read_network_address
    clc
    ret
.failed:
    stc
    ret

hardware_setup_phase_init_handoff:
    mov dl, [handoff_addr + handoff_boot_drive]
    mov bp, [handoff_addr + handoff_ram_top]
    push ds
    pop es
    mov di, handoff_addr
    xor ax, ax
    mov cx, handoff_size_bytes / 2
.clear:
    stosw
    loop .clear
    mov word [handoff_addr + handoff_magic], 0x4553
    mov word [handoff_addr + handoff_magic + 2], 0x4445
    mov byte [handoff_addr + handoff_version], handoff_struct_version
    mov byte [handoff_addr + handoff_size], handoff_size_bytes
    mov word [handoff_addr + handoff_build], build_number
    mov byte [handoff_addr + handoff_boot_drive], dl
    mov word [handoff_addr + handoff_ram_top], bp
    mov byte [handoff_addr + handoff_status], handoff_status_booting
    mov byte [blink_state], 0
    ; Build 9/12: size the low arena/context pool from ram_top. The pool spans chat_pool_start ..
    ; tier ceiling and splits 50/50; arena is the lower half and the context window lives at the
    ; far end. The compaction threshold stays at 3/4 of the live window.
    mov ax, [handoff_addr + handoff_ram_top]
    sub ax, 0x100
    ; Build 12 (32K floppy-free loop): on a 32K direct boot the chat-loop preload cache + the stack sit
    ; above loop_cache_start, so the arena/context pool must top out THERE, not at ram_top, or
    ; chatting would overwrite the cached phases. (16K keeps ram_top - stack reserve.)
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .pool_ceiling_ready
    ; Build 12 native tool calling: reserve the resident tools-schema buffer just below loop_cache_start,
    ; so the 32K conventional window/arena top out at tools_cache (2 sectors lower) and never clobber it.
    mov ax, tools_cache
.pool_ceiling_ready:
    sub ax, chat_pool_start
    shr ax, 1
    mov [chat_context_len_var], ax
    mov [chat_effective_cap], ax    ; #4: boot default = full window (the cold greeting skips the
                                    ; ready path; agent_request resets it per ready request)
    mov bx, ax
    shr ax, 1          ; window/2
    shr bx, 1
    shr bx, 1          ; window/4 (two single-bit shifts; 8086 has no shr-by-immediate)
    add ax, bx         ; window*3/4
    mov [chat_compact_threshold], ax
    ret

; Build 12 capability vector: detect whether the CPU is a 286 or better and record it (the secure
; real-crypto tier gates on this). Classic real-mode test: on an 8086/8088 (and the V20/V30) FLAGS
; bits 12-15 are wired to 1 and cannot be cleared; a 286+ in real mode forces them to 0. So clear
; them, reload, read back: still 1 => 8086-class (leave the bit clear); 0 => 286 or better. Runs
; once at boot, after init_handoff has cleared the handoff. Preserves the live flags.
hardware_setup_detect_cpu:
    pushf
    pop ax
    mov cx, ax
    and ah, 0x0f                 ; clear FLAGS bits 12-15
    push ax
    popf
    pushf
    pop ax
    push cx
    popf                         ; restore the original flags
    and ah, 0xf0
    cmp ah, 0xf0
    je .done                     ; bits 12-15 stuck high => 8086/8088/V20 (leave 286+ bit clear)
    or word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    ; 286 vs 386+: on a 286 the high FLAGS bits stay forced low; a 386 in real mode lets IOPL/NT
    ; (bits 12-14) change through PUSHF/POPF. Keep this behind the 286+ gate so 8088-class CPUs never
    ; see it as a consumer decision.
    pushf
    pop ax
    mov cx, ax
    xor ah, 0x70
    push ax
    popf
    pushf
    pop ax
    push cx
    popf
    xor ax, cx
    test ah, 0x70
    jz .done
    or word [handoff_addr + handoff_flags], handoff_flag_cpu_386plus
.done:
    ret

hardware_setup_phase_display:
    mov ah, 0x0f
    int 0x10
    mov [handoff_addr + handoff_video_mode], al
    mov [handoff_addr + handoff_video_cols], ah
    mov [screen_cols], ah
    ; Build 10 rework: precompute the scroll bottom-right corner for scroll_text_area
    ; (dh = last text row, dl = cols-1) so that shared BIOS-scroll helper stays tiny.
    push ax
    mov al, ah
    dec al
    mov ah, dpi_prompt_row
    mov [scroll_br], ax
    pop ax
    ; Build 10 (agentic loop): the loop flags live in low_phase_state (persists across phase
    ; loads -> no resident cost) but are NOT boot-cleared, and the cold greeting runs before the
    ; tool phase's per-turn reset. Clear both here (one word write, count is adjacent) so the
    ; greeting reads pending=0 and takes the normal request path (restore_prompt_from_screen).
    mov word [agent_loop_pending], 0
    ; Build 11 reorg: compact_next, compacting_msg and chat_context_used moved out of the resident
    ; nucleus into reconnect_state_* (no longer boot-loaded db/dw 0). The cold greeting's renderer/X
    ; phase read all three before their first write (their only writers are the ready/chat path), so
    ; zero them here at boot like agent_loop_pending above. compact_next + compacting_msg are adjacent
    ; bytes (one word write); chat_context_used follows (the conversation window starts empty).
    mov word [compact_next], 0
    mov word [esc_stop], 0          ; Build 11 ESC: esc_stop + the adjacent esc_panic -- tool_phase reads
                                    ; both at the greeting, before agent_request resets esc_stop
    mov byte [dpi_reached], 0       ; Build 11 ESC gate: hook stays inert until dpi_phase sets this post-boot
    mov word [chat_context_used], 0
    ; Native tool state lives in the reconnect-safe pool, not the boot-cleared low runtime block. The
    ; ROM BASIC sidecar can leave nonzero bytes there, so clear the capture FSM before the cold greeting
    ; and first DPI; otherwise DPI may skip the prompt as a bogus auto-continue.
    mov word [tool_fc_state], 0
    mov word [fc_capture_len], 0
    ; Build 12 milestone 2 (EMS): detect + size the Lo-tech EMS board bare-metal (board registers, no
    ; int 67h/EMM). ems_page_count = 0 means no board -> EMS inactive (byte-for-byte milestone 1). Probe
    ; via slot 0 (port ems_base_port, window seg ems_frame_seg): map logical page 0, write a signature to
    ; the frame; if it doesn't hold, there's no writable banked RAM there -> no board. Then find the page
    ; count by a banking test: for P = 1.., map page P and write its own index; page P is real+distinct
    ; only if (a) that write holds AND (b) page 0's signature survived (P didn't alias/wrap to page 0).
    ; The banking test rejects plain static RAM at the frame. Runs BEFORE the far-log sizing below (which
    ; reads ems_page_count to pick M1-vs-EMS-invert). ds=0 here. Save/restore every GP register it touches.
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    mov word [ems_page_count], 0
    xor al, al
    mov dx, ems_base_port
    out dx, al                      ; frame slot 0 <- logical page 0
    mov ax, ems_frame_seg
    mov es, ax
    xor di, di
    mov word [es:di], 0x5eed
    cmp word [es:di], 0x5eed
    jne .ems_done
    mov bx, 1
.ems_probe:
    mov al, bl
    mov dx, ems_base_port
    out dx, al
    mov [es:di], bx
    cmp [es:di], bx
    jne .ems_sized
    xor al, al
    out dx, al
    cmp word [es:di], 0x5eed
    jne .ems_sized
    inc bx
    cmp bx, ems_max_pages
    jb .ems_probe
.ems_sized:
    ; A plain NIC shared-RAM window can hold writes but cannot prove page 1 distinct from page 0.
    cmp bx, 2
    jb .ems_done
    mov [ems_page_count], bx
.ems_done:
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ; Build 12 Stage C (C1b): the far context log starts empty -- no frozen history, zero escaped length.
    ; Read-before-write on the first turn (the mirror dest offset + the ready CL), so boot-zero here.
    mov word [far_flushed_len], 0
    mov word [far_flushed_len + 2], 0
    mov word [far_flushed_esc], 0
    mov word [far_flushed_esc + 2], 0
    ; Activate the far log only when conventional RAM (BDA word at 0x0413, KB) exceeds 64 KB -- otherwise
    ; flat 0x10000 is unbacked and the seg-0 window stays canonical (Build-11 fallback). far_log_seg_var
    ; holds the active conventional context segment or 0 = inactive. ds=0 here, so 0x0413 reads the BDA directly.
    ; Inactive default: zero cap, empty far arena range (base == top == 0x10000).
    mov word [far_log_seg_var], 0
    xor ax, ax
    mov [far_window_cap], ax
    mov [far_window_cap + 2], ax
    mov word [far_arena_base], 0x0000
    mov word [far_arena_base + 2], 0x0001        ; 0x00010000
    mov word [far_arena_top], 0x0000
    mov word [far_arena_top + 2], 0x0001         ; base == top == 0x10000 -> empty far range
    mov word [far_ctx_base], 0x0000
    mov word [far_ctx_base + 2], 0x0001          ; context base = 0x00010000 (M1 default / inactive)
    mov ax, [0x0413]
    cmp ax, 64
    jbe .far_log_inactive
    mov word [far_log_seg_var], far_log_seg
    mov bx, 1024
    mul bx                                        ; dx:ax = conv_KB * 1024 = conv_top (bytes)
    mov [far_arena_top], ax
    mov [far_arena_top + 2], dx
    mov ax, (((core_ext_layout_phase_end - core_ext_layout_phase_start + 511) / 512) << 8) | ((core_ext_layout_phase_start - $$) / 512)
    mov bx, high_crypto_scratch_start
    phase_call_res run_core_phase_at
    jnc .far_log_inactive
    cmp word [ems_page_count], 0
    jne .far_ems_invert
    mov ax, [far_arena_top]
    mov dx, [far_arena_top + 2]
    ; --- M1 layout (no EMS): arena first [0x10000 .. conv_top-cap), context at the far end
    ; [conv_top-cap .. conv_top). cap = min((conv_top-0x10000)/2, 1 MB). ---
    sub ax, 0
    sbb dx, 1                                     ; dx:ax = conv_top - 0x10000 = far region
    shr dx, 1
    rcr ax, 1                                     ; dx:ax = region / 2 (the 50/50 window half)
    cmp dx, 0x0010                                ; 1 MB = 0x00100000 (high word 0x0010)
    jb .cap_ready
    ja .cap_1mb
    or ax, ax
    jz .cap_ready                                 ; exactly 1 MB
.cap_1mb:
    xor ax, ax
    mov dx, 0x0010                                ; clamp the window to 1 MB
.cap_ready:
    mov [far_window_cap], ax
    mov [far_window_cap + 2], dx
    mov ax, [far_arena_top]
    mov dx, [far_arena_top + 2]
    sub ax, [far_window_cap]
    sbb dx, [far_window_cap + 2]                  ; context base / far arena top = conv_top - cap
    mov [far_ctx_base], ax
    mov [far_ctx_base + 2], dx
    mov [far_arena_top], ax
    mov [far_arena_top + 2], dx
    mov cx, 4
.ctx_seg_shift:
    shr dx, 1
    rcr ax, 1
    loop .ctx_seg_shift
    mov [far_log_seg_var], ax
    jmp .far_log_inactive
.far_ems_invert:
    ; M2b: the EMS-invert layout math lives in hardware_setup_ems_layout at the phase TAIL (past the
    ; ne_prom MAC-PROM overlap at runtime 0x0CEE), so this ~90 B does NOT shift the network routines into
    ; that clobber window (the size-fragile cold-boot-freeze hazard). Only a 3 B call sits here.
    call hardware_setup_ems_layout
.far_log_inactive:
    mov word [note_len], 0          ; #4 note-as-memory: no compacted note until the first compaction
    mov byte [recert_flag], 0       ; Build 12 auto-recertify: net_phase reads it pre-handshake before
                                    ; any recertify writes it; boot-zero here (a phase, not the nucleus)
    ; (The EMS board probe now runs ABOVE the far-log sizing -- it must set ems_page_count before the
    ; far-sizing reads it to choose the M1-vs-EMS-invert layout.)
    ; Splash centering: reload the column count from [screen_cols] rather than trusting ah to survive --
    ; the far-log detection/sizing above clobbers ax/ah (xor, [0x0413], mul), which would otherwise shift
    ; seed_col (and every glyph/form column derived from it). (Build 12 Stage C regression fix.)
    mov ah, [screen_cols]
    sub ah, seed_len
    shr ah, 1
    mov [seed_col], ah
    mov [handoff_addr + handoff_seed_col], ah
    mov byte [form_left_col], 2
    mov byte [form_field_col], 20
    cmp byte [screen_cols], 80
    jb .display_kind
    ; Provider menu (miller-column drill): when a level drills in, the parent panel (agent? + option)
    ; slides LEFT only a short way to form_left_col and the inner panel (key/server form) fills the freed
    ; space to its right at form_field_col -- a compact, roughly-centered pair, not stretched edge-to-edge.
    mov al, [seed_col]
    sub al, 6
    mov [form_left_col], al        ; parent-panel column when drilled (short left of the centered menu)
    mov al, [seed_col]
    add al, 4
    mov [form_field_col], al        ; inner-panel (key/server) column, just right of the parent panel
.display_kind:
    mov byte [seed_attr], seed_attr_cga
    mov byte [build_attr], build_attr_cga
    mov byte [load_attr], load_attr_cga
    mov byte [crypto_attr], crypto_attr_cga
    mov byte [ready_attr], ready_attr_cga
    mov byte [question_attr], question_attr_cga
    mov byte [error_attr], error_attr_cga
    mov byte [menu_selected_attr], menu_selected_attr_cga
    mov byte [menu_idle_attr], menu_idle_attr_cga
    mov word [video_seg], color_video_seg
    cmp byte [handoff_addr + handoff_video_mode], 0x07
    jne .clear
    or word [handoff_addr + handoff_flags], handoff_flag_mda
    mov byte [seed_attr], seed_attr_mda
    mov byte [build_attr], build_attr_mda
    mov byte [load_attr], load_attr_mda
    mov byte [crypto_attr], crypto_attr_mda
    mov byte [ready_attr], ready_attr_mda
    mov byte [question_attr], question_attr_mda
    mov byte [error_attr], error_attr_mda
    mov byte [menu_selected_attr], menu_selected_attr_mda
    mov byte [menu_idle_attr], menu_idle_attr_mda
    mov word [video_seg], 0xb000
.clear:
    mov ax, 0x0600
    mov bh, 0x07
    xor cx, cx
    mov dh, 0x18
    mov dl, [screen_cols]
    dec dl
    int 0x10

    mov ah, 0x01
    mov ch, 0x20
    mov cl, 0x00
    int 0x10
    ret

probe_network_card:
    mov si, low_scratch_start + (hardware_nic_ports - PHASE_BASE)
.next:
    lodsw
    or ax, ax
    jz .missing
    mov dx, ax
    in al, dx
    cmp al, 0xff
    je .next
    mov [handoff_addr + handoff_nic_base], dx
    or word [handoff_addr + handoff_flags], handoff_flag_nic_present
    clc
    ret
.missing:
    stc
    ret

resolve_network_config:
    mov ax, [handoff_addr + handoff_nic_base]
    cmp ax, 0x250
    je .known_3c503
    cmp ax, 0x280
    je .detect_io_280
    ; Build 12: any probed base at/above 0x300 is the NE-family range. hardware_nic_ports probes
    ; 0x300..0x3a0, but resolve only dispatched the exact 0x300 -> an NE2000 jumpered higher (real
    ; cards vary; 86Box's ibmat puts ne2k8 at 0x320) was found by the probe yet left unresolved
    ; (no family -> no MAC -> packet_io_init "01/01"). `jae` routes the whole range to detect_ne.
    ; 8088-safe: 0x300 still goes NE; bases below 0x300 (0x2a0/0x2c0/0x2e0) keep the old ELSE.
    cmp ax, 0x300
    jae .detect_ne
    mov cx, load_ticks
    phase_call_res wait_ticks
    ret
.known_3c503:
    mov al, family_3c503
    call store_auto_network_config
    ret
    ; Build 12 UI unification: the manual adapter-select menu is removed. Autodetect resolves every
    ; supported family (ne1000/ne2000 by PROM signature, wd8003/3c501 by MAC probe, 3c503 by base); the
    ; 7-NIC matrix passes with no keypresses, proving the menu never fired for a supported card. If
    ; autodetect fails the card isn't one seed can drive, and picking a family by hand can't rescue the
    ; failing probe -- so just return with no family set; packet_io_init then reports a network error and
    ; the terminal failure screen offers retry/restart.
.detect_io_280:
    call autodetect_io_280
    jnc store_auto_network_config
    ret
.detect_ne:
    call autodetect_ne
    jnc store_auto_network_config
    ret

store_auto_network_config:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    mov cx, load_ticks
    phase_call_res wait_ticks
    ret

autodetect_io_280:
    call probe_wd8003_mac
    jc .probe_3c501
    call detect_wd_family
    clc
    ret
.probe_3c501:
    call probe_3c501_mac
    jc .failed
    mov al, family_3c501
    clc
    ret
.failed:
    stc
    ret

autodetect_ne:
    call probe_ne_family
    ret

read_network_address:
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_3c501
    je read_3c501_mac
    cmp al, family_3c503
    je read_3c503_mac
    cmp al, family_ne1000
    je read_ne_prom_mac
    cmp al, family_ne2000
    je read_ne_prom_mac
    cmp al, family_wd8003
    je read_wd8003_mac
    cmp al, family_wd8013
    je read_wd8003_mac
    ret

read_3c501_mac:
    call read_3c501_mac_raw
    call finish_handoff_mac
    ret

probe_3c501_mac:
    call read_3c501_mac_raw
    call validate_handoff_mac
    jc .failed
    cmp byte [handoff_addr + handoff_mac], 0x02
    jne .failed
    cmp byte [handoff_addr + handoff_mac + 1], 0x60
    jne .failed
    cmp byte [handoff_addr + handoff_mac + 2], 0x8c
    jne .failed
    clc
    ret
.failed:
    stc
    ret

read_3c501_mac_raw:
    xor ax, ax
    mov cx, 6
    mov di, handoff_addr + handoff_mac
.read:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_dataptr
    out dx, ax
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el1_saprom
    in al, dx
    stosb
    mov ax, di
    sub ax, handoff_addr + handoff_mac
    loop .read
    ret

read_3c503_mac:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    in al, dx
    push ax
    mov al, el2_ctrl_saprom | el2_ctrl_thin
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.read:
    in al, dx
    stosb
    inc dx
    loop .read

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    pop ax
    out dx, al

    call finish_handoff_mac
    ret

read_wd8003_mac:
    call read_wd8003_mac_raw
    call finish_handoff_mac
    ret

probe_wd8003_mac:
    call read_wd8003_mac_raw
    call validate_handoff_mac
    jc .failed
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, wd_saprom
    xor ah, ah
    mov cx, 8
.sum:
    in al, dx
    add ah, al
    inc dx
    loop .sum
    cmp ah, 0xff
    jne .failed
    clc
    ret
.failed:
    stc
    ret

detect_wd_family:
    mov al, family_wd8003
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .done
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, wd_saprom + 6
    in al, dx
    and al, 0xff ^ wd_id_extra_ram
    cmp al, wd_type_wd8013ebt
    mov al, family_wd8003
    jne .done
    mov al, family_wd8013
.done:
    ret

read_wd8003_mac_raw:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, wd_saprom
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.read:
    in al, dx
    stosb
    inc dx
    loop .read
    ret

read_ne_prom_mac:
    call read_ne_prom_raw
    call copy_ne_mac
    call finish_handoff_mac
    ret

probe_ne_family:
    call read_ne_prom_raw
    call copy_ne_mac
    call validate_handoff_mac
    jc .failed
    mov al, family_ne1000
    cmp byte [ne_prom + 16], 0x57
    jne .done
    call ne_prom_is_paired
    jc .done
    mov al, family_ne2000
.done:
    clc
    ret
.failed:
    stc
    ret

read_ne_prom_raw:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_reset
    in al, dx
    out dx, al

    mov cx, 0xffff
.wait_reset:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    in al, dx
    test al, ne_isr_reset
    jnz .reset_done
    loop .wait_reset
.reset_done:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_stop_nodma
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_isr
    mov al, 0xff
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_dcr
    mov al, ne_dcr_bytewide
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rbcr0
    mov al, ne_prom_len
    out dx, al
    inc dx
    xor al, al
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_rsar0
    xor al, al
    out dx, al
    inc dx
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_remote_read
    out dx, al

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_data
    mov di, ne_prom
    mov cx, ne_prom_len
.read:
    in al, dx
    stosb
    loop .read

    mov dx, [handoff_addr + handoff_nic_base]
    add dx, ne_cr
    mov al, ne_cmd_start_nodma
    out dx, al
    ret

ne_prom_is_paired:
    mov si, ne_prom
    mov cx, 6
.pair:
    lodsb
    cmp al, [si]
    jne .no
    inc si
    loop .pair
    clc
    ret
.no:
    stc
    ret

copy_ne_mac:
    mov si, ne_prom
    mov al, [si]
    cmp al, [si + 1]
    jne .linear
    mov al, [si + 2]
    cmp al, [si + 3]
    jne .linear
    mov al, [si + 4]
    cmp al, [si + 5]
    jne .linear
    mov al, [si + 6]
    cmp al, [si + 7]
    jne .linear
    mov al, [si + 8]
    cmp al, [si + 9]
    jne .linear
    mov al, [si + 10]
    cmp al, [si + 11]
    jne .linear
    mov di, handoff_addr + handoff_mac
    mov cx, 6
.paired:
    lodsb
    stosb
    inc si
    loop .paired
    ret
.linear:
    mov di, handoff_addr + handoff_mac
    mov cx, 6
    rep movsb
    ret

clear_handoff_mac:
    mov di, handoff_addr + handoff_mac
    xor al, al
    mov cx, 6
    rep stosb
    ret

finish_handoff_mac:
    call validate_handoff_mac
    jnc .valid
    call clear_handoff_mac
    ret
.valid:
    or word [handoff_addr + handoff_flags], handoff_flag_mac_valid
    ret

validate_handoff_mac:
    test byte [handoff_addr + handoff_mac], 0x01
    jnz .invalid

    mov si, handoff_addr + handoff_mac
    xor al, al
    mov cx, 6
.nonzero:
    or al, [si]
    inc si
    loop .nonzero
    or al, al
    jz .invalid

    mov si, handoff_addr + handoff_mac
    mov al, 0xff
    mov cx, 6
.not_ff:
    and al, [si]
    inc si
    loop .not_ff
    cmp al, 0xff
    je .invalid

    clc
    ret
.invalid:
    stc
    ret


; NIC I/O-port probe table: the bases probe_network_card scans for the first responding card. 0x250 ->
; 3c503; 0x280 -> wd8003/3c501 (autodetected); 0x300+ -> ne2000/ne1000 (autodetected). 0-terminated.
hardware_nic_ports dw 0x250, 0x280, 0x2a0, 0x2c0, 0x2e0
                   dw 0x300, 0x310, 0x320, 0x330, 0x340
                   dw 0x350, 0x360, 0x380, 0x3a0
                   dw 0

; Build 11 ESC: stage the int 9 keyboard hook to its pool slot + install the vector before the network
; I/O, so the source is copied while intact. Position-independent handler (only absolute esc_stop/
; esc_int9_old refs at seg 0 + relative jumps), so it runs from the pool. It chains every non-ESC key
; to the BIOS, so the prompt's keyboard input is unaffected.
hardware_setup_stage_ka_template:
    push es
    push ds
    pop es
    cld
    mov si, low_scratch_start + (esc_int9_handler_source - PHASE_BASE)
    mov di, esc_int9_handler
    mov cx, esc_int9_handler_len
    rep movsb
    cli
    mov ax, [0x0024]
    mov [esc_int9_old], ax
    mov ax, [0x0026]
    mov [esc_int9_old + 2], ax
    mov word [0x0024], esc_int9_handler
    mov word [0x0026], 0
    sti
    pop es
    ret

; Build 11 ESC: the int 9 keyboard hook handler. Staged to esc_int9_handler (pool) at boot, runs from
; there. Position-independent: absolute seg-0 refs + relative internal jumps + an absolute far chain/jmp.
; Peeks the scancode; on the ESC make-code, if Ctrl is held (BIOS kb-flag) it's Ctrl+ESC -> hard escape
; (longjmp to chat_loop), else it sets esc_stop (graceful stop; emit_char reacts). Chains EVERY other key
; to the saved BIOS int 9 (typing + the DPI prompt's ESC still work). Reading 0x60 is non-destructive; the
; chained BIOS handler re-reads it and acks.
esc_int9_handler_source:
    push ax
    push ds
    xor ax, ax
    mov ds, ax
    in al, 0x60
    cmp al, 0x01
    jne .esc_hook_chain
    cmp byte [dpi_reached], 0        ; Build 11 ESC gate: inert until the DPI is live (dpi_phase sets it)
    je .esc_hook_chain               ; boot / pre-DPI keypress -> just chain to BIOS, never act on ESC
    test byte [0x0417], 0x04         ; BIOS kb-flag 0040:0017 bit 2 = Ctrl held -> Ctrl+ESC hard escape
    jnz .esc_panic
    mov [esc_stop], al               ; plain ESC: graceful stop (al = 1)
    mov word [chat_effective_cap], 0 ; + stop storing the rest into the window during the drain: no
                                     ; context-fill / compaction-on-ESC; the drain just decrypt-discards
.esc_hook_chain:
    pop ds
    pop ax
    jmp far [cs:esc_int9_old]
.esc_panic:
    ; Ctrl+ESC hard escape: abandon a hung $x / stuck render and longjmp back to the prompt. esc_panic ->
    ; tool_phase draws "> panic stopped" + clears esc_stop+esc_panic (never-both). Mark the session dead
    ; (reconnect next turn). EOI since we never IRET. Reset SP to the boot's ram_top, zero segments, and
    ; do an ABSOLUTE far jmp to chat_loop (a relative jmp would be wrong from the pool). DS is already 0.
    mov byte [esc_panic], 1
    mov byte [tls_key_schedule_ready], 0
    ; Ack the keyboard ourselves: this path does NOT chain to the BIOS int 9, so pulse PB7 (port 0x61
    ; bit 7) or the 8255 stays latched on the un-acked ESC scancode and sends no more keys -- typing goes
    ; dead at the prompt (the bug). The graceful path needs none of this: it chains to the BIOS, which acks.
    in al, 0x61
    mov ah, al
    or al, 0x80
    out 0x61, al
    mov al, ah
    out 0x61, al
    mov al, 0x20
    out 0x20, al
    mov bx, [handoff_addr + handoff_ram_top]
    xor ax, ax
    mov es, ax
    mov ss, ax
    mov sp, bx
    sti
    jmp 0x0000:chat_loop
esc_int9_handler_source_end:
%if (esc_int9_handler_source_end - esc_int9_handler_source) != esc_int9_handler_len
%error "esc_int9_handler_len (layout.inc) != the staged int 9 handler length"
%endif

; Build 12 M2b/M2e: EMS-invert context layout. Defined at the phase TAIL (highest offsets, past the
; ne_prom MAC-PROM clobber window) so its ~90 B never shifts the network routines into that window --
; the size-fragile cold-boot-freeze hazard. Called from the far-sizing (.far_ems_invert) with far_arena_top
; already = conv_top and far_ctx_base still = 0x10000. Sets far_window_cap + far_ctx_base + ems_ctx_page/off.
; ARENA takes ALL conventional [0x10000..conv_top]; CONTEXT = top min(pool/2,1MB) of EMS, pool = conv
; region + ems_size (ems_page_count << 14). ds=0. Clobbers ax/bx/cx/dx.
hardware_setup_ems_layout:
    mov ax, [ems_page_count]
    mov dx, ax
    xor ax, ax                                    ; dx:ax = pages << 16
    shr dx, 1
    rcr ax, 1
    shr dx, 1
    rcr ax, 1                                     ; dx:ax = pages << 14 = ems_size (bytes)
    mov [far_ctx_base], ax                        ; stash ems_size
    mov [far_ctx_base + 2], dx
    mov ax, [far_arena_top]
    mov dx, [far_arena_top + 2]
    sub ax, 0
    sbb dx, 1                                     ; dx:ax = conv_top - 0x10000 (conv region)
    add ax, [far_ctx_base]
    adc dx, [far_ctx_base + 2]                    ; dx:ax = pool = conv region + ems_size
    shr dx, 1
    rcr ax, 1                                     ; dx:ax = pool / 2
    cmp dx, 0x0010                                ; clamp to 1 MB
    jb .ems_cap_ready
    ja .ems_cap_1mb
    or ax, ax
    jz .ems_cap_ready
.ems_cap_1mb:
    xor ax, ax
    mov dx, 0x0010                                ; cap = 1 MB
.ems_cap_ready:
    mov [far_window_cap], ax
    mov [far_window_cap + 2], dx
    mov ax, [far_ctx_base]
    mov dx, [far_ctx_base + 2]
    add ax, 0
    adc dx, 0x0010                                ; ems_size + 0x00100000 -> ems_flat_top
    sub ax, [far_window_cap]
    sbb dx, [far_window_cap + 2]                  ; - cap -> context flat base (top cap bytes of EMS)
    mov [far_ctx_base], ax
    mov [far_ctx_base + 2], dx
    ; precompute far_ctx_base's EMS page + frame offset (dx:ax = far_ctx_base) for agent_api_stream.
    sub dx, 0x0010                                ; dx:ax = rel = far_ctx_base - 0x100000
    mov bx, ax
    and bx, 0x3fff
    mov [ems_ctx_off], bx
    mov cl, 14
.ems_ctxshift:
    shr dx, 1
    rcr ax, 1
    dec cl
    jnz .ems_ctxshift
    mov [ems_ctx_page], ax                        ; page number (< 256)
    ret

isapnp_addr_port equ 0x0279
isapnp_write_data_port equ 0x0a79
isapnp_read_data_config equ 0x83
isapnp_read_data_port equ (isapnp_read_data_config << 2) | 3
isapnp_reg_set_read_data equ 0x00
isapnp_reg_serial_isolation equ 0x01
isapnp_reg_config_control equ 0x02
isapnp_reg_wake_csn equ 0x03
isapnp_reg_csn equ 0x06
isapnp_reg_ldn equ 0x07
isapnp_reg_activate equ 0x30
isapnp_reg_io_range_check equ 0x31
isapnp_reg_io_base_hi equ 0x60
isapnp_reg_io_base_lo equ 0x61
isapnp_reg_irq equ 0x70
isapnp_reg_irq_type equ 0x71

; 86Box exposes RTL8019AS and D-Link DE-220P as ISA PnP NE-compatible adapters.
; Activate only those IDs, then let the existing NE PROM probe select ne1000/ne2000
; and load NE.DRV by metadata.
activate_ne_pnp_card:
    mov si, low_scratch_start + (isapnp_key_normal - PHASE_BASE)
    call isapnp_try_ne_key
    jnc .done
    call isapnp_return_to_key
    mov si, low_scratch_start + (isapnp_key_rt - PHASE_BASE)
    call isapnp_try_ne_key
    jnc .done
    call isapnp_return_to_key
    stc
    ret
.done:
    clc
    ret

isapnp_try_ne_key:
    call isapnp_send_key
    mov ax, (isapnp_read_data_config << 8) | isapnp_reg_set_read_data
    call isapnp_write_reg
    mov ax, (0x04 << 8) | isapnp_reg_config_control
    call isapnp_write_reg
    xor ax, ax
    mov al, isapnp_reg_wake_csn
    call isapnp_write_reg
    mov di, handoff_addr + handoff_mac
    mov cx, 4
.read_id:
    call isapnp_read_serial_byte
    stosb
    loop .read_id
    mov cx, 5
.drain_serial:
    call isapnp_read_serial_byte
    loop .drain_serial
    cmp word [handoff_addr + handoff_mac], 0x8c4a
    jne .check_dlink
    cmp word [handoff_addr + handoff_mac + 2], 0x1980
    je .configure
.check_dlink:
    cmp word [handoff_addr + handoff_mac], 0x8b11
    jne .no_match
    cmp word [handoff_addr + handoff_mac + 2], 0x0122
    jne .no_match
.configure:
    mov ax, (0x01 << 8) | isapnp_reg_csn
    call isapnp_write_reg
    xor ax, ax
    mov al, isapnp_reg_ldn
    call isapnp_write_reg
    mov ax, (0x03 << 8) | isapnp_reg_io_base_hi
    call isapnp_write_reg
    xor ax, ax
    mov al, isapnp_reg_io_base_lo
    call isapnp_write_reg
    mov ax, (profile_irq << 8) | isapnp_reg_irq
    call isapnp_write_reg
    mov ax, (0x02 << 8) | isapnp_reg_irq_type
    call isapnp_write_reg
    xor ax, ax
    mov al, isapnp_reg_io_range_check
    call isapnp_write_reg
    mov ax, (0x01 << 8) | isapnp_reg_activate
    call isapnp_write_reg
    clc
    ret
.no_match:
    stc
    ret

isapnp_return_to_key:
    mov ax, (0x02 << 8) | isapnp_reg_config_control
    jmp isapnp_write_reg

isapnp_send_key:
    mov dx, isapnp_addr_port
    mov cx, 32
.write:
    lodsb
    out dx, al
    loop .write
    ret

isapnp_write_reg:
    mov dx, isapnp_addr_port
    out dx, al
    mov al, ah
    mov dx, isapnp_write_data_port
    out dx, al
    ret

isapnp_read_serial_byte:
    push bx
    push cx
    xor ah, ah
    mov bl, 1
    mov cx, 8
.bit:
    mov dx, isapnp_addr_port
    mov al, isapnp_reg_serial_isolation
    out dx, al
    mov dx, isapnp_read_data_port
    in al, dx
    cmp al, 0x55
    jne .second
    or ah, bl
.second:
    in al, dx
    shl bl, 1
    loop .bit
    mov al, ah
    pop cx
    pop bx
    ret

isapnp_key_normal:
    db 0x6a,0xb5,0xda,0xed,0xf6,0xfb,0x7d,0xbe
    db 0xdf,0x6f,0x37,0x1b,0x0d,0x86,0xc3,0x61
    db 0xb0,0x58,0x2c,0x16,0x8b,0x45,0xa2,0xd1
    db 0xe8,0x74,0x3a,0x9d,0xce,0xe7,0x73,0x39
isapnp_key_rt:
    db 0xda,0x6d,0x36,0x1b,0x8d,0x46,0x23,0x91
    db 0x48,0xa4,0xd2,0x69,0x34,0x9a,0x4d,0x26
    db 0x13,0x89,0x44,0xa2,0x51,0x28,0x94,0xca
    db 0x65,0x32,0x19,0x0c,0x86,0x43,0xa1,0x50

%unmacro phase_call_res 1
