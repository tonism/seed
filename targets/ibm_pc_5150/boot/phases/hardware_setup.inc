%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

hardware_setup_phase:
    call hardware_setup_phase_init_handoff
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
    mov bl, [load_attr]
    mov al, '.'
    phase_call_res show_load_marker
    call probe_network_card
    jc .failed
    call resolve_network_config
    call read_network_address
    call populate_nic_vtable
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
    ; Build 9: size the conversation window from ram_top so it scales with RAM. The context pool
    ; (window + arena) spans chat_context_start .. (ram_top - stack reserve); split it 50/50 and set
    ; the compaction threshold to 3/4 of the window. The 0x100 reserve covers the ~196 B worst-case
    ; static stack; the compile-time floor %if keeps pool/2 above the arena floor on 16K (bigger
    ; machines only widen both). NOTE: ram_top is fixed 0x8000 on BIOS boot, so scaling currently
    ; tops out near 32K until RAM detection lands (see HANDOFF.md context-management knobs).
    mov ax, [handoff_addr + handoff_ram_top]
    sub ax, 0x100
    sub ax, chat_context_start
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
    mov word [note_len], 0          ; #4 note-as-memory: no compacted note until the first compaction
    sub ah, seed_len
    shr ah, 1
    mov [seed_col], ah
    mov [handoff_addr + handoff_seed_col], ah
    mov byte [form_left_col], 2
    mov byte [form_field_col], 20
    cmp byte [screen_cols], 80
    jb .display_kind
    mov al, [seed_col]
    sub al, 14
    mov [form_left_col], al
    mov al, [seed_col]
    add al, 10
    mov [form_field_col], al
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
    cmp ax, 0x300
    je .detect_ne
    mov cx, load_ticks
    phase_call_res wait_ticks
    ret
.known_3c503:
    mov al, family_3c503
    call store_auto_network_config
    ret
.detect_io_280:
    call autodetect_io_280
    jnc store_auto_network_config
    mov byte [menu_value_a], adapter_select_io_280
    call adapter_select_phase
    ret
.detect_ne:
    call autodetect_ne
    jnc store_auto_network_config
    mov byte [menu_value_a], adapter_select_ne
    call adapter_select_phase
    ret

store_auto_network_config:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_auto
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    mov cx, load_ticks
    phase_call_res wait_ticks
    ret

; Build 12 NIC HAL: fill the dispatch-vector for the detected NIC family, once at boot (the family is
; final after resolve_network_config / the adapter-select menu). Default = the NE-family / no-op ops;
; 3c501 (el1) is a full driver override (its own transmit, receive, and second-frame fallback);
; wd8003 overrides only the DP8390-window enter/restore. This is the ONE remaining per-family `cmp`
; for the hot path -- it runs once, off the hot path, and every resident TX/RX/packet-path call then
; dispatches through the slots with no family branch. Each store writes a resident routine's address
; (absolute) into a resident slot (absolute), so it runs correctly from this phase at low_scratch_start.
populate_nic_vtable:
    mov word [nic_vt_enter], nic_noop
    mov word [nic_vt_restore], nic_noop
    mov word [nic_vt_transmit], ne_transmit_frame
    mov word [nic_vt_receive], ne_try_receive_frame
    mov word [nic_vt_rx_fallback], nic_rx_fallback_none
    mov al, [handoff_addr + handoff_nic_family]
    cmp al, family_3c501
    jne .check_wd
    mov word [nic_vt_transmit], el1_transmit_frame
    mov word [nic_vt_receive], el1_try_receive_frame
    mov word [nic_vt_rx_fallback], el1_rx_second_frame
    ret
.check_wd:
    cmp al, family_wd8003
    jne .done
    mov word [nic_vt_enter], wd_do_enter
    mov word [nic_vt_restore], wd_do_restore
.done:
    ret

autodetect_io_280:
    call probe_wd8003_mac
    jc .probe_3c501
    mov al, family_wd8003
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

adapter_select_phase:
    mov byte [menu_index], 0
    mov byte [blink_state], 0
    call hardware_setup_phase_notify_question
    call .render_adapter_question
.input:
    call hardware_setup_phase_blink_load_marker
    mov ah, 0x01
    int 0x16
    jz .input
    xor ah, ah
    int 0x16
    cmp al, 0x0d
    je .accept
    cmp ah, 0x48
    je .toggle
    cmp ah, 0x50
    jne .input
.toggle:
    xor byte [menu_index], 1
    call .draw_adapter_options
    jmp .input
.accept:
    cmp byte [menu_value_a], adapter_select_ne
    je .accept_ne
    mov al, family_3c501
    cmp byte [menu_index], 0
    je .store
    mov al, family_wd8003
    jmp .store
.accept_ne:
    mov al, family_ne2000
    cmp byte [menu_index], 0
    je .store
    mov al, family_ne1000
.store:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_user
    mov byte [handoff_addr + handoff_nic_irq], profile_irq
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    call hardware_setup_phase_clear_question_area
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    phase_call_res show_load_marker
    ret

.render_adapter_question:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [question_attr]
    mov si, low_scratch_start + (adapter_prompt_text - PHASE_BASE)
    call hardware_setup_phase_type_z
    call .type_adapter_options
    ret

.type_adapter_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_selected_attr]
    call .option_a_ptr
    call hardware_setup_phase_type_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    call .option_b_ptr
    call hardware_setup_phase_type_z
    ret

.draw_adapter_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 0
    jne .draw_first
    mov bl, [menu_selected_attr]
.draw_first:
    call .option_a_ptr
    call .print_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 1
    jne .draw_second
    mov bl, [menu_selected_attr]
.draw_second:
    call .option_b_ptr
    call .print_z
    ret

.option_a_ptr:
    mov si, low_scratch_start + (adapter_3c501_text - PHASE_BASE)
    cmp byte [menu_value_a], adapter_select_ne
    jne .option_done
    mov si, low_scratch_start + (adapter_ne2000_text - PHASE_BASE)
    ret
.option_b_ptr:
    mov si, low_scratch_start + (adapter_wd8003_text - PHASE_BASE)
    cmp byte [menu_value_a], adapter_select_ne
    jne .option_done
    mov si, low_scratch_start + (adapter_ne1000_text - PHASE_BASE)
.option_done:
    ret

.print_z:
    lodsb
    or al, al
    jz .print_done
    phase_call_res print_char
    jmp .print_z
.print_done:
    ret

hardware_setup_phase_type_z:
    lodsb
    or al, al
    jz .type_done
    call hardware_setup_phase_type_char
    jmp hardware_setup_phase_type_z
.type_done:
    ret

hardware_setup_phase_type_char:
    phase_call_res print_char
    mov cx, type_ticks
    phase_call_res wait_ticks
    ret

hardware_nic_ports dw 0x250, 0x280, 0x2a0, 0x2c0, 0x2e0
                   dw 0x300, 0x310, 0x320, 0x330, 0x340
                   dw 0x350, 0x360, 0x380, 0x3a0
                   dw 0
adapter_prompt_text db 'adapter?', 0
adapter_ne2000_text db 'ne2000', 0
adapter_ne1000_text db 'ne1000', 0
adapter_3c501_text db '3c501', 0
adapter_wd8003_text db 'wd8003', 0

hardware_setup_phase_notify_question:
    mov ax, 6087
    call hardware_setup_phase_speaker_tone
    mov cx, 2
    phase_call_res wait_ticks
    jmp hardware_setup_phase_speaker_off

hardware_setup_phase_clear_question_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, seed_row
    xor cl, cl
    mov dh, question_row + agent_slot_count
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

hardware_setup_phase_blink_load_marker:
    mov byte [cursor_row], seed_row
    mov dl, [seed_col]
    mov [cursor_col], dl
    mov bl, [load_marker_attr]
    mov al, [load_marker_char]
    xor byte [blink_state], 1
    jnz .show
    mov al, ' '
.show:
    phase_call_res print_char
    mov cx, 2
    phase_call_res wait_ticks
    ret

hardware_setup_phase_speaker_tone:
    push ax
    mov al, 0xb6
    out 0x43, al
    pop ax
    out 0x42, al
    mov al, ah
    out 0x42, al
    in al, 0x61
    or al, 0x03
    out 0x61, al
    ret

hardware_setup_phase_speaker_off:
    in al, 0x61
    and al, 0xfc
    out 0x61, al
    ret

; Build 9 (compaction redesign): copy the keep-alive GET template into its persistent pool slot
; (ka_template_persistent) once at boot. agent_api_keepalive sends it from there during long
; renders; relocating it out of the renderer frees that one sector for the compaction capture.
hardware_setup_stage_ka_template:
    push es
    push ds
    pop es
    cld
    mov si, low_scratch_start + (ka_template_source - PHASE_BASE)
    mov di, ka_template_persistent
    mov cx, ka_request_len
    rep movsb
    ; Build 11 ESC: stage the int 9 keyboard hook to its pool slot + install the vector, HERE (before the
    ; network I/O, like the ka template) so the source is copied while intact. Position-independent handler
    ; (only absolute esc_stop/esc_int9_old refs at seg 0 + relative jumps), so it runs from the pool. It
    ; chains every non-ESC key to the BIOS, so the prompt's keyboard input is unaffected.
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
ka_template_source:
    db "GET /v1 HTTP/1.1", 13, 10
    db "Host: api.openai.com", 13, 10
    db 13, 10
ka_template_source_end:
%if (ka_template_source_end - ka_template_source) != ka_request_len
%error "ka_request_len (layout.inc) does not match the staged keep-alive template length"
%endif

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

%unmacro phase_call_res 1
