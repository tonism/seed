%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name the runtime load address"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

tool_xfer_gdt equ tls_rx_copy
tool_xfer_buf equ tool_xfer_gdt + 0x30
tool_ext_exec_len equ 256

tool_memory_phase:
    cld
    mov al, [tool_helper_pending]
    mov byte [tool_helper_pending], 0
    cmp al, 'r'
    je .do_read
    cmp al, 'w'
    je .do_write
    cmp al, 'e'
    je .do_exec
    ret

.do_exec:
    mov cx, 1
    call .addr_range_ok
    jc .exec_range_fail
    call .addr_is_native_ext
    jnc .do_exec_ext
    call .addr_to_farptr             ; build [tool_farptr] = off:seg from the 32-bit tool_addr; es back to ds
    mov ax, .word_execute            ; print "> execute <addr>" BEFORE the call: bad code may never return,
    call .res_line                   ; so the action line must land first or the screen looks stuck on the
    call .res_close                  ; previous directive. es back to 0 for the far call.
    push ds
    push es
    cld
    call far [tool_farptr]           ; agent code returns with retf (uniform far call)
    cld
    pop es
    pop ds
    mov bx, ax                       ; bx = returned AX (survives the out_* helpers)
    pushf
    pop dx                           ; dx = returned flags (CF in bit 0)
    mov al, '0'
    test dl, 1
    jz .exec_cf_char
    mov al, '1'
.exec_cf_char:
    push ax
    mov byte [tool_sink], 1
    mov si, PHASE_LOAD_ADDR + (.text_ax - PHASE_BASE)
    call .out_str
    mov ax, bx
    call .out_hex16
    mov si, PHASE_LOAD_ADDR + (.text_cf - PHASE_BASE)
    call .out_str
    pop ax
    call .out_putc
    call .compute_fc_suffix_len
    ret
.do_exec_ext:
    mov ax, .word_execute
    call .res_line
    call .res_close
    mov cx, tool_ext_exec_len
    mov di, tool_xfer_buf
    call .ext_read_to_near
    jc .exec_ext_failed
    mov word [tool_farptr], tool_xfer_buf
    mov word [tool_farptr + 2], 0
    push ds
    push es
    cld
    call far [tool_farptr]
    cld
    pop es
    pop ds
    mov bx, ax
    pushf
    pop dx
    jmp .exec_report
.exec_ext_failed:
    mov bx, 0x8700
    mov dx, 1
.exec_report:
    mov al, '0'
    test dl, 1
    jz .exec_ext_cf_char
    mov al, '1'
.exec_ext_cf_char:
    push ax
    mov byte [tool_sink], 1
    mov si, PHASE_LOAD_ADDR + (.text_ax - PHASE_BASE)
    call .out_str
    mov ax, bx
    call .out_hex16
    mov si, PHASE_LOAD_ADDR + (.text_cf - PHASE_BASE)
    call .out_str
    pop ax
    call .out_putc
    call .compute_fc_suffix_len
    ret
.exec_range_fail:
    mov ax, .word_execute_failed
    call .res_fail_range
    call .compute_fc_suffix_len
    ret

.do_read:
    mov cl, [tool_readlen]
    xor ch, ch
    jcxz .read_emit
    call .addr_range_ok
    jc .read_range_fail
    call .addr_is_unreal_ext
    jnc .read_unreal
    call .addr_is_native_ext
    jc .read_direct
    mov di, tool_readbuf
    mov cl, [tool_readlen]
    xor ch, ch
    call .ext_read_to_near
    jnc .read_emit
    mov byte [tool_readlen], 0
    jmp .read_emit
.read_direct:
    call .addr_to_esbx
    mov cl, [tool_readlen]
    xor ch, ch
    mov di, tool_readbuf
.read_stage:
    mov al, [es:bx]
    mov [di], al
    inc bx
    inc di
    loop .read_stage
    push ds
    pop es
    jmp .read_emit
.read_unreal:
    call .refresh_unreal
    mov cl, [tool_readlen]
    xor ch, ch
    db 0x66, 0x8b, 0x1e
    dw tool_addr                         ; mov ebx, [tool_addr]
    push ds
    pop es
    mov di, tool_readbuf
.read_unreal_stage:
    db 0x64, 0x67, 0x8a, 0x03            ; mov al, [fs:ebx]
    stosb
    db 0x66, 0x43                        ; inc ebx
    loop .read_unreal_stage
.read_emit:
    mov ax, .word_read
    call .res_line
    call .fc_drop_read_from
    mov byte [tool_sink], 1
    mov al, ':'
    call .out_putc
.read_dump:
    xor ax, ax
    mov al, [tool_readlen]
    mov [tool_seg], ax
    mov si, tool_readbuf
.read_byte:
    cmp word [tool_seg], 0
    je .read_done
    mov al, ' '
    call .out_putc
    mov al, [si]
    call .out_hex8
    inc si
    dec word [tool_seg]
    jmp .read_byte
.read_done:
.read_eol:
    call .res_close
    call .compute_fc_suffix_len
    ret
.read_range_fail:
    mov ax, .word_read_failed
    call .res_fail_range
    call .compute_fc_suffix_len
    ret

.do_write:
    mov si, [tool_readlen]           ; parser stored the byte-string scan pointer here
    call .count_hex_bytes
    or cx, cx
    jnz .write_has_bytes
    jmp .write_report
.write_has_bytes:
    call .addr_range_ok
    jc .write_range_fail
    mov si, [tool_readlen]
    call .addr_is_unreal_ext
    jnc .write_unreal
    call .addr_is_native_ext
    jnc .write_ext
    call .addr_to_esbx
    mov bp, 4
.write_byte:
    or bp, bp
    jz .write_eol
    call .parse_hex
    jc .write_eol
    mov [es:bx], al
    inc bx
    dec bp
    jmp .write_byte
.write_eol:
    push ds
    pop es
    jmp .write_report
.write_ext:
    mov di, tool_xfer_buf
    xor bp, bp
.write_ext_byte:
    call .parse_hex
    jc .write_ext_done
    stosb
    inc bp
    cmp bp, 4
    jb .write_ext_byte
.write_ext_done:
    mov cx, bp
    jcxz .write_ext_report
    mov si, tool_xfer_buf
    call .ext_write_from_near
.write_ext_report:
    jmp .write_report
.write_unreal:
    call .refresh_unreal
    db 0x66, 0x8b, 0x1e
    dw tool_addr                         ; mov ebx, [tool_addr]
    mov bp, 4
.write_unreal_byte:
    or bp, bp
    jz .write_ext_report
    call .parse_hex
    jc .write_ext_report
    db 0x64, 0x67, 0x88, 0x03            ; mov [fs:ebx], al
    db 0x66, 0x43                        ; inc ebx
    dec bp
    jmp .write_unreal_byte
.write_report:
    mov ax, .word_wrote
    call .res_line
    call .res_close
    call .compute_fc_suffix_len
    ret
.write_range_fail:
    mov ax, .word_write_failed
    call .res_fail_range
    call .compute_fc_suffix_len
    ret

; ---- flat 32-bit address -> far/HMA/EMS access (Build 12 M1/M2/M3) ----
.addr_to_esbx:
    mov dx, [tool_addr + 2]
    cmp dx, ems_flat_base_hi
    jae .addr_to_ems
    mov ax, [tool_addr]
    mov bx, ax
    and bx, 0x000f
    mov cl, 4
    shr ax, cl
    mov cl, 12
    shl dx, cl
    or ax, dx
    mov [tool_seg], ax
    mov es, ax
    ret
.addr_to_hma:
    mov ax, [tool_addr]
    cmp ax, hma_flat_top_lo
    jae .addr_to_ems
    mov bx, ax
    add bx, 0x0010
    mov ax, 0xffff
    mov [tool_seg], ax
    mov es, ax
    ret
.addr_to_ems:
    cmp dx, hma_flat_base_hi
    jne .addr_to_ems_window
    test word [handoff_addr + handoff_flags], handoff_flag_hma
    jnz .addr_to_hma
.addr_to_ems_window:
    mov ax, [tool_addr]
    sub dx, ems_flat_base_hi
    mov bx, ax
    and bx, 0x3fff
    mov cl, 14
    shr ax, cl
    mov cl, 2
    shl dx, cl
    or ax, dx
    mov dx, ems_base_port
    out dx, al
    mov ax, ems_frame_seg
    mov [tool_seg], ax
    mov es, ax
    ret
.addr_to_farptr:
    call .addr_to_esbx
    mov [tool_farptr], bx
    mov ax, [tool_seg]
    mov [tool_farptr + 2], ax
    push ds
    pop es
    ret

.addr_is_native_ext:
    cmp word [ems_page_count], 0
    jne .not_native_ext
    cmp word [far_ctx_base + 2], ems_flat_base_hi
    jb .not_native_ext
    mov dx, [tool_addr + 2]
    cmp dx, ext_flat_base_hi
    jb .not_native_ext
    clc
    ret
.not_native_ext:
    stc
    ret

.addr_is_unreal_ext:
    test word [handoff_addr + handoff_flags], handoff_flag_unreal
    jz .not_native_ext
    mov dx, [tool_addr + 2]
    cmp dx, ext_flat_base_hi
    jb .not_native_ext
    clc
    ret

.refresh_unreal:
    push ax
    pushf
    cli
    db 0x0f, 0x01, 0x16
    dw PHASE_LOAD_ADDR + (.tool_unreal_gdt_ptr - PHASE_BASE) ; lgdt [tool_unreal_gdt_ptr]
    db 0x0f, 0x20, 0xc0                              ; mov eax, cr0
    db 0x0c, 0x01                                    ; or al, 1
    db 0x0f, 0x22, 0xc0                              ; mov cr0, eax
    db 0xea
    dw PHASE_LOAD_ADDR + (.refresh_pm - PHASE_BASE)
    dw 0x0008
.refresh_pm:
    mov ax, 0x0010
    db 0x8e, 0xe0                                    ; mov fs, ax
    db 0x0f, 0x20, 0xc0                              ; mov eax, cr0
    db 0x24, 0xfe                                    ; and al, ~1
    db 0x0f, 0x22, 0xc0                              ; mov cr0, eax
    db 0xea
    dw PHASE_LOAD_ADDR + (.refresh_rm - PHASE_BASE)
    dw 0x0000
.refresh_rm:
    popf
    pop ax
    clc
    ret

align 8, db 0
.tool_unreal_gdt:
    dq 0
    dw 0xffff, 0x0000
    db 0x00, 0x9a, 0x00, 0x00
    dw 0xffff, 0x0000
    db 0x00, 0x92, 0xcf, 0x00
.tool_unreal_gdt_end:
.tool_unreal_gdt_ptr:
    dw .tool_unreal_gdt_end - .tool_unreal_gdt - 1
    dd PHASE_LOAD_ADDR + (.tool_unreal_gdt - PHASE_BASE)

.ext_read_to_near:                  ; cx = byte count, di = near destination
    mov ax, [tool_addr]
    mov dx, [tool_addr + 2]
    mov si, di
    jmp .ext_move_to_near
.ext_write_from_near:               ; cx = byte count, si = near source
    mov ax, si
    xor dx, dx
    mov [tool_farptr], ax
    mov [tool_farptr + 2], dx
    mov ax, [tool_addr]
    mov dx, [tool_addr + 2]
    mov [tool_farptr + 4], ax
    mov [tool_farptr + 6], dx
    jmp .ext_move
.ext_move_to_near:
    mov [tool_farptr], ax
    mov [tool_farptr + 2], dx
    mov [tool_farptr + 4], si
    mov word [tool_farptr + 6], 0
.ext_move:
    jcxz .ext_ok
    push cx
    inc cx
    shr cx, 1                         ; BIOS wants words; odd byte counts copy one padded byte
    push cx
    push ds
    pop es
    mov di, tool_xfer_gdt
    xor ax, ax
    mov cx, 24
    rep stosw
    pop cx                            ; cx = word count
    mov ax, cx
    shl ax, 1
    dec ax                            ; descriptor limit = copied bytes - 1
    mov [tool_xfer_gdt + 0x10], ax
    mov [tool_xfer_gdt + 0x18], ax
    mov ax, [tool_farptr]
    mov [tool_xfer_gdt + 0x12], ax
    mov al, [tool_farptr + 2]
    mov [tool_xfer_gdt + 0x14], al
    mov byte [tool_xfer_gdt + 0x15], 0x93
    mov ax, [tool_farptr + 4]
    mov [tool_xfer_gdt + 0x1a], ax
    mov al, [tool_farptr + 6]
    mov [tool_xfer_gdt + 0x1c], al
    mov byte [tool_xfer_gdt + 0x1d], 0x93
    push ds
    pop es
    mov si, tool_xfer_gdt
    mov ah, 0x87
    int 0x15
    pop ax                             ; original byte count, discarded
    jc .ext_fail
.ext_ok:
    clc
    ret
.ext_fail:
    push ds
    pop es
    stc
    ret

; ---- parse one hex token at [si] into dx:ax; callers use al for byte writes ----
.parse_hex:
    push bx
    xor ax, ax
    xor dx, dx
    xor bx, bx
.ph_skip_space:
    cmp byte [si], ' '
    jne .ph_quote
    inc si
    jmp .ph_skip_space
.ph_quote:
    cmp word [si], 0x225c
    jne .ph_prefix
    inc si
    inc si
.ph_prefix:
    cmp byte [si], '0'
    jne .ph_next
    mov cl, [si + 1]
    or cl, 0x20
    cmp cl, 'x'
    jne .ph_next
    add si, 2
.ph_next:
    mov cl, [si]
    cmp cl, '0'
    jb .ph_end
    cmp cl, '9'
    jbe .ph_digit
    or cl, 0x20
    cmp cl, 'a'
    jb .ph_end
    cmp cl, 'f'
    ja .ph_end
    sub cl, 'a' - 10
    jmp .ph_accum
.ph_digit:
    sub cl, '0'
.ph_accum:
    shl ax, 1
    rcl dx, 1
    shl ax, 1
    rcl dx, 1
    shl ax, 1
    rcl dx, 1
    shl ax, 1
    rcl dx, 1
    or al, cl
    inc bx
    inc si
    jmp .ph_next
.ph_end:
    or bx, bx
    jz .ph_fail
    cmp byte [si], ' '
    jne .ph_ok
    inc si
.ph_ok:
    pop bx
    clc
    ret
.ph_fail:
    pop bx
    stc
    ret

.count_hex_bytes:
    xor bp, bp
    mov di, 4
.chb_next:
    call .parse_hex
    jc .chb_done
    inc bp
    dec di
    jnz .chb_next
.chb_done:
    mov cx, bp
    ret

.addr_range_ok:
    or cx, cx
    jnz .range_nonempty
    jmp .range_fail
.range_nonempty:
    mov si, [tool_addr]                ; start low
    mov di, [tool_addr + 2]            ; start high
    mov bx, si
    mov bp, di
    add bx, cx
    adc bp, 0                          ; exclusive end = start + len
    jc .range_fail

    ; Low conventional arena: [chat_pool_start .. dynamic_context_base).
    or di, di
    jnz .range_far
    or bp, bp
    jnz .range_far
    cmp si, chat_pool_start
    jb .range_far
    mov ax, [handoff_addr + handoff_ram_top]
    sub ax, 0x100
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .range_low_top_ready
    mov ax, tools_cache
.range_low_top_ready:
    sub ax, [chat_context_len_var]
    cmp si, ax
    jae .range_far
    cmp bx, ax
    jbe .range_ok

.range_far:
    ; Far conventional arena: [far_arena_base .. far_arena_top).
    mov ax, di
    cmp ax, [far_arena_base + 2]
    jb .range_hma
    ja .range_far_start_ok
    mov ax, si
    cmp ax, [far_arena_base]
    jb .range_hma
.range_far_start_ok:
    mov ax, bp
    cmp ax, [far_arena_top + 2]
    ja .range_hma
    jb .range_ok
    mov ax, bx
    cmp ax, [far_arena_top]
    jbe .range_ok

.range_hma:
    ; HMA direct arena: [0x00100000 .. 0x0010fff0), only when A20 opened it.
    test word [handoff_addr + handoff_flags], handoff_flag_hma
    jz .range_ext
    cmp di, hma_flat_base_hi
    jne .range_ext
    cmp si, hma_flat_top_lo
    jae .range_fail
    cmp bp, hma_flat_top_hi
    jne .range_fail
    cmp bx, hma_flat_top_lo
    jbe .range_ok
    jmp .range_fail

.range_ext:
    ; EMS/native extended arena: [ledger e@ base .. far_ctx_base).
    mov ax, ems_flat_base_hi
    test word [handoff_addr + handoff_flags], handoff_flag_hma
    jz .range_ext_base_ready
    mov ax, ext_flat_base_hi
.range_ext_base_ready:
    cmp di, ax
    jb .range_fail
    mov ax, bp
    cmp ax, [far_ctx_base + 2]
    ja .range_fail
    jb .range_ok
    mov ax, bx
    cmp ax, [far_ctx_base]
    jbe .range_ok
    jmp .range_fail

.range_ok:
    clc
    ret
.range_fail:
    stc
    ret

; ---- result emit: one readable line, model-facing output + dim screen echo ----
.res_line:
    call .res_open
    call .out_hex32
    call .phys_differs
    jnc .res_line_done
    mov si, PHASE_LOAD_ADDR + (.text_arrow - PHASE_BASE)
    call .out_str
    call .out_phys32
.res_line_done:
    ret
.res_fail_range:
    call .res_open
    call .out_hex32
    mov si, PHASE_LOAD_ADDR + (.text_out_of_range - PHASE_BASE)
    call .out_str
    call .res_close
    ret
.res_open:
    push ax
    mov byte [api_stream_seen], 1
    mov byte [tool_sink], 0
    mov byte [fc_output_len], 0
    mov byte [fc_output_buf], 0
    cmp byte [render_last_type], render_type_system
    je .res_line_nl
    cmp byte [render_last_type], render_type_user
    je .res_line_set_type
    call .scr_newline
.res_line_set_type:
    mov byte [render_last_type], render_type_system
.res_line_nl:
    call .scr_newline
    call .scr_set_video
    mov al, '>'
    call .scr_putc
    mov al, ' '
    call .scr_putc
    pop si
    add si, PHASE_LOAD_ADDR - PHASE_BASE
    call .out_str
    ret
.res_close:
    call .scr_clr_video
    ret

.out_str:
    push ax
.ostr_next:
    mov al, [si]
    or al, al
    jz .ostr_done
    call .out_putc
    inc si
    jmp .ostr_next
.ostr_done:
    pop ax
    ret

.out_putc:
    cmp byte [tool_sink], 2
    je .out_putc_screen
    call .fc_out_putc
    cmp byte [tool_sink], 0
    jne .out_putc_done
.out_putc_screen:
    call .scr_putc
.out_putc_done:
    ret
.fc_out_putc:
    push bx
    xor bh, bh
    mov bl, [fc_output_len]
    cmp bx, fc_output_max - 1
    jae .fop_done
    mov [fc_output_buf + bx], al
    inc byte [fc_output_len]
    mov byte [fc_output_buf + bx + 1], 0
.fop_done:
    pop bx
    ret
.fc_drop_read_from:
    push ds
    pop es
    xor ch, ch
    mov cl, [fc_output_len]
    cmp cx, 10
    jb .fdrf_done
    sub cx, 10
    inc cx
    mov si, fc_output_buf + 10
    mov di, fc_output_buf + 5
    rep movsb
    sub byte [fc_output_len], 5
.fdrf_done:
    ret
.scr_putc:
    push bx
    mov bl, [menu_idle_attr]
.sp_store:
    phase_call_res print_char
    pop bx
    mov al, [cursor_col]
    cmp al, [screen_cols]
    jb .sp_done
    call .scr_newline
.sp_done:
    ret

.out_hex32:
    mov dx, [tool_addr + 2]
    mov ax, [tool_addr]
.out_hex32_dxax:
    push ax
    push dx
    mov al, '0'
    call .out_putc
    mov al, 'x'
    call .out_putc
    pop ax
    call .out_hex16
    pop ax
    jmp .out_hex16
.out_phys32:
    call .addr_is_unreal_ext
    jnc .out_hex32
    call .addr_is_native_ext
    jnc .out_hex32
    mov dx, [tool_addr + 2]
    cmp dx, ems_flat_base_hi
    jb .out_hex32
    cmp dx, hma_flat_base_hi
    jne .out_phys32_ems
    test word [handoff_addr + handoff_flags], handoff_flag_hma
    jz .out_phys32_ems
    cmp word [tool_addr], hma_flat_top_lo
    jb .out_hex32
.out_phys32_ems:
    mov ax, [tool_addr]
    and ax, 0x3fff
    mov dx, ems_frame_seg >> 12
    jmp .out_hex32_dxax
.phys_differs:
    call .addr_is_unreal_ext
    jnc .phys_same
    call .addr_is_native_ext
    jnc .phys_same
    mov dx, [tool_addr + 2]
    cmp dx, ems_flat_base_hi
    jb .phys_same
    cmp dx, hma_flat_base_hi
    jne .phys_diff
    test word [handoff_addr + handoff_flags], handoff_flag_hma
    jz .phys_diff
    cmp word [tool_addr], hma_flat_top_lo
    jb .phys_same
.phys_diff:
    stc
    ret
.phys_same:
    clc
    ret
.out_hex16:
    push ax
    mov al, ah
    call .out_hex8
    pop ax
.out_hex8:
    push ax
    shr al, 1
    shr al, 1
    shr al, 1
    shr al, 1
    call .out_hex_nib
    pop ax
.out_hex_nib:
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .out_nib_emit
    add al, 'A' - '0' - 10
.out_nib_emit:
    jmp .out_putc

.scr_set_video:
    mov ax, [video_seg]
    mov es, ax
    ret
.scr_clr_video:
    push ds
    pop es
    ret
.scr_newline:
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

.compute_fc_suffix_len:
    mov ax, api_fc_call_open_text_len + api_fc_name_mid_text_len + api_fc_args_mid_text_len
    add ax, api_fc_output_open_text_len + api_fc_output_mid_text_len + api_stream_json_close_text_len
    xor bh, bh
    mov bl, [fc_call_id_len]
    add ax, bx
    add ax, bx
    mov bl, [fc_name_len]
    add ax, bx
    add ax, [fc_args_len]
    mov bl, [fc_output_len]
    add ax, bx
    call .add_prev_fc_suffix_len
    mov [fc_suffix_len], ax
    ret
.add_prev_fc_suffix_len:
    cmp byte [fc_match_state], 0
    je .ap_done
    add ax, api_fc_call_open_text_len + api_fc_name_mid_text_len + api_fc_args_mid_text_len + 1
    add ax, api_fc_output_open_text_len + api_fc_output_mid_text_len
    mov bl, [fc_match_state]
    add ax, bx
    add ax, bx
    mov bl, [fc_capture_len + 1]
    add ax, bx
    mov bl, [fc_capture_len]
    add ax, bx
.ap_done:
    ret

.word_read           db 'read from ', 0
.word_wrote          db 'write to ', 0
.word_execute        db 'execute ', 0
.word_read_failed    db 'read failed: ', 0
.word_write_failed   db 'write failed: ', 0
.word_execute_failed db 'execute failed: ', 0
.text_ax             db ' ax=', 0
.text_cf             db ' cf=', 0
.text_arrow          db ' -> ', 0
.text_out_of_range   db ' out of range', 0

%unmacro phase_call_res 1
