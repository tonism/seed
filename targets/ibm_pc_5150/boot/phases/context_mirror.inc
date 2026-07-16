%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

ctx_xfer_gdt equ tls_rx_copy

context_mirror_phase:
    ; Mirror the live seg-0 chat window to the canonical far context log. <=64K machines leave
    ; far_log_seg_var = 0 and keep the Build 11 local compaction path.
    push ds
    xor ax, ax
    mov ds, ax
    cmp word [far_log_seg_var], 0
    je .done
    cmp byte [compacting_msg], 0
    je .not_compacted_note
    xor ax, ax
    mov [far_flushed_len], ax
    mov [far_flushed_len + 2], ax
    mov [far_flushed_esc], ax
    mov [far_flushed_esc + 2], ax
.not_compacted_note:
    mov ax, [far_flushed_len]
    mov dx, [far_flushed_len + 2]
    add ax, [chat_context_used]
    adc dx, 0
    cmp dx, [far_window_cap + 2]
    ja .far_log_full
    jb .cap_ok
    cmp ax, [far_window_cap]
    jb .cap_ok
.far_log_full:
    stc
    jmp .return
.cap_ok:
    push es
    cmp word [far_ctx_base + 2], ems_flat_base_hi
    jb .mirror_conv
    cmp word [ems_page_count], 0
    je .mirror_ext

    ; EMS windowed write: seg-0 window -> flat (far_ctx_base + far_flushed_len).
    mov ax, [far_ctx_base]
    mov dx, [far_ctx_base + 2]
    add ax, [far_flushed_len]
    adc dx, [far_flushed_len + 2]
    sub ax, 0
    sbb dx, ems_flat_base_hi
    mov di, ax
    and di, 0x3fff
    mov cl, 14
.ems_wr_pshift:
    shr dx, 1
    rcr ax, 1
    dec cl
    jnz .ems_wr_pshift
    mov bx, ax
    mov dx, ems_base_port
    mov al, bl
    out dx, al
    mov ax, ems_frame_seg
    mov es, ax
    call .context_base_si
    mov cx, [chat_context_used]
    cld
    jcxz .ok_pop
.ems_wr_loop:
    lodsb
    stosb
    cmp di, ems_page_size
    jb .ems_wr_cont
    xor di, di
    inc bx
    mov dx, ems_base_port
    mov al, bl
    out dx, al
.ems_wr_cont:
    loop .ems_wr_loop
    jmp .ok_pop

.mirror_conv:
    mov ax, [far_flushed_len]
    mov dx, [far_flushed_len + 2]
    mov di, ax
    and di, 0x000f
    mov cx, 4
.conv_norm:
    shr dx, 1
    rcr ax, 1
    loop .conv_norm
    add ax, [far_log_seg_var]
    mov es, ax
    call .context_base_si
    mov cx, [chat_context_used]
    cld
    rep movsb
.ok_pop:
    pop es
.ok:
    clc
    jmp .return

.mirror_ext:
    test word [handoff_addr + handoff_flags], handoff_flag_unreal
    jz .mirror_ext_bios
    ; 386+ unreal mode keeps BIOS-compatible real mode while allowing a flat
    ; write into the native extended context.
    call .refresh_unreal
    mov ax, [far_ctx_base]
    mov dx, [far_ctx_base + 2]
    add ax, [far_flushed_len]
    adc dx, [far_flushed_len + 2]
    mov [tool_addr], ax
    mov [tool_addr + 2], dx
    db 0x66, 0x8b, 0x3e
    dw tool_addr                         ; mov edi, [tool_addr]
    call .context_base_si
    mov cx, [chat_context_used]
    cld
    jcxz .ok_pop
.unreal_wr_loop:
    lodsb
    db 0x64, 0x67, 0x88, 0x07            ; mov [fs:edi], al
    db 0x66, 0x47                        ; inc edi
    loop .unreal_wr_loop
    jmp .ok_pop
.mirror_ext_bios:
    ; 286 native extended memory is windowed through BIOS int 15h AH=87h. The live window is small
    ; enough to copy in one block; odd byte counts copy one harmless pad byte past the streamed length.
    mov cx, [chat_context_used]
    jcxz .ok_pop
    push ds
    pop es
    mov di, ctx_xfer_gdt
    xor ax, ax
    mov cx, 24
    rep stosw
    mov cx, [chat_context_used]
    inc cx
    shr cx, 1
    mov ax, cx
    shl ax, 1
    dec ax
    mov [ctx_xfer_gdt + 0x10], ax
    mov [ctx_xfer_gdt + 0x18], ax
    call .context_base_si
    mov [ctx_xfer_gdt + 0x12], si
    mov byte [ctx_xfer_gdt + 0x14], 0
    mov byte [ctx_xfer_gdt + 0x15], 0x93
    mov ax, [far_ctx_base]
    mov dx, [far_ctx_base + 2]
    add ax, [far_flushed_len]
    adc dx, [far_flushed_len + 2]
    mov [ctx_xfer_gdt + 0x1a], ax
    mov [ctx_xfer_gdt + 0x1c], dl
    mov byte [ctx_xfer_gdt + 0x1d], 0x93
    push ds
    pop es
    mov si, ctx_xfer_gdt
    mov ah, 0x87
    int 0x15
    jc .fail_pop
    jmp .ok_pop
.fail_pop:
    pop es
    stc
    jmp .return

.done:
    clc
.return:
    pop ds
    ret

.context_base_si:
    mov si, [handoff_addr + handoff_ram_top]
    sub si, 0x100
    cmp word [handoff_addr + handoff_ram_top], ram_tier_32k_min
    jb .ctx_base_ready
    mov si, tools_cache
.ctx_base_ready:
    sub si, [chat_context_len_var]
    ret

.refresh_unreal:
    push ax
    pushf
    cli
    db 0x0f, 0x01, 0x16
    dw low_scratch_start + (.unreal_gdt_ptr - PHASE_BASE) ; lgdt [unreal_gdt_ptr]
    db 0x0f, 0x20, 0xc0                  ; mov eax, cr0
    db 0x0c, 0x01                        ; or al, 1
    db 0x0f, 0x22, 0xc0                  ; mov cr0, eax
    db 0xea
    dw low_scratch_start + (.refresh_pm - PHASE_BASE)
    dw 0x0008
.refresh_pm:
    mov ax, 0x0010
    db 0x8e, 0xe0                        ; mov fs, ax
    db 0x0f, 0x20, 0xc0                  ; mov eax, cr0
    db 0x24, 0xfe                        ; and al, ~1
    db 0x0f, 0x22, 0xc0                  ; mov cr0, eax
    db 0xea
    dw low_scratch_start + (.refresh_rm - PHASE_BASE)
    dw 0x0000
.refresh_rm:
    popf
    pop ax
    clc
    ret

align 8, db 0
.unreal_gdt:
    dq 0
    dw 0xffff, 0x0000
    db 0x00, 0x9a, 0x00, 0x00
    dw 0xffff, 0x0000
    db 0x00, 0x92, 0xcf, 0x00
.unreal_gdt_end:
.unreal_gdt_ptr:
    dw .unreal_gdt_end - .unreal_gdt - 1
    dd low_scratch_start + (.unreal_gdt - PHASE_BASE)
