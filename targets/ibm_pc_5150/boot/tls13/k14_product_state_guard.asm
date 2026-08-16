; K14 product state guard.
;
; This two-sector, fixed-origin phase brackets the 16 KiB K14 route without
; becoming a new runtime module ABI.  The future resident dispatcher will load
; it at 0000:0700 and near-call the first byte with:
;
;   AL=0  PRE_COLD    invalidate prompt snapshot; save loop-control word
;   AL=1  PRE_HUMAN   as above, then capture an eligible MDA prompt
;   AL=2  POST_ROUTE  reconstruct scrubbed constants/UI and redraw MDA
;   AL=3  ABORT       invalidate a snapshot when the route root never ran
;
; Entry requires DS=0 and a valid SS:SP.  It preserves DS and SS, leaves DF
; clear, and may clobber AX/BX/CX/DX/SI/DI/BP/ES.  Recognized modes return
; CF=0; any other AL returns CF=1 without touching product state.
;
; POST_ROUTE ordering contract:
;   - K14 has scrubbed retired conventional state;
;   - its vault escrow has already restored cursor_row, cursor_col,
;     dpi_prompt_marker_row, agent_loop_pending, and agent_loop_count;
;   - the lifecycle has zeroized the video vault and re-enabled MDA; and
;   - the caller has restored the NIC window exactly once.
;
; POST_ROUTE therefore preserves those five escrow-restored bytes.  The
; PRE-side copy of the loop word is an explicit status-last handoff/fallback,
; not the ordinary POST source.

bits 16
cpu 8086

%include "k14_product_state_guard_abi.inc"

org k14_guard_origin

k14_product_state_guard:
    cld
    cmp al, k14_guard_mode_pre_cold
    je k14_guard_pre_cold
    cmp al, k14_guard_mode_pre_human
    je k14_guard_pre_human
    cmp al, k14_guard_mode_post_route
    je k14_guard_post_route
    cmp al, k14_guard_mode_abort
    je k14_guard_abort
    stc
    ret

k14_guard_pre_cold:
    call k14_guard_pre_common
    clc
    ret

k14_guard_pre_human:
    call k14_guard_pre_common

    ; The volatile vault consumes only MDA's visible page.  CGA uses its
    ; off-screen tail and therefore keeps the durable on-screen prompt.  The
    ; three established MDA facts are one fail-closed boundary: the vault maps
    ; from the BDA, so any disagreement could otherwise erase an unsnapshotted
    ; visible prompt.
    test word [k14_guard_handoff_flags], k14_guard_handoff_flag_mda
    jz .handoff_not_mda
    cmp word [k14_guard_bda_crt_port], k14_guard_mda_crt_port
    jne .capture_failed
    cmp word [k14_guard_video_seg], k14_guard_mda_video_seg
    jne .capture_failed
    jmp short .mda_consistent
.handoff_not_mda:
    cmp word [k14_guard_bda_crt_port], k14_guard_cga_crt_port
    jne .capture_failed
    cmp word [k14_guard_video_seg], k14_guard_cga_video_seg
    jne .capture_failed
    jmp short .not_volatile
.mda_consistent:

    ; A cold/no-prompt route needs no snapshot.  Once a non-empty human MDA
    ; prompt is active, however, every capture rejection is fatal: returning
    ; CF=0 with prompt_valid=0 would let the vault erase the only durable copy.
    cmp byte [k14_guard_prompt_len], 0
    je .not_volatile
    cmp byte [k14_guard_agent_loop_pending], 0
    jne .capture_failed
    cmp byte [k14_guard_tool_fc_state], 0
    jne .capture_failed

    mov cl, [k14_guard_prompt_len]
    xor ch, ch
    mov bl, [k14_guard_screen_cols]
    cmp bl, k14_guard_min_cols
    jb .capture_failed
    cmp bl, k14_guard_max_cols
    ja .capture_failed

    mov dl, k14_guard_prompt_col
    mov dh, [k14_guard_dpi_prompt_marker_row]
    and dh, 0x7f
    cmp dh, k14_guard_visible_rows
    jae .capture_failed

    ; SI = byte offset of the first prompt character in text VRAM.
    mov al, dh
    mul bl
    xor bh, bh
    add ax, k14_guard_prompt_col
    shl ax, 1
    mov si, ax
    mov ax, k14_guard_mda_video_seg
    mov es, ax
    mov di, k14_guard_prompt_head

.capture_next:
    cmp dh, k14_guard_visible_rows
    jae .capture_failed               ; partial copy stays invalid
    mov al, [es:si]
    mov [di], al
    inc di
    cmp di, k14_guard_prompt_hole
    jne .capture_advance
    mov di, k14_guard_prompt_tail     ; never write tool_fc_state
.capture_advance:
    add si, 2
    inc dl
    cmp dl, bl
    jb .capture_loop
    mov dl, k14_guard_prompt_col
    inc dh
    add si, k14_guard_prompt_col * 2
.capture_loop:
    loop .capture_next

    ; Status is the final publication write.  Consumers accept exactly one.
    mov byte [k14_guard_prompt_valid], 1
.not_volatile:
    clc
    ret
.capture_failed:
    stc
    ret

k14_guard_pre_common:
    mov byte [k14_guard_prompt_valid], 0
    mov ax, [k14_guard_agent_loop_pending]
    mov [k14_guard_saved_loop_word], ax
    ret

k14_guard_abort:
    mov byte [k14_guard_prompt_valid], 0
    clc
    ret

k14_guard_post_route:
    ; Restore the exact low-static band tls_client_hello used to install.
    push ds
    pop es
    mov si, k14_guard_low_constants_image
    mov di, k14_guard_low_constants_start
    mov cx, k14_guard_low_constants_len
    rep movsb

    call k14_guard_restore_ui_geometry

    cmp word [k14_guard_bda_crt_port], k14_guard_mda_crt_port
    jne .no_mda_redraw
    call k14_guard_redraw_mda
.no_mda_redraw:
    ; The prompt head aliases ems_ctx_page / ems_ctx_off.  Consume it before
    ; reconstructing those fields; neither representation is live afterward.
    call k14_guard_recompute_ems_cursor
    mov byte [k14_guard_render_last_type], k14_guard_render_type_user

    ; Invalidation is deliberately the final memory write in POST_ROUTE.
    mov byte [k14_guard_prompt_valid], 0
    clc
    ret

k14_guard_restore_ui_geometry:
    ; Prefer the handoff captured by hardware_setup; fall back to the BDA and
    ; finally 80 columns under hostile/corrupt metadata.
    mov al, [k14_guard_handoff_video_cols]
    call k14_guard_validate_cols
    jnc .cols_ready
    mov al, [k14_guard_bda_video_cols]
    call k14_guard_validate_cols
    jnc .cols_ready
    mov al, k14_guard_max_cols
.cols_ready:
    mov [k14_guard_screen_cols], al
    mov [k14_guard_handoff_video_cols], al

    mov ah, k14_guard_dpi_prompt_row
    dec al
    mov [k14_guard_scroll_br], ax

    mov al, [k14_guard_screen_cols]
    sub al, 4
    shr al, 1
    mov [k14_guard_seed_col], al
    mov [k14_guard_handoff_seed_col], al
    mov byte [k14_guard_form_left_col], 2
    mov byte [k14_guard_form_field_col], 20
    cmp byte [k14_guard_screen_cols], 80
    jb .form_ready
    mov al, [k14_guard_seed_col]
    sub al, 6
    mov [k14_guard_form_left_col], al
    add al, 10
    mov [k14_guard_form_field_col], al
.form_ready:

    mov si, k14_guard_cga_attrs
    mov ax, k14_guard_cga_video_seg
    cmp word [k14_guard_bda_crt_port], k14_guard_mda_crt_port
    jne .adapter_ready
    mov si, k14_guard_mda_attrs
    mov ax, k14_guard_mda_video_seg
.adapter_ready:
    mov [k14_guard_video_seg], ax
    mov di, k14_guard_seed_attr
    mov cx, 9
    rep movsb
    mov byte [k14_guard_load_marker_char], '.'
    mov al, [k14_guard_load_attr]
    mov [k14_guard_load_marker_attr], al
    ret

k14_guard_validate_cols:
    cmp al, k14_guard_min_cols
    jb .bad
    cmp al, k14_guard_max_cols
    ja .bad
    clc
    ret
.bad:
    stc
    ret

k14_guard_recompute_ems_cursor:
    cmp word [k14_guard_ems_page_count], 0
    je .done
    mov ax, [k14_guard_far_ctx_base]
    mov dx, [k14_guard_far_ctx_base + 2]
    cmp dx, k14_guard_ems_flat_base_hi
    jb .invalid
    sub dx, k14_guard_ems_flat_base_hi
    mov bx, ax
    and bx, 0x3fff
    mov [k14_guard_ems_ctx_off], bx
    mov cl, 14
.shift:
    shr dx, 1
    rcr ax, 1
    dec cl
    jnz .shift
    mov [k14_guard_ems_ctx_page], ax
.done:
    ret
.invalid:
    xor ax, ax
    mov [k14_guard_ems_ctx_page], ax
    mov [k14_guard_ems_ctx_off], ax
    ret

k14_guard_redraw_mda:
    ; The zeroized vault contains NUL cells.  Establish a readable direct-text
    ; baseline without BIOS or disk I/O, then optionally replay the snapshot.
    mov ax, k14_guard_mda_video_seg
    mov es, ax
    xor di, di
    mov ax, 0x0720
    mov cx, k14_guard_visible_cells
    rep stosw

    cmp byte [k14_guard_prompt_valid], 1
    jne .done
    mov cl, [k14_guard_prompt_len]
    xor ch, ch
    jcxz .done
    mov bl, [k14_guard_screen_cols]
    call k14_guard_validate_cols_bl
    jc .done
    mov dh, [k14_guard_dpi_prompt_marker_row]
    and dh, 0x7f
    cmp dh, k14_guard_visible_rows
    jae .done

    ; Fail safely if hostile state says the wrapped prompt would leave the
    ; visible 25-row page.  Valid product state always passes this bound.
    mov al, k14_guard_visible_rows
    sub al, dh
    xor ah, ah
    mov dl, bl
    sub dl, k14_guard_prompt_col
    mul dl
    cmp ax, cx
    jb .done

    mov al, dh
    mul bl
    xor bh, bh
    shl ax, 1
    mov di, ax
    mov ah, [k14_guard_ready_attr]
    mov al, '>'
    stosw
    mov al, ' '
    stosw

    mov dl, k14_guard_prompt_col
    mov si, k14_guard_prompt_head
    mov bp, k14_guard_prompt_head_len
.draw_next:
    lodsb
    mov ah, [k14_guard_ready_attr]
    stosw
    dec bp
    jnz .source_ready
    mov si, k14_guard_prompt_tail
.source_ready:
    inc dl
    cmp dl, bl
    jb .draw_loop
    mov dl, k14_guard_prompt_col
    add di, k14_guard_prompt_col * 2
.draw_loop:
    loop .draw_next
.done:
    ret

k14_guard_validate_cols_bl:
    cmp bl, k14_guard_min_cols
    jb .bad
    cmp bl, k14_guard_max_cols
    ja .bad
    clc
    ret
.bad:
    stc
    ret

k14_guard_cga_attrs:
    db k14_guard_seed_attr_cga
    db k14_guard_build_attr_cga
    db k14_guard_load_attr_cga
    db k14_guard_crypto_attr_cga
    db k14_guard_ready_attr_cga
    db k14_guard_question_attr_cga
    db k14_guard_error_attr_cga
    db k14_guard_menu_selected_attr_cga
    db k14_guard_menu_idle_attr_cga

k14_guard_mda_attrs:
    db k14_guard_seed_attr_mda
    db k14_guard_build_attr_mda
    db k14_guard_load_attr_mda
    db k14_guard_crypto_attr_mda
    db k14_guard_ready_attr_mda
    db k14_guard_question_attr_mda
    db k14_guard_error_attr_mda
    db k14_guard_menu_selected_attr_mda
    db k14_guard_menu_idle_attr_mda

k14_guard_low_constants_image:
%include "low_static_constants.inc"
k14_guard_low_constants_image_end:

%if (k14_guard_low_constants_image_end - \
    k14_guard_low_constants_image) != k14_guard_low_constants_len
%error "K14 guard constant image does not match the scrubbed constant band"
%endif

k14_product_state_guard_end:

%if (k14_product_state_guard_end - k14_product_state_guard) > \
    k14_guard_max_bytes
%error "K14 product state guard exceeds its two-sector phase"
%endif

times k14_guard_max_bytes - \
    (k14_product_state_guard_end - k14_product_state_guard) db 0
k14_product_state_guard_image_end:
