%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

driver_candidate_table equ agent_ids
driver_candidate_len equ 16
driver_candidate_count equ agent_count
driver_choice_index equ agent_draw_index

driver_load_phase:
    mov byte [driver_candidate_count], 0
    mov byte [handoff_addr + handoff_net_error], net_error_driver
    call .find_seed_dir
    jc .failed
    mov ax, [fs_file_cluster]
    mov [fs_current_cluster], ax
    mov di, low_scratch_start + (driver_load_drivers_name - PHASE_BASE)
    call .find_dir_entry
    jc .failed
    mov ax, [fs_file_cluster]
    call .scan_driver_dir
    cmp byte [driver_candidate_count], 0
    je .failed
    cmp byte [driver_candidate_count], 1
    jne .choose_driver
    xor al, al
    jmp .load_selected
.choose_driver:
    call .ask_driver
.load_selected:
    call .candidate_ptr
    mov ax, [si]
    call .load_driver_cluster
    jc .failed
    call .install_loaded_driver
    jc .failed
    mov byte [handoff_addr + handoff_net_error], net_error_none
    clc
    ret
.failed:
    mov byte [handoff_addr + handoff_net_error], net_error_driver
    stc
    ret

.scan_driver_dir:
    cmp ax, fat_first_data_cluster
    jb .scan_failed
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    phase_call_res read_abs_sector
    jc .scan_failed
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.scan_entry:
    mov al, [si]
    or al, al
    jz .scan_done
    cmp al, 0xe5
    je .scan_advance
    test byte [si + 11], 0x18
    jnz .scan_advance
    call .entry_is_drv
    jc .scan_advance
    cmp word [si + 30], 0
    jne .scan_advance
    cmp word [si + 28], nic_driver_slot_len
    jne .scan_advance
    push si
    push cx
    mov ax, [si + 26]
    call .load_driver_cluster
    jc .candidate_done
    call .loaded_driver_suits
    jc .candidate_done
    pop cx
    pop si
    call .add_candidate
    jmp .scan_advance
.candidate_done:
    pop cx
    pop si
.scan_advance:
    add si, fat_dir_entry_size
    loop .scan_entry
.scan_done:
    clc
    ret
.scan_failed:
    stc
    ret

.entry_is_drv:
    cmp byte [si + 8], 'D'
    jne .not_drv
    cmp byte [si + 9], 'R'
    jne .not_drv
    cmp byte [si + 10], 'V'
    jne .not_drv
    clc
    ret
.not_drv:
    stc
    ret

.load_driver_cluster:
    cmp ax, fat_first_data_cluster
    jb .load_failed
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, nic_driver_slot
    phase_call_res read_abs_sector
    ret
.load_failed:
    stc
    ret

.loaded_driver_suits:
    cmp word [nic_driver_slot + nic_driver_meta_magic_off], 0x4453
    jne .suit_failed
    cmp word [nic_driver_slot + nic_driver_meta_magic_off + 2], 0x5652
    jne .suit_failed
    cmp byte [nic_driver_slot + nic_driver_meta_version_off], nic_driver_abi_version
    jne .suit_failed
    mov cl, [handoff_addr + handoff_nic_family]
    mov ax, 1
    shl ax, cl
    test [nic_driver_slot + nic_driver_meta_family_mask_off], ax
    jz .suit_failed
    clc
    ret
.suit_failed:
    stc
    ret

.add_candidate:
    cmp byte [driver_candidate_count], agent_slot_count
    jae .add_done
    push cx
    push si
    mov al, [driver_candidate_count]
    xor ah, ah
    mov di, ax
    shl di, 1
    shl di, 1
    shl di, 1
    shl di, 1
    add di, driver_candidate_table
    pop si
    push si
    mov ax, [si + 26]
    mov [di], ax
    add di, 2
    mov cx, 11
    rep movsb
    pop si
    pop cx
    inc byte [driver_candidate_count]
.add_done:
    ret

.install_loaded_driver:
    call .loaded_driver_suits
    jc .install_failed
    mov si, nic_driver_slot
    mov di, nic_vtable
    mov cx, nic_vt_slot_count
    rep movsw
    clc
    ret
.install_failed:
    stc
    ret

.ask_driver:
.ask_again:
    call .newline
    mov si, low_scratch_start + (driver_question_text - PHASE_BASE)
    mov bl, [question_attr]
    call .print_msg
    mov byte [driver_choice_index], 0
.list_next:
    mov al, [driver_choice_index]
    cmp al, [driver_candidate_count]
    jae .list_done
    call .newline
    mov bl, 0x07
    mov al, [driver_choice_index]
    add al, '1'
    phase_call_res print_char
    mov al, '.'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    mov al, [driver_choice_index]
    call .candidate_ptr
    add si, 2
    mov bl, 0x07
    call .print_fat_name
    inc byte [driver_choice_index]
    jmp .list_next
.list_done:
    call .newline
    call .newline
    call .show_cursor
    mov bl, [ready_attr]
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
.read_choice:
    call .sync_cursor
    xor ah, ah
    int 0x16
    sub al, '1'
    jb .bad_choice
    cmp al, [driver_candidate_count]
    jae .bad_choice
    mov [driver_choice_index], al
    add al, '1'
    mov bl, 0x0f
    phase_call_res print_char
    call .hide_cursor
    call .newline
    mov al, [driver_choice_index]
    ret
.bad_choice:
    call .hide_cursor
    call .newline
    mov bl, [menu_idle_attr]
    mov al, '>'
    phase_call_res print_char
    mov al, ' '
    phase_call_res print_char
    mov si, low_scratch_start + (driver_incorrect_text - PHASE_BASE)
    call .print_msg
    jmp .ask_again

.candidate_ptr:
    xor ah, ah
    mov si, ax
    shl si, 1
    shl si, 1
    shl si, 1
    shl si, 1
    mov di, driver_candidate_table
    add si, di
    mov di, si
    ret

.print_fat_name:
    push si
    push cx
    mov cx, 8
.stem:
    mov al, [si]
    cmp al, ' '
    je .stem_done
    phase_call_res print_char
    inc si
    loop .stem
.stem_done:
    pop cx
    pop si
    push si
    add si, 8
    cmp byte [si], ' '
    je .name_done
    mov al, '.'
    phase_call_res print_char
    mov cx, 3
.ext:
    mov al, [si]
    cmp al, ' '
    je .name_done
    phase_call_res print_char
    inc si
    loop .ext
.name_done:
    pop si
    ret

.print_msg:
    lodsb
    or al, al
    jz .print_msg_done
    phase_call_res print_char
    jmp .print_msg
.print_msg_done:
    ret

.newline:
    mov byte [cursor_col], 0
    mov al, [cursor_row]
    cmp al, dpi_prompt_row
    jb .newline_down
    mov ax, 0x0601
    mov cx, 0x0100
    phase_call_res scroll_text_area
    ret
.newline_down:
    inc byte [cursor_row]
    ret

.show_cursor:
    mov cx, 0x0607
    jmp .apply_cursor_shape
.hide_cursor:
    mov cx, 0x2000
.apply_cursor_shape:
    mov ah, 0x01
    int 0x10
    ret

.sync_cursor:
    mov ah, 0x02
    xor bh, bh
    mov dh, [cursor_row]
    mov dl, [cursor_col]
    int 0x10
    ret

.find_seed_dir:
    mov word [fs_lba], fat_root_start_lba
    mov word [fs_root_left], fat_root_sectors
.root_sector:
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
.root_entry:
    mov al, [si]
    or al, al
    jz .not_found
    cmp al, 0xe5
    je .root_advance
    test byte [si + 11], 0x10
    jz .root_advance
    mov di, low_scratch_start + (driver_load_seed_name - PHASE_BASE)
    call .entry_matches
    jnc .matched
.root_advance:
    add si, fat_dir_entry_size
    loop .root_entry
    inc word [fs_lba]
    dec word [fs_root_left]
    jmp .root_sector

.find_dir_entry:
    mov ax, [fs_current_cluster]
    cmp ax, fat_first_data_cluster
    jb .not_found
    sub ax, fat_first_data_cluster
    add ax, fat_data_start_lba
    push ds
    pop es
    mov bx, fs_sector_buffer
    phase_call_res read_abs_sector
    jc .not_found
    mov si, fs_sector_buffer
    mov cx, fat_dir_entries_per_sector
.dir_entry:
    mov al, [si]
    or al, al
    jz .not_found
    cmp al, 0xe5
    je .dir_advance
    test byte [si + 11], 0x08
    jnz .dir_advance
    test byte [si + 11], 0x10
    jz .dir_advance
    call .entry_matches
    jnc .matched
.dir_advance:
    add si, fat_dir_entry_size
    loop .dir_entry
.not_found:
    stc
    ret

.entry_matches:
    push si
    push di
    push cx
    mov cx, 11
.cmp:
    mov al, [si]
    cmp al, [di]
    jne .mismatch
    inc si
    inc di
    loop .cmp
    pop cx
    pop di
    pop si
    clc
    ret
.mismatch:
    pop cx
    pop di
    pop si
    stc
    ret
.matched:
    mov ax, [si + 26]
    mov [fs_file_cluster], ax
    mov ax, [si + 28]
    mov [fs_file_size_low], ax
    mov ax, [si + 30]
    mov [fs_file_size_high], ax
    clc
    ret

driver_load_seed_name db 'SEED       '
driver_load_drivers_name db 'DRIVERS    '
driver_question_text db 'which driver?', 0
driver_incorrect_text db 'incorrect option', 0

%unmacro phase_call_res 1
