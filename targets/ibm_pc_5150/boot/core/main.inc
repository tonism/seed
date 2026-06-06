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
