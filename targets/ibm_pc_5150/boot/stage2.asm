bits 16
org 0x8000

%ifndef STAGE2_SECTORS
%define STAGE2_SECTORS 4
%endif

build_number equ 4
handoff_addr equ 0x0600
handoff_magic equ 0
handoff_version equ 4
handoff_size equ 5
handoff_build equ 6
handoff_flags equ 8
handoff_boot_drive equ 10
handoff_video_mode equ 11
handoff_video_cols equ 12
handoff_seed_col equ 13
handoff_nic_base equ 14
handoff_nic_family equ 16
handoff_config_source equ 17
handoff_nic_irq equ 18
handoff_mac equ 19
handoff_status equ 25
handoff_size_bytes equ 26
handoff_struct_version equ 1
handoff_flag_mda equ 0x0001
handoff_flag_nic_present equ 0x0002
handoff_flag_config_resolved equ 0x0004
handoff_flag_mac_valid equ 0x0008
handoff_status_booting equ 1
handoff_status_no_nic equ 2
handoff_status_ready equ 3
seed_attr_cga equ 0x0f
build_attr_cga equ 0x08
load_attr_cga equ 0x0f
error_attr_cga equ 0x0c
menu_selected_attr_cga equ 0x0f
menu_idle_attr_cga equ 0x08
seed_attr_mda equ 0x0f
build_attr_mda equ 0x07
load_attr_mda equ 0x0f
error_attr_mda equ 0x0f
menu_selected_attr_mda equ 0x0f
menu_idle_attr_mda equ 0x07
seed_len equ 4
seed_row equ 12
question_row equ seed_row + 2
load_ticks equ 6
type_ticks equ 1
done_ticks equ 9
config_auto equ 1
config_user equ 2
family_3c503 equ 1
family_ne2000 equ 2
family_ne1000 equ 3
family_3c501 equ 4
family_wd8003 equ 5

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    sti
    cld

    call init_handoff
    call detect_display
    call clear_screen
    call hide_cursor

    call set_seed_cursor
    mov bl, [load_attr]
    mov al, ' '
    call print_char
    call probe_network_card
    jc network_error

    call set_seed_cursor
    mov al, '.'
    call print_char
    call resolve_network_config

    call set_seed_cursor
    mov al, 'o'
    call print_char
    mov byte [handoff_addr + handoff_status], handoff_status_ready
    mov cx, load_ticks
    call wait_ticks

    call set_seed_cursor
    mov si, seed_text
    mov bl, [seed_attr]
    call type_z

    mov al, ' '
    mov bl, [build_attr]
    call type_char

    mov si, build_text
    call type_z

    mov cx, done_ticks
    call wait_ticks

halt:
    hlt
    jmp halt

network_error:
    mov byte [handoff_addr + handoff_status], handoff_status_no_nic
    call set_seed_cursor
    mov bl, [error_attr]
    mov al, '+'
    call print_char

    inc byte [cursor_col]
    call notify_failure
    mov si, network_error_text
    call type_z
    jmp halt

set_seed_cursor:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    mov [cursor_col], al
    ret

init_handoff:
    mov di, handoff_addr
    xor ax, ax
    mov cx, handoff_size_bytes / 2
.clear:
    stosw
    loop .clear
    mov byte [handoff_addr + handoff_magic], 'S'
    mov byte [handoff_addr + handoff_magic + 1], 'E'
    mov byte [handoff_addr + handoff_magic + 2], 'E'
    mov byte [handoff_addr + handoff_magic + 3], 'D'
    mov byte [handoff_addr + handoff_version], handoff_struct_version
    mov byte [handoff_addr + handoff_size], handoff_size_bytes
    mov word [handoff_addr + handoff_build], build_number
    mov byte [handoff_addr + handoff_boot_drive], dl
    mov byte [handoff_addr + handoff_status], handoff_status_booting
    ret

detect_display:
    mov ah, 0x0f
    int 0x10
    mov [handoff_addr + handoff_video_mode], al
    mov [handoff_addr + handoff_video_cols], ah
    mov [screen_cols], ah
    sub ah, seed_len
    shr ah, 1
    mov [seed_col], ah
    mov [handoff_addr + handoff_seed_col], ah
    cmp al, 0x07
    jne .color
    or word [handoff_addr + handoff_flags], handoff_flag_mda
    mov byte [seed_attr], seed_attr_mda
    mov byte [build_attr], build_attr_mda
    mov byte [load_attr], load_attr_mda
    mov byte [error_attr], error_attr_mda
    mov byte [menu_selected_attr], menu_selected_attr_mda
    mov byte [menu_idle_attr], menu_idle_attr_mda
    ret
.color:
    ret

clear_screen:
    mov ax, 0x0600
    mov bh, 0x07
    xor cx, cx
    mov dh, 0x18
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

hide_cursor:
    mov ah, 0x01
    mov ch, 0x20
    mov cl, 0x00
    int 0x10
    ret

type_z:
    lodsb
    or al, al
    jz .done
    call type_char
    jmp type_z
.done:
    ret

type_char:
    call print_char
    mov cx, type_ticks
    call wait_ticks
    ret

print_char:
    push ax
    push bx
    mov ah, 0x02
    mov bh, 0x00
    mov dh, [cursor_row]
    mov dl, [cursor_col]
    int 0x10
    pop bx
    pop ax

    push bx
    push cx
    mov ah, 0x09
    mov bh, 0x00
    mov cx, 0x0001
    int 0x10
    pop cx
    pop bx

    inc byte [cursor_col]
    ret

wait_ticks:
    push ax
    push bx
    push cx
    mov bx, [0x046c]
.next_tick:
    hlt
    mov ax, [0x046c]
    cmp ax, bx
    je .next_tick
    mov bx, ax
    loop .next_tick
    pop cx
    pop bx
    pop ax
    ret

probe_network_card:
    mov si, nic_ports
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
    je .ask_io_280
    cmp ax, 0x300
    je .ask_ne
    mov cx, load_ticks
    call wait_ticks
    ret
.known_3c503:
    mov byte [handoff_addr + handoff_nic_family], family_3c503
    mov byte [handoff_addr + handoff_config_source], config_auto
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    mov cx, load_ticks
    call wait_ticks
    ret
.ask_io_280:
    mov word [menu_option_a], adapter_3c501_text
    mov word [menu_option_b], adapter_wd8003_text
    mov byte [menu_value_a], family_3c501
    mov byte [menu_value_b], family_wd8003
    call ask_adapter
    ret
.ask_ne:
    mov word [menu_option_a], adapter_ne2000_text
    mov word [menu_option_b], adapter_ne1000_text
    mov byte [menu_value_a], family_ne2000
    mov byte [menu_value_b], family_ne1000
    call ask_adapter
    ret

ask_adapter:
    mov byte [menu_index], 0
    mov byte [blink_state], 0
    call notify_question
    call render_adapter_question
.input:
    call blink_load_marker
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
    call draw_menu_options
    jmp .input
.accept:
    mov al, [menu_value_a]
    cmp byte [menu_index], 0
    je .store
    mov al, [menu_value_b]
.store:
    mov [handoff_addr + handoff_nic_family], al
    mov byte [handoff_addr + handoff_config_source], config_user
    or word [handoff_addr + handoff_flags], handoff_flag_config_resolved
    call clear_question_area
    ret

render_adapter_question:
    mov byte [cursor_row], seed_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [load_attr]
    mov si, adapter_prompt_text
    call type_z

    call type_menu_options
    ret

type_menu_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_selected_attr]
    mov si, [menu_option_a]
    call type_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    mov si, [menu_option_b]
    call type_z
    ret

draw_menu_options:
    mov byte [cursor_row], question_row
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 0
    jne .first
    mov bl, [menu_selected_attr]
.first:
    mov si, [menu_option_a]
    call print_z

    mov byte [cursor_row], question_row + 1
    mov al, [seed_col]
    add al, 2
    mov [cursor_col], al
    mov bl, [menu_idle_attr]
    cmp byte [menu_index], 1
    jne .second
    mov bl, [menu_selected_attr]
.second:
    mov si, [menu_option_b]
    call print_z
    ret

print_z:
    lodsb
    or al, al
    jz .done
    call print_char
    jmp print_z
.done:
    ret

blink_load_marker:
    call set_seed_cursor
    mov bl, [load_attr]
    mov al, '.'
    xor byte [blink_state], 1
    jnz .show
    mov al, ' '
.show:
    call print_char
    mov cx, 2
    call wait_ticks
    ret

clear_question_area:
    mov ax, 0x0600
    mov bh, 0x07
    mov ch, seed_row
    xor cl, cl
    mov dh, question_row + 1
    mov dl, [screen_cols]
    dec dl
    int 0x10
    ret

notify_question:
    mov ax, 6087
    call speaker_tone
    mov cx, 2
    call wait_ticks
    call speaker_off
    ret

notify_failure:
    mov ax, 5424
    call speaker_tone
    mov cx, 2
    call wait_ticks
    mov ax, 7231
    call speaker_tone
    mov cx, 3
    call wait_ticks
    call speaker_off
    ret

speaker_tone:
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

speaker_off:
    in al, 0x61
    and al, 0xfc
    out 0x61, al
    ret

cursor_row db 0
cursor_col db 0
screen_cols db 80
seed_col db (80 - seed_len) / 2
seed_attr db seed_attr_cga
build_attr db build_attr_cga
load_attr db load_attr_cga
error_attr db error_attr_cga
menu_selected_attr db menu_selected_attr_cga
menu_idle_attr db menu_idle_attr_cga
menu_option_a dw 0
menu_option_b dw 0
menu_value_a db 0
menu_value_b db 0
menu_index db 0
blink_state db 0
seed_text db 'seed', 0
build_text db 'build ', '0' + build_number, 0
network_error_text db 'no network card', 0
adapter_prompt_text db 'adapter', 0
adapter_ne2000_text db 'ne2000', 0
adapter_ne1000_text db 'ne1000', 0
adapter_3c501_text db '3c501', 0
adapter_wd8003_text db 'wd8003', 0
nic_ports dw 0x250, 0x280, 0x2a0, 0x2c0, 0x2e0
          dw 0x300, 0x310, 0x320, 0x330, 0x340
          dw 0x350, 0x360, 0x380, 0x3a0, 0x3c0
          dw 0

times (STAGE2_SECTORS * 512) - ($ - $$) db 0
