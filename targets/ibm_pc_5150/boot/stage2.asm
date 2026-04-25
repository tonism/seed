bits 16
org 0x8000

%ifndef STAGE2_SECTORS
%define STAGE2_SECTORS 4
%endif

seed_attr_cga equ 0x0f
build_attr_cga equ 0x08
load_attr_cga equ 0x0f
error_attr_cga equ 0x0c
seed_attr_mda equ 0x0f
build_attr_mda equ 0x07
load_attr_mda equ 0x0f
error_attr_mda equ 0x0f
seed_len equ 4
seed_row equ 12
load_ticks equ 6
type_ticks equ 1
done_ticks equ 9

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    sti
    cld

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

detect_display:
    mov ah, 0x0f
    int 0x10
    mov [screen_cols], ah
    sub ah, seed_len
    shr ah, 1
    mov [seed_col], ah
    cmp al, 0x07
    jne .color
    mov byte [seed_attr], seed_attr_mda
    mov byte [build_attr], build_attr_mda
    mov byte [load_attr], load_attr_mda
    mov byte [error_attr], error_attr_mda
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
    mov [nic_base], dx
    clc
    ret
.missing:
    stc
    ret

resolve_network_config:
    mov cx, load_ticks
    call wait_ticks
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
nic_base dw 0
seed_text db 'seed', 0
build_text db 'build 4', 0
network_error_text db 'no network card', 0
nic_ports dw 0x250, 0x280, 0x2a0, 0x2c0, 0x2e0
          dw 0x300, 0x310, 0x320, 0x330, 0x340
          dw 0x350, 0x360, 0x380, 0x3a0, 0x3c0
          dw 0

times (STAGE2_SECTORS * 512) - ($ - $$) db 0
