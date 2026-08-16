; Exact 6 MHz / 512 KiB CPU gate for the TLS 1.3 286 deadline transitions.
;
; PACKMX measures the product cached-pack loader's real critical transition:
; authenticate/decode ML-KEM decapsulation, retire it, authenticate/decode
; X25519, then retire it.  This includes directory lookup, raw-LZ4 decode,
; CRC-16, and the exact S286MOD2 ABI/state/flags/stack header checks.  The
; primitive calls themselves remain timed by their dedicated module gates.
;
; FLIGHTDC measures the current product protected-flight component's exact
; LZ4/header/CRC decode through loader entry 3.  The component is staged in low
; RAM before the timer starts, so rotational floppy I/O is deliberately not
; represented here; the live provider pcap remains authoritative for that.

bits 16
cpu 8086
org 0x1000

%include "tls13/tls13_286_abi.inc"
%include "build/ibm_pc_5150/crypto-bench/tls13-286-pack-meta.inc"

cache_segment equ 0x7000
flight_component_high equ tls13_286_pack_cache_bytes
bench_stack_top equ 0x8000

core_header:
    jmp short start
    nop
    db 'SEEDCORE'
    db 1
    db 0
    dw core_header_end - core_header
    dw (image_end - core_header + 511) / 512
    dw (image_end - core_header + 511) / 512
    dw 0
    dw 0
core_header_end:

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0xfff0
    sti
    cld
    mov ax, 0x0003
    int 0x10
    call serial_init

    ; Cache the exact fixed-size product pack and the current flight component
    ; above conventional low RAM before adopting the product stack geometry.
    mov ax, cache_segment
    mov es, ax
    mov si, pack_blob
    xor di, di
    mov cx, (pack_blob_end - pack_blob) / 2
    rep movsw
    mov si, flight_component_blob
    mov di, flight_component_high
    mov cx, (flight_component_blob_end - flight_component_blob) / 2
    rep movsw

    ; The embedded source pack crosses the product stack band.  It is cold
    ; after the high copy, so retire that low alias before switching stacks.
    xor ax, ax
    mov es, ax
    mov di, tls13_286_module_limit
    mov cx, (bench_stack_top - tls13_286_module_limit) / 2
    rep stosw
    cli
    mov sp, bench_stack_top
    sti

    mov di, tls13_286_root_state_loader
    mov cx, tls13_286_state_bytes / 2
    rep stosw
    mov word [tls13_286_root_state_loader + tls13_286_state_cache_seg], \
        cache_segment
    mov word [tls13_286_root_state_loader + \
        tls13_286_state_cache_capacity], tls13_286_pack_cache_bytes

    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_validate]
    jc fail
    cmp word [tls13_286_root_state_loader + tls13_286_state_pack_bytes], \
        tls13_286_pack_cache_bytes
    jne fail

    ; Both provider windows execute this order.  Starting the next decode is
    ; the loader's authenticated transition and retires the preceding image.
    ; The final deliberately invalid decode retires X without decoding another
    ; module; its fixed error check makes this a conservative transition cost.
    call timer_start
    mov ax, tls13_286_mod_kind_mlkem_decap
    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc fail
    mov ax, tls13_286_mod_kind_x25519
    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc fail
    xor ax, ax
    mov bx, tls13_286_root_state_loader
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jnc fail
    cmp ax, tls13_286_error_abi
    jne fail
    call timer_stop
    mov [pack_ticks], ax
    cmp word [tls13_286_root_state_loader + tls13_286_state_loaded_kind], 0
    jne fail

    ; Stand in only for the completed BIOS read.  The timed portion below is
    ; the root's LZ4 header checks and generic decoder boundary.  The embedded
    ; component is independently bound to the current raw flight below.
    mov ax, cache_segment
    mov ds, ax
    mov si, flight_component_high
    xor ax, ax
    mov es, ax
    mov di, tls13_286_module_load
    mov cx, flight_component_blob_end - flight_component_blob
    rep movsb
    xor ax, ax
    mov ds, ax

    call timer_start
    mov si, tls13_286_module_load
    cmp word [si + tls13_286_tail_lz4_magic], 'LZ'
    jne fail
    cmp word [si + tls13_286_tail_lz4_magic + 2], '4B'
    jne fail
    cmp word [si + tls13_286_tail_lz4_reserved], 0
    jne fail
    mov cx, [si + tls13_286_tail_lz4_block_bytes]
    mov ax, cx
    add ax, tls13_286_tail_lz4_header_bytes
    jc fail
    cmp ax, flight_component_blob_end - flight_component_blob
    ja fail
    mov dx, [si + tls13_286_tail_lz4_raw_bytes]
    cmp dx, flight_raw_blob_end - flight_raw_blob
    jne fail
    mov bp, [si + tls13_286_tail_lz4_crc16]
    add si, tls13_286_tail_lz4_header_bytes
    mov di, tls13_286_flight_load
    xor ax, ax
    mov es, ax
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    jc fail
    call timer_stop
    mov [flight_ticks], ax

    ; The loader already checked the complete decoded CRC.  This independent
    ; byte comparison also binds the timing input to the freshly built product
    ; flight image rather than merely to a self-consistent component header.
    mov si, tls13_286_flight_load
    mov di, flight_raw_blob
    mov cx, flight_raw_blob_end - flight_raw_blob
    repe cmpsb
    jne fail
    cmp word [tls13_286_flight_load], 'S2'
    jne fail
    cmp word [tls13_286_flight_load + 2], '86'
    jne fail
    cmp word [tls13_286_flight_load + 4], 'FL'
    jne fail
    cmp word [tls13_286_flight_load + 6], '02'
    jne fail
    cmp word [tls13_286_flight_load + 8], tls13_286_abi_version
    jne fail
    cmp word [tls13_286_flight_load + 10], \
        flight_raw_blob_end - flight_raw_blob
    jne fail

    mov si, tag_pack
    mov ax, [pack_ticks]
    call emit_metric
    mov si, tag_flight
    mov ax, [flight_ticks]
    call emit_metric
    mov si, tag_check
    xor ax, ax
    call emit_metric
    mov si, tag_done
    call emit_str
    call emit_crlf
.hang:
    hlt
    jmp .hang

fail:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov si, tag_fail
    call emit_str
    call emit_crlf
    jmp start.hang

timer_start:
    call read_tick_low
    mov bx, ax
.edge:
    call read_tick_low
    cmp ax, bx
    je .edge
    call read_tick
    mov [tick_lo], ax
    mov [tick_hi], dx
    ret

timer_stop:
    call read_tick
    sub ax, [tick_lo]
    sbb dx, [tick_hi]
    ret

read_tick:
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret

read_tick_low:
    mov ax, [0x046c]
    ret

emit_metric:
    push ax
    call emit_str
    mov si, str_n
    call emit_str
    mov ax, 1
    call emit_dec16
    mov si, str_dt
    call emit_str
    pop ax
    call emit_dec16
    mov si, str_ck
    call emit_str
    mov ax, 1
    call emit_hex16
    call emit_crlf
    ret

serial_init:
    mov dx, 0x3fb
    mov al, 0x80
    out dx, al
    mov dx, 0x3f8
    mov al, 0x0c
    out dx, al
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 0x03
    out dx, al
    ret

emit_char:
    push ax
    push bx
    push cx
    push dx
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    mov ah, al
    mov dx, 0x3fd
.wait:
    in al, dx
    test al, 0x20
    jz .wait
    mov dx, 0x3f8
    mov al, ah
    out dx, al
    pop dx
    pop cx
    pop bx
    pop ax
    ret

emit_str:
    push ax
    push si
.next:
    lodsb
    or al, al
    jz .done
    call emit_char
    jmp short .next
.done:
    pop si
    pop ax
    ret

emit_crlf:
    push ax
    mov al, 13
    call emit_char
    mov al, 10
    call emit_char
    pop ax
    ret

emit_hex16:
    push ax
    push cx
    push dx
    mov dx, ax
    mov cx, 4
.digit:
    rol dx, 1
    rol dx, 1
    rol dx, 1
    rol dx, 1
    mov al, dl
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .emit
    add al, 7
.emit:
    call emit_char
    loop .digit
    pop dx
    pop cx
    pop ax
    ret

emit_dec16:
    push ax
    push bx
    push cx
    push dx
    mov bx, 10
    xor cx, cx
.divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    or ax, ax
    jnz .divide
.pop:
    pop ax
    add al, '0'
    call emit_char
    loop .pop
    pop dx
    pop cx
    pop bx
    pop ax
    ret

tick_lo dw 0
tick_hi dw 0
pack_ticks dw 0
flight_ticks dw 0
tag_pack db 'PACKMX', 0
tag_flight db 'FLIGHTDC', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_n db ' N=', 0
str_dt db ' dt=', 0
str_ck db ' ck=', 0

times tls13_286_loader_load - ($ - $$ + 0x1000) db 0
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-pack-loader.bin"

align 512, db 0
pack_blob:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-modules.bin"
pack_blob_end:
flight_component_blob:
    incbin "build/ibm_pc_5150/tls13-286-flight-component.bin"
flight_component_blob_end:
flight_raw_blob:
    incbin "build/ibm_pc_5150/tls13-286-flight.bin"
flight_raw_blob_end:
image_end:

%if pack_blob_end - pack_blob != tls13_286_pack_cache_bytes
%error "deadline-transition gate needs the exact fixed-size product pack"
%endif
%if (pack_blob_end - pack_blob) & 1
%error "deadline-transition gate pack copy needs an even byte count"
%endif
%if (flight_component_blob_end - flight_component_blob) & 1
%error "deadline-transition gate flight copy needs an even byte count"
%endif
%if flight_component_blob_end - flight_component_blob > \
    tls13_286_module_load - tls13_286_controller_limit
%error "flight component no longer fits the root low staging window"
%endif
%if image_end - $$ + 0x1000 > 0xf000
%error "deadline-transition gate collides with its initial stack"
%endif
