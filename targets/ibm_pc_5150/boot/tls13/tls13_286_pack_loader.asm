; Product 286 TLS 1.3 cached-pack loader.
;
; This fixed-origin image is the only code allowed to turn cold high-RAM pack
; bytes into executable code at 0000:4230.  It validates the complete S286PK02
; directory before any connection, then validates LZ4 length, CRC-16, and the
; decoded S286MOD2 header on every transition.  Unknown flags, duplicate or
; missing kinds, gaps, overlaps, trailing payload bytes, and malformed modules
; fail closed.
;
; Entry ABI (DS=ES=SS=0, DF=0, BX=near tls13_286_state):
;   0 validate cached pack
;   1 AX=module kind, decode/authenticate at 0000:4230
;   2 AX=module operation, SI=descriptor, invoke decoded module
;   3 DS:SI compressed controller block, CX=compressed bytes, ES=0,
;     DI=destination, DX=raw bytes, BP=expected CRC16
;
; Each entry returns CF=0/AX=0 on success or CF=1/AX=defined error.

bits 16
cpu 8086
org 0x3400

%include "tls13/tls13_286_abi.inc"

loader_header:
    db 'S286CTL2'
    dw tls13_286_abi_version
    dw loader_image_end - loader_header
    dw tls13_286_loader_entries
loader_entry_table:
    dw loader_validate_pack
    dw loader_decode_kind
    dw loader_call_module
    dw loader_decode_block

loader_validate_pack:
    push bp
    mov bp, bx
    cld
    xor ax, ax
    mov [bp + tls13_286_state_pack_bytes], ax
    mov [bp + tls13_286_state_loaded_kind], ax
    mov [cs:loader_raw_bytes], ax
    cmp word [bp + tls13_286_state_cache_capacity], \
        tls13_286_pack_cache_bytes
    jb loader_error_bounds_pop
    mov ax, [bp + tls13_286_state_cache_seg]
    cmp ax, 0x1000
    jb loader_error_bounds_pop
    cmp ax, 0xa000 - (tls13_286_pack_cache_bytes / 16)
    ja loader_error_bounds_pop

    mov ds, ax
    xor si, si
    mov di, loader_pack_magic
    mov cx, 8
    repe cmpsb
    jne loader_error_pack_ds_pop
    cmp word [tls13_286_pack_abi], tls13_286_abi_version
    jne loader_error_pack_ds_pop
    cmp word [tls13_286_pack_count], 5
    jne loader_error_pack_ds_pop
    cmp word [tls13_286_pack_header_bytes_off], \
        tls13_286_pack_header_bytes
    jne loader_error_pack_ds_pop
    cmp word [tls13_286_pack_entry_bytes_off], \
        tls13_286_pack_entry_bytes
    jne loader_error_pack_ds_pop
    cmp word [tls13_286_pack_total_bytes + 2], 0
    jne loader_error_bounds_ds_pop
    mov ax, [tls13_286_pack_total_bytes]
    cmp ax, tls13_286_pack_header_bytes
    jb loader_error_bounds_ds_pop
    cmp ax, [cs:bp + tls13_286_state_cache_capacity]
    ja loader_error_bounds_ds_pop
    test ax, 511
    jnz loader_error_pack_ds_pop
    mov [cs:loader_candidate_pack_bytes], ax

    mov word [cs:loader_seen_kinds], 0
    mov word [cs:loader_expected_offset], tls13_286_pack_header_bytes
    mov si, tls13_286_pack_directory_off
    mov cx, 5
.entry:
    cmp word [si + tls13_286_pack_entry_flags], \
        tls13_286_pack_flag_raw_lz4
    jne loader_error_pack_ds_pop
    cmp word [si + tls13_286_pack_entry_reserved], 0
    jne loader_error_pack_ds_pop
    mov ax, [si + tls13_286_pack_entry_kind]
    cmp ax, tls13_286_mod_kind_mlkem_keygen
    jb loader_error_pack_ds_pop
    cmp ax, tls13_286_mod_kind_ecdsa_verify
    ja loader_error_pack_ds_pop
    dec ax
    mov bx, 1
    xchg ax, cx
    shl bx, cl
    xchg ax, cx
    test [cs:loader_seen_kinds], bx
    jnz loader_error_pack_ds_pop
    or [cs:loader_seen_kinds], bx

    mov ax, [si + tls13_286_pack_entry_raw_bytes]
    or ax, ax
    jz loader_error_pack_ds_pop
    cmp ax, tls13_286_module_max_bytes
    ja loader_error_bounds_ds_pop
    mov ax, [si + tls13_286_pack_entry_comp_bytes]
    or ax, ax
    jz loader_error_pack_ds_pop
    cmp word [si + tls13_286_pack_entry_payload_off + 2], 0
    jne loader_error_bounds_ds_pop
    mov dx, [si + tls13_286_pack_entry_payload_off]
    cmp dx, [cs:loader_expected_offset]
    jne loader_error_pack_ds_pop
    add dx, ax
    jc loader_error_bounds_ds_pop
    cmp dx, [cs:loader_candidate_pack_bytes]
    ja loader_error_bounds_ds_pop
    mov [cs:loader_expected_offset], dx
    add si, tls13_286_pack_entry_bytes
    dec cx
    jnz .entry
    cmp word [cs:loader_seen_kinds], 0x001f
    jne loader_error_pack_ds_pop

    ; The payload extent may end before sector padding, but every remaining
    ; byte covered by pack_total must be zero.
    mov si, [cs:loader_expected_offset]
    mov cx, [cs:loader_candidate_pack_bytes]
    sub cx, si
    jc loader_error_bounds_ds_pop
.padding:
    jcxz .valid
    cmp byte [si], 0
    jne loader_error_pack_ds_pop
    inc si
    loop .padding
.valid:
    push es
    pop ds
    mov ax, [loader_candidate_pack_bytes]
    mov [bp + tls13_286_state_pack_bytes], ax
    xor ax, ax
    pop bp
    ret

loader_decode_kind:
    push bp
    mov bp, bx
    cld
    mov [loader_requested_kind], ax
    call loader_wipe_overlay
    mov ax, [loader_requested_kind]
    cmp ax, tls13_286_mod_kind_mlkem_keygen
    jb loader_error_abi_pop
    cmp ax, tls13_286_mod_kind_ecdsa_verify
    ja loader_error_abi_pop
    cmp word [bp + tls13_286_state_pack_bytes], \
        tls13_286_pack_header_bytes
    jb loader_error_abi_pop

    mov dx, [bp + tls13_286_state_cache_seg]
    mov ds, dx
    mov si, tls13_286_pack_directory_off
    mov cx, 5
.find:
    cmp ax, [si + tls13_286_pack_entry_kind]
    je .found
    add si, tls13_286_pack_entry_bytes
    loop .find
    jmp loader_error_pack_ds_pop
.found:
    cmp word [si + tls13_286_pack_entry_flags], \
        tls13_286_pack_flag_raw_lz4
    jne loader_error_pack_ds_pop
    mov dx, [si + tls13_286_pack_entry_raw_bytes]
    mov [cs:loader_raw_bytes], dx
    mov ax, [si + tls13_286_pack_entry_crc16]
    mov [cs:loader_expected_crc], ax

    ; Source is the paragraph-aligned high cache; destination is segment zero.
    mov cx, [si + tls13_286_pack_entry_comp_bytes]
    mov si, [si + tls13_286_pack_entry_payload_off]
    mov di, tls13_286_module_load
    push bp
    call loader_lz4_decode
    pop bp
    jc loader_error_decode_ds_pop
    cmp ax, [cs:loader_raw_bytes]
    jne loader_error_decode_ds_pop
    xor ax, ax
    mov ds, ax
    mov si, tls13_286_module_load
    mov cx, [loader_raw_bytes]
    call loader_crc16
    cmp ax, [loader_expected_crc]
    jne loader_error_decode_pop

    mov si, tls13_286_module_load
    mov di, loader_module_magic
    mov cx, 8
    repe cmpsb
    jne loader_error_decode_pop
    cmp word [tls13_286_module_load + tls13_286_mod_abi], \
        tls13_286_abi_version
    jne loader_error_abi_pop
    mov ax, [loader_requested_kind]
    cmp ax, [tls13_286_module_load + tls13_286_mod_kind]
    jne loader_error_abi_pop
    mov dx, [tls13_286_module_load + tls13_286_mod_image_bytes]
    cmp dx, [loader_raw_bytes]
    jne loader_error_decode_pop
    mov ax, [tls13_286_module_load + tls13_286_mod_entry_off]
    cmp ax, tls13_286_mod_header_bytes
    jb loader_error_decode_pop
    cmp ax, dx
    jae loader_error_decode_pop
    cmp word [tls13_286_module_load + tls13_286_mod_required_state], \
        tls13_286_state_bytes
    jne loader_error_abi_pop
    mov ax, [tls13_286_module_load + tls13_286_mod_flags]
    cmp ax, tls13_286_mod_flag_one_shot
    jne loader_error_abi_pop
    cmp word [tls13_286_module_load + tls13_286_mod_required_stack], 2048
    ja loader_error_abi_pop
    mov ax, [loader_requested_kind]
    mov [bp + tls13_286_state_loaded_kind], ax
    xor ax, ax
    pop bp
    ret

loader_call_module:
    push bp
    mov bp, bx
    cld
    mov dx, [tls13_286_module_load + tls13_286_mod_kind]
    or dx, dx
    jz loader_error_abi_pop
    cmp dx, [bp + tls13_286_state_loaded_kind]
    jne loader_error_abi_pop
    mov dx, [tls13_286_module_load + tls13_286_mod_entry_off]
    add dx, tls13_286_module_load
    xor di, di
    call dx
    pushf
    push ax
    cld
    xor ax, ax
    mov ds, ax
    mov es, ax
    call loader_wipe_overlay
    pop ax
    popf
    cld
    jc .done
    cmp ax, tls13_286_status_ok
    jne .bad
.done:
    pop bp
    ret
.bad:
    mov ax, tls13_286_error_crypto
    stc
    pop bp
    ret

loader_decode_block:
    cld
    mov ax, es
    or ax, ax
    jnz loader_error_generic_bounds
    or cx, cx
    jz loader_error_generic_bounds
    or dx, dx
    jz loader_error_generic_bounds
    mov ax, si
    add ax, cx
    jc loader_error_generic_bounds
    mov bx, ds
    or bx, bx
    jnz .source_high
    cmp si, tls13_286_module_load
    jb loader_error_generic_bounds
    cmp ax, tls13_286_flight_load
    ja loader_error_generic_bounds
    jmp short .source_ok
.source_high:
    cmp bx, 0x1000
    jb loader_error_generic_bounds
.source_ok:
    mov ax, di
    add ax, dx
    jc loader_error_generic_bounds
    cmp di, tls13_286_controller_load
    jb loader_error_generic_bounds
    cmp di, tls13_286_controller_limit
    jb .controller_destination
    cmp di, tls13_286_flight_load
    jb loader_error_generic_bounds
    cmp di, tls13_286_flight_limit
    jae loader_error_generic_bounds
    cmp ax, tls13_286_flight_limit
    ja loader_error_generic_bounds
    jmp short .destination_ok
.controller_destination:
    cmp ax, tls13_286_controller_limit
    ja loader_error_generic_bounds
.destination_ok:
    mov [cs:loader_generic_start], di
    mov [cs:loader_generic_bytes], dx
    mov [cs:loader_generic_crc], bp
    push cx
    mov cx, dx
    xor ax, ax
    rep stosb
    sub di, dx
    pop cx
    call loader_lz4_decode
    jc loader_error_generic
    cmp ax, [cs:loader_generic_bytes]
    jne loader_error_generic
    xor ax, ax
    mov ds, ax
    mov si, [loader_generic_start]
    mov cx, [loader_generic_bytes]
    call loader_crc16
    cmp ax, [loader_generic_crc]
    jne loader_error_generic
    xor ax, ax
    ret

loader_error_generic:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov di, [loader_generic_start]
    mov cx, [loader_generic_bytes]
    rep stosb
    mov ax, tls13_286_error_decode
    stc
    ret

loader_error_generic_bounds:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ax, tls13_286_error_bounds
    stc
    ret

loader_error_pack_ds_pop:
    xor ax, ax
    mov ds, ax
loader_error_pack_pop:
    mov ax, tls13_286_error_profile
    stc
    pop bp
    ret
loader_error_bounds_ds_pop:
    xor ax, ax
    mov ds, ax
loader_error_bounds_pop:
    mov ax, tls13_286_error_bounds
    stc
    pop bp
    ret
loader_error_decode_ds_pop:
    xor ax, ax
    mov ds, ax
loader_error_decode_pop:
    call loader_wipe_overlay
    mov ax, tls13_286_error_decode
    stc
    pop bp
    ret
loader_error_abi_pop:
    call loader_wipe_overlay
    mov ax, tls13_286_error_abi
    stc
    pop bp
    ret

loader_wipe_overlay:
    mov word [bp + tls13_286_state_loaded_kind], 0
    mov cx, [cs:loader_raw_bytes]
    mov word [cs:loader_raw_bytes], 0
    or cx, cx
    jz .done
    cmp cx, tls13_286_module_max_bytes
    ja .done
    xor ax, ax
    mov es, ax
    mov di, tls13_286_module_load
    rep stosb
.done:
    ret

; Raw-LZ4 decode from DS:SI to ES:DI.  All mutable decoder state is addressed
; through CS because DS names the high cache.
loader_lz4_decode:
    mov ax, si
    add ax, cx
    jc .bad
    mov [cs:loader_src_end], ax
    mov [cs:loader_dst_start], di
    mov ax, di
    add ax, dx
    jc .bad
    mov [cs:loader_dst_end], ax
.sequence:
    cmp di, [cs:loader_dst_end]
    je .success
    call loader_lz4_get_byte
    jc .bad
    mov [cs:loader_token], al
    mov cl, 4
    shr al, cl
    xor ah, ah
    mov bp, ax
    cmp bp, 15
    jne .literal_ready
    call loader_lz4_extend
    jc .bad
.literal_ready:
    mov ax, [cs:loader_src_end]
    sub ax, si
    cmp ax, bp
    jb .bad
    mov ax, [cs:loader_dst_end]
    sub ax, di
    cmp ax, bp
    jb .bad
    mov cx, bp
    rep movsb
    cmp di, [cs:loader_dst_end]
    jne .offset
    cmp si, [cs:loader_src_end]
    jne .bad
    jmp short .success
.offset:
    call loader_lz4_get_byte
    jc .bad
    mov bl, al
    call loader_lz4_get_byte
    jc .bad
    mov bh, al
    or bx, bx
    jz .bad
    mov ax, di
    sub ax, [cs:loader_dst_start]
    cmp bx, ax
    ja .bad
    mov [cs:loader_offset], bx
    mov al, [cs:loader_token]
    and ax, 0x000f
    mov bp, ax
    add bp, 4
    cmp al, 15
    jne .match_ready
    call loader_lz4_extend
    jc .bad
.match_ready:
    mov ax, [cs:loader_dst_end]
    sub ax, di
    cmp ax, bp
    jb .bad
    mov bx, di
    sub bx, [cs:loader_offset]
    mov cx, bp
.match:
    mov al, [es:bx]
    stosb
    inc bx
    loop .match
    jmp .sequence
.success:
    cmp si, [cs:loader_src_end]
    jne .bad
    mov ax, di
    sub ax, [cs:loader_dst_start]
    clc
    ret
.bad:
    stc
    ret

loader_lz4_get_byte:
    cmp si, [cs:loader_src_end]
    jae .bad
    lodsb
    clc
    ret
.bad:
    stc
    ret

loader_lz4_extend:
.next:
    call loader_lz4_get_byte
    jc .bad
    xor ah, ah
    add bp, ax
    jc .bad
    cmp al, 0xff
    je .next
    clc
    ret
.bad:
    stc
    ret

loader_crc16:
    mov ax, 0xffff
    mov dx, cx
.byte:
    or dx, dx
    jz .done
    xor ah, [si]
    inc si
    mov cx, 8
.bit:
    shl ax, 1
    jnc .plain
    xor ax, 0x1021
.plain:
    loop .bit
    dec dx
    jmp .byte
.done:
    ret

loader_pack_magic db 'S286PK02'
loader_module_magic db 'S286MOD2'
loader_seen_kinds dw 0
loader_expected_offset dw 0
loader_candidate_pack_bytes dw 0
loader_requested_kind dw 0
loader_raw_bytes dw 0
loader_expected_crc dw 0
loader_src_end dw 0
loader_dst_start dw 0
loader_dst_end dw 0
loader_offset dw 0
loader_token db 0
loader_generic_start dw 0
loader_generic_bytes dw 0
loader_generic_crc dw 0

loader_image_end:

%if (loader_image_end - $$ + tls13_286_loader_load) > tls13_286_controller_handoff
%error "TLS 1.3 286 pack loader overlaps the controller handoff"
%endif
