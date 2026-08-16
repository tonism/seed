; Exact 6 MHz / 512 KiB gate for the product cached-pack loader.

bits 16
cpu 8086
org 0x1000

%include "tls13/tls13_286_abi.inc"
%include "build/ibm_pc_5150/crypto-bench/tls13-286-pack-meta.inc"

cache_segment equ 0x7000
x_pack_entry equ \
    tls13_286_pack_directory_off + tls13_286_pack_entry_bytes
; The fixed S286MOD2 header starts with a 22-byte literal in every current pack
; entry: token f6, one-byte literal extension 07, then raw bytes 0..21.
x_lz4_literal_base equ 2
x_lz4_required_state equ x_lz4_literal_base + tls13_286_mod_required_state
x_lz4_flags equ x_lz4_literal_base + tls13_286_mod_flags

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

    ; Reproduce the product's pre-TCP high-cache load without involving disk
    ; geometry in this loader-specific gate.  The embedded low source extends
    ; through the product stack guard, so retain the temporary high stack until
    ; every source byte needed below has been copied into the top reservation.
    mov ax, cache_segment
    mov es, ax
    mov si, pack_blob
    xor di, di
    mov cx, (pack_blob_end - pack_blob) / 2
    rep movsw
    mov si, controller_lz4
    mov di, controller_lz4_high
    mov cx, controller_lz4_end - controller_lz4
    rep movsb
    mov si, controller_match_lz4
    mov di, controller_match_lz4_high
    mov cx, controller_match_lz4_end - controller_match_lz4
    rep movsb

    ; Materialize a maximum-size literal block only in high scratch so the
    ; gate proves both source and destination limits without consuming the
    ; controller window that it is about to test.
    mov di, full_controller_lz4_high
    mov al, 0xf0
    stosb
    mov al, 0xff
    mov cx, 28
    rep stosb
    mov al, 13
    stosb
    mov al, controller_plain_byte
    mov cx, full_controller_plain_bytes
    rep stosb

    ; X25519's one-shot boundary accepts only the exact product scalar slot.
    mov si, x_scalar_fixture
    mov di, tls13_286_x25519_scalar_off
    mov cx, tls13_286_x25519_scalar_bytes / 2
    rep movsw

    ; The pack source is now cold high RAM.  Retire its low stack-overlap before
    ; atomically adopting the production SS:SP=0000:8000 geometry.  No live
    ; code or data resides in this part of the copied source pack.
    xor ax, ax
    mov es, ax
    mov di, tls13_286_module_limit
    mov cx, (0x8000 - tls13_286_module_limit) / 2
    rep stosw
    cli
    mov sp, 0x8000
    sti

    ; The hardened modules bind BX to the real root loader state and bind that
    ; state to the same top-reservation segment which contains the pack cache.
    mov di, loader_state
    mov cx, tls13_286_state_bytes / 2
    rep stosw
    mov word [loader_state + tls13_286_state_cache_seg], cache_segment
    mov word [loader_state + tls13_286_state_cache_capacity], \
        tls13_286_pack_cache_bytes

    cmp word [tls13_286_loader_load + tls13_286_loader_entry_count], \
        tls13_286_loader_entries
    jne fail
    mov bx, loader_state
    call word [tls13_286_loader_load + \
        tls13_286_loader_entry_validate]
    jc fail
    cmp word [loader_state + tls13_286_state_pack_bytes], \
        pack_blob_end - pack_blob
    jne fail

    ; Unknown pack flags must invalidate the cache atomically.
    mov ax, cache_segment
    mov es, ax
    or word [es:tls13_286_pack_directory_off + \
        tls13_286_pack_entry_flags], tls13_286_pack_flag_research
    mov bx, loader_state
    call word [tls13_286_loader_load + \
        tls13_286_loader_entry_validate]
    jnc fail
    cmp ax, tls13_286_error_profile
    jne fail
    cmp word [loader_state + tls13_286_state_pack_bytes], 0
    jne fail
    and word [es:tls13_286_pack_directory_off + \
        tls13_286_pack_entry_flags], ~tls13_286_pack_flag_research
    xor ax, ax
    mov es, ax
    mov bx, loader_state
    call word [tls13_286_loader_load + \
        tls13_286_loader_entry_validate]
    jc fail

    ; Every required product kind must decode, CRC, and pass its S286MOD2
    ; header check through the same transition used by the controller.
    mov cx, 5
    mov ax, 1
.decode:
    push ax
    push cx
    mov bx, loader_state
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    pop cx
    pop dx
    jc fail
    cmp [loader_state + tls13_286_state_loaded_kind], dx
    jne fail
    mov ax, dx
    inc ax
    loop .decode

    ; Exercise the strict callable-header policy after the entry CRC has
    ; authenticated each deliberately changed raw image.  Restore and decode
    ; the pristine X25519 image between cases so no rejection can be credited
    ; to stale overlay state.
    call test_module_header_rejections
    jc fail

    ; Decode X25519 once more and invoke a real descriptor through entry 2.
    mov ax, tls13_286_mod_kind_x25519
    mov bx, loader_state
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc fail
    ; Retirement erases the exact authenticated image extent.  The following
    ; byte is not module state and must remain untouched.
    mov byte [tls13_286_module_load + x_raw_len], 0x5a
    mov ax, tls13_286_mod_op_x25519_keygen
    mov si, x_desc
    mov bx, loader_state
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
    jc fail
    mov si, x_output
    mov di, x_expected
    mov cx, 32
    repe cmpsb
    jne fail
    cmp word [loader_state + tls13_286_state_loaded_kind], 0
    jne fail
    cmp word [loader_state + tls13_286_state_loaded_flags], 0
    jne fail
    xor ax, ax
    mov es, ax
    mov di, tls13_286_module_load
    mov cx, x_raw_len
    repe scasb
    jne fail
    cmp byte [tls13_286_module_load + x_raw_len], 0x5a
    jne fail

    ; A one-shot image is retired even when its operation rejects.
    mov ax, tls13_286_mod_kind_mlkem_keygen
    mov bx, loader_state
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc fail
    mov ax, tls13_286_mod_op_mlkem_keygen
    mov si, bad_desc
    mov bx, loader_state
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
    jnc fail
    cmp word [loader_state + tls13_286_state_loaded_kind], 0
    jne fail

    ; A hostile module may return with DF set.  Publication is retired and
    ; the loader's caller-visible ABI must still return DF=0.  A second call
    ; without a fresh authenticated decode must fail closed.
    mov ax, tls13_286_mod_kind_x25519
    mov bx, loader_state
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    jc fail
    mov byte [tls13_286_module_load + x_raw_len], 0x5a
    mov word [tls13_286_module_load + tls13_286_mod_kind], \
        tls13_286_mod_kind_x25519
    mov word [tls13_286_module_load + tls13_286_mod_entry_off], \
        tls13_286_mod_header_bytes
    mov byte [tls13_286_module_load + tls13_286_mod_header_bytes + 0], 0x31
    mov byte [tls13_286_module_load + tls13_286_mod_header_bytes + 1], 0xc0
    mov byte [tls13_286_module_load + tls13_286_mod_header_bytes + 2], 0xf8
    mov byte [tls13_286_module_load + tls13_286_mod_header_bytes + 3], 0xfd
    mov byte [tls13_286_module_load + tls13_286_mod_header_bytes + 4], 0xc3
    xor ax, ax
    mov si, bad_desc
    mov bx, loader_state
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
    pushf
    pop dx
    test dx, 0x0401
    jnz fail
    or ax, ax
    jnz fail
    cmp word [loader_state + tls13_286_state_loaded_kind], 0
    jne fail
    xor ax, ax
    mov es, ax
    mov di, tls13_286_module_load
    mov cx, x_raw_len
    repe scasb
    jne fail
    cmp byte [tls13_286_module_load + x_raw_len], 0x5a
    jne fail
    xor ax, ax
    mov si, bad_desc
    mov bx, loader_state
    call word [tls13_286_loader_load + tls13_286_loader_entry_call]
    jnc fail
    cmp ax, tls13_286_error_abi
    jne fail
    pushf
    pop dx
    test dx, 0x0400
    jnz fail

    ; The same authenticated decoder used by the root must accept a valid
    ; controller into its bounded safe window.
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov si, controller_lz4
    mov di, tls13_286_module_load
    mov cx, controller_lz4_end - controller_lz4
    rep movsb
    mov si, tls13_286_module_load
    mov cx, controller_lz4_end - controller_lz4
    mov di, 0x1800
    mov dx, controller_plain_bytes
    mov bp, controller_plain_crc
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    jc fail
    xor ax, ax
    mov es, ax
    mov di, 0x1800
    mov al, controller_plain_byte
    mov cx, controller_plain_bytes
    repe scasb
    jne fail

    ; A bad content authenticator must fail closed and erase the whole
    ; destination extent after decoding.
    mov ax, cache_segment
    mov ds, ax
    mov si, controller_lz4_high
    mov cx, controller_lz4_end - controller_lz4
    xor ax, ax
    mov es, ax
    mov di, 0x1840
    mov dx, controller_plain_bytes
    mov bp, controller_plain_crc ^ 1
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    jnc fail
    cmp ax, tls13_286_error_decode
    jne fail
    xor ax, ax
    mov es, ax
    mov di, 0x1840
    mov cx, controller_plain_bytes
    repe scasb
    jne fail

    ; Match-completion must consume the exact compressed source.  The same
    ; valid block with one trailing byte is rejected and erased.
    mov ax, cache_segment
    mov ds, ax
    mov si, controller_match_lz4_high
    mov cx, controller_match_lz4_valid_bytes
    xor ax, ax
    mov es, ax
    mov di, 0x1880
    mov dx, controller_plain_bytes
    mov bp, controller_plain_crc
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    jc fail
    mov ax, cache_segment
    mov ds, ax
    mov si, controller_match_lz4_high
    mov cx, controller_match_lz4_end - controller_match_lz4
    xor ax, ax
    mov es, ax
    mov di, 0x18c0
    mov dx, controller_plain_bytes
    mov bp, controller_plain_crc
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    jnc fail
    cmp ax, tls13_286_error_decode
    jne fail
    xor ax, ax
    mov es, ax
    mov di, 0x18c0
    mov cx, controller_plain_bytes
    repe scasb
    jne fail

    ; Below-window and crossing-window requests are bounds errors and must not
    ; touch adjacent resident bytes.
    mov byte [0x17ff], 0x5a
    mov ax, cache_segment
    mov ds, ax
    mov si, controller_lz4_high
    mov cx, controller_lz4_end - controller_lz4
    xor ax, ax
    mov es, ax
    mov di, 0x17ff
    mov dx, controller_plain_bytes
    mov bp, controller_plain_crc
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    jnc fail
    cmp ax, tls13_286_error_bounds
    jne fail
    cmp byte [0x17ff], 0x5a
    jne fail

    mov byte [0x33f0], 0x5a
    mov ax, cache_segment
    mov ds, ax
    mov si, controller_lz4_high
    mov cx, controller_lz4_end - controller_lz4
    xor ax, ax
    mov es, ax
    mov di, 0x33f0
    mov dx, controller_plain_bytes
    mov bp, controller_plain_crc
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    jnc fail
    cmp ax, tls13_286_error_bounds
    jne fail
    cmp byte [0x33f0], 0x5a
    jne fail

    ; The complete 0x1800..0x33ff controller extent is admissible, including
    ; a compressed source larger than the low resident core.
    mov ax, cache_segment
    mov ds, ax
    mov si, full_controller_lz4_high
    mov cx, full_controller_lz4_bytes
    xor ax, ax
    mov es, ax
    mov di, 0x1800
    mov dx, full_controller_plain_bytes
    mov bp, full_controller_plain_crc
    call word [cs:tls13_286_loader_load + \
        tls13_286_loader_entry_decode_block]
    jc fail
    xor ax, ax
    mov es, ax
    mov di, 0x1800
    mov al, controller_plain_byte
    mov cx, full_controller_plain_bytes
    repe scasb
    jne fail

    mov si, tag_check
    call emit_str
    mov si, str_check
    call emit_str
    mov ax, 1
    call emit_hex16
    call emit_crlf
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

; Decode the exact X25519 pack entry currently cached in high RAM.
decode_x:
    mov ax, tls13_286_mod_kind_x25519
    mov bx, loader_state
    call word [tls13_286_loader_load + tls13_286_loader_entry_decode]
    ret

; A hostile header reached the ABI policy only when decode returns ERROR_ABI.
decode_x_expect_abi:
    call decode_x
    jnc .bad
    cmp ax, tls13_286_error_abi
    jne .bad
    clc
    ret
.bad:
    stc
    ret

; Restore the pack bytes changed by a case before calling this helper, then
; restore the authenticated directory CRC and prove a pristine decode works.
restore_x_decode:
    mov ax, cache_segment
    mov es, ax
    mov word [es:x_pack_entry + tls13_286_pack_entry_crc16], x_crc
    xor ax, ax
    mov es, ax
    jmp short decode_x

; Publish the CRC of the deliberately modified raw overlay into the X25519
; directory entry.  This makes the subsequent failure specifically a callable
; header-policy rejection rather than a preceding content-integrity failure.
publish_x_overlay_crc:
    push bx
    push cx
    push dx
    push si
    mov si, tls13_286_module_load
    mov cx, x_raw_len
    call bench_crc16
    mov dx, ax
    mov ax, cache_segment
    mov es, ax
    mov [es:x_pack_entry + tls13_286_pack_entry_crc16], dx
    xor ax, ax
    mov es, ax
    pop si
    pop dx
    pop cx
    pop bx
    ret

test_module_header_rejections:
    ; Assert the tiny LZ4 prefix this targeted mutation relies on.  If module
    ; compression changes, fail loudly instead of mutating an unrelated byte.
    mov ax, cache_segment
    mov es, ax
    mov bx, [es:x_pack_entry + tls13_286_pack_entry_payload_off]
    cmp byte [es:bx + 0], 0xf6
    jne .bad_reset
    cmp byte [es:bx + 1], 7
    jne .bad_reset
    xor ax, ax
    mov es, ax

    ; required_state must name the complete root loader state.
    call decode_x
    jc .bad_reset
    xor byte [tls13_286_module_load + tls13_286_mod_required_state], 1
    call publish_x_overlay_crc
    mov ax, cache_segment
    mov es, ax
    mov bx, [es:x_pack_entry + tls13_286_pack_entry_payload_off]
    xor byte [es:bx + x_lz4_required_state], 1
    xor ax, ax
    mov es, ax
    call decode_x_expect_abi
    jc .bad_reset
    mov ax, cache_segment
    mov es, ax
    mov bx, [es:x_pack_entry + tls13_286_pack_entry_payload_off]
    xor byte [es:bx + x_lz4_required_state], 1
    xor ax, ax
    mov es, ax
    call restore_x_decode
    jc .bad_reset

    ; The loader accepts exactly ONE_SHOT, not an optional empty flag word.
    mov word [tls13_286_module_load + tls13_286_mod_flags], 0
    call publish_x_overlay_crc
    mov ax, cache_segment
    mov es, ax
    mov bx, [es:x_pack_entry + tls13_286_pack_entry_payload_off]
    mov byte [es:bx + x_lz4_flags], 0
    xor ax, ax
    mov es, ax
    call decode_x_expect_abi
    jc .bad_reset
    mov ax, cache_segment
    mov es, ax
    mov bx, [es:x_pack_entry + tls13_286_pack_entry_payload_off]
    mov byte [es:bx + x_lz4_flags], tls13_286_mod_flag_one_shot
    xor ax, ax
    mov es, ax
    call restore_x_decode
    jc .bad_reset
    ret

.bad_reset:
    xor ax, ax
    mov ds, ax
    mov es, ax
    stc
    ret

bench_crc16:
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
    jmp short .byte
.done:
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

loader_state equ tls13_286_root_state_loader
x_output equ tls13_286_client_x_public

x_scalar_fixture:
    db 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d
    db 0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45
    db 0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a
    db 0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
x_expected:
    db 0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
    db 0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
    db 0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
    db 0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a

full_controller_lz4_high equ 0x6000
controller_lz4_high equ 0x7d00
controller_match_lz4_high equ 0x7e00
controller_plain_byte equ 0xa5
controller_plain_bytes equ 64
controller_plain_crc equ 0x0e6e
full_controller_plain_bytes equ 0x1c00
full_controller_lz4_bytes equ 1 + 28 + 1 + full_controller_plain_bytes
full_controller_plain_crc equ 0x53cf
controller_lz4:
    db 0xf0, controller_plain_bytes - 15
    times controller_plain_bytes db controller_plain_byte
controller_lz4_end:
controller_match_lz4:
    db 0x1f, controller_plain_byte, 0x01, 0x00, 44
controller_match_lz4_valid_bytes equ $ - controller_match_lz4
    db 0x7e
controller_match_lz4_end:

tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_check db ' N=1 dt=0 ck=', 0

; Module descriptors belong to the same bounded controller window used by the
; product.  Keep both test descriptors there even though this standalone image
; begins at 0x1000.
times (tls13_286_controller_load - 0x1000) - ($ - $$) db 0
x_desc:
    dw tls13_286_mod_op_x25519_keygen, 0
    dw tls13_286_x25519_scalar_off & 15, \
        cache_segment + (tls13_286_x25519_scalar_off >> 4)
    dd 32
    times 3 * tls13_286_span_bytes db 0
    dw x_output & 15, x_output >> 4
    dd 32
    times tls13_286_span_bytes db 0

bad_desc:
    times tls13_286_desc_bytes db 0

times (tls13_286_loader_load - 0x1000) - ($ - $$) db 0
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-pack-loader.bin"
align 512, db 0
pack_blob:
incbin "build/ibm_pc_5150/crypto-bench/tls13-286-modules.bin"
pack_blob_end:

image_end:

%if (pack_blob_end - pack_blob) != 44 * 512
%error "cached-pack loader gate needs regenerated module-pack metadata"
%endif
%if (image_end - $$ + 0x1000) > 0xf000
%error "cached-pack loader gate collides with its stack guard"
%endif
