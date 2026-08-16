; Exact 80286 cost/correctness gate for the TLS 1.3 module-pack decoder.
;
; The blocks are the exact ML-KEM keygen, ML-KEM decapsulation, X25519, and
; table-free width-7 ECDSA payloads emitted by build_286_module_pack.py.  They
; decode to disjoint RAM ranges so every target CRC-16 check can run after the
; timed transitions.  Keygen is the pre-TCP transition; the critical-window
; transition decodes ML-KEM decapsulation followed by X25519.  ECDSA is
; decoded separately because certificate authentication runs offline between
; the acquisition and resumed connections.

bits 16
cpu 8086
org 0x1000

kg_output equ 0x6000
x_output equ 0x8000
m_output equ 0xaf00
e_output equ 0xd800

%include "build/ibm_pc_5150/crypto-bench/tls13-286-pack-meta.inc"
race_crc equ m_crc ^ x_crc
pre_crc equ kg_crc

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

    call read_tick_low
    mov bx, ax
.edge:
    call read_tick_low
    cmp ax, bx
    je .edge
    call read_tick
    mov [t0_lo], ax
    mov [t0_hi], dx

    mov si, kg_block
    mov cx, kg_block_end - kg_block
    mov di, kg_output
    mov dx, kg_raw_len
    call lz4_decode_block
    jc .failed

    call read_tick
    sub ax, [t0_lo]
    sbb dx, [t0_hi]
    mov [pre_dt_lo], ax

    call read_tick_low
    mov bx, ax
.race_edge:
    call read_tick_low
    cmp ax, bx
    je .race_edge
    call read_tick
    mov [t0_lo], ax
    mov [t0_hi], dx

    mov si, m_block
    mov cx, m_block_end - m_block
    mov di, m_output
    mov dx, m_raw_len
    call lz4_decode_block
    jc .failed

    mov si, x_block
    mov cx, x_block_end - x_block
    mov di, x_output
    mov dx, x_raw_len
    call lz4_decode_block
    jc .failed

    call read_tick
    sub ax, [t0_lo]
    sbb dx, [t0_hi]
    mov [race_dt_lo], ax

    ; ECDSA module loading belongs to the offline authentication interval and
    ; is deliberately excluded from both provider-deadline measurements.
    mov si, e_block
    mov cx, e_block_end - e_block
    mov di, e_output
    mov dx, e_raw_len
    call lz4_decode_block
    jc .failed

    mov si, kg_output
    mov cx, kg_raw_len
    call crc16_ccitt
    cmp ax, kg_crc
    jne .failed
    mov si, x_output
    mov cx, x_raw_len
    call crc16_ccitt
    cmp ax, x_crc
    jne .failed
    mov si, m_output
    mov cx, m_raw_len
    call crc16_ccitt
    cmp ax, m_crc
    jne .failed
    mov si, e_output
    mov cx, e_raw_len
    call crc16_ccitt
    cmp ax, e_crc
    jne .failed

    mov si, tag_pre
    call emit_str
    mov si, str_n
    call emit_str
    mov ax, 1
    call emit_dec16
    mov si, str_dt
    call emit_str
    mov ax, [pre_dt_lo]
    call emit_dec16
    mov si, str_ck
    call emit_str
    mov ax, pre_crc
    call emit_hex16
    call emit_crlf
    mov si, tag_race
    call emit_str
    mov si, str_n
    call emit_str
    mov ax, 2
    call emit_dec16
    mov si, str_dt
    call emit_str
    mov ax, [race_dt_lo]
    call emit_dec16
    mov si, str_ck
    call emit_str
    mov ax, race_crc
    call emit_hex16
    call emit_crlf
    mov si, tag_check
    call emit_str
    mov si, str_validation
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

.failed:
    mov si, tag_fail
    call emit_str
    call emit_crlf
    jmp .hang

; Decode one raw LZ4 block.
;
; in:  DS:SI source, CX compressed bytes, ES:DI destination, DX raw bytes
; out: CF clear and AX=raw bytes, or CF set on malformed/truncated input
;
; Match copies are bytewise because LZ4 explicitly permits overlapping
; back-references.  No history buffer is needed: the already-written output is
; the dictionary.
lz4_decode_block:
    mov ax, si
    add ax, cx
    jc .bad
    mov [lz_src_end], ax
    mov [lz_dst_start], di
    mov ax, di
    add ax, dx
    jc .bad
    mov [lz_dst_end], ax

.sequence:
    cmp di, [lz_dst_end]
    je .success
    call lz4_get_byte
    jc .bad
    mov [lz_token], al

    mov cl, 4
    shr al, cl
    xor ah, ah
    mov bp, ax
    cmp bp, 15
    jne .literal_length_ready
    call lz4_extend_length
    jc .bad
.literal_length_ready:
    mov ax, [lz_src_end]
    sub ax, si
    cmp ax, bp
    jb .bad
    mov ax, [lz_dst_end]
    sub ax, di
    cmp ax, bp
    jb .bad
    mov cx, bp
    rep movsb

    cmp di, [lz_dst_end]
    jne .read_offset
    cmp si, [lz_src_end]
    jne .bad
    jmp short .success

.read_offset:
    call lz4_get_byte
    jc .bad
    mov bl, al
    call lz4_get_byte
    jc .bad
    mov bh, al
    or bx, bx
    jz .bad
    mov ax, di
    sub ax, [lz_dst_start]
    cmp bx, ax
    ja .bad
    mov [lz_offset], bx

    mov al, [lz_token]
    and ax, 0x000f
    mov bp, ax
    add bp, 4
    cmp al, 15
    jne .match_length_ready
    call lz4_extend_length
    jc .bad
.match_length_ready:
    mov ax, [lz_dst_end]
    sub ax, di
    cmp ax, bp
    jb .bad
    mov bx, di
    sub bx, [lz_offset]
    mov cx, bp
.match_copy:
    mov al, [es:bx]
    stosb
    inc bx
    loop .match_copy
    jmp .sequence

.success:
    mov ax, di
    sub ax, [lz_dst_start]
    clc
    ret
.bad:
    stc
    ret

lz4_get_byte:
    cmp si, [lz_src_end]
    jae .eof
    lodsb
    clc
    ret
.eof:
    stc
    ret

; Add LZ4's sequence of 0xff extension bytes to BP.
lz4_extend_length:
.next:
    call lz4_get_byte
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

; CRC-16/CCITT-FALSE over CX bytes at DS:SI.
crc16_ccitt:
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

read_tick:
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret

read_tick_low:
    mov ax, [0x046c]
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

tag_pre db 'LZ4PRE', 0
tag_race db 'LZ4RACE', 0
tag_check db 'CHECK', 0
tag_done db 'DONE', 0
tag_fail db 'FAIL', 0
str_n db ' N=', 0
str_dt db ' dt=', 0
str_ck db ' ck=', 0
str_validation db ' N=1 dt=0 ck=', 0

t0_lo dw 0
t0_hi dw 0
pre_dt_lo dw 0
race_dt_lo dw 0
lz_src_end dw 0
lz_dst_start dw 0
lz_dst_end dw 0
lz_offset dw 0
lz_token db 0
align 2

kg_block:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem-keygen.raw.lz4-block"
kg_block_end:
x_block:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-x25519.raw.lz4-block"
x_block_end:
m_block:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-mlkem.raw.lz4-block"
m_block_end:
e_block:
    incbin "build/ibm_pc_5150/crypto-bench/tls13-286-ecdsa-w7.raw.lz4-block"
e_block_end:

image_end:

%if (image_end - $$ + 0x1000) > kg_output
    %error "compressed decoder image overlaps its first output range"
%endif
%if kg_output + kg_raw_len > x_output
    %error "ML-KEM keygen output overlaps X25519 output"
%endif
%if kg_output + kg_raw_len > m_output
    %error "ML-KEM keygen output overlaps ML-KEM decapsulation output"
%endif
%if kg_output + kg_raw_len > e_output
    %error "ML-KEM keygen output overlaps ECDSA output"
%endif
%if x_output + x_raw_len > m_output
    %error "X25519 output overlaps ML-KEM decapsulation output"
%endif
%if x_output + x_raw_len > e_output
    %error "X25519 output overlaps ECDSA output"
%endif
%if m_output + m_raw_len > e_output
    %error "ML-KEM decapsulation output overlaps ECDSA output"
%endif
%if e_output + e_raw_len > 0xff80
    %error "decoder output collides with the benchmark stack guard"
%endif
