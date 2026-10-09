; Generated from the standalone, oracle-tested Huffman primitive.
state equ 0x35b0
delta equ state
base equ state+2
depth equ state+4
ones equ state+5
bad equ state+6
used equ state+7
output equ state+8
input equ state+10
bits_left equ state+11
state_bytes equ 12

reset:
    call clear
    mov byte [ones], 1
    ret

clear:
    cld
    xor ax, ax
    mov di, state
    mov cx, state_bytes/2
    rep stosw
    ret

; AL is one encoded octet. SI/CX returns zero, one, or two decoded symbols.
; State carries an unfinished symbol across arbitrary input boundaries.
feed:
    cmp byte [bad], 0
    jne .reject
    mov [input], al
    mov byte [bits_left], 8
    mov byte [used], 0
.bit:
    xor ax, ax
    shl byte [input], 1
    adc ax, ax
    and [ones], al
    shl word [delta], 1
    add [delta], ax
    inc byte [depth]
    xor bx, bx
    mov bl, [depth]
    cmp bl, 30
    ja .reject
    mov al, [counts+bx]
    xor ah, ah
    mov dx, [delta]
    cmp dx, ax
    jb .symbol
    sub [delta], ax
    add [base], ax
    jmp short .next_bit
.symbol:
    mov bx, [base]
    add bx, dx
    cmp bx, 256                     ; EOS is a forbidden actual symbol.
    jae .reject
    mov al, [symbols+bx]
    xor bx, bx
    mov bl, [used]
    cmp bl, 2
    jae .reject
    mov [output+bx], al
    inc byte [used]
    xor ax, ax
    mov [delta], ax
    mov [base], ax
    mov byte [depth], 0
    mov byte [ones], 1
.next_bit:
    dec byte [bits_left]
    jnz .bit
    xor cx, cx
    mov cl, [used]
    mov si, output
    clc
    ret
.reject:
    mov byte [bad], 1
    xor cx, cx
    stc
    ret

; RFC 7541 section 5.2: an unfinished code must be at most seven one bits.
finish:
    cmp byte [bad], 0
    jne .reject
    cmp byte [depth], 0
    je .ok
    cmp byte [depth], 7
    ja .reject
    cmp byte [ones], 1
    jne .reject
.ok:
    clc
    ret
.reject:
    mov byte [bad], 1
    stc
    ret

code_end:
%include "hpack_huffman_tables.inc"
