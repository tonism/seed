; Generated from the oracle-tested response decoder.
hp equ 0x3570
hp_phase equ hp
hp_kind equ hp+1
hp_integer equ hp+2
hp_shift equ hp+4
hp_huffman equ hp+5
hp_left equ hp+6
hp_count equ hp+8
hp_name_len equ hp+10
hp_name equ hp+12                    ; 17 bytes, longest special name
hp_class equ hp+29                  ; 0 ordinary, 1 status, 2 content-length
hp_last equ hp+30
hp_fields equ hp+31
hp_status_seen equ hp+32
hp_regular equ hp+33
hp_trailers equ hp+34
hp_table_zero equ hp+35             ; persists across blocks on a connection
hp_status equ hp+36
hp_number equ hp+38                 ; 32-bit parsed field value
hp_content_length equ hp+42         ; 32-bit result (caller owns stream check)
hp_length_seen equ hp+46
hp_input equ hp+47
hp_bad equ hp+48                    ; 1 compression, 2 field, 3 resource
hp_total equ hp+49                  ; decoded header-list size including 32/field
hp_updates equ hp+51                ; at most two table updates per field block
hp_bytes equ 64
hp_limit equ 4096                   ; advertise through MAX_HEADER_LIST_SIZE

hp_init:
    call hp_clear
    ret
hp_clear:
    cld
    mov di, hp
    xor ax, ax
    mov cx, (hp_bytes+12)/2
    rep stosw
    ret

; AL=1 for trailers, 0 for a response header block. The encoder must reduce
; its table to zero in the first block after our zero-size setting is ACKed.
hp_begin:
    push ax
    xor ax, ax
    mov di, hp
    mov cx, hp_bytes/2
    mov bl, [hp_table_zero]
    rep stosw
    mov [hp_table_zero], bl
    pop ax
    mov [hp_trailers], al
    clc
    ret

hp_feed:
    cmp byte [hp_bad], 0
    jne hp_fail
    mov [hp_input], al
    cmp byte [hp_phase], 0
    je hp_representation
    cmp byte [hp_phase], 1
    je hp_integer_more
    cmp byte [hp_phase], 2
    je hp_name_length
    cmp byte [hp_phase], 3
    je hp_value_length
    jmp hp_string_byte

hp_representation:
    test al, 0x80
    jz .literal
    mov byte [hp_kind], 0
    mov dl, 0x7f
    jmp hp_integer_start
.literal:
    test al, 0x40
    jz .small
    mov byte [hp_kind], 1
    mov dl, 0x3f
    jmp hp_integer_start
.small:
    test al, 0x20
    jz .unindexed
    mov byte [hp_kind], 2
    mov dl, 0x1f
    jmp hp_integer_start
.unindexed:
    mov byte [hp_kind], 1
    mov dl, 0x0f
    jmp hp_integer_start
hp_name_length:
    mov byte [hp_kind], 3
    jmp short hp_string_length
hp_value_length:
    mov byte [hp_kind], 4
hp_string_length:
    mov ah, al
    and ah, 0x80
    mov [hp_huffman], ah
    mov dl, 0x7f
hp_integer_start:
    and al, dl
    xor ah, ah
    mov [hp_integer], ax
    cmp al, dl
    jne hp_integer_done
    mov byte [hp_shift], 0
    mov byte [hp_phase], 1
    clc
    ret
hp_integer_more:
    mov bl, al
    and al, 0x7f
    xor ah, ah
    mov cl, [hp_shift]
    ; String lengths are resource-bounded to 16 bits. A third continuation
    ; contributes at bit 14, so values above three would overflow.
    cmp cl, 14
    jb .shift
    cmp al, 3
    ja hp_compression_error
.shift:
    shl ax, cl
    add [hp_integer], ax
    jc hp_compression_error
    test bl, 0x80
    jz hp_integer_done
    add byte [hp_shift], 7
    cmp byte [hp_shift], 14
    ja hp_compression_error
    clc
    ret
hp_integer_done:
    mov ax, [hp_integer]
    cmp byte [hp_kind], 2
    je hp_table_update
    cmp byte [hp_kind], 3
    jae hp_string_start
    cmp byte [hp_table_zero], 1
    jne hp_compression_error
    cmp ax, 61
    ja hp_compression_error          ; no dynamic entries at table size zero
    cmp byte [hp_kind], 0
    je hp_indexed
    or ax, ax
    jnz .named
    mov byte [hp_phase], 2
    clc
    ret
.named:
    call hp_static_name
    jc hp_fail
    mov byte [hp_phase], 3
    clc
    ret
hp_table_update:
    or ax, ax
    jnz hp_compression_error
    cmp byte [hp_fields], 0
    jne hp_compression_error
    inc byte [hp_updates]
    cmp byte [hp_updates], 2
    ja hp_compression_error
    mov byte [hp_table_zero], 1
    mov byte [hp_phase], 0
    clc
    ret
hp_indexed:
    or ax, ax
    jz hp_compression_error
    push ax
    call hp_static_name
    pop bx
    jc hp_fail
    ; All static values except statuses and accept-encoding are empty.
    cmp byte [hp_class], 1
    jne .ordinary
    sub bx, 8
    shl bx, 1
    mov ax, [hp_static_status+bx]
    mov [hp_number], ax
    mov word [hp_number+2], 0
    mov word [hp_count], 3
    mov byte [hp_last], '0'
    add word [hp_total], 3
    jmp hp_value_done
.ordinary:
    mov word [hp_count], 0
    mov byte [hp_last], 0
    cmp bx, 16
    jne hp_value_done
    mov word [hp_count], 13           ; "gzip, deflate" is actually 13 bytes
    add word [hp_total], 13
    mov byte [hp_last], 'e'
    jmp hp_value_done

hp_static_name:
    mov byte [hp_class], 0
    cmp ax, 8
    jb hp_field_error                ; request pseudo-fields in a response
    cmp ax, 14
    ja .regular
    mov byte [hp_class], 1
    mov word [hp_name_len], 7
    jmp hp_name_ready
.regular:
    cmp ax, 57                       ; transfer-encoding
    je hp_field_error
    cmp ax, 28                       ; content-length
    jne .length
    mov byte [hp_class], 2
.length:
    mov bx, ax
    sub bx, 15
    xor ax, ax
    mov al, [hp_static_lengths+bx]
    mov [hp_name_len], ax
    jmp hp_name_ready

hp_string_start:
    mov [hp_left], ax
    mov word [hp_count], 0
    mov byte [hp_last], 0
    mov word [hp_number], 0
    mov word [hp_number+2], 0
    mov dl, 4
    cmp byte [hp_kind], 3
    je .phase
    inc dl
.phase:
    mov [hp_phase], dl
    push ax
    call reset                       ; embedded Huffman state
    pop ax
    or ax, ax
    jz hp_string_done
    clc
    ret
hp_string_byte:
    cmp byte [hp_huffman], 0
    jne .huffman
    call hp_decoded_byte
    jc hp_fail
    jmp short .consumed
.huffman:
    call feed
    jc hp_compression_error
    jcxz .consumed
.next:
    lodsb
    push cx
    push si
    call hp_decoded_byte
    pop si
    pop cx
    jc hp_fail
    loop .next
.consumed:
    dec word [hp_left]
    jz hp_string_done
    clc
    ret
hp_string_done:
    cmp byte [hp_huffman], 0
    je .valid
    call finish
    jc hp_compression_error
.valid:
    cmp byte [hp_phase], 4
    jne hp_value_done
    mov ax, [hp_count]
    or ax, ax
    jz hp_field_error
    mov [hp_name_len], ax
    mov byte [hp_class], 0
    mov si, hp_special_names
.match:
    xor cx, cx
    lodsb
    mov cl, al
    jcxz .unknown
    lodsb
    mov dl, al                       ; class: 0xff means forbidden
    mov bx, si
    cmp cx, [hp_name_len]
    jne .skip
    mov di, hp_name
    repe cmpsb
    je .found
.skip:
    mov si, bx
    xor ax, ax
    mov al, [si-2]
    add si, ax
    jmp .match
.found:
    cmp dl, 0xff
    je hp_field_error
    mov [hp_class], dl
    jmp short .ready
.unknown:
    cmp byte [hp_name], ':'
    je hp_field_error
.ready:
    call hp_name_ready
    jc hp_fail
    mov byte [hp_phase], 3
    clc
    ret

hp_decoded_byte:
    inc word [hp_total]
    cmp word [hp_total], hp_limit
    ja hp_resource_error
    cmp byte [hp_phase], 4
    jne .value
    ; RFC 9113 field-name validity; a colon is permitted only as the first
    ; character, and the complete name must later match :status exactly.
    cmp al, 0x21
    jb hp_field_error
    cmp al, 0x7f
    jae hp_field_error
    cmp al, 'A'
    jb .colon
    cmp al, 'Z'
    jbe hp_field_error
.colon:
    cmp al, ':'
    jne .save_name
    cmp word [hp_count], 0
    jne hp_field_error
.save_name:
    mov bx, [hp_count]
    cmp bx, 17
    jae .count
    mov [hp_name+bx], al
    jmp short .count
.value:
    or al, al
    jz hp_field_error
    cmp al, 10
    je hp_field_error
    cmp al, 13
    je hp_field_error
    cmp word [hp_count], 0
    jne .not_first
    cmp al, ' '
    je hp_field_error
    cmp al, 9
    je hp_field_error
.not_first:
    mov [hp_last], al
    cmp byte [hp_class], 0
    je .count
    sub al, '0'
    cmp al, 9
    ja hp_field_error
    xor ah, ah
    mov di, ax
    ; Checked 32-bit decimal multiply by ten. This runs only post-tag.
    mov ax, [hp_number]
    mov bx, 10
    mul bx
    mov si, ax
    mov cx, dx
    mov ax, [hp_number+2]
    mul bx
    or dx, dx
    jnz hp_resource_error
    add ax, cx
    jc hp_resource_error
    add si, di
    adc ax, 0
    jc hp_resource_error
    mov [hp_number], si
    mov [hp_number+2], ax
.count:
    inc word [hp_count]
    clc
    ret

hp_name_ready:
    cmp byte [hp_class], 1
    jne .regular
    cmp byte [hp_trailers], 0
    jne hp_field_error
    cmp byte [hp_regular], 0
    jne hp_field_error
    cmp byte [hp_status_seen], 0
    jne hp_field_error
    jmp short .size
.regular:
    mov byte [hp_regular], 1
.size:
    ; Literal name characters were already counted during decoding; indexed
    ; names need the same decoded-size charge here.
    cmp byte [hp_phase], 4
    je .overhead
    mov ax, [hp_name_len]
    add [hp_total], ax
.overhead:
    add word [hp_total], 32
    cmp word [hp_total], hp_limit
    ja hp_resource_error
    clc
    ret

hp_value_done:
    cmp byte [hp_last], ' '
    je hp_field_error
    cmp byte [hp_last], 9
    je hp_field_error
    cmp word [hp_total], hp_limit
    ja hp_resource_error
    cmp byte [hp_class], 1
    jne .length
    cmp word [hp_count], 3
    jne hp_field_error
    cmp word [hp_number+2], 0
    jne hp_field_error
    mov ax, [hp_number]
    cmp ax, 100
    jb hp_field_error
    cmp ax, 599
    ja hp_field_error
    cmp ax, 101
    je hp_field_error
    mov [hp_status], ax
    mov byte [hp_status_seen], 1
    jmp short .done
.length:
    cmp byte [hp_class], 2
    jne .done
    cmp word [hp_count], 0
    je hp_field_error
    cmp byte [hp_trailers], 0
    jne hp_field_error
    mov ax, [hp_number]
    mov dx, [hp_number+2]
    cmp byte [hp_length_seen], 0
    je .store_length
    cmp ax, [hp_content_length]
    jne hp_field_error
    cmp dx, [hp_content_length+2]
    jne hp_field_error
.store_length:
    mov [hp_content_length], ax
    mov [hp_content_length+2], dx
    mov byte [hp_length_seen], 1
.done:
    mov byte [hp_fields], 1
    mov byte [hp_phase], 0
    clc
    ret

hp_finish:
    cmp byte [hp_bad], 0
    jne hp_fail
    cmp byte [hp_phase], 0
    jne hp_compression_error
    cmp byte [hp_table_zero], 1
    jne hp_compression_error
    cmp byte [hp_trailers], 0
    jne .done
    cmp byte [hp_status_seen], 1
    jne hp_field_error
.done:
    clc
    ret
hp_compression_error:
    mov byte [hp_bad], 1
    stc
    ret
hp_field_error:
    mov byte [hp_bad], 2
    stc
    ret
hp_resource_error:
    mov byte [hp_bad], 3
hp_fail:
    stc
    ret

hp_static_status: dw 200,204,206,304,400,404,500
; Names for static indices 15..61 (RFC 7541 Appendix A).
hp_static_lengths:
    db 14,15,15,13,6,27,3,5,13,13,19,16,16,14,16,13,12,6,4,4,6,7,4,4,8,17,13,8,19,13,4,8,12,18,19,5,7,7,11,6,10,25,17,10,4,3,16
hp_special_names:
    db 7,1,':status'
    db 14,2,'content-length'
    db 10,0xff,'connection'
    db 16,0xff,'proxy-connection'
    db 10,0xff,'keep-alive'
    db 17,0xff,'transfer-encoding'
    db 7,0xff,'upgrade'
    db 2,0xff,'te'
    db 0
%include "hpack_huffman_embedded.inc"
