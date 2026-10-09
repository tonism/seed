h2_rx_live equ 0x2e00
h2_rx_state_size equ 28
h2_rx_work equ h2_rx_live+h2_rx_state_size
h2_rx_work_size equ 50
h2_rx_cut equ h2_rx_work+h2_rx_work_size
h2_rx_header equ h2_rx_work
h2_rx_hpos equ h2_rx_work+9
h2_rx_remaining equ h2_rx_work+10
h2_rx_mode equ h2_rx_work+12
h2_rx_padding equ h2_rx_work+13
h2_rx_body_used equ h2_rx_work+14
h2_rx_budget equ h2_rx_work+16
h2_rx_charged equ h2_rx_work+18
h2_rx_ended equ h2_rx_work+20
h2_rx_bad equ h2_rx_work+21
h2_rx_active_stream equ h2_rx_work+22
h2_rx_control_used equ h2_rx_work+26
h2_rx_m_good equ h2_rx_work+28
h2_rx_m_header equ h2_rx_work+30
h2_rx_m_new equ h2_rx_work+32
h2_rx_m_data equ h2_rx_work+34
h2_rx_m_control equ h2_rx_work+36
h2_rx_m_body equ h2_rx_work+38
h2_rx_m_finish equ h2_rx_work+40
h2_rx_m_type_data equ h2_rx_work+42
h2_rx_next_mode equ h2_rx_work+44
h2_rx_length_word equ h2_rx_work+46
h2_rx_new_remaining equ h2_rx_work+48
h2_rx_position equ h2_rx_cut+h2_rx_state_size
h2_rx_last_position equ h2_rx_position+2
h2_rx_last_value equ h2_rx_position+4
h2_rx_input equ h2_rx_position+5
h2_rx_journal equ h2_rx_position+6
h2_rx_capacity equ 512
h2_rx_control_journal equ h2_rx_journal+h2_rx_capacity
h2_rx_control_capacity equ 1280
%if h2_rx_control_journal+h2_rx_control_capacity > 0x3600
%error "retention crosses the small-RAM spool"
%endif

; AX := 0xffff iff AX was zero. Operand-independent instructions on 8088.
%macro h2_rx_zero_mask 0
    neg ax
    sbb ax, ax
    not ax
%endmacro
%macro h2_rx_equal_byte 2
    xor ax, ax
    mov al, [%1]
    sub ax, %2
    h2_rx_zero_mask
%endmacro
; Select AX into a word iff DX=ffff, preserving old contents otherwise.
%macro h2_rx_select_word 1
    xor ax, [%1]
    and ax, dx
    xor [%1], ax
%endmacro
; AX is a mask for a failure; DX is the applicability mask.
%macro h2_rx_mark_bad 0
    and ax, dx
    and al, 1
    or [h2_rx_bad], al
%endmacro
; Retain h2_rx_input iff the h2_rx_mode mask is set and h2_rx_capacity remains. Out-of-range
; indices are masked to zero before accessing RAM; an inactive write preserves
; that existing byte. A full h2_rx_journal sets sticky failure, never wraps a pointer.
%macro h2_rx_retain 4 ; mask, used, base, cap
    mov bx, [%2]
    cmp bx, %4
    sbb dx, dx
    mov ax, dx
    not ax
    and ax, [%1]
    and al, 1
    or [h2_rx_bad], al
    and dx, [%1]
    and bx, dx
    mov al, [h2_rx_input]
    xor al, [%3+bx]
    and al, dl
    xor [%3+bx], al
    and dx, 1
    add [%2], dx
%endmacro

h2_rx_begin_record:
    cld
    call h2_rx_clear_record
    mov si, h2_rx_live
    mov di, h2_rx_work
    mov cx, h2_rx_state_size/2
    rep movsw
    mov word [h2_rx_body_used], 0
    mov word [h2_rx_charged], 0
    mov word [h2_rx_control_used], 0
    ret

h2_rx_feed_byte:
    mov [h2_rx_input], al
    xor ah, ah
    neg ax
    sbb dx, dx                       ; all ones iff incoming byte is nonzero
    mov al, [h2_rx_input]
    xor al, [h2_rx_last_value]
    and al, dl
    xor [h2_rx_last_value], al
    mov ax, [h2_rx_position]
    h2_rx_select_word h2_rx_last_position
    inc word [h2_rx_position]
    mov si, h2_rx_work
    mov di, h2_rx_cut
    mov cx, h2_rx_state_size/2
.snapshot:
    lodsw
    xor ax, [di]
    and ax, dx
    xor [di], ax
    inc di
    inc di
    loop .snapshot

    cmp byte [h2_rx_bad], 1
    sbb ax, ax
    mov [h2_rx_m_good], ax
    h2_rx_equal_byte h2_rx_mode, 0
    mov dx, ax
    and ax, [h2_rx_m_good]
    mov [h2_rx_m_header], ax
    not dx
    and dx, [h2_rx_m_good]
    mov [h2_rx_m_body], dx
    h2_rx_equal_byte h2_rx_hpos, 8
    and ax, [h2_rx_m_header]
    mov [h2_rx_m_new], ax
    xor ax, ax
    mov al, [h2_rx_mode]
    dec ax
    cmp ax, 2
    sbb ax, ax                       ; old h2_rx_mode is DATA pad-length or body
    and ax, [h2_rx_m_good]
    mov [h2_rx_m_data], ax
    h2_rx_equal_byte h2_rx_mode, 3
    and ax, [h2_rx_m_good]
    or ax, [h2_rx_m_header]
    mov [h2_rx_m_control], ax

    ; Exactly one masked h2_rx_header-byte write on every invocation.
    xor bx, bx
    mov bl, [h2_rx_hpos]
    mov dx, [h2_rx_m_header]
    mov al, [h2_rx_input]
    xor al, [h2_rx_header+bx]
    and al, dl
    xor [h2_rx_header+bx], al
    and dl, 1
    add [h2_rx_hpos], dl
    mov ax, [h2_rx_m_new]
    not ax
    and [h2_rx_hpos], al

    h2_rx_retain h2_rx_m_control, h2_rx_control_used, h2_rx_control_journal, h2_rx_control_capacity
    h2_rx_retain h2_rx_m_data, h2_rx_body_used, h2_rx_journal, h2_rx_capacity
    add [h2_rx_charged], dx               ; actual retained raw DATA, including pad

    h2_rx_equal_byte h2_rx_header+3, 0
    mov [h2_rx_m_type_data], ax
    mov dx, [h2_rx_header+1]
    xchg dl, dh
    mov [h2_rx_length_word], dx
    ; A frame's declared length is at most the default 16,384-byte maximum.
    xor ax, ax
    mov al, [h2_rx_header]
    neg ax
    sbb ax, ax
    cmp dx, 16385
    sbb bx, bx
    not bx
    or ax, bx
    mov dx, [h2_rx_m_new]
    h2_rx_mark_bad

    ; DATA belongs only to the configured response stream, before END_STREAM.
    mov ax, [h2_rx_header+5]
    and ax, 0xff7f                  ; reserved high bit is ignored
    xor ax, [h2_rx_active_stream]
    mov bx, [h2_rx_header+7]
    xor bx, [h2_rx_active_stream+2]
    or ax, bx
    xor bh, bh
    mov bl, [h2_rx_ended]
    or ax, bx
    neg ax
    sbb ax, ax
    mov dx, [h2_rx_m_new]
    and dx, [h2_rx_m_type_data]
    h2_rx_mark_bad
    mov ax, [h2_rx_budget]
    cmp ax, [h2_rx_length_word]
    sbb ax, ax
    h2_rx_mark_bad
    mov ax, [h2_rx_length_word]
    and ax, dx
    sub [h2_rx_budget], ax

    ; PADDED DATA cannot have an empty payload.
    mov ax, [h2_rx_length_word]
    h2_rx_zero_mask
    mov bx, ax
    mov al, [h2_rx_header+4]
    and ax, 8
    neg ax
    sbb ax, ax
    and ax, bx
    h2_rx_mark_bad

    ; The first DATA byte is the pad count when PADDED was set.
    h2_rx_equal_byte h2_rx_mode, 1
    and ax, [h2_rx_m_good]
    mov dx, ax
    xor ax, ax
    mov al, [h2_rx_input]
    cmp ax, [h2_rx_remaining]
    sbb ax, ax
    not ax
    h2_rx_mark_bad
    mov al, [h2_rx_input]
    xor al, [h2_rx_padding]
    and al, dl
    xor [h2_rx_padding], al

    ; Compute the post-byte h2_rx_remaining length without conditional flow.
    mov ax, [h2_rx_m_body]
    and ax, 1
    mov bx, [h2_rx_remaining]
    sub bx, ax
    mov [h2_rx_new_remaining], bx
    mov ax, [h2_rx_length_word]
    mov dx, [h2_rx_m_new]
    h2_rx_select_word h2_rx_new_remaining

    ; End of a DATA frame, including zero-length DATA headers.
    mov ax, [h2_rx_new_remaining]
    h2_rx_zero_mask
    mov bx, [h2_rx_m_new]
    and bx, [h2_rx_m_type_data]
    or bx, [h2_rx_m_data]
    and ax, bx
    mov [h2_rx_m_finish], ax
    mov al, [h2_rx_header+4]
    and al, 1
    and al, [h2_rx_m_finish]
    or [h2_rx_ended], al

    ; A new frame selects DATA(1/2), known control(3), or unknown body(4).
    mov ax, 4
    cmp byte [h2_rx_header+3], 10
    sbb dx, dx
    and dx, 1
    sub ax, dx
    mov [h2_rx_next_mode], ax
    xor ax, ax
    mov al, [h2_rx_header+4]
    and al, 8
    shr al, 1
    shr al, 1
    shr al, 1
    mov bx, 2
    sub bx, ax
    mov ax, bx
    mov dx, [h2_rx_m_type_data]
    h2_rx_select_word h2_rx_next_mode
    ; A processed pad-count byte changes old h2_rx_mode 1 to 2.
    h2_rx_equal_byte h2_rx_mode, 1
    and ax, 1
    mov bl, [h2_rx_mode]
    add al, bl
    mov dx, [h2_rx_m_new]
    mov bx, [h2_rx_next_mode]
    xor bx, ax
    and bx, dx
    xor ax, bx
    mov bx, ax
    mov ax, [h2_rx_new_remaining]
    neg ax
    sbb ax, ax
    and ax, bx                      ; no h2_rx_remaining bytes => next frame h2_rx_header
    mov [h2_rx_mode], al
    mov ax, [h2_rx_new_remaining]
    mov [h2_rx_remaining], ax
    clc                            ; feed has no externally usable verdict
    ret
h2_rx_feed_end:

h2_rx_finish_record:
    cmp al, 1
    jne .reject
    cmp byte [h2_rx_last_value], 0x17
    jne .reject
    cmp word [h2_rx_position], 16624
    ja .reject
    cmp word [h2_rx_last_position], 16384
    ja .reject
    cmp byte [h2_rx_cut+(h2_rx_bad-h2_rx_work)], 0
    jne .reject
    mov si, h2_rx_cut
    mov di, h2_rx_live
    mov cx, h2_rx_state_size/2
    rep movsw
    mov si, h2_rx_journal
    mov cx, [h2_rx_live+(h2_rx_body_used-h2_rx_work)]
    mov dx, [h2_rx_live+(h2_rx_charged-h2_rx_work)]
    mov di, h2_rx_control_journal
    mov bp, [h2_rx_live+(h2_rx_control_used-h2_rx_work)]
    clc
    ret
.reject:
    call h2_rx_clear_record
    stc
    ret

h2_rx_consume_credit:
    mov ax, [h2_rx_live+(h2_rx_charged-h2_rx_work)]
    mov bx, [h2_rx_live+(h2_rx_budget-h2_rx_work)]
    add bx, ax
    cmp bx, h2_rx_capacity
    ja .h2_rx_bad
    mov [h2_rx_live+(h2_rx_budget-h2_rx_work)], bx
    mov word [h2_rx_live+(h2_rx_charged-h2_rx_work)], 0
    clc
    ret
.h2_rx_bad:
    stc
    ret

h2_rx_clear_record:
    xor ax, ax
    mov di, h2_rx_work
    mov cx, (h2_rx_journal-h2_rx_work)/2
    rep stosw
    mov di, h2_rx_journal
    mov cx, h2_rx_capacity/2
    cmp byte [0x062e+61], 1
    je .source_live
    rep stosw
.source_live:
    mov di, h2_rx_control_journal
    mov cx, h2_rx_control_capacity/2
    rep stosw
    ret
