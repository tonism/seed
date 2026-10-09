; Private authenticated HTTP/2 frame consumer. No TLS, NIC, BIOS or I/O here.
; Caller supplies the collector's DATA/control queues ONLY after tag success.
; These addresses are a candidate layout, not a product lifetime approval.
bits 16
cpu 8086
org 0x1800
dw h2_init, h2_open, h2_consume, h2_clear
h2 equ 0x062e                      ; handshake-only SHA state, pending audit
h2_header equ h2
h2_hpos equ h2+9
h2_left equ h2+10
h2_offset equ h2+12
h2_pad equ h2+14
h2_prefix equ h2+15
h2_cont equ h2+16
h2_header_end equ h2+17
h2_stage equ h2+18                 ; 0 headers, 1 DATA, 2 ended
h2_bad equ h2+19                   ; HTTP/2 connection error code
h2_active equ h2+20                ; network-order uint31
h2_initial equ h2+24               ; peer initial TX stream window
h2_stream_window equ h2+28         ; signed little-endian int32
h2_connection_window equ h2+32
h2_body_count equ h2+36
h2_length equ h2+40
h2_length_seen equ h2+44
h2_status equ h2+45
h2_settings_seen equ h2+47
h2_pending_ack equ h2+48
h2_retired equ h2+49
h2_small equ h2+50                 ; up to eight carried control payload bytes
h2_setting_pos equ h2+58
h2_no_body equ h2+59
h2_zero_concurrency equ h2+60
h2_bytes equ 68
h2_reply_prefix equ h2+h2_bytes
h2_reply_prefix_bytes equ 16
; Collector's provisional state is dead after authentication until next begin.
h2_tmp equ 0x2e1c
h2_ctl_ptr equ h2_tmp
h2_ctl_end equ h2_tmp+2
h2_data_ptr equ h2_tmp+4
h2_data_end equ h2_tmp+6
h2_output_ptr equ h2_tmp+8
h2_reply_used equ h2_tmp+10
h2_skipped equ h2_tmp+12
h2_input equ h2_tmp+14
h2_frame_len equ h2_tmp+16
h2_data_base equ 0x2e70
h2_control_base equ 0x3070
h2_control_end equ 0x3570
h2_collect_live equ 0x2e00
h2_last_position equ 0x2e6c

h2_init:
    call h2_clear
    mov word [h2_initial], 65535
    mov word [h2_connection_window], 65535
    mov byte [h2_pending_ack], 1
    mov byte [h2_stage], 2
    clc
    ret
h2_clear:
    call hp_clear
    cld
    xor ax, ax
    mov di, h2
    mov cx, (h2_bytes+h2_reply_prefix_bytes)/2
    rep stosw
    ret

; Open the next odd client stream after peer SETTINGS and our SETTINGS ACK.
; CF with no h2_bad indicates more control input is needed before opening.
h2_open:
    cmp byte [h2_bad], 0
    jne h2_fail
    cmp byte [h2_retired], 0
    jne h2_fail
    cmp byte [h2_zero_concurrency], 0
    jne h2_fail
    cmp byte [h2_pending_ack], 0
    jne h2_fail
    cmp byte [h2_settings_seen], 1
    jne h2_fail
    cmp byte [h2_stage], 2
    jne h2_fail
    cmp byte [h2_cont], 0
    jne h2_fail
    cmp word [h2_left], 0
    jne h2_fail
    cmp byte [h2_hpos], 0
    jne h2_fail
    mov ax, [h2_active+2]
    mov dx, [h2_active]
    xchg al, ah
    xchg dl, dh
    mov bx, ax
    or bx, dx
    jnz .next
    mov ax, 1
    jmp short .id
.next:
    add ax, 2
    adc dx, 0
    test dh, 0x80
    jnz h2_resource
.id:
    xchg al, ah
    xchg dl, dh
    mov [h2_active+2], ax
    mov [h2_active], dx
    mov [h2_collect_live+24], ax
    mov [h2_collect_live+22], dx
    mov word [h2_collect_live+16], 0
    mov byte [h2+61], 1               ; source owns DATA until END_STREAM sent
    mov word [h2+62], 0               ; no reserved outbound fragment
    mov byte [h2+65], 1               ; normal owner: validate/drain NST only
    mov byte [h2_collect_live+20], 0
    mov ax, [h2_initial]
    mov dx, [h2_initial+2]
    mov [h2_stream_window], ax
    mov [h2_stream_window+2], dx
    xor ax, ax
    mov [h2_body_count], ax
    mov [h2_body_count+2], ax
    mov [h2_length_seen], al
    mov [h2_no_body], al
    mov [h2_status], ax
    mov [h2_stage], al
    clc
    ret

; SI/CX DATA queue, DI/BP control queue, last_position = content length.
; Return AX: stripped DATA length, BX: reply prefix bytes (at h2_reply_prefix),
; CX: reply tail bytes (at h2_control_base). Caller sends both only on CF=0.
h2_consume:
    cld
    cmp byte [h2_bad], 0
    jne h2_fail
    mov [h2_data_ptr], si
    add cx, si
    mov [h2_data_end], cx
    mov [h2_ctl_ptr], di
    add bp, di
    mov [h2_ctl_end], bp
    mov word [h2_output_ptr], h2_data_base
    mov word [h2_reply_used], 0
    mov ax, [h2_last_position]
    sub ax, cx
    add ax, si
    sub ax, bp
    add ax, di
    mov [h2_skipped], ax
.loop:
    cmp word [h2_left], 0
    jne .payload
    mov si, [h2_ctl_ptr]
    cmp si, [h2_ctl_end]
    jae .done
    lodsb
    mov [h2_ctl_ptr], si
    xor bx, bx
    mov bl, [h2_hpos]
    mov [h2_header+bx], al
    inc byte [h2_hpos]
    cmp byte [h2_hpos], 9
    jb .loop
    mov byte [h2_hpos], 0
    call h2_new_frame
    jc h2_fail
    jmp .loop
.payload:
    cmp byte [h2_header+3], 9
    ja .skip
    cmp byte [h2_header+3], 0
    jne .control
    mov si, [h2_data_ptr]
    cmp si, [h2_data_end]
    jae .done
    lodsb
    mov [h2_data_ptr], si
    jmp short .byte
.control:
    mov si, [h2_ctl_ptr]
    cmp si, [h2_ctl_end]
    jae .done
    lodsb
    mov [h2_ctl_ptr], si
.byte:
    call h2_payload_byte
    jc h2_fail
    dec word [h2_left]
    inc word [h2_offset]
    jnz .not_wrap
    jmp h2_resource
.not_wrap:
    cmp word [h2_left], 0
    jne .loop
    call h2_frame_done
    jc h2_fail
    jmp .loop
.skip:
    mov ax, [h2_skipped]
    or ax, ax
    jz .done
    cmp ax, [h2_left]
    jbe .take
    mov ax, [h2_left]
.take:
    sub [h2_skipped], ax
    sub [h2_left], ax
    jmp .loop
.done:
    mov ax, [h2_ctl_ptr]
    cmp ax, [h2_ctl_end]
    jne h2_protocol
    mov ax, [h2_data_ptr]
    cmp ax, [h2_data_end]
    jne h2_protocol
    cmp word [h2_skipped], 0
    jne h2_protocol
    mov ax, [h2_output_ptr]
    sub ax, h2_data_base
    mov bx, [h2_reply_used]
    xor cx, cx
    cmp bx, h2_reply_prefix_bytes
    jbe .return
    mov cx, bx
    sub cx, h2_reply_prefix_bytes
    mov bx, h2_reply_prefix_bytes
.return:
    clc
    ret

h2_new_frame:
    cmp byte [h2_header], 0
    jne h2_frame_size
    mov ax, [h2_header+1]
    xchg al, ah
    cmp ax, 16384
    ja h2_frame_size
    mov [h2_left], ax
    mov [h2_frame_len], ax
    mov word [h2_offset], 0
    mov byte [h2_pad], 0
    mov byte [h2_prefix], 0
    mov byte [h2_setting_pos], 0
    and byte [h2_header+5], 0x7f
    cmp byte [h2_cont], 0
    je .dispatch
    cmp byte [h2_header+3], 9
    jne h2_protocol
.dispatch:
    mov al, [h2_header+3]
    cmp byte [h2_settings_seen], 0
    jne .peer_preface_ready
    cmp al, 4
    jne h2_protocol
    test byte [h2_header+4], 1
    jnz h2_protocol
.peer_preface_ready:
    cmp al, 0
    je .data
    cmp al, 1
    je .headers
    cmp al, 9
    je .continuation
    cmp al, 5
    je h2_protocol                   ; push was disabled before any request
    cmp al, 4
    je .settings
    cmp al, 6
    je .ping
    cmp al, 7
    je .goaway
    cmp al, 8
    je .window
    cmp al, 3
    je .reset
    cmp al, 2
    je .priority
    jmp .ready                       ; unknown extension body is skipped
.data:
    call h2_require_active
    jc h2_fail
    cmp byte [h2_stage], 1
    jne h2_protocol
    test byte [h2_header+4], 8
    jz .ready
    inc byte [h2_prefix]
    jmp .prefix_ready
.headers:
    call h2_require_active
    jc h2_fail
    cmp byte [h2_stage], 2
    je h2_protocol
    mov al, [h2_header+4]
    and al, 1
    mov [h2_header_end], al
    mov al, [h2_stage]
    cmp al, 1
    jne .begin_headers
    cmp byte [h2_header_end], 1
    jne h2_protocol
.begin_headers:
    call hp_begin
    test byte [h2_header+4], 8
    jz .priority_prefix
    inc byte [h2_prefix]
.priority_prefix:
    test byte [h2_header+4], 0x20
    jz .prefix_ready
    add byte [h2_prefix], 5
.prefix_ready:
    xor ax, ax
    mov al, [h2_prefix]
    cmp ax, [h2_left]
    ja h2_protocol
    jmp .ready
.continuation:
    call h2_require_active
    jc h2_fail
    cmp byte [h2_cont], 1
    jne h2_protocol
    jmp .ready
.settings:
    call h2_require_connection
    jc h2_fail
    test byte [h2_header+4], 1
    jz .settings_values
    cmp word [h2_left], 0
    jne h2_frame_size
    cmp byte [h2_pending_ack], 0
    je h2_protocol
    dec byte [h2_pending_ack]
    jmp .ready
.settings_values:
    mov ax, [h2_left]
    xor dx, dx
    mov bx, 6
    div bx
    or dx, dx
    jnz h2_frame_size
    jmp .ready
.ping:
    call h2_require_connection
    jc h2_fail
    cmp word [h2_left], 8
    jne h2_frame_size
    jmp .ready
.goaway:
    call h2_require_connection
    jc h2_fail
    cmp word [h2_left], 8
    jb h2_frame_size
    jmp .ready
.window:
    cmp word [h2_left], 4
    jne h2_frame_size
    jmp .ready
.reset:
    test byte [h2_header+8], 1
    jz h2_protocol
    call h2_require_nonzero
    jc h2_fail
    cmp word [h2_left], 4
    jne h2_frame_size
    jmp .ready
.priority:
    call h2_require_nonzero
    jc h2_fail
    cmp word [h2_left], 5
    jne h2_frame_size
.ready:
    cmp word [h2_left], 0
    je h2_frame_done
    clc
    ret

h2_require_connection:
    mov ax, [h2_header+5]
    or ax, [h2_header+7]
    jnz h2_protocol
    clc
    ret
h2_require_nonzero:
    mov ax, [h2_header+5]
    or ax, [h2_header+7]
    jz h2_protocol
    clc
    ret
h2_require_active:
    mov si, h2_header+5
    mov di, h2_active
    mov cx, 2
    repe cmpsw
    jne h2_protocol
    mov ax, [h2_active]
    or ax, [h2_active+2]
    jz h2_protocol
    clc
    ret

h2_payload_byte:
    mov [h2_input], al
    mov al, [h2_header+3]
    cmp al, 1
    jbe .data_or_headers
    cmp al, 9
    je .hpack
    cmp al, 4
    je .settings
    mov bx, [h2_offset]
    cmp bx, 8
    jae .done
    mov al, [h2_input]
    mov [h2_small+bx], al
    jmp .done
.settings:
    xor bx, bx
    mov bl, [h2_setting_pos]
    mov al, [h2_input]
    mov [h2_small+bx], al
    inc byte [h2_setting_pos]
    cmp byte [h2_setting_pos], 6
    jne .done
    mov byte [h2_setting_pos], 0
    jmp h2_setting
.data_or_headers:
    test byte [h2_header+4], 8
    jz .content
    cmp word [h2_offset], 0
    jne .content
    mov al, [h2_input]
    mov [h2_pad], al
    xor ah, ah
    xor bx, bx
    mov bl, [h2_prefix]
    add ax, bx
    cmp ax, [h2_left]
    ja h2_protocol
    jmp .done
.content:
    xor ax, ax
    mov al, [h2_prefix]
    cmp [h2_offset], ax
    jb .priority_byte
    xor ax, ax
    mov al, [h2_pad]
    cmp [h2_left], ax
    jbe .done
    cmp byte [h2_header+3], 1
    je .hpack
    cmp byte [h2_no_body], 0
    jne h2_protocol
    mov di, [h2_output_ptr]
    mov al, [h2_input]
    stosb
    mov [h2_output_ptr], di
    add word [h2_body_count], 1
    adc word [h2_body_count+2], 0
    jc h2_resource
    cmp byte [h2_length_seen], 0
    je .done
    mov ax, [h2_body_count+2]
    cmp ax, [h2_length+2]
    ja h2_protocol
    jb .done
    mov ax, [h2_body_count]
    cmp ax, [h2_length]
    ja h2_protocol
    jmp .done
.priority_byte:
    mov bx, [h2_offset]
    test byte [h2_header+4], 8
    jz .priority_index
    dec bx
.priority_index:
    cmp bx, 5
    jae h2_protocol
    mov al, [h2_input]
    mov [h2_small+bx], al
    cmp bx, 4
    jne .done
    call h2_check_dependency
    ret
.hpack:
    mov al, [h2_input]
    call hp_feed
    jc h2_header_error
.done:
    clc
    ret

h2_frame_done:
    mov al, [h2_header+3]
    cmp al, 0
    je .data
    cmp al, 1
    je .headers
    cmp al, 9
    je .headers
    cmp al, 4
    je .settings
    cmp al, 6
    je .ping
    cmp al, 8
    je h2_window
    cmp al, 7
    je .goaway
    cmp al, 3
    je .reset
    cmp al, 2
    je h2_check_dependency
    clc
    ret
.data:
    test byte [h2_header+4], 1
    jnz h2_end_stream
    clc
    ret
.headers:
    mov byte [h2_cont], 1
    test byte [h2_header+4], 4
    jz .done
    mov byte [h2_cont], 0
    call hp_finish
    jc h2_header_error
    cmp byte [h2_stage], 1
    je h2_end_stream                 ; trailer HEADERS required END_STREAM
    mov ax, [hp_status]
    cmp ax, 200
    jae .final_headers
    cmp byte [h2_header_end], 0
    jne h2_protocol
    cmp byte [hp_length_seen], 0
    jne h2_protocol
    jmp .done
.final_headers:
    mov [h2_status], ax
    mov byte [h2_stage], 1
    cmp ax, 204
    je .no_body
    cmp ax, 304
    jne .length
.no_body:
    mov byte [h2_no_body], 1
.length:
    mov al, [hp_length_seen]
    mov [h2_length_seen], al
    mov ax, [hp_content_length]
    mov dx, [hp_content_length+2]
    mov [h2_length], ax
    mov [h2_length+2], dx
    cmp word [h2_status], 204
    jne .end_headers
    cmp byte [h2_length_seen], 0
    jne h2_protocol
.end_headers:
    cmp byte [h2_header_end], 0
    jne h2_end_stream
    jmp .done
.settings:
    test byte [h2_header+4], 1
    jnz .done
    mov byte [h2_settings_seen], 1
    mov si, h2_settings_ack
    mov cx, 9
    jmp h2_reply
.ping:
    test byte [h2_header+4], 1
    jnz .done
    mov si, h2_ping_ack
    mov cx, 9
    call h2_reply
    jc h2_fail
    mov si, h2_small
    mov cx, 8
    jmp h2_reply
.goaway:
    mov byte [h2_retired], 1
    and byte [h2_small], 0x7f
    mov si, h2_small
    mov di, h2_active
    mov cx, 4
    repe cmpsb
    jb h2_protocol
    jmp .done
.reset:
    call h2_stream_order
    ja h2_protocol
    je h2_protocol                  ; active stream was reset, no completion
.done:
    clc
    ret

h2_end_stream:
    cmp byte [h2_no_body], 1
    je .done
    cmp byte [h2_length_seen], 0
    je .done
    mov ax, [h2_length]
    cmp ax, [h2_body_count]
    jne h2_protocol
    mov ax, [h2_length+2]
    cmp ax, [h2_body_count+2]
    jne h2_protocol
.done:
    mov byte [h2_stage], 2
    clc
    ret

h2_check_dependency:
    mov ax, [h2_small]
    and ax, 0xff7f
    cmp ax, [h2_header+5]
    jne .done
    mov ax, [h2_small+2]
    cmp ax, [h2_header+7]
    je h2_protocol
.done:
    clc
    ret
h2_stream_order:
    mov si, h2_header+5
    mov di, h2_active
    mov cx, 4
    repe cmpsb
    ret

; SETTINGS values are processed in order; the ACK is queued only at frame end.
h2_setting:
    mov ax, [h2_small]
    xchg al, ah
    mov dx, [h2_small+2]
    mov bx, [h2_small+4]
    xchg dl, dh
    xchg bl, bh
    cmp ax, 2
    je .push                        ; RFC 9113 permits a server to send zero
    cmp ax, 3
    je .concurrency
    cmp ax, 4
    je .initial
    cmp ax, 5
    je .max_frame
    clc                              ; static encoder ignores other settings
    ret
.push:
    or dx, bx
    jnz h2_protocol
    clc
    ret
.concurrency:
    or dx, bx
    mov byte [h2_zero_concurrency], 0
    jnz .done
    mov byte [h2_zero_concurrency], 1
.done:
    clc
    ret
.initial:
    test dh, 0x80
    jnz h2_flow_error
    mov ax, bx
    mov cx, dx
    sub ax, [h2_initial]
    sbb cx, [h2_initial+2]
    add [h2_stream_window], ax
    adc [h2_stream_window+2], cx
    jo h2_flow_error
    mov [h2_initial], bx
    mov [h2_initial+2], dx
    clc
    ret
.max_frame:
    cmp dx, 0x00ff
    ja h2_protocol
    or dx, dx
    jnz .done
    cmp bx, 16384
    jb h2_protocol
    clc
    ret

h2_window:
    mov dx, [h2_small]
    mov ax, [h2_small+2]
    xchg dl, dh
    xchg al, ah
    and dh, 0x7f
    mov bx, dx
    or bx, ax
    jz h2_protocol
    mov bx, [h2_header+5]
    or bx, [h2_header+7]
    jnz .stream
    add [h2_connection_window], ax
    adc [h2_connection_window+2], dx
    jo h2_flow_error
    clc
    ret
.stream:
    test byte [h2_header+8], 1
    jz h2_protocol
    push ax
    push dx
    call h2_stream_order
    pop dx
    pop ax
    ja h2_protocol
    jb .done
    cmp byte [h2_stage], 2
    je .done
    add [h2_stream_window], ax
    adc [h2_stream_window+2], dx
    jo h2_flow_error
.done:
    clc
    ret

; A carried PING can produce 17 reply bytes from one retained byte. Keep the
; first 16 reply bytes in otherwise-dead SHA state. Further bytes compact into
; the consumed prefix of the original control queue. Never overwrite unread
; control bytes, even if a caller passes inconsistent queue metadata.
h2_reply:
.next:
    lodsb
    mov bx, [h2_reply_used]
    cmp bx, h2_reply_prefix_bytes
    jae .tail
    mov [h2_reply_prefix+bx], al
    jmp short .wrote
.tail:
    mov di, bx
    sub di, h2_reply_prefix_bytes
    add di, h2_control_base
    cmp di, h2_control_end
    jae h2_resource
    cmp di, [h2_ctl_ptr]
    jae h2_resource
    mov [di], al
.wrote:
    inc word [h2_reply_used]
    loop .next
    clc
    ret

h2_header_error:
    cmp byte [hp_bad], 1
    je .compression
    cmp byte [hp_bad], 3
    je h2_resource
    jmp h2_protocol
.compression:
    mov byte [h2_bad], 9
    stc
    ret
h2_frame_size:
    mov byte [h2_bad], 6
    stc
    ret
h2_flow_error:
    mov byte [h2_bad], 3
    stc
    ret
h2_protocol:
    mov byte [h2_bad], 1
    stc
    ret
h2_resource:
    mov byte [h2_bad], 11
h2_fail:
    stc
    ret

h2_settings_ack: db 0,0,0,4,1,0,0,0,0
h2_ping_ack: db 0,0,8,6,1,0,0,0,0
%include "hpack_response_embedded.inc"
