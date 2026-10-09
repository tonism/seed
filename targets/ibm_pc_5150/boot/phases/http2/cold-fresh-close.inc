post_zero_window:
    mov al, 0x10
    xor cx, cx
    mov si, tcp_remote_ack
    call res_build_tcp_frame
    mov word [tcp_window_word], 0
    mov ax, [tcp_checksum_word]
    add ax, 1
    adc ax, 0
    mov [tcp_checksum_word], ax
    mov si, ne_tx_frame
    call word [res_nic_vt_transmit]
    ret

; The ordinary C phase was replaced when this controller loaded at 0900.
; Keep its bounded close leaf here instead of calling into stale phase bytes.
post_close_cached:
    mov ax, [tcp_source_port_word]
    or ax, ax
    jz .done
    mov al, 0x11
    mov dx, [tcp_remote_ack]
    or dx, [tcp_remote_ack + 2]
    jnz .send
    mov al, 0x04
.send:
    xor cx, cx
    mov si, tcp_remote_ack
    call res_build_tcp_frame
    mov si, ne_tx_frame
    call word [res_nic_vt_transmit]
.done:
    clc
    ret
