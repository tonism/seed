tcp_receive_payload:
    ; Keep this distinct from dhcp_rx_frame_len, which enables the DHCP prefix filter.
    mov word [ne_rx_read_limit], tcp_payload_read_len
    mov word [dhcp_wait_count], tcp_payload_wait_count
.poll:
    call [nic_vt_receive]
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .wait
    call parse_tcp_payload
    jnc .done
    call [nic_vt_rx_fallback]
    jnc .done
.wait:
    mov cx, 0x0800
.delay:
    loop .delay
    dec word [dhcp_wait_count]
    jnz .poll
.failed:
    mov al, net_error_tcp
    jmp net_fail_al
.done:
    ret

; Build 12 NIC HAL: the resident rx_fallback default (CF=1 = "no usable second frame"). Every driver
; header points its rx_fallback slot here EXCEPT 3c501, whose driver provides el1_second_frame (the
; single-buffer card is the only one that needs a second-frame retry).
nic_rx_fallback_none:
    stc
    ret
