; Cached-target TCP opener for the literal-16K TLS 1.3 first flight.
;
; Preconditions:
;   * DHCP, endpoint DNS, and next-hop ARP ran before KeyGen.
;   * tcp_target_ip, arp_target_mac, tcp_dest_port_word, the handoff IP/MAC,
;     and the selected NIC vtable remain resident.
;   * no old live socket is owned by this helper.  A preflight socket must be
;     closed before the offline KeyGen interval.
;   * DS=ES=SS=0 and DF clear.
;
; The old tcp-connect phase cannot be loaded here: its 0x0900..0x0ed2 image
; would overwrite ek at 0x08c0.  This copy calls only the Build-13 resident
; frame builder, ACK sender, sequence adder, and active-driver vtable.  Empty
; receive polls wait on PIT channel 0 directly because the secure phase keeps
; interrupts masked and therefore cannot depend on the BIOS tick advancing.
; It never loads a floppy sector and caps NIC reads at the 96-byte SYN frame.

hello_res_tcp_ack                equ 0x13a6
hello_res_build_tcp_frame        equ 0x13e2
hello_res_tcp_add_cx_to_seq      equ 0x14da
hello_nic_vt_transmit            equ 0x15df
hello_nic_vt_receive             equ 0x15e1

hello_handoff_nic_base           equ 0x060e
hello_handoff_nic_family         equ 0x0610
hello_handoff_ip                 equ 0x061c
hello_ne_frame                   equ 0x0700
hello_ne_rx_sample_count         equ 0x06d5
hello_ne_rx_read_limit           equ 0x06d7
hello_wait_count                 equ 0x06df
hello_arp_target_mac             equ 0x06e1
hello_tcp_target_ip              equ 0x06e7
hello_tcp_dest_port              equ 0x06eb
hello_tcp_local_seq              equ 0x06ed
hello_tcp_remote_ack             equ 0x06f1
hello_tcp_source_port            equ 0x06f9

hello_family_3c501               equ 4
hello_el1_rx_cmd                 equ 0x06
hello_el1_rcvptr                 equ 0x0a
hello_el1_rx_cmd_good            equ 0x80
hello_tcp_offset                 equ 14 + 20
hello_tcp_rx_read_len            equ 96
hello_tcp_wait_count             equ 4
hello_tcp_wait_count_3c501       equ 128
hello_tcp_syn_retry_count        equ 3

hello_cached_connect:
    cld
    mov ax, [hello_tcp_target_ip]
    or ax, [hello_tcp_target_ip + 2]
    jz .failed
    call hello_cached_flush
    jc .failed
    call hello_cached_reset
    mov cx, hello_tcp_syn_retry_count
.try:
    push cx
%ifdef HELLO_CACHED_CONNECT_AUTO_3C501_PRIME
    call hello_cached_prepare_3c501_receive
%endif
    call hello_cached_send_syn
    jc .next
    call hello_cached_wait_synack
    jnc .connected
.next:
    pop cx
    loop .try
.failed:
    stc
    ret
.connected:
    pop cx
    call hello_res_tcp_ack
    ret

; Bound stale-frame drainage so a broken driver cannot pin the offline phase.
hello_cached_flush:
    mov word [hello_ne_rx_read_limit], hello_tcp_rx_read_len
    mov cx, 256
.next:
    push cx
    call [hello_nic_vt_receive]
    pop cx
    jc .failed
    cmp word [hello_ne_rx_sample_count], 0
    je .done
    loop .next
.failed:
    stc
    ret
.done:
    clc
    ret

hello_cached_reset:
    mov ax, [hello_tcp_source_port]
    or ax, ax
    jnz .bump
    mov bx, [0x046c]
    mov al, bl
    and al, 0x3f
    add al, 0xc0
    mov ah, bh
    jmp short .port_ready
.bump:
    inc ah
    jnz .port_ready
    inc al
    cmp al, 0xc0
    jae .port_ready
    mov al, 0xc0
.port_ready:
    mov [hello_tcp_source_port], ax
    mov word [hello_tcp_local_seq], 0x4553
    mov word [hello_tcp_local_seq + 2], 0x4445
    mov di, hello_tcp_remote_ack
    xor ax, ax
    stosw
    stosw
    ret

hello_cached_send_syn:
    mov al, 0x02
    mov cx, 4
    mov si, hello_cached_mss_option
    call hello_res_build_tcp_frame
    mov byte [hello_ne_frame + hello_tcp_offset + 12], 0x60
    mov ax, [hello_ne_frame + hello_tcp_offset + 16]
    add ax, 0xffef
    adc ax, 0
    mov [hello_ne_frame + hello_tcp_offset + 16], ax
    mov si, hello_ne_frame
    call [hello_nic_vt_transmit]
    ret

hello_cached_mss_option:
    db 0x02,0x04,0x01,0x80

hello_cached_wait_synack:
    mov word [hello_ne_rx_read_limit], hello_tcp_rx_read_len
    mov word [hello_wait_count], hello_tcp_wait_count
    cmp byte [hello_handoff_nic_family], hello_family_3c501
    jne .poll
    mov word [hello_wait_count], hello_tcp_wait_count_3c501
.poll:
    call [hello_nic_vt_receive]
    jc .failed
    cmp word [hello_ne_rx_sample_count], 0
    je .wait
    call hello_cached_parse_synack
    jnc .done
.wait:
    call hello_cached_wait_slice
    dec word [hello_wait_count]
    jnz .poll
.failed:
    stc
    ret
.done:
    clc
    ret

; Wait for one PIT channel-0 wrap without relying on IRQ0 or the BDA tick.
; Comparing every sample with the immediately preceding value also handles an
; initial sample at 0xffff: a reload is observed when the down-counter rises.
hello_cached_wait_slice:
    call hello_cached_read_pit
    mov bx, ax
.poll:
    call hello_cached_read_pit
    cmp ax, bx
    ja .done
    mov bx, ax
    jmp short .poll
.done:
    ret

hello_cached_read_pit:
    xor al, al
    out 0x43, al
    in al, 0x40
    mov ah, al
    in al, 0x40
    xchg al, ah
    ret

%ifdef HELLO_CACHED_CONNECT_AUTO_3C501_PRIME
; The fresh 16K HELLO owns enough code space to reset the 3c501 receive pointer
; immediately before every SYN.  That prevents a late frame from the closed
; preflight socket from owning the single receive buffer when SYN-ACK arrives.
hello_cached_prepare_3c501_receive:
    cmp byte [hello_handoff_nic_family], hello_family_3c501
    jne .done
    mov bx, [hello_handoff_nic_base]
    ; Reading receive status clears the 3c501's not-stale latch.  Clearing the
    ; buffer pointer or rewriting RX_CMD alone does not re-arm reception after
    ; an accepted late frame from the closed preflight socket.
    mov dx, bx
    in al, dx
    xor al, al
    lea dx, [bx + hello_el1_rcvptr]
    out dx, al
    lea dx, [bx + hello_el1_rx_cmd]
    mov al, hello_el1_rx_cmd_good
    out dx, al
.done:
    ret
%else
; The one-sector post-auth connector exports this compact leaf.  Its caller
; must first prove family_3c501 and load BX from the handoff NIC-base word.
hello_cached_prime_3c501_bx:
    ; BX is the prevalidated NIC base.  Read status before clearing the buffer
    ; pointer so an accepted old frame cannot leave later SYN-ACK reception
    ; inhibited.
    mov dx, bx
    in al, dx
    xor al, al
    lea dx, [bx + hello_el1_rcvptr]
    out dx, al
    sub dl, hello_el1_rcvptr - hello_el1_rx_cmd
    mov al, hello_el1_rx_cmd_good
    out dx, al
    ret
%endif

hello_cached_parse_synack:
    cmp word [hello_ne_rx_sample_count], hello_tcp_offset + 20
    jb .bad
    cmp word [hello_ne_frame + 12], 0x0008
    jne .bad
    cmp byte [hello_ne_frame + 14], 0x45
    jne .bad
    cmp byte [hello_ne_frame + 23], 6
    jne .bad
    push ds
    pop es
    mov si, hello_ne_frame + 26
    mov di, hello_tcp_target_ip
    mov cx, 2
    repe cmpsw
    jne .bad
    mov si, hello_ne_frame + 30
    mov di, hello_handoff_ip
    mov cx, 2
    repe cmpsw
    jne .bad
    mov ax, [hello_tcp_dest_port]
    cmp [hello_ne_frame + hello_tcp_offset], ax
    jne .bad
    mov ax, [hello_tcp_source_port]
    cmp [hello_ne_frame + hello_tcp_offset + 2], ax
    jne .bad
    mov al, [hello_ne_frame + hello_tcp_offset + 13]
    test al, 0x04
    jnz .bad
    and al, 0x12
    cmp al, 0x12
    jne .bad
    cmp word [hello_ne_frame + hello_tcp_offset + 8], 0x4553
    jne .bad
    cmp word [hello_ne_frame + hello_tcp_offset + 10], 0x4545
    jne .bad
    mov si, hello_ne_frame + hello_tcp_offset + 8
    mov di, hello_tcp_local_seq
    movsw
    movsw
    mov si, hello_ne_frame + hello_tcp_offset + 4
    mov di, hello_tcp_remote_ack
    movsw
    movsw
    mov di, hello_tcp_remote_ack
    mov cx, 1
    call hello_res_tcp_add_cx_to_seq
    clc
    ret
.bad:
    stc
    ret

; Backpressure boundary after the last ServerHello byte.  The caller first
; sets tcp_remote_ack to exactly the first unconsumed protected-flight byte
; (discarding any coalesced tail), then advertises a zero receive window.
; Removing the builder's wire 0x0100 window subtracts 1 from its little-endian
; checksum accumulator, so the stored one's-complement checksum increases by
; one with end-around carry.
hello_cached_zero_window_ack:
    mov al, 0x10
    xor cx, cx
    mov si, hello_tcp_remote_ack
    call hello_res_build_tcp_frame
    mov word [hello_ne_frame + hello_tcp_offset + 14], 0
    mov ax, [hello_ne_frame + hello_tcp_offset + 16]
    add ax, 1
    adc ax, 0
    mov [hello_ne_frame + hello_tcp_offset + 16], ax
    mov si, hello_ne_frame
    call [hello_nic_vt_transmit]
    ret

; After candidate + symmetric import/key schedule, drain stale unacknowledged
; frames and send this ordinary 256-byte-window ACK with unchanged seq/ack.
hello_cached_window_update:
    jmp hello_res_tcp_ack
