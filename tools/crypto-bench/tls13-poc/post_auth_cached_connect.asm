; Cold cached-target connector for the post-auth resumption dispatcher.
;
; This one-sector wrapper keeps the connector outside the eight-sector
; resumed HELLO phase.  The live post-auth composition loads it into the
; borrowed ninth sector at 0x2800 only after the complete ClientHello
; transcript pass, opens TCP, and then replaces it with the RX phase.

bits 16
cpu 8086

%ifndef POST_AUTH_CACHED_CONNECT_ORIGIN
%define POST_AUTH_CACHED_CONNECT_ORIGIN 0x2400
%endif

org POST_AUTH_CACHED_CONNECT_ORIGIN

post_auth_cached_header:
    db 'RHC1'
    dw 1
    dw post_auth_cached_end - post_auth_cached_header
    dw post_auth_cached_entry_count
post_auth_cached_entry_table:
    dw post_auth_cached_connect
    dw hello_cached_zero_window_ack
    dw hello_cached_window_update
    dw hello_cached_prime_3c501_bx
post_auth_cached_entry_count equ \
    ($ - post_auth_cached_entry_table) / 2

%include "hello_cached_connect.inc"

; The later resumption workers are packed to their sector ceilings and cannot
; each carry another zero-window builder.  Install one relocatable leaf in the
; stable 0x0f00..0x0fe1 TCP-tail gap before opening the resumed socket.  All
; intervening 0x0900 workers end at (and therefore preserve) that address.
post_auth_cached_connect:
    cld
    push ds
    pop es
    mov si, post_auth_zero_window_source
    mov di, 0x0f00
    mov cx, post_auth_zero_window_end - post_auth_zero_window_source
    rep movsb
    jmp hello_cached_connect

post_auth_zero_window_source:
    mov al, 0x10
    xor cx, cx
    mov si, hello_tcp_remote_ack
    mov dx, hello_res_build_tcp_frame
    call dx
    mov word [hello_ne_frame + hello_tcp_offset + 14], 0
    inc word [hello_ne_frame + hello_tcp_offset + 16]
    jnz .checksum_ready
    inc word [hello_ne_frame + hello_tcp_offset + 16]
.checksum_ready:
    mov si, hello_ne_frame
    call [hello_nic_vt_transmit]
    ret
post_auth_zero_window_end:

post_auth_cached_end:

%if ($ - $$) > 0x0200
%error "post-auth cached connector exceeds one sector"
%endif
