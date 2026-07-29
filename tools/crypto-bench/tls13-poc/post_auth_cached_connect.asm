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
    dw hello_cached_connect
    dw hello_cached_zero_window_ack
    dw hello_cached_window_update
post_auth_cached_entry_count equ \
    ($ - post_auth_cached_entry_table) / 2

%include "hello_cached_connect.inc"

post_auth_cached_end:

%if ($ - $$) > 0x0200
%error "post-auth cached connector exceeds one sector"
%endif
