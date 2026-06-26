%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%define PHASE_LOAD_ADDR low_scratch_start
%define PHASE_LOAD_ADDR_DEFAULTED
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

; Build 12 task #7 -- 286-only network-time sync (auto-recertify validity clock).
; ARP the gateway, query an INDEPENDENT NTP server, and set the CMOS RTC -- in the setup sequence,
; BEFORE any TLS -- so the recertify cert-validity gate later has a trustworthy "now" that did NOT
; come from the connection it authenticates (not circular). The CMOS RTC (hardware) carries the time
; forward; nothing is shared in RAM across the connect. On the 8088 (no CMOS RTC, no secure tier) and
; on ANY ARP/NTP failure or timeout, skip silently with CF=0 -- this never blocks the setup sequence.
; Self-contained (its own ARP) so it can't destabilise the hard-won connect/reconnect path.

; PI const ref: a phase loads at PHASE_LOAD_ADDR but is assembled at PHASE_BASE, so an embedded
; constant is reached at PHASE_LOAD_ADDR + (label - PHASE_BASE), never by its assembled address.
%define ntp_pi(label) (PHASE_LOAD_ADDR + (label - PHASE_BASE))

%define NTP_PAYLOAD_OFF (eth_header_len + ipv4_header_len + udp_header_len)
%define NTP_TXSEC_OFF   (NTP_PAYLOAD_OFF + 40)     ; transmit-timestamp seconds (big-endian)
%define NTP_FRAME_LEN   (NTP_PAYLOAD_OFF + 48)
%define NTP_ARP_TRIES   8                          ; ~0.9 s for the local gateway ARP
%define NTP_REPLY_TRIES 24                         ; ~2.6 s for the NTP round-trip

ntp_setup_phase:
    test    word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz      .skip                                  ; 8088: no RTC, no secure tier
    ; ARP the gateway (the NTP server is off-subnet -> route via the router)
    mov     si, handoff_addr + handoff_router_addr
    mov     di, arp_target_ip
    mov     cx, 4
    rep     movsb
    call    ntp_arp_gateway
    jc      .skip
    ; build + send the NTP query
    call    ntp_build_query
    mov     si, ne_tx_frame
    mov     cx, NTP_FRAME_LEN
    call    [nic_vt_transmit]
    jc      .skip
    call    ntp_wait_reply                         ; on success [ntp_seconds] is set
    jc      .skip
    ; convert + set the CMOS RTC
    call    ntp_to_rtc_fields                      ; rtc_time.inc -> rtc_* BCD
    call    ntp_set_rtc
.skip:
    clc                                            ; NTP trouble never fails the setup sequence
    ret

; ARP arp_target_ip -> arp_target_mac. CF=0 ok, CF=1 no reply.
ntp_arp_gateway:
    call    ntp_build_arp
    mov     si, ne_tx_frame
    mov     cx, arp_tx_frame_len
    call    [nic_vt_transmit]
    jc      .fail
    mov     word [ne_rx_read_limit], arp_tx_frame_len
    mov     word [dhcp_wait_count], NTP_ARP_TRIES
.poll:
    call    [nic_vt_receive]
    jc      .fail
    cmp     word [ne_rx_sample_count], 0
    je      .wait
    call    ntp_parse_arp
    jnc     .ok
.wait:
    mov     cx, 2
    phase_call_res wait_ticks
    dec     word [dhcp_wait_count]
    jnz     .poll
.fail:
    stc
    ret
.ok:
    clc
    ret

; minimal ARP request into ne_tx_frame (broadcast who-has arp_target_ip).
ntp_build_arp:
    mov     di, ne_tx_frame
    xor     al, al
    mov     cx, arp_tx_frame_len
    rep     stosb
    mov     di, ne_tx_frame
    mov     al, 0xff                               ; dest = broadcast
    mov     cx, 6
    rep     stosb
    mov     si, handoff_addr + handoff_mac
    mov     cx, 6
    rep     movsb
    mov     ax, 0x0608                             ; ethertype ARP
    stosw
    mov     ax, 0x0100                             ; htype Ethernet
    stosw
    mov     ax, 0x0008                             ; ptype IPv4
    stosw
    mov     ax, 0x0406                             ; hlen 6 / plen 4
    stosw
    mov     ax, 0x0100                             ; op request
    stosw
    mov     si, handoff_addr + handoff_mac         ; sender MAC
    mov     cx, 6
    rep     movsb
    mov     si, handoff_addr + handoff_ip_addr     ; sender IP
    mov     cx, 4
    rep     movsb
    xor     al, al                                 ; target MAC = 0
    mov     cx, 6
    rep     stosb
    mov     si, arp_target_ip                      ; target IP
    mov     cx, 4
    rep     movsb
    ret

; received ARP reply for arp_target_ip? copy its sender MAC -> arp_target_mac. CF=0 ok.
ntp_parse_arp:
    cmp     word [ne_rx_sample_count], arp_frame_len
    jb      .no
    cmp     word [ne_tx_frame + 12], 0x0608                  ; ethertype ARP
    jne     .no
    cmp     word [ne_tx_frame + arp_payload_offset + 6], 0x0200   ; op = reply
    jne     .no
    mov     si, ne_tx_frame + arp_spa_offset                 ; sender IP == the gateway?
    mov     di, arp_target_ip
    mov     cx, 4
.cmp_ip:
    lodsb
    cmp     al, [di]
    jne     .no
    inc     di
    loop    .cmp_ip
    mov     si, ne_tx_frame + arp_sha_offset                 ; sender MAC -> arp_target_mac
    mov     di, arp_target_mac
    mov     cx, 6
    rep     movsb
    clc
    ret
.no:
    stc
    ret

; build the NTP query into ne_tx_frame (eth -> gateway, IP -> ntp_server_ip, UDP dst 123).
ntp_build_query:
    mov     di, ne_tx_frame
    xor     al, al
    mov     cx, NTP_FRAME_LEN
    rep     stosb
    mov     di, ne_tx_frame
    mov     si, arp_target_mac                     ; dest MAC = gateway
    mov     cx, 6
    rep     movsb
    mov     si, handoff_addr + handoff_mac         ; src MAC
    mov     cx, 6
    rep     movsb
    mov     ax, 0x0008                             ; ethertype IPv4
    stosw
    mov     ax, 0x0045                             ; ver/IHL, TOS 0
    stosw
    mov     ax, ipv4_header_len + udp_header_len + 48   ; IP total length
    xchg    al, ah                                 ; -> big-endian
    stosw
    xor     ax, ax                                 ; id
    stosw
    stosw                                          ; flags/frag
    mov     ax, 0x1140                             ; TTL 0x40, proto 0x11 (UDP)
    stosw
    xor     ax, ax                                 ; header checksum (filled below)
    stosw
    mov     si, handoff_addr + handoff_ip_addr     ; src IP
    mov     cx, 4
    rep     movsb
    mov     si, ntp_pi(ntp_server_ip)              ; dest IP (PI const)
    mov     cx, 4
    rep     movsb
    mov     ax, 0x01c0                             ; UDP src port 49153 (ephemeral)
    stosw
    mov     ax, 0x7b00                             ; UDP dst port 123 (network order 00 7b)
    stosw
    mov     ax, udp_header_len + 48                ; UDP length
    xchg    al, ah
    stosw
    xor     ax, ax                                 ; UDP checksum 0 (optional in IPv4)
    stosw
    mov     byte [ne_tx_frame + NTP_PAYLOAD_OFF], 0x1B   ; LI=0 VN=3 Mode=3 (client); rest zero
    phase_call_res write_ipv4_checksum
    ret

; poll for the NTP reply; on success store the transmit-timestamp seconds in [ntp_seconds]. CF=0 ok.
ntp_wait_reply:
    mov     word [ne_rx_read_limit], NTP_FRAME_LEN
    mov     word [dhcp_wait_count], NTP_REPLY_TRIES
.poll:
    call    [nic_vt_receive]
    jc      .fail
    cmp     word [ne_rx_sample_count], 0
    je      .wait
    call    ntp_parse_reply
    jnc     .ok
.wait:
    mov     cx, 2
    phase_call_res wait_ticks
    dec     word [dhcp_wait_count]
    jnz     .poll
.fail:
    stc
    ret
.ok:
    clc
    ret

; match the NTP reply (IPv4 UDP from ntp_server_ip, src port 123) + reverse the 4 big-endian
; transmit-timestamp seconds into [ntp_seconds] (little-endian for ntp_to_rtc_fields). CF=0 ok.
ntp_parse_reply:
    cmp     word [ne_rx_sample_count], NTP_FRAME_LEN
    jb      .no
    cmp     word [ne_tx_frame + 12], 0x0008                  ; IPv4
    jne     .no
    cmp     byte [ne_tx_frame + eth_header_len + 9], 17      ; proto UDP
    jne     .no
    mov     si, ne_tx_frame + eth_header_len + 12            ; source IP == ntp_server_ip?
    mov     di, ntp_pi(ntp_server_ip)
    mov     cx, 4
.cmp_src:
    lodsb
    cmp     al, [di]
    jne     .no
    inc     di
    loop    .cmp_src
    cmp     word [ne_tx_frame + eth_header_len + ipv4_header_len], 0x7b00   ; UDP src port 123
    jne     .no
    mov     al, [ne_tx_frame + NTP_TXSEC_OFF + 0]            ; big-endian b0 (MSB)
    mov     [ntp_seconds + 3], al
    mov     al, [ne_tx_frame + NTP_TXSEC_OFF + 1]
    mov     [ntp_seconds + 2], al
    mov     al, [ne_tx_frame + NTP_TXSEC_OFF + 2]
    mov     [ntp_seconds + 1], al
    mov     al, [ne_tx_frame + NTP_TXSEC_OFF + 3]            ; b3 (LSB)
    mov     [ntp_seconds + 0], al
    clc
    ret
.no:
    stc
    ret

; write the BCD rtc_* fields to the CMOS RTC via the AT BIOS (int 1Ah AH=05h date, AH=03h time).
ntp_set_rtc:
    mov     ch, [rtc_century]
    mov     cl, [rtc_year]
    mov     dh, [rtc_month]
    mov     dl, [rtc_day]
    mov     ah, 0x05
    int     0x1a
    mov     ch, [rtc_hour]
    mov     cl, [rtc_min]
    mov     dh, [rtc_sec]
    xor     dl, dl                                 ; DST flag off
    mov     ah, 0x03
    int     0x1a
    ret

ntp_server_ip db 216, 239, 35, 0                   ; time1.google.com anycast (independent of the CDN)

%include "core/rtc_time.inc"
