; Live, credential-free TLS 1.3 logical-K14 controller chain.
;
; The LIVE_K15 names are historical.  This source is assembled six ways by
; build_live_k15.py:
;   LIVE_K15_BOOTSTRAP       temporary 0x1600 slot entry
;   LIVE_K15_BOOT_CONTROLLER post-DHCP/offline preparation at 0x3400
;   LIVE_K15_HELLO_CONTROLLER live ClientHello/ServerHello at 0x3400
;   LIVE_K15_CRYPTO_CONTROLLER candidate + symmetric schedule at 0x3400
;   LIVE_K15_PROTECTED_CONTROLLER protected receive + Finished TX at 0x0900
;   LIVE_K15_POST_CONTROLLER post-Finished HEAD/NST canary at 0x0900
;
; The controllers are deliberately sibling PoC code.  They call the byte-exact
; Build-13 resident NIC/TCP ABI from a copied SEED.SYS nucleus; they are not
; linked into the product runtime.

bits 16
cpu 8086

%ifdef LIVE_K15_BOOTSTRAP

%ifndef LIVE_K15_SCHEDULER_LBA
%error "LIVE_K15_SCHEDULER_LBA is required"
%endif

org 0x1600

live_bootstrap:
    ; Preserve the ROM BASIC handoff registers while providing immediate,
    ; BIOS-visible evidence that RUN reached machine code.
    push ax
    push bx
    push cx
    push dx
    push es
    mov si, live_boot_text
.paint:
    lodsb
    or al, al
    jz .read_controller
    mov ah, 0x0e
    xor bh, bh
    mov bl, 0x07
    int 0x10
    jmp short .paint

.read_controller:
    ; The 160 KiB harness is single-sided, eight sectors/track.  The scheduler
    ; is one aligned sector inside the first, contiguous SEED.SYS file.
    xor ax, ax
    mov es, ax
    mov ax, LIVE_K15_SCHEDULER_LBA
    mov bl, 8
    div bl
    mov ch, al
    mov cl, ah
    inc cl
    xor dh, dh
    mov dl, 1                         ; ROM BASIC sidecar mounts harness at B:
    mov bx, 0x3400
    mov ax, 0x0201
    int 0x13
    jc .failed

    pop es
    pop dx
    pop cx
    pop bx
    pop ax

    ; Recreate the four product bytes replaced by the detour and continue at
    ; the first untouched instruction in Build-13 start.
    cli
    mov bp, 0x8000
    jmp 0x101b

.failed:
    mov ax, 0x0e21                    ; visible "!"
    xor bh, bh
    mov bl, 0x0c
    int 0x10
.halt:
    sti
    hlt
    jmp short .halt

live_boot_text db 13,10,'K15 boot',13,10,0

%elifdef LIVE_K15_BOOT_CONTROLLER

%ifndef LIVE_K15_SYM_KEY
%error "live phase keys are required"
%endif
%ifndef LIVE_K15_ENDPOINT_KEY
%error "live phase keys are required"
%endif
%ifndef LIVE_K15_TCP_KEY
%error "live phase keys are required"
%endif
%ifndef LIVE_K15_SECURE_FO
%ifndef LIVE_K15_FIXTURE_KEY
%error "live phase keys are required"
%endif
%endif
%ifndef LIVE_K15_KEYGEN_KEY
%error "live phase keys are required"
%endif
%ifndef LIVE_K15_HELLO_KEY
%error "live phase keys are required"
%endif
%ifndef LIVE_K15_HELLO_CONTROLLER_KEY
%error "live phase keys are required"
%endif
%ifdef LIVE_K15_SECURE_FO
%ifndef LIVE_K15_SECURE_SYM_CONTROLLER_KEY
%error "secure FO requires the card-resident symmetric controller phase"
%endif
%ifndef LIVE_K15_NE_BUF_LOAD
%error "secure FO requires the guarded NE2000 remote-DMA write leaf"
%endif
%ifndef LIVE_K15_ENTROPY_CONTROLLER_KEY
%error "secure FO requires the read-only entropy controller phase"
%endif
%ifndef LIVE_K15_SECURE_PRECONNECT_KEY
%error "secure FO requires the pre-connect continuation phase"
%endif
%endif

org 0x3400

res_load_phase               equ 0x10c4
res_nic_vt_enter             equ 0x15db
tcp_connect_entry            equ 0x0900
tcp_close_cached_entry       equ 0x0941
attempt_cache                equ 0x3b9c
reconnect_retries            equ 0x3c9d
compacting_msg               equ 0x3c9f
pre_sym_transition          equ 0x0f00
%ifdef LIVE_K15_SECURE_FO
handoff_nic_base            equ 0x060e
handoff_nic_family          equ 0x0610
family_ne2000               equ 2
ne_tx_start                 equ 0x06cb
ne_rx_stop                  equ 0x06cd
secure_ne_pstop             equ 0x73
secure_sym_card_page        equ 0x73
secure_ek_card_page         equ 0x74
secure_handoff_a_page       equ 0x7e
secure_handoff_b_page       equ 0x7f
%endif

live_boot_controller:
    cld
    mov si, live_net_text
    call live_emit

    call word [res_nic_vt_enter]
    jc live_fail

%ifdef LIVE_K15_SECURE_FO
    ; The secure artifact is deliberately NE2000-only.  Its live-only packet
    ; init patch shrinks PSTOP from 0x80 to 0x73, reserving the remaining
    ; volatile card RAM without changing the packaged driver.
    cmp byte [handoff_nic_family], family_ne2000
    jne live_fail
    cmp byte [ne_rx_stop], secure_ne_pstop
    jne live_fail

    ; Stage the sub-page symmetric continuation before opening a socket.  The
    ; later low trampoline can replace 0x3400..0x34ff from card RAM without a
    ; critical-path floppy read; 0x3500..0x35ff, including persistent services,
    ; stays resident from the secure crypto controller.
    mov ax, LIVE_K15_SECURE_SYM_CONTROLLER_KEY
    mov bx, 0x0700
    call res_load_phase
    jc live_fail
    mov al, secure_sym_card_page
    mov si, 0x0700
    mov bp, 256
    call live_secure_card_write
    jc live_fail

    ; A prior run may have failed after publishing any part of the resumed
    ; vault but before its best-effort cold scrub could load.  Page 0x73 was
    ; just overwritten by the continuation controller; fully overwrite every
    ; remaining reserved page before any path can read card-vault state.  Keep
    ; attempting after an individual DMA failure, then fail closed if any page
    ; could not be cleared.
    push ds
    pop es
    xor ax, ax
    mov di, 0x0700
    mov cx, 128
    rep stosw
    xor di, di
    mov al, secure_ek_card_page
.secure_scrub_next:
    mov si, 0x0700
    mov bp, 256
    call live_secure_card_write
    adc di, 0
    inc al
    cmp al, 0x80
    jne .secure_scrub_next
    or di, di
    jz .secure_scrub_done
    jmp live_fail
.secure_scrub_done:
%endif

    ; Preload the complete symmetric image before opening any socket.  HELLO
    ; and candidate later dirty only its checked prefix; the critical path
    ; restores exactly LIVE_K15_SYM_RESTORE_KEY.
    mov ax, LIVE_K15_SYM_KEY
    mov bx, 0x1800
    call res_load_phase
    jc live_fail

%ifdef LIVE_K15_SECURE_FO
    ; KeyGen must be resident before entropy collection because the read-only
    ; floppy-timing controller reuses its checked Keccak-f[1600] primitive.
    mov ax, LIVE_K15_KEYGEN_KEY
    mov bx, 0x1800
    call res_load_phase
    jc live_fail
    ; Install the complete continuation before collecting entropy.  Once the
    ; collector finishes, no further floppy read can strand the 256-byte output
    ; without the continuation's local/card fail scrub being resident.
    mov ax, LIVE_K15_SECURE_PRECONNECT_KEY
    mov bx, 0x2400
    call res_load_phase
    jc live_fail
    mov ax, LIVE_K15_ENTROPY_CONTROLLER_KEY
    mov bx, 0x0900
    call res_load_phase
    jc live_fail
    mov si, live_entropy_ready_text
    call live_emit
    call word [0x0910]
    jc live_fail
    mov si, live_entropy_pass_text
    call live_emit
    jmp 0x2400
%else
    ; Credential-free endpoint setup: the retained production endpoint phase
    ; writes only api.openai.com's DNS qname and TCP/443 destination.
    mov byte [reconnect_retries], 3
    mov byte [compacting_msg], 0
    mov ax, LIVE_K15_ENDPOINT_KEY
    mov bx, 0x0700
    call res_load_phase
    jc live_fail
    call 0x0700
    jc live_fail

    mov si, live_preflight_text
    call live_emit
    mov ax, LIVE_K15_TCP_KEY
    mov bx, 0x0900
    call res_load_phase
    jc live_fail
    call tcp_connect_entry
    jc live_fail
    call tcp_close_cached_entry

    ; The fixture contains only a provisioned 64-byte d||z device seed and
    ; 64 public ClientHello random/session bytes.  All KeyGen, encapsulation
    ; recovery, transcript, and traffic-key work runs on the 8088.
    mov ax, LIVE_K15_FIXTURE_KEY
    mov bx, 0x0700
    call res_load_phase
    jc live_fail
    mov si, 0x0700
    mov di, attempt_cache
    mov cx, 32
    rep movsw

    mov si, live_keygen_text
    call live_emit
    mov ax, LIVE_K15_KEYGEN_KEY
    mov bx, 0x1800
    call res_load_phase
    jc live_fail
    call 0x1800
%ifdef LIVE_K15_SECURE_FO
    ; KeyGen's actual public key is still live at 0x08c0.  Preserve it in
    ; volatile card RAM before HELLO reuses the low object window.
    mov al, secure_ek_card_page
    mov si, 0x08c0
    mov bp, 1184
    call live_secure_card_write
    jc live_fail
%endif

    mov si, 0x0740
    mov di, attempt_cache
    mov cx, 32
    rep movsw
    mov ax, LIVE_K15_HELLO_KEY
    mov bx, 0x1800
    call res_load_phase
    jc live_fail

    mov si, live_connect_text
    call live_emit
    ; Endpoint/DNS setup is now complete.  Only now install the tiny
    ; self-overwrite trampoline in 0x0f00, after the product bytes that used
    ; to corrupt a larger diagnostic service there have retired.  It survives
    ; the live HELLO controller and is replaced by delta_load after HELLO.
    push ds
    pop es
    mov si, live_pre_sym_transition_source
    mov di, pre_sym_transition
    mov cx, live_pre_sym_transition_len
    rep movsb
    mov ax, LIVE_K15_HELLO_CONTROLLER_KEY
    jmp pre_sym_transition

live_pre_sym_transition_source:
    mov bx, 0x3400
    mov dx, res_load_phase
    call dx
    jc .failed
    mov dx, 0x3400
    jmp dx
.failed:
    sti
    hlt
    jmp short .failed
live_pre_sym_transition_end:
live_pre_sym_transition_len equ \
    live_pre_sym_transition_end - live_pre_sym_transition_source
%endif

live_serial_init:
    mov dx, 0x03fb
    mov al, 0x80
    out dx, al
    mov dx, 0x03f8
    mov al, 12                        ; 9600 baud
    out dx, al
    inc dx
    xor al, al
    out dx, al
    mov dx, 0x03fb
    mov al, 0x03                      ; 8N1
    out dx, al
    mov dx, 0x03fc
    mov al, 0x03
    out dx, al
    ret

live_emit:
    ; Product endpoint/DNS setup changes the UART-adjacent low state that
    ; corrupted the old 0x0f00 diagnostic copy.  Reinitializing at each string
    ; also makes a dropped diagnostic line fail independently.
    call live_serial_init
.next:
    lodsb
    or al, al
    jz .done
    call live_putchar
    jmp short .next
.done:
    ret

live_putchar:
    push ax
    push bx
    push cx
    push dx
    mov bl, al
    mov ah, 0x0e
    xor bh, bh
    int 0x10
    mov dx, 0x03fd
    mov cx, 0xffff
.serial_wait:
    in al, dx
    test al, 0x20
    jnz .serial_ready
    loop .serial_wait
    jmp short .restore
.serial_ready:
    mov dx, 0x03f8
    mov al, bl
    out dx, al
.restore:
    pop dx
    pop cx
    pop bx
    pop ax
    ret

%ifndef LIVE_K15_SECURE_FO
live_emit_hex16:
    push ax
    push cx
    push dx
    mov dx, ax
    mov cx, 4
.nibble:
    rol dx, 1
    rol dx, 1
    rol dx, 1
    rol dx, 1
    mov al, dl
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .digit
    add al, 'A' - '9' - 1
.digit:
    call live_putchar
    loop .nibble
    pop dx
    pop cx
    pop ax
    ret
%endif

%ifdef LIVE_K15_SECURE_FO
; AL=card page, SI=source, BP=count.  ne_buf_load hard-wires RSAR0=0 and
; sources RSAR1 from ne_tx_start, so temporarily substitute the vault page.
; POP/MOV preserve the driver's carry result while restoring normal TX page.
live_secure_card_write:
    mov ah, [ne_tx_start]
    push ax
    mov [ne_tx_start], al
    mov bx, [handoff_nic_base]
    call LIVE_K15_NE_BUF_LOAD
    pop ax
    mov [ne_tx_start], ah
live_secure_card_write_restored:
    ret
%endif

live_fail:
    mov si, live_fail_text
    call live_emit
.halt:
    sti
    hlt
    jmp short .halt

live_fail_text db 13,10,'FAIL',13,10,'RESULT',13,10,0

%ifdef LIVE_K15_SECURE_FO
live_net_text           db 'K15 local ready',13,10,0
live_entropy_ready_text db 'ENTROPY START 256',13,10,0
live_entropy_pass_text  db 'ENTROPY PASS 256',13,10,0
%else
live_net_text       db 'K15 net ready',13,10,0
live_preflight_text db 'preflight cache',13,10,0
live_keygen_text    db 'offline keygen',13,10,0
live_connect_text   db 'live connect',13,10,0
%endif

%elifdef LIVE_K15_SECURE_PRECONNECT_CONTROLLER

%ifndef LIVE_K15_ENDPOINT_KEY
%error "secure pre-connect continuation requires endpoint phase"
%endif
%ifndef LIVE_K15_TCP_KEY
%error "secure pre-connect continuation requires TCP phase"
%endif
%ifndef LIVE_K15_KEYGEN_KEY
%error "secure pre-connect continuation requires KeyGen phase"
%endif
%ifndef LIVE_K15_HELLO_KEY
%error "secure pre-connect continuation requires HELLO phase"
%endif
%ifndef LIVE_K15_HELLO_CONTROLLER_KEY
%error "secure pre-connect continuation requires HELLO controller phase"
%endif
%ifndef LIVE_K15_BOOT_EMIT
%error "secure pre-connect continuation requires boot emit service"
%endif
%ifndef LIVE_K15_BOOT_FAIL
%error "secure pre-connect continuation requires boot failure service"
%endif
%ifndef LIVE_K15_BOOT_CARD_WRITE
%error "secure pre-connect continuation requires boot card-write service"
%endif
%ifndef LIVE_K15_NE_BUF_READ
%error "secure pre-connect continuation requires card-read service"
%endif
%ifndef LIVE_K15_NE_BUF_LOAD
%error "secure pre-connect continuation requires card-write service"
%endif
%ifndef LIVE_K15_PREPARE_INTERNET
%error "secure pre-connect continuation requires pre-network DHCP entry"
%endif

org 0x2400

res_load_phase                 equ 0x10c4
tcp_connect_entry              equ 0x0900
tcp_close_cached_entry         equ 0x0941
attempt_cache                  equ 0x3b9c
reconnect_retries              equ 0x3c9d
compacting_msg                 equ 0x3c9f
pre_sym_transition             equ 0x0f00
pre_generic_installer          equ 0x0e80
secure_ek_card_page            equ 0x74
secure_handoff_a_page          equ 0x7e
secure_handoff_b_page          equ 0x7f
secure_handoff_a               equ 0x7e00
secure_handoff_b               equ 0x7f00
handoff_nic_base               equ 0x060e
ne_tx_start                    equ 0x06cb

live_secure_preconnect_controller:
    cld
    ; Install the self-overwrite-safe transition and failure scrub before the
    ; first fallible operation touches the target-generated entropy.
    push ds
    pop es
    mov si, preconnect_transition_source
    mov di, pre_sym_transition
    mov cx, preconnect_transition_len
    rep movsb

    ; Duplicate the complete two-attempt entropy output before any overlay
    ; can reuse 0x0700.  Later initial-handshake writes replace only the first
    ; 128 bytes of each page, preserving the one-shot resumption half.
    mov al, secure_handoff_a_page
    mov si, 0x0700
    mov bp, 256
    call LIVE_K15_BOOT_CARD_WRITE
    jc preconnect_failed
    mov al, secure_handoff_b_page
    mov si, 0x0700
    mov bp, 256
    call LIVE_K15_BOOT_CARD_WRITE
    jc preconnect_failed

    ; The live controller now takes over immediately before the product's
    ; first DHCP call.  Only after both complete entropy bundles are duplicated
    ; into volatile card RAM may network-controlled work reuse the low output
    ; window.  The product routine performs DHCP and restores the NIC vtable;
    ; any failure joins the existing full local/card scrub.
    call LIVE_K15_PREPARE_INTERNET
    jc preconnect_failed

    ; Endpoint/DNS setup and the cached TCP preflight must complete before
    ; KeyGen.  Both product paths use the exact high TLS scratch at
    ; 0x36c2..0x3b8f, which overlaps the live ML-KEM private key at
    ; 0x3600..0x3b00.  Generating the key first silently corrupts decapsulation
    ; even though the public encapsulation key remains intact.
    mov byte [reconnect_retries], 3
    mov byte [compacting_msg], 0
    mov ax, LIVE_K15_ENDPOINT_KEY
    mov bx, 0x0700
    call res_load_phase
    jc preconnect_failed
    call 0x0700
    jc preconnect_failed

    mov si, preconnect_cache_text
    call LIVE_K15_BOOT_EMIT
    mov ax, LIVE_K15_TCP_KEY
    mov bx, 0x0900
    call res_load_phase
    jc preconnect_failed
    call tcp_connect_entry
    jc preconnect_failed
    call tcp_close_cached_entry

    ; Endpoint/TCP setup reused 0x0700.  Restore and compare both complete
    ; initial bundles from card RAM before selecting random/session bytes.
    push ds
    pop es
    mov bx, secure_handoff_a
    mov cx, 128
    mov di, 0x0700
    call LIVE_K15_NE_BUF_READ
    jc preconnect_failed
    mov bx, secure_handoff_b
    mov cx, 128
    mov di, 0x0780
    call LIVE_K15_NE_BUF_READ
    jc preconnect_failed
    mov si, 0x0700
    mov di, 0x0780
    mov cx, 64
    xor dx, dx
.compare_initial:
    lodsw
    xor ax, [di]
    or dx, ax
    add di, 2
    loop .compare_initial
    or dx, dx
    jnz preconnect_failed

    ; Only after every product high-scratch user has retired do we expose d||z
    ; to KeyGen.  Reload its exact phase so endpoint/TCP implementation details
    ; cannot become an implicit code-lifetime dependency.
    mov si, 0x0700
    mov di, attempt_cache
    mov cx, 32
    rep movsw
    mov ax, LIVE_K15_KEYGEN_KEY
    mov bx, 0x1800
    call res_load_phase
    jc preconnect_failed
    mov si, preconnect_keygen_text
    call LIVE_K15_BOOT_EMIT
    call 0x1800

    ; FO validation is deliberately deferred until after authenticated HEAD
    ; and ticket processing.  Preserve the public encapsulation key for that
    ; later re-encryption check; unlike the old ordering, HELLO can use the
    ; live low copy directly and no card read is needed on the critical path.
    mov al, secure_ek_card_page
    mov si, 0x08c0
    mov bp, 1184
    call LIVE_K15_BOOT_CARD_WRITE
    jc preconnect_failed

    mov si, 0x0740
    mov di, attempt_cache
    mov cx, 32
    rep movsw

    ; TCP's exact three-sector load ends at 0x0f00 and therefore overwrote
    ; the low generic installer slot.  Install it only now, after every low
    ; product overlay has retired but before HELLO overwrites this controller.
    mov si, preconnect_generic_installer_source
    mov di, pre_generic_installer
    mov cx, preconnect_generic_installer_len
    rep movsb

    mov si, preconnect_live_text
    call LIVE_K15_BOOT_EMIT
    ; HELLO's full eight-sector load overwrites this 0x2400 continuation.
    ; The already-relocated low transition remains live across that overwrite.
    mov ax, LIVE_K15_HELLO_KEY
    jmp pre_sym_transition

preconnect_transition_source:
    mov dx, res_load_phase
    mov bx, 0x1800
    call dx
    jc preconnect_transition_failed_source
    mov ax, LIVE_K15_HELLO_CONTROLLER_KEY
    ; Stage the fallible sector read in retired KeyGen polynomial work.  A
    ; failed or partial read cannot corrupt the still-live boot fail service.
    mov bx, 0x3000
    mov dx, res_load_phase
    call dx
    jc preconnect_transition_failed_source
    push ds
    pop es
    mov si, 0x3000
    mov di, 0x3400
    mov cx, 256
    rep movsw
    ; Run outside 0x0f00 while replacing this HELLO-specific transition with
    ; the generic staged one-sector transition that HELLO will use for the
    ; secure crypto controller.
    mov dx, pre_generic_installer
    jmp dx
preconnect_transition_failed_source:
    push ds
    pop es
    xor ax, ax
    mov di, 0x0700
    mov cx, 0x0100
    rep stosb
    mov di, 0x1800
    mov cx, 0x0b37
    rep stosb
    mov di, 0x3000
    mov cx, 0x0400
    rep stosb
    mov di, 0x3600
    mov cx, 0x0500
    rep stosb
    mov di, attempt_cache
    mov cx, 0x0040
    rep stosb
    mov al, secure_handoff_a_page
    call .card_zero
    mov al, secure_handoff_b_page
    call .card_zero
    mov dx, LIVE_K15_BOOT_FAIL
    jmp dx
.card_zero:
    xor bx, bx
    mov bl, [ne_tx_start]
    push bx
    mov [ne_tx_start], al
    mov bx, [handoff_nic_base]
    mov si, 0x0700
    mov bp, 256
    mov dx, LIVE_K15_NE_BUF_LOAD
    call dx
    pop bx
    mov [ne_tx_start], bl
    ret
preconnect_transition_end:
preconnect_transition_len equ \
    preconnect_transition_end - preconnect_transition_source
preconnect_transition_failed equ \
    pre_sym_transition + \
    preconnect_transition_failed_source - preconnect_transition_source

; This second relocated block executes after the first HELLO controller has
; been read successfully.  Its template fits entirely before the retained
; failure scrub inside 0x0f00, so replacing the transition cannot strand
; target entropy if the later HELLO->crypto phase read fails.
preconnect_generic_installer_source:
    push ds
    pop es
    mov si, preconnect_generic_template_relocated
    mov di, pre_sym_transition
    mov cx, preconnect_generic_template_len
    rep movsb
    mov dx, 0x3400
    jmp dx
preconnect_generic_template_source:
    mov bx, 0x3000
    mov dx, res_load_phase
    call dx
    jc .failed
    push ds
    pop es
    mov si, 0x3000
    mov di, 0x3400
    mov cx, 256
    rep movsw
    mov dx, 0x3400
    jmp dx
.failed:
    mov dx, preconnect_transition_failed
    jmp dx
preconnect_generic_installer_end:
preconnect_generic_template_relocated equ \
    pre_generic_installer + \
    preconnect_generic_template_source - \
    preconnect_generic_installer_source
preconnect_generic_template_len equ \
    preconnect_generic_installer_end - preconnect_generic_template_source
preconnect_generic_installer_len equ \
    preconnect_generic_installer_end - \
    preconnect_generic_installer_source

%if preconnect_generic_installer_len > \
    (pre_sym_transition - pre_generic_installer)
%error "generic transition installer exceeds its retired low slot"
%endif
%if preconnect_generic_template_len > \
    (preconnect_transition_failed_source - preconnect_transition_source)
%error "generic transition would overwrite the retained failure scrub"
%endif

preconnect_keygen_text db 'offline keygen',13,10,0
preconnect_cache_text  db 'preflight cache',13,10,0
preconnect_live_text   db 'live connect',13,10,0

; Every controller-resident failure joins the already-relocated scrub.  It
; erases the exact retired KeyGen image and output/work ranges plus complete
; local/card entropy copies without touching this 0x2400 caller or the 0x3400
; boot services.
preconnect_failed:
    mov dx, preconnect_transition_failed
    jmp dx

%if ($ - $$) > 0x0200
%error "secure pre-connect controller exceeds its one-sector slot"
%endif

%elifdef LIVE_K15_HELLO_CONTROLLER

%ifndef LIVE_K15_CRYPTO_CONTROLLER_KEY
%error "LIVE_K15_CRYPTO_CONTROLLER_KEY is required"
%endif

org 0x3400

hello_entry_table             equ 0x1830
hello_fresh_begin_entry       equ hello_entry_table + (0 * 2)
hello_next_fragment_entry     equ hello_entry_table + (2 * 2)
hello_fragment_done_entry     equ hello_entry_table + (3 * 2)
hello_rewind_entry            equ hello_entry_table + (4 * 2)
hello_server_begin_entry      equ hello_entry_table + (5 * 2)
hello_server_feed_entry       equ hello_entry_table + (6 * 2)
hello_server_finish_entry     equ hello_entry_table + (7 * 2)
hello_cached_connect_entry    equ hello_entry_table + (9 * 2)
hello_zero_window_entry       equ hello_entry_table + (10 * 2)
hello_relocate_pending_entry  equ hello_entry_table + (12 * 2)
hello_prehashed_entry         equ hello_entry_table + (13 * 2)
res_tcp_ack                   equ 0x13a6
res_tcp_send                  equ 0x13bf
res_tcp_receive               equ 0x14ed
tcp_remote_ack                equ 0x06f1
tcp_rx_payload_ptr            equ 0x0fe2
tcp_rx_payload_len            equ 0x0fe4
timing_first_tick             equ 0x3ca0
timing_commit_tick            equ 0x3ca2
timing_tx_tick                equ 0x3ca4
timing_first_seen             equ 0x3ca6
hello_tx_stage                equ 0x2700
hello_tx_stage_end            equ 0x2800
poc_rx_frame_start            equ 0x0700
pre_sym_transition            equ 0x0f00

live_hello_controller:
    cld
    call word [hello_fresh_begin_entry]
    jc hello_fail

    ; Build and consume the complete deterministic ClientHello once before
    ; opening a socket.  This first iterator pass performs all transcript
    ; SHA-256 work without transmitting.  hello_rewind preserves that digest
    ; and disables hashing for the byte-identical replay.
.prehash:
    call word [hello_next_fragment_entry]
    jc hello_fail
    or ax, ax
    jz .rewind
    call word [hello_prehashed_entry]
    jc hello_fail
    jmp short .prehash
.rewind:
    call word [hello_rewind_entry]
    jc hello_fail

    ; Prebuild the first replay fragment while the cached connection helper
    ; is still offline.  Its SYN/SYN-ACK frame aliases 0x0700, so retain the
    ; complete prefix in the checked 0x2700 staging tail before connecting.
    call word [hello_next_fragment_entry]
    jc hello_fail
    cmp ax, 1
    jne hello_fail
    cmp si, poc_rx_frame_start
    jne hello_fail
    cmp cx, hello_tx_stage_end - hello_tx_stage
    ja hello_fail
    push es
    push ds
    pop es
    push cx
    mov di, hello_tx_stage
    rep movsb
    pop cx
    pop es
    mov si, hello_tx_stage
    call word [hello_relocate_pending_entry]
    jc hello_fail

    call word [hello_cached_connect_entry]
    jc hello_fail

    ; Re-read the still-pending iterator result after SYN/SYN-ACK overwrote
    ; 0x0700.  The relocation ABI, rather than a controller literal, owns both
    ; the staged pointer and exact length.
    call word [hello_next_fragment_entry]
    jc hello_fail
    cmp ax, 1
    jne hello_fail
    call res_tcp_send
    jc hello_fail
    call word [hello_fragment_done_entry]
    jc hello_fail

.send_fragment:
    call word [hello_next_fragment_entry]
    jc hello_fail
    or ax, ax
    jz .sent
    call res_tcp_send
    jc hello_fail
    call word [hello_fragment_done_entry]
    jc hello_fail
    jmp short .send_fragment

.sent:
    call word [hello_server_begin_entry]
    jc hello_fail
    mov byte [hello_header_pos], 0
    mov word [hello_body_remaining], 0
    mov byte [timing_first_seen], 0

.receive:
    call res_tcp_receive
    jc hello_fail
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]
    cmp byte [timing_first_seen], 0
    jne .consume
    mov ax, [0x046c]
    mov [timing_first_tick], ax
    mov byte [timing_first_seen], 1

.consume:
    or cx, cx
    jz .ack_more
    cmp byte [hello_header_pos], 5
    je .body
    xor bx, bx
    mov bl, [hello_header_pos]
    mov al, [si]
    mov [hello_record_header + bx], al
    inc si
    dec cx
    inc byte [hello_header_pos]
    cmp byte [hello_header_pos], 5
    jne .consume
    cmp byte [hello_record_header], 0x16
    jne hello_fail
    cmp word [hello_record_header + 1], 0x0303
    jne hello_fail
    cmp word [hello_record_header + 3], 0xba04
    jne hello_fail
    mov word [hello_body_remaining], 1210
    jmp short .consume

.body:
    mov ax, [hello_body_remaining]
    or ax, ax
    jz .boundary
    mov dx, cx
    cmp cx, ax
    jbe .feed
    mov cx, ax
.feed:
    mov [hello_feed_len], cx
    push dx
    call word [hello_server_feed_entry]
    pop dx
    jc hello_fail
    mov ax, [hello_feed_len]
    sub dx, ax
    mov cx, dx
    sub [hello_body_remaining], ax
    cmp word [hello_body_remaining], 0
    jne .ack_more

.boundary:
    ; tcp_receive_payload has advanced ACK across the complete TCP segment.
    ; Rewind only a coalesced protected tail, so the zero-window ACK lands on
    ; the exact first byte after ServerHello.
    or cx, cx
    jz .zero_window
    mov di, tcp_remote_ack + 3
    sub [di], cl
    sbb [di - 1], ch
    sbb byte [di - 2], 0
    sbb byte [di - 3], 0
.zero_window:
    call word [hello_zero_window_entry]
    jc hello_fail
    call word [hello_server_finish_entry]
    jc hello_fail
    mov ax, [0x046c]
    mov [timing_commit_tick], ax
    mov ax, LIVE_K15_CRYPTO_CONTROLLER_KEY
    jmp pre_sym_transition

.ack_more:
    call res_tcp_ack
    jc hello_fail
    jmp .receive

hello_fail:
    mov si, hello_fail_text
    call hello_emit
.halt:
    sti
    hlt
    jmp short .halt

hello_emit:
    mov dx, 0x03fb
    mov al, 0x80
    out dx, al
    mov dx, 0x03f8
    mov al, 12
    out dx, al
    inc dx
    xor al, al
    out dx, al
    mov dx, 0x03fb
    mov al, 0x03
    out dx, al
    mov dx, 0x03fc
    mov al, 0x03
    out dx, al
.next:
    lodsb
    or al, al
    jz .done
    push ax
    push cx
    mov ah, 0x0e
    xor bh, bh
    int 0x10
    mov dx, 0x03fd
    mov cx, 0xffff
.wait:
    in al, dx
    test al, 0x20
    jnz .ready
    loop .wait
    jmp short .restore
.ready:
    mov dx, 0x03f8
    pop cx
    pop ax
    out dx, al
    jmp short .next
.restore:
    pop cx
    pop ax
    jmp short .next
.done:
    ret

hello_record_header  times 5 db 0
hello_header_pos     db 0
hello_body_remaining dw 0
hello_feed_len       dw 0
hello_fail_text       db 13,10,'FAIL',13,10,'RESULT',13,10,0

%elifdef LIVE_K15_CRYPTO_CONTROLLER

%ifndef LIVE_K15_CANDIDATE_KEY
%error "live phase keys are required"
%endif
%ifndef LIVE_K15_SYM_RESTORE_KEY
%error "live phase keys are required"
%endif
%ifndef LIVE_K15_PROTECTED_CONTROLLER_KEY
%error "live phase keys are required"
%endif
%ifndef LIVE_K15_DELTA_LOADER_PATH
%error "LIVE_K15_DELTA_LOADER_PATH is required"
%endif
%ifndef LIVE_K15_CORE_START_LBA
%error "LIVE_K15_CORE_START_LBA is required"
%endif

org 0x3400

res_load_phase                 equ 0x10c4
res_tcp_ack                    equ 0x13a6
res_build_tcp_frame            equ 0x13e2
res_nic_vt_receive             equ 0x15e1
res_nic_vt_transmit            equ 0x15df
ne_rx_sample_count             equ 0x06d5
ne_rx_read_limit               equ 0x06d7
tcp_remote_ack                 equ 0x06f1
ne_tx_frame                    equ 0x0700
tcp_window_word                equ ne_tx_frame + 34 + 14
tcp_checksum_word              equ ne_tx_frame + 34 + 16
candidate_k_prime              equ 0x3b9c
sym_entry_table                equ 0x1820
sym_init_entry                 equ sym_entry_table + (0 * 2)
sym_critical_entry             equ sym_entry_table + (3 * 2)
sym_import_entry               equ sym_entry_table + (15 * 2)
sym_input_shared_secret        equ 0x3600
live_delta_load_entry          equ 0x0f00

live_crypto_controller:
    cld
    ; The product's 16 KiB phase loader issues one BIOS call per sector.
    ; Copy the already-gated track-batched trampoline out of this controller
    ; before sym_init reclaims the source tail.  Its 0x0f00 destination is
    ; live only after HELLO commits: DNS/file scratch is dead, while the
    ; resident TCP tail begins above the loader at 0x0fe2.
    push ds
    pop es
    mov si, live_delta_loader_source
    mov di, live_delta_load_entry
    mov cx, (live_delta_loader_end - live_delta_loader_source) / 2
    rep movsw

    mov ax, LIVE_K15_CANDIDATE_KEY
    mov bx, 0x1800
    call live_batch_phase
    jc live_persist_fail
    call 0x1800

    ; sym_init clears retained high state through candidate K' at 0x3b9c.
    ; Preserve K' temporarily in the now-dead first 32 bytes of raw c.  This
    ; lies below the later 0x0900 protected controller.
    push ds
    pop es
    mov si, candidate_k_prime
    mov di, 0x08c0
    mov cx, 16
    rep movsw

    mov ax, LIVE_K15_SYM_RESTORE_KEY
    mov bx, 0x1800
    call live_batch_phase
    jc live_persist_fail
    call word [sym_init_entry]
    jc live_persist_fail
    push ds
    pop es
    mov si, 0x08c0
    mov di, sym_input_shared_secret
    mov cx, 16
    rep movsw
    xor ax, ax
    mov di, 0x08c0
    mov cx, 16
    rep stosw
    call word [sym_import_entry]
    jc live_persist_fail
    call word [sym_critical_entry]
    jc live_persist_fail

    ; Candidate c at 08c0..0cff is now dead, and the transcript import has
    ; consumed 0d00..0daa.  Install the complete protected-flight controller
    ; into the two-sector 0900..0cff slot while the peer still sees a zero
    ; window.  In particular, never load or copy another controller through
    ; K14's 3400..35ff extension after sym_init has made 3510..355d live.
    mov ax, LIVE_K15_PROTECTED_CONTROLLER_KEY
    mov bx, 0x0900
    call live_batch_phase
    jc live_persist_fail

    ; Drop unacknowledged copies that arrived while the peer saw a zero
    ; window.  Then advertise the ordinary resident 256-byte window without
    ; changing seq/ack, causing retransmission from the exact SH boundary.
    mov word [ne_rx_read_limit], 438
    mov cx, 256
.flush:
    push cx
    call word [res_nic_vt_receive]
    pop cx
    jc live_persist_fail
    cmp word [ne_rx_sample_count], 0
    je .window_update
    loop .flush
    jmp live_persist_fail
.window_update:
    call res_tcp_ack
    jc live_persist_fail
    jmp 0x0900

live_batch_phase:
    ; Convert the resident phase key (AH=count, AL=file-sector offset) to
    ; delta_load's absolute-LBA AX, word-count CX ABI.
    mov cl, ah
    xor ch, ch
    xor ah, ah
    add ax, LIVE_K15_CORE_START_LBA
    jmp live_delta_load_entry

live_crypto_controller_code_end:
live_delta_loader_source:
    incbin LIVE_K15_DELTA_LOADER_PATH
live_delta_loader_end:

%if (live_delta_loader_end - live_delta_loader_source) & 1
%error "live delta loader copy requires an even byte count"
%endif

; sym_init owns 0x3510..0x355c.  Keep the post-Finished scheduler and
; diagnostics in the untouched tail of the K14 extension, never in the
; product's 0x3e40 arena/context pool.
times (0x355d - 0x3400) - ($ - $$) db 0
live_persist_services_start:

live_persist_transition:
    ; AX=phase key, BX=destination.  delta_load preserves BX.
    call live_batch_phase
    jc live_persist_fail
    jmp bx

live_persist_zero_window:
    ; Build the ordinary ACK, then change its advertised 0x0100 wire window to
    ; zero and repair the one's-complement checksum exactly as HELLO does.
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

live_persist_emit:
    call live_persist_serial_init
.next:
    lodsb
    or al, al
    jz .done
    call live_persist_putchar
    jmp short .next
.done:
    ret

live_persist_putchar:
    push ax
    push bx
    push cx
    push dx
    mov bl, al
    mov ah, 0x0e
    xor bh, bh
    int 0x10
    mov dx, 0x03fd
    mov cx, 0xffff
.wait:
    in al, dx
    test al, 0x20
    jnz .ready
    loop .wait
    jmp short .restore
.ready:
    mov dx, 0x03f8
    mov al, bl
    out dx, al
.restore:
    pop dx
    pop cx
    pop bx
    pop ax
    ret

live_persist_serial_init:
    mov dx, 0x03fb
    mov al, 0x80
    out dx, al
    mov dx, 0x03f8
    mov al, 12
    out dx, al
    inc dx
    xor al, al
    out dx, al
    mov dx, 0x03fb
    mov al, 0x03
    out dx, al
    mov dx, 0x03fc
    mov al, 0x03
    out dx, al
    ret

live_persist_fail:
    mov si, live_persist_fail_text
    call live_persist_emit
.halt:
    sti
    hlt
    jmp short .halt

live_persist_fail_text db 13,10,'FAIL',13,10,'RESULT',13,10,0
live_persist_services_end:

%if ($ - $$) > 0x0200
%error "persistent post-Finished services exceed the K14 extension"
%endif

%elifdef LIVE_K15_SECURE_CRYPTO_CONTROLLER

%ifndef LIVE_K15_CANDIDATE_KEY
%error "secure crypto controller requires the candidate phase"
%endif
%ifndef LIVE_K15_DELTA_LOADER_PATH
%error "secure crypto controller requires the delta loader image"
%endif
%ifndef LIVE_K15_CORE_START_LBA
%error "secure crypto controller requires the core LBA"
%endif
%ifndef LIVE_K15_NE_BUF_LOAD
%error "secure crypto controller requires the guarded NE2000 DMA-write leaf"
%endif
%ifndef LIVE_K15_NE_BUF_READ
%error "secure crypto controller requires the guarded NE2000 DMA-read leaf"
%endif
%ifndef LIVE_K15_SCRUB_CONTROLLER_KEY
%error "secure crypto controller requires the cold scrub phase"
%endif

org 0x3400

res_load_phase                 equ 0x10c4
res_build_tcp_frame            equ 0x13e2
res_nic_vt_transmit            equ 0x15df
handoff_nic_base               equ 0x060e
handoff_nic_family             equ 0x0610
family_ne2000                  equ 2
ne_tx_start                    equ 0x06cb
ne_rx_stop                     equ 0x06cd
tcp_remote_ack                 equ 0x06f1
ne_tx_frame                    equ 0x0700
tcp_window_word                equ ne_tx_frame + 34 + 14
tcp_checksum_word              equ ne_tx_frame + 34 + 16
secure_c_card_page             equ 0x79
secure_handoff_a_page          equ 0x7e
secure_handoff_b_page          equ 0x7f
secure_handoff                 equ 0x0dab
secure_transition              equ 0x0e30
live_delta_load_entry          equ 0x0f00

live_secure_crypto_controller:
    cld
    cmp byte [handoff_nic_family], family_ne2000
    jne .invalid_nic
    cmp byte [ne_rx_stop], 0x73
    je .valid_nic
.invalid_nic:
    jmp live_secure_persist_fail
.valid_nic:

    ; Install the already-gated critical loader while HELLO's low transcript
    ; handoff remains intact below it.
    push ds
    pop es
    mov si, live_secure_delta_loader_source
    mov di, live_delta_load_entry
    mov cx, (live_secure_delta_loader_end - live_secure_delta_loader_source) / 2
    rep movsw

    ; Preserve the actual live ServerHello ciphertext before the candidate
    ; and symmetric phases reclaim its 0x08c0 low-object window.
    mov al, secure_c_card_page
    mov si, 0x08c0
    mov bp, 1088
    call live_secure_card_write
    jc live_secure_persist_fail

    mov ax, LIVE_K15_CANDIDATE_KEY
    mov bx, 0x1800
    call live_secure_batch_phase
    jc live_secure_persist_fail
    call 0x1800

    ; Freeze two independent copies of m' || G(m'||H(ek)) || z in card RAM
    ; before sym_init converts the high candidate cache into TLS state.
    push ds
    pop es
    mov si, 0x3a40
    mov di, secure_handoff
    mov cx, 16
    rep movsw
    mov si, 0x3b9c
    mov cx, 48
    rep movsw
    mov al, secure_handoff_a_page
    mov si, secure_handoff
    mov bp, 128
    call live_secure_card_write
    jc live_secure_persist_fail
    mov al, secure_handoff_b_page
    mov si, secure_handoff
    mov bp, 128
    call live_secure_card_write
    jc live_secure_persist_fail

    ; Execute outside the destination while the guarded driver leaf replaces
    ; only 0x3400..0x34ff.  The secure controller's persistent services at
    ; 0x355d+ remain resident and the intervening bytes are retired.
live_secure_transition_prepare:
    push ds
    pop es
    mov si, live_secure_transition_source
    mov di, secure_transition
    mov cx, live_secure_transition_len
    rep movsb
    jmp secure_transition

live_secure_batch_phase:
    mov cl, ah
    xor ch, ch
    xor ah, ah
    add ax, LIVE_K15_CORE_START_LBA
    jmp live_delta_load_entry

; AL=card page, SI=source, BP=count.  Restore ordinary TX page without
; disturbing the remote-DMA leaf's carry result.
live_secure_card_write:
    mov ah, [ne_tx_start]
    push ax
    mov [ne_tx_start], al
    mov bx, [handoff_nic_base]
    call LIVE_K15_NE_BUF_LOAD
    pop ax
    mov [ne_tx_start], ah
    ret

live_secure_transition_source:
    mov bx, 0x7300
    mov cx, 256
    mov di, 0x3400
    mov dx, LIVE_K15_NE_BUF_READ
    call dx
    jc .failed
    mov dx, 0x3400
    jmp dx
.failed:
    mov dx, live_secure_persist_fail
    jmp dx
live_secure_transition_end:
live_secure_transition_len equ \
    live_secure_transition_end - live_secure_transition_source

live_secure_crypto_controller_code_end:
live_secure_delta_loader_source:
    incbin LIVE_K15_DELTA_LOADER_PATH
live_secure_delta_loader_end:

%if (live_secure_delta_loader_end - live_secure_delta_loader_source) & 1
%error "secure delta loader copy requires an even byte count"
%endif

times (0x355d - 0x3400) - ($ - $$) db 0
live_secure_persist_services_start:

; Post-deadline transitions use the immutable resident phase loader.  The
; critical candidate/symmetric/protected loads above still use delta_load.
live_secure_persist_transition:
    call res_load_phase
    jc live_secure_persist_fail
    jmp bx

live_secure_persist_zero_window:
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

live_secure_persist_emit:
    call live_secure_persist_serial_init
.next:
    lodsb
    or al, al
    jz .done
    call live_secure_persist_putchar
    jmp short .next
.done:
    ret

live_secure_persist_putchar:
    push ax
    push bx
    push cx
    push dx
    mov bl, al
    mov ah, 0x0e
    xor bh, bh
    int 0x10
    mov dx, 0x03fd
    mov cx, 0xffff
.wait:
    in al, dx
    test al, 0x20
    jnz .ready
    loop .wait
    jmp short .restore
.ready:
    mov dx, 0x03f8
    mov al, bl
    out dx, al
.restore:
    pop dx
    pop cx
    pop bx
    pop ax
    ret

live_secure_persist_serial_init:
    mov dx, 0x03fb
    mov al, 0x80
    out dx, al
    mov dx, 0x03f8
    mov al, 12
    out dx, al
    inc dx
    xor al, al
    out dx, al
    mov dx, 0x03fb
    mov al, 0x03
    out dx, al
    mov dx, 0x03fc
    mov al, 0x03
    out dx, al
    ret

live_secure_persist_fail:
    ; Once a secret handoff may have been staged, make a best-effort cold
    ; transition to the scrub controller.  A floppy/load failure still fails
    ; closed through the local marker path, but cannot promise card erasure;
    ; every later secure boot therefore clears both vault pages before any
    ; possible read.
    mov ax, LIVE_K15_SCRUB_CONTROLLER_KEY
    mov bx, 0x2400
    call res_load_phase
    jc .emit
    jmp bx
.emit:
    mov si, live_secure_persist_fail_text
    call live_secure_persist_emit
.halt:
    cli
    hlt

live_secure_persist_fail_text db 13,10,'FAIL',13,10,'RESULT',13,10,0
live_secure_persist_services_end:

%if ($ - $$) > 0x0200
%error "secure crypto controller exceeds the K14 extension"
%endif

%elifdef LIVE_K15_SECURE_SYM_CONTROLLER

%ifndef LIVE_K15_SYM_RESTORE_KEY
%error "secure symmetric controller requires the restore phase"
%endif
%ifndef LIVE_K15_PROTECTED_CONTROLLER_KEY
%error "secure symmetric controller requires the protected controller phase"
%endif
%ifndef LIVE_K15_CORE_START_LBA
%error "secure symmetric controller requires the core LBA"
%endif
%ifndef LIVE_K15_PERSIST_FAIL
%error "secure symmetric controller requires the persistent fail service"
%endif

org 0x3400

res_tcp_ack                    equ 0x13a6
res_nic_vt_receive             equ 0x15e1
ne_rx_sample_count             equ 0x06d5
ne_rx_read_limit               equ 0x06d7
candidate_k_prime              equ 0x3b9c
sym_entry_table                equ 0x1820
sym_init_entry                 equ sym_entry_table + (0 * 2)
sym_critical_entry             equ sym_entry_table + (3 * 2)
sym_import_entry               equ sym_entry_table + (15 * 2)
sym_input_shared_secret        equ 0x3600
live_delta_load_entry          equ 0x0f00

live_secure_sym_controller:
    cld
    ; c is already card-resident.  Preserve provisional K' in its retired low
    ; prefix across sym_init exactly as the original controller does.
    push ds
    pop es
    mov si, candidate_k_prime
    mov di, 0x08c0
    mov cx, 16
    rep movsw

    mov ax, LIVE_K15_SYM_RESTORE_KEY
    mov bx, 0x1800
    call live_secure_sym_batch_phase
    jc LIVE_K15_PERSIST_FAIL
    call word [sym_init_entry]
    jc LIVE_K15_PERSIST_FAIL
    push ds
    pop es
    mov si, 0x08c0
    mov di, sym_input_shared_secret
    mov cx, 16
    rep movsw
    xor ax, ax
    mov di, 0x08c0
    mov cx, 16
    rep stosw
    call word [sym_import_entry]
    jc LIVE_K15_PERSIST_FAIL
    call word [sym_critical_entry]
    jc LIVE_K15_PERSIST_FAIL

    mov ax, LIVE_K15_PROTECTED_CONTROLLER_KEY
    mov bx, 0x0900
    call live_secure_sym_batch_phase
    jc LIVE_K15_PERSIST_FAIL

live_secure_sym_nic_prepare:
    ; Symmetric primitives are not required to preserve ES.  The NE receive
    ; leaf scatters through ES:DI, so normalize before touching the queued
    ; protected flight.
    push ds
    pop es
    mov word [ne_rx_read_limit], 438
    mov cx, 256
.flush:
    push cx
    call word [res_nic_vt_receive]
    pop cx
    jc LIVE_K15_PERSIST_FAIL
    cmp word [ne_rx_sample_count], 0
    je .window_update
    loop .flush
    jmp LIVE_K15_PERSIST_FAIL
.window_update:
    call res_tcp_ack
    jc LIVE_K15_PERSIST_FAIL
live_secure_sym_protected_handoff:
    ; Keep the same segment contract at the low-controller boundary even if
    ; packet construction changed ES while advertising the new window.
    push ds
    pop es
    jmp 0x0900

live_secure_sym_batch_phase:
    mov cl, ah
    xor ch, ch
    xor ah, ah
    add ax, LIVE_K15_CORE_START_LBA
    jmp live_delta_load_entry

live_secure_sym_controller_code_end:
times 0x0100 - ($ - $$) db 0

%elifdef LIVE_K15_PROTECTED_CONTROLLER

%ifndef LIVE_K15_PERSIST_FAIL
%error "persistent service addresses are required"
%endif
%ifndef LIVE_K15_PERSIST_EMIT
%error "persistent service addresses are required"
%endif
%ifndef LIVE_K15_PERSIST_ZERO_WINDOW
%error "persistent service addresses are required"
%endif
%ifndef LIVE_K15_PERSIST_TRANSITION
%error "persistent service addresses are required"
%endif
%ifndef LIVE_K15_POST_CONTROLLER_KEY
%error "post-Finished controller key is required"
%endif
%ifdef LIVE_K15_IDENTITY_CAPTURE
%ifndef LIVE_K15_SYM_TRANSCRIPT_SNAPSHOT
%error "identity capture requires symmetric SHA/transcript addresses"
%endif
%ifndef LIVE_K15_SHA256_INIT
%error "identity capture requires symmetric SHA/transcript addresses"
%endif
%ifndef LIVE_K15_SHA256_UPDATE
%error "identity capture requires symmetric SHA/transcript addresses"
%endif
%ifndef LIVE_K15_SHA256_FINISH
%error "identity capture requires symmetric SHA/transcript addresses"
%endif
%ifndef LIVE_K15_SHA256_SAVE_CONTEXT
%error "identity capture requires symmetric SHA/transcript addresses"
%endif
%ifndef LIVE_K15_SHA256_RESTORE_CONTEXT
%error "identity capture requires symmetric SHA/transcript addresses"
%endif
%endif

org 0x0900

res_wait_ticks                 equ 0x11e5
res_tcp_ack                    equ 0x13a6
res_tcp_send                   equ 0x13bf
res_tcp_receive                equ 0x14ed
res_parse_tcp_payload          equ 0x1522
res_nic_vt_receive             equ 0x15e1
res_nic_vt_rx_fallback         equ 0x15e3
tcp_local_seq                  equ 0x06ed
ne_rx_sample_count             equ 0x06d5
tcp_rx_payload_ptr             equ 0x0fe2
tcp_rx_payload_len             equ 0x0fe4
timing_first_tick              equ 0x3ca0
timing_commit_tick             equ 0x3ca2
timing_finished_return         equ 0x3ca4
record_header                  equ 0x3c30
record_header_pos              equ record_header + 5
record_state                   equ record_header_pos + 1
record_wire_remaining          equ record_state + 1
record_cipher_remaining        equ record_wire_remaining + 2
record_plain_offset            equ record_cipher_remaining + 2
record_finished_prefix         equ record_plain_offset + 2
record_tag_pos                 equ record_finished_prefix + 2
finished_tail_count            equ record_tag_pos + 1
chunk_ptr                      equ finished_tail_count + 1
chunk_len                      equ chunk_ptr + 2
record_shape_flags             equ chunk_len + 2
record_shape_ccs               equ 0x01
record_shape_encrypted         equ 0x02
sym_entry_table                equ 0x1820
sym_transcript_update_entry    equ sym_entry_table + (2 * 2)
sym_hs_open_begin_entry        equ sym_entry_table + (4 * 2)
sym_open_chunk_entry           equ sym_entry_table + (6 * 2)
sym_open_finish_entry          equ sym_entry_table + (7 * 2)
sym_verify_finish_entry        equ sym_entry_table + (8 * 2)
sym_build_finish_entry         equ sym_entry_table + (9 * 2)
sym_build_head_entry           equ sym_entry_table + (11 * 2)
sym_derive_client_app_entry    equ sym_entry_table + (16 * 2)
sym_received_finish            equ 0x38f0
sym_received_tag               equ 0x3910
sym_io                         equ 0x39a0
deadline_ticks                 equ 273
%ifdef LIVE_K15_IDENTITY_CAPTURE
; The protected controller is three sectors only in the identity build.
; Its executable must end below this retired-handshake scratch.  The final
; 117 plaintext bytes always comprise a suffix of CompressedCertificate,
; the complete bounded CertificateVerify, server Finished, and inner type.
identity_tail                  equ 0x0e00
identity_tail_len              equ 117
identity_cv_end                equ identity_tail + 80
identity_cert_hash             equ 0x0e80
identity_spaces                equ 0x0ea0
identity_cv_ptr                equ 0x0ec0
identity_cv_der_len            equ 0x0ec2
auth_input_digest              equ 0x3c30
auth_input_signature_len       equ 0x3c50
auth_input_signature           equ 0x3c52
auth_input_signature_max       equ 72
auth_output_status             equ 0x3c9a
flight_tail                    equ identity_tail
flight_tail_len                equ identity_tail_len
%else
flight_tail_len                equ 37
%endif

live_protected_controller:
    cld
    mov word [record_header_pos], 0
    mov byte [record_shape_flags], 0

.receive:
    call res_tcp_receive
    jc LIVE_K15_PERSIST_FAIL
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]

.consume:
    or cx, cx
    jz .ack_more
    cmp byte [record_state], 0
    jne .record_body
    xor bx, bx
    mov bl, [record_header_pos]
    mov al, [si]
    mov [record_header + bx], al
    inc si
    dec cx
    inc byte [record_header_pos]
    cmp byte [record_header_pos], 5
    jne .consume
    push si
    push cx
    call start_record
    pop cx
    pop si
    jc LIVE_K15_PERSIST_FAIL
    jmp short .consume

.record_body:
    cmp byte [record_state], 1
    je .ccs
    cmp byte [record_state], 2
    jne LIVE_K15_PERSIST_FAIL
    mov ax, [record_cipher_remaining]
    or ax, ax
    jz .tag
    mov dx, cx
    cmp cx, ax
    jbe .cipher_chunk
    mov cx, ax
.cipher_chunk:
    mov [chunk_ptr], si
    mov [chunk_len], cx
    push si
    push dx
    call word [sym_open_chunk_entry]
    pop dx
    pop si
    jc LIVE_K15_PERSIST_FAIL
    call capture_flight_tail
    jc LIVE_K15_PERSIST_FAIL
    mov ax, [chunk_len]
    add si, ax
    sub dx, ax
    mov cx, dx
    sub [record_cipher_remaining], ax
    add [record_plain_offset], ax
    jmp .consume

.tag:
    xor bx, bx
    mov bl, [record_tag_pos]
    mov dx, 16
    sub dx, bx
    cmp cx, dx
    jbe .tag_count_ready
    mov cx, dx
.tag_count_ready:
    push es
    push ds
    pop es
    mov di, sym_received_tag
    add di, bx
    mov ax, cx
    rep movsb
    pop es
    add [record_tag_pos], al
    mov cx, [tcp_rx_payload_len]
    ; Recover the unconsumed count from the current frame endpoint.  The
    ; record is expected to end at the frame tail; any additional bytes are a
    ; strict-shape failure rather than silently ACKing unknown handshake data.
    mov bx, [tcp_rx_payload_ptr]
    add bx, cx
    sub bx, si
    mov cx, bx
    cmp byte [record_tag_pos], 16
    jne .consume
    or cx, cx
    jnz LIVE_K15_PERSIST_FAIL
    cmp byte [finished_tail_count], flight_tail_len
    jne LIVE_K15_PERSIST_FAIL
    mov si, sym_received_tag
    call word [sym_open_finish_entry]
    jc LIVE_K15_PERSIST_FAIL
    call commit_finished_tail
    jc LIVE_K15_PERSIST_FAIL
    call res_tcp_ack
    jc LIVE_K15_PERSIST_FAIL
    jmp finish_and_report

.ccs:
    cmp byte [si], 1
    jne LIVE_K15_PERSIST_FAIL
    inc si
    dec cx
    dec word [record_wire_remaining]
    jnz LIVE_K15_PERSIST_FAIL
    mov word [record_header_pos], 0
    jmp .consume

.ack_more:
    call res_tcp_ack
    jc LIVE_K15_PERSIST_FAIL
    jmp .receive

start_record:
    cmp word [record_header + 1], 0x0303
    jne .failed
    xor ax, ax
    mov ah, [record_header + 3]
    mov al, [record_header + 4]
    mov [record_wire_remaining], ax
    cmp byte [record_header], 0x14
    jne .encrypted
    test byte [record_shape_flags], record_shape_ccs | record_shape_encrypted
    jnz .failed
    cmp ax, 1
    jne .failed
    or byte [record_shape_flags], record_shape_ccs
    mov byte [record_state], 1
    clc
    ret
.encrypted:
    cmp byte [record_header], 0x17
    jne .failed
    test byte [record_shape_flags], record_shape_encrypted
    jnz .failed
    cmp ax, 16 + flight_tail_len
    jb .failed
    sub ax, 16
    cmp ax, 4096
    ja .failed
    mov [record_cipher_remaining], ax
    sub ax, flight_tail_len
    mov [record_finished_prefix], ax
    mov word [record_plain_offset], 0
    mov byte [record_tag_pos], 0
    mov byte [finished_tail_count], 0
    push es
    push ds
    pop es
    mov si, record_header
    mov di, sym_io
    mov cx, 5
    rep movsb
    pop es
    mov ax, [record_finished_prefix]
    call word [sym_hs_open_begin_entry]
    jc .failed
    or byte [record_shape_flags], record_shape_encrypted
    mov byte [record_state], 2
    clc
    ret
.failed:
    stc
    ret

capture_flight_tail:
    push ax
    push bx
    push cx
    push dx
    push di
    push si
    mov si, [chunk_ptr]
    mov cx, [chunk_len]
    mov bx, [record_plain_offset]
.byte:
    cmp bx, [record_finished_prefix]
    jb .next
    mov dx, bx
    sub dx, [record_finished_prefix]
    cmp dx, flight_tail_len
    jae .failed
    mov di, flight_tail
    add di, dx
    mov al, [si]
    mov [di], al
.count:
    inc byte [finished_tail_count]
.next:
    inc si
    inc bx
    loop .byte
    clc
    jmp short .done
.failed:
    stc
.done:
    pop si
    pop di
    pop dx
    pop cx
    pop bx
    pop ax
    ret

finished_header db 0x14,0x00,0x00,0x20
%ifndef LIVE_K15_IDENTITY_CAPTURE
flight_tail times flight_tail_len db 0
%endif

; The streaming open API has now authenticated the complete record.  Only at
; this point may provisional bytes control flow or enter retained Finished
; state.
commit_finished_tail:
%ifdef LIVE_K15_IDENTITY_CAPTURE
    jmp commit_identity_tail
%else
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, flight_tail
    mov di, finished_header
    mov cx, 4
    repe cmpsb
    jne .failed
    cmp byte [flight_tail + 36], 0x16
    jne .failed
    mov si, flight_tail + 4
    mov di, sym_received_finish
    mov cx, 32
    rep movsb
    clc
    jmp short .done
.failed:
    stc
.done:
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret
%endif

%ifdef LIVE_K15_IDENTITY_CAPTURE
; Parse only after the enclosing AEAD tag has authenticated all provisional
; plaintext.  CertificateVerify must end exactly 37 bytes before the record
; end, so its bounded header can be found without trusting Certificate
; compression lengths.  The later P-256 phase still performs strict DER and
; scalar checks.
commit_identity_tail:
    xor bx, bx
.find_cv:
    cmp bx, 64
    ja .failed
    mov si, identity_tail
    add si, bx
    cmp byte [si], 0x0f
    jne .next
    cmp word [si + 1], 0
    jne .next
    xor ax, ax
    mov al, [si + 3]                 ; bounded one-byte body length
    mov dx, ax
    add ax, bx
    add ax, 4
    cmp ax, 80
    jne .next
    cmp word [si + 4], 0x0304        ; ecdsa_secp256r1_sha256
    jne .next
    cmp byte [si + 6], 0
    jne .next
    xor ax, ax
    mov al, [si + 7]
    cmp ax, 8
    jb .next
    cmp ax, auth_input_signature_max
    ja .next
    mov cx, dx
    sub cx, 4
    cmp ax, cx
    jne .next
    mov dx, ax                       ; exact strict-DER byte count
    jmp short .found
.next:
    inc bx
    jmp short .find_cv

.found:
    mov [identity_cv_ptr], si
    mov [identity_cv_der_len], dx
    ; Complete the transcript through CompressedCertificate, snapshot it for
    ; the CertificateVerify signed input, then append the complete CV message.
    mov si, identity_tail
    mov cx, bx
    call word [sym_transcript_update_entry]
    jc .failed
    mov di, identity_cert_hash
    call LIVE_K15_SYM_TRANSCRIPT_SNAPSHOT
    jc .failed
    ; The SHA update ABI deliberately does not preserve BX.  Recover this
    ; authenticated boundary from the frozen pointer instead of retaining the
    ; parser offset across the non-empty compressed-certificate suffix update.
    mov si, [identity_cv_ptr]
    nop
    mov cx, identity_cv_end
    sub cx, si
    call word [sym_transcript_update_entry]
    jc .failed

    ; Freeze the compact post-socket P-256 ABI before reusing SHA work.
    mov byte [auth_output_status], 0
    mov dx, [identity_cv_der_len]
    mov [auth_input_signature_len], dx
    push ds
    pop es
    xor ax, ax
    mov di, auth_input_signature
    mov cx, auth_input_signature_max / 2
    rep stosw
    mov dx, [identity_cv_der_len]
    mov si, [identity_cv_ptr]
    add si, 8
    mov di, auth_input_signature
    mov cx, dx
    rep movsb

    ; Hash RFC 8446's CertificateVerify signed content while preserving the
    ; live transcript-through-CV context needed by server Finished.
    call LIVE_K15_SHA256_SAVE_CONTEXT
    call LIVE_K15_SHA256_INIT
    push ds
    pop es
    mov al, 0x20
    mov di, identity_spaces
    mov cx, 32
    rep stosb
    mov si, identity_spaces
    mov cx, 32
    call LIVE_K15_SHA256_UPDATE
    mov si, identity_spaces
    mov cx, 32
    call LIVE_K15_SHA256_UPDATE
    mov si, identity_cv_context
    mov cx, identity_cv_context_end - identity_cv_context
    call LIVE_K15_SHA256_UPDATE
    mov si, identity_cert_hash
    mov cx, 32
    call LIVE_K15_SHA256_UPDATE
    mov di, auth_input_digest
    call LIVE_K15_SHA256_FINISH
    call LIVE_K15_SHA256_RESTORE_CONTEXT

    ; Finished and the TLSInnerPlaintext type have fixed positions after the
    ; CV end.  Publish verify_data only after all structural checks succeeded.
    mov si, identity_cv_end
    mov di, finished_header
    mov cx, 4
    repe cmpsb
    jne .failed
    cmp byte [identity_cv_end + 36], 0x16
    jne .failed
    mov si, identity_cv_end + 4
    mov di, sym_received_finish
    mov cx, 32
    rep movsb
    clc
    ret
.failed:
    stc
    ret

; Includes the required zero separator as its final byte.
identity_cv_context db 'TLS 1.3, server CertificateVerify',0
identity_cv_context_end:
%endif

finish_and_report:
    call word [sym_verify_finish_entry]
    jc LIVE_K15_PERSIST_FAIL
    call word [sym_build_finish_entry]
    jc LIVE_K15_PERSIST_FAIL
    cmp ax, 58
    jne LIVE_K15_PERSIST_FAIL
    ; The record-tail check above rejects bytes coalesced into the frame that
    ; completed the encrypted record.  Also drain the NIC's already-queued
    ; frames before sending Finished: any payload at the exact next TCP
    ; sequence is a second TLS record (or raw trailing bytes) and therefore a
    ; strict-shape failure.  Duplicate/out-of-sequence and unrelated frames
    ; are harmlessly discarded.  This is non-blocking on the ordinary NIC
    ; path and avoids the resident receive routine's long payload timeout.
    call reject_queued_tail
    jc LIVE_K15_PERSIST_FAIL
    mov si, sym_io
    mov cx, 58
    call res_tcp_send
    jc LIVE_K15_PERSIST_FAIL
    mov ax, [0x046c]                  ; includes Finished TX return
    mov [timing_finished_return], ax

client_finished_sent:
    ; Preserve the original ServerHello -> client-Finished gate.  Do not emit
    ; its success text yet: serial output, the old redundant Finished retry,
    ; and the receive-window update are all moved after the complete HEAD.
    mov ax, [timing_finished_return]
    sub ax, [timing_first_tick]
    cmp ax, deadline_ticks
    ja .late
    jmp short .derive
.late:
    mov si, deadline_late
    call LIVE_K15_PERSIST_EMIT
    jmp LIVE_K15_PERSIST_FAIL
.derive:
    call word [sym_derive_client_app_entry]
    jc LIVE_K15_PERSIST_FAIL

    ; A complete application request is the observed liveness boundary.  Seal
    ; and transmit the immutable credential-free HEAD while the symmetric
    ; image and protected controller are still resident, before the cold
    ; post-controller load that missed the edge timer in the first live run.
    call word [sym_build_head_entry]
    jc LIVE_K15_PERSIST_FAIL
    cmp ax, 72
    jne LIVE_K15_PERSIST_FAIL
    mov si, sym_io
    mov cx, 72
    call res_tcp_send
    jc LIVE_K15_PERSIST_FAIL

    ; Pace the following raw ACK by one BIOS tick so it cannot replace an
    ; in-flight HEAD in a slow emulated NIC.  This wait is deliberately after
    ; the complete request.  The post controller discards any queued response
    ; copies and reopens the ordinary receive window at the same ACK boundary.
    mov cx, 1
    call res_wait_ticks
    call LIVE_K15_PERSIST_ZERO_WINDOW
    jc LIVE_K15_PERSIST_FAIL

    ; The request is now complete and the peer is held at a zero receive
    ; window.  User-visible milestones remain outside the critical interval so
    ; display/serial latency cannot consume the server's edge timer.
    mov si, deadline_pass
    call LIVE_K15_PERSIST_EMIT
    mov si, head_tx_text
    call LIVE_K15_PERSIST_EMIT
%ifdef LIVE_K15_IDENTITY_CAPTURE
    ; The post controller uses 0x3c30+ for record/parser state.  Preserve the
    ; already-authenticated CertificateVerify digest in retired identity-tail
    ; scratch, outside the identity-mode plaintext scatter, until the exact
    ; HEAD+ticket record boundary commits.
    push ds
    pop es
    mov si, auth_input_digest
    mov di, 0x0ee0
    mov cx, 16
    rep movsw
%endif
    mov ax, LIVE_K15_POST_CONTROLLER_KEY
    mov bx, 0x0900
    jmp LIVE_K15_PERSIST_TRANSITION

reject_queued_tail:
    mov bp, 256
.poll:
    push bp
    call word [res_nic_vt_receive]
    pop bp
    jc .failed
    cmp word [ne_rx_sample_count], 0
    je .clean
    push bp
    call res_parse_tcp_payload
    pop bp
    jnc .failed
    push bp
    call word [res_nic_vt_rx_fallback]
    pop bp
    jnc .failed
    dec bp
    jnz .poll
.failed:
    stc
    ret
.clean:
    clc
    ret

deadline_pass db 13,10,'DEADLINE PASS',13,10,0
deadline_late db 13,10,'DEADLINE LATE',13,10,0
head_tx_text db 13,10,'HEAD TX',13,10,0

%elifdef LIVE_K15_POST_CONTROLLER

%ifndef LIVE_K15_PERSIST_FAIL
%error "persistent service addresses are required"
%endif
%ifndef LIVE_K15_PERSIST_EMIT
%error "persistent service addresses are required"
%endif
%ifdef LIVE_K15_IDENTITY_CAPTURE
%ifndef LIVE_K15_PERSIST_ZERO_WINDOW
%error "identity transition requires the persistent zero-window service"
%endif
%ifndef LIVE_K15_PERSIST_TRANSITION
%error "identity transition requires the persistent phase-transition service"
%endif
%ifdef LIVE_K15_SECURE_FO
%ifndef LIVE_K15_FO_CONTROLLER_KEY
%error "secure transition requires the FO controller phase key"
%endif
%ifdef LIVE_K15_RESUME_RECEIPT
%ifndef LIVE_K15_RESUME_RECEIPT_KEY
%error "same-boot resumption requires the fixed NTR1 receipt phase"
%endif
%ifndef LIVE_K15_RESUME_RECEIPT_BYTES
%error "same-boot resumption requires the exact NTR1 worker length"
%endif
%if LIVE_K15_RESUME_RECEIPT_BYTES > 0x0110
%error "NTR1 receipt worker reaches K14 mutable work"
%endif
%endif
%else
%ifndef LIVE_K15_AUTH_CONTROLLER_KEY
%error "identity transition requires the auth controller phase key"
%endif
%endif
%endif

org 0x0900

res_load_phase                  equ 0x10c4
res_tcp_ack                    equ 0x13a6
res_tcp_send                   equ 0x13bf
res_tcp_receive                equ 0x14ed
res_nic_vt_receive             equ 0x15e1
ne_rx_sample_count             equ 0x06d5
ne_rx_read_limit               equ 0x06d7
tcp_rx_payload_ptr             equ 0x0fe2
tcp_rx_payload_len             equ 0x0fe4
sym_entry_table                equ 0x1820
sym_server_app_open_entry      equ sym_entry_table + (5 * 2)
sym_open_chunk_entry           equ sym_entry_table + (6 * 2)
sym_open_finish_entry          equ sym_entry_table + (7 * 2)
sym_parse_nst_entry            equ sym_entry_table + (12 * 2)
sym_derive_server_app_entry    equ sym_entry_table + (17 * 2)
sym_received_tag               equ 0x3910
sym_io                         equ 0x39a0
sym_ticket_present             equ 0x3c2c
post_quarantine                equ 0x0d00
%ifdef LIVE_K15_IDENTITY_CAPTURE
post_quarantine_limit          equ 0x0ee0
post_auth_digest_hold          equ 0x0ee0
post_auth_input_digest         equ 0x3c30
%else
post_quarantine_limit          equ 0x0f00
%endif
post_buffer_max                equ post_quarantine_limit - post_quarantine
post_scatter_mid               equ 0x3600
post_scatter_mid_len           equ 0x0238
post_scatter_high              equ 0x3920
post_scatter_high_len          equ 0x0220
post_record_plain_max          equ post_buffer_max + post_scatter_mid_len + post_scatter_high_len
post_scatter_high_offset       equ post_buffer_max + post_scatter_mid_len

post_record_header             equ 0x3c30
post_header_pos                equ post_record_header + 5
post_record_active             equ post_header_pos + 1
post_cipher_remaining          equ post_record_active + 1
post_plain_len                 equ post_cipher_remaining + 2
post_tag_pos                   equ post_plain_len + 2
post_chunk_ptr                 equ post_tag_pos + 1
post_chunk_len                 equ post_chunk_ptr + 2
post_head_outstanding          equ post_chunk_len + 2
post_head_complete             equ post_head_outstanding + 1
post_ticket_milestone          equ post_head_complete + 1
post_http_total                equ post_ticket_milestone + 1
post_http_match                equ post_http_total + 2
post_message_ptr               equ post_http_match + 1
post_message_remaining         equ post_message_ptr + 2
post_message_len               equ post_message_remaining + 2
post_message_count             equ post_message_len + 2
post_http_done                 equ post_message_count + 1
live_post_controller:
    cld
    call word [sym_derive_server_app_entry]
    jc LIVE_K15_PERSIST_FAIL
    ; These adjacent bytes form one zeroable/committable record-state word.
    mov word [post_header_pos], 0
    mov byte [post_head_complete], 0
    mov byte [post_ticket_milestone], 0
    mov word [post_http_total], 0
    mov byte [post_http_match], 0
    mov byte [post_http_done], 0
    mov byte [post_message_count], 0

    ; The peer saw a zero receive window after the complete HEAD.  Discard
    ; unacknowledged copies accumulated during that load, then advertise the
    ; resident 256-byte window.  The server retransmits from the exact
    ; post-Finished application-data boundary.
    mov word [ne_rx_read_limit], 438
    mov bp, 256
.flush:
    push bp
    call word [res_nic_vt_receive]
    pop bp
    jc LIVE_K15_PERSIST_FAIL
    cmp word [ne_rx_sample_count], 0
    je .window_update
    dec bp
    jnz .flush
    jmp LIVE_K15_PERSIST_FAIL
.window_update:
    call res_tcp_ack
    jc LIVE_K15_PERSIST_FAIL

.receive:
    call res_tcp_receive
    jc LIVE_K15_PERSIST_FAIL
    mov si, [tcp_rx_payload_ptr]
    mov cx, [tcp_rx_payload_len]

.consume:
    or cx, cx
    jz .ack_more
    cmp byte [post_record_active], 0
    jne .record_body
    xor bx, bx
    mov bl, [post_header_pos]
    mov al, [si]
    mov [post_record_header + bx], al
    inc si
    dec cx
    inc byte [post_header_pos]
    cmp byte [post_header_pos], 5
    jne .consume
    push si
    push cx
    call post_start_record
    pop cx
    pop si
    jc LIVE_K15_PERSIST_FAIL
    jmp short .consume

.record_body:
    mov ax, [post_cipher_remaining]
    or ax, ax
    jz .tag
    mov dx, cx
    cmp cx, ax
    jbe .bound_mss
    mov cx, ax
.bound_mss:
    cmp cx, 384
    jbe .cipher_chunk
    mov cx, 384
.cipher_chunk:
    mov [post_chunk_ptr], si
    mov [post_chunk_len], cx
    push dx
    call word [sym_open_chunk_entry]
    pop dx
    jc LIVE_K15_PERSIST_FAIL
    call post_store_chunk
    mov ax, [post_chunk_len]
    sub [post_cipher_remaining], ax
    sub dx, ax
    mov cx, dx
    jmp .consume

.tag:
    mov dx, cx
    xor bx, bx
    mov bl, [post_tag_pos]
    mov ax, 16
    sub ax, bx
    cmp cx, ax
    jbe .tag_count
    mov cx, ax
.tag_count:
    mov [post_chunk_len], cx
    push es
    push ds
    pop es
    mov di, sym_received_tag
    add di, bx
    rep movsb
    pop es
    mov ax, [post_chunk_len]
    add [post_tag_pos], al
    sub dx, ax
    mov cx, dx
    cmp byte [post_tag_pos], 16
    jne .consume
    push si
    push cx
    mov si, sym_received_tag
    call word [sym_open_finish_entry]
    jc LIVE_K15_PERSIST_FAIL
    call post_process_plaintext
    jc LIVE_K15_PERSIST_FAIL
    pop cx
    pop si
    mov word [post_header_pos], 0
    jmp .consume

.ack_more:
    call res_tcp_ack
    jc LIVE_K15_PERSIST_FAIL
    call post_check_commit
    jmp .receive

post_start_record:
    cmp byte [post_record_header], 0x17
    jne .failed
    cmp word [post_record_header + 1], 0x0303
    jne .failed
    xor ax, ax
    mov ah, [post_record_header + 3]
    mov al, [post_record_header + 4]
    cmp ax, 17
    jb .failed
    sub ax, 16
    cmp ax, post_record_plain_max
    ja .failed
    mov [post_cipher_remaining], ax
    mov word [post_plain_len], 0
    mov byte [post_tag_pos], 0
    push es
    push ds
    pop es
    mov si, post_record_header
    mov di, sym_io
    mov cx, 5
    rep movsb
    pop es
    call word [sym_server_app_open_entry]
    jc .failed
    mov byte [post_record_active], 1
    clc
    ret
.failed:
    stc
    ret

; Before tag verification, copy every decrypted byte without inspecting it.
; The scatter spans are all retired at post-controller entry.
post_store_chunk:
    mov si, [post_chunk_ptr]
    mov cx, [post_chunk_len]
    mov bx, [post_plain_len]
    push es
    push ds
    pop es
.byte:
    call post_scatter_di
    movsb
    inc bx
    loop .byte
    pop es
    mov [post_plain_len], bx
    ret

; BX=logical plaintext offset, returns DI=physical scatter address.
post_scatter_di:
    mov di, bx
    cmp bx, post_buffer_max
    jb .low
    cmp bx, post_scatter_high_offset
    jb .mid
    add di, post_scatter_high - post_scatter_high_offset
    ret
.mid:
    add di, post_scatter_mid - post_buffer_max
    ret
.low:
    add di, post_quarantine
    ret

; The full plaintext is authenticated before either its bytes or inner type
; affect control flow.  No TLSInnerPlaintext padding is accepted.
post_process_plaintext:
    mov cx, [post_plain_len]
    or cx, cx
    jz .failed
    mov bx, cx
    dec bx
    call post_scatter_di
    mov dl, [di]
    dec cx                              ; content excludes exact final type
    or cx, cx
    jz .failed
    cmp byte [post_head_complete], 0
    jne .classify
    cmp word [post_http_total], 0
    jne .http
.classify:
    mov al, [post_quarantine]
    cmp al, 'H'
    je .http
    cmp al, 4
    je .ticket
    cmp al, 1
    je .alert
    cmp al, 2
    jne .failed
.alert:
    cmp dl, 0x15
    jne .failed
    cmp cx, 2
    jne .failed
    jmp short .failed
.ticket:
    cmp dl, 0x16
    jne .failed
    cmp cx, post_buffer_max
    ja .failed
    jmp post_process_tickets
.http:
    cmp dl, 0x17
    jne .failed
    call post_process_http
    ret
.failed:
    stc
    ret

post_process_tickets:
    mov word [post_message_ptr], post_quarantine
    mov [post_message_remaining], cx
.next:
    cmp word [post_message_remaining], 0
    je .done
    cmp word [post_message_remaining], 4
    jb .failed
    mov si, [post_message_ptr]
    cmp byte [si], 4
    jne .failed
    cmp byte [si + 1], 0
    jne .failed
    mov ax, [si + 2]
    xchg al, ah
    add ax, 4
    jc .failed
    cmp ax, 384
    ja .failed
    cmp ax, [post_message_remaining]
    ja .failed
    mov [post_message_len], ax
    mov cx, ax
    cmp byte [post_message_count], 4
    jae .failed
    call word [sym_parse_nst_entry]
    jc .failed
    inc byte [post_message_count]
    mov ax, [post_message_len]
    add [post_message_ptr], ax
    sub [post_message_remaining], ax
    jmp short .next
.done:
    cmp byte [post_message_count], 0
    je .failed
    cmp byte [post_ticket_milestone], 0
    jne .success
    cmp byte [sym_ticket_present], 0
    je .failed
    mov byte [post_ticket_milestone], 1
    mov si, post_ticket_text
    call LIVE_K15_PERSIST_EMIT
.success:
    clc
    ret
.failed:
    stc
    ret

; Parse authenticated HTTP bytes across the three scatter spans.  The DFA may
; continue across records, but completion is committed only at a record end.
post_process_http:
    cmp byte [post_head_complete], 0
    jne .failed
    mov dx, cx
    mov si, post_quarantine
    cmp dx, post_buffer_max
    jbe .last
    mov cx, post_buffer_max
    call post_feed_http
    jc .failed
    sub dx, post_buffer_max
    mov si, post_scatter_mid
    cmp dx, post_scatter_mid_len
    jbe .last
    mov cx, post_scatter_mid_len
    call post_feed_http
    jc .failed
    sub dx, post_scatter_mid_len
    mov si, post_scatter_high
.last:
    mov cx, dx
    call post_feed_http
    jc .failed
    cmp byte [post_http_done], 0
    je .success
    mov byte [post_head_complete], 1
    mov si, post_head_complete_text
    call LIVE_K15_PERSIST_EMIT
.success:
    clc
    ret
.failed:
    stc
    ret

post_feed_http:
.byte:
    cmp byte [post_http_done], 0
    jne .failed
    mov bx, [post_http_total]
    cmp bx, 2048
    jae .failed
    inc word [post_http_total]
    lodsb
    cmp bx, 9
    jb .prefix
    cmp bx, 12
    jb .status_digit
    je .status_space
    cmp al, 9
    je .match
    cmp al, 10
    je .match
    cmp al, 13
    je .match
    cmp al, 0x20
    jb .failed
    cmp al, 0x7e
    ja .failed
.match:
    xor bx, bx
    mov bl, [post_http_match]
    cmp al, [post_http_end + bx]
    je .matched
    xor bl, bl
    cmp al, 13
    jne .store_match
    inc bl
.store_match:
    mov [post_http_match], bl
    jmp short .next
.matched:
    inc bl
    mov [post_http_match], bl
    cmp bl, 4
    jne .next
    mov byte [post_http_done], 1
    jmp short .next
.prefix:
    cmp al, [post_http_prefix + bx]
    jne .failed
    jmp short .next
.status_digit:
    cmp al, '0'
    jb .failed
    cmp al, '9'
    ja .failed
    cmp bx, 9
    jne .next
    cmp al, '2'
    je .next
    cmp al, '4'
    je .next
    cmp al, '5'
    jne .failed
    jmp short .next
.status_space:
    cmp al, ' '
    jne .failed
.next:
    dec cx
    jz .done
    jmp .byte
.done:
    clc
    ret
.failed:
    stc
    ret

post_check_commit:
    ; Do not promote at a TCP-frame boundary inside a partial TLS record.
    cmp word [post_header_pos], 0
    jne .pending
    cmp byte [post_head_complete], 1
    jne .pending
    cmp byte [post_ticket_milestone], 1
    jne .pending
%ifdef LIVE_K15_SECURE_FO
    ; Retire live dialogue and freeze the tentative ticket at the exact
    ; authenticated record boundary.  The FO controller emits its first marker
    ; immediately after the one-sector transition.
    call LIVE_K15_PERSIST_ZERO_WINDOW
    jc LIVE_K15_PERSIST_FAIL
    push ds
    pop es
    mov si, post_auth_digest_hold
    mov di, post_auth_input_digest
    mov cx, 16
    rep movsw
%ifdef LIVE_K15_RESUME_RECEIPT
    ; This is the sole NTR1 entry edge: authenticated HTTP completion, first
    ; retained NST, no partial TLS record, and a frozen receive window have all
    ; been proved immediately above.  Stage the immutable one-sector file
    ; outside K14, then copy only its measured <=0x110 bytes to 0x3400 so the
    ; live SHA code/work and persistent fail services remain resident.  The
    ; worker publishes/readbacks NTR1 before it reconstructs the existing FO
    ; ticket hold and enters the unmodified FO controller.
.resume_receipt_edge:
    mov ax, LIVE_K15_RESUME_RECEIPT_KEY
    mov bx, post_quarantine
    call res_load_phase
    jc LIVE_K15_PERSIST_FAIL
    push ds
    pop es
    mov si, post_quarantine
    mov di, 0x3400
    mov cx, LIVE_K15_RESUME_RECEIPT_BYTES
    rep movsb
    mov dx, 0x3400
    jmp dx
%else
    mov si, 0x3b40
    mov di, 0x0700
    mov cx, 119
    rep movsw
    mov ax, LIVE_K15_FO_CONTROLLER_KEY
    mov bx, 0x2400
    jmp LIVE_K15_PERSIST_TRANSITION
%endif
%elifdef LIVE_K15_IDENTITY_CAPTURE
    ; Retire live dialogue before the long target-side signature equation.
    ; The ticket remains tentative; no credential or product state is exposed.
    call LIVE_K15_PERSIST_ZERO_WINDOW
    jc LIVE_K15_PERSIST_FAIL
    ; Record parsing is now at an exact boundary.  Restore the captured
    ; CertificateVerify digest before either FO or identity authentication
    ; reuses the low hold.
    push ds
    pop es
    mov si, post_auth_digest_hold
    mov di, post_auth_input_digest
    mov cx, 16
    rep movsw
    mov si, post_auth_begin_text
    call LIVE_K15_PERSIST_EMIT
    mov ax, LIVE_K15_AUTH_CONTROLLER_KEY
    mov bx, 0x3200
    jmp LIVE_K15_PERSIST_TRANSITION
%else
    mov si, post_canary_text
    call LIVE_K15_PERSIST_EMIT
.halt:
    sti
    hlt
    jmp short .halt
%endif
.pending:
    ret

post_http_prefix       db 'HTTP/1.1 '
post_http_end          db 13,10,13,10
post_head_complete_text db 13,10,'HEAD OK',13,10,0
post_ticket_text       db 13,10,'TICKET',13,10,0
%ifdef LIVE_K15_SECURE_FO
%elifdef LIVE_K15_IDENTITY_CAPTURE
post_auth_begin_text   db 13,10,'AUTH BEGIN',13,10,0
%else
post_canary_text       db 13,10,'CANARY COMMIT',13,10,'PASS',13,10,'RESULT',13,10,0
%endif

%elifdef LIVE_K15_FO_CONTROLLER

%ifndef LIVE_K15_FO_PHASE_KEY
%error "FO controller requires the unchanged FO kernel phase"
%endif
%ifndef LIVE_K15_AUTH_CONTROLLER_KEY
%error "FO controller requires the post-FO auth controller phase"
%endif
%ifndef LIVE_K15_NE_BUF_READ
%error "FO controller requires the guarded NE2000 DMA-read leaf"
%endif
%ifndef LIVE_K15_NE_BUF_LOAD
%error "FO controller requires the guarded NE2000 DMA-write leaf"
%endif
%ifndef LIVE_K15_PERSIST_FAIL
%error "FO controller requires the persistent fail service"
%endif
%ifndef LIVE_K15_PERSIST_EMIT
%error "FO controller requires the persistent emit service"
%endif

org 0x2400

res_load_phase                 equ 0x10c4
fo_kernel_entry                equ 0x1800
fo_ticket_hold                 equ 0x0700
fo_ticket_len                  equ 238
fo_expected_k                  equ fo_ticket_hold + fo_ticket_len
fo_handoff_a                   equ 0x0d00
fo_handoff_b                   equ 0x0d80
fo_auth_transition             equ 0x0d00
fo_message                     equ 0x3a40
fo_candidate_g                 equ 0x3b9c
fo_card_ek                     equ 0x7400
fo_card_c                      equ 0x7900
fo_card_handoff_a              equ 0x7e00
fo_card_handoff_b              equ 0x7f00
fo_handoff_a_page              equ 0x7e
fo_handoff_b_page              equ 0x7f
handoff_nic_base               equ 0x060e
ne_tx_start                    equ 0x06cb

live_fo_controller:
    cld
    mov si, fo_begin_text
    call LIVE_K15_PERSIST_EMIT

    ; Load the unchanged six-sector FO kernel.  Its end is exactly 0x2400, so
    ; this controller remains executable while the resident loader returns.
    mov ax, LIVE_K15_FO_PHASE_KEY
    mov bx, fo_kernel_entry
    call res_load_phase
    jc fo_failed

    ; Read both independently stored handoffs and compare all 128 bytes before
    ; publishing any of their secret fields into the kernel ABI.
    mov bx, fo_card_handoff_a
    mov cx, 128
    mov di, fo_handoff_a
    call LIVE_K15_NE_BUF_READ
    jc fo_failed
    mov bx, fo_card_handoff_b
    mov cx, 128
    mov di, fo_handoff_b
    call LIVE_K15_NE_BUF_READ
    jc fo_failed
    mov si, fo_handoff_a
    mov di, fo_handoff_b
    mov cx, 64
    xor dx, dx
.compare_handoff:
    lodsw
    xor ax, [di]
    or dx, ax
    add di, 2
    loop .compare_handoff
    or dx, dx
    jnz fo_failed

    ; Scatter m', G=K'||r', and z into the unchanged FO fixed-input ABI.  Keep
    ; a separate expected provisional K' inside the kernel-preserved hold.
    push ds
    pop es
    mov si, fo_handoff_b
    mov di, fo_message
    mov cx, 16
    rep movsw
    mov di, fo_expected_k
    mov cx, 16
    rep movsw
    mov si, fo_handoff_b + 32
    mov di, fo_candidate_g
    mov cx, 48
    rep movsw

    mov bx, fo_card_read_callback
    call fo_kernel_entry
    jc fo_failed
    cmp ax, 1
    jne fo_failed

    ; The FO kernel has selected its output.  Require the valid-path secret to
    ; equal the independently retained provisional K' before restoring ticket
    ; state or advancing to identity authentication.
    mov si, fo_candidate_g
    mov di, fo_expected_k
    mov cx, 16
    xor dx, dx
.compare_k:
    lodsw
    xor ax, [di]
    or dx, ax
    add di, 2
    loop .compare_k
    or dx, dx
    jnz fo_failed

    push ds
    pop es
    mov si, fo_ticket_hold
    mov di, 0x3b40
    mov cx, fo_ticket_len / 2
    rep movsw
    call fo_cleanup_handoffs
    mov si, fo_valid_text
    call LIVE_K15_PERSIST_EMIT
    mov si, fo_auth_text
    call LIVE_K15_PERSIST_EMIT

    ; FO work overwrote delta_load and the auth overlay will overwrite this
    ; controller.  Relocate a tiny absolute trampoline into retired low work
    ; and use the immutable resident phase loader from there.
    push ds
    pop es
    mov si, fo_auth_transition_source
    mov di, fo_auth_transition
    mov cx, fo_auth_transition_len
    rep movsb
    jmp fo_auth_transition

; Erase both low copies, the independent K' compare value, the retired
; high m', and the initial-attempt half of both secret card pages.  The second
; 128-byte half remains for one same-boot resumption attempt.  Public ek/c may
; remain.  Card-write errors are intentionally ignored here so local erasure
; and fail-closed control flow still complete if the NIC itself has failed.
fo_cleanup_handoffs:
    mov bp, 128
    jmp short fo_cleanup_handoffs_counted

; A failed initial secure path cannot resume.  Erase both complete pages.
fo_cleanup_handoffs_full:
    mov bp, 256

fo_cleanup_handoffs_counted:
    push ds
    pop es
    xor ax, ax
    mov di, fo_handoff_a
    mov cx, 128
    rep stosw
    mov di, fo_expected_k
    mov cx, 16
    rep stosw
    mov di, fo_message
    mov cx, 16
    rep stosw
    mov al, fo_handoff_a_page
    mov si, fo_handoff_a
    push bp
    call fo_card_write
    pop bp
    mov al, fo_handoff_b_page
    mov si, fo_handoff_a
    call fo_card_write
    ret

fo_card_write:
    xor bx, bx
    mov bl, [ne_tx_start]
    push bx
    mov [ne_tx_start], al
    mov bx, [handoff_nic_base]
    call LIVE_K15_NE_BUF_LOAD
    pop bx
    mov [ne_tx_start], bl
    ret

fo_failed:
    call fo_cleanup_handoffs_full
    ; No ticket will be promoted on failure, so also erase the provisional
    ; high G||z window even though it overlaps tentative ticket state.
    push ds
    pop es
    xor ax, ax
    mov di, fo_candidate_g
    mov cx, 48
    rep stosw
    jmp LIVE_K15_PERSIST_FAIL

; FO callback ABI:
;   AL object (0=ek, 1=c), DX offset, CX count, DI destination.
; Preserve BX/BP/DS/ES/SS, bound every read, and return with DF clear while
; retaining the guarded driver leaf's carry result.
fo_card_read_callback:
    push bx
    push bp
    push ds
    push es
    or al, al
    jz .ek
    cmp al, 1
    jne .failed
    mov ax, dx
    add ax, cx
    jc .failed
    cmp ax, 1088
    ja .failed
    mov bx, fo_card_c
    jmp short .read
.ek:
    mov ax, dx
    add ax, cx
    jc .failed
    cmp ax, 1184
    ja .failed
    mov bx, fo_card_ek
.read:
    add bx, dx
    call LIVE_K15_NE_BUF_READ
    cld
    jmp short .restore
.failed:
    stc
    cld
.restore:
    pop es
    pop ds
    pop bp
    pop bx
    ret

fo_auth_transition_source:
    mov ax, LIVE_K15_AUTH_CONTROLLER_KEY
    mov bx, 0x3200
    mov dx, res_load_phase
    call dx
    jc .failed
    jmp bx
.failed:
    mov dx, LIVE_K15_PERSIST_FAIL
    jmp dx
fo_auth_transition_end:
fo_auth_transition_len equ \
    fo_auth_transition_end - fo_auth_transition_source

fo_begin_text db 13,10,'FO BEGIN',13,10,0
fo_valid_text db 13,10,'KEM VALID',13,10,0
fo_auth_text  db 13,10,'AUTH BEGIN',13,10,0

%if ($ - $$) > 0x0200
%error "live FO controller exceeds its one-sector slot"
%endif

%elifdef LIVE_K15_SCRUB_CONTROLLER

%ifndef LIVE_K15_NE_BUF_LOAD
%error "scrub controller requires the guarded NE2000 DMA-write leaf"
%endif
%ifndef LIVE_K15_PERSIST_EMIT
%error "scrub controller requires the persistent emit service"
%endif

org 0x2400

handoff_nic_base               equ 0x060e
ne_tx_start                    equ 0x06cb
scrub_expected_k               equ 0x07ee
scrub_handoff_low              equ 0x0d00
scrub_message                  equ 0x3a40
scrub_candidate_g              equ 0x3b9c
scrub_first_card_page          equ 0x73
scrub_card_page_end            equ 0x80

live_scrub_controller:
    cld
    push ds
    pop es
    xor ax, ax

    ; Clear every local secret copy first.  On the failure path no tentative
    ; ticket can be promoted, so the overlapping high G||z range is retired.
    mov di, scrub_handoff_low
    mov cx, 128
    rep stosw
    mov di, scrub_expected_k
    mov cx, 16
    rep stosw
    mov di, scrub_message
    mov cx, 16
    rep stosw
    mov di, scrub_candidate_g
    mov cx, 48
    rep stosw

    ; Use the already-zero 256-byte low handoff window as the full-page source.
    ; The helper attempts every reserved page even after a DMA error and
    ; returns the aggregate result in CF.  This terminal failure controller
    ; deliberately continues to the same fail marker either way.
    call scrub_card_pages

    mov si, scrub_fail_text
    call LIVE_K15_PERSIST_EMIT
.halt:
    sti
    hlt
    jmp short .halt

; Attempt every reserved card page and aggregate individual DMA failures.
; Output CF=1 if any page failed, CF=0 only when all pages were overwritten.
scrub_card_pages:
    xor di, di
    mov al, scrub_first_card_page
.next:
    call scrub_card_page
    adc di, 0
    inc al
    cmp al, scrub_card_page_end
    jne .next
    or di, di
    jz .complete
    stc
    ret
.complete:
    clc
    ret

scrub_card_page:
    mov ah, [ne_tx_start]
    push ax
    mov [ne_tx_start], al
    mov si, scrub_handoff_low
    mov bp, 256
    mov bx, [handoff_nic_base]
    call LIVE_K15_NE_BUF_LOAD
    pop ax
    mov [ne_tx_start], ah
scrub_card_page_restored:
    ret

scrub_fail_text db 13,10,'FAIL',13,10,'RESULT',13,10,0

%if ($ - $$) > 0x0200
%error "live scrub controller exceeds its one-sector slot"
%endif

%elifdef LIVE_K15_AUTH_CONTROLLER

%ifdef LIVE_K15_AUTH_USE_RESIDENT_LOADER
%ifndef LIVE_K15_AUTH_PHASE_KEY
%error "secure auth controller requires its resident-loader phase key"
%endif
%else
%ifndef LIVE_K15_AUTH_ABSOLUTE_LBA
%error "auth controller requires an absolute auth phase LBA"
%endif
%ifndef LIVE_K15_AUTH_SECTORS
%error "auth controller requires the auth phase sector count"
%endif
%endif

org 0x3200

live_auth_controller:
    cld
%ifdef LIVE_K15_AUTH_USE_RESIDENT_LOADER
    mov ax, LIVE_K15_AUTH_PHASE_KEY
    mov bx, 0x1800
    call 0x10c4
%else
    mov ax, LIVE_K15_AUTH_ABSOLUTE_LBA
    mov bx, 0x1800
    mov cx, LIVE_K15_AUTH_SECTORS
    call 0x0f00
%endif
    jc auth_failed
    call word [0x1800]
    jc auth_failed
    cmp ax, 1
    jne auth_failed
    cmp byte [0x3c9a], 1
    jne auth_failed
    mov si, auth_pass_text
    call auth_emit
.halt:
    sti
    hlt
    jmp short .halt

auth_failed:
    mov si, auth_fail_text
    call auth_emit
    jmp short live_auth_controller.halt

auth_emit:
    mov dx, 0x03fb
    mov al, 0x80
    out dx, al
    mov dx, 0x03f8
    mov al, 12
    out dx, al
    inc dx
    xor al, al
    out dx, al
    mov dx, 0x03fb
    mov al, 0x03
    out dx, al
    mov dx, 0x03fc
    mov al, 0x03
    out dx, al
.next:
    lodsb
    or al, al
    jz .done
    push ax
    push bx
    push cx
    push dx
    mov bl, al
    mov ah, 0x0e
    xor bh, bh
    int 0x10
    mov dx, 0x03fd
    mov cx, 0xffff
.wait:
    in al, dx
    test al, 0x20
    jnz .ready
    loop .wait
    jmp short .restore
.ready:
    mov dx, 0x03f8
    mov al, bl
    out dx, al
.restore:
    pop dx
    pop cx
    pop bx
    pop ax
    jmp short .next
.done:
    ret

auth_pass_text db 13,10,'IDENTITY PASS',13,10,'PASS',13,10,'RESULT',13,10,0
auth_fail_text db 13,10,'FAIL',13,10,'RESULT',13,10,0

%else
%error "select one LIVE_K15_* controller build"
%endif
