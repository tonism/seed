; Seed TLS 1.3 fixed-profile ClientHello / ServerHello PoC overlay.
;
; This is an isolated product-shape proof.  It is not linked into SEED.SYS.
; The flat cpu-8086 image is loaded at 0000:1800 and shares the 16 KiB memory
; contract in layout.inc.
;
; Entry ABI (near call, DS=ES=SS=0, DF clear):
;   0  hello_fresh_begin
;   1  hello_resumed_begin
;   2  hello_next_fragment       -> AX=1, SI/CX fragment; AX=0 at end
;   3  hello_fragment_consumed   caller confirms the pending fragment was sent
;   4  hello_rewind              exact whole-ClientHello retransmission
;   5  hello_server_begin
;   6  hello_server_feed         SI=handshake bytes, CX=1..384
;   7  hello_server_finish
;   8  hello_clear
;  14  hello_client_digest        resumed-early-data build only; after an
;                                 offline full-ClientHello iterator pass,
;                                 finalize its digest in the former truncated
;                                 digest slot
;   9..11 cached-connect helpers when HELLO_CACHED_CONNECT is selected
;  12  hello_relocate_pending    SI/CX becomes pending replay owner
;  13  hello_fragment_prehashed  advance one offline-hashed fragment
;
; Every operation returns CF=0 on success and CF=1 on a state/shape failure.
; hello_next_fragment includes the five-byte TLS record header in fragment
; zero, but hashes only the ClientHello handshake message.  The receive-side
; ABI accepts ServerHello *handshake* bytes after the resident record layer has
; checked/removed the TLS record header.
;
; Fragment ownership is explicit: hello_next_fragment returns the same pending
; fragment until hello_fragment_consumed is called.  hello_server_begin is
; rejected until the final fragment was consumed.  Thus raw c may overwrite ek
; at 08c0 only after no ClientHello fragment can still refer to ek.
;
; HELLO_DYNAMIC_X25519 is the narrow 286 product handoff.  Before entry 0 or 1
; the controller writes one raw 32-byte RFC 7748 client public share at
; hello_dynamic_x25519_input (0000:4000).  The selected begin entry rejects an
; all-zero value, snapshots it into HELLO-owned mutable state, and scrubs the
; input.  Rewrites of the input cannot change binder construction or the
; pending/replayed ClientHello.  The snapshot is scrubbed when ServerHello
; parsing begins.  This define neither adds a public entry nor changes the
; overlay header/table format.

bits 16
cpu 8086
org 0x1800

; The first-flight image is deliberately fresh-only. The post-auth image is
; a distinct resumed-only phase: it retains the cached connector entries, but
; makes the fresh entry fail closed so a dispatcher cannot silently fall back
; to another full handshake.
%ifdef HELLO_RESUMED_CACHED_CONNECT
%ifndef HELLO_RESUMED_ONLY
%error "resumed cached connect requires HELLO_RESUMED_ONLY"
%endif
%ifdef HELLO_FRESH_ONLY
%error "resumed-only and fresh-only hello modes are mutually exclusive"
%endif
%define HELLO_CACHED_CONNECT 1
%endif

%ifdef HELLO_DYNAMIC_X25519
%ifndef TLS13_PRODUCT_TLS13
%error "dynamic X25519 requires the TLS 1.3 product wire profile"
%endif
%ifndef HELLO_FRESH_ONLY
%ifndef HELLO_RESUMED_ONLY
%error "dynamic X25519 requires an explicit fresh-only or resumed-only image"
%endif
%endif
%endif

%include "layout.inc"

sha256_digest_len equ 32
sha256_block_size equ 64
sha256_k_len equ 256

hello_version                 equ 1
hello_mss_max                 equ 384
%ifdef TLS13_PRODUCT_TLS13
; RFC 8449 record_size_limit = 2048.  This is an offer, not an assumption:
; the protected-record receiver keeps its own fail-closed staging bound even
; when a server (including the current OpenAI edge) omits the extension from
; EncryptedExtensions.
hello_product_extension_delta equ 6
%else
hello_product_extension_delta equ 0
%endif
hello_base_fresh_message_len  equ 1376 + hello_product_extension_delta
hello_base_fresh_extensions_len equ 0x0511 + hello_product_extension_delta
%ifdef HELLO_FRESH_TICKET_REQUEST
hello_fresh_message_len       equ hello_base_fresh_message_len + 6
hello_fresh_extensions_len    equ hello_base_fresh_extensions_len + 6
%else
hello_fresh_message_len       equ hello_base_fresh_message_len
hello_fresh_extensions_len    equ hello_base_fresh_extensions_len
%endif
hello_fresh_body_len          equ hello_fresh_message_len - 4
hello_fresh_server_len        equ 1210
hello_resumed_server_len      equ 1216
hello_prefix_fragment_len     equ 5 + 142
hello_ek_fragment_count       equ 4
hello_fresh_fragment_count    equ 6
hello_resumed_fragment_count  equ 8
hello_ticket_min              equ 1
hello_ticket_max              equ poc_ticket_identity_max
%ifdef HELLO_RESUMED_EARLY_DATA
hello_resumed_tail_prefix_len equ 68 + hello_product_extension_delta
%else
hello_resumed_tail_prefix_len equ 64 + hello_product_extension_delta
%endif

hello_mode_fresh              equ 0
hello_mode_resumed            equ 1

; The resumed TX worker can construct its bounded generated fragments directly
; where the resident TCP builder will place payload.  Header construction ends
; immediately before this address, and the subsequent payload copy is a safe
; source==destination operation.  This avoids borrowing either HELLO's live
; 0x0dc0..0x0efc state or the outer resume transition at 0x0f00.
%ifdef HELLO_RESUMED_ONLY
hello_tx_build_start          equ poc_rx_frame_start + 14 + 20 + 20
%else
hello_tx_build_start          equ poc_rx_frame_start
%endif

hello_phase_idle              equ 0
hello_phase_tx                equ 1
hello_phase_tx_done           equ 2
hello_phase_rx                equ 3
hello_phase_complete          equ 4
hello_phase_failed            equ 5

; Attempt-input ABI.  The legacy PoC borrows the high attempt cache.  The
; system-RAM-only product route instead takes its fresh random and session ID
; from the conditioned-input tail below the resident handoff.  That route is
; fresh-only: ticket inputs remain a later resumption-phase concern.
hello_server_x25519           equ poc_hello_server_x
hello_transcript_digest       equ poc_hello_digest
%ifdef HELLO_SYSTEM_RAM_INPUTS
%ifndef HELLO_FRESH_ONLY
%error "system-RAM HELLO inputs require the fresh-only image"
%endif
hello_input_random            equ 0x0560
hello_input_session_id        equ 0x0580
hello_attempt_used_end        equ hello_input_session_id + 32
%elifdef HELLO_SYSTEM_RAM_RESUME_INPUTS
%ifndef HELLO_RESUMED_ONLY
%error "system-RAM resumed HELLO inputs require the resumed-only image"
%endif
; The root remains at 3400..341f until the resumed hybrid schedule commits.
; Everything after it is one bounded attempt-input block and becomes dead
; before c is scattered through the extension.
hello_input_random            equ 0x3420
hello_input_session_id        equ hello_input_random + 32
hello_input_ticket_psk        equ hello_input_session_id + 32
hello_input_ticket_age        equ hello_input_ticket_psk + 32
hello_input_ticket_len        equ hello_input_ticket_age + 4
hello_attempt_used_end        equ hello_input_ticket_len + 2
%else
hello_input_random            equ poc_attempt_cache_start
hello_input_session_id        equ hello_input_random + 32
hello_input_ticket_psk        equ hello_input_session_id + 32
hello_input_ticket_age        equ hello_input_ticket_psk + 32 ; 4-byte wire order
hello_input_ticket_len        equ hello_input_ticket_age + 4  ; native word
hello_attempt_used_end        equ hello_input_ticket_len + 2
%endif
hello_status                  equ poc_hello_status
%ifdef HELLO_DYNAMIC_X25519
; Controller/HELLO ABI: write one nonzero RFC 7748 public share here before
; either begin entry.  This 286-only handoff sits above the 16 KiB ceiling and
; below the fixed 0000:4200 asymmetric-module overlay, so resumed tickets keep
; their independent PSK at 0000:3bdc.  HELLO snapshots and erases these bytes.
hello_dynamic_x25519_input     equ 0x4000
hello_dynamic_x25519_len       equ 32
%if hello_dynamic_x25519_input < poc_ram_end
%error "dynamic X25519 input must remain outside the 16 KiB product floor"
%endif
%endif

hello_overlay_header:
    db 'T13HEL01'
    dw hello_version
    dw hello_image_end - hello_overlay_header
    dw poc_k_start
    dw poc_k_end
    dw poc_rx_frame_start
    dw poc_rx_frame_end
    dw poc_mlkem_ek
    dw poc_mlkem_ek_end
    dw poc_mlkem_ciphertext
    dw poc_mlkem_ciphertext_end
    dw poc_ticket_identity
    dw hello_ticket_max
    dw hello_server_x25519
    dw hello_transcript_digest
    dw hello_state_base
    dw hello_state_end
    dw hello_sha_work_start
    dw hello_sha_work_end
    dw hello_attempt_used_end
    dw hello_entry_count
hello_entry_table:
    dw hello_fresh_begin
    dw hello_resumed_begin
    dw hello_next_fragment
    dw hello_fragment_consumed
    dw hello_rewind
    dw hello_server_begin
    dw hello_server_feed
    dw hello_server_finish
    dw hello_clear
%ifdef HELLO_CACHED_CONNECT
    dw hello_cached_connect
    dw hello_cached_zero_window_ack
    dw hello_cached_window_update
    dw hello_relocate_pending
    dw hello_fragment_prehashed
%elifdef HELLO_RESUMED_ONLY
    ; The post-auth composition provides cached connect through a separate
    ; fixed phase.  Preserve entry numbers 9..13: cached operations fail
    ; closed while pending-fragment ownership and offline-hash advance remain
    ; available to its resumed TX worker.
    dw hello_fail
    dw hello_fail
    dw hello_fail
    dw hello_relocate_pending
    dw hello_fragment_prehashed
%endif
%ifdef HELLO_RESUMED_EARLY_DATA
    dw hello_client_digest
%endif
hello_entry_count equ ($ - hello_entry_table) / 2

; ---------------------------------------------------------------------------
; ClientHello orchestration
; ---------------------------------------------------------------------------

hello_fresh_begin:
%ifdef HELLO_RESUMED_ONLY
    jmp hello_fail
%else
    call hello_begin_common
    jc .done
%ifdef HELLO_DYNAMIC_X25519
    call hello_dynamic_x25519_capture
    jc hello_fail
%endif
    mov byte [hello_mode], hello_mode_fresh
    mov word [hello_message_len], hello_fresh_message_len
    mov word [hello_extensions_len], hello_fresh_extensions_len
    call sha256_init
.done:
    ret
%endif

hello_resumed_begin:
%ifdef HELLO_FRESH_ONLY
    ; The first-flight race never has a usable ticket.  A later, separately
    ; loaded resumption overlay owns binder construction; keep this ABI slot
    ; fail-closed so the resident scheduler cannot accidentally request it.
    jmp hello_fail
%else
    call hello_begin_common
    jc .done
%ifdef HELLO_DYNAMIC_X25519
    call hello_dynamic_x25519_capture
    jc hello_fail
%endif
    mov ax, [hello_input_ticket_len]
    cmp ax, hello_ticket_min
    jb hello_fail
    cmp ax, hello_ticket_max
    ja hello_fail
    mov bx, ax
    mov byte [hello_mode], hello_mode_resumed
    mov [hello_ticket_len_snapshot], bx
    ; Resumption adds psk_key_exchange_modes (6), and one final
    ; pre_shared_key extension (ticket_len + 47).  The secure-floor
    ; resumption profile also offers the fixed replay-safe public HEAD as
    ; early data; pre_shared_key remains the mandatory final extension.
    mov ax, bx
%ifdef HELLO_RESUMED_EARLY_DATA
    add ax, hello_base_fresh_message_len + 57
%else
    add ax, hello_base_fresh_message_len + 53
%endif
    mov [hello_message_len], ax
    mov ax, bx
%ifdef HELLO_RESUMED_EARLY_DATA
    add ax, hello_base_fresh_extensions_len + 57
%else
    add ax, hello_base_fresh_extensions_len + 53
%endif
    mov [hello_extensions_len], ax
    call hello_make_binder
    jc hello_fail
    ; Binder preparation is an offline pass.  Start a new context for the
    ; byte-exact ClientHello that the fragment iterator will actually emit.
    call sha256_init
    clc
.done:
    ret
%endif

hello_begin_common:
    cld
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, hello_state_clear_start
    mov cx, hello_state_clear_end - hello_state_clear_start
    rep stosb
    mov byte [hello_status], 0
    mov si, hello_input_random
    mov di, hello_random
    mov cx, 32
    rep movsb
    mov si, hello_input_session_id
    mov di, hello_session
    mov cx, 32
    rep movsb
%ifndef HELLO_FRESH_ONLY
    mov si, hello_input_ticket_age
    mov di, hello_age
    mov cx, 4
    rep movsb
%endif
    mov byte [hello_phase], hello_phase_tx
    mov byte [hello_hash_enabled], 1
    pop es
    pop di
    pop si
    pop cx
    pop ax
    clc
    ret

%ifdef HELLO_DYNAMIC_X25519
; Snapshot the controller-owned public share before the ClientHello iterator
; can expose any fragment.  The source is erased on both success and failure;
; after this call only HELLO's private snapshot can influence the wire.
hello_dynamic_x25519_capture:
    xor dx, dx
    mov si, hello_dynamic_x25519_input
    mov di, hello_dynamic_x25519_snapshot
    mov cx, hello_dynamic_x25519_len / 2
.copy:
    lodsw
    or dx, ax
    stosw
    mov word [si - 2], 0
    loop .copy
    or dx, dx
    jz .bad
    clc
    ret
.bad:
    stc
    ret
%endif

hello_next_fragment:
    cmp byte [hello_phase], hello_phase_tx
    je .tx_active
    cmp byte [hello_phase], hello_phase_tx_done
    jne .failed
    xor ax, ax
    xor cx, cx
    clc
    ret
.tx_active:
    cmp byte [hello_pending], 0
    jne .repeat_pending
    xor ax, ax
    mov al, [hello_segment]
%ifdef HELLO_FRESH_ONLY
    cmp ax, hello_fresh_fragment_count
    jae .at_end
%else
    cmp byte [hello_mode], hello_mode_fresh
    je .fresh_limit
    cmp ax, hello_resumed_fragment_count
    jae .at_end
    jmp short .dispatch
.fresh_limit:
    cmp ax, hello_fresh_fragment_count
    jae .at_end
%endif
.dispatch:
    or ax, ax
    jz .prefix
    cmp ax, 5
    jb .ek
%ifdef HELLO_FRESH_ONLY
    jmp short .fresh_tail
%else
    cmp byte [hello_mode], hello_mode_fresh
    je .fresh_tail
    cmp ax, 5
    je .resumed_tail_prefix
    cmp ax, 6
    je .identity
    call hello_build_resumed_suffix
    mov si, hello_tx_build_start
    mov cx, 39
    jmp short .publish
%endif
.prefix:
    call hello_build_prefix
    mov si, hello_tx_build_start
    mov cx, hello_prefix_fragment_len
    jmp short .publish
.ek:
    ; Segments 1..3 are 384 bytes.  Segment 4 is the final 32 ek bytes.
    dec ax
    mov bx, hello_mss_max
    mul bx
    add ax, poc_mlkem_ek
    mov si, ax
    mov cx, hello_mss_max
    cmp byte [hello_segment], 4
    jne .publish
    mov cx, poc_mlkem_ek_len - (3 * hello_mss_max)
    jmp short .publish
.fresh_tail:
%ifdef HELLO_DYNAMIC_X25519
    call hello_build_dynamic_fresh_tail
    mov si, hello_tx_build_start
%else
    mov si, hello_fresh_tail
%endif
%ifdef HELLO_FRESH_TICKET_REQUEST
    ; The live fresh-flight PoC advertises PSK-DHE ticket usability without
    ; offering a PSK.  hello_psk_modes_extension is laid out directly after
    ; the base tail, so this remains one stable iterator fragment.
    mov cx, hello_fresh_tail_len + hello_psk_modes_extension_len
%else
    mov cx, hello_fresh_tail_len
%endif
    jmp short .publish
%ifndef HELLO_FRESH_ONLY
.resumed_tail_prefix:
    call hello_build_resumed_tail_prefix
    mov si, hello_tx_build_start
    mov cx, hello_resumed_tail_prefix_len
    jmp short .publish
.identity:
    mov si, poc_ticket_identity
    mov cx, [hello_ticket_len_snapshot]
%endif
.publish:
    mov [hello_pending_ptr], si
    mov [hello_pending_len], cx
    mov byte [hello_pending], 1
    cmp byte [hello_hash_enabled], 0
    je .return_fragment
    push si
    push cx
    cmp byte [hello_segment], 0
    jne .hash
    add si, 5                         ; record header is not transcript data
    sub cx, 5
.hash:
    call sha256_update
    pop cx
    pop si
.return_fragment:
    mov ax, 1
    clc
    ret
.repeat_pending:
    mov si, [hello_pending_ptr]
    mov cx, [hello_pending_len]
    mov ax, 1
    clc
    ret
.at_end:
    xor ax, ax
    xor cx, cx
    clc
    ret
.failed:
    stc
    ret

hello_fragment_consumed:
    jmp short hello_advance_pending

; This entry is intentionally distinct from fragment_consumed: it advances an
; iterator fragment that was hashed during an offline pass without claiming
; that the bytes reached TCP.
hello_fragment_prehashed:
    cmp byte [hello_hash_enabled], 1
    jne hello_advance_failed

hello_advance_pending:
    cmp byte [hello_phase], hello_phase_tx
    jne hello_advance_failed
    cmp byte [hello_pending], 1
    jne hello_advance_failed
    mov byte [hello_pending], 0
    inc byte [hello_segment]
    xor ax, ax
    mov al, [hello_segment]
    mov bl, hello_fresh_fragment_count
%ifndef HELLO_FRESH_ONLY
    cmp byte [hello_mode], hello_mode_fresh
    je .check_done
    mov bl, hello_resumed_fragment_count
%endif
.check_done:
    cmp al, bl
    jb .ok
    mov byte [hello_phase], hello_phase_tx_done
    mov byte [hello_hash_enabled], 0
.ok:
    clc
    ret
hello_advance_failed:
    stc
    ret

hello_rewind:
    cmp byte [hello_phase], hello_phase_tx_done
    jne .failed
    mov byte [hello_phase], hello_phase_tx
    mov byte [hello_segment], 0
    mov byte [hello_pending], 0
    mov byte [hello_hash_enabled], 0
    clc
    ret
.failed:
    stc
    ret

%ifdef HELLO_RESUMED_EARLY_DATA
; PREPARE has already copied the truncated digest and binder before driving
; the normal iterator to TX_DONE.  The live SHA context now covers the exact
; ClientHello, including its binder.  It will not be reused after this
; offline-only entry, so finalize directly into the retired truncated slot.
hello_client_digest:
    cmp byte [hello_phase], hello_phase_tx_done
    jne hello_fail
    mov di, hello_truncated_digest
    call sha256_finish
    clc
    ret
%endif

; Relocate a published-but-unconsumed fragment when its builder aliases a
; lower-layer frame workspace.  The frozen length must still match.  A later
; hello_next_fragment returns this pointer/length without rebuild or rehash.
hello_relocate_pending:
    cmp byte [hello_phase], hello_phase_tx
    jne .failed
    cmp byte [hello_pending], 1
    jne .failed
    cmp cx, [hello_pending_len]
    jne .failed
    mov [hello_pending_ptr], si
    clc
    ret
.failed:
    stc
    ret

; ---------------------------------------------------------------------------
; Strict fixed-profile streaming ServerHello parser
; ---------------------------------------------------------------------------

; RFC 8446 leaves ServerHello extension order unconstrained.  The two live
; resumed shapes seen from the target edge differ only by swapping the
; six-byte supported_versions and pre_shared_key extensions around the fixed
; key_share.  Map the alternate wire positions onto the canonical comparison
; literals while retaining the real wire position in hello_server_pos.  The
; selector is fixed by the first differing type byte; an unknown type follows
; the canonical comparison and fails closed.  A duplicate versions or PSK
; extension is mapped to the opposite literal at the suffix and is rejected.
%macro hello_map_resumed_server_order 0
    cmp bx, 77
    jne %%order_known
    cmp al, 0x29
    jne %%order_known
    mov byte [hello_segment], 3
%%order_known:
    cmp byte [hello_segment], 3
    jne .server_shape_ready
    cmp bx, 82
    jb %%prefix
    cmp bx, 1210
    jb .server_shape_ready
    sub bx, 1210 - 76
    jmp short .server_shape_ready
%%prefix:
    cmp bx, 76
    jb .server_shape_ready
    add bx, 1210 - 76
    jmp short .server_shape_ready
%endmacro

hello_server_begin:
    cmp byte [hello_phase], hello_phase_tx_done
    jne .failed
    mov byte [hello_phase], hello_phase_rx
    ; TX no longer needs the fragment index.  Reuse it as the fresh
    ; ServerHello extension-order selector without growing mutable state:
    ; 0 = undecided, 1 = supported_versions first, 2 = key_share first.
    mov byte [hello_segment], 0
    mov byte [hello_status], 0
    mov word [hello_server_pos], 0
    mov byte [hello_hrr_difference], 0
    mov byte [hello_x_nonzero], 0
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, hello_server_x_work
    mov cx, 32
    rep stosb
    ; The low handoff aliases the final 96 bytes of ek while ClientHello is
    ; still being sent.  It becomes dead only after the caller acknowledges
    ; the final fragment, which hello_server_begin's phase gate enforces.
    mov di, poc_hello_handoff_start
    mov cx, poc_hello_handoff_end - poc_hello_handoff_start
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    clc
    ret
.failed:
    stc
    ret

hello_server_feed:
    cmp byte [hello_phase], hello_phase_rx
    jne .failed_direct
    or cx, cx
    jz .failed_direct
    cmp cx, hello_mss_max
    ja .failed_direct
    mov ax, [hello_server_pos]
    add ax, cx
    mov dx, hello_fresh_server_len
%ifndef HELLO_FRESH_ONLY
    cmp byte [hello_mode], hello_mode_fresh
    je .bound_ready
    mov dx, hello_resumed_server_len
%endif
.bound_ready:
    cmp ax, dx
    ja .failed_direct
    push si
    push cx
.next_byte:
    lodsb
    mov bx, [hello_server_pos]
    cmp bx, 6
    jb .header
    cmp bx, 38
    jb .random
    cmp bx, 39
    jb .session_len
    cmp bx, 71
    jb .session
    ; RFC 8446 does not assign semantic meaning to ServerHello extension
    ; order.  OpenAI's edge has emitted both legal fixed-profile layouts:
    ;
    ;   supported_versions || key_share || exchange
    ;   key_share || exchange || supported_versions
    ;
    ; Accept exactly those two byte shapes.  For key_share-first, map the
    ; current wire position in BX onto the canonical versions-first position;
    ; the existing strict comparisons and c/X copy offsets can then stay
    ; shared.  hello_server_pos retains the real wire position.
%ifdef HELLO_RESUMED_ONLY
    hello_map_resumed_server_order
%else
%ifndef HELLO_FRESH_ONLY
    cmp byte [hello_mode], hello_mode_resumed
    jne .fresh_order_check
    hello_map_resumed_server_order
%endif
.fresh_order_check:
    cmp bx, 77
    jne .fresh_order_known
    cmp al, 0x2b
    je .fresh_versions_first
    cmp al, 0x33
    jne .failed_stacked
    mov byte [hello_segment], 2
    jmp short .fresh_order_known
.fresh_versions_first:
    mov byte [hello_segment], 1
.fresh_order_known:
    cmp byte [hello_segment], 2
    jne .server_shape_ready
    cmp bx, 1204
    jae .fresh_versions_tail
    add bx, 6
    jmp short .server_shape_ready
.fresh_versions_tail:
    sub bx, 1128
%endif
.server_shape_ready:
    cmp bx, 90
    jb .middle
    cmp bx, 1178
    jb .ciphertext
    cmp bx, 1210
    jb .server_x
%ifdef HELLO_FRESH_ONLY
    jmp .failed_stacked
%else
    cmp byte [hello_mode], hello_mode_resumed
    jne .failed_stacked
    mov di, bx
    sub di, 1210
    cmp al, [hello_server_psk_suffix + di]
    jne .failed_stacked
    jmp .accepted_byte
%endif
.header:
    mov di, hello_server_fresh_header
%ifndef HELLO_FRESH_ONLY
    cmp byte [hello_mode], hello_mode_fresh
    je .header_selected
    mov di, hello_server_resumed_header
%endif
.header_selected:
    cmp al, [di + bx]
    jne .failed_stacked
    jmp .accepted_byte
.random:
    mov di, bx
    sub di, 6
    mov ah, [hello_hrr_random + di]
    xor ah, al
    or [hello_hrr_difference], ah
    jmp .accepted_byte
.session_len:
    cmp al, 32
    jne .failed_stacked
    jmp .accepted_byte
.session:
    mov di, bx
    sub di, 39
    cmp al, [hello_session + di]
    jne .failed_stacked
    jmp .accepted_byte
.middle:
    mov di, hello_server_fresh_middle
%ifndef HELLO_FRESH_ONLY
    cmp byte [hello_mode], hello_mode_fresh
    je .middle_selected
    mov di, hello_server_resumed_middle
%endif
.middle_selected:
    sub bx, 71
    cmp al, [di + bx]
    jne .failed_stacked
    jmp .accepted_byte
.ciphertext:
    mov di, bx
    sub di, 90
    mov [poc_mlkem_ciphertext + di], al
    jmp .accepted_byte
.server_x:
    mov di, bx
    sub di, 1178
    mov [hello_server_x_work + di], al
    or [hello_x_nonzero], al
.accepted_byte:
    inc word [hello_server_pos]
    dec cx
    jz .chunk_valid
    jmp .next_byte
.chunk_valid:
    pop cx
    pop si
    ; Hash the exact input chunk after its full structural validation/copy.
    call sha256_update
    clc
    ret
.failed_stacked:
    pop cx
    pop si
    jmp hello_fail
.failed_direct:
    jmp hello_fail

hello_server_finish:
    cmp byte [hello_phase], hello_phase_rx
    jne .failed
    mov ax, hello_fresh_server_len
%ifndef HELLO_FRESH_ONLY
    cmp byte [hello_mode], hello_mode_fresh
    je .length_ready
    mov ax, hello_resumed_server_len
%endif
.length_ready:
    cmp [hello_server_pos], ax
    jne .failed
    cmp byte [hello_hrr_difference], 0
    je .failed
    cmp byte [hello_x_nonzero], 0
    je .failed
    call hello_export_transcript_context
    mov di, hello_transcript_digest
    call sha256_finish
    push si
    push di
    push cx
    push es
    push ds
    pop es
    mov si, hello_server_x_work
    mov di, hello_server_x25519
    mov cx, 32
    rep movsb
    pop es
    pop cx
    pop di
    pop si
    mov byte [hello_status], 1
    mov byte [hello_phase], hello_phase_complete
    clc
    ret
.failed:
    jmp hello_fail

; Publish a fixed-format live SHA-256 context before sha256_finish pads and
; consumes it.  The symmetric overlay imports this state after the candidate
; and eight-sector delta reload, avoiding a 2,586-byte CH||SH replay.
hello_export_transcript_context:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, poc_hello_ctx_magic
    mov ax, 0x3154                    ; "T1"
    stosw
    mov ax, 0x4333                    ; "3C"
    stosw
    mov al, 1
    stosb
    mov al, [sha256_block_len]
    stosb
    mov ax, [sha256_len_low]
    stosw
    mov ax, [sha256_len_high]
    stosw
    mov si, sha256_state
    mov di, poc_hello_sha_state
    mov cx, 16
    rep movsw
    mov si, sha256_block
    mov di, poc_hello_sha_block
    mov cx, sha256_block_size
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

; ---------------------------------------------------------------------------
; Fixed-profile construction and resumption binder
; ---------------------------------------------------------------------------

%macro hello_binder_diagnostic 1
%ifdef HELLO_BINDER_DIAGNOSTIC
    mov al, %1
    call hello_binder_diagnostic_emit
%endif
%endmacro

%ifdef HELLO_BINDER_DIAGNOSTIC
%macro SHA256_FINISH_DIAGNOSTIC_MARK 1
    mov al, %1
    call hello_binder_diagnostic_emit
%endmacro
%macro SHA256_HMAC_DIAGNOSTIC_MARK 1
    mov al, %1
    call hello_binder_diagnostic_emit
%endmacro
%endif

hello_build_prefix:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, hello_tx_build_start
    mov al, 0x16
    stosb
    mov ax, 0x0103                    ; writes wire 03 01
    stosw
    mov ax, [hello_message_len]
    xchg al, ah
    stosw
    mov al, 1
    stosb
    xor al, al                        ; uint24 high byte
    stosb
    mov ax, [hello_message_len]
    sub ax, 4
    xchg al, ah
    stosw
    mov ax, 0x0303
    xchg al, ah
    stosw
    mov si, hello_random
    mov cx, 32
    rep movsb
    mov al, 32
    stosb
    mov si, hello_session
    mov cx, 32
    rep movsb
    mov si, hello_client_fixed_vectors
    mov cx, hello_client_fixed_vectors_len
    rep movsb
    mov ax, [hello_extensions_len]
    xchg al, ah
    stosw
    mov si, hello_prefix_extensions
    mov cx, hello_prefix_extensions_len
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

%ifdef HELLO_DYNAMIC_X25519
; Build the one contiguous tail fragment from the frozen RFC 7748 share and
; the immutable product suffix.  Every non-dynamic image retains the fixed-u=9
; bytes byte-for-byte, while this path neither stores nor publishes them.
hello_build_dynamic_fresh_tail:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, hello_tx_build_start
    mov si, hello_dynamic_x25519_snapshot
    mov cx, hello_dynamic_x25519_len
    rep movsb
    mov si, hello_fresh_tail_suffix
    mov cx, hello_fresh_tail_suffix_len
    rep movsb
%ifdef HELLO_FRESH_TICKET_REQUEST
    mov si, hello_psk_modes_extension
    mov cx, hello_psk_modes_extension_len
    rep movsb
%endif
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret
%endif

%ifndef HELLO_FRESH_ONLY
hello_build_resumed_tail_prefix:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, hello_tx_build_start
%ifdef HELLO_DYNAMIC_X25519
    mov si, hello_dynamic_x25519_snapshot
    mov cx, hello_dynamic_x25519_len
    rep movsb
    mov si, hello_fresh_tail_suffix
    mov cx, hello_fresh_tail_suffix_len
%else
    mov si, hello_fresh_tail
    mov cx, hello_fresh_tail_len
%endif
    rep movsb
    mov si, hello_psk_modes_extension
    mov cx, hello_psk_modes_extension_len
    rep movsb
%ifdef HELLO_RESUMED_EARLY_DATA
    mov si, hello_early_data_extension
    mov cx, hello_early_data_extension_len
    rep movsb
%endif
    mov ax, 0x2900                    ; extension type 0x0029
    stosw
    mov ax, [hello_ticket_len_snapshot]
    add ax, 43
    xchg al, ah
    stosw
    mov ax, [hello_ticket_len_snapshot]
    add ax, 6
    xchg al, ah
    stosw
    mov ax, [hello_ticket_len_snapshot]
    xchg al, ah
    stosw
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

hello_build_resumed_suffix:
    push ax
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov di, hello_tx_build_start
    mov si, hello_age
    mov cx, 4
    rep movsb
    mov ax, 0x2100                    ; binder vector length 33
    stosw
    mov al, 32
    stosb
    mov si, hello_secret_b            ; final binder
    mov cx, 32
    rep movsb
    pop es
    pop di
    pop si
    pop cx
    pop ax
    ret

hello_make_binder:
    hello_binder_diagnostic 'n'
    ; Transcript-Hash(ClientHelloTruncated): full encoded lengths are present,
    ; but the binders vector itself is omitted as required by RFC 8446.
    call hello_build_prefix
    hello_binder_diagnostic 'a'
    call sha256_init
    hello_binder_diagnostic 'b'
    mov si, hello_tx_build_start + 5
    mov cx, hello_prefix_fragment_len - 5
    call sha256_update
    hello_binder_diagnostic 'c'
    mov si, poc_mlkem_ek
    mov cx, poc_mlkem_ek_len
    call sha256_update
    hello_binder_diagnostic 'd'
    call hello_build_resumed_tail_prefix
    hello_binder_diagnostic 'e'
    mov si, hello_tx_build_start
    mov cx, hello_resumed_tail_prefix_len
    call sha256_update
    hello_binder_diagnostic 'f'
    mov si, poc_ticket_identity
    mov cx, [hello_ticket_len_snapshot]
    call sha256_update
    hello_binder_diagnostic 'g'
    mov si, hello_age
    mov cx, 4
    call sha256_update
    hello_binder_diagnostic 'h'
%ifdef HELLO_BINDER_DIAGNOSTIC
    ; The live OpenAI ticket makes the expected 1,586-byte truncated
    ; transcript residual exactly 50 (ASCII "2").  Emit the byte itself so a
    ; corrupt block count is distinguishable without exposing transcript data.
    mov al, [sha256_block_len]
    call hello_binder_diagnostic_emit
%endif
    mov di, hello_truncated_digest
    call sha256_finish
    hello_binder_diagnostic 'o'

    ; early_secret = HKDF-Extract(zeros, PSK)
    mov si, hello_zeros
    mov bx, hello_input_ticket_psk
    mov cx, 32
    mov di, hello_secret_a
    call hello_hmac_once
    jc .done
    hello_binder_diagnostic 'p'

    ; binder_key = Derive-Secret(early_secret, "res binder", Hash(""))
    mov si, hello_secret_a
    mov bx, hello_label_res_binder
    mov cx, hello_label_res_binder_len
    mov dx, hello_empty_hash
    mov ax, 32
    mov di, hello_secret_b
    call hello_expand_label
    jc .done
    hello_binder_diagnostic 'q'

    ; finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
    mov si, hello_secret_b
    mov bx, hello_label_finished
    mov cx, hello_label_finished_len
    mov dx, hello_empty_context
    xor ax, ax
    mov di, hello_secret_a
    call hello_expand_label
    jc .done
    hello_binder_diagnostic 'r'

    ; binder = HMAC(finished_key, Transcript-Hash(ClientHelloTruncated)).
    mov si, hello_secret_a
    mov bx, hello_truncated_digest
    mov cx, 32
    mov di, hello_secret_b
    call hello_hmac_once
    hello_binder_diagnostic 's'
.done:
    ret

%ifdef HELLO_BINDER_DIAGNOSTIC
hello_binder_diagnostic_emit:
    pushf
    push ax
    push cx
    push dx
    mov ah, al
    mov dx, 0x03fd
    xor cx, cx
.wait:
    in al, dx
    test al, 0x20
    loopz .wait
    mov dl, 0xf8
    mov al, ah
    out dx, al
    pop dx
    pop cx
    pop ax
    popf
    ret
%endif

; SI=secret32, BX=label, CX=label length, DX=context, AX=context length,
; DI=32-byte output.
hello_expand_label:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    mov [hello_expand_output], di
    mov [hello_expand_context], dx
    mov [hello_expand_context_len], ax
    mov [hmac_key_ptr], si
    mov word [hmac_key_len], 32
    call hmac_prepare_current_key_context
    jc .done
    push ds
    pop es
    mov di, hello_hkdf_info
    mov ax, 0x2000                    ; output uint16 = 32, wire order
    stosw
    mov al, hello_label_prefix_len
    add al, cl
    stosb
    mov si, hello_label_prefix
    push cx
    mov cx, hello_label_prefix_len
    rep movsb
    pop cx
    mov si, bx
    rep movsb
    mov ax, [hello_expand_context_len]
    stosb
    mov si, [hello_expand_context]
    mov cx, ax
    rep movsb
    mov al, 1
    stosb
    mov ax, di
    sub ax, hello_hkdf_info
    mov word [hmac_data1_ptr], hello_hkdf_info
    mov [hmac_data1_len], ax
    mov word [hmac_data2_len], 0
    mov word [hmac_output_ptr], hello_hkdf_block
    call hmac_sha256_prepared
    jc .done
    mov si, hello_hkdf_block
    mov di, [hello_expand_output]
    mov cx, 32
    rep movsb
    clc
.done:
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; SI=key32, BX=data, CX=data length, DI=output32.
hello_hmac_once:
    mov [hmac_key_ptr], si
    mov word [hmac_key_len], 32
    mov [hmac_data1_ptr], bx
    mov [hmac_data1_len], cx
    mov word [hmac_data2_len], 0
    mov [hmac_output_ptr], di
    call hmac_prepare_current_key_context
    jc .done
    jmp hmac_sha256_prepared
.done:
    ret
%endif

hello_fail:
    mov byte [hello_phase], hello_phase_failed
    mov byte [hello_status], 0
    stc
    ret

hello_clear:
    cld
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, poc_rx_frame_start
    mov cx, poc_rx_frame_max_len
    rep stosb
    mov di, poc_mlkem_ciphertext
    ; The same low object held the longer ek before c; clear the union.
    mov cx, poc_mlkem_ek_len
    rep stosb
    mov di, hello_state_clear_start
    mov cx, hello_state_clear_end - hello_state_clear_start
    rep stosb
    mov di, poc_ticket_identity
    mov cx, hello_ticket_max
    rep stosb
    mov di, hello_sha_work_start
    mov cx, hello_sha_work_end - hello_sha_work_start
    rep stosb
    mov di, poc_hello_handoff_start
    mov cx, poc_hello_handoff_end - poc_hello_handoff_start
    rep stosb
    mov di, hello_input_random
    mov cx, hello_attempt_used_end - hello_input_random
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    clc
    ret

%ifdef HELLO_CACHED_CONNECT
%ifndef HELLO_FRESH_ONLY
%ifndef HELLO_RESUMED_ONLY
%error "cached connector requires an explicit fresh-only or resumed-only mode"
%endif
%endif
%define HELLO_CACHED_CONNECT_AUTO_3C501_PRIME 1
%include "hello_cached_connect.inc"
%undef HELLO_CACHED_CONNECT_AUTO_3C501_PRIME
%endif

; ---------------------------------------------------------------------------
; Shipping SHA-256/HMAC implementation and immutable profile constants
; ---------------------------------------------------------------------------

%include "core/sha256.inc"

hello_client_fixed_vectors:
    db 0x00,0x02,0x13,0x03           ; one fixed cipher
    db 0x01,0x00                     ; one null compression method
hello_client_fixed_vectors_len equ $ - hello_client_fixed_vectors

hello_prefix_extensions:
    ; server_name = api.openai.com
    db 0x00,0x00,0x00,0x13,0x00,0x11,0x00,0x00,0x0e
    db 'api.openai.com'
    ; supported_versions = TLS 1.3
    db 0x00,0x2b,0x00,0x03,0x02,0x03,0x04
    ; supported_groups = X25519MLKEM768 (0x11ec)
    db 0x00,0x0a,0x00,0x04,0x00,0x02,0x11,0xec
    ; signature_algorithms = ecdsa_secp256r1_sha256
    db 0x00,0x0d,0x00,0x04,0x00,0x02,0x04,0x03
    ; compress_certificate = Brotli
    db 0x00,0x1b,0x00,0x03,0x02,0x00,0x02
    ; one hybrid key_share entry: 1184-byte ek || fixed X25519 u=9
    db 0x00,0x33,0x04,0xc6,0x04,0xc4,0x11,0xec,0x04,0xc0
hello_prefix_extensions_len equ $ - hello_prefix_extensions

hello_fresh_tail:
%ifndef HELLO_DYNAMIC_X25519
    db 0x09
    times 31 db 0
%endif
hello_fresh_tail_suffix:
%ifdef TLS13_PRODUCT_TLS13
    ; record_size_limit = 2048.  Keep it ahead of padding and, on resumed
    ; handshakes, ahead of the mandatory-final pre_shared_key extension.
    db 0x00,0x1c,0x00,0x02,0x08,0x00
%endif
    db 0x00,0x15,0x00,0x0e
    times 14 db 0
%ifdef HELLO_DYNAMIC_X25519
hello_fresh_tail_len equ hello_dynamic_x25519_len + \
    ($ - hello_fresh_tail_suffix)
%else
hello_fresh_tail_len equ $ - hello_fresh_tail
%endif
hello_fresh_tail_suffix_len equ $ - hello_fresh_tail_suffix

%ifdef HELLO_FRESH_TICKET_REQUEST
%define HELLO_INCLUDE_PSK_MODES_BYTES 1
%else
%ifndef HELLO_FRESH_ONLY
%define HELLO_INCLUDE_PSK_MODES_BYTES 1
%endif
%endif

%ifdef HELLO_INCLUDE_PSK_MODES_BYTES
hello_psk_modes_extension:
    db 0x00,0x2d,0x00,0x02,0x01,0x01 ; psk_dhe_ke only
hello_psk_modes_extension_len equ $ - hello_psk_modes_extension
%endif

%ifdef HELLO_RESUMED_EARLY_DATA
hello_early_data_extension:
    db 0x00,0x2a,0x00,0x00           ; fixed replay-safe public HEAD only
hello_early_data_extension_len equ $ - hello_early_data_extension
%endif

hello_server_fresh_header:
    db 0x02,0x00,0x04,0xb6,0x03,0x03

%ifndef HELLO_FRESH_ONLY
hello_server_resumed_header:
    db 0x02,0x00,0x04,0xbc,0x03,0x03
%endif

hello_server_fresh_middle:
    db 0x13,0x03,0x00,0x04,0x6e
    db 0x00,0x2b,0x00,0x02,0x03,0x04
    db 0x00,0x33,0x04,0x64,0x11,0xec,0x04,0x60

%ifndef HELLO_FRESH_ONLY
hello_server_resumed_middle:
    db 0x13,0x03,0x00,0x04,0x74
    db 0x00,0x2b,0x00,0x02,0x03,0x04
    db 0x00,0x33,0x04,0x64,0x11,0xec,0x04,0x60
hello_server_psk_suffix:
    db 0x00,0x29,0x00,0x02,0x00,0x00 ; selected_identity = 0
%endif

; RFC 8446 HelloRetryRequest random.  The fixed one-shot profile rejects it.
hello_hrr_random:
    db 0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11
    db 0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91
    db 0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e
    db 0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c

%ifndef HELLO_FRESH_ONLY
hello_label_prefix db 'tls13 '
hello_label_prefix_len equ $ - hello_label_prefix
hello_label_res_binder db 'res binder'
hello_label_res_binder_len equ $ - hello_label_res_binder
hello_label_finished db 'finished'
hello_label_finished_len equ $ - hello_label_finished
hello_empty_context:
hello_empty_hash:
    db 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14
    db 0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24
    db 0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c
    db 0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
hello_zeros times 32 db 0
%endif

sha256_initial_state:
    dw 0xe667,0x6a09,0xae85,0xbb67
    dw 0xf372,0x3c6e,0xf53a,0xa54f
    dw 0x527f,0x510e,0x688c,0x9b05
    dw 0xd9ab,0x1f83,0xcd19,0x5be0
sha256_k:
    dw 0x2f98,0x428a,0x4491,0x7137
    dw 0xfbcf,0xb5c0,0xdba5,0xe9b5
    dw 0xc25b,0x3956,0x11f1,0x59f1
    dw 0x82a4,0x923f,0x5ed5,0xab1c
    dw 0xaa98,0xd807,0x5b01,0x1283
    dw 0x85be,0x2431,0x7dc3,0x550c
    dw 0x5d74,0x72be,0xb1fe,0x80de
    dw 0x06a7,0x9bdc,0xf174,0xc19b
    dw 0x69c1,0xe49b,0x4786,0xefbe
    dw 0x9dc6,0x0fc1,0xa1cc,0x240c
    dw 0x2c6f,0x2de9,0x84aa,0x4a74
    dw 0xa9dc,0x5cb0,0x88da,0x76f9
    dw 0x5152,0x983e,0xc66d,0xa831
    dw 0x27c8,0xb003,0x7fc7,0xbf59
    dw 0x0bf3,0xc6e0,0x9147,0xd5a7
    dw 0x6351,0x06ca,0x2967,0x1429
    dw 0x0a85,0x27b7,0x2138,0x2e1b
    dw 0x6dfc,0x4d2c,0x0d13,0x5338
    dw 0x7354,0x650a,0x0abb,0x766a
    dw 0xc92e,0x81c2,0x2c85,0x9272
    dw 0xe8a1,0xa2bf,0x664b,0xa81a
    dw 0x8b70,0xc24b,0x51a3,0xc76c
    dw 0xe819,0xd192,0x0624,0xd699
    dw 0x3585,0xf40e,0xa070,0x106a
    dw 0xc116,0x19a4,0x6c08,0x1e37
    dw 0x774c,0x2748,0xbcb5,0x34b0
    dw 0x0cb3,0x391c,0xaa4a,0x4ed8
    dw 0xca4f,0x5b9c,0x6ff3,0x682e
    dw 0x82ee,0x748f,0x636f,0x78a5
    dw 0x7814,0x84c8,0x0208,0x8cc7
    dw 0xfffa,0x90be,0x6ceb,0xa450
    dw 0xa3f7,0xbef9,0x78f2,0xc671

hello_image_end:

; ---------------------------------------------------------------------------
; Mutable K work.  No mutable byte lives in the split high dk region.
; ---------------------------------------------------------------------------

; Keep mutable HELLO state out of the code/image prefix.  The current K14
; integration may preload the twelve-sector symmetric overlay before the SYN,
; replace its first nine sectors with HELLO, run the candidate, then restore
; those same nine sectors.  A code-adjacent state block would dirty the next
; preloaded symmetric suffix sector and make that delta still larger.
; K14 moves this 317-byte block below the resident nucleus, after the committed
; HELLO handoff, so ticket/SHA work can move down without changing the exact
; nine-sector symmetric delta restore.
%ifdef TLS13_POC_K14
hello_state_base equ 0x0dc0
%else
hello_state_base equ 0x3000
%endif
hello_state_clear_start equ hello_state_base
hello_phase equ hello_state_clear_start
hello_mode equ hello_phase + 1
hello_segment equ hello_mode + 1
hello_pending equ hello_segment + 1
hello_hash_enabled equ hello_pending + 1
hello_hrr_difference equ hello_hash_enabled + 1
hello_x_nonzero equ hello_hrr_difference + 1
hello_message_len equ hello_x_nonzero + 1
hello_extensions_len equ hello_message_len + 2
hello_pending_ptr equ hello_extensions_len + 2
hello_pending_len equ hello_pending_ptr + 2
hello_server_pos equ hello_pending_len + 2
hello_ticket_len_snapshot equ hello_server_pos + 2
hello_expand_output equ hello_ticket_len_snapshot + 2
hello_expand_context equ hello_expand_output + 2
hello_expand_context_len equ hello_expand_context + 2
hello_age equ hello_expand_context_len + 2
hello_random equ hello_age + 4
hello_session equ hello_random + 32
hello_truncated_digest equ hello_session + 32
hello_server_x_work equ hello_truncated_digest + 32
hello_secret_a equ hello_server_x_work + 32
hello_secret_b equ hello_secret_a + 32
%ifdef HELLO_DYNAMIC_X25519
; Server-share work is dead throughout ClientHello binder/send/replay and is
; cleared at hello_server_begin before it receives the peer share.  Reuse that
; exact block for the frozen client public share without growing mutable state.
hello_dynamic_x25519_snapshot equ hello_server_x_work
%if hello_dynamic_x25519_snapshot + hello_dynamic_x25519_len > hello_secret_a
%error "dynamic X25519 snapshot escapes its 32-byte mutable slot"
%endif
%endif
hello_hkdf_info equ hello_secret_b + 32
hello_hkdf_info_len equ 64
hello_hkdf_block equ hello_hkdf_info + hello_hkdf_info_len
hello_state_clear_end equ hello_hkdf_block + 32
hello_state_end equ hello_state_clear_end

; Ticket identity occupies the reserved decoded-u sector before the candidate.
; SHA/HMAC scratch follows it and ends below K's 0x3600 ceiling.
hello_sha_work_start equ poc_ticket_identity_end
sha256_state equ hello_sha_work_start
sha256_a equ sha256_state + 32
sha256_b equ sha256_a + 4
sha256_c equ sha256_b + 4
sha256_d equ sha256_c + 4
sha256_e equ sha256_d + 4
sha256_f equ sha256_e + 4
sha256_g equ sha256_f + 4
sha256_h equ sha256_g + 4
sha256_t1 equ sha256_h + 4
sha256_t2 equ sha256_t1 + 4
sha256_new_e equ sha256_t2 + 4
sha256_tmp equ sha256_new_e + 4
sha256_w_ptr equ sha256_tmp + 4
sha256_k_ptr equ sha256_w_ptr + 2
sha256_len_low equ sha256_k_ptr + 2
sha256_len_high equ sha256_len_low + 2
sha256_saved_len_low equ sha256_len_high + 2
sha256_saved_len_high equ sha256_saved_len_low + 2
sha256_bit_len0 equ sha256_saved_len_high + 2
sha256_bit_len1 equ sha256_bit_len0 + 2
sha256_bit_len2 equ sha256_bit_len1 + 2
sha256_bit_len3 equ sha256_bit_len2 + 2
sha256_digest_ptr equ sha256_bit_len3 + 2
hmac_key_ptr equ sha256_digest_ptr + 2
hmac_key_len equ hmac_key_ptr + 2
hmac_data1_ptr equ hmac_key_len + 2
hmac_data1_len equ hmac_data1_ptr + 2
hmac_data2_ptr equ hmac_data1_len + 2
hmac_data2_len equ hmac_data2_ptr + 2
hmac_output_ptr equ hmac_data2_len + 2
sha256_block_len equ hmac_output_ptr + 2
sha256_saved_block_len equ sha256_block_len + 1
sha256_schedule_count equ sha256_saved_block_len + 1
sha256_round_count equ sha256_schedule_count + 1
sha256_block equ sha256_round_count + 1
sha256_w equ sha256_block + sha256_block_size
sha256_saved_state equ sha256_w + sha256_k_len
sha256_saved_block equ sha256_saved_state + 32
hmac_ipad equ sha256_saved_block + sha256_block_size
hmac_opad equ hmac_ipad + sha256_block_size
hmac_inner_digest equ hmac_opad + sha256_block_size
hmac_prepared_inner_state equ hmac_inner_digest + 32
hmac_prepared_outer_state equ hmac_prepared_inner_state + 32
hello_sha_work_end equ hmac_prepared_outer_state + 32

%ifdef TLS13_POC_K14
%if hello_state_base < poc_hello_handoff_end
%error "K14 hello state overlaps the committed transcript handoff"
%endif
%if hello_state_end > poc_low_scratch_end
%error "K14 hello state reaches the resident nucleus"
%endif
%else
%if (hello_image_end - hello_overlay_header) > \
    (hello_state_base - poc_k_start)
%error "hello immutable image overlaps mutable state"
%endif
%endif
%if hello_state_end > poc_ticket_identity
%error "hello state reaches the reserved ticket identity"
%endif
%if hello_sha_work_start != poc_ticket_identity_end
%error "hello SHA work must follow the bounded ticket identity"
%endif
%if hello_sha_work_end > poc_k_end
%error "hello code/work exceeds the 15-sector K window"
%endif
%ifdef HELLO_SYSTEM_RAM_INPUTS
%if hello_input_random != 0x0560 || hello_attempt_used_end != 0x05a0
%error "system-RAM HELLO input ABI drifted"
%endif
%elifdef HELLO_SYSTEM_RAM_RESUME_INPUTS
%if hello_input_random != 0x3420 || hello_attempt_used_end != 0x3486
%error "system-RAM resumed HELLO input ABI drifted"
%endif
%else
%if hello_attempt_used_end > poc_attempt_cache_end
%error "hello attempt-cache ABI reaches reconnect state"
%endif
%endif
%if poc_rx_frame_end > poc_mlkem_ek
%error "hello receive/fragment frame overlaps ek"
%endif
%if hello_prefix_fragment_len > hello_mss_max
%error "hello prefix fragment exceeds the advertised MSS"
%endif
%if hello_tx_build_start + hello_prefix_fragment_len > poc_rx_frame_end
%error "hello generated TX fragment exceeds the resident frame workspace"
%endif
%if hello_ticket_max > hello_mss_max
%error "hello ticket fragment exceeds the advertised MSS"
%endif
