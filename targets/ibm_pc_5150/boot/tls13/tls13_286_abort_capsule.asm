; Authenticated 286 escrow restore/private-state retirement capsule.
;
; A live Ethernet frame and the hybrid public object necessarily overwrite the
; three-sector bootstrap at 0000:0700.  HELLO therefore installs this
; independently authenticated, fixed-origin capsule at 0000:4040 before it
; acquires the NIC; the later flight/auth controllers reuse that exact copy.
; The band is above the root state and below the asymmetric module overlay.
;
; Both entries are tail jumps with the original controller caller's return
; address still on the stack.  Abort returns CF=1/AX=profile error.  Success
; requires the status-last ready byte, preserves only the already-published
; application key/IV/sequence span, restores the parent boundary, retires
; every private/executable overlay, and returns through the resident route-mode
; callback with CF=0.  A valid escrow is restored only after all magic,
; inverse, length, CRC, mode, crypto-base, and protected-low-state checks pass;
; any rejection takes the abort cleanup.

bits 16
cpu 8086
org 0x4040

%include "tls13/tls13_286_abi.inc"
%include "tls13-286-runtime-abi.inc"

capsule_header:
    db 'S286AB02'
    dw tls13_286_abi_version
    dw capsule_image_end - capsule_header
    dw capsule_abort_entry
    dw capsule_success_entry

capsule_abort_entry:
    xor bp, bp
    jmp short capsule_enter
capsule_success_entry:
    cmp byte [cs:TLS13_286_LINK_APP_READY], 1
    jne capsule_abort_entry
    mov bp, 1
capsule_enter:
    cld
    push cs
    pop ds
    push cs
    pop es
    ; Root authenticated the high caller SP before switching to the fixed
    ; tail stack.  Validate its status/inverse now and keep it in SI until the
    ; geometry inverse has been consumed below.
    cmp word [tls13_286_root_state_parent_sp_status_inv], 0xa55a
    jne capsule_parent_corrupt
    mov si, [tls13_286_root_state_parent_sp]
    mov dx, [tls13_286_root_state_parent_sp_inverse]
    not dx
    cmp si, dx
    jne capsule_parent_corrupt
    ; HELLO froze the bootstrap-validated geometry in this capsule before
    ; private-state consumption.  Resolve one bad/torn geometry word from the
    ; segment, its inverse, and the separate root-state copy.  In particular,
    ; cleanup never trusts a mutable BDA[0413] read after private state exists.
    mov bx, [tls13_286_root_state_crypto_seg]
    mov ax, [cs:capsule_crypto_seg]
    mov dx, [cs:capsule_crypto_seg_inverse]
    mov [cs:capsule_crypto_seg_inverse], si
    not dx
    cmp ax, dx
    je .geometry_bound
    cmp ax, bx
    je .geometry_selected
    cmp dx, bx
    jne capsule_retire
    mov ax, dx
.geometry_selected:
    mov [cs:capsule_crypto_seg], ax
.geometry_bound:
    cmp ax, bx
    jne capsule_retire

    mov ds, bx
    cmp word [tls13_286_escrow_magic_off], tls13_286_escrow_magic_lo
    jne capsule_retire_ds
    cmp word [tls13_286_escrow_magic_off + 2], tls13_286_escrow_magic_hi
    jne capsule_retire_ds
    cmp word [tls13_286_escrow_magic_inv_off], \
        tls13_286_escrow_magic_inv_lo
    jne capsule_retire_ds
    cmp word [tls13_286_escrow_magic_inv_off + 2], \
        tls13_286_escrow_magic_inv_hi
    jne capsule_retire_ds
    cmp byte [tls13_286_escrow_status_inv_off], \
        tls13_286_escrow_status_inverse
    jne capsule_retire_ds
    cmp byte [tls13_286_escrow_status_off], tls13_286_escrow_status_valid
    jne capsule_retire_ds
    cmp [tls13_286_escrow_crypto_seg_off], bx
    jne capsule_retire_ds
    mov al, [cs:tls13_286_root_state_mode]
    cmp [tls13_286_escrow_mode_off], al
    jne capsule_retire_ds

    mov si, tls13_286_escrow_config_off
    mov cx, tls13_286_escrow_config_bytes
    call capsule_crc16
    cmp ax, [tls13_286_escrow_config_crc_off]
    jne capsule_retire_ds
    mov si, tls13_286_escrow_low_off
    mov cx, tls13_286_escrow_low_bytes
    call capsule_crc16
    cmp ax, [tls13_286_escrow_low_crc_off]
    jne capsule_retire_ds
    mov si, tls13_286_prompt_off
    mov cx, tls13_286_prompt_max
    call capsule_crc16
    cmp ax, [tls13_286_escrow_prompt_crc_off]
    jne capsule_retire_ds
    mov al, [tls13_286_prompt_len_off]
    cmp al, [tls13_286_escrow_prompt_len_off]
    jne capsule_retire_ds
    mov ah, [tls13_286_escrow_prompt_len_inv_off]
    not ah
    cmp al, ah
    jne capsule_retire_ds

    ; Retire decoded code before publishing restored low state.  The capsule
    ; itself is outside all three spans.
    call capsule_wipe_low_overlays
    xor ax, ax
    mov es, ax
    mov si, tls13_286_escrow_config_off
    mov di, tls13_286_escrow_config_source
    mov cx, tls13_286_escrow_config_bytes
    rep movsb
    mov si, tls13_286_escrow_low_off
    mov di, tls13_286_escrow_low_source
    mov cx, tls13_286_escrow_low_bytes
    rep movsb
    mov si, tls13_286_prompt_off
    mov di, tls13_286_prompt_source
    mov cx, tls13_286_prompt_max
    rep movsb
    mov al, [tls13_286_prompt_len_off]
    mov [es:tls13_286_prompt_len_source], al
    jmp short capsule_wipe_high

capsule_retire_ds:
    push cs
    pop ds
capsule_retire:
    xor bp, bp
    call capsule_wipe_low_overlays

capsule_wipe_high:
    mov ax, [cs:capsule_crypto_seg]
    or ax, ax
    jz .return
    mov es, ax
    xor di, di
    xor ax, ax
    mov cx, tls13_286_high_reserve_bytes / 2
    rep stosw
.return:
    ; BX has retained the independently bound crypto segment since entry. The
    ; cache shadow is the fixed arena-excluded band immediately below it.
    sub bx, tls13_286_loop_shadow_seg_delta
    mov ds, ax
    mov es, ax
    ; Resume the resident caller on the exact stack frame frozen before the
    ; tail switch.  Once SP is high, retire module code and the complete low
    ; guard in one pass without touching a live return address.
    mov dx, [cs:capsule_crypto_seg_inverse]
    cli
    mov sp, dx
    mov di, tls13_286_module_load
    mov cx, (tls13_286_tail_stack_top - tls13_286_module_load) / 2
    rep stosw
    sti
    ; Restore the DPI gate while DS still names resident state, then authenticate
    ; the immutable RAM shadow. The resident copy thunk runs outside 0x4000..
    ; 0x79ff, so it may safely overwrite this capsule and return directly through
    ; the original scheduler frame. No floppy operation occurs on this path.
    call TLS13_286_LINK_ROUTE_MODE
    mov di, ax
    mov ds, bx
    mov si, tls13_286_loop_shadow_data_off
    mov cx, tls13_286_loop_shadow_data_bytes
    call capsule_crc16
    cmp ax, [tls13_286_loop_shadow_crc_off]
    jne .shadow_failed
    mov ax, di
    mov si, tls13_286_loop_shadow_data_off
    mov di, tls13_286_loop_cache_low
    mov cx, tls13_286_loop_shadow_data_bytes / 2
    mov bx, tls13_286_loop_cache_entries
    jmp TLS13_286_LINK_RESTORE_LOOP_CACHE_SHADOW
.shadow_failed:
    push es
    pop ds
    mov ax, tls13_286_error_profile
    stc
    ret

capsule_parent_corrupt:
    ; No trustworthy return frame remains.  Continuing on the temporary tail
    ; stack could redirect execution into retired key material, so reset at
    ; the architectural vector instead of attempting a best-effort return.
    cli
    jmp 0xffff:0x0000

capsule_wipe_low_overlays:
    xor ax, ax
    mov es, ax
    cmp bp, 1
    je .wipe_prefix
    mov di, TLS13_286_LINK_APP_CLIENT_KEY
    mov cx, (capsule_app_state_end - TLS13_286_LINK_APP_CLIENT_KEY) / 2
    rep stosw
.wipe_prefix:
    mov di, tls13_286_controller_load
    mov cx, (TLS13_286_LINK_APP_CLIENT_KEY - \
        tls13_286_controller_load) / 2
    rep stosw
    mov di, capsule_app_state_end
    mov cx, (0x3c00 - capsule_app_state_end) / 2
    rep stosw
    mov di, tls13_286_controller_handoff
    mov cx, (tls13_286_abort_capsule_load - \
        tls13_286_controller_handoff) / 2
    rep stosw
    ret

capsule_crc16:
    mov ax, 0xffff
    mov dx, cx
.byte:
    or dx, dx
    jz .done
    xor ah, [si]
    inc si
    mov cx, 8
.bit:
    shl ax, 1
    jnc .plain
    xor ax, 0x1021
.plain:
    loop .bit
    dec dx
    jmp .byte
.done:
    ret

times (tls13_286_abort_capsule_crypto_seg - tls13_286_abort_capsule_load) - \
    ($ - $$) db 0
%if ($ - $$) != \
    (tls13_286_abort_capsule_crypto_seg - tls13_286_abort_capsule_load)
%error "TLS 1.3 286 abort capsule geometry tail moved"
%endif
capsule_crypto_seg dw 0
capsule_crypto_seg_inverse dw 0
capsule_image_end:

capsule_app_state_end equ TLS13_286_LINK_APP_SERVER_SEQ + 8

%if TLS13_286_LINK_APP_SERVER_KEY != TLS13_286_LINK_APP_CLIENT_KEY + 32
%error "TLS 1.3 286 application keys are no longer contiguous"
%endif
%if TLS13_286_LINK_APP_CLIENT_IV != TLS13_286_LINK_APP_SERVER_KEY + 32
%error "TLS 1.3 286 application IVs moved away from the key span"
%endif
%if TLS13_286_LINK_APP_SERVER_IV != TLS13_286_LINK_APP_CLIENT_IV + 12
%error "TLS 1.3 286 application IVs are no longer contiguous"
%endif
%if TLS13_286_LINK_APP_CLIENT_SEQ != TLS13_286_LINK_APP_SERVER_IV + 12
%error "TLS 1.3 286 application sequences moved away from the IV span"
%endif
%if TLS13_286_LINK_APP_SERVER_SEQ != TLS13_286_LINK_APP_CLIENT_SEQ + 8
%error "TLS 1.3 286 application sequences are no longer contiguous"
%endif
%if TLS13_286_LINK_APP_CLIENT_KEY < tls13_286_controller_load
%error "TLS 1.3 286 application state moved below the controller window"
%endif
%if capsule_app_state_end > 0x3c00
%error "TLS 1.3 286 application state escaped the success-preserve span"
%endif
%if ((TLS13_286_LINK_APP_CLIENT_KEY - tls13_286_controller_load) & 1) || \
    ((capsule_app_state_end - TLS13_286_LINK_APP_CLIENT_KEY) & 1)
%error "TLS 1.3 286 application state is not word-aligned for retirement"
%endif
%if TLS13_286_LINK_APP_READY >= tls13_286_controller_load
%error "TLS 1.3 286 application-ready byte escaped resident low state"
%endif
%if TLS13_286_LINK_ROUTE_MODE >= tls13_286_controller_load
%error "TLS 1.3 286 route-mode callback escaped resident low code"
%endif

%if (capsule_header - $$) != 0
%error "TLS 1.3 286 abort capsule origin moved"
%endif
%if (capsule_image_end - $$) > \
    (tls13_286_abort_capsule_limit - tls13_286_abort_capsule_load)
%error "TLS 1.3 286 abort capsule exceeds 0x4040..41ff"
%endif
