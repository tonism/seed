; Seed TLS 1.3 same-boot resumption deferred-FO worker.
;
; RSD1 exposes a one-sector direct broker at 0x3000.  It validates only the
; fixed op-7 publication edge, cold-loads the three-sector controller at
; 0x2400..0x29ff, restores AX=7, and tail-enters it.  The controller remains
; above the exact six-sector FO image and outside all FO mutable work.
;
; Before FO, both 128-byte candidate copies are read and compared.  The
; measured FO image and its working span end below 0x3400; the immutable
; resident abort capsule at 0x3510..0x35ff is never written by this path.  The
; controller restores the tentative ticket, RSU1 scatter, and the outer
; continuation, wipes and verifies page 0x7e, then tail-enters a low trampoline
; which restores the complete K14 symmetric image.  Only that trampoline may
; publish the FO inverse/status bytes and return to RSU1.
;
; Any failure after FO begins is terminal and jumps the resident persistent
; abort entry directly.  It neither reloads a recovery phase nor falls back to
; HLT.  No post-FO path returns through overwritten state.

bits 16
cpu 8086

%include "post_auth_resume_vault.inc"

%ifndef RESUME_FO_LOAD_PHASE
%error "resumption FO requires the resident phase loader"
%endif
%ifndef RESUME_FO_NE_BUF_READ
%error "resumption FO requires the guarded NE2000 read leaf"
%endif
%ifndef RESUME_FO_NE_BUF_LOAD
%error "resumption FO requires the guarded NE2000 write leaf"
%endif
%ifndef RESUME_FO_NIC_BASE
%error "resumption FO requires the resident NIC-base word"
%endif
%ifndef RESUME_FO_NE_TX_START
%error "resumption FO requires the resident NE transmit-page byte"
%endif
%ifndef RESUME_FO_CONTROLLER_LIMIT
%define RESUME_FO_CONTROLLER_LIMIT 0x0600
%endif

fo_candidate_generation       equ 0x3c66
fo_candidate_c_sum            equ 0x3c68
fo_candidate_ek_sum           equ 0x3c6a
fo_candidate_inverse          equ 0x3c6c
fo_candidate_status           equ 0x3c6d
fo_generation                 equ 0x3c6e
fo_c_sum                      equ 0x3c70
fo_ek_sum                     equ 0x3c72
fo_inverse                    equ 0x3c74
fo_status                     equ 0x3c75

%ifdef RESUME_FO_BROKER

%ifndef RESUME_FO_CONTROLLER_KEY
%error "resumption FO broker requires the fixed controller key"
%endif
%ifndef RESUME_FO_CONTROLLER_ENTRY
%define RESUME_FO_CONTROLLER_ENTRY 0x2400
%endif
%ifdef RESUME_FO_VAULT_ACCESS_KEY
%ifndef RESUME_FO_VAULT_ACCESS_STAGE
%error "resumption FO access repin requires a fixed stage"
%endif
%endif

org 0x3000

resume_fo_broker_entry:
    jmp short resume_fo_broker_code
resume_fo_broker_header:
    db 'RFB1'
    dw 1
    dw resume_fo_broker_end - $$
    dw 0x3000
    dw resume_fo_broker_entry

resume_fo_broker_code:
    cld
    cmp ax, 7
    jne resume_fo_broker_failed
    cmp byte [resume_vault_lifecycle_status], \
        resume_vault_lifecycle_valid
    jne resume_fo_broker_failed
    cmp byte [resume_vault_lifecycle_inverse], \
        resume_vault_lifecycle_valid_inverse
    jne resume_fo_broker_failed
    cmp byte [fo_candidate_status], 0xa5
    jne resume_fo_broker_failed
    cmp byte [fo_candidate_inverse], 0x5a
    jne resume_fo_broker_failed
%ifdef RESUME_FO_VAULT_ACCESS_KEY
    ; EXCHANGE restored the complete symmetric image and deliberately retired
    ; the overlapping 0x2c00 lease.  Full symmetric work is now complete, so
    ; pin a fresh measured access image before the first FO card callback.
    mov ax, RESUME_FO_VAULT_ACCESS_KEY
    mov bx, RESUME_FO_VAULT_ACCESS_STAGE
    call RESUME_FO_LOAD_PHASE
    jc resume_fo_broker_failed
%endif
    mov ax, RESUME_FO_CONTROLLER_KEY
    mov bx, RESUME_FO_CONTROLLER_ENTRY
    call RESUME_FO_LOAD_PHASE
    jc resume_fo_broker_failed
    mov ax, 7
    mov dx, RESUME_FO_CONTROLLER_ENTRY
    jmp dx

resume_fo_broker_failed:
    xor ax, ax
    stc
    ret

resume_fo_broker_end:

%if (resume_fo_broker_header - resume_fo_broker_entry) != 2
%error "resumption FO broker header moved"
%endif
%if ($ - $$) > 0x0200
%error "resumption FO broker exceeds one sector"
%endif

%elifdef RESUME_FO_CONTROLLER

%ifndef RESUME_FO_KERNEL_KEY
%error "resumption FO controller requires the unchanged FO kernel key"
%endif
%ifndef RESUME_FO_KERNEL_ENTRY
%define RESUME_FO_KERNEL_ENTRY 0x1800
%endif
%ifndef RESUME_FO_SYM_RESTORE_KEY
%error "resumption FO controller requires the complete K14 restore"
%endif
%ifndef RESUME_FO_RECOVERY_FAIL
%error "resumption FO controller requires the persistent abort entry"
%endif
%ifndef RESUME_FO_RSU_HEAD_KEY
%error "resumption FO controller requires the RSU1 head key"
%endif
%ifndef RESUME_FO_RSU_TAIL_KEY
%error "resumption FO controller requires the RSU1 tail key"
%endif
%ifndef RESUME_FO_RSU_LOW_BYTES
%error "resumption FO controller requires exact RSU1 low bytes"
%endif
%ifndef RESUME_FO_RSU_LOW_START
%error "resumption FO controller requires fixed RSU1 low start"
%endif
%ifndef RESUME_FO_RSU_PREFIX_BYTES
%error "resumption FO controller requires exact RSU1 prefix bytes"
%endif
%ifndef RESUME_FO_RSU_PREFIX_START
%error "resumption FO controller requires fixed RSU1 prefix start"
%endif
%ifndef RESUME_FO_RSU_SUFFIX_BYTES
%error "resumption FO controller requires exact RSU1 suffix bytes"
%endif
%ifndef RESUME_FO_RSU_SUFFIX_START
%error "resumption FO controller requires fixed RSU1 suffix start"
%endif
%ifndef RESUME_FO_SUPERVISOR_KEY
%error "resumption FO controller requires the fixed supervisor key"
%endif
%ifndef RESUME_FO_SUPERVISOR_TRANSITION_SOURCE
%error "resumption FO controller requires the supervisor transition source"
%endif
%ifndef RESUME_FO_SUPERVISOR_TRANSITION_BYTES
%error "resumption FO controller requires exact supervisor transition bytes"
%endif
%ifndef RESUME_FO_SUPERVISOR_TRANSITION_DEST
%define RESUME_FO_SUPERVISOR_TRANSITION_DEST 0x0f00
%endif

org 0x2400

fo_candidate_a_buffer         equ 0x0d00
fo_candidate_b_buffer         equ 0x0d80
fo_page_buffer                equ 0x0d00
fo_readback_buffer            equ 0x0e00
fo_expected_k                 equ 0x0700
fo_message                    equ 0x3a40
fo_candidate_g                equ 0x3b9c
fo_ticket_psk                 equ 0x38b0
fo_ticket_identity            equ 0x3b40
fo_ticket_tail                equ 0x3c00
fo_ticket_present             equ 0x3c2c
fo_stage                      equ 0x3000
fo_low_transition             equ 0x0d00

resume_fo_controller_entry:
    jmp short resume_fo_controller_code
resume_fo_controller_header:
    db 'RFC1'
    dw 1
    dw resume_fo_controller_end - $$
    dw 0x2400
    dw resume_fo_controller_entry

resume_fo_controller_code:
    cld
    push es
    push ds
    pop es
    mov byte [fo_status], 0
    mov byte [fo_inverse], 0
    cmp ax, 7
    jne resume_fo_pre_failed
    call resume_fo_validate_publication
    jc resume_fo_pre_failed

    ; Verify both independently committed candidate halves before admitting
    ; FO.  Page 0x7e is retired and verified zero only after proof succeeds.
    mov bx, resume_card_candidate_a
    mov cx, resume_card_candidate_len
    mov di, fo_candidate_a_buffer
    call RESUME_FO_NE_BUF_READ
    jc resume_fo_pre_failed
    mov bx, resume_card_candidate_b
    mov cx, resume_card_candidate_len
    mov di, fo_candidate_b_buffer
    call RESUME_FO_NE_BUF_READ
    jc resume_fo_pre_failed
    mov si, fo_candidate_a_buffer
    mov di, fo_candidate_b_buffer
    mov cx, resume_card_candidate_len / 2
    xor dx, dx
.candidate_compare:
    lodsw
    xor ax, [di]
    or dx, ax
    add di, 2
    loop .candidate_compare
    or dx, dx
    jnz resume_fo_pre_failed

    ; Scatter m' || K' || r' || z into the unchanged FO ABI and retain an
    ; independent expected K' in the FO kernel's preserved low ticket hold.
    mov si, fo_candidate_a_buffer
    mov di, fo_message
    mov cx, 16
    rep movsw
    mov si, fo_candidate_a_buffer + 32
    mov di, fo_expected_k
    mov cx, 16
    rep movsw
    mov si, fo_candidate_a_buffer + 32
    mov di, fo_candidate_g
    mov cx, 48
    rep movsw

    mov word [resume_fo_ek_seen], 0
    mov word [resume_fo_c_seen], 0
    mov word [resume_fo_ek_running_sum], 0
    mov word [resume_fo_c_running_sum], 0

    ; The six-sector image ends exactly at this controller's 0x2400 origin.
    mov ax, RESUME_FO_KERNEL_KEY
    mov bx, RESUME_FO_KERNEL_ENTRY
    call RESUME_FO_LOAD_PHASE
    jc resume_fo_pre_failed
    mov bx, resume_fo_card_read_callback
    call RESUME_FO_KERNEL_ENTRY

    ; FO has now destroyed RSU1 low state.  Its measured upper clobber span
    ; ends below 0x3400, leaving the resident 0x3510..0x35ff abort capsule
    ; intact.  No failure below this point may return normally.
    jc resume_fo_post_failed
    cmp ax, 1
    jne resume_fo_post_failed
    cmp word [resume_fo_ek_seen], resume_card_ek_len
    jne resume_fo_post_failed
    cmp word [resume_fo_c_seen], resume_card_c_len * 2
    jne resume_fo_post_failed
    mov ax, [resume_fo_ek_running_sum]
    cmp ax, [fo_candidate_ek_sum]
    jne resume_fo_post_failed
    mov ax, [resume_fo_c_running_sum]
    cmp ax, [fo_candidate_c_sum]
    jne resume_fo_post_failed
    mov si, fo_candidate_g
    mov di, fo_expected_k
    mov cx, 16
    xor dx, dx
.selected_compare:
    lodsw
    xor ax, [di]
    or dx, ax
    add di, 2
    loop .selected_compare
    or dx, dx
    jnz resume_fo_post_failed

    call resume_fo_restore_ticket
    jc resume_fo_post_failed
    call resume_fo_wipe_retired_page
    jc resume_fo_post_failed

    mov ax, [fo_candidate_generation]
    mov [fo_generation], ax
    mov ax, [resume_fo_c_running_sum]
    mov [fo_c_sum], ax
    mov ax, [resume_fo_ek_running_sum]
    mov [fo_ek_sum], ax

    call resume_fo_restore_rsu
    jc resume_fo_post_failed

    ; The low trampoline survives the final complete symmetric reload.
    ; It is the only normal status publication/return edge.
    mov si, resume_fo_low_transition_source
    mov di, fo_low_transition
    mov cx, resume_fo_low_transition_end - \
        resume_fo_low_transition_source
    rep movsb
    xor ax, ax
    mov di, fo_expected_k
    mov cx, 16
    rep stosw
    mov di, fo_message
    mov cx, 16
    rep stosw
    mov dx, fo_low_transition
    jmp dx

resume_fo_validate_publication:
    cmp byte [fo_ticket_present], 1
    jne .bad
    cmp byte [resume_vault_lifecycle_status], \
        resume_vault_lifecycle_valid
    jne .bad
    cmp byte [resume_vault_lifecycle_inverse], \
        resume_vault_lifecycle_valid_inverse
    jne .bad
    cmp byte [fo_candidate_status], 0xa5
    jne .bad
    cmp byte [fo_candidate_inverse], 0x5a
    jne .bad
    mov ax, [fo_candidate_generation]
    or ax, ax
    jz .bad
    cmp ax, [resume_vault_lifecycle_generation]
    jne .bad
    cmp word [fo_candidate_c_sum], 0
    je .bad
    cmp word [fo_candidate_ek_sum], 0
    je .bad
    clc
    ret
.bad:
    stc
    ret

; Restore only the tentative ticket required by authenticated liveness.
; Issuer and route authority remain quarantined until operation 9 validates
; the complete RVL1 digest, restores status-last, scrubs, and invokes ROG4.
resume_fo_restore_ticket:
    mov bx, resume_card_vault_head
    mov cx, 256
    mov di, fo_page_buffer
    call RESUME_FO_NE_BUF_READ
    jc .bad
    mov bx, resume_card_vault_tail
    mov cx, 256
    mov di, fo_readback_buffer
    call RESUME_FO_NE_BUF_READ
    jc .bad
    cmp word [fo_readback_buffer + resume_vault_meta_magic], \
        resume_vault_magic_word0
    jne .bad
    cmp word [fo_readback_buffer + resume_vault_meta_magic + 2], \
        resume_vault_magic_word1
    jne .bad
    cmp word [fo_readback_buffer + resume_vault_meta_inverse], \
        resume_vault_inverse_word0
    jne .bad
    cmp word [fo_readback_buffer + resume_vault_meta_inverse + 2], \
        resume_vault_inverse_word1
    jne .bad
    cmp byte [fo_readback_buffer + resume_vault_meta_status], \
        resume_vault_status_valid
    jne .bad
    cmp byte [fo_readback_buffer + resume_vault_meta_inverse_status], \
        resume_vault_status_valid_inverse
    jne .bad
    mov ax, [fo_readback_buffer + resume_vault_meta_generation]
    cmp ax, [fo_candidate_generation]
    jne .bad
    cmp byte [fo_readback_buffer + resume_vault_tail_zero], 0
    jne .bad
    cmp word [fo_readback_buffer + resume_vault_meta_pad], 0
    jne .bad
    cmp word [fo_readback_buffer + resume_vault_meta_pad + 2], 0
    jne .bad
    cmp byte [fo_readback_buffer + resume_vault_tail_ticket + \
        resume_vault_ticket_tail_len - 1], 2
    jne .bad
    mov si, fo_page_buffer + resume_vault_head_psk
    mov di, fo_ticket_psk
    mov cx, resume_vault_psk_len
    rep movsb
    mov si, fo_page_buffer + resume_vault_head_identity
    mov di, fo_ticket_identity
    mov cx, resume_vault_head_identity_len
    rep movsb
    mov si, fo_readback_buffer + resume_vault_tail_identity
    mov di, fo_ticket_identity + resume_vault_head_identity_len
    mov cx, resume_vault_tail_identity_len
    rep movsb
    mov si, fo_readback_buffer + resume_vault_tail_ticket
    mov di, fo_ticket_tail
    mov cx, resume_vault_ticket_tail_len - 1
    rep movsb
    cmp byte [fo_ticket_present], 1
    jne .bad
    clc
    ret
.bad:
    stc
    ret

resume_fo_wipe_retired_page:
    xor ax, ax
    mov di, fo_page_buffer
    mov cx, 128
    rep stosw
    mov al, 0x7e
    mov si, fo_page_buffer
    mov bp, 256
    call resume_fo_card_write
    jc .bad
    mov bx, resume_card_candidate_a
    mov cx, 256
    mov di, fo_readback_buffer
    call RESUME_FO_NE_BUF_READ
    jc .bad
    mov si, fo_page_buffer
    mov di, fo_readback_buffer
    mov cx, 128
    repe cmpsw
    jne .bad
    clc
    ret
.bad:
    stc
    ret

resume_fo_restore_rsu:
    mov ax, RESUME_FO_RSU_TAIL_KEY
    mov bx, fo_stage
    call RESUME_FO_LOAD_PHASE
    jc .bad
    mov si, fo_stage
    mov di, RESUME_FO_RSU_LOW_START + 512
    mov cx, RESUME_FO_RSU_LOW_BYTES - 512
    rep movsb
    mov si, fo_stage + RESUME_FO_RSU_LOW_BYTES - 512
    mov di, RESUME_FO_RSU_PREFIX_START
    mov cx, RESUME_FO_RSU_PREFIX_BYTES
    rep movsb
    mov si, fo_stage + RESUME_FO_RSU_LOW_BYTES - 512 + \
        RESUME_FO_RSU_PREFIX_BYTES
    mov di, RESUME_FO_RSU_SUFFIX_START
    mov cx, RESUME_FO_RSU_SUFFIX_BYTES
    rep movsb
    mov ax, RESUME_FO_RSU_HEAD_KEY
    mov bx, RESUME_FO_RSU_LOW_START
    call RESUME_FO_LOAD_PHASE
    jc .bad
    mov ax, RESUME_FO_SUPERVISOR_KEY
    mov bx, fo_stage
    call RESUME_FO_LOAD_PHASE
    jc .bad
    mov si, RESUME_FO_SUPERVISOR_TRANSITION_SOURCE
    mov di, RESUME_FO_SUPERVISOR_TRANSITION_DEST
    mov cx, RESUME_FO_SUPERVISOR_TRANSITION_BYTES
    rep movsb
    clc
    ret
.bad:
    stc
    ret

; FO callback ABI: AL object, DX offset, CX count, DI destination.  All reads
; are bounded, the first complete c pass and complete ek are checksummed, and
; the fixed kernel's second c pass is counted independently.
resume_fo_card_read_callback:
    push bx
    push bp
    push ds
    push es
    mov [resume_fo_cb_object], al
    mov [resume_fo_cb_offset], dx
    mov [resume_fo_cb_count], cx
    mov [resume_fo_cb_destination], di
    push ds
    pop es
    or al, al
    jz .ek
    cmp al, 1
    jne .failed
    mov ax, dx
    add ax, cx
    jc .failed
    cmp ax, resume_card_c_len
    ja .failed
    mov bx, resume_card_c
    jmp short .read
.ek:
    mov ax, dx
    add ax, cx
    jc .failed
    cmp ax, resume_card_ek_len
    ja .failed
    mov bx, resume_card_ek
.read:
    add bx, dx
    call RESUME_FO_NE_BUF_READ
    jc .failed
    test byte [resume_fo_cb_count], 1
    jnz .failed
    cmp byte [resume_fo_cb_object], 0
    jne .c
    mov ax, [resume_fo_ek_seen]
    add ax, [resume_fo_cb_count]
    jc .failed
    cmp ax, resume_card_ek_len
    ja .failed
    mov [resume_fo_ek_seen], ax
    mov di, resume_fo_ek_running_sum
    jmp short .sum
.c:
    mov ax, [resume_fo_c_seen]
    mov dx, ax
    add ax, [resume_fo_cb_count]
    jc .failed
    cmp ax, resume_card_c_len * 2
    ja .failed
    mov [resume_fo_c_seen], ax
    cmp dx, resume_card_c_len
    jae .succeeded
    cmp ax, resume_card_c_len
    ja .failed
    mov di, resume_fo_c_running_sum
.sum:
    mov si, [resume_fo_cb_destination]
    mov cx, [resume_fo_cb_count]
    shr cx, 1
.sum_words:
    lodsw
    add [di], ax
    loop .sum_words
.succeeded:
    clc
    jmp short .restore
.failed:
    stc
.restore:
    cld
    pop es
    pop ds
    pop bp
    pop bx
    ret

; AL=page, SI=source, BP=count.
resume_fo_card_write:
    xor bx, bx
    mov bl, [RESUME_FO_NE_TX_START]
    push bx
    mov [RESUME_FO_NE_TX_START], al
    mov bx, [RESUME_FO_NIC_BASE]
    call RESUME_FO_NE_BUF_LOAD
    pop bx
    mov [RESUME_FO_NE_TX_START], bl
    ret

resume_fo_pre_failed:
    xor ax, ax
    stc
    pop es
    cld
    ret

resume_fo_post_failed:
    mov dx, RESUME_FO_RECOVERY_FAIL
    jmp dx

; Copied to 0x0d00 only after RSU1 and the outer transition are restored.
; The complete symmetric load destroys this controller and retires the fresh
; FO access lease, so direct failure dispatch is fully self-contained in the
; low copy and liveness receives byte-exact symmetric code plus immutable data.
resume_fo_low_transition_source:
    mov ax, RESUME_FO_SYM_RESTORE_KEY
    mov bx, 0x1800
    mov dx, RESUME_FO_LOAD_PHASE
    call dx
    jc .recover
%ifdef RESUME_FO_SYM_TAIL_KEY
    mov ax, RESUME_FO_SYM_TAIL_KEY
    mov bx, 0x2e00
    mov dx, RESUME_FO_LOAD_PHASE
    call dx
    jc .recover
%endif
    mov byte [fo_inverse], 0x5a
    mov byte [fo_status], 0xa5
    mov ax, 1
    clc
    pop es
    cld
    ret
.recover:
    mov dx, RESUME_FO_RECOVERY_FAIL
    jmp dx
resume_fo_low_transition_end:

resume_fo_cb_object          db 0
resume_fo_cb_offset          dw 0
resume_fo_cb_count           dw 0
resume_fo_cb_destination     dw 0
resume_fo_ek_seen            dw 0
resume_fo_c_seen             dw 0
resume_fo_ek_running_sum     dw 0
resume_fo_c_running_sum      dw 0

resume_fo_controller_end:

%if (resume_fo_controller_header - resume_fo_controller_entry) != 2
%error "resumption FO controller header moved"
%endif
%if RESUME_FO_RSU_LOW_BYTES < 512
%error "resumption FO RSU1 head is not one complete sector"
%endif
%if (resume_fo_low_transition_end - resume_fo_low_transition_source) > 0x100
%error "resumption FO low transition exceeds its safe slot"
%endif
%if ($ - $$) > RESUME_FO_CONTROLLER_LIMIT
%error "resumption FO controller exceeds three sectors"
%endif

%else
%error "select RESUME_FO_BROKER or RESUME_FO_CONTROLLER"
%endif
