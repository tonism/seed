; Integrated conventional-RAM-only controllers for the 16 KiB TLS 1.3 route.
;
; Each build selects exactly one controller.  Slow resident-loader calls in
; this file are intentionally outside the provider deadline unless a comment
; explicitly identifies the bounded track-batched transition.

bits 16
cpu 8086

resident_load_phase           equ 0x10c4
resident_nic_enter            equ 0x15db
resident_tcp_close_cached     equ SYSRAM_TCP_CLOSE_CACHED
; Status-last return metadata plus the resident UI/control snapshot occupy the
; retired bottom of the 16 KiB stack guard.  On the 32 KiB direct tier that
; same fixed ABI overlaps 28 bytes of the larger low arena, so the root first
; shadows those bytes at the bottom of the 0x7a00 stack guard and replaces its
; caller return with a flag-preserving restoration trampoline.  Every normal
; success/abort return therefore restores the full 224-byte arena before the
; resident scheduler resumes.  No display or adapter RAM participates.
root_frame_sp                 equ 0x3f00
root_frame_inverse            equ 0x3f02
root_frame_magic              equ 0x3f04
root_frame_runtime_state      equ 0x3f06
runtime_state_start           equ 0x0f55
runtime_state_end             equ 0x0f69
runtime_state_words           equ (runtime_state_end - runtime_state_start) / 2
root_frame_prompt_marker      equ root_frame_runtime_state + (runtime_state_end - runtime_state_start)
root_frame_end                equ root_frame_prompt_marker + 2
dpi_prompt_marker_row         equ 0x0f33
handoff_ram_top_word          equ 0x062c
direct_stack_top              equ 0x8000
direct_root_shadow            equ 0x7a00
direct_root_return            equ direct_root_shadow + (root_frame_end - root_frame_sp)
direct_root_trampoline        equ direct_root_return + 2
private_state_end             equ 0x3b9c
low_abort                     equ 0x0f60
sym_entry_table               equ 0x1820
lifecycle_entry_table         equ 0x090a

%ifdef SYSRAM_PRODUCT_ROOT

%ifndef SYSRAM_LOW_ABORT_PATH
%error "product root requires SYSRAM_LOW_ABORT_PATH"
%endif
%ifndef SYSRAM_ENDPOINT_KEY
%error "product root requires phase keys"
%endif
%ifndef SYSRAM_TCP_KEY
%error "product root requires phase keys"
%endif
%ifndef SYSRAM_ACQ_SYM_KEY
%error "product root requires phase keys"
%endif
%ifndef SYSRAM_KEYGEN_KEY
%error "product root requires phase keys"
%endif
%ifndef SYSRAM_CONDITIONER_KEY
%error "product root requires phase keys"
%endif
%ifndef SYSRAM_FRESH_HELLO_KEY
%error "product root requires phase keys"
%endif
%ifndef SYSRAM_FRESH_HELLO_CONTROLLER_KEY
%error "product root requires phase keys"
%endif
%ifndef SYSRAM_ROOT_HELLO_CONTINUATION_PATH
%error "product root requires its linked 0f00 continuation"
%endif
%ifndef SYSRAM_KEYGEN_NONCE_ENTRY
%error "product root requires KeyGen nonce entry"
%endif

org 0x3400

sysram_product_root:
    cld
    mov dl, al
    push ds
    pop es
    ; The 16 KiB fixed frame is outside its user pool.  A direct-entry machine
    ; has a larger pool through 0x4000, so preserve the aliased bytes and chain
    ; the original caller return through a conventional-RAM trampoline.  The
    ; trampoline preserves CF, restores the arena, and erases its data shadow.
    cmp word [handoff_ram_top_word], direct_stack_top
    jb .direct_shadow_ready
    mov si, root_frame_sp
    mov di, direct_root_shadow
    mov cx, (root_frame_end - root_frame_sp) / 2
    rep movsw
    mov bx, sp
    mov ax, [bx]
    mov [direct_root_return], ax
    mov word [bx], direct_root_trampoline
    mov si, direct_root_trampoline_image
    mov di, direct_root_trampoline
    mov cx, direct_root_trampoline_image_end - direct_root_trampoline_image
    rep movsb
.direct_shadow_ready:
    ; Save the sole resident caller frame before any overlay can replace this
    ; controller.  The inverse/magic pair lets a later disk-independent abort
    ; reject a torn or corrupted stack snapshot.
    mov [root_frame_sp], sp
    mov ax, sp
    not ax
    mov [root_frame_inverse], ax
    mov si, runtime_state_start
    mov di, root_frame_runtime_state
    mov cx, runtime_state_words
    rep movsw
    mov al, [dpi_prompt_marker_row]
    mov [root_frame_prompt_marker], al
    mov byte [root_frame_prompt_marker + 1], 0
    ; Publish validity last: neither abort nor success may consume a partial
    ; software-display snapshot.
    mov word [root_frame_magic], 0xa55a
    mov si, root_low_abort_image
    mov di, low_abort
    mov cx, root_low_abort_image_end - root_low_abort_image
    rep movsb

    cmp dl, 1
    ja low_abort
    mov al, dl
    call word [resident_nic_enter]

    ; Reuse the established silent endpoint path without changing the
    ; resident scheduler's one-replay budget.
    mov byte [0x06c4], 2
    mov ax, SYSRAM_ENDPOINT_KEY
    mov bx, 0x0700
    call resident_load_phase
    jc low_abort
    mov al, [0x3c9d]
    push ax
    mov byte [0x3c9d], 1
    call 0x0700
    pop ax
    mov [0x3c9d], al
    jc low_abort

    mov ax, SYSRAM_TCP_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc low_abort
    call 0x0900
    jc low_abort
    call resident_tcp_close_cached

    ; Preload the complete acquisition symmetric image.  KeyGen and HELLO
    ; replace only its prefix; the critical controller restores that prefix in
    ; one track-batched operation after ServerHello.
    mov ax, SYSRAM_ACQ_SYM_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc low_abort
    mov ax, SYSRAM_KEYGEN_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc low_abort
    mov ax, SYSRAM_CONDITIONER_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc low_abort
    call word [0x0910]
    jc low_abort

    xor ax, ax                       ; epoch 0
    mov si, 0x0500
    call 0x1800
    jc low_abort
    xor ax, ax
    mov si, 0x0500
    mov di, 0x0560
    call SYSRAM_KEYGEN_NONCE_ENTRY
    jc low_abort
    mov si, 0x0500
    mov di, 0x2f40
    mov cx, 16
    rep movsw

    mov ax, SYSRAM_FRESH_HELLO_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc low_abort
    mov si, root_hello_transition_image
    mov di, 0x0f00
    mov cx, root_hello_transition_image_end - root_hello_transition_image
    rep movsb
    mov ax, SYSRAM_FRESH_HELLO_CONTROLLER_KEY
    jmp 0x0f00

root_hello_transition_image:
    incbin SYSRAM_ROOT_HELLO_CONTINUATION_PATH
root_hello_transition_image_end:

; Copied to 0x7a1e only on the direct-entry tier.  MOV/CLD/REP/JMP preserve
; the root's success/failure carry while the original arena bytes are restored.
direct_root_trampoline_image:
    mov bx, [direct_root_return]
    cld
    mov si, direct_root_shadow
    mov di, root_frame_sp
    mov cx, (root_frame_end - root_frame_sp) / 2
    rep movsw
    mov di, direct_root_shadow
    mov cx, (direct_root_return + 2 - direct_root_shadow) / 2
    mov ax, 0
    rep stosw
    jmp bx
direct_root_trampoline_image_end:
%if direct_root_trampoline + (direct_root_trampoline_image_end - direct_root_trampoline_image) > 0x7a40
%error "direct root return reservation reaches the cold stack scrub floor"
%endif

root_low_abort_image:
    incbin SYSRAM_LOW_ABORT_PATH
root_low_abort_image_end:

sysram_product_root_end:

%if (root_hello_transition_image_end - root_hello_transition_image) > 0x60
%error "root HELLO transition reaches low abort"
%endif
%if (sysram_product_root_end - sysram_product_root) > 512
%error "system-RAM product root exceeds one sector"
%endif

%elifdef SYSRAM_ACQUISITION_OFFLINE

%ifndef SYSRAM_LIFECYCLE_KEY
%error "acquisition offline controller requires lifecycle phase"
%endif
%ifndef SYSRAM_KEYGEN_KEY
%error "acquisition offline controller requires KeyGen phase"
%endif
%ifndef SYSRAM_CANDIDATE_KEY
%error "acquisition offline controller requires candidate phase"
%endif
%ifndef SYSRAM_ACQ_FO_CONTROLLER_KEY
%error "acquisition offline controller requires FO continuation"
%endif
%ifndef SYSRAM_ACQ_STAGE1_PATH
%error "acquisition offline controller requires its linked 0f00 continuation"
%endif

org 0x0900

sysram_acquisition_offline:
    cld
    ; Server-read keys and the resumption master are deliberately deferred
    ; until after the credential-free HEAD transmit.  The peer is already at
    ; a zero window, so this work is outside the liveness race.
    call word [sym_entry_table + 17 * 2]
    jc low_abort
    push ds
    pop es
    mov si, acq_stage1_image
    mov di, 0x0f00
    mov cx, acq_stage1_image_end - acq_stage1_image
    rep movsb
    jmp 0x0f00

acq_stage1_image:
    incbin SYSRAM_ACQ_STAGE1_PATH
acq_stage1_image_end:

sysram_acquisition_offline_end:

%if (acq_stage1_image_end - acq_stage1_image) > 0x60
%error "acquisition offline continuation reaches low abort"
%endif
%if (sysram_acquisition_offline_end - sysram_acquisition_offline) > 512
%error "acquisition offline controller exceeds one sector"
%endif

%elifdef SYSRAM_RESUMPTION_OFFLINE

%ifndef SYSRAM_LIFECYCLE_KEY
%error "resumption offline controller requires lifecycle phase"
%endif
%ifndef SYSRAM_KEYGEN_KEY
%error "resumption offline controller requires KeyGen phase"
%endif
%ifndef SYSRAM_CANDIDATE_KEY
%error "resumption offline controller requires candidate phase"
%endif
%ifndef SYSRAM_RESUME_FO_CONTROLLER_KEY
%error "resumption offline controller requires FO continuation"
%endif
%ifndef SYSRAM_RESUME_STAGE1_PATH
%error "resumption offline controller requires its linked 0f00 continuation"
%endif

org 0x0900

sysram_resumption_offline:
    cld
    push ds
    pop es
    mov si, resume_stage1_image
    mov di, 0x0f00
    mov cx, resume_stage1_image_end - resume_stage1_image
    rep movsb
    jmp 0x0f00

resume_stage1_image:
    incbin SYSRAM_RESUME_STAGE1_PATH
resume_stage1_image_end:

sysram_resumption_offline_end:

%if (resume_stage1_image_end - resume_stage1_image) > 0x60
%error "resumption offline continuation reaches low abort"
%endif
%if (sysram_resumption_offline_end - sysram_resumption_offline) > 512
%error "resumption offline controller exceeds one sector"
%endif

%elifdef SYSRAM_ACQUISITION_FO

%ifndef SYSRAM_FO_KEY
%error "acquisition FO controller requires FO phase"
%endif
%ifndef SYSRAM_LIFECYCLE_KEY
%error "acquisition FO controller requires lifecycle phase"
%endif
%ifndef SYSRAM_AUTH_RETURN_KEY
%error "acquisition FO controller requires auth return phase"
%endif
%ifndef SYSRAM_AUTH_KEY
%error "acquisition FO controller requires auth phase"
%endif
%ifndef SYSRAM_ACQ_STAGE2_PATH
%error "acquisition FO controller requires its linked 0f00 continuation"
%endif
%ifndef SYSRAM_LOW_ABORT_PATH
%error "acquisition FO controller requires the checked low abort image"
%endif
%ifndef SYSRAM_FO_RUNNER_PATH
%error "acquisition FO controller requires its stable 0500 runner"
%endif

org 0x0900

sysram_acquisition_fo:
    cld
    push ds
    pop es
    mov si, acq_fo_runner_image
    mov di, 0x0500
    mov cx, acq_fo_runner_image_end - acq_fo_runner_image
    rep movsb
    mov si, acq_stage2_image
    mov di, 0x3550
    mov cx, acq_stage2_image_end - acq_stage2_image
    rep movsb
    mov si, acq_low_abort_image
    mov cx, acq_low_abort_image_end - acq_low_abort_image
    rep movsb
    mov ax, SYSRAM_FO_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc low_abort
    jmp 0x0500

acq_fo_runner_image:
    incbin SYSRAM_FO_RUNNER_PATH
acq_fo_runner_image_end:

acq_stage2_image:
    incbin SYSRAM_ACQ_STAGE2_PATH
acq_stage2_image_end:

acq_low_abort_image:
    incbin SYSRAM_LOW_ABORT_PATH
acq_low_abort_image_end:

sysram_acquisition_fo_end:

%if (acq_stage2_image_end - acq_stage2_image) > 0x60
%error "acquisition FO continuation reaches low abort"
%endif
%if (acq_fo_runner_image_end - acq_fo_runner_image) > 0x100
%error "acquisition FO runner reaches the 0600 handoff"
%endif
%if ((acq_stage2_image_end - acq_stage2_image) + (acq_low_abort_image_end - acq_low_abort_image)) > 0x0b0
%error "acquisition FO staged continuation/abort exceeds 3550..35ff"
%endif
%if (sysram_acquisition_fo_end - sysram_acquisition_fo) > 512
%error "acquisition FO controller exceeds one sector"
%endif

%elifdef SYSRAM_RESUMPTION_FO

%ifndef SYSRAM_FO_KEY
%error "resumption FO controller requires FO phase"
%endif
%ifndef SYSRAM_LIFECYCLE_KEY
%error "resumption FO controller requires lifecycle phase"
%endif
%ifndef SYSRAM_RES_SYM_KEY
%error "resumption FO controller requires resumption symmetric phase"
%endif
%ifndef SYSRAM_FINAL_POST_KEY
%error "resumption FO controller requires final post controller"
%endif
%ifndef SYSRAM_RESUME_STAGE2_PATH
%error "resumption FO controller requires its linked 0f00 continuation"
%endif
%ifndef SYSRAM_LOW_ABORT_PATH
%error "resumption FO controller requires the checked low abort image"
%endif
%ifndef SYSRAM_FO_RUNNER_PATH
%error "resumption FO controller requires its stable 0500 runner"
%endif

org 0x0900

sysram_resumption_fo:
    cld
    push ds
    pop es
    mov si, resume_fo_runner_image
    mov di, 0x0500
    mov cx, resume_fo_runner_image_end - resume_fo_runner_image
    rep movsb
    mov si, resume_stage2_image
    mov di, 0x3550
    mov cx, resume_stage2_image_end - resume_stage2_image
    rep movsb
    mov si, resume_low_abort_image
    mov cx, resume_low_abort_image_end - resume_low_abort_image
    rep movsb
    mov ax, SYSRAM_FO_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc low_abort
    jmp 0x0500

resume_fo_runner_image:
    incbin SYSRAM_FO_RUNNER_PATH
resume_fo_runner_image_end:

resume_stage2_image:
    incbin SYSRAM_RESUME_STAGE2_PATH
resume_stage2_image_end:

resume_low_abort_image:
    incbin SYSRAM_LOW_ABORT_PATH
resume_low_abort_image_end:

sysram_resumption_fo_end:

%if (resume_stage2_image_end - resume_stage2_image) > 0x60
%error "resumption FO continuation reaches low abort"
%endif
%if (resume_fo_runner_image_end - resume_fo_runner_image) > 0x100
%error "resumption FO runner reaches the 0600 handoff"
%endif
%if ((resume_stage2_image_end - resume_stage2_image) + (resume_low_abort_image_end - resume_low_abort_image)) > 0x0b0
%error "resumption FO staged continuation/abort exceeds 3550..35ff"
%endif
%if (sysram_resumption_fo_end - sysram_resumption_fo) > 512
%error "resumption FO controller exceeds one sector"
%endif

%elifdef SYSRAM_AUTH_RETURN

%ifndef SYSRAM_ACQ_SYM_KEY
%error "auth return requires acquisition sym phase"
%endif
%ifndef SYSRAM_LIFECYCLE_KEY
%error "auth return requires lifecycle phase"
%endif
%ifndef SYSRAM_FRESH_POST_KEY
%error "auth return requires fresh post controller"
%endif
%ifndef SYSRAM_AUTH_CAPSULE_RESTORE
%error "auth return requires the stable runner capsule-restore helper"
%endif

org 0x3550

sysram_auth_return:
    jc sysram_high_abort
    cmp ax, 1
    jne sysram_high_abort
    cmp byte [0x34aa], 1
    jne sysram_high_abort
    mov ax, SYSRAM_ACQ_SYM_KEY
    mov bx, 0x1800
    call resident_load_phase
    jc sysram_high_abort
    call word [sym_entry_table]
    jc sysram_high_abort
    call SYSRAM_AUTH_CAPSULE_RESTORE
    mov ax, SYSRAM_LIFECYCLE_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc sysram_high_abort
    call word [lifecycle_entry_table + 3 * 2]
    jc sysram_high_abort
    ; Successful restore installed the low abort before compact-root
    ; publication overwrote the latter half of this high emergency path.
    mov ax, SYSRAM_FRESH_POST_KEY
    mov bx, 0x0900
    call resident_load_phase
    jc low_abort
    jmp 0x0900

; Kept in the successful path's fixed padding so the size-critical high abort
; can restore this non-contiguous survivor with one near call.
sysram_restore_prompt_state:
    mov al, [root_frame_prompt_marker]
    mov [dpi_prompt_marker_row], al
    xor ax, ax
    mov [0x06c4], al
    ret

times 0x0050 - ($ - $$) db 0
sysram_high_abort:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov bx, [root_frame_sp]
    mov dx, [root_frame_inverse]
    not dx
    cmp bx, dx
    jne .restart
    cmp word [root_frame_magic], 0xa55a
    jne .restart
    mov di, 0x0500
    mov cx, (0x0600 - 0x0500) / 2
    rep stosw
    mov di, 0x0700
    mov cx, (0x1000 - 0x0700) / 2
    rep stosw
    ; The helper lives below 35a0. Restore the low prompt/capability state
    ; while it is executable, before the next clear retires its bytes.
    call sysram_restore_prompt_state
    mov di, 0x1800
    mov cx, (0x35a0 - 0x1800) / 2
    rep stosw
    mov di, 0x3600
    mov cx, (private_state_end - 0x3600) / 2
    rep stosw
    mov si, root_frame_runtime_state
    mov di, runtime_state_start
    mov cx, runtime_state_words
    rep movsw
    mov sp, bx
    mov di, root_frame_sp
    mov cx, (root_frame_end - root_frame_sp) / 2
    rep stosw
    sti
    stc
    ret
.restart:
    jmp 0xffff:0x0000

sysram_auth_return_end:

%if (sysram_auth_return_end - $$) > 0x00b0
%error "auth return/high abort exceeds 3550..3600"
%endif

%else
%error "select one system-RAM product controller"
%endif
