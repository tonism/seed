; Phase bridge for the experimental issuer-input relocation.
;
; The strict certificate parser/hash/time phases publish their bounded results
; in 3600h..378fh.  Once the K14 symmetric controller and FO stream staging
; have retired, this bridge copies exactly one issuer-authentication pass into
; the now-dead 3400h..34aeh extension prefix.  Loading the 14-sector issuer
; overlay at 1800h ends at 3400h and therefore preserves the staged input.
;
; Public near-call ABI, DS=ES=SS=0:
;   entry +0: AX=nonzero generation, stage WE1/leaf pass
;   entry +2: AX=same generation, stage TLS CertificateVerify pass
;   entry +4: clear relocated input and authenticated handoff
;
; Success is CF=0, AX=1.  Rejection is CF=1, AX=0 and clears both the input
; and issuer handoff.  The bridge never reads or writes ticket state.

bits 16
cpu 8086
org 0x1800

bridge_table:
    dw bridge_stage_leaf
    dw bridge_stage_cv
    dw bridge_clear
    dw bridge_image_end - $$
    dw 1

; Parser/hash/time output ABI.
parser_leaf_status          equ 0x3600
parser_leaf_profile         equ 0x3601
parser_output_tbs_digest    equ 0x3609
parser_output_cert_sig_len  equ 0x3629
parser_output_cert_sig      equ 0x362b
parser_output_leaf_x        equ 0x3673
parser_output_leaf_y        equ 0x3693

parser_cv_status            equ 0x3700
parser_cv_profile           equ 0x3701
parser_transcript_status    equ 0x3703
parser_output_cv_digest     equ 0x3724
parser_output_cv_sig_len    equ 0x3744
parser_output_cv_sig        equ 0x3746
parser_hash_status          equ 0x378e
parser_time_status          equ 0x378f

parser_leaf_hashed_status   equ 2
issuer_leaf_profile         equ 0x003f
issuer_cv_profile           equ 0x0700

; Relocated issuer input ABI.  The interval is half-open [3400h,34afh).
issuer_input_profile        equ 0x3400
issuer_input_generation     equ issuer_input_profile + 2
issuer_input_digest         equ issuer_input_generation + 2
issuer_input_signature_len  equ issuer_input_digest + 32
issuer_input_signature      equ issuer_input_signature_len + 2
issuer_input_signature_max  equ 72
issuer_input_leaf_x         equ issuer_input_signature + issuer_input_signature_max
issuer_input_leaf_y         equ issuer_input_leaf_x + 32
issuer_output_status        equ issuer_input_leaf_y + 32
issuer_input_end            equ issuer_output_status + 1
issuer_input_guard_hi       equ 0x3508
issuer_input_guard_hi_end   equ issuer_input_guard_hi + 8

; Pass-1 authenticated handoff.  Pass 2 must be same-attempt.
issuer_commit_start         equ 0x3600
issuer_commit_status        equ issuer_commit_start
issuer_commit_generation    equ issuer_commit_start + 10
issuer_commit_end           equ 0x3672

bridge_stage_leaf:
    cld
    push ax
    call bridge_clear_input
    pop ax
    or ax, ax
    jz bridge_failed
    cmp byte [parser_leaf_status], parser_leaf_hashed_status
    jne bridge_failed
    cmp word [parser_leaf_profile], issuer_leaf_profile
    jne bridge_failed
    cmp byte [parser_cv_status], 1
    jne bridge_failed
    cmp word [parser_cv_profile], issuer_cv_profile
    jne bridge_failed
    cmp byte [parser_transcript_status], 1
    jne bridge_failed
    cmp byte [parser_hash_status], 1
    jne bridge_failed
    cmp byte [parser_time_status], 1
    jne bridge_failed
    mov dx, [parser_output_cert_sig_len]
    cmp dx, 8
    jb bridge_failed
    cmp dx, issuer_input_signature_max
    ja bridge_failed

    mov [issuer_input_generation], ax
    mov word [issuer_input_profile], issuer_leaf_profile
    push ds
    pop es
    mov si, parser_output_tbs_digest
    mov di, issuer_input_digest
    mov cx, 16
    rep movsw
    mov [issuer_input_signature_len], dx
    mov si, parser_output_cert_sig
    mov di, issuer_input_signature
    mov cx, dx
    rep movsb
    mov si, parser_output_leaf_x
    mov di, issuer_input_leaf_x
    mov cx, 32
    rep movsw
    mov byte [issuer_output_status], 0
    ; All pass-1 source fields now survive in the relocated input, so the
    ; stale handoff/parser overlap can finally be retired.
    call bridge_clear_commit
    call bridge_set_guard
    jmp bridge_succeeded

bridge_stage_cv:
    cld
    or ax, ax
    jz bridge_failed
    cmp byte [issuer_commit_status], 1
    jne bridge_failed
    cmp ax, [issuer_commit_generation]
    jne bridge_failed
    cmp byte [parser_cv_status], 1
    jne bridge_failed
    cmp word [parser_cv_profile], issuer_cv_profile
    jne bridge_failed
    cmp byte [parser_transcript_status], 1
    jne bridge_failed
    cmp byte [parser_hash_status], 1
    jne bridge_failed
    cmp byte [parser_time_status], 1
    jne bridge_failed
    mov dx, [parser_output_cv_sig_len]
    cmp dx, 8
    jb bridge_failed
    cmp dx, issuer_input_signature_max
    ja bridge_failed

    push ax
    call bridge_clear_input
    pop ax
    mov [issuer_input_generation], ax
    mov word [issuer_input_profile], issuer_cv_profile
    push ds
    pop es
    mov si, parser_output_cv_digest
    mov di, issuer_input_digest
    mov cx, 16
    rep movsw
    mov [issuer_input_signature_len], dx
    mov si, parser_output_cv_sig
    mov di, issuer_input_signature
    mov cx, dx
    rep movsb
    ; Pass 2 deliberately receives no point from the untrusted parser.
    mov byte [issuer_output_status], 0
    call bridge_set_guard
    jmp bridge_succeeded

bridge_clear:
    call bridge_clear_extension
    jmp short bridge_clear_commit

bridge_clear_commit:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, issuer_commit_start
    mov cx, issuer_commit_end - issuer_commit_start
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

bridge_clear_input:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, issuer_input_profile
    mov cx, issuer_input_guard_hi_end - issuer_input_profile
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

bridge_clear_extension:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    xor ax, ax
    mov di, 0x3400
    mov cx, 0x0200
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

bridge_set_guard:
    mov word [issuer_input_guard_hi], 0x5249       ; "IR"
    mov word [issuer_input_guard_hi + 2], 0x3149  ; "I1"
    mov word [issuer_input_guard_hi + 4], 0xadde
    mov word [issuer_input_guard_hi + 6], 0xceb6
    ret

bridge_failed:
    call bridge_clear
    xor ax, ax
    stc
    ret

bridge_succeeded:
    mov ax, 1
    clc
    ret

bridge_image_end:

%if issuer_input_end != 0x34af
%error "relocated issuer input ABI drifted"
%endif
%if issuer_input_guard_hi_end > 0x3510
%error "relocated issuer input reaches the retired symmetric runtime suffix"
%endif
%if (bridge_image_end - $$) > 512
%error "issuer-input relocation bridge exceeds one sector"
%endif
