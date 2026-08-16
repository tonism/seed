; Fixed same-boot resumption operation dispatcher.
;
; RSU1 calls the immutable entry at 0x0500 with AX=1..11.  The caller cannot
; select a phase key, load address, execution address, mode, or byte count:
; every operation's complete dispatch tuple is compiled into the table below.
;
; Direct workers are loaded and tail-entered at 0x3000.  Symmetric workers are
; staged at 0x0d00, copied by their exact measured length to 0x3400, and
; tail-entered there so live K14 mutable work is never executed in place.
; Transcript-page workers are loaded and tail-entered directly at 0x0d00 only
; after sym_import has consumed that handoff.  A low-tail worker is loaded and
; tail-entered at 0x0900 after RSU1 has pushed the fixed outer 0x0fxx
; continuation.  Its phase load deliberately destroys RSU1, so only that
; outer continuation may receive its RET.  Every mode tail-jumps after
; removing all dispatcher-owned stack state.

bits 16
cpu 8086
org 0x0500

%ifnidn __OUTPUT_FORMAT__, bin
%error "resumption dispatcher requires flat-binary output"
%endif

%ifndef RESUME_DISPATCH_OP1_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP1_MODE"
%endif
%ifndef RESUME_DISPATCH_OP1_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP1_KEY"
%endif
%ifndef RESUME_DISPATCH_OP1_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP1_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP2_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP2_MODE"
%endif
%ifndef RESUME_DISPATCH_OP2_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP2_KEY"
%endif
%ifndef RESUME_DISPATCH_OP2_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP2_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP3_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP3_MODE"
%endif
%ifndef RESUME_DISPATCH_OP3_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP3_KEY"
%endif
%ifndef RESUME_DISPATCH_OP3_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP3_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP4_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP4_MODE"
%endif
%ifndef RESUME_DISPATCH_OP4_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP4_KEY"
%endif
%ifndef RESUME_DISPATCH_OP4_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP4_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP5_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP5_MODE"
%endif
%ifndef RESUME_DISPATCH_OP5_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP5_KEY"
%endif
%ifndef RESUME_DISPATCH_OP5_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP5_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP6_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP6_MODE"
%endif
%ifndef RESUME_DISPATCH_OP6_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP6_KEY"
%endif
%ifndef RESUME_DISPATCH_OP6_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP6_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP7_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP7_MODE"
%endif
%ifndef RESUME_DISPATCH_OP7_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP7_KEY"
%endif
%ifndef RESUME_DISPATCH_OP7_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP7_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP8_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP8_MODE"
%endif
%ifndef RESUME_DISPATCH_OP8_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP8_KEY"
%endif
%ifndef RESUME_DISPATCH_OP8_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP8_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP9_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP9_MODE"
%endif
%ifndef RESUME_DISPATCH_OP9_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP9_KEY"
%endif
%ifndef RESUME_DISPATCH_OP9_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP9_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP10_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP10_MODE"
%endif
%ifndef RESUME_DISPATCH_OP10_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP10_KEY"
%endif
%ifndef RESUME_DISPATCH_OP10_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP10_BYTES"
%endif
%ifndef RESUME_DISPATCH_OP11_MODE
%error "resumption dispatcher requires RESUME_DISPATCH_OP11_MODE"
%endif
%ifndef RESUME_DISPATCH_OP11_KEY
%error "resumption dispatcher requires RESUME_DISPATCH_OP11_KEY"
%endif
%ifndef RESUME_DISPATCH_OP11_BYTES
%error "resumption dispatcher requires RESUME_DISPATCH_OP11_BYTES"
%endif

resident_load_phase              equ 0x10c4
resume_dispatch_origin          equ 0x0500
resume_dispatch_direct_stage    equ 0x3000
resume_dispatch_sym_stage       equ 0x0d00
resume_dispatch_sym_destination equ 0x3400
resume_dispatch_low_destination equ 0x0900
resume_dispatch_mode_direct     equ 0
resume_dispatch_mode_sym        equ 1
resume_dispatch_mode_low        equ 2
resume_dispatch_mode_transcript equ 3
resume_dispatch_sector_bytes    equ 0x0200
resume_dispatch_direct_max_bytes equ 0x0400
resume_dispatch_sym_max_bytes   equ 0x0110
resume_dispatch_low_max_bytes   equ 0x0600
resume_dispatch_transcript_max_bytes equ 0x0200

%macro validate_dispatch_operation 3
%if ((%1) != resume_dispatch_mode_direct) && \
    ((%1) != resume_dispatch_mode_sym) && \
    ((%1) != resume_dispatch_mode_low) && \
    ((%1) != resume_dispatch_mode_transcript)
%error "resumption dispatcher operation has an invalid fixed mode"
%endif
%if ((%3) <= 0) || ((%3) > 0xffff)
%error "resumption dispatcher operation has an invalid measured length"
%endif
%if (((%2) >> 8) & 0xff) != \
    (((%3) + resume_dispatch_sector_bytes - 1) / \
    resume_dispatch_sector_bytes)
%error "resumption dispatcher phase-key sector count differs from measured length"
%endif
%if ((%1) == resume_dispatch_mode_direct) && \
    ((%3) > resume_dispatch_direct_max_bytes)
%error "resumption direct worker exceeds the fixed 0x400-byte load slot"
%endif
%if ((%1) == resume_dispatch_mode_sym) && \
    ((%3) > resume_dispatch_sym_max_bytes)
%error "resumption symmetric worker exceeds the fixed 0x110-byte copy slot"
%endif
%if ((%1) == resume_dispatch_mode_low) && \
    ((%3) > resume_dispatch_low_max_bytes)
%error "resumption low worker exceeds the fixed 0x600-byte phase window"
%endif
%if ((%1) == resume_dispatch_mode_transcript) && \
    ((%3) > resume_dispatch_transcript_max_bytes)
%error "resumption transcript worker exceeds the retired 0x0d00 page"
%endif
%endmacro

validate_dispatch_operation \
    RESUME_DISPATCH_OP1_MODE, RESUME_DISPATCH_OP1_KEY, \
    RESUME_DISPATCH_OP1_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP2_MODE, RESUME_DISPATCH_OP2_KEY, \
    RESUME_DISPATCH_OP2_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP3_MODE, RESUME_DISPATCH_OP3_KEY, \
    RESUME_DISPATCH_OP3_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP4_MODE, RESUME_DISPATCH_OP4_KEY, \
    RESUME_DISPATCH_OP4_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP5_MODE, RESUME_DISPATCH_OP5_KEY, \
    RESUME_DISPATCH_OP5_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP6_MODE, RESUME_DISPATCH_OP6_KEY, \
    RESUME_DISPATCH_OP6_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP7_MODE, RESUME_DISPATCH_OP7_KEY, \
    RESUME_DISPATCH_OP7_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP8_MODE, RESUME_DISPATCH_OP8_KEY, \
    RESUME_DISPATCH_OP8_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP9_MODE, RESUME_DISPATCH_OP9_KEY, \
    RESUME_DISPATCH_OP9_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP10_MODE, RESUME_DISPATCH_OP10_KEY, \
    RESUME_DISPATCH_OP10_BYTES
validate_dispatch_operation \
    RESUME_DISPATCH_OP11_MODE, RESUME_DISPATCH_OP11_KEY, \
    RESUME_DISPATCH_OP11_BYTES

resume_dispatch_entry:
    jmp short resume_dispatch_code

resume_dispatch_header:
    db 'RSD1'
    dw 1
    dw resume_dispatch_end - $$
    dw resume_dispatch_origin
    dw resume_dispatch_entry

resume_dispatch_code:
    cld
    cmp ax, 1
    jb resume_dispatch_failed
    cmp ax, 11
    ja resume_dispatch_failed

    ; Keep the RSU1 operation beneath the loader's return frame.  The fixed
    ; table entry is six bytes: mode/reserved, phase key, measured byte count.
    push ax
    dec ax
    mov bx, ax
    shl bx, 1
    mov si, bx
    shl bx, 1
    add bx, si
    mov dl, [cs:resume_dispatch_table + bx]
    xor dh, dh
    mov ax, [cs:resume_dispatch_table + bx + 2]
    mov cx, [cs:resume_dispatch_table + bx + 4]
    push dx
    push cx

    cmp dl, resume_dispatch_mode_direct
    je resume_dispatch_load_direct
    cmp dl, resume_dispatch_mode_sym
    je resume_dispatch_load_sym
    cmp dl, resume_dispatch_mode_transcript
    je resume_dispatch_load_sym
    cmp dl, resume_dispatch_mode_low
    jne resume_dispatch_table_failed
    mov bx, resume_dispatch_low_destination
    jmp short resume_dispatch_load
resume_dispatch_load_sym:
    mov bx, resume_dispatch_sym_stage
    jmp short resume_dispatch_load
resume_dispatch_load_direct:
    mov bx, resume_dispatch_direct_stage
resume_dispatch_load:
    call resident_load_phase
    jc resume_dispatch_load_failed

    pop cx
    pop dx
    pop ax
    cmp dl, resume_dispatch_mode_direct
    je resume_dispatch_direct
    cmp dl, resume_dispatch_mode_sym
    je resume_dispatch_sym
    cmp dl, resume_dispatch_mode_transcript
    je resume_dispatch_transcript
    cmp dl, resume_dispatch_mode_low
    jne resume_dispatch_failed
    jmp resume_dispatch_low_destination

    ; The immutable table supplies CX.  No caller register controls this copy.
resume_dispatch_sym:
    push ds
    push es
    push cs
    pop ds
    push cs
    pop es
    mov si, resume_dispatch_sym_stage
    mov di, resume_dispatch_sym_destination
    rep movsb
    pop es
    pop ds
    jmp resume_dispatch_sym_destination

resume_dispatch_direct:
    jmp resume_dispatch_direct_stage

resume_dispatch_transcript:
    jmp resume_dispatch_sym_stage

resume_dispatch_table_failed:
resume_dispatch_load_failed:
    pop cx
    pop dx
    pop ax
resume_dispatch_failed:
    xor ax, ax
    stc
    ret

resume_dispatch_code_end:

%macro dispatch_table_entry 3
    db %1, 0
    dw %2
    dw %3
%endmacro

resume_dispatch_table:
dispatch_table_entry \
    RESUME_DISPATCH_OP1_MODE, RESUME_DISPATCH_OP1_KEY, \
    RESUME_DISPATCH_OP1_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP2_MODE, RESUME_DISPATCH_OP2_KEY, \
    RESUME_DISPATCH_OP2_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP3_MODE, RESUME_DISPATCH_OP3_KEY, \
    RESUME_DISPATCH_OP3_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP4_MODE, RESUME_DISPATCH_OP4_KEY, \
    RESUME_DISPATCH_OP4_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP5_MODE, RESUME_DISPATCH_OP5_KEY, \
    RESUME_DISPATCH_OP5_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP6_MODE, RESUME_DISPATCH_OP6_KEY, \
    RESUME_DISPATCH_OP6_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP7_MODE, RESUME_DISPATCH_OP7_KEY, \
    RESUME_DISPATCH_OP7_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP8_MODE, RESUME_DISPATCH_OP8_KEY, \
    RESUME_DISPATCH_OP8_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP9_MODE, RESUME_DISPATCH_OP9_KEY, \
    RESUME_DISPATCH_OP9_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP10_MODE, RESUME_DISPATCH_OP10_KEY, \
    RESUME_DISPATCH_OP10_BYTES
dispatch_table_entry \
    RESUME_DISPATCH_OP11_MODE, RESUME_DISPATCH_OP11_KEY, \
    RESUME_DISPATCH_OP11_BYTES
resume_dispatch_table_end:

resume_dispatch_end:

%if (resume_dispatch_table_end - resume_dispatch_table) != (11 * 6)
%error "resumption dispatcher table geometry drifted"
%endif
%if (resume_dispatch_header - resume_dispatch_entry) != 2
%error "resumption dispatcher header moved from file offset 2"
%endif
%if ($ - $$) > 0x0100
%error "fixed resumption dispatcher exceeds 0x0500..0x05ff"
%endif
