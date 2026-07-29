; Streaming uncompressed TLS 1.3 Certificate + CertificateVerify parser PoC.
;
; This phase captures only the bounded first certificate (the leaf), validates
; the remainder of Certificate-list framing while discarding it, then applies a
; strict fixed-profile P-256 X.509 parser.  CertificateVerify is supplied as a
; separate complete authenticated handshake message (<=80 bytes).

bits 16
cpu 8086
org 0x1800

; During the protected flight the NIC receive frame still owns 0700h..08b6h.
; The ML-KEM ciphertext at 08c0h is dead after the candidate phase, so the
; tentative-plaintext callback may reuse exactly that low object band.
parser_leaf_buffer         equ 0x08c0
parser_leaf_capacity       equ 1024
parser_leaf_buffer_end     equ parser_leaf_buffer + parser_leaf_capacity
parser_stream_state_start  equ parser_leaf_buffer_end
parser_state               equ parser_stream_state_start
parser_failed              equ parser_state + 1
parser_body_remaining      equ parser_failed + 1
parser_list_remaining      equ parser_body_remaining + 2
parser_accumulator         equ parser_list_remaining + 2
parser_leaf_len            equ parser_accumulator + 2
parser_entry_remaining     equ parser_leaf_len + 2
parser_ext_remaining       equ parser_entry_remaining + 2
parser_leaf_write          equ parser_ext_remaining + 2
parser_chain_count         equ parser_leaf_write + 2
parser_certificate_done    equ parser_chain_count + 1
parser_stream_state_end    equ parser_certificate_done + 1
; X.509 parsing runs only after the symmetric protected-flight phase.  Its
; transient state may therefore reuse the retired HELLO handoff at 0d00h.
parser_x509_state_start    equ 0x0d00

; Reuse the symmetric overlay's existing 384-byte mutable record payload
; (sym_io_base + 5).  This is not additional high-memory allocation.
; K14's 3400h..3600h controller extension remains live and untouched.
parser_chunk_start         equ 0x39a5
parser_chunk_capacity      equ 384
parser_chunk_end           equ parser_chunk_start + parser_chunk_capacity

parser_leaf_output         equ 0x3600
parser_leaf_status         equ parser_leaf_output
parser_leaf_profile        equ parser_leaf_status + 1
parser_output_leaf_len     equ parser_leaf_profile + 2
parser_output_tbs_ptr      equ parser_output_leaf_len + 2
parser_output_tbs_len      equ parser_output_tbs_ptr + 2
parser_output_tbs_digest   equ parser_output_tbs_len + 2
parser_output_cert_sig_len equ parser_output_tbs_digest + 32
parser_output_cert_sig     equ parser_output_cert_sig_len + 2
parser_output_leaf_x       equ parser_output_cert_sig + 72
parser_output_leaf_y       equ parser_output_leaf_x + 32
parser_output_not_before   equ parser_output_leaf_y + 32
parser_output_not_after    equ parser_output_not_before + 14
parser_leaf_output_end     equ parser_output_not_after + 14

parser_cv_output           equ 0x3700
parser_cv_status           equ parser_cv_output
parser_cv_profile          equ parser_cv_status + 1
parser_transcript_status   equ parser_cv_profile + 2
parser_transcript_hash     equ parser_transcript_status + 1
parser_output_cv_digest    equ parser_transcript_hash + 32
parser_output_cv_sig_len   equ parser_output_cv_digest + 32
parser_output_cv_sig       equ parser_output_cv_sig_len + 2
parser_cv_output_end       equ parser_output_cv_sig + 72
parser_hash_status         equ parser_cv_output_end
parser_time_status         equ parser_hash_status + 1
parser_phase_output_end    equ parser_time_status + 1

; 001fh is the parser-earned structural/name/use profile.  issuer_auth requires
; 003fh; only a separate trusted-time policy may add bit 0020h after comparing
; the normalized validity fields emitted below.
parser_leaf_profile_value  equ 0x001f
parser_cv_profile_value    equ 0x0700
parser_certificate_max     equ 4096
parser_chain_cert_max      equ 2048
parser_entry_ext_max       equ 1024

PSTATE_HS_TYPE             equ 0
PSTATE_HS_LEN0             equ 1
PSTATE_HS_LEN1             equ 2
PSTATE_HS_LEN2             equ 3
PSTATE_CONTEXT             equ 4
PSTATE_LIST_LEN0           equ 5
PSTATE_LIST_LEN1           equ 6
PSTATE_LIST_LEN2           equ 7
PSTATE_LEAF_LEN0           equ 8
PSTATE_LEAF_LEN1           equ 9
PSTATE_LEAF_LEN2           equ 10
PSTATE_LEAF_DATA           equ 11
PSTATE_LEAF_EXT_LEN0       equ 12
PSTATE_LEAF_EXT_LEN1       equ 13
PSTATE_LEAF_EXT_DATA       equ 14
PSTATE_CHAIN_LEN0          equ 15
PSTATE_CHAIN_LEN1          equ 16
PSTATE_CHAIN_LEN2          equ 17
PSTATE_CHAIN_DATA          equ 18
PSTATE_CHAIN_EXT_LEN0      equ 19
PSTATE_CHAIN_EXT_LEN1      equ 20
PSTATE_CHAIN_EXT_DATA      equ 21
PSTATE_DONE                equ 22

cert_parser_table:
    dw cert_parser_reset
    dw cert_parser_feed
    dw cert_parser_finish_certificate
    dw cert_parser_set_transcript_hash
    dw cert_parser_parse_certificate_verify
    dw cert_parser_clear
    dw cert_parser_capture_reset
    dw cert_parser_capture_end - cert_parser_capture_reset
    dw cert_parser_image_end - $$
    dw 1

; Standalone phase reset: clear capture, parser work, and published outputs.
cert_parser_reset:
    cld
    call cert_parser_clear
    jmp cert_parser_mark_start

; Live protected-flight reset/rollback.  Unlike the standalone reset, this
; clears only the provisional leaf and streaming state.  It must not touch
; 3600h..3790h while that band still holds symmetric handshake state.
cert_parser_capture_reset:
    cld
    call cert_parser_capture_clear
cert_parser_mark_start:
    mov byte [parser_state], PSTATE_HS_TYPE
    mov ax, 1
    clc
    ret

cert_parser_capture_clear:
    push ax
    push cx
    push di
    push es
    push ds
    pop es
    cld
    xor ax, ax
    mov di, parser_leaf_buffer
    mov cx, parser_stream_state_end - parser_leaf_buffer
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

; Feed one tentative decrypted Certificate-handshake chunk. SI/CX may split at
; every byte; product callers cap a chunk at the 384-byte MSS. The caller may
; publish it only after the enclosing record tag passes.
cert_parser_feed:
    cld
    cmp byte [parser_failed], 0
    jne .failed
    cmp byte [parser_certificate_done], 0
    jne .failed
    cmp cx, parser_chunk_capacity
    ja .failed_latch
    or cx, cx
    jz .success
.byte:
    lodsb
    push cx
    call cert_parser_consume_byte
    pop cx
    jc .failed_latch
    loop .byte
.success:
    mov ax, 1
    clc
    ret
.failed_latch:
    mov byte [parser_failed], 1
.failed:
    xor ax, ax
    stc
    ret

; AL is one byte from the Certificate handshake message.
cert_parser_consume_byte:
    push ax
    push bx
    push dx
    mov bl, [parser_state]
    cmp bl, PSTATE_CONTEXT
    jb .dispatch
    cmp word [parser_body_remaining], 0
    je .bad
    dec word [parser_body_remaining]
    cmp bl, PSTATE_LEAF_LEN0
    jb .dispatch
    cmp bl, PSTATE_DONE
    jae .bad
    cmp word [parser_list_remaining], 0
    je .bad
    dec word [parser_list_remaining]
.dispatch:
    xor bh, bh
    shl bx, 1
    jmp word [cs:cert_parser_state_table + bx]

.type:
    cmp al, 11                    ; TLS Handshake Certificate
    jne .bad
    mov byte [parser_state], PSTATE_HS_LEN0
    jmp .ok
.hs_len0:
    or al, al                     ; bounded 16-bit body only
    jnz .bad
    mov word [parser_accumulator], 0
    mov byte [parser_state], PSTATE_HS_LEN1
    jmp .ok
.hs_len1:
    mov [parser_accumulator + 1], al
    mov byte [parser_state], PSTATE_HS_LEN2
    jmp .ok
.hs_len2:
    mov [parser_accumulator], al
    mov dx, [parser_accumulator]
    cmp dx, 10                    ; framing plus a nonempty leaf
    jb .bad
    cmp dx, parser_certificate_max
    ja .bad
    mov [parser_body_remaining], dx
    mov byte [parser_state], PSTATE_CONTEXT
    jmp .ok
.context:
    or al, al                     ; server request_context must be empty
    jnz .bad
    mov word [parser_accumulator], 0
    mov byte [parser_state], PSTATE_LIST_LEN0
    jmp .ok
.list_len0:
    or al, al                     ; bounded 16-bit list only
    jnz .bad
    mov byte [parser_state], PSTATE_LIST_LEN1
    jmp .ok
.list_len1:
    mov [parser_accumulator + 1], al
    mov byte [parser_state], PSTATE_LIST_LEN2
    jmp .ok
.list_len2:
    mov [parser_accumulator], al
    mov dx, [parser_accumulator]
    cmp dx, [parser_body_remaining]
    jne .bad
    cmp dx, 6
    jb .bad
    mov [parser_list_remaining], dx
    mov word [parser_accumulator], 0
    mov byte [parser_state], PSTATE_LEAF_LEN0
    jmp .ok
.leaf_len0:
    or al, al
    jnz .bad
    mov byte [parser_state], PSTATE_LEAF_LEN1
    jmp .ok
.leaf_len1:
    mov [parser_accumulator + 1], al
    mov byte [parser_state], PSTATE_LEAF_LEN2
    jmp .ok
.leaf_len2:
    mov [parser_accumulator], al
    mov dx, [parser_accumulator]
    or dx, dx
    jz .bad
    cmp dx, parser_leaf_capacity
    ja .bad
    mov bx, dx
    add bx, 2
    cmp bx, [parser_list_remaining]
    ja .bad
    mov [parser_leaf_len], dx
    mov [parser_entry_remaining], dx
    mov word [parser_leaf_write], parser_leaf_buffer
    mov byte [parser_state], PSTATE_LEAF_DATA
    jmp .ok
.leaf_data:
    mov bx, [parser_leaf_write]
    mov [bx], al
    inc word [parser_leaf_write]
    dec word [parser_entry_remaining]
    jnz .ok
    mov word [parser_accumulator], 0
    mov byte [parser_state], PSTATE_LEAF_EXT_LEN0
    jmp .ok
.leaf_ext_len0:
    mov [parser_accumulator + 1], al
    mov byte [parser_state], PSTATE_LEAF_EXT_LEN1
    jmp .ok
.leaf_ext_len1:
    mov [parser_accumulator], al
    mov dx, [parser_accumulator]
    cmp dx, parser_entry_ext_max
    ja .bad
    cmp dx, [parser_list_remaining]
    ja .bad
    mov [parser_ext_remaining], dx
    or dx, dx
    jz .next_entry
    mov byte [parser_state], PSTATE_LEAF_EXT_DATA
    jmp .ok
.leaf_ext_data:
    dec word [parser_ext_remaining]
    jnz .ok
    jmp .next_entry
.chain_len0:
    or al, al
    jnz .bad
    mov word [parser_accumulator], 0
    mov byte [parser_state], PSTATE_CHAIN_LEN1
    jmp .ok
.chain_len1:
    mov [parser_accumulator + 1], al
    mov byte [parser_state], PSTATE_CHAIN_LEN2
    jmp .ok
.chain_len2:
    mov [parser_accumulator], al
    mov dx, [parser_accumulator]
    or dx, dx
    jz .bad
    cmp dx, parser_chain_cert_max
    ja .bad
    mov bx, dx
    add bx, 2
    cmp bx, [parser_list_remaining]
    ja .bad
    mov [parser_entry_remaining], dx
    mov byte [parser_state], PSTATE_CHAIN_DATA
    jmp .ok
.chain_data:
    dec word [parser_entry_remaining]
    jnz .ok
    mov word [parser_accumulator], 0
    mov byte [parser_state], PSTATE_CHAIN_EXT_LEN0
    jmp .ok
.chain_ext_len0:
    mov [parser_accumulator + 1], al
    mov byte [parser_state], PSTATE_CHAIN_EXT_LEN1
    jmp .ok
.chain_ext_len1:
    mov [parser_accumulator], al
    mov dx, [parser_accumulator]
    cmp dx, parser_entry_ext_max
    ja .bad
    cmp dx, [parser_list_remaining]
    ja .bad
    mov [parser_ext_remaining], dx
    or dx, dx
    jz .next_entry
    mov byte [parser_state], PSTATE_CHAIN_EXT_DATA
    jmp .ok
.chain_ext_data:
    dec word [parser_ext_remaining]
    jnz .ok
.next_entry:
    cmp word [parser_list_remaining], 0
    jne .another
    cmp word [parser_body_remaining], 0
    jne .bad
    mov byte [parser_state], PSTATE_DONE
    mov byte [parser_certificate_done], 1
    jmp .ok
.another:
    inc byte [parser_chain_count]
    cmp byte [parser_chain_count], 4
    ja .bad
    mov byte [parser_state], PSTATE_CHAIN_LEN0
    jmp .ok
.done:
.bad:
    stc
    jmp .return
.ok:
    clc
.return:
    pop dx
    pop bx
    pop ax
    ret

cert_parser_state_table:
    dw cert_parser_consume_byte.type
    dw cert_parser_consume_byte.hs_len0
    dw cert_parser_consume_byte.hs_len1
    dw cert_parser_consume_byte.hs_len2
    dw cert_parser_consume_byte.context
    dw cert_parser_consume_byte.list_len0
    dw cert_parser_consume_byte.list_len1
    dw cert_parser_consume_byte.list_len2
    dw cert_parser_consume_byte.leaf_len0
    dw cert_parser_consume_byte.leaf_len1
    dw cert_parser_consume_byte.leaf_len2
    dw cert_parser_consume_byte.leaf_data
    dw cert_parser_consume_byte.leaf_ext_len0
    dw cert_parser_consume_byte.leaf_ext_len1
    dw cert_parser_consume_byte.leaf_ext_data
    dw cert_parser_consume_byte.chain_len0
    dw cert_parser_consume_byte.chain_len1
    dw cert_parser_consume_byte.chain_len2
    dw cert_parser_consume_byte.chain_data
    dw cert_parser_consume_byte.chain_ext_len0
    dw cert_parser_consume_byte.chain_ext_len1
    dw cert_parser_consume_byte.chain_ext_data
    dw cert_parser_consume_byte.done

cert_parser_capture_end:

; Clear all standalone parser work and outputs.  Product rollback during the
; protected flight uses cert_parser_capture_reset instead.
cert_parser_clear:
    push ax
    push cx
    push di
    push es
    call cert_parser_capture_clear
    push ds
    pop es
    cld
    xor ax, ax
    mov di, parser_stream_state_end
    mov cx, parser_x509_state_end - parser_stream_state_end
    rep stosb
    mov di, parser_leaf_output
    mov cx, parser_leaf_output_end - parser_leaf_output
    rep stosb
    mov di, parser_cv_output
    mov cx, parser_phase_output_end - parser_cv_output
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

cert_parser_finish_certificate:
    cld
    mov byte [parser_leaf_status], 0
    mov word [parser_leaf_profile], 0
    cmp byte [parser_failed], 0
    jne .failed
    cmp byte [parser_certificate_done], 1
    jne .failed
    mov si, parser_leaf_buffer
    mov cx, [parser_leaf_len]
    push es
    push ds
    pop es
    call x509_parse_leaf
    pop es
    jc .failed

    mov ax, [parser_leaf_len]
    mov [parser_output_leaf_len], ax
    mov ax, [x509_tbs_ptr]
    mov [parser_output_tbs_ptr], ax
    mov ax, [x509_tbs_len]
    mov [parser_output_tbs_len], ax
    mov ax, [x509_sig_len]
    mov [parser_output_cert_sig_len], ax
    mov si, [x509_sig_ptr]
    mov di, parser_output_cert_sig
    mov cx, ax
    call cert_parser_copy
    mov si, [x509_point_x_ptr]
    mov di, parser_output_leaf_x
    mov cx, 64
    call cert_parser_copy
    mov al, [x509_nb_tag]
    mov si, [x509_nb_ptr]
    mov di, parser_output_not_before
    call cert_parser_normalize_time
    jc .failed
    mov al, [x509_na_tag]
    mov si, [x509_na_ptr]
    mov di, parser_output_not_after
    call cert_parser_normalize_time
    jc .failed
    mov word [parser_leaf_profile], parser_leaf_profile_value
    mov byte [parser_leaf_status], 1
    mov ax, 1
    clc
    ret
.failed:
    mov byte [parser_failed], 1
    xor ax, ax
    stc
    ret

; Copy the live transcript hash through Certificate from the symmetric phase.
cert_parser_set_transcript_hash:
    cld
    mov byte [parser_transcript_status], 0
    cmp byte [parser_leaf_status], 1
    jne .failed
    cmp cx, 32
    jne .failed
    mov di, parser_transcript_hash
    call cert_parser_copy
    mov byte [parser_transcript_status], 1
    mov ax, 1
    clc
    ret
.failed:
    xor ax, ax
    stc
    ret

; Parse one complete authenticated TLS CertificateVerify handshake message.
cert_parser_parse_certificate_verify:
    cld
    mov byte [parser_cv_status], 0
    mov word [parser_cv_profile], 0
    cmp byte [parser_leaf_status], 1
    jne .failed
    cmp byte [parser_transcript_status], 1
    jne .failed
    cmp cx, 12
    jb .failed
    cmp cx, 80
    ja .failed
    mov dx, cx
    cmp byte [si], 15
    jne .failed
    cmp byte [si + 1], 0
    jne .failed
    mov ax, [si + 2]
    xchg al, ah
    mov bx, dx
    sub bx, 4
    cmp ax, bx
    jne .failed
    cmp word [si + 4], 0x0304       ; scheme 04 03
    jne .failed
    cmp byte [si + 6], 0
    jne .failed
    mov al, [si + 7]
    xor ah, ah
    cmp ax, 8
    jb .failed
    cmp ax, 72
    ja .failed
    mov bx, ax
    add bx, 8
    cmp bx, dx
    jne .failed
    push si
    add si, 8
    mov cx, ax
    call x509_check_ecdsa_signature
    pop si
    jc .failed
    mov [parser_output_cv_sig_len], ax
    add si, 8
    mov di, parser_output_cv_sig
    mov cx, ax
    call cert_parser_copy
    mov word [parser_cv_profile], parser_cv_profile_value
    mov byte [parser_cv_status], 1
    mov ax, 1
    clc
    ret
.failed:
    xor ax, ax
    stc
    ret

cert_parser_copy:
    push es
    push ds
    pop es
    cld
    rep movsb
    pop es
    ret

; Normalize UTCTime/GeneralizedTime to YYYYMMDDHHMMSS without evaluating it
; against a clock.
cert_parser_normalize_time:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    push ds
    pop es
    cmp al, 0x17
    jne .generalized
    mov bx, si
    call x509_decimal_pair
    cmp al, 50
    jb .year_20
    mov ax, 0x3931                ; "19"
    jmp .year
.year_20:
    mov ax, 0x3032                ; "20"
.year:
    stosw
    mov cx, 12
    rep movsb
    jmp .ok
.generalized:
    cmp al, 0x18
    jne .bad
    mov cx, 14
    rep movsb
.ok:
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    clc
    ret
.bad:
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    stc
    ret

%include "cert_parser_p256.inc"

cert_parser_image_end:

%if parser_stream_state_end > parser_x509_state_start
%error "stream state overlaps X.509 state"
%endif
%if parser_x509_state_end > 0x0d40
%error "X.509 state exceeds low parser-state budget"
%endif
%if (cert_parser_image_end - $$) > (0x3400 - 0x1800)
%error "certificate parser exceeds 14-sector code phase"
%endif
%if parser_phase_output_end > parser_chunk_start
%error "certificate parser output overlaps high input window"
%endif
%if parser_chunk_end > 0x3b9c
%error "certificate parser high input reaches attempt cache"
%endif
%if parser_leaf_output_end > parser_cv_output
%error "leaf output overlaps CertificateVerify output"
%endif
%if parser_phase_output_end > 0x3b9c
%error "certificate parser output reaches attempt cache"
%endif
