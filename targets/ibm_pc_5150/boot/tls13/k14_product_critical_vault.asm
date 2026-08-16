; Deadline-only K14 video-vault writer.
;
; The full public-vault lifecycle verifies every page before entering raw mode.
; This fixed half-sector leaf then performs only status-last writes of objects
; whose authority is supplied later by duplicated entropy, TLS Server Finished,
; full ML-KEM FO, and the exact-leaf/CertificateVerify proof.  It never grants
; ordinary vault read authority: the off-window lifecycle must rebuild all CRC
; tags and return to checked mode before a normal access leaf can run.
;
; Entry: AL=virtual page 73h..7fh, SI=source, BP=count (>0).
; DS must be zero.  DS and SS are preserved; other registers and ES may be
; clobbered.  CF is clear only after inverse-status then status publication.

bits 16
cpu 8086

%ifndef K14_CRITICAL_VAULT_ORIGIN
%define K14_CRITICAL_VAULT_ORIGIN 0x2ee0
%endif

org K14_CRITICAL_VAULT_ORIGIN

k14_cv_virtual_start          equ 0x73
k14_cv_virtual_end            equ 0x7f
k14_cv_payload_len            equ 0x0d00
k14_cv_meta_rel               equ 0x0d00
k14_cv_meta_epoch             equ k14_cv_meta_rel + 0x0c
k14_cv_meta_epoch_inverse     equ k14_cv_meta_rel + 0x0e
k14_cv_meta_backend           equ k14_cv_meta_rel + 0x10
k14_cv_meta_access_mode       equ k14_cv_meta_rel + 0x15
k14_cv_meta_inverse_status    equ k14_cv_meta_rel + 0xfe
k14_cv_meta_status            equ k14_cv_meta_rel + 0xff

k14_cv_bda_crt_port           equ 0x0463
k14_cv_mda_crt_port           equ 0x03b4
k14_cv_cga_crt_port           equ 0x03d4
k14_cv_mda_segment            equ 0xb000
k14_cv_cga_segment            equ 0xb800
k14_cv_cga_offset             equ 0x1000
k14_cv_backend_mda            equ 1
k14_cv_raw_mode_pair          equ 0x5aa5
k14_cv_valid_status_pair      equ 0xa55a

k14_product_critical_vault_write:
    cld
    cmp al, k14_cv_virtual_start
    jb .bad
    cmp al, k14_cv_virtual_end
    ja .bad
    or bp, bp
    jz .bad
    sub al, k14_cv_virtual_start
    mov ah, al
    xor al, al
    mov di, ax
    add ax, bp
    jc .bad
    cmp ax, k14_cv_payload_len
    ja .bad

    mov dx, [k14_cv_bda_crt_port]
    cmp dx, k14_cv_mda_crt_port
    je .mda
    cmp dx, k14_cv_cga_crt_port
    jne .bad
    mov dx, k14_cv_cga_segment
    mov es, dx
    mov bx, k14_cv_cga_offset
    xor dx, dx
    jmp short .mapped
.mda:
    mov dx, k14_cv_mda_segment
    mov es, dx
    xor bx, bx
    mov dl, k14_cv_backend_mda
.mapped:
    cmp [es:bx + k14_cv_meta_backend], dl
    jne .bad
    cmp word [es:bx + k14_cv_meta_access_mode], k14_cv_raw_mode_pair
    jne .bad
    cmp word [es:bx + k14_cv_meta_inverse_status], \
        k14_cv_valid_status_pair
    jne .bad
    mov ax, [es:bx + k14_cv_meta_epoch]
    mov cx, ax
    not cx
    cmp cx, [es:bx + k14_cv_meta_epoch_inverse]
    jne .bad

    mov word [es:bx + k14_cv_meta_inverse_status], 0
    add di, bx
    mov cx, bp
    rep movsb
    inc ax
    mov [es:bx + k14_cv_meta_epoch], ax
    not ax
    mov [es:bx + k14_cv_meta_epoch_inverse], ax
    mov byte [es:bx + k14_cv_meta_inverse_status], 0x5a
    mov byte [es:bx + k14_cv_meta_status], 0xa5
    clc
    ret
.bad:
    stc
    ret

k14_product_critical_vault_write_end:

%if (k14_product_critical_vault_write_end - \
    k14_product_critical_vault_write) > 0xa0
%error "K14 critical vault writer exceeds its 160-byte tail slot"
%endif

times 0xa0 - ($ - $$) db 0
