; Build 12 286 secure tier: the handshake-only P-256 ECDHE module.
;
; Assembled as its OWN flat binary at its run address (org p256_module_load) so the ~5 KiB of
; p256.inc -- which is full of absolute self-references (mov si, p256_s0; call p256_mul_mod; ...) --
; resolves correctly without the per-label PHASE_BASE fixup that small phases use. The .bin is then
; incbin'd into CORE.SYS (core.asm) and loaded -- ONLY on the 286 secure path -- into the high
; overlay band that aliases the 32K loop cache (lifetime-disjoint: this runs during the boot
; handshake; the loop cache is preloaded after it). The 16K / 8088 tier never loads it, so inactive
; it costs 0 resident RAM.
;
; ABI: an entry-point-only contract -- a fixed 3-byte-stride near-jump table at the module base
; (p256_module_load). The resident K-window code calls in with `mov ax, p256_ep_*; call ax` (the
; equates live in layout.inc), so NO module data offset is ever exposed across the boundary. The
; module is fully self-contained (p256.inc has no resident dependency); the ONLY cross-boundary
; write is the derived premaster -> tls_premaster_secret (0x3600, the resident high crypto scratch).

cpu 8086
bits 16
%include "core/layout.inc"
org p256_module_load

; The one data.inc equate p256.inc needs (data.inc itself emits real bytes -- nic_vtable etc. -- so
; it must NOT be included into this module unit; this single equate is all p256.inc references).
tls_premaster_secret equ high_crypto_work

; ---- ABI dispatch table: 5 near-pointer WORDS at the module base. The resident code calls in via
; `call word [p256_ep_*]` (each equate in layout.inc IS a table-slot address). A word table -- not a
; jmp table -- so there is no short/near jmp-size ambiguity (NASM shortens `jmp near` to a 2-byte
; `jmp short` for nearby targets); the stride is exactly 2 by construction. (Size assert at the tail.)
p256_module_entry:
p256_ep_table:
    dw p256_ep_set_client_private_impl          ; [p256_module_load + 0]
    dw p256_ep_gen_client_public_impl           ; [+2]
    dw p256_ep_set_server_ec_impl               ; [+4]
    dw p256_ep_compute_premaster_impl           ; [+6]
    dw p256_ep_copy_client_public_impl          ; [+8]
p256_ep_table_end:

; ---- entry implementations (thin wrappers over the verified p256.inc primitives) ----

p256_ep_set_client_private_impl:
    ; in: SI = ptr to a 32-byte secret (big-endian; the resident SHA-256 entropy digest).
    ; Stores it as the little-endian-word client ephemeral scalar. A SHA-256 output is never 1/2
    ; (LANDMINE #3) and, if >= the group order, reduces mod n in the group -- consistently used for
    ; both the client public (priv x G) and the premaster (priv x server_pub), so the handshake agrees.
    mov di, p256_client_private
    call p256_from_be32
    ret

p256_ep_gen_client_public_impl:
    ; client ephemeral public = client_private x G (affine), encoded uncompressed into
    ; p256_client_public_uncompressed (0x04 || X_be32 || Y_be32). out: CF=1 on a degenerate result.
    mov word [p256_affine_x_ptr], p256_generator_x
    mov word [p256_affine_y_ptr], p256_generator_y
    mov si, p256_client_private
    call p256_scalar_mult_mixed                 ; jac = priv x G
    mov si, p256_jac_z
    call p256_is_zero
    jc .fail                                    ; identity / degenerate -> refuse
    mov di, p256_cpub_x_words
    mov bx, p256_cpub_y_words
    call p256_w_to_affine                       ; jac -> affine (cpub_x, cpub_y)
    mov byte [p256_client_public_uncompressed], 0x04
    mov si, p256_cpub_x_words
    mov di, p256_client_public_uncompressed + 1
    call p256_to_be32
    mov si, p256_cpub_y_words
    mov di, p256_client_public_uncompressed + 1 + tls_ec_coordinate_len
    call p256_to_be32
    clc
    ret
.fail:
    stc
    ret

p256_ep_set_server_ec_impl:
    ; in: SI = ptr to server X (32 big-endian bytes), DI = ptr to server Y (32 big-endian bytes),
    ; both inside the ServerKeyExchange buffer. Convert + store as the server public point.
    push di                                     ; save Y ptr
    mov di, tls_server_ec_x_words
    call p256_from_be32                          ; x_words <- be32(X)   (from_be32 preserves SI/DI)
    pop si                                       ; si = Y ptr
    mov di, tls_server_ec_y_words
    call p256_from_be32                          ; y_words <- be32(Y)
    ret

p256_ep_compute_premaster_impl:
    ; premaster = client_private x server_public; the be32 shared X lands in tls_premaster_secret
    ; (0x3600). out: CF=1 on failure (degenerate point). Tail-jump: its ret returns to our caller.
    jmp p256_compute_server_premaster_secret

p256_ep_copy_client_public_impl:
    ; in: DI = destination. Copies the 65-byte uncompressed client public key for the CKE.
    push ds
    pop es
    cld
    mov si, p256_client_public_uncompressed
    mov cx, tls_ec_public_uncompressed_len
    rep movsb
    ret

; ---- the verified P-256 implementation + its module-resident data ----
%include "core/p256.inc"
%include "core/p256_data.inc"

p256_module_image_end:

; ---- tail asserts (label DIFFERENCES, org-independent, so NASM %if evaluates them correctly) ----
%if (p256_ep_table_end - p256_module_entry) != 10
%error "p256 module ABI table must be exactly 5 near-pointer words (the +0/+2/+4/+6/+8 stride)"
%endif
%if (p256_module_image_end - p256_module_entry) > p256_module_max_len
%error "p256 module (code + data) exceeds its band -- raise p256_module_max_sectors (must fit the loop cache)"
%endif
