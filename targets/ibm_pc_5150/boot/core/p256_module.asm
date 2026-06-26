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
    dw p256_ep_verify_ske_sig_impl              ; [+10]  (286 secure tier increment B: RSA cert auth)
    dw p256_ep_parse_leaf_impl                  ; [+12]  (auto-recertify: X.509 strict-DER parse)
    dw p256_ep_chain_verify_sig_impl            ; [+14]  (auto-recertify: verify leaf sig vs WR1)
    dw p256_ep_adopt_leaf_impl                  ; [+16]  (auto-recertify: adopt the new leaf key)
p256_ep_table_end:
; Auto-recertify result block at a FIXED ABI offset (p256_module_load + 18, right after the 9-word
; table) -- p256_ep_parse_leaf copies the parser's extracted field pointers here so the resident
; orchestration can read them across the module boundary (the parser's own labels are module-internal).
p256_x509_results:
    dw 0    ; [+18] tbs_ptr
    dw 0    ; [+20] tbs_len
    dw 0    ; [+22] sig_ptr
    dw 0    ; [+24] mod_ptr (the leaf modulus to adopt)
    dw 0    ; [+26] notBefore ptr
    dw 0    ; [+28] notAfter ptr
; Auto-recertify capture entry points, a second fixed pointer block at +30 (the leaf capture is
; 286-only, so it lives in the module; the K-window drain calls these via the table). Placed after
; the result block so the existing +0..+28 ABI offsets are unchanged.
p256_capture_ep_table:
    dw p256_ep_capture_reset_impl               ; [+30]  reset the capture cursor (drain start)
    dw p256_ep_capture_chunk_impl               ; [+32]  fold one drained fragment into the leaf
    dw p256_ep_recertify_prep_impl              ; [+34]  if a leaf was captured, parse it -> result block

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

; ---- 286 secure tier increment B: RSA cert authentication (leaf-key pin) ----
; Verify the ServerKeyExchange's RSA-PKCS1-v1.5-SHA256 signature against the PINNED leaf public key
; (rsa_pinned_key.inc). This is the ONE in-race RSA verify; passing it proves the server holds the
; pinned api.openai.com leaf private key (possession proof) -> the channel is authenticated.
; in:  SI = the 256-byte signature (big-endian wire bytes), DI = the 32-byte expected hash h =
;          SHA-256(client_random || server_random || ServerECDHParams) -- the resident K window does
;          the SHA (the module has none) and hands h in.
; out: CF=0 valid, CF=1 invalid. Rigour: the recovered block is compared to a fully RECONSTRUCTED
;      EMSA-PKCS1-v1.5 block (00 01 FF..FF 00 DigestInfo h) with a whole-256-byte memcmp -- no lax
;      structural parsing, so padding-forgery vectors (e.g. Bleichenbacher-style) cannot slip through.
p256_ep_verify_ske_sig_impl:
    push di                                      ; save h ptr
    mov di, rsa_sig
    call rsa_from_be256                          ; rsa_sig <- the wire signature (BE -> LE words)
    pop si                                       ; si = h
    call rsa_build_expected_block                ; rsa_expected <- EMSA-PKCS1-v1.5(h)
    call rsa_verify                              ; rsa_result = rsa_sig^65537 mod rsa_n (LE words)
    mov si, rsa_result
    mov di, rsa_recovered
    call rsa_to_be256                            ; rsa_recovered <- the recovered block (LE words -> BE)
    push ds
    pop es
    cld
    mov si, rsa_recovered
    mov di, rsa_expected
    mov cx, tls_ec_coordinate_len * 8            ; 256 bytes
    repe cmpsb
    jne .invalid
    clc
    ret
.invalid:
    stc
    ret

; si = 256 big-endian bytes, di = 128 LE-word dest. Preserves SI/DI (so the caller's h ptr survives).
rsa_from_be256:
    push ax
    push bx
    push cx
    push si
    push di
    mov bx, si
    add bx, 255                                  ; -> the least-significant byte
    mov cx, 128
.next:
    mov al, [bx]
    mov ah, [bx - 1]
    mov [di], ax
    add di, 2
    sub bx, 2
    loop .next
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

; si = 128 LE words, di = 256 big-endian bytes dest.
rsa_to_be256:
    push ax
    push bx
    push cx
    push si
    push di
    mov bx, si
    add bx, 254                                  ; -> the most-significant word
    mov cx, 128
.next:
    mov ax, [bx]
    mov [di], ah                                 ; high byte first (big-endian)
    mov [di + 1], al
    add di, 2
    sub bx, 2
    loop .next
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

; si = the 32-byte hash h. Reconstructs the EMSA-PKCS1-v1.5(SHA-256) block (big-endian) into
; rsa_expected: 00 01 [FF x 202] 00 [19-byte SHA-256 DigestInfo prefix] [h x 32] (= 256 bytes).
rsa_build_expected_block:
    push ds
    pop es
    cld
    mov dx, si                                   ; stash h ptr
    mov di, rsa_expected
    mov al, 0x00
    stosb
    mov al, 0x01
    stosb
    mov al, 0xff
    mov cx, 202
    rep stosb
    mov al, 0x00
    stosb
    mov si, rsa_sha256_digestinfo
    mov cx, 19
    rep movsb
    mov si, dx
    mov cx, 32
    rep movsb
    ret

; The DER DigestInfo prefix for SHA-256 (RFC 8017): SEQ{ SEQ{ OID sha256, NULL }, OCTET STRING(32) }.
rsa_sha256_digestinfo:
    db 0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
rsa_expected:  times 256 db 0
rsa_recovered: times 256 db 0

; ---- auto-recertify entry points (off-race X.509 chain-verify + adopt; 286 secure path) ----
; p256_ep_parse_leaf: strict-DER parse the leaf cert. in: SI=cert DER, CX=len. out: CF; on accept,
; the extracted field pointers are copied to the fixed result block for the resident orchestrator.
p256_ep_parse_leaf_impl:
    call x509_parse_leaf
    jc .pl_fail
    mov ax, [x509_tbs_ptr]
    mov [p256_x509_results + 0], ax
    mov ax, [x509_tbs_len]
    mov [p256_x509_results + 2], ax
    mov ax, [x509_sig_ptr]
    mov [p256_x509_results + 4], ax
    mov ax, [x509_mod_ptr]
    mov [p256_x509_results + 6], ax
    mov ax, [x509_nb_ptr]
    mov [p256_x509_results + 8], ax
    mov ax, [x509_na_ptr]
    mov [p256_x509_results + 10], ax
    clc
    ret
.pl_fail:
    stc
    ret

; p256_ep_chain_verify_sig: verify the leaf signature chains to the pinned WR1. in: SI=256-byte
; signature, DI=32-byte SHA-256(TBS) hash (the resident K window computes the hash, as for the SKE
; sig). out: CF=0 valid. Loads WR1 into the rsa_verify constants, then REUSES the shipped SKE-verify
; routine verbatim (it is modulus-agnostic -- it verifies against whatever rsa_n is loaded).
p256_ep_chain_verify_sig_impl:
    push si                                      ; x509_load_wr1's rep movsw clobber SI/DI, but the
    push di                                      ; SKE-verify routine below needs SI=sig, DI=hash
    call x509_load_wr1
    pop di
    pop si
    call p256_ep_verify_ske_sig_impl             ; (1) leaf sig chains to the pinned WR1?
    jc .cv_reject
    call ntp_validity_ok                         ; (2) auto-recertify task#7: leaf in its validity window
    jc .cv_reject                                ;     per the NTP-synced CMOS RTC (skips if RTC unset)
    clc
    ret
.cv_reject:
    stc
    ret

; Task #7 cert-validity gate: is the parsed leaf currently within [notBefore, notAfter]? Reads the
; CMOS RTC (set from NTP at boot, before any TLS, so "now" is independent of this connection), renders
; it as the leaf's own UTCTime form "YYMMDDHHMMSS", and does a byte-lexicographic compare against the
; leaf's notBefore/notAfter (result block +8/+10, already UTCTime content from the parser). FAIL-OPEN:
; if the RTC read fails or reads an implausible century (NTP never synced), SKIP -> CF=0 (best-effort,
; matching the cold-recertify-skips design). Mirrors tools/x509/http_date_rtc.py's compare. cpu 8086.
ntp_validity_ok:
    push    ds
    pop     es                                   ; ES=DS=0 for the stosb/cmpsb below
    mov     ah, 0x04
    int     0x1a                                 ; CH=century CL=year DH=month DL=day (BCD); CF=1 = not set
    jc      .skip
    ; Sanity on the YEAR (CL), not the century byte (CH): the CMOS century reg is unreliable (BIOSes
    ; vary; 86Box's crafted CMOS leaves it unset), and the leaf's UTCTime is 2-digit-year anyway
    ; (RFC 5280: 00-49 -> 20xx), so the whole compare runs in 2-digit-year space. A plausible synced
    ; year is BCD 0x24..0x49 (2024..2049); anything else means the RTC was never NTP-synced -> skip.
    cmp     cl, 0x24
    jb      .skip
    cmp     cl, 0x50
    jae     .skip
    cld
    mov     di, ntp_now_str
    mov     al, cl                               ; year
    call    .emit_bcd
    mov     al, dh                               ; month
    call    .emit_bcd
    mov     al, dl                               ; day
    call    .emit_bcd
    mov     ah, 0x02
    int     0x1a                                 ; CH=hour CL=min DH=sec (BCD)
    jc      .skip
    mov     al, ch                               ; hour
    call    .emit_bcd
    mov     al, cl                               ; minute
    call    .emit_bcd
    mov     al, dh                               ; second
    call    .emit_bcd
    ; now = "YYMMDDHHMMSS"; require notBefore <= now <= notAfter (12-byte lexicographic).
    mov     si, ntp_now_str
    mov     di, [p256_x509_results + 8]          ; notBefore (UTCTime content)
    mov     cx, 12
    repe    cmpsb
    jb      .reject                              ; now < notBefore -> not yet valid
    mov     si, ntp_now_str
    mov     di, [p256_x509_results + 10]         ; notAfter
    mov     cx, 12
    repe    cmpsb
    ja      .reject                              ; now > notAfter -> expired
.skip:
    clc
    ret
.reject:
    stc
    ret
.emit_bcd:                                       ; al = BCD byte -> two ASCII digits at [di]; di += 2
    mov     ah, al
    push    cx
    mov     cl, 4
    shr     al, cl
    pop     cx
    add     al, '0'
    stosb
    mov     al, ah
    and     al, 0x0f
    add     al, '0'
    stosb
    ret

align 2
ntp_now_str: times 12 db 0

; p256_ep_adopt_leaf: install a chain-verified leaf as the fast-path pin. in: SI=256-byte BE modulus.
p256_ep_adopt_leaf_impl:
    call rsa_adopt
    clc
    ret

; x509_load_wr1: install the pinned WR1 modulus into the rsa_verify working constants. Only wr1_n is
; baked; rsa_adopt_derive computes the Montgomery constants (r2, n0inv) on the fly -- ~514 B less in
; the module so the captured leaf fits the handshake-transient slot above the module (not the arena ->
; mid-chat-safe recertify). rsa_one is the shared 1; the ~2s r2 derivation is fully off-race. The
; off-race chain-verify and the in-race leaf verify never overlap, so they share the rsa_* constants;
; after a successful chain-verify + adopt, rsa_* hold the new leaf for the retry handshake's SKE verify.
x509_load_wr1:
    push ds
    pop es
    cld
    mov si, wr1_n
    mov di, rsa_n
    mov cx, 128
    rep movsw                            ; rsa_n <- WR1 modulus (already LE limbs)
    mov word [rsa_one], 1                ; rsa_one = the integer 1 (shared; rsa_adopt_derive leaves it, rest stays 0)
    jmp rsa_adopt_derive                 ; derive rsa_r2 + rsa_n0inv from rsa_n; tail-call (rets to caller)

; ---- auto-recertify capture entry points (286-only; the leaf capture lives in the module) ----
; p256_ep_capture_reset: reset the capture cursor; call once at the cert-drain start (from net_phase,
; before the handshake, so it costs no K-window bytes).
p256_ep_capture_reset_impl:
    jmp capture_leaf_reset
; p256_ep_capture_chunk: fold one drained fragment into the captured leaf. in: SI=fragment, CX=len.
p256_ep_capture_chunk_impl:
    jmp capture_leaf_chunk
; p256_ep_recertify_prep: if a leaf was captured this handshake, strict-DER parse it and publish the
; field pointers to the result block. out: CF=0 = a leaf was captured + parsed OK (the resident
; orchestration then does SHA -> chain-verify-vs-WR1 -> validity -> adopt); CF=1 = no leaf OR bad parse.
p256_ep_recertify_prep_impl:
    cmp word [capture_leaf_len], 0
    je .none
    mov si, [capture_buf_ptr]
    mov cx, [capture_leaf_len]
    jmp p256_ep_parse_leaf_impl                  ; parses + copies results to the block + returns CF
.none:
    stc
    ret

; ---- the verified P-256 + RSA implementations + the module-resident data ----
%include "core/p256.inc"
%include "core/p256_data.inc"
%include "core/rsa_verify.inc"
%include "core/rsa_pinned_key.inc"
%include "core/x509_verify.inc"
%include "core/rsa_adopt.inc"
%include "core/rsa_anchor_wr1.inc"
%include "core/x509_capture.inc"

p256_module_image_end:

; ---- tail asserts (label DIFFERENCES, org-independent, so NASM %if evaluates them correctly) ----
%if (p256_ep_table_end - p256_module_entry) != 18
%error "p256 module ABI table must be exactly 9 near-pointer words (+0..+16; auto-recertify added +12/+14/+16)"
%endif
%if (p256_x509_results - p256_module_entry) != 18
%error "p256_x509_results must sit at module offset +18 (the layout.inc p256_x509_result_* equates depend on it)"
%endif
%if (p256_capture_ep_table - p256_module_entry) != 30
%error "p256_capture_ep_table must sit at module offset +30 (the layout.inc p256_ep_capture_* equates depend on it)"
%endif
%if (p256_module_image_end - p256_module_entry) > p256_module_max_len
%error "p256 module (code + data) exceeds its band -- raise p256_module_max_sectors (must fit the loop cache)"
%endif
