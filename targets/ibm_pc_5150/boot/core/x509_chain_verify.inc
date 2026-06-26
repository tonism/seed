; Build 12 auto-recertify: the off-race X.509 chain-verify -- "does this freshly-presented leaf
; chain to the pinned WR1?"  Ties together the strict parser, SHA-256 over the TBS, and the
; RSA-PKCS#1 verify against the baked WR1 anchor. Runs OFF the ~15s race (only on a detected leaf
; rotation), so its cost (~1 RSA verify + 1 SHA) is unconstrained by the handshake window.
;
; in:  SI = leaf Certificate DER, CX = length.
; out: CF=0 accept -- structural+policy gates pass AND the signature chains to WR1; the caller then
;        does the validity-vs-RTC compare (x509_nb_ptr/x509_na_ptr) and rsa_adopt (x509_mod_ptr).
;      CF=1 reject -- fail closed.
; deps: x509_parse_leaf (x509_verify.inc), sha256_init/update/finish (sha256.inc), the wr1_* anchor
;       constants (rsa_anchor_wr1.inc), rsa_pkcs1_verify + rsa_verify (rsa_pkcs1.inc/rsa_verify.inc).
; cpu 8086.

x509_chain_verify:
    call    x509_parse_leaf                      ; strict DER + policy gates + field extraction
    jc      .reject
    ; SHA-256 over the exact TBS span (the parser captured its ptr+len)
    call    sha256_init
    mov     si, [x509_tbs_ptr]
    mov     cx, [x509_tbs_len]
    call    sha256_update
    mov     di, x509_tbs_hash
    call    sha256_finish
    ; load the pinned WR1 modulus into the rsa_verify working constants
    call    x509_load_wr1
    ; verify the leaf's signature against WR1 over the TBS hash (1 RSA verify, reconstruct+compare)
    mov     si, [x509_sig_ptr]
    mov     di, x509_tbs_hash
    call    rsa_pkcs1_verify
    jc      .reject
    clc
    ret
.reject:
    stc
    ret

; Install the pinned WR1 modulus into the rsa_verify inputs. We bake ONLY wr1_n (256 B) and DERIVE the
; Montgomery constants (rsa_r2 / rsa_n0inv) on the fly via rsa_adopt_derive -- ~514 B less in the module
; so the captured leaf fits the handshake-transient slot above the module (not the arena -> mid-chat
; safe). rsa_one is the shared constant 1. The ~2s r2 derivation is fully off-race. The off-race
; chain-verify and the in-race leaf verify never run at once, so they share the rsa_* constants; after a
; successful chain-verify, rsa_adopt overwrites them with the new leaf.
x509_load_wr1:
    push    ds
    pop     es
    cld
    mov     si, wr1_n
    mov     di, rsa_n
    mov     cx, 128
    rep     movsw                            ; rsa_n <- WR1 modulus (already LE limbs)
    mov     word [rsa_one], 1                ; rsa_one = the integer 1 (shared; rsa_adopt_derive leaves it, rest stays 0)
    jmp     rsa_adopt_derive                 ; derive rsa_r2 + rsa_n0inv from rsa_n; tail-call (rets to caller)

align 2
x509_tbs_hash: times 32 db 0
