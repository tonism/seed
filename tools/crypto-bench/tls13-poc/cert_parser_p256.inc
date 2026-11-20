; Bounded fixed-profile ECDSA X.509 leaf parser for the TLS 1.3 PC/16 PoC.
;
; The false-security crux, ported from the offline oracle (tools/x509/x509_verify.py); the tamper
; matrix (tools/x509/tamper_matrix.py) is the reference and tools/crypto-bench/x509_eval.py runs
; THIS code under unicorn against the same vectors. RULE: strict DER for every
; walked/profile field, positional walk, fail closed. A wrong security-relevant
; length/tag accepts a forged cert.
;
; It enforces strict TLV bounds/minimal lengths for the walked fields,
; positional Certificate/TBS structure, exact ECDSA-with-SHA256 algorithms
; (SHA384 with X509_ISSUER_P384; callers supply its strict scalar parser),
; exact uncompressed P-256 SPKI,
; required leaf usage extensions, and exactly one SAN extension containing the
; exact host.  It extracts the TBS span, strict DER ECDSA signature, leaf point,
; and validity fields. Signature proof under the caller's immutable issuer,
; point validation, hashing,
; and trusted-time policy are separate phases.
;
; in:  SI = pointer to the leaf Certificate DER, CX = its total length.
; out: CF=0 accept (structural+policy ok), CF=1 reject. On accept the x509_* result words are set.
; clobbers AX BX CX DX SI DI (preserves BP). cpu 8086.

%define X509_HOST_LEN 14            ; "api.openai.com"

; descend into the TLV just read by der_read (DI=content, CX=len): save (cursor, bound), narrow.
; The body is factored into the der_descend routine (called) to fold its 9 expansions; the routine
; preserves the parent (si, der_end) on the stack BELOW its return address so DER_ASCEND's two pops
; still balance it. (der_descend clobbers AX/DX -- both are der_read-volatile + dead at every site.)
%macro DER_DESCEND 0
    call    der_descend
%endmacro
%macro DER_ASCEND 0
    pop     word [der_end]
    pop     si
%endmacro

x509_parse_leaf:
    push    bp
    mov     bp, sp                  ; any reject just restores SP to here -- no per-site SP counting
    mov     [x509_buf_end], si
    add     [x509_buf_end], cx      ; absolute end of the cert buffer (the no-trailing bound)
%ifdef X509_ISSUER_DUAL
    mov     byte [x509_issuer_algorithm], 0
%endif
    mov     byte [x509_san_count], 0
    mov     byte [x509_host_found], 0
    mov     byte [x509_bc_count], 0
    mov     byte [x509_ku_count], 0
    mov     byte [x509_eku_count], 0
    mov     ax, si
    add     ax, cx
    mov     [der_end], ax

    ; ---- Certificate ::= SEQUENCE ----
    call    der_read_seq
    jc      .reject
    cmp     si, [x509_buf_end]      ; nothing may follow the Certificate
    jne     .reject
    DER_DESCEND                     ; [frame C] -> Certificate content

    ; ---- tbsCertificate ::= SEQUENCE  (capture the exact signed span) ----
    mov     [x509_tbs_ptr], si
    call    der_read_seq
    jc      .reject
    mov     ax, di
    add     ax, cx
    sub     ax, [x509_tbs_ptr]      ; (content end) - (tag start) = full TBS length
    mov     [x509_tbs_len], ax
    DER_DESCEND                     ; [frame T] -> TBS content (frame T saved the post-TBS cursor)

    ; version [0] EXPLICIT { INTEGER 2 }  (v3, required for extensions/SAN)
    call    der_read
    jc      .reject
    cmp     al, 0xA0
    jne     .reject
    DER_DESCEND                     ; [frame V]
    call    der_read_int
    jc      .reject
    cmp     cx, 1
    jne     .reject
    cmp     byte [di], 2
    jne     .reject
    cmp     si, [der_end]
    jne     .reject
    DER_ASCEND                      ; [frame V released]

    ; serialNumber INTEGER: positive, nonzero, canonical, <=20 content bytes.
    call    der_read_int
    jc      .reject
    cmp     cx, 20
    ja      .reject
    call    x509_check_positive_integer
    jc      .reject

    ; signature AlgorithmIdentifier (inner) == ecdsa-with-SHA256
    call    .read_sigalg
    jc      .reject

    ; issuer Name outer SEQUENCE (signed inner Name content stays opaque)
    call    der_read_seq
    jc      .reject

    ; validity SEQUENCE { notBefore, notAfter }
    call    der_read_seq
    jc      .reject
    DER_DESCEND                     ; [frame Va]
    call    .read_time
    jc      .reject
    mov     [x509_nb_ptr], di
    mov     [x509_nb_len], cl
    mov     [x509_nb_tag], al
    call    .read_time
    jc      .reject
    mov     [x509_na_ptr], di
    mov     [x509_na_len], cl
    mov     [x509_na_tag], al
    cmp     si, [der_end]           ; exactly two times
    jne     .reject
    DER_ASCEND                      ; [frame Va released]

    ; subject Name outer SEQUENCE (signed inner Name content stays opaque)
    call    der_read_seq
    jc      .reject

    ; subjectPublicKeyInfo -> exact P-256 point.
    call    der_read_seq
    jc      .reject
    DER_DESCEND                     ; [frame S]
    call    .parse_spki
    jc      .reject
    DER_ASCEND                      ; [frame S released]

    ; optional issuerUniqueID [1] / subjectUniqueID [2]; then extensions [3] EXPLICIT
.find_ext:
    cmp     si, [der_end]
    jae     .reject                 ; reached TBS end without extensions -> no SAN possible
    call    der_read
    jc      .reject
    cmp     al, 0xA1
    je      .find_ext
    cmp     al, 0xA2
    je      .find_ext
    cmp     al, 0xA3
    jne     .reject
    DER_DESCEND                     ; [frame X1] -> [3] content
    call    der_read_seq            ; SEQUENCE OF Extension
    jc      .reject
    cmp     si, [der_end]           ; [3] holds exactly that one SEQUENCE
    jne     .reject
    DER_DESCEND                     ; [frame X2] -> the extensions list
.ext_loop:
    cmp     si, [der_end]
    jae     .ext_done
    call    der_read_seq            ; Extension ::= SEQUENCE
    jc      .reject
    DER_DESCEND                     ; [frame E]
    call    .parse_ext
    jc      .reject
    DER_ASCEND                      ; [frame E released]
    jmp     .ext_loop
.ext_done:
    DER_ASCEND                      ; [frame X2 released]
    DER_ASCEND                      ; [frame X1 released] -> TBS level, cursor after [3]
    cmp     si, [der_end]           ; extensions is the last TBS field -> TBS fully consumed
    jne     .reject
    DER_ASCEND                      ; [frame T released] -> Certificate level, cursor at outer sigAlg

    ; ---- outer signatureAlgorithm == inner (exact selected issuer profile) ----
    call    .read_sigalg
    jc      .reject

    ; ---- signatureValue BIT STRING (00 unused bits || strict DER ECDSA) ----
    call    der_read
    jc      .reject
    cmp     al, 0x03
    jne     .reject
    cmp     cx, 9                   ; 1 unused-bits byte + minimum 8-byte DER
    jb      .reject
    %ifdef X509_ISSUER_P384
    cmp     cx, 105                 ; unused-bits byte + maximum 104-byte DER
%else
    cmp     cx, 73                  ; 1 unused-bits byte + maximum 72-byte DER
%endif
    ja      .reject
    cmp     byte [di], 0x00
    jne     .reject
    cmp     si, [x509_buf_end]      ; Certificate body fully consumed
    jne     .reject
    mov     ax, di
    inc     ax
    mov     [x509_sig_ptr], ax
    dec     cx
    mov     [x509_sig_len], cx
    mov     si, ax
    call    x509_check_ecdsa_signature
    jc      .reject

    ; ---- required leaf extension policy ----
    cmp     byte [x509_san_count], 1
    jne     .reject
    cmp     byte [x509_host_found], 1
    jne     .reject
    cmp     byte [x509_bc_count], 1
    jne     .reject
    cmp     byte [x509_ku_count], 1
    jne     .reject
    cmp     byte [x509_eku_count], 1
    jne     .reject

    DER_ASCEND                      ; [frame C released] (balance for cleanliness)
    mov     sp, bp
    pop     bp
    clc
    ret
.reject:
    mov     sp, bp
    pop     bp
    stc
    ret

; ---- .read_sigalg / .read_time: der_read the next TLV then run the matching check, folding the
; twice-each `call der_read / jc fail / call .check_X / jc fail` idiom into one call. CF propagates.
.read_sigalg:
    call    der_read
    jc      .alg_bad
    jmp     .check_sigalg
.read_time:
    call    der_read
    jc      .alg_bad
    jmp     .check_time

; ---- .check_sigalg: exact { ecdsa-with-SHA256 }, parameters absent.
.check_sigalg:
    cmp     al, 0x30
    jne     .alg_bad
    cmp     cx, 10
    jne     .alg_bad
%ifdef X509_ISSUER_DUAL
    dec     cx                      ; exact common OID prefix, absent parameters
    mov     bx, x509_sigalg_content
    call    der_memeq
    jne     .alg_bad
    mov     al, [si - 1]             ; der_read left SI at content end
    cmp     al, 2                   ; ecdsa-with-SHA256 (WE1)
    je      .known_issuer
    cmp     al, 3                   ; ecdsa-with-SHA384 (YE2)
    jne     .alg_bad
.known_issuer:
    cmp     byte [x509_issuer_algorithm], 0
    je      .first_issuer
    cmp     al, [x509_issuer_algorithm]
    jne     .alg_bad                ; inner and outer must agree
.first_issuer:
    mov     [x509_issuer_algorithm], al
%else
    mov     bx, x509_sigalg_content
    call    der_memeq
    jne     .alg_bad
%endif
    clc
    ret
.alg_bad:
    stc
    ret

; ---- .check_time: AL=tag,DI=content,CX=len of a Time. Accept UTCTime(0x17,13) "YYMMDDHHMMSSZ" or
; GeneralizedTime(0x18,15) "YYYYMMDDHHMMSSZ"; require the trailing 'Z'. (Clock compare is the
; caller's job.) CF=1 if malformed. Preserves DI (the caller stores it).
.check_time:
    mov     [x509_time_tag_tmp], al
    cmp     al, 0x17
    jne     .t_gen
    cmp     cx, 13
    jne     .alg_bad
    jmp     .t_z
.t_gen:
    cmp     al, 0x18
    jne     .alg_bad
    cmp     cx, 15
    jne     .alg_bad
.t_z:
    mov     bx, di
    add     bx, cx
    dec     bx
    cmp     byte [bx], 'Z'
    jne     .alg_bad
    push    cx
    push    di
    dec     cx
.t_digit:
    mov     al, [di]
    cmp     al, '0'
    jb      .t_bad
    cmp     al, '9'
    ja      .t_bad
    inc     di
    loop    .t_digit
    pop     di
    pop     cx

    ; Enforce coarse calendar/time ranges without claiming trusted time.
    mov     bx, di
    cmp     byte [x509_time_tag_tmp], 0x17
    je      .t_have_month
    add     bx, 2                   ; generalized year has two extra digits
.t_have_month:
    add     bx, 2                   ; month
    call    x509_decimal_pair
    cmp     al, 1
    jb      .alg_bad
    cmp     al, 12
    ja      .alg_bad
    add     bx, 2                   ; day
    call    x509_decimal_pair
    cmp     al, 1
    jb      .alg_bad
    cmp     al, 31
    ja      .alg_bad
    add     bx, 2                   ; hour
    call    x509_decimal_pair
    cmp     al, 23
    ja      .alg_bad
    add     bx, 2                   ; minute
    call    x509_decimal_pair
    cmp     al, 59
    ja      .alg_bad
    add     bx, 2                   ; second
    call    x509_decimal_pair
    cmp     al, 59
    ja      .alg_bad
    mov     al, [x509_time_tag_tmp]
    clc
    ret
.t_bad:
    pop     di
    pop     cx
    jmp     .alg_bad

; ---- .parse_spki: exact id-ecPublicKey + prime256v1, then
; BIT STRING(00 || 04 || X32 || Y32).
.parse_spki:
    call    der_read                ; AlgorithmIdentifier
    jc      .spki_bad
    cmp     al, 0x30
    jne     .spki_bad
    cmp     cx, 19
    jne     .spki_bad
    mov     bx, x509_spki_alg_content
    call    der_memeq
    jne     .spki_bad
    call    der_read                ; subjectPublicKey BIT STRING
    jc      .spki_bad
    cmp     al, 0x03
    jne     .spki_bad
    cmp     cx, 66
    jne     .spki_bad
    cmp     byte [di], 0x00         ; zero unused bits
    jne     .spki_bad
    cmp     byte [di + 1], 0x04     ; uncompressed SEC1 point
    jne     .spki_bad
    cmp     si, [der_end]           ; SPKI = exactly { alg, key }
    jne     .spki_bad
    mov     ax, di
    add     ax, 2
    mov     [x509_point_x_ptr], ax
    add     ax, 32
    mov     [x509_point_y_ptr], ax
    clc
    ret
.spki_bad:
    stc
    ret

; ---- .parse_ext: cursor=SI over one Extension's content, der_end set. Read extnID; if it is the
; required BC/KU/EKU/SAN OIDs, enforce the exact leaf value. Unknown
; noncritical extensions are consumed; unknown critical extensions reject.
.parse_ext:
    call    der_read                ; extnID OID
    jc      .ext_bad
    cmp     al, 0x06
    jne     .ext_bad
    mov     byte [x509_ext_kind], 0
    cmp     cx, 3
    jne     .have_kind
    cmp     word [di], 0x1d55       ; all required OIDs begin 55 1D
    jne     .have_kind
    mov     al, [di + 2]
    cmp     al, 0x13
    jne     .kind_ku
    mov     byte [x509_ext_kind], 1 ; basicConstraints
    jmp     .have_kind
.kind_ku:
    cmp     al, 0x0f
    jne     .kind_eku
    mov     byte [x509_ext_kind], 2 ; keyUsage
    jmp     .have_kind
.kind_eku:
    cmp     al, 0x25
    jne     .kind_san
    mov     byte [x509_ext_kind], 3 ; extendedKeyUsage
    jmp     .have_kind
.kind_san:
    cmp     al, 0x11
    jne     .have_kind
    mov     byte [x509_ext_kind], 4 ; subjectAltName
.have_kind:
    call    .read_extnvalue
    jc      .ext_bad
    mov     al, [x509_ext_kind]
    or      al, al
    jnz     .known
    cmp     byte [x509_ext_critical], 0
    jne     .ext_bad                ; unknown critical extension
    clc
    ret
.known:
    cmp     al, 1
    jne     .known_ku
    cmp     byte [x509_bc_count], 0
    jne     .ext_bad
    inc     byte [x509_bc_count]
    cmp     byte [x509_ext_critical], 1
    jne     .ext_bad
    cmp     cx, 2
    jne     .ext_bad
    cmp     word [di], 0x0030       ; SEQUENCE {} -> CA=false default
    jne     .ext_bad
    clc
    ret
.known_ku:
    cmp     al, 2
    jne     .known_eku
    cmp     byte [x509_ku_count], 0
    jne     .ext_bad
    inc     byte [x509_ku_count]
    cmp     byte [x509_ext_critical], 1
    jne     .ext_bad
    cmp     cx, 4
    jne     .ext_bad
    cmp     word [di], 0x0203       ; BIT STRING, two content bytes
    jne     .ext_bad
    cmp     word [di + 2], 0x8007   ; 7 unused bits, digitalSignature only
    jne     .ext_bad
    clc
    ret
.known_eku:
    cmp     al, 3
    jne     .known_san
    cmp     byte [x509_eku_count], 0
    jne     .ext_bad
    inc     byte [x509_eku_count]
    cmp     byte [x509_ext_critical], 0
    jne     .ext_bad
    cmp     cx, 12
    jne     .ext_bad
    mov     bx, x509_eku_serverauth
    call    der_memeq
    jne     .ext_bad
    clc
    ret
.known_san:
    cmp     byte [x509_san_count], 0
    jne     .ext_bad
    inc     byte [x509_san_count]
    cmp     byte [x509_ext_critical], 0
    jne     .ext_bad
    call    .scan_san
    jc      .ext_bad
    clc
    ret
.ext_bad:
    stc
    ret

; ---- .read_extnvalue: after extnID, read the optional critical BOOLEAN then the extnValue OCTET
; STRING; require the Extension is exactly consumed. out: DI=value ptr, CX=value len, CF=err.
.read_extnvalue:
    mov     byte [x509_ext_critical], 0
    call    der_read
    jc      .ext_bad
    cmp     al, 0x01                ; critical BOOLEAN present?
    jne     .rev_have
    cmp     cx, 1
    jne     .ext_bad
    cmp     byte [di], 0xff         ; canonical TRUE; DEFAULT FALSE is omitted
    jne     .ext_bad
    mov     byte [x509_ext_critical], 1
    call    der_read
    jc      .ext_bad
.rev_have:
    cmp     al, 0x04
    jne     .ext_bad
    cmp     si, [der_end]           ; nothing may follow extnValue inside the Extension
    jne     .ext_bad
    clc
    ret

; ---- .scan_san: DI=extnValue content, CX=len. extnValue wraps GeneralNames ::= SEQUENCE OF
; GeneralName; for each dNSName (tag 0x82) compare to the exact host, set x509_host_found on a
; match. CF=1 only on malformed structure (a non-matching name is not an error).
.scan_san:
    call    der_descend             ; save parent (si, der_end); narrow to the extnValue content
    call    der_read                ; GeneralNames SEQUENCE
    jc      .san_bad
    cmp     al, 0x30
    jne     .san_bad
    cmp     si, [der_end]
    jne     .san_bad
    call    der_narrow              ; narrow to the GeneralNames content
.san_loop:
    cmp     si, [der_end]
    jae     .san_ok
    call    der_read                ; GeneralName
    jc      .san_bad
    cmp     al, 0x82                ; dNSName?
    jne     .san_loop
    cmp     cx, X509_HOST_LEN
    jne     .san_loop
    mov     bx, x509_host           ; CX==X509_HOST_LEN here
    call    der_memeq
    jne     .san_loop
    mov     byte [x509_host_found], 1
    jmp     .san_loop
.san_ok:
    pop     word [der_end]
    pop     si
    clc
    ret
.san_bad:
    pop     word [der_end]
    pop     si
    stc
    ret

x509_decimal_pair:
    push    dx
    mov     al, [bx]
    sub     al, '0'
    xor     ah, ah
    mov     dl, 10
    mul     dl
    add     al, [bx + 1]
    sub     al, '0'
    pop     dx
    ret

; Canonical positive nonzero INTEGER content at DI/CX.
x509_check_positive_integer:
    push    ax
    push    bx
    push    cx
    push    di
    or      cx, cx
    jz      .bad
    mov     al, [di]
    test    al, 0x80
    jnz     .bad
    or      al, al
    jnz     .scan_nonzero
    cmp     cx, 1
    jbe     .bad
    test    byte [di + 1], 0x80
    jz      .bad                    ; redundant sign padding
.scan_nonzero:
    xor     bl, bl
.scan:
    mov     al, [di]
    or      bl, al
    inc     di
    loop    .scan
    or      bl, bl
    jz      .bad
    clc
    jmp     .done
.bad:
    stc
.done:
    pop     di
    pop     cx
    pop     bx
    pop     ax
    ret

; Strict short-form-or-minimal-long-form DER ECDSA signature framing.
; Scalar order/range is rechecked by issuer_auth; this gate enforces canonical
; positive, nonzero, at-most-256-bit r/s.
; The P-384 product profile supplies this entry using its strict verifier's
; DER parser (including scalar-order checks), avoiding duplicate framing code.
%ifndef X509_ISSUER_P384
x509_check_ecdsa_signature:
    push    ax
    push    bx
    push    cx
    push    dx
    push    si
    push    di
    mov     ax, si
    add     ax, cx
    jc      .bad
    mov     [x509_sig_der_end], ax
    mov     [der_end], ax
    call    der_read_seq
    jc      .bad
    cmp     si, [x509_sig_der_end]
    jne     .bad
    mov     ax, di
    add     ax, cx
    mov     [der_end], ax
    mov     si, di
    call    der_read_int
    jc      .bad
    cmp     cx, 33
    ja      .bad
    cmp     cx, 33
    jne     .r_width_ok
    cmp     byte [di], 0
    jne     .bad                    ; 33 bytes is allowed only as sign padding
.r_width_ok:
    call    x509_check_positive_integer
    jc      .bad
    call    der_read_int
    jc      .bad
    cmp     cx, 33
    ja      .bad
    cmp     cx, 33
    jne     .s_width_ok
    cmp     byte [di], 0
    jne     .bad                    ; reject positive values wider than 256 bits
.s_width_ok:
    call    x509_check_positive_integer
    jc      .bad
    cmp     si, [der_end]
    jne     .bad
    clc
    jmp     .done
.bad:
    stc
.done:
    pop     di
    pop     si
    pop     dx
    pop     cx
    pop     bx
    pop     ax
    ret

%endif

; der_descend -- the called body of DER_DESCEND. Given der_read's outputs (DI=content, CX=len),
; saves the parent (cursor SI, bound [der_end]) and narrows the strict-DER window to [DI, DI+CX).
; The two parent words are left on the stack BELOW the return address (popped, then re-pushed), so
; the matching DER_ASCEND (pop der_end; pop si) still balances exactly. Clobbers AX + DX (DX is the
; return-address shuttle; both registers are der_read-volatile and unused at every descend site).
der_descend:
    pop     dx                      ; stash the return address (DX is dead scratch here)
    push    si                      ; parent: the next-sibling cursor
    push    word [der_end]          ; parent: the bound
    mov     ax, di
    add     ax, cx
    mov     [der_end], ax           ; new bound = content end
    mov     si, di                  ; new cursor = content start
    push    dx                      ; restore the return address atop the saved parent
    ret

; der_narrow -- narrow the strict-DER window to the just-read TLV's content [DI, DI+CX) WITHOUT
; saving a parent frame (used where the caller already owns the surrounding frame, e.g. inside the
; SPKI walk and .scan_san). Sets SI=DI (cursor at content start), [der_end]=DI+CX. Clobbers AX only.
der_narrow:
    mov     ax, di
    add     ax, cx
    mov     [der_end], ax
    mov     si, di
    ret

; der_memeq -- compare CX bytes at the just-read content DI against the constant at BX. out: ZF=1 on
; equal (caller branches je/jne). Preserves SI (the cursor); clobbers DI/CX/AX. Folds the three
; `push si / mov si,di / mov di,const / repe cmpsb / pop si` constant-compare idioms in the parser.
der_memeq:
    push    si
    mov     si, di
    mov     di, bx
    repe    cmpsb
    pop     si
    ret

; ============================================================================================
; der_read -- the strict DER TLV reader.
; in:  SI = cursor (at a tag), [der_end] = exclusive bound.
; out: CF=1 on any strict-DER violation; else CF=0, AL=tag, CX=content length, DI=content ptr,
;      SI advanced to the next sibling (content end). clobbers AX BX CX DX DI. preserves BP.
der_read:
    mov     bx, [der_end]
    cmp     si, bx
    jae     .err                    ; need a tag byte
    mov     al, [si]                ; tag
    mov     ah, al
    and     ah, 0x1F
    cmp     ah, 0x1F
    je      .err                    ; high-tag-number form not allowed
    inc     si
    cmp     si, bx
    jae     .err                    ; need a length byte
    mov     ah, [si]
    inc     si
    test    ah, 0x80
    jz      .short                  ; ah < 0x80: short form
    cmp     ah, 0x81
    jb      .err                    ; ah == 0x80: indefinite length
    cmp     ah, 0x82
    ja      .err                    ; > 2 length octets (incl 0xFF): too large for the device
    je      .len2
.len1:
    cmp     si, bx
    jae     .err
    mov     cl, [si]
    inc     si
    cmp     cl, 0x80
    jb      .err                    ; non-minimal (short form should have been used)
    xor     ch, ch
    jmp     .have
.len2:
    mov     dx, si
    add     dx, 2
    cmp     dx, bx
    ja      .err                    ; need 2 length bytes within bound
    mov     ch, [si]                ; high byte (big-endian)
    mov     cl, [si+1]              ; low byte
    add     si, 2
    cmp     ch, 0
    je      .err                    ; non-minimal (leading zero length octet)
.have:
    mov     di, si                  ; content pointer
    mov     dx, si
    add     dx, cx                  ; content end
    jc      .err                    ; 16-bit address overflow
    cmp     dx, bx
    ja      .err                    ; content exceeds the bound
    mov     si, dx                  ; advance cursor to the next sibling
    clc
    ret
.short:
    mov     cl, ah
    xor     ch, ch
    jmp     .have
.err:
    stc
    ret

; der_read_seq -- der_read a MANDATORY SEQUENCE (the most common positional step). Returns der_read's
; outputs (AL/CX/DI/SI); CF=1 if the read failed OR the tag != 0x30. Folds the repeated
; `call der_read / jc fail / cmp al,0x30 / jne fail` idiom; callers just do `call der_read_seq / jc <fail>`.
der_read_seq:
    call    der_read
    jc      .ds_fail
    cmp     al, 0x30
    jne     .ds_fail
    ret                             ; CF=0 (equal cmp), der_read's AL/CX/DI/SI preserved
.ds_fail:
    stc
    ret

; der_read_int -- der_read a mandatory INTEGER (tag 0x02). Same contract/idiom-fold as der_read_seq
; (shares der_read_seq's stc/ret fail tail).
der_read_int:
    call    der_read
    jc      der_read_seq.ds_fail
    cmp     al, 0x02
    jne     der_read_seq.ds_fail
    ret

; ---- constants ----
x509_sigalg_content:                ; OID ecdsa-with-SHA256, absent parameters
%ifdef X509_ISSUER_P384
    db 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03
%else
    db 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02
%endif
x509_spki_alg_content:              ; id-ecPublicKey + prime256v1
    db 0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01
    db 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07
x509_eku_serverauth:
    db 0x30,0x0a,0x06,0x08,0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x01
x509_host:
    db "api.openai.com"

; ---- externally placed parser state/results ----
der_end             equ parser_x509_state_start
x509_buf_end        equ der_end + 2
x509_tbs_ptr        equ x509_buf_end + 2
x509_tbs_len        equ x509_tbs_ptr + 2
x509_sig_ptr        equ x509_tbs_len + 2
x509_sig_len        equ x509_sig_ptr + 2
x509_point_x_ptr    equ x509_sig_len + 2
x509_point_y_ptr    equ x509_point_x_ptr + 2
x509_nb_ptr         equ x509_point_y_ptr + 2
x509_na_ptr         equ x509_nb_ptr + 2
x509_sig_der_end    equ x509_na_ptr + 2
x509_nb_len         equ x509_sig_der_end + 2
x509_na_len         equ x509_nb_len + 1
x509_nb_tag         equ x509_na_len + 1
x509_na_tag         equ x509_nb_tag + 1
x509_san_count      equ x509_na_tag + 1
x509_host_found     equ x509_san_count + 1
x509_bc_count       equ x509_host_found + 1
x509_ku_count       equ x509_bc_count + 1
x509_eku_count      equ x509_ku_count + 1
x509_ext_kind       equ x509_eku_count + 1
x509_ext_critical   equ x509_ext_kind + 1
x509_time_tag_tmp   equ x509_ext_critical + 1
%ifdef X509_ISSUER_DUAL
x509_issuer_algorithm equ x509_time_tag_tmp + 1
parser_x509_state_end equ x509_issuer_algorithm + 1
%else
parser_x509_state_end equ x509_time_tag_tmp + 1
%endif
