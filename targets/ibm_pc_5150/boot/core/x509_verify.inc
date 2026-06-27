; Build 12 auto-recertify: strict-DER X.509 leaf parser for the 286 secure tier.
;
; The false-security crux, ported from the offline oracle (tools/x509/x509_verify.py); the tamper
; matrix (tools/x509/tamper_matrix.py) is the reference and tools/crypto-bench/x509_eval.py runs
; THIS code under unicorn against the same vectors. RULE: strict DER, positional walk, fail closed.
; A wrong length/tag accepts a forged cert.
;
; x509_parse_leaf does the STRUCTURAL + POLICY gates (everything that is a parse decision): strict
; TLV (minimal lengths, in-bounds, no trailing) * positional Certificate/TBS walk * inner==outer
; signatureAlgorithm == sha256WithRSAEncryption * exactly-one-SAN carrying the exact host * leaf key
; RSA-2048 with e=65537. It EXTRACTS the fields the orchestrator needs: the tbs span (to SHA), the
; 256-byte signature, the leaf modulus (to adopt), notBefore/notAfter. The signature verify (vs the
; pinned WR1 key) and the validity-vs-RTC-clock compare are the caller's job, NOT done here.
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
    mov     byte [x509_san_count], 0
    mov     byte [x509_host_found], 0
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

    ; serialNumber INTEGER  (skip, but require the tag)
    call    der_read_int
    jc      .reject

    ; signature AlgorithmIdentifier (inner) == sha256WithRSAEncryption
    call    .read_sigalg
    jc      .reject

    ; issuer Name  (skip)
    call    der_read_seq
    jc      .reject

    ; validity SEQUENCE { notBefore, notAfter }
    call    der_read_seq
    jc      .reject
    DER_DESCEND                     ; [frame Va]
    call    .read_time
    jc      .reject
    mov     [x509_nb_ptr], di
    call    .read_time
    jc      .reject
    mov     [x509_na_ptr], di
    cmp     si, [der_end]           ; exactly two times
    jne     .reject
    DER_ASCEND                      ; [frame Va released]

    ; subject Name  (skip)
    call    der_read_seq
    jc      .reject

    ; subjectPublicKeyInfo  -> the leaf RSA key to adopt
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

    ; ---- outer signatureAlgorithm == inner (== sha256WithRSAEncryption) ----
    call    .read_sigalg
    jc      .reject

    ; ---- signatureValue BIT STRING (00 unused bits || 256-byte signature) ----
    call    der_read
    jc      .reject
    cmp     al, 0x03
    jne     .reject
    cmp     cx, 257                 ; 1 unused-bits byte + 256 signature bytes
    jne     .reject
    cmp     byte [di], 0x00
    jne     .reject
    cmp     si, [x509_buf_end]      ; Certificate body fully consumed
    jne     .reject
    mov     ax, di
    inc     ax
    mov     [x509_sig_ptr], ax

    ; ---- policy: exactly one SAN carrying the exact host ----
    cmp     byte [x509_san_count], 1
    jne     .reject
    cmp     byte [x509_host_found], 1
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

; ---- .check_sigalg: AL=tag,DI=content,CX=len of an AlgorithmIdentifier. Require the EXACT
; { sha256WithRSAEncryption, NULL } encoding (so inner==outer is automatic). CF=1 if not.
.check_sigalg:
    mov     bx, x509_sigalg_content
    ; fall through to .match_alg13

; ---- .match_alg13: shared SEQUENCE(13)==expected check, used by .check_sigalg AND .parse_spki's
; AlgorithmIdentifier (both compare a fixed 13-byte { OID, NULL } encoding). in: AL=tag, DI=content,
; CX=len, BX=ptr to the 13-byte expected encoding. out: CF=0 match, CF=1 mismatch. Preserves SI.
.match_alg13:
    cmp     al, 0x30
    jne     .alg_bad
    cmp     cx, 13
    jne     .alg_bad
    call    der_memeq               ; CX==13 here; [di..]==[bx..] over 13 bytes?
    jne     .alg_bad
    clc
    ret
.alg_bad:
    stc
    ret

; ---- .check_time: AL=tag,DI=content,CX=len of a Time. Accept UTCTime(0x17,13) "YYMMDDHHMMSSZ" or
; GeneralizedTime(0x18,15) "YYYYMMDDHHMMSSZ"; require the trailing 'Z'. (Clock compare is the
; caller's job.) CF=1 if malformed. Preserves DI (the caller stores it).
.check_time:
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
    clc
    ret

; ---- .parse_spki: cursor=SI over the SPKI content, der_end set. Require AlgorithmIdentifier ==
; { rsaEncryption, NULL }, then BIT STRING(00 || RSAPublicKey{ INTEGER n(2048-bit), INTEGER 65537 }).
; Sets x509_mod_ptr to the 256-byte modulus. CF=1 on any deviation.
.parse_spki:
    call    der_read                ; AlgorithmIdentifier
    jc      .spki_bad
    mov     bx, x509_oid_rsaenc_seq
    call    .match_alg13            ; require { rsaEncryption, NULL } (shared 13-byte check)
    jc      .spki_bad
    call    der_read                ; subjectPublicKey BIT STRING
    jc      .spki_bad
    cmp     al, 0x03
    jne     .spki_bad
    cmp     byte [di], 0x00         ; zero unused bits
    jne     .spki_bad
    cmp     si, [der_end]           ; SPKI = exactly { alg, key }
    jne     .spki_bad
    call    der_narrow              ; narrow to the BIT STRING content
    inc     si                      ; skip the 00 unused-bits byte
    call    der_read_seq            ; RSAPublicKey SEQUENCE
    jc      .spki_bad
    cmp     si, [der_end]
    jne     .spki_bad
    call    der_narrow              ; narrow to the RSAPublicKey content
    call    der_read_int            ; modulus INTEGER
    jc      .spki_bad
    cmp     cx, 257                 ; 0x00 || 256-byte modulus (exactly 2048 bits)
    jne     .spki_bad
    cmp     byte [di], 0x00
    jne     .spki_bad
    test    byte [di+1], 0x80       ; top bit set -> genuinely 2048-bit (the leading 0x00 is required)
    jz      .spki_bad
    mov     ax, di
    inc     ax
    mov     [x509_mod_ptr], ax      ; -> the 256-byte big-endian modulus
    call    der_read_int            ; exponent INTEGER
    jc      .spki_bad
    cmp     cx, 3                   ; 65537 == 01 00 01 (the only minimal encoding)
    jne     .spki_bad
    cmp     byte [di], 0x01
    jne     .spki_bad
    cmp     byte [di+1], 0x00
    jne     .spki_bad
    cmp     byte [di+2], 0x01
    jne     .spki_bad
    cmp     si, [der_end]           ; RSAPublicKey fully consumed
    jne     .spki_bad
    clc
    ret
.spki_bad:
    stc
    ret

; ---- .parse_ext: cursor=SI over one Extension's content, der_end set. Read extnID; if it is the
; SAN OID bump x509_san_count + scan dNSNames for the exact host; consume the (optional critical +)
; extnValue strictly either way. CF=1 on malformed structure.
.parse_ext:
    call    der_read                ; extnID OID
    jc      .ext_bad
    cmp     al, 0x06
    jne     .ext_bad
    cmp     cx, 3                   ; SAN OID body is 3 bytes (55 1D 11)
    jne     .not_san
    mov     bx, x509_oid_san_body   ; CX==3 here
    call    der_memeq
    jne     .not_san
    inc     byte [x509_san_count]
    call    .read_extnvalue
    jc      .ext_bad
    call    .scan_san
    jc      .ext_bad
    clc
    ret
.not_san:
    jmp     .read_extnvalue         ; consume the rest for strictness (tail-call; its CF/ret is ours)
.ext_bad:
    stc
    ret

; ---- .read_extnvalue: after extnID, read the optional critical BOOLEAN then the extnValue OCTET
; STRING; require the Extension is exactly consumed. out: DI=value ptr, CX=value len, CF=err.
.read_extnvalue:
    call    der_read
    jc      .ext_bad
    cmp     al, 0x01                ; critical BOOLEAN present?
    jne     .rev_have
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
x509_sigalg_content:                ; { OID sha256WithRSAEncryption, NULL } (13 content bytes)
    db 0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B,0x05,0x00
x509_oid_rsaenc_seq:                ; { OID rsaEncryption, NULL } (13 bytes)
    db 0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00
x509_oid_san_body:                  ; subjectAltName OID body (after the 06 03)
    db 0x55,0x1D,0x11
x509_host:
    db "api.openai.com"

; ---- parser state + results (handshake-only lifetime) ----
align 2
der_end:          dw 0              ; current strict-DER bound (exclusive)
x509_buf_end:     dw 0              ; absolute end of the cert buffer
x509_tbs_ptr:     dw 0              ; -> tbsCertificate (the signed span start)
x509_tbs_len:     dw 0              ; length of the signed span
x509_sig_ptr:     dw 0              ; -> 256-byte signatureValue
x509_mod_ptr:     dw 0              ; -> 256-byte leaf modulus (big-endian, to adopt)
x509_nb_ptr:      dw 0              ; -> notBefore time string
x509_na_ptr:      dw 0              ; -> notAfter time string
x509_san_count:   db 0
x509_host_found:  db 0
