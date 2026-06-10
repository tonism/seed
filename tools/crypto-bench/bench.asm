; Standalone crypto micro-benchmark for the IBM PC 5150 (4.77 MHz 8088).
;
; Boots as a CORE.SYS via the real boot.bin/loader.bin/FAT12 chain (loaded to
; 0x0000:0x1000, the loader honors the SEEDCORE resident-sector count below).
; Deploys the SHA/TLS constants exactly like phases/tls_client_hello.inc, then
; times each crypto op with the BIOS tick counter (0040:006c, ~18.2065 Hz),
; emitting one machine-parseable line per op to the CGA screen AND COM1 serial:
;
;     <tag> N=<dec> dt=<dec> ck=<hex4>
;
; dt = elapsed BIOS ticks for N iterations; the host turns that into ms at the
; true 4.77 MHz rate (1 tick = 54.9254 ms) and ms/iter = dt*54.9254/N. ck is a
; 16-bit word-sum of the op's output region (a cheap "did it actually run + same
; result" tag; correctness proper is gated host-side in unicorn vs OpenSSL).
;
; 8086 instructions only. Reuses core/sha256.inc + prf_driver.inc verbatim.

bits 16
cpu 8086
org 0x1000

%include "core/layout.inc"

core_header:
    jmp short start
    nop
    db 'SEEDCORE'
    db 1
    db 0
    dw core_header_end - core_header
    dw (image_end - core_header + 511) / 512      ; resident sectors = whole image
    dw (image_end - core_header + 511) / 512
    dw 0
    dw 0
core_header_end:

; The data address map (sha256_k, low_static_constants_*, tls_*, etc.). It emits
; a few bytes (tls_app_data_ptr/tls_app_plain_ptr) which the header's short jump
; skips; everything else is EQUs into low/high RAM scratch.
%include "core/data.inc"

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7000          ; clear of code (0x1000+) and crypto data (<0x4000); fits >=32 KB RAM
    sti
    cld

    mov ax, 0x0003          ; 80x25 text, clears screen
    int 0x10
    call serial_init
    call deploy_constants

    ; ---- op: SHA-256 process_block ----
    call setup_sha_block
    mov si, tag_shablk
    mov cx, 96              ; iterations
    mov bp, sha256_process_block
    call run_op
    mov si, sha256_state    ; checksum region
    mov cx, 8
    call emit_tail

    ; ---- op: TLS-PRF master secret only ----
    mov si, tag_master
    mov cx, 6
    mov bp, op_prf_master
    call run_op
    mov si, tls_master_secret
    mov cx, tls_master_secret_len / 2
    call emit_tail

    ; ---- op: TLS-PRF master secret + key block (the ~7.5 s CKE->Finished cost) ----
    mov si, tag_full
    mov cx, 3
    mov bp, op_prf_full
    call run_op
    mov si, tls_key_block
    mov cx, tls_key_block_len / 2
    call emit_tail

    mov si, tag_done
    call emit_str
    call emit_crlf

.hang:
    hlt
    jmp .hang

; ---------------------------------------------------------------------------
; op wrappers (set up inputs fresh, then the timed routine is called via BP)
; ---------------------------------------------------------------------------
op_prf_master:
    call setup_prf_inputs
    jmp tls_prepare_master_secret

op_prf_full:
    call setup_prf_inputs
    call tls_prepare_master_secret
    jmp tls_prepare_key_block

setup_prf_inputs:
    ; premaster = 00..1f, client random = 20..3f, server random = 40..5f
    mov di, tls_premaster_secret
    xor al, al
    mov cx, 0x20
.p:
    mov [di], al
    inc di
    inc al
    loop .p
    mov di, tls_random
    mov al, 0x20
    mov cx, 0x20
.c:
    mov [di], al
    inc di
    inc al
    loop .c
    mov di, tls_server_random
    mov al, 0x40
    mov cx, 0x20
.s:
    mov [di], al
    inc di
    inc al
    loop .s
    ret

setup_sha_block:
    call sha256_init
    mov di, sha256_block        ; fill the 64-byte block with 00..3f
    xor al, al
    mov cx, sha256_block_size
.f:
    mov [di], al
    inc di
    inc al
    loop .f
    ret

; ---------------------------------------------------------------------------
; run_op: time CX iterations of [BP], leaving dt in dx:ax-ish via globals.
; in: SI=tag string, CX=iterations, BP=routine. prints "<tag> N=<n> dt=<d> "
; ---------------------------------------------------------------------------
run_op:
    mov [op_ptr], bp            ; save routine ptr to MEMORY: the op may clobber bp
    mov [bench_iters], cx       ; (evolved SHA variants use bp as a scratch/state register)
    call emit_str               ; tag
    mov al, ' '
    call emit_char
    ; wait for a fresh tick edge to cut quantization
    call read_tick_low
    mov bx, ax
.edge:
    call read_tick_low
    cmp ax, bx
    je .edge
    call read_tick
    mov [t0_lo], ax
    mov [t0_hi], dx
    mov cx, [bench_iters]
.loop:
    push cx
    call [op_ptr]               ; memory-indirect: survives the op clobbering bp
    pop cx
    loop .loop
    call read_tick
    sub ax, [t0_lo]
    sbb dx, [t0_hi]
    mov [dt_lo], ax             ; dt assumed < 65536 ticks
    ; print N=<iters>
    mov si, str_N
    call emit_str
    mov ax, [bench_iters]
    call emit_dec16
    ; print dt=<dt_lo>
    mov si, str_dt
    call emit_str
    mov ax, [dt_lo]
    call emit_dec16
    ret

; emit_tail: checksum CX words at SI, print " ck=<hex4>" + CRLF
emit_tail:
    xor ax, ax
    mov di, cx                  ; use DI as the word counter (loop-instr-free)
.sum:
    or di, di
    jz .sum_done
    add ax, [si]
    inc si
    inc si
    dec di
    jmp .sum
.sum_done:
    push ax
    mov si, str_ck
    call emit_str
    pop ax
    call emit_hex16
    call emit_crlf
    ret

; ---------------------------------------------------------------------------
; BIOS tick helpers (0040:006c, ds=0)
; ---------------------------------------------------------------------------
read_tick:                      ; -> dx:ax = 32-bit tick
    mov ax, [0x046c]
    mov dx, [0x046e]
    ret
read_tick_low:                  ; -> ax = low word
    mov ax, [0x046c]
    ret

; ---------------------------------------------------------------------------
; constant deployment (mirrors phases/tls_client_hello.inc:16-23)
; ---------------------------------------------------------------------------
deploy_constants:
    mov si, sha256_k_constant
    mov di, sha256_k
    mov cx, sha256_k_len
    rep movsb
    mov si, tls_low_constants_constant
    mov di, low_static_constants_start
    mov cx, low_static_constants_len
    rep movsb
    ret

; ---------------------------------------------------------------------------
; output: COM1 serial (LSR-polled TX) + CGA teletype
; ---------------------------------------------------------------------------
serial_init:
    mov dx, 0x3fb               ; LCR
    mov al, 0x80                ; DLAB
    out dx, al
    mov dx, 0x3f8               ; divisor low (0x000c = 9600)
    mov al, 0x0c
    out dx, al
    mov dx, 0x3f9
    xor al, al
    out dx, al
    mov dx, 0x3fb
    mov al, 0x03                ; 8N1, DLAB off
    out dx, al
    ret

emit_char:                      ; al = char -> screen + serial (preserves all regs)
    push ax
    push bx
    push cx                      ; 86Box INT 10h teletype clobbers CX
    push dx
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10                     ; al still = char on return
    mov ah, al
    mov dx, 0x3fd               ; LSR -- clobbers dx, so restore it LAST (below)
.wait:
    in al, dx
    test al, 0x20               ; THR empty
    jz .wait
    mov dx, 0x3f8
    mov al, ah
    out dx, al
    pop dx                       ; restore caller regs after the serial port I/O
    pop cx
    pop bx
    pop ax
    ret

emit_hexbuf:                    ; si = addr, cx = byte count -> "HX <hex...>" + CRLF
    push ax
    push bx
    push cx
    push si
    push di
    mov di, cx                  ; di = remaining bytes (emit_char preserves di)
    mov al, 'H'
    call emit_char
    mov al, 'X'
    call emit_char
    mov al, ' '
    call emit_char
.byte:
    or di, di
    jz .end
    mov bl, [si]
    mov al, bl
    mov cl, 4
    shr al, cl
    and al, 0x0f
    call .nyb
    mov al, bl
    and al, 0x0f
    call .nyb
    inc si
    dec di
    jmp .byte
.end:
    call emit_crlf
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret
.nyb:
    add al, '0'
    cmp al, '9'
    jbe .e
    add al, 7
.e:
    jmp emit_char               ; tail-call: emit_char's ret returns past `call .nyb`

emit_str:                       ; si = NUL-terminated
    push ax
    push si
.next:
    lodsb
    or al, al
    jz .done
    call emit_char
    jmp .next
.done:
    pop si
    pop ax
    ret

emit_crlf:
    push ax
    mov al, 13
    call emit_char
    mov al, 10
    call emit_char
    pop ax
    ret

emit_hex16:                     ; ax -> 4 hex digits
    push ax
    push cx
    push dx
    mov dx, ax
    mov cx, 4
.dig:
    rol dx, 1
    rol dx, 1
    rol dx, 1
    rol dx, 1
    mov al, dl
    and al, 0x0f
    add al, '0'
    cmp al, '9'
    jbe .ok
    add al, 7
.ok:
    call emit_char
    loop .dig
    pop dx
    pop cx
    pop ax
    ret

emit_dec16:                     ; ax -> decimal (no leading zeros, min 1 digit)
    push ax
    push bx
    push cx
    push dx
    mov bx, 10
    xor cx, cx                  ; digit count
.div:
    xor dx, dx
    div bx                      ; ax/10 -> ax rem dx
    push dx
    inc cx
    or ax, ax
    jnz .div
.pop:
    pop ax
    add al, '0'
    call emit_char
    loop .pop
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; ---------------------------------------------------------------------------
; strings + constant tables
; ---------------------------------------------------------------------------
tag_shablk db 'SHABLK', 0
tag_master db 'PRFMAS', 0
tag_full   db 'PRFALL', 0
tag_done   db 'DONE', 0
str_N      db 'N=', 0
str_dt     db ' dt=', 0
str_ck     db ' ck=', 0
str_ck2    db ' raw=', 0

bench_iters dw 0
op_ptr dw 0
ck_val dw 0
t0_lo dw 0
t0_hi dw 0
dt_lo dw 0

; ---- crypto under test (override with -DSHA256_SRC='"variants/foo.inc"') ----
%ifndef SHA256_SRC
%define SHA256_SRC "core/sha256.inc"
%endif
%include SHA256_SRC
%include "prf_driver.inc"

; ---- compiled-in constant tables (from phases/tls_client_hello.inc) ----
tls_low_constants_constant:
tls_label_master_secret_constant db 'master secret'
tls_label_client_finished_constant db 'client finished'
tls_label_server_finished_constant db 'server finished'
tls_label_key_expansion_constant db 'key expansion'
chacha_constants_constant dw 0x7865, 0x6170, 0x646e, 0x3320
                           dw 0x2d32, 0x7962, 0x6574, 0x6b20
poly1305_prime_constant db 0xfb
                           times 15 db 0xff
                           db 0x03
sha256_initial_state_constant dw 0xe667, 0x6a09, 0xae85, 0xbb67
                           dw 0xf372, 0x3c6e, 0xf53a, 0xa54f
                           dw 0x527f, 0x510e, 0x688c, 0x9b05
                           dw 0xd9ab, 0x1f83, 0xcd19, 0x5be0
tls_low_constants_constant_len equ $ - tls_low_constants_constant
%if tls_low_constants_constant_len != low_static_constants_len
%error "low static constants length mismatch"
%endif
sha256_k_constant dw 0x2f98, 0x428a, 0x4491, 0x7137
                  dw 0xfbcf, 0xb5c0, 0xdba5, 0xe9b5
                  dw 0xc25b, 0x3956, 0x11f1, 0x59f1
                  dw 0x82a4, 0x923f, 0x5ed5, 0xab1c
                  dw 0xaa98, 0xd807, 0x5b01, 0x1283
                  dw 0x85be, 0x2431, 0x7dc3, 0x550c
                  dw 0x5d74, 0x72be, 0xb1fe, 0x80de
                  dw 0x06a7, 0x9bdc, 0xf174, 0xc19b
                  dw 0x69c1, 0xe49b, 0x4786, 0xefbe
                  dw 0x9dc6, 0x0fc1, 0xa1cc, 0x240c
                  dw 0x2c6f, 0x2de9, 0x84aa, 0x4a74
                  dw 0xa9dc, 0x5cb0, 0x88da, 0x76f9
                  dw 0x5152, 0x983e, 0xc66d, 0xa831
                  dw 0x27c8, 0xb003, 0x7fc7, 0xbf59
                  dw 0x0bf3, 0xc6e0, 0x9147, 0xd5a7
                  dw 0x6351, 0x06ca, 0x2967, 0x1429
                  dw 0x0a85, 0x27b7, 0x2138, 0x2e1b
                  dw 0x6dfc, 0x4d2c, 0x0d13, 0x5338
                  dw 0x7354, 0x650a, 0x0abb, 0x766a
                  dw 0xc92e, 0x81c2, 0x2c85, 0x9272
                  dw 0xe8a1, 0xa2bf, 0x664b, 0xa81a
                  dw 0x8b70, 0xc24b, 0x51a3, 0xc76c
                  dw 0xe819, 0xd192, 0x0624, 0xd699
                  dw 0x3585, 0xf40e, 0xa070, 0x106a
                  dw 0xc116, 0x19a4, 0x6c08, 0x1e37
                  dw 0x774c, 0x2748, 0xbcb5, 0x34b0
                  dw 0x0cb3, 0x391c, 0xaa4a, 0x4ed8
                  dw 0xca4f, 0x5b9c, 0x6ff3, 0x682e
                  dw 0x82ee, 0x748f, 0x636f, 0x78a5
                  dw 0x7814, 0x84c8, 0x0208, 0x8cc7
                  dw 0xfffa, 0x90be, 0x6ceb, 0xa450
                  dw 0xa3f7, 0xbef9, 0x78f2, 0xc671
sha256_k_constant_len equ $ - sha256_k_constant
%if sha256_k_constant_len != sha256_k_len
%error "sha256 k length mismatch"
%endif

image_end:
