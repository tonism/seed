; Preloaded conventional-RAM ciphertext mover for the 16 KiB TLS 1.3 path.
;
; HELLO receives c contiguously at 08c0..0cff and the provisional candidate
; consumes it there.  This resident tail then moves the now-public ciphertext
; into slices that survive the following symmetric phase.  It performs no I/O
; and is installed before TCP, so the move adds no floppy activity to either
; provider deadline window.

bits 16
cpu 8086
org 0x0f00

%ifndef SYSRAM_SCATTER_ACQUISITION
%ifndef SYSRAM_SCATTER_RESUMPTION
%error "select one system-RAM scatter layout"
%endif
%endif
%ifdef SYSRAM_SCATTER_ACQUISITION
%ifdef SYSRAM_SCATTER_RESUMPTION
%error "select only one system-RAM scatter layout"
%endif
%endif

sysram_scatter_entry:
    cld
    push ds
    pop es

%ifdef SYSRAM_SCATTER_RESUMPTION
    ; HELLO's input capsule is about to be overwritten by c.  The symmetric
    ; early-secret step needs only the PSK, which fits in retired HELLO state
    ; immediately before the final ciphertext slice.
    mov si, 0x3460
    mov di, 0x0dc0
    mov cx, 16
    rep movsw

    mov si, 0x08c0
    mov di, 0x3400
    mov cx, 272
    rep movsb
    mov si, 0x09d0
    mov di, 0x3640
    mov cx, 13
    rep movsb
    mov si, 0x09dd
    mov di, 0x3b40
    mov cx, 80
    rep movsb
    mov si, 0x0a2d
    mov di, 0x355d
    mov cx, 99
    rep movsb
    mov si, 0x0a90
    mov di, 0x0500
    mov cx, 256
    rep movsb
    mov si, 0x0b90
    mov di, 0x33f8
    mov cx, 8
    rep movsb
%else
    mov si, 0x08c0
    mov di, 0x3400
    mov cx, 272
    rep movsb
    mov si, 0x09d0
    mov di, 0x3600
    mov cx, 77
    rep movsb
    mov si, 0x0a1d
    mov di, 0x355d
    mov cx, 99
    rep movsb
    mov si, 0x0a80
    mov di, 0x0500
    mov cx, 256
    rep movsb
    mov si, 0x0b80
    mov di, 0x33e8
    mov cx, 24
    rep movsb
%endif

    ; Common suffix.  Copy the overlapping 72-byte slice only after logical
    ; c[0..727] is safe, then retire all remaining contiguous duplicates.
    mov si, 0x0b98
    mov di, 0x08b8
    mov cx, 72
    rep movsb
    mov si, 0x0be0
    mov di, 0x0de0
    mov cx, 288
    rep movsb
    xor ax, ax
    mov di, 0x0900
    mov cx, (0x0d00 - 0x0900) / 2
    rep stosw
    clc
    ret

sysram_scatter_end:
%if (sysram_scatter_end - $$) > (0x0fe2 - 0x0f00)
%error "system-RAM scatter reaches the resident TCP tail"
%endif
