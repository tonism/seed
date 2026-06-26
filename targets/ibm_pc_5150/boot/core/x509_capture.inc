; Build 12 auto-recertify: capture the server's leaf certificate from the streamed cert-drain.
;
; The shipped handshake drains the TLS Certificate message in <=592-byte fragments and discards it
; (tls.inc tls_drain_server_certificate). To recertify a ROTATED leaf off-race, we must keep the
; leaf DER. This captures it incrementally as the drain streams, into leaf_capture_buf (the arena;
; 286-only, handshake-only). The off-race chain-verify (parse -> SHA -> verify-vs-WR1 -> adopt) then
; reads it. Oracle-gated offline by tools/crypto-bench/capture_eval.py against the real chain.
;
; TLS Certificate framing the drain sees, from the record start (offset 0):
;   [0..4]  TLS record header (16 03 0v + 2-byte len)
;   [5..8]  handshake header (0b + 3-byte len)
;   [9..11] certificate_list length (3 bytes)
;   [12..14] cert0 (leaf) length (3 bytes)  <- leaf_len
;   [15..]  cert0 DER = the leaf            <- what we capture
; So the leaf occupies record offsets [15, 15+leaf_len).
;
; State (resident; survives the drain -> the off-race recertify in net_phase.retry):
;   capture_pos      record offset of the NEXT byte the chunk handler will see
;   capture_leaf_len cert0 length (0 = not captured / unusable -> recertify fails closed)
;   capture_done     leaf bytes captured so far (== leaf_len when complete)
; cpu 8086.

%define X509_LEAF_FRAME_OFF 15          ; record offset where the leaf DER begins

; capture_leaf_reset -- call once at the start of a Certificate drain. in: DI = destination buffer
; (the resident caller supplies it, since the module can't see the arena address); stored for the
; chunk handler. The module references only this pointer + the layout constant leaf_capture_max.
capture_leaf_reset:
    mov [capture_buf_ptr], di
    mov word [capture_pos], 0
    mov word [capture_leaf_len], 0
    mov word [capture_done], 0
    ret

; capture_leaf_chunk -- fold one drained fragment into the captured leaf.
; in: SI = fragment bytes (record-contiguous), CX = fragment length. 286-gated (no-op on 8088).
; Preserves all registers (the drain keeps using SI/CX after the call).
capture_leaf_chunk:
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .ret
    push ax
    push bx
    push cx                             ; [original fragment length -- restored at .done]
    push dx
    push si
    push di
    ; first fragment? read cert0_len from [si+12..14] (record offset 12..14)
    cmp word [capture_pos], 0
    jne .have_len
    cmp cx, X509_LEAF_FRAME_OFF
    jb .abort                           ; first fragment too small to hold the framing
    cmp byte [si + 12], 0               ; cert0_len high byte (leaf must be < 64 KiB)
    jne .abort
    mov ah, [si + 13]
    mov al, [si + 14]
    or ax, ax
    jz .abort                           ; zero-length leaf
    cmp ax, leaf_capture_max
    ja .abort                           ; leaf bigger than the arena -> cannot capture
    mov [capture_leaf_len], ax
.have_len:
    cmp word [capture_leaf_len], 0
    je .done                            ; aborted earlier -> just track position
    ; skip = (X509_LEAF_FRAME_OFF + capture_done) - capture_pos  (offset into this fragment)
    mov ax, [capture_done]
    add ax, X509_LEAF_FRAME_OFF
    sub ax, [capture_pos]
    js .done                            ; next leaf byte is before this fragment -> gap, skip
    cmp ax, cx
    jae .done                           ; next leaf byte is past this fragment -> nothing here
    mov bx, cx
    sub bx, ax                          ; bx = avail = cx - skip
    mov dx, [capture_leaf_len]
    sub dx, [capture_done]              ; dx = need = leaf_len - done
    cmp bx, dx
    jbe .have_n
    mov bx, dx                          ; bx = min(avail, need)
.have_n:
    or bx, bx
    jz .done
    add si, ax                          ; src = fragment + skip
    mov di, [capture_buf_ptr]
    add di, [capture_done]              ; dst = capture buffer + done
    mov cx, bx
    push ds
    pop es
    cld
    rep movsb
    add [capture_done], bx
.done:
    pop di
    pop si
    pop dx
    pop cx                              ; original fragment length
    add [capture_pos], cx
    pop bx
    pop ax
.ret:
    ret
.abort:
    mov word [capture_leaf_len], 0
    jmp .done

align 2
capture_buf_ptr:  dw 0                  ; destination buffer (set by capture_leaf_reset)
capture_pos:      dw 0
capture_leaf_len: dw 0
capture_done:     dw 0
