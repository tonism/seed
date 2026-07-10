; Build 12 M3/M4: native extended-memory layout. Called after far_arena_top = conv_top and after the
; default far_ctx_base/far_window_cap values are installed. If BIOS AH=88h reports memory above 1 MiB,
; enable A20 for the HMA direct window. If there is usable memory above the HMA, move the canonical
; context to the top of that native extended range and leave all conventional far memory as direct arena.
; Returns CF clear when far_ctx_base/far_window_cap now name a native extended context; CF set means the
; caller should fall back to EMS or the conventional M1 split. Uses far_ctx_base as scratch only on the
; success path. Clobbers ax/bx/cx/dx/si/di/bp/ds/es.

ext_layout_phase:
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_286plus
    jz .failed
    mov ah, 0x88
    int 0x15
    jc .failed
    or ax, ax
    jz .failed
    mov bp, ax                                      ; extended KiB above 1 MiB
    call .enable_a20
    jc .no_hma
    cmp bp, 64
    jb .no_hma
    or word [handoff_addr + handoff_flags], handoff_flag_hma
.no_hma:
    cmp bp, 64                                      ; e@ starts above the HMA; HMA-only is not an ext layout
    jbe .failed
    mov ax, bp
    xor dx, dx
    mov cl, 10
.ext_size_shift:
    shl ax, 1
    rcl dx, 1
    dec cl
    jnz .ext_size_shift                             ; dx:ax = ext_size bytes
    mov [far_ctx_base], ax                          ; scratch: ext_size
    mov [far_ctx_base + 2], dx
    mov ax, [far_arena_top]
    mov dx, [far_arena_top + 2]
    sub ax, 0
    sbb dx, 1                                       ; dx:ax = conv_top - 0x10000
    add ax, [far_ctx_base]
    adc dx, [far_ctx_base + 2]                      ; pool = conventional arena + native extended bytes
    shr dx, 1
    rcr ax, 1                                       ; cap = pool / 2
    cmp dx, 0x0010
    jb .cap_ready
    ja .cap_1mb
    or ax, ax
    jz .cap_ready
.cap_1mb:
    xor ax, ax
    mov dx, 0x0010
.cap_ready:
    mov si, [far_ctx_base]
    mov di, [far_ctx_base + 2]
    sub si, 0
    sbb di, 1                                       ; ext_size - 64 KiB: bytes available above HMA
    cmp dx, di
    ja .failed_reset
    jb .use_ext_layout
    cmp ax, si
    ja .failed_reset
.use_ext_layout:
    mov [far_window_cap], ax
    mov [far_window_cap + 2], dx
    mov ax, [far_ctx_base]
    mov dx, [far_ctx_base + 2]
    add ax, 0
    adc dx, ems_flat_base_hi                        ; ext_top = 0x00100000 + ext_size
    sub ax, [far_window_cap]
    sbb dx, [far_window_cap + 2]                    ; context base = ext_top - cap
    mov [far_ctx_base], ax
    mov [far_ctx_base + 2], dx
    clc
    jmp .return
.failed_reset:
    mov word [far_ctx_base], 0x0000
    mov word [far_ctx_base + 2], 0x0001
.failed:
    stc
.return:
    pushf
    xor ax, ax
    mov ds, ax
    mov es, ax
    popf
    ret

.enable_a20:
    mov ax, 0x2401
    int 0x15
    call .verify
    jnc .ok
    in al, 0x92
    or al, 0x02
    and al, 0xfe
    out 0x92, al
    call .verify
    jnc .ok
    call .enable_kbc_a20
    jc .done
    call .verify
    jc .done
.ok:
    clc
.done:
    ret
.enable_kbc_a20:
    call .kbc_wait_in
    jc .kbc_fail
    mov al, 0xd1
    out 0x64, al
    call .kbc_wait_in
    jc .kbc_fail
    mov al, 0xdf
    out 0x60, al
    call .kbc_wait_in
    ret
.kbc_fail:
    stc
    ret
.kbc_wait_in:
    xor cx, cx
.kbc_wait_in_loop:
    in al, 0x64
    test al, 0x02
    jz .kbc_ready
    loop .kbc_wait_in_loop
    stc
    ret
.kbc_ready:
    clc
    ret
.verify:
    xor ax, ax
    mov ds, ax
    mov si, 0x0500
    mov ax, 0xffff
    mov es, ax
    mov di, 0x0510
    mov ax, [si]
    mov bx, [es:di]
    mov cx, ax
    xor ax, 0xffff
    mov [si], ax
    cmp [es:di], ax
    mov [si], cx
    je .wrapped
    mov ax, bx
    xor ax, 0xa55a
    mov [es:di], ax
    cmp [es:di], ax
    mov [es:di], bx
    jne .wrapped
    clc
    ret
.wrapped:
    stc
    ret
