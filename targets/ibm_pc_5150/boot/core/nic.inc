; Build 12 NIC HAL: per-family packet-path ops reached via nic_vtable (populate_nic_vtable fills the
; slots at boot). nic_noop is the shared default for families with no enter/restore work; wd_do_enter
; / wd_do_restore window the DP8390 (wd8003 maps the NIC registers behind a +wd_dp8390_offset window
; the packet path uses, then unmaps). The `cmp [nic_family]` is gone -- the vtable already routed the
; active family in, so these run only for the family that needs them.
nic_noop:
    ret

wd_do_enter:
    add word [handoff_addr + handoff_nic_base], wd_dp8390_offset
    ret

wd_do_restore:
    sub word [handoff_addr + handoff_nic_base], wd_dp8390_offset
    ret

c503_select_dp8390:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    mov al, el2_ctrl_thin
    out dx, al
    ret

; Build 10 rework (DRY): write AX to two consecutive I/O ports (al->dx, ah->dx+1).
; Folds the repeated "out dx,al; inc dx; mov al,ah; out dx,al" across the NE/3c503
; DMA register loads into one resident helper, reclaiming nucleus bytes for the
; shared scroll helper. Callers set DX to the low port and AX to the value.
out_dx_word:
    out dx, al
    inc dx
    mov al, ah
    out dx, al
    ret

; Build 10 rework (DRY): shared BIOS scroll of the text area (rows 1..last), so the phases
; that scroll (renderer, dpi, tool, compaction status) drop their own copies and free phase
; bytes for the new features. Caller sets AX = 0x0601 (scroll up 1 line) and CX = top-left
; (0x0100), and saves CX if it needs it (BIOS may clobber it); scroll_br is the precomputed
; bottom-right corner. (AX/CX are caller-set to keep this within the reclaimed nucleus budget.)
scroll_text_area:
    mov bh, 0x07
    mov dx, [scroll_br]
    int 0x10
    ret
