wd_enter_packet_path:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .done
    add word [handoff_addr + handoff_nic_base], wd_dp8390_offset
.done:
    ret

wd_restore_dp8390_base:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .done
    sub word [handoff_addr + handoff_nic_base], wd_dp8390_offset
.done:
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
