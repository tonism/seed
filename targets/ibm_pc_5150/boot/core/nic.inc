; Build 13 NIC HAL: the SHARED NIC helpers that stay resident. Per-family driver code lives in
; SEED/DRIVERS/*.DRV and is loaded into the active-driver slot at boot. c503_select_dp8390 returns
; the 3c503 gate array to DP8390 mode; both the 3c503 driver and cold packet_io_init call it, so it
; stays resident.
c503_select_dp8390:
    mov dx, [handoff_addr + handoff_nic_base]
    add dx, el2_ctrl
    mov al, el2_ctrl_thin
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
