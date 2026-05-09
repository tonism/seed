wd_enter_packet_path:
    cmp byte [handoff_addr + handoff_nic_family], family_wd8003
    jne .done
    mov dx, [handoff_addr + handoff_nic_base]
    in al, dx
    or al, wd_msr_enable_ram
    out dx, al
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
