%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

unreal_setup_phase:
    test word [handoff_addr + handoff_flags], handoff_flag_cpu_386plus
    jz .done
    test word [handoff_addr + handoff_flags], handoff_flag_hma
    jz .done
    cmp word [far_ctx_base + 2], ext_flat_base_hi
    jb .done
    pushf
    cli
    db 0x0f, 0x01, 0x16
    dw low_scratch_start + (unreal_gdt_ptr - PHASE_BASE) ; lgdt [unreal_gdt_ptr]
    db 0x0f, 0x20, 0xc0                              ; mov eax, cr0
    db 0x0c, 0x01                                    ; or al, 1
    db 0x0f, 0x22, 0xc0                              ; mov cr0, eax
    db 0xea
    dw low_scratch_start + (.pm - PHASE_BASE)
    dw 0x0008
.pm:
    mov ax, 0x0010
    db 0x8e, 0xe0                                    ; mov fs, ax
    db 0x0f, 0x20, 0xc0                              ; mov eax, cr0
    db 0x24, 0xfe                                    ; and al, ~1
    db 0x0f, 0x22, 0xc0                              ; mov cr0, eax
    db 0xea
    dw low_scratch_start + (.rm - PHASE_BASE)
    dw 0x0000
.rm:
    or word [handoff_addr + handoff_flags], handoff_flag_unreal
    popf
.done:
    clc
    ret

align 8, db 0
unreal_gdt:
    dq 0
    dw 0xffff, 0x0000
    db 0x00, 0x9a, 0x00, 0x00
    dw 0xffff, 0x0000
    db 0x00, 0x92, 0xcf, 0x00
unreal_gdt_end:
unreal_gdt_ptr:
    dw unreal_gdt_end - unreal_gdt - 1
    dd low_scratch_start + (unreal_gdt - PHASE_BASE)
