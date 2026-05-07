bits 16
cpu 8086
org 0x1000

%include "core/layout.inc"

core_phase_entry_len equ 10

core_header:
    jmp short start
    nop
core_header_magic db 'SEEDCORE'
core_header_version db 1
core_header_flags db 0
core_header_len dw core_header_end - core_header
core_header_resident_sectors dw (core_resident_end - $$ + 511) / 512
core_header_total_sectors dw (core_image_end - $$ + 511) / 512
core_header_phase_table_off dw core_phase_table - $$
core_header_phase_count dw (core_phase_table_end - core_phase_table) / core_phase_entry_len
core_header_reserved dw 0
core_header_end:

%include "core/main.inc"
%include "core/hal_display.inc"
%include "core/ui_core.inc"
%include "core/hal_detect.inc"
%include "core/ui_menu.inc"
%include "core/hal_nic.inc"
%include "core/net_phase.inc"
%include "core/config.inc"
%include "core/fs.inc"
%include "core/nic.inc"
%include "core/net_tx.inc"
%include "core/transport.inc"
%include "core/sha256.inc"
%include "core/p256.inc"
%include "core/chacha20.inc"
%include "core/poly1305.inc"
%include "core/tls.inc"
%include "core/agent_api.inc"
%include "core/net_rx.inc"
%include "core/ui.inc"
%include "core/data.inc"

core_phase_table:
    db 'N', 0
    dw (core_noop_phase_start - $$) / 512
    dw 1
    dw low_scratch_start
    dw 0
    db 'S', 0
    dw (core_save_phase_start - $$) / 512
    dw (core_save_phase_end - core_save_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
core_phase_table_end:

core_resident_end:

%if (core_resident_end - $$) > (runtime_stack_top - runtime_stack_guard_len - 0x1000)
%error "CORE.SYS exceeds 32KB runtime stack guard"
%endif

align 512, db 0

core_noop_phase_start:
    incbin "phase-noop.bin"
core_noop_phase_end:

%if (core_noop_phase_end - core_noop_phase_start) > 512
%error "noop phase exceeds one sector"
%endif

times 512 - (core_noop_phase_end - core_noop_phase_start) db 0

core_save_phase_start:
%define PHASE_BASE core_save_phase_start
%include "phases/save_user_cfg.inc"
%undef PHASE_BASE
core_save_phase_end:

%if (core_save_phase_end - core_save_phase_start) > 512
%error "save phase exceeds one sector"
%endif

times 512 - (core_save_phase_end - core_save_phase_start) db 0

core_image_end:
