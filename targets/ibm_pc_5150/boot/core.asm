bits 16
cpu 8086
org 0x1000

%include "core/layout.inc"
%include "core/nic_ring.inc"

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
core_header_end:

%include "core/main.inc"
%include "core/ui_core.inc"
%include "core/net_phase.inc"
%include "core/fs.inc"
%include "core/nic.inc"
%include "core/net_tx.inc"
%include "core/transport.inc"
%include "core/net_rx.inc"
%include "core/ui.inc"
%include "core/data.inc"

; Build 12 NIC HAL: pad the shared resident code up to the active-driver slot, then reserve the slot.
; The detected family's driver module is loaded here at boot (hardware_setup / populate_nic_vtable);
; every other family's driver stays on the floppy (0 resident RAM). The slot is the 4th nucleus
; sector, so the K crypto window still starts at 0x1800 (= nic_driver_slot_end) — the arena and the
; crypto window are untouched. The shared resident code must fit the 3 sectors below the slot.
%if ($ - $$) > (nic_driver_slot - core_load_addr)
%error "shared resident code overflows past the NIC driver slot (must fit <= 3 sectors / 0x1600)"
%endif
times (nic_driver_slot - core_load_addr) - ($ - $$) db 0
times nic_driver_slot_len db 0

core_resident_end:

; The resident nucleus is loaded at 0x1000 and the K crypto window is pinned at 0x1800,
; so the nucleus must fit the 2 KiB below it. The checks below compare against the much
; higher crypto/critical scratch and would NOT directly flag a spill into the K window.
%if (core_resident_end - $$) > 0x0800
%error "resident nucleus exceeds the 2KB window below the K crypto window at 0x1800"
%endif

%if (core_resident_end - $$) > (critical_scratch_start - core_load_addr)
%error "resident nucleus overlaps critical scratch"
%endif

%if (core_resident_end - $$) > (high_crypto_scratch_start - core_load_addr)
%error "resident nucleus overlaps high crypto scratch"
%endif

%if high_crypto_scratch_end > critical_scratch_start
%error "high crypto scratch overlaps critical scratch"
%endif

%if critical_scratch_end > (basic_sidecar_stack_top_24k - basic_sidecar_stack_guard_len_24k)
%error "critical scratch overlaps 24KB BASIC stack guard"
%endif

; Build 12 (32K floppy-free loop): the chat-loop preload cache is a 32K-only high region. It must sit
; ABOVE the 16K ceiling (so it is absent on a 16K machine and the preload is correctly skipped) and
; BELOW the runtime stack guard (so a 32K boot's stack never collides with it).
%if loop_cache_start <= basic_sidecar_stack_top_16k
%error "32K loop cache base dipped to/below the 16K ceiling — it would collide with the 16K arena"
%endif
%if loop_cache_end > (runtime_stack_top - runtime_stack_guard_len)
%error "32K loop cache overruns the runtime stack guard"
%endif
; (The "preload working set fits the cache" assert references the phase labels, so it lives at the END
;  of this file — below all the phase definitions — where they are backward references the %if can see.)

%if (core_resident_end - $$) > (runtime_stack_top - runtime_stack_guard_len - core_load_addr)
%error "CORE.SYS exceeds 32KB runtime stack guard"
%endif

align 512, db 0

core_link_window_start:
%include "core/sha256.inc"
%include "core/chacha20.inc"
%include "core/poly1305.inc"
%include "core/tls.inc"
%include "core/agent_api.inc"
core_link_window_end:

%if (core_load_addr + (core_link_window_end - $$)) > high_crypto_scratch_start
%error "LINK window overlaps high crypto scratch"
%endif

align 512, db 0

core_failure_phase_start:
%define PHASE_BASE core_failure_phase_start
%include "phases/failure_action.inc"
%undef PHASE_BASE
core_failure_phase_end:

%if (core_failure_phase_end - core_failure_phase_start) > 512
%error "failure action phase exceeds one sector"
%endif

times 512 - (core_failure_phase_end - core_failure_phase_start) db 0

core_hardware_setup_phase_start:
%define PHASE_BASE core_hardware_setup_phase_start
%include "phases/hardware_setup.inc"
%undef PHASE_BASE
core_hardware_setup_phase_end:

%if (core_hardware_setup_phase_end - core_hardware_setup_phase_start) > 2048
%error "hardware setup phase exceeds low scratch window"
%endif

align 512, db 0

core_packet_io_init_phase_start:
%define PHASE_BASE core_packet_io_init_phase_start
%include "phases/packet_io_init.inc"
%undef PHASE_BASE
core_packet_io_init_phase_end:

%if (core_packet_io_init_phase_end - core_packet_io_init_phase_start) > 512
%error "packet IO init phase exceeds one sector"
%endif

times 512 - (core_packet_io_init_phase_end - core_packet_io_init_phase_start) db 0

core_dhcp_setup_phase_start:
%define PHASE_BASE core_dhcp_setup_phase_start
%define PHASE_LOAD_ADDR net_setup_phase_start
%include "phases/dhcp_setup.inc"
%undef PHASE_LOAD_ADDR
%undef PHASE_BASE
core_dhcp_setup_phase_end:

%if (((core_dhcp_setup_phase_end - core_dhcp_setup_phase_start + 511) / 512) * 512) > (low_scratch_end - net_setup_phase_start)
%error "dhcp setup phase rounds to too many sectors for the net setup window (would clobber the resident nucleus at 0x1000)"
%endif

align 512, db 0

core_tcp_connect_phase_start:
%define PHASE_BASE core_tcp_connect_phase_start
%define PHASE_LOAD_ADDR net_setup_phase_start
%include "phases/tcp_connect.inc"
%undef PHASE_LOAD_ADDR
%undef PHASE_BASE
core_tcp_connect_phase_end:

%if (((core_tcp_connect_phase_end - core_tcp_connect_phase_start + 511) / 512) * 512) > (low_scratch_end - net_setup_phase_start)
%error "tcp connect phase rounds to too many sectors for the net setup window (would clobber the resident nucleus at 0x1000)"
%endif

align 512, db 0

core_tls_client_hello_phase_start:
%define PHASE_BASE core_tls_client_hello_phase_start
%include "phases/tls_client_hello.inc"
%undef PHASE_BASE
core_tls_client_hello_phase_end:

%if (core_tls_client_hello_phase_end - core_tls_client_hello_phase_start) > (low_scratch_end - low_scratch_start)
%error "tls client hello phase exceeds low scratch window"
%endif

align 512, db 0

core_agent_endpoint_phase_start:
%define PHASE_BASE core_agent_endpoint_phase_start
%include "phases/agent_endpoint.inc"
%undef PHASE_BASE
core_agent_endpoint_phase_end:

%if (core_agent_endpoint_phase_end - core_agent_endpoint_phase_start) > 512
%error "agent endpoint phase exceeds one sector"
%endif

times 512 - (core_agent_endpoint_phase_end - core_agent_endpoint_phase_start) db 0

core_agents_cfg_phase_start:
%define PHASE_BASE core_agents_cfg_phase_start
%include "phases/agents_cfg.inc"
%undef PHASE_BASE
core_agents_cfg_phase_end:

%if (core_agents_cfg_phase_end - core_agents_cfg_phase_start) > (low_scratch_end - low_scratch_start)
%error "agents config phase exceeds low scratch window"
%endif

align 512, db 0

core_user_cfg_phase_start:
%define PHASE_BASE core_user_cfg_phase_start
%include "phases/user_cfg.inc"
%undef PHASE_BASE
core_user_cfg_phase_end:

%if (core_user_cfg_phase_end - core_user_cfg_phase_start) > 2048
%error "user config phase exceeds low scratch window"
%endif

align 512, db 0

core_agent_setup_phase_start:
%define PHASE_BASE core_agent_setup_phase_start
%include "phases/agent_setup.inc"
%undef PHASE_BASE
core_agent_setup_phase_end:

%if (core_agent_setup_phase_end - core_agent_setup_phase_start) > 2048
%error "agent setup phase exceeds low scratch window"
%endif

align 512, db 0

core_agent_request_phase_start:
%define PHASE_BASE core_agent_request_phase_start
%include "phases/agent_request.inc"
%undef PHASE_BASE
core_agent_request_phase_end:

%if (core_agent_request_phase_end - core_agent_request_phase_start) > (fs_sector_buffer - low_scratch_start)
%error "agent request phase overlaps request body scratch"
%endif

align 512, db 0

core_agent_cache_phase_start:
%define PHASE_BASE core_agent_cache_phase_start
%include "phases/agent_cache.inc"
%undef PHASE_BASE
core_agent_cache_phase_end:

%if (core_agent_cache_phase_end - core_agent_cache_phase_start) > 512
%error "agent cache phase exceeds one sector"
%endif

times 512 - (core_agent_cache_phase_end - core_agent_cache_phase_start) db 0

core_agent_api_stream_phase_start:
%define PHASE_BASE core_agent_api_stream_phase_start
%define PHASE_LOAD_ADDR net_setup_phase_start
%include "phases/agent_api_stream.inc"
%undef PHASE_LOAD_ADDR
%undef PHASE_BASE
core_agent_api_stream_phase_end:

%if (((core_agent_api_stream_phase_end - core_agent_api_stream_phase_start + 511) / 512) * 512) > (low_scratch_end - net_setup_phase_start)
%error "agent api stream phase rounds to too many sectors for the net setup window (would clobber the resident nucleus at 0x1000)"
%endif

align 512, db 0

core_agent_response_phase_start:
%define PHASE_BASE core_agent_response_phase_start
%define PHASE_LOAD_ADDR agent_response_phase_load_addr
%include "phases/agent_response.inc"
%undef PHASE_LOAD_ADDR
%undef PHASE_BASE
core_agent_response_phase_end:

%if (agent_response_phase_load_addr + 512) > low_scratch_end
%error "agent response phase load address exceeds low scratch"
%endif

%if (core_agent_response_phase_end - core_agent_response_phase_start) > (low_scratch_end - agent_response_phase_load_addr)
%error "agent response phase exceeds cold response window"
%endif

%if (core_agent_response_phase_end - core_agent_response_phase_start) > 512
%error "agent response phase exceeds hot one-sector window"
%endif

align 512, db 0

core_splash_phase_start:
%define PHASE_BASE core_splash_phase_start
%include "phases/splash.inc"
%undef PHASE_BASE
core_splash_phase_end:

%if (core_splash_phase_end - core_splash_phase_start) > 512
%error "splash phase exceeds one sector"
%endif

times 512 - (core_splash_phase_end - core_splash_phase_start) db 0

core_tool_phase_start:
%define PHASE_BASE core_tool_phase_start
%define PHASE_LOAD_ADDR net_setup_phase_start
%include "phases/tool_call.inc"
%undef PHASE_LOAD_ADDR
%undef PHASE_BASE
core_tool_phase_end:

; Loaded at net_setup_phase_start (0x0900) by dpi and run between turns. Keep it
; clear of low_phase_state (cursor/colour bytes dpi reads after) - those sit near
; the top of low scratch, so cap well under the full 0x0900..low_scratch_end span.
%if (core_tool_phase_end - core_tool_phase_start) > 1024
%error "tool phase exceeds its between-turns budget"
%endif

align 512, db 0

core_dpi_phase_start:
%define PHASE_BASE core_dpi_phase_start
%include "phases/dpi.inc"
%undef PHASE_BASE
core_dpi_phase_end:

%if (core_dpi_phase_end - core_dpi_phase_start) > 512
%error "dpi phase exceeds one sector"
%endif

times 512 - (core_dpi_phase_end - core_dpi_phase_start) db 0

core_save_phase_start:
%define PHASE_BASE core_save_phase_start
%include "phases/save_user_cfg.inc"
%undef PHASE_BASE
core_save_phase_end:

core_phase_table:
    db 'K', 0
    dw (core_link_window_start - $$) / 512
    dw (core_link_window_end - core_link_window_start + 511) / 512
    dw core_link_window_start
    dw 0
    db 'F', 0
    dw (core_failure_phase_start - $$) / 512
    dw (core_failure_phase_end - core_failure_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'H', 0
    dw (core_hardware_setup_phase_start - $$) / 512
    dw (core_hardware_setup_phase_end - core_hardware_setup_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'I', 0
    dw (core_packet_io_init_phase_start - $$) / 512
    dw (core_packet_io_init_phase_end - core_packet_io_init_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'D', 0
    dw (core_dhcp_setup_phase_start - $$) / 512
    dw (core_dhcp_setup_phase_end - core_dhcp_setup_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'C', 0
    dw (core_tcp_connect_phase_start - $$) / 512
    dw (core_tcp_connect_phase_end - core_tcp_connect_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'L', 0
    dw (core_tls_client_hello_phase_start - $$) / 512
    dw (core_tls_client_hello_phase_end - core_tls_client_hello_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'E', 0
    dw (core_agent_endpoint_phase_start - $$) / 512
    dw (core_agent_endpoint_phase_end - core_agent_endpoint_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'A', 0
    dw (core_agents_cfg_phase_start - $$) / 512
    dw (core_agents_cfg_phase_end - core_agents_cfg_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'U', 0
    dw (core_user_cfg_phase_start - $$) / 512
    dw (core_user_cfg_phase_end - core_user_cfg_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'Q', 0
    dw (core_agent_setup_phase_start - $$) / 512
    dw (core_agent_setup_phase_end - core_agent_setup_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'R', 0
    dw (core_agent_request_phase_start - $$) / 512
    dw (core_agent_request_phase_end - core_agent_request_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'V', 0
    dw (core_agent_cache_phase_start - $$) / 512
    dw (core_agent_cache_phase_end - core_agent_cache_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'X', 0
    dw (core_agent_api_stream_phase_start - $$) / 512
    dw (core_agent_api_stream_phase_end - core_agent_api_stream_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'T', 0
    dw (core_agent_response_phase_start - $$) / 512
    dw (core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512
    dw agent_response_phase_load_addr
    dw 0
    db 'B', 0
    dw (core_splash_phase_start - $$) / 512
    dw (core_splash_phase_end - core_splash_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'Y', 0
    dw (core_dpi_phase_start - $$) / 512
    dw (core_dpi_phase_end - core_dpi_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
    db 'M', 0
    dw (core_tool_phase_start - $$) / 512
    dw (core_tool_phase_end - core_tool_phase_start + 511) / 512
    dw net_setup_phase_start
    dw 0
    db 'S', 0
    dw (core_save_phase_start - $$) / 512
    dw (core_save_phase_end - core_save_phase_start + 511) / 512
    dw low_scratch_start
    dw 0
core_phase_table_end:

%if (core_phase_table_end - core_save_phase_start) > 1024
%error "save phase and metadata exceed metadata window"
%endif

; Build 12 NIC HAL: the four NIC driver modules. Each is a self-contained driver assembled at its
; image position but run at nic_driver_slot; hardware_setup loads ONLY the detected family's module
; (whole-sector) into the slot at boot, so inactive drivers cost zero resident RAM. Each must fit
; the one-sector slot. DRIVER_BASE names the module start (for the slot-relative header + drv_call_res).
align 512, db 0
core_ne_driver_start:
%define DRIVER_BASE core_ne_driver_start
%include "drivers/ne.inc"
%undef DRIVER_BASE
core_ne_driver_end:
%if (core_ne_driver_end - core_ne_driver_start) > nic_driver_slot_len
%error "ne driver module exceeds the active-driver slot"
%endif

align 512, db 0
core_wd8003_driver_start:
%define DRIVER_BASE core_wd8003_driver_start
%include "drivers/wd8003.inc"
%undef DRIVER_BASE
core_wd8003_driver_end:
%if (core_wd8003_driver_end - core_wd8003_driver_start) > nic_driver_slot_len
%error "wd8003 driver module exceeds the active-driver slot"
%endif

align 512, db 0
core_el2_3c503_driver_start:
%define DRIVER_BASE core_el2_3c503_driver_start
%include "drivers/el2_3c503.inc"
%undef DRIVER_BASE
core_el2_3c503_driver_end:
%if (core_el2_3c503_driver_end - core_el2_3c503_driver_start) > nic_driver_slot_len
%error "3c503 driver module exceeds the active-driver slot"
%endif

align 512, db 0
core_el1_3c501_driver_start:
%define DRIVER_BASE core_el1_3c501_driver_start
%include "drivers/el1_3c501.inc"
%undef DRIVER_BASE
core_el1_3c501_driver_end:
%if (core_el1_3c501_driver_end - core_el1_3c501_driver_start) > nic_driver_slot_len
%error "3c501 driver module exceeds the active-driver slot"
%endif

align 512, db 0

; Build 12 (32K floppy-free loop): the preloaded chat-loop working set (loop_preload_list — dpi/Y +
; agent_request/R + agent_api_stream/X + agent_response/T + tool/M + the K crypto window) is written
; sequentially from loop_cache_start and must not collide with the two prompt slots pinned at the top
; of the cache (prompt_id_cache / prompt_compact_cache, 2 sectors). Placed here (not with the other
; layout guards near the top) because %if cannot forward-reference the phase labels. Keep the sum in
; sync with loop_preload_list (main.inc).
%if (((core_dpi_phase_end - core_dpi_phase_start + 511) / 512) + \
     ((core_agent_request_phase_end - core_agent_request_phase_start + 511) / 512) + \
     ((core_agent_api_stream_phase_end - core_agent_api_stream_phase_start + 511) / 512) + \
     ((core_agent_response_phase_end - core_agent_response_phase_start + 511) / 512) + \
     ((core_tool_phase_end - core_tool_phase_start + 511) / 512) + \
     ((core_link_window_end - core_link_window_start + 511) / 512)) > (loop_cache_max_sectors - 2)
%error "32K chat-loop preload working set + 2 prompt sectors exceeds the loop cache (raise loop_cache_max_sectors)"
%endif

core_image_end:
