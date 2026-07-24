%ifndef LOADER_SECTORS
%define LOADER_SECTORS 4
%endif

build_number equ 13
; Build 10 (agentic loop): max consecutive auto-continue turns before handing back to the
; user, so a model that keeps emitting tool calls cannot loop forever.
agent_loop_max equ 8
core_load_addr equ 0x1000
handoff_addr equ 0x0600
low_sha256_k equ 0x0500
runtime_stack_top equ 0x8000
runtime_stack_guard_len equ 1536
; Build 12 Stage C: the legacy/default far context segment. Hardware setup recomputes
; far_log_seg_var when conventional RAM is split arena-first, so this constant is only the
; inactive/default 0x10000 base, not a permanent layout promise.
far_log_seg equ 0x1000
; Build 12 milestone 2 (EMS): the windowed backend targets the Lo-tech EMS board (86Box isamem
; `lotechems`) — bare-metal, so seed drives the board's mapping registers directly (no int 67h/EMM).
; Four frame slots at BASE+0..+3, each a plain byte = the 16 KB logical page it shows; slot S is visible
; at segment EMS_FRAME_SEG + 0x400*S. EMS gets a synthetic flat range above the 1 MB real-mode ceiling:
; [EMS_FLAT_BASE .. EMS_FLAT_BASE + ems_page_count*EMS_PAGE_SIZE), tagged windowed in the ledger.
ems_base_port equ 0x0260        ; slot-0 page-map register (slots at ems_base_port + slot)
ems_frame_seg equ 0xD000        ; 64 KB page frame; slot S window seg = ems_frame_seg + 0x400*slot
ems_page_size equ 0x4000        ; 16 KB logical page
ems_max_pages equ 256           ; probe ceiling: 256 * 16 KB = 4 MB (the board's max)
ems_flat_base_hi equ 0x0010     ; EMS flat base 0x00100000 (high word; low word 0)
hma_flat_base_hi equ 0x0010     ; HMA base 0x00100000; top is 0x0010fff0 (exclusive)
hma_flat_top_lo equ 0xfff0
hma_flat_top_hi equ 0x0010
ext_flat_base_hi equ 0x0011     ; native extended arena starts after the HMA window: 0x00110000
low_scratch_start equ 0x0700
low_scratch_end equ 0x1000
; Build 12 NIC HAL: the resident active-driver slot — the 4th nucleus sector. The shared resident
; code fits the first 3 sectors (0x1000..nic_driver_slot); the detected family's driver module is
; loaded HERE at boot and every other family's driver stays on the floppy (0 resident RAM). The K
; crypto window still starts at 0x1800 (= nic_driver_slot_end), so this costs no arena and no
; crypto-window move. Each driver module must fit one sector (loaded whole-sector into the slot).
nic_driver_slot equ 0x1600
nic_driver_slot_len equ 0x200
nic_driver_slot_end equ nic_driver_slot + nic_driver_slot_len
nic_vt_slot_count equ 5
; Build 12 (32K floppy-free chat loop): on a 32K DIRECT boot the chat-loop working set (the dpi,
; agent_request, K crypto window, agent_api_stream, agent_response and tool phases) is preloaded into
; a high RAM cache at boot, so the loop runs with NO mid-conversation floppy reads. The cache sits
; ABOVE the arena/context pool and BELOW the runtime stack guard, and exists ONLY on 32K (on
; 16K ram_top=0x4000 is below loop_cache_start, so the region is absent and the preload is skipped).
; ram_tier_32k_min gates it (ram_top >= this => 32K direct boot). loop_cache_max_sectors caps the
; working set (Y/R/K/X/T/M = 26 sectors today, T=tool grew to 3 for the EMS $r/$w path); hardware_setup
; tops the 32K arena out at loop_cache_start, and the ledger advertises that ceiling so the agent never
; $w's the cache. 28 keeps loop_cache_start (0x4200) above the 16K ceiling (0x4000); 29 would collide.
ram_tier_32k_min equ 0x6000
loop_cache_max_sectors equ 28
loop_cache_len equ loop_cache_max_sectors * 512
loop_cache_end equ runtime_stack_top - runtime_stack_guard_len
loop_cache_start equ loop_cache_end - loop_cache_len
; Build 12 incr 3: the normal-turn IDENTITY prompt (<=512 B = 1 sector, see the Makefile cap) caches
; in a fixed slot at the TOP of the loop cache, independent of the phase count; the phases fill from
; loop_cache_start upward. The rare COMPACT prompt streams from floppy so the local-history response
; scanner can keep its second sector without moving the 32K cache below the 16K ceiling.
prompt_id_cache equ loop_cache_end - 512
; Build 12 native tool calling: raw SSE function_call capture. The response phase loads at 0x0900
; during receive, so this sector at 0x0d00 is a low-memory handoff buffer that survives the later
; parser phase (loaded at 0x0700..0x0d00). The memory helper may later load through 0x0d00 because
; the parser has already copied call id/name/arguments into reconnect-safe state. This keeps native
; tools available on the 16K floor without using the 32K-only loop-cache/stack-guard band.
fc_capture_max equ 512
fc_capture_buf equ low_scratch_start + 0x0600
; Tool-memory helper handoff. The parser phase sets this byte to 'r'/'w'/'e' after parsing a native
; memory call, then the resident chat loop loads the helper phase below this 0x0f00 scratch window.
tool_scratch_base equ net_setup_phase_start + 3 * 512
tool_sink equ tool_scratch_base
tool_helper_pending equ net_setup_phase_start + 3 * 512 + 1
tool_addr    equ tool_scratch_base + 2
tool_seg     equ tool_scratch_base + 6
tool_farptr  equ tool_scratch_base + 8
tool_readlen equ tool_scratch_base + 12
tool_readbuf equ tool_scratch_base + 14
tool_scratch_end equ tool_readbuf + 32
; Build 12 native tool calling: the resident tools-schema buffer on the loop-cache tiers (32K/256K).
; The schema is kept <=1 sector so the cache only steals 512 B from the arena/context pool; a 2-sector
; cache leaves the 32K window too small for ordinary turns after the parser state grew this block.
; 16K has NO resident buffer (tools_cache is referenced only on 32K+); it streams TOOLS from floppy.
tools_cache_sectors equ 1
tools_cache_len equ tools_cache_sectors * 512
tools_cache equ loop_cache_start - tools_cache_len
tools_schema_max_len equ 384
; Build 12 286 secure tier: the handshake-only P-256 ECDHE module (core/p256_module.asm, incbin'd into
; SEED.SYS). Loaded ONLY on the 286 secure path (handoff_flag_cpu_286plus) into a high overlay band
; that ALIASES the 32K loop cache — lifetime-disjoint: the module runs during the boot handshake; the
; loop cache is preloaded AFTER it (a reconnect reloads the module, then re-preloads the cache). The
; 286 secure tier is inherently 32K (it needs this high region), so the 16K floor never reaches here;
; p256_module_load == loop_cache_start keeps the band above the 16K ceiling (absent on 16K). The module
; (code + data) must fit p256_module_max_sectors (build-asserted in p256_module.asm) AND the loop cache.
p256_module_load equ loop_cache_start
; Sized for the P-256 ECDHE code+data (incr A, 14 sectors) PLUS the RSA-2048 modexp, the external
; leaf SKE-signature verify (incr B), and the auto-recertify trust core (X.509 strict parser + adopt
; math + WR1 anchor). The RSA verify workspace is emitted as zeroed data, not a baked host key;
; SEED/LEAF.DER supplies the host leaf. The captured leaf gets the 24..27 slot above the module
; (leaf_capture_buf, mid-chat-safe; see data.inc). Must stay <= the loop cache.
p256_module_max_sectors equ 24
p256_module_max_len equ p256_module_max_sectors * 512
p256_module_end equ p256_module_load + p256_module_max_len
%if p256_module_end > loop_cache_end
%error "p256 module band overruns the 32K loop cache region"
%endif
; The entry-point-only ABI: a 5-entry near-pointer WORD table at the module base (mirrored + asserted
; in p256_module.asm). Each equate IS a table-slot address; the resident code calls in via
; `call word [p256_ep_*]` (a near indirect call through the slot -- no jmp-size ambiguity).
p256_ep_set_client_private equ p256_module_load + 0
p256_ep_gen_client_public  equ p256_module_load + 2
p256_ep_set_server_ec      equ p256_module_load + 4
p256_ep_compute_premaster  equ p256_module_load + 6
p256_ep_copy_client_public equ p256_module_load + 8
p256_ep_verify_ske_sig     equ p256_module_load + 10
; auto-recertify entry points (off-race X.509 chain-verify + adopt; 286 secure path only):
p256_ep_parse_leaf         equ p256_module_load + 12
p256_ep_chain_verify_sig   equ p256_module_load + 14
p256_ep_adopt_leaf         equ p256_module_load + 16
; the parser's extracted field pointers, written by p256_ep_parse_leaf at a FIXED ABI offset (right
; after the 9-word table) so the resident orchestrator reads them across the module boundary:
p256_x509_result_tbs_ptr   equ p256_module_load + 18
p256_x509_result_tbs_len   equ p256_module_load + 20
p256_x509_result_sig_ptr   equ p256_module_load + 22
p256_x509_result_mod_ptr   equ p256_module_load + 24
p256_x509_result_nb_ptr    equ p256_module_load + 26
p256_x509_result_na_ptr    equ p256_module_load + 28
; auto-recertify capture entry points (second pointer block at +30, after the result block):
p256_ep_capture_reset      equ p256_module_load + 30
p256_ep_capture_chunk      equ p256_module_load + 32
p256_ep_recertify_prep     equ p256_module_load + 34
; Max leaf the capture buffer holds (a layout constant the module references; the resident caller
; supplies the actual buffer to capture_leaf_reset). data.inc asserts the arena is at least this big.
leaf_capture_max equ 1536
; (loop_cache_start must stay above the 16K ceiling so the region is 32K-only — asserted in core.asm,
; where every equate is defined; %if here would precede basic_sidecar_stack_top_16k's definition.)
net_setup_frame_scratch_len equ 512
net_setup_phase_start equ low_scratch_start + net_setup_frame_scratch_len
; Build 12 task#7: transient scratch for the NTP->RTC conversion (NTP setup phase only). Lives in the
; net-setup frame-scratch tail -- free once the ~90 B NTP frame is sent/received. The CMOS RTC, not
; this scratch, carries the time forward to the recertify validity gate, so it need not persist.
ntp_rtc_scratch equ low_scratch_start + net_setup_frame_scratch_len - 16
ntp_seconds equ ntp_rtc_scratch            ; dd: unsigned seconds-since-1900 from the NTP reply
rtc_fields equ ntp_seconds + 4             ; 7 contiguous BCD bytes (sec..century):
rtc_sec equ rtc_fields
rtc_min equ rtc_sec + 1
rtc_hour equ rtc_min + 1
rtc_day equ rtc_hour + 1
rtc_month equ rtc_day + 1
rtc_year equ rtc_month + 1
rtc_century equ rtc_year + 1
agent_response_phase_load_addr equ net_setup_phase_start
basic_sidecar_stack_top_16k equ 0x4000
basic_sidecar_stack_guard_len_16k equ 0x0100   ; Build 9: 0x200->0x100; ~196 B static worst-case stack (Phase 4 tripwire confirms); frees 256 B -> context pool
basic_sidecar_stack_top_24k equ 0x6000
basic_sidecar_stack_guard_len_24k equ 0x0100
handoff_magic equ 0
handoff_version equ 4
handoff_size equ 5
handoff_build equ 7
handoff_flags equ 8
handoff_boot_drive equ 10
handoff_video_mode equ 11
handoff_video_cols equ 12
handoff_seed_col equ 13
handoff_nic_base equ 14
handoff_nic_family equ 16
handoff_config_source equ 17
handoff_nic_irq equ 18
handoff_mac equ 19
handoff_status equ 25
handoff_net_status equ 26
handoff_net_error equ 27
handoff_ip_addr equ 28
handoff_router_addr equ 32
handoff_dns_addr equ 36
handoff_subnet_addr equ 40
handoff_ram_top equ 44
handoff_size_bytes equ 46
handoff_struct_version equ 4   ; Build 12: capability vector extended (handoff_flag_cpu_286plus / _fpu)
basic_boot_magic_bx equ 0x5345
basic_boot_magic_cx equ 0x4544
handoff_flag_mda equ 0x0001
handoff_flag_nic_present equ 0x0002
handoff_flag_config_resolved equ 0x0004
handoff_flag_mac_valid equ 0x0008
; Build 12 capability vector: CPU class. The secure (real-crypto) tier gates on "is this a 286 or
; better?" — a single bit is all that gate needs, so it rides the free handoff_flags bits rather than
; growing the full-packed handoff + reclaiming low_runtime_state. hardware_setup detects it at boot.
; A finer class enum (V20 / 386 / 486), FPU-present, and link-type stay RESERVED in the free bits
; (0x0040+) until a consumer needs them (the FPU does not unlock secure crypto — measured).
handoff_flag_cpu_286plus equ 0x0010
handoff_flag_fpu equ 0x0020
; Reserved for a future writable-boot-media hint. Startup must not write the boot
; floppy; persistence writes are attempted only when a save action explicitly
; requests them.
handoff_flag_writable_media equ 0x0040
handoff_flag_cpu_386plus equ 0x0080
handoff_flag_hma equ 0x0100
handoff_flag_unreal equ 0x0200
handoff_flag_wd_ram_dc00 equ 0x0400
handoff_status_booting equ 1
handoff_status_no_nic equ 2
handoff_status_ready equ 3
handoff_status_network_failed equ 4
handoff_status_agent_failed equ 5
seed_flag_agent equ 0x01
seed_flag_model equ 0x02
seed_flag_key equ 0x04
seed_flag_endpoint equ 0x08
seed_flag_reasoning equ 0x10
net_status_none equ 0
net_status_identity_ready equ 1
net_status_packet_ready equ 2
net_status_tx_ready equ 3
net_status_rx_poll_ready equ 4
net_status_rx_frame_read equ 5
net_status_dhcp_discover_sent equ 6
net_status_dhcp_offer_received equ 7
net_status_dhcp_request_sent equ 8
net_status_dhcp_ack_received equ 9
net_status_arp_request_sent equ 10
net_status_arp_resolved equ 11
net_status_dns_query_sent equ 12
net_status_dns_response_received equ 13
net_status_next_hop_arp_request_sent equ 14
net_status_next_hop_arp_resolved equ 15
net_status_tcp_syn_sent equ 16
net_status_tcp_synack_received equ 17
net_status_tcp_connected equ 18
net_status_tcp_payload_sent equ 19
net_status_tcp_payload_received equ 20
net_status_tls_clienthello_sent equ 21
net_status_tls_record_received equ 22
net_status_tls_serverhello_received equ 23
net_status_tls_certificate_received equ 24
net_status_tls_certificate_drained equ 25
net_status_tls_serverkeyexchange_received equ 26
net_status_tls_serverhellodone_received equ 27
net_status_tls_transcript_ready equ 28
net_status_tls_premaster_ready equ 29
net_status_tls_keys_ready equ 30
net_status_tls_clientkeyexchange_sent equ 31
net_status_tls_changecipherspec_sent equ 32
net_status_tls_clientfinished_sent equ 33
net_status_tls_serverccs_received equ 34
net_status_tls_serverfinished_verified equ 35
net_error_none equ 0
net_error_ne_init equ 1
net_error_ne_tx equ 2
net_error_ne_rx equ 3
net_error_dhcp_offer equ 4
net_error_ne_rx_dma equ 5
net_error_ne_rx_header equ 6
net_error_ne_rx_count equ 7
net_error_dhcp_ack equ 8
net_error_arp equ 9
net_error_dns equ 10
net_error_next_hop_arp equ 11
net_error_tcp equ 12
net_error_tls equ 13
net_error_driver equ 14
nic_driver_meta_magic_off equ nic_vt_slot_count * 2
nic_driver_meta_version_off equ nic_driver_meta_magic_off + 4
nic_driver_meta_family_mask_off equ nic_driver_meta_version_off + 1
nic_driver_abi_version equ 2
seed_attr_cga equ 0x0f
build_attr_cga equ 0x08
load_attr_cga equ 0x08
crypto_attr_cga equ 0x07
ready_attr_cga equ 0x0f
question_attr_cga equ 0x0f
error_attr_cga equ 0x0c
menu_selected_attr_cga equ 0x0f
menu_idle_attr_cga equ 0x08
color_video_seg equ 0xb800
seed_attr_mda equ 0x0f
build_attr_mda equ 0x07
load_attr_mda equ 0x07
crypto_attr_mda equ 0x07
ready_attr_mda equ 0x0f
question_attr_mda equ 0x0f
error_attr_mda equ 0x0f
menu_selected_attr_mda equ 0x0f
menu_idle_attr_mda equ 0x07
seed_len equ 4
seed_row equ 12
question_row equ seed_row + 2
dpi_prompt_row equ 24
dpi_prompt_col equ 0
dpi_input_max_len equ 255   ; 256 B prompt region in RX (255 chars + 1 length byte; len is a byte, max 255)
api_response_text_max_len equ 192
load_ticks equ 6
pnp_settle_ticks equ 18
type_ticks equ 1
done_ticks equ 9
agent_slot_count equ 5
adapter_select_io_280 equ 0
adapter_select_ne equ 1
agent_id_len equ 12
seed_model_len equ 64
; Seed policy cap for supported OpenAI/Anthropic/Google key formats.
seed_key_len equ 192
seed_endpoint_len equ 80
seed_reasoning_len equ 8
seed_value_total_len equ agent_id_len + seed_model_len + seed_key_len + seed_endpoint_len + seed_reasoning_len
config_auto equ 1
config_user equ 2
profile_irq equ 3
family_tulip equ 0
family_3c503 equ 1
family_ne2000 equ 2
family_ne1000 equ 3
family_3c501 equ 4
family_wd8003 equ 5
family_wd8013 equ 6
family_pcnet equ 7
family_rtl8139 equ 8
pci_bios_install equ 0xb101
pci_bios_find_device equ 0xb102
pci_bios_read_config_word equ 0xb109
pci_config_bar0 equ 0x10
pci_dec_vendor equ 0x1011
pci_dec_21040_device equ 0x0002
pci_dec_21140_device equ 0x0009
pci_dec_21143_device equ 0x0019
pci_amd_vendor equ 0x1022
pci_pcnet_device equ 0x2000
pci_realtek_vendor equ 0x10ec
pci_rtl8029_device equ 0x8029
pci_rtl8139_device equ 0x8139
el1_dataptr equ 0x08
el1_rx_cmd equ 0x06
el1_tx_cmd equ 0x07
el1_rcvptr equ 0x0a
el1_saprom equ 0x0c
el1_aux equ 0x0e
el1_data equ 0x0f
el1_rx_status_good equ 0x20
el1_tx_status_ready equ 0x08
el1_rx_cmd_bcast_good equ 0xa0
el1_tx_cmd_success equ 0x08
el1_aux_system equ 0x00
el1_aux_xmit_recv equ 0x04
el1_aux_receive equ 0x08
el1_aux_reset equ 0x80
el2_ctrl equ 0x406
el2_start_page equ 0x400
el2_stop_page equ 0x401
el2_drq_count equ 0x402
el2_ga_config equ 0x405
el2_status equ 0x407
el2_da_high equ 0x409
el2_da_low equ 0x40a
el2_data equ 0x40e
el2_ctrl_thin equ 0x02
el2_ctrl_saprom equ 0x04
el2_ctrl_dma equ 0x80
el2_ctrl_download equ 0x40
el2_ga_config_norm equ 0x49
el2_status_dprdy equ 0x80
ne_cr equ 0x00
ne_bnry equ 0x03
ne_tsr equ 0x04
ne_tbcr0 equ 0x05
ne_isr equ 0x07
ne_rsar0 equ 0x08
ne_rbcr0 equ 0x0a
ne_tpsr equ 0x04
ne_rcr equ 0x0c
ne_tcr equ 0x0d
ne_dcr equ 0x0e
ne_imr equ 0x0f
ne_data equ 0x10
ne_reset equ 0x1f
ne_cmd_stop_nodma equ 0x21
ne_cmd_start_nodma equ 0x22
ne_cmd_start_page1 equ 0x62
ne_cmd_remote_read equ 0x0a
ne_cmd_remote_write equ 0x12
ne_cmd_transmit equ 0x26
ne_isr_reset equ 0x80
ne_isr_rdc equ 0x40
ne_isr_txe equ 0x08
ne_isr_ptx equ 0x02
ne_dcr_bytewide equ 0x48
ne_read_dma_wait_count equ 0x0800
ne_prom_len equ 32
ne_rx_header_len equ 4
ne_rx_sample_len equ 64
ne_rx_max_count equ 1518
net_frame_buffer_len equ ne_rx_max_count
pcnet_rdp equ 0x10
pcnet_rap equ 0x12
pcnet_reset equ 0x14
pcnet_bdp equ 0x16
pcnet_aprom_hw_isa equ 0x00
pcnet_aprom_hw_pnp equ 0x01
pcnet_aprom_hw_vlb equ 0x10
pcnet_aprom_sig_amd equ 0x5757
pcnet_aprom_sig_racal equ 0x4452
pcnet_csr_init equ 0x0001
pcnet_csr_start equ 0x0002
pcnet_csr_stop equ 0x0004
pcnet_csr_tx_demand equ 0x0008
pcnet_csr_idon equ 0x0100
pcnet_desc_own equ 0x8000
pcnet_desc_stp_enp equ 0x0300
pcnet_desc_err equ 0x4000
pcnet_rx_buf_len equ 1536
pcnet_rx_buf_bcnt equ 0xf000 | ((0 - pcnet_rx_buf_len) & 0x0fff)
; PCnet/LANCE bus-master buffers. PCnet is only valid for later ISA-class
; profiles, so keep the DMA area above Seed's 0x8000 downward-growing stack.
pcnet_dma_base equ 0x8000
pcnet_init_block equ pcnet_dma_base
pcnet_rx_desc equ pcnet_dma_base + 0x20
pcnet_tx_desc equ pcnet_dma_base + 0x28
pcnet_rx_buf equ pcnet_dma_base + 0x100
pcnet_tx_buf equ pcnet_rx_buf + pcnet_rx_buf_len
pcnet_dma_end equ pcnet_tx_buf + net_frame_buffer_len
%if pcnet_dma_end > 0x10000
%error "PCnet DMA workspace must stay below the 64KB real-mode segment ceiling"
%endif
; DEC Tulip PCI bus-master buffers. Tulip is PCI-only and therefore valid only
; on 386+ later-machine profiles; keep the DMA area under 64 KiB so 16-bit
; register writes can program the low physical address with an implicit zero
; high word in 86Box.
tulip_dma_base equ pcnet_dma_base
tulip_rx_desc equ tulip_dma_base
tulip_tx_desc equ tulip_dma_base + 0x10
tulip_rx_buf equ tulip_dma_base + 0x100
tulip_tx_buf equ tulip_rx_buf + pcnet_rx_buf_len
tulip_dma_end equ tulip_tx_buf + net_frame_buffer_len
%if tulip_dma_end > 0x10000
%error "Tulip DMA workspace must stay below the 64KB real-mode segment ceiling"
%endif
; Realtek RTL8139C+ legacy-mode DMA buffers. RTL8139 is PCI-only and uses
; 32-bit I/O registers; the driver emits raw operand-size prefixes for those
; writes while the detection path keeps execution on 386+ PCI machines.
rtl8139_dma_base equ pcnet_dma_base
rtl8139_rx_ring_len equ 8192
rtl8139_rx_buf equ rtl8139_dma_base
rtl8139_tx_buf equ rtl8139_rx_buf + rtl8139_rx_ring_len
rtl8139_dma_end equ rtl8139_tx_buf + net_frame_buffer_len
%if rtl8139_dma_end > 0x10000
%error "RTL8139 DMA workspace must stay below the 64KB real-mode segment ceiling"
%endif
dhcp_rx_frame_len equ 384
ne_rcr_broadcast equ 0x04
ne_rsr_prx equ 0x01
ne_tcr_loopback equ 0x02
ne_tx_start_1k equ 0x20
ne_rx_start_1k equ 0x26
ne_rx_stop_1k equ 0x40
ne_tx_start_2k equ 0x40
ne_rx_start_2k equ 0x46
ne_rx_stop_2k equ 0x80
wd_dp8390_offset equ 0x10
wd_msr_enable_ram equ 0x40
wd_id_extra_ram equ 0x40
wd_id_bus_mca equ 0x80
wd_type_wd8013ebt equ 0x05
wd_type_wd8013ep equ 0x27
wd_ram_segment equ 0xd000
wd_ram_segment_dc00 equ 0xdc00
wd_tx_start equ 0x00
wd_rx_start equ 0x06
wd_rx_stop equ 0x20
wd8013_rx_stop equ 0x40
eth_header_len equ 14
ipv4_header_len equ 20
udp_header_len equ 8
dhcp_fixed_len equ 236
dhcp_options_len equ 26
dhcp_payload_len equ dhcp_fixed_len + dhcp_options_len
dhcp_udp_len equ udp_header_len + dhcp_payload_len
dhcp_ip_len equ ipv4_header_len + dhcp_udp_len
dhcp_frame_len equ eth_header_len + dhcp_ip_len
dhcp_ip_checksum equ 0x79cc
dhcp_bootp_offset equ eth_header_len + ipv4_header_len + udp_header_len
dhcp_yiaddr_offset equ dhcp_bootp_offset + 16
dhcp_chaddr_offset equ dhcp_bootp_offset + 28
dhcp_cookie_offset equ dhcp_bootp_offset + dhcp_fixed_len
dhcp_options_offset equ dhcp_cookie_offset + 4
dhcp_filter_len equ dhcp_bootp_offset + 8
dhcp_offer_wait_count equ 2
dhcp_ack_wait_count equ 2
arp_frame_len equ eth_header_len + 28
arp_tx_frame_len equ 60
arp_payload_offset equ eth_header_len
arp_sha_offset equ arp_payload_offset + 8
arp_spa_offset equ arp_payload_offset + 14
arp_tpa_offset equ arp_payload_offset + 24
arp_wait_count equ 2
dns_qname_default_len equ 13
dns_qname_max_len equ 80
dns_payload_base_len equ 12 + 4
dns_tx_frame_default_len equ eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len + dns_qname_default_len
dns_tx_frame_max_len equ eth_header_len + ipv4_header_len + udp_header_len + dns_payload_base_len + dns_qname_max_len
dns_rx_read_len equ 192
dns_udp_offset equ eth_header_len + ipv4_header_len
dns_payload_offset equ dns_udp_offset + udp_header_len
dns_query_id_word equ 0x4453
dns_wait_count equ 32
tcp_ip_len equ ipv4_header_len + 20
tcp_tx_frame_len equ 60
tcp_rx_read_len equ 96
tcp_offset equ eth_header_len + ipv4_header_len
tcp_payload_offset equ tcp_offset + 20
tcp_payload_max_len equ 1460
tcp_payload_read_len equ tcp_payload_offset + tcp_payload_max_len
; Build 13 3c501 receive safety: advertise an MSS whose complete Ethernet frame fits below the
; response phase at 0x0900 even when a pure ACK is latched ahead of it in the single el1 buffer.
; The TLS receive buffer stays at its 592-byte scratch floor below.
tcp_syn_mss equ 384
; TLS record receive buffer. Post the Build 11 draining-FIFO collapse the receive STREAMS per
; segment (tls.inc:911 "removed the LAST whole-record receive path"): tls_rx_copy holds ONE TCP
; segment, never a whole record, so there is no record-size ceiling - a multi-KB TLS record arrives
; as many <=MSS segments, each decrypted + drained + incrementally MAC'd in turn. The buffer only
; needs to hold one segment, and Seed advertises tcp_syn_mss in its SYN to cap the server's segment
; size to match. 592 is also the floor for tls_rx_copy's other uses: the DNS qname lives at +512, so
; 512 + dns_qname_max_len(80) = 592 (asserted in data.inc via dns_qname), and the ClientHello + DPI
; input both fit. (Pre-collapse this buffer DID hold a whole record and 1460 was the hard floor -
; shrinking to 640 then failed a long essay; the collapse is what made this shrink safe.)
tls_payload_buffer_len equ 592
tls_pre_response_tail_len equ tls_app_record_buffer_len + (16 * 2) + (16 * 2) + tls_random_len + tls_master_secret_len + sha256_digest_len
tls_stream_buffer_len equ tls_payload_buffer_len + tls_pre_response_tail_len
critical_scratch_start equ 0x36c2
critical_scratch_len equ tls_stream_buffer_len
critical_scratch_end equ critical_scratch_start + critical_scratch_len
tcp_port_http_word equ 0x5000
tcp_port_https_word equ 0xbb01
tcp_wait_count equ 4
tcp_wait_count_3c501 equ 128
; Payload waits are BIOS-tick based, not CPU-spin based, so fast 486/Pentium
; profiles get the same server-response window as slow XT/AT profiles.
tcp_payload_wait_count equ 512
; Build 11 slice 2 (SYN retransmit): how many times the connect (re)sends the SYN, waiting
; tcp_wait_count for a SYN-ACK each time, before giving up. A lost SYN or SYN-ACK is then a fast
; in-place resend (the server dedups the duplicate SYN) instead of failing the whole connect. 3
; attempts make the connect robust to a single dropped SYN/SYN-ACK on spotty links.
tcp_syn_retry_count equ 3
; Keep-alive: during a long (~11min) render the connection would otherwise idle past
; Cloudflare's measured ~400s HTTP-idle timeout and be closed, forcing the next prompt to
; reconnect (a handshake that races the ~15s window). Ping the server with a lightweight
; HTTP request this often (BIOS ticks at ~18.2065 Hz) to reset that idle so the next prompt
; REUSES the live session. ~300s gives margin under 400s. ka_request_len is the template
; length (a bare "GET / HTTP/1.1" + Host that 401/421s but keeps the connection alive;
; measured: a partial/CRLF ping does NOT reset the idle and can trigger an early close).
ka_interval_ticks equ 5461
ka_request_len equ 42
; Build 11 ESC: byte length of the int 9 keyboard hook handler staged into the persistent pool at boot
; (hardware_setup, mirroring the keep-alive template). Asserted against the source there.
esc_int9_handler_len equ 86
tls_client_base_len equ 88
tls_body_base_len equ 79
tls_record_base_len equ 83
tls_extensions_base_len equ 36
tls_random_len equ 32
tls_after_random_len equ 7
tls_extensions_prefix_len equ 5
tls_extensions_tail_len equ 22
tls_bulk_aes_128_gcm equ 1
tls_bulk_aes_256_gcm equ 2
tls_bulk_chacha20_poly1305 equ 3
tls_prf_sha256 equ 1
tls_prf_sha384 equ 2
tls_curve_secp256r1 equ 0x0017
tls_ec_coordinate_len equ 32
tls_ec_public_uncompressed_len equ 65
sha256_digest_len equ 32
sha256_block_size equ 64
sha256_k_len equ 256
tls_master_secret_len equ 48
tls_key_block_len equ 88
tls_chacha_key_len equ 32
tls_chacha_iv_len equ 12
tls_prf_seed_max_len equ 77
tls_client_key_exchange_handshake_len equ 1 + tls_ec_public_uncompressed_len
tls_client_key_exchange_record_len equ 4 + tls_client_key_exchange_handshake_len
tls_client_key_exchange_total_len equ 5 + tls_client_key_exchange_record_len
tls_change_cipher_spec_total_len equ 6
tls_finished_verify_len equ 12
tls_finished_plain_len equ 4 + tls_finished_verify_len
tls_finished_cipher_len equ tls_finished_plain_len
tls_finished_record_len equ tls_finished_cipher_len + 16
tls_finished_total_len equ 5 + tls_finished_record_len
tls_aead_aad_len equ 13
tls_record_seq_len equ 8
tls_client_record_seq_len equ tls_record_seq_len
tls_server_record_seq_len equ tls_record_seq_len
tls_record_header_len equ 5
tls_aead_tag_len equ 16
tls_app_max_plain_len equ tcp_payload_max_len - tls_record_header_len - tls_aead_tag_len
; Fixed OpenAI proof request with max 192-byte key and max 64-byte model.
api_request_plain_len equ 440
api_ready_tiny_prompt_max equ 10
api_ready_short_prompt_max equ 24
tls_app_record_buffer_len equ api_request_plain_len + tls_record_header_len + tls_aead_tag_len
api_request_key_value_offset equ 71
api_request_model_value_offset equ 10
chacha_word_count equ 16
chacha_block_len equ 64
poly1305_r_len equ 16
poly1305_s_len equ 16
poly1305_acc_len equ 17
poly1305_product_len equ 36
poly1305_value_len equ 24
p256_word_count equ 16
p256_word_len equ p256_word_count * 2
p256_product_word_count equ p256_word_count * 2
p256_product_word_len equ p256_product_word_count * 2
high_crypto_scratch_start equ 0x3600
high_tls_client_write_key equ high_crypto_scratch_start
high_tls_server_write_key equ high_tls_client_write_key + tls_chacha_key_len
high_tls_client_write_iv equ high_tls_server_write_key + tls_chacha_key_len
high_tls_server_write_iv equ high_tls_client_write_iv + tls_chacha_iv_len
high_tls_client_record_seq equ high_tls_server_write_iv + tls_chacha_iv_len
high_tls_server_record_seq equ high_tls_client_record_seq + tls_client_record_seq_len
high_tls_client_nonce equ high_tls_server_record_seq + tls_server_record_seq_len
high_tls_aead_aad equ high_tls_client_nonce + tls_chacha_iv_len
high_tls_finished_plain equ high_tls_aead_aad + tls_aead_aad_len + 1
high_tls_finished_cipher equ high_tls_finished_plain + tls_finished_plain_len
high_tls_finished_tag equ high_tls_finished_cipher + tls_finished_cipher_len
high_tls_received_tag equ high_tls_finished_tag + tls_aead_tag_len
high_tls_persistent_end equ high_tls_received_tag + tls_aead_tag_len
high_crypto_work equ high_crypto_scratch_start
%if (high_crypto_work + tls_key_block_len) > high_tls_persistent_end
%error "high crypto work overlay exceeds persistent TLS key arena"
%endif
%if (high_crypto_work + (agent_slot_count * 16)) > high_tls_persistent_end
%error "agent id overlay exceeds persistent TLS key arena"
%endif
high_crypto_scratch_end equ high_tls_persistent_end
%if critical_scratch_start != high_crypto_scratch_end
%error "critical scratch must immediately follow high crypto scratch"
%endif
wd_saprom equ 0x08
fat_root_start_lba equ LOADER_SECTORS + 3
fat_fat_start_lba equ LOADER_SECTORS + 1
fat_data_start_lba equ LOADER_SECTORS + 7
fat_root_sectors equ 4
fat_dir_entries_per_sector equ 16
fat_dir_entry_size equ 32
fat_first_data_cluster equ 2
fat_max_cluster equ 300
; Build 12 env save/load (format: docs/memory.md, "ENV.DAT Snapshot Format"): the ENV.DAT snapshot format. The restore
; phase (read) and the save phase (write) share these; tools/env-dat.py is the byte-for-byte
; reference implementation and MUST stay in sync. The header is little-endian; "SEDV" magic stored
; as two words (distinct from the handoff "SEED"). format is the compatibility axis: seed restores
; only when env_format_min <= file.format <= env_format_current.
env_magic_w0 equ 0x4553           ; 'S','E'
env_magic_w1 equ 0x5644           ; 'D','V'
; Format 2 (Build 12): the payload is TRIMMED to skip dead space, so a save fits a floppy and restores
; fast. The arena+window region drops its trailing zeros (store region_stored of region_len). The
; screen snapshot is per-row trailing-blank trimmed: stored as [screen_rows row-length bytes][packed
; used cells]. region_len / screen_cols / screen_rows stay the FULL extents (for the fit check + the
; clear-before-paint). Format 1 (untrimmed) is dropped -- nothing shipped, so min == current == 2.
env_format_current equ 2
env_format_min equ 2
env_hdr_magic equ 0               ; header field offsets (mirror tools/env-dat.py)
env_hdr_format equ 4
env_hdr_flags equ 5
env_hdr_build equ 6
env_hdr_ram_top equ 8
env_hdr_window_cap equ 10         ; chat_context_len_var at save time (context cap at region end)
env_hdr_used equ 12               ; chat_context_used (valid conversation bytes)
env_hdr_note_len equ 14
env_hdr_region_len equ 16         ; FULL arena+window extent from chat_pool_start (fit check + clear)
env_hdr_region_stored equ 18      ; (word) region bytes actually in the file (trailing zeros trimmed)
env_hdr_screen_cols equ 20        ; (byte) screen snapshot width; 0 = no snapshot
env_hdr_screen_rows equ 21        ; (byte) screen snapshot height
env_hdr_screen_stored equ 22      ; (word) encoded screen bytes in the file (row-lengths + packed cells)
env_hdr_payload_checksum equ 24   ; (word) 16-bit sum of the payload (region_stored + screen_stored bytes)
env_hdr_checksum equ 26           ; (word) 16-bit sum of header bytes [0 .. 26)
env_hdr_len equ 28                ; payload: [region_stored region bytes][screen_stored encoded-screen bytes]
; The screen snapshot is the literal video text buffer (char+attr cells) captured at save time and
; painted back verbatim at restore, so the user lands on the EXACT screen they left (dim tool lines,
; prompts, wrapping -- all of it), not a semantic You:/Assistant reconstruction of the model-facing
; window. The window is still restored underneath (for the model); the snapshot is purely for the
; user's eyes. Painted only when the saved screen_cols matches this machine's (else skipped).
; The restore phase stages the whole ENV.DAT file HERE before validating + copying. This is the K
; crypto window base (0x1800), NOT yet loaded during prepare_agent_path (restore runs BEFORE the
; greeting connect that load_core_window's K), so it is ~7 KiB of free scratch (0x1800..0x3600). The
; max-size cap keeps the staged file (header + window + an 80x25 char+attr snapshot ~= 4 KiB) under
; that, and bounds a corrupt/hostile root-dir size before any staging read.
env_restore_stage equ nic_driver_slot_end
env_restore_max_size equ 7168
