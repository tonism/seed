; Fixed product ABI for the K14 state guard.
;
; The guard is deliberately assembled outside core.asm until the product
; dispatcher is wired.  These prefixed constants mirror the canonical
; layout.inc/data.inc symbols without defining or shadowing those symbols.
; tools/check-tls13-k14-state-guard.py resolves the canonical equates and
; fails if any mirrored address drifts.

k14_guard_origin                    equ 0x0700
k14_guard_max_bytes                 equ 1024

k14_guard_mode_pre_cold             equ 0
k14_guard_mode_pre_human            equ 1
k14_guard_mode_post_route           equ 2
k14_guard_mode_abort                equ 3

k14_guard_handoff                   equ 0x0600
k14_guard_handoff_flags             equ k14_guard_handoff + 0x08
k14_guard_handoff_video_mode        equ k14_guard_handoff + 0x0b
k14_guard_handoff_video_cols        equ k14_guard_handoff + 0x0c
k14_guard_handoff_seed_col          equ k14_guard_handoff + 0x0d
k14_guard_handoff_flag_mda          equ 0x0001

k14_guard_bda_video_cols            equ 0x044a
k14_guard_bda_cursor_pos            equ 0x0450
k14_guard_bda_crt_port              equ 0x0463
k14_guard_mda_crt_port              equ 0x03b4
k14_guard_cga_crt_port              equ 0x03d4
k14_guard_mda_video_seg             equ 0xb000
k14_guard_cga_video_seg             equ 0xb800
k14_guard_visible_rows              equ 25
k14_guard_visible_cells             equ 80 * k14_guard_visible_rows
k14_guard_min_cols                  equ 20
k14_guard_max_cols                  equ 80

k14_guard_dpi_prompt_row            equ 24
k14_guard_dpi_prompt_col            equ 0
k14_guard_prompt_col                equ k14_guard_dpi_prompt_col + 2
k14_guard_prompt_max                equ 255

k14_guard_dpi_prompt_marker_row     equ 0x0f33
k14_guard_form_left_col             equ 0x0f38
k14_guard_form_field_col            equ 0x0f39
k14_guard_cursor_row                equ 0x0f55
k14_guard_cursor_col                equ 0x0f56
k14_guard_screen_cols               equ 0x0f57
k14_guard_video_seg                 equ 0x0f58
k14_guard_seed_col                  equ 0x0f5a
k14_guard_seed_attr                 equ 0x0f5b
k14_guard_build_attr                equ 0x0f5c
k14_guard_load_attr                 equ 0x0f5d
k14_guard_crypto_attr               equ 0x0f5e
k14_guard_ready_attr                equ 0x0f5f
k14_guard_question_attr             equ 0x0f60
k14_guard_error_attr                equ 0x0f61
k14_guard_menu_selected_attr        equ 0x0f62
k14_guard_menu_idle_attr            equ 0x0f63
k14_guard_load_marker_char          equ 0x0f64
k14_guard_load_marker_attr          equ 0x0f65
k14_guard_agent_loop_pending        equ 0x0f66
k14_guard_agent_loop_count          equ 0x0f67

k14_guard_low_constants_start       equ 0x0f69
k14_guard_low_constants_end         equ 0x0fe2
k14_guard_low_constants_len         equ \
    k14_guard_low_constants_end - k14_guard_low_constants_start

k14_guard_prompt_len                equ 0x3c9c
k14_guard_scroll_br                 equ 0x3ca9
k14_guard_prompt_valid              equ 0x3cbf
k14_guard_saved_loop_word           equ 0x3cc0
k14_guard_ems_page_count            equ 0x3ce0
k14_guard_far_ctx_base              equ 0x3ce2
k14_guard_prompt_head               equ 0x3ce6
k14_guard_ems_ctx_page              equ k14_guard_prompt_head
k14_guard_ems_ctx_off               equ 0x3ce8
k14_guard_render_last_type          equ 0x3cea
k14_guard_prompt_hole               equ 0x3ceb
k14_guard_tool_fc_state             equ k14_guard_prompt_hole
k14_guard_prompt_tail               equ 0x3cec
k14_guard_reconnect_state_end       equ 0x3de6

k14_guard_prompt_head_len           equ 5
k14_guard_prompt_tail_len           equ \
    k14_guard_prompt_max - k14_guard_prompt_head_len
k14_guard_render_type_user          equ 1
k14_guard_ems_flat_base_hi          equ 0x0010

k14_guard_seed_attr_cga             equ 0x0f
k14_guard_build_attr_cga            equ 0x08
k14_guard_load_attr_cga             equ 0x08
k14_guard_crypto_attr_cga           equ 0x07
k14_guard_ready_attr_cga            equ 0x0f
k14_guard_question_attr_cga         equ 0x0f
k14_guard_error_attr_cga            equ 0x0c
k14_guard_menu_selected_attr_cga    equ 0x0f
k14_guard_menu_idle_attr_cga        equ 0x08

k14_guard_seed_attr_mda             equ 0x0f
k14_guard_build_attr_mda            equ 0x07
k14_guard_load_attr_mda             equ 0x07
k14_guard_crypto_attr_mda           equ 0x07
k14_guard_ready_attr_mda            equ 0x0f
k14_guard_question_attr_mda         equ 0x0f
k14_guard_error_attr_mda            equ 0x0f
k14_guard_menu_selected_attr_mda    equ 0x0f
k14_guard_menu_idle_attr_mda        equ 0x07

%if k14_guard_prompt_head != k14_guard_ems_ctx_page
%error "K14 guard prompt head no longer aliases ems_ctx_page"
%endif
%if k14_guard_prompt_hole != k14_guard_tool_fc_state
%error "K14 guard prompt hole no longer aliases tool_fc_state"
%endif
%if k14_guard_prompt_hole != \
    (k14_guard_prompt_head + k14_guard_prompt_head_len)
%error "K14 guard prompt head does not end at the protected hole"
%endif
%if k14_guard_prompt_tail != (k14_guard_prompt_hole + 1)
%error "K14 guard prompt tail does not begin after the protected hole"
%endif
%if (k14_guard_prompt_tail + k14_guard_prompt_tail_len) != \
    k14_guard_reconnect_state_end
%error "K14 guard prompt scatter no longer covers exactly 255 logical bytes"
%endif
%if k14_guard_prompt_valid >= k14_guard_prompt_head && \
    k14_guard_prompt_valid < k14_guard_reconnect_state_end
%error "K14 guard status aliases the prompt scatter"
%endif
%if k14_guard_saved_loop_word + 2 > k14_guard_ems_page_count
%error "K14 guard saved loop word overlaps later reconnect state"
%endif
%if k14_guard_low_constants_len != 121
%error "K14 guard low-static constant extent drifted"
%endif
%if k14_guard_agent_loop_count != (k14_guard_agent_loop_pending + 1)
%error "K14 guard loop word is no longer contiguous"
%endif
%if k14_guard_menu_idle_attr != (k14_guard_seed_attr + 8)
%error "K14 guard UI attribute band is no longer contiguous"
%endif
