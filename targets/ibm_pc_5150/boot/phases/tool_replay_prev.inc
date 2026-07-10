%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif
%ifndef PHASE_LOAD_ADDR
%error "PHASE_LOAD_ADDR must name the runtime load address"
%endif

%macro phase_call_stream 1
    db 0xe8
    dw (net_setup_phase_start + (%1 - core_agent_api_stream_phase_start)) - (PHASE_LOAD_ADDR + ($ - PHASE_BASE) + 2)
%endmacro

tool_replay_prev_phase:
    push ds
    pop es
    cld
    mov si, net_setup_phase_start + (api_fc_call_open_text - core_agent_api_stream_phase_start)
    phase_call_stream agent_api_stream_append_z_to_buffer
    call .append_call_id
    mov si, net_setup_phase_start + (api_fc_name_mid_text - core_agent_api_stream_phase_start)
    phase_call_stream agent_api_stream_append_z_to_buffer
    call .append_name
    mov si, net_setup_phase_start + (api_fc_args_mid_text - core_agent_api_stream_phase_start)
    phase_call_stream agent_api_stream_append_z_to_buffer
    mov al, '}'
    stosb
    mov si, net_setup_phase_start + (api_fc_output_open_text - core_agent_api_stream_phase_start)
    phase_call_stream agent_api_stream_append_z_to_buffer
    call .append_call_id
    mov si, net_setup_phase_start + (api_fc_output_mid_text - core_agent_api_stream_phase_start)
    phase_call_stream agent_api_stream_append_z_to_buffer
    mov si, fc_prev_output
    mov cl, [fc_capture_len]
    call .append_counted
    clc
    ret
.append_call_id:
    mov si, fc_prev_call_id
    mov cl, [fc_match_state]
.append_counted:
    xor ch, ch
    rep movsb
    ret
.append_name:
    mov al, [fc_prev_name_code]
    cmp al, 'r'
    je .name_read
    cmp al, 'w'
    je .name_write
    cmp al, 'e'
    je .name_exec
    cmp al, 's'
    je .name_save
    mov si, PHASE_LOAD_ADDR + (.name_load - PHASE_BASE)
    jmp .name_emit
.name_read:
    mov si, PHASE_LOAD_ADDR + (.name_read_text - PHASE_BASE)
    jmp .name_emit
.name_write:
    mov si, PHASE_LOAD_ADDR + (.name_write_text - PHASE_BASE)
    jmp .name_emit
.name_exec:
    mov si, PHASE_LOAD_ADDR + (.name_exec_text - PHASE_BASE)
    jmp .name_emit
.name_save:
    mov si, PHASE_LOAD_ADDR + (.name_save_text - PHASE_BASE)
.name_emit:
    phase_call_stream agent_api_stream_append_z_to_buffer
    ret

.name_read_text db 'read_mem', 0
.name_write_text db 'write_mem', 0
.name_exec_text db 'exec', 0
.name_save_text db 'save_env', 0
.name_load db 'load_env', 0

%unmacro phase_call_stream 1
