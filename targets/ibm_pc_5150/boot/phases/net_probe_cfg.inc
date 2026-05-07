%ifndef PHASE_BASE
%error "PHASE_BASE must name the containing phase start label"
%endif

%macro phase_call_res 1
    db 0xe8
    dw %1 - (low_scratch_start + ($ - PHASE_BASE) + 2)
%endmacro

net_probe_cfg_phase:
    mov di, net_cfg_name
    phase_call_res find_root_file
    jc .failed
    cmp word [fs_file_size_high], 0
    jne .failed
    cmp word [fs_file_size_low], 7
    jb .failed
    mov ax, [fs_file_cluster]
    phase_call_res read_cluster_to_buffer
    jc .failed
    mov si, fs_sector_buffer
    mov cx, [fs_file_size_low]
    cmp cx, 512
    jbe .size_ready
    mov cx, 512
.size_ready:
    mov byte [fs_line_start], 1
.next_byte:
    cmp cx, 0
    je .failed
    cmp byte [fs_line_start], 1
    jne .consume
    cmp cx, 6
    jb .consume
    cmp byte [si], 'p'
    jne .consume
    cmp byte [si + 1], 'r'
    jne .consume
    cmp byte [si + 2], 'o'
    jne .consume
    cmp byte [si + 3], 'b'
    jne .consume
    cmp byte [si + 4], 'e'
    jne .consume
    cmp byte [si + 5], ' '
    jne .consume
    add si, 6
    sub cx, 6
    mov di, seed_endpoint
    mov dl, seed_endpoint_len
    phase_call_res copy_line_value
    cmp byte [seed_endpoint], 0
    je .failed
    mov si, seed_endpoint
    phase_call_res set_dns_target_from_text
    ret
.consume:
    lodsb
    dec cx
    cmp al, 13
    je .line_start
    cmp al, 10
    je .line_start
    mov byte [fs_line_start], 0
    jmp .next_byte
.line_start:
    mov byte [fs_line_start], 1
    jmp .next_byte
.failed:
    stc
    ret

%unmacro phase_call_res 1
