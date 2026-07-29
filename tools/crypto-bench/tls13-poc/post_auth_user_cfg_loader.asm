; Fixed, read-only USER.CFG credential/model loader for the post-auth PoC.
;
; The standalone checker keeps the historical 0x0520 origin. The live
; composition relocates this cold body to 0x0900..0x0cff after RSU1 retires,
; so the immutable 0x0500 callback page cannot overwrite the live handoff and
; NIC/TCP state at 0x0600..0x08b6. Its entry address remains build-fixed:
; caller registers do not select an authorization phase, disk address,
; destination, or route.
;
; The callback calls one compile-time full-authorization entry before touching
; disk.  Its sole INT 13h wrapper repeats that authorization immediately before
; every permitted AH=00 reset or AH=02 one-sector read, then reconstructs all
; BIOS arguments from immutable build geometry.  The raw sector, temporary
; key/model fields, and every partial PAK1 publication are scrubbed on failure.
;
; Entry ABI (near call, DS=ES=SS=0):
;   USER_CFG_LOADER_ORIGIN user_cfg_loader_callback
; Success: CF=0, AX=1, fixed status-last PAK1 at 0x0d00.
; Failure: CF=1, AX=0, raw/temp/publication plaintext clear.

bits 16
cpu 8086

%ifndef USER_CFG_FULL_AUTHORIZE_ENTRY
%error "USER_CFG_FULL_AUTHORIZE_ENTRY is required"
%endif
%ifndef USER_CFG_LOADER_ORIGIN
%define USER_CFG_LOADER_ORIGIN 0x0520
%endif
%ifndef USER_CFG_LOADER_LIMIT
%define USER_CFG_LOADER_LIMIT 0x0900
%endif
%ifndef USER_CFG_AUTH_GENERATION_ADDR
%define USER_CFG_AUTH_GENERATION_ADDR 0x3c30
%endif
%ifndef USER_CFG_ABSOLUTE_LBA
%error "builder-resolved USER_CFG_ABSOLUTE_LBA is required"
%endif
%ifndef USER_CFG_FILE_SIZE
%error "builder-resolved USER_CFG_FILE_SIZE is required"
%endif
%ifndef USER_CFG_CLUSTER_COUNT
%error "builder-resolved USER_CFG_CLUSTER_COUNT is required"
%endif
%ifndef USER_CFG_SECTORS_PER_TRACK
%error "builder media geometry is required"
%endif
%ifndef USER_CFG_HEAD_COUNT
%error "builder media geometry is required"
%endif
%ifndef USER_CFG_DRIVE
%define USER_CFG_DRIVE 0
%endif

org USER_CFG_LOADER_ORIGIN

%assign user_cfg_cylinder \
    USER_CFG_ABSOLUTE_LBA / \
    (USER_CFG_SECTORS_PER_TRACK * USER_CFG_HEAD_COUNT)
%assign user_cfg_track_remainder \
    USER_CFG_ABSOLUTE_LBA % \
    (USER_CFG_SECTORS_PER_TRACK * USER_CFG_HEAD_COUNT)
%assign user_cfg_head \
    user_cfg_track_remainder / USER_CFG_SECTORS_PER_TRACK
%assign user_cfg_sector \
    (user_cfg_track_remainder % USER_CFG_SECTORS_PER_TRACK) + 1
%assign user_cfg_chs_cx \
    ((user_cfg_cylinder & 0xff) << 8) | \
    (user_cfg_sector | ((user_cfg_cylinder >> 2) & 0xc0))
%assign user_cfg_chs_dx ((user_cfg_head & 0xff) << 8) | USER_CFG_DRIVE

user_cfg_loader_callback:
    jmp loader_main

loader_header:
    db 'UCL1'
    dw 1
    dw loader_end - user_cfg_loader_callback
    dw user_cfg_loader_callback
    dw checked_int13
loader_layout:
    dw USER_CFG_ABSOLUTE_LBA
loader_file_size:
    dw USER_CFG_FILE_SIZE
loader_cluster_count:
    dw USER_CFG_CLUSTER_COUNT
    dw USER_CFG_SECTORS_PER_TRACK
    dw USER_CFG_HEAD_COUNT
    dw user_cfg_cylinder
    db user_cfg_head
    db user_cfg_sector
    db USER_CFG_DRIVE
    db 0

raw_sector                 equ 0x0e00
raw_sector_end             equ 0x1000

publication_start          equ 0x0d00
publication_status         equ publication_start
publication_reserved       equ publication_status + 1
publication_magic          equ publication_reserved + 1
publication_magic_inverse  equ publication_magic + 4
publication_generation     equ publication_magic_inverse + 4
publication_route          equ publication_generation + 2
publication_route_inverse  equ publication_route + 1
publication_key_len        equ publication_route_inverse + 1
publication_key            equ publication_key_len + 2
publication_key_max        equ 192
publication_key_end        equ publication_key + publication_key_max + 1
publication_model_len      equ publication_key_end
publication_model          equ publication_model_len + 2
publication_model_max      equ 64
publication_model_end      equ publication_model + publication_model_max + 1
publication_checksum_a     equ publication_model_end
publication_checksum_b     equ publication_checksum_a + 2
publication_end            equ publication_checksum_b + 2
publication_check_start    equ publication_generation
publication_check_len      equ publication_checksum_a - publication_check_start

; ROG4 occupies the exact two-sector 0x1800..0x1c00 phase while UCL1 runs.
; Its retired HELLO tail above 0x1c00 is safe temporary plaintext space. The
; loader scrubs it before return; the supervisor then reuses it only to stage
; the credential-free request callback page. Never use 0x3600 here: that is
; the durable LP1/WE1 issuer object required by the next ROG4 authorization.
temp_key_len               equ 0x1c00
temp_key                   equ temp_key_len + 2
temp_key_end               equ temp_key + publication_key_max + 1
temp_model_len             equ temp_key_end
temp_model                 equ temp_model_len + 2
temp_model_end             equ temp_model + publication_model_max + 1

int13_total_count          equ 0x3c62
int13_read_count           equ int13_total_count + 2
int13_reset_count          equ int13_read_count + 2
int13_denied_count         equ int13_reset_count + 2
authorize_count            equ int13_denied_count + 2
parse_flags                equ authorize_count + 2
parse_line_len             equ parse_flags + 1
parse_line_start           equ parse_line_len + 2
loader_state_end           equ parse_line_start + 2

parse_flag_model           equ 0x01
parse_flag_key             equ 0x02
parse_flag_agent           equ 0x04

loader_main:
    cld
    call clear_publication
    call clear_loader_state
    call invoke_full_authorize
    jc loader_failed
    call validate_layout
    jc loader_failed

    mov ax, 0x0201
    call checked_int13
    jnc .sector_ready
    xor ax, ax
    call checked_int13
    jc loader_failed
    mov ax, 0x0201
    call checked_int13
    jc loader_failed

.sector_ready:
    ; The final disk operation has revalidated the still-intact auth object.
    ; It is now safe to retire that object into bounded parse destinations.
    call clear_temporary
    call parse_config
    jc loader_failed
    call clear_raw_sector
    call build_publication
    jc loader_failed
    call clear_temporary
    call clear_parse_state
    mov byte [publication_status], 1       ; atomic publication, always last
    mov ax, 1
    clc
    ret

loader_failed:
    call scrub_sensitive
    xor ax, ax
    stc
    ret

validate_layout:
    cmp word [loader_cluster_count], 1
    jne .failed
    mov ax, [loader_file_size]
    or ax, ax
    jz .failed
    cmp ax, 512
    ja .failed
    clc
    ret
.failed:
    stc
    ret

; This is the only path to INT 13h. Requested AX survives the no-argument full
; authorization call, then the wrapper accepts only 0000h or 0201h and rebuilds
; every other BIOS register from compile-time geometry.
checked_int13:
    push ax
    call invoke_full_authorize
    pop ax
    jc .denied
    or ax, ax
    jz .reset
    cmp ax, 0x0201
    jne .denied
    inc word [int13_read_count]
    mov ax, 0x0201
    mov bx, raw_sector
    mov cx, user_cfg_chs_cx
    mov dx, user_cfg_chs_dx
    push ds
    pop es
    jmp short .perform
.reset:
    inc word [int13_reset_count]
    xor ax, ax
    xor bx, bx
    xor cx, cx
    mov dx, USER_CFG_DRIVE
.perform:
    inc word [int13_total_count]
    int 0x13
    cld
    ret
.denied:
    inc word [int13_denied_count]
    stc
    ret

invoke_full_authorize:
    inc word [authorize_count]
    xor ax, ax
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    call USER_CFG_FULL_AUTHORIZE_ENTRY
    jc .failed
    cmp ax, 1
    jne .failed
    clc
    ret
.failed:
    stc
    ret

parse_config:
    push ds
    pop es
    mov si, raw_sector
    mov dx, [loader_file_size]
    mov [parse_line_start], si
    mov word [parse_line_len], 0
.next:
    or dx, dx
    jz .eof
    lodsb
    dec dx
    or al, al
    jz .failed
    cmp al, 13
    je .cr
    cmp al, 10
    je .line_end
    cmp al, 0x20
    jb .failed
    cmp al, 0x7e
    ja .failed
    inc word [parse_line_len]
    jmp short .next
.cr:
    or dx, dx
    jz .failed
    cmp byte [si], 10
    jne .failed
    inc si
    dec dx
.line_end:
    push si
    call parse_current_line
    pop si
    jc .failed
    mov [parse_line_start], si
    mov word [parse_line_len], 0
    jmp short .next
.eof:
    cmp word [parse_line_len], 0
    jne .failed                         ; declared bytes ended mid-line
    mov al, [parse_flags]
    and al, parse_flag_model | parse_flag_key
    cmp al, parse_flag_model | parse_flag_key
    jne .failed
    clc
    ret
.failed:
    stc
    ret

parse_current_line:
    mov cx, [parse_line_len]
    or cx, cx
    jz .ignored
    mov si, [parse_line_start]
    mov di, model_prefix
    mov bx, model_prefix_len
    call match_prefix
    jnc .model
    mov di, key_prefix
    mov bx, key_prefix_len
    call match_prefix
    jnc .key
    mov di, agent_prefix
    mov bx, agent_prefix_len
    call match_prefix
    jnc .agent
.ignored:
    clc
    ret

.model:
    test byte [parse_flags], parse_flag_model
    jnz .failed
    sub cx, model_prefix_len
    or cx, cx
    jz .failed
    cmp cx, publication_model_max
    ja .failed
    mov [temp_model_len], cx
    add si, model_prefix_len
    mov di, temp_model
.model_byte:
    lodsb
    call model_char
    jc .failed
    stosb
    loop .model_byte
    mov byte [di], 0
    or byte [parse_flags], parse_flag_model
    clc
    ret

.key:
    test byte [parse_flags], parse_flag_key
    jnz .failed
    sub cx, key_prefix_len
    or cx, cx
    jz .failed
    cmp cx, publication_key_max
    ja .failed
    mov [temp_key_len], cx
    add si, key_prefix_len
    mov di, temp_key
.key_byte:
    lodsb
    cmp al, 0x21
    jb .failed
    cmp al, 0x7e
    ja .failed
    stosb
    loop .key_byte
    mov byte [di], 0
    or byte [parse_flags], parse_flag_key
    clc
    ret

.agent:
    test byte [parse_flags], parse_flag_agent
    jnz .failed
    cmp cx, agent_prefix_len + openai_value_len
    jne .failed
    add si, agent_prefix_len
    mov di, openai_value
    mov cx, openai_value_len
    repe cmpsb
    jne .failed
    or byte [parse_flags], parse_flag_agent
    clc
    ret
.failed:
    stc
    ret

; Match BX prefix bytes at SI without consuming the caller's SI/CX.
match_prefix:
    push si
    push cx
    push di
    push bx
    cmp cx, bx
    jb .no
    mov cx, bx
    repe cmpsb
    jne .no
    clc
    jmp short .done
.no:
    stc
.done:
    pop bx
    pop di
    pop cx
    pop si
    ret

model_char:
    cmp al, '0'
    jb .punct
    cmp al, '9'
    jbe .good
    cmp al, 'A'
    jb .punct
    cmp al, 'Z'
    jbe .good
    cmp al, 'a'
    jb .punct
    cmp al, 'z'
    jbe .good
.punct:
    cmp al, '-'
    je .good
    cmp al, '.'
    je .good
    cmp al, ':'
    je .good
    cmp al, '_'
    jne .bad
.good:
    clc
    ret
.bad:
    stc
    ret

build_publication:
    call clear_publication
    mov word [publication_magic], 0x4150
    mov word [publication_magic + 2], 0x314b
    mov word [publication_magic_inverse], 0xbeaf
    mov word [publication_magic_inverse + 2], 0xceb4
    mov ax, [USER_CFG_AUTH_GENERATION_ADDR]
    or ax, ax
    jz .failed
    mov [publication_generation], ax
    mov byte [publication_route], 1
    mov byte [publication_route_inverse], 0xfe

    mov ax, [temp_key_len]
    mov [publication_key_len], ax
    mov cx, ax
    mov si, temp_key
    mov di, publication_key
    rep movsb
    mov byte [di], 0

    mov ax, [temp_model_len]
    mov [publication_model_len], ax
    mov cx, ax
    mov si, temp_model
    mov di, publication_model
    rep movsb
    mov byte [di], 0

    mov si, publication_check_start
    mov cx, publication_check_len
    call publication_checksum
    mov [publication_checksum_a], ax
    mov [publication_checksum_b], dx
    clc
    ret
.failed:
    stc
    ret

publication_checksum:
    push bx
    mov ax, 0x6d5a
    mov dx, 0xb481
.byte:
    xor bx, bx
    mov bl, [si]
    inc si
    add ax, bx
    rol ax, 1
    xor dx, ax
    add dx, 0x9e37
    rol dx, 1
    loop .byte
    pop bx
    ret

clear_loader_state:
    push ds
    pop es
    xor ax, ax
    mov di, int13_total_count
    mov cx, loader_state_end - int13_total_count
    rep stosb
    ret

clear_parse_state:
    push ds
    pop es
    xor ax, ax
    mov di, parse_flags
    mov cx, loader_state_end - parse_flags
    rep stosb
    ret

clear_publication:
    push ds
    pop es
    xor ax, ax
    mov di, publication_start
    mov cx, publication_end - publication_start
    rep stosb
    ret

clear_raw_sector:
    push ds
    pop es
    xor ax, ax
    mov di, raw_sector
    mov cx, raw_sector_end - raw_sector
    rep stosb
    ret

clear_temporary:
    push ds
    pop es
    xor ax, ax
    mov di, temp_key_len
    mov cx, temp_model_end - temp_key_len
    rep stosb
    ret

scrub_sensitive:
    call clear_publication
    call clear_raw_sector
    call clear_temporary
    call clear_parse_state
    ret

model_prefix db 'model '
model_prefix_len equ $ - model_prefix
key_prefix db 'key '
key_prefix_len equ $ - key_prefix
agent_prefix db 'agent '
agent_prefix_len equ $ - agent_prefix
openai_value db 'openai'
openai_value_len equ $ - openai_value

loader_end:

%if ($ - $$) > (USER_CFG_LOADER_LIMIT - USER_CFG_LOADER_ORIGIN)
%error "post-auth USER.CFG loader exceeds its fixed cold slot"
%endif
%if publication_end > raw_sector + 32
%error "PAK1/raw overlap exceeds the intentional first 32 raw bytes"
%endif
%if temp_model_end > 0x1e00
%error "USER.CFG temporary fields exceed retired HELLO staging space"
%endif
%if loader_state_end > 0x3c9c
%error "USER.CFG loader state reaches reconnect scratch"
%endif
%if user_cfg_cylinder > 1023
%error "USER.CFG CHS cylinder exceeds INT 13h encoding"
%endif
%if user_cfg_sector < 1 || user_cfg_sector > 63
%error "USER.CFG CHS sector is invalid"
%endif
