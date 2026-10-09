%include "h2-helper-crc.inc"
flight_h2_load:
    mov ax,0x01a4
    mov bx,0x5500
    call TLS13_286_LINK_LOAD_CORE_SECTORS_AT
    jc .bad
    mov si,0x5500
    mov dx,H2_HELPER_BYTES
    call flight_crc16
    cmp ax,H2_HELPER_CRC
    jne .bad
    jmp word [0x5500]
.bad:
    stc
    ret
flight_post_h2_bytes:
    jmp word [0x5502]
flight_h2_ready:
    jmp word [0x5504]
flight_h2_publish:
    jmp word [0x5506]
flight_h2_send:
    jcxz .done
    cmp cx, 436                     ; complete TLS/TCP frame fits NIC scratch
    ja .bad
    mov word [FLIGHT_SYM_RECORD_KEY_PTR], TLS13_286_FLIGHT_SYM_CLIENT_APP_KEY
    mov word [FLIGHT_SYM_RECORD_IV_PTR], TLS13_286_FLIGHT_SYM_CLIENT_APP_IV
    mov word [FLIGHT_SYM_RECORD_SEQ_PTR], TLS13_286_FLIGHT_SYM_CLIENT_APP_SEQ
    mov al, 0x17
    call FLIGHT_SYM_SEAL_RECORD
    jc .return
    jmp flight_send_sym_io
.bad:
    stc
    ret
.done:
    clc
.return:
    ret

flight_h2_preface:
    db 'PRI * HTTP/2.0',13,10,13,10,'SM',13,10,13,10
    db 0,0,24,4,0,0,0,0,0
    db 0,1,0,0,0,0
    db 0,2,0,0,0,0
    db 0,4,0,0,0,0
    db 0,6,0,0,0x10,0
flight_h2_preface_end:
