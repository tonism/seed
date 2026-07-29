; Narrow K14 adapter for sealing caller-supplied client application data.
;
; Load this cold sector at 0x3400 after the symmetric image has been restored
; at 0x1800.  The sector may clear 0x3510..0x35ff while loading: those bytes
; are symmetric runtime state, not retained secrets, and are initialized by
; the calls below.  Retained client/server application keys and sequences live
; at 0x3838..0x38ef and are never part of this image.
;
; Entry ABI (near call, DS=ES=SS=0, DF clear):
;   SI=content, CX=1..383
;   success: CF=0, AX=complete TLS record bytes at 0x39a0
;   failure: CF=1

bits 16
cpu 8086
org 0x3400

%ifndef POST_AUTH_SYM_SEAL_RECORD
%error "POST_AUTH_SYM_SEAL_RECORD must name sym_seal_record"
%endif
%ifndef POST_AUTH_RESPONSE_LOAD_PHASE
%error "post-auth adapter requires the resident response phase loader"
%endif

adapter_header:
    db 'PAS1'
    dw 1
    dw adapter_end - adapter_header
    dw adapter_seal_client_application

sym_record_key_ptr equ 0x3510
sym_record_iv_ptr  equ 0x3512
sym_record_seq_ptr equ 0x3514
sym_client_app_key equ 0x3838
sym_client_app_iv  equ 0x3858
sym_client_app_seq equ 0x38e0

adapter_seal_client_application:
    or cx, cx
    jz .failed
    cmp cx, 383
    ja .failed
    mov word [sym_record_key_ptr], sym_client_app_key
    mov word [sym_record_iv_ptr], sym_client_app_iv
    mov word [sym_record_seq_ptr], sym_client_app_seq
    mov al, 0x17
    jmp POST_AUTH_SYM_SEAL_RECORD
.failed:
    stc
    ret

; Immutable request literals consume the remainder of this cold phase's
; executable-safe 0x3400..0x350f prefix.  The low controller is compiled with
; these source-derived addresses and lengths.
adapter_request_prefix:
    db 'POST /v1/responses HTTP/1.1',13,10
    db 'Host: api.openai.com',13,10
    db 'Authorization: Bearer '
adapter_request_prefix_len equ $ - adapter_request_prefix
adapter_request_after_key:
    db 13,10,'Content-Type: application/json',13,10
    db 'Content-Length: '
adapter_request_after_key_len equ $ - adapter_request_after_key
adapter_request_header_end db 13,10,13,10
adapter_request_header_end_len equ $ - adapter_request_header_end
adapter_request_body_prefix db '{"model":"'
adapter_request_body_prefix_len equ $ - adapter_request_body_prefix
adapter_request_body_suffix:
    db '","input":"Reply exactly ok.","stream":true}'
adapter_request_body_suffix_len equ $ - adapter_request_body_suffix

; Request sealing leaves this executable-safe prefix intact. The supervisor
; uses this tail exactly once to stage the response literals outside 0x3400,
; then overwrites the complete request adapter with that response phase.
post_auth_live_response_stage_adapter:
    mov bx, 0x0d00
    jmp POST_AUTH_RESPONSE_LOAD_PHASE

adapter_end:

%if (adapter_end - adapter_header) > (0x3510 - 0x3400)
%error "post-auth symmetric adapter reaches K14 runtime state"
%endif
