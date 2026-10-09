; The authenticated HTTP/2 response owner is loaded before X returns.
agent_api_exchange:
    jmp word [0x2a00]
; HTTP/2 flow credit/control replaces HTTP/1 keep-alive requests. T's old
; call is removed; keep the symbol only for source compatibility.
agent_api_keepalive equ h2_tx_control.done
ka_last_tick dw 0
ka_sent_count db 0
%include "core/h2_tx_credit.inc"
