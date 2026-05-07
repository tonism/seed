bits 16
cpu 8086
org 0x0700

%include "core/layout.inc"

start:
    call word [phase_svc_probe_ok]
    ret
