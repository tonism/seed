; Component-breakdown build of the observed TLS 1.3 server-flight benchmark.
;
; Emits four run_8088.py-compatible timing lines:
;
;   CHAXOR N=1 dt=<ticks> ck=<hex4>  ; 69 ChaCha blocks + RX copy/XOR
;   POLY   N=1 dt=<ticks> ck=<hex4>  ; 272 Poly blocks + stream shuttle/copy
;   SHAFLT N=1 dt=<ticks> ck=<hex4>  ; 4310-byte SHA + RX copy
;   FLIGHT N=1 dt=<ticks> ck=<hex4>  ; combined workload
;
; The shared source includes the current shipping 8086 ChaCha20, Poly1305, and
; SHA-256 routines verbatim.  FLIGHT_COMPONENTS only selects this alternate
; standalone entry and its additional frozen checks.

%define FLIGHT_COMPONENTS 1
%include "tls13-spike/flight_bench.asm"
