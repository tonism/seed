; Component-breakdown build for the Brotli-compressed compact ECDSA flight.
;
; Emits CHAXOR, POLY, SHAFLT, and FLIGHT timing lines with the frozen
; 1942/1926/1925-byte record geometry and deterministic checks.

%define FLIGHT_PROFILE_CERTCOMP 1
%define FLIGHT_COMPONENTS 1
%include "tls13-spike/flight_bench.asm"
