; Component-breakdown build for the compact pre-286 OpenAI TLS 1.3 flight.
;
; Emits CHAXOR, POLY, SHAFLT, and FLIGHT timing lines with the ECDSA profile's
; frozen 2638/2622/2621-byte record geometry and deterministic checks.

%define FLIGHT_PROFILE_ECDSA 1
%define FLIGHT_COMPONENTS 1
%include "tls13-spike/flight_bench.asm"
