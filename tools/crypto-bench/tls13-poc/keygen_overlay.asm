; Product-shaped ML-KEM-768 KeyGen overlay for the 16 KiB TLS 1.3 PoC.
;
; The implementation is shared with the independently checked arithmetic
; spike, but this wrapper changes its lifetime contract:
;
;   input  d || z       0x3b9c..0x3bdc
;   output ek           0x08c0..0x0d60
;   output sHat/H(ek)/z split through 0x3600..0x3b00
;   work polynomials    final two logical K sectors (K15: 3200..3600,
;                       optional K14: 3000..3400)
;
; The entry returns to a resident phase scheduler.  It performs no BIOS,
; network, filesystem, timing, or benchmark operation.

bits 16
cpu 8086

%include "tools/crypto-bench/tls13-poc/layout.inc"
%define TLS13_POC_OVERLAY 1
%include "tools/crypto-bench/tls13-spike/mlkem768_integrated_keygen.asm"
