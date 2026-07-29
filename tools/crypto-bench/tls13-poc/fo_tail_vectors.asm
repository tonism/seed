; Oracle-only wrapper for the frozen OpenSSL/FIPS-derived ML-KEM-768 fixture.
; These bytes are never linked into fo_tail_kernel.asm.

bits 16
cpu 8086
org 0

%include "../tls13-spike/mlkem768_integrated_vectors.inc"
