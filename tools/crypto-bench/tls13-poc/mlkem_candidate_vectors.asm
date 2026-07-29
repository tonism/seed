; Deterministic oracle-only wrapper for the frozen OpenSSL/FIPS-derived
; ML-KEM-768 fixture.  This file is assembled only by mlkem_candidate_check.py;
; none of these bytes are linked into the product-shaped candidate overlay.

bits 16
cpu 8086
org 0

%include "../tls13-spike/mlkem768_integrated_vectors.inc"
