; Product-owned flat-pack root for the validated 8088/K14 TLS 1.3 phases.
;
; The RAM-only product builder generates the include named by
; TLS13_PRODUCT_GENERATED_INCLUDE from independently assembled and checked
; conventional-RAM phases, then assembles this wrapper and byte-compares the
; complete flat pack with its phase ledger.
;
; This is source organization only.  The eventual product integration includes
; these phases in the one flat SEED.SYS image; it does not load a new runtime
; module or define a module ABI.

bits 16
cpu 8086
org 0

%ifndef TLS13_PRODUCT_GENERATED_INCLUDE
%error "define TLS13_PRODUCT_GENERATED_INCLUDE to the generated phase include"
%endif

tls13_product_k14_pack_start:
%include TLS13_PRODUCT_GENERATED_INCLUDE
tls13_product_k14_pack_end:

%if (tls13_product_k14_pack_end - tls13_product_k14_pack_start) % 512
%error "TLS 1.3 K14 product phase pack is not sector aligned"
%endif
