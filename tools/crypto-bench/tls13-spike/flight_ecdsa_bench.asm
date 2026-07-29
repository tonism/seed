; Full symmetric-work benchmark for the compact pre-286 OpenAI TLS 1.3 flight.
;
; Live-observed geometry:
;   outer record payload 2638, ciphertext/inner 2622, transcript 2621
;   7 receive chunks at Seed's 384-byte MSS
;   42 ChaCha blocks including OTK, 166 Poly blocks, 42 SHA blocks
;   leaf DER 903 bytes; CertificateVerify handshake 80 bytes

%define FLIGHT_PROFILE_ECDSA 1
%include "tls13-spike/flight_bench.asm"
