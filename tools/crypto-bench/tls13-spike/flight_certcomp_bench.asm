; Full symmetric-work benchmark for OpenAI's compact ECDSA TLS 1.3 flight
; when RFC 8879 Brotli certificate compression is negotiated.
;
; Live-observed geometry:
;   outer record payload 1942, ciphertext/inner 1926, transcript 1925
;   6 receive chunks at Seed's 384-byte MSS
;   32 ChaCha blocks including OTK, 123 Poly blocks, 31 SHA blocks
;   CompressedCertificate handshake 1799 bytes (2491-byte decoded body)

%define FLIGHT_PROFILE_CERTCOMP 1
%include "tls13-spike/flight_bench.asm"
