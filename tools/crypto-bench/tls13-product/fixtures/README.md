# Provider authentication fixtures

## Current WE1 capture

`provider_we1_live_*` records a credential-free `api.openai.com:443` capture
on 2026-11-08 at 16:13:27 UTC. A separate capture at 16:59:42 UTC confirmed the
same leaf and issuer. Both passed system-CA, hostname, time, certificate-link
and real P-256 CertificateVerify verification. These are public provenance
checks, not live target acceptance or runtime assistance.

The route selected TLS 1.3, `X25519MLKEM768`,
`TLS_CHACHA20_POLY1305_SHA256` and ALPN `h2`, without certificate compression.
The ordinary Certificate message contains three entries and is 2,504 bytes;
the leaf is 912 bytes, valid from 2026-11-03 03:44:41 UTC through
2027-02-01 04:43:49 UTC.

- Leaf SPKI SHA-256: `ce0265df44be9bacfcf32d6c12a74ffb5b7222e4aec845e44f527a740744657c`.
- Google Trust Services WE1 issuer SPKI SHA-256: `908769e8d34477cc2cba0632c88605b22d7294c0840f78596d247c645b1afc0e`.
- Leaf DER SHA-256: `2270f63dd2b8877cc70781a9744b5da61fd5eacd1f44f00790764a9908249173`.

`auth_p256_check.py` checks this exact-leaf asset and its captured CV.
`check_286_dual_issuer.py` checks both immutable issuer points, executes target
TBS capture and full authentication, and rejects mismatched algorithms,
corrupted evidence and signatures. Captured-flight and real-CV fixtures have
different transcripts; the live VM gate separately proves the full handoff.
The original capture remains under `OPT-030/provider-diagnostic/`; the
independent recheck is under `OPT-031/provenance/` in the campaign evidence.

## Retained YE2 capture

The unchanged `provider_auth_live_*` fixtures were captured from `api.openai.com:443` on
2026-11-02 at 18:46:20 UTC. No credential or application request was sent.
OpenSSL verified the system-CA chain, hostname and current time. Independent
certificate-link verification and P-256 CertificateVerify verification passed.

The capture selected TLS 1.3, `X25519MLKEM768`,
`TLS_CHACHA20_POLY1305_SHA256`, P-256/SHA-256 CertificateVerify and ALPN `h2`,
with certificate compression disabled. The ordinary Certificate handshake is
3,434 bytes and contains four certificates. The leaf is 928 bytes and is valid
from 2026-11-02 14:44:36 UTC through 2027-01-31 14:44:35 UTC.

- Leaf SPKI SHA-256: `6ea3c81fbd1ba27325dfa35f3d518bc1b66076d6e9e74a09a86f5cef92a6d6c2`.
- Let's Encrypt YE2 issuer SPKI SHA-256: `b3fb5d00e994cddf2cc9a4eea9f806bc5727e83cc0e4299bf956f2d524fe5376`.
- Leaf DER SHA-256: `2183dbfa00cf35f985ddac7c2fd171d60a94a4891eba41d65fb27b505bf86e40`.

The vector records the captured transcript digest and real CertificateVerify
signature.
`check_issuer_p384.py` checks the immutable issuer point against the fixture and
executes the target SHA-384/P-384 implementation against independent oracles.
`check_286_auth.py` executes the full target offline authentication path.

The complete credential-free capture, OpenSSL verification log and source
hashes are retained under `build/optimization-campaign/OPT-028/provenance/`.
Earlier WE1 research fixtures are separate and remain unchanged. None of
these certificate files is packaged on the floppy or read by the runtime.
