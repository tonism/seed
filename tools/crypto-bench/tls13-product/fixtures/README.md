# Current provider authentication fixture

These public fixtures were captured from `api.openai.com:443` on
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
signature. `auth_p256_check.py` independently checks the leaf, hostname,
purpose, capture-time validity, exact pin and CertificateVerify.
`check_issuer_p384.py` checks the immutable issuer point against the fixture and
executes the target SHA-384/P-384 implementation against independent oracles.
`check_286_auth.py` executes the full target offline authentication path.

The complete credential-free capture, OpenSSL verification log and source
hashes are retained under `build/optimization-campaign/OPT-028/provenance/`.
Historical WE1 research fixtures are separate and remain unchanged. None of
these certificate files is packaged on the floppy or read by the runtime.
