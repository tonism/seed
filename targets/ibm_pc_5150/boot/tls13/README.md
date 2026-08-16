# TLS 1.3 product phase packs

This directory owns the TLS 1.3 code linked into the single flat product
`SEED.SYS`. TLS 1.2 is no longer a product fallback. One runtime detects the
machine and selects one of two OpenAI-only routes:

| Floor | Route | Claim |
| --- | --- | --- |
| 4.77 MHz 8088, 16 KiB | streamed K14 schedule, ChaCha20-Poly1305/SHA-256 and ML-KEM-768 contribution | TLS 1.3 wire protocol with the bounded Seed boundary described below; not standards-conforming hybrid TLS |
| 6 MHz 286, 512 KiB | authenticated acquisition plus no-0RTT PSK-DHE resumption with independent full `X25519MLKEM768` | fully standards-conforming final credential-bearing TLS 1.3 path |

Both paths are integrated in the product source and are currently
**integration-under-validation**. Current-source offline gates establish the
byte layouts, ABIs, fail-closed transitions, and cryptographic known-answer
behavior; both exact-floor live routes pass, and the 8088 profile passes
the seven-profile original-speed matrix. Physical entropy characterization and
additional provider-edge repetition remain before either profile is described as
product-validated.

## 8088 security boundary

The 8088 ClientHello uses the `X25519MLKEM768` wire identifier, but fixes the
X25519 public value to `u=9`; it therefore has no genuine classical X25519
contribution. Its effective key exchange is ML-KEM-only. To fit the provider's
observed connection deadline, the route may send client Finished and only
literal, credential-free liveness probes after provisional decapsulation. It
does **not** make the API key or a business request reachable until the same
machine has completed full Fujisaki-Okamoto validation, exact dated leaf
possession/CertificateVerify validation, and status-last capability
publication.

The exact leaf's issuer, hostname, purpose, and validity interval are trusted
image-generation provenance. The 8088 does not yet have a trusted runtime
clock, so image expiry is an explicit operational limit rather than a target
date check.

That is a deliberately narrow Seed security boundary. It must not be called a
standards-conforming `X25519MLKEM768` handshake, a FIPS-conforming hybrid, or
equivalent to the 286 profile.

The K14 code is cold-loaded in phases. Its public objects live temporarily in
the video-RAM vault documented in
[`PUBLIC_VAULT_16K.md`](PUBLIC_VAULT_16K.md); no writable floppy and no NIC RAM
are required. Private material is retired on every success and failure path.

## 286 conforming boundary

The 286 route uses three ordered stages:

```text
acquisition
  candidate ML-KEM + real X25519
  authenticated protected flight and server Finished
  client Finished + immutable credential-free HEAD
  authenticated HTTP response + tentative NewSessionTicket

offline authority
  complete ML-KEM FO decapsulation and constant-time candidate comparison
  strict WE1 / api.openai.com / purpose / UTC-validity / CertificateVerify
  generate P-256 tables and promote the same-boot ticket status-last

final credential connection
  consume the promoted ticket before reading its PSK/identity
  independent ML-KEM + X25519 keys and a real PSK binder
  no early_data; require selected_identity=0
  full decapsulation before a strict EncryptedExtensions-to-Finished flight
  verify server Finished, send client Finished, then publish credentials
```

The acquisition candidate can authorize only the fixed credential-free HEAD
and tentative ticket capture. It cannot expose the API key or business
request. The final channel is standards-conforming no-0RTT PSK-DHE resumption:
the authenticated same-boot ticket is combined with a fresh genuine
`X25519MLKEM768` exchange.

The ticket, PSK, certificate, generated tables, and all private attempts are
volatile RAM state. No ticket or private key is persisted, no mutable leaf file
is packaged, and a write-protected floppy is sufficient. A restart repeats the
complete acquisition/offline/resumption sequence.

## Pack gate

Run:

```sh
python3 tools/check-tls13-product-pack.py
```

The checker performs no VM launch and no network access. It:

1. builds a fresh credential-free K14 secure-FO/exact-leaf base;
2. builds its fixed public synthetic post-auth composition;
3. rejects credential-bearing or diagnostic variants;
4. emits a temporary assembly include containing product labels, canonical
   phase keys, load destinations, and the full padded phase slots;
5. assembles `k14_product_pack.asm`; and
6. compares every base and post-auth phase slot, plus the complete contiguous
   pack, byte-for-byte with the validated research builder output.

The generated include and extracted phase slots are build-time inputs only.
They are not packaged as runtime files. The product scheduler loads the
relocation-sensitive phase keys at their final `SEED.SYS` sector positions
while preserving the checked runtime memory layout.

The 286+ fully conforming route uses a fixed-origin asymmetric
controller/module boundary documented in
[`TLS13_286_ABI.md`](TLS13_286_ABI.md). Its machine-readable memory, pack,
descriptor, callback, and return constants are in `tls13_286_abi.inc`.

## Same-request reconnect

The application layer reuses a live TLS session. If a human request fails
before any response text appears, Seed retires the failed channel, constructs
exactly one fresh route, reconstructs the same durable prompt from the screen,
and sends that request once more. A second failure returns to the prompt.
There is no automatic replay after text has rendered, and no replay of
tool/agent-loop continuations, because either could duplicate visible output
or local effects. The offline contract is checked by:

```sh
python3 tools/check-tls13-product-reconnect.py
```
