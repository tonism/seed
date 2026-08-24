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
behavior. Current read-only exact-floor runs prove the RAM-only 8088 fresh and
resumed wire profiles, bounded reconnect, authenticated dialogue, all seven
original-speed NIC profiles, and clean CGA/MDA display return. The conforming
286 four-flow topology also passes at 6 MHz / 512 KiB. Physical entropy
characterization and additional provider-edge repetition are still required
before either profile is product-validated.

## 8088 security boundary

The 8088 ClientHello uses the `X25519MLKEM768` wire identifier, but fixes the
X25519 public value to `u=9`; it therefore has no genuine classical X25519
contribution. Its effective key exchange is ML-KEM-only. To fit the provider's
observed connection deadline, the route may send client Finished and only
literal, credential-free liveness probes after provisional decapsulation. It
does **not** make the API key or a business request reachable until the same
machine has completed full Fujisaki-Okamoto validation, exact dated leaf
possession/CertificateVerify validation, and status-last capability
publication. The fresh connection must authenticate both its HEAD response and
tentative ticket. The final same-boot resumption offers no early data, performs
fresh KEM work, and sends its HEAD only after client Finished.

The exact leaf's issuer, hostname, purpose, and validity interval are trusted
image-generation provenance. The 8088 does not yet have a trusted runtime
clock, so image expiry is an explicit operational limit rather than a target
date check.

That is a deliberately narrow Seed security boundary. It must not be called a
standards-conforming `X25519MLKEM768` handshake, a FIPS-conforming hybrid, or
equivalent to the 286 profile.

The K14 code is cold-loaded in phases. Public and private TLS objects use
lifetime-separated conventional RAM below `0x4000`: scattered ciphertext is
reshaped between KeyGen/FO epochs and compact status-last capsules bridge the
authenticated transitions. The 32 KiB direct tier additionally uses its
conventional stack guard for an exact 28-byte arena shadow plus a public return
trampoline; both success and abort restore the full arena and erase the shadow.
Video RAM, NIC RAM, config/arena memory, and writable media are not TLS
storage. Private material is retired on every success and failure path.

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

Build and run the product gate through Make:

```sh
make build/ibm_pc_5150/tls13-k14-product-pack.bin
```

The build performs no VM launch or network access. It independently assembles
every fixed phase, emits the phase-key/destination ABI and 130-sector pack,
then the mandatory integration checker rebuilds every byte and executes:

1. the acquisition and resumption deadline phase/load sequences;
2. exact 1,088-byte ciphertext survival across overwritten aliases;
3. both regenerated-KeyGen/full-FO eight-entry lifecycle paths;
4. fragmented multi-record HTTP and authenticated NewSessionTicket handling;
5. embedded bounded close behavior; and
6. unchanged config, arena/context, video, and adapter-RAM guards.

The generated include and phase slots are build-time inputs only. They are not
packaged as runtime files. The product scheduler loads the checked phase keys
at their final `SEED.SYS` sector positions while preserving the verified
conventional-RAM layout.

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
