# Security

Seed has two TLS 1.3 profiles in one `SEED.SYS`. They share the record
layer and OpenAI endpoint, but they do **not** make the same security claim.
This document is the authority for that distinction.

> **Validation status.** Both routes are integrated. The current HTTP/2
> transport passes guarded offline composition and original-speed live chat,
> reconnect and native-tool acceptance on the 16 KiB, 32 KiB and 286/512 KiB
> paths, plus the seven-profile ISA NIC matrix.
> Physical entropy characterization remains a separate gate. See
> [the transport contract](http2.md) and [campaign evidence](optimization-campaign.md).

## Claims at a glance

| Profile | Product floor | Security claim |
| --- | --- | --- |
| 8088 | 4.77 MHz 8088, 16 KiB RAM | TLS 1.3 wire protocol with a bounded Seed credential-release boundary; effective ML-KEM-only key exchange, deferred authentication; not standards-conforming hybrid TLS |
| 286 conforming | 6 MHz 286, 512 KiB RAM | fully standards-conforming TLS 1.3 `X25519MLKEM768`, with real ML-KEM-768 and X25519 contributions and P-256 certificate authentication |

The 8088 route must not be described as FIPS-conforming, as a conforming
`X25519MLKEM768` hybrid, or as equivalent to the 286 route. The 286 protocol
claim likewise does not imply that the physical entropy source has already
been validated; that is a separate hardware acceptance gate.

These names are not product-capability tiers. After its route commits, the
8088 exposes the same chat and tool loop and protects application records with
TLS 1.3 ChaCha20-Poly1305. Its qualification differs at key establishment and
identity freshness: no secret classical X25519 contribution, no trusted
runtime expiry check, and a physical entropy source still awaiting validation.
The neutral-gray `security note` on its splash points to this documented
boundary; it is not a key-leakage warning or a reduced-function mode.

The 286 wire protocol is not cryptographically weakened relative to an
ordinary conforming `X25519MLKEM768` client. Seed as an implementation and its
1980s hardware entropy source still have less assurance than a mature,
independently audited TLS stack until physical characterization and external
review are complete. That implementation qualification applies separately
from protocol conformance.

## The 8088 security boundary

The 16 KiB route uses TLS 1.3, SHA-256, and ChaCha20-Poly1305 on the wire. Its
ClientHello names `X25519MLKEM768` and carries a genuine, target-generated
ML-KEM-768 public key. Its X25519 share is the fixed coordinate `u=9`, however,
so there is no secret classical X25519 contribution. The effective key
exchange is ML-KEM-only.

The provider's observed fresh-connection deadline is close to 15 seconds.
Full ML-KEM Fujisaki-Okamoto validation and P-256 identity verification cannot
all complete before that deadline on a 4.77 MHz 8088. Seed therefore divides
the route into three trust states:

```text
provisional
  verify the protected flight and exact server Finished with the provisional
  ML-KEM candidate
  send client Finished
  permit only a compiled, credential-free H2 preface and SETTINGS
  authenticate peer SETTINGS and acknowledgement of our SETTINGS and retain at most one bounded same-boot
  ticket as tentative state

quarantine
  finish full ML-KEM re-encryption, comparison, and implicit rejection
  re-derive and compare the TLS traffic material
  verify the immutable dated leaf possession and live CertificateVerify
  accept no credential, prompt, tool continuation, redirect, or business effect

committed
  publish the capability status-last
  only now restore access to USER.CFG credentials and construct the API request
```

The provisional preface/SETTINGS exchange contains no Authorization header, API key, prompt,
account identifier, cookie, or server-derived redirect target. It is still an
external effect: the provider may log, fingerprint, rate-limit, or count it.
The fresh socket must return both an authenticated SETTINGS/ACK completion and a
bounded authenticated NewSessionTicket. A close before either completes fails
the attempt; a ticket or close is not a substitute for liveness.

A received ticket is not trusted merely because its record tag verified under
provisional keys. It stays RAM-only and tentative until full FO and
exact-leaf/CV proof complete. The final connection consumes it once, performs
fresh KEM work with no `early_data`, verifies its protected flight and
Finished, sends the H2 preface/SETTINGS only after client Finished, completes full FO
validation and authenticated H2 liveness, retires its lifetime-separated
conventional-RAM state, and only then promotes the route status-last. Tickets
and keys never survive a restart.

### 8088 identity and rotation

The fast identity object is an immutable `api.openai.com` P-256 leaf point in
`SEED.SYS`. Its issuer, hostname, purpose, and validity interval are checked
when the trusted image object is generated, and the route requires possession
of that exact key through TLS CertificateVerify. “Dated exact leaf” refers to
that image provenance; the 8088 route does not yet have a trusted runtime
clock, so it cannot independently know that the current boot is still inside
the interval. A changed leaf fails closed and requires a new trusted Seed
image unless a separately validated WE1-authorized rotation path is later
added. Image expiry is therefore an operational trust limit of this 8088
boundary, not a silently enforced target check.

There is no mutable leaf file and no trust-on-first-use. In particular,
`SEED/LEAF.DER` is not part of the TLS 1.3 image.

### 8088 entropy status

The machine gathers its own input before TCP without adding disk activity.
After each already-required successful floppy sector read, the resident tail
records one PIT channel-0 phase byte, up to 120 observations. The cold
conditioner freezes the recorder, rejects too few samples and gross stuck/long
run failures, and SHA3-conditions the observations into domain-separated,
one-shot attempt material. It does not perform an entropy-only read, ask for
dice rolls, treat elapsed seconds as entropy, or depend on a trusted modern
machine. The mechanism works unchanged with write-protected media.

The emulator proves the mechanism but receives zero entropy credit. A secure
floor claim still requires traces from representative physical drives, a
conservative min-entropy estimate, and calibrated startup and continuous
health tests. Until that is complete, this is a functional 8088 boundary under
validation, not a claimed production secure floor.

## The 286 conforming profile

The 286 route is admitted only when the CPU is 286+ and the BIOS Data Area
reports at least 512 KiB conventional RAM. It implements a real
`X25519MLKEM768` TLS 1.3 exchange:

- target-generated ML-KEM-768 keypair and full decapsulation;
- target-generated X25519 scalar, public share, and shared secret;
- the standard hybrid secret construction;
- SHA-256 and ChaCha20-Poly1305 handshake and record protection;
- strict ordinary Certificate parsing;
- Google Trust Services WE1 P-256 issuer verification;
- exact `api.openai.com` hostname, purpose, key-use, and validity policy; and
- P-256 CertificateVerify over the acquisition transcript, followed by a
  standards-conforming authenticated PSK-DHE resumption.

The final credential-bearing connection is no-0RTT PSK-DHE resumption. It uses
a same-boot ticket from the authenticated acquisition, a real binder, and an
independent genuine hybrid key exchange. The ticket is a timing bridge, not a
classical-share or authentication shortcut.

### Authenticate, then use

The slow certificate work is moved outside the provider timer without moving
it outside the security boundary:

1. An acquisition connection generates real ML-KEM-768 and X25519 shares. It
   uses the exact ML-KEM candidate provisionally, verifies the protected flight
   and server Finished, captures the ordinary Certificate and
   CertificateVerify, sends client Finished plus the immutable
   credential-free H2 preface/SETTINGS, and authenticates peer SETTINGS/ACK and one
   NewSessionTicket. That ticket is published only as tentative.
2. With no provider connection timer running, the same machine performs full
   ML-KEM FO decapsulation and a constant-time comparison with the provisional
   candidate, then strictly validates WE1, hostname, purpose, key use, UTC
   validity, and the acquisition CertificateVerify. Only the complete proof
   promotes the volatile ticket.
3. The final connection consumes the promoted ticket before reading its PSK
   or identity, stages the immutable symmetric image, generates independent
   ML-KEM-768 and X25519 keys, sends a real binder with no `early_data`, and
   requires `selected_identity=0`. Before TCP it computes the ticket-only
   early-derived value and the public ML-KEM A^T matrix. After ServerHello it
   consumes that matrix for complete full FO decapsulation before accepting a
   strict EncryptedExtensions-to-Finished flight. After server Finished
   verifies, Seed sends client Finished and the credential-free H2 preface/SETTINGS, then
   requires a complete authenticated ticket plus peer SETTINGS/ACK. It
   publishes application keys with the advanced server-record sequence; only
   then is credential access restored.

### Pre-TCP cache boundary

The final route moves only connection-independent or already-determined work
outside the provider timer:

- the immutable 12-sector symmetric image is read from the write-protected
  floppy into the high record quarantine before either live TCP connection;
- the 32-byte resumption early-derived value is computed from the promoted
  ticket PSK before final TCP and stored beside a bytewise complement; and
- the 4,608-byte, nine-polynomial public A^T matrix is generated from the
  fresh ML-KEM public `rho` before final TCP.

Each cache begins invalid, publishes its inverse/READY status last, is consumed
by invalidating that status before the first read, and is retired after its
one permitted use. The symmetric image is checked again by the relocated-image
CRC; the early-derived value must match its complete complement and is wiped
after import. Missing, torn, reversed, or stale status aborts before the
consumer can publish authority. A corrupted public matrix does not turn cached
decapsulation into a candidate shortcut: full ciphertext comparison, `J`, and
branchless implicit rejection still run after ServerHello, and the resulting
wrong secret cannot verify server Finished. Client Finished and credential
publication remain after those checks.

The conventional-RAM-only image repeats the exact-floor serialized CPU and
four-flow wire gates with matrix generation and offline authentication outside
the live provider windows. CPU/RAM, RTC/time, entropy, certificate, CV,
Finished, FO/cache, pack, and abort rejection gates pass. Physical RTC/PIT
entropy characterization remains open.

The immutable trust object is the WE1 P-256 affine point baked into
`SEED.SYS`. The leaf, generated tables, private state, and same-boot pin live
only in RAM and are discarded on restart. The ticket and PSK are also volatile
and never become a disk cache. Read-only floppy media is sufficient.

The acquisition candidate is not an authority boundary: it can enable only the
fixed credential-free H2 preface/SETTINGS and tentative ticket capture. A candidate mismatch,
failed X.509/CV check, torn ticket state, bad binder/identity selection, or
resumed Finished failure aborts and wipes without exposing the API key.

There is no 0-RTT, compressed certificate, persisted ticket, persisted private
key, mutable leaf, classical-share shortcut, or no-time validity bypass.

## Pinning and the earlier “double pin” idea

Pinning is part of the TLS architecture, not a packaging afterthought. The
useful authority chain is:

```text
durable issuer authority     WE1 point in the immutable image
acquisition identity         authenticated api.openai.com leaf + live CV
same-boot bridge             promoted ticket derived only after full offline proof
credential-bearing channel  binder + independent hybrid KEX + resumed Finished
```

That is the 286 route. It avoids trust-on-first-use and survives ordinary leaf
rotation without making a mutable floppy file authoritative. The earlier
“double pin” intuition therefore belongs in the architecture scope, but not as
two guessed leaf files: issuer authorization, exact live acquisition identity,
and the promoted same-boot ticket are distinct links with distinct lifetimes.

The 8088 fast route currently has only the immutable exact-leaf identity
object; adding trusted runtime time and a general WE1-authorized rotation path
at that floor remains future work. Until then, leaf change or the image
object's validity end requires an updated trusted image. Baking “current and
guessed next leaf” is not a sound substitute:
there is no authenticated way to know the future leaf, and it only delays the
same rollover problem. A future issuer rollover can use a bounded active and
successor issuer set only with an authenticated update story.

### Trusted time

An IBM PC/AT RTC exposes no timezone. Seed treats its coherent BCD Gregorian
value as the machine's platform UTC clock, just as a conventional TLS client
relies on its configured platform clock. This is silent: a user confirmation
would add no trustworthy time information. Invalid, incoherent, or
out-of-range values fail the profile. Unauthenticated NTP is not a trust input and
there is no no-time expiry bypass.

### Entropy

The 286 route silently gathers 1,024 timing events by polling the
MC146818-compatible RTC's 4,096 Hz periodic flag and sampling that independent
32.768 kHz oscillator against PIT channel 0. It does not enable IRQ8 or perform
entropy-only floppy reads, and it restores RTC Status A afterward. Seed applies
repetition-count and adaptive-proportion health tests, conditions the transcript
with SHA3, and instantiates HMAC_DRBG attempt bundles. No private seed is
supplied by the build machine or persisted.

The health-test cutoffs and min-entropy credit remain provisional until
representative physical-machine characterization is complete. This is an
explicit acceptance risk, not a protocol shortcut.

## Same-request reconnect and replay

The application layer keeps a successfully authenticated TLS session open.
When a human request fails before any response text appears, Seed retires the
channel, creates exactly one fresh route, reconstructs the same durable prompt
from the screen, and sends it once more. A second failure returns an error.

Seed never automatically replays:

- a response after any text has rendered; the visible text is accepted and the
  channel is retired; or
- a tool/agent-loop continuation, because replay could duplicate local effects.

Reconnect is availability logic. It cannot promote tentative crypto state or
weaken either profile's authentication gates.

## Local machine boundary

TLS protects the network route; it does not turn the floppy into secret
storage or Seed into a sandbox.

- `SEED/USER.CFG` stores an API key in plaintext when the user chooses to save
  it. A write-protected floppy protects recovery and immutability, not
  confidentiality at rest.
- A model-authorized native tool runs with bare-metal authority over the
  published arena. The recovery boundary is a reboot from known media.
- TLS state is confined to conventional system RAM below the applicable
  machine ceiling. Video RAM remains display state and adapter RAM remains
  device state; neither is used as a vault, escrow, scratch area, or restart
  wipe target.

## Evidence and acceptance gates

The architecture and exact memory contracts are in
[`architecture.md`](architecture.md),
[`memory.md`](memory.md), and the target TLS directory. The earlier TLS 1.2
feasibility record remains in
[`crypto-feasibility.md`](crypto-feasibility.md) as historical evidence only.

The current HTTP/2 emulator evidence covers the affected product/KAT/layout
gates, RAM-only acquisition/resumption guards, and read-only original-speed
fresh/resumed/reconnect runs on both CPU routes and all seven ISA NIC profiles.
The three main CPU/RAM paths complete repeated conversation and native
write/execute/read, and the NIC matrix includes CGA/MDA return to input.
The 32 KiB numeric-format caveat is recorded in the
[functional acceptance](http2.md#functional-acceptance). These functional
passes do not remove the broader security qualification. Remaining work is to:

- extend deadline characterization across cold boots and provider-edge
  variation; and
- characterize entropy and health-test behavior for PIT samples from the
  8088's already-required floppy reads and for the 286 RTC/PIT source on
  representative physical machines.
