# TLS 1.3 / Runtime Rearchitecture Spike

Branch context: `codex/build-13-tls13-rearchitecture-spike`, starting from
`548053d` (`codex/build-13-driver-modules`).

This is a research design note, not product documentation. It records the
architecture hypotheses and acceptance gates for a replacement-only TLS 1.3
spike. Current behavior remains described by `docs/`; none of the designs below
is a shipped contract until it is implemented, measured, accepted, and promoted
to the relevant reference document.

Terms used below:

- **Measured** means read from the current assembled artifacts or already
  validated and recorded in the reference docs.
- **Calculated** means exact arithmetic over the current layout, conditional on
  the stated layout change.
- **Estimate** means a plausible implementation outcome that the spike must
  replace with a measurement.
- **Unknown** means the spike exists specifically to answer it.

Standards baseline checked on 25 July 2026:
[TLS 1.3 / RFC 9846](https://www.rfc-editor.org/info/rfc9846),
[TLS Certificate Compression / RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html),
[ML-KEM / FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), and the active
[`draft-ietf-tls-ecdhe-mlkem-05`](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/).

## Scope and decision to make

The immediate decision is whether a narrow TLS 1.3 implementation can replace
TLS 1.2 everywhere while **establishing a secure floor and preserving the
current functional** headline floor:

```text
4.77 MHz 8088
16 KiB RAM
live OpenAI request / response
native memory tools and bounded local context
authenticated server and confidential credentials/product traffic
```

An unauthenticated 8088 tier is no longer an acceptable TLS 1.3 replacement
target. If the 8088 cannot complete the chosen security proof, TLS 1.2 cannot
be removed merely to make the wire version uniform.

The floor must be self-contained after every cold start. A modern helper may be
used to build Seed and the floppy, just as it is today, but it may not compute a
per-boot key, KEM answer, ECDSA table, ticket, transcript, or other session
state for the 8088. The original machine must generate all ephemeral secrets
and acceleration caches itself. Immutable code, public constants, certificate
anchors, and provider configuration may still ship as normal program assets.

This creates four separate questions:

1. Can a standards-conforming TLS 1.3 key exchange finish before the provider's
   initial close?
2. If not, can the 8088 safely cross that deadline without releasing any
   credential or trusted effect?
3. Can it then finish the exact KEM and server-identity proofs on the same
   connection?
4. Can the required code and state be phase-overlaid inside 16 KiB without
   reducing the product arena/context contract?

The wider architecture goal is:

> One Seed product, zero architecture questions for the user.

That does not require one native instruction stream. It means a self-selecting
medium/package whose small firmware-native entry shims choose the correct
payload automatically. It also means keeping the original-machine recovery
artifact simple rather than exposing a matrix of CPU-specific floppy images.

## Spike outcome and recommendation

Do **not** promote the replacement into the product yet. The spike now has a
complete 91,136-byte / 178-sector credentialed composition over the hardened
four-sector-resident secure-FO base. All 11 fixed same-boot resumption
operations, the card-RAM receipt/vault lifecycle, fresh target KeyGen and
binder, PSK-DHE exchange, resumed Finished, credential-free liveness request,
deferred FO, status-last route promotion, credential loader, and authenticated
application response path are linked and have their offline hostile gates.
On 28 July 2026 two independent exact credentialed functional runs completed
on the admitted 4.772728-MHz 8088 / 16-KiB / ROM-BASIC / NE2000 profile and
emitted authenticated `ok / PASS / RESULT` from unchanged host-read-only
images. The second was a fresh rerun after host sleep inhibition was confirmed.
Physical-source entropy characterization is still pending, so this is a
measured functional-feasibility result rather than a secure-tier result.

The predecessor fixture and credential-free live artifacts remain important
evidence. Their K15 **and K14** proof chains complete on a configured
4.772728-MHz 8088 with exactly 16 KiB RAM. K14 recovers one 512-byte physical
sector; after the two-order ServerHello parser fix its fixture-fed critical
result is 225 ticks, matching the current K15 record. A separate
credential-free K14 image traverses the real baseline product NE.DRV/TCP path
against the live provider and puts client Finished on the host wire in three repeated
13.483030–13.536609-second deadline-only runs. Its successor passed a full
credential-free canary on the same exact floor: client Finished at 13.404952
seconds, encrypted HEAD, two RAM-only tickets and a 1,125-byte HTTP response
AEAD-verified under provisional traffic keys, and atomic tentative canary
commit.

Those predecessor results resolve the deadline bridge, application-record
buffer, ticket-capture, and previous K14 RX/controller lifetime questions for
this fixed profile and one representative NIC. The final composition closes
the remaining implementation gaps for the dated exact-leaf route and now
includes unattended pre-network floppy-timing collection. Its exact
credentialed functional path passes twice. Physical-source entropy characterization,
provider repetition, other-NIC storage strategy, general
certificate-chain/trusted-time policy, and external review remain open. It is
not yet a secure product floor.

```text
pre-TCP, entirely on the 8088:
    collect 256 read-only physical-floppy completion timings locally
    SHA3-condition them into two domain-separated one-shot attempt bundles
    use/verify a durable ratchet as an additional route only when media is writable
    generate a fresh ML-KEM-768 keypair
    resolve/cache the fixed target and preload the symmetric delta

timed provisional first handshake:
    TLS 1.3 / ChaCha20-Poly1305 / SHA-256
    OpenAI's X25519MLKEM768 wire group
    real ML-KEM share, but X25519 client u-coordinate fixed to 9
    commit the exact ServerHello transcript context
    compute the provisional K-PKE.Decrypt/G candidate
    restore the eight-sector symmetric delta
    verify the complete protected flight and exact server Finished
    construct and transmit client Finished
    immediately send a literal credential-free HEAD request
    retain the first bounded NewSessionTicket and validate/drain later tickets

post-Finished quarantine, allowed to finish after socket close:
    complete exact ML-KEM re-encryption, compare, and implicit rejection
    parse the uncompressed certificate, or bounded-decompress first if
    compression is retained
    verify the leaf under WE1 and verify TLS CertificateVerify
    use additional literal HEAD requests only at clean checkpoints
    if the socket closes, continue the proof without promoting any state

atomic commit:
    if the first socket lives, promote its traffic secrets
    otherwise promote the retrospectively authenticated same-boot ticket
    a resumed connection still performs fresh KEM work but omits cert/CV
    only then make the API-key buffer reachable and build the real request
```

### Final credentialed composition (functional result passes; physical entropy pending)

The final PoC composes the preceding design into one flat file-backed
`SEED.SYS` while retaining the existing resident and driver contracts:

| Property | Current composed artifact |
|---|---:|
| Machine gate | IBM PC 5150, 4.772728-MHz 8088, dynarec off |
| Installed RAM | exactly 16 KiB |
| Entry | ROM BASIC sidecar |
| NIC/storage gate | 8-bit NE2000 and its guarded card-RAM DMA |
| Hardened secure-FO base | 62,464 B / 122 sectors |
| Final `SEED.SYS` | **91,136 B / 178 sectors** |
| Initial resident prefix | 2,048 B / four sectors, unchanged |
| Added post-auth phase entries | 37 entries / 56 sectors |
| Fixed resumption dispatcher | 221 B at `0x0500` |
| Fixed operation surface | 11 operations |
| Credentialed 86Box functional result | **PASS twice, 28 July 2026** |
| Entropy credit | **0 bits in emulator; physical characterization pending** |

The fixed operation sequence is:

```text
1 CLOCK        2 PREPARE      3 EXCHANGE     4 RECEIVE
5 SEND         6 HEAD         7 DEFERRED_FO  8 LIVENESS
9 ROUTE_VALID 10 NST_VALID   11 RESTORE
```

After the provisional HEAD response is tag-verified and the first bounded
NewSessionTicket is retained at an exact TLS-record boundary, a status-last
`NTR1` receipt is written to and reread from NE2000 page `0x73`. The initial
connection then completes exact ML-KEM FO and the dated exact-leaf P-256
possession checkpoint. PREPARE consumes the domain-separated, one-shot second
entropy bundle, vaults the issuer/ticket/control state in volatile NE2000 pages
`0x73..0x7f`, generates a fresh target ML-KEM keypair, and builds the
resumption binder. No floppy write or trusted modern helper participates.

The resumed PSK-DHE route verifies the exact certificate-free protected flight,
sends client Finished and one literal credential-free HEAD, completes deferred
FO, authenticates and drains the HEAD response, validates/restores/scrubs the
vault, and only then promotes `TICKET_ONLY` to `LIVE_TICKET` status-last. The
`USER.CFG` loader and real request are unreachable before promotion.

The final lifetime schedule includes three explicit self-overwrite repairs:

- Lifecycle digest work stages a one-sector bridge at `0x2400`, exact-copies it
  to `0x3400`, permits K14 SHA-256 to overwrite `0x3000..0x33f8`, then reloads
  the lifecycle worker at `0x3000` before returning.
- Deferred FO uses a 71-byte broker at `0x3000` and a 1,282-byte/three-sector
  controller at `0x2400`. It verifies both candidate copies, backs up
  `0x3510..0x35ff` status-last through card page `0x7e`, restores the
  symmetric/controller state after FO, scrubs the retired page, and makes every
  post-FO failure terminal through the unchanged recovery controller.
- After request sealing, record AEAD owns `0x32af..0x33f8`. The response-phase
  loader, ACK continuation, and success literal therefore live in the
  exact-copied executable-safe prefix below `0x3510`; the supervisor installs
  response literals inline and jumps only to persistent failure services above
  the scratch. A listing/CFG gate rejects reachable instructions, call return
  addresses, direct targets, absolute operands, or literals that enter the
  K14 work range. Response success additionally requires authenticated exact
  `ok`, authenticated `response.completed`, and the authenticated terminal
  HTTP chunk `0\r\n\r\n`.

The linked collector runs before the first network transmission and requires
no operator input. It performs 256 one-sector `INT 13h/AH=02h` reads,
alternating CHS `0/0/1` with `39/0/8`, brackets each read with latched PIT
channel-0 counts, and SHA3-256-conditions the timing events into the two
attempt bundles. The reads work on write-protected media; the collector issues
no disk write. The PIT is only a measurement clock:
elapsed seconds, milliseconds, BIOS ticks, and nominal timer resolution alone
receive zero entropy credit. 86Box proves mechanics and the full functional
route but also receives zero credit. A secure-floor claim requires
representative physical-drive traces, a conservative min-entropy estimate, and
calibrated startup/continuous health tests.

The generated floppy is host mode `0444`; a successful run must prove host
write-open denial and an unchanged private before/after image digest.
`USER.CFG` remains plaintext inside that image, so read-only media provides
immutability, not credential confidentiality at rest.

#### Exact credentialed live result

Both admitted runs on 28 July 2026 produced this ordered target evidence:

```text
ENTROPY START 256
ENTROPY PASS 256
DEADLINE PASS
HEAD TX
TICKET
HEAD OK
FO BEGIN
KEM VALID
AUTH BEGIN
ok
PASS
RESULT
```

The runner admitted only the IBM PC 5150 / 4,772,728-Hz 8088 / exactly
16-KiB / dynarec-off / 8-bit-NE2000 / ROM-BASIC profile. It accepted no entropy
values, observed collection before networking, denied a host write-open, and
proved the private before/after floppy digest equal without logging that digest
or credential contents, path, size, or hash.

The first run's fresh socket put client Finished on wire at SYN +13.699603 s, sent its
credential-free HEAD at +14.653640 s, and received response bytes at
+14.830376 s. The resumed socket sent the precomputed early-data object at
+0.128235 s, received the protected flight at +0.133319 s, put client Finished
on wire at +10.358263 s, sent the credential-free liveness HEAD at
+11.314858 s, and received its response at +11.497390 s. After local
FO/auth/vault promotion, the two business-request records left at
+58.644804/+59.258603 s; the response began at +60.040317 s and its last TLS
record arrived at +61.492372 s. The authenticated target markers, rather than
pcap plaintext inference, are the success authority.

This exact composition is NE2000-specific because its volatile lifecycle uses
guarded remote DMA and card pages `0x73..0x7f`. Its same-boot receipt clock is
audited against the configured IBM PC BIOS `INT 1Ah/AH=00` tick and
midnight-flag semantics. It does not establish another NIC, another BIOS,
another RAM size, persistent tickets, or a product retry contract.

The profile remains deliberately nonconforming: fixed X25519 `u=9` contributes
no classical secrecy, the effective key exchange is ML-KEM-only, and
provisional candidate use precedes the FIPS 203 FO boundary. The dated
exact-leaf checkpoint is not a general certificate-chain, trusted-time, or pin
rotation solution. This functional VM pass followed by a physically credited
run would add the missing entropy evidence to the already established
exact-target functional feasibility; it would not establish conforming TLS,
FIPS conformance, external review, or product replacement authorization.

### Literal 16-KiB integrated result

`tools/crypto-bench/tls13-poc/phase_chain_literal16k_results.json` records the
original K15 target run.
`tools/crypto-bench/tls13-poc/phase_chain_literal16k_k14_results.json` records
the diagnostic-free K14 target run:

| Property | Measured result |
|---|---:|
| Machine | IBM PC 5150, 4.772728-MHz 8088, dynarec off |
| Installed RAM | exactly 16 KiB |
| Entry | ROM BASIC sidecar |
| Resident nucleus | 2,048 B / four sectors |
| Whole cold phase container | 79,872 B / 156 sectors |
| Terminal protocol | exact `PASS` then `RESULT` |
| End-to-end harness wall time | 159.285 s |

The raw target phase stream was:

```text
PRE l=12
ENT t=181 w=14 r=3 load=7
KG t=402 load=3
CF t=225
FO t=470 load=6
AU t=989 load=13
PASS
RESULT
```

At 18.20648193 BIOS ticks per second, the measured work is:

| Phase | Ticks | Seconds | Timer relationship |
|---|---:|---:|---|
| symmetric preload | 12 | 0.659 | before TCP |
| deterministic entropy durability | 181 | 9.941 | before TCP |
| ML-KEM KeyGen | 402 | 22.080 | before TCP |
| critical protected-flight path | **225** | **12.358** | before client Finished |
| complete FO tail | 470 | 25.815 | quarantined/post-Finished |
| exact adopted-leaf authentication | 989 | 54.321 | quarantined/post-Finished |

The working 15-second bound is 273 ticks. The target critical section therefore
has **48 ticks / 2.636 seconds of measured margin**. It starts after the final
ServerHello transcript-context commit and includes candidate-overlay load,
provisional ML-KEM candidate computation, eight-sector symmetric restore,
protected-flight fixture reads, context import, the critical key schedule,
ChaCha20-Poly1305 flight authentication, server Finished verification, and
exact 58-byte client Finished construction.

This 225-tick timestamp remains the reproducible fixture-chain gate: its
protected flight is read from floppy and it stops after exact client-Finished
construction. The live sibling result below supersedes the old projection for
NIC/TCP, record parsing, ACK/window behavior, phase-load latency, and actual
Finished transmission. Keep both gates: the fixture chain covers the complete
FO and exact-leaf-authentication continuation components in isolation, while
the live image covers the literal wire race. The final 178-sector artifact
composes those paths with target resumption and credential gating; its exact
credentialed live execution now passes.

### Exact-speed live K14 deadline and canary result

The credential-free live image uses the same four-sector baseline product
resident prefix and production `NE.DRV`, plus the K14 overlays and live
controllers.
Its cold `SEED.SYS` is 45,568 bytes / 89 sectors; only the four resident
sectors and one phase are live at a time. The harness contains no credential
or business API request. It sends one exact credential-free 50-byte
`HEAD /v1/models` request after client Finished, AEAD-verifies the response
under provisional traffic keys, and retains the first bounded
NewSessionTicket in RAM. Frozen artifact hashes and per-run evidence are in
`tools/crypto-bench/tls13-poc/live_k14_16k_results.json`.

The repeat 8-10 v1 run records bind the predecessor deadline-only
`3f263028...` core and `d70ce462...` floppy. The current hardened attempt-6
canary record embeds its distinct `ccedcd8d...` core, `be79ab23...` floppy,
and `b254df91...` frozen-manifest hashes directly. The aggregate ledger preserves
the historical deadline baseline separately rather than treating those
different images as repeat measurements of one artifact.
A fresh offline replay after the final checker/document reconciliation
reproduced the attempt-6 core and floppy byte-for-byte. Its manifest differed
only in absolute output paths; no VM or network launch was performed.

The first live attempt exposed a legal provider ServerHello extension order
of `key_share, supported_versions`; the strict parser had accepted only
`supported_versions, key_share`. The fixed parser accepts exactly those two
orders, hashes the actual wire bytes, and keeps all other order/content/length
mutations fail-closed.

The hardened protected-flight parser accepts zero or one one-byte compatibility
CCS and exactly one encrypted handshake record. Offline negatives reject a
duplicate CCS, a coalesced later record, and a later record delivered through a
separate already-queued NIC/TCP callback before any client Finished transmit.

Critical media work initially used sixteen one-sector BIOS reads. Copying the
existing 146-byte track-batched loader to `0x0f00..0x0f92` after HELLO saved
37 ticks / 2.032 seconds. The predecessor deadline artifact used seven cold
padding sectors. The successor canary uses five—two before candidate and three
before SYM—while retaining the five-sector candidate at absolute LBA 80 and
the eight-sector symmetric restore at LBA 88 so each remains one BIOS batch.

| Live revision / run | Guest interval | Host-wire interval | Result |
|---|---:|---:|---|
| one-sector phase loader | 284 ticks | 15.950545 s | late |
| track-batched loader | 247 ticks | 13.921277 s | pass |
| aligned media | 239 ticks | 13.481118 s | pass |
| aligned-media repeat | 239 ticks | 13.480155 s | pass |
| hardened current image, repeat 8 | 240 ticks | 13.536559 s | pass |
| hardened current image, repeat 9 | 240 ticks | 13.536609 s | pass |
| hardened current image, repeat 10 | 239 ticks | 13.483030 s | pass |
| hardened post-Finished canary | `F/A/H=04a7/04b3/04b9` | **13.404952 s** | ticket + HTTP + commit pass |

The predecessor three-run deadline baseline has a 1.463391-second worst
observed margin against 15.000000 seconds. The successor canary leaves
1.595048 seconds. All three predecessor Finished records were ACKed by the
server 46.5–66.7 ms after appearing on the host interface; the successor
continued immediately into encrypted application data.

One diagnostic run stopped the pcap only 13.396 seconds after ServerHello and
reported `missing-client-finished` despite guest `PASS / RESULT`. The same
image passed after adding a two-second post-`RESULT` observation grace outside
the measured interval. That was a harness capture-shutdown race, not evidence
of a dropped NIC frame. The current controller sends one exact 58-byte
Finished record and advances the logical TCP sequence once; its offline gate
pins both properties.

The successor proves deadline, transport, K14 memory lifetimes, tag-verified
application-record buffering, a complete credential-free HTTP dialogue, and
tentative ticket capture on one representative NIC. The independent capture
oracle verified exact server and client Finished values, the encrypted HEAD,
two 222-byte tickets in server application sequence zero, and the 1,125-byte
HTTP 401 response in sequence one. During the run the floppy was host mode
`0444`, a write-only open was denied, its before/after hash was unchanged, and
the original mode was restored. The image still uses public deterministic
`d||z` and ClientHello values, fixed X25519 `u=9`, and a provisional ML-KEM
candidate. Full FO implicit rejection (25.815 s) and adopted-leaf
authentication (54.321 s) remain quarantined after Finished. Credentials and
the real business request must remain unreachable until those proofs, trusted
time, failure zeroization, and atomic commit all succeed.

The coherent-chain mode deliberately fixes `d` and `z` so every later byte can
be compared exactly. It still performs prepare -> BIOS write -> disk
reset/flush -> physical reread -> exact record verification -> `d||z` release.
It does **not** mix the PIT/BDA collector and therefore establishes durable
ratchet integration, not physical min-entropy. The separate entropy checker
keeps the collector/crash matrix green while crediting zero bits of established
physical min-entropy.

### Post-Finished proofs and ticket recovery

The full FO overlay performs exact re-encryption, fixed ciphertext comparison,
`J`, and branchless implicit rejection with a fixed 17-read public-stream
schedule. It generates and consumes each matrix polynomial immediately rather
than retaining a 4,608-byte matrix cache.

The exact adopted-leaf authentication overlay is now **6,632 bytes / 13
sectors**, after moving 896 bytes of mutable P-256 work into the phase-local low
window. The production P-256 include emits byte-identical default code unless
that external-work option is explicitly selected. This hot path verifies the
tracked exact leaf's CertificateVerify, but the tracked leaf expires on
8 August 2026 and no longer matches the freshly observed live leaf.

A separate **7,134-byte / 14-sector** issuer-authorized overlay executes a real
WE1 -> current live OpenAI leaf -> captured TLS CertificateVerify two-signature
proof. It gates the leaf handoff on issuer success and rejects DER, range,
curve, signature, ordering, torn-commit, return-stack, and sentinel failures.
This is target arithmetic over real captured chain material.

A strict uncompressed Certificate/CV parser now supplies that bounded handoff
in isolated target overlays: 2,696-byte parser, 2,045-byte leaf hash phase, and
335-byte trusted-time comparator, with a 40-byte measured stack high-water.
Its truncation, DER/profile, hostname, key-usage, CV, time, re-entry,
zeroization, DF/ES, and sentinel matrices pass. The current symmetric image is
6,142 bytes through `0x2ffe`; its 1,016-byte mutable K work occupies
`0x3000..0x33f8`, leaving only **8 bytes** below `0x3400`. Appending the
748-byte capture callback therefore exceeds K14 by **744 bytes** after
alignment. Earlier
5,951-byte/724-byte-overflow and 469-byte-headroom figures describe superseded
layouts, not current linked capacity. The former `0x0d00..0x0fec` callback
candidate is no longer available either: the live path now uses
`0x0d00..0x0eff` for tag-verified scatter plaintext and begins its batched
loader at `0x0f00`. A general issuer-authorized live certificate handoff still
needs another phase/lifetime schedule rather than an append. The final
credentialed composition instead uses the already linked dated exact-leaf
possession checkpoint.

Omitting Brotli expands the protected flight by 696 bytes and costs a projected
44 target ticks / 2.4167 seconds. Applying that delta to the measured
225-tick compressed chain projects to 269 ticks, leaving only four ticks
before a 273-tick
deadline, before live NIC/TCP and transmit overhead. That arithmetic is not a
linked uncompressed timing result, but it makes compression/critical-path
optimization a first-order blocker. A general RFC 8879 Brotli decoder is not
yet bounded: the reconstructed stream legally advertises a 4,080-byte backward
distance even though one re-encode happened to use at most 1,705 bytes.
Trusted time remains unresolved.

A credential-free live host observation captured two NewSessionTickets and
successfully resumed with `TLS_CHACHA20_POLY1305_SHA256`. The resumed handshake
omitted Certificate and CertificateVerify but retained PSK plus an
X25519MLKEM768 key share. The exact-floor target now independently
AEAD-verifies under provisional traffic keys and retains the first of two live tickets and derives its
tentative RAM-only resumption PSK. At this predecessor canary checkpoint it did
not yet construct or complete a resumed handshake. The final 178-sector
composition now implements the target binder, fresh PSK-DHE resumed handshake,
deferred resumed FO, authenticated liveness, and route promotion. Its exact
functional live result passes; physical entropy credit remains pending. Neither
artifact removes fresh KEM work or authorizes persistent/cross-boot tickets.

That proof is deliberately **not** standards-conforming X25519MLKEM768. Its
classical component contributes no secrecy, so the effective key exchange is
ML-KEM-only. Using the K-PKE candidate before full Fujisaki-Okamoto validation
is also outside FIPS 203's decapsulation contract. This profile must not be
called TLS-compliant, hybrid-secure, FIPS-conformant, or a shipped secure tier
without a dedicated cryptographic review and the integrated gates below.

The approximately 15-second close was originally measured with a P-256/RSA
profile. Three predecessor fixed-`u=9`/ML-KEM/ECDSA target runs and the current
canary reached client Finished before that bound; the current run then
completed an encrypted HEAD dialogue and captured tickets. The final exact run
adds fresh client Finished at SYN +13.699603 s and resumed client Finished at
+10.358263 s; its resumed socket survived liveness, FO/auth, credential unlock,
and the authenticated business response. These observations establish one
working schedule, not the provider's close-time distribution, SLA, or repeated
long-dialogue reliability. Ticket-assisted recovery remains primary; later
HEAD checkpoints are opportunistic continuity.

The K15 and K14 containers both preserve the current **96-byte executable arena
plus 96-byte context** at 16 KiB and **224/224 bytes** at 32 KiB. K14 now
passes the exact full-chain literal target and hostile offline gates. The
previous proposed K13 split is no longer address-feasible: symmetric primitive
work crosses its `0x3200` ceiling by 56 bytes. K14 keeps all existing high-state
addresses and uses `0x3400..0x3600` as a phase-specific controller/staging
extension. That sector is reusable ephemeral scratch between connections, not
a persistent user arena: a reconnect reloads phase-owned
controller/staging/runtime state there and would overwrite user code. The safe
persistent contract therefore remains **96 executable bytes plus 96 context
bytes**. A hypothetical full low-band repack has a 704-byte arithmetic upper
bound, but the passing K14 schedule also has live control state through
`0x3cac`, overlapping that proposed pool. Reaching either a balanced 352/352
split or an executable-first 608/96 split therefore requires a newly linked
phase/high-state schedule and renewed memory, deadline, wire, reconnect,
`$w`/`$x`, compaction, and versioned ENV gates.

The fixture chain retains its 128-byte handoff at `0x0700..0x077f`, so it
remains an offline full-chain artifact rather than the live memory proof. The
live sibling resolves both former blockers: raw ciphertext and temporary
`K′` use `0x08c0` only under explicit lifetimes, the final 1,013-byte
post-Finished controller loads at `0x0900..0x0d00`, and the embedded
delta-loader source is dead before the overlapping symmetric runtime becomes
live. Its AEAD plaintext quarantine scatters across
`0x0d00..0x0eff`, `0x3600..0x3837`, and `0x3920..0x3b3f` while retaining both
application-secret bands and native ticket state. Executable write hooks show
zero post-`sym_init` writes to `0x3400..0x35ff`; copying a padded controller
sector there remains forbidden.

Two further post-Finished lifetimes are now resolved in the isolated target
chain. The default issuer-auth input ABI at `0x3ba4..0x3c53` overlaps symmetric
full retained state at `0x3b40..0x3c2e` by 138 bytes; the native ticket bundle
may still end at `0x3c2d`. The
`TLS13_POC_READ_ONLY_INPUT` profile instead uses `0x3400..0x34af`, immediately
after the exact 14-sector issuer image and 97 bytes below the old symmetric
runtime at `0x3510`. Both real signatures pass across physical phase reloads
while the native 269-byte ticket remains byte-stable. This ordering is valid
only after the network/parser/FO users of `0x3400..0x3600` retire.

The separate 659-byte/two-sector atomic gate validates issuer handoff, live-CV
status, ticket bounds/lifetime, generation, and torn-state checksums; clears
the retired input; and stores committed state last. Its 18-case hostile matrix
zeroizes every declared tentative range without invoking the read callback.
The literal 16-KiB harness then passed in the exact-speed 4.772728-MHz 8088
86Box configuration while its generated floppy image was host mode `0444`.
The host denied a write-only open and the before/after image hash was
unchanged. WE1-to-current-leaf took 984 ticks, leaf-to-CV took 986 ticks,
commit and canary unlock passed, and the complete path made 34 BIOS reads; the
guest contains no disk-write service. A sector cannot be read directly at the
32-byte `0x3e40` canary slot because it would cross `0x4000`; the passing
callback stages at retired `0x0700` and copies exactly 32 bytes. This proves
the fixture-fed PoC's write independence and actual post-Finished
arithmetic/phase cost, not a physical write-protect mechanism or live chain.

Parser outputs at `0x3600..0x3790` may replace handshake/application state only
after Finished verification, application-key derivation, and every outstanding
HEAD/ticket record's tag has verified and drained at an exact record boundary.
The final composition implements live FO objects, direct target entropy,
same-boot resumption, and the dated exact-leaf possession path. General live
identity-material handoff into the issuer-authorized parser/auth overlays and
a trusted certificate-validity-time policy remain open.

`tools/crypto-bench/tls13-spike/integrated_spike_results.json` freezes the
pre-final decision, including the literal K14 full-chain fixture, the historical
three-run deadline ledger, and the distinct post-Finished canary.
`integrated_spike_check.py` verifies their component hashes,
measurement-source hashes, exact decision inputs, and the explicit
`secure_floor_proven=false` / `product_replacement_authorized=false` gates.
Keep those flags as the historical ledger rather than rewriting the generated
JSON around the later composition. The final artifact implements live FO,
dated exact-leaf CertificateVerify, automatic pre-network floppy-timing
collection, failure close/zeroization, target resumption/recovery, and atomic
credential unlock. Its two exact credentialed functional runs pass. Physical
entropy characterization, trusted-time/rotation policy, provider repetition,
external review, and the NIC matrix still follow.

## Invariants during the spike

The completed product runtime/driver split is the baseline, not a refactor
target:

- `SEED.SYS` remains the first FAT data file on the IBM PC images.
- The reserved loader and ROM BASIC sidecar continue to enter the same
  `SEED.SYS`.
- `SEED/DRIVERS/*.DRV`, the SDRV metadata, the vtable ABI, driver selection, and
  the one-sector active-driver slot remain unchanged.
- Inactive NIC drivers continue to cost zero resident RAM.
- The 16 KiB entry remains the ROM BASIC sidecar; direct BIOS boot remains
  available at 32 KiB and above.
- The IBM PC handoff at `0000:0600`, 8086 opcode floor, text-mode UI, failure
  behavior, and persistence rules do not change.
- The spike does not introduce a general module loader, protected mode, a new
  local-tool ABI, or a second production TLS stack.

The implementation spike may use isolated host tools, captured transcripts, and
temporary experimental source paths. A production checkpoint must contain the
chosen implementation only, with diagnostic shortcuts and duplicate TLS 1.2
code removed.

## Current architecture summary

Seed currently has one IBM-PC target and one file-backed runtime contract:

- stage 1 plus a four-sector reserved FAT12 loader finds root `SEED.SYS`;
- only the four-sector / 2,048-byte nucleus is loaded initially;
- the same on-disk `SEED.SYS` contains demand-loaded low phases and the pinned
  15-sector K TLS/API window;
- the 16-KiB machine enters through the ROM BASIC sidecar because conventional
  BIOS boot address `0x7c00` is outside installed RAM, while 32 KiB and larger
  machines retain direct boot;
- one selected one-sector NIC driver occupies the active slot; all other
  current product drivers remain on disk and cost no resident RAM;
- current TLS 1.2 uses the RSA leaf plus WR1 trust path and a 286-only high
  secure-module overlay; the functional 8088 path is not yet the proposed TLS
  1.3 secure path;
- the current persistent low-memory product floor is 96 bytes of executable
  arena plus 96 bytes of context at 16 KiB, and 224/224 bytes at 32 KiB.

There is no current 64-bit addressing or no-BIOS implementation. Those are
native modern-slice concerns: widen addresses inside x64/AArch64 payloads and
enter them through UEFI shims. Do not burden PC16 with a universal 64-bit
pointer model or make the old machine parse PE/ELF merely to share a download.

## Constraints and hard limits

| Constraint | Nature | Architectural consequence |
|---|---|---|
| 16 KiB ends at `0x4000`; ROM BASIC loader begins at `0x3a00` | hard for the headline profile | the resident prefix loaded at `0x1000` must sector-round to end no later than `0x3a00`, with stack/product state separately proven; the cold file may be larger |
| BIOS boot sector executes at `0x7c00` | hard on 16/24-KiB machines | preserve ROM BASIC entry; do not replace it with a conventional boot-only design |
| stage 1 is 512 bytes and reserved loader is four sectors | current release contract | architecture selection and security phases belong after the existing handoff, not in stage 1 |
| `cpu 8086`, real mode, no graphics-mode switch | current target contract | no 286 instructions, protected mode, or firmware dependency in PC16 |
| current K is exactly 15 sectors with zero slack | measured implementation limit | TLS replacement must be phase-linked; isolated component sizes cannot be added or called a K fit |
| loader now accepts a 32-bit `SEED.SYS` size but still reads only the declared resident prefix | implemented and regression-gated | cold phase growth is now bounded by media and the compact phase-call offset, not the former 65,024-byte arithmetic |
| direct-boot resident prefix may be at most 55 sectors / 28,160 bytes | hard while the loader stack remains at `0x8000` | the normal four-sector nucleus is unaffected; corrupt or future headers cannot load through the `0x7e00..0x7fff` stack guard |
| compact phase call has an 8-bit sector offset | correctable implementation ceiling near 128 KiB | widen before any phase start reaches offset 256; offsets 0..255 are valid and the on-disk table is already wider |
| observed provider pre-Finished close is about 15 seconds on the P-256/RSA probe profile | cross-profile measured behavior, not a protocol or SLA hard limit | repeat held-Finished timing on the selected candidate and establish integrated margin |
| API credentials and trusted product effects must remain unreachable before full proof | security hard limit | provisional Finished/HEAD/ticket state stays quarantined and literal; one atomic commit unlocks credentials |
| cold boot cannot depend on a modern helper or prior ticket | product/security hard limit | entropy, KeyGen, tables, proof, and restart handling must be generated by the original machine |
| Current product driver files, metadata, selection, vtable, and active slot are stable | scope hard limit | the security architecture wraps the existing NIC/TCP path rather than refactoring drivers |

## Recommended packaging architecture

### User-facing shape

Use firmware-native shims behind one logical Seed package:

```text
Seed recovery package
├── classic 160 KiB IBM PC image
│   ├── BIOS sector-0 + reserved x86 loader
│   ├── SEED.SYS (PC16 slice, first FAT data file)
│   └── SEED/... (drivers, prompts, config, leaf)
└── universal removable-media image
    ├── BIOS sector-0 entry
    ├── EFI/BOOT/BOOTX64.EFI
    ├── EFI/BOOT/BOOTAA64.EFI        (when AArch64 exists)
    └── SEED/SEED.PAK
        ├── fixed manifest
        ├── PC16 payload slice
        ├── x64 payload slice
        ├── AArch64 payload slice
        └── shared assets
```

This is one product contract, even if physical-media constraints require a
classic floppy image and a capacious universal image inside the download. A
160 KiB disk cannot physically carry future x64 and AArch64 payloads; that is a
carrier-capacity limit, not a reason to ask users to understand architectures.
A future image writer can choose the appropriate carrier image from the
destination, while the booted medium selects its payload without user input.

The standard UEFI removable paths select the native EFI shim. BIOS executes the
legacy boot sector. Within the x86 BIOS path, a small 16-bit selector can detect
CPU capabilities before choosing a PC16/386+/x64-capable payload. An AArch64
machine cannot execute the x86 selector, and x64 UEFI does not need to execute
the legacy sector, so small native entry shims are an unavoidable internal
detail. They are not separate user-facing products.

### Payload-container rules

If/when modern payloads require a container, keep it deliberately narrower than
a general executable/module format:

```text
magic + format version
entry count
per entry:
    architecture / firmware kind
    minimum CPU and RAM
    file offset and stored length
    load/entry contract
    integrity digest
```

The legacy slice should be first and independently bootable. The 8088 path
should not parse PE, ELF, or a general-purpose fat-binary format. Native modern
shims may parse the fixed manifest and load only their slice. Shared immutable
assets may remain separately addressable where that avoids duplicating them.

Do not introduce `SEED.PAK` merely to make the current file look smaller. The
current `SEED.SYS` is already an on-disk phase container, and most of it is
already loaded on demand.

## Current `SEED.SYS` and loader limits

### Measured current artifact

From `build/ibm_pc_5150/SEED.SYS` and `tools/core-sys-info.py` at the branch
baseline:

| Item | Current value | Status |
|---|---:|---|
| `SEED.SYS` file | 53,760 B / 105 sectors | measured |
| Initial resident load | 2,048 B / 4 sectors | measured |
| Resident nonzero bytes | 1,495 B | measured |
| K TLS/API window | 7,680 B / 15 sectors at `0x1800` | measured |
| Cold phase count | 29 | measured |
| Phase-table offset | 40,995 B | measured |
| 286 P-256/RSA/X.509 module file | 12,066 B | measured |
| Secure-module budget | 12,288 B / 24 sectors | measured |
| Secure-module byte slack | 222 B | measured |

Only the four resident sectors are loaded by the reserved loader. The runtime
loads K and cold phases later. The 286 secure module is loaded only on that
tier. Therefore:

> Increasing or splitting the on-disk file does not by itself reduce live RAM.

It creates file/offset/media headroom. Arena/context growth requires a smaller
pinned window, a smaller reconnect-safe state block, removal of a duplicate
resident copy, or a higher-memory placement.

### Current implementation ceilings

The rearchitecture branch removes the reserved loader's former 65,024-byte
ceiling without increasing its four-sector footprint or changing the
resident-only load contract. It now retains the FAT directory entry's full
32-bit file size and compares the header's resident byte extent against that
size without 16-bit rounding overflow. It still reads only the resident
prefix.

`tools/check-loader-large-core.py` executes the real assembled loader at
`0000:0600` over a deterministic synthetic FAT12 image. The large-file positive
gate accepts a 70,000-byte `SEED.SYS`, reads exactly its four declared resident
data sectors, jumps to `0000:1000`, and leaves the cold tail untouched. A
stack-safe negative declares four resident sectors for a file whose rounded
size covers only three, isolating the file-size rejection. A 2,047-byte
four-sector control preserves the predecessor's partial-final-sector contract.
Separate gates reject the first stack-colliding 56-sector resident extent and
accept the exact 55-sector maximum through `0x7dff`, retaining
`0x7e00..0x7fff` for the active loader stack.

The remaining whole-file ceiling on the current 160-KiB artifact is therefore
the carrier and FAT12 cluster space, not a 16-bit loader-size calculation.
Larger media would encounter runtime phase addressing before the FAT directory
size field.

The next ceiling is runtime phase dispatch. Its compact call key packs:

```text
AL = sector offset from the start of SEED.SYS
AH = sector count
```

Phase starts are consequently limited to offsets 0..255, roughly the first
128 KiB of `SEED.SYS`. The on-disk phase table already stores 16-bit sector
offsets and counts, so this is a compact runtime-call ABI limit rather than a
file-format limit.

### Loader evolution, only when needed

Migration should be incremental:

1. Keep the corrected 32-bit loader validation and resident-only regression
   gate.
2. When phase growth reaches the 8-bit offset boundary, widen the internal phase
   load request to carry a 16-bit sector offset separately from its count.
3. Use a second fixed payload file/container only when modern architecture
   slices or medium size make that simpler than extending `SEED.SYS`.

Cold code and data can be streamed from floppy, and current cold phases already
are. The current product path preloads timing-critical work, but the exact-floor
PoC also proves that selected bounded, track-aligned phase reads can occur after
TCP opens when the complete read schedule retains measured deadline margin and
never advertises receive capacity for bytes whose destination is unavailable.
Moving code to another file is therefore not automatically safe or unsafe; the
gate is its exact lifetime, disk schedule, TCP window, and wire timing.

Compression is a media-size option, not an arena win. It also adds decoder code,
scratch, and 8088 cycles, so it should be evaluated only against an actual
carrier-capacity problem.

## Memory baseline and projections

The **arena is the executable area** advertised to `$w`/`$x`; there is no third
executable allocation. The tables below preserve the current 50/50
arena/context policy unless stated otherwise.

### Current measured low-memory layout

| Tier | Pinned K | User pool | Executable arena | Context | Other important bands |
|---|---:|---:|---:|---:|---|
| 16 KiB ROM BASIC | 15 sectors / 7,680 B | 192 B | 96 B | 96 B | 2,048 B nucleus; 256 B stack guard |
| 32 KiB direct | 15 sectors / 7,680 B | 448 B | 224 B | 224 B | 512 B tools cache; 28-sector loop/secure-overlay band; 1,536 B stack guard |

The 32 KiB high band is `0x4200..0x7a00`. During normal turns it caches the
floppy-free loop. During a 286 handshake it instead holds the secure module and
leaf-capture tail; those lifetimes are disjoint. K itself still executes from
the low `0x1800..0x3600` band, so a 32 KiB pre-286 machine stores a second copy
of K in the normal-turn cache.

### Initial conventional-P-256/RSA K projections

These are calculated layout outcomes from the first, now-rejected
P-256/RSA profile. They remain useful arithmetic for any eventual K size but
are not claims that the ML-KEM/ECDSA phase architecture reaches it:

| Layout hypothesis | User pool | Executable arena | Context | Status / assumption |
|---|---:|---:|---:|---|
| 16 KiB, K remains 15 sectors | 192 B | 96 B | 96 B | calculated: no memory regression |
| 16 KiB, staged K14 | 192 B persistent + 512 B ephemeral phase-owned space | 96 B persistent | 96 B persistent | measured phase implementation; reconnect reuses the released sector, so it is not user arena |
| 16 KiB, relinked/repacked K14, executable-first | at most 704 B contiguous | 608 B | 96 B | calculated upper bound; requires a new phase/high-state schedule, all memory/wire/reconnect/tool/ENV gates, and a non-50/50 split policy |
| 16 KiB, relinked/repacked K14, balanced | at most 704 B contiguous | 352 B | 352 B | calculated upper bound with the same new schedule and gates; matches the current 50/50 policy |
| 16 KiB, K becomes 13 sectors | 1,216 B | 608 B | 608 B | calculated stretch case |
| 32 KiB, K remains 15 sectors | 448 B | 224 B | 224 B | current measured baseline |
| 32 KiB, K=14; high cache stays 28 sectors | 960 B | 480 B | 480 B | calculated conservative TLS 1.3 case |
| 32 KiB, K=14; high cache shrinks to 27 sectors | 1,472 B | 736 B | 736 B | calculated; secure module plus capture must also fit 27 sectors |

A 14-sector file alone produces no persistent arena gain. The staged K14 link
reuses the reclaimed `0x3400..0x3600` sector as phase-owned space while leaving
reconnect/high-state addresses stable. Treating it as user code would corrupt
that code on reconnect. The 704-byte figure is only a calculated upper bound:
moving following product bands down by 512 bytes collides with the passing
K14 control-state lifetime, so a persistent pool first needs a different
linked phase/high-state schedule.

The 27-sector high-cache result is conditional. The secure overlay currently
uses:

```text
24 sectors  P-256 + RSA + X.509 module budget
 3 sectors  maximum captured leaf
-----------
27 sectors  secure handshake requirement
```

TLS 1.3 changes the in-race RSA proof from TLS 1.2
ServerKeyExchange/PKCS#1 v1.5 to CertificateVerify/RSA-PSS. The existing module
has only 222 bytes of slack. If the replacement module grows to 25 sectors, its
25-sector module plus 3-sector capture tail requires the existing 28-sector
band. In that case the conservative 32 KiB K=14 result is **480 B arena + 480 B
context**, not 736 B + 736 B. The spike must report actual unpadded module bytes,
sector extent, capture extent, and remaining slack.

### High-linked K option for exactly 32 KiB pre-286 machines

On pre-286 32 KiB machines, a CPU-specific K image could be linked to and
executed directly from the high normal-turn cache. That removes the low
resident K copy and lets the low state following it repack downward.

| Pre-286 32 KiB hypothesis | User pool | Executable arena | Context | Status / assumption |
|---|---:|---:|---:|---|
| High-linked current 15-sector K; current cache | 8,128 B | 4,064 B | 4,064 B | calculated after a full low-band repack |
| High-linked 14-sector TLS 1.3 K; 27-sector cache | 8,640 B | 4,320 B | 4,320 B | calculated; K and normal-turn set fit the smaller cache |
| K=14 kept high; stream every other normal-turn asset | 15,808 B | 7,904 B | 7,904 B | calculated upper bound; gives up floppy-free ordinary turns |

This should be a separate experiment after the TLS 1.3 replacement is sized.
It requires a second link address or relocation scheme and multiplies code-path
validation. It is attractive only if the build can select the slice
transparently.

It does **not** apply cleanly to an exact-32-KiB 286 secure handshake: high-linked
K must execute while the P-256/RSA module occupies the same high overlay band.
The current secure layout keeps K low precisely so both coexist. A machine with
more RAM can place one of them elsewhere; exact 32 KiB must retain low K or
design a different non-overlapping secure pack.

The 50/50 policy is also not a hard limit. If executable workspace is the
product priority, examples with a minimum useful context reserve are:

| Hypothesis | Executable arena | Context | Status |
|---|---:|---:|---|
| 16 KiB, relinked/repacked K14, 96 B context floor | 608 B | 96 B | calculated upper bound after a new lifetime schedule, full gates, and split-policy change |
| 32 KiB pre-286, high-linked K=14, 2 KiB context | 6,592 B | 2,048 B | calculated policy alternative |

Policy changes should follow, not precede, measured TLS sizing.

## Candidate architecture options

| Option | Arena/code effect | Secure-floor effect | Decision |
|---|---|---|---|
| Keep TLS 1.2 and add a second TLS 1.3 stack | worst: duplicate protocol/crypto code competes with K and cold-phase space | preserves a fallback but does not prove one uniform secure floor | reject as the final architecture; retain TLS 1.2 only while the replacement is research |
| Conventional TLS 1.3 with ordinary X25519MLKEM768 and complete authentication before client Finished | no unusual quarantine state, but full crypto must remain in the timed path | ordinary server-dependent X25519 alone is 45.753 s; complete ML-KEM decapsulation alone is 24.845 s | reject for the 4.77-MHz floor |
| Lower the 8088 to an unauthenticated or credential-bearing provisional tier | smallest apparent implementation | violates the headline functional/security contract and exposes product traffic before identity | reject |
| One monolithic 16-KiB TLS 1.3 image | simple control flow, but cannot coexist with the current nucleus/K/TCP/arena layout demonstrated here | standalone arithmetic fit is misleading because KeyGen output and the nucleus are overwritten by later images | reject until a link proves otherwise; not the working hypothesis |
| Phase-stream the proof and rely only on periodic credential-free HEAD requests | maximizes overlay reuse and keeps the original machine self-contained | plausible 25-second checkpoints, but depends on provider liveness and live floppy/TCP scheduling | viable fallback experiment, too fragile as the primary recovery mechanism |
| Phase-stream the proof, capture one tentative ticket, finish retrospectively, then resume if needed | same overlay advantage; adds bounded volatile ticket/binder state | original proof remains mandatory; a promoted same-boot ticket removes repeated Brotli/ECDSA after close but still requires fresh KEM | **recommended research architecture** |
| Precompute per-boot work on a modern helper | could minimize the legacy image | fails restart independence and the explicit self-contained-machine requirement | reject |

The packaging decision is separate from the security phase decision:

| Packaging option | User experience | Decision |
|---|---|---|
| A visible fleet of CPU/firmware-specific floppy downloads | requires the user or technician to classify machines | reject |
| One 160-KiB file containing PC16, x64, and AArch64 | impossible once payloads exceed the carrier capacity | reject as a physical format, not as a product goal |
| One Seed download/writer with a classic image and a universal image selected automatically, then native shims select the payload | one product choice; internal architecture slices remain hidden | recommended |

## TLS 1.3 replacement shape

### Research compatibility profile

The candidate remains a narrow OpenAI-specific implementation, not a general
TLS library:

```text
protocol         TLS 1.3 only
cipher suite     TLS_CHACHA20_POLY1305_SHA256
wire key share   X25519MLKEM768
effective KEX    ML-KEM-768 only; fixed X25519 u=9 research deviation
signature        ecdsa_secp256r1_sha256
timing fixture   Brotli-compressed Certificate
parser-first PoC omit certificate compression; measure the larger flight
SNI              selected endpoint
application      existing HTTP/1.1 + Responses SSE path
quarantine probe literal credential-free HEAD /v1/models only
excluded         TLS 1.2 fallback, 0-RTT, client certificates,
                 persistent PSKs, generic cipher/group negotiation
```

There are three independent review boundaries:

1. The client contributes a genuine ML-KEM public key but uses the canonical
   X25519 base-point coordinate `u=9` and copies the server's returned X25519
   share as that component of the concatenated secret. It does not perform
   genuine X25519.
2. It derives provisional handshake keys from the K-PKE candidate before
   completing ML-KEM's re-encryption/compare/implicit-rejection path.
3. It sends client Finished and fixed application probes before validating the
   certificate and CertificateVerify. This preserves TLS wire ordering but
   violates the normal TLS peer-authentication processing order.

The first two boundaries disappear if the provider offers a pure ML-KEM group
and the client completes standard decapsulation before Finished. Deferred
authentication disappears only if certificate and CertificateVerify
validation also finish before client Finished. A pure group is still the
preferred key-exchange escape hatch. Exact complete decapsulation is
24.845 seconds in the literal 16-KiB 86Box configuration, so conventional
pre-Finished decapsulation does not fit even before the symmetric flight.

Ordinary X25519 is not a fallback for this floor. The correctness-gated
RFC 7748 server-dependent scalar multiplication measured 45.7529 seconds on
the original-speed 8088. Moving client public-key generation before TCP saves
another 45.5881 seconds from the race but cannot move the peer-dependent
operation.

### Self-contained phase sequence

The security boundary is
`speculate -> provisional key confirmation -> authenticate -> commit`:

1. **Freshness gate before TCP**
   - On the read-only route, perform 256 successful one-sector BIOS reads
     alternating CHS `0/0/1` and `39/0/8`. Latch PIT channel 0 before and after
     each completion and SHA3-256-condition the events into two
     domain-separated, one-shot 128-byte attempt bundles.
   - Perform the complete collection before DHCP or any other network
     transmission. Card-vault both bundles before network-controlled work can
     reuse the low output window.
   - Treat the PIT only as the measurement clock. Elapsed time, BIOS ticks,
     nominal timer resolution, emulator time, MAC addresses, and network
     timing receive zero entropy credit by themselves.
   - 86Box can validate the controller mechanics and full route but contributes
     zero credited bits. Physical drives require representative raw traces,
     conservative min-entropy analysis, and calibrated source-health gates
     before this route can establish restart freshness.
   - If physical floppy timing proves insufficient, investigate natural
     keystroke timing as a separate fallback source. Do not require the user to
     enter random characters or values.
   - On writable media, a durable ratchet may remain an additional source and
     recovery mechanism, but it is not required for read-only boot.
   - A copied or rolled-back writable floppy is outside any no-secure-storage
     replay guarantee. This must be explicit in the threat model.

2. **Self-preparation before TCP**
   - Generate a new ML-KEM-768 keypair on the 8088.
   - Retain or safely hand off the exact 2,400-byte expanded key generated by
     the KeyGen phase. The exact overlay already computes `H(ek)`; the product
     link must preserve that object in RAM without a modern helper, boot-media
     spill, or overwrite.
   - Generate small P-256 tables on the same machine. ML-KEM matrix
     coefficients are regenerated with SHAKE128 and consumed four at a time,
     so no public matrix cache or cache-integrity protocol is required. Keep
     all attempt-secret state — the expanded ML-KEM key, ECDSA tables,
     candidate secrets, and derived PSKs — in RAM. The required read-only path
     never spills it to boot media. If a later RAM layout slices a generated
     object's lifetime, regenerate each slice locally and verify it against
     its exact constraints under an attempt-local digest.
   - API-key bytes are absent from provisional RAM and loaded only after
     commit. Prompt, context, tool state, saved tickets, and the real request
     constructor are likewise unavailable. If prior UI key entry becomes
     unavoidable, store it outside every precommit network/parser overlay and
     give no precommit routine a pointer to it.

3. **Timed candidate**
   - Send exactly the frozen profile above and reject HelloRetryRequest,
     fallback, alternate groups/ciphers/signatures, and unexpected record
     transitions.
   - Derive the provisional candidate from `K-PKE.Decrypt` plus
     `G(m' || H(ek))`. One ciphertext gets one fresh secret key and one
     connection; no retry may reuse either.
   - Hash the exact hybrid ServerHello and derive only the handshake material
     required for the next gate.

4. **Strict pre-Finished gate**
   - Incrementally verify every encrypted-handshake record's AEAD tag under the
     provisional traffic key, decrypt it, and update the frozen transcript.
     This verifies provisional-key possession, not server identity.
   - Decrypted bytes, extracted messages, and the running transcript remain
     tentative; no inner message may affect accepted state until the complete
     containing record's tag passes.
   - Bound and stage only the Certificate and CertificateVerify material
     needed later.
   - Verify the exact server Finished before emitting client Finished. This is
     key confirmation under the provisional candidate, not yet server-identity
     authentication.

5. **Credential quarantine**
   - Send client Finished, derive the minimum application traffic state, and
     immediately send one immutable literal `HEAD /v1/models` request with the
     correct public Host header.
   - The probe contains no Authorization header, API key, cookie, prompt,
     model, context, redirect target, server-derived byte, or user/device/
     account/session/request identifier beyond protocol-required public SNI,
     Host, and ordinary network metadata.
   - Verify each response record's AEAD tag under the provisional key before
     draining one small bounded HTTP header block. Keep one request outstanding
     at a time and require an unambiguous response boundary. Status/header
     values cannot alter proof state or scheduling; redirects are never
     followed. Response completion may only permit the next fixed probe or
     cause an abort. Reject a body, upgrade, interim response, or oversized
     input, and preserve TLS sequence numbers continuously.
   - During provisional state, accept only AEAD-valid application bytes for the
   single outstanding HEAD and one to four strictly bounded tentative
   NewSessionTickets. Retain only the first ticket and tag-verify and drain the
   rest without changing proof state. Reject KeyUpdate,
   CertificateRequest/post-handshake
     authentication, unexpected handshake messages/inner types, upgrades, and
     key-epoch changes. Alerts only terminate the attempt.
   - A HEAD request is intended to be safe, but it is not operationally
     invisible: the provider may log, rate-limit, fingerprint, or count it.

6. **Retrospective authentication**
   - Complete standard ML-KEM re-encryption and require constant-time
     `c' == c` to succeed. Compute `J(z || c)`, implicit-rejection selection,
     and the selected standard ML-KEM shared secret regardless; require that
     selected secret to equal the provisional ML-KEM candidate. Re-derive and
     compare the TLS key/IV bundle without resetting live record sequence
     numbers.
   - Parse the bounded uncompressed Certificate body. If compression is
     retained as a later optimization, bounded-decompress the 1,799-byte
     CompressedCertificate into the exact 2,491-byte Certificate body while
     hashing the original compressed handshake bytes in the transcript.
   - Parse the leaf, verify hostname/trusted-time/key-usage policy, verify its
     signature under the pinned WE1 key when recertification is required, and
     verify the saved TLS CertificateVerify under that leaf against the frozen
     transcript. Plain unauthenticated NTP is not a trusted time source; the
     integrated design must supply an authenticated persisted lower bound,
     trusted user-set time, or an explicitly weaker expiry policy.
   - A leaf may bypass the WE1 signature only with immutable trusted pin
     provenance or after WE1 revalidation during this boot. Mutable persisted
     adoption never creates a cold-boot trust root.
   - Interleave another fixed HEAD only at a clean crypto checkpoint when the
     preceding response is completely drained.

7. **Atomic commit**
   - Promote the live connection, accepted leaf, and any received ticket in one
     state transition only after every proof succeeds.
   - Only committed state loads API-key bytes and the real request constructor.
   - AEAD/server-Finished failures close before client Finished and are
     observably part of the admitted one-shot provisional key-confirmation
     oracle. After client Finished, aggregate KEM, certificate, pin, and CV
     failures into one fixed close checkpoint: no differing alert, probe
     cadence, retry behavior, ticket promotion, persistence, or real request.
     Zeroize all tentative state and never persist a learned pin.

The candidate promotion argument is retrospective and conditional: if
standards-complete ML-KEM selects the same provisional candidate, re-derived
TLS material matches, the server Finished is valid for the frozen transcript,
and the current leaf plus CertificateVerify validate, then the existing
application traffic secrets match those a normally authenticated handshake
would have produced. Earlier HEAD traffic remains an untrusted external effect
and cannot be undone; that is why it is literal, credential-free, bounded, and
semantically ignored. Independent review still has to validate this argument.

### Provider liveness and live wire geometry

Live probes on 25 July 2026 established the following dated behavior. The
held-Finished close bracket used the P-256/RSA profile. The post-Finished
KeyUpdate/HTTP experiments used a standards-complete host OpenSSL handshake.
Neither exercised fixed `u=9`, provisional pre-FO use, nor Seed target
networking:

| Experiment | Result |
|---|---|
| Hold client Finished 12 s | accepted |
| Hold client Finished 15 s | upstream closed before release |
| Repeated requested TLS KeyUpdate | batched near 15 s, then close; no extension |
| Slowly drip an incomplete HTTP header | reset near 15 s; no extension |
| Six complete unauthorized GETs through 25 s | six responses; alive at 30 s |
| Seven complete unauthorized HEADs every 25 s | seven responses; alive at 155.033 s when stopped |

Client Finished ends the original race. Of the mechanisms tested, only complete
application dialogue reset the observed edge idle behavior. The result does not
promise a stable status code—live runs returned 401 and 503—so liveness must
depend only on a bounded complete response, never its semantics. Response
completion is solely a transport-liveness observation, never an authentication
or commit signal.

The complete nonconforming hybrid proof used a genuine ML-KEM keypair and
standard decapsulation in the host harness:

| Item | Bytes |
|---|---:|
| ClientHello handshake | 1,376 |
| ServerHello handshake | 1,210 |
| protected server record, wire | 1,947 |
| EncryptedExtensions | 10 |
| CompressedCertificate | 1,799 |
| CertificateVerify | 80 |
| server Finished | 36 |
| client Finished record, wire | 58 |

The host harness verified the complete server-flight AEAD tag and server
Finished under keys from conventional OpenSSL ML-KEM decapsulation, sent client
Finished, and received a NewSessionTicket while sending no application data or
credential. A later host run sent one compiled credential-free HEAD, validated
two tickets, and exercised the strict tentative state machine. Those host runs
did not execute the provisional split or Seed target networking. The separate
exact-floor target canary now performs its own credential-free HEAD and ticket
capture through production NE.DRV, but a ticket still does not extend the
pre-Finished race.

A separate fresh/resumed host/OpenSSL observation used the required ChaCha20
cipher and X25519MLKEM768 group. The resumed handshake reported PSK and
key-share extensions; the frozen text parser flattened extension reports
across the server handshake and did not retain their containing-message
attribution. The protected resumed flight contained only EncryptedExtensions
and Finished, with no Certificate or CertificateVerify. This establishes
current provider support for ticket-assisted recovery, not a target
implementation or provider SLA.

The exact v1 measurement source is retained beside the corrected current v2
probe. The frozen v2 result is explicitly an offline curation: it preserves the
observed values and output hashes, renames the flattened extension fields, and
records the missing message attribution without claiming a network rerun.

Tickets are fallback only. A NewSessionTicket stays tentative until the same
atomic commit, remains volatile by default, is never used for 0-RTT, and must
not replace fresh key exchange. If the current socket survives, continue on it
and avoid a second KEM. If an AEAD-valid tentative ticket arrives and the socket
dies while proof work continues, finish the original session's proofs and
atomically promote the ticket—not the dead connection—only if all succeed.
Bind it to endpoint/SNI, ALPN, cipher/profile, authenticated leaf policy, age,
and lifetime. Resume with PSK-DHE plus a fresh one-shot KEM key, reject
`psk_ke`, verify resumed server Finished before real data, and never use 0-RTT.
Cold-start security must never depend on a ticket.

### 16 KiB phase and media consequences

The K15 and K14 phase containers prove their fixture-fed handoffs across the
entire literal 16-KiB address map. Their cold files are larger than RAM because
only one phase and the deliberately retained state are live at a time:

| State/code item | Measured size / placement | Lifetime |
|---|---:|---|
| resident file prefix | 2,048 B / four sectors loaded at `0x1000..0x1800` | initial entry contract |
| permanent scheduler nucleus | `0x1000..0x1600` | whole run |
| active NIC driver slot | 512 B, `0x1600..0x1800` | replaces the prefix's fourth sector for the network attempt |
| expanded ML-KEM decapsulation-key object | 2,400 B split across low/high bands | KeyGen through candidate/FO handoffs |
| server ML-KEM ciphertext | 1,088 B in low phase storage | candidate through `J(z || c)`, re-encryption, and compare |
| KeyGen overlay | 2,871 B / 6 sectors | pre-TCP |
| HELLO overlay | 4,132 B / 9 sectors | fresh/resumed ClientHello, both legal fresh ServerHello extension orders, ticket-request variant, and transcript handoff |
| provisional-candidate overlay | 2,113 B / 5 sectors | timed path |
| symmetric overlay | 6,142 B / 12 sectors | timed protected flight, Finished, live ticket-extension profile, sequence-exhaustion guard, and resumption |
| exact FO overlay | 2,829 B / 6 sectors | quarantined post-Finished |
| exact adopted-leaf authentication | 6,632 B / 13 sectors | quarantined post-Finished |
| issuer-authorized real-chain authentication | 7,134 B / 14 sectors | cold/rotation fallback |
| entropy overlay | 2,076 B / 5 sectors | pre-TCP durable ratchet |
| whole cold phase container | 79,872 B / 156 sectors | floppy only; four sectors resident initially |
| current executable arena/context | 96 B / 96 B | untouched across every phase |

K14's exact additional placements are:

```text
logical K                 1800..33ff  (14 sectors)
SYM preload               1800..2fff  (12 sectors)
HELLO dirty prefix        1800..29ff  (9 sectors)
preloaded SYM suffix      2a00..2fff  live through HELLO/candidate
SYM prefix restore        1800..29ff  (9 sectors)
ServerHello disk stage    3400..35ff  before SYM controller/runtime is live
SYM controller            3400..34c4
SYM runtime tail          3510..355c
protected-flight stage    0e00..0fff
candidate handoff         0700..077f  fixture-only; overlaps live NIC RX
FO public-stream stage    3400..35ff  after SYM releases the extension
```

The live canary sibling uses a different, checked lifetime schedule:

```text
NIC RX frame              [0700,08b6)
temporary K' handoff      08c0..08df  copied/zeroized around sym_init
protected/post controller 0900..0cff  mutually exclusive, loaded after ciphertext
transcript/quarantine     0d00..0eff  transcript first; scatter after import
track-batched loader      0f00..0f91  installed after HELLO commits
scatter continuation      3600..3837,3920..3b3f after authenticated decrypt
application state gap     3838..391f  both directions' retained TLS state
native ticket state       3b40...     bounded first ticket and derived PSK
product arena/context     3e40..3eff  zero harness writes
crypto-controller code    3400..34b0
embedded loader source    34b1..3542  dead before overlapping SYM runtime
SYM runtime tail          3510..355c
```

BIOS reads write the complete 512-byte destination sector even when the useful
fixture chunk is only 384 bytes. The K14 gate derives those stage addresses,
sector counts, controller bounds, and candidate handoff endpoints from the
assembled sources and rejects overlap with each phase's live objects.

The viable layout is a sequence of mutually exclusive K-window images, not one
sum of all code and data:

```text
entropy/keygen -> timed KEM+TLS -> full KEM validation
               -> DER/ECDSA slices interleaved with liveness
                  (+ bounded Brotli only if compression is retained)
               -> committed application TLS/API loop
```

The existing SEED.SYS phase mechanism is sufficient in principle; this does
not justify a general module ABI. Any floppy phase swap while TCP is alive
must happen with no outstanding HEAD response, a closed/zero advertised receive
window, preserved TLS/TCP state, and a measured bound shorter than the
liveness cadence. The cached connector adds zero-window ACK/checksum, window
reopen, retransmit/RST, and timeout gates in 408 bytes. The exact-speed NE.DRV
trace now validates that path for one representative family; 3c501, 3c503, and
WD80x3 live traces remain regression work. The final composition integrates
the dated exact-leaf path; general target Brotli/parser segments and trusted
certificate time remain outside that chain.

The phase design reconstructs the timed image from the same `SEED.SYS` cold
tail. Whether a product retry may reread those sectors remains an explicit
policy decision; the present product rule says the normal retry path must be
floppy-free. Preserve enough reconnect/timed state to meet that rule or obtain
an intentional architecture change before product integration.

The current 96-byte arena and 96-byte context must remain outside every
handshake overlay. A benchmark merely fitting below `0x4000` is not enough.

### Earlier conventional-P-256/RSA size ledger

The following ledger remains useful as a measured comparison for the rejected
P-256/RSA profile. It is **not** a size claim for the ML-KEM/ECDSA candidate.

The auditable static gate is:

```sh
python3 tools/crypto-bench/tls13-spike/size_ledger.py
```

It assembles the current runtime plus the isolated HKDF, PSS, and flight
benches in a temporary directory and reads NASM label boundaries. It does not
edit or relink the product runtime. The resulting distinction is important:
the table below measures implemented pieces and exact deletion spans. It was
recorded before the later strict parser overlays and deliberately does not
retroactively treat those mutually exclusive phases as a direct K addition.

Current K is exactly full:

| K component | Bytes | Status |
|---|---:|---|
| Shared SHA-256/HMAC | 1,801 | measured |
| Shared ChaCha20 | 574 | measured |
| Poly1305, including fixed TLS 1.2 Finished wrapper | 699 | measured |
| TLS 1.2/profile logic | 4,436 | measured |
| Agent API exchange glue | 170 | measured |
| **K total** | **7,680 / 15 sectors** | measured; **0 B slack** |

The gate identifies 2,688 non-overlapping bytes that are unambiguously TLS
1.2-only: the fixed Finished Poly1305 wrapper, TLS 1.2 top-level handshake and
ServerHello/Certificate/SKE/SHD waits, PRF/master/key-block derivation,
CKE/CCS/Finished construction and retry path, TLS 1.2 application-record/AAD
builders, and the SKE/SHD/CKE parser-builder tail. Generic transcript,
buffering, sequence, nonce, compare, and streaming routines are deliberately
excluded from that deletion number even where the final TLS 1.3 code may
reshape them. The script prints every exact start/end label and byte count.

Implemented replacement pieces currently measure:

| Replacement piece | Executable bytes | Separate live data | Status |
|---|---:|---:|---|
| TLS 1.3 full/hot/critical HKDF schedules, labels, and descriptors | 849 | scratch is accounted by its liveness study | measured |
| RSA-PSS SHA-256 decoder | 272 | 74 B scratch + 256 B signature staging + 32 B hash; recovered EM aliases module RSA workspace | measured |
| Complete 4,327-byte encrypted-flight reference glue | 438 | bounded stream state/chunk buffer | measured benchmark reference |

The 438-byte flight figure is intentionally not treated as a direct product
addition: it contains benchmark counters, deterministic receive copying, and
fixed flight geometry. It is useful as a conservative implemented reference
for incremental AEAD-tag verification/decrypt/transcript work, while a
production path should reuse the existing receive and record scaffolding.

Exact arithmetic over the conservative deletion set gives:

```text
current K                            7680
- unambiguously TLS-1.2-only         2688
+ implemented HKDF                    849
+ implemented PSS decoder             272
-----------------------------------------
conservative carry-forward subtotal   6113

K=15 unknown-code allowance           1567
K=14 unknown-code allowance           1055
```

If the entire 438-byte flight benchmark glue is charged as though none of it
can replace/reuse current streaming code, the reference total is 6,551 bytes:
1,129 bytes remain for K=15 and 617 bytes remain for K=14.

This pre-link ledger originally made K15 credible and K14 plausible. The
product-shaped PoC now runs both deterministic linked chains on the literal
16-KiB target. K14 additionally passes derived controller/staging,
write-set, hostile-input, exact-symbol, and repeated NE.DRV on-wire deadline
gates. Safe live-linking of the existing certificate parser, issuer/ticket
coexistence, and the remaining NIC-family traces must still preserve those
fits.

For completeness, the current cold `L` phase is 1,209 bytes / 3 sectors. Its
TLS 1.2 PRF labels occupy 56 bytes and its old ClientHello literals occupy 34
bytes. Those cold bytes affect `SEED.SYS` and phase sizing, not pinned K or the
arena.

The secure module has a stronger static result. The current 12,066-byte module
has only 222 bytes below its 24-sector limit. The size gate builds, in a
temporary source unit, a proposed algorithm-neutral RSA ABI:

```text
input:  SI -> 256-byte RSA signature
module: RSA-2048/e=65537 recovery only
output: SI -> 256-byte recovered EM in module-owned rsa_sig workspace
        (pointer dies when the overlay unloads)

hot TLS 1.3 caller: PSS decode in resident K
off-race WR1 caller: strict PKCS#1-v1.5 SHA-256 validation
```

The K-side CertificateVerify staging requirement is 362 bytes
(`256 + 74 + 32`) and fits the existing `0x7800..0x7a00` 512-byte tail. The
recovered EM reuses the module's existing `rsa_sig` workspace, so it adds no
second 256-byte allocation. K must finish PSS validation before unloading or
overwriting the secure overlay.

The old 693-byte TLS 1.2 hot-verify span becomes a 176-byte generic
recover/conversion/PKCS#1-validation span. The off-race chain wrapper grows by
6 bytes and the following word alignment needs one byte less padding, for an
exact net module reduction of 512 bytes:

| Secure module layout | Bytes | Sector extent | Slack below 24-sector limit | Status |
|---|---:|---:|---:|---|
| Current | 12,066 | 24 | 222 | measured product |
| Generic-RSA-recover candidate | 11,554 | 23 | 734 | measured isolated transform |

Thus the proposed split has a measured 24-sector fit and even a 23-sector
candidate extent; PSS is not duplicated into the module. This is not yet a
production ABI or security checkpoint. It still needs integration, positive
and tamper gates, and a final module link before the layout may claim the
23-sector extent. With a 14-sector K, the normal-turn preload still requires a
27-sector high cache, so the candidate's 23-sector module plus 3-sector leaf
capture does not by itself shrink that cache below 27 sectors.

### Encrypted-flight and key-schedule target timing

The target flight benchmark models complete observed protected records,
including receive copies, incremental Poly1305 authentication, ChaCha20
decryption, and the SHA-256 transcript pass. All frozen tags, digests, block
counts, final inner types, and component checks passed.

The decisive candidate is OpenAI's Brotli-compressed ECDSA flight:

| 8088 component | BIOS ticks | Time |
|---|---:|---:|
| ChaCha20 + XOR/copy | 40 | 2.1970 s |
| Poly1305 + stream/copy | 66 | 3.6251 s |
| SHA-256 transcript | 21 | 1.1534 s |
| **complete protected flight** | **128** | **7.0305 s** |

Its protected payload is 1,942 bytes, containing a 1,799-byte
CompressedCertificate handshake that expands to the 2,491-byte Certificate
body. It takes six 384-byte TCP chunks. Brotli decode and certificate
validation are deliberately excluded from the pre-Finished timing because the
AEAD-verified compressed bytes and tentative transcript can be retained/bounded
for the quarantine phase; this is not server-identity authentication.

The critical HKDF schedule derives only the material needed through both
Finished messages. It independently validated the exact output bundle in
24 ticks / **1.3182 s**, versus 41 ticks / 2.2519 s for the earlier
application-complete hot schedule. Therefore:

```text
exact provisional K-PKE.Decrypt + G candidate    1.9004 s
strict compressed flight AEAD + transcript       7.0305 s
critical HKDF through Finished                    1.3182 s
---------------------------------------------------------
isolated nominal subtotal                        10.2491 s
```

This leaves a nominal 4.7509 seconds against the P-256/RSA probe's 15-second
working close bound for hybrid ServerHello hashing, parser/TCP work,
client-Finished AEAD/transmit, and immediate application-key/HEAD setup. The
KEM and critical HKDF values are exact literal-16-KiB results; the compressed
flight used the 64-KiB BIOS-entry harness with a statically `<0x4000` layout.
This historical sum combined isolated artifacts and was not a safe budget.
The linked literal target result supersedes it with 225 ticks / 12.358 seconds
for candidate load/compute, symmetric restore, protected-flight fixture reads,
critical schedule, server Finished verification, and exact client Finished
construction. The credential-free live sibling then closes the old
NIC/TCP/transmit omission with three 13.483030–13.536609-second host-wire
deadline passes. Its successor extends that evidence with the 13.404952-second
Finished, provisionally tag-verified HEAD response, and two live tickets described in the
central result above.

For comparison, the earlier uncompressed profiles measured:

| Machine / profile | BIOS ticks | Flight time | Status |
|---|---:|---:|---|
| 8088 at 4.77 MHz, compact ECDSA | 172 | 9.4472 s | measured, `CHECK PASS` |
| 8088 at 4.77 MHz, RSA | 282 | 15.4890 s | measured, `CHECK PASS` |
| 286 at 6 MHz, compact ECDSA | 43 | 2.3618 s | measured, `CHECK PASS` |
| 286 at 6 MHz, RSA | 70 | 3.8448 s | measured, `CHECK PASS` |
| 286 at 8 MHz, compact ECDSA | 32 | 1.7576 s | measured, `CHECK PASS` |
| 286 at 8 MHz, RSA | 52 | 2.8561 s | measured, `CHECK PASS` |

On the 8088, separately timed ChaCha/copy, Poly1305/copy, and SHA/copy
components sum within one BIOS tick of each complete path:

| Profile | ChaCha + XOR/copy | Poly1305 + copy | SHA + copy | Full |
|---|---:|---:|---:|---:|
| Compact ECDSA | 53 / 2.9110 s | 89 / 4.8884 s | 29 / 1.5928 s | 172 / 9.4472 s |
| RSA | 87 / 4.7785 s | 147 / 8.0740 s | 47 / 2.5815 s | 282 / 15.4890 s |

The wider HKDF bench emits a 528-byte bundle containing every handshake and
application secret/key/IV result. Both the complete schedule and the selected
hot schedule, which bakes the public no-PSK `derived` constant, produced
checksum `2D5F` and an independent bundle validation value of `1`:

| Machine | Complete schedule | Baked-hot schedule |
|---|---:|---:|
| 8088 at 4.77 MHz | 47 ticks / 2.5815 s | 41 ticks / 2.2519 s |
| 286 at 6 MHz | 13 ticks / 0.7140 s | 11 ticks / 0.6042 s |
| 286 at 8 MHz | 9 ticks / 0.4943 s | 8 ticks / 0.4394 s |

Those older profile totals remain useful rejection evidence:

| Machine / profile | Flight + baked-hot HKDF | Excluded |
|---|---:|---|
| 8088 at 4.77 MHz, compact ECDSA | **11.6991 s** | TCP/parser/client-Finished overhead |
| 8088 at 4.77 MHz, RSA | **17.7409 s** | TCP/parser/client-Finished overhead |
| 286 at 6 MHz, RSA | **4.4490 s** | ECDHE, RSA recovery, PSS, TCP/parser overhead |
| 286 at 8 MHz, RSA | **3.2955 s** | ECDHE, RSA recovery, PSS, TCP/parser overhead |

The live patience result still rejects the RSA-served 8088 path and explains
why compression is architectural rather than cosmetic. The candidate verifies
their provisional record protection before Finished and authenticates server
identity only after the certificate/CV commit gates.

The encrypted-flight and older comparison benches used a 64 KiB BIOS-entry
environment because their benchmark boot sector is above a 16 KiB ceiling.
Their load, scratch, and stack addresses are statically below `0x4000`. The
critical HKDF has a separate literal-16-KiB ROM-BASIC record, and the current
target canary proves one credential-free live HEAD dialogue at that floor.
Those older measurements alone do not prove the complete self-authenticating
proof chain, failure recovery, atomic credential unlock, or credentialed
business request. The final 178-sector artifact now implements those paths for
the dated exact-leaf route and its exact credentialed functional path passes twice;
physical entropy characterization remains pending. Static addressing still
does not make the older flight measurements literal-16-KiB runs.

For 286 measurements, the generic `run_286_bench.py` runner accepts an
arbitrary standalone `--asm`, builds the fixed 360 KiB `bench_boot.asm` image,
selects 86Box 9001 stdout mode, and restores the tracked configuration and CMOS
state in `finally`. Explicit NASM include/define options select the exact
shipped P-256 and optimized-RSA implementations rather than similarly named
older benchmark files.

### Rejected RSA-PSS comparison

The fixed-profile 8086 decoder was gated against the deterministic recovered
RSA message plus wrong-transcript, unused-bit, padding, hash, and trailer
tampering. All six cases passed. Its work is:

```text
CertificateVerify signed-content hash    3 SHA-256 blocks
MGF1                                      7 SHA-256 blocks
PSS H'                                    2 SHA-256 blocks
--------------------------------------------
full post-RSA operation                  12 SHA-256 blocks
```

The 286 ground-truth bench runs four complete post-RSA operations per timed
sample:

| Machine | Four iterations | Per operation | Status |
|---|---:|---:|---|
| 286 at 6 MHz | 9 BIOS ticks | 0.124 s | measured, 4/4 accepted |
| 286 at 8 MHz | 7 BIOS ticks | 0.096 s | measured, 4/4 accepted |

One BIOS tick is 54.925 ms, so the four-iteration measurements have about
13.7 ms of quantization per operation. They include the TLS 1.3 signed-content
hash and PSS/MGF1 decode, but exclude the existing separately measured RSA-2048
modular exponentiation. The result makes the PSS format change negligible next
to current RSA recovery and P-256 costs; secure-floor risk is dominated by
provider timing, receive/state transitions, and those existing asymmetric
operations rather than PSS decoding.

The exact shipped P-256 implementation and optimized `montsqr` RSA
implementation were then measured through the same runner. Adding them to the
flight, hot HKDF, and PSS measurements gives the serial authenticated bound:

| Component | 286 at 6 MHz | 286 at 8 MHz |
|---|---:|---:|
| P-256 ECDHE | 120 ticks / 6.5910 s | 90 ticks / 4.9433 s |
| Optimized RSA-2048 verify | 94 ticks / 5.1630 s | 70 ticks / 3.8448 s |
| RSA encrypted flight | 70 ticks / 3.8448 s | 52 ticks / 2.8561 s |
| Baked-hot HKDF | 11 ticks / 0.6042 s | 8 ticks / 0.4394 s |
| CertificateVerify post-RSA PSS | 0.1236 s | 0.0961 s |
| **Measured serial subtotal** | **16.3266 s** | **12.1797 s** |
| **Margin against observed 15 s close** | **-1.3266 s** | **+2.8203 s** |

This made 6 MHz a no-go for the measured TLS 1.3 RSA comparison before adding
live TCP receive, production parsing, or state-transition overhead. Eight MHz
would have been that rejected profile's candidate floor. It is retained as
comparison data, not the current recommendation.

The installed 86Box 9001 configuration model required one harness
compatibility correction: `serial1_device = stdio` with virtual-console
`mode = 0` routes COM1 through process standard I/O. `mode = 1` creates a PTY,
and legacy `serial1_passthrough_enabled` migration selects that PTY mode without
exposing its path to the old capture helper. The runner restores the tracked VM
configuration after every measurement.

## Leaf pin, WR1, and “double pinning”

Pinning is part of this architecture scope because the compressed ECDSA profile
changes the chain:

```text
hot per-connection proof:
    exact adopted ECDSA leaf public key verifies TLS 1.3 CertificateVerify

post-Finished rotation proof:
    baked WE1 ECDSA anchor verifies strict-DER api.openai.com leaf
    hostname + explicitly defined certificate-time + key-usage policy pass
    verified leaf is adopted only in the atomic connection commit
```

The live ECDSA leaf is issued under WE1. The existing WR1 anchor belongs to the
RSA profile and cannot simply be relabeled or reused. Moving to the compressed
ECDSA flight is therefore an explicit trust-anchor migration, not merely a
different CertificateVerify parser.

An exact leaf point inside the immutable trust boundary can make the fast path
one ECDSA CertificateVerify, but the received certificate must still be
decompressed and matched to that point/hash before commit. The current
`SEED/LEAF.DER` is writable/untrusted state and must be verified under WE1 on
every boot; merely matching that file cannot skip the issuer signature. The
architecture must either bake/image-authenticate the exact point explicitly or
budget the two-signature recertification path.

The self-contained 8088 comparison corrected an earlier large-comb
recommendation:

| P-256 strategy | Active pair / retained three-base tables | Cycle-model cold two-signature sample mean |
|---|---:|---:|
| binary Shamir | 64 B / no retained precompute | 108.80 s |
| unsigned fixed window w4 | 1,920 B / 2,880 B | 113.63 s |
| fixed comb w4 | 1,920 B / 2,880 B | 119.80 s |
| **two-base Straus wNAF w4** | **512 B / 768 B** | **89.61 s expected; 97.88 s conservative bound** |

The recommended cold-bootstrap baseline is Straus wNAF width 4. That comparison
was a pre-integration static cycle model. The linked overlays now supersede its
size estimates:

- the exact adopted-leaf path is 6,632 bytes / 13 sectors and measures 989
  ticks / 54.321 seconds in the literal full-chain run;
- the WE1-authorized two-signature fallback is 7,134 bytes / 14 sectors,
  uses the real captured WE1/current-leaf/CertificateVerify vector, and passes
  exact target arithmetic/order gates under Unicorn;
- both reuse 896 bytes of mutable P-256 work in the low phase window rather
  than embedding it in every overlay; the default product P-256 layout remains
  byte-identical.

The issuer fallback now passes a separate exact-speed, literal-16-KiB,
host-read-only harness at 984 ticks for WE1-to-leaf plus 986 ticks for
leaf-to-CertificateVerify. That remains fixture-fed timing, not live-chain
composition. The strict uncompressed certificate parser exists as separate
target overlays, but it is not linked from live protected-flight capture into
this issuer phase; certificate compression and a trusted validity-time policy
also remain unresolved. Therefore the arithmetic and timing success cannot yet
authorize a live leaf rotation.

Fixed comb verifies each signature in about 24.34 seconds but takes about
23.70 seconds to generate each base table on the same machine. It loses on a
cold two-signature boot and becomes worthwhile only when immutable tables are
accepted as shipped program data or one key is verified repeatedly. The
self-contained baseline assumes neither.

Interpretations of “double pinning”:

- **Leaf plus issuing anchor:** required. For this candidate that is leaf +
  WE1, replacing the RSA path's leaf + WR1.
- **Current plus guessed next leaf:** not reliable. No authenticated
  successor-leaf channel was observed in the probed TLS/X.509 path or is
  available to this design, so two concrete leaves merely postpone one
  rollover and add expiry/state complexity.
- **Active plus successor CA anchor:** potentially useful for planned WE1
  rollover, but only with an authenticated distribution/update story. Verify
  entries sequentially so the bounded set does not duplicate hot RAM.

Thus “double pinning” belongs in the design as a two-level leaf/issuer proof,
not as two speculative leaf hashes. The integrated spike must exercise both
the exact-current-leaf path and forced WE1-authorized recertification.

Every ECDSA gate must additionally enforce strict DER for both signatures,
`1 <= r,s < n`, exact uncompressed P-256 SPKI encoding, on-curve/non-infinity
leaf and WE1 points, and exact TLS signature-scheme binding.

## Spike plan and measured outputs

Completed linked/offline work:

1. **Product-shaped phase link:** one flat 79,872-byte cold container, four
   initially resident sectors, unchanged driver slot, exact 16-KiB memory
   sentinels, and real BIOS sector phase loading pass.
2. **Literal full-chain target runs:** both K15 and K14 execute deterministic
   entropy durability, KeyGen, ServerHello handoff, candidate, symmetric
   restore/protected flight, FO, and exact-leaf authentication through
   `PASS / RESULT`.
3. **Critical target timing:** the linked fixture work is 225 ticks /
   12.358 seconds. The live K14/NE.DRV sibling includes fragmented provider
   receive, zero-window phase swaps, protected-flight verification, and actual
   transmit; three predecessor wire runs pass at 13.483030–13.536609 seconds
   and the hardened current canary passes at 13.404952 seconds.
4. **Exact ML-KEM arithmetic:** KeyGen, candidate, full re-encryption/compare,
   valid selection, and one-bit-invalid implicit rejection match independent
   Python and OpenSSL gates.
5. **Restart/durability and read-only entropy mechanics:** alternate-slot
   write, BIOS reset, physical reread, torn-write/corruption matrices, and
   release ordering pass for the optional writable ratchet. The final
   read-only route instead automatically makes 256 alternating BIOS reads,
   measures each with PIT channel 0, SHA3-256-conditions the events into two
   domain-separated attempt bundles, and performs no disk write or operator
   input. Its exact 8086 controller/oracle/hostile gate passes. Emulator timing
   receives zero credited bits; representative physical-drive characterization
   and writable-media rollback policy remain unresolved.
6. **Authentication link:** exact-leaf 13-sector and real-chain issuer
   14-sector overlays pass strict arithmetic/order/sentinel gates; the exact
   path has a literal 54.321-second result.
7. **Target symmetric/ticket state:** transcript-context import, full/resumed
   schedules, Finished, literal credential-free HEAD, tentative bounded
   ticket, binder, replay prevention, hostile records, and consume-once handoff
   pass offline.
8. **Live evidence:** the literal 8088 target reaches client Finished through
   production NE.DRV before the provider bound, sends an exact encrypted HEAD,
   tag-verifies two bounded tickets and the HTTP response under provisional
   traffic keys, and commits the
   tentative canary from a host-read-only floppy. Separately, a host handshake
   resumed a bounded same-boot ticket with ChaCha20 and X25519MLKEM768 PSK-DHE.
9. **K-window gate:** K15 and K14 are integrated for the fixture-fed chain;
   K14's source-derived full-sector staging, extension bounds, live-controller
   write hooks, and on-wire memory schedule pass. The current proposed K13
   split overflows by 56 bytes and is rejected.
10. **Final post-auth composition:** one 91,136-byte / 178-sector artifact
    retains the four-sector resident prefix and adds 37 checked phase entries /
    56 sectors for all 11 resumption operations. Its receipt/vault lifecycle,
    fresh target KeyGen/binder, exchange, resumed symmetric I/O, deferred FO,
    liveness, restore/scrub, route promotion, credential loader, and exact
    application response paths pass their offline hostile gates and exact
    functional live run.
11. **Overwrite-safe continuations:** the lifecycle hash bridges tolerate the
    full K14 SHA work overwrite and reload their caller; the deferred-FO
    controller backs up and restores the persistent K14 tail, scrubs its
    retired card page, and sends post-FO failures only through the unchanged
    terminal recovery path.

Remaining before a secure-floor claim:

- preserve and repeat the exact credentialed 86Box functional result with the
  automatic collector, a host-read-only unchanged image, and authenticated
  exact `ok / PASS / RESULT`; emulator runs receive zero entropy credit;
- collect raw timing traces across representative physical drives,
  controllers, media, temperatures, and cold/warm restarts; establish a
  conservative min-entropy estimate and calibrated startup/continuous health
  tests; then repeat the exact credentialed route on physical hardware;
- measure repeated candidate-profile held-Finished close distributions;
- reproduce the live bridge on 3c501, 3c503, and WD80x3 before the full driver
  matrix, including an explicit volatile-storage strategy to replace the
  NE2000 card-RAM vault;
- safely link the checked uncompressed Certificate/CV parser to protected
  flight capture and issuer auth, resolve its staging/ticket overlaps, and
  establish trusted validity time;
- prove the checked uncompressed parser in the live Certificate/CV schedule;
  if certificate compression is retained, also implement and adversarially gate
  a bounded decoder;
- obtain independent review of fixed `u=9`, provisional pre-FO use, and
  deferred authentication;
- run the full legacy and current product NIC/regression matrix.

## Migration order after the spike

1. **Freeze all proof artifacts.** Keep the four-sector nucleus, driver ABI,
   exact K15/K14 memory maps, deterministic coherent chain, live canary image,
   final 178-sector composition, source hashes, capture oracle, pcap analyzer,
   and `PASS / RESULT` parser under reproducible checkers.
2. **Generalize the live bridge without changing its memory schedule.** Keep
   the candidate handoff outside active RX, forbid extension writes after
   `sym_init`, retain zero-window backpressure and track-aligned reads, and
   repeat the exact wire gate on 3c501, 3c503, and WD80x3. Do not attempt K13
   in the product migration.
3. **Finish general target identity integration.** Keep the final dated
   exact-leaf path as a PoC gate, then link the strict uncompressed
   DER/SPKI/name/key-usage parser through tag rollback and the issuer phase,
   resolve the low staging and high vault collisions, establish a trusted
   validity-time policy, and exercise forced WE1 fallback. Treat bounded
   compression as a separate optional optimization unless uncompressed timing
   fails.
4. **Validate the completed entropy/ticket recovery route.** Preserve and
   repeat the passing exact automatic-floppy credentialed functional proof,
   exercise every socket-close boundary, and characterize the raw source on
   representative physical machines before assigning any entropy credit.
   Retain the durable ratchet for writable media. Persistent/cross-boot tickets
   remain excluded.
5. **Adversarial review.** Exercise invalid ciphertexts with known provisional
   candidates, bad tags/Finished/CV/pins, malformed compressed certificates,
   response desynchronization, oversized HEAD responses, close/retry, and
   state-leak tests. Obtain external cryptographic review of all three
   independent boundaries.
6. **Provider repetition.** Repeat cold boots and long liveness runs over time;
   include held-Finished and HEAD-cadence probes under the selected candidate
   profile, and fail closed when expected geometry or liveness changes.
7. **Legacy NIC matrix.** Run all seven original-speed 16 KiB NIC profiles,
   then every current driver family. Driver binaries and ABI remain
   unchanged.
8. **Promote the atomic real-request gate only after review.** The final PoC
   keeps the API-key buffer unreachable until the volatile same-boot ticket is
   promoted and implements one exact request/response. The functional live gate
   is satisfied; physical-source entropy credit, repetition, and the preceding
   identity/review gates remain required before moving that path into the
   product.
9. **Persistent arena migration.** Design a new linked K14 phase/high-state
   schedule before moving any following low bands; the passing schedule
   overlaps the calculated `0x3c40..0x3eff` pool. Re-run the complete memory,
   deadline, and wire gates; prove that reconnect preserves user code and
   context; update `$r`/`$w`/`$x` and compaction for the new bounds; and
   version, migrate, or cleanly reject ENV snapshots whose arena base differs.
   An executable-first 608/96 split additionally changes the current 50/50
   policy.
10. **Replacement decision.** Only after the preceding gates pass, decide
   whether to replace TLS 1.2. Remove the old stack in the same coherent
   migration; do not ship a dormant dual stack or label the research profile
   standards-conforming.
11. **Widen phase addressing when required.** The 32-bit loader-size fix is
   already gated. Widen the 8-bit phase request before any phase start reaches
   sector offset 256.
12. **Modern/no-BIOS slices.** Keep the user-facing self-selecting package
    architecture. Add the fixed manifest and x64 UEFI slice after the PC16
    security/layout decision, then add AArch64 only with a real native payload.

If the integrated or review gates fail, retain current TLS 1.2 and keep these
artifacts as rejection evidence.

## Regression gates

### Build and static layout

- `make`
- `make inspect`
- fresh `SEED.SYS`
- `tools/check-layout.py`
- generated `docs/memory.md` map agrees with assembled symbols
- 512-byte stage 1 including `55 aa`
- four-sector reserved loader
- four-sector resident `SEED.SYS` load
- one-sector active NIC driver slot and unchanged vtable ABI
- every phase, writable object, stack, receive window, arena, and context range
  has a mechanically checked non-overlap lifetime
- 16 KiB arena/context remain at least 96/96 bytes
- ML-KEM secret and tentative state are zeroized before the committed loop

### Offline crypto and parser gates

- RFC 7748 X25519 positive vectors and the measured no-go remain reproducible
- ML-KEM keygen/encapsulation/decapsulation known-answer tests
- independent full-byte Keccak/NTT/polynomial/ciphertext comparisons
- repeated valid/invalid representative ML-KEM timing distributions; no
  single synthetic BIOS-tick sample is accepted as a bound
- expanded-key/ciphertext handoff integrity and proof that every streamed
  matrix is regenerated from the current attempt's intended `rho`
- valid and invalid ML-KEM ciphertexts, including a malicious peer that knows
  the provisional candidate
- exact equality between provisional and standards-complete decapsulation on
  valid inputs
- constant-time full ciphertext compare/implicit-rejection selection
- TLS transcript, HKDF, AEAD, Finished, nonce/sequence, and fragmentation
  positive/negative vectors
- bounded uncompressed Certificate input and parser limits; if compression is
  retained, Brotli output, malformed stream, truncation, trailing-data, and
  decompression-bomb rejection
- DER, hostname, time, key-usage, WE1 signature, exact-leaf, and
  CertificateVerify tamper matrix
- strict ECDSA DER/range, exact SPKI encoding, point-on-curve/non-infinity, and
  signature-scheme binding gates
- trusted-time rollback/expiry tests; unauthenticated NTP cannot authorize a
  new leaf
- ECDSA table corruption rejects; no unverified table byte influences an
  acceptance decision
- HEAD response-boundary parser rejects body-bearing, oversized, interim,
  upgraded, malformed, unsolicited, and overlapping responses

### Boot/media

- 16 KiB ROM BASIC sidecar reaches DPI
- 32 KiB direct boot reaches DPI
- 160 KiB and 360 KiB geometry paths
- `SEED.SYS` remains first FAT data file
- all drivers included and `INCLUDE_NIC_DRIVERS=0` images inspect
- no-card and no-suitable-driver failures offer normal retry/restart
- retry does not reread resident sectors
- writable ratchet survives torn-write/reset tests without attempt-key reuse
- write-protected media completes all 256 alternating read-only timing samples
  and SHA3 conditioning before the first network transmission, without
  external provisioning or operator-entered random values
- emulator runs explicitly retain zero entropy credit; representative physical
  drives pass the characterized min-entropy model and calibrated health gates
- every live-socket phase read is bounded and occurs with no outstanding HEAD
  response and a closed/zero advertised receive window

### Quarantine and atomic-commit security

- fresh ML-KEM keypair for every connection attempt, HRR, retry, and reboot
- full server-flight Poly1305 and exact server Finished pass before client
  Finished
- before commit, the only application bytes are one compiled literal HEAD at a
  time; capture proves no Authorization, key, prompt, model, context, cookie,
  server-derived field, or user/device/account/session/request identifier
  beyond public SNI/Host and ordinary network metadata
- API-key bytes are absent from provisional RAM and loaded only after the
  single commit transition; if prior UI entry is unavoidable, no precommit
  routine has a pointer to their isolated storage
- each HEAD response record's AEAD tag verifies under the provisional key
  before bounded drain; TLS sequence numbers never reset across
  provisional/committed state
- standards-complete ML-KEM decapsulation, including constant-time `c' == c`
  and implicit rejection, plus Certificate policy, leaf/WE1 proof, and TLS
  CertificateVerify all pass before commit; decompression is an additional
  gate only if compression is retained
- no outstanding probe response at commit
- provisional state rejects KeyUpdate, post-handshake authentication,
  unexpected inner types/epochs, upgrades, and all application input not tied
  to the single outstanding HEAD; alerts only terminate
- every failure path sends no real request, promotes no ticket/pin, and
  persists no learned state; post-Finished proof failures share one fixed close
  checkpoint and zeroize tentative secrets
- NewSessionTicket is tentative until commit, volatile by default, no 0-RTT,
  and never a cold-start dependency

### Live TLS/API

- repeated original-speed 4.77 MHz/16 KiB cold boots complete the full
  self-contained proof and one real request
- held-Finished measurement under the selected candidate profile establishes
  its own close distribution; the P-256/RSA 14.994-second observation is only
  a working bound
- pre-Finished candidate span stays below that candidate-profile close with
  measured margin
- candidate-profile HEAD cadence survives the complete KEM + uncompressed DER
  + two-ECDSA worst path; if compression is retained, its decoder cost is also
  included; the standards-complete OpenSSL result is not substituted
- provider status code/headers may vary without affecting the state machine
- forced connection close at every quarantine checkpoint fails closed or uses
  only a fully promoted same-boot ticket
- immutable exact-leaf fast path (if adopted) and forced WE1-authorized
  recertification both work; mutable `SEED/LEAF.DER` always takes the latter
- original-speed seven-profile 16 KiB matrix and representative 32 KiB direct
  matrix
- multi-turn, idle reconnect, compaction, `$r`/`$w`/`$x`, function-call replay,
  maximum tool-loop bound, and streamed fragmentation remain unchanged

### Driver stability

At minimum, rerun one representative from every implemented family and every
receive/transport shape touched by shared timing. Before a checkpoint, preserve
the documented full current 86Box Ethernet coverage, including ISA, ISA PnP,
MCA, VLB, PCI BIOS, onboard PCnet, shared-memory, programmed-I/O, and bus-master
drivers.

## Risks and open questions

| Question / risk | Why it matters | Spike evidence required |
|---|---|---|
| Is the `u=9` ML-KEM-only use reviewable/acceptable? | it is not conforming X25519MLKEM768 and loses classical/hybrid security | independent protocol/cryptographic review or provider pure-ML-KEM support |
| Is pre-FO key confirmation safe enough? | a malicious peer can know an invalid-ciphertext candidate; Finished/HEAD expose a one-shot confirmation oracle | formal/adversarial review plus fresh-key, one-ciphertext, uniform-failure proof |
| Is deferred peer authentication acceptable? | client Finished and HEAD precede certificate/CV validation even though wire order is preserved | independent TLS state-machine review and adversarial tentative-parser proof |
| Can strong attempt entropy be generated after every restart? | key reuse collapses the one-shot quarantine argument | the final route automatically collects 256 alternating read-only floppy completions before networking and SHA3-256-conditions them into two domain-separated one-shot bundles; 86Box receives zero credit, so representative physical-drive min-entropy characterization, calibrated health tests, and writable-media ratchet policy remain |
| What is the candidate profile's actual pre-Finished close distribution? | three predecessor runs accepted Finished at 13.483030–13.536609 s and the hardened current canary at 13.404952 s, but they do not map the provider's close tail | held-Finished candidate-profile repetitions over time |
| Does the live critical path fit before that close? | yes on six exact-speed 16-KiB NE.DRV observations; the final fresh path leaves 1.300397 s and its resumed path leaves 4.641737 s against the 15-second bound | repeat distribution on the remaining legacy NIC receive shapes |
| Will candidate-profile dialogue remain available long enough? | the exact run completed fresh HEAD/ticket capture and resumed liveness before offline FO/auth, then completed the credentialed response on that resumed socket | repeated candidate-profile liveness runs |
| Can ECDSA pause safely for liveness? | one verification exceeds the 25 s cadence | the exact-leaf recovery route does not require the first socket to survive ECDSA; resumable point/scalar state remains a gate only for a future issuer-authorized path that chooses to keep dialogue live |
| Can phases be swapped without losing packets? | the track-aligned zero-window schedule passes on NE.DRV, but 3c501 single-buffer and shared-memory shapes may differ | on-wire zero-window/no-outstanding-response traces on every NIC receive shape |
| Can retry remain floppy-free? | overwriting the timed K slice may make current retry semantics impossible | exact retention/reconstruction layout or explicit architecture decision |
| Does the candidate fit the 15-sector K window? | yes; both fixture containers and the final logical-K14 exact-leaf composition fit, with a 2,048-byte resident prefix | preserve padded phase geometry while adding any general parser/issuer path |
| Can it reach K=14? | yes for the fixture chain, live canary, and final 178-sector offline-gated and functionally live composition; RX/controller lifetimes, write hooks, lifecycle SHA overwrite, deferred-FO restoration, and hostile sentinels pass on NE.DRV | physical-source credit, then preserve the schedule across the NIC matrix |
| Where can protected-flight certificate capture execute? | the 748-byte callback cannot append below K14: only 8 bytes remain after current symmetric code/work, and the naive aligned link overflows by 744 bytes; the former low slice is now scatter/loader state | a new phase/lifetime receive handoff with exact ordered write hooks and tag-failure rollback |
| Can issuer auth coexist with ticket capture? | the final dated exact-leaf path coexists with ticket capture/resumption, while the separate WE1-authorized parser/issuer fallback is still not in that execution | general live parser/issuer ordering plus close/recovery tests |
| Can Brotli be bounded in 16 KiB? | the advertised stream window is much larger than RAM despite a small observed backward distance | compact streaming decoder, exact output cap, adversarial corpus |
| What is the trusted 5150 time source? | unauthenticated NTP is attacker-controlled and a rolled-back clock can admit an expired leaf | trusted user-set time, authenticated persisted lower-bound ratchet, or explicitly accepted weaker expiry semantics |
| How is WE1 rollover staged? | current+next leaf hashes do not solve issuer rotation | bounded authenticated successor-anchor story before WE1 expiry |
| Does OpenAI keep the exact group/signature/compression/profile? | the candidate intentionally has no generic negotiation fallback | recurring compatibility probe and clear failure UI |
| Can target ticket resumption safely recover a closed socket? | the exact target run completes a fresh-KEM binder, PSK-DHE exchange, exact resumed Finished, pre-FO HEAD, deferred FO, authenticated liveness, vault restore/scrub, status-last promotion, and the credentialed response | physical-source credit and close-fault/repetition testing; persistent PSKs remain excluded without a separate threat model |
| Is high-linked K worth a second link slice? | it can yield kilobytes on 32 KiB pre-286, but increases validation paths | isolated prototype with size and full turn/reconnect tests |
| How should exact-32-KiB secure machines coexist with high-linked K? | K and secure overlay are simultaneously live | no overlap proof or explicit decision to keep low K |
| When should `SEED.PAK` appear? | premature modularity adds parser/ABI cost | actual >255-sector or multi-ISA requirement |
| How are universal images signed/verified? | native shims and payload slices broaden the recovery trust boundary | threat model and fixed manifest integrity design before shipping |
| Can one download remain simple across incompatible physical media? | original floppy capacity cannot hold modern slices | packaging/writer UX design; no architecture choice presented to user |

## Current spike decision record

```text
architecture status:
  literal-16-KiB K15 and K14 fixture-fed phase architectures pass
  live K14 RX/controller lifetimes, NE.DRV wire deadline, provisionally tag-verified
  credential-free HEAD response, and tentative RAM-only ticket capture pass
  final 91136-byte / 178-sector exact-leaf credentialed composition is linked
  all 11 target resumption operations and their hostile offline gates pass
  automatic pre-network floppy-timing collector and hostile oracle gate pass
  exact credentialed 86Box functional result passes; physical entropy credit remains pending
  conforming secure tier and product replacement remain unauthorized
  requirement: all per-boot work must be generated by the original machine

final composition:
  exact IBM PC 5150 / 4.772728-MHz 8088 / 16 KiB / ROM BASIC / NE2000 only
  62464-byte / 122-sector hardened secure-FO base remains unchanged
  91136-byte / 178-sector final SEED.SYS; 2048-byte / four-sector resident prefix
  37 added post-auth phase entries / 56 sectors
  fixed 221-byte dispatcher; CLOCK, PREPARE, EXCHANGE, RECEIVE, SEND, HEAD,
  DEFERRED_FO, LIVENESS, ROUTE_VALID, NST_VALID, RESTORE all implemented
  NTR1 receipt plus RVL1 issuer/ticket/control vault use volatile card pages 73..7f
  lifecycle SHA bridge reload and deferred-FO backup/restore/scrub gates pass
  target binder, fresh PSK-DHE resumption, exact resumed Finished, pre-FO HEAD,
  post-FO authenticated liveness, status-last route promotion, credential loader,
  and authenticated exact-ok application path are implemented
  before networking, 256 alternating read-only BIOS floppy reads are timed by PIT
  SHA3-256 derives two domain-separated one-shot 128-byte attempt bundles
  no manual input or disk write; emulator entropy credit is zero
  representative physical-drive min-entropy characterization remains pending

research wire profile:
  TLS 1.3 / ChaCha20-Poly1305 / SHA-256
  X25519MLKEM768 wire group, but fixed X25519 u=9
  genuine self-generated ML-KEM-768 contribution
  ECDSA P-256; current timing fixture uses Brotli
  first strict-parser integration should omit compression unless a bounded
  decoder and its critical timing are independently proved
standards status:
  not conforming hybrid TLS; effective KEX is ML-KEM-only
  provisional pre-FO use is not FIPS 203 decapsulation
  peer authentication is deferred until after client Finished/application probes

pre-Finished gates:
  fresh one-shot ML-KEM key
  strict expected transcript/profile
  full server-flight Poly1305
  exact server Finished
allowed provisional application:
  immutable credential-free HEAD only
commit gates:
  full ML-KEM re-encryption/compare/implicit rejection
  exact candidate/result equality
  final exact route: dated exact-leaf possession plus TLS CertificateVerify
  general route: bounded uncompressed DER/name/time/policy and leaf under WE1;
  bounded Brotli only if retained
  atomic credential unlock on the proven connection or promoted same-boot ticket

ordinary X25519 server-dependent operation:
  45.7529 s; no-go
historical integrated literal target:
  IBM PC 5150; 4.772728-MHz 8088; exactly 16 KiB; dynarec off; ROM BASIC
  79872-byte / 156-sector cold container; 2048-byte / four-sector resident prefix
  complete deterministic K14 chain PASS / RESULT in 159.285 s wall time
  current K15 regression PASS / RESULT in 159.480 s wall time
pre-TCP phases:
  symmetric preload 12 ticks / 0.659 s
  deterministic entropy durability 181 ticks / 9.941 s
  ML-KEM KeyGen 402 ticks / 22.080 s
critical linked phase:
  225 ticks / 12.358 s
  includes candidate load/compute, 8-sector symmetric restore, protected-flight
  fixture reads, transcript import, schedule, AEAD, server Finished, and exact
  client Finished construction
  remains the deterministic fixture/full-chain gate
working deadline margin:
  48 ticks / 2.636 s against conservative 273-tick / approximately 15 s bound
predecessor live K14 canary image:
  45568 B / 89 sectors; same 2048-byte baseline product resident prefix and NE.DRV
  real provider ServerHello/protected flight and actual client-Finished transmit
  predecessor deadline repeats 13.536559, 13.536609, and 13.483030 s
  hardened current canary wire interval 13.404952 s; margin 1.595048 s
  exact encrypted HEAD; two tickets and 1125-byte HTTP response tag-verified
  under provisional traffic keys
  read-only host gate and before/after floppy hash pass
  no credential, business request, full FO, certificate/CV proof, or secure commit
candidate-profile close distribution:
  four Finished-accepted observations only; held-Finished tail measurement required
exact post-Finished FO:
  2829 B / 6 sectors; 470 ticks / 25.815 s in the K14 full chain
  exact re-encryption/compare/J and branchless implicit rejection
exact adopted-leaf authentication:
  6632 B / 13 sectors; 989 ticks / 54.321 s in the full chain
  tracked leaf is expiring and differs from the newly captured live leaf
issuer-authorized fallback:
  7134 B / 14 sectors
  real WE1 -> current live leaf -> captured CertificateVerify arithmetic/order
  relocated input 3400..34af preserves the complete native ticket
  exact-speed literal passes: 984 + 986 ticks; 34 BIOS reads; no guest
  disk-write service; host-read-only image hash unchanged
  659 B / 2-sector atomic gate and 32-byte canary unlock pass
  strict uncompressed target parser passes in isolation; safe protected-flight
  linkage into the final ticket route, optional compression, and trusted time remain open
observed candidate-profile dialogue:
  target HEAD and response complete; two provisionally tag-verified tickets at
  SYN +14.718766 s
  one exact resumed socket survives liveness, FO/auth, credential unlock, and
  the authenticated business response; repetition/cadence distribution remains open
observed same-boot resumption:
  host accepted; certificate/CV omitted, PSK-DHE key share retained
  predecessor target ticket/PSK retention passes
  final target binder/resumed handshake/deferred-FO/liveness/promotion code and
  hostile offline gates pass; exact functional live result passes
  physical-source entropy credit remains pending
KeyUpdate/incomplete-HTTP liveness:
  no extension

current resident:
  2048 B / 4 sectors; unchanged
integrated K15:
  7680 B / 15 sectors; current literal regression passes
optional K14:
  7168 B / 14 sectors; linked fixture chain and hostile offline gates pass
  live candidate/RX schedule, post-sym-init write hooks, and NE canary pass
  tag-verified 1624-byte scatter, bounded live ticket, and HTTP DFA pass
  issuer/ticket lifetime and host-read-only atomic unlock pass in isolation
  final dated exact-leaf live-FO/ticket-resumption composition passes offline and live
  general live parser/issuer fallback and physical entropy credit remain open
K13:
  current proposed split is address-infeasible by 56 bytes and rejected
current product SEED.SYS:
  53760 B / 105 sectors
full-chain PoC cold container:
  79872 B / 156 sectors; not a product replacement image
live canary PoC cold container:
  45568 B / 89 sectors; credential-free and not a product replacement image
final credentialed PoC cold container:
  91136 B / 178 sectors; exact live result passes; not a product replacement image
  USER.CFG is a separate plaintext FAT file; read-only does not provide secrecy at rest
loader:
  full 32-bit file-size validation; four-sector resident-only behavior retained
  70000-byte positive, stack-safe undersized-file negative, 2047-byte
  partial-final-sector positive, stack-collision, and exact 55-sector safe-max
  regression gates pass

safe current 16 KiB arena/context:
  96 / 96 B
staged K14:
  96 / 96 B persistent; released 512 B is phase-owned, not user arena
conditional relinked/repacked K14 upper bounds:
  352 / 352 B under current split policy, or 608 / 96 B after policy change
  neither is accepted; both require a new lifetime schedule and full gates
safe current 32 KiB arena/context:
  224 / 224 B

decision:
  retain both deterministic proofs; use K14 as the memory target
  preserve and repeat the passing final exact-leaf functional live composition
  characterize the physical floppy-timing source before assigning entropy credit
  extend the wire and volatile-storage gate across NIC families
  with the exact run passing, integrate general issuer/parser/trusted-time rotation next
  make ticket-assisted close recovery primary and HEAD continuity secondary
  retain TLS 1.2 product until live repetition, general identity policy,
  full regressions, and external review pass
candidate exact-target feasibility:
  implemented, offline-gated, and functionally live at 4.77 MHz 8088 / 16 KiB
  emulator entropy credit is zero; representative physical-drive credit pending
conforming secure tier:
  unproved; fixed u=9 is ML-KEM-only and provisional use is outside FIPS 203
product replacement:
  unauthorized
accepted memory layout:
  retain current arena/context and baseline product driver layout
remaining open risks:
  representative physical-source characterization and live repetition,
  writable-media rollback, three independent review boundaries,
  provider close tail/cross-NIC timing, product retry fit,
  general parser/issuer coexistence, compression, trusted time and pin rotation,
  provider stability, external review,
  full boot/NIC/security matrix
```
