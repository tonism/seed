# TLS 1.3 286 controller and module boundary

This is the product-owned integration contract for the fully
standards-conforming `X25519MLKEM768` TLS 1.3 tier. It fixes the memory, disk,
call, and retry boundaries. The controller, cold tail, and dispatch are wired
into the boot core. Current validation status is recorded in
[the testing guide](../../../../docs/testing.md). The machine-readable
constants are in `tls13_286_abi.inc`.

## Dispatch and conventional RAM

The tier is selected only when both conditions hold:

1. the existing FLAGS probe has set `handoff_flag_cpu_286plus`; and
2. the BDA conventional-memory word at `0000:0413` is at least 512.

`handoff_ram_top` must not be used for this decision. It describes Seed's low
entry contract and remains `0x8000` on direct boots with more than 32 KiB.

The controller computes:

```text
conv_top        = dword(BDA[0x0413]) * 1024
crypto_base     = conv_top - 64 KiB
usable_conv_top = crypto_base
```

The existing far arena/context sizing must receive `usable_conv_top`, so the
TLS reservation is never advertised as model arena or conversation context.
This also keeps the reservation below the actual conventional-memory ceiling
on 512–640 KiB machines rather than assuming a fixed top.

At the 512 KiB floor, `crypto_base` is `0x70000`:

| Physical range | Bytes | Owner |
| --- | ---: | --- |
| `70000..751ff` | 20,992 | module-pack cache |
| `75200..75663` | 1,124 | preserved parent config/control escrow |
| `75664..757ff` | 412 | unused gap before the G table |
| `75800..777bf` | 8,128 | entropy scratch, candidate escrow, then width-7 P-256 G table |
| `777c0..7977f` | 8,128 | target-generated validated-leaf table |
| `79780..7a77f` | 4,096 | ordinary Certificate quarantine and same-boot pin |
| `7a780..7bf0f` | 6,032 | private attempts, ticket/PSK, metadata, hashes, descriptors, guards |
| `7bf10..7ffff` | 16,624 | full authenticated-record plaintext quarantine |

The current product pack occupies 20,992 bytes (41 sectors). The
remaining conventional far pool is `0x10000..0x70000`, or 384 KiB. With
the current 50/50 conventional layout this yields a 192 KiB executable arena
and 192 KiB context window. Native extended memory and EMS may enlarge or move
the context as they do today; neither may consume the reserved conventional
top.

## Single-file disk layout

The pack is a cold, sector-aligned tail included in the one flat `SEED.SYS`.
It is not another FAT file and does not create an architecture-specific boot
floppy. The existing core sector map supplies its `SEED.SYS`-relative start.
Before TCP, the 286 controller reads the complete pack into the high cache
through the resident disk callback and validates:

- `S286PK02`, ABI version, header and entry sizes;
- total/header/payload bounds without 16-bit wrap;
- a unique required module kind for every operation;
- raw length no larger than `0x3800`;
- raw-LZ4 decode ending exactly at the declared length; and
- CRC-16/CCITT-FALSE of every decoded image.

The current pack is 20,992 bytes (41 sectors), including target-side ML-KEM
key generation and the callable target table generator. Product modules are
assembled for `0000:4230` and carry an `S286MOD2` header; no runtime relocation
stream is needed.

The complete product tail follows the 211-sector prefix and occupies 82
sectors, file sectors 212 through 293 (the tail footer stores raw start sector
211). It contains 4 root-stage sectors, the 41-sector module pack, 7
entropy/precompute sectors, one shared 11-sector acquisition/resumption HELLO
image, 6 protected-flight sectors, 12 offline-auth sectors, and a one-sector
footer. The distinct acquisition and resumption directory entries
intentionally alias the byte-identical HELLO image at different entry points.

## Module entry ABI

Only one asymmetric image is decoded into `0000:4230..79ff`. The driver/DMA
band at `0000:8000..ffff` is untouched. The controller validates the module
header and performs a near call through:

```text
0000:(4200 + module.entry_off)
```

Entry state is:

```text
AX = operation selector
BX = near controller-state pointer
SI = near operation-descriptor pointer
DI = 0 (reserved)
DS = ES = SS = 0
DF = 0
```

On success the module clears carry and returns `AX=0`. Rejection sets carry
and returns a defined error in `AX`. `CS`, `SS`, `SP`, and `BP` are preserved;
other general registers and arithmetic flags are volatile. A module owns no
state after return. Secrets, tables, transcript state, and outputs live only
in explicit descriptor spans or the controller state. The controller wipes
the low overlay before decoding its successor.

All descriptor buffers use segment:offset plus a 32-bit length. The fixed
operation lengths are:

| Operation | Required inputs | Outputs |
| --- | --- | --- |
| ML-KEM-768 keygen | 64-byte local entropy seed | 1,184-byte `ek`, 2,400-byte `dk` |
| ML-KEM-768 candidate | 2,400-byte `dk`, 1,088-byte server ciphertext | exact 32-byte provisional `K'` |
| ML-KEM-768 decap | 2,400-byte `dk`, 1,088-byte server ciphertext | 32-byte shared secret |
| X25519 keygen | 32-byte local scalar | 32-byte ClientHello share |
| X25519 shared | scalar and 32-byte server share | 32-byte shared secret |
| P-256 tablegen | 64-byte affine point and 16,256-byte temporary far span | 8,128-byte width-7 table |
| ECDSA verify | 32-byte issuer/CV digest, strict DER signature, G and selected public-point tables | one-byte decision |

The offline auth controller selects WE1/P-256/SHA-256 or YE2/P-384/SHA-384
from the matching inner/outer signature algorithm. The immutable `IA02` object
uses pack-header bytes 140..463: a four-byte tag, followed by P-384 G (96),
YE2 (96), WE1 (64) and P-256 G (64), with little-endian affine coordinates.
The existing whole-pack CRC covers it. Remaining header bytes are zero and
the pack stays 41 sectors. No generated comb table is stored on disk.

Offline auth copies P-384 G and YE2 into public near space `0d40..0dff`, below
the FAT buffer. WE1 and P-256 G use `3340..337f` and `3380..33bf`; the module
descriptor starts at `33c0`. Parsed leaf coordinates use `0c70..0caf`, outside
the bounded `0800..0bff` leaf. The auth image is 7,156 raw / 6,143 stored bytes
in twelve sectors. Its public SHA-384/P-384 scratch is `4230..58ff`; that span
is wiped before the next P-256 module. The WE1 route generates G and issuer
tables, verifies the issuer signature, then replaces the issuer table with
the authenticated leaf table for CertificateVerify.

After acquisition Finished and credential-free liveness, the existing
one-sector H2 helper calls the relocated symmetric SHA-256 entries to capture
the exact encoded TBS. It uses the retired `0800..0bff` leaf window; the normal
TCP-close phase is reloaded before close. The 32-byte digest at high offset
`bd22`, near-span pair at `bd42`, and CRC at `bd46` temporarily reuse later
resumption metadata. Strict offline parsing must match that span and its RAM
corruption guard before full WE1 ECDSA verification. These fields grant no
authority by themselves. Auth clears all 64 bytes from `bd22` before promotion;
abort wipes the reservation. No additional disk read, private key, host table
or runtime helper is introduced.

The entropy seed is gathered on the target. It is not supplied by a build
machine or persisted as a private key.

## Core callback and control return ABI

The final flat link supplies near pointers for the resident operations the
controller may call:

- `read_abs_sector` through a `SEED.SYS`-relative sector adapter;
- `tcp_send_payload`;
- the resident TCP receive adapter; and
- a bounded socket-close adapter;
- the NIC enter/restore slots; and
- the resident route-mode return continuation.

Cold connection setup remains core-owned. The controller returns
`NEED_RECONNECT` or `ACQUIRE_CERTIFICATE`; it never jumps to a phase-sector
address. This makes final sector relocation explicit in the callback vector
and avoids research addresses becoming an accidental ABI.

The core enters this route from `prepare_agent_endpoint_path`, after agent
configuration, credentials, prompts, and the request cache are ready. The
initial `prepare_internet_path` remains DHCP-only. The 286 controller owns its
acquisition/retry ordering: DHCP/reacquire as needed, trusted-time
confirmation, then TCP/TLS.
On success it returns a live application-data session for the already-cached
OpenAI request.

The real Finished transmit gate must call the supplied `tcp_send_payload`
pointer with the exact 58-byte TLS record. Success is not published until the
NIC transmit returns success and a pcap observes the record before the
provider deadline.

Every HELLO controller carries and installs the byte-identical fixed-origin
cleanup capsule at `0000:4040..41ff`. Its authenticated header publishes
separate abort and success entry pointers. Both entries validate the same
high-memory escrow. HELLO freezes the bootstrap-validated crypto segment and
its inverse in the capsule's final four bytes before consuming private state.
Cleanup resolves that pair against the independent root-state copy, so a
later corrupt `BDA[0413]` cannot redirect or suppress high-reservation
retirement. With valid escrow, both restore the preserved parent
config/control/prompt state, retire the 64 KiB high reservation, and wipe the
handoff and asymmetric overlays before returning through the resident
route-mode callback. The success entry first requires the status-last
application-ready byte, then alone preserves `0000:3600..3667`, the published
application keys, IVs, and sequence counters. The abort entry zeroes that span
and returns carry set with the profile error. Missing readiness or any escrow
or geometry rejection takes the same full abort cleanup; it cannot fall
through the success return.

## Same-machine acquisition, authentication, and resumption

Certificate authentication remains mandatory even though the final
credential-bearing connection is resumed:

1. The acquisition HELLO consumes its own attempt bundle and generates genuine
   ML-KEM-768 and X25519 shares. Its candidate ML-KEM result is provisional.
   The protected-flight controller verifies record tags and server Finished,
   captures ordinary Certificate and CertificateVerify messages, transmits
   client Finished plus the immutable credential-free H2 preface/SETTINGS, and authenticates
   peer SETTINGS/ACK and one NewSessionTicket. Only then does it export the
   ticket as `TENTATIVE`.
2. With no server deadline running, offline authentication performs complete
   ML-KEM FO decapsulation and constant-time comparison against the retained
   candidate, then performs strict X.509/anchor/SAN/purpose/time validation,
   verifies CertificateVerify, and generates the G and leaf width-7 tables.
   It publishes the authentication decision before promoting the ticket
   status-last.
3. The resumption HELLO consumes the promoted ticket before reading the PSK or
   identity, consumes the second independent attempt bundle, and constructs a
   no-0RTT PSK-DHE ClientHello with a real binder. It requires
   `selected_identity=0`, performs full ML-KEM decapsulation and X25519 shared
   secret derivation, and accepts only a strict
   EncryptedExtensions-to-Finished protected flight. After server Finished
   verifies, it transmits the 58-byte client Finished and credential-free H2 preface/SETTINGS,
   then requires a complete authenticated ticket and peer SETTINGS/ACK.
   Application keys, credentials, and the advanced record sequence publish
   together only after that authenticated liveness boundary.

The candidate operation and acquisition preface can never reach credentials.
Ticket states are redundant/status-last `TENTATIVE -> PROMOTED -> USED`; the
final HELLO publishes `USED` before reading ticket secrets. Any torn state,
candidate mismatch, authentication failure, binder/identity rejection, or
unexpected Certificate flight aborts and wipes.

Thus offline certificate authentication is outside the acquisition deadline,
not outside the security boundary. Read-only media is supported: the pin,
tables, ticket, PSK, and attempts live in RAM, and a restart repeats the whole
route. There is no 0-RTT, compressed certificate, persisted ticket, mutable
leaf, or persisted private key.

The immutable trust objects in `SEED.SYS` are the WE1 P-256 and YE2 P-384
public points. `signature_algorithms_cert` advertises P-256/SHA-256 then
P-384/SHA-384, separately from the P-256/SHA-256-only CertificateVerify offer.
The acquisition handshake is 1,376 bytes (1,381 with the record header),
without an optional padding extension. No leaf file is shipped or refreshed. Certificate
validity uses the coherent BIOS RTC as the platform UTC clock after Seed obtains a valid BCD
Gregorian value in the supported date range. There is no interactive clock
question; invalid time fails closed. Unauthenticated network time is not a
trust input.

## Serialized timing status and fail-closed boundary

The exact 6 MHz module measurements distinguish the operation that is allowed
inside provisional acquisition from the operation that establishes authority:
the exact ML-KEM candidate takes 6 BIOS ticks, while complete uncached FO
decapsulation takes 88 ticks. Moving the latter into the offline stage is
what creates room for client Finished, the credential-free H2 preface/SETTINGS, and ticket
capture without treating the candidate as authenticated.

The product controller gates independently prove candidate escrow, full
decapsulation and constant-time comparison, strict certificate/CV
authentication, ticket state transitions, binder construction,
`selected_identity=0`, full hybrid resumption, strict resumed-flight grammar,
the exact 58-byte client Finished callback, status-last publication, canaries,
and failure-path wipes. The aggregate serialized gate models their ordered
target work. These remain offline evidence, not a live product-handshake claim.

The read-only 6 MHz / 512 KiB single-profile VM pcap now proves the ordered
acquisition/resumption/reconnect/resumption topology, four on-time
ServerHello-to-client-Finished intervals, authenticated OpenAI application
data, and bounded same-request replay over the resident TCP/NIC path. Broader
injected CPU/RAM/time/entropy/auth/Finished/FO/pack/abort gates now pass. The
seven-profile 8088 NIC matrix is a separate stable transport gate;
no broader 286 NIC claim is inferred. Physical entropy-source characterization
also remains open; protocol conformance does not by itself validate the amount
of min-entropy available from physical RTC/PIT event timing.
