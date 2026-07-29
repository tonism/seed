# TLS 1.3 ticket-resumption controller proof

This proof closes the architectural gap between retaining an authenticated TLS
1.3 NewSessionTicket and safely promoting a resumed connection on the 16 KiB
8088 floor. It is still an isolated proof, not runtime integration.

The proof composes the existing product-shaped 8086 overlays:

- PREPARE uses HELLO to build a real bounded PSK-DHE ClientHello and its one
  on-wire binder. PREPARE SYM_BINDER independently recomputes and compares that
  binder before reconnect; PREPARE then derives the early write key and seals
  HEAD plus EndOfEarlyData.
- EXCHANGE reconnects, replays that verified ClientHello, burns the one-shot
  ticket marker, and sends the immutable 50-byte credential-free
  `HEAD /v1/models` as a 72-byte TLS early-data record before waiting for
  ServerHello. It strictly accepts `selected_identity = 0` and a fresh
  X25519MLKEM768 share.
- After authenticating exact `EncryptedExtensions(early_data)` + Finished,
  direct RSI1 sends the pre-sealed 26-byte EndOfEarlyData record and appends its
  plaintext to the transcript. The controller then builds and sends the
  58-byte client Finished and completes application traffic state.
- The unchanged FO-tail kernel re-encrypts the resumed ML-KEM ciphertext and
  requires `c' = c` before the provisional `K'` can be promoted.
- After FO, the fixed callback authenticates and drains the HEAD response.
  HTTP 425 is authenticated early-data rejection, not success. Route promotion
  remains forbidden until a complete 2xx, non-425 4xx, or 5xx response header
  reaches the exact liveness boundary.
- ROG3's LP1-backed committed TICKET_ONLY route remains the only live-product
  input route. The controller promotes it to LIVE_TICKET only after all of the
  above succeeds. Durable WE1 remains a separately regressed publisher profile,
  not an extra step in this dated exact-leaf live composition.

## Why resumption does not remove FO

A valid PSK binder and server Finished prove possession of the retained ticket
PSK, but the resumed ServerHello contains a new hybrid key exchange. Its
ML-KEM ciphertext must be checked against the new on-device private key. The
controller therefore treats the provisional `K' || X25519` secret as usable for
the deadline-bound handshake, but requires deferred FO re-encryption before
route promotion.

There is one binder in the ClientHello and no "second binder" invariant.
PREPARE BINDER constructs it and records the full ClientHello digest; PREPARE
SYM_BINDER independently recomputes and compares that exact binder, then
retains the corresponding early schedule. EXCHANGE consumes the verified
HELLO material without another binder derivation.

Candidate and FO publications are status-last and bind:

- the ROG3 attempt generation;
- a checksum of the exact resumed ciphertext;
- a checksum of the fresh KeyGen public key.

Missing, stale, mismatched, or zero publications fail closed.

## One-shot entropy and retry contract

The fixed PREPARE callback consumes the second 128-byte attempt bundle:

```text
0x0780..0x07ff = d[32] || z[32] || ClientHello.random[32] || session_id[32]
```

It rejects an all-zero bundle, rejects reuse even if old bytes are copied back,
and zeroizes the bundle before repurposing that low-memory band. After the
attempt bytes and readback are consumed, PREPARE stores its digest holdings at
`0x0700..0x075f`, installs a private phase trampoline at `0x0780`, and uses
`0x07fe..0x07ff` for retry/outcome. The original bundle layout therefore
describes only the initial lifetime of that page.
The checker independently runs the 8086 KeyGen overlay for the initial
`0x0700..0x077f` bundle and the one-shot resumption bundle, then proves that
their `d || z`, public keys, randoms, and session IDs differ.

The authenticated ticket parser publishes marker `2` for an unspent
early-capable ticket. PREPARE requires `2`; after committing the card vault it
retires the native marker to `0`. Pre-send cleanup may reconstruct `2`, but TX
irreversibly writes `1` before the first ambiguous 0-RTT send. Any send or later
failure therefore preserves normal-only spent state `1`, so this secure-floor
0-RTT path cannot retry the same ticket in that boot. Operation 9 adjusts the
ROG3 checksum while preserving `1`, and liveness requires `1`. A restart
supplies a new attempt bundle through the entropy bootstrap contract.

## Ticket age

The authenticated NST parser parks one status-last receipt object atomically
with the ticket at the card tail. Callback operation 10 validates that native
ticket-plus-receipt object and imports its original authenticated receipt
clock into the controller; the controller does not restamp it at resumption
entry. The receipt records:

- the BIOS tick count since midnight;
- a resident monotonic day/wrap counter;
- a checksum binding the timestamp to the retained ticket.

The resume path accepts the same day or exactly one day transition, rejects
backward/ambiguous clocks and elapsed time over 18 hours, converts elapsed ticks
to milliseconds with:

```text
ticks * 55 - ((ticks * 611) >> 13)
```

and sends:

```text
obfuscated_ticket_age = ticket_age_add + elapsed_ms  (mod 2^32)
```

The executable gate covers both a 16-bit tick low-word rollover and midnight
wrap. It also rejects an expired ticket.

## Memory and phase reuse

The 976-byte controller is a scatter-loaded cold phase. Ranges are half-open:

| span | bytes | purpose |
| --- | ---: | --- |
| `0x0dab..0x0fcb` | 544 | header and orchestration |
| `0x3400..0x350d` | 269 | validation, age, and valid-dialogue helpers |
| `0x355d..0x3600` | 163 | proof validation and promotion |
| `0x3510..0x355d` | 77 | preserved symmetric mutable hole |
| `0x3c46..0x3c76` | 48 | timestamp, age, candidate, and FO state; not file bytes |

The low controller is retired before the later PAK1/model publication reuses
`0x0d00..0x0eff`. The high executable spans are retired before credential load
reuses `0x3400`.

The credentialed live composition relocates the same 976-byte image as three
half-open spans: 544 low bytes at `0x0900..0x0b20`, 269 prefix bytes at
`0x0b20..0x0c2d`, and 163 suffix bytes at `0x0c30..0x0cd3`, with entries
`0x091a` and `0x097d`. This phase-reuses the retired initial post-controller
slot while preserving the live secure persistent services at
`0x355d..0x3600`. The later request controller retires the whole low variant.
The default origins above remain the standalone PoC ABI.

The durable issuer object at `0x3600..0x3671` overlaps resumed symmetric state.
PREPARE therefore vaults the issuer/ticket/control bundle outside host RAM.
Fresh KeyGen then places its 1184-byte public key at `0x08c0..0x0d5f`,
necessarily overwriting all three live controller spans. A fixed final
PREPARE phase reloads the controller's tail sector, scatters its exact
low-tail/prefix/suffix lengths, reloads the head sector directly at `0x0900`,
and wipes the `0x0d00..0x0eff` staging page before either success or ordinary
rejection returns. A controller-sector load failure is terminal and enters
the persistent scrub/failure service instead of returning through damaged
code.

PREPARE publishes a status-last early-data object on card page `0x7e`: derived
A at `0x7e00..0x7e1f`, 72-byte HEAD A at `0x7e20..0x7e67`, 26-byte
EndOfEarlyData at `0x7e68..0x7e81`, derived B at `0x7e82..0x7ea1`, HEAD B at
`0x7ea2..0x7ee9`, and metadata through status byte `0x7eff`. EXCHANGE moves
EndOfEarlyData to `0x7d40..0x7d59` before the duplicated candidate replaces
page `0x7e`; deferred FO later uses the page for its backup and scrubs it.

The eight-sector HELLO occupies `0x1800..0x27ff`; two-sector RX temporarily
borrows `0x2800..0x2bff`. POST relocates its measured suffix to `0x3400` and
reloads ten symmetric sectors at `0x1800..0x2bff` before `sym_init`. The
separate fixed-callback and deferred-FO restores remain eight-sector
operations.

Failures that occur before destructive overwrite may use fixed restore.
Failures after code or authority state has been replaced are deliberately
terminal through the persistent scrub/failure service. Deferred FO restores
the issuer before final ROG3 validation; only then may route state be published
last. The product arena/context `0x3e40..0x3eff` is untouched.

## Fixed callback ABI

The callback address is the shared post-auth send ABI at `0x0500`; AX is the
only operation selector:

1. current clock for the resumption attempt;
2. require marker 2, consume the one-shot bundle, vault committed state, run
   KeyGen, sample late age, construct and independently cross-check the binder,
   retain the early schedule, seal HEAD plus EndOfEarlyData, restore RSU1, and
   wipe the host PSK;
3. consume the verified HELLO material, reconnect, send ClientHello plus the
   early HEAD, capture the strict resumed flight, and publish the candidate;
4. validate and import the captured `EncryptedExtensions(early_data)` +
   Finished record;
5. send client Finished and complete accepted-0-RTT application-key and
   zero-window state;
6. retained compatibility 1-RTT HEAD entry, unused by this route;
7. deferred FO and proof publication;
8. authenticate and drain a complete 2xx, non-425 4xx, or 5xx HEAD response;
9. validate the ROG3 TICKET_ONLY bundle before PREPARE, then restore and
   revalidate the vault after liveness while preserving spent marker 1;
10. validate the parser-committed NST plus card-tail receipt and return the
    original receipt clock;
11. perform failure-only best-effort restore of the vaulted bundle, then full
    scrub.

Direct RSI1 AX=7 is distinct from fixed dispatcher operation 7: it recovers and
sends EndOfEarlyData before operation 5/client Finished. No caller pointer,
destination, route, credential, or media handle crosses this ABI. PREPARE seals
the fixed HEAD before reconnect and duplicates it status-last on page `0x7e`;
EXCHANGE verifies both copies and burns ticket eligibility before its single
0-RTT TCP send. The checker rejects replay and confirms there are no
credential-bearing request literals.

## Run

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/crypto-bench/tls13-poc/ticket_resumption_controller_check.py \
  --output tools/crypto-bench/tls13-poc/ticket_resumption_controller_results.json
```

The gate runs in an exact 16 KiB Unicorn map, is locked to `cpu 8086`, contains
no interrupt, port-I/O, credential, or writable-media path, and exercises 36
hostile cases. It proves protocol composition and memory/order feasibility; a
live network boot remains a separate integration gate.
