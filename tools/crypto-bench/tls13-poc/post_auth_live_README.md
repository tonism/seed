# 16 KiB post-auth live feasibility PoC

This is an isolated full-target feasibility harness for the quarantined TLS
1.3 candidate on a 4.77 MHz 8088 with 16 KiB RAM and a read-only floppy. It is
designed to test a fresh-to-resumed candidate route followed by a credentialed
OpenAI request after the candidate commit gates. The complete target
composition, offline hostile gates, and one exact functional live result are
present. Physical-source entropy credit is still pending. This is not the
product boot path.

The candidate sends the fixed X25519 `u = 9` value and effectively relies on
ML-KEM for key agreement, then performs full FO and peer-proof work after a
provisional Finished and credential-free request. That is a deliberately
nonconforming `X25519MLKEM768` experiment with independent-review boundaries.
The recorded live pass establishes full-target feasibility, not a conforming TLS
1.3 secure tier.

## Composed target architecture

The current PoC `SEED.SYS` is 91,136 bytes / 178 sectors. Its initial
resident prefix remains 2,048 bytes / four sectors; the rest is cold-loaded
from the read-only floppy. The post-auth composition contributes 37 phase
entries occupying 56 sectors.

A fixed 221-byte dispatcher at `0x0500` exposes exactly 11 operations:

| Operation | Function |
|---:|---|
| 1 | sample the same-boot clock |
| 2 | require early-capable marker 2; vault state; consume the second entropy bundle; run target KeyGen; sample late ticket age; build the one on-wire binder and full ClientHello digest; independently recompute that binder with the symmetric overlay; derive and seal 0-RTT HEAD plus EndOfEarlyData; restore RSU1 |
| 3 | reconnect; replay the verified ClientHello; burn marker 0 to 1; send the 72-byte 0-RTT HEAD before any server byte; capture the strict resumed flight; publish the provisional candidate |
| 4 | validate and import the captured `EncryptedExtensions(early_data)` + Finished record |
| 5 | send the exact client Finished and complete the accepted-0-RTT application-key/zero-window step |
| 6 | retained compatibility 1-RTT HEAD entry; unused by the current 0-RTT route |
| 7 | complete deferred ML-KEM FO validation |
| 8 | authenticate and drain a complete 2xx, non-425 4xx, or 5xx HEAD response after FO |
| 9 | validate the ticket-only route before preparation, then restore and revalidate the vault after liveness |
| 10 | validate the native ticket and its card-RAM receipt |
| 11 | perform failure-only best-effort restore and full scrub |

There is one binder in the resumed ClientHello, not a two-binder protocol
invariant. PREPARE BINDER constructs it and records the full ClientHello
digest; PREPARE SYM_BINDER independently recomputes and compares that exact
binder before reconnect. EXCHANGE consumes the verified HELLO material without
another binder derivation.

RSI1 also has a direct AX=7 entry distinct from dispatcher operation 7. After
the authenticated server Finished, that entry recovers and sends the pre-sealed
26-byte EndOfEarlyData record and adds its plaintext to the transcript before
operation 5 sends the 58-byte client Finished.

At the exact provisional TLS-record boundary after the HEAD response is
tag-verified and the first bounded NewSessionTicket is retained, a status-last
`NTR1` receipt is written to and reread from NE2000 card page `0x73`. The
initial connection then completes full FO validation and the dated exact-leaf
P-256 possession checkpoint. Only after those gates does the same machine
create a fresh PSK-DHE resumption attempt. Its issuer, ticket, control, and
one-shot attempt state are kept in a volatile card-RAM vault over pages
`0x73..0x7f`; the floppy is never used as writable spill.

The receipt worker preserves `0x3c76..0x3c9a` because that range still holds
the tail of the live CertificateVerify signature before the P-256 checkpoint.
The post-auth entry initializes the same range as the resumption lifecycle
block only after exact-pin P-256 succeeds and LP1 has been published. The
lifecycle checker pre-fills and verifies this entire alias-sensitive span.

The resumed route performs vault commit, target KeyGen, late age, binder
construction plus independent symmetric cross-check, early-key derivation, and
HEAD/EndOfEarlyData sealing entirely in PREPARE. It publishes the early object
status-last to card page `0x7e`, reconnects, sends ClientHello, burns its
one-shot marker, and sends the fixed 72-byte 0-RTT HEAD before waiting for any
server byte. It then authenticates the exact
`EncryptedExtensions(early_data)` + Finished flight, sends the 26-byte
EndOfEarlyData and 58-byte client Finished, completes application keys and the
zero-window hold, completes deferred FO, and authenticates and drains the HEAD
response. HTTP 425 is authenticated early-data rejection and fails without
promotion. Operation 9 finally restores and validates the vault while
preserving spent marker 1, then changes `TICKET_ONLY` to `LIVE_TICKET`
status-last. The `USER.CFG` loader and real request remain unreachable before
that promotion.

Overwrite-sensitive transitions and lifetime overlays are explicit parts of
the architecture:

- The initial `0x0780..0x07ff` attempt bundle is consumed before PREPARE
  repurposes that page. Digests then occupy `0x0700..0x075f`, the private phase
  trampoline begins at `0x0780`, and `0x07fe..0x07ff` hold retry/outcome state.
  The trampoline stages HASH, COMMIT, CRYPTO, and BINDER at `0x3000`, copies
  only their measured bytes to `0x3400`, and jumps there. PREPARE RESTORE is a
  separate direct worker that really executes at `0x3000`.
- PREPARE's fresh 1184-byte ML-KEM public key at `0x08c0..0x0d5f`
  overwrites the complete live RSU1 scatter below `0x0d00`. After binder
  verification, a fixed direct phase reconstructs all three controller spans
  from the immutable two-sector image and wipes its `0x0d00..0x0eff` staging
  page before returning. Either controller-sector load failure enters the
  persistent scrub/failure service and never returns through damaged code.
- Lifecycle SHA-256 runs through one-sector bridges staged at `0x2400` and
  exact-copied to `0x3400`. The complete K14 symmetric phase may overwrite its
  mutable `0x3000..0x33f8` span; the bridge reloads the lifecycle worker at
  `0x3000` before returning to it.
- Page `0x7e` first holds the status-last early object: derived A at
  `0x7e00..0x7e1f`, 72-byte HEAD A at `0x7e20..0x7e67`, 26-byte
  EndOfEarlyData at `0x7e68..0x7e81`, derived B at `0x7e82..0x7ea1`, HEAD B at
  `0x7ea2..0x7ee9`, and metadata through `0x7eff`. EXCHANGE moves
  EndOfEarlyData to `0x7d40..0x7d59` before the duplicated candidate replaces
  the page. Deferred FO later uses the same page for its backup and finally
  scrubs it.
- HELLO owns eight sectors at `0x1800..0x27ff`; the two-sector RX phase borrows
  `0x2800..0x2bff`. POST relocates its measured suffix to `0x3400` and reloads
  ten symmetric sectors at `0x1800..0x2bff` before `sym_init`. The separate
  fixed-callback and deferred-FO restores remain eight-sector operations.
- The ticket marker is `2` for an unspent early-capable ticket, `0` while the
  committed vault owns temporarily unpublished state, and `1` after the
  attempt is spent. PREPARE requires `2` and retires it to `0`; TX writes `1`
  before the first ambiguous network send; operation 9 and liveness preserve
  `1`.
- Deferred FO uses a one-sector broker at `0x3000` and a three-sector
  controller at `0x2400`, outside the FO kernel's clobber ranges. It validates
  both candidate copies, uses page `0x7e` for a status-last backup of
  `0x3510..0x35ff`, restores the symmetric/controller state after FO, scrubs
  the retired page, and treats every failure after FO begins as terminal.

This composition is specifically tied to the 8-bit NE2000 proof profile. Its
guarded remote-DMA leaves and volatile card pages are part of the memory and
failure contract; another NIC needs its own checked volatile-storage strategy.
The receipt clock has likewise been audited only against the configured IBM PC
BIOS `INT 1Ah/AH=00` tick and midnight-flag behavior.

## Credentialed functional live run

The explicit live feasibility run accepts a real `USER.CFG` only through:

```sh
python3 tools/crypto-bench/tls13-poc/run_post_auth_live.py \
  --credentialed-live \
  --automatic-floppy-entropy \
  --user-cfg /absolute/path/to/USER.CFG \
  --base-build build/crypto-bench/tls13-live-secure \
  --build-dir build/crypto-bench/tls13-live-k15-post-auth
```

Use only a disposable, tightly rate-limited test credential. This route is
experimental, nonconforming, and not externally reviewed. The generated
credential-bearing image remains under `build/` after the run until the
operator removes it. `USER.CFG` is plaintext inside that image: mode `0444`
protects the run from writes, not the credential from disclosure. Do not share
or archive the generated image.

The runner accepts no entropy values and requires no entropy-entry ceremony.
The target emits:

```text
ENTROPY START 256
ENTROPY PASS 256
```

after 256 alternating read-only floppy timing samples complete. A functional
run must observe the target markers in this order:

```text
ENTROPY START 256
ENTROPY PASS 256
ok
PASS
RESULT
```

Collection happens before the first DHCP/network transmission. The complete
256-byte initial/resumption output is duplicated into volatile NE2000 RAM
before DHCP may reuse the low window. 86Box timing receives zero entropy
security credit; a physical secure-floor claim remains pending representative
real-drive min-entropy characterization and calibrated health tests. See
`floppy_entropy_README.md`.

The runner admits only `vm-net-ne2k8` and makes a temporary copy pinned to:

- IBM PC 5150
- 8088 at 4,772,728 Hz
- 16 KiB RAM
- dynamic recompilation disabled
- 8-bit NE2000
- ROM BASIC sidecar entry

The generated floppy is mode `0444`. Before launch, the runner proves that a
host write-open is denied. On a successful functional run it also proves that
the private before/after image digest is unchanged; it does not print that
digest. It does not print the selected config's original path, contents, size,
or hash.

On 28 July 2026 two independent exact admitted runs completed. The second was
a fresh rerun after host sleep inhibition was confirmed and reproduced the
same ordered target markers:

```text
ENTROPY START 256
ENTROPY PASS 256
...
ok
PASS
RESULT
```

The machine gate was IBM PC 5150, 4,772,728-Hz 8088, 16 KiB RAM, dynarec off,
8-bit NE2000, and ROM BASIC sidecar entry. Both runs denied host write-open and
proved the private before/after floppy digest equal. On the first run's resumed
connection, wire capture measured early data at SYN +0.128235 s, client Finished at
SYN +10.358263 s, the credential-free liveness response at SYN +11.497390 s,
the two-part business request at SYN +58.644804/+59.258603 s, and the last
business-response TLS record at SYN +61.492372 s. These timings and the
authenticated target markers establish functional feasibility for this exact
profile; they do not assign entropy credit or make the nonconforming
cryptographic construction a product secure tier.

Before a target run, execute the credential-free offline gates:

```sh
python3 tools/crypto-bench/tls13-poc/live_k15_secure_fo_check.py \
  --build-dir build/crypto-bench/tls13-live-secure
python3 tools/crypto-bench/tls13-poc/ticket_resumption_controller_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_resumption_dispatcher_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_resume_lifecycle_worker_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_resume_prepare_worker_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_resume_exchange_worker_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_resume_sym_io_worker_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_resume_fo_worker_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_resume_liveness_worker_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_live_composition_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_application_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_user_cfg_loader_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_resumed_hello_check.py
python3 tools/crypto-bench/tls13-poc/post_auth_proof_integrity_check.py
```

The synthetic builder mode is only a plumbing test and earns no security
credit:

```sh
python3 tools/crypto-bench/tls13-poc/build_post_auth_live.py \
  --synthetic-fixture
```

This PoC does not claim persistent cross-boot tickets, writable-media support,
validated physical entropy credit, other NICs, other RAM sizes, product integration,
conforming hybrid TLS, FIPS 203 decapsulation, or an externally reviewed secure
tier. The dated exact-leaf checkpoint is not a general certificate-chain,
trusted-time, or pin-rotation solution. The runner emits its success marker
only after the candidate fresh-to-resumed route, credential gate, and
authenticated application response complete.
