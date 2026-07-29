# Live TLS 1.3 16 KiB deadline and post-Finished canary

This sibling harness answers two narrow questions: can an original-speed
4.77 MHz 8088, entered through the 16 KiB ROM BASIC path, receive a real
OpenAI TLS 1.3 ServerHello and put its own client Finished on the wire within
15 seconds; and, after that deadline, can the same machine derive application
keys, send one exact credential-free HEAD, AEAD-tag-verify/drain its response
under provisional traffic keys, and tentatively derive a RAM-only ticket PSK?

The `live_k15_*` filenames, `LIVEK15.BAS`, and `K15 boot` marker are historical
spike names. The assembled crypto is the logical **K14** variant: its K window
is `0x1800..0x33ff`, with phase-owned reclaimed space at
`0x3400..0x35ff` and the symmetric runtime tail at `0x3510..0x355c`.
That reclaimed space is neither user arena nor reconnect-safe storage. This
harness is not a 15-sector-K memory proof.

It is deliberately not a product runtime. It copies the stable baseline product
four-sector nucleus and production NE.DRV into an isolated floppy, then adds
the K14 TLS 1.3 overlays and a small controller chain. It does not modify the
shipping `SEED.SYS`, driver sources, K14 overlays, or the existing literal
phase-chain harness.

## Scope and safety

- The build step never starts 86Box and performs no network I/O.
- The floppy contains only `SEED.SYS` and `SEED/DRIVERS/NE.DRV`.
- The copied TLS 1.2/API LINK window is zeroed.
- Exactly one hash-pinned 50-byte
  `HEAD /v1/models HTTP/1.1` request is retained. It has no body or credential.
- The live-only fresh ClientHello includes exactly one
  `psk_key_exchange_modes = psk_dhe_ke` extension
  (`00 2d 00 02 01 01`) without a `pre_shared_key` offer. This advertises the
  PSK-DHE mode needed for a reusable TLS 1.3 ticket; ticket issuance remains
  the server's choice.
- After subtracting that exact allowlisted value, a whole-image literal gate
  rejects Authorization, Bearer, every other HTTP method/path, model/input
  request bodies, and common API-key material.
- The three `api.openai.com` host literals are endpoint DNS, ClientHello SNI,
  and the allowlisted HEAD Host header.
- No credential is loaded, persisted, or sent. `CANARY COMMIT` is a transport
  and tentative-ticket milestone only; it cannot unlock a business request.

In the default fixture build, `d||z` and the ClientHello random/session values
are public and deterministic. The 8088 itself still performs ML-KEM KeyGen,
constructs and sends the ClientHello, parses the real ServerHello, computes the
candidate secret and TLS schedule, verifies the protected server flight, and
constructs and transmits the client Finished, derives application keys,
encrypts the compiled HEAD, tag-verifies server application records under
provisional traffic keys, and parses bounded NewSessionTickets. This isolates
the scheduling question; it does not claim production entropy, ML-KEM FO
validation, certificate authentication, secure commit, ticket persistence, or
resumption.

The `--secure` build removes that public fixture. After local NIC setup but
before the product's first DHCP call, the target automatically makes 256
one-sector read-only BIOS calls alternating CHS `0/0/1` and `39/0/8`. It
latches PIT channel 0 before and after every completion, absorbs the two counts
and sample index through SHA3-256, and derives two domain-separated one-shot
128-byte attempt bundles. Both bundles are duplicated into volatile NE2000
card RAM before DHCP can reuse the low output window. The collector performs
no disk write and requires no operator input. Elapsed time alone receives zero
entropy credit, and 86Box timing receives zero credit; representative physical
drives still require min-entropy characterization and calibrated health tests.
See `floppy_entropy_README.md`.

## Offline build

The current K14 fixture outputs and stable baseline product artifacts are
prerequisites:

```sh
python3 tools/crypto-bench/tls13-poc/build_poc_harness.py --k14
python3 tools/crypto-bench/tls13-poc/build_live_k15.py
python3 tools/crypto-bench/tls13-poc/live_k15_check.py
python3 tools/crypto-bench/tls13-poc/live_k15_pcap.py --self-test
```

Build and gate the automatic read-only secure candidate separately:

```sh
python3 tools/crypto-bench/tls13-poc/build_live_k15.py \
  --secure \
  --build-dir build/crypto-bench/tls13-live-secure
python3 tools/crypto-bench/tls13-poc/live_k15_secure_fo_check.py \
  --build-dir build/crypto-bench/tls13-live-secure
```

Default fixture outputs are written under:

```text
build/crypto-bench/tls13-live-k15/
```

The important files are:

```text
floppy-160k-live-k15.img
LIVEK15.BAS
manifest.json
```

`manifest.json` records every appended phase's disk sector, load key,
destination, size, and hash, plus the current product ABI addresses used by the
controllers.

After final evidence reconciliation, a fresh offline build reproduced the
hardened attempt-6 `SEED.SYS` and floppy byte-for-byte. The regenerated
manifest differed only in absolute output paths; the replay did not launch
86Box or use the network.

## Memory and phase lifetime

Boot, HELLO, and candidate/schedule controllers occupy `0x3400` before
symmetric initialization. After endpoint/DNS setup retires, the boot
controller installs only a tiny self-overwrite trampoline at `0x0f00`; it
loads the HELLO and crypto controllers directly at `0x3400`, never staging a
sector through the live ciphertext at `0x08c0`.

The 500-byte crypto controller contains the 146-byte track-batched loader and
the persistent post-Finished services. It copies the loader to
`0x0f00..0x0f92` before candidate recovery. `sym_init` then owns
`0x3510..0x355c`; transition, zero-window, serial, and fail services occupy the
untouched phase-owned tail `0x355d..0x35f3`. No harness byte is installed or
written in the product arena/context at `0x3e40..0x3eff`.

After candidate recovery, transcript import, and the critical schedule have
consumed the ML-KEM ciphertext, the 950-byte protected-flight controller is
loaded as a two-sector phase at `0x0900..0x0cff`. After client Finished it is
cold-replaced by the separate 1,013-byte post-Finished controller in the same
slot. This slot:

- starts above the production NIC RX frame at half-open
  `[0x0700,0x08b6)`;
- reuses dead candidate ciphertext bytes at `0x0900..0x0cff`;
- ends before the transcript-then-quarantine boundary at `0x0d00`; and
- remains below the track-batched delta loader at `0x0f00`.

Candidate `K′` is originally returned at `0x3b9c`, inside the high band that
`sym_init` deliberately clears. Before init, the transition controller copies
those 32 bytes to dead ciphertext space at `0x08c0..0x08df`; after init it
copies them to the symmetric input at `0x3600` and zeroizes the temporary.

Each controller load occurs while the peer sees a zero receive window. The
successor drains unacknowledged copies and advertises the ordinary window.
After transcript import, three dead-lifetime spans become a 1,624-byte
plaintext scatter quarantine: `0x0d00..0x0eff` (512 bytes),
`0x3600..0x3837` (568 bytes), and `0x3920..0x3b3f` (544 bytes). The gap at
`0x3838..0x391f` preserves the client and server application keys, IVs,
sequences, resumption material, and received tag; native ticket state starts
at `0x3b40`. Before tag verification, record handling depends only on public
length and offset and merely decrypts and copies into those spans. Only after
authentication may the controller inspect the inner type or feed HTTP state.
It accepts either bounded HTTP header bytes for the one outstanding HEAD or
one to four complete NewSessionTicket messages; the first ticket is retained
only in native RAM and later tickets are validated and drained. A ticket
extension vector must be empty, contain exactly the four-byte `early_data`
value, or contain that extension followed by one well-formed zero-length
unknown extension (never a second `early_data`).

The 160 KiB image carries five zero padding sectors solely to align critical
reads on its eight-sector tracks: two before candidate put the
five-sector candidate at absolute LBA 80, and three before SYM put the
eight-sector critical restore at absolute LBA 88. Candidate, restore, and both
two-sector low controllers therefore each require one batched BIOS call.
If a BIOS rejects a multi-sector read, the loader resets the disk and falls
back to single-sector reads.

The sequence is:

1. Production hardware, driver, and local packet-I/O initialization run
   unchanged.
2. In the secure build only, the collector completes all 256 reads, conditions
   the result, and duplicates both attempt bundles into volatile card RAM.
3. Production DHCP then runs unchanged. No secure-build network transmission
   can precede the collector and vault writes.
4. The live controller preloads the full symmetric image.
5. Production endpoint DNS and TCP open/close establish a cached target.
6. The 8088 performs offline ML-KEM KeyGen.
7. The cached connector opens a fresh socket and sends the live-only
   ticket-eligible ClientHello.
8. ServerHello is consumed through the production TCP receive/ACK path.
9. A zero-window ACK pins the exact post-ServerHello boundary.
10. Candidate recovery, transcript import, and the critical symmetric schedule
   run.
11. The consolidated protected-flight controller is loaded at
   `0x0900..0x0cff`, with zero writes to `0x3400..0x35ff`.
12. Stale retransmissions are drained and an ordinary window update resumes
    the protected server flight.
13. The server record/tag/Finished are verified.
14. The 58-byte client Finished is sent once through production
    `tcp_send_payload`.
15. The protected controller derives only the client application write side,
    sends exactly one 72-byte encrypted HEAD record, advertises zero window,
    and cold-loads the post-Finished controller over `0x0900`.
16. The successor derives the deferred server application read and resumption
    secrets, reopens the window, AEAD-tag-verifies the response under
    provisional traffic keys into the three-span scatter quarantine, and
    tag-verifies/parses at least one tentative NewSessionTicket.
17. In the default fixture, only the conjunction emits `CANARY COMMIT`, `PASS`,
    and `RESULT`; no credential, persistence, resumption, identity proof, or
    secure commit is reachable. The secure build instead continues through
    full FO validation and the exact-leaf identity checkpoint before its
    terminal success.

## Strict live-server shape

The harness fails closed unless the live flow matches the shape already used
by the TLS 1.3 spike:

- one TLS handshake record containing the 1,210-byte hybrid ServerHello;
- exactly one of the two observed RFC-legal fresh extension orders,
  `supported_versions, key_share` or `key_share, supported_versions`;
- zero or one one-byte compatibility CCS;
- exactly one encrypted handshake record;
- no TLSInnerPlaintext padding;
- no coalesced or already-queued later record before client Finished;
- after client Finished, only encrypted application records with at most 1,624
  plaintext bytes per record;
- inner application data only while the single HEAD is outstanding, with an
  exact `HTTP/1.1` final `2xx`, `4xx`, or `5xx` header ending at
  `CRLFCRLF` within 2,048 bytes; and
- inner handshake records containing only complete, bounded type-4
  NewSessionTickets, with every message beginning and ending in the same
  record and no more than four messages cumulatively across the connection;
  accepted extension vectors are empty, exact four-byte `early_data`, or
  `early_data` followed by one zero-length unknown extension. A duplicate
  `early_data`, KeyUpdate, cross-record ticket fragment, and every other
  post-handshake type fail closed.

The offline controller gate covers the positive zero-CCS and one-CCS paths and
rejects duplicate CCS, a coalesced second record, and a second record delivered
through a separate queued NIC/TCP callback before any client Finished transmit.
It also covers a fragmented 72-byte HEAD send, an exact 1,124-byte plaintext
response crossing both scatter seams, HTTP continuation across two records,
both ticket/HTTP orders, two coalesced bounded tickets, exact milestone
conjunction after a clean ACK boundary, arena/context and retained-key
sentinels, cap overflow, wrong inner types, padding rejection, tag-verified
alerts, exact live `early_data` plus a trailing zero-length extension,
malformed and duplicate ticket extension vectors, real-AEAD protected-flight
bad-tag/tampered-tail cases that reach tag verification without touching
retained Finished state, and a bad post-Finished tag that cannot escape
quarantine or mutate HTTP commit state.

These are PoC assumptions, not a proposed general TLS parser. A live failure
may therefore mean the current server shape changed rather than that the
crypto path is wrong.

The independent capture oracle mirrors these target constraints without
discarding record order. It requires the exact optional compatibility CCS
before the protected handshake record, ledgers every later server record, and
marks any post-protected outer type other than `0x17` target-incompatible.
For each parsed ticket, `message_within_seed_bounds` reports only that
message's local 384-byte/lifetime/nonce/identity/extension limits;
`target_acceptable` additionally requires a complete NST-only record and the
four-ticket connection-wide ceiling. Consecutive handshake records are never
concatenated to make a fragmented ticket appear acceptable.
This contract is capture-oracle schema v3. It deliberately removes the
ambiguous v2 `within_seed_bounds`/`seed_bound_violations` names and claims no
v1 or v2 semantic compatibility.

## Live run, only after explicit approval

Do not run the live command as part of the offline build. The dedicated runner
has a credential-free dry preflight that performs no VM launch or network I/O:

```sh
python3 tools/crypto-bench/tls13-poc/run_live_k14_16k.py --dry-run
```

Once a VM/network run is explicitly approved, use the original-speed
`vm-net-ne2k8` profile:

```sh
python3 tools/crypto-bench/tls13-poc/run_live_k14_16k.py --run
```

For the secure candidate, point the same runner at its build:

```sh
python3 tools/crypto-bench/tls13-poc/run_live_k14_16k.py \
  --run \
  --build-dir build/crypto-bench/tls13-live-secure
```

Every live run changes the generated floppy image to host mode `0444` before
86Box starts, verifies that a write-only open is denied, hashes it before and
after the run, and restores its original mode. An unchanged hash and restored
mode are mandatory success gates, and the run record freezes all four facts.
There is no writable-media fallback in this path.

The explicit `--run` gate launches 86Box directly, configures COM1 as the
stdout-backed virtual console, injects BASIC at the proven 16 KiB timings,
starts the host pcap before typing `RUN`, and stops on the first exact `RESULT`
or after the bounded timeout. After `RESULT`, it retains the VM and pcap for a
two-second observation grace so a completed emulated NIC transmit can cross
the host bridge. That grace is outside the measured deadline. It restores the
profile config and NVR byte-for-byte. Before launch it also verifies that the
profile remains the exact IBM PC/8088, 4.772728 MHz, multiplier-1,
dynarec-disabled profile and that the rewrite produced exactly 16 KiB RAM.
It then runs `live_k15_pcap.py` automatically. Full emulator stdout, extracted
COM1, pcap, wire JSON, and the combined run record are written as
`live-stdout.txt`, `live-com.txt`, `live.pcap`, `live-wire.json`, and
`live-run.json` under `build/crypto-bench/tls13-live-k15/`.
Run-record schema v2 freezes the exact manifest, core, and floppy hashes in
the record itself.

`K15 boot` is BIOS-only because it appears before serial initialization. The
default fixture continues at `K15 net ready`; its remaining controller
milestones (`preflight cache`, `offline keygen`, and `live connect`) are
mirrored to bounded COM1. The secure build instead emits `K15 local ready`,
then:

```text
ENTROPY START 256
ENTROPY PASS 256
```

before DHCP or any other network transmission. These markers establish
functional collection, not physical min-entropy. A terminal run then emits one
of:

```text
DEADLINE PASS
HEAD TX
TICKET
HEAD OK
CANARY COMMIT
PASS
RESULT
```

`TICKET` and `HEAD OK` may appear in either order. `CANARY COMMIT` appears
only after both and after the current TCP payload has been drained and ACKed.

or:

```text
FAIL
RESULT
```

The deadline marker is emitted from the protected controller before
application-key derivation and the post-Finished disk load. The pcap remains
authoritative for the exact ServerHello-to-client-Finished interval.

## Authoritative wire timing

The guest counter includes the real TCP receive/ACK, crypto, phase loads,
window transition, verification, and Finished transmit call. Its first tick
is necessarily sampled after the resident receive routine returns, so the
pcap is the authority for the literal on-wire interval:

```sh
python3 tools/crypto-bench/tls13-poc/live_k15_pcap.py \
  build/crypto-bench/tls13-live-k15/live.pcap \
  --json-out build/crypto-bench/tls13-live-k15/live-wire.json
```

The analyzer identifies Seed's hybrid X25519MLKEM768 ClientHello rather than
ordinary host browser traffic, reassembles the TCP stream, and measures from
the first byte of the exact ServerHello record to the first byte of the
58-byte client Finished record. The gate is `<= 15.000000` seconds.

The deeper offline reconstruction validates the ordered record shape, derives
the deterministic handshake/application keys, verifies both Finished values,
and applies the target post-Finished acceptance rules:

```sh
python3 tools/crypto-bench/tls13-poc/live_k15_capture_oracle.py \
  build/crypto-bench/tls13-live-k15/live.pcap
python3 -m unittest \
  tools/crypto-bench/tls13-poc/test_live_k15_capture_oracle.py
```

## Post-Finished receive bound

The post-Finished controller deliberately caps each tag-verified plaintext
record at 1,624 bytes. The passing live HEAD response was 1,126 plaintext
bytes: 1,125 HTTP bytes plus the inner application-data type. The current
scatter layout therefore leaves 498 bytes of headroom while retaining both
traffic directions' application state. This is a current-provider PoC bound,
not the TLS record maximum. A larger record fails closed before any scatter
write; supporting it would require another AEAD-verified buffering or
streaming architecture.

## Exact-speed post-Finished canary result

On 26 July 2026, the current image passed the exact original-speed
`vm-net-ne2k8` profile: IBM PC 5150, 4.772728-MHz 8088, dynarec off, exactly
16 KiB RAM, and ROM BASIC entry. Its credential-free terminal sequence was:

```text
DEADLINE PASS
HEAD TX
TICKET
HEAD OK
CANARY COMMIT
PASS
RESULT
```

The hardened attempt-6 host pcap measured 13.404952 seconds from the first
ServerHello byte to the first client-Finished byte, leaving 1.595048 seconds against the
15-second gate. The independent capture oracle verified the server Finished,
the target's exact client Finished and HEAD, two bounded 222-byte
NewSessionTickets in server application sequence 0, and the 1,125-byte HTTP
401 response in sequence 1. Both post-Finished records first appeared at
SYN + 14.718766 seconds.

The run used core SHA-256 `ccedcd8d...` and floppy SHA-256 `be79ab23...`.
During the run the floppy was host mode `0444`, a write-only open was denied,
and its before/after hash was unchanged; the original mode was restored.
This establishes the credential-free live dialogue and volatile ticket
capture on one representative NIC/profile. It is not physical
write-protection evidence or the full secure tier.

## Exact-speed deadline baseline

On 26 July 2026, the predecessor 89-sector deadline-only image passed three
independent original-speed `vm-net-ne2k8` runs. The frozen hashes and per-run
evidence are in `live_k14_16k_results.json`.

Those three v1 run records bind the prior `3f263028...` core and
`d70ce462...` floppy bytes. They establish the client-Finished deadline
baseline only. They do not validate the new app-key derivation, cold
post-Finished controller, HEAD response drain, ticket capture, canary
milestones, or current artifact hashes; the separate passing canary result
above supplies that evidence.

| Run | Guest `SH-TX` | Wire seconds | Margin |
|---|---:|---:|---:|
| repeat 8 | 240 ticks | 13.536559 | 1.463441 |
| repeat 9 | 240 ticks | 13.536609 | 1.463391 |
| repeat 10 | 239 ticks | 13.483030 | 1.516970 |

The worst observed wire result is therefore 13.536609 seconds. The server
ACKed all three Finished records 46.5–66.7 ms after they appeared on the host
interface.

An earlier run stopped its pcap only 13.396 seconds after the ServerHello and
reported `missing-client-finished` despite guest `PASS / RESULT`. Repeating the
same image with the explicit post-result observation grace passed. That result
was a capture-shutdown race; it is not evidence that the NIC or bridge lost
the Finished. The current offline controller gate separately pins one exact
58-byte Finished transmit and one logical TCP-sequence advance.

The frozen baseline is a deadline, memory-lifetime, and transport proof only.
The current image extends it through a credential-free HEAD response and
tentative RAM-only ticket capture. Both use public deterministic seeds and
fixed X25519 `u=9`; neither performs complete ML-KEM FO validation or
certificate/WE1/CertificateVerify authentication. The image contains no
credential and cannot issue an authenticated business request. Neither guest
nor wire `PASS`, nor `CANARY COMMIT`, proves peer identity, atomic secure
commit, ticket recovery, resumption, TLS conformance, or the product secure
tier. Credentials must remain unreachable until every quarantined proof
succeeds.
