# TLS 1.3 rearchitecture spike

This directory contains isolated oracles, 8086 kernels, target benchmarks, and
live probes for a possible **replacement** of Seed's TLS 1.2 path. It does not
edit the runtime or NIC drivers, and its current result is a conditional
research direction—not a production TLS profile.

The goal is authenticated TLS 1.3 on a self-contained 4.77 MHz 8088 with
16 KiB. The original machine must generate its own per-boot keys and caches;
no modern helper supplies a ticket, KEM answer, scalar, or verification table.

The current candidate uses:

```text
TLS 1.3
TLS_CHACHA20_POLY1305_SHA256
X25519MLKEM768 wire group
ecdsa_secp256r1_sha256
Brotli certificate compression
```

It has three independent review boundaries. The client sends X25519 `u=9` and
copies the server's X25519 public share, so effective secrecy is ML-KEM-only.
It derives provisional handshake keys from the K-PKE candidate before full
ML-KEM re-encryption/implicit-rejection validation. Finally, it sends client
Finished and fixed application probes before validating the certificate and
CertificateVerify. This last step preserves TLS wire ordering but violates the
normal peer-authentication processing order.

Before client Finished, the design verifies the protected server-flight AEAD
tag under the provisional traffic key and verifies server Finished as
provisional key confirmation. Neither authenticates server identity. Only
after full KEM and leaf/WE1/CertificateVerify validation may one atomic
transition load credentials.

This is not conforming X25519MLKEM768 and is not FIPS 203 decapsulation at
client Finished. The artifacts exist to determine whether the quarantine can
be implemented and reviewed safely. The earlier P-256/RSA measurements remain
below as rejected comparison data.

The protocol oracle constructs a coherent synthetic RSA-profile handshake
with:

- a normal, nontrivial P-256 scalar for the rejected authenticated comparison;
- the legacy scalar-one shortcut as a separate checked negative-design vector;
- TLS 1.3 HKDF handshake and application traffic secrets;
- encrypted EncryptedExtensions, Certificate, CertificateVerify, and Finished;
- a deterministic RSA-2048 certificate and RSA-PSS CertificateVerify;
- a sample encrypted application record;
- record replay under one-byte, 384-byte MSS, and awkward mixed TCP fragments;
- fail-closed AEAD-tag, RSA-PSS transcript/signature, and Finished checks.

Two deterministic server-flight shapes are checked:

- a compact four-record fixture that keeps individual crypto boundaries easy to
  inspect; and
- the actual observed OpenAI geometry, represented as one protected record
  containing `EncryptedExtensions=10`, `Certificate=4000`,
  `CertificateVerify=264`, and `Finished=36` bytes.

For the observed shape, the four handshake messages total 4,310 bytes. Adding
the TLS inner content type and 16-byte AEAD tag produces a 4,327-byte record
payload and a 4,332-byte wire record. The valid synthetic leaf remains the
first Certificate entry; a second strictly valid deterministic X.509 entry,
padded through a private test extension, fills the observed chain length and
proves that later entries are bounded, transcript-hashed, and drained without
being mistaken for the pinned leaf. The combined record is replayed at one byte
per TCP fragment, Seed's 384-byte MSS, and a mixed boundary schedule.

The compact ECDSA geometries are deterministic symmetric/streaming fixtures.
The separate exact target authentication gate executes the leaf-under-WE1 and
CertificateVerify-under-leaf equations, strict DER/range checks, and P-256
point checks. Target Brotli/X.509/time parsing and the product phase link
remain integration gates.

Run the complete offline gate:

```sh
python3 tools/crypto-bench/tls13-spike/tls13_spike.py
```

Emit the machine-readable sizing report:

```sh
python3 tools/crypto-bench/tls13-spike/tls13_spike.py --json
```

Run the unit suite:

```sh
python3 -m unittest discover -s tools/crypto-bench/tls13-spike -p 'test_*.py'
```

Run the static K/module replacement ledger:

```sh
python3 tools/crypto-bench/tls13-spike/size_ledger.py
```

Use `--json` for its machine-readable form. The ledger assembles only temporary
artifacts, reports every exact current/removable label span, and keeps
unimplemented TLS 1.3 parser/transition code explicit as an unknown.

## Integrated literal-16-KiB checkpoint

The earlier synthetic ML-KEM kernel proxy in this document has now been
superseded by complete target arithmetic. Under 86Box v9001 configured as a
4.772728 MHz 8088 with 16 KiB RAM, no dynarec, and the ROM BASIC sidecar:

| Exact operation | Repetitions | BIOS ticks | Seconds/op |
|---|---:|---:|---:|
| `K-PKE.Decrypt + G` provisional candidate | 5 | 173 total | 1.900 |
| complete valid ML-KEM-768 decapsulation | 3 | 1,357 total | 24.845 |
| complete one-bit-invalid decapsulation | 3 | 1,357 total | 24.845 |
| `KeyGen_internal(d,z)` from a 64-byte fixture | 1 | 401 | 22.025 |

These are literal-configuration emulator measurements, not physical IBM PC
measurements. The valid and invalid selected secrets match both independent
Python arithmetic and OpenSSL 3.6.2; all 2,400 generated key bytes also match.
The decapsulation image streams all nine SHAKE128-generated matrix
polynomials—there is no 4,608-byte matrix cache.

The frozen invalid vector flips `c[0]` but happens to preserve the valid
message and `G` output. Equal coarse tick totals therefore prove only that the
rejection/`J`/selection path executed; they are not fixed-work or constant-time
evidence.

The isolated sizes are 10,149 bytes / 20 sectors for decapsulation and 7,063
bytes / 14 sectors for KeyGen. Both fit below the 16-KiB ceiling as standalone
images, but they did **not** by themselves form a product layout: loading
decapsulation would overwrite the KeyGen output and Seed's resident nucleus,
and the decapsulation image extends beyond the current K window. This was the
hard gate at the isolated-measurement stage. The later K14 fixture and live
PoC supply the measured sparse handoff and literal-16-KiB phase/lifetime link
through client Finished. Full post-Finished coexistence, atomic credential
unlock, and the product secure floor remain open.

The conventional 24.845-second decapsulation misses a 15-second pre-Finished
interval by 9.845 seconds. Reaching 15 seconds would require a 39.6% runtime
reduction, or about 1.656x throughput. The exact 1.900-second candidate leaves
a nominal **4.751-second** remainder after the separately measured
7.0305-second compressed-flight and 1.3182-second critical-HKDF spans.
ServerHello parsing/hash, TCP, client-Finished encryption/transmit, and
immediate HEAD setup still consume that remainder, so this isolated subtotal
was not an integrated deadline pass. The later live K14 result supersedes this
projection for its exact provider shape and NE.DRV path.

In the original component ledger, the candidate and critical HKDF were
literal-16-KiB ROM-BASIC measurements. Only the compressed-flight component
used the same original-speed CPU and a statically checked `<0x4000` address
layout in a 64-KiB BIOS-entry benchmark VM, and the 15-second close bracket
used a P-256/RSA profile. That subtotal was therefore a
cross-harness/profile projection. The later live K14 PoC resolves the selected
provider-shaped pre-Finished path on the literal-16-KiB NE2K profile; it does
not establish a held-Finished distribution, other NIC families, or the
post-Finished secure commit.

The inferred post-candidate FO tail is 22.944 seconds, only 2.056 seconds below
the observed 25-second HEAD cadence before parser/network/checkpoint overhead.
Those HEAD observations used a standards-complete host OpenSSL handshake, not
fixed `u=9` or provisional pre-FO target execution. It must be sliced or
rescued through a promoted ticket; the isolated timing and transferred cadence
are not a keepalive proof.

A credential-free host/OpenSSL live observation established that OpenAI
accepted a same-boot TLS 1.3 session ticket with ChaCha20-Poly1305. The resumed
handshake omitted Certificate and CertificateVerify but still carried PSK and
an X25519MLKEM768 key share. The frozen OpenSSL text parser flattened extension
reports across server messages, so the result does not claim per-message
extension attribution. A ticket captured tentatively on the first connection
can, after the original proof promotes it, recover from a closed socket without
repeating Brotli/leaf/WE1/CertificateVerify work. It does not remove fresh KEM
work, prove target resumption, or justify persistent/cross-boot tickets.
The exact measurement source is preserved as
`tls13_ticket_resumption_probe_measurement_v1.py`. The checked-in v2 JSON is an
offline curation of that observation: raw values and output hashes are
unchanged, while the schema and flattened-extension labels are corrected. The
current `tls13_ticket_resumption_probe.py` emits the qualified v2 shape on any
future opt-in live run.

The restart oracle separately passes 516 modeled torn-write/crash boundaries,
4,096 advances, and 512 single-byte corruptions. It proves deterministic
attempt-seed non-reuse only when the latest writable-medium state is not copied
or rolled back; it does not establish physical entropy quality or a
write-protected cold-start path.

The exact standalone authentication image contains 9,790 bytes and rounds to
20 sectors through `0x3800`, below the ROM BASIC loader at `0x3a00`. It
executes both P-256 signatures in the required order and records a 74-byte
routine-only Unicorn stack high-water plus a 706-byte resumable Straus
checkpoint. Its issuer/leaf identities are deterministic synthetic fixtures,
not the live OpenAI chain. A cycle model over the exact executed
instruction/data trace at
4.772728 MHz estimates **94.419 seconds** cold and **89.167 seconds**
post-Finished. This is not an 86Box timing: both the authentication image and a
known-good HKDF control encountered the same 0-Hz/no-COM1 emulator startup
failure, so neither timeout was converted into a result.

The aggregate authentication is slow, but every candidate checkpoint interval
is comfortably below the observed 25-second HEAD cadence: the longest is one
width-4 table generation at **2.591 seconds**; one modular inverse is 0.464
seconds, one modular multiply 0.321 seconds, and one Straus digit at most 0.399
seconds. That supports a resumable scheduler design. It does not prove live
network scheduling or cover target Brotli, X.509/SPKI policy, or trusted time.

Exact arithmetic details and provenance are in
`mlkem768_integrated_README.md` and
`mlkem768_integrated_results.json`. Authentication evidence is in
`auth_integrated_results.json`; ticket evidence is in
`tls13_ticket_resumption_live_results.json`. The current decision also
binds the literal K14 full-chain fixture record and the three-run live
production-nucleus/NE.DRV wire record from the sibling `tls13-poc` directory.
Together those records validate the phase/lifetime architecture through client
Finished while keeping the secure-floor, product-replacement, and TLS 1.2
removal gates explicitly false.

Audit all frozen decision inputs and their transitive source hashes:

```sh
python3 tools/crypto-bench/tls13-spike/integrated_spike_check.py
```

The machine-readable architecture decision is
`integrated_spike_results.json`.

## Target timing results

`run_8088.py` is the original-speed IBM PC timing runner. The generic
`run_286_bench.py` accepts any standalone benchmark assembly, wraps it with
`bench_boot.asm` in a 360 KiB image, runs one or more IBM AT clocks, and
restores both the shared VM configuration and generated CMOS state in
`finally`. Both runners select 86Box 9001's stdout virtual console:

```text
serial1_device = stdio
[Virtual Console (COM) #1]
mode = 0
```

`mode = 1` creates a pseudoterminal. The legacy
`serial1_passthrough_enabled` migration selects that PTY mode without exposing
its path to the old capture helper.

The encrypted-flight benchmark incrementally copies, verifies the record AEAD
tag, decrypts, and transcript-hashes two live-observed OpenAI shapes. The RSA profile's
4,327-byte payload has checksum `73AA` and operation counts `69/272/68`
(ChaCha/Poly/SHA). Advertising the compact pre-286 ECDSA profile produced a
2,638-byte payload with a 903-byte leaf, checksum `7EF6`, and counts
`42/166/42`. Both frozen tags, transcript digests, inner type `16`, and
component checks passed:

| Live shape | RSA profile | Compact ECDSA profile |
| --- | ---: | ---: |
| EncryptedExtensions | 10 B | 10 B |
| Certificate | 4,000 B | 2,495 B |
| CertificateVerify | 264 B | 80 B |
| Finished | 36 B | 36 B |
| Transcript / protected payload / wire | 4,310 / 4,327 / 4,332 B | 2,621 / 2,638 / 2,643 B |
| Leaf DER / 384-byte TCP chunks | 1,300 B / 12 | 903 B / 7 |

| Machine/profile | BIOS ticks | Flight time |
| --- | ---: | ---: |
| 8088 at 4.77 MHz, compact ECDSA | 172 | 9.4472 s |
| 8088 at 4.77 MHz, RSA | 282 | 15.4890 s |
| 286 at 6 MHz, compact ECDSA | 43 | 2.3618 s |
| 286 at 6 MHz, RSA | 70 | 3.8448 s |
| 286 at 8 MHz, compact ECDSA | 32 | 1.7576 s |
| 286 at 8 MHz, RSA | 52 | 2.8561 s |

The candidate enables Brotli certificate compression. The observed protected
payload falls to 1,942 bytes: the 1,799-byte CompressedCertificate expands to
the exact 2,491-byte Certificate body. Its original-speed 8088 result is:

| Brotli ECDSA flight component | BIOS ticks | Time |
| --- | ---: | ---: |
| ChaCha20 + XOR/copy | 40 | 2.1970 s |
| Poly1305 + stream/copy | 66 | 3.6251 s |
| SHA-256 transcript | 21 | 1.1534 s |
| **complete protected flight** | **128** | **7.0305 s** |

The narrowed HKDF path through both Finished messages takes 24 ticks /
**1.3182 s**. Before the exact KEM implementation, adding the synthetic
provisional proxy gave a historical nominal subtotal of **9.8317 seconds**.
The superseding exact-candidate subtotal is reported in the integrated
checkpoint above. Hybrid ServerHello hashing, TCP/parser work, client Finished
AEAD/transmit, and immediate HEAD setup remain excluded, so only a final
product-integrated run can establish a deadline fit.

The isolated 8088 component image measures the same receive copies and crypto
state shuttles. Component sums differ from each full path by one BIOS tick:

| Profile | ChaCha + XOR/copy | Poly + stream/copy | SHA + copy | Full |
| --- | ---: | ---: | ---: | ---: |
| compact ECDSA | 53 / 2.9110 s | 89 / 4.8884 s | 29 / 1.5928 s | 172 / 9.4472 s |
| RSA | 87 / 4.7785 s | 147 / 8.0740 s | 47 / 2.5815 s | 282 / 15.4890 s |

Offline and 8088 gates:

```sh
python3 tools/crypto-bench/tls13-spike/flight_profiles_check.py

python3 tools/crypto-bench/tls13-spike/run_8088.py \
  --asm tools/crypto-bench/tls13-spike/flight_ecdsa_components_bench.asm

python3 tools/crypto-bench/tls13-spike/run_8088.py \
  --asm tools/crypto-bench/tls13-spike/flight_components_bench.asm

python3 tools/crypto-bench/tls13-spike/run_8088.py \
  --asm tools/crypto-bench/tls13-spike/flight_certcomp_components_bench.asm
```

The checked-in machine-readable result is `flight_8088_results.json`.

The HKDF benchmark reports both the complete schedule and the selected hot
schedule with the public no-PSK `derived` value baked in. Every run produced
checksum `2D5F`; the independent 528-byte output-bundle validation returned
`1`:

| Machine | Full schedule | Baked-hot schedule |
| --- | ---: | ---: |
| 8088 at 4.77 MHz | 47 ticks / 2.5815 s | 41 ticks / 2.2519 s |
| 286 at 6 MHz | 13 ticks / 0.7140 s | 11 ticks / 0.6042 s |
| 286 at 8 MHz | 9 ticks / 0.4943 s | 8 ticks / 0.4394 s |

Commands for the 286 measurements:

```sh
python3 tools/crypto-bench/tls13-spike/run_286_bench.py \
  --asm tools/crypto-bench/tls13-spike/flight_bench.asm \
  --mhz 6 8 --expect FLIGHT=73AA --require 'CHECK PASS'

python3 tools/crypto-bench/tls13-spike/run_286_bench.py \
  --asm tools/crypto-bench/tls13-spike/flight_ecdsa_bench.asm \
  --mhz 6 8 --expect FLIGHT=7EF6 --require 'CHECK PASS'

python3 tools/crypto-bench/tls13-spike/run_286_bench.py \
  --asm tools/crypto-bench/tls13-spike/hkdf_bench.asm \
  --mhz 6 8 \
  --expect HKFULL=2D5F --expect VFULL=0001 \
  --expect HKHOT=2D5F --expect VHOT=0001
```

In the rejected conventional profile, the RSA flight plus baked-hot key
schedule totals **17.7409 seconds after ServerHello** and misses the observed
15.0-second provider close by 2.7409 seconds. The uncompressed ECDSA flight
plus the same wider schedule totals **11.6991 seconds**. These results motivated
the compressed profile; they are not a recommendation for an unauthenticated
functional tier.

The provider deadline was checked independently with
`tls13_patience_probe.py` under the P-256/RSA comparison profile. A localhost
relay forwarded the ClientHello and server flight but held the client's
compatibility CCS plus encrypted Finished (64 wire bytes):

| Held-client delay | Result |
| --- | --- |
| 12.0 s | accepted; a post-release NewSessionTicket proved remote completion |
| 15.0 s | OpenAI closed upstream before release |

In the failed run the upstream EOF arrived 14.994 seconds after the hold
started. This is a cross-profile working bound, not a candidate-profile
deadline or provider SLA. The bounded raw result is checked in as
`patience_results.json`; the 8088 component results are in
`flight_8088_results.json`.

```sh
python3 tools/crypto-bench/tls13-spike/tls13_patience_probe.py \
  --delay-seconds 12 --overall-timeout-seconds 35
```

Gate the real 8086 EMSA-PSS decoder against the deterministic recovered-RSA
vector and its tamper matrix:

```sh
python3 tools/crypto-bench/tls13-spike/pss_decode_bench.py
```

The decoder streams MGF1 one SHA-256 digest at a time rather than allocating
the 223-byte mask. It assembles to **272 bytes**, uses **74 bytes** of transient
scratch, and consumes nine SHA-256 blocks after RSA recovery. Hashing the
130-byte TLS `CertificateVerify` signed-content construction raises the full
post-RSA operation to twelve SHA-256 blocks.

The 86Box ground-truth runner includes that signed-content hash and restores
the tracked VM configuration after each run:

```sh
python3 tools/crypto-bench/tls13-spike/run_pss_286.py 6
python3 tools/crypto-bench/tls13-spike/run_pss_286.py 8
```

Measured on the integer-only IBM AT profiles:

| machine | four iterations | per CertificateVerify post-RSA |
| --- | ---: | ---: |
| 286 at 6 MHz | 9 BIOS ticks | 0.124 s |
| 286 at 8 MHz | 7 BIOS ticks | 0.096 s |

The BIOS-tick resolution is 54.925 ms, so four iterations leave about
13.7 ms of quantization per reported operation. These timings exclude the
existing separately measured RSA-2048 modular exponentiation.

The synthetic RSA key is deterministically generated by the existing X.509
oracle and is test-only. It is neither shipped nor suitable for production.

## Secure-tier timing bound

The generic runner also measured the exact P-256 implementation and optimized
`montsqr` RSA implementation currently shipped in Seed. Its include/define
options make the selected implementation explicit instead of silently using
the older sibling benchmark include:

```sh
python3 tools/crypto-bench/tls13-spike/run_286_bench.py \
  --asm tools/crypto-bench/p256_bench.asm \
  --nasm-define 'P256_SRC="core/p256.inc"' \
  --mhz 6 8 --expect ECDHE=D51E

python3 tools/crypto-bench/tls13-spike/run_286_bench.py \
  --asm tools/crypto-bench/rsa_bench.asm \
  --include-dir targets/ibm_pc_5150/boot/core \
  --mhz 6 8 --expect RSA=54F2
```

All checksums passed. Adding those asymmetric operations to the exact RSA
flight, baked-hot HKDF schedule, and post-RSA PSS measurement gives the serial
post-ServerHello bound:

| Component | 286 at 6 MHz | 286 at 8 MHz |
| --- | ---: | ---: |
| P-256 ECDHE | 120 ticks / 6.5910 s | 90 ticks / 4.9433 s |
| Optimized RSA-2048 verify | 94 ticks / 5.1630 s | 70 ticks / 3.8448 s |
| RSA encrypted flight | 70 ticks / 3.8448 s | 52 ticks / 2.8561 s |
| Baked-hot HKDF | 11 ticks / 0.6042 s | 8 ticks / 0.4394 s |
| CertificateVerify post-RSA PSS | 0.1236 s | 0.0961 s |
| **Measured serial subtotal** | **16.3266 s** | **12.1797 s** |
| **Margin against observed 15 s close** | **-1.3266 s** | **+2.8203 s** |

The 6 MHz subtotal already exceeds the observed close before production
TCP/parser/state-transition overhead, so it is a no-go for this RSA TLS 1.3
profile. Eight MHz would have been the rejected profile's candidate
authenticated floor. The machine-readable comparison is
`secure_286_results.json`.

The compact ECDSA flight also measures 2.3618 s at 6 MHz and 1.7576 s at
8 MHz, saving 1.4830 s and 1.0985 s respectively versus the RSA flight.
Authentication replaces the fast RSA public exponentiation with much slower
P-256 ECDSA verification and changes the anchor from WR1 to WE1. The later
same-connection liveness result is what makes that slow verification worth
researching; this conventional 286 comparison is no longer the selected
architecture.

## What the sizes mean

`semantic_state_bytes` reports protocol material, not assembled 8086 storage:
the post-handshake minimum is two directions of `{32-byte key, 12-byte IV,
8-byte sequence}` = **104 bytes** when KeyUpdate and resumption are out of
scope. HKDF secrets and handshake keys are transient and may overlay one
another after liveness analysis.

`host_oracle_whole_record_peak` is explicitly **not** a proposed Seed buffer.
The Python oracle buffers complete records for clarity. The RSA protected
record spans 12 TCP segments and the compact ECDSA record spans 7 at the
384-byte advertised MSS, so the device implementation must retain Seed's
existing incremental decrypt/MAC, transcript, and certificate-drain receive
shape.

The size ledger measures current K/module boundaries, conservative TLS 1.2
deletions, isolated implemented additions, and an isolated generic-RSA-recover
module transform. It does not claim a final replacement K size. That number
still requires the missing TLS 1.3 parsers/transitions and a replacement-only
runtime link.

## Historical ML-KEM kernel proxy

This section records the precursor experiment that motivated the exact
implementation above. It is retained as rejection/comparison evidence, not as
the current architecture or budget. In particular, the exact result now
implements on-device KeyGen and complete valid/invalid decapsulation, produces
the 32-byte output, and streams SHAKE128 matrix coefficients without the
calculated 4,608-byte cache assumed here.

The isolated `cpu 8086` precursor full-byte checked Keccak-f[1600], forward NTT,
inverse NTT, the reference polynomial base multiplication, and mlkem-native's
multiplication-cache/K=3 accumulated-dot strategy. It timed synthetic
dominant-kernel multisets associated with mandatory CCA re-encryption and
implicit rejection, but did not implement ML-KEM KeyGen, encapsulation,
decapsulation, ciphertext validity, or a 32-byte KEM output:

| Original 4.772728 MHz 8088 operation | BIOS ticks | Time |
| --- | ---: | ---: |
| Keccak-f[1600] | 8 | 0.4394 s |
| Forward NTT | 3 | 0.1648 s |
| Inverse NTT | 5 | 0.2746 s |
| Two K=3 cache builds + five K=3 dots | 13 | 0.7140 s |
| **Provisional-path dominant-kernel proxy** | **27** | **1.4830 s** |
| **Remaining-path dominant-kernel proxy** | **171** | **9.3922 s** |
| Conventional minimum dominant multiset | 415 | 22.7940 s |
| Same-machine precomputed-matrix multiset | 198 | 10.8752 s |

The precomputed case still needs 17 post-ServerHello Keccak permutations, six
forward NTTs, five inverse NTTs, two dynamic-vector cache builds, and five K=3
dot products. Its 10.8752 seconds excludes hash byte absorption/extraction,
key and ciphertext unpacking, CBD conversion, polynomial add/reduce,
compression, the constant-time 1,088-byte compare and selection, cache I/O,
and zeroization. Adding it to the measured 8.3487-second compressed-flight +
critical-HKDF work gives **19.2239 seconds** before those omissions, so this
portable kernel multiset cannot fit the 15-second P-256/RSA cross-profile
working bound.

Every proxy timing in this table is a single `N=1` BIOS-tick observation; the
four decimal places are only tick conversion. The 8088's 16-bit `IMUL` is
operand-dependent, so the synthetic fixtures are not conservative KAT bounds.

The two bold proxy rows isolated a separate, explicitly non-standard research split.
The provisional proxy represents the kernel multiset expected within
`K-PKE.Decrypt` and `G(m' || H(ek))`: one Keccak permutation, three forward
NTTs, one dynamic K=3 cache build, one K=3 dot, and one inverse NTT. It does not
produce a candidate. It omits ciphertext/key unpacking, decompression,
subtract/reduce/message conversion, sponge absorb/extract, and the 32-byte
output. Its 1.4830-second synthetic subtotal justified building the subsequent
exact path; it was never a pre-Finished budget.

That proxy is **not ML-KEM decapsulation** and is not a trust decision. The
subsequently implemented candidate may be used only to speculate far enough to
send TLS Finished and a credential-free liveness request; it may not release an
API key or product data, authenticate the session, or trust/persist a ticket.

The 171-tick row covers only sixteen Keccak permutations, three forward NTTs,
four inverse NTTs, one cache build, and four K=3 dots. Promotion additionally
requires decoding, CBD, add/reduce, re-encryption serialization, constant-time
`c' == c`, `J(z || c)`, implicit-rejection selection, a real selected 32-byte
secret, equality with the provisional candidate, and all TLS/certificate
gates. Server Finished is a separate pre-Finished gate, not part of the
9.3922-second row. The two measured synthetic kernel phases sum to the cached
198-tick multiset; they do not sum to full decapsulation.

The resulting research direction remains conditional: keep standards-complete
decapsulation as the commit gate, but carry the speculate-then-commit profile
forward only if security review proves the quarantine and the post-Finished
path supplies enough time. Do not call the provisional boundary FIPS 203
conformant.

A 16-bit MSP430 artifact reports substantially faster assembly primitives, but
its full Kyber-768 decapsulation improves by only 1.62x and its lattice
optimizations use a dedicated hardware multiplier that the 8088 does not
have. Even mechanically projecting its individual primitive ratios onto this
spike gives 6.13 seconds for the dominant cached kernels before omitted work.
An 8-9 second crypto-only budget remains worth a full hand-optimized
known-answer spike, but is not demonstrated here and is no longer required to
test the provisional split.

The assembled precursor benchmark contains 7,992 bytes in the half-open range
`[0x1000,0x2f38)`; the loader reads 16 sectors / 8,192 bytes through `0x3000`.
It remains below the `0x4000` address ceiling, but timing used 64 KiB for BIOS
entry and is not a live 16 KiB integration. Of the content, 1,537 bytes are
kernel code and 4,904 bytes are writable benchmark fixtures; the latter keeps
all K=3 operands resident. The Keccak scratch is 488 bytes and the mulcache
fixture is 4,352 bytes. The 4,608-byte public matrix media cache is calculated,
not generated/written/streamed by this spike.

The standard expanded decapsulation-key object is 2,400 bytes. The exact
KeyGen overlay now produces it from `d || z`; its safe handoff into the
decapsulation overlay and the final product peak layout remain unmeasured.

Run the independent primitive/fixture full-output and size gate:

```sh
python3 tools/crypto-bench/tls13-spike/mlkem768_kernels_check.py
```

Run the original-speed timing gate:

```sh
python3 tools/crypto-bench/tls13-spike/run_8088.py \
  --asm tools/crypto-bench/tls13-spike/mlkem768_kernels_bench.asm \
  --timeout 300
```

The frozen machine-readable record is `mlkem768_8088_results.json`.

## Ordinary X25519 rejection

`x25519_bench.asm` is an 8086 Montgomery-ladder implementation checked against
both RFC 7748 section 6.1 values. The algorithm is 1,526 bytes, uses 808 bytes
of writable state plus 20 bytes of call stack, and fits below `0x4000`.

| Original 4.772728 MHz 8088 operation | BIOS ticks | Time |
| --- | ---: | ---: |
| client public key, movable before TCP | 830 | 45.5881 s |
| server-dependent shared secret | 833 | 45.7529 s |

Each scalar multiplication performs 506,816 16-bit word multiplies. Even
charging only the measured 8088 multiply floor gives 13.1676 seconds, before
field additions, carries, reductions, swaps, inversion, or TLS. Ordinary
X25519 therefore has no credible path inside the remaining provider window.

```sh
python3 tools/crypto-bench/tls13-spike/x25519_bench_check.py

python3 tools/crypto-bench/tls13-spike/run_8088.py \
  --asm tools/crypto-bench/tls13-spike/x25519_bench.asm \
  --timeout 180
```

The checked-in result is `x25519_8088_results.json`.

## Live `u=9` hybrid wire proof

`tls13_hybrid_u9_probe.py` asks the local OpenSSL build for a current
ClientHello template, replaces its hybrid share with a genuine ML-KEM-768
public key plus X25519 `u=9`, and completes the rest of the handshake itself.
For the X25519 half it copies the server's returned public share as the shared
value. The equality follows from both sides evaluating the server scalar
against the canonical base point.

The host probe used OpenSSL to complete conventional ML-KEM decapsulation
before Finished. It verified the 1,947-byte protected record's AEAD tag and
server Finished, sent the 58-byte client Finished, and decrypted a
NewSessionTicket. It sent no application data or credential. This proves
current wire interoperability only; it did not exercise the provisional split
or any 8088 ML-KEM implementation and does not turn the shortcut into
conforming X25519 or hybrid security.

```sh
python3 tools/crypto-bench/tls13-spike/tls13_hybrid_u9_probe.py
```

The dated record is `hybrid_u9_live_results.json`.

## Post-Finished liveness

These experiments used a normal, standards-complete host OpenSSL handshake.
They did not execute fixed `u=9`, the provisional pre-FO split, or Seed target
networking. Applying their cadence to the candidate is an explicit inference
that the integrated candidate-profile gate must test.

The initial edge behavior is not extended by TLS-level activity:

- five requested KeyUpdates were batched around 15 seconds, followed by close;
- slowly advancing an incomplete HTTP header was reset around 15 seconds.

Complete credential-free application requests behaved differently. Six fixed
unauthorized GETs kept the connection alive through 30 seconds. Seven fixed
`HEAD /v1/models` requests at 25-second intervals received seven complete
responses and the socket remained alive when the client deliberately stopped
at 155.033 seconds. Live status varied, so only a bounded complete response is
usable as a liveness signal.

The probe sends no Authorization header, API key, prompt, context, cookie, or
tool data:

```sh
python3 tools/crypto-bench/tls13-spike/tls13_post_finished_dialogue_probe.py \
  --mode head --duration 30 --interval 5
```

`post_finished_dialogue_results.json` records all four experiments. The
quarantine design permits only one compiled literal HEAD at a time, verifies
each response record's AEAD tag under the provisional key, drains a bounded
header terminator, and requires no outstanding response at commit. Status and
headers cannot affect proof state or scheduling; redirects are never followed.
Completion may only permit the next probe or cause abort. It is solely a
transport-liveness observation, never authentication or a commit signal. This
is measured provider behavior, not an SLA.

## Self-generated pinned ECDSA

The integrated `cpu 8086` image now supplies the exact target correctness and
storage gate for the recommended two-base Straus width-4 design:

| Integrated target item | Result |
| --- | ---: |
| Content / sector-rounded load | 9,790 / 10,240 B |
| Executable + header / data | 6,948 / 2,842 B |
| Included current P-256 executable | 5,023 B |
| Authentication working state | 815 B |
| Resumable Straus checkpoint | 706 B |
| Routine-only Unicorn stack high-water | 74 B |
| Leaf-under-WE1 executed-trace estimate | 43.067 s |
| TLS CertificateVerify executed-trace estimate | 43.510 s |
| Complete post-Finished authentication estimate | 89.167 s |
| Cold total including initial point/table preparation | 94.419 s |

Unicorn executes the assembled instructions and exact fixtures. The “WE1” and
leaf are deterministic synthetic test identities, not the live OpenAI
certificate bytes. The gate proves target arithmetic/control flow: it accepts
the two valid equations in order and rejects noncanonical DER, out-of-range
`r`/`s`, off-curve points, and coordinates equal to the field modulus. Timing
comes from the repository's calibrated 8088 cycle model over that exact
executed trace. It is not physical hardware or 86Box timing, and it does not
prove the target X.509 path.

The earlier strategy comparison still explains why Straus width 4 was chosen:
binary Shamir modeled at 108.80 seconds, unsigned fixed-window width 4 at
113.63 seconds, fixed comb width 4 at 119.80 seconds, and Straus width 4 at
89.61 seconds for the two curve equations. The integrated result supersedes
that estimate for the actual assembled arithmetic and adds modular-`n`, strict
signature parsing, point validation, exact state, and routine-only stack
measurements. It still excludes target Brotli, full X.509/SPKI/profile parsing,
trusted time, I/O, interrupts, and the product caller stack.

Because the original machine must generate its own tables after every cold
boot, fixed comb remains unattractive unless immutable precomputed tables enter
the shipped trust boundary. An immutable exact leaf can avoid the issuer
signature on the fast path, but writable `SEED/LEAF.DER` does not qualify and
must be verified under WE1 on every boot.

The ECDSA profile is leaf + WE1. WR1 belongs to the rejected RSA profile.
Shipping both current and guessed-next leaf pins is not a rollover mechanism:
no authenticated successor-leaf channel was observed in the probed TLS/X.509
path or is available to this design.

Small ECDSA tables remain in RAM on the required read-only path; no
attempt-generated table may be a boot-media dependency. If an optional writable
performance cache is ever added, the read-only path must still regenerate the
same slice locally, while the cached copy is covered by an attempt-local digest
retained in trusted RAM and checked over the exact bytes used. Verification
must enforce strict DER, `1 <= r,s < n`, exact uncompressed P-256 SPKI encoding,
on-curve/non-infinity points, and the offered TLS signature scheme. Leaf
validity also needs a trusted 5150 time policy; unauthenticated NTP cannot
authorize recertification.

```sh
python3 tools/crypto-bench/tls13-spike/ecdsa_pinned_comb_spike.py
python3 tools/crypto-bench/tls13-spike/auth_integrated_check.py
python3 tools/crypto-bench/tls13-spike/auth_integrated_cycles.py
```

The frozen integrated record is `auth_integrated_results.json`.

## Required quarantine boundary

The integrated experiment may promote the same connection only after all of
the following:

1. fresh entropy and a never-reused ML-KEM secret key for this one ciphertext;
2. strict profile/transcript parsing, all server-flight AEAD tags under the
   provisional key, and exact server Finished before client Finished; all
   decrypted messages/transcript state remain tentative until the complete
   containing record tag passes;
3. one literal credential-free HEAD at a time and, optionally, one bounded
   tentative NewSessionTicket; reject KeyUpdate, post-handshake
   authentication, unexpected inner types/epochs, upgrades, and all unrelated
   application input;
4. full ML-KEM re-encryption with constant-time `c' == c`; compute implicit
   rejection and the selected standard secret regardless, require ciphertext
   equality and selected-secret/provisional-candidate equality, then re-derive
   and compare TLS key/IV material without resetting live sequence numbers;
5. bounded certificate decompression and policy, WE1/leaf verification, and
   CertificateVerify against the frozen transcript;
6. no outstanding probe and continuous TLS sequence numbers;
7. API-key bytes absent from provisional RAM and loaded only by one atomic
   transition; if prior UI entry is unavoidable, no precommit routine has a
   pointer to the isolated bytes.

AEAD/server-Finished failures close before client Finished and are visibly
part of the admitted one-shot key-confirmation oracle. After client Finished,
KEM/certificate/pin/CV failures share one fixed close checkpoint with no
differing alert, probe cadence, retry, persistence, ticket promotion, or real
request. No learned pin may persist.

An AEAD-valid tentative ticket may be promoted only after the original
session's complete proof. Bind it to endpoint/SNI, ALPN, cipher/profile, leaf
policy, age, and lifetime. Resume only with PSK-DHE plus a fresh one-shot KEM
key, reject `psk_ke`, verify resumed server Finished, and never use 0-RTT.
Tickets remain volatile and never a cold-start dependency.

This remains research-only because three independent boundaries require
review: fixed `u=9`, provisional pre-FO ML-KEM use, and deferred certificate/CV
processing until after client Finished/application probes.

Standards references used by the spike:

- [TLS 1.3, RFC 9846](https://www.rfc-editor.org/info/rfc9846)
- [TLS Certificate Compression, RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html)
- [ML-KEM, FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [current `draft-ietf-tls-ecdhe-mlkem-05`](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [HTTP Semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)
