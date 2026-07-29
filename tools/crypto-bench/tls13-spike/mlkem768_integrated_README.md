# Integrated ML-KEM-768 8088 spike

This isolated spike answers two narrow architecture questions on a literal
16-KiB emulation of the headline floor:

1. Can an original 4.77 MHz 8088 with 16 KiB perform real, complete
   ML-KEM-768 decapsulation?
2. Can that machine generate its own ML-KEM-768 key from only locally obtained
   `d || z`, without a modern helper expanding the key?

The answer to both arithmetic questions is **yes** in the 86Box target
environment. The remaining
self-contained boundary is obtaining and restart-safely committing sufficient
entropy for `d` and `z`; product integration is not implemented here.

Nothing in this directory is product code. The spike does not modify
`SEED.SYS`, the driver ABI, a boot image, or the TLS implementation.

## Measured result

All target measurements use 86Box v9001 configured with the literal-16-KiB ROM
BASIC entry, an emulated 4.772728 MHz 8088, no dynarec, and code assembled with
`cpu 8086`. They are not physical IBM PC measurements. One BIOS tick is
`65536 / 1193182`, approximately 54.925 ms.

| Operation | Repetitions | Total ticks | Ticks/op | Seconds/op |
|---|---:|---:|---:|---:|
| exact `K-PKE.Decrypt + G` candidate | 5 | 173 | 34.60 | 1.900 |
| complete decapsulation, valid ciphertext | 3 | 1,357 | 452.33 | 24.845 |
| complete decapsulation, one-bit-invalid ciphertext | 3 | 1,357 | 452.33 | 24.845 |
| deterministic `KeyGen_internal(d,z)` | 1 | 401 | 401.00 | 22.025 |

The inferred post-candidate Fujisaki-Okamoto tail is 417.73 ticks, or 22.944
seconds. This is not a separately timed phase, so it is a subtraction of the
two repeated measurements.

`BENCH_INVALID` flips bit 0 of `c[0]`. For this frozen vector,
`K-PKE.Decrypt` produces the same `m'` and therefore the same 64-byte `G`
output as the valid ciphertext. This run proves that the target visits the
fixed-length ciphertext comparison, computes `J(z || c)`, and selects the
implicit-rejection secret. Its equal N=3 BIOS-tick total is not representative
fixed-work or constant-time evidence. Representative invalid ciphertexts that
change `m'`/`G`, repeated timing distributions, and cycle-level branch/memory
review remain required.

## Correctness boundary

The decapsulation artifact performs:

```text
m'       = K-PKE.Decrypt(dkPKE, c)
(K', r') = G(m' || H(ek))
c'       = K-PKE.Encrypt(ek, m', r')
Kbar     = J(z || c)
K        = constant-work-select(c' == c, K', Kbar)
```

Its re-encryption generates all nine `A^T` polynomials with SHAKE128 on the
8088. It accepts coefficients into four-word groups and immediately feeds
them into base multiplication. There is no 4,608-byte matrix cache.

The companion checker independently evaluates the full lattice arithmetic,
re-encrypts the valid vector, checks the fixed-length serialized difference,
and tests both:

- a valid ciphertext, for which the selected 32-byte secret equals `K'`; and
- a one-bit-invalid ciphertext, for which the selected secret equals
  `SHAKE256(z || c, 32)`.

Both selected secrets equal OpenSSL 3.6.2 ML-KEM-768 decapsulation output.

The KeyGen overlay starts from only the frozen 64-byte `d || z` input and
performs:

```text
(rho, sigma) = SHA3-512(d || byte(3))
sHat         = NTT(CBD(PRF(sigma, 0..2)))
eHat         = NTT(CBD(PRF(sigma, 3..5)))
tHat         = A(rho) o sHat + eHat
ekPKE        = ByteEncode_12(tHat) || rho
dk           = ByteEncode_12(sHat) || ekPKE || H(ekPKE) || z
```

All 2,400 assembly output bytes equal both an independent Python FIPS-arithmetic
implementation and the frozen OpenSSL-expanded key.

The frozen vector was generated with OpenSSL 3.6.2. It is not claimed to be a
NIST ACVP response file. Before product use, the gate needs multiple official
or independently sourced vectors, malformed-input coverage, and a dedicated
side-channel review.

## Literal 16 KiB layout

| Artifact | Content | Rounded load | Loaded range | Routine-only stack high water |
|---|---:|---:|---|---:|
| complete decapsulation | 10,149 B | 10,240 B / 20 sectors | `0x1000..<0x3800` | 26 B |
| deterministic KeyGen | 7,063 B | 7,168 B / 14 sectors | `0x1000..<0x2c00` | 24 B |

The stack values are routine-only Unicorn high-water measurements; they do not
include the benchmark caller, timer/BIOS interrupt stack, or the product
nucleus. The ROM BASIC loader begins at `0x3a00`; RAM ends at `0x4000`. Thus the
decapsulation load has 512 bytes before the loader and 2,048 bytes before the
RAM ceiling. KeyGen has 3,584 and 5,120 bytes respectively.

The decapsulation image contains a 3,616-byte immutable KAT fixture, four
512-byte polynomial buffers, 488 bytes of Keccak work state, and small
message/result state. A product phase would need to replace the baked expanded
key and ciphertext with same-sized locally generated and received objects.

KeyGen uses:

- one 2,400-byte expanded-key output;
- two 512-byte polynomial buffers;
- 488 bytes of Keccak work state;
- 64 bytes for `rho || sigma`; and
- small four-coefficient sample/product groups.

It first serializes `sHat` into the output key, then decodes one component for
each `tHat` row. This removes both a retained three-polynomial secret vector
and the matrix cache.

KeyGen and decapsulation are intentionally separate standalone overlays. Their
required product handoff is not implemented:

```text
entropy/ratchet
  -> KeyGen overlay
  -> retain expanded dk (2,400 B), transmit ek view (1,184 B)
  -> replace overlay with TLS/decapsulation phase
  -> receive c (1,088 B), derive provisional candidate
  -> full FO validation, authentication, atomic promotion
  -> erase ephemeral dk/candidate/work state
```

In the benchmark, KeyGen writes its 2,400-byte output inside
`0x2237..0x2b97`, while loading the decapsulation image at
`0x1000..<0x3800` would overwrite it. Both images also overwrite Seed's current
resident nucleus at `0x1000..<0x1800`, and decapsulation extends beyond the
current K window's `0x3600` end. The arithmetic executes on the emulated 8088,
but `d || z`, the expanded key, and ciphertext are still frozen fixtures in
the isolated images. A sparse/relocated or attempt-media handoff plus a final
product phase link is therefore a hard gate; no modern machine may supply the
per-attempt objects.

## Timing implication

A conventional full decapsulation inside a strict 15-second pre-Finished
interval misses by about 9.845 seconds. Meeting 15 seconds would require a
39.6% runtime reduction, equivalently about 1.656x throughput / a 65.6%
throughput increase.

The provisional candidate fits at about 1.90 seconds. The inferred
post-candidate validation tail takes about 22.94 seconds, leaving only about
2.06 seconds below the observed 25-second credential-free HEAD cadence before
TCP/parser/checkpoint margin. This isolated subtraction motivates, but does not
prove, the quarantined architecture under investigation:

- use no credential and permit no trusted effect while the secret is only
  provisional;
- keep the same connection active with literal credential-free traffic;
- perform full FO validation and server authentication on the 8088; and
- expose the API key and real request only after an atomic successful commit.

Using `K'` before FO validation is not the FIPS 203 decapsulation contract.
This spike proves the arithmetic and timing boundary; it does not approve that
protocol construction, the fixed-X25519-`u=9` research profile, or TLS
conformance.

## Optimization directions

The no-cache implementation is the safest memory baseline. If conventional
pre-Finished decapsulation remains desirable, the most relevant next
experiments are:

1. Measure a phase breakdown for SHAKE128 matrix generation, NTT/base
   multiplication, compression/compare, and `J`.
2. Specialize the memory-heavy generic 64-bit Keccak rotation/permutation for
   the 8088 and measure the code-size trade.
3. Have the 8088 precompute its public matrix before TCP and persist it in
   attempt-scoped floppy scratch. During FO validation, stream one sector/group
   at a time. The matrix is public and deterministic from `rho`; corruption
   safely causes rejection, though the cache must be bound to the current
   attempt for availability and lifecycle correctness.
4. Measure whether floppy reads cost less than regenerating the matrix. Do not
   assume that a 4,608-byte RAM cache fits the 16 KiB tier.
5. Audit all secret-dependent branches and memory accesses at cycle level.
   Equal BIOS-tick totals are too coarse for a side-channel conclusion.

The current result also removes an earlier architecture dependency: a
post-Finished matrix cache is optional, not required for correctness or memory
fit.

## Entropy and restart contract still required

KeyGen arithmetic no longer requires external pre-plumbing, but a fixed
`d || z` would still be insecure. The original machine must:

1. collect local physical timing input;
2. condition it with SHA3 together with a persistent secret ratchet state;
3. durably write and read-verify the next ratchet generation before emitting
   the corresponding public key; and
4. derive a fresh `d || z` for every connection attempt, retry, HRR, and reboot.

Network input, MAC addresses, BIOS ticks, or floppy timing are attacker-visible
or influenceable and must not be the sole credited entropy. On write-protected
media or after ratchet loss/rollback, the conservative fallback is an
interactive timing ceremony on the 8088, not reuse of a prior key. Actual
5150/emulator sampling and a defensible min-entropy model remain open gates.

The existing hostile crash oracle covers 516 write/crash boundaries, 4,096
successful advances, and all 512 single-byte corruptions. It proves
non-reuse only under its stated non-rollback writable-media model; it does not
establish entropy quality.

## Provenance limits

The frozen result records exact commands and define sets, and every variant
reassembles byte-for-byte to its recorded benchmark-image SHA-256. The raw
runner JSON's `command` field omitted `--define`, `--timeout`, and
`--json-out`; the curated command strings correct that recorder omission.
Source, checker, runner, ROM-BASIC harness, profile, NASM, and Unicorn
provenance is recorded in `mlkem768_integrated_results.json`. The 86Box binary
and BIOS ROM hashes were not captured at measurement time, so physical-hardware
timing and a more completely frozen emulator environment remain gates.

## Reproduction

Offline gates:

```sh
python3 tools/crypto-bench/tls13-spike/mlkem768_integrated_check.py
python3 tools/crypto-bench/tls13-spike/mlkem768_integrated_keygen_check.py
```

Literal target gates:

```sh
python3 tools/crypto-bench/tls13-spike/run_8088_16k.py \
  --asm tools/crypto-bench/tls13-spike/mlkem768_integrated_candidate.asm \
  --define BENCH_CANDIDATE_ONLY --define BENCH_ITERS=5

python3 tools/crypto-bench/tls13-spike/run_8088_16k.py \
  --asm tools/crypto-bench/tls13-spike/mlkem768_integrated_candidate.asm \
  --define BENCH_ITERS=3

python3 tools/crypto-bench/tls13-spike/run_8088_16k.py \
  --asm tools/crypto-bench/tls13-spike/mlkem768_integrated_candidate.asm \
  --define BENCH_INVALID --define BENCH_ITERS=3

python3 tools/crypto-bench/tls13-spike/run_8088_16k.py \
  --asm tools/crypto-bench/tls13-spike/mlkem768_integrated_keygen.asm
```

Exact hashes, define sets, output checksums, and captured timings are frozen in
`mlkem768_integrated_results.json`.
