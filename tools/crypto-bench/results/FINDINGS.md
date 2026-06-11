# Handshake-crypto speed + real-crypto feasibility on the 4.77 MHz 8088 — findings

A measurement spike. Question: **what TLS-handshake crypto speed is achievable on
the original 4.77 MHz 8088**, with benchmarked evidence, so we can decide what to
build. Two fronts: (1) speed up the symmetric crypto that always runs (SHA-256 /
HMAC / TLS-PRF); (2) measure whether real public-key crypto (ECDHE, entropy,
cert-auth) can fit the time + 16 KiB budget.

All numbers are for the IBM PC 5150 profile: **8088 @ 4.772728 MHz, no dynarec,
CGA**. 1 BIOS tick = 54.9254 ms. Method and tools in `tools/crypto-bench/`.

---

## Method — a cheap 3-tier harness (built first, per the brief)

Running the full Seed boot+DHCP+DNS+TLS flow per variant would cap us at a handful
of experiments. Instead, three tiers (cheapest first):

1. **Correctness — host, instant, parallel.** Each asm variant is assembled with
   nasm and run in **unicorn** (16-bit real-mode CPU emulator); the result is read
   straight out of emulated RAM and compared to OpenSSL / hashlib reference vectors
   (`bench_harness.py`, `evaluate.py`). No VM boot. The real `core/sha256.inc` and
   the dormant P-256 both verified here against the existing `check-*.py` oracles.
2. **Speed estimate — host, instant.** A static **8088 cycle model**
   (`cycles8088.py`) over the executed instruction trace, modelling the 8088's
   single 8-bit bus as `max(EU+EA cycles, 4 × (insn_len + memory_bytes))`.
   **Calibrated 98.7%** against real 86Box (predicted 735,461 vs measured 745,420
   cycles for one SHA-256 block). Used to rank variants before any VM run.
3. **Ground truth — 86Box, serial.** A standalone CORE.SYS micro-benchmark
   (`bench.asm`) boots via the real boot chain, times each op with the BIOS tick
   counter, and reports over COM1 (`run86box.py`). One VM at a time. Confirms the
   leaders and calibrates the model.

This made the evolutionary search possible: tens of variants filtered instantly on
tiers 1–2, only leaders spending a ~50 s VM run on tier 3.

---

## Baseline (frozen — the comparison point for every variant)

Original `core/sha256.inc` + `tls.inc` PRF, measured on real 86Box:

| op | ms/iter | cycles | note |
|---|---|---|---|
| SHA-256 process_block | **156 ms** | ~745 K | the hot primitive |
| TLS-PRF master secret | **2.39 s** | ~11.4 M | |
| TLS-PRF master + key block | **4.92 s** | ~23.5 M | the always-runs symmetric handshake cost |

Where the time goes in `process_block`: the original `sha256_rotr32`/`sha256_shr32`
**rotate one bit per loop iteration** (rotr-by-22 = 22×`shr/rcr/loop`), and all
32-bit math is **memory-to-memory** 16-bit halves over the 8-bit bus (~4 cycles per
byte). Rotation and memory traffic dominate.

The ~4.92 s PRF is the bulk of the "~7.5 s CKE→Finished gap"; the remainder is the
client-Finished transcript hash + CKE build + transmit + server round-trip.

---

## Front 1 — symmetric speed (SHA-256 / PRF)

Evolutionary search: rounds of parallel agents, each proposing+implementing+
correctness-checking+cycle-ranking ONE variant (`evaluate.py`), selecting leaders,
recombining. Every variant is bit-exact SHA-256 (gated against OpenSSL and through
the full TLS-PRF vectors) before its cycles count.

20 correct variants were produced across 4 rounds; all 20 verified bit-exact and
reproduce on independent re-evaluation.

### Evolution progression — how each round optimized it (model cycles/block)
| stage | best variant | the insight it added | cyc/block | ×base |
|---|---|---|---|---|
| baseline | `core/sha256.inc` | bit-at-a-time rotate (rotr22 = 22 loop iters); all 32-bit math memory-to-memory | 735,461 | 1.0× |
| seed | `v001_byterot` | **byte-granular rotate**: rotr n = `xchg`/byte-moves + ≤7 residual bits — kills the bit loop | 481,653 | 1.53× |
| round 1 | `r1_v7` | **inline sigmas + unrolled ring-shuffle**: no `call` clobbering regs mid-round; chained register sigmas | 172,709 | 4.26× |
| round 2 | `r2_v22` | **register-fold the round body**: Ch/Maj/T1 through registers + stack, not the `sha256_t1/t2` memory temporaries | 148,438 | 4.95× |
| round 3 | `r3_v32` | **state base-ptr + disp8 addressing**: SI as a fixed `sha256_a` base so a..h are base+disp8 (cheaper EA) not `[disp16]`; drop all spills | 135,491 | 5.43× |
| round 4 | `r4_v42`/`r4_v44` | **`xchg` byte-rotate as register renaming** (no scratch/moves) + branchless shortest-path sigma chains | 127,327 | 5.78× |

The thread: **kill bit-loops (byte rotation) → kill call overhead (inline) → kill
memory traffic (registers + disp8 + stack) → kill the rotate moves themselves
(`xchg` register renaming).** Memory traffic on the 8-bit bus was the dominant
cost; the search drove the working set into registers step by step.

### 86Box ground truth (real 4.77 MHz hardware) — the verified claim
The two round-4 leaders (`r4_v42`, `r4_v44`) are a dead heat; confirmed on 86Box,
output **bit-identical** (checksums 4E3F/2368/2228 unchanged):

| op | baseline | r4_v42 | **speedup (HW)** |
|---|---|---|---|
| SHA-256 block | 273 ticks | 55 ticks | **4.96×** |
| PRF master secret | 261 | 57 | 4.58× |
| **PRF master + key block** | 269 (4.92 s) | 58 (**1.06 s**) | **4.64×** |

The always-runs PRF drops **4.92 s → 1.06 s** on real hardware. (The cycle model
said 5.78×; it ran ~16% optimistic here — it was calibrated on the memory-heavy
baseline, and under-counts prefetch-queue starvation in the new register-dense
code. The model still RANKED the variants correctly; 86Box is the claim.)

### The catch: size. The win does NOT fit the hot path as-is.
The K crypto link window (sha256+chacha20+poly1305+tls+agent_api) currently ends
at **0x33f7 — 9 bytes below** `high_crypto_scratch_start` (0x3400). The speed win
costs code:

| variant | code Δ vs baseline | HW speedup | fits 9 B? |
|---|---|---|---|
| v001_byterot | +61 B | 1.42× | no |
| r1_v7 | +471 B | ~4.3× (model) | no |
| **r4_v42** | **+595 B** | **4.64×** | no |

So landing ANY of these requires freeing ~50–590 B in the K window, **or** bumping
`high_crypto_scratch_start` up ~600 B — which pushes the crypto RAM scratch up and
costs conversation-arena bytes at the 16 KiB RAM floor (fine at 32 KiB). That is a
real product tradeoff + a full-handshake / 7-NIC re-validation, i.e. a focused
follow-up, **not** a spike-tail change to the hot crypto path. The verified win is
preserved in `tools/crypto-bench/variants/r4_v42.inc` (reproducible:
`python3 evaluate.py variants/r4_v42.inc` then `run86box.py --sha variants/r4_v42.inc`).

---

## Front 2 — real crypto feasibility (measured)

### Real ECDHE — P-256 scalar multiplication
The real constant-time P-256 (field math + Jacobian point ops + scalar mult) has
sat under `%if 0` in `core/p256.inc` since Build 6 and **had never been assembled**.
Brought to life (`p256_real.inc`), it assembles **8086-clean** and is **correct**:
verified incrementally against the `check-p256.py` oracle (which cross-checks
OpenSSL) — field mul/add/sub/inv, point double/add, and
`scalar_mult(PEER_PRIVATE × G) == PEER_PUBLIC`, end-to-end shared-X == SHARED_X.

| metric | value |
|---|---|
| **one real ECDHE scalar mult** | **528.9 M cycles = 110.8 s** (24.2 M instrs) |
| full ECDHE (mult + inv + affine → shared X) | 531.4 M cyc = **111.3 s** |
| field multiply `p256_mul_mod` (the hot primitive, 97% of cost) | 137,625 cyc (28.8 ms) |
| point double / point add | 1.14 M / 1.68 M cyc |
| final inv_mod (Fermat) | 2.23 M cyc |
| **code size** | **2.4 KiB code + ~1 KiB data ≈ 3.4 KiB** |

- **Time budget: FAILS by ~7.4×** (110.8 s vs the ~15 s server window).
- **Size budget: fits 16 KiB easily.**
- Floor: even a *perfect* schoolbook multiply (raw `mul`s only, no overhead)
  bottoms at ~26.6 s; windowed/Comba-tuned realistically ~30–50 s. The 8088's
  ~133-cycle `mul` opcode is the wall — real P-256 ECDHE cannot fit the window.
- One optimization tried (multiply accumulator in register BP, no per-iter RMW):
  **1.05×**, still correct, 8 bytes smaller — modest because the `mul` opcode, not
  bookkeeping, dominates.

### Real entropy
Cheap in CPU (a SHA-256-mixed pool fed by keystroke timing / NIC arrival / PIT
samples = **~0.16 s**, one extra block). The catch: the emulator is
cycle-deterministic, so timing-jitter entropy is zero under test — only
keystroke timing works under emulation; the rest needs real-hardware validation.
**The one real-crypto upgrade that fits the budget.** Details:
`results/entropy_certauth_scoping.md`.

### Cert-auth (signature verification)
Costs derived from the measured field multiply:
- **RSA-2048 verify (e=65537): ~43 s/sig** (17 modmuls; the *least bad* option).
- **ECDSA-P256 verify: ~220 s/sig** (~2 scalar mults).
Both blow the window; a chain is minutes. Even RSA's theoretical floor (~15 s) has
no headroom. (Correcting an initial bad ~1 s guess — desktop RSA-verify is fast,
but on the 8088 the n² word-`mul`s dominate.)

### Combined real-security reality
ECDHE 110.8 s + cheapest auth ~45 s + PRF ~5 s, all serial ≈ **~160 s ≈ 2.7 min**,
**~11× over** Cloudflare's ~15 s patience.

---

## Recommendation — what to build, what stays out of reach

**Build (symmetric speed — high leverage, always runs):**
- The SHA-256 / PRF speed win is real and large: **4.64× on the PRF, 4.92 s → 1.06 s,
  verified on 86Box**, output bit-exact. It widens the margin under Cloudflare's
  ~15 s window (the degraded-link reconnect failure mode) at zero security cost.
- Integration is a focused follow-up: it adds ~595 B and the K window has 9 B free,
  so land it together with freeing ~590 B (size-tune the other K-window crypto) or a
  `high_crypto_scratch_start` +~600 B bump (validate the 16 KiB target's arena +
  the 7-NIC handshake). A middle option is a size-conscious variant trading some of
  the 4.64× for a smaller footprint (the frontier: +61 B→1.42×, +471 B→~4.3×, +595 B→4.64×).

**Out of reach on a stock 4.77 MHz 8088 (measured):**
- **Real ECDHE (110.8 s), cert-auth (43–220 s/sig)** — each alone is multiples of
  the server window; together ~2.7 min. Not shippable against Cloudflare. They
  fit the 16 KiB *size* budget — the wall is purely the `mul`-bound *time*.
- Real public-key security would need a self-hosted long-patience endpoint, an
  opt-in multi-minute "secure handshake" mode, or hardware help.

**Don't ship a cosmetic "fix":**
- Real entropy (~0.16 s) is the only piece that *fits* the time budget, but it is
  **gated** — alone it improves nothing, because the client random is just a nonce and
  the premaster is public, so every session key is already derivable from the wire.
  Entropy only earns its keep bundled with real key agreement (the secret ECDHE scalar,
  or an RSA-encrypted random premaster — RSA key transport ~43 s is the cheapest real
  confidentiality, still ~3× over the window). Shipping entropy standalone would be
  cosmetic and cut against honest framing.
- Keep the precise **"encrypted but not secure"** label. Real confidentiality/
  authenticity wait for a faster machine (286/386+) or a self-hosted patient endpoint.
