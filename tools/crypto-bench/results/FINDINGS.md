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

### Would offloading to an 8087 FPU unlock real secure crypto? — NO (measured + bounded)
Question (the right framing): offload to the 8087 whatever gives the *fastest
end-to-end* crypto — does real crypto then fit a usable handshake? Two cases:

**Measured anchor** — the decisive primitive on 86Box (8087 enabled, `fpu_bench.asm`):
a `32×32→64` multiply, 8088 (four 16×16 `MUL`s + carry) vs 8087 (`FILD/FMUL/FISTP`,
exact in the 80-bit mantissa). Identical correct product (ck `ACE6`):
**8088 1074 cyc/op, 8087 585 cyc/op = 1.84× faster.** (`FILD` is *signed* — verified:
unsigned limbs with the top bit set come out wrong until kept ≤31-bit.)

- **Naive drop-in** (FP multiply, integer reduction): ~1.3–1.45× on the field
  multiply (reduction stays integer; per-multiply `FILD`/`FISTP` overhead).
- **Optimal holistic offload** (the user's framing — keep the *entire* field
  arithmetic in a floating-point-limb representation: multiply, add/sub, and the
  modular reduction all as `FMUL`/`FADD` with carries deferred to a final pass,
  converting to/from integer only at the point-arithmetic boundaries; overlap 8088
  integer bookkeeping with 8087 multiplies): plausibly **~2–3.5×**.

Even the optimal case is hard-floored by the **`FMUL` count**, not by overhead we
could engineer away. One 256-bit scalar mult needs ~3,700 field multiplies; each is
~121 limb-`FMUL`s (11 limbs of ≤24 bits, schoolbook, bounded by exact accumulation)
⇒ **~450,000 `FMUL`s**. At the 8087's ~130-clock `FMUL` (4.77 MHz) that is **~12 s of
`FMUL` alone** — before a single `FADD`, conversion, reduction step, point
double/add, or scalar-loop iteration. Realistic all-in: **~35–50 s** per scalar mult.

| metric | 8088 | 8087 naive | 8087 optimal | vs 15 s window |
|---|---|---|---|---|
| field multiply | 137.6 K cyc | ~1.3× | ~2–3.5× | — |
| one ECDHE scalar mult | 110.8 s | ~85 s | **~35–50 s** (FMUL-only floor ~12 s) | ✗ still 2–3× over |
| ECDSA-P256 cert verify | ~220 s | ~155 s | ~70–100 s | ✗ |
| RSA-2048 cert verify | ~43 s | ~30 s | ~15–20 s | ✗/borderline |
| full real-security handshake | ~160 s | ~115 s | **~55–75 s** | ✗ ~4× over |
| SHA-256 / PRF (always-runs) | 156 ms / 4.92 s | identical | identical | — no `FMUL`s to offload |

**Verdict: even optimal 8087 offload does not unlock secure crypto.** Best case it
~halves-to-thirds the asymmetric time (ECDHE 110.8 s → ~35–50 s), but the `FMUL`-count
floor keeps one scalar mult well over the ~15 s window, cert-auth adds tens of seconds
more, and the always-runs symmetric cost (SHA/PRF) has **no multiplies to offload** so
it does not move at all. The wall is 256-bit *modular-integer* work at 4.77 MHz; a
~130-clock float multiply is not enough leverage. **No FPU crypto path is worth
building.** Keep FPU as a future-additive capability dimension for possible non-crypto
uses only. (The optimal ~2–3.5× is a bounded projection from the measured primitive +
the FMUL count; implementing a full FP-limb field mul would confirm it but cannot beat
the ~12 s FMUL-only floor — the decision holds without it.)

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

### 80186 instructions on V20/V30 — MEASURED (correcting an earlier reasoned claim)
Tested, not reasoned (`bench186.asm`, on a V20). The SHA hot op is a 32-bit rotate;
after the byte-granular step the residual is 1..7 bits. The 186 shift-by-immediate
cross-register combine is a FIXED cost; the 8086 single-bit residual grows with the
residual (dt for 30000 iters, V20):

| residual | 8086 single-bit | 186 shift-imm | winner |
|---|---|---|---|
| 2 | 17 | 20 | 8086 (186 ~18% slower) |
| 5 | 24 | 20 | 186 (~17% faster) |
| 7 | 28 | 20 | 186 (~29% faster) |

Crossover ~residual 3-4. SHA-256's 12 rotate residuals = [2,5,6,6,3,1,7,2,3,1,3,2]:
8/12 are small (8086 wins), 4/12 large (186 wins). A smart hybrid nets only ~2-4% on a
full SHA block; naive all-186 is ~a wash. And a fully 186-tuned V20 SHA (~82 ms) is still
slower than plain-8086 code on a 16-bit-bus 8086@8 (71 ms) -- the bus beats the ISA.
**Verdict: real but small + residual-dependent; not worth a CPU-specific code path. Tier
on RAM + bus-class, not 086-ISA.** (Earlier I reasoned "~nothing"; measured it's ~18-29%
on large-residual rotates but ~nil net on SHA -- the test was right to run.)

## Front 3 — the 286 tier: where real secure crypto first fits (measured 6/8 MHz + linear projection)
The 086-class can't reach a secure handshake even maxed+hybridized (Front 1/2). The 286
can. Booted the 360K bench image on 86Box `ibmat` (286) via a crafted IBM-AT CMOS (the AT
halts at "Run SETUP" on blank CMOS; the XT class has no CMOS) + a minimal raw boot sector
with a real 360K BPB (`bench_boot.asm`) -- the AT rejects the product's 160K single-sided
image. `ibmat` clamps to 8 MHz (real AT speed); the 286 has no cache so 6->8 scaled exactly
with clock -> higher clocks project linearly.

| CPU | SHA block | int 32x32 | 287 FMUL 32x32 |
|---|---|---|---|
| 8088 @4.77 | 155.6 ms | 0.225 ms | 0.124 ms |
| 286 @6 (measured) | 61.8 ms (2.5x) | 0.0330 ms (6.8x) | 0.0604 ms |
| 286 @8 (measured) | 45.8 ms (3.4x) | 0.0247 ms (9.1x) | 0.0467 ms |
| 286 @20 (linear proj) | ~18 ms | ~0.010 ms | - |
| 286 @25 (linear proj) | ~15 ms | ~0.008 ms | - |

Findings:
- The 286's integer MUL is ~9x the 8088's @8 MHz -- exactly the P-256 bottleneck. Linear
  with clock (no cache).
- The 287 FPU is SLOWER than the 286 integer MUL (0.047 vs 0.025 ms @8) -- on the 286 you do
  NOT use the FPU for bignum; integer MUL wins. (Opposite of the 8088's 8087.) So "286 + FPU"
  adds nothing for crypto.

Crypto projection (286, from the measured MUL/general speedups, linear with clock):
| 286 clock | real ECDHE | secure handshake (ECDHE + RSA cert-auth + PRF) | vs 15 s window |
|---|---|---|---|
| 8 MHz | ~18-20 s | ~22 s | just over |
| 16 MHz | ~9 s | ~11 s | FITS |
| 20 MHz | ~7 s | ~10 s | FITS |
| 25 MHz | ~6 s | ~8 s | FITS |

**Threshold: a 286 @ ~16-20 MHz is where a full real-secure handshake (real ECDHE + RSA
cert-auth + real entropy) first fits Cloudflare's ~15 s window.** The 086-class never does;
the 286's ~9x faster MUL is what crosses the line. Caveat: RSA cert-auth (cheap on the 286's
fast MUL, ~2 s) or a pinned key -- full ECDSA chain auth (~2x ECDHE) would push back over.
NB ibmat caps at 8 MHz in 86Box; 20/25 MHz Harris parts are projected (linear scaling proven
6->8) -- literal 20/25 needs a fast-286 clone (its own CMOS) or real hardware.

### 286@6 with an OPTIMIZED P-256 — security begins at the 286 (MEASURED)
Testbench feasibility (NOT shipped; core/p256.inc still %if0'd). To test whether real
secure crypto fits the ~15s window on the LOWEST 286, the dormant P-256 was optimized
(testbench variants in variants/p256_*.inc), each correctness-gated vs the OpenSSL oracle:
- Solinas (direct NIST) reduction replacing the table-driven reduce: 1.375x field mul.
- register-resident Comba multiply: 1.233x; single-level Karatsuba + Comba sub-mul: 1.505x.
- wNAF width-4 windowed scalar mult: point-adds 141 -> 51.
- COMBINED (Karatsuba + Solinas + wNAF, variants/p256_combined.inc): 2.554x field mul,
  3.273x fewer scalar-mult instructions, VERIFIED scalar_mult == PEER_PUBLIC vs OpenSSL.

Measured on 86Box ibmat @ 6 MHz (one full ECDHE = scalar mult + inv + affine, ck=D51E correct):
| | 286@6 ECDHE |
|---|---|
| baseline real P-256 | 470 ticks = 25.8 s |
| **optimized (combined)** | **120 ticks = 6.6 s (3.9x)** |

Full secure handshake @286@6: ECDHE 6.6s (measured) + RSA-2048 cert verify ~2.5s (projected;
286's fast MUL) + PRF/transcript ~1-4s (measured SHA +/- the 4.64x SHA win) + entropy ~0.2s
= **~10-14s -- fits the ~15s window.**

**Threshold result: security begins at the 286.** The 086-class (even maxed+hybridized) stays
minutes over; an optimized real ECDHE is 6.6s on the LOWEST 6 MHz 286, so a full real-secure
handshake (real ECDHE + RSA cert-auth + real entropy) fits the window. Caveats: ECDHE measured,
auth/PRF/entropy projected; RSA cert-auth not ECDSA (ECDSA ~2x ECDHE would exceed); the 3.9x
HW speedup exceeds the 8088-model 2.55x because the 286's fast MUL makes the cut overhead
(Solinas/wNAF) dominate. Reproduce: build p256_bench.asm -DP256_SRC='"variants/p256_combined.inc"'
onto the 360K image, boot ibmat@6 (crafted CMOS).

### Full handshake crypto on 286@6 (MEASURED, hs_bench.asm)
Beyond the ECDHE component, the rest of the handshake crypto measured on ibmat@6:
- PRF (master+keyblock) + transcript SHA-256 over ~3 KB (cert + messages):
  - baseline SHA: 90 ticks = **4.94 s**
  - with the 4.64x SHA win (variants/r4_v42.inc, -DSHA256_SRC): 12 ticks = **0.66 s** (ck=C31E identical -> bit-exact; ~7.5x here, more than the lone-block 4.64x because PRF+transcript is almost pure SHA)
Summed with the measured ECDHE (6.6 s) -- they run sequentially, no overlap:
| 286@6 handshake crypto | time | basis |
|---|---|---|
| ECDHE (optimized real P-256) | 6.6 s | measured |
| PRF + transcript (baseline SHA) | 4.94 s | measured |
| PRF + transcript (4.64x SHA win) | 0.66 s | measured |
| RSA-2048 cert verify | **6.37 s** | **measured** (rsa_bench.asm, ck=54F2) |
| + entropy | ~0.2 s | projected (gated/cosmetic) |

### RSA-2048 verify MEASURED (rsa_bench.asm, was the one projection)
s^65537 mod N = 16 squarings + 1 multiply = 19 CIOS Montgomery 128-limb modmuls (plain --
squarings done as full multiplies, no squaring optimization). Verified correct on-device
(ck=54F2 = wordsum of all 128 result limbs == pow(s,65537,N)). Implementation: rsa_verify.inc
(host oracle: rsa_eval.py / rsa_bench_harness.py).
| 286 clock | RSA-2048 verify | basis |
|---|---|---|
| @6 | 116 ticks = **6.37 s** | measured |
| @8 | 87 ticks = **4.78 s** | measured (= 6.37 x 6/8 -> time scales linearly with clock; 286 has no cache) |
This is ~2.5x the earlier ~2.5 s guess (that guess assumed squaring optimization). The honest
plain-CIOS cost dominates the handshake budget more than ECDHE does.

### Slack vs the server hang-up (the flakiness question) -- corrected with measured RSA
The server (Cloudflare) closes a handshake that idles too long between its ServerHelloDone and
the client's ClientKeyExchange+Finished -- the client is SILENT during the whole crypto grind
(cert-verify -> ECDHE -> PRF -> Finished, all serial: it can't send ClientKeyExchange until ECDHE
produces the premaster, and must verify the cert before trusting the server's key). That patience
was measured empirically for Seed at **~15 s** (the shipped ~14.5 s 8088 handshake "sat ~0.2 s
inside" it -- why it was flaky on degraded links). It's a measured-for-Seed figure, not a published
SLA, so the goal is comfortable margin, not "under 15".

Full SECURE handshake (ECDHE + PRF/transcript + RSA cert-verify + entropy), all crypto serial:
| 286 clock | baseline SHA | + 4.64x SHA win | slack (SHA win) vs ~15 s | verdict |
|---|---|---|---|---|
| @6 (lowest) | ~18.1 s (over) | **~13.8 s** | ~1.2 s | **flaky** -- fits only with the SHA win, and barely |
| @8 | ~13.6 s | **~10.4 s** | ~4.6 s | **robust** |
| @12 (proj, linear) | ~9.1 s | ~6.9 s | ~8 s | comfortable |
(@6 fully measured except entropy; @8 RSA measured, ECDHE/PRF linear-scaled from @6; @12 linear.)

**Corrected verdict.** The measured RSA pushes the full secure handshake to ~13.8 s on the LOWEST
286 -- it fits the ~15 s window ONLY with the 4.64x SHA win, and even then ~1.2 s slack = flaky (the
8088's exact failure mode). Comfortable slack (~4.6 s) starts at the **8 MHz 286**; the 6 MHz part
is the boundary, not the comfortable home. "Security begins at the 286" holds, but the practical,
non-flaky secure tier is 286@8+ (or shave RSA: a dedicated squaring path would drop the 16 squarings
to ~0.6x = RSA ~4.3 s -> @6 handshake ~11.7 s -> ~3.3 s slack -- a future lever, not built). The
honest one-liner: a real cert-authenticated TLS handshake is *reachable* at the lowest 286 and
*comfortable* by 8-12 MHz; the 16K / 4.77 MHz tier stays "encrypted, not secure."
