# Crypto feasibility — where a real secure handshake fits, and why

This is the research record behind one decision: **can seed's hand-rolled TLS
handshake be genuinely *secure*, and if so, on what hardware?** It is a measured
answer, not a reasoned one — every claim below comes from a benchmark, and the
ones that started as guesses are marked where the measurement corrected them.

**The answer, up front.** On a stock 4.77 MHz 8088 a real secure handshake is out
of reach by ~11× — not for lack of RAM, but because 256-bit modular arithmetic at
that clock takes minutes, and the server closes the connection in ~15 seconds. So
the 8088 tier stays honestly **"encrypted, not secure."** Security *begins at the
286*: with an optimised P-256, a pinned-key RSA verify, and a faster SHA-256, a
full cert-authenticated handshake first fits the window on the lowest 6 MHz 286
(on a ~1.2 s knife-edge) and is comfortable by 8 MHz. That tier shipped in Build 12;
see [security.md](security.md) for the security posture and
[architecture.md](architecture.md) for the system mechanics.

The rest of this document is *how* we know that: the method, the symmetric-crypto
optimisation hunt, the asymmetric-crypto wall, the levers we ruled out (the 8087
FPU and the V20/80186 ISA), the 286 threshold, the specific variants we shipped
and why, and the ECDSA tier we scoped but did not build.

---

## How we measured it — a three-tier harness

Running seed's full boot + DHCP + DNS + TLS flow per experiment would have capped us
at a handful of trials. Instead the work ran on three tiers, cheapest first, so that
tens of variants could be filtered instantly and only the leaders spent a VM run:

1. **Correctness — host, instant, parallel.** Each assembly variant is assembled
   with `nasm` and run under **unicorn** (a 16-bit real-mode CPU emulator); the
   result is read straight out of emulated RAM and compared to OpenSSL / `hashlib`
   reference vectors (`bench_harness.py`, `evaluate.py`). No VM boot. A variant is
   not allowed to *have* a speed number until it is bit-exact against the oracle.
2. **Speed estimate — host, instant.** A static **8088 cycle model**
   (`cycles8088.py`) walks the executed instruction trace, modelling the 8088's
   single 8-bit bus as `max(EU+EA cycles, 4 × (insn_len + memory_bytes))`. It was
   **calibrated to 98.7%** against real hardware (predicted 735,461 vs measured
   745,420 cycles for one SHA-256 block) — accurate enough to *rank* variants before
   any VM run.
3. **Ground truth — 86Box, serial.** A standalone `SEED.SYS` micro-benchmark boots
   through the real boot chain, times each operation with the BIOS tick counter
   (1 tick = 54.9254 ms), and reports over COM1 (`run86box.py`, one VM at a time).
   This confirms the leaders and re-calibrates the model.

The cycle model earns its keep by *ranking*, not by absolute accuracy: it ran ~16%
optimistic on the final register-dense code (it was calibrated on the memory-heavy
baseline and under-counts prefetch-queue starvation), but it ordered the variants
correctly. **86Box on real timing is always the claim; the model only decides what
gets a VM run.**

### The optimisation method — parallel agents, correctness-gated

The symmetric-speed search was an **evolutionary hunt run by parallel agents**: each
round, several agents each proposed, implemented, correctness-checked, and
cycle-ranked **one** variant; the leaders were selected and recombined into the next
round's seeds. Twenty correct variants survived across four rounds (two agents failed
to return structured output and their variants were dropped — the gate is strict).
The P-256 hunt was structured the same way, one optimisation per agent against a
fixed contract (`P256_OPT_CONTRACT.md`): a variant must be `ok` against the OpenSSL
oracle before its speedup counts — *"a correct 1.3× beats a broken 3×."*

---

## The symmetric track — SHA-256 / TLS-PRF (the crypto that always runs)

Every handshake, secure or not, grinds the TLS-PRF (key schedule) and a transcript
hash. On the 8088 baseline that is the bulk of the "CKE→Finished gap":

| op | baseline (real 86Box) | cycles |
|---|---|---|
| SHA-256 `process_block` | **156 ms** | ~745 K |
| TLS-PRF master secret | 2.39 s | ~11.4 M |
| **TLS-PRF master + key block** | **4.92 s** | ~23.5 M |

Where the time went: the original rotates **one bit per loop iteration** (a rotate-by-22
is 22× `shr`/`rcr`/`loop`), and all 32-bit math is **memory-to-memory** 16-bit halves
over the 8-bit bus (~4 cycles/byte). Rotation and memory traffic dominate — so the
search drove the working set into registers, step by step:

| stage | best variant | the insight it added | ×base (model) |
|---|---|---|---|
| baseline | `core/sha256.inc` (orig) | bit-at-a-time rotate; 32-bit math memory-to-memory | 1.0× |
| seed | `v001_byterot` | **byte-granular rotate** (`xchg`/byte-moves + ≤7 residual bits) — kills the bit loop | 1.53× |
| round 1 | `r1_v7` | **inline sigmas + unrolled ring-shuffle** — no `call` clobbering regs mid-round | 4.26× |
| round 2 | `r2_v22` | **register-fold** Ch/Maj/T1 through regs + stack, not memory temporaries | 4.95× |
| round 3 | `r3_v32` | **state base-ptr + disp8 addressing** — `a..h` as `base+disp8`, drop all spills | 5.43× |
| round 4 | `r4_v44` | **`xchg` byte-rotate as register renaming** + branchless shortest-path sigma chains | 5.78× |

The thread: **kill bit-loops → kill call overhead → kill memory traffic → kill the
rotate moves themselves.** On real hardware the two round-4 leaders (`r4_v42`,
`r4_v44`) are a dead heat and **bit-identical** to the baseline output:

| op | baseline | `r4_v42` | speedup (HW) |
|---|---|---|---|
| SHA-256 block | 273 ticks | 55 ticks | **4.96×** |
| PRF master + key block | 269 (4.92 s) | 58 (**1.06 s**) | **4.64×** |

The always-runs PRF drops **4.92 s → 1.06 s** on real hardware, at zero security cost
— pure margin under the server's window.

### The catch, and the shipped decision: speed vs. size

The win costs code, and the resident K crypto window (SHA + ChaCha20 + Poly1305 + TLS
+ agent-API) had only **9 bytes** of headroom. The speedup is a frontier against size:

| variant | code Δ vs baseline | HW speedup | notes |
|---|---|---|---|
| `v001_byterot` | +61 B | 1.42× | the cheap first step |
| `r1_v7` | +471 B | ~4.3× | |
| `r2_v25` | (fits 15 sectors, no golf) | **4.62× block / 4.33× PRF** | **← shipped** |
| `r4_v42` | +595 B | 4.64× | needs a fragile 74 B crypto golf for the last ~0.3× |

**We shipped `r2_v25`, not the faster `r4_v42`.** The reason is the whole point of the
size column: `r2_v25` fits the 16K K-window in 15 sectors with **no golf**, while
`r4_v42` bought its extra ~0.3× only with a fragile 74-byte hand-squeeze of the hot
crypto path. The ~0.02× of PRF speed was not worth a brittle hot-path edit on the
machine with the least slack. `r2_v25` is now the 16K crypto baseline (the slow path
was deleted); the verified `r4_v42` is preserved in `variants/` as the frontier marker.
This same fast SHA is **load-bearing for the 286 secure tier** — it is what gets the
6 MHz handshake under the window at all (below).

---

## The asymmetric track — real public-key crypto (the wall)

"Encrypted but not secure" on the 8088 rests on three skipped pieces: real key
agreement, real entropy, and certificate authentication. We measured each.

### Real ECDHE — P-256 scalar multiplication
The constant-time P-256 had sat under `%if 0` in `core/p256.inc` since Build 6 and had
never been assembled. Brought to life (`p256_real.inc`), it assembles 8086-clean and
verifies against the OpenSSL oracle end-to-end (`scalar_mult(d×G) == public`). Then:

| metric | value |
|---|---|
| **one real ECDHE scalar mult** | **528.9 M cycles = 110.8 s** |
| field multiply `p256_mul_mod` (the hot primitive, ~97% of cost) | 137,625 cyc (28.8 ms) |
| code size | ~2.4 KiB code + ~1 KiB data ≈ **3.4 KiB** |

- **Time: fails by ~7.4×** (110.8 s vs the ~15 s window).
- **Size: fits 16 KiB easily.** The wall is purely time.
- Even a *perfect* schoolbook multiply (raw `mul`s, zero overhead) bottoms at ~26.6 s.
  The 8088's ~133-cycle `mul` opcode is the floor — real P-256 ECDHE cannot fit.

### Certificate authentication — signature verification
Costs derived from (and later confirmed against) the measured field multiply:

- **RSA-2048 verify (e=65537): ~43 s/sig** — a modexp of ~17 Montgomery modmuls; the
  *least bad* option.
- **ECDSA-P256 verify: ~220 s/sig** — two scalar mults; ~5× worse than RSA.

> A guess the measurement corrected: on a desktop, RSA *verify* is microseconds and
> "cheap", which misled an initial ~1 s estimate. On a 4.77 MHz 8088 the n² word-`mul`s
> dominate and RSA-2048 verify is ~43 s. Even its theoretical floor (raw `mul`s only)
> is ~15 s — *at* the window, with no headroom.

### Real entropy
Cheap in CPU: a SHA-256-mixed pool fed by keystroke timing / NIC arrival / PIT samples
is **~0.16 s**, one extra block. But it is **gated**: with a public premaster the client
random is only a nonce, so better entropy buys *no* confidentiality on its own — it earns
its keep only bundled with real key agreement. (It is also largely untestable on the
cycle-deterministic emulator: only keystroke timing is genuine entropy under emulation;
the rest needs real-hardware validation.) Shipping it standalone would be cosmetic, so we
did not. Detail in `tools/crypto-bench/results/entropy_certauth_scoping.md`.

### Combined reality on the 8088
ECDHE 110.8 s + cheapest auth ~45 s + PRF ~5 s, all serial ≈ **~160 s ≈ 2.7 minutes**,
**~11× over** the server's ~15 s patience. Real public-key security on a stock 8088 would
need a self-hosted long-patience endpoint, an opt-in multi-minute "secure" mode, or a
faster machine. We chose the faster machine.

---

## The levers we ruled out (measured, not assumed)

### An 8087 FPU? No.
The right framing is "offload whatever gives the fastest end-to-end crypto." Measured
anchor (`fpu_bench.asm`, 8087 enabled): a 32×32→64 multiply is **8088 1074 cyc vs 8087
585 cyc = 1.84×** on the primitive. But one scalar mult needs ~450,000 `FMUL`s, and at
the 8087's ~130-clock `FMUL` that is **~12 s of `FMUL` alone** — before a single add,
conversion, reduction, or point op. Realistic all-in is ~35–50 s per scalar mult: still
2–3× over the window. And the always-runs SHA/PRF has **no multiplies to offload**, so it
does not move at all. The wall is 256-bit modular-*integer* work; a float multiply is not
enough leverage. **No FPU crypto path is worth building.**

### V20 / 80186 instructions? Marginal, and the bus wins.
Tested on a V20 (`bench186.asm`), not reasoned. The 186 shift-by-immediate is a fixed
cost; the 8086 single-bit residual grows with the residual, so the 186 wins only on large
residuals (crossover ~residual 3–4). Across SHA-256's twelve rotate residuals, 8/12 favour
the 8086 — a hybrid nets only ~2–4% on a full block, and a fully 186-tuned V20 SHA (~82 ms)
is still slower than plain-8086 code on a 16-bit-bus 8086 @ 8 MHz (71 ms). **The bus beats
the ISA.** Tier capability on RAM and bus class, not on the 80186 instruction set — not
worth a CPU-specific code path. (This corrected an earlier "~nothing" reasoning: it is real
but small, and the test was right to run.)

---

## Where security begins — the 286 (measured at 6 and 8 MHz)

The 086 class cannot reach a secure handshake even maxed and hybridised. The 286 can. We
booted the 360K bench image on 86Box's `ibmat` (286, clamped to its real 6–8 MHz) via a
crafted IBM-AT CMOS. The 286 has no cache, so 6→8 MHz scaled exactly with clock — higher
clocks project linearly.

| CPU | SHA block | integer 32×32 MUL |
|---|---|---|
| 8088 @ 4.77 | 155.6 ms | 0.225 ms |
| 286 @ 6 (measured) | 61.8 ms (2.5×) | 0.0330 ms (**6.8×**) |
| 286 @ 8 (measured) | 45.8 ms (3.4×) | 0.0247 ms (**9.1×**) |

The 286's integer `MUL` is ~9× the 8088's at 8 MHz — *exactly* the P-256 bottleneck. (And
the 287 FPU is **slower** than the 286 integer `MUL`, 0.047 vs 0.025 ms — the opposite of
the 8088's 8087, so "286 + FPU" adds nothing for crypto either.)

### Optimising P-256 for the 286 — three approaches, then combine
On the 286 the `MUL` opcode is cheap, so the *overhead* (memory traffic, the reduction
loop) dominates — which is what the P-256 hunt targeted. Three high-value optimisations,
one per agent, each correctness-gated:

| optimisation | what it does | field-mul win |
|---|---|---|
| **Solinas reduction** | direct NIST P-256 fast reduction (limb adds/subs) replacing the table-driven reduce — no table, no coeff loop | 1.375× |
| **register-Comba multiply** | keep the 3 column accumulators in registers across the inner loop, not memory | 1.233× |
| **Karatsuba + Comba** | one-level Karatsuba split over the Comba sub-multiply | 1.505× |
| **wNAF width-4 scalar** | recode the scalar into signed digits → point-adds 141 → 51 | (fewer field muls) |
| **combined** (all three) | `variants/p256_combined.inc`, verified vs OpenSSL | **2.554× field mul, 3.27× fewer scalar-mult instrs** |

Measured on real 286 @ 6 MHz hardware (one full ECDHE, output checksum-verified):

| | 286 @ 6 ECDHE |
|---|---|
| baseline real P-256 | 470 ticks = 25.8 s |
| **optimised (combined)** | **120 ticks = 6.6 s (3.9×)** |

(The 3.9× on hardware exceeds the 2.55× field-mul model because the 286's fast `MUL` makes
the *cut overhead* — Solinas/wNAF — the thing that matters, which is what those two cut.)

### The full secure-handshake budget on the 286
Each piece measured on `ibmat @ 6` (entropy projected, gated/cosmetic):

| component | 286 @ 6 | basis |
|---|---|---|
| ECDHE (optimised P-256) | 6.6 s | measured |
| RSA-2048 cert verify | **6.37 s** | measured (`rsa_bench.asm`) — 16 squarings + 1 multiply as plain Montgomery modmuls, no squaring shortcut at first (a later Build-12 increment, `montsqr`, adds one — see *Follow-up* below) |
| PRF + transcript (baseline SHA) | 4.94 s | measured |
| PRF + transcript (with the fast-SHA win) | **0.66 s** | measured (~7.5× here — it is almost pure SHA) |
| entropy | ~0.2 s | projected (gated) |

The measured RSA was the late correction: it is ~2.5× an earlier ~2.5 s guess (that guess
assumed a squaring shortcut we did not build), and it dominates the budget more than ECDHE
does. Summing the serial crypto against the ~15 s window:

| 286 clock | full secure handshake (with fast SHA) | slack vs ~15 s | verdict |
|---|---|---|---|
| @ 6 (lowest) | **~13.8 s** | ~1.2 s | **knife-edge** — fits only *with* the SHA win, and barely |
| @ 8 | **~10.4 s** | ~4.6 s | **comfortable** |
| @ 12 (linear proj) | ~6.9 s | ~8 s | ample |

**Threshold result: security begins at the 286.** An optimised real ECDHE is 6.6 s on the
lowest 6 MHz part, so a real cert-authenticated handshake (real ECDHE + RSA cert-auth + the
fast SHA + entropy) *fits* the ~15 s window there — but on a ~1.2 s knife-edge that will
flake on a degraded link (the 8088's exact failure mode). The practical, non-flaky secure
tier is **286 @ 8 MHz and up**.

> An earlier linear projection (before the P-256 optimisation and the SHA win were folded
> in) put the threshold at ~16–20 MHz. The optimisation work closed that gap by ~3×: the
> lowest 6 MHz 286 reaches it, knife-edge; 8 MHz is comfortable. That is the corrected,
> measured verdict.

### Follow-up — the squaring shortcut, built (`montsqr`)

The budget above assumed the RSA verify away with no squaring shortcut. A later Build-12
increment built one: **`montsqr`**, a Montgomery SOS squaring used for the modexp's 16
squaring steps. Squaring `a²` is cheaper than a generic `a·b` because the off-diagonal
products `a[i]·a[j]` (i<j) each appear twice — computed once and the partial sum doubled
(a single left shift), halving the multiply-phase multiplies. It cuts the verify **~19%**
in the `rsa_eval` instruction proxy (6.92M → 5.60M), correct against `pow(s,65537,N)` and
on the real `api.openai.com` signature. So the @6 secure handshake greets with more margin
than the ~1.2 s above, and the off-race re-pin (auto-recertify) is correspondingly faster.
It is 286-only (the handshake module) and was golfed back into the original 24-sector module
band — sharing the montmul/montsqr conditional-subtract + carry tails and factoring the
strict-DER parser's repeated idioms into helpers reclaimed 312 B — so it costs **no**
conversation context. The RSA-squaring lever the earlier scoping called "slack-polish, not
the @6 enabler" is exactly that: it widens the shipped tier's margin; the off-race
architecture is still what makes silent re-pin fit @6.

---

## What we shipped, and why

| decision | choice | why |
|---|---|---|
| **SHA-256 / PRF** | `r2_v25` (4.62× block / 4.33× PRF) | fits the 16K K-window in 15 sectors with **no golf**; the faster `r4_v42` (4.64×) needed a fragile 74 B hot-path squeeze for ~0.02× more — not worth it. Now the single 16K crypto baseline (slow path deleted). |
| **ECDHE** | the combined Karatsuba + Solinas + wNAF P-256 → `core/p256.inc` | 3.9× on the 286 (25.8 s → 6.6 s @6) — the only thing that gets ECDHE under the window on the lowest 286. 286-only (handshake module). |
| **Cert-auth** | pin the `api.openai.com` leaf key; one in-race RSA-2048 verify | one verify fits the lowest 286; a full chain (~3 verifies) would push back over the window. RSA over ECDSA because ECDSA verify is ~2× ECDHE. (Leaf rotation is handled by [silent re-pinning](architecture.md); see auto-recertify.) |
| **Entropy** | not shipped standalone | gated — cosmetic without real key agreement; would cut against honest framing. Ships only bundled with the secret it protects. |
| **Tier** | secure begins at the 286, comfortable at @8; the 8088 stays "encrypted, not secure" | measured: the 8088 is ~11× over the window and cannot be optimised across it; the label is precise, not aspirational. |
| **FPU / 80186** | neither | measured to not unlock crypto (FMUL-count floor; the bus beats the 186 ISA). FPU stays a future *non-crypto* capability dimension. |

---

## The ECDSA question — scoped, not built

The shipped 286 tier pins an RSA leaf — but `api.openai.com` is **dual-cert
load-balanced** and migrating to ECDSA. The 286's forced `ECDHE_RSA` profile still draws
the RSA-2048 leaf (via GTS WR1, valid to 2029-02-20); default clients now get a P-256/WE1
ECDSA leaf. Today's pin survives only because the 286 forces RSA. So we asked the obvious
next question — *if the RSA leaf ever goes away, can the 286 do ECDSA?* — and scoped it with
two more parallel-agent spikes (the same method, findings adversarially checked against the
shipped code).

**First: is ECDSA verify even affordable @6?** ECDSA verify is `u1·G + u2·Q` — *two* scalar
mults — against RSA's one modexp, so on this CPU it is ~2× the RSA verify (the opposite of a
desktop, where ECDSA is the cheap one). With Shamir's trick the two mults interleave to
~8.3 s, putting the in-race handshake at ~15.7 s @6 — *over* the ~15 s window. A fan-out of
optimisations (a fixed-base comb on `G`, tighter Shamir/JSF, field-mul and Solinas-reduction
micro-tuning, 286-ISA, the mod-n inverse) lands a best honest, non-overlapping stack at only
~15.1–15.9 s — still on or over the line — and the comb's big win turns out to be *off-race*
(it accelerates the client `d·G` keygen, which runs before the window even opens). Worse, the
secure module is already **24/24 sectors with zero headroom**: there is nowhere to put the new
code. Field tuning does not make @6.

**Then: can we move the verify off the race?** Auto-recertify already verifies the cert
*chain* off the window — so could the in-race SKE-signature verify be deferred the same way? A
second spike (security-first, with an adversarial security reviewer) said **no, as proposed**.
It is *sound for confidentiality* — behind a strict fail-closed app-data gate nothing durable
leaks — but it is a **security downgrade**: a MITM gets a completed session and the client
Finished (an interactive oracle) before rejection, which the shipped authenticate-before-use
never grants. And the tempting "just reuse recertify's hook" is false: recertify verifies
*disconnected, between handshakes*, while the SKE signature is *per-connection*, so off-racing
it means holding the live connection **idle ~8 s** — a timing risk the wire-proven @6 fragility
makes a bad bet, and one nobody has measured.

**Verdict: ECDSA @6 is not reachable cleanly; 286 @8 MHz (~12.4 s, no deferral, no downgrade)
is the floor** if the contingency fires. It stays design-intent — no code while the RSA leaf is
served to 2029. The decision reference is
[security.md](security.md#the-future-ecdsa-tier--scoped-not-built); the raw spike record is
`notes/old/ecdsa-tier-scoping.md`.

---

## Reproduce / the record

The harness, contracts, and every variant live in `tools/crypto-bench/`:

- **`results/FINDINGS.md`** — the original spike log (raw tables, every measurement,
  reproduce commands), now summarised here.
- **`results/entropy_certauth_scoping.md`** — the entropy + cert-auth deep dive.
- **`results/speed_leaderboard.json`** / **`baseline.json`** — the 20-variant audit trail
  and the frozen baseline.
- **`P256_OPT_CONTRACT.md`, `RSA_CONTRACT.md`, `CONTRACT.md`** — the per-track agent
  contracts (entry points, oracles, required structured output).
- **`variants/`** — the assembled, OpenSSL-verified variants (`r1_*`…`r4_*` SHA,
  `p256_*` ECDHE). The shipped picks are `r2_v25` (SHA → `core/sha256.inc`) and
  `p256_combined` (→ `core/p256.inc`).

Example reproductions:

```sh
cd tools/crypto-bench
python3 evaluate.py variants/r4_v42.inc          # SHA variant: correctness + cycle rank
python3 run86box.py --sha variants/r4_v42.inc    # SHA variant on real 86Box timing
python3 p256_eval.py variants/p256_combined.inc --full   # P-256: correct vs OpenSSL + scalar-instr ratio
```

All numbers are for the IBM PC 5150 profile (8088 @ 4.772728 MHz, no dynarec) unless a row
says `286 @ N` (86Box `ibmat`, crafted AT CMOS, 6–8 MHz measured / higher projected linearly).
