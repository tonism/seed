# Handshake speed — crypto optimization + real-crypto feasibility (fresh-session brief)

Self-contained. A fresh session should be able to run this from THIS file + the code. This is a
MEASUREMENT / FEASIBILITY SPIKE, not a ship-it task: the deliverable is knowing **what TLS-handshake
crypto speed is achievable on the original 4.77 MHz 8088**, with benchmarked evidence, so we can then
decide what to actually build.

## Two fronts (do both)

1. **Make the current handshake faster.** The TLS 1.2 handshake takes ~15 s and sits only ~0.2 s
   inside Cloudflare's ~15 s patience window — any latency spike tips it over (the observed
   degraded-link boot/reconnect failure). The dominant cost is the ~7.5 s CKE→Finished gap, which is
   the 8088 grinding the **TLS-PRF** (master secret + key block), i.e. SHA-256 / HMAC-SHA256. Faster
   PRF = more patience margin AND a shorter window for packet loss to bite. This is pure symmetric
   crypto that ALWAYS runs, so it's the highest-leverage speed win.
2. **Investigate real crypto.** Today the channel is "encrypted but not secure" — three deliberate
   sacrifices, all CPU-bound:
   - **No key agreement.** `p256_compute_server_premaster_secret` (p256.inc) is a scalar-1 stub: it
     copies the server's public X straight into the premaster. The REAL constant-time P-256
     primitives (field math, point double/add, scalar-mult) exist under `%if 0` (p256.inc:8) and are
     OpenSSL-cross-checked, but are compiled out for speed + size.
   - **No real entropy.** The client random + (eventual) ephemeral scalar use a BIOS-tick LCG.
     `RDRAND`/`RDSEED` don't exist on an 8088; entropy must come from timing jitter / disk / NIC.
   - **No server authentication.** The certificate chain + signature are skipped (the Certificate
     handshake message is parsed for length and drained, never verified). Real auth needs RSA-2048 or
     ECDSA-P256 signature verification.
   Measure how expensive each is on 4.77 MHz 8088 and whether real ECDHE (and ideally entropy +
   cert-auth) can fit the time budget (under the server's ~15 s patience) and the 16 KiB byte budget.

## Method: a deep parallel evolutionary search

This is intensive by design. Run the two fronts as TWO INDEPENDENT, CONCURRENT investigations; each
is its own wide multi-agent evolutionary search that should produce TENS of benchmarked variants /
evolutions, not a handful. The `Workflow` tool is built for exactly this fan-out + loop; use it.
The goal is to map the achievable frontier on 4.77 MHz 8088 with hard evidence.

**STEP 0 — build a CHEAP, isolated benchmark harness FIRST.** Do NOT run the full Seed
boot+DHCP+DNS+TLS flow per variant — that's minutes each and would cap you at a handful of
evolutions, not tens. Test the crypto IN ISOLATION, on three cheap tiers (cheapest first):
- **Correctness (host, instant):** the OpenSSL cross-checkers — `tools/check-p256.py`,
  `tools/check-tls-prf.py`, `tools/check-chacha-poly1305.py`. A variant must pass before it's timed.
- **Speed first-pass (host, instant):** analytic 8088 cycle-count of the hot inner loop (8088 cycle
  table + memory/prefetch penalties — the 8088's 8-bit bus makes word access and the prefetch queue
  the real cost). Rank variants here and only emulate the promising ones. Consider a small host-side
  8088 cycle-cost scorer so the search can self-filter without a VM.
- **Speed confirm (86Box, seconds):** a STANDALONE crypto micro-benchmark binary that boots straight
  into "run op N times, time via the BIOS tick counter `0x0040:0x006c` (~18.2065 Hz, ~55 ms), print
  the result" — no DHCP/DNS/TLS/handshake. Reuse the crypto `.inc` files directly; ideally one boot
  benchmarks several variants in a row. This op-only binary is the per-variant workhorse — BUILD IT
  FIRST. Time N iterations and divide; pick N so the total is many ticks.
- **Final only (full flow, once):** confirm the chosen winners in the real Seed handshake, wire-timed
  via `tools/tls-flow.py <pcap> <ip-substr>` (the ~15 s / ~7.5 s baselines were measured this way) —
  to check the isolated speedups actually move the end-to-end handshake. Not per variant.

**STEP 1 — two concurrent evolutionary searches.** Run the speed track and the real-crypto track in
parallel (they touch independent code, so they don't bottleneck each other). Each track loops:
- ROUND: spawn MANY independent agents; each proposes + implements + correctness-checks + benchmarks
  ONE variant (a mutation/recombination of the round's leaders, or a fresh idea).
- SELECT: rank the correctness-passing variants by benchmarked cost; keep the top few.
- EVOLVE: the next round's agents build on the leaders plus a couple of wild cards. Repeat for many
  rounds, until gains plateau — aim for tens of evolutions per track.
Number + log every variant (idea, diff, correctness, cycles/ticks) so nothing is silently re-tried
and the frontier is auditable. Seed ideas to explore (not exhaustive):
- SHA-256 (`core/sha256.inc`, ~765 lines — the hot op): faster inner round loop, the message
  schedule, loop-unrolling vs size, table vs computed K, register pressure on 8086. This is where
  most of the PRF time goes.
- TLS-PRF / HMAC (`core/tls.inc` `tls_prepare_master_secret` @594, `tls_prepare_key_block` @82, and
  the prepared ipad/opad states): fewer PRF rounds (derive only the bytes actually used), reuse of
  the prepared HMAC states, avoid recomputing the inner hash.
- P-256 scalar-mult (`core/p256.inc` under `%if 0`): enable it, benchmark a single real ECDHE
  shared-point computation. Then explore windowed / wNAF / fixed-base precomputation, faster
  field-mul/reduction (Comba is already there), leading-zero skip. Goal: a real-scalar cost number +
  how low it can go.
- Entropy + cert-auth: scope only (cost estimate + approach), unless time allows a prototype.

**STEP 2 — verify every variant.** A faster crypto that's wrong is useless. Cross-check against
OpenSSL with the dependency-free checkers: `tools/check-p256.py`, `tools/check-tls-prf.py`,
`tools/check-chacha-poly1305.py`, `tools/poly1305-port-check.py`. Any variant must pass its checker
before its benchmark counts.

**STEP 3 — report.** What's the floor for the current PRF (ms, and what margin it buys under the
~15 s server window)? What does a real P-256 scalar-mult cost, and the cheapest achievable? Can real
ECDHE + entropy + cert-auth fit the time + 16 KiB budget, or which subset can? Recommend what to
build (and what stays out of reach on 4.77 MHz).

## Constraints

- **8086 instructions only** — the 4.77 MHz 8088 target. No 186/286/386 opcodes (no `shl r, imm>1`,
  no `movzx`, etc.). Validate any variant assembles for the real target.
- **16 KiB byte budget.** The resident nucleus is full (≈2047/2048 B) and the crypto phases are
  tight; a "faster" variant that doesn't fit is out. Size/speed is a real trade. (The real P-256
  primitives were compiled out for BOTH speed and size.)
- **Honest-security framing.** Don't let docs/README claim "secure" unless real ECDHE **and** real
  entropy **and** cert-auth all land — partial work stays "encrypted but not secure." Per-record
  app-data is already MAC-verified (the Build 11 FIFO collapse kept incremental Poly1305) — that's
  record integrity, not a secure channel.
- This is a spike on a fresh branch off `work/draining-fifo` — don't commit half-optimized crypto to
  the main line; land only verified, benchmarked wins.

## Key files + tools

- Crypto: `core/sha256.inc` (765), `core/p256.inc` (1214; real primitives under `%if 0`),
  `core/poly1305.inc` (395), `core/chacha20.inc` (169).
- Handshake + PRF/key-schedule: `core/tls.inc` (2051) — `tls_prepare_master_secret`,
  `tls_prepare_key_block`, `tls_build_master_secret_seed`, the prepared HMAC ipad/opad.
- Checkers (OpenSSL cross-check): `tools/check-p256.py`, `tools/check-tls-prf.py`,
  `tools/check-chacha-poly1305.py`, `tools/poly1305-port-check.py`.
- Wire + emulator: `tools/tls-flow.py`, `tools/run-basic-bootstrap-86box.py`. Build: `make`,
  `make inspect` (byte budget). 8088 timing baseline: ~15 s handshake, ~7.5 s CKE→Finished (PRF).
- Background: `docs/builds.md` ("Forward-looking ideas" → handshake speed / true security), Build 6
  section (the original TLS implementation + the scalar-1 tradeoff note), README security status.

## Deliverable

A written findings report (what's achievable, with benchmark numbers) + any verified, benchmarked
optimization landed on the spike branch. When the spike concludes, fold the findings into
`docs/builds.md` and delete this brief (one-attempts-log-per-build convention).
