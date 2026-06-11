# Memory-layout redesign — design charter (fresh-session brief)

Self-contained. A clear session should be able to start from THIS file + the code. This is a
**foundational redesign** of Seed's RAM layout, not a feature. Such redesigns are expensive and
high-blast-radius; the goal is a design that makes future features/NICs/CPUs/crypto **additive**
instead of forcing another byte-scrounge. Get the foundational decisions right so we do this rarely.

> Status: signals-gathering for the redesign. Numbers + symptoms below are from the Build-11 era and
> the crypto spike (`tools/crypto-bench/results/FINDINGS.md`, `docs/architecture.md` "CPU And Crypto
> Budget"). Validate against the current tree before committing — the layout moves fast.
>
> **Crypto/CPU investigations COMPLETE (2026-06-11, branch `spike/crypto-speed`).** The two crypto
> questions this charter gated on are now measured, not hypothesized: (1) the FPU does NOT unlock
> secure crypto on the 086 class, and (2) a full cert-authenticated TLS handshake becomes *reachable*
> at the 286 and *comfortable* at 286@8+. Folded into the Principles / O2 / Investigations below — the
> upshot is a concrete future objective: **"secure" is a 286@8+ tier, never the 16K/4.77 MHz floor.**

---

## Why now — the forcing signals

The current layout was never designed top-down; it accreted, region by region, as features landed.
It has hit its ceiling for the small target, and several known-incoming features do not fit cleanly:

- **The address space is maxed.** Resident nucleus ~2048/2048 B. The K crypto link window
  (0x1800–0x33f7) is **9 bytes** from the crypto-scratch boundary at 0x3400.
- **Reuse has gone ad hoc.** `data.inc` is dozens of hand-reasoned aliases — `poly_rx_save equ
  tls_master_secret`, `tls_app_record_buffer equ api_request_plain`, `dpi_input_buf equ tls_rx_copy`,
  "reuse the setup form scratch for the response scanner"… each clever, collectively a map whose
  "is this region dead here?" logic lives in comments and human memory, not in a check.
- **That's the recurring bug class.** Build 11 repeatedly hit aliasing bugs (`ne_tx_frame` aliasing
  `low_crypto_work`; the streaming-decrypt chacha keystream clobbered by an inter-chunk NIC receive;
  the keep-alive tail clobbered by the MAC-PROM read). All "a region assumed dead was actually live."
- **A verified win can't land.** The crypto spike's SHA-256/PRF rewrite is **4.64× on real hardware**
  (PRF 4.92 s → 1.06 s, bit-exact) but adds ~595 B — and there are 9 B free. The forcing function.
- **Known backlog doesn't fit:** faster/real crypto on capable machines, more NIC families, an
  FPU-accelerated path, floppy-free mid-session on big machines, and eventually >64 KiB / "gigabytes".

The marginal cost — and bug risk — of the *next* feature's bytes is now high. Organic allocation has
run its course for the constrained tier.

---

## Principles to KEEP (do NOT redesign these away)

- **The chat arena grows with RAM.** Original intent, works well. It is the user/agent **playground**
  and where the agent's hardware access lives (peek/poke/CALL operate there). Keep it **large,
  contiguous, and advertised** (the ledger `a@` already publishes base+length). Growing HW code must
  not fragment it.
- **One visible `CORE.SYS`; one write-protected 160 KiB FAT12 floppy as the recovery boundary.**
- **16 KiB is the primary target and is inviolable.** Design for 4.77 MHz 8088 / 16 KiB **first**;
  every feature must FUNCTION there (ROM-BASIC entry). It is the recovery/identity boundary — never
  break it. Bigger machines scale and add opportunities; they are not a different product.
- **Two tiers, LOCKED: 16K and 32K.** 16K = minimal, full functionality. 32K = the scale tier where
  performance + headroom opportunities switch on (fast crypto, floppy-free loop, preloads). Machines
  larger than 32 KiB reuse the 32K tier and simply keep growing the chat arena with `ram_top` — there
  is **no third tier**. Keep it that simple.
- **Functional parity at 16K; 32K adds performance + headroom, never new *required* functionality.**
- **One artifact** (see the crux): all tier code ships in the single `CORE.SYS`; the capability vector
  selects what loads and where.
- **Honest security framing** stays: a faster machine is not "secure" unless real ECDHE **and** entropy
  **and** cert-auth all land in a usable handshake. The spike now MEASURED where that line is: on a
  stock 8088 they don't (real ECDHE alone = 110 s); the full secure handshake first FITS the ~15 s
  server window at the **286** — ~13.8 s on the lowest 6 MHz part (only with the fast SHA, on a
  knife-edge ~1.2 s slack) and a comfortable ~10.4 s by 8 MHz. So "secure" is a **286@8+ tier**, never
  the 16K / 4.77 MHz floor — which stays honestly "encrypted, not secure."
- **Hardware-agnostic static prompts** (identity, compaction) never name the hardware — portability.

---

## Objectives (what the new layout must achieve)

- **O1 — Capability-tiered layout.** A boot-detected **capability vector** drives allocation and which
  modules load. Primary dimensions NOW: **RAM (the 16K/32K gate)** and **NIC family** (needed on every
  tier). Future-additive dimensions — design the vector to *hold* them, don't act on them yet:
  **CPU class** (V20/286/386+) and **FPU present**. Carry it in the handoff struct (already carries
  `ram_top`, `nic_family` — extend it). "Arena grows" becomes one instance of the general rule:
  *everything that can scale, scales by tier.*
- **O2 — Fit the crypto wins, by class not by hack.** A crypto-variant slot the capable tier fills
  with the fast SHA/PRF (the +595 B 4.64× win lands here) and the 16K tier fills with the small-slow
  version. NB the spike showed the fast SHA is **load-bearing for the 286 secure tier**, not just a
  perf nicety: it's what pulls the secure handshake from ~18 s (over the window) to ~13.8 s @6 / ~10.4 s
  @8. Leave room for the real-crypto slot the secure tier needs — measured on a 286@6: optimized real
  P-256 ECDHE 6.6 s + RSA-2048 cert-verify 6.37 s + fast PRF/transcript 0.66 s, all serial (the dormant
  P-256 is ~3.4 KiB). The FPU does NOT earn a crypto slot (see Investigations). One mechanism, not a
  per-feature byte-fight.
- **O3 — A floppy-free *conversational loop* on the 32K tier.** "Floppy-free" means specifically: once
  the chat loop is live, NO disk reads (no mid-chat latency, no keep-alive-fires-during-render →
  disk-read hazard, and a mid-session reconnect needs no phase reload). Achieve it by doing MORE at
  boot — **boot-time floppy reads are fine and encouraged** when they buy loop-time RAM: on 32K,
  preload the loop's phases + the streamed IDENTITY/COMPACT prompts resident at boot. 16K keeps
  demand-loading in-loop (no room to preload) — acceptable; this is a 32K opportunity, not a 16K
  requirement.
- **O4 — Owned regions + checked lifetimes (replace hacky reuse).** Each region declares
  `{owner, size, lifetime, load-policy}` where lifetime ∈ {boot-only, handshake-only, per-turn,
  session-persistent, reconnect-survives}. Reuse is allowed ONLY across provably-disjoint lifetimes,
  and the build **asserts** it. Reuse stays (16K needs it) but becomes intentional + safe, killing the
  alias-bug class.
- **O5 — A HAL / capability layer with a home.** NIC drivers, FPU-accelerated crypto, CPU-class code
  paths live in a declared layer loaded per the capability vector — additive as new NICs/CPUs arrive,
  not wedged into shared scratch.
- **O6 — Don't block the >64 KiB future.** Pick boundaries + a relocation model that let a later
  multi-segment / EMS / protected-mode tier be **additive, not a rewrite**. Be segment-model-aware;
  do NOT build protected mode speculatively now (YAGNI). "Gigabytes" is likely its own future redesign
  — design the seams for it.
- **O7 — One authoritative, checked memory map.** Today it's split across `layout.inc` + `data.inc` +
  the `core.asm` phase table + `Makefile` constants + `core-sys-info` ranges + `docs/memory.md`. One
  spec should **generate** the constants + the docs map + the budget checks. (`docs/memory.md` +
  `tools/memory-map.py` are a seed.)

---

## The crux decision — settle FIRST (one-way door)

**LOCKED: one artifact.** Seed ships a single `CORE.SYS` that runs every tier; the capability vector
selects what loads + where. Multiple artifacts are off the table — the ONLY thing that would ever
justify a second is a fundamentally different ISA (e.g. an ARM/RISC port) where binary reuse is
literally impossible. **Compile-time multi-build per tier is OUT.**

**The relocation model (within the one artifact)** is then the foundational call — settle it before
drawing any boundaries:
- **Runtime-relative addressing** — region bases set from the capability vector (a base register or
  segment per relocatable region); maximally flexible, costs some hot-path bytes/cycles.
- **Hybrid** (likely the pragmatic answer) — a small fixed low nucleus (16K-shaped, always present) +
  optional high modules placed at runtime per tier. 16K uses only the nucleus + demand-loaded phases;
  32K additionally places the optional modules (fast crypto, preloaded phases/prompts) in the headroom
  above. The 16K hot path keeps fixed addressing (no relocation tax); only the optional 32K modules
  relocate.
Everything hangs on this; decide it with eyes open.

---

## Investigations to run (gate the design on evidence)

Use the crypto-bench harness (`tools/crypto-bench/` — unicorn correctness + calibrated 8088 cycle model
+ 86Box ground truth) for anything crypto/CPU:
- **FPU (8087/287/387): DONE — measured, no crypto slot warranted.** Confirmed the hypothesis: SHA is
  add/rotate-bound (FPU-immune), and while an `FMUL` can stand in for four 8088 `MUL`s in the P-256
  field multiply, the reduction/carry work dominates — an 8087 FMUL-only floor is still ~tens of
  seconds, far over the window. The FPU does NOT unlock secure crypto on the 086 class. ⇒ **O5 does not
  need an FPU crypto slot**; the capability vector still HOLDS the FPU dimension (O1) but nothing acts
  on it. The real lever was CPU class (the 286 — see Principles / O2), not the FPU.
- **>64 KiB reach:** which mechanism per era — EMS bank-switching (works on 8088), unreal/protected
  mode (286/386+). Scope only; informs O6 seams.
- **Preload economics:** at each tier, cost (boot time, RAM) vs benefit of preloading all phases +
  prompts (O3).

---

## Constraints / risks / non-goals

- **Blast radius:** the layout touches nearly every `.inc`. Stage the redesign; keep the
  **NIC × RAM-tier test matrix green at every step** (extend `run-basic-bootstrap-matrix.py` with RAM
  tiers). No big-bang.
- **16 KiB is a hard non-regression floor** — it is the recovery/identity boundary. A design that
  optimizes big machines but quietly breaks 16K is a failure.
- **Tiers are LOCKED to 16K + 32K** (>32K reuses the 32K tier and just grows the arena; >64K is
  future). Do not invent more tiers or knobs.
- **Honest crypto framing across all tiers** (see Principles).
- **Non-goal:** implementing >1 MB / protected mode now. Only: don't block it.

---

## Success criteria (so we don't redo this soon)

- Adding a feature / NIC / crypto-variant is **additive** — no hand-scrounged bytes, no new ad-hoc alias.
- Each tier's headroom is **visible and build-checked**; aliases are lifetime-checked.
- The 4.64× crypto win lands on capable tiers (it's load-bearing for the 286 secure tier, not just perf).
- No mid-session floppy I/O on capable tiers.
- 16K still boots and passes the full matrix.
- The memory map has one source of truth.

---

## Inputs / where to start

- Current map: `targets/ibm_pc_5150/boot/core/layout.inc` (equs), `core/data.inc` (the alias web),
  `core.asm` (phase table + the K window + the `%error` budget guards), `Makefile` (scratch bases),
  `docs/memory.md` + `tools/memory-map.py` (partial generated map).
- Headroom probe: `tools/core-sys-info.py` (resident/phase sizes; the `%error` guards already check
  overlaps — generalize them into the O4 lifetime checker).
- Crypto numbers + harness: `tools/crypto-bench/` and its `results/FINDINGS.md`.
- The handoff struct (`layout.inc` `handoff_*`) — the place to grow the O1 capability vector.
- This charter is a living draft during signals-gathering; refine before kicking off the build.
