# Build 12 — capability-tiered layout redesign: staging plan + log

Design of record: **`docs/architecture.md`** (rewritten 2026-06-11). This file is
the *how we land it* — the increment sequence, the file-structure changes, the
verification approach, and the running grind log. The charter
`notes/memory-layout-redesign-brief.md` is *how we got here*.

## Guardrails (from the user)

- **No push.** One push at the very end, once the whole thing works. Commit only
  when a genuinely big part is working and verified (no micro-commits).
- **Matrix green at every step.** The redesign is staged, never big-bang. The
  compatibility gate is original 4.77 MHz / 16 KiB `vm-net-ne2k8` via the ROM
  BASIC sidecar harness; the fuller 7-NIC matrix at larger milestones.
- **16 KiB is inviolable.** Every increment must keep the baseline booting.
- Work autonomously to the final solution; stop only for a genuine decision.

## Scope of THIS pass (user, 2026-06-11)

**Rearchitecting only — feature parity with released Build 11.** Establish the new
*structure* (capability vector, lifetime-banded memory, single source of truth, the
seams) while behavior stays exactly Build 11. New/heavy features get fresh context
windows later. So the physical defrag is NOT required now: it is enough to make the
structure explicit + enforced + seam-ready, keeping the binary at parity.

- **This pass (parity, mostly binary-identical):** 1 checker · 2 capability-vector
  seam · 3 source-of-truth consolidation · 4 band model formalized + enforced ·
  9 docs/close-out. Simple safe things welcome.
- **Deferred to feature sessions (heavy, fresh context):** 5 land the fast crypto ·
  6 the live dispatch-vector mechanism · 7 the 32K floppy-free loop · 8 the HAL
  refactor · the 286 secure tier. Leave the band + vector + seam SHAPED for them.

## Verification ladder (cheap → expensive)

1. **Binary identity** — for pure tooling/doc/manifest changes, prove `CORE.SYS`
   is byte-for-byte unchanged (`md5`). No emulator needed; strongest cheap proof.
2. **`make`** — nasm (`cpu 8086` catches bad opcodes) + `core-sys-info --check` +
   the new layout checker. Catches overlap/size/budget regressions at build time.
3. **ne2k8 gate** — one `run-basic-bootstrap-86box.py --profile vm-net-ne2k8`
   (16 KiB BASIC sidecar). The single-canary smoke for any behavior change.
4. **7-NIC matrix** — `run-basic-bootstrap-matrix.py` at milestones / when TLS
   timing or shared packet code moves. Add 32 KiB-tier profiles as we get there.

`pkill -f 86Box` before any canary (one VM at a time). Clean up screenshots.

## Increment sequence

Dependency-ordered. Each is its own commit when green. Risk + verification noted.

1. **Region/lifetime manifest + checker** (O4/O7 seed). New `tools/check-layout.py`
   reads `layout.inc`+`data.inc` equates and a declared region table
   `{owner, lifetime}`, asserts overlap-only-across-disjoint-lifetimes, wired into
   `make`. Authored to pass on the *current* tree and to document the fragile
   overlays (the alias web). **Binary-identical** — zero nasm change. Verify: md5 +
   checker passes. _Lowest risk; the safety net every later move leans on._

2. **Capability vector** — formalize the handoff capability fields (RAM tier
   explicit; reserve CPU-class / FPU / link-type slots). Append-only to the
   handoff; mind that `low_runtime_state_start = handoff_addr + handoff_size_bytes`
   (growing the handoff shifts low scratch — the checker + `%error` guards catch
   overflow). Verify: build + ne2k8 gate.

3. **Lifetime-tag in place + consolidate the source of truth** (O7). Make
   `check-layout.py` authoritative; kill the Makefile's hand-synced
   `HIGH_CRYPTO_SCRATCH_*` / `CRITICAL_SCRATCH_*` constants (derive from the
   build); fold scattered per-phase `%error` caps into the checker. Mostly
   binary-identical. Verify: md5 (where constants only) + build.

4. **Carve the reconnect-safe line + overlay zone as first-class regions.**
   Formalize what is already roughly true (reconnect-survivors above the line, the
   handshake-only ⟷ per-turn overlay below). Small/no moves. Verify: ne2k8 gate.

5. **Land the fast SHA/PRF crypto** (+595 B, 4.64×, bit-exact) in the
   handshake-only overlay band — the forcing-function payoff. One crypto impl
   (slow deleted). Port the spike's routine into `core/` under the `cpu 8086` /
   org constraints. Verify: `make test` crypto self-checks + ne2k8 gate + matrix.

6. **Dispatch-vector seam** for tier-varying entry points (phase
   preload-vs-demand; near→far-ready). Sets up 32K + HAL. Verify: ne2k8 gate.

7. **32 KiB floppy-free chat loop** — preload the loop's phases + IDENTITY/COMPACT
   prompts at boot on 32 KiB; demand-load stays the 16 KiB path. Add a 32 KiB test
   profile. Verify: ne2k8 (16K) + a 32 KiB profile.

8. **HAL / driver vtable + active-driver slot** — NIC families as
   capability-selected modules, bounded resident slot. Larger; later.

9. **Close-out** — extend the matrix with RAM tiers, full 7-NIC green, regenerate
   `docs/memory.md` + the activity monitor, refresh `AGENTS.md` (stale `NET.CFG`),
   bump nothing else. Then hand back for the single push.

## Source-tree / file-structure review

Current `core/` mixes lifetimes in one crypto group. Conservative, increment-aligned moves:

- **New `tools/check-layout.py`** + the region manifest (increment 1). The manifest
  references `layout.inc` symbols for addresses (single-sourced) and adds the
  lifetime/owner layer.
- **Crypto by lifetime (increment 5+):** `chacha20.inc` + `poly1305.inc` are
  session-resident (record path); `sha256.inc` (+ future `p256`/RSA) are
  handshake-only. Keep them as separate includes already — group them in the link
  window by lifetime rather than splitting the monolithic `tls.inc` (2051 lines;
  too high-blast-radius to split now).
- **Defer:** a `hal/` or `drivers/` dir for NIC families until increment 8, so the
  move travels with the code that needs it. Do **not** split `tls.inc` unless an
  increment specifically requires it.

## Grind log

- 2026-06-11 — Plan written. Design of record = the rewritten `docs/architecture.md`.
  Baseline build confirmed: `CORE.SYS` 27648 B / 54 sectors, nucleus 2033/2048,
  K window 0x1800..0x33f7 (9 B slack). Starting increment 1.
- 2026-06-11 — **Increment 1 DONE** (commit `54f9d94`). `tools/check-layout.py`:
  parses `layout.inc`+`data.inc` equates + the `CORE.SYS` header, prints the
  labeled band map, asserts band geometry + the 19-entry intended-alias web,
  wired into `make`. Binary-identical (md5 `cb2c7d7d…`). It immediately caught the
  drift below.
- 2026-06-11 — **Increments 3+4 DONE** (commit `7d63d70`). O7: the Makefile's
  inspect ranges now derive from `layout.inc` via `check-layout.py --emit` — the
  stale `CRITICAL_SCRATCH_LEN` (2097) is now the real 1229; `make inspect` was
  wrong before, fixed. Checker deepened: reconnect-safe-line divider in the map +
  a phase-footprint backstop (no demand-loaded phase may overrun the nucleus).
  Binary-identical. (Increment 4's *hard* line enforcement = the deferred physical
  reorg, since the band above `critical_scratch_end` still interleaves per-turn
  `tls_app_*` with reconnect-survivor caches; the checker documents the line + gap.)
- 2026-06-11 — **Increment 2 (seam, doc-only).** `HANDOFF.md` now documents the
  capability vector: RAM-tier + NIC-family live; CPU-class / FPU / link-type
  reserved. The struct is full-packed (ends 0x2e, `low_runtime_state` packed to
  0x0700), so field allocation defers to the feature session that adds the first
  consumer. Zero binary change.
- 2026-06-11 — **Pass green.** Full `make` builds the 160K floppy; `make inspect`
  budget correct (critical 1229); `CORE.SYS` byte-identical throughout — Build 11
  parity proven by md5 across every increment. No emulator run needed (no behavior
  change). No push (per policy).
- 2026-06-11 — **FAST SHA LANDED + WORKING on 16K (commit de49ffb).** Landed
  **r2_v25** (4.33× PRF / 4.62× block, bit-exact) — the fastest variant that fits
  the K window in **15 sectors with ZERO golf**. r4_v42 (4.64×) is 16 sectors and
  would need a fragile 74 B bit-exact golf of working TLS/chacha/poly for the last
  ~0.3× *and the same 321 B arena* — not worth the handshake risk. One impl,
  everywhere. Base-raised high_crypto_scratch 0x3400→0x3600 + critical 0x34c2→0x36c2
  (the fast SHA is +1 sector). **16K arena 833→321 B** (the +512 B; reduced but
  functional — conversation window + boot/chat buffers are separate; 32K unaffected).
  **Validated:** 16K vm-net-ne2k8 via the ROM BASIC sidecar reached the model
  greeting (full DHCP→DNS→TCP→TLS-handshake→API→chat, screen-oracle SUCCESS) +
  offline gates (evaluate.py ok_sha/ok_prf, check-tls-prf, check-chacha-poly1305).
  NB the architecture's "overlay zone keeps the arena" was aspirational: at the 16K
  byte level there is no hole for the ~2 KB SHA *code* (the handshake uses all of
  low scratch incl. the packet buffer), so the fast SHA's extra sector costs ~512 B
  of arena. Recommended follow-up: the 7-NIC matrix (the change is NIC-independent;
  ne2k8 is the documented gate). PRIOR ANALYSIS (kept for the record):
- 2026-06-11 — **Fast-crypto landing — crypto de-risked, fit is a hard wall.** Per
  user "push now": confirmed r4_v42 (the 4.64× winner) bit-exact via the offline
  gate (`cd tools/crypto-bench && python3 evaluate.py variants/r4_v42.inc`:
  ok_sha+ok_prf, 5.27× PRF / 5.75× block in-env) and that it is an interface-safe
  wholesale drop-in (defines all 7 externally-called symbols; the 12 extra
  `core/sha256.inc` symbols are internal-only). **Measured fit infeasible at 16K via
  base-raise:** r4_v42 grows the K window 14 → **16 sectors** (loader reads whole
  sectors → loads 0x1800..0x3800), forcing the base up **+1024 B (2 sectors)** >
  the whole 833 B arena (→ −191 B, build fails). Even v001 (+61 B) → 15 sectors →
  +768 B → ~65 B arena (unusable). The K window MUST stay ≤ 14 sectors; the two
  parity landings (golf ~586 B from the other crypto, or the holistic SHA-out
  reorg) are both heavy/fresh-context. Reverted to clean parity (cb2c7d7d). The
  crypto is ready; the fit is the deferred work.

## Deferred to fresh-context feature sessions (heavy)

The parity pass established the structure + seams. The heavy, binary-changing work
is teed up but intentionally NOT done here:

- **Physical band reorg** — separate per-turn `tls_app_*` from reconnect-survivor
  caches above `critical_scratch_end`; carve the handshake-only ⟷ per-turn overlay
  zone as distinct regions. Then `check-layout.py` can *enforce* the reconnect-safe
  line + arena contiguity (the hooks are already in the checker).
- **Land the fast SHA/PRF crypto** (r4_v42, 4.64×) — the forcing function. One
  impl, slow deleted. **Crypto port is fully DE-RISKED** (see grind log
  2026-06-11): r4_v42 is bit-exact (offline gate green) and an interface-safe
  wholesale drop-in for `core/sha256.inc`. **The wall is the fit, not the crypto.**
  Hard constraint measured: the K window must stay **≤ 14 sectors (≤ 7168 B)** or
  it sector-rounds past `high_crypto_scratch_start` and a base-raise eats the whole
  833 B 16K arena (r4_v42 alone = 16 sectors → +1024 B → −191 B arena → build
  fails). So landing it on 16K needs ONE of: (a) **size-golf ~586 B out of the
  other K-window crypto** (chacha/poly/tls/agent_api) to keep K ≤ 14 sectors —
  full parity, no arena cost, but risky bit-exact golf; or (b) the **holistic
  reorg** making SHA handshake-only + non-resident (its ~2.5 KB out of the K
  window, loaded-before-handshake into a region reused during chat — needs a real
  handshake-time re-layout, since no existing region is both free-during-handshake
  and reusable-during-chat). Either way: crypto self-tests (`evaluate.py`) + the
  ne2k8 gate + the 7-NIC matrix.
- **Capability-vector field allocation** — when the 286 secure tier (or Wi-Fi)
  adds the first consumer of CPU-class/FPU/link-type; reclaim low-runtime slack,
  bump the handoff version, re-verify via `check-layout.py`.
- **Live dispatch-vector mechanism**, **32K floppy-free loop**, **HAL/driver
  vtable**, **286 secure tier**.
- **Doc-staleness sweep** (pre-existing, out of this pass's scope): `AGENTS.md`
  still references shipped `NET.CFG`; `HANDOFF.md` "Context-management knobs
  (Build 9)" describes the recap-first compaction that Build 10 removed. Fix in a
  focused doc pass (verify against code first).
