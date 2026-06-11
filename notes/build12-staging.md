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
