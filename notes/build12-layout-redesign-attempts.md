# Build 12 — Capability-Tiered Layout Redesign (attempts)

Branch context: Build 12 is the foundational RAM-layout redesign — make future
features / NICs / CPUs / crypto *additive* instead of byte-scrounging
(`docs/builds.md`). Build 11 shipped (tag `build-11`); its log is archived in
`notes/old/build11-hardening-attempts.md`. Work branch: `work/scaling`. The
design-of-record is `docs/architecture.md` (rewritten this build); the original
design charter (how we got here) is `notes/memory-layout-redesign-brief.md`.

Scope (user, locked 2026-06-11): **rearchitect for Build-11 feature PARITY** —
establish the structure (capability vector, lifetime-banded memory, single source
of truth, the dispatch seams) while behaviour stays exactly Build 11. The fast
crypto and the NIC HAL landed within this; the heavier features (32K floppy-free
loop, 286 secure tier) are deferred to fresh contexts.

Baseline (Build 11, `make inspect`): CORE.SYS 27648 B / 54 sectors; resident
nucleus 2048 B (2033 nonzero); K crypto window 14 sectors / 7168 B (0x1800..0x33f7,
**9 B slack** to the crypto scratch — the forcing function); 16K arena ~833 B.

## 2026-06-11 — increment 1: region/lifetime checker (O4/O7 seed)

`tools/check-layout.py` (commit `54f9d94`): parses `layout.inc` + `data.inc`
equates + the CORE.SYS header, prints the labeled lifetime-band map, asserts band
geometry + the intended-alias web + a phase-footprint backstop; wired into `make`.
Binary-identical (md5 `cb2c7d7d…` = Build-11 parity). It immediately caught the
drift fixed next.

## 2026-06-11 — increments 3+4: O7 range derivation + deepened checker

Commit `7d63d70`. The Makefile's inspect ranges now DERIVE from `layout.inc` via
`check-layout.py --emit` instead of hand-synced constants — caught + fixed a real
drift (`CRITICAL_SCRATCH_LEN` 2097 → the real 1229; the inspect budget had been
wrong since the Build-11 RX shrink). Checker deepened: reconnect-safe-line divider
in the map + the phase-footprint backstop. Binary-identical.

## 2026-06-11 — increment 2: capability-vector seam (doc)

Commit `09ab1fb`. `HANDOFF.md` documents the handoff as the capability vector:
RAM-tier + NIC-family live; CPU-class / FPU / link-type reserved. The struct is
full-packed (ends 0x2e, `low_runtime_state` packed to 0x0700), so field allocation
defers to the consuming feature session. Zero binary change.

## 2026-06-11 — fast SHA/PRF: de-risked, then the fit wall

`r4_v42` (the 4.64× spike winner) confirmed bit-exact via the offline gate
(`tools/crypto-bench/evaluate.py`: ok_sha + ok_prf) and an interface-safe wholesale
drop-in for `core/sha256.inc`. But measured: r4_v42 grows the K window 14 → 16
sectors, and the loader reads WHOLE sectors, so a base-raise needs +1024 B > the
entire 833 B arena (→ negative, build fails the floor). Conclusion: the K window
must stay ≤ 15 sectors for any fit; 14 (full arena parity) would need an infeasible
~586 B golf of byte-tight crypto.

## 2026-06-11 — fast SHA/PRF LANDED on 16K (r2_v25)

Commits `de49ffb`, `6c4787b`. Shipped `r2_v25` (4.33× PRF / 4.62× block,
bit-exact) — the fastest variant that fits 15 sectors with ZERO golf. r4_v42
(4.64×) NOT shipped: 16 sectors, needs a fragile 74 B golf for the last ~0.3× AND
lands the same arena — not worth the handshake risk. One impl everywhere.
Base-raise `high_crypto_scratch` 0x3400→0x3600 + `critical_scratch` 0x34c2→0x36c2;
16K arena 833 → 321 B (the cost of the +1 sector; functional — the conversation
window + boot/chat buffers are separate); 32K unaffected. The architecture-doc
"overlay keeps the arena" claim was aspirational — corrected to this honest reality
(at the 16K byte level there is no hole for the ~2 KB SHA code; the handshake uses
all of low scratch incl. the packet buffer). Validated: 16K `vm-net-ne2k8` via the
ROM BASIC sidecar reached the model greeting (full DHCP→DNS→TCP→TLS-handshake→
API→chat, screen-oracle SUCCESS) + offline gates (`evaluate.py`, `check-tls-prf`,
`check-chacha-poly1305`).

## 2026-06-11 — 7-NIC matrix: effectively 7/7

Commit `647625e`. First pass 6/7; 3c501 (ran first, before a stability ping) was a
lone clean-failure, then PASSED 3/3 on re-run with a clean ping (1004 replies, 0
drops) = a WIFI TRANSIENT (spotty link), NOT the fast SHA and NOT a 3c501 timing
interaction. Fast SHA validated across all 7 NIC families.

## 2026-06-11 — band reorg: enforce the reconnect-safe line (checker-only)

Commit `93afc55`. The layout already physically realizes the lifetime-band model
(Builds 9–11 evolved it: per-turn `tls_app_*` sits below the reconnect-survivor
caches, survivors contiguous, context + arena on top). So the "physical reorg" was
checker-only: draw the reconnect-safe line at the true survivor boundary
(`chat_model_cache` / 0x3b9c, not `critical_scratch_end`) and make `check-layout.py`
ENFORCE it — survivor-pool contiguity + no survivor stranded below the line.
CORE.SYS byte-identical. `tls_retransmit_seq` + `chat_effective_cap` (transients
homed in the reconnect_state block for headroom) are declared accepted-exceptions:
16K has no room below the line to rehome them, and they're rewritten before use.

## 2026-06-11 — NIC HAL vtable / dispatch-vector LANDED (increments A/B/C/D)

Commits `f65f46d` (A: stand up + enter/restore/rx_fallback), `c8867a4` (B: TX),
`7cd9492` (C: RX), `daddaf5` (D: populate-coverage build guard). Converted the
NIC-family runtime branching in the resident network path into a boot-populated
dispatch-vector: a 5-slot vtable (`nic_vt_enter / restore / transmit / receive /
rx_fallback`) filled once by `populate_nic_vtable` in hardware_setup (after the
family is final), then the resident hot path does `call [nic_vt_*]` with no
`cmp [nic_family]`. **7-NIC matrix 7/7 PASS after EACH increment**; Build-11 parity.

Two refinements vs the original plan: (1) the table lives RESIDENT in the nucleus,
not low memory — the conversions free more than the 10 B table costs, so the
nucleus went 2033 → 2002 B at ZERO arena cost, and it survives reconnect for free;
(2) the inner NE-family buffer load/read sub-dispatch (wd-sharedmem / 3c503-chipmem
/ remote-DMA) was left a direct branch — it's the NE driver's own DP8390 access
taxonomy, not a separate driver (high DMA-timing risk, ~zero additivity).
`handoff_nic_family` stays the source of truth for the cold-phase flight-order /
pacing / display reads. One register subtlety: `el1_transmit_frame` (3c501), now
reached directly via the slot, establishes `bp = len` from `cx` itself. NB
`make all` does NOT build the BASIC sidecars — run `make basic-bootstrap` before a
`--no-build` matrix.

## Remaining (deferred to fresh-context sessions)

- **32K floppy-free chat loop** — preload the loop's phases + IDENTITY/COMPACT
  prompts at boot on 32 KiB; demand-load stays the 16 KiB path. The dispatch-vector
  seam + the band model are ready.
- **286 secure tier** — the orthogonal CPU-class capability; carries the 286@8+
  secure objective + the "full-286 needs a further crypto-opt pass" gate.
- **Floppy-loaded NIC driver modules** — a bounded resident active-driver slot.
  Today every family's driver is resident; the HAL vtable made *dispatch* additive,
  but inactive drivers don't yet cost zero RAM.
- **Capability-vector field allocation** — when the first consumer (286 / Wi-Fi)
  needs CPU-class / FPU / link-type; reclaim low-runtime slack, bump the handoff
  version, re-verify via `check-layout.py`.
- **Doc-staleness sweep** — `AGENTS.md` still references shipped `NET.CFG`;
  `HANDOFF.md` "Context-management knobs (Build 9)" describes the recap-first
  compaction Build 10 removed. Verify against code first.

Build 12 lives on `work/scaling`, NOT pushed. The release (fast-forward `main`,
annotated tag `build-12`, per `AGENTS.md`) is the user's single push when satisfied.
