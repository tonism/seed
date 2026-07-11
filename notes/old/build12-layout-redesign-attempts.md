# Build 12 — Capability-Tiered Layout Redesign (attempts)

Branch context: Build 12 is the foundational RAM-layout redesign — make future
features / NICs / CPUs / crypto *additive* instead of byte-scrounging
(`docs/builds.md`). Build 11 shipped (tag `build-11`); its log is archived in
`notes/old/build11-hardening-attempts.md`. Work branch: `work/scaling`. The
design-of-record is `docs/architecture.md` (rewritten this build); the original
design charter (how we got here) is `notes/old/memory-layout-redesign-brief.md`.

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

## 2026-06-11 — floppy-loaded NIC driver modules (0 RAM for inactive) — LANDED 2026-06-12

User directive: follow the architecture's full HAL — inactive drivers must cost
**zero resident RAM**. So the per-family hot-path code moves OFF the nucleus onto the
floppy as self-contained driver modules; only the detected family's driver is loaded
into a bounded **resident active-driver slot** at boot.

Measured (this tree): per-family NIC code = **915 B** resident; shared NIC code = 588 B;
non-NIC resident ≈ 498 B. Driver-size estimates (self-contained): ne ~377, wd ~357,
3c503 ~426, 3c501 ~262 B — all < 512.

**Binding constraint → forced big-bang.** All current NIC code (1504 B) + a slot can't
coexist in the 4-sector (2048 B) nucleus, and the DP8390 ring is shared by ne/wd/3c503,
so there's no intermediate state that both fits 16K and isn't broken. The slot only
fits once the per-family code is removed → all families migrate at once. (A 2-driver
"dp8390+el1" shortcut needs a 1024 B/2-sector slot → 5 sectors → breaks 16K, so the
faithful 4-driver design is also the only one that fits.) De-risk: build-green
sub-steps + faithful relocation (driver code == current instructions) + the full 7-NIC
matrix before commit; never commit broken.

**Design.**
- `nic_driver_slot` = 0x1600..0x1800 (the 4th nucleus sector). Shared resident code
  shrinks to 3 sectors; K window stays at 0x1800 → **no arena/crypto disruption**.
- 4 driver modules (floppy phases, load at the slot): `ne` (ne1000/ne2000/novell),
  `wd8003`, `3c503`, `3c501`. DP8390 ring = a shared macro source (`%%` locals,
  buf-leaf as a macro param) emitted into ne/wd/3c503; 3c501 is fully custom.
- ABI: a driver runs at the slot (like a phase) — internal calls relative, resident
  calls (out_dx_word / net_fail_al / parse_tcp_payload) via a slot-aware `drv_call_res`
  (the established `phase_call_res` idiom, base = `nic_driver_slot`). First 10 bytes =
  a header of the 5 `nic_vt_*` entries (slot-relative for own ops, resident addr for
  shared defaults nic_noop / nic_rx_fallback_none).
- Boot (hardware_setup, after detection, before the crypto race): `load_core_sectors_at`
  the active driver's sectors into the slot, then copy its 10-byte header into the
  resident `nic_vtable`. Replaces `populate_nic_vtable`.
- The resident hot path is unchanged — it already does `call [nic_vt_*]`; the entries
  now point into the slot instead of the nucleus.

**Result — LANDED, 7/7.** The shared resident code dropped from **2002 B → 1095 B** (the
915 B of per-family code is now 4 floppy driver modules, one sector each; ne ~310, wd
~310, 3c503 ~448, 3c501 ~350 B, all < the 512 B slot). Resident image stays 4 sectors
(3 shared + the slot); CORE.SYS grew 55 → 59 sectors (the 4 driver sectors, on the
floppy). On any given machine only the detected family's driver is resident — e.g. a
3c501 box carries ~350 B in the slot, not the other ~565 B — so **inactive drivers cost
0 resident RAM**, exactly the architecture's HAL. K window unchanged at 0x1800; 16K arena
untouched. `check-layout.py` gained an active-driver-slot band + a driver-header guard
(every driver module must begin with nic_vt_slot_count `dw` entries). Validated: a single
ne2k8 canary first (proved slot-load + vtable-from-header + the ring + drv_call_res),
then the full **7-NIC matrix 7/7 PASS** (~134 s each, full boot → handshake → greeting),
covering all four drivers — el1 (3c501, fully custom), 3c503 (chip-mem + gate array), ne
(ne1k/ne2k8/novell remote-DMA), wd (wd8003e/eb windowing + shared mem). 3c501 passed
first try (no flake). The big-bang was forced by the byte budget but de-risked via a
faithful relocation (driver code == the prior resident instructions) + build-green
sub-steps + the matrix; never committed broken.

This realizes the architecture's HAL vision for NIC families. What is still future: the
slot is sized at one sector (512 B) for the current worst-case driver (3c503 ~448 B) —
a larger future driver (or Wi-Fi, which also wants scan/SSID UI phases + WPA crypto in
the handshake-only band) may need a 2-sector slot, which on 16K would cost arena (the
sizing seam the architecture flagged).

## 2026-06-12 — 32K floppy-free chat loop — LANDED, fully floppy-free (incr 1+2+3)

User: do the full preload incl. K; bigger floppy-free win over a bigger arena.

**LANDED (incr 1 `8203f78` + the combined K+prompt commit below, NOT pushed).** On a 32K direct boot
the chat-loop working set is preloaded into a high RAM cache (loop_cache 0x4400..0x7a00, above the
window/arena, below the stack guard); on 16K the tier-gate is off and the loop demand-loads as before.
- **Phases** (dpi/Y, agent_request/R, agent_api_stream/X, agent_response/T, tool/M, AND the 15-sector
  K crypto window): `load_core_sectors_at` serves them from RAM by a key match (sectors<<8|offset),
  the loop's own loads hit by construction. K (reloaded every turn to restore 0x1800 after a $x) now
  memcpy's the pristine cache copy — the dominant cost, gone.
- **Prompts** (IDENTITY/COMPACT, streamed per request via the fs cluster path): pinned in two fixed
  top-of-cache slots; a resident `agent_resolve_prompt_source` returns the slot to the stream phase
  (ax IS the cluster being checked, so a 32K hit is guaranteed). Preloaded AFTER agents_cfg sets the
  clusters (so the preload call moved from hal_start to after prepare_agent_path).
- **Per-turn floppy I/O: ~25 sectors → 0** — the 32K loop is fully floppy-free. Cost: window/arena
  capped below the cache (32K arena ~321 B band shown on the 16K map; the 32K window/arena ~2 KB) and
  the ledger advertises loop_cache_start as ram= so the agent can't $w the cache. Nucleus 1095→1322 B
  (3 shared sectors; K window + driver slot unmoved).

**Lesson — a broken intermediate I caught at incr 3.** The incr-2 "fits the cache" build assert was a
`%if` over the phase labels placed near the TOP of core.asm — but `%if` can't forward-reference labels,
so incr-2 (`8ce6ac9`) actually FAILED to build. My validation command filtered the make output, so I
missed the error; `make basic-bootstrap` then fell back to the stale incr-1 floppy and "validated" K
against a build that didn't have it. Fixes: (1) the assert moved to the END of core.asm (backward ref);
(2) always read the FULL build output, never a keyword-filtered grep; (3) confirm the floppy md5 is
fresh before trusting a run. The branch was unpushed, so the broken `8ce6ac9` + its doc commit were
`reset --soft`'d away and K+prompts re-committed as one clean, building, properly-validated commit.

Validated (the FINAL build, md5-confirmed fresh): 32K direct boot, **2 turns**, verdict=success — the
TLS crypto ran from cache-loaded K and the identity streamed from cache each turn; + full **7-NIC 16K
matrix** (no regression — the preload is 32K-gated). docs/architecture.md Floppy Policy updated. (A
dedicated 32K matrix profile is still a nice-to-have; the ne2k8 direct-boot run is the gate today.)

Per-turn floppy reads today (BOTH tiers identically — no tier branch exists; ram_top
only sizes the window): dpi/Y(1) + agent_request/R(3) + **K window(15)** +
agent_api_stream/X(3) + agent_response/T(1) + tool/M(2) = ~25 sectors. K dominates;
it reloads every turn because the `$x` tool phase can run arbitrary code into the K
window (0x1800). All reads funnel through ONE routine, `load_core_sectors_at` (every
`call_core_phase` / `load_core_window` / phase-internal load).

**Design (one seam).** Intercept `load_core_sectors_at`: scan a small table; on a hit,
`rep movsw` from a high RAM cache; else read the floppy. At boot on 32K, a preload step
reads the working-set phases into the cache (reusing `load_core_sectors_at` with the
table count = 0, so it floppy-fills) and sets the count; on 16K the preload never runs,
the table stays empty, and every load hits the floppy (unchanged). No per-call-site
changes. Tier gate = `ram_top >= ram_tier_32k_min (0x6000)`.

**Layout.** Cache = `loop_cache_start (0x4600) .. loop_cache_end (0x7a00 = stack-guard
floor)`, 26-sector cap (working set is 25). It sits ABOVE the conversation window/arena
and BELOW the runtime stack guard, and is 32K-only (on 16K ram_top=0x4000 < 0x4600, so
the region doesn't exist and the preload is skipped). hardware_setup caps the
window/arena ceiling at `loop_cache_start` on 32K (instead of ram_top). 32K arena
becomes ~2.2 KB (~5x the 16K arena) — the cost of preloading the full set incl. K.

**The one subtle trap — the ledger arena ceiling.** The ledger advertises
`ram=<ram_top>` and tells the model the arena spans `a@ .. (ram − stack reserve)`. The
cache sits INSIDE that range, so the model would treat it as free and could `$w` into
it, corrupting a preloaded phase → crash on the next load. Fix: on 32K advertise the
CAPPED ceiling (`loop_cache_start`) as `ram=` so the model never reaches the cache. A
32K smoke test (boot + chat) does NOT exercise this (a normal turn doesn't `$w`), so it
must be handled by design, not caught by validation.

**Increments (matrix-green each; never commit broken):** (1) mechanism + small phases
(Y/R/X/T/M) + window-sizing + ledger-ceiling; validate 16K matrix (no regression, the
code is 32K-gated) + a 32K direct-boot smoke (`--entry direct --ram-kib 32`). (2) add K
to the preload (cache already sized for it). (3) IDENTITY/COMPACT preload + docs + a 32K
matrix profile. Validation note: the 16K matrix only proves no-regression (the path is
32K-only); the 32K direct-boot run is the real gate.

## 2-image build (160K + 360K) + one-CORE.SYS geometry auto-detect

**Decision (user):** ship TWO floppy images — the 160K single-sided (the 1981 IBM PC
5150 weakest-config headline) AND a 360K double-sided (the 286: the AT's 1.2 MB drive
rejects the single-sided 160K geometry). Same CORE.SYS in both. The "one artifact"
principle bends to "one runtime, two image containers" so the 1981 config stays headline.

**Build (the boot chain is parametric).** `boot.asm` + `loader.asm` geometry (BPB
total/spt/heads/media + the loader's LBA→CHS) parameterised via NASM `%define`s defaulting
to 160K (`FLOPPY_TOTAL_SECTORS=320 / SPT=8 / HEADS=1 / MEDIA=0xfc`); the 360K target
overrides them (`720 / 9 / 2 / 0xfd`). `build-fat12-image.py` gained `--total-sectors` +
`--media` (default 160K). The Makefile builds both (`floppy-160k.img` + `floppy-360k.img`,
via `boot-360k.bin`/`loader-360k.bin` with `NASM_FLAGS_360K`); `all` makes both. Lowest-risk
design: the 360K reuses the EXACT 160K FAT12 internal layout (data at LBA 11, 1 FAT sector,
64 root entries) — only the physical geometry the AT needs changes; the dual-head LBA→CHS
(`%if FLOPPY_HEADS>1`) reduces to the byte-identical head-0 path when heads=1. VERIFIED:
the 160K artifacts (boot.bin/loader.bin/floppy-160k.img) are byte-for-byte the baseline.

**The bug the 286 surfaced — CORE.SYS is ONE binary, two geometries.** The boot sector +
loader were geometry-parametric, but CORE.SYS's OWN on-demand phase loader
(`core/fs.inc read_abs_sector`) hardcoded `mov cl,8 / div cl` + `xor dh,dh` (160K, single
head). On the 360K it computed the wrong CHS for every phase read → garbage phase →
black-screen hang on the 286 (floppy LED active = it WAS reading, just the wrong sectors).
The crypto-bench booted the 286 because `bench_boot.asm` is single-stage (loads everything
up front, no on-demand reads) — the user's pointer to "lend ideas from there" cracked it.
Fix (the architecturally-right one, per the user "same seed.sys works on 160K or 360K"):
the nucleus AUTO-DETECTS its geometry at startup. `detect_floppy_geometry` (called from
the nucleus entry, before the first phase load) reads the boot sector (LBA 0 = CHS 0/0/1,
which is geometry-independent) and adopts its BPB spt (offset 0x18) + heads (0x1a);
`read_abs_sector` uses those runtime values. Works on 160K (8/1), 360K (9/2), and the
BASIC-sidecar path alike — one CORE.SYS, any floppy, no build-time geometry baked in.
Resident nucleus stays 4 sectors (the routine fits the existing free space, check-layout OK).

**Failure-screen spacing (user).** `failure_action.inc` typed the error message at
`seed_col+1`, adjacent to the load marker → `.no network card`. Bumped to `seed_col+2` →
`. no network card` (a blank column after the marker, now aligned with retry/restart).

**286 test harness (new, reusable).** `tools/run-286-86box.py` boots a Seed image on
86Box's `ibmat` (286) with a crafted CMOS (360K floppy A, 512K base, CGA, no FPU) at a
chosen MHz and screenshots the window. Reuses the crypto-bench's `run86box.py`
launch/screenshot + `at286_ladder.py`'s CMOS. Default 6 MHz = the security clock.

**Validated.** 360K boots on the 286 @16 MHz → Seed runs its phases to `. no network card`
(no NIC in this minimal config). 8088/16K regression (ne2k8, full ROM-BASIC → network →
DHCP → TLS → chat) PASS verdict=success — the fix is NIC-independent (floppy geometry +
failure-screen text), so the full 7-NIC matrix was skipped (user). Build green (resident 4
sectors, check-layout OK).

## Remaining (deferred to fresh-context sessions)
- **286 secure tier — real crypto** — the harness now boots Seed on the 286 (above), so
  this is unblocked: land the optimised real P-256 ECDHE + RSA-2048 cert-chain verify +
  entropy, 286-gated on `handoff_flag_cpu_286plus`, fitting the ~15 s window. Test policy:
  6 MHz 286 + always the 4.77 MHz 8088/16K regression. Follow-up record: the later
  "286 secure tier" entries in this file plus `auto-recertify-attempts.md`.
- **"insecure" splash warning** — once secure crypto ships, a dim "insecure" on the
  splash's 2nd line (right-aligned with "seed build 12") for pre-286 machines (gate on
  `handoff_flag_cpu_286plus` clear).
- **Capability-vector field allocation** — when the first consumer needs a richer CPU
  class / FPU / link-type; reclaim low-runtime slack, bump the handoff version, re-verify.
- **Doc-staleness sweep (partly done)** — `NET.CFG` refs removed from `config.md` +
  `AGENTS.md` (commit e4f82de). STILL pending: `HANDOFF.md` struct version (now 4) + the
  new flags bits (0x0010 CPU, 0x0020 FPU) + the stale "Context-management knobs (Build 9)"
  recap section + its `NET.CFG`/port-80 network narrative; regenerate `docs/memory.md`.

## 286 secure tier — increment A LANDED (real ECDHE), 2026-06-14

Provider list first stripped to OpenAI-only (commit 584ef80): the others were never wired end
to end (agent_request builds only `/v1/responses`); AGENTS.CFG + the dead host switch + the
built-in fallback IDs all cut.

**Increment A — real ECDHE key agreement (commit c87a411), VALIDATED END TO END @286@6.**
- **Module mechanism.** `core/p256.inc` makes thousands of absolute self-references, so it
  can't use the per-label PHASE_BASE fixup small phases use. Solved by assembling it as its OWN
  flat binary at its run address — `core/p256_module.asm` (`org p256_module_load`) +
  `core/p256_data.inc` — `incbin`'d into CORE.SYS (Makefile rule + a core.asm incbin AFTER the
  NIC drivers, so existing phase/driver offsets are unchanged; resident bytes byte-identical bar
  the header total-sectors field). 14 sectors. Loaded ONLY on the 286 path into a high band
  aliasing the 32K loop cache (lifetime-disjoint; 16K never loads it -> 0 resident RAM).
  Code+data all at 0x4400+ -> LANDMINE #4 holds by construction. ABI = an entry-point-only
  near-POINTER word table at the module base (NOT a jmp table -- `jmp near` shortens to short and
  broke the fixed stride); resident calls in via `call word [p256_ep_*]`.
- **Wiring (286-gated):** L phase mixes a real entropy pool (LCG random + MAC + BIOS tick + PIT
  phase) -> SHA-256 -> client scalar (never 1/2 -> LANDMINE #3 holds), then client_public =
  scalar x G PRE-CONNECT (outside the server window). CKE sends real client_public (8088: fixed
  G); SKE parser hands the server point to the module (8088: X-passthrough); premaster =
  client_private x server_public, computed after the CKE is on the wire, before the PRF.
- **286-network blocker (separate fix, commit 42f47b5).** The 286 harness never had a NIC;
  adding ne2k8/SLiRP, the boot died "network setup failed 01/01". A temporary on-screen hex dump
  showed base=**0x320**, family=0, flags=0x0012 (cpu_286plus + nic_present, NO mac_valid). Root
  cause: `resolve_network_config` dispatched ONLY base 0x300 to the NE path, but
  `hardware_nic_ports` probes 0x300..0x3a0 -- a NIC above 0x300 was found yet left unresolved.
  Fix: `jae 0x300` (8088-safe). After it the dump read 0x320 / 02 / 001E (all flags set).
- **Validation:** check-p256.py + `p256_eval.py --full` (scalar_mult==PEER_PUBLIC, unicorn);
  8088 16K ne2k8 greets (secure gated off, no regression); **286 @6 MHz completes the full
  real-ECDHE handshake and greets** -- the server accepted our Finished => keys matched => a
  correct premaster => bidirectional key agreement. Channel now has REAL key agreement; cert
  AUTH is increment B (confidential-but-unauthenticated until then).

## 286 secure tier — COMPLETE (B/C/D landed), 2026-06-14

**Trust model RE-DECIDED with the user once the real chain was in hand.** api.openai.com's leaf
is RSA-2048 but issued by Google Trust Services WR1 (RSA-2048 intermediate) under an RSA-4096 root
(too slow to chain to) with ~90-day leaves. Each RSA-2048 verify is ~6.4s@6 / ~4.8s@8; the
mandatory ServerKeyExchange-signature verify is already 1. Chaining to WR1 (2 verifies) needs
~12 MHz; so the user chose **PIN THE LEAF KEY** (1 verify -> fits the 6 MHz window / the FINDINGS
budget). Real cert auth (possession proof of the pinned key); brittle to leaf rotation (re-pin).

**B — RSA cert authentication (commit 4e330a6).** tools/gen-rsa-pinned-key.py bakes the leaf
modulus + Montgomery params (generator self-tested vs the bench, ck=54F2) into core/rsa_pinned_key.inc
(documents subject/issuer/dates/SHA-256 fingerprint; re-pin on rotation). The module gained the bench
RSA modexp (core/rsa_verify.inc) + p256_ep_verify_ske_sig: reconstruct the FULL EMSA-PKCS1-v1.5
block + whole-256-byte memcmp (no lax parsing -> forgery-resistant). 286 ClientHello (patched
pre-build) offers ECDHE_RSA (0xcca8) + only rsa_pkcs1_sha256; the ServerHello cipher-accept folds
0xcca8/0xcca9 with one masked compare (8088-harmless). The SKE parser (286-gated) requires
{sha256,rsa,256-byte sig}, hashes client_random||server_random||ServerECDHParams (save/restore the
transcript SHA), verifies vs the pinned key BEFORE the CKE/premaster; a mismatch fails the handshake.
**DEBUG TRAIL (the cipher switch broke the handshake before the verify):** a verify-stub + temp
net_status milestones localized it -- net_status stuck at tcp_connected (18) => failed in
tls_wait_for_server_hello, where `cmp word [di],0xa9cc` rejected the server's 0xcca8 echo. The
masked accept fixed it; then the stubbed handshake greeted (cipher/cert/SKE/premaster all OK with
the bigger RSA chain), so only the verify needed unstubbing + a K-window fit (15 sectors, no slack
-> golfed a redundant `mov di` + the masked accept). Also surfaced: the RSA Certificate message is
~4 KB (3 certs) vs the smaller ECDSA chain, but Seed's streaming cert drain handles it fine.

**C — module layout (commit 868b4c6).** check-layout.py now models the 286 module band
(0x4400..0x7400, overlays the 32K loop cache, 0 RAM on 16K) + asserts it stays above the critical
scratch (no 0x0700/0x36c2 alias) and within the loop cache. Reconnect safety: the secure-prep zeroes
loop_cache_count when it loads the module (the module clobbers the cached chat phases on a mid-chat
reconnect) -> later phase loads demand-read the floppy; no-op on the boot path.

**D — pre-286 "insecure" splash (commit f2a2b7e).** A dim "insecure" on the splash's 2nd line,
right-aligned under "seed build NN", shown only when handoff_flag_cpu_286plus is CLEAR (8088).

**VALIDATED end to end (the networked 286 harness made this real):**
- 286 @8 MHz: ACCEPTS OpenAI's real signature and greets (authenticated handshake); a 1-bit-tampered
  pinned modulus REJECTS it (handshake fails) -> the pin is enforced. No "insecure" on the splash.
- 286 @6 MHz: greets too -- the FULL secure handshake (ECDHE + RSA cert auth + PRF) fits the lowest
  6 MHz 286. "Security begins at the 286" holds; per FINDINGS @6 is a ~1.2s-slack knife-edge (may
  flake), @8 the comfortable floor.
- 8088 16K (ne2k8): greets (secure gated off, no regression) and shows the dim "insecure".
- Offline: check-p256.py + rsa_eval.py (modexp) + the generator self-test.

NOTE: api.openai.com's leaf is GTS-issued (NOT Cloudflare as the handover assumed; the 172.66/
162.159 IPs are a Cloudflare front, but the cert chain is GTS). The pinned leaf is valid ->
2026-08-08; re-pin with tools/gen-rsa-pinned-key.py before then.

Build 12 lives on `work/scaling`, NOT pushed. The release (fast-forward `main`,
annotated tag `build-12`, per `AGENTS.md`) is the user's single push when satisfied.
