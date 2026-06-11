# Build 12 — NIC HAL vtable (dispatch-vector) handover

Self-contained brief for a **fresh session** to execute the NIC HAL / dispatch-vector
refactor. Read this + `docs/architecture.md` ("The One-Artifact Relocation Model")
+ `notes/build12-staging.md`. The prior session mapped the dispatch and the design
but deliberately did **not** execute it (high-risk, breaks-cards-if-wrong, and that
session was very deep — see "Why fresh").

## Goal

Convert the NIC-family runtime branching into a **boot-populated HAL vtable**: the
active adapter's per-family operations are written into a small fixed table once at
boot (after family detection), and the resident network path calls them
**indirectly** through the table instead of `cmp [nic_family] / je`. This is the
architecture's "active NIC driver" dispatch-vector consumer and the O5 HAL.

**Value:** makes new NIC families *additive* — a new card is a new driver module +
a vtable fill, with no new branches woven into the hot path (the user's stated
AT-world need: "way more NIC drivers"). It is also the near→far seam for a future
>64 KiB tier (the vector becomes a far pointer without touching call sites).

**Honest caveat:** this is a **structural/seam refactor — no parity behavior
change.** The current "default NE-family path + special-case overrides" already
works for all 5 families (7/7 matrix). The payoff is future additivity, not a
behavior win. Weigh that against the risk; it's why the prior session flagged it as
the one piece to do fresh rather than rush.

## Why fresh (the risk profile — different from the band reorg)

- **Breaks-cards-if-wrong.** A mistake in extracting the el1(3c501)/wd8003/3c503
  override code = a dead NIC, caught only by the full 7-NIC matrix (currently 7/7).
- **Nucleus is FULL** (2033/2048 B, ~15 B free). The conversion must be
  nucleus-neutral-or-positive: removing `cmp/je` branches frees bytes; the vtable
  DATA must live in low memory (not the nucleus); the population must live in the
  `packet_io_init` phase (not resident). `check-layout.py` + the `core.asm` `%error`
  guards enforce the nucleus cap — keep them green.
- **Pervasive + atomic-ish.** ~15 conversion sites across ~1,300 lines; a
  half-converted tree is a broken tree. Convert one op at a time, matrix-validate,
  commit only green.

## Current state (read first)

- Branch: **`work/scaling`**. Build 12 = 11 commits (`b4fed6f..` the HAL-handover
  commit), **NOT pushed** (single push at the end, user does it).
- Build 12 already landed: capability-tiered architecture rewrite; the
  region/lifetime checker (`tools/check-layout.py`, wired into `make`); O7 range
  derivation; the fast SHA/PRF on 16K (`r2_v25`, ~4.3×, validated 7/7); the enforced
  reconnect-safe-line band model.
- **Layout note (post fast-SHA base-raise):** `high_crypto_scratch_start = 0x3600`,
  `critical_scratch_start = 0x36c2`, K window = 15 sectors, 16K arena = 321 B.
- The dispatch-vector's *other* consumers (32K floppy-free-loop phase preload, 286
  secure crypto path) are FUTURE features — do NOT build vector slots for them now
  (YAGNI). The NIC family is the only parity consumer.

## The dispatch map (what the prior session read + verified)

Family constants (`layout.inc`): `family_3c503=1, ne2000=2, ne1000=3, 3c501=4,
wd8003=5`. The **NE-family (ne2000/ne1000/novell-ne1k) is the default path**;
**3c501 (el1_*), 3c503 (el2_*), wd8003 (DP8390-windowed)** are the special cases.

The ~15 family-branch sites (the rest of the 62 grep hits are `family_*`/`el1_*`/
`el2_*` *constant* uses, not dispatch):

- **`core/nic.inc`** (READ): `wd_enter_packet_path` / `wd_restore_dp8390_base` —
  wd8003 only, add/sub `wd_dp8390_offset` to `nic_base` (window the DP8390). Others
  are no-ops. Called from `net_phase` around the packet path. *(Smallest, cleanest,
  self-contained — good first conversion.)* Also here: `c503_select_dp8390`,
  `out_dx_word`, `scroll_text_area` (shared helpers, not family dispatch).
- **`core/net_tx.inc`** (READ): `ne_transmit_frame` branches:
  `3c501 → el1_transmit_frame` (a *fully separate* transmit, lines 128-167);
  `wd8003 → wd_write_sharedmem_bytes`; `3c503 → c503_write_chipmem_bytes`;
  `else → PIO remote-DMA`; then a shared `.frame_loaded` trigger (wd/3c503/NE).
  So TX = a top-level `el1 vs NE-family` split + a `wd/3c503/NE` buffer-load
  sub-split. Vtable surface: `load_tx_frame` (per family) + keep the shared trigger;
  el1 is a full `transmit_frame` override.
- **`core/transport.inc`** (READ): `tcp_parse_3c501_second_frame` /
  `tcp_3c501_drop_first_frame` — 3c501 single-buffer quirk (drop a stale frame,
  parse a second). Called from `tcp_receive_payload`. 3c501 only. *(Self-contained —
  good early conversion.)*
- **`core/net_rx.inc`** (NOT fully read — 411 lines; READ IT): family branches at
  lines ~2 (3c501), ~253 (wd8003), ~260 (3c503). The RX read/poll override surface.
- **`phases/packet_io_init.inc`** (NOT fully read — 231 lines; READ IT): ~6 family
  branches (the per-family hardware init: rings, DMA, start/stop pages). This is
  **where the vtable gets POPULATED** (runs after `hal_detect` sets the family).
  It's a **1-sector phase** — the `%error "packet IO init phase exceeds one sector"`
  guard is the budget; adding population may need golfing it.
- Detection (sets the family, no dispatch to convert): `core/hal_detect.inc`
  (`probe_network_card → resolve_network_config → autodetect_io_280 / autodetect_ne`)
  writes `handoff_nic_family`. The vtable is populated *after* this.

## Vtable design (proposed — refine as you read net_rx + packet_io_init)

- **Slots** (per-family function pointers): `load_tx_frame`, `transmit_frame`
  (el1 overrides this; NE-family points at the shared path), `read_rx_frame`,
  `init`, `enter_packet` / `restore_base`, `rx_fallback` (3c501 second-frame).
  ~6-8 words.
- **Where the table lives** — the key constraint. Low runtime/persistent state is
  FULL to `0x0700` (`low_runtime_state_end == 0x0700`), so there's no room there.
  The vtable is set-once-at-boot and survives the session (incl. reconnect — a
  reconnect doesn't re-detect), so it's a reconnect-survivor: candidates are the
  **reconnect_state pool headroom** (above the line, where `tls_retransmit_seq` /
  `chat_effective_cap` already live as accepted strays) or growing the handoff
  (but that shifts `low_runtime_state` — avoid). Decide + assert with
  `check-layout.py`.
- **Population:** in `packet_io_init`, after detection, a single per-family dispatch
  that writes the active family's pointers into the slots. NE-family → the default
  impls; 3c501/wd8003/3c503 → their overrides. This is the *one* remaining
  `cmp family` site (acceptable — it runs once).
- **Call-site conversion:** replace each resident `cmp [nic_family] / je <override>`
  with `call [nic_vtable + SLOT]`. Net nucleus impact ≈ neutral-to-positive.

## Incremental plan (matrix-green each step, never commit broken)

1. Stand up the vtable (table + the population skeleton in `packet_io_init`) and
   convert the **smallest self-contained op first**: `enter_packet`/`restore_base`
   (nic.inc) + the `3c501 second-frame` (transport.inc). Build + 7-NIC matrix. Commit.
2. Convert **TX** (`load_tx_frame` + el1 `transmit_frame` override). Matrix. Commit.
3. Convert **RX** (`read_rx_frame`). Matrix. Commit.
4. Convert **init** (the `packet_io_init` per-family setup). Matrix. Commit.
5. Optionally: extend `check-layout.py` to assert the vtable region + that every
   slot is populated.

## Validation

- `make` runs `core-sys-info --check` + `check-layout.py` (keep both green; watch
  the nucleus cap + the `packet_io_init` one-sector guard).
- **7-NIC matrix:** `python3 tools/run-basic-bootstrap-matrix.py --no-build`
  (~14 min serial; the 16K BASIC sidecar path). **3c501 is the flakiest** (single
  buffer) — a transient/wifi blip reads as `agent setup failed`; re-run a failed
  card ×3 (`--profiles vm-net-3c501 --repeat 3`) before treating it as real. A
  background `ping` overlay helps separate wifi from regression (see the prior
  session's method in `build12-staging.md`).
- `pkill -f 86Box` before any canary (one VM at a time / auto-typing).

## References

- `docs/architecture.md` — "The One-Artifact Relocation Model" (the vtable + near→far
  seam), "Memory Shape" (the bands + the reconnect-safe line).
- `notes/build12-staging.md` — the full Build-12 grind log + the matrix method.
- `tools/check-layout.py` — the single-source layout checker (band map, alias web,
  phase footprints, reconnect-safe-line enforcement).
