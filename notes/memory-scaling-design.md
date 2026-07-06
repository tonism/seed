# Memory Scaling — Beyond Segment 0 (design / charter)

> STATUS (2026-07-05): **Milestones 1 + 2 SHIPPED in Build 12** — far seg:off `$r/$w/$x` to conventional
> memory (M1), and the 256K+ LIM-EMS arena-first inversion (arena takes all conventional; context relocates
> to the top of EMS, streamed via the 64K page frame with 16K bank-switching) + the 32K+ cached chat
> loop (M2). Reader-facing summary is in `docs/builds.md`. **The remaining Build 12 work is 286/HMA
> native extended memory and 386+ unreal mode** so context/arena scale past the EMS page-frame window —
> see the tier sections below. Build 13 is reserved for TLS 1.3 and the 64-bit/no-BIOS runtime.

The settled design for letting seed's agent address far more than the 64 KiB of segment 0 — the
goal being "address absolutely any size": ~640 KB on an XT, megabytes on an EMS box, 16 MB on a 286,
4 GB on a 386+, and (Build 13) terabytes on a 64-bit host. This is the build-against reference;
when tiers ship, the load-bearing parts graduate into docs/architecture.md.

## The idea

seed itself stays exactly where it is: **the resident runtime lives in low segment 0** (nucleus,
crypto window, request buffers, the per-turn phase loader). What grows is the **agent-facing memory**:
the conversation **window** (context) and the **arena** (the agent's write/execute workspace). The agent
sees **one flat linear address space** of an advertised size and never has to know how it is
physically reached — seed's memory-HAL translates a flat address into the machine's real access
mechanism, per capability tier. Same shape as the existing RAM / CPU / writable-media tiers.

## What scales, and the split policy

- **window + arena scale together, 50/50**, as detected memory grows...
- ...**until the window reaches a 1 MB cap**; beyond that the window stays 1 MB and **all surplus
  goes to the arena**. (1 MB of context ~ a large-model context window; past that, more local
  scratch is the better use.)
- A window past 64 KB lives **outside segment 0**, so it uses the *same* extended-access path as the
  arena, and building a request **streams the context out of far/extended memory through seg 0 into
  TLS** (the request path is already chunked — this is "stream from far memory", not new transport).
- seed's seg-0 footprint (nucleus + crypto + buffers) is reserved first; the agent's conventional
  arena is what's left of conventional memory below it/around it.

## The flat-address abstraction

- Native `read_mem` / `write_mem` / `exec` take a **flat linear address**. Address syntax is stable hex; the
  **max width grows with the tier** (20-bit on a plain 8088, up to 32-bit through the 386/4 GB tier,
  64-bit when long mode lands in Build 13). Parsed into a **32-bit value for now** (covers through
  386); widened to 64-bit in B13. An address beyond the advertised arena top is an error.
- The ledger advertises a **MAP of usable regions, NOT one contiguous pool** — real-mode memory is
  inherently fragmented (the 640 KB→1 MB video/ROM gap, hardware in the upper area). Each region is
  tagged (direct/windowed, executable/data, fast/slow) so the agent places hot/executable data in
  direct/fast memory and cold/bulk in windowed/slow, and **respects the holes**. **Direct** regions are
  addressed by their **real** addresses (so code run via `exec` uses the same addresses at runtime — no
  logical↔physical mismatch). **Windowed** memory is a single paged *logical* range (data-only). Builds
  on the existing `a@` arena-base + `c@` context-cap ledger fields.
- Two kinds of access, advertised so the agent knows the rules of each region:
  - **Direct** — far `seg:off` (8088), unreal-flat (386), long-flat (64-bit): touched in place, fast,
    and **executable** (`exec` runs there).
  - **Windowed** — 286 `int 15h` block-move, EMS bank-switch: reached by **copying through a
    conventional window**, slow, and effectively **data-only** (`exec` = copy-down-to-conventional then run).

## The tier ladder

| CPU / config | Mechanism | Reach | Direct? | BIOS? |
|---|---|---|---|---|
| 8088/V30 | far `seg:off` (`seg=A>>4, off=A&0xF`) | ~640 KB conventional *(UMB not offered — see below)* | direct/exec | ✓ |
| 8088/V30 + EMS | bank-switch a 64 KB page frame (per-board backend) | + EMS board (e.g. 4 MB) | windowed/data | ✓ |
| 286 | far + `int 15h AH=87h` block-move window (+ **HMA** ~64 KB via A20) | 16 MB (24-bit) | conv/UMB/HMA direct/exec; ext windowed/data | ✓ |
| 386+ | **unreal mode** (brief PM setup → 4 GB segment limits → back to real mode, 32-bit offsets) | **4 GB** | direct/exec | ✓ |
| 64-bit *(Build 13)* | long mode (one CORE.SYS, early CPUID pivot) | TB | direct/exec | ✗ (loses BIOS) |

**HMA — clean direct RAM (286+).** The ~64 KB just above 1 MB, reachable via the A20 gate on a 286+.
It's a single contiguous block of plain RAM, no fragmentation, no device contention — so it joins the
**direct** arena as-is (milestone 3), same far access, executable.

**UMB — NOT offered (out of scope).** The upper-memory area (≈0xC000–0xF000) is exactly where hardware
lives — option-ROM BIOSes, the EMS page frame, the NIC's shared buffer, other adapters' memory-mapped
RAM/registers — and a write/read-back probe can false-positive on a device buffer (the device owns it
and will clobber it). It's also non-contiguous with conventional (video at 0xA0000–0xC0000) and small
(~100 KB) beside the MB–GB the real tiers deliver. Flaky for little gain, so seed does **not advertise
or manage** UMB as arena. The agent still has universal read/write/exec tools, so it can explore the upper area
itself at its own risk — the same posture as the VRAM path — but it's never handed to it as pool memory.

Notes:
- **XMS is intentionally NOT used.** XMS is a *driver API* (HIMEM.SYS) over extended memory; seed is
  bare-metal and does the raw access itself (`int 15h` block-move on the 286, unreal on the 386), so
  the XMS layer buys nothing. **EMS is NOT redundant** — it is the *only* way an 8088/V30 (20-bit,
  1 MB-capped) exceeds 1 MB at all, so it stays.
- **EMS sits at the top of the flat arena** (fast-first: conventional → extended → EMS), since it is
  the slowest. Extended (286) and EMS rarely coexist (XT-era = EMS, AT-era = extended), so it is
  usually conventional + *one* of them.
- **unreal mode is the BIOS-compatible ceiling.** You are still in real mode (BIOS ints work) but with
  32-bit offsets over 4 GB flat — so a 386+ gets 4 GB direct+executable without becoming a different
  OS. "Gigabytes for modern machines" = exactly this band.
- **64-bit's real cost is BIOS, not the pivot.** Long mode has no real-mode BIOS — every
  `int 10h/13h/16h/15h` + the packet path dies — so the network/floppy/video/crypto need 64-bit native
  re-implementation: a second runtime inside CORE.SYS. The single-file early-CPUID pivot is the right
  *structure*; the *content* is a port. Hence Build 13.

## Real hardware target

A physical **V30 Olivetti, 1 MB RAM + 4 MB EMS board** — so the 8088+EMS tier is a concrete target,
not an emulator curiosity. At milestone 2 that machine is fully addressable: ~640 KB conventional
(direct/executable) + 4 MB EMS (windowed/data). Validated in 86Box (emulated EMS board) + ideally on
the real machine.

## Implementation decisions (locked)

- **Flat→access on 8088**: uniform far, `seg = addr>>4, off = addr&0xF`; re-normalize when a multi-byte
  op would cross a 64 KB segment boundary.
- **`exec` across the boundary**: uniform **far call**, agent code ends with `retf`. The agent already
  adapts its machine code to the tier it sees in the ledger; the calling convention is documented in
  the tool contract. Windowed (EMS/286-ext) code is copied down to conventional before `exec`.
- **Tool address width**: variable-length hex → a 32-bit value now (through the 386 tier), widened to
  64-bit in B13. Agent syntax never changes; only the max grows.
- **Detection**: true conventional size via `int 12h`; extended size via the 286/386 BIOS; EMS via the
  board backend. Drives the arena extent + the window/arena 50/50 split.
- seed's resident footprint stays in low seg 0; only the window + arena move into far/extended space.

## Build plan — Build 12 ("scaling beyond segment 0"); 64-bit → Build 13

Each numbered milestone is a `build12:` COMMIT, landing only when that tier is fully working
(addressing foundation + the window/arena scaling for that tier; internal sequencing is at the
implementer's discretion). Matrix-green per milestone.

1. **8088 far** — flat abstraction + wide-hex native read/write/exec + far translation; arena past seg 0 into the
   **clean contiguous conventional region** (~640 KB); window scales (50/50, streamed from far memory).
   The foundation every higher tier reuses. (UMB not offered — out of scope; see above.)
2. **8088 + EMS** — bank-switch backend behind the windowed-access path; arena (and cold window
   overflow) extends into the EMS board. The V30 becomes fully addressable here.
3. **286 / HMA** — `int 15h AH=87h` block-move window for native extended memory (16 MB) plus HMA via
   A20. EMS support comes free from #2's windowing logic when a board is present.
4. **386+ unreal** — unreal-mode setup → 4 GB flat direct/executable while retaining BIOS calls in real
   mode. The windowed tiers fall away in favor of direct access where present.

**Build 13: TLS 1.3 + 64-bit long mode** → TB. One CORE.SYS, early-CPUID pivot, but a native-driver
runtime because long mode loses BIOS. Build 13 is intentionally not the home for the 286/HMA or 386
unreal work; those remain Build 12 scope.

## Milestone 1 status + the window-streaming design (Stage C)

Milestone 1 split into the **arena** half and the **window** half; both are shipped for M1/M2.

- **Stage A — far addressing (DONE):** native read/write/exec take a 32-bit flat address → far `seg:off`; `exec` = far
  call + `retf`; action line prints before the op. Validated on ibmpc82 @256 KB.
- **Stage B — far-arena advert (DONE):** ledger field `far@00010000-<top>` (top = BDA conv-KB << 10);
  funded by dropping `gw/dns/mask`. Agent quoted `far@00010000-040000`.
- **Stage C — window (context) streaming (SHIPPED for M1/M2):** the window is a fixed ~14 KB seg-0 buffer read
  by ~95 sites (renderer, scanner, request builder, trim). A pure far window = a whole-loop rewrite, so use
  a **two-tier** design:
  - **Far context log** — the canonical conversation, appended sequentially in far memory (base = far arena
    base 0x10000), grows to the 50/50 cap (≤1 MB). This is what STREAMS to the model.
  - **Seg-0 active window** — the recent tail (the existing `chat_context` buffer), kept as-is for the
    **renderer + scanner** (they only need recent content). The ~95 seg-0 sites are UNCHANGED.
  - Far changes confined to: the **append** (also writes the far log), the **request builder** (streams the
    far log, not the seg-0 buffer; the chunked TLS send is already there — feed it from far), and
    **compaction/sizing** (triggers on the far-log length, not the seg-0 length).
  - The display shows the recent tail; the model gets the full far context (correct — the screen is 25 rows
    regardless). State lives in the `reconnect_state_*` block beside `chat_context_used` (survives phases +
    reconnect): add `far_log_used` (DWORD) + `far_log_cap`.
  - **Phasing:** C1a stream the request from far (copy seg-0 window → far log → TLS; identical content, no
    scaling, low-risk); C1b far log canonical (append direct, grow past 64 KB, seg-0 = synced mirror); C2
    50/50 far-log/arena sizing + compaction on the far threshold; C3 the 1 MB cap + spill-to-arena. Each is
    a `build12:` commit; the nucleus is full so each needs space reclaimed (like Stage B dropped gw/dns/mask).
  - **C1a + C1b DONE (implemented + validated 2026-06-29).** C1b = the far-log FLUSH
    model: at the compaction threshold the seg-0 window is FROZEN into the far log (far_flushed_len/esc
    advance, window resets) instead of being model-summarized; the whole far log (frozen turns ++ live
    window) streams every turn via a precomputed dialogue range; append_context renorms ds across 64K; the
    Content-Length is 32-bit. **Gated on conv RAM > 64 KB** (far_log_seg_var) — a <=64 KB machine is
    byte-for-byte Build 11 (seg-0 window + model-summarize), because flat 0x10000 is unbacked there. This
    gate is the one thing the original C1b plan missed; without it every 16K machine got garbage context.
    Validated: a needle ("ZEPHYR") planted in turn 1 survived 5 overflow turns (multiple flushes) on a
    256K machine; the 32K seg-0 fallback recalls correctly.
  - **C2 + C3 DONE (implemented + validated 2026-07-03).** The far region
    [0x10000 .. conv_top) is now SPLIT: far_window_cap = min(region/2, 1 MB) [C2 50/50 + C3 1 MB cap] is
    the far log's ceiling; the far ARENA the ledger advertises is far@<0x10000+cap>-<conv_top>, ABOVE the
    log — the overlap is gone (C3 spill-to-arena is automatic: arena = region - window_cap). The far log is
    bounded at the cap (a hard drop-oldest reset at the cap — drop-oldest/summarize is a future refinement;
    can't trigger on realistic tiers where the seg-0 window << cap). Boot-computed in hardware_setup;
    advertised via a new hex32 ledger emitter; api_ledger_len updated (fixed-width, exact for the CL).
    Validated on 256K: the model reported far@00028000-00040000 (region 0x30000, cap 0x18000, arena base
    0x28000) — the split is live. The 1 MB cap itself is MATH-verified only (offline sim: 4 MB -> 1 MB
    window + ~3 MB arena) — it is unreachable on milestone 1 (conventional <=640 KB never hits it, and
    real-mode far seg:off tops out ~1 MB), so its HW gate is milestone 3 (286 extended memory + windowed
    addressing). See stage-c-handoff.md. NB a splash/loading-glyph mis-centering regression (the far detection
    clobbered `ah` = screen cols before seed_col was computed) was found + fixed (reload cols from
    [screen_cols]); user-confirmed centered.

**Milestones 1 and 2 are functionally complete in Build 12.** The next implementation target is
Milestone 3 (286/HMA native extended memory), followed by Milestone 4 (386+ unreal mode).

## Open risks / things to watch

- **`exec` execute-and-return across a far/windowed boundary** is the delicate contract; get the far-call
  / copy-down-and-run conventions exactly right and documented.
- **Window streaming**: building a >64 KB request by streaming context out of far/extended memory —
  must not regress the seg-0 request/TLS path.
- **EMS backend is per-board** (port I/O), like a mini-HAL; emulator-standard first, real-board notes
  as they come.
- **unreal mode + BIOS interplay**: some BIOS calls reset segment limits; re-establish unreal after
  calls that drop it. A20 handling.
- **Multi-byte ops crossing 64 KB** (real-mode) need mid-copy re-normalization.
