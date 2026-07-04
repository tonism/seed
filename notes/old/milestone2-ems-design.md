# Milestone 2 — 8088 + EMS (design / charter)

Extends the flat-address abstraction (milestone 1, `notes/memory-scaling-design.md`) with the first
**windowed** access backend: LIM EMS. Milestone 1 gave direct far `seg:off` over conventional memory
(~640 KB); milestone 2 reaches an EMS board (e.g. 4 MB) as windowed/data-or-executable memory, and
makes the V30-class machine (small conventional + big EMS) fully addressable.

Ordering (confirmed): **M2 EMS → M3 286 native-extended + HMA → M4 386 unreal → Build 13 64-bit.**
EMS first because it is the broad-payoff shared mechanism: it works on the 8088 AND on any 286 that
has an EMS board (same code). The 286 native-extended block-move is a lower-value fallback (M3); the
clean flat-direct win arrives at the 386 (M4).

## The context/arena inversion (the key refinement)

Milestone 1 put the conversation window (far log) in direct conventional memory. That was fine when
conventional was all there was. Once memory extends beyond the directly-addressable region (EMS here,
extended on the 286), letting the context consume direct memory is wrong: **the context is data, and
only three things genuinely need direct/executable memory** — seed's resident, the small hot tail the
renderer/scanner read, and a place to *run code*.

So allocation priority inverts. Direct/executable memory is reserved **first**, in order:

1. **seed resident** (~2 KB + crypto buffers) — conventional, fixed.
2. **seg-0 hot tail** (~14 KB) — the recent context the renderer/scanner need in place.
3. **reserved direct execution window** — where agent code runs (see below).

*Then* the data pools — the frozen context far-log and the agent data arena — take everything else and
are allowed to **spill into windowed memory**. The 50/50 window/arena split applies to that data pool.
Growing the context to its cap no longer starves execution, because it grows into *windowed* memory,
not the reserved direct region.

Consequence: "1 MB consumed by seed + context" stops being true. seed + hot tail + exec window are a
small direct reservation; a large context is data living in windowed memory beyond the barrier,
streamed down when building a request.

## EMS mechanism (what the hardware gives us) — BARE-METAL: board registers, NOT int 67h

EMS is a feature of the **EMS board**, not the CPU: the board has mapping registers that remap its
memory into a **page frame** — a 64 KB conventional-addressable window (typically segment 0xE000),
four 16 KB physical pages. Expanded memory is organized in 16 KB **logical pages**; you map a logical
page into a physical frame slot by writing the board's mapping register, then touch it at the frame's
conventional address. The data does not move — you *remap* which slice is visible (zero-copy banking).

**Critical: seed is bare-metal, so int 67h is unavailable.** int 67h is the software EMM (EMM.SYS,
loaded via DOS `CONFIG.SYS`) — there is no DOS and no driver here, so no int 67h handler exists. 86Box's
`isamem` card emulates the *board hardware*, not the driver. So seed drives the board's **mapping
registers directly via port I/O** — the per-board backend the charter always specified ("bank-switch a
64 KB page frame (per-board backend)"; "EMS via the board backend"). This is the same shape as seed's
NIC HAL: detect the board, then program its specific registers. seed effectively *is* its own minimal EMM.

Per-board backend responsibilities (register-level, NOT int 67h):
- **Detect** the board (probe its registers / known board type + I/O base), like the NIC family probe.
- **Page frame segment** — fixed/known per board (commonly 0xE000); the frame's four 16 KB slots.
- **Map logical page L → physical slot S** — write L to the board's slot-S mapping register (port I/O).
- **Page count / size** — from the configured board size (or a probe).

TODO (pending register research): the exact board target (86Box `genericxt` / `ems5150` / Above Board),
its mapping-register I/O ports, the byte format to map a page, and the enable/config sequence. All at
boot (cold, in `hardware_setup`) for detect/enable → no resident cost; per-op mapping lives in the
`tool_call` / `agent_api_stream` phases.

## Flat-address mapping for EMS

EMS gets a synthetic flat range **above the 1 MB real-mode ceiling**: base `0x100000`, extent
`ems_pages * 0x4000`. Tagged **windowed** (and executable via the frame — see `$x`). This keeps it
cleanly separated from the direct conventional region (`< 0x100000`, the 640 KB→1 MB hole excluded)
and lets the existing `.addr_to_esbx` far translation stay untouched for direct addresses.

`$r/$w/$x` dispatch on the flat address:
- **`addr < 0x100000`** → direct conventional far path (`.addr_to_esbx`, M1, unchanged).
- **`addr >= 0x100000`** → EMS path: `rel = addr - 0x100000`, `logical_page = rel >> 14`,
  `page_off = rel & 0x3FFF`; write `logical_page` to the board's slot-0 mapping register (port I/O);
  access `frame_seg:page_off`. Multi-byte ops crossing a 16 KB boundary remap the next page.

Note (bare-metal): there is no EMM "allocate pages" step — seed owns the whole board, so all logical
pages `0..page_count-1` are seed's to map directly. No handle, no int 67h AH=43h.

## Executable EMS (the 64 KB page frame is the execution window)

EMS must be executable — on a small-conventional + big-EMS machine the agent's entire arena can be
EMS, so data-only EMS would lock it out of running its own programs. The frame makes this natural:

- **`$x` on a direct addr** → far-call in place (M1).
- **`$x` on an EMS addr, program ≤ 64 KB** → map the program's ≤4 logical pages into the frame's four
  slots, far-call `frame_seg:0` (or the mapped offset). Code executes **in place in the frame** — no
  copy, no separate scratch. The ceiling is the frame's 64 KB, which is exactly the 8088's own
  single-code-segment limit (real-mode `CS:IP` wraps at 64 KB) — so this covers every normal program.
- **`$x` on an EMS addr, program > 64 KB** → cooperative overlay: the program far-jumps chunk to chunk
  via a small seed page-map **trampoline** (map logical page N into the frame, far-jump). No total-size
  limit; the executing window is always the 64 KB frame. This is how the DOS era ran >segment programs.

Tool contract: `$x <addr>` for direct (runs in place at its real address); `$x <addr> <len>` for
windowed (how much to map/run). The agent assembles windowed code for the frame address it sees in the
ledger — the charter's "the agent adapts its machine code to the tier it sees."

Caveat: while agent code occupies the frame, that frame can't simultaneously serve EMS *data* access.
A program needing both keeps working data in conventional (its inputs/outputs) or calls back to seed to
swap. Advanced case, not common; save/restore the EMS page map (AH=47h/48h) around `$x`.

## Ledger — the region map

The ledger graduates from a single `far@` range to a small **tagged region map**:
- `far@<base>-<top>` — the direct conventional arena (M1), direct/executable.
- `ems@<base>-<top>` — the EMS arena, windowed (executable via the frame). base = 0x100000.

Each region is tagged so the agent places hot/executable data where it runs cheapest and respects the
holes. (Extends the M1 hex32 emitter.)

## Dynamic conventional → EMS overflow

Chosen over "arena-only EMS": memory fills the direct conventional region first and **spills into EMS as
it grows**, so the far-log window (and the arena) is a single logical stream spanning direct conventional
+ windowed EMS, with the boundary wherever conventional runs out. When streaming a request,
`agent_api_stream` reads the direct conventional part in place, then walks the EMS 16 KB pages by
writing successive logical-page numbers to the board's slot-0 mapping register and reading the frame,
feeding TLS. This is the one place EMS touches the per-turn (matrix-green) streaming path — done
carefully, sequential page walk.

Overflow ordering — LOCKED (user, reverses the earlier lean): the ONE pool is divided **ARENA FIRST,
CONTEXT AFTER**. The arena takes the pool from the low/direct end (0x10000 conventional first, so the
agent's CODE lives in directly-executable memory) and grows up into EMS; the CONTEXT window follows
immediately after the arena (size = min(pool/2, 1 MB), same as M1), landing wherever it falls physically.
This INVERTS M1 (context was at 0x10000, arena above). Rationale: code executability is a hard constraint
(needs direct memory), while the context is data that tolerates the per-turn bank-switch stream — so the
scarce direct/executable conventional goes to the arena, and the context spills into windowed EMS.
`agent_api_stream` streams the context from its (possibly-EMS) location via the per-address dispatch
(< 0x100000 direct read; >= 0x100000 EMS bank-switch). EXECUTION model LOCKED = the **EMS-frame path
(map, no copy)**: conventional-resident code runs in place; EMS-resident code runs via the 64 KB page
frame (map its pages into the 4 slots; <=64 KB in place, >64 KB overlay). The frame is seed's exec
mechanism, not an agent-addressed arena item. (Implemented: M2a detect+ledger, M2c $r/$w, M2d $x <=16 KB.
Remaining: M2b the arena-first/context-after re-layout, M2e context stream from the new location, M2d-full
4-slot + >64 KB overlay.)

## Space budget

All EMS logic lives in **phases** — `tool_call` (`$r/$w/$x`), `hardware_setup` (detect/allocate),
`agent_api_stream` (ledger + overflow streaming) — plus ~8 bytes of data state (`ems_frame_seg`,
`ems_handle`, `ems_page_count`/`ems_top`). The resident nucleus (hard 2 KB ceiling at 0x1800) is
untouched, so **M2 needs no reclamation** (unlike M1's stages). This is the main de-risking fact.

## Cross-tier backend model (why the abstraction earns its keep)

The agent sees one flat field with tagged regions; the backend is CPU/board-specific and gets *simpler*
as hardware improves:

| Tier | Data beyond direct | Code beyond 64 KB | Notes |
|---|---|---|---|
| 8088 + EMS | frame remap (map) | run in frame; overlay via trampoline | board hardware maps; execute in place |
| 286 + EMS board | frame remap (map) | same as 8088 | EMS comes free — same M2 code |
| 286 native-extended | `int 15h AH=87h` (copy) | copy-down to a reserved conv exec buffer | no map hw, no MMU; block-move is the only BIOS-safe door |
| 386+ | unreal 4 GB flat (direct) | far-jump between direct segments; 32-bit PM for true-flat | windowing falls away |
| 64-bit (B13) | long-mode flat | flat | loses BIOS — a native runtime |

Key facts behind the table:
- **EMS paging is board hardware**, not a CPU trick — any machine with a board can page. So a 286 with a
  board uses the EMS path; the block-move is only for bare extended RAM.
- **The 286 is the awkward middle**: it has memory beyond the barrier but neither an EMS board's mapping
  hardware nor a 386's paging MMU / clean unreal-mode escape. Block-move (copy) is the only door to bare
  extended RAM, and returning from 286 protected mode is notoriously ugly. Hence M3 is the low-value
  fallback tier.
- **The 64 KB code-segment granule is the CPU's real-mode limit** (16-bit `IP`), identical on 8088/286;
  it only dissolves in 386 32-bit PM / 64-bit long mode. It is *not* a property of the memory backend.

## Phasing (each a `build12:` commit, matrix-green)

- **M2a** — EMS detect + allocate at boot (state only; no behavior change yet). 86Box EMS profile.
- **M2b** — memory-map + context/arena inversion + reserved exec window; ledger region map (`ems@`).
- **M2c** — `$r/$w` windowed EMS path (agent can touch EMS; roundtrip).
- **M2d** — `$x` windowed EMS execute (in-frame ≤64 KB; overlay trampoline beyond).
- **M2e** — dynamic context overflow into EMS (streaming the far-log tail from EMS).
- **M2f** — validation: ledger advert, `$r/$w` roundtrip, `$x` run, large-context overflow + recall;
  16K/256K matrix stays green (no-EMS path byte-identical).

## Open risks / watch

- **86Box EMS support for an XT/8088** — confirm the emulator offers an EMS board (ISA memory
  expansion) for the ibmpc82-class profile; if not, find the right machine/card combo. Blocks M2f.
- **Frame code-vs-data contention** — save/restore the page map around `$x`.
- **Overflow on the streaming hot path** — the one matrix-green path EMS touches; walk pages
  sequentially, keep it minimal, re-validate the 256K direct path stays green.
- **No-EMS regression** — every EMS path must be gated (frame_seg==0 → inactive) so a no-EMS machine is
  byte-for-byte the milestone-1 build, exactly as the `far_log_seg_var` gate protects ≤64 KB machines.
