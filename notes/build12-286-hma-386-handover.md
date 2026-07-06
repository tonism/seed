# Build 12 Handover — 286/HMA and 386 Unreal Memory Tiers

## Goal

Continue Build 12 memory scaling after the native function-calling checkpoint. Keep Build 13 reserved
for TLS 1.3 and the 64-bit/no-BIOS runtime; 286/HMA and 386 unreal are Build 12 scope.

Implement the remaining memory tiers from `notes/memory-scaling-design.md`:

1. **286 / HMA / native extended memory**
   - HMA via A20: direct, executable memory just above 1 MiB.
   - Native extended memory via BIOS `int 15h AH=87h` block move: windowed/data unless copied down for
     `exec`.
2. **386+ unreal mode**
   - Brief protected-mode setup, return to real mode with wide segment limits.
   - Preserve BIOS compatibility; re-establish unreal limits after BIOS calls that reset them.
   - Provide direct/executable flat access up to the detected 386 memory ceiling.

## Read First

- `AGENTS.md`
- `docs/builds.md` — Build 12 remaining scope and Build 13 boundary.
- `docs/architecture.md` — memory shape, capability tiers, native tool loop, authority model.
- `docs/memory.md` — current 16 KiB and 32 KiB layout.
- `docs/testing.md` — 16 KiB sidecar and 32 KiB direct gates.
- `targets/ibm_pc_5150/HANDOFF.md` — handoff block and capability flags.
- `notes/memory-scaling-design.md` — canonical tier plan.
- `notes/native-tool-calling-design.md` — current native tool surface and validation record.

## Current Baseline

- Branch: `work/scaling`.
- Native tool calling is shipped: `read_mem`, `write_mem`, `exec`, `save_env`, `load_env`.
- Requests use local input-array replay with `store:false`; do not reintroduce `previous_response_id`.
- 16 KiB tools schema streams from floppy; 32 KiB+ streams it from resident `tools_cache`.
- Local 16 KiB split is 96 B context + 96 B arena.
- Per-turn ledger is intentionally terse: `r=`, `a@`, `c@`, `F@`, `e@`, `s=`.
- M1/M2 memory scaling is shipped:
  - 8088 far `seg:off` access for conventional memory.
  - LIM EMS arena-first inversion; context can live at top of EMS and stream through the page frame.
  - 32 KiB normal chat turns are cache-backed; rare compaction can still stream COMPACT from floppy.
- 286 secure TLS tier is already present and gated by `handoff_flag_cpu_286plus`.

## Constraints

- Keep the 16 KiB BASIC-sidecar path working.
- Keep normal 32 KiB direct boot working.
- Keep `cpu 8086` coverage for common 8088 code. Any 286/386-only instruction path must be isolated and
  gated so unsupported opcodes cannot execute on 8088-class machines.
- Preserve BIOS text mode and BIOS-based disk/network assumptions until Build 13.
- Do not advertise UMB as safe arena memory.
- Content-Length must match streamed request bytes exactly.
- Every touched phase is sector-budget sensitive; run `make` / check-layout frequently.

## Implementation Shape

- Treat this as extending the existing memory HAL, not replacing the tool protocol.
- Start from the current flat-address path in `targets/ibm_pc_5150/boot/phases/tool_call.inc`:
  `addr_to_esbx`, EMS handling, far-call `exec`, and read/write staging.
- Extend detection/sizing in `targets/ibm_pc_5150/boot/phases/hardware_setup.inc` and the handoff state
  in `targets/ibm_pc_5150/boot/core/data.inc` / `layout.inc`.
- Keep the context/arena split policy:
  - window + arena split 50/50 as detected memory grows;
  - window caps at 1 MiB;
  - surplus goes to arena.
- Decide whether the existing `F@` / `e@` ledger fields are enough for HMA/extended/unreal or whether a
  compact tagged map extension is needed. If expanding the ledger, update `prompts/identity.txt`,
  Content-Length math, and docs together.
- For 286 extended memory, prefer block-move data access and copy-down-for-`exec` over trying to execute
  from windowed extended memory.
- For HMA, handle A20 explicitly and remember that real-mode HMA addressing is limited to the high
  segment window.
- For 386 unreal, isolate 386 setup code and validate BIOS calls that may destroy the widened limits.

## Validation Gates

Minimum before a working checkpoint:

- `make`
- `make basic-bootstrap`
- `tools/run-basic-bootstrap-86box.py --profile vm-net-ne2k8 --entry basic --ram-kib 16 ...`
- 32 KiB direct `vm-net-ne2k8` smoke with plain chat + `read_mem`
- 286 harness via `tools/run-286-86box.py` for the new 286/HMA path
- EMS regression via `targets/ibm_pc_5150/86box/vm-net-ems/86box.cfg` or the existing EMS harness path
- Add or document a 386 86Box profile/harness before landing the unreal tier

## Suggested First Slice

1. Add detection and layout state for 286 extended memory size and HMA availability without changing
   tool access yet.
2. Advertise nothing new until the values are validated and the request-size math is known.
3. Implement HMA read/write/exec first; it is direct and smaller than full extended block-move.
4. Add `int 15h AH=87h` block-move read/write for extended memory; add copy-down `exec` only after
   data access is green.
5. Then start 386 unreal as a separate milestone.

## New Chat Prompt

```text
Continue Build 12 memory scaling for Seed on branch work/scaling.

Read first:
- AGENTS.md
- notes/build12-286-hma-386-handover.md
- notes/memory-scaling-design.md
- docs/builds.md
- docs/architecture.md
- docs/memory.md
- docs/testing.md
- targets/ibm_pc_5150/HANDOFF.md

Current checkpoint: native Responses function calling is shipped with local `store:false` input-array
replay; 16K tools stream from floppy; 32K+ uses tools_cache; 16K context/arena is 96/96; M1/M2 memory
scaling (8088 far + EMS) is shipped. Build 13 is only TLS 1.3 + 64-bit/no-BIOS runtime. Do not move
286/HMA or 386 unreal out of Build 12.

Your job: implement the remaining Build 12 memory tiers:
1. 286/HMA + native extended memory via A20 and int 15h AH=87h.
2. 386+ unreal mode for BIOS-compatible flat direct access.

Keep 16K BASIC-sidecar and 32K direct boot green. Run `make`/check-layout frequently, validate with
16K, 32K, 286, and EMS gates, and add/document a 386 profile before landing unreal mode. Ask before
commits; push only when I explicitly tell you.
```
