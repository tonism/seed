# Build 10 plan — minimal tool calling + max pool

Started 2026-06-04 (evening, autonomous session). Build 9 just shipped (tag build-9).

## Goal (user priority order)
1. **Deliver Build 10**: the agent gets the "keys to the kingdom" — RAM read, RAM
   write, and execute/jump. Minimal primitives that give full control.
2. **Maximize pool space** (conversation window + user/agent arena) as Seed's gift
   to the user/agent. Today it is ~256 B split 50/50 on the 16K gate. More is better.

## What I learned reading the codebase (the constraints)

- **Resident nucleus is full: 2043 / 2048 bytes** (`make inspect`). Hard ceiling: the
  K crypto window is pinned resident at `0x1800`, so the nucleus must fit `0x1000..0x1800`.
  Adding resident code requires reclaiming bytes. This is the "memory rework" the roadmap
  says Build 10 opens with.
- **Pool layout**: `chat_context_start` (~0x3e00, just above the pinned model/key caches +
  keep-alive template) up to `ram_top - 0x100` stack reserve. `hardware_setup` splits it
  50/50 (window / arena) and sets compaction threshold to 3/4 of the window — all computed
  from `ram_top` at boot, so it already scales with RAM.
- **`ram_top` is hardwired `0x8000`** on any BIOS (direct) boot; the BASIC sidecar passes
  the real top (`0x4000` on 16K). So the pool tops out near 32K today.
- **The model is held to plain ASCII** (no JSON, no UTF-8) — Build 9 instruction. The tool
  grammar must be ASCII and JSON-safe (it rides inside the JSON request when echoed back).
- **The conversation window already captures the full model response** (both-sides capture
  in `agent_response.inc .emit_char`). So tool directives the model emits land in the window.
- **All Seed state lives in segment 0** (DS=ES=SS=0). The pool/arena is segment-0 memory.

## Design

### Priority 2 — pool space: two levers

**Lever A — real RAM detection (the big win for >=32K machines).** Replace the hardwired
`ram_top=0x8000` on the direct-boot path with `int 0x12` (KB of conventional memory),
convert to a segment-0 byte ceiling, cap at ~63 KB (`0xFC00`, avoids the 64K*1024 16-bit
overflow and leaves a top margin). The window/arena already scale from `ram_top`, so a
64K+ machine jumps from a ~16 KB pool (capped at 0x8000) to a ~47 KB pool. 16K BASIC path
unchanged (sidecar still supplies the top). 32K direct boot unchanged (int 0x12 -> 32 ->
0x8000). Resident cost ~12-15 B (must come from reclaim). Carried-in Build 10 work.

**Lever B — lower the pool floor / defrag (helps the 16K gate, where pool is tiny).**
The pinned model cache (64 B) + key cache (192 B) + ka template (42 B) sit between the
critical scratch and the pool. The Build 9 notes' analysis says full island consolidation
is unnecessary; targeted reclaim funds it. This is the higher-risk lever (touches tight
critical scratch). Treat as a careful later pass; quantify the win before spending risk.

### Priority 1 — tool calling

**Grammar (v1, ASCII, line-oriented, JSON-safe).** The model emits, on its own line, a
command prefixed with `$` at line start. One call per line.

```
$r <addr> <len>          read <len> bytes from <addr>          (hex)
$w <addr> <b0> <b1> ...  write the bytes to <addr>             (hex)
$x <addr>                call <addr> (near, seg 0); report AX+CF (hex)
```

Seed appends a result line to the conversation (so the model sees it next turn):

```
$r <addr>: <hex bytes>
$w <addr>: ok
$x <addr>: ax=<hex> cf=<0|1>
```

Rationale: `$` at start-of-line is rare in prose, printable, JSON-safe (no escaping).
16-bit seg-0 addresses. **Write + execute = full control**: the agent writes a routine into
the arena and `$x` jumps to it; that routine can set any segment (ES=0xB800 for video, etc.),
hit any port, call BIOS — so three primitives escape the segment limit and own the machine.
Read lets it inspect results/memory. This is the minimal "keys to the kingdom."

**Mechanism (near-zero resident cost):**
- The full model response is already in the conversation window after a turn.
- Add a **cold `tool` phase** (loaded on demand into low scratch `0x0700`, like every other
  phase) invoked from `chat_loop` after a successful exchange. It scans the window for `$`
  directives, parses + executes each, appends the result line to the window, and **overwrites
  the leading `$`** of each executed directive so a re-scan next turn won't re-fire it.
- Resident cost: just the call site in `chat_loop` (~6-8 B). The executor itself is on the
  floppy (cold phase) — between-turn floppy reads are already accepted on 16K.
- Tool execution runs **between turns**, with the TLS session idle-but-alive — safe point.
  `$x` to agent code that never returns hangs the machine: reboot recovery, per the authority
  model ("the tool owns the crash").

**Result feedback:** results land in the conversation window -> the next request carries them
(Build 9 context path). v1 is **user-paced** (the user prompts again to let the agent act on a
read). **Auto-follow-up** (agent chains tool calls without a user turn) is a documented
enhancement, deferred — it complicates the loop + prompt-injection and is not required by scope.

**Ledger advertisement:** once the write tool exists, advertise the arena + context knobs in
the ledger (`arena@<hex> win@<hex> compact@<hex>=<dec>`) and the tool grammar in the
instructions, so the agent can discover and use them. (Build 9 deferred this precisely because
advertising addresses with no write tool made the model hallucinate tool calls.)

## Sequencing (each step builds + 16K-boot-tested before commit; no broken commits)

0. **Foundation reclaim** — free ~20-30 resident bytes from the nucleus (candidates: a shared
   `out dx,ax` NIC port-pair helper, dropping the near-constant `tls_app_plain_ptr` store,
   other DRY). Validate: unchanged 16K boot+chat on the gate NIC. (Risk: medium — hand-tuned
   asm. Do carefully, measured.)
1. **Tool calling** (priority 1): cold `tool` phase + grammar + `chat_loop` call site +
   instructions text advertising the grammar. Test read/write/exec end to end.
2. **RAM detection** (priority 2, Lever A): int 0x12 ceiling. Test 16K (unchanged), 32K
   (unchanged), 64K + 256K/640K (pool grows — needs new test profiles).
3. **Ledger advertisement** of arena + knobs (now that the write tool exists).
4. **Pool floor defrag** (priority 2, Lever B) — only if the win justifies the risk.
5. Docs (builds.md Build 10 checkpoint, architecture/memory/HANDOFF), splash -> build 10,
   full 7-NIC matrix, release per AGENTS.md.

## Decisions made during implementation (2026-06-04/05 session)

- **Scanner fires on `$<verb> ` ANYWHERE**, not just at a line start. The model often
  prefixes prose on the same line (`(hex...): $w 7000 ...`), so line-start was too strict
  and missed real calls. The `$` is only neutralized once a valid hex address parses, so a
  prose `$w ` with no address is left intact (no conversation-text damage).
- **Tool calls cannot fail in a Seed-observable way.** Real-mode RAM read/write never faults
  on the 8088 (no MMU). `$x` either returns (we capture AX+CF) or the agent's code hangs the
  machine (reboot recovery, per the authority model). So there is no success/fail flag to
  show — the only meaningful feedback is the DATA (read bytes, `$x` AX/CF), which the MODEL
  needs, not the user.
- **Screen echo = action only; window = data.** Per the above, the dim on-screen echo shows
  just `read from <addr>` / `write to <addr>` / `jump to <addr>` (liveness, fast-typed, dark
  like `compacting context`). The model-facing window carries the actual result (`read from
  7000: 41 42 43`, `jump to 7010 ax=abcd cf=0`) via a window-only "sink" flag on the data
  suffix. Keeps long read dumps off the screen on bigger/faster machines.
- **RAM detection moved into the LOADER** (not the full nucleus): the loader does `int 0x12`
  and hands CORE.SYS the capped seg-0 ceiling in AX with the SEED magic — the exact contract
  `start:` already handles for the BASIC sidecar. Zero nucleus reclaim. 32K stays 0x8000
  (no regression); >=64K caps at 0xFFF0. VALIDATED to assemble + 32K boots; 64K scaling test pending.

## Validated so far (this session)

- All three primitives end-to-end on 32K direct boot: write 41 42 43 -> read back -> model
  reported "41 42 43"; `$x` of `mov ax,0xABCD; clc; ret` -> `ax=abcd cf=0`. (screenshots)
- 16K gate regression: `seed build 10` splash, multi-turn chat, both-sides recall AND
  `compacting context` all intact with the tool phase loading every turn. (screenshot)
- Splash two-digit fix (`'0'+N` broke at 10 -> `:`); now `build 10`.

## PENDING / hard: streamed-command suppression

The user wants the model's RAW streamed `$...` command hidden (it currently shows in bright
above the dim action line). That detection FSM must live in the renderer (`agent_response`
phase), which is 511/512 bytes full; the nucleus (5 B free) and K window are also packed. A
validated FSM (detect `$<verb> `, suppress to newline, render-anyway when it is not a tool)
is ~30-50 B. So this needs a genuine hot-path memory reclaim (the "rework"): e.g. reclaim
~12 nucleus bytes -> add a resident shared `scroll_text_area` helper -> frees ~13 B in each
of response/dpi/tool phases -> room for the FSM. Multi-step, delicate, regression-risky.
Deferred until the working core + RAM detection are committed; do it carefully or surface
the risk/priority to the user.

## Open decisions for the user to steer (non-blocking; sensible defaults chosen)

- **Tool grammar**: `$r/$w/$x` line format above. Reversible (isolated to the tool phase +
  instructions). Steer if you want a different sentinel/shape.
- **Auto-follow-up**: deferred (user-paced v1). Say if you want the agent to chain tool calls
  within one turn (bounded) for Build 10.
- **RAM ceiling cap**: 63 KB (0xFC00) segment-0. Could push to 0xFFF0 with a touch more code.
- **Execute safety**: `$x` is a bare `call` (agent owns the crash). No sandbox (matches the
  authority model). Confirm you don't want a softer default (e.g. require a confirip).
