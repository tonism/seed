# Build 9 — Context Management (attempts)

Branch context: Build 9 owns minimal context management for agentic continuity
(`docs/builds.md`). Build 8 (the DPI chat loop) shipped (tag `build-8`); each
prompt is currently a fresh, semantically-stateless provider request on the
reused keep-alive TLS session. Build 9 makes the next prompt non-fresh. Build 9
ships as its own release ("first build with actual memory"), not only as part of
the 8+9+10 public-release gate.

Baseline (Build 8, measured 2026-06-02, `make inspect`):
- 16 KiB ceiling `0x4000`; resident nucleus `0x1000..0x1800` (2 KiB, 2032/2048
  nonzero — effectively full) + K crypto window `0x1800..0x3400` (7 KiB).
- high-crypto `0x3400..0x34c2` (194 B) + critical scratch `0x34c2..0x3cf3`
  (2097 B = TLS stream buffer: 1460 B receive payload + 637 B pre-response tail).
- Reconnect-safe durable pocket `0x3cf3..0x3e00` = 269 B, and it is EXACTLY full:
  ~13 B TLS app send-state + `chat_model_cache` (64) + `chat_key_cache` (192) ends
  precisely on the 16 KiB BASIC stack-guard floor `0x3e00`. `0x3e00..0x4000` is the
  16 KiB runtime stack. So there is ZERO free reconnect-safe working RAM today.
- Per-turn floppy reads: `chat_loop` reloads the DPI phase (Y) + request/send/
  recv/parse (R/X/T) every prompt — the Build 8 blocker #4 documented exception.
- Request build: fixed `api_request_plain` 440 B -> `tls_app_record_buffer`
  (461 B) in the pre-response tail; prompt injected. `dpi_input_buf` aliases
  `tls_rx_copy`; the prompt is recovered from the screen on reconnect via the
  resident `chat_resend_prompt_len`.

## Target design (locked 2026-06-02)

Layered request:

```text
identity      static · floppy · hand-tuned        tone / self / tools                 never changes -> cache/prefix anchor
ledger        RAM · structured · deterministic     machine facts / addresses / state   built NOW (boot-facts), consumed Build 10
conversation  RAM · model-compacted near budget                                        recent turns
prompt        RAM · visible + editable                                                 current turn
```

identity + ledger together are the protected framing (the model's "system" view) —
never lossy-compacted. No umbrella name for the pair (dropped "preamble").

- Context is NOT the screen. Tool calling (Build 10) needs durable machine-facing
  state (owned RAM addresses, tool registrations, results) that does not belong in
  the user's visible compose area.
- Compaction is a MODEL round-trip, not local heuristics — fired only when the
  assembled request nears the transmit budget (a second request shape in the loop;
  amortized, not per-turn). The ledger is never summarized: it is deterministic
  client bookkeeping (address in when a tool is parked, out when freed). identity
  and ledger are protected — identity is never sent for compaction, the ledger is
  never subject to it. So aggressive conversation compaction cannot poison the
  agent's identity, capabilities, or owned addresses.
- Two budgets: TRANSMIT (per-turn request size the NIC send lanes + send time
  tolerate; sets the conversation ceiling and the byte target handed to the model
  for compaction) and RAM (reclaimable space for ledger + conversation tail +
  response).

Decisions:
- identity hand-tuned tight — transmit cost is per-turn; floppy storage is free
  but irrelevant to the binding constraint.
- ledger built in Build 9 and populated with boot-facts now, to measure Build 10's
  footprint early (functionally Build 10, but its space must be budgeted now).
- Defrag appetite: TBD pending Phase 0 (targeted reclaim / bounded incremental
  defrag / full island consolidation). Build 7/8 lesson is about METHOD: measured,
  incremental, revertable, NIC-validated per step — not a big-bang ocean rewrite.
  Now is plausibly the time only because the chat loop is finally stable.
- Hot-loop floppy reads (blocker #4): aim to eliminate; accept bounded + documented
  reads if 16 KiB cannot host residency once context is funded.
- Agent arena (Q3, forward to Build 10): TBD.

Naming: retire "sysprompt". The slices are `identity` + `ledger` + `conversation`
+ `prompt` — no umbrella term for the identity+ledger pair.

## 2026-06-02 19:23:18 - Design lock + Phase 0 kickoff

Locked the layered model above in design dialogue. Opened this log before
implementation per `notes/README.md`.

Phase 0 (measure the two budgets) started. Initial TRANSMIT-budget findings from
`net_phase.inc` + `agent_api.inc`:
- The request is built into `tls_app_record_buffer`, which lives in the
  pre-response tail and overlaps the tail of the receive stream buffer
  (`tls_app_record_buffer == tls_rx_copy + tls_payload_buffer_len`). Growing the
  request to carry context grows the pre-response tail -> competes directly with
  the 1460 B receive payload buffer and the guard. Transmit-vs-RAM tension located.
- One TLS app record carries <= `tls_app_max_plain_len` = 1439 B plaintext. Larger
  requests already use a multi-record split-body lane (`api_ready_short_prompt_max`
  =24 / tiny=10; 3c503 split lane in `docs/networking.md`). A bigger request is NOT
  a protocol wall — it is (1) request-buffer sizing in critical scratch and (2)
  multi-record send reliability per NIC (esp. 3c501 single-buffer).
- The screen already serves as durable prompt storage on reconnect
  (`agent_request` rebuilds the prompt from video memory via the resident
  `chat_resend_prompt_len`).

## 2026-06-02 19:35:12 - Phase 0: RAM reclaim inventory

Traced the scratch map (`data.inc`) and handshake-state lifetimes (`tls.inc`).
Decisive finding: durable context must be RECONNECT-SAFE, and there is ZERO free
reconnect-safe working RAM today.

Why reconnect-safe is the binding requirement: a dropped session reconnects on the
next prompt (the text-seen fallback invalidates the session rather than reconnecting
mid-exchange), and the next request must still carry the context. A reconnect is a
full fresh handshake that overwrites essentially all of `0x3400..0x3cf3`:
- `tls_client_hello_buffer == tls_rx_copy` (`0x34c2`) and the 1460 B receive buffer
  hold ClientHello + ServerHello/Cert/SKE.
- The pre-response tail is overlaid by handshake state: `tls_server_random` (32),
  `tls_master_secret` (48), `tls_handshake_hash` (32) reuse the `seed_*` config arena.
- high-crypto holds the session keys (live every turn) plus the Finished buffers
  (handshake-only): `tls_finished_plain/cipher/tag/received_tag` ~64 B.

So the ~240 B of "handshake-only" scratch (Finished buffers + random/master/hash +
prepared-HMAC pads) is dead in steady-state chat BUT is required again on the next
reconnect — it is NOT a safe home for durable context. The only memory that survives
a reconnect is at/above `critical_scratch_end` (`0x3cf3`), and that pocket
(`0x3cf3..0x3e00`, 269 B) is exactly full (chat caches; the 192 B API-key cache alone
is 71% of it). The K window's idle-in-chat handshake routines are CODE, not
repurposable data — freeing them means a reload (= floppy read).

Consequences (decision-relevant):
- Targeted-reclaim-only is INSUFFICIENT for durable context: the reclaimable bytes
  are reconnect-unsafe. A useful conversation+ledger window must be CREATED by
  relocating/shrinking TLS scratch (bounded defrag) OR stored outside working RAM.
- Reconnect-safe stores OUTSIDE the 16 KiB working budget exist and are already used:
  VIDEO MEMORY (`0xb800`) survives the handshake and costs 0 working RAM. The prompt
  is already recovered from it. The CONVERSATION slice (human-readable) can live in
  the visible scrollback the same way — bounded by screen size, which doubles as a
  natural compaction trigger. Only the LEDGER (machine state, not displayed) needs
  reconnect-safe working RAM, and it is small.
- This reframes the build: if conversation is video-backed, the durable working-RAM
  need shrinks to ~the ledger, which a small relocation (or trimming the 192 B key
  cache) can fund — making "full island consolidation" likely unnecessary.

Still to measure in Phase 0:
- Ledger boot-facts size: serialize the handoff fields (RAM top, NIC, IP, memory
  contract, arena bounds) into draft ledger text; measure bytes -> sets the durable
  reconnect-safe RAM Build 9 must create.
- Screen budget for the conversation slice: usable chars after chrome at the detected
  column count (CGA 40/80, MDA 80), and how reconnect-recovery reads multi-line text
  back (today only the single prompt line is recovered).
- Bounded-defrag option sizing: what relocating the request buffer / shrinking the
  receive window frees above `0x3cf3`, vs. the video-memory route.

## 2026-06-02 19:53:12 - Phase 0: video-backed conversation + floppy posture decided

Min-spec video is MDA: framebuffer `0xB000`, 4 KB = one 80x25 page (char+attr
interleaved), NO off-screen pages. So on MDA "conversation in video memory" = the
VISIBLE screen: ~2000 cells, ~1.7 KB usable after chrome. It is outside the
`0x0000..0x4000` working budget and survives a reconnect (the prompt is already
recovered from it). CGA (`0xB800`/16 KB) has 3 extra 80x25 pages -> ~4x more history,
a bigger-machine bonus, not the floor.

Convergence on MDA: screen size = conversation store size = conversation transmit
budget = compaction trigger. One ~1.7 KB number governs all four.

Conversation slice is therefore SCREEN-BACKED. Reconciles "context != screen": the
human-readable conversation is the screen; the ledger stays hidden in RAM.

Visible-compaction UX (direction): when the screen is about to fill, fire the model
compaction round-trip and redraw older messages as a short summary (dim attr / under a
rule), recent verbatim turns below — honest, transparent compaction the user watches
happen. Must fire AT the fill boundary, before new lines destructively scroll old ones
off the single MDA page. Known limit: a single response longer than the screen scrolls
its own top away mid-stream -> retained only as its on-screen tail (+ next summary).
Accepted tiny-machine sacrifice.

Floppy posture DECIDED: identity is cold (floppy), read during request build each turn.
Build 9 ACCEPTS bounded, documented per-turn floppy reads (R/X/T/Y already reload per
turn; identity rides along / streams into the request records). This descopes blocker
#4 from "eliminate hot-loop floppy reads" to "accept + document" on 16 KiB, trading
hot-loop disk for context + user/agent-env RAM. Floppy-read elimination -> bigger-
machine QoL after Build 10. Storage is free, so floppy identity can be rich; hand-tune
only for TRANSMIT size.

Defrag appetite (updated): full island consolidation now looks UNNECESSARY. With the
conversation video-backed, durable reconnect-safe working RAM is needed only for the
(small) ledger -> fundable by a small relocation or by trimming the 192 B key cache.
Surgical, not a big-bang rewrite.

Next: measure ledger boot-facts size (sets the durable reconnect-safe RAM to create) +
exact screen chrome budget at CGA 40/80 and MDA 80.

## 2026-06-02 20:26:34 - Phase 0: reconnect-safe context, handoff=ledger, guard reclaim

Supersedes the 19:53 video-backed / reset-on-reconnect direction.

RECONNECT-SAFETY IS MANDATORY. Users walk away; losing context on the idle-timeout
reconnect is a product failure. Context must survive a reconnect -> it must live ABOVE
`critical_scratch_end` (`0x3cf3`), the only region the handshake never overwrites. Drop
reset-on-reconnect. Drop VRAM as a store (also leaves VRAM to the user for graphical UIs).

HANDOFF = LEDGER (unify). The handoff block (`0x0600`, 46 B, struct v3 - `HANDOFF.md`) was
built to publish machine state to the user/agent env; the ledger publishes the same machine
state to the model. Same data, two consumers. Redesign:
- Canonical state-ledger boot-facts source. Compact binary at `0x0600`, reconnect-safe
  (handshake never touches `0x0600`). Model-facing ledger = TEXT serialization of it, built
  transiently at request-build (~0 durable RAM). Env handoff reads the same block.
- ADD free-arena bounds (start/end of the user/agent buildable region) as new fields -> both
  the agent (ledger) and the env (handoff) learn where they can build. Folds in the old
  "publish the arena" item. Bump struct version (3 -> 4); update `HANDOFF.md`.
- Block can't grow in place (`low_runtime_state` starts at `0x062e`, right above it). So
  DYNAMIC ledger state (Build 10 tool-state: owned addresses, tool regs) lives in the
  reclaimed-guard reconnect-safe region, alongside the conversation summary.
  Ledger = handoff boot-facts (fixed, regenerated) + dynamic tool-state (reclaimed guard).

NOTHING ELSE MOVES TO FLOPPY (confirmed). Resident set is timing/correctness-bound: 2 KB
nucleus (phase loader + shared NIC/TCP/UI primitives the hot loop calls) and 7 KB K window
(handshake-race crypto, cannot take a mid-race floppy read - the Build 7 crypto-race result).
Config caches are pinned by write-protect (user-typed key/model live only in RAM). Everything
else is working scratch. So RAM for context comes from the GUARD, not floppy.

RECLAIM THE GUARD (reconnect-safe context home). The guard region (above `0x3cf3`) is
reconnect-safe by construction -> it is where context lives. Closed-contract guard philosophy
(`architecture.md`) already justifies running it thin: no third-party software, we track every
byte. But `0x3cf3..0x4000` is packed today: ~13 B TLS app-state + 269 B config caches (pinned)
+ 512 B 16K-BASIC stack reserve. So "reclaim" = shave the SAFETY MARGIN: measure worst-case
stack depth (incl. BIOS) and trim the stack reserve to a small measured margin, freeing
reconnect-safe bytes below it. Context then sits just under the stack -> measured boundary.

32K LAYOUT PRINCIPLE. Seed resident+scratch+context = a compact block at the BOTTOM; the
stack/guard "top" floats with detected RAM (`0x4000` on 16K, `0x8000` on 32K), never pinned at
`0x4000`. Free user/agent arena = everything above Seed's block up to the stack margin (tiny on
16K, ~16 KB on 32K). Layout made RAM-relative so the guard never fragments a bigger machine;
the published free-arena bounds come from this.

SIZE (honest): guard-reclaim is reconnect-safe but modest (~few hundred B from a stack-reserve
shave) -> a terse rolling summary. Richer budget needs a bounded TLS-receive-scratch trim
(pushes `0x3cf3` down, enlarges the reconnect-safe region) - riskier, per-NIC validated. Size
before proposing.

Next: (a) redesign the handoff/ledger layout (+ free-arena fields, version bump) and measure
its serialized text size; (b) measure worst-case stack depth -> reclaimable guard ->
reconnect-safe context budget.

## 2026-06-02 20:50:56 - Phase 0 RESULTS: stack budget, handoff free-arena removed

Work moved to branch `context-management` (main stays clean; FF on release per AGENTS.md).
Commits only when the user asks.

CORRECTION to the 20:26 entry: NO free-arena field in the handoff. Seed publishes FACTS
(RAM top, what Seed occupies) and does NOT dictate a free arena - that is the user/agent's
to determine (architecture.md: "Seed publishing enough memory and storage facts for that
environment to make its own decisions"; "unused low memory is not reserved by default").
- Seed's memory-ownership MODEL (which ranges Seed occupies; free RAM = above Seed's block,
  below the stack) is described in IDENTITY (static). The ledger/handoff carry the dynamic
  numbers (RAM top). The agent computes free RAM itself.
- So Build 9 needs NO structural handoff change. It is recognized as the ledger source and
  serialized to terse text. Structural growth (tool-state) is Build 10.

STACK DEPTH (static call-tree analysis): worst-case core depth ~68 B, on the deepest LIVE
chain: large-record decrypt -> render re-entry -> keep-alive -> ChaCha20. Notable: p256.inc
scalar-mult is NOT in the live image (fixed-scalar ECDHE - constant client pubkey, server X
copied as premaster), so there is no deep point-mult/Comba chain; the PRF->HMAC->SHA-256
handshake chain is only ~44 B. BIOS ISR margin (int 0x10 video scroll fires on the live
receive stack) recommended ~96-128 B. => worst-case ~68 + ~128 ~= ~200 B.
The 16K BASIC stack reserve is 512 B -> ~300 B reclaimable, and it is RECONNECT-SAFE (above
critical_scratch_end 0x3cf3, below the stack low-water). CAVEATS: static estimate - confirm
with a runtime high-water canary (paint + run boot/chat/reconnect, read mark) during
validation; re-measure if a real (non-fixed) ECDHE scalar mult is ever linked in.

PHASE 0 CONTEXT BUDGET (both numbers now in):
- ledger: ~130 B per-turn transmit (terse), ~0 durable RAM (regenerated from handoff @ 0x0600).
- conversation summary: ~300 B reconnect-safe RAM (reclaimed from the stack reserve) -> a
  terse model-maintained rolling summary. Richer needs a bounded TLS-receive-scratch trim
  (pushes 0x3cf3 down) - deferred/risky, per-NIC validated.
- identity: hand-tuned tight, on floppy, read per request-build; also carries Seed's memory-
  ownership model so the agent can compute free RAM.

Phase 0 essentially complete. Next: Phase 1 implementation, and update docs/builds.md Build 9
with the locked shape once results are confirmed.

## 2026-06-02 21:00:45 - User/agent arena is a first-class reservation

Caught a gap: on bare 16 KiB, Seed resident+scratch already fills ~`0x0500..0x4000`, so giving
the full ~300 B reclaimable to the conversation summary leaves ~0 RAM for the user/agent to
build in - breaks Seed's core "leave room for the user" promise.

PRINCIPLE: the user/agent arena is a FIRST-CLASS reservation, not leftovers. Reserve an arena
floor first; context gets the remainder. Future-proofs Build 10 (tools need RAM to live in =
this arena); avoids clawing context back later. Reconciles with "Seed does not dictate the
arena": Seed LEAVES A GAP (does not place its own data there) and publishes FACTS (RAM top +
ownership model in identity); the agent discovers the free gap itself. Leaving room != dictating.

16 KiB split of the ~300 B reclaimable (starting point, tune during testing):
- arena floor ~128 B - reserved, unowned (token PoC crumb on 16K, but proves the contract);
- conversation summary ~150-170 B - terser than the earlier ~300 B; leans hard on compaction
  + the shorter-answers identity instruction.

RAM-relative payoff: on 32 KiB the arena floor becomes the whole ~`0x4000..0x7e00` band (~16 KiB
real build space) while context stays ~constant. 16 KiB proves the contract; bigger machines
make the arena useful. This answers the long-running "agent arena" (Q3): reserve it, keep it
small on 16 KiB, let it scale.

Phase 0 now truly complete (budget + arena reservation locked). Ready for Phase 1.

## 2026-06-02 21:10:16 - Merged bordered pool (prompt + conversation + arena)

Current prompt location: `dpi_input_buf equ tls_rx_copy` = `critical_scratch_start` (0x34c2),
128 B (`dpi_input_max_len`), ALIASED over the TLS receive buffer (typing and receiving never
overlap, so the prompt costs 0 dedicated RAM today). Because it is below 0x3cf3 (handshake-
clobbered), it is NOT reconnect-safe -> hence the `chat_resend_prompt_len` + recover-from-screen
hack.

DECISION: merge prompt + conversation + arena into ONE contiguous reconnect-safe pool, split by
movable borders the user/agent controls. Don't impose fixed sizes; let them balance the three.
Most Seed-shaped layout: "don't dictate, publish facts, leave the machine to them."

Wins:
- Prompt becomes RECONNECT-SAFE (lives above 0x3cf3): a half-typed prompt survives an idle
  walk-away, and the `chat_resend_prompt_len`/screen-recovery hack RETIRES.
- It is the "context + prompt window": prompt = unsent tail of the conversation; request = whole
  pool + identity + ledger.

Refinements:
- Borders = STORED POINTERS, not in-band magic markers (content could contain any byte
  sequence). Keep the pointers in the handoff/ledger -> published facts the agent reads AND
  rewrites; rewriting a pointer = moving a border (the adjustability mechanism).
- The whole pool must be reconnect-safe (above 0x3cf3, below the stack): the ~300 B reclaimed
  sliver on 16 K, the whole ~0x3e00..stack band on 32 K (RAM-relative). The three areas SHARE
  ~300 B on 16 K via the borders; ~16 KB on 32 K. Cost on 16 K: prompt loses its RX free-ride
  and spends its own bytes - offset by retiring the screen hack.

Layout shape: `[ config caches (Seed, pinned) ] [ conversation (+prompt tail) | <border> | arena ] [ stack, RAM-relative ]`.
One border balances context-vs-arena; an optional second border hard-caps prompt size. Build 9
ships default border positions; MOVING borders is a Build 10 tool capability (no tools yet), but
the pointers are designed in now so Build 10 just writes them. (Ordering note for Phase 1: arena
nearest the stack doubles as a stack-overflow buffer protecting Seed's context.)

Does not change the Phase 1 gate: still need the stack canary to size the pool.

## 2026-06-02 21:30:25 - Layout CONVERGED: prompt 256 B in RX, pool = conversation + arena

Supersedes the 21:10 merged-pool idea - the prompt is NOT in the reconnect-safe pool after all.
RX (`tls_rx_copy`) is 1460 B and idle while typing; the prompt free-rides it. Putting a 256 B
prompt in the ~300 B pool would burn 85% of the pool, so keep it in RX.

Converged layout:
- identity: floppy, hand-tuned, read per request-build.
- ledger: handoff serialization, ~130 B transmit, ~0 durable RAM (regenerated from 0x0600).
- prompt: RX (aliased), grow `dpi_input_max_len` 128 -> 256 B. data.inc:366 guard already allows
  up to ~1459 B, so 256 B is conservative with headroom. Reconnect-safe via EXISTING screen-
  recovery (chat_resend_prompt_len) - kept, not retired. 256 B sits at 0x34c2-0x35c2, clear of
  dns_qname (setup-only) - no chat-time conflict.
- pool (~300 B reconnect-safe, reclaimed stack reserve): conversation + arena, ONE movable
  border, arena open-ended. 2 published pointers (pool-start = conversation-start;
  conversation-end / arena-start). Arena end unpublished -> agent discovers from RAM top.
- stack: ~256 B reserve (conservative, > 68 B core + BIOS margin); rest reclaimed as the pool.
  RAM-relative top (0x4000 on 16K, 0x8000 on 32K).

Follow-ons: bigger prompt -> bigger request -> multi-record send (Phase 1, per-NIC validate);
screen compose rows trade against conversation-display rows (tune later).

CANARY DECISION: no number-print helper exists -> a precise on-screen high-water readout needs
throwaway hex-print + OCR for ~50 B gain. DECIDED: size the reserve conservatively from static
(~256 B) and reclaim the rest now; confirm/tighten with a lightweight high-water tripwire folded
into the 7-NIC validation runs. No standalone canary session.

Phase 0 COMPLETE. Phase 1 (implementation) next, starting with the now-fully-specified layout
changes (prompt 256 B, pool + pointers, stack reserve 256 B, RAM-relative).

## 2026-06-02 21:49:25 - Build 9 work sequence (TODOs integrated)

Carried Build-8 TODOs status:
- Floppy reads (#3): SOLVED by decision. Accept bounded, documented per-turn reads on 16 K
  (identity from floppy; phases still reload). Blocker #4 "eliminate" -> "accept + document".
  Context STATE (conversation + ledger) stays RAM-only, so the meaningful part of the scope holds.
- Memory reclaim (#2): FOLDED into the core. Stack-reserve reclaim funds the pool + arena.
  Conscious reversal of the old "toward 1 KB guard" framing -> reclaim the guard, keep a measured
  ~256 B reserve (below the doc guard floor; permitted by guard philosophy ONLY with runtime
  collision detection -> the Phase 4 stack tripwire provides it).
- NIC merging (#1): the one open investigation. Sequenced into validation, evidence-gated.

Sequence (build_number -> 9 already done):
- Phase 1 Layout foundation: prompt 256 B; stack reserve 512 -> 256 B + RAM-relative; pool + 2
  pointers; reclaim -> make inspect/memory-map. Update docs/builds.md Build 9 (locked shape,
  descope blocker #4, guard reinterpretation). [memory-reclaim + floppy land here]
- Phase 2 Context plumbing: ledger (serialize handoff -> terse text at request-build); identity
  (tight text on floppy, wired in); request assembly = STREAM identity+ledger+conversation+prompt
  record-by-record (never buffer whole -> preserves the pool; the unified generic send).
- Phase 3 Conversation + compaction: rolling summary in the pool; model compaction round-trip
  near budget; visible collapse (splash scrolls out first; identity asks for shorter answers);
  reconnect-survival.
- Phase 4 Validation + NIC unification: 7-NIC matrix (continuity, compaction, walk-away reconnect-
  survival, bigger streamed request through every send lane esp. 3c501/3c503); stack high-water
  tripwire baked in (confirms 256 B reserve); fold per-NIC send carve-outs ONLY with documented
  replacement + cross-NIC evidence. [memory-reclaim confirmation + NIC TODO land here]
- Phase 5 Ship (on user ask): docs (context contract, HANDOFF.md fields/pointers, networking.md
  folded carve-outs); release per AGENTS.md (FF main, tag build-9).

## 2026-06-02 22:11:09 - Phase 1 layout landed + conversation/arena scaling rule

Phase 1 layout DONE (builds clean; %if guards enforce the fit). 16 K top-of-RAM now:
  0x3cf3 TLS app-state 13 B + config caches 256 B (pinned)
  0x3e00 conversation 128 B   (reclaimed)
  0x3e80 arena 128 B          (reclaimed; grows on bigger RAM)
  0x3f00 stack reserve 256 B  (was 512 B; RAM-relative top)
  0x4000
Carved 256 B from the old 512 B reserve into conversation(128)+arena(128), both reconnect-safe.
Prompt grew to a 256 B region in RX (dpi_input_max_len=255), costing none of the pool. Edits:
layout.inc (prompt, reserve), data.inc (chat_context_*/chat_arena_* + guards), Makefile
(BASIC_BOOTSTRAP_16K_STACK_GUARD -> 0x0100, inspect display). memory-map regen = no diff (128 B
granularity + generator doesn't know the pool yet; enrich it in Phase 2-3 when conversation is
populated). builds.md fold still pending.

SCALING RULE (bigger machines; does NOT change 16 K). ADOPTED: conversation/arena split the free
pool 50/50 by default, capped at the model context window, user/agent-adjustable via the border.
(Superseded my earlier transmit-cap framing.) Rationale: speed is NOT a Seed constraint - the
promise is "a self-building agent fits and works on 4.77 MHz 8088," not "fast." Slow-but-richer
conversation is the right default; anyone wanting a snappier loop slides the border toward arena.
The model-window cap (~256K tok / ~1 MB ~= 2 MB RAM at 50/50) is 286+ territory, never binding on
8088 (max 640 KB -> conversation <= ~300 KB ~= ~75K tok), so it is a harmless forward ceiling here;
RAM is always the binding limit on this CPU. Simplification: with slow accepted, the conversation
region IS what's sent (compacted by the model when it fills) - no separate transmit budget or
raw-history split. Residual VALIDATION item (not a cap): a pathologically slow upload could hit a
provider/edge request timeout; bounded by RAM on 8088 (minutes; active send doesn't trip idle
timeout), so likely fine - verify at the large end. Build 9 (16 K): 50/50 of the 256 B pool = the
128/128 already built; runtime 50/50 (border from ram_top) is a bigger-machine feature, deferred.

## 2026-06-03 00:14:25 - Phase 2 DONE + validated: ledger + chunked streaming end-to-end

Request is now the layered `instructions`=identity+ledger / `input`=prompt split, `effort:high`.

Hit + fixed B5/05 (request_too_large): the instructions+ledger prefix (~600 B) overflowed the
440 B `api_request_plain` build buffer. The harness caught it (the build can't). FIX = chunk-by-
chunk streaming (option B; rebalancing the receive buffer [A] was rejected - it risks the
hard-won Build-8 receive timing and "sooner or later eats everything"). The HTTP body now goes
as 3 TLS records, each << 440 B:
  chunk 1 (agent_request/R): headers + {"model":"<model>
  chunk 2 (agent_api_stream/X): ","reasoning":{"effort":"high"},"instructions":"<identity> <ledger>","input":"
  chunk 3 (X): <prompt-from-screen>","stream":true}
The ledger serializer + instructions/input templates MOVED R -> stream phase (the post-handshake
send lives there; renamed agent_api_stream_ledger_*, uses the X z-append helper). R back to 3
sectors; stream phase grew 1->2 sectors (guard 1792 B). Content-Length = total body across the 3
records (fixed-width ledger => api_ledger_len constant), unchanged by chunking. Receive path
UNTOUCHED.

VALIDATION (vm-net-ne2k8, 16K BASIC sidecar harness, real OpenAI): boot -> "seed build 9" ->
greeting -> typed "What IP address does this machine have? Reply with only the IP." -> model
answered "10.0.2.15" (the SLiRP DHCP IP) -> screen oracle verdict=success. That IP is knowable
ONLY from the ledger, so this PROVES the ledger reaches the model + the 3-chunk stream is accepted
and reassembled. Screenshots cleaned.

Uncommitted WIP on context-management. Next: Phase 3 (conversation - rolling summary in the
reclaimed pool, model-compacted, into `input`). Identity still the seed "Concise, factual,
professional."; tighten/expand later.

## 2026-06-03 00:43:42 - Phase 3 MVP: turn-to-turn continuity WORKS (validated)

The core Build 9 feature. A `chat_context` window in the reclaimed pool (chat_context_start,
128 B) holds the recent prompt; it's prepended into the request `input` ahead of the current
prompt, so the next turn isn't semantically fresh. New: `chat_context_used` (resident byte,
reconnect-safe, 0 at boot); agent_api_stream_append_context (copies the window into chunk 3 before
the prompt); agent_api_stream_append_prompt_to_context (after the send, stores the just-sent
prompt for next turn, JSON-escaped via the screen-read, bounded to chat_context_len). R's
compute_ready_body_lengths adds chat_context_used to Content-Length. Build clean; nucleus still
2048 (the byte fit), stream phase still 2 sectors.

VALIDATION (vm-net-ne2k8, real OpenAI, 2 prompts): turn 1 "My favorite number is 42." -> model
"Got it, 42 is ... the answer to life ...". turn 2 "What is my favorite number? Reply with only
the number." -> model "42". screen oracle verdict=success. That fact is NOT in the re-sent frame
(unlike the IP), so this PROVES turn-to-turn memory: turn 1's prompt was carried into turn 2.

MVP SCOPE (honest): carries only the LAST prompt (1-turn deep, replace-not-accumulate) and only
PROMPTS (not model responses); overflow = drop (placeholder). So "set turn 1, ask turn 3" or
"recall what you told me" would fail today - the MECHANISM is proven, depth isn't.
ENRICHMENTS (Phase 3b): accumulate N recent turns; carry response snippets too; model-compaction
on fill (the user's "no local heuristics" - compact via a round-trip when the window fills);
the visible-collapse render. Also pending: long-prompt chunk-3 overflow (escaped prompt+context
can exceed the 440 B record - generalize the chunked send), and identity tighten/expand.

Uncommitted WIP on context-management. Build 9 core (continuity) now functional end-to-end.

## 2026-06-03 07:56:30 - Phase 2 + 3-MVP committed; Phase 3b accumulation works (validated)

Committed the working slice as e88a3a7 (Phase 2 ledger + chunked streaming + Phase 3-MVP
continuity + the AGENTS.md release-note fold) and pushed to origin/context-management.

Phase 3b step 1 = multi-turn accumulation: agent_api_stream_append_prompt_to_context now appends
at the used-offset (accumulate) instead of resetting each turn; resets only on window-full
(eviction placeholder; model-compaction-on-fill still TODO). Build clean, stream phase still 2
sectors.

VALIDATION (vm-net-ne2k8, 3 prompts): turn 1 "My favorite number is 42." -> turn 2 "My favorite
color is blue." -> model replied "Noted: your favorite number is 42 AND your favorite color is
blue" (referenced BOTH -> turn 1 still in context at turn 2) -> turn 3 "What is my favorite
number?" -> "42" (recalled past the intervening color turn). verdict=success. Proves the window
accumulates multiple turns, not just the last.

Uncommitted (the accumulation change). Remaining Phase 3b: response-capture (carry model replies,
not just prompts; watch the 512 B render-phase cap), model-compaction-on-fill (round-trip summary
instead of drop), the long-prompt chunk-3 overflow (generalize the chunked send), identity
tighten/expand.

## 2026-06-03 09:09:00 - Phase 3b: model-compaction request-side built; capture is the crux

Direction (user): TRUE model-driven compaction (B). Bigger machines naturally hold more verbatim
context + compact less often once the window itself is RAM-sized (deferred runtime pool-sizing).

BUILT + GREEN (request side):
- Trigger MEASURED BEFORE SENDING (compute_ready_body_lengths, R): if chat_context_used >=
  chat_compact_threshold, set compact_next + add the directive's length to Content-Length. The
  "measure before send so the reply has room to land" rule (user).
- chat_compact_threshold: resident byte, default (chat_context_len*3)/4 = 96 (the 3/4 rule),
  TUNABLE by user/agent (read every request -> instant effect).
- compact_next -> chunk 2 (X) appends api_json_compact_directive_text ("After answering, add a
  final line beginning SUMMARY: then a <=80-char recap..."). So the model emits the summary.

CAPTURE (PENDING - the crux): divert the model's rendered "SUMMARY: <recap>" into the window.
- Inline-in-renderer FAILED: the render phase T is a hard 512 B one-sector phase (load region
  0x0d00..0x1000 abuts the nucleus; can't grow), and the resident nucleus has ~12 B free. These
  are FIXED low-memory regions - they do NOT scale with RAM (correcting the earlier "scales with
  machines" - that holds for the window SIZE, not the capture CODE).
- HOME = R (request phase): already does a screen-read (.restore_prompt_from_screen), runs per
  turn, has sectors. At request-build, scan the PRIOR response's rendered SUMMARY: line ->
  window (replace, reset chat_context_used), gated on compact_next (still set from last turn) so
  it never false-matches a normal reply. One-turn lag is fine (the model got the verbatim window
  in the compaction turn's chunk 3; the summary lands next R). ~40-line screen-scan (cell loop +
  marker match + de-wrap + bounded copy) - the focused remaining build.

ALSO PENDING:
- Dim "compacting..." status (dark attr) shown while the compaction reply is in flight (user:
  explains the sudden slowness; cheap for us).
- HANDOFF-ADVERTISE the adjustment points (user, NEW): publish chat_compact_threshold + the
  context/arena pool borders in the handoff so the agent can DISCOVER + TUNE them. Fits "handoff
  publishes facts the agent reads and rewrites" (21:10 bordered-pool entry). Borders tie to the
  still-deferred bordered-pool; threshold address is concrete now.

CAVEAT of the current green state: request-side is active but capture is pending, so a window-
FILLING conversation would show an un-captured "SUMMARY:" line (transient until capture lands);
short conversations never fill the window, so they're unaffected. Accumulation + drop-on-overflow
(validated) is still the effective behavior until the capture + dim + handoff-advertise land.

## 2026-06-03 10:06:08 - Phase 3b COMPLETE: model-driven compaction works end-to-end (validated)

The capture landed in R (.capture_summary_from_screen): when compact_next is still set from the
prior turn, it linearly scans the rendered response area (rows 0..dpi_prompt_row-1; dpi_prompt_col=0
so a flat scan is already de-wrapped) for the LAST "SUMMARY:" and copies the recap into the window,
replacing the verbose history. Inline-in-renderer was impossible (T is a hard 512 B phase, nucleus
~12 B free, both fixed low-memory); R already screen-reads + runs per turn + has room.

RAW-STORAGE REWORK (fixed a real bug found while planning validation): the window now stores RAW
text and is JSON-escaped only at send (append_context -> json-bytes escaper). Before, the
accumulation fit-check used prompt*2 (worst-case escaping), capping the window at ~half and making
the 3/4 threshold barely reachable for normal prompts. Raw storage = full capacity + simpler
capture (no escape in the scan). Accumulation reads the raw prompt from dpi_input_buf (intact:
accumulation runs before the receive).

VALIDATION (vm-net-ne2k8, real OpenAI, 4 turns): facts accumulated turns 1-2; turn 3 (window past
threshold) -> answered "pizza" AND emitted "SUMMARY: User facts: #42, blue, pizza, Paris..." with
the dim "compacting context..." status shown; turn 4 "favorite number and city?" -> "42 and Paris"
recalled from the CAPTURED recap (verbose history was replaced). verdict=success. Full chain
proven: measure-before-send trigger -> SUMMARY: directive -> screen-scan capture -> window=recap ->
continuity across the collapse.

DIM STATUS: shown (dark-gray 0x08 CGA / 0x07 MDA) but v1 overprinted the prompt line; FIXED to
advance one line first (scroll-at-bottom mirroring the renderer) so it gets its own line below the
prompt, reply below that. (Re-validating.)

HANDOFF-ADVERTISE (user btw): the ledger now publishes 3 context-management knobs so the agent can
find/tune them - win@<hex> (window addr), arena@<hex> (arena addr), compact@<hex>=<dec> (threshold
addr=value). Documented in HANDOFF.md (## Context-management knobs). api_ledger_len 129 -> 166
(fixed-width, Content-Length stays exact); chunk 2 still fits 440. (Re-validating with the dim fix.)

Uncommitted on context-management (capture + raw-rework + dim-fix + ledger-knobs + HANDOFF.md +
this log). Ready to commit when asked.

## 2026-06-03 10:32:37 - dim block polish + ledger-knobs REVERTED (premature for Build 9)

Two iterations after user feedback on the validation screenshot:
- DIM STATUS BLOCK: v1 overprinted the prompt; v2 advanced a line (scroll-at-bottom mirroring the
  renderer) -> own line + blank before; user wanted it bracketed -> v3 adds inc cursor_row after
  the status so the reply lands below a blank too. "compacting context..." now reads as its own
  block (blank / status / blank / reply).
- LEDGER KNOBS REVERTED: advertising win@/arena@/compact@<addr>=<val> in the ledger made the model
  hallucinate a memory-WRITE tool call (validation OCR turn 2: '...should_write_memory "yes",
  memory_to_write:"User favorites..."}'; the prior run WITHOUT knobs never did this). Root cause:
  advertising ACTIONABLE addresses before any memory-write tool exists (Build 10) nudges the agent
  to act on memory it can't write -> hallucination. So the agent-facing ledger advertisement is
  DEFERRED to Build 10 (lands with the write tool). The knobs stay fully documented in HANDOFF.md
  (## Context-management knobs) as the contract. api_ledger_len back to 129.

One transient hiccup seen: a re-run stuck on turn 1 (no response, screen unchanged) - not code
(the only diff, the dim blank-after, runs only on compaction turns; the same ledger flew the prior
run), just an API/render stall. Clean re-run in progress.

Net Build 9 Phase 3b state: capture + raw-storage + dim block all validated/validating; ledger
knobs deferred. Compaction itself proven end-to-end (42-and-Paris recall across the collapse).
