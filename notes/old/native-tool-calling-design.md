# Native tool calling (function calling) — design + Codex handover

## COMPLETION UPDATE — 2026-07-05

T3-T7 are implemented on `work/scaling`: the receive phase captures native `function_call` SSE bytes,
`tool_call` parses/executes structured args, and the request stream locally replays the submitted user
item plus the captured `function_call` and `function_call_output` items with `store:false` (no
`previous_response_id`, no server-side response chain). The redundant line-start `$` scanner /
synthetic Continue path is deleted, and `save_env` / `load_env` are native tools. The 32 KiB+ tier
streams the schema from resident `tools_cache`; the 16 KiB tier streams the one-sector TOOLS asset from
floppy and uses a low 0x0d00 capture handoff so native tools no longer depend on the loop-cache band.
Validation: `make`, check-layout, `make basic-bootstrap`, original-speed 32 KiB `vm-net-ne2k8` direct
boot plain chat (`ok`), and 16 KiB BASIC-sidecar `read_mem(0x00000400,8)` returning
`f8 03 f8 02 00 00 00 00` with pcap-confirmed local replay + `store:false`.

## HANDOVER — Codex, start here (2026-07-05)

**Goal:** finish native function-calling. **Baseline** is `work/scaling` at the M2 commit + task-19
spacing + **T2 shipped** (tools schema advertised to gpt-5). Build is green (`make`, check-layout OK;
CORE.SYS `a7fef9c9`). Right now tools are *advertised but not parsed*: a plain chat turn works; a
tool-requiring prompt ("remember X") will misrender because the `function_call` in the SSE stream is
not yet parsed. Your job: **T3–T6** (parse → execute → feed back → render + delete the `$`-scan).

**Do first — the enabler (this is why the last attempt stalled):** the receive phase `agent_response`
is **hard-capped at 512 B** (loads at `0x0D00`, nucleus at `0x1000`, persists across the receive loop),
and it is ~full. The `function_call` handler does NOT fit there. Either (a) MAKE ROOM — relocate
`agent_response`'s load address lower (verify the `0x0900` net-setup region is free during receive; the
keep-alive path is the thing to check) so it can be 2–3 sectors — or (b) capture-during-receive + parse
-between-turns in `tool_call` (which has room after you delete the `$`-scan). Read the "HARD BLOCKER"
and "T2 BUILD STATE" sections below — they have the full budget map and the walls already hit.

**`$`-machinery is now REDUNDANT — delete it, don't keep both.** With a tools schema advertised, gpt-5
emits structured `function_call`s and NEVER `$` text. The entire inline-`$` path (`tool_call`'s
`.scan`/`.exec_directive`/`.line_is_call`/`$s`/`$l`, and `agent_response`'s inline-`$` dimming) is dead
weight and its deletion is exactly what frees the budget your parser + dispatch need (T6). Re-add
`save_env`/`load_env` as native tools (they were the `$s`/`$l` verbs). KEEP the `$r/$w/$x` executor
bodies (`.do_read`/`.do_write`/`.do_exec` + `.addr_to_esbx`/`.parse_hex` + the `.res_*` result emitters)
— T4 dispatches to them with structured args.

**Current decisions:** transport follows the standard Responses tool-item shape without remote
response storage: every ready turn uses an input array and `store:false`; a tool continuation locally
replays the submitted user item, the captured `function_call`, and the `function_call_output`. Tool set
= 5 distinct tools (`read_mem`/`write_mem`/`exec`/`save_env`/`load_env`), per-field structured args;
schema is `prompts/tools.json`, shipped resident in `tools_cache` on 32K+ and streamed from floppy on
16K. Parse defensively (match distinctive substrings, order-tolerant).

**Gotchas that cost real time:** every touched phase is at/near its sector cap — expect a byte-fight;
measure phase sizes with a temp-copy listing (do NOT edit `core.asm` in place to measure — it bit me).
Content-Length must match the streamed bytes EXACTLY or the request breaks. Validate on 86Box with a
PLAIN chat turn for the T2 regression, and a memory prompt only once T3–T5 land (see T8). The safety
snapshot of the abandoned mid-flight attempt (T2+gut+T3-buffers) is on branch `build12-native-tools-wip`
— reference only; the code there is superseded by this plan.

The full design, budget map, and the sequence of walls follow.

---

Status: IMPLEMENTED for T3-T6 on 2026-07-05; the historical design follows. Chosen 2026-07-04 over
"observation framing" and "render-only" — user picked the full-fidelity option. Target model is **gpt-5** on the OpenAI Responses API
(`/v1/responses`), so function-calling reliability is not a concern (the earlier small-model worry
is moot). This is milestone-scale and touches seed's tightest, most fragile code: the request
builder (`agent_request.inc`) and the SSE stream parser (`agent_response.inc` / `agent_api_stream.inc`),
both near-full.

## Why (the bug that motivated this)

Today seed has NO tool protocol. The model writes `$w <addr> <bytes>` as plain text inside its
reply; `tool_call.inc` scans the *rendered window text* for a line-start `$`, executes it, appends a
readable result line (`write to 00003fb5`) into the window, then injects a **synthetic user turn**
`" User: Continue; answer using the tool output above."` to re-prompt.

Two structural failures fall out of this (both seen live 2026-07-04, the "all messed up" screen):

1. **Answer-before-result.** Nothing stops the model from emitting the `$w` *and* a final answer in
   the same turn (it did: `$w …` + "Got it…"). A real tool API stops the turn at the call.
2. **Imperative continuation.** `" User: Continue; answer using the tool output above."` reads to the
   model as a *fresh user instruction* → it re-does the write and re-answers → visible duplication.

Native function calling fixes both for free: the API stops the model at the call (stop reason =
tool use), and the result is handed back as its own role (`function_call_output`), never a synthetic
"continue" imperative.

## OpenAI Responses API function-calling shape (to be wire-confirmed, T1)

### Request adds a `tools` array
```json
"tools": [
  {"type":"function","name":"read_mem",
   "description":"Read len bytes from a flat memory address.",
   "parameters":{"type":"object",
     "properties":{"addr":{"type":"string","description":"hex flat address, e.g. 3fb5"},
                   "len":{"type":"integer","description":"byte count, <=32"}},
     "required":["addr","len"]}},
  {"type":"function","name":"write_mem",
   "description":"Write space-separated hex bytes to a flat memory address.",
   "parameters":{"type":"object",
     "properties":{"addr":{"type":"string"},
                   "bytes":{"type":"string","description":"space-separated hex, e.g. 7a 65 70"}},
     "required":["addr","bytes"]}},
  {"type":"function","name":"exec",
   "description":"Near-call a routine at a flat address; returns AX and CF.",
   "parameters":{"type":"object",
     "properties":{"addr":{"type":"string"}},"required":["addr"]}},
  {"type":"function","name":"save_env",
   "description":"Save the current conversation and arena to disk (ENV.DAT).",
   "parameters":{"type":"object","properties":{},"required":[]}},
  {"type":"function","name":"load_env",
   "description":"Restore the saved conversation and arena from disk. Reboots seed.",
   "parameters":{"type":"object","properties":{},"required":[]}}
]
```
Five tools, mapping the full current `$` grammar: `read_mem`→`$r`, `write_mem`→`$w`, `exec`→`$x`,
`save_env`→`$s`, `load_env`→`$l`. The two env tools take NO arguments and have side effects handled
specially (they are not memory ops):
- `save_env`: set `save_pending` (dpi runs the cold save phase after the turn, as `$s` does today);
  return `output` = "saved" so the model can acknowledge.
- `load_env`: `int 0x19` reboot — **never returns**, so its `function_call_output` is never sent
  (the restored boot lands on the saved screen, exactly like `$l`). The model call is the last thing
  that happens this session.
The `tools` blob is STATIC — it can live as a fixed byte template appended to chunk 1 of the request
(like the existing model/instructions fields), so it costs request bytes but no new build logic.

### Tool schema shipping — RESIDENT pool-carved buffer (resolved 2026-07-04)
Five distinct tools WITH descriptions (~700 B, up to 2 sectors) exceed the one-sector floppy asset
path, and the 32K tier must stay floppy-free. Resolution (user's call, refined 2026-07-04): a **tier-split**, mirroring the existing loop-cache /
prompt-cache regime (those exist only on 32K+; 16K floppy-streams them):
- **32K / 256K (loop-cache tiers)**: a **resident 1-sector tools buffer** carved from the TOP of the
  arena/context pool, capping window/arena ~1 KB lower, **preloaded ONCE at boot**, streamed from RAM
  every ready turn. Conversation loop stays floppy-free (the whole point of the 32K tier).
- **16K**: NO resident buffer (do not touch 16K's scarce pool). Stream `tools.json` from the FLOPPY
  per ready request — 16K already does per-turn floppy I/O (phases stream every turn), so this is
  consistent. The one wrinkle: tools is 2 sectors and the RX staging buffer (tls_rx_copy, 592 B) holds
  only one — so the floppy path streams SECTOR-BY-SECTOR (read cluster LBA, stream <=512; read LBA+1,
  stream the rest). The two clusters are contiguous (the FAT12 builder allocates sequentially), so no
  chain-walk. This multi-sector floppy stream is needed ONLY on 16K, ONLY for tools.

This is exactly `agent_resolve_prompt_source`'s existing shape for identity/compact (32K+ → fixed
cache slot; else → floppy sector into tls_rx_copy), extended to two sectors for tools.

The request splices `,"tools":` then streams the tools bytes verbatim (raw, no escaping — it is literal
JSON) into chunk 2, on NORMAL ready turns only (not the boot greeting, not compaction). Content-Length
adds the tools `size`.

### Implementation refinements (during T2 build, 2026-07-04)
- **Nucleus is full (2047/2048)** — do NOT modify `agent_resolve_prompt_source` (resident). On 32K+
  the whole schema is resident in `tools_cache`, so the splice streams it DIRECTLY from `tools_cache`
  via `agent_api_stream_stream_contract.sc_copy` (the record-flushing copy loop, entered with si/cx/di
  preset — no resolver call). All new code stays in the cold `agent_api_stream` phase.
- **16K tools (T7)**: with no resident buffer, 16K reads the one-sector TOOLS asset into `tls_rx_copy`
  and streams it through the same record-flushing path. The function-call capture handoff moved into
  low scratch (`0x0d00`) so parsed tool calls no longer depend on the 32K loop-cache band.
- **JSON splice shape**: chunk 1 ends `{"model":"<model>` (open string). Normal 32K+ turn:
  `api_json_tools_open_text` = `","tools":` (closes the model string + key), then stream tools bytes
  `[...]`, then `reasoning_prefix + 1` (skip its leading `"` since the model string is already closed)
  = `,"reasoning":{...},"instructions":"`. Compaction / no-tools: `reasoning_prefix` verbatim (its
  leading `","` closes the model string). Envelope (BOTH ready paths): input-open →
  `","input":[{"role":"user","content":"`; close → `"}],"store":false,"stream":true}`. Boot greeting
  path (agent_request `.build_openai_body`) is UNTOUCHED (string input, no tools, no store).
- **Content-Length**: `api_json_input_open_text_len` auto-updates (derived from the string). The ready
  close length must be re-derived from the NEW `api_stream_json_close_text` (today `api_ready_stream_
  close_text_len` aliases the BOOT close's length — must repoint it). Tools adds `tools_open_len +
  prompt_tools_size - 1` (the -1 = reasoning_prefix offset) ONLY on normal 32K+ turns with size>0.

### Streaming response — function-call events (SSE, to confirm exact keys in T1)
For a tool call the stream carries (instead of / alongside `response.output_text.delta`):
- `response.output_item.added` → item `{"type":"function_call","id":"fc_…","call_id":"call_…","name":"write_mem","arguments":""}`
- `response.function_call_arguments.delta` → `{"delta":"{\"addr\":\"3fb5\","}` (streamed JSON string)
- `response.function_call_arguments.done` → `{"arguments":"{\"addr\":\"3fb5\",\"bytes\":\"7a 65\"}"}`
- `response.completed`

seed already scans the SSE byte stream for `"delta":"` (text). It must now ALSO recognise a
function_call item and capture three things: **name**, **call_id** (`call_…`, ~30 chars), and
**arguments** (the JSON string). The answer text path (`response.output_text.delta`) is unchanged.

### Feeding the result back — next request `input` items
```json
{"type":"function_call","call_id":"call_…","name":"write_mem","arguments":"{…}"},
{"type":"function_call_output","call_id":"call_…","output":"wrote 8 bytes to 0x00003fb5"}
```
The model then continues (calls another tool, or answers). seed must store `call_id` and echo it.

### TRANSPORT CONSTRAINT (discovered during T2 recon, 2026-07-04)
Seed today sends `"input":"<window+prompt>"` — a plain STRING (the Responses API treats it as one
user message). But a `function_call_output` can only be delivered as an **input ARRAY item**:
```json
"input":[ {"type":"function_call_output","call_id":"…","output":"…"} ]
```
So "stateless re-send as a string" CANNOT carry a tool result. Two ways out:

- **(X) previous_response_id continuation (RECOMMENDED, minimal).** User turns stay exactly as today
  (string input) — zero request-builder change on the hot path. Additionally capture `response.id`
  from the stream. When a tool fires, the continuation request is tiny: `"previous_response_id":"<id>"`
  + `"input":[{"type":"function_call_output","call_id":"…","output":"…"}]` (+ the same tools array).
  The model resumes server-side; seed need NOT echo the function_call item or re-serialize the window.
  The final answer is still captured into seed's text window for recall (unchanged). response.id +
  call_id are transient per tool-loop state. COST: a server-side dependency (OpenAI retains the
  response ~30 days) and reconnect interaction (a mid-loop reconnect must still carry the response.id
  — it is valid across a fresh TLS session since it is server-side; ties into issue #21). New state:
  response.id buffer (~64 B) + call_id buffer (~40 B).
- **(Y) full input-array, stateless.** Restructure `input` from string to an array every turn: a user
  message item + (on continuation) the echoed `function_call` item + the `function_call_output` item.
  Purely stateless (no server retention), but a large rewrite of the request builder's hot path and
  it re-sends more wire, and forces echoing the function_call (capture name+args+call_id). Heavier.

Chosen: **(Y)** — full input-array, stateless (confirmed 2026-07-04, on the "which is more
architecturally correct" question). Rationale: it preserves seed's defining property — a
self-contained, stateless agent that re-sends its own complete state every turn and never outsources
its continuity to server-side session state. Single source of truth (the array IS the state);
idiomatic native shape (function_call / function_call_output are array items by design); reconnect
stays trivially self-contained (just re-send the array — no response.id to preserve through the
handshake clobber); and it can run `store=false` (honest, depends on nothing but itself). (X) was
rejected despite being less code: it splits truth between seed's text window and the server's chain.

### (Y) implementation shape — smaller than it sounds
Seed already serializes the whole role-labeled window into ONE `"input"` string. (Y) does NOT break
that into per-turn items. It:
1. Wraps that same window+prompt string as a single array item:
   `"input":[{"role":"user","content":"<window+prompt>"}]` (envelope change only; the window /
   recall / compaction machinery is untouched — it still produces one big role-labeled blob).
2. During an ACTIVE tool loop, appends the model's echoed call + its output as further array items:
   `,{"type":"function_call","call_id":"…","name":"…","arguments":"…"}` then
   `,{"type":"function_call_output","call_id":"…","output":"…"}`.
3. Sets `"store":false` (self-contained; no server retention).

The one genuinely new capture is the model's `function_call` (name + arguments + call_id) so it can
be echoed back verbatim in step 2. call_id + name + arguments are captured in T3, held in transient
per-tool-loop state, and re-serialized in T5. Because content is JSON-escaped already, the wrapping
just adds the `[{"role":"user","content":"` prefix and the `"}]` (or `"},<tool items>]`) suffix
around the existing escaped window string — a close-text swap plus a small tool-items builder.

## Argument parsing

gpt-5 emits well-formed JSON `arguments`. seed does NOT need a general JSON parser — it needs
targeted key extraction from a flat string: find `"addr":"` → read hex to the closing `"`; find
`"len":` → read digits; find `"bytes":"` → read the hex-and-spaces run. This is close to the existing
`.parse_hex` token scan, just keyed by field name. Reuse `tool_call.inc`'s hex/exec primitives
verbatim (`$r/$w/$x` internals are sound — only the *front end* changes from text-scan to
structured-args).

## What this DELETES / simplifies

- `tool_call.inc` window-text scan for line-start `$` (`.scan`, `.line_is_call`, the whole-line gate).
- `agent_response.inc` inline `$`-dimming (`compact_next` / `.dim_line` / the line-start `$` test) —
  the model's tool call no longer appears in the answer text at all, so there's nothing to dim.
- The synthetic `" User: Continue…"` turn and `agent_loop_pending`'s dpi auto-submit path (the
  phantom-prompt fix I just built becomes unnecessary once continuation is API-driven — though the
  auto-continue turn still exists mechanically; TBD in T5).

The dim `> write to <addr>` result line STAYS (now rendered from the structured call, not scanned
text), and task-19 type-change spacing still applies to it.

## Interactions to reconcile (T7)

- **Recall window format** (` User: …  You:\n…`): tool calls/results must serialize into the carried
  window in a role-faithful way so recall + compaction still read cleanly.
- **Compaction** (model-summarize + far-log): a compaction turn must not carry tool schemas oddly.
- **Reconnect / session reuse**: a reconnect mid-tool-loop must resume correctly (call_id state must
  survive or be re-derivable). The reconnect-safe block is the home for any must-survive tool state.
- **ESC graceful stop / panic**: stopping mid-tool-loop.
- **Byte budgets**: request builder + stream parser are both near-full; new states/buffers need room
  (call_id buffer ~40 B, arguments accumulation, name match). Likely needs golf or band moves.

## T2 BUILD STATE (2026-07-05) — GREEN ✅

T2 builds clean: check-layout OK, 160K image fits, all budgets satisfied (nucleus, agent_api_stream 3
sectors, agent_request 3 sectors, loop-cache working set 26/26). CORE.SYS a7fef9c9. The 42 B was
reclaimed by shortening the compaction/note strings (user's call): ' Target about '->' ~',
' characters, at most '->' chars max ', ' Conversation so far (context, do not restate): '->
' Context (do not restate): ' (keeps 'do not restate'). Plus: dropped the redundant tools-size guard
from BOTH the splice and the Content-Length block (they must match; the asset is Makefile-guaranteed
on 32K+) -- which also fixed a splice/CL gate mismatch.

NOT YET VALIDATED on hardware, and NOT functionally complete: with tools offered but no function_call
parsing (T3), a NO-TOOL prompt (plain chat) still answers normally (the regression test), but a
TOOL-requiring prompt ('remember X') will make gpt-5 emit a function_call the stream scanner can't yet
read -> no text delta -> misrender. That's expected until T3-T5 land. So the T2 smoke test is a plain
chat turn, NOT a memory prompt.

--- historical (the wall, now cleared) ---
The tree was RED because the tools splice pushed `agent_api_stream` 42 B past its HARD 1536 B cap. That cap is physical: the phase
loads at net_setup_phase_start (0x0900) and a 4th sector would clobber the resident nucleus at 0x1000.

Fixed along the way:
- Nucleus overflow → RESOLVED by relocating the tools preload from the resident `main.inc` `.commit`
  into the `agents_cfg` PHASE (has room; already finds the cluster; runs after ram_top is set).
- The input-array envelope (store:false + `[{role:user,content}]`) was DEFERRED to T5 (only needed to
  send `function_call_output` back) — it saved ~42 B of string growth now.
- Splice simplified (dropped the size-0 guard; unified the reasoning-prefix select, no branch/jmp).
- (A `/tmp` measurement detour accidentally reverted core.asm's tool-phase budget 1536→1024 from a
  stale backup; restored from HEAD. Lesson: never edit core.asm in place to measure — use a temp copy.)

REMAINING: reclaim 42 B so `agent_api_stream` fits 3 sectors. The tools feature itself costs ~42 B
(stream call 12 + tools_open append 6 + `","tools":` string 11 + 2 guards 14 - shared reasoning mov).
Options to weigh (golfing the request builder is the most critical, already-golfed code → do it
deliberately): (a) golf 42 B from existing phase helpers; (b) drop `"reasoning":{"effort":"high"},`
from the reasoning prefix (~29 B) — but that changes model reasoning effort (behavior, not pure golf);
(c) move part of the phase (a helper/string block) into the persistent pool or another phase; (d) a
larger refactor of the net-setup window. Measured via a temp-copy listing: phase size 1578, cap 1536.

## Staged plan

- **T1 — DESIGN FROM SPEC (probe skipped 2026-07-04).** No live wire capture. Parse defensively:
  match on distinctive substrings (`"type":"function_call"`, `"call_id":"`, `"name":"`, the
  `response.function_call_arguments.delta` event's `"delta":"`, `"arguments":"`) rather than relying
  on field ORDER; tolerate unknown interleaved events by ignoring anything not matched. Risk: a shape
  mismatch surfaces only on 86Box (T8) — mitigate by keeping the matcher forgiving and logging via the
  wire-capture tooling if it misbehaves.
- **T2 — request `tools` blob.** Append the static tools array to the openai request. Regression:
  the model still answers a no-tool prompt normally. (No parsing yet.)
- **T3 — stream: detect a function_call.** Recognise the function_call item; capture name + call_id +
  arguments; suppress from the answer-text render. Detect "model wants a tool" vs "model answered".
- **T4 — execute from structured args.** Field-extract addr/len/bytes; run the existing $r/$w/$x
  primitives; build the `output` result string.
- **T5 — feed back + continue.** Build the follow-up request with `function_call` +
  `function_call_output` input items; model continues → answers. Retire the synthetic "Continue" turn.
- **T6 — render from the structured call.** `> read/write/jump <addr>` dim line derived from the call;
  delete the old inline-`$` text-scan + dimming paths.
- **T7 — reconcile** compaction / reconnect / recall / ESC / budgets.
- **T8 — validate on 86Box** across the NIC matrix; confirm no duplication, clean spacing, recall.

## T3 PLAN + budget strategy (2026-07-05)

Budget reality: `agent_response` (the SSE scanner) is 511/512 B and `tool_call` is near-full. T3's
parser will NOT fit incrementally. BUT the old `$`-text tool system and native function-calling are
mutually exclusive — with tools offered, gpt-5 emits structured `function_call`s and NEVER `$` text.
So T3/T4 are FUNDED BY DELETING the old machinery (T6) in the same phases: a swap, not an add.
 - `agent_response.emit_char`: delete the inline-`$` dimming (`compact_next` open, `.dim_line`, the
   line-start `$` test) → frees ~30-40 B → spend on function_call detection + capture + suppression.
 - `tool_call`: delete the window text-scan front-end (`.scan`, `.line_is_call`, `.exec_directive`'s
   `$`-parsing) → frees room → spend on T4's structured-arg dispatch. KEEP the `$r/$w/$x` executor
   primitives (`.do_read/.do_write/.do_exec`, addr_to_esbx, parse_hex) — T4 calls them with parsed args.

Parse strategy (design-from-spec, defensive; a tool-call response is text XOR function_call):
 - Detect `"function_call"` in the stream → set `fc_mode=1`.
 - Capture `"call_id":"..."` → durable buf (reconnect-safe block; echoed to the API in T5).
 - Capture `"name":"..."` → short buf (dispatch in T4).
 - Capture `"arguments":"..."` (the complete args in the output_item.done event; ignore the streamed
   deltas) → into fs_sector_buffer (free during receive; where tool_call already stages its scratch).
 - Suppress render: when `fc_mode`, the `"delta"` scanner captures nothing to screen (the delta events
   are arg chunks, not text). Reuse the existing `.match_char` machine for the new key patterns.
 - On completion with `fc_mode`: set the T4/T5 hand-off flag instead of finishing as a text answer.

Buffers (reuse existing scratch, avoid new RAM): args → fs_sector_buffer (dead between turns, already
tool_call's scratch home); call_id → reconnect-safe block (survives to the next request); name → small
scratch. Sizes: call_id ~40 B, name ~16 B, args uses fs_sector_buffer (512 B, ample for a written
routine's hex bytes).

### HARD BLOCKER found 2026-07-05: agent_response is 512-capped, can't hold the parser
`agent_response_phase_load_addr = 0x0D00` (low_scratch_start+0x600) and it persists there across the
WHOLE receive loop; the nucleus is at 0x1000. So agent_response can load at most 1 sector (0x0D00+512
= 0x0F00 <= 0x1000; 2 sectors -> 0x1100 clobbers the nucleus). It is ~511/512 B now. The parser CANNOT
grow there. The "grow agent_response to 2 sectors" plan (below) is DEAD.

REVISED PLAN (option a — capture-during-receive, parse-between-turns):
 - agent_response (512-hard): do the MINIMAL per-byte work only — detect fc_mode, CAPTURE the raw
   function_call bytes (call_id/name/arguments region) into fs_sector_buffer, and SUPPRESS render.
   Funded by deleting the inline-$ dimming (~35 B freed). No full parse here.
 - tool_call (roomy after the gut): PARSE the captured buffer between turns for name/call_id/args and
   dispatch to the kept $r/$w/$x executors (T4). This is where the parsing budget lives now.
 - This keeps the heavy parser out of the 512-capped receive phase. The loop-cache rebalance below is
   NO LONGER NEEDED (agent_response stays 1 sector); tool stays 2 sectors post-gut. Working set fell to
   ~25 after the gut (green, 5a017cbb).
 - OPEN: exactly what to capture in the 512-cap. Cheapest = capture the whole response's raw SSE into a
   buffer when fc seen, parse in tool_call. Or capture just the 3 fields via minimal key-detect. TBD.

### (dead — see blocker above) The loop-cache rebalance
`agent_response` (the scanner) is 1 sector and CANNOT hold the parser even after removing its $-dimming
(~30 B freed vs ~100+ B needed). So the parser needs `agent_response` to be 2 sectors. The working set
is 26/26 (dpi 1 + agent_request 3 + agent_api_stream 3 + agent_response 1 + tool 3 + K/link 15). To
give agent_response a 2nd sector WITHOUT raising loop_cache_max_sectors, SHRINK `tool` from 3→2 sectors
by deleting its $-text-scan front-end (T6): tool is 1076 B now (3 sectors); removing the scan drops it
under 1024 (2 sectors), freeing exactly the 1 sector agent_response needs. Net working set stays 26.
=> T3 (parser in agent_response, grown to 2 sectors) and T6 (delete tool_call's $-scan, shrinking it to
2 sectors) are ONE coordinated swap; T4 (structured-arg dispatch) reuses tool's kept $r/$w/$x executors.
This is why T3-T6 land together, not incrementally: it's a budget-neutral swap of old tool code for new.

## Decisions (resolved 2026-07-04)

1. **Argument granularity**: RESOLVED → full per-field structured args (read_mem/write_mem/exec with
   real JSON fields; env tools no-arg). Small keyed field extractor, not a general JSON parser.
2. **Transport**: RESOLVED (start) → stateless re-send + echo `function_call` + `function_call_output`
   items each turn (matches seed's current re-send-the-window model). `previous_response_id` chaining
   is a later optimization.
3. **T1 wire probe**: RESOLVED → SKIPPED. Design the parser from spec, defensively (see T1 above).
4. **Tool set**: RESOLVED → five tools incl. `save_env`/`load_env` (the `$s`/`$l` env tools), not just
   the three memory ops.
