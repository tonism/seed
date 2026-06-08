# Build 11 — never-blank reconnect: design + nucleus-reorg plan (handoff)

Self-contained pickup doc. Branch `work/draining-fifo`.

## Status
- **DONE + committed (422697a):** RX buffer shrink 1460→592 via a SYN MSS option (`tcp_syn_mss=592`
  in layout.inc; data-offset 0x60 for the SYN in net_tx.inc `build_tcp_segment_frame`; 4-byte option
  in tcp_connect.inc `ne_transmit_tcp_syn`). Grew the chat pool ~868 B. Validated 7/7 NIC matrix +
  a multi-segment >592 app-data reply (coherent). The FIFO collapse + per-record verify + keystream
  fix are earlier on the branch (49fc3f9, ffaf80f).
- **BLOCKED:** never-blank reconnect-3x — needs a resident-nucleus structural reorg FIRST.

## Goal (user's exact UX — do not lose this)
"silent 3x retries show single `> reconnect` message. if this fails `failed` is appended so it reads
`> reconnect failed` and user is returned to DPI. If user sends message again, harness tries the same
reconnect loop again by writing `> reconnect`." Dim attr 0x08 (MDA→0x07), `> ` prefix.

## The wall (verified this session)
Resident nucleus (0x1000, 2048 B) is FULL: **2045/2048 used (~3 B free)** — the SYN MSS option ate the
prior slack. Already heavily golfed (net_phase shares exit epilogues; per-turn reset golfed "~24 B").
No clean relief exists:
- `print_char` (core render primitive) and `show_load_marker` (called by 7+ phases via
  `phase_call_res`) are both widely-used resident helpers — CANNOT remove. (A subagent scan proposed
  both; both verified bogus.)
- main.inc has no dead recap-compaction code; net_phase.inc is golfed.

## Budget need
- Retry loop **must** be resident (it's the orchestrator `prepare_agent_endpoint_path`, net_phase.inc):
  ~13 B (init `reconnect_retries=3` ~5 B + after the reconnect exchange `jnc/dec/jnz` ~8 B). The counter
  itself lives in `low_runtime_state` (NOT nucleus).
- Message FLAG-set is also nucleus (~4-5 B).
- → need ~15-18 nucleus bytes. The message RENDER can live in a phase (endpoint phase has slack:
  1-sector, padded to 512 @ core.asm:160-164).

## Reorg options to free ~15-20 nucleus B (fresh session: scan + pick; do NOT micro-opt-hunt golfed code)
1. **Move the MSS data-offset cost out of the nucleus (~6 B):** today `build_tcp_segment_frame`
   (net_tx.inc) does `test dl,0x02 / jz / mov al,0x60` (~6 B) to set data-offset 0x60 for the SYN.
   Move it to `ne_transmit_tcp_syn` (tcp_connect PHASE): patch the data-offset byte 0x50→0x60 AND
   fix the TCP checksum (the byte is the high byte of a header word: +0x1000 to the word → subtract
   0x1000 from the checksum, with end-around-carry fold) — a ~10 B phase-side fixup. Frees ~6 nucleus B.
2. **Relocate a single-phase-use resident helper into its phase:** scan callers of each resident
   function; any called from EXACTLY ONE phase context (unlike print_char/show_load_marker) can move
   there. Needs a caller-frequency scan.
3. **Reclaim a nucleus `db`/`dw` to the freed scratch:** the buffer shrink freed ~868 B of critical
   scratch (now pool, ~0x36xx). Move a nucleus-initialized var there via `equ` alias (+ boot-zero IF
   it's read-before-write; free if written-before-read). Verify read/write order per var.

Likely path: (1) + (2 or 3) to reach ~15-18 B.

## Implementation (after the relief)
1. **Retry loop** — net_phase.inc `prepare_agent_endpoint_path` (~lines 24-78). Flow today:
   reuse → (fail) → rebuild (agent_request ~line 49) → `.connect_new_session` (endpoint→client_hello→
   cache→tcp_connect→tls_probe) → `.stream_and_exchange` → fall to `.restore`. Change: init
   `reconnect_retries=3` at the top (covers cold + reuse paths); label the rebuild point
   `.rebuild_and_connect` (~line 49); after the reconnect's `.stream_and_exchange` (~line 67):
   `jnc .restore` (success) / `dec byte [reconnect_retries]` / `jnz .rebuild_and_connect` (retry).
2. **`> reconnect` message** — render in the FIRST reconnect phase (agent_endpoint.inc, the endpoint
   phase) so it shows BEFORE the ~14.5s handshake. (NOT agent_api_stream/X phase — that runs AFTER the
   handshake, too late.) Flag-gated: a `reconnect_msg` byte in low_runtime_state, set by the retry loop;
   a "rendered" sub-flag so it shows ONCE, not per-retry; gate OFF on the cold first connect (endpoint
   phase also runs cold). Render dim via print_char (cursor-aware) or the dim-render style. Template:
   `agent_api_stream_show_compacting` (agent_api_stream.inc ~526) — but it's ROW-START based (di from
   cursor_row), so an in-place append needs cursor-COL awareness (print_char has it).
3. **`failed`** — on total failure (loop exhausts), make it read `> reconnect failed`. DECIDE:
   (a) clean two-line form — a second dim line `> reconnect failed` via the row-start render (SIMPLEST,
   recommended), or (b) true append — cursor-col render, needs `> reconnect` to leave the cursor with
   no trailing newline + a conditional newline on success (more intricate). The render is post-loop
   (no phase runs then): a sacrificial endpoint-phase call, or a small resident render if budget allows.
4. **Cursor on success** (only if option b): if `> reconnect` had no trailing newline, the response
   must start on a fresh line — add a conditional newline (agent_response phase start, or the success path).

## Validation
- build: nucleus ≤2048 (core.asm:38), phases ≤ their sector windows.
- FORCED-failure test: temporarily make `agent_api_exchange` fail N times → confirm the 3x retry,
  `> reconnect`, `> reconnect failed`, the DPI return, and that a re-prompt re-runs the loop. Remove the force.
- 7-NIC matrix: `tools/run-basic-bootstrap-86box.py` single canary first, then
  `tools/run-basic-bootstrap-matrix.py --jobs 1`. Plus a LIVE reconnect (idle past keep-alive / kill session).

## Key refs
net_phase.inc (`prepare_agent_endpoint_path`); agent_endpoint.inc (endpoint phase);
agent_api_stream.inc ~526 (dim-render template); data.inc (`low_runtime_state` for flags/counter;
`compacting_msg` is the flag pattern to mirror); core.asm:38 (nucleus assert), :160 (endpoint ≤512);
layout.inc (`tcp_syn_mss`). One-86Box-at-a-time; `pkill -f 86Box` before each canary.
