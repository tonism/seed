# Build 10 — Minimal Tool Calling + Max Pool (attempts)

Running log (newest sections appended). Build 9 shipped (tag build-9); its log is in
`notes/old/build9-context-attempts.md`. Work branch: `build-10-work`.

## Direction (user priority order)

1. **Keys to the kingdom**: give the cloud agent the minimal primitives for full control of the
   machine — RAM **read / write / execute**. Three primitives ($r/$w/$x) compose into arbitrary
   code: $w a routine into RAM, $x to run it (any segment, any port, BIOS). The agent owns the
   crash ($x to bad code hangs the machine; reboot recovers — no sandbox, by design).
2. **Maximize pool space** (conversation window + user/agent arena). Was ~256 B at the 16K gate.

Constraints (carried in): resident nucleus is full (2 KiB at 0x1000, K crypto window pinned at
0x1800); cold phases stream from floppy into low scratch (0x0700/0x0900/0x0D00); the 0x0900
net-setup window is only 3.5 sectors (0x0900..0x1000); model held to ASCII (no JSON/UTF-8).

## 2026-06-05 00:45 (9e71bf5) — Tool calling MVP: cold $r/$w/$x phase

Grammar (ASCII, JSON-safe, hex, seg-0): `$r ADDR LEN` / `$w ADDR BYTES` / `$x ADDR`. A cold tool
phase (loaded by dpi at net_setup_phase_start, between turns with the TLS session idle-alive)
scans the conversation window for directives, executes each, appends a readable result line back
INTO the window (so it rides the Build 9 context path) + a dim on-screen echo, and neutralizes
the leading `$` so a re-scan won't re-fire. Near-zero resident cost (the executor is on floppy).
Bugs fixed before first green: scr_putc's wait_ticks clobbered cx; $x left scan-si on the stack +
destroyed flags before the CF test; scanner relaxed to fire on `$<verb> ` ANYWHERE (model prefixes
prose), neutralize only on a valid hex parse; splash two-digit ('0'+10=':'); grammar trimmed to
fit chunk-2. Validated end-to-end on 32K: write 41 42 43 -> read back -> model reported them; $x of
`mov ax,0xABCD; clc; ret` -> ax=abcd cf=0.

## 2026-06-05 01:02 (6136f66) — RAM detection (Lever A) in the loader

`int 0x12` in the loader -> capped seg-0 ceiling handed to CORE.SYS via the SEED magic (zero
nucleus reclaim). Pool scales from ram_top: **16K=256 B, 32K=16.6 KB, 64K=49 KB** (caps at 0xFFF0,
the seg-0 limit). 16K BASIC path + 32K direct unchanged.

## 2026-06-05 01:13 (6688d82) — Advertise the grammar; instant tool echo

Tool grammar advertised in the instructions ("RAM tools, hex: $r ADDR LEN read, ..."). Dropped
fast-typing for the tool echo (would drag on bigger machines writing large programs) — dim but
instant, like `compacting context`.

## 2026-06-05 02:55 (c1b047a) — Rework: shared scroll helper + packet DRY -> suppression

Reclaimed bytes (shared `scroll_text_area` BIOS-scroll helper + `out_dx_word` NIC port-pair DRY)
to fund streamed-command **suppression**: the renderer sets `compact_next` on a `$` and hides the
raw command to its newline (still stored in the window for the tool phase) — so the `$...` appears
exactly once, as the dim readable echo, never as the model's raw stream.

## 2026-06-05 05:27 (f9e5611) — Agentic loop + THE boot freeze (root-caused)

**Loop:** on a tool fire the tool phase arms `agent_loop_pending` + stages a continue directive
into dpi_input_buf; dpi auto-submits it next turn -> the model acts on the tool result and either
calls more tools (loop chains) or stops (no tool -> clears -> back to the user). Capped at
`agent_loop_max=8`. Flags live in low_phase_state (no resident cost), boot-cleared in
hardware_setup. The directive is "Continue; answer using the tool output above." — a bare
"continue" made the model keep tool-calling or fall silent.

**THE bug it exposed (the hard one):** the loop additions grew `agent_api_stream` to 1551 B, which
rounds up to **4 sectors** and, loaded at 0x0900, overwrote the **resident nucleus at 0x1000** ->
deterministic black screen + dim "0", NO splash. Looked like a logic bug; was a silent SIZE
overflow. The size assertions checked raw bytes (<=1792) not LOADED sectors, so the 4-sector phase
passed the build and only froze at runtime. Root-caused by bisection (data-shift boots -> +boot-
clear boots -> +loop tool_call boots -> +loop agent_request boots -> +loop agent_api_stream
FREEZES) and proved by tightening the assertion (it then errored). Fix: golfed the per-turn state
reset to `xor ax,ax` + word writes (-24 B -> 3 sectors) and tightened the X/D/C net-setup-window
assertions to the true loaded-sector bound. See memory `reference_phase_sector_overflow`.
Validated: 7/7 NIC matrix + 16K gate + 32K/64K direct boot; auto-continue confirmed firing (a `*`
probe at the loop hook) and chaining (model issued a second read off the first result).

## 2026-06-05 07:35 (4d1acb3) — Arena advertisement (completes priority 1)

Ledger now carries ` a@<hex>` = the runtime arena base (window base + live window length), so the
agent knows where it may safely $w a routine and $x it. Funded by an api_stream send-DRY helper
(`.send_app_record` DRYs the two identical chunk-2/tail TLS sends) + folding the auto-continue copy
length to the `agent_continue_len` constant (phase stays 3 sectors). **Arena-use test (the
capstone):** the agent read a@ from the ledger, `$w b8 34 12 c3` into the arena, `$x`'d it, and
reported `ax=0x1234` — a frontier model wrote x86 machine code, shipped it over TLS to a 1981 IBM
PC, which ran it and returned the result. (It also poked 0x0add on its own and hung the machine
once — the authority model in action; user chose to keep full unguarded control.)

## 2026-06-05 (post-4d1acb3) — Pool: defrag dead end, then the real lever

**Cache defrag = no win.** Researched provider key lengths: OpenAI ~165 (grew from 56 in 2024),
Anthropic ~108, OpenRouter ~73, Google 39, LiteLLM <70. `seed_key_len=192` is right-sized (can't
shrink without truncating keys); model cache 64 fits gateway `provider/model` names; 0x3400 is
live crypto so no reconnect-safe relocation space.

**The real Lever B — TLS receive buffer.** `tls_payload_buffer_len` was MSS-sized (1460), but Seed
advertises no TCP MSS so the server uses the 536-byte default, and TLS records fit well under it.
It sits below the pool floor, so shrinking it grows the pool 1:1 everywhere. Decoupled to **640**
(floor 592 = the dns_qname overlay at tls_rx_copy+512). Frees **820 B -> 16K pool 256 -> 1076
(4.2x), +820 B at every RAM level.** Failure mode = a server TLS record (cert/response) > 635 ->
receive fails (tls.inc:261). Gate boot at 640 ✓ (handshake Certificate + greeting fit); 7-NIC
matrix validating; one long-response check to follow. Caveat: only the configured agent's (OpenAI)
cert is exercised — other providers' handshake records untested; response records are tiny SSE
chunks, safe for all.

## Remaining

- **ESC-stop** (user-requested): stop the streaming render, drain to a TLS-safe point -> "stopped";
  double-ESC -> "panic stopped". Hard: needs ~8-25 B reclaimed in the validated transport hot-path
  (resident receive loop / response phase T, both near-full) — the riskiest reclaim left.
- **Tunable window/arena split**: agent-runtime needs the window-len knob advertised (more
  api_stream reclaim; phase at 0 margin) OR a boot config knob (clunky — config change = floppy
  re-flash). Pool is already maxed otherwise.
- **Release**: docs (builds.md checkpoint, architecture/memory/HANDOFF), splash already at build 10,
  final 7-NIC chat matrix, tag.

## Open design notes (reference)

- Grammar/authority: $x is a bare `call` (agent owns the crash; no sandbox — matches "minimal
  primitives, full control", confirmed by the user 2026-06-05). Screen echo = action only
  ("read from/write to/jump to <addr>"); the model-facing window carries the data (read bytes,
  $x AX/CF) via a window-only sink flag.
- Layout invariant: phases loaded at net_setup_phase_start (0x0900) must be <= 3 sectors (1536 B)
  or they clobber the resident at 0x1000. Assertions now check loaded sectors, not raw size.
