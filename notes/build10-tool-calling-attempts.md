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
receive fails (tls.inc:261). **Validated: gate boot ✓ + 7-NIC matrix 7/7 PASS at 640** (handshake
Certificate + streamed greeting on every NIC family). A separate long-response test was deemed
redundant (and skipped): the greeting is a real streamed response through the same buffer-bounded
receive path, and the server chunks SSE into same-sized records regardless of total length — a
longer response is just more records of the same size. A hypothetical >640 record would fail
gracefully (carry -> reuse-fail/reconnect), not crash. Caveat: only the configured agent's (OpenAI)
cert is exercised; other providers' handshake records untested; response records are tiny SSE
chunks, safe for all.

**NOT committed yet — keep-alive risk on a LONG render (caught the redundancy claim being wrong).**
The keep-alive gate keys off `tls_payload_buffer_len` (the constant I changed): it skips the ping
when (current record + buffered tail) reaches the buffer size, i.e. when the receive buffer is
~full. At 1460 that's rare (records <=640 << 1460, fires reliably); at 640 the buffer can be full,
so a long render's connection-hold could degrade -> 0D/F0. The matrix only ran short greetings (no
keep-alive), so it could NOT catch this. User ran into repeated 0D/F0 + "network setup failed" on
retries — but home internet is flaky, and "network setup failed" is the DHCP/ARP/DNS/TCP layer
(BEFORE TLS, the buffer plays no part), and the matrix proved the splash/handshake at 640 — so the
splash failures are very likely the internet, not 640. The long-render keep-alive remains the one
real, untested 640 risk. Plan: validate one long render at 640 on a stable connection; if the
keep-alive degrades, fix it with a dedicated ~70 B ping buffer carved FROM the 820 B win (user's
steer: "not everything needs to go to the pool" — spend some win on features/safety, rest to pool).

## 2026-06-05 (later) — 640 DISPROVEN; client record-size cap is dead on TLS 1.2 -> 1460 stands

640 passed the greeting matrix but FAILED a long essay: no response rendered, on a steady connection
(0 ICMP drops + an OpenAI-path probe). Cause is RECORD-SIZE, not keep-alive (the failure was at the
first chunk, before the keep-alive interval even engages); A/B confirmed it (1460 renders the essay,
640 does not). Measured the server's records directly with openssl/gnutls `s_client` to the real
endpoint: Cloudflare sends TLS records up to **~13 KB** to a fast reader — Seed only survives at 1460
because the 4.77 MHz drain flow-controls the server down to <=~1460. Tried to force a server-side cap
via a client extension; **DEAD on TLS 1.2**: openssl `-maxfraglen 512` ignored (still 13 KB records);
gnutls `--recordsize 512` (record_size_limit / RFC 8449) was NOT echoed in Cloudflare's ServerHello
(so not negotiated) and the connection was dropped right after the POST. record_size_limit only works
on TLS 1.3, which Seed's hand-rolled 1.2 stack doesn't speak. CONCLUSION: **1460 is the buffer floor;
the TLS-buffer pool lever yields no safe win.** Reverted to tcp_payload_max_len; finding written into
layout.inc so it is never re-chased. The essay test earned its keep (caught a latent correctness bug
the greeting-only matrix missed). Tooling: a background ping + an openssl/curl probe to the real
endpoint separates net flakes from product bugs (now in docs/testing.md Gotchas).

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

## Future avenues (user-flagged 2026-06-05, PARKED — not Build 10 scope)

- **Error recovery UX.** The 0D/F0 failure currently dumps to "network setup failed" / a frozen
  splash on retry. A graceful retry/backoff or a clearer state would help. Future.
- **Reconnect asymmetry: setup 100%, mid-chat flaky.** User observation: the TLS handshake /
  re-handshake succeeds ~100% during the initial splash-phase setup, but is markedly less reliable
  mid-chat (after a long render / a drop). The user's read — and it's a good one — is that this is
  a QUALITATIVE difference, not merely the ~15s Cloudflare-window race (else setup would also lose
  sometimes). Worth a real investigation later. Initial hypotheses to test:
  - Old-connection state: at setup there's no prior socket; mid-chat the dropped connection leaves
    server-side / TCP teardown state (TIME_WAIT, stale seq, half-open) the reconnect collides with.
  - Different trigger: setup is a clean cold start; mid-chat reconnect fires reactively after a
    failure (keep-alive missed / server idle-close / mid-render drop) — it may inherit that
    condition (e.g. the socket is already half-dead, or buffers hold stale cipher state).
  - Scratch reuse: mid-chat, more cross-turn state is live (window, caches, cipher seqs); confirm
    the reconnect path resets ALL of it (vs the pristine setup path).
  Cross-ref the Build 8 reconnect work (keep-alive 2b09f60, completion fallback 535de35) + memory
  `project_reconnect_reliability_byte_wall`.

## Build 11 curiosity items (user-flagged 2026-06-05)

- **TLS 1.3.** NOT a memory play: Cloudflare honors neither max_fragment_length nor record_size_limit
  on 1.2 OR 1.3 (verified - ServerHello/EncryptedExtensions echoes neither), so it buys zero buffer
  bytes, and it is a large risky rewrite of the hand-rolled 1.2 handshake. Park as a someday
  modern-stack/security item only.
- **Drop floppy reads during the chat loop on 32K+ machines.** Cache the cold phases in RAM (room
  exists at 32K+) so the loop doesn't re-read the floppy each turn - faster + quieter.
- **Detect a fast-enough machine -> turn on real (authenticated) crypto.** Seed skips the expensive
  server cert-chain + signature verification because the 4.77MHz CPU can't afford the EC verify - so
  the channel is ENCRYPTED but NOT AUTHENTICATED (MITM-exposed). RAM tier is already detected; add a
  CPU-speed probe and, on a fast enough machine (286/386 or a higher clock), enable full verification
  for a genuinely secure connection.

## Record-size flake - likely the chat-loop de-sync ROOT CAUSE (user hypothesis 2026-06-05, STRONG)

User asked: Cloudflare sends records bigger than our 1460 buffer - is THAT the chat flake (prompt left
with no response, de-synced)? Very likely YES. The early structural SSE records
(response.created/in_progress/output_item.added) measure ~1393 B - only **67 B under** the 1460
buffer. A slightly bigger one (Seed's system prompt echoed in the response object, more metadata)
tips over 1460; the receive HARD-fails (tls.inc:261/288, AEAD needs the whole record) ->
tls_fail_error -> response lost AND the TLS stream left mid-record -> de-sync -> next prompt fails too
until a clean reconnect. Matches the symptoms; "flaky not always" because the structural records sit
at the cliff edge. Plus rarer large records on long responses (server dynamic record sizing grows
with the congestion window). REFRAMES the buffer: razor-thin reliability margin, not a shrink
candidate. Fixes: (a) bigger buffer where RAM allows (costs pool; tight at 16K); (b) clean reconnect
on oversized record instead of de-syncing hard-fail (works everywhere - the error-recovery work);
(c) trim Seed's request so the echoed structural events stay small. VALIDATE FIRST: (a) host-side -
replicate Seed's exact request (system prompt included) via openssl, measure the structural-event
record size; (b) definitive - instrument the receive to log the max record across real chats, read
via $r. Likely the root cause behind tasks #11 (error recovery) + #12 (reconnect asymmetry).

MEASURED UPDATE (replicated Seed's exact request incl. the echoed instructions): the structural
records (response.created/in_progress) come in at ~1393 B - the server CHUNKS the response object
into ~1-MSS (~1393) records, so even instructions-bloated response.created is split; no single
structural record exceeds 1393. They FIT (67 B under 1460) - which is why Seed mostly works + the
1460 essay was rendering fine. The >1460 records appear only LATE (pos ~3000+) and only on FAST
connections (server grows records with the cwnd); Seed's slow 4.77MHz drain keeps the cwnd small, so
it likely stays ~1393. NET: the mechanism is real but the data leans AGAINST this being the PRIMARY
flake cause - it's a thin-margin fragility (a very long response or a smaller network MSS could tip a
late record over 1460), not a smoking gun. Primary chat flakes more likely the keep-alive/reconnect
path (#11/#12). DEFINITIVE test if ever needed: instrument the receive to log the max record across a
long chat, read via $r.
