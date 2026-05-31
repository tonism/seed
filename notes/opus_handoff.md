# Opus handoff: Build 8 NIC chat-loop stabilization

Created: 2026-05-29

This is a focused review brief for a fresh model/chat. The durable attempt log is
`notes/default-prompt-interface-attempts.md`; read that from the
`2026-05-18T16:48+03:00` entry onward. Also read `notes/nic_timing_lanes.md`.
This file is only a short map of the current problem and where to look first.

## Scope

Work only on stabilizing Build 8 repeated chat loops for the original 16 KiB
ROM BASIC NIC profiles:

- `vm-net-3c501`
- `vm-net-3c503`
- `vm-net-ne1k`
- `vm-net-ne2k8`
- `vm-net-novell-ne1k`
- `vm-net-wd8003e`
- `vm-net-wd8003eb`

Do not work on roadmap, docs polish, memory-ocean/defrag, Build 9 tool calling,
or new product features. Keep changes scoped to repeated prompt/response loop
reliability.

## Product gate

Each NIC profile needs a stable individual lane before unifying shared paths.
The target gate per profile is:

1. Short loop: greeting plus `Say one.` through `Say five.`, all answered and
   returning to DPI prompt.
2. Long loop: greeting, then:

   ```text
   What do you think if I created a non-OS bootstrapped harness that gives you direct agentic access to 16KB 8088 RAM? R/W/jump.
   ```

   followed by `Say done.` and usually `Say ok.`, returning to DPI prompt.
3. Repeat short and long gates `5/5` for each profile.
4. Harness OCR should be captured for every run.

Clean red fatals are failures. Active long rendering is not a failure. A prompt
return with no response is suspicious and needs pcap/OCR context.

## Testing workflow

Use the ROM BASIC harness for Build 8 compatibility. The normal profile gate is
the 16 KiB original-speed ROM BASIC path, not faster ad hoc profiles.

General rules:

- Prefer harness OCR/screen-oracle output over screenshots. Use `--no-screenshot`
  by default unless a screenshot is explicitly needed.
- `--screen-oracle` captures the 86Box window without focusing it and prints OCR
  lines. This is the default evidence source for automated runs.
- Avoid `--foreground-launch` and `--restore-focus` unless you intentionally want
  86Box to take focus. The default `pidkeycode` input mode posts keys directly
  to the 86Box process.
- Use pcap-backed focused single-profile runs when investigating a failure.
- Use serial `5/5` matrices after a focused fix looks plausible.
- Use broad all-family matrices only at stability checkpoints because they are
  expensive and can take many hours.
- If a long answer is still actively streaming/rendering, do not kill it and
  call it a product failure. Increase the timeout or use manual observation.

Manual VM session, no automatic close:

```sh
python3 tools/run-basic-bootstrap-86box.py \
  --profile vm-net-3c503 \
  --no-build \
  --long-running \
  --no-screenshot
```

Semi-automated run that still leaves the VM open for manual inspection:

```sh
python3 tools/run-basic-bootstrap-86box.py \
  --profile vm-net-3c503 \
  --no-build \
  --leave-running \
  --screen-oracle \
  --no-screenshot \
  --post-dpi-text 'What do you think if I created a non-OS bootstrapped harness that gives you direct agentic access to 16KB 8088 RAM? R/W/jump.' \
  --post-dpi-text 'Say done.' \
  --post-dpi-text 'Say ok.' \
  --post-dpi-wait 120 \
  --post-dpi-gate-timeout 1200 \
  --capture-delay 2
```

Classify an already-open VM without launching a new one:

```sh
python3 tools/run-basic-bootstrap-86box.py \
  --profile vm-net-3c503 \
  --oracle-only \
  --fail-on-screen-oracle
```

Run order for a suspected fix:

1. `make -B inspect`.
2. One focused pcap-backed long run for the target profile.
3. If that passes, serial long `5/5` for that profile.
4. Serial short `5/5` guardrail for that profile.
5. Only then consider nearby families or the all-family matrix.

## Current working rule

Stabilize per-NIC lanes first. Do not keep "fixing" one NIC by perturbing a path
that is known-good for another. Unify timing/order only after the replacement
shared rule passes the affected profiles.

The project has had focused stable lanes at different times, but no documented
single code state where all seven profiles passed Build 8 chat-loop `5+5`.

## Current approximate status

Read `notes/nic_timing_lanes.md` for the fuller table. Current practical state:

**2026-05-30 update (overnight, NO code changes — only notes/memory):** 3c503
stabilized + committed (`4162147`); NE2K8 stabilized and WD8003e smoke-validated
on that same build with no NIC-specific changes. The shared fixes are NIC-agnostic.
The dominant residual is the shared `0D/12` handshake flake (see below). Nothing
committed since `4162147`.

- `vm-net-3c501`: regression smoke `4/4` on `4162147` (2 long + 2 short) — the
  commit removed its 512-byte window special-case and 3c501 (the most-different
  NIC) did NOT regress. Optionally complete a strict long `5/5`.
- `vm-net-3c503`: STABLE + committed (`4162147`); long + short loops confirmed.
- `vm-net-ne2k8`: STABLE on `4162147`, no NE-specific changes. 7 clean long +
  `5/5` short overnight (false-green-checked); residual = the shared `0D/12`.
- `vm-net-ne1k`: suspicious/regressed in earlier WIP; not re-verified on `4162147`.
- `vm-net-novell-ne1k`: not proven equivalent to NE2K8; keep separate.
- `vm-net-wd8003e`: smoke `4/4` (2 long + 2 short) on `4162147`, no WD-specific
  changes; one long rode out a ~5.5 min intermittent-loss window. Optionally
  extend to strict `5/5`.
- `vm-net-wd8003eb`: not re-verified on `4162147`; earlier first-prompt-stall
  suspicion stands until rechecked.

Shared `0D/12` finding (now the dominant non-environmental failure: ~20% of long
runs, network up, recoverable via the on-screen retry but a gate fail): the
(re)handshake Certificate receive times out. `tcp_receive_payload`
(`transport.inc:1`) polls with a bounded budget (`tcp_payload_wait_count`), so a
single late cert segment aborts the handshake (`tls.inc:219-345`) → `0D/12`. This
is a SEPARATE path from the always-decrypt data-path fix (`tls.inc:1032`), so it is
neither a regression nor covered by it. Hardening is SHARED (touches
3c503/3c501/NE/WD — validate 3c503 first): raise `tcp_payload_wait_count`, and/or
auto-retry the reconnect handshake once on `0D/12`. Not changed overnight.

The immediate focus before this handoff was `vm-net-3c503` long; that is now done.

## Important evidence

Do not start by blaming request construction or OpenAI packet ordering unless
new evidence contradicts this:

- Earlier pcaps showed later prompts do leave the VM and OpenAI/Cloudflare
  replies.
- Multiple decrypted pcaps show complete HTTP 200 Responses streams with valid
  ChaCha20-Poly1305 tags.
- Failures usually happen locally at receive/decrypt/response-parser
  completion, long-record tail preservation, ACK/render pacing, or reconnect
  readiness after a long stream.

OpenAI streaming shape expected by the current parser:

- HTTP response headers, then chunked SSE stream.
- Text arrives in `response.output_text.delta` events.
- Text item can end with `response.output_text.done`.
- The whole response ends with `response.completed`.
- HTTP transport ends with `0\r\n\r\n` zero chunk, and sometimes TLS
  close/FIN follows.

Do not assume event names are contiguous inside one TLS record. We saw
`response.output_text.done` split across records on 3c501, causing a completion
miss until parser logic changed.

## Key files to inspect

- `targets/ibm_pc_5150/boot/core/tls.inc`
  - TLS final flight ordering.
  - Application-data send before/after server Finished.
  - Oversized application-record decrypt/parse path.
  - Following TLS record tail preservation.
  - Reconnect/key-schedule readiness after close.
- `targets/ibm_pc_5150/boot/core/agent_api.inc`
  - Main receive/render/ACK loop.
  - `api_stream_completed` handling.
  - Per-family ACK-before-render vs render-before-ACK.
  - Failure fallback rules.
- `targets/ibm_pc_5150/boot/phases/agent_response.inc`
  - HTTP/SSE parser.
  - `_text.done`, `.done`, `response.completed`, and zero-chunk detection.
  - Response text rendering and DPI completion transition.
- `targets/ibm_pc_5150/boot/phases/agent_api_stream.inc`
  - Ready/follow-up request body, split prompt tail, and prompt preservation
    across reconnect.
- `tools/run-basic-bootstrap-86box.py`
  - Harness OCR gates and long-run classification.
- `tools/run-basic-bootstrap-matrix.py`
  - Matrix orchestration. Use only after a focused lane looks stable.

## Known/rejected traps

- Do not re-add the 3c503 "large record after any text means success" shortcut.
  It produced false green runs by visibly truncating long answers.
- Do not force split-body sending for short 3c503 prompts. Short prompts that
  fit should be sent as one complete application record; forcing split caused
  missing-tail/server-wait failures.
- Do not blindly move 3c503 application send after server Finished. A pcap
  showed Cloudflare FIN/RST races in that shape.
- Do not blindly move 3c503 key schedule earlier. That regressed cold greeting
  setup.
- Do not assume `vm-net-novell-ne1k` can share NE2K8 timing until it passes.
- Do not use broad matrix runs as the first diagnostic step; they are expensive.
  Use focused pcap-backed single-profile gates first.

## Current 3c503 long investigation

As of 2026-05-28, after rejecting the truncating shortcut, 3c503 long had two
clean current long/done/ok/DPI passes:

- `/private/tmp/seed-3c503-long-noskip-20260528T2030.pcap`
- `/private/tmp/seed-3c503-long-noskip-2-20260528T2048.pcap`

It still was not `5/5`.

On 2026-05-29 a pcap-backed 3c503 long repro was run after zero-chunk scanning
changes:

- `/private/tmp/seed-3c503-long-zerochunk-repro-20260529T0820.pcap`

The VM rendered a long answer, then sat with HTTPS in `CLOSE_WAIT` instead of
returning to DPI. Decryption showed the server sent complete terminal records:

- many `response.output_text.delta` records
- `response.output_text.done`
- `response.completed`
- final `0\r\n\r\n`

So the wire response completed; Seed missed local completion/drain.

An experimental WIP then changed `agent_api.inc` so 3c503 split/large responses
could treat `api_stream_completed == 2` as success and force reconnect. A
focused gate then failed earlier/cleanly with `0D/F0`:

- `/private/tmp/seed-3c503-long-textdone-success-20260529T0835.pcap`

The OCR/debug trace included `CPFSAT`, which may imply the response parser saw
a completion marker (`C`) and then entered split/follow-up request path, but the
screen did not show the follow-up prompt before the fatal. First next step:
decrypt this pcap and determine whether failure happened before text-done,
after text-done but before exchange success, or after success during reconnect.

Suggested command:

```sh
python3 /private/tmp/decrypt_seed_tls.py /private/tmp/seed-3c503-long-textdone-success-20260529T0835.pcap --contains delta > /private/tmp/seed-3c503-long-textdone-success-20260529T0835.decrypt.txt
tail -n 160 /private/tmp/seed-3c503-long-textdone-success-20260529T0835.decrypt.txt
```

If the decrypt script is missing, regenerate a focused pcap rather than guessing.

## Debug/error notes

OCR often confuses `0` with `@` or `o`; `@D/F0` is usually `0D/F0`.

Useful observed fatal suffixes:

- `0D/12`: generic agent setup/exchange failure, often before completing the
  expected receive/parser state.
- `0D/F0`: `agent_api_exchange` failure path in current WIP.
- `0D/E8`: seen around TLS append/receive drain failures in earlier WIP.
- `0D/FE`: seen when returning too early after semantic completion left trailer
  state poisoning the next request.

Common debug trail markers:

- `P`: prompt/request path activity.
- `B`: request build completed.
- `F/S/A/T`: split ready-tail path entry/tail/build/send.
- `d`: text delta/render activity in long streams.
- `C`: completion marker seen by response parser.
- `Z`: zero chunk was previously traced in some attempts, but may not exist in
  current code.

Confirm marker meanings in current source before leaning heavily on them.

## Build/test commands

Build and inspect:

```sh
make -B inspect
```

Focused 3c503 long gate:

```sh
python3 tools/run-basic-bootstrap-86box.py \
  --profile vm-net-3c503 \
  --no-build \
  --screen-oracle \
  --fail-on-screen-oracle \
  --no-screenshot \
  --pcap /private/tmp/seed-3c503-long-review.pcap \
  --pcap-report-filter 'tcp port 443' \
  --pcap-max-lines 100 \
  --post-dpi-text 'What do you think if I created a non-OS bootstrapped harness that gives you direct agentic access to 16KB 8088 RAM? R/W/jump.' \
  --post-dpi-text 'Say done.' \
  --post-dpi-text 'Say ok.' \
  --post-dpi-wait 120 \
  --post-dpi-gate-timeout 1200 \
  --capture-delay 2
```

Focused 3c503 short guardrail:

```sh
python3 tools/run-basic-bootstrap-matrix.py \
  --profiles vm-net-3c503 \
  --repeat 5 \
  --jobs 1 \
  --artifact-dir /private/tmp/seed-matrix-3c503-short-review \
  --no-build \
  --run-timeout 900 \
  -- \
  --screen-oracle \
  --no-screenshot \
  --post-dpi-text 'Say one.' \
  --post-dpi-text 'Say two.' \
  --post-dpi-text 'Say three.' \
  --post-dpi-text 'Say four.' \
  --post-dpi-text 'Say five.' \
  --post-dpi-wait 60 \
  --post-dpi-gate-timeout 420 \
  --capture-delay 2
```

Only run the broad all-family matrix once a focused lane looks stable enough to
justify the time.

## Requested review posture

Please act as a bug reviewer and stabilization engineer:

- Read the notes and current diff before changing code.
- Prioritize concrete bugs in receive/decrypt/parser completion, TLS record
  tail preservation, and per-NIC timing/order.
- Keep 3c501 and 3c503 lanes isolated unless there is strong evidence a shared
  change preserves both known-good shapes.
- Prefer one focused pcap-backed hypothesis at a time.
- Record every meaningful attempt in `notes/default-prompt-interface-attempts.md`
  and update `notes/nic_timing_lanes.md` when a lane changes.

## TLS session resumption — implementation plan (2026-05-30)

GOAL: TLS 1.2 Session-ID resumption so a reconnect skips the ~7s ECDHE -> abbreviated
handshake ~1-2s (just the key_block PRF) -> within Cloudflare's ~7.5s handshake timeout.
Fixes the post-long reconnect EMPTY + the reconnect 0D/12 (same root). Cold handshake
unchanged.

FEASIBILITY (confirmed): api.openai.com supports pure Session-ID resumption — openssl
-reconnect -no_ticket -> 5/5 "Reused", server assigns Session-ID 910087CE...; reconnect
hits the same Cloudflare IP. ServerHello session-id is at si+43 (len) / si+44 (bytes).

DESIGN (code-grounded, flag-gated so the cold/full path is byte-for-byte unchanged):
 1. Session cache (persistent ~80B, survives the next handshake): cached_session_id[32]
    + cached_master_secret[48] + session_valid flag. Needs space NOT clobbered by the
    handshake (tls_master_secret/tls_server_random are per-handshake) -> find/reclaim in
    data.inc; assess LINK-window byte budget first (likely the gating constraint).
 2. ClientHello (phases/tls_client_hello.inc, the `tls_client_hello_after_random` db 0 =
    empty session_id at line 141): if session_valid, emit len=32 + cached_session_id;
    else len=0 (unchanged). Adjust the record/body/handshake length fields (+33).
 3. ServerHello parse (tls.inc tls_wait_for_server_hello ~159): read server session_id
    (si+44, len si+43); if == cached_session_id -> set resuming=1; else resuming=0 (full).
 4. tls_probe_server: if resuming -> ABBREVIATED flow: skip cert/SKE/ServerHelloDone/CKE/
    ECDHE; restore cached_master_secret -> hmac_prepare_current_key_context (tls.inc:562-
    564) -> tls_prepare_key_block (key block from restored master_secret + NEW randoms,
    runs as-is); then receive server CCS+Finished, verify, send client CCS+Finished.
    NOTE order flips vs full (server sends Finished first on resume). Transcript hash =
    ClientHello+ServerHello only. Else -> full flow (current, untouched).
 5. After a FULL handshake: copy server session_id + tls_master_secret -> cache; set valid.
FLAG-GATE: a build define (e.g. TLS_RESUME) + the session_valid runtime gate; resume taken
ONLY when valid AND the server echoes the id. Cold/first handshake always full -> no
regression to the critical path. Boot 0D/12 (cold) is unaffected (cold is always full).
BYTE BUDGET: resume code (~250-450B) + 80B cache in a LINK-window-constrained resident
area -> MUST assess + probably reclaim bytes before it fits. Prerequisite.
TEST: reconnect harness (--post-dpi-idle >keep-alive ~540s, OR the post-long sequence) +
pcap -> confirm the 2nd handshake is SHORT (no cert flight, ~1-2s) and the response renders;
cold greeting unchanged; repeat across 3c503/NE2K8/WD8003e/3c501. Grade by done/ok responses.
RISK: critical-path TLS state-machine change; a bug breaks ALL connectivity and needs many
(minutes-long) runs to validate. The flag-gate protects the cold path but the resume path
itself must be exercised + verified before trusting it.

### Session resumption — concrete byte-budget / memory findings (2026-05-30)

The design above is complete + feasible, but the IMPLEMENTATION is gated by two
critical-path constraints I scoped out:

1. PERSISTENT CACHE (80B: session_id 32B + master_secret 48B). The current
   tls_master_secret/tls_server_random OVERLAY the seed_* config arena
   (data.inc:266, reused after the request build) -> per-connection, overwritten
   each handshake -> cannot be the cache. The persistent regions are densely
   overlaid: high_tls_persistent (0x3400, the session keys - re-derived each
   handshake, key-block overlays it) and chat_*_cache (data.inc:344-347, the
   ready-path config cache). Placing a NEW 80B region that survives "after a full
   handshake -> next reconnect's ClientHello+key-block" needs a careful overlay
   analysis (candidate: extend the chat_*_cache region if space exists before the
   next boundary; verify against the data.inc collision %if guards).
2. K-PHASE RECLAIM (~100-200B). The resident TLS handshake phase ends exactly at
   0x3400 (largest-phase-end). The abbreviated-flow GLUE is modest because it
   REUSES tls_prepare_key_block + the server-Finished receive/verify + the
   client-CCS+Finished send (just reordered: server-first) + the master_secret
   hmac-context tail (tls.inc:562-564). Resume-detection lives in
   tls_wait_for_server_hello (compare server session_id at si+44/len si+43 to the
   cache). The branch is one `cmp [tls_resuming],1 / je .resumed` after line 20.
   Still ~100-200B over budget -> reclaim candidate: collapse the CKE early/late
   family gate (tls.inc:30-56) to early-CKE-for-all (removes the late path), but
   that changes NE2K8/WD8003e's full handshake -> must re-validate them.
   The ClientHello session_id change is in the tls_client_hello PHASE (low_scratch,
   NOT the byte-full K phase), so that part is free of the K-phase wall.

IMPLEMENTATION ORDER (flag-gated; test the COLD greeting after every build to
protect the critical path): (a) reclaim K-phase bytes + carve the 80B cache;
(b) cache session_id+master_secret after a full handshake; (c) ClientHello sends
the cached session_id (gated); (d) ServerHello resume-detect; (e) .resumed branch
calling the reused fns in resume order; (f) validate with the reconnect harness
(pcap: 2nd handshake short ~1-2s, response renders) + cold no-regression x4 NICs.

### 2026-05-30 update - stopgap shipped; full retry blocked on byte-reclaim
- SHIPPED (committed): agent_api empty->carry stopgap. Silent post-long empty eliminated
  (validated 3c503: no-regression 3/3; post-long 2/3 render, 1/3 clean 0D/12, 0 silent).
- The full bounded reconnect retry (universal fix incl. hours-idle) is implemented +
  cold-safe in notes/net_phase_retry_draft.inc but OVERFLOWS the link window by ~15-20B
  (net_phase shares the 0x3400 crypto ceiling) - SAME byte wall as resumption.
- THE unlock for both retry and resumption: reclaim ~15-20B in crypto/tls/agent_api
  (delicate, focused effort), then apply the retry draft.

## ============================================================
## NEXT SESSION — BUILD: keep-alive + probe (the proven fix)
## ============================================================
## (2026-05-31; hand-off after the diagnosis was proven. Jump straight to the build.)

### THE PROVEN PROBLEM (packet-level, no longer a hypothesis)
After a long answer, the connection dies: the ~11min 8088 render idles it past Cloudflare's
**400s** keep-alive, so the server FINs it (pcap: cold conn lived 482s then server FIN). So the
next prompt MUST reconnect. The reconnect handshake is the 8088's **~14.7s of crypto = TWO ~7s
P-256 scalar mults** (ECDHE ephemeral key-gen + shared-secret). The server FINs each reconnect at
**~15s**. So the handshake RACES the ~15s window — a coin-flip → ~25-75% of post-long follow-ups
fail. PCAP EVIDENCE (filter to Cloudflare 162.159.0.0/16 to escape the Mac's heavy background
:443 noise): success conn computed gaps +7.15s,+7.54s, done ~14.7s, FIN 17.5s (made it);
fail conn done ~15.0s, server FIN+RST at exactly 15.0s (missed it).

### LOCKED ARCHITECTURE (the user agreed)
Reuse-while-engaged (connection stays alive -> reuse, snappy, NO handshake) + reconnect-after-idle
(slower reconnect after hours = acceptable). Two pieces:
 1. KEEP-ALIVE during render: periodic request-ping (every <400s) inside agent_api_exchange's
    receive+render loop, to keep the SERVER's connection alive through the long render -> next
    prompt reuses it. (A TCP keep-alive does NOT reset Cloudflare's idle - MEASURED; needs an
    HTTP-request-level ping.) TRICKY PART: send the ping to the server THROUGH the SLiRP proxy
    mid-render and drain its reply (the proxy buffers; the ping-response arrives after the answer).
    SUGGESTION: first measure whether a partial request (a bare CRLF) resets Cloudflare's idle -
    much simpler than a full request+drain if it works.
 2. PROBE (check-first): before sending the real request, a lightweight liveness check -> reuse if
    alive, reconnect if dead. Replaces today's OPTIMISTIC reuse (net_phase sends the real request
    on a maybe-dead socket, discovers death via a slow receive-timeout).

### THE BYTE-WALL SOLUTION (critical - this is what makes it viable where resumption wasn't)
The resident LINK window is FULL at 0x3400 ("LINK window overlaps high crypto scratch"). ANY new
resident code overflows. PUT THE NEW CODE IN LOADED PHASES (load_core_window / call_core_phase),
NOT the resident link window: PROBE -> the tcp_connect phase (already loaded for connects);
KEEP-ALIVE -> the response/render phase. This sidesteps the 0x3400 wall.

### CONCRETE DESIGNS
- PROBE: TCP keep-alive segment (seq = tcp_local_seq-1, ACK flag, len 0) -> transmit -> receive
  (short timeout) -> read flags at [ne_tx_frame + tcp_offset + 13]: RST(0x04)=dead, ACK(0x10)=alive,
  timeout=dead. Model the flag-parse + connection-match on parse_tcp_synack (tcp_connect.inc:623).
- net_phase: replace the optimistic reuse (current .ee_send path) with: if session flag set, load
  tcp_connect phase + call probe -> alive: reuse(send); dead: reconnect. (Probe-first.)
- KEEP-ALIVE: in the receive+render loop, track BIOS tick [0x046c]; every <400s send the ping +
  drain. Validate by pcap: post-long should show ONE connection (no reconnect SYN) -> reuse.

### CURRENT STATE
Branch work/default-prompt-interface-rebuild. COMMITTED: bb01581 (stopgap agent_api empty->carry =
silent post-long empty gone) + 269cb28 (reconnect-send fix + --post-dpi-idle harness) + 4162147.
UNCOMMITTED: net_phase.inc has a simplified bounded-retry (.ensure_and_exchange loop, max 8, relies
on agent_api's carry). Validated: short 3/3 no-regression; post-long ~75% recovery (3/4) but WEAK
(each failed attempt ~2min so it barely gets a few tries; user doubts it). For the keep-alive+probe
build: revert net_phase to bb01581 for a clean base (the retry is superseded by reuse), OR keep as a
backstop. Full retry draft committed at notes/net_phase_retry_draft.inc.

### KEY FACTS / TEST RECIPE
- Cloudflare idle=400s exact; TCP keep-alive does NOT extend it; reconnect handshake window ~15s.
- Test: post-long = the "16kb 8088 ram ABI design" prompt -> "say done" -> "say ok"; ~12min/run;
  ~25-75% post-long fail. Harness: python3 tools/run-basic-bootstrap-86box.py --profile vm-net-3c503
  --no-build --screen-oracle --foreground-launch --post-dpi-gate-timeout 900 --post-dpi-text "...".
  pcap: --pcap FILE --pcap-filter "tcp port 443" --pcap-iface en0, then analyze with
  `tcpdump -nttr FILE 'net 162.159.0.0/16 and (tcp[13]&0x07!=0 or tcp[13]&0x12=0x12)'`.
- One 86Box at a time (pkill -9 -f 86Box first). Grade by rendered tokens, not harness exit code.
