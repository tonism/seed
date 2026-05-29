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

- `vm-net-3c501`: historical `5+5`; current WIP recovered short `5/5` and has
  multiple strict current long/follow-up passes, but current long was not yet
  completed to `5/5`.
- `vm-net-3c503`: short lane recovered to `5/5`; long lane is the active
  problem and is not stable.
- `vm-net-ne2k8`: strongest NE control; focused historical short+long `5/5`,
  current short spot pass.
- `vm-net-ne1k`: suspicious/regressed in current WIP; failures resemble 3c503
  short-loop failure family.
- `vm-net-novell-ne1k`: not proven equivalent to NE2K8; keep separate.
- `vm-net-wd8003e`: current short mostly healthy, not strict-clean because of
  harness capture noise; long needs current recheck.
- `vm-net-wd8003eb`: current short mostly works but has a first-prompt stall
  suspicion; long needs current recheck.

The immediate focus before this handoff was `vm-net-3c503` long.

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
