# Build 8 NIC timing lanes

This is a working engineering note for the Build 8 chat-loop stabilization.
Keep it factual and update it when a NIC lane changes. The purpose is to avoid
rediscovering or accidentally erasing per-card timing requirements.

Do not treat a shared path as correct just because it works for one NIC family.
When changing TLS final-flight, request send, receive ACK/render pacing, large
record handling, or post-long-response reconnect behavior, check the affected
lanes here first and update the evidence after testing.

## Current lane inventory

| Profile | Lane state | Best-known evidence | Current next step |
| --- | --- | --- | --- |
| `vm-net-3c501` | Regression-smoke `4/4` on the committed shared build (4162147) - its 512B window special-case was removed by that commit and 3c501 (el1 single-buffer, render-before-ACK, the most-different NIC) did NOT regress. Historical `5+5`; current strict long was paused before `5/5`. | `2026-05-21T02:47`: short `5/5` at `/tmp/seed-matrix-3c501-short-presendrx-20260521T0123`; long `5/5` at `/tmp/seed-matrix-3c501-long-presendrx-20260521T0153`. `2026-05-26T00:05`: current short `5/5` at `/private/tmp/seed-matrix-3c501-short-ckefirst-20260525T2340`. `2026-05-27T06:31`: pcap evidence for split `output_text.done` causing long completion miss; parser now keys on `response.completed`. `2026-05-27T08:42`: strict current long/follow-up pass at `/private/tmp/seed-3c501-long-followup-windowonly-gatefix-20260527T0835.pcap`. `2026-05-27T09:39`: two strict passes in `/private/tmp/seed-matrix-3c501-long-windowonly-20260527T0842`, plus one strict pass in `/private/tmp/seed-matrix-3c501-long-windowonly-gatefix-20260527T0920`; paused before completing `5/5`. `2026-05-30T05:21`: regression smoke `4/4` on 4162147 (2 long + 2 short, false-green-checked; long-2 rode out 17 ping timeouts). Dir `/private/tmp/seed-3c501-smoke-20260530T043946`. | Shared changes (incl. the window removal) did NOT regress 3c501. Optionally complete a strict long `5/5`. |
| `vm-net-3c503` | Current short lane recovered; current long lane is not stable. | `2026-05-24T21:45`: focused five-short-prompt pass at `/private/tmp/seed-3c503-short5-largeparse-20260524T2138.pcap`. `2026-05-25T08:34`: focused long `5/5` at `/private/tmp/seed-matrix-3c503-long-postfix-20260525T0709`, plus short control pass. `2026-05-27T11:12`: current short serial `0/5` under `/private/tmp/seed-matrix-other-short-serial-20260527T0958`, failures `0D/12` cold and likely `0D/F0` after `Say two.`. `2026-05-27T13:48`: scoped short-inline fix passed one pcap-backed focused run at `/private/tmp/seed-3c503-short-inline-20260527T1305.pcap` and serial short `5/5` at `/private/tmp/seed-matrix-3c503-short-inline-20260527T1315`. `2026-05-28T18:15`: manual-assisted current long recheck had two passes, then run 3 failed mid long response stream with `0D/F0`. | Investigate 3c503 long receive/drain/parser completion or long-stream pacing; do not call the long lane stable. |
| `vm-net-ne1k` | Regressed/suspicious in current WIP. Strong historical evidence, but current serial short runs hit the same failure family as 3c503. | `2026-05-20T15:50`: short profile passed and long matrix was `5/5`. `2026-05-22T13:29`: mixed later matrix, including long full-loop passes but not clean all-run stability. `2026-05-27T11:12`: current serial short attempts under `/private/tmp/seed-matrix-other-short-serial-20260527T0958` failed after `Say one.`/`Say two.` with likely `0D/F0`; one later run had corrupted BASIC input and is invalid. | Recheck with a reliable serial harness, then compare with NE2K8 because NE1K no longer looks equivalent. |
| `vm-net-ne2k8` | STABLE on the committed shared build (commit 4162147), no NE-specific changes. `5/5` short + 7 clean long (exceeds `5/5`). Residual: intermittent `0D/12` large-Certificate-receive flake on the (re)handshake (~20% of long runs, network up, NIC-agnostic, pre-existing, retryable). | `2026-05-20T12:56`: focused short `5/5` and long `5/5`. `2026-05-23T23:38`: focused long plus `Say done.` follow-up pass at `/private/tmp/seed-ne2k8-long-directrender-rerun-20260523T2302.pcap`. `2026-05-30T03:49`: overnight validation on 4162147 - 10 long attempts, 7 clean PASS (full long + `Say done.`->done + `Say ok.`->ok + DPI return, false-green-checked on long-3), `5/5` short; 3 fails = 1 wifi outage + 2 network-up `0D/12`. Dirs `/private/tmp/seed-ne2k8-{full,rerun,char}-*`, ping `/private/tmp/seed-overnight-ping.log`. | DONE for NE2K8 itself. The `0D/12` is a SHARED TLS-layer item (large Certificate receive on handshake; same large-record family as the data path the always-decrypt fix covered) - do not gate NE2K8 on it; address shared with the user. |
| `vm-net-novell-ne1k` | Not stable in current WIP. | `2026-05-20T15:50`: serial short rerun passed, long serial rerun was `3/5`. `2026-05-22T13:29`: mixed results with one strong long full-loop pass. `2026-05-27T11:12`: current one-run short scan timed out after `Say two.` with success-shaped screen and no response under `/private/tmp/seed-matrix-remaining-short-scan-20260527T1022`. | Treat separately from NE until proven equivalent. Needs reliable focused short and long gates. |
| `vm-net-wd8003e` | Smoke-validated on the committed shared build (4162147), no WD-specific changes: 2/2 long + 2/2 short, incl. a long that survived a ~5.5min intermittent-loss window. Long lane now has current evidence (was "needs recheck"). | `2026-05-20T15:50`: short profile passed and long matrix was `5/5`. `2026-05-22T13:29`: short `5/5`, long had prompt-return/fatal failures. `2026-05-27T15:11`: serial short matrix under `/private/tmp/seed-matrix-wd-short-20260527T1355` was strict `4/5` (run 1 capture-invalid, runs 2-5 clean). `2026-05-30T04:33`: bonus smoke 4/4 on 4162147 - long-1/long-2 + short-1/short-2 all `verdict=success` (false-green-checked; long-1 rode out 34 ping timeouts). Dir `/private/tmp/seed-wd8003-smoke-20260530T035045`. | Smoke is clean; optionally extend to strict `5/5` long+short. Shares the NIC-agnostic `0D/12` handshake flake (not WD-specific). |
| `vm-net-wd8003eb` | Current short lane mostly works but is not clean. | `2026-05-20T15:50`: short profile passed and long matrix was `5/5`. `2026-05-22T13:29`: short `5/5`, long had prompt-return/fatal failures. `2026-05-27T11:12`: current one-run short scan reached `Say one.` then became invalid when the harness could not capture the window at gate 3. `2026-05-27T15:11`: serial short matrix under `/private/tmp/seed-matrix-wd-short-20260527T1355` was strict `4/5`; run 1 timed out after `Say one.` with no answer visible, runs 2, 4, and 5 cleanly passed, and run 3 passed by harness but OCR around `Say two.` was noisy. | Investigate/retry the first-prompt stall before calling WD8003EB short stable. Long lane still needs current recheck. |

## Known timing contracts

### 3c501

- Send ClientKeyExchange before the expensive PRF/key-block work.
- Keep the prebuilt application frame path separate from normal NICs.
- Preserve live TLS reuse for short prompt loops unless a real close/reconnect
  condition is seen.
- Prepare the 3c501 receive latch around post-DPI sends; historical stable lane
  called `tls_prepare_3c501_receive` before and after ready-tail app-data send.
- During active chat after response text has started, use render-before-ACK
  pacing so the single-buffer card does not acknowledge a long text stream
  faster than the 8088 renderer can consume it. Cold greeting/setup and
  metadata before text still use ACK-before-render.
- Be cautious with long-response completion. Current WIP can render long text
  for minutes and then miss terminal SSE records; treat this as a 3c501
  receive/drain/completion problem, not request construction.
- Do not rely only on contiguous `output_text.done`; OpenAI can split the event
  name across TLS records. Current WIP uses `response.completed` as the semantic
  completion marker, then drains or reconnects according to TLS state.

### 3c503

- Keep the request phase loaded away from HTTP body scratch; the enlarged ready
  request builder must not execute from a region it overwrites.
- Use the pre-server-Finished application-data send path. Moving application
  send until after server Finished regressed into server FIN/RST races.
- Do not force split-body sending for short prompts. Prompts at or below
  `api_ready_short_prompt_max` should inline the whole request when it fits;
  longer prompts still use the split lane.
- Metadata records may ACK before rendering; once response text has started,
  render-before-ACK matched the successful short-loop shape.
- Oversized TLS application records can contain real output text. Do not blanket
  fast-drain them for 3c503; chunk decrypt/parse and preserve following TLS
  record tails.

### NE family

- NE2K8 has the strongest focused evidence.
- After response text has started, NE1000/NE2000 use render-before-ACK pacing
  for long responses.
- Prompt tail must be durable across reconnect; do not rely on input scratch
  that TLS setup can overwrite.
- `vm-net-novell-ne1k` is not yet proven equivalent to the NE lane; keep it as
  a separate verification target until it passes focused `5+5`.

### WD family

- Historical stable runs used the safer ACK-before-render shape; earlier global
  delayed-ACK experiments regressed WD8003e.
- Treat WD8003e and WD8003eb as likely related but verify both. Do not assume
  one WD profile passing covers the other until the focused gates say so.

## Required gates

For each profile, the target stabilization gate is:

1. Short loop: greeting plus `Say one.` through `Say five.`, with all five
   prompt/response turns returning to DPI.
2. Long loop: greeting, the open-ended 16 KiB 8088 R/W/jump prompt, then a
   follow-up `Say done.`, repeated `5/5` for the profile.
3. OCR evidence captured by the harness for every run.
4. Clean red fatal screens are failures. Active long rendering is not a
   failure. Prompt-return-without-response is suspicious and must be classified
   with pcap/OCR context.

## Working rule

Stabilize individual lanes first. Only after every profile has a documented
stable lane should we merge timing paths. A per-card rule can be removed only
when this note records the replacement shared rule and the evidence that it
passed the affected card's focused gates.

2026-05-28T20:57+03:00 - 3c503 long lane update: rejected the temporary large-record-after-text completion shortcut because it truncated valid long answers. Current restored lane streams/decrypts large records through real completion and has two clean current long/done/ok/DPI passes: `/private/tmp/seed-3c503-long-noskip-20260528T2030.pcap` and `/private/tmp/seed-3c503-long-noskip-2-20260528T2048.pcap`. Need three more serial passes before calling current 3c503 long `5/5`.

2026-05-29T11:05+03:00 - 3c503 long lane update. Confirmed via decrypt + focused reruns that the long answer fully completes on the wire (greeting + long answer on one reused keep-alive TLS flow, 100% ACKed, no FIN/RST). The WIP 08:29 experiment (api_stream_completed==2 early-success + per-follow-up forced reconnect, keyed off the api_stream_large_seen=api_stream_prompt_len alias) made every 3c503 follow-up force a fresh handshake that flakes right after a long stream -> clean `0D/12` (tcp_connected then tls_probe_server fail). Reverted both 3c503 carve-outs in agent_api.inc: 3c503 now waits for completed==3 (zero chunk) and REUSES the live session like the NE family (server sends Connection: keep-alive). New 3c503 timing-contract note: reuse the live TLS session for follow-ups; do NOT force a reconnect per follow-up. Remaining 3c503 long blockers after this fix: (b) short follow-up (`Say done.`) after a long answer is built but not transmitted on the reuse path (ready_tail inline prefix gated by tls_app_len, which the long answer's large-record path disturbs) - deterministic; (c) intermittent mid/late long-stream TLS-record receive failure -> `0D/F0` (completed<2), the same large-record receive reliability that likely also flakes the reconnect handshake. Lane state: long NOT stable; reuse fix removes the red fatal for (a) but the long+done loop still fails on (b)/(c). Keep 3c501/NE/WD untouched (only 3c503 branches changed).

2026-05-29T13:00+03:00 - 3c503 contract additions (in-progress, not yet 5/5). (1) Reuse the live keep-alive TLS session for post-DPI follow-ups; do NOT force a reconnect per follow-up (the per-follow-up handshake races Cloudflare -> 0D/12). (2) Completion must be the transport zero chunk (completed==3), and the large-record receive path must keep scanning past output_text.done so a zero chunk BUNDLED into a >2097 B response.completed record is still detected (else the answer renders fully but never returns to DPI -> stall). Implemented 3c503-scoped in tls_receive_large_application_record.cipher_take_ready; NE/3c501/WD keep the post-completion fast-drain skip. (3) Still-open 3c503 blockers: mode (b) follow-up not transmitted on reuse (ready_tail send branch), and mode (c2) intermittent mid-stream receive 0D/F0. Keep these per-NIC until each is green, then evaluate unifying the large-record completion rule across the DP8390 NICs (NE family likely benefits from the same bundled-zero-chunk scan).

2026-05-29T13:55+03:00 - 3c503 long: consolidated root cause = large-record receive reliability. Wire proof: Seed ACKs 100% of the answer but never recognizes completion (completed stays 2; the zero chunk after the LARGE response.completed records isn't detected) -> stall; other runs fail mid-large-record with 0D/F0; the follow-up reconnect 0D/12 also fails while receiving a LARGE Certificate. All three are the same large-record path. Kept contract: 3c503 reuses the live keep-alive session and waits for completed==3 (the only state that completed a full long+done+ok loop on this branch, run 2). Rejected this session: (A) accept completed==2 + reuse -> answer returns but the undrained LARGE trailer poisons the follow-up (0D/F0); (B) scanning large records past completed==2 -> inconclusive (hit mid-stream 0D/F0 first). Next: harden tls_receive_large_application_record (the cx=0xffff TX-ACK/RX poll timeouts that cause intermittent mid-stream 0D/F0) and make completion robust without depending on the elusive zero chunk. Keep 3c501/NE/WD untouched.

2026-05-29T22:27+0300 - 3c503 long lane: WORKING (user-confirmed full long+short loop). Root cause of the intermittent stall was the tls_receive_large_application_record fast-drain dropping the bundled 0\r\n\r\n zero chunk on edges that pack it into a large trailer record; fix = always decrypt+scan large records. Plus the universal reuse->reconnect->resend follow-up path. Pending: 4-5 long + 5 short stabilization runs on the cleaned (debug-trace-stripped) build.

2026-05-30T00:13+0300 - 3c503 long lane: STABLE + committed. 4 long + 4 short clean in the auto stabilization batch. The fix (universal reuse->reconnect->resend follow-up + always-decrypt large records to catch the bundled HTTP zero chunk) is SHARED across NICs (no family gates). Remaining 3c503 item: cold-handshake 0D/12 (Certificate receive) intermittent flake at gate 1 - pre-existing, recoverable via retry, separate from the long loop. NE/WD/3c501 pending re-verify against the shared build.

2026-05-30T04:37+0300 - Overnight cross-NIC validation of the committed shared build (4162147), no code changes. NE2K8 STABILIZED (7 clean long + 5/5 short, no NE-specific changes). WD8003e SMOKE 4/4 (no WD-specific changes; one long survived ~5.5min intermittent loss). So the shared fixes (always-decrypt large records for the bundled zero chunk + universal reuse->reconnect->resend) generalize across 3c503/NE2K8/WD8003e + known-good 3c501 - no per-NIC carve-out was needed for any of them.
  NEW CONTRACT NOTE (cross-NIC, the dominant residual failure): the intermittent 0D/12 is the (re)handshake Certificate receive timing out, NOT the data path. tls_probe_server -> tls_wait_for_server_certificate -> tls_ensure_current_handshake_record_complete / tls_drain_server_certificate (tls.inc:219-345) pull the large multi-segment cert chain via repeated ne_transmit_tcp_ack + tcp_receive_payload. tcp_receive_payload (transport.inc:1) polls with a BOUNDED budget (tcp_payload_wait_count x 0x0800 spin) and on timeout -> net_error_tcp -> handshake abort -> 0D/12. A single late cert segment (cold TCP/TLS after idle, SLiRP warm-up, host jitter) trips it; ~20% of long runs, network UP, recoverable via on-screen retry. This is a DIFFERENT path from tls_receive_large_application_record (tls.inc:1032, the always-decrypt data-path fix), so 0D/12 is neither a regression nor covered by it. Hardening (SHARED, affects all NICs - validate 3c503 first): raise tcp_payload_wait_count, and/or auto-retry the reconnect handshake once on 0D/12. The 05-29T13:55 note's mid-stream 0D/F0 is the same bounded-poll family in the data path, so a wait-budget bump likely helps both.
