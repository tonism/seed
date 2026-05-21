# Default Prompt Interface Rebuild Attempts

Branch: `work/default-prompt-interface-rebuild`

Baseline: current released `main` / Build 7 (`0c8eb5e`). This includes the
verified 16 KiB ROM BASIC path, the settled 3c501 driver work, and the stable
minimal OpenAI Responses proof that displays `ok`.

Target: Build 8 minimal chat loop without arena cleanup/defrag. Keep the Build
7 memory layout and proven TLS/NIC path, add request/response streaming as the
real I/O shape, render model text into the Default Prompt Interface, then allow
one-line user prompts to repeat through the same path.

Rules for this rebuild:

- Do not reintroduce cleanup, defrag, resident relocation, or a one-big-ocean
  memory handoff until chat works reliably.
- Treat the first request and later DPI requests as the same model-call path.
- Stream request body slices instead of building one large in-RAM prompt blob.
- Stream response text directly to the renderer instead of requiring a full
  response body buffer.
- Use the OCR/background harness for routine canaries; avoid screenshot uploads
  unless local classification is ambiguous and the image is needed for human
  inspection.
- Record failed approaches here before moving on.

## 2026-05-16 00:35:27 - Reset Build 8 onto the stable Build 7 baseline

Created `work/default-prompt-interface-rebuild` from `main` / `build-7`
(`0c8eb5e`) instead of continuing on the cleanup/defrag-derived
`work/default-prompt-interface` branch.

Rationale:

- The released Build 7 path is the stable ground: 16 KiB ROM BASIC entry,
  settled 3c501 behavior, proven TLS session setup, and minimal OpenAI
  request/response.
- The arena cleanup/defrag branch changed too many memory lifetime invariants
  before the chat loop existed. Debugging there led to hidden/erased output and
  unclear ownership of live data.
- The useful newer harness/OCR changes were restored onto the rebuild branch,
  but the cleanup/defrag memory architecture was not.

Verification:

- `make inspect` succeeds from the Build 7 baseline.
- `vm-net-ne2k8` through the ROM BASIC OCR harness reached:

```text
seed build 7
ok
```

Conclusion:

Proceed by adding the smallest real Build 8 chat path on top of Build 7:
stream prompt slices out, stream model response back to screen, then enter the
interactive prompt loop.

## 2026-05-16 00:35:27 - Carry forward portable diagnostics, not arena code

Pulled forward the useful tooling from the abandoned Build 8 branch without
bringing the cleanup/defrag implementation:

- `tools/run-basic-bootstrap-86box.py` — latest background/OCR harness.
- `tools/ocr-vision.swift` — local macOS OCR helper kept as a fallback.
- `tools/run-basic-bootstrap-matrix.py` — bounded repeated canary runner for
  profile/repeat sweeps.
- `tools/memory-map.py` — generated memory-map appendix tool.
- `tools/build-dpi-prompt.py` — build-time JSON escaper for static prompt
  template slices, so the 8088 runtime does not need a general JSON string
  escape routine.
- `docs/memory.md` — regenerated against the Build 7 baseline, not copied from
  the cleanup/defrag branch.
- `make memory-map` — convenience target for refreshing the appendix.

Conclusion:

These are safe to keep. They improve observability and release discipline
without changing Seed's runtime behavior.

## 2026-05-16 15:25:00 - Preserve first request metadata instead of rescanning it

Observed behavior:

- First Build 8 model response rendered correctly in DPI.
- Submitting `hi` after that waited for a long time and then failed in agent
  setup with `0D/12`.
- Packet capture from earlier NE2K runs showed only the first TLS application
  request/response. No second application request left the VM after the DPI
  prompt was submitted.

Diagnosis:

- The first plaintext HTTP request is intentionally preserved so later DPI
  requests can reuse the key/model without rereading `USER.CFG`.
- The ready-path model reuse code tried to rediscover the JSON model value by
  scanning the preserved request for `CRLF CRLF` on every prompt submit.
- That scan was unbounded. If the delimiter was missed for any reason, the
  second request path could hang before `tls_send_application_data_current_seq`,
  matching the "no second packet leaves" capture.

Change:

- First attempted to store the model value pointer in `dns_tx_len`, but that
  was wrong: the endpoint/DNS phase still owns `dns_tx_len` after the first
  request is built, and overwrites it before DPI.
- Replaced that with a no-new-state calculation on the ready path:
  `api_request_plain + tls_record_header_len + tls_tx_len -
  tls_record_header_len - tls_aead_tag_len - api_body_len +
  api_request_model_value_offset`.
- On later DPI requests, copy the model from that calculated pointer instead
  of rescanning the preserved HTTP request.

Correction:

- The first version of the no-new-state calculation used `tls_app_len`.
  That also failed with `B2/02`, because `tls_receive_application_data`
  overwrites `tls_app_len` with the response plaintext length after the first
  response arrives.
- `tls_tx_len` remains the encrypted record length from the first application
  send, so subtracting the TLS record header and AEAD tag gives the preserved
  first HTTP request length.

Expected result:

- The second request should either leave the machine or fail earlier with a
  bounded error. It should not spin forever trying to rediscover saved request
  structure.

## 2026-05-16 15:50:00 - Move chat key/model cache out of the receive arena

Observed behavior:

- The second prompt still failed quickly with `B2/02`.
- That means the ready-path body builder still could not read a valid model
  string.

Diagnosis:

- `api_request_plain` lives in `tls_pre_response_scratch`, which is part of
  the extended TLS receive window.
- The first model response can overwrite that area before DPI submits the next
  prompt.
- Therefore preserving the whole first HTTP request in that arena is not a
  valid chat-loop lifetime model.

Change:

- Added a one-sector cold `agent_cache` phase.
- After the TLS handshake and first application send complete, but before the
  first application response is received, copy only the durable values needed
  for later prompts:
  - model -> `chat_model_cache`
  - key -> `chat_key_cache`
- These caches reuse the retired SHA-256 K table at `0x0500`. That table is
  needed during the handshake, but not for later TLS application-data
  send/receive on the current Build 8 keep-open session path.
- Later DPI prompt requests now read key/model from this compact cache instead
  of the overwritten request/receive arena.

Tradeoff:

- `CORE.SYS` grows by one sector because this is a separate cold phase. The
  resident/K/critical memory layout still fits the 16 KiB guarded target.
- Removed the nonessential bright ready marker in resident code to keep the
  resident nucleus within four sectors.

## 2026-05-16 10:54:08 - Response rendered but first call did not return

Observed behavior:

- The first model greeting appeared on screen, but Seed stayed in the normal
  `o` phase. No `seed build 8` splash and no usable prompt appeared.
- The harness mistakenly promoted this to success because OCR saw the greeting.
  Tightened the harness so it reports both shape verdict and OCR lines, and no
  longer treats a greeting alone as a ready DPI prompt.

Diagnosis:

- The first response renderer was working.
- The response phase then kept waiting for the HTTP response body to drain
  before returning to `main`.
- The drain code only searched for lowercase `content-length: `.
- A real HTTP/1.1 OpenAI Responses call uses `Content-Length: ...` with
  uppercase `C` and `L`, so Seed rendered the answer but never learned how many
  bytes remained to drain.

Change:

- Added `Content-Length: ` as a second response-phase header pattern.
- Kept the response renderer direct-to-video; `api_response_text_buf` remains
  unsuitable for durable text because later TLS receive records reuse that
  arena.

Verification:

- `make inspect` passes.
- `vm-net-ne2k8` ROM BASIC background harness:
  - first call rendered a greeting;
  - `seed build 8` splash appeared afterward;
  - `hi` submitted from the prompt;
  - a second model response rendered;
  - local pixel inspection of the kept oracle image shows bright prompt-band
    pixels after the second response, even though OCR does not reliably read
    the lone `>` prompt marker.

Conclusion:

The immediate hang before DPI was caused by case-sensitive content-length
parsing, not a TLS sequencing failure. Continue with NIC-family testing and
then clean up the remaining harness/oracle rough edges.

## 2026-05-16 11:13 - restore 3c501 early CKE timing

- Observation: 3c501 pcap still showed ClientHello/ServerHello and Finished OK, but server sent close+FIN before our first application request. The request then hit RST.
- Comparison: stable Build 7 sent ClientKeyExchange immediately for 3c501 before the expensive key schedule, then sent only CCS/Finished later. The rebuild regressed to sending CKE after key schedule for all cards.
- Change: restore 3c501-specific early ClientKeyExchange ordering in tls_probe_server.

## 2026-05-16 23:30 - return 3c501 to the Build 7 final-flight shape

Observed behavior:

- Delaying ClientKeyExchange until after more Build 8 request precompute missed
  Cloudflare/OpenAI's first idle timer. The server sent FIN roughly 14.4s after
  ServerHello/SKE/SHD, and our CKE left just after the close.
- Sending CKE early again fixed the first timer, but the server then sent FIN
  roughly 1.1s after CKE. The CCS/Finished path missed that by a small margin
  when extra debug/marker work remained in the path.

Useful packet captures:

- `/tmp/seed-3c501-retry-after-basic-hiccup.pcap`: CKE left after server FIN.
- `/tmp/seed-3c501-build7-order.pcap`: early CKE worked, but CCS/Finished
  missed the second timer by about 18 ms.
- `/tmp/seed-3c501-shaved-delay.pcap`: early CKE plus smaller 3c501 delay and
  skipped crypto marker reached server Finished and received application data.

Change:

- Restored the Build 7 ordering for 3c501:
  - send ClientKeyExchange early;
  - finish key schedule and client Finished locally;
  - send CCS/Finished;
  - send the already-built application request before waiting for server
    Finished.
- Reduced the 3c501 post-ClientHello receive delay from 4 ticks to 2 ticks.
- Skipped the nonessential crypto load-marker redraw on the 3c501 fast lane.

Conclusion:

This is timing-sensitive but no longer looks fundamentally broken. The 3c501
path is viable if we keep the first request path close to the proven Build 7
sequence and avoid decorative work inside the CKE-to-Finished window.


## 2026-05-16 11:19 - pre-encrypt first app record before final flight

- Observation: restoring early ClientKeyExchange moved CKE earlier, but pcap still showed the first app record 40 ms after server close/FIN. The remaining delay was application-record encryption after Finished.
- Change: prebuild the first application-data record using the next client record sequence before sending CCS/Finished, then send the prepared record immediately after final flight. Normal ready-loop sends still build+send through the same wrapper.

## 2026-05-16 11:53 - post-Finished request chunk timing

- Observation: with the request split into 128-byte TLS application records and
  server Finished verified before sending application data, 3c501 completed the
  TLS handshake but still froze at the dark `o` marker.
- Focused pcap showed:
  - ClientKeyExchange at 11:53:21.005.
  - ChangeCipherSpec + client Finished at 11:53:22.196.
  - Server Finished at 11:53:22.205 and ACKed immediately.
  - Server close/FIN at 11:53:23.388.
  - First 128-byte application-data chunk at 11:53:24.389, one second after
    the server had already closed the connection.
- Diagnosis: waiting for server Finished is correct, but encrypting a 128-byte
  first request chunk on 3c501 is still too slow for the provider's
  post-Finished application-data timeout.
- Next attempt: send a tiny 16-byte first application-data record immediately
  after server Finished, then continue the same plaintext request with 128-byte
  records once the provider has seen application data.

## 2026-05-16 12:00 - 16-byte first chunk still too late if built after Finished

- Observation: changing the first post-Finished application record to 16 bytes
  still froze at the dark `o` marker on 3c501.
- Focused pcap showed:
  - Server Finished arrived and was ACKed at 12:01:11.990.
  - Server sent close/FIN at 12:01:13.181.
  - The first 16-byte application-data record left at 12:01:13.895, after the
    connection was already closed.
- Diagnosis: even a 16-byte encrypted record is too slow if the encryption
  work starts only after server Finished. The record must be prepared before
  the server-Finished wait, but stored somewhere the receive path will not
  overwrite.
- Change under test: prebuild the first 16-byte application-data record in
  `fs_sector_buffer`, build/send the client final flight from `tls_rx_copy`,
  verify server Finished, then send the prepared record immediately and
  continue the remaining request in 128-byte records.

## 2026-05-16 - Build 8 rebuild: TLS ordering rollback and chat config cache

- Observation: trying to precompute the server-Finished verifier and move the
  chat config cache between ClientHello and final-flight send regressed NE2K8
  from the previously working first response back into first-turn TLS/network
  failures. This was the wrong layer to touch for the second-prompt bug.
- Rollback: restored the Build 7-compatible final-flight shape: send
  ClientKeyExchange/CCS/Finished, transcript-update the client Finished after
  send, send the prepared application record, then wait for and verify server
  Finished with the normal server-Finished verifier path.
- Diagnosis for the second-prompt `B2/02`: the chat cache was placed at
  `low_sha256_k`. `tls_client_hello` reloads SHA-256 K constants there during
  the first handshake, so the ready-loop model/key cache was corrupted before
  DPI could send the second request.
- Fix under test: preserve only the bytes the handshake actually destroys:
  the model string plus the first `tls_pre_response_scratch_end - seed_key`
  bytes of the key. The remaining key tail stays in the original `seed_key`
  arena. This keeps the first-turn path unchanged while giving the ready loop
  stable config state without a full 256-byte duplicate.
- Result: wrong assumption. The key tail begins exactly where ready-loop
  state starts, so `tls_app_len` and related state overwrote the first bytes of
  the supposed preserved tail. The second request reached OpenAI again, but
  OpenAI rejected the reconstructed key as invalid.
- Follow-up: cache the full model plus full key in the 269-byte gap between
  the TLS stream arena and the 16K stack guard. This spends that local slack,
  but it is the smallest non-cheating path that keeps the TLS connection open
  and avoids rereading config from floppy for every prompt.
- Result: NE2K8 and WD8003e reached first response, accepted `hi`, and
  rendered the second model response. 3c501 regressed at first-turn TLS with
  `@D/12`.
- Adjustment under test: move the cache phase later, after endpoint/DNS/TCP
  setup has consumed the config values and immediately before `tls_probe_server`
  reuses the config arena for TLS state.
- Follow-up observation: 3c501 still failed at first-turn TLS with `@D/12`.
  Diff review showed the Build 7 internet-readiness probe had been removed from
  `prepare_internet_path`, reducing the path to DHCP only. Restoring the
  probe/TCP-80 readiness step before the agent path because this was part of
  the stable 3c501 sequence.

## 2026-05-16 - Stop TLS ordering experiments and return to the first-response anchor

- Decision: the stable ground is the rebuild state that displayed the first
  model response in the DPI area, accepted a user prompt, and then exposed the
  second-prompt problem. That is the correct Build 8 anchor.
- Rejected path: further packet-order experiments around the TLS final flight.
  Build 7's TLS ordering was heavily tested across all 16 KiB NIC profiles, so
  changing that path is a regression risk unless a first-flight bug is proven.
- Active recovery:
  - Keep the unified `send_agent_prompt_path` model-call shape.
  - Keep the key/model chat cache outside the receive arena.
  - Restore the Build 7 internet-readiness probe in `prepare_internet_path`;
    it had been removed in the rebuild and is part of the settled 3c501 path.
  - Keep `tls_build_application_data_record` bounded, but do not prebuild or
    reorder the application record relative to the final flight.

## 2026-05-16 18:16 - Preserve request split offset across TLS scratch

- Observation: NE2K8 reached the first model response and accepted a user
  prompt, but the follow-up request produced an OpenAI invalid-JSON error.
  The ready-loop body tail was being cut from `tls_app_chunk_len`.
- Diagnosis: `tls_app_chunk_len` is TLS encryption scratch. It is overwritten
  inside the encrypted application-data send path, so it cannot safely carry
  the request-body split offset from the request phase to the stream phase.
- Change: keep the boot request unsplit in the first application-data record.
  For ready-loop prompts, keep the split offset in request-owned
  `api_response_pending_len` until the stream phase sends the remaining body
  tail, then clear both request length fields.
- Result: NE2K8 and WD8003e rendered the first model greeting, accepted a
  prompt, and rendered a follow-up model response. This is the first clean
  Build 8 proof of multiple model responses flowing through the DPI loop.
- Remaining issue: 3c501 still fails before DPI at the TLS `0D/12` point.
  A temporary attempt to defer the first 3c501 application record until after
  server Finished changed the failure into a dark `o` freeze, so that
  experiment was backed out. Treat 3c501 as the next separate TLS timing issue.

## 2026-05-17 00:41 - Keep request-before-server-Finished ordering for every NIC

- Regression: after the 3c501 prebuilt-record fix, NE2K8 froze at the normal
  `o` before DPI. Three consecutive runs reproduced it.
- Wire evidence: NE2K8 sent ClientHello, received the server flight, sent
  ClientKeyExchange/CCS/Finished, received server encrypted data and FIN, and
  only then sent the HTTP application request. Cloudflare reset that late
  request. This proved the non-3c501 path had been moved away from the proven
  Build 7 ordering.
- Fix: keep application request before `tls_wait_for_server_finished` for all
  NICs. The 3c501 path sends the prebuilt application record there; other NICs
  build and send the current-sequence application record there. No NIC waits
  for server Finished before sending the first application record.
- Verification: `make inspect` passed. First-response canaries passed on
  `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e`.

## 2026-05-18 01:15 - Separate harness misclicks from Seed failures

- Harness regression: a canary appeared to fail, but OCR showed the VM was
  still in ROM BASIC with a garbled bootstrap listing. Seed had not run.
- Root cause: the experimental PID keycode path sent shifted characters as a
  single flagged key event. 86Box did not consume that reliably for ROM BASIC
  typing. Reverted to explicit Shift down/key/Shift up, but added a tiny delay
  inside shifted chords so the old race is less likely.
- Harness hardening:
  - Added common prompt punctuation (`?`, `'`, `/`, `;`, `!`, `_`) to the
    direct key map so chat canaries do not fail before reaching Seed.
  - Added a ROM BASIC/Syntax Error OCR guard so the oracle cannot classify a
    failed BASIC bootstrap as a successful Seed splash.
  - Changed post-DPI prompt injection to wait for OCR-visible DPI readiness
    instead of typing at a fixed timestamp by default. OCR often drops a bare
    `>` prompt marker, so the initial greeting text also counts as ready.
- Verification: NE2K8 and WD8003e each completed two post-DPI prompts with
  HTTPS observed for both prompts and final local OCR success. 3c501 remains
  intermittent: one first-response-only canary passed, while a longer gated
  run failed before DPI with the known `0D/12` TLS/app-data failure.

## 2026-05-18 01:57 - Let 3c501 skip more leading frames before payload parse

- Observation: the 3c501 failure was still isolated to TLS/app-data receive
  (`0D/12`) while NE2K8, 3c503, and WD8003e were stable. This pointed away
  from the shared DPI/request path and toward the 3c501 receive parser.
- Cleanup: removed a duplicated `tcp_parse_3c501_second_frame` definition that
  had been introduced during the previous patch iteration. The remaining
  implementation initializes the frame-skip counter explicitly.
- Change: keep the 3c501-only fallback parser as a bounded multi-frame scan:
  after the normal `parse_tcp_payload` fails, it may drop up to four leading

## 2026-05-18 14:20 - Bound post-DPI stream tail draining

Observed behavior:

- The first model greeting and post-DPI request path were both alive.
- A follow-up prompt could receive and render model text, but sometimes did
  not return to the `>` prompt before the canary timed out.
- The phase-size check rejected the theory that loading the request or stream
  phase at `0x0900` overwrote the response parser at `0x0d00`; the measured
  request/stream ends were below `0x0d00`.

Diagnosis:

- Treating `.done` as immediate success returned too early and could leave
  trailing HTTP/SSE bytes queued for the next chat turn.
- Waiting only for the HTTP chunked zero-length terminator moved too far the
  other way: if the terminator is delayed, split across records, or missed by
  the tiny parser, the UI can render text but never regain control.

Change:

- Restore detection of the SSE `.done` event, but mark it as "tail drain
  pending" instead of complete.
- Once `.done` is seen, `agent_api_exchange` performs only one additional
  no-payload wait before returning to DPI. The zero-length HTTP chunk remains
  the clean completion signal when it arrives naturally.

Expected result:

- Avoid the early-return poison-tail failure while also avoiding an unbounded
  wait after the model has already finished its visible text.

Follow-up:

- Two-prompt NE2K8 canaries showed that the prompt can now return after the
  first post-DPI response.
- A third-prompt gate reproduced `0D/12` after the second prompt, so the next
  failure moved from "never regains DPI" to "TLS receive rejects a later
  application-data record".
- Found one remaining receive-side length check that still rejected decrypted
  TLS application data above the old single-TCP-payload cap (`1460`) even
  though the copy/assembly path now has the larger `tls_stream_buffer_len`
  window. Widened that check to the same stream buffer.

Verification:

- `vm-net-ne2k8` passed a three-prompt OCR canary with `say ok`, `say blue`,
  and `say red`.
- The harness observed HTTPS traffic for all three submitted prompts.
- `post-DPI gate 2` and `post-DPI gate 3` both returned to the prompt, which
  proves the second model turn no longer dies with the previous `0D/12` receive
  failure on this NIC.

Correction:

- Manual visual inspection showed the first rendered byte of a post-DPI model
  response was consistently corrupted (`ok` appeared with a wrong first glyph).
- Root cause: the first-response-byte path advanced to the response line before
  printing, and `.advance_response_line` clobbered `AL`, which still held the
  character to render.
- Fixed by preserving `AX` around that first-line advance.
  Ethernet/IP frames from the single 3c501 receive buffer and retry payload
  parsing after each drop.
- Rationale: the 3c501 single-buffer path can receive leading ACK/control
  frames before the TLS application-data payload. The old fallback only
  tolerated two leading frames, so a valid payload behind more noise could be
  missed and reported as a TLS receive failure.
- Verification: `make inspect` passed with `CORE.SYS` still 25088 bytes and
  16K guarded slack still 269 bytes. Two-prompt OCR canaries passed on
  `vm-net-3c501` twice, plus `vm-net-ne2k8`, `vm-net-3c503`, and
  `vm-net-wd8003e`. Each successful run observed HTTPS traffic for both
  post-DPI prompts and returned a final local oracle success without uploading
  screenshots.

## 2026-05-18 02:28 - Rejected delayed ACK after render

- Hypothesis: long responses might overflow NIC receive buffers because Seed
  ACKed each decrypted TLS record before spending time rendering the text,
  allowing the server to send more data while the 8088 was busy printing.
- Experiment: moved the post-record TCP ACK after `agent_response_phase` so
  the sender would be paced by screen rendering.
- Result: `make inspect` passed and NE2K8 stayed green, but `vm-net-wd8003e`
  regressed on a two-prompt canary. It reached DPI and sent HTTPS for both
  prompts, then ended in `0D/12`.
- Decision: reverted the ACK-order experiment. Keep ACK-before-render as the
  safer shared path for now; the earlier 3c501 multi-frame parser change
  remains in place.

## 2026-05-18 02:40 - Harden post-DPI canary gate against greeting false positives

- Observation: a canary failure was reported as a harness misclick rather than
  a Seed failure.
- Diagnosis: the OCR prompt gate accepted `how can i help` as ready because
  OCR sometimes drops the bare `>` marker. That is too broad: the greeting can
  remain visible in scrollback, so later gates may inject the next prompt while
  the model response is still streaming.
- Change: only prompt-like leading marker OCR (`>`, `›`, `»`) counts as
  post-DPI ready. If OCR misses the bare prompt, use explicit timed injection
  for that canary instead of allowing a false positive.
- Follow-up: NE2K8 confirmed that Tesseract reads Seed's bare `>` prompt as
  `gee,` in this window. Added that exact artifact as a prompt marker; this is
  still narrow enough not to match the greeting scrollback.

## 2026-05-18 02:55 - Test 256-byte receive window for long streamed replies

- Observation: short two-prompt canaries were green on 3c501, NE2K8, 3c503,
  and WD8003e, but manually asking for a much longer response could stream
  multiple screens and eventually fail with `0D/12`.
- Hypothesis: Seed ACKs a decrypted TLS record before rendering it. While the
  8088 spends time writing text, the provider can send ahead into the NIC.
  A smaller advertised TCP window should reduce how much data can pile up while
  rendering is busy.
- Change under test: lower the advertised TCP receive window from 512 bytes to
  256 bytes for the unified path.

## 2026-05-18 03:21 - Keep 256-byte window, lengthen prompt gate

- Result: `make inspect` passed after the 256-byte window change. NE2K8 passed
  both a short two-prompt canary and a long streamed-answer canary. WD8003e
  passed a two-prompt canary.
- 3c503 and 3c501 initially looked like regressions because the post-DPI OCR
  gate timed out at 100-120 seconds while only the splash was visible. Reruns
  with longer gates reached the prompt, sent the post-DPI prompt, observed
  HTTPS, and finished with local oracle success.
- Decision: keep the 256-byte window for now and raise the harness post-DPI
  gate default from 120 seconds to 240 seconds. This avoids false failures on
  slower NICs while preserving the stricter OCR rule that no longer treats the
  greeting text as a prompt marker.

## 2026-05-18 04:18 - Restore 3c501-specific 512-byte window

- Observation: the 256-byte receive window stabilized long streamed replies on
  NE2K8 and WD8003e, but made 3c501 intermittently fail before or around the
  first post-DPI prompt. This looked like a 3c501 receive sequencing issue
  rather than a generic streamer failure.
- Change under test: keep the 256-byte advertised receive window for the
  normal path, but restore 512 bytes only for `family_3c501`. Also widen the
  3c501 second-frame scan from 8 to 16 dropped-leading-frame attempts before
  declaring receive failure.
- Result: `vm-net-3c501` passed 2/2 post-DPI `hi` canaries. Both runs observed
  HTTPS traffic, reached the post-DPI prompt, and ended with local oracle
  success. OCR read the final prompt as `gee,`, the known Tesseract artifact
  for Seed's bare `>` marker.
- Follow-up: keep this as a card-specific transport compatibility carve-out.
  The unified path remains the goal, but 3c501 is single-buffered enough that
  preserving its wider window is safer than forcing it through the NE/WD tuning.

## 2026-05-18 04:42 - Treat rendered stream timeout as completion fallback

- Observation: NE2K8 could render the first greeting but never repaint the DPI
  prompt. Local oracle saw the splash plus greeting, but no prompt marker. This
  means the response renderer had printed text and then stayed in the receive
  loop waiting for a final HTTP/SSE trailer that did not arrive or was not
  parsed.
- Rejected approach: add a `response.completed` event matcher inside the
  response phase. This is architecturally cleaner, but pushed the one-sector
  hot response phase over 512 bytes.
- Change: keep the one-sector response parser unchanged and add a cheap receive
  loop fallback. If `tls_receive_application_data` times out after at least one
  streamed text byte was rendered, return success instead of turning the phase
  red. If no stream text was seen, the same timeout remains a real failure.

## 2026-05-18 06:05 - Shorten TCP payload wait so streamed fallback can fire

- Observation: a controlled NE2K8 canary rendered the first greeting but did
  not return to the prompt within the harness gate. This was not the latest
  harness misclick: Seed had run, the greeting was visible, and the receive
  path was still busy.
- Diagnosis: the rendered-text fallback only runs after
  `tls_receive_application_data` returns. That routine can block inside one
  `tcp_receive_payload` wait using the global `tcp_payload_wait_count`.
  With the old count (`4096`), a post-answer idle wait can dominate the whole
  canary and make the fallback practically unreachable.
- Change under test: lower `tcp_payload_wait_count` from `4096` to `512`.
  This avoids TLS final-flight/order changes and does not grow the hot
  one-sector response parser. The tradeoff is a shorter idle tolerance between
  streamed response records, so long-answer behavior needs canary/manual
  verification.
- Result: NE2K8 passed a two-post-DPI-prompt canary and a long streamed-answer
  canary. A single 3c501 run still failed `0D/12`, but an immediate 3-run
  repeat passed 3/3, so the failure still looks like intermittent 3c501 receive
  timing rather than a deterministic fallback regression.

## 2026-05-18 09:18 - Revert the too-aggressive 128 wait and fix first-pass layout

- Observation: a manual NE2K8 session reached DPI, but the line break between
  model text and the next prompt was missing, the next response appeared to
  lose or corrupt its first character, and a short interaction ended with
  `0D/12`. This is consistent with the receiver timing out before the first
  token of a follow-up response, not with the original BASIC harness misclick.
- Rejected result: the 128-count `tcp_payload_wait_count` experiment did not
  fix the greeting-without-prompt case and made short follow-up prompts too
  brittle. It should not stay as the default.
- Change: restore `tcp_payload_wait_count` to 512, start the first streamed
  greeting one row higher before the renderer's first-line advance, and add an
  explicit blank separator before drawing a prompt after streamed model text.
- Result: `make inspect` passed. A NE2K8 canary with one post-DPI `hi` reached
  the second response and returned to the prompt. OCR still mangles exact text,
  so this needs a manual UI pass for visual correctness.

2026-05-18T15:55+03:00 - Tightened post-DPI receive completion: the retry fallback may now return success only after the SSE .done event has been seen, not merely after any text has rendered. This targets the second-prompt hang where Seed returned to DPI before the previous streamed response was fully complete.

2026-05-18T16:48+03:00 - Safe-stop checkpoint. Current WIP has the Build 8 chat path close but not release-ready. Manual NE2K8 testing showed the initial greeting renders, the first post-DPI prompt `say ok` can receive a clean `ok`, and the earlier first-byte corruption on that first response appears fixed. The next prompt (`say blue`) still hangs instead of reliably returning the second response. A 3c503 two-prompt canary reached the first post-DPI prompt and rendered `okh`, then timed out waiting for the second DPI prompt; OCR showed `say okh / okh / say bule / bule / say dffd`, so the UI path is active but the completion/drain contract is still wrong. The pcap from that run was broad/noisy and not enough by itself to isolate the guest flow. Resume from the receive-completion/stream-drain boundary, not from TLS packet ordering or BASIC harness timing.

2026-05-18T16:51+03:00 - User visual follow-up on the same 3c503 run: the session got much further than earlier failures. It showed greeting, then `say okh` -> `okh`, then `say bule` -> `bule`, then accepted `say dffd`. After that last prompt the response took unexpectedly long; it may have frozen or may have eventually errored, but the harness terminated before the final state was visible. Treat this as evidence that multi-turn send/render works for short replies, while the next unresolved issue is a long wait after a later prompt, likely around response completion, receive idle handling, or stream-drain state.

2026-05-18T22:18+03:00 - Tightened stream completion handling after OpenAI SSE documentation review. The response parser now ignores bytes until a real HTTP response start (`H`) before scanning headers, so stale chunk tails from a previous response cannot be mistaken for the next response header. The core receive loop now distinguishes semantic model completion (`response.completed`) from HTTP transport completion (zero chunk): after semantic completion it uses a short drain window instead of immediately returning to DPI. This is intended to fix the observed freeze after the second/third prompt where stale transport tail or incomplete drain could poison the next request.

2026-05-19T04:16+03:00 - Found cached request phase invalidation bug. Split TLS responses use tls_rx_overflow from 0x0700..0x0cff, which overlaps the preloaded request phase at net_setup_phase_start (0x0900). If api_stream_event_ready stayed set after a split response, the next prompt could run a clobbered request builder. Change under test: clear api_stream_event_ready in agent_api_exchange split-record path so DPI reloads the request phase before the next prompt.

2026-05-19T11:54+03:00 - Reworked the on-screen debug trail so it is a real append-only string rather than an accidental reuse of user config dirty state. Added a dedicated debug_trace_cursor byte and fixed yellow trace constants; phase-local trace writers now append to the next top-screen cell and naturally wrap as the string grows. Reset the trace cursor once the initial agent setup succeeds. Also changed response trace semantics from one D per delta chunk to one D when response text first starts, so later prompt/request boundaries are not drowned out by long answers. A C completion marker was attempted but rejected because the hot one-sector response phase overflowed.

2026-05-19T16:40+03:00 - Pcap isolated the repeated-prompt freeze to local receive/decrypt/parse, not request construction or wire send. A NE2K8 canary sent `say one`, `say two`, and `say three`; the first two returned to DPI, and the third hung after the user prompt. Tcpdump showed the third prompt did leave the VM and OpenAI/Cloudflare replied on the same TLS connection. The failing response included back-to-back TCP payloads of 1448, 1448, and 124 bytes, followed by more server data. That exceeds the current single TLS receive buffer shape (`tls_stream_buffer_len` around 2 KiB) if those bytes belong to one application record. Treat the next investigation as receive-buffer/record-streaming work; do not go back to request ordering unless new evidence contradicts this.

2026-05-19T17:08+03:00 - Rejected TLS max_fragment_length mitigation. Added TLS 1.2 max_fragment_length=1024 to ClientHello to try to keep OpenAI/Cloudflare application records below the 16K receive window. `make inspect` passed, but NE2K8 regressed before DPI with `0D/12`/`RB` trail. Backed the extension out; after rebuild, a short NE2K8 three-prompt canary recovered and reached DPI after each prompt. Do not retry max_fragment_length blindly; if revisited, inspect ServerHello extension parsing and Cloudflare behavior first. The real fix remains receive-side oversized application record streaming.

2026-05-19T19:32+03:00 - Fixed a request-phase load-address regression and then isolated the next freeze to the oversized TLS record streamer. The request phase is assembled for `net_setup_phase_start`; using plain `call_core_phase` loaded it at `low_scratch_start`, so the post-DPI request builder could execute at the wrong address. Restored `call_core_phase_at ... net_setup_phase_start`. After that, NE2K sent HTTPS after the first post-DPI prompt but timed out waiting for the next prompt with only the splash visible, so the remaining failure is response receive/parse, not request construction. Code review found a concrete large-record bug: `tls_large_feed_cipher_bytes` called the response phase while leaving `DX` unpreserved, but the caller uses `DX` as the bytes-consumed count after return. Response rendering can clobber `DX`, causing the large TLS record loop to lose its place after streamed text. Preserve `DX` across the large-record parser call and retest NE2K multi-prompt.

2026-05-19T20:11+03:00 - Added a narrower hot-path debug trail after repeated splash+B freezes. `B` still means the ready request phase finished building the first record. TLS send now appends `w/e/p/q` for app-data record build, post-build, post-TCP-send, and client sequence increment. The tail phase still appends `F/S/A/T` for ready-tail entry, tail present, tail built, and tail sent. The receive loop now appends `R` before each TLS receive attempt and `V` after a TLS record is received/decrypted, before invoking the response phase. A fuller exchange trace overflowed the K/LINK window, so the kept markers are the minimum useful set that still fits with K ending at `0x3400`.

2026-05-19T20:47+03:00 - `VhRRR...` isolated the splash freeze to a split TLS application record tail-loss bug. The parser reached HTTP header completion (`h`) inside the first decrypted app record, then no body/completion arrived and the receive loop kept retrying. Code review found that after `tls_ensure_current_tls_record_complete` appended TCP bytes, `tls_receive_application_data` reused `AX` as the current buffered byte count rather than the TLS record total before calling `tls_save_payload_after_current_offset`. If the appended TCP payload also contained the start of the next TLS record, Seed discarded that tail. Change under test: reload `AX` from `tls_app_total_len` after the ensure call so only the current TLS record is consumed and any following record remains buffered.

2026-05-20T00:53+03:00 - Found a second tail-loss bug in the oversized TLS application-record path. When `tls_receive_large_application_record` finished a large record with bytes from the next TLS record still in the same TCP payload, it saved `tls_buffered_payload_ptr` directly into `ne_tx_frame`; the immediate `ne_transmit_tcp_ack` then rebuilt `ne_tx_frame` and destroyed that saved tail before the next receive pass could parse it. Change under test: copy any large-record tail into `tls_rx_copy` before finishing MAC verification and ACKing, so the next TLS record header/body survives the ACK send. This stays on the receive/decrypt/parser boundary and does not change request construction or packet ordering.

2026-05-20T00:58+03:00 - Tightened the same large-record fix after the first patch overgrew the K/LINK window. The large-record loop now returns to MAC verification immediately when the final tag byte is consumed instead of falling back to `tcp_receive_payload` with `CX=0`; this targets the observed TX/RX blink followed by no rendered third response when the VM had already sent the prompt and was waiting locally. Kept the high-crypto/critical scratch map unchanged by replacing the receive caller with a direct large-record jump and removing dead carry-flush failure handling. `make inspect` passes again with K packed at `0x1800..0x3400` and 16K guarded critical slack still 269 bytes.

2026-05-20T01:18+03:00 - Hardened the oversized-record tail copy after decrypting the prior canary pcap. The third response's final HTTP zero chunk is present in the following small TLS record, so the remaining local failure still points at preserving and parsing that tail after a large record. Added an explicit `DS -> ES` load before copying large-record tail bytes into `tls_rx_copy`; this keeps the fix narrowly on the receive/decrypt/parser boundary. `make inspect` still passes with K packed at `0x1800..0x3400` and 16K guarded critical slack 269 bytes.

2026-05-20T01:29+03:00 - Reproduced the third-prompt failure with the hardened tail copy: the three post-DPI gates fired, but the final oracle still reached clean `0D/12`. Decrypted the actual NE2K8 pcap flow (`172.66.0.243:443`) and verified all four HTTP responses decrypt with valid ChaCha20-Poly1305 tags; the third post-DPI response contains both `response.completed` and the HTTP zero chunk. Added a one-sector response parser matcher for `.completed` while the SSE scanner is idle, setting `api_stream_completed` as soon as OpenAI emits the semantic completion event. This deliberately uses the existing HTTP-start guard to tolerate a leftover `0\r\n\r\n` transport trailer on the next turn instead of waiting forever on trailer parsing. `make inspect` passes; response phase is 506 bytes, still one sector.

2026-05-20T01:34+03:00 - Rejected immediate return on semantic `.completed`. It regressed the next turn: the first post-DPI gate was ready, but the run failed before gate 2 with `0D/FE`, consistent with leaving response trailer state ahead of the next request. Changed the semantic marker to `api_stream_completed=2`, so the receiver still drains for the HTTP zero chunk; `agent_api_exchange` now treats a later receive timeout as success only if semantic completion was already seen. To fit the fallback in K, compacted the large-record tail bookkeeping (`jcxz`, clear pointer first) and removed a redundant `clc` after a successful ACK. `make inspect` passes; K has 2 bytes of alignment slack and the response phase remains 506 bytes.

2026-05-20T01:50+03:00 - The drain-fallback canary with `say one`/`say two`/`say three` passed: all three post-DPI gates were ready and the final OCR oracle was `success`. A stronger four-gate run using the older failing prompts then timed out before gate 2, with pcap showing the first post-DPI response left the server and was fully ACKed. Decryption verified the response contained the `one` delta, `response.completed`, and the zero chunk. The likely issue is not seeing the final trailer quickly enough after semantic completion; cap the remaining receive drain window in the response parser by setting `api_receive_tries=4` when `.completed` is seen. `make inspect` passes.

2026-05-20T06:15+03:00 - Fixed the Build 8 repeated prompt freeze on the NE2K8 16 KiB ROM BASIC harness. The failing trace pattern was `PBFdeCZPBFdeCZPBF`: two post-DPI turns reached delta/text/completed/zero, while the third stopped immediately after request build/stream setup. Decrypted pcap confirmed the third response started with a 2999-byte TLS application record containing only Responses metadata, followed by small records containing `delta:"three"`, `.completed`, and `0\r\n\r\n`. The 16 KiB path now fast-drains oversized application records instead of decrypting/scanning them in the hot receive loop, then continues with normal authenticated small-record receive/decrypt/parse for the rendered output stream. Also fixed the small-record tail preservation bug by copying buffered following-record bytes out of `ne_tx_frame` before the ACK path can rebuild it. `make inspect` passes.

2026-05-20T06:15+03:00 - Verification: `tools/run-basic-bootstrap-86box.py --profile vm-net-ne2k8 --screen-oracle --screen-ocr-success --no-screenshot --post-dpi-text 'say one' --post-dpi-text 'say two' --post-dpi-text 'say three' --post-dpi-text 'say done' --post-dpi-wait 60 --post-dpi-gate-timeout 300 --capture-delay 2` passed. Harness OCR gates 1-4 all reached DPI prompt readiness, and the final oracle was `success`; OCR showed `say two / two / say three / three / say done / done`. The user-requested handover note `notes/handover_chat_loop_freeze.md` was deleted; this attempts file is now the durable record.

2026-05-20T08:06+03:00 - Kept the on-screen debug trail after user feedback; removing it was premature while long-response testing is still active. Fixed two DPI layout issues found in manual testing: the first greeting starts one line lower, and submit now advances from the actual wrapped input row instead of the prompt marker row, preserving the blank gap between a multi-line user prompt and the model response. `make inspect` passes with the 16K guarded critical slack still 269 bytes.

2026-05-20T08:06+03:00 - Greeting prompt experiment: changing the cold prompt from `Hi!` to a long instruction (`Briefly invite a prompt; factual, professional.`) first overgrew the 1 KiB request phase; removing two dead request-phase append helpers made it fit, but the runtime then failed before the first response with `B` trace and `0D/12`. A tiny `Prompt?` cold prompt passed but changed the user-visible behavior instead of steering tone. Current compromise is `Greet briefly.`: it preserves a real greeting instruction while keeping the first TLS exchange stable. OCR canary with a longer post-DPI prompt and `say done` passed, then a long-running `vm-net-ne2k8` manual canary was launched from that build.

2026-05-20T08:34+03:00 - Manual long-prompt run failed after the first prompt with trace `PBFdCZ` and `0D/12`; the trace means request build/stream setup completed and the response scanner saw a delta key, semantic completion, and the HTTP zero chunk, but no emitted text marker. A strict OCR canary using the same long prompt plus a second `say done` turn passed twice, so this is not a deterministic request-build failure. Added core exchange-exit trace markers: `x` before `agent_api_exchange` returns success, `f` before it returns failure. `make inspect` passes; launched a long-running NE2K8 manual VM from that instrumented build.

2026-05-20T08:50+03:00 - Found the API-contract-shaped reason for `d` without `e`: the exchange loop reset `api_stream_state` before every TLS record. Responses streaming text can split anywhere across TLS/HTTP records, so matching `"delta":"` at the end of one TLS record and receiving the actual text bytes in the next record left Seed outside the JSON string state and produced no rendered text. Removed the per-record parser-state reset; request construction still resets parser state once at the start of each request. The strict long-prompt canary with a follow-up `say done` passed after this change. Going forward, use open-ended long-answer prompts as the primary canary for this bug; short `say one/two/three` prompts are useful smoke tests but no longer cover the highest-risk path.

2026-05-20T10:34+03:00 - Switched the primary gate to the user's open-ended long prompt: `What do you think if I created a non-OS bootstrapped harness that gives you direct agentic access to 16KB 8088 RAM? R/W/jump.` Tightened the harness OCR prompt gate so toolbar/title OCR starting with `>` no longer counts as a DPI prompt; only whole-line prompt artifacts such as `>`, `›`, `»`, `)`, `gee`, and `gee,` count. A one-long-prompt NE2K8 gate passed after adding ready-loop `reasoning:{"effort":"minimal"}` to the Responses request body. This is not an output cap; it avoids the GPT-5 medium-reasoning behavior where the stream may emit only reasoning/keepalive events for 90+ seconds before any `response.output_text.delta`. Cold greeting requests stay small and unchanged (`Greet briefly.`) because adding the reasoning field to the first request overflowed or destabilized the cold setup exchange.

2026-05-20T10:34+03:00 - Long-answer testing status: one long-prompt run is fully harness-confirmed, and three additional long-answer/manual or timeout-interrupted runs are tentative passes by user observation because Seed was still receiving/rendering when the harness timeout or stop intervened. This puts the long-answer evidence at four tentative passes, but only one strict harness-confirmed prompt-return pass. Keep testing with no output-token cap; long answers are product behavior, and a slow answer is not a freeze. If a later run fails, resume from the receive/decrypt/parser completion boundary, especially the large-record path visible through `L` markers, not from request construction.

2026-05-20T11:42+03:00 - NE2K8 five-short-prompt gate found and cleared a large-record regression. First run with `say one` through `say five` reached gates 1-4, then failed before gate 5 with clean `0D/12`; OCR trace showed an `L` marker near the failure, pointing at the oversized TLS application-record path. The streaming-decrypt large-record experiment was reverted to the safer fast-drain behavior: skip oversized metadata records, preserve any following TLS tail, and let normal small-record decrypt/parse handle rendered text and completion. Verification rerun passed on `vm-net-ne2k8`: gates 1-5 all reached DPI prompt readiness, HTTPS was observed for all five prompts, and final OCR oracle was `success` showing `say one/one`, `say two/two`, `say three/three`, and subsequent prompts.

2026-05-20T12:56+03:00 - Stable checkpoint before push: forced `make -B inspect` passed on the fast-drain large-record build. NE2K8 short repeated loop passed 5/5 with `say one` through `say five`. NE2K8 long open-ended loop then passed 5/5 with the prompt `What do you think if I created a non-OS bootstrapped harness that gives you direct agentic access to 16KB 8088 RAM? R/W/jump. Explore what you would do first, the risks, and how you would stay useful.` Each long run reached the post-DPI prompt gate again, observed HTTPS to OpenAI/Cloudflare, and completed through the harness OCR/screen oracle without screenshots. Treat this as the current known-good Build 8 NE2K8 chat-loop checkpoint.

2026-05-20T13:10+03:00 - Strengthened the ROM BASIC harness evidence trail before broader confidence testing. `tools/run-basic-bootstrap-86box.py` now OCRs final screen-oracle captures by default on success as well as failure, keeps `--no-screen-ocr` as the explicit escape hatch, treats `--screen-ocr-success` as a deprecated no-op, prints all OCR lines instead of truncating at eight, and OCRs ordinary final screenshots when a run uses screenshot capture instead of screen-oracle capture. `tools/run-basic-bootstrap-matrix.py` now includes the per-VM log path for every result in `summary.txt`, not just failures. A single NE2K8 matrix smoke was already in flight when testing was paused and completed 1/1 PASS; its per-VM log contained `screen oracle OCR (tesseract)` without requiring `--screen-ocr-success`.

2026-05-20T15:50+03:00 - Extended confidence test results, no fixes attempted yet. Short in-session five-prompt matrix across the seven original NIC profiles passed 4/7: `ne1k`, `ne2k8`, `wd8003e`, and `wd8003eb` passed; `3c501` and `3c503` failed before the first post-DPI prompt with clean `agent setup failed 0D/12`; `novell-ne1k` exited nonzero in parallel but passed the serial rerun. Serial short rerun of failures: `3c501` failed again with clean `0D/12`; `3c503` exited nonzero after gate 3 timed out despite a success-shaped final screen; `novell-ne1k` passed. Long open-ended five-run parallel matrix passed 26/35: `ne1k`, `ne2k8`, `wd8003e`, and `wd8003eb` were 5/5; `3c501` was 0/5 clean `0D/12`; `3c503` was 3/5 with two clean `0D/12`; `novell-ne1k` was 3/5 with two gate-timeout/nonzero runs on success-shaped screens. Serial five-run rerun of long failures passed 5/15: `3c501` 1/5, `3c503` 1/5, `novell-ne1k` 3/5. Artifacts: `/tmp/seed-matrix-short-20260520T140257`, `/tmp/seed-matrix-short-serial-20260520T140257`, `/tmp/seed-matrix-long-20260520T140257`, `/tmp/seed-matrix-long-serial-failures-20260520T140257`. Interpretation: NE2K8 remains strong after the chat-loop fix, and NE1K/WD profiles look solid in the long gate; 3c501/3c503 still have a separate cold setup/first-response reliability problem, mostly clean `0D/12` before any post-DPI prompt, so do not call the all-family Build 8 bug solved yet.

2026-05-20T17:27+03:00 - Focused on `vm-net-3c501` cold setup after the all-family matrix. A fresh failing pcap (`/tmp/seed-3c501-current-1.pcap`) showed the server flight arrived, Cloudflare sent FIN around 15 seconds later, and Seed transmitted ClientKeyExchange only after that FIN, receiving RST. This is a 3c501 cold-handshake/setup timing problem, not the repeated-prompt receive/parser freeze already fixed on NE/WD. Change under test: delay 3c501 early key-schedule preparation until after ServerHelloDone has been consumed, and send pure TCP ACKs around the expensive 3c501 PRF/key-schedule work. `make inspect` passed with `CORE.SYS` 25600 bytes, K still packed at `0x1800..0x3400`, and 16K guarded critical slack still 269 bytes. A single focused long-prompt run with pcap (`/tmp/seed-3c501-ackpace-1.pcap`) passed and sent ClientKeyExchange before Cloudflare's idle FIN. However, the serial five-run long gate was only 3/5: runs 1, 2, and 5 passed; run 3 failed before DPI with `agent setup failed @A/@C`; run 4 failed before DPI with `network setup failed`. Artifacts: `/tmp/seed-matrix-3c501-long-ackpace-20260520T1710`. Interpretation: the ACK/key-schedule pacing helps some 3c501 handshakes but is not sufficient; remaining 3c501 failures are still pre-DPI cold setup/network/TLS reliability, not long response rendering.

2026-05-21T02:47+03:00 - 3c501 5+5 gate reached after separating three issues. First, a focused pcap showed a post-DPI response path failure was actually HTTP 401 `invalid_api_key` after header compaction; fixed `api_request_key_value_offset` from 73 to 71 and kept the OpenAI request on HTTP/1.1 `Host` plus `Authorization:Bearer`. Second, moving agent cache before TCP connect made the 3c501 cold ClientHello/CKE timing viable, but one attempted cache address (`dns_qname_len + 1`, `0x06fc`) self-overwrote the `0x0700` phase load window while `agent_cache` executed and produced setup/freeze artifacts. The kept cache is `dns_tx_len + 2` (`0x3d00..0x3dff`) with assembly guards against phase-window, TLS/request-scratch, and 16K stack-guard overlap. Third, a short serial gate after the cache fix still hit an intermittent post-DPI `0D/12` at gate 4; treating that as a stale 3c501 RX latch between turns, the ready-tail path now calls `tls_prepare_3c501_receive` before as well as after each post-DPI TLS application-data send. `make inspect` passed (`CORE.SYS` 25600 bytes, K packed at `0x1800..0x3400`, 16K guarded critical slack 269 bytes). Verification: short 3c501 serial matrix passed 5/5, each run doing `say one` through `say five`, artifacts `/tmp/seed-matrix-3c501-short-presendrx-20260521T0123`; long 3c501 serial matrix passed 5/5 with the open-ended 16KB 8088 R/W/jump prompt, artifacts `/tmp/seed-matrix-3c501-long-presendrx-20260521T0153`. Long-run OCR showed large rendered answers still on screen after the 300s final wait with no fatal/freeze, which matches the agreed rule that active long rendering is not a failure.
