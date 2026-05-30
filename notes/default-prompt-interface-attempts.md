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

2026-05-22T01:50+03:00 - Reproduced and fixed the NE2K long-response follow-up corruption. Manual testing showed that after a long answer, `say done` caused the centered `o` reconnect marker and returned to the prompt without text. Pcap confirmed the reconnect completed but OpenAI/Cloudflare returned HTTP 400: the ready request prefix had the correct headers, while the streamed body tail was corrupt after TLS setup overwrote `dpi_input_buf` (`tls_rx_copy`). First attempted to rebuild the tail by reading the submitted prompt back from the text screen; that exposed two more lifetime bugs. When the submitted prompt was on the bottom row, Enter scrolled it up but `dpi_prompt_marker_row` still pointed at the cleared bottom row, so requests contained spaces. After fixing that row decrement, reconnect still appended too many spaces because `dpi_input_len_byte` also lived in TLS scratch and was overwritten by the handshake. Added durable `api_stream_prompt_len` and used it for the streamed tail. Verification: short foreground NE2K control with `say one`/`say two`/`say three` decrypted as inputs `Greet.`, `say one.`, `say two.`, `say three.` with clean HTTP 200 responses.

2026-05-22T01:50+03:00 - Reproduced and fixed the NE2K long-answer `0D/E8` drain failure. With the prompt-tail corruption fixed, the same long open-ended prompt still failed before the follow-up gate: OpenAI sent the full SSE response and encrypted close_notify, but Seed errored in `tls_ensure_current_tls_record_complete.append_next_payload` while rendering/draining a very large response. Restoring the old 256-byte receive window for all non-3c501 NICs was not enough by itself. The kept pacing fix is NE-family specific: after response text has started, NE1000/NE2000 now call the response renderer before sending the TCP ACK for that TLS record. Other NIC families keep ACK-before-render because the earlier global delayed-ACK experiment regressed WD8003e. Verification: `make inspect` passed (`CORE.SYS` 25600 bytes, 16K guarded critical slack 269 bytes). Foreground NE2K long gate passed with the user prompt `What do you think if I created a non-OS bootstrapped harness that gives you direct agentic access to 16KB 8088 RAM? R/W/jump.`, then `Say done.`, then `Say ok.`; OCR showed the long answer returned to DPI, `say done` -> `done,`, and `say ok` -> `ok`. Decrypted pcap `/private/tmp/seed-ne2k8-long-nepace-fg-20260522T0127/ne2k8.pcap` showed two clean OpenAI TLS sessions: first carried `Greet.` plus the long prompt, second carried `say done.` and `say ok.`, all HTTP 200 with valid tags and zero chunks. Short NE2K smoke `/private/tmp/seed-ne2k8-short-nepace-fg-20260522T0145/ne2k8.pcap` also passed through three short prompts.

2026-05-22T13:29+03:00 - Broad post-fix matrix results, no fixes attempted from these results yet. Short five-prompt matrix across the seven original NIC profiles ran with 5 parallel repeats per profile and artifacts under `/private/tmp/seed-matrix-short-20260522T064053Z`; harness summary was 30/35 passed. Short results: `3c501` 5/5, `3c503` 5/5, `ne1k` 2/5 with three prompt-gate timeouts after `say four`, `ne2k8` 4/5 with one ambiguous/no-OCR first-gate failure, `novell-ne1k` 4/5 with one clean fatal during repeated short prompts, `wd8003e` 5/5, `wd8003eb` 5/5. Long open-ended matrix used the 16KB 8088 R/W/jump prompt plus follow-ups `Say done.` and `Say ok.`, artifacts under `/private/tmp/seed-matrix-long-20260522T074041Z`; three final runs were manually stopped after the user observed they were waiting at prompts. Strong full-loop long passes were sparse: `ne1k` runs 03 and 04, `ne2k8` run 04, and `novell-ne1k` run 05. Dominant long failure modes: clean fatals after long response (`0D/E8` common on NE/WD, `0D/FE` consistent on all five `3c501` runs, `0D/28` once on `ne1k`), long-answer gate timeouts where text rendered but no reliable return-to-prompt was detected, and prompt-return-without-response after reconnect or request submission (`ne2k8` run 02, `wd8003e` run 05, and user-observed `wd8003eb` runs 03/04 returning to prompt after the long prompt without an answer). Interpretation: the latest NE2K-focused fixes improved the targeted manual case but did not solve the all-family long-response loop. The next work should focus on long-response completion/reconnect/follow-up response handling and should treat harness visual prompt false positives separately from true DPI readiness.

2026-05-23T23:38+03:00 - Corrected a false positive in the long-response canary and reran the focused NE2K8 gate. A previous harness run closed the VM while a long answer was still rendering, so that result is invalid. Tightened `tools/run-basic-bootstrap-86box.py` so a DPI prompt gate requires real visual prompt evidence or OCR prompt evidence with a stable bottom-band image across repeated samples, and kept the explicit final post-DPI gate after the last follow-up prompt. Product-side changes under test: ready/follow-up Responses requests disable stream obfuscation, request minimal reasoning and low text verbosity without a hard token cap, response text is rendered with direct text-memory writes instead of per-character BIOS teletype, and the response parser returns to DPI at output-text completion while forcing a reconnect for the next prompt. Verification: `make inspect` passed (`CORE.SYS` 26112 bytes, K packed at `0x1800..0x3400`, 16K guarded critical slack 269 bytes) and `python3 -m py_compile tools/run-basic-bootstrap-86box.py` passed. Focused canary passed on `vm-net-ne2k8` with cold greeting, the open-ended 16KB 8088 R/W/jump prompt, then `Say done.`; OCR showed the long answer returned to a prompt, `Say done.` rendered `Done,`, and the final prompt gate succeeded. Artifact: `/private/tmp/seed-ne2k8-long-directrender-rerun-20260523T2302.pcap`. This is a clean NE2K8 focused pass for long answer plus follow-up, not yet an all-family matrix result.

2026-05-24T00:46+03:00 - Fixed two DPI UI regressions after the focused long-response pass. The cold greeting had collided with the centered `seed build 8` splash because stale setup cursor state could leak into the first response renderer; the response phase now forces the first cold response byte into the DPI response band before rendering. The reconnect path showed a centered `o` during follow-up TLS setup because the crypto-ready marker was still drawn after `handoff_status_ready`; TLS setup now suppresses that marker in active chat sessions while keeping the initial setup marker behavior. `make inspect` and harness py-compile passed. Manual NE2K8 verification confirmed the greeting is correctly positioned and no centered reconnect `o` appears. A pcap-backed harness rerun also showed the long prompt rendered, `Say done` returned `Done,`, and no centered `o` appeared, but duplicate same-profile 86Box windows from aborted reruns confused the harness gate/oracle, so this is recorded as a manual/OCR product pass rather than a clean automated gate. Artifact: `/private/tmp/seed-ne2k8-ui-fix-long-20260523T-pcap.pcap`. All harness/86Box/tcpdump processes were stopped afterward.

2026-05-24T02:49+03:00 - Hardened the ROM BASIC harness against stale same-profile 86Box windows before broad retest: the harness now closes pre-existing same-VM-path windows by default, `--oracle-only` refuses ambiguous same-path matches, prompt-gate OCR uses actual display bounds and ignores cursor cells for stability, and prompt-gate diagnostics always include OCR lines. A focused NE2K8 long canary initially hit an intermittent clean `0C/10` reconnect failure, then an immediate pcap-backed rerun passed: cold greeting, long 16KB 8088 R/W/jump prompt, `Say done.`, final prompt gate, and no centered reconnect `o`. Artifact: `/private/tmp/seed-ne2k8-autocanary-0c10-20260524T0124.pcap`.

2026-05-24T02:49+03:00 - Short five-prompt full NIC matrix was not clean, so the expensive long matrix was not started. Command used five parallel repeats per profile with `say one` through `say five`, artifacts under `/private/tmp/seed-matrix-short-20260524T0124Z`. Strict harness result was 9/35 passed. Using the earlier agreed classification that clean red fatals are failures and success-shaped prompt-gate timeouts are plausible product passes, the run is 23/35 plausible and 12/35 clean fatal failures. By profile: `3c501` 1 pass, 1 gate timeout, 3 clean `0D/12`; `3c503` 5 gate timeouts, no clean fatals; `ne1k` 3 passes, 1 gate timeout, 1 clean `0C/10`; `ne2k8` 2 passes, 1 gate timeout, 2 clean fatals (`0D/12` plus one OCR-unreadable early red screen); `novell-ne1k` 1 pass, 1 gate timeout, 3 clean fatals (`0D/12` where readable); `wd8003e` 3 gate timeouts, 2 clean fatals (`0C/10`, `0C/18`); `wd8003eb` 2 passes, 2 gate timeouts, 1 clean `0C/10`. Interpretation: the focused NE2K8 UI/reconnect case is improved, but all-family repeated short loops are not at a stability point. The next investigation should separate prompt-gate OCR/visual false negatives from real clean fatal reconnect/setup errors; do not spend a half-day long matrix until the short matrix is substantially cleaner.

2026-05-24T14:10+03:00 - Focused on `vm-net-3c503` instead of continuing the expensive matrix. A pre-fix five-short-prompt pcap (`/private/tmp/seed-3c503-short5-renderack-20260524T1335.pcap`) decrypted as complete OpenAI HTTP 200 streams for greeting plus `say one`, `say two`, `say three`, and `say four`; the final attempted flow reached only TLS handshake. This proves the apparent stale screen was not request construction. Change under test: 3c503 now renders each received TLS application record before sending the pure ACK, matching the already successful NE pacing shape more closely. Result: a focused 3-prompt 3c503 canary passed (`say one`/`say two`/`say three` all rendered), but a 5-prompt run still was not clean.

2026-05-24T14:10+03:00 - 3c503 TLS timing experiments so far. Adding an early CCS after ClientKeyExchange kept the response/render shape intact through several short turns, but a focused five-prompt run (`/private/tmp/seed-3c503-short5-earlyccs-20260524T1346.pcap`) still failed cleanly at `0D/12` on the fourth prompt: pcap showed Cloudflare FIN about 14 ms before client Finished. Two follow-up timing attempts were rejected: building the 3c503 application record after client Finished regressed into a completed server response that Seed ACKed but did not render (`/private/tmp/seed-3c503-short5-currentapp-20260524T1354.pcap`), and moving the 3c503 key schedule before ServerHelloDone regressed the cold greeting setup (`/private/tmp/seed-3c503-short5-earlykey-20260524T1406.pcap`). Keep the durable conclusion scoped: 3c503 has both a local receive/render completion edge and a very tight reconnect/final-flight timer; do not retry app-after-Finished or early-key-schedule blindly.

2026-05-24T21:45+03:00 - Focused 3c503 short-loop flow is working again after isolating the remaining failure to oversized TLS application records that contain real output text. First, the direct text-memory response writer was backed out to BIOS cursor/write-character calls because a 3c503 manual screen showed CGA-style green corruption while chat text was visible. Second, 3c503 pacing now matches the NE path: ACK metadata records before response text starts, then render-before-ACK once text has started. Third, the large-record skip loop now preserves a same-packet following TLS tail when the oversized record ends. That moved the failure from `say three` to `say four`, and pcap showed why: `say four` carried the actual `delta:"four"` inside a 4245-byte TLS app record, so blanket fast-drain of oversized records was unsafe. The kept fix decrypts oversized app records in chunks, invokes the resident response scanner on each decrypted chunk, drains the tag, preserves any following TLS tail, and still relies on later small records/final `0\r\n\r\n` for completion. Harness OCR was also taught to accept exact `gee`/`gee,` as the known OCR artifact for the lone DPI prompt. Verification: `make -B inspect` passed, and `vm-net-3c503` ROM BASIC harness passed one focused five-short-prompt canary with greeting plus `say one`, `say two`, `say three`, `say four`, and `say five`; OCR showed each answer and final DPI prompt, artifact `/private/tmp/seed-3c503-short5-largeparse-20260524T2138.pcap`. This is a focused 3c503 short-loop pass, not yet a full all-family/long-response matrix result.

2026-05-25T07:08+03:00 - Found and fixed a 3c503 cold/request phase self-overlap introduced by the enlarged ready request builder. The request phase had grown to three sectors but was still assembled and loaded at `net_setup_phase_start` (`0x0900`), while the HTTP body scratch starts at `fs_sector_buffer` around `0x0d0e`; long/ready request construction could overwrite the tail of the executing request phase before any Seed TLS traffic. Kept fix: assemble and load `agent_request` at `low_scratch_start` again and guard its size against `fs_sector_buffer - low_scratch_start`, so the request body cannot overlap the phase. `make -B inspect` passed with `CORE.SYS` 26112 bytes, Q phase at `0x0700`, and 16K guarded critical slack still 269 bytes. A focused 3c503 short smoke reached DPI and answered `Say one.`, confirming the cold centered-`o` freeze was fixed.

2026-05-25T07:08+03:00 - Rechecked the 3c503 long prompt after the overlap fix and found a separate TLS final-flight race. A pcap-filtered failing run (`/private/tmp/seed-3c503-long-stall-20260525T0633.pcap`) showed Cloudflare sending server Finished plus FIN immediately after the client Finished; Seed then sent the application record after that FIN and received RST. This was caused by moving 3c503 to the safer-looking app-after-server-Finished path. Kept fix: restore 3c503 to the pre-server-Finished application-data send path, matching the 3c501 timing while keeping the request-overlap guard. Verification: one strict focused 3c503 long run with the 16KB 8088 R/W/jump prompt, then `Say done.`, passed after an extended gate. OCR showed the long response rendering to DPI, then `say done` -> `Done,` and final DPI. A 300s pcap run before the extended gate timed out while still rendering but showed the split ready request left correctly and the server streamed about 171 KB back; do not count long active rendering as a freeze.

2026-05-25T08:34+03:00 - Focused 3c503 post-fix verification is clean. Ran four additional serial long gates with the same open-ended 16KB 8088 R/W/jump prompt plus `Say done.` follow-up and a 30-minute post-DPI gate, artifacts under `/private/tmp/seed-matrix-3c503-long-postfix-20260525T0709`. Matrix result: 4/4 passed (`847.4s`, `928.2s`, `1033.7s`, `957.5s`). Combined with the earlier focused pass above, this is 5/5 strict 3c503 long-loop passes after the request-phase overlap fix and pre-server-Finished app send restore. Short control also passed on 3c503 with greeting plus `Say one.` through `Say five.`, final oracle success. Current interpretation: focused 3c503 short and long loops are stable again; next confidence step should be an all-family matrix only when we are ready to spend the time, because long responses are legitimately slow and need long gates.

2026-05-25T11:52+03:00 - Wider short all-family regression screen says do not commit this checkpoint as an overall improvement yet. Parallel five-short-prompt matrix across all seven NIC profiles used `Say one.` through `Say five.`, artifacts under `/private/tmp/seed-matrix-short-20260525T110345Z`; strict harness result was only 4/35 passed. By profile: `3c501` 0/5 (3 clean failures, 2 ambiguous), `3c503` 0/5 strict but all 5 were success-shaped final oracle/gate failures, `ne1k` 0/5 strict (3 success-shaped, 2 clean failures), `ne2k8` 1/5, `novell-ne1k` 0/5 clean failures, `wd8003e` 1/5, `wd8003eb` 2/5. Because this could be parallel load/harness pressure, started a serial rerun under `/private/tmp/seed-matrix-short-serial-20260525T110345Z`, but the first completed serial 3c501 run reproduced a clean pre-DPI `agent setup failed 0D/12`; the second 3c501 run was in progress when the rerun was stopped to avoid spending hours after already getting enough no-commit signal. Interpretation: the current WIP is a real focused 3c503 improvement, but broad NIC stability is not better enough than the last commit to justify committing now. Do not run the expensive long all-family matrix until the short all-family shape is substantially cleaner.

2026-05-26T00:05+03:00 - Recovered the focused 3c501 short-loop shape by restoring the specific timing/order from the previous 3c501-good lane while keeping the later 3c503 request-overlap fix. First attempt fixed an artificial reconnect: `chat_prompt_len_cache` now starts at zero when the chat config cache is built, and the ready-tail cleanup no longer clears `tls_key_schedule_ready` just because a 3c501 prompt tail was sent. That moved 3c501 short from failing at the first real prompt to 3/5. A pcap-backed passing run (`/private/tmp/seed-3c501-short-reusefix-probe-20260525T2335.pcap`) confirmed all five post-DPI prompts stayed on one TLS flow, so live-session reuse was restored. The remaining failures were still clean cold-handshake `0D/12`; comparing against `bac9b41` showed the current WIP had reintroduced 3c501 early key-schedule work before ClientKeyExchange. Removed that again so 3c501 sends CKE before the expensive PRF/key-block work, matching the known-good timing contract. Verification: `vm-net-3c501` serial short matrix passed 5/5, each run sending `Say one.` through `Say five.`, artifacts `/private/tmp/seed-matrix-3c501-short-ckefirst-20260525T2340`. Treat 3c501 as a preserved timing lane: reuse live TLS unless close_notify actually clears it, send CKE before local key schedule on cold setup, and keep the prebuilt application frame path separate from 3c503/NE/WD changes.

2026-05-26T15:43+03:00 - Added `notes/nic_timing_lanes.md` as the working inventory for per-NIC timing/order contracts. This is intentionally a notes-level engineering document, not product docs polish. Current interpretation: the project has had focused stable lanes at different times (`3c501` historical short+long `5/5`, `3c503` focused long `5/5` plus short control, `ne2k8` focused short+long `5/5`, and strong but less current/focused evidence for `ne1k`, `wd8003e`, and `wd8003eb`), but no documented single shared code state where all seven profiles passed Build 8 chat-loop `5+5`. New working rule: stabilize and document individual lanes first, then unify only after replacement shared timing has passed the affected cards' focused gates. The latest 3c501 long canary after forcing reconnect on 3c501 large-tail mode still failed cleanly with `0D/12` while the long response was actively rendering, before the follow-up `Say done.` gate; that points back to 3c501 long receive/drain/completion, not request construction or stale follow-up reuse.

2026-05-26T17:31+03:00 - Latest focused 3c501 long completion trace narrowed the failure further. With `.output_text.done` matching fixed and a temporary `C` marker on text completion, the cold greeting returned to DPI and emitted `C`; the long open-ended response then rendered for several minutes but failed cleanly with `0D/12` before any second `C` appeared. Pcap/decryption for the preceding run showed OpenAI/Cloudflare sent a complete response including `response.output_text.done`, `response.completed`, zero chunk, close_notify, and FIN, and the VM ACKed through the final bytes. Interpretation: the 3c501 long lane is locally falling behind or losing receive state while consuming rendered text, before reaching the terminal SSE records. Change under test: after text starts, 3c501 now uses the same render-before-ACK pacing as 3c503/NE, while WD remains ACK-before-render.

2026-05-27T06:31+03:00 - 3c501 long-response stall root cause found at the response parser boundary. A focused pcap run with the long 16KB 8088 R/W/jump prompt plus several short follow-ups got stuck with the VM socket in `CLOSE_WAIT`; decryption of `/private/tmp/seed-3c501-long-multifollow-20260527T0615.pcap` showed OpenAI/Cloudflare sent the complete long answer, `response.completed`, `0\r\n\r\n`, close_notify, and FIN. The local parser missed completion because the SSE event was split as `event: response.output_text` in one TLS record and `.done` in the next, while the WIP parser only looked for contiguous `output_text.done`. Kept fix: make the terminal semantic marker `response.completed`, which is later in the stream and stable across the Responses API. `make -B inspect` passed (`CORE.SYS` 26112 bytes, 16K guarded critical slack 269 bytes). A pcap-only cold 3c501 run after the change (`/private/tmp/seed-3c501-cold-completed-marker-20260527T0655.pcap`) decrypted cleanly: greeting request left the VM, the response included `response.completed` split across records followed by the zero chunk, and all TLS tags verified.

2026-05-27T06:31+03:00 - Harness note while verifying the 3c501 completion fix: macOS `screencapture -l<86Box window>` started returning `could not create image from window`, and full-screen fallback captures were black in this desktop state. The harness was patched so `wait_for_dpi_prompt`, final oracle classification, and `--oracle-only` use the existing full-screen fallback when per-window capture fails, and the fallback now returns a boolean to the prompt gate. `python3 -m py_compile tools/run-basic-bootstrap-86box.py` passes. This is a harness resilience improvement, but the current desktop capture failure means the post-DPI OCR gate could not yet prove the new 3c501 long/follow-up loop; resume with OCR/manual-visible verification before calling 3c501 `5+5`.

2026-05-27T08:42+03:00 - Tightened the harness after two operator-facing regressions. Full-screen fallback captures were removed again from prompt/oracle paths because they could classify unrelated desktop windows as Seed output; capture is now window-id only and screen classification is constrained to the detected 86Box display rectangle. The prompt gate now tracks a response-area CRC after each accepted DPI prompt so later gates cannot pass on an unchanged greeting/prompt screen. A focused `vm-net-3c501` long-plus-follow-up run then passed with window-only OCR: the open-ended 16 KiB 8088 R/W/jump prompt rendered to DPI, `Say done.` was submitted and answered `done,`, and the final DPI gate succeeded. Artifact: `/private/tmp/seed-3c501-long-followup-windowonly-gatefix-20260527T0835.pcap`. This is one strict current 3c501 long/follow-up pass, not a `5/5` lane yet. Follow-up harness focus fix: launch focus restoration is now opt-in via `--restore-focus`; `--no-restore-focus` is a deprecated no-op because no-restore is the default. Future long/manual runs should avoid `--foreground-launch` unless we explicitly want 86Box to take focus.

2026-05-27T09:39+03:00 - Paused per user request during 3c501 long-gate verification. Before the pause, the first fresh fixed-gate run under `/private/tmp/seed-matrix-3c501-long-windowonly-gatefix-20260527T0920` passed strictly: long answer returned to DPI, `Say done.` rendered `done,`, and final screen oracle succeeded. Run 2 had only reached the first DPI gate and submitted the long prompt when stopped, so it is not counted. The prior artifact `/private/tmp/seed-matrix-3c501-long-windowonly-20260527T0842` had two strict passes, and run 3 was product-success-shaped but exposed a harness false negative: `image_display_bounds` treated the whole 86Box window including the status bar as the guest display, making the visual prompt detector sample the wrong band. Fixed the display-bound helper to use the first/last dark display rows/columns and moved the DPI prompt visual sampling lower in the detected display; the saved run-3 oracle now detects the prompt visually. All active 86Box/harness processes were stopped.

2026-05-27T11:12+03:00 - Short-loop spot testing of non-3c501 profiles, no fixes attempted. First tried a six-profile parallel matrix under `/private/tmp/seed-matrix-other-short-20260527T0945`, but it was invalid as product evidence because the strict window-only harness frequently failed with `could not capture 86Box window`. Switched to serial under `/private/tmp/seed-matrix-other-short-serial-20260527T0958`; this gave real failures for `vm-net-3c503`: `0/5` short sessions passed, with two post-DPI failures after `Say two.` reporting OCR `@D/FO@` (likely `0D/F0`) and three cold failures reporting `0D/12`. The same serial run showed `vm-net-ne1k` failing in the same family: run 1 reached `Say two.` then clean `@D/FO@`; run 2 failed after `Say one.` with OCR `@D/F@`; run 3 corrupted ROM BASIC input and is invalid harness evidence. A slower one-run scan of remaining cards under `/private/tmp/seed-matrix-remaining-short-scan-20260527T1022` produced: `vm-net-ne2k8` PASS for one full five-prompt short loop; `vm-net-novell-ne1k` timed out after `Say two.` with a success-shaped screen but no `two` response; `vm-net-wd8003e` invalid due window-capture failure before gate 1; `vm-net-wd8003eb` got through `Say one.` then became invalid due window-capture failure at gate 3. Interpretation: short loops are not broadly stable in current WIP; `3c503` and `ne1k` have real repeated short-loop failures, `ne2k8` still has a clean short-loop spot pass, Novell NE1K is suspicious, and WD needs a more reliable harness path before classification.

2026-05-27T13:48+03:00 - Recovered the current `vm-net-3c503` short lane without touching the 3c501 long path. The focused pcap-backed repro after `Say two.` showed the failing reconnect sent the ready request prefix but not the small streamed body tail, so the server waited for the missing body bytes and reset later. Kept fix: 3c503 no longer forces the split-body path for prompts at or below `api_ready_short_prompt_max`; short prompts that fit are sent as one complete TLS application record, while longer 3c503 prompts still use the existing split lane. `make -B inspect` passed with `CORE.SYS` 26112 bytes and the 16K guarded critical slack still 269 bytes. Verification: one pcap-backed focused run passed greeting plus `Say one.` through `Say five.` at `/private/tmp/seed-3c503-short-inline-20260527T1305.pcap`, then a serial five-run 3c503 short matrix passed `5/5` with OCR evidence for every gate under `/private/tmp/seed-matrix-3c503-short-inline-20260527T1315`. This is a scoped 3c503 short recovery; it does not prove 3c503 long or the other NIC lanes.

2026-05-27T15:11+03:00 - Tested current WD-family short loops with no product changes. Serial matrix used greeting plus `Say one.` through `Say five.` for `vm-net-wd8003e` and `vm-net-wd8003eb`, artifacts under `/private/tmp/seed-matrix-wd-short-20260527T1355`. Strict harness result was `8/10`: `wd8003e` was `4/5` and `wd8003eb` was `4/5`. Interpretation from per-run OCR: `wd8003e` has four clean passes and one invalid harness/window-capture failure after `Say one.`, with no clean Seed fatal and no confirmed product stall. `wd8003eb` has four passes and one real-looking gate timeout after `Say one.` where the submitted prompt remained on screen with no answer visible; this is not a clean fatal but should count as suspicious product evidence. Current short classification: WD8003E looks healthy but not strict `5/5` due harness capture; WD8003EB is mostly working but not clean/stable.

2026-05-28T18:15+03:00 - Manual-assisted current `vm-net-3c503` long recheck is not clean. Run 1 passed by harness OCR and user observation: long answer rendered back to DPI, `Say done.` answered `done`, user also confirmed `ok` and DPI. Run 2 also passed by user observation with long/done/ok/DPI, although the harness later reported the process exited before a queued extra gate after the manual result. Run 3 failed during the long response stream with clean `0D/F0` (`agent_api_exchange` failure before semantic completion), before the follow-up could run; OCR showed text still on screen and the fatal overlay landed mid-answer. Interpretation: the 3c503 short-inline fix did not break every long run, but 3c503 long is not stable at `5/5`; the next 3c503 long work should focus on receive/drain/parser completion or long-stream ACK/render pacing, not request construction.

2026-05-28T20:57+03:00 - 3c503 long-response false-success probe resolved. A 3c503-only large-record-after-text early-complete shortcut made one run look green while visibly truncating the long answer after only the first section; user correctly rejected that as a false pass. Backed out that shortcut and also backed out the 3c503 any-text failure-success fallback, leaving 3c503 to stream/decrypt large records until real response completion. `make -B inspect` still passes with CORE.SYS 26112 bytes and 16K guarded critical slack 269 bytes. Verification after the revert: `/private/tmp/seed-3c503-long-noskip-20260528T2030.pcap` completed a full long answer, then `Say done.` -> `done`, `Say ok.` -> `ok`, final DPI by user observation and harness OCR; `/private/tmp/seed-3c503-long-noskip-2-20260528T2048.pcap` also passed long/done/ok/DPI with narrow pcap evidence. Current count for this restored no-shortcut 3c503 long lane is 2/2 clean, but not yet 5/5.

2026-05-29T11:05+03:00 - Diagnosed the current WIP 3c503 long-loop failure and characterized three distinct failure modes. Decrypted the handoff target pcap `/private/tmp/seed-3c503-long-textdone-success-20260529T0835.pcap`: a single reused TLS flow (cca9, port 62324 -> Cloudflare 162.159.140.245) carried the cold greeting and the long answer, both completing fully on the wire (output_text.done, response.completed, and the `0\r\n\r\n` zero chunk). Seed ACKed 100% of the 137,917 server bytes, last ACK +125s, no FIN/RST; the server held the socket open (`Connection: keep-alive`). So the long answer itself fully succeeds; the `0D/F0`/`0D/12` is NOT a before-text-done failure. Answer to the diagnostic question: the fatal is case (c) - after the long answer succeeds and returns to DPI, during the follow-up turn. A fresh focused run reproduced it: greeting OK, long answer rendered + returned to DPI, `Say done.` submitted, then clean red `0D/12` (net_status 0x12 = net_status_tcp_connected) = the follow-up established TCP then failed in tls_probe_server. Root cause of mode (a): the 08:29 WIP made every 3c503 post-DPI follow-up force a fresh TLS handshake (api_stream_completed==2 early-success in agent_api.inc .check_complete + `tls_key_schedule_ready=0` in .success); note `api_stream_large_seen` is just an alias for `api_stream_prompt_len` (data.inc:153), so the carve-out fired on every follow-up (prompt_len>0), not on large records. 3c503's reconnect handshake races/flakes right after a long stream. Fix applied: removed both 3c503 carve-outs in agent_api.inc so 3c503 waits for true completion (completed==3 via zero chunk) and reuses the live keep-alive session like the NE family. Only 3c503 branches changed; 3c501/NE/WD byte-identical. make -B inspect passes, CORE.SYS 26112, 16K guarded critical slack still 269.

2026-05-29T11:05+03:00 - The reuse fix removed mode (a)'s red fatal but exposed/surfaced two more 3c503 long-loop failure modes, so the lane is still not green. (b) Deterministic on the keep-alive reuse path: after the long answer completes and returns to DPI, the short follow-up `Say done.` is built but NEVER transmitted (wire shows zero outbound bytes after the long prompt, no FIN/RST, no reconnect SYN; agent_api_exchange then waits forever -> gate-3 timeout, no fatal). In ready_tail a short prompt is inlined (chat_prompt_len_cache->0 at agent_request.inc:187) and is only sent via the prefix path, gated by `tls_app_len != 0`; agent_request provably sets tls_app_len to the request length, yet nothing is sent, so something the long answer's large-record path does (it rewrites tls_app_len per chunk and zeroes it at .record_done) leaves the follow-up send skipped. Could not pin tls_app_len's value: on-screen trace is unreliable here (the ~300 delta `d` traces wrap debug_trace_cursor, and the macOS window-capture intermittently fails); the committed SEED_COM_DEBUG serial channel referenced in memory is NOT present in this branch. (c) Intermittent (seen on edge 162.159.140.245): the long answer renders ~fully then a TLS record receive fails mid/near-end with clean `0D/F0` (hard fail, completed<2) - the known 3c503 long-stream receive flake (also seen 2026-05-28 run 3). The reuse fix increases (c) exposure because 3c503 now drains all the way to the zero chunk instead of early-returning at output_text.done. Working theory: modes (a) and (c) share a root - 3c503 large-record/long-stream receive reliability degrades after a long stream, so both the reconnect handshake (receives a large Certificate) and the stream tail flake. Next focus options: reliable instrumentation (re-add a scoped SEED_COM_DEBUG dump of tls_app_len/chat_prompt_len_cache at the Say done ready_tail) to crack (b); and a 3c503 receive-reliability pass for (c). Reuse fix kept in the tree as the cleaner base. Not committing per per-NIC plan.

2026-05-29T12:15+03:00 - Tooling + 3c503 long-stall (mode c) findings. Tooling: harness OCR/screen trace is reliable when launched with --foreground-launch (frontmost window makes macOS screencapture -l work); without it, ~2 of 4 runs failed with "could not capture 86Box window". With --foreground-launch the on-screen yellow trace is cleanly OCR'd (e.g. long-prompt ready_tail showed `RspFSAT` + delta `d`s = ready_tail/split/prefix-sent/tail F/S/A/T). COM serial capture (--com-capture) connects (PTY announced) but a naive 6x `out 0x3f8` dump only delivered 1 byte (the last, '>'): classic THR-overwrite with no flow control. A ~20-byte LSR-poll (in 0x3fd, test 0x20) fix would make it reliable, but since OCR works with --foreground-launch, COM is not needed now. Reset debug_trace_cursor at the trace site so the ~300 delta `d` markers don't bury later markers. Mode (c) characterization: with the reuse fix, the 3c503 long answer intermittently STALLS mid-stream (one run: rendered ~28 deltas of the first paragraph, then no more text, NO completion `C`, NO red fatal -> gate-2 timeout shape=success), while other runs complete fully (run 2 received 115 KB cleanly) or fatal late with 0D/F0. Root-cause evidence: the shared DP8390 receive path (net_rx.inc ne_try_receive_frame / ne_read_ring_pointers) never reads the page-0 ISR or clears the overflow (OVW, 0x10) bit and has no overflow-recovery sequence; on RX-ring overflow during a fast 137 KB burst the NIC stops receiving and Seed polls forever -> silent stall. (A TX wedge after heavy use is an alternative/parallel cause that would also explain mode (b)'s un-transmitted follow-up.) Mode (c) is now the dominant blocker: it prevents the long answer completing AND blocks reaching the Say done follow-up needed to diagnose mode (b). Next proposed step: implement DP8390 RX overflow recovery, scoped to family_3c503 first to keep NE lanes isolated. This is real but bounded NIC work; flagged to the user as a fork given prior rabbit-hole caution.

2026-05-29T12:25+03:00 - Correction to the mode (c) overflow hypothesis. build_tcp_segment_frame (net_tx.inc ~228) advertises a 256-byte TCP receive window for all non-3c501 NICs (3c501 uses 512). A 256-byte window means the server cannot overrun the 8 KB+ DP8390 RX ring, so RX ring overflow is NOT the likely mode (c) cause and DP8390 overflow recovery is probably the wrong fix. What the tiny window does imply: a 137 KB long answer is received as ~500+ small segment/ACK round-trips, so mode (c) is most consistent with an intermittent NIC RX-miss or ACK-TX hiccup accumulated over hundreds of cycles (position of the stall varies run-to-run: early stall, late 0D/F0, or clean completion). Tension to weigh next: a larger advertised window would cut round-trips (fewer chances to glitch) but then needs overflow recovery; keeping the small window needs the per-round-trip NIC RX/TX path hardened. Did NOT implement either yet - flagged to user as the real fork. Net state this session: reuse fix (agent_api.inc) removes mode (a) reconnect red-fatal and is the cleaner base; mode (b) follow-up-send-drop and mode (c) long-stream stall remain; tooling settled on OCR screen-trace + --foreground-launch + wire (COM not needed).

2026-05-29T13:00+03:00 - Mode (c) split into two distinct sub-failures and a fix for the dominant one. (c1) STALL: the 3c503 answer renders fully but never returns to DPI; completion is missed (completed stuck at 2) so agent_api_exchange waits forever -> gate-2 timeout, shape=success, no fatal. Root cause: with the reuse fix 3c503 waits for completed==3 (zero chunk), but tls_receive_large_application_record SKIPS decrypt/parse once completed>=2 (`cmp completed,2 / jae .cipher_drained`), so when the Cloudflare edge bundles response.completed + the `0\r\n\r\n` zero chunk into one >2097-byte record, the zero chunk is never scanned -> completed never reaches 3 -> stall. This is the same run-04 bundled-zero-chunk stall the 08:29 early-success experiment was masking. (c2) FATAL: a different run rendered most of the answer then clean red 0D/F0 (completed<2) = a genuine mid-stream TLS-record receive error before output_text.done; separate, rarer, not addressed here. Fix #2 (3c503-scoped, tls.inc .cipher_take_ready): for family_3c503 keep decrypting+scanning the large record past completed==2 so a bundled zero chunk still reaches completed==3 (continuous decrypt also keeps the ChaCha keystream in sync); other NICs keep the fast-drain skip. Build clean, CORE.SYS 26112, 16K guarded critical slack still 269. Also cleared a mode-(b) red herring: dpi .render_prompt resets dpi_input_len_byte=0 every turn (dpi.inc:126) and dpi_input_buf is re-typed, so the follow-up input is clean - mode (b) is in the ready_tail send branch (tls_app_len), not input corruption. Tooling note: --foreground-launch makes macOS window capture reliable; the full 137 KB long answer fails mode-c almost every run, so mode-b is being chased via a ~250-word prompt (forces a >2 KB response.completed large record but ~half the round-trips). Fix #2 + mode-b confirmation run in flight at time of writing.

2026-05-29T13:10+03:00 - Two more mode-(c) learnings. (a) Fix #2 (bundled-zero-chunk scan) did not fix the latest stalls because those were MID-stream stalls (answer rendered only partway, receive then stops, no completion, no fatal) - a third mode-(c) face distinct from the end-of-stream bundled-zero-chunk stall (c1, which fix #2 does target) and the mid-stream 0D/F0 fatal (c2). (b) Strong tooling correlation: every run launched with --foreground-launch failed the long/medium answer (0/4: stalls or 0D/F0), while the only run that completed the answer and reached the Say done follow-up (run 2, /private/tmp/seed-3c503-long-reusefix-20260529T0950) had NO --foreground-launch. AGENTS/handoff already warn to avoid --foreground-launch; it likely shifts host/emulation wall-clock timing enough to destabilize the ~500 small-segment round-trips of a 256-byte-window receive. Action: retry mode-b confirmation WITHOUT --foreground-launch (accept intermittent window-capture failures and retry on those) so the long answer can complete and reach Say done. Reuse fix + fix #2 retained.

2026-05-29T13:55+03:00 - Consolidated 3c503 long root cause + experiment outcomes; left a clean base. Used the WIRE (decrypt + ACK coverage) as the reliable diagnostic: on a stall run Seed ACKed 100% of the 211 KB answer and kept ACKing for 325s after the server finished - so Seed RECEIVES the entire answer (all terminal records) but never recognizes completion. So the stall is a completion-detection miss, NOT a receive stall. Fixed-cell trace 'Q' (set at the tls.inc 5-byte zero-chunk -> completed=3) never appeared => completed never reaches 3 (zero chunk not detected); 'C' (output_text.done matched -> completed=2) did appear. The terminal metadata records on the 172.66 edge are nearly all LARGE (output_text.done 2373 B, content_part.done 2395, output_item.done 2468, response.completed split 33 B + 3486 B), zero chunk a separate 5 B record; with the large-record fast-drain skip (after completed==2) the bundled/late records aren't scanned and the separate 5 B zero chunk isn't recognized as terminal -> 3c503 (waiting for completed==3) spins. Experiment A (3c503 accept completed==2 -> success + reuse): FIXED the stall - the answer returned to DPI and 'Say done.' was submitted (trace C,C,P) - but the undrained trailer (response.completed + zero chunk, all LARGE) poisoned the follow-up turn -> 0D/F0 (the 2026-05-20 trailer-poison hazard). Reverted A. Experiment B (fix #2: 3c503 scan large records past completed==2 to catch a bundled zero chunk): inconclusive - runs hit the mid-stream 0D/F0 (c2) before reaching the end; reverted. CONSOLIDATED ROOT CAUSE: 3c503 large-record receive reliability. All three faces share it - the answer's mid-stream 0D/F0 (c2 = ne_transmit_tcp_ack/tcp_receive_payload carry inside tls_receive_large_application_record during a big record), the trailer-poison 0D/F0 on reuse (re-processing the leftover LARGE response.completed on the next turn), and the reconnect 0D/12 (handshake must receive a LARGE Certificate). The zero-chunk-detection miss (stall) rides on the same large-record handling. LEFT STATE: kept the agent_api.inc reuse fix (3c503 reuses keep-alive + waits for completed==3) - it removes the 08:29 reconnect red-fatal and is the only state that has completed a full long+done+ok loop this branch (run 2, /private/tmp/seed-3c503-long-reusefix-20260529T0950). Reverted experiments A and B and all diagnostics; tls.inc/agent_api_stream.inc back to WIP baseline, build clean (CORE 26112, slack 269). NEXT FOCUSED STEP: harden the 3c503 large-record receive path (tls_receive_large_application_record): investigate the ne_transmit_tcp_ack / tcp_receive_payload timeout (cx=0xffff poll) that produces the intermittent mid-stream 0D/F0, and make completion robust (either reliable zero-chunk detection through large records, or output_text.done + a bounded trailer drain so reuse is clean). Tooling that works: screen trace + --foreground-launch, fixed-cell video traces for core code, and wire decrypt+ACK-coverage (most reliable).

2026-05-29T16:40+03:00 - Localized the 3c503 long stall to intermittent completion-detection in multi-large-record trailers (continuation). Confirmed on a STABLE network (cdiag2/cdiag3) that the stall is a real code bug, not a network artifact: the answer is fully received (100% ACK) and rendered, the final gate times out shape=success (no fatal). Caveat learned: a mid-run host network switch DOES poison runs (TLS connection drops -> spurious 0D/F0 right after send, no deltas); always cross-check the wire before trusting a failing run. Diagnostic method that works for core code: write a one-byte marker to a fixed video cell (e.g. debug_trace_video_seg offset 110) - but the ~hundreds of delta 'd' trace markers flood the trace row and tesseract collapses the run, so DISABLE the 'd' trace in agent_response.inc .scan_idle while diagnosing. Findings via a fixed-cell completed-value marker + the C/P/F/S/A/T trace: completion is INTERMITTENT in the large-record trailer - some runs reach completed==2 (output_text.done matched, two 'C's) then stall waiting for completed==3 (zero chunk never recognized); other runs never reach completed==2 at all (the bounded-drain experiment, gated on ==2, never fired). The decisive difference vs the one full-pass run (run 2, /private/tmp/seed-3c503-long-reusefix-20260529T0950): run 2's output_text.done was a SMALL record (small-path, reliable completion); the stall runs have output_text.done + content_part.done + output_item.done + response.completed ALL as back-to-back LARGE records (>2097 B), and the large-record streaming path (tls_receive_large_application_record + per-chunk agent_response calls) intermittently loses the completion markers. Inspected tls_receive_large_application_record: the skip/parse accounting, the ChaCha keystream (tls_xor_large_app_chunk, per-record counter=1/offset reset, per-record nonce), and the matcher-state persistence all look correct on paper, so the bug is subtle (chunk-boundary handling or matcher state across the per-chunk agent_response calls). Experiments this continuation, all REVERTED to the clean reuse+wait-for-3 base: (A) accept completed==2 + reuse -> answer returns but trailer poisons follow-up 0D/F0; (B) 3c503 parse large records past completed==2 -> didn't reliably fix it; (C) bounded trailer drain (api_http_state counter) -> didn't fire because completed often never reaches 2. NEXT FOCUSED STEP: per-chunk instrument tls_receive_large_application_record across the multi-large-record trailer (dump decrypted chunk heads / api_stream_done_match + api_http_header_match state at each chunk via fixed-cell video markers, 'd' trace disabled) to find why output_text.done / the zero chunk are intermittently missed when 4 large records arrive back-to-back. State: kept the agent_api.inc reuse fix; tls.inc/agent_response.inc/agent_api_stream.inc at WIP baseline; build clean (CORE 26112, slack 269).

2026-05-29T17:25+03:00 - Found a CONFIRMED regression behind the 3c503 long completion miss: the small-record receive path lost tls_preserve_buffered_payload. git show HEAD:tls.inc has `.application_record: call tls_preserve_buffered_payload; call tls_increment_server_record_seq; ret`, but the WIP removed the preserve call. That preserve (the 2026-05-20 fix) copies any following-record bytes that share the frame into tls_rx_copy BEFORE ne_transmit_tcp_ack rebuilds ne_tx_frame. Without it, when a small trailer record (e.g. response.completed-start) shares a frame with the next LARGE record's start, the ACK clobbers that buffered start -> the next record is parsed from a corrupted header -> completion (output_text.done / zero chunk) intermittently missed. Matches the signature exactly: intermittent, amplified by multi-large-record trailers (more small->large transitions), and the answer still renders (the deltas are small records received earlier; only the trailer corrupts). RESTORED the preserve call in .application_record. Also re-applied fix #2 (3c503 scan large records past completed==2) as a complement for the BUNDLED zero-chunk case (preserve handles the separate-record case; fix #2 the bundled case). Net code now: agent_api.inc reuse fix + tls.inc preserve-restore + tls.inc fix#2. Build clean (CORE 26112, slack 269). VERIFICATION BLOCKED by environment: the user switched host network mid-session, which poisons runs (connection drops -> forced reconnect -> 0D/12 handshake fail with the answer barely rendered; distinct from the stall). Host connectivity later measured stable (3x curl api.openai.com ~0.35s). Also hit intermittent 3c503 COLD-handshake 0D/12 at gate 1 (known separate cold flakiness, not the long-answer path). Running a serial 4x medium-loop matrix to get a reliability signal past the intermittency. The preserve-restore is the high-confidence fix; fix #2 is complementary; both need stable-network multi-run confirmation.

2026-05-29T18:40+03:00 - MAJOR RE-FRAME (user-prompted): the 3c503 long "stall" is NOT a stall - it is premature gate termination of active-slow rendering, plus a follow-up failure caused by that slowness. Proof: re-ran the medium loop with a 700s gate (vs 280s) + --leave-running. The answer RENDERED COMPLETELY and returned to DPI; the harness then typed "Say done". So earlier gate-2 "timeouts" (shape=success, changed=True every sample) were the 280s gate cutting off a still-rendering answer. The 8088 is just slow: the 256-byte advertised TCP window forces ~750 round-trips for a long answer, ~300-690s wall-clock (RTT-bound). Wire for the follow-up failure (flow 54215->162.159.140.245): handshake+greeting+medium-prompt by +67s; server (Cloudflare) sent FIN at +475.9s closing the connection; the slow VM only finished + sent the "Say done" request (332 B) at +690.6s onto the dead socket; server replied RST -> 0D/F0. So the follow-up 0D/F0 is a consequence of slowness (server idle/closes before the slow VM catches up to send the next prompt), not an independent receive bug. Implications: (1) earlier "stall" diagnoses across this session were premature-termination artifacts; use a >=700s gate or --leave-running + manual observation for 3c503 long. (2) fix #2 (parse large records past completed==2) made it WORSE (more decrypt = slower) -> correctly reverted. (3) the reuse fix is fine; the preserve-restore is a correct regression fix (HEAD had it) -> kept. (4) The real engineering problems are now: (a) 3c503 long-answer SPEED (256-byte window -> ~750 round-trips); a larger advertised window would cut round-trips and likely finish before the server FIN, but risks RX-ring overflow; (b) the follow-up after a long answer needs to detect the closed/FIN'd connection and reconnect (reuse hits RST), and/or finish fast enough that the server has not closed. Net code state: agent_api.inc reuse fix + tls.inc preserve-restore (fix #2 reverted). Build clean (CORE 26112, slack 269). Not committed.

2026-05-29T19:10+03:00 - Implemented the 3c503 long-answer SPEED fix from the 18:40 re-frame: a larger advertised TCP receive window so the long answer is bandwidth- not RTT-limited and finishes before the server's idle FIN. The 256-byte window (1 page) is SMALLER than one 1448-byte segment, so the server stop-and-waited every ~256 bytes (~535 round-trips for a 137 KB answer, ~hundreds of seconds). Now 3c503 advertises 2048 (8 pages); 3c501 keeps its known-good 512 (2 pages); NE/WD stay at 256. Byte-budget journey (both code AND data are exhausted on the 16K target): (1) inline family-cmp in build_tcp_segment_frame added ~10 resident-code bytes -> `LINK window overlaps high crypto scratch`; (2) a per-NIC `ne_tcp_window_pages` data byte set at packet_io_init fixed the code overflow but `low runtime state overlaps phase load window` (data region is exactly full); (3) no persistent byte is free - handoff struct is fully packed (46 B), and the setup-form scratch bytes the chat scanner reuses (api_stream_* aliased onto menu_/input_/form_) are clobbered by agent_setup which runs AFTER packet_io_init (net_phase:19) and before the agent connection. SOLUTION: a 5-byte lookup table `tcp_window_pages_table: db 8,1,1,2,1` (indexed by handoff_nic_family 1..5 = 3c503/ne2000/ne1000/3c501/wd8003), read in build_tcp_segment_frame via `mov bl,[nic_family]; xor bh,bh; mov al,[table-1+bx]; xor ah,ah; stosw`. This is net-zero vs the original 3c501-only window code plus a 5-byte table - it FITS (build clean, CORE.SYS 26112, 16K guarded critical slack still 269). Only net_tx.inc changed; data.inc/packet_io_init.inc reverted to baseline. WIRE CONFIRMATION: a 3c503 long run (greeting + the 16KB 8088 R/W/jump prompt + Say done + Say ok, /private/tmp/seed-3c503-winfix-20260529T190520.pcap) shows the Seed VM now advertising a uniform ~2048 window cluster (2045-2048, minimal stack/no wscale) instead of 256; gate 1 (greeting) passed and the VM connected to 172.66.0.243. Full-loop result (does the long answer now complete fast + return to DPI + does Say done succeed on the still-alive reused session) pending run completion. Caveat to weigh in analysis: this run used --foreground-launch (the 13:10 timing confounder), but with 8x fewer round-trips that sensitivity should be largely gone; the pcap rate is the reliable signal either way.

2026-05-29T20:46+0300 - SLiRP re-frame + universal reuse-then-reconnect follow-up algorithm (under test). TOOLING REALIZATION: the 86Box vm-net-* profiles use net_type=slirp, so the VM TCP is proxied through a host socket; the en0 pcap shows SLiRP's host-stack connection (wscale/timestamps/win 65535), indistinguishable from the Mac's own traffic, and CANNOT see the VM's real TCP window or isolate the VM flow. So the earlier win-2048 reading was host traffic not the VM, and en0 wire analysis is unreliable for these profiles - rely on the on-screen error code + guest behavior. Consequence: the larger-TCP-window experiment (net_tx.inc per-NIC lookup table 8,1,1,2,1) was REVERTED - under SLiRP the VM-to-proxy link is local (no real RTT) so the window barely affects speed; the ~5-11 min long-answer slowness is the 8088's own decrypt+render, and 2 KB also risked re-opening the 2026-05-22 0D/E8 drain that 256 B fixed. net_tx/packet_io_init/data back at baseline.

USER DESIGN DIRECTION (confirmed): one universal follow-up algorithm - try to REUSE the live session if open (short back-and-forth stays fast), REOPEN only if closed (long-answer case: OpenAI drops the idle keep-alive ~7 min in while the slow 8088 is still rendering, so the next prompt hits a dead socket). Not always-reuse (today's 0D/F0), not always-reconnect (the 08:29 0D/12).

IMPLEMENTED net_phase.inc prepare_agent_endpoint_path (net-zero): the reuse path now calls a .stream_and_exchange subroutine and, on failure, falls through to .connect_new_session (reopen) which calls .stream_and_exchange again. Net-zero bytes by removing the redundant handoff_status==ready guard (tls_key_schedule_ready==1 already implies a live post-handshake session; boot-cleared so it excludes the first request). Note agent_api_exchange is receive-only; the request SEND lives in the agent_api_stream phase .ready_tail (prefix via tls_app_len + prompt tail rebuilt from the SCREEN = the 2026-05-22 durable mechanism), so a reconnect resends from durable state.

MANUAL-ASSISTED TESTING (user types Say done after the long answer; en0 wire useless under SLiRP): test 1 = 0D/F0 (old code reused the dead socket). After the net_phase fix, test 2 = B6/06 with NO TX. Decoded: failure screen prints net_error byte / net_status byte; agent_cache.inc sets net_status=0xb606 -> B6/06. Root cause: agent_cache re-parses api_request_plain for key/model at FIXED cold-request offsets, but on a reconnect api_request_plain holds the READY-request layout -> parse fails. Important: the reconnect WAS correctly triggered (universal control flow works) - it only tripped on agent_cache. FIX (agent_cache.inc, in-phase so no resident-nucleus pressure): skip re-caching when handoff_status==ready - key/model already cached from the cold connect and still valid, and skipping preserves the live chat_prompt_len_cache. Build clean (CORE 26112, slack 269). Test 3 in flight; watching for done (success) vs 0D/12 (the known 3c503 reconnect-after-long-stream large-Certificate receive flake = next blocker).

2026-05-29T21:31+0300 - Universal reuse->reconnect->resend control flow COMPLETED, and it isolated the singular blocker. Changes this session: net_phase.inc prepare_agent_endpoint_path = try reuse (call .stream_and_exchange); on failure RE-RUN agent_request (the long answer's receive reuses tls_app_len/tls_app_total_len for received records, clobbering the request send-state; api_request_plain itself survives) then fall through to .connect_new_session (reopen + resend). agent_cache.inc = skip re-caching when handoff ready (fixed B6/06: agent_cache re-parsed api_request_plain at fixed COLD offsets, but a reconnect holds the READY layout). net_tx.inc = window collapsed to uniform 256 (3c501 was 512) to free the bytes for the rebuild - behavior-neutral under SLiRP (window has no effect on the local proxy link). Manual-assisted test progression (user types Say done; en0 wire useless under SLiRP): 0D/F0 (reuse on dead socket, pre-fix) -> B6/06 (agent_cache reconnect parse) -> reconnect-happens-but-empty-response (resend send-state clobbered) -> THIS RUN 0D/12 DURING long-answer streaming, no DPI. DIAGNOSIS: the long answer flaked MID-STREAM (pre-existing intermittent mode c2), the universal algorithm retried via reconnect, and tls_probe's large Certificate hit the SAME flake -> 0D/12. SINGULAR ROOT: 3c503 large-record TLS receive reliability - it gates BOTH the long answer completing AND any reconnect handshake (large Certificate). Two follow-ups: (1) the algorithm should NOT reconnect on a mid-stream flake, only on a truly-closed socket (guard: cmp api_stream_text_seen,0 -> if text already rendered, fail clean instead of reconnect; needs ~6 reclaimed bytes); (2) the core fix is the large-record receive path (the notes' circled issue: per-chunk instrument tls_receive_large_application_record). Build clean (CORE 26112, slack 269). Universal algorithm kept in tree (correct architecture per user design); NOT committed (lane not green).

2026-05-29T22:27+0300 - 3c503 LONG LOOP WORKS (user-confirmed): long response + short follow-ups (Say done / Say ok) all complete and return to DPI. ROOT CAUSE of the dominant intermittent long-answer stall FOUND + FIXED. tls_receive_large_application_record had a fast-drain: once api_stream_completed>=2 (output_text.done seen) it skipped decrypt+parse for the rest of the large record. On Cloudflare edges that BUNDLE the terminal 0\r\n\r\n zero chunk into a large (>2097 B) trailer record, the fast-drain skipped the zero chunk unscanned, so completed never reached 3 -> the exchange spun forever -> stall. (My universal algorithm then turned that stall into a reconnect that hit the SAME large-record flake on the handshake Certificate -> 0D/12, which is what the last failing run showed.) The bundling is edge-dependent -> that is exactly why it was INTERMITTENT (the notes' circled c1 stall, and likely much of the "16K intermittent" memory note). FIX: removed the fast-drain; large records are now always decrypted+scanned (restores the 2026-05-24 design), so the bundled zero chunk is caught -> completed==3 -> clean completion. Full fix set this session (all kept, NOT committed): (1) net_phase.inc universal reuse->reconnect->resend (try reuse; on failure re-run agent_request to rebuild the receive-clobbered send-state, then reopen+resend); (2) agent_cache.inc skip re-caching on reconnect (B6/06 was agent_cache re-parsing api_request_plain at cold offsets); (3) net_tx.inc uniform 256 window (3c501 was 512; behavior-neutral under SLiRP) to free bytes; (4) tls.inc remove large-record fast-drain = THE stall fix. CLEANUP: stripped debug-trace machinery (3 trace funcs + F/S/A/T/P/C/d markers + debug_trace_cursor/attr; renamed debug_trace_video_seg->color_video_seg keeping its 2 legit color-text screen read/write uses); build clean, CORE 26112, slack 269, behavior-preserving (verified push/pop balance + control flow). STABILIZATION GATE agreed with user: 4-5 long + 5 short runs on the cleaned build = 3c503 stabilized. Auto-harness full-loop run in flight (testing whether it can now run hands-off since the answer completes). Commit when fully stabilized.

2026-05-30T00:13+0300 - 3c503 STABILIZED (long loop) and committed. Stabilization batch (4 long + 5 short auto, --foreground-launch, cleaned debug-trace-stripped build): 8 clean (incl. the prior auto long run); every long-loop that reached the chat completed. 2 setup-phase failures: long-3 (transient wifi blip - YouTube dropped too) and short-5 (0D/12 cold handshake AFTER the wifi recovered + 5 clean runs, so the known pre-existing intermittent 3c503 cold-handshake Certificate-receive flake; recoverable via the on-screen retry; separate from the long loop). NOTE: harness exit codes are unreliable here (returns 0 even on a gate-1 clean-failure) - grade by log verdict=success, not exit code. SCOPE (confirmed via grep): the session fixes are SHARED / NIC-agnostic, NO family gates (net_phase follow-up, tls large-record zero-chunk, agent_cache reconnect-skip, net_tx uniform 256 window) = the 'unify' step reached by fixing protocol-level bugs; the per-NIC pacing/receive/TX-dispatch (agent_api, tls receive, net_rx, net_tx dispatch) stays family-gated. Committed as the 3c503-stable milestone. NEXT: re-verify NE/WD/3c501 against the shared build (untested, likely improved); cold-handshake 0D/12 is a tracked known item; family-gate any NIC-specific tweak; restore 3c501's 512 window if real-hardware testing needs it.

2026-05-30T00:29+0300 - OVERNIGHT AUTONOMOUS (user asleep). Goal: stabilize a 2nd NIC = vm-net-ne2k8 (NE2000; DP8390 control, closest to 3c503, best validates the shared fixes) as a SEPARATE PATH that keeps 3c503 green. Setup: timestamped ping to 8.8.8.8 (/private/tmp/seed-overnight-ping.log) runs alongside the VMs to distinguish wifi hiccups from real failures (per user). Method: grade by log verdict=success (NOT exit code - it returns 0 even on a gate-1 clean-failure). Loop: NE2K8 smoke (2 long + 2 short) on the committed shared build -> if clean, scale to 5 long + 5 short -> any REAL failure (not wifi per the ping log): diagnose via on-screen oracle + failure code + screenshot (wire is blind under SLiRP), fix FAMILY-GATED (family_ne2000, never touching 3c503's path), rebuild, re-verify NE2K8 AND re-run a 3c503 long loop to confirm no regression. Will NOT commit autonomously - leave NE work uncommitted + a morning writeup; 3c503 commit 4162147 stands. Loop is driven by background-batch completions re-invoking me.

2026-05-30T01:10+0300 - NE2K8 smoke: 4/4 PASS (long-1, long-2, short-1, short-2; graded verdict=success). The shared/committed 3c503 build carries over to NE2K8 (NE2000) CLEANLY - no NE-specific changes needed so far, so the protocol fixes are genuinely NIC-agnostic as expected. Robustness bonus: the ping log shows a ~18s wifi hiccup (8.8.8.8 timeouts icmp_seq 465-474, 00:46:18-00:46:36) DURING long-2's answer, and long-2 still PASSED - the universal reuse->reconnect->resend recovered from a real mid-answer network drop (not just the idle keep-alive close). Scaling to a full NE2K8 5 long + 5 short gate (no code changes; 3c503 untouched).

2026-05-30T02:46+0300 - NE2K8 FULL gate: 9/10 PASS (long-2,3,4,5 + short-1..5). The 1 FAIL = long-1 (center_red, 01:12:31-01:22:58) is ENVIRONMENTAL: the ping log shows a ~31s wifi outage (8.8.8.8 timeouts 01:22:36-01:23:07) hitting long-1's end. Robustness pattern: the universal reuse->reconnect->resend RECOVERED from transient hiccups (long-5 through a ~6s drop at 02:06; smoke long-2 through ~18s at 00:46) but a sustained ~31s outage during the run's critical path is a legitimate failure (network down too long). NE2K8 is product-stable on the committed shared build with NO NE-specific changes - the protocol fixes are NIC-agnostic. User's wifi is flaky tonight (3 hiccups in ~2h), so runs need ping cross-check. Re-running 2 NE2K8 long to fill a clean 5/5 long (already 5/5 short). No code changes; 3c503 untouched.

2026-05-30T03:12+0300 - NE2K8 long re-run (2): long-1 FAIL, long-2 PASS. long-1 [02:52:18-02:57:50] = NOT wifi (ping CLEAN, 195 ok / 0 timeouts in window) -> the red screen reads "agent setup failed 0D/12" + "retry", with the long answer partially rendered. So this is the PRE-EXISTING intermittent 0D/12 TLS-handshake flake (Certificate receive), here on the universal RECONNECT handshake after a mid-stream drop, network UP. NIC-agnostic (TLS layer), NOT a regression, recoverable via on-screen "retry" (harness doesn't auto-retry so it counts as a gate fail). long-2 [02:57:53-03:09:29] = full clean ~11.5min long render + reconnect + ok.
  NE2K8 STATUS: bar MET - 5 clean long (full-gate long-2,3,4,5 + rerun long-2) + 5 clean short, with ZERO NE-specific code changes (shared committed fixes are NIC-agnostic). 2 fails to date: 1 wifi outage (full-gate long-1) + 1 retryable 0D/12 (rerun long-1). FINDING: now that the stall is fixed, the 0D/12 handshake flake is the dominant non-environmental failure, and it also bites the reconnect handshake. Possible future hardening (SHARED change, discuss w/ user first - touches 3c503): internal handshake-retry on reconnect instead of surfacing 0D/12. NOT attempting overnight. Running 3 more NE2K8 long to characterize the 0D/12 rate.

2026-05-30T03:50+0300 - NE2K8 char (3 long): long-1 FAIL(0D/12, ping CLEAN -> the TLS-handshake flake again, network up), long-2 PASS, long-3 PASS. long-3 PASS spot-checked against false-green: GENUINE - full ABI answer rendered, then say done->done + say ok->ok with prompt return (the universal reuse->reconnect->resend works end-to-end on NE2K8).
  *** NE2K8 STABILIZED *** Aggregate long tally (full-gate + rerun + char): 10 attempts, 7 clean PASS, 3 FAIL = 1 wifi outage (full-gate long-1) + 2 network-up 0D/12 (rerun long-1, char long-1). Short: 5/5 clean. Bar (5+5) exceeded with ZERO NE-specific code changes; the committed shared fixes are NIC-agnostic, so the user's "separate path in case NE needs changes" concern was moot.
  0D/12 RATE ~20% (2/10), network-up, NIC-agnostic, recoverable via on-screen retry but the harness counts it a gate fail. WEAK LEAD (n=2, do not over-read): both 0D/12 landed on the FIRST run of a batch (first cold launch after a multi-min idle gap); back-to-back subsequent launches passed. Could be a cold-start handshake issue or just chance. RECOMMENDATION for user (SHARED change, touches 3c503 - discuss first): internal handshake-retry on reconnect/cold, or a cold-start warmup, to absorb the 0D/12 instead of surfacing it. NOT attempting overnight.

2026-05-30T04:36+0300 - WD8003e SMOKE (bonus, test-only): 4/4 PASS - long-1, long-2, short-1, short-2 all verdict=success on the committed shared build, NO WD-specific changes. long-1 [03:50:58-04:04:24] survived a REAL ~5.5min intermittent-loss wifi window (34 ping timeouts 03:58:58-04:04:29 overlapping its 2nd half) and still passed; false-green-checked: full ABI answer + say done->done + say ok->ok + DPI return. So the universal reuse->reconnect->resend rides out transient loss on the shared-memory NIC too. Dir /private/tmp/seed-wd8003-smoke-20260530T035045. => the committed shared fixes generalize across 3 NIC families now (3c503 committed, NE2K8 validated, WD8003e smoke) + known-good 3c501.

==================== OVERNIGHT SUMMARY (2026-05-30, autonomous) ====================
TASK: pick + stabilize a new NIC as a separate path (protect 3c503), run a ping alongside to filter wifi.
OUTCOME:
- 3c503: stabilized + committed 4162147 (before tonight).
- NE2K8 (the picked NIC): STABILIZED. 10 long attempts -> 7 clean PASS (full long + say done + say ok + DPI, false-green-checked) + 5/5 short. 3 fails = 1 wifi outage + 2 network-up 0D/12. ZERO NE-specific code changes needed - the committed shared fixes are NIC-agnostic, so the "separate path in case NE needs changes" was moot (nothing to isolate).
- WD8003e (bonus smoke): 4/4 (2 long + 2 short), one long survived a ~5.5min loss window. No WD-specific changes.
- NO CODE CHANGES were made tonight (only notes/memory). 3c503 untouched -> no re-verify needed (byte-for-byte the committed build). Nothing committed; left for user review.
KEY FINDING (0D/12, code-grounded): now that the stall is fixed, the intermittent 0D/12 is the dominant non-environmental failure (~20% of long runs, network UP, NIC-agnostic, recoverable via on-screen retry but counts as a gate fail). ROOT: the (re)handshake Certificate receive (tls_probe_server -> tls_wait_for_server_certificate -> tls_ensure_current_handshake_record_complete / tls_drain_server_certificate, tls.inc:219-345) reads the large multi-segment cert chain via repeated ne_transmit_tcp_ack + tcp_receive_payload; tcp_receive_payload (transport.inc:1) has a BOUNDED poll (tcp_payload_wait_count x spin-delay) and on timeout returns net_error_tcp -> the whole handshake aborts -> 0D/12. Intermittent because a single late segment (cold TCP/TLS after idle, SLiRP warm-up, host jitter) trips the bound. This is a SEPARATE path from the always-decrypt data-path fix (tls_receive_large_application_record, tls.inc:1032) - so the 0D/12 is neither a regression nor covered by that fix. WEAK lead (n=2): both NE2K8 0D/12 landed on the first cold launch after an idle gap.
RECOMMENDATION (SHARED - touches 3c503/3c501/NE/WD; discuss before implementing): (a) raise tcp_payload_wait_count so a late cert segment doesn't abort the handshake (also helps the data-path mid-stream 0D/F0 the 05-29 note flagged); and/or (b) auto-retry the reconnect handshake once on 0D/12 (the screen already offers a manual retry). NOT changed tonight.
WIFI (ping log /private/tmp/seed-overnight-ping.log): flaky overnight - bursts ~00:46(18s), ~01:22(31s), ~02:06(6s), ~03:58(5.5min intermittent). Used to separate environmental from real failures. (YouTube also dropped earlier per user = environmental, not Seed.)
NEXT (for user): decide on the 0D/12 hardening (shared); optionally extend WD8003e to full 5/5; then ne1k/novell-ne1k/wd8003eb/3c501 against the shared build; then consider unifying per-NIC pacing.
====================================================================================

2026-05-30T05:22+0300 - 3c501 REGRESSION SMOKE: 4/4 PASS (2 long + 2 short) on 4162147. 3c501 is the NIC the commit CHANGED (uniform 256B window removed its 512B special-case) and the most-different (el1 single-buffer, render-before-ACK) -> NO regression. long-2 [04:50:17-05:04:23] survived an ~8min intermittent-loss window (17 ping timeouts 04:52:02-04:59:49) and passed; false-green-checked (say done->done + say ok->ok + DPI return). No 0D/12 this batch. Dir /private/tmp/seed-3c501-smoke-20260530T043946.
  COVERAGE NOW: all 4 NIC families validated on the committed shared build 4162147 with ZERO per-NIC code changes - 3c503 (committed), NE2K8 (stabilized 7L+5S), WD8003e (smoke 4/4), 3c501 (regression smoke 4/4). Shared fixes confirmed NIC-agnostic; the commit regressed nothing (incl. the NIC it changed). Untested on 4162147: ne1k, novell-ne1k, wd8003eb. The only systemic residual across all of them is the shared 0D/12 handshake-Certificate-receive flake (root + recommendation above).

2026-05-30T12:18+0300 - *** RECONNECT-RESEND BUG FOUND + FIXED *** (user caught the oracle false-green: a reconnect returns to the DPI prompt with NO response, no error).
ROOT (net_phase.inc): on every reconnect the code did `mov word [tls_app_len], 0` (the old line 56) right before .stream_and_exchange. But the reuse-fail path already re-runs agent_request, which correctly rebuilds tls_app_len, AND the TLS HANDSHAKE never touches tls_app_len/total (only the APP-DATA receive writes them, tls.inc:916-918). So the zeroing DESTROYED the correct send-state. For an INLINE follow-up (chat_prompt_len_cache=0, e.g. "say done"/"say three"/"say ok"), agent_api_stream .ready_tail with tls_app_len=0 takes neither the prefix-send (tls_app_len==0) nor the tail-append (cache==0) -> SENDS NOTHING -> the reconnect reopens a live session but never resends the prompt -> prompt returns empty, no error. The NEXT prompt rides the now-live session, so it works (matches the user's exact symptom). Triggered by ANY inline prompt that needs a reconnect: after a long answer's idle, OR a long user idle before a short prompt (user repro: wait long, then "say three" -> empty). Deterministic per-reconnect; looked ~1/13 only because natural reconnects are rare.
FIX: REMOVE the `mov word [tls_app_len], 0`. The rebuilt tls_app_len survives the handshake, so .ready_tail resends the full inline (or split) request. Byte-NEGATIVE (frees nucleus bytes). Cold path unchanged: cold uses its own send path and ignores tls_app_len here (it works today with the value at 0; leaving it set is harmless).
WRONG FIRST ATTEMPT (recorded so we don't repeat it): re-running agent_request AFTER tls_probe_server (call_core_phase at the old line 56) was logically correct but CORRUPTED the just-established cold TLS session -> clean A/B showed committed build cold 3/3 PASS vs that build cold 5/5 FAIL in the SAME window. Reverted. Lesson: do NOT re-run the request builder after the handshake; only restore the length (here: just don't destroy it).
VALIDATION (3c503, force-hook makes EVERY follow-up reconnect): 14/14 non-environmental forced-reconnect resends RENDERED (short-1 one..five, short-2 one..five, short-3 one..four then a wifi-blip 0C/10 on turn 5 per ping 12:08:22-26) + cold 3/3 OK. Resend fix CONFIRMED.
HARNESS CAVEAT (important): the screen oracle FALSE-GREENS an empty reconnect (it sees the prior long answer + a prompt = "success"). ALL reconnect grading must check the actual response tokens (done/ok/one..five), never bare verdict=success. The temporary force-hook in net_phase (TEMP-VALIDATION comment) forces every follow-up to reconnect for deterministic testing; REMOVE it for the production (reuse-first) build.
NEXT: forced 5+5 per NIC (3c503 running, then NE2K8/WD8003e/3c501) graded by responses; then production build + normal sanity; uncommitted for review. The separate 0D/12 handshake-cert-receive flake is unchanged (deferred).

2026-05-30T13:29+0300 - 3c503 forced 5+5 (force-hook): SHORT 4/6 fully clean (one..five rendered through forced reconnects); short-2/short-6 rendered the early turns then hit a mid-loop 0D/12 (the SEPARATE handshake flake, clean ping) -> resend works, 0D/12 is the deferred separate issue. LONG 0/6: all died at GATE 2 = the long PROMPT's forced reconnect (0D/12), ~3min each, before the answer. Note: forcing the long PROMPT (205-char, likely SPLIT request) to reconnect is an UNREALISTIC scenario - normally the long prompt reuses the greeting session; the realistic long-loop reconnect is the short say done/say ok afterward (inline -> covered by the forced-short test). long-1,2,3 (13:03-13:13) had clean 8.8.8.8 ping but the API path may have been marginal 13:03-13:22; disambiguating with 2 forced-long now (env vs a real split-reconnect edge). The inline reconnect resend (the user's actual bug) is FIXED + proven.

2026-05-30T13:38+0300 - Forced-long disambiguation: 2/2 forced-long FAILED again (13:29-13:35, ~3min, 0D/12 at the long-PROMPT reconnect) with 0 ping timeouts = REAL edge, not env (8/8 total). Mechanism: forcing the ~205-char long prompt to reconnect runs agent_request (large request build) right before the handshake -> 0D/12 at the handshake (same "builder-around-handshake corrupts it" class as the reverted first fix). NOT my regression (my fix is post-handshake; the 0D/12 is at the handshake) and NOT the user's bug. UNREALISTIC: the long prompt always reuses the fresh greeting session; it never reconnects normally. The realistic long-loop reconnect is the short say done/say ok (inline -> FIXED + proven). => VALIDATION APPROACH: forced-SHORT (inline reconnect resend proof) + normal-LONG (realistic long loop). The long-PROMPT-reconnect edge is SEPARATE/pre-existing/rare - flag for later, do not chase now.

2026-05-30T15:35+0300 - *** INLINE RECONNECT RESEND PROVEN, ALL 4 NIC FAMILIES *** (forced-short, every follow-up reconnects): 3c503 4 clean 5/5 (chipmem), NE2K8 2 (remote-DMA), WD8003e 3 (sharedmem), 3c501 4 clean 5/5 (el1 single-buffer). 13 fully-clean forced-short runs = 65 forced-reconnect resends RENDERED. Partials were the separate 0D/12 handshake flake (clean ping) or a wifi blip (NE2K8 short-3, 34s outage 14:07-08); their pre-fault turns rendered. The fix (remove the net_phase tls_app_len reconnect-zeroing) is NIC-AGNOSTIC - confirmed on all 4 TX/RX paths. Phase A complete. Removing the force-hook now -> production (reuse-first) build for Phase B normal 5+5 per NIC.

2026-05-30T18:26+0300 - *** RESIDUAL POST-LONG EMPTY = ROOT-CAUSED (TCP/pcap) = the deferred 0D/12 handshake-timing flake ***
Path: the long render's idle (~8-11min) EXCEEDS the server keep-alive (>5min: a 300s idle-then-short REUSED, 1 SYN; the ~8.5min render reconnected, 2 SYNs), so post-long say-done RECONNECTS (reuse-fail on the dead socket -> reconnect). The reconnect's TLS handshake then fails: pcap (vm-net-3c503, both conns to 172.66.0.243) shows the 8088 takes ~7.1s for the ECDHE key compute (cert-in -> ClientKeyExchange-out), and the CCS+Finished lands ~7.5-7.6s in. Cloudflare's handshake timeout is ~7.5s: COLD conn made it (CCS+Finished @7.49s -> server Finished -> app data -> greeting OK); RECONNECT missed it (server FIN @7.5s, VM's CCS+Finished @7.6s -> RST). So the handshake is RIGHT AT the server timeout -> ~25% it's a hair too slow -> server closes mid-handshake -> reconnect never establishes -> say-done request hits a dead socket -> EMPTY (no response, no red). SAME ROOT as the 0D/12 (marginal handshake timing): detected FIN = 0D/12 red; undetected = silent empty.
NOT my zeroing fix's domain (that fixes the reconnect SEND once the handshake completes - still valid, forced-short 65/65). The residual is the reconnect HANDSHAKE failing.
WHY post-long-specific: reconnects only happen after a >keep-alive idle, and only the long render idles that long. Short loops reuse (no reconnect) -> no residual.
FIX LEVER (handshake timing; the deferred shared area - discuss before implementing): the 3c501 timing contract already says "Send ClientKeyExchange BEFORE the expensive PRF/key-block work" - 3c503's pcap shows it sends CKE AFTER the ~7s work, landing at the timeout. Applying 3c501's early-CKE to all NICs would get the CKE to the server sooner and beat the timeout (likely fixes BOTH the empty and the 0D/12). Alternatives: detect the mid-handshake FIN/RST -> fail+retry (turn the silent empty into a retried reconnect); or retry the reconnect handshake once.
RECONNECT-TEST LEARNING: reconnects need idle > keep-alive (~5-8min); the idle-then-short test must use --post-dpi-idle ~540s (300s reused). The post-long sequence (long -> say done) naturally reconnects = the reliable reconnect test.

2026-05-30T18:28+0300 - CORRECTION + UNIFIED ROOT CAUSE (supersedes the early-CKE fix idea above).
Read tls.inc:30-56: 3c501 AND 3c503 ALREADY send CKE early (line 37-38); NE2K8/WD8003e send it LATE (after the key-block). BUT the 3c503 pcap shows CKE STILL at +7.1s -> the ~7s is the 8088's ECDHE KEY-GEN (the client's ephemeral P-256 keypair), which must happen BEFORE the CKE regardless of early/late. So "early CKE" only saves the post-CKE key-block time; it cannot beat the ~7s key-gen. Extending early-CKE is NOT the fix (it would help NE2K8/WD8003e reach 3c503's level but not fix the root).
UNIFIED ROOT: the 8088's ~7s ECDHE handshake (key-gen ~7s + shared-secret/key-block + CCS+Finished, total ~7.5s) lands RIGHT AT Cloudflare's ~7.5s handshake timeout. Marginal race -> ~20-25% the flight is a hair too slow -> server FIN/RST mid-handshake -> handshake fails. This is the SAME root for BOTH: boot 0D/12 (cold handshake, the VM detects the fail -> red 0D/12) and the post-long empty (reconnect handshake, the VM does NOT detect the FIN -> proceeds -> sends request to a dead socket -> silent empty). Evidence: cold conn made CCS+Finished @7.49s (server completed); reconnect conn @7.6s (server FIN @7.5s) - same VM, 0.1s tipped it.
REAL FIX (the deferred handshake area - significant, needs user decision; do NOT implement unsupervised):
  (1) TLS session resumption (reuse the session ticket/ID from the first handshake -> abbreviated handshake skips ECDHE -> fast reconnect within the timeout). Best fix; a real feature to build.
  (2) Detect the mid-handshake FIN/RST -> turn the silent empty into a detected fail -> retry the reconnect handshake once (a marginal race -> a retry likely succeeds; ~25% -> ~6%). More contained.
  (3) Speed the 8088 ECDHE (hard; inherent).
This is the dominant remaining reliability ceiling across ALL NICs (cold 0D/12 ~20% + post-long reconnect empty ~25%). My tls_app_len reconnect-send fix is valid + orthogonal (fixes the SEND once the handshake completes; proven forced-short 65/65). The reconnect-test automation (--post-dpi-idle + post-long sequence) is the regression harness for whatever handshake fix is chosen.

## 2026-05-30 (cont.) - keep-alive measured dead, retry hits byte wall, stopgap shipped

Keep-alive-during-render evaluated + rejected as universal: measured api.openai.com idle
timeout = EXACTLY 400s, and a TCP keep-alive does NOT extend it (Cloudflare closes on
HTTP-request inactivity, not TCP packets). A keep-alive would need a request-level ping,
and it cannot cover the hours-long-idle case at all -> the reconnect ITSELF must be
reliable. (Probe: /private/tmp/seed-keepalive-probe.py.)

Full bounded retry (ensure-live -> reconnect-with-retry -> send, max 8, clean error on
exhaustion) DESIGNED + IMPLEMENTED + cold-safe (notes/net_phase_retry_draft.inc), but
net_phase is INSIDE the link window (resident code + crypto share the 0x3400 ceiling).
The retry overflows by ~15-20B even after max net_phase shrinking (merged the two send
sites, dropped the net_status write, removed a redundant request build). SAME byte wall
as session resumption. => reclaiming ~15-20B in the crypto/tls region is the gating
prerequisite for the full retry AND resumption.

STOPGAP shipped (+8B, fits): agent_api_exchange returns CARRY when an exchange completes
with NO text rendered (api_stream_text_seen==0). The committed reuse-fail -> reopen ->
resend path then auto-recovers the silent empty. cmp against 0 never sets CF, so the
non-empty path still returns nc (no regression). Validated on 3c503:
- no-regression short loop: 3/3 (cold + reuse unaffected).
- post-long recovery (long render idles the socket >400s, then say done/say ok): 2/3
  trials fully rendered BOTH follow-ups; 1/3 reconnected but the handshake raced -> clean
  0D/12 (NOT a silent empty). Silent post-long empty ELIMINATED; residual = the ~25-33%
  handshake race (same root as the cold boot 0D/12), which only the full retry fixes.

NEXT: reclaim ~15-20B in the link window -> apply net_phase_retry_draft.inc -> full
bounded retry -> auto-retry the race + hours-idle seamless (~100%).
