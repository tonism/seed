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
