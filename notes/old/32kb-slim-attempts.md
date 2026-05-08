# 32KB OpenAI Attempts

## 2026-05-06 - Initial 32KB scratch-layout work

Branch: `work/32kb-slim`

Starting point:
- Remote `main` / `work/48kb-slim` had a known-good 4.77 MHz OpenAI proof:
  valid NIC profiles, including the 3c501 after the 48KB fix, reached
  `seed build 6` and displayed returned `ok`.
- The first 32KB work kept one `CORE.SYS`, one floppy image, and one code path.
  The runtime stack was moved to `0x8000`; the loader stack was also moved to
  `0x8000`.
- The root 32KB pressure came from resident buffers and crypto scratch that
  were separate in the 48KB/64KB shape. The 32KB experiment moved phase-local
  buffers into low/high scratch arenas outside the loaded `CORE.SYS` image.

Memory-shape changes tried:
- Low scratch: `0x0700..0x1000` for loader-reusable I/O and crypto scratch.
- High scratch: below the 32KB stack guard for TLS receive/API request data.
- Added an assembly guard so `CORE.SYS` cannot overlap the high scratch arena.
- Set all supported NIC 86Box profiles to 32KB RAM.

Observed results:
- Boot gets past the loader after the stack relocation; the original black
  screen was a memory-above-installed-RAM assumption, not a fundamental 32KB
  boot impossibility.
- The 32KB NE2K path reaches TLS server Finished verification, then fails in
  the agent/application-response phase.

## 2026-05-06 - Response-size and streaming probes

Host-side OpenAI probes, using the same TLS 1.2
`ECDHE-ECDSA-CHACHA20-POLY1305` cipher, showed:
- `{"model":...}` returns a small 400 response around 1.0KB.
- `{"model":...,"input":"Reply exactly: ok"}` returns about 2.7KB.
- Adding `"max_output_tokens":16` reduces the successful non-streaming
  response to about 2.2KB, typically split into two host reads.
- Adding `"stream":true` returns first bytes quickly and contains
  `"delta":"ok"` in a later event; observed host reads stayed at or below
  about 1369 bytes.

Changes tried:
- Added `"max_output_tokens":16` to reduce the non-streaming OpenAI response.
- Temporarily raised the high TLS receive buffer to about 2304 bytes.
- Switched to `"stream":true` and added parser support for `"delta":"`.
- Raised the API receive loop from 8 to 16 records.
- Restored the safer 512-byte stack guard by keeping `high_scratch_end` at
  `0x7e00` and moving `high_scratch_start` as needed for test builds.

Observed VM results:
- NE2K still failed after server Finished.
- A coarse marker showed failure during TLS application receive (`r`).
- Raising `tcp_payload_wait_count` from 2048 to 16384 did not change the result.
- Finer markers showed final failure marker `A`: the VM received and
  authenticated an encrypted TLS alert instead of accepting an application data
  record as the answer path.

Current interpretation:
- This is no longer a DHCP/DNS/TCP/NIC bring-up issue; the path reaches past
  TLS server Finished.
- The `A` marker means OpenAI responded at the TLS layer after our application
  request. The most likely causes are an invalid encrypted application record,
  a sequence/order drift from the known-good remote flow, or a parser/receive
  loop that consumes application records and then reports the final close alert.
- The remote ordering should remain the baseline. Any further 32KB optimization
  should first preserve the known-good request/final-flight sequencing, then
  prove whether any application records are received before the alert.

Follow-up diagnostic:
- Added an application-record counter before the alert marker. The VM still
  ended on the first-alert marker, so it did not successfully decrypt any
  application-data record before the alert.
- Next marker build maps the decrypted TLS alert description: `0` close notify,
  `M` bad record MAC, `O` record overflow, `H` handshake failure, `D` decode
  error, and `X` other.
- NE2K returned marker `0`: the first decrypted post-handshake TLS record was
  `close_notify`. That points away from an AEAD tag/sequence rejection and
  toward the application request not arriving, arriving too late, or arriving
  as an HTTP request the server closes without answering.

Decision:
- Stashed this broken scratch-layout attempt as
  `32kb-broken-post-handshake-close-notify` and kept a patch copy at
  `/private/tmp/seed-32kb-broken-attempt.patch`.
- Returned the branch to the pushed 48KB known-good baseline before continuing.
  The proven final-flight ordering is now treated as the fixed reference:
  send client Finished, prepare/send the OpenAI application record on the
  current sequence, then wait for server Finished with the existing deferred
  ACK behavior.

## 2026-05-06 - Restart from known-good baseline

Baseline measurement:
- Clean `work/32kb-slim` / `origin/work/32kb-slim` still uses 48KB profiles.
- Baseline `CORE.SYS` size: 35,952 bytes.
- A 32KB machine can only safely use memory below `0x8000`; with `CORE.SYS`
  loaded at `0x1000`, resident image plus stack guard must fit below that.

Controlled reduction 1:
- Shrunk only the outgoing OpenAI request buffers:
  `api_request_plain` from `tls_app_max_plain_len` to 512 bytes and
  `tls_app_record_buffer` from a full TCP payload to request + TLS header/tag.
- This does not change TLS final-flight ordering or receive buffering.
- Resulting `CORE.SYS` size: 34,098 bytes, saving 1,854 bytes.
- 48KB NE2K test stayed green: displayed `ok` and `seed build 6`.

Controlled reduction 2:
- Moved `ne_tx_frame` and `ne_prom` out of the resident image into the
  loader-reusable low scratch arena at `0x0700..0x0d5f`.
- This keeps TLS final-flight ordering and receive buffering unchanged.
- Resulting `CORE.SYS` size: 32,466 bytes, saving 1,632 bytes
  (3,486 bytes cumulative).
- 48KB NE2K test stayed green: displayed `ok` and `seed build 6`.

Controlled reduction 3:
- Moved `fs_sector_buffer` out of the resident image into the remaining
  loader-reusable low scratch tail at `0x0d60..0x0f5f`.
- This kept the packet transmit frame separate from the TLS/file sector buffer.
- Resulting `CORE.SYS` size: 31,954 bytes, saving 512 bytes
  (3,998 bytes cumulative).
- 48KB NE2K test stayed green: displayed `ok` and `seed build 6`.

Failed reduction 4:
- Tried reducing `tls_rx_copy` from two packet reads to one packet read by
  changing `tls_stream_buffer_len` from `tcp_payload_read_len * 2` to
  `tcp_payload_read_len`.
- Resulting `CORE.SYS` size was 30,354 bytes, saving 1,600 more bytes
  (5,598 bytes cumulative).
- 48KB NE2K test failed, so the one-packet receive buffer is not currently a
  valid cut. Reverted to the last green state from controlled reduction 3.

Checkpoint validation:
- Rebuilt the last green state after reverting failed reduction 4.
- `CORE.SYS` size: 31,954 bytes.
- 48KB representative family tests passed:
  `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e`
  each displayed `ok` and `seed build 6`.
- This checkpoint is not yet 32KB-bootable. With `CORE.SYS` loaded at
  `0x1000`, a 32KB system has at most 28,672 bytes before `0x8000`, and less
  after reserving stack/guard space.

Controlled reduction 4:
- Merged the outgoing HTTP plaintext buffer and TLS application record buffer.
  The request is now built at `api_request_plain + tls_record_header_len`, and
  `tls_app_record_buffer` aliases `api_request_plain` so the existing AEAD
  send path can encrypt in place.
- This does not change TLS final-flight ordering or receive buffering.
- Resulting `CORE.SYS` size: 31,442 bytes, saving 512 bytes
  (4,510 bytes cumulative).
- 48KB NE2K test stayed green: displayed `ok` and `seed build 6`.
- 48KB representative family tests also stayed green:
  `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e` each displayed `ok`
  and `seed build 6`.
- Remaining gap to the hard 32KB load ceiling is about 2,770 bytes; allowing a
  small stack/guard target leaves roughly 3.3KB still to cut.

Controlled reduction 5:
- Reduced the TCP/TLS receive read cap from the old `net_frame_buffer_len`
  budget of 1600 bytes to `tcp_payload_offset + tcp_payload_max_len`, which is
  1514 bytes. This preserves room for Ethernet/IP/TCP headers plus one full
  1460-byte TCP payload while shrinking both `tls_rx_copy` slots.
- Resulting `CORE.SYS` size: 31,270 bytes, saving 172 bytes
  (4,682 bytes cumulative).
- 48KB NE2K test stayed green: displayed `ok` and `seed build 6`.

Controlled reduction 6:
- Reused the P-256 scratch arena for ChaCha20 and Poly1305 scratch. P-256 is
  only needed through premaster-secret generation; ChaCha/Poly start after the
  TLS key schedule has derived the write keys, so these workspaces do not need
  separate resident storage.
- Resulting `CORE.SYS` size: 30,953 bytes, saving 317 bytes
  (4,999 bytes cumulative).
- 48KB NE2K test stayed green: displayed `ok` and `seed build 6`.

Family checkpoint after reductions 5 and 6:
- Rebuilt and tested the combined TCP/TLS read-cap reduction plus the
  P-256/ChaCha/Poly scratch alias.
- `CORE.SYS` size: 30,953 bytes.
- 48KB representative family tests passed:
  `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e`
  each displayed `ok` and `seed build 6`.
- Remaining gap to the hard 32KB load ceiling is about 2,281 bytes; allowing a
  small stack/guard target leaves roughly 2.8KB still to cut.

Failed reduction 7a:
- Tried a broad post-P-256 scratch alias: `agent_ids`, premaster/key-block
  output, PRF seed/chunks, HMAC pads and prepared states, SHA saved context,
  and shared-X scratch all reused the P-256 arena.
- Also converted ServerKeyExchange public coordinates directly into P-256 word
  buffers instead of first staging separate raw X/Y byte copies.
- Resulting `CORE.SYS` size: 30,168 bytes, saving 785 bytes
  (5,784 bytes cumulative), and local crypto checks passed with `make test`.
- 48KB NE2K VM failed at `agent setup failed`, so the broad PRF/HMAC/SHA alias
  is not valid as written.

Controlled reduction 7:
- Kept the lower-risk parts of 7a only: `agent_ids`, premaster/key-block
  output, and shared-X scratch reuse the P-256 arena, and ServerKeyExchange
  public coordinates are converted directly into P-256 word buffers.
- Left PRF seed/chunks, HMAC pads/prepared states, and SHA saved context as
  separate resident storage.
- Resulting `CORE.SYS` size: 30,632 bytes, saving 321 bytes
  (5,320 bytes cumulative).
- Remaining gap to the hard 32KB load ceiling is about 1,960 bytes; allowing a
  small stack/guard target leaves roughly 2.5KB still to cut.
- 48KB NE2K test stayed green: displayed `ok` and `seed build 6`.
- Representative family validation stayed green:
  `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e`
  each displayed `ok` and `seed build 6`. The first 3c501 run failed at
  `agent setup failed`, but an immediate rerun of the same image passed, so
  this cut is treated as family-green while keeping 3c501 as the timing canary.

Failed reduction 8:
- Host-side OpenAI timing probe still showed that adding
  `"max_output_tokens":16` reduces the successful response from about 2790
  bytes to about 2282 bytes.
- Tried adding that field to the real-mode OpenAI request and trimming
  `tls_stream_buffer_len` from two full TCP payloads to
  `tcp_payload_read_len + 1024`.
- Resulting `CORE.SYS` size: 30,165 bytes, saving 467 bytes from reduction 7,
  and local crypto checks passed.
- 48KB NE2K failed at `agent setup failed`; an immediate rerun failed the same
  way.
- Tried a safer partial receive trim, `tcp_payload_read_len + 1302`.
  Resulting `CORE.SYS` size: 30,443 bytes, saving 189 bytes from reduction 7,
  and local crypto checks passed, but 48KB NE2K still failed at
  `agent setup failed`.
- Diagnostic split restored the full two-payload receive buffer while keeping
  `"max_output_tokens":16`; 48KB NE2K still failed. Therefore the request shape
  change, not just the smaller receive buffer, is incompatible with the current
  parser/receive flow. Reverted this attempt and returned to reduction 7.

Controlled reduction 9:
- Compiled out the dormant full P-256 scalar/arithmetic path and kept a
  guarded scalar-1 premaster path. The current Build 6 client private key is
  fixed to scalar 1, so the ECDHE shared X is the server public X; if the
  scalar changes, the guard fails closed.
- Resulting `CORE.SYS` size: 28,396 bytes, saving 2,236 bytes from reduction 7
  (7,556 bytes cumulative).
- Local P-256, TLS PRF, and ChaCha20/Poly1305 checks passed.
- 48KB representative family tests passed:
  `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e`
  each displayed `ok` and `seed build 6`.
- This put the image 276 bytes under the hard 32KB load ceiling, but with
  essentially no practical stack/guard room.

Failed reduction 10a:
- Tried removing the now-dormant full P-256 scratch arena and replacing the
  overlapping ChaCha/Poly scratch windows with explicit smaller buffers.
- Resulting `CORE.SYS` sizes were 27,706 bytes for the first broad removal and
  27,767 bytes after restoring explicit ChaCha/Poly scratch tails.
- Local crypto checks passed, but 48KB NE2K failed at `agent setup failed` in
  both forms. The broad scratch layout is therefore not valid as written.
- Reverted to the reduction 9 arena shape.

Controlled reduction 10:
- Removed only dormant full P-256 constant tables: curve `b`, constant `three`,
  and the reduction coefficient table. Left the proven scratch arena layout
  unchanged.
- Resulting `CORE.SYS` size: 28,092 bytes, saving 304 bytes from reduction 9
  (7,860 bytes cumulative).
- Local P-256, TLS PRF, and ChaCha20/Poly1305 checks passed.
- 48KB representative family tests passed so far:
  `vm-net-ne2k8`, `vm-net-3c501`, and `vm-net-3c503` each displayed `ok` and
  `seed build 6`. `vm-net-wd8003e` remains to be rerun for the complete family
  checkpoint.
- Current hard 32KB load gap: `0x8000 - (0x1000 + 28092) = 580` bytes. That is
  below the ceiling, but still tight for a lowered 32KB stack and guard.

Controlled reduction 11:
- Removed only the inactive tail of the old full P-256 scratch/loop state:
  `p256_s7`, `p256_s8`, `p256_product`, `p256_reduce_acc`, and the dormant
  scalar/arithmetic pointer/counter temporaries.
- Kept the proven active scratch windows through `p256_s6`, including the
  ChaCha20/Poly1305 aliases that made broader scratch removal fail in reduction
  10a.
- Resulting `CORE.SYS` size: 27,866 bytes, saving 226 bytes from reduction 10
  (8,086 bytes cumulative).
- Local P-256, TLS PRF, and ChaCha20/Poly1305 checks passed.
- 48KB representative family tests passed:
  `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e` each
  displayed `ok` and `seed build 6`.
- Current hard 32KB load gap: `0x8000 - (0x1000 + 27866) = 806` bytes. Still
  tight, but meaningfully better than reduction 10.

Controlled reduction 12:
- For the fixed scalar-1 proof path, ServerKeyExchange parsing now copies the
  server public X coordinate directly into the TLS premaster buffer.
- Compiled out the remaining active P-256 big-endian conversion and range-check
  helpers, removed the runtime X/Y word buffers, removed the P-256 prime and
  fixed private scalar data, and removed a leftover active reduction-table row.
- Resulting `CORE.SYS` size: 27,534 bytes, saving 332 bytes from reduction 11
  (8,418 bytes cumulative).
- Local P-256, TLS PRF, and ChaCha20/Poly1305 checks passed.
- 48KB validation passed so far:
  `vm-net-ne2k8` and `vm-net-3c501` each displayed `ok` and `seed build 6`.
- Current hard 32KB load gap: `0x8000 - (0x1000 + 27534) = 1138` bytes. That
  clears a 1KB guard, but is still about 398 bytes short of a 1.5KB guard.

Controlled reduction 13:
- Checked the current Anthropic and Google API docs for a published hard API
  key string maximum. The docs describe the authentication headers and Google's
  `keyString`, but do not publish a longer maximum key length.
- Set Seed's Build 6 runtime API credential cap to 192 bytes. This keeps the
  supported OpenAI/Anthropic/Google provider surface, covers the current
  OpenAI project-key shape with margin, and stops reserving space for
  arbitrary longer credentials.
- Reduced `api_request_plain_len` from 512 to 488 bytes. With the 192-byte key
  cap, the current minimal OpenAI request still has slack.
- Resulting `CORE.SYS` size: 27,462 bytes, saving 72 bytes from reduction 12
  (8,490 bytes cumulative).
- Local P-256, TLS PRF, and ChaCha20/Poly1305 checks passed.
- 48KB representative family tests passed:
  `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e` each
  displayed `ok` and `seed build 6`.
- Current hard 32KB load gap: `0x8000 - (0x1000 + 27462) = 1210` bytes. That
  is about 326 bytes short of a 1.5KB guard.

Controlled reduction 14:
- Replaced the remaining old P-256 scratch tail with exact live scratch sizes.
  The active fixed-scalar path no longer needs full `p256_s4`, `p256_s5`, or
  `p256_s6` word slots; active users are the TLS/agent/ChaCha aliases plus a
  36-byte Poly1305 product and a 24-byte Poly1305 value.
- Resulting `CORE.SYS` size: 27,394 bytes, saving 68 bytes from reduction 13
  (8,558 bytes cumulative).
- Local P-256, TLS PRF, and ChaCha20/Poly1305 checks passed.
- 48KB NE2K smoke test passed: displayed `ok` and `seed build 6`.
- Current hard 32KB load gap: `0x8000 - (0x1000 + 27394) = 1278` bytes. That
  is about 258 bytes short of a 1.5KB guard.

Controlled reduction 15:
- Removed the dormant unprepared HMAC-SHA256 runtime path. The TLS PRF callers
  already prepare the fixed key pads, so the active path can use
  `hmac_sha256_prepared` directly and the old runtime selector/state can stay
  compiled out.
- Resulting `CORE.SYS` size: 27,156 bytes, saving 238 bytes from reduction 14
  (8,796 bytes cumulative).
- Local P-256, TLS PRF, and ChaCha20/Poly1305 checks passed.
- 48KB NE2K smoke test passed: displayed `ok` and `seed build 6`.
- Current hard 32KB load gap: `0x8000 - (0x1000 + 27156) = 1516` bytes. That
  is 20 bytes short of a 1.5KB guard.

Controlled reduction 16:
- Reduced the stored agent-id slot from 16 bytes to 12 bytes. The shipped
  provider IDs fit within 11 visible characters plus a terminator.
- Reduced the TLS PRF seed workspace from 80 bytes to 77 bytes, matching the
  largest current label-plus-seed construction.
- Replaced the remaining PRF HMAC wrapper calls with direct prepared-HMAC
  calls and removed the wrapper.
- Resulting `CORE.SYS` size: 27,134 bytes, saving 22 bytes from reduction 15
  (8,818 bytes cumulative).
- Local P-256, TLS PRF, and ChaCha20/Poly1305 checks passed.
- 48KB representative family tests passed:
  `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e` each
  displayed `ok` and `seed build 6`.
- Current hard 32KB load gap: `0x8000 - (0x1000 + 27134) = 1538` bytes. This
  clears the provisional 1.5KB guard by 2 bytes, but the margin is too narrow
  to call the 32KB target stable without another cut and a real 32KB VM pass.

Controlled reduction 17:
- Reduced endpoint storage from 96 bytes to 80 bytes, reasoning storage from
  16 bytes to 8 bytes, and the DNS qname workspace from 96 bytes to 80 bytes.
  The current shipped endpoint, reasoning, and DNS values fit those caps.
- Resulting `CORE.SYS` size: 27,094 bytes, saving 40 bytes from reduction 16
  (8,858 bytes cumulative).
- Moved the loader and runtime stack tops to `0x8000` for 32 KiB machines and
  added an assembly-time 1.5 KiB runtime stack guard.
- Set all nine 86Box profiles to 32 KiB RAM and normalized the host CPU label
  to Apple M5 Pro.
- Address check: `CORE.SYS` loads at `0x1000`, ends at `0x79d5`, the 32 KiB
  stack top is `0x8000`, and the guarded stack range starts at `0x7a00`. That
  leaves 42 bytes before the 1.5 KiB stack guard.
- Local `make`, `make inspect`, and `make test` checks passed.
- 32 KiB representative family tests passed:
  `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e` each
  displayed `ok` and `seed build 6`.
