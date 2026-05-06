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
