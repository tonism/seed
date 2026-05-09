# 16KB Windowed Nucleus Attempts

Branch: `work/16kb-windowed-nucleus`

Starting point:

- `main` 24 KiB BASIC sidecar release at `3f49a3f`.
- One 160 KiB FAT12 floppy image.
- One visible `CORE.SYS` runtime.
- BIOS boot remains the path for machines with at least 32 KiB RAM.
- ROM BASIC sidecar entry remains the path for machines below 32 KiB.
- Current 24 KiB sidecar release keeps `CORE.SYS` loaded at `0x1000` and uses
  a runtime ceiling of `0x6000`.

Milestone target:

- First raw target is a 16 KiB BASIC sidecar run reaching returned `ok` on one
  representative NIC.
- Release target is representative NIC-family success under a 16 KiB ceiling,
  including 3c501 as the timing canary, while preserving 32 KiB+ BIOS boot from
  the same floppy and same `CORE.SYS`.

Design reference:

```text
notes/16kb-windowed-nucleus-design.md
```

Initial measured baseline from the 24 KiB release:

```text
CORE.SYS total bytes:       29696
CORE.SYS total sectors:     58
resident sectors:           37
resident bytes:             18944
resident load range:        0x1000..0x5a00
24 KiB ceiling:             0x6000
16 KiB ceiling:             0x4000
BASIC sidecar loader addr:  0x5a00
```

Initial implication:

- With `CORE.SYS` still loaded at `0x1000`, a 16 KiB machine leaves only
  `0x1000..0x4000`, or 12 KiB total.
- The current resident image alone is about 6.5 KiB too large before stack,
  scratch, and guard budgets are considered.
- This branch should not proceed as blind trimming. It should turn the current
  windowed runtime into a stricter windowed nucleus: small resident control,
  explicit reloadable windows, and one no-floppy provider critical window.

Attempt log:

## 2026-05-08 - Add explicit scratch collision reporting

Change:

- Extended `tools/core-sys-info.py` with fixed `--range` reporting and ideal
  `--packed-range` reporting.
- Updated `make inspect` to show the current high-crypto scratch and TLS/API
  critical scratch arenas against both the 24 KiB BASIC budget and the 16 KiB
  target budget.

Reasoning:

- The previous `16k-target` budget only compared resident `CORE.SYS` against
  the stack guard. That was useful for resident-sector cuts, but it did not
  make the current above-16K scratch arenas visible.
- The new packed ranges show the harder final question: if these scratch
  lifetimes are eventually placed directly after the resident nucleus, how much
  measured guard remains?

Current measurement before any new resident cut:

- Resident sectors: 26.
- Resident bytes: 13312.
- Resident load range: `0x1000..0x4400`.
- Fixed high-crypto scratch range: `0x4c00..0x4f5e`.
- Fixed critical TLS/API scratch range: `0x5000..0x5bd4`.
- `16k-target` resident-only guarded slack remains -2048 bytes.
- `16k-target` ideal packed high-crypto + critical scratch guarded slack is
  -5938 bytes.

Implication:

- The old resident-only number still tells us how many resident sectors must
  drop before the nucleus can fit below the 1 KiB stack guard.
- The packed-scratch number is the real final 16 KiB pressure. It confirms that
  we also need to pack or reduce scratch lifetimes once enough resident sectors
  have been cut.

## 2026-05-08 - Move boot/UI/config helpers into setup windows

Change:

- Moved boot-time display detection, screen clear, and initial cursor hide into
  the hardware setup phase.
- Moved the built-in `example.com` probe default into the `NET.CFG` phase.
- Moved question/failure tones and marker blinking into the phases that use
  them.
- Localized `print_z` and cursor show/hide into the agent setup phase.
- Moved cached `USER.CFG` completeness validation into the `USER.CFG` phase.
- Merged the high-crypto and critical scratch startup clears into one
  contiguous scratch-band clear.

Measurements:

- Resident sectors: 26 -> 25.
- Resident bytes: 13312 -> 12800.
- Resident nonzero payload: 13186 -> 12797.
- Total `CORE.SYS` bytes: 26112 -> 25600.
- Resident load range: `0x1000..0x4400` -> `0x1000..0x4200`.
- `16k-target` resident-only guarded slack: -2048 -> -1536 bytes.
- `16k-target` ideal packed high-crypto + critical scratch guarded slack:
  -5938 -> -5426 bytes.

Result:

- One more resident sector removed without changing the TLS/OpenAI critical
  ordering.
- Remaining ideal packed guarded 16 KiB deficit is 5426 bytes.

Verification:

- `make inspect` passes.
- `make test` passes.

## 2026-05-09 - Trim resident network/phase glue to 21 sectors

Change:

- Replaced one-use resident phase-runner wrappers with compact phase-call
  macros while preserving the original `BX` phase-entry contract.
- Removed TCP TX/RX temporary fields by carrying lengths and pointers in
  registers through the TCP frame builder/parser.
- Removed low-value packet TX/RX status writes and consolidated several network
  failure exits through the shared `net_fail_al` tail.
- Moved explicitly initialized TLS/TCP state into the 35-byte tail after the low
  static constants at the top of the low scratch arena.
- Replaced the 3c501 four-byte unrolled TX/RX copy loops with straight byte
  loops. This trades a small amount of 3c501 copy-loop time for resident code
  size.
- Merged resident WD/3c503 packet helper tails, kept transmit frame length in
  `BP` instead of low runtime memory, folded DP8390 next-page selection into
  ring-pointer reads, and moved two zero-initialized words into the freed low
  runtime bytes.
- Removed a few one-use TCP/NIC branches and tails without changing packet
  ordering.

Rejected/reverted experiments:

- Do not change `run_core_phase_at` to preserve the phase load address in `DI`.
  Loaded phases rely on `BX` still naming their entry/load base.
- Do not collapse `selected_nic_has_packet_path` into a direct-flags predicate
  without preserving its carry contract; the attempted version broke NE2K8
  network setup.
- Do not move the TCP-connected status write out of the resident ACK transmit
  path without reworking `tcp_connect` expectations; the attempted version
  broke NE2K8 network setup.
- `wait_ticks` remains fully preserving `AX/BX/CX`; the reduced-preservation
  experiment was part of the broken batch and was reverted.

Measurements:

- `CORE.SYS` total size: 25600 -> 25088 bytes.
- `CORE.SYS` total sectors: 50 -> 49.
- Resident sectors: 22 -> 21.
- Resident bytes: 11264 -> 10752.
- Resident nonzero payload: 11066 -> 10670.
- Resident load range: `0x1000..0x3c00` -> `0x1000..0x3a00`.
- `16k-target` resident guarded slack: 0 -> 512 bytes.
- `16k-target` packed critical guarded slack: -3395 -> -2883 bytes.

Result:

- One more resident sector removed.
- Remaining guarded 16 KiB deficit is 2883 bytes, now dominated by the packed
  high-crypto plus critical scratch windows rather than resident raw fit.

Verification:

- `make test` passes.
- `make inspect` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-09 - Size TLS reassembly to payload bytes instead of frame bytes

Change:

- Split the NIC read limit (`tcp_payload_read_len`, Ethernet/IP/TCP frame
  bytes) from the TLS reassembly arena (`tls_payload_buffer_len`, TCP payload
  bytes).
- Kept NIC reads unchanged, but sized `tls_stream_buffer_len` and the
  TLS reassembly safety checks from the actual payload bytes copied into
  `tls_rx_copy`.

Measurements:

- `CORE.SYS` total size: unchanged at 25600 bytes.
- `CORE.SYS` total sectors: unchanged at 50.
- Resident sectors: unchanged at 5.
- LINK window: unchanged at 17 sectors, `0x1a00..0x3c00`.
- High crypto scratch: unchanged at 282 bytes.
- Critical scratch: 2560 -> 2506 bytes.
- Guarded 16 KiB deficit: -2842 -> -2788 bytes.

Result:

- Accepted 54-byte critical-scratch trim. This is small, but it corrects the
  accounting model: TLS stores payload bytes, while the NIC read limit still
  covers the full frame.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-09 - Reject TLS status-tail and fixed-scalar P-256 include cleanup

Change tried:

- Replaced the shared `tls_status_ok` jump tail with local `clc`/`ret`
  success returns.
- Simplified `tls_prepare_premaster_secret` to a direct `clc`/`ret`, relying on
  ServerKeyExchange parsing already copying the fixed-scalar proof secret into
  `tls_premaster_secret`.
- Removed `core/p256.inc` from the runtime LINK window, leaving the source file
  available for reference and vector tooling.

Measurements:

- LINK end moved from `0x2b4f` to `0x2b39`, saving 22 actual LINK bytes.
- K still occupied 17 sectors, so `CORE.SYS` stayed 25600 bytes.
- Guarded 16 KiB packed deficit stayed at -2788 bytes.
- K would still need about 313 more bytes before dropping from 17 sectors to
  16.

Result:

- Rejected and reverted.
- `make inspect` and `make test` passed.
- NE2K8 and 3c501 BASIC-sidecar canaries on 32 KiB hosts reached returned
  `ok`, but 3c503 failed during agent setup.

Implication:

- Do not remove the P-256 fixed-scalar stub/include or the shared TLS success
  tail as a blind size cut. The 3c503 failure suggests that even apparently
  equivalent TLS control-flow/link-layout changes can perturb the fragile
  secure-link path.

## 2026-05-09 - Reject request-record receive-buffer reuse

Change tried:

- Moved `api_request_plain` / `tls_app_record_buffer` out of the critical
  pre-response scratch tail into the TLS receive payload arena.
- First tried the front of `tls_rx_copy`.
- Then tried the middle DNS qname area at `tls_rx_copy + 512`, to avoid the
  likely buffered TLS data at the front.
- Removed `tls_app_record_buffer_len` from `tls_pre_response_tail_len` and
  reduced `CRITICAL_SCRATCH_LEN` from 2506 to 2045.

Measurements:

- Critical scratch: 2506 -> 2045 bytes.
- Guarded 16 KiB packed deficit: -2788 -> -2327 bytes.
- `CORE.SYS` stayed 25600 bytes and K stayed at 17 sectors.

Result:

- Rejected and reverted.
- `make inspect` and `make test` passed for both placements.
- NE2K8 BASIC-sidecar canary failed at agent setup for both the front-of-RX and
  DNS-area placements.

Implication:

- Keep the prepared application request record outside the TLS receive payload
  until the secure-link ordering is redesigned. The current path prepares and
  sends application data around the server-Finished receive window, and the RX
  arena is not a safe alias even when the static lifetimes look tempting.

## 2026-05-09 - Move SHA-256 block/schedule scratch into low sector buffer tail

Change:

- Reused the unused tail of `fs_sector_buffer` for transient SHA-256
  block/schedule scratch during the secure-link window.
- Kept the first 128 bytes of `fs_sector_buffer` reserved for TLS transmit
  records and added assembly-time collision checks for the ClientKeyExchange,
  ChangeCipherSpec, and Finished record sizes.
- Moved the remaining high crypto scratch start directly to the TLS write key
  block.

Measurements:

- `CORE.SYS` total size: unchanged at 25600 bytes.
- `CORE.SYS` total sectors: unchanged at 50.
- Resident sectors: unchanged at 5.
- LINK window: unchanged at 17 sectors, `0x1a00..0x3c00`.
- High crypto scratch: 602 -> 282 bytes.
- Critical scratch: unchanged at 2560 bytes.
- Guarded 16 KiB deficit: -3162 -> -2842 bytes.

Result:

- Accepted 320-byte scratch relocation. This does not cross a sector boundary,
  but it removes high-memory pressure without touching packet timing or TLS
  ordering.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-09 - Move fixed TLS client public key out of high scratch

Change:

- Stopped reserving high-crypto scratch for the fixed P-256 client public key.
- Moved the constant into the LINK window and made ClientKeyExchange copy it
  directly from there.
- Removed the ROM BASIC TLS ClientHello phase copy into high scratch.
- Updated the P-256 checker to validate the constant in its new home.

Measurements:

- High crypto scratch: 835 -> 770 bytes.
- `16k-target packed critical guarded slack`: -3395 -> -3330 bytes.
- LINK window stayed at 17 sectors, so this is a direct 65-byte scratch win.

Result:

- Low-risk lifetime cleanup. The fixed public key is needed only as constant
  input for ClientKeyExchange and does not need writable scratch.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-09 - Reject direct key-block write-key aliases

Change tried:

- Tried to point `tls_client_write_key`, `tls_server_write_key`,
  `tls_client_write_iv`, and `tls_server_write_iv` directly into
  `tls_key_block`.
- Removed `tls_split_key_block`.

Measurements:

- High crypto scratch: 602 -> 514 bytes.
- `16k-target packed critical guarded slack`: -3162 -> -3074 bytes.
- Static build and unit tests passed.

Result:

- Rejected. NE2K8 BASIC-sidecar canary reached returned `ok`, but the 3c501
  canary failed during agent setup.
- Reverted the cut and kept the previous accepted AEAD scratch relocation.

Implication:

- Treat the key block as more fragile than it looks from static lifetime
  inspection. If revisited, add targeted diagnostics around key schedule,
  ClientKeyExchange, and first AEAD use before removing the split copy.

## 2026-05-09 - Move transient AEAD scratch into critical scratch

Change:

- Stopped reserving high-crypto scratch for transient ChaCha20 and Poly1305
  working state.
- Aliased the AEAD working state into the pre-response critical scratch tail,
  after the PRF/config/server-random/master-secret lifetimes are finished.
- Aliased `tls_random` onto the handshake-hash slot, because the client random
  is only needed before the Finished transcript hash is materialized there.
- Added assembly-time collision checks for the critical AEAD overlays.

Measurements:

- High crypto scratch: 770 -> 602 bytes.
- `16k-target packed critical guarded slack`: -3330 -> -3162 bytes.
- LINK window stayed at 17 sectors.
- Packed high-crypto range is now `0x3c00..0x3e5a`.
- Packed critical range is now `0x3e5a..0x485a`.

Result:

- Accepted lifetime aliasing cut. This does not change the TLS/OpenAI ordering
  or touch the remote fast path behavior; it only moves transient AEAD storage
  into an already-reserved critical scratch gap.
- Remaining guarded 16 KiB deficit is 3162 bytes.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-09 - Rejected low TCP receive cap

Change:

- Tried reducing `tcp_payload_max_len` from 1460 to 576 bytes, based on the
  idea that Seed does not advertise an MSS option and peers should therefore
  stay at the TCP default-MSS class.
- Temporarily reduced the tracked `CRITICAL_SCRATCH_LEN` from 2560 to 1696
  bytes to match the smaller receive arena.

Measurements:

- `16k-target packed critical guarded slack`: -3330 -> -2466 bytes.
- This was an 864-byte improvement in the release-tracking metric.
- A stricter 536-byte cap did not assemble because the DNS qname scratch would
  overlap pre-response scratch.

Result:

- Rejected and reverted.
- NE2K8 BASIC-sidecar canary on a 32 KiB host failed at agent setup. The
  practical provider/TLS response path still needs the larger receive arena, or
  a real streaming/segmented receive design rather than a simple cap.

Recovery:

- Restored `tcp_payload_max_len` to 1460 and `CRITICAL_SCRATCH_LEN` to 2560.
- The release-tracking metric returned to -3330 bytes.
- 3c503 restored-baseline BASIC-sidecar canary on a 32 KiB host reached
  `seed build 6` and returned `ok`.

## 2026-05-09 - Rejected TLS nonce/AAD helper dedupe

Change:

- Tried sharing the client/server nonce builders and the client/server AEAD AAD
  builders across Finished and application-data records.

Measurements:

- LINK code shrank by about 69 bytes (`core_link_window_end` moved from
  `0x2b6f` to `0x2b2a` in the listing).
- `16k-target packed critical guarded slack`: unchanged at -3330 bytes,
  because LINK still occupied 17 sectors.

Result:

- Rejected and reverted.
- NE2K8 and 3c501 BASIC-sidecar canaries on 32 KiB hosts reached returned
  `ok`, but 3c503 failed at agent setup. That makes the shared helper change
  unsafe on the current timing/order-sensitive secure-link path.

Recovery:

- Restored the separate nonce and AAD builders.
- `make inspect` returned to the pushed baseline metric:
  `16k-target packed critical guarded slack` = -3330 bytes.
- 3c503 restored-baseline BASIC-sidecar canary on a 32 KiB host reached
  `seed build 6` and returned `ok`.

## 2026-05-09 - Add LINK-aware packed budget tracking

Change:

- Updated `make inspect` so the 16 KiB packed budget includes the `K` LINK
  window before high-crypto and critical scratch.

Measurements:

- Packed `K` LINK window: `0x1a00..0x3c00`, 8704 bytes.
- Packed high-crypto scratch after LINK: `0x3c00..0x3f43`, 835 bytes.
- Packed critical scratch after high-crypto: `0x3f43..0x4943`, 2560 bytes.
- Corrected guarded 16 KiB packed deficit: -3395 bytes.

Result:

- The tracked release number is truthful again. The next runtime cuts must
  recover about 3.4 KiB from LINK and/or scratch before the 1 KiB guard target
  is met.

Verification:

- `make inspect` passes.

## 2026-05-08 - Compact high crypto scratch overlay

Change:

- Replaced the disabled full-P-256 scratch reservation with active
  ChaCha20/Poly1305 scratch lifetimes.
- Kept persistent Poly1305 `r`/`s` separate while allowing the accumulator,
  block, product, and reduced value scratch to overlay the ChaCha state/work
  area after each ChaCha block is generated.
- Added a build-time overlap check for the Poly1305 scratch overlay.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: unchanged at 11220.
- High crypto scratch: 959 -> 835 bytes.
- Critical scratch: unchanged at 2964 bytes.
- `16k-target packed critical guarded slack`: -3923 -> -3799.

Result:

- Kept. This saves 124 bytes from the ideal packed 16 KiB pressure without
  changing TCP receive tolerance or provider request ordering.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- A later 3c501 run failed quickly at the dark `,` network setup phase, but
  an immediate rerun of the same tree/profile reached `seed build 6` and
  returned `ok`. Treat the `,` result as transient unless it repeats.

## 2026-05-08 - Rejected seed config pre-ClientHello overlay

Change tried:

- Moved `seed_agent_id`, `seed_model`, `seed_key`, `seed_endpoint`, and
  `seed_reasoning` from the pre-response scratch tail into the first TLS
  receive-buffer area before DNS qname scratch.
- Removed `seed_value_total_len` from the critical pre-response tail budget.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: unchanged at 11220.
- Critical scratch would have dropped 2964 -> 2608 bytes.
- `16k-target packed critical guarded slack` would have improved -3799 -> -3443.

Result:

- Rejected and reverted.
- `make inspect` and `make test` passed, but the 3c501 BASIC-sidecar canary
  failed at red `o agent setup failed`.
- The selected provider/config values are still live longer than this overlay
  assumed, or the endpoint/request path depends on them across a receive-buffer
  overwrite boundary. Keep them in the pre-response tail until that lifetime is
  redesigned explicitly.

## 2026-05-08 - Rejected ClientKeyExchange public key config-arena reuse

Change tried:

- Removed the fixed ClientKeyExchange public key from high crypto scratch.
- Reused the saved config value arena starting at `seed_agent_id` for that
  65-byte public key after `agent_request_phase` has already built the HTTP
  request.
- Reduced the inspected high crypto scratch budget from 835 to 770 bytes.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: unchanged at 11220.
- High crypto scratch would have dropped 835 -> 770 bytes.
- Critical scratch would have stayed at 2964 bytes.
- `16k-target packed critical guarded slack` would have improved -3799 -> -3734.

Result:

- Rejected and reverted.
- `make inspect` and `make test` passed.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- NE2K8 BASIC-sidecar canary on a 32 KiB host failed at red `o agent setup
  failed`.
- The config arena is not a valid long-lived home for the fixed public key
  across the non-3c501 key-schedule/ClientKeyExchange send ordering. Keep the
  public key in high scratch unless the non-3c501 ordering is redesigned.

## 2026-05-08 - Rejected universal early ClientKeyExchange plus public-key reuse

Change tried:

- Changed the TLS path to send ClientKeyExchange immediately after adding it to
  the transcript for every NIC family, matching the existing 3c501 early-send
  ordering.
- Kept the same fixed-public-key config-arena reuse as the previous attempt.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload would have dropped 11220 -> 11198 bytes.
- High crypto scratch would have dropped 835 -> 770 bytes.
- Critical scratch would have stayed at 2964 bytes.
- `16k-target packed critical guarded slack` would have improved -3799 -> -3734.

Result:

- Rejected and reverted.
- `make inspect` and `make test` passed, but the NE2K8 BASIC-sidecar canary on
  a 32 KiB host failed at red `o agent setup failed`.
- The proven non-3c501 ordering should stay as-is for now. The fixed
  ClientKeyExchange public key remains in high scratch.

## 2026-05-08 - Cut OpenAI request buffer to fixed proof bounds

Change:

- Reduced `api_request_plain_len` from 488 to 440 bytes.
- The current fixed OpenAI Responses proof request fits in 440 bytes with the
  supported maximum 192-byte API key and 64-byte model name.
- Reduced the inspected critical scratch budget from 2964 to 2916 bytes.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: unchanged at 11220.
- High crypto scratch stayed at 835 bytes.
- Critical scratch dropped 2964 -> 2916 bytes.
- `16k-target packed critical guarded slack` improved -3799 -> -3751.

Result:

- Accepted.
- This is a small critical scratch reduction, not a resident-sector cut.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.

## 2026-05-08 - Overlay post-request TLS state on saved config arena

Change:

- Removed saved agent/model/key/endpoint/reasoning value storage from the
  critical pre-response tail budget.
- After `agent_request_phase` has built the HTTP request, the OpenAI proof path
  no longer needs those saved config strings. Reused the same arena starting at
  `seed_agent_id` for TLS server random, master secret, handshake hash, and
  verify data.
- Reduced the inspected critical scratch budget from 2916 to 2560 bytes.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: unchanged at 11220.
- High crypto scratch stayed at 835 bytes.
- Critical scratch dropped 2916 -> 2560 bytes.
- `16k-target packed critical guarded slack` improved -3751 -> -3395.

Result:

- Accepted.
- This saves 356 bytes in the packed critical window without changing the
  TLS/OpenAI packet ordering.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.

## 2026-05-08 - Rejected 1024-byte TCP receive cap

Change tried:

- Reduced `tcp_payload_max_len` from 1460 to 1024 bytes.
- Updated the inspected critical scratch budget from 2964 to 2528 bytes.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: unchanged at 11220.
- Critical scratch would have dropped 2964 -> 2528 bytes.
- `16k-target packed critical guarded slack` would have improved -3923 -> -3487.

Result:

- Rejected and reverted.
- `make inspect` and `make test` passed, but the 3c501 BASIC-sidecar canary
  failed at red `o agent setup failed`.
- This confirms the earlier 512-byte failure was not only an over-aggressive
  lower bound; the current provider/NIC path still needs the full-size TCP
  receive tolerance or deeper TCP/TLS receive redesign.

## 2026-05-08 - Keep low-risk TLS tail-call cleanup

Change:

- Replaced several TLS helper wrappers of the form `call`, `jc .failed`,
  `clc`, `ret` with direct tail jumps where the callee already returns the
  carry status expected by the caller.
- Deliberately avoided changing the ClientKeyExchange/key-schedule storage
  ordering after the earlier failed scratch-reuse attempt.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: 11248 -> 11224 bytes.
- High crypto scratch: unchanged at 959 bytes.
- Critical scratch: unchanged at 2964 bytes.
- `16k-target` packed critical guarded slack: unchanged at -3923 bytes.

Result:

- Saves 24 bytes of resident payload without moving the fragile provider LINK
  path state or timing order.
- Does not move the release metric yet; another resident sector drop still
  requires roughly 488 bytes of resident payload reduction.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Failed TCP receive window shrink

Change:

- Tried reducing `tcp_payload_max_len` from 1460 to 512 so the critical
  scratch window would no longer reserve a full-size Ethernet TCP payload.
- First tried relying on a universal 512-byte advertised receive window.
- Then tried adding a TCP MSS 512 option to SYN while keeping the 512-byte
  payload cap.

Measurements:

- The window-only form built with resident sectors unchanged at 22.
- Critical scratch would have dropped from 2964 to 2016 bytes.
- `16k-target` packed critical guarded slack would have improved from -3923 to
  -2975 bytes.

Result:

- Rejected and reverted.
- 3c501 BASIC-sidecar canary failed at red `o agent setup failed` with the
  512-byte cap, both without MSS and with MSS.
- This suggests the current TCP receive logic/provider path still depends on
  accepting a larger wire payload, or at least needs better diagnostics before
  this cap can be lowered safely.

Verification:

- `make inspect` and `make test` passed for the attempted builds.
- VM proof failed on 3c501, so the cut was not kept.
- NE2K BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Rejected packed phase wrapper immediates

Change tried:

- Replaced phase loader wrappers' separate `mov al, sector` and
  `mov cl, sectors` immediates with a packed `mov ax, sector|sectors<<8`
  plus `mov cl, ah`.

Result:

- Rejected and reverted.
- On 8086 this encoding is larger, not smaller. Resident nonzero payload grew
  by 15 bytes.

## 2026-05-08 - Move TCP SYN construction into TCP-connect phase

Change:

- Moved `ne_transmit_tcp_syn` and `tcp_reset_state` out of resident
  `net_tx.inc` and into the TCP-connect setup phase.
- Kept TCP ACK, payload construction/transmit, checksums, and receive parsing
  resident because the TLS/OpenAI critical path still needs them.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: 11220 -> 11169 bytes.
- High crypto scratch stayed at 835 bytes.
- Critical scratch stayed at 2560 bytes.
- `16k-target packed critical guarded slack` stayed at -3395.

Result:

- Accepted.
- Saves 51 resident payload bytes without changing TLS/OpenAI packet ordering.
- This does not move the release metric yet; another resident sector still
  requires roughly 418 more resident payload bytes of reduction.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.

## 2026-05-08 - Keep compact NIC transmit port setup

Change:

- Kept the NIC I/O base in `BX` inside DP8390 and 3c501 transmit paths.
- Replaced repeated absolute `handoff_nic_base` loads plus `add dx, imm` with
  shorter indexed `lea dx, [bx + imm]` setup.
- This is a mechanical transmit-path size cut; packet ordering and TLS state
  lifetimes are unchanged.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: 11169 -> 11131 bytes.
- High crypto scratch stayed at 835 bytes.
- Critical scratch stayed at 2560 bytes.
- `16k-target packed critical guarded slack` stayed at -3395.

Result:

- Accepted.
- Saves 38 resident payload bytes.
- Another resident sector still requires roughly 380 more resident payload
  bytes of reduction.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.

## 2026-05-08 - Keep compact NIC receive port setup

Change:

- Applied the same NIC-base reuse pattern to resident receive paths.
- Used one loaded NIC I/O base for 3c501 receive/release and DP8390 remote DMA
  receive setup.
- Reused the base in 3c503 chip-memory receive/write loops.
- Packet receive ordering and TLS state lifetimes are unchanged.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: 11131 -> 11084 bytes.
- High crypto scratch stayed at 835 bytes.
- Critical scratch stayed at 2560 bytes.
- `16k-target packed critical guarded slack` stayed at -3395.

Result:

- Accepted.
- Saves 47 resident payload bytes.
- Another resident sector still requires roughly 333 more resident payload
  bytes of reduction.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached returned `ok`.

## 2026-05-08 - Keep compact NIC pointer setup

Change:

- Reused the already loaded NIC I/O base in 3c501 general-pointer setup and
  DP8390 ring-pointer reads.
- This is a mechanical follow-up to the transmit/receive port setup cleanup;
  packet ordering, TLS state lifetimes, and the OpenAI fast path are unchanged.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: 11084 -> 11066 bytes.
- High crypto scratch stayed at 835 bytes.
- Critical scratch stayed at 2560 bytes.
- `16k-target packed critical guarded slack` stayed at -3395.

Result:

- Accepted.
- Saves 18 resident payload bytes.
- Another resident sector still requires roughly 315 more resident payload
  bytes of reduction.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached returned `ok`.

## 2026-05-09 - Keep compact resident NIC helper tails

Change:

- Inlined the DP8390 remote-DMA finish step where the NIC I/O base was already
  live in `BX`.
- Made 3c503 DMA helpers leave the NIC I/O base live for their callers, then
  reused it for chip-memory status/data ports.
- Shortened 3c503/WD wrap-address setup and 3c501 TLS receive-prep port setup.
- Shortened TCP window construction by deriving the 3c501 small window from the
  normal DP8390 window value.
- These are mechanical resident-code cuts; packet ordering and TLS/OpenAI
  state lifetimes are unchanged.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: 11066 -> 11027 bytes.
- High crypto scratch stayed at 835 bytes.
- Critical scratch stayed at 2560 bytes.
- `16k-target packed critical guarded slack` stayed at -3395.

Result:

- Accepted.
- Saves 39 resident payload bytes.
- Another resident sector still requires roughly 279 more resident payload
  bytes of reduction.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached returned `ok`.

## 2026-05-08 - Keep follow-up tail-position cleanup

Change:

- Converted remaining simple hardware-detection `call`/`ret` tails into
  jumps.
- Converted the final server-Finished compare wrapper into a direct
  `tls_compare_buffers` tail jump.
- Left the wrappers that intentionally map lower-level failure into
  `tls_fail_error`.

Measurements:

- Resident sectors: unchanged at 22.
- Resident bytes: unchanged at 11264.
- Resident nonzero payload: 11224 -> 11220 bytes.
- High crypto scratch: unchanged at 959 bytes.
- Critical scratch: unchanged at 2964 bytes.
- `16k-target` packed critical guarded slack: unchanged at -3923 bytes.

Result:

- Saves 4 more resident bytes.
- Does not move the release metric yet.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Failed TLS bookkeeping and CKE scratch reuse cut

Change tried:

- Removed several TLS bookkeeping fields that looked write-only:
  transcript byte counters, `tls_key_schedule_ready`, ServerKeyExchange curve,
  public-length, signature hash/algorithm, and signature-length state.
- Moved `tcp_tx_flags` and `api_receive_tries` from resident data into the low
  runtime state area.
- Also tried moving the fixed ClientKeyExchange public key out of high crypto
  scratch by staging it in `tls_prf_seed` before PRF use and caching the built
  CKE record in `fs_sector_buffer`.

Measurements:

- Full cut built and passed local crypto tests.
- High crypto scratch would have dropped 959 -> 894 bytes.
- `16k-target packed critical guarded slack` would have improved -3923 -> -3858.
- After backing out only the CKE/public-key relocation, resident nonzero bytes
  still dropped 11248 -> 11158, but resident sectors stayed at 22 and the
  tracked 16 KiB guarded target stayed at -3923 bytes.

Result:

- Rejected. 3c501 BASIC-sidecar canary failed twice at red `o agent setup
  failed` with the CKE/public-key relocation.
- After backing out the CKE/public-key relocation but keeping the TLS
  bookkeeping cleanup, 3c501 still failed at red `o agent setup failed`.
- The branch was reverted to the prior green code state. Do not retry this
  cleanup inside the TLS handshake state without adding better diagnostics or
  splitting it into smaller canaries.

## 2026-05-08 - Drop one resident sector with TLS/runtime cleanup

Change:

- Removed redundant HMAC key reloads and now-unused PRF secret pointer/length
  stores from the TLS PRF path.
- Shared repeated TLS status/failure tails.
- Moved 46 bytes of persistent packet/TCP runtime state from file-backed
  resident data into the zeroed low runtime state below the phase load window.
- Converted safe call/return wrappers into direct jumps.
- Inlined the one-use TLS cipher-suite check.
- Merged a duplicate TCP receive error exit.

Measurements:

- `CORE.SYS` total size: 26112 -> 25600 bytes.
- `CORE.SYS` total sectors: 51 -> 50.
- Resident sectors: 23 -> 22.
- Resident bytes: 11776 -> 11264.
- Resident nonzero payload: 11542 -> 11248.
- Resident load range: `0x1000..0x3e00` -> `0x1000..0x3c00`.
- `16k-target` packed critical guarded slack: -4435 -> -3923 bytes.

Result:

- One resident sector removed without changing TLS/OpenAI ordering or adding
  floppy I/O to the fragile path.
- Remaining guarded 16 KiB deficit is 3923 bytes.

Verification:

- `make inspect` passes.
- `make test` passes.
- BASIC-sidecar family sweep on 32 KiB host reached `seed build 6` and
  returned `ok` on `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and
  `vm-net-wd8003e`.

## 2026-05-08 - Rejected compact ChaCha double-round

Change tried:

- Replaced the fully unrolled ChaCha20 double-round with one shared quarter
  round and a compact dispatcher.
- First variant used a table-driven dispatcher; second variant hardcoded the
  eight quarter-round offset sets to remove the table/loop overhead.

Measurements:

- Both compact variants reduced `CORE.SYS` from 26112 to 24576 bytes.
- Resident sectors dropped from 23 to 20.
- Resident load range moved from `0x1000..0x3e00` to `0x1000..0x3800`.
- `16k-target` packed critical guarded slack improved from -4435 to -2899.

Result:

- Rejected and reverted.
- `make test` passed, including ChaCha20/Poly1305 vectors, so the compact
  implementation was mathematically equivalent for local coverage.
- `vm-net-ne2k8` BASIC-sidecar canary reached `seed build 6` and returned
  `ok`.
- `vm-net-3c501` failed twice at red `o agent setup failed`, once with the
  table-driven dispatcher and once with the hardcoded dispatcher.
- Conclusion: the memory saving is real, but the extra ChaCha runtime cost is
  not acceptable on the fragile 3c501/OpenAI timing path. Future work should
  keep the fast unrolled ChaCha path and move/preload it into a window if we
  want this class of resident-code saving.

## 2026-05-08 - Rejected post-TCP crypto runtime preload

Change tried:

- Kept the fast unrolled ChaCha20 implementation, but moved it out of resident
  code and into a new low-memory `X` runtime phase at `0x0700`.
- Loaded the `X` phase after TCP connect and before sending ClientHello, so no
  floppy access would happen during the TLS/OpenAI response window itself.

Measurements:

- Resident sectors dropped from 23 to 19.
- Resident bytes dropped from 11776 to 9728.
- Resident load range moved from `0x1000..0x3e00` to `0x1000..0x3600`.
- `16k-target` packed critical guarded slack improved from -4435 to -2387.
- The new `X` phase occupied 4 sectors at `0x0700..0x0f00`.

Result:

- Rejected and reverted.
- `make inspect` and `make test` passed.
- A 135-second 3c501 BASIC-sidecar canary was inconclusive: it remained at the
  `o` agent/TLS phase.
- A 220-second 3c501 retry still remained at `o` and never reached `ok` or a
  fatal error.
- Conclusion: loading four floppy sectors after TCP connect is not viable on
  the fragile path. A future fast-crypto window must be resident before TCP
  connect, or the TCP-connect phase must be reorganized so it does not clobber
  a preloaded crypto window.

## 2026-05-08 - Move fixed TLS constants into low scratch

Baseline:

- Last pushed checkpoint was `88062dd` on `work/16kb-windowed-nucleus`.
- Resident sectors: 24.
- Resident nonzero payload: 12080 bytes.
- `16k-target` packed critical guarded slack: -4947 bytes.
- 3c501 and WD8003e BASIC-sidecar canaries on a 32 KiB host both reached
  `seed build 6` and returned `ok` before this cut.

Change:

- Moved these fixed constants out of resident data and into a low static
  constants area under `0x0700..0x0fff`, populated by the TLS ClientHello
  phase:
  - `master secret`
  - `client finished`
  - `server finished`
  - ChaCha20 constants
  - Poly1305 prime
  - SHA-256 initial state
- Left `key expansion` resident. Moving it too would have pushed the TLS
  ClientHello phase over one sector before the next cut.
- Updated local check scripts to validate the phase-local constant copies.

Measurements:

- Resident sectors: unchanged at 24.
- Resident bytes: unchanged at 12288.
- Resident nonzero payload: 12080 -> 11972 bytes.
- `16k-target` packed critical guarded slack: unchanged at -4947 bytes.

Result:

- Saved 108 resident payload bytes, but not enough to remove a loaded resident
  sector.
- This is a low-risk lifetime cleanup because the constants are staged before
  any TLS hash/PRF/AEAD use.

Verification:

- `make inspect` passes.
- `make test` passes.

## 2026-05-08 - Stage SHA-256 K table in bootstrap scratch

Change:

- Moved the 256-byte SHA-256 K round table out of resident data.
- Stages it from the TLS ClientHello phase into `0x0500..0x05ff`, the
  emergency/bootstrap scratch area below the handoff block.
- Added a build-time guard so the staged table cannot overlap the handoff block
  at `0x0600`.
- Relaxed the TLS ClientHello phase from "must fit in one sector" to "must fit
  in low scratch"; this phase is now two sectors, loaded before the network/TLS
  fast path starts.

Measurements:

- Resident sectors: 24 -> 23.
- Resident bytes: 12288 -> 11776.
- Resident nonzero payload: 11972 -> 11716 bytes.
- Resident load range: `0x1000..0x4000` -> `0x1000..0x3e00`.
- `16k-target` resident guarded slack: -1024 -> -512 bytes under the 1 KiB
  guard calculation, because the raw resident image now ends at `0x3e00`.
- `16k-target` packed critical guarded slack: -4947 -> -4435 bytes.

Result:

- One resident sector removed.
- The current single release-tracking value is now:
  `budget[16k-target] packed-range[critical] guarded-slack = -4435`.
- This cut is verified but should be watched because it uses the `0x0500`
  bootstrap scratch window during the TLS/hash path.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- First 3c501 BASIC-sidecar run after the cut reached `agent setup failed`,
  then an immediate 3c501 retry reached `seed build 6` and returned `ok`.
  Treat the first result as transient unless it repeats.

## 2026-05-08 - Move remaining TLS constants and crypto state to low memory

Change:

- Moved the remaining `key expansion` TLS PRF label into the low static
  constants area staged by the TLS ClientHello phase.
- Moved SHA-256, HMAC, TLS PRF, ChaCha20, Poly1305, and small TLS parser
  working state out of resident file-backed data and into the unused part of
  the handoff page after the published handoff structure.
- Added a boot-time clear for this low runtime state.
- Added build-time guards so the low runtime state cannot overlap later low
  scratch windows.

Measurements:

- Resident sectors: unchanged at 23.
- Resident bytes: unchanged at 11776.
- Resident nonzero payload: 11716 -> 11542 bytes.
- `16k-target` resident guarded slack: unchanged at -512 bytes.
- `16k-target` packed critical guarded slack: unchanged at -4435 bytes.

Result:

- Saved 174 resident payload bytes since the previous logged state, but did
  not yet cross another resident sector boundary.
- Current single release-tracking value remains:
  `budget[16k-target] packed-range[critical] guarded-slack = -4435`.
- This cut deliberately reuses low memory that belongs to Seed before the
  eventual agent handoff; the published handoff structure itself remains at
  `0x0600`.

Verification:

- `make inspect` passes.
- `make test` passes.
- BASIC-sidecar family tests on a 32 KiB host reached `seed build 6` and
  returned `ok` on `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and
  `vm-net-wd8003e`.

## 2026-05-08 - Stage TLS random and client public key in high scratch

Change:

- Moved the mutable TLS client random out of resident data and into high
  scratch.
- Moved the fixed P-256 client public key out of resident data. The existing
  TLS ClientHello phase now copies it into high scratch before TCP connects to
  the API endpoint, so it is available during the no-floppy TLS fast window.
- Updated the P-256 checker to validate the staged phase constant rather than
  requiring this key to live in resident data.

Measurements:

- Resident sectors: 25 -> 24.
- Resident bytes: 12800 -> 12288.
- Resident nonzero payload: 12367 -> 12270.
- High crypto scratch: 862 -> 959 bytes.
- Critical scratch: unchanged at 2964 bytes.
- `16k-target` packed critical guarded slack: -5362 -> -4947 bytes.

Result:

- One loaded resident sector removed.
- Net progress toward the guarded 16 KiB packed target: 415 bytes.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- NE2K BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Trim critical scratch to actual pre-response tail

Change:

- Replaced the implicit `tcp_payload_read_len * 2` critical scratch sizing
  with `tcp_payload_read_len + tls_pre_response_tail_len`.
- Added an assembly check so the pre-response scratch-tail constant fails the
  build if the scratch aliases drift.
- Updated the inspection budget's critical range from 3028 bytes to 2964
  bytes.

Measurements:

- Resident sectors: unchanged at 25.
- Resident bytes: unchanged at 12800.
- Resident nonzero payload: unchanged at 12367.
- Critical scratch bytes: 3028 -> 2964.
- `packed-range[critical]` guarded 16 KiB slack: -5426 -> -5362 bytes.

Result:

- Saved 64 bytes in the ideal packed 16 KiB memory budget.
- This is a small but useful lifetime cleanup; it does not solve the larger
  need to shrink or relocate the TLS/OpenAI critical window.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Rejected OpenAI max-output request-shape cut

Change tried:

- Temporarily changed the minimal OpenAI Responses request body from
  `{"model":"...","input":"Reply exactly: ok","store":false}` to include
  `"max_output_tokens":16`.
- The goal was to make the returned application-data records smaller before
  attempting to shrink the TLS application receive window.

Measurements:

- Build layout was unchanged before VM testing:
  - Resident sectors: 25.
  - Resident bytes: 12800.
  - Resident nonzero payload: 12367.
  - `packed-range[critical]` guarded 16 KiB slack: -5426 bytes.

Result:

- Rejected and reverted immediately.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached the agent/TLS path but
  failed with red `o agent setup failed`.
- This matches the earlier 32 KiB experiment: changing the OpenAI request shape
  is not currently a safe way to earn receive-buffer memory.

Verification:

- `make inspect` passed before VM testing.
- `make test` passed before VM testing.

## 2026-05-08 - Small resident UI/startup cuts, keep DNS state resident

Change:

- Removed the reserved word from the `CORE.SYS` header. The parsed header fields
  still end at the phase-count word and `tools/core-sys-info.py --check` accepts
  the shorter 23-byte header.
- Stopped preserving registers in one-shot startup scratch clearing and inlined
  the one remaining seed-marker cursor helper.
- Kept `dns_qname_len` and `dns_tx_len` resident after testing showed that
  moving them into the low phase-state tail broke the 3c501 network setup path.

Measurements:

- Resident sectors: unchanged at 25.
- Resident bytes: unchanged at 12800.
- Resident nonzero payload: 12375 -> 12367 bytes after the accepted cuts.
- Raw resident tail: about `0x3057` -> `0x304f`.
- Remaining raw bytes before dropping to 24 resident sectors: about 79 bytes.
- `16k-target` guarded slack: unchanged at -1536 bytes until the resident
  sector count drops.

Rejected/rolled back:

- Returning carry-set for packet-capable NICs was logically equivalent in the
  two local callers, but was rolled back together with the DNS-state move to
  keep this checkpoint conservative after the failed canary.
- Moving `dns_qname_len`/`dns_tx_len` into low scratch saved only 3 resident
  bytes and caused `vm-net-3c501` to stop at red `, network setup failed`.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok` after the network-related micro-cuts were rolled back.

## 2026-05-08 - Move phase-local setup state to low scratch tail

Change:

- Moved phase-local UI/config/DHCP/ARP/DNS scratch variables out of
  file-backed resident data and into the low phase-state tail after
  `user_cfg_size_current`.
- Kept state resident when it is still consumed by later resident network/TLS
  code, notably `dhcp_wait_count`, `arp_target_mac`, `dns_qname_len`, and
  `dns_tx_len`.

Measurements:

- `CORE.SYS` total size: unchanged at 26624 bytes.
- `CORE.SYS` total sectors: unchanged at 52.
- Resident sectors: unchanged at 25.
- Resident bytes: unchanged at 12800.
- Resident nonzero payload: 12508 -> 12472 bytes.
- Raw resident end moved from about `0x30dc` to `0x30b8`, leaving about
  184 bytes before the next resident-sector boundary.
- `16k-target` resident-only guarded slack: unchanged at -1536 bytes.
- `16k-target` packed high-crypto + critical scratch guarded slack: unchanged
  at -5426 bytes.

Result:

- Safe small resident-data cleanup. It does not change the loaded sector count
  yet, but it makes the next sector drop closer without touching TLS/crypto or
  OpenAI ordering.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Move remaining setup wrappers out of the resident path

Change:

- Reduced resident handoff initialization to only the boot drive and RAM-top
  values needed before the first phase load.
- Moved full handoff clear/magic/status initialization into the hardware setup
  phase.
- Folded the resident packet-I/O prepare wrapper into the existing packet init
  phase.
- Localized BIOS cursor positioning into the agent setup phase.

Measurements:

- Resident sectors: unchanged at 25.
- Resident bytes: unchanged at 12800.
- Resident nonzero payload: 12797 -> 12658.
- `16k-target` resident-only guarded slack: unchanged at -1536 bytes.
- `16k-target` ideal packed high-crypto + critical scratch guarded slack:
  unchanged at -5426 bytes.

Result:

- Saved 139 more resident bytes, but not enough to drop the next resident
  sector.
- The next sector boundary still needs roughly 370 more resident bytes.

Verification:

- `make inspect` passes.
- `make test` passes.

## 2026-05-08 - Move config FAT lookup/state into setup windows

Change:

- Moved FAT root lookup helpers out of the resident path and into the
  `NET.CFG`, `AGENTS.CFG`, and `USER.CFG` phases that need them.
- Moved config/FAT scratch temporaries into the unused low scratch tail after
  the file-sector buffer.

Measurements:

- Resident sectors: unchanged at 25.
- Resident bytes: unchanged at 12800.
- Resident nonzero payload: 12658 -> 12508.
- Total `CORE.SYS` bytes: 25600 -> 26624.
- Total `CORE.SYS` sectors: 50 -> 52.
- `NET.CFG` and `AGENTS.CFG` phases each grew from one sector to two sectors.
- `16k-target` resident-only guarded slack: unchanged at -1536 bytes.
- `16k-target` ideal packed high-crypto + critical scratch guarded slack:
  unchanged at -5426 bytes.

Result:

- Saved 150 more resident bytes without touching the TLS/OpenAI critical path.
- The next resident sector boundary needs roughly 220 more raw resident bytes.
- This deliberately trades extra setup-window floppy bytes for a smaller
  resident nucleus.

Verification:

- `make inspect` passes.
- `make test` passes.
- 32 KiB ROM BASIC sidecar smoke tests reached `seed build 6` and returned
  `ok` on `vm-net-3c501`, `vm-net-ne2k8`, and `vm-net-wd8003e`.

## 2026-05-08 - Add explicit 16 KiB budget reporting

Change:

- Extended `tools/core-sys-info.py` with `--load-addr`,
  `--budget LABEL:RAM_TOP[:STACK_GUARD]`, and `--fail-budget`.
- Updated `make inspect` to report both the current `24k-basic` budget and the
  future `16k-target` budget.

Measurements:

- `CORE.SYS` total size: 29696 bytes / 58 sectors.
- Resident size: 18944 bytes / 37 sectors.
- Resident nonzero payload: 18808 bytes.
- Resident load range: `0x1000..0x5a00`.
- `24k-basic` guarded slack: 1280 bytes.
- `16k-target` raw slack: -6656 bytes.
- `16k-target` guarded slack: -7680 bytes.
- Largest current phase window: 1536 bytes, ending at `0x0d00`.

Verification:

- `python3 -m py_compile tools/core-sys-info.py` passes.
- `make inspect` passes.
- `make test` passes.

## 2026-05-08 - Move save-only `USER.CFG` key labels out of resident data

Change:

- Moved `agent `, `model `, `reasoning `, `key `, and `endpoint ` labels
  from resident `data.inc` into the reloadable `save_user_cfg` phase.
- The save phase now references those labels through its loaded
  `low_scratch_start + (label - PHASE_BASE)` address, matching the existing
  phase-local `USER    CFG` filename.

Measurements:

- Resident sectors: unchanged at 37.
- Resident bytes: unchanged at 18944.
- Resident nonzero payload: 18808 -> 18768 bytes.
- `16k-target` guarded slack: unchanged at -7680 bytes.

Result:

- Correct low-risk lifetime cleanup, but too small to affect the 16 KiB
  sector-level fit. Next cuts need to move full scratch/code lifetimes into
  windows instead of only trimming resident constants.

## 2026-05-08 - Move TLS receive/pre-response arena out of resident file bytes

Change:

- Replaced the resident `tls_rx_copy times tls_stream_buffer_len db 0` payload
  with an explicit `critical_scratch_start` arena at `0x5000`.
- Added boot-time clearing for that scratch arena so config/TLS values still
  start from the same zero state that file-backed data previously provided.
- Added build-time overlap checks:
  - resident nucleus must end before `critical_scratch_start`
  - critical scratch must end before the current 24 KiB BASIC stack guard

Measurements:

- `CORE.SYS` total size: 29696 -> 26624 bytes.
- `CORE.SYS` total sectors: 58 -> 52.
- Resident sectors: 37 -> 31.
- Resident bytes: 18944 -> 15872.
- Resident nonzero payload: 18768 -> 15764.
- Resident load range: `0x1000..0x5a00` -> `0x1000..0x4e00`.
- `24k-basic` guarded slack: 1280 -> 4352 bytes.
- `16k-target` guarded slack: -7680 -> -4608 bytes.

Result:

- This is the first real sector-level win: 6 resident sectors removed.
- It is an intermediate 24 KiB-safe layout, not the final 16 KiB layout,
  because the scratch arena currently lives at `0x5000`.
- The next 16 KiB work must either shrink this TLS/API scratch or relocate it
  below the 16 KiB ceiling after more resident code moves out of the nucleus.

Verification:

- `make inspect` passes.
- `make test` passes.

## 2026-05-08 - Prebuild TLS ClientHello before TCP connect

Context:

- A previous ClientHello phase experiment loaded the phase after TCP connect
  and broke 3c501 during the first encrypted application-data receive.
- A follow-up dummy-read test showed that even one extra floppy sector read
  after `run_tcp_connect_phase` is enough to break the 3c501 path.

Change:

- Added a one-sector `L` phase that builds the TLS ClientHello before TCP
  connect.
- Wrote the finished ClientHello into `tls_client_hello_buffer`, currently
  aliasing `tls_rx_copy` in critical scratch.
- Changed `tls_probe_server` so the fast window only starts the transcript and
  sends already-built ClientHello bytes. It no longer reads floppy or builds
  ClientHello after TCP connect.
- Moved the ClientHello-only builder, PRNG state, and small ClientHello
  constants out of the resident nucleus.

Measurements:

- `CORE.SYS` total size: 26112 -> 26624 bytes, because of the new one-sector
  nonresident phase.
- Resident sectors: unchanged at 27.
- Resident bytes: unchanged at 13824.
- Resident nonzero payload: 13626 -> 13360 bytes.
- `16k-target` guarded slack: unchanged at -2560 bytes.

Result:

- Saves 266 resident nonzero bytes but does not yet cross a resident-sector
  boundary.
- Confirms the safe ordering rule: load/build ClientHello before TCP connect;
  keep the TCP-connected TLS/OpenAI fast window floppy-free.

Verification:

- `make test` passes.
- `make inspect` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- NE2K BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Remove obsolete resident ClientHello extension tail

Change:

- Removed the old resident `tls_extensions_tail` bytes after the `L`
  ClientHello phase gained its own phase-local copy.

Measurements:

- `CORE.SYS` total size: 26624 -> 26112 bytes.
- Resident sectors: 27 -> 26.
- Resident bytes: 13824 -> 13312.
- Resident nonzero payload: 13360 -> 13292.
- Resident load range: `0x1000..0x4600` -> `0x1000..0x4400`.
- `16k-target` guarded slack: -2560 -> -2048 bytes.

Result:

- First full resident sector drop after the pre-connect ClientHello phase.
- Remaining guarded 16 KiB deficit is 2048 bytes.

Verification:

- `make test` passes.
- `make inspect` passes.
- First 3c501 BASIC-sidecar canary on a 32 KiB host failed at agent setup,
  then an immediate rerun reached `seed build 6` and returned `ok`.
- NE2K BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Move DNS qname into pre-connect scratch

Change:

- Replaced the resident mutable `dns_qname` buffer with an alias inside the
  first critical scratch receive buffer at `tls_rx_copy + 512`.
- Kept the tiny resident `dns_default_qname` seed for the default internet
  probe.
- Added a build-time overlap check so the scratch DNS name cannot collide with
  the pre-response TLS/API scratch window.

Reasoning:

- `dns_qname` is needed during internet setup and selected-agent DNS/TCP setup,
  before the TLS receive buffer has to hold incoming TLS records.
- Once the prebuilt ClientHello has been sent, the first TLS receive buffer can
  overwrite this scratch space; DNS state is no longer needed in the connected
  TLS/OpenAI fast window.

Measurements:

- Resident sectors: unchanged at 26.
- Resident bytes: unchanged at 13312.
- Resident nonzero payload: 13292 -> 13212 bytes.
- `16k-target` guarded slack: unchanged at -2048 bytes.

Result:

- Saves 80 resident nonzero bytes, but not enough by itself to drop a resident
  sector.
- Remaining guarded 16 KiB deficit is still 2048 bytes.

Verification:

- `make test` passes.
- `make inspect` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- NE2K BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Shrink phase runner stubs

Change:

- Changed cold phase runner stubs to load phase sector/count values with
  8-bit immediates (`al`/`cl`) instead of 16-bit immediates (`ax`/`cx`).
- Added zero-extension in the shared phase runner before converting the sector
  offset to a FAT data LBA.

Measurements:

- Resident sectors: unchanged at 26.
- Resident bytes: unchanged at 13312.
- Resident nonzero payload: 13212 -> 13186 bytes.
- `16k-target` guarded slack: unchanged at -2048 bytes.

Result:

- Saves 26 resident nonzero bytes.
- The guarded 16 KiB deficit remains 2048 bytes.

Verification:

- `make test` passes.
- `make inspect` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Recover after unsafe ClientHello phase experiment

Context:

- Tried moving TLS ClientHello construction into a separate cold phase to save
  another resident sector on the fast-path code.
- Saved the full experimental dirty state outside the repository before
  backing it out:
  `/private/tmp/seed-16kb-windowed-nucleus-danger-zone-state.patch`
  and `/private/tmp/seed-16kb-windowed-nucleus-danger-zone-untracked.tgz`.

Result:

- NE2K still reached `seed build 6` and returned `ok` with the experiment.
- 3c501 regressed: it reached TLS server-Finished verified, then failed at the
  first encrypted application-data receive.
- Reverted only the ClientHello phase move and temporary failure diagnostics.
  Kept the earlier proven window/nucleus slimming cuts.
- Kept the failure-menu key-drain fix, since it prevents stale Enter from
  immediately selecting retry and hiding the first failure.

Measurements after recovery:

- Resident sectors: 27.
- Resident bytes: 13824.
- Resident nonzero payload: 13626.
- Resident load range: `0x1000..0x4600`.
- `24k-basic` guarded slack: 6400 bytes.
- `16k-target` guarded slack: -2560 bytes.

Verification:

- `make test` passes.
- `make inspect` passes.
- NE2K BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

Future rule:

- Before editing TLS/OpenAI fast-path code again, stop and ask whether to
  commit or at least save a reversible checkpoint.

## 2026-05-08 - Move TLS/P-256 working state to high scratch

Change:

- Moved TLS write keys, write IVs, record sequence numbers, AEAD nonce/AAD,
  Finished plaintext/ciphertext/tag buffers, and P-256/chacha/poly1305 working
  state out of file-backed resident data into the high scratch gap starting at
  `0x4c00`.
- Added boot-time clearing for the high crypto scratch window before any crypto
  path uses it.
- Kept the already moved TLS receive/pre-response arena at `0x5000`.

Measurements:

- `CORE.SYS` total size: 26112 -> 25600 bytes.
- `CORE.SYS` total sectors: 51 -> 50.
- Resident sectors: 30 -> 29.
- Resident bytes: 15360 -> 14848.
- Resident nonzero payload: 15308 -> 14791.
- Resident load range: `0x1000..0x4c00` -> `0x1000..0x4a00`.
- `24k-basic` guarded slack: 4864 -> 5376 bytes.
- `16k-target` guarded slack: -4096 -> -3584 bytes.

Result:

- One more resident sector removed.
- This is still an intermediate layout, because both high crypto scratch
  (`0x4c00..`) and TLS receive/pre-response scratch (`0x5000..`) are above the
  final 16 KiB ceiling.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- The same 3c501 BASIC-sidecar run with the VM set to 24 KiB did not reach
  Seed; it showed corrupted/partial BASIC-sidecar text before handoff.
- A minimal 3c501 16 KiB ROM BASIC smoke test with no BASIC typing reached IBM
  ROM BASIC and reported `12252 Bytes free`. This means the emulator/5150 ROM
  can enter BASIC at 16 KiB; the current failure is in our sidecar loader/memory
  map, not a fundamental 16 KiB VM boot blocker.

## 2026-05-08 - Move setup-only packet builders into setup phases

Change:

- Moved DHCP Discover/Request frame construction and transmit wrappers from the
  resident packet transmitter into the DHCP setup phase.
- Moved ARP request and DNS query frame construction/transmit wrappers from the
  resident packet transmitter into the TCP-connect setup phase.
- Kept `ne_transmit_frame`, TCP SYN/ACK/payload construction, TCP checksums, and
  TLS-facing send paths resident because TLS/OpenAI still needs those during
  the critical window.

Measurements:

- Resident sectors: 29 -> 28.
- Resident bytes: 14848 -> 14336.
- Resident nonzero payload: 14791 -> 14218.
- Resident load range: `0x1000..0x4a00` -> `0x1000..0x4800`.
- `24k-basic` guarded slack: 5376 -> 5888 bytes.
- `16k-target` guarded slack: -3584 -> -3072 bytes.
- TCP-connect phase grew to 3 sectors, still ending at `0x0f00` inside the
  `net_setup_phase_start..low_scratch_end` window.

Result:

- One more resident sector removed without changing the TLS/OpenAI ordering.
- Remaining guarded 16 KiB deficit is 3072 bytes.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c501 canary passed through the ROM BASIC sidecar path on a 32 KiB host with
  Seed mounted in B: and the current 24 KiB runtime ceiling. The run reached
  `seed build 6` and returned `ok`.
- 3c501 canary passed through the ROM BASIC sidecar path on a 32 KiB host with
  Seed mounted in B: and the current 24 KiB runtime ceiling. The run reached
  `seed build 6` and returned `ok`.

Harness note:

- Low-memory BASIC runs must keep A: empty and mount the Seed floppy as B:.
  Mounting Seed in A: makes the IBM PC try to boot it first, which fails before
  ROM BASIC on the low-memory path.
- Added `*` to the keycode injector because the compact hex BASIC sidecar uses
  `J=I*2+1`.

## 2026-05-08 - Move packet I/O initialization into a setup window

Change:

- Added a one-sector `I` phase for packet I/O initialization.
- Moved NE/3c503/3c501 packet init code out of resident `nic.inc` and into the
  new phase.
- Kept the actual packet send/receive routines resident for the current
  TLS/OpenAI path.
- Moved response-parser answer pointer/length scratch into the nonresident
  response phase, since that state is consumed immediately by the same phase.

Measurements:

- Resident sectors: 28 -> 27.
- Resident bytes: 14336 -> 13824.
- Resident nonzero payload: 14218 -> 13822.
- Resident load range: `0x1000..0x4800` -> `0x1000..0x4600`.
- `24k-basic` guarded slack: 5888 -> 6400 bytes.
- `16k-target` guarded slack: -3072 -> -2560 bytes.
- Added one nonresident `I` phase sector. Total `CORE.SYS` sectors stayed at
  50 because the resident sector dropped at the same time.

Result:

- One more resident sector removed.
- Remaining guarded 16 KiB deficit is 2560 bytes.
- This is still an intermediate 32 KiB-host validation layout; high crypto
  scratch and TLS receive scratch are still above the final 16 KiB ceiling.

Verification:

- `make inspect` passes.
- `make test` passes.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-08 - Prune unused TLS extension flag state

Change:

- Removed resident ServerHello extension flag bookkeeping.
- Removed extended-master-secret seed construction and label text. The current
  ClientHello does not offer EMS, so the proven OpenAI path uses the normal TLS
  1.2 master-secret seed.

Measurements:

- Resident sectors: unchanged at 31.
- Resident bytes: unchanged at 15872.
- Resident nonzero payload: 15764 -> 15628 bytes.
- `16k-target` guarded slack: unchanged at -4608 bytes.

Result:

- Correct lifetime/product cleanup, but not enough by itself to drop a loaded
  resident sector.

## 2026-05-08 - Move SHA-256 block schedule to high scratch

Change:

- Moved `sha256_block` and `sha256_w` out of file-backed resident data into a
  fixed high scratch gap at `0x4e00..0x4f40`.
- Added build-time overlap checks so resident code must stay below this high
  scratch gap and the high scratch gap must stay below the TLS/API scratch at
  `0x5000`.

Measurements:

- `CORE.SYS` total size: 26624 -> 26112 bytes.
- `CORE.SYS` total sectors: 52 -> 51.
- Resident sectors: 31 -> 30.
- Resident bytes: 15872 -> 15360.
- Resident nonzero payload: 15628 -> 15308.
- Resident load range: `0x1000..0x4e00` -> `0x1000..0x4c00`.
- `24k-basic` guarded slack: 4352 -> 4864 bytes.
- `16k-target` guarded slack: -4608 -> -4096 bytes.

Result:

- One more resident sector removed.
- This is still an intermediate 24 KiB-safe layout. The SHA scratch is above
  the final 16 KiB ceiling and will need to move down once the nucleus is small
  enough.

Verification:

- `make inspect` passes.
- `make test` passes.

## 2026-05-09 - Trim unused HMAC third segment and successful TLS status writes

Change:

- Removed the unused third HMAC input segment from resident state and the HMAC
  update path.
- Removed successful TLS milestone writes to `handoff_net_status`. Fatal TLS
  paths still report the TLS error class, and the visible phase marker remains
  the user-facing progress/error state.

Measurements:

- Resident sectors: unchanged at 21.
- Resident bytes: unchanged at 10752.
- Resident nonzero payload: 10670 -> 10576 bytes.
- `16k-target packed critical guarded slack`: unchanged at -2883 bytes.

Result:

- Safe cleanup that recovered 94 bytes inside the current resident sector
  envelope, but did not yet cross the next 512-byte sector boundary.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-09 - Move crypto/API implementation into natural LINK window

Change:

- Split the secure-link implementation (`sha256`, `p256`, `chacha20`,
  `poly1305`, `tls`, and `agent_api`) out of the always-resident nucleus.
- Added a `K` phase-table entry for the LINK window and a
  `load_core_window` helper that loads that window at its natural runtime
  address before the selected-agent TCP connection starts.
- Preserved the proven provider timing rule: the floppy load happens before
  TCP 443 connect, not inside the TLS/OpenAI fast path.

Measurements:

- `CORE.SYS` total size: 25088 -> 25600 bytes.
- `CORE.SYS` total sectors: 49 -> 50.
- Resident sectors: 21 -> 5.
- Resident bytes: 10752 -> 2560.
- Resident nonzero payload: 10576 -> 2092 bytes.
- New LINK window: 17 sectors, loaded at `0x1a00..0x3c00`.
- The old `16k-target packed critical guarded slack` number is no longer the
  release-tracking number because it does not account for the natural LINK
  window. Use `largest-phase-end`/explicit LINK-window accounting before
  making the next 16 KiB fit claim.

Result:

- Major structural progress: the nucleus itself is now tiny, while the
  time-sensitive secure-link path stays contiguous and preloaded before the
  remote timing window.
- Not a final 16 KiB map yet. High crypto scratch and critical scratch are
  still above the 16 KiB ceiling and must be relocated or reduced next.

Verification:

- `make inspect` passes.
- `make test` passes.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached `seed build 6` and
  returned `ok`.

## 2026-05-09 - Rejected low HMAC scratch alias

Change:

- Tried to move HMAC ipad/opad/prepared-state scratch into the unused front of
  `fs_sector_buffer`, ahead of the low SHA-256 scratch already stored there.

Measurements:

- Attempted critical scratch: 2506 -> 2282 bytes.
- Attempted `16k-target packed critical guarded slack`: -2788 -> -2564 bytes.

Result:

- Rejected and reverted. The vector tests passed, but NE2K8 failed during
  agent setup in the BASIC-sidecar VM run.
- Likely cause: the agent request/setup path still depends on the front of
  `fs_sector_buffer`, so this alias is not lifetime-safe without a deeper
  request-buffer redesign.

Verification:

- Attempted build: `make inspect` and `make test` passed.
- Runtime canary: NE2K8 failed during agent setup.

## 2026-05-09 - Rejected partial low HMAC scratch alias

Change:

- Tried a narrower version of the low HMAC alias: move only transient
  `hmac_ipad`, `hmac_opad`, and `hmac_inner_digest` into the front of
  `fs_sector_buffer`, while keeping the prepared HMAC state in the critical
  scratch window.

Measurements:

- Attempted critical scratch: 2506 -> 2346 bytes.
- Attempted `16k-target packed critical guarded slack`: -2788 -> -2628 bytes.

Result:

- Rejected and reverted. This was less invasive than the full HMAC alias and
  passed the early canaries, but it still was not safe across NIC families.

Verification:

- `make inspect` passed.
- `make test` passed.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c503 BASIC-sidecar canary failed during agent setup.

## 2026-05-09 - Rejected prepared-only TLS app send cleanup

Change:

- Tried to simplify the early application-data send path so it only checked and
  sent `tls_prepared_app_len`, removing the fallback path through
  `tls_send_application_data_for_nic`.

Measurements:

- LINK code shrank by 18 bytes.
- LINK window remained 17 sectors.
- `CORE.SYS` remained 25600 bytes.
- `16k-target packed critical guarded slack` remained -2788 bytes.

Result:

- Rejected and reverted. The static savings were too small, and 3c503 failed
  during agent setup.

Verification:

- `make inspect` passed.
- `make test` passed.
- 3c503 BASIC-sidecar canary failed during agent setup.

## 2026-05-09 - Rejected TLS transcript/key-schedule bookkeeping trim

Change:

- Tried removing `tls_transcript_len_low/high`, which were maintained but not
  consumed by the current SHA-256 transcript path.
- Tried removing the `tls_key_schedule_ready` byte and branch because
  `tls_probe_server` currently starts with a fresh transcript/key schedule.

Measurements:

- Resident nonzero bytes: 2092 -> 2088.
- Actual LINK end moved from `0x2b4f` to `0x2b25`.
- LINK window remained 17 sectors.
- `16k-target packed critical guarded slack` remained -2788 bytes.

Result:

- Rejected and reverted. The static savings were real but small, and 3c501
  failed during agent setup.
- The failure was specific to removing `tls_key_schedule_ready`: 3c501 uses
  `tls_prepare_early_key_schedule` before its early ClientKeyExchange send and
  later needs the ready flag to avoid recomputing the keys in the final path.

Verification:

- `make inspect` passed.
- `make test` passed.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary failed during agent setup.

## 2026-05-09 - Drop unused TLS transcript length counters

Change:

- Removed `tls_transcript_len_low/high` and their update/clear writes.
- Kept `tls_key_schedule_ready` because 3c501 depends on the early key
  schedule state across its split ClientKeyExchange path.

Measurements:

- Resident nonzero bytes: 2092 -> 2088.
- Actual LINK end moved from `0x2b4f` to `0x2b35`.
- LINK window remained 17 sectors, with roughly 309 bytes still needed to drop
  it to 16 sectors.
- `16k-target packed critical guarded slack` remained -2788 bytes.

Result:

- Accepted small TLS bookkeeping cleanup. It is not enough to move the tracked
  release metric yet, but it removes 26 bytes from the LINK window without
  changing packet ordering, key material placement, or ACK timing.

Verification:

- `make inspect` passed.
- `make test` passed.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached returned `ok`.

## 2026-05-09 - Trim unused ServerKeyExchange parse state

Change:

- Removed unused ServerKeyExchange scratch fields for the curve id,
  public-key length, signature hash/algorithm, and signature length.
- Simplified `tls_parse_server_key_exchange` to use the already-validated
  fixed uncompressed P-256 public-key length directly.
- Preserved the current fixed-scalar proof behavior: the server public X
  coordinate is copied directly into `tls_premaster_secret`.

Measurements:

- `CORE.SYS` total size: unchanged at 25600 bytes.
- LINK window remained 17 sectors.
- Actual LINK end moved to `0x2b4f`.
- 16-sector LINK threshold still needs about 335 more bytes of code removed.
- `16k-target packed critical guarded slack` remained -2788 bytes.

Result:

- Accepted small LINK-window cleanup. It does not yet cross a sector boundary,
  but it removes dead parse state and moves us closer to the first 512-byte
  LINK-sector win.

Verification:

- `make inspect` passed.
- `make test` passed.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host reached returned `ok`.

## 2026-05-09 - Rejected transient HMAC pad scratch

Change tried:

- Removed the persistent `hmac_ipad` and `hmac_opad` buffers from the critical
  pre-response scratch tail.
- Generated each HMAC pad directly in the existing `sha256_block` scratch,
  then compressed that one block to capture the prepared inner and outer HMAC
  states.
- Reduced the inspected critical scratch budget from 2506 to 2378 bytes.

Measurements:

- Critical scratch would have dropped 2506 -> 2378 bytes.
- `16k-target packed critical guarded slack` would have improved
  -2788 -> -2660 bytes.
- `CORE.SYS` stayed 25600 bytes and K stayed at 17 sectors.

Result:

- Rejected and reverted.
- Static crypto vectors passed, and live BASIC-sidecar canaries reached
  returned `ok` on NE2K8, 3c501, and 3c503.
- WD8003e failed during agent setup, so this scratch alias is not safe across
  all required families.

Recovery:

- Restored persistent `hmac_ipad` / `hmac_opad` scratch and
  `CRITICAL_SCRATCH_LEN=2506`.

## 2026-05-09 - Rejected TLS client public key phase relocation

Change tried:

- Moved the fixed 65-byte P-256 ClientKeyExchange public key constant from the
  LINK window into the TLS ClientHello phase.
- Pointed `build_tls_client_key_exchange` at the low-memory phase copy, with an
  assembly guard that kept the constant in the first 512 bytes so the later
  TCP-connect phase load would not overwrite it.

Measurements:

- LINK end moved from `0x2b35` to `0x2af4`.
- K still stayed at 17 sectors, with roughly 244 more bytes needed to drop to
  16 sectors.
- `16k-target packed critical guarded slack` stayed at -2788 bytes because no
  sector boundary moved.

Result:

- Rejected and reverted.
- `make inspect` and `make test` passed after updating the host-side P-256
  checker to read the relocated constant, but the NE2K8 BASIC-sidecar canary
  failed at agent setup.
- Cause: the low-memory TLS phase copy is not actually stable through the
  handshake. NIC packet buffers use `low_scratch_start`, so network traffic can
  overwrite that area before ClientKeyExchange is built.

Recovery:

- Restored the public key constant to the LINK window and restored the checker
  expectation.

## 2026-05-09 - Inline fixed P-256 premaster stub

Change:

- Removed the LINK-window include of `core/p256.inc`.
- Inlined `tls_prepare_premaster_secret` as the current fixed-scalar proof
  stub (`clc; ret`).
- Preserved the Build 6 behavior where ServerKeyExchange parsing already copies
  the server public X coordinate into `tls_premaster_secret`.

Measurements:

- Actual LINK end moved from `0x2b35` to `0x2b2b`.
- LINK window remained 17 sectors, with roughly 299 bytes still needed to drop
  it to 16 sectors.
- `CORE.SYS` stayed 25600 bytes.
- `16k-target packed critical guarded slack` stayed at -2788 bytes.

Result:

- Accepted small LINK-window cleanup. This removes an emitted no-op helper from
  the fragile TLS path without changing packet timing, transcript state, or key
  material placement.

Verification:

- `make inspect` passed.
- `make test` passed.
- NE2K8 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c501 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- 3c503 BASIC-sidecar canary on a 32 KiB host reached returned `ok`.
- WD8003e BASIC-sidecar canary on a 32 KiB host initially failed during agent
  setup, then reached returned `ok` on clean rerun; treated as transient.
