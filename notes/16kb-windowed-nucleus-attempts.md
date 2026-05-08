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
