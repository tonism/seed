# 24KB Windowed Attempts

Branch: `work/24kb-windowed`

Starting point:
- `main` 32 KiB release at `e9eb29f`.
- One 160 KiB FAT12 floppy image.
- One visible `CORE.SYS` runtime.
- 4.77 MHz IBM PC 5150 profiles are the compatibility gate.
- Representative 32 KiB NIC-family tests passed on `vm-net-ne2k8`,
  `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e`.

Milestone target:
- First releasable target for this branch is 24 KiB RAM.
- Architecture decisions should still be compatible with a later 16 KiB target.

Design direction:
- Keep one floppy, one codebase, and one user-visible `CORE.SYS`.
- Reduce the permanent resident nucleus.
- Use explicit phase-local windows for code/data that do not need to stay
  resident after the phase completes.
- Preserve the known-good Build 6 ordering, especially the TLS final flight,
  early OpenAI request send, server Finished verification, response parse, and
  splash handoff.
- Prefer controlled cuts: one change, measure resident size, test at the
  current safe RAM size, then lower the VM ceiling only when the measured
  memory map justifies it.
- Keep the detailed architecture reference in
  `notes/windowed-architecture-design.md`.

Initial hard numbers from the 32 KiB release:
- `CORE.SYS` loads at `0x1000`.
- 32 KiB ceiling is `0x8000`.
- Release `CORE.SYS` size is 27,094 bytes.
- Release loaded end is `0x79d5`.
- Release stack top is `0x8000`.
- Release 1.5 KiB stack guard starts at `0x7a00`.
- Release guard slack is 42 bytes.

Implication for 24 KiB:
- 24 KiB ceiling is `0x6000`.
- With `CORE.SYS` still loaded at `0x1000`, the hard resident window before
  stack/guard is 20,480 bytes.
- Compared with the 32 KiB release image, roughly 6.6 KiB must move out of the
  permanent resident image before adding any useful stack guard.

## 2026-05-07 - Move cold failure and adapter UI into phases

Change:
- Moved the fatal retry/restart UI into nonresident `F`.
- Moved the ambiguous-adapter fallback menu into nonresident `H`.
- Moved phase-only root filenames and interactive prompt strings out of
  resident data and into their owning phases.
- Reused the existing pre-agent menu scratch byte for the adapter-select mode
  instead of keeping a dedicated resident byte.
- Left the normal auto-detected NIC path and TLS/OpenAI fast path unchanged.

Measurements:
- Resident sectors dropped from 46 to 45.
- Resident bytes when sector-rounded dropped from 23,552 to 23,040.
- `CORE.SYS` total size remains 29,696 bytes / 58 sectors after adding `F`
  and `H` phase sectors and removing enough resident data/code to cross the
  resident sector boundary.
- Phase entries:
  - `F`: sector offset 45, one sector, load address `0x0700`.
  - `H`: sector offset 46, one sector, load address `0x0700`.
  - `P`: sector offset 47, one sector, load address `0x0700`.
  - `A`: sector offset 48, one sector, load address `0x0700`.
  - `U`: sector offset 49, two sectors, load address `0x0700`.
  - `Q`: sector offset 51, three sectors, load address `0x0700`.
  - `R`: sector offset 54, one sector, load address `0x0700`.
  - `T`: sector offset 55, one sector, load address `0x0700`.
  - `B`: sector offset 56, one sector, load address `0x0700`.
  - `S`: sector offset 57, one sector, load address `0x0700`.
- Gap to the guarded 24 KiB BASIC target is now 8 resident sectors / 4,096
  bytes.

Verification:
- `make inspect` passes.

## 2026-05-07 - Phase-only helper cleanup reaches 44 resident sectors

Change:
- Moved selected-agent DNS target preparation into a nonresident `E` phase.
  This runs before TCP/TLS and remains outside the OpenAI response timing
  window.
- Moved phase-only helper state out of the resident image:
  - built-in agent IDs now live in the `A`/`AGENTS.CFG` phase.
  - single-cluster config file reads are duplicated locally in the `A`, `P`,
    and `U` phases.
  - config line value copying is duplicated locally in the `P` and `U` phases.
  - seed value clearing and the LiteLLM endpoint predicate are duplicated in
    the setup phases that need them.
  - request/save buffer append helpers are duplicated in the `R` and `S`
    phases.
- Kept `find_root_file` resident because duplicating it would overflow the
  one-sector config phases.

Measurements:
- Resident sectors dropped from 45 to 44.
- Resident bytes when sector-rounded dropped from 23,040 to 22,528.
- `CORE.SYS` total size dropped from 30,208 to 29,696 bytes.
- `core_resident_end` is at image offset `0x57fc`, leaving 4 bytes before the
  44-sector resident boundary.
- Gap to the guarded 24 KiB BASIC target is now 7 resident sectors, or 3,584
  sector-rounded bytes.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- `vm-net-ne2k8` reaches `seed build 6` and displays returned `ok`.

## 2026-05-07 - Hardware setup phase reaches 43 resident sectors

Change:
- Moved hardware setup into the nonresident `H` phase:
  - I/O port scan.
  - ambiguous adapter selection UI.
  - 3c501, 3c503, NE1000/NE2000, and WD8003 MAC/PROM reads.
  - MAC validation and handoff MAC finalization.
- Kept resident packet setup and all network/TLS/application paths resident.
  The `H` phase only runs before the packet/TLS window and leaves the handoff
  block populated for later resident paths.

Measurements:
- Resident sectors dropped from 44 to 43.
- Resident bytes when sector-rounded dropped from 22,528 to 22,016.
- `CORE.SYS` total size is 30,208 bytes because the `H` phase now spans three
  sectors.
- `core_resident_end` is at image offset `0x5541`, leaving 191 bytes before
  the 43-sector resident boundary.
- Gap to the guarded 24 KiB BASIC target is now 6 resident sectors, or 3,072
  sector-rounded bytes.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- No-card BIOS boot smoke reaches the expected phased red
  `. no network card` screen with `retry` and `restart`.
- Saved `USER.CFG` `vm-net-ne2k8` canary reaches `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-3c501` canary reaches `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-3c503` canary reaches `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-wd8003e` canary reaches `seed build 6` with `ok`.

## 2026-05-07 - Move pre-TLS DHCP/DNS/TCP setup into phases

Change:
- Moved DHCP offer/ACK waiting and parsing into nonresident `D`.
- Moved pre-TLS DNS ARP, DNS response parsing, next-hop ARP, TCP SYN/ACK
  waiting, and TCP connect parsing into nonresident `C`.
- Kept established TCP payload receive, TLS, crypto, request send, and response
  handling resident.
- Loaded `D` and `C` at `0x0900` instead of `0x0700`, reserving the first
  512 bytes of low scratch for the pre-TLS packet frame they must build/read.
- Changed TCP segment construction to clear only the actual frame length rather
  than the full 1600-byte packet arena, so SYN/ACK setup does not overwrite a
  phase executing above the packet scratch.

Measurements:
- Resident sectors dropped from 43 to 40.
- Resident bytes when sector-rounded dropped from 22,016 to 20,480.
- Saved 1,536 resident bytes.
- `CORE.SYS` total size is 31,232 bytes / 61 sectors because the new `D` and
  `C` setup phases each occupy two nonresident sectors.
- Phase entries:
  - `D`: sector offset 44, two sectors, load address `0x0900`.
  - `C`: sector offset 46, two sectors, load address `0x0900`.
- Gap to the guarded 24 KiB BASIC target is now 3 resident sectors, or 1,536
  sector-rounded bytes.

Important finding:
- The first version loaded `D`/`C` at `0x0700`, which is also `ne_tx_frame`.
  DHCP transmit then overwrote the currently executing phase.
- Moving the phases to `0x0900` fixed the DHCP self-overwrite but exposed the
  TCP builder clearing the full packet arena. Limiting that clear to the actual
  TCP frame length made the cut runtime-safe in the tested families.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- Saved `USER.CFG` `vm-net-ne2k8` canary reaches `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-3c501` canary reaches `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-3c503` canary reaches `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-wd8003e` canary reaches `seed build 6` with `ok`.

## 2026-05-07 - Low-memory BASIC entry path

Change:
- Added a ROM BASIC-style bootstrap generator and tiny 8086 loader.
- The normal BIOS boot path stays intact: boot sector -> reserved loader ->
  FAT12 root `CORE.SYS`.
- The same floppy also ships `SEED24A.BAS` and `SEED24B.BAS`. These poke a
  tiny loader at `0x3a00`, then use BIOS INT 13h to read the same `CORE.SYS`
  sectors from drive A or drive B and jump to `0000:1000`.
- `CORE.SYS` remains the first FAT data file, so the BASIC loader can use the
  stable first-data LBA while the boot loader still reads through FAT12.
- The BASIC loader uses a 24 KiB stack ceiling (`0x6000`) and refuses to load a
  core that would collide with its 256-byte stack guard. The current 32 KiB
  release `CORE.SYS` is still too large for this path, so running the BASIC
  bootstrap now should show the red `X` failure marker until the resident core
  is slimmed.

Verification:
- `make inspect` passes.

## 2026-05-07 - Move response parsing, splash, and phase metadata out of resident memory

Change:
- Moved decrypted application response parsing and answer typing into
  nonresident `T`, loaded after TLS has already copied the decrypted record into
  `tls_rx_copy`.
- Moved the final `seed build 6` splash into nonresident `B`.
- Moved the phase table out of the resident image and into the padded `S` phase
  sector; `tools/core-sys-info.py` now validates phase table bounds against the
  full `CORE.SYS` container instead of resident bytes.
- Removed the unreachable post-TLS request resend fallback and compacted several
  small resident branches.

Measurements:
- Resident sectors dropped from 47 to 46.
- Resident bytes when sector-rounded dropped from 24,064 to 23,552.
- `CORE.SYS` total size is 29,184 bytes / 57 sectors.
- Phase entries:
  - `P`: sector offset 46, one sector, load address `0x0700`.
  - `A`: sector offset 47, one sector, load address `0x0700`.
  - `U`: sector offset 48, two sectors, load address `0x0700`.
  - `Q`: sector offset 50, three sectors, load address `0x0700`.
  - `R`: sector offset 53, one sector, load address `0x0700`.
  - `T`: sector offset 54, one sector, load address `0x0700`.
  - `B`: sector offset 55, one sector, load address `0x0700`.
  - `S`: sector offset 56, one sector, load address `0x0700`.
- Gap to the guarded 24 KiB BASIC target is now 9 resident sectors / 4,608
  bytes.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- Saved `USER.CFG` `vm-net-ne2k8` canary reaches `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-3c501` canary initially showed one `agent setup
  failed` warning, then two immediate reruns reached `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-3c503` canary reaches `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-wd8003e` canary reaches `seed build 6` with `ok`.

## 2026-05-07 - Move optional config readers into phases

Change:
- Moved optional `NET.CFG` probe parsing into nonresident `P`.
- Moved `AGENTS.CFG` agent-list parsing and built-in fallback population into
  nonresident `A`.
- Added a generic one-sector phase runner; the existing `S` save phase now uses
  the same path.
- Left the resident TLS/OpenAI fast path unchanged.

Measurements:
- Resident sectors dropped from 52 to 51.
- Resident bytes when sector-rounded dropped from 26,624 to 26,112.
- `CORE.SYS` total size returned to 27,648 bytes because `P`, `A`, and `S`
  each occupy one nonresident sector.
- Phase table entries:
  - `P`: sector offset 51, one sector, load address `0x0700`.
  - `A`: sector offset 52, one sector, load address `0x0700`.
  - `S`: sector offset 53, one sector, load address `0x0700`.
- Phase table offset is 26,002 bytes into `CORE.SYS`.
- Estimated `core_resident_end` is now image offset 26,032, leaving 80 bytes
  before the 51-sector resident boundary.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- First `vm-net-ne2k8` canary reached the agent selection prompt instead of
  saved `USER.CFG`; the menu showed the old built-in fallback stride bug
  (`openai`, truncated `anthropic`, hidden `google`).
- Root cause was the phase resident-call relocation macro targeting one byte
  before the intended resident routine.
- Fixed the phase-call displacement in all phase includes and made built-in
  fallback agent IDs populate the same 16-byte slots used by the menu.
- Re-run `vm-net-ne2k8` canary reaches `seed build 6` with `ok`.
- `vm-net-ne2k8` canary reaches `seed build 6` with `ok`.

## 2026-05-07 - Move USER.CFG read/parser into a phase

Change:
- Moved optional `USER.CFG` read, line parsing, and saved-agent matching into
  nonresident `U`.
- Generalized the resident phase runner to load multi-sector phase windows into
  low scratch before jumping to them.
- Kept the resident interactive prompt, validation, and save trigger in place.
- Left the resident TLS/OpenAI fast path unchanged.

Measurements:
- Resident sectors dropped from 51 to 50.
- Resident bytes when sector-rounded dropped from 26,112 to 25,600.
- `CORE.SYS` total size grew from 27,648 to 28,160 bytes because `U` occupies
  two nonresident sectors.
- Phase table entries:
  - `P`: sector offset 50, one sector, load address `0x0700`.
  - `A`: sector offset 51, one sector, load address `0x0700`.
  - `U`: sector offset 52, two sectors, load address `0x0700`.
  - `S`: sector offset 54, one sector, load address `0x0700`.
- Phase table offset is 25,422 bytes into `CORE.SYS`.
- Estimated `core_resident_end` is now image offset 25,462, leaving 138 bytes
  before the 50-sector resident boundary.
- Gap to the guarded 24 KiB BASIC target is now roughly 6.7 KiB of resident
  code/data.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- `make test` passes.
- `git diff --check` passes.
- `vm-net-ne2k8` canary reaches `seed build 6` with `ok`.

## 2026-05-07 - Move missing-config agent setup into a phase

Change:
- Moved the interactive agent selector and key/endpoint entry path into a
  nonresident `Q` phase.
- Changed resident `ensure_seed_values` into a validation-only guard: saved
  `USER.CFG` with required values skips `Q`; missing or invalid values load
  `Q` from floppy.
- Kept the resident TLS/OpenAI fast path unchanged.
- Left the shared form drawing helpers resident for this cut to reduce UI
  regression risk.

Measurements:
- Resident sectors dropped from 50 to 49.
- Resident bytes when sector-rounded dropped from 25,600 to 25,088.
- `CORE.SYS` total size grew from 28,160 to 28,672 bytes because `Q` occupies
  two nonresident sectors.
- Phase table entries:
  - `P`: sector offset 49, one sector, load address `0x0700`.
  - `A`: sector offset 50, one sector, load address `0x0700`.
  - `U`: sector offset 51, two sectors, load address `0x0700`.
  - `Q`: sector offset 53, two sectors, load address `0x0700`.
  - `S`: sector offset 55, one sector, load address `0x0700`.
- Phase table offset is 24,842 bytes into `CORE.SYS`.
- Gap to the guarded 24 KiB BASIC target is now roughly 6.0 KiB of resident
  code/data.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- Saved `USER.CFG` `vm-net-ne2k8` canary reaches `seed build 6` with `ok`.
- `INCLUDE_USER_CFG=0` `vm-net-ne2k8` canary reaches the `agent?` selector and
  shows all configured agents, including `anthropic` and `google`.

## 2026-05-07 - Move agent-specific UI helpers into Q

Change:
- Moved the agent selector drawing, agent values form drawing, input line
  rendering, and agent-specific panel clearing helpers into the nonresident
  `Q` phase.
- Kept generic text output, failure UI, tones, and hot network/TLS/OpenAI code
  resident.

Measurements:
- Resident sectors dropped from 49 to 48.
- Resident bytes when sector-rounded dropped from 25,088 to 24,576.
- `CORE.SYS` total size remains 28,672 bytes.
- `Q` grew from two phase sectors to three phase sectors.
- Phase table entries:
  - `P`: sector offset 48, one sector, load address `0x0700`.
  - `A`: sector offset 49, one sector, load address `0x0700`.
  - `U`: sector offset 50, two sectors, load address `0x0700`.
  - `Q`: sector offset 52, three sectors, load address `0x0700`.
  - `S`: sector offset 55, one sector, load address `0x0700`.
- Phase table offset is 24,355 bytes into `CORE.SYS`.
- Gap to the guarded 24 KiB BASIC target is now roughly 5.5 KiB of resident
  code/data.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- Saved `USER.CFG` `vm-net-ne2k8` canary reaches `seed build 6` with `ok`.
- `INCLUDE_USER_CFG=0` `vm-net-ne2k8` canary reaches the `agent?` selector and
  shows all configured agents, including `anthropic` and `google`.

## 2026-05-07 - Move OpenAI request build into R

Change:
- Moved the OpenAI HTTP/JSON request construction into a nonresident `R` phase.
- The resident agent path now loads `R` before TCP connect and TLS handshake,
  so the critical TLS/application-data window only consumes the already-built
  `api_request_plain` buffer.
- Removed the fallback that could build an application request from inside the
  TLS send path. A missing prepared request now fails instead of touching
  floppy during the fast window.
- First NE2K canary failed because `R` used phase-local string labels without
  rebasing them to the low-scratch load address. Fixed the phase-local string
  references to use `low_scratch_start + (label - PHASE_BASE)`.

Measurements:
- Resident sectors dropped from 48 to 47.
- Resident bytes when sector-rounded dropped from 24,576 to 24,064.
- `CORE.SYS` total size remains 28,672 bytes.
- Added one phase sector:
  - `P`: sector offset 47, one sector, load address `0x0700`.
  - `A`: sector offset 48, one sector, load address `0x0700`.
  - `U`: sector offset 49, two sectors, load address `0x0700`.
  - `Q`: sector offset 51, three sectors, load address `0x0700`.
  - `R`: sector offset 54, one sector, load address `0x0700`.
  - `S`: sector offset 55, one sector, load address `0x0700`.
- Phase table offset is 23,906 bytes into `CORE.SYS`.
- Gap to the guarded 24 KiB BASIC target is now roughly 5.0 KiB of resident
  code/data.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- Saved `USER.CFG` `vm-net-ne2k8` canary reaches `seed build 6` with `ok`.
- Saved `USER.CFG` `vm-net-3c501` canary reaches `seed build 6` with `ok`.

## 2026-05-07 - Remove temporary no-op phase

Change:
- Removed the temporary `N` no-op phase that only proved nonresident phase
  loading.
- Removed the associated startup phase probe, probe byte, service-vector slot,
  and `phase-noop.bin` build rule.
- Kept the real nonresident `S` save phase as the only phase entry.

Measurements:
- `CORE.SYS` total size dropped from 27,648 bytes to 27,136 bytes.
- Total sectors dropped from 54 to 53.
- Resident sectors remain 52.
- Resident bytes when sector-rounded remain 26,624.
- Phase table now has one entry:
  - `S`: sector offset 52, one sector, load address `0x0700`.
- Phase table offset is 26,492 bytes into `CORE.SYS`.
- Estimated `core_resident_end` is now image offset 26,502, leaving 122 bytes
  before the 52-sector resident boundary.
- This recovered about 59 resident bytes, so dropping to 51 resident sectors
  still needs roughly 390 more resident bytes moved or cut.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- No-card BIOS boot smoke reaches the expected red `. no network card` screen
  with the reserved loader clearing the BASIC-entry signature.
- The FAT root order is `CORE.SYS`, config files, `SEED24A.BAS`,
  `SEED24B.BAS`.
- `SEED24A.BAS` and `SEED24B.BAS` are generated at 635 bytes each.
- `make test` passes.

## 2026-05-07 - CORE.SYS container header scaffold

Change:
- Added a tiny `CORE.SYS` header at `0x1000`.
- The first instruction is still executable from the old loader entry point:
  it jumps over the header into the existing `start` label and preserves `DL`.
- Added `tools/core-sys-info.py` to parse and check the header.
- `make inspect` now prints the parsed header fields.
- The BASIC bootstrap build now reads `resident-sectors` from the `CORE.SYS`
  header instead of estimating from file size directly.
- For this scaffold checkpoint, `resident-sectors` still equals
  `total-sectors`; no phase is split out yet.

Measurements:
- Previous `CORE.SYS` size: 27,094 bytes.
- New `CORE.SYS` size: 27,119 bytes.
- Header size: 25 bytes.
- Resident sectors: 53.
- Resident bytes when sector-rounded: 27,136.
- Total sectors: 53.
- At the current 32 KiB stack guard, the rounded resident load reaches
  `0x7a00`, exactly the guard start. This is acceptable as a temporary bridge,
  but the next useful step must reduce `resident-sectors`.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- No-card BIOS boot smoke reaches the expected red `. no network card` screen.

## 2026-05-07 - Reserved loader uses resident-sector count

Change:
- Updated the reserved BIOS loader to read the first `CORE.SYS` sector,
  validate the `SEEDCORE` header, and then load only `resident-sectors` through
  the FAT12 cluster chain.
- Because `resident-sectors` still equals `total-sectors`, current runtime
  behavior remains a full-image load.
- Once the core is split, BIOS boot and BASIC boot will both load the same
  resident nucleus before jumping to `0000:1000`.

Measurements:
- Reserved loader still fits in the configured four-sector loader area.
- `CORE.SYS` remains 27,119 bytes.
- Resident sectors remain 53.

Verification:
- `make inspect` passes.
- `git diff --check` passes.
- No-card BIOS boot smoke reaches the expected red `. no network card` screen
  through the header-validating loader.

## 2026-05-07 - First runtime phase-load proof

Change:
- Factored the three fatal paths in `main.inc` through one shared
  `show_failure` routine.
- Added a one-sector no-op phase after the resident image inside `CORE.SYS`.
- Startup reads that no-op phase from the `CORE.SYS` container into low scratch
  and calls it.
- The phase writes a resident probe byte before returning; startup checks that
  byte before continuing.

Measurements:
- Failure-path factoring reduced the resident image by 52 bytes before adding
  the phase-load proof.
- `CORE.SYS` total size is now 27,648 bytes because it includes one extra
  sector outside the resident load.
- Resident sectors remain 53.
- Total sectors are now 54.
- This proves the container can hold a non-resident phase sector while both
  BIOS boot and BASIC boot still load only the resident sector count.

Verification:
- `make inspect` passes.
- `make test` passes.
- `git diff --check` passes.
- No-card BIOS boot smoke reaches the expected red `. no network card` screen
  after the startup phase-load probe.

## 2026-05-07 - Resident phase table

Change:
- Added the first resident phase-table entry.
- The current table has one entry:
  - id `N`
  - sector offset 53
  - sector count 1
  - load address `0x0700`
  - flags `0`
- Extended `tools/core-sys-info.py` to validate and print phase-table entries.

Measurements:
- `CORE.SYS` total size remains 27,648 bytes.
- Resident sectors remain 53.
- Total sectors remain 54.
- Phase table offset is 27,100 bytes into `CORE.SYS`.

Verification:
- `make inspect` passes and prints the `N` phase entry.
- `make test` passes.
- `git diff --check` passes.

## 2026-05-07 - Separately assembled phase and service vector

Change:
- Moved the no-op proof code into
  `targets/ibm_pc_5150/boot/phases/noop.asm`.
- The no-op phase is assembled for its runtime address, `0x0700`, then
  embedded as a sector-aligned nonresident `CORE.SYS` phase.
- Added a fixed low-memory phase service vector immediately after the handoff
  block at `0x062c`.
- The phase calls the probe service through that vector instead of directly
  calling resident labels. This validates the rule that phase code cannot rely
  on normal near calls into the resident image.

Measurements:
- `CORE.SYS` total size remains 27,648 bytes.
- Resident sectors remain 53.
- Total sectors remain 54.
- Phase table offset is 27,116 bytes into `CORE.SYS`.
- `core_resident_end` is at image offset `0x69f6`, leaving 10 bytes before the
  53-sector resident boundary.
- Dropping to 52 resident sectors requires moving or cutting about 502 bytes
  from the resident image.

Verification:
- `make inspect` passes and prints the `N` phase entry.
- `make test` passes.
- No-card BIOS boot smoke reaches the expected red `. no network card` screen
  after the separately assembled phase calls back through the service vector.

## 2026-05-07 - First resident sector cut and SAVE phase

Change:
- Removed the resident `USER.CFG` creation/write path and write-only FAT/root
  bookkeeping from the permanent image.
- Kept `USER.CFG`, `AGENTS.CFG`, and `NET.CFG` reads resident for now.
- Added a nonresident `S` phase after the no-op phase. The resident code loads
  it only after the provider response path has finished and only when
  `user_cfg_dirty` is set.
- The `S` phase updates an existing `USER.CFG` data cluster and root-directory
  size. It intentionally does not create `USER.CFG` when missing yet; missing
  persistence remains non-fatal and should be expanded later if product scope
  requires writes on a floppy without a shipped `USER.CFG`.

Measurements:
- Resident sectors dropped from 53 to 52.
- Resident bytes when sector-rounded dropped from 27,136 to 26,624.
- `CORE.SYS` total size is 27,648 bytes because it now contains two
  nonresident phase sectors.
- Phase table entries:
  - `N`: sector offset 52, one sector, load address `0x0700`.
  - `S`: sector offset 53, one sector, load address `0x0700`.
- `core_resident_end` is at image offset `0x67ad`, leaving 83 bytes before the
  52-sector resident boundary.
- The `S` phase code is 371 bytes and fits in one sector.

Verification:
- `make inspect` passes and prints both phase entries.
- `make test` passes.
- `git diff --check` passes.
- No-card BIOS boot smoke reaches the expected red `. no network card` screen.

Follow-up:
- The inline `S` phase uses explicit resident-call relocation because it is
  still assembled in the same NASM pass as the resident image. Before many
  larger phases are added, this needs to become a stricter phase ABI or a
  generated-symbol/link step so relocated calls cannot be used accidentally.

## 2026-05-07 - BASIC entry passes RAM ceiling

Change:
- Added a tiny BASIC-entry convention: the BASIC bootstrap passes
  `AX=SEED_RAM_TOP`, `BX=0x5345`, and `CX=0x4544` before jumping to
  `CORE.SYS`.
- The core checks that signature before setting its initial stack. BIOS boot
  keeps the normal `0x8000` stack top, while the 24 KiB BASIC path can use
  `0x6000`.
- The reserved BIOS loader explicitly clears `AX/BX/CX` before jumping so it
  cannot accidentally match the BASIC-entry signature.
- Extended the handoff block to publish the runtime RAM top.

Measurements:
- Resident sectors remain 52.
- `core_resident_end` is now at image offset `0x67c1`, leaving 63 bytes before
  the 52-sector resident boundary.
- BASIC loader programs grew from 635 bytes to 664 bytes.

Verification:
- `make inspect` passes.
