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
  `notes/24kb-windowed-design.md`.

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
