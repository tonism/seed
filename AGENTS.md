# AGENTS

> Operating instructions for coding agents and human contributors working **on**
> Seed — scope discipline, constraints, build/test, and release process. This is
> not documentation of Seed's AI-agent runtime; for that, start at the
> [README](README.md) and [docs/architecture.md](docs/architecture.md).

This project is still intentionally small. Keep changes scoped to the milestone
the user is asking for, and prefer preserving the current shape over adding
general OS infrastructure early.

## Documentation style

- Product docs describe current capability and are version-independent.
- Build and version numbers appear only in `docs/builds.md` (the roadmap).
- The runtime splash number is the one exception, since it shows the build.

## Current Context

Seed is a boot-first agent runtime experiment. The active implementation target
is an IBM PC 5150-class FAT12 boot floppy in:

```text
targets/ibm_pc_5150/
```

The current boot artifact is:

```text
build/ibm_pc_5150/floppy-160k.img
```

The Seed boot core source is split into NASM include files under:

```text
targets/ibm_pc_5150/boot/core/
```

This is source organization only. The build emits one flat file-backed
`SEED.SYS` runtime plus one-sector NIC driver files under `SEED/DRIVERS/`.
Do not introduce other runtime module loading unless explicitly scoped.

That image is a 160 KiB FAT12 floppy image with a stage 1 boot sector, a small
reserved-sector FAT12 loader, FAT copies, a root directory, and file data. The
loader reads the visible root `SEED.SYS` file's declared resident prefix
through its FAT12 cluster chain and jumps to it at `0000:1000`. Runtime
configuration and prompt files are shipped under the root `SEED/` directory.
TLS 1.3 trust objects are immutable program assets or same-boot RAM state:
the 8088 profile uses an exact image-dated leaf point (with no
trusted runtime clock at that floor) and the 286
conforming route uses the baked WE1 P-256 issuer point. Do not package
`SEED/LEAF.DER` or make writable media part of either trust path. The tracked
`AGENTS.CFG` file is shipped as `SEED/AGENTS.CFG` when present; OpenAI at
`api.openai.com` is the only current provider route. Optional `USER.CFG`
user-local state is ignored and included as `SEED/USER.CFG` only when
`config/USER.CFG` exists. NIC driver files are shipped as `SEED/DRIVERS/*.DRV` by default; build
with `INCLUDE_NIC_DRIVERS=0` or per-driver `INCLUDE_NIC_DRIVER_*` switches to
produce a floppy without some or all drivers. Runtime driver loading must scan
the shipped `.DRV` files, select a suitable driver by metadata, ask if multiple
drivers suit the detected adapter, and fail through the normal retry/restart
path when no suitable driver is present. The build may also generate
ROM BASIC bootstrap sidecar text under `build/ibm_pc_5150/` for sub-32 KiB
entry. Do not package those BASIC helpers into the release floppy FAT root
unless explicitly scoped; keep `SEED.SYS` as the first FAT data file so both
the boot loader and the BASIC loader can find the same runtime image.

## Constraints

- Keep the stage 1 boot sector within 512 bytes, including the `55 aa`
  signature.
- Keep the reserved loader within `LOADER_SECTORS` in `Makefile`. The current
  four-sector loader occupies sectors 2-5 and loads `SEED.SYS` as a normal
  FAT12 root file. Stage 1 loads the reserved loader one sector at a time with
  CHS rollover. Keep loader buffers outside the `SEED.SYS` load range; the
  loader currently keeps its FAT buffer at `0x0e00` and uses a `0x8000` stack
  top for 32 KiB machines.
- For sub-32 KiB work, keep the normal boot path available for larger
  machines and add the 16 KiB entry through BASIC helpers instead. The BIOS
  boot sector at `0000:7c00` is above the installed RAM ceiling on 24 KiB and
  16 KiB machines.
- Target 8088-compatible 16-bit real-mode code for `ibm_pc_5150`. Keep NASM
  sources locked to `cpu 8086` so unsupported opcodes are caught at build time.
- Do not introduce protected mode or graphics mode unless explicitly scoped.
- The current capability is the Default Prompt Interface chat loop, a
  model-compacted rolling conversation window, Responses native RAM
  read/write/execute tools with an agentic loop, and optional environment
  save/load on writable media, on the 16 KiB ROM BASIC + 32 KiB direct-boot
  entry contract. Keep tool access target-local and preserve the current ENV
  compatibility contract; do not introduce a general OS-style local-tool ABI
  unless explicitly scoped.
- OpenAI at `api.openai.com` is the supported agent TLS compatibility surface.
  The bounded `AGENTS.CFG` parser may retain its multi-entry format, but
  alternate providers/endpoints must not select another crypto path.
- TLS 1.2 is not a product fallback. Keep the 8088 TLS 1.3 boundary
  and the 286/512 KiB fully conforming `X25519MLKEM768` route explicit; never
  describe the former as standards-conforming hybrid TLS.
- Both TLS routes must remain self-contained on the target and work with a
  write-protected floppy. Do not depend on a trusted modern helper, persisted
  private key, writable scratch slot, or mutable leaf file.
- TLS state belongs only in conventional system RAM. Video RAM is exclusively
  display state and adapter RAM is exclusively device state; neither may be a
  crypto vault, escrow, scratch area, or warm-restart scrub target.
- 3c501, 3c503, NE1000/NE2000, and WD80x3 station-address PROM reads must stay
  non-fatal.
- The current first packet path covers the
  5150 3c501, 3c503, NE1000/NE2000, and WD80x3 families; keep later NIC
  expansion target-scoped.
- Do not switch video modes on the current target. Keep the BIOS-provided text
  mode and use the detected column count for layout.
- Keep the IBM PC 5150 runtime handoff block at `0000:0600` compatible with
  `targets/ibm_pc_5150/HANDOFF.md`.
- Keep the cursor hidden unless an input field is actively accepting text.
- Use BIOS text services for current display output.
- Avoid BIOS bell for notifications. Use low PC speaker tones through PIT
  channel 2.
- Treat persisted user config as optional. Missing or bad config means ask;
  failed writes mean continue without storing.

## UI Rules

Follow `docs/ui.md`.

User-visible text should appear through the fast-type path:

```text
success text
error messages
questions
menu labels
modal text
field labels
button labels
```

Small status markers may appear immediately because they represent state.
The marker-state table is documented once in [docs/ui.md](docs/ui.md).

Fatal errors should turn the current marker red, play the low failure tone,
fast-type the error text, then offer `retry` and `restart`. Retry should return
to the dark `"."` hardware phase without rereading floppy sectors; restart
should perform a warm machine restart. Questions should use the low attention
tone and fast-type the prompt. Menus indicate selection by color rather than
marker glyphs.

## Build And Test

Build:

```sh
make
```

Inspect:

```sh
make inspect
```

Generate the ROM BASIC sidecar helpers:

```sh
make basic-bootstrap
```

Run default no-card VM:

```sh
tools/run-86box.sh
```

Run a NIC-present VM:

```sh
tools/run-86box.sh vm-net-ne2k8
```

Run the ROM BASIC sidecar harness:

```sh
tools/run-basic-bootstrap-86box.py --profile vm-net-ne2k8
```

Boot modes (16 KiB ROM BASIC sidecar vs 32 KiB direct-from-A:), harness flags,
validation recipes, pcap wire capture (and isolating seed's traffic from the
SLiRP-NATed host noise), and the OCR/cfg/screenshot gotchas live in
`docs/testing.md`.

Useful expected screens and acceptance rules:

The existing TLS 1.2 original-speed results are regression history, not the
current product claim. The TLS 1.3 integration is under validation. Do not
update product docs from an offline gate or earlier PoC alone.

For the 8088 floor, use the original 4.77 MHz, exactly 16 KiB
`vm-net-ne2k8` profile through the ROM BASIC sidecar harness. Acceptance needs
a live pcap showing the fresh TLS 1.3 deadline phase, credential-free liveness,
full FO and exact-leaf/CV proof, status-last credential unlock, authenticated
OpenAI response, session reuse, and the bounded one-reconnect policy. Then
repeat the relevant first-response/reuse/reconnect gates across the seven
original-speed ISA NIC profiles. Conventional-RAM lifetime guards, read-only
media, corruption/torn-state cases, and complete zeroization are mandatory.
Video and adapter RAM must remain unchanged outside their ordinary display and
device operations.

For the conforming floor, use a 6 MHz 286 with 512 KiB conventional RAM. The
gate is CPU286+ AND BDA memory >=512 KiB. Acceptance needs a live pcap of the
acquisition/offline-auth/independent-fresh-connection sequence, genuine
ML-KEM-768 and X25519, WE1/hostname/UTC-validity/CV checks, client Finished
before the provider close, authenticated OpenAI application data, reuse, and
bounded reconnect. Exercise wrong CPU/RAM, RTC refusal/bad time, certificate,
CV, Finished, FO, pack, and entropy failures with no downgrade.

Run all current TLS 1.3 offline gates before live claims, including the exact
RAM-only product pack/composition, dispatch/config guards, application record
bounds, existing-read sampler, cold send, FAT budget, reconnect/replay, 286
module KATs and serialized timing. Physical characterization of PIT samples
attached to already-required 8088 floppy reads remains a separate secure-floor
gate; 86Box receives zero entropy credit.

Stable driver/NIC work remains a regression surface. A TLS change must not
alter driver metadata, selection, PROM-read non-fatal behavior, station MAC,
DHCP/DNS/ARP/TCP, or the established no-card/no-driver retry/restart paths.
Retest individual profiles whenever shared packet, timing, phase loading, or
TLS application code changes.

## Commits

**Ask before every commit** — do not commit on your own initiative, not even tested-and-working
code. At a validated checkpoint, present what is done + its validation + a proposed message, and
wait for the maintainer's go. Unprompted commits, however clean, are the failure mode this section
exists to prevent.

A commit must be a **working checkpoint** — never a broken or mid-refactor state. Working means the
build is green (`make` succeeds, fresh `SEED.SYS`) **and** the change is validated for what it
touches: the relevant target boots and greets, or its offline gate passes (a crypto eval,
`tools/check-layout.py`, the X.509 tamper matrix). If you cannot show it works, it is not a
checkpoint — keep iterating or stash, but do not commit it.

- One commit per coherent change, not per edit. No "increment A / B / C" chains and no
  "fix the previous commit" commits — fold them into the one meaningful unit.
- Revert diagnostic scaffolding first (debug markers, short-circuit patches, a deliberately
  wrong test pin): commit the fix, not the investigation.
- Do not push unless the maintainer explicitly asks for a push. Local commits
  accumulate on the work branch until then; when asked, push only the requested
  branch or ref.

## Release

Releasing is a git convention, not a build artifact:

1. Fast-forward `main` to the release branch tip. `main` stays linear (no merge
   commits), so it is fast-forward-only, never a merge. If `main` is checked out in
   a worktree, fast-forward via `git push origin HEAD:main`, then sync the local ref.
2. Annotated tag `build-N`, message `Build N <description>`, on `main`'s tip; push
   the tag.
3. Prune superseded work branches (local + remote) down to just `main`. Inspect
   each first (`git rev-list --count main..<branch>` and its worktree state) and
   confirm before deleting any branch that still carries unmerged commits or a live
   worktree.

The build stamp is `build_number equ N` in
`targets/ibm_pc_5150/boot/core/layout.inc`; `docs/builds.md` keeps the milestone
history.

## Documentation

Keep root `README.md` high level. Put target-specific boot and emulator details
under `targets/ibm_pc_5150/`.

Important docs:

```text
README.md
docs/architecture.md
docs/builds.md
docs/config.md
docs/testing.md
docs/ui.md
targets/ibm_pc_5150/README.md
targets/ibm_pc_5150/HANDOFF.md
targets/ibm_pc_5150/86box/README.md
targets/ibm_pc_5150/86box/NICS.md
```

When a behavior becomes a project rule, document it in `docs/` and link target
docs to it instead of duplicating long explanations.
