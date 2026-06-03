# AGENTS

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
`CORE.SYS` runtime; do not introduce additional runtime module loading unless
explicitly scoped.

That image is a 160 KiB FAT12 floppy image with a stage 1 boot sector, a small
reserved-sector FAT12 loader, FAT copies, a root directory, and file data. The
loader reads the visible root `CORE.SYS` file through its FAT12 cluster chain
and jumps to it at `0000:1000`. The tracked `AGENTS.CFG` and `NET.CFG` files
are shipped in the root directory when present. `AGENTS.CFG` overrides built-in
`openai`, `anthropic`, and `google` agent interfaces; `NET.CFG` overrides the
built-in `example.com` probe. Optional `USER.CFG` user-local state is ignored
and included only when `config/USER.CFG` exists. The build may also generate
ROM BASIC bootstrap sidecar text under `build/ibm_pc_5150/` for sub-32 KiB
entry. Do not package those BASIC helpers into the release floppy FAT root
unless explicitly scoped; keep `CORE.SYS` as the first FAT data file so both
the boot loader and the BASIC loader can find the same runtime image.

## Constraints

- Keep the stage 1 boot sector within 512 bytes, including the `55 aa`
  signature.
- Keep the reserved loader within `LOADER_SECTORS` in `Makefile`. The current
  four-sector loader occupies sectors 2-5 and loads `CORE.SYS` as a normal
  FAT12 root file. Stage 1 loads the reserved loader one sector at a time with
  CHS rollover. Keep loader buffers outside the `CORE.SYS` load range; the
  loader currently keeps its FAT buffer at `0x0e00` and uses a `0x8000` stack
  top for 32 KiB machines.
- For sub-32 KiB work, keep the normal boot path available for larger
  machines and add the 16 KiB entry through BASIC helpers instead. The BIOS
  boot sector at `0000:7c00` is above the installed RAM ceiling on 24 KiB and
  16 KiB machines.
- Target 8088-compatible 16-bit real-mode code for `ibm_pc_5150`. Keep NASM
  sources locked to `cpu 8086` so unsupported opcodes are caught at build time.
- Do not introduce protected mode or graphics mode unless explicitly scoped.
- The current capability is the Default Prompt Interface chat loop on the
  16 KiB ROM BASIC entry, built on the secure-connection + 16 KiB contract.
  It is feature-complete and validated; do not add context management, tool
  calling, or environment handover unless explicitly scoped.
- OpenAI, Anthropic, and Google define the supported agent TLS compatibility
  surface. Extra default `AGENTS.CFG` entries may stay only if they fit the
  same path; do not add alternate crypto paths just to keep a gateway.
- 3c501, 3c503, NE1000/NE2000, and WD8003 station-address PROM reads must stay
  non-fatal.
- The current first packet path covers the
  5150 3c501, 3c503, NE1000/NE2000, and WD8003 families; keep later NIC
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

Small status markers may appear immediately because they represent state:

```text
none         boot sector, loader, CORE.SYS load
"." dark     hardware, local machine setup, and internet prep/reachability
"o" dark     secure connection setup
"o" normal   local TLS crypto/key material setup
"o" bright   agent and environment prep
red marker   fatal error state; keep the current phase glyph
```

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

Useful expected screens:

The 16 KiB checkpoint for these IBM PC 5150 profiles is expected
to use saved `USER.CFG` when present. Use original 4.77 MHz, 16 KiB
`vm-net-ne2k8` through the ROM BASIC sidecar harness as the compatibility gate.
Faster ad hoc profiles are not part of the normal workflow. On 1 May 2026, all seven original-speed NIC profiles
completed the minimal direct OpenAI Responses request/response proof and
displayed the returned `ok`: `vm-net-3c501`, `vm-net-3c503`, `vm-net-ne1k`,
`vm-net-ne2k8`, `vm-net-novell-ne1k`, `vm-net-wd8003e`, and
`vm-net-wd8003eb`. On 7 May 2026, the 32 KiB slimming checkpoint passed
representative family tests on `vm-net-ne2k8`, `vm-net-3c501`,
`vm-net-3c503`, and `vm-net-wd8003e`, each displaying returned `ok` and
`seed build 6`. On 10 May 2026, the Build 7 ROM BASIC sidecar path reached
returned `ok` on all seven 16 KiB NIC profiles: `vm-net-3c501`,
`vm-net-3c503`, `vm-net-ne1k`, `vm-net-ne2k8`, `vm-net-novell-ne1k`,
`vm-net-wd8003e`, and `vm-net-wd8003eb`; the no-card CGA and MDA profiles
failed cleanly with no NIC.
Retest individual profiles when changing TLS timing/shared packet code.
The current runtime provides FAT12 `AGENTS.CFG` and `NET.CFG` parsing, built-in
fallback agent interfaces, optional `USER.CFG` persistence for selected
agent/model/reasoning/key/endpoint values, with `server?` shown for LiteLLM's
stored endpoint value on the same form panel as `key?`, selected-agent DNS/TCP
443 connection, minimal TLS 1.2 ClientHello with SNI offering only P-256
ECDHE-ECDSA-CHACHA20-POLY1305 without extended master secret for the current
crypto path, ServerHello proof with
parsed version, random, cipher-suite, session-id, extension flags, and selected
cipher path, Certificate handshake
header parsing and draining, ServerKeyExchange header parsing with
uncompressed P-256 public-point capture, 16-bit field-word conversion and
coordinate range checks, P-256 field add/sub/mul/reduction helpers, P-256
public-point curve-equation validation in the dependency-free checker, P-256
Jacobian point double and mixed-add helpers, P-256 scalar multiplication helper
for mixed affine points
with leading-zero skip, ServerHelloDone proof, live SHA-256 TLS handshake
transcript context through ServerHelloDone, sparse fixed-scalar ECDHE
shared-point generation, Jacobian shared point conversion into the affine
X-coordinate pre-master secret, TLS 1.2 SHA-256 PRF key schedule deriving the
master secret and ChaCha20-Poly1305 client/server write keys and IVs,
prepared HMAC-SHA256 states for repeated PRF calls,
fixed-scalar ClientKeyExchange transmit with live transcript update,
ChangeCipherSpec + encrypted client Finished transmit, encrypted server
Finished authentication/decryption/verify_data check, early TLS
application-data send/receive carrying the Default Prompt Interface chat loop
(model greeting, prompt input, and streamed multi-turn responses in one boot
session) on all seven original-speed NIC profiles, and
bright questions when
saved values are missing or invalid; retest individual profiles when changing
boot, filesystem, agent-prep code, or shared packet code.

```text
vm                   red "." no network card, retry/restart menu
vm-mda               red "." no network card, retry/restart menu
vm-net-3c501         auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, application data, Default Prompt Interface chat loop (model greeting, prompt input, streamed multi-turn responses), then splash
vm-net-3c503         MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, application data, Default Prompt Interface chat loop (model greeting, prompt input, streamed multi-turn responses), then splash
vm-net-ne1k          auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, application data, Default Prompt Interface chat loop (model greeting, prompt input, streamed multi-turn responses), then splash
vm-net-ne2k8         auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, application data, Default Prompt Interface chat loop (model greeting, prompt input, streamed multi-turn responses), then splash
vm-net-novell-ne1k   auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, application data, Default Prompt Interface chat loop (model greeting, prompt input, streamed multi-turn responses), then splash
vm-net-wd8003e       auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, application data, Default Prompt Interface chat loop (model greeting, prompt input, streamed multi-turn responses), then splash
vm-net-wd8003eb      auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, application data, Default Prompt Interface chat loop (model greeting, prompt input, streamed multi-turn responses), then splash
```

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
docs/ui.md
targets/ibm_pc_5150/README.md
targets/ibm_pc_5150/HANDOFF.md
targets/ibm_pc_5150/86box/README.md
targets/ibm_pc_5150/86box/NICS.md
```

When a behavior becomes a project rule, document it in `docs/` and link target
docs to it instead of duplicating long explanations.
