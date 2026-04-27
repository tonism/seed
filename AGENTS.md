# AGENTS

This project is still intentionally small. Keep changes scoped to the milestone
the user is asking for, and prefer preserving the current shape over adding
general OS infrastructure early.

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

That image is a 160 KiB FAT12 floppy image with a stage 1 boot sector, fixed
reserved stage 2 sectors, FAT copies, a root directory, and file data. The
tracked `AGENTS.CFG` and `NET.CFG` files are shipped in the root directory when
present. `AGENTS.CFG` overrides built-in `openai`, `anthropic`, and `google`
agent interfaces; `NET.CFG` overrides the built-in `example.com` probe.
Optional `SEED.CFG` user-local state is ignored and included only when
`config/SEED.CFG` exists.

## Constraints

- Keep the stage 1 boot sector within 512 bytes, including the `55 aa`
  signature.
- Keep stage 2 within the fixed sector count declared in `Makefile`. The
  current twenty-four-sector stage 2 spans sectors 2-8 on the first 160 KiB
  floppy track, all of tracks 1 and 2, and track 3 sector 1. Stage 1 loads one
  sector at a time with CHS rollover.
- Target 8088-compatible 16-bit real-mode code for `ibm_pc_5150`. Keep NASM
  sources locked to `cpu 8086` so unsupported opcodes are caught at build time.
- Do not introduce protected mode or graphics mode unless explicitly scoped.
- Keep Build 6 focused on agent prep. Do not add TLS, model API requests,
  agent sessions, or environment handover beyond the current Build 6 step
  unless explicitly scoped.
- 3c501, 3c503, NE1000/NE2000, and WD8003 station-address PROM reads must stay
  non-fatal.
- Build 5 owns internet readiness. The current first packet path covers the
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
" "          project init
"." dark     HAL setup
"o" dark     internet prep
"o" bright   agent prep
red marker   fatal error state; keep the current phase glyph
```

Fatal errors should turn the current marker red, play the low failure tone,
fast-type the error text, then offer `retry` and `restart`. Retry should return
to the dark `"."` HAL setup phase without rereading floppy sectors; restart
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

Run default no-card VM:

```sh
tools/run-86box.sh
```

Run a NIC-present VM:

```sh
tools/run-86box.sh vm-net-ne2k8
```

Useful expected screens:

The Build 6 internet-proof checkpoint for these IBM PC 5150 profiles was
validated on 27 April 2026 with `SEED.CFG` excluded from the test floppy. Build
6 currently adds FAT12 `AGENTS.CFG` and `NET.CFG` parsing, built-in fallback
agent interfaces, optional `SEED.CFG` persistence for selected
agent/model/reasoning/key/endpoint values, with `server?` shown for LiteLLM's
stored endpoint value on the same form panel as `key?`, selected-agent DNS/TCP
443 reachability, and bright questions when saved values are missing or
invalid; retest individual profiles when changing boot, filesystem, agent-prep
code, or shared packet code.

```text
vm                   red "." no network card, retry/restart menu
vm-mda               red "." no network card, retry/restart menu
vm-net-3c501         adapter prompt, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP SYN-ACK, then agent?
vm-net-3c503         MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP SYN-ACK, then agent?
vm-net-ne1k          adapter prompt, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP SYN-ACK, then agent?
vm-net-ne2k8         adapter prompt, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP SYN-ACK, then agent?
vm-net-novell-ne1k   adapter prompt, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP SYN-ACK, then agent?
vm-net-wd8003e       adapter prompt, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP SYN-ACK, then agent?
vm-net-wd8003eb      adapter prompt, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP SYN-ACK, then agent?
```

## Documentation

Keep root `README.md` high level. Put target-specific boot and emulator details
under `targets/ibm_pc_5150/`.

Important docs:

```text
README.md
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
