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
and included only when `config/USER.CFG` exists.

## Constraints

- Keep the stage 1 boot sector within 512 bytes, including the `55 aa`
  signature.
- Keep the reserved loader within `LOADER_SECTORS` in `Makefile`. The current
  four-sector loader occupies sectors 2-5 and loads `CORE.SYS` as a normal
  FAT12 root file. Stage 1 loads the reserved loader one sector at a time with
  CHS rollover.
- Target 8088-compatible 16-bit real-mode code for `ibm_pc_5150`. Keep NASM
  sources locked to `cpu 8086` so unsupported opcodes are caught at build time.
- Do not introduce protected mode or graphics mode unless explicitly scoped.
- Keep Build 6 focused on agent prep. Do not add TLS, model API requests,
  agent sessions, or environment handover beyond the current Build 6 step
  unless explicitly scoped.
- OpenAI, Anthropic, and Google define the supported agent TLS compatibility
  surface. Extra default `AGENTS.CFG` entries may stay only if they fit the
  same path; do not add alternate crypto paths just to keep a gateway.
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
validated on 28 April 2026 with saved `USER.CFG` included in the test floppy.
Build 6 currently adds FAT12 `AGENTS.CFG` and `NET.CFG` parsing, built-in
fallback agent interfaces, optional `USER.CFG` persistence for selected
agent/model/reasoning/key/endpoint values, with `server?` shown for LiteLLM's
stored endpoint value on the same form panel as `key?`, selected-agent DNS/TCP
443 connection, minimal TLS 1.2 ClientHello with SNI offering only P-256
ECDHE-RSA-CHACHA20-POLY1305 for the current crypto path, ServerHello proof with
parsed version, random, cipher-suite, session-id, extension flags, and selected
cipher path, Certificate handshake
header parsing and draining, ServerKeyExchange header parsing with
uncompressed P-256 public-point capture, 16-bit field-word conversion and
coordinate range checks, ServerHelloDone proof, live SHA-256 TLS handshake
transcript context through ServerHelloDone, and bright questions when saved
values are missing or invalid; retest individual profiles when changing boot,
filesystem, agent-prep code, or shared packet code.

```text
vm                   red "." no network card, retry/restart menu
vm-mda               red "." no network card, retry/restart menu
vm-net-3c501         auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, then agent?
vm-net-3c503         MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, then agent?
vm-net-ne1k          auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, then agent?
vm-net-ne2k8         auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, then agent?
vm-net-novell-ne1k   auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, then agent?
vm-net-wd8003e       auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, then agent?
vm-net-wd8003eb      auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, then agent?
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
