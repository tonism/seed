# AGENTS

This project is still intentionally small. Keep changes scoped to the milestone
the user is asking for, and prefer preserving the current shape over adding
general OS infrastructure early.

## Current Context

Seed is a boot-first agent runtime experiment. The active implementation target
is an IBM PC 5150-class raw boot floppy in:

```text
targets/ibm_pc_5150/
```

The current boot artifact is:

```text
build/ibm_pc_5150/floppy-160k.img
```

That image is a raw 160 KiB floppy image with a stage 1 boot sector, fixed
stage 2 sectors, and zero-filled padding. It is not a DOS filesystem and
contains no files.

## Constraints

- Keep the stage 1 boot sector within 512 bytes, including the `55 aa`
  signature.
- Keep stage 2 within the fixed sector count declared in `Makefile`. The
  current seven-sector stage 2 fits sectors 2-8 on the first 160 KiB floppy
  track; going past seven sectors requires a stage 1 multi-track loader.
- Target 8088-compatible 16-bit real-mode code for `ibm_pc_5150`.
- Do not introduce protected mode, graphics mode, a filesystem, config parsing,
  packet I/O, IP, TLS, or model API logic unless explicitly scoped.
- 3c501, 3c503, NE1000/NE2000, and WD8003 station-address PROM reads must stay
  non-fatal.
- Build 5 owns internet readiness. Keep its first packet path focused on
  NE1000/NE2000-family cards before expanding to other NIC families.
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
" "   active phase below 33%
"."   active phase from 33% to 66%
"o"   active phase above 66%
"+"   fatal error marker
```

Fatal errors should switch the marker first, play the low failure tone,
fast-type the error text, then offer `retry` and `restart`. Retry should rerun
stage 2 from its start without rereading floppy sectors; restart should perform
a warm machine restart. Questions should use the low attention tone and
fast-type the prompt. Menus indicate selection by color rather than marker
glyphs.

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

```text
vm                   + no network card, retry/restart menu
vm-mda               + no network card, retry/restart menu
vm-net-3c501         adapter prompt, MAC read, then seed build 5 after Enter
vm-net-3c503         MAC read, then seed build 5
vm-net-ne1k          adapter prompt, MAC read, RX read check, DHCPDISCOVER, then seed build 5 after Down/Enter
vm-net-ne2k8         adapter prompt, MAC read, RX read check, DHCPDISCOVER, then seed build 5 after Enter
vm-net-novell-ne1k   adapter prompt, MAC read, RX read check, DHCPDISCOVER, then seed build 5 after Down/Enter
vm-net-wd8003e       adapter prompt, MAC read, then seed build 5 after Down/Enter
vm-net-wd8003eb      adapter prompt, MAC read, then seed build 5 after Down/Enter
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
