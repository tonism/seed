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
- Keep stage 2 within the fixed sector count declared in `Makefile`.
- Target 8088-compatible 16-bit real-mode code for `ibm_pc_5150`.
- Do not introduce protected mode, graphics mode, a filesystem, config parsing,
  packet I/O, IP, TLS, or model API logic unless explicitly scoped.
- NE1000/NE2000 station-address PROM reads are allowed in build 4, but must stay
  non-fatal and must not grow into packet I/O.
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

Fatal errors should switch the marker first, play the low failure tone, then
fast-type the error text. Questions should use the low attention tone and
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
vm                   + no network card
vm-mda               + no network card
vm-net-3c503         seed build 4
vm-net-ne2k8         adapter prompt, MAC read, then seed build 4 after Enter
```

## Documentation

Keep root `README.md` high level. Put target-specific boot and emulator details
under `targets/ibm_pc_5150/`.

Important docs:

```text
README.md
docs/config.md
docs/ui.md
targets/ibm_pc_5150/README.md
targets/ibm_pc_5150/HANDOFF.md
targets/ibm_pc_5150/86box/README.md
targets/ibm_pc_5150/86box/NICS.md
```

When a behavior becomes a project rule, document it in `docs/` and link target
docs to it instead of duplicating long explanations.
