# IBM PC 5150 Target

This target is the first Seed discipline target: an original IBM PC-class boot
path, starting from a 160 KiB 5.25-inch single-sided floppy image.

Current milestone:

```text
BIOS loads boot sector
  -> stage 1 loads the fixed-sector stage 2 boot core
  -> stage 2 reads the current BIOS text-mode column count
  -> stage 2 clears text mode
  -> shows the phase-one load marker at the centered project start column
  -> probes common ISA network card I/O bases
  -> records the responding NIC I/O base if one is found
  -> shows + no network card and plays a low failure tone if no card responds
  -> asks for adapter family when the responding I/O base is ambiguous
  -> otherwise types seed build 4 rightward from that column
  -> waits about 500 ms
  -> halts
```

The floppy image is intentionally not a filesystem. It contains no files:

```text
sector 1      stage 1 boot sector
sectors 2-5   stage 2 boot core
sector 6+     zero-filled padding
```

Optional persisted user config is a later environment feature, not a dependency
of this raw boot sector. The project-level policy is documented in:

```text
docs/config.md
```

Text UI behavior, including fast-typed errors, questions, menus, and modals, is
documented in:

```text
docs/ui.md
```

Build 4 introduces a fixed-sector stage 2 boot core and treats phase one as
network hardware discovery. Stage 2 probes common ISA Ethernet I/O bases, stores
the responding I/O base as in-memory network config, and starts resolving an
adapter family. Known single-card bases continue automatically. Shared bases ask
the user to choose the adapter family through a minimal color-selected menu.
This is intentionally still a hardware/config handoff only; packet I/O, IP,
TLS, and model API calls are later milestones.

The boot path does not switch video modes. It keeps the BIOS-provided text
mode, reads the active column count, and uses that value for clearing and for
the centered project-name anchor.

The first screen text is hardcoded in the boot sector for now:

```text
phase one       " "
failure         +, low descending PC speaker tone, fast-typed no network card
question        low PC speaker attention tone, fast-typed prompt
success         " " -> "." -> "o" -> seed build 4
```

Build 4 adapter prompts:

```text
0x250       auto 3c503
0x280       ask 3c501 or wd8003
0x300       ask ne2000 or ne1000
other base  keep base only
```

Default display attributes:

```text
seed       CGA white / MDA bright
build 4    CGA dark gray / MDA normal
error      CGA red / MDA bright
menu       selected white/bright, inactive dark gray/normal
```

Build:

```sh
make
```

Output:

```text
build/ibm_pc_5150/floppy-160k.img
```

Inspect the generated raw image:

```sh
make inspect
```
