# IBM PC 5150 Target

This target is the first Seed discipline target: an original IBM PC-class boot
path, starting from a 160 KiB 5.25-inch single-sided floppy image.

Current milestone:

```text
BIOS loads boot sector
  -> reads the current BIOS text-mode column count
  -> boot sector clears text mode
  -> shows the phase-one load marker at the centered project start column
  -> probes common ISA network card I/O bases
  -> shows + no network card and plays a low failure tone if no card responds
  -> otherwise types seed build 3 rightward from that column
  -> waits about 500 ms
  -> halts
```

The floppy image is intentionally not a filesystem. It contains no files:

```text
sector 1    boot sector
sector 2+   zero-filled padding
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

Build 3 treats phase one as network hardware discovery. The current boot sector
probes common ISA Ethernet I/O bases and stops at a minimal error if no card
responds. This is intentionally a hardware-presence check only; packet I/O,
IP, TLS, and model API calls are later milestones.

The boot sector does not switch video modes. It keeps the BIOS-provided text
mode, reads the active column count, and uses that value for clearing and for
the centered project-name anchor.

The first screen text is hardcoded in the boot sector for now:

```text
phase one       " "
failure         +, low descending PC speaker tone, fast-typed no network card
question        low PC speaker attention tone, fast-typed prompt
success         " " -> "." -> "o" -> seed build 3
```

Default display attributes:

```text
seed       CGA white / MDA bright
build 3    CGA dark gray / MDA normal
error      CGA red / MDA bright
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
