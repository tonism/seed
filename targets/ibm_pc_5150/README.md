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
  -> publishes boot, video, and NIC state to the handoff block at 0000:0600
  -> shows + no network card and plays a low failure tone if no card responds
  -> asks for adapter family when the responding I/O base is ambiguous
  -> records the current 86Box profile IRQ after adapter family resolution
  -> reads station-address PROMs into handoff when valid
  -> initializes NE1000/NE2000-family packet hardware
  -> reads one NE1000/NE2000-family pending receive-ring frame when available
  -> sends one NE1000/NE2000-family DHCPDISCOVER
  -> otherwise types seed build 5 rightward from that column
  -> waits about 500 ms
  -> halts
```

The floppy image is intentionally not a filesystem. It contains no files:

```text
sector 1      stage 1 boot sector
sectors 2-8   stage 2 boot core
sector 9+     zero-filled padding
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

The stage 2 runtime handoff block is documented in:

```text
targets/ibm_pc_5150/HANDOFF.md
```

Build 5 is the internet-readiness milestone. Stage 2 still probes common ISA
Ethernet I/O bases, publishes boot/video/NIC state to a low-memory handoff
block, and resolves the adapter family. Known single-card bases continue
automatically. Shared bases ask the user to choose the adapter family through a
minimal color-selected menu. For 3c501, 3c503, NE1000/NE2000-family, and
WD8003-family cards, stage 2 reads the station-address PROM and marks the MAC
valid only after rejecting multicast, all-zero, and all-`ff` addresses. Stage 2
also records IRQ 3 for the current 86Box IBM PC 5150 profiles once the adapter
family is known; real IRQ discovery is later scope.

The current build 5 checkpoint initializes NE1000/NE2000-family packet hardware
after a valid MAC read, polls the receive-ring pointers, reads one pending
receive frame when available, sends a minimal DHCPDISCOVER, and records that
readiness in the handoff block. DHCP offer parsing, DNS, and outbound
reachability remain in build 5 scope but are not implemented yet.

The boot path does not switch video modes. It keeps the BIOS-provided text
mode, reads the active column count, and uses that value for clearing and for
the centered project-name anchor.

The first screen text is hardcoded in the boot sector for now:

```text
phase one       " "
failure         +, low descending PC speaker tone, fast-typed no network card
question        low PC speaker attention tone, fast-typed prompt
success         " " -> "." -> "o" -> seed build 5
```

Adapter prompts:

```text
0x250       auto 3c503
0x280       ask 3c501 or wd8003
0x300       ask ne2000 or ne1000
other base  keep base only
```

Default display attributes:

```text
seed       CGA white / MDA bright
build 5    CGA dark gray / MDA normal
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
