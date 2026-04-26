# 86Box Harness Notes

86Box is installed on this machine through Homebrew Cask, with the official
86Box ROM repository cloned to:

```text
~/Library/Application Support/net.86box.86Box/roms
```

The default no-network VM lives at:

```text
targets/ibm_pc_5150/86box/vm/86box.cfg
```

The MDA no-network VM lives at:

```text
targets/ibm_pc_5150/86box/vm-mda/86box.cfg
```

Networked success-profile VMs live beside those profiles:

```text
targets/ibm_pc_5150/86box/vm-net-3c501/86box.cfg
targets/ibm_pc_5150/86box/vm-net-3c503/86box.cfg
targets/ibm_pc_5150/86box/vm-net-ne1k/86box.cfg
targets/ibm_pc_5150/86box/vm-net-ne2k8/86box.cfg
targets/ibm_pc_5150/86box/vm-net-novell-ne1k/86box.cfg
targets/ibm_pc_5150/86box/vm-net-wd8003e/86box.cfg
targets/ibm_pc_5150/86box/vm-net-wd8003eb/86box.cfg
```

Current CGA machine shape:

```text
Machine: IBM PC 5150
CPU:     8088, 4.77 MHz
RAM:     64 KiB
Video:   CGA
FDC:     XT floppy controller
Floppy:  5.25" single-sided drive as A:
Disk A:  build/ibm_pc_5150/floppy-160k.img
```

The 86Box NIC inventory for this target is tracked in:

```text
targets/ibm_pc_5150/86box/NICS.md
```

Expected first screen:

```text
phase one       " " at centered project start for active text columns
no card         +, low descending PC speaker tone, fast-typed no network card
question        low PC speaker attention tone, fast-typed prompt
success         " " -> "." -> "o" -> seed build 5
```

Build 5 adapter prompts use color for selection. The selected adapter is bright
and the inactive adapter is dim; Up and Down toggle the selected row, and Enter
accepts it.

Seed does not switch video modes in this target. It reads the active BIOS text
column count and uses that for screen clearing and centering, so 40-column and
80-column text modes share the same path.

The broader text UI rule is documented in:

```text
docs/ui.md
```

The stage 2 runtime handoff block is documented in:

```text
targets/ibm_pc_5150/HANDOFF.md
```

Default CGA colors:

```text
seed       white
build 5    dark gray
error      red
menu       selected white, inactive dark gray
```

The floppy is a raw boot image, not a DOS filesystem. Sector 1 is the stage 1
boot sector. Sectors 2-8 are the fixed-sector stage 2 boot core. The remaining
sectors are zero-filled padding. There are no files or directory entries.

This launcher builds the floppy and starts a VM profile:

```sh
tools/run-86box.sh
tools/run-86box.sh vm-net-ne2k8
```

Without an argument it starts `vm`. 86Box 5.x starts specific machines with
`--vmpath`; the launcher also passes the generated floppy image as drive `A:`.

The original IBM PC target has no built-in floppy controller in 86Box, so the
VM config must explicitly use:

```ini
[Storage controllers]
fdc = fdc_xt
```

The Seed floppy image is a raw boot image, not a DOS-formatted image with a
BIOS Parameter Block, so BPB checking is disabled:

```ini
[Floppy and CD-ROM drives]
fdd_01_type = 525_1dd
fdd_01_check_bpb = 0
```

Build 5 was boot-tested on 86Box 5.3 build 8200 on 26 April 2026 with the CGA
no-card, `vm-net-ne2k8`, and `vm-net-3c503` configs. The no-card screen showed:

```text
+ no network card
```

On MDA, the error is expected to render bright because monochrome adapters do
not have red. The no-card path also plays the low failure tone through the PC
speaker using the PIT rather than the BIOS bell. `vm-net-ne2k8` showed the
adapter prompt, accepted `ne2000`, initialized packet hardware, and advanced to
`seed build 5`. `vm-net-3c503` preserved the non-NE handoff path and advanced
to `seed build 5`.
