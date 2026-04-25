# seed

Seed is a tiny boot-first agent runtime experiment.

The working idea is deliberately narrow: boot on old x86 hardware, establish a
path toward a direct cloud-model connection, then hand control to an
agent-built environment. The project starts with the smallest useful target and
keeps later convenience features out until they are needed.

## Current Target

The active target is an IBM PC 5150-class boot path:

```text
CPU       8088, 4.77 MHz
media     160 KiB 5.25-inch floppy image
video     BIOS text mode, no mode switch
emulator  86Box
build     seed build 3
```

The current boot image is a raw boot sector, not a filesystem:

```text
sector 1    boot sector
sector 2+   zero-filled padding
```

Build 3 treats the first loading phase as network hardware discovery. It probes
common ISA Ethernet I/O bases, shows `+ no network card` with a low PC speaker
failure tone if no card responds, and otherwise fast-types `seed build 3`.

## Build

Prerequisites:

```text
nasm
make
86Box for emulator testing
```

Build the floppy image:

```sh
make
```

Inspect the generated image:

```sh
make inspect
```

Run the default no-card 86Box profile:

```sh
tools/run-86box.sh
```

Run a NIC-present profile:

```sh
tools/run-86box.sh vm-net-ne2k8
```

## Repository Map

```text
Makefile                         build raw 160 KiB floppy image
docs/config.md                   optional user config policy
docs/ui.md                       text UI and fast-type rules
targets/ibm_pc_5150/README.md    current target details
targets/ibm_pc_5150/boot/        8088 boot sector source
targets/ibm_pc_5150/86box/       86Box profiles and NIC inventory
tools/run-86box.sh               build and launch a 86Box profile
```

## Project Rules

Seed stays text-mode first. The current target does not switch video modes; it
reads the active BIOS text column count and adapts clearing and centering to it.

User-visible messages use the fast-type path. Success text, errors, questions,
menus, modals, field labels, and button labels should appear consistently.

Stored user config is optional. Missing, unreadable, unparseable, or invalid
config means ask the user. Failed writes are ignored so read-only boot media
remain usable.

The current floppy image has no files. Do not add a filesystem, config file, or
boot-time seeking unless that becomes an explicit milestone.
