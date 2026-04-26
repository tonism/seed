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
build     seed build 6
```

The current boot image is a minimal FAT12 floppy:

```text
sector 1       stage 1 boot sector with FAT12 BPB
sectors 2-17   stage 2 boot core in reserved sectors
sectors 18-19  FAT copies
sectors 20-23  root directory
sector 24+     file data
```

Build 6 is the agent-prep milestone. The current checkpoint keeps build 5's
internet-readiness path, adds a FAT12 boot image, ships tracked agent interface
declarations in `AGENTS.CFG`, reads optional ignored local user state from
`SEED.CFG`, asks `agent?` when the saved agent choice is missing or invalid,
and writes `agent <id>` back best-effort after validation. Credentials, TLS,
model API calls, session creation, and environment handover remain later
build 6 work.

Build 5 completed the internet-readiness milestone. It initializes
NE1000/NE2000-family packet hardware after a valid MAC read, reads one pending
receive-ring frame when available, sends DHCPDISCOVER, performs bounded
DHCPOFFER and DHCPACK waits, ARPs for the DHCP-provided DNS server, resolves
`example.com`, selects and ARPs the TCP next hop, sends a TCP SYN to port 80,
and waits for a matching SYN-ACK before leaving the dark `"o"` phase.

If no card responds, Seed shows `+ no network card` with a low PC speaker
failure tone, then offers `retry` or `restart`. Retry returns to the dark `.`
HAL setup phase without rereading the floppy; restart asks BIOS for a warm
machine restart. If the responding I/O base maps cleanly to one supported card,
Seed continues automatically. If the base is shared by multiple 86Box adapters,
it pauses on a dim `.` and asks `adapter?` before continuing.

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
Makefile                         build FAT12 160 KiB floppy image
config/AGENTS.CFG                shipped agent interface declarations
docs/config.md                   agent config and optional user state policy
docs/builds.md                   loading phase and build scope map
docs/ui.md                       text UI and fast-type rules
targets/ibm_pc_5150/README.md    current target details
targets/ibm_pc_5150/HANDOFF.md   current low-memory runtime handoff block
targets/ibm_pc_5150/boot/        8088 stage 1 and stage 2 sources
targets/ibm_pc_5150/86box/       86Box profiles and NIC inventory
tools/build-fat12-image.py       deterministic 160 KiB FAT12 image builder
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

`AGENTS.CFG` is shipped with Seed and describes five available agent
interfaces: two gateways followed by three direct vendors. `SEED.CFG` is
ignored local state for validated user choices and secrets; if it is missing or
unusable, Seed should ask and continue.
