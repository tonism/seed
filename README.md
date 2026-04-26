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
build     seed build 5
```

The current boot image is raw sectors, not a filesystem:

```text
sector 1      stage 1 boot sector
sectors 2-8   stage 2 boot core
sector 9+     zero-filled padding
```

Build 5 is the internet-readiness milestone. The current checkpoint keeps build
4's NIC identity handoff, extends the handoff block for network readiness,
initializes NE1000/NE2000-family packet hardware after a valid MAC read,
reads one pending receive-ring frame when available, and sends a minimal
DHCPDISCOVER. It then performs a single bounded DHCPOFFER probe and records the
offered IPv4 address, router, and DNS server when one is observed. DHCP lease
acceptance, repeated DHCP receive, DNS, and outbound reachability remain in the
same build 5 scope.

If no card responds, Seed shows `+ no network card` with a low PC speaker
failure tone, then offers `retry` or `restart`. Retry returns to the dark `.`
HAL setup phase without rereading the floppy; restart asks BIOS for a warm
machine restart. If the responding I/O base maps cleanly to one supported card,
Seed fast-types `seed build 5`. If the base is shared by multiple 86Box
adapters, it pauses on a dim `.` and asks `adapter?` before continuing.

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
docs/builds.md                   loading phase and build scope map
docs/ui.md                       text UI and fast-type rules
targets/ibm_pc_5150/README.md    current target details
targets/ibm_pc_5150/HANDOFF.md   current low-memory runtime handoff block
targets/ibm_pc_5150/boot/        8088 stage 1 and stage 2 sources
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

The current floppy image has no files. Do not add a filesystem or config file
unless that becomes an explicit milestone.
