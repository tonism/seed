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
sector 1       boot sector with FAT12 BPB
sectors 2-5    reserved FAT12 loader
sectors 6-7    FAT copies
sectors 8-11   root directory
sector 12+     file data, starting with CORE.SYS
```

Build 6 is the agent-prep milestone. The current checkpoint keeps build 5's
internet-readiness path, adds a FAT12 boot image, ships tracked agent interface
declarations in `AGENTS.CFG`, ships the generic internet probe host in
`NET.CFG`, falls back to built-in `openai`, `anthropic`, and `google` agent
interfaces when `AGENTS.CFG` is missing or bad, reads optional ignored local
user state from `USER.CFG`, asks `agent?` when the saved agent choice is
missing or invalid, asks for missing `server?` and `key?` values needed by that
agent on one form panel when both are required, preserves saved model and
reasoning values when present, proves selected-agent DNS and TCP 443 connection
through the shared boot-core TCP connect path, sends a minimal TLS 1.2
ClientHello with SNI, parses and stores ServerHello version, random,
cipher-suite, session-id, and extension bounds, and writes
validated values back best-effort. Completing TLS, model API calls, capability fetches,
session creation, and environment handover remain later build 6 work.

Build 5 completed the internet-readiness milestone. It initializes
NE1000/NE2000-family packet hardware after a valid MAC read, reads one pending
receive-ring frame when available, sends DHCPDISCOVER, performs bounded
DHCPOFFER and DHCPACK waits, ARPs for the DHCP-provided DNS server, resolves
the `NET.CFG` probe host, selects and ARPs the TCP next hop, opens a port 80
TCP connection through the same connect path used by agent prep, and sends the
final ACK before leaving the dark `"o"` phase.

If no card responds, Seed turns the current `.` marker red and fast-types
`no network card` with a low PC speaker failure tone, then offers `retry` or
`restart`. Retry returns to the dark `.` HAL setup phase without rereading the
floppy; restart asks BIOS for a warm machine restart. Seed first tries to
resolve shared ISA NIC bases with safe station-address PROM probes. It only
pauses on a dim `.` and asks `adapter?` if the adapter family is still
ambiguous.

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

Future shippable artifacts may include host loaders that enter `CORE.SYS` from
an already-running system instead of booting the floppy path directly. DOS,
Windows, macOS/OSX, Linux, and other common host paths are candidates, but they
should be treated as one-way chainloaders that abandon the host runtime rather
than normal applications.

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
config/AGENTS.CFG                optional shipped agent interface override
config/NET.CFG                   optional shipped generic internet probe override
docs/config.md                   agent config and optional user state policy
docs/builds.md                   loading phase and build scope map
docs/ui.md                       text UI and fast-type rules
targets/ibm_pc_5150/README.md    current target details
targets/ibm_pc_5150/HANDOFF.md   current low-memory runtime handoff block
targets/ibm_pc_5150/boot/        8088 boot sector, loader, and core wrapper
targets/ibm_pc_5150/boot/core/   boot core include files; emitted as CORE.SYS
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

`AGENTS.CFG` is shipped with Seed as an override describing five available
agent interfaces: two gateways followed by three direct vendors. If it is
missing or bad, Seed falls back to the built-in big three direct vendors.
`NET.CFG` is shipped with the generic internet probe host. `USER.CFG` is
ignored local state for validated user choices and secrets; if it is missing or
unusable, Seed should ask and continue.
