# Seed

Seed is a boot-first agent runtime for memory-constrained computers. It brings
up enough of a machine to reach a cloud model directly, exposes a clear
hardware and memory contract, and then leaves the rest of the machine open for
user and agent-built local tooling.

Seed is not a general-purpose operating system and it is not a sandbox. It is a
small trusted control plane: boot the machine, establish the agent API path,
publish what memory and hardware Seed owns, and make recovery simple by keeping
the boot floppy as the reset boundary.

The current implementation targets IBM PC 5150-class hardware and emulation.
The same floppy image supports direct BIOS boot on larger machines and ROM
BASIC sidecar entry on smaller machines that cannot boot from the BIOS-loaded
sector address.

## Highlights

Two things make Seed unusual, and both are worth reading about in depth:

- **A full agent stack in 16 KiB.** The whole TLS 1.2 path — handshake, key schedule,
  ChaCha20-Poly1305 record crypto, HTTP, and streamed responses — fits in a 16 KiB RAM
  budget. Only a 2 KiB resident nucleus and a 7 KiB crypto window ever stay in memory;
  18 other phases stream from the floppy on demand and time-share one small window.
- **…on a 4.77 MHz 8088.** That same modern crypto — P-256 ECDHE, ChaCha20-Poly1305,
  SHA-256 — runs on a sub-MIPS 16-bit CPU with no crypto acceleration, using hand-tuned
  field arithmetic, a reused TLS session, and an add-rotate-xor cipher that suits the
  part.

Small and slow, but it works. The full CPU and memory story is in
[docs/architecture.md](docs/architecture.md), with stage-by-stage memory maps in
[docs/memory.md](docs/memory.md). Target-specific boot, memory, and emulator details
live under [targets/ibm_pc_5150/](targets/ibm_pc_5150/).

## Minimum Specs

Current IBM PC 5150 target:

```text
CPU       8088-compatible, 4.77 MHz
RAM       16 KiB minimum through ROM BASIC sidecar entry
          32 KiB minimum for direct BIOS floppy boot
media     160 KiB 5.25-inch FAT12 floppy image
video     BIOS text mode, CGA or MDA
network   supported ISA Ethernet adapter
emulator  86Box profiles are provided for development and verification
```

Supported network families on the current target:

```text
3Com 3c501
3Com 3c503
NE1000 / NE2000 compatible
Novell NE1000 compatible
WD8003 compatible
```

No-card machines fail cleanly with a text error and retry/restart choices.

## Current Capability

On the IBM PC 5150 target, Seed can:

- start from the 160 KiB floppy image,
- enter through direct BIOS boot on machines with enough RAM,
- enter through a generated ROM BASIC helper on 16 KiB machines,
- detect supported ISA Ethernet adapters,
- acquire IPv4 configuration with DHCP,
- resolve hostnames with DNS,
- open a TCP connection to the selected agent provider,
- complete the current minimal TLS 1.2 provider path,
- run the Default Prompt Interface chat loop: an initial model greeting, prompt
  input, and streamed model responses across multiple turns in one boot session,
- use shipped `AGENTS.CFG` and `NET.CFG` defaults, and
- use optional local `USER.CFG` state when present.

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

Inspect the generated image and memory layout:

```sh
make inspect
```

Generate the ROM BASIC sidecar helpers for sub-32 KiB entry:

```sh
make basic-bootstrap
```

Run the default no-card 86Box profile:

```sh
tools/run-86box.sh
```

Run a NIC-present profile:

```sh
tools/run-86box.sh vm-net-ne2k8
```

Run the automated ROM BASIC sidecar harness:

```sh
tools/run-basic-bootstrap-86box.py --profile vm-net-ne2k8
```

The generated boot image is:

```text
build/ibm_pc_5150/floppy-160k.img
```

## Repository Map

```text
Makefile                           build FAT12 160 KiB floppy image
config/AGENTS.CFG                  shipped agent interface defaults
config/NET.CFG                     shipped generic internet probe default
docs/architecture.md               Seed product and hardware/tooling contract
docs/builds.md                     milestone and scope history
docs/config.md                     agent config and optional user state policy
docs/networking.md                 NIC and TLS-transport behavioral contract
docs/ui.md                         text UI and fast-type rules
notes/                             design notes and implementation logs
targets/ibm_pc_5150/README.md      target details
targets/ibm_pc_5150/HANDOFF.md     runtime handoff block
targets/ibm_pc_5150/boot/          8088 boot sector, loader, and core wrapper
targets/ibm_pc_5150/boot/core/     boot core include files; emitted as CORE.SYS
targets/ibm_pc_5150/86box/         86Box profiles and NIC inventory
tools/build-basic-bootstrap.py     generated ROM BASIC sidecar helper builder
tools/build-fat12-image.py         deterministic 160 KiB FAT12 image builder
tools/core-sys-info.py             CORE.SYS header, resident, and phase inspector
tools/check-p256.py                dependency-free P-256 vector and field checker
tools/check-tls-prf.py             dependency-free TLS PRF and key schedule checker
tools/check-chacha-poly1305.py     dependency-free record crypto shape checker
tools/run-86box.sh                 build and launch an 86Box profile
tools/run-basic-bootstrap-86box.py launch 86Box and inject the BASIC sidecar
```

## Runtime Contract

Seed stays text-mode first. The current target does not switch video modes; it
reads the active BIOS text column count and adapts clearing and centering to it.

Seed-owned memory ranges are cooperation boundaries, not hardware-enforced
protection. Agent-built tools may use the machine directly outside Seed-owned
ranges. If they violate the published contract, that tool owns the crash and
the boot floppy remains the recovery path.

User-visible messages use the fast-type path. Success text, errors, questions,
menus, modals, field labels, and button labels should appear consistently.

Stored user config is optional. Missing, unreadable, unparseable, or invalid
config means Seed asks the user. Failed writes are ignored so read-only boot
media remain usable.

Future host loaders may enter `CORE.SYS` from an already-running system instead
of booting the floppy directly. Those loaders should behave as one-way
chainloaders that abandon the host runtime, not as normal host applications.
