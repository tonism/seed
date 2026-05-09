# seed

Seed is a tiny boot-first agent runtime experiment.

The working idea is deliberately narrow: boot on old x86 hardware, establish a
path toward a direct cloud-model connection, then hand control to an
agent-built environment. The project starts with the smallest useful target and
keeps later convenience features out until they are needed.

The stable product contract is in `docs/architecture.md`: Seed is a minimal
bootstrapping control plane, not a protected OS. It provides the trusted boot
and agent API path, publishes the memory/hardware contract, and leaves the rest
of the machine open for user and agent-built local tooling.

## Current Target

The active target is an IBM PC 5150-class boot path:

```text
CPU       8088, 4.77 MHz
media     160 KiB 5.25-inch floppy image
video     BIOS text mode, no mode switch
emulator  86Box
build     seed build 7
```

The current boot image is a minimal FAT12 floppy:

```text
sector 1       boot sector with FAT12 BPB
sectors 2-5    reserved FAT12 loader
sectors 6-7    FAT copies
sectors 8-11   root directory
sector 12+     file data, starting with CORE.SYS
```

Build 7 is the ROM BASIC low-memory milestone. The current checkpoint keeps
build 6's agent/API proof, keeps build 5's internet-readiness path, ships
tracked agent interface
declarations in `AGENTS.CFG`, ships the generic internet probe host in
`NET.CFG`, falls back to built-in `openai`, `anthropic`, and `google` agent
interfaces when `AGENTS.CFG` is missing or bad, reads optional ignored local
user state from `USER.CFG`, asks `agent?` when the saved agent choice is
missing or invalid, asks for missing `server?` and `key?` values needed by that
agent on one form panel when both are required, preserves saved model and
reasoning values when present, proves selected-agent DNS and TCP 443 connection
through the shared boot-core TCP connect path, sends a minimal TLS 1.2
ClientHello with SNI offering only P-256 ECDHE-ECDSA-CHACHA20-POLY1305 without
extended master secret for the current crypto path, parses and stores
ServerHello version, random,
cipher-suite, session-id, known extension flags, and the selected cipher path,
then parses the following Certificate handshake header, declared list length,
drains that Certificate handshake to the next handshake boundary, parses the
ECDHE ServerKeyExchange header, captures the uncompressed P-256 public point,
converts X/Y into 16-bit little-endian field words, range-checks them below
the P-256 prime, parses ServerHelloDone, maintains a live SHA-256 TLS
handshake transcript context through ServerHelloDone, computes the sparse
fixed-scalar ECDHE shared point, converts the Jacobian result into the affine
X-coordinate pre-master secret, derives the TLS master secret plus
client/server ChaCha20-Poly1305 write keys and IVs with the TLS 1.2 SHA-256
PRF using prepared HMAC states for repeated PRF calls, sends ClientKeyExchange,
sends ChangeCipherSpec and encrypted client Finished together, verifies the
encrypted server Finished, sends a minimal OpenAI Responses request asking for
`ok`, displays the returned answer, then writes validated values back
best-effort. All seven original-speed 5150 NIC profiles, including 3c501,
reach that proof in the 32 KiB BIOS-boot path. The current release also has a
ROM BASIC sidecar bootstrap path for machines that cannot enter through the
BIOS boot sector. The active 16 KiB release work is now down to choosing
between the preferred 1 KiB measured guard and a smaller guarded release floor.
Capability fetches, session creation, and environment handover remain later
work.

Build 5 completed the internet-readiness milestone. It initializes
NE1000/NE2000-family packet hardware after a valid MAC read, reads one pending
receive-ring frame when available, sends DHCPDISCOVER, performs bounded
DHCPOFFER and DHCPACK waits, ARPs for the DHCP-provided DNS server, resolves
the `NET.CFG` probe host, selects and ARPs the TCP next hop, opens a port 80
TCP connection through the same connect path used by agent prep, and sends the
final ACK before leaving the dark `","` phase.

If no card responds, Seed turns the current `.` marker red and fast-types
`no network card` with a low PC speaker failure tone, then offers `retry` or
`restart`. Retry returns to the dark `.` hardware phase without rereading the
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

## Repository Map

```text
Makefile                         build FAT12 160 KiB floppy image
config/AGENTS.CFG                optional shipped agent interface override
config/NET.CFG                   optional shipped generic internet probe override
docs/architecture.md             Seed product and hardware/tooling contract
docs/config.md                   agent config and optional user state policy
docs/builds.md                   loading phase and build scope map
docs/ui.md                       text UI and fast-type rules
targets/ibm_pc_5150/README.md    current target details
targets/ibm_pc_5150/HANDOFF.md   current low-memory runtime handoff block
targets/ibm_pc_5150/boot/        8088 boot sector, loader, and core wrapper
targets/ibm_pc_5150/boot/core/   boot core include files; emitted as CORE.SYS
targets/ibm_pc_5150/86box/       86Box profiles and NIC inventory
tools/build-basic-bootstrap.py    generated ROM BASIC sidecar helper builder
tools/build-fat12-image.py       deterministic 160 KiB FAT12 image builder
tools/core-sys-info.py            CORE.SYS header, resident, and phase inspector
tools/check-p256.py              dependency-free P-256 vector and field checker
tools/check-tls-prf.py           dependency-free TLS PRF and key schedule checker
tools/check-chacha-poly1305.py   dependency-free record crypto shape checker
tools/run-86box.sh               build and launch a 86Box profile
tools/run-basic-bootstrap-86box.py  launch 86Box and inject the BASIC sidecar
```

## Project Rules

Seed stays text-mode first. The current target does not switch video modes; it
reads the active BIOS text column count and adapts clearing and centering to it.

Seed is not a sandbox. On real-mode targets, reserved memory ranges are
published cooperation boundaries, not hardware-enforced protection. Agent-built
tools may use the machine directly outside Seed-owned ranges; if they violate
the published contract, that tool owns the crash and the boot floppy remains
the recovery boundary.

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
