# Seed Architecture Contract

Seed is a bootstrapping control plane, not a protected operating system.

The product goal is to give a memory-constrained machine a working agent API
path, publish the live hardware and memory contract, then leave the machine
open for user and agent-built local tooling. Seed should stay small enough that
the user and agent keep as much of the machine as possible.

## Core Shape

Seed owns the parts that are painful, fragile, or timing-sensitive to build
from bare metal:

```text
boot entry
basic hardware discovery
text UI and recovery path
network setup
provider TLS/API bootstrap
compact memory map and handoff state
minimal handoff into the user/agent environment, when that build phase exists
```

Seed should not grow into a general hardware abstraction layer or restrictive
runtime. Local tool formats, loaders, ABIs, workspaces, and result handling
belong to the user/agent environment. Seed's job is to get that environment to
the point where it can exist, not to become the environment itself.

## Current Target Snapshot

The active implementation target is an IBM PC 5150-class machine:

```text
CPU              8088-compatible, 4.77 MHz
RAM floor        16 KiB through ROM BASIC sidecar entry
BIOS boot floor  32 KiB through direct floppy boot
media            160 KiB 5.25-inch FAT12 floppy image
video            BIOS text mode, CGA or MDA
network          3c501, 3c503, NE1000/NE2000, Novell NE1000, WD8003 families
runtime file     one visible CORE.SYS
```

Current measured image:

```text
CORE.SYS total bytes:       23040
CORE.SYS total sectors:     45
resident nucleus sectors:   4
resident nucleus bytes:     2048
phase count:                16
provider-critical K window: 13 sectors / 6656 bytes
16 KiB raw slack:           1293 bytes after critical scratch
16 KiB guarded slack:       +269 bytes after the preferred 1 KiB guard
```

## Boot Artifact

The current floppy is a small FAT12 image with a reserved boot loader and a
normal visible runtime file:

```text
160 KiB FAT12 floppy
|
| sector 1       boot sector with BPB
| sectors 2-5    reserved loader
| sectors 6-7    FAT copies
| sectors 8-11   root directory
| sector 12+     file data
|                CORE.SYS is the first FAT data file
|                AGENTS.CFG, NET.CFG, optional USER.CFG follow
```

`CORE.SYS` is one file-backed runtime. The build splits its source into NASM
include files and cold phases, but the release artifact remains one visible
`CORE.SYS`. Do not introduce a second runtime image for low-memory entry.

## Entry Paths

Seed has two entry paths into the same resident nucleus.

```text
32 KiB and larger
-----------------
BIOS loads boot sector at 0000:7c00
  -> stage 1 reads reserved loader to 0000:0600
  -> reserved loader reads CORE.SYS root entry and FAT chain
  -> loader reads only the resident CORE.SYS sectors to 0000:1000
  -> loader clears BASIC-entry registers
  -> jump 0000:1000

16 KiB path
-----------
machine enters ROM BASIC
  -> user types or pastes generated SEED24A.BAS / SEED24B.BAS sidecar text
  -> BASIC pokes a tiny 8086 loader at 0000:3a00
  -> helper reads the resident CORE.SYS sectors from the Seed floppy
  -> helper passes AX = RAM top, BX/CX = "SEED" magic, DL = boot drive
  -> jump 0000:1000
```

The BASIC loader at `0x3a00` is entry-time only. It is deliberately placed in
memory that later becomes Seed critical scratch. Once it jumps to `CORE.SYS`,
the BASIC runtime and sidecar loader are abandoned.

## Runtime Step Order

The resident nucleus is a small scheduler plus shared hardware, UI, filesystem,
network, and state primitives. It reloads cold phases from the same `CORE.SYS`
file as needed.

High-level flow:

```text
entry normalize
  -> set stack from BIOS path or BASIC-provided RAM top
  -> clear low and high runtime scratch
  -> remember boot drive and RAM top in handoff block

hardware phase "."
  -> H: display, handoff, adapter discovery
  -> I: packet I/O initialization

internet phase ","
  -> D: DHCP setup
  -> P: NET.CFG probe-host load/parse
  -> C: TCP connect to generic probe path

agent phase "o"
  -> A: AGENTS.CFG load/parse or built-in fallback
  -> U: USER.CFG load/parse
  -> Q: ask for missing agent/server/key/model/reasoning values if needed
  -> E: selected-agent endpoint and DNS name preparation
  -> R: fixed minimal request construction
  -> K: load provider-critical LINK window at 0x1800
  -> L: build TLS ClientHello and low crypto constants
  -> C: TCP connect to selected provider on port 443
  -> K: TLS server proof, key schedule, encrypted request, application receive
  -> T: parse a received application-data chunk for the returned answer
  -> S: best-effort USER.CFG save if values changed
  -> B: splash/result screen

failure
  -> F: mark current phase red, type error, offer retry/restart
  -> retry returns to the hardware "." phase without rereading resident sectors
```

The same TCP connect phase is used for the internet probe and for the selected
agent provider. It is loaded into the network setup window each time it is
needed.

## Phase Windows

`CORE.SYS` starts with a resident nucleus and a phase table. The phase loader
uses sector offsets inside `CORE.SYS`, so keeping `CORE.SYS` first in the FAT
data area is part of the boot contract.

Current phase table:

```text
id  sectors  load addr  responsibility
K   13       0x1800     provider-critical LINK window: SHA-256, TLS, AEAD, API exchange
F   1        0x0700     failure action UI
H   3        0x0700     hardware/display/NIC discovery
I   1        0x0700     packet I/O initialization
D   3        0x0900     DHCP setup
C   3        0x0900     TCP connect
L   2        0x0700     TLS ClientHello and low crypto constants
E   1        0x0700     selected agent endpoint setup
P   2        0x0700     NET.CFG probe config
A   2        0x0700     AGENTS.CFG provider config
U   2        0x0700     USER.CFG persisted user values
Q   3        0x0700     agent selection and missing-value prompts
R   1        0x0700     minimal API request construction
T   1        0x0d0e     response chunk parse
B   1        0x0700     final splash/result display
S   1        0x0700     best-effort USER.CFG save
```

Most cold phases share the low scratch/window region. The K window is different:
it is loaded once into a larger high window before the provider-critical path.

## Provider Timing Model

The provider path is Seed's gift to the agent. The agent should inherit a
working API channel instead of rediscovering TCP, TLS, request construction, and
response parsing from raw hardware on every boot.

Floppy access is acceptable while Seed is still preparing the path:

```text
read config
ask user questions
resolve endpoint
build request
load K, L, and C windows
```

The fast path begins once Seed has enough code and scratch resident to open the
provider TCP connection and drive TLS/application data:

```text
TCP connect to provider
send ClientHello
receive ServerHello / Certificate / ServerKeyExchange / ServerHelloDone
derive ECDHE shared secret and TLS keys
send ClientKeyExchange / ChangeCipherSpec / encrypted client Finished
verify encrypted server Finished
send encrypted application request
receive encrypted application data
```

The current 16 KiB design keeps the handshake, key schedule, AEAD, request send,
and application receive inside the resident K window plus high/critical scratch.
After an encrypted application-data chunk has arrived, Seed may load the cold
T response parser from floppy and inspect that chunk. That is intentionally
later than the handshake/request race and has been validated on the 16 KiB
profiles.

## Memory Layout

The 16 KiB target ceiling is `0x4000`. Seed currently keeps a 1 KiB measured
execution guard below that ceiling.

Entry-time BASIC view:

```text
0000..03ff  interrupt vectors
0400..04ff  BIOS data area
0500..06ff  low Seed/handoff area used after CORE starts
0700..0fff  low scratch/window area used after CORE starts
1000..17ff  resident CORE.SYS sectors loaded by BASIC helper
1800..39ff  ROM BASIC/program workspace until helper jumps
3a00..3a81  temporary BASIC sidecar machine-code loader
3a82..3fff  BASIC helper stack/top area before CORE starts
```

Runtime 16 KiB view after `CORE.SYS` takes over:

```text
0000..03ff  interrupt vectors
0400..04ff  BIOS data area
0500..05ff  low SHA-256 constants/scratch
0600..062d  Seed handoff block
062e..06ff  low runtime state
0700..0fff  low scratch, filesystem sector buffer, cold phase windows
1000..17ff  resident nucleus, 4 sectors / 2048 bytes
1800..31ff  K provider-critical window, 13 sectors / 6656 bytes
3200..32c1  high crypto scratch, 194 bytes
32c2..3af2  critical TLS/API scratch, 2097 bytes
3af3..3bff  measured guarded slack, 269 bytes
3c00..3fff  preferred 1 KiB stack/variance guard
```

The important collision boundary is the end of critical scratch:

```text
critical end       0x3af3
guard begins       0x3c00
16 KiB RAM top     0x4000
raw slack          1293 bytes
guarded slack       269 bytes
```

32 KiB and larger machines use the same `CORE.SYS` and the same low-memory
contract. Extra memory may be exposed later as optional arenas, caches, or tool
space, but the base product must not require it.

## Hardware And Handoff Contract

Seed publishes machine state through the handoff block at `0000:0600`. The
target-specific binary layout is documented in
`targets/ibm_pc_5150/HANDOFF.md`.

The handoff state includes:

```text
build/runtime identity
entry flags
boot drive
video mode and detected text columns
seed text column
NIC base, family, IRQ, and MAC when known
network status and error code
IPv4 address, router, DNS, and subnet
detected RAM top
```

On IBM PC 5150-class real-mode hardware, Seed cannot enforce memory protection.
Reserved ranges are contract boundaries, not sandbox walls. Everything outside
Seed-owned ranges is available to the user and agent. Tools may use BIOS calls,
I/O ports, RAM, video memory, NIC registers, disk services, or other hardware
directly when that is the right implementation.

If a tool writes into Seed-owned memory or otherwise violates the published
contract, the tool owns the crash. Seed is not expected to defend itself from
trusted bare-metal tooling.

## User/Agent Environment

The remote agent should not be in tight hardware timing loops. Network latency
and model latency make live step-by-step hardware control unreliable on small
machines.

The intended post-Seed model is asynchronous:

```text
Seed boots and establishes the provider API path
Seed publishes memory, hardware, and recovery contracts
Seed hands control to the user/agent environment
the environment decides what local tool is needed
the environment owns tool format, loading, calling, and result handling
the tool runs locally at machine speed
the environment uses Seed-published state and any retained API service surface
```

Seed may provide the first handoff mechanism and may retain a tiny service
surface for things that are hard to reconstruct or timing-sensitive, such as the
existing provider API channel or published hardware state. It should not own a
general local-tool execution runtime.

This keeps Seed minimal while still letting the environment build direct
hardware tooling. A later source-level workflow may make tool authoring nicer,
but the machine does not need an underlying OS, shell, compiler, or command
library for Seed itself to fulfill its contract.

## Recovery Boundary

The boot floppy is the trusted recovery boundary. A user must be able to
restart the machine from known Seed media after an agent-built tool hangs the
machine, corrupts RAM, or leaves hardware in a bad state.

Write-protected Seed media is a valid and desirable deployment mode. Local
configuration writes are convenience only; failed writes must not prevent boot
or agent/API use. Faster boot from `USER.CFG` is useful when the medium is
writable, but read-only media remains the cleanest physical kill switch.

## Authority Model

Seed is not a security boundary between the user, agent, and machine. If the
user allows an agent-built tool to run, that tool has bare-metal authority.

This is intentional. Seed optimizes for recovery, transparency, and freedom on
small machines rather than for multi-user isolation.

The product promise is:

```text
Seed can reboot from trusted media.
Seed can say where it lives and what it needs.
Seed can provide a working agent API path.
Seed can hand off to the user/agent environment.
The environment owns local tooling.
The user and agent get the machine outside Seed-owned ranges.
```

## Guard Philosophy

Memory guard is an execution uncertainty budget, not reserved space for
arbitrary third-party applications. Seed's closed contract removes the classic
need to protect against unknown programs casually stepping on the runtime.

A guard is still useful for stack depth, BIOS side effects, packet timing,
worst-case accepted config values, emulator versus real hardware variance, and
Seed's own mistakes. The guard should therefore be explicit, measured, and
small enough that it does not waste the point of a low-memory target.

For the 16 KiB target, the release guard target is 1 KiB of measured execution
headroom after Seed-owned resident state, scratch, window space, and stack
needs are accounted for. A 512-byte guard may be accepted as an intermediate
milestone only with stronger collision detection, such as explicit bound
checks, visible loader failure, and runtime canaries for the stack or scratch
areas that are most likely to collide.

Unused low memory is not reserved for future features by default. Future
features should either fit the published contract or belong to the user/agent
environment.

## Larger Machines

Seed should keep one floppy, one visible `CORE.SYS`, and one product contract
across small and larger machines. Larger machines may get additional optional
arenas, caches, or tool space after Seed detects the available RAM, but the base
16 KiB contract must not depend on those expansions.

Future work should test how larger-memory machines expose extra room to the
user/agent environment:

```text
larger packet/cache buffers
larger environment arena
larger environment-owned result/work buffers
optional persisted or prefetched windows
faster provider setup when extra RAM is available
```

Those are expansions of the same contract, not alternate products.
