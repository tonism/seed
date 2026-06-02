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

Protected mode is not part of the current product direction. Even on later
machines, Seed should not become a protected supervisor unless the product
direction explicitly changes.

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
CORE.SYS total bytes:       26112
CORE.SYS total sectors:     51
resident nucleus sectors:   4
resident nucleus bytes:     2048
phase count:                19
provider-critical K window: 14 sectors / 7168 bytes
16 KiB slack after critical: 781 bytes
16 KiB guard:               781 bytes (below the 1 KiB target, above the 512 B floor)
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
`CORE.SYS`. Do not introduce a second runtime image for 16 KiB entry.

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

internet phase (still ".")
  -> D: DHCP setup
  -> P: NET.CFG probe-host load/parse
  -> C: TCP connect to generic probe path

agent phase "o"
  -> A: AGENTS.CFG load/parse or built-in fallback
  -> U: USER.CFG load/parse
  -> Q: ask for missing agent/server/key/model/reasoning values if needed
  -> E: selected-agent endpoint and DNS name preparation
  -> R: request construction
  -> K: load provider-critical LINK window at 0x1800
  -> L: build TLS ClientHello and low crypto constants
  -> C: TCP connect to selected provider on port 443
  -> K: TLS server proof, key schedule, encrypted request, application receive
  -> T: parse a received application-data chunk for the returned answer
  -> S: best-effort USER.CFG save if values changed
  -> B: splash/result screen

prompt loop "Default Prompt Interface"
  -> render the model greeting, then take prompt input
  -> per turn: build request, encrypted send, streamed application receive, render
  -> reuse the live TLS session across turns; reconnect and resend on a real drop

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
K   14       0x1800     provider-critical LINK window: SHA-256, TLS, AEAD, API exchange
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
R   3        0x0900     API request construction
V   1        0x0700     agent/endpoint cache
X   1        0x0900     application-data stream (encrypted send/receive)
T   1        0x0d00     agent response parse
B   1        0x0700     splash/result display
Y   1        0x0700     Default Prompt Interface chat loop
S   1        0x0700     best-effort USER.CFG save
```

This is the live 19-phase layout; regenerate it with `make inspect` /
`tools/core-sys-info.py`. Phases that do network I/O — `D`, `C`, `R`, `X` — load at
`0x0900` so they coexist with the TCP/NIC scratch; the response parser `T` loads at
`0x0d00`; every other cold phase loads at `0x0700`.

Most cold phases share the low scratch/window region. The K window is different:
it is loaded once into a larger high window before the provider-critical path.

This windowed, phase-streaming design is what lets a full TLS 1.2 agent path — P-256
ECDHE, ChaCha20-Poly1305, HTTP/1.1, and SSE streaming — run in 16 KiB on a 4.77 MHz
8088: only the 2 KiB nucleus and the 7 KiB `K` crypto window stay permanently resident,
while the other 18 phases stream from the floppy on demand and take turns in one small
window. See [`memory.md`](memory.md) for the stage-by-stage memory maps.

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

After splash and into the prompt loop, floppy access should be avoided unless
the user or agent explicitly chooses to use the floppy, or Seed must recover
from a dropped or rebuilt provider link. The hot prompt/response path should be
RAM, network, and video flow rather than per-message overlay reads.

The per-NIC transport timing contracts this path depends on — render-before-ACK
pacing, the receive latch, and large-record completion handling — are documented in
[`networking.md`](networking.md).

## Memory Layout

The 16 KiB target ceiling is `0x4000`. At steady state three regions stay permanently
resident: the 2 KiB nucleus at `0x1000`, the 7 KiB `K` crypto/TLS/API window at
`0x1800`, and ~2.3 KiB of high-crypto plus critical TLS/API scratch above it. Cold
phases stream through the shared low scratch at `0x0700`. Critical scratch ends at
`0x3cf3`, leaving the measured execution guard — currently 781 bytes, below the 1 KiB
target — under the ceiling.

The byte-level entry-time and runtime layouts, and the per-stage maps, live in
[`memory.md`](memory.md); regenerate them with `make memory-map` after any
memory-layout change and before release checks.

32 KiB and larger machines use the same `CORE.SYS` and the same 16 KiB contract.
Extra memory may be exposed later as optional arenas, caches, or tool space, but the
base product must not require it.

## CPU And Crypto Budget

The other half of the constraint is the processor. A 4.77 MHz 8088 is a 16-bit,
sub-MIPS part with a slow multiply and no crypto acceleration, and the provider path
asks it to run modern TLS 1.2 — P-256 ECDHE, ChaCha20-Poly1305, and SHA-256 — heavy
256-bit math on a CPU built for 16-bit adds. The whole boot to first response reads as four resource tracks — one column per
second, `░▒▓█` from light to full:

```text
         0    5    10   15   20      seconds
  CPU    ▒▒    ██████████████▒
  RAM    ░░░▒▒▒██████████████████
  DSK    █▓▒▒▒██             ▒▒░
  NET      ▓▓▓▓▒            ░▒▓▓▓

  CPU  real computation    flat-out only during ECDHE + key schedule (s6-19)
  RAM  16 KiB filled         climbs, then the K window lands (~s6) and stays ~98% full
  DSK  floppy sector reads   nucleus + every cold phase; the big spike is K (14 sectors)
  NET  packets on the wire   DHCP / DNS / TCP (s2-5), then the streamed response (s21+)

The correlation is the story: the K window lands, disk spikes, RAM fills — then the
CPU pins flat-out on the two crypto steps while disk and network fall quiet. After the
first response the DPI loop runs near-idle, reusing the session. (Shapes approximate.)
```

What keeps that tractable:

- **An ARX record cipher.** The negotiated suite uses ChaCha20-Poly1305, an
  add-rotate-xor design with no S-boxes or large tables, so it needs no AES hardware
  and stays cheap on the 8088.
- **Field math tuned for the part.** Comba-style product accumulation for the 256-bit
  multiplies, Jacobian coordinates to avoid per-step modular inversions in the ECDHE
  scalar multiply, and prepared HMAC pad states reused across the TLS PRF so the
  SHA-256 blocks are not recomputed.
- **The scalar multiply is the bottleneck, and a known limitation.** A full P-256
  scalar multiply runs into minutes on this CPU, so the current build uses a sparse
  fixed development scalar to keep boot in the seconds range. A real entropy source and
  a faster constant-time full-scalar strategy are required before the path can be
  treated as secure TLS.
- **Pace the stream to the renderer.** On the most constrained NICs, response text uses
  render-before-ACK pacing so the network does not outrun the 8088's text renderer (see
  `networking.md`).
- **No tight remote loops.** Network and model latency on top of a slow CPU make
  step-by-step remote hardware control unreliable, which is why the post-Seed model is
  asynchronous (see User/Agent Environment, below).

The handshake is also why the chat loop never reconnects mid-conversation — that is a
race it cannot reliably win:

```text
  fresh TLS handshake on the 8088   ├──────────────── ~15 s ────────────────┤ done
  provider reconnect window         ├─────────────── ~15 s ───────────────┤ ✗ closed

  A mid-chat reconnect can lose this race and surface a connect error — for an
  answer the user has already seen. So the chat loop instead:
    · holds ONE TLS session open and reuses it for every prompt
    · if the completion marker is missed but the text already rendered, it accepts
      the answer rather than forcing a new (racing) handshake
  The ~15 s handshake is paid once, at boot — never per turn.
```

The two constraints are answered the same way: do the irreducible work once, keep it
resident only as long as it is needed, and lean on algorithm and layout choices that
suit a small, slow machine instead of fighting them.

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

The Default Prompt Interface is Seed's disposable starter UI. It is useful
enough to prove repeated chat after boot, but it is not the future environment
and should not accumulate terminal, shell, or operating-system responsibilities.
The first DPI release may send each prompt as a fresh provider request; the next
roadmap step is minimal context assembly so recent interaction state can shape
the following request.

Seed-owned context management should be compact and volatile on the 16 KiB
target: recent prompt/response state, a small rolling summary or equivalent
context record, and later tool-result slots. It should not depend on writeable
boot media and should not turn the hot prompt loop into a floppy-bound path.

Long-term semantic agent memory is a later environment concern. Persistent
notes, preferences, project state, and durable workspaces should use formats and
storage chosen by the user/agent environment, with Seed publishing enough memory
and storage facts for that environment to make its own decisions.

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
small enough that it does not waste the point of a 16 KiB target.

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

The long-term memory-ocean direction remains plausible: keep fixed Seed-owned
runtime ranges, keep dynamic scratch/request/response ranges explicit, and make
the remaining machine available to the user/agent environment. Do not reenter a
full memory defragmentation or ocean redesign until the chat loop is
stable.
