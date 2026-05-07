# 24KB Windowed Design

Branch: `work/24kb-windowed`

This note is the architectural reference for the 24 KiB work. The branch's
first releasable target is 24 KiB, but the design must keep the later 16 KiB
target in view.

## Core Constraints

- Keep one Seed floppy.
- Keep one user-visible `CORE.SYS`.
- Keep one codebase and one runtime path after entry.
- Preserve automatic BIOS boot for machines with enough RAM.
- Support BASIC entry for machines below 32 KiB, because the PC BIOS boot
  sector entry at `0000:7c00` is above the RAM ceiling of 24 KiB and 16 KiB
  machines.
- Do not use floppy during the provider application-link critical path.

## Current Measured Baseline

The 32 KiB release loads `CORE.SYS` at `0x1000`.

```text
32 KiB ceiling:       0x8000
24 KiB ceiling:       0x6000
16 KiB ceiling:       0x4000
CORE.SYS size:        27094 bytes
CORE.SYS load range:  0x1000..0x79d5
32 KiB stack top:     0x8000
32 KiB guard start:   0x7a00
32 KiB guard slack:   42 bytes
```

Approximate assembled contribution in the 32 KiB release:

```text
main/control       0.2 KiB
display/ui/menu    1.2 KiB
hardware detect    0.8 KiB
config/fs          2.9 KiB
net tx/transport   1.6 KiB
net rx             2.6 KiB
sha256/hmac        1.5 KiB
chacha/poly1305    2.7 KiB
tls                5.3 KiB
agent api          0.5 KiB
resident data      7.0 KiB
```

For 24 KiB, loading at `0x1000` leaves 20 KiB before any stack or guard. For
16 KiB, it leaves 12 KiB total. A flat resident image cannot get us there
without making the design fragile. The architecture must make most code and
many buffers phase-local.

## File Shape

`CORE.SYS` should become a container, not a single always-resident flat body.
It still remains the only user-visible runtime file.

Proposed layout:

```text
CORE.SYS
  resident nucleus header
  resident nucleus code/data
  phase table
  sector-aligned phase windows
```

The normal boot loader and BASIC loader should both load only the resident
nucleus, then jump to `0000:1000`. After that, all paths are the same.
The BIOS loader should clear the BASIC-entry signature registers before the
jump. The BASIC loader should pass the RAM ceiling in `AX` with the explicit
`BX/CX = "SEED"` signature so the core can choose a valid initial stack before
using any calls.

The phase table should describe each window:

```text
id
file sector offset from CORE.SYS start
sector count
load address
entry offset
scratch/state requirements
flags, including fast-lane/no-floppy
```

The image builder already writes root files contiguously. We should preserve
and verify that `CORE.SYS` is first in the FAT data area. Runtime phase loads
can then use `CORE.SYS` sector offsets rather than a full FAT walk during low
memory operation. The build should fail if a phase exceeds its window budget.

Phase code must be assembled for the address where it will execute. Directly
copying normal resident code into another window is unsafe because near calls
and jumps are relative to the assembly origin. Shared resident services should
be reached through a small fixed low-memory service table or another explicit
ABI, not by assuming phase code can call arbitrary resident labels directly.

## Memory Shape

The resident nucleus owns stable state and services that must survive phase
window replacement.

Low memory that must stay stable:

```text
0x0000..0x03ff  IVT
0x0400..0x04ff  BIOS data area
0x0600..0x06ff  Seed handoff and tiny persistent boot state
0x0700..0x0fff  reusable low scratch, disk sector, packet scratch
0x1000..        resident nucleus
```

24 KiB target shape:

```text
0x1000..0x17ff  resident nucleus target, about 2 KiB
0x1800..0x4bff  largest AGENTLINK window target, about 13 KiB
0x1800..0x33ff  smaller reloadable setup windows, about 7 KiB
0x4c00..0x57ff  shared packet/TLS/API scratch target, about 3 KiB
0x5800..0x5fff  stack and guard target, about 2 KiB
```

16 KiB target shape:

```text
0x1000..0x17ff  resident nucleus hard target, about 2 KiB
0x1800..0x37ff  largest AGENTLINK window hard target, about 8 KiB
0x1800..0x2bff  smaller reloadable setup windows, about 5 KiB
0x3800..0x3bff  shared scratch hard target, about 1 KiB
0x3c00..0x3fff  stack and guard hard target, about 1 KiB
```

The 24 KiB map is a bring-up scaffold. Any 24 KiB-only luxury must be treated
as temporary unless it has a path to the 16 KiB map. The maps are intentionally
asymmetric: the critical provider link gets the largest no-floppy window, while
setup, configuration, DHCP/DNS, and post-response UI must fit smaller
reloadable windows.

## Resident Nucleus

The nucleus should stay small and boring. It should contain:

- entry normalization from BIOS boot and BASIC boot
- phase-table lookup
- sector read for phase windows
- minimal CHS disk read
- fixed service-vector setup for phase code
- low-memory handoff and persistent state
- fatal marker/error display path
- a tiny phase dispatcher
- selected NIC packet-service entry points, or a stable vector table to them

The nucleus should not contain:

- full config parsing
- full UI menus/forms
- DHCP/DNS/TCP protocol logic
- TLS handshake parser
- SHA/HMAC/PRF/ChaCha/Poly1305 implementation
- OpenAI response parser
- large strings
- temporary diagnostics

## Phase Windows

Likely first set:

```text
BOOTCFG
  display setup, config reads, USER.CFG/AGENTS.CFG/NET.CFG parsing, questions

NIC
  NIC detection, family selection, MAC read, hardware init

IP
  DHCP, DNS, ARP, TCP connect helper, generic internet readiness

AGENTLINK
  selected-agent TCP 443 connection through provider response parse

READY
  post-response UI, splash, later handoff work
```

This is not a recommendation to create multiple user-visible files. These are
internal phase windows inside `CORE.SYS`.

## Provider Link Critical Path

This is the most important invariant. Once the provider link starts, the
runtime must not touch floppy until the answer has been received and parsed.
OpenAI is the first concrete implementation, but the same rule is assumed for
Anthropic and Google until proven otherwise.

Conservative AGENTLINK boundary:

```text
load AGENTLINK window before selected-agent TCP 443 connect
no floppy access
TCP connect to selected agent
ClientHello send
ServerHello parse
Certificate drain
ServerKeyExchange parse
ServerHelloDone parse
ClientKeyExchange / key schedule / Finished / app request ordering
server Finished verification
provider application response decrypt and parse
critical path ends after answer found
floppy access allowed again
```

The current working 32 KiB order must be preserved:

```text
1. Build OpenAI request before selected-agent TCP connect.
2. Connect TCP 443.
3. Build/send ClientHello and start transcript.
4. Receive/parse ServerHello.
5. Drain Certificate into the transcript.
6. Parse ServerKeyExchange and copy the server public X into premaster state.
7. For 3c501 without extended master secret, prepare the key schedule before
   ServerHelloDone.
8. Parse ServerHelloDone and update transcript.
9. Prepare ClientKeyExchange transcript.
10. For 3c501, send ClientKeyExchange immediately after ServerHelloDone.
11. Prepare premaster/master/key block if not already ready.
12. Build and encrypt client Finished.
13. For non-3c501, send ClientKeyExchange.
14. Send ChangeCipherSpec + encrypted client Finished.
15. Increment client record sequence.
16. Build the application record using the current client sequence.
17. Send the OpenAI application record before waiting for server Finished.
18. Receive server ChangeCipherSpec/Finished.
19. Verify server Finished and increment server sequence.
20. Receive/decrypt OpenAI application records.
21. Parse the response for the answer text or error message.
```

Do not move the application send after server Finished. The old 16 KiB work
proved that this can produce server `close_notify` before the request reaches
OpenAI. Do not load overlays, read config, save config, or touch floppy between
steps 8 and 21.

The 3c501 remains the timing canary. It needs the early key schedule and early
ClientKeyExchange behavior preserved unless a replacement is proven on real
VM runs.

Known bad paths from earlier work:

- Do not send the OpenAI request only after server Finished; OpenAI can close
  before the request reaches the relay/server.
- Do not assume a one-packet TLS receive buffer. Cutting the receive stream
  from two packet reads to one packet read broke the working path.
- Do not change the OpenAI request shape just to reduce response size unless
  the full VM path is retested. Adding `max_output_tokens` reduced host-side
  response bytes but broke the real-mode request/receive flow.
- Do not broadly alias PRF/HMAC/SHA state into crypto scratch unless each
  lifetime is proven. A broad alias passed local crypto checks but failed in
  the VM.

## State That Must Survive Window Loads

Persistent state should be explicit and compact:

- boot drive
- display columns and current marker attributes
- selected NIC family/base/IRQ/MAC
- DHCP IP/router/DNS/subnet
- ARP next-hop MAC
- TCP sequence/ack state
- selected agent id/model/key/endpoint/reasoning
- TLS transcript SHA state and byte counts
- client/server random
- TLS extension flags and selected cipher
- premaster, master secret, traffic keys, IVs
- client/server record sequence numbers
- prepared request length/pointer or compact request buffer
- small response buffer and parser state

State that should not survive:

- root directory scan buffers
- config line parsing scratch
- menu/form rendering scratch
- DHCP/DNS packet bodies after their phase
- ServerHello/Certificate raw payload after transcript update
- full response history after answer found
- debug marker trails unless explicitly enabled in a debug build

## Disk Access Rules

Allowed:

- before TCP 443 connect
- between non-fast phases
- after OpenAI answer has been parsed
- during error/retry/restart setup when no remote server is waiting

Forbidden:

- after ServerHelloDone is available and before the app request is sent
- while waiting for server Finished and the first application response
- inside AEAD/key schedule/retry loops
- inside packet receive loops that are protecting already-arrived TLS data

Preferred discipline:

- load the next needed phase before starting any remote timer
- keep AGENTLINK loaded through the entire TLS/API exchange
- defer USER.CFG writes until after answer parse

## First Implementation Direction

Do not start by moving TLS. Start by making the container and loader mechanics
boring:

1. Add a `CORE.SYS` header and resident-size field.
2. Teach BASIC bootstrap to load only resident nucleus sectors.
3. Teach the reserved boot loader to load only resident nucleus sectors too,
   so BIOS and BASIC paths converge.
4. Add a build-time window-budget checker.
5. Move a low-risk phase first, probably config/UI or no-card/error UI.
6. Only after window load/return is stable, split network phases.
7. Design AGENTLINK last, using the invariant order above as a test oracle.

The first released 24 KiB build can keep larger AGENTLINK windows than the future
16 KiB build, but it must not introduce a fast-lane floppy dependency.
