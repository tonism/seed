# 16KB Windowed Nucleus Design

This note is the design reference for the next low-memory step after the
24 KiB BASIC sidecar release. It modifies the existing windowed architecture;
it is not a new product shape.

The stable product contract lives in `docs/architecture.md`. This note only
describes the current 16 KiB implementation strategy for that contract.

The external promise stays the same:

- one Seed floppy
- one user-visible `CORE.SYS`
- one codebase
- one runtime behavior after entry
- BIOS boot for machines with enough RAM
- ROM BASIC sidecar entry for machines below the BIOS boot-sector ceiling

The internal change is stricter: Seed becomes a windowed nucleus. The resident
part must become a tiny nucleus, and nearly everything else must run from
explicit, reloadable windows inside `CORE.SYS`.

## Current Baseline

The current 24 KiB release still loads `CORE.SYS` at `0x1000`.

Measured current image:

```text
CORE.SYS total bytes:       29696
CORE.SYS total sectors:     58
resident sectors:           37
resident bytes:             18944
resident load range:        0x1000..0x5a00
24 KiB ceiling:             0x6000
16 KiB ceiling:             0x4000
BASIC sidecar loader addr:  0x5a00
```

For a 16 KiB machine, `0x1000..0x4000` is only 12 KiB total. That must cover
resident code, persistent data, phase/window space or scratch, stack, and
guards. The current resident image alone is about 6.5 KiB too large before any
useful stack/scratch budget is considered. This is why 16 KiB is not a normal
trimming pass.

Lowering the `CORE.SYS` load address may be worth evaluating later, but it is
not the main strategy. It buys at most a small amount and risks colliding with
the handoff block, low scratch, disk buffers, and phase windows. The primary
strategy is reducing what is resident.

## Design Principle

Seed is a minimal bootstrapping control plane, not a protected operating
system. On the 5150 target, memory ranges are published cooperation boundaries,
not hardware-enforced protection. The boot floppy is the recovery boundary.

The 16 KiB architecture is lifetime-based.

Anything that does not need to survive the next phase boundary must not be
resident. Anything that is only needed before the provider critical path may
use floppy. Anything needed after the provider response may use floppy again.
Only the remote critical path gets a large no-floppy window.

The nucleus owns control, not features.

Resident nucleus responsibilities:

- normalize BIOS and BASIC entry
- choose a stack that is valid for the detected RAM ceiling
- maintain the phase/window table
- read sectors from the same `CORE.SYS`
- load and enter windows
- expose a tiny stable service table for windows
- keep the handoff block and compact persistent state
- keep minimal display marker/failure primitives
- keep only packet/TLS state that must survive window replacement

The nucleus must not own:

- full config parsing
- menus/forms
- DHCP/DNS/TCP setup logic
- TLS parser bodies
- SHA/HMAC/PRF/ChaCha/Poly1305 implementation bodies
- provider request/response parser bodies
- splash text
- verbose error UI
- debug trails

Small code duplication inside windows is acceptable when it removes resident
services. For 16 KiB, resident convenience is more expensive than some duplicate
phase-local bytes on floppy.

## Memory Shape

Hard target with the current `0x1000` load address:

```text
0x0000..0x03ff  IVT
0x0400..0x04ff  BIOS data area
0x0500..0x05ff  emergency/bootstrap scratch if needed
0x0600..0x06ff  Seed handoff and persistent ABI
0x0700..0x0fff  low scratch, disk sector, small packet/window scratch
0x1000..0x17ff  resident nucleus target, about 2 KiB
0x1800..0x33ff  normal phase window target, about 7 KiB
0x1800..0x37ff  provider critical window maximum, about 8 KiB
0x3800..0x3bff  shared critical scratch, about 1 KiB
0x3c00..0x3fff  stack plus guard target, about 1 KiB
```

These are target budgets, not promises. The 16 KiB release target is a measured
1 KiB execution guard. A 512-byte guard is acceptable as an intermediate
milestone only if collision detection improves at the same time: visible loader
failure for known collisions, explicit build-time bounds, and runtime canaries
for the stack or scratch areas most likely to overlap.

If the provider critical window cannot fit in about 8 KiB, the next design
lever is not to make the resident nucleus larger. The next lever is to split
the provider path into setup windows plus one minimal no-floppy link capsule.

## Window Classes

Expected window classes:

```text
BOOTCFG
  display setup, root/config reads, USER.CFG/AGENTS.CFG/NET.CFG parsing,
  agent/menu/form questions

NIC
  adapter detection, ambiguous-family UI, MAC/PROM reads, card init

IP
  DHCP, DNS, ARP, plain internet reachability, selected-agent host resolution

CONNECT
  selected-agent TCP 443 connect preparation and SYN/SYN-ACK handling

LINK
  no-floppy provider critical path from TLS ClientHello through answer parse

READY
  post-answer save, splash, later handoff work

FAILURE
  verbose failure text and retry/restart UI after no remote timer matters
```

The exact names do not matter. The lifetime boundaries do.

## Provider Critical Path

This remains the main invariant. Once the selected provider connection begins,
do not touch floppy until the answer has been found.

OpenAI is the concrete test path. Anthropic and Google should be assumed to
have the same practical timing sensitivity until proven otherwise.

The LINK window must preserve the known-good ordering:

```text
1. Build or finalize the minimal API request before starting remote timing.
2. Connect TCP 443 or enter with a freshly connected TCP 443 socket.
3. Send ClientHello and start the transcript.
4. Parse ServerHello.
5. Drain Certificate into the transcript.
6. Parse ServerKeyExchange and capture the server P-256 public point.
7. Preserve the 3c501 early schedule/early ClientKeyExchange behavior.
8. Parse ServerHelloDone and update transcript.
9. Prepare ClientKeyExchange transcript.
10. Derive premaster/master/key block.
11. Build and encrypt client Finished.
12. Send ClientKeyExchange at the proven point for the current NIC.
13. Send ChangeCipherSpec plus encrypted client Finished.
14. Build/send the application record before waiting for server Finished.
15. Receive and verify server Finished.
16. Receive/decrypt provider application data.
17. Parse answer text or error message.
18. End critical path; floppy is allowed again.
```

Do not move the application send after server Finished without a full VM proof.
Earlier experiments showed that this can lose the race and produce server close
behavior before the request reaches OpenAI.

The LINK window may be large, but it must be self-contained for the whole
critical path. Loading a response parser after sending the request is not
allowed unless the parser is loaded before the remote timer starts.

## Persistent State

Persistent state should be compact and named. If a value is not listed here,
it should be treated as phase-local by default.

Must survive windows:

- boot drive and entry mode
- RAM ceiling
- display columns and current marker state
- selected NIC family, base, IRQ, and MAC
- IP address, subnet, router, DNS
- selected next-hop MAC
- TCP sequence and acknowledgement state
- selected agent id, endpoint, model, reasoning, and key
- TLS client/server random
- TLS transcript hash state and byte counts
- selected TLS flags and cipher state
- server public key or derived premaster state
- master secret, traffic keys, IVs
- client/server record sequence numbers
- compact API request descriptor or request bytes
- current answer/error buffer after response parse

Should not survive windows:

- root directory scan buffers
- config line parse scratch
- menu/form render scratch
- DHCP/DNS packet bodies after IP setup
- ARP packet bodies after resolution
- raw Certificate bytes after transcript update
- raw ServerHello fields after required state is copied
- full HTTP response history after answer parse
- save-file construction scratch
- splash strings

## Disk Rules

Allowed floppy reads:

- before selected-agent TCP 443 connect
- between setup windows
- after provider answer parse
- during verbose failure UI after a fatal network/provider failure

Forbidden floppy reads:

- while a selected provider TCP/TLS connection is waiting
- between ServerHelloDone and application request send
- between application request send and answer parse
- inside TLS receive loops
- inside AEAD/key schedule loops that protect already-arrived TLS data

The safe pattern is:

```text
load all critical code and scratch
start selected provider remote timing
complete TLS/API exchange
find answer
release critical window
load post-answer windows
```

## Implementation Strategy

Do not attempt a blind 24 KiB to 16 KiB cut. Work one boundary at a time.

Recommended sequence:

1. Add a measured 16 KiB build target and make the build print nucleus,
   window, scratch, and stack budgets.
2. Rename the resident area conceptually to nucleus and fail the build when it
   grows past a temporary ceiling.
3. Move verbose failure UI and final splash fully out of resident if any pieces
   remain.
4. Move all config and selection UI behind BOOTCFG windows.
5. Move NIC detection/init behind NIC windows, leaving only compact handoff
   state resident.
6. Move remaining DHCP/DNS/ARP/TCP-connect code behind IP/CONNECT windows.
7. Inventory every resident buffer and give it an owner and lifetime.
8. Build a first LINK window that preserves the 32 KiB/24 KiB proven ordering,
   even if it is too large for final 16 KiB.
9. Shrink LINK by removing noncritical parsing, generic helpers, and strings.
10. Only then test a real 16 KiB BASIC sidecar run.

At each cut:

```text
measure resident bytes and phase sizes
run make inspect
run make test
test one canary NIC at the current safe RAM ceiling
only lower the RAM ceiling when the measured map says it should fit
record the result in the attempt log
```

## Success Criteria

Raw 16 KiB fit:

- BASIC sidecar entry reaches Seed under a 16 KiB ceiling.
- The loader refuses visibly with the red `X` if the resident image or loader
  would collide.
- At least one representative NIC reaches returned `ok`.

Instrumented 16 KiB milestone:

- BASIC sidecar entry works under a 16 KiB ceiling.
- At least 512 bytes of measured execution guard remains.
- Collision detection covers known loader, stack, scratch, and resident/window
  bounds.
- Representative NIC families reach returned `ok`.
- 3c501 remains a canary and reaches returned `ok`.

16 KiB release candidate:

- BASIC sidecar entry works under a 16 KiB ceiling.
- The build has explicit nucleus/window/scratch/stack bounds.
- At least 1 KiB of measured execution guard remains.
- Representative NIC families reach returned `ok`.
- 3c501 remains a canary and reaches returned `ok`.
- 32 KiB+ BIOS boot still works from the same floppy and same `CORE.SYS`.
- No alternate provider-only product path or second `CORE.SYS` is introduced.

## Open Questions

- Whether `CORE.SYS` should remain at `0x1000` for 16 KiB or move lower after
  the nucleus is small enough to make that safe.
- Whether LINK can fit as one window or needs prelink subwindows plus one
  smaller no-floppy capsule.
- How much stack is truly needed in the final LINK path after phase-local code
  stops sharing resident helper call chains.
- Whether the response parser can be reduced to answer/error scanning only
  inside LINK, with richer response handling delayed until after 16 KiB is
  proven.
- How larger machines should expose optional extra RAM as caches, tool arenas,
  or result buffers without changing the base 16 KiB contract.
