# Seed Architecture Contract

Seed is a tiny bootstrapping control plane, not a protected operating system.

The product goal is to give an old machine a working agent API path, publish
the live hardware and memory contract, then leave the machine open for
agent-built local tooling. Seed should stay small enough that the user and
agent keep as much of the machine as possible.

## Core Shape

Seed owns the parts that are painful or timing-sensitive to build from bare
metal:

```text
boot entry
basic hardware discovery
text UI and recovery path
network setup
provider TLS/API bootstrap
compact memory map and handoff state
tool loading and result handoff, when that build phase exists
```

Seed should not grow into a general hardware abstraction layer or restrictive
runtime. If a task can be handled by an agent-authored local tool without
making boot, recovery, or the provider critical path unreliable, prefer the
tool.

## Recovery Boundary

The boot floppy is the trusted recovery boundary. A user must be able to
restart the machine from known Seed media after an agent-built tool hangs the
machine, corrupts RAM, or leaves hardware in a bad state.

Write-protected Seed media is a valid and desirable deployment mode. Local
configuration writes are convenience only; failed writes must not prevent boot
or agent/API use. Faster boot from `USER.CFG` is useful when the medium is
writable, but read-only media remains the cleanest physical kill switch.

## Memory And Hardware Contract

On IBM PC 5150-class real-mode hardware, Seed cannot enforce memory protection.
Reserved ranges are contract boundaries, not sandbox walls.

Seed must publish enough information for tools to cooperate:

```text
Seed resident range
Seed scratch, stack, and phase/window ranges
stable handoff block
free tool arena, when available
result/output buffer, when available
current NIC, display, disk, and provider state that tools may rely on
```

Everything outside Seed-owned ranges is available to the user and agent. Tools
may use BIOS calls, I/O ports, RAM, video memory, NIC registers, disk services,
or other hardware directly when that is the right implementation.

If a tool writes into Seed-owned memory or otherwise violates the published
contract, the tool owns the crash. Seed is not expected to defend itself from
trusted bare-metal tooling.

## Agent-Built Tools

The remote agent should not be in tight hardware timing loops. Network latency
and model latency make live step-by-step hardware control unreliable on small
machines.

The intended model is asynchronous:

```text
agent decides what local tool is needed
agent produces or selects a small binary payload
Seed loads the payload into the tool arena
Seed calls the tool through a tiny ABI
the tool runs locally at machine speed
Seed reads back status and result data
Seed reports the result through the provider API path
```

This keeps Seed minimal while still letting the agent build direct hardware
tooling. A later source-level workflow may make tool authoring nicer, but the
machine does not need an underlying OS, shell, compiler, or command library for
the architecture to work.

## Provider Critical Path

Seed keeps responsibility for the provider API path because it is both painful
and timing-sensitive on the target machines. Once a selected provider
connection enters the critical TLS/API window, Seed should avoid floppy access
until the answer has been found.

The provider path is Seed's gift to the agent. The agent should inherit a
working API channel instead of rediscovering TCP, TLS, request construction,
and response parsing from raw hardware on every boot.

## Authority Model

Seed is not a security boundary between the user, agent, and machine. If the
user allows an agent-built tool to run, that tool has bare-metal authority.

This is intentional. Seed optimizes for recovery, transparency, and freedom on
tiny machines rather than for multi-user isolation.

The product promise is:

```text
Seed can reboot from trusted media.
Seed can say where it lives and what it needs.
Seed can provide a working agent API path.
Seed can load and call local tooling.
The user and agent get the rest of the machine.
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
features should either fit the published contract or move into reloadable local
tools and windows.

## Larger Machines

Seed should keep one floppy, one visible `CORE.SYS`, and one product contract
across small and larger machines. Larger machines may get additional optional
arenas, caches, or tool space after Seed detects the available RAM, but the
base 16 KiB contract must not depend on those expansions.

Future work should test how larger-memory machines expose extra room to the
agent and tools:

```text
larger packet/cache buffers
larger tool arena
larger result buffer
optional persisted or prefetched windows
faster provider setup when extra RAM is available
```

Those are expansions of the same contract, not alternate products.
