# Build Scope

Seed's loading marker has four semantic phases plus the final splash:

```text
" "          project init: boot-sector load, stage 2 entry, display setup
"." dark     HAL setup: hardware detection, adapter init, hardware handoff
"o" dark     internet prep: network configuration and reachability
"o" bright   agent prep: gateway, key, session, and environment setup
splash       ready handoff animation; no loading work happens here
```

`retry` returns to the dark `"."` HAL setup phase. It does not rerun the
project-init phase or reread floppy sectors.

Builds can be larger than individual internal checkpoints. A build should map
to a user-visible readiness goal; commits inside that build can still be small.

## Current Map

```text
build 1   boot floppy proof
build 2   loading animation and fast-type banner
build 3   " " phase: project init and machine-readiness baseline
build 4   "." dark phase: HAL setup and adapter handoff
build 5   "o" dark phase: internet readiness
build 6   "o" bright phase: agent prep and environment handover
```

Build 5 is intentionally broad. It should end when Seed can bring up a network
path from the IBM PC 5150 target and prove outbound internet readiness. The
internal sequence is:

```text
NE-family packet hardware init
Ethernet transmit and receive
DHCP network configuration
DNS resolution
TCP or chosen transport reachability proof
```

Current build 5 checkpoints completed: NE-family packet hardware init,
bounded receive polling, receive-path diagnostics, DHCPDISCOVER transmit, and
opportunistic DHCPOFFER parsing into the handoff block. Lease acceptance, DNS,
and outbound reachability are still open. The current DHCPOFFER poll remains
intentionally short; a longer wait loop should filter packet headers before it
reads larger frames from the receive ring.

TLS, model API calls, agent session creation, and environment handover belong
to build 6 unless build 5 proves that a different split is required.
