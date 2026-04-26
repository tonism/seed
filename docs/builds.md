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
build 2   minimal boot presentation: centered marker and fast-type banner
build 3   " " phase: project init, display baseline, handoff block, retry boundary
build 4   "." dark phase: HAL setup, adapter questions, hardware handoff
build 5   "o" dark phase: internet prep, IP config, reachability proof
build 6   "o" bright phase: agent prep, session setup, environment handover
```

Build 5 is intentionally broad. It should end when Seed can bring up a network
path from the IBM PC 5150 target and prove outbound internet readiness. The
internal sequence is:

```text
NE-family packet hardware init
Ethernet transmit and receive
DHCP network configuration
ARP resolution for the next-hop or service endpoint
DNS resolution
TCP or chosen transport reachability proof
```

Current build 5 checkpoints completed: NE-family packet hardware init,
bounded receive polling, receive-path diagnostics, DHCPDISCOVER transmit, and a
two-pass bounded filtered DHCPOFFER wait that records offer details in the
handoff block when one is observed. When an offer is available, Seed now sends
DHCPREQUEST and performs a bounded DHCPACK wait to mark the lease accepted.
After DHCPACK, Seed sends a bounded ARP request for the DHCP-provided DNS server
and records the resolved MAC, then sends a minimal DNS query and waits for a
matching response before leaving the dark `"o"` phase. Endpoint-specific DNS
answer parsing and outbound transport reachability are still open.

TLS, model API calls, agent session creation, and environment handover belong
to build 6 unless build 5 proves that a different split is required.
