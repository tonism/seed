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
build 6   "o" bright phase: agent prep, credentials, TLS, API, session, handover
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

Current build 5 checkpoints completed for the current NE-family 5150 profiles:
NE-family packet hardware init, bounded receive polling, receive-path
diagnostics, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DHCP subnet/router/DNS
capture, DNS-server ARP, DNS A resolution for `example.com`, subnet-aware
next-hop ARP, TCP SYN transmit to port 80, and SYN-ACK receive. This gives the
dark `"o"` phase a real outbound reachability proof without starting TLS,
model API calls, or an agent session.

## Build 6

Build 6 owns the bright `"o"` phase. It starts after internet readiness is
proven and ends when Seed can connect to an agent and hand over to the first
agent/user environment.

Current build 6 checkpoint:

```text
FAT12 160 KiB boot floppy with fixed reserved stage 2 sectors
tracked AGENTS.CFG root file with gateway and vendor agent interfaces
ignored SEED.CFG reserved for validated local user choices and secrets
bright "o" validation that AGENTS.CFG exists and starts with an agent declaration
```

Still in build 6 scope:

```text
read optional SEED.CFG without making it a boot dependency
ask for missing provider, endpoint, model, and credential values
write validated user state best-effort when the boot image is writable
attempt TLS directly from the 8088 runtime
send the first model API request
create the agent session and hand over to the environment path
```
